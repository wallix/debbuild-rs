//! The install sequence, as dpkg runs it: for each package, prerm/preinst/unpack/postrm,
//! registration in the dpkg database, then postinst configure and the triggers.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;

use debbuild_rs_common::deb822::{Stanza, state_of};
use debbuild_rs_common::relation::{Relation, show_alternatives};
use debbuild_rs_common::{Error, IoContext, Kind, Result, py};

use crate::action::{Action, decide};
use crate::db::{Database, is_absent_state, is_installed_state};
use crate::exec::Exec;
use crate::fsx;
use crate::staged::Package;

pub const STATEDIR: &str = "var/lib/debbuild-rs";

/// The force options dpkg enables by default, as it passes them to maintainer scripts.
const DPKG_FORCE_DEFAULT: &str = "security-mac,downgrade";

/// Rounds of trigger processing before giving up on triggers activating each other.
const MAX_TRIGGER_ROUNDS: u32 = 100;

/// What to do with a conffile where dpkg would prompt: one both the administrator and
/// the package changed, or an existing file a fresh install brings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Conffiles {
    /// Keep the file, the new version going to `<conffile>.dpkg-dist`
    /// (`--force-confold`).
    #[default]
    Keep,
    /// Install the new version, the file kept as `<conffile>.dpkg-old`
    /// (`--force-confnew`).
    Replace,
}

/// How the installer settles what dpkg would skip, ask about or refuse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InstallOptions {
    /// Reinstall the unchanged packages instead of skipping them.
    pub reinstall: bool,
    pub conffiles: Conffiles,
    /// Take over the files of other packages, as dpkg's `--force-overwrite`, instead of
    /// failing.
    pub force_overwrite: bool,
}

impl InstallOptions {
    /// `--force`: all of them.
    pub const FORCE: Self = Self {
        reinstall: true,
        conffiles: Conffiles::Replace,
        force_overwrite: true,
    };
}

/// Print an informational line.
pub fn log(msg: &str) {
    let mut out = std::io::stdout().lock();
    // A closed stdout must not stop the installation.
    let _ = writeln!(out, "debbuild-rs install: {msg}");
    let _ = out.flush();
}

/// The last configured version of a package, as dpkg passes it to its maintainer scripts.
pub(crate) fn config_version(s: Option<&Stanza>) -> Option<String> {
    let s = s?;
    if let Some(c) = s.get("Config-Version") {
        return (!c.is_empty()).then(|| c.clone());
    }
    if is_installed_state(state_of(Some(s))) {
        s.get("Version").cloned()
    } else {
        None
    }
}

/// A package unpacked in this run, to configure.
pub(crate) struct Unpacked<'p> {
    pub pkg: &'p Package,
    pub config_version: Option<String>,
}

/// What unpacking a package gave.
#[derive(Default)]
pub(crate) struct UnpackResult {
    pub files: Vec<Vec<u8>>,
    /// conffile -> its Conffiles field value (`<md5>` or `<md5> obsolete`).
    pub conffiles: IndexMap<Vec<u8>, String>,
    /// (`st_dev`, `st_ino`) of every path of the new version.
    pub inodes: BTreeSet<(u64, u64)>,
    /// remove-on-upgrade conffiles, which leave the package.
    pub dropped: BTreeSet<Vec<u8>>,
    /// md5 of each regular file, for a package without DEBIAN/md5sums.
    pub md5sums: Option<IndexMap<Vec<u8>, String>>,
    /// The paths dpkg's path filters kept from being unpacked: listed, but not part of
    /// the new version on disk.
    pub filtered: BTreeSet<Vec<u8>>,
}

pub struct Installer<'e, 'p> {
    pub(crate) root: PathBuf,
    pub db: Database,
    pub(crate) opts: InstallOptions,
    exec: &'e dyn Exec,
    dpkg_version: String,
    pub(crate) triggers: BTreeMap<String, BTreeSet<String>>,
    unconfigured: IndexMap<String, Unpacked<'p>>,
    /// The packages being configured, waiting for their dependencies.
    configuring: Vec<&'p Package>,
    pub(crate) passwd: HashMap<String, u32>,
    pub(crate) group: HashMap<String, u32>,
    pub(crate) statoverride: HashMap<Vec<u8>, (u32, u32, u32)>,
    pub(crate) owners: Option<BTreeMap<Vec<u8>, BTreeSet<String>>>,
    pending_dirty: bool,
    pub(crate) disowned: BTreeMap<String, BTreeSet<Vec<u8>>>,
    /// dpkg's path filters, read from the root on the first unpack.
    pub(crate) filters: Option<crate::filter::Filters>,
}

/// One `DEBIAN/triggers` directive.
pub(crate) const TRIGGER_DIRECTIVES: [&str; 6] = [
    "interest",
    "interest-await",
    "interest-noawait",
    "activate",
    "activate-await",
    "activate-noawait",
];

/// The directives of a package's DEBIAN/triggers: `#` comments stripped, blank lines
/// skipped; anything but `<directive> <trigger>` with a known directive is an error
/// (H5).
///
/// # Errors
/// An unknown directive, a line without exactly two words, or an unreadable file.
pub fn trigger_directives(pkg: &Package) -> Result<Vec<(String, String)>> {
    let Some(e) = pkg.debian_entry("triggers") else {
        return Ok(Vec::new());
    };
    if !e.exists {
        return Ok(Vec::new());
    }
    let text = fsx::decode(e.data.clone()?)?;
    let mut out = Vec::new();
    for line in py::splitlines_str(&text) {
        let content = line.split('#').next().unwrap_or_default();
        let parts = py::split_ws_str(content);
        match parts.as_slice() {
            [] => {}
            [kind, name] if TRIGGER_DIRECTIVES.contains(kind) => {
                out.push(((*kind).to_owned(), (*name).to_owned()));
            }
            [kind, _] => {
                return Err(Error::new(format!(
                    "{}: DEBIAN/triggers: unknown directive {}",
                    pkg.name,
                    py::repr_str(kind)
                )));
            }
            _ => {
                return Err(Error::new(format!(
                    "{}: DEBIAN/triggers: malformed line {}",
                    pkg.name,
                    py::repr_str(line)
                )));
            }
        }
    }
    Ok(out)
}

impl<'e, 'p> Installer<'e, 'p> {
    #[must_use]
    pub fn new(db: Database, opts: InstallOptions, exec: &'e dyn Exec) -> Self {
        let dpkg_version = db
            .installed("dpkg")
            .and_then(|s| s.get("Version"))
            .cloned()
            .unwrap_or_default();
        Self {
            root: db.root.clone(),
            db,
            opts,
            exec,
            dpkg_version,
            triggers: BTreeMap::new(),
            unconfigured: IndexMap::new(),
            configuring: Vec::new(),
            passwd: HashMap::new(),
            group: HashMap::new(),
            statoverride: HashMap::new(),
            owners: None,
            pending_dirty: false,
            disowned: BTreeMap::new(),
            filters: None,
        }
    }

    /// `rel` in the root, resolved inside it.
    pub(crate) fn path(&self, rel: &[u8], follow: bool) -> Result<PathBuf> {
        crate::confine::confined(&self.root, rel, follow)
    }

    // --- maintainer scripts ---

    /// Run a maintainer script (`script`: its path, absent scripts are skipped).
    pub(crate) fn run_script(
        &self,
        pkg: &Package,
        script: Option<&Path>,
        name: &str,
        args: &[String],
    ) -> Result<()> {
        let Some(script) = script else {
            return Ok(());
        };
        if !fsx::exists(&self.path(self.db.rel(script).as_bytes(), true)?) {
            return Ok(());
        }
        let joined = args.join(" ");
        log(&format!("{}: {name} {joined}", pkg.name));
        let inside = self.db.rel(script);
        let mut force = DPKG_FORCE_DEFAULT.to_owned();
        if self.opts.force_overwrite {
            force.push_str(",overwrite");
        }
        if self.opts.conffiles == Conffiles::Replace {
            force.push_str(",confnew");
        }
        let mut cmd = self.exec.command(&self.root, &inside, args);
        cmd.env("DPKG_MAINTSCRIPT_PACKAGE", &pkg.name)
            .env("DPKG_MAINTSCRIPT_PACKAGE_REFCOUNT", "1")
            .env("DPKG_MAINTSCRIPT_ARCH", pkg.arch())
            .env("DPKG_MAINTSCRIPT_NAME", name)
            .env("DPKG_MAINTSCRIPT_DEBUG", "0")
            .env("DPKG_RUNNING_VERSION", &self.dpkg_version)
            .env("DPKG_FORCE", force)
            .env("DPKG_ADMINDIR", format!("/{}", crate::db::ADMINDIR))
            .env("DPKG_ROOT", "")
            // The dpkg locks are held for the whole run, as by a package manager
            // frontend (H2).
            .env("DPKG_FRONTEND_LOCKED", "1")
            .current_dir(&self.root);
        let program = PathBuf::from(cmd.get_program());
        let status = cmd.status().at(&program)?;
        let rc = status
            .code()
            .or_else(|| status.signal().map(|s| 0i32.saturating_sub(s)))
            .unwrap_or(1);
        if rc != 0 {
            return Err(Error::new(format!(
                "{}: {name} {joined} failed with exit status {rc}",
                pkg.name
            )));
        }
        Ok(())
    }

    /// `run_script` for error unwinding: a script failure is logged, not raised.
    pub(crate) fn try_script(
        &self,
        pkg: &Package,
        script: Option<&Path>,
        name: &str,
        args: &[String],
    ) -> Result<bool> {
        match self.run_script(pkg, script, name, args) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == Kind::Refusal => {
                log(&format!("warning: {e}"));
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    // --- users, groups and dpkg-statoverride, from the root's own databases (preinst
    // may have added some) ---

    fn read_ids(&self, file: &str) -> Result<HashMap<String, u32>> {
        let p = self.path(file.as_bytes(), true)?;
        let mut ids = HashMap::new();
        if fsx::exists(&p) {
            for line in py::splitlines_str(&fsx::read_text(&p)?) {
                let parts: Vec<&str> = line.split(':').collect();
                if let [name, _, id, ..] = parts.as_slice()
                    && !id.is_empty()
                    && id.bytes().all(|c| c.is_ascii_digit())
                    && let Ok(n) = id.parse::<u32>()
                {
                    ids.insert((*name).to_owned(), n);
                }
            }
        }
        Ok(ids)
    }

    pub(crate) fn load_ids(&mut self) -> Result<()> {
        self.passwd = self.read_ids("/etc/passwd")?;
        self.group = self.read_ids("/etc/group")?;
        Ok(())
    }

    fn lookup_id(spec: &str, table: &HashMap<String, u32>, what: &str) -> Result<u32> {
        if let Some(n) = spec.strip_prefix('#')
            && !n.is_empty()
            && n.bytes().all(|c| c.is_ascii_digit())
            && let Ok(id) = n.parse()
        {
            return Ok(id);
        }
        table.get(spec).copied().ok_or_else(|| {
            Error::new(format!(
                "statoverride: unknown {what} {}",
                py::repr_str(spec)
            ))
        })
    }

    pub(crate) fn load_statoverride(&mut self) -> Result<()> {
        self.statoverride.clear();
        let f = self.db.path("statoverride", true)?;
        if !fsx::exists(&f) {
            return Ok(());
        }
        for line in py::splitlines_str(&fsx::read_text(&f)?) {
            if py::is_blank(line.as_bytes()) {
                continue;
            }
            let parts: Vec<&[u8]> = py::split_ws_n(line.as_bytes(), Some(3));
            let malformed = || {
                Error::new(format!(
                    "{}: malformed line {}",
                    f.display(),
                    py::repr_str(line)
                ))
            };
            let [user, group, mode, path] = parts.as_slice() else {
                return Err(malformed());
            };
            if mode.is_empty() || !mode.iter().all(|c| (b'0'..=b'7').contains(c)) {
                return Err(malformed());
            }
            let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
            let uid = Self::lookup_id(&s(user), &self.passwd, "user")?;
            let gid = Self::lookup_id(&s(group), &self.group, "group")?;
            let mode = u32::from_str_radix(&s(mode), 8).map_err(|_| malformed())?;
            self.statoverride.insert(path.to_vec(), (uid, gid, mode));
        }
        Ok(())
    }

    // --- file ownership ---

    pub(crate) fn owners(&mut self) -> Result<&mut BTreeMap<Vec<u8>, BTreeSet<String>>> {
        if self.owners.is_none() {
            self.owners = Some(self.db.file_owners()?);
        }
        Ok(self.owners.get_or_insert_with(BTreeMap::new))
    }

    fn set_owned(&mut self, pkg: &str, old_files: &[Vec<u8>], new_files: &[Vec<u8>]) -> Result<()> {
        let owners = self.owners()?;
        for f in old_files {
            if let Some(o) = owners.get_mut(f) {
                o.remove(pkg);
            }
        }
        for f in new_files {
            owners.entry(f.clone()).or_default().insert(pkg.to_owned());
        }
        Ok(())
    }

    /// Let `pkg` unpack `rel`, which other packages may have: Replaces, or
    /// --force-overwrite.
    pub(crate) fn take_over(
        &mut self,
        pkg: &Package,
        rel: &[u8],
        replaces: &[Vec<Relation>],
    ) -> Result<()> {
        let current: Vec<String> = self
            .owners()?
            .get(rel)
            .map(|o| o.iter().cloned().collect())
            .unwrap_or_default();
        let shown = String::from_utf8_lossy(rel);
        for owner in current {
            let name = owner.split(':').next().unwrap_or_default();
            let s = self.db.status.get(&owner);
            if name == pkg.name || is_absent_state(state_of(s)) {
                continue;
            }
            let version = s.and_then(|s| s.get("Version")).map(String::as_str);
            let mut is_replaced = false;
            'outer: for alts in replaces {
                for r in alts {
                    if r.name == name && r.matches(version)? {
                        is_replaced = true;
                        break 'outer;
                    }
                }
            }
            if is_replaced {
                if !self.disowned.contains_key(&owner) {
                    log(&format!(
                        "{}: replacing files in old package {owner}",
                        pkg.name
                    ));
                }
            } else if self.opts.force_overwrite {
                log(&format!(
                    "warning: {}: overwriting {shown}, which is also in package {owner} (--force-overwrite)",
                    pkg.name
                ));
            } else {
                return Err(Error::new(format!(
                    "{}: trying to overwrite {shown}, which is also in package {owner}",
                    pkg.name
                )));
            }
            self.disowned
                .entry(owner.clone())
                .or_default()
                .insert(rel.to_vec());
            if let Some(o) = self.owners()?.get_mut(rel) {
                o.remove(&owner);
            }
        }
        Ok(())
    }

    /// Drop the paths taken over from their former owners' file lists and md5sums.
    pub(crate) fn flush_disowned(&mut self) -> Result<()> {
        let disowned = std::mem::take(&mut self.disowned);
        for (owner, paths) in &disowned {
            let lst = self.db.info(owner, "list", true)?;
            if fsx::exists(&lst) {
                let lines = fsx::read_lines(&lst)?;
                let kept = lines
                    .iter()
                    .filter(|l| !paths.contains(*l))
                    .map(Vec::as_slice);
                self.db.write_atomic(
                    format!("info/{owner}.list").as_bytes(),
                    &fsx::lines_bytes(kept),
                    None,
                    None,
                )?;
            }
            let sums = self.db.info(owner, "md5sums", true)?;
            if fsx::exists(&sums) {
                let rels: BTreeSet<&[u8]> = paths
                    .iter()
                    .map(|p| {
                        let n = p.iter().take_while(|&&c| c == b'/').count();
                        p.get(n..).unwrap_or_default()
                    })
                    .collect();
                let lines = fsx::read_lines(&sums)?;
                let mut kept = Vec::new();
                for line in &lines {
                    let path_field = py::split_ws_n(line, Some(1))
                        .last()
                        .copied()
                        .ok_or_else(|| Error::value("list index out of range"))?;
                    if !rels.contains(path_field) {
                        kept.push(line.as_slice());
                    }
                }
                self.db.write_atomic(
                    format!("info/{owner}.md5sums").as_bytes(),
                    &fsx::lines_bytes(kept),
                    None,
                    None,
                )?;
            }
        }
        Ok(())
    }

    // --- registration ---

    pub(crate) fn register(
        &mut self,
        pkg: &Package,
        old_files: &[Vec<u8>],
        res: &UnpackResult,
        config_version: Option<&str>,
    ) -> Result<()> {
        let prefix = format!("{}.", pkg.name);
        for name in self.db.info_names()? {
            // pkg.* also matches the files of pkg.foo
            if let Some(rest) = name.strip_prefix(prefix.as_bytes())
                && !rest.contains(&b'.')
                && rest != b"list"
            {
                let p = self.db.path_bytes("info", &name, false)?;
                fs::remove_file(&p).at(&p)?;
            }
        }
        for e in &pkg.debian {
            if e.name == b"control" {
                continue;
            }
            let data = e.data.as_ref().map_err(Clone::clone)?;
            let mut rel = format!("info/{}.", pkg.name).into_bytes();
            rel.extend_from_slice(&e.name);
            self.db.write_atomic(&rel, data, Some(e.mode), None)?;
        }
        if let Some(sums) = &res.md5sums
            && !sums.is_empty()
        {
            // dpkg generates the md5sums a package does not ship.
            let lines: Vec<Vec<u8>> = sums
                .iter()
                .map(|(path, md5)| {
                    let n = path.iter().take_while(|&&c| c == b'/').count();
                    [md5.as_bytes(), b"  ", path.get(n..).unwrap_or_default()].concat()
                })
                .collect();
            self.db.write_atomic(
                format!("info/{}.md5sums", pkg.name).as_bytes(),
                &fsx::lines_bytes(lines.iter().map(Vec::as_slice)),
                None,
                None,
            )?;
        }
        self.db.write_atomic(
            format!("info/{}.list", pkg.name).as_bytes(),
            &fsx::lines_bytes(res.files.iter().map(Vec::as_slice)),
            None,
            None,
        )?;
        self.set_owned(&pkg.name, old_files, &res.files)?;
        let mut stanza = pkg.control.clone();
        stanza.insert("Status".into(), "install ok unpacked".into());
        if let Some(c) = config_version.filter(|c| !c.is_empty()) {
            stanza.insert("Config-Version".into(), c.to_owned());
        }
        if !res.conffiles.is_empty() {
            let mut sorted: Vec<(&Vec<u8>, &String)> = res.conffiles.iter().collect();
            sorted.sort();
            let mut v = String::new();
            for (f, md5) in sorted {
                v.push_str("\n ");
                v.push_str(&String::from_utf8_lossy(f));
                v.push(' ');
                v.push_str(md5);
            }
            stanza.insert("Conffiles".into(), v);
        }
        self.db.status.insert(pkg.name.clone(), stanza);
        self.db.save()?;
        self.register_interests(pkg)?;
        self.activate(pkg, &res.files)?;
        self.save_pending()
    }

    /// Set a package's state; Config-Version stays while it is not installed.
    pub(crate) fn set_state(
        &mut self,
        name: &str,
        state: &str,
        config_version: Option<&str>,
        eflag: &str,
    ) -> Result<()> {
        let s = self
            .db
            .status
            .get_mut(name)
            .ok_or_else(|| Error::value(format!("KeyError: {}", py::repr_str(name))))?;
        s.insert("Status".into(), format!("install {eflag} {state}"));
        match config_version.filter(|c| !c.is_empty()) {
            Some(c) if !is_installed_state(state) => {
                s.insert("Config-Version".into(), c.to_owned());
            }
            _ => {
                s.shift_remove("Config-Version");
            }
        }
        self.db.save()
    }

    // --- triggers ---

    fn trigdir(&self) -> Result<PathBuf> {
        self.db.path("triggers", true)
    }

    /// Replace the package's trigger interests in triggers/, as dpkg does.
    fn register_interests(&mut self, pkg: &Package) -> Result<()> {
        let trigdir = self.trigdir()?;
        if let Err(e) = fs::create_dir(&trigdir)
            && !fsx::is_dir(&trigdir)
        {
            return Err(Error::os(&e, &trigdir));
        }
        let mut names: Vec<Vec<u8>> = Vec::new();
        for e in fs::read_dir(&trigdir).at(&trigdir)? {
            names.push(
                std::os::unix::ffi::OsStrExt::as_bytes(e.at(&trigdir)?.file_name().as_os_str())
                    .to_vec(),
            );
        }
        names.sort();
        let mut before: IndexMap<Vec<u8>, Vec<Vec<u8>>> = IndexMap::new();
        for n in names {
            if n == b"Lock" || n == b"Unincorp" || n.ends_with(b".debbuild-rs-new") {
                continue;
            }
            let p = self.db.path_bytes("triggers", &n, true)?;
            if !fsx::is_file(&p) {
                continue;
            }
            before.insert(n, fsx::read_lines(&p)?);
        }
        let owner = |entry: &[u8]| -> Vec<u8> {
            entry
                .split(|&c| c == b'/')
                .next()
                .unwrap_or_default()
                .to_vec()
        };
        let mut after: IndexMap<Vec<u8>, Vec<Vec<u8>>> = IndexMap::new();
        for (name, lines) in &before {
            let col = usize::from(name == b"File");
            let kept = lines
                .iter()
                .filter(|l| {
                    let w = py::split_ws(l);
                    w.get(col).is_none_or(|e| owner(e) != pkg.name.as_bytes())
                })
                .cloned()
                .collect();
            after.insert(name.clone(), kept);
        }
        for (kind, name) in trigger_directives(pkg)? {
            if !kind.starts_with("interest") {
                continue;
            }
            let entry = format!(
                "{}{}",
                pkg.name,
                if kind.ends_with("-noawait") {
                    "/noawait"
                } else {
                    ""
                }
            );
            if name.starts_with('/') {
                after
                    .entry(b"File".to_vec())
                    .or_default()
                    .push(format!("{name} {entry}").into_bytes());
            } else {
                after
                    .entry(name.into_bytes())
                    .or_default()
                    .push(entry.into_bytes());
            }
        }
        for (name, lines) in &after {
            if Some(lines) == before.get(name) {
                continue;
            }
            let mut rel = b"triggers/".to_vec();
            rel.extend_from_slice(name);
            if !lines.is_empty() || name == b"File" {
                self.db.write_atomic(
                    &rel,
                    &fsx::lines_bytes(lines.iter().map(Vec::as_slice)),
                    None,
                    None,
                )?;
            } else {
                let p = self.db.path_bytes("triggers", name, false)?;
                fs::remove_file(&p).at(&p)?;
            }
        }
        Ok(())
    }

    fn activate(&mut self, pkg: &Package, files: &[Vec<u8>]) -> Result<()> {
        for (kind, name) in trigger_directives(pkg)? {
            if kind.starts_with("activate") {
                self.activate_name(name.as_bytes())?;
            }
        }
        self.activate_paths(files)
    }

    /// Record an activation; an installed package gets it in its status, as with dpkg.
    fn note(&mut self, interested: &str, name: &str) {
        self.triggers
            .entry(interested.to_owned())
            .or_default()
            .insert(name.to_owned());
        let bare = interested.split(':').next().unwrap_or_default();
        let key = if self.db.status.contains_key(interested) {
            interested
        } else {
            bare
        };
        let Some(s) = self.db.status.get_mut(key) else {
            return;
        };
        if !is_installed_state(state_of(Some(s))) {
            return;
        }
        let pending = s.get("Triggers-Pending").cloned().unwrap_or_default();
        let mut words = py::split_ws_str(&pending);
        if !words.contains(&name) {
            words.push(name);
            s.insert("Triggers-Pending".into(), words.join(" "));
            s.insert("Status".into(), "install ok triggers-pending".into());
            self.pending_dirty = true;
        }
    }

    /// Save the activations recorded since the last save of the database.
    pub(crate) fn save_pending(&mut self) -> Result<()> {
        if self.pending_dirty {
            self.db.save()?;
            self.pending_dirty = false;
        }
        Ok(())
    }

    fn activate_name(&mut self, name: &[u8]) -> Result<()> {
        if name.starts_with(b"/") {
            return self.activate_paths(&[name.to_vec()]);
        }
        let name_s = fsx::decode(name.to_vec())?;
        for interested in self.explicit_interest(name)? {
            self.note(&interested, &name_s);
        }
        Ok(())
    }

    pub(crate) fn activate_paths(&mut self, paths: &[Vec<u8>]) -> Result<()> {
        let interests = self.file_interests()?;
        if interests.is_empty() {
            return Ok(());
        }
        for path in paths {
            for (trig, interested) in &interests {
                let mut dir = trig.trim_end_matches('/').as_bytes().to_vec();
                dir.push(b'/');
                if path.as_slice() == trig.as_bytes() || path.starts_with(&dir) {
                    self.note(interested, trig);
                }
            }
        }
        Ok(())
    }

    fn explicit_interest(&self, name: &[u8]) -> Result<Vec<String>> {
        let f = self.db.path_bytes("triggers", name, true)?;
        if !fsx::exists(&f) {
            return Ok(Vec::new());
        }
        Ok(py::splitlines_str(&fsx::read_text(&f)?)
            .into_iter()
            .filter(|l| !py::is_blank(l.as_bytes()))
            .filter_map(|l| {
                py::split_ws_str(l)
                    .first()
                    .map(|w| w.split('/').next().unwrap_or_default().to_owned())
            })
            .collect())
    }

    fn file_interests(&self) -> Result<Vec<(String, String)>> {
        let f = self.db.path("triggers/File", true)?;
        if !fsx::exists(&f) {
            return Ok(Vec::new());
        }
        Ok(py::splitlines_str(&fsx::read_text(&f)?)
            .into_iter()
            .filter_map(|l| match py::split_ws_str(l).as_slice() {
                [path, who, ..] => Some((
                    (*path).to_owned(),
                    who.split('/').next().unwrap_or_default().to_owned(),
                )),
                _ => None,
            })
            .collect())
    }

    /// Read activations left by dpkg-trigger in triggers/Unincorp, then empty it.
    fn incorporate(&mut self) -> Result<()> {
        let f = self.db.path("triggers/Unincorp", true)?;
        let lines = match fs::read(&f) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            r => py::splitlines(&r.at(&f)?)
                .into_iter()
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>(),
        };
        if lines.iter().all(|l| py::is_blank(l)) {
            return Ok(());
        }
        for line in &lines {
            if let Some(first) = py::split_ws(line).first() {
                self.activate_name(first)?;
            }
        }
        self.db.write_atomic(b"triggers/Unincorp", b"", None, None)
    }

    /// Triggers left pending in the database by an earlier run.
    fn seed_pending(&mut self) {
        for (key, s) in &self.db.status {
            let names = py::split_ws_str(s.get("Triggers-Pending").map_or("", String::as_str));
            if !names.is_empty() {
                self.triggers
                    .entry(key.clone())
                    .or_default()
                    .extend(names.into_iter().map(str::to_owned));
            }
        }
    }

    fn triggers_done(&mut self, key: &str) -> Result<()> {
        let name = key.split(':').next().unwrap_or_default().to_owned();
        if let Some(s) = self.db.status.get_mut(key) {
            s.shift_remove("Triggers-Pending");
            s.shift_remove("Config-Version");
        }
        for other in self.db.status.values_mut() {
            let awaited = other.get("Triggers-Awaited").cloned().unwrap_or_default();
            let words = py::split_ws_str(&awaited);
            if words.contains(&name.as_str()) || words.contains(&key) {
                let kept: Vec<&str> = words
                    .into_iter()
                    .filter(|a| *a != name && *a != key)
                    .collect();
                if kept.is_empty() {
                    other.shift_remove("Triggers-Awaited");
                    if state_of(Some(other)) == "triggers-awaited" {
                        other.insert("Status".into(), "install ok installed".into());
                    }
                } else {
                    other.insert("Triggers-Awaited".into(), kept.join(" "));
                }
            }
        }
        if let Some(s) = self.db.status.get_mut(key) {
            let state = if s.contains_key("Triggers-Awaited") {
                "triggers-awaited"
            } else {
                "installed"
            };
            s.insert("Status".into(), format!("install ok {state}"));
        }
        self.db.save()
    }

    /// Run postinst triggered for the activated triggers, until there are none left.
    ///
    /// # Errors
    /// A postinst fails, or triggers keep activating each other.
    pub fn process_triggers(&mut self) -> Result<()> {
        for _ in 0..MAX_TRIGGER_ROUNDS {
            self.incorporate()?;
            self.save_pending()?;
            if self.triggers.is_empty() {
                return Ok(());
            }
            let pending = std::mem::take(&mut self.triggers);
            for (interested, names) in pending {
                let name = interested.split(':').next().unwrap_or_default().to_owned();
                let key = if self.db.status.contains_key(&interested) {
                    interested.clone()
                } else {
                    name.clone()
                };
                let Some(s) = self.db.status.get_mut(&key) else {
                    continue;
                };
                // A package not installed gets its triggers handled by postinst configure.
                if !is_installed_state(state_of(Some(s))) {
                    continue;
                }
                // As dpkg's trigproc: half-configured, with the triggers no longer pending,
                // until postinst triggered succeeds; a failure leaves it to be configured.
                let cfg = config_version(Some(s))
                    .unwrap_or_else(|| s.get("Version").cloned().unwrap_or_default());
                s.insert("Config-Version".into(), cfg);
                s.insert("Status".into(), "install ok half-configured".into());
                s.shift_remove("Triggers-Pending");
                let pkg = Package::from_status(&name, s.clone());
                self.db.save()?;
                let script = self.db.info_lookup(&name, "postinst")?;
                let names: Vec<&str> = names.iter().map(String::as_str).collect();
                self.run_script(
                    &pkg,
                    script.as_deref(),
                    "postinst",
                    &["triggered".into(), names.join(" ")],
                )?;
                self.triggers_done(&key)?;
            }
        }
        Err(Error::new("triggers keep activating each other, giving up"))
    }

    // --- the whole sequence ---

    fn statedir(&self) -> Result<PathBuf> {
        // Resolved in the root (H3).
        self.path(STATEDIR.as_bytes(), true)
    }

    /// Install `pkgs` (in this order), then process the triggers.
    ///
    /// # Errors
    /// A step fails; the database records how far it got, as dpkg's would.
    pub fn install(&mut self, pkgs: &[&'p Package]) -> Result<()> {
        // H5: every triggers file is checked before anything is written.
        for p in pkgs {
            trigger_directives(p)?;
        }
        let state = self.statedir()?;
        let mut todo: Vec<&'p Package> = Vec::new();
        for p in pkgs {
            match decide(&self.db, p, self.opts.reinstall)?.action {
                Action::Skip => {
                    log(&format!("{} {}: unchanged, skipping", p.name, p.version()));
                }
                Action::Configure => {
                    // Its postinst failed: configure it again, as dpkg --configure would.
                    log(&format!(
                        "{} {}: unchanged, half-configured, configuring it",
                        p.name,
                        p.version()
                    ));
                    let cv = config_version(self.db.status.get(&p.name));
                    self.unconfigured.insert(
                        p.name.clone(),
                        Unpacked {
                            pkg: p,
                            config_version: cv,
                        },
                    );
                }
                Action::Install | Action::Upgrade | Action::Downgrade | Action::Reinstall => {
                    todo.push(p);
                }
            }
        }
        // H7: the payload to unpack must match its recorded digest.
        for p in &todo {
            p.verify()?;
        }
        fs::create_dir_all(&state).at(&state)?;
        // Triggers left pending by an earlier run are processed even if nothing changed.
        self.seed_pending();
        if todo.is_empty() && self.unconfigured.is_empty() {
            log("all packages up to date");
            return self.process_triggers();
        }
        if !todo.is_empty() {
            let names: Vec<&str> = todo.iter().map(|p| p.name.as_str()).collect();
            log(&format!("installing: {}", names.join(" ")));
        }
        for p in todo {
            // Pre-Depends must be configured before the package is unpacked.
            for alts in p.relations("Pre-Depends")? {
                self.ensure_configured(&p.name, &alts)?;
            }
            self.unpack_one(p)?;
        }
        let names: Vec<String> = self.unconfigured.keys().cloned().collect();
        for name in names {
            self.configure_unpacked(&name)?;
        }
        self.process_triggers()
    }

    /// Configure a package unpacked in this run that satisfies `alts`, unless an
    /// installed one does, or one being configured (a dependency cycle, broken there as
    /// dpkg does).
    ///
    /// # Errors
    /// Nothing satisfies `alts`, or configuring fails.
    fn ensure_configured(&mut self, of: &str, alts: &[Relation]) -> Result<()> {
        for a in alts {
            if self.db.provider(a)?.is_some() {
                return Ok(());
            }
        }
        for a in alts {
            for p in &self.configuring {
                if p.satisfies(a)? {
                    return Ok(());
                }
            }
        }
        for a in alts {
            let mut found = None;
            for (name, u) in &self.unconfigured {
                if u.pkg.satisfies(a)? {
                    found = Some(name.clone());
                    break;
                }
            }
            if let Some(name) = found {
                return self.configure_unpacked(&name);
            }
        }
        Err(Error::new(format!(
            "{of}: unsatisfied dependency: {}",
            show_alternatives(alts)
        )))
    }

    /// Configure a package unpacked in this run, after the unpacked packages it depends on.
    fn configure_unpacked(&mut self, name: &str) -> Result<()> {
        let Some(u) = self.unconfigured.shift_remove(name) else {
            return Ok(());
        };
        self.configuring.push(u.pkg);
        let deps = (|| {
            for alts in u.pkg.depends()? {
                self.ensure_configured(name, &alts)?;
            }
            Ok(())
        })();
        self.configuring.pop();
        deps?;
        self.configure(u.pkg, u.config_version.as_deref())
    }

    fn configure(&mut self, p: &Package, config_version: Option<&str>) -> Result<()> {
        // postinst configure handles the triggers the package got while unpacked.
        self.triggers.remove(&p.name);
        self.set_state(&p.name, "half-configured", config_version, "ok")?;
        // dpkg passes an empty version to a package never configured.
        let postinst = self.db.info(&p.name, "postinst", false)?;
        self.run_script(
            p,
            Some(&postinst),
            "postinst",
            &["configure".into(), config_version.unwrap_or("").to_owned()],
        )?;
        self.set_state(&p.name, "installed", None, "ok")
    }

    /// var/lib/debbuild-rs/<pkg>.sha256, resolved in the root (H3).
    fn digest_path(&self, name: &str) -> Result<PathBuf> {
        let mut rel = STATEDIR.as_bytes().to_vec();
        rel.extend_from_slice(format!("/{name}.sha256").as_bytes());
        self.path(&rel, true)
    }

    /// Record the digest of the staged package whose files are now on disk: from then
    /// on, a rerun with the same staged package only finishes what is left (configure,
    /// or nothing), whatever happens to the package afterwards.
    fn record_digest(&self, p: &Package) -> Result<()> {
        let f = self.digest_path(&p.name)?;
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o666)
            .open(&f)
            .at(&f)?;
        out.write_all(format!("{}\n", p.digest()?).as_bytes())
            .at(&f)
    }

    /// Forget the recorded digest, before the package's files change on disk: if the
    /// unpack does not complete, they match no staged package.
    fn clear_digest(&self, name: &str) -> Result<()> {
        let f = self.digest_path(name)?;
        match fs::remove_file(&f) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(Error::os(&e, &f)),
            _ => Ok(()),
        }
    }

    /// Unpack one package: dpkg's `process_archive`.
    #[allow(clippy::too_many_lines)] // one sequence, kept in dpkg's order
    fn unpack_one(&mut self, p: &'p Package) -> Result<()> {
        let old: Option<Stanza> = self.db.status.get(&p.name).cloned();
        let prev = old.clone();
        let state = state_of(old.as_ref()).to_owned();
        // not-installed and config-files packages get installed, half-installed and
        // unpacked ones are unpacked again over the old version, the others are upgraded.
        let fresh = is_absent_state(&state);
        let configured = is_installed_state(&state) || state == "half-configured";
        let cfgver = config_version(old.as_ref());
        let old_version = old
            .as_ref()
            .and_then(|o| o.get("Version"))
            .cloned()
            .unwrap_or_default();
        // The version arguments of the scripts, as dpkg passes them.
        let versions: Vec<String> = if state == "not-installed" || old_version.is_empty() {
            Vec::new()
        } else {
            vec![old_version, p.version().to_owned()]
        };
        let with = |first: &str, rest: &[String]| -> Vec<String> {
            std::iter::once(first.to_owned())
                .chain(rest.iter().cloned())
                .collect()
        };
        let new_version = vec![p.version().to_owned()];
        let mut old_files: Vec<Vec<u8>> = Vec::new();
        let lst = self.db.info(&p.name, "list", true)?;
        if state != "not-installed" && fsx::exists(&lst) {
            old_files = fsx::read_lines(&lst)?;
        }

        let tmpci = self.db.path("tmp.ci", false)?;
        fsx::rmtree_quiet(&tmpci);
        Self::copy_debian(p, &tmpci)?;
        let tmp_script = |n: &str| tmpci.join(n);

        let result = (|| -> Result<UnpackResult> {
            let restore = |me: &mut Self| -> Result<()> {
                match &prev {
                    None => {
                        me.db.status.shift_remove(&p.name);
                    }
                    Some(s) => {
                        me.db.status.insert(p.name.clone(), s.clone());
                    }
                }
                me.db.save()
            };
            // dpkg's error unwinding after a failed preinst or unpack
            let unwind = |me: &mut Self| -> Result<bool> {
                if fresh {
                    return me.try_script(
                        p,
                        Some(&tmp_script("postrm")),
                        "postrm",
                        &with("abort-install", &versions),
                    );
                }
                let mut ok = me.try_script(
                    p,
                    Some(&tmp_script("postrm")),
                    "postrm",
                    &with("abort-upgrade", &versions),
                )?;
                if ok && configured {
                    let postinst = me.db.info(&p.name, "postinst", false)?;
                    ok = me.try_script(
                        p,
                        Some(&postinst),
                        "postinst",
                        &with("abort-upgrade", &new_version),
                    )?;
                }
                Ok(ok)
            };

            if configured {
                self.set_state(&p.name, "half-configured", cfgver.as_deref(), "ok")?;
                let prerm = self.db.info(&p.name, "prerm", false)?;
                match self.run_script(p, Some(&prerm), "prerm", &with("upgrade", &new_version)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == Kind::Refusal => {
                        if !self.try_script(
                            p,
                            Some(&tmp_script("prerm")),
                            "prerm",
                            &with("failed-upgrade", &versions),
                        )? {
                            let postinst = self.db.info(&p.name, "postinst", false)?;
                            if self.try_script(
                                p,
                                Some(&postinst),
                                "postinst",
                                &with("abort-upgrade", &new_version),
                            )? {
                                restore(self)?;
                            }
                            return Err(e);
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            // Half-installed until the new files are registered.
            let mut half = match &old {
                Some(_) if !fresh => self.db.status.get(&p.name).cloned().unwrap_or_default(),
                _ => p.control.clone(),
            };
            half.insert("Status".into(), "install reinstreq half-installed".into());
            if let Some(c) = cfgver.as_deref().filter(|c| !c.is_empty()) {
                half.insert("Config-Version".into(), c.to_owned());
            }
            self.db.status.insert(p.name.clone(), half);
            self.db.save()?;
            let verb = if fresh { "install" } else { "upgrade" };
            match self.run_script(
                p,
                Some(&tmp_script("preinst")),
                "preinst",
                &with(verb, &versions),
            ) {
                Ok(()) => {}
                Err(e) if e.kind() == Kind::Refusal => {
                    if unwind(self)? {
                        restore(self)?;
                    }
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
            log(&format!("{}: unpacking {}", p.name, p.version()));
            self.clear_digest(&p.name)?;
            let res = match self.unpack(p, old.as_ref()) {
                Ok(r) => r,
                Err(e) if matches!(e.kind(), Kind::Refusal | Kind::Os) => {
                    // The files are mixed: the package stays half-installed whatever the
                    // scripts do.
                    unwind(self)?;
                    return Err(e);
                }
                Err(e) => return Err(e),
            };
            if !fresh {
                let postrm = self.db.info(&p.name, "postrm", false)?;
                match self.run_script(p, Some(&postrm), "postrm", &with("upgrade", &new_version)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == Kind::Refusal => {
                        self.run_script(
                            p,
                            Some(&tmp_script("postrm")),
                            "postrm",
                            &with("failed-upgrade", &versions),
                        )?;
                    }
                    Err(e) => return Err(e),
                }
            }
            let removed = self.remove_obsolete(&p.name, &old_files, &res)?;
            self.activate_paths(&removed)?;
            self.save_pending()?;
            Ok(res)
        })();
        fsx::rmtree_quiet(&tmpci);
        let res = result?;
        self.register(p, &old_files, &res, cfgver.as_deref())?;
        self.record_digest(p)?;
        self.unconfigured.insert(
            p.name.clone(),
            Unpacked {
                pkg: p,
                config_version: cfgver,
            },
        );
        Ok(())
    }

    /// `copytree(DEBIAN, tmp.ci)`, from the contents read at load time.
    fn copy_debian(p: &Package, tmpci: &Path) -> Result<()> {
        fs::create_dir(tmpci).at(tmpci)?;
        for e in &p.debian {
            let dst = tmpci.join(crate::db::os(&e.name));
            if e.is_dir {
                fs::create_dir(&dst).at(&dst)?;
                continue;
            }
            let data = e.data.as_ref().map_err(Clone::clone)?;
            let mut f = fsx::create(&dst)?;
            f.write_all(data).at(&dst)?;
            drop(f);
            fs::set_permissions(&dst, fs::Permissions::from_mode(e.mode)).at(&dst)?;
        }
        Ok(())
    }
}
