//! The dpkg database of the target root: status, info/, triggers/, locks.
//!
//! Every path below var/lib/dpkg is resolved inside the root (H4): a symlink there
//! cannot make the installer read or write outside it.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use nix::fcntl::{FcntlArg, fcntl};
use nix::libc;

use debbuild_rs_common::deb822::{Stanza, format_stanza, parse_stanzas, state_of};
use debbuild_rs_common::relation::{FIELDS, Relation, parse_status_field};
use debbuild_rs_common::{Error, IoContext, Result};

use crate::confine::confined;
use crate::fsx;

pub const ADMINDIR: &str = "var/lib/dpkg";

/// Package states that satisfy a dependency.
pub const INSTALLED_STATES: [&str; 3] = ["installed", "triggers-pending", "triggers-awaited"];
/// Package states without files on disk, other than conffiles.
pub const ABSENT_STATES: [&str; 2] = ["not-installed", "config-files"];

#[must_use]
pub fn is_installed_state(state: &str) -> bool {
    INSTALLED_STATES.contains(&state)
}

#[must_use]
pub fn is_absent_state(state: &str) -> bool {
    ABSENT_STATES.contains(&state)
}

pub struct Database {
    pub root: PathBuf,
    /// Package (`Package:Arch` for Multi-Arch: same) -> its status entry, in file order.
    pub status: IndexMap<String, Stanza>,
    /// What dpkg would warn about reading the status file.
    pub warnings: Vec<String>,
}

/// The dpkg locks, held until dropped.
pub struct Lock {
    _files: Vec<File>,
}

impl Database {
    #[must_use]
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            status: IndexMap::new(),
            warnings: Vec::new(),
        }
    }

    /// `rel` below var/lib/dpkg, resolved in the root; the last component is followed
    /// with `follow`.
    ///
    /// # Errors
    /// The resolution fails (symlink loop, lstat error).
    pub fn path(&self, rel: &str, follow: bool) -> Result<PathBuf> {
        let mut p = ADMINDIR.as_bytes().to_vec();
        if !rel.is_empty() {
            p.push(b'/');
            p.extend_from_slice(rel.as_bytes());
        }
        confined(&self.root, &p, follow)
    }

    /// `path`, for a name that may not be UTF-8.
    ///
    /// # Errors
    /// See [`Database::path`].
    pub fn path_bytes(&self, dir: &str, name: &[u8], follow: bool) -> Result<PathBuf> {
        let mut p = ADMINDIR.as_bytes().to_vec();
        p.push(b'/');
        p.extend_from_slice(dir.as_bytes());
        p.push(b'/');
        p.extend_from_slice(name);
        confined(&self.root, &p, follow)
    }

    /// The admin directory itself (var/lib/dpkg, symlinks followed in the root).
    ///
    /// # Errors
    /// See [`Database::path`].
    pub fn admindir(&self) -> Result<PathBuf> {
        self.path("", true)
    }

    /// Hold the dpkg locks (lock-frontend, then lock), so that dpkg or apt cannot run
    /// concurrently: fcntl record locks, as dpkg and apt take them.
    ///
    /// # Errors
    /// A lock is held by another process, or cannot be opened.
    pub fn lock(&self) -> Result<Lock> {
        let mut files = Vec::new();
        for name in ["lock-frontend", "lock"] {
            let p = self.path(name, true)?;
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o640)
                .open(&p)
                .at(&p)?;
            let fl = libc::flock {
                l_type: libc::c_short::try_from(libc::F_WRLCK).unwrap_or(1),
                l_whence: libc::c_short::try_from(libc::SEEK_SET).unwrap_or(0),
                l_start: 0,
                l_len: 0,
                l_pid: 0,
            };
            if fcntl(&f, FcntlArg::F_SETLK(&fl)).is_err() {
                return Err(Error::new(format!(
                    "{} is locked: is dpkg or apt running?",
                    p.display()
                )));
            }
            files.push(f);
        }
        Ok(Lock { _files: files })
    }

    /// Reject an interrupted dpkg journal, as dpkg does.
    ///
    /// # Errors
    /// updates/ holds something other than tmp.i.
    pub fn check_interrupted(&self) -> Result<()> {
        let updates = self.path("updates", true)?;
        if !fsx::is_dir(&updates) {
            return Ok(());
        }
        for e in fs::read_dir(&updates).at(&updates)? {
            let e = e.at(&updates)?;
            if e.file_name() != "tmp.i" {
                return Err(Error::new(
                    "dpkg was interrupted, you must manually run 'dpkg --configure -a' to correct the problem",
                ));
            }
        }
        Ok(())
    }

    fn key(s: &Stanza) -> Result<String> {
        let package = s
            .get("Package")
            .ok_or_else(|| Error::value("status: an entry has no Package field"))?;
        // Multi-Arch: same packages can be installed once per architecture.
        Ok(if s.get("Multi-Arch").map(String::as_str) == Some("same") {
            format!(
                "{package}:{}",
                s.get("Architecture").map_or("None", String::as_str)
            )
        } else {
            package.clone()
        })
    }

    /// Read the status file, with its relationship fields as dpkg reads them: what dpkg
    /// refuses in its database is an error, as for dpkg, whichever package it is in;
    /// what it only warns about goes to `warnings`.
    ///
    /// # Errors
    /// It cannot be read or parsed.
    pub fn load(&mut self) -> Result<()> {
        let p = self.path("status", true)?;
        let text = fsx::read_text(&p)?;
        let mut status = IndexMap::new();
        let mut warnings = Vec::new();
        for s in parse_stanzas(&text)? {
            let key = Self::key(&s)?;
            let at = |msg: &str| {
                format!(
                    "parsing file '{}' package '{}': {msg}",
                    p.display(),
                    s.get("Package").map_or("", String::as_str)
                )
            };
            for field in FIELDS {
                let (_, w) = parse_status_field(field, s.get(field).map(String::as_str))
                    .map_err(|e| Error::new(at(e.message())))?;
                warnings.extend(w.iter().map(|w| at(w)));
            }
            status.insert(key, s);
        }
        self.status = status;
        self.warnings = warnings;
        Ok(())
    }

    /// Write `data` to `rel` below var/lib/dpkg durably (temporary file, fsync,
    /// rename); `tmp_name` defaults to `<name>.debbuild-rs-new`.
    ///
    /// # Errors
    /// Any step fails.
    pub fn write_atomic(
        &self,
        rel: &[u8],
        data: &[u8],
        mode: Option<u32>,
        tmp_name: Option<&str>,
    ) -> Result<()> {
        let (dir, name) = match rel.iter().rposition(|&c| c == b'/') {
            Some(i) => (
                rel.get(..i).unwrap_or_default(),
                rel.get(i.saturating_add(1)..).unwrap_or_default(),
            ),
            None => (&b""[..], rel),
        };
        let tmp: Vec<u8> = match tmp_name {
            Some(t) => t.as_bytes().to_vec(),
            None => [name, b".debbuild-rs-new"].concat(),
        };
        let dir = std::str::from_utf8(dir).unwrap_or_default();
        let resolve = |n: &[u8], follow: bool| {
            if dir.is_empty() {
                self.path(std::str::from_utf8(n).unwrap_or_default(), follow)
            } else {
                self.path_bytes(dir, n, follow)
            }
        };
        fsx::write_atomic(
            &resolve(name, false)?,
            &resolve(&tmp, false)?,
            &resolve(&tmp, true)?,
            data,
            mode,
        )
    }

    /// Write the status file: entries sorted by package name, then architecture, each
    /// followed by an empty line; the previous one kept as status-old.
    ///
    /// # Errors
    /// The files cannot be written.
    pub fn save(&self) -> Result<()> {
        let mut entries: Vec<&Stanza> = self.status.values().collect();
        entries.sort_by(|a, b| {
            let k = |s: &Stanza| {
                (
                    s.get("Package").cloned().unwrap_or_default(),
                    s.get("Architecture").cloned().unwrap_or_default(),
                )
            };
            k(a).cmp(&k(b))
        });
        let status = self.path("status", true)?;
        fsx::copy2(&status, &self.path("status-old", true)?)?;
        let mut data = String::new();
        for s in entries {
            data.push_str(&format_stanza(s));
            data.push('\n');
        }
        self.write_atomic(b"status", data.as_bytes(), None, Some("status-new"))
    }

    /// The installed package called `name`, whether or not it is Multi-Arch: same.
    #[must_use]
    pub fn installed(&self, name: &str) -> Option<&Stanza> {
        let prefix = format!("{name}:");
        self.status
            .get(name)
            .into_iter()
            .chain(
                self.status
                    .iter()
                    .filter(|(k, _)| k.starts_with(&prefix))
                    .map(|(_, s)| s),
            )
            .find(|s| is_installed_state(state_of(Some(s))))
    }

    /// The installed package satisfying `rel`, directly or through Provides.
    ///
    /// # Errors
    /// An invalid version or Provides field.
    pub fn provider(&self, rel: &Relation) -> Result<Option<String>> {
        self.provider_except(rel, &|_| false)
    }

    /// [`Database::provider`], ignoring the packages `skip` names (the ones a plan
    /// replaces).
    ///
    /// # Errors
    /// An invalid version or Provides field.
    pub fn provider_except(
        &self,
        rel: &Relation,
        skip: &dyn Fn(&str) -> bool,
    ) -> Result<Option<String>> {
        if !skip(&rel.name)
            && let Some(s) = self.installed(&rel.name)
            && rel.matches(s.get("Version").map(String::as_str))?
        {
            return Ok(Some(rel.name.clone()));
        }
        for (key, s) in &self.status {
            if !is_installed_state(state_of(Some(s)))
                || skip(s.get("Package").map_or("", String::as_str))
            {
                continue;
            }
            for p in status_relations(s, "Provides")? {
                if let Some(p) = p.first()
                    && p.name == rel.name
                    && rel.matches(p.version.as_deref())?
                {
                    return Ok(Some(key.clone()));
                }
            }
        }
        Ok(None)
    }

    /// `info/<pkg>.<what>`, resolved in the root.
    ///
    /// # Errors
    /// See [`Database::path`].
    pub fn info(&self, pkg: &str, what: &str, follow: bool) -> Result<PathBuf> {
        self.path(&format!("info/{pkg}.{what}"), follow)
    }

    /// `info/<pkg>.<what>`, or the one of `<pkg>:<arch>`, if it exists: (as the
    /// maintainer script path, followed).
    ///
    /// # Errors
    /// See [`Database::path`].
    pub fn info_lookup(&self, pkg: &str, what: &str) -> Result<Option<PathBuf>> {
        let prefix = format!("{pkg}:");
        let names = std::iter::once(pkg).chain(
            self.status
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .map(String::as_str),
        );
        for name in names {
            if fsx::exists(&self.info(name, what, true)?) {
                return Ok(Some(self.info(name, what, false)?));
            }
        }
        Ok(None)
    }

    /// The names in info/ (a missing directory has none).
    ///
    /// # Errors
    /// The directory cannot be read.
    pub fn info_names(&self) -> Result<Vec<Vec<u8>>> {
        let info = self.path("info", true)?;
        let rd = match fs::read_dir(&info) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            r => r.at(&info)?,
        };
        let mut out = Vec::new();
        for e in rd {
            out.push(e.at(&info)?.file_name().as_bytes().to_vec());
        }
        Ok(out)
    }

    /// File path -> the packages listing it, from every info/*.list.
    ///
    /// # Errors
    /// A list cannot be read.
    pub fn file_owners(&self) -> Result<BTreeMap<Vec<u8>, BTreeSet<String>>> {
        let mut owners: BTreeMap<Vec<u8>, BTreeSet<String>> = BTreeMap::new();
        for name in self.info_names()? {
            let Some(pkg) = name.strip_suffix(b".list") else {
                continue;
            };
            let pkg = String::from_utf8_lossy(pkg).into_owned();
            for line in fsx::read_lines(&self.path_bytes("info", &name, true)?)? {
                owners.entry(line).or_default().insert(pkg.clone());
            }
        }
        Ok(owners)
    }

    /// A path inside the root, as the root sees it (`/...`).
    #[must_use]
    pub fn rel(&self, p: &Path) -> String {
        format!("/{}", p.strip_prefix(&self.root).unwrap_or(p).display())
    }
}

/// Relationship field `field` of status entry `s`, as dpkg reads its database (see
/// [`Database::load`], which reports what it warns about).
///
/// # Errors
/// What dpkg refuses in the field.
pub fn status_relations(s: &Stanza, field: &str) -> Result<Vec<Vec<Relation>>> {
    Ok(parse_status_field(field, s.get(field).map(String::as_str))?.0)
}

/// `OsStr` of bytes.
#[must_use]
pub fn os(b: &[u8]) -> &OsStr {
    OsStr::from_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_dpkg() {
        let t = tempfile::tempdir().unwrap();
        let updates = t.path().join("var/lib/dpkg/updates");
        fs::create_dir_all(&updates).unwrap();
        fs::write(updates.join("tmp.i"), "").unwrap();
        let db = Database::new(t.path());
        db.check_interrupted().unwrap();
        fs::write(updates.join("0001"), "").unwrap();
        assert!(
            db.check_interrupted()
                .unwrap_err()
                .message()
                .contains("dpkg --configure -a")
        );
    }
}
