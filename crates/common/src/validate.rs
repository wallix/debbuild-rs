//! The checks dpkg-deb --build makes of a package tree before it builds the .deb: its
//! control directory, control file, maintainer scripts and conffiles.
//!
//! What dpkg-deb refuses is refused, with dpkg-deb's wording; what it only warns about
//! (a missing Maintainer or Description, an invalid architecture name, a conffile that
//! is not a plain file or is listed twice, user-defined fields) passes.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use rustix::io::Errno;

use crate::deb822::{self, Stanza};
use crate::error::{Error, Result, strerror};
use crate::relation::{self, name_problem};
use crate::version;

/// The maintainer scripts dpkg-deb checks the modes of.
pub const MAINTAINER_SCRIPTS: [&str; 5] = ["preinst", "postinst", "prerm", "postrm", "config"];

/// The fields of the status file a control file may not hold.
const STATUS_FIELDS: [&str; 4] = [
    "Status",
    "Config-Version",
    "Triggers-Pending",
    "Triggers-Awaited",
];

/// Check package tree `tree` as dpkg-deb --build does: `tree/DEBIAN` and its control
/// file, maintainer scripts and conffiles. `in_payload` tells whether the file tree
/// holds a conffile, given its name as listed (`/etc/x`); its error is the one of
/// dpkg-deb's `lstat`. Return the control stanza.
///
/// # Errors
/// The first problem dpkg-deb would refuse the tree for, the tree named in the message.
pub fn package(
    tree: &Path,
    mut in_payload: impl FnMut(&[u8]) -> io::Result<bool>,
) -> Result<Stanza> {
    let at = |why: String| Error::new(format!("{}: {why}", tree.display()));
    let debian = tree.join("DEBIAN");
    control_dir(&debian).map_err(at)?;
    let control = debian.join("control");
    let stanza = control_file(&control)
        .map_err(|why| Error::new(format!("{}: {why}", control.display())))?;
    scripts(&debian).map_err(at)?;
    conffiles(&debian, &mut in_payload).map_err(at)?;
    Ok(stanza)
}

/// Why a path of the file tree (as data.tar names it) would install outside the root:
/// an absolute name or a `..` component.
#[must_use]
pub fn payload_path_problem(name: &[u8]) -> Option<&'static str> {
    if name.starts_with(b"/") {
        return Some("absolute path");
    }
    name.split(|&c| c == b'/')
        .any(|c| c == b"..")
        .then_some("'..' component")
}

/// A path as the file tree resolves it, without following symlinks: no leading `/` or
/// `./`, no `.` or empty components, `..` going up.
#[must_use]
pub fn normalize(name: &[u8]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    for c in name.split(|&c| c == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    parts.join(&b'/')
}

/// What a path of the file tree is, as far as looking a path up goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Member {
    Dir,
    /// A symlink, with its target.
    Symlink(Vec<u8>),
    /// Anything else: a file, a hard link, a device.
    Other,
}

/// The symlinks a lookup follows at most, as Linux does (`MAXSYMLINKS`).
const MAX_SYMLINKS: u32 = 40;

/// The file tree of a package as data.tar lists it, to look paths up in it as
/// dpkg-deb --build looks them up under the package tree on disk.
#[derive(Debug, Default)]
pub struct Payload {
    members: HashMap<Vec<u8>, Member>,
}

impl Payload {
    /// Add `name`, a path of data.tar (`./etc/x`), and the directories above it, which
    /// data.tar may not list.
    pub fn insert(&mut self, name: &[u8], member: Member) {
        let path = normalize(name);
        let mut dir = path.as_slice();
        while let Some(parent) = dir
            .iter()
            .rposition(|&c| c == b'/')
            .and_then(|i| dir.get(..i))
        {
            self.members.entry(parent.to_vec()).or_insert(Member::Dir);
            dir = parent;
        }
        self.members.insert(path, member);
    }

    /// Whether `name` (`/etc/x`, as DEBIAN/conffiles lists it) is in the file tree, as
    /// `lstat` of the package tree's `./etc/x` tells: symlinks followed but the last
    /// component (unless a `/` follows it), `..` going up from where they lead. Targets
    /// resolve within the file tree, absolute ones from its root; `..` stops at the root.
    ///
    /// # Errors
    /// `lstat`'s: a component that must be a directory is not one (`ENOTDIR`), too many
    /// symlinks (`ELOOP`).
    pub fn lstat(&self, name: &[u8]) -> io::Result<bool> {
        fn parts(path: &[u8]) -> impl DoubleEndedIterator<Item = &[u8]> {
            path.split(|&c| c == b'/').filter(|c| !c.is_empty())
        }
        let mut todo: VecDeque<&[u8]> = parts(name).collect();
        let follow_last = name.ends_with(b"/");
        let mut path: Vec<&[u8]> = Vec::new();
        let mut links = MAX_SYMLINKS;
        while let Some(c) = todo.pop_front() {
            match c {
                b"." => continue,
                b".." => {
                    path.pop();
                    continue;
                }
                _ => path.push(c),
            }
            let follow = follow_last || !todo.is_empty();
            match self.members.get(&path.join(&b'/')) {
                None => return Ok(false),
                Some(Member::Dir) => {}
                Some(_) if !follow => {}
                Some(Member::Other) => return Err(Errno::NOTDIR.into()),
                Some(Member::Symlink(target)) => {
                    links = links.checked_sub(1).ok_or(Errno::LOOP)?;
                    path.pop();
                    if target.is_empty() {
                        return Ok(false);
                    }
                    if target.starts_with(b"/") {
                        path.clear();
                    }
                    for part in parts(target).rev() {
                        todo.push_front(part);
                    }
                }
            }
        }
        Ok(true)
    }
}

fn control_dir(debian: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(debian).map_err(|e| {
        format!(
            "unable to stat control directory '{}': {}",
            debian.display(),
            strerror(&e)
        )
    })?;
    if !meta.is_dir() {
        return Err("control directory is not a directory".to_owned());
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o7757 != 0o755 {
        return Err(format!(
            "control directory has bad permissions {mode:03o} (must be >=0755 and <=0775)"
        ));
    }
    Ok(())
}

/// A field whose value is empty counts as missing, as with dpkg.
fn get<'a>(stanza: &'a Stanza, name: &str) -> Option<&'a str> {
    stanza
        .get(name)
        .map(String::as_str)
        .filter(|v| !v.is_empty())
}

fn control_file(path: &Path) -> Result<Stanza, String> {
    let text = fs::read_to_string(path).map_err(|e| {
        format!(
            "failed to open package control file for reading: {}",
            strerror(&e)
        )
    })?;
    if let Some(last) = text.rsplit('\n').next()
        && !last.trim_matches([' ', '\t']).is_empty()
    {
        return Err("end of file during value of a field (missing final newline)".to_owned());
    }
    let mut stanzas = deb822::parse_stanzas(&text).map_err(|e| e.message().to_owned())?;
    duplicate_fields(&text)?;
    if stanzas.len() > 1 {
        return Err("several package info entries found, only one allowed".to_owned());
    }
    let stanza = stanzas
        .pop()
        .ok_or_else(|| "no package information".to_owned())?;
    if let Some(f) = STATUS_FIELDS.iter().find(|f| stanza.contains_key(**f)) {
        return Err(format!("value for '{f}' field not allowed in this context"));
    }
    let package = get(&stanza, "Package").ok_or("missing 'Package' field")?;
    if let Some(why) = name_problem(package) {
        return Err(format!("invalid package name in 'Package' field: {why}"));
    }
    if !package
        .to_ascii_lowercase()
        .bytes()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-+.".contains(&c))
    {
        return Err(
            "package name has characters that are not lowercase alphanums or '-+.'".to_owned(),
        );
    }
    let version = get(&stanza, "Version").ok_or("missing 'Version' field")?;
    if let Some(why) = version::problem(version) {
        return Err(format!("'Version' field value '{version}': {why}"));
    }
    let arch = get(&stanza, "Architecture").ok_or("package architecture is missing or empty")?;
    for field in ["Essential", "Protected"] {
        if let Some(v) = stanza.get(field)
            && !matches!(v.to_ascii_lowercase().as_str(), "yes" | "no")
        {
            return Err(format!(
                "boolean (yes/no) '{field}' field: has invalid value '{v}'"
            ));
        }
    }
    if let Some(v) = stanza.get("Multi-Arch") {
        let v = v.to_ascii_lowercase();
        if !matches!(v.as_str(), "no" | "same" | "foreign" | "allowed") {
            return Err(format!(
                "quadstate (foreign/allowed/same/no) 'Multi-Arch' field: has invalid value '{v}'"
            ));
        }
        if v == "same" && arch == "all" {
            return Err(
                "package has 'Multi-Arch: same' field but is architecture 'all'".to_owned(),
            );
        }
    }
    for field in relation::FIELDS {
        relation::parse_field(field, stanza.get(field).map(String::as_str))
            .map_err(|e| e.message().to_owned())?;
    }
    Ok(stanza)
}

/// A field given twice in a stanza (names compare case-insensitively).
fn duplicate_fields(text: &str) -> Result<(), String> {
    let mut seen: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.trim_matches([' ', '\t']).is_empty() {
            seen.clear();
        } else if !line.starts_with([' ', '\t'])
            && let Some((name, _)) = line.split_once(':')
        {
            let lower = name.to_ascii_lowercase();
            if seen.contains(&lower) {
                return Err(format!("duplicate value for '{name}' field"));
            }
            seen.push(lower);
        }
    }
    Ok(())
}

fn scripts(debian: &Path) -> Result<(), String> {
    for name in MAINTAINER_SCRIPTS {
        let path = debian.join(name);
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(format!(
                    "unable to stat maintainer script '{}': {}",
                    path.display(),
                    strerror(&e)
                ));
            }
        };
        if meta.is_symlink() {
            continue;
        }
        if !meta.is_file() {
            return Err(format!(
                "maintainer script '{name}' is not a plain file or symlink"
            ));
        }
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o7557 != 0o555 {
            return Err(format!(
                "maintainer script '{name}' has bad permissions {mode:03o} (must be >=0555 and <=0775)"
            ));
        }
    }
    Ok(())
}

fn conffiles(
    debian: &Path,
    in_payload: &mut impl FnMut(&[u8]) -> io::Result<bool>,
) -> Result<(), String> {
    let text = match fs::read(debian.join("conffiles")) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("error reading conffiles file: {}", strerror(&e))),
    };
    let show = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let mut lines: Vec<&[u8]> = text.split(|&c| c == b'\n').collect();
    // The text after the last newline: empty, unless that newline is missing.
    let last = lines.pop().unwrap_or_default();
    if !last.is_empty() {
        return Err(format!(
            "conffile name '{}' is too long, or missing final newline",
            show(last)
        ));
    }
    for line in lines {
        if line.first().is_some_and(u8::is_ascii_whitespace) {
            let name = line.trim_ascii_start();
            if name.is_empty() {
                return Err(
                    "empty and whitespace-only lines are not allowed in conffiles".to_owned(),
                );
            }
            return Err(format!(
                "line with conffile filename '{}' has leading white spaces",
                show(name)
            ));
        }
        let mut name = line;
        let mut remove_on_upgrade = false;
        if !line.starts_with(b"/") {
            // A flag, a space, then the name.
            let Some(sp) = line.iter().position(|&c| c == b' ') else {
                return Err(format!(
                    "conffile name '{}' is not an absolute pathname",
                    show(line)
                ));
            };
            let (flag, rest) = line.split_at(sp);
            name = rest.get(1..).unwrap_or_default();
            if name.first().is_some_and(|&c| c != b'/') {
                return Err(format!(
                    "conffile name '{}' is not an absolute pathname",
                    show(name)
                ));
            }
            if name.is_empty() {
                return Err(format!("conffile name missing after flag '{}'", show(flag)));
            }
            if flag != b"remove-on-upgrade" {
                return Err(format!(
                    "unknown flag '{}' for conffile '{}'",
                    show(flag),
                    show(name)
                ));
            }
            remove_on_upgrade = true;
        }
        let present = in_payload(name).map_err(|e| {
            format!(
                "conffile '{}' is not stattable: {}",
                show(name),
                strerror(&e)
            )
        })?;
        if present && remove_on_upgrade {
            return Err(format!(
                "conffile '{}' is present but is requested to be removed",
                show(name)
            ));
        }
        if !present && !remove_on_upgrade {
            return Err(format!(
                "conffile '{}' does not appear in package",
                show(name)
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    const CONTROL: &str =
        "Package: p\nVersion: 1\nArchitecture: all\nMaintainer: m <m@x>\nDescription: d\n";

    /// A package tree in `dir`: DEBIAN/ (mode 0755) with `control`, and `etc/c`.
    fn tree(dir: &Path, control: &str) -> std::path::PathBuf {
        let tree = dir.join("p");
        let debian = tree.join("DEBIAN");
        fs::create_dir_all(&debian).unwrap();
        fs::set_permissions(&debian, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(debian.join("control"), control).unwrap();
        fs::create_dir_all(tree.join("etc")).unwrap();
        fs::write(tree.join("etc/c"), "c").unwrap();
        tree
    }

    /// The file tree on disk, looked up as dpkg-deb does.
    fn on_disk(tree: &Path) -> impl FnMut(&[u8]) -> io::Result<bool> {
        use std::os::unix::ffi::OsStrExt;
        let tree = tree.to_path_buf();
        move |name| {
            let mut p = tree.as_os_str().as_bytes().to_vec();
            p.push(b'/');
            p.extend_from_slice(name);
            match fs::symlink_metadata(std::ffi::OsStr::from_bytes(&p)) {
                Ok(_) => Ok(true),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e),
            }
        }
    }

    fn check(tree: &Path) -> Result<Stanza> {
        package(tree, on_disk(tree))
    }

    /// The file tree on disk as data.tar would list it.
    fn payload(tree: &Path) -> Payload {
        use std::os::unix::ffi::OsStrExt;
        fn walk(dir: &Path, name: &[u8], out: &mut Payload) {
            for e in fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let mut n = name.to_vec();
                n.push(b'/');
                n.extend_from_slice(e.file_name().as_bytes());
                if n == b"./DEBIAN" {
                    continue;
                }
                let t = e.file_type().unwrap();
                if t.is_dir() {
                    out.insert(&n, Member::Dir);
                    walk(&e.path(), &n, out);
                } else if t.is_symlink() {
                    let target = fs::read_link(e.path()).unwrap();
                    out.insert(&n, Member::Symlink(target.as_os_str().as_bytes().to_vec()));
                } else {
                    out.insert(&n, Member::Other);
                }
            }
        }
        let mut out = Payload::default();
        walk(tree, b".", &mut out);
        out
    }

    /// [`check`], the file tree looked up in its [`payload`].
    fn check_payload(tree: &Path) -> Result<Stanza> {
        let payload = payload(tree);
        package(tree, |name| payload.lstat(name))
    }

    /// Each case: a setup of the tree, and the problem (None: the tree passes).
    type Case = (&'static str, fn(&Path), Option<&'static str>);

    fn write_control(t: &Path, text: &str) {
        fs::write(t.join("DEBIAN/control"), text).unwrap();
    }

    fn add_control(t: &Path, line: &str) {
        write_control(t, &format!("{CONTROL}{line}\n"));
    }

    fn script(t: &Path, name: &str, mode: u32) {
        let p = t.join("DEBIAN").join(name);
        fs::write(&p, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn conffiles(t: &Path, text: &str) {
        fs::write(t.join("DEBIAN/conffiles"), text).unwrap();
    }

    /// The symlink `etc/foo` to `target`, and conffiles `text`.
    fn link_conffile(t: &Path, target: &str, text: &str) {
        symlink(target, t.join("etc/foo")).unwrap();
        conffiles(t, text);
    }

    const CASES: &[Case] = &[
        ("valid", |_| {}, None),
        (
            "upper case name",
            |t| write_control(t, &CONTROL.replace("Package: p", "Package: P")),
            None,
        ),
        (
            "no maintainer",
            |t| write_control(t, &CONTROL.replace("Maintainer: m <m@x>\n", "")),
            None,
        ),
        (
            "no description",
            |t| write_control(t, &CONTROL.replace("Description: d\n", "")),
            None,
        ),
        (
            "invalid architecture name",
            |t| write_control(t, &CONTROL.replace("all", "a_b")),
            None,
        ),
        ("user field", |t| add_control(t, "X-Foo: 1"), None),
        ("trailing blank lines", |t| add_control(t, "\n"), None),
        (
            "relations",
            |t| {
                add_control(
                    t,
                    "Depends: a (>= 1) | b:any, c\nProvides: v (= 1)\nConflicts: d (<< 2)",
                );
            },
            None,
        ),
        (
            "multi-arch",
            |t| add_control(t, "Multi-Arch: Foreign\nEssential: Yes"),
            None,
        ),
        (
            "control dir 0775",
            |t| fs::set_permissions(t.join("DEBIAN"), fs::Permissions::from_mode(0o775)).unwrap(),
            None,
        ),
        (
            "control dir 0700",
            |t| fs::set_permissions(t.join("DEBIAN"), fs::Permissions::from_mode(0o700)).unwrap(),
            Some("control directory has bad permissions 700 (must be >=0755 and <=0775)"),
        ),
        (
            "control dir 0777",
            |t| fs::set_permissions(t.join("DEBIAN"), fs::Permissions::from_mode(0o777)).unwrap(),
            Some("control directory has bad permissions 777 (must be >=0755 and <=0775)"),
        ),
        (
            "no control file",
            |t| fs::remove_file(t.join("DEBIAN/control")).unwrap(),
            Some("failed to open package control file for reading: No such file or directory"),
        ),
        (
            "empty control file",
            |t| write_control(t, ""),
            Some("no package information"),
        ),
        (
            "missing final newline",
            |t| write_control(t, CONTROL.trim_end()),
            Some("end of file during value of a field (missing final newline)"),
        ),
        (
            "two stanzas",
            |t| add_control(t, "\nPackage: q"),
            Some("several package info entries found, only one allowed"),
        ),
        (
            "duplicate field",
            |t| add_control(t, "version: 2"),
            Some("duplicate value for 'version' field"),
        ),
        (
            "malformed line",
            |t| add_control(t, "X Y"),
            Some("malformed field line: 'X Y'"),
        ),
        (
            "status field",
            |t| add_control(t, "Status: install ok installed"),
            Some("value for 'Status' field not allowed in this context"),
        ),
        (
            "config version",
            |t| add_control(t, "Config-Version: 1"),
            Some("value for 'Config-Version' field not allowed in this context"),
        ),
        (
            "no package",
            |t| write_control(t, &CONTROL.replace("Package: p\n", "")),
            Some("missing 'Package' field"),
        ),
        (
            "bad package name",
            |t| write_control(t, &CONTROL.replace("Package: p", "Package: -p")),
            Some(
                "invalid package name in 'Package' field: must start with an alphanumeric character",
            ),
        ),
        (
            "underscore in package name",
            |t| write_control(t, &CONTROL.replace("Package: p", "Package: p_q")),
            Some("package name has characters that are not lowercase alphanums or '-+.'"),
        ),
        (
            "no version",
            |t| write_control(t, &CONTROL.replace("Version: 1\n", "")),
            Some("missing 'Version' field"),
        ),
        (
            "bad version",
            |t| write_control(t, &CONTROL.replace("Version: 1", "Version: a1")),
            Some("'Version' field value 'a1': version number does not start with digit"),
        ),
        (
            "no architecture",
            |t| write_control(t, &CONTROL.replace("Architecture: all\n", "")),
            Some("package architecture is missing or empty"),
        ),
        (
            "empty architecture",
            |t| write_control(t, &CONTROL.replace("Architecture: all", "Architecture:")),
            Some("package architecture is missing or empty"),
        ),
        (
            "bad essential",
            |t| add_control(t, "Essential: maybe"),
            Some("boolean (yes/no) 'Essential' field: has invalid value 'maybe'"),
        ),
        (
            "bad protected",
            |t| add_control(t, "Protected: x"),
            Some("boolean (yes/no) 'Protected' field: has invalid value 'x'"),
        ),
        (
            "bad multi-arch",
            |t| add_control(t, "Multi-Arch: bogus"),
            Some(
                "quadstate (foreign/allowed/same/no) 'Multi-Arch' field: has invalid value 'bogus'",
            ),
        ),
        (
            "multi-arch same on all",
            |t| add_control(t, "Multi-Arch: same"),
            Some("package has 'Multi-Arch: same' field but is architecture 'all'"),
        ),
        (
            "bad depends",
            |t| add_control(t, "Depends: a (>> )"),
            Some(
                "'Depends' field 'a (>> )': reference to 'a': version '': version string is empty",
            ),
        ),
        (
            "provides with an inequality",
            |t| add_control(t, "Provides: a (>= 1)"),
            Some("'Provides' field 'a (>= 1)': only exact versions may be used"),
        ),
        (
            "alternatives in conflicts",
            |t| add_control(t, "Conflicts: a | b"),
            Some("'Conflicts' field 'a | b': alternatives ('|') not allowed"),
        ),
        (
            "scripts 0555 and 0775",
            |t| {
                script(t, "postinst", 0o555);
                script(t, "prerm", 0o775);
                fs::write(t.join("DEBIAN/templates"), "").unwrap();
            },
            None,
        ),
        (
            "script symlink",
            |t| std::os::unix::fs::symlink("/nonexistent", t.join("DEBIAN/postinst")).unwrap(),
            None,
        ),
        (
            "preinst 0644",
            |t| script(t, "preinst", 0o644),
            Some("maintainer script 'preinst' has bad permissions 644 (must be >=0555 and <=0775)"),
        ),
        (
            "config 0777",
            |t| script(t, "config", 0o777),
            Some("maintainer script 'config' has bad permissions 777 (must be >=0555 and <=0775)"),
        ),
        (
            "postrm setuid",
            |t| script(t, "postrm", 0o4755),
            Some("maintainer script 'postrm' has bad permissions 4755 (must be >=0555 and <=0775)"),
        ),
        (
            "script directory",
            |t| fs::create_dir(t.join("DEBIAN/postinst")).unwrap(),
            Some("maintainer script 'postinst' is not a plain file or symlink"),
        ),
        ("conffile", |t| conffiles(t, "/etc/c\n"), None),
        ("empty conffiles", |t| conffiles(t, ""), None),
        (
            "conffile directory",
            |t| conffiles(t, "/etc\n/etc/c\n/etc/c\n"),
            None,
        ),
        (
            "conffile resolved",
            |t| conffiles(t, "//etc/../etc/./c\n"),
            None,
        ),
        (
            "removed conffile absent",
            |t| conffiles(t, "remove-on-upgrade /etc/gone\n"),
            None,
        ),
        (
            "conffile missing",
            |t| conffiles(t, "/etc/nope\n"),
            Some("conffile '/etc/nope' does not appear in package"),
        ),
        (
            "conffile with trailing space",
            |t| conffiles(t, "/etc/c \n"),
            Some("conffile '/etc/c ' does not appear in package"),
        ),
        (
            "relative conffile",
            |t| conffiles(t, "etc/c\n"),
            Some("conffile name 'etc/c' is not an absolute pathname"),
        ),
        (
            "conffiles without final newline",
            |t| conffiles(t, "/etc/c"),
            Some("conffile name '/etc/c' is too long, or missing final newline"),
        ),
        (
            "empty conffile line",
            |t| conffiles(t, "/etc/c\n\n"),
            Some("conffile name '' is not an absolute pathname"),
        ),
        (
            "blank conffile line",
            |t| conffiles(t, "/etc/c\n  \n"),
            Some("empty and whitespace-only lines are not allowed in conffiles"),
        ),
        (
            "indented conffile",
            |t| conffiles(t, " /etc/c\n"),
            Some("line with conffile filename '/etc/c' has leading white spaces"),
        ),
        (
            "removed conffile present",
            |t| conffiles(t, "remove-on-upgrade /etc/c\n"),
            Some("conffile '/etc/c' is present but is requested to be removed"),
        ),
        (
            "unknown conffile flag",
            |t| conffiles(t, "bogus /etc/c\n"),
            Some("unknown flag 'bogus' for conffile '/etc/c'"),
        ),
        (
            "flag without conffile",
            |t| conffiles(t, "remove-on-upgrade \n"),
            Some("conffile name missing after flag 'remove-on-upgrade'"),
        ),
        (
            "flag before a relative conffile",
            |t| conffiles(t, "remove-on-upgrade  /etc/c\n"),
            Some("conffile name ' /etc/c' is not an absolute pathname"),
        ),
        (
            "conffile under a file",
            |t| conffiles(t, "/etc/c/\n"),
            Some("conffile '/etc/c/' is not stattable: Not a directory"),
        ),
        (
            "conffile under a symlinked directory",
            |t| {
                link_conffile(t, "real", "/etc/foo/x.conf\n");
                fs::create_dir(t.join("etc/real")).unwrap();
                fs::write(t.join("etc/real/x.conf"), "").unwrap();
            },
            None,
        ),
        (
            "conffile under a chain of symlinks",
            |t| {
                link_conffile(t, "../usr/./bar", "/etc/foo/x.conf\n");
                fs::create_dir_all(t.join("usr/real")).unwrap();
                symlink("real/", t.join("usr/bar")).unwrap();
                fs::write(t.join("usr/real/x.conf"), "").unwrap();
            },
            None,
        ),
        (
            "conffile .. after a symlink",
            |t| {
                link_conffile(t, "real/sub", "/etc/foo/../x.conf\n");
                fs::create_dir_all(t.join("etc/real/sub")).unwrap();
                fs::write(t.join("etc/real/x.conf"), "").unwrap();
            },
            None,
        ),
        (
            "conffile .. after a symlink, missing",
            |t| {
                link_conffile(t, "real/sub", "/etc/foo/../c\n");
                fs::create_dir_all(t.join("etc/real/sub")).unwrap();
            },
            Some("conffile '/etc/foo/../c' does not appear in package"),
        ),
        (
            "conffile symlink",
            |t| link_conffile(t, "c", "/etc/foo\n"),
            None,
        ),
        (
            "dangling conffile symlink",
            |t| link_conffile(t, "nowhere", "/etc/foo\n"),
            None,
        ),
        (
            "conffile symlink to a directory, with a slash",
            |t| {
                link_conffile(t, ".", "/etc/foo/\n");
            },
            None,
        ),
        (
            "conffile symlink to a file, with a slash",
            |t| link_conffile(t, "c", "/etc/foo/\n"),
            Some("conffile '/etc/foo/' is not stattable: Not a directory"),
        ),
        (
            "conffile under a dangling symlink",
            |t| link_conffile(t, "nowhere", "/etc/foo/x.conf\n"),
            Some("conffile '/etc/foo/x.conf' does not appear in package"),
        ),
        (
            "conffile under a symlink to a file",
            |t| link_conffile(t, "c", "/etc/foo/x.conf\n"),
            Some("conffile '/etc/foo/x.conf' is not stattable: Not a directory"),
        ),
        (
            "conffile under a symlink loop",
            |t| {
                link_conffile(t, "bar", "/etc/foo/x.conf\n");
                symlink("foo", t.join("etc/bar")).unwrap();
            },
            // The libc's message: glibc's and musl's differ.
            Some("conffile '/etc/foo/x.conf' is not stattable: {ELOOP}"),
        ),
        (
            "conffiles directory",
            |t| fs::create_dir(t.join("DEBIAN/conffiles")).unwrap(),
            Some("error reading conffiles file: Is a directory"),
        ),
    ];

    #[test]
    fn cases() {
        for (what, setup, problem) in CASES {
            let tmp = tempdir();
            let t = tree(&tmp, CONTROL);
            setup(&t);
            let on_disk = check(&t);
            assert_eq!(check_payload(&t), on_disk, "{what}: in the payload");
            match (on_disk, problem) {
                (Ok(_), None) => {}
                (Err(e), Some(why)) => {
                    let file = if why.starts_with("control directory")
                        || why.contains("maintainer script")
                        || why.contains("conffile")
                    {
                        t.display().to_string()
                    } else {
                        t.join("DEBIAN/control").display().to_string()
                    };
                    let why = why.replace("{ELOOP}", &strerror(&Errno::LOOP.into()));
                    assert_eq!(e.message(), format!("{file}: {why}"), "{what}");
                }
                (r, _) => panic!("{what}: {r:?}"),
            }
            fs::remove_dir_all(&tmp).unwrap();
        }
    }

    /// The cases dpkg-deb --build refuses since dpkg 1.22, and only warns about before.
    const WARNED_BEFORE_1_22: [&str; 1] = ["provides with an inequality"];

    /// dpkg-deb --build refuses the same trees.
    #[test]
    fn cases_against_dpkg_deb() {
        if Command::new("dpkg-deb").arg("--version").output().is_err() {
            assert!(
                std::env::var_os("DEBBUILD_RS_TEST_REQUIRE_TOOLS").is_none(),
                "no dpkg-deb"
            );
            eprintln!("skipped: no dpkg-deb");
            return;
        }
        let mut mismatches = Vec::new();
        for (what, setup, problem) in CASES {
            let tmp = tempdir();
            let t = tree(&tmp, CONTROL);
            setup(&t);
            let o = Command::new("dpkg-deb")
                .args(["--root-owner-group", "--build"])
                .arg(&t)
                .arg(tmp.join("p.deb"))
                .output()
                .unwrap();
            // dpkg before 1.22 (Debian 12) only warns about some of them.
            let warned = o.status.success()
                && WARNED_BEFORE_1_22.contains(what)
                && String::from_utf8_lossy(&o.stderr).contains("warning");
            if o.status.success() != problem.is_none() && !warned {
                mismatches.push(format!("{what}: {}", String::from_utf8_lossy(&o.stderr)));
            }
            fs::remove_dir_all(&tmp).unwrap();
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "debbuild-rs-validate-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// What the file tree on disk cannot show: targets resolved within the payload.
    #[test]
    fn payload_lookups() {
        let mut p = Payload::default();
        p.insert(b"./etc/real/x", Member::Other);
        p.insert(b"./etc/abs", Member::Symlink(b"/etc/real".to_vec()));
        p.insert(b"./etc/up", Member::Symlink(b"../../../etc/real".to_vec()));
        p.insert(b"./etc/empty", Member::Symlink(Vec::new()));
        for (name, found) in [
            (&b"/etc/abs/x"[..], true),
            (b"/etc/up/x", true),
            (b"/../../etc/real/x", true),
            (b"/etc/real/../real/x", true),
            (b"/etc/abs/y", false),
            (b"/etc/empty", true),
            (b"/etc/empty/", false),
            (b"/", true),
        ] {
            assert_eq!(
                p.lstat(name).unwrap(),
                found,
                "{}",
                String::from_utf8_lossy(name)
            );
        }
        // A chain of MAX_SYMLINKS links resolves, one more does not.
        let mut p = Payload::default();
        p.insert(b"./d/x", Member::Other);
        for i in 0..=MAX_SYMLINKS {
            let target = if i == 0 {
                "d".to_owned()
            } else {
                format!("l{}", i - 1)
            };
            p.insert(
                format!("./l{i}").as_bytes(),
                Member::Symlink(target.into_bytes()),
            );
        }
        assert!(
            p.lstat(format!("/l{}/x", MAX_SYMLINKS - 1).as_bytes())
                .unwrap()
        );
        let e = p
            .lstat(format!("/l{MAX_SYMLINKS}/x").as_bytes())
            .unwrap_err();
        assert_eq!(e.raw_os_error(), Some(Errno::LOOP.raw_os_error()));
    }

    #[test]
    fn payload_paths() {
        assert_eq!(payload_path_problem(b"./usr/bin/x"), None);
        assert_eq!(payload_path_problem(b"./a..b/"), None);
        assert_eq!(payload_path_problem(b"/etc/x"), Some("absolute path"));
        assert_eq!(payload_path_problem(b"./a/../../x"), Some("'..' component"));
        assert_eq!(normalize(b"./usr/bin/"), b"usr/bin");
        assert_eq!(normalize(b"//etc/../etc/./c"), b"etc/c");
        assert_eq!(normalize(b"./"), b"");
    }
}
