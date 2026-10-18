//! Manifests of the paths an installation touched.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::util::{Context, Result};

/// The bookkeeping each tool keeps for itself, never compared
/// (check-against-dpkg.sh's list).
pub const IGNORED: [&str; 12] = [
    "tmp",
    "usr/sbin/policy-rc.d",
    "var/lib/debbuild-rs",
    "var/log/dpkg.log",
    "var/log/alternatives.log",
    "var/lib/dpkg/status-old",
    "var/lib/dpkg/available",
    "var/lib/dpkg/available-old",
    "var/lib/dpkg/diversions-old",
    "var/lib/dpkg/statoverride-old",
    "var/lib/dpkg/lock",
    "var/lib/dpkg/lock-frontend",
];

fn ignored(path: &str, extra: &[&str]) -> bool {
    let rel = path.trim_start_matches('/');
    IGNORED
        .iter()
        .chain(["var/lib/dpkg/triggers/Lock"].iter())
        .chain(extra.iter())
        .any(|i| rel == *i || rel.starts_with(&format!("{i}/")))
}

fn walk(dir: &Path, rel: &str, out: &mut BTreeSet<String>) -> io::Result<()> {
    for e in fs::read_dir(dir)? {
        let e = e?;
        let name = String::from_utf8_lossy(e.file_name().as_bytes()).into_owned();
        let r = format!("{rel}/{name}");
        let is_dir = e.file_type()?.is_dir();
        out.insert(r.clone());
        if is_dir {
            walk(&e.path(), &r, out)?;
        }
    }
    Ok(())
}

/// Every path below the upper directories.
///
/// # Errors
/// An upper directory cannot be read.
pub fn touched_all(uppers: &[&Path]) -> Result<Vec<String>> {
    let mut all = BTreeSet::new();
    for u in uppers {
        walk(u, "", &mut all).ctx(u.display())?;
    }
    Ok(all.into_iter().collect())
}

/// The paths below the upper directories, minus the ignored ones (and `extra`).
///
/// # Errors
/// An upper directory cannot be read.
pub fn touched(uppers: &[&Path], extra: &[&str]) -> Result<Vec<String>> {
    Ok(touched_all(uppers)?
        .into_iter()
        .filter(|p| !ignored(p, extra))
        .collect())
}

/// The hex sha256 of a file.
///
/// # Errors
/// It cannot be read.
pub fn sha256(p: &Path) -> io::Result<String> {
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(buf.get(..n).unwrap_or_default());
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn name_of(uid: u32, gid: u32) -> String {
    let u = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map_or_else(|| "UNKNOWN".to_owned(), |u| u.name);
    let g = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))
        .ok()
        .flatten()
        .map_or_else(|| "UNKNOWN".to_owned(), |g| g.name);
    format!("{u}:{g}")
}

fn kind(m: &fs::Metadata) -> &'static str {
    let t = m.file_type();
    if t.is_fifo() {
        "fifo"
    } else if t.is_socket() {
        "socket"
    } else if t.is_char_device() {
        "character special file"
    } else if t.is_block_device() {
        "block special file"
    } else {
        "unknown"
    }
}

/// check-against-dpkg.sh's manifest line of `path` in `merged`: owners as names (from
/// this system's databases), no mtimes.
#[must_use]
pub fn ck_line(merged: &Path, path: &str) -> String {
    let p = merged.join(path.trim_start_matches('/'));
    let Ok(l) = fs::symlink_metadata(&p) else {
        return format!("{path} absent");
    };
    if l.file_type().is_symlink() {
        let target = fs::read_link(&p)
            .map(|t| t.to_string_lossy().into_owned())
            .unwrap_or_default();
        return format!("{path} link {} {target}", name_of(l.uid(), l.gid()));
    }
    let m = fs::metadata(&p).unwrap_or(l);
    let mode = format!("{:o}", m.mode() & 0o7777);
    let owner = name_of(m.uid(), m.gid());
    if m.is_dir() {
        format!("{path} dir {mode} {owner}")
    } else if m.is_file() {
        format!(
            "{path} file {mode} {owner} {}",
            sha256(&p).unwrap_or_default()
        )
    } else {
        format!("{path} other {} {mode} {owner}", kind(&m))
    }
}

/// The strict manifest line of `path` in `merged`: numeric owners; the mtime of a
/// regular file when `mtime` says so.
#[must_use]
pub fn strict_line(merged: &Path, path: &str, mtime: bool) -> String {
    let p = merged.join(path.trim_start_matches('/'));
    let Ok(m) = fs::symlink_metadata(&p) else {
        return format!("{path} absent");
    };
    let ids = format!("{}:{}", m.uid(), m.gid());
    let mode = format!("{:o}", m.mode() & 0o7777);
    if m.file_type().is_symlink() {
        let target = fs::read_link(&p)
            .map(|t| t.to_string_lossy().into_owned())
            .unwrap_or_default();
        format!("{path} link {ids} {target}")
    } else if m.is_dir() {
        format!("{path} dir {mode} {ids}")
    } else if m.is_file() {
        let t = if mtime {
            format!(" mtime {}", m.mtime())
        } else {
            String::new()
        };
        format!(
            "{path} file {mode} {ids} {}{t}",
            sha256(&p).unwrap_or_default()
        )
    } else {
        format!("{path} other {} {mode} {ids}", kind(&m))
    }
}

/// The hard-link classes among `paths`: paths sharing an inode, one line per class.
#[must_use]
pub fn hardlink_classes(merged: &Path, paths: &[String]) -> Vec<String> {
    let mut classes: BTreeMap<(u64, u64), Vec<&str>> = BTreeMap::new();
    for path in paths {
        let p = merged.join(path.trim_start_matches('/'));
        if let Ok(m) = fs::symlink_metadata(&p)
            && !m.is_dir()
            && m.nlink() > 1
        {
            classes.entry((m.dev(), m.ino())).or_default().push(path);
        }
    }
    let mut out: Vec<String> = classes
        .into_values()
        .filter(|c| c.len() > 1)
        .map(|c| format!("hardlinks: {}", c.join(" ")))
        .collect();
    out.sort();
    out
}
