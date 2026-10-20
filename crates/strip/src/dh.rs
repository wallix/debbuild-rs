//! `dh_strip_nondeterminism`, native: `debbuild-rs stage` puts this binary first in
//! the PATH of debian/rules under that name.
//!
//! As debhelper's: the packages are those `dh_listpackages` selects with the same
//! options (`-p`, `-N`, `-i`, `-a`, `DH_OPTIONS`...); every regular file under each
//! package's build directory (debian/<package>, or `-P`) is normalized, except those
//! whose path, as `debian/<package>/...`, contains an `-X` item; of the names left, each
//! inode once (an excluded name does not hide another one of its inode).
//! The timestamp is the date of the latest debian/changelog entry, else
//! `SOURCE_DATE_EPOCH`, else 0.
//!
//! `-v` (or `DH_VERBOSE`) names each file rewritten, with its handler: debhelper's
//! helper prints other lines, for every file a handler takes.
//!
//! With `DEBBUILD_RS_STRIP_PYC` set, the .pyc files are normalized too, as
//! add-determinism does: an option debhelper's helper does not have, and which leaves
//! the output debhelper's otherwise.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::{Normalizers, Options, Result, Target, io_err, strip, tree};

/// Set (non-empty) to normalize the .pyc files as add-determinism does.
pub const PYC: &str = "DEBBUILD_RS_STRIP_PYC";

const ME: &str = "dh_strip_nondeterminism (debbuild-rs)";

/// The options this helper acts on itself; `dh_listpackages` gets all of them.
#[derive(Default)]
struct Opts {
    excludes: Vec<String>,
    tmpdir: Option<String>,
    verbose: bool,
}

fn parse(args: &[String], o: &mut Opts) {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |short: &str, long: &str| -> Option<String> {
            if a == short || a == long {
                it.next().cloned()
            } else if let Some(v) = a.strip_prefix(&format!("{long}=")) {
                Some(v.to_owned())
            } else {
                a.strip_prefix(short)
                    .filter(|v| !v.is_empty() && !a.starts_with("--"))
                    .map(str::to_owned)
            }
        };
        if let Some(v) = value("-X", "--exclude") {
            o.excludes.push(v);
        } else if let Some(v) = value("-P", "--tmpdir") {
            o.tmpdir = Some(v);
        } else if a == "-v" || a == "--verbose" {
            o.verbose = true;
        } else if let Some(opt) = a.strip_prefix("-O") {
            parse(&[opt.to_owned()], o);
        }
    }
}

/// Whether the environment variable `name` is set and not empty.
#[must_use]
pub fn env_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

/// The packages `dh_listpackages` selects with `args`.
fn packages(args: &[OsString]) -> Result<Vec<String>, u8> {
    let out = Command::new("dh_listpackages")
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| {
            eprintln!("{ME}: error: dh_listpackages: {e}");
            25
        })?;
    if !out.status.success() {
        return Err(u8::try_from(out.status.code().unwrap_or(25)).unwrap_or(25));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .map(str::to_owned)
        .collect())
}

/// The date of the latest changelog entry, else `SOURCE_DATE_EPOCH`, else 0.
fn timestamp() -> i64 {
    let changelog = Command::new("dpkg-parsechangelog")
        .arg("-STimestamp")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok());
    changelog
        .or_else(|| {
            std::env::var("SOURCE_DATE_EPOCH")
                .ok()
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0)
}

/// Run as `dh_strip_nondeterminism ARGS`; the exit status.
#[must_use]
pub fn run(args: &[OsString]) -> u8 {
    let mut o = Opts::default();
    let mut words: Vec<String> = std::env::var("DH_OPTIONS")
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    words.extend(args.iter().map(|a| a.to_string_lossy().into_owned()));
    parse(&words, &mut o);
    o.verbose |= env_set("DH_VERBOSE");
    let packages = match packages(args) {
        Ok(p) => p,
        Err(status) => return status,
    };
    let time = timestamp();
    for pkg in packages {
        let shown = o.tmpdir.clone().unwrap_or_else(|| format!("debian/{pkg}"));
        let root = PathBuf::from(&shown);
        if !root.is_dir() {
            continue;
        }
        if let Err(e) = package(&root, &shown, time, &o) {
            eprintln!("{ME}: error: {e}");
            eprintln!("{ME}: error: Aborting due to earlier error");
            return 25;
        }
    }
    0
}

fn package(root: &Path, shown: &str, time: i64, o: &Opts) -> Result<()> {
    let mut found = Vec::new();
    tree::walk(root, shown, &mut found)?;
    // as debhelper's helper: an excluded name does not hide another name of its inode
    let mut seen = std::collections::HashSet::new();
    let mut targets: Vec<Target> = Vec::with_capacity(found.len());
    for t in found {
        if o.excludes.iter().any(|x| t.display.contains(x.as_str())) {
            continue;
        }
        let meta = fs::symlink_metadata(&t.path).map_err(|e| io_err(&t.path, &e))?;
        if meta.nlink() == 1 || seen.insert((meta.dev(), meta.ino())) {
            targets.push(t);
        }
    }
    let outcome = strip(
        targets,
        &mut Options {
            time,
            kind: None,
            enabled: Normalizers::DEFAULT,
            pyc: env_set(PYC),
            warn: &mut |t, w| eprintln!("{ME}: {}: {w}", t.display),
        },
    )?;
    if o.verbose {
        for (t, kind) in &outcome.normalized {
            println!("\tNormalized {} ({})", t.display, kind.name());
        }
    }
    if let Some((_, e)) = outcome.failed.into_iter().next() {
        return Err(e);
    }
    Ok(())
}

/// Whether `arg0`, the name this binary was run as, is this helper's.
#[must_use]
pub fn is_argv0(arg0: &OsStr) -> bool {
    Path::new(arg0).file_name().map(OsStrExt::as_bytes) == Some(b"dh_strip_nondeterminism")
}
