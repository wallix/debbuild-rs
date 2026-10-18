//! `dh_strip_nondeterminism`, native: `debbuild-rs stage` puts this binary first in
//! the PATH of debian/rules under that name.
//!
//! As debhelper's: the packages are those `dh_listpackages` selects with the same
//! options (`-p`, `-N`, `-i`, `-a`, `DH_OPTIONS`...); every regular file under each
//! package's build directory (debian/<package>, or `-P`) is normalized, each inode
//! once, except those whose path, as `debian/<package>/...`, contains an `-X` item.
//! The timestamp is the date of the latest debian/changelog entry, else
//! `SOURCE_DATE_EPOCH`, else 0.
//!
//! Files the native handlers do not cover go through the real `dh_strip_nondeterminism`,
//! on copies in a scratch package tree, whose results are copied back: the output is
//! that of debhelper's helper either way. Without it, or with
//! `DEBBUILD_RS_STRIP_NATIVE_ONLY` set, they are left as they are, with a note.
//!
//! With `DEBBUILD_RS_STRIP_PYC` set, the .pyc files are normalized too, as
//! add-determinism does: an option debhelper's helper does not have, and which leaves
//! the output debhelper's otherwise.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use crate::{Error, Kind, Options, Result, Target, io_err, strip, tree};

/// The real helper, by absolute path: PATH leads back to this binary.
pub const REAL: &str = "/usr/bin/dh_strip_nondeterminism";
/// Set (non-empty) to leave the files the native handlers do not cover as they are.
pub const NATIVE_ONLY: &str = "DEBBUILD_RS_STRIP_NATIVE_ONLY";
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
        if let Err(e) = package(&pkg, &root, &shown, time, &o) {
            eprintln!("{ME}: error: {e}");
            eprintln!("{ME}: error: Aborting due to earlier error");
            return 25;
        }
    }
    0
}

fn package(pkg: &str, root: &Path, shown: &str, time: i64, o: &Opts) -> Result<()> {
    let targets: Vec<Target> = tree::walk(root, shown)?
        .into_iter()
        .filter(|t| !o.excludes.iter().any(|x| t.display.contains(x.as_str())))
        .collect();
    let outcome = strip(
        targets,
        &mut Options {
            time,
            kind: None,
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
    if outcome.foreign.is_empty() {
        return Ok(());
    }
    if env_set(NATIVE_ONLY) || !Path::new(REAL).exists() {
        for (t, _, why) in &outcome.foreign {
            eprintln!("{ME}: note: {} left as it is ({why})", t.display);
        }
        return Ok(());
    }
    if o.verbose {
        for (t, kind, why) in &outcome.foreign {
            println!("\t{} through {REAL} ({}: {why})", t.display, kind.name());
        }
    }
    let files: Vec<(&Target, Kind)> = outcome.foreign.iter().map(|(t, k, _)| (t, *k)).collect();
    through_real(pkg, root, &files)
}

/// The mtime given to the copies, to tell the ones the real helper rewrote.
fn untouched() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// Normalize `files` of `pkg` (under `root`) with the real helper, on copies in a
/// scratch package tree under debian/, then copy back those it rewrote.
fn through_real(pkg: &str, root: &Path, files: &[(&Target, Kind)]) -> Result<()> {
    let debian = Path::new("debian");
    let scratch = tempfile::Builder::new()
        .prefix(".debbuild-rs-strip")
        .tempdir_in(debian)
        .map_err(|e| io_err(debian, &e))?;
    let sdebian = scratch.path().join("debian");
    fs::create_dir(&sdebian).map_err(|e| io_err(&sdebian, &e))?;
    for name in ["control", "changelog", "compat"] {
        let src = debian.join(name);
        if src.exists() {
            fs::copy(&src, sdebian.join(name)).map_err(|e| io_err(&src, &e))?;
        }
    }
    let mut copies = Vec::with_capacity(files.len());
    for (t, _) in files {
        let rel = t.path.strip_prefix(root).unwrap_or(&t.path);
        let copy = sdebian.join(pkg).join(rel);
        if let Some(dir) = copy.parent() {
            fs::create_dir_all(dir).map_err(|e| io_err(dir, &e))?;
        }
        fs::copy(&t.path, &copy).map_err(|e| io_err(&t.path, &e))?;
        fs::File::options()
            .write(true)
            .open(&copy)
            .and_then(|f| f.set_modified(untouched()))
            .map_err(|e| io_err(&copy, &e))?;
        copies.push(copy);
    }
    let status = Command::new(REAL)
        .arg(format!("-p{pkg}"))
        .current_dir(scratch.path())
        .stdin(Stdio::null())
        .status()
        .map_err(|e| Error::Io(format!("{REAL}: {e}")))?;
    if !status.success() {
        return Err(Error::Io(format!("{REAL} failed ({status})")));
    }
    for ((t, _), copy) in files.iter().zip(&copies) {
        let meta = fs::metadata(copy).map_err(|e| io_err(copy, &e))?;
        if meta.modified().ok() == Some(untouched()) {
            continue;
        }
        let data = fs::read(copy).map_err(|e| io_err(copy, &e))?;
        tree::write(&t.path, &data, false)?;
        fs::set_permissions(&t.path, fs::Permissions::from_mode(meta.mode() & 0o7777))
            .map_err(|e| io_err(&t.path, &e))?;
    }
    Ok(())
}

/// Whether `arg0`, the name this binary was run as, is this helper's.
#[must_use]
pub fn is_argv0(arg0: &OsStr) -> bool {
    Path::new(arg0).file_name().map(OsStrExt::as_bytes) == Some(b"dh_strip_nondeterminism")
}
