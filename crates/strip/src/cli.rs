//! `debbuild-rs strip-nondeterminism`: strip-nondeterminism's command line, on the
//! native handlers.
//!
//! Natively, with `-T`: each file is detected by name and file(1), or `-t`, as the real
//! tool does. Files the native handlers do not cover go to the real
//! `strip-nondeterminism` when it is installed, with the same options; otherwise, or
//! with `--native-only`, they are left as they are with a note. Without `-T`, or with
//! `--clamp-timestamp` or `--normalizers`, the whole run is the real tool's.
//!
//! With `--pyc` (or `-t pyc`), the .pyc files among the operands, and those under the
//! directory operands, are normalized first as add-determinism does, whatever the other
//! options; the other files of directory operands are not looked at.

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::{Kind, Options, Target, is_pyc_name, strip, tree};

/// The real tool, found in PATH.
pub const REAL: &str = "strip-nondeterminism";

const ME: &str = "debbuild-rs strip-nondeterminism";

/// The command line.
#[allow(clippy::struct_excessive_bools)] // its flags
pub struct Args {
    pub timestamp: Option<i64>,
    pub kind: Option<String>,
    pub clamp_timestamp: bool,
    pub normalizers: Option<String>,
    pub verbose: bool,
    pub native_only: bool,
    /// Normalize the .pyc files too, as add-determinism does.
    pub pyc: bool,
    pub files: Vec<PathBuf>,
}

impl Args {
    /// The options as the real tool takes them, without the files.
    fn real_options(&self) -> Vec<OsString> {
        let mut v: Vec<OsString> = Vec::new();
        if let Some(t) = self.timestamp {
            v.push(format!("--timestamp={t}").into());
        }
        if let Some(k) = &self.kind {
            v.push(format!("--type={k}").into());
        }
        if self.clamp_timestamp {
            v.push("--clamp-timestamp".into());
        }
        if let Some(n) = &self.normalizers {
            v.push(format!("--normalizers={n}").into());
        }
        if self.verbose {
            v.push("--verbose".into());
        }
        v
    }
}

/// Run the real tool on `files`; its exit status, or 2 when it cannot run.
fn real(args: &Args, files: &[PathBuf]) -> u8 {
    match Command::new(REAL)
        .args(args.real_options())
        .arg("--")
        .args(files)
        .stdin(Stdio::null())
        .status()
    {
        Ok(s) => u8::try_from(s.code().unwrap_or(1)).unwrap_or(1),
        Err(e) => {
            eprintln!("{ME}: {REAL}: {e}");
            2
        }
    }
}

fn have_real() -> bool {
    Command::new(REAL)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The .pyc files among `files` and under the directories of `files` (all the files
/// operands with `all`), and the other operands.
fn split_pyc(files: &[PathBuf], all: bool) -> Result<(Vec<Target>, Vec<PathBuf>), String> {
    let mut pyc = Vec::new();
    let mut rest = Vec::new();
    for p in files {
        let display = p.display().to_string();
        if fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) {
            let found = tree::walk(p, display.trim_end_matches('/')).map_err(|e| e.to_string())?;
            pyc.extend(found.into_iter().filter(|t| {
                t.path
                    .file_name()
                    .is_some_and(|n| is_pyc_name(n.as_bytes()))
            }));
        } else if all || p.file_name().is_some_and(|n| is_pyc_name(n.as_bytes())) {
            pyc.push(Target {
                path: p.clone(),
                display,
            });
        } else {
            rest.push(p.clone());
        }
    }
    Ok((pyc, rest))
}

/// Normalize `targets` as add-determinism does; the exit status.
fn run_pyc(targets: Vec<Target>, verbose: bool) -> u8 {
    let outcome = match strip(
        targets,
        &mut Options {
            time: 0,
            kind: Some(Kind::Pyc),
            pyc: true,
            warn: &mut |t, w| eprintln!("{ME}: {}: {w}", t.display),
        },
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{ME}: error: {e}");
            return 1;
        }
    };
    if verbose {
        for (t, kind) in &outcome.normalized {
            eprintln!("Normalized {} ({})", t.display, kind.name());
        }
    }
    for (_, e) in &outcome.failed {
        eprintln!("{ME}: error: {e}");
    }
    u8::from(!outcome.failed.is_empty())
}

/// Run the command; the exit status.
#[must_use]
pub fn run(args: &Args) -> u8 {
    let mut status = 0;
    let mut files = args.files.clone();
    let force_pyc = args.kind.as_deref() == Some(Kind::Pyc.name());
    if args.pyc || force_pyc {
        let (pyc, rest) = match split_pyc(&args.files, force_pyc) {
            Ok(split) => split,
            Err(e) => {
                eprintln!("{ME}: error: {e}");
                return 1;
            }
        };
        status = run_pyc(pyc, args.verbose);
        if rest.is_empty() {
            return status;
        }
        files = rest;
    }
    status.max(run_files(args, &files))
}

/// [`run`] on the `files` the strip-nondeterminism handlers may take.
fn run_files(args: &Args, files: &[PathBuf]) -> u8 {
    let forced = match args.kind.as_deref().map(Kind::from_name) {
        None => None,
        Some(Some(k)) => Some(k),
        Some(None) => {
            eprintln!(
                "{ME}: no native {} handler",
                args.kind.as_deref().unwrap_or_default()
            );
            return if args.native_only {
                2
            } else {
                real(args, files)
            };
        }
    };
    let Some(time) = args
        .timestamp
        .filter(|_| !args.clamp_timestamp && args.normalizers.is_none())
    else {
        if args.native_only {
            eprintln!(
                "{ME}: natively, only with --timestamp, without --clamp-timestamp and --normalizers"
            );
            return 2;
        }
        return real(args, files);
    };
    let targets = files
        .iter()
        .map(|p| Target {
            path: p.clone(),
            display: p.display().to_string(),
        })
        .collect();
    let outcome = match strip(
        targets,
        &mut Options {
            time,
            kind: forced,
            pyc: false,
            warn: &mut |t, w| eprintln!("{REAL}: {}: {w}", t.display),
        },
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{ME}: error: {e}");
            return 1;
        }
    };
    if args.verbose {
        for (t, kind) in &outcome.normalized {
            eprintln!("Normalized {} ({})", t.display, kind.name());
        }
    }
    if outcome.foreign.is_empty() {
        return 0;
    }
    if args.native_only || !have_real() {
        for (t, _, why) in &outcome.foreign {
            eprintln!("{ME}: note: {} left as it is ({why})", t.display);
        }
        return 0;
    }
    let files: Vec<PathBuf> = outcome
        .foreign
        .into_iter()
        .map(|(t, _, _)| t.path)
        .collect();
    real(args, &files)
}
