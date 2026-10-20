//! `debbuild-rs strip-nondeterminism`: strip-nondeterminism's command line, on the
//! native handlers.
//!
//! Natively, with `-T`: each file is detected by name, content and file(1), or `-t`, as
//! the real tool does, and goes through the native handler of its format. `--normalizers`
//! selects the handlers as for the real tool (with pyzip disabled, a file no other
//! handler takes is left alone, where the real tool dies: a bug of it). Without `-T`, or
//! with `--clamp-timestamp`, the files are the real `strip-nondeterminism`'s, with the
//! same options.
//!
//! The operands are files, which go through detection (a symbolic link only with `-t`,
//! as for the real tool), and directories (which the real tool skips), whose regular
//! files are all found, symbolic links not followed. A file reached through several
//! operands or names (hard links) is processed each time, as when it is named twice.
//! Without `-T`, or with `--clamp-timestamp`, only the .pyc files under a directory are
//! taken (with `--pyc`): the real tool would skip it. A file whose name matches an
//! `--exclude` glob, given or found, is left alone. A missing operand stops the run
//! there, as for the real tool: the files before it are processed. With `-t`, a
//! directory operand is an error (status 2), before any file is processed: the real
//! tool tries the handler on the directory itself. A directory that cannot be read
//! fails the run (status 1), before any file is processed. `--normalizers` and `-t` are
//! checked first, whatever the operands, as the real tool does.
//!
//! A file already normalized is never rewritten, where the real tool rewrites every
//! file a handler takes: a new modification time, and for zip archives a new inode
//! owned by the process.
//!
//! What the real tool prints on stdout differs between its releases and is not
//! reproduced: `-v` names each file rewritten, with its handler, on stderr.
//!
//! `-T` takes an integer (an optional sign, then digits), as the real tool does, but
//! within 64 bits: a larger one, which the real tool takes in floating point, is
//! refused with its status for a value that is not a number, 255.
//!
//! With `--pyc` (or `-t pyc`), the .pyc files (all the files with `-t pyc`) are
//! normalized as add-determinism does, whatever the other options; the others go
//! through the strip-nondeterminism handlers.

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::{Kind, Normalizers, Options, Target, glob, is_pyc_name, strip, tree};

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
    /// Normalize the .pyc files too, as add-determinism does.
    pub pyc: bool,
    /// Globs of the names of files to leave alone.
    pub exclude: Vec<String>,
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

/// What [`operands`] finds: the files, each with whether it was found under a directory,
/// and the first operand that does not exist.
type Operands = (Vec<(Target, bool)>, Option<PathBuf>);

/// The files of the operands: the files given (symbolic links with `forced` only) and
/// those under the directories given, but those whose name an `exclude` glob matches,
/// each with whether it was found under a directory; and the first operand that does
/// not exist, which ends the list.
fn operands(files: &[PathBuf], forced: bool, exclude: &[String]) -> Result<Operands, String> {
    let mut out = Vec::new();
    let mut missing = None;
    for p in files {
        let display = p.display().to_string();
        let Ok(meta) = fs::symlink_metadata(p) else {
            missing = Some(p.clone());
            break;
        };
        if meta.is_symlink() && fs::metadata(p).is_err() {
            missing = Some(p.clone());
            break;
        }
        if meta.is_dir() {
            let mut found = Vec::new();
            tree::walk(p, display.trim_end_matches('/'), &mut found).map_err(|e| e.to_string())?;
            out.extend(found.into_iter().map(|t| (t, true)));
        } else if meta.is_file() || (meta.is_symlink() && forced) {
            out.push((
                Target {
                    path: p.clone(),
                    display,
                },
                false,
            ));
        }
    }
    out.retain(|(t, _)| !excluded(&t.path, exclude));
    Ok((out, missing))
}

fn excluded(path: &Path, exclude: &[String]) -> bool {
    path.file_name().is_some_and(|n| {
        exclude
            .iter()
            .any(|g| glob::matches(g.as_bytes(), n.as_bytes()))
    })
}

/// Normalize `targets` as add-determinism does; the exit status.
fn run_pyc(targets: Vec<Target>, verbose: bool) -> u8 {
    let outcome = match strip(
        targets,
        &mut Options {
            time: 0,
            kind: Some(Kind::Pyc),
            enabled: Normalizers::DEFAULT,
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
    let native = args.timestamp.is_some() && !args.clamp_timestamp;
    let force_pyc = args.kind.as_deref() == Some(Kind::Pyc.name());
    // the options are checked before any file is looked at, as the real tool does
    let enabled = match &args.normalizers {
        None => Normalizers::DEFAULT,
        Some(spec) => {
            // the real tool reports the changes itself when it runs
            let verbose = args.verbose && native;
            match Normalizers::parse(spec, &mut |m| {
                if verbose {
                    eprintln!("{ME}: {m}");
                }
            }) {
                Ok(set) => set,
                Err(e) => {
                    eprintln!("{ME}: {e}");
                    return 255;
                }
            }
        }
    };
    let forced = match args.kind.as_deref() {
        None => None,
        Some(_) if force_pyc => None,
        Some("javaproperties") => {
            eprintln!("{ME}: cannot load the javaproperties handler: there is none");
            return 2;
        }
        Some(name) => {
            let Some(k) = Kind::from_name(name) else {
                eprintln!("Unknown handler: {name}");
                return 255;
            };
            if !enabled.contains(k) {
                // as strip-nondeterminism, for a handler it does not run
                eprintln!("{}: Unknown file type", k.name());
                return 255;
            }
            Some(k)
        }
    };
    // a handler is forced on files named one by one, not on every file of a tree
    if args.kind.is_some()
        && let Some(dir) = args.files.iter().find(|p| p.is_dir())
    {
        eprintln!(
            "{ME}: error: -t takes files, not directories: {}",
            dir.display()
        );
        return 2;
    }
    let (targets, missing) = match operands(&args.files, args.kind.is_some(), &args.exclude) {
        Ok(found) => found,
        Err(e) => {
            eprintln!("{ME}: error: {e}");
            return 1;
        }
    };
    let mut pyc = Vec::new();
    let mut rest = Vec::new();
    for (t, from_dir) in targets {
        if force_pyc
            || (args.pyc
                && t.path
                    .file_name()
                    .is_some_and(|n| is_pyc_name(n.as_bytes())))
        {
            pyc.push(t);
        } else if native || !from_dir {
            // the real tool skips directories: only the .pyc files under them are ours
            rest.push(t);
        }
    }
    let mut status = 0;
    if !pyc.is_empty() {
        status = run_pyc(pyc, args.verbose);
    }
    if !rest.is_empty() {
        status = status.max(if native {
            run_native(args, forced, enabled, rest)
        } else {
            real(args, &rest.into_iter().map(|t| t.path).collect::<Vec<_>>())
        });
    }
    if let Some(p) = missing {
        eprintln!("{}: Does not exist", p.display());
        status = status.max(2);
    }
    status
}

/// [`run`] on the `targets` the strip-nondeterminism handlers may take, with `-T`.
fn run_native(args: &Args, forced: Option<Kind>, enabled: Normalizers, targets: Vec<Target>) -> u8 {
    let outcome = match strip(
        targets,
        &mut Options {
            time: args.timestamp.unwrap_or_default(),
            kind: forced,
            enabled,
            pyc: false,
            warn: &mut |t, w| eprintln!("{REAL}: {}: {w}", t.display),
        },
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{ME}: error: {e}");
            return e.status();
        }
    };
    if args.verbose {
        for (t, kind) in &outcome.normalized {
            eprintln!("Normalized {} ({})", t.display, kind.name());
        }
    }
    // only .pyc files fail without failing the run, and they are not here
    debug_assert!(outcome.failed.is_empty());
    0
}
