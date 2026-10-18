//! Build timestamps and other details of a build normalized out of the files of a
//! package tree, byte for byte as Debian's strip-nondeterminism does.
//!
//! Each format has a handler, a function from the file's bytes to the normalized bytes
//! (or `None` when the file is left as it is). Which handler a file goes through is
//! decided as strip-nondeterminism decides it: by the end of its name, confirmed by
//! file(1)'s description of its content (a `.zip` that file(1) calls a Java archive is
//! not one). The behaviour was derived from the file format specifications and from
//! running strip-nondeterminism on crafted files.
//!
//! Formats strip-nondeterminism knows and these handlers do not (Java modules, Python
//! zip applications, cpio, U-Boot and bFLT images), and archives a handler cannot
//! rewrite exactly ([`Error::Unsupported`]), are left to the real tool by the callers
//! ([`dh`], [`cli`]).
//!
//! Python bytecode ([`pyc`]) is normalized on request ([`Options::pyc`]), as
//! add-determinism does: strip-nondeterminism leaves .pyc files alone.

pub mod cli;
pub mod dh;
mod gettext;
mod gzip;
mod javadoc;
mod png;
pub mod pyc;
mod time;
mod tree;
mod zip;

use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

/// Why a file could not be normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The file is not what its name and content said; strip-nondeterminism fails on it
    /// too.
    Malformed(String),
    /// The file needs what the native handlers do not do: the real tool can.
    Unsupported(String),
    /// A system call failed.
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(m) | Error::Io(m) => f.write_str(m),
            Error::Unsupported(m) => write!(f, "not supported natively: {m}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

fn io_err(path: &Path, e: &std::io::Error) -> Error {
    Error::Io(format!("{}: {e}", path.display()))
}

/// The handlers of strip-nondeterminism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Gzip,
    Zip,
    Jar,
    Png,
    Gettext,
    Javadoc,
    /// Java modules (`.jmod`): the real tool's.
    Jmod,
    /// Python zip applications, a `#!` line before a zip archive: the real tool's.
    Pyzip,
    /// cpio archives: the real tool's.
    Cpio,
    /// U-Boot legacy images: the real tool's.
    Uimage,
    /// bFLT executables: the real tool's.
    Bflt,
    /// Python bytecode, as add-determinism normalizes it: not strip-nondeterminism's,
    /// only with [`Options::pyc`] or forced.
    Pyc,
}

impl Kind {
    /// The name strip-nondeterminism gives the handler (`-t`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Kind::Gzip => "gzip",
            Kind::Zip => "zip",
            Kind::Jar => "jar",
            Kind::Png => "png",
            Kind::Gettext => "gettext",
            Kind::Javadoc => "javadoc",
            Kind::Jmod => "jmod",
            Kind::Pyzip => "pyzip",
            Kind::Cpio => "cpio",
            Kind::Uimage => "uimage",
            Kind::Bflt => "bflt",
            Kind::Pyc => "pyc",
        }
    }

    /// The handler named `name`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Kind> {
        [
            Kind::Gzip,
            Kind::Zip,
            Kind::Jar,
            Kind::Png,
            Kind::Gettext,
            Kind::Javadoc,
            Kind::Jmod,
            Kind::Pyzip,
            Kind::Cpio,
            Kind::Uimage,
            Kind::Bflt,
            Kind::Pyc,
        ]
        .into_iter()
        .find(|k| k.name() == name)
    }

    /// Whether this crate has the handler.
    #[must_use]
    pub fn native(self) -> bool {
        matches!(
            self,
            Kind::Gzip
                | Kind::Zip
                | Kind::Jar
                | Kind::Png
                | Kind::Gettext
                | Kind::Javadoc
                | Kind::Pyc
        )
    }

    /// Whether the normalized file replaces the old one as a new file rather than
    /// being written over it.
    fn replaces(self) -> bool {
        matches!(self, Kind::Zip | Kind::Jar)
    }
}

/// Whether a file name is one add-determinism takes as Python bytecode: a `.pyc`
/// extension, after a non-empty stem.
#[must_use]
pub fn is_pyc_name(name: &[u8]) -> bool {
    name.len() > 4 && name.ends_with(b".pyc")
}

/// The handler a file name asks for, before its content is looked at.
#[must_use]
pub fn by_name(name: &[u8]) -> Option<Kind> {
    let ext = name.rsplit(|&b| b == b'.').next()?;
    if ext.len() == name.len() {
        return None;
    }
    Some(match ext {
        b"gz" | b"dz" => Kind::Gzip,
        b"zip" | b"xpi" | b"whl" | b"epub" | b"par" | b"htb" => Kind::Zip,
        b"jar" | b"war" | b"hpi" | b"apk" | b"sym" => Kind::Jar,
        b"png" => Kind::Png,
        b"mo" | b"gmo" => Kind::Gettext,
        b"html" => Kind::Javadoc,
        b"jmod" => Kind::Jmod,
        b"cpio" => Kind::Cpio,
        b"uimage" | b"uImage" => Kind::Uimage,
        b"bflt" => Kind::Bflt,
        _ => return None,
    })
}

/// Whether file(1)'s description of a file confirms the handler its name asks for.
#[must_use]
pub fn confirms(kind: Kind, description: &str) -> bool {
    let has = |s: &str| description.contains(s);
    match kind {
        Kind::Gzip => has("gzip compressed data"),
        Kind::Zip => has("Zip archive data") || has("EPUB document"),
        Kind::Jar => has("Zip archive data") || has("Java archive data"),
        Kind::Png => has("PNG image data"),
        Kind::Gettext => has("GNU message catalog"),
        Kind::Pyzip => has("script executable (Zip archive)"),
        Kind::Javadoc | Kind::Jmod | Kind::Cpio | Kind::Uimage | Kind::Bflt | Kind::Pyc => true,
    }
}

/// The same check as [`confirms`], from the magic numbers, when file(1) is missing.
#[must_use]
pub fn confirms_magic(kind: Kind, head: &[u8]) -> bool {
    match kind {
        Kind::Gzip => head.starts_with(b"\x1f\x8b"),
        Kind::Zip | Kind::Jar => head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06"),
        Kind::Png => head.starts_with(b"\x89PNG\r\n\x1a\n"),
        Kind::Gettext => {
            head.starts_with(b"\xde\x12\x04\x95") || head.starts_with(b"\x95\x04\x12\xde")
        }
        Kind::Pyzip => head.starts_with(b"#!"),
        Kind::Javadoc | Kind::Jmod | Kind::Cpio | Kind::Uimage | Kind::Bflt | Kind::Pyc => true,
    }
}

/// The normalized content of a file the `kind` handler takes, or `None` when the file
/// stays as it is. `time` is the timestamp, in seconds since the epoch; `warn` gets the
/// warnings strip-nondeterminism prints (and carries on).
///
/// # Errors
/// The file is malformed, or [`Error::Unsupported`] (also for a kind that is not
/// [`Kind::native`]).
pub fn normalize(
    kind: Kind,
    data: &[u8],
    time: i64,
    warn: &mut dyn FnMut(String),
) -> Result<Option<Vec<u8>>> {
    match kind {
        Kind::Gzip => gzip::normalize(data, u32::try_from(time).unwrap_or(0)),
        Kind::Zip => zip::normalize(data, time, zip::Flavor::Zip, warn),
        Kind::Jar => zip::normalize(data, time, zip::Flavor::Jar, warn),
        Kind::Png => Ok(png::normalize(data, time)),
        Kind::Gettext => Ok(gettext::normalize(data, time)),
        Kind::Javadoc => Ok(javadoc::normalize(data, time)),
        Kind::Pyc => pyc::normalize(data, warn),
        Kind::Jmod | Kind::Pyzip | Kind::Cpio | Kind::Uimage | Kind::Bflt => {
            Err(Error::Unsupported(format!("the {} handler", kind.name())))
        }
    }
}

/// A file to normalize, and the name it is reported under.
#[derive(Debug, Clone)]
pub struct Target {
    pub path: PathBuf,
    pub display: String,
}

/// What became of the files given to [`strip`].
#[derive(Debug, Default)]
pub struct Outcome {
    /// Files a native handler rewrote, with the handler.
    pub normalized: Vec<(Target, Kind)>,
    /// Files only the real tool can normalize, with the handler and why.
    pub foreign: Vec<(Target, Kind, String)>,
    /// .pyc files that could not be read or written, or too short for a magic number:
    /// add-determinism fails for them once it is through with the others.
    pub failed: Vec<(Target, Error)>,
}

/// Options of [`strip`].
pub struct Options<'a> {
    /// The timestamp, in seconds since the epoch.
    pub time: i64,
    /// Every file goes through this handler instead of the one detection picks.
    pub kind: Option<Kind>,
    /// Normalize Python bytecode too: the files named `*.pyc`.
    pub pyc: bool,
    /// Gets each warning, with the file it is about.
    pub warn: &'a mut dyn FnMut(&Target, String),
}

/// What [`prepare`] makes of a file, before it is written.
enum Prepared {
    /// Its new content: a .pyc file's, or written by [`tree::write`].
    Pyc(Vec<u8>, std::fs::Metadata),
    Write(Vec<u8>),
    Unchanged,
    /// Only the real tool can normalize it.
    Foreign(String),
    /// A .pyc file add-determinism fails on, after the others.
    Failed(Error),
    /// An error that stops the run there.
    Fatal(Error),
}

/// Read and normalize a file with its handler, without writing it.
fn prepare(t: &Target, kind: Kind, time: i64, warnings: &mut Vec<String>) -> Prepared {
    let mut warn = |w| warnings.push(w);
    if kind == Kind::Pyc {
        return match pyc::prepare(&t.path, &mut warn) {
            Ok(pyc::Prepared::Rewrite(data, meta)) => Prepared::Pyc(data, meta),
            Ok(pyc::Prepared::Unchanged) => Prepared::Unchanged,
            Ok(pyc::Prepared::Skipped(why)) => {
                warn(why);
                Prepared::Unchanged
            }
            Err(e) => Prepared::Failed(e),
        };
    }
    if !kind.native() {
        return Prepared::Foreign(format!("no native {} handler", kind.name()));
    }
    let data = match std::fs::read(&t.path) {
        Ok(d) => d,
        Err(e) => return Prepared::Fatal(io_err(&t.path, &e)),
    };
    match normalize(kind, &data, time, &mut warn) {
        Ok(Some(new)) => Prepared::Write(new),
        Ok(None) => Prepared::Unchanged,
        Err(Error::Unsupported(why)) => Prepared::Foreign(why),
        Err(Error::Malformed(m)) => {
            Prepared::Fatal(Error::Malformed(format!("{}: {m}", t.display)))
        }
        Err(e) => Prepared::Fatal(e),
    }
}

/// What became of a file, with the warnings it got.
enum Fate {
    Normalized,
    Unchanged,
    Foreign(String),
    Failed(Error),
    Fatal(Error),
}

/// Whether a file can stop the run: .pyc files never do.
fn risky(kind: Kind) -> bool {
    kind != Kind::Pyc
}

/// The decisions of the risky files, in order: a file is written only once the risky
/// files before it are decided, and not after a fatal error.
struct Gate {
    /// Whether each risky file, by rank among them, is decided.
    decided: Vec<bool>,
    /// How many risky files from the first are decided.
    prefix: usize,
    /// The rank of the first fatal error.
    fatal: Option<usize>,
}

struct Turns {
    gate: Mutex<Gate>,
    changed: Condvar,
}

impl Turns {
    fn lock(&self) -> MutexGuard<'_, Gate> {
        self.gate.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The file with `before` risky files before it, of rank `rank` if risky, is
    /// decided (`fatal`: it stops the run): wait for the risky files before it; whether
    /// it may be written.
    fn take(&self, before: usize, rank: Option<usize>, fatal: bool) -> bool {
        let mut g = self.lock();
        if let Some(r) = rank {
            if fatal {
                g.fatal = Some(g.fatal.map_or(r, |f| f.min(r)));
            }
            if let Some(d) = g.decided.get_mut(r) {
                *d = true;
            }
            let start = g.prefix;
            while g.decided.get(g.prefix) == Some(&true) {
                g.prefix = g.prefix.saturating_add(1);
            }
            if g.prefix != start || fatal {
                self.changed.notify_all();
            }
        }
        while g.prefix < before && g.fatal.is_none_or(|f| f >= before) {
            g = self.changed.wait(g).unwrap_or_else(PoisonError::into_inner);
        }
        g.fatal.is_none_or(|f| f >= before)
    }

    /// The risky file of rank `rank` failed to be written: stop the run there.
    fn stop(&self, rank: usize) {
        let mut g = self.lock();
        g.fatal = Some(g.fatal.map_or(rank, |f| f.min(rank)));
        self.changed.notify_all();
    }
}

/// A file to process, with its place among the risky files.
struct Job {
    target: Target,
    kind: Kind,
    /// Risky files before it.
    before: usize,
    /// Its rank among them, if risky.
    rank: Option<usize>,
}

/// Prepare `job`, wait for its turn, write it; `None` once the run stopped before it.
fn process(job: &Job, time: i64, turns: &Turns) -> Option<(Vec<String>, Fate)> {
    let t = &job.target;
    let mut warnings = Vec::new();
    let prepared = prepare(t, job.kind, time, &mut warnings);
    let fatal = matches!(prepared, Prepared::Fatal(_));
    if !turns.take(job.before, job.rank, fatal) {
        return None;
    }
    let mut warn = |w| warnings.push(w);
    let fate = match prepared {
        Prepared::Pyc(data, meta) => match pyc::write_back(&t.path, &meta, &data, &mut warn) {
            Ok(()) => Fate::Normalized,
            Err(e) => Fate::Failed(e),
        },
        Prepared::Write(data) => match tree::write(&t.path, &data, job.kind.replaces()) {
            Ok(()) => Fate::Normalized,
            Err(e) => {
                turns.stop(job.rank.unwrap_or_default());
                Fate::Fatal(e)
            }
        },
        Prepared::Unchanged => Fate::Unchanged,
        Prepared::Foreign(why) => Fate::Foreign(why),
        Prepared::Failed(e) => Fate::Failed(e),
        Prepared::Fatal(e) => Fate::Fatal(e),
    };
    Some((warnings, fate))
}

/// The jobs a worker takes at once: up to [`RUN`] files of one directory. Workers
/// creating and renaming files in one directory wait for each other on its lock.
fn runs(jobs: &[Job]) -> Vec<Range<usize>> {
    const RUN: usize = 256;
    let mut runs: Vec<Range<usize>> = Vec::new();
    let mut dir = None;
    for (i, job) in jobs.iter().enumerate() {
        let parent = job.target.path.parent();
        match runs.last_mut() {
            Some(r) if dir == Some(parent) && r.len() < RUN => r.end = i.saturating_add(1),
            _ => runs.push(i..i.saturating_add(1)),
        }
        dir = Some(parent);
    }
    runs
}

/// Normalize `targets` in place with the native handlers, as strip-nondeterminism
/// would; the files only the real tool can do are returned in [`Outcome::foreign`].
/// The .pyc files are normalized as add-determinism does: one it cannot process is left
/// as it is with a warning, one it fails on is returned in [`Outcome::failed`].
///
/// The files are processed in parallel, with the outcome and warnings of processing
/// them in order: one is written only once those before it are decided, and none after
/// a fatal error (except the files already decided when another fails to be written).
///
/// # Errors
/// A file is malformed (as strip-nondeterminism, the first one stops the run) or
/// cannot be read or written.
pub fn strip(targets: Vec<Target>, opts: &mut Options) -> Result<Outcome> {
    let mut risky_files = 0_usize;
    let jobs: Vec<Job> = tree::classify(targets, opts.kind, opts.pyc)?
        .into_iter()
        .map(|(target, kind)| {
            let before = risky_files;
            let rank = risky(kind).then(|| {
                risky_files = risky_files.saturating_add(1);
                before
            });
            Job {
                target,
                kind,
                before,
                rank,
            }
        })
        .collect();
    let runs = runs(&jobs);
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(runs.len());
    let next = AtomicUsize::new(0);
    let turns = Turns {
        gate: Mutex::new(Gate {
            decided: vec![false; risky_files],
            prefix: 0,
            fatal: None,
        }),
        changed: Condvar::new(),
    };
    let mut fates: Vec<Option<(Vec<String>, Fate)>> = Vec::new();
    fates.resize_with(jobs.len(), || None);
    std::thread::scope(|s| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(|| {
                    let mut done = Vec::new();
                    // claimed in order: the risky files before a claimed one are
                    // claimed too, and get decided without waiting
                    while let Some(run) = runs.get(next.fetch_add(1, Ordering::Relaxed)) {
                        for i in run.clone() {
                            if let Some(job) = jobs.get(i) {
                                done.push((i, process(job, opts.time, &turns)));
                            }
                        }
                    }
                    done
                })
            })
            .collect();
        for w in workers {
            for (i, fate) in w.join().unwrap_or_default() {
                if let Some(slot) = fates.get_mut(i) {
                    *slot = fate;
                }
            }
        }
    });
    let mut out = Outcome::default();
    for (job, fate) in jobs.into_iter().zip(fates) {
        let Some((warnings, fate)) = fate else {
            continue;
        };
        let (t, kind) = (job.target, job.kind);
        for w in warnings {
            (opts.warn)(&t, w);
        }
        match fate {
            Fate::Normalized => out.normalized.push((t, kind)),
            Fate::Unchanged => {}
            Fate::Foreign(why) => out.foreign.push((t, kind, why)),
            Fate::Failed(e) => out.failed.push((t, e)),
            Fate::Fatal(e) => return Err(e),
        }
    }
    Ok(out)
}
