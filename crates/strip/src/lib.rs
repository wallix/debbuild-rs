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
//! Python bytecode ([`pyc`]) is normalized on request ([`Options::pyc`]), as
//! add-determinism does: strip-nondeterminism leaves .pyc files alone.

mod ar;
mod bflt;
pub mod cli;
mod cpio;
pub mod dh;
mod gettext;
mod glob;
mod gzip;
mod javadoc;
mod numeric;
mod png;
pub mod pyc;
mod time;
mod tree;
mod uimage;
mod zip;

use std::fmt;
use std::ops::Range;
use std::os::unix::fs::MetadataExt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

/// Why a file could not be normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The file is not what its name and content said; strip-nondeterminism fails on it
    /// too, with this exit status.
    Malformed(String, u8),
    /// A system call failed.
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(m, _) | Error::Io(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// A malformed file strip-nondeterminism dies on: its exit status is 255.
    fn malformed(message: impl Into<String>) -> Error {
        Error::Malformed(message.into(), 255)
    }

    /// The exit status strip-nondeterminism ends with on this error: 255, or another one
    /// for some malformed files (25 for a zip archive too short); 1 for this crate's I/O
    /// errors.
    #[must_use]
    pub fn status(&self) -> u8 {
        match self {
            Error::Malformed(_, status) => *status,
            Error::Io(_) => 1,
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

fn io_err(path: &Path, e: &std::io::Error) -> Error {
    Error::Io(format!("{}: {e}", path.display()))
}

/// The handlers of strip-nondeterminism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Unix ar archives: a normalizer strip-nondeterminism only runs when enabled.
    Ar,
    Gzip,
    Zip,
    Jar,
    Png,
    Gettext,
    Javadoc,
    /// Java modules (`.jmod`).
    Jmod,
    /// Python zip applications, a `#!` line before a zip archive.
    Pyzip,
    /// cpio archives.
    Cpio,
    /// U-Boot legacy images.
    Uimage,
    /// bFLT executables.
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
            Kind::Ar => "ar",
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

    /// Every handler, strip-nondeterminism's in its order of names, then [`Kind::Pyc`].
    pub const ALL: [Kind; 13] = [
        Kind::Ar,
        Kind::Bflt,
        Kind::Cpio,
        Kind::Gettext,
        Kind::Gzip,
        Kind::Jar,
        Kind::Javadoc,
        Kind::Jmod,
        Kind::Png,
        Kind::Pyzip,
        Kind::Uimage,
        Kind::Zip,
        Kind::Pyc,
    ];

    /// The handler named `name`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.name() == name)
    }

    /// Whether the normalized file replaces the old one as a new file rather than
    /// being written over it.
    fn replaces(self) -> bool {
        matches!(self, Kind::Zip | Kind::Jar)
    }
}

/// The handlers that run, as strip-nondeterminism's `--normalizers` selects them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Normalizers(u16);

impl Normalizers {
    /// strip-nondeterminism's default: every handler but ar's.
    pub const DEFAULT: Normalizers = Normalizers(!Normalizers::bit(Kind::Ar));
    /// Every handler.
    pub const ALL: Normalizers = Normalizers(u16::MAX);
    /// None.
    pub const NONE: Normalizers = Normalizers(0);

    const fn bit(kind: Kind) -> u16 {
        1 << kind as u16
    }

    /// Whether the `kind` handler runs; [`Kind::Pyc`] always does when asked for.
    #[must_use]
    pub fn contains(self, kind: Kind) -> bool {
        kind == Kind::Pyc || self.0 & Normalizers::bit(kind) != 0
    }

    /// Enable or disable the `kind` handler.
    pub fn set(&mut self, kind: Kind, on: bool) {
        if on {
            self.0 |= Normalizers::bit(kind);
        } else {
            self.0 &= !Normalizers::bit(kind);
        }
    }
}

impl Normalizers {
    /// The names `--normalizers` takes: the handlers', and `javaproperties`, a handler
    /// strip-nondeterminism names but does not have.
    pub const NAMES: [&'static str; 13] = [
        "ar",
        "bflt",
        "cpio",
        "gettext",
        "gzip",
        "jar",
        "javadoc",
        "javaproperties",
        "jmod",
        "png",
        "pyzip",
        "uimage",
        "zip",
    ];

    /// The default set changed by a `--normalizers` spec, as strip-nondeterminism
    /// applies it: comma-separated `+NAME` and `-NAME` items (`all` naming every
    /// handler), left to right; empty items at the end are ignored. `report` gets each
    /// change, for `--verbose`.
    ///
    /// # Errors
    /// The message of an item that is not `+` or `-` and a word, or names no handler.
    pub fn parse(spec: &str, report: &mut dyn FnMut(String)) -> Result<Normalizers, String> {
        let mut set = Normalizers::DEFAULT;
        let items: Vec<&str> = spec.split(',').collect();
        let last = items
            .iter()
            .rposition(|i| !i.is_empty())
            .map_or(0, |n| n.saturating_add(1));
        for item in items.get(..last).unwrap_or_default() {
            let (on, name) = match item.as_bytes().first() {
                Some(b'+') => (true, item.get(1..).unwrap_or_default()),
                Some(b'-') => (false, item.get(1..).unwrap_or_default()),
                _ => return Err(format!("invalid --normalizer spec: {item}")),
            };
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(format!("invalid --normalizer spec: {item}"));
            }
            let verb = if on { "Enabling" } else { "Disabling" };
            if name == "all" {
                report(format!("{verb} all normalizers"));
                set = if on {
                    Normalizers::ALL
                } else {
                    Normalizers::NONE
                };
                continue;
            }
            report(format!("{verb} normalizer {name}"));
            if !Normalizers::NAMES.contains(&name) {
                return Err(format!("Unknown normalizer: {name}"));
            }
            if let Some(kind) = Kind::from_name(name) {
                set.set(kind, on);
            }
        }
        Ok(set)
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
        b"a" => Kind::Ar,
        b"gz" | b"dz" => Kind::Gzip,
        b"zip" | b"pk3" | b"epub" | b"whl" | b"xpi" | b"htb" | b"zhfst" | b"par" | b"codadef" => {
            Kind::Zip
        }
        b"jar" | b"war" | b"hpi" | b"apk" | b"sym" => Kind::Jar,
        b"png" => Kind::Png,
        b"mo" | b"gmo" => Kind::Gettext,
        b"html" => Kind::Javadoc,
        b"jmod" => Kind::Jmod,
        b"cpio" => Kind::Cpio,
        _ if ext.eq_ignore_ascii_case(b"uimage") => Kind::Uimage,
        b"bflt" => Kind::Bflt,
        _ => return None,
    })
}

/// Whether file(1)'s description of a file confirms the handler its name asks for.
#[must_use]
pub fn confirms(kind: Kind, description: &str) -> bool {
    let has = |s: &str| description.contains(s);
    match kind {
        Kind::Ar => has("ar archive"),
        Kind::Cpio => has("cpio archive"),
        Kind::Gzip => has("gzip compressed data"),
        Kind::Zip => has("Zip archive data") || has("EPUB document"),
        Kind::Jar => has("Zip archive data") || has("Java archive data"),
        Kind::Png => has("PNG image data"),
        Kind::Gettext => has("GNU message catalog"),
        Kind::Pyzip => {
            has("python3 script executable (Zip archive)")
                || has("python3 script executable (binary data)")
        }
        Kind::Javadoc | Kind::Jmod | Kind::Uimage | Kind::Bflt | Kind::Pyc => true,
    }
}

/// The same check as [`confirms`], from the magic numbers, when file(1) is missing.
#[must_use]
pub fn confirms_magic(kind: Kind, head: &[u8]) -> bool {
    match kind {
        Kind::Ar => head.starts_with(b"!<arch>\n"),
        Kind::Cpio => [&b"070707"[..], b"070701", b"\xc7\x71"]
            .iter()
            .any(|m| head.starts_with(m)),
        Kind::Gzip => head.starts_with(b"\x1f\x8b"),
        Kind::Zip | Kind::Jar => head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06"),
        Kind::Png => head.starts_with(b"\x89PNG\r\n\x1a\n"),
        Kind::Gettext => {
            head.starts_with(b"\xde\x12\x04\x95") || head.starts_with(b"\x95\x04\x12\xde")
        }
        Kind::Pyzip => zip::pyzip_line(head),
        Kind::Javadoc | Kind::Jmod | Kind::Uimage | Kind::Bflt | Kind::Pyc => true,
    }
}

/// The normalized content of a file the `kind` handler takes, or `None` when the file
/// stays as it is: already normalized, it is never rewritten. `time` is the timestamp, in seconds since the epoch; `warn` gets the
/// warnings strip-nondeterminism prints (and carries on).
///
/// # Errors
/// The file is malformed.
pub fn normalize(
    kind: Kind,
    data: &[u8],
    time: i64,
    warn: &mut dyn FnMut(String),
) -> Result<Option<Vec<u8>>> {
    let new = match kind {
        Kind::Ar => ar::normalize(data, time),
        Kind::Gzip => gzip::normalize(data, u32::try_from(time & 0xffff_ffff).unwrap_or(0)),
        Kind::Zip => zip::normalize(data, time, zip::Flavor::Zip, warn),
        Kind::Jar => zip::normalize(data, time, zip::Flavor::Jar, warn),
        Kind::Jmod => zip::normalize_jmod(data, time, warn),
        Kind::Pyzip => zip::normalize_pyzip(data, time, warn),
        Kind::Png if !png::is_png(data) => Err(Error::malformed("does not appear to be a PNG")),
        Kind::Png => Ok(png::normalize(data, time)),
        Kind::Gettext => Ok(gettext::normalize(data, time)),
        Kind::Javadoc => Ok(javadoc::normalize(data, time)),
        Kind::Uimage => Ok(uimage::normalize(data, time)),
        Kind::Bflt => Ok(bflt::normalize(data, time)),
        Kind::Pyc => pyc::normalize(data, warn),
        Kind::Cpio => cpio::normalize(data, time),
    }?;
    Ok(new.filter(|new| new != data))
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
    /// The handlers detection may pick.
    pub enabled: Normalizers,
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
    let data = match std::fs::read(&t.path) {
        Ok(d) => d,
        Err(e) => return Prepared::Fatal(io_err(&t.path, &e)),
    };
    match normalize(kind, &data, time, &mut warn) {
        Ok(Some(new)) => Prepared::Write(new),
        Ok(None) => Prepared::Unchanged,
        Err(Error::Malformed(m, status)) => {
            Prepared::Fatal(Error::Malformed(format!("{}: {m}", t.display), status))
        }
        Err(e) => Prepared::Fatal(e),
    }
}

/// What became of a file, with the warnings it got.
enum Fate {
    Normalized,
    Unchanged,
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
    /// Whether each job has finished (written or skipped), by index. The next job for
    /// the same file waits for it.
    done: Vec<bool>,
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

    /// Job `index` is through.
    fn finish(&self, index: usize) {
        let mut g = self.lock();
        if let Some(d) = g.done.get_mut(index) {
            *d = true;
        }
        self.changed.notify_all();
    }

    /// The job with `before` risky files before it, of rank `rank` if risky, panicked:
    /// it is decided, and stops the run there.
    fn abort(&self, before: usize, rank: Option<usize>) {
        let mut g = self.lock();
        let at = rank.unwrap_or(before);
        g.fatal = Some(g.fatal.map_or(at, |f| f.min(at)));
        if let Some(d) = rank.and_then(|r| g.decided.get_mut(r)) {
            *d = true;
        }
        self.changed.notify_all();
    }

    /// Wait until job `index` is through.
    fn wait_done(&self, index: usize) {
        let mut g = self.lock();
        while g.done.get(index) == Some(&false) {
            g = self.changed.wait(g).unwrap_or_else(PoisonError::into_inner);
        }
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
    /// The job before it of the same file (inode), which it waits for.
    after: Option<usize>,
}

/// Prepare `job` after the previous job for the same file finishes, then wait for its
/// turn to write. Return `None` if the run stopped before it.
fn process(job: &Job, time: i64, turns: &Turns) -> Option<(Vec<String>, Fate)> {
    if let Some(i) = job.after {
        turns.wait_done(i);
    }
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

/// The jobs of the classified files, and how many are risky.
fn jobs(classified: Vec<(Target, Kind)>) -> (Vec<Job>, usize) {
    let mut risky_files = 0_usize;
    let mut jobs: Vec<Job> = classified
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
                after: None,
            }
        })
        .collect();
    // the jobs of one inode run one after the other
    let mut last = std::collections::HashMap::new();
    for (i, job) in jobs.iter_mut().enumerate() {
        if let Ok(m) = std::fs::metadata(&job.target.path) {
            job.after = last.insert((m.dev(), m.ino()), i);
        }
    }
    (jobs, risky_files)
}

/// What [`process`] makes of a job: `None` once the run stopped before it.
type Processed = Option<(Vec<String>, Fate)>;

/// Run `process` on `jobs` (`risky_files` of them risky) in parallel, taking turns; what
/// it made of each, by index. A job that panics stops the run there, as a fatal error
/// would, and its panic is raised again once the workers are through.
fn schedule(
    jobs: &[Job],
    risky_files: usize,
    process: &(dyn Fn(&Job, &Turns) -> Processed + Sync),
) -> Vec<Processed> {
    let runs = runs(jobs);
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(runs.len());
    let next = AtomicUsize::new(0);
    let turns = Turns {
        gate: Mutex::new(Gate {
            decided: vec![false; risky_files],
            prefix: 0,
            fatal: None,
            done: vec![false; jobs.len()],
        }),
        changed: Condvar::new(),
    };
    let mut fates: Vec<Processed> = Vec::new();
    fates.resize_with(jobs.len(), || None);
    let mut panic = None;
    std::thread::scope(|s| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(|| {
                    let mut done = Vec::new();
                    let mut panic = None;
                    // claimed in order: the risky files before a claimed one are
                    // claimed too, and get decided without waiting
                    while let Some(run) = runs.get(next.fetch_add(1, Ordering::Relaxed)) {
                        for i in run.clone() {
                            if let Some(job) = jobs.get(i) {
                                match catch_unwind(AssertUnwindSafe(|| process(job, &turns))) {
                                    Ok(fate) => done.push((i, fate)),
                                    Err(p) => {
                                        turns.abort(job.before, job.rank);
                                        panic.get_or_insert(p);
                                    }
                                }
                                turns.finish(i);
                            }
                        }
                    }
                    (done, panic)
                })
            })
            .collect();
        for w in workers {
            let (done, panicked) = w.join().unwrap_or_else(|p| (Vec::new(), Some(p)));
            for (i, fate) in done {
                if let Some(slot) = fates.get_mut(i) {
                    *slot = fate;
                }
            }
            if let Some(p) = panicked {
                panic.get_or_insert(p);
            }
        }
    });
    if let Some(p) = panic {
        resume_unwind(p);
    }
    fates
}

/// Normalize `targets` in place with the native handlers, as strip-nondeterminism
/// would.
/// The .pyc files are normalized as add-determinism does: one it cannot process is left
/// as it is with a warning, one it fails on is returned in [`Outcome::failed`].
///
/// The files are processed in parallel, with the outcome and warnings of processing
/// them in order: one is written only once those before it are decided, and none after
/// a fatal error (except the files already decided when another fails to be written).
/// A file reached twice (the same inode, under one name or two) is read the second time
/// only after its first processing finishes, as in the real tool.
///
/// # Errors
/// A file is malformed (as strip-nondeterminism, the first one stops the run) or
/// cannot be read or written.
pub fn strip(targets: Vec<Target>, opts: &mut Options) -> Result<Outcome> {
    let (jobs, risky_files) = jobs(tree::classify(targets, opts.kind, opts.pyc, opts.enabled)?);
    let time = opts.time;
    let fates = schedule(&jobs, risky_files, &|job, turns| process(job, time, turns));
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
            Fate::Failed(e) => out.failed.push((t, e)),
            Fate::Fatal(e) => return Err(e),
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    fn job(i: usize, dir: bool) -> Job {
        Job {
            target: Target {
                // each in its own directory, a run of its own, or all in one
                path: PathBuf::from(if dir {
                    format!("d{i}/f")
                } else {
                    format!("f{i}")
                }),
                display: format!("f{i}"),
            },
            kind: Kind::Gzip,
            before: i,
            rank: Some(i),
            after: None,
        }
    }

    /// `--normalizers` names every handler but pyc, plus javaproperties, in order.
    #[test]
    fn normalizer_names() {
        let mut names: Vec<&str> = Kind::ALL
            .into_iter()
            .filter(|k| *k != Kind::Pyc)
            .map(Kind::name)
            .chain(["javaproperties"])
            .collect();
        names.sort_unstable();
        assert_eq!(names, Normalizers::NAMES);
    }

    #[test]
    fn normalizer_specs() {
        let parse = |spec: &str| Normalizers::parse(spec, &mut |_| {});
        let mut all_but_ar = Normalizers::ALL;
        all_but_ar.set(Kind::Ar, false);
        assert_eq!(parse("+all,-ar"), Ok(all_but_ar));
        assert_eq!(parse("-all,+ar").map(|n| n.contains(Kind::Ar)), Ok(true));
        assert_eq!(parse("-all,+ar").map(|n| n.contains(Kind::Zip)), Ok(false));
        // empty items are ignored at the end only
        assert_eq!(parse("+ar,,").map(|n| n.contains(Kind::Ar)), Ok(true));
        assert_eq!(parse(""), Ok(Normalizers::DEFAULT));
        for bad in [",+ar", "+ar,,-zip", "ar", "+", "+a-r", "+nosuch"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        // a name strip-nondeterminism knows, with no handler: nothing changes
        assert_eq!(parse("-javaproperties"), Ok(Normalizers::DEFAULT));
    }

    /// A job that panics makes the run panic, once the others are through: none waits
    /// for it forever, nor are the results of its worker dropped.
    #[test]
    fn panics_are_raised() {
        for dir in [true, false] {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut jobs: Vec<Job> = (0..64).map(|i| job(i, dir)).collect();
                // the same file as job 3
                jobs[10].after = Some(3);
                let run = std::panic::catch_unwind(|| {
                    schedule(&jobs, jobs.len(), &|job, turns| {
                        assert!(job.before != 3, "job 3");
                        turns
                            .take(job.before, job.rank, false)
                            .then(|| (Vec::new(), Fate::Unchanged))
                    })
                });
                let _ = tx.send(run.is_err());
            });
            let panicked = rx.recv_timeout(std::time::Duration::from_secs(20));
            assert_eq!(panicked, Ok(true), "{dir}");
        }
    }
}
