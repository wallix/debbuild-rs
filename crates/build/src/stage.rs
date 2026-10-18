//! `debbuild-rs stage`: build a source package into staged package trees.
//!
//! Runs the package's own debian/rules (clean, build, binary, clean) as
//! dpkg-buildpackage does, except that `dh_builddeb` is `debbuild-rs builddeb`, which
//! keeps each binary package as a staged tree (DEBIAN/ + data.tar) in
//! OUTDIR/<dir>/<package> instead of packing a .deb, and lists them in
//! OUTDIR/<dir>/.staged.
//!
//! The trees are staged in a work directory of OUTDIR and published together: the new
//! OUTDIR/<dir> is exchanged with the previous one in a single rename, so that readers
//! see either generation whole. Runs staging the same OUTDIR/<dir>, from the same
//! source tree or from another one of the same name, take turns through a lock file,
//! OUTDIR/.<dir>.lock. The exchange waits for the readers of OUTDIR/<dir>, and they
//! for it, through another one, OUTDIR/.<dir>.publish.lock
//! ([`debbuild_rs_common::staged_lock`]).
//!
//! Other differences with dpkg-buildpackage: dpkg-checkbuilddeps only on request, no
//! dpkg-source --before-build, and the changelog can be generated for the run (`--version`), for
//! source trees that do not keep one.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};

use debbuild_rs_common::staged_lock;

use crate::fsutil::{exchange_dir, logical_abs, remove_all};
use crate::{Error, Result, rfc2822, run, signals};

/// The help text of `debbuild-rs stage`.
pub const ABOUT: &str = "Build a source package into staged package trees.

Runs the package's own debian/rules (clean, build, binary, clean) as dpkg-buildpackage
does, except that dh_builddeb is `debbuild-rs builddeb`, which keeps each binary package
as a staged tree (DEBIAN/ + data.tar) in OUTDIR/<dir>/<package> instead of packing a
.deb, and lists them in OUTDIR/<dir>/.staged. `debbuild-rs pack` makes .deb files of
them, `debbuild-rs install` puts them in place the way dpkg would.

<dir> is the name of the source directory. The new OUTDIR/<dir> replaces the previous
one in a single rename once every package is staged. One run at a time stages a given
source tree, and one a given OUTDIR/<dir> (lock file OUTDIR/.<dir>.lock). The rename
waits for the debbuild-rs commands reading OUTDIR/<dir> (lock file
OUTDIR/.<dir>.publish.lock), and they for it.

The version is the one of debian/changelog, or, with --version, a changelog entry is
written for the run and removed after it (debian/changelog must not exist then).
SOURCE_DATE_EPOCH is --epoch, otherwise the one of the environment, otherwise the
changelog date (now, for a generated entry). Each tree records it in
OUTDIR/<dir>/<package>/staged.info, and `debbuild-rs pack` uses it.

Other differences with dpkg-buildpackage: dpkg-checkbuilddeps runs only with
--check-build-deps, and dpkg-source --before-build not at all. dh_strip_nondeterminism
is debbuild-rs's native one, with the same output (`debbuild-rs strip-nondeterminism
--help`). debian/rules runs in the caller's environment, plus dpkg-architecture's
variables and SOURCE_DATE_EPOCH.";

/// The changelog entry to write for the run.
pub struct Entry {
    pub version: Vec<u8>,
    /// Default: UNRELEASED.
    pub distribution: Option<String>,
    /// `Name <email>`. Default: `DEBFULLNAME <DEBEMAIL>`, otherwise the Maintainer field
    /// of debian/control.
    pub maintainer: Option<String>,
    /// The change line. Default: `Build <version>`.
    pub message: Option<String>,
}

pub struct Options {
    /// The source package directory (holding debian/).
    pub srcdir: PathBuf,
    /// Where the staged trees go: OUTDIR/<basename of srcdir>.
    pub outdir: PathBuf,
    /// The binary `dh_builddeb` runs: this one.
    pub exe: PathBuf,
    /// Write this changelog entry for the run instead of reading debian/changelog.
    pub entry: Option<Entry>,
    /// `SOURCE_DATE_EPOCH`, and the date of a generated entry.
    pub epoch: Option<i64>,
    /// Check the build dependencies with dpkg-checkbuilddeps first.
    pub check_build_deps: bool,
}

/// The tools a run needs besides those the rules call, and their packages.
const TOOLS: [(&str, &str); 4] = [
    ("dpkg-architecture", "dpkg-dev"),
    ("dpkg-parsechangelog", "dpkg-dev"),
    ("fakeroot", "fakeroot"),
    ("tar", "tar"),
];

fn in_path(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| {
            fs::metadata(d.join(name))
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    })
}

/// Fail before touching the source tree when a tool is missing or, with
/// `check_build_deps`, a build dependency is not installed.
fn preflight(opts: &Options) -> Result<()> {
    let missing: Vec<String> = TOOLS
        .iter()
        .filter(|(t, _)| !in_path(t))
        .map(|(t, p)| format!("{t} (package {p})"))
        .collect();
    if !missing.is_empty() {
        return Err(err(format_args!("missing tools: {}", missing.join(", "))));
    }
    if opts.check_build_deps {
        let mut cmd = Command::new("dpkg-checkbuilddeps");
        cmd.current_dir(&opts.srcdir);
        run(&mut cmd, "dpkg-checkbuilddeps")?;
    }
    Ok(())
}

fn err(msg: impl std::fmt::Display) -> Error {
    Error::msg(format!("debbuild-rs: {msg}"))
}

fn io_err(path: &Path, e: &io::Error) -> Error {
    err(format_args!("{}: {e}", path.display()))
}

/// `sed -n 's/^Source: *//p' debian/control`: every Source: line, one per line.
fn source_name(control: &[u8]) -> Vec<u8> {
    let values: Vec<&[u8]> = control
        .split(|&c| c == b'\n')
        .filter_map(|l| l.strip_prefix(b"Source:".as_slice()))
        .map(|v| {
            let n = v.iter().take_while(|&&c| c == b' ').count();
            v.get(n..).unwrap_or_default()
        })
        .collect();
    let mut out = values.join(&b'\n');
    // $(...) drops the trailing newlines.
    while out.last() == Some(&b'\n') {
        out.pop();
    }
    out
}

/// What must be undone when the run ends, successful or not.
struct Cleanup {
    pkgdir: PathBuf,
    workdir: PathBuf,
    env: Vec<(OsString, OsString)>,
    /// The rules may have run: clean the tree.
    started: bool,
    /// The run wrote debian/changelog: remove it.
    generated: bool,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if self.started {
            let ok = signals::run_cleanup(
                Command::new("fakeroot")
                    .args(["debian/rules", "clean"])
                    .current_dir(&self.pkgdir)
                    .envs(self.env.iter().map(|(k, v)| (k, v)))
                    .stdout(Stdio::null()),
            )
            .is_ok_and(|s| s.success());
            if !ok {
                eprintln!(
                    "debbuild-rs: debian/rules clean failed in {}",
                    self.pkgdir.display()
                );
            }
        }
        let changelog = self.pkgdir.join("debian/changelog");
        if self.generated
            && let Err(e) = fs::remove_file(&changelog)
            && e.kind() != io::ErrorKind::NotFound
        {
            eprintln!("debbuild-rs: {}: {e}", changelog.display());
        }
        if let Err(e) = remove_all(&self.workdir) {
            eprintln!("debbuild-rs: {}: {e}", self.workdir.display());
        }
    }
}

/// The variables of `dpkg-architecture` (`VAR=value` lines), as dpkg-buildpackage
/// exports them.
fn dpkg_architecture() -> Result<Vec<(OsString, OsString)>> {
    let out = Command::new("dpkg-architecture")
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| err(format_args!("dpkg-architecture: {e}")))?;
    if !out.status.success() {
        return Err(Error::Exit(crate::shell_status(out.status)));
    }
    Ok(out
        .stdout
        .split(|&c| c == b'\n')
        .filter_map(|l| {
            let eq = l.iter().position(|&c| c == b'=')?;
            Some((
                OsString::from_vec(l.get(..eq)?.to_vec()),
                OsString::from_vec(l.get(eq.saturating_add(1)..)?.to_vec()),
            ))
        })
        .collect())
}

/// The source package to stage, checked.
struct Source {
    pkgdir: PathBuf,
    /// The directory name: OUTDIR/<name>.
    name: OsString,
    /// The `Source:` value(s).
    srcpkg: Vec<u8>,
    /// The changelog to write for the run, if any.
    changelog: Option<Vec<u8>>,
    epoch: i64,
}

/// A version given with `--version`: a Debian version, starting with a digit, made of
/// the characters policy allows (`[0-9A-Za-z.+~:-]`).
fn check_version(v: &[u8]) -> Result<()> {
    let ok = v.first().is_some_and(u8::is_ascii_digit)
        && v.iter()
            .all(|&c| c.is_ascii_alphanumeric() || b".+~:-".contains(&c));
    if ok {
        Ok(())
    } else {
        Err(err(format_args!(
            "invalid version '{}'",
            String::from_utf8_lossy(v)
        )))
    }
}

/// The first value of `field` in the first stanza of control data.
fn control_field(control: &[u8], field: &[u8]) -> Option<String> {
    control
        .split(|&c| c == b'\n')
        .take_while(|l| !l.trim_ascii().is_empty())
        .find_map(|l| {
            let (k, v) = l.split_at(l.iter().position(|&c| c == b':')?);
            let v = v.get(1..)?.trim_ascii();
            k.eq_ignore_ascii_case(field)
                .then(|| String::from_utf8_lossy(v).into_owned())
        })
}

/// `dpkg-parsechangelog -S Timestamp` in `srcdir`.
fn changelog_timestamp(srcdir: &Path) -> Result<i64> {
    let out = Command::new("dpkg-parsechangelog")
        .args(["-S", "Timestamp"])
        .current_dir(srcdir)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| err(format_args!("dpkg-parsechangelog: {e}")))?;
    if !out.status.success() {
        return Err(Error::Exit(crate::shell_status(out.status)));
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .map_err(|_| err("dpkg-parsechangelog: no valid Timestamp"))
}

/// The changelog entry of `entry` for source package `srcpkg`.
fn changelog_entry(entry: &Entry, srcpkg: &[u8], control: &[u8], epoch: i64) -> Vec<u8> {
    let maintainer = entry.maintainer.clone().unwrap_or_else(|| {
        match (std::env::var("DEBFULLNAME"), std::env::var("DEBEMAIL")) {
            (Ok(n), Ok(e)) if !n.is_empty() && !e.is_empty() => format!("{n} <{e}>"),
            _ => control_field(control, b"Maintainer").unwrap_or_default(),
        }
    });
    let version = String::from_utf8_lossy(&entry.version);
    let mut out = srcpkg.to_vec();
    out.extend_from_slice(
        format!(
            " ({version}) {}; urgency=medium\n\n  * {}\n\n -- {maintainer}  {}\n",
            entry.distribution.as_deref().unwrap_or("UNRELEASED"),
            entry
                .message
                .clone()
                .unwrap_or_else(|| format!("Build {version}")),
            rfc2822::format(epoch)
        )
        .as_bytes(),
    );
    out
}

/// `SOURCE_DATE_EPOCH` of the environment, unless unset or empty: a number of seconds.
fn env_epoch() -> Result<Option<i64>> {
    match std::env::var_os("SOURCE_DATE_EPOCH") {
        None => Ok(None),
        Some(e) if e.is_empty() => Ok(None),
        Some(e) => e
            .to_str()
            .filter(|s| s.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
            .map(Some)
            .ok_or_else(|| {
                err(format_args!(
                    "invalid SOURCE_DATE_EPOCH '{}' in the environment",
                    e.to_string_lossy()
                ))
            }),
    }
}

/// Check and resolve the source directory, read its source name, the changelog to
/// write and the epoch.
fn resolve(opts: &Options) -> Result<Source> {
    let srcdir = logical_abs(&opts.srcdir).map_err(err)?;
    match fs::metadata(&srcdir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(err(format_args!(
                "{}: Not a directory",
                opts.srcdir.display()
            )));
        }
        Err(e) => return Err(io_err(&opts.srcdir, &e)),
    }
    let control_path = srcdir.join("debian/control");
    if !control_path.is_file() {
        return Err(err(format_args!(
            "no debian/control in {}",
            srcdir.display()
        )));
    }
    let control = fs::read(&control_path).map_err(|e| io_err(&control_path, &e))?;
    let srcpkg = source_name(&control);
    if srcpkg.is_empty() {
        return Err(err(format_args!(
            "no Source: in {}",
            control_path.display()
        )));
    }
    let env_epoch = match opts.epoch {
        Some(_) => None,
        None => env_epoch()?,
    };
    let changelog_path = srcdir.join("debian/changelog");
    let (changelog, epoch) = if let Some(entry) = &opts.entry {
        check_version(&entry.version)?;
        if fs::symlink_metadata(&changelog_path).is_ok() {
            return Err(err(format_args!(
                "{} exists: --version would replace it",
                changelog_path.display()
            )));
        }
        let epoch = opts.epoch.or(env_epoch).unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        });
        (
            Some(changelog_entry(entry, &srcpkg, &control, epoch)),
            epoch,
        )
    } else {
        if !changelog_path.is_file() {
            return Err(err(format_args!(
                "no debian/changelog in {}: give --version",
                srcdir.display()
            )));
        }
        let epoch = match opts.epoch.or(env_epoch) {
            Some(e) => e,
            None => changelog_timestamp(&srcdir)?,
        };
        (None, epoch)
    };
    Ok(Source {
        name: srcdir.file_name().unwrap_or_default().to_os_string(),
        pkgdir: srcdir,
        srcpkg,
        changelog,
        epoch,
    })
}

/// The environment debian/rules gets on top of the caller's: this binary as
/// `dh_builddeb` and `dh_strip_nondeterminism` first in PATH (from `workdir/.bin`,
/// which publishing skips), the staging directory, `SOURCE_DATE_EPOCH` and
/// dpkg-architecture's variables.
fn rules_env(
    workdir: &Path,
    pkgdir: &Path,
    exe: &Path,
    epoch: i64,
) -> Result<Vec<(OsString, OsString)>> {
    let bin = workdir.join(".bin");
    fs::create_dir(&bin).map_err(|e| io_err(&bin, &e))?;
    for helper in ["dh_builddeb", "dh_strip_nondeterminism"] {
        symlink(exe, bin.join(helper)).map_err(|e| io_err(&bin, &e))?;
    }
    let mut path = bin.into_os_string();
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());

    // The environment dpkg-buildpackage gives debian/rules: host/build architecture
    // (dh_python3 needs DEB_HOST_ARCH). It does not export the dpkg-buildflags flags:
    // debhelper passes them to its own dh_auto_* helpers only.
    let mut env = vec![(
        OsString::from("SOURCE_DATE_EPOCH"),
        OsString::from(epoch.to_string()),
    )];
    env.extend(dpkg_architecture()?);
    for (k, v) in [
        ("DEBBUILD_RS_STAGE_DIR", workdir.as_os_str()),
        ("PATH", path.as_os_str()),
        // The rules run in the package directory, as after a shell's `cd`.
        ("PWD", pkgdir.as_os_str()),
    ] {
        env.push((k.into(), v.to_os_string()));
    }
    Ok(env)
}

/// The length of the random part of a work directory name.
const WORK_RAND: usize = 6;

/// Whether `name`, an entry of OUTDIR, is a work directory of a run staging the output
/// whose work directories start with `prefix` (`.work.<dir>.`): `prefix`, then the
/// random part, then nothing, or `.old` for a previous generation set aside.
fn own_workdir(name: &[u8], prefix: &[u8]) -> bool {
    name.strip_prefix(prefix)
        .and_then(|rest| rest.split_at_checked(WORK_RAND))
        .is_some_and(|(rand, tail)| {
            rand.iter().all(u8::is_ascii_alphanumeric) && matches!(tail, b"" | b".old")
        })
}

/// Lock the output `dest` (OUTDIR/<dir>) for the run: a flock on OUTDIR/.<dir>.lock.
fn lock_output(outdir: &Path, name: &OsStr, dest: &Path) -> Result<Flock<File>> {
    let mut lock_name = OsString::from(".");
    lock_name.push(name);
    lock_name.push(".lock");
    let path = outdir.join(lock_name);
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| io_err(&path, &e))?;
    Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| {
        if e == Errno::EWOULDBLOCK {
            err(format_args!("{} is already being staged", dest.display()))
        } else {
            err(format_args!("{}: {e}", path.display()))
        }
    })
}

/// Take the publish lock `file` of `dest` (OUTDIR/<dir>) exclusively, once its readers
/// are done; a caught signal ends the wait.
fn lock_publish(mut file: File, dest: &Path) -> Result<Flock<File>> {
    let mut waiting = false;
    loop {
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(held) => return Ok(held),
            Err((f, Errno::EWOULDBLOCK)) => {
                if signals::caught().is_some() {
                    return Err(Error::Exit(1));
                }
                if !waiting {
                    eprintln!("debbuild-rs: waiting for the readers of {}", dest.display());
                    waiting = true;
                }
                std::thread::sleep(Duration::from_millis(50));
                file = f;
            }
            Err((_, e)) => return Err(err(format_args!("{}: {e}", dest.display()))),
        }
    }
}

/// Publish the staged trees of `workdir` as `outdir/<name>`, listed in `.staged`, in
/// place of the previous ones, under the publish lock `lock`; return the staged
/// packages.
fn publish(src: &Source, workdir: &Path, outdir: &Path, lock: File) -> Result<Vec<OsString>> {
    // The staged packages: the subdirectories of workdir (`*/`, so no dot names).
    let mut staged: Vec<OsString> = Vec::new();
    for entry in fs::read_dir(workdir).map_err(|e| io_err(workdir, &e))? {
        let entry = entry.map_err(|e| io_err(workdir, &e))?;
        let n = entry.file_name();
        if !n.as_bytes().starts_with(b".") && entry.path().is_dir() {
            staged.push(n);
        }
    }
    staged.sort();
    if staged.is_empty() {
        return Err(err(format_args!(
            "{} staged no package",
            String::from_utf8_lossy(&src.srcpkg)
        )));
    }
    let mut list = Vec::new();
    for n in &staged {
        list.extend_from_slice(n.as_bytes());
        list.push(b'\n');
    }
    let list_path = workdir.join(".staged");
    fs::write(&list_path, list).map_err(|e| io_err(&list_path, &e))?;
    fs::set_permissions(workdir, fs::Permissions::from_mode(0o755))
        .map_err(|e| io_err(workdir, &e))?;
    let dest = outdir.join(&src.name);
    let held = lock_publish(lock, &dest)?;
    let old = exchange_dir(workdir, &dest).map_err(|e| io_err(&dest, &e))?;
    // No reader can be in the previous generation now: remove it without the lock.
    drop(held);
    if let Some(old) = old {
        remove_all(&old).map_err(|e| io_err(&old, &e))?;
    }
    Ok(staged)
}

/// Build `opts.srcdir` into staged package trees.
///
/// # Errors
/// Any failed step: the message, or the exit status of the failed child process.
pub fn stage(opts: &Options) -> Result<()> {
    preflight(opts)?;
    let src = resolve(opts)?;
    let pkgdir = &src.pkgdir;
    let outdir = &opts.outdir;
    fs::create_dir_all(outdir).map_err(|e| io_err(outdir, &e))?;
    let outdir = logical_abs(outdir).map_err(err)?;

    // Builds modify the source tree, so allow only one staging run per source tree: a
    // flock on debian/.
    let debian = File::open(pkgdir.join("debian")).map_err(|e| io_err(pkgdir, &e))?;
    let _lock = Flock::lock(debian, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| {
        if e == Errno::EWOULDBLOCK {
            err(format_args!(
                "{} is already being staged",
                src.name.to_string_lossy()
            ))
        } else {
            err(format_args!("{}/debian: {e}", pkgdir.display()))
        }
    })?;
    // Other source trees of the same name stage into the same OUTDIR/<dir>: one run at a
    // time, the lock held until the run ends.
    let _out_lock = lock_output(&outdir, &src.name, &outdir.join(&src.name))?;
    // The readers' lock, created now so that readers starting during the build take it.
    let publish_lock_path = staged_lock::lock_path(&outdir, &src.name);
    let publish_lock = staged_lock::open_lock(&publish_lock_path, true)
        .map_err(|e| io_err(&publish_lock_path, &e))?;
    // The work directories of this output left by killed runs (no other run holds the
    // lock).
    let mut prefix = b".work.".to_vec();
    prefix.extend_from_slice(src.name.as_bytes());
    prefix.push(b'.');
    for entry in fs::read_dir(&outdir).map_err(|e| io_err(&outdir, &e))? {
        let entry = entry.map_err(|e| io_err(&outdir, &e))?;
        if own_workdir(entry.file_name().as_bytes(), &prefix) {
            remove_all(&entry.path()).map_err(|e| io_err(&entry.path(), &e))?;
        }
    }
    // Stage in a private directory; publish all packages together after a successful build.
    let workdir = tempfile::Builder::new()
        .prefix(OsStr::from_bytes(&prefix))
        .rand_bytes(WORK_RAND)
        .tempdir_in(&outdir)
        .map_err(|e| io_err(&outdir, &e))?
        .keep();
    let mut cleanup = Cleanup {
        pkgdir: pkgdir.clone(),
        workdir: workdir.clone(),
        env: Vec::new(),
        started: false,
        generated: src.changelog.is_some(),
    };

    let changelog_path = pkgdir.join("debian/changelog");
    if let Some(changelog) = &src.changelog {
        fs::write(&changelog_path, changelog).map_err(|e| io_err(&changelog_path, &e))?;
    }

    let env = rules_env(&workdir, pkgdir, &opts.exe, src.epoch)?;
    cleanup.env.clone_from(&env);
    cleanup.started = true;
    let rules = |fakeroot: bool, target: &str| -> Result<()> {
        let mut cmd = if fakeroot {
            let mut c = Command::new("fakeroot");
            c.arg("debian/rules");
            c
        } else {
            Command::new("debian/rules")
        };
        cmd.arg(target)
            .current_dir(pkgdir)
            .envs(env.iter().map(|(k, v)| (k, v)));
        run(&mut cmd, "debian/rules")?;
        match signals::caught() {
            Some(_) => Err(Error::Exit(1)),
            None => Ok(()),
        }
    };
    rules(true, "clean")?;
    rules(false, "build")?;
    rules(true, "binary")?;
    rules(true, "clean")?;
    cleanup.started = false;
    if src.changelog.is_some() {
        fs::remove_file(&changelog_path).map_err(|e| io_err(&changelog_path, &e))?;
    }
    let bin = workdir.join(".bin");
    fs::remove_dir_all(&bin).map_err(|e| io_err(&bin, &e))?;

    let staged = publish(&src, &workdir, &outdir, publish_lock)?;
    drop(cleanup);
    let names: Vec<_> = staged.iter().map(|n| n.as_bytes()).collect();
    let mut line = b"debbuild-rs: ".to_vec();
    line.extend_from_slice(&src.srcpkg);
    line.extend_from_slice(b" -> ");
    line.extend_from_slice(&names.join(&b' '));
    line.push(b'\n');
    io::Write::write_all(&mut io::stdout(), &line).map_err(err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_fields() {
        let c = b"Source: s\nmaintainer:  A <a@b>\n\nPackage: p\nMaintainer: x\n";
        assert_eq!(control_field(c, b"Maintainer").as_deref(), Some("A <a@b>"));
        assert_eq!(control_field(c, b"Package"), None);
    }

    #[test]
    fn own_workdirs() {
        let p = b".work.a.";
        for (name, own) in [
            (&b".work.a.Xy0123"[..], true),
            (b".work.a.Xy0123.old", true),
            (b".work.a.Xy012", false),
            (b".work.a.Xy0123x", false),
            (b".work.a.b.Xy0123", false),
            (b".work.a.Xy01-3", false),
            (b".work.ab.Xy0123", false),
            (b".a.lock", false),
        ] {
            assert_eq!(
                own_workdir(name, p),
                own,
                "{}",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn source_lines() {
        assert_eq!(source_name(b"Source: a\nPackage: b\n"), b"a");
        assert_eq!(source_name(b"Source:a\nSource:   b  \n"), b"a\nb  ");
        assert_eq!(source_name(b"source: a\n Source: b\n"), b"");
    }
}
