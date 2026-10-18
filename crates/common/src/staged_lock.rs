//! The readers of a staged output and the stage run publishing it take turns.
//!
//! A stage run publishes OUTDIR/<dir> by exchanging it with the previous generation in
//! one rename. A reader that reads `.staged` and then the package trees by path could
//! still see two generations, one before the exchange and one after it, or have files
//! of the previous generation removed under it. So the exchange takes a flock on
//! OUTDIR/.<dir>.publish.lock exclusively, and a reader holds it shared for as long as
//! it reads OUTDIR/<dir>. A reader waits for an exchange at most, never for a build
//! (the stage run's own lock, OUTDIR/.<dir>.lock, is a different file); a publish waits
//! for the readers at hand.
//!
//! The stage run creates the lock file when it starts, before its build; a reader
//! creates it when it is missing. When a reader cannot create it, on a read-only file
//! system or in an output directory it may not write (a cache restored it read-only),
//! it reads without the lock: no stage run can publish there, unless one of a user
//! who may write the directory starts during the read, creates the lock file and
//! finishes its build before the read ends.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{FlockOperation, Mode, OFlags, fchmod, flock, open};
use rustix::io::Errno;

/// `cd DIR && pwd` without the cd: `dir` made absolute and normalized lexically, as the
/// shell's logical `cd` does (`..` removes the previous component).
///
/// # Errors
/// `dir` is relative and the current directory is unknown.
pub fn logical_abs(dir: &Path) -> io::Result<PathBuf> {
    let joined = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()?.join(dir)
    };
    let mut out = PathBuf::from("/");
    for c in joined.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(n) => out.push(n),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    Ok(out)
}

/// The publish lock file of OUTDIR/<name>: OUTDIR/.<name>.publish.lock.
#[must_use]
pub fn lock_path(outdir: &Path, name: &OsStr) -> PathBuf {
    let mut file = b".".to_vec();
    file.extend_from_slice(name.as_bytes());
    file.extend_from_slice(b".publish.lock");
    outdir.join(OsStr::from_bytes(&file))
}

/// Open the lock file `path`, creating it (mode 0644, whatever the umask: the readers
/// and stage runs of other users open it too) when `create`.
///
/// # Errors
/// The file cannot be opened, or created when `create`.
pub fn open_lock(path: &Path, create: bool) -> io::Result<File> {
    let flags = OFlags::RDONLY | OFlags::CLOEXEC;
    loop {
        match open(path, flags, Mode::empty()) {
            Err(Errno::NOENT) if create => {}
            r => return Ok(File::from(r?)),
        }
        match open(
            path,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from(0o644),
        ) {
            Ok(fd) => {
                fchmod(&fd, Mode::from(0o644))?;
                return Ok(File::from(fd));
            }
            // Created meanwhile: open that one.
            Err(Errno::EXIST) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// Shared flocks on the publish locks of staged source directories, released on drop.
#[derive(Debug, Default)]
pub struct ReadLock {
    files: Vec<File>,
}

impl ReadLock {
    /// The number of source directories locked: those read unlocked are not counted.
    #[must_use]
    pub fn held(&self) -> usize {
        self.files.len()
    }

    /// Lock the staged source directory `dir` (OUTDIR/<dir>) for reading too.
    ///
    /// # Errors
    /// The lock file cannot be opened or locked.
    pub fn add_source(&mut self, dir: &Path) -> io::Result<()> {
        let abs = logical_abs(dir)?;
        let (Some(outdir), Some(name)) = (abs.parent(), abs.file_name()) else {
            return Ok(());
        };
        let path = lock_path(outdir, name);
        // The lock file of what is not a directory is not created: nothing to lock,
        // and the reader reports it.
        let file = match open_lock(&path, abs.is_dir()) {
            Ok(f) => f,
            Err(e)
                if matches!(
                    Errno::from_io_error(&e),
                    Some(Errno::NOENT | Errno::ROFS | Errno::ACCESS | Errno::PERM)
                ) =>
            {
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        loop {
            match flock(&file, FlockOperation::LockShared) {
                Err(Errno::INTR) => {}
                r => break r?,
            }
        }
        self.files.push(file);
        Ok(())
    }
}

/// Lock the staged source directory `dir` (OUTDIR/<dir>) for reading.
///
/// # Errors
/// The lock file cannot be opened or locked.
pub fn read_source(dir: &Path) -> io::Result<ReadLock> {
    let mut lock = ReadLock::default();
    lock.add_source(dir)?;
    Ok(lock)
}

/// Lock `staged` for reading: a staged source directory (holding .staged), or the one
/// of a staged package tree (holding DEBIAN/).
///
/// # Errors
/// The lock file cannot be opened or locked.
pub fn read_staged(staged: &Path) -> io::Result<ReadLock> {
    if !staged.join(".staged").exists() && staged.join("DEBIAN").is_dir() {
        let abs = logical_abs(staged)?;
        return read_source(abs.parent().unwrap_or(&abs));
    }
    read_source(staged)
}

/// Lock every staged source directory of the output directory `outdir` (its
/// directories holding .staged, symlinks followed, but the `.` ones) for reading. An
/// `outdir` that cannot be listed has none: the reader reports it.
///
/// # Errors
/// A lock file cannot be opened or locked.
pub fn read_output(outdir: &Path) -> io::Result<ReadLock> {
    let mut lock = ReadLock::default();
    let Ok(entries) = fs::read_dir(outdir) else {
        return Ok(lock);
    };
    let mut dirs = Vec::new();
    for e in entries {
        let e = e?;
        if !e.file_name().as_bytes().starts_with(b".") && e.path().join(".staged").is_file() {
            dirs.push(e.path());
        }
    }
    // One order for every reader.
    dirs.sort();
    for d in dirs {
        lock.add_source(&d)?;
    }
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt;

    fn try_exclusive(path: &Path) -> bool {
        let f = File::open(path).unwrap();
        flock(&f, FlockOperation::NonBlockingLockExclusive).is_ok()
    }

    /// [`try_exclusive`], until it succeeds or for a second: a test of another thread
    /// spawning a process holds a copy of the descriptors until the exec.
    fn exclusive_soon(path: &Path) -> bool {
        (0..100).any(|_| {
            try_exclusive(path) || {
                std::thread::sleep(std::time::Duration::from_millis(10));
                false
            }
        })
    }

    #[test]
    fn logical_paths() {
        assert_eq!(
            logical_abs(Path::new("/a/./b/../c/")).unwrap(),
            Path::new("/a/c")
        );
        assert_eq!(logical_abs(Path::new("/../x")).unwrap(), Path::new("/x"));
        assert!(logical_abs(Path::new("rel")).unwrap().is_absolute());
    }

    #[test]
    fn read_locks() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path();
        fs::create_dir_all(out.join("src/pkg/DEBIAN")).unwrap();
        fs::write(out.join("src/.staged"), "pkg\n").unwrap();
        fs::create_dir(out.join(".work.src.abc123")).unwrap();
        fs::write(out.join("file"), "").unwrap();
        fs::create_dir_all(out.join("unstaged/pkg/DEBIAN")).unwrap();
        let lock = out.join(".src.publish.lock");

        // A source directory, a package tree of it, an output directory: the source's.
        let locks: [&dyn Fn() -> io::Result<ReadLock>; 4] = [
            &|| read_source(&out.join("src")),
            &|| read_staged(&out.join("src")),
            &|| read_staged(&out.join("src/pkg/../pkg")),
            &|| read_output(out),
        ];
        for lock_it in locks {
            let held = lock_it().unwrap();
            assert_eq!(held.held(), 1);
            assert_eq!(
                fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
                0o644
            );
            assert!(!try_exclusive(&lock));
            drop(held);
            assert!(exclusive_soon(&lock));
        }
        // Nothing created for what is not a directory, or not a staged one in an output.
        assert_eq!(read_source(&out.join("missing")).unwrap().held(), 0);
        assert!(!out.join(".missing.publish.lock").exists());
        assert!(!out.join(".unstaged.publish.lock").exists());
        assert_eq!(read_output(&out.join("missing")).unwrap().held(), 0);

        // A lock file that cannot be created: read unlocked.
        fs::remove_file(&lock).unwrap();
        fs::set_permissions(out, fs::Permissions::from_mode(0o555)).unwrap();
        let ro = read_source(&out.join("src"));
        fs::set_permissions(out, fs::Permissions::from_mode(0o755)).unwrap();
        // root writes anyway
        assert_eq!(ro.unwrap().held(), usize::from(lock.exists()));
    }
}
