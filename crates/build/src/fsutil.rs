//! File helpers with the semantics of the shell commands they replace.

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use nix::sys::stat::{UtimensatFlags, utimensat};
use nix::sys::time::TimeSpec;

pub use debbuild_rs_common::staged_lock::logical_abs;

/// Put directory `new` in place as `dest`: in one rename that readers see as atomic,
/// exchanging the two when `dest` exists (`RENAME_EXCHANGE`). Returns where the
/// previous `dest` now is, for the caller to remove: `new`.
pub fn exchange_dir(new: &Path, dest: &Path) -> io::Result<Option<PathBuf>> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    use rustix::io::Errno;
    match renameat_with(CWD, new, CWD, dest, RenameFlags::NOREPLACE) {
        Ok(()) => return Ok(None),
        Err(Errno::EXIST) => {}
        // A file system without the flags.
        Err(Errno::INVAL) => return exchange_dir_unflagged(new, dest),
        Err(e) => return Err(e.into()),
    }
    match renameat_with(CWD, new, CWD, dest, RenameFlags::EXCHANGE) {
        Ok(()) => Ok(Some(new.to_path_buf())),
        Err(Errno::INVAL) => exchange_dir_unflagged(new, dest),
        Err(e) => Err(e.into()),
    }
}

/// [`exchange_dir`] on file systems without `renameat2`'s flags: the previous `dest` is
/// renamed to `<new>.old`, then `new` to `dest`. Between the two, `dest` is missing.
fn exchange_dir_unflagged(new: &Path, dest: &Path) -> io::Result<Option<PathBuf>> {
    let mut old = new.as_os_str().to_owned();
    old.push(".old");
    let old = PathBuf::from(old);
    let had = match fs::rename(dest, &old) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(e),
    };
    if let Err(e) = fs::rename(new, dest) {
        if had {
            // Put the previous generation back; the error at hand is the one to report.
            let _ = fs::rename(&old, dest);
        }
        return Err(e);
    }
    Ok(had.then_some(old))
}

/// `rm -rf PATH`.
pub fn remove_all(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(m) if m.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
    }
}

fn set_times(path: &Path, m: &fs::Metadata) -> io::Result<()> {
    let atime = TimeSpec::new(m.atime(), m.atime_nsec());
    let mtime = TimeSpec::new(m.mtime(), m.mtime_nsec());
    utimensat(
        nix::fcntl::AT_FDCWD,
        path,
        &atime,
        &mtime,
        UtimensatFlags::NoFollowSymlink,
    )
    .map_err(io::Error::from)
}

/// `cp -a SRC DST` minus the ownership: contents, permission bits, access and
/// modification times; symlinks copied as symlinks.
pub fn copy_tree(src: &Path, dst: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(src)?;
    if m.file_type().is_symlink() {
        symlink(fs::read_link(src)?, dst)?;
    } else if m.is_dir() {
        fs::create_dir(dst)?;
        let mut names: Vec<_> = fs::read_dir(src)?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<io::Result<_>>()?;
        names.sort();
        for name in names {
            copy_tree(&src.join(&name), &dst.join(&name))?;
        }
        fs::set_permissions(dst, fs::Permissions::from_mode(m.mode() & 0o7777))?;
    } else {
        fs::copy(src, dst)?;
        fs::set_permissions(dst, fs::Permissions::from_mode(m.mode() & 0o7777))?;
    }
    set_times(dst, &m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let (new, dest) = (tmp.path().join("new"), tmp.path().join("dest"));
        let names = || {
            let mut v: Vec<_> = fs::read_dir(tmp.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            v.sort();
            v
        };
        for f in [exchange_dir, exchange_dir_unflagged] {
            remove_all(&dest).unwrap();
            fs::create_dir(&new).unwrap();
            fs::write(new.join("1"), "").unwrap();
            assert_eq!(f(&new, &dest).unwrap(), None);
            assert!(dest.join("1").exists());
            fs::create_dir(&new).unwrap();
            fs::write(new.join("2"), "").unwrap();
            let old = f(&new, &dest).unwrap().unwrap();
            assert!(dest.join("2").exists() && old.join("1").exists());
            remove_all(&old).unwrap();
            assert_eq!(names(), ["dest"]);
        }
    }
}
