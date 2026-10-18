//! File helpers with the semantics of the Python calls the installer was written with.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use md5::{Digest, Md5};
use nix::sys::stat::{UtimensatFlags, utimensat};
use nix::sys::time::TimeSpec;

use debbuild_rs_common::{Error, IoContext, Result, py};

/// Lowercase hex of a digest.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        // Writing to a String cannot fail.
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// `bytes.decode()`: strict UTF-8, with Python's error message.
///
/// # Errors
/// Invalid UTF-8.
pub fn decode(data: Vec<u8>) -> Result<String> {
    String::from_utf8(data).map_err(|e| {
        let u = e.utf8_error();
        let pos = u.valid_up_to();
        let bytes = e.as_bytes();
        let byte = bytes.get(pos).copied().unwrap_or(0);
        let why = match u.error_len() {
            None => "unexpected end of data",
            Some(_) if (0x80..=0xc1).contains(&byte) || byte >= 0xf5 => "invalid start byte",
            Some(_) => "invalid continuation byte",
        };
        Error::value(format!(
            "'utf-8' codec can't decode byte 0x{byte:02x} in position {pos}: {why}"
        ))
    })
}

/// `Path.read_text()`.
///
/// # Errors
/// The file cannot be read, or is not UTF-8.
pub fn read_text(path: &Path) -> Result<String> {
    decode(fs::read(path).at(path)?)
}

/// `read_text(errors="surrogateescape").splitlines()`, as bytes.
///
/// # Errors
/// The file cannot be read.
pub fn read_lines(path: &Path) -> Result<Vec<Vec<u8>>> {
    let data = fs::read(path).at(path)?;
    Ok(py::splitlines(&data)
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect())
}

/// Lines, each ended by a newline.
pub fn lines_bytes<'a>(lines: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    for l in lines {
        out.extend_from_slice(l);
        out.push(b'\n');
    }
    out
}

/// `Path.exists()`: false on any error.
pub fn exists(path: &Path) -> bool {
    fs::metadata(path).is_ok()
}

/// `os.path.lexists()`.
pub fn lexists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// `Path.is_dir()`.
pub fn is_dir(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_dir())
}

/// `Path.is_file()`.
pub fn is_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file())
}

/// `Path.is_symlink()`.
pub fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// md5 of the regular file at `path` (symlinks followed), `None` when there is none.
///
/// # Errors
/// The file cannot be read, or a path component is not a directory.
pub fn md5_file(path: &Path) -> Result<Option<String>> {
    match fs::metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::os(&e, path)),
        Ok(m) if !m.is_file() => return Ok(None),
        Ok(_) => {}
    }
    let mut f = match File::open(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        r => r.at(path)?,
    };
    let mut h = Md5::new();
    copy_hashing(&mut f, &mut io::sink(), |c| h.update(c)).at(path)?;
    Ok(Some(hex(&h.finalize())))
}

/// Copy `src` to `dst` in 1 MiB chunks, passing each chunk to `update`.
pub fn copy_hashing(
    src: &mut impl Read,
    dst: &mut impl Write,
    mut update: impl FnMut(&[u8]),
) -> io::Result<()> {
    let mut buf = vec![0; 1 << 20];
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let chunk = buf.get(..n).unwrap_or_default();
        update(chunk);
        dst.write_all(chunk)?;
    }
}

/// Create (or truncate) a file as Python's `open(path, "wb")` does: mode 0666 minus
/// the umask, symlinks followed.
///
/// # Errors
/// The file cannot be created.
pub fn create(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o666)
        .open(path)
        .at(path)
}

fn fsync_dir(dir: &Path) -> Result<()> {
    let d = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_DIRECTORY.bits())
        .open(dir)
        .at(dir)?;
    d.sync_all().at(dir)
}

/// Replace `path` with `data` durably: write `tmp` (opened as `tmp_open`, the same path
/// with a final symlink resolved), fsync it, set `mode`, rename it over `path`, fsync
/// the directory.
///
/// # Errors
/// Any step fails.
pub fn write_atomic(
    path: &Path,
    tmp: &Path,
    tmp_open: &Path,
    data: &[u8],
    mode: Option<u32>,
) -> Result<()> {
    let mut f = create(tmp_open)?;
    f.write_all(data).at(tmp_open)?;
    f.flush().at(tmp_open)?;
    f.sync_all().at(tmp_open)?;
    drop(f);
    if let Some(m) = mode {
        fs::set_permissions(tmp_open, fs::Permissions::from_mode(m)).at(tmp_open)?;
    }
    fs::rename(tmp, path).at2(tmp, path)?;
    fsync_dir(path.parent().unwrap_or(Path::new("/")))
}

/// Set the access and modification times of `path` (not following a symlink).
///
/// # Errors
/// The call fails.
pub fn set_times(path: &Path, atime: TimeSpec, mtime: TimeSpec) -> io::Result<()> {
    utimensat(
        nix::fcntl::AT_FDCWD,
        path,
        &atime,
        &mtime,
        UtimensatFlags::FollowSymlink,
    )
    .map_err(io::Error::from)
}

/// `shutil.copy2`: contents, mode, access and modification times.
///
/// # Errors
/// A file cannot be read or written.
pub fn copy2(src: &Path, dst: &Path) -> Result<()> {
    let m = fs::metadata(src).at(src)?;
    let mut from = File::open(src).at(src)?;
    let mut to = create(dst)?;
    io::copy(&mut from, &mut to).at(dst)?;
    drop(to);
    set_times(
        dst,
        TimeSpec::new(m.atime(), m.atime_nsec()),
        TimeSpec::new(m.mtime(), m.mtime_nsec()),
    )
    .at(dst)?;
    fs::set_permissions(dst, fs::Permissions::from_mode(m.mode() & 0o7777)).at(dst)
}

/// `shutil.rmtree(path, ignore_errors=True)`.
pub fn rmtree_quiet(path: &Path) {
    // A symlink is not removed (rmtree refuses it); errors are ignored, as with
    // ignore_errors=True.
    if fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
        let _ = fs::remove_dir_all(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_errors() {
        assert_eq!(decode(b"ab".to_vec()).unwrap(), "ab");
        assert_eq!(
            decode(b"ab\xff".to_vec()).unwrap_err().message(),
            "'utf-8' codec can't decode byte 0xff in position 2: invalid start byte"
        );
        assert_eq!(
            decode(b"a\xc3(".to_vec()).unwrap_err().message(),
            "'utf-8' codec can't decode byte 0xc3 in position 1: invalid continuation byte"
        );
        assert_eq!(
            decode(b"a\xe2\x82".to_vec()).unwrap_err().message(),
            "'utf-8' codec can't decode byte 0xe2 in position 1: unexpected end of data"
        );
    }

    #[test]
    fn md5_of_files() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("f");
        fs::write(&f, "a").unwrap();
        assert_eq!(
            md5_file(&f).unwrap().unwrap(),
            "0cc175b9c0f1b6a831c399e269772661"
        );
        assert_eq!(md5_file(&t.path().join("missing")).unwrap(), None);
        assert_eq!(md5_file(t.path()).unwrap(), None);
        assert!(md5_file(&f.join("x")).is_err());
    }
}
