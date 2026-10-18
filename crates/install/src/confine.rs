//! Paths resolved inside a root directory, symlinks included, as if it were `/`.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use debbuild_rs_common::{Error, IoContext, Result};

fn components(path: &[u8]) -> impl DoubleEndedIterator<Item = &[u8]> {
    path.split(|&c| c == b'/')
        .filter(|c| !c.is_empty() && *c != b".")
}

fn join(root: &Path, done: &[Vec<u8>]) -> PathBuf {
    let mut p = root.to_path_buf();
    for c in done {
        p.push(OsStr::from_bytes(c));
    }
    p
}

/// `root/path`, with the symlinks on the way resolved as if `root` were `/`.
///
/// The last component is resolved only with `follow`. Components that do not exist
/// are kept as they are (and a later `..` removes them, lexically). `..` never goes
/// above `root`.
///
/// # Errors
/// More than 40 symlinks, or a failed lstat other than a missing path.
pub fn confined(root: &Path, path: &[u8], follow: bool) -> Result<PathBuf> {
    let mut parts: VecDeque<Vec<u8>> = components(path).map(<[u8]>::to_vec).collect();
    let mut done: Vec<Vec<u8>> = Vec::new();
    let mut links = 0u32;
    while let Some(name) = parts.pop_front() {
        if name == b".." {
            done.pop();
            continue;
        }
        if !parts.is_empty() || follow {
            let mut cur = join(root, &done);
            cur.push(OsStr::from_bytes(&name));
            let st = match fs::symlink_metadata(&cur) {
                Ok(st) => st,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    done.push(name);
                    continue;
                }
                Err(e) => return Err(Error::os(&e, &cur)),
            };
            if st.file_type().is_symlink() {
                links = links.saturating_add(1);
                if links > 40 {
                    return Err(Error::new(format!(
                        "{}: too many levels of symbolic links",
                        String::from_utf8_lossy(path)
                    )));
                }
                let target = fs::read_link(&cur).at(&cur)?;
                let target = target.as_os_str().as_bytes();
                if target.starts_with(b"/") {
                    done.clear();
                }
                for c in components(target).rev() {
                    parts.push_front(c.to_vec());
                }
                continue;
            }
        }
        done.push(name);
    }
    Ok(join(root, &done))
}

/// `confined` on a `str` path.
///
/// # Errors
/// See [`confined`].
pub fn confined_str(root: &Path, path: &str, follow: bool) -> Result<PathBuf> {
    confined(root, path.as_bytes(), follow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn root_confinement() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir(root.join("target")).unwrap();
        symlink("/target", root.join("etc/abs")).unwrap();
        symlink("../../../../..", root.join("etc/up")).unwrap();
        assert_eq!(
            confined_str(root, "/etc/abs/f", false).unwrap(),
            root.join("target/f")
        );
        assert_eq!(
            confined_str(root, "/etc/up/f", true).unwrap(),
            root.join("f")
        );
        assert_eq!(
            confined_str(root, "/etc/abs", true).unwrap(),
            root.join("target")
        );
        assert_eq!(
            confined_str(root, "/etc/abs", false).unwrap(),
            root.join("etc/abs")
        );
    }

    /// K1: a missing component followed by `..` is removed lexically.
    #[test]
    fn missing_then_dotdot() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        fs::create_dir_all(root.join("a")).unwrap();
        symlink("missing/../../b", root.join("a/l")).unwrap();
        assert_eq!(
            confined_str(root, "a/l/x", false).unwrap(),
            root.join("b/x")
        );
        assert_eq!(
            confined_str(root, "nope/../../x", false).unwrap(),
            root.join("x")
        );
    }

    #[test]
    fn loops() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        symlink("l2", root.join("l1")).unwrap();
        symlink("l1", root.join("l2")).unwrap();
        assert_eq!(
            confined_str(root, "/l1/x", false).unwrap_err().message(),
            "/l1/x: too many levels of symbolic links"
        );
        // not followed: no loop
        assert_eq!(confined_str(root, "/l1", false).unwrap(), root.join("l1"));
    }

    #[test]
    fn not_a_directory() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        fs::write(root.join("f"), "").unwrap();
        let e = confined_str(root, "/f/x/y", false).unwrap_err();
        assert!(
            e.message().starts_with("[Errno 20] Not a directory: "),
            "{e}"
        );
    }
}
