//! The error type of every debbuild-rs library: a message, printed as
//! `debbuild-rs-<cmd>: error: <message>` by the binary.
//!
//! System errors read as Python printed them (`[Errno 2] No such file or directory:
//! '/x'`), so that the installer's messages stay those of its first implementation.

use std::fmt;
use std::io;
use std::path::Path;

use crate::py;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: Kind,
    msg: String,
}

/// What raised the error, in the Python implementation: the error unwinding of the
/// installer catches some kinds and not others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A refusal of the installer (`DebstageError`).
    Refusal,
    /// A failed system call or archive read (`OSError`, `TarError`).
    Os,
    /// Invalid data no handler expects (`ValueError` from a version, `KeyError`).
    Value,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            kind: Kind::Refusal,
            msg: msg.into(),
        }
    }

    /// An error of the kind Python's `ValueError` was.
    pub fn value(msg: impl Into<String>) -> Self {
        Self {
            kind: Kind::Value,
            msg: msg.into(),
        }
    }

    /// An error of the kind Python's `OSError` was, with its message.
    pub fn os_msg(msg: impl Into<String>) -> Self {
        Self {
            kind: Kind::Os,
            msg: msg.into(),
        }
    }

    /// An error of a system call on `path`.
    #[must_use]
    pub fn os(err: &io::Error, path: &Path) -> Self {
        Self::os_msg(os_message(err, Some(path), None))
    }

    /// An error of a system call on two paths (rename, link, symlink).
    #[must_use]
    pub fn os2(err: &io::Error, src: &Path, dst: &Path) -> Self {
        Self::os_msg(os_message(err, Some(src), Some(dst)))
    }

    /// An error of a system call without a path.
    #[must_use]
    pub fn os_bare(err: &io::Error) -> Self {
        Self::os_msg(os_message(err, None, None))
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.msg
    }

    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Error {}

/// The C library's message for an I/O error, without std's ` (os error N)` suffix.
#[must_use]
pub fn strerror(err: &io::Error) -> String {
    let s = err.to_string();
    match err.raw_os_error() {
        Some(n) => s
            .strip_suffix(&format!(" (os error {n})"))
            .unwrap_or(&s)
            .to_owned(),
        None => s,
    }
}

fn os_message(err: &io::Error, path: Option<&Path>, path2: Option<&Path>) -> String {
    use std::os::unix::ffi::OsStrExt;
    let Some(errno) = err.raw_os_error() else {
        return err.to_string();
    };
    let mut s = format!("[Errno {errno}] {}", strerror(err));
    if let Some(p) = path {
        s.push_str(": ");
        s.push_str(&py::repr(p.as_os_str().as_bytes()));
        if let Some(p2) = path2 {
            s.push_str(" -> ");
            s.push_str(&py::repr(p2.as_os_str().as_bytes()));
        }
    }
    s
}

/// `.map_err(Error::os)` with the path at hand.
pub trait IoContext<T> {
    /// # Errors
    /// The I/O error, as Python prints it with `path`.
    fn at(self, path: &Path) -> Result<T>;
    /// # Errors
    /// The I/O error, as Python prints it with `src` and `dst`.
    fn at2(self, src: &Path, dst: &Path) -> Result<T>;
}

impl<T> IoContext<T> for io::Result<T> {
    fn at(self, path: &Path) -> Result<T> {
        self.map_err(|e| Error::os(&e, path))
    }

    fn at2(self, src: &Path, dst: &Path) -> Result<T> {
        self.map_err(|e| Error::os2(&e, src, dst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_format() {
        let e = io::Error::from_raw_os_error(2);
        assert_eq!(
            Error::os(&e, Path::new("/x/y")).message(),
            "[Errno 2] No such file or directory: '/x/y'"
        );
        assert_eq!(
            Error::os2(&e, Path::new("a"), Path::new("b")).message(),
            "[Errno 2] No such file or directory: 'a' -> 'b'"
        );
        assert_eq!(
            Error::os_bare(&e).message(),
            "[Errno 2] No such file or directory"
        );
    }
}
