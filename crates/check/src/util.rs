//! Commands and files for the checks: they run as root on throwaway overlays.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// A failure of the check itself (not a difference it found).
#[derive(Debug)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub fn err(msg: impl Into<String>) -> Error {
    Error(msg.into())
}

pub trait Context<T> {
    /// # Errors
    /// The error, with what was being done.
    fn ctx(self, what: impl fmt::Display) -> Result<T>;
}

impl<T, E: fmt::Display> Context<T> for std::result::Result<T, E> {
    fn ctx(self, what: impl fmt::Display) -> Result<T> {
        self.map_err(|e| Error(format!("{what}: {e}")))
    }
}

fn describe(cmd: &Command) -> String {
    let mut s = cmd.get_program().to_string_lossy().into_owned();
    for a in cmd.get_args() {
        s.push(' ');
        s.push_str(&a.to_string_lossy());
    }
    s
}

/// Run `cmd`, output inherited; fail unless it succeeds.
///
/// # Errors
/// It cannot start or fails.
pub fn run(cmd: &mut Command) -> Result<()> {
    let st = cmd.status().ctx(describe(cmd))?;
    if st.success() {
        Ok(())
    } else {
        Err(err(format!("{}: {st}", describe(cmd))))
    }
}

/// Run `cmd`, stdout captured (stderr inherited); fail unless it succeeds.
///
/// # Errors
/// It cannot start or fails.
pub fn output(cmd: &mut Command) -> Result<Vec<u8>> {
    let out = cmd.stderr(Stdio::inherit()).output().ctx(describe(cmd))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(err(format!("{}: {}", describe(cmd), out.status)))
    }
}

/// Run `cmd` with stdout and stderr captured together (in order), whatever its status.
///
/// # Errors
/// It cannot start.
pub fn transcript(cmd: &mut Command) -> Result<(i32, Vec<u8>)> {
    let (reader, writer) = io::pipe().ctx("pipe")?;
    let writer2 = writer.try_clone().ctx("pipe")?;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(writer2)
        .spawn()
        .ctx(describe(cmd))?;
    // The child holds the write ends now; ours are dropped with the Command.
    drop(std::mem::replace(cmd, Command::new("true")));
    let mut out = Vec::new();
    io::Read::read_to_end(&mut &reader, &mut out).ctx("read transcript")?;
    let st = child.wait().ctx("wait")?;
    let rc = st.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        st.signal().map_or(1, |s| s.saturating_add(128))
    });
    Ok((rc, out))
}

/// `Command::new(program).args(args)`.
pub fn cmd<I, S>(program: impl AsRef<OsStr>, args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut c = Command::new(program);
    c.args(args);
    c
}

/// `mkdir -p`.
///
/// # Errors
/// The directory cannot be created.
pub fn mkdirs(p: &Path) -> Result<()> {
    fs::create_dir_all(p).ctx(p.display())
}

/// The text of an output, lossy (for messages and line lists).
#[must_use]
pub fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// `cp -a SRC DST`.
///
/// # Errors
/// cp fails.
pub fn cp_a(src: &Path, dst: &Path) -> Result<()> {
    run(Command::new("cp").arg("-a").arg(src).arg(dst))
}

/// The one staged tree of `pkg` in `stagedir` (`STAGEDIR/*/PKG` with a DEBIAN directory).
///
/// # Errors
/// None or several.
pub fn staged_tree(stagedir: &Path, pkg: &str) -> Result<PathBuf> {
    let mut found = Vec::new();
    let mut dirs: Vec<PathBuf> = fs::read_dir(stagedir)
        .ctx(stagedir.display())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    dirs.sort();
    for d in dirs {
        let t = d.join(pkg);
        if t.join("DEBIAN").is_dir() {
            found.push(t);
        }
    }
    match found.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(err(format!(
            "{pkg}: expected one staged tree in {}, found {}",
            stagedir.display(),
            found.len()
        ))),
    }
}
