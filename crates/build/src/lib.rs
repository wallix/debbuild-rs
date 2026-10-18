//! The build side of debbuild-rs: `debbuild-rs stage` runs a package's debian/rules into
//! staged package trees, and `debbuild-rs builddeb` is the `dh_builddeb` the rules call.
//!
//! Everything here shapes the staged trees, so a build cache keyed on the tool should
//! cover this crate; it depends on no other debbuild-rs crate.

pub mod builddeb;
mod fsutil;
mod rfc2822;
mod signals;
pub mod stage;

use std::fmt;

/// A failure of `stage` or `builddeb`.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// A message for stderr, printed as is.
    Message(String),
    /// A child process failed and said why: exit with its status, as `set -e` does.
    Exit(u8),
}

impl Error {
    pub fn msg(s: impl Into<String>) -> Self {
        Self::Message(s.into())
    }

    /// The exit status of the process.
    #[must_use]
    pub fn status(&self) -> u8 {
        match self {
            Error::Message(_) => 1,
            Error::Exit(n) => *n,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Message(m) => f.write_str(m),
            Error::Exit(n) => write!(f, "exit status {n}"),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The shell's exit status for a finished child: its code, or 128 + the signal.
fn shell_status(status: std::process::ExitStatus) -> u8 {
    use std::os::unix::process::ExitStatusExt;
    let n = status
        .code()
        .or_else(|| status.signal().map(|s| s.saturating_add(128)))
        .unwrap_or(1);
    u8::try_from(n & 0xff).unwrap_or(1)
}

/// Run `cmd` to completion; a failure is [`Error::Exit`] with the shell's status.
fn run(cmd: &mut std::process::Command, what: &str) -> Result<()> {
    let status = signals::run(cmd).map_err(|e| Error::msg(format!("{what}: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Exit(shell_status(status)))
    }
}

/// Catch SIGINT, SIGTERM and SIGHUP from now on, to clean up before dying of them (see
/// `stage`). Call it before any other thread starts.
///
/// # Errors
/// The signal mask cannot be set.
pub fn signals_install() -> std::io::Result<()> {
    signals::install()
}

/// Die of the signal caught by [`signals_install`]'s thread, if any.
pub fn die_of_caught_signal() {
    if let Some(sig) = signals::caught() {
        signals::die_of(sig);
    }
}
