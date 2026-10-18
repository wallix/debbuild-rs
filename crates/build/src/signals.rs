//! Signal handling of a stage run: on SIGINT, SIGTERM or SIGHUP, the
//! running child gets the signal, and the stage run cleans up (`debian/rules clean` runs
//! to completion) before it dies of it.
//!
//! The signals are blocked in the main thread (children start with an empty mask:
//! std resets it) and a thread takes them with sigwait, so no handler is needed.

use std::io;
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicI32, Ordering};

use nix::sys::signal::{SigSet, Signal, kill, raise};
use nix::unistd::Pid;

/// The pid of the running child, 0 when there is none.
static CHILD: AtomicI32 = AtomicI32::new(0);
/// The first signal caught, 0 before.
static CAUGHT: AtomicI32 = AtomicI32::new(0);

fn set() -> SigSet {
    let mut set = SigSet::empty();
    for s in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP] {
        set.add(s);
    }
    set
}

/// Catch the signals from now on. Call it before any other thread starts.
///
/// # Errors
/// The signal mask cannot be set or the thread cannot start.
pub fn install() -> io::Result<()> {
    let set = set();
    set.thread_block().map_err(io::Error::from)?;
    std::thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            while let Ok(sig) = set.wait() {
                let _ = CAUGHT.compare_exchange(0, sig as i32, Ordering::SeqCst, Ordering::SeqCst);
                let pid = CHILD.load(Ordering::SeqCst);
                if pid > 0 {
                    // The child may have exited already: nothing to do then.
                    let _ = kill(Pid::from_raw(pid), sig);
                }
            }
        })?;
    Ok(())
}

/// The signal caught, if any.
pub fn caught() -> Option<Signal> {
    Signal::try_from(CAUGHT.load(Ordering::SeqCst)).ok()
}

/// Spawn `cmd` and wait for it; a caught signal is passed on to it.
///
/// # Errors
/// The child cannot be spawned or waited for.
pub fn run(cmd: &mut Command) -> io::Result<ExitStatus> {
    spawn_wait(cmd, true)
}

/// Spawn the cleanup `cmd` and wait for it: the signal that ended the run is not passed
/// on to it, the ones received while it runs are.
///
/// # Errors
/// The child cannot be spawned or waited for.
pub fn run_cleanup(cmd: &mut Command) -> io::Result<ExitStatus> {
    spawn_wait(cmd, false)
}

fn spawn_wait(cmd: &mut Command, replay: bool) -> io::Result<ExitStatus> {
    let mut child = cmd.spawn()?;
    CHILD.store(i32::try_from(child.id()).unwrap_or(0), Ordering::SeqCst);
    if replay && let Some(sig) = caught() {
        // Caught before the pid was recorded.
        let _ = kill(Pid::from_raw(i32::try_from(child.id()).unwrap_or(0)), sig);
    }
    let status = child.wait();
    CHILD.store(0, Ordering::SeqCst);
    status
}

/// Die of the caught signal, as a shell does after its EXIT trap.
pub fn die_of(sig: Signal) {
    let _ = raise(sig);
    let _ = set().thread_unblock();
}
