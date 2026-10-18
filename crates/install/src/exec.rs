//! How maintainer scripts run: chrooted into the target root.

use std::path::Path;
use std::process::Command;

/// Builds the command running a maintainer script.
pub trait Exec {
    /// The command running `inside` (the script's path in the root) with `args`; the
    /// caller sets the environment and the working directory.
    fn command(&self, root: &Path, inside: &str, args: &[String]) -> Command;
}

/// `chroot ROOT SCRIPT ARGS...`, or the script itself when the root is `/`.
pub struct Chroot;

impl Exec for Chroot {
    fn command(&self, root: &Path, inside: &str, args: &[String]) -> Command {
        if root == Path::new("/") {
            let mut c = Command::new(inside);
            c.args(args);
            c
        } else {
            // chroot(8) changes to the new root's / itself.
            let mut c = Command::new("chroot");
            c.arg(root).arg(inside).args(args);
            c
        }
    }
}
