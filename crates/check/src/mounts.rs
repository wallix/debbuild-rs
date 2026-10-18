//! Throwaway overlays of a root directory, as check-against-dpkg.sh mounted them.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::util::{Context, Result, cmd, err, mkdirs, output, run, text};

/// The mounts made, unmounted (lazily, in reverse order) when dropped; the work
/// directory is removed then, unless something is still mounted under it.
pub struct Work {
    pub dir: PathBuf,
    mounts: Vec<PathBuf>,
}

impl Work {
    /// A new work directory: `WORKDIR/debbuild-rs-check.XXXXXX`, or under /var/tmp.
    ///
    /// # Errors
    /// It cannot be created, or is on overlayfs (which cannot be an upper layer).
    pub fn new(workdir: Option<&Path>) -> Result<Self> {
        let parent = match workdir {
            Some(w) => {
                mkdirs(w)?;
                fs::canonicalize(w).ctx(w.display())?
            }
            None => PathBuf::from("/var/tmp"),
        };
        let dir = tempfile::Builder::new()
            .prefix("debbuild-rs-check.")
            .rand_bytes(6)
            .tempdir_in(&parent)
            .ctx(parent.display())?
            .keep();
        let work = Self {
            dir,
            mounts: Vec::new(),
        };
        let fs_type = nix::sys::statfs::statfs(&work.dir).ctx(work.dir.display())?;
        if fs_type.filesystem_type() == nix::sys::statfs::OVERLAYFS_SUPER_MAGIC {
            return Err(err(format!(
                "{} is on overlayfs, which cannot be an overlay upper layer: use -w",
                work.dir.display()
            )));
        }
        Ok(work)
    }

    /// An overlay of `root` in `WORK/<name>/merged`, with /proc, /sys and /dev bound
    /// and a new tmpfs on /tmp; returns the merged directory.
    ///
    /// # Errors
    /// A mount fails.
    pub fn overlay(&mut self, root: &Path, name: &str) -> Result<PathBuf> {
        let d = self.dir.join(name);
        for sub in ["upper", "work", "merged"] {
            mkdirs(&d.join(sub))?;
        }
        let merged = d.join("merged");
        run(Command::new("mount")
            .args(["-t", "overlay", "overlay", "-o"])
            .arg(format!(
                "lowerdir={},upperdir={},workdir={}",
                root.display(),
                d.join("upper").display(),
                d.join("work").display()
            ))
            .arg(&merged))?;
        self.mounts.push(merged.clone());
        for fs in ["proc", "sys", "dev"] {
            let target = merged.join(fs);
            run(Command::new("mount")
                .arg("--rbind")
                .arg(Path::new("/").join(fs))
                .arg(&target))?;
            self.mounts.push(target);
        }
        let tmp = merged.join("tmp");
        run(Command::new("mount")
            .args(["-t", "tmpfs", "tmpfs"])
            .arg(&tmp))?;
        self.mounts.push(tmp);
        Ok(merged)
    }

    /// The upper directory of an overlay.
    #[must_use]
    pub fn upper(&self, name: &str) -> PathBuf {
        self.dir.join(name).join("upper")
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        for m in self.mounts.iter().rev() {
            // Lazy: whatever still uses it does not keep the others mounted.
            let _ = Command::new("umount").arg("-l").arg(m).status();
        }
        let mounted = output(&mut cmd("findmnt", ["-rn", "-o", "TARGET"])).map_or(true, |o| {
            let prefix = format!("{}/", self.dir.display());
            text(&o).lines().any(|l| l.starts_with(&prefix))
        });
        if mounted {
            eprintln!(
                "debbuild-rs check: filesystems still mounted under {}, not removing it",
                self.dir.display()
            );
        } else {
            let _ = Command::new("rm")
                .arg("-rf")
                .arg("--one-file-system")
                .arg(&self.dir)
                .status();
        }
    }
}

/// The filesystems mounted below `root`, other than /proc, /sys, /dev and /tmp and the
/// work directory: they are not part of the overlays.
///
/// # Errors
/// findmnt fails.
pub fn submounts(root: &Path, work: &Path) -> Result<Vec<String>> {
    let root = root.to_string_lossy();
    let root = root.trim_end_matches('/');
    let out = output(&mut cmd("findmnt", ["-rn", "-o", "TARGET"]))?;
    let work = work.to_string_lossy().into_owned();
    Ok(text(&out)
        .lines()
        .filter(|l| {
            l.strip_prefix(&format!("{root}/")).is_some_and(|rest| {
                !rest.is_empty()
                    && !["proc", "sys", "dev", "tmp"]
                        .iter()
                        .any(|s| rest == *s || rest.starts_with(&format!("{s}/")))
            }) && !l.starts_with(&work)
        })
        .map(str::to_owned)
        .collect())
}

/// A policy-rc.d forbidding service starts in `merged`.
///
/// # Errors
/// It cannot be written.
pub fn policy_rc_d(merged: &Path) -> Result<()> {
    let p = merged.join("usr/sbin/policy-rc.d");
    fs::write(&p, "#!/bin/sh\nexit 101\n").ctx(p.display())?;
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).ctx(p.display())
}
