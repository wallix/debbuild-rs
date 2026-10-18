//! `debbuild-rs check`: check that `debbuild-rs install` leaves a root exactly as dpkg does.
//!
//! Two throwaway overlays of ROOT receive the same staged packages: one from .deb files
//! packed from the staged trees and installed by `dpkg -i`, the other from `debbuild-rs
//! install`. Then every path either installation touched (type, mode, owner, content or
//! link target) and the dpkg database entries are compared.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use debbuild_rs_common::staged_lock;

use crate::manifest::{ck_line, touched};
use crate::mounts::{Work, policy_rc_d, submounts};
use crate::util::{Context, Result, cp_a, err, mkdirs, output, run, staged_tree, text};

pub const ABOUT: &str = "Check that `debbuild-rs install` leaves a root exactly as dpkg does.

Two throwaway overlays of ROOT (default /) receive the same staged packages: one from
.deb files packed from the staged trees and installed by `dpkg -i`, the other from
`debbuild-rs install`. The check then compares every path either installation touched
(type, mode, owner, content or link target) and the dpkg database entries, and exits
non-zero on any difference.

With -u, both sides then upgrade to a copy of the staged packages with a higher version
(<version>+u1) and a line appended to each conffile, and the comparison covers both
rounds.

With --vs-oracle INSTALLER, a third overlay is installed by that other installer
(for instance another version of debbuild-rs install), through scenarios run round by round;
see the scenario list (--scenario help).

Dependencies outside the staged set must be installed in ROOT; the staged packages the
requested ones depend on are installed along with them.

The overlays live in WORKDIR (default: a new directory under /var/tmp), which must be on
a filesystem overlayfs accepts as upper layer (not overlayfs itself). Filesystems mounted
under ROOT are not part of the overlays: they show up as empty directories, except for
/proc, /sys, /dev (bind-mounted) and /tmp (a new tmpfs).

Must run as root.";

pub struct Options {
    pub root: PathBuf,
    pub stagedir: PathBuf,
    pub workdir: Option<PathBuf>,
    pub upgrade: bool,
    pub packages: Vec<String>,
}

/// This binary, to run `debbuild-rs install`.
///
/// # Errors
/// It cannot be found.
pub fn self_exe() -> Result<PathBuf> {
    std::env::current_exe().ctx("this binary")
}

/// The packages `debbuild-rs install` plans for `requested` (`--dry-run` against `root`),
/// whatever it would do with them: the first word of each line of the plan.
///
/// # Errors
/// The planning fails or plans nothing.
pub fn planned(root: &Path, stagedir: &Path, requested: &[String]) -> Result<Vec<String>> {
    let out = output(
        Command::new(self_exe()?)
            .arg("install")
            .arg("--root")
            .arg(root)
            .arg("--stage")
            .arg(stagedir)
            .arg("--dry-run")
            .args(requested),
    )?;
    let pkgs: Vec<String> = text(&out)
        .lines()
        .filter_map(|l| l.split(' ').next())
        .map(str::to_owned)
        .collect();
    if pkgs.is_empty() {
        return Err(err("debbuild-rs install planned no package"));
    }
    Ok(pkgs)
}

/// The staged packages with a higher version (`+u1`) and `# upgraded` appended to each
/// regular conffile, in `out` (the same layout).
///
/// # Errors
/// A copy fails.
pub fn upgraded_copy(work: &Path, stagedir: &Path, out: &Path, pkgs: &[String]) -> Result<()> {
    // The exact-version relations between the packages follow them: `p (= 1)` -> `p (= 1+u1)`.
    let mut exact = Vec::new();
    for pkg in pkgs {
        let control = staged_tree(stagedir, pkg)?.join("DEBIAN/control");
        let c = fs::read(&control).ctx(control.display())?;
        if let Some(v) = text(&c).lines().find_map(|l| l.strip_prefix("Version: ")) {
            exact.push((format!("{pkg} (= {v})"), format!("{pkg} (= {v}+u1)")));
        }
    }
    for pkg in pkgs {
        let tree = staged_tree(stagedir, pkg)?;
        let dir = tree.parent().and_then(Path::file_name).unwrap_or_default();
        let o = out.join(dir).join(pkg);
        let t = work.join("tree-u").join(pkg);
        mkdirs(&o)?;
        mkdirs(&t)?;
        cp_a(&tree.join("DEBIAN"), &o.join("DEBIAN"))?;
        let control = o.join("DEBIAN/control");
        let c = fs::read(&control).ctx(control.display())?;
        let c: String = text(&c)
            .split_inclusive('\n')
            .map(|l| match l.strip_prefix("Version: ") {
                Some(_) => {
                    let (body, nl) = l.strip_suffix('\n').map_or((l, ""), |b| (b, "\n"));
                    format!("{body}+u1{nl}")
                }
                None => l.to_owned(),
            })
            .collect::<String>();
        let c = exact
            .iter()
            .fold(c, |c, (old, new)| c.replace(old.as_str(), new));
        fs::write(&control, c).ctx(control.display())?;
        run(Command::new("tar")
            .arg("-xpf")
            .arg(tree.join("data.tar"))
            .arg("-C")
            .arg(&t))?;
        let conffiles = o.join("DEBIAN/conffiles");
        if conffiles.is_file() {
            for line in text(&fs::read(&conffiles).ctx(conffiles.display())?).lines() {
                if line.starts_with("remove-on-upgrade") {
                    continue;
                }
                let p = t.join(line.trim().trim_start_matches('/'));
                if p.is_file() && !p.is_symlink() {
                    let mut d = fs::read(&p).ctx(p.display())?;
                    d.extend_from_slice(b"# upgraded\n");
                    fs::write(&p, d).ctx(p.display())?;
                }
            }
        }
        run(Command::new("tar")
            .arg("-C")
            .arg(&t)
            .args(["--sort=name", "--format=gnu", "-cf"])
            .arg(o.join("data.tar"))
            .arg("."))?;
    }
    Ok(())
}

/// Pack each staged tree of `pkgs` into `debs/<pkg>.deb` (extracted with its recorded
/// ownership, then dpkg-deb, as root).
///
/// # Errors
/// A step fails.
pub fn build_debs(work: &Path, stagedir: &Path, debs: &Path, pkgs: &[String]) -> Result<()> {
    mkdirs(debs)?;
    for pkg in pkgs {
        let tree = staged_tree(stagedir, pkg)?;
        let t = work.join("tree");
        let _ = fs::remove_dir_all(&t);
        mkdirs(&t)?;
        run(Command::new("tar")
            .arg("-xpf")
            .arg(tree.join("data.tar"))
            .arg("-C")
            .arg(&t))?;
        cp_a(&tree.join("DEBIAN"), &t.join("DEBIAN"))?;
        output(
            Command::new("dpkg-deb")
                .args(["--build", "-Zzstd", "-z1"])
                .arg(&t)
                .arg(debs.join(format!("{pkg}.deb"))),
        )?;
    }
    Ok(())
}

/// `diff -u A B` of two texts; returns whether they are equal.
///
/// # Errors
/// The files cannot be written or diff fails to run.
pub fn diff(dir: &Path, name: &str, a: &str, b: &str, labels: (&str, &str)) -> Result<bool> {
    let pa = dir.join(format!("{name}.{}", labels.0));
    let pb = dir.join(format!("{name}.{}", labels.1));
    fs::write(&pa, a).ctx(pa.display())?;
    fs::write(&pb, b).ctx(pb.display())?;
    let st = Command::new("diff")
        .arg("-u")
        .arg(&pa)
        .arg(&pb)
        .status()
        .ctx("diff")?;
    Ok(st.success())
}

/// `dpkg-query -s` of each package, in `merged`'s database.
///
/// # Errors
/// dpkg-query cannot run.
pub fn dpkg_query(merged: &Path, pkgs: &[String]) -> Result<String> {
    let mut out = String::new();
    for p in pkgs {
        let o = Command::new("dpkg-query")
            .arg(format!(
                "--admindir={}",
                merged.join("var/lib/dpkg").display()
            ))
            .args(["-s", p])
            .output()
            .ctx("dpkg-query")?;
        out.push_str(&text(&o.stdout));
    }
    Ok(out)
}

/// Run the check; whether both sides agree.
///
/// # Errors
/// A step of the check fails.
pub fn check(opts: &Options) -> Result<bool> {
    if !nix::unistd::geteuid().is_root() {
        return Err(err("must run as root"));
    }
    let root = fs::canonicalize(&opts.root).ctx(opts.root.display())?;
    // Both sides from one generation of each staged output.
    let _lock = staged_lock::read_output(&opts.stagedir).ctx(opts.stagedir.display())?;
    let mut work = Work::new(opts.workdir.as_deref())?;
    let w = work.dir.clone();
    let sub = submounts(&root, &w)?;
    if !sub.is_empty() {
        eprintln!(
            "warning: not part of the overlays (empty there): {}",
            sub.join(" ")
        );
    }
    let dpkg = work.overlay(&root, "dpkg")?;
    let stage = work.overlay(&root, "stage")?;
    // the same set of packages for both: the requested ones and their staged dependencies
    let pkgs = planned(&stage, &opts.stagedir, &opts.packages)?;
    println!("packages: {}", pkgs.join(" "));
    policy_rc_d(&dpkg)?;
    policy_rc_d(&stage)?;

    let round = |n: u32, dir: &Path| -> Result<()> {
        let debs = dpkg.join(format!("tmp/debs-{n}"));
        build_debs(&w, dir, &debs, &pkgs)?;
        println!("--- round {n}: dpkg -i");
        run(Command::new("chroot")
            .arg(&dpkg)
            .args(["sh", "-c", &format!("dpkg -i /tmp/debs-{n}/*.deb")])
            .env("DEBIAN_FRONTEND", "noninteractive"))?;
        println!("--- round {n}: debbuild-rs install");
        run(Command::new(self_exe()?)
            .arg("install")
            .arg("--root")
            .arg(&stage)
            .arg("--stage")
            .arg(dir)
            .args(&pkgs)
            .env("DEBIAN_FRONTEND", "noninteractive"))
    };
    round(1, &opts.stagedir)?;
    if opts.upgrade {
        let u = w.join("stage-u");
        upgraded_copy(&w, &opts.stagedir, &u, &pkgs)?;
        round(2, &u)?;
    }

    // Paths touched by either side, minus the bookkeeping each tool keeps for itself.
    let paths = touched(&[&work.upper("dpkg"), &work.upper("stage")], &[])?;
    let manifest =
        |merged: &Path| -> String { paths.iter().map(|p| ck_line(merged, p) + "\n").collect() };
    println!("--- files ({} paths)", paths.len());
    let mut ok = diff(
        &w,
        "manifest",
        &manifest(&dpkg),
        &manifest(&stage),
        ("dpkg", "stage"),
    )?;
    println!("--- dpkg database");
    ok &= diff(
        &w,
        "status",
        &dpkg_query(&dpkg, &pkgs)?,
        &dpkg_query(&stage, &pkgs)?,
        ("dpkg", "stage"),
    )?;
    let without_status = |merged: &Path| -> Result<String> {
        let p = merged.join("var/lib/dpkg/status");
        Ok(text(&fs::read(&p).ctx(p.display())?)
            .split_inclusive('\n')
            .filter(|l| !l.starts_with("Status:"))
            .collect())
    };
    ok &= diff(
        &w,
        "status-file",
        &without_status(&dpkg)?,
        &without_status(&stage)?,
        ("dpkg", "stage"),
    )?;
    if ok {
        println!(
            "OK: debbuild-rs install and dpkg agree on {}",
            pkgs.join(" ")
        );
    }
    drop(work);
    Ok(ok)
}
