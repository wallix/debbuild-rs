//! `debbuild-rs builddeb`: `dh_builddeb`, staging variant.
//!
//! `debbuild-rs stage` puts it first in PATH as `dh_builddeb`. Every debian/rules ends its
//! binary target with `dh_builddeb` (from an override or from the dh sequence), so this
//! is the one point where the fully assembled package tree exists: files installed,
//! scripts and debhelper snippets merged, permissions fixed, DEBIAN/control generated.
//!
//! Instead of a .deb, it records each package as a staged tree under
//! `$DEBBUILD_RS_STAGE_DIR`:
//!   <pkg>/DEBIAN/          control files, as dpkg-deb would put them in control.tar
//!   <pkg>/data.tar         the file tree, as dpkg-deb would put it in data.tar
//!   <pkg>/data.tar.sha256  sha256 of data.tar (hex), so that the installer need not
//!                          hash the whole tarball to tell whether the package changed
//!   <pkg>/dpkg-deb.options the dpkg-deb options given after `--`, one per line, for
//!                          `debbuild-rs pack`; absent without any
//!   <pkg>/staged.info      a deb822 stanza: `Format: 1` and `Epoch:`, the
//!                          `SOURCE_DATE_EPOCH` the tree was staged with, which
//!                          `debbuild-rs pack` takes as the epoch of the .deb
//!
//! The tarball stays uncompressed: the task cache stores content-defined chunks, which
//! deduplicate across versions of a package only as long as unchanged files stay
//! unchanged bytes.
//!
//! data.tar lists the tree as dpkg-deb does: each directory's entries sorted by name,
//! the symlinks last, so that a .deb packed from it has the same layout.
//!
//! This runs inside the fakeroot session of `debian/rules binary`, and data.tar is
//! written by GNU tar, a child in the same session, so the ownership the rules set
//! (`dh_fixperms`, explicit chown) is what tar records. Modification times newer than
//! `SOURCE_DATE_EPOCH`, which must be set, are clamped to it, as dpkg-deb does. The
//! -dbgsym package `dh_strip` prepares for a package is staged too, under its own name
//! and owned by root, as `dh_builddeb` builds it with `--root-owner-group`. -P,
//! --destdir and --filename are not supported.
//! Each tree is first checked as dpkg-deb --build checks it (control file, maintainer
//! script modes, conffiles present in the tree): what dpkg-deb refuses is not staged.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use debbuild_rs_common::validate;
use sha2::{Digest, Sha256};

use crate::fsutil::{copy_tree, remove_all};
use crate::{Error, Result, run};

/// The real `dh_builddeb`, by absolute path: PATH leads back to this binary.
const DH_BUILDDEB: &str = "/usr/bin/dh_builddeb";

fn err(msg: impl std::fmt::Display) -> Error {
    Error::msg(format!("dh_builddeb (debbuild-rs): {msg}"))
}

fn io_err(path: &Path, e: &io::Error) -> Error {
    err(format_args!("{}: {e}", path.display()))
}

/// The hex sha256 of a file.
///
/// # Errors
/// The file cannot be read.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(buf.get(..n).unwrap_or_default());
    }
    Ok(h.finalize()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write as _;
            // Writing to a String cannot fail.
            let _ = write!(s, "{b:02x}");
            s
        }))
}

/// The paths of `tree` but DEBIAN/ in dpkg-deb's data.tar order, NUL-terminated: `.`,
/// then a depth-first walk with each directory's entries sorted by name, the symlinks
/// moved to the end.
fn data_list(tree: &Path) -> io::Result<Vec<u8>> {
    fn walk(dir: &Path, rel: &[u8], files: &mut Vec<u8>, links: &mut Vec<u8>) -> io::Result<()> {
        let mut entries = fs::read_dir(dir)?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<io::Result<Vec<_>>>()?;
        entries.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for name in entries {
            if rel == b"." && name == "DEBIAN" {
                continue;
            }
            let mut path = rel.to_vec();
            path.push(b'/');
            path.extend_from_slice(name.as_bytes());
            let full = dir.join(&name);
            let ft = fs::symlink_metadata(&full)?.file_type();
            if ft.is_symlink() {
                links.extend_from_slice(&path);
                links.push(0);
            } else {
                files.extend_from_slice(&path);
                files.push(0);
                if ft.is_dir() {
                    walk(&full, &path, files, links)?;
                }
            }
        }
        Ok(())
    }
    let mut files = b".\0".to_vec();
    let mut links = Vec::new();
    walk(tree, b".", &mut files, &mut links)?;
    files.extend_from_slice(&links);
    Ok(files)
}

/// The value of the first `Package:` field of control data.
fn package_name(control: &[u8]) -> Option<&[u8]> {
    control
        .split(|&c| c == b'\n')
        .find_map(|l| l.strip_prefix(b"Package:".as_slice()))
        .map(<[u8]>::trim_ascii)
        .filter(|v| !v.is_empty())
}

/// Check package tree `tree` as dpkg-deb --build does, looking its conffiles up with
/// `lstat` under the tree as dpkg-deb does.
fn check_tree(tree: &Path) -> Result<()> {
    validate::package(tree, |name| {
        let mut path = tree.as_os_str().to_owned();
        path.push("/");
        path.push(OsStr::from_bytes(name));
        match fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    })
    .map(drop)
    .map_err(err)
}

/// The format of staged.info this version writes.
const INFO_FORMAT: u32 = 1;

/// `SOURCE_DATE_EPOCH`: set, and a number of seconds.
fn source_date_epoch() -> Result<u64> {
    let Some(e) = std::env::var_os("SOURCE_DATE_EPOCH") else {
        return Err(err("SOURCE_DATE_EPOCH is not set"));
    };
    e.to_str()
        .filter(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            err(format_args!(
                "invalid SOURCE_DATE_EPOCH '{}'",
                e.to_string_lossy()
            ))
        })
}

/// Stage package tree `tree` as `stagedir/name`: DEBIAN/, data.tar (mtimes clamped to
/// `epoch`, owned by root with `root_owner`), data.tar.sha256, dpkg-deb.options and
/// staged.info.
fn stage_tree(
    tree: &Path,
    name: &OsStr,
    stagedir: &OsStr,
    epoch: u64,
    dpkg_deb_opts: &[u8],
    root_owner: bool,
) -> Result<()> {
    // DEBBUILD_RS_STAGE_DIR is private to the stage run, which publishes it whole.
    let mut outdir = PathBuf::from(stagedir);
    outdir.push(name);
    remove_all(&outdir).map_err(|e| io_err(&outdir, &e))?;
    fs::create_dir_all(&outdir).map_err(|e| io_err(&outdir, &e))?;
    let debian = tree.join("DEBIAN");
    copy_tree(&debian, &outdir.join("DEBIAN")).map_err(|e| io_err(&debian, &e))?;
    let data = outdir.join("data.tar");
    let mut list = tempfile::NamedTempFile::new().map_err(err)?;
    list.write_all(&data_list(tree).map_err(|e| io_err(tree, &e))?)
        .map_err(|e| io_err(list.path(), &e))?;
    let owner: &[&str] = if root_owner {
        &["--owner=root:0", "--group=root:0"]
    } else {
        &[]
    };
    run(
        Command::new("tar")
            .arg("-C")
            .arg(tree)
            .args(["--null", "--no-unquote", "--no-recursion", "-T"])
            .arg(list.path())
            .arg(format!("--mtime=@{epoch}"))
            .arg("--clamp-mtime")
            .args(owner)
            .args(["--format=gnu", "-cf"])
            .arg(&data),
        "tar",
    )?;
    let mut sum = sha256_file(&data).map_err(|e| io_err(&data, &e))?;
    sum.push('\n');
    let sum_path = outdir.join("data.tar.sha256");
    fs::write(&sum_path, sum).map_err(|e| io_err(&sum_path, &e))?;
    if !dpkg_deb_opts.is_empty() {
        let opts_path = outdir.join("dpkg-deb.options");
        fs::write(&opts_path, dpkg_deb_opts).map_err(|e| io_err(&opts_path, &e))?;
    }
    let info_path = outdir.join("staged.info");
    fs::write(
        &info_path,
        format!("Format: {INFO_FORMAT}\nEpoch: {epoch}\n"),
    )
    .map_err(|e| io_err(&info_path, &e))?;
    let mut line = b"dh_builddeb (debbuild-rs): staged ".to_vec();
    line.extend_from_slice(name.as_bytes());
    line.extend_from_slice(b" in ");
    line.extend_from_slice(outdir.as_os_str().as_bytes());
    line.push(b'\n');
    io::stdout().write_all(&line).map_err(err)
}

/// Stage the packages `dh_listpackages` selects from `args` (the arguments after
/// `--` are dpkg-deb's: recorded), or run the real `dh_builddeb` outside a stage run.
///
/// # Errors
/// A package without DEBIAN/control or that dpkg-deb --build would refuse, a dpkg-deb
/// option holding a newline, an unset or invalid `SOURCE_DATE_EPOCH`, or a failed step.
pub fn builddeb(args: &[OsString]) -> Result<()> {
    let Some(stagedir) = std::env::var_os("DEBBUILD_RS_STAGE_DIR").filter(|d| !d.is_empty()) else {
        let e = Command::new(DH_BUILDDEB).args(args).exec();
        return Err(err(format_args!("{DH_BUILDDEB}: {e}")));
    };
    let dh_opts: Vec<&OsString> = args.iter().take_while(|a| *a != "--").collect();
    let mut dpkg_deb_opts = Vec::new();
    for a in args.iter().skip_while(|a| *a != "--").skip(1) {
        if a.as_bytes().contains(&b'\n') {
            return Err(err(format_args!(
                "dpkg-deb option {} holds a newline",
                a.to_string_lossy()
            )));
        }
        dpkg_deb_opts.extend_from_slice(a.as_bytes());
        dpkg_deb_opts.push(b'\n');
    }
    let epoch = source_date_epoch()?;

    let out = Command::new("dh_listpackages")
        .args(&dh_opts)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| err(format_args!("dh_listpackages: {e}")))?;
    if !out.status.success() {
        return Err(Error::Exit(crate::shell_status(out.status)));
    }
    // The shell's word splitting of $(dh_listpackages).
    let pkgs = out
        .stdout
        .split(|c| matches!(c, b' ' | b'\t' | b'\n'))
        .filter(|w| !w.is_empty());
    for pkg in pkgs {
        let pkg = OsStr::from_bytes(pkg);
        let tree = Path::new("debian").join(pkg);
        let debian = tree.join("DEBIAN");
        if !debian.join("control").is_file() {
            return Err(err(format_args!(
                "{}/DEBIAN/control missing, dh_gencontrol did not run",
                tree.display()
            )));
        }
        check_tree(&tree)?;
        stage_tree(&tree, pkg, &stagedir, epoch, &dpkg_deb_opts, false)?;
        // dh_builddeb builds the dbgsym package only with a control file.
        let dbgsym = Path::new("debian/.debhelper").join(pkg).join("dbgsym-root");
        let control = dbgsym.join("DEBIAN/control");
        if control.is_file() {
            let text = fs::read(&control).map_err(|e| io_err(&control, &e))?;
            let name = package_name(&text)
                .ok_or_else(|| err(format_args!("{}: no Package field", control.display())))?;
            check_tree(&dbgsym)?;
            stage_tree(
                &dbgsym,
                OsStr::from_bytes(name),
                &stagedir,
                epoch,
                &dpkg_deb_opts,
                true,
            )?;
        } else if dbgsym.is_dir() {
            eprintln!(
                "dh_builddeb (debbuild-rs): warning: not staging the dbgsym package of {}: no control file",
                pkg.to_string_lossy()
            );
        }
    }
    Ok(())
}
