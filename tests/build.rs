//! `debbuild-rs stage` and `debbuild-rs builddeb` (as `dh_builddeb`), through the binary.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use debbuild_rs_build::stage::{Entry, Options, stage};
use debbuild_rs_build::{Error, builddeb::sha256_file};

const EXE: &str = env!("CARGO_BIN_EXE_debbuild-rs");
const EPOCH: i64 = 1_767_225_600;

/// Skip a test whose tools are missing: a failure under `DEBBUILD_RS_TEST_REQUIRE_TOOLS`.
fn skip(what: &str) {
    assert!(
        std::env::var_os("DEBBUILD_RS_TEST_REQUIRE_TOOLS").is_none(),
        "no {what}"
    );
    eprintln!("skipped: no {what}");
}

fn have(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {cmd}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn write(path: &Path, content: &str, mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// A package tree as `dh_gencontrol` leaves it, and a bin directory with `dh_builddeb`
/// (this binary) and a stub `dh_listpackages` printing `pkgs`.
fn fake_rules_dir(tmp: &Path, pkgs: &str) -> (PathBuf, PathBuf) {
    let src = tmp.join("src");
    let tree = src.join("debian/p");
    write(
        &tree.join("DEBIAN/control"),
        "Package: p\nVersion: 1\nArchitecture: all\n",
        0o644,
    );
    write(&tree.join("DEBIAN/postinst"), "#!/bin/sh\n", 0o755);
    write(&tree.join("usr/share/p/a"), "a", 0o644);
    write(&tree.join("usr/bin/b"), "b", 0o755);
    symlink("../share/p/a", tree.join("usr/bin/l")).unwrap();
    // newer than SOURCE_DATE_EPOCH: clamped
    filetime(&tree.join("usr/share/p/a"), EPOCH + 1000);
    filetime(&tree.join("DEBIAN/control"), 1_000_000_000);
    let bin = tmp.join("bin");
    fs::create_dir(&bin).unwrap();
    symlink(EXE, bin.join("dh_builddeb")).unwrap();
    write(
        &bin.join("dh_listpackages"),
        &format!("#!/bin/sh\necho \"$*\" >\"$0.args\"\necho '{pkgs}'\n"),
        0o755,
    );
    (src, bin)
}

fn filetime(path: &Path, epoch: i64) {
    let st = Command::new("touch")
        .arg("-h")
        .arg("-d")
        .arg(format!("@{epoch}"))
        .arg(path)
        .status()
        .unwrap();
    assert!(st.success());
}

fn run_builddeb(src: &Path, bin: &Path, out: &Path, args: &[&str], fakeroot: bool) -> Output {
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let mut cmd = if fakeroot {
        let mut c = Command::new("fakeroot");
        c.arg("dh_builddeb");
        c
    } else {
        Command::new(bin.join("dh_builddeb"))
    };
    cmd.args(args)
        .current_dir(src)
        .env("PATH", path)
        .env("DEBBUILD_RS_STAGE_DIR", out)
        .env("SOURCE_DATE_EPOCH", EPOCH.to_string())
        .output()
        .unwrap()
}

#[test]
fn builddeb() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, bin) = fake_rules_dir(tmp.path(), "p");
    let out = tmp.path().join("out");
    let fakeroot = have("fakeroot");
    let o = run_builddeb(&src, &bin, &out, &["-pp", "--", "-Zzstd", "-z19"], fakeroot);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        String::from_utf8(o.stdout).unwrap(),
        format!(
            "dh_builddeb (debbuild-rs): staged p in {}/p\n",
            out.display()
        )
    );
    // the options before -- select the packages
    assert_eq!(
        fs::read_to_string(bin.join("dh_listpackages.args")).unwrap(),
        "-pp\n"
    );
    let p = out.join("p");
    assert_eq!(
        fs::read(p.join("DEBIAN/control")).unwrap(),
        b"Package: p\nVersion: 1\nArchitecture: all\n"
    );
    assert_eq!(
        fs::metadata(p.join("DEBIAN/postinst")).unwrap().mode() & 0o7777,
        0o755
    );
    assert_eq!(
        fs::read_to_string(p.join("data.tar.sha256")).unwrap(),
        format!("{}\n", sha256_file(&p.join("data.tar")).unwrap())
    );
    // GNU tar, name order, the root first, the symlinks last, DEBIAN excluded, mtimes
    // clamped
    let listing = Command::new("tar")
        .args(["-tvf"])
        .arg(p.join("data.tar"))
        .args(["--numeric-owner", "--full-time"])
        .env("TZ", "UTC")
        .output()
        .unwrap();
    let listing = String::from_utf8(listing.stdout).unwrap();
    let names: Vec<&str> = listing
        .lines()
        .map(|l| l.rsplit_once(' ').unwrap().1)
        .collect();
    assert_eq!(names[0], "./");
    assert!(!listing.contains("DEBIAN"), "{listing}");
    let files: Vec<&str> = listing
        .lines()
        .filter_map(|l| l.split_whitespace().nth(5))
        .collect();
    assert_eq!(
        files,
        [
            "./",
            "./usr/",
            "./usr/bin/",
            "./usr/bin/b",
            "./usr/share/",
            "./usr/share/p/",
            "./usr/share/p/a",
            "./usr/bin/l"
        ]
    );
    assert!(
        listing.contains("2026-01-01 00:00:00 ./usr/share/p/a"),
        "{listing}"
    );
    if fakeroot {
        assert!(listing.lines().all(|l| l.contains(" 0/0 ")), "{listing}");
    }
    let mut header = [0u8; 512];
    header.copy_from_slice(&fs::read(p.join("data.tar")).unwrap()[..512]);
    assert_eq!(&header[257..265], b"ustar  \0", "GNU format");
    assert_eq!(fs::metadata(p.join("data.tar")).unwrap().len() % 10240, 0);
    // the options after -- are kept for debbuild-rs pack
    assert_eq!(
        fs::read_to_string(p.join("dpkg-deb.options")).unwrap(),
        "-Zzstd\n-z19\n"
    );
    // and the epoch the tree was clamped to
    assert_eq!(
        fs::read_to_string(p.join("staged.info")).unwrap(),
        format!("Format: 1\nEpoch: {EPOCH}\n")
    );
}

/// `SOURCE_DATE_EPOCH` is the recorded epoch: unset or invalid, nothing is staged.
#[test]
fn builddeb_needs_epoch() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, bin) = fake_rules_dir(tmp.path(), "p");
    let out = tmp.path().join("out");
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    for (epoch, msg) in [
        (None, "SOURCE_DATE_EPOCH is not set"),
        (Some(""), "invalid SOURCE_DATE_EPOCH ''"),
        (Some("-1"), "invalid SOURCE_DATE_EPOCH '-1'"),
        (Some("+1"), "invalid SOURCE_DATE_EPOCH '+1'"),
        (Some("1.5"), "invalid SOURCE_DATE_EPOCH '1.5'"),
    ] {
        let mut cmd = Command::new(bin.join("dh_builddeb"));
        cmd.current_dir(&src)
            .env("PATH", &path)
            .env("DEBBUILD_RS_STAGE_DIR", &out)
            .env_remove("SOURCE_DATE_EPOCH");
        if let Some(e) = epoch {
            cmd.env("SOURCE_DATE_EPOCH", e);
        }
        let o = cmd.output().unwrap();
        assert_eq!(o.status.code(), Some(1), "{epoch:?}");
        assert_eq!(
            String::from_utf8(o.stderr).unwrap(),
            format!("dh_builddeb (debbuild-rs): {msg}\n")
        );
        assert!(!out.exists());
    }
}

#[test]
fn builddeb_preserves_debian_mtimes() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, bin) = fake_rules_dir(tmp.path(), "p");
    let out = tmp.path().join("out");
    let o = run_builddeb(&src, &bin, &out, &[], false);
    assert!(o.status.success(), "{o:?}");
    let m = fs::metadata(out.join("p/DEBIAN/control")).unwrap();
    assert_eq!(m.mtime(), 1_000_000_000);
    assert!(!out.join("p/dpkg-deb.options").exists());
    let orig = fs::metadata(src.join("debian/p/DEBIAN/postinst")).unwrap();
    let copy = fs::metadata(out.join("p/DEBIAN/postinst")).unwrap();
    assert_eq!(
        (copy.mtime(), copy.mtime_nsec()),
        (orig.mtime(), orig.mtime_nsec())
    );
}

/// The dbgsym package `dh_strip` prepared: staged under its name, owned by root.
#[test]
fn builddeb_dbgsym() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, bin) = fake_rules_dir(tmp.path(), "p");
    let dbgsym = src.join("debian/.debhelper/p/dbgsym-root");
    write(
        &dbgsym.join("DEBIAN/control"),
        "Package: p-dbgsym\nVersion: 1\nArchitecture: all\n",
        0o644,
    );
    write(
        &dbgsym.join("usr/lib/debug/.build-id/ab/cd.debug"),
        "d",
        0o644,
    );
    let out = tmp.path().join("out");
    let o = run_builddeb(&src, &bin, &out, &["--", "-Zzstd"], false);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        String::from_utf8(o.stdout).unwrap(),
        format!(
            "dh_builddeb (debbuild-rs): staged p in {0}/p\n\
             dh_builddeb (debbuild-rs): staged p-dbgsym in {0}/p-dbgsym\n",
            out.display()
        )
    );
    let d = out.join("p-dbgsym");
    assert_eq!(
        fs::read(d.join("DEBIAN/control")).unwrap(),
        b"Package: p-dbgsym\nVersion: 1\nArchitecture: all\n"
    );
    assert_eq!(
        fs::read_to_string(d.join("dpkg-deb.options")).unwrap(),
        "-Zzstd\n"
    );
    assert_eq!(
        fs::read_to_string(d.join("staged.info")).unwrap(),
        format!("Format: 1\nEpoch: {EPOCH}\n")
    );
    let listing = Command::new("tar")
        .args(["-tvf"])
        .arg(d.join("data.tar"))
        .arg("--numeric-owner")
        .output()
        .unwrap();
    let listing = String::from_utf8(listing.stdout).unwrap();
    assert!(
        listing.contains("./usr/lib/debug/.build-id/ab/cd.debug"),
        "{listing}"
    );
    assert!(listing.lines().all(|l| l.contains(" 0/0 ")), "{listing}");

    // without a control file: a warning, as dh_builddeb gives
    fs::remove_file(dbgsym.join("DEBIAN/control")).unwrap();
    let out = tmp.path().join("out2");
    let o = run_builddeb(&src, &bin, &out, &[], false);
    assert!(o.status.success(), "{o:?}");
    assert!(!out.join("p-dbgsym").exists());
    assert_eq!(
        String::from_utf8(o.stderr).unwrap(),
        "dh_builddeb (debbuild-rs): warning: not staging the dbgsym package of p: no control file\n"
    );
}

#[test]
fn builddeb_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, bin) = fake_rules_dir(tmp.path(), "p q");
    let out = tmp.path().join("out");
    let o = run_builddeb(&src, &bin, &out, &[], false);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(o.stderr).unwrap(),
        "dh_builddeb (debbuild-rs): debian/q/DEBIAN/control missing, dh_gencontrol did not run\n"
    );
    // p was staged before
    assert!(out.join("p/data.tar").exists());
}

/// A tree dpkg-deb --build would refuse is not staged.
#[test]
fn builddeb_checks_trees() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, bin) = fake_rules_dir(tmp.path(), "p");
    let tree = src.join("debian/p");
    let refused = |what: &str, why: &str| {
        let out = tmp.path().join("out");
        let o = run_builddeb(&src, &bin, &out, &[], false);
        assert_eq!(o.status.code(), Some(1), "{what}: {o:?}");
        assert_eq!(
            String::from_utf8(o.stderr).unwrap(),
            format!("dh_builddeb (debbuild-rs): {why}\n"),
            "{what}"
        );
        assert!(!out.join("p").exists(), "{what}");
    };

    fs::set_permissions(
        tree.join("DEBIAN/postinst"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    refused(
        "script mode",
        "debian/p: maintainer script 'postinst' has bad permissions 644 (must be >=0555 and <=0775)",
    );
    fs::set_permissions(
        tree.join("DEBIAN/postinst"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    write(&tree.join("DEBIAN/conffiles"), "/etc/p.conf\n", 0o644);
    refused(
        "missing conffile",
        "debian/p: conffile '/etc/p.conf' does not appear in package",
    );
    write(&tree.join("etc/p.conf"), "c", 0o644);

    let control = fs::read_to_string(tree.join("DEBIAN/control")).unwrap();
    write(
        &tree.join("DEBIAN/control"),
        &format!("{control}Depends: a (>> )\n"),
        0o644,
    );
    refused(
        "bad Depends",
        "debian/p/DEBIAN/control: 'Depends' field 'a (>> )': reference to 'a': version '': version string is empty",
    );
    write(&tree.join("DEBIAN/control"), &control, 0o644);

    // and the -dbgsym tree too
    let dbgsym = src.join("debian/.debhelper/p/dbgsym-root");
    write(
        &dbgsym.join("DEBIAN/control"),
        "Package: p-dbgsym\nVersion: 1\n",
        0o644,
    );
    let out = tmp.path().join("out");
    let o = run_builddeb(&src, &bin, &out, &[], false);
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert_eq!(
        String::from_utf8(o.stderr).unwrap(),
        "dh_builddeb (debbuild-rs): debian/.debhelper/p/dbgsym-root/DEBIAN/control: package architecture is missing or empty\n",
    );
    assert!(out.join("p/data.tar").exists());
    assert!(!out.join("p-dbgsym").exists());
}

/// A source package `tmp/src/xx` (no changelog) whose rules record their environment
/// and the changelog in the package.
fn fake_source(tmp: &Path) -> PathBuf {
    let srcdir = tmp.join("src/xx");
    let debian = srcdir.join("debian");
    write(
        &debian.join("control"),
        "Source: xx\nMaintainer: t <t@example.com>\nBuild-Depends: debhelper-compat (= 12)\n\n\
         Package: xx\nArchitecture: all\nDescription: test\n test\n",
        0o644,
    );
    write(
        &debian.join("rules"),
        "#!/usr/bin/make -f\n%:\n\tdh $@\n\noverride_dh_auto_install:\n\t\
         mkdir -p debian/xx/usr/share/x\n\techo \"$$PWD $$SOURCE_DATE_EPOCH\" >debian/xx/usr/share/x/env\n\t\
         cp debian/changelog debian/xx/usr/share/x/\n",
        0o755,
    );
    srcdir
}

/// The entries of `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}

/// A source package `tmp/<rel>` named xx whose shell rules stage package xx with the
/// staging `dh_builddeb`, its file `usr/share/x/f` holding `content`, and the PATH that
/// runs them without fakeroot, debhelper or dpkg-dev (stubs in `tmp/stubs`).
fn stub_source(tmp: &Path, rel: &str, content: &str) -> (PathBuf, String) {
    let srcdir = tmp.join(rel);
    write(
        &srcdir.join("debian/control"),
        "Source: xx\n\nPackage: xx\n",
        0o644,
    );
    write(
        &srcdir.join("debian/rules"),
        &format!(
            "#!/bin/sh\nset -e\ncase \"$1\" in\n\
             clean) rm -rf debian/xx ;;\n\
             binary) mkdir -p debian/xx/DEBIAN debian/xx/usr/share/x\n\
             printf 'Package: xx\\nVersion: 1\\nArchitecture: all\\n' >debian/xx/DEBIAN/control\n\
             echo '{content}' >debian/xx/usr/share/x/f\n\
             dh_builddeb ;;\nesac\n"
        ),
        0o755,
    );
    let stubs = tmp.join("stubs");
    if !stubs.exists() {
        write(&stubs.join("fakeroot"), "#!/bin/sh\nexec \"$@\"\n", 0o755);
        write(
            &stubs.join("dpkg-architecture"),
            "#!/bin/sh\necho DEB_HOST_ARCH=amd64\n",
            0o755,
        );
        write(
            &stubs.join("dh_listpackages"),
            "#!/bin/sh\necho xx\n",
            0o755,
        );
    }
    let path = format!(
        "{}:{}",
        stubs.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    (srcdir, path)
}

/// `debbuild-rs stage --version 1 --epoch EPOCH -o outdir srcdir` with `path`.
fn stage_bin(outdir: &Path, srcdir: &Path, path: &str) -> Output {
    stage_cmd(outdir, srcdir, path).output().unwrap()
}

fn stage_cmd(outdir: &Path, srcdir: &Path, path: &str) -> Command {
    let mut cmd = Command::new(EXE);
    cmd.args([
        "stage",
        "--version",
        "1",
        "--epoch",
        &EPOCH.to_string(),
        "-o",
    ])
    .arg(outdir)
    .arg(srcdir)
    .env("PATH", path);
    cmd
}

/// The new output replaces the previous one whole, and the previous generation is
/// removed with the run's own leftovers, not with those of other outputs.
#[test]
fn stage_publish() {
    use std::os::unix::fs::MetadataExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let (srcdir, path) = stub_source(tmp.path(), "a/xx", "1");
    let outdir = tmp.path().join("out");
    let o = stage_bin(&outdir, &srcdir, &path);
    assert!(o.status.success(), "{o:?}");
    let x = outdir.join("xx");
    assert_eq!(fs::read_to_string(x.join(".staged")).unwrap(), "xx\n");
    assert!(x.join("xx/data.tar").exists());
    let first = fs::metadata(&x).unwrap().ino();
    fs::write(x.join("stale"), "").unwrap();

    // leftovers of killed runs: of this output (removed), of output xx.y (kept)
    for d in [
        ".work.xx.abc123",
        ".work.xx.abc123.old",
        ".work.xx.y.abc123",
    ] {
        fs::create_dir_all(outdir.join(d).join("p")).unwrap();
    }
    let (srcdir, path) = stub_source(tmp.path(), "b/xx", "2");
    let o = stage_bin(&outdir, &srcdir, &path);
    assert!(o.status.success(), "{o:?}");
    assert_ne!(fs::metadata(&x).unwrap().ino(), first);
    assert!(!x.join("stale").exists());
    let tar = Command::new("tar")
        .arg("-xOf")
        .arg(x.join("xx/data.tar"))
        .arg("./usr/share/x/f")
        .output()
        .unwrap();
    assert_eq!(tar.stdout, b"2\n");
    assert_eq!(
        names(&outdir),
        [".work.xx.y.abc123", ".xx.lock", ".xx.publish.lock", "xx"]
    );
}

/// A run staging the same output holds its lock: another one stops before touching it.
#[test]
fn stage_output_locked() {
    use nix::fcntl::{Flock, FlockArg};
    let tmp = tempfile::tempdir().unwrap();
    let (srcdir, path) = stub_source(tmp.path(), "a/xx", "1");
    let outdir = tmp.path().join("out");
    fs::create_dir_all(outdir.join("xx")).unwrap();
    fs::create_dir_all(outdir.join(".work.xx.abc123")).unwrap();
    let lock = fs::File::create(outdir.join(".xx.lock")).unwrap();
    let held = Flock::lock(lock, FlockArg::LockExclusiveNonblock).unwrap();
    let o = stage_bin(&outdir, &srcdir, &path);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(o.stderr).unwrap(),
        format!(
            "debbuild-rs: {}/xx is already being staged\n",
            outdir.display()
        )
    );
    // the other run's work directory and output are left alone
    assert_eq!(names(&outdir), [".work.xx.abc123", ".xx.lock", "xx"]);
    drop(held);
    let o = stage_bin(&outdir, &srcdir, &path);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(names(&outdir), [".xx.lock", ".xx.publish.lock", "xx"]);
}

/// A reader of the output, holding its publish lock shared, delays the publish of a run
/// that has built: the output stays the previous generation until the reader is done.
#[test]
fn stage_waits_for_readers() {
    use nix::fcntl::{Flock, FlockArg};
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let tmp = tempfile::tempdir().unwrap();
    let outdir = tmp.path().join("out");
    let (srcdir, path) = stub_source(tmp.path(), "a/xx", "1");
    assert!(stage_bin(&outdir, &srcdir, &path).status.success());
    let sum = outdir.join("xx/xx/data.tar.sha256");
    let first = fs::read_to_string(&sum).unwrap();
    let lock = fs::File::open(outdir.join(".xx.publish.lock")).unwrap();
    let held = Flock::lock(lock, FlockArg::LockSharedNonblock).unwrap();

    let (srcdir, path) = stub_source(tmp.path(), "b/xx", "2");
    let mut child = stage_cmd(&outdir, &srcdir, &path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    assert_eq!(
        line,
        format!(
            "debbuild-rs: waiting for the readers of {}/xx\n",
            outdir.display()
        )
    );
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(child.try_wait().unwrap().is_none());
    assert_eq!(fs::read_to_string(&sum).unwrap(), first);

    drop(held);
    assert!(child.wait().unwrap().success());
    assert_ne!(fs::read_to_string(&sum).unwrap(), first);
    assert_eq!(names(&outdir), [".xx.lock", ".xx.publish.lock", "xx"]);
}

fn opts(srcdir: &Path, outdir: &Path, entry: Option<Entry>, epoch: Option<i64>) -> Options {
    Options {
        srcdir: srcdir.to_path_buf(),
        outdir: outdir.to_path_buf(),
        exe: EXE.into(),
        entry,
        epoch,
        check_build_deps: false,
    }
}

fn entry(version: &str) -> Entry {
    Entry {
        version: version.as_bytes().to_vec(),
        distribution: None,
        maintainer: None,
        message: None,
    }
}

#[test]
fn stage_checks() {
    let tmp = tempfile::tempdir().unwrap();
    let srcdir = fake_source(tmp.path());
    let out = tmp.path().join("out");
    let missing = tmp.path().join("missing");
    assert_eq!(
        stage(&opts(&missing, &out, None, None)),
        Err(Error::Message(format!(
            "debbuild-rs: {}: No such file or directory (os error 2)",
            missing.display()
        )))
    );
    let y = tmp.path().join("y");
    fs::create_dir_all(&y).unwrap();
    assert_eq!(
        stage(&opts(&y, &out, None, None)),
        Err(Error::Message(format!(
            "debbuild-rs: no debian/control in {}",
            y.display()
        )))
    );
    assert_eq!(
        stage(&opts(&srcdir, &out, None, None)),
        Err(Error::Message(format!(
            "debbuild-rs: no debian/changelog in {}: give --version",
            srcdir.display()
        )))
    );
    write(&srcdir.join("debian/changelog"), "kept\n", 0o644);
    assert_eq!(
        stage(&opts(&srcdir, &out, Some(entry("1.0")), None)),
        Err(Error::Message(format!(
            "debbuild-rs: {}/debian/changelog exists: --version would replace it",
            srcdir.display()
        )))
    );
    assert_eq!(
        fs::read_to_string(srcdir.join("debian/changelog")).unwrap(),
        "kept\n"
    );
}

/// An invalid `SOURCE_DATE_EPOCH` in the environment is refused, unless --epoch
/// replaces it.
#[test]
fn stage_bad_env_epoch() {
    let tmp = tempfile::tempdir().unwrap();
    let srcdir = fake_source(tmp.path());
    let out = tmp.path().join("out");
    for bad in ["x", "-1", "1e9"] {
        let o = Command::new(EXE)
            .args(["stage", "--version", "1.0", "-o"])
            .arg(&out)
            .arg(&srcdir)
            .env("SOURCE_DATE_EPOCH", bad)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(1), "{bad}");
        assert_eq!(
            String::from_utf8(o.stderr).unwrap(),
            format!("debbuild-rs: invalid SOURCE_DATE_EPOCH '{bad}' in the environment\n")
        );
    }
    // with --epoch, the run gets past the epoch (and fails later, on --version's check)
    let o = Command::new(EXE)
        .args(["stage", "--version", "x", "--epoch", "1", "-o"])
        .arg(&out)
        .arg(&srcdir)
        .env("SOURCE_DATE_EPOCH", "x")
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(o.stderr).unwrap(),
        "debbuild-rs: invalid version 'x'\n"
    );
    assert!(!out.exists());
}

#[test]
fn stage_bad_version() {
    let tmp = tempfile::tempdir().unwrap();
    let srcdir = fake_source(tmp.path());
    for v in ["", "x1", "1 2", "1/2", "1\n2"] {
        let res = stage(&opts(
            &srcdir,
            &tmp.path().join("out"),
            Some(entry(v)),
            None,
        ));
        assert_eq!(
            res,
            Err(Error::Message(format!(
                "debbuild-rs: invalid version '{v}'"
            ))),
        );
    }
    assert!(!srcdir.join("debian/changelog").exists());
}

/// The whole run, with debhelper (skipped where dh is missing).
#[test]
fn stage_package() {
    if !(have("dh") && have("fakeroot") && have("dpkg-architecture")) {
        skip("debhelper");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let srcdir = fake_source(tmp.path());
    let outdir = tmp.path().join("out");
    let x = outdir.join("xx");
    let extract = |name: &str| {
        let o = Command::new("tar")
            .args(["-xOf"])
            .arg(x.join("xx/data.tar"))
            .arg(name)
            .output()
            .unwrap();
        String::from_utf8(o.stdout).unwrap()
    };

    // a written entry, through the binary: the options, SOURCE_DATE_EPOCH from the
    // environment
    let o = Command::new(EXE)
        .args(["stage", "-o"])
        .arg(&outdir)
        .args([
            "--version",
            "5.0.1.20261017-br~x1",
            "--distribution",
            "Product",
            "--maintainer",
            "Dev <dev@example.com>",
            "--message",
            "Release 5.0.1",
        ])
        .arg(&srcdir)
        .env("SOURCE_DATE_EPOCH", EPOCH.to_string())
        .output()
        .unwrap();
    assert!(o.status.success(), "{o:?}");
    assert_eq!(fs::read_to_string(x.join(".staged")).unwrap(), "xx\n");
    let control = fs::read_to_string(x.join("xx/DEBIAN/control")).unwrap();
    assert!(
        control.contains("Version: 5.0.1.20261017-br~x1\n"),
        "{control}"
    );
    assert!(x.join("xx/data.tar.sha256").exists());
    assert_eq!(fs::metadata(&x).unwrap().mode() & 0o777, 0o755);
    assert!(!x.join(".bin").exists());
    assert!(!srcdir.join("debian/changelog").exists());
    assert!(!srcdir.join("debian/xx").exists());
    assert_eq!(names(&outdir), [".xx.lock", ".xx.publish.lock", "xx"]);
    assert_eq!(
        extract("./usr/share/x/env"),
        format!("{} {EPOCH}\n", srcdir.display())
    );
    assert_eq!(
        extract("./usr/share/x/changelog"),
        "xx (5.0.1.20261017-br~x1) Product; urgency=medium\n\n  \
         * Release 5.0.1\n\n \
         -- Dev <dev@example.com>  Thu, 01 Jan 2026 00:00:00 +0000\n"
    );

    // the defaults of a written entry, --epoch over the environment
    let res = stage(&opts(
        &srcdir,
        &outdir,
        Some(entry("2.0")),
        Some(1_792_195_200),
    ));
    assert_eq!(res, Ok(()));
    assert_eq!(
        extract("./usr/share/x/changelog"),
        "xx (2.0) UNRELEASED; urgency=medium\n\n  * Build 2.0\n\n \
         -- t <t@example.com>  Sat, 17 Oct 2026 00:00:00 +0000\n"
    );

    // the package's own changelog: its version and date, kept
    let own = "xx (3.0-1) unstable; urgency=medium\n\n  * x\n\n \
               -- t <t@example.com>  Sat, 17 Oct 2026 00:00:00 +0000\n";
    write(&srcdir.join("debian/changelog"), own, 0o644);
    let o = Command::new(EXE)
        .args(["stage", "-o"])
        .arg(&outdir)
        .arg(&srcdir)
        .env_remove("SOURCE_DATE_EPOCH")
        .output()
        .unwrap();
    assert!(o.status.success(), "{o:?}");
    let control = fs::read_to_string(x.join("xx/DEBIAN/control")).unwrap();
    assert!(control.contains("Version: 3.0-1\n"), "{control}");
    assert!(extract("./usr/share/x/env").ends_with(" 1792195200\n"));
    assert_eq!(
        fs::read_to_string(x.join("xx/staged.info")).unwrap(),
        "Format: 1\nEpoch: 1792195200\n"
    );
    assert_eq!(
        fs::read_to_string(srcdir.join("debian/changelog")).unwrap(),
        own
    );
}

/// A signal during the build: the build gets it, `debian/rules clean` then runs to
/// completion, and the run dies of the signal.
#[test]
fn stage_signal_cleans_up() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::{Duration, Instant};

    for (sig, signo) in [("TERM", 15), ("INT", 2), ("HUP", 1)] {
        let tmp = tempfile::tempdir().unwrap();
        let srcdir = fake_source(tmp.path());
        let stubs = tmp.path().join("stubs");
        write(&stubs.join("fakeroot"), "#!/bin/sh\nexec \"$@\"\n", 0o755);
        write(
            &stubs.join("dpkg-architecture"),
            "#!/bin/sh\necho DEB_HOST_ARCH=amd64\n",
            0o755,
        );
        let marks = tmp.path().join("marks");
        fs::create_dir(&marks).unwrap();
        write(
            &srcdir.join("debian/rules"),
            "#!/bin/sh\ncase \"$1\" in\n\
             clean) if [ -e \"$MARKS/built\" ]; then sleep 1; echo cleaned >\"$MARKS/cleaned\"; fi ;;\n\
             build) touch \"$MARKS/built\"; exec sleep 60 ;;\nesac\n",
            0o755,
        );
        let outdir = tmp.path().join("out");
        let path = format!(
            "{}:{}",
            stubs.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut child = Command::new(EXE)
            .args(["stage", "--version", "1.0", "-o"])
            .arg(&outdir)
            .arg(&srcdir)
            .env("PATH", path)
            .env("MARKS", &marks)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !marks.join("built").exists() {
            assert!(Instant::now() < deadline, "{sig}: the build did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        // the build's sleep is running (or about to)
        std::thread::sleep(Duration::from_millis(200));
        // the shell's kill: minimal systems lack /bin/kill
        let kill = Command::new("sh")
            .args(["-c", "kill -s \"$0\" \"$1\"", sig])
            .arg(child.id().to_string())
            .status()
            .unwrap();
        assert!(kill.success());
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                panic!("{sig}: the run did not end");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.signal(), Some(signo), "{sig}: {status:?}");
        assert!(
            marks.join("cleaned").exists(),
            "{sig}: clean did not complete"
        );
        assert!(!srcdir.join("debian/changelog").exists());
        assert_eq!(names(&outdir), [".xx.lock", ".xx.publish.lock"], "{sig}");
    }
}

#[test]
fn stage_missing_tools() {
    let tmp = tempfile::tempdir().unwrap();
    let src = fake_source(tmp.path());
    let o = Command::new(EXE)
        .args(["stage", "-o"])
        .arg(tmp.path().join("out"))
        .arg(&src)
        .env("PATH", tmp.path().join("nothing"))
        .output()
        .unwrap();
    assert!(!o.status.success());
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        stderr.contains("missing tools: dpkg-architecture (package dpkg-dev)"),
        "{stderr}"
    );
    // the source tree untouched
    assert!(!tmp.path().join("out").exists());
}
