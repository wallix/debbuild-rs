//! `debbuild-rs pack`, through the binary, checked against dpkg-deb where it is installed.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const EXE: &str = env!("CARGO_BIN_EXE_debbuild-rs");
const EPOCH: u64 = 1_792_195_200;

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

fn write(path: &Path, content: &[u8], mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// A staged source directory `src` with package `p` (version with an epoch), staged by
/// the staging `dh_builddeb` from a package tree, and that tree's file tree.
fn staged(tmp: &Path, options: Option<&str>) -> (PathBuf, PathBuf) {
    let pkgdir = tmp.join("pkg");
    let tree = pkgdir.join("debian/p");
    write(&tree.join("usr/share/p/a"), b"a\n", 0o644);
    write(&tree.join("usr/bin/b"), b"#!/bin/sh\n", 0o755);
    symlink("../share/p/a", tree.join("usr/bin/a")).unwrap();
    write(
        &tree.join("DEBIAN/control"),
        b"Package: p\nVersion: 1:2.0-1\nArchitecture: all\nMaintainer: t <t@example.com>\n\
          Description: test\n test\n",
        0o644,
    );
    write(&tree.join("DEBIAN/postinst"), b"#!/bin/sh\nexit 0\n", 0o755);
    let bin = tmp.join("bin");
    fs::create_dir_all(&bin).unwrap();
    symlink(EXE, bin.join("dh_builddeb")).unwrap();
    write(&bin.join("dh_listpackages"), b"#!/bin/sh\necho p\n", 0o755);
    let src = tmp.join("stage/src");
    let mut args = vec!["--".to_owned()];
    args.extend(options.unwrap_or_default().lines().map(str::to_owned));
    // in a fakeroot session, as debian/rules binary runs it
    let mut cmd = if have("fakeroot") {
        let mut c = Command::new("fakeroot");
        c.arg(bin.join("dh_builddeb"));
        c
    } else {
        Command::new(bin.join("dh_builddeb"))
    };
    let o = cmd
        .args(&args)
        .current_dir(&pkgdir)
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        )
        .env("DEBBUILD_RS_STAGE_DIR", &src)
        .env("SOURCE_DATE_EPOCH", EPOCH.to_string())
        .output()
        .unwrap();
    assert!(o.status.success(), "{o:?}");
    write(&src.join(".staged"), b"p\n", 0o644);
    // the file tree without DEBIAN, for dpkg-deb
    let root = tmp.join("root");
    let st = Command::new("cp")
        .arg("-a")
        .arg(&tree)
        .arg(&root)
        .status()
        .unwrap();
    assert!(st.success());
    fs::remove_dir_all(root.join("DEBIAN")).unwrap();
    (src, root)
}

fn pack(staged: &Path, dest: &Path) -> Output {
    pack_with(staged, dest, &["--epoch", &EPOCH.to_string()], None)
}

/// `pack` with `args` before -d, `SOURCE_DATE_EPOCH` set to `env` or unset.
fn pack_with(staged: &Path, dest: &Path, args: &[&str], env: Option<&str>) -> Output {
    let mut cmd = Command::new(EXE);
    cmd.arg("pack")
        .args(args)
        .arg("-d")
        .arg(dest)
        .arg(staged)
        .env_remove("SOURCE_DATE_EPOCH");
    if let Some(e) = env {
        cmd.env("SOURCE_DATE_EPOCH", e);
    }
    cmd.output().unwrap()
}

fn ar_members(deb: &Path) -> Vec<String> {
    let o = Command::new("ar").arg("t").arg(deb).output().unwrap();
    String::from_utf8(o.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// `tar -tv` of a member, through dpkg-deb.
fn listing(deb: &Path, what: &str) -> String {
    let o = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "dpkg-deb {what} \"$1\" | tar -tv --numeric-owner --full-time"
        ))
        .arg("sh")
        .arg(deb)
        .env("TZ", "UTC")
        .output()
        .unwrap();
    assert!(o.status.success(), "{o:?}");
    String::from_utf8(o.stdout).unwrap()
}

#[test]
fn pack_deb() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, root) = staged(tmp.path(), None);
    let dest = tmp.path().join("out");
    let o = pack(&src, &dest);
    assert!(o.status.success(), "{o:?}");
    let deb = dest.join("p_2.0-1_all.deb");
    assert_eq!(
        String::from_utf8(o.stdout).unwrap(),
        format!("{}\n", deb.display())
    );
    assert_eq!(
        fs::metadata(&deb).unwrap().permissions().mode() & 0o777,
        0o644
    );
    let bytes = fs::read(&deb).unwrap();
    assert!(bytes.starts_with(
        b"!<arch>\ndebian-binary   1792195200  0     0     100644  4         `\n2.0\n"
    ));
    if have("ar") {
        assert_eq!(
            ar_members(&deb),
            ["debian-binary", "control.tar.xz", "data.tar.xz"]
        );
    }
    // the same staged tree and epoch: the same bytes
    let again = tmp.path().join("again");
    assert!(pack(&src.join("p"), &again).status.success());
    assert_eq!(fs::read(again.join("p_2.0-1_all.deb")).unwrap(), bytes);
    // the epoch recorded at stage time, over the environment's
    let recorded = tmp.path().join("recorded");
    let o = pack_with(&src, &recorded, &[], Some("1"));
    assert!(o.status.success(), "{o:?}");
    assert_eq!(fs::read(recorded.join("p_2.0-1_all.deb")).unwrap(), bytes);

    if !(have("dpkg-deb") && have("fakeroot")) {
        skip("dpkg-deb");
        return;
    }
    // what dpkg-deb --build makes of the same tree
    let build = tmp.path().join("build");
    let st = Command::new("cp")
        .arg("-a")
        .arg(&root)
        .arg(&build)
        .status()
        .unwrap();
    assert!(st.success());
    let st = Command::new("cp")
        .arg("-a")
        .arg(src.join("p/DEBIAN"))
        .arg(build.join("DEBIAN"))
        .status()
        .unwrap();
    assert!(st.success());
    let reference = tmp.path().join("ref.deb");
    let o = Command::new("fakeroot")
        // Debian's default compression (Ubuntu's dpkg-deb defaults to zstd)
        .args(["dpkg-deb", "-Zxz", "--root-owner-group", "--build"])
        .arg(&build)
        .arg(&reference)
        .env("SOURCE_DATE_EPOCH", EPOCH.to_string())
        .output()
        .unwrap();
    assert!(o.status.success(), "{o:?}");
    assert_eq!(ar_members(&deb), ar_members(&reference));
    for what in ["--ctrl-tarfile", "--fsys-tarfile"] {
        assert_eq!(listing(&deb, what), listing(&reference, what), "{what}");
    }
    let info = |d: &Path| {
        Command::new("dpkg-deb")
            .args(["-f"])
            .arg(d)
            .output()
            .unwrap()
            .stdout
    };
    assert_eq!(info(&deb), info(&reference));
    assert!(
        bytes == fs::read(&reference).unwrap(),
        "not dpkg-deb's bytes"
    );
}

#[test]
fn pack_options() {
    if !have("ar") {
        skip("ar");
        return;
    }
    for (opts, ext) in [
        ("-Zzstd\n-z19\n", ".zst"),
        ("-Zgzip\n", ".gz"),
        ("-Zxz\n-Sextreme\n-z9\n", ".xz"),
        ("-Znone\n", ""),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let (src, _) = staged(tmp.path(), Some(opts));
        let dest = tmp.path().join("out");
        let o = pack(&src, &dest);
        assert!(o.status.success(), "{o:?}");
        let deb = dest.join("p_2.0-1_all.deb");
        assert_eq!(
            ar_members(&deb),
            [
                "debian-binary".to_owned(),
                format!("control.tar{ext}"),
                format!("data.tar{ext}")
            ]
        );
        if have("dpkg-deb") {
            let o = Command::new("dpkg-deb")
                .arg("--fsys-tarfile")
                .arg(&deb)
                .output()
                .unwrap();
            assert!(o.status.success(), "{opts}: {o:?}");
            assert_eq!(o.stdout, fs::read(src.join("p/data.tar")).unwrap());
        }
    }
}

#[test]
fn pack_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, _) = staged(tmp.path(), Some("-Zbz2\n"));
    let dest = tmp.path().join("out");
    let o = pack(&src, &dest);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(o.stderr).unwrap(),
        format!(
            "debbuild-rs pack: error: {}/p/dpkg-deb.options: unknown compression type 'bz2'\n",
            src.display()
        )
    );

    fs::remove_file(src.join("p/dpkg-deb.options")).unwrap();
    write(&src.join("p/data.tar.sha256"), b"0\n", 0o644);
    let o = pack(&src, &dest);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(o.stderr).unwrap(),
        format!(
            "debbuild-rs pack: error: {0}/p/data.tar: does not match {0}/p/data.tar.sha256\n",
            src.display()
        )
    );
    assert!(!dest.join("p_2.0-1_all.deb").exists());
    // no temporary file left behind
    assert_eq!(fs::read_dir(&dest).unwrap().count(), 0);

    let o = pack(tmp.path(), &dest);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(o.stderr).unwrap(),
        format!(
            "debbuild-rs pack: error: {}: neither a staged source directory nor a staged package\n",
            tmp.path().display()
        )
    );
}

/// The epoch of a tree: the recorded one, which --epoch must match; --epoch, the
/// environment's, otherwise the current time for a tree without a record.
#[test]
fn pack_epochs() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, _) = staged(tmp.path(), Some("-Znone\n"));
    let dest = tmp.path().join("out");
    let deb = dest.join("p_2.0-1_all.deb");
    let mtime = |deb: &Path| {
        let bytes = fs::read(deb).unwrap();
        String::from_utf8(bytes[24..36].to_vec())
            .unwrap()
            .trim_end()
            .parse::<u64>()
            .unwrap()
    };

    let o = pack_with(&src, &dest, &["--epoch", "5"], None);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(o.stderr).unwrap(),
        format!(
            "debbuild-rs pack: error: {}/p: staged with epoch {EPOCH}, not 5\n",
            src.display()
        )
    );
    assert!(!deb.exists());

    let info = src.join("p/staged.info");
    for (text, msg) in [
        ("Format: 2\nEpoch: 1\n", "unknown format '2'"),
        ("Epoch: 1\n", "no Format field"),
        ("Format: 1\nEpoch: -1\n", "no valid Epoch field"),
        ("Format: 1\n", "no valid Epoch field"),
    ] {
        write(&info, text.as_bytes(), 0o644);
        let o = pack_with(&src, &dest, &[], None);
        assert_eq!(o.status.code(), Some(1), "{text}");
        assert_eq!(
            String::from_utf8(o.stderr).unwrap(),
            format!("debbuild-rs pack: error: {}: {msg}\n", info.display())
        );
    }

    // a tree staged before staged.info
    fs::remove_file(&info).unwrap();
    assert!(
        pack_with(&src, &dest, &["--epoch", "5"], Some("7"))
            .status
            .success()
    );
    assert_eq!(mtime(&deb), 5);
    assert!(pack_with(&src, &dest, &[], Some("7")).status.success());
    assert_eq!(mtime(&deb), 7);
    let o = pack_with(&src, &dest, &[], Some("x"));
    assert_eq!(
        String::from_utf8(o.stderr).unwrap(),
        "debbuild-rs pack: error: invalid SOURCE_DATE_EPOCH 'x' in the environment\n"
    );
    assert!(pack_with(&src, &dest, &[], None).status.success());
    assert!(mtime(&deb) > EPOCH);
}

#[test]
fn inspect() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, _) = staged(tmp.path(), Some("-Zzstd\n-z19"));
    let o = Command::new(EXE).arg("inspect").arg(&src).output().unwrap();
    assert!(o.status.success(), "{o:?}");
    assert_eq!(
        String::from_utf8(o.stdout).unwrap(),
        format!("src/p 1:2.0-1 all zstd -19 epoch {EPOCH}\n")
    );
    // the output directory, and a broken tree
    fs::remove_file(src.join("p/data.tar")).unwrap();
    let o = Command::new(EXE)
        .arg("inspect")
        .arg(src.parent().unwrap())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("data.tar"),
        "{o:?}"
    );
}

/// A staged tree dpkg-deb --build would refuse is not packed.
#[test]
fn pack_checks_trees() {
    let tmp = tempfile::tempdir().unwrap();
    let (src, _) = staged(tmp.path(), None);
    let p = src.join("p");
    let dest = tmp.path().join("out");
    let refused = |what: &str, why: &str| {
        let o = pack(&src, &dest);
        assert_eq!(o.status.code(), Some(1), "{what}: {o:?}");
        assert_eq!(
            String::from_utf8(o.stderr).unwrap(),
            format!("debbuild-rs pack: error: {why}\n"),
            "{what}"
        );
        assert_eq!(fs::read_dir(&dest).unwrap().count(), 0, "{what}");
    };

    let postinst = p.join("DEBIAN/postinst");
    fs::set_permissions(&postinst, fs::Permissions::from_mode(0o644)).unwrap();
    refused(
        "script mode",
        &format!(
            "{}: maintainer script 'postinst' has bad permissions 644 (must be >=0555 and <=0775)",
            p.display()
        ),
    );
    fs::set_permissions(&postinst, fs::Permissions::from_mode(0o755)).unwrap();

    let control = p.join("DEBIAN/control");
    let text = fs::read_to_string(&control).unwrap();
    write(
        &control,
        format!("{text}Provides: v (>= 1)\n").as_bytes(),
        0o644,
    );
    refused(
        "Provides",
        &format!(
            "{}: 'Provides' field 'v (>= 1)': only exact versions may be used",
            control.display()
        ),
    );
    write(&control, text.as_bytes(), 0o644);

    // conffiles are looked up in data.tar
    let conffiles = p.join("DEBIAN/conffiles");
    write(&conffiles, b"/usr/share/p/b\n", 0o644);
    refused(
        "missing conffile",
        &format!(
            "{}: conffile '/usr/share/p/b' does not appear in package",
            p.display()
        ),
    );
    // as lstat looks them up: symlinks followed before a slash
    write(&conffiles, b"/usr/bin/a/\n", 0o644);
    refused(
        "conffile under a symlink to a file",
        &format!(
            "{}: conffile '/usr/bin/a/' is not stattable: Not a directory",
            p.display()
        ),
    );
    write(
        &conffiles,
        b"/usr/share/p/a\n/usr/bin/a\nremove-on-upgrade /etc/old\n",
        0o644,
    );
    let o = pack(&src, &dest);
    assert!(o.status.success(), "{o:?}");
    fs::remove_file(dest.join("p_2.0-1_all.deb")).unwrap();
    fs::remove_file(&conffiles).unwrap();

    // a data.tar path escaping the root
    let mut tar = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.as_old_mut().name[..9].copy_from_slice(b"./../evil");
    h.set_entry_type(tar::EntryType::Regular);
    h.set_mode(0o644);
    h.set_size(0);
    h.set_cksum();
    tar.append(&h, std::io::empty()).unwrap();
    write(&p.join("data.tar"), &tar.into_inner().unwrap(), 0o644);
    fs::remove_file(p.join("data.tar.sha256")).unwrap();
    refused(
        "path escaping the root",
        &format!(
            "{}: ./../evil: '..' component",
            p.join("data.tar").display()
        ),
    );
}

/// The readers of a staged output wait for the publish holding its lock: pack of the
/// source directory or of a package tree of it, inspect, diff-stage.
#[test]
fn readers_wait_for_publish() {
    use nix::fcntl::{Flock, FlockArg};
    use std::process::Stdio;
    let tmp = tempfile::tempdir().unwrap();
    let (src, _) = staged(tmp.path(), None);
    let out = src.parent().unwrap();
    let lock = fs::File::create(out.join(".src.publish.lock")).unwrap();
    let held = Flock::lock(lock, FlockArg::LockExclusiveNonblock).unwrap();
    let dest = tmp.path().join("debs");
    let epoch = EPOCH.to_string();
    let mut children: Vec<_> = [
        vec![
            "pack",
            "--epoch",
            &epoch,
            "-d",
            dest.to_str().unwrap(),
            src.to_str().unwrap(),
        ],
        vec![
            "pack",
            "--epoch",
            &epoch,
            "-d",
            dest.to_str().unwrap(),
            src.join("p").to_str().unwrap(),
        ],
        vec!["inspect", out.to_str().unwrap()],
        vec!["diff-stage", src.to_str().unwrap(), src.to_str().unwrap()],
    ]
    .iter()
    .map(|args| {
        Command::new(EXE)
            .args(args)
            .stdout(Stdio::null())
            .spawn()
            .unwrap()
    })
    .collect();
    std::thread::sleep(std::time::Duration::from_millis(300));
    for c in &mut children {
        assert!(c.try_wait().unwrap().is_none(), "{c:?}");
    }
    assert!(!dest.exists() || fs::read_dir(&dest).unwrap().next().is_none());
    drop(held);
    for mut c in children {
        assert!(c.wait().unwrap().success(), "{c:?}");
    }
    assert_eq!(fs::read_dir(&dest).unwrap().count(), 1);
}
