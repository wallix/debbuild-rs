//! The installer, on tiny synthetic staged packages installed into a temporary root
//! holding a minimal dpkg database, without privileges. One test per case of the
//! Python self-test it replaces (same names), then the additions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::process::Command;

use common::{Base, Entry, Opts, file, gid, link, md5, uid};
use debbuild_rs_install::staged::{LoadPoint, hooks};
use debbuild_rs_install::{Conffiles, Database, InstallOptions, Installer, load_staged};

fn o() -> Opts<'static> {
    Opts::default()
}

fn ctl<'a>(control: &'a [(&'a str, &'a str)]) -> Opts<'a> {
    Opts {
        control,
        ..Opts::default()
    }
}

fn scr<'a>(scripts: &'a [(&'a str, &'a str)]) -> Opts<'a> {
    Opts {
        scripts,
        ..Opts::default()
    }
}

// --- Plan ---

#[test]
fn alternatives_and_order() {
    let t = Base::new();
    t.set_installed("c", "1", &[]);
    t.set_installed("e", "0.9", &[]);
    t.stage_pkg("b", "1", &[], &o());
    t.stage_pkg("e", "1", &[], &o());
    // an installed alternative will do
    t.stage_pkg("a", "1", &[], &ctl(&[("Depends", "b | c")]));
    assert_eq!(t.plan(&["a"]), ["a"]);
    // otherwise the first staged one
    t.stage_pkg("x", "1", &[], &ctl(&[("Depends", "nothere | b")]));
    assert_eq!(t.plan(&["x"]), ["b", "x"]);
    // a staged alternative already installed is taken from the stage
    t.stage_pkg("y", "1", &[], &ctl(&[("Depends", "b | e")]));
    t.stage_pkg("z", "1", &[], &ctl(&[("Pre-Depends", "y")]));
    assert_eq!(t.plan(&["z"]), ["e", "y", "z"]);
    t.stage_pkg("m", "1", &[], &ctl(&[("Depends", "nothere")]));
    assert!(
        t.try_plan(&["m"])
            .unwrap_err()
            .message()
            .contains("unsatisfied")
    );
}

#[test]
fn conflicts_and_breaks() {
    let t = Base::new();
    t.set_installed("c", "1", &[]);
    t.set_installed("e", "0.9", &[("Breaks", "k3")]);
    t.stage_pkg("e", "1", &[], &o());
    t.stage_pkg("k", "1", &[], &ctl(&[("Conflicts", "c")]));
    assert!(
        t.try_plan(&["k"])
            .unwrap_err()
            .message()
            .contains("k conflicts c")
    );
    t.stage_pkg("k2", "1", &[], &ctl(&[("Breaks", "e (<< 1)")]));
    assert!(
        t.try_plan(&["k2"])
            .unwrap_err()
            .message()
            .contains("k2 breaks e")
    );
    // the plan upgrades e to a version k2 does not break
    let mut p = t.plan(&["k2", "e"]);
    p.sort();
    assert_eq!(p, ["e", "k2"]);
    // an installed package breaking a planned one
    t.stage_pkg("k3", "1", &[], &o());
    assert!(
        t.try_plan(&["k3"])
            .unwrap_err()
            .message()
            .contains("e breaks k3")
    );
    // a package may conflict with what it provides
    t.stage_pkg(
        "v",
        "1",
        &[],
        &ctl(&[("Provides", "vv"), ("Conflicts", "vv")]),
    );
    assert_eq!(t.plan(&["v"]), ["v"]);
}

#[test]
fn relationship_field_rules() {
    let t = Base::new();
    let refused = |name: &str, field: &str, value: &str, why: &str| {
        t.stage_pkg(name, "1", &[], &ctl(&[(field, value)]));
        assert_eq!(
            t.try_plan(&[name]).unwrap_err().message(),
            format!(
                "parsing file '{}' package '{name}': '{field}' field '{value}': {why}",
                t.pkgdir(name).join("DEBIAN/control").display()
            )
        );
    };
    refused("a", "Conflicts", "b | c", "alternatives ('|') not allowed");
    refused("a", "Replaces", "b | c", "alternatives ('|') not allowed");
    refused(
        "a",
        "Provides",
        "b (>= 1)",
        "only exact versions may be used",
    );
    // as dpkg -i, a field the installer does not use
    refused(
        "a",
        "Enhances",
        "b c",
        "syntax error after reference to package 'b'",
    );
    // a package the plan pulls in
    t.stage_pkg("a", "1", &[], &o());
    t.stage_pkg("b", "1", &[], &ctl(&[("Breaks", "x | y")]));
    t.stage_pkg("c", "1", &[], &ctl(&[("Depends", "b")]));
    assert!(
        t.try_plan(&["c"])
            .unwrap_err()
            .message()
            .contains("package 'b': 'Breaks' field 'x | y'")
    );
    t.stage_pkg(
        "b",
        "1",
        &[],
        &ctl(&[("Breaks", "x"), ("Suggests", "x | y")]),
    );
    assert_eq!(t.plan(&["c"]), ["b", "c"]);
}

#[test]
fn status_relationship_fields() {
    let t = Base::new();
    t.stage_pkg("a", "1", &[], &ctl(&[("Depends", "v")]));
    // dpkg reads its database with lax rules: warnings
    t.set_installed("s", "1", &[("Provides", "v (>= 1), w (= 1_a)")]);
    let mut db = Database::new(&t.root);
    db.load().unwrap();
    let status = t.admin.join("status");
    assert_eq!(
        db.warnings,
        [
            format!(
                "parsing file '{}' package 's': 'Provides' field 'v (>= 1), w (= 1_a)': only exact versions may be used",
                status.display()
            ),
            format!(
                "parsing file '{}' package 's': 'Provides' field 'v (>= 1), w (= 1_a)': reference to 'w': version '1_a': invalid character in version number",
                status.display()
            ),
        ]
    );
    assert_eq!(t.plan(&["a"]), ["a"]);
    let out = cli(&t, &["--dry-run", "--json", "a"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(out.stdout.starts_with(b"{\"packages\""), "{out:?}");
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .starts_with("debbuild-rs install: warning: parsing file '")
    );
    // what dpkg refuses there makes the database unusable, as for dpkg
    t.set_installed("u", "1", &[("Conflicts", "x | y")]);
    assert_eq!(
        t.try_plan(&["a"]).unwrap_err().message(),
        format!(
            "parsing file '{}' package 'u': 'Conflicts' field 'x | y': alternatives ('|') not allowed",
            status.display()
        )
    );
}

/// dpkg-query as the oracle: the status file entries it refuses and warns about.
#[test]
fn status_relationship_fields_against_dpkg() {
    if Command::new("dpkg-query")
        .arg("--version")
        .output()
        .is_err()
    {
        assert!(
            std::env::var_os("DEBBUILD_RS_TEST_REQUIRE_TOOLS").is_none(),
            "no dpkg-query"
        );
        eprintln!("skipped: no dpkg-query");
        return;
    }
    let cases = [
        ("Depends", "a (>= 1) | b"),
        ("Depends", "a (= 1_a)"),
        ("Depends", "a (= x1)"),
        ("Depends", "a (= 1-a_b)"),
        ("Depends", "a (= :1)"),
        ("Depends", "a (= 1-)"),
        ("Depends", "a ||b"),
        ("Pre-Depends", "a:any"),
        ("Enhances", "a b"),
        ("Provides", "a (>= 1)"),
        ("Provides", "a | b"),
        ("Conflicts", "a | b"),
        ("Breaks", "a (<< 1)"),
        ("Replaces", "a | b"),
    ];
    for (field, value) in cases {
        let t = Base::new();
        fs::write(
            t.admin.join("status"),
            format!(
                "Package: s\nStatus: install ok installed\nVersion: 1\nArchitecture: all\nMaintainer: m\nDescription: d\n{field}: {value}\n\n"
            ),
        )
        .unwrap();
        let o = Command::new("dpkg-query")
            .arg(format!("--admindir={}", t.admin.display()))
            .args(["-s", "s"])
            .output()
            .unwrap();
        let mut db = Database::new(&t.root);
        let ours = db.load();
        assert_eq!(o.status.success(), ours.is_ok(), "{field}: {value}: {o:?}");
        let warned = String::from_utf8_lossy(&o.stderr).contains("warning:");
        assert_eq!(warned, !db.warnings.is_empty(), "{field}: {value}: {o:?}");
    }
}

#[test]
fn multiarch_same() {
    let t = Base::new();
    t.stage_pkg("ma", "1", &[], &ctl(&[("Multi-Arch", "same")]));
    assert!(
        t.try_plan(&["ma"])
            .unwrap_err()
            .message()
            .contains("Multi-Arch")
    );
}

#[test]
fn triggers_pending_counts_as_installed() {
    let t = Base::new();
    t.set_installed("c", "1", &[("Provides", "cc")]);
    t.edit_status(
        "c",
        &[
            ("Status", Some("install ok triggers-pending")),
            ("Triggers-Pending", Some("foo")),
        ],
    );
    t.stage_pkg("a", "1", &[], &ctl(&[("Depends", "c (>= 1), cc")]));
    assert_eq!(t.plan(&["a"]), ["a"]);
}

#[test]
fn upgrade_breaking_a_dependency() {
    let t = Base::new();
    t.set_installed("b", "1", &[]);
    t.stage_pkg("b", "2", &[], &o());
    t.stage_pkg("a", "1", &[], &ctl(&[("Depends", "b (= 1)")]));
    let status = t.read("var/lib/dpkg/status");
    // b 1 satisfies a, but the plan upgrades it to 2
    assert_eq!(
        t.install_err(&["a", "b"]),
        "unsatisfied dependencies:\n  a: b (= 1)"
    );
    assert_eq!(t.scripts(), Vec::<String>::new());
    assert_eq!(t.read("var/lib/dpkg/status"), status);
    assert!(!t.f("var/lib/debbuild-rs").exists());
    // the installed b, kept, satisfies it
    assert_eq!(t.plan(&["a"]), ["a"]);
    t.install(&["a"]);
    assert_eq!(t.field("b", "Version").as_deref(), Some("1"));
    assert_eq!(
        t.field("a", "Status").as_deref(),
        Some("install ok installed")
    );
}

#[test]
fn upgrade_keeping_a_dependency() {
    let t = Base::new();
    t.set_installed("b", "1", &[]);
    t.stage_pkg("b", "2", &[], &o());
    t.stage_pkg("a", "1", &[], &ctl(&[("Depends", "b (>= 1)")]));
    assert_eq!(t.plan(&["a", "b"]), ["b", "a"]);
    t.install(&["a", "b"]);
    assert_eq!(t.field("b", "Version").as_deref(), Some("2"));
    let calls = t.scripts();
    let at = |s: &str| calls.iter().position(|c| c == s).unwrap();
    assert!(at("b postinst configure 1") < at("a postinst configure"));
}

#[test]
fn versioned_provides() {
    let t = Base::new();
    // staged provider
    t.stage_pkg("p", "1", &[], &ctl(&[("Provides", "foo (= 2)")]));
    t.stage_pkg("a", "1", &[], &ctl(&[("Depends", "foo (>= 2)")]));
    t.stage_pkg("a3", "1", &[], &ctl(&[("Depends", "foo (>= 3)")]));
    t.stage_pkg("u", "1", &[], &ctl(&[("Provides", "bar")]));
    t.stage_pkg("ub", "1", &[], &ctl(&[("Depends", "bar (>= 1)")]));
    assert_eq!(t.plan(&["a"]), ["p", "a"]);
    assert_eq!(
        t.try_plan(&["a3"]).unwrap_err().message(),
        "unsatisfied dependencies:\n  a3: foo (>= 3)"
    );
    // an unversioned Provides does not satisfy a versioned dependency
    assert_eq!(
        t.try_plan(&["ub"]).unwrap_err().message(),
        "unsatisfied dependencies:\n  ub: bar (>= 1)"
    );
    t.install(&["a"]);
    assert_eq!(
        t.field("a", "Status").as_deref(),
        Some("install ok installed")
    );
    // installed provider
    t.set_installed("q", "1", &[("Provides", "baz (= 2)")]);
    t.stage_pkg("c", "1", &[], &ctl(&[("Depends", "baz (>= 2)")]));
    t.stage_pkg("c3", "1", &[], &ctl(&[("Depends", "baz (>= 3)")]));
    assert_eq!(t.plan(&["c"]), ["c"]);
    assert!(
        t.try_plan(&["c3"])
            .unwrap_err()
            .message()
            .contains("c3: baz (>= 3)")
    );
    t.install(&["c"]);
    assert_eq!(
        t.field("c", "Status").as_deref(),
        Some("install ok installed")
    );
    // a staged q no longer providing baz replaces the installed provider
    t.stage_pkg("q", "2", &[], &o());
    assert!(
        t.try_plan(&["c", "q"])
            .unwrap_err()
            .message()
            .contains("c: baz (>= 2)")
    );
}

#[test]
fn dependency_on_installed_package_not_replaced() {
    let t = Base::new();
    t.set_installed("lib", "1", &[]);
    t.stage_pkg("other", "1", &[], &o());
    t.stage_pkg("a", "1", &[], &ctl(&[("Depends", "lib (>= 1), other")]));
    assert_eq!(t.plan(&["a"]), ["other", "a"]);
    t.install(&["a"]);
    assert_eq!(
        t.field("a", "Status").as_deref(),
        Some("install ok installed")
    );
    assert_eq!(t.field("lib", "Version").as_deref(), Some("1"));
}

#[test]
fn replaced_installed_alternative_falls_back_to_staged() {
    let t = Base::new();
    t.set_installed("b", "1", &[]);
    t.stage_pkg("b", "2", &[], &o());
    t.stage_pkg("c", "1", &[], &o());
    t.stage_pkg("a", "1", &[], &ctl(&[("Depends", "b (= 1) | c")]));
    assert_eq!(t.plan(&["a"]), ["a"]);
    let mut p = t.plan(&["a", "b"]);
    p.sort();
    assert_eq!(p, ["a", "b", "c"]);
}

#[test]
fn configure_checks_versions() {
    // Bypassing the plan: the installer itself refuses to configure a package whose
    // dependency the run left unsatisfied.
    let t = Base::new();
    t.set_installed("b", "1", &[]);
    t.stage_pkg("b", "2", &[], &o());
    t.stage_pkg("a", "1", &[], &ctl(&[("Depends", "b (= 1)")]));
    let mut db = Database::new(&t.root);
    db.load().unwrap();
    let staged = load_staged(&t.stage).unwrap();
    let pkgs = [&staged["b"], &staged["a"]];
    let exec = t.exec();
    let err = Installer::new(db, InstallOptions::default(), &exec)
        .install(&pkgs)
        .unwrap_err();
    assert_eq!(err.message(), "a: unsatisfied dependency: b (= 1)");
    assert_eq!(t.field("b", "Version").as_deref(), Some("2"));
    assert_eq!(
        t.field("a", "Status").as_deref(),
        Some("install ok unpacked")
    );
}

// --- Conffiles (an upgrade 1 -> 2 of /etc/c) ---

fn upgrade(t: &Base, v1: &[u8], v2: &[u8], change: impl FnOnce(&Base), opts: InstallOptions) {
    let conf = Opts {
        conffiles: &["/etc/c"],
        ..Opts::default()
    };
    t.stage_pkg("p", "1", &[("/etc/c", file(v1))], &conf);
    t.install(&["p"]);
    change(t);
    t.stage_pkg("p", "2", &[("/etc/c", file(v2))], &conf);
    t.try_install(&["p"], opts).unwrap();
    assert!(
        t.field("p", "Conffiles")
            .unwrap()
            .contains(&format!("\n /etc/c {}", md5(v2)))
    );
}

fn local(t: &Base) {
    t.write("/etc/c", b"local");
}

fn delete(t: &Base) {
    fs::remove_file(t.f("/etc/c")).unwrap();
}

#[test]
fn unmodified_changed() {
    let t = Base::new();
    upgrade(&t, b"A", b"B", |_| {}, InstallOptions::default());
    assert_eq!(t.read("/etc/c"), b"B");
    assert!(!t.f("/etc/c.dpkg-dist").exists());
}

#[test]
fn modified_unchanged() {
    let t = Base::new();
    upgrade(&t, b"A", b"A", local, InstallOptions::default());
    assert_eq!(t.read("/etc/c"), b"local");
    assert!(!t.f("/etc/c.dpkg-dist").exists());
}

#[test]
fn modified_changed() {
    let t = Base::new();
    upgrade(&t, b"A", b"B", local, InstallOptions::default());
    assert_eq!(t.read("/etc/c"), b"local");
    assert_eq!(t.read("/etc/c.dpkg-dist"), b"B");
}

#[test]
fn deleted() {
    let t = Base::new();
    upgrade(&t, b"A", b"B", delete, InstallOptions::default());
    assert!(!t.f("/etc/c").exists());
}

#[test]
fn modified_force() {
    let t = Base::new();
    upgrade(&t, b"A", b"B", local, InstallOptions::FORCE);
    assert_eq!(t.read("/etc/c"), b"B");
    assert_eq!(t.read("/etc/c.dpkg-old"), b"local");
}

#[test]
fn force_unmodified_changed() {
    let t = Base::new();
    upgrade(&t, b"A", b"B", |_| {}, InstallOptions::FORCE);
    assert_eq!(t.read("/etc/c"), b"B");
    assert!(!t.f("/etc/c.dpkg-old").exists());
}

#[test]
fn force_modified_unchanged() {
    let t = Base::new();
    upgrade(&t, b"A", b"A", local, InstallOptions::FORCE);
    assert_eq!(t.read("/etc/c"), b"local");
    assert!(!t.f("/etc/c.dpkg-old").exists());
}

#[test]
fn force_deleted() {
    let t = Base::new();
    upgrade(&t, b"A", b"B", delete, InstallOptions::FORCE);
    assert!(!t.f("/etc/c").exists());
}

#[test]
fn force_fresh_install_over_existing_file() {
    let t = Base::new();
    t.write("/etc/c", b"pre");
    let conf = Opts {
        conffiles: &["/etc/c"],
        ..Opts::default()
    };
    t.stage_pkg("p", "1", &[("/etc/c", file(b"A"))], &conf);
    t.install_force(&["p"]);
    assert_eq!(t.read("/etc/c"), b"A");
    assert_eq!(t.read("/etc/c.dpkg-old"), b"pre");
}

#[test]
fn conffiles_replace_alone() {
    let t = Base::new();
    let replace = InstallOptions {
        conffiles: Conffiles::Replace,
        ..InstallOptions::default()
    };
    upgrade(&t, b"A", b"B", local, replace);
    assert_eq!(t.read("/etc/c"), b"B");
    assert_eq!(t.read("/etc/c.dpkg-old"), b"local");
    t.scripts();
    // Unchanged packages are still skipped.
    t.try_install(&["p"], replace).unwrap();
    assert_eq!(t.scripts(), Vec::<String>::new());
}

#[test]
fn reinstall_alone() {
    let t = Base::new();
    let reinstall = InstallOptions {
        reinstall: true,
        ..InstallOptions::default()
    };
    upgrade(&t, b"A", b"B", local, reinstall);
    // Modified conffiles are kept.
    assert_eq!(t.read("/etc/c"), b"local");
    assert_eq!(t.read("/etc/c.dpkg-dist"), b"B");
    t.scripts();
    t.try_install(&["p"], reinstall).unwrap();
    assert_eq!(
        t.scripts()[..2],
        ["p prerm upgrade 2", "p preinst upgrade 2 2"]
    );
    // Other packages' files are not taken over.
    t.stage_pkg("q", "1", &[("/etc/c", file(b"q"))], &o());
    let err = t.try_install(&["q"], reinstall).unwrap_err();
    assert!(
        err.message().contains("trying to overwrite /etc/c"),
        "{err:?}"
    );
}

#[test]
fn force_overwrite_alone() {
    let t = Base::new();
    let overwrite = InstallOptions {
        force_overwrite: true,
        ..InstallOptions::default()
    };
    t.stage_pkg("a", "1", &[("/usr/share/x", file(b"a"))], &o());
    t.install(&["a"]);
    t.stage_pkg("b", "1", &[("/usr/share/x", file(b"b"))], &o());
    t.try_install(&["b"], overwrite).unwrap();
    assert_eq!(t.read("/usr/share/x"), b"b");
    assert!(!t.listed("a").contains(&"/usr/share/x".to_owned()));
    t.scripts();
    // Unchanged packages are still skipped.
    t.try_install(&["b"], overwrite).unwrap();
    assert_eq!(t.scripts(), Vec::<String>::new());
}

/// H8: the `.dpkg-old` copy of --force writes through a symlink resolved in the root.
#[test]
fn force_backup_confined() {
    for (i, abs) in [(0, true), (1, false)] {
        let t = Base::new();
        let (host, image) = sentinels(&t, &format!("old{i}"));
        upgrade(
            &t,
            b"A",
            b"B",
            |t| {
                local(t);
                if abs {
                    symlink(&host, t.f("/etc/c.dpkg-old")).unwrap();
                } else {
                    symlink(format!("../../old{i}"), t.f("/etc/c.dpkg-old")).unwrap();
                }
            },
            InstallOptions::FORCE,
        );
        assert_eq!(t.read("/etc/c"), b"B");
        assert_eq!(fs::read(&host).unwrap(), b"host", "abs={abs}");
        let image = if abs { image } else { t.f(&format!("/old{i}")) };
        assert_eq!(fs::read(&image).unwrap(), b"local", "abs={abs}");
    }
}

#[test]
fn symlink_written_through() {
    let t = Base::new();
    upgrade(
        &t,
        b"A",
        b"B",
        |t| {
            fs::rename(t.f("/etc/c"), t.f("/etc/c.real")).unwrap();
            symlink("c.real", t.f("/etc/c")).unwrap();
        },
        InstallOptions::default(),
    );
    assert!(t.f("/etc/c").is_symlink());
    assert_eq!(t.read("/etc/c.real"), b"B");
}

#[test]
fn fresh_install_over_existing_file() {
    let t = Base::new();
    t.write("/etc/c", b"pre");
    let conf = Opts {
        conffiles: &["/etc/c"],
        ..Opts::default()
    };
    t.stage_pkg("p", "1", &[("/etc/c", file(b"A"))], &conf);
    t.install(&["p"]);
    assert_eq!(t.read("/etc/c"), b"pre");
    assert_eq!(t.read("/etc/c.dpkg-dist"), b"A");
}

#[test]
fn obsolete_and_remove_on_upgrade() {
    let t = Base::new();
    let v1 = [
        ("/etc/a", file(b"a")),
        ("/etc/b", file(b"b")),
        ("/etc/r", file(b"r")),
        ("/etc/r2", file(b"r2")),
    ];
    let c1 = Opts {
        conffiles: &["/etc/a", "/etc/b", "/etc/r", "/etc/r2"],
        ..Opts::default()
    };
    t.stage_pkg("p", "1", &v1, &c1);
    t.install(&["p"]);
    t.write("/etc/r2", b"local");
    let c2 = Opts {
        conffiles: &[
            "/etc/a",
            "remove-on-upgrade /etc/r",
            "remove-on-upgrade /etc/r2",
        ],
        ..Opts::default()
    };
    t.stage_pkg("p", "2", &[("/etc/a", file(b"a"))], &c2);
    t.install(&["p"]);
    assert_eq!(t.read("/etc/b"), b"b");
    assert!(t.listed("p").contains(&"/etc/b".to_owned()));
    let conffiles = t.field("p", "Conffiles").unwrap();
    assert!(conffiles.contains(&format!("\n /etc/b {} obsolete", md5(b"b"))));
    assert!(!t.f("/etc/r").exists());
    assert!(!t.f("/etc/r2").exists());
    assert_eq!(t.read("/etc/r2.dpkg-bak"), b"local");
    assert!(!t.listed("p").contains(&"/etc/r".to_owned()));
    assert!(!conffiles.contains("/etc/r "));
    // still obsolete, still there, on the next upgrade
    let c3 = Opts {
        conffiles: &["/etc/a"],
        ..Opts::default()
    };
    t.stage_pkg("p", "3", &[("/etc/a", file(b"a"))], &c3);
    t.install(&["p"]);
    assert!(t.f("/etc/b").exists());
    assert!(
        t.field("p", "Conffiles")
            .unwrap()
            .contains(&format!("\n /etc/b {} obsolete", md5(b"b")))
    );
}

// --- Unpack ---

#[test]
fn statoverride() {
    let t = Base::new();
    fs::write(
        t.admin.join("statoverride"),
        format!(
            "tester testers 4750 /usr/bin/sw\n#{} #{} 0700 /srv/d\n",
            uid(),
            gid()
        ),
    )
    .unwrap();
    t.stage_pkg(
        "p",
        "1",
        &[("/usr/bin/sw", file(b"x")), ("/srv/d", Entry::Dir)],
        &o(),
    );
    t.install(&["p"]);
    let st = fs::metadata(t.f("/usr/bin/sw")).unwrap();
    assert_eq!((st.mode() & 0o7777, st.uid()), (0o4750, uid()));
    assert_eq!(fs::metadata(t.f("/srv/d")).unwrap().mode() & 0o7777, 0o700);
    fs::write(
        t.admin.join("statoverride"),
        "nobody root 0755 /usr/bin/sw\n",
    )
    .unwrap();
    t.stage_pkg("p", "2", &[("/usr/bin/sw", file(b"y"))], &o());
    assert!(t.install_err(&["p"]).contains("unknown user"));
}

#[test]
fn symlink_never_replaces_directory() {
    let t = Base::new();
    fs::create_dir_all(t.f("/opt/x")).unwrap();
    t.stage_pkg("p", "1", &[("/opt/x", link("nowhere"))], &o());
    t.install(&["p"]);
    assert!(t.f("/opt/x").is_dir());
    assert!(!t.f("/opt/x").is_symlink());
}

#[test]
fn generated_md5sums() {
    let t = Base::new();
    let files = [
        ("/usr/share/p/a", file(b"a")),
        ("/etc/c", file(b"c")),
        ("/usr/bin/l", link("x")),
    ];
    let opts = Opts {
        conffiles: &["/etc/c"],
        no_md5sums: true,
        ..Opts::default()
    };
    t.stage_pkg("p", "1", &files, &opts);
    t.install(&["p"]);
    assert_eq!(
        fs::read_to_string(t.admin.join("info/p.md5sums")).unwrap(),
        format!("{}  etc/c\n{}  usr/share/p/a\n", md5(b"c"), md5(b"a"))
    );
    // a shipped one is kept verbatim
    t.stage_pkg("p", "2", &[("/usr/share/p/a", file(b"a"))], &o());
    fs::write(t.pkgdir("p").join("DEBIAN/md5sums"), "shipped\n").unwrap();
    t.install(&["p"]);
    assert_eq!(
        fs::read_to_string(t.admin.join("info/p.md5sums")).unwrap(),
        "shipped\n"
    );
}

#[test]
fn recorded_data_digest() {
    let t = Base::new();
    t.stage_pkg("p", "1", &[], &o());
    fs::write(t.pkgdir("p").join("data.tar.sha256"), "abc\n").unwrap();
    let digest = load_staged(&t.stage).unwrap()["p"].digest().unwrap();
    fs::write(t.pkgdir("p").join("data.tar.sha256"), "abd\n").unwrap();
    assert_ne!(
        load_staged(&t.stage).unwrap()["p"].digest().unwrap(),
        digest
    );
}

#[test]
fn replaces() {
    let t = Base::new();
    t.stage_pkg(
        "a",
        "1",
        &[("/usr/share/x", file(b"a")), ("/usr/share/y", file(b"y"))],
        &o(),
    );
    t.install(&["a"]);
    t.stage_pkg("b", "1", &[("/usr/share/x", file(b"b"))], &o());
    assert!(
        t.install_err(&["b"])
            .contains("trying to overwrite /usr/share/x, which is also in package a")
    );
    t.stage_pkg(
        "b",
        "1",
        &[("/usr/share/x", file(b"b"))],
        &ctl(&[("Replaces", "a (<< 2)")]),
    );
    t.install(&["b"]);
    assert_eq!(t.read("/usr/share/x"), b"b");
    assert!(!t.listed("a").contains(&"/usr/share/x".to_owned()));
    assert!(t.listed("a").contains(&"/usr/share/y".to_owned()));
    assert!(t.listed("b").contains(&"/usr/share/x".to_owned()));
    let sums = fs::read_to_string(t.admin.join("info/a.md5sums")).unwrap();
    assert!(!sums.contains("usr/share/x"));
    assert!(sums.contains("usr/share/y"));
    // shared directories are fine
    assert!(t.listed("a").contains(&"/usr/share".to_owned()));
}

#[test]
fn root_confinement() {
    let t = Base::new();
    fs::create_dir(t.root.join("target")).unwrap();
    symlink("/target", t.f("/etc/abs")).unwrap();
    symlink("../../../../..", t.f("/etc/up")).unwrap();
    // (the confined() assertions are unit tests of debbuild_rs_install::confine)
    t.stage_pkg("p", "1", &[("/etc/abs/f", file(b"x"))], &o());
    t.install(&["p"]);
    assert_eq!(fs::read(t.root.join("target/f")).unwrap(), b"x");
    assert!(t.f("/etc/abs").is_symlink());
}

#[test]
fn symlinked_dir_and_file_to_dir() {
    let t = Base::new();
    fs::create_dir_all(t.root.join("usr/lib")).unwrap();
    symlink("usr/lib", t.f("/lib")).unwrap();
    // the base system owns /lib, as in a real root
    fs::write(t.admin.join("info/base.list"), "/.\n/lib\n").unwrap();
    fs::create_dir_all(t.f("/opt/d")).unwrap();
    t.write("/opt/d/keep", b"");
    t.stage_pkg(
        "p",
        "1",
        &[("/lib/foo/f", file(b"f")), ("/usr/share/fd", file(b"file"))],
        &o(),
    );
    t.install(&["p"]);
    assert!(t.f("/lib").is_symlink());
    // same file through /lib and /usr/lib: not removed as obsolete
    t.stage_pkg(
        "p",
        "2",
        &[
            ("/usr/lib/foo/f", file(b"f")),
            ("/usr/share/fd/x", file(b"x")),
            ("/opt/d", link("/usr/lib")),
        ],
        &o(),
    );
    t.install(&["p"]);
    assert_eq!(t.read("/usr/lib/foo/f"), b"f");
    assert_eq!(t.read("/usr/share/fd/x"), b"x");
    // a directory is not replaced by a symlink to a directory (policy §6.6)
    assert!(!t.f("/opt/d").is_symlink());
    assert!(t.f("/opt/d/keep").exists());
}

#[test]
fn obsolete_files_removed() {
    let t = Base::new();
    t.stage_pkg(
        "p",
        "1",
        &[
            ("/usr/share/p/a", file(b"a")),
            ("/usr/share/p/old/b", file(b"b")),
        ],
        &o(),
    );
    t.install(&["p"]);
    t.write("/usr/share/p/old/local", b"");
    t.stage_pkg("p", "2", &[("/usr/share/p/a", file(b"a"))], &o());
    t.install(&["p"]);
    assert!(!t.f("/usr/share/p/old/b").exists());
    // a non-empty directory stays
    assert!(t.f("/usr/share/p/old").is_dir());
    assert!(!t.listed("p").contains(&"/usr/share/p/old".to_owned()));
}

#[test]
fn register_keeps_other_packages_info() {
    let t = Base::new();
    fs::write(t.admin.join("info/python3.11.postinst"), "").unwrap();
    fs::write(t.admin.join("info/python3.preinst"), "").unwrap();
    t.stage_pkg("python3", "1", &[], &o());
    t.install(&["python3"]);
    assert!(t.admin.join("info/python3.11.postinst").exists());
    assert!(t.admin.join("info/python3.postinst").exists());
}

#[test]
fn interrupted_dpkg() {
    let t = Base::new();
    fs::write(t.admin.join("updates/tmp.i"), "").unwrap();
    Database::new(&t.root).check_interrupted().unwrap();
    fs::write(t.admin.join("updates/0001"), "").unwrap();
    assert!(
        Database::new(&t.root)
            .check_interrupted()
            .unwrap_err()
            .message()
            .contains("dpkg --configure -a")
    );
}

const EXE: &str = env!("CARGO_BIN_EXE_debbuild-rs");

fn cli(t: &Base, args: &[&str]) -> std::process::Output {
    Command::new(EXE)
        .arg("install")
        .arg("--root")
        .arg(&t.root)
        .arg("--stage")
        .arg(&t.stage)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn main_errors() {
    let t = Base::new();
    t.stage_pkg("a", "1", &[], &ctl(&[("Depends", "b (>= 1.0-)")]));
    t.set_installed("b", "1", &[]);
    let out = cli(&t, &["--dry-run", "a"]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("revision"), "{err}");
    assert!(err.starts_with("debbuild-rs install: error: "), "{err}");
}

// --- Sequence ---

#[test]
fn install_upgrade_classification() {
    let t = Base::new();
    t.stage_pkg("p", "1", &[], &o());
    t.install(&["p"]);
    assert_eq!(t.scripts(), ["p preinst install", "p postinst configure"]);
    assert_eq!(t.field("p", "Status").unwrap(), "install ok installed");
    // unchanged: skipped
    t.install(&["p"]);
    assert_eq!(t.scripts(), Vec::<String>::new());
    t.stage_pkg("p", "2", &[], &o());
    t.install(&["p"]);
    assert_eq!(
        t.scripts(),
        [
            "p prerm upgrade 2",
            "p preinst upgrade 1 2",
            "p postrm upgrade 2",
            "p postinst configure 1"
        ]
    );
    // left unpacked by an interrupted upgrade from 1
    t.edit_status(
        "p",
        &[
            ("Status", Some("install ok unpacked")),
            ("Config-Version", Some("1")),
        ],
    );
    t.stage_pkg("p", "3", &[], &o());
    t.install(&["p"]);
    assert_eq!(
        t.scripts(),
        [
            "p preinst upgrade 2 3",
            "p postrm upgrade 3",
            "p postinst configure 1"
        ]
    );
    assert_eq!(t.field("p", "Config-Version"), None);
    // removed, not purged
    t.edit_status(
        "p",
        &[
            ("Status", Some("deinstall ok config-files")),
            ("Config-Version", Some("3")),
        ],
    );
    t.stage_pkg("p", "4", &[], &o());
    t.install(&["p"]);
    assert_eq!(
        t.scripts(),
        ["p preinst install 3 4", "p postinst configure 3"]
    );
}

#[test]
fn config_version_while_unpacked() {
    let t = Base::new();
    t.stage_pkg("p", "1", &[], &o());
    t.install(&["p"]);
    t.stage_pkg(
        "p",
        "2",
        &[],
        &scr(&[("postinst", "[ \"$1\" = configure ] && exit 1\nexit 0\n")]),
    );
    t.scripts();
    assert!(t.try_install(&["p"], InstallOptions::default()).is_err());
    let s = t.status("p").unwrap();
    assert_eq!(
        (
            s["Status"].as_str(),
            s["Version"].as_str(),
            s.get("Config-Version").map(String::as_str)
        ),
        ("install ok half-configured", "2", Some("1"))
    );
}

#[test]
fn unpack_failure() {
    let t = Base::new();
    fs::create_dir_all(t.f("/srv/x")).unwrap();
    t.write("/srv/x/keep", b"");
    t.stage_pkg("f", "1", &[("/srv/x", file(b"file"))], &o());
    assert!(t.install_err(&["f"]).contains("non-empty directory"));
    assert_eq!(t.scripts(), ["f preinst install", "f postrm abort-install"]);
    assert_eq!(
        t.field("f", "Status").unwrap(),
        "install reinstreq half-installed"
    );
    fs::remove_file(t.f("/srv/x/keep")).unwrap();
    t.install(&["f"]);
    assert_eq!(
        t.scripts(),
        ["f preinst upgrade 1 1", "f postinst configure"]
    );
    assert_eq!(t.field("f", "Status").unwrap(), "install ok installed");
    assert_eq!(t.read("/srv/x"), b"file");
}

#[test]
fn prerm_failure_unwinds() {
    let t = Base::new();
    t.stage_pkg("f", "1", &[], &scr(&[("prerm", "exit 1\n")]));
    t.install(&["f"]);
    t.stage_pkg(
        "f",
        "2",
        &[],
        &scr(&[("prerm", "[ \"$1\" = failed-upgrade ] && exit 1\nexit 0\n")]),
    );
    t.scripts();
    assert!(t.try_install(&["f"], InstallOptions::default()).is_err());
    assert_eq!(
        t.scripts(),
        [
            "f prerm upgrade 2",
            "f prerm failed-upgrade 1 2",
            "f postinst abort-upgrade 2"
        ]
    );
    let s = t.status("f").unwrap();
    assert_eq!(
        (s["Status"].as_str(), s["Version"].as_str()),
        ("install ok installed", "1")
    );
}

#[test]
fn preinst_failure_unwinds() {
    let t = Base::new();
    t.stage_pkg("f", "1", &[], &scr(&[("preinst", "exit 1\n")]));
    assert!(t.try_install(&["f"], InstallOptions::default()).is_err());
    assert_eq!(t.scripts(), ["f preinst install", "f postrm abort-install"]);
    assert!(t.status("f").is_none());
    t.stage_pkg("f", "1", &[], &o());
    t.install(&["f"]);
    t.stage_pkg("f", "2", &[], &scr(&[("preinst", "exit 1\n")]));
    t.scripts();
    assert!(t.try_install(&["f"], InstallOptions::default()).is_err());
    assert_eq!(
        t.scripts(),
        [
            "f prerm upgrade 2",
            "f preinst upgrade 1 2",
            "f postrm abort-upgrade 1 2",
            "f postinst abort-upgrade 2"
        ]
    );
    let s = t.status("f").unwrap();
    assert_eq!(
        (s["Status"].as_str(), s["Version"].as_str()),
        ("install ok installed", "1")
    );
}

#[test]
fn failed_old_scripts() {
    let t = Base::new();
    t.stage_pkg(
        "f",
        "1",
        &[],
        &scr(&[
            ("prerm", "exit 1\n"),
            ("postrm", "[ \"$1\" = upgrade ] && exit 1\nexit 0\n"),
        ]),
    );
    t.install(&["f"]);
    t.stage_pkg("f", "2", &[], &o());
    t.scripts();
    t.install(&["f"]);
    assert_eq!(
        t.scripts(),
        [
            "f prerm upgrade 2",
            "f prerm failed-upgrade 1 2",
            "f preinst upgrade 1 2",
            "f postrm upgrade 2",
            "f postrm failed-upgrade 1 2",
            "f postinst configure 1",
        ]
    );
}

#[test]
fn pre_depends() {
    let t = Base::new();
    t.stage_pkg("c", "1", &[], &o());
    t.stage_pkg("b", "1", &[], &ctl(&[("Depends", "c"), ("Provides", "bb")]));
    t.stage_pkg("a", "1", &[], &ctl(&[("Pre-Depends", "bb")]));
    t.install(&["a"]);
    let calls = t.scripts();
    let at = |s: &str| calls.iter().position(|c| c == s).unwrap();
    assert!(at("c postinst configure") < at("b postinst configure"));
    assert!(at("b postinst configure") < at("a preinst install"));
}

/// t, interested in /usr/share/trig, installed; u shipping a file there, staged.
fn stage_trigger_pair(t: &Base, fail_in: &str) {
    let fail = format!(
        "[ \"$1\" = {fail_in} ] && [ -e \"$DEBBUILD_RS_TEST_LOG.fail\" ] && exit 1\nexit 0\n"
    );
    t.stage_pkg(
        "t",
        "1",
        &[],
        &Opts {
            triggers: Some("interest /usr/share/trig\n"),
            scripts: &[("postinst", &fail)],
            ..Opts::default()
        },
    );
    t.install(&["t"]);
    t.stage_pkg("u", "1", &[("/usr/share/trig/x", file(b"x"))], &o());
    fs::write(format!("{}.fail", t.logfile.display()), "").unwrap();
    t.scripts();
}

#[test]
fn pending_trigger_processed_when_nothing_changed() {
    let t = Base::new();
    // w's postinst fails after u activated t: the activation stays pending in t's status.
    stage_trigger_pair(&t, "never");
    let fail =
        "[ \"$1\" = configure ] && [ -e \"$DEBBUILD_RS_TEST_LOG.fail\" ] && exit 1\nexit 0\n";
    t.stage_pkg(
        "w",
        "1",
        &[],
        &Opts {
            control: &[("Depends", "u")],
            scripts: &[("postinst", fail)],
            ..Opts::default()
        },
    );
    assert!(t.try_install(&["w"], InstallOptions::default()).is_err());
    assert_eq!(
        t.field("t", "Status").unwrap(),
        "install ok triggers-pending"
    );
    fs::remove_file(format!("{}.fail", t.logfile.display())).unwrap();
    t.scripts();
    // u is unchanged: nothing to install, but the pending trigger runs
    t.install(&["u"]);
    assert_eq!(t.scripts(), ["t postinst triggered /usr/share/trig"]);
    assert_eq!(
        (
            t.field("t", "Status").unwrap(),
            t.field("t", "Triggers-Pending")
        ),
        ("install ok installed".to_owned(), None)
    );
}

#[test]
fn failed_trigger_leaves_half_configured() {
    let t = Base::new();
    stage_trigger_pair(&t, "triggered");
    assert!(t.try_install(&["u"], InstallOptions::default()).is_err());
    assert_eq!(
        (
            t.field("t", "Status").unwrap(),
            t.field("t", "Triggers-Pending"),
            t.field("t", "Config-Version")
        ),
        (
            "install ok half-configured".to_owned(),
            None,
            Some("1".to_owned())
        )
    );
    fs::remove_file(format!("{}.fail", t.logfile.display())).unwrap();
    t.scripts();
    // t is unchanged: configured again, as dpkg --configure -a does
    t.install(&["t"]);
    assert_eq!(t.scripts(), ["t postinst configure 1"]);
    assert_eq!(
        (
            t.field("t", "Status").unwrap(),
            t.field("t", "Config-Version")
        ),
        ("install ok installed".to_owned(), None)
    );
}

/// p 1 with /srv/p holding `content`, its postinst configure failing while the
/// `.fail` sentinel next to the script log exists, if `failing`.
fn stage_content(t: &Base, content: &[u8], failing: bool) {
    let fail =
        "[ \"$1\" = configure ] && [ -e \"$DEBBUILD_RS_TEST_LOG.fail\" ] && exit 1\nexit 0\n";
    let scripts: &[(&str, &str)] = if failing { &[("postinst", fail)] } else { &[] };
    t.stage_pkg("p", "1", &[("/srv/p", file(content))], &scr(scripts));
}

fn digest_of(t: &Base) -> Option<String> {
    fs::read_to_string(t.f("/var/lib/debbuild-rs/p.sha256")).ok()
}

/// The recorded digest is the one of the files on disk: a failed configure of other
/// content of the same version leaves that content's digest, and going back to the
/// installed content reinstalls it.
#[test]
fn digest_recorded_at_unpack() {
    let t = Base::new();
    stage_content(&t, b"A", false);
    t.install(&["p"]);
    let a = digest_of(&t).unwrap();
    // B, same version: unpacked, its configure fails
    stage_content(&t, b"B", true);
    fs::write(format!("{}.fail", t.logfile.display()), "").unwrap();
    t.scripts();
    assert!(t.try_install(&["p"], InstallOptions::default()).is_err());
    assert_eq!(
        t.field("p", "Status").unwrap(),
        "install ok half-configured"
    );
    assert_eq!(t.read("/srv/p"), b"B");
    let b = digest_of(&t).unwrap();
    assert_ne!(a, b);
    // back to A: B's files are on disk, A is unpacked again
    stage_content(&t, b"A", false);
    t.scripts();
    let out = cli(&t, &["--dry-run", "p"]);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "p reinstall 1 (requested)\n"
    );
    t.install(&["p"]);
    assert_eq!(
        t.scripts(),
        [
            "p prerm upgrade 1",
            "p preinst upgrade 1 1",
            "p postrm upgrade 1",
            "p postinst configure 1"
        ]
    );
    assert_eq!(t.read("/srv/p"), b"A");
    assert_eq!(t.field("p", "Status").unwrap(), "install ok installed");
    assert_eq!(digest_of(&t).unwrap(), a);
    // B again, configure failing then succeeding: B is only configured again
    stage_content(&t, b"B", true);
    assert!(t.try_install(&["p"], InstallOptions::default()).is_err());
    fs::remove_file(format!("{}.fail", t.logfile.display())).unwrap();
    t.scripts();
    let out = cli(&t, &["--dry-run", "p"]);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "p configure 1 (requested)\n"
    );
    t.install(&["p"]);
    assert_eq!(t.scripts(), ["p postinst configure 1"]);
    assert_eq!(t.read("/srv/p"), b"B");
    assert_eq!(digest_of(&t).unwrap(), b);
}

/// An unpack that does not complete leaves no digest; one that never starts (preinst
/// failing, unwound) keeps the one of the files still on disk.
#[test]
fn digest_on_unpack_failures() {
    let t = Base::new();
    stage_content(&t, b"A", false);
    t.install(&["p"]);
    let a = digest_of(&t).unwrap();
    // preinst fails and is unwound: A is still installed, and unchanged
    t.stage_pkg(
        "p",
        "1",
        &[("/srv/p", file(b"B"))],
        &scr(&[("preinst", "exit 1\n")]),
    );
    assert!(t.try_install(&["p"], InstallOptions::default()).is_err());
    assert_eq!(t.field("p", "Status").unwrap(), "install ok installed");
    assert_eq!(digest_of(&t).unwrap(), a);
    stage_content(&t, b"A", false);
    t.scripts();
    t.install(&["p"]);
    assert_eq!(t.scripts(), Vec::<String>::new());
    // the unpack fails: the files are mixed, half-installed, no digest
    fs::create_dir_all(t.f("/srv/q")).unwrap();
    t.write("/srv/q/keep", b"");
    t.stage_pkg(
        "p",
        "1",
        &[("/srv/p", file(b"B")), ("/srv/q", file(b"q"))],
        &o(),
    );
    assert!(t.install_err(&["p"]).contains("non-empty directory"));
    assert_eq!(
        t.field("p", "Status").unwrap(),
        "install reinstreq half-installed"
    );
    assert_eq!(digest_of(&t), None);
    // back to A: unpacked again
    stage_content(&t, b"A", false);
    t.scripts();
    t.install(&["p"]);
    assert!(t.scripts().contains(&"p preinst upgrade 1 1".to_owned()));
    assert_eq!(t.read("/srv/p"), b"A");
    assert_eq!(digest_of(&t).unwrap(), a);
    // old postrm upgrade and new postrm failed-upgrade fail after the unpack:
    // half-installed, no digest
    t.stage_pkg(
        "p",
        "1",
        &[("/srv/p", file(b"A"))],
        &scr(&[("postrm", "exit 1\n")]),
    );
    t.install(&["p"]);
    let c = digest_of(&t).unwrap();
    t.stage_pkg(
        "p",
        "1",
        &[("/srv/p", file(b"B"))],
        &scr(&[("postrm", "exit 1\n")]),
    );
    assert!(t.try_install(&["p"], InstallOptions::default()).is_err());
    assert_eq!(
        t.field("p", "Status").unwrap(),
        "install reinstreq half-installed"
    );
    assert_eq!(digest_of(&t), None);
    assert_ne!(c, a);
}

/// A failed postinst triggered leaves the package half-configured with the digest of
/// its files, which did not change: an unchanged rerun configures it.
#[test]
fn digest_kept_by_failed_trigger() {
    let t = Base::new();
    stage_trigger_pair(&t, "triggered");
    let state = t.f("/var/lib/debbuild-rs/t.sha256");
    let before = fs::read(&state).unwrap();
    assert!(t.try_install(&["u"], InstallOptions::default()).is_err());
    assert_eq!(
        t.field("t", "Status").unwrap(),
        "install ok half-configured"
    );
    assert_eq!(fs::read(&state).unwrap(), before);
}

#[test]
fn triggers() {
    let t = Base::new();
    t.stage_pkg(
        "t",
        "1",
        &[],
        &Opts {
            triggers: Some("interest /usr/share/trig\ninterest mytrig\n"),
            ..Opts::default()
        },
    );
    t.install(&["t"]);
    let unincorp = "printf \"mytrig -\\n\" >>\"$DEBBUILD_RS_TEST_ADMINDIR/triggers/Unincorp\"\n";
    t.stage_pkg(
        "u",
        "1",
        &[("/usr/share/trig/x", file(b"x"))],
        &scr(&[("postinst", unincorp)]),
    );
    t.scripts();
    t.install(&["u"]);
    assert_eq!(
        t.scripts(),
        [
            "u preinst install",
            "u postinst configure",
            "t postinst triggered /usr/share/trig mytrig"
        ]
    );
    assert_eq!(
        fs::read_to_string(t.admin.join("triggers/Unincorp")).unwrap(),
        ""
    );
    // removing an obsolete path activates the file trigger too
    t.stage_pkg("u", "2", &[], &o());
    t.install(&["u"]);
    assert!(
        t.scripts()
            .contains(&"t postinst triggered /usr/share/trig".to_owned())
    );
    // an activation is saved at once: a later failure leaves it pending, for dpkg --configure -a
    t.stage_pkg("u", "4", &[("/usr/share/trig/z", file(b"z"))], &o());
    t.stage_pkg(
        "w",
        "1",
        &[],
        &Opts {
            control: &[("Depends", "u (>= 4)")],
            scripts: &[("postinst", "exit 1\n")],
            ..Opts::default()
        },
    );
    assert!(t.try_install(&["w"], InstallOptions::default()).is_err());
    assert_eq!(
        (
            t.field("t", "Status").unwrap(),
            t.field("t", "Triggers-Pending")
        ),
        (
            "install ok triggers-pending".to_owned(),
            Some("/usr/share/trig".to_owned())
        )
    );
    assert_eq!(t.field("u", "Status").unwrap(), "install ok installed");
    assert!(t.root.join("var/lib/debbuild-rs/u.sha256").exists());
    // w's files are unpacked, its digest recorded
    assert_eq!(
        t.field("w", "Status").unwrap(),
        "install ok half-configured"
    );
    assert!(t.root.join("var/lib/debbuild-rs/w.sha256").exists());
    // the next run processes it
    t.stage_pkg("w", "1", &[], &ctl(&[("Depends", "u (>= 4)")]));
    t.scripts();
    t.install(&["w"]);
    assert!(
        t.scripts()
            .contains(&"t postinst triggered /usr/share/trig".to_owned())
    );
    assert_eq!(t.field("t", "Status").unwrap(), "install ok installed");
    // an unpacked package does not process triggers
    t.edit_status("t", &[("Status", Some("install ok unpacked"))]);
    t.stage_pkg("u", "3", &[("/usr/share/trig/y", file(b"y"))], &o());
    t.install(&["u"]);
    assert!(
        !t.scripts()
            .contains(&"t postinst triggered /usr/share/trig".to_owned())
    );
}

// --- Additions ---

#[test]
fn cli_usage() {
    let out = Command::new(EXE)
        .args(["install", "--stage", "/x"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(EXE).args(["install", "p"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(EXE)
        .args(["install", "--help"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    // abbreviations, as argparse takes them
    let t = Base::new();
    t.stage_pkg("p", "1", &[], &o());
    let out = Command::new(EXE)
        .arg("install")
        .arg("--ro")
        .arg(&t.root)
        .arg("--st")
        .arg(&t.stage)
        .args(["--dry", "p"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}

#[test]
fn dry_run_output() {
    let t = Base::new();
    t.stage_pkg("b", "1.0-1", &[], &o());
    t.stage_pkg("a", "2", &[], &ctl(&[("Depends", "b")]));
    let dry = |args: &[&str]| {
        let out = cli(&t, args);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        String::from_utf8(out.stdout).unwrap()
    };
    assert_eq!(
        dry(&["--dry-run", "a"]),
        "b install 1.0-1 (needed by a (Depends: b))\na install 2 (requested)\n"
    );
    assert!(t.status("a").is_none());
    t.install(&["a"]);
    t.scripts();
    // What the installation then does is what the dry run said.
    assert_eq!(
        dry(&["--dry-run", "a", "b"]),
        "b skip 1.0-1 (requested, needed by a (Depends: b))\na skip 2 (requested)\n"
    );
    t.install(&["a", "b"]);
    assert_eq!(t.scripts(), Vec::<String>::new());
    assert_eq!(
        dry(&["--dry-run", "--force", "b"]),
        "b reinstall 1.0-1 (requested)\n"
    );
    assert_eq!(
        dry(&["--dry-run", "--reinstall", "b"]),
        "b reinstall 1.0-1 (requested)\n"
    );
    assert_eq!(
        dry(&["--dry-run", "--conffiles=replace", "--force-overwrite", "b"]),
        "b skip 1.0-1 (requested)\n"
    );
    // --force is all of them.
    for bad in [&["--force", "--conffiles=keep"][..], &["--conffiles=new"]] {
        let args = [bad, &["--dry-run", "b"]].concat();
        assert_eq!(cli(&t, &args).status.code(), Some(2), "{bad:?}");
    }
    t.stage_pkg("a", "3", &[], &ctl(&[("Pre-Depends", "b (<< 1)")]));
    t.stage_pkg("b", "0.9", &[], &o());
    assert_eq!(
        dry(&["--dry-run", "a"]),
        "b downgrade 1.0-1 -> 0.9 (needed by a (Pre-Depends: b (<< 1)))\n\
         a upgrade 2 -> 3 (requested)\n"
    );
    // A changed package at the same version is reinstalled.
    t.stage_pkg("b", "1.0-1", &[("/usr/share/b", file(b"b"))], &o());
    assert_eq!(dry(&["--dry-run", "b"]), "b reinstall 1.0-1 (requested)\n");
    // An unchanged half-configured one is configured again.
    t.stage_pkg("b", "1.0-1", &[], &o());
    t.stage_pkg("a", "2", &[], &ctl(&[("Depends", "b")]));
    t.edit_status(
        "a",
        &[
            ("Status", Some("install ok half-configured")),
            ("Config-Version", Some("2")),
        ],
    );
    assert_eq!(
        dry(&["--dry-run", "a"]),
        "b skip 1.0-1 (needed by a (Depends: b))\na configure 2 (requested)\n"
    );
    t.install(&["a"]);
    assert_eq!(t.scripts(), ["a postinst configure 2"]);
    // Only removed: installed again.
    t.edit_status("a", &[("Status", Some("deinstall ok config-files"))]);
    t.stage_pkg("a", "3", &[], &ctl(&[("Depends", "b (>= 1) | c")]));
    assert_eq!(
        dry(&["--dry-run", "--json", "a"]),
        concat!(
            r#"{"packages":[{"name":"b","action":"skip","state":"installed","#,
            r#""old_version":"1.0-1","new_version":"1.0-1","reasons":[{"kind":"dependency","#,
            r#""by":"a","field":"Depends","relation":"b (>= 1) | c"}]},"#,
            r#"{"name":"a","action":"install","state":"config-files","old_version":null,"#,
            r#""new_version":"3","reasons":[{"kind":"requested"}]}]}"#,
            "\n"
        )
    );
    // --json is an option of --dry-run.
    assert_eq!(cli(&t, &["--json", "a"]).status.code(), Some(2));
}

/// A mode-only change of a control file is a change.
#[test]
fn control_mode_change() {
    let t = Base::new();
    t.stage_pkg("p", "1", &[], &o());
    t.install(&["p"]);
    t.scripts();
    let postinst = t.pkgdir("p").join("DEBIAN/postinst");
    fs::set_permissions(&postinst, fs::Permissions::from_mode(0o700)).unwrap();
    let out = cli(&t, &["--dry-run", "p"]);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "p reinstall 1 (requested)\n"
    );
    t.install(&["p"]);
    assert_eq!(
        t.scripts()[..2],
        ["p prerm upgrade 1", "p preinst upgrade 1 1"]
    );
    let info = t.f("/var/lib/dpkg/info/p.postinst");
    assert_eq!(
        fs::metadata(info).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    t.install(&["p"]);
    assert_eq!(t.scripts(), Vec::<String>::new());
}

#[test]
fn install_through_cli() {
    let t = Base::new();
    t.stage_pkg("p", "1", &[("/usr/share/p/a", file(b"a"))], &o());
    // root=/... with chroot needs privileges: run the binary through its own seam-free
    // path only where it does not matter, i.e. a package without scripts.
    for s in ["preinst", "postinst", "prerm", "postrm"] {
        fs::remove_file(t.pkgdir("p").join("DEBIAN").join(s)).unwrap();
    }
    let out = cli(&t, &["p"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "debbuild-rs install: installing: p\ndebbuild-rs install: p: unpacking 1\n"
    );
    assert_eq!(t.read("/usr/share/p/a"), b"a");
    let out = cli(&t, &["p"]);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "debbuild-rs install: p 1: unchanged, skipping\ndebbuild-rs install: all packages up to date\n"
    );
}

#[test]
fn hardlink_member() {
    let t = Base::new();
    t.stage_pkg(
        "p",
        "1",
        &[
            ("/usr/share/p/a", file(b"a")),
            ("/usr/share/p/b", Entry::Hardlink("/usr/share/p/a".into())),
        ],
        &o(),
    );
    t.install(&["p"]);
    let a = fs::metadata(t.f("/usr/share/p/a")).unwrap();
    let b = fs::metadata(t.f("/usr/share/p/b")).unwrap();
    assert_eq!((a.dev(), a.ino()), (b.dev(), b.ino()));
    assert_eq!(a.nlink(), 2);
    assert!(t.listed("p").contains(&"/usr/share/p/b".to_owned()));
    // the md5sums the fixture ships cover a only: no metadata or digest of its own
    assert_eq!(a.mode() & 0o7777, 0o644);
}

#[test]
fn hardlink_member_to_symlink() {
    // as Python 3.11's os.link (link(2)): the symlink itself is linked
    let t = Base::new();
    t.stage_pkg(
        "p",
        "1",
        &[
            ("/usr/share/p/a", file(b"a")),
            ("/usr/share/p/l", link("a")),
            ("/usr/share/p/m", Entry::Hardlink("/usr/share/p/l".into())),
        ],
        &o(),
    );
    t.install(&["p"]);
    let l = fs::symlink_metadata(t.f("/usr/share/p/l")).unwrap();
    let m = fs::symlink_metadata(t.f("/usr/share/p/m")).unwrap();
    assert!(m.file_type().is_symlink());
    assert_eq!(l.ino(), m.ino());
    assert_eq!(fs::metadata(t.f("/usr/share/p/a")).unwrap().nlink(), 1);
}

/// A file next to the root, `host`, and the file at the same path inside the root,
/// `image`: what a symlink to that absolute path reaches for the OS and in the root.
/// `ROOT/<name>` is what `../` up to the root and beyond, then `<name>`, reaches in it.
fn sentinels(t: &Base, name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let host = t.root.parent().unwrap().join(name);
    let image = t.root.join(host.strip_prefix("/").unwrap());
    fs::create_dir_all(image.parent().unwrap()).unwrap();
    fs::write(&host, "host").unwrap();
    fs::write(&image, "image").unwrap();
    fs::write(t.root.join(name), "image").unwrap();
    (host, image)
}

/// A hard link to a symlink out of the root links the symlink, never the host file it
/// points to (absolute and upward-relative).
#[test]
fn hardlink_member_to_escaping_symlink() {
    let t = Base::new();
    let (host, image) = sentinels(&t, "s");
    fs::create_dir_all(t.f("/usr/share/p")).unwrap();
    symlink(&host, t.f("/usr/share/p/abs")).unwrap();
    // root/usr/share/p/../../../.. is the root's parent for the OS
    symlink("../../../../s", t.f("/usr/share/p/up")).unwrap();
    t.stage_pkg(
        "p",
        "1",
        &[
            ("/usr/share/p/m", Entry::Hardlink("/usr/share/p/abs".into())),
            ("/usr/share/p/n", Entry::Hardlink("/usr/share/p/up".into())),
        ],
        &Opts {
            no_md5sums: true,
            ..Opts::default()
        },
    );
    t.install(&["p"]);
    for (m, l) in [
        ("/usr/share/p/m", "/usr/share/p/abs"),
        ("/usr/share/p/n", "/usr/share/p/up"),
    ] {
        let lm = fs::symlink_metadata(t.f(l)).unwrap();
        let mm = fs::symlink_metadata(t.f(m)).unwrap();
        assert!(mm.file_type().is_symlink(), "{m}");
        assert_eq!(mm.ino(), lm.ino(), "{m}");
    }
    for f in [host, image, t.f("/s")] {
        assert_eq!(fs::metadata(&f).unwrap().nlink(), 1, "{}", f.display());
    }
}

#[test]
fn tar_types_regular() {
    // K2: '\0' and '7' members are regular files
    let t = Base::new();
    t.stage_pkg("p", "1", &[("/a", file(b"a")), ("/b", file(b"b"))], &o());
    let data = fs::read(t.pkgdir("p").join("data.tar")).unwrap();
    let mut patched = data.clone();
    let mut ar = tar::Archive::new(data.as_slice());
    for e in ar.entries().unwrap() {
        let e = e.unwrap();
        let off = usize::try_from(e.raw_header_position()).unwrap();
        let name = e.path_bytes().into_owned();
        let kind = match name.as_slice() {
            b"./a" => 0u8,
            b"./b" => b'7',
            _ => continue,
        };
        patched[off + 156] = kind;
        let mut h = tar::Header::from_byte_slice(&patched[off..off + 512]).clone();
        h.set_cksum();
        patched[off..off + 512].copy_from_slice(h.as_bytes());
    }
    fs::write(t.pkgdir("p").join("data.tar"), patched).unwrap();
    t.install(&["p"]);
    assert_eq!(t.read("/a"), b"a");
    assert_eq!(t.read("/b"), b"b");
}

fn patch_type(t: &Base, pkg: &str, member: &[u8], kind: u8) {
    let path = t.pkgdir(pkg).join("data.tar");
    let data = fs::read(&path).unwrap();
    let mut patched = data.clone();
    let mut ar = tar::Archive::new(data.as_slice());
    for e in ar.entries().unwrap() {
        let e = e.unwrap();
        if e.path_bytes().as_ref() == member {
            let off = usize::try_from(e.raw_header_position()).unwrap();
            patched[off + 156] = kind;
            let mut h = tar::Header::from_byte_slice(&patched[off..off + 512]).clone();
            if kind == b'S' {
                // a sparse file without holes
                let size = h.entry_size().unwrap();
                h.as_gnu_mut().unwrap().set_real_size(size);
            }
            h.set_cksum();
            patched[off..off + 512].copy_from_slice(h.as_bytes());
        }
    }
    fs::write(&path, patched).unwrap();
}

/// H6: a GNU sparse member is rejected, not extracted.
#[test]
fn sparse_member_rejected() {
    let t = Base::new();
    t.stage_pkg("p", "1", &[("/usr/share/p/s", file(b""))], &o());
    patch_type(&t, "p", b"./usr/share/p/s", b'S');
    let err = t.install_err(&["p"]);
    assert_eq!(err, "p: /usr/share/p/s: unsupported file type in archive");
    assert!(!t.f("/usr/share/p/s").exists());
    assert_eq!(t.scripts(), ["p preinst install", "p postrm abort-install"]);
}

/// Cut data.tar of `pkg` `keep` bytes into the data of its member `member`.
fn truncate_in(t: &Base, pkg: &str, member: &[u8], keep: u64) {
    let path = t.pkgdir(pkg).join("data.tar");
    let data = fs::read(&path).unwrap();
    let mut ar = tar::Archive::new(data.as_slice());
    let start = ar
        .entries()
        .unwrap()
        .map(Result::unwrap)
        .find(|e| e.path_bytes().as_ref() == member)
        .unwrap()
        .raw_file_position();
    fs::write(&path, &data[..usize::try_from(start + keep).unwrap()]).unwrap();
}

/// A truncated member fails the unpack before it replaces the installed file, as with
/// Python's tarfile: the package is left half-installed, the file as it was.
#[test]
fn truncated_member_keeps_destination() {
    for conffile in [false, true] {
        let t = Base::new();
        let opts = Opts {
            conffiles: if conffile { &["/etc/c"] } else { &[] },
            ..Opts::default()
        };
        t.stage_pkg("p", "1", &[("/etc/c", file(b"old"))], &opts);
        t.install(&["p"]);
        t.scripts();
        t.stage_pkg("p", "2", &[("/etc/c", file(&[b'n'; 4096]))], &opts);
        truncate_in(&t, "p", b"./etc/c", 1000);
        let err = t.install_err(&["p"]);
        assert_eq!(
            String::from_utf8_lossy(&t.read("/etc/c")),
            "old",
            "conffile={conffile}"
        );
        assert_eq!(err, "unexpected end of data");
        // nothing of the short read written, as with Python's tarfile
        let tmp = fs::read(t.f("/etc/c.dpkg-new")).ok();
        assert_eq!(tmp, (!conffile).then(Vec::new), "conffile={conffile}");
        assert_eq!(
            t.scripts(),
            [
                "p prerm upgrade 2",
                "p preinst upgrade 1 2",
                "p postrm abort-upgrade 1 2",
                "p postinst abort-upgrade 2"
            ]
        );
        assert_eq!(
            t.field("p", "Status").unwrap(),
            "install reinstreq half-installed"
        );
    }
}

/// H2: the maintainer scripts get dpkg's variables and `DPKG_FRONTEND_LOCKED`.
#[test]
fn script_env() {
    let t = Base::new();
    let dump = "env | grep -E '^DPKG_' | sort >\"$DEBBUILD_RS_TEST_LOG.env\"\n";
    t.set_installed("dpkg", "1.21.23", &[]);
    t.stage_pkg("p", "1", &[], &scr(&[("postinst", dump)]));
    t.install(&["p"]);
    assert_eq!(
        fs::read_to_string(format!("{}.env", t.logfile.display())).unwrap(),
        "DPKG_ADMINDIR=/var/lib/dpkg\nDPKG_FORCE=security-mac,downgrade\nDPKG_FRONTEND_LOCKED=1\n\
         DPKG_MAINTSCRIPT_ARCH=all\nDPKG_MAINTSCRIPT_DEBUG=0\nDPKG_MAINTSCRIPT_NAME=postinst\n\
         DPKG_MAINTSCRIPT_PACKAGE=p\nDPKG_MAINTSCRIPT_PACKAGE_REFCOUNT=1\nDPKG_ROOT=\n\
         DPKG_RUNNING_VERSION=1.21.23\n"
    );
    t.stage_pkg("p", "2", &[], &scr(&[("postinst", dump)]));
    t.install_force(&["p"]);
    assert!(
        fs::read_to_string(format!("{}.env", t.logfile.display()))
            .unwrap()
            .contains("DPKG_FORCE=security-mac,downgrade,overwrite,confnew\n")
    );
}

/// H3: var/lib/debbuild-rs is resolved inside the root.
#[test]
fn statedir_confined() {
    let t = Base::new();
    let elsewhere = t.tmp.path().join("elsewhere");
    fs::create_dir_all(elsewhere.join("lib/debbuild-rs")).unwrap();
    fs::create_dir_all(t.root.join("realvar/lib")).unwrap();
    fs::rename(t.root.join("var/lib/dpkg"), t.root.join("realvar/lib/dpkg")).unwrap();
    fs::remove_dir_all(t.root.join("var")).unwrap();
    // absolute: outside the root for the OS, root/realvar inside it
    symlink("/realvar", t.root.join("var")).unwrap();
    t.stage_pkg("p", "1", &[], &o());
    let exec = t.exec();
    let mut db = Database::new(&t.root);
    db.load().unwrap();
    let staged = load_staged(&t.stage).unwrap();
    let pkgs = debbuild_rs_install::plan(&db, &staged, &["p".to_owned()])
        .unwrap()
        .packages;
    debbuild_rs_install::Installer::new(db, InstallOptions::default(), &exec)
        .install(&pkgs)
        .unwrap();
    assert!(t.root.join("realvar/lib/debbuild-rs/p.sha256").exists());
    assert!(!std::path::Path::new("/realvar").exists());
}

/// H3: the digest of the unchanged check is read inside the root.
#[test]
fn statedir_digest_confined() {
    for in_root_right in [true, false] {
        let t = Base::new();
        t.stage_pkg("p", "1", &[], &o());
        t.install(&["p"]);
        t.scripts();
        let state = t.f("/var/lib/debbuild-rs/p.sha256");
        let right = fs::read(&state).unwrap();
        let (host, image) = sentinels(&t, "p.sha256");
        let (inside, outside) = if in_root_right {
            (right.clone(), b"0\n".to_vec())
        } else {
            (b"0\n".to_vec(), right.clone())
        };
        fs::write(&image, inside).unwrap();
        fs::write(&host, &outside).unwrap();
        fs::remove_file(&state).unwrap();
        symlink(&host, &state).unwrap();
        t.install(&["p"]);
        if in_root_right {
            assert_eq!(t.scripts(), Vec::<String>::new());
        } else {
            assert_eq!(
                t.scripts(),
                [
                    "p prerm upgrade 1",
                    "p preinst upgrade 1 1",
                    "p postrm upgrade 1",
                    "p postinst configure 1"
                ]
            );
        }
        // written in the root too
        assert_eq!(fs::read(&host).unwrap(), outside);
        assert_eq!(fs::read(&image).unwrap(), right);
    }
}

/// H4: paths below var/lib/dpkg are resolved inside the root.
#[test]
fn admindir_children_confined() {
    let t = Base::new();
    fs::create_dir_all(t.root.join("x")).unwrap();
    fs::remove_dir(t.admin.join("info")).unwrap();
    symlink("/x", t.admin.join("info")).unwrap();
    t.stage_pkg("p", "1", &[("/usr/share/p/a", file(b"a"))], &o());
    t.install(&["p"]);
    assert!(t.root.join("x/p.list").exists());
    assert!(t.root.join("x/p.postinst").exists());
}

/// H5: only dpkg's directives, two words each.
#[test]
fn triggers_unknown_directive() {
    let t = Base::new();
    let opts = Opts {
        triggers: Some("# c\n\ninterest-noawait /x # c\ninterestfoo x\n"),
        ..Opts::default()
    };
    t.stage_pkg("p", "1", &[], &opts);
    assert_eq!(
        t.install_err(&["p"]),
        "p: DEBIAN/triggers: unknown directive 'interestfoo'"
    );
    // nothing written
    assert!(t.status("p").is_none());
    assert!(!t.root.join("var/lib/debbuild-rs").exists());
    assert_eq!(t.scripts(), Vec::<String>::new());
}

#[test]
fn triggers_bad_arity() {
    let t = Base::new();
    let opts = Opts {
        triggers: Some("activate a b\n"),
        ..Opts::default()
    };
    t.stage_pkg("p", "1", &[], &opts);
    assert_eq!(
        t.install_err(&["p"]),
        "p: DEBIAN/triggers: malformed line 'activate a b'"
    );
    let opts = Opts {
        triggers: Some("activate\n"),
        ..Opts::default()
    };
    t.stage_pkg("p", "1", &[], &opts);
    assert_eq!(
        t.install_err(&["p"]),
        "p: DEBIAN/triggers: malformed line 'activate'"
    );
    assert!(t.status("p").is_none());
}

/// H7: data.tar must match data.tar.sha256 before anything is written.
#[test]
fn data_tar_digest_mismatch() {
    let t = Base::new();
    t.stage_pkg("p", "1", &[("/usr/share/p/a", file(b"a"))], &o());
    fs::write(
        t.pkgdir("p").join("data.tar.sha256"),
        format!("{}\n", "0".repeat(64)),
    )
    .unwrap();
    assert_eq!(
        t.install_err(&["p"]),
        "p: staged tree changed while installing, rerun"
    );
    assert!(t.status("p").is_none());
    assert_eq!(t.scripts(), Vec::<String>::new());
    // the right digest installs
    let sum = debbuild_rs_build::builddeb::sha256_file(&t.pkgdir("p").join("data.tar")).unwrap();
    fs::write(t.pkgdir("p").join("data.tar.sha256"), format!("{sum}\n")).unwrap();
    t.install(&["p"]);
}

/// H7: the tree is read once; a publish after the load leaves the installer on the old
/// generation.
#[test]
fn stage_replaced_after_load() {
    let t = Base::new();
    t.stage_pkg("p", "1", &[("/usr/share/p/a", file(b"old"))], &o());
    let staged = load_staged(&t.stage).unwrap();
    // a stage run publishes a new generation: rm -rf + mv
    let new = t.tmp.path().join("new");
    fs::rename(t.pkgdir("p"), &new).unwrap();
    t.stage_pkg("p", "2", &[("/usr/share/p/a", file(b"new"))], &o());
    fs::remove_dir_all(&new).unwrap();
    let mut db = Database::new(&t.root);
    db.load().unwrap();
    let pkgs = debbuild_rs_install::plan(&db, &staged, &["p".to_owned()])
        .unwrap()
        .packages;
    let exec = t.exec();
    debbuild_rs_install::Installer::new(db, InstallOptions::default(), &exec)
        .install(&pkgs)
        .unwrap();
    assert_eq!(t.read("/usr/share/p/a"), b"old");
    assert_eq!(t.field("p", "Version").unwrap(), "1");
}

/// What a stage run does to a package directory while it is being loaded.
#[derive(Clone, Copy, Debug)]
enum Publish {
    /// rm -rf + mv: the old tree is gone, the new one in its place.
    Replace,
    /// The old tree moved away, still whole.
    MoveAway,
}

/// Stage p, with its data.tar.sha256 as debbuild-rs stage writes it.
fn stage_with_sha256(t: &Base, version: &str, content: &[u8]) {
    t.stage_pkg("p", version, &[("/usr/share/p/a", file(content))], &o());
    let sum = debbuild_rs_build::builddeb::sha256_file(&t.pkgdir("p").join("data.tar")).unwrap();
    fs::write(t.pkgdir("p").join("data.tar.sha256"), format!("{sum}\n")).unwrap();
}

/// Load the stage while `publish` happens at `point` to p (staged as version 1, version
/// 2 ready), then install p if it loaded.
fn load_during(point: LoadPoint, publish: Publish) -> (Base, std::result::Result<(), String>) {
    let t = Base::new();
    stage_with_sha256(&t, "2", b"new");
    let next = t.tmp.path().join("next");
    fs::rename(t.pkgdir("p"), &next).unwrap();
    stage_with_sha256(&t, "1", b"old");
    let (dir, away) = (t.pkgdir("p"), t.tmp.path().join("away"));
    let mut done = false;
    hooks::set(move |at, path| {
        if done || at != point || path != dir {
            return;
        }
        done = true;
        fs::rename(&dir, &away).unwrap();
        if let Publish::Replace = publish {
            fs::rename(&next, &dir).unwrap();
            fs::remove_dir_all(&away).unwrap();
        }
    });
    let staged = load_staged(&t.stage);
    hooks::clear();
    let res = staged
        .map_err(|e| e.message().to_owned())
        .and_then(|staged| {
            let mut db = Database::new(&t.root);
            db.load().unwrap();
            let pkgs = debbuild_rs_install::plan(&db, &staged, &["p".to_owned()])
                .unwrap()
                .packages;
            let exec = t.exec();
            debbuild_rs_install::Installer::new(db, InstallOptions::default(), &exec)
                .install(&pkgs)
                .map_err(|e| e.message().to_owned())
        });
    (t, res)
}

/// H7: a publish while the tree is loaded installs one generation, or none and says
/// the tree changed.
#[test]
fn stage_replaced_during_load() {
    let changed = Err("p: staged tree changed while installing, rerun".to_owned());
    // (one Base at a time: each holds the tests' lock)
    let installed = |point, publish, version: &str, content: &[u8]| {
        let (t, res) = load_during(point, publish);
        assert_eq!(res, Ok(()), "{point:?} {publish:?}");
        assert_eq!(t.field("p", "Version").unwrap(), version);
        assert_eq!(t.read("/usr/share/p/a"), content);
    };
    let refused = |point, publish| {
        let (t, res) = load_during(point, publish);
        assert_eq!(res, changed, "{point:?} {publish:?}");
        assert!(t.status("p").is_none(), "{point:?} {publish:?}");
        assert_eq!(t.scripts(), Vec::<String>::new());
        assert!(!t.f("/usr/share/p").exists());
    };
    // between the scan and the open: the directory gone, or the new tree read
    refused(LoadPoint::Scanned, Publish::MoveAway);
    installed(LoadPoint::Scanned, Publish::Replace, "2", b"new");
    // between the listing of DEBIAN/ and the open of its entries: the old tree, through
    // the open directory, or the changed error once it is removed
    installed(LoadPoint::Listed, Publish::MoveAway, "1", b"old");
    refused(LoadPoint::Listed, Publish::Replace);
    // between DEBIAN/* and data.tar: the same, reported before anything is written
    installed(LoadPoint::Read, Publish::MoveAway, "1", b"old");
    refused(LoadPoint::Read, Publish::Replace);
}

/// H7: a staged tree without data.tar is reported as changed when it is needed.
#[test]
fn stage_without_data_tar() {
    let t = Base::new();
    t.stage_pkg("q", "1", &[], &o());
    fs::remove_file(t.pkgdir("q").join("data.tar")).unwrap();
    let staged = load_staged(&t.stage).unwrap();
    let mut db = Database::new(&t.root);
    db.load().unwrap();
    let pkgs = debbuild_rs_install::plan(&db, &staged, &["q".to_owned()])
        .unwrap()
        .packages;
    let exec = t.exec();
    let err = debbuild_rs_install::Installer::new(db, InstallOptions::default(), &exec)
        .install(&pkgs)
        .unwrap_err();
    assert_eq!(
        err.message(),
        "q: staged tree changed while installing, rerun"
    );
}

/// R1: the digest is stable (fixed vectors): it is recorded in the roots.
#[test]
fn digest_vectors() {
    let t = Base::new();
    for (name, version, extra) in [("p", "1", true), ("q", "2", false)] {
        let d = t.stage.join(name).join(name);
        fs::create_dir_all(d.join("DEBIAN")).unwrap();
        fs::write(
            d.join("DEBIAN/control"),
            format!("Package: {name}\nVersion: {version}\n"),
        )
        .unwrap();
        fs::set_permissions(d.join("DEBIAN/control"), fs::Permissions::from_mode(0o644)).unwrap();
        if extra {
            fs::write(d.join("DEBIAN/postinst"), "#!/bin/sh\n").unwrap();
            fs::set_permissions(d.join("DEBIAN/postinst"), fs::Permissions::from_mode(0o755))
                .unwrap();
            fs::write(d.join("data.tar.sha256"), " abc\n").unwrap();
        }
        fs::write(d.join("data.tar"), "DATA").unwrap();
    }
    let staged = load_staged(&t.stage).unwrap();
    assert_eq!(
        staged["p"].digest().unwrap(),
        "bb3da37f8ebf69538b5a404ebce9af73486e2a5910205e60a1d2a4df40764a15"
    );
    assert_eq!(
        staged["q"].digest().unwrap(),
        "306042112b2752a3e02ddefd9b22c2cc49a01c05e3da3fdd9942d981473dfc65"
    );
}

#[test]
fn staged_twice_and_dot_dirs() {
    let t = Base::new();
    t.stage_pkg("p", "1", &[], &o());
    let other = t.stage.join("other/p");
    fs::create_dir_all(other.join("DEBIAN")).unwrap();
    fs::write(other.join("DEBIAN/control"), "Package: p\nVersion: 2\n").unwrap();
    let err = load_staged(&t.stage).err().unwrap();
    assert_eq!(
        err.message(),
        format!(
            "p is staged twice: in {} and {}",
            other.display(),
            t.pkgdir("p").display()
        )
    );
    fs::rename(t.stage.join("other"), t.stage.join(".work.other.x")).unwrap();
    assert_eq!(load_staged(&t.stage).unwrap().len(), 1);
    fs::set_permissions(
        t.stage.join(".work.other.x"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
}

#[test]
fn path_filters() {
    let t = Base::new();
    std::fs::create_dir_all(t.f("etc/dpkg/dpkg.cfg.d")).unwrap();
    t.write(
        "etc/dpkg/dpkg.cfg.d/excludes",
        b"# as in Debian's container images\npath-exclude /usr/share/doc/*\n\
          path-include=/usr/share/doc/*/copyright\n",
    );
    t.stage_pkg(
        "p",
        "1",
        &[
            ("/usr/share/doc/p/changelog.gz", file(b"c")),
            ("/usr/share/doc/p/copyright", file(b"(c)")),
            ("/usr/bin/p", file(b"p")),
        ],
        &o(),
    );
    t.install(&["p"]);
    assert!(!t.f("usr/share/doc/p/changelog.gz").exists());
    assert_eq!(t.read("usr/share/doc/p/copyright"), b"(c)");
    assert_eq!(t.read("usr/bin/p"), b"p");
    // listed all the same, as dpkg does
    assert!(
        t.listed("p")
            .contains(&"/usr/share/doc/p/changelog.gz".to_owned())
    );
}
