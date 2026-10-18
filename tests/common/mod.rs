//! The installer's test fixture: a temporary root holding a minimal dpkg database, tiny
//! staged packages, and maintainer scripts run in place (no chroot) that log their
//! arguments.
#![allow(
    dead_code,
    clippy::format_collect,
    clippy::format_push_string,
    clippy::many_single_char_names
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use debbuild_rs_common::Result;
use debbuild_rs_common::deb822::Stanza;
use debbuild_rs_install::{Database, Exec, InstallOptions, Installer, load_staged, plan};

pub const LOG_SCRIPT: &str = "#!/bin/sh\necho \"$DPKG_MAINTSCRIPT_PACKAGE $DPKG_MAINTSCRIPT_NAME $*\" >>\"$DEBBUILD_RS_TEST_LOG\"\n";
pub const MTIME: u64 = 1_767_225_600;

pub fn uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

pub fn gid() -> u32 {
    nix::unistd::getgid().as_raw()
}

pub fn md5(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    Md5::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Runs the maintainer scripts in place, without chroot.
pub struct TestExec {
    pub log: PathBuf,
    pub admin: PathBuf,
}

impl Exec for TestExec {
    fn command(&self, root: &Path, inside: &str, args: &[String]) -> Command {
        let mut c = Command::new(format!("{}{inside}", root.display()));
        c.args(args)
            .env("DEBBUILD_RS_TEST_LOG", &self.log)
            .env("DEBBUILD_RS_TEST_ADMINDIR", &self.admin);
        c
    }
}

/// A file of a staged package.
pub enum Entry {
    Dir,
    File(Vec<u8>),
    Symlink(String),
    /// A hard link to another path of the package.
    Hardlink(String),
}

pub fn file(content: &[u8]) -> Entry {
    Entry::File(content.to_vec())
}

pub fn link(target: &str) -> Entry {
    Entry::Symlink(target.to_owned())
}

#[derive(Default)]
pub struct Opts<'a> {
    pub control: &'a [(&'a str, &'a str)],
    pub conffiles: &'a [&'a str],
    pub scripts: &'a [(&'a str, &'a str)],
    pub triggers: Option<&'a str>,
    pub no_md5sums: bool,
}

/// One test at a time: a script written by one test and executed by it while another
/// test forks (its child holding the write descriptor until exec) fails with ETXTBSY.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub struct Base {
    _serial: std::sync::MutexGuard<'static, ()>,
    pub tmp: tempfile::TempDir,
    pub root: PathBuf,
    pub stage: PathBuf,
    pub admin: PathBuf,
    pub logfile: PathBuf,
}

/// A GNU tar header for `name`, written as is (no `./` normalization).
pub fn header(name: &str, kind: tar::EntryType, mode: u32, size: u64) -> tar::Header {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(kind);
    h.set_mode(mode);
    h.set_size(size);
    h.set_uid(u64::from(uid()));
    h.set_gid(u64::from(gid()));
    h.set_username("tester").unwrap();
    h.set_groupname("testers").unwrap();
    h.set_mtime(MTIME);
    let gnu = h.as_gnu_mut().unwrap();
    gnu.name = [0; 100];
    gnu.name[..name.len()].copy_from_slice(name.as_bytes());
    h.set_cksum();
    h
}

impl Base {
    pub fn new() -> Self {
        let serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::Builder::new()
            .prefix("debbuild-rs-test.")
            .tempdir()
            .unwrap();
        let t = fs::canonicalize(tmp.path()).unwrap();
        let root = t.join("root");
        let admin = root.join("var/lib/dpkg");
        for d in ["info", "updates", "triggers"] {
            fs::create_dir_all(admin.join(d)).unwrap();
        }
        fs::write(admin.join("status"), "").unwrap();
        fs::create_dir(root.join("etc")).unwrap();
        fs::write(
            root.join("etc/passwd"),
            format!(
                "root:x:0:0::/root:/bin/sh\ntester:x:{}:{}::/:/bin/sh\n",
                uid(),
                gid()
            ),
        )
        .unwrap();
        fs::write(
            root.join("etc/group"),
            format!("root:x:0:\ntesters:x:{}:\n", gid()),
        )
        .unwrap();
        let logfile = t.join("scripts.log");
        fs::write(&logfile, "").unwrap();
        Self {
            _serial: serial,
            stage: t.join("stage"),
            tmp,
            root,
            admin,
            logfile,
        }
    }

    pub fn exec(&self) -> TestExec {
        TestExec {
            log: self.logfile.clone(),
            admin: self.admin.clone(),
        }
    }

    pub fn pkgdir(&self, name: &str) -> PathBuf {
        self.stage.join(name).join(name)
    }

    /// Stage `name`: `files` maps a path to its entry; parent directories and the root
    /// `.` entry are added.
    pub fn stage_pkg(&self, name: &str, version: &str, files: &[(&str, Entry)], o: &Opts<'_>) {
        let d = self.pkgdir(name);
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("DEBIAN")).unwrap();
        let mut fields: Vec<(String, String)> = vec![
            ("Package".into(), name.into()),
            ("Version".into(), version.into()),
            ("Architecture".into(), "all".into()),
            ("Maintainer".into(), "t <t@example.com>".into()),
        ];
        for (k, v) in o.control {
            if let Some(f) = fields.iter_mut().find(|(n, _)| n == k) {
                f.1 = (*v).into();
            } else {
                fields.push(((*k).into(), (*v).into()));
            }
        }
        fields.push(("Description".into(), "test package".into()));
        let control: String = fields.iter().map(|(k, v)| format!("{k}: {v}\n")).collect();
        fs::write(d.join("DEBIAN/control"), control).unwrap();
        if !o.conffiles.is_empty() {
            let c: String = o.conffiles.iter().map(|c| format!("{c}\n")).collect();
            fs::write(d.join("DEBIAN/conffiles"), c).unwrap();
        }
        for script in ["preinst", "postinst", "prerm", "postrm"] {
            let p = d.join("DEBIAN").join(script);
            let extra = o
                .scripts
                .iter()
                .find(|(s, _)| *s == script)
                .map_or("", |(_, x)| x);
            fs::write(&p, format!("{LOG_SCRIPT}{extra}")).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        if let Some(t) = o.triggers {
            fs::write(d.join("DEBIAN/triggers"), t).unwrap();
        }
        let mut entries: std::collections::BTreeMap<String, &Entry> =
            std::collections::BTreeMap::new();
        let dir = Entry::Dir;
        entries.insert(String::new(), &dir);
        for (path, content) in files {
            let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
            for i in 1..parts.len() {
                entries.entry(parts[..i].join("/")).or_insert(&dir);
            }
            entries.insert(path.trim_matches('/').to_owned(), content);
        }
        let mut sums = String::new();
        let mut b = tar::Builder::new(Vec::new());
        for (path, content) in &entries {
            let name = if path.is_empty() {
                "./".to_owned()
            } else {
                format!("./{path}")
            };
            match content {
                Entry::Dir => {
                    let n = if path.is_empty() {
                        name
                    } else {
                        format!("{name}/")
                    };
                    let h = header(&n, tar::EntryType::Directory, 0o755, 0);
                    b.append(&h, &[][..]).unwrap();
                }
                Entry::File(data) => {
                    let h = header(&name, tar::EntryType::Regular, 0o644, data.len() as u64);
                    b.append(&h, data.as_slice()).unwrap();
                    if !o.conffiles.contains(&format!("/{path}").as_str()) {
                        sums.push_str(&format!("{}  {path}\n", md5(data)));
                    }
                }
                Entry::Symlink(target) => {
                    let mut h = header(&name, tar::EntryType::Symlink, 0o777, 0);
                    h.set_link_name(target).unwrap();
                    h.set_cksum();
                    b.append(&h, &[][..]).unwrap();
                }
                Entry::Hardlink(target) => {
                    let mut h = header(&name, tar::EntryType::Link, 0o644, 0);
                    h.set_link_name(format!("./{}", target.trim_start_matches('/')))
                        .unwrap();
                    h.set_cksum();
                    b.append(&h, &[][..]).unwrap();
                }
            }
        }
        fs::write(d.join("data.tar"), b.into_inner().unwrap()).unwrap();
        if !o.no_md5sums {
            fs::write(d.join("DEBIAN/md5sums"), sums).unwrap();
        }
    }

    pub fn try_install(&self, names: &[&str], opts: InstallOptions) -> Result<()> {
        let mut db = Database::new(&self.root);
        db.check_interrupted()?;
        db.load()?;
        let staged = load_staged(&self.stage)?;
        let names: Vec<String> = names.iter().map(|s| (*s).to_owned()).collect();
        let plan = plan(&db, &staged, &names)?;
        let exec = self.exec();
        Installer::new(db, opts, &exec).install(&plan.packages)
    }

    pub fn install(&self, names: &[&str]) {
        self.try_install(names, InstallOptions::default()).unwrap();
    }

    pub fn install_force(&self, names: &[&str]) {
        self.try_install(names, InstallOptions::FORCE).unwrap();
    }

    pub fn install_err(&self, names: &[&str]) -> String {
        self.try_install(names, InstallOptions::default())
            .unwrap_err()
            .message()
            .to_owned()
    }

    pub fn try_plan(&self, names: &[&str]) -> Result<Vec<String>> {
        let mut db = Database::new(&self.root);
        db.load()?;
        let staged = load_staged(&self.stage)?;
        let names: Vec<String> = names.iter().map(|s| (*s).to_owned()).collect();
        Ok(plan(&db, &staged, &names)?
            .packages
            .iter()
            .map(|p| p.name.clone())
            .collect())
    }

    pub fn plan(&self, names: &[&str]) -> Vec<String> {
        self.try_plan(names).unwrap()
    }

    /// The maintainer script calls since the last call.
    pub fn scripts(&self) -> Vec<String> {
        let text = fs::read_to_string(&self.logfile).unwrap();
        fs::write(&self.logfile, "").unwrap();
        text.lines().map(|l| l.trim_end().to_owned()).collect()
    }

    pub fn status(&self, name: &str) -> Option<Stanza> {
        let mut db = Database::new(&self.root);
        db.load().unwrap();
        db.status.get(name).cloned()
    }

    pub fn field(&self, name: &str, field: &str) -> Option<String> {
        self.status(name).and_then(|s| s.get(field).cloned())
    }

    pub fn edit_status(&self, name: &str, fields: &[(&str, Option<&str>)]) {
        let mut db = Database::new(&self.root);
        db.load().unwrap();
        let s = db.status.get_mut(name).unwrap();
        for (k, v) in fields {
            match v {
                None => {
                    s.shift_remove(*k);
                }
                Some(v) => {
                    s.insert((*k).into(), (*v).into());
                }
            }
        }
        db.save().unwrap();
    }

    /// Add an installed package to the database, as if dpkg had installed it.
    pub fn set_installed(&self, name: &str, version: &str, fields: &[(&str, &str)]) {
        let mut db = Database::new(&self.root);
        db.load().unwrap();
        let mut s = Stanza::new();
        s.insert("Package".into(), name.into());
        s.insert("Status".into(), "install ok installed".into());
        s.insert("Version".into(), version.into());
        for (k, v) in fields {
            s.insert((*k).into(), (*v).into());
        }
        db.status.insert(name.into(), s);
        db.save().unwrap();
    }

    pub fn listed(&self, name: &str) -> Vec<String> {
        fs::read_to_string(self.admin.join(format!("info/{name}.list")))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    pub fn f(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }

    pub fn read(&self, path: &str) -> Vec<u8> {
        fs::read(self.f(path)).unwrap()
    }

    pub fn write(&self, path: &str, data: &[u8]) {
        fs::write(self.f(path), data).unwrap();
    }
}
