//! Small synthetic staged packages for the differential scenarios, written as root
//! (root-owned members) with maintainer scripts that log their calls inside the root.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::util::{Context, Result, mkdirs};

/// The logging part of every maintainer script: it logs its calls to
/// /var/log/debbuild-rs-check/scripts.log, inside the root.
const LOG_SCRIPT: &str = "#!/bin/sh\nmkdir -p /var/log/debbuild-rs-check\necho \"$DPKG_MAINTSCRIPT_PACKAGE $DPKG_MAINTSCRIPT_NAME $*\" >>/var/log/debbuild-rs-check/scripts.log\n";

/// A file of a staged package.
pub enum Entry {
    Dir,
    File(Vec<u8>),
    Symlink(String),
    Hardlink(String),
    /// A GNU sparse member without holes (H6).
    Sparse(Vec<u8>),
}

pub fn file(c: &str) -> Entry {
    Entry::File(c.as_bytes().to_vec())
}

pub fn link(t: &str) -> Entry {
    Entry::Symlink(t.to_owned())
}

#[derive(Default)]
pub struct Pkg<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub files: Vec<(&'a str, Entry)>,
    pub control: Vec<(&'a str, &'a str)>,
    pub conffiles: Vec<&'a str>,
    pub scripts: Vec<(&'a str, &'a str)>,
    pub triggers: Option<&'a str>,
    /// Without DEBIAN/md5sums.
    pub no_md5sums: bool,
    /// Without maintainer scripts (for roots without a shell).
    pub no_scripts: bool,
    /// A data.tar.sha256 not matching data.tar (H7).
    pub bad_sha256: bool,
}

fn header(name: &str, kind: tar::EntryType, mode: u32, size: u64) -> Result<tar::Header> {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(kind);
    h.set_mode(mode);
    h.set_size(size);
    h.set_uid(0);
    h.set_gid(0);
    h.set_username("root").ctx("header")?;
    h.set_groupname("root").ctx("header")?;
    h.set_mtime(1_767_225_600);
    if let Some(gnu) = h.as_gnu_mut() {
        gnu.name = [0; 100];
        let n = name.as_bytes();
        if let Some(dst) = gnu.name.get_mut(..n.len()) {
            dst.copy_from_slice(n);
        }
    }
    h.set_cksum();
    Ok(h)
}

fn md5(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    Md5::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Stage `p` in `stage/<name>/<name>`; returns its directory.
///
/// # Errors
/// It cannot be written.
pub fn stage_pkg(stage: &Path, p: &Pkg<'_>) -> Result<PathBuf> {
    let d = stage.join(p.name).join(p.name);
    let _ = fs::remove_dir_all(&d);
    mkdirs(&d.join("DEBIAN"))?;
    let mut fields: Vec<(String, String)> = vec![
        ("Package".into(), p.name.into()),
        ("Version".into(), p.version.into()),
        ("Architecture".into(), "all".into()),
        ("Maintainer".into(), "t <t@example.com>".into()),
    ];
    for (k, v) in &p.control {
        fields.push(((*k).into(), (*v).into()));
    }
    fields.push(("Description".into(), "debbuild-rs check fixture".into()));
    let control: String = fields.iter().map(|(k, v)| format!("{k}: {v}\n")).collect();
    let w = |path: PathBuf, data: &[u8], mode: u32| -> Result<()> {
        fs::write(&path, data).ctx(path.display())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).ctx(path.display())
    };
    w(d.join("DEBIAN/control"), control.as_bytes(), 0o644)?;
    if !p.conffiles.is_empty() {
        let c: String = p.conffiles.iter().map(|c| format!("{c}\n")).collect();
        w(d.join("DEBIAN/conffiles"), c.as_bytes(), 0o644)?;
    }
    if !p.no_scripts {
        for script in ["preinst", "postinst", "prerm", "postrm"] {
            let extra = p
                .scripts
                .iter()
                .find(|(s, _)| *s == script)
                .map_or("", |(_, x)| *x);
            w(
                d.join("DEBIAN").join(script),
                format!("{LOG_SCRIPT}{extra}").as_bytes(),
                0o755,
            )?;
        }
    }
    if let Some(t) = p.triggers {
        w(d.join("DEBIAN/triggers"), t.as_bytes(), 0o644)?;
    }
    let mut entries: BTreeMap<String, &Entry> = BTreeMap::new();
    let dir = Entry::Dir;
    entries.insert(String::new(), &dir);
    for (path, e) in &p.files {
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        for i in 1..parts.len() {
            entries
                .entry(parts.get(..i).unwrap_or_default().join("/"))
                .or_insert(&dir);
        }
        entries.insert(path.trim_matches('/').to_owned(), e);
    }
    let mut sums = String::new();
    let mut b = tar::Builder::new(Vec::new());
    for (path, e) in &entries {
        let name = if path.is_empty() {
            "./".to_owned()
        } else {
            format!("./{path}")
        };
        let conffile = p
            .conffiles
            .iter()
            .any(|c| c.split_whitespace().last() == Some(&format!("/{path}")));
        match e {
            Entry::Dir => {
                let n = if path.is_empty() {
                    name
                } else {
                    format!("{name}/")
                };
                b.append(&header(&n, tar::EntryType::Directory, 0o755, 0)?, &[][..])
                    .ctx("tar")?;
            }
            Entry::File(data) => {
                let h = header(&name, tar::EntryType::Regular, 0o644, data.len() as u64)?;
                b.append(&h, data.as_slice()).ctx("tar")?;
                if !conffile {
                    sums.push_str(&format!("{}  {path}\n", md5(data)));
                }
            }
            Entry::Sparse(data) => {
                let mut h = header(&name, tar::EntryType::GNUSparse, 0o644, data.len() as u64)?;
                if let Some(gnu) = h.as_gnu_mut() {
                    gnu.set_real_size(data.len() as u64);
                    // one chunk: the whole file
                    if let Some(chunk) = gnu.sparse.first_mut() {
                        chunk.offset = *b"00000000000\0";
                        let n = format!("{:011o}\0", data.len());
                        chunk.numbytes.copy_from_slice(n.as_bytes());
                    }
                }
                h.set_cksum();
                b.append(&h, data.as_slice()).ctx("tar")?;
            }
            Entry::Symlink(target) => {
                let mut h = header(&name, tar::EntryType::Symlink, 0o777, 0)?;
                h.set_link_name(target).ctx("tar")?;
                h.set_cksum();
                b.append(&h, &[][..]).ctx("tar")?;
            }
            Entry::Hardlink(target) => {
                let mut h = header(&name, tar::EntryType::Link, 0o644, 0)?;
                h.set_link_name(format!("./{}", target.trim_start_matches('/')))
                    .ctx("tar")?;
                h.set_cksum();
                b.append(&h, &[][..]).ctx("tar")?;
            }
        }
    }
    let data = b.into_inner().ctx("tar")?;
    w(d.join("data.tar"), &data, 0o644)?;
    let digest: String = if p.bad_sha256 {
        "0".repeat(64)
    } else {
        use sha2::{Digest, Sha256};
        Sha256::digest(&data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    w(
        d.join("data.tar.sha256"),
        format!("{digest}\n").as_bytes(),
        0o644,
    )?;
    if !p.no_md5sums {
        w(d.join("DEBIAN/md5sums"), sums.as_bytes(), 0o644)?;
    }
    Ok(d)
}

/// Cut the data.tar of the staged `pkg` `keep` bytes into the data of its member
/// `path`, and record the digest of what is left in data.tar.sha256.
///
/// # Errors
/// It cannot be read or written, or has no such member.
pub fn truncate_member(stage: &Path, pkg: &str, path: &str, keep: u64) -> Result<()> {
    use sha2::{Digest, Sha256};
    let d = stage.join(pkg).join(pkg);
    let tar_path = d.join("data.tar");
    let data = fs::read(&tar_path).ctx(tar_path.display())?;
    let member = format!(".{path}");
    let mut start = None;
    let mut ar = tar::Archive::new(data.as_slice());
    for e in ar.entries().ctx("tar")? {
        let e = e.ctx("tar")?;
        if e.path_bytes().as_ref() == member.as_bytes() {
            start = Some(e.raw_file_position());
        }
    }
    let end = start
        .and_then(|s| s.checked_add(keep))
        .and_then(|e| usize::try_from(e).ok())
        .ok_or_else(|| crate::util::err(format!("{pkg}: no member {member}")))?;
    let cut = data.get(..end).unwrap_or_default();
    fs::write(&tar_path, cut).ctx(tar_path.display())?;
    let digest: String = Sha256::digest(cut)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let sha = d.join("data.tar.sha256");
    fs::write(&sha, format!("{digest}\n")).ctx(sha.display())
}
