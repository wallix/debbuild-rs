//! Unpacking data.tar, as dpkg does: file takeover, conffiles, obsolete files.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use md5::{Digest, Md5};
use nix::fcntl::{AT_FDCWD, AtFlags};
use nix::sys::time::TimeSpec;
use nix::unistd::{Gid, Uid, fchownat, linkat};

use debbuild_rs_common::deb822::Stanza;
use debbuild_rs_common::relation::Relation;
use debbuild_rs_common::{Error, IoContext, Result, py};

use crate::db::os;
use crate::fsx;
use crate::installer::{Conffiles, Installer, UnpackResult, log};
use crate::staged::Package;

/// `os.path.normpath("/" + name)`.
#[must_use]
pub fn normpath_abs(name: &[u8]) -> Vec<u8> {
    let path = [b"/", name].concat();
    let initial: usize = if path.starts_with(b"//") && !path.starts_with(b"///") {
        2
    } else {
        1
    };
    let mut comps: Vec<&[u8]> = Vec::new();
    for c in path.split(|&c| c == b'/') {
        if c.is_empty() || c == b"." {
            continue;
        }
        if c == b".." {
            // Never above the root.
            comps.pop();
        } else {
            comps.push(c);
        }
    }
    let mut out = vec![b'/'; initial];
    out.extend_from_slice(&comps.join(&b'/'));
    out
}

/// What the installer needs of an archive member.
struct Member {
    /// The typeflag, as in the header (`\0` made `5` for a name ending in `/`).
    kind: u8,
    mode: u32,
    uid: u32,
    gid: u32,
    uname: Option<String>,
    gname: Option<String>,
    mtime: i64,
    linkname: Vec<u8>,
}

impl Member {
    fn is_dir(&self) -> bool {
        self.kind == b'5'
    }

    /// Python's `TarInfo.isreg()`: `0`, `\0`, `7` and the GNU sparse `S`, which is
    /// rejected (H6).
    fn is_reg(&self) -> bool {
        matches!(self.kind, b'0' | 0 | b'7')
    }

    fn is_sym(&self) -> bool {
        self.kind == b'2'
    }

    fn is_lnk(&self) -> bool {
        self.kind == b'1'
    }
}

/// The name and the metadata of an archive member.
fn member_of<R: Read>(entry: &tar::Entry<'_, R>) -> Result<(Vec<u8>, Member)> {
    let name = entry.path_bytes().into_owned();
    let header = entry.header();
    let mut kind = header.entry_type().as_byte();
    if kind == 0 && name.ends_with(b"/") {
        kind = b'5';
    }
    let num = |v: io::Result<u64>| v.map_err(|e| tar_err(&e));
    let member = Member {
        kind,
        mode: header.mode().map_err(|e| tar_err(&e))?,
        uid: u32::try_from(num(header.uid())?).unwrap_or(u32::MAX),
        gid: u32::try_from(num(header.gid())?).unwrap_or(u32::MAX),
        uname: header
            .username_bytes()
            .map(|u| String::from_utf8_lossy(u).into_owned()),
        gname: header
            .groupname_bytes()
            .map(|g| String::from_utf8_lossy(g).into_owned()),
        mtime: i64::try_from(num(header.mtime())?).unwrap_or(i64::MAX),
        linkname: entry
            .link_name_bytes()
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_default(),
    };
    Ok((name, member))
}

fn tar_err(e: &io::Error) -> Error {
    Error::os_msg(e.to_string())
}

/// The conffiles of a package and its remove-on-upgrade ones.
type PathSet = BTreeSet<Vec<u8>>;

fn conffiles(pkg: &Package) -> Result<(PathSet, PathSet)> {
    let mut keep = BTreeSet::new();
    let mut remove = BTreeSet::new();
    if let Some(e) = pkg.debian_entry("conffiles")
        && e.exists
    {
        let text = fsx::decode(e.data.clone()?)?;
        for line in py::splitlines_str(&text) {
            let parts = py::split_ws_str(line);
            if let Some((last, flags)) = parts.split_last() {
                if flags.contains(&"remove-on-upgrade") {
                    remove.insert(last.as_bytes().to_vec());
                } else {
                    keep.insert(last.as_bytes().to_vec());
                }
            }
        }
    }
    Ok((keep, remove))
}

/// Conffiles field: path -> md5 (flags such as obsolete dropped).
fn parse_conffiles_field(value: &str) -> IndexMap<Vec<u8>, String> {
    let mut out = IndexMap::new();
    for line in py::splitlines_str(value) {
        if let [path, md5, ..] = py::split_ws_str(line).as_slice() {
            out.insert(path.as_bytes().to_vec(), (*md5).to_owned());
        }
    }
    out
}

impl Installer<'_, '_> {
    /// Extract the package's files, as dpkg does.
    pub(crate) fn unpack(&mut self, pkg: &Package, old: Option<&Stanza>) -> Result<UnpackResult> {
        self.load_ids()?;
        self.load_statoverride()?;
        if self.filters.is_none() {
            self.filters = Some(crate::filter::Filters::load(&self.root)?);
        }
        let (conffiles, remove_on_upgrade) = conffiles(pkg)?;
        let old_conf = old.map_or_else(IndexMap::new, |o| {
            parse_conffiles_field(o.get("Conffiles").map_or("", String::as_str))
        });
        let replaces = pkg.relations("Replaces")?;
        let mut res = UnpackResult::default();
        if !pkg.debian_entry("md5sums").is_some_and(|e| e.exists) {
            res.md5sums = Some(IndexMap::new());
        }
        // dpkg-deb --build puts symlinks last in data.tar, so dpkg lists them last.
        let mut symlinks: Vec<Vec<u8>> = Vec::new();
        let read = self.unpack_members(
            pkg,
            &conffiles,
            &old_conf,
            &replaces,
            &mut res,
            &mut symlinks,
        );
        // As in a `finally`: an error of the flush wins.
        let flushed = self.flush_disowned();
        flushed?;
        read?;
        res.files.extend(symlinks);

        let new: BTreeSet<Vec<u8>> = res.files.iter().cloned().collect();
        for (path, md5) in &old_conf {
            if conffiles.contains(path) || new.contains(path) || remove_on_upgrade.contains(path) {
                continue;
            }
            // dpkg never removes an obsolete conffile: it stays, still owned by the package.
            res.conffiles
                .insert(path.clone(), format!("{md5} obsolete"));
            res.files.push(path.clone());
        }
        for path in &remove_on_upgrade {
            res.dropped.insert(path.clone());
            if let Some(md5) = old_conf.get(path) {
                self.remove_on_upgrade(pkg, path, md5)?;
            }
        }
        Ok(res)
    }

    fn unpack_members(
        &mut self,
        pkg: &Package,
        conffiles: &BTreeSet<Vec<u8>>,
        old_conf: &IndexMap<Vec<u8>, String>,
        replaces: &[Vec<Relation>],
        res: &mut UnpackResult,
        symlinks: &mut Vec<Vec<u8>>,
    ) -> Result<()> {
        let mut ar = tar::Archive::new(pkg.data_tar()?);
        for entry in ar.entries().map_err(|e| tar_err(&e))? {
            let entry = entry.map_err(|e| tar_err(&e))?;
            let (name, m) = member_of(&entry)?;
            let size = entry.size();
            let mut entry = Exact {
                inner: entry,
                left: size,
            };
            let rel = normpath_abs(&name);
            let listed = if rel == b"/" {
                b"/.".to_vec()
            } else {
                rel.clone()
            };
            if m.is_sym() {
                symlinks.push(listed);
            } else {
                res.files.push(listed);
            }
            if rel == b"/" {
                continue;
            }
            if self
                .filters
                .as_ref()
                .is_some_and(|f| f.skip(&rel, m.is_dir() || m.is_sym()))
            {
                res.filtered.insert(rel);
                continue;
            }
            self.unpack_member(
                pkg, &mut entry, &m, &rel, conffiles, old_conf, replaces, res,
            )?;
            let p = self.path(&rel, false)?;
            match fs::symlink_metadata(&p) {
                Ok(st) => {
                    res.inodes.insert((st.dev(), st.ino()));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::os(&e, &p)),
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn unpack_member(
        &mut self,
        pkg: &Package,
        data: &mut impl Read,
        m: &Member,
        rel: &[u8],
        conffiles: &BTreeSet<Vec<u8>>,
        old_conf: &IndexMap<Vec<u8>, String>,
        replaces: &[Vec<Relation>],
        res: &mut UnpackResult,
    ) -> Result<()> {
        if m.is_dir() {
            return self.unpack_dir(pkg, rel, m, replaces);
        }
        self.take_over(pkg, rel, replaces)?;
        let shown = String::from_utf8_lossy(rel).into_owned();
        if m.is_reg() {
            if conffiles.contains(rel) {
                let mut content = Vec::new();
                data.read_to_end(&mut content).map_err(|e| tar_err(&e))?;
                let md5 = fsx::hex(&Md5::digest(&content));
                res.conffiles.insert(rel.to_vec(), md5.clone());
                let old_md5 = old_conf.get(rel).map(String::as_str);
                self.unpack_conffile(rel, m, &content, old_md5, &md5)?;
                if let Some(sums) = &mut res.md5sums {
                    sums.insert(rel.to_vec(), md5);
                }
            } else if res.md5sums.is_none() {
                let p = self.path(rel, false)?;
                self.replace(&p, rel, m, |tmp| write_stream(tmp, data, |_| {}))?;
            } else {
                let p = self.path(rel, false)?;
                let mut h = Md5::new();
                self.replace(&p, rel, m, |tmp| write_stream(tmp, data, |c| h.update(c)))?;
                if let Some(sums) = &mut res.md5sums {
                    sums.insert(rel.to_vec(), fsx::hex(&h.finalize()));
                }
            }
        } else if m.is_sym() {
            let p = self.path(rel, false)?;
            let target = PathBuf::from(os(&m.linkname));
            self.replace(&p, rel, m, |tmp| symlink(&target, tmp).at2(&target, tmp))?;
        } else if m.is_lnk() {
            // Python 3.11's os.link (link(2)) does not follow a final symlink: the
            // symlink itself is linked, never what it points to.
            let target = self.path(&normpath_abs(&m.linkname), false)?;
            let p = self.path(rel, false)?;
            self.replace(&p, rel, m, |tmp| {
                linkat(AT_FDCWD, &target, AT_FDCWD, tmp, AtFlags::empty())
                    .map_err(io::Error::from)
                    .at2(&target, tmp)
            })?;
        } else {
            return Err(Error::new(format!(
                "{}: {shown}: unsupported file type in archive",
                pkg.name
            )));
        }
        Ok(())
    }

    fn unpack_dir(
        &mut self,
        pkg: &Package,
        rel: &[u8],
        m: &Member,
        replaces: &[Vec<Relation>],
    ) -> Result<()> {
        // An existing directory, or a symlink to one, is kept as is (policy §6.6).
        if fsx::is_dir(&self.path(rel, true)?) {
            return Ok(());
        }
        let p = self.path(rel, false)?;
        if fsx::lexists(&p) {
            // A file of the old version, or of nobody, becomes a directory.
            self.take_over(pkg, rel, replaces)?;
            fs::remove_file(&p).at(&p)?;
        }
        fs::create_dir(&p).at(&p)?;
        let (uid, gid, mode) = self.perms(rel, m);
        std::os::unix::fs::chown(&p, Some(uid), Some(gid)).at(&p)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(mode & 0o7777)).at(&p)
    }

    /// Owner, group and mode of an archive member, after dpkg-statoverride.
    fn perms(&self, rel: &[u8], m: &Member) -> (u32, u32, u32) {
        if let Some(so) = self.statoverride.get(rel) {
            return *so;
        }
        let uid = m
            .uname
            .as_ref()
            .and_then(|u| self.passwd.get(u))
            .copied()
            .unwrap_or(m.uid);
        let gid = m
            .gname
            .as_ref()
            .and_then(|g| self.group.get(g))
            .copied()
            .unwrap_or(m.gid);
        (uid, gid, m.mode)
    }

    /// Atomically put a new non-directory entry at `p` (`rel` in the package), made by
    /// `create(tmp)`.
    fn replace(
        &self,
        p: &Path,
        rel: &[u8],
        m: &Member,
        create: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<()> {
        if !fsx::is_symlink(p) && fsx::is_dir(p) {
            if m.is_sym() {
                // dpkg never replaces an existing directory by a symlink, whatever it
                // points to (policy §6.6).
                return Ok(());
            }
            if fs::remove_dir(p).is_err() {
                return Err(Error::new(format!(
                    "{}: is a non-empty directory, cannot replace it",
                    String::from_utf8_lossy(rel)
                )));
            }
        }
        let mut tmp_name = p.file_name().unwrap_or_default().to_os_string();
        tmp_name.push(".dpkg-new");
        let tmp = p.with_file_name(tmp_name);
        match fs::remove_file(&tmp) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(Error::os(&e, &tmp)),
            _ => {}
        }
        create(&tmp)?;
        if !m.is_lnk() {
            let (uid, gid, mode) = self.perms(rel, m);
            fchownat(
                AT_FDCWD,
                &tmp,
                Some(Uid::from_raw(uid)),
                Some(Gid::from_raw(gid)),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(io::Error::from)
            .at(&tmp)?;
            if !m.is_sym() {
                fs::set_permissions(&tmp, fs::Permissions::from_mode(mode & 0o7777)).at(&tmp)?;
                fsx::set_times(&tmp, TimeSpec::new(m.mtime, 0), TimeSpec::new(m.mtime, 0))
                    .at(&tmp)?;
            }
        }
        fs::rename(&tmp, p).at2(&tmp, p)
    }

    /// Settle a conffile as dpkg does, with --force-confold (--conffiles=replace:
    /// --force-confnew) where it would prompt.
    fn unpack_conffile(
        &mut self,
        rel: &[u8],
        m: &Member,
        data: &[u8],
        old_md5: Option<&str>,
        new_md5: &str,
    ) -> Result<()> {
        // A conffile that is a symlink is written through, as dpkg does.
        let target = self.path(rel, true)?;
        // dpkg's mark for a conffile not configured yet
        let old_md5 = old_md5.filter(|o| *o != "newconffile");
        let current = fsx::md5_file(&target)?;
        let exists = fsx::lexists(&target);
        let shown = String::from_utf8_lossy(rel).into_owned();
        let sibling = |suffix: &str| {
            let mut n = target.file_name().unwrap_or_default().to_os_string();
            n.push(suffix);
            target.with_file_name(n)
        };
        let write = |me: &Self, p: &Path| me.replace(p, rel, m, |tmp| fs::write(tmp, data).at(tmp));
        let prompt = |me: &Self, why: &str| -> Result<()> {
            // dpkg asks here: --force-confold, or --force-confnew with --conffiles=replace.
            if me.opts.conffiles == Conffiles::Replace {
                let old = sibling(".dpkg-old");
                log(&format!(
                    "{shown}: {why}, installing the new version; old one in {}",
                    me.db.rel(&old)
                ));
                // Written through a symlink resolved in the root, as the conffile (H8).
                let in_root = old.strip_prefix(&me.root).unwrap_or(&old);
                fsx::copy2(&target, &me.path(in_root.as_os_str().as_bytes(), true)?)?;
                write(me, &target)
            } else {
                let dist = sibling(".dpkg-dist");
                log(&format!(
                    "{shown}: {why}, keeping it; new version in {}",
                    me.db.rel(&dist)
                ));
                write(me, &dist)
            }
        };
        if !exists {
            if old_md5.is_none() {
                write(self, &target)?;
            } else {
                log(&format!("{shown}: deleted locally, leaving it deleted"));
            }
        } else if current.as_deref() == Some(new_md5) {
            // already the new content
        } else if old_md5.is_none() {
            prompt(self, "exists and is not from this package")?;
        } else if current.as_deref() == old_md5 {
            write(self, &target)?;
        } else if old_md5 == Some(new_md5) {
            // modified locally, unchanged in the package
        } else {
            prompt(self, "modified locally")?;
        }
        Ok(())
    }

    /// Remove a conffile marked remove-on-upgrade, or keep it aside when modified, as
    /// dpkg does.
    fn remove_on_upgrade(&self, pkg: &Package, rel: &[u8], old_md5: &str) -> Result<()> {
        let p = self.path(rel, false)?;
        if !fsx::lexists(&p) {
            return Ok(());
        }
        let shown = String::from_utf8_lossy(rel);
        if fsx::md5_file(&self.path(rel, true)?)?.as_deref() == Some(old_md5) {
            log(&format!("{}: removing obsolete conffile {shown}", pkg.name));
            fs::remove_file(&p).at(&p)
        } else {
            log(&format!(
                "{}: obsolete conffile {shown} modified locally, keeping it as {shown}.dpkg-bak",
                pkg.name
            ));
            let mut n = p.file_name().unwrap_or_default().to_os_string();
            n.push(".dpkg-bak");
            let bak = p.with_file_name(n);
            fs::rename(&p, &bak).at2(&p, &bak)
        }
    }

    /// Remove the old files absent from the new version; return the removed paths.
    pub(crate) fn remove_obsolete(
        &mut self,
        pkg: &str,
        old_files: &[Vec<u8>],
        res: &UnpackResult,
    ) -> Result<Vec<Vec<u8>>> {
        let new: BTreeSet<&Vec<u8>> = res
            .files
            .iter()
            .filter(|f| !res.filtered.contains(*f))
            .collect();
        let gone: BTreeSet<&Vec<u8>> = old_files
            .iter()
            .filter(|f| !new.contains(f) && !res.dropped.contains(*f))
            .collect();
        let mut removed = Vec::new();
        for f in gone.into_iter().rev() {
            if f.as_slice() == b"/." {
                continue;
            }
            let others = self.owners()?.get(f).is_some_and(|o| {
                o.iter()
                    .any(|o| o.split(':').next().unwrap_or_default() != pkg)
            });
            if others {
                continue;
            }
            let shown = String::from_utf8_lossy(f);
            let p = self.path(f, false)?;
            let result = fs::symlink_metadata(&p).and_then(|st| {
                if res.inodes.contains(&(st.dev(), st.ino())) {
                    return Ok(false);
                }
                if st.is_dir() {
                    fs::remove_dir(&p)
                } else {
                    fs::remove_file(&p)
                }
                .map(|()| true)
            });
            match result {
                Ok(false) => {
                    // Another name of a path of the new version (a symlinked directory).
                    log(&format!(
                        "{pkg}: {shown}: same file as a new one, not removing it"
                    ));
                }
                Ok(true) => {
                    log(&format!("{pkg}: removed {shown}"));
                    removed.push(f.clone());
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e)
                    if e.raw_os_error()
                        .is_some_and(|n| n == nix::libc::ENOTEMPTY || n == nix::libc::EEXIST) =>
                {
                    log(&format!(
                        "warning: {pkg}: unable to delete old directory '{shown}': directory not empty"
                    ));
                }
                Err(e) => {
                    log(&format!(
                        "warning: {pkg}: unable to delete old file '{shown}': {}",
                        debbuild_rs_common::error::strerror(&e)
                    ));
                }
            }
        }
        Ok(removed)
    }
}

/// A member's data, which must be as long as its header says. As with Python's
/// tarfile, each read is filled (up to what is left of the member) or fails with
/// nothing returned: a truncated archive fails before the extracted file replaces
/// anything.
struct Exact<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = usize::try_from(self.left).map_or(buf.len(), |l| l.min(buf.len()));
        let mut n = 0;
        while n < want {
            match self.inner.read(buf.get_mut(n..want).unwrap_or_default()) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected end of data",
                    ));
                }
                Ok(k) => n = n.saturating_add(k),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        self.left = self
            .left
            .saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
        Ok(n)
    }
}

/// Write `src` to a new file `tmp`, passing each chunk to `update`.
fn write_stream(tmp: &Path, src: &mut impl Read, update: impl FnMut(&[u8])) -> Result<()> {
    let mut f = fsx::create(tmp)?;
    fsx::copy_hashing(src, &mut f, update).map_err(|e| tar_err(&e))?;
    f.flush().at(tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normpath() {
        assert_eq!(normpath_abs(b"./usr/bin/"), b"/usr/bin");
        assert_eq!(normpath_abs(b"."), b"/");
        assert_eq!(normpath_abs(b"./"), b"/");
        assert_eq!(normpath_abs(b"/x"), b"//x");
        assert_eq!(normpath_abs(b"//x"), b"/x");
        assert_eq!(normpath_abs(b"../../x/./y/../z"), b"/x/z");
    }
}
