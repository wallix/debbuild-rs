//! Staged packages: STAGEDIR/<dir>/<package>/{DEBIAN/, data.tar, data.tar.sha256}.
//!
//! Each package is read once (H7): its directory is opened, and everything else is
//! read relative to it at load time: DEBIAN/* into memory with their modes,
//! data.tar.sha256, and an open descriptor on data.tar. A stage run publishing a new
//! tree meanwhile (rm -rf + mv) leaves the installer on the old one, or makes a load
//! fail; the installer reports that as a changed tree instead of mixing generations.

use std::cell::OnceCell;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use nix::errno::Errno;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;
use sha2::{Digest, Sha256};

use debbuild_rs_common::deb822::{Stanza, parse_stanzas};
use debbuild_rs_common::relation::{FIELDS, Relation, parse_field};
use debbuild_rs_common::{Error, IoContext, Result, py, staged_lock};

use crate::fsx;

/// The points of a load where a concurrent publish changes the outcome (H7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadPoint {
    /// The package directory was found, not opened yet.
    Scanned,
    /// DEBIAN/ was listed, its entries not opened yet.
    Listed,
    /// DEBIAN/* and data.tar.sha256 were read, data.tar not opened yet.
    Read,
}

/// A callback at each [`LoadPoint`], for the tests of H7.
#[cfg(feature = "test-hooks")]
pub mod hooks {
    use std::cell::RefCell;
    use std::path::Path;

    use super::LoadPoint;

    type Hook = Box<dyn FnMut(LoadPoint, &Path)>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    /// Call `hook` with the point and the package directory, in this thread.
    pub fn set(hook: impl FnMut(LoadPoint, &Path) + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub fn clear() {
        HOOK.with(|h| *h.borrow_mut() = None);
    }

    pub(crate) fn fire(point: LoadPoint, path: &Path) {
        HOOK.with(|h| {
            if let Some(hook) = h.borrow_mut().as_mut() {
                hook(point, path);
            }
        });
    }
}

#[cfg(not(feature = "test-hooks"))]
mod hooks {
    pub(crate) fn fire(_: super::LoadPoint, _: &std::path::Path) {}
}

/// One DEBIAN entry, as read at load time.
pub struct DebEntry {
    pub name: Vec<u8>,
    /// Its contents, or the error reading them gave (raised where they are used).
    pub data: Result<Vec<u8>>,
    /// Permission bits (symlinks followed).
    pub mode: u32,
    pub is_dir: bool,
    /// Whether it exists, symlinks followed (`Path.exists()`).
    pub exists: bool,
}

pub struct Package {
    pub name: String,
    /// STAGEDIR/<dir>/<package>.
    pub path: PathBuf,
    pub control: Stanza,
    /// Sorted by name.
    pub debian: Vec<DebEntry>,
    /// data.tar.sha256, if present.
    recorded: Option<Result<Vec<u8>>>,
    data: Result<File>,
    digest: OnceCell<String>,
}

/// The H7 error.
#[must_use]
pub fn changed(name: &str) -> Error {
    Error::new(format!(
        "{name}: staged tree changed while installing, rerun"
    ))
}

fn open_at(dir: impl AsFd, name: &OsStr, flags: OFlag) -> std::result::Result<OwnedFd, Errno> {
    openat(
        dir,
        name,
        flags | OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
}

fn read_all(fd: OwnedFd, path: &Path) -> Result<Vec<u8>> {
    let mut f = File::from(fd);
    let mut data = Vec::new();
    f.read_to_end(&mut data).at(path)?;
    Ok(data)
}

fn errno_err(e: Errno, path: &Path) -> Error {
    Error::os(&io::Error::from(e), path)
}

/// The entries of the open directory `fd` (`path`), sorted.
fn list_dir(fd: &OwnedFd, path: &Path) -> Result<Vec<OsString>> {
    let mut names: Vec<OsString> = Vec::new();
    let dir = nix::dir::Dir::from_fd(fd.try_clone().map_err(|e| Error::os(&e, path))?)
        .map_err(|e| errno_err(e, path))?;
    for e in dir {
        let e = e.map_err(|e| errno_err(e, path))?;
        let n = e.file_name().to_bytes();
        if n != b"." && n != b".." {
            names.push(OsStr::from_bytes(n).to_os_string());
        }
    }
    names.sort();
    Ok(names)
}

impl Package {
    /// Load the package in `path` (`dirname` for messages before its control is read).
    fn load(path: PathBuf, dirname: &str) -> Result<Self> {
        let gone = |e: Errno, p: &Path| {
            if e == Errno::ENOENT {
                changed(dirname)
            } else {
                errno_err(e, p)
            }
        };
        hooks::fire(LoadPoint::Scanned, &path);
        let dirfd = open_at(nix::fcntl::AT_FDCWD, path.as_os_str(), OFlag::O_DIRECTORY)
            .map_err(|e| gone(e, &path))?;
        let debian_path = path.join("DEBIAN");
        let debfd = open_at(&dirfd, OsStr::new("DEBIAN"), OFlag::O_DIRECTORY)
            .map_err(|e| gone(e, &debian_path))?;
        let names = list_dir(&debfd, &debian_path)?;
        hooks::fire(LoadPoint::Listed, &path);
        let mut debian = Vec::new();
        for n in names {
            let p = debian_path.join(&n);
            let fd = match open_at(&debfd, &n, OFlag::empty()) {
                Ok(fd) => fd,
                // A dangling symlink: an error where its contents are needed.
                Err(Errno::ENOENT)
                    if nix::sys::stat::fstatat(
                        &debfd,
                        n.as_os_str(),
                        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
                    )
                    .is_ok() =>
                {
                    debian.push(DebEntry {
                        name: n.as_bytes().to_vec(),
                        data: Err(errno_err(Errno::ENOENT, &p)),
                        mode: 0,
                        is_dir: false,
                        exists: false,
                    });
                    continue;
                }
                Err(e) => return Err(gone(e, &p)),
            };
            let meta = File::from(fd.try_clone().map_err(|e| Error::os(&e, &p))?)
                .metadata()
                .at(&p)?;
            let data = if meta.is_dir() {
                Err(Error::os(&io::Error::from_raw_os_error(libc_eisdir()), &p))
            } else {
                read_all(fd, &p)
            };
            debian.push(DebEntry {
                name: n.as_bytes().to_vec(),
                data,
                mode: meta.mode() & 0o7777,
                is_dir: meta.is_dir(),
                exists: true,
            });
        }
        let control_path = debian_path.join("control");
        let control = debian
            .iter()
            .find(|e| e.name == b"control")
            .ok_or_else(|| changed(dirname))?;
        let text = fsx::decode(control.data.clone()?)?;
        let stanza = parse_stanzas(&text)?.into_iter().next();
        let Some(control) =
            stanza.filter(|s| s.contains_key("Package") && s.contains_key("Version"))
        else {
            return Err(Error::new(format!(
                "{}: no Package or Version field",
                control_path.display()
            )));
        };
        let sha_path = path.join("data.tar.sha256");
        let recorded = match open_at(&dirfd, OsStr::new("data.tar.sha256"), OFlag::empty()) {
            Err(Errno::ENOENT) => None,
            Err(e) => Some(Err(errno_err(e, &sha_path))),
            Ok(fd) => Some(read_all(fd, &sha_path)),
        };
        let tar_path = path.join("data.tar");
        hooks::fire(LoadPoint::Read, &path);
        let data = open_at(&dirfd, OsStr::new("data.tar"), OFlag::empty())
            .map(File::from)
            .map_err(|e| gone(e, &tar_path));
        Ok(Self {
            name: control.get("Package").cloned().unwrap_or_default(),
            path,
            control,
            debian,
            recorded,
            data,
            digest: OnceCell::new(),
        })
    }

    /// A package of the status database (for scripts run outside a staged package).
    #[must_use]
    pub fn from_status(name: &str, control: Stanza) -> Self {
        Self {
            name: name.to_owned(),
            path: PathBuf::new(),
            control,
            debian: Vec::new(),
            recorded: None,
            data: Err(Error::new("no data.tar")),
            digest: OnceCell::new(),
        }
    }

    #[must_use]
    pub fn version(&self) -> &str {
        self.control.get("Version").map_or("", String::as_str)
    }

    #[must_use]
    pub fn arch(&self) -> &str {
        self.control
            .get("Architecture")
            .map_or("all", String::as_str)
    }

    /// A DEBIAN entry.
    #[must_use]
    pub fn debian_entry(&self, name: &str) -> Option<&DebEntry> {
        self.debian.iter().find(|e| e.name == name.as_bytes())
    }

    /// data.tar, rewound.
    ///
    /// # Errors
    /// It could not be opened at load time, or cannot be rewound.
    pub fn data_tar(&self) -> Result<&File> {
        let mut f = self.data.as_ref().map_err(Clone::clone)?;
        f.seek(SeekFrom::Start(0)).at(&self.path.join("data.tar"))?;
        Ok(f)
    }

    fn recorded_text(&self) -> Result<Option<String>> {
        match &self.recorded {
            None => Ok(None),
            Some(r) => Ok(Some(py::strip_str(&fsx::decode(r.clone()?)?).to_owned())),
        }
    }

    fn sha256_data(&self) -> Result<String> {
        let mut h = Sha256::new();
        let mut f = self.data_tar()?;
        fsx::copy_hashing(&mut f, &mut io::sink(), |c| h.update(c))
            .at(&self.path.join("data.tar"))?;
        Ok(fsx::hex(&h.finalize()))
    }

    /// Content digest of the staged package, to skip reinstalling it unchanged: sha256
    /// over each DEBIAN entry, by name, with its mode, since the installer installs the
    /// control files with their modes (`name\0d<mode>\0` for a directory,
    /// `name\0f<mode>\0<size>\0content` otherwise, the mode in octal); then
    /// `data.tar.sha256\0<recorded digest>`, or data.tar itself without one.
    ///
    /// # Errors
    /// A DEBIAN entry or data.tar could not be read.
    pub fn digest(&self) -> Result<String> {
        if let Some(d) = self.digest.get() {
            return Ok(d.clone());
        }
        let mut h = Sha256::new();
        for e in &self.debian {
            h.update(&e.name);
            if e.is_dir {
                h.update(format!("\0d{:o}\0", e.mode));
                continue;
            }
            let data = e.data.as_ref().map_err(Clone::clone)?;
            h.update(format!("\0f{:o}\0{}\0", e.mode, data.len()));
            h.update(data);
        }
        if let Some(r) = self.recorded_text()? {
            h.update(b"data.tar.sha256\0");
            h.update(r.as_bytes());
        } else {
            let mut f = self.data_tar()?;
            fsx::copy_hashing(&mut f, &mut io::sink(), |c| h.update(c))
                .at(&self.path.join("data.tar"))?;
        }
        let d = fsx::hex(&h.finalize());
        Ok(self.digest.get_or_init(|| d).clone())
    }

    /// Check data.tar against data.tar.sha256 (H7): a mismatch means a torn or mixed
    /// tree.
    ///
    /// # Errors
    /// The digests differ, or data.tar cannot be read.
    pub fn verify(&self) -> Result<()> {
        let Some(recorded) = self.recorded_text()? else {
            return Ok(());
        };
        if self.sha256_data()? == recorded {
            Ok(())
        } else {
            Err(changed(&self.name))
        }
    }

    /// Relationship field `field` (one of [`FIELDS`]), with dpkg's rules for it.
    ///
    /// # Errors
    /// What dpkg refuses in the field, as dpkg -i reports it for the package's control
    /// file.
    pub fn relations(&self, field: &str) -> Result<Vec<Vec<Relation>>> {
        parse_field(field, self.control.get(field).map(String::as_str)).map_err(|e| {
            Error::new(format!(
                "parsing file '{}' package '{}': {}",
                self.path.join("DEBIAN/control").display(),
                self.name,
                e.message()
            ))
        })
    }

    /// Check every relationship field, as dpkg -i does before it unpacks the package.
    ///
    /// # Errors
    /// The first field dpkg refuses.
    pub fn check_relations(&self) -> Result<()> {
        for field in FIELDS {
            self.relations(field)?;
        }
        Ok(())
    }

    /// Pre-Depends, then Depends.
    ///
    /// # Errors
    /// A field cannot be parsed.
    pub fn depends(&self) -> Result<Vec<Vec<Relation>>> {
        let mut d = self.relations("Pre-Depends")?;
        d.extend(self.relations("Depends")?);
        Ok(d)
    }

    /// The Provides entries (one per group: the field takes no alternatives).
    ///
    /// # Errors
    /// The field cannot be parsed.
    pub fn provides(&self) -> Result<Vec<Relation>> {
        Ok(self
            .relations("Provides")?
            .into_iter()
            .filter_map(|g| g.into_iter().next())
            .collect())
    }

    /// Whether this package satisfies `rel`, by its name and version or through a
    /// Provides (versioned or not), as dpkg >= 1.17.11 accepts it.
    ///
    /// # Errors
    /// An invalid version or Provides field.
    pub fn satisfies(&self, rel: &Relation) -> Result<bool> {
        if self.name == rel.name && rel.matches(Some(self.version()))? {
            return Ok(true);
        }
        for p in self.provides()? {
            if p.name == rel.name && rel.matches(p.version.as_deref())? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn libc_eisdir() -> i32 {
    Errno::EISDIR as i32
}

/// The directories in `dir` (symlinks followed), as `Path.glob("*")` lists them for a
/// pattern that continues below them; an unreadable directory has none.
fn glob_dirs(dir: &Path) -> Result<Vec<OsString>> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Ok(Vec::new()),
        Err(e) => return Err(Error::os(&e, dir)),
    };
    let mut out = Vec::new();
    for e in rd {
        let e = e.at(dir)?;
        if fsx::is_dir(&e.path()) {
            out.push(e.file_name());
        }
    }
    Ok(out)
}

/// The staged packages of `stagedir` (`*/*/DEBIAN/control`; `.`-directories skipped),
/// by name, in path order.
///
/// # Errors
/// A package is staged twice, its control file is invalid, or it cannot be read.
pub fn load_staged(stagedir: &Path) -> Result<IndexMap<String, Package>> {
    // Each staged output loaded from one generation (the data.tar files stay open).
    let _lock = staged_lock::read_output(stagedir).at(stagedir)?;
    let mut found: Vec<(OsString, OsString)> = Vec::new();
    // Path.glob() lists nothing in what is not a directory.
    let top = if fsx::is_dir(stagedir) {
        glob_dirs(stagedir)?
    } else {
        Vec::new()
    };
    for d1 in top {
        for d2 in glob_dirs(&stagedir.join(&d1))? {
            let debian = stagedir.join(&d1).join(&d2).join("DEBIAN");
            if fsx::is_dir(&debian) && fsx::exists(&debian.join("control")) {
                found.push((d1.clone(), d2));
            }
        }
    }
    found.sort();
    let mut staged: IndexMap<String, Package> = IndexMap::new();
    for (d1, d2) in found {
        // .work.* directories are stage runs in progress.
        if d1.as_bytes().starts_with(b".") || d2.as_bytes().starts_with(b".") {
            continue;
        }
        let path = stagedir.join(&d1).join(&d2);
        let p = Package::load(path, &d2.to_string_lossy())?;
        if let Some(prev) = staged.get(&p.name) {
            return Err(Error::new(format!(
                "{} is staged twice: in {} and {}",
                p.name,
                prev.path.display(),
                p.path.display()
            )));
        }
        staged.insert(p.name.clone(), p);
    }
    Ok(staged)
}
