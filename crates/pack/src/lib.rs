//! `debbuild-rs pack`: staged package trees into .deb files, as `dpkg-deb --build` does.
//!
//! A staged tree (see `debbuild-rs builddeb`) already holds the two members of a .deb:
//! DEBIAN/ becomes control.tar and data.tar is compressed as it is. Both are compressed
//! the same way (dpkg-deb's uniform compression), with the options recorded in
//! dpkg-deb.options (default: xz -6), and every timestamp is clamped to the epoch, so
//! that a staged tree and an epoch always give the same .deb, byte for byte. The epoch
//! of a tree is the `SOURCE_DATE_EPOCH` it was staged with, recorded in staged.info:
//! its data.tar was clamped to it, so any other epoch would make a .deb dpkg-deb
//! never makes from the same build. The
//! compressors always run multithreaded: their output does not depend on the number
//! of threads.
//!
//! Each tree is first checked as dpkg-deb --build checks a package tree (control file,
//! maintainer script modes, conffiles present), its conffiles looked up in data.tar as
//! `lstat` looks them up on disk, whose paths must stay under the root.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use debbuild_rs_common::{Error, IoContext, Result, deb822, staged_lock, validate};
use sha2::{Digest, Sha256};

/// The help text of `debbuild-rs pack`.
pub const ABOUT: &str = "Pack staged package trees into .deb files, as dpkg-deb --build does.

Each STAGED is a staged source directory (OUTDIR/<dir> of `debbuild-rs stage`, whose
.staged lists its packages) or a single staged package tree. The .deb files are written
to DESTDIR as <package>_<version>_<architecture>.deb, and their paths printed, one per
line. They are compressed with the dpkg-deb options the rules gave dh_builddeb (default:
xz -6), and their timestamps are clamped to the epoch: the same staged tree gives the
same .deb.

The epoch is the SOURCE_DATE_EPOCH the tree was staged with, recorded in its
staged.info; --epoch, if given, must be that one. Trees staged without a record take
--epoch, otherwise SOURCE_DATE_EPOCH, otherwise the current time.

A tree dpkg-deb --build would refuse (control file, maintainer script modes,
conffiles) is refused.";

pub struct Options {
    /// Staged source directories or staged package trees.
    pub staged: Vec<PathBuf>,
    /// Where the .deb files go.
    pub destdir: PathBuf,
    /// The epoch the trees must have been staged with, and the epoch of trees without
    /// staged.info. Unset, those take `SOURCE_DATE_EPOCH`, otherwise the current time.
    pub epoch: Option<u64>,
}

/// The staged.info format this version reads.
const INFO_FORMAT: &str = "1";

/// The epoch a staged tree records in staged.info (`Format: 1`, `Epoch: <seconds>`),
/// or `None` for a tree staged without one.
///
/// # Errors
/// An unreadable or invalid staged.info, or an unknown format.
pub fn recorded_epoch(tree: &Path) -> Result<Option<u64>> {
    let path = tree.join("staged.info");
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::os(&e, &path)),
    };
    let bad = |what: &str| Error::new(format!("{}: {what}", path.display()));
    let stanzas = deb822::parse_stanzas(&text).map_err(|e| bad(&e.to_string()))?;
    let [stanza] = stanzas.as_slice() else {
        return Err(bad("not one stanza"));
    };
    match stanza.get("Format").map(String::as_str) {
        Some(INFO_FORMAT) => {}
        Some(f) => return Err(bad(&format!("unknown format '{f}'"))),
        None => return Err(bad("no Format field")),
    }
    stanza
        .get("Epoch")
        .filter(|e| !e.is_empty() && e.bytes().all(|c| c.is_ascii_digit()))
        .and_then(|e| e.parse().ok())
        .map(Some)
        .ok_or_else(|| bad("no valid Epoch field"))
}

/// The epoch of trees without staged.info, `--epoch` unset: `SOURCE_DATE_EPOCH`,
/// otherwise the current time.
///
/// # Errors
/// An invalid `SOURCE_DATE_EPOCH`.
fn unrecorded_epoch() -> Result<u64> {
    match std::env::var_os("SOURCE_DATE_EPOCH") {
        Some(e) if !e.is_empty() => e
            .to_str()
            .filter(|s| s.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| {
                Error::new(format!(
                    "invalid SOURCE_DATE_EPOCH '{}' in the environment",
                    e.to_string_lossy()
                ))
            }),
        _ => Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())),
    }
}

/// The epoch to pack `tree` with: the recorded one, which `given` must match, otherwise
/// `given`, otherwise [`unrecorded_epoch`].
fn tree_epoch(tree: &Path, given: Option<u64>) -> Result<u64> {
    match (recorded_epoch(tree)?, given) {
        (Some(r), Some(g)) if r != g => Err(Error::new(format!(
            "{}: staged with epoch {r}, not {g}",
            tree.display()
        ))),
        (Some(e), _) | (None, Some(e)) => Ok(e),
        (None, None) => unrecorded_epoch(),
    }
}

/// A dpkg-deb compression type (`-Z`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Gzip,
    Xz,
    Zstd,
    None,
}

/// The compression of both members, from dpkg-deb's `-Z`, `-z` and `-S` options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compression {
    pub kind: Kind,
    /// dpkg-deb's default for the type when unset: 9 (gzip), 6 (xz), 3 (zstd).
    pub level: Option<u32>,
    /// `-Sextreme` (xz).
    pub extreme: bool,
}

impl Default for Compression {
    fn default() -> Self {
        Self {
            kind: Kind::Xz,
            level: None,
            extreme: false,
        }
    }
}

impl Compression {
    /// Parse the dpkg-deb options `-Z<type>`, `-z<level>` and `-S<strategy>`, the forms
    /// the rules use; anything else is refused rather than ignored.
    ///
    /// # Errors
    /// An unsupported option or value.
    pub fn from_options<S: AsRef<str>>(opts: &[S]) -> Result<Self> {
        let mut c = Self::default();
        let mut strategy = None;
        for opt in opts {
            let opt = opt.as_ref();
            if let Some(t) = opt.strip_prefix("-Z") {
                c.kind = match t {
                    "gzip" => Kind::Gzip,
                    "xz" => Kind::Xz,
                    "zstd" => Kind::Zstd,
                    "none" => Kind::None,
                    _ => return Err(Error::new(format!("unknown compression type '{t}'"))),
                };
            } else if let Some(l) = opt.strip_prefix("-z") {
                c.level = Some(
                    l.parse()
                        .map_err(|_| Error::new(format!("invalid compression level '{l}'")))?,
                );
            } else if let Some(s) = opt.strip_prefix("-S") {
                strategy = Some(s.to_owned());
            } else {
                return Err(Error::new(format!("unsupported dpkg-deb option '{opt}'")));
            }
        }
        match (strategy.as_deref(), c.kind) {
            (None | Some("none"), _) => {}
            (Some("extreme"), Kind::Xz) => c.extreme = true,
            (Some(s), _) => {
                return Err(Error::new(format!(
                    "compression strategy '{s}' is not supported with {:?}",
                    c.kind
                )));
            }
        }
        let max = match c.kind {
            Kind::Gzip | Kind::Xz => 9,
            Kind::Zstd => 22,
            Kind::None => u32::MAX,
        };
        if let Some(l) = c.level
            && (l > max || (c.kind == Kind::Zstd && l == 0))
        {
            return Err(Error::new(format!(
                "compression level {l} out of range for {:?}",
                c.kind
            )));
        }
        Ok(c)
    }

    /// The member name suffix.
    fn ext(self) -> &'static str {
        match self.kind {
            Kind::Gzip => ".gz",
            Kind::Xz => ".xz",
            Kind::Zstd => ".zst",
            Kind::None => "",
        }
    }

    /// Compress `input` into `out`, with up to `threads` threads.
    fn compress(self, input: &mut impl Read, out: &mut File, threads: u32) -> io::Result<()> {
        let threads = threads.max(1);
        match self.kind {
            Kind::Gzip => {
                let level = flate2::Compression::new(self.level.unwrap_or(9));
                let mut enc = flate2::write::GzEncoder::new(out, level);
                io::copy(input, &mut enc)?;
                enc.finish()?;
            }
            Kind::Xz => {
                let mut preset = self.level.unwrap_or(6);
                if self.extreme {
                    preset |= liblzma::stream::PRESET_EXTREME;
                }
                let stream = liblzma::stream::MtStreamBuilder::new()
                    .preset(preset)
                    .threads(threads)
                    .check(liblzma::stream::Check::Crc64)
                    .encoder()
                    .map_err(io::Error::other)?;
                let mut enc = liblzma::write::XzEncoder::new_stream(out, stream);
                io::copy(input, &mut enc)?;
                enc.finish()?;
            }
            Kind::Zstd => {
                let level = i32::try_from(self.level.unwrap_or(3)).unwrap_or(i32::MAX);
                let mut enc = zstd::stream::write::Encoder::new(out, level)?;
                enc.multithread(threads)?;
                io::copy(input, &mut enc)?;
                enc.finish()?;
            }
            Kind::None => {
                io::copy(input, out)?;
            }
        }
        Ok(())
    }
}

/// The 60-byte header of an ar member, as dpkg-deb writes it: owner 0/0, mode 100644.
fn ar_header(name: &str, epoch: u64, size: u64) -> Vec<u8> {
    format!(
        "{name:<16}{epoch:<12}{:<6}{:<6}{:<8}{size:<10}`\n",
        0, 0, 100_644
    )
    .into_bytes()
}

/// Append an ar member from `data` (`size` bytes), padded to an even size.
fn ar_member(
    out: &mut impl Write,
    name: &str,
    epoch: u64,
    size: u64,
    data: &mut impl Read,
) -> io::Result<()> {
    out.write_all(&ar_header(name, epoch, size))?;
    let copied = io::copy(data, out)?;
    if copied != size {
        return Err(io::Error::other(format!(
            "{name}: {copied} bytes instead of {size}"
        )));
    }
    if size & 1 == 1 {
        out.write_all(b"\n")?;
    }
    Ok(())
}

/// A tar header for `name`, owned by root, its timestamp clamped to `epoch`.
fn tar_header(
    name: &str,
    kind: tar::EntryType,
    mode: u32,
    size: u64,
    mtime: i64,
    epoch: u64,
) -> Result<tar::Header> {
    let mut h = tar::Header::new_gnu();
    // set_path would drop the leading ./ dpkg-deb writes.
    let field = h
        .as_old_mut()
        .name
        .get_mut(..name.len())
        .ok_or_else(|| Error::new(format!("{name}: name too long for control.tar")))?;
    field.copy_from_slice(name.as_bytes());
    h.set_entry_type(kind);
    h.set_mode(mode & 0o7777);
    h.set_size(size);
    h.set_mtime(u64::try_from(mtime).unwrap_or(0).min(epoch));
    h.set_uid(0);
    h.set_gid(0);
    h.set_username("root").at(Path::new(name))?;
    h.set_groupname("root").at(Path::new(name))?;
    gnu_cksum(&mut h);
    Ok(h)
}

/// Set the checksum the way GNU tar writes it: six octal digits, NUL, space (the tar crate
/// writes seven digits and a NUL).
fn gnu_cksum(h: &mut tar::Header) {
    let field = &mut h.as_old_mut().cksum;
    field.fill(b' ');
    let sum = h
        .as_bytes()
        .iter()
        .fold(0u32, |sum, &b| sum.wrapping_add(u32::from(b)));
    let text = format!("{sum:06o}\0 ");
    h.as_old_mut().cksum.copy_from_slice(text.as_bytes());
}

/// The mode of a control.tar entry: dpkg-deb packs DEBIAN/ with `--mode=go=rX,u+rw,a-s`.
#[must_use]
pub fn control_mode(mode: u32, dir: bool) -> u32 {
    let x = dir || mode & 0o111 != 0;
    (mode & 0o1700) | 0o600 | 0o044 | if x { 0o011 } else { 0 }
}

/// control.tar: `./` and the files of DEBIAN/, by name.
fn control_tar(debian: &Path, epoch: u64) -> Result<Vec<u8>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(debian).at(debian)? {
        let entry = entry.at(debian)?;
        let name = entry.file_name().into_string().map_err(|n| {
            Error::new(format!(
                "{}: non-UTF-8 name {}",
                debian.display(),
                n.display()
            ))
        })?;
        names.push(name);
    }
    names.sort();
    let mut tar = tar::Builder::new(Vec::new());
    let meta = fs::metadata(debian).at(debian)?;
    let h = tar_header(
        "./",
        tar::EntryType::Directory,
        control_mode(meta.mode(), true),
        0,
        meta.mtime(),
        epoch,
    )?;
    tar.append(&h, io::empty()).at(debian)?;
    for name in names {
        let path = debian.join(&name);
        let meta = fs::symlink_metadata(&path).at(&path)?;
        if !meta.is_file() {
            return Err(Error::new(format!(
                "{}: not a regular file",
                path.display()
            )));
        }
        let h = tar_header(
            &format!("./{name}"),
            tar::EntryType::Regular,
            control_mode(meta.mode(), false),
            meta.len(),
            meta.mtime(),
            epoch,
        )?;
        tar.append(&h, File::open(&path).at(&path)?).at(&path)?;
    }
    let mut tar = tar.into_inner().at(debian)?;
    // GNU tar fills the last record of 20 blocks.
    tar.resize(tar.len().next_multiple_of(RECORD), 0);
    Ok(tar)
}

/// The record size of GNU tar's default blocking factor (20 blocks of 512 bytes).
const RECORD: usize = 10_240;

/// A reader hashing what it reads.
struct Hashing<R> {
    inner: R,
    hash: Sha256,
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hash.update(buf.get(..n).unwrap_or_default());
        Ok(n)
    }
}

/// The value of a control field, or an error naming the tree.
fn field<'a>(stanza: &'a deb822::Stanza, name: &str, tree: &Path) -> Result<&'a str> {
    stanza
        .get(name)
        .map(String::as_str)
        .filter(|v| !v.is_empty() && !v.contains(char::is_whitespace) && !v.contains('/'))
        .ok_or_else(|| {
            Error::new(format!(
                "{}/DEBIAN/control: no valid {name} field",
                tree.display()
            ))
        })
}

/// The file tree of data.tar; an error for a path that would install outside the root.
fn data_paths(data: &Path) -> Result<validate::Payload> {
    let mut archive = tar::Archive::new(BufReader::new(File::open(data).at(data)?));
    let mut paths = validate::Payload::default();
    for entry in archive.entries_with_seek().at(data)? {
        let entry = entry.at(data)?;
        let name = entry.path_bytes();
        if let Some(why) = validate::payload_path_problem(&name) {
            return Err(Error::new(format!(
                "{}: {}: {why}",
                data.display(),
                String::from_utf8_lossy(&name)
            )));
        }
        let member = match entry.header().entry_type() {
            tar::EntryType::Directory => validate::Member::Dir,
            tar::EntryType::Symlink => {
                validate::Member::Symlink(entry.link_name_bytes().unwrap_or_default().into_owned())
            }
            _ => validate::Member::Other,
        };
        paths.insert(&name, member);
    }
    Ok(paths)
}

/// Pack one staged package tree into `destdir`, compressing with up to `threads`
/// threads (the .deb does not depend on it); return the .deb path.
///
/// # Errors
/// Invalid staged data, a tree dpkg-deb --build would refuse, a data.tar not matching
/// data.tar.sha256, or a failed write.
pub fn pack_tree(tree: &Path, destdir: &Path, epoch: u64, threads: u32) -> Result<PathBuf> {
    let payload = data_paths(&tree.join("data.tar"))?;
    let stanza = validate::package(tree, |name| payload.lstat(name))?;
    let package = field(&stanza, "Package", tree)?;
    let version = field(&stanza, "Version", tree)?;
    let arch = field(&stanza, "Architecture", tree)?;
    // The file name drops the epoch.
    let version = version.split_once(':').map_or(version, |(_, v)| v);

    let opts_path = tree.join("dpkg-deb.options");
    let compression = match fs::read_to_string(&opts_path) {
        Ok(text) => Compression::from_options(&text.lines().collect::<Vec<_>>())
            .map_err(|e| Error::new(format!("{}: {e}", opts_path.display())))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Compression::default(),
        Err(e) => return Err(Error::os(&e, &opts_path)),
    };

    let ctrl = control_tar(&tree.join("DEBIAN"), epoch)?;
    let mut ctrl_z = tempfile::tempfile_in(destdir).at(destdir)?;
    compression
        .compress(&mut ctrl.as_slice(), &mut ctrl_z, 1)
        .at(&tree.join("DEBIAN"))?;

    let data_path = tree.join("data.tar");
    let mut data = Hashing {
        inner: BufReader::with_capacity(1 << 20, File::open(&data_path).at(&data_path)?),
        hash: Sha256::new(),
    };
    let mut data_z = tempfile::tempfile_in(destdir).at(destdir)?;
    compression
        .compress(&mut data, &mut data_z, threads)
        .at(&data_path)?;
    let sum_path = tree.join("data.tar.sha256");
    match fs::read_to_string(&sum_path) {
        Ok(recorded) => {
            let actual = data
                .hash
                .finalize()
                .iter()
                .fold(String::with_capacity(64), |mut s, b| {
                    use std::fmt::Write as _;
                    // Writing to a String cannot fail.
                    let _ = write!(s, "{b:02x}");
                    s
                });
            if recorded.trim_end() != actual {
                return Err(Error::new(format!(
                    "{}: does not match {}",
                    data_path.display(),
                    sum_path.display()
                )));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::os(&e, &sum_path)),
    }

    let deb_path = destdir.join(format!("{package}_{version}_{arch}.deb"));
    let mut deb = tempfile::NamedTempFile::new_in(destdir).at(destdir)?;
    {
        let mut out = io::BufWriter::new(deb.as_file_mut());
        out.write_all(b"!<arch>\n").at(&deb_path)?;
        ar_member(&mut out, "debian-binary", epoch, 4, &mut &b"2.0\n"[..]).at(&deb_path)?;
        for (name, f) in [("control.tar", &mut ctrl_z), ("data.tar", &mut data_z)] {
            let size = f.seek(SeekFrom::End(0)).at(&deb_path)?;
            f.seek(SeekFrom::Start(0)).at(&deb_path)?;
            let name = format!("{name}{}", compression.ext());
            ar_member(&mut out, &name, epoch, size, f).at(&deb_path)?;
        }
        out.flush().at(&deb_path)?;
    }
    deb.as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))
        .at(&deb_path)?;
    deb.persist(&deb_path)
        .map_err(|e| Error::os(&e.error, &deb_path))?;
    Ok(deb_path)
}

/// The package trees of a staged source directory (listed in its .staged), or the
/// staged package tree itself.
///
/// # Errors
/// Neither a staged source directory nor a staged package tree.
pub fn trees(staged: &Path) -> Result<Vec<PathBuf>> {
    let list = staged.join(".staged");
    match fs::read_to_string(&list) {
        Ok(text) => Ok(text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| staged.join(l))
            .collect()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if staged.join("DEBIAN/control").is_file() {
                Ok(vec![staged.to_path_buf()])
            } else {
                Err(Error::new(format!(
                    "{}: neither a staged source directory nor a staged package",
                    staged.display()
                )))
            }
        }
        Err(e) => Err(Error::os(&e, &list)),
    }
}

/// The data.tar size from which a tree is packed alone, with every thread: xz -6
/// compresses blocks of 24 MiB in parallel, a smaller data.tar is one block.
const BIG: u64 = 24 << 20;

/// Pack `trees` into `destdir`: the big ones one at a time with `threads` threads, then
/// the others `threads` at a time with one each, so that at most `threads` compressor
/// threads run. The results are in the order of `trees`.
fn pack_trees(
    trees: &[PathBuf],
    destdir: &Path,
    epoch: Option<u64>,
    threads: usize,
) -> Vec<Result<PathBuf>> {
    let one = |tree: &PathBuf, threads: usize| {
        let epoch = tree_epoch(tree, epoch)?;
        pack_tree(
            tree,
            destdir,
            epoch,
            u32::try_from(threads).unwrap_or(u32::MAX),
        )
    };
    let big = |tree: &PathBuf| fs::metadata(tree.join("data.tar")).is_ok_and(|m| m.len() >= BIG);
    let mut out: Vec<Option<Result<PathBuf>>> = trees
        .iter()
        .map(|t| big(t).then(|| one(t, threads)))
        .collect();
    let small: Vec<usize> = (0..trees.len())
        .filter(|&i| out.get(i).is_some_and(Option::is_none))
        .collect();
    let next = AtomicUsize::new(0);
    std::thread::scope(|s| {
        let workers: Vec<_> = (0..threads.min(small.len()))
            .map(|_| {
                s.spawn(|| {
                    let mut done = Vec::new();
                    while let Some(&i) = small.get(next.fetch_add(1, Ordering::Relaxed)) {
                        if let Some(tree) = trees.get(i) {
                            done.push((i, one(tree, 1)));
                        }
                    }
                    done
                })
            })
            .collect();
        for w in workers {
            for (i, r) in w.join().unwrap_or_default() {
                if let Some(slot) = out.get_mut(i) {
                    *slot = Some(r);
                }
            }
        }
    });
    out.into_iter()
        .map(|r| r.unwrap_or_else(|| Err(Error::new("a packing thread failed".to_owned()))))
        .collect()
}

/// Pack every staged package of `opts.staged` into `opts.destdir`, each with its epoch
/// (see [`Options::epoch`]), calling `done` with each .deb in order. The trees of a
/// staged directory are packed in parallel.
///
/// # Errors
/// The first failure in order, an epoch not matching the recorded one included; the
/// .deb files written before it stay, and those of the same staged directory packed
/// alongside it.
pub fn pack(opts: &Options, mut done: impl FnMut(&Path)) -> Result<()> {
    fs::create_dir_all(&opts.destdir).at(&opts.destdir)?;
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    for staged in &opts.staged {
        // Its trees from one generation of the staged output.
        let _lock = staged_lock::read_staged(staged).at(staged)?;
        for deb in pack_trees(&trees(staged)?, &opts.destdir, opts.epoch, threads) {
            done(&deb?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options() {
        assert_eq!(
            Compression::from_options::<&str>(&[]).unwrap(),
            Compression::default()
        );
        assert_eq!(
            Compression::from_options(&["-Zzstd", "-z19"]).unwrap(),
            Compression {
                kind: Kind::Zstd,
                level: Some(19),
                extreme: false
            }
        );
        assert!(
            Compression::from_options(&["-Zxz", "-Sextreme"])
                .unwrap()
                .extreme
        );
        for bad in [
            &["-Zbz2"][..],
            &["-zx"],
            &["-Zgzip", "-Sextreme"],
            &["-Zxz", "-z10"],
            &["-Zzstd", "-z0"],
            &["--threads-max=2"],
        ] {
            assert!(Compression::from_options(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn control_modes() {
        assert_eq!(control_mode(0o775, true), 0o755);
        assert_eq!(control_mode(0o700, true), 0o755);
        assert_eq!(control_mode(0o664, false), 0o644);
        assert_eq!(control_mode(0o400, false), 0o644);
        assert_eq!(control_mode(0o4750, false), 0o755);
        assert_eq!(control_mode(0o500, false), 0o755);
    }

    #[test]
    fn ar_headers() {
        let h = ar_header("debian-binary", 1_700_000_000, 4);
        assert_eq!(
            h,
            b"debian-binary   1700000000  0     0     100644  4         `\n"
        );
    }
}
