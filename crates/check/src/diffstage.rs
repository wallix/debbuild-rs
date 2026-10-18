//! `debbuild-rs diff-stage A B`: compare two staged trees, as two stage runs of the same
//! source tree must produce them.
//!
//! Both sides are validated first, then compared at one of two levels: what `pack` would
//! make of them (the default), or what `install` would leave on disk. Every difference is
//! reported; the payloads are walked member by member, their contents hashed.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use debbuild_rs_common::{deb822, staged_lock};
use debbuild_rs_pack::{Compression, Kind, control_mode};
use sha2::{Digest, Sha256};

use crate::util::{Error, Result, err};

/// The help text of `debbuild-rs diff-stage`.
pub const ABOUT: &str =
    "Compare two staged trees, as two stage runs of the same source must produce them.

A and B are both staged source directories (OUTDIR/<dir>, holding .staged) or both output
directories (OUTDIR, each <dir> holding a .staged). Each side is validated first: .staged
lists existing package trees, each with DEBIAN/control, a data.tar matching its
data.tar.sha256, and valid dpkg-deb.options and staged.info when present. An invalid side
is an error, not a difference.

Default, pack-equivalence: would `debbuild-rs pack` make the same .deb files of A and B.
Compared: the compression dpkg-deb.options selects, the epoch staged.info records, the
control files' contents and the modes and timestamps pack writes for them (timestamps
when both sides record their epoch), and data.tar byte for byte.

--install, install-equivalence: would `debbuild-rs install` leave the same files. Compared:
the control files' contents and modes, and each payload member's type, mode, owner,
content and link target; compression, epoch and modification times aside.

Every difference is printed, one per line; past 50 payload members of a package, only
their count. Exit status: 0 equal, 1 different, 2 invalid side or failure.";

/// What the comparison asks of two staged trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// `pack` makes the same .deb files of them.
    Pack,
    /// `install` leaves the same files from them.
    Install,
}

/// Differences, one line each.
pub type Report = Vec<String>;

/// The payload members reported per package; the others are counted.
const MAX_MEMBERS: usize = 50;

/// A control file, or DEBIAN/ itself, as pack reads it.
struct ControlFile {
    mode: u32,
    mtime: i64,
    digest: Vec<u8>,
}

/// dpkg-deb's compression: type, level, `-Sextreme`.
pub(crate) type Packing = (Kind, u32, bool);

/// A validated staged package tree.
pub(crate) struct Tree {
    pub(crate) compression: Packing,
    /// The epoch of staged.info, if the tree has one.
    pub(crate) epoch: Option<u64>,
    debian: ControlFile,
    control: BTreeMap<String, ControlFile>,
    data_digest: Vec<u8>,
}

/// The staged packages of a source directory, by name.
pub(crate) type Source = BTreeMap<String, Tree>;

fn sha256(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut hash = Sha256::new();
    let mut buf = vec![0; 1 << 16];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return Ok(hash.finalize().to_vec()),
            Ok(n) => hash.update(buf.get(..n).unwrap_or_default()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_opt(path: &Path) -> io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(d) => Ok(Some(d)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// The compression of dpkg-deb.options with the type's default level filled in: options
/// `pack` turns into the same bytes compare equal.
fn compression(opts: &str) -> debbuild_rs_common::Result<Packing> {
    let c = Compression::from_options(&opts.lines().collect::<Vec<_>>())?;
    let level = match c.kind {
        Kind::Gzip => c.level.unwrap_or(9),
        Kind::Xz => c.level.unwrap_or(6),
        Kind::Zstd => c.level.unwrap_or(3),
        Kind::None => 0,
    };
    Ok((c.kind, level, c.extreme))
}

pub(crate) fn compression_name((kind, level, extreme): Packing) -> String {
    let name = match kind {
        Kind::Gzip => "gzip",
        Kind::Xz => "xz",
        Kind::Zstd => "zstd",
        Kind::None => return "none".to_owned(),
    };
    format!("{name} -{level}{}", if extreme { "e" } else { "" })
}

/// The epoch of a staged.info stanza (`Format: 1`, `Epoch: <seconds>`).
fn epoch_of(info: &str) -> std::result::Result<u64, String> {
    let stanzas = deb822::parse_stanzas(info).map_err(|e| e.to_string())?;
    let stanza = stanzas.first().ok_or("empty")?;
    match stanza.get("Format").map(String::as_str) {
        Some("1") => {}
        Some(f) => return Err(format!("unsupported Format {f}")),
        None => return Err("no Format field".to_owned()),
    }
    let epoch = stanza.get("Epoch").ok_or("no Epoch field")?;
    epoch.parse().map_err(|_| format!("invalid Epoch {epoch}"))
}

fn control_file(path: &Path, digest: Vec<u8>) -> io::Result<ControlFile> {
    let meta = fs::metadata(path)?;
    Ok(ControlFile {
        mode: meta.mode(),
        mtime: meta.mtime(),
        digest,
    })
}

/// The control files of DEBIAN/, by name; what pack would refuse goes to `problem`.
fn control_files(debian: &Path, problem: &mut impl FnMut(String)) -> BTreeMap<String, ControlFile> {
    let mut control = BTreeMap::new();
    let entries = match fs::read_dir(debian) {
        Ok(e) => e,
        Err(e) => {
            problem(format!("DEBIAN: {e}"));
            return control;
        }
    };
    for e in entries {
        let e = match e {
            Ok(e) => e,
            Err(e) => {
                problem(format!("DEBIAN: {e}"));
                break;
            }
        };
        let Ok(name) = e.file_name().into_string() else {
            problem(format!(
                "DEBIAN/{}: non-UTF-8 name",
                e.file_name().display()
            ));
            continue;
        };
        let path = e.path();
        if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
            problem(format!("DEBIAN/{name}: not a regular file"));
            continue;
        }
        match File::open(&path)
            .and_then(|mut f| sha256(&mut f))
            .and_then(|d| control_file(&path, d))
        {
            Ok(f) => {
                control.insert(name, f);
            }
            Err(e) => problem(format!("DEBIAN/{name}: {e}")),
        }
    }
    if !control.contains_key("control") {
        problem("no DEBIAN/control".to_owned());
    }
    control
}

/// Read and validate a staged package tree; what is missing or invalid goes to `problems`.
fn load_tree(dir: &Path, problems: &mut Vec<String>) -> Option<Tree> {
    let n = problems.len();
    let mut problem = |what: String| problems.push(format!("{}: {what}", dir.display()));
    if !dir.is_dir() {
        problem("listed in .staged, missing".to_owned());
        return None;
    }

    let debian = control_file(&dir.join("DEBIAN"), Vec::new())
        .map_err(|e| problem(format!("DEBIAN: {e}")))
        .ok();
    let control = control_files(&dir.join("DEBIAN"), &mut problem);

    let data_digest = File::open(dir.join("data.tar"))
        .and_then(|f| sha256(&mut BufReader::new(f)))
        .map_err(|e| problem(format!("data.tar: {e}")))
        .ok();
    match (read_opt(&dir.join("data.tar.sha256")), &data_digest) {
        (Ok(Some(sum)), Some(d)) if sum.trim_end() != hex(d) => {
            problem("data.tar does not match data.tar.sha256".to_owned());
        }
        (Err(e), _) => problem(format!("data.tar.sha256: {e}")),
        _ => {}
    }

    let compression = read_opt(&dir.join("dpkg-deb.options"))
        .map_err(|e| e.to_string())
        .and_then(|o| compression(o.as_deref().unwrap_or_default()).map_err(|e| e.to_string()))
        .map_err(|e| problem(format!("dpkg-deb.options: {e}")))
        .ok();
    let epoch = read_opt(&dir.join("staged.info"))
        .map_err(|e| e.to_string())
        .and_then(|i| i.as_deref().map(epoch_of).transpose())
        .map_err(|e| problem(format!("staged.info: {e}")));

    if problems.len() != n {
        return None;
    }
    Some(Tree {
        compression: compression?,
        epoch: epoch.ok()?,
        debian: debian?,
        control,
        data_digest: data_digest?,
    })
}

/// Read and validate the staged packages of a source directory.
pub(crate) fn load_source(dir: &Path, problems: &mut Vec<String>) -> Option<Source> {
    let list = match fs::read_to_string(dir.join(".staged")) {
        Ok(l) => l,
        Err(e) => {
            problems.push(format!("{}/.staged: {e}", dir.display()));
            return None;
        }
    };
    let n = problems.len();
    let mut source = Source::new();
    for pkg in list.lines().filter(|l| !l.is_empty()) {
        if pkg.contains('/') || pkg.starts_with('.') {
            problems.push(format!(
                "{}/.staged: invalid package {pkg:?}",
                dir.display()
            ));
        } else if let Some(t) = load_tree(&dir.join(pkg), problems) {
            source.insert(pkg.to_owned(), t);
        }
    }
    (problems.len() == n).then_some(source)
}

/// The staged source directories of an output directory, by name.
pub(crate) fn staged_dirs(outdir: &Path) -> io::Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for e in fs::read_dir(outdir)? {
        let e = e?;
        let name = e.file_name();
        if !name.as_bytes().starts_with(b".") && e.path().join(".staged").is_file() {
            out.insert(name.to_string_lossy().into_owned());
        }
    }
    Ok(out)
}

fn side(in_a: bool) -> &'static str {
    if in_a { "A" } else { "B" }
}

/// A timestamp as pack writes it: clamped to the epoch.
fn clamped(mtime: i64, epoch: u64) -> u64 {
    u64::try_from(mtime).unwrap_or(0).min(epoch)
}

/// The differences of a control file, or of DEBIAN/ itself (`dir`); timestamps with
/// both sides' epochs.
fn control_differences(
    a: &ControlFile,
    b: &ControlFile,
    dir: bool,
    epochs: Option<(u64, u64)>,
) -> Vec<String> {
    let mut what = Vec::new();
    let (ma, mb) = (control_mode(a.mode, dir), control_mode(b.mode, dir));
    if ma != mb {
        what.push(format!("mode {ma:04o} != {mb:04o}"));
    }
    if let Some((ea, eb)) = epochs {
        let (ta, tb) = (clamped(a.mtime, ea), clamped(b.mtime, eb));
        if ta != tb {
            what.push(format!("mtime {ta} != {tb}"));
        }
    }
    if a.digest != b.digest {
        what.push("content differs".to_owned());
    }
    what
}

/// A data.tar member: its position, header fields and content digest.
struct Member {
    index: u64,
    kind: u8,
    mode: u32,
    uid: u64,
    gid: u64,
    uname: Vec<u8>,
    gname: Vec<u8>,
    mtime: u64,
    size: u64,
    link: Option<Vec<u8>>,
    header: Vec<u8>,
    digest: Vec<u8>,
}

type Archive = tar::Archive<BufReader<File>>;
type Entries<'a> = tar::Entries<'a, BufReader<File>>;

fn entries<'a>(ar: &'a mut Archive, tar: &Path) -> Result<Entries<'a>> {
    ar.entries()
        .map_err(|e| err(format!("{}: {e}", tar.display())))
}

/// The next member of an archive and its path, numbered by `index`.
fn next_member(
    entries: &mut Entries<'_>,
    index: &mut u64,
    tar: &Path,
) -> Result<Option<(Vec<u8>, Member)>> {
    let read = |e: &mut tar::Entry<'_, BufReader<File>>| -> io::Result<(Vec<u8>, Member)> {
        let path = e.path_bytes().into_owned();
        let h = e.header();
        let m = Member {
            index: *index,
            kind: h.entry_type().as_byte(),
            mode: h.mode()?,
            uid: h.uid()?,
            gid: h.gid()?,
            uname: h.username_bytes().unwrap_or_default().to_vec(),
            gname: h.groupname_bytes().unwrap_or_default().to_vec(),
            mtime: h.mtime()?,
            size: h.size()?,
            link: e.link_name_bytes().map(std::borrow::Cow::into_owned),
            header: h.as_bytes().to_vec(),
            digest: Vec::new(),
        };
        let digest = sha256(e)?;
        Ok((path, Member { digest, ..m }))
    };
    let m = entries
        .next()
        .map(|e| e.and_then(|mut e| read(&mut e)))
        .transpose()
        .map_err(|e| err(format!("{}: {e}", tar.display())))?;
    *index = index.saturating_add(1);
    Ok(m)
}

/// The member type as install reads it: old-style regular files, directories by their
/// trailing slash.
fn install_kind(path: &[u8], kind: u8) -> u8 {
    match kind {
        b'\0' | b'0' if path.ends_with(b"/") => b'5',
        b'\0' => b'0',
        k => k,
    }
}

fn lossy(b: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(b)
}

/// What differs between two members of the same path, at `level`.
fn member_differences(path: &[u8], a: &Member, b: &Member, level: Level) -> Vec<String> {
    let mut what = Vec::new();
    let (ka, kb) = match level {
        Level::Pack => (a.kind, b.kind),
        Level::Install => (install_kind(path, a.kind), install_kind(path, b.kind)),
    };
    if ka != kb {
        what.push(format!("type {:?} != {:?}", char::from(ka), char::from(kb)));
    }
    let (ma, mb) = (a.mode & 0o7777, b.mode & 0o7777);
    if ma != mb {
        what.push(format!("mode {ma:04o} != {mb:04o}"));
    }
    if (a.uid, a.gid, &a.uname, &a.gname) != (b.uid, b.gid, &b.uname, &b.gname) {
        what.push(format!(
            "owner {}:{} ({}:{}) != {}:{} ({}:{})",
            a.uid,
            a.gid,
            lossy(&a.uname),
            lossy(&a.gname),
            b.uid,
            b.gid,
            lossy(&b.uname),
            lossy(&b.gname)
        ));
    }
    if level == Level::Pack && a.mtime != b.mtime {
        what.push(format!("mtime {} != {}", a.mtime, b.mtime));
    }
    if level == Level::Pack && a.size != b.size {
        what.push(format!("size {} != {}", a.size, b.size));
    }
    if a.link != b.link {
        let l = |l: &Option<Vec<u8>>| l.as_deref().map(lossy).unwrap_or_default().into_owned();
        what.push(format!("link target {:?} != {:?}", l(&a.link), l(&b.link)));
    }
    if a.digest != b.digest {
        what.push("content differs".to_owned());
    }
    if level == Level::Pack && what.is_empty() && a.header != b.header {
        what.push("header encoding differs".to_owned());
    }
    what
}

/// The payload differences of a package: the first [`MAX_MEMBERS`] listed, all counted.
struct Payload<'a> {
    label: String,
    report: &'a mut Report,
    count: usize,
}

impl Payload<'_> {
    fn push(&mut self, path: &[u8], what: &str) {
        if self.count < MAX_MEMBERS {
            self.report
                .push(format!("{}: {}: {what}", self.label, lossy(path)));
        }
        self.count = self.count.saturating_add(1);
    }
}

/// Walk both data.tar member by member, reporting the members added, removed or
/// changed. builddeb sorts both archives alike: members are matched as they come, and
/// the ones out of step are kept, without their contents, until their path comes up on
/// the other side.
fn compare_payload(l: &str, a: &Path, b: &Path, level: Level, report: &mut Report) -> Result<()> {
    let (pa, pb) = (a.join("data.tar"), b.join("data.tar"));
    let open = |p: &Path| {
        File::open(p)
            .map(|f| Archive::new(BufReader::with_capacity(1 << 20, f)))
            .map_err(|e| err(format!("{}: {e}", p.display())))
    };
    let (mut ara, mut arb) = (open(&pa)?, open(&pb)?);
    let (mut ea, mut eb) = (entries(&mut ara, &pa)?, entries(&mut arb, &pb)?);

    let mut out = Payload {
        label: format!("{l}/data.tar"),
        report,
        count: 0,
    };
    let (mut ia, mut ib) = (0, 0);
    let mut pending_a: HashMap<Vec<u8>, Member> = HashMap::new();
    let mut pending_b: HashMap<Vec<u8>, Member> = HashMap::new();
    // The positions of the matched members, in A and in B.
    let mut matched = Vec::new();
    let mut compare = |path: &[u8], x: &Member, y: &Member, out: &mut Payload<'_>| {
        matched.push((x.index, y.index));
        let what = member_differences(path, x, y, level);
        if !what.is_empty() {
            out.push(path, &what.join(", "));
        }
    };
    loop {
        let x = next_member(&mut ea, &mut ia, &pa)?;
        let y = next_member(&mut eb, &mut ib, &pb)?;
        match (x, y) {
            (None, None) => break,
            (Some((p, x)), Some((q, y))) if p == q => compare(&p, &x, &y, &mut out),
            (x, y) => {
                if let Some((p, x)) = x {
                    match pending_b.remove(&p) {
                        Some(y) => compare(&p, &x, &y, &mut out),
                        None => {
                            pending_a.insert(p, x);
                        }
                    }
                }
                if let Some((q, y)) = y {
                    match pending_a.remove(&q) {
                        Some(x) => compare(&q, &x, &y, &mut out),
                        None => {
                            pending_b.insert(q, y);
                        }
                    }
                }
            }
        }
    }
    for (pending, only) in [(pending_a, "only in A"), (pending_b, "only in B")] {
        let mut paths: Vec<_> = pending.into_keys().collect();
        paths.sort();
        for p in paths {
            out.push(&p, only);
        }
    }
    let count = out.count;
    if count > MAX_MEMBERS {
        report.push(format!(
            "{l}/data.tar: {} more members differ",
            count.saturating_sub(MAX_MEMBERS)
        ));
    }
    if level == Level::Pack {
        matched.sort_unstable();
        if matched.windows(2).any(|w| matches!(w, [x, y] if y.1 < x.1)) {
            report.push(format!("{l}/data.tar: member order differs"));
        } else if count == 0 {
            report.push(format!(
                "{l}/data.tar: differs outside the members (padding, end of archive)"
            ));
        }
    }
    Ok(())
}

fn compare_tree(
    l: &str,
    (a, ta): (&Path, &Tree),
    (b, tb): (&Path, &Tree),
    level: Level,
    report: &mut Report,
) -> Result<()> {
    // Both epochs, to compare the timestamps pack writes.
    let mut epochs = None;
    if level == Level::Pack {
        if ta.compression != tb.compression {
            report.push(format!(
                "{l}/dpkg-deb.options: compression {} != {}",
                compression_name(ta.compression),
                compression_name(tb.compression)
            ));
        }
        match (ta.epoch, tb.epoch) {
            (Some(ea), Some(eb)) => {
                if ea != eb {
                    report.push(format!("{l}/staged.info: epoch {ea} != {eb}"));
                }
                epochs = Some((ea, eb));
            }
            (None, None) => {}
            (x, _) => report.push(format!("{l}/staged.info: only in {}", side(x.is_some()))),
        }
        let what = control_differences(&ta.debian, &tb.debian, true, epochs);
        if !what.is_empty() {
            report.push(format!("{l}/DEBIAN/: {}", what.join(", ")));
        }
    }
    let names: BTreeSet<_> = ta.control.keys().chain(tb.control.keys()).collect();
    for name in names {
        match (ta.control.get(name), tb.control.get(name)) {
            (Some(x), Some(y)) => {
                let what = control_differences(x, y, false, epochs);
                if !what.is_empty() {
                    report.push(format!("{l}/DEBIAN/{name}: {}", what.join(", ")));
                }
            }
            (x, _) => report.push(format!("{l}/DEBIAN/{name}: only in {}", side(x.is_some()))),
        }
    }
    if ta.data_digest != tb.data_digest {
        compare_payload(l, a, b, level, report)?;
    }
    Ok(())
}

fn compare_source(
    label: &str,
    (a, sa): (&Path, &Source),
    (b, sb): (&Path, &Source),
    level: Level,
    report: &mut Report,
) -> Result<()> {
    let names: BTreeSet<_> = sa.keys().chain(sb.keys()).collect();
    for pkg in names {
        let l = format!("{label}/{pkg}");
        match (sa.get(pkg), sb.get(pkg)) {
            (Some(x), Some(y)) => {
                compare_tree(&l, (&a.join(pkg), x), (&b.join(pkg), y), level, report)?;
            }
            (x, _) => report.push(format!("{l}: only in {}", side(x.is_some()))),
        }
    }
    Ok(())
}

/// Lock `dir` for reading with `lock` ([`staged_lock::read_source`] or
/// [`staged_lock::read_output`]).
pub(crate) fn read_lock(
    dir: &Path,
    lock: fn(&Path) -> io::Result<staged_lock::ReadLock>,
) -> Result<staged_lock::ReadLock> {
    lock(dir).map_err(|e| err(format!("{}: {e}", dir.display())))
}

pub(crate) fn invalid(problems: &[String]) -> Error {
    err(format!(
        "invalid staged trees:\n  {}",
        problems.join("\n  ")
    ))
}

/// Compare two staged trees (one source package's, or whole output directories) at
/// `level`.
///
/// # Errors
/// A side is not a complete staged tree (every problem listed), or cannot be read.
pub fn diff_stage(a: &Path, b: &Path, level: Level) -> Result<Report> {
    let mut report = Report::new();
    let mut problems = Vec::new();
    if a.join(".staged").exists() || b.join(".staged").exists() {
        // Each side from one generation of its staged output, until compared.
        let _locks = (
            read_lock(a, staged_lock::read_source)?,
            read_lock(b, staged_lock::read_source)?,
        );
        let (sa, sb) = (load_source(a, &mut problems), load_source(b, &mut problems));
        let (Some(sa), Some(sb)) = (sa, sb) else {
            return Err(invalid(&problems));
        };
        let label = a.file_name().unwrap_or_default().to_string_lossy();
        compare_source(&label, (a, &sa), (b, &sb), level, &mut report)?;
        return Ok(report);
    }

    let _locks = (
        read_lock(a, staged_lock::read_output)?,
        read_lock(b, staged_lock::read_output)?,
    );
    let dirs = |d: &Path| staged_dirs(d).map_err(|e| err(format!("{}: {e}", d.display())));
    let (da, db) = (dirs(a)?, dirs(b)?);
    if da.is_empty() && db.is_empty() {
        return Err(err(format!(
            "{} and {}: no staged source directory (holding .staged)",
            a.display(),
            b.display()
        )));
    }
    let mut load = |root: &Path, dirs: &BTreeSet<String>| -> BTreeMap<String, Source> {
        dirs.iter()
            .filter_map(|n| Some((n.clone(), load_source(&root.join(n), &mut problems)?)))
            .collect()
    };
    let (sa, sb) = (load(a, &da), load(b, &db));
    if !problems.is_empty() {
        return Err(invalid(&problems));
    }
    for n in da.union(&db) {
        match (sa.get(n), sb.get(n)) {
            (Some(x), Some(y)) => {
                compare_source(n, (&a.join(n), x), (&b.join(n), y), level, &mut report)?;
            }
            (x, _) => report.push(format!("{n}: only in {}", side(x.is_some()))),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;

    fn tar_of(files: &[(&str, &[u8], u64)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, data, mtime) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(*mtime);
            h.set_uid(0);
            h.set_gid(0);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, path, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn staged(root: &Path, dir: &str, pkg: &str, tar: &[u8], control: &str) {
        let d = root.join(dir).join(pkg);
        fs::create_dir_all(d.join("DEBIAN")).unwrap();
        fs::write(root.join(dir).join(".staged"), format!("{pkg}\n")).unwrap();
        fs::write(d.join("DEBIAN/control"), control).unwrap();
        set_mode(&d.join("DEBIAN/control"), 0o644);
        fs::write(d.join("data.tar"), tar).unwrap();
        let sum = hex(&sha256(&mut &tar[..]).unwrap());
        fs::write(d.join("data.tar.sha256"), format!("{sum}\n")).unwrap();
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Two equal output directories, with the source directory `src` of package `p`.
    fn pair() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        let tar = tar_of(&[("./x", b"x", 1), ("./y", b"y", 1)]);
        staged(&a, "src", "p", &tar, "Package: p\n");
        staged(&b, "src", "p", &tar, "Package: p\n");
        (t, a, b)
    }

    /// The reports of both levels.
    fn both(a: &Path, b: &Path) -> (Report, Report) {
        (
            diff_stage(a, b, Level::Pack).unwrap(),
            diff_stage(a, b, Level::Install).unwrap(),
        )
    }

    #[test]
    fn equal_and_different_trees() {
        let (_t, a, b) = pair();
        assert_eq!(both(&a, &b), (Report::new(), Report::new()));
        assert_eq!(
            both(&a.join("src"), &b.join("src")),
            (Report::new(), Report::new())
        );

        let tar = tar_of(&[("./x", b"x", 1), ("./y", b"y", 2)]);
        staged(&b, "src", "p", &tar, "Package: q\n");
        set_mode(&b.join("src/p/DEBIAN/control"), 0o700);
        let (pack, install) = both(&a, &b);
        assert_eq!(
            pack,
            [
                "src/p/DEBIAN/control: mode 0644 != 0755, content differs",
                "src/p/data.tar: y: mtime 1 != 2",
            ],
        );
        assert_eq!(
            install,
            ["src/p/DEBIAN/control: mode 0644 != 0755, content differs"]
        );
    }

    #[test]
    fn incomplete_trees_are_errors() {
        let (_t, a, b) = pair();
        for f in ["data.tar", "DEBIAN/control"] {
            fs::remove_file(a.join("src/p").join(f)).unwrap();
            fs::remove_file(b.join("src/p").join(f)).unwrap();
        }
        fs::write(a.join("src/p/dpkg-deb.options"), "-Zzstd\n").unwrap();
        let e = diff_stage(&a, &b, Level::Pack).unwrap_err().to_string();
        assert_eq!(e.matches("p: data.tar: ").count(), 2, "{e}");
        assert_eq!(e.matches("no DEBIAN/control").count(), 2, "{e}");

        let (_t, a, b) = pair();
        fs::write(a.join("src/p/data.tar.sha256"), "0\n").unwrap();
        fs::write(a.join("src/p/dpkg-deb.options"), "-Zlz4\n").unwrap();
        fs::write(b.join("src/.staged"), "p\nq\n").unwrap();
        fs::write(b.join("src/p/staged.info"), "Format: 2\n").unwrap();
        let e = diff_stage(&a, &b, Level::Install).unwrap_err().to_string();
        assert!(e.contains("does not match data.tar.sha256"), "{e}");
        assert!(e.contains("dpkg-deb.options: unknown compression"), "{e}");
        assert!(e.contains("q: listed in .staged, missing"), "{e}");
        assert!(e.contains("staged.info: unsupported Format 2"), "{e}");

        let (_t, a, b) = pair();
        fs::remove_file(b.join("src/.staged")).unwrap();
        assert!(diff_stage(&a.join("src"), &b.join("src"), Level::Pack).is_err());
        let t = tempfile::tempdir().unwrap();
        assert!(diff_stage(t.path(), t.path(), Level::Pack).is_err());
    }

    #[test]
    fn pack_only_differences() {
        let (_t, a, b) = pair();
        // xz -6 is the default.
        fs::write(a.join("src/p/dpkg-deb.options"), "-Zxz\n-z6\n").unwrap();
        assert_eq!(both(&a, &b), (Report::new(), Report::new()));

        fs::write(b.join("src/p/dpkg-deb.options"), "-Zzstd\n").unwrap();
        // The same mode in control.tar.
        set_mode(&b.join("src/p/DEBIAN/control"), 0o664);
        for (d, epoch) in [(&a, 1_000), (&b, 2_000)] {
            let info = format!("Format: 1\nEpoch: {epoch}\n");
            fs::write(d.join("src/p/staged.info"), info).unwrap();
        }
        let (pack, install) = both(&a, &b);
        assert_eq!(
            pack,
            [
                "src/p/dpkg-deb.options: compression xz -6 != zstd -3",
                "src/p/staged.info: epoch 1000 != 2000",
                "src/p/DEBIAN/: mtime 1000 != 2000",
                "src/p/DEBIAN/control: mtime 1000 != 2000",
            ]
        );
        assert_eq!(install, Report::new());

        fs::remove_file(a.join("src/p/staged.info")).unwrap();
        set_mode(&b.join("src/p/DEBIAN/control"), 0o755);
        let (pack, install) = both(&a, &b);
        assert_eq!(
            pack,
            [
                "src/p/dpkg-deb.options: compression xz -6 != zstd -3",
                "src/p/staged.info: only in B",
                "src/p/DEBIAN/control: mode 0644 != 0755",
            ]
        );
        assert_eq!(install, ["src/p/DEBIAN/control: mode 0644 != 0755"]);
    }

    #[test]
    fn every_payload_difference() {
        let (_t, a, b) = pair();
        let names: Vec<String> = (0..60).map(|i| format!("./f{i:02}")).collect();
        let files = |content: &'static [u8]| {
            let mut v = vec![("./a", &b"a"[..], 1)];
            v.extend(names.iter().map(|n| (n.as_str(), content, 1)));
            v
        };
        let mut x = files(b"x");
        x.push(("./z", b"z", 1));
        staged(&a, "src", "p", &tar_of(&x), "Package: p\n");
        staged(&b, "src", "p", &tar_of(&files(b"y")), "Package: p\n");
        let (pack, install) = both(&a, &b);
        assert_eq!(pack, install);
        assert_eq!(pack.len(), MAX_MEMBERS + 1, "{pack:#?}");
        assert_eq!(
            pack.first().unwrap(),
            "src/p/data.tar: f00: content differs"
        );
        assert_eq!(
            pack.last().unwrap(),
            "src/p/data.tar: 11 more members differ"
        );

        // Members of one side only, the others matched past them.
        let x = tar_of(&[("./a", b"a", 1), ("./b", b"b", 1), ("./c", b"c", 1)]);
        let y = tar_of(&[("./a", b"a", 1), ("./c", b"C", 1), ("./d", b"d", 1)]);
        staged(&a, "src", "p", &x, "Package: p\n");
        staged(&b, "src", "p", &y, "Package: p\n");
        assert_eq!(
            diff_stage(&a, &b, Level::Install).unwrap(),
            [
                "src/p/data.tar: c: content differs",
                "src/p/data.tar: b: only in A",
                "src/p/data.tar: d: only in B",
            ]
        );

        // The same members, in another order.
        let y = tar_of(&[("./a", b"a", 1), ("./c", b"c", 1), ("./b", b"b", 1)]);
        staged(&b, "src", "p", &y, "Package: p\n");
        let (pack, install) = both(&a, &b);
        assert_eq!(pack, ["src/p/data.tar: member order differs"]);
        assert_eq!(install, Report::new());
    }
}
