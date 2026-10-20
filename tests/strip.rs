//! The native `dh_strip_nondeterminism` and `debbuild-rs strip-nondeterminism`, checked
//! against debhelper's helper and strip-nondeterminism where they are installed: the
//! same crafted files, normalized by both, must come out the same bytes, with the same
//! permissions, rewritten (a new mtime) or not alike.
#![allow(
    clippy::format_push_string,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

const EXE: &str = env!("CARGO_BIN_EXE_debbuild-rs");
/// The changelog date of the test packages: odd seconds, not UTC.
const CHANGELOG: &str = "Mon, 14 Oct 2024 12:34:57 +0200";
/// The mtime of the files before normalization: older than the changelog.
const OLD: u64 = 1_000_000_000;

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

fn crc32(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

// ---- crafted files ----

/// A gzip member of "hello\n": header fields, then the deflate data and trailer.
fn gz(flags: u8, mtime: u32, xfl: u8, os: u8, fields: &[u8]) -> Vec<u8> {
    let mut v = vec![0x1f, 0x8b, 8, flags];
    v.extend_from_slice(&mtime.to_le_bytes());
    v.extend_from_slice(&[xfl, os]);
    v.extend_from_slice(fields);
    v.extend_from_slice(&deflate(b"hello\n"));
    v.extend_from_slice(&crc32(b"hello\n").to_le_bytes());
    v.extend_from_slice(&6_u32.to_le_bytes());
    v
}

/// A zip member as written by [`zip`].
#[derive(Clone)]
struct Ent {
    name: Vec<u8>,
    data: Vec<u8>,
    deflated: bool,
    flags: u16,
    made_by: u16,
    needed: u16,
    external: u32,
    internal: u16,
    local_extra: Vec<u8>,
    central_extra: Vec<u8>,
    comment: Vec<u8>,
    dos: (u16, u16),
    /// With bit 3 of the flags: whether the data descriptor has its signature.
    descriptor_sig: bool,
}

fn ent(name: &str, data: &[u8]) -> Ent {
    Ent {
        name: name.as_bytes().to_vec(),
        data: data.to_vec(),
        deflated: false,
        flags: 0,
        made_by: 0x0314,
        needed: 20,
        external: 0o100_644 << 16,
        internal: 0,
        local_extra: Vec::new(),
        central_extra: Vec::new(),
        comment: Vec::new(),
        dos: (0x6354, 0x512d),
        descriptor_sig: true,
    }
}

fn ext(id: u16, data: &[u8]) -> Vec<u8> {
    let mut v = id.to_le_bytes().to_vec();
    v.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
    v.extend_from_slice(data);
    v
}

fn zip_with(entries: &[Ent], comment: &[u8]) -> Vec<u8> {
    let p16 = |v: &mut Vec<u8>, x: u16| v.extend_from_slice(&x.to_le_bytes());
    let p32 = |v: &mut Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes());
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for e in entries {
        let body = if e.deflated {
            deflate(&e.data)
        } else {
            e.data.clone()
        };
        let method = if e.deflated { 8 } else { 0 };
        let crc = crc32(&e.data);
        let (cs, us) = (
            u32::try_from(body.len()).unwrap(),
            u32::try_from(e.data.len()).unwrap(),
        );
        let off = u32::try_from(out.len()).unwrap();
        let dd = e.flags & 8 != 0;
        p32(&mut out, 0x0403_4b50);
        for x in [e.needed, e.flags, method, e.dos.0, e.dos.1] {
            p16(&mut out, x);
        }
        for x in if dd { [0, 0, 0] } else { [crc, cs, us] } {
            p32(&mut out, x);
        }
        p16(&mut out, u16::try_from(e.name.len()).unwrap());
        p16(&mut out, u16::try_from(e.local_extra.len()).unwrap());
        out.extend_from_slice(&e.name);
        out.extend_from_slice(&e.local_extra);
        out.extend_from_slice(&body);
        if dd {
            if e.descriptor_sig {
                p32(&mut out, 0x0807_4b50);
            }
            for x in [crc, cs, us] {
                p32(&mut out, x);
            }
        }
        p32(&mut cd, 0x0201_4b50);
        for x in [e.made_by, e.needed, e.flags, method, e.dos.0, e.dos.1] {
            p16(&mut cd, x);
        }
        for x in [crc, cs, us] {
            p32(&mut cd, x);
        }
        for x in [
            u16::try_from(e.name.len()).unwrap(),
            u16::try_from(e.central_extra.len()).unwrap(),
            u16::try_from(e.comment.len()).unwrap(),
            0,
            e.internal,
        ] {
            p16(&mut cd, x);
        }
        p32(&mut cd, e.external);
        p32(&mut cd, off);
        cd.extend_from_slice(&e.name);
        cd.extend_from_slice(&e.central_extra);
        cd.extend_from_slice(&e.comment);
    }
    let start = u32::try_from(out.len()).unwrap();
    let n = u16::try_from(entries.len()).unwrap();
    out.extend_from_slice(&cd);
    p32(&mut out, 0x0605_4b50);
    for x in [0, 0, n, n] {
        p16(&mut out, x);
    }
    p32(&mut out, u32::try_from(cd.len()).unwrap());
    p32(&mut out, start);
    p16(&mut out, u16::try_from(comment.len()).unwrap());
    out.extend_from_slice(comment);
    out
}

fn zip(entries: &[Ent]) -> Vec<u8> {
    zip_with(entries, b"")
}

/// [`zip`], its offsets counted from `base` bytes before it.
fn zip_at(entries: &[Ent], base: u32) -> Vec<u8> {
    let mut d = zip(entries);
    let eocd = d.len() - 22;
    let mut at = le32(&d, eocd + 16);
    d = patch(d, eocd + 16, u32::try_from(at).unwrap() + base, 4);
    for _ in entries {
        let off = u32::try_from(le32(&d, at + 42)).unwrap();
        d = patch(d, at + 42, off + base, 4);
        at += 46 + le16(&d, at + 28) + le16(&d, at + 30) + le16(&d, at + 32);
    }
    d
}

fn png_chunk(out: &mut Vec<u8>, kind: &[u8], data: &[u8]) {
    out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    out.extend_from_slice(&crc32(&[kind, data].concat()).to_be_bytes());
}

/// A 1x1 grey PNG with `chunks` between IHDR and IDAT.
fn png(chunks: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    png_chunk(&mut v, b"IHDR", b"\0\0\0\x01\0\0\0\x01\x08\0\0\0\0");
    for (k, d) in chunks {
        png_chunk(&mut v, k, d);
    }
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
    z.write_all(b"\0\0").unwrap();
    png_chunk(&mut v, b"IDAT", &z.finish().unwrap());
    png_chunk(&mut v, b"IEND", b"");
    v
}

/// A message catalog of `entries` (original, translation).
fn mo(entries: &[(&str, &str)], revision: u32, big: bool) -> Vec<u8> {
    let w = |v: &mut Vec<u8>, x: u32| {
        v.extend_from_slice(&if big {
            x.to_be_bytes()
        } else {
            x.to_le_bytes()
        });
    };
    let n = u32::try_from(entries.len()).unwrap();
    let (ot, tt) = (28, 28 + 8 * n);
    let mut off = tt + 8 * n;
    let mut v = Vec::new();
    for x in [0x9504_12de, revision, n, ot, tt, 0, off] {
        w(&mut v, x);
    }
    let mut strings = Vec::new();
    let mut tables = Vec::new();
    for i in 0..2 {
        for e in entries {
            let s = if i == 0 { e.0 } else { e.1 };
            let len = u32::try_from(s.len()).unwrap();
            w(&mut tables, len);
            w(&mut tables, off);
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            off += len + 1;
        }
    }
    v.extend(tables);
    v.extend(strings);
    v
}

// ---- the oracle ----

/// A file of a test package: path under the package tree, content, mode.
type File = (String, Vec<u8>, u32);

fn f(path: &str, content: impl Into<Vec<u8>>) -> File {
    (path.to_owned(), content.into(), 0o644)
}

fn set_mtime(path: &Path, secs: u64) {
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
        .unwrap();
}

/// A source package directory with binary packages `pkgs`, each holding `files`.
fn package(dir: &Path, pkgs: &[&str], files: &[File]) {
    fs::create_dir_all(dir.join("debian")).unwrap();
    let mut control =
        "Source: strip-test\nMaintainer: t <t@example.org>\nBuild-Depends: debhelper-compat (= 13)\n"
            .to_owned();
    for p in pkgs {
        control.push_str(&format!(
            "\nPackage: {p}\nArchitecture: all\nDescription: x\n x\n"
        ));
    }
    fs::write(dir.join("debian/control"), control).unwrap();
    fs::write(
        dir.join("debian/changelog"),
        format!("strip-test (1.0) unstable; urgency=medium\n\n  * x\n\n -- t <t@example.org>  {CHANGELOG}\n"),
    )
    .unwrap();
    for p in pkgs {
        for (path, content, mode) in files {
            let file = dir.join("debian").join(p).join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(&file, content).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(*mode)).unwrap();
            set_mtime(&file, OLD);
            own(&file);
        }
    }
}

/// Every regular file under `root`: (path, content, mode, rewritten).
fn snapshot(root: &Path) -> Vec<(String, Vec<u8>, u32, bool)> {
    let mut out = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                dirs.push(p);
            } else if m.is_file() {
                out.push((
                    p.strip_prefix(root).unwrap().display().to_string(),
                    fs::read(&p).unwrap(),
                    m.mode() & 0o7777,
                    m.mtime() != i64::try_from(OLD).unwrap(),
                ));
            }
        }
    }
    out.sort();
    out
}

/// The owner the crafted files are given, when the tests run as root: a file rewritten
/// in place keeps it, one replaced is the process's.
const OWNER: u32 = 4242;

/// Give `path` the owner [`OWNER`], when the tests run as root.
fn own(path: &Path) {
    let _ = std::os::unix::fs::lchown(path, Some(OWNER), Some(OWNER));
}

/// The inode of every regular file under `root`, by path, with the files held open:
/// an inode replaced while they are held is not freed, so its number cannot come back
/// as that of a new file (as it may on ext4) and pass for the old one. With the state of
/// each file, as [`snapshot`] and [`identities`] give it.
struct Inodes {
    by_path: std::collections::BTreeMap<String, u64>,
    states: std::collections::BTreeMap<String, (Vec<u8>, u32, bool, u32, u32)>,
    _open: Vec<fs::File>,
}

fn inodes(root: &Path) -> Inodes {
    let mut by_path = std::collections::BTreeMap::new();
    let mut states = std::collections::BTreeMap::new();
    let mut open = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                dirs.push(p);
            } else if m.is_file() {
                // one with no read permission is not held, outside root
                open.extend(fs::File::open(&p).ok());
                let name = p.strip_prefix(root).unwrap().display().to_string();
                states.insert(
                    name.clone(),
                    (
                        fs::read(&p).unwrap_or_default(),
                        m.mode() & 0o7777,
                        m.mtime() != i64::try_from(OLD).unwrap(),
                        m.uid(),
                        m.gid(),
                    ),
                );
                by_path.insert(name, m.ino());
            }
        }
    }
    Inodes {
        by_path,
        states,
        _open: open,
    }
}

/// The real tool rewrites a file even when its content does not change, which this one
/// never does: the files it left with their content and mode are reported as they were
/// `before`, not rewritten or replaced.
fn untouched(
    before: &Inodes,
    snap: &mut [(String, Vec<u8>, u32, bool)],
    ids: &mut [(String, bool, u32, u32)],
) {
    let same = |name: &str, data: &[u8], mode: u32| {
        before
            .states
            .get(name)
            .filter(|s| s.0 == data && s.1 == mode)
    };
    for s in snap.iter_mut() {
        if let Some(b) = same(&s.0, &s.1, s.2) {
            s.3 = b.2;
        }
    }
    let unchanged: std::collections::BTreeSet<&str> = snap
        .iter()
        .filter(|s| same(&s.0, &s.1, s.2).is_some())
        .map(|s| s.0.as_str())
        .collect();
    for i in ids.iter_mut() {
        if let Some(b) = before
            .states
            .get(&i.0)
            .filter(|_| unchanged.contains(i.0.as_str()))
        {
            *i = (i.0.clone(), false, b.3, b.4);
        }
    }
}

/// Every regular file under `root`: (path, whether it is another inode than in
/// `before`, its owner and group).
fn identities(root: &Path, before: &Inodes) -> Vec<(String, bool, u32, u32)> {
    inodes(root)
        .by_path
        .into_iter()
        .map(|(path, ino)| {
            let m = fs::symlink_metadata(root.join(&path)).unwrap();
            let replaced = before.by_path.get(&path) != Some(&ino);
            (path, replaced, m.uid(), m.gid())
        })
        .collect()
}

fn dh_available() -> bool {
    if have("dh_strip_nondeterminism") && have("dh_listpackages") {
        return true;
    }
    skip("dh_strip_nondeterminism (debhelper)");
    false
}

/// Run `dh_strip_nondeterminism ARGS` in `dir`: debhelper's, or this binary's.
fn run_dh(dir: &Path, ours: bool, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = if ours {
        let bin = dir.join("../bin");
        fs::create_dir_all(&bin).unwrap();
        let link = bin.join("dh_strip_nondeterminism");
        if !link.exists() {
            symlink(EXE, &link).unwrap();
        }
        let mut c = Command::new(&link);
        c.env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        );
        c
    } else {
        Command::new("dh_strip_nondeterminism")
    };
    cmd.args(args)
        .current_dir(dir)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .env_remove("DH_VERBOSE")
        .env_remove("DH_OPTIONS");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

/// A member of a zip archive, as its central directory and local header describe it.
struct ZipMember {
    /// The central directory entry; CRC, sizes and offset zeroed (the contents are
    /// compared instead).
    central: Vec<u8>,
    /// The local header; CRC and sizes zeroed.
    local: Vec<u8>,
    method: u16,
    name: Vec<u8>,
    data: Vec<u8>,
    /// The data descriptor; CRC and sizes zeroed.
    descriptor: Vec<u8>,
}

fn le16(d: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes([d[at], d[at + 1]]))
}

fn le32(d: &[u8], at: usize) -> usize {
    u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]]) as usize
}

/// The members of a zip archive and its end record (offsets zeroed); `None` if it is not
/// one this reader follows.
fn zip_members(d: &[u8]) -> Option<(Vec<ZipMember>, Vec<u8>)> {
    let eocd = (0..d.len().checked_sub(21)?)
        .rev()
        .find(|&i| d[i..].starts_with(b"PK\x05\x06"))?;
    let mut end = d.get(eocd..)?.to_vec();
    end[12..20].fill(0);
    let (count, mut at) = (le16(d, eocd + 10), le32(d, eocd + 16));
    let mut members = Vec::new();
    for _ in 0..count {
        let c = d.get(at..at + 46)?;
        if !c.starts_with(b"PK\x01\x02") {
            return None;
        }
        let (nlen, xlen, klen) = (le16(c, 28), le16(c, 30), le16(c, 32));
        let mut central = d.get(at..at + 46 + nlen + xlen + klen)?.to_vec();
        let name = central[46..46 + nlen].to_vec();
        let off = le32(c, 42);
        let csize = le32(c, 20);
        central[16..28].fill(0);
        central[42..46].fill(0);
        let lh = d.get(off..off + 30)?;
        let (ln, lx) = (le16(lh, 26), le16(lh, 28));
        let mut local = d.get(off..off + 30 + ln + lx)?.to_vec();
        local[14..26].fill(0);
        let start = off + 30 + ln + lx;
        let data = d.get(start..start + csize)?.to_vec();
        let mut descriptor = Vec::new();
        if le16(c, 8) & 8 != 0 {
            descriptor = d.get(start + csize..start + csize + 16)?.to_vec();
            descriptor[4..16].fill(0);
        }
        members.push(ZipMember {
            central,
            local,
            method: u16::try_from(le16(c, 10)).ok()?,
            name,
            data,
            descriptor,
        });
        at += 46 + nlen + xlen + klen;
    }
    Some((members, end))
}

/// A member's content: its data, inflated when deflated.
fn zip_content(m: &ZipMember) -> Option<Vec<u8>> {
    match m.method {
        0 => Some(m.data.clone()),
        8 => {
            let mut out = Vec::new();
            std::io::Read::read_to_end(
                &mut flate2::read::DeflateDecoder::new(&m.data[..]),
                &mut out,
            )
            .ok()?;
            Some(out)
        }
        _ => None,
    }
}

/// Whether two zip archives differ only in the compressed bytes of members of the same
/// content: the same members, in the same order, with the same headers but for the
/// compressed sizes and offsets, the same contents, nested archives compared alike.
fn zip_equivalent(a: &[u8], b: &[u8]) -> Result<(), String> {
    let ((ma, ea), (mb, eb)) = (
        zip_members(a).ok_or("not a zip archive (real)")?,
        zip_members(b).ok_or("not a zip archive (ours)")?,
    );
    if ea != eb || ma.len() != mb.len() {
        return Err("different end records or member counts".to_owned());
    }
    for (x, y) in ma.iter().zip(&mb) {
        let name = String::from_utf8_lossy(&x.name);
        if (&x.central, &x.local, &x.descriptor) != (&y.central, &y.local, &y.descriptor) {
            return Err(format!("{name}: different headers"));
        }
        if x.data == y.data {
            continue;
        }
        let (cx, cy) = (zip_content(x), zip_content(y));
        let (Some(cx), Some(cy)) = (cx, cy) else {
            return Err(format!("{name}: different data, method {}", x.method));
        };
        if cx != cy {
            let nested = name.ends_with(".jar") || name.ends_with(".war");
            if !nested {
                return Err(format!("{name}: different content"));
            }
            zip_equivalent(&cx, &cy).map_err(|e| format!("{name}: {e}"))?;
        }
    }
    Ok(())
}

/// Normalize `files` in packages `pkgs` with debhelper's helper and with this binary's,
/// and require the same result; whether debhelper's helper succeeded.
fn same(pkgs: &[&str], files: &[File], args: &[&str]) -> bool {
    let tmp = tempfile::tempdir().unwrap();
    let (real, ours) = (tmp.path().join("real/src"), tmp.path().join("ours/src"));
    package(&real, pkgs, files);
    package(&ours, pkgs, files);
    let (before_r, before_o) = (inodes(&real.join("debian")), inodes(&ours.join("debian")));
    let r = run_dh(&real, false, args, &[]);
    let o = run_dh(&ours, true, args, &[]);
    assert_eq!(r.status.code(), o.status.code(), "real: {r:?}\nours: {o:?}");
    let (mut rs, os) = (
        snapshot(&real.join("debian")),
        snapshot(&ours.join("debian")),
    );
    let mut real_ids = identities(&real.join("debian"), &before_r);
    untouched(&before_r, &mut rs, &mut real_ids);
    assert_eq!(
        real_ids,
        identities(&ours.join("debian"), &before_o),
        "{args:?}: (path, replaced, owner, group)"
    );
    assert_eq!(rs.len(), os.len());
    for (a, b) in rs.iter().zip(&os) {
        assert_eq!(a.0, b.0);
        // strip-nondeterminism compresses rewritten jar members with zlib, this with
        // flate2: such archives must hold the same members and contents.
        let jar = [".jar", ".war", ".hpi", ".apk", ".sym"]
            .iter()
            .any(|e| a.0.ends_with(e));
        if jar && a.1 != b.1 {
            if let Err(e) = zip_equivalent(&a.1, &b.1) {
                panic!("{args:?} {}: {e}", a.0);
            }
        } else if a.1 != b.1 {
            let at = a.1.iter().zip(&b.1).position(|(x, y)| x != y).unwrap_or(0);
            let from = at.saturating_sub(48);
            panic!(
                "{args:?} {}: content differs at {at} (sizes {} {})\nreal: {}\nours: {}\nreal: {:02x?}\nours: {:02x?}\nreal stderr: {}\nours stderr: {}",
                a.0,
                a.1.len(),
                b.1.len(),
                String::from_utf8_lossy(&a.1[from..a.1.len().min(at + 48)]).escape_debug(),
                String::from_utf8_lossy(&b.1[from..b.1.len().min(at + 48)]).escape_debug(),
                &a.1[from..a.1.len().min(at + 48)],
                &b.1[from..b.1.len().min(at + 48)],
                String::from_utf8_lossy(&r.stderr),
                String::from_utf8_lossy(&o.stderr)
            );
        }
        if (a.2, a.3) != (b.2, b.3) {
            let modes: Vec<_> = rs
                .iter()
                .zip(&os)
                .map(|(x, y)| format!("{} {:o}/{} {:o}/{}", x.0, x.2, x.3, y.2, y.3))
                .collect();
            panic!(
                "{args:?} {}: (mode, rewritten) differ\n{}\nreal: {r:?}\nours: {o:?}",
                a.0,
                modes.join("\n")
            );
        }
    }
    r.status.success()
}

/// [`same`] on `files`, which debhelper's helper must normalize without failing.
fn oracle(files: &[File]) {
    if dh_available() {
        let names: Vec<&str> = files.iter().map(|f| f.0.as_str()).collect();
        assert!(
            same(&["pp"], files, &[]),
            "debhelper's helper failed on {names:?}"
        );
    }
}

/// [`same`] on each of `files` alone, which debhelper's helper must fail on: the run
/// stops at the first failure, which would leave the files after it unexamined.
fn oracle_failing(files: &[File]) {
    if dh_available() {
        for file in files {
            assert!(
                !same(&["pp"], std::slice::from_ref(file), &[]),
                "debhelper's helper normalized {}",
                file.0
            );
        }
    }
}

// ---- the handlers ----

#[test]
fn gzip_members() {
    let mut bad_flags = gz(0, 1_800_000_000, 0, 3, b"");
    bad_flags[3] = 0xe0;
    let mut method7 = gz(0, 1_800_000_000, 0, 3, b"");
    method7[2] = 7;
    let mut multi = gz(8, 1_800_000_000, 0, 3, b"a\0");
    multi.extend(gz(8, 1_800_000_000, 0, 3, b"b\0"));
    let mut trailing = gz(0, 1_800_000_000, 0, 3, b"");
    trailing.extend_from_slice(b"garbage");
    oracle(&[
        f("plain.gz", gz(0, 1_800_000_000, 0, 3, b"")),
        f("old.gz", gz(0, 1000, 0, 3, b"")),
        f("zero.gz", gz(0, 0, 0, 3, b"")),
        f("name.gz", gz(8, 1_800_000_000, 2, 3, b"name.txt\0")),
        f("comment.gz", gz(16, 1_800_000_000, 4, 3, b"a comment\0")),
        f(
            "extra.gz",
            gz(4, 1_800_000_000, 0, 3, b"\x08\0AB\x04\0wxyz"),
        ),
        f("hcrc.gz", gz(2, 1_800_000_000, 0, 3, b"\x12\x34")),
        f("text.gz", gz(1, 1_800_000_000, 0, 3, b"")),
        f(
            "all.gz",
            gz(0x1f, 1_800_000_000, 2, 0, b"\x04\0CD\0\0n\0c\0\x99\x99"),
        ),
        f("os.gz", gz(0, 1_800_000_000, 9, 255, b"")),
        f("flags.gz", bad_flags),
        f("method.gz", method7),
        f("multi.gz", multi),
        f("trailing.gz", trailing),
        f("short.gz", b"\x1f\x8b\x08\x00\x00".to_vec()),
        f("text-file.gz", b"not gzip\n".to_vec()),
        f("empty.gz", Vec::new()),
        f("x.dz", gz(0, 1_800_000_000, 0, 3, b"")),
        // names of no handler
        f("x.tgz", gz(0, 1_800_000_000, 0, 3, b"")),
        f("x.GZ", gz(0, 1_800_000_000, 0, 3, b"")),
        f("gz", gz(0, 1_800_000_000, 0, 3, b"")),
        f(
            "usr/share/doc/p/changelog.gz",
            gz(0, 1_800_000_000, 0, 3, b""),
        ),
    ]);
}

#[test]
fn gzip_malformed_fails() {
    if !dh_available() {
        return;
    }
    let mut name = gz(8, 1, 0, 3, b"abc");
    name.truncate(13);
    oracle_failing(&[f("bad.gz", name)]);
}

#[test]
fn gzip_hardlinks() {
    if !dh_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    // an excluded name does not hide the other one: -X applies before the inodes are
    // deduplicated, whichever name comes first
    for (i, args) in [&[][..], &["-Xa.gz"], &["-Xb.gz"]].into_iter().enumerate() {
        let mut outs = Vec::new();
        for ours in [false, true] {
            let dir =
                tmp.path()
                    .join(format!("{i}"))
                    .join(if ours { "ours/src" } else { "real/src" });
            package(&dir, &["pp"], &[f("a.gz", gz(0, 1_800_000_000, 0, 3, b""))]);
            let a = dir.join("debian/pp/a.gz");
            fs::hard_link(&a, dir.join("debian/pp/b.gz")).unwrap();
            assert!(run_dh(&dir, ours, args, &[]).status.success());
            let (ma, mb) = (
                fs::metadata(&a).unwrap(),
                fs::metadata(dir.join("debian/pp/b.gz")).unwrap(),
            );
            outs.push((ma.ino() == mb.ino(), fs::read(&a).unwrap()));
        }
        assert_eq!(outs[0], outs[1], "{args:?}");
        assert_ne!(outs[1].1, gz(0, 1_800_000_000, 0, 3, b""), "{args:?}");
    }
}

fn zip_extras() -> Vec<Ent> {
    let ut = |flags: u8, times: &[u32]| {
        let mut d = vec![flags];
        for t in times {
            d.extend_from_slice(&t.to_le_bytes());
        }
        ext(0x5455, &d)
    };
    let ux = ext(0x7875, b"\x01\x04\xe8\x03\0\0\x04\xe8\x03\0\0");
    let ux2 = ext(0x7875, b"\x01\x02\xe8\x03\x02\xe8\x03");
    let ux_old = ext(0x5855, b"\0\xb3\x3f\x71\0\xb3\x3f\x71\xe8\x03\xe8\x03");
    let ntfs = ext(
        0x000a,
        &[
            &[0_u8; 4][..],
            b"\x01\0\x18\0",
            &1_u64.to_le_bytes(),
            &2_u64.to_le_bytes(),
            &3_u64.to_le_bytes(),
        ]
        .concat(),
    );
    let unknown = ext(0xcafe, b"xyz");
    let with = |name: &str, local: Vec<u8>, central: Vec<u8>| Ent {
        local_extra: local,
        central_extra: central,
        ..ent(name, b"e\n")
    };
    vec![
        with(
            "e1",
            [ut(7, &[1_900_000_000, 1, 2]), ux.clone(), unknown.clone()].concat(),
            [ut(7, &[1_900_000_000]), ux.clone(), unknown].concat(),
        ),
        with("e2", [ux_old.clone(), ntfs.clone()].concat(), ux_old),
        with("e3", ut(3, &[5]), ut(3, &[5])),
        with("e4", ut(4, &[7]), ut(4, &[])),
        with("e5", ext(0x5455, b""), ext(0x5455, b"")),
        with("e6", ux2, ntfs),
        with(
            "e7",
            ext(0x000d, b"\0\xb3\x3f\x71\0\xb3\x3f\x71\xe8\x03\xe8\x03"),
            Vec::new(),
        ),
    ]
}

fn zip_attributes() -> Vec<Ent> {
    let mut v = Vec::new();
    for (i, (made_by, external)) in [
        (0x0314, 0),
        (0x0014, 0x10),
        (0x0314, 0o100_755 << 16),
        (0x0314, 0o040_700 << 16),
        (0x0014, 0o100_644 << 16),
        (0x0314, (0o100_010 << 16) | 0x20),
        (0x0314, 0o104_755 << 16),
        (0x0314, 0o120_777 << 16),
        (0x0b14, (0o100_700 << 16) | 0x21),
        (0x1314, 0o100_700 << 16),
        (0x0314, 0o100_444 << 16),
    ]
    .into_iter()
    .enumerate()
    {
        for name in [format!("f{i:02}"), format!("d{i:02}/")] {
            v.push(Ent {
                made_by,
                external,
                ..ent(&name, b"")
            });
        }
    }
    v.push(ent("full/", b"not empty"));
    v.push(Ent {
        internal: 1,
        ..ent("text", b"t")
    });
    v
}

#[test]
fn zip_archives() {
    let order = [
        ent("z/", b""),
        ent("z/b", b"1"),
        ent("A", b"2"),
        ent("a", b"3"),
        ent("z/a", b"4"),
        ent(
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\r\nBnd-LastModified: 1\r\n\r\n",
        ),
        ent("META-INF/", b""),
        ent("a.clj", b"x"),
        ent("t", b"dup 1"),
        ent("t", b"dup 2"),
    ];
    let deflated = [
        Ent {
            deflated: true,
            ..ent("d.txt", &b"hello hello hello\n".repeat(10))
        },
        Ent {
            deflated: true,
            flags: 8,
            ..ent("dd.txt", b"descriptor\n")
        },
        Ent {
            flags: 8,
            descriptor_sig: false,
            ..ent("dd-nosig.txt", b"no signature\n")
        },
        Ent {
            flags: 0x800,
            ..ent("\u{e9}.txt", b"utf-8 name")
        },
        Ent {
            comment: b"file comment".to_vec(),
            needed: 10,
            ..ent("c.txt", b"c")
        },
    ];
    let mut files = Vec::new();
    for ext in [
        "zip", "jar", "whl", "war", "epub", "apk", "xpi", "hpi", "par", "htb", "sym",
    ] {
        files.push(f(&format!("order.{ext}"), zip(&order)));
    }
    files.extend([
        f("deflated.zip", zip(&deflated)),
        f("deflated.jar", zip(&deflated)),
        f("extras.zip", zip(&zip_extras())),
        f("extras.jar", zip(&zip_extras())),
        f("attributes.zip", zip(&zip_attributes())),
        f("attributes.jar", zip(&zip_attributes())),
        f(
            "comment.zip",
            zip_with(&[ent("a", b"a")], b"archive comment"),
        ),
        f("empty.zip", zip(&[])),
        f(
            "encrypted.zip",
            zip(&[Ent {
                flags: 1,
                ..ent("e", b"xxxxxxxxxxxx")
            }]),
        ),
        f("dir/mode.zip", zip(&order)),
        ("exec.jar".to_owned(), zip(&order), 0o755),
        ("setuid.zip".to_owned(), zip(&order), 0o4751),
        ("readonly.zip".to_owned(), zip(&order), 0o444),
        // not handled: names of no handler, contents file(1) calls another format
        f("order.ear", zip(&order)),
        f("order.ZIP", zip(&order)),
        f("prefixed.zip", [&b"PREFIX"[..], &zip(&order)].concat()),
        f(
            "epub.zip",
            zip(&[
                ent("mimetype", b"application/epub+zip"),
                ent("a.xhtml", b"x"),
            ]),
        ),
        f(
            "odt.zip",
            zip(&[
                ent("mimetype", b"application/vnd.oasis.opendocument.text"),
                ent("content.xml", b"x"),
            ]),
        ),
        f(
            "android.zip",
            zip(&[
                ent("AndroidManifest.xml", b"\x03\x00\x08\x00"),
                ent("classes.dex", b"dex\n035\0"),
            ]),
        ),
        f(
            "android.jar",
            zip(&[
                ent("AndroidManifest.xml", b"\x03\x00\x08\x00"),
                ent("classes.dex", b"dex\n035\0"),
            ]),
        ),
        f(
            "javaish.zip",
            zip(&[
                Ent {
                    local_extra: ext(0xcafe, b""),
                    central_extra: ext(0xcafe, b""),
                    ..ent("META-INF/", b"")
                },
                ent("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n"),
            ]),
        ),
        f("garbage.zip", b"PK\x03\x04 not really".to_vec()),
    ]);
    oracle(&files);
}

#[test]
fn zip_truncated_fails() {
    if !dh_available() {
        return;
    }
    let good = zip(&[ent("t", b"t")]);
    let bad = [&good[..40], &good[good.len() - 22..]].concat();
    oracle_failing(&[f("bad.zip", bad)]);
}

/// `d` with `value` written at `at`, little-endian, in `width` bytes.
fn patch(mut d: Vec<u8>, at: usize, value: u32, width: usize) -> Vec<u8> {
    d[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    d
}

fn find(d: &[u8], what: &[u8], nth: usize) -> usize {
    d.windows(what.len())
        .enumerate()
        .filter(|(_, w)| *w == what)
        .nth(nth)
        .unwrap()
        .0
}

/// Archives whose end record, central directory or local headers disagree, as zip and
/// jar: strip-nondeterminism reads past some of these, leaves some alone, fails on others.
#[test]
fn zip_reading() {
    let good = zip(&[ent("a", b"hello"), ent("b", b"world!")]);
    let deflated = zip(&[
        ent("a", b"hello"),
        Ent {
            deflated: true,
            ..ent("b", b"world! world! world!")
        },
    ]);
    let eocd = good.len() - 22;
    let cd_b = find(&good, b"PK\x01\x02", 1);
    let local_b = le32(&good, cd_b + 42);
    let cd_size = u32::try_from(le32(&good, eocd + 12)).unwrap();
    let cd_off = u32::try_from(le32(&good, eocd + 16)).unwrap();
    let local =
        |at: usize, value: u32, width: usize| patch(good.clone(), local_b + at, value, width);
    let central =
        |at: usize, value: u32, width: usize| patch(good.clone(), cd_b + at, value, width);
    let end = |at: usize, value: u32, width: usize| patch(good.clone(), eocd + at, value, width);
    let cases = [
        ("cd-size-more", end(12, cd_size + 4, 4)),
        ("cd-size-less", end(12, cd_size - 4, 4)),
        ("cd-offset-more", end(16, cd_off + 4, 4)),
        ("cd-offset-far", end(16, 100_000, 4)),
        ("count-more", patch(end(10, 3, 2), eocd + 8, 3, 2)),
        ("count-less", patch(end(10, 1, 2), eocd + 8, 1, 2)),
        ("count-total", end(10, 1, 2)),
        ("disk", end(4, 1, 2)),
        ("comment-past-end", end(20, 10, 2)),
        ("trailing", [&good[..], b"junk"].concat()),
        (
            "local-offset-off",
            central(42, u32::try_from(local_b).unwrap() + 1, 4),
        ),
        ("local-offset-far", central(42, 100_000, 4)),
        ("local-signature", local(0, 0x5858, 2)),
        ("local-name-longer", local(26, 2, 2)),
        ("local-name-shorter", local(26, 0, 2)),
        ("local-name-other", local(30, u32::from(b'c'), 1)),
        ("local-crc", local(14, 777, 4)),
        ("local-sizes", patch(local(18, 9, 4), local_b + 22, 9, 4)),
        ("local-flags", local(6, 0x800, 2)),
        ("local-method", local(8, 8, 2)),
        ("local-version", local(4, 10, 2)),
        ("local-extra-far", local(28, 60_000, 2)),
        ("csize-far", central(20, 100_000, 4)),
        ("csize-more", central(20, 7, 4)),
        ("usize-more", central(24, 7, 4)),
        ("crc", central(16, 12_345, 4)),
        ("cd-signature", central(0, 0x0301_4b50, 4)),
        ("cd-name-longer", central(28, 3, 2)),
        ("method", central(10, 99, 2)),
        ("prepended", [&b"junkjunk"[..], &good[..]].concat()),
        (
            "deflated-local-name-longer",
            patch(
                deflated.clone(),
                find(&deflated, b"PK\x03\x04", 1) + 26,
                2,
                2,
            ),
        ),
    ];
    let mut files = Vec::new();
    for (name, data) in cases {
        files.push(f(&format!("{name}.zip"), data.clone()));
        files.push(f(&format!("{name}.jar"), data));
    }
    let (fatal, ok): (Vec<File>, Vec<File>) = files.iter().cloned().partition(|f| {
        [
            "cd-size-more",
            "cd-size-less",
            "comment-past-end",
            "cd-signature",
            "cd-name-longer",
        ]
        .iter()
        .any(|n| f.0.starts_with(&format!("{n}.")))
    });
    oracle(&ok);
    oracle_failing(&fatal);
    cli_same(&files, &["-T", "1700000000"]);
    // data prepended or cut off, the offsets counting it or not
    let rel = [&b"junkjunk"[..], &good[..]].concat();
    let abs = [
        &b"junkjunk"[..],
        &zip_at(&[ent("a", b"hello"), ent("b", b"world!")], 8),
    ]
    .concat();
    let offset = |d: &[u8], by: i64| {
        let at = d.len() - 22 + 16;
        let v = i64::try_from(le32(d, at)).unwrap() + by;
        patch(d.to_vec(), at, u32::try_from(v).unwrap(), 4)
    };
    let forced = [
        f("rel", rel.clone()),
        f("abs", abs.clone()),
        f("rel-more", offset(&rel, 4)),
        f("rel-far", offset(&rel, 100)),
        f("rel-less", offset(&rel, -4)),
        f("abs-more", offset(&abs, 4)),
        f("abs-less", offset(&abs, -16)),
        f("cut", good[1..].to_vec()),
        f("cut-fixed", offset(&good[1..], -1)),
        f("cut-more", offset(&good[1..], 1)),
        f("empty", zip(&[])),
    ];
    cli_same(&forced, &["-T", "1700000000", "-t", "zip"]);
}

/// Members of the Java modules and Python zip applications.
fn prefixed_members() -> Vec<Ent> {
    vec![
        ent("classes/module-info.class", b"\xca\xfe\xba\xbe"),
        ent("META-INF/MANIFEST.MF", b"M: 1\r\nBnd-LastModified: 1\r\n"),
        ent("classes/x.clj", b"y"),
        ent("bin/", b""),
        Ent {
            deflated: true,
            ..ent("lib/a.so", &b"x".repeat(100))
        },
        ent("lib/in.jar", &zip(&[ent("z.clj", b"z")])),
        ent("__main__.py", b"print(1)\n"),
    ]
}

#[test]
fn java_modules() {
    let members = prefixed_members();
    let jmod = |header: &[u8]| [header, &zip(&members)].concat();
    let mut files = vec![
        f("plain.jmod", jmod(b"JM\x01\x00")),
        f("version.jmod", jmod(b"JM\x02\x01")),
        f("long.jmod", jmod(b"JMxyz")),
        f("twice.jmod", jmod(b"JM\x01\x00JM\x01\x00")),
        f("short-header.jmod", jmod(b"JM")),
        f("other.jmod", jmod(b"JX\x01\x00")),
        f("lower.jmod", jmod(b"jm\x01\x00")),
        f("newline.jmod", jmod(b"JM\n\x00")),
        f("newline2.jmod", jmod(b"JM\x01\n")),
        f("bare.jmod", zip(&members)),
        f(
            "absolute.jmod",
            [&b"JM\x01\x00"[..], &zip_at(&members, 4)].concat(),
        ),
        f("empty-zip.jmod", jmod_empty()),
        f("short.jmod", b"JM\x01".to_vec()),
        f("text.jmod", b"hello\n".to_vec()),
        f(".jmod", jmod(b"JM\x01\x00")),
        ("exec.jmod".to_owned(), jmod(b"JM\x01\x00"), 0o755),
        ("ro.jmod".to_owned(), jmod(b"JM\x01\x00"), 0o444),
        // names of no handler, and a jmod named as a jar or zip (file(1) knows it)
        f("x.JMOD", jmod(b"JM\x01\x00")),
        f("x.jmod.gz", jmod(b"JM\x01\x00")),
        f("module.jar", jmod(b"JM\x01\x00")),
        f("module.zip", jmod(b"JM\x01\x00")),
    ];
    let mut truncated = jmod(b"JM\x01\x00");
    truncated.truncate(truncated.len() - 30);
    files.push(f("truncated.jmod", truncated));
    oracle(&files);
    cli_same(&files, &["-T", "1700000000"]);
    cli_same(
        &[f("forced", jmod(b"JM\x01\x00"))],
        &["-T", "1700000000", "-t", "jmod"],
    );
    // files the handler fails on
    let failing = [
        f("header-only.jmod", b"JM\x01\x00".to_vec()),
        f(
            "garbage.jmod",
            b"JM\x01\x00PK\x03\x04garbage, not a zip archive".to_vec(),
        ),
    ];
    oracle_failing(&failing);
    cli_same(&failing, &["-T", "1700000000"]);
}

fn jmod_empty() -> Vec<u8> {
    [&b"JM\x01\x00"[..], &zip(&[])].concat()
}

#[test]
fn python_zip_applications() {
    let members = prefixed_members();
    let app = |prefix: &[u8]| [prefix, &zip(&members)].concat();
    let sb = b"#!/usr/bin/python3\n";
    let mut files = Vec::new();
    for (i, line) in [
        &b"#!/usr/bin/python3\n"[..],
        b"#!/usr/bin/python3 \n",
        b"#!/usr/bin/python3\r\n",
        b"#!/usr/bin/env python3\n",
        b"#! /usr/bin/python3\n",
        b"#!python3\n",
        b"#!/usr/local/bin/python3\n",
        b"#!/usr/bin/xpython3\n",
        // not python3 at the end of the line
        b"#!/usr/bin/python\n",
        b"#!/usr/bin/python3.11\n",
        b"#!/usr/bin/python3 -I\n",
        b"#!/usr/bin/env -S python3 -I\n",
        b"#!/bin/sh\n",
        b"#!python3",
        b" #!python3\n",
        b"#!\n",
    ]
    .into_iter()
    .enumerate()
    {
        files.push(f(&format!("shebang{i:02}"), app(line)));
    }
    for (i, lines) in [
        &b"\n"[..],
        b"x\n",
        b"print(1)\n",
        b"# comment\n",
        b"a\nb\nc\n",
        b"#!x\n",
        b"abc",
        b"a\nb",
    ]
    .into_iter()
    .enumerate()
    {
        files.push(f(&format!("lines{i:02}"), app(&[&sb[..], lines].concat())));
    }
    // the zip archive must start within the first 32 bytes
    for n in 26..32 {
        let line = [&b"#!/"[..], &b"x".repeat(n - 12), b"/python3\n"].concat();
        files.push(f(&format!("length{n}"), app(&line)));
    }
    files.extend([
        f("absolute", [&sb[..], &zip_at(&members, 19)].concat()),
        f("absolute.zip", [&sb[..], &zip_at(&members, 19)].concat()),
        f("empty", [&sb[..], &zip(&[])].concat()),
        f(
            "comment",
            [&sb[..], &zip_with(&members, b"an archive comment")].concat(),
        ),
        f("app.zip", app(sb)),
        f("app.jar", app(sb)),
        f("app.jmod", app(sb)),
        f("app.gz", app(sb)),
        f("app.pyz", app(sb)),
        ("exec".to_owned(), app(sb), 0o755),
        ("ro".to_owned(), app(sb), 0o444),
    ]);
    let mut truncated = app(sb);
    truncated.truncate(truncated.len() - 30);
    files.push(f("truncated", truncated));
    oracle(&files);
    cli_same(&files, &["-T", "1700000000"]);
    cli_same(
        &[f("forced", [&sb[..], &zip_at(&members, 19)].concat())],
        &["-T", "1700000000", "-t", "pyzip"],
    );
    let failing = [f(
        "garbage",
        [&sb[..], b"PK\x03\x04garbage, not a zip archive"].concat(),
    )];
    oracle_failing(&failing);
    cli_same(&failing, &["-T", "1700000000"]);
}

/// A Zip64 member of [`zip64`]: which of its local sizes go to a Zip64 extra field (with
/// these values), which of its central usize, csize and offset do, plus values the
/// central field has too many of.
#[derive(Clone, Default)]
struct Z64 {
    local: Option<(u64, u64)>,
    central: [bool; 3],
    extra_values: usize,
}

fn z64x(values: &[u64]) -> Vec<u8> {
    ext(
        0x0001,
        &values
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>(),
    )
}

/// An archive of `entries`, with Zip64 end records (`end`: 0 none, 1 with the end record
/// holding markers, 2 with it holding the real values) and Zip64 fields as `z` says.
fn zip64(entries: &[(Ent, Z64)], end: u8, comment: &[u8]) -> Vec<u8> {
    let mut members: Vec<Ent> = Vec::new();
    for (e, z) in entries {
        let mut e = e.clone();
        if let Some(vals) = z.local {
            e.local_extra = [&e.local_extra[..], &z64x(&[vals.0, vals.1])].concat();
        }
        members.push(e);
    }
    let mut d = zip_with(&members, b"");
    // the sizes and offsets the Zip64 fields take, central extras appended
    let mut cd = d.len() - 22 - (le32(&d, d.len() - 22 + 12));
    let mut local_fix = Vec::new();
    let mut out_cd = Vec::new();
    for (_, z) in entries {
        let (nl, xl, kl) = (le16(&d, cd + 28), le16(&d, cd + 30), le16(&d, cd + 32));
        let mut c = d[cd..cd + 46 + nl + xl + kl].to_vec();
        let off = le32(&c, 42);
        if z.local.is_some() {
            local_fix.push(off);
        }
        let mut values = Vec::new();
        for (i, at) in [(0, 24), (1, 20), (2, 42)] {
            if z.central[i] {
                values.push(u64::try_from(le32(&c, at)).unwrap());
                c[at..at + 4].fill(0xff);
            }
        }
        values.extend(std::iter::repeat_n(7, z.extra_values));
        if !values.is_empty() {
            let x = z64x(&values);
            let at = 46 + nl + xl;
            c.splice(at..at, x.iter().copied());
            c[30..32].copy_from_slice(&u16::try_from(xl + x.len()).unwrap().to_le_bytes());
        }
        out_cd.extend(c);
        cd += 46 + nl + xl + kl;
    }
    let cd_start = d.len() - 22 - le32(&d, d.len() - 22 + 12);
    for off in local_fix {
        d[off + 18..off + 26].fill(0xff);
    }
    d.truncate(cd_start);
    let n = u64::try_from(entries.len()).unwrap();
    let cd_size = u64::try_from(out_cd.len()).unwrap();
    d.extend(out_cd);
    let start = u64::try_from(cd_start).unwrap();
    if end > 0 {
        let rec = u64::try_from(d.len()).unwrap();
        d.extend_from_slice(b"PK\x06\x06");
        d.extend_from_slice(&44_u64.to_le_bytes());
        d.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        for v in [n, n, cd_size, start] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d.extend_from_slice(b"PK\x06\x07\0\0\0\0");
        d.extend_from_slice(&rec.to_le_bytes());
        d.extend_from_slice(&1_u32.to_le_bytes());
    }
    d.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    let n16 = u16::try_from(n).unwrap();
    let (count, size, offset) = if end == 1 {
        (u16::MAX, u32::MAX, u32::MAX)
    } else {
        (
            n16,
            u32::try_from(cd_size).unwrap(),
            u32::try_from(start).unwrap(),
        )
    };
    for x in [count, count] {
        d.extend_from_slice(&x.to_le_bytes());
    }
    d.extend_from_slice(&size.to_le_bytes());
    d.extend_from_slice(&offset.to_le_bytes());
    d.extend_from_slice(&u16::try_from(comment.len()).unwrap().to_le_bytes());
    d.extend_from_slice(comment);
    d
}

#[test]
fn zip64_archives() {
    let none = Z64::default();
    let plain = |name: &str, data: &[u8]| (ent(name, data), none.clone());
    let three = [
        plain("b.txt", b"hello\n"),
        plain("a/", b""),
        (
            Ent {
                deflated: true,
                ..ent("a/c", &b"x".repeat(100))
            },
            none.clone(),
        ),
    ];
    let local = |need: u16, vals| {
        (
            Ent {
                needed: need,
                ..ent("b.txt", b"hello\n")
            },
            Z64 {
                local: Some(vals),
                ..Z64::default()
            },
        )
    };
    let central = |c: [bool; 3], extra_values| {
        (
            ent("b.txt", b"hello\n"),
            Z64 {
                central: c,
                extra_values,
                ..Z64::default()
            },
        )
    };
    let streamed = |end| {
        let e = Ent {
            deflated: true,
            flags: 8,
            needed: 45,
            ..ent("-", b"hello\n")
        };
        let mut d = zip64(
            &[(
                e,
                Z64 {
                    local: Some((0, 0)),
                    ..Z64::default()
                },
            )],
            end,
            b"",
        );
        // the descriptor with 8-byte sizes
        let at = find(&d, b"PK\x07\x08", 0);
        let (crc, cs, us) = (le32(&d, at + 4), le32(&d, at + 8), le32(&d, at + 12));
        let mut dd = b"PK\x07\x08".to_vec();
        dd.extend_from_slice(&u32::try_from(crc).unwrap().to_le_bytes());
        dd.extend_from_slice(&u64::try_from(cs).unwrap().to_le_bytes());
        dd.extend_from_slice(&u64::try_from(us).unwrap().to_le_bytes());
        d.splice(at..at + 16, dd);
        // the offsets after it moved by 8
        zip_offsets_shift(&d, at, 8)
    };
    let mut files = vec![
        f("end-markers.zip", zip64(&three, 1, b"")),
        f("end-real.zip", zip64(&three, 2, b"")),
        f("end-markers.jar", zip64(&three, 1, b"")),
        f("comment.zip", zip64(&three, 1, b"a comment")),
        f("no-end-markers.zip", {
            let mut d = zip64(&three, 0, b"");
            let n = d.len();
            d[n - 12..n - 8].fill(0xff);
            d
        }),
        f("local.zip", zip64(&[local(45, (6, 6))], 2, b"")),
        f("local-markers.zip", zip64(&[local(45, (6, 6))], 1, b"")),
        f("local-20.zip", zip64(&[local(20, (6, 6))], 2, b"")),
        f("local-wrong.zip", zip64(&[local(45, (99, 77))], 2, b"")),
        f("local-no-end.zip", zip64(&[local(45, (6, 6))], 0, b"")),
        f(
            "local-two.zip",
            zip64(&[local(45, (6, 6)), plain("c.txt", b"cc")], 2, b""),
        ),
        f(
            "central-sizes.zip",
            zip64(&[central([true, true, false], 0)], 1, b""),
        ),
        f(
            "central-all.zip",
            zip64(&[central([true, true, true], 0)], 1, b""),
        ),
        f(
            "central-offset.zip",
            zip64(&[central([false, false, true], 0)], 1, b""),
        ),
        f(
            "central-usize.zip",
            zip64(&[central([true, false, false], 0)], 1, b""),
        ),
        f(
            "central-csize.zip",
            zip64(&[central([false, true, false], 0)], 1, b""),
        ),
        f(
            "central-unneeded.zip",
            zip64(&[central([false, false, false], 2)], 1, b""),
        ),
        f(
            "central-short.zip",
            zip64(&[central([true, true, false], 0)], 1, b""),
        ),
        f(
            "central-no-end.zip",
            zip64(&[central([false, false, false], 2)], 0, b""),
        ),
        f("streamed.zip", streamed(2)),
        f("streamed-no-end.zip", streamed(0)),
    ];
    // the Zip64 field shorter than the overflowed fields
    let short = files
        .iter_mut()
        .find(|f| f.0 == "central-short.zip")
        .unwrap();
    short.1 = zip64(&[central([true, true, true], 0)], 1, b"");
    let at = find(&short.1, b"\x01\x00\x18\x00", 0);
    short.1[at + 2] = 0x10;
    short.1.drain(at + 4 + 16..at + 4 + 24);
    let (mut fatal, ok): (Vec<File>, Vec<File>) = files.into_iter().partition(|f| {
        [
            "no-end-markers.zip",
            "central-unneeded.zip",
            "central-short.zip",
            "streamed.zip",
        ]
        .contains(&f.0.as_str())
    });
    oracle(&ok);
    cli_same(&ok, &["-T", "1700000000"]);
    fatal.sort();
    oracle_failing(&fatal);
    cli_same(&fatal, &["-T", "1700000000"]);
}

/// `d` with the offsets of its central directory and end records that point past `at`
/// moved by `by` (data inserted there).
fn zip_offsets_shift(d: &[u8], at: usize, by: u32) -> Vec<u8> {
    let mut d = d.to_vec();
    let eocd = d.len() - 22;
    let bump32 = |d: &mut Vec<u8>, p: usize| {
        let v = u32::try_from(le32(d, p)).unwrap();
        if v != u32::MAX && v as usize > at {
            d[p..p + 4].copy_from_slice(&(v + by).to_le_bytes());
        }
    };
    bump32(&mut d, eocd + 16);
    if d[..eocd].ends_with(&[1, 0, 0, 0]) && d[eocd - 20..].starts_with(b"PK\x06\x07") {
        let loc = eocd - 20;
        let rec =
            usize::try_from(u64::from_le_bytes(d[loc + 8..loc + 16].try_into().unwrap())).unwrap();
        let newrec = u64::try_from(rec).unwrap() + u64::from(by);
        d[loc + 8..loc + 16].copy_from_slice(&newrec.to_le_bytes());
        let start = u64::from_le_bytes(d[rec + 48..rec + 56].try_into().unwrap()) + u64::from(by);
        d[rec + 48..rec + 56].copy_from_slice(&start.to_le_bytes());
    }
    d
}

fn manifest(extra: &[u8]) -> Ent {
    ent(
        "META-INF/MANIFEST.MF",
        &[&b"Manifest-Version: 1.0\r\n"[..], extra].concat(),
    )
}

/// `members` as a jar and as a zip, under `name`.
fn jar_and_zip(name: &str, members: &[Ent]) -> [File; 2] {
    [
        f(&format!("{name}.jar"), zip(members)),
        f(&format!("{name}.zip"), zip(members)),
    ]
}

fn oracle_and_cli(files: &[File]) {
    oracle(files);
    cli_same(files, &["-T", "1700000000"]);
}

#[test]
fn jar_signed() {
    let bnd = manifest(b"Bnd-LastModified: 1\r\n");
    let mut files = Vec::new();
    for (name, sig) in [
        ("signed", "META-INF/A.SF"),
        ("signed-sub", "META-INF/x/A.SF"),
        ("signed-bare", "META-INF/.SF"),
        ("lower", "META-INF/a.sf"),
        ("other-dir", "OTHER/A.SF"),
        ("rsa", "META-INF/A.RSA"),
        ("signed-nl", "META-INF/A.SF\n"),
        ("mid-nl", "META-INF/a\nb.SF"),
    ] {
        files.extend(jar_and_zip(
            name,
            &[bnd.clone(), ent(sig, b"x"), ent("a.clj", b"x")],
        ));
    }
    oracle_and_cli(&files);
    // a signed jar is left alone before its javac leftovers are looked at: no removal
    // is reported
    let tmp = tempfile::tempdir().unwrap();
    let jar = tmp.path().join("a.jar");
    let d = zip(&[bnd, ent("META-INF/A.SF", b"x"), ent("javac.sh", b"x")]);
    fs::write(&jar, &d).unwrap();
    let o = Command::new(EXE)
        .args(["strip-nondeterminism", "-T", "1700000000"])
        .arg(&jar)
        .output()
        .unwrap();
    assert!(o.status.success(), "{o:?}");
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("ignoring signed JAR file"), "{stderr}");
    assert!(!stderr.contains("Removing"), "{stderr}");
    assert_eq!(fs::read(&jar).unwrap(), d);
}

#[test]
fn jar_removed_members() {
    oracle_and_cli(&jar_and_zip(
        "removed",
        &[
            ent("javac.sh", b"x"),
            ent("x/javac.sh", b"x"),
            ent("javac.shx", b"x"),
            ent(
                "org.codehaus.plexus.compiler.javac.JavacCompiler123arguments",
                b"x",
            ),
            ent(
                "org.codehaus.plexus.compiler.javac.JavacCompilerarguments",
                b"x",
            ),
            ent(
                "org.codehaus.plexus.compiler.javac.JavacCompiler1argumentsx",
                b"x",
            ),
            ent(
                "x/org.codehaus.plexus.compiler.javac.JavacCompiler1arguments",
                b"x",
            ),
            ent("00", b"x"),
            ent("kept", b"x"),
        ],
    ));
    // strip-nondeterminism drops a member named 0 too: a bug, not reproduced
    let jar = zip(&[ent("b", b"x"), ent("0", b"x")]);
    let (ok, out) = ours_cli(&f("zero.jar", jar), &["-T", "1700000000"]);
    assert!(ok);
    let names: Vec<Vec<u8>> = zip_members(&out)
        .unwrap()
        .0
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert_eq!(names, [b"0".to_vec(), b"b".to_vec()]);
}

/// This binary's strip-nondeterminism (native handlers only) on `file` alone: whether
/// it succeeded, and the file after it.
fn ours_cli(file: &File, args: &[&str]) -> (bool, Vec<u8>) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(&file.0);
    fs::write(&path, &file.1).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(file.2)).unwrap();
    let o = Command::new(EXE)
        .args(["strip-nondeterminism"])
        .args(args)
        .arg(&path)
        .output()
        .unwrap();
    (o.status.success(), fs::read(&path).unwrap())
}

#[test]
fn zip_empty_members() {
    let mut members = vec![
        Ent {
            deflated: true,
            ..ent("deflated", b"")
        },
        Ent {
            deflated: true,
            flags: 8,
            ..ent("deflated-dd", b"")
        },
        Ent {
            flags: 8,
            ..ent("stored-dd", b"")
        },
        Ent {
            deflated: true,
            flags: 2,
            ..ent("deflated-max", b"")
        },
        ent("stored", b""),
        ent("dir/", b""),
        ent("a", b"a"),
    ];
    let mut files = jar_and_zip("empty", &members).to_vec();
    // an unknown method
    members.truncate(1);
    let mut odd = zip(&members);
    let at = find(&odd, b"PK\x01\x02", 0);
    odd[at + 10..at + 12].copy_from_slice(&99_u16.to_le_bytes());
    odd[8..10].copy_from_slice(&99_u16.to_le_bytes());
    files.push(f("method99.zip", odd));
    oracle_and_cli(&files);
}

#[test]
fn zip_directory_entries() {
    let local = |name: &str, at: usize, value: &[u8]| {
        let mut d = zip(&[ent(name, b""), ent("c", b"c")]);
        d[at..at + value.len()].copy_from_slice(value);
        d
    };
    let mut files = Vec::new();
    for (name, d) in [
        ("version", local("a/b/", 4, &10_u16.to_le_bytes())),
        ("flags", local("a/b/", 6, &0x800_u16.to_le_bytes())),
        ("method", local("a/b/", 8, &8_u16.to_le_bytes())),
        ("time", local("a/b/", 10, &[1, 2, 3, 4])),
        ("backslash", local("a/b/", 30, b"a\\b/")),
        ("slashes", local("d//e/", 30, b"d/e//")),
        ("other-name", local("a/b/", 30, b"x/y/")),
        ("crc", local("a/b/", 14, &[1, 0, 0, 0])),
        ("size", local("a/b/", 22, &[1, 0, 0, 0])),
    ] {
        files.push(f(&format!("{name}.zip"), d.clone()));
        files.push(f(&format!("{name}.jar"), d));
    }
    let (fatal, ok): (Vec<File>, Vec<File>) = files
        .into_iter()
        .partition(|f| f.0.starts_with("crc") || f.0.starts_with("size"));
    oracle_and_cli(&ok);
    oracle_failing(&fatal);
    cli_same(&fatal, &["-T", "1700000000"]);
}

#[test]
fn zip_names() {
    let mut files = Vec::new();
    for ext in [
        "pk3", "zhfst", "codadef", "PK3", "pk4", "odt", "docx", "nupkg", "aar", "ear", "kar",
    ] {
        files.push(f(
            &format!("x.{ext}"),
            zip(&[ent("b", b"b"), ent("a", b"a")]),
        ));
    }
    oracle_and_cli(&files);
}

#[test]
fn zip_extra_fields() {
    let ut = ext(0x5455, b"\x01\x00\xf1\x53\x65");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "ux-v2",
            ext(0x7875, b"\x02\x04\xe8\x03\0\0\x04\xe8\x03\0\0"),
        ),
        ("ux-v0", ext(0x7875, b"\x00\x02\xe8\x03\x02\xe8\x03")),
        ("unknown-over3", [&ut[..], b"\xfe\xca\x05\x00ab"].concat()),
        ("tail3-ut", [&ut[..], b"UT\x05"].concat()),
        ("zero", ext(0, b"")),
    ];
    let mut files = Vec::new();
    for (name, x) in cases {
        files.push(f(
            &format!("{name}-central.zip"),
            zip(&[Ent {
                central_extra: x.clone(),
                ..ent("a", b"a")
            }]),
        ));
        files.push(f(
            &format!("{name}-local.zip"),
            zip(&[Ent {
                local_extra: x,
                ..ent("a", b"a")
            }]),
        ));
    }
    oracle_and_cli(&files);
    // strip-nondeterminism drops a stray byte, and every field of a header with 2 or 3
    // stray bytes or a field running 4 bytes past its end: bugs, not reproduced; the
    // bytes are kept as they are
    let normalized_ut = ext(0x5455, b"\x01\x00\xf1\x53\x65");
    for tail in [
        &b"\x00"[..],
        b"xy",
        b"\xfe\xca\x09\x00ab",
        b"\xfe\xca\x06\x00ab",
    ] {
        let x = [&ut[..], tail].concat();
        let file = f(
            "tail.zip",
            zip(&[Ent {
                local_extra: x.clone(),
                central_extra: x,
                ..ent("a", b"a")
            }]),
        );
        let (ok, out) = ours_cli(&file, &["-T", "1700000000"]);
        assert!(ok);
        let (members, _) = zip_members(&out).unwrap();
        let want = [&normalized_ut[..], tail].concat();
        assert!(
            members[0].central.ends_with(&[b"a", &want[..]].concat()),
            "{tail:?}"
        );
    }
    // strip-nondeterminism writes an Info-ZIP Unix field whose uid and gid sizes do not
    // add up to its length again from those sizes, under its old length: a bug, not
    // reproduced; the field is kept as it is
    for ux in [
        ext(0x7875, b"\x01\x04\xe8\x03\0\0"),
        ext(0x7875, b"\x01\x02\xe8\x03\x02\xe8\x03xy"),
    ] {
        let file = f(
            "ux.zip",
            zip(&[Ent {
                local_extra: ux.clone(),
                central_extra: ux.clone(),
                ..ent("a", b"a")
            }]),
        );
        let (ok, out) = ours_cli(&file, &["-T", "1700000000"]);
        assert!(ok);
        let (members, _) = zip_members(&out).unwrap();
        assert!(
            members[0].central.ends_with(&[b"a", &ux[..]].concat()),
            "{ux:?}"
        );
    }
}

#[test]
fn jar_unknown_methods() {
    let method99 = |members: &[Ent], which: &[u8]| {
        let mut d = zip(members);
        let local = find(&d, &[b"\0\0", which].concat(), 0) - 28;
        d[local + 8..local + 10].copy_from_slice(&99_u16.to_le_bytes());
        let at = find(&d, b"PK\x01\x02", 0);
        let mut cd = at;
        while d[cd..].starts_with(b"PK\x01\x02") {
            let n = le16(&d, cd + 28);
            if &d[cd + 46..cd + 46 + n] == which {
                d[cd + 10..cd + 12].copy_from_slice(&99_u16.to_le_bytes());
            }
            cd += 46 + n + le16(&d, cd + 30) + le16(&d, cd + 32);
        }
        d
    };
    let javadoc = b"<!-- Generated by javadoc (1) on x -->\n<html></html>\n";
    let files = [
        f(
            "manifest.jar",
            method99(
                &[manifest(b"Bnd-LastModified: 1\r\n"), ent("b", b"b")],
                b"META-INF/MANIFEST.MF",
            ),
        ),
        f(
            "manifest-plain.jar",
            method99(&[manifest(b""), ent("b", b"b")], b"META-INF/MANIFEST.MF"),
        ),
        f(
            "javadoc.jar",
            method99(&[ent("a.html", javadoc), ent("b", b"b")], b"a.html"),
        ),
        f(
            "plain-html.jar",
            method99(
                &[ent("a.html", b"<html></html>\n"), ent("b", b"b")],
                b"a.html",
            ),
        ),
        f(
            "nested.jar",
            method99(
                &[ent("in.jar", &zip(&[ent("z", b"z")])), ent("b", b"b")],
                b"in.jar",
            ),
        ),
    ];
    let (fatal, ok): (Vec<File>, Vec<File>) = files
        .iter()
        .cloned()
        .partition(|f| f.0 == "javadoc.jar" || f.0 == "plain-html.jar");
    oracle(&ok);
    oracle_failing(&fatal);
    cli_same(&files, &["-T", "1700000000"]);
    oracle_and_cli(&[f(
        "other.jar",
        method99(&[ent("x.class", b"x"), ent("b", b"b")], b"x.class"),
    )]);
}

/// Jars in jars: normalized as strip-nondeterminism normalizes them up to 32 deep; one
/// nested deeper fails the archive (strip-nondeterminism has no limit).
#[test]
fn jar_nesting() {
    let nest = |n: usize| {
        let mut z = zip(&[ent("b.class", b"x"), ent("a.class", b"y")]);
        for _ in 0..n {
            z = zip(&[ent("z.class", b"x"), ent("in.jar", &z)]);
        }
        z
    };
    cli_same(
        &[f("a.jar", nest(2)), f("b.jar", nest(32))],
        &["-T", "1700000000"],
    );
    let deep = f("c.jar", nest(33));
    assert_eq!(
        ours_cli(&deep, &["-T", "1700000000"]),
        (false, deep.1.clone())
    );
}

#[test]
fn jar_manifest_built_by() {
    oracle_and_cli(&jar_and_zip(
        "built-by",
        &[manifest(
            b"Built-By: someone\r\n continued\r\nBuilt-Byx: 1\r\nX-Built-By: 2\r\n",
        )],
    ));
}

/// Jar members strip-nondeterminism rewrites, stored.
fn jar_members() -> Vec<Ent> {
    let javadoc = b"<!-- Generated by javadoc (1.8.0) on Thu Jan 02 03:04:05 UTC 2030 -->\n\
                    <meta name=\"date\" content=\"2030-01-02\">\n<html></html>\n";
    let nested = zip(&[
        ent("b", b"b"),
        ent("META-INF/MANIFEST.MF", b"M: 1\r\nBnd-LastModified: 1\r\n"),
        ent("a.clj", b"x"),
        ent("doc/i.html", javadoc),
        ent("x/i.jar", &zip(&[ent("z", b"z")])),
    ]);
    vec![
        ent(
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\r\nBnd-LastModified: 1\r\nbnd-lastmodified: 2\r\n\
              X-Bnd-LastModified: 3\r\nBnd-LastModified:4\r\nBnd-LastModified: 1\r\n continued\r\n\
              \r\nName: a\r\nBnd-LastModified: 8\r\n\r\nBnd-LastModified: 9",
        ),
        ent("META-INF/sub/MANIFEST.MF", b"Bnd-LastModified: 1\r\n"),
        ent("doc/index.html", javadoc),
        ent("doc/index.htm", javadoc),
        ent("doc/plain.html", b"<html></html>\n"),
        ent("doc/empty.html", b"<!-- Generated by javadoc (1) -->\n"),
        ent("lib/in.jar", &nested),
        ent("lib/in.war", &nested),
        ent("lib/in.zip", &nested),
        ent("lib/bad.jar", b"not a zip"),
        ent("x.gz", &gz(0, 1_800_000_000, 0, 3, b"")),
        ent("p.png", &png(&[(b"tIME", b"\x07\xee\x01\x02\x03\x04\x05")])),
        ent(
            "META-INF/maven/g/a/pom.properties",
            b"#Generated by Maven\n#Thu Jan 02 03:04:05 GMT 2030\ngroupId=g\n",
        ),
        ent("b.cljs", b"x"),
        ent("c.CLJ", b"x"),
        ent("d/e.clj", b"x"),
        ent("C.class", b"\xca\xfe\xba\xbe"),
    ]
}

#[test]
fn jar_archives() {
    let members = jar_members();
    oracle(&[
        f("members.jar", zip(&members)),
        f("members.zip", zip(&members)),
        f("members.war", zip(&members)),
        f(
            "single.jar",
            zip(&[ent("META-INF/MANIFEST.MF", b"Bnd-LastModified: 1\r\n")]),
        ),
        f(
            "zero.jar",
            zip(&[ent("META-INF/MANIFEST.MF", b"Bnd-LastModified: 1\r\n0")]),
        ),
    ]);
}

#[test]
fn png_images() {
    let time = (&b"tIME"[..], &b"\x07\xee\x01\x02\x03\x04\x05"[..]);
    let text = |k: &str| [k.as_bytes(), b"\0", b"2030-01-02T03:04:05+00:00"].concat();
    let keys = [
        "date:create",
        "date:modify",
        "date:timestamp",
        "date:x",
        "date:",
        "date",
        "Date:create",
        "Creation Time",
        "creation time",
        "Creation Time ",
        "Software",
    ];
    let mut files: Vec<File> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| f(&format!("key{i:02}.png"), png(&[(b"tEXt", &text(k))])))
        .collect();
    let mut bad_crc = png(&[time]);
    let at = bad_crc.windows(4).position(|w| w == b"tIME").unwrap() + 11;
    bad_crc[at] ^= 0xff;
    let mut after_iend = png(&[]);
    png_chunk(&mut after_iend, b"tIME", time.1);
    let mut trailing = png(&[time]);
    trailing.extend_from_slice(b"TRAILING");
    let mut truncated = png(&[time]);
    truncated.truncate(truncated.len() - 12);
    let ztxt = [&b"date:create\0\0"[..], &deflate(b"2030")].concat();
    files.extend([
        f("time.png", png(&[time])),
        f(
            "old.png",
            png(&[(b"tIME", b"\x07\xd0\x01\x02\x03\x04\x05")]),
        ),
        f(
            "long.png",
            png(&[(b"tIME", b"\x07\xee\x01\x02\x03\x04\x05\x06")]),
        ),
        f("short.png", png(&[(b"tIME", b"\x07\xee\x01")])),
        f("plain.png", png(&[])),
        f("nokey.png", png(&[(b"tEXt", b"date:create")])),
        f("ztxt.png", png(&[(b"zTXt", &ztxt)])),
        f("itxt.png", png(&[(b"iTXt", &text("date:create"))])),
        f("badcrc.png", bad_crc),
        f("after-iend.png", after_iend),
        f("trailing.png", trailing),
        f("truncated.png", truncated),
        f(
            "multi.png",
            png(&[
                time,
                (b"tEXt", &text("date:create")),
                (b"tEXt", &text("date:modify")),
            ]),
        ),
        f("signature.png", b"\x89PNG\r\n\x1a\n".to_vec()),
        f("upper.PNG", png(&[time])),
    ]);
    oracle(&files);
}

#[test]
fn gettext_catalogs() {
    let hdr = |pot: &str, rev: &str| {
        format!(
            "Project-Id-Version: x\nPOT-Creation-Date: {pot}\nPO-Revision-Date: {rev}\n\
             Content-Type: text/plain; charset=UTF-8\n"
        )
    };
    let d = "2030-01-02 03:04+0100";
    let one = |h: &str| mo(&[("", h), ("a", "b")], 0, false);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("le.mo", one(&hdr(d, d))),
        ("be.mo", mo(&[("", &hdr(d, d)), ("a", "b")], 0, true)),
        ("x.gmo", one(&hdr(d, d))),
        ("old.mo", one(&hdr("2020-01-02 03:04+0100", d))),
        ("zone-before.mo", one(&hdr("2024-10-14 11:34+0100", d))),
        ("zone-after.mo", one(&hdr("2024-10-14 10:35+0000", d))),
        ("same-minute.mo", one(&hdr("2024-10-14 10:34+0000", d))),
        (
            "rev-first.mo",
            one(&format!("PO-Revision-Date: {d}\nPOT-Creation-Date: {d}\n")),
        ),
        (
            "rev-only.mo",
            one(&format!("X: y\nPO-Revision-Date: {d}\n")),
        ),
        (
            "seconds.mo",
            one("POT-Creation-Date: 2030-01-02 03:04:05+0100\n"),
        ),
        (
            "colon-zone.mo",
            one("POT-Creation-Date: 2030-01-02 03:04+01:00\n"),
        ),
        ("no-zone.mo", one("POT-Creation-Date: 2030-01-02 03:04\n")),
        ("trailing.mo", one(&format!("POT-Creation-Date: {d} x\n"))),
        ("crlf.mo", one(&format!("POT-Creation-Date: {d}\r\n"))),
        (
            "mid-line.mo",
            one(&format!("X-Foo: POT-Creation-Date: {d}\n")),
        ),
        ("no-newline.mo", one(&format!("POT-Creation-Date: {d}"))),
        (
            "bad-date.mo",
            one("POT-Creation-Date: 2030-13-45 03:04+0100\n"),
        ),
        (
            "revision1.mo",
            mo(&[("", &format!("POT-Creation-Date: {d}\n"))], 1, false),
        ),
        (
            "major1.mo",
            mo(
                &[("", &format!("POT-Creation-Date: {d}\n"))],
                0x1_0000,
                false,
            ),
        ),
        (
            "header-second.mo",
            mo(
                &[("a", "b"), ("", &format!("POT-Creation-Date: {d}\n"))],
                0,
                false,
            ),
        ),
        (
            "no-header.mo",
            mo(&[("a", &format!("POT-Creation-Date: {d}\n"))], 0, false),
        ),
        ("short.mo", b"\xde\x12\x04\x95abc".to_vec()),
        ("text.mo", b"not a catalog\n".to_vec()),
    ];
    let files: Vec<File> = cases.into_iter().map(|(n, c)| f(n, c)).collect();
    oracle(&files);
}

#[test]
fn javadoc_pages() {
    let c = "<!-- Generated by javadoc (1.8.0) on Thu Jan 02 03:04:05 UTC 2030 -->";
    let meta = "<meta name=\"date\" content=\"2030-01-02\">";
    let cases = [
        format!("{c}\n<html></html>\n"),
        format!("<!DOCTYPE HTML>\n{c}\n<html>\n<head>\n{meta}\n<meta name=\"dc.created\" content=\"2030-01-02\">\n</head>\n"),
        format!("x {c}\ny\n"),
        format!("{c} y\nz\n"),
        format!("\t{c}  \r\nz\n"),
        format!("{c} {c}\nz\n"),
        format!("a\n\n  {c}\nz\n"),
        c.to_owned(),
        format!("{c}\r{c}\r"),
        "<!-- Generated by javadoc -->\nx\n".to_owned(),
        "<!-- Generated by javadoc -- and more -->\nx\n".to_owned(),
        "<!-- Generated by javadoc\n on two lines -->\nx\n".to_owned(),
        "<!-- generated by javadoc (1) -->\nx\n".to_owned(),
        format!("<!-- Generated by javadoc -->\n{meta}\n<META NAME=\"Date\" CONTENT=\"x\">\n"),
        "<!-- Generated by javadoc -->\n<meta  name=\"date\" content=\"x\">\n<meta name='date' content='x'>\n<meta name=\"date\" content=\"x\"/>\n<meta name=\"dc.modified\" content=\"x\">\n".to_owned(),
        "<!-- Generated by javadoc -->\n<meta name=\"date\" content=\"2024-10-14\">\n".to_owned(),
        format!("<html>\n{meta}\n"),
        format!("{}{c}\nx\n", "a\n".repeat(14)),
        format!("{}{c}\nx\n", "a\n".repeat(15)),
        format!("{c}\n{}{meta}\n", "a\n".repeat(13)),
        format!("{c}\n{}{meta}\n", "a\n".repeat(14)),
        format!("{}\n{c}\nx\n", "y".repeat(998)),
        format!("{}\n{c}\nx\n", "y".repeat(999)),
        format!("{c}\n{}\n{meta}\n", "z".repeat(5000)),
    ];
    let mut files: Vec<File> = cases
        .iter()
        .enumerate()
        .map(|(i, s)| f(&format!("api/c{i:02}.html"), s.as_bytes()))
        .collect();
    for name in ["x.htm", "x.xhtml", "x.HTML"] {
        files.push(f(name, cases[0].as_bytes()));
    }
    oracle(&files);
}

/// A U-Boot legacy image of `data` created at `time`, with a header CRC off by `crc_off`.
fn uimage(time: u32, magic: u32, crc_off: u32, data: &[u8]) -> Vec<u8> {
    let mut h = Vec::new();
    for w in [
        magic,
        0,
        time,
        u32::try_from(data.len()).unwrap(),
        0x8000,
        0x8000,
        crc32(data),
    ] {
        h.extend_from_slice(&w.to_be_bytes());
    }
    h.extend_from_slice(&[5, 2, 2, 0]);
    let mut name = [0_u8; 32];
    name[..10].copy_from_slice(b"test image");
    h.extend_from_slice(&name);
    let sum = crc32(&h) ^ crc_off;
    h[4..8].copy_from_slice(&sum.to_be_bytes());
    [&h[..], data].concat()
}

#[test]
fn uimage_images() {
    const MAGIC: u32 = 0x2705_1956;
    let img = |t: u32| uimage(t, MAGIC, 0, b"hello world\n");
    let mut files = vec![
        f("plain.uimage", img(1_800_000_000)),
        f("older.uimage", img(1000)),
        f("zero.uimage", img(0)),
        f("max.uimage", img(u32::MAX)),
        // the changelog date, the oracle's timestamp
        f("same.uimage", img(1_728_902_097)),
        f("bad-hcrc.uimage", uimage(1_800_000_000, MAGIC, 1, b"x")),
        f(
            "bad-magic.uimage",
            uimage(1_800_000_000, MAGIC + 1, 0, b"x"),
        ),
        f("header-only.uimage", uimage(1_800_000_000, MAGIC, 0, b"")),
        f("short.uimage", img(1_800_000_000)[..63].to_vec()),
        f(
            "trailing.uimage",
            [&img(1_800_000_000)[..], b"trailing"].concat(),
        ),
        f("truncated.uimage", img(1_800_000_000)[..70].to_vec()),
        f("empty.uimage", Vec::new()),
        f("text.uimage", b"hello\n".to_vec()),
        f("upper.uImage", img(1_800_000_000)),
        f("UPPER.UIMAGE", img(1_800_000_000)),
        f(".uimage", img(1_800_000_000)),
        ("exec.uimage".to_owned(), img(1_800_000_000), 0o755),
        ("ro.uimage".to_owned(), img(1_800_000_000), 0o444),
    ];
    // names of no handler: file(1) knows these too
    for n in [
        "uImage",
        "x.img",
        "x.ub",
        "x.bin",
        "x.uimage.gz.not",
        "boot.scr",
    ] {
        files.push(f(n, img(1_800_000_000)));
    }
    oracle(&files);
    cli_same(&files, &["-T", "1234"]);
    cli_same(&[f("wrap.uimage", img(5))], &["-T", "4294967297"]);
    cli_same(&[f("forced", img(5))], &["-T", "1234", "-t", "uimage"]);
}

/// A bFLT header: `fields` (version, entry, data start and end, bss end, stack size,
/// relocations' start and count, flags), the build date, 20 reserved bytes; then code.
fn bflt(fields: [u32; 9], date: u32, reserved: u8) -> Vec<u8> {
    let mut v = b"bFLT".to_vec();
    for w in fields.iter().chain([&date]) {
        v.extend_from_slice(&w.to_be_bytes());
    }
    v.extend_from_slice(&[reserved; 20]);
    v.extend_from_slice(b"code");
    v
}

/// The fields of a bFLT header strip-nondeterminism takes: version, entry, data start
/// and end, bss end, stack size, relocations' start and count, flags.
const BFLT: [u32; 9] = [4, 0x40, 0x44, 0x48, 0x50, 0x1000, 0x48, 0, 0];

#[test]
fn bflt_executables() {
    const F: [u32; 9] = BFLT;
    let with = |i: usize, v: u32| {
        let mut f = F;
        f[i] = v;
        bflt(f, 1_800_000_000, 0)
    };
    let mut files = vec![
        f("plain.bflt", bflt(F, 1_800_000_000, 0)),
        f("older.bflt", bflt(F, 1000, 0)),
        f("zero.bflt", bflt(F, 0, 0)),
        f("same.bflt", bflt(F, 1_728_902_097, 0)),
        f("max.bflt", bflt(F, u32::MAX, 0)),
        f("reserved.bflt", bflt(F, 1_800_000_000, 1)),
        f(
            "magic.bflt",
            [&b"bFLt"[..], &bflt(F, 1_800_000_000, 0)[4..]].concat(),
        ),
        f("header.bflt", bflt(F, 1_800_000_000, 0)[..64].to_vec()),
        f("short.bflt", bflt(F, 1_800_000_000, 0)[..63].to_vec()),
        f("text.bflt", b"hello\n".to_vec()),
        f("empty.bflt", Vec::new()),
        f(".bflt", bflt(F, 1_800_000_000, 0)),
        ("exec.bflt".to_owned(), bflt(F, 1_800_000_000, 0), 0o755),
        ("ro.bflt".to_owned(), bflt(F, 1_800_000_000, 0), 0o444),
    ];
    for (i, v) in [
        (0, 3),
        (0, 5),
        (0, 0x0400_0000),
        (1, 0x0fff_fffe),
        (1, 0x0fff_ffff),
        (2, u32::MAX),
        (3, 0x0fff_ffff),
        (4, 0x0fff_ffff),
        (5, 0x00ff_fffe),
        (5, 0x00ff_ffff),
        (6, 0x0fff_fffe),
        (6, 0x0fff_ffff),
        (7, 0x00ff_fffe),
        (7, 0x00ff_ffff),
        (8, 0x3f),
        (8, 0x40),
        (8, 0x8000_0000),
    ] {
        files.push(f(&format!("field{i}-{v:x}.bflt"), with(i, v)));
    }
    // names of no handler
    for n in ["x", "x.BFLT", "x.flt", "busybox"] {
        files.push(f(n, bflt(F, 1_800_000_000, 0)));
    }
    oracle(&files);
    cli_same(&files, &["-T", "1234"]);
    cli_same(&[f("wrap.bflt", bflt(F, 5, 0))], &["-T", "4294967297"]);
    cli_same(&[f("forced", bflt(F, 5, 0))], &["-T", "1234", "-t", "bflt"]);
}

/// A newc cpio entry: (ino, mode, nlink, mtime) and the name (NUL added) and data.
fn newc(magic: &[u8], name: &[u8], data: &[u8], fields: [u32; 4]) -> Vec<u8> {
    let [ino, mode, nlink, mtime] = fields;
    let name = [name, b"\0"].concat();
    let mut v = magic.to_vec();
    for x in [
        ino,
        mode,
        1000,
        1000,
        nlink,
        mtime,
        u32::try_from(data.len()).unwrap(),
        8,
        1,
        0,
        0,
        u32::try_from(name.len()).unwrap(),
        0,
    ] {
        v.extend_from_slice(format!("{x:08X}").as_bytes());
    }
    v.extend_from_slice(&name);
    v.resize(v.len().next_multiple_of(4), 0);
    v.extend_from_slice(data);
    v.resize(v.len().next_multiple_of(4), 0);
    v
}

fn odc(name: &[u8], data: &[u8], mtime: u64) -> Vec<u8> {
    let name = [name, b"\0"].concat();
    let mut v = format!(
        "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{mtime:011o}{:06o}{:011o}",
        0o2001,
        5,
        0o100_644,
        1000,
        1000,
        1,
        0,
        name.len(),
        data.len()
    )
    .into_bytes();
    v.extend_from_slice(&name);
    v.extend_from_slice(data);
    v
}

fn bincpio(name: &[u8], data: &[u8], mtime: u32) -> Vec<u8> {
    let name = [name, b"\0"].concat();
    let mut v = Vec::new();
    let len = u32::try_from(data.len()).unwrap();
    for w in [
        0o070_707,
        0x801,
        5,
        0o100_644,
        1000,
        1000,
        1,
        0,
        mtime >> 16,
        mtime & 0xffff,
        u32::try_from(name.len()).unwrap(),
        len >> 16,
        len & 0xffff,
    ] {
        v.extend_from_slice(&u16::try_from(w).unwrap().to_le_bytes());
    }
    v.extend_from_slice(&name);
    v.resize(v.len().next_multiple_of(2), 0);
    v.extend_from_slice(data);
    v.resize(v.len().next_multiple_of(2), 0);
    v
}

#[test]
fn cpio_archives() {
    const M: &[u8] = b"070701";
    const T: u32 = 1_800_000_000;
    let e = |name: &[u8], data: &[u8]| newc(M, name, data, [5, 0o100_644, 1, T]);
    let trailer = newc(M, b"TRAILER!!!", b"", [0, 0, 1, 0]);
    let block = |mut v: Vec<u8>| {
        v.resize(v.len().next_multiple_of(512), 0);
        v
    };
    let tree = [
        e(b"b", b"hello\n"),
        newc(M, b"a/", b"", [6, 0o40_755, 2, T]),
        newc(M, b"a/c", b"x", [7, 0o100_755, 1, 0]),
        newc(M, b"l", b"b", [8, 0o120_777, 1, 1_728_902_097]),
        newc(M, b"h1", b"", [9, 0o100_644, 2, T]),
        newc(M, b"h2", b"data", [9, 0o100_644, 2, T]),
        newc(M, b"dev/null", b"", [10, 0o20_666, 1, T]),
    ]
    .concat();
    let otrailer = odc(b"TRAILER!!!", b"", 0);
    let btrailer = bincpio(b"TRAILER!!!", b"", 0);
    let one = [&e(b"b", b"hello\n")[..], &trailer].concat();
    let mut lower = one.clone();
    let at = find(&lower, b"6B49D200", 0);
    lower[at..at + 8].copy_from_slice(b"6b49d200");
    let mut bad_hex = one.clone();
    bad_hex[at + 7] = b'G';
    let mut files = vec![
        f("tree.cpio", block([&tree[..], &trailer].concat())),
        f("unblocked.cpio", [&tree[..], &trailer].concat()),
        f("one.cpio", one.clone()),
        f("lower.cpio", lower),
        f(
            "junk-after.cpio",
            [&one[..], b"garbage after the trailer"].concat(),
        ),
        f("two.cpio", [&one[..], &one[..]].concat()),
        f(
            "no-nul.cpio",
            [&newc(M, b"bc", b"x", [1, 0o100_644, 1, T])[..], &trailer].concat(),
        ),
        f(
            "nuls.cpio",
            [&newc(M, b"a\0\0", b"x", [1, 0o100_644, 1, T])[..], &trailer].concat(),
        ),
        f(
            "long-name.cpio",
            [&e(&[b'n'; 300], b"x")[..], &trailer].concat(),
        ),
        f(
            "big.cpio",
            block([&e(b"f", &[7; 5000])[..], &trailer].concat()),
        ),
        f(
            "crc.cpio",
            [
                &newc(b"070702", b"b", b"x", [1, 0o100_644, 1, T])[..],
                &trailer,
            ]
            .concat(),
        ),
        f("bad-hex.cpio", bad_hex),
        f("no-trailer.cpio", e(b"b", b"hello\n")),
        f("truncated.cpio", one[..115].to_vec()),
        f(
            "mixed.cpio",
            [&e(b"b", b"x")[..], &odc(b"c", b"y", 5), &otrailer].concat(),
        ),
        f(
            "odc.cpio",
            [
                &odc(b"b", b"hello\n", 1_800_000_000)[..],
                &odc(b"a\0\0", b"", 0),
                &otrailer,
            ]
            .concat(),
        ),
        f(
            "odc-block.cpio",
            block([&odc(b"b", b"x", 9)[..], &otrailer].concat()),
        ),
        f(
            "odc-junk.cpio",
            [&odc(b"b", b"x", 9)[..], &otrailer, b"junk"].concat(),
        ),
        f(
            "binary.cpio",
            [
                &bincpio(b"b", b"hello\n", T)[..],
                &bincpio(b"ab", b"xyz", 7),
                &btrailer,
            ]
            .concat(),
        ),
        f(
            "binary-block.cpio",
            block([&bincpio(b"b", b"x", T)[..], &btrailer].concat()),
        ),
        f("text.cpio", b"hello\n".to_vec()),
        f("empty.cpio", Vec::new()),
        ("exec.cpio".to_owned(), one.clone(), 0o755),
        ("ro.cpio".to_owned(), one.clone(), 0o444),
        f("x.CPIO", one.clone()),
        f("initrd.img", one.clone()),
    ];
    let mut odc8 = odc(b"b", b"x", 9);
    odc8[11] = b'8';
    files.push(f("odc-8.cpio", [&odc8[..], &otrailer].concat()));
    let mut be = bincpio(b"b", b"x", T);
    be.swap(0, 1);
    files.push(f("binary-be.cpio", [&be[..], &btrailer].concat()));
    oracle(&files);
    cli_same(&files, &["-T", "1234"]);
    for t in ["0", "4294967295"] {
        cli_same(&files[..3], &["-T", t]);
        cli_same(&files[15..20], &["-T", t]);
    }
    cli_same(&files[15..18], &["-T", "8589934591"]);
    // a timestamp the mtime field cannot hold, which strip-nondeterminism lets overflow
    // into the next fields (a bug, not reproduced), fails the file
    for (file, t) in [
        (&files[2], "4294967296"),
        (&files[16], "8589934592"),
        (&files[19], "4294967296"),
    ] {
        assert_eq!(
            ours_cli(file, &["-T", t]),
            (false, file.1.clone()),
            "{}",
            file.0
        );
    }
    assert!(ours_cli(&files[15], &["-T", "4294967296"]).0);
    cli_same(&[f("forced", one.clone())], &["-T", "1234", "-t", "cpio"]);
    // an archive of no entry fails
    let failing = [f("trailer-only.cpio", trailer.clone())];
    oracle_failing(&failing);
    cli_same(&failing, &["-T", "1234"]);
}

#[test]
fn png_details() {
    let date = |k: &str| [k.as_bytes(), b"\0", b"2030-01-02T03:04:05+00:00"].concat();
    let ztxt = [&b"date:create\0\0"[..], &deflate(b"2030")].concat();
    let itxt = [&b"date:modify\0\0\0\0\0"[..], b"2030"].concat();
    let big_time = [&b"\x07\xee\x01\x02\x03\x04\x05"[..], &[0; 4090]].concat();
    let big_text = [&date("date:create")[..], &[b'x'; 4100]].concat();
    let files = [
        f("ztxt.png", png(&[(b"zTXt", &ztxt)])),
        f("itxt.png", png(&[(b"iTXt", &itxt)])),
        f("itxt-ctime.png", png(&[(b"iTXt", &date("Creation Time"))])),
        f("time-4091.png", png(&[(b"tIME", &[7; 4091])])),
    ];
    oracle_and_cli(&files);
    cli_same(
        &[f("not-png", b"hello\n".to_vec())],
        &["-T", "1700000000", "-t", "png"],
    );
    // a deliberate difference: strip-nondeterminism copies chunks of 4092 bytes or more
    // unexamined, a tIME or date text chunk included
    let t = (&b"tIME"[..], &b"\x07\xe7\x0b\x0e\x16\x0d\x14"[..]);
    let text = [&b"date:create\0"[..], b"2023-11-14T22:13:20-00:00"].concat();
    for (chunk, want) in [
        ((&b"tIME"[..], &big_time[..]), t),
        ((&b"tEXt"[..], &big_text[..]), (&b"tEXt"[..], &text[..])),
    ] {
        let (ok, out) = ours_cli(&f("big.png", png(&[chunk])), &["-T", "1700000000"]);
        assert!(ok);
        assert_eq!(out, png(&[want]));
    }
}

#[test]
fn gettext_details() {
    let h = "POT-Creation-Date: 2030-01-02 03:04+0100\nPO-Revision-Date: 2030-01-02 03:04+0100\n";
    let files = [
        f("major1.mo", mo(&[("", h)], 0x1_0000, false)),
        f("minor1.mo", mo(&[("", h)], 1, false)),
        f("rev256.mo", mo(&[("", h)], 0x100, false)),
        f("rev512.mo", mo(&[("", h)], 0x200, false)),
        f("major2.mo", mo(&[("", h)], 0x2_0000, false)),
    ];
    oracle_and_cli(&files);
}

#[test]
fn javadoc_details() {
    let c = "<!-- Generated by javadoc (17) on Thu Jan 02 03:04:05 UTC 2030 -->";
    let pages = [
        format!("<!DOCTYPE HTML>\n<html lang=\"en\">\n<head>\n{c}\n</head>\n"),
        format!("<html lang=\"en\" dir=\"ltr\">\n{c}\n"),
        format!("{c}\n<HTML LANG=\"en\">\n"),
        format!("{c}\n<html lang=\"\">\n"),
        format!("{c}\n  <html lang=\"de\">  x\n"),
        format!("{c}\n</HEAD>\n<html lang=\"en\">\n"),
    ];
    let files: Vec<File> = pages
        .iter()
        .enumerate()
        .map(|(i, p)| f(&format!("p{i}.html"), p.as_bytes()))
        .collect();
    oracle_and_cli(&files);
}

/// `--normalizers` and `-t` are checked before the operands, whatever they are; without
/// `-T`, only the .pyc files under a directory are taken, the real tool not run.
#[test]
fn options_before_operands() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("d");
    fs::create_dir(&dir).unwrap();
    let gz_file = gz(0, 1_800_000_000, 0, 3, b"");
    fs::write(dir.join("a.gz"), &gz_file).unwrap();
    fs::write(dir.join("b.txt"), b"text\n").unwrap();
    let pyc = tmp.path().join("x.pyc");
    fs::write(&pyc, b"not bytecode").unwrap();
    // no strip-nondeterminism in PATH
    let empty = tmp.path().join("bin");
    fs::create_dir(&empty).unwrap();
    let run = |args: &[&str], operands: &[&Path]| {
        Command::new(EXE)
            .env("PATH", &empty)
            .arg("strip-nondeterminism")
            .args(args)
            .args(operands)
            .output()
            .unwrap()
    };
    for (args, operands) in [
        (&["--normalizers=bogus", "-T", "5"][..], &[&dir][..]),
        (&["--pyc", "--normalizers=bogus"], &[&pyc]),
        (&["-t", "bogus", "-T", "5"], &[&dir]),
        (&["--pyc", "-t", "bogus"], &[&pyc]),
        (&["--normalizers=-gzip", "-t", "gzip", "-T", "5"], &[&pyc]),
    ] {
        let paths: Vec<&Path> = operands.iter().map(|p| p.as_path()).collect();
        let o = run(args, &paths);
        assert_eq!(o.status.code(), Some(255), "{args:?}: {o:?}");
        assert_eq!(fs::read(&pyc).unwrap(), b"not bytecode");
    }
    let o = run(&["--pyc"], &[&dir]);
    assert!(o.status.success(), "{o:?}");
    assert_eq!(fs::read(dir.join("a.gz")).unwrap(), gz_file);
    assert_eq!(fs::read(dir.join("b.txt")).unwrap(), b"text\n");
}

/// Behaviours of strip-nondeterminism that are bugs, not reproduced.
#[test]
fn strip_nondeterminism_bugs() {
    // file(1)'s output line starts with the path: strip-nondeterminism takes this text
    // file for a gzip one
    let text = f("gzip compressed data.gz", b"just text\n".to_vec());
    assert_eq!(
        ours_cli(&text, &["-T", "1700000000"]),
        (true, text.1.clone())
    );
    // a zip archive is replaced without a .zbk backup next to it
    let tmp = tempfile::tempdir().unwrap();
    let (archive, backup) = (tmp.path().join("a.zip"), tmp.path().join("a.zbk"));
    fs::write(&archive, zip(&[ent("a", b"a")])).unwrap();
    fs::write(&backup, b"keep me").unwrap();
    let o = Command::new(EXE)
        .args(["strip-nondeterminism", "-T", "1700000000"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(o.status.success());
    assert_eq!(fs::read(&backup).unwrap(), b"keep me");
}

/// An ar member header: name, mtime, uid and gid, mode, size (strings, padded).
fn ar_header(name: &str, mtime: &str, owner: &str, mode: &str, size: &str) -> Vec<u8> {
    format!("{name:<16}{mtime:<12}{owner:<6}{owner:<6}{mode:<8}{size:<10}`\n").into_bytes()
}

fn ar(members: &[(&str, &str, &[u8])]) -> Vec<u8> {
    let mut v = b"!<arch>\n".to_vec();
    for (name, mode, data) in members {
        v.extend(ar_header(
            name,
            "1700000000",
            "1000",
            mode,
            &data.len().to_string(),
        ));
        v.extend_from_slice(data);
        if data.len() % 2 == 1 {
            v.push(b'\n');
        }
    }
    v
}

#[test]
fn ar_archives() {
    let m = |mode: &str| ar(&[("a.o/", mode, b"x")]);
    let mut files = vec![
        f(
            "plain.a",
            ar(&[("a.o/", "100644", b"hello"), ("bb.o/", "100755", b"wo")]),
        ),
        f(
            "symtab.a",
            ar(&[
                ("/", "100755", b"\0\0\0\x01\0\0\0\x50a\0\0"),
                ("a.o/", "100644", b"x"),
            ]),
        ),
        f(
            "longnames.a",
            ar(&[
                ("//", "", b"averyveryverylongname.o/\n"),
                ("/0", "100644", b"x"),
            ]),
        ),
        f(
            "bsd.a",
            ar(&[
                ("#1/8", "100644", b"name.o\0\0data"),
                ("__.SYMDEF SORTED", "100644", b"abcd"),
            ]),
        ),
        f("empty.a", b"!<arch>\n".to_vec()),
        f("thin.a", b"!<thin>\n".to_vec()),
        f("text.a", b"hello world\n".to_vec()),
        f(
            "deb.a",
            ar(&[
                ("debian-binary", "100644", b"2.0\n"),
                ("control.tar.gz", "100644", b"x"),
            ]),
        ),
        f(
            "odd-end.a",
            [
                &b"!<arch>\n"[..],
                &ar_header("a.o/", "1", "1000", "644", "1"),
                b"x",
            ]
            .concat(),
        ),
        f(
            "same.a",
            [
                &b"!<arch>\n"[..],
                &ar_header("a.o/", "1234", "0", "644", "1"),
                b"x\n",
            ]
            .concat(),
        ),
        ("exec.a".to_owned(), m("100644"), 0o755),
        ("ro.a".to_owned(), m("100644"), 0o444),
        f("x.A", m("100644")),
        f("x.lib", m("100644")),
    ];
    for (i, mode) in [
        "644", "100600", "104755", "", "abc", "0", "77777777", "0x40", "0x3f", "0o100", "x40",
        "b1", "1_00", "_100", "\t100", "100\t", "-100", "1006449",
    ]
    .into_iter()
    .enumerate()
    {
        files.push(f(&format!("mode{i:02}.a"), m(mode)));
    }
    let sized = |size: &str, data: &[u8]| {
        [
            &b"!<arch>\n"[..],
            &ar_header("a.o/", "1", "1000", "644", size),
            data,
            &ar_header("b.o/", "1", "1000", "644", "2"),
            b"yy",
        ]
        .concat()
    };
    for (i, size) in ["  1", "01"].into_iter().enumerate() {
        files.push(f(&format!("sized{i}.a"), sized(size, b"x\n")));
    }
    for (i, mt) in ["0", "", "abc", "999999999999", "1234", "-5", "0x10"]
        .into_iter()
        .enumerate()
    {
        files.push(f(
            &format!("mtime{i}.a"),
            [
                &b"!<arch>\n"[..],
                &ar_header("a.o/", mt, "1000", "644", "1"),
                b"x\n",
            ]
            .concat(),
        ));
    }
    // the debhelper helper leaves ar archives alone
    oracle(&files);
    cli_same(&files, &["-T", "1234", "--normalizers=+ar"]);
    cli_same(&files[..3], &["-T", "1234"]);
    cli_same(&files[..3], &["-T", "999999999999", "--normalizers=+ar"]);
    cli_same(
        &[f("forced", m("644"))],
        &["-T", "1234", "--normalizers=+ar", "-t", "ar"],
    );
    // archives strip-nondeterminism fails on, the first header malformed
    let failing = [
        f("short.a", [&b"!<arch>\n"[..], &m("644")[8..38]].concat()),
        f(
            "magic.a",
            [
                &b"!<arch>\n"[..],
                &ar_header("a.o/", "1", "1000", "644", "1")[..58],
                b"xx",
                b"x\n",
            ]
            .concat(),
        ),
        f(
            "size-neg.a",
            [
                &b"!<arch>\n"[..],
                &ar_header("a.o/", "1", "1000", "644", "-1"),
                b"x\n",
            ]
            .concat(),
        ),
        f(
            "size-hex.a",
            [
                &b"!<arch>\n"[..],
                &ar_header("a.o/", "1", "1000", "644", "0x1"),
                b"x\n",
            ]
            .concat(),
        ),
        f("junk.a", b"!<arch>\njunk".to_vec()),
    ];
    cli_same(&failing, &["-T", "1234", "--normalizers=+ar"]);
    // size fields it reads as Perl numbers, and a member cut short, which ends the
    // archive for it: not a decimal size, so the file fails and stays as it was
    for data in [
        sized("1x", b"x\n"),
        sized("+1", b"x\n"),
        sized("1e0", b"x\n"),
        sized("5.9", b"abcdef"),
        sized("9e18", b"abcdef"),
        [
            &b"!<arch>\n"[..],
            &ar_header("a.o/", "1", "1000", "644", "100"),
            b"abc",
        ]
        .concat(),
    ] {
        let file = f("sized.a", data.clone());
        assert_eq!(
            ours_cli(&file, &["-T", "1234", "--normalizers=+ar"]),
            (false, data)
        );
    }
    // an empty member, which it fails on
    assert_eq!(
        ours_cli(
            &f(
                "size0.a",
                [
                    &b"!<arch>\n"[..],
                    &ar_header("a.o/", "1", "1000", "644", "0"),
                ]
                .concat(),
            ),
            &["-T", "1234", "--normalizers=+ar"]
        ),
        (
            true,
            [
                &b"!<arch>\n"[..],
                &ar_header("a.o/", "1234", "0", "644", "0"),
            ]
            .concat()
        )
    );
    // ones it fails on after rewriting the first headers, which it keeps (a bug, not
    // reproduced): the file stays as it was
    for data in [
        [&m("644")[..], b"trailing"].concat(),
        [&m("644")[..], b"\n"].concat(),
        [
            &b"!<arch>\n"[..],
            &ar_header("a.o/", "1", "1000", "644", "1"),
            b"x",
            &ar_header("b.o/", "1", "1000", "644", "2"),
            b"yy",
        ]
        .concat(),
    ] {
        let file = f("halfway.a", data.clone());
        assert_eq!(
            ours_cli(&file, &["-T", "1234", "--normalizers=+ar"]),
            (false, data)
        );
    }
}

#[test]
fn normalizers() {
    let files = [
        f("x.gz", gz(0, 1_800_000_000, 0, 3, b"")),
        f("x.a", ar(&[("a.o/", "100644", b"x")])),
        f("x.png", png(&[(b"tIME", b"\x07\xee\x01\x02\x03\x04\x05")])),
        f("x.zip", zip(&[ent("a", b"a")])),
        f(
            "app",
            [&b"#!/usr/bin/python3\n"[..], &zip(&[ent("a", b"a")])].concat(),
        ),
        f(
            "app.zip",
            [&b"#!/usr/bin/python3\n"[..], &zip(&[ent("a", b"a")])].concat(),
        ),
    ];
    for spec in [
        "+all",
        "-gzip,+all",
        "+all,-gzip",
        "+ar",
        "+ar,-ar",
        "-ar,+ar",
        "+all,-ar",
        "-zip",
        "+gzip,",
        ",,",
        "+javaproperties",
        "-javaproperties",
        // errors
        "gzip",
        "+foo",
        "-foo",
        "+",
        "-",
        "+gzip,,-zip",
        ",+gzip",
        " +gzip",
        "+gzip ",
        "+GZIP",
        "+gzip,foo",
        "+pyc",
        "+g-zip",
        "+_",
    ] {
        cli_same(&files, &["-T", "1234", &format!("--normalizers={spec}")]);
    }
    // with pyzip disabled, strip-nondeterminism dies on a file no other handler takes
    // (a bug, not reproduced): those are left alone
    for spec in [
        "-all",
        "-all,+gzip",
        "+gzip,-all",
        "+all,-all,+ar",
        "-pyzip",
        "-png,-pyzip",
    ] {
        let spec = format!("--normalizers={spec}");
        let args = ["-T", "1234", spec.as_str()];
        cli_same(&files[..4], &args);
        for file in &files[4..] {
            assert_eq!(
                ours_cli(file, &args),
                (true, file.1.clone()),
                "{spec} {}",
                file.0
            );
        }
    }
    // the last one counts
    cli_same(
        &files,
        &["-T", "1234", "--normalizers=-gzip", "--normalizers=+ar"],
    );
    // with -t
    for (spec, kind) in [
        ("-gzip", "gzip"),
        ("-all,+ar", "ar"),
        ("-all", "gzip"),
        ("+all", "ar"),
    ] {
        cli_same(
            &files[..2],
            &["-T", "1234", &format!("--normalizers={spec}"), "-t", kind],
        );
    }
    for kind in ["ar", "foo", "all", "javaproperties", "GZIP"] {
        cli_same(&files[..1], &["-T", "1234", "-t", kind]);
    }
}

/// Directory operands: every regular file found, under each of its names, symbolic
/// links not followed, `--exclude` matching names; the same output as strip-nondeterminism's on
/// the list of those files.
#[test]
fn directory_operands() {
    if !cli_available() {
        return;
    }
    let tree = [
        f("a.gz", gz(8, 1_800_000_000, 0, 3, b"n\0")),
        f("sub/b.zip", zip(&[ent("b", b"b"), ent("a", b"a")])),
        f(
            "sub/deep/c.png",
            png(&[(b"tIME", b"\x07\xee\x01\x02\x03\x04\x05")]),
        ),
        f("sub/deep/d.a", ar(&[("a.o/", "100644", b"x")])),
        f("sub/e.jar", zip(&jar_members())),
        f("text.txt", b"just text\n".to_vec()),
        f("skip/x.gz", gz(0, 1_800_000_000, 0, 3, b"")),
        f("keep.gz.orig", gz(0, 1_800_000_000, 0, 3, b"")),
        f("excluded.gz", gz(0, 1_800_000_000, 0, 3, b"")),
        f("[x].gz", gz(0, 1_800_000_000, 0, 3, b"")),
        f(".hidden.gz", gz(0, 1_800_000_000, 0, 3, b"")),
    ];
    let excludes = ["excluded.*", "x.gz", "\\[x].gz"];
    let tmp = tempfile::tempdir().unwrap();
    let mut results = Vec::new();
    for ours in [false, true] {
        let root = tmp.path().join(if ours { "ours" } else { "real" });
        for (path, data, mode) in &tree {
            let p = root.join(path);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, data).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(*mode)).unwrap();
            set_mtime(&p, OLD);
        }
        // a second name of a.gz, and links the walk does not follow
        fs::hard_link(root.join("a.gz"), root.join("sub/a-link.gz")).unwrap();
        symlink("../a.gz", root.join("sub/sym.gz")).unwrap();
        symlink(tmp.path().join("elsewhere"), root.join("sub/dir-link")).unwrap();
        let o = if ours {
            let mut c = Command::new(EXE);
            c.args([
                "strip-nondeterminism",
                "--normalizers=+ar",
                "-T",
                "1700000000",
            ]);
            for x in excludes {
                c.arg(format!("--exclude={x}"));
            }
            c.arg(&root).output().unwrap()
        } else {
            let names = [
                "a.gz",
                "sub/b.zip",
                "sub/deep/c.png",
                "sub/deep/d.a",
                "sub/e.jar",
                "text.txt",
                "keep.gz.orig",
                ".hidden.gz",
            ];
            Command::new("strip-nondeterminism")
                .args(["--normalizers=+ar", "-T", "1700000000"])
                .args(names.iter().map(|n| root.join(n)))
                .output()
                .unwrap()
        };
        assert!(o.status.success(), "{o:?}");
        results.push(snapshot(&root));
    }
    assert_eq!(results[0], results[1]);
}

/// Operands as strip-nondeterminism takes them: symbolic links only with -t, a missing
/// one stopping the run there.
#[test]
fn file_operands() {
    if !cli_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    for (case, args) in [("plain", &[][..]), ("forced", &["-t", "gzip"][..])] {
        let mut results = Vec::new();
        for ours in [false, true] {
            let root = tmp.path().join(format!("{case}-{ours}"));
            fs::create_dir_all(&root).unwrap();
            for n in ["a.gz", "b.gz", "c.gz"] {
                fs::write(root.join(n), gz(0, 1_800_000_000, 0, 3, b"")).unwrap();
                set_mtime(&root.join(n), OLD);
            }
            fs::write(root.join("t.gz"), gz(0, 1_800_000_000, 0, 3, b"")).unwrap();
            set_mtime(&root.join("t.gz"), OLD);
            symlink("t.gz", root.join("l.gz")).unwrap();
            symlink("nowhere", root.join("dangling.gz")).unwrap();
            let run = |names: &[&str]| {
                let mut c = if ours {
                    let mut c = Command::new(EXE);
                    c.args(["strip-nondeterminism"]);
                    c
                } else {
                    Command::new("strip-nondeterminism")
                };
                c.args(["-T", "1700000000"]).args(args);
                c.args(names.iter().map(|n| root.join(n))).output().unwrap()
            };
            let a = run(&["a.gz", "l.gz"]).status.code();
            let b = run(&["b.gz", "missing.gz", "c.gz"]).status.code();
            let d = run(&["dangling.gz"]).status.code();
            results.push((a, b, d, snapshot(&root)));
        }
        assert_eq!(results[0], results[1], "{case}");
    }
}

/// Zip archives and jars are replaced: a new inode, owned by the process; the other
/// files are rewritten in place, keeping their inode and owner.
#[test]
fn rewritten_files_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    put(root, "a.zip", &zip(&[ent("b", b"b"), ent("a", b"a")]));
    put(root, "b.jar", &zip(&jar_members()));
    put(root, "c.gz", &gz(0, 1_800_000_000, 0, 3, b""));
    put(
        root,
        "d.png",
        &png(&[(b"tIME", b"\x07\xee\x01\x02\x03\x04\x05")]),
    );
    let before = inodes(root);
    let o = Command::new(EXE)
        .args(["strip-nondeterminism", "-T", "1700000000"])
        .args(before.by_path.keys().map(|n| root.join(n)))
        .output()
        .unwrap();
    assert!(o.status.success(), "{o:?}");
    let owned = fs::metadata(root.join("c.gz")).unwrap().uid() == OWNER;
    let me = fs::metadata(root).unwrap().uid();
    for (name, replaced, uid, _) in identities(root, &before) {
        let zip = name == "a.zip" || name == "b.jar";
        assert_eq!(replaced, zip, "{name}");
        if owned {
            assert_eq!(uid, if zip { me } else { OWNER }, "{name}");
        }
    }
}

/// `-t` forces a handler on the files named: a directory operand is an error, before
/// any file is processed.
#[test]
fn forced_handler_on_directories() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    put(root, "a.gz", &gz(0, 1_800_000_000, 0, 3, b""));
    put(root, "d/b.gz", &gz(0, 1_800_000_000, 0, 3, b""));
    let before = snapshot(root);
    let o = Command::new(EXE)
        .args(["strip-nondeterminism", "-t", "gzip", "-T", "1700000000"])
        .args([root.join("a.gz"), root.join("d")])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert!(String::from_utf8_lossy(&o.stderr).contains("not directories"));
    assert_eq!(snapshot(root), before);
}

/// Run strip-nondeterminism, the real one and this binary's, with `args` then the
/// paths `operands(root)` gives, on two copies of the tree `setup` makes; require the
/// same exit status and tree.
fn cli_tree(setup: &dyn Fn(&Path), args: &[&str], operands: &dyn Fn(&Path) -> Vec<PathBuf>) {
    if !cli_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let mut results = Vec::new();
    for ours in [false, true] {
        let root = tmp.path().join(if ours { "ours" } else { "real" });
        fs::create_dir_all(&root).unwrap();
        setup(&root);
        let before = inodes(&root);
        let mut c = if ours {
            let mut c = Command::new(EXE);
            c.args(["strip-nondeterminism"]);
            c
        } else {
            Command::new("strip-nondeterminism")
        };
        let o = c.args(args).args(operands(&root)).output().unwrap();
        let (mut snap, mut ids) = (snapshot(&root), identities(&root, &before));
        if !ours {
            untouched(&before, &mut snap, &mut ids);
        }
        results.push((o.status.code(), snap, o.stderr, ids));
    }
    let (real, ours) = (&results[0], &results[1]);
    assert_eq!(real.3, ours.3, "(path, replaced, owner, group)");
    assert_eq!(
        real.0,
        ours.0,
        "real: {}\nours: {}",
        String::from_utf8_lossy(&real.2),
        String::from_utf8_lossy(&ours.2)
    );
    same_trees(&real.1, &ours.1);
}

/// Require two snapshots to be the same, naming the files that differ.
fn same_trees(a: &[(String, Vec<u8>, u32, bool)], b: &[(String, Vec<u8>, u32, bool)]) {
    let names =
        |s: &[(String, Vec<u8>, u32, bool)]| s.iter().map(|f| f.0.clone()).collect::<Vec<_>>();
    assert_eq!(names(a), names(b));
    let differ: Vec<String> = a
        .iter()
        .zip(b)
        .filter(|(x, y)| x != y)
        .map(|(x, y)| {
            format!(
                "{} ({} {:o} {} / {} {:o} {})",
                x.0,
                x.1.len(),
                x.2,
                x.3,
                y.1.len(),
                y.2,
                y.3
            )
        })
        .collect();
    assert!(differ.is_empty(), "{} differ: {differ:?}", differ.len());
}

fn put(root: &Path, path: &str, data: &[u8]) {
    let p = root.join(path);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, data).unwrap();
    set_mtime(&p, OLD);
    own(&p);
}

/// One file reached twice: each time after the other is written, as the real tool
/// processes them one after the other.
#[test]
fn same_file_twice() {
    const N: u8 = 96;
    // big enough for a write to be under way when the other name is read
    let noise = filler(2 << 20, 1, 7);
    let big = |seed: u8| {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
        e.write_all(&[seed]).unwrap();
        e.write_all(&noise).unwrap();
        let mut v = e.finish().unwrap();
        v[4..8].copy_from_slice(&1_800_000_000_u32.to_le_bytes());
        v
    };
    let tree = |root: &Path, links: bool| {
        for i in 0..N {
            put(root, &format!("d/sub/f{i:02}.gz"), &big(i));
        }
        put(root, "d/a.zip", &zip(&[ent("b", b"b"), ent("a", b"a")]));
        put(
            root,
            "d/sub/p.png",
            &png(&[(b"tIME", b"\x07\xee\x01\x02\x03\x04\x05")]),
        );
        put(root, "j/a.jar", &zip(&jar_members()));
        fs::create_dir_all(root.join("e")).unwrap();
        if links {
            fs::hard_link(root.join("d/a.zip"), root.join("e/a-link.zip")).unwrap();
            fs::hard_link(root.join("j/a.jar"), root.join("e/b.jar")).unwrap();
        }
    };
    let args = ["-T", "1700000000"];
    // the files of a tree, as a list
    let files = |root: &Path, links: bool| {
        let mut v: Vec<PathBuf> = (0..N)
            .map(|i| root.join(format!("d/sub/f{i:02}.gz")))
            .collect();
        v.extend(["d/a.zip", "d/sub/p.png", "j/a.jar"].map(|n| root.join(n)));
        if links {
            v.extend(["e/a-link.zip", "e/b.jar"].map(|n| root.join(n)));
        }
        v
    };
    // every file twice in a row, the second time through another directory path
    cli_tree(&|root| tree(root, true), &args, &|root| {
        files(root, true)
            .into_iter()
            .flat_map(|p| {
                let dir = p.parent().unwrap();
                let again = dir
                    .join("..")
                    .join(dir.file_name().unwrap())
                    .join(p.file_name().unwrap());
                [p, again]
            })
            .collect()
    });
    if !cli_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let run = |root: &Path, operands: Vec<PathBuf>| {
        let o = Command::new(EXE)
            .args(["strip-nondeterminism"])
            .args(args)
            .args(operands)
            .output()
            .unwrap();
        assert!(o.status.success(), "{o:?}");
        snapshot(root)
    };
    // ours on directories (the real tool skips them), overlapping, given twice: the same
    // as on the list of their files
    let mut results = Vec::new();
    for dirs in [false, true] {
        let root = tmp.path().join(format!("{dirs}"));
        fs::create_dir_all(&root).unwrap();
        tree(&root, false);
        let operands = if dirs {
            ["d", "d/sub", "d", "d/sub/.", "e", "j"]
                .map(|n| root.join(n))
                .to_vec()
        } else {
            files(&root, false)
        };
        results.push(run(&root, operands));
        fs::remove_dir_all(&root).unwrap();
    }
    same_trees(&results[0], &results[1]);
    // both names of hard-linked archives are normalized, now different files, whether
    // given or found under directories
    for (case, dirs) in [("files", false), ("dirs", true), ("root", true)] {
        let root = tmp.path().join(format!("links-{case}"));
        fs::create_dir_all(&root).unwrap();
        tree(&root, true);
        // the pairs are under different directories, and under the root together
        let operands = if case == "root" {
            vec![root.clone()]
        } else if dirs {
            ["d", "e", "j"].map(|n| root.join(n)).to_vec()
        } else {
            files(&root, true)
        };
        run(&root, operands);
        for (a, b) in [("d/a.zip", "e/a-link.zip"), ("j/a.jar", "e/b.jar")] {
            let (ma, mb) = (
                fs::metadata(root.join(a)).unwrap(),
                fs::metadata(root.join(b)).unwrap(),
            );
            assert_ne!(ma.ino(), mb.ino(), "{a} {b}, {case}");
            assert_eq!((ma.nlink(), mb.nlink()), (1, 1));
            assert_eq!(
                fs::read(root.join(a)).unwrap(),
                fs::read(root.join(b)).unwrap(),
                "{a} {b}, {case}"
            );
        }
    }
}

// ---- debhelper's interface ----

#[test]
fn options_and_packages() {
    if !dh_available() {
        return;
    }
    let files = [
        f("usr/share/a.gz", gz(0, 1_800_000_000, 0, 3, b"")),
        f("usr/share/b.gz", gz(0, 1_800_000_000, 0, 3, b"")),
        f(
            "usr/lib/c.png",
            png(&[(b"tIME", b"\x07\xee\x01\x02\x03\x04\x05")]),
        ),
    ];
    for args in [
        &[][..],
        &["-Xa.gz"],
        &["-X", "share/b"],
        &["--exclude=usr/lib", "-Xnothing"],
        &["-X./debian"],
        &["-pp1"],
        &["-Np1"],
        &["-p", "p2", "-Xc.png"],
        &["-O--foo"],
        &["--foo"],
        &["--no-act"],
    ] {
        // debhelper refuses an unknown option
        assert_eq!(
            same(&["p1", "p2"], &files, args),
            args != ["--foo"],
            "{args:?}"
        );
    }
}

// ---- the command line ----

fn cli_available() -> bool {
    if have("strip-nondeterminism") {
        return true;
    }
    skip("strip-nondeterminism");
    false
}

/// Run strip-nondeterminism `args` on each of `files` alone, the real one and this
/// binary's (native handlers only), and require the same outcome, bytes, permissions and
/// rewritten-or-not.
fn cli_same(files: &[File], args: &[&str]) {
    if !cli_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    for (i, file) in files.iter().enumerate() {
        let mut results = Vec::new();
        for ours in [false, true] {
            let dir = tmp.path().join(format!("{i}-{ours}"));
            let path = dir.join(&file.0);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, &file.1).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(file.2)).unwrap();
            set_mtime(&path, OLD);
            own(&path);
            let before = inodes(&dir);
            let mut cmd = if ours {
                let mut c = Command::new(EXE);
                c.args(["strip-nondeterminism"]);
                c
            } else {
                Command::new("strip-nondeterminism")
            };
            let o = cmd.args(args).arg(&path).output().unwrap();
            let (mut snap, mut ids) = (snapshot(&dir), identities(&dir, &before));
            if !ours {
                untouched(&before, &mut snap, &mut ids);
            }
            results.push((o.status.code(), snap, o, ids));
        }
        let (real, ours) = (&results[0], &results[1]);
        assert_eq!(
            (real.0, &real.1, &real.3),
            (ours.0, &ours.1, &ours.3),
            "{args:?} {}\nreal: {:?}\nours: {:?}",
            file.0,
            real.2,
            ours.2
        );
    }
}

#[test]
fn command_line() {
    if !cli_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let files = [
        f("a.gz", gz(8, 1_800_000_000, 0, 3, b"n\0")),
        f("b.zip", zip(&jar_members())),
        f("c.jar", zip(&jar_members())),
        f("d.png", png(&[(b"tIME", b"\x07\xee\x01\x02\x03\x04\x05")])),
        f(
            "e.mo",
            mo(
                &[("", "POT-Creation-Date: 2030-01-02 03:04+0100\n")],
                0,
                false,
            ),
        ),
    ];
    let mut results = Vec::new();
    for ours in [false, true] {
        let dir = tmp.path().join(if ours { "ours" } else { "real" });
        fs::create_dir(&dir).unwrap();
        let paths: Vec<PathBuf> = files
            .iter()
            .map(|(n, c, _)| {
                let p = dir.join(n);
                fs::write(&p, c).unwrap();
                p
            })
            .collect();
        let mut cmd = if ours {
            let mut c = Command::new(EXE);
            c.args(["strip-nondeterminism"]);
            c
        } else {
            Command::new("strip-nondeterminism")
        };
        let o = cmd
            .arg("-T")
            .arg("1728902097")
            .args(&paths)
            .output()
            .unwrap();
        assert!(o.status.success(), "{o:?}");
        results.push(snapshot(&dir));
    }
    assert_eq!(results[0], results[1]);
}

/// The exit status strip-nondeterminism dies with on a malformed file: 255, or the error
/// number a failed system call left.
#[test]
fn exit_statuses() {
    let good = zip(&[ent("a", b"hello"), ent("b", b"world!")]);
    let end = find(&good, b"PK\x05\x06", 0);
    let mut inflate = zip(&[Ent {
        deflated: true,
        ..ent("a.html", "<html>".repeat(50).as_bytes())
    }]);
    let at = find(&inflate, b"a.html", 0) + 6;
    inflate[at..at + 4].copy_from_slice(b"\xff\xff\xff\xff");
    // the end record is looked for in the last 32 KiB: a longer comment hides it
    let commented = |len: usize| {
        let mut d = good.clone();
        let n = d.len();
        d[n - 2..].copy_from_slice(&u16::try_from(len).unwrap().to_le_bytes());
        d.resize(n + len, b'c');
        d
    };
    let mut no_newline = b"#!/usr/bin/python3 ".to_vec();
    no_newline.extend(good.iter().filter(|&&b| b != b'\n'));
    let files = [
        f("comment-32746.zip", commented(32_746)),
        f("comment-32747.zip", commented(32_747)),
        f("comment-40960.zip", commented(40_960)),
        f("noname.gz", &b"\x1f\x8b\x08\x08\0\0\0\0\0\x03abc"[..]),
        f("tiny.zip", [&b"PK\x05\x06"[..], &[0; 10]].concat()),
        f("tiny.jmod", &b"JM\x01\x00PK\x05\x06"[..]),
        f("cd-before.zip", patch(good.clone(), end + 12, 100_000, 4)),
        f("garbage.zip", [&b"PK\x03\x04"[..], &[7; 40]].concat()),
        f("inflate.jar", inflate),
        f("not.png", &b"\x89PNG\r\n\x1a\n"[..]),
    ];
    cli_same(&files, &["-T", "1700000000"]);
    cli_same(&files[4..5], &["-t", "jar", "-T", "1700000000"]);
    cli_same(&files[3..4], &["-t", "png", "-T", "1700000000"]);
    // a Python zip application without a newline is all first line
    cli_same(
        &[f("no-newline", no_newline)],
        &["-t", "pyzip", "-T", "1700000000"],
    );
}

/// Timestamps outside the range of the fields they go to, through the command line.
#[test]
fn timestamps_out_of_range() {
    let extras = zip_extras();
    let mut members = extras.clone();
    members.extend([ent("a.clj", b"x"), ent("b.class", b"y")]);
    let files = [
        f("a.zip", zip(&members)),
        f("a.jar", zip(&members)),
        f("a.gz", gz(0, 1_800_000_000, 0, 3, b"")),
        f("a.uimage", uimage(1234, 0x2705_1956, 0, b"x")),
        f("max.uimage", uimage(u32::MAX, 0x2705_1956, 0, b"x")),
        f("a.bflt", bflt(BFLT, 1234, 0)),
        f("max.bflt", bflt(BFLT, u32::MAX, 0)),
    ];
    for t in [
        "0",
        "1234",
        "315532800",
        "315576059",
        "315576060",
        "315576061",
        "315576062",
        "4294967295",
        "4294967296",
        "4294968530",
        "8589934591",
        "4354819199",
        "4354819200",
        "9999999999",
    ] {
        cli_same(&files, &["-T", t]);
    }
}

/// Negative timestamps, which strip-nondeterminism takes.
#[test]
fn negative_timestamps() {
    let mut members = zip_extras();
    members.extend([ent("a.clj", b"x"), ent("b.class", b"y")]);
    members.extend(jar_members());
    let c = "<!-- Generated by javadoc (1.8.0) on Thu Jan 02 03:04:05 UTC 2030 -->";
    let newc_one = [
        &newc(b"070701", b"b", b"hi\n", [5, 0o100_644, 1, 1_800_000_000])[..],
        &newc(b"070701", b"TRAILER!!!", b"", [0, 0, 1, 0]),
    ]
    .concat();
    // the files without dates first
    let files = [
        f("a.zip", zip(&members)),
        f("a.gz", gz(0, 1_800_000_000, 0, 3, b"")),
        f("a.uimage", uimage(1234, 0x2705_1956, 0, b"x")),
        f("a.bflt", bflt(BFLT, 1234, 0)),
        f("a.a", ar(&[("a.o/", "644", b"x")])),
        f("a.jar", zip(&members)),
        f(
            "a.png",
            png(&[
                (b"tIME", b"\x07\xee\x01\x02\x03\x04\x05"),
                (b"tEXt", b"date:create\x002030-01-01T00:00:00+00:00"),
            ]),
        ),
        f(
            "a.mo",
            mo(
                &[(
                    "",
                    "POT-Creation-Date: 2030-01-02 03:04+0100\nPO-Revision-Date: 2030-01-02 03:04+0100\n",
                )],
                0,
                false,
            ),
        ),
        f(
            "a.html",
            format!("{c}\n<meta name=\"date\" content=\"2030-01-02\">\n<html>\n"),
        ),
    ];
    let cpio = [
        f("a.cpio", newc_one),
        f(
            "b.cpio",
            [&odc(b"b", b"x", 5)[..], &odc(b"TRAILER!!!", b"", 0)].concat(),
        ),
        f(
            "c.cpio",
            [&bincpio(b"b", b"x", 5)[..], &bincpio(b"TRAILER!!!", b"", 0)].concat(),
        ),
    ];
    for t in [
        "-1",
        "-60",
        "-86400",
        "-315532800",
        "-2147483648",
        "-4294967295",
        "-4294967296",
        "-9999999999",
        "-11644473601",
        "-20000000000",
        "-30610224000",
        "-30610224001",
        "-62135596800",
        "-922337203685",
        "-1844674407370",
        "1844674407370",
        "99999999999999",
        "+5",
        "-0",
    ] {
        // before year 1, the dates strip-nondeterminism writes are wrong;
        // past 12 characters, an ar mtime runs into the next fields
        let before_year_1 = t.parse::<i64>().unwrap() < -62_135_596_800;
        let files: Vec<File> = files
            .iter()
            .enumerate()
            .filter(|(i, f)| (!before_year_1 || *i < 5) && (f.0 != "a.a" || t.len() <= 12))
            .map(|(_, f)| f.clone())
            .collect();
        cli_same(&files, &["--normalizers=+ar", "-T", t]);
        // the mtime fields of cpio archives are unsigned: a negative timestamp fails the
        // archive, where strip-nondeterminism writes past the field or wraps it around
        for file in cpio.iter().filter(|_| t.starts_with('-') && t != "-0") {
            assert_eq!(ours_cli(file, &["-T", t]), (false, file.1.clone()), "{t}");
        }
    }
    // what strip-nondeterminism takes as an integer, and its status for the rest
    let gz = [f("a.gz", gz(0, 1_800_000_000, 0, 3, b""))];
    for t in [
        "abc",
        "1.5",
        "",
        "0x10",
        " 7",
        "7 ",
        "1e3",
        "-v",
        "9223372036854775807",
    ] {
        cli_same(&gz, &["-T", t]);
    }
    // beyond 64 bits, which strip-nondeterminism takes in floating point, refused
    for t in ["9223372036854775808", "-99999999999999999999"] {
        let o = Command::new(EXE)
            .args(["strip-nondeterminism", "-T", t, "a.gz"])
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(255), "{o:?}");
    }
}

// ---- jar members recompressed ----

/// `n` bytes: lines of words (compressible), random bytes (not), or both.
fn filler(n: usize, kind: u8, seed: u32) -> Vec<u8> {
    let mut x = seed | 1;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    let words = ["alpha ", "beta ", "gamma\r\n", "<p>delta</p>\n", "e", "ff "];
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        let r = next();
        match kind {
            0 => out.extend_from_slice(words[(r % 6) as usize].as_bytes()),
            1 => out.push((r >> 24) as u8),
            _ if (out.len() / 10_000) % 2 == 0 => {
                out.extend_from_slice(words[(r % 6) as usize].as_bytes());
            }
            _ => out.push((r >> 24) as u8),
        }
    }
    out.truncate(n);
    out
}

/// Deflated jar members strip-nondeterminism rewrites, of `n` bytes or so: the manifest,
/// a javadoc page and a nested jar, each compressed again.
fn deflated_rewritten(n: usize, kind: u8, flags: u16) -> Vec<Ent> {
    let javadoc = [
        &b"<!-- Generated by javadoc (17) on Thu Jan 02 03:04:05 UTC 2030 -->\n\
           <meta name=\"dc.created\" content=\"2030-01-02\">\n"[..],
        &filler(n, kind, 7),
    ]
    .concat();
    let manifest = [
        &b"Manifest-Version: 1.0\r\nBnd-LastModified: 1700000000000\r\n"[..],
        &filler(n, kind, 11),
    ]
    .concat();
    let d = |e: Ent| Ent {
        deflated: true,
        flags,
        ..e
    };
    let nested = zip(&[
        d(ent("META-INF/MANIFEST.MF", &manifest)),
        d(ent("doc/index.html", &javadoc)),
        d(ent("data.bin", &filler(n / 2, kind, 13))),
    ]);
    vec![
        d(ent("META-INF/MANIFEST.MF", &manifest)),
        d(ent("doc/index.html", &javadoc)),
        d(ent("lib/nested.jar", &nested)),
        d(ent("lib/nested.war", &nested)),
        d(ent("data.bin", &filler(n, kind, 17))),
    ]
}

#[test]
fn jar_deflated_members() {
    let mut files = Vec::new();
    for n in [10, 1_000, 33_000, 70_000, 200_000] {
        for kind in 0..3 {
            for flags in [0, 2, 8] {
                files.push(f(
                    &format!("r-{n}-{kind}-{flags}.jar"),
                    zip(&deflated_rewritten(n, kind, flags)),
                ));
            }
        }
    }
    // deflated members that come out as they went in
    let same = |e: Ent| Ent {
        deflated: true,
        ..e
    };
    files.extend([
        f(
            "manifest-unchanged.jar",
            zip(&[same(ent(
                "META-INF/MANIFEST.MF",
                &[&b"Manifest-Version: 1.0\r\n"[..], &filler(50_000, 0, 3)].concat(),
            ))]),
        ),
        f(
            "plain-html.jar",
            zip(&[same(ent("doc/plain.html", &filler(50_000, 0, 5)))]),
        ),
        f(
            "nested-normalized.jar",
            zip(&[same(ent(
                "lib/in.jar",
                &zip(&[same(ent("a.txt", &filler(20_000, 0, 9)))]),
            ))]),
        ),
        f(
            "sub-manifest.jar",
            zip(&[same(ent(
                "META-INF/sub/MANIFEST.MF",
                &[&b"Bnd-LastModified: 1\r\n"[..], &filler(5_000, 0, 4)].concat(),
            ))]),
        ),
        // javadoc whose date is already the changelog's: the same content, compressed again
        f(
            "javadoc-same.jar",
            zip(&[same(ent(
                "doc/same.html",
                &[
                    &b"<html>\n<!-- Generated by javadoc -->\n<meta name=\"date\" content=\"2024-10-14\">\n"[..],
                    &filler(30_000, 0, 6),
                ]
                .concat(),
            ))]),
        ),
        f(
            "empty-manifest.jar",
            zip(&[same(ent("META-INF/MANIFEST.MF", b"Bnd-LastModified: 1\r\n"))]),
        ),
    ]);
    oracle(&files);
}

/// The comparison of rewritten jars tells headers and contents apart (the jar tests
/// exercise it on other compressed bytes).
#[test]
fn zip_equivalence() {
    let plain = |data: &[u8]| zip(&[ent("a.txt", data)]);
    let deflated = |data: &[u8], flags: u16| {
        zip(&[Ent {
            deflated: true,
            flags,
            ..ent("a.txt", data)
        }])
    };
    let text = b"words words words words words\n".repeat(50);
    assert!(zip_equivalent(&plain(&text), &plain(&text)).is_ok());
    assert!(zip_equivalent(&plain(&text), &plain(b"other")).is_err());
    assert!(zip_equivalent(&deflated(&text, 0), &deflated(&text, 2)).is_err());
    assert!(zip_equivalent(&deflated(&text, 0), &plain(&text)).is_err());
}
