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
        .env_remove("DH_OPTIONS")
        .env_remove(debbuild_rs_strip_native_only());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

fn debbuild_rs_strip_native_only() -> &'static str {
    "DEBBUILD_RS_STRIP_NATIVE_ONLY"
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

/// Normalize `files` in packages `pkgs` with debhelper's helper and with this binary's
/// (native handlers only, unless `fallback`), and require the same result.
fn same(pkgs: &[&str], files: &[File], args: &[&str], fallback: bool) {
    let tmp = tempfile::tempdir().unwrap();
    let (real, ours) = (tmp.path().join("real/src"), tmp.path().join("ours/src"));
    package(&real, pkgs, files);
    package(&ours, pkgs, files);
    let r = run_dh(&real, false, args, &[]);
    let native = if fallback { "" } else { "1" };
    let o = run_dh(
        &ours,
        true,
        args,
        &[(debbuild_rs_strip_native_only(), native)],
    );
    assert_eq!(
        r.status.success(),
        o.status.success(),
        "real: {r:?}\nours: {o:?}"
    );
    let (rs, os) = (
        snapshot(&real.join("debian")),
        snapshot(&ours.join("debian")),
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
    // the native run leaves no scratch directory behind
    assert!(fs::read_dir(ours.join("debian")).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".debbuild")
    }));
}

fn oracle(files: &[File]) {
    if dh_available() {
        same(&["pp"], files, &[], false);
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
    same(&["pp"], &[f("bad.gz", name)], &[], false);
}

#[test]
fn gzip_hardlinks() {
    if !dh_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let mut outs = Vec::new();
    for ours in [false, true] {
        let dir = tmp.path().join(if ours { "ours/src" } else { "real/src" });
        package(&dir, &["pp"], &[f("a.gz", gz(0, 1_800_000_000, 0, 3, b""))]);
        let a = dir.join("debian/pp/a.gz");
        fs::hard_link(&a, dir.join("debian/pp/b.gz")).unwrap();
        assert!(run_dh(&dir, ours, &[], &[]).status.success());
        let (ma, mb) = (
            fs::metadata(&a).unwrap(),
            fs::metadata(dir.join("debian/pp/b.gz")).unwrap(),
        );
        outs.push((ma.ino() == mb.ino(), fs::read(&a).unwrap()));
    }
    assert_eq!(outs[0], outs[1]);
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
    let ux_short = ext(0x7875, b"\x01\x04\xe8\x03\0\0");
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
        with("e7", ux_short.clone(), ux_short),
        with(
            "e8",
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
    same(&["pp"], &[f("bad.zip", bad)], &[], false);
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
        same(&["p1", "p2"], &files, args, false);
    }
}

#[test]
fn foreign_formats_through_the_real_helper() {
    if !dh_available() {
        return;
    }
    let py = zip(&[Ent {
        dos: (0x8dd4, 0x6471),
        ..ent("__main__.py", b"print(1)\n")
    }]);
    let files = [
        (
            "app".to_owned(),
            [&b"#!/usr/bin/python3\n"[..], &py].concat(),
            0o755,
        ),
        f("m.jmod", [&b"JM\x01\x00"[..], &py].concat()),
        f("plain.gz", gz(0, 1_800_000_000, 0, 3, b"")),
    ];
    same(&["pp"], &files, &[], true);
}

// ---- the command line ----

#[test]
fn command_line() {
    if !have("strip-nondeterminism") {
        // not part of debhelper's dependencies: the handlers are checked above
        eprintln!("skipped: no strip-nondeterminism");
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
            c.args(["strip-nondeterminism", "--native-only"]);
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
