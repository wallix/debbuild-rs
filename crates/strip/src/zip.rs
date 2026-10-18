//! Zip archives (APPNOTE.TXT) and the Java archives built on them.
//!
//! The archive is rewritten whole, as strip-nondeterminism's zip writer lays it out:
//! the members sorted by name (a jar puts `META-INF/` and `META-INF/MANIFEST.MF`
//! first), each local header followed by its data and, for members with bit 3 of the
//! flags, a data descriptor with its signature; then the central directory and the end
//! record, which keeps the archive comment. Compressed data is copied as it is.
//!
//! In every member:
//!   - the MS-DOS time and date become the timestamp's, in UTC (in a jar, a second
//!     earlier for `.clj` sources, so that they stay older than their classes);
//!   - the extended timestamp (0x5455) and NTFS (0x000a) extra fields get the
//!     timestamp, the Info-ZIP Unix (0x7875) one uid and gid 0;
//!   - members made on Unix get the attributes of a plain file or directory, 0755 when
//!     the owner could execute, else 0644.
//!
//! In a jar, the content of some members is normalized too: the main manifest loses
//! its `Bnd-LastModified:` lines (one without them is left as it is), javadoc pages are
//! normalized as files are, nested `.jar` members as jars. A deflated member whose
//! content is rewritten, even to the same bytes, is compressed again at level 6, as
//! strip-nondeterminism's zip writer does, even when that is larger than the content;
//! its flags stay as they were. strip-nondeterminism compresses with zlib, this with
//! flate2: the compressed bytes of those members differ, their content does not. Zip64 archives are [`Error::Unsupported`]. An archive with an encrypted member
//! is left alone.

use std::io::{Read, Write};

use flate2::Crc;

use crate::time::Utc;
use crate::{Error, Result, javadoc};

/// Which handler of strip-nondeterminism the archive goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Zip,
    Jar,
}

const LOCAL: u32 = 0x0403_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const END: u32 = 0x0605_4b50;
const DESCRIPTOR: u32 = 0x0807_4b50;
const ZIP64_LOCATOR: u32 = 0x0706_4b50;

fn malformed(what: &str) -> Error {
    Error::Malformed(format!("Reading ZIP archive failed: {what}"))
}

fn u16_at(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(*d.get(at..)?.first_chunk::<2>()?))
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(*d.get(at..)?.first_chunk::<4>()?))
}

fn short_at(d: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(u16_at(d, at)?))
}

/// A member, as the central directory and its local header describe it.
struct Member<'a> {
    made_by: u16,
    needed: u16,
    flags: u16,
    method: u16,
    crc: u32,
    csize: u32,
    usize: u32,
    name: &'a [u8],
    local_extra: Vec<u8>,
    central_extra: Vec<u8>,
    comment: &'a [u8],
    internal: u16,
    external: u32,
    /// The compressed data.
    data: Vec<u8>,
    /// The MS-DOS time and date to write.
    dos: (u16, u16),
}

/// The members and the archive comment.
fn read(d: &[u8]) -> Result<Option<(Vec<Member<'_>>, &[u8])>> {
    let bad = || malformed("format error: can't find EOCD signature");
    let last = d.len().checked_sub(22).ok_or_else(bad)?;
    let first = last.saturating_sub(0xffff);
    let end = (first..=last)
        .rev()
        .find(|&p| u32_at(d, p) == Some(END))
        .ok_or_else(bad)?;
    let trunc = || malformed("truncated archive");
    let count = short_at(d, end.saturating_add(10)).ok_or_else(trunc)?;
    let cd_offset = u32_at(d, end.saturating_add(16)).ok_or_else(trunc)?;
    let comment_len = short_at(d, end.saturating_add(20)).ok_or_else(trunc)?;
    let comment = d
        .get(end.saturating_add(22)..end.saturating_add(22).saturating_add(comment_len))
        .ok_or_else(trunc)?;
    let zip64_locator = end
        .checked_sub(20)
        .is_some_and(|p| u32_at(d, p) == Some(ZIP64_LOCATOR));
    if count == 0xffff || cd_offset == u32::MAX || zip64_locator {
        return Err(Error::Unsupported("Zip64 archive".to_owned()));
    }
    let mut pos = usize::try_from(cd_offset).map_err(|_| trunc())?;
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        if u32_at(d, pos) != Some(CENTRAL) {
            return Err(malformed("bad signature in central directory"));
        }
        let field = |off: usize| u16_at(d, pos.saturating_add(off)).ok_or_else(trunc);
        let word = |off: usize| u32_at(d, pos.saturating_add(off)).ok_or_else(trunc);
        let (name_len, extra_len, comment_len) = (
            usize::from(field(28)?),
            usize::from(field(30)?),
            usize::from(field(32)?),
        );
        let name_at = pos.saturating_add(46);
        let extra_at = name_at.saturating_add(name_len);
        let comment_at = extra_at.saturating_add(extra_len);
        let next = comment_at.saturating_add(comment_len);
        let csize = word(20)?;
        let usize_ = word(24)?;
        let offset = word(42)?;
        if csize == u32::MAX || usize_ == u32::MAX || offset == u32::MAX {
            return Err(Error::Unsupported("Zip64 member".to_owned()));
        }
        let flags = field(8)?;
        if flags & 1 != 0 {
            return Ok(None);
        }
        let local = usize::try_from(offset).map_err(|_| trunc())?;
        if u32_at(d, local) != Some(LOCAL) {
            return Err(malformed("bad signature in local header"));
        }
        let lname = short_at(d, local.saturating_add(26)).ok_or_else(trunc)?;
        let lextra = short_at(d, local.saturating_add(28)).ok_or_else(trunc)?;
        let lextra_at = local.saturating_add(30).saturating_add(lname);
        let data_at = lextra_at.saturating_add(lextra);
        let csize_n = usize::try_from(csize).map_err(|_| trunc())?;
        members.push(Member {
            made_by: field(4)?,
            needed: field(6)?,
            flags,
            method: field(10)?,
            crc: word(16)?,
            csize,
            usize: usize_,
            name: d.get(name_at..extra_at).ok_or_else(trunc)?,
            local_extra: d.get(lextra_at..data_at).ok_or_else(trunc)?.to_vec(),
            central_extra: d.get(extra_at..comment_at).ok_or_else(trunc)?.to_vec(),
            comment: d.get(comment_at..next).ok_or_else(trunc)?,
            internal: field(36)?,
            external: word(38)?,
            data: d
                .get(data_at..data_at.saturating_add(csize_n))
                .ok_or_else(trunc)?
                .to_vec(),
            dos: (field(12)?, field(14)?),
        });
        pos = next;
    }
    Ok(Some((members, comment)))
}

/// The extra fields of a member with their timestamps and owners normalized.
fn extra(fields: &[u8], time: u32, filetime: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.len());
    let mut pos = 0;
    while let (Some(id), Some(size)) =
        (u16_at(fields, pos), short_at(fields, pos.saturating_add(2)))
    {
        let start = pos.saturating_add(4);
        let end = start.saturating_add(size);
        let (Some(header), Some(data)) = (fields.get(pos..start), fields.get(start..end)) else {
            break;
        };
        out.extend_from_slice(header);
        match (id, data) {
            // extended timestamp: flags, then up to three times
            (0x5455, [flags, times @ ..]) => {
                out.push(*flags);
                let (slots, rest) = times.as_chunks::<4>();
                for _ in slots {
                    out.extend_from_slice(&time.to_le_bytes());
                }
                out.extend_from_slice(rest);
            }
            // Info-ZIP Unix, new: version, then uid and gid, each with its size
            (0x7875, [version, uid_size, rest @ ..]) => {
                let gid_size = rest.get(usize::from(*uid_size)).copied().unwrap_or(0);
                out.extend_from_slice(&[*version, *uid_size]);
                out.resize(out.len().saturating_add(usize::from(*uid_size)), 0);
                out.push(gid_size);
                out.resize(out.len().saturating_add(usize::from(gid_size)), 0);
            }
            // NTFS: reserved, then tagged attributes; tag 1 holds three FILETIMEs
            (0x000a, [r0, r1, r2, r3, attrs @ ..]) => {
                out.extend_from_slice(&[*r0, *r1, *r2, *r3]);
                ntfs(&mut out, attrs, filetime);
            }
            _ => out.extend_from_slice(data),
        }
        pos = end;
    }
    out.extend_from_slice(fields.get(pos..).unwrap_or_default());
    out
}

/// The tagged attributes of an NTFS extra field, the times of tag 1 replaced.
fn ntfs(out: &mut Vec<u8>, attrs: &[u8], filetime: u64) {
    let mut at = 0;
    while let (Some(tag), Some(len)) = (u16_at(attrs, at), short_at(attrs, at.saturating_add(2))) {
        let body = at.saturating_add(4);
        let (Some(header), Some(value)) = (
            attrs.get(at..body),
            attrs.get(body..body.saturating_add(len)),
        ) else {
            break;
        };
        out.extend_from_slice(header);
        if tag == 1 && len == 24 {
            for _ in 0..3 {
                out.extend_from_slice(&filetime.to_le_bytes());
            }
        } else {
            out.extend_from_slice(value);
        }
        at = body.saturating_add(len);
    }
    out.extend_from_slice(attrs.get(at..).unwrap_or_default());
}

/// The external attributes of a member made on Unix: a plain file or directory.
fn unix_attributes(m: &Member) -> u32 {
    if m.made_by >> 8 != 3 {
        return m.external;
    }
    let dir = m.name.ends_with(b"/") && m.usize == 0;
    let perm = if (m.external >> 16) & 0o100 != 0 {
        0o755
    } else {
        0o644
    };
    let kind = if dir { 0o040_000 } else { 0o100_000 };
    ((kind | perm) << 16) | if dir { 0x10 } else { 0 }
}

/// The manifest without its `Bnd-LastModified:` lines.
fn manifest(content: &[u8]) -> Vec<u8> {
    content
        .split_inclusive(|&b| b == b'\n')
        .filter(|line| !line.starts_with(b"Bnd-LastModified:"))
        .flatten()
        .copied()
        .collect()
}

fn inflate(m: &Member) -> Result<Vec<u8>> {
    match m.method {
        0 => Ok(m.data.clone()),
        8 => {
            let mut out = Vec::new();
            flate2::read::DeflateDecoder::new(&m.data[..])
                .read_to_end(&mut out)
                .map_err(|e| {
                    malformed(&format!(
                        "inflating {}: {e}",
                        String::from_utf8_lossy(m.name)
                    ))
                })?;
            Ok(out)
        }
        n => Err(Error::Unsupported(format!(
            "compression method {n} of {}",
            String::from_utf8_lossy(m.name)
        ))),
    }
}

/// The new content of a jar member, if strip-nondeterminism rewrites it.
fn jar_content(m: &Member, time: i64, warn: &mut dyn FnMut(String)) -> Result<Option<Vec<u8>>> {
    let new = if m.name == b"META-INF/MANIFEST.MF" {
        // rewritten only when it had such lines: otherwise its data stays as it is
        let old = inflate(m)?;
        Some(manifest(&old)).filter(|n| *n != old)
    } else if m.name.ends_with(b".html") {
        javadoc::normalize(&inflate(m)?, time)
    } else if m.name.ends_with(b".jar") {
        match normalize(&inflate(m)?, time, Flavor::Jar, warn) {
            Ok(Some(n)) => Some(n),
            Ok(None) => None,
            Err(Error::Malformed(_)) => {
                warn(format!(
                    "unknown file type of {}",
                    String::from_utf8_lossy(m.name)
                ));
                None
            }
            Err(e) => return Err(e),
        }
    } else {
        None
    };
    // an empty result leaves the member as it was
    Ok(new.filter(|n| !n.is_empty()))
}

fn sort_rank(flavor: Flavor, name: &[u8]) -> u8 {
    match (flavor, name) {
        (Flavor::Jar, b"META-INF/") => 0,
        (Flavor::Jar, b"META-INF/MANIFEST.MF") => 1,
        _ => 2,
    }
}

fn push16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn len16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// `data` as a raw deflate stream, at the level strip-nondeterminism's zip writer uses.
fn deflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
    e.write_all(data)
        .and_then(|()| e.finish())
        .map_err(|err| Error::Io(format!("deflate: {err}")))
}

fn len32(n: usize) -> Result<u32> {
    u32::try_from(n).map_err(|_| Error::Unsupported("archive over 4 GiB".to_owned()))
}

/// The normalized archive; `None` for an archive with an encrypted member.
///
/// # Errors
/// The archive cannot be read ([`Error::Malformed`]), or needs what this crate does
/// not write ([`Error::Unsupported`]).
pub fn normalize(
    d: &[u8],
    time: i64,
    flavor: Flavor,
    warn: &mut dyn FnMut(String),
) -> Result<Option<Vec<u8>>> {
    let Some((mut members, comment)) = read(d)? else {
        warn("ignoring encrypted zip file".to_owned());
        return Ok(None);
    };
    let time32 = u32::try_from(time).unwrap_or(0);
    let filetime = u64::try_from(time)
        .unwrap_or(0)
        .saturating_mul(10_000_000)
        .saturating_add(116_444_736_000_000_000);
    let dos = Utc::from_unix(time).dos();
    let clj_dos = Utc::from_unix(time.saturating_sub(1)).dos();
    members.sort_by(|a, b| {
        (sort_rank(flavor, a.name), a.name).cmp(&(sort_rank(flavor, b.name), b.name))
    });
    for m in &mut members {
        if flavor == Flavor::Jar
            && let Some(content) = jar_content(m, time, warn)?
        {
            let mut crc = Crc::new();
            crc.update(&content);
            m.crc = crc.sum();
            m.usize = len32(content.len())?;
            m.data = if m.method == 8 {
                deflate(&content)?
            } else {
                content
            };
            m.csize = len32(m.data.len())?;
        }
        m.local_extra = extra(&m.local_extra, time32, filetime);
        m.central_extra = extra(&m.central_extra, time32, filetime);
        m.external = unix_attributes(m);
        m.dos = if flavor == Flavor::Jar && m.name.ends_with(b".clj") {
            clj_dos
        } else {
            dos
        };
    }
    write(&members, comment).map(Some)
}

/// The archive of `members`, in this order.
fn write(members: &[Member], comment: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut offsets = Vec::with_capacity(members.len());
    for m in members {
        offsets.push(len32(out.len())?);
        let (t, dt) = m.dos;
        let descriptor = m.flags & 8 != 0;
        push32(&mut out, LOCAL);
        push16(&mut out, m.needed);
        push16(&mut out, m.flags);
        push16(&mut out, m.method);
        push16(&mut out, t);
        push16(&mut out, dt);
        for v in if descriptor {
            [0, 0, 0]
        } else {
            [m.crc, m.csize, m.usize]
        } {
            push32(&mut out, v);
        }
        push16(&mut out, len16(m.name.len()));
        push16(&mut out, len16(m.local_extra.len()));
        out.extend_from_slice(m.name);
        out.extend_from_slice(&m.local_extra);
        out.extend_from_slice(&m.data);
        if descriptor {
            for v in [DESCRIPTOR, m.crc, m.csize, m.usize] {
                push32(&mut out, v);
            }
        }
    }
    let cd_start = len32(out.len())?;
    for (m, offset) in members.iter().zip(offsets) {
        let (t, dt) = m.dos;
        push32(&mut out, CENTRAL);
        for v in [m.made_by, m.needed, m.flags, m.method, t, dt] {
            push16(&mut out, v);
        }
        for v in [m.crc, m.csize, m.usize] {
            push32(&mut out, v);
        }
        for v in [
            len16(m.name.len()),
            len16(m.central_extra.len()),
            len16(m.comment.len()),
            0,
            m.internal,
        ] {
            push16(&mut out, v);
        }
        push32(&mut out, m.external);
        push32(&mut out, offset);
        out.extend_from_slice(m.name);
        out.extend_from_slice(&m.central_extra);
        out.extend_from_slice(m.comment);
    }
    let cd_size = len32(out.len())?.saturating_sub(cd_start);
    let count = len16(members.len());
    push32(&mut out, END);
    for v in [0, 0, count, count] {
        push16(&mut out, v);
    }
    push32(&mut out, cd_size);
    push32(&mut out, cd_start);
    push16(&mut out, len16(comment.len()));
    out.extend_from_slice(comment);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    const T: i64 = 1_767_225_600;

    struct E<'a> {
        name: &'a str,
        data: &'a [u8],
        made_by: u16,
        external: u32,
        extra: &'a [u8],
    }

    fn e<'a>(name: &'a str, data: &'a [u8]) -> E<'a> {
        E {
            name,
            data,
            made_by: 0x0314,
            external: 0o100_644 << 16,
            extra: b"",
        }
    }

    /// A stored archive of `entries`, every time 2020-09-13.
    fn zip(entries: &[E]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for en in entries {
            let mut crc = Crc::new();
            crc.update(en.data);
            let off = u32::try_from(out.len()).unwrap();
            let n = len16(en.name.len());
            let x = len16(en.extra.len());
            let size = u32::try_from(en.data.len()).unwrap();
            push32(&mut out, LOCAL);
            for v in [20, 0, 0, 0x6354, 0x512d] {
                push16(&mut out, v);
            }
            for v in [crc.sum(), size, size] {
                push32(&mut out, v);
            }
            push16(&mut out, n);
            push16(&mut out, x);
            out.extend_from_slice(en.name.as_bytes());
            out.extend_from_slice(en.extra);
            out.extend_from_slice(en.data);
            push32(&mut cd, CENTRAL);
            for v in [en.made_by, 20, 0, 0, 0x6354, 0x512d] {
                push16(&mut cd, v);
            }
            for v in [crc.sum(), size, size] {
                push32(&mut cd, v);
            }
            for v in [n, x, 0, 0, 0] {
                push16(&mut cd, v);
            }
            push32(&mut cd, en.external);
            push32(&mut cd, off);
            cd.extend_from_slice(en.name.as_bytes());
            cd.extend_from_slice(en.extra);
        }
        let start = u32::try_from(out.len()).unwrap();
        let count = len16(entries.len());
        out.extend_from_slice(&cd);
        push32(&mut out, END);
        for v in [0, 0, count, count] {
            push16(&mut out, v);
        }
        push32(&mut out, u32::try_from(cd.len()).unwrap());
        push32(&mut out, start);
        push16(&mut out, 0);
        out
    }

    fn norm(d: &[u8], flavor: Flavor) -> Vec<u8> {
        normalize(d, T, flavor, &mut |_| {}).unwrap().unwrap()
    }

    /// (name, time, date, external attributes, extra, data) of a member.
    type Seen = (String, u16, u16, u32, Vec<u8>, Vec<u8>);

    fn members(d: &[u8]) -> Vec<Seen> {
        let (ms, _) = read(d).unwrap().unwrap();
        ms.iter()
            .map(|m| {
                let at = d.windows(m.name.len()).position(|w| w == m.name).unwrap();
                (
                    String::from_utf8(m.name.to_vec()).unwrap(),
                    u16_at(d, at - 20).unwrap(),
                    u16_at(d, at - 18).unwrap(),
                    m.external,
                    m.local_extra.clone(),
                    m.data.clone(),
                )
            })
            .collect()
    }

    #[test]
    fn order_times_attributes() {
        let input = zip(&[
            e("z/", b""),
            e("b", b"1"),
            E {
                external: 0o120_777 << 16,
                ..e("A", b"2")
            },
            E {
                external: 0o100_700 << 16,
                ..e("META-INF/MANIFEST.MF", b"M: 1\r\nBnd-LastModified: 1\r\n")
            },
            e("a.clj", b"x"),
            E {
                made_by: 0x0014,
                external: 0x21,
                ..e("META-INF/", b"")
            },
        ]);
        let zip_names: Vec<_> = members(&norm(&input, Flavor::Zip))
            .into_iter()
            .map(|m| (m.0, m.1, m.2, m.3))
            .collect();
        assert_eq!(
            zip_names,
            [
                ("A".into(), 0, 0x5c21, 0o100_755 << 16),
                ("META-INF/".into(), 0, 0x5c21, 0x21),
                ("META-INF/MANIFEST.MF".into(), 0, 0x5c21, 0o100_755 << 16),
                ("a.clj".into(), 0, 0x5c21, 0o100_644 << 16),
                ("b".into(), 0, 0x5c21, 0o100_644 << 16),
                ("z/".into(), 0, 0x5c21, (0o040_644 << 16) | 0x10),
            ]
        );
        let jar = members(&norm(&input, Flavor::Jar));
        let names: Vec<_> = jar.iter().map(|m| m.0.as_str()).collect();
        assert_eq!(
            names,
            ["META-INF/", "META-INF/MANIFEST.MF", "A", "a.clj", "b", "z/"]
        );
        assert_eq!(jar[1].5, b"M: 1\r\n");
        assert_eq!((jar[3].1, jar[3].2), (0xbf7d, 0x5b9f));
    }

    #[test]
    fn extra_fields() {
        let ut = b"UT\x0d\x00\x07\x00\xd2\x49\x6b\x01\x00\x00\x00\x02\x00\x00\x00";
        let ux = b"ux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00";
        let ux_short = b"ux\x06\x00\x01\x04\xe8\x03\x00\x00";
        let other = b"\xfe\xca\x03\x00xyz";
        let mut fields = [&ut[..], ux, other, ux_short].concat();
        let input = zip(&[E {
            extra: &fields,
            ..e("e", b"e")
        }]);
        let out = members(&norm(&input, Flavor::Zip));
        fields = [
            &b"UT\x0d\x00\x07"[..],
            &b"\x00\xb9\x55\x69".repeat(3),
            b"ux\x0b\x00\x01\x04\0\0\0\0\x04\0\0\0\0",
            other,
            // the gid size the field lacks is written, its length left as it was
            b"ux\x06\x00\x01\x04\0\0\0\0\0",
        ]
        .concat();
        assert_eq!(out[0].4, fields);
    }

    #[test]
    fn unchanged_data_and_comment() {
        let mut input = zip(&[e("a", b"aaa")]);
        let n = input.len();
        input[n - 2] = 3;
        input.extend_from_slice(b"abc");
        let out = norm(&input, Flavor::Zip);
        assert!(out.ends_with(b"\x03\x00abc"));
        assert_eq!(members(&out)[0].5, b"aaa");
        let mut bad = input.clone();
        bad.truncate(40);
        assert!(normalize(&bad, T, Flavor::Zip, &mut |_| {}).is_err());
    }
}
