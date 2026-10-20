//! Zip archives (APPNOTE.TXT) and the formats built on them: Java archives, Java
//! modules (`JM`, a version, then a zip archive, normalized as a jar after those 4 bytes
//! kept) and Python zip applications (a `#!` line, kept, then a zip archive).
//!
//! The archive is rewritten whole, as strip-nondeterminism's zip writer lays it out:
//! the members sorted by name (a jar puts `META-INF/` and `META-INF/MANIFEST.MF`
//! first), each local header followed by its data and, for members with bit 3 of the
//! flags, a data descriptor with its signature; then the central directory and the end
//! record, which keeps the archive comment. Compressed data is copied as it is; the CRC
//! and uncompressed size of a stored member are those of its data, the others keep
//! theirs; a member of no content is written stored, without data or data descriptor
//! (one of another method than deflate leaves the archive alone).
//!
//! In every member:
//!   - the MS-DOS time and date become the timestamp's, in UTC (in a jar, a second
//!     earlier for `.clj` sources, so that they stay older than their classes); a year
//!     past 2107 wraps around, as the 7-bit year field does;
//!   - the extended timestamp (0x5455) extra field gets the timestamp modulo 2^32, the
//!     NTFS (0x000a) one the timestamp, the Info-ZIP Unix (0x7875, version 1) one uid
//!     and gid 0;
//!   - members made on Unix get the attributes of a plain file or directory, 0755 when
//!     the owner could execute, else 0644.
//!
//! The MS-DOS and extended timestamps are never earlier than 1980-01-01 12:01:00 UTC
//! (the earliest time strip-nondeterminism writes there), the NTFS ones are.
//!
//! A signed jar (a `META-INF/*.SF` member) is left alone. A jar loses its `javac.sh`,
//! `org.codehaus.plexus.compiler.javac.JavacCompiler<digits>arguments` members, as
//! strip-nondeterminism drops them (it drops members named `0` too, a bug debbuild-rs
//! does not reproduce). In a jar, the content of some members is normalized too: the
//! main manifest loses its `Bnd-LastModified:` and `Built-By:` lines (one without them
//! is left as it is), javadoc pages are normalized as files are, nested `.jar` members
//! as jars; such a member of another method than store or deflate fails the archive,
//! but for the manifest, kept. A deflated member whose content is rewritten, even to
//! the same bytes, is compressed again at level 6, as strip-nondeterminism's zip writer
//! does, even when that is larger than the content; its flags stay as they were.
//! strip-nondeterminism compresses with zlib, this with flate2: the compressed bytes of
//! those members differ, their content does not.
//!
//! Zip64 (an end record whose locator and record check out) is read and written as
//! strip-nondeterminism reads and writes it: the Zip64 extra fields of a Zip64
//! archive give the values the headers overflow and are dropped; a local header is
//! written Zip64 (sizes in a Zip64 extra field appended to its others) when its size
//! needs it or it was one, the Zip64 end records when a local header is Zip64 or the
//! central directory needs them. In an archive without them, Zip64 extra fields are
//! kept as any other, and the overflow markers in the end record are an error.
//!
//! The archive is read as strip-nondeterminism reads it: the central directory ends
//! where the end record starts, whatever offset the end record gives, and its entries
//! run up to the end record, whatever count it gives; if the first local header is not
//! at the offset its entry gives, every local header is shifted by the difference
//! between the central directory's place and that offset (data prepended to the
//! archive). An archive with an encrypted member, or one whose local headers or data are
//! not there, is left alone with a warning; a central directory or end record that
//! cannot be read is an error. Data prepended to the archive is not written back. A
//! directory entry takes its version needed, flags, method and name from its local
//! header, which must agree with the central directory on its CRC and sizes. An extra
//! field block that would outgrow its 16-bit length with the Zip64 field the writer
//! appends leaves the archive alone, with a warning.
//!
//! Differences from strip-nondeterminism, bugs of its handler: bytes of an extra field
//! block that do not make a whole field are kept as they are, where it drops them or
//! every field of the header; an Info-ZIP Unix field whose uid and gid sizes do not add
//! up to its length is kept as it is, where it writes the field again from those sizes
//! under its old length; a jar member named `0` is kept, where it drops it. Jars are
//! normalized in jars up to 32 deep: one nested deeper fails the outermost archive
//! (strip-nondeterminism has no limit).

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
/// The earliest time strip-nondeterminism writes in the MS-DOS and extended timestamps:
/// 1980-01-01 12:01:00 UTC.
const EARLIEST: i64 = 315_576_060;

fn malformed(what: &str) -> Error {
    Error::malformed(format!("Reading ZIP archive failed: {what}"))
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
    csize: u64,
    usize: u64,
    /// The name its central directory entry gives.
    cd_name: &'a [u8],
    /// A directory's name as its local header gives it, when it differs.
    local_name: Option<Vec<u8>>,
    local_extra: Vec<u8>,
    central_extra: Vec<u8>,
    comment: &'a [u8],
    internal: u16,
    external: u32,
    /// The compressed data.
    data: Vec<u8>,
    /// The MS-DOS time and date to write.
    dos: (u16, u16),
    /// Its local header had a Zip64 extra field, in a Zip64 archive.
    zip64_local: bool,
}

impl Member<'_> {
    fn name(&self) -> &[u8] {
        self.local_name.as_deref().unwrap_or(self.cd_name)
    }
}

/// The made-by and version-needed fields of a Zip64 end record.
#[derive(Clone, Copy)]
struct Zip64End {
    made_by: u16,
    needed: u16,
}

/// An archive as strip-nondeterminism reads it.
enum Archive<'a> {
    /// The members, the archive comment, and the Zip64 end record if it has one.
    Members(Vec<Member<'a>>, &'a [u8], Option<Zip64End>),
    /// An archive it leaves as it is, with this warning: an encrypted member, or one
    /// whose local header, data or data descriptor cannot be read.
    Left(String),
}

const ZIP64_END: u32 = 0x0606_4b50;
const ZIP64_EXTRA: u16 = 0x0001;
const MAX16: u16 = u16::MAX;
const MAX32: u32 = u32::MAX;

fn u64_at(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(*d.get(at..)?.first_chunk::<8>()?))
}

/// The end record, and the place of the Zip64 end record if there is one: its locator
/// 20 bytes before the end record, and the record itself ending at the locator.
fn ends(d: &[u8]) -> Result<(usize, Option<usize>)> {
    if d.len() < 22 {
        // strip-nondeterminism exits with status 25 on such a file
        return Err(Error::Malformed(
            "Reading ZIP archive failed: format error: file is too short".to_owned(),
            25,
        ));
    }
    // as strip-nondeterminism, the end record is looked for in the last 32 KiB only: an
    // archive comment longer than that hides it
    let last = d.len().saturating_sub(22);
    let first = d.len().saturating_sub(32_768);
    let end = (first..=last)
        .rev()
        .find(|&p| u32_at(d, p) == Some(END))
        .ok_or_else(|| malformed("format error: can't find EOCD signature"))?;
    let zip64 = end.checked_sub(20).and_then(|loc| {
        if u32_at(d, loc)? != ZIP64_LOCATOR {
            return None;
        }
        let rec = usize::try_from(u64_at(d, loc.checked_add(8)?)?).ok()?;
        let size = usize::try_from(u64_at(d, rec.checked_add(4)?)?).ok()?;
        (rec <= loc.checked_sub(56)?
            && u32_at(d, rec)? == ZIP64_END
            && rec.checked_add(12)?.checked_add(size)? == loc)
            .then_some(rec)
    });
    Ok((end, zip64))
}

/// The archive in `d`, read as strip-nondeterminism reads it. The central directory
/// ends where the (Zip64) end record starts, whatever offset the end record gives, and
/// its entries run up to that record, whatever count it gives. A local header is
/// looked for at the offset its entry gives, then shifted by the difference between
/// where the central directory is and the offset the end record gives (data prepended
/// to the archive). In a Zip64 archive, the Zip64 extra fields give the sizes and
/// offsets the headers overflow, and are dropped.
fn read(d: &[u8]) -> Result<Archive<'_>> {
    let (end, zip64) = ends(d)?;
    let trunc = || malformed("truncated archive");
    let comment_len = short_at(d, end.saturating_add(20)).ok_or_else(trunc)?;
    let comment = d
        .get(end.saturating_add(22)..end.saturating_add(22).saturating_add(comment_len))
        .ok_or_else(|| malformed("IO error: reading zipfile comment"))?;
    let (cd_end, cd_size, cd_offset, zip64_end) = if let Some(rec) = zip64 {
        let at = |off: usize| u64_at(d, rec.saturating_add(off)).ok_or_else(trunc);
        let half = |off: usize| u16_at(d, rec.saturating_add(off)).ok_or_else(trunc);
        let z = Zip64End {
            made_by: half(12)?,
            needed: half(14)?,
        };
        (rec, at(40)?, at(48)?, Some(z))
    } else {
        let field = |off: usize| u16_at(d, end.saturating_add(off)).ok_or_else(trunc);
        let word = |off: usize| u32_at(d, end.saturating_add(off)).ok_or_else(trunc);
        let markers = [field(4)?, field(6)?, field(8)?, field(10)?].contains(&MAX16)
            || [word(12)?, word(16)?].contains(&MAX32);
        if markers {
            return Err(malformed(
                "format error: unexpected zip64 marker values in EOCD",
            ));
        }
        (end, u64::from(word(12)?), u64::from(word(16)?), None)
    };
    let cd_start = usize::try_from(cd_size)
        .ok()
        .and_then(|n| cd_end.checked_sub(n))
        .ok_or_else(|| {
            // strip-nondeterminism fails to seek there (EINVAL)
            Error::Malformed(
                "Reading ZIP archive failed: format error: central directory before the file"
                    .to_owned(),
                22,
            )
        })?;
    let terminator = if zip64.is_some() { ZIP64_END } else { END };
    let entries = central_directory(d, cd_start, terminator, zip64.is_some())?;
    let shift = i128::try_from(cd_start)
        .unwrap_or(0)
        .saturating_sub(i128::from(cd_offset));
    let mut members = Vec::with_capacity(entries.len());
    for e in entries {
        if e.flags & 1 != 0 {
            return Ok(Archive::Left("ignoring encrypted zip file".to_owned()));
        }
        match member(d, e, shift, zip64.is_some())? {
            Ok(m) => members.push(m),
            Err(why) => return Ok(Archive::Left(why)),
        }
    }
    Ok(Archive::Members(members, comment, zip64_end))
}

/// The member of entry `e`, its local header found at its offset or `shift` bytes
/// further; the warning to leave the archive with when it cannot be read.
fn member<'a>(
    d: &'a [u8],
    e: Entry<'a>,
    shift: i128,
    zip64: bool,
) -> Result<Result<Member<'a>, String>> {
    {
        let left = |what: &str| {
            Ok(Err(format!(
                "{what} of {}: left as it is",
                String::from_utf8_lossy(e.name)
            )))
        };
        let at = |offset: i128| usize::try_from(offset).ok();
        let stored = at(i128::from(e.offset));
        let local = match stored {
            Some(l) if u32_at(d, l) == Some(LOCAL) => l,
            _ => match at(i128::from(e.offset).saturating_add(shift)) {
                Some(l) => l,
                None => return left("IO error: seeking to local header"),
            },
        };
        match u32_at(d, local) {
            Some(LOCAL) => {}
            Some(_) => return left("bad local header signature"),
            None => return left("IO error: reading header signature"),
        }
        let (Some(lname), Some(lextra)) = (
            short_at(d, local.saturating_add(26)),
            short_at(d, local.saturating_add(28)),
        ) else {
            return left("IO error: reading local header");
        };
        let dir = if e.name.ends_with(b"/") && e.usize == 0 {
            Some(directory(d, local, lname, &e)?)
        } else {
            None
        };
        let lextra_at = local.saturating_add(30).saturating_add(lname);
        let data_at = lextra_at.saturating_add(lextra);
        let Some(local_extra) = d.get(lextra_at..data_at) else {
            return left("IO error: reading local extra field");
        };
        let (local_extra, zip64_local) = if zip64 {
            let (fields, z64) = without_zip64(local_extra)?;
            (fields, z64.is_some())
        } else {
            (local_extra.to_vec(), false)
        };
        let csize = usize::try_from(e.csize).unwrap_or(usize::MAX);
        let data_end = data_at.saturating_add(csize);
        let Some(data) = d.get(data_at..data_end) else {
            return left("IO error: reading data");
        };
        if e.flags & 8 != 0 && !descriptor_matches(d, data_end, &e, zip64_local) {
            return left("format error: CRC or size mismatch in the data descriptor");
        }
        // as strip-nondeterminism's zip writer, stored data has its own CRC and size
        let (crc, usize) = if e.method == 0 {
            let mut crc = Crc::new();
            crc.update(data);
            (crc.sum(), e.csize)
        } else {
            (e.crc, e.usize)
        };
        Ok(Ok(Member {
            made_by: e.made_by,
            needed: dir.as_ref().map_or(e.needed, |d| d.needed),
            flags: dir.as_ref().map_or(e.flags, |d| d.flags),
            method: dir.as_ref().map_or(e.method, |d| d.method),
            crc,
            csize: e.csize,
            usize,
            cd_name: e.name,
            local_name: dir.as_ref().and_then(|d| d.name.clone()),
            local_extra,
            central_extra: e.extra,
            comment: e.comment,
            internal: e.internal,
            external: e.external,
            data: data.to_vec(),
            dos: dir.as_ref().map_or(e.dos, |d| d.dos),
            zip64_local,
        }))
    }
}

/// What a directory takes from its local header, as strip-nondeterminism reads it.
struct Directory {
    needed: u16,
    flags: u16,
    method: u16,
    dos: (u16, u16),
    /// Its name, backslashes made slashes and runs of slashes one, if not the entry's.
    name: Option<Vec<u8>>,
}

/// The fields of the local header of the directory at `local`.
///
/// # Errors
/// The header cannot be read, or (without a data descriptor) its CRC or sizes are not
/// the entry's.
fn directory(d: &[u8], local: usize, lname: usize, e: &Entry) -> Result<Directory> {
    let bad = || malformed("format error: CRC or size mismatch in a directory's local header");
    let field = |off: usize| u16_at(d, local.saturating_add(off)).ok_or_else(bad);
    let word = |off: usize| u32_at(d, local.saturating_add(off)).ok_or_else(bad);
    let flags = field(6)?;
    if flags & 8 == 0
        && (word(14)? != e.crc
            || u64::from(word(18)?) != e.csize
            || u64::from(word(22)?) != e.usize)
    {
        return Err(bad());
    }
    let raw = d
        .get(local.saturating_add(30)..local.saturating_add(30).saturating_add(lname))
        .ok_or_else(bad)?;
    let mut name: Vec<u8> = Vec::with_capacity(raw.len());
    for &b in raw {
        let b = if b == b'\\' { b'/' } else { b };
        if !(b == b'/' && name.last() == Some(&b'/')) {
            name.push(b);
        }
    }
    Ok(Directory {
        needed: field(4)?,
        flags,
        method: field(8)?,
        dos: (field(10)?, field(12)?),
        name: (name != e.name).then_some(name),
    })
}

/// Whether the data descriptor after a member's data, its signature optional, holds the
/// CRC and sizes of its entry (sizes of 8 bytes for a Zip64 local header).
fn descriptor_matches(d: &[u8], at: usize, e: &Entry, zip64: bool) -> bool {
    let at = if u32_at(d, at) == Some(DESCRIPTOR) {
        at.saturating_add(4)
    } else {
        at
    };
    let sizes = if zip64 {
        u64_at(d, at.saturating_add(4)).zip(u64_at(d, at.saturating_add(12)))
    } else {
        u32_at(d, at.saturating_add(4))
            .zip(u32_at(d, at.saturating_add(8)))
            .map(|(c, u)| (u64::from(c), u64::from(u)))
    };
    u32_at(d, at) == Some(e.crc) && sizes == Some((e.csize, e.usize))
}

/// Extra fields without their Zip64 one, and its data; an error, as in a Zip64 archive
/// for strip-nondeterminism, for fields that do not fill the block exactly.
fn without_zip64(fields: &[u8]) -> Result<(Vec<u8>, Option<&[u8]>)> {
    let invalid = || malformed("format error: invalid extra field");
    let mut out = Vec::with_capacity(fields.len());
    let mut zip64 = None;
    let mut pos = 0;
    while pos < fields.len() {
        let id = u16_at(fields, pos).ok_or_else(invalid)?;
        let size = short_at(fields, pos.saturating_add(2)).ok_or_else(invalid)?;
        let start = pos.saturating_add(4);
        let end = start.saturating_add(size);
        let field = fields.get(pos..end).ok_or_else(invalid)?;
        if id == ZIP64_EXTRA {
            zip64 = field.get(4..);
        } else {
            out.extend_from_slice(field);
        }
        pos = end;
    }
    Ok((out, zip64))
}

/// A central directory entry.
struct Entry<'a> {
    made_by: u16,
    needed: u16,
    flags: u16,
    method: u16,
    dos: (u16, u16),
    crc: u32,
    csize: u64,
    usize: u64,
    internal: u16,
    external: u32,
    offset: u64,
    name: &'a [u8],
    extra: Vec<u8>,
    comment: &'a [u8],
}

/// The entries of the central directory at `pos`, up to the `terminator` signature;
/// with `zip64`, the values their Zip64 extra fields give.
fn central_directory(
    d: &[u8],
    mut pos: usize,
    terminator: u32,
    zip64: bool,
) -> Result<Vec<Entry<'_>>> {
    let trunc = || malformed("truncated archive");
    let mut entries = Vec::new();
    loop {
        match u32_at(d, pos) {
            Some(CENTRAL) => {}
            Some(sig) if sig == terminator => return Ok(entries),
            Some(sig) => {
                return Err(malformed(&format!(
                    "format error: bad signature: {sig:#010x} at offset {pos}"
                )));
            }
            None => return Err(trunc()),
        }
        let field = |off: usize| u16_at(d, pos.saturating_add(off)).ok_or_else(trunc);
        let word = |off: usize| u32_at(d, pos.saturating_add(off)).ok_or_else(trunc);
        let name_at = pos.saturating_add(46);
        let extra_at = name_at.saturating_add(usize::from(field(28)?));
        let comment_at = extra_at.saturating_add(usize::from(field(30)?));
        let next = comment_at.saturating_add(usize::from(field(32)?));
        let raw_extra = d.get(extra_at..comment_at).ok_or_else(trunc)?;
        let (mut usize_, mut csize, mut offset) = (
            u64::from(word(24)?),
            u64::from(word(20)?),
            u64::from(word(42)?),
        );
        let extra = if zip64 {
            let (fields, z64) = without_zip64(raw_extra)?;
            if let Some(values) = z64 {
                let mut values = values;
                for v in [&mut usize_, &mut csize, &mut offset] {
                    if *v == u64::from(MAX32) {
                        *v = u64_at(values, 0).ok_or_else(|| {
                            malformed(
                                "format error: invalid zip64 extended information extra field",
                            )
                        })?;
                        values = values.get(8..).unwrap_or_default();
                    }
                }
                if field(34)? == MAX16 {
                    values = values.get(4..).unwrap_or_default();
                }
                if !values.is_empty() {
                    return Err(malformed(
                        "format error: invalid zip64 extended information extra field",
                    ));
                }
            }
            fields
        } else {
            raw_extra.to_vec()
        };
        entries.push(Entry {
            made_by: field(4)?,
            needed: field(6)?,
            flags: field(8)?,
            method: field(10)?,
            dos: (field(12)?, field(14)?),
            crc: word(16)?,
            csize,
            usize: usize_,
            internal: field(36)?,
            external: word(38)?,
            offset,
            name: d.get(name_at..extra_at).ok_or_else(trunc)?,
            extra,
            comment: d.get(comment_at..next).ok_or_else(trunc)?,
        });
        pos = next;
    }
}

/// The extra fields of a member with their timestamps and owners normalized; bytes
/// that do not make a whole field are kept as they are (strip-nondeterminism drops
/// them, or every field of the header, a bug of its handler).
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
            // Info-ZIP Unix, new, version 1: uid and gid, each with its size; one of
            // another length is kept (strip-nondeterminism writes past it, a bug)
            (0x7875, [1, uid_size, rest @ ..]) => match ux_sizes(*uid_size, rest) {
                Some((uid_size, gid_size)) => {
                    out.extend_from_slice(&[1, uid_size]);
                    out.resize(out.len().saturating_add(usize::from(uid_size)), 0);
                    out.push(gid_size);
                    out.resize(out.len().saturating_add(usize::from(gid_size)), 0);
                }
                None => out.extend_from_slice(data),
            },
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

/// The uid and gid sizes of an Info-ZIP Unix field whose data after its version is
/// `uid_size` then `rest`, if they make up the whole field.
fn ux_sizes(uid_size: u8, rest: &[u8]) -> Option<(u8, u8)> {
    let gid_size = *rest.get(usize::from(uid_size))?;
    let len = usize::from(uid_size)
        .checked_add(1)?
        .checked_add(usize::from(gid_size))?;
    (len == rest.len()).then_some((uid_size, gid_size))
}

/// The NTFS time of `time` (in 100 ns since 1601) as strip-nondeterminism writes it:
/// the remainder and the truncated quotient of its division by 2^32, each modulo 2^32;
/// computed exactly from -2^63 to 2^64 ticks, in floating point past that, as its
/// output shows.
fn filetime(time: i64) -> u64 {
    const HALF: i128 = 1 << 32;
    let secs = i128::from(time).saturating_add(11_644_473_600);
    let ticks = secs.saturating_mul(10_000_000);
    let (low, high) = if (i128::from(i64::MIN)..=i128::from(u64::MAX)).contains(&ticks) {
        (
            ticks.rem_euclid(HALF),
            ticks.checked_div(HALF).unwrap_or_default(),
        )
    } else {
        // |ticks| < 2^87: the f64 values and their quotient fit an i128
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let float = |f: f64| f as i128;
        #[allow(clippy::cast_precision_loss)]
        let ticks = secs as f64 * 1e7;
        let half = 4_294_967_296.0_f64;
        (float(ticks.rem_euclid(half)), float((ticks / half).trunc()))
    };
    let word = |v: i128| u64::try_from(v & 0xffff_ffff).unwrap_or_default();
    word(high) << 32 | word(low)
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
    let dir = m.name().ends_with(b"/") && m.usize == 0;
    let perm = if (m.external >> 16) & 0o100 != 0 {
        0o755
    } else {
        0o644
    };
    let kind = if dir { 0o040_000 } else { 0o100_000 };
    ((kind | perm) << 16) | if dir { 0x10 } else { 0 }
}

/// Whether strip-nondeterminism drops a jar member of this name: build leftovers of
/// javac (`javac.sh`, plexus's `JavacCompiler<digits>arguments`). It drops members named
/// `0` too, a bug of its handler, which debbuild-rs does not have.
fn removed(name: &[u8]) -> bool {
    let plexus = name
        .strip_prefix(b"org.codehaus.plexus.compiler.javac.JavacCompiler")
        .and_then(|rest| rest.strip_suffix(b"arguments"))
        .is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit));
    name == b"javac.sh" || plexus
}

/// The manifest without its `Bnd-LastModified:` and `Built-By:` lines (their
/// continuation lines stay, as strip-nondeterminism leaves them).
fn manifest(content: &[u8]) -> Vec<u8> {
    content
        .split_inclusive(|&b| b == b'\n')
        .filter(|line| !line.starts_with(b"Bnd-LastModified:") && !line.starts_with(b"Built-By:"))
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
                        String::from_utf8_lossy(m.name())
                    ))
                })?;
            Ok(out)
        }
        n => Err(malformed(&format!(
            "failed to rewind ZIP member {}: compression method {n}",
            String::from_utf8_lossy(m.name())
        ))),
    }
}

/// How deep jars are normalized in jars: a jar nested deeper fails the outermost one.
const NESTING: usize = 32;

/// Why an archive nested in jars failed: a jar nested too deep fails the outermost
/// archive, where the other errors of a nested jar leave it as it is.
enum Fail {
    TooDeep,
    Error(Error),
}

impl From<Error> for Fail {
    fn from(e: Error) -> Fail {
        Fail::Error(e)
    }
}

/// The new content of a jar member, if strip-nondeterminism rewrites it; the jar is
/// nested `depth` deep.
fn jar_content(
    m: &Member,
    time: i64,
    depth: usize,
    warn: &mut dyn FnMut(String),
) -> Result<Option<Vec<u8>>, Fail> {
    let new = if m.name() == b"META-INF/MANIFEST.MF" {
        if m.method != 0 && m.method != 8 {
            // as strip-nondeterminism: it cannot read the manifest, and keeps it
            warn(format!(
                "unsupported compression method {} of the manifest: kept as it is",
                m.method
            ));
            return Ok(None);
        }
        // rewritten only when it had such lines: otherwise its data stays as it is
        let old = inflate(m)?;
        Some(manifest(&old)).filter(|n| *n != old)
    } else if m.name().ends_with(b".html") {
        javadoc::normalize(&inflate(m)?, time)
    } else if m.name().ends_with(b".jar") {
        let depth = depth.saturating_add(1);
        if depth > NESTING {
            return Err(Fail::TooDeep);
        }
        match nested(&inflate(m)?, time, Flavor::Jar, depth, warn) {
            Ok(Some(n)) => Some(n),
            Ok(None) => None,
            Err(Fail::Error(Error::Malformed(..))) => {
                warn(format!(
                    "unknown file type of {}",
                    String::from_utf8_lossy(m.name())
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

fn len64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The normalized archive; `None` when it is left as it is (see the module doc).
///
/// # Errors
/// The archive cannot be read ([`Error::Malformed`]).
pub fn normalize(
    d: &[u8],
    time: i64,
    flavor: Flavor,
    warn: &mut dyn FnMut(String),
) -> Result<Option<Vec<u8>>> {
    nested(d, time, flavor, 0, warn).map_err(|e| match e {
        Fail::TooDeep => malformed(&format!("jars nested more than {NESTING} deep")),
        Fail::Error(e) => e,
    })
}

/// [`normalize`] for an archive nested `depth` deep in jars.
fn nested(
    d: &[u8],
    time: i64,
    flavor: Flavor,
    depth: usize,
    warn: &mut dyn FnMut(String),
) -> Result<Option<Vec<u8>>, Fail> {
    let (mut members, comment, zip64) = match read(d)? {
        Archive::Members(members, comment, zip64) => (members, comment, zip64),
        Archive::Left(why) => {
            warn(why);
            return Ok(None);
        }
    };
    // as strip-nondeterminism, a signed jar is left alone before any member is removed;
    // a name ending in `.SF` and one newline counts as a signature too, one with a
    // newline elsewhere does not
    if flavor == Flavor::Jar
        && members.iter().any(|m| {
            m.name().strip_prefix(b"META-INF/").is_some_and(|rest| {
                let rest = rest.strip_suffix(b"\n").unwrap_or(rest);
                rest.ends_with(b".SF") && !rest.contains(&b'\n')
            })
        })
    {
        warn("ignoring signed JAR file".to_owned());
        return Ok(None);
    }
    if flavor == Flavor::Jar {
        members.retain(|m| {
            let gone = removed(m.name());
            if gone {
                warn(format!(
                    "Removing {} from the archive",
                    String::from_utf8_lossy(m.name())
                ));
            }
            !gone
        });
    }
    let filetime = filetime(time);
    let clamped = time.max(EARLIEST);
    let time32 = u32::try_from(clamped & 0xffff_ffff).unwrap_or(0);
    let dos = Utc::from_unix(clamped).dos();
    let clj_dos = Utc::from_unix(clamped.saturating_sub(1)).dos();
    members.sort_by(|a, b| {
        (sort_rank(flavor, a.name()), a.name()).cmp(&(sort_rank(flavor, b.name()), b.name()))
    });
    for m in &mut members {
        if flavor == Flavor::Jar
            && let Some(content) = jar_content(m, time, depth, warn)?
        {
            let mut crc = Crc::new();
            crc.update(&content);
            m.crc = crc.sum();
            m.usize = len64(content.len());
            m.data = if m.method == 8 {
                deflate(&content)?
            } else {
                content
            };
            m.csize = len64(m.data.len());
        }
        // as strip-nondeterminism's zip writer, an empty member is stored; one of an
        // unknown method it cannot write, and leaves the archive alone
        if m.usize == 0 && m.method != 0 && m.method != 8 {
            warn(format!(
                "unsupported compression method {} of {}: left as it is",
                m.method,
                String::from_utf8_lossy(m.name())
            ));
            return Ok(None);
        }
        if m.usize == 0 {
            m.method = 0;
            m.flags &= !8;
            m.data.clear();
            m.csize = 0;
            m.crc = 0;
        }
        m.local_extra = extra(&m.local_extra, time32, filetime);
        m.central_extra = extra(&m.central_extra, time32, filetime);
        m.external = unix_attributes(m);
        m.dos = if flavor == Flavor::Jar && m.name().ends_with(b".clj") {
            clj_dos
        } else {
            dos
        };
    }
    let out = write(&members, comment, zip64);
    if out.is_none() {
        warn(
            "extra fields too long for their header with the Zip64 field: left as it is".to_owned(),
        );
    }
    Ok(out)
}

/// Whether the first bytes of a file are those of a Python zip application, as
/// strip-nondeterminism tells them (file(1) confirms it is a python3 script): in its
/// first 32 bytes, `#!`, then a zip local header at the start of a line.
#[must_use]
pub fn is_pyzip(head: &[u8]) -> bool {
    let head = head.get(..32).unwrap_or(head);
    head.starts_with(b"#!") && head.windows(5).skip(1).any(|w| w == b"\nPK\x03\x04")
}

/// Without file(1): whether the first line of a Python zip application names python3,
/// as file(1) would.
#[must_use]
pub fn pyzip_line(head: &[u8]) -> bool {
    let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = line
        .iter()
        .rposition(|b| !b.is_ascii_whitespace() && *b != 0x0b)
        .and_then(|end| line.get(..=end))
        .unwrap_or_default();
    line.ends_with(b"python3")
}

/// A Python zip application normalized: its first line, then the zip archive after it
/// normalized as a zip (the lines between are dropped, as the real handler drops them).
///
/// # Errors
/// As [`normalize`]. A file without a newline is all first line, before an empty
/// archive: too short, as for strip-nondeterminism.
pub fn normalize_pyzip(
    d: &[u8],
    time: i64,
    warn: &mut dyn FnMut(String),
) -> Result<Option<Vec<u8>>> {
    let line = d
        .iter()
        .position(|&b| b == b'\n')
        .map_or(d.len(), |nl| nl.saturating_add(1));
    prefixed(d, line, time, Flavor::Zip, warn)
}

/// A Java module normalized: `JM` and two version bytes, kept, then a zip archive
/// normalized as a jar; `None` for a file that does not start with `JM` and two bytes
/// other than a newline.
///
/// # Errors
/// As [`normalize`].
pub fn normalize_jmod(
    d: &[u8],
    time: i64,
    warn: &mut dyn FnMut(String),
) -> Result<Option<Vec<u8>>> {
    if !matches!(d, [b'J', b'M', v1, v2, ..] if *v1 != b'\n' && *v2 != b'\n') {
        return Ok(None);
    }
    prefixed(d, 4, time, Flavor::Jar, warn)
}

/// The first `len` bytes of `d` as they are, then the archive after them normalized.
fn prefixed(
    d: &[u8],
    len: usize,
    time: i64,
    flavor: Flavor,
    warn: &mut dyn FnMut(String),
) -> Result<Option<Vec<u8>>> {
    let (head, archive) = d.split_at(len.min(d.len()));
    Ok(normalize(archive, time, flavor, warn)?.map(|z| [head, &z[..]].concat()))
}

/// The archive of `members`, in this order, as strip-nondeterminism's zip writer lays
/// it out. A member's local header is Zip64 when its size needs it or, in a Zip64
/// archive, when it was before (a directory's never is); its central header when a size
/// or its offset needs it. The Zip64 end records are written when a local header is
/// Zip64, or the count, size or offset of the central directory needs them. `None` when
/// the extra fields of a header, with the Zip64 one, are longer than its length field
/// holds.
fn write(members: &[Member], comment: &[u8], zip64: Option<Zip64End>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut offsets = Vec::with_capacity(members.len());
    let mut any_zip64 = false;
    for m in members {
        offsets.push(len64(out.len()));
        any_zip64 |= write_local(&mut out, m, zip64.is_some())?;
    }
    let cd_start = len64(out.len());
    for (m, offset) in members.iter().zip(offsets) {
        write_central(&mut out, m, offset)?;
    }
    let cd_end = len64(out.len());
    let cd_size = cd_end.saturating_sub(cd_start);
    let count = len64(members.len());
    if any_zip64 || count > 0xffff || over(cd_size) || over(cd_start) {
        let (made_by, needed) = zip64.map_or((45, 45), |z| (z.made_by, z.needed.max(45)));
        push32(&mut out, ZIP64_END);
        out.extend_from_slice(&44_u64.to_le_bytes());
        push16(&mut out, made_by);
        push16(&mut out, needed);
        push32(&mut out, 0);
        push32(&mut out, 0);
        for v in [count, count, cd_size, cd_start] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        push32(&mut out, ZIP64_LOCATOR);
        push32(&mut out, 0);
        out.extend_from_slice(&cd_end.to_le_bytes());
        push32(&mut out, 1);
    }
    let count16 = u16::try_from(count).unwrap_or(MAX16);
    push32(&mut out, END);
    for v in [0, 0, count16, count16] {
        push16(&mut out, v);
    }
    push32(&mut out, narrow(cd_size));
    push32(&mut out, narrow(cd_start));
    push16(&mut out, len16(comment.len()));
    out.extend_from_slice(comment);
    Some(out)
}

fn over(v: u64) -> bool {
    v > u64::from(MAX32)
}

fn narrow(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(MAX32)
}

/// Whether a member's local header is Zip64 (in a `zip64` archive or not).
fn local_zip64(m: &Member, zip64: bool) -> bool {
    let dir = m.name().ends_with(b"/") && m.usize == 0;
    !dir && (over(m.usize) || over(m.csize) || (zip64 && m.zip64_local))
}

/// Write the local header, data and data descriptor of `m`; whether the header is Zip64,
/// or `None` if its extra fields are too long for it.
fn write_local(out: &mut Vec<u8>, m: &Member, zip64: bool) -> Option<bool> {
    let (t, dt) = m.dos;
    let descriptor = m.flags & 8 != 0;
    let z64 = local_zip64(m, zip64);
    let (crc, csize, usize) = if descriptor {
        (0, 0, 0)
    } else {
        (m.crc, m.csize, m.usize)
    };
    push32(out, LOCAL);
    push16(out, if z64 { m.needed.max(45) } else { m.needed });
    push16(out, m.flags);
    push16(out, m.method);
    push16(out, t);
    push16(out, dt);
    push32(out, crc);
    if z64 {
        push32(out, MAX32);
        push32(out, MAX32);
    } else {
        push32(out, narrow(csize));
        push32(out, narrow(usize));
    }
    let mut extra = m.local_extra.clone();
    if z64 {
        extra.extend_from_slice(&ZIP64_EXTRA.to_le_bytes());
        extra.extend_from_slice(&16_u16.to_le_bytes());
        extra.extend_from_slice(&usize.to_le_bytes());
        extra.extend_from_slice(&csize.to_le_bytes());
    }
    push16(out, len16(m.name().len()));
    push16(out, u16::try_from(extra.len()).ok()?);
    out.extend_from_slice(m.name());
    out.extend_from_slice(&extra);
    out.extend_from_slice(&m.data);
    if descriptor {
        push32(out, DESCRIPTOR);
        push32(out, m.crc);
        if z64 {
            out.extend_from_slice(&m.csize.to_le_bytes());
            out.extend_from_slice(&m.usize.to_le_bytes());
        } else {
            push32(out, narrow(m.csize));
            push32(out, narrow(m.usize));
        }
    }
    Some(z64)
}

/// Write the central directory entry of `m`, whose local header is at `offset`; `None`
/// if its extra fields are too long for it.
fn write_central(out: &mut Vec<u8>, m: &Member, offset: u64) -> Option<()> {
    let (t, dt) = m.dos;
    let z64 = over(m.usize) || over(m.csize) || over(offset);
    let mut extra = m.central_extra.clone();
    if z64 {
        // the offset goes in whenever the field is there
        let values: Vec<u64> = [m.usize, m.csize]
            .into_iter()
            .filter(|&v| over(v))
            .chain([offset])
            .collect();
        extra.extend_from_slice(&ZIP64_EXTRA.to_le_bytes());
        extra.extend_from_slice(&len16(values.len().saturating_mul(8)).to_le_bytes());
        for v in values {
            extra.extend_from_slice(&v.to_le_bytes());
        }
    }
    push32(out, CENTRAL);
    let needed = if z64 { m.needed.max(45) } else { m.needed };
    for v in [m.made_by, needed, m.flags, m.method, t, dt] {
        push16(out, v);
    }
    push32(out, m.crc);
    push32(
        out,
        if over(m.csize) {
            MAX32
        } else {
            narrow(m.csize)
        },
    );
    push32(
        out,
        if over(m.usize) {
            MAX32
        } else {
            narrow(m.usize)
        },
    );
    for v in [
        len16(m.name().len()),
        u16::try_from(extra.len()).ok()?,
        len16(m.comment.len()),
        0,
        m.internal,
    ] {
        push16(out, v);
    }
    push32(out, m.external);
    push32(out, if z64 { MAX32 } else { narrow(offset) });
    out.extend_from_slice(m.name());
    out.extend_from_slice(&extra);
    out.extend_from_slice(m.comment);
    Some(())
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
        let Archive::Members(ms, _, _) = read(d).unwrap() else {
            panic!("left as it is");
        };
        ms.iter()
            .map(|m| {
                let at = d
                    .windows(m.name().len())
                    .position(|w| w == m.name())
                    .unwrap();
                (
                    String::from_utf8(m.name().to_vec()).unwrap(),
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

    /// An extended timestamp of another length than 1 + 4n, which strip-nondeterminism
    /// writes inconsistently, and an NTFS attribute of size 0, on which it hangs: bugs,
    /// not reproduced.
    #[test]
    fn odd_extra_fields() {
        let ut = b"UT\x06\x00\x01abcdz";
        assert_eq!(
            extra(ut, 0x0102_0304, 0),
            b"UT\x06\x00\x01\x04\x03\x02\x01z"
        );
        let ntfs = [
            &b"\x0a\x00\x24\x00\0\0\0\0\x02\x00\x00\x00\x01\x00\x18\x00"[..],
            &[9; 24],
        ]
        .concat();
        let out = extra(&ntfs, 0, 5);
        assert_eq!(&out[..16], &ntfs[..16]);
        assert_eq!(&out[16..], &[5_u64.to_le_bytes(); 3].concat()[..]);
    }

    #[test]
    fn extra_fields() {
        let ut = b"UT\x0d\x00\x07\x00\xd2\x49\x6b\x01\x00\x00\x00\x02\x00\x00\x00";
        let ux = b"ux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00";
        let ux_short = b"ux\x06\x00\x01\x04\xe8\x03\x00\x00";
        let ux_long = b"ux\x09\x00\x01\x02\xe8\x03\x02\xe8\x03xy";
        let other = b"\xfe\xca\x03\x00xyz";
        let mut fields = [&ut[..], ux, other, ux_short, ux_long].concat();
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
            // kept: their sizes do not add up to their lengths
            ux_short,
            ux_long,
        ]
        .concat();
        assert_eq!(out[0].4, fields);
    }

    /// A header whose extra fields leave no room for the Zip64 one its sizes or offset
    /// need fails the writer, which leaves the archive alone.
    #[test]
    fn extra_too_long_for_zip64() {
        let m = |central_extra: Vec<u8>, usize: u64| Member {
            made_by: 0x0314,
            needed: 20,
            flags: 0,
            method: 0,
            crc: 0,
            csize: 0,
            usize,
            cd_name: b"a",
            local_name: None,
            local_extra: Vec::new(),
            central_extra,
            comment: b"",
            internal: 0,
            external: 0,
            data: Vec::new(),
            dos: (0, 0),
            zip64_local: false,
        };
        let over = u64::from(MAX32) + 1;
        let mut out = Vec::new();
        assert!(write_central(&mut out, &m(vec![0; 65_523], 0), over).is_some());
        assert!(write_central(&mut out, &m(vec![0; 65_524], 0), over).is_none());
        assert!(write_local(&mut out, &m(Vec::new(), 0), false).is_some());
        assert!(write(&[m(vec![0; 65_520], over)], b"", None).is_none());
        assert!(write(&[m(vec![0; 65_400], 0)], b"", None).is_some());
    }

    #[test]
    fn pyzip_without_newline() {
        let mut d = b"#!/usr/bin/python3 ".to_vec();
        d.extend(zip(&[e("a", b"a")]));
        d.retain(|&b| b != b'\n');
        let err = normalize_pyzip(&d, T, &mut |_| {}).unwrap_err();
        assert_eq!(err.status(), 25, "{err}");
    }

    /// As strip-nondeterminism, the end record is looked for in the last 32 KiB only.
    #[test]
    fn long_comment() {
        for (len, found) in [(32_746, true), (32_747, false), (40_960, false)] {
            let mut d = zip(&[e("a", b"a")]);
            let n = d.len();
            d[n - 2..].copy_from_slice(&u16::try_from(len).unwrap().to_le_bytes());
            d.resize(n + len, b'c');
            let out = normalize(&d, T, Flavor::Zip, &mut |_| {});
            assert_eq!(out.is_ok(), found, "{len}: {out:?}");
        }
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
