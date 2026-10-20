//! cpio archives (`.cpio`): the modification times of the entries.
//!
//! Three formats of cpio(5), told by the first entry's magic: odc (`070707`, octal
//! fields), newc (`070701`, hexadecimal fields) and the old binary format with
//! little-endian fields. The archive is read up to its `TRAILER!!!` entry and written
//! again in the same format, as strip-nondeterminism writes it: every entry as it was
//! but for its mtime, the timestamp; then a trailer of zeros (but nlink 1); newc and
//! binary archives padded with zeros to a multiple of 512 bytes, odc ones not padded.
//! What follows the trailer is dropped. A name loses one trailing NUL when read and
//! gets one when written; newc pads names and data to 4 bytes, binary to 2.
//!
//! An archive that cannot be read (another format, a field that is not a number, an
//! entry of another format, data or a trailer missing), or with a name that, given its
//! NUL back, no longer fits the namesize field, is left alone; one with no entry before
//! its trailer is an error, as for strip-nondeterminism.
//!
//! Difference from strip-nondeterminism, a bug of its handler: a timestamp the format's
//! mtime field cannot hold (negative, or above 32 bits, 11 octal digits for odc) fails
//! the file, where it runs into the next fields, or loses its high bits.
//!
//! Written from cpio(5) and from running strip-nondeterminism 1.13 (Debian 12) and 1.14
//! (Debian 13) on crafted archives.

use std::fmt::Write as _;

use crate::{Error, Result, numeric};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Odc,
    Newc,
    Binary,
}

/// An entry: its header fields in the format's order, mtime aside, its name without
/// the trailing NUL, its data.
struct Entry<'a> {
    /// odc: dev, ino, mode, uid, gid, nlink, rdev; newc: ino, mode, uid, gid, nlink,
    /// then (after mtime and filesize) devmajor, devminor, rdevmajor, rdevminor, then
    /// (after namesize) check; binary: dev, ino, mode, uid, gid, nlink, rdev.
    fields: Vec<u64>,
    name: &'a [u8],
    data: &'a [u8],
}

const TRAILER: &[u8] = b"TRAILER!!!";

fn pad(n: usize, to: usize) -> usize {
    n.checked_rem(to)
        .filter(|&r| r != 0)
        .map_or(0, |r| to.saturating_sub(r))
}

/// The value of an odc field: its digits read as octal up to the first 8 or 9, as
/// strip-nondeterminism reads them; `None` if it is not all digits.
fn octal(field: &[u8]) -> Option<u64> {
    field
        .iter()
        .all(u8::is_ascii_digit)
        .then(|| numeric::radix(field))
}

fn hex(field: &[u8]) -> Option<u64> {
    if !field.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(field).ok()?, 16).ok()
}

/// The name of `namesize` bytes, without one trailing NUL.
fn name(raw: &[u8]) -> &[u8] {
    raw.strip_suffix(b"\0").unwrap_or(raw)
}

/// The entry at `pos` in `format`, and where the next one starts.
fn entry(d: &[u8], pos: usize, format: Format) -> Option<(Entry<'_>, usize)> {
    let rest = d.get(pos..)?;
    let (fields, namesize, filesize, header, align) = match format {
        Format::Odc => {
            let h = rest.get(..76)?;
            if !h.starts_with(b"070707") {
                return None;
            }
            let mut v = Vec::with_capacity(10);
            for (at, len) in [
                (6_usize, 6_usize),
                (12, 6),
                (18, 6),
                (24, 6),
                (30, 6),
                (36, 6),
                (42, 6),
                (48, 11),
                (59, 6),
                (65, 11),
            ] {
                v.push(octal(h.get(at..at.checked_add(len)?)?)?);
            }
            let filesize = v.pop()?;
            let namesize = v.pop()?;
            v.pop()?; // mtime
            (v, namesize, filesize, 76, 1)
        }
        Format::Newc => {
            let h = rest.get(..110)?;
            if !h.starts_with(b"070701") {
                return None;
            }
            let mut v = Vec::with_capacity(13);
            for i in 0..13_usize {
                let at = i.checked_mul(8)?.checked_add(6)?;
                v.push(hex(h.get(at..at.checked_add(8)?)?)?);
            }
            let check = v.pop()?;
            let namesize = v.pop()?;
            let mut fields: Vec<u64> = v.get(..5)?.to_vec();
            fields.extend_from_slice(v.get(7..11)?);
            fields.push(check);
            (fields, namesize, *v.get(6)?, 110, 4)
        }
        Format::Binary => {
            let h = rest.get(..26)?;
            let w = |i: usize| {
                let at = i.checked_mul(2)?;
                Some(u64::from(u16::from_le_bytes(
                    *h.get(at..)?.first_chunk::<2>()?,
                )))
            };
            if w(0)? != 0o070_707 {
                return None;
            }
            let fields = (1..=7).map(w).collect::<Option<Vec<_>>>()?;
            let filesize = (w(11)? << 16) | w(12)?;
            (fields, w(10)?, filesize, 26, 2)
        }
    };
    let namesize = usize::try_from(namesize).ok()?;
    let filesize = usize::try_from(filesize).ok()?;
    let name_at = pos.checked_add(header)?;
    let name_end = name_at.checked_add(namesize)?;
    let raw = d.get(name_at..name_end)?;
    let data_at = name_end.checked_add(pad(header.checked_add(namesize)?, align))?;
    let data_end = data_at.checked_add(filesize)?;
    let data = d.get(data_at..data_end)?;
    let next = data_end.checked_add(pad(filesize, align))?;
    Some((
        Entry {
            fields,
            name: name(raw),
            data,
        },
        next,
    ))
}

/// The entries before the trailer; `None` if the archive cannot be read.
fn read(d: &[u8]) -> Option<(Format, Vec<Entry<'_>>)> {
    let format = if d.starts_with(b"070707") {
        Format::Odc
    } else if d.starts_with(b"070701") {
        Format::Newc
    } else if d.starts_with(&[0xc7, 0x71]) {
        Format::Binary
    } else {
        return None;
    };
    let mut entries = Vec::new();
    let mut pos = 0;
    loop {
        let (e, next) = entry(d, pos, format)?;
        if e.name == TRAILER {
            return Some((format, entries));
        }
        entries.push(e);
        pos = next;
    }
}

fn write(out: &mut Vec<u8>, format: Format, e: &Entry, mtime: u64) {
    let namesize = e.name.len().saturating_add(1);
    let filesize = e.data.len();
    let f = |i: usize| e.fields.get(i).copied().unwrap_or(0);
    let align = match format {
        Format::Odc => {
            let mut h = String::from("070707");
            for i in 0..7 {
                let _ = write!(h, "{:06o}", f(i));
            }
            let _ = write!(h, "{mtime:011o}{namesize:06o}{filesize:011o}");
            out.extend_from_slice(h.as_bytes());
            1
        }
        Format::Newc => {
            let mut h = String::from("070701");
            for i in 0..5 {
                let _ = write!(h, "{:08X}", f(i));
            }
            let _ = write!(h, "{mtime:08X}{filesize:08X}");
            for i in 5..9 {
                let _ = write!(h, "{:08X}", f(i));
            }
            let _ = write!(h, "{namesize:08X}{:08X}", f(9));
            out.extend_from_slice(h.as_bytes());
            4
        }
        Format::Binary => {
            let size = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
            let mut words = vec![0o070_707];
            words.extend((0..7).map(f));
            words.extend([mtime >> 16, mtime, size(namesize), size(filesize) >> 16]);
            words.push(size(filesize));
            for w in words {
                let w = u16::try_from(w & 0xffff).unwrap_or(0);
                out.extend_from_slice(&w.to_le_bytes());
            }
            2
        }
    };
    out.extend_from_slice(e.name);
    out.push(0);
    let name_pad = pad(header_len(format).saturating_add(namesize), align);
    out.resize(out.len().saturating_add(name_pad), 0);
    out.extend_from_slice(e.data);
    out.resize(out.len().saturating_add(pad(filesize, align)), 0);
}

/// Whether the namesize and filesize fields of `format` hold those of `e` as written.
fn fits(format: Format, e: &Entry) -> bool {
    let (name_max, file_max): (u64, u64) = match format {
        Format::Odc => (0o777_777, 0o77_777_777_777),
        Format::Newc => (u64::from(u32::MAX), u64::from(u32::MAX)),
        Format::Binary => (0xffff, u64::from(u32::MAX)),
    };
    let size = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    size(e.name.len()) < name_max && size(e.data.len()) <= file_max
}

fn header_len(format: Format) -> usize {
    match format {
        Format::Odc => 76,
        Format::Newc => 110,
        Format::Binary => 26,
    }
}

/// The normalized archive, or `None` when it is left as it is.
///
/// # Errors
/// The archive has no entry before its trailer, or the timestamp does not fit it.
pub fn normalize(d: &[u8], time: i64) -> Result<Option<Vec<u8>>> {
    let Some((format, entries)) = read(d).filter(|(f, es)| es.iter().all(|e| fits(*f, e))) else {
        return Ok(None);
    };
    if entries.is_empty() {
        return Err(Error::malformed("no entry before the trailer"));
    }
    let limit = match format {
        Format::Odc => 0o77_777_777_777,
        Format::Newc | Format::Binary => u64::from(u32::MAX),
    };
    let Some(mtime) = u64::try_from(time).ok().filter(|t| *t <= limit) else {
        return Err(Error::malformed(format!(
            "timestamp {time} out of the range of the archive's mtime fields"
        )));
    };
    let mut out = Vec::with_capacity(d.len());
    for e in &entries {
        write(&mut out, format, e, mtime);
    }
    let trailer_fields = match format {
        Format::Odc | Format::Binary => vec![0, 0, 0, 0, 0, 1, 0],
        Format::Newc => vec![0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
    };
    write(
        &mut out,
        format,
        &Entry {
            fields: trailer_fields,
            name: TRAILER,
            data: b"",
        },
        0,
    );
    if format != Format::Odc {
        out.resize(out.len().saturating_add(pad(out.len(), 512)), 0);
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(format: Format, entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in entries {
            let fields = match format {
                Format::Odc | Format::Binary => vec![1, 2, 0o100_644, 0, 0, 1, 0],
                Format::Newc => vec![2, 0o100_644, 0, 0, 1, 0, 0, 0, 0, 0],
            };
            write(&mut out, format, &Entry { fields, name, data }, 1234);
        }
        write(
            &mut out,
            format,
            &Entry {
                fields: vec![0; 10],
                name: TRAILER,
                data: b"",
            },
            0,
        );
        out
    }

    #[test]
    fn odd_padding() {
        for format in [Format::Odc, Format::Newc, Format::Binary] {
            let entries: [(&[u8], &[u8]); 3] = [(b"a", b"xyz"), (b"bc", b"x"), (b"def", b"")];
            let d = archive(format, &entries);
            let (_, read) = read(&d).expect("readable");
            let got: Vec<(&[u8], &[u8])> = read.iter().map(|e| (e.name, e.data)).collect();
            assert_eq!(got, entries);
            let out = normalize(&d, 5).unwrap().expect("rewritten");
            let (_, again) = super::read(&out).expect("readable");
            let got: Vec<(&[u8], &[u8])> = again.iter().map(|e| (e.name, e.data)).collect();
            assert_eq!(got, entries);
            if format != Format::Odc {
                assert_eq!(out.len() % 512, 0);
            }
        }
    }

    /// A name without its NUL whose namesize field is already at the maximum is left
    /// alone: written with its NUL, its size would not fit.
    #[test]
    fn name_overflowing_namesize() {
        // binary: namesize 0xffff, no NUL, 1 byte of padding to 2
        let mut bin = vec![0xc7, 0x71];
        bin.extend([0; 18]);
        bin.extend([0xff, 0xff, 0, 0, 0, 0]);
        bin.extend(std::iter::repeat_n(b'n', 0xffff));
        bin.push(0);
        bin.extend(archive(Format::Binary, &[]));
        assert_eq!(read(&bin).map(|(_, es)| es.len()), Some(1));
        assert_eq!(normalize(&bin, 5).unwrap(), None);
        // odc: namesize 0o777777, no NUL
        let mut odc = b"070707".to_vec();
        odc.extend(b"000000".repeat(7));
        odc.extend(b"00000000000777777");
        odc.extend(b"00000000000");
        odc.extend(std::iter::repeat_n(b'n', 0o777_777));
        odc.extend(archive(Format::Odc, &[]));
        assert_eq!(read(&odc).map(|(_, es)| es.len()), Some(1));
        assert_eq!(normalize(&odc, 5).unwrap(), None);
        // one byte less fits
        let mut odc = b"070707".to_vec();
        odc.extend(b"000000".repeat(7));
        odc.extend(b"00000000000777776");
        odc.extend(b"00000000000");
        odc.extend(std::iter::repeat_n(b'n', 0o777_776));
        odc.extend(archive(Format::Odc, &[]));
        let out = normalize(&odc, 5).unwrap().expect("rewritten");
        assert_eq!(out.get(59..65), Some(&b"777777"[..]));
    }
}
