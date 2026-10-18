//! gzip (RFC 1952): the header of the first member.
//!
//! A non-zero MTIME becomes the timestamp (zero, "no time", stays), the original file
//! name (FNAME) and the header CRC (FHCRC) are dropped with their flags; FTEXT, FEXTRA,
//! FCOMMENT, XFL, OS and the reserved flag bits stay as they are. The compressed data,
//! the trailer and anything after the first member are copied unchanged. A file too
//! short for a header, or without the gzip magic, is left alone; a header field that
//! runs past the end of the file is an error.

use crate::{Error, Result};

const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;

fn malformed() -> Error {
    Error::Malformed("Malformed gzip file".to_owned())
}

/// The index just past the NUL ending the string at `pos`.
fn past_nul(data: &[u8], pos: usize) -> Result<usize> {
    let rest = data.get(pos..).ok_or_else(malformed)?;
    let n = rest.iter().position(|&b| b == 0).ok_or_else(malformed)?;
    pos.checked_add(n)
        .and_then(|p| p.checked_add(1))
        .ok_or_else(malformed)
}

/// The normalized file, or `None` for a file that is not gzip.
///
/// # Errors
/// A header field runs past the end of the file.
pub fn normalize(data: &[u8], time: u32) -> Result<Option<Vec<u8>>> {
    let Some((head, _)) = data.split_first_chunk::<10>() else {
        return Ok(None);
    };
    if head[..2] != [0x1f, 0x8b] {
        return Ok(None);
    }
    let flags = head[3];
    let mtime = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
    let mut pos = 10_usize;
    let mut extra = &[][..];
    if flags & FEXTRA != 0 {
        let len = data
            .get(pos..)
            .and_then(<[u8]>::first_chunk::<2>)
            .ok_or_else(malformed)?;
        let xlen = usize::from(u16::from_le_bytes(*len));
        let end = pos.saturating_add(2).saturating_add(xlen);
        extra = data.get(pos..end).ok_or_else(malformed)?;
        pos = end;
    }
    if flags & FNAME != 0 {
        pos = past_nul(data, pos)?;
    }
    let mut comment = &[][..];
    if flags & FCOMMENT != 0 {
        let end = past_nul(data, pos)?;
        comment = data.get(pos..end).ok_or_else(malformed)?;
        pos = end;
    }
    if flags & FHCRC != 0 {
        pos = pos.saturating_add(2);
        if pos > data.len() {
            return Err(malformed());
        }
    }
    let rest = data.get(pos..).ok_or_else(malformed)?;
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&head[..3]);
    out.push(flags & !(FNAME | FHCRC));
    out.extend_from_slice(&(if mtime == 0 { 0 } else { time }).to_le_bytes());
    out.extend_from_slice(&head[8..10]);
    out.extend_from_slice(extra);
    out.extend_from_slice(comment);
    out.extend_from_slice(rest);
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u32 = 1_767_225_600;
    const BODY: &[u8] = b"\xcb\x48\xcd\xc9\xc9\xe7\x02\x00\x20\x30\x3a\x36\x06\x00\x00\x00";

    fn gz(flags: u8, mtime: u32, fields: &[u8]) -> Vec<u8> {
        let mut v = vec![0x1f, 0x8b, 8, flags];
        v.extend_from_slice(&mtime.to_le_bytes());
        v.extend_from_slice(&[2, 3]);
        v.extend_from_slice(fields);
        v.extend_from_slice(BODY);
        v
    }

    #[test]
    fn header_fields() {
        // every flag: name and header CRC go, extra and comment stay
        let input = gz(0x1f, 1_800_000_000, b"\x04\x00CD\x00\x00n\x00c\x00\x99\x99");
        let mut want = gz(0x15, T, b"\x04\x00CD\x00\x00c\x00");
        want[8] = 2;
        assert_eq!(normalize(&input, T).unwrap(), Some(want));
        // no time stays no time, an older time is replaced all the same
        assert_eq!(normalize(&gz(0, 0, b""), T).unwrap(), Some(gz(0, 0, b"")));
        assert_eq!(
            normalize(&gz(0, 1000, b""), T).unwrap(),
            Some(gz(0, T, b""))
        );
        // reserved flag bits are kept
        assert_eq!(
            normalize(&gz(0xe0, 5, b""), T).unwrap(),
            Some(gz(0xe0, T, b""))
        );
    }

    #[test]
    fn not_gzip_or_truncated() {
        assert_eq!(normalize(b"\x1f\x8b\x08\x00\x00", T).unwrap(), None);
        assert_eq!(normalize(b"hello world, not gzip\n", T).unwrap(), None);
        let mut name = gz(8, 1, b"abc");
        name.truncate(13);
        assert!(normalize(&name, T).is_err());
    }
}
