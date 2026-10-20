//! Unix ar archives (`.a`): the member headers.
//!
//! An archive starts with `!<arch>\n`; anything else (a thin archive, `!<thin>\n`) is
//! left alone. Each member is a 60-byte header (name, mtime, uid, gid, mode, size, then
//! `` `\n ``) followed by its data, padded to an even length. The headers are rewritten
//! in place, in order, as strip-nondeterminism does: from the mtime field on, the
//! timestamp in decimal, uid and gid 0, and the mode `644`, or `755` when the mode
//! field, read as an integer with an optional radix prefix, has the owner's execute
//! bit; each left-aligned in its field. A member whose name starts with `/ ` (the
//! symbol table) keeps its mode, one whose name starts with `// ` (the long name table)
//! its whole header.
//!
//! The archive ends where a header would start at the end of the file. The size field is
//! a decimal number, padded with spaces; the data of a member is skipped by its size,
//! plus one if that is odd (the padding byte may be missing at the end of the file). A
//! header cut short, one without `` `\n ``, a size field that is not a decimal number, a
//! member whose data runs past the end of the file, or a timestamp of more than 12
//! digits fails the file.
//!
//! Differences from strip-nondeterminism, bugs of its handler: a failing archive is left
//! as it is, where it keeps the headers rewritten before the failure; a timestamp too
//! long for the mtime field fails the file, where it runs into the next fields. Its size
//! field is read as Perl reads a number (`+1`, `1x`, `5.9` or `9e18` pass, the last one
//! failing or not with the file system's largest offset), an empty member fails the
//! file, and a member cut short ends the archive.
//!
//! Written from ar(5) and from running strip-nondeterminism 1.13 (Debian 12) and 1.14
//! (Debian 13) on crafted archives.

use crate::{Error, Result, numeric};

const MAGIC: &[u8] = b"!<arch>\n";
const HEADER: usize = 60;

/// The normalized archive, or `None` when it is not one or has no header to rewrite.
///
/// # Errors
/// A header is malformed, or the timestamp does not fit the mtime field.
pub fn normalize(data: &[u8], time: i64) -> Result<Option<Vec<u8>>> {
    if !data.starts_with(MAGIC) {
        return Ok(None);
    }
    let stamp = format!("{time:<12}");
    if stamp.len() > 12 {
        return Err(Error::malformed(format!(
            "timestamp {time} too long for an ar header"
        )));
    }
    let mut out = data.to_vec();
    let mut written = false;
    let mut pos = MAGIC.len();
    let fail = |why: &str| Err(Error::malformed(why));
    while let Some(rest) = data.get(pos..).filter(|r| !r.is_empty()) {
        let Some(header) = rest.get(..HEADER) else {
            return fail("Incorrect header length");
        };
        if header.get(58..) != Some(b"`\n") {
            return fail("Incorrect file magic");
        }
        let Some(size) = size(header.get(48..58).unwrap_or_default()) else {
            return fail("Incorrect file size");
        };
        let data_start = pos.saturating_add(HEADER);
        let Some(end) = data_start
            .checked_add(size)
            .filter(|&end| end <= data.len())
        else {
            return fail("Member past the end of the file");
        };
        if !header.starts_with(b"// ") {
            let mode = header.get(40..48).unwrap_or_default();
            let mut fields = format!("{stamp}{:<6}{:<6}", 0, 0).into_bytes();
            if header.starts_with(b"/ ") {
                fields.extend_from_slice(mode);
            } else if numeric::radix(mode) & 0o100 != 0 {
                fields.extend_from_slice(b"755     ");
            } else {
                fields.extend_from_slice(b"644     ");
            }
            let at = pos.saturating_add(16);
            if let Some(slot) = out.get_mut(at..at.saturating_add(fields.len())) {
                slot.copy_from_slice(&fields);
            }
            written = true;
        }
        pos = end.saturating_add(size & 1);
    }
    Ok(written.then_some(out))
}

/// The size field: decimal digits, padded with spaces.
fn size(field: &[u8]) -> Option<usize> {
    let mut words = field.split(|&b| b == b' ').filter(|w| !w.is_empty());
    let (Some(n), None) = (words.next(), words.next()) else {
        return None;
    };
    if !n.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(n).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, mtime: &str, owner: u32, mode: &str, size: &str) -> Vec<u8> {
        format!("{name:<16}{mtime:<12}{owner:<6}{owner:<6}{mode:<8}{size:<10}`\n").into_bytes()
    }

    fn archive(members: &[(&str, &str, &[u8])]) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        for (name, mode, data) in members {
            v.extend(header(
                name,
                "1700000000",
                1000,
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
    fn headers() {
        let input = archive(&[
            ("/", "100644", b"sym"),
            ("//", "", b"long/\n"),
            ("a.o/", "100755", b"x"),
            ("b.o/", "100600", b"yy"),
            ("c.o/", "0x40", b"z"),
        ]);
        let out = normalize(&input, 1234).unwrap().unwrap();
        let want = [
            MAGIC,
            &header("/", "1234", 0, "100644", "3"),
            b"sym\n",
            &header("//", "1700000000", 1000, "", "6"),
            b"long/\n",
            &header("a.o/", "1234", 0, "755", "1"),
            b"x\n",
            &header("b.o/", "1234", 0, "644", "2"),
            b"yy",
            &header("c.o/", "1234", 0, "755", "1"),
            b"z\n",
        ]
        .concat();
        assert_eq!(
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(&want)
        );
    }

    #[test]
    fn long_timestamp_fails() {
        let input = archive(&[("a.o/", "644", b"x")]);
        assert!(normalize(&input, 999_999_999_999).unwrap().is_some());
        assert!(normalize(&input, 1_000_000_000_000).is_err());
    }

    #[test]
    fn not_ar_or_malformed() {
        assert_eq!(normalize(b"!<thin>\n", 0).unwrap(), None);
        assert_eq!(normalize(MAGIC, 0).unwrap(), None);
        assert_eq!(
            normalize(b"!<arch>\njunk", 0),
            Err(Error::malformed("Incorrect header length"))
        );
        // an empty member
        let empty = archive(&[("a.o/", "644", b""), ("b.o/", "644", b"x")]);
        assert!(normalize(&empty, 0).unwrap().is_some());
        let mut trailing = archive(&[("a.o/", "644", b"x")]);
        trailing.extend_from_slice(b"\n");
        assert!(matches!(normalize(&trailing, 0), Err(Error::Malformed(..))));
        // the last padding byte may be missing, not data
        let mut unpadded = MAGIC.to_vec();
        unpadded.extend(header("a.o/", "1", 1000, "644", "1"));
        unpadded.extend_from_slice(b"x");
        assert!(normalize(&unpadded, 5).unwrap().is_some());
        let mut long = MAGIC.to_vec();
        long.extend(header("a.o/", "1", 1000, "644", "100"));
        long.extend_from_slice(b"abc");
        assert_eq!(
            normalize(&long, 5),
            Err(Error::malformed("Member past the end of the file"))
        );
        for size in [
            "", "-1", "+1", "1x", "0x1", "1e0", "5.9", "9e18", "inf", "nan", "1 2", "\t1",
        ] {
            let mut v = MAGIC.to_vec();
            v.extend(header("a.o/", "1", 1000, "644", size));
            v.extend_from_slice(b"abcdef");
            assert_eq!(
                normalize(&v, 5),
                Err(Error::malformed("Incorrect file size")),
                "{size:?}"
            );
        }
        for size in ["6", "  6", "006"] {
            let mut v = MAGIC.to_vec();
            v.extend(header("a.o/", "1", 1000, "644", size));
            v.extend_from_slice(b"abcdef");
            assert!(normalize(&v, 5).unwrap().is_some(), "{size:?}");
        }
    }
}
