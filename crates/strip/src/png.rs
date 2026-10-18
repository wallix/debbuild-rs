//! PNG: the modification time chunk and the date text chunks.
//!
//! A `tIME` chunk, whatever its length, becomes the 7-byte timestamp. A `tEXt` chunk
//! whose keyword is `Creation Time` or starts with `date:` followed by at least one
//! character gets the timestamp as its text, `YYYY-MM-DDTHH:MM:SS-00:00`. Every other
//! chunk is copied as it is, CRC included; compressed text chunks (`zTXt`, `iTXt`) are
//! not looked into. Chunks after `IEND`, and bytes that do not make a whole chunk, are
//! copied unchanged.

use flate2::Crc;

use crate::time::Utc;

fn chunk(out: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) {
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&kind);
    out.extend_from_slice(data);
    let mut crc = Crc::new();
    crc.update(&kind);
    crc.update(data);
    out.extend_from_slice(&crc.sum().to_be_bytes());
}

/// Whether a `tEXt` keyword names a date strip-nondeterminism replaces.
fn date_keyword(key: &[u8]) -> bool {
    key == b"Creation Time" || key.strip_prefix(b"date:").is_some_and(|k| !k.is_empty())
}

/// The normalized file, or `None` when nothing changes.
#[must_use]
pub fn normalize(data: &[u8], time: i64) -> Option<Vec<u8>> {
    const SIG: &[u8] = b"\x89PNG\r\n\x1a\n";
    if !data.starts_with(SIG) {
        return None;
    }
    let utc = Utc::from_unix(time);
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(SIG);
    let mut pos = SIG.len();
    while let Some(head) = data
        .get(pos..)
        .and_then(<[u8]>::split_first_chunk::<8>)
        .map(|(h, _)| *h)
    {
        let len = usize::try_from(u32::from_be_bytes([head[0], head[1], head[2], head[3]]))
            .unwrap_or(usize::MAX);
        let kind = [head[4], head[5], head[6], head[7]];
        let end = pos.saturating_add(12).saturating_add(len);
        let (Some(whole), Some(body)) = (
            data.get(pos..end),
            data.get(pos.saturating_add(8)..end.saturating_sub(4)),
        ) else {
            break;
        };
        match &kind {
            b"tIME" => {
                let year = u16::try_from(utc.year).unwrap_or(0).to_be_bytes();
                let small = |n: u32| u8::try_from(n).unwrap_or(0);
                chunk(
                    &mut out,
                    *b"tIME",
                    &[
                        year[0],
                        year[1],
                        small(utc.month),
                        small(utc.day),
                        small(utc.hour),
                        small(utc.minute),
                        small(utc.second),
                    ],
                );
            }
            b"tEXt"
                if body
                    .iter()
                    .position(|&b| b == 0)
                    .is_some_and(|n| date_keyword(body.get(..n).unwrap_or_default())) =>
            {
                let key = body.split(|&b| b == 0).next().unwrap_or_default();
                let mut text = key.to_vec();
                text.push(0);
                text.extend_from_slice(
                    format!(
                        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}-00:00",
                        utc.year, utc.month, utc.day, utc.hour, utc.minute, utc.second
                    )
                    .as_bytes(),
                );
                chunk(&mut out, *b"tEXt", &text);
            }
            _ => out.extend_from_slice(whole),
        }
        pos = end;
        if &kind == b"IEND" {
            break;
        }
    }
    out.extend_from_slice(data.get(pos..).unwrap_or_default());
    (out != data).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_767_225_600;

    fn png(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        for (k, d) in chunks {
            chunk(&mut v, **k, d);
        }
        v
    }

    #[test]
    fn time_and_dates() {
        let ihdr = (b"IHDR", &b"\0\0\0\x01\0\0\0\x01\x08\0\0\0\0"[..]);
        let iend = (b"IEND", &b""[..]);
        let input = png(&[
            ihdr,
            (b"tIME", b"\x07\xee\x01\x02\x03\x04\x05\x06"),
            (b"tEXt", b"date:create\x002030-01-02T03:04:05+00:00"),
            (b"tEXt", b"Creation Time\x00Thu, 02 Jan 2030"),
            (b"tEXt", b"date:\x002030"),
            (b"tEXt", b"Software\x00gimp"),
            iend,
        ]);
        let want = png(&[
            ihdr,
            (b"tIME", b"\x07\xea\x01\x01\x00\x00\x00"),
            (b"tEXt", b"date:create\x002026-01-01T00:00:00-00:00"),
            (b"tEXt", b"Creation Time\x002026-01-01T00:00:00-00:00"),
            (b"tEXt", b"date:\x002030"),
            (b"tEXt", b"Software\x00gimp"),
            iend,
        ]);
        assert_eq!(normalize(&input, T), Some(want));
        assert_eq!(normalize(&png(&[ihdr, iend]), T), None);
    }

    #[test]
    fn after_iend_untouched() {
        let mut input = png(&[(b"IEND", b"")]);
        chunk(&mut input, *b"tIME", b"\x07\xee\x01\x02\x03\x04\x05");
        assert_eq!(normalize(&input, T), None);
    }
}
