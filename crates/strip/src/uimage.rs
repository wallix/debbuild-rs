//! U-Boot legacy images (`.uimage`): the creation time in the header.
//!
//! The image starts with a 64-byte big-endian header: the magic number 0x27051956, the
//! CRC-32 of the header (computed with this field zero), the creation time in seconds
//! since the epoch, then the sizes, addresses, data CRC, types and name. A header with
//! another magic number or a CRC that does not match is left alone, as is a creation
//! time of zero or equal to the timestamp; any other time becomes the timestamp (modulo
//! 2^32: a time equal to that is written again) and the header CRC is computed again.
//! The data and its CRC are not looked at.
//!
//! Written from the U-Boot legacy image header layout (`image_header_t`) and from
//! running strip-nondeterminism 1.13 (Debian 12) and 1.14 (Debian 13) on crafted images.

use flate2::Crc;

const MAGIC: u32 = 0x2705_1956;

fn crc(header: &[u8; 64]) -> u32 {
    let mut zeroed = *header;
    zeroed[4..8].fill(0);
    let mut c = Crc::new();
    c.update(&zeroed);
    c.sum()
}

/// The normalized image, or `None` when it stays as it is.
#[must_use]
pub fn normalize(data: &[u8], time: i64) -> Option<Vec<u8>> {
    let (header, _) = data.split_first_chunk::<64>()?;
    let word = |at: usize| {
        header
            .get(at..)
            .and_then(<[u8]>::first_chunk::<4>)
            .map(|b| u32::from_be_bytes(*b))
    };
    if word(0)? != MAGIC || word(4)? != crc(header) {
        return None;
    }
    let old = word(8)?;
    let new = u32::try_from(time & 0xffff_ffff).ok()?;
    // as strip-nondeterminism, a time equal to the whole timestamp stays
    if old == 0 || i64::from(old) == time {
        return None;
    }
    let mut header = *header;
    header[8..12].copy_from_slice(&new.to_be_bytes());
    let sum = crc(&header);
    header[4..8].copy_from_slice(&sum.to_be_bytes());
    let mut out = data.to_vec();
    out.get_mut(..64)?.copy_from_slice(&header);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(time: u32) -> Vec<u8> {
        let mut h = [0_u8; 64];
        h[..4].copy_from_slice(&MAGIC.to_be_bytes());
        h[8..12].copy_from_slice(&time.to_be_bytes());
        h[12..16].copy_from_slice(&3_u32.to_be_bytes());
        h[32..36].copy_from_slice(b"name");
        let sum = crc(&h);
        h[4..8].copy_from_slice(&sum.to_be_bytes());
        [&h[..], b"abc"].concat()
    }

    #[test]
    fn creation_time() {
        assert_eq!(normalize(&image(1_700_000_000), 1234), Some(image(1234)));
        assert_eq!(normalize(&image(1000), 1234), Some(image(1234)));
        assert_eq!(normalize(&image(1234), 1234), None);
        assert_eq!(normalize(&image(0), 1234), None);
        assert_eq!(normalize(&image(5), (1 << 32) + 7), Some(image(7)));
    }

    #[test]
    fn not_an_image() {
        let mut bad = image(1_700_000_000);
        bad[5] ^= 1;
        assert_eq!(normalize(&bad, 1234), None);
        bad = image(1_700_000_000);
        bad[3] ^= 1;
        assert_eq!(normalize(&bad, 1234), None);
        assert_eq!(normalize(&image(1_700_000_000)[..63], 1234), None);
    }
}
