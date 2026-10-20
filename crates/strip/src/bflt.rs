//! bFLT executables (`.bflt`): the build date in the header.
//!
//! The header is 64 bytes, big-endian: `bFLT`, the version, the entry point, the
//! starts and ends of the data and bss segments, the stack size, the relocations' start
//! and count, the flags, the build date (version 4), then 20 reserved bytes. As
//! strip-nondeterminism, only a header that looks like one is touched: version 4, the
//! addresses and the relocations' start below 0x0fffffff, the stack size and relocation
//! count below 0x00ffffff, no flag above the six defined ones, the reserved bytes zero.
//! A build date of zero or equal to the timestamp stays; any other becomes the
//! timestamp (modulo 2^32: a date equal to that is written again).
//!
//! Written from the bFLT header layout (uClinux's `flat.h`) and from running
//! strip-nondeterminism 1.13 (Debian 12) and 1.14 (Debian 13) on crafted headers.

/// The normalized executable, or `None` when it stays as it is.
#[must_use]
pub fn normalize(data: &[u8], time: i64) -> Option<Vec<u8>> {
    let (header, _) = data.split_first_chunk::<64>()?;
    let word = |i: usize| {
        let at = i.checked_mul(4)?;
        header
            .get(at..)
            .and_then(<[u8]>::first_chunk::<4>)
            .map(|b| u32::from_be_bytes(*b))
    };
    let looks_right = header.starts_with(b"bFLT")
        && word(1)? == 4
        && [2, 3, 4, 5, 7]
            .iter()
            .all(|&i| word(i).is_some_and(|v| v < 0x0fff_ffff))
        && [6, 8]
            .iter()
            .all(|&i| word(i).is_some_and(|v| v < 0x00ff_ffff))
        && word(9)? & !0x3f == 0
        && header.get(44..)?.iter().all(|&b| b == 0);
    let old = word(10)?;
    let new = u32::try_from(time & 0xffff_ffff).ok()?;
    // as strip-nondeterminism, a date equal to the whole timestamp stays
    if !looks_right || old == 0 || i64::from(old) == time {
        return None;
    }
    let mut out = data.to_vec();
    out.get_mut(40..44)?.copy_from_slice(&new.to_be_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Version, entry, data start and end, bss end, stack size, relocations' start and
    /// count, flags; then the date.
    fn bflt(fields: [u32; 9], date: u32) -> Vec<u8> {
        let mut v = b"bFLT".to_vec();
        for f in fields.iter().chain([&date]) {
            v.extend_from_slice(&f.to_be_bytes());
        }
        v.resize(64, 0);
        v.extend_from_slice(b"code");
        v
    }

    const F: [u32; 9] = [4, 0x40, 0x44, 0x48, 0x50, 0x1000, 0x48, 0, 0];

    #[test]
    fn build_date() {
        let fields = |i: usize, v: u32| {
            let mut f = F;
            f[i] = v;
            f
        };
        assert_eq!(
            normalize(&bflt(F, 1_700_000_000), 1234),
            Some(bflt(F, 1234))
        );
        assert_eq!(normalize(&bflt(F, 0), 1234), None);
        assert_eq!(normalize(&bflt(F, 1234), 1234), None);
        assert!(normalize(&bflt(fields(1, 0x0fff_fffe), 1), 2).is_some());
        assert!(normalize(&bflt(fields(1, 0x0fff_ffff), 1), 2).is_none());
        assert!(normalize(&bflt(fields(5, 0x00ff_fffe), 1), 2).is_some());
        assert!(normalize(&bflt(fields(5, 0x00ff_ffff), 1), 2).is_none());
        assert!(normalize(&bflt(fields(7, 0x00ff_ffff), 1), 2).is_none());
        assert!(normalize(&bflt(fields(6, 0x0fff_fffe), 1), 2).is_some());
        assert!(normalize(&bflt(fields(8, 0x3f), 1), 2).is_some());
        assert!(normalize(&bflt(fields(8, 0x40), 1), 2).is_none());
        assert!(normalize(&bflt(fields(0, 3), 1), 2).is_none());
    }

    #[test]
    fn not_bflt() {
        let mut v = bflt(F, 5);
        v[60] = 1;
        assert_eq!(normalize(&v, 1), None);
        assert_eq!(normalize(&bflt(F, 5)[..63], 1), None);
        v = bflt(F, 5);
        v[3] = b't';
        assert_eq!(normalize(&v, 1), None);
    }
}
