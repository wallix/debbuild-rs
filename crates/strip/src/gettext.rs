//! GNU gettext message catalogs (.mo): the date in the header entry.
//!
//! The header is the translation of the entry whose original string is empty. Its first
//! line starting with `POT-Creation-Date: ` or `PO-Revision-Date: ` holds a date,
//! `YYYY-MM-DD HH:MM±hhmm` and nothing else to the end of the line; a date later than
//! the timestamp is replaced with the timestamp, in UTC, in place (the same length, so
//! no offset moves: a timestamp before the year 1000 leaves it). Catalogs whose
//! revision, shifted right by 8 bits, is above 1 (as strip-nondeterminism reads the
//! major revision), or whose tables do not fit in the file, are left alone.

use crate::time::{Utc, days_from_civil};

fn word(data: &[u8], at: usize, big: bool) -> Option<usize> {
    let b = *data.get(at..)?.first_chunk::<4>()?;
    usize::try_from(if big {
        u32::from_be_bytes(b)
    } else {
        u32::from_le_bytes(b)
    })
    .ok()
}

/// The (start, length) of the header string.
fn header(data: &[u8]) -> Option<(usize, usize)> {
    let big = match data.get(..4)? {
        [0xde, 0x12, 0x04, 0x95] => false,
        [0x95, 0x04, 0x12, 0xde] => true,
        _ => return None,
    };
    if word(data, 4, big)? >> 8 > 1 {
        return None;
    }
    let n = word(data, 8, big)?;
    let originals = word(data, 12, big)?;
    let translations = word(data, 16, big)?;
    for i in 0..n {
        let at = originals.checked_add(i.checked_mul(8)?)?;
        if word(data, at, big)? == 0 {
            let at = translations.checked_add(i.checked_mul(8)?)?;
            let len = word(data, at, big)?;
            let start = word(data, at.checked_add(4)?, big)?;
            data.get(start..start.checked_add(len)?)?;
            return Some((start, len));
        }
    }
    None
}

fn digits(s: &[u8]) -> Option<u32> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(s).ok()?.parse().ok()
}

/// Seconds since the epoch of `YYYY-MM-DD HH:MM±hhmm`.
#[allow(clippy::arithmetic_side_effects)] // two-digit fields, checked below
fn parse(v: &[u8]) -> Option<i64> {
    let v: &[u8; 21] = v.try_into().ok()?;
    if [v[4], v[7], v[10], v[13]] != *b"-- :" {
        return None;
    }
    let num = |a: usize, b: usize| v.get(a..b).and_then(digits);
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute) = (num(11, 13)?, num(14, 16)?);
    let sign = match v[16] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let (zh, zm) = (num(17, 19)?, num(19, 21)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let local = days_from_civil(i64::from(year), month, day) * 86_400
        + i64::from(hour * 3600 + minute * 60);
    Some(local - sign * i64::from(zh * 3600 + zm * 60))
}

/// The normalized catalog, or `None` when nothing changes.
#[must_use]
pub fn normalize(data: &[u8], time: i64) -> Option<Vec<u8>> {
    let (start, len) = header(data)?;
    let text = data.get(start..start.checked_add(len)?)?;
    let mut line_start = 0;
    let (value_start, value) = loop {
        let line_end = text
            .get(line_start..)?
            .iter()
            .position(|&b| b == b'\n')
            .map_or(text.len(), |n| line_start.saturating_add(n));
        let line = text.get(line_start..line_end)?;
        if let Some(v) = line
            .strip_prefix(b"POT-Creation-Date: ")
            .or_else(|| line.strip_prefix(b"PO-Revision-Date: "))
        {
            break (line_end.saturating_sub(v.len()), v);
        }
        if line_end >= text.len() {
            return None;
        }
        line_start = line_end.saturating_add(1);
    };
    if parse(value)? <= time {
        return None;
    }
    let u = Utc::from_unix(time);
    let new = format!(
        "{}-{:02}-{:02} {:02}:{:02}+0000",
        u.year, u.month, u.day, u.hour, u.minute
    );
    // as strip-nondeterminism, a date of another length (a year before 1000) is not
    // written
    if new.len() != value.len() {
        return None;
    }
    let at = start.saturating_add(value_start);
    let mut out = data.to_vec();
    out.get_mut(at..at.saturating_add(new.len()))?
        .copy_from_slice(new.as_bytes());
    Some(out)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    const T: i64 = 1_767_225_600;

    /// A little-endian catalog of `entries` (original, translation).
    fn mo(entries: &[(&str, &str)], revision: u32) -> Vec<u8> {
        let n = u32::try_from(entries.len()).unwrap();
        let (ot, tt) = (28, 28 + 8 * n);
        let mut off = tt + 8 * n;
        let mut v = Vec::new();
        for w in [0x9504_12de, revision, n, ot, tt, 0, off] {
            v.extend_from_slice(&u32::to_le_bytes(w));
        }
        let mut strings = Vec::new();
        let mut tables = [Vec::new(), Vec::new()];
        for (i, table) in tables.iter_mut().enumerate() {
            for e in entries {
                let s = if i == 0 { e.0 } else { e.1 };
                let len = u32::try_from(s.len()).unwrap();
                table.extend_from_slice(&len.to_le_bytes());
                table.extend_from_slice(&off.to_le_bytes());
                strings.extend_from_slice(s.as_bytes());
                strings.push(0);
                off += len + 1;
            }
        }
        v.extend(tables.concat());
        v.extend(strings);
        v
    }

    #[test]
    fn first_date_line_clamped() {
        let hdr = |pot: &str, rev: &str| {
            format!("Project-Id-Version: x\nPOT-Creation-Date: {pot}\nPO-Revision-Date: {rev}\n")
        };
        let input = mo(
            &[
                ("", &hdr("2030-01-02 03:04+0100", "2030-01-02 03:04+0100")),
                ("a", "b"),
            ],
            0,
        );
        let want = mo(
            &[
                ("", &hdr("2026-01-01 00:00+0000", "2030-01-02 03:04+0100")),
                ("a", "b"),
            ],
            0,
        );
        assert_eq!(normalize(&input, T), Some(want));
        // earlier dates, with their zone, stay
        let old = mo(&[("", &hdr("2026-01-01 00:30+0100", "x"))], 0);
        assert_eq!(normalize(&old, T), None);
        let late = mo(&[("", &hdr("2025-12-31 23:30-0100", "x"))], 0);
        assert!(normalize(&late, T).is_some());
        // only the first date line counts, whichever field it is
        let rev_first = mo(
            &[(
                "",
                "PO-Revision-Date: 2020-01-01 00:00+0000\nPOT-Creation-Date: 2030-01-01 00:00+0000\n",
            )],
            0,
        );
        assert_eq!(normalize(&rev_first, T), None);
    }

    #[test]
    fn left_alone() {
        let date = "POT-Creation-Date: 2030-01-02 03:04+0100\n";
        assert_eq!(normalize(&mo(&[("", date)], 0x1_0000), T), None);
        assert_eq!(normalize(&mo(&[("a", date)], 0), T), None);
        for bad in [
            "POT-Creation-Date: 2030-01-02 03:04+0100 x\n",
            "POT-Creation-Date: 2030-01-02 03:04\n",
            "POT-Creation-Date:  2030-01-02 03:04+0100\n",
            "X: POT-Creation-Date: 2030-01-02 03:04+0100\n",
            "POT-Creation-Date: 2030-01-02 03:04+0100\r\n",
        ] {
            assert_eq!(normalize(&mo(&[("", bad)], 0), T), None, "{bad}");
        }
    }
}
