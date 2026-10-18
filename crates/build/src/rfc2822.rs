//! `date -R -u -d @EPOCH`.

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian (Howard Hinnant's
/// `civil_from_days`).
#[allow(clippy::arithmetic_side_effects)] // bounded calendar arithmetic
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// The UTC date of `epoch` in RFC 2822 format: `Thu, 01 Jan 2026 00:00:00 +0000`.
#[must_use]
#[allow(clippy::arithmetic_side_effects)] // bounded calendar arithmetic
pub fn format(epoch: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let wday = DAYS
        .get(usize::try_from(days.rem_euclid(7)).unwrap_or(0))
        .unwrap_or(&"Thu");
    let month = MONTHS
        .get(usize::try_from(m - 1).unwrap_or(0))
        .unwrap_or(&"Jan");
    format!(
        "{wday}, {d:02} {month} {y} {:02}:{:02}:{:02} +0000",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(format(1_767_225_600), "Thu, 01 Jan 2026 00:00:00 +0000");
        assert_eq!(format(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(format(951_782_400), "Tue, 29 Feb 2000 00:00:00 +0000");
        assert_eq!(format(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 +0000");
    }
}
