//! UTC calendar arithmetic for the timestamps the handlers write and read.
//!
//! Dates are those of the proleptic Gregorian calendar, before the year 1 too: a
//! difference from strip-nondeterminism, which writes wrong dates there.

/// A UTC date and time, to the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utc {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

/// Days since 1970-01-01 of a proleptic Gregorian date (month 1..=12).
#[must_use]
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 {
        year.saturating_sub(1)
    } else {
        year
    };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(month);
    let mp = if m > 2 {
        m.saturating_sub(3)
    } else {
        m.saturating_add(9)
    };
    let doy = (153_i64.saturating_mul(mp).saturating_add(2) / 5)
        .saturating_add(i64::from(day))
        .saturating_sub(1);
    let doe = yoe
        .saturating_mul(365)
        .saturating_add(yoe / 4)
        .saturating_sub(yoe / 100)
        .saturating_add(doy);
    era.saturating_mul(146_097)
        .saturating_add(doe)
        .saturating_sub(719_468)
}

impl Utc {
    /// The UTC breakdown of `t`, in seconds since the epoch.
    #[must_use]
    pub fn from_unix(t: i64) -> Self {
        let days = t.div_euclid(86_400);
        let secs = t.rem_euclid(86_400);
        let z = days.saturating_add(719_468);
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = doe
            .saturating_sub(doe / 1460)
            .saturating_add(doe / 36_524)
            .saturating_sub(doe / 146_096)
            / 365;
        let doy = doe.saturating_sub(
            yoe.saturating_mul(365)
                .saturating_add(yoe / 4)
                .saturating_sub(yoe / 100),
        );
        let mp = doy.saturating_mul(5).saturating_add(2) / 153;
        let day = doy
            .saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5)
            .saturating_add(1);
        let month = if mp < 10 {
            mp.saturating_add(3)
        } else {
            mp.saturating_sub(9)
        };
        let year = yoe
            .saturating_add(era.saturating_mul(400))
            .saturating_add(i64::from(month <= 2));
        let small = |n: i64| u32::try_from(n).unwrap_or(0);
        Self {
            year,
            month: small(month),
            day: small(day),
            hour: small(secs / 3600),
            minute: small(secs % 3600 / 60),
            second: small(secs % 60),
        }
    }

    /// Seconds since the epoch.
    #[cfg(test)]
    #[allow(clippy::arithmetic_side_effects)] // bounded calendar arithmetic
    #[must_use]
    pub fn to_unix(self) -> i64 {
        days_from_civil(self.year, self.month, self.day) * 86_400
            + i64::from(self.hour * 3600 + self.minute * 60 + self.second)
    }

    /// The MS-DOS time and date words of zip headers (two-second resolution, years
    /// before 1980 as 1980, later ones modulo 128 years from 1980).
    #[must_use]
    pub fn dos(&self) -> (u16, u16) {
        let year = u16::try_from(self.year.max(1980).saturating_sub(1980) & 0x7f).unwrap_or(0);
        let w = |n: u32| u16::try_from(n).unwrap_or(0);
        let time = (w(self.hour) << 11) | (w(self.minute) << 5) | (w(self.second) >> 1);
        let date = (year << 9) | (w(self.month) << 5) | w(self.day);
        (time, date)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for t in [
            0,
            951_782_400,
            1_767_225_600,
            1_767_225_599,
            4_102_444_800,
            -1,
        ] {
            assert_eq!(Utc::from_unix(t).to_unix(), t);
        }
        assert_eq!(
            Utc::from_unix(1_767_225_600),
            Utc {
                year: 2026,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0
            }
        );
        assert_eq!(Utc::from_unix(951_782_400).month, 2);
        assert_eq!(Utc::from_unix(951_782_400).day, 29);
    }

    #[test]
    fn dos_words() {
        // 2026-01-01 00:00:00 and 2025-12-31 23:59:58, as strip-nondeterminism writes them
        assert_eq!(Utc::from_unix(1_767_225_600).dos(), (0x0000, 0x5c21));
        assert_eq!(Utc::from_unix(1_767_225_598).dos(), (0xbf7d, 0x5b9f));
        // 2108-01-01 and 2286-11-20 17:46:39 wrap around
        assert_eq!(Utc::from_unix(4_354_819_200).dos(), (0, 0x21));
        assert_eq!(Utc::from_unix(9_999_999_999).dos(), (0x8dd3, 0x6574));
    }
}
