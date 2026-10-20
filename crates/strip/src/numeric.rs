//! Numbers read from the text fields of headers as strip-nondeterminism reads them: an
//! Numbers read from the text fields of headers as strip-nondeterminism reads them: an
//! integer with an optional radix prefix.
//!
//! Written from running strip-nondeterminism 1.13 (Debian 12) and 1.14 (Debian 13) on
//! crafted ar headers.

/// The integer at the start of `s`: after leading white space, `0x`/`x` starts a hexadecimal number,
/// `0b`/`b` a binary one, `0o`/`o` (or nothing) an octal one; the digits stop at the
/// first character that is not one, an underscore followed by a digit being skipped.
/// Saturates instead of overflowing.
#[must_use]
pub fn radix(s: &[u8]) -> u64 {
    let start = s.iter().position(|b| !is_space(*b)).unwrap_or(s.len());
    let s = s.get(start..).unwrap_or_default();
    let (radix, digits) = match s {
        [b'0', b'x' | b'X', rest @ ..] | [b'x' | b'X', rest @ ..] => (16, rest),
        [b'0', b'b' | b'B', rest @ ..] | [b'b' | b'B', rest @ ..] => (2, rest),
        [b'0', b'o' | b'O', rest @ ..] | [b'o' | b'O', rest @ ..] => (8, rest),
        _ => (8, s),
    };
    let digit = |b: u8| char::from(b).to_digit(radix).map(u64::from);
    let mut value = 0_u64;
    let mut i = 0;
    while let Some(&b) = digits.get(i) {
        let d = match (b, digits.get(i.saturating_add(1))) {
            (b'_', Some(&next)) if digit(next).is_some() => {
                i = i.saturating_add(1);
                digit(next)
            }
            _ => digit(b),
        };
        let Some(d) = d else { break };
        value = value.saturating_mul(u64::from(radix)).saturating_add(d);
        i = i.saturating_add(1);
    }
    value
}

/// The white space [`radix`] skips.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radix_forms() {
        for (s, v) in [
            (&b"100644  "[..], 0o100_644),
            (b"  644", 0o644),
            (b"\t100", 0o100),
            (b"0x40    ", 0x40),
            (b"x40", 0x40),
            (b"0b100000", 0b10_0000),
            (b"b1", 1),
            (b"0o100", 0o100),
            (b"o100", 0o100),
            (b"1_00", 0o100),
            (b"_100", 0o100),
            (b"100_ ", 0o100),
            (b"1__0", 1),
            (b"1006449 ", 0o100_644),
            (b"-100", 0),
            (b"abc", 0),
            (b"", 0),
        ] {
            assert_eq!(radix(s), v, "{}", String::from_utf8_lossy(s));
        }
    }
}
