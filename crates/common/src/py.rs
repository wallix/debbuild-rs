//! Python's string semantics where the original implementation relied on them.
//!
//! The installer was first written in Python, and its file formats inherit
//! `str.splitlines()`, `str.split()`, `str.strip()` and `repr()`: they split and strip
//! on more than ASCII whitespace. These helpers work on bytes (UTF-8 text, possibly
//! with invalid sequences, which are never whitespace), so that they also cover the
//! files Python read with `surrogateescape`.

/// Length of the line break at `b[i..]`, as `str.splitlines()` sees one (0: none).
fn line_break_len(b: &[u8], i: usize) -> usize {
    match b.get(i..).unwrap_or_default() {
        [b'\r', b'\n', ..] | [0xc2, 0x85, ..] => 2,
        [b'\n' | b'\r' | 0x0b | 0x0c | 0x1c | 0x1d | 0x1e, ..] => 1,
        [0xe2, 0x80, 0xa8 | 0xa9, ..] => 3,
        _ => 0,
    }
}

/// Length of the whitespace character at `b[i..]`, as `str.isspace()` sees one (0: none).
fn space_len(b: &[u8], i: usize) -> usize {
    match b.get(i..).unwrap_or_default() {
        [b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | 0x1c..=0x1f | b' ', ..] => 1,
        [0xc2, 0x85 | 0xa0, ..] => 2,
        [0xe1, 0x9a, 0x80, ..]
        | [0xe2, 0x80, 0x80..=0x8a | 0xa8 | 0xa9 | 0xaf, ..]
        | [0xe2, 0x81, 0x9f, ..]
        | [0xe3, 0x80, 0x80, ..] => 3,
        _ => 0,
    }
}

/// Whether `c` is whitespace for Python's `str.isspace()`.
#[must_use]
pub fn is_space(c: char) -> bool {
    let mut buf = [0; 4];
    let s = c.encode_utf8(&mut buf);
    space_len(s.as_bytes(), 0) == s.len()
}

/// `bytes.decode(errors="surrogateescape").splitlines()`, on bytes.
#[must_use]
pub fn splitlines(b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        let n = line_break_len(b, i);
        if n == 0 {
            i = i.saturating_add(1);
        } else {
            out.push(b.get(start..i).unwrap_or_default());
            i = i.saturating_add(n);
            start = i;
        }
    }
    if start < b.len() {
        out.push(b.get(start..).unwrap_or_default());
    }
    out
}

/// `str.splitlines()`.
#[must_use]
pub fn splitlines_str(s: &str) -> Vec<&str> {
    // The breaks are whole characters, so the pieces are valid UTF-8.
    splitlines(s.as_bytes())
        .into_iter()
        .map(|l| std::str::from_utf8(l).unwrap_or_default())
        .collect()
}

/// `str.split(maxsplit=max)` (`None`: no limit), on bytes.
#[must_use]
pub fn split_ws_n(b: &[u8], max: Option<usize>) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        while i < b.len() && space_len(b, i) > 0 {
            i = i.saturating_add(space_len(b, i));
        }
        if i >= b.len() {
            return out;
        }
        if max.is_some_and(|m| out.len() >= m) {
            out.push(b.get(i..).unwrap_or_default());
            return out;
        }
        let start = i;
        while i < b.len() && space_len(b, i) == 0 {
            i = i.saturating_add(1);
        }
        out.push(b.get(start..i).unwrap_or_default());
    }
}

/// `str.split()`, on bytes.
#[must_use]
pub fn split_ws(b: &[u8]) -> Vec<&[u8]> {
    split_ws_n(b, None)
}

/// `str.split()`.
#[must_use]
pub fn split_ws_str(s: &str) -> Vec<&str> {
    split_ws(s.as_bytes())
        .into_iter()
        .map(|w| std::str::from_utf8(w).unwrap_or_default())
        .collect()
}

/// `str.lstrip()`, on bytes.
#[must_use]
pub fn lstrip(b: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < b.len() && space_len(b, i) > 0 {
        i = i.saturating_add(space_len(b, i));
    }
    b.get(i..).unwrap_or_default()
}

/// `str.rstrip()`, on bytes.
#[must_use]
pub fn rstrip(b: &[u8]) -> &[u8] {
    // Scan forward: whitespace characters are recognized from their first byte.
    let mut end = 0;
    let mut i = 0;
    while i < b.len() {
        let n = space_len(b, i);
        if n == 0 {
            i = i.saturating_add(1);
            end = i;
        } else {
            i = i.saturating_add(n);
        }
    }
    b.get(..end).unwrap_or_default()
}

/// `str.strip()`, on bytes.
#[must_use]
pub fn strip(b: &[u8]) -> &[u8] {
    rstrip(lstrip(b))
}

/// `str.strip()`.
#[must_use]
pub fn strip_str(s: &str) -> &str {
    std::str::from_utf8(strip(s.as_bytes())).unwrap_or_default()
}

/// `str.rstrip()`.
#[must_use]
pub fn rstrip_str(s: &str) -> &str {
    std::str::from_utf8(rstrip(s.as_bytes())).unwrap_or_default()
}

/// `str.isspace()` over the whole string, `True` for an empty one too (`not s.strip()`).
#[must_use]
pub fn is_blank(b: &[u8]) -> bool {
    strip(b).is_empty()
}

fn is_printable(c: char) -> bool {
    // Python's str.isprintable(): no control, format, separator (but space), private
    // use or unassigned character. Approximated for the characters paths and control
    // data can reasonably hold.
    !matches!(c,
        '\0'..='\x1f' | '\x7f'..='\u{a0}' | '\u{ad}' | '\u{1680}' | '\u{2000}'..='\u{200f}'
        | '\u{2028}'..='\u{202f}' | '\u{205f}'..='\u{206f}' | '\u{3000}' | '\u{feff}'
        | '\u{e000}'..='\u{f8ff}' | '\u{fff9}'..='\u{fffb}')
}

/// `repr()` of the string Python decodes from `b` with `surrogateescape`.
#[must_use]
pub fn repr(b: &[u8]) -> String {
    // Writing to a String cannot fail.
    use std::fmt::Write as _;
    let mut chars: Vec<Result<char, u8>> = Vec::new();
    for chunk in b.utf8_chunks() {
        chars.extend(chunk.valid().chars().map(Ok));
        chars.extend(chunk.invalid().iter().map(|&x| Err(x)));
    }
    let quote = if chars.contains(&Ok('\'')) && !chars.contains(&Ok('"')) {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for c in chars {
        match c {
            Err(x) => {
                let _ = write!(out, "\\udc{x:02x}");
            }
            Ok(c) if c == quote || c == '\\' => {
                out.push('\\');
                out.push(c);
            }
            Ok('\t') => out.push_str("\\t"),
            Ok('\n') => out.push_str("\\n"),
            Ok('\r') => out.push_str("\\r"),
            Ok(c) if is_printable(c) => out.push(c),
            Ok(c) => {
                let n = u32::from(c);
                if n < 0x100 {
                    let _ = write!(out, "\\x{n:02x}");
                } else if n < 0x10000 {
                    let _ = write!(out, "\\u{n:04x}");
                } else {
                    let _ = write!(out, "\\U{n:08x}");
                }
            }
        }
    }
    out.push(quote);
    out
}

/// `repr()` of a `str`.
#[must_use]
pub fn repr_str(s: &str) -> String {
    repr(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitlines_like_python() {
        assert_eq!(
            splitlines(b"a\nb\r\nc\rd\x0be\x1cf\xc2\x85g\n\n"),
            vec![&b"a"[..], b"b", b"c", b"d", b"e", b"f", b"g", b""]
        );
        assert_eq!(splitlines(b""), Vec::<&[u8]>::new());
        assert_eq!(splitlines(b"x"), vec![&b"x"[..]]);
        // an invalid byte is not a break
        assert_eq!(splitlines(b"a\x85b"), vec![&b"a\x85b"[..]]);
    }

    #[test]
    fn split_like_python() {
        assert_eq!(split_ws(b"  a \t b\x1fc  "), vec![&b"a"[..], b"b", b"c"]);
        assert_eq!(
            split_ws_n(b" a  b  c d ", Some(1)),
            vec![&b"a"[..], b"b  c d "]
        );
        assert_eq!(
            split_ws_n(b"a b c d", Some(3)),
            vec![&b"a"[..], b"b", b"c", b"d"]
        );
        assert_eq!(
            split_ws_n(b"a b c d e", Some(3)),
            vec![&b"a"[..], b"b", b"c", b"d e"]
        );
        assert_eq!(split_ws(b"\xc2\xa0x\xe3\x80\x80"), vec![&b"x"[..]]);
    }

    #[test]
    fn strip_like_python() {
        assert_eq!(strip(b" \tx y \n"), b"x y");
        assert_eq!(rstrip(b"x \n more  "), b"x \n more");
        assert_eq!(lstrip(b"  "), b"");
        assert!(is_space('\u{1c}'));
        assert!(!is_space('x'));
    }

    #[test]
    fn repr_like_python() {
        assert_eq!(repr(b"Package foo"), "'Package foo'");
        assert_eq!(repr(b"it's"), "\"it's\"");
        assert_eq!(repr(b"a'\"b"), "'a\\'\"b'");
        assert_eq!(repr(b" cont\t\x01\xff\\"), "' cont\\t\\x01\\udcff\\\\'");
        assert_eq!(repr("\u{e9}\u{2028}".as_bytes()), "'\u{e9}\\u2028'");
    }
}
