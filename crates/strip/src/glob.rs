//! Shell glob patterns matched against file names (`--exclude`): `*` any run of bytes,
//! `?` one byte, `[...]` one of a set (ranges `a-z`, negated by a leading `!` or `^`, a
//! leading `]` or a trailing `-` meaning themselves), `\` quoting the next byte. A `[`
//! without its `]` matches itself. Bytes, not characters: patterns and names are
//! matched as they are, `/` and a leading `.` included.

/// Whether `name` matches the glob `pattern`.
#[must_use]
pub fn matches(pattern: &[u8], name: &[u8]) -> bool {
    // the position after the last `*`, and the name position it was tried at
    let (mut p, mut n) = (0_usize, 0_usize);
    let mut star: Option<(usize, usize)> = None;
    loop {
        if let Some(&c) = pattern.get(p) {
            match c {
                b'*' => {
                    p = p.saturating_add(1);
                    star = Some((p, n));
                    continue;
                }
                _ => {
                    if let Some((len, ok)) = one(pattern, p, name.get(n).copied())
                        && ok
                    {
                        p = p.saturating_add(len);
                        n = n.saturating_add(1);
                        continue;
                    }
                }
            }
        } else if n == name.len() {
            return true;
        }
        // backtrack: the last `*` takes one more byte
        match star {
            Some((sp, sn)) if sn < name.len() => {
                let sn = sn.saturating_add(1);
                star = Some((sp, sn));
                p = sp;
                n = sn;
            }
            _ => return false,
        }
    }
}

/// The length of the pattern item at `p` (not `*`), and whether it matches `byte`.
fn one(pattern: &[u8], p: usize, byte: Option<u8>) -> Option<(usize, bool)> {
    let c = *pattern.get(p)?;
    match c {
        b'?' => Some((1, byte.is_some())),
        b'\\' => match pattern.get(p.saturating_add(1)) {
            Some(&q) => Some((2, byte == Some(q))),
            None => Some((1, byte == Some(b'\\'))),
        },
        b'[' => match class(pattern, p.saturating_add(1), byte?) {
            Some((len, ok)) => Some((len.saturating_add(1), ok)),
            None => Some((1, byte == Some(b'['))),
        },
        _ => Some((1, byte == Some(c))),
    }
}

/// The set starting at `p` (after `[`): its length with the `]`, and whether `byte` is
/// in it; `None` when it has no `]`.
fn class(pattern: &[u8], p: usize, byte: u8) -> Option<(usize, bool)> {
    let mut i = p;
    let negated = matches!(pattern.get(i), Some(b'!' | b'^'));
    if negated {
        i = i.saturating_add(1);
    }
    let mut found = false;
    let mut first = true;
    loop {
        let c = *pattern.get(i)?;
        if c == b']' && !first {
            let len = i.saturating_add(1).saturating_sub(p);
            return Some((len, found != negated));
        }
        first = false;
        let (lo, next) = if c == b'\\' {
            (*pattern.get(i.saturating_add(1))?, i.saturating_add(2))
        } else {
            (c, i.saturating_add(1))
        };
        if pattern.get(next) == Some(&b'-')
            && let Some(&hi) = pattern.get(next.saturating_add(1))
            && hi != b']'
        {
            found |= (lo..=hi).contains(&byte);
            i = next.saturating_add(2);
        } else {
            found |= lo == byte;
            i = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        for (pattern, name, want) in [
            ("*", "", true),
            ("*", "abc", true),
            ("*.pyc", "a.pyc", true),
            ("*.pyc", "a.pyc.x", false),
            ("a*b*c", "aXbYc", true),
            ("a*b*c", "aXbY", false),
            ("?", "a", true),
            ("?", "", false),
            ("??", "a", false),
            ("[abc]", "b", true),
            ("[abc]", "d", false),
            ("[a-c]x", "bx", true),
            ("[!a-c]", "d", true),
            ("[^a-c]", "a", false),
            ("[]]", "]", true),
            ("[a-]", "-", true),
            ("[", "[", true),
            ("[ab", "[ab", true),
            ("\\*", "*", true),
            ("\\*", "a", false),
            ("*.[ch]", "x.h", true),
            ("lib*.so.*", "libz.so.1", true),
            (".*", ".hidden", true),
            ("*", ".hidden", true),
            ("**x", "abx", true),
        ] {
            assert_eq!(
                matches(pattern.as_bytes(), name.as_bytes()),
                want,
                "{pattern} {name}"
            );
        }
    }
}
