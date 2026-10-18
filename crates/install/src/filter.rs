//! dpkg's path filters: the `path-exclude` and `path-include` options of the root's dpkg
//! configuration (/etc/dpkg/dpkg.cfg.d/*, then /etc/dpkg/dpkg.cfg), which keep matching
//! archive members from being unpacked. Debian's container images exclude
//! /usr/share/doc/* that way.

use std::fs;
use std::io;
use std::path::Path;

use debbuild_rs_common::{IoContext, Result};

/// The filters, in the order dpkg reads them: the last one matching a path decides.
#[derive(Debug, Default)]
pub struct Filters(Vec<(Vec<u8>, bool)>);

impl Filters {
    /// The filters of `root`'s dpkg configuration (the configuration files of `dpkg`
    /// itself; ~/.dpkg.cfg, which is the caller's, is not read).
    ///
    /// # Errors
    /// A configuration file or directory cannot be read.
    pub fn load(root: &Path) -> Result<Self> {
        let mut filters = Self::default();
        let dir = root.join("etc/dpkg/dpkg.cfg.d");
        let mut names = Vec::new();
        match fs::read_dir(&dir) {
            Ok(entries) => {
                for e in entries {
                    names.push(e.at(&dir)?.file_name());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).at(&dir),
        }
        // dpkg's scandir filter: no dot files, only [A-Za-z0-9_-] names; sorted bytewise.
        names.retain(|n| {
            let n = n.as_encoded_bytes();
            n.first() != Some(&b'.')
                && n.iter()
                    .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
        });
        names.sort();
        for n in names {
            filters.read(&dir.join(n))?;
        }
        filters.read(&root.join("etc/dpkg/dpkg.cfg"))?;
        Ok(filters)
    }

    fn read(&mut self, file: &Path) -> Result<()> {
        let text = match fs::read(file) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).at(file),
        };
        for line in text.split(|&c| c == b'\n') {
            if let Some(f) = parse_line(line) {
                self.0.push(f);
            }
        }
        Ok(())
    }

    /// Whether dpkg skips the archive member `path` (absolute, without a trailing
    /// slash). A directory or a symlink a filter excludes is kept when an include
    /// pattern's fixed prefix starts with its path: something under it may be included.
    #[must_use]
    pub fn skip(&self, path: &[u8], dir_or_symlink: bool) -> bool {
        let mut skip = false;
        for (pattern, include) in &self.0 {
            if fnmatch(pattern, path) {
                skip = !include;
            }
        }
        if skip && dir_or_symlink {
            for (pattern, include) in &self.0 {
                if !include {
                    continue;
                }
                let mut fixed = pattern
                    .iter()
                    .position(|c| b"*?[\\".contains(c))
                    .map_or(pattern.as_slice(), |i| pattern.get(..i).unwrap_or_default());
                while let Some(f) = fixed.strip_suffix(b"/") {
                    fixed = f;
                }
                // dpkg's strncmp(path, pattern, len(fixed)) == 0
                if path.starts_with(fixed) {
                    return false;
                }
            }
        }
        skip
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A `path-exclude`/`path-include` line of a dpkg configuration file, as dpkg parses
/// it: `name value` or `name=value`, the value possibly quoted.
fn parse_line(line: &[u8]) -> Option<(Vec<u8>, bool)> {
    let line = line.trim_ascii_end();
    if line.first().is_none_or(|&c| c == b'#') {
        return None;
    }
    let name_len = line
        .iter()
        .position(|c| !(c.is_ascii_alphanumeric() || *c == b'-'))
        .unwrap_or(line.len());
    let (name, rest) = line.split_at(name_len);
    let include = match name {
        b"path-exclude" => false,
        b"path-include" => true,
        _ => return None,
    };
    let rest = rest.get(1..)?;
    let rest = rest.strip_prefix(b"=").unwrap_or(rest).trim_ascii_start();
    let value = match rest.first() {
        Some(&q @ (b'"' | b'\'')) => rest.strip_prefix(&[q])?.strip_suffix(&[q])?,
        _ => rest,
    };
    (!value.is_empty()).then(|| (value.to_vec(), include))
}

/// `fnmatch(pattern, string, 0)`: `*` and `?` match `/` and leading dots too.
#[must_use]
pub fn fnmatch(pattern: &[u8], string: &[u8]) -> bool {
    // The position after the last `*` and the string position it is retried from.
    let mut star: Option<(usize, usize)> = None;
    let (mut p, mut s) = (0, 0);
    loop {
        if let Some(&pc) = pattern.get(p) {
            match pc {
                b'*' => {
                    p = p.saturating_add(1);
                    star = Some((p, s));
                    continue;
                }
                b'?' if s < string.len() => {
                    p = p.saturating_add(1);
                    s = s.saturating_add(1);
                    continue;
                }
                b'[' => {
                    if let Some(&c) = string.get(s)
                        && let Some((matched, next)) = bracket(pattern, p, c)
                    {
                        if matched {
                            p = next;
                            s = s.saturating_add(1);
                            continue;
                        }
                    } else if string.get(s) == Some(&b'[') {
                        // An unclosed bracket is a literal `[`.
                        p = p.saturating_add(1);
                        s = s.saturating_add(1);
                        continue;
                    }
                }
                b'\\' => {
                    let lit = pattern.get(p.saturating_add(1)).copied().unwrap_or(b'\\');
                    if string.get(s) == Some(&lit) {
                        p = p.saturating_add(if pattern.get(p.saturating_add(1)).is_some() {
                            2
                        } else {
                            1
                        });
                        s = s.saturating_add(1);
                        continue;
                    }
                }
                c if string.get(s) == Some(&c) => {
                    p = p.saturating_add(1);
                    s = s.saturating_add(1);
                    continue;
                }
                _ => {}
            }
        } else if s == string.len() {
            return true;
        }
        // Mismatch: let the last `*` take one more character.
        match star {
            Some((sp, ss)) if ss < string.len() => {
                star = Some((sp, ss.saturating_add(1)));
                p = sp;
                s = ss.saturating_add(1);
            }
            _ => return false,
        }
    }
}

/// The bracket expression at `pattern[p]` (`[`) against `c`: whether it matches, and the
/// position after it; `None` when it is not closed.
fn bracket(pattern: &[u8], p: usize, c: u8) -> Option<(bool, usize)> {
    let mut i = p.saturating_add(1);
    let negate = matches!(pattern.get(i), Some(b'!' | b'^'));
    if negate {
        i = i.saturating_add(1);
    }
    let mut matched = false;
    let mut first = true;
    loop {
        let mut lo = *pattern.get(i)?;
        if lo == b']' && !first {
            return Some((matched != negate, i.saturating_add(1)));
        }
        first = false;
        if lo == b'\\' {
            i = i.saturating_add(1);
            lo = *pattern.get(i)?;
        }
        i = i.saturating_add(1);
        if pattern.get(i) == Some(&b'-')
            && pattern.get(i.saturating_add(1)).is_some_and(|&h| h != b']')
        {
            let mut hi_at = i.saturating_add(1);
            if pattern.get(hi_at) == Some(&b'\\') {
                hi_at = hi_at.saturating_add(1);
            }
            let hi = *pattern.get(hi_at)?;
            matched |= (lo..=hi).contains(&c);
            i = hi_at.saturating_add(1);
        } else {
            matched |= lo == c;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(fnmatch(b"/usr/share/doc/*", b"/usr/share/doc/a/b"));
        assert!(!fnmatch(b"/usr/share/doc/*", b"/usr/share/doc"));
        assert!(fnmatch(
            b"/usr/share/doc/*/copyright",
            b"/usr/share/doc/a/copyright"
        ));
        assert!(fnmatch(b"/a?c", b"/abc"));
        assert!(!fnmatch(b"/a?c", b"/ac"));
        assert!(fnmatch(b"/[a-c]x", b"/bx"));
        assert!(!fnmatch(b"/[!a-c]x", b"/bx"));
        assert!(fnmatch(b"/[]]", b"/]"));
        assert!(fnmatch(b"/\\*", b"/*"));
        assert!(!fnmatch(b"/\\*", b"/a"));
        assert!(fnmatch(b"/[x", b"/[x"));
        assert!(fnmatch(b"*.gz", b"/a/.b.gz"));
        assert!(fnmatch(b"", b""));
    }

    #[test]
    fn lines() {
        assert_eq!(
            parse_line(b"path-exclude /a/*"),
            Some((b"/a/*".to_vec(), false))
        );
        assert_eq!(
            parse_line(b"path-include=/a/b  "),
            Some((b"/a/b".to_vec(), true))
        );
        assert_eq!(
            parse_line(b"path-include = \"/a b\""),
            Some((b"/a b".to_vec(), true))
        );
        assert_eq!(parse_line(b"# path-exclude /a"), None);
        assert_eq!(parse_line(b"force-unsafe-io"), None);
    }

    #[test]
    fn last_match_and_directories() {
        let f = Filters(vec![
            (b"/usr/share/doc/*".to_vec(), false),
            (b"/usr/share/doc/*/copyright".to_vec(), true),
        ]);
        assert!(f.skip(b"/usr/share/doc/p/changelog.gz", false));
        assert!(!f.skip(b"/usr/share/doc/p/copyright", false));
        // kept: copyright files may be under it
        assert!(!f.skip(b"/usr/share/doc/p", true));
        assert!(!f.skip(b"/usr/share/doc", true));
        assert!(!f.skip(b"/usr/bin/p", false));
        let f = Filters(vec![(b"/usr/share/doc/*".to_vec(), false)]);
        assert!(f.skip(b"/usr/share/doc/p", true));
        assert!(f.skip(b"/usr/share/doc/p-link", true));
    }
}
