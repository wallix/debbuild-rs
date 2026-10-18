//! deb822 stanzas (control files, the dpkg status file), as dpkg reads and writes them.

use indexmap::IndexMap;

use crate::error::{Error, Result};
use crate::py;

/// A stanza: field name -> value. Insertion order is kept (it is observable).
pub type Stanza = IndexMap<String, String>;

/// Field order of a status file entry, as dpkg writes it; other fields follow in their
/// control file order.
pub const STATUS_FIELD_ORDER: [&str; 28] = [
    "Package",
    "Essential",
    "Protected",
    "Status",
    "Priority",
    "Section",
    "Installed-Size",
    "Origin",
    "Maintainer",
    "Bugs",
    "Architecture",
    "Multi-Arch",
    "Source",
    "Version",
    "Config-Version",
    "Replaces",
    "Provides",
    "Depends",
    "Pre-Depends",
    "Recommends",
    "Suggests",
    "Breaks",
    "Conflicts",
    "Enhances",
    "Conffiles",
    "Description",
    "Triggers-Pending",
    "Triggers-Awaited",
];

/// dpkg matches field names case-insensitively: the known fields get their usual spelling.
fn canonical(name: &str) -> String {
    let lower = name.to_lowercase();
    STATUS_FIELD_ORDER
        .iter()
        .find(|k| k.to_lowercase() == lower)
        .map_or_else(|| name.to_owned(), |k| (*k).to_owned())
}

/// Parse deb822 stanzas. Values keep their continuation lines; as with dpkg, only the
/// whitespace ending the whole value goes (a first line followed by continuation lines
/// keeps its trailing spaces).
///
/// # Errors
/// A continuation line before any field, or a line that is not a field.
pub fn parse_stanzas(text: &str) -> Result<Vec<Stanza>> {
    fn end(stanzas: &mut Vec<Stanza>, cur: Stanza) {
        if !cur.is_empty() {
            stanzas.push(
                cur.into_iter()
                    .map(|(k, v)| (k, py::rstrip_str(&v).to_owned()))
                    .collect(),
            );
        }
    }
    let mut stanzas = Vec::new();
    let mut cur = Stanza::new();
    let mut key: Option<String> = None;
    for line in py::splitlines_str(text) {
        if py::is_blank(line.as_bytes()) {
            end(&mut stanzas, std::mem::take(&mut cur));
            key = None;
        } else if line.starts_with([' ', '\t']) {
            let value = key.as_ref().and_then(|k| cur.get_mut(k)).ok_or_else(|| {
                Error::new(format!(
                    "continuation line without field: {}",
                    py::repr_str(line)
                ))
            })?;
            value.push('\n');
            value.push_str(line);
        } else {
            let (name, value) = line
                .split_once(':')
                .filter(|(name, _)| !name.is_empty() && !name.chars().any(py::is_space))
                .ok_or_else(|| {
                    Error::new(format!("malformed field line: {}", py::repr_str(line)))
                })?;
            let k = canonical(name);
            cur.insert(k.clone(), value.trim_start_matches([' ', '\t']).to_owned());
            key = Some(k);
        }
    }
    end(&mut stanzas, cur);
    Ok(stanzas)
}

/// A stanza as dpkg writes it in the status file: the known fields first, in dpkg's
/// order, then the others in insertion order; ends with a newline.
#[must_use]
pub fn format_stanza(stanza: &Stanza) -> String {
    let known = STATUS_FIELD_ORDER
        .iter()
        .filter_map(|k| stanza.get_key_value(*k));
    let others = stanza
        .iter()
        .filter(|(k, _)| !STATUS_FIELD_ORDER.contains(&k.as_str()));
    let mut out = String::new();
    for (k, v) in known.chain(others) {
        out.push_str(k);
        out.push(':');
        if !(v.is_empty() || v.starts_with('\n')) {
            out.push(' ');
        }
        out.push_str(v);
        out.push('\n');
    }
    out
}

/// The package state in a status entry (installed, unpacked, ...): the last word of
/// its Status field.
#[must_use]
pub fn state_of(s: Option<&Stanza>) -> &str {
    s.and_then(|s| s.get("Status"))
        .and_then(|v| py::split_ws_str(v).last().copied())
        .unwrap_or("not-installed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stanza(fields: &[(&str, &str)]) -> Stanza {
        fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn parse_stanzas_cases() {
        let s = parse_stanzas(
            "package: foo\nVERSION: 1.0  \nX-Custom: y\nDescription: x \n more  \n\n",
        )
        .unwrap();
        assert_eq!(
            s,
            vec![stanza(&[
                ("Package", "foo"),
                ("Version", "1.0"),
                ("X-Custom", "y"),
                ("Description", "x \n more")
            ])]
        );
        for (bad, msg) in [
            ("Package foo\n", "malformed field line: 'Package foo'"),
            (" cont\n", "continuation line without field: ' cont'"),
            (": x\n", "malformed field line: ': x'"),
        ] {
            assert_eq!(parse_stanzas(bad).unwrap_err().message(), msg, "{bad}");
        }
    }

    #[test]
    fn parse_stanzas_blank_lines_and_duplicates() {
        let s = parse_stanzas("\n \nA: 1\nB: 2\nA: 3\n \t\nC:\n").unwrap();
        assert_eq!(
            s,
            vec![stanza(&[("A", "3"), ("B", "2")]), stanza(&[("C", "")])]
        );
        // a '#' line is not a comment
        assert!(parse_stanzas("# x\n").is_err());
        assert_eq!(
            parse_stanzas("#x: 1\n").unwrap(),
            vec![stanza(&[("#x", "1")])]
        );
    }

    #[test]
    fn format_round_trip() {
        let text = "Package: p\nStatus: install ok installed\nVersion: 1\nConffiles:\n /etc/c 0123 obsolete\nDescription: d\n more\nX-B: 2\nX-A: \n";
        let s = parse_stanzas(text).unwrap();
        // X-A's value is empty: "X-A:" without a space
        assert_eq!(
            format_stanza(&s[0]),
            "Package: p\nStatus: install ok installed\nVersion: 1\nConffiles:\n /etc/c 0123 obsolete\nDescription: d\n more\nX-B: 2\nX-A:\n"
        );
        let unordered = stanza(&[
            ("X-Z", "z"),
            ("Version", "1"),
            ("Package", "p"),
            ("Depends", "a"),
        ]);
        assert_eq!(
            format_stanza(&unordered),
            "Package: p\nVersion: 1\nDepends: a\nX-Z: z\n"
        );
    }

    #[test]
    fn states() {
        assert_eq!(state_of(None), "not-installed");
        assert_eq!(state_of(Some(&stanza(&[("Status", "")]))), "not-installed");
        assert_eq!(
            state_of(Some(&stanza(&[("Status", "install ok half-configured")]))),
            "half-configured"
        );
    }
}
