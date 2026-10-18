//! Package relationships (Depends, Pre-Depends, Provides, Conflicts, Breaks, Replaces).

use crate::error::{Error, Result};
use crate::py;
use crate::version::{self, Op, version_satisfies};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relation {
    pub name: String,
    pub op: Option<Op>,
    pub version: Option<String>,
}

impl Relation {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            op: None,
            version: None,
        }
    }

    #[must_use]
    pub fn versioned(name: &str, op: Op, version: &str) -> Self {
        Self {
            name: name.to_owned(),
            op: Some(op),
            version: Some(version.to_owned()),
        }
    }

    /// Whether a package answering with `version` (`None`: an unversioned Provides)
    /// satisfies the relation.
    ///
    /// # Errors
    /// An invalid version.
    pub fn matches(&self, version: Option<&str>) -> Result<bool> {
        match (self.op, version) {
            (None, _) => Ok(true),
            (Some(_), None) => Ok(false),
            (Some(op), Some(v)) => version_satisfies(v, op, self.version.as_deref().unwrap_or("")),
        }
    }
}

/// `name` or `name (op version)`, as written in a control field.
impl std::fmt::Display for Relation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.op, &self.version) {
            (Some(op), Some(v)) => write!(f, "{} ({} {v})", self.name, op.as_str()),
            _ => f.write_str(&self.name),
        }
    }
}

/// Alternatives as written in a control field: `a | b (>= 1)`.
#[must_use]
pub fn show_alternatives(alts: &[Relation]) -> String {
    alts.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" | ")
}

/// dpkg's `pkg_name_is_illegal`: why `name` cannot be a package name.
#[must_use]
pub fn name_problem(name: &str) -> Option<String> {
    let Some(first) = name.chars().next() else {
        return Some("may not be empty string".to_owned());
    };
    if !first.is_ascii_alphanumeric() {
        return Some("must start with an alphanumeric character".to_owned());
    }
    name.chars()
        .find(|c| !c.is_ascii_alphanumeric() && !"-+._".contains(*c))
        .map(|c| {
            format!(
                "character '{c}' not allowed (only letters, digits and characters '-+._' allowed)"
            )
        })
}

/// dpkg's `dpkg_arch_name_is_illegal`: why `arch` cannot be an architecture name.
#[must_use]
pub fn arch_problem(arch: &str) -> Option<String> {
    let Some(first) = arch.chars().next() else {
        return Some("may not be empty string".to_owned());
    };
    if !first.is_ascii_alphanumeric() {
        return Some("must start with an alphanumeric".to_owned());
    }
    arch.chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '-')
        .map(|c| format!("character '{c}' not allowed (only letters, digits and characters '-')"))
}

/// C's `isspace` in the C locale.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// A relationship field, read as dpkg's `f_dependency` reads it.
struct Parser<'a> {
    s: &'a str,
    i: usize,
    rules: Rules,
    /// What the lax rules turned into warnings.
    warnings: Vec<String>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.as_bytes().get(self.i).copied()
    }

    /// The character at the cursor, for messages.
    fn char_at(&self) -> char {
        self.s
            .get(self.i..)
            .and_then(|r| r.chars().next())
            .unwrap_or_default()
    }

    fn bump(&mut self) {
        self.i = self.i.saturating_add(1);
    }

    fn skip_spaces(&mut self) {
        while self.peek().is_some_and(is_space) {
            self.bump();
        }
    }

    /// The text from the cursor up to the first byte `stop` matches.
    fn take_until(&mut self, stop: impl Fn(u8) -> bool) -> &str {
        let start = self.i;
        while self.peek().is_some_and(|c| !stop(c)) {
            self.bump();
        }
        self.s.get(start..self.i).unwrap_or_default()
    }

    /// One alternative: `name[:arch] [(op version)]`, and the whitespace after it.
    fn relation(&mut self) -> Result<Relation, String> {
        let name = self
            .take_until(|c| is_space(c) || matches!(c, b':' | b'(' | b',' | b'|'))
            .to_owned();
        if name.is_empty() {
            return Err("missing package name, or garbage where package name expected".to_owned());
        }
        if let Some(why) = name_problem(&name) {
            return Err(format!("invalid package name '{name}': {why}"));
        }
        // dpkg folds package names to lower case.
        let mut rel = Relation::new(&name.to_ascii_lowercase());
        if self.peek() == Some(b':') {
            self.bump();
            let arch = self.take_until(|c| is_space(c) || matches!(c, b'(' | b',' | b'|'));
            if arch.is_empty() {
                return Err(
                    "missing architecture name, or garbage where architecture name expected"
                        .to_owned(),
                );
            }
            if let Some(why) = arch_problem(arch) {
                return Err(format!(
                    "reference to '{name}': invalid architecture name '{arch}': {why}"
                ));
            }
        }
        self.skip_spaces();
        if self.peek() != Some(b'(') {
            return Ok(rel);
        }
        self.bump();
        self.skip_spaces();
        let op = match self.peek() {
            Some(c1 @ (b'<' | b'>')) => {
                self.bump();
                let (strict, or_equal, old) = if c1 == b'<' {
                    (Op::Lt, Op::Le, Op::OldLe)
                } else {
                    (Op::Gt, Op::Ge, Op::OldGe)
                };
                match self.peek() {
                    Some(b'=') => {
                        self.bump();
                        or_equal
                    }
                    Some(c2) if c2 == c1 => {
                        self.bump();
                        strict
                    }
                    Some(c2 @ (b'<' | b'>')) => {
                        return Err(format!(
                            "reference to '{name}': bad version relationship {}{}",
                            char::from(c1),
                            char::from(c2)
                        ));
                    }
                    _ => old,
                }
            }
            Some(b'=') => {
                self.bump();
                Op::Eq
            }
            // An implicit exact match.
            _ => Op::Eq,
        };
        self.skip_spaces();
        let version = self
            .take_until(|c| is_space(c) || matches!(c, b'(' | b')'))
            .to_owned();
        self.skip_spaces();
        match self.peek() {
            None => return Err(format!("reference to '{name}': version unterminated")),
            Some(b')') => self.bump(),
            Some(_) => {
                return Err(format!(
                    "reference to '{name}': version contains '{}' instead of ')'",
                    self.char_at()
                ));
            }
        }
        if let Some(why) = version::problem(&version) {
            let msg = format!("reference to '{name}': version '{version}': {why}");
            if !(self.rules.lax && version::is_warning(why)) {
                return Err(msg);
            }
            self.warnings.push(msg);
        }
        self.skip_spaces();
        rel.op = Some(op);
        rel.version = Some(version);
        Ok(rel)
    }

    /// The groups of alternatives of the whole field.
    fn field(&mut self) -> Result<Vec<Vec<Relation>>, String> {
        let rules = self.rules;
        let mut groups = Vec::new();
        self.skip_spaces();
        if self.peek().is_none() {
            return Ok(groups);
        }
        loop {
            let mut alts = Vec::new();
            loop {
                let rel = self.relation()?;
                if rules.exact_only && rel.op.is_some_and(|op| op != Op::Eq) {
                    let msg = "only exact versions may be used".to_owned();
                    if !rules.lax {
                        return Err(msg);
                    }
                    self.warnings.push(msg);
                }
                let name = rel.name.clone();
                alts.push(rel);
                match self.peek() {
                    None | Some(b',') => break,
                    Some(b'|') if rules.alternatives => {}
                    Some(b'|') => return Err("alternatives ('|') not allowed".to_owned()),
                    Some(_) => {
                        return Err(format!("syntax error after reference to package '{name}'"));
                    }
                }
                self.bump();
                self.skip_spaces();
            }
            groups.push(alts);
            if self.peek().is_none() {
                return Ok(groups);
            }
            self.bump();
            self.skip_spaces();
        }
    }
}

/// What a relationship field allows beyond the common syntax.
#[derive(Clone, Copy)]
struct Rules {
    alternatives: bool,
    exact_only: bool,
    /// dpkg's lax parser, for its own database: a version it can still compare, and a
    /// Provides with another operator than `=`, are warnings.
    lax: bool,
}

/// The relationship fields of a binary package control file, as dpkg parses them.
pub const FIELDS: [&str; 9] = [
    "Depends",
    "Pre-Depends",
    "Recommends",
    "Suggests",
    "Enhances",
    "Breaks",
    "Conflicts",
    "Provides",
    "Replaces",
];

/// The groups of alternatives of a field, and the warnings of the lax rules.
pub type Parsed = (Vec<Vec<Relation>>, Vec<String>);

fn parse(what: &str, value: Option<&str>, rules: Rules) -> Result<Parsed> {
    let Some(value) = value else {
        return Ok((Vec::new(), Vec::new()));
    };
    let shown = |why: &str| format!("{what} {}: {why}", py::repr_str(value));
    let mut parser = Parser {
        s: value,
        i: 0,
        rules,
        warnings: Vec::new(),
    };
    let groups = parser.field().map_err(|why| Error::new(shown(&why)))?;
    Ok((groups, parser.warnings.iter().map(|w| shown(w)).collect()))
}

/// dpkg's rules for relationship field `field`.
fn field_rules(field: &str, lax: bool) -> Rules {
    Rules {
        alternatives: !matches!(field, "Breaks" | "Conflicts" | "Provides" | "Replaces"),
        exact_only: field == "Provides",
        lax,
    }
}

/// Parse a Depends-like field into groups of alternatives, as dpkg does: package names
/// are folded to lower case, architecture qualifiers are checked and dropped.
///
/// # Errors
/// What dpkg refuses in a Depends field, the field text in the message.
pub fn parse_relations(value: Option<&str>) -> Result<Vec<Vec<Relation>>> {
    parse(
        "relationship field",
        value,
        Rules {
            alternatives: true,
            exact_only: false,
            lax: false,
        },
    )
    .map(|(groups, _)| groups)
}

/// Parse relationship field `field` (one of [`FIELDS`]) as [`parse_relations`] does,
/// with dpkg's rules for that field: Breaks, Conflicts, Provides and Replaces take no
/// alternatives, and Provides only exact versions.
///
/// # Errors
/// What dpkg refuses in that field, the field name and text in the message.
pub fn parse_field(field: &str, value: Option<&str>) -> Result<Vec<Vec<Relation>>> {
    parse(
        &format!("'{field}' field"),
        value,
        field_rules(field, false),
    )
    .map(|(groups, _)| groups)
}

/// Parse relationship field `field` of an entry of dpkg's status file, as dpkg reads its
/// own database: [`parse_field`]'s rules, except that a version dpkg only warns about
/// (one it can still compare) and a Provides with another operator than `=` are
/// returned as warnings, worded as the errors [`parse_field`] gives for them.
///
/// # Errors
/// What dpkg refuses in that field of its database, the field name and text in the
/// message.
pub fn parse_status_field(field: &str, value: Option<&str>) -> Result<Parsed> {
    parse(&format!("'{field}' field"), value, field_rules(field, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_relations_cases() {
        assert_eq!(
            parse_relations(Some("a (>= 1.0), b | c:any (<< 2),\n d")).unwrap(),
            vec![
                vec![Relation::versioned("a", Op::Ge, "1.0")],
                vec![Relation::new("b"), Relation::versioned("c", Op::Lt, "2")],
                vec![Relation::new("d")],
            ]
        );
        assert_eq!(
            parse_relations(Some("")).unwrap(),
            Vec::<Vec<Relation>>::new()
        );
        assert_eq!(parse_relations(None).unwrap(), Vec::<Vec<Relation>>::new());
        assert_eq!(
            parse_relations(Some("a (>> )")).unwrap_err().message(),
            "relationship field 'a (>> )': reference to 'a': version '': version string is empty"
        );
    }

    #[test]
    fn dpkg_corners() {
        let one = |s: &str| parse_relations(Some(s)).unwrap().remove(0).remove(0);
        // names are folded to lower case
        assert_eq!(one("A_b"), Relation::new("a_b"));
        assert_eq!(one("a(>=1)"), Relation::versioned("a", Op::Ge, "1"));
        assert_eq!(one("a:Any (=  1 )"), Relation::versioned("a", Op::Eq, "1"));
        // obsolete operators, and an implicit exact match
        assert_eq!(one("a (< 1)"), Relation::versioned("a", Op::OldLe, "1"));
        assert_eq!(one("a (> 1)"), Relation::versioned("a", Op::OldGe, "1"));
        assert_eq!(one("a ( 1)"), Relation::versioned("a", Op::Eq, "1"));
        assert_eq!(
            parse_relations(Some("a|b(=1)\n\t| c")).unwrap(),
            vec![vec![
                Relation::new("a"),
                Relation::versioned("b", Op::Eq, "1"),
                Relation::new("c")
            ]]
        );
    }

    /// What dpkg-deb --build refuses in a Depends field.
    const INVALID: [(&str, &str); 22] = [
        (
            "a (>> )",
            "reference to 'a': version '': version string is empty",
        ),
        (
            "a (>=)",
            "reference to 'a': version '': version string is empty",
        ),
        ("a (=1", "reference to 'a': version unterminated"),
        ("a (", "reference to 'a': version unterminated"),
        (
            "a (~ 1)",
            "reference to 'a': version contains '1' instead of ')'",
        ),
        (
            "a (= 1 2)",
            "reference to 'a': version contains '2' instead of ')'",
        ),
        ("a (><1)", "reference to 'a': bad version relationship ><"),
        (
            "a (= a1)",
            "reference to 'a': version 'a1': version number does not start with digit",
        ),
        (
            "a (= 1-)",
            "reference to 'a': version '1-': revision number is empty",
        ),
        (
            "a: (= 1)",
            "missing architecture name, or garbage where architecture name expected",
        ),
        (
            "a:",
            "missing architecture name, or garbage where architecture name expected",
        ),
        (
            "a:b:c",
            "reference to 'a': invalid architecture name 'b:c': character ':' not allowed (only letters, digits and characters '-')",
        ),
        ("a :any", "syntax error after reference to package 'a'"),
        ("a [amd64]", "syntax error after reference to package 'a'"),
        (
            "a (= 1) <!nocheck>",
            "syntax error after reference to package 'a'",
        ),
        ("a (= 1)x", "syntax error after reference to package 'a'"),
        ("a (= 1)(", "syntax error after reference to package 'a'"),
        (
            "a, ",
            "missing package name, or garbage where package name expected",
        ),
        (
            " , a",
            "missing package name, or garbage where package name expected",
        ),
        (
            "a ||b",
            "missing package name, or garbage where package name expected",
        ),
        (
            "a,,b",
            "missing package name, or garbage where package name expected",
        ),
        (
            "-a",
            "invalid package name '-a': must start with an alphanumeric character",
        ),
    ];

    #[test]
    fn invalid() {
        for (value, why) in INVALID {
            assert_eq!(
                parse_relations(Some(value)).unwrap_err().message(),
                format!("relationship field {}: {why}", py::repr_str(value)),
                "{value}"
            );
        }
    }

    #[test]
    fn field_rules() {
        assert_eq!(
            parse_field("Provides", Some("a (= 1), b")).unwrap(),
            vec![
                vec![Relation::versioned("a", Op::Eq, "1")],
                vec![Relation::new("b")]
            ]
        );
        assert_eq!(
            parse_field("Provides", Some("a (>= 1)"))
                .unwrap_err()
                .message(),
            "'Provides' field 'a (>= 1)': only exact versions may be used"
        );
        for field in ["Breaks", "Conflicts", "Provides", "Replaces"] {
            assert_eq!(
                parse_field(field, Some("a | b")).unwrap_err().message(),
                format!("'{field}' field 'a | b': alternatives ('|') not allowed")
            );
        }
        assert_eq!(parse_field("Conflicts", Some("a (<< 1)")).unwrap().len(), 1);
        assert_eq!(parse_field("Suggests", Some("a | b")).unwrap().len(), 1);
    }

    /// What dpkg only warns about in its status file, and what it refuses there too.
    #[test]
    fn status_field_rules() {
        let (groups, warnings) =
            parse_status_field("Provides", Some("a (>= 1), b (= 1:x_y)")).unwrap();
        assert_eq!(
            groups,
            vec![
                vec![Relation::versioned("a", Op::Ge, "1")],
                vec![Relation::versioned("b", Op::Eq, "1:x_y")]
            ]
        );
        assert_eq!(
            warnings,
            [
                "'Provides' field 'a (>= 1), b (= 1:x_y)': only exact versions may be used",
                "'Provides' field 'a (>= 1), b (= 1:x_y)': reference to 'b': version '1:x_y': version number does not start with digit"
            ]
        );
        for v in ["1_a", "1-a_b"] {
            assert_eq!(
                parse_status_field("Depends", Some(&format!("a (= {v})")))
                    .unwrap()
                    .1
                    .len(),
                1
            );
        }
        for (field, value, why) in [
            ("Conflicts", "a | b", "alternatives ('|') not allowed"),
            (
                "Depends",
                "a (= :1)",
                "reference to 'a': version ':1': epoch in version is empty",
            ),
            (
                "Depends",
                "a (= 1-)",
                "reference to 'a': version '1-': revision number is empty",
            ),
            (
                "Enhances",
                "a b",
                "syntax error after reference to package 'a'",
            ),
        ] {
            assert_eq!(
                parse_status_field(field, Some(value))
                    .unwrap_err()
                    .message(),
                format!("'{field}' field {}: {why}", py::repr_str(value))
            );
        }
    }

    /// dpkg-deb --build as the oracle: a control file with each Depends field.
    #[test]
    fn against_dpkg_deb() {
        use std::process::Command;
        if Command::new("dpkg-deb").arg("--version").output().is_err() {
            assert!(
                std::env::var_os("DEBBUILD_RS_TEST_REQUIRE_TOOLS").is_none(),
                "no dpkg-deb"
            );
            eprintln!("skipped: no dpkg-deb");
            return;
        }
        let tmp = std::env::temp_dir().join(format!("debbuild-rs-relation-{}", std::process::id()));
        let tree = tmp.join("p");
        std::fs::create_dir_all(tree.join("DEBIAN")).unwrap();
        let valid = [
            "A_b",
            "a(>=1)",
            "a:Any (=  1 )",
            "a (< 1)",
            "a ( 1)",
            "a|b(=1)\n\t| c",
            "a (>> 1) | b:native (<= 2) ,c",
        ];
        // Some empty versions crash dpkg-deb rather than fail it: left out.
        let invalid = INVALID
            .iter()
            .map(|(v, _)| *v)
            .filter(|v| !matches!(*v, "a (>> )" | "a (>=)"));
        for (value, ok) in valid
            .iter()
            .map(|v| (*v, true))
            .chain(invalid.map(|v| (v, false)))
        {
            let value = value.replace('\n', "\n ");
            std::fs::write(
                tree.join("DEBIAN/control"),
                format!(
                    "Package: p\nVersion: 1\nArchitecture: all\nMaintainer: m\nDescription: d\nDepends: {value}\n"
                ),
            )
            .unwrap();
            let o = Command::new("dpkg-deb")
                .args(["--root-owner-group", "--build"])
                .arg(&tree)
                .arg(tmp.join("p.deb"))
                .output()
                .unwrap();
            assert_eq!(o.status.success(), ok, "{value}: {o:?}");
            assert_eq!(parse_relations(Some(&value)).is_ok(), ok, "{value}");
        }
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn matches() {
        let r = Relation::versioned("a", Op::Ge, "1");
        assert!(r.matches(Some("1.1")).unwrap());
        assert!(!r.matches(None).unwrap());
        assert!(Relation::new("a").matches(None).unwrap());
        assert!(r.matches(Some("1.0-")).is_err());
    }

    #[test]
    fn display() {
        assert_eq!(
            show_alternatives(&[Relation::versioned("a", Op::Ge, "1"), Relation::new("b")]),
            "a (>= 1) | b"
        );
    }
}
