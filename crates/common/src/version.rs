//! Debian versions, compared as dpkg's `verrevcmp` does.

use std::cmp::Ordering;

use crate::error::{Error, Result};
use crate::py;

/// A relation operator of a dependency field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Lt,
    Le,
    Eq,
    Ge,
    Gt,
    /// The obsolete `<`, meaning `<=`.
    OldLe,
    /// The obsolete `>`, meaning `>=`.
    OldGe,
}

impl Op {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Lt => "<<",
            Op::Le => "<=",
            Op::Eq => "=",
            Op::Ge => ">=",
            Op::Gt => ">>",
            Op::OldLe => "<",
            Op::OldGe => ">",
        }
    }

    fn holds(self, c: Ordering) -> bool {
        match self {
            Op::Lt => c.is_lt(),
            Op::Le | Op::OldLe => c.is_le(),
            Op::Eq => c.is_eq(),
            Op::Ge | Op::OldGe => c.is_ge(),
            Op::Gt => c.is_gt(),
        }
    }
}

fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(b'~') => -1,
        Some(c) => i32::from(c).saturating_add(256),
    }
}

/// dpkg's verrevcmp, on version parts already checked to be ASCII.
fn verrevcmp(a: &[u8], b: &[u8]) -> Ordering {
    let digit = |s: &[u8], i: usize| s.get(i).is_some_and(u8::is_ascii_digit);
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() || j < b.len() {
        let mut first_diff = Ordering::Equal;
        while (i < a.len() && !digit(a, i)) || (j < b.len() && !digit(b, j)) {
            let ac = order(a.get(i).copied());
            let bc = order(b.get(j).copied());
            if ac != bc {
                return ac.cmp(&bc);
            }
            i = i.saturating_add(1);
            j = j.saturating_add(1);
        }
        while a.get(i) == Some(&b'0') {
            i = i.saturating_add(1);
        }
        while b.get(j) == Some(&b'0') {
            j = j.saturating_add(1);
        }
        while digit(a, i) && digit(b, j) {
            if first_diff.is_eq() {
                first_diff = a.get(i).cmp(&b.get(j));
            }
            i = i.saturating_add(1);
            j = j.saturating_add(1);
        }
        if digit(a, i) {
            return Ordering::Greater;
        }
        if digit(b, j) {
            return Ordering::Less;
        }
        if first_diff.is_ne() {
            return first_diff;
        }
    }
    Ordering::Equal
}

struct Parts<'a> {
    /// Without its leading zeros, so that it compares by length, then bytes.
    epoch: &'a str,
    upstream: &'a str,
    revision: &'a str,
}

fn all_in(s: &str, extra: &[u8]) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

/// Epoch, upstream version and revision of `v`; an error for what dpkg rejects.
fn split(v: &str) -> Result<Parts<'_>> {
    let err = |what: &str| Error::value(format!("version {}: {what}", py::repr_str(v)));
    let mut s = py::strip_str(v);
    let mut epoch = "";
    if let Some((e, rest)) = s.split_once(':') {
        if e.is_empty() || !e.bytes().all(|c| c.is_ascii_digit()) {
            return Err(err("epoch is not a number"));
        }
        epoch = e.trim_start_matches('0');
        s = rest;
    }
    let (upstream, revision) = match s.rsplit_once('-') {
        None => (s, ""),
        Some((_, "")) => return Err(err("empty revision")),
        Some(parts) => parts,
    };
    if upstream.is_empty() {
        return Err(err("empty version number"));
    }
    if !all_in(upstream, b".+~:-") || (!revision.is_empty() && !all_in(revision, b".+~")) {
        return Err(err("invalid character"));
    }
    Ok(Parts {
        epoch,
        upstream,
        revision,
    })
}

/// What dpkg's `parseversion` finds wrong with `v`, the problems it only warns about
/// included: in a control file, dpkg-deb --build refuses them all.
#[must_use]
pub fn problem(v: &str) -> Option<&'static str> {
    if v.is_empty() {
        return Some("version string is empty");
    }
    let s = v.trim_matches([' ', '\t']);
    if s.contains([' ', '\t']) {
        return Some("version string has embedded spaces");
    }
    let mut rest = s;
    if let Some((epoch, after)) = s.split_once(':') {
        // strtol: a sign, then digits.
        let digits = epoch.strip_prefix(['+', '-']).unwrap_or(epoch);
        let n = digits.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return Some("epoch in version is empty");
        }
        if n != digits.len() {
            return Some("epoch in version is not number");
        }
        let value = digits.bytes().fold(0u64, |acc, c| {
            acc.saturating_mul(10)
                .saturating_add(u64::from(c.saturating_sub(b'0')))
        });
        if epoch.starts_with('-') && value != 0 {
            return Some("epoch in version is negative");
        }
        if value > u64::from(i32::MAX.unsigned_abs()) {
            return Some("epoch in version is too big");
        }
        if after.is_empty() {
            return Some("nothing after colon in version number");
        }
        rest = after;
    }
    let (upstream, revision) = match rest.rsplit_once('-') {
        None => (rest, ""),
        Some((_, "")) => return Some("revision number is empty"),
        Some(parts) => parts,
    };
    if upstream.is_empty() {
        return Some("version number is empty");
    }
    if !upstream.starts_with(|c: char| c.is_ascii_digit()) {
        return Some("version number does not start with digit");
    }
    if !upstream
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b".-+~:".contains(&c))
    {
        return Some("invalid character in version number");
    }
    if !revision
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b".+~".contains(&c))
    {
        return Some("invalid character in revision number");
    }
    None
}

/// Whether [`problem`] `why` is one dpkg only warns about when it reads its own
/// database (its lax parser): the version can still be compared.
#[must_use]
pub fn is_warning(why: &str) -> bool {
    matches!(
        why,
        "version number does not start with digit"
            | "invalid character in version number"
            | "invalid character in revision number"
    )
}

/// Check a version as dpkg-deb --build does.
///
/// # Errors
/// What [`problem`] finds.
pub fn check(v: &str) -> Result<()> {
    match problem(v) {
        Some(why) => Err(Error::value(format!("version {}: {why}", py::repr_str(v)))),
        None => Ok(()),
    }
}

/// Compare two versions as dpkg does.
///
/// # Errors
/// A version dpkg rejects (bad epoch, empty revision or version, invalid character).
pub fn version_compare(a: &str, b: &str) -> Result<Ordering> {
    let pa = split(a)?;
    let pb = split(b)?;
    Ok(pa
        .epoch
        .len()
        .cmp(&pb.epoch.len())
        .then_with(|| pa.epoch.cmp(pb.epoch))
        .then_with(|| verrevcmp(pa.upstream.as_bytes(), pb.upstream.as_bytes()))
        .then_with(|| verrevcmp(pa.revision.as_bytes(), pb.revision.as_bytes())))
}

/// Whether `version` `op` `wanted` holds.
///
/// # Errors
/// An invalid version.
pub fn version_satisfies(version: &str, op: Op, wanted: &str) -> Result<bool> {
    Ok(op.holds(version_compare(version, wanted)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn version_compare_against_dpkg() {
        if Command::new("dpkg").arg("--version").output().is_err() {
            assert!(
                std::env::var_os("DEBBUILD_RS_TEST_REQUIRE_TOOLS").is_none(),
                "no dpkg"
            );
            eprintln!("skipped: no dpkg");
            return;
        }
        let pairs = [
            ("1.0", "1.0"),
            ("1.0", "1.1"),
            ("1.0~rc1", "1.0"),
            ("1.0~~", "1.0~"),
            ("1:0.1", "2.0"),
            ("0:1.0", "1.0"),
            ("1.0-1", "1.0-2"),
            ("1.0-1", "1.0"),
            ("1.0a", "1.0"),
            ("1.0+b1", "1.0"),
            ("1.2.10", "1.2.9"),
            ("1.0-0.1", "1.0-1"),
            ("2.36-9+deb12u1", "2.36-9"),
            ("12.5.0.0-dev", "12.5.0.0.1"),
            ("1.0.0-dev", "1.0.0"),
            ("1.001", "1.1"),
            ("1.0-a", "1.0-A"),
            ("1:1.0-1", "1.0-1"),
            ("10", "9"),
        ];
        let dpkg = |x: &str, op: &str, y: &str| {
            Command::new("dpkg")
                .args(["--compare-versions", x, op, y])
                .status()
                .unwrap()
                .success()
        };
        for (a, b) in pairs {
            for (x, y) in [(a, b), (b, a)] {
                let want = if dpkg(x, "lt", y) {
                    Ordering::Less
                } else if dpkg(x, "eq", y) {
                    Ordering::Equal
                } else {
                    Ordering::Greater
                };
                assert_eq!(version_compare(x, y).unwrap(), want, "{x} vs {y}");
            }
        }
    }

    #[test]
    fn bad_versions() {
        for (v, why) in [
            ("1.0-", "empty revision"),
            ("a:1.0", "epoch is not a number"),
            ("", "empty version number"),
            (":1.0", "epoch is not a number"),
            ("1.0_1", "invalid character"),
            ("1 0", "invalid character"),
            ("-1", "empty version number"),
        ] {
            let e = version_compare(v, "1.0").unwrap_err();
            assert_eq!(
                e.message(),
                format!("version {}: {why}", py::repr_str(v)),
                "{v}"
            );
        }
    }

    const VALID: [&str; 6] = ["1", "1.0-1", "0:1.0~rc1+b1-0.1", "+1:1", "-0:1", "1:2-c"];
    const INVALID: [(&str, &str); 13] = [
        ("", "version string is empty"),
        ("1 0", "version string has embedded spaces"),
        (":1", "epoch in version is empty"),
        ("a:1", "epoch in version is empty"),
        ("1a:1", "epoch in version is not number"),
        ("-1:1", "epoch in version is negative"),
        ("99999999999:1", "epoch in version is too big"),
        ("1:", "nothing after colon in version number"),
        ("1-", "revision number is empty"),
        ("-1", "version number is empty"),
        ("a1", "version number does not start with digit"),
        ("1_0", "invalid character in version number"),
        ("1-a_b", "invalid character in revision number"),
    ];

    #[test]
    fn strict_versions() {
        for v in VALID {
            assert_eq!(problem(v), None, "{v}");
        }
        for (v, why) in INVALID {
            assert_eq!(problem(v), Some(why), "{v}");
        }
        assert_eq!(
            check("a1").unwrap_err().message(),
            "version 'a1': version number does not start with digit"
        );
    }

    /// dpkg-deb --build as the oracle: a control file with each version.
    #[test]
    fn strict_versions_against_dpkg_deb() {
        if Command::new("dpkg-deb").arg("--version").output().is_err() {
            assert!(
                std::env::var_os("DEBBUILD_RS_TEST_REQUIRE_TOOLS").is_none(),
                "no dpkg-deb"
            );
            eprintln!("skipped: no dpkg-deb");
            return;
        }
        let tmp = std::env::temp_dir().join(format!("debbuild-rs-version-{}", std::process::id()));
        let tree = tmp.join("p");
        std::fs::create_dir_all(tree.join("DEBIAN")).unwrap();
        // The empty version is a missing field to dpkg: refused too.
        let all = VALID.iter().chain(INVALID.iter().map(|(v, _)| v));
        for v in all {
            std::fs::write(
                tree.join("DEBIAN/control"),
                format!(
                    "Package: p\nVersion: {v}\nArchitecture: all\nMaintainer: m\nDescription: d\n"
                ),
            )
            .unwrap();
            let ok = Command::new("dpkg-deb")
                .args(["--root-owner-group", "--build"])
                .arg(&tree)
                .arg(tmp.join("p.deb"))
                .output()
                .unwrap()
                .status
                .success();
            assert_eq!(problem(v).is_none(), ok, "{v}");
        }
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn epochs_compare_numerically() {
        assert_eq!(
            version_compare("00010:1", "9:1").unwrap(),
            Ordering::Greater
        );
        assert_eq!(version_compare("0:1", "1").unwrap(), Ordering::Equal);
        assert!(version_satisfies("1.0", Op::OldLe, "1.0").unwrap());
        assert!(!version_satisfies("1.0", Op::Lt, "1.0").unwrap());
    }
}
