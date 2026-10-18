//! What installing a planned package does, decided once for the dry run and the
//! installation alike, and the dry run's output.

use std::cmp::Ordering;
use std::fmt::Write as _;

use debbuild_rs_common::deb822::state_of;
use debbuild_rs_common::version::version_compare;
use debbuild_rs_common::{Result, py};

use crate::db::{Database, is_absent_state, is_installed_state};
use crate::fsx;
use crate::installer::STATEDIR;
use crate::plan::{Plan, Reason};
use crate::staged::Package;

/// What the installer does with a planned package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Not installed (or only its conffiles left): installed.
    Install,
    /// Installed at a lower version: upgraded.
    Upgrade,
    /// Installed at a higher version: downgraded.
    Downgrade,
    /// Installed at the same version, with other content, not fully installed, or
    /// reinstalled on request: unpacked again.
    Reinstall,
    /// Unchanged, half-configured (its postinst failed): configured again, as
    /// `dpkg --configure` would.
    Configure,
    /// Unchanged and installed: left as it is.
    Skip,
}

impl Action {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Install => "install",
            Action::Upgrade => "upgrade",
            Action::Downgrade => "downgrade",
            Action::Reinstall => "reinstall",
            Action::Configure => "configure",
            Action::Skip => "skip",
        }
    }
}

/// The action for a planned package, with what it starts from.
pub struct Decision {
    pub action: Action,
    /// The package's dpkg state in the root (`not-installed` when it has no entry).
    pub state: String,
    /// The version in the root, unless not installed or only its conffiles are left.
    pub old_version: Option<String>,
}

/// What installing `pkg` into the root of `db` does. A package is unchanged when the
/// root has the same version, and the content digest recorded when its files were last
/// unpacked is the staged one's, so that the files on disk are the staged ones;
/// `reinstall` makes no package unchanged.
///
/// # Errors
/// The recorded digest or the staged package cannot be read, or a version is invalid.
pub fn decide(db: &Database, pkg: &Package, reinstall: bool) -> Result<Decision> {
    let old = db.status.get(&pkg.name);
    let state = state_of(old).to_owned();
    let version = old.and_then(|o| o.get("Version"));
    let unchanged = !reinstall && version.map(String::as_str) == Some(pkg.version()) && {
        // Read in the root, as it is written (H3).
        let digest = crate::confine::confined_str(
            &db.root,
            &format!("{STATEDIR}/{}.sha256", pkg.name),
            true,
        )?;
        fsx::exists(&digest) && py::strip_str(&fsx::read_text(&digest)?) == pkg.digest()?
    };
    let old_version = version.filter(|_| !is_absent_state(&state)).cloned();
    let action = if unchanged && is_installed_state(&state) {
        Action::Skip
    } else if unchanged && state == "half-configured" {
        Action::Configure
    } else {
        match &old_version {
            None => Action::Install,
            Some(v) if v == pkg.version() => Action::Reinstall,
            Some(v) => match version_compare(pkg.version(), v)? {
                Ordering::Greater => Action::Upgrade,
                Ordering::Less => Action::Downgrade,
                Ordering::Equal => Action::Reinstall,
            },
        }
    };
    Ok(Decision {
        action,
        state,
        old_version,
    })
}

/// One package of the dry run.
pub struct Step<'a> {
    pub pkg: &'a Package,
    pub decision: Decision,
    pub reasons: &'a [Reason],
}

/// The decision for each planned package, in plan order.
///
/// # Errors
/// A decision fails.
pub fn steps<'a>(db: &Database, plan: &'a Plan<'a>, reinstall: bool) -> Result<Vec<Step<'a>>> {
    plan.packages
        .iter()
        .map(|p| {
            Ok(Step {
                pkg: p,
                decision: decide(db, p, reinstall)?,
                reasons: plan.reasons.get(&p.name).map_or(&[][..], Vec::as_slice),
            })
        })
        .collect()
}

/// The dry run as text, one line per package in plan order:
/// `<package> <action> <version> (<reason>, ...)`, where `<version>` is
/// `<old> -> <new>` when the root has another version.
#[must_use]
pub fn text(steps: &[Step<'_>]) -> String {
    let mut out = String::new();
    for s in steps {
        let new = s.pkg.version();
        let version = match &s.decision.old_version {
            Some(old) if old != new => format!("{old} -> {new}"),
            _ => new.to_owned(),
        };
        let reasons: Vec<String> = s.reasons.iter().map(ToString::to_string).collect();
        let _ = writeln!(
            out,
            "{} {} {version} ({})",
            s.pkg.name,
            s.decision.action.as_str(),
            reasons.join(", ")
        );
    }
    out
}

/// `s` as a JSON string.
fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The dry run as one JSON object (see `ABOUT`), followed by a newline.
#[must_use]
pub fn json(steps: &[Step<'_>]) -> String {
    let mut out = String::from("{\"packages\":[");
    for (i, s) in steps.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        json_str(&mut out, &s.pkg.name);
        out.push_str(",\"action\":");
        json_str(&mut out, s.decision.action.as_str());
        out.push_str(",\"state\":");
        json_str(&mut out, &s.decision.state);
        out.push_str(",\"old_version\":");
        match &s.decision.old_version {
            Some(v) => json_str(&mut out, v),
            None => out.push_str("null"),
        }
        out.push_str(",\"new_version\":");
        json_str(&mut out, s.pkg.version());
        out.push_str(",\"reasons\":[");
        for (j, r) in s.reasons.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            match r {
                Reason::Requested => out.push_str("{\"kind\":\"requested\"}"),
                Reason::Needed {
                    by,
                    field,
                    relation,
                } => {
                    out.push_str("{\"kind\":\"dependency\",\"by\":");
                    json_str(&mut out, by);
                    out.push_str(",\"field\":");
                    json_str(&mut out, field);
                    out.push_str(",\"relation\":");
                    json_str(&mut out, relation);
                    out.push('}');
                }
            }
        }
        out.push_str("]}");
    }
    out.push_str("]}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_strings() {
        let mut out = String::new();
        json_str(&mut out, "a\"b\\c\nd\u{1}é");
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\\u0001é\"");
    }
}
