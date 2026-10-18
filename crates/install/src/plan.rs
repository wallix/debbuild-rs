//! What to install: the requested packages and the staged packages they need, in
//! dependency order, checked for conflicts.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;

use indexmap::IndexMap;

use debbuild_rs_common::deb822::{Stanza, state_of};
use debbuild_rs_common::relation::{Relation, show_alternatives};
use debbuild_rs_common::{Error, Result};

use crate::db::{Database, is_absent_state, status_relations};
use crate::staged::Package;

/// Post-order DFS over the sorted names; cycles are broken where they are found, as
/// dpkg does.
fn visit(
    n: &str,
    selected: &HashMap<String, Vec<String>>,
    seen: &mut BTreeSet<String>,
    order: &mut Vec<String>,
) {
    if !seen.insert(n.to_owned()) {
        return;
    }
    let mut deps: Vec<&String> = selected
        .get(n)
        .map(|d| d.iter().collect())
        .unwrap_or_default();
    deps.sort();
    for d in deps {
        visit(d, selected, seen, order);
    }
    order.push(n.to_owned());
}

/// The staged packages answering to each name: (package, the version it answers with;
/// None for an unversioned Provides), in stage order.
type Answers<'a> = HashMap<&'a str, Vec<(&'a str, Option<&'a str>)>>;

/// The staged package to install for `rel`: the one of that name if its version
/// satisfies it, otherwise the first one providing it with a matching version.
fn staged_candidate(answers: &Answers<'_>, rel: &Relation) -> Result<Option<String>> {
    let mut found = None;
    for (name, version) in answers
        .get(rel.name.as_str())
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        if rel.matches(*version)? {
            if *name == rel.name {
                return Ok(Some((*name).to_owned()));
            }
            found = found.or(Some(*name));
        }
    }
    Ok(found.map(str::to_owned))
}

/// Why a package is in the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// It was named on the command line.
    Requested,
    /// It was chosen for a dependency of another planned package.
    Needed {
        /// The package depending on it.
        by: String,
        /// `Pre-Depends` or `Depends`.
        field: &'static str,
        /// The alternatives of the relation, as written in the field.
        relation: String,
    },
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Requested => f.write_str("requested"),
            Reason::Needed {
                by,
                field,
                relation,
            } => write!(f, "needed by {by} ({field}: {relation})"),
        }
    }
}

/// The planned packages, in dependency order, and why each one is planned.
pub struct Plan<'a> {
    pub packages: Vec<&'a Package>,
    /// Package -> its reasons: `Requested` first, then the dependencies in the order
    /// they were followed.
    pub reasons: Reasons,
}

/// Selected package -> the staged packages chosen for its dependencies.
type Selection = HashMap<String, Vec<String>>;

/// Planned package -> why it is planned.
type Reasons = HashMap<String, Vec<Reason>>;

/// The requested packages and the staged packages they need: name -> the staged
/// packages chosen for its dependencies; why each one was selected; and the
/// dependencies nothing satisfies. An installed package named in `replaced` does not
/// satisfy a dependency: the plan installs another version of it.
fn select(
    db: &Database,
    staged: &IndexMap<String, Package>,
    answers: &Answers<'_>,
    requested: &[String],
    replaced: &BTreeSet<String>,
) -> Result<(Selection, Reasons, Vec<String>)> {
    let skip = |n: &str| replaced.contains(n);
    let mut selected: Selection = HashMap::new();
    let mut reasons: Reasons = HashMap::new();
    for name in requested {
        reasons.insert(name.clone(), vec![Reason::Requested]);
    }
    let mut missing: Vec<String> = Vec::new();
    let mut todo: VecDeque<String> = requested.iter().cloned().collect();
    while let Some(name) = todo.pop_front() {
        if selected.contains_key(&name) {
            continue;
        }
        let Some(pkg) = staged.get(&name) else {
            return Err(Error::new(format!("{name} is not staged")));
        };
        let mut edges = Vec::new();
        // Pre-Depends, then Depends, as Package::depends() gives them.
        let mut relations = Vec::new();
        for field in ["Pre-Depends", "Depends"] {
            for alts in pkg.relations(field)? {
                relations.push((field, alts));
            }
        }
        for (field, alts) in relations {
            let mut cands = Vec::new();
            for a in &alts {
                if let Some(c) = staged_candidate(answers, a)? {
                    cands.push(c);
                }
            }
            // A staged alternative already installed comes from the stage, as from a
            // pinned repository; otherwise an installed alternative the plan keeps will
            // do; otherwise the first staged one is installed.
            let mut choice = cands.iter().find(|c| db.installed(c).is_some()).cloned();
            if choice.is_none() {
                let mut satisfied = false;
                for a in &alts {
                    if db.provider_except(a, &skip)?.is_some() {
                        satisfied = true;
                        break;
                    }
                }
                if satisfied {
                    continue;
                }
                if cands.is_empty() {
                    missing.push(format!("{name}: {}", show_alternatives(&alts)));
                    continue;
                }
                choice = cands.first().cloned();
            }
            if let Some(c) = choice {
                let why = Reason::Needed {
                    by: name.clone(),
                    field,
                    relation: show_alternatives(&alts),
                };
                let r = reasons.entry(c.clone()).or_default();
                if !r.contains(&why) {
                    r.push(why);
                }
                edges.push(c.clone());
                todo.push_back(c);
            }
        }
        selected.insert(name, edges);
    }
    Ok((selected, reasons, missing))
}

/// Requested packages and the staged packages they need, in dependency order, with
/// why each one is planned.
///
/// Every dependency (Pre-Depends, Depends) of a planned package holds once the plan is
/// installed: it is satisfied by a planned package at its staged version, or by an
/// installed package the plan does not replace, at its installed version; directly or
/// through a Provides, versioned or not.
///
/// # Errors
/// A package is not staged, a dependency cannot be satisfied, a Multi-Arch: same
/// package is selected, a relationship field is invalid, or packages conflict.
pub fn plan<'a>(
    db: &Database,
    staged: &'a IndexMap<String, Package>,
    requested: &[String],
) -> Result<Plan<'a>> {
    let mut answers: Answers<'_> = HashMap::new();
    for p in staged.values() {
        answers
            .entry(p.name.as_str())
            .or_default()
            .push((p.name.as_str(), Some(p.version())));
    }
    let provides: Vec<(&str, Vec<Relation>)> = staged
        .values()
        .map(|p| Ok((p.name.as_str(), p.provides()?)))
        .collect::<Result<_>>()?;
    for (name, provs) in &provides {
        for prov in provs {
            answers
                .entry(prov.name.as_str())
                .or_default()
                .push((name, prov.version.as_deref()));
        }
    }

    for name in requested {
        if !staged.contains_key(name) {
            return Err(Error::new(format!("{name} is not staged")));
        }
    }
    // The installed version of a selected package does not count, since the plan
    // replaces it: select again, without the installed versions of the packages
    // selected so far, until no new package is selected.
    let mut replaced: BTreeSet<String> = requested.iter().cloned().collect();
    let (selected, reasons) = loop {
        let (selected, reasons, missing) = select(db, staged, &answers, requested, &replaced)?;
        if selected.keys().all(|n| replaced.contains(n)) {
            if !missing.is_empty() {
                return Err(Error::new(format!(
                    "unsatisfied dependencies:\n  {}",
                    missing.join("\n  ")
                )));
            }
            break (selected, reasons);
        }
        replaced.extend(selected.into_keys());
    };
    let multiarch: BTreeSet<&String> = selected
        .keys()
        .filter(|n| {
            staged
                .get(*n)
                .and_then(|p| p.control.get("Multi-Arch"))
                .is_some_and(|m| m == "same")
        })
        .collect();
    if !multiarch.is_empty() {
        let names: Vec<&str> = multiarch.into_iter().map(String::as_str).collect();
        return Err(Error::new(format!(
            "Multi-Arch: same packages are not supported: {}",
            names.join(" ")
        )));
    }

    let mut names: Vec<&String> = selected.keys().collect();
    names.sort();
    let mut order = Vec::new();
    let mut seen = BTreeSet::new();
    for n in names {
        visit(n, &selected, &mut seen, &mut order);
    }
    let pkgs: Vec<&Package> = order.iter().filter_map(|n| staged.get(n)).collect();
    // dpkg -i refuses a package with an invalid relationship field, used or not.
    for p in &pkgs {
        p.check_relations()?;
    }
    check_conflicts(db, &pkgs)?;
    Ok(Plan {
        packages: pkgs,
        reasons,
    })
}

/// Fail on Conflicts or Breaks between the planned packages and the ones on disk after
/// the plan.
///
/// # Errors
/// The conflicts found, or an invalid field.
pub fn check_conflicts(db: &Database, pkgs: &[&Package]) -> Result<()> {
    let planned: IndexMap<&str, &Package> = pkgs.iter().map(|p| (p.name.as_str(), *p)).collect();
    let mut after: IndexMap<String, &Stanza> = IndexMap::new();
    for s in db.status.values() {
        if !is_absent_state(state_of(Some(s))) {
            after.insert(s.get("Package").cloned().unwrap_or_default(), s);
        }
    }
    for (n, p) in &planned {
        after.insert((*n).to_owned(), &p.control);
    }
    // A planned package's fields as its control file has them, the others as the status
    // file has them.
    let relations = |name: &str, s: &Stanza, field: &str| match planned.get(name) {
        Some(p) => p.relations(field),
        None => status_relations(s, field),
    };
    // The packages answering to a name, with the version they answer with (None for an
    // unversioned Provides).
    let mut answers: HashMap<String, Vec<(String, Option<String>)>> = HashMap::new();
    for (name, s) in &after {
        answers
            .entry(name.clone())
            .or_default()
            .push((name.clone(), s.get("Version").cloned()));
        for alts in relations(name, s, "Provides")? {
            if let Some(a) = alts.into_iter().next() {
                answers
                    .entry(a.name)
                    .or_default()
                    .push((name.clone(), a.version));
            }
        }
    }
    let mut hits: BTreeSet<String> = BTreeSet::new();
    for (name, s) in &after {
        for kind in ["Conflicts", "Breaks"] {
            for alts in relations(name, s, kind)? {
                for rel in alts {
                    for (other, version) in answers
                        .get(&rel.name)
                        .map(Vec::as_slice)
                        .unwrap_or_default()
                    {
                        // dpkg lets a package conflict with itself or with what it provides.
                        if other == name
                            || (!planned.contains_key(name.as_str())
                                && !planned.contains_key(other.as_str()))
                        {
                            continue;
                        }
                        if rel.matches(version.as_deref())? {
                            let cond = match (&rel.op, &rel.version) {
                                (Some(op), Some(v)) => format!(" ({} {v})", op.as_str()),
                                _ => String::new(),
                            };
                            let other_version = after
                                .get(other)
                                .and_then(|s| s.get("Version"))
                                .map_or("None", String::as_str);
                            hits.insert(format!(
                                "{name} {} {}{cond}: {other} {other_version}",
                                kind.to_lowercase(),
                                rel.name
                            ));
                        }
                    }
                }
            }
        }
    }
    if hits.is_empty() {
        Ok(())
    } else {
        let hits: Vec<String> = hits.into_iter().collect();
        Err(Error::new(format!(
            "conflicting packages:\n  {}",
            hits.join("\n  ")
        )))
    }
}
