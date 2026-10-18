//! `debbuild-rs inspect`: what a staged tree holds, validated as `diff-stage` validates it.

use std::fs;
use std::path::Path;

use debbuild_rs_common::{deb822, staged_lock};

use crate::diffstage::{Source, compression_name, invalid, load_source, read_lock, staged_dirs};
use crate::util::{Result, err};

/// The help text of `debbuild-rs inspect`.
pub const ABOUT: &str = "List the packages of staged trees, after validating them.

STAGED is a staged source directory (OUTDIR/<dir>, holding .staged) or an output
directory (OUTDIR). Each tree is validated as `diff-stage` does: .staged lists existing
package trees, each with DEBIAN/control, a data.tar matching data.tar.sha256, and valid
dpkg-deb.options and staged.info. Then one line per package:

  <dir>/<package> <version> <architecture> <compression> epoch <seconds|unrecorded>

followed by its relationship fields, indented. Exit status: 0, or 2 when a tree is invalid
(every problem listed).";

/// The relationship fields shown under each package.
const RELATIONS: [&str; 8] = [
    "Pre-Depends",
    "Depends",
    "Recommends",
    "Breaks",
    "Conflicts",
    "Replaces",
    "Provides",
    "Enhances",
];

fn describe(dir: &str, path: &Path, source: &Source, out: &mut Vec<String>) -> Result<()> {
    for (pkg, tree) in source {
        let control = path.join(pkg).join("DEBIAN/control");
        let text =
            fs::read_to_string(&control).map_err(|e| err(format!("{}: {e}", control.display())))?;
        let stanzas =
            deb822::parse_stanzas(&text).map_err(|e| err(format!("{}: {e}", control.display())))?;
        let stanza = stanzas.first();
        let field = |f: &str| stanza.and_then(|s| s.get(f)).map_or("?", String::as_str);
        out.push(format!(
            "{dir}/{pkg} {} {} {} epoch {}",
            field("Version"),
            field("Architecture"),
            compression_name(tree.compression),
            tree.epoch
                .map_or_else(|| "unrecorded".to_owned(), |e| e.to_string()),
        ));
        for f in RELATIONS {
            if let Some(v) = stanza.and_then(|s| s.get(f)) {
                out.push(format!(
                    "  {f}: {}",
                    v.split_whitespace().collect::<Vec<_>>().join(" ")
                ));
            }
        }
    }
    Ok(())
}

/// The description of the staged trees of `staged` (a source or an output directory).
///
/// # Errors
/// A tree is invalid (every problem listed) or cannot be read.
pub fn inspect(staged: &Path) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    let mut out = Vec::new();
    if staged.join(".staged").exists() {
        let _lock = read_lock(staged, staged_lock::read_source)?;
        let source = load_source(staged, &mut problems).ok_or_else(|| invalid(&problems))?;
        let dir = staged.file_name().unwrap_or_default().to_string_lossy();
        describe(&dir, staged, &source, &mut out)?;
        return Ok(out);
    }
    let _lock = read_lock(staged, staged_lock::read_output)?;
    let dirs = staged_dirs(staged).map_err(|e| err(format!("{}: {e}", staged.display())))?;
    if dirs.is_empty() {
        return Err(err(format!(
            "{}: no staged source directory (holding .staged)",
            staged.display()
        )));
    }
    let sources: Vec<_> = dirs
        .iter()
        .filter_map(|d| Some((d, load_source(&staged.join(d), &mut problems)?)))
        .collect();
    if !problems.is_empty() {
        return Err(invalid(&problems));
    }
    for (d, source) in &sources {
        describe(d, &staged.join(d), source, &mut out)?;
    }
    Ok(out)
}
