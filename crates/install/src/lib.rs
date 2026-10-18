//! `debbuild-rs install`: install staged packages into a root directory, the way dpkg does.
//!
//! A staged package is a directory holding the two halves of a .deb: DEBIAN/ (control,
//! md5sums, conffiles, maintainer scripts, ...) and data.tar (the file tree).
//! `debbuild-rs stage` stages the binary packages of a source directory <dir> in
//! STAGEDIR/<dir>/<package>.
//!
//! For each requested package and the staged packages it depends on, in dependency
//! order, this follows dpkg's sequence for an install or an upgrade
//! (prerm/preinst/unpack/postrm, then postinst configure), registers the result in the
//! dpkg database (status, info/*), and processes the triggers the new files activate.
//! dpkg itself is not involved: the database it reads afterwards (dpkg -l, -S, -V)
//! describes the packages as if it had installed them.

pub mod action;
pub mod confine;
pub mod db;
pub mod exec;
pub mod filter;
mod fsx;
pub mod installer;
pub mod plan;
pub mod staged;
mod unpack;

use std::io::Write;
use std::path::{Component, Path, PathBuf};

use debbuild_rs_common::{IoContext, Result};

pub use db::Database;
pub use exec::{Chroot, Exec};
pub use installer::{Conffiles, InstallOptions, Installer};
pub use plan::{Plan, plan};
pub use staged::load_staged;

/// The help text of `debbuild-rs install`.
pub const ABOUT: &str = "Install staged packages into a root directory, the way dpkg does.

A staged package is a directory holding the two halves of a .deb:
    DEBIAN/        the control files (control, md5sums, conffiles, maintainer scripts, ...)
    data.tar       the file tree
`debbuild-rs stage` stages the binary packages of a source directory <dir> in
STAGEDIR/<dir>/<package>.

For each requested package and the staged packages it depends on, in dependency order,
this follows dpkg's sequence for an install or an upgrade (prerm/preinst/unpack/postrm,
then postinst configure), registers the result in the dpkg database (status, info/*), and
processes the triggers the new files activate. dpkg itself is not involved: the database
it reads afterwards (dpkg -l, -S, -V) describes the packages as if it had installed them.

Dependencies outside the staged set must already be installed in the root.

--dry-run prints the plan without changing the root: in installation order, one line
per package,
    <package> <action> <version> (<reason>, ...)
where <version> is `<old> -> <new>` when the root has another version, and <action> is
what the installation does with it:
    install     not installed, or only its conffiles are left
    upgrade     installed at a lower version
    downgrade   installed at a higher version
    reinstall   installed at the same version but with other content (or not fully
                installed, or --reinstall): unpacked again
    configure   unchanged, half-configured: postinst configure runs again
    skip        unchanged and installed: left as it is
A package is unchanged when the root has the same version, and the content digest
recorded in var/lib/debbuild-rs/<package>.sha256 when its files were last unpacked is the
staged one's: an unpack that does not complete leaves no digest. Each reason is `requested`, or `needed by <package> (<field>: <relation>)`
for the dependency that pulled it in.
With --json, the plan is one JSON object instead:
    {\"packages\": [{\"name\": \"b\", \"action\": \"upgrade\", \"state\": \"installed\",
                   \"old_version\": \"1\", \"new_version\": \"2\",
                   \"reasons\": [{\"kind\": \"requested\"},
                               {\"kind\": \"dependency\", \"by\": \"a\",
                                \"field\": \"Depends\", \"relation\": \"b (>= 2)\"}]},
                  ...]}
where state is the package's dpkg state in the root (not-installed without an entry) and
old_version is null when it is not installed or only its conffiles are left. Members
may be added; the existing ones keep their meaning.

Differences with dpkg:
- Conffiles are settled at unpack time, where dpkg extracts them as .dpkg-new and settles
  them at configure time: postrm upgrade already sees the new conffile. The decisions are
  dpkg's, with --force-confold where dpkg would prompt (--conffiles=replace:
  --force-confnew there, the replaced file kept as <conffile>.dpkg-old): a conffile both
  the administrator and the package changed is kept, with the new version in
  <conffile>.dpkg-dist, and so is an existing file with other content on a fresh install. Otherwise a conffile the
  administrator changed and the package did not stays as it is, a deleted one stays
  deleted, and an unmodified one is replaced. A conffile that is a symlink is written
  through.
- The files of a failed unpack are not restored: after the abort-* maintainer scripts, the
  package stays half-installed, to be reinstalled.
- Conflicts and Breaks are errors: conflicting packages are not removed or deconfigured.
- A package whose files all get taken over through Replaces stays installed: no postrm
  disappear.
- Triggers are never awaited: activating packages do not go to triggers-awaited.
- Multi-Arch: same packages cannot be staged, and FIFOs, device nodes or sparse files
  cannot be unpacked.
- Not supported: removal and purge, diversions and alternatives of its own (the scripts'
  dpkg-divert and update-alternatives work), dpkg's updates/ journal, the available
  file, dpkg.log.
- Every path is resolved inside the root, symlinks included, so that --root ROOT does not
  write outside ROOT; maintainer scripts run chrooted in it, with DPKG_FRONTEND_LOCKED
  set: the dpkg locks are held for the whole run.
- A staged tree that changes while it is installed (data.tar not matching
  data.tar.sha256, files gone) is an error: rerun once the stage run is over.";

/// `Path.resolve()` (non-strict `os.path.realpath`): absolute, symlinks resolved, missing
/// components kept.
///
/// # Errors
/// The current directory cannot be read, or a symlink loops.
pub fn realpath(path: &Path) -> Result<PathBuf> {
    fn walk(out: &mut PathBuf, path: &Path, seen: &mut u32) -> Result<()> {
        for c in path.components() {
            match c {
                Component::RootDir => *out = PathBuf::from("/"),
                Component::CurDir | Component::Prefix(_) => {}
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(n) => {
                    let next = out.join(n);
                    match std::fs::read_link(&next) {
                        Ok(target) => {
                            *seen = seen.saturating_add(1);
                            if *seen > 40 {
                                *out = next;
                                continue;
                            }
                            walk(out, &target, seen)?;
                        }
                        Err(_) => *out = next,
                    }
                }
            }
        }
        Ok(())
    }
    let start = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        std::env::current_dir().at(Path::new("."))?
    };
    let mut out = start;
    let mut seen = 0;
    walk(&mut out, path, &mut seen)?;
    Ok(out)
}

pub struct Options {
    pub root: PathBuf,
    pub stage: PathBuf,
    pub install: InstallOptions,
    pub dry_run: bool,
    /// With `dry_run`: print the plan as JSON.
    pub json: bool,
    pub packages: Vec<String>,
}

/// `debbuild-rs install`: lock the database, plan, and install (or print the plan).
///
/// # Errors
/// Any error of the run, to print as `debbuild-rs install: error: <message>`.
pub fn run(opts: &Options, exec: &dyn Exec) -> Result<()> {
    let root = realpath(&opts.root)?;
    let mut db = Database::new(&root);
    let _lock = db.lock()?;
    db.check_interrupted()?;
    db.load()?;
    for w in &db.warnings {
        // On stderr, as dpkg prints them: stdout may be the dry run's JSON.
        let _ = writeln!(std::io::stderr(), "debbuild-rs install: warning: {w}");
    }
    let staged = load_staged(&opts.stage)?;
    let plan = plan(&db, &staged, &opts.packages)?;
    if opts.dry_run {
        let steps = action::steps(&db, &plan, opts.install.reinstall)?;
        let text = if opts.json {
            action::json(&steps)
        } else {
            action::text(&steps)
        };
        let mut out = std::io::stdout().lock();
        out.write_all(text.as_bytes()).at(Path::new("<stdout>"))?;
        return Ok(());
    }
    Installer::new(db, opts.install, exec).install(&plan.packages)
}
