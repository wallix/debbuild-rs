//! `debbuild-rs check --vs-oracle OLD`: the differential harness of the Rust installer
//! against another installer (OLD, for instance another version of it) and against dpkg.
//!
//! Each scenario runs on fresh overlays of ROOT, one per side: `dpkg` (.deb files packed
//! from the staged trees, `dpkg -i`), `old` and `new` (`debbuild-rs install`). After every
//! round each side is snapshotted and compared at once, so a later round cannot mask a
//! difference:
//! - old vs new, strictly: exit status, transcript (root paths normalized), every touched
//!   path (type, mode, numeric owner, content or target, the mtime of regular files the
//!   packages list unless a script rewrote them in the round, hard-link classes),
//!   var/lib/dpkg included. The only accepted differences are the deliberate ones of the
//!   scenario (H2 to H8), and those of the installer's own state and messages:
//!   - var/lib/debbuild-rs is compared by the packages that have a digest there, not by
//!     the digests: their format is the installer's own (new hashes the control files'
//!     modes);
//!   - new records a package's digest when its unpack completes, old once it is
//!     configured: a package new leaves unpacked or half-configured may have a digest on
//!     new only, and an unchanged half-configured one is only configured again by new
//!     where old reinstalls it (script-failures, last round);
//!   - the --force-overwrite warning names `(--force-overwrite)` where old names
//!     `(--force)`;
//! - new vs dpkg, relaxed: check-against-dpkg.sh's ignored paths, status compared stanza
//!   by stanza (dpkg's triggers-pending/-awaited against our installed allowed), no
//!   mtimes, no transcripts. The differences are reported; those old vs dpkg shares are
//!   the designed ones, any other one fails.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::ck::{build_debs, self_exe, upgraded_copy};
use crate::fixtures::{Entry, Pkg, file, link, stage_pkg, truncate_member};
use crate::manifest::{hardlink_classes, strict_line, touched, touched_all};
use crate::mounts::{Work, policy_rc_d};
use crate::util::{Context, Result, cmd, err, mkdirs, run, staged_tree, text, transcript};

pub struct Options {
    pub root: PathBuf,
    pub stagedir: PathBuf,
    pub workdir: Option<PathBuf>,
    /// The other installer.
    pub oracle: PathBuf,
    /// Scenarios to run (empty: all).
    pub scenarios: Vec<String>,
    pub packages: Vec<String>,
}

pub const SCENARIOS: &[(&str, &str)] = &[
    (
        "upgrade",
        "the packages: fresh install, unchanged rerun, conffiles modified/deleted/symlinked locally, upgrade (+u1), forced reinstall",
    ),
    (
        "statoverride",
        "the packages, with dpkg-statoverride entries for some of their paths",
    ),
    (
        "failing-postinst",
        "the packages, the last one with a postinst failing, then the original ones",
    ),
    (
        "conffiles",
        "fixture: every conffile case of an upgrade, then a forced one",
    ),
    (
        "obsolete-conffiles",
        "fixture: obsolete and remove-on-upgrade conffiles",
    ),
    (
        "replaces",
        "fixture: a file of another package, without then with Replaces",
    ),
    (
        "symlinks",
        "fixture: symlinked directories, a file becoming a directory, a directory kept against a symlink",
    ),
    (
        "obsolete-files",
        "fixture: files removed by an upgrade, a non-empty directory kept",
    ),
    (
        "triggers",
        "fixture: file and explicit triggers (dpkg-trigger), activation by removal",
    ),
    (
        "script-failures",
        "fixture: failing prerm, preinst and unpack, and their unwinding",
    ),
    (
        "pre-depends",
        "fixture: Pre-Depends configured before the unpack",
    ),
    ("md5sums", "fixture: a package without md5sums"),
    ("hardlink", "fixture: a hard link in data.tar"),
    (
        "statedir",
        "fixture: an unpacked package's info files and var/lib/debbuild-rs state",
    ),
    ("h2-env", "H2: the maintainer scripts' environment"),
    (
        "h3-statedir-escape",
        "H3: var/lib/debbuild-rs, a symlink out of the root",
    ),
    (
        "h4-admindir-escape",
        "H4: var/lib/dpkg/info, a symlink out of the root",
    ),
    ("h5-bad-trigger", "H5: an unknown DEBIAN/triggers directive"),
    (
        "hardlink-symlink",
        "fixture: a hard-link member to a symlink out of the root",
    ),
    (
        "h8-backup-escape",
        "H8: a forced upgrade's .dpkg-old, a symlink out of the root",
    ),
    (
        "truncated-member",
        "fixture: upgrades whose data.tar ends inside a file, then a conffile (data.tar.sha256 matching)",
    ),
    ("h6-sparse", "H6: a GNU sparse member"),
    ("h7-corrupt", "H7: data.tar not matching data.tar.sha256"),
    (
        "unchanged-forced",
        "fixture: an unchanged rerun, then --force",
    ),
    (
        "multi",
        "fixture: several packages, alternatives and Provides",
    ),
    (
        "existing-dir",
        "fixture: a directory of the package already there, other owner and mode (Q5)",
    ),
];

/// One side of a scenario.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Side {
    Dpkg,
    Old,
    New,
}

impl Side {
    fn name(self) -> &'static str {
        match self {
            Side::Dpkg => "dpkg",
            Side::Old => "old",
            Side::New => "new",
        }
    }
}

/// What a round left on one side.
struct Snapshot {
    rc: i32,
    transcript: String,
    /// path -> strict manifest line (with mtime when relevant).
    strict: BTreeMap<String, String>,
    /// path -> relaxed manifest line.
    relaxed: BTreeMap<String, String>,
    hardlinks: Vec<String>,
    /// The names in var/lib/debbuild-rs: the packages with a recorded digest.
    state: BTreeSet<String>,
    /// Status stanzas by package key, as written.
    status: BTreeMap<String, String>,
}

/// The outcome of the run: per scenario and round, the differences found.
#[derive(Default)]
pub struct Report {
    pub lines: Vec<String>,
    pub failed: bool,
}

impl Report {
    fn say(&mut self, s: impl Into<String>) {
        let s = s.into();
        println!("{s}");
        self.lines.push(s);
    }
}

struct Scenario<'a> {
    name: &'static str,
    opts: &'a Options,
    work: Work,
    roots: BTreeMap<Side, PathBuf>,
    sides: Vec<Side>,
    round: u32,
    /// path -> mtime of the data.tar members installed so far (the last round's).
    headers: BTreeMap<String, u64>,
    report: &'a mut Report,
    /// Accepted old vs new differences of this scenario, by round.
    accept: Acceptor<'a>,
    /// Run after each side's install, before its snapshot.
    after_side: Option<Box<dyn FnMut(Side) + 'a>>,
}

/// The old vs new differences a scenario accepts, given the round and the differences.
type Acceptor<'a> = Box<dyn Fn(u32, &Diffs) -> Accepted + 'a>;

/// The differences of one comparison.
#[derive(Default, Debug)]
struct Diffs {
    lines: Vec<String>,
    rc: Option<(i32, i32)>,
    transcript: Option<(String, String)>,
    /// Script outputs that differ between any two runs (generated keys, ...): counted.
    volatile: u32,
}

/// What maintainer scripts generate differently on every run: keys and certificates,
/// the installation history, ldconfig's cache, pid files. Compared but for their
/// content.
fn volatile(path: &str, a: &str, b: &str) -> bool {
    random_output(path) && mask(path, a) == mask(path, b)
}

fn random_output(path: &str) -> bool {
    [".pem", ".key", ".key.pub", ".crt", ".pid"]
        .iter()
        .any(|s| path.ends_with(s))
        || [
            "/etc/product_installation_history",
            "/var/cache/ldconfig/aux-cache",
        ]
        .contains(&path)
}

/// A manifest line without the content of a random script output.
fn mask(path: &str, line: &str) -> String {
    if random_output(path) {
        line.split(' ').take(4).collect::<Vec<_>>().join(" ")
    } else {
        line.to_owned()
    }
}

/// A transcript without what varies between runs: timestamps and openssl's key
/// generation progress lines.
fn stable_transcript(t: &str) -> Vec<String> {
    t.lines()
        .filter(|l| {
            let l = l.trim();
            !(l.len() >= 10 && l.chars().all(|c| matches!(c, '.' | '+' | '*')))
        })
        .map(|l| {
            // The option the --force-overwrite warning names, as old named it.
            let l = l.replace("(--force-overwrite)", "(--force)");
            let l = l.as_str();
            // YYYY-MM-DD HH:MM:SS[,mmm]
            let b = l.as_bytes();
            let mut out = String::new();
            let mut i = 0;
            while i < b.len() {
                let ts = b.get(i..i.saturating_add(19)).is_some_and(|w| {
                    w.iter().enumerate().all(|(j, c)| match j {
                        4 | 7 => *c == b'-',
                        10 => *c == b' ' || *c == b'T',
                        13 | 16 => *c == b':',
                        _ => c.is_ascii_digit(),
                    })
                });
                if ts {
                    out.push_str("<TS>");
                    i = i.saturating_add(19);
                    while b
                        .get(i)
                        .is_some_and(|c| *c == b',' || *c == b'.' || c.is_ascii_digit())
                    {
                        i = i.saturating_add(1);
                    }
                } else {
                    let ch = l.get(i..).and_then(|r| r.chars().next()).unwrap_or(' ');
                    out.push(ch);
                    i = i.saturating_add(ch.len_utf8());
                }
            }
            out
        })
        .collect()
}

/// What a scenario says of the old vs new differences of a round.
enum Accepted {
    /// None expected: any difference fails.
    Nothing,
    /// These are the deliberate ones: the check passes when the predicate does.
    Exactly(bool, String),
}

fn normalize(out: &[u8], root: &Path, work: &Path) -> String {
    text(out)
        .replace(&root.display().to_string(), "<ROOT>")
        .replace(&work.display().to_string(), "<WORK>")
}

fn read_status(root: &Path) -> BTreeMap<String, String> {
    let text = fs::read_to_string(root.join("var/lib/dpkg/status")).unwrap_or_default();
    let mut out = BTreeMap::new();
    for stanza in text.split("\n\n").filter(|s| !s.trim().is_empty()) {
        let mut key = String::new();
        let mut arch = String::new();
        let mut same = false;
        for l in stanza.lines() {
            if let Some(v) = l.strip_prefix("Package: ") {
                v.clone_into(&mut key);
            } else if let Some(v) = l.strip_prefix("Architecture: ") {
                v.clone_into(&mut arch);
            } else if l == "Multi-Arch: same" {
                same = true;
            }
        }
        if same {
            key = format!("{key}:{arch}");
        }
        out.insert(key, format!("{}\n", stanza.trim_start_matches('\n')));
    }
    out
}

/// The packages' listed paths in `root` (info/*.list).
fn listed(root: &Path) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let info = root.join("var/lib/dpkg/info");
    if let Ok(rd) = fs::read_dir(&info) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().ends_with(".list")
                && let Ok(t) = fs::read(e.path())
            {
                out.extend(text(&t).lines().map(str::to_owned));
            }
        }
    }
    out
}

/// Whether state file `name` is the digest of a package `snap` has unpacked or
/// half-configured: new records it when the unpack completes, old once configured.
fn unpacked_on(snap: &Snapshot, name: &str) -> bool {
    name.strip_suffix(".sha256")
        .and_then(|pkg| snap.status.get(pkg))
        .is_some_and(|s| {
            s.lines().any(|l| {
                l.strip_prefix("Status: ")
                    .is_some_and(|v| v.ends_with(" unpacked") || v.ends_with(" half-configured"))
            })
        })
}

/// The difference between old's and new's var/lib/debbuild-rs: the packages with a
/// digest on one side only, but those new has unpacked or half-configured.
fn state_diff(old: &Snapshot, new: &Snapshot) -> Option<String> {
    let only_old: Vec<&String> = old.state.difference(&new.state).collect();
    let only_new: Vec<&String> = new
        .state
        .difference(&old.state)
        .filter(|n| !unpacked_on(new, n))
        .collect();
    (!only_old.is_empty() || !only_new.is_empty())
        .then(|| format!("var/lib/debbuild-rs: - {only_old:?}\n+ {only_new:?}"))
}

/// Without the Status field, when dpkg's state is a triggers state and ours installed.
fn relax_status(dpkg: &str, ours: &str) -> (String, String) {
    let status = |s: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix("Status: "))
            .map(str::to_owned)
    };
    let (d, o) = (status(dpkg), status(ours));
    let triggers = d
        .as_deref()
        .is_some_and(|d| d.ends_with("triggers-pending") || d.ends_with("triggers-awaited"));
    let installed = o.as_deref().is_some_and(|o| o.ends_with(" installed"));
    if triggers && installed {
        let strip = |s: &str| -> String {
            s.split_inclusive('\n')
                .filter(|l| {
                    !l.starts_with("Status:")
                        && !l.starts_with("Triggers-Pending:")
                        && !l.starts_with("Triggers-Awaited:")
                })
                .collect()
        };
        (strip(dpkg), strip(ours))
    } else {
        (dpkg.to_owned(), ours.to_owned())
    }
}

impl<'a> Scenario<'a> {
    fn new(
        name: &'static str,
        opts: &'a Options,
        report: &'a mut Report,
        sides: &[Side],
        root: Option<&Path>,
    ) -> Result<Self> {
        let mut work = Work::new(opts.workdir.as_deref())?;
        let mut roots = BTreeMap::new();
        for s in sides {
            // a synthetic root is copied per side
            let merged = if let Some(r) = root {
                let d = work.dir.join(s.name()).join("merged");
                mkdirs(&work.dir.join(s.name()))?;
                run(Command::new("cp").arg("-a").arg(r).arg(&d))?;
                d
            } else {
                let m = work.overlay(&opts.root, s.name())?;
                policy_rc_d(&m)?;
                m
            };
            roots.insert(*s, merged);
        }
        report.say(format!("=== scenario {name}"));
        Ok(Self {
            name,
            opts,
            work,
            roots,
            sides: sides.to_vec(),
            round: 0,
            headers: BTreeMap::new(),
            report,
            accept: Box::new(|_, _| Accepted::Nothing),
            after_side: None,
        })
    }

    fn root(&self, s: Side) -> &Path {
        self.roots
            .get(&s)
            .map_or(Path::new("/nonexistent"), PathBuf::as_path)
    }

    fn fixtures(&self) -> PathBuf {
        self.work.dir.join("fixtures")
    }

    /// Run `script` (sh) on every side, with ROOT set to its root.
    fn mutate(&mut self, script: &str) -> Result<()> {
        for s in self.sides.clone() {
            run(cmd("sh", ["-c", script]).env("ROOT", self.root(s)))?;
        }
        Ok(())
    }

    /// Install `pkgs` from `stage` on every side (dpkg too unless `dpkg` is false).
    fn install(
        &mut self,
        label: &str,
        stage: &Path,
        pkgs: &[String],
        force: bool,
        dpkg: bool,
    ) -> Result<()> {
        self.round = self.round.saturating_add(1);
        self.index_headers(stage, pkgs)?;
        let mut snaps: BTreeMap<Side, Snapshot> = BTreeMap::new();
        for s in self.sides.clone() {
            let root = self.root(s).to_path_buf();
            let (rc, out) = match s {
                Side::Dpkg if !dpkg => continue,
                Side::Dpkg => {
                    let debs = root.join(format!("tmp/debs-{}", self.round));
                    build_debs(&self.work.dir, stage, &debs, pkgs)?;
                    // debbuild-rs install takes --force-confold where dpkg would prompt, and
                    // --force-confnew --force-overwrite with --force.
                    let force = if force {
                        "--force-confnew --force-overwrite "
                    } else {
                        "--force-confold "
                    };
                    transcript(
                        Command::new("chroot")
                            .arg(&root)
                            .args([
                                "sh",
                                "-c",
                                &format!("dpkg -i {force}/tmp/debs-{}/*.deb", self.round),
                            ])
                            .env("DEBIAN_FRONTEND", "noninteractive"),
                    )?
                }
                Side::Old | Side::New => {
                    let mut c = if s == Side::Old {
                        Command::new(&self.opts.oracle)
                    } else {
                        let mut c = Command::new(self_exe()?);
                        c.arg("install");
                        c
                    };
                    c.arg("--root").arg(&root).arg("--stage").arg(stage);
                    if force {
                        c.arg("--force");
                    }
                    c.args(pkgs).env("DEBIAN_FRONTEND", "noninteractive");
                    transcript(&mut c)?
                }
            };
            if let Some(h) = self.after_side.as_mut() {
                h(s);
            }
            snaps.insert(s, self.snapshot(s, rc, &out)?);
        }
        self.compare(label, &snaps);
        Ok(())
    }

    fn snapshot(&self, s: Side, rc: i32, out: &[u8]) -> Result<Snapshot> {
        let root = self.root(s);
        let upper = match fs::metadata(self.work.upper(s.name())) {
            Ok(_) => self.work.upper(s.name()),
            Err(_) => root.to_path_buf(),
        };
        let strict_paths: Vec<String> = touched_all(&[&upper])?
            .into_iter()
            .filter(|p| !(p.starts_with("/tmp/") || p == "/tmp" || p == "/usr/sbin/policy-rc.d"))
            .collect();
        let listed = listed(root);
        let mut strict = BTreeMap::new();
        // var/lib/debbuild-rs/*: compared as `state`.
        for p in strict_paths
            .iter()
            .filter(|p| !p.starts_with("/var/lib/debbuild-rs/"))
        {
            let generated =
                p.starts_with("/var/lib/dpkg/") || p.starts_with("/var/lib/debbuild-rs/");
            let line = strict_line(root, p, listed.contains(p) && !generated);
            strict.insert(p.clone(), line);
        }
        let relaxed_paths = touched(&[&upper], &["var/lib/dpkg/status"])?;
        let mut relaxed = BTreeMap::new();
        for p in &relaxed_paths {
            relaxed.insert(p.clone(), strict_line(root, p, false));
        }
        let mut state = BTreeSet::new();
        if let Ok(rd) = fs::read_dir(root.join("var/lib/debbuild-rs")) {
            for e in rd.flatten() {
                state.insert(e.file_name().to_string_lossy().into_owned());
            }
        }
        Ok(Snapshot {
            rc,
            transcript: normalize(out, root, &self.work.dir),
            hardlinks: hardlink_classes(root, &strict_paths),
            strict,
            relaxed,
            state,
            status: read_status(root),
        })
    }

    /// A path whose content a script rewrote during the round (mtime after its start)
    /// on both sides: its mtime is not compared.
    /// Whether a regular file's mtime difference is not the installer's: the file is
    /// not from a data.tar of the scenario, or neither side kept the member's mtime
    /// (a script rewrote it on both, at different times).
    fn not_extracted(&self, path: &str, a: &str, b: &str) -> bool {
        let mtime =
            |l: &str| -> Option<u64> { l.rsplit_once(" mtime ").and_then(|(_, t)| t.parse().ok()) };
        match self.headers.get(path) {
            None => true,
            Some(h) => mtime(a) != Some(*h) && mtime(b) != Some(*h),
        }
    }

    /// Record the members' mtimes of the data.tar files of `pkgs` in `stage`.
    fn index_headers(&mut self, stage: &Path, pkgs: &[String]) -> Result<()> {
        for p in pkgs {
            let tar = staged_tree(stage, p)?.join("data.tar");
            let f = fs::File::open(&tar).ctx(tar.display())?;
            let mut ar = tar::Archive::new(f);
            // a truncated archive (truncated-member) is indexed up to the cut
            for e in ar.entries().ctx(tar.display())? {
                let Ok(e) = e else { break };
                if e.header().entry_type().is_file() {
                    let name = text(&e.path_bytes());
                    let path = format!("/{}", name.trim_start_matches("./"));
                    self.headers.insert(path, e.header().mtime().unwrap_or(0));
                }
            }
        }
        Ok(())
    }

    fn strict_diffs(&self, a: &Snapshot, b: &Snapshot) -> Diffs {
        let mut d = Diffs::default();
        if a.rc != b.rc {
            d.rc = Some((a.rc, b.rc));
        }
        if stable_transcript(&a.transcript) != stable_transcript(&b.transcript) {
            d.transcript = Some((a.transcript.clone(), b.transcript.clone()));
        }
        let keys: std::collections::BTreeSet<&String> =
            a.strict.keys().chain(b.strict.keys()).collect();
        for k in keys {
            let (la, lb) = (a.strict.get(k), b.strict.get(k));
            let (la, lb) = (
                la.cloned()
                    .unwrap_or_else(|| strict_line(self.root(Side::Old), k, false)),
                lb.cloned()
                    .unwrap_or_else(|| strict_line(self.root(Side::New), k, false)),
            );
            if la != lb {
                let strip = |l: &str| {
                    l.rsplit_once(" mtime ")
                        .map_or(l.to_owned(), |(h, _)| h.to_owned())
                };
                if strip(&la) == strip(&lb) && self.not_extracted(k, &la, &lb) {
                    continue;
                }
                if volatile(k, &la, &lb) {
                    d.volatile = d.volatile.saturating_add(1);
                    continue;
                }
                d.lines.push(format!("- {la}\n+ {lb}"));
            }
        }
        if a.hardlinks != b.hardlinks {
            d.lines
                .push(format!("- {:?}\n+ {:?}", a.hardlinks, b.hardlinks));
        }
        d.lines.extend(state_diff(a, b));
        d
    }

    fn relaxed_diffs(&self, dpkg: &Snapshot, ours: &Snapshot, ours_side: Side) -> Vec<String> {
        let mut out = Vec::new();
        let keys: std::collections::BTreeSet<&String> =
            dpkg.relaxed.keys().chain(ours.relaxed.keys()).collect();
        for k in keys {
            let la = dpkg
                .relaxed
                .get(k)
                .cloned()
                .unwrap_or_else(|| strict_line(self.root(Side::Dpkg), k, false));
            let lb = ours
                .relaxed
                .get(k)
                .cloned()
                .unwrap_or_else(|| strict_line(self.root(ours_side), k, false));
            let (la, lb) = (mask(k, &la), mask(k, &lb));
            if la != lb {
                out.push(format!("- {la}\n+ {lb}"));
            }
        }
        let keys: std::collections::BTreeSet<&String> =
            dpkg.status.keys().chain(ours.status.keys()).collect();
        for k in keys {
            let (sa, sb) = (
                dpkg.status.get(k).cloned().unwrap_or_default(),
                ours.status.get(k).cloned().unwrap_or_default(),
            );
            let (sa, sb) = relax_status(&sa, &sb);
            if sa != sb {
                out.push(format!(
                    "status {k}:\n- {}\n+ {}",
                    sa.trim_end().replace('\n', "\n- "),
                    sb.trim_end().replace('\n', "\n+ ")
                ));
            }
        }
        out
    }

    fn compare(&mut self, label: &str, snaps: &BTreeMap<Side, Snapshot>) {
        let round = self.round;
        let head = format!("--- {} round {round} ({label})", self.name);
        let mut lines = vec![head];
        for (s, snap) in snaps {
            lines.push(format!("{}: rc {}", s.name(), snap.rc));
            if snap.rc != 0 {
                let tail: Vec<&str> = snap.transcript.lines().rev().take(4).collect();
                for l in tail.into_iter().rev() {
                    lines.push(format!("  | {l}"));
                }
            }
        }
        let mut failed = false;
        if let (Some(old), Some(new)) = (snaps.get(&Side::Old), snaps.get(&Side::New)) {
            let d = self.strict_diffs(old, new);
            let clean = d.lines.is_empty() && d.rc.is_none() && d.transcript.is_none();
            if d.volatile > 0 {
                lines.push(format!(
                    "old vs new: {} script outputs differ as on any run (keys, history)",
                    d.volatile
                ));
            }
            match (self.accept)(round, &d) {
                Accepted::Nothing if clean => lines.push("old vs new: identical".to_owned()),
                Accepted::Nothing => {
                    failed = true;
                    lines.push("old vs new: DIFFERENT".to_owned());
                    if let Some((a, b)) = &d.rc {
                        lines.push(format!("  rc {a} != {b}"));
                    }
                    if let Some((a, b)) = &d.transcript {
                        lines.push(format!("  transcript old:\n{a}  transcript new:\n{b}"));
                    }
                    for l in &d.lines {
                        lines.push(format!("  {l}"));
                    }
                }
                Accepted::Exactly(true, why) => {
                    lines.push(format!("old vs new: only the deliberate difference: {why}"));
                }
                Accepted::Exactly(false, why) => {
                    failed = true;
                    lines.push(format!("old vs new: NOT the expected difference: {why}"));
                    lines.push(format!("  {d:#?}"));
                }
            }
        }
        if let Some(dpkg) = snaps.get(&Side::Dpkg) {
            for ours in [Side::Old, Side::New] {
                if let Some(o) = snaps.get(&ours) {
                    let d = self.relaxed_diffs(dpkg, o, ours);
                    if d.is_empty() {
                        lines.push(format!("{} vs dpkg: identical", ours.name()));
                    } else {
                        lines.push(format!("{} vs dpkg: {} differences", ours.name(), d.len()));
                        for l in d {
                            lines.push(format!("  {l}"));
                        }
                    }
                }
            }
            if let (Some(old), Some(new)) = (snaps.get(&Side::Old), snaps.get(&Side::New)) {
                let (a, b) = (
                    self.relaxed_diffs(dpkg, old, Side::Old),
                    self.relaxed_diffs(dpkg, new, Side::New),
                );
                if a != b {
                    // new vs dpkg must differ exactly as old vs dpkg did, but for the
                    // deliberate changes the scenario accepted.
                    if matches!((self.accept)(round, &Diffs::default()), Accepted::Nothing) {
                        failed = true;
                        lines.push("new vs dpkg: differs from old vs dpkg".to_owned());
                    }
                }
            }
        }
        if failed {
            self.report.failed = true;
            lines.push("RESULT: FAIL".to_owned());
        } else {
            lines.push("RESULT: ok".to_owned());
        }
        for l in lines {
            self.report.say(l);
        }
    }
}

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

const ALL: [Side; 3] = [Side::Dpkg, Side::Old, Side::New];
const OURS: [Side; 2] = [Side::Old, Side::New];

/// The planned packages of the run, on a scratch overlay.
fn plan_packages(opts: &Options) -> Result<Vec<String>> {
    let mut work = Work::new(opts.workdir.as_deref())?;
    let m = work.overlay(&opts.root, "plan")?;
    crate::ck::planned(&m, &opts.stagedir, &opts.packages)
}

fn conffiles_of(stagedir: &Path, pkgs: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for p in pkgs {
        let c = staged_tree(stagedir, p)?.join("DEBIAN/conffiles");
        if let Ok(t) = fs::read(&c) {
            for l in text(&t).lines() {
                if !l.starts_with("remove-on-upgrade") && !l.trim().is_empty() {
                    out.push(l.trim().to_owned());
                }
            }
        }
    }
    Ok(out)
}

fn scenario_upgrade(opts: &Options, report: &mut Report, pkgs: &[String]) -> Result<()> {
    let mut sc = Scenario::new("upgrade", opts, report, &ALL, None)?;
    sc.install("fresh install", &opts.stagedir, pkgs, false, true)?;
    sc.install("unchanged rerun", &opts.stagedir, pkgs, false, false)?;
    let mut script = String::new();
    for (i, c) in conffiles_of(&opts.stagedir, pkgs)?.iter().enumerate() {
        let q = format!("\"$ROOT{c}\"");
        let _ = match i % 3 {
            0 => writeln!(script, "[ -f {q} ] && [ ! -L {q} ] && echo '# local' >>{q}"),
            1 => writeln!(script, "[ -f {q} ] && [ ! -L {q} ] && rm -f {q}"),
            _ => writeln!(
                script,
                "[ -f {q} ] && [ ! -L {q} ] && mv {q} {q}.real && ln -s \"$(basename {q}).real\" {q}"
            ),
        };
    }
    script.push_str("true\n");
    sc.mutate(&script)?;
    let u = sc.work.dir.join("stage-u");
    upgraded_copy(&sc.work.dir, &opts.stagedir, &u, pkgs)?;
    sc.install("upgrade to +u1", &u, pkgs, false, true)?;
    sc.install("forced reinstall", &u, pkgs, true, true)?;
    Ok(())
}

fn scenario_statoverride(opts: &Options, report: &mut Report, pkgs: &[String]) -> Result<()> {
    let mut sc = Scenario::new("statoverride", opts, report, &ALL, None)?;
    // a directory and a file of the first package that has both, not in ROOT already
    let mut lines = String::new();
    for p in pkgs {
        let tar = staged_tree(&opts.stagedir, p)?.join("data.tar");
        let list = crate::util::output(Command::new("tar").arg("-tvf").arg(&tar))?;
        let mut dir = None;
        let mut reg = None;
        for l in text(&list).lines() {
            let path = l
                .split_whitespace()
                .nth(5)
                .unwrap_or_default()
                .trim_start_matches('.')
                .trim_end_matches('/');
            if path.is_empty() || opts.root.join(path.trim_start_matches('/')).exists() {
                continue;
            }
            if l.starts_with('d') && dir.is_none() {
                dir = Some(path.to_owned());
            } else if l.starts_with('-') && reg.is_none() {
                reg = Some(path.to_owned());
            }
        }
        if let (Some(d), Some(f)) = (dir, reg) {
            let _ = writeln!(lines, "root root 0700 {d}\nroot root 4750 {f}");
            break;
        }
    }
    sc.mutate(&format!(
        "printf '%s' '{lines}' >>\"$ROOT/var/lib/dpkg/statoverride\""
    ))?;
    sc.report.say(format!("statoverride entries:\n{lines}"));
    sc.install("fresh install", &opts.stagedir, pkgs, false, true)?;
    Ok(())
}

fn scenario_failing_postinst(opts: &Options, report: &mut Report, pkgs: &[String]) -> Result<()> {
    let mut sc = Scenario::new("failing-postinst", opts, report, &ALL, None)?;
    let b = sc.work.dir.join("stage-broken");
    let mut broken = None;
    for p in pkgs.iter().rev() {
        let tree = staged_tree(&opts.stagedir, p)?;
        if tree.join("DEBIAN/postinst").is_file() {
            broken = Some(p.clone());
            break;
        }
    }
    let Some(broken) = broken else {
        sc.report.say("no package with a postinst: skipped");
        return Ok(());
    };
    for p in pkgs {
        let tree = staged_tree(&opts.stagedir, p)?;
        let dir = tree.parent().and_then(Path::file_name).unwrap_or_default();
        let o = b.join(dir);
        mkdirs(&o)?;
        crate::util::cp_a(&tree, &o.join(p))?;
        if *p == broken {
            let pi = o.join(p).join("DEBIAN/postinst");
            let t = text(&fs::read(&pi).ctx(pi.display())?);
            let (first, rest) = t.split_once('\n').unwrap_or((&t, ""));
            fs::write(
                &pi,
                format!("{first}\necho debbuild-rs-check: failing on purpose >&2; exit 1\n{rest}"),
            )
            .ctx(pi.display())?;
            // its digest changes with its postinst
        }
    }
    sc.report.say(format!("failing postinst: {broken}"));
    sc.install("failing postinst", &b, pkgs, false, true)?;
    sc.install("original packages", &opts.stagedir, pkgs, false, true)?;
    Ok(())
}

/// A fixture scenario: stage versions with `stage`, install with `install`.
struct Fx<'a, 'b> {
    sc: Scenario<'b>,
    _p: std::marker::PhantomData<&'a ()>,
}

impl Fx<'_, '_> {
    fn stage(&self, p: &Pkg<'_>) -> Result<()> {
        stage_pkg(&self.sc.fixtures(), p).map(|_| ())
    }

    fn install(&mut self, label: &str, pkgs: &[&str], force: bool) -> Result<()> {
        let stage = self.sc.fixtures();
        self.sc.install(label, &stage, &names(pkgs), force, true)
    }

    fn install_ours(&mut self, label: &str, pkgs: &[&str], force: bool) -> Result<()> {
        let stage = self.sc.fixtures();
        self.sc.install(label, &stage, &names(pkgs), force, false)
    }
}

fn fx<'b>(
    name: &'static str,
    opts: &'b Options,
    report: &'b mut Report,
) -> Result<Fx<'static, 'b>> {
    Ok(Fx {
        sc: Scenario::new(name, opts, report, &ALL, None)?,
        _p: std::marker::PhantomData,
    })
}

fn pkg<'a>(name: &'a str, version: &'a str, files: Vec<(&'a str, Entry)>) -> Pkg<'a> {
    Pkg {
        name,
        version,
        files,
        ..Pkg::default()
    }
}

fn scenario_conffiles(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("conffiles", opts, report)?;
    let conf = vec![
        "/etc/dc/a",
        "/etc/dc/b",
        "/etc/dc/c",
        "/etc/dc/d",
        "/etc/dc/e",
        "/etc/dc/f",
    ];
    f.sc.mutate("mkdir -p \"$ROOT/etc/dc\" && echo pre >\"$ROOT/etc/dc/f\"")?;
    let v = |ver: &'static str, content: &'static str| Pkg {
        conffiles: conf.clone(),
        ..pkg(
            "dc-conf",
            ver,
            vec![
                ("/etc/dc/a", file(content)),
                ("/etc/dc/b", file(content)),
                ("/etc/dc/c", file(content)),
                ("/etc/dc/d", file(content)),
                ("/etc/dc/e", file("same\n")),
                ("/etc/dc/f", file(content)),
            ],
        )
    };
    f.stage(&v("1", "A\n"))?;
    f.install("fresh, one conffile existing", &["dc-conf"], false)?;
    // b modified, c deleted, d a symlink, e modified (unchanged in the package)
    f.sc.mutate(
        "cd \"$ROOT/etc/dc\" && echo local >>b && rm c && mv d d.real && ln -s d.real d && echo local >>e",
    )?;
    f.stage(&v("2", "B\n"))?;
    f.install("upgrade", &["dc-conf"], false)?;
    f.sc.mutate("cd \"$ROOT/etc/dc\" && echo local2 >>a")?;
    f.stage(&v("3", "C\n"))?;
    f.install("forced upgrade", &["dc-conf"], true)?;
    Ok(())
}

fn scenario_obsolete_conffiles(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("obsolete-conffiles", opts, report)?;
    f.stage(&Pkg {
        conffiles: vec!["/etc/dc/a", "/etc/dc/b", "/etc/dc/r", "/etc/dc/r2"],
        ..pkg(
            "dc-obs",
            "1",
            vec![
                ("/etc/dc/a", file("a\n")),
                ("/etc/dc/b", file("b\n")),
                ("/etc/dc/r", file("r\n")),
                ("/etc/dc/r2", file("r2\n")),
            ],
        )
    })?;
    f.install("fresh", &["dc-obs"], false)?;
    f.sc.mutate("echo local >>\"$ROOT/etc/dc/r2\"")?;
    f.stage(&Pkg {
        conffiles: vec![
            "/etc/dc/a",
            "remove-on-upgrade /etc/dc/r",
            "remove-on-upgrade /etc/dc/r2",
        ],
        ..pkg("dc-obs", "2", vec![("/etc/dc/a", file("a\n"))])
    })?;
    f.install("b obsolete, r and r2 remove-on-upgrade", &["dc-obs"], false)?;
    f.stage(&Pkg {
        conffiles: vec!["/etc/dc/a"],
        ..pkg("dc-obs", "3", vec![("/etc/dc/a", file("a\n"))])
    })?;
    f.install("b still obsolete", &["dc-obs"], false)?;
    Ok(())
}

fn scenario_replaces(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("replaces", opts, report)?;
    f.stage(&pkg(
        "dc-a",
        "1",
        vec![
            ("/usr/share/dc-rep/x", file("a\n")),
            ("/usr/share/dc-rep/y", file("y\n")),
        ],
    ))?;
    f.install("a", &["dc-a"], false)?;
    f.stage(&pkg(
        "dc-b",
        "1",
        vec![("/usr/share/dc-rep/x", file("b\n"))],
    ))?;
    f.install("b without Replaces", &["dc-b"], false)?;
    f.stage(&Pkg {
        control: vec![("Replaces", "dc-a (<< 2)")],
        ..pkg("dc-b", "1", vec![("/usr/share/dc-rep/x", file("b\n"))])
    })?;
    f.install("b with Replaces", &["dc-b"], false)?;
    Ok(())
}

fn scenario_symlinks(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("symlinks", opts, report)?;
    f.sc.mutate("mkdir -p \"$ROOT/opt/dc-d\" && touch \"$ROOT/opt/dc-d/keep\"")?;
    f.stage(&pkg(
        "dc-sym",
        "1",
        vec![
            ("/lib/dc-foo/f", file("f\n")),
            ("/usr/share/dc-fd", file("file\n")),
        ],
    ))?;
    f.install("through /lib", &["dc-sym"], false)?;
    f.stage(&pkg(
        "dc-sym",
        "2",
        vec![
            ("/usr/lib/dc-foo/f", file("f\n")),
            ("/usr/share/dc-fd/x", file("x\n")),
            ("/opt/dc-d", link("/usr/lib")),
        ],
    ))?;
    f.install(
        "moved to /usr/lib, file to directory, directory against symlink",
        &["dc-sym"],
        false,
    )?;
    Ok(())
}

fn scenario_obsolete_files(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("obsolete-files", opts, report)?;
    f.stage(&pkg(
        "dc-of",
        "1",
        vec![
            ("/usr/share/dc-of/a", file("a\n")),
            ("/usr/share/dc-of/old/b", file("b\n")),
        ],
    ))?;
    f.install("fresh", &["dc-of"], false)?;
    f.sc.mutate("touch \"$ROOT/usr/share/dc-of/old/local\"")?;
    f.stage(&pkg(
        "dc-of",
        "2",
        vec![("/usr/share/dc-of/a", file("a\n"))],
    ))?;
    f.install("upgrade dropping old/", &["dc-of"], false)?;
    Ok(())
}

fn scenario_triggers(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("triggers", opts, report)?;
    f.stage(&Pkg {
        triggers: Some("interest-noawait /usr/share/dc-trig\ninterest-noawait dc-mytrig\n"),
        ..pkg("dc-t", "1", vec![])
    })?;
    f.install("interested package", &["dc-t"], false)?;
    f.stage(&Pkg {
        scripts: vec![("postinst", "dpkg-trigger --no-await dc-mytrig\n")],
        ..pkg("dc-u", "1", vec![("/usr/share/dc-trig/x", file("x\n"))])
    })?;
    f.install("file and explicit activation", &["dc-u"], false)?;
    f.stage(&pkg("dc-u", "2", vec![]))?;
    f.install("activation by removal", &["dc-u"], false)?;
    f.stage(&Pkg {
        triggers: Some("activate-noawait dc-mytrig\n"),
        ..pkg("dc-v", "1", vec![])
    })?;
    f.install("activate directive", &["dc-v"], false)?;
    Ok(())
}

fn scenario_script_failures(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("script-failures", opts, report)?;
    f.stage(&Pkg {
        scripts: vec![("prerm", "exit 1\n")],
        ..pkg("dc-f1", "1", vec![])
    })?;
    f.install("prerm failing on upgrade only", &["dc-f1"], false)?;
    f.stage(&Pkg {
        scripts: vec![("prerm", "[ \"$1\" = failed-upgrade ] && exit 1\nexit 0\n")],
        ..pkg("dc-f1", "2", vec![])
    })?;
    f.install("prerm and failed-upgrade failing", &["dc-f1"], false)?;
    f.stage(&Pkg {
        scripts: vec![("preinst", "exit 1\n")],
        ..pkg("dc-f2", "1", vec![])
    })?;
    f.install("preinst failing on a fresh install", &["dc-f2"], false)?;
    f.sc.mutate("mkdir -p \"$ROOT/srv/dc-x\" && touch \"$ROOT/srv/dc-x/keep\"")?;
    f.stage(&pkg("dc-f3", "1", vec![("/srv/dc-x", file("file\n"))]))?;
    f.install(
        "unpack failing (file over a non-empty directory)",
        &["dc-f3"],
        false,
    )?;
    f.sc.mutate("rm -rf \"$ROOT/srv/dc-x\"")?;
    f.install("unpack retried", &["dc-f3"], false)?;
    f.stage(&Pkg {
        scripts: vec![(
            "postinst",
            "[ \"$1\" = configure ] && [ -e /etc/dc-fail ] && exit 1\nexit 0\n",
        )],
        ..pkg("dc-f4", "1", vec![])
    })?;
    f.sc.mutate("touch \"$ROOT/etc/dc-fail\"")?;
    f.install("postinst failing", &["dc-f4"], false)?;
    f.sc.mutate("rm \"$ROOT/etc/dc-fail\"")?;
    // old recorded no digest for dc-f4, which never got configured: it reinstalls it.
    let last = f.sc.round.saturating_add(1);
    f.sc.accept = Box::new(move |round, d: &Diffs| {
        if round != last {
            return Accepted::Nothing;
        }
        let ok = d.rc.is_none()
            && d.lines.is_empty()
            && d.transcript.as_ref().is_some_and(|(old, new)| {
                old.contains("dc-f4: unpacking 1")
                    && new.contains("dc-f4 1: unchanged, half-configured, configuring it")
                    && !new.contains("unpacking")
            });
        Accepted::Exactly(
            ok,
            "new configures the unchanged half-configured package, old reinstalls it".into(),
        )
    });
    f.install_ours(
        "unchanged half-configured package configured again",
        &["dc-f4"],
        false,
    )?;
    Ok(())
}

fn scenario_pre_depends(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("pre-depends", opts, report)?;
    f.stage(&pkg("dc-c", "1", vec![]))?;
    f.stage(&Pkg {
        control: vec![("Depends", "dc-c"), ("Provides", "dc-bb")],
        ..pkg("dc-b", "1", vec![])
    })?;
    f.stage(&Pkg {
        control: vec![("Pre-Depends", "dc-bb")],
        ..pkg("dc-a", "1", vec![])
    })?;
    // dpkg -i takes them in its own order: only our sides
    f.install_ours("Pre-Depends through a Provides", &["dc-a"], false)?;
    Ok(())
}

fn scenario_md5sums(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("md5sums", opts, report)?;
    f.stage(&Pkg {
        no_md5sums: true,
        conffiles: vec!["/etc/dc-m/c"],
        ..pkg(
            "dc-m",
            "1",
            vec![
                ("/usr/share/dc-m/a", file("a\n")),
                ("/etc/dc-m/c", file("c\n")),
                ("/usr/share/dc-m/l", link("a")),
            ],
        )
    })?;
    f.install("no md5sums shipped", &["dc-m"], false)?;
    Ok(())
}

fn scenario_hardlink(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("hardlink", opts, report)?;
    f.stage(&pkg(
        "dc-h",
        "1",
        vec![
            ("/usr/share/dc-h/a", file("a\n")),
            (
                "/usr/share/dc-h/b",
                Entry::Hardlink("/usr/share/dc-h/a".into()),
            ),
        ],
    ))?;
    f.install("hard link", &["dc-h"], false)?;
    Ok(())
}

fn scenario_statedir(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("statedir", opts, report)?;
    f.stage(&Pkg {
        triggers: Some("interest-noawait dc-st-trig\n"),
        conffiles: vec!["/etc/dc-st/c"],
        ..pkg(
            "dc-st",
            "1.0-1",
            vec![
                ("/etc/dc-st/c", file("c\n")),
                ("/usr/share/dc-st/a", file("a\n")),
            ],
        )
    })?;
    f.install("info files and state", &["dc-st"], false)?;
    Ok(())
}

fn scenario_unchanged_forced(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("unchanged-forced", opts, report)?;
    f.stage(&pkg(
        "dc-uf",
        "1",
        vec![("/usr/share/dc-uf/a", file("a\n"))],
    ))?;
    f.install("fresh", &["dc-uf"], false)?;
    f.install_ours("unchanged", &["dc-uf"], false)?;
    f.install("forced", &["dc-uf"], true)?;
    Ok(())
}

fn scenario_multi(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("multi", opts, report)?;
    f.stage(&Pkg {
        control: vec![("Provides", "dc-virt")],
        ..pkg("dc-p1", "1", vec![("/usr/share/dc-multi/p1", file("1\n"))])
    })?;
    f.stage(&pkg(
        "dc-p2",
        "1",
        vec![("/usr/share/dc-multi/p2", file("2\n"))],
    ))?;
    f.stage(&Pkg {
        control: vec![
            ("Depends", "dc-nothere | dc-p2, dc-virt"),
            ("Conflicts", "dc-nothere"),
        ],
        ..pkg(
            "dc-top",
            "1",
            vec![("/usr/share/dc-multi/top", file("t\n"))],
        )
    })?;
    f.install_ours("alternatives and Provides", &["dc-top"], false)?;
    Ok(())
}

fn scenario_existing_dir(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("existing-dir", opts, report)?;
    f.sc.mutate("mkdir -p \"$ROOT/usr/share/dc-q5\" && chown 1:1 \"$ROOT/usr/share/dc-q5\" && chmod 700 \"$ROOT/usr/share/dc-q5\"")?;
    f.stage(&pkg(
        "dc-q5",
        "1",
        vec![("/usr/share/dc-q5/a", file("a\n"))],
    ))?;
    f.install("over an existing directory", &["dc-q5"], false)?;
    Ok(())
}

fn scenario_truncated(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("truncated-member", opts, report)?;
    f.sc.sides = OURS.to_vec();
    let v = |name: &'static str, ver: &'static str, path: &'static str, c: &str| Pkg {
        conffiles: if path.starts_with("/etc/") {
            vec![path]
        } else {
            Vec::new()
        },
        ..pkg(name, ver, vec![(path, file(c))])
    };
    let big = "n".repeat(4096);
    for (name, path) in [("dc-tr", "/usr/share/dc-tr/a"), ("dc-trc", "/etc/dc-trc/c")] {
        f.stage(&v(name, "1", path, "old\n"))?;
        f.install_ours("fresh", &[name], false)?;
        f.stage(&v(name, "2", path, &big))?;
        truncate_member(&f.sc.fixtures(), name, path, 1000)?;
        f.install_ours("truncated upgrade", &[name], false)?;
    }
    Ok(())
}

// --- the deliberate differences ---

fn h2_env(opts: &Options, report: &mut Report) -> Result<()> {
    let mut f = fx("h2-env", opts, report)?;
    f.sc.accept = Box::new(|_, d: &Diffs| {
        let only_env = d.rc.is_none()
            && d.transcript.is_none()
            && d.lines.len() == 1
            && d.lines
                .first()
                .is_some_and(|l| l.contains("/var/log/dc-env "));
        Accepted::Exactly(
            only_env,
            "the environment dump (DPKG_FRONTEND_LOCKED)".into(),
        )
    });
    f.stage(&Pkg {
        scripts: vec![(
            "postinst",
            "env | grep -E '^DPKG_' | sort >/var/log/dc-env\n",
        )],
        ..pkg("dc-env", "1", vec![])
    })?;
    f.install("environment dump", &["dc-env"], false)?;
    let old = fs::read_to_string(f.sc.root(Side::Old).join("var/log/dc-env")).unwrap_or_default();
    let new = fs::read_to_string(f.sc.root(Side::New).join("var/log/dc-env")).unwrap_or_default();
    let mut expected: Vec<&str> = old.lines().chain(["DPKG_FRONTEND_LOCKED=1"]).collect();
    expected.sort_unstable();
    let ok = new.lines().collect::<Vec<_>>() == expected;
    f.sc.report.say(format!(
        "h2: new dump = old dump + DPKG_FRONTEND_LOCKED=1: {}",
        if ok { "yes" } else { "NO" }
    ));
    f.sc.report.failed |= !ok;
    Ok(())
}

/// A minimal root for the escape scenarios (no shell: the fixtures have no scripts).
fn bare_root(work: &Path) -> Result<PathBuf> {
    let r = work.join("bare-root");
    for d in [
        "var/lib/dpkg/info",
        "var/lib/dpkg/updates",
        "var/lib/dpkg/triggers",
        "etc",
    ] {
        mkdirs(&r.join(d))?;
    }
    fs::write(r.join("var/lib/dpkg/status"), "").ctx("status")?;
    fs::write(r.join("etc/passwd"), "root:x:0:0::/root:/bin/sh\n").ctx("passwd")?;
    fs::write(r.join("etc/group"), "root:x:0:\n").ctx("group")?;
    Ok(r)
}

/// A file tree outside the root, with what any write, link or replacement changes.
fn host_tree(dir: &Path) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    let mut paths = vec!["/".to_owned()];
    paths.extend(touched_all(&[dir]).unwrap_or_default());
    paths
        .iter()
        .map(|p| {
            let st = fs::symlink_metadata(dir.join(p.trim_start_matches('/'))).map_or_else(
                |e| e.to_string(),
                |m| {
                    format!(
                        "ino {} nlink {} mtime {}.{} ctime {}.{}",
                        m.ino(),
                        m.nlink(),
                        m.mtime(),
                        m.mtime_nsec(),
                        m.ctime(),
                        m.ctime_nsec()
                    )
                },
            );
            format!("{} {st}", strict_line(dir, p, false))
        })
        .collect()
}

/// Whether `pkg` is installed in `root`.
fn installed(root: &Path, pkg: &str) -> bool {
    read_status(root)
        .get(pkg)
        .is_some_and(|s| s.contains("\nStatus: install ok installed\n"))
}

/// Whether the old vs new differences are only on manifest paths `ok` accepts (with
/// the old line): the same rc and transcript, at least one difference.
fn only_paths(d: &Diffs, ok: &dyn Fn(&str, &str) -> bool) -> bool {
    d.rc.is_none()
        && d.transcript.is_none()
        && !d.lines.is_empty()
        && d.lines.iter().all(|l| {
            let old = l
                .lines()
                .next()
                .and_then(|o| o.strip_prefix("- "))
                .unwrap_or("");
            let path = old.split(' ').next().unwrap_or("");
            ok(path, old)
        })
}

type HostTrees = std::rc::Rc<std::cell::RefCell<Vec<(Side, Vec<String>)>>>;

/// An escape scenario (H3, H4, H8, hardlink-symlink): a bare root holding a symlink to
/// `outside`, an absolute path that exists on the host and, at the same path, in the
/// root. After each round, the host tree must be as old left it; for the H items, old
/// (resolving the symlink on the host) must have changed it at least once.
struct Escape<'a> {
    sc: Scenario<'a>,
    tmp: Work,
    outside: PathBuf,
    /// `outside` in the root, as a manifest path.
    inside: String,
    /// The host tree after each side's install.
    trees: HostTrees,
    initial: Vec<String>,
}

impl<'a> Escape<'a> {
    /// The bare root gets `setup(bare, outside, inside dir)` before the sides copy it.
    fn new(
        opts: &'a Options,
        report: &'a mut Report,
        name: &'static str,
        setup: impl FnOnce(&Path, &Path, &Path) -> Result<()>,
    ) -> Result<Self> {
        let tmp = Work::new(opts.workdir.as_deref())?;
        let bare = bare_root(&tmp.dir)?;
        let outside = tmp.dir.join(format!("outside-{name}"));
        mkdirs(&outside)?;
        let rel = outside.strip_prefix("/").unwrap_or(&outside);
        let inside_dir = bare.join(rel);
        mkdirs(&inside_dir)?;
        setup(&bare, &outside, &inside_dir)?;
        let mut sc = Scenario::new(name, opts, report, &OURS, Some(&bare))?;
        let trees = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let (t, o) = (trees.clone(), outside.clone());
        sc.after_side = Some(Box::new(move |s| t.borrow_mut().push((s, host_tree(&o)))));
        Ok(Self {
            sc,
            tmp,
            initial: host_tree(&outside),
            inside: format!("/{}", rel.display()),
            outside,
            trees,
        })
    }

    /// Check the host tree (changed by old if `old_escapes`, untouched otherwise), and
    /// that `pkg` is installed on the new side.
    fn finish(self, pkg: &str, old_escapes: bool) {
        let trees = self.trees.borrow();
        let mut same = true;
        let mut old_wrote = false;
        for pair in trees.chunks(2) {
            if let [(Side::Old, old), (Side::New, new)] = pair {
                old_wrote |= *old != self.initial;
                same &= old == new;
            } else {
                same = false;
            }
        }
        let new_ok = installed(self.sc.root(Side::New), pkg);
        let yes = |b: bool| if b { "yes" } else { "no" };
        let name = self.sc.name;
        let report = self.sc.report;
        report.say(format!(
            "{name}: host tree {}: changed by old: {} (expected: {}); new left it as old did: {}; new installed {pkg}: {}",
            self.outside.display(),
            yes(old_wrote),
            yes(old_escapes),
            yes(same),
            yes(new_ok),
        ));
        let ok = same && new_ok && old_wrote == old_escapes;
        if !ok {
            report.say(format!("{name}: host tree check FAILED"));
        }
        report.failed |= !ok;
        drop(self.tmp);
    }
}

/// H3/H4: a state or admin directory linked out of the root. New writes only the
/// package's files in the in-root counterpart, where old has none.
fn escape(
    opts: &Options,
    report: &mut Report,
    name: &'static str,
    link_at: &str,
    what: &str,
) -> Result<()> {
    let mut e = Escape::new(opts, report, name, |bare, outside, inside| {
        let link = bare.join(link_at);
        if link.is_dir() {
            // its content stays in the root, at the target
            fs::remove_dir(inside).ctx("rmdir")?;
            fs::rename(&link, inside).ctx("move")?;
        }
        std::os::unix::fs::symlink(outside, &link).ctx("symlink")
    })?;
    let prefix = format!("{}/dc-esc.", e.inside);
    let what_c = what.to_owned();
    e.sc.accept = Box::new(move |_, d: &Diffs| {
        let ok = only_paths(d, &|path, old| {
            path.starts_with(&prefix) && old == format!("{path} absent")
        });
        Accepted::Exactly(ok, what_c.clone())
    });
    let stage = e.sc.fixtures();
    stage_pkg(
        &stage,
        &Pkg {
            no_scripts: true,
            ..pkg("dc-esc", "1", vec![("/usr/share/dc-esc/a", file("a\n"))])
        },
    )?;
    e.sc.install(what, &stage, &names(&["dc-esc"]), false, false)?;
    e.finish("dc-esc", true);
    Ok(())
}

/// A hard-link member to a symlink out of the root: the symlink is linked (Python
/// 3.11's os.link), the host file untouched.
fn scenario_hardlink_symlink(opts: &Options, report: &mut Report) -> Result<()> {
    let mut e = Escape::new(opts, report, "hardlink-symlink", |bare, outside, inside| {
        fs::write(outside.join("s"), "host\n").ctx("host")?;
        fs::write(inside.join("s"), "image\n").ctx("image")?;
        let d = bare.join("usr/share/dc-hl");
        mkdirs(&d)?;
        std::os::unix::fs::symlink(outside.join("s"), d.join("l")).ctx("symlink")
    })?;
    let stage = e.sc.fixtures();
    stage_pkg(
        &stage,
        &Pkg {
            no_scripts: true,
            ..pkg(
                "dc-hl",
                "1",
                vec![(
                    "/usr/share/dc-hl/m",
                    Entry::Hardlink("/usr/share/dc-hl/l".into()),
                )],
            )
        },
    )?;
    e.sc.install(
        "hard link to a symlink",
        &stage,
        &names(&["dc-hl"]),
        false,
        false,
    )?;
    e.finish("dc-hl", false);
    Ok(())
}

/// H8: the .dpkg-old copy of a forced upgrade, a symlink out of the root, is written in
/// the root.
fn h8_backup(opts: &Options, report: &mut Report) -> Result<()> {
    let mut e = Escape::new(opts, report, "h8-backup-escape", |bare, outside, inside| {
        fs::write(outside.join("old"), "host\n").ctx("host")?;
        fs::write(inside.join("old"), "image\n").ctx("image")?;
        let d = bare.join("etc/dc-h8");
        mkdirs(&d)?;
        std::os::unix::fs::symlink(outside.join("old"), d.join("c.dpkg-old")).ctx("symlink")
    })?;
    let old_in = format!("{}/old", e.inside);
    e.sc.accept = Box::new(move |round, d: &Diffs| {
        if round == 1 {
            return Accepted::Nothing;
        }
        let ok = only_paths(d, &|path, _| path == old_in);
        Accepted::Exactly(ok, "the .dpkg-old copy written in the root".into())
    });
    let stage = e.sc.fixtures();
    let v = |ver: &'static str, c: &'static str| Pkg {
        no_scripts: true,
        conffiles: vec!["/etc/dc-h8/c"],
        ..pkg("dc-h8", ver, vec![("/etc/dc-h8/c", file(c))])
    };
    stage_pkg(&stage, &v("1", "A\n"))?;
    e.sc.install("fresh", &stage, &names(&["dc-h8"]), false, false)?;
    e.sc.mutate("echo local >\"$ROOT/etc/dc-h8/c\"")?;
    stage_pkg(&stage, &v("2", "B\n"))?;
    e.sc.install(
        "forced upgrade, modified conffile",
        &stage,
        &names(&["dc-h8"]),
        true,
        false,
    )?;
    e.finish("dc-h8", true);
    Ok(())
}

fn refused(
    opts: &Options,
    report: &mut Report,
    name: &'static str,
    p: &Pkg<'_>,
    msg: &'static str,
    before_anything: bool,
) -> Result<()> {
    let mut f = fx(name, opts, report)?;
    f.sc.sides = OURS.to_vec();
    let m = msg.to_owned();
    f.sc.accept = Box::new(move |_, d: &Diffs| {
        let new_failed = d.rc.is_some_and(|(o, n)| o == 0 && n == 1);
        let says = d.transcript.as_ref().is_some_and(|(_, n)| n.contains(&m));
        Accepted::Exactly(new_failed && says, format!("new refuses: {m}"))
    });
    f.stage(p)?;
    let name_owned = p.name.to_owned();
    f.install_ours("install", &[&name_owned], false)?;
    if before_anything {
        let upper = f.sc.work.upper("new");
        let t = touched(&[&upper], &["usr/sbin/policy-rc.d"])?;
        let written: Vec<&String> = t
            .iter()
            .filter(|p| {
                // the overlays' own copy-ups: the locks, policy-rc.d's parents
                !p.starts_with("/var/lib/dpkg/lock")
                    && !["/var/lib/dpkg", "/var/lib", "/var", "/usr", "/usr/sbin"]
                        .contains(&p.as_str())
            })
            .collect();
        let ok = written.is_empty();
        f.sc.report.say(format!(
            "{name}: nothing written by new ({written:?}): {}",
            if ok { "yes" } else { "NO" }
        ));
        f.sc.report.failed |= !ok;
    }
    Ok(())
}

type Fixture = fn(&Options, &mut Report) -> Result<()>;

/// Run the scenarios; whether every one passed.
///
/// # Errors
/// A step of the harness fails.
pub fn run_all(opts: &Options) -> Result<Report> {
    if !nix::unistd::geteuid().is_root() {
        return Err(err("must run as root"));
    }
    let want = |n: &str| opts.scenarios.is_empty() || opts.scenarios.iter().any(|s| s == n);
    let mut report = Report::default();
    let r = &mut report;
    let pkgs = if opts.packages.is_empty() {
        Vec::new()
    } else {
        plan_packages(opts)?
    };
    if !pkgs.is_empty() {
        r.say(format!("packages: {}", pkgs.join(" ")));
        if want("upgrade") {
            scenario_upgrade(opts, r, &pkgs)?;
        }
        if want("statoverride") {
            scenario_statoverride(opts, r, &pkgs)?;
        }
        if want("failing-postinst") {
            scenario_failing_postinst(opts, r, &pkgs)?;
        }
    }
    let fixtures: [(&str, Fixture); 12] = [
        ("conffiles", scenario_conffiles),
        ("obsolete-conffiles", scenario_obsolete_conffiles),
        ("replaces", scenario_replaces),
        ("symlinks", scenario_symlinks),
        ("obsolete-files", scenario_obsolete_files),
        ("triggers", scenario_triggers),
        ("script-failures", scenario_script_failures),
        ("pre-depends", scenario_pre_depends),
        ("md5sums", scenario_md5sums),
        ("hardlink", scenario_hardlink),
        ("statedir", scenario_statedir),
        ("unchanged-forced", scenario_unchanged_forced),
    ];
    for (n, f) in fixtures {
        if want(n) {
            f(opts, r)?;
        }
    }
    if want("multi") {
        scenario_multi(opts, r)?;
    }
    if want("existing-dir") {
        scenario_existing_dir(opts, r)?;
    }
    if want("h2-env") {
        h2_env(opts, r)?;
    }
    if want("h3-statedir-escape") {
        escape(
            opts,
            r,
            "h3-statedir-escape",
            "var/lib/debbuild-rs",
            "var/lib/debbuild-rs resolved in the root",
        )?;
    }
    if want("h4-admindir-escape") {
        escape(
            opts,
            r,
            "h4-admindir-escape",
            "var/lib/dpkg/info",
            "var/lib/dpkg/info resolved in the root",
        )?;
    }
    if want("hardlink-symlink") {
        scenario_hardlink_symlink(opts, r)?;
    }
    if want("h8-backup-escape") {
        h8_backup(opts, r)?;
    }
    if want("truncated-member") {
        scenario_truncated(opts, r)?;
    }
    if want("h5-bad-trigger") {
        refused(
            opts,
            r,
            "h5-bad-trigger",
            &Pkg {
                triggers: Some("interestfoo dc-x\n"),
                ..pkg("dc-h5", "1", vec![])
            },
            "dc-h5: DEBIAN/triggers: unknown directive 'interestfoo'",
            true,
        )?;
    }
    if want("h6-sparse") {
        refused(
            opts,
            r,
            "h6-sparse",
            &pkg(
                "dc-h6",
                "1",
                vec![("/usr/share/dc-h6/s", Entry::Sparse(b"sparse\n".to_vec()))],
            ),
            "dc-h6: /usr/share/dc-h6/s: unsupported file type in archive",
            false,
        )?;
    }
    if want("h7-corrupt") {
        refused(
            opts,
            r,
            "h7-corrupt",
            &Pkg {
                bad_sha256: true,
                ..pkg("dc-h7", "1", vec![("/usr/share/dc-h7/a", file("a\n"))])
            },
            "dc-h7: staged tree changed while installing, rerun",
            true,
        )?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(state: &[&str], status: &[(&str, &str)]) -> Snapshot {
        Snapshot {
            rc: 0,
            transcript: String::new(),
            strict: BTreeMap::new(),
            relaxed: BTreeMap::new(),
            hardlinks: Vec::new(),
            state: state.iter().map(|s| (*s).to_owned()).collect(),
            status: status
                .iter()
                .map(|(p, st)| ((*p).to_owned(), format!("Package: {p}\nStatus: {st}\n")))
                .collect(),
        }
    }

    #[test]
    fn state_compared_by_name() {
        let installed = [("a", "install ok installed"), ("b", "install ok installed")];
        assert_eq!(
            state_diff(
                &snap(&["a.sha256"], &installed),
                &snap(&["a.sha256"], &installed)
            ),
            None
        );
        assert_eq!(
            state_diff(
                &snap(&["a.sha256"], &installed),
                &snap(&["a.sha256", "b.sha256"], &installed)
            ),
            Some("var/lib/debbuild-rs: - []\n+ [\"b.sha256\"]".to_owned())
        );
        assert!(state_diff(&snap(&["a.sha256"], &installed), &snap(&[], &installed)).is_some());
        // recorded at unpack by new only
        for st in ["install ok half-configured", "install ok unpacked"] {
            let new = [("a", "install ok installed"), ("b", st)];
            assert_eq!(
                state_diff(
                    &snap(&["a.sha256"], &new),
                    &snap(&["a.sha256", "b.sha256"], &new)
                ),
                None
            );
        }
        let half = [("b", "install reinstreq half-installed")];
        assert!(state_diff(&snap(&[], &half), &snap(&["b.sha256"], &half)).is_some());
    }

    #[test]
    fn overwrite_warning_normalized() {
        assert_eq!(
            stable_transcript(
                "debbuild-rs install: warning: b: overwriting /x, which is also in package a (--force-overwrite)\n"
            ),
            stable_transcript(
                "debbuild-rs install: warning: b: overwriting /x, which is also in package a (--force)\n"
            )
        );
    }
}
