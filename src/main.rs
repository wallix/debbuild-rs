//! debbuild-rs: stage Debian packages from their debian/rules, pack them into .deb files
//! and install them the way dpkg does.
//!
//! `dh_builddeb` as argv[0] runs `debbuild-rs builddeb`, `dh_strip_nondeterminism` the
//! native `dh_strip_nondeterminism` (`debbuild-rs stage` puts such links first in the PATH
//! of debian/rules).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use debbuild_rs_build::stage::Entry;

#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser)]
#[command(name = "debbuild-rs", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// `install --conffiles`.
#[derive(Clone, Copy, ValueEnum)]
enum Conffiles {
    Keep,
    Replace,
}

/// `stage`'s arguments.
#[derive(Args)]
struct StageArgs {
    /// Write the staged trees to OUTDIR/<dir>
    #[arg(short, long, value_name = "OUTDIR")]
    output: PathBuf,
    /// Write a changelog entry with this version for the run
    #[arg(long, value_name = "VERSION")]
    version: Option<String>,
    /// The distribution of the written entry (default: UNRELEASED)
    #[arg(long, value_name = "DIST", requires = "version")]
    distribution: Option<String>,
    /// The maintainer of the written entry, `Name <email>` (default: DEBFULLNAME and
    /// DEBEMAIL, otherwise the Maintainer of debian/control)
    #[arg(long, value_name = "MAINTAINER", requires = "version")]
    maintainer: Option<String>,
    /// The change line of the written entry (default: Build <version>)
    #[arg(long, value_name = "TEXT", requires = "version")]
    message: Option<String>,
    /// `SOURCE_DATE_EPOCH`, in seconds since the epoch (default: the environment's,
    /// otherwise the changelog date; now for a written entry)
    #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(i64).range(0..))]
    epoch: Option<i64>,
    /// Check the build dependencies with dpkg-checkbuilddeps first
    #[arg(long)]
    check_build_deps: bool,
    /// The source package directory (holding debian/)
    #[arg(value_name = "SRCDIR")]
    srcdir: PathBuf,
}

/// `strip-nondeterminism`'s arguments.
#[derive(Args)]
#[allow(clippy::struct_excessive_bools)] // its flags
struct StripArgs {
    /// Set the timestamps to SECONDS since the epoch (an integer, negative ones too)
    #[arg(
        short = 'T',
        long,
        value_name = "SECONDS",
        allow_hyphen_values = true,
        overrides_with = "timestamp"
    )]
    timestamp: Option<String>,
    /// Use this handler (gzip, zip, jar, png, gettext, javadoc...) instead of detecting
    #[arg(
        short = 't',
        long = "type",
        value_name = "TYPE",
        overrides_with = "kind"
    )]
    kind: Option<String>,
    /// Only replace later timestamps (the real tool's)
    #[arg(long)]
    clamp_timestamp: bool,
    /// Enable or disable handlers, +NAME,-NAME,+all,-all, left to right from the default
    /// set (every handler but ar); the last --normalizers counts
    #[arg(
        long,
        value_name = "SPEC",
        overrides_with = "normalizers",
        allow_hyphen_values = true
    )]
    normalizers: Option<String>,
    /// Name each file normalized
    #[arg(short, long)]
    verbose: bool,
    /// Also normalize Python bytecode as add-determinism does: the .pyc files, and
    /// those under the directories given
    #[arg(long)]
    pyc: bool,
    /// Leave alone the files whose name (not path) matches this shell glob (`*`, `?`,
    /// `[...]`), whether given or found under a directory; repeatable
    #[arg(long, value_name = "PATTERN")]
    exclude: Vec<String>,
    /// The files, and directories whose files are all normalized
    #[arg(required = true, value_name = "PATH")]
    files: Vec<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build a source package into staged package trees (OUTDIR/<dir>/<package>)
    #[command(long_about = debbuild_rs_build::stage::ABOUT, args_override_self = true)]
    Stage(StageArgs),
    /// The staging `dh_builddeb` (debian/rules runs it as `dh_builddeb`)
    #[command(disable_help_flag = true, hide = true)]
    Builddeb {
        /// `dh_builddeb` options; the ones after `--` (dpkg-deb's) are recorded for `pack`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// The native `dh_strip_nondeterminism` (debian/rules runs it under that name)
    #[command(disable_help_flag = true, hide = true)]
    DhStripNondeterminism {
        /// debhelper options
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// Normalize timestamps and build details out of files, as strip-nondeterminism does
    #[command(long_about = STRIP_ABOUT)]
    StripNondeterminism(StripArgs),
    /// Install staged packages into a root directory, the way dpkg does
    #[command(long_about = debbuild_rs_install::ABOUT, infer_long_args = true)]
    Install {
        /// Root directory to install into
        #[arg(long, value_name = "ROOT", default_value = "/")]
        root: PathBuf,
        /// Directory holding the staged packages
        #[arg(long, value_name = "STAGE")]
        stage: PathBuf,
        /// Reinstall unchanged packages instead of skipping them
        #[arg(long)]
        reinstall: bool,
        /// A conffile both the administrator and the package changed: keep it, the new
        /// version in <conffile>.dpkg-dist (dpkg's --force-confold), or replace it, the
        /// old one in <conffile>.dpkg-old (dpkg's --force-confnew)
        #[arg(long, value_enum, value_name = "WHAT", default_value = "keep")]
        conffiles: Conffiles,
        /// Take over files of other packages instead of failing, as dpkg's --force-overwrite
        #[arg(long)]
        force_overwrite: bool,
        /// Shorthand for --reinstall --conffiles=replace --force-overwrite
        #[arg(long, conflicts_with = "conffiles")]
        force: bool,
        /// Only print the plan: per package, its action, versions and why it is planned
        #[arg(long)]
        dry_run: bool,
        /// With --dry-run, print the plan as JSON
        #[arg(long, requires = "dry_run")]
        json: bool,
        /// Packages to install, with the staged packages they depend on
        #[arg(required = true, value_name = "PACKAGE")]
        packages: Vec<String>,
    },
    /// Check that `debbuild-rs install` leaves a root as dpkg does
    #[command(long_about = debbuild_rs_check::ck::ABOUT)]
    Check {
        /// Then upgrade both sides to a copy with a higher version and changed conffiles
        #[arg(short)]
        upgrade: bool,
        /// The root the overlays are made of
        #[arg(short, value_name = "ROOT", default_value = "/")]
        root: PathBuf,
        /// The staged packages
        #[arg(short, value_name = "STAGEDIR", required = true)]
        stagedir: PathBuf,
        /// Where the overlays go (default: a new directory under /var/tmp)
        #[arg(short, value_name = "WORKDIR")]
        workdir: Option<PathBuf>,
        /// Compare with that other installer too, through scenarios
        #[arg(long, value_name = "INSTALLER")]
        vs_oracle: Option<PathBuf>,
        /// With --vs-oracle, the scenarios to run (default: all; `help` lists them)
        #[arg(long, value_name = "NAME")]
        scenario: Vec<String>,
        /// The packages to install, with the staged packages they depend on
        #[arg(value_name = "PACKAGE")]
        packages: Vec<String>,
    },
    /// Compare two staged trees (OUTDIR, or OUTDIR/<dir>): would pack, or install, make
    /// the same of them
    #[command(long_about = debbuild_rs_check::diffstage::ABOUT)]
    DiffStage {
        /// Compare install-equivalence (the files install leaves) instead of
        /// pack-equivalence (the .deb files pack makes)
        #[arg(long)]
        install: bool,
        /// A staged output directory (OUTDIR) or source directory (OUTDIR/<dir>)
        a: PathBuf,
        /// The staged directory to compare with, of the same kind
        b: PathBuf,
    },
    /// List the packages of staged trees (OUTDIR, or OUTDIR/<dir>), after validating them
    #[command(long_about = debbuild_rs_check::inspect::ABOUT)]
    Inspect {
        /// A staged output directory (OUTDIR) or source directory (OUTDIR/<dir>)
        staged: PathBuf,
    },
    /// Pack staged package trees into .deb files
    #[command(long_about = debbuild_rs_pack::ABOUT)]
    Pack {
        /// Write the .deb files to DESTDIR
        #[arg(short, long, value_name = "DESTDIR")]
        destdir: PathBuf,
        /// The epoch the trees were staged with, in seconds since the epoch: checked
        /// against the one they record; for trees without a record, the timestamp of the
        /// members and the bound of the others (default: `SOURCE_DATE_EPOCH`, otherwise
        /// now)
        #[arg(long, value_name = "SECONDS")]
        epoch: Option<u64>,
        /// Staged source directories (OUTDIR/<dir>) or staged package trees
        #[arg(required = true, value_name = "STAGED")]
        staged: Vec<PathBuf>,
    },
}

const STRIP_ABOUT: &str = "Normalize timestamps and build details out of files, as \
strip-nondeterminism does, byte for byte.

Natively, with --timestamp, for every format strip-nondeterminism handles: gzip, zip \
and the formats it handles as zip (.xpi, .whl, .epub..., Zip64 included), jar (.jar, \
.war, .apk...), Java modules, Python zip applications, PNG, gettext .mo, javadoc HTML, \
cpio, U-Boot images, bFLT executables and ar (when enabled); a file is detected as \
strip-nondeterminism detects it, by its name, content and file(1). Without \
--timestamp, or with --clamp-timestamp, the run is the real strip-nondeterminism's. \
--normalizers enables and disables handlers as for strip-nondeterminism: from the \
default set (all but ar), +NAME and -NAME items applied left to right, `all` naming \
every handler; -t takes only an enabled one. Both are checked before any file.

Operands are files and directories. With --timestamp, a directory's regular files are \
all normalized as files given are (strip-nondeterminism skips directories), symbolic \
links not followed; a file reached through several operands or names (hard links) is \
processed each time. Without it, only the .pyc files under a directory are (with \
--pyc). -t takes files only (a directory is an error, status 2). A symbolic link \
given is followed only with -t, and a missing operand stops the run there, as for \
strip-nondeterminism. --exclude PATTERN (repeatable) leaves alone the files whose \
name, not path, matches the shell glob PATTERN (`*`, `?`, `[...]`, `\\` quoting), \
whether given or found under a directory.

--pyc (or DEBBUILD_RS_STRIP_PYC set) adds Python bytecode, which strip-nondeterminism \
leaves alone: the .pyc files, given or found, are normalized as add-determinism 0.7.3 \
does, whatever the other options. A file it cannot process is left as it is, with a \
warning; one too short for a magic number makes the run fail, after the others.

`debbuild-rs strip-nondeterminism --pyc --normalizers=+ar -T \"$SOURCE_DATE_EPOCH\" \
[--exclude GLOB]... DIR...` replaces add-determinism DIR...: the same .pyc files, and \
ar, gzip, jar, javadoc and zip files as strip-nondeterminism normalizes them.

`dh_strip_nondeterminism` as the name of this binary runs debhelper's helper natively; \
`debbuild-rs stage` puts it in the PATH of debian/rules. With DEBBUILD_RS_STRIP_PYC set, \
it normalizes the .pyc files of the package trees too.";

fn status(n: u8) -> ExitCode {
    ExitCode::from(n)
}

fn stage(args: StageArgs) -> ExitCode {
    use debbuild_rs_build::signals_install;
    if args.output.as_os_str().is_empty() {
        eprintln!("debbuild-rs stage: the output directory is empty");
        return ExitCode::FAILURE;
    }
    let entry = args.version.map(|v| Entry {
        version: v.into_bytes(),
        distribution: args.distribution,
        maintainer: args.maintainer,
        message: args.message,
    });
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("debbuild-rs: cannot find this binary: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = signals_install() {
        eprintln!("debbuild-rs: cannot catch signals: {e}");
        return ExitCode::FAILURE;
    }
    let opts = debbuild_rs_build::stage::Options {
        srcdir: args.srcdir,
        outdir: args.output,
        exe,
        entry,
        epoch: args.epoch,
        check_build_deps: args.check_build_deps,
    };
    let res = debbuild_rs_build::stage::stage(&opts);
    debbuild_rs_build::die_of_caught_signal();
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if let debbuild_rs_build::Error::Message(m) = &e {
                eprintln!("{m}");
            }
            status(e.status())
        }
    }
}

fn builddeb(args: &[OsString]) -> ExitCode {
    match debbuild_rs_build::builddeb::builddeb(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if let debbuild_rs_build::Error::Message(m) = &e {
                eprintln!("{m}");
            }
            status(e.status())
        }
    }
}

fn install(opts: &debbuild_rs_install::Options) -> ExitCode {
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o022));
    match debbuild_rs_install::run(opts, &debbuild_rs_install::Chroot) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("debbuild-rs install: error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::needless_pass_by_value)] // the subcommand's fields, moved
fn check(
    upgrade: bool,
    root: PathBuf,
    stagedir: PathBuf,
    workdir: Option<PathBuf>,
    vs_oracle: Option<PathBuf>,
    scenario: Vec<String>,
    packages: Vec<String>,
) -> ExitCode {
    if scenario.iter().any(|s| s == "help") {
        for (n, d) in debbuild_rs_check::oracle::SCENARIOS {
            println!("{n:20} {d}");
        }
        return ExitCode::SUCCESS;
    }
    let res = if let Some(oracle) = vs_oracle {
        debbuild_rs_check::oracle::run_all(&debbuild_rs_check::oracle::Options {
            root,
            stagedir,
            workdir,
            oracle,
            scenarios: scenario,
            packages,
        })
        .map(|r| !r.failed)
    } else {
        if packages.is_empty() {
            eprintln!("debbuild-rs check: no package given");
            return ExitCode::FAILURE;
        }
        debbuild_rs_check::ck::check(&debbuild_rs_check::ck::Options {
            root,
            stagedir,
            workdir,
            upgrade,
            packages,
        })
    };
    match res {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("debbuild-rs check: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn inspect(staged: &Path) -> ExitCode {
    match debbuild_rs_check::inspect::inspect(staged) {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("debbuild-rs inspect: error: {e}");
            status(2)
        }
    }
}

fn diff_stage(a: &Path, b: &Path, install: bool) -> ExitCode {
    use debbuild_rs_check::diffstage::Level;
    let level = if install { Level::Install } else { Level::Pack };
    match debbuild_rs_check::diffstage::diff_stage(a, b, level) {
        Ok(report) if report.is_empty() => {
            println!(
                "debbuild-rs diff-stage: {} and {} are {}-equivalent",
                a.display(),
                b.display(),
                if install { "install" } else { "pack" }
            );
            ExitCode::SUCCESS
        }
        Ok(report) => {
            for line in report {
                println!("{line}");
            }
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("debbuild-rs diff-stage: error: {e}");
            status(2)
        }
    }
}

fn pack(destdir: PathBuf, epoch: Option<u64>, staged: Vec<PathBuf>) -> ExitCode {
    let opts = debbuild_rs_pack::Options {
        staged,
        destdir,
        epoch,
    };
    match debbuild_rs_pack::pack(&opts, |deb| println!("{}", deb.display())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("debbuild-rs pack: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn strip_nondeterminism(a: StripArgs) -> ExitCode {
    // an integer, as strip-nondeterminism takes it: an optional sign, then digits;
    // strip-nondeterminism names the option as it was typed (T or timestamp), this
    // always T
    let timestamp = match a.timestamp.as_deref().map(str::parse::<i64>) {
        None => None,
        Some(Ok(t)) => Some(t),
        Some(Err(_)) => {
            eprintln!(
                "Value \"{}\" invalid for option T (number expected)",
                a.timestamp.unwrap_or_default()
            );
            return status(255);
        }
    };
    status(debbuild_rs_strip::cli::run(&debbuild_rs_strip::cli::Args {
        timestamp,
        kind: a.kind,
        clamp_timestamp: a.clamp_timestamp,
        normalizers: a.normalizers,
        verbose: a.verbose,
        pyc: a.pyc || debbuild_rs_strip::dh::env_set(debbuild_rs_strip::dh::PYC),
        exclude: a.exclude,
        files: a.files,
    }))
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let argv0 = args
        .first()
        .and_then(|a| Path::new(a).file_name())
        .unwrap_or_default();
    if argv0 == "dh_builddeb" {
        return builddeb(args.get(1..).unwrap_or_default());
    }
    if debbuild_rs_strip::dh::is_argv0(argv0) {
        return status(debbuild_rs_strip::dh::run(
            args.get(1..).unwrap_or_default(),
        ));
    }
    let matches = match Cli::command().try_get_matches_from(&args) {
        Ok(m) => m,
        Err(e) => {
            // Usage errors of `stage` and `check` exit 1, of the other subcommands 2.
            let stage = args.get(1).is_some_and(|a| a == "stage" || a == "check");
            let _ = e.print();
            return match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    ExitCode::SUCCESS
                }
                _ if stage => ExitCode::FAILURE,
                _ => status(2),
            };
        }
    };
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return status(2);
        }
    };
    match cli.cmd {
        Cmd::Stage(args) => stage(args),
        Cmd::Builddeb { args } => builddeb(&args),
        Cmd::DhStripNondeterminism { args } => status(debbuild_rs_strip::dh::run(&args)),
        Cmd::StripNondeterminism(a) => strip_nondeterminism(a),
        Cmd::DiffStage { install, a, b } => diff_stage(&a, &b, install),
        Cmd::Inspect { staged } => inspect(&staged),
        Cmd::Pack {
            destdir,
            epoch,
            staged,
        } => pack(destdir, epoch, staged),
        Cmd::Install {
            root,
            stage,
            reinstall,
            conffiles,
            force_overwrite,
            force,
            dry_run,
            json,
            packages,
        } => install(&debbuild_rs_install::Options {
            root,
            stage,
            install: if force {
                debbuild_rs_install::InstallOptions::FORCE
            } else {
                debbuild_rs_install::InstallOptions {
                    reinstall,
                    conffiles: match conffiles {
                        Conffiles::Keep => debbuild_rs_install::Conffiles::Keep,
                        Conffiles::Replace => debbuild_rs_install::Conffiles::Replace,
                    },
                    force_overwrite,
                }
            },
            dry_run,
            json,
            packages,
        }),
        Cmd::Check {
            upgrade,
            root,
            stagedir,
            workdir,
            vs_oracle,
            scenario,
            packages,
        } => check(
            upgrade, root, stagedir, workdir, vs_oracle, scenario, packages,
        ),
    }
}
