# Changelog

Each release has a `## vX.Y.Z - YYYY-MM-DD` section: the release workflow requires it and
publishes it as the release notes. Changes waiting for a release go under `## Unreleased`.

## v0.1.0 - 2026-10-19

First release.

- `stage`: build a source package's binary packages into staged trees, running its
  `debian/rules` as dpkg-buildpackage does, with `debbuild-rs` as `dh_builddeb`. Trees
  are checked as dpkg-deb --build checks them, record their epoch (`staged.info`), and
  are published atomically under a lock of the output. `--check-build-deps` runs
  dpkg-checkbuilddeps first.
- `pack`: staged trees into .deb files, byte for byte those of dpkg-deb, at the epoch
  each tree was staged with.
- `install`: staged packages into a root, the way dpkg does, honouring dpkg's
  `path-exclude`/`path-include` filters. `--dry-run [--json]` shows what it would do
  with each package and why; `--reinstall`, `--conffiles=keep|replace` and
  `--force-overwrite` (all three: `--force`).
- `check`: compare `debbuild-rs install` with `dpkg -i` on overlays of a root.
- `diff-stage`: validate two staged trees and list every difference between the .deb
  files `pack` makes of them, or (`--install`) the files `install` leaves.
- `inspect`: validate staged trees and list their packages.
- Relationship fields are parsed as strictly as dpkg parses them.
- Static release binaries for x86_64 and aarch64, reproducible from the source.
- The commands reading staged trees and `stage` publishing them take turns through
  OUTDIR/.<dir>.publish.lock: a reader sees one generation of OUTDIR/<dir> whole, and
  the publish waits for the readers at hand, never they for a build.
- `pack` looks conffiles up in data.tar as dpkg-deb --build looks them up on disk: through
  symlinked parent directories (resolved within the file tree), `..` after them, and a
  trailing slash following the last one.
- `install` parses each relationship field with dpkg's rules for it: a staged package
  with alternatives in Breaks, Conflicts, Provides or Replaces, a non-exact Provides, or
  any invalid relationship field is refused, naming its control file. The status file is
  read as dpkg reads it: what dpkg refuses there is an error naming the file and package,
  what it only warns about is a warning on stderr.
- `install` records a package's content digest (var/lib/debbuild-rs/<package>.sha256)
  when its unpack completes, and removes it before the files change: a package whose
  configure failed is compared with the content left on disk, so restaging the
  previously installed content reinstalls it instead of only configuring it again.
- `stage`: `dh_strip_nondeterminism` is native, with the output of debhelper's: gzip,
  zip, jar, PNG, gettext and javadoc files are normalized without strip-nondeterminism;
  the formats it does not cover go through debhelper's helper when it is installed.
- `strip-nondeterminism`: strip-nondeterminism's command line on the same handlers.
- Python bytecode, as add-determinism 0.7.3 normalizes it: `strip-nondeterminism --pyc`
  for .pyc files and the .pyc files under directories, `dh_strip_nondeterminism` for those
  of the package trees with `DEBBUILD_RS_STRIP_PYC` set.
- `stage`, `strip-nondeterminism`: jars whose deflated members strip-nondeterminism
  rewrites (the manifest, javadoc pages, nested jars) are normalized natively, those
  members compressed again with flate2: the same contents as strip-nondeterminism's,
  other compressed bytes.
- The native strip-nondeterminism and add-determinism handlers process files in parallel,
  with the warnings and outcome of processing them in order; `pack` packs the small trees
  of a source in parallel. The release binaries allocate with jemalloc.
