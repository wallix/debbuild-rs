# debbuild-rs

Build Debian binary packages from their `debian/rules` into *staged trees*, pack them
into `.deb` files, and install them into a root directory the way dpkg does.

A staged tree is a binary package before the `ar` container: its control files and its
file tree as an uncompressed tarball.

```
OUTDIR/<dir>/.staged             the staged packages of source directory <dir>
OUTDIR/<dir>/<pkg>/DEBIAN/       control files, as dpkg-deb puts them in control.tar
OUTDIR/<dir>/<pkg>/data.tar      the file tree, as dpkg-deb puts it in data.tar
OUTDIR/<dir>/<pkg>/data.tar.sha256
OUTDIR/<dir>/<pkg>/dpkg-deb.options   dpkg-deb options the rules passed to dh_builddeb
OUTDIR/<dir>/<pkg>/staged.info   Format: 1, and the Epoch (SOURCE_DATE_EPOCH) it was staged with
OUTDIR/.<dir>.lock               held by the stage run writing OUTDIR/<dir>
OUTDIR/.<dir>.publish.lock       shared by its readers, exclusive while it is replaced
```

A stage run publishes OUTDIR/<dir> whole, in place of the previous one, in a single
rename. Every command reading staged trees (`pack`, `install`, `check`, `inspect`,
`diff-stage`) holds a shared flock on OUTDIR/.<dir>.publish.lock while it reads
OUTDIR/<dir>, or OUTDIR/<dir>/<pkg>, so that it sees one generation whole; the stage run
takes it exclusively for the rename only, after its build, and removes the previous
generation once it has released it. A reader waits for a rename at most, a publish for
the readers at hand. Other tools reading staged trees while a stage run may publish
them should take the lock the same way. The stage run creates the lock file when it starts,
a reader when it is missing; a reader that cannot create it (a read-only file system,
or an output directory it may not write, as a cache restores it) reads without it. Staged trees are content-addressable build outputs: an unchanged source tree
stages byte-identical content, which build caches can store and deduplicate, and the
same tree can become a `.deb` for a release or be installed directly into a
development root.

## Commands

| Command | What it does |
|---|---|
| `debbuild-rs stage -o OUTDIR SRCDIR` | Runs `debian/rules` (clean, build, binary, clean) as dpkg-buildpackage does, with `debbuild-rs` as `dh_builddeb`: each binary package, `-dbgsym` included, is staged instead of packed. `dh_strip_nondeterminism` is `debbuild-rs` too (see below). |
| `debbuild-rs pack -d DESTDIR STAGED...` | Packs staged trees into `.deb` files, as `dpkg-deb --build` would: same members, compression (from `dpkg-deb.options`, default xz -6), control modes and timestamps clamped to the epoch the tree was staged with. The same tree gives the same bytes. |
| `debbuild-rs install --stage STAGEDIR PKG...` | Installs staged packages and the staged packages they depend on into `--root`, following dpkg's sequence (maintainer scripts, conffiles, triggers) and writing the dpkg database. `--dry-run` prints what it would do with each package and why (`--json` for CI); `--reinstall`, `--conffiles=keep\|replace` and `--force-overwrite` (all three: `--force`) settle what dpkg would skip, ask about or refuse. |
| `debbuild-rs check -s STAGEDIR PKG...` | Installs the same packages with dpkg and with `debbuild-rs install` on two overlays of a root, and compares the results. |
| `debbuild-rs diff-stage [--install] A B` | Validates two staged trees and lists every difference that would change the `.deb` files `pack` makes of them, or with `--install` the files `install` leaves. |
| `debbuild-rs inspect STAGED` | Validates staged trees and lists their packages: version, architecture, compression, epoch, relationships. |
| `debbuild-rs strip-nondeterminism -T SECONDS FILE...` | Normalizes the timestamps and build details of files as Debian's strip-nondeterminism does, byte for byte. |
| `debbuild-rs strip-nondeterminism --pyc PATH...` | Normalizes Python bytecode (.pyc files, and those under directories) as add-determinism does, byte for byte. |

`debbuild-rs <command> --help` documents each one, including where it differs from the
Debian tool it stands in for.

### Versions and reproducibility

`stage` takes the version from `debian/changelog`. For source trees that keep none,
`--version` writes an entry for the run (`--distribution`, `--maintainer`, `--message`)
and removes it afterwards. `SOURCE_DATE_EPOCH` is `--epoch`, else the environment's,
else the changelog date; each staged tree records it, and `pack` uses it.
`debian/rules` runs in the caller's environment plus `dpkg-architecture`'s variables.

### dh_strip_nondeterminism

Under `stage`, debian/rules runs `debbuild-rs` as `dh_strip_nondeterminism`: the same
packages, files, `-X` exclusions and timestamp (the changelog date) as debhelper's, and
the same output, from native handlers for gzip, zip (and `.whl`, `.epub`, `.xpi`...),
jar (and `.war`, `.apk`...), PNG, gettext `.mo` and javadoc HTML, picked as
strip-nondeterminism picks them, by file name and file(1). The files it does not cover
natively (Java modules, Python zip applications, cpio, U-Boot and bFLT images, Zip64
archives) go through debhelper's `dh_strip_nondeterminism` on copies, or are left as they are, with a note, when it is not
installed or `DEBBUILD_RS_STRIP_NATIVE_ONLY` is set. `debbuild-rs strip-nondeterminism`
is the same on strip-nondeterminism's command line.

The handlers were written from the format specifications (RFC 1952, the zip APPNOTE,
PNG, the GNU gettext catalog format) and from running strip-nondeterminism 1.13 (Debian
12) and 1.14 (Debian 13) on crafted files; `tests/strip.rs` keeps comparing the two.
One difference is deliberate: a deflated jar member whose content is rewritten (the
manifest, a javadoc page, a nested jar) is compressed again with flate2, where
strip-nondeterminism uses zlib. Such a jar holds the same members, metadata and contents
as strip-nondeterminism's, but different compressed bytes for those members; the tests
compare them by content.

### Python bytecode

strip-nondeterminism leaves `.pyc` files alone. Their marshal stream depends on the
process that compiled them: which objects carry a back-reference flag, and which equal
objects are written twice, follow the interpreter's reference counts at that moment.
debbuild-rs normalizes them on request, with the output of add-determinism 0.7.3: each
equal value written once and referred back to afterwards, flags on exactly the
referenced objects, the header kept, the file's permissions, owner and mtime kept. It
reads Python 3.0 to 3.16 files; it leaves Python 2 files, and those it cannot rewrite
(with a warning), as they are.

- `debbuild-rs strip-nondeterminism --pyc PATH...` normalizes the .pyc files among the
  PATHs and under the directories among them, then handles the other files as without
  `--pyc`.
- Under `stage`, `dh_strip_nondeterminism` normalizes the .pyc files of the package trees
  too when `DEBBUILD_RS_STRIP_PYC` is set (non-empty), as in
  `export DEBBUILD_RS_STRIP_PYC = 1` in debian/rules. Debhelper's helper ignores it.

For a build that runs `add-determinism DIR` for its .pyc files,
`debbuild-rs strip-nondeterminism --pyc DIR` is the replacement. It covers
add-determinism's pyc handler only, not its ar, gzip, jar, javadoc and zip handlers.

The handler was written from the marshal format (CPython's documentation and
Python/marshal.c) and from running add-determinism on the files Python 3.11 (Debian 12)
and 3.13 (Debian 13) compile and on crafted streams; `tests/pyc.rs` keeps comparing the
two.

## Example

```sh
debbuild-rs stage -o out --version 1.2.3-1 --epoch "$(date +%s)" path/to/hello
debbuild-rs pack -d debs out/hello
sudo debbuild-rs install --root /srv/root --stage out hello
```

## Requirements

At build time, what the package's rules need plus `fakeroot`, `tar` and `dpkg-dev`
(`dpkg-architecture`, `dpkg-parsechangelog`); `check` also needs `dpkg` and overlayfs.

The release binaries are static (musl), for x86_64 and aarch64; they run on any Linux.

## Development

Every script runs in the images of [.devcontainer/Dockerfile](.devcontainer/Dockerfile), in
[vk](https://github.com/wallix/virtkit) microVMs when `vk` is on the PATH, otherwise (or
with `--docker`) in Docker:

```sh
./build.sh [--package] [--verify]   # dist/debbuild-rs, its manifest (and archive)
./check.sh fmt [--check] | clippy | lint | audit
./test.sh [--debian=12,13]          # the tests, on Debian 12 and 13
tests/e2e.sh [--debian=12,13]       # the end-to-end gate, against dist/'s archive
./ci.sh                             # all of the above, in CI's order
```

The build image pins its base by digest and its toolchain by
[flake.lock](.devcontainer/nix/flake.lock): the same commit builds the same binary, which
`./build.sh --verify` checks by building it twice. `build.sh` writes the commit and the pins
next to the binary's checksum, in `dist/debbuild-rs.sha256`.

The tests are built static in the build image and run on Debian, where the tools
debbuild-rs stands in for are those of the release: a test needing one fails there rather
than skip. The end-to-end gate builds a C package with dpkg-buildpackage and with
`stage` + `pack` and requires identical .deb files, checks `install` against `dpkg -i`,
and has each upgrade and remove what the other installed.

A plain `cargo build` / `cargo test` works too, given a C compiler; Rust 1.88 is the
minimum.

## Releases

Push the candidate to the `release` branch: a commit setting the version in Cargo.toml and
turning `## Unreleased` of [CHANGELOG.md](CHANGELOG.md) into `## vX.Y.Z - YYYY-MM-DD`.
The release workflow runs the checks, builds the archives twice requiring identical
bytes, runs the end-to-end gate on them, then fast-forwards `main`, tags `vX.Y.Z` and
publishes the archives with their checksums and build manifests.

## Status

Developed for the WALLIX Bastion build, where it builds every product package. The
installer's error messages and the `check --vs-oracle` harness still follow the
implementation it replaced there.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.
