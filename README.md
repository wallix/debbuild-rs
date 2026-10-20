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
| `debbuild-rs strip-nondeterminism --pyc PATH...` | Also normalizes Python bytecode (.pyc files, and those under directories) as add-determinism does, byte for byte. |
| `debbuild-rs strip-nondeterminism -T SECONDS [--exclude GLOB]... DIR...` | Normalizes every regular file under directories, except those whose name matches a glob. |

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
the same output, from native handlers for every format strip-nondeterminism normalizes:
gzip, zip (and `.whl`, `.epub`, `.pk3`..., Zip64 included), jar (and `.war`, `.apk`...),
Java modules, Python zip applications, PNG, gettext `.mo`, javadoc HTML, cpio archives,
U-Boot images, bFLT executables, and ar archives (off by default, as there), picked as
strip-nondeterminism picks them, by file name, content and file(1); neither
strip-nondeterminism nor debhelper's helper is run. `debbuild-rs strip-nondeterminism`
is the same on strip-nondeterminism's command line, where `-T` is needed (without it, or
with `--clamp-timestamp`, the run is strip-nondeterminism's).

The handlers were written from the format specifications (RFC 1952, the zip APPNOTE,
PNG, the GNU gettext catalog format, cpio(5), the U-Boot legacy image and bFLT headers,
the JDK's jmod and Python's zipapp documentation) and from running strip-nondeterminism
1.13 (Debian 12) and 1.14 (Debian 13) on crafted files; `tests/strip.rs` keeps comparing
the two.

#### Differences from strip-nondeterminism

The output is strip-nondeterminism's for every well-formed file, but for the compressed
bytes of rewritten jar members (below). Where its handlers have a bug, debbuild-rs does
the right thing instead, and a few details of the interface differ; `tests/strip.rs` and the handlers' unit tests check these behaviours on their
own:

- zip, jar: a deflated jar member whose content is rewritten (the manifest, a javadoc
  page, a nested jar) is compressed again with flate2, where strip-nondeterminism uses
  zlib. Such a jar holds the same members, metadata and contents as
  strip-nondeterminism's, but different compressed bytes for those members; the tests
  compare them by content.
- zip, jar: archives are replaced through a temporary file, where strip-nondeterminism
  moves the original to a `.zbk` backup next to it, overwriting and deleting any file
  of that name.
- zip, jar: bytes of an extra field block that do not make a whole field (a stray
  byte, a field running past the end of the block) are kept as they are, where
  strip-nondeterminism drops them, or every field of the header.
- zip, jar: an extended timestamp field of another length than 1 + 4n gets the
  timestamp in each whole slot, its last bytes kept, where strip-nondeterminism writes
  past them; an NTFS attribute of size 0 is stepped over, where strip-nondeterminism
  hangs; an Info-ZIP Unix field whose uid and gid sizes do not add up to its length is
  kept as it is, where strip-nondeterminism writes it again from those sizes under its
  old length.
- jar: a member named `0` is kept, which strip-nondeterminism drops along with javac's
  leftovers.
- jar: jars in jars are normalized up to 32 deep; a jar nested deeper fails the
  outermost archive, where strip-nondeterminism has no limit.
- ar: an archive that fails (a malformed header after good ones) is left as it is,
  where strip-nondeterminism leaves the headers before the failure rewritten; a
  timestamp too long for the 12-digit mtime field fails the file, where it overwrites
  the fields after it.
- cpio: a timestamp the mtime field of the archive's format cannot hold (negative, or
  too large) fails the file, where strip-nondeterminism lets it overwrite the fields
  after it, or wraps it around; an archive with a name that, given back its NUL, no
  longer fits its namesize field is left alone.
- PNG: the bytes of a partial chunk header at the end of the file are kept, where
  strip-nondeterminism loses them; a `tIME` or date text chunk of 4092 bytes or more is
  normalized, where strip-nondeterminism copies it unexamined.
- A timestamp before the year 1 gives javadoc, gettext and PNG dates in the proleptic
  Gregorian calendar, where strip-nondeterminism writes wrong dates.
- Detection matches file(1)'s description of a file, not its whole output line, which
  starts with the file's path: a name such as `gzip compressed data.gz` does not make a
  text file a gzip one.
- With the pyzip handler disabled (`--normalizers=-pyzip`, `-all`...), a file no other
  handler takes is left alone, where strip-nondeterminism dies.
- `strip-nondeterminism` prints what it normalized as neither release does (1.13 prints
  `Normalizing FILE` with `-v` for each file it handles; 1.14 prints `Normalized FILE`
  for each file it rewrites, and `Calling normalizer for FILE` before with `-v`): with
  `-v`, `Normalized FILE (HANDLER)` on stderr for each file it rewrote, otherwise
  nothing.
- `strip-nondeterminism -t` with a directory operand is an error (exit status 2), where
  strip-nondeterminism tries the handler on the directory itself.
- `strip-nondeterminism -T` takes an integer of 64 bits, negative ones included, and
  refuses a larger one (exit status 255), which strip-nondeterminism takes in floating
  point. The error for a value that is not a number names the option `T`, however it
  was spelled.
- A failed system call (reading or writing a file) ends `strip-nondeterminism` with
  exit status 1, where strip-nondeterminism's status depends on the error.
- `dh_strip_nondeterminism -v` prints `Normalized FILE (HANDLER)` for each file it
  rewrote, where debhelper's helper (Debian 12 and 13) prints `Using TIMESTAMP as
  canonical time`, then `Normalizing FILE using
  File::StripNondeterminism::handlers::HANDLER` for each file a handler takes,
  rewritten or not.

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
- With `-T`, directory operands are walked: each regular file, symbolic links not
  followed, goes through detection as files given do; a file reached through several
  operands or names (hard links) is processed each time. Without `-T`, only the .pyc
  files under them are taken, as strip-nondeterminism skips directories. With `-t`,
  which forces a handler on the files named, a directory operand is an error (exit
  status 2). `--exclude GLOB` (repeatable, a shell glob: `*`, `?`, `[...]`) leaves
  alone the files whose name matches it.
- Under `stage`, `dh_strip_nondeterminism` normalizes the .pyc files of the package trees
  too when `DEBBUILD_RS_STRIP_PYC` is set (non-empty), as in
  `export DEBBUILD_RS_STRIP_PYC = 1` in debian/rules. Debhelper's helper ignores it.

For a build that runs `add-determinism DIR`, the replacement is

```sh
debbuild-rs strip-nondeterminism --pyc --normalizers=+ar -T "$SOURCE_DATE_EPOCH" \
  [--exclude GLOB]... DIR...
```

This applies add-determinism's pyc normalization and strip-nondeterminism's
handlers to every file under the directories. It covers add-determinism's ar, gzip,
jar, javadoc and zip formats, plus the other formats strip-nondeterminism handles.

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
