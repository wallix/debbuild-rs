#!/usr/bin/env bash
# Build the release binary: a static musl debbuild-rs for the host architecture, in the
# pinned build image, written to dist/debbuild-rs with its manifest dist/debbuild-rs.sha256.
#
#   --docker    use Docker instead of the vk on PATH
#   --package   also write the release archive (package.sh)
#   --verify    rebuild from a clean copy of the tree and require the same bytes
set -euo pipefail
cd "$(dirname "$0")"
. scripts/lib.sh

backend_from_args build.sh "$@"
PACKAGE=""
VERIFY=""
for a in "${ARGS[@]}"; do
  case "$a" in
    --package) PACKAGE=1 ;;
    --verify) VERIFY=1 ;;
    *) echo "build.sh: unknown argument: $a (--docker, --package, --verify)" >&2; exit 2 ;;
  esac
done

TARGET=$(host_target)
OUT=dist
cargo_env "$TARGET"
run_in debbuild-rs-build --net "${CARGO_ENV[@]}" -- \
  cargo build --release --locked --target "$TARGET" --bin debbuild-rs

mkdir -p "$OUT"
# A rename, so a running debbuild-rs is never overwritten in place.
cp "target/$TARGET/release/debbuild-rs" "$OUT/.debbuild-rs.tmp"
mv -f "$OUT/.debbuild-rs.tmp" "$OUT/debbuild-rs"

toolchain=$(sed -nE 's/^channel = "(.*)"$/\1/p' rust-toolchain.toml)
base_image=$(sed -nE 's/^FROM (nixos\/nix:[^ ]+) .*$/\1/p' "$DOCKERFILE")
flake_lock=$(sha256sum .devcontainer/nix/flake.lock | cut -d' ' -f1)
commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
dirty=""
git diff --quiet HEAD 2>/dev/null || dirty=" (dirty tree)"
(
  cd "$OUT"
  {
    echo "# debbuild-rs reproducible build manifest"
    echo "# commit:     ${commit}${dirty}"
    echo "# target:     ${TARGET}"
    echo "# toolchain:  ${toolchain}"
    echo "# base image: ${base_image}"
    echo "# flake lock: sha256:${flake_lock}"
    echo "# verify: git checkout ${commit} && cp dist/debbuild-rs.sha256 /tmp/expected &&"
    echo "#         ./build.sh && ( cd dist && sha256sum -c /tmp/expected )"
    sha256sum debbuild-rs
  } >debbuild-rs.sha256
)
echo "build.sh: wrote $OUT/debbuild-rs" >&2

if [ -n "$VERIFY" ]; then
  built=$(sha256sum <"$OUT/debbuild-rs" | cut -d' ' -f1)
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  case "$tmp" in
    "$PWD"/*) echo "build.sh: \$TMPDIR must be outside the repository ($tmp)" >&2; exit 2 ;;
  esac
  echo "build.sh: rebuilding in $tmp to verify reproducibility" >&2
  tar -cf - --exclude=./.git --exclude=./target --exclude=./dist . | tar -xf - -C "$tmp"
  backend=()
  [ "$BACKEND" = docker ] && backend=(--docker)
  (cd "$tmp" && ./build.sh "${backend[@]}")
  rebuilt=$(sha256sum <"$tmp/$OUT/debbuild-rs" | cut -d' ' -f1)
  if [ "$built" != "$rebuilt" ]; then
    cp "$tmp/$OUT/debbuild-rs" "$OUT/debbuild-rs.rebuild"
    echo "build.sh: not reproducible: $built != $rebuilt (the rebuild is $OUT/debbuild-rs.rebuild)" >&2
    exit 1
  fi
  echo "build.sh: reproducible, both builds are $built" >&2
fi

if [ -n "$PACKAGE" ]; then
  ./package.sh "$OUT/debbuild-rs" "$OUT"
fi
