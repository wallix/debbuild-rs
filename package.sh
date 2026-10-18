#!/usr/bin/env bash
# Write the release archive of a built binary, byte-for-byte reproducible:
#
#   OUT/debbuild-rs-linux-<arch>.tar.gz   debbuild-rs, README.md and the licenses
#   OUT/debbuild-rs-linux-<arch>.sha256   its sha256sum line
#
# Usage: ./package.sh BINARY OUT
set -euo pipefail
cd "$(dirname "$0")"

[ $# -eq 2 ] || { echo "usage: $0 BINARY OUT" >&2; exit 2; }
BINARY=$1
OUT=$2
[ -f "$BINARY" ] || { echo "package.sh: no binary at $BINARY" >&2; exit 1; }

# The architecture comes from the binary, not the host.
case "$(file -b "$BINARY")" in
  *x86-64*) ARCH=x86_64 ;;
  *aarch64*) ARCH=aarch64 ;;
  *) echo "package.sh: $BINARY is no x86-64 or aarch64 executable" >&2; exit 1 ;;
esac
STEM=debbuild-rs-linux-$ARCH

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
install -m 0755 "$BINARY" "$STAGE/debbuild-rs"
install -m 0644 README.md LICENSE-APACHE LICENSE-MIT "$STAGE/"

mkdir -p "$OUT"
# Members listed in a fixed order, with fixed owners, modes and times; gzip -n leaves the
# name and time out of its header.
tar --format=gnu --no-recursion --owner=0 --group=0 --numeric-owner --mtime=@0 \
  -cf - -C "$STAGE" LICENSE-APACHE LICENSE-MIT README.md debbuild-rs |
  gzip -9n >"$OUT/.$STEM.tar.gz.tmp"
digest=$(sha256sum "$OUT/.$STEM.tar.gz.tmp" | cut -d' ' -f1)
printf '%s  %s\n' "$digest" "$STEM.tar.gz" >"$OUT/.$STEM.sha256.tmp"
mv -f "$OUT/.$STEM.tar.gz.tmp" "$OUT/$STEM.tar.gz"
mv -f "$OUT/.$STEM.sha256.tmp" "$OUT/$STEM.sha256"
echo "package.sh: wrote $OUT/$STEM.tar.gz" >&2
