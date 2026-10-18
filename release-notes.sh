#!/usr/bin/env bash
# Print the CHANGELOG.md section of a release tag: from `## vX.Y.Z - <date>` to the next
# `## ` heading, without trailing blank lines. A missing or empty section is an error.
#
# Usage: ./release-notes.sh vX.Y.Z
set -euo pipefail
cd "$(dirname "$0")"

[ $# -eq 1 ] || { echo "usage: $0 vX.Y.Z" >&2; exit 2; }
TAG=$1
case "$TAG" in
  v[0-9]*) ;;
  *) echo "release-notes.sh: '$TAG' is not a vX.Y.Z tag" >&2; exit 2 ;;
esac

notes=$(awk -v tag="$TAG" '
  /^## / { split($0, f, " "); inside = (f[2] == tag); next }
  !inside { next }
  /^[[:space:]]*$/ { if (seen) pending = pending "\n"; next }
  { printf "%s%s\n", pending, $0; pending = ""; seen = 1 }
' CHANGELOG.md)
[ -n "$notes" ] || { echo "release-notes.sh: no '## $TAG' section with a body in CHANGELOG.md" >&2; exit 1; }
printf '%s\n' "$notes"
