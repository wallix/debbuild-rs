#!/usr/bin/env bash
# The end-to-end gate: tests/e2e/run.sh in each Debian image, against the release archive
# in dist/ (./build.sh --package) or DIST.
#
#   tests/e2e.sh [--docker] [--debian=12,13]
#   RELEASE_TAG=v0.1.0 tests/e2e.sh     # also require that version
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib.sh

backend_from_args e2e.sh "$@"
DEBIAN="12 13"
for a in "${ARGS[@]}"; do
  case "$a" in
    --debian=*) DEBIAN=${a#--debian=}; DEBIAN=${DEBIAN//,/ } ;;
    *) echo "e2e.sh: unknown argument: $a (--docker, --debian=)" >&2; exit 2 ;;
  esac
done
DIST=${DIST:-dist}
case "$(cd "$DIST" && pwd)/" in
  "$PWD"/*) ;;
  *) echo "e2e.sh: DIST must be inside the repository, which the images share" >&2; exit 2 ;;
esac
dist=/work/$(realpath --relative-to=. "$DIST")

status=0
for v in $DEBIAN; do
  run_in "debian-$v" --root --env "DIST=$dist" --env "RELEASE_TAG=${RELEASE_TAG:-}" -- \
    tests/e2e/run.sh || { echo "e2e.sh: Debian $v failed" >&2; status=1; }
done
exit $status
