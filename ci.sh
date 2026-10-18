#!/usr/bin/env bash
# What CI runs (.github/workflows/ci.yml), locally and in order, stopping at the first
# failure: the source checks, the tests on Debian 12 and 13, the release archive built
# twice to require identical bytes, and the end-to-end gate on it.
#
#   ./ci.sh [--docker]
#
# The MSRV build of quality.yml is left out: it needs that toolchain on the host.
set -euo pipefail
cd "$(dirname "$0")"

args=()
for a in "$@"; do
  case "$a" in
    --docker) args+=("$a") ;;
    *) echo "ci.sh: unknown argument: $a (--docker)" >&2; exit 2 ;;
  esac
done

step() {
  echo "ci.sh: $*" >&2
  "$@" "${args[@]}"
}
step ./check.sh lint
step ./check.sh audit
step ./test.sh
step ./build.sh --package --verify
step tests/e2e.sh
echo "ci.sh: passed" >&2
