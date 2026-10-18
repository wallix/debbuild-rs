#!/usr/bin/env bash
# The source checks, in the pinned build image:
#
#   ./check.sh fmt [--check]   cargo fmt
#   ./check.sh clippy          cargo clippy on every target, warnings denied
#   ./check.sh lint            fmt --check, then clippy
#   ./check.sh audit           cargo audit of Cargo.lock, warnings denied
#
# --docker uses Docker instead of the vk on PATH. ./test.sh runs the tests, ./ci.sh all
# of CI.
set -euo pipefail
cd "$(dirname "$0")"
. scripts/lib.sh

backend_from_args check.sh "$@"
set -- "${ARGS[@]}"
[ $# -ge 1 ] || { echo "usage: $0 fmt [--check] | clippy | lint | audit [--docker]" >&2; exit 2; }
cmd=$1
shift

cargo_env "$(host_target)"
fmt() { run_in debbuild-rs-build "${CARGO_ENV[@]}" -- cargo fmt --all "$@"; }
clippy() {
  run_in debbuild-rs-build --net "${CARGO_ENV[@]}" -- \
    cargo clippy --workspace --all-targets --locked "$@" -- -D warnings
}
case "$cmd" in
  fmt) fmt "$@" ;;
  clippy) clippy "$@" ;;
  lint) fmt --check && clippy "$@" ;;
  audit)
    # A fresh advisory database each run: cargo-audit fails to update the copy a
    # previous run left in the cargo home ("failed to find `origin` remote").
    rm -rf target/.cargo-home/advisory-db target/.cargo-home/advisory-db..lock
    run_in debbuild-rs-build --net "${CARGO_ENV[@]}" -- cargo audit --deny warnings "$@"
    ;;
  *) echo "check.sh: unknown check $cmd (fmt, clippy, lint, audit)" >&2; exit 2 ;;
esac
