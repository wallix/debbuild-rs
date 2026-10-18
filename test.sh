#!/usr/bin/env bash
# Run the test suite on Debian: the tests are built static (musl) in the pinned build
# image, then run in the Debian images, where dpkg, debhelper and fakeroot are those of the
# release. A test that needs one of them fails there instead of skipping.
#
#   ./test.sh [--docker] [--debian=12,13] [TEST ARGS...]
#
# TEST ARGS go to every test binary (a name filter, --nocapture...).
set -euo pipefail
cd "$(dirname "$0")"
. scripts/lib.sh

backend_from_args test.sh "$@"
DEBIAN="12 13"
targs=()
for a in "${ARGS[@]}"; do
  case "$a" in
    --debian=*) DEBIAN=${a#--debian=}; DEBIAN=${DEBIAN//,/ } ;;
    *) targs+=("$a") ;;
  esac
done

TARGET=$(host_target)
cargo_env "$TARGET"
# The test executables, with the package directory cargo would run each one in.
# target/ is missing from a fresh checkout; pipefail: a failed build is not a short list.
run_in debbuild-rs-build --net "${CARGO_ENV[@]}" -- bash -c "
  set -eo pipefail
  mkdir -p target
  cargo test --workspace --locked --target $TARGET --no-run --message-format=json-render-diagnostics |
    jq -r 'select(.reason == \"compiler-artifact\" and .profile.test and .executable != null)
      | [(.manifest_path | rtrimstr(\"/Cargo.toml\")), .executable] | @tsv' >target/test-bins.tsv
"

# shellcheck disable=SC2016 # expanded by the Debian shell
runner='
  status=0
  while IFS="$(printf "\t")" read -r dir exe; do
    echo "== $exe" >&2
    (cd "$dir" && "$exe" "$@") || status=1
  done <target/test-bins.tsv
  exit $status
'
status=0
for v in $DEBIAN; do
  echo "test.sh: Debian $v" >&2
  run_in "debian-$v" --root --env DEBBUILD_RS_TEST_REQUIRE_TOOLS=1 -- \
    sh -c "$runner" sh "${targs[@]}" || status=1
done
exit $status
