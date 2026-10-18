#!/bin/sh
# The end-to-end run, as root in a Debian image (tests/e2e.sh starts it), against the
# release archive in DIST:
#
#   1. the archive matches its sidecar, and its binary runs (and has RELEASE_TAG's version)
#   2. stage + pack builds the same .deb files, byte for byte, as dpkg-buildpackage (the
#      data package carries files of the build time that dh_strip_nondeterminism, native
#      or debhelper's, normalizes)
#   3. `debbuild-rs check` finds that `debbuild-rs install` leaves a root as dpkg -i does,
#      on install and on upgrade
#   4. on the system itself: debbuild-rs installs, dpkg verifies, upgrades and purges it,
#      and debbuild-rs upgrades what dpkg installed
set -eu

DIST=${DIST:-/work/dist}
HERE=$(cd "$(dirname "$0")" && pwd)
. /etc/os-release
say() { printf '\n######## %s (Debian %s)\n' "$*" "$VERSION_ID"; }

case "$(uname -m)" in
  x86_64) ARCH=x86_64 ;;
  aarch64) ARCH=aarch64 ;;
  *) echo "e2e: no release archive for $(uname -m)" >&2; exit 2 ;;
esac

# Scratch on a tmpfs: `check` puts its overlays' upper layers there, which overlayfs
# refuses on an overlayfs (the root of a container).
W=/var/tmp/debbuild-rs-e2e
mkdir -p "$W"
mount -t tmpfs tmpfs "$W"
# On failure, the packages of both sides go to KEEP for a look.
KEEP=${KEEP:-/work/target/e2e/debian-$VERSION_ID}
keep() {
  status=$?
  if [ $status -ne 0 ] && [ -d "$W/ref" ]; then
    rm -rf "$KEEP" && mkdir -p "$KEEP" && cp -a "$W/ref" "$W/debs" "$W/stage" "$KEEP/" 2>/dev/null || :
    echo "e2e: failed; the packages are in $KEEP" >&2
  fi
  umount -l "$W"
  exit $status
}
trap keep EXIT

say "release archive"
(cd "$DIST" && sha256sum -c "debbuild-rs-linux-$ARCH.sha256")
mkdir "$W/bin"
tar -xzf "$DIST/debbuild-rs-linux-$ARCH.tar.gz" -C "$W/bin"
DB=$W/bin/debbuild-rs
file "$DB" | grep -Eq 'static(ally|-pie) linked' || { file "$DB"; echo "e2e: not a static binary" >&2; exit 1; }
"$DB" --version
if [ -n "${RELEASE_TAG:-}" ]; then
  [ "$("$DB" --version)" = "debbuild-rs ${RELEASE_TAG#v}" ] ||
    { echo "e2e: the binary is not version ${RELEASE_TAG#v}" >&2; exit 1; }
fi

say "stage + pack against dpkg-buildpackage"
# The same directory for both builds: the debug info names it.
SRC=$W/src/hello-e2e
mkdir -p "$W/src" "$W/ref"
cp -a "$HERE/hello-e2e" "$SRC"
(cd "$SRC" && dpkg-buildpackage -b -uc -us >"$W/ref/build.log" 2>&1) ||
  { cat "$W/ref/build.log"; exit 1; }
mv "$W"/src/*.deb "$W/ref/"
"$DB" stage --check-build-deps -o "$W/stage" "$SRC"
# pack takes the epoch stage recorded: the changelog's, as dpkg-buildpackage's.
"$DB" pack -d "$W/debs" "$W/stage/hello-e2e" >/dev/null
(cd "$W/ref" && ls -- *.deb) >"$W/ref.list"
(cd "$W/debs" && ls -- *.deb) >"$W/debs.list"
diff -u "$W/ref.list" "$W/debs.list"
grep -q -- '-dbgsym_' "$W/ref.list" || { echo "e2e: no -dbgsym package" >&2; exit 1; }
while read -r deb; do
  cmp "$W/ref/$deb" "$W/debs/$deb"
  echo "identical: $deb"
done <"$W/ref.list"

say "stage again: inspect, diff-stage"
"$DB" inspect "$W/stage"
"$DB" stage -o "$W/stage-again" "$SRC"
"$DB" diff-stage "$W/stage/hello-e2e" "$W/stage-again/hello-e2e"

say "check: debbuild-rs install against dpkg -i"
"$DB" check -u -s "$W/stage" -w "$W/check" hello-e2e

say "debbuild-rs install, then dpkg"
"$DB" install --stage "$W/stage" --dry-run hello-e2e
"$DB" install --stage "$W/stage" hello-e2e
[ "$("$DB" install --stage "$W/stage" --dry-run --json hello-e2e)" = \
  '{"packages":[{"name":"hello-e2e-data","action":"skip","state":"installed","old_version":"1.0","new_version":"1.0","reasons":[{"kind":"dependency","by":"hello-e2e","field":"Depends","relation":"hello-e2e-data (= 1.0)"}]},{"name":"hello-e2e","action":"skip","state":"installed","old_version":"1.0","new_version":"1.0","reasons":[{"kind":"requested"}]}]}' ]
[ "$(hello-e2e)" = "hello from debbuild-rs" ]
[ "$(dpkg-query -W -f '${Status} ${Version}' hello-e2e-data)" = "install ok installed 1.0" ]
[ -z "$(cat /var/lib/hello-e2e/configured-from)" ]
dpkg --verify hello-e2e hello-e2e-data
[ -z "$(dpkg --audit)" ]

# A second version, staged from a new changelog entry.
cp -a "$SRC" "$W/src/v2"
{
  printf 'hello-e2e (1.1) unstable; urgency=medium\n\n  * Upgrade.\n\n'
  printf ' -- debbuild-rs <debbuild-rs@example.org>  Fri, 02 Jan 2026 00:00:00 +0000\n\n'
  cat "$SRC/debian/changelog"
} >"$W/src/v2/debian/changelog.new"
mv "$W/src/v2/debian/changelog.new" "$W/src/v2/debian/changelog"
echo "verbose = yes" >"$W/src/v2/hello-e2e.conf"
"$DB" stage -o "$W/stage2" "$W/src/v2"
"$DB" pack -d "$W/debs2" "$W/stage2/v2" >/dev/null

# dpkg upgrades what debbuild-rs installed, then purges it.
dpkg -i "$W"/debs2/hello-e2e_1.1_*.deb "$W"/debs2/hello-e2e-data_1.1_all.deb
[ "$(cat /var/lib/hello-e2e/configured-from)" = 1.0 ]
[ "$(cat /etc/hello-e2e.conf)" = "verbose = yes" ]
dpkg --verify hello-e2e hello-e2e-data
dpkg --purge hello-e2e hello-e2e-data
[ ! -e /usr/bin/hello-e2e ] && [ ! -e /etc/hello-e2e.conf ] && [ ! -e /var/lib/hello-e2e ]

say "dpkg -i, then debbuild-rs install"
dpkg -i "$W"/ref/hello-e2e_1.0_*.deb "$W"/ref/hello-e2e-data_1.0_all.deb
echo "verbose = maybe" >/etc/hello-e2e.conf
"$DB" install --stage "$W/stage2" hello-e2e
[ "$(dpkg-query -W -f '${Version}' hello-e2e)" = 1.1 ]
[ "$(cat /var/lib/hello-e2e/configured-from)" = 1.0 ]
# The modified conffile is kept, the new one put beside it, as dpkg --force-confold does.
[ "$(cat /etc/hello-e2e.conf)" = "verbose = maybe" ]
[ "$(cat /etc/hello-e2e.conf.dpkg-dist)" = "verbose = yes" ]
dpkg --verify hello-e2e-data
[ -z "$(dpkg --audit)" ]
dpkg --purge hello-e2e hello-e2e-data

say "passed"
