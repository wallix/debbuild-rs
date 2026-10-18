# The images the scripts run in (docker build, or `vk run --file`):
#
#   debbuild-rs-build  the pinned toolchain release builds, lint, audit and the test build
#                      run in (build.sh, check.sh, test.sh)
#   debian-12          Debian bookworm and trixie with the Debian tools debbuild-rs stands
#   debian-13          in for, where the tests and the end-to-end run (test.sh,
#                      tests/e2e.sh)
#   add-determinism    add-determinism, the reference the Python bytecode normalizer is
#                      tested against in the Debian images; it never goes into debbuild-rs
#
# The build image's inputs are pinned for good: the nixos/nix base by manifest-list
# digest, and its packages by nix/flake.lock (nixpkgs and rust-overlay by commit). The
# Debian images pin their base by digest and install the current packages of their release.

# nixos/nix 2.35.3 by manifest-list digest.
FROM nixos/nix:2.35.3@sha256:ff480dbb23511aa1c10710aa068ceea5b93fed9bfce5f5379f3a6b07282cbc7b AS debbuild-rs-build

# Flakes are gated behind experimental-features on the stock image, and the Nix sandbox
# needs user namespaces neither Docker's builder nor vk's give it.
RUN mkdir -p /etc/nix \
 && printf 'experimental-features = nix-command flakes\nsandbox = false\n' >> /etc/nix/nix.conf

COPY nix /src/nix

# --no-update-lock-file rejects a missing or stale lock.
RUN nix build --no-update-lock-file "path:/src/nix#buildEnv" --out-link /opt/toolchain

ENV PATH=/opt/toolchain/bin:/root/.nix-profile/bin:/nix/var/nix/profiles/default/bin:/nix/var/nix/profiles/default/sbin \
    SSL_CERT_FILE=/opt/toolchain/etc/ssl/certs/ca-bundle.crt

# A passwd entry for uid 1000; HOME=/tmp for the other uids docker runs as.
RUN printf '\ndev:x:1000:1000:dev:/home/dev:/bin/sh\n' >> /etc/passwd \
 && printf '\ndev:x:1000:\n' >> /etc/group \
 && mkdir -p /home/dev && chown 1000:1000 /home/dev \
 && chmod 1777 /tmp

# add-determinism 0.7.3, static (musl) so it runs on both Debians: the .pyc reference
# of tests/strip.rs. Its crates come from crates.io, pinned by its Cargo.lock (--locked).
FROM debbuild-rs-build AS add-determinism
# The musl cross tools, as ../.cargo/config.toml names them for the workspace.
RUN t="$(uname -m)-unknown-linux-musl" \
 && T="$(echo "$t" | tr a-z- A-Z_)" \
 && env "CARGO_TARGET_${T}_LINKER=$t-cc" "CC_$(echo "$t" | tr - _)=$t-cc" \
      "AR_$(echo "$t" | tr - _)=$t-ar" CARGO_HOME=/tmp/cargo \
      cargo install --locked --target "$t" --root /opt/add-determinism add-determinism@0.7.3 \
 && rm -rf /tmp/cargo

# The Debian side: dpkg-dev and debhelper for staging, fakeroot, build-essential for the
# C package of the end-to-end run (its -dbgsym), file for its checks, and python3 with
# add-determinism for the .pyc tests.
FROM debian:12-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS debian-12
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential debhelper dpkg-dev fakeroot file python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=add-determinism /opt/add-determinism/bin/add-det /usr/local/bin/add-det

FROM debian:13-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS debian-13
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential debhelper dpkg-dev fakeroot file python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=add-determinism /opt/add-determinism/bin/add-det /usr/local/bin/add-det
