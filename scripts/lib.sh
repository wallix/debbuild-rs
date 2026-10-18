# shellcheck shell=bash
# Run commands in the images of .devcontainer/Dockerfile, sourced by the top-level scripts.
#
# The backend is the vk on PATH (a microVM), else Docker; --docker in the script's
# arguments, which the caller passes to backend_from_args, forces Docker. Both share the
# repository at /work and run the command there, so paths agree between the build image
# and the Debian images (the test binaries name their executables by path).

DOCKERFILE=.devcontainer/Dockerfile
CONTEXT=.devcontainer

BACKEND=""

# backend_from_args SCRIPT ARGS...: pick the backend, and leave the other arguments in
# the ARGS array.
backend_from_args() {
  local script=$1
  shift
  ARGS=()
  local force_docker=""
  for a in "$@"; do
    case "$a" in
      --docker) force_docker=1 ;;
      *) ARGS+=("$a") ;;
    esac
  done
  if [ -z "$force_docker" ] && command -v vk >/dev/null 2>&1; then
    BACKEND=vk
    echo "$script: running in vk microVMs ($(command -v vk)); pass --docker to use Docker" >&2
  else
    command -v docker >/dev/null 2>&1 || { echo "$script: neither vk nor docker is on PATH" >&2; exit 2; }
    BACKEND=docker
  fi
}

# run_in TARGET [--net] [--root] [--env K=V]... -- CMD...
#
# Runs CMD in the image of the Dockerfile stage TARGET. --net gives it network access
# (cargo fetching crates); --root runs it as root under Docker, as it always is in a vk
# guest (the Debian side installs packages and mounts overlays).
run_in() {
  local target=$1
  shift
  local net="" root=""
  local envs=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --net) net=1; shift ;;
      --root) root=1; shift ;;
      --env) envs+=("$2"); shift 2 ;;
      --) shift; break ;;
      *) echo "run_in: unknown option $1" >&2; return 2 ;;
    esac
  done
  if [ "$BACKEND" = vk ]; then
    local opts=(--file "$DOCKERFILE" --context "$CONTEXT" --target "$target"
      --workdir "$PWD" --cpus host --mem 8G)
    [ -n "$net" ] && opts+=(--net)
    for e in "${envs[@]}"; do opts+=(--env "$e"); done
    vk run "${opts[@]}" -- "$@"
  else
    # CI builds the images beforehand, with a layer cache (.github/actions/image).
    if [ -z "${DEBBUILD_RS_PREBUILT_IMAGES:-}" ]; then
      docker build -q --target "$target" -t "debbuild-rs-$target" -f "$DOCKERFILE" "$CONTEXT" >/dev/null
    fi
    local opts=(--rm --init -v "$PWD":/work -w /work -e HOME=/tmp)
    if [ -n "$root" ]; then
      # Mounting the overlays of `debbuild-rs check` needs the privileges of a VM root.
      opts+=(--privileged)
    else
      # The host user, so target/ stays theirs.
      opts+=(--user "$(id -u):$(id -g)")
    fi
    [ -z "$net" ] && opts+=(--network none)
    for e in "${envs[@]}"; do opts+=(-e "$e"); done
    docker run "${opts[@]}" "debbuild-rs-$target" "$@"
  fi
}

# The musl target of the host architecture: releases are built natively.
host_target() {
  case "$(uname -m)" in
    x86_64 | amd64) echo x86_64-unknown-linux-musl ;;
    aarch64 | arm64) echo aarch64-unknown-linux-musl ;;
    *) echo "no musl target for $(uname -m)" >&2; return 2 ;;
  esac
}

# The environment of every cargo run in the build image: a cargo home under target/ (cached
# with it) and the paths of the sources remapped out of the binaries.
cargo_env() {
  local target=$1
  local remap="--remap-path-prefix=/work=/src --remap-path-prefix=/work/target/.cargo-home=/cargo"
  # shellcheck disable=SC2034 # read by the scripts sourcing this file
  CARGO_ENV=(
    --env HOME=/tmp
    --env CARGO_HOME=/work/target/.cargo-home
    --env CARGO_TARGET_DIR=/work/target
    --env SOURCE_DATE_EPOCH=0
    --env "RUSTFLAGS=$remap"
    --env "CFLAGS_${target//-/_}=-ffile-prefix-map=/work=/src -ffile-prefix-map=/work/target/.cargo-home=/cargo"
  )
}
