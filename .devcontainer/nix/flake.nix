{
  # The build toolchain, installed by .devcontainer/Dockerfile as `buildEnv`:
  #   - Rust with the host architecture's musl target, clippy and rustfmt, at the channel
  #     ../../rust-toolchain.toml pins (inline: a flake cannot read outside its directory).
  #   - the musl cross gcc/binutils for the C of liblzma-sys and zstd-sys, and the host gcc
  #     for build scripts. ../../.cargo/config.toml selects them.
  #   - git, ca-certificates, cargo-audit, jq (test.sh lists the test binaries with it) and
  #     the shell tools the scripts run.
  #
  # flake.lock pins nixpkgs and rust-overlay by commit, so the closure can be rebuilt from
  # the same sources later. Nix runs only inside the build image.
  #
  # On a host with Nix:  nix develop ./.devcontainer/nix

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = nixpkgs.lib.genAttrs systems;

      envFor = system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };

          # pkgsCross names its compilers `<triple>-cc`, which .cargo/config.toml uses,
          # without clashing with the host `cc`.
          muslPkgs = {
            x86_64-linux = pkgs.pkgsCross.musl64;
            aarch64-linux = pkgs.pkgsCross.aarch64-multiplatform-musl;
          }.${system};
          muslTarget = muslPkgs.stdenv.hostPlatform.config;

          rustToolchain = pkgs.rust-bin.stable."1.99.0".minimal.override {
            extensions = [ "clippy" "rustfmt" ];
            targets = [ muslTarget ];
          };

          buildTools = with pkgs; [
            rustToolchain
            muslPkgs.stdenv.cc
            stdenv.cc
            git
            cacert
            cargo-audit
            jq
            coreutils
            bash
            gnugrep
            gnused
            findutils
            diffutils
            # jemalloc's configure and build (tikv-jemalloc-sys)
            gnumake
            gawk
          ];

          binEnv = pkgs.buildEnv {
            name = "debbuild-rs-build-env";
            paths = buildTools;
            pathsToLink = [ "/bin" "/etc" "/lib" "/libexec" ];
          };
        in
        { inherit pkgs muslTarget buildTools binEnv; };
    in
    {
      devShells = eachSystem (system:
        let env = envFor system; in
        {
          default = env.pkgs.mkShell {
            packages = env.buildTools;
            SOURCE_DATE_EPOCH = "0";
          };
        });

      packages = eachSystem (system:
        let env = envFor system; in
        {
          buildEnv = env.binEnv;
          default = env.binEnv;
        });
    };
}
