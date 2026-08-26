{
  description = "Rustinel - open-source endpoint detection for Windows, Linux, and macOS (Nix flake)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      eachSystem = nixpkgs.lib.genAttrs supportedSystems;

      forSystem =
        system:
        let
          pkgs = import nixpkgs { inherit system; };

          rustinel = pkgs.callPackage ./nix/package.nix { };
        in
        {
          packages.default = rustinel;
          packages.rustinel = rustinel;

          # `nix flake check` builds the checks output. CI collapses to a
          # single `nix flake check` (no --no-build), which builds the native
          # package, fetches + verifies the aarch64 archive's SRI hash using
          # the local stdenv's fetchurl (no QEMU), and runs a --version smoke
          # test. Nothing here is exposed as an installable.
          checks = {
            # Native package build.
            rustinel = rustinel;

            # Fetch + SRI-verify the aarch64 release archive on the local
            # arch. fetchurl only needs bash + curl, so this builds on an
            # x86_64 runner without emulation and catches a broken URL or
            # stale hash for the non-native arch.
            aarch64-src = rustinel.passthru.srcFor "aarch64-linux";

            # Smoke-test that the wrapped binary reports a rustinel version.
            version = pkgs.runCommand "rustinel-version-check" { } ''
              ${rustinel}/bin/rustinel --version | grep -q '^rustinel ' || {
                echo "unexpected version output:" >&2
                ${rustinel}/bin/rustinel --version >&2
                exit 1
              }
              touch $out
            '';
          };

          formatter = pkgs.nixfmt-tree;
        };
    in
    {
      overlays.default = final: prev: {
        rustinel = final.callPackage ./nix/package.nix { };
      };

      packages = eachSystem (system: (forSystem system).packages);

      checks = eachSystem (system: (forSystem system).checks);

      formatter = eachSystem (system: (forSystem system).formatter);
    };
}
