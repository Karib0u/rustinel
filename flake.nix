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
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfree = true;
          };

          rustinel = pkgs.callPackage ./nix/package.nix { };
        in
        {
          packages.default = rustinel;
          packages.rustinel = rustinel;

          devShells.default = pkgs.callPackage ./nix/shell.nix { };

          formatter = pkgs.nixfmt-tree;
        };
    in
    {
      overlays.default = final: prev: {
        rustinel = prev.callPackage ./nix/package.nix { };
      };

      packages = eachSystem (system: (forSystem system).packages);

      devShells = eachSystem (system: (forSystem system).devShells);

      formatter = eachSystem (system: (forSystem system).formatter);
    };
}
