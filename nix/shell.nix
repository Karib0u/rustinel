{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  name = "rustinel-nix";

  packages = with pkgs; [
    nixfmt-rfc-style
    nil
  ];
}
