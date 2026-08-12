# Version and hash synchronization
#
# The `version` and `hashes` below are pinned to a GitHub release tarball.
# To update when a new rustinel release is published:
#
#   1. Set `version` to the new release tag (without the leading "v").
#   2. Recompute the SRI hash for each architecture:
#
#        nix-prefetch-url --type sha256 \
#          https://github.com/Karib0u/rustinel/releases/download/vVERSION/rustinel-VERSION-x86_64-unknown-linux-musl.tar.gz \
#          | xargs nix hash to-sri --type sha256
#
#        nix-prefetch-url --type sha256 \
#          https://github.com/Karib0u/rustinel/releases/download/vVERSION/rustinel-VERSION-aarch64-unknown-linux-musl.tar.gz \
#          | xargs nix hash to-sri --type sha256
#
#   3. Paste the two sha256-... strings into the `hashes` attrset below.
#   4. Run `nix flake check` and `nix build .#rustinel` to verify.
#
# The tarball layout is expected to be:
#   rustinel-VERSION-ARCH/
#     rustinel          (static musl binary)
#     config.toml
#     rules/{sigma,yara,ioc}/
{
  lib,
  stdenv,
  fetchurl,
}:

let
  version = "1.2.0";
  hashes = {
    x86_64-linux = "sha256-9Z+zB9tIvJsgTNORBDpu4w2YJdRtawnE1cZLIyXtCU0=";
    aarch64-linux = "sha256-de5YMFdyogyUFMMOtaEEoX6Pr9/dwwXYWxi/C74FVhM=";
  };
  archMap = {
    x86_64-linux = "x86_64-unknown-linux-musl";
    aarch64-linux = "aarch64-unknown-linux-musl";
  };
in
stdenv.mkDerivation {
  pname = "rustinel";
  inherit version;

  src = fetchurl {
    url = "https://github.com/Karib0u/rustinel/releases/download/v${version}/rustinel-${version}-${
      archMap.${stdenv.hostPlatform.system} or (throw "Unsupported system: ${stdenv.hostPlatform.system}")
    }.tar.gz";
    hash =
      hashes.${stdenv.hostPlatform.system} or (throw "Unsupported system: ${stdenv.hostPlatform.system}");
  };

  sourceRoot = "rustinel-${version}-${archMap.${stdenv.hostPlatform.system}}";

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin $out/etc/rustinel $out/share/rustinel/rules/{sigma,yara,ioc}

    install -Dm755 rustinel $out/bin/rustinel
    install -Dm644 config.toml $out/etc/rustinel/config.toml

    cp -r rules/sigma/* $out/share/rustinel/rules/sigma/
    cp -r rules/yara/* $out/share/rustinel/rules/yara/
    cp -r rules/ioc/* $out/share/rustinel/rules/ioc/

    runHook postInstall
  '';

  # TODO: once rustinel is upstreamed into nixpkgs, set meta.maintainers
  # with a registered lib.maintainers.<handle> entry.
  meta = {
    description = "Open-source endpoint detection engine using eBPF, Sigma, YARA, and IOC matching";
    homepage = "https://github.com/Karib0u/rustinel";
    license = lib.licenses.asl20;
    maintainers = with lib.maintainers; [ ];
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
    mainProgram = "rustinel";
  };
}
