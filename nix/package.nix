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
#
# Config / rule path coherence
#
# Rustinel resolves relative paths in config.toml against the selected config
# file's parent directory.
# It discovers config.toml in the following order:
# `--config <PATH>`, the `RUSTINEL_CONFIG` env var, the managed platform path
# (/etc/rustinel/config.toml on Linux), next-to-the-binary, then CWD.
#
# To make `nix run` / `nix build` work without a NixOS module:
#   - Rules are installed read-only under $out/share/rustinel/rules/...
#   - A runtime config is generated from the bundled config.toml with the
#     relative rule paths rewritten to absolute store paths and the logs /
#     alerts directories pointed at the writable /var/log/rustinel.
#   - The binary is wrapped so RUSTINEL_CONFIG points at that generated
#     config, so it is discovered without a module and rule paths resolve
#     correctly.
#   - The unmodified bundled config.toml is shipped as config.example.toml
#     for reference / for users who want to copy and customize it.
{
  lib,
  stdenv,
  fetchurl,
  makeWrapper,
}:

let
  version = "1.3.0";
  hashes = {
    x86_64-linux = "sha256-Co3Pn9PyiFn7MDPA8wV2RttdmvvlEFjVHpCZwPBuFV0=";
    aarch64-linux = "sha256-DhV5OkCSBnHckq2cAeEjC7PwCtJU3+uorVJtHcWPNYM=";
  };
  archMap = {
    x86_64-linux = "x86_64-unknown-linux-musl";
    aarch64-linux = "aarch64-unknown-linux-musl";
  };

  # Writable system location for agent logs and security alerts. Matches the
  # upstream rustinel.service file. `rustinel doctor` will warn (not fail) if
  # this directory is missing or not writable; create it or override via
  # --config / RUSTINEL_CONFIG / EDR__LOGGING__DIRECTORY.
  logDir = "/var/log/rustinel";

  # Writable location for `rustinel capture` recordings. The bundled
  # config.toml ships `directory = "captures"` (relative), which would resolve
  # against the read-only store. Rewritten to a writable system path.
  captureDir = "/var/lib/rustinel/captures";
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

  nativeBuildInputs = [ makeWrapper ];

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin $out/share/rustinel/rules/{sigma,yara,ioc}

    install -Dm755 rustinel $out/bin/rustinel

    cp -r rules/sigma/* $out/share/rustinel/rules/sigma/
    cp -r rules/yara/* $out/share/rustinel/rules/yara/
    cp -r rules/ioc/* $out/share/rustinel/rules/ioc/

    # Runtime config: rewrite the bundled config.toml so that relative rule
    # paths point into the read-only store and logs / alerts / captures point
    # at writable system directories.
    #
    # `--replace-fail` makes the build fail loudly if any of these strings
    # ever drift from the bundled config.toml. The `directory = "logs"` pair
    # matches twice by design (logging.directory and alerts.directory); a
    # future third occurrence would be swept up silently — revisit if the
    # config grows another `directory = "logs"` field.
    #
    # The `directory = "captures"` substitution uses `--replace` (non-failing):
    # the [capture] section was added to the repo config after the v1.3.0 tag,
    # so the v1.3.0 release archive does not contain it. `--replace` no-ops
    # on archives without the section and rewrites it on releases that ship
    # it, keeping the package forward-compatible without breaking the current
    # build.
    install -Dm644 config.toml $out/share/rustinel/config.toml
    substituteInPlace $out/share/rustinel/config.toml \
      --replace-fail 'sigma_rules_path = "rules/sigma"' \
                     'sigma_rules_path = "'"$out"'/share/rustinel/rules/sigma"' \
      --replace-fail 'yara_rules_path = "rules/yara"' \
                     'yara_rules_path = "'"$out"'/share/rustinel/rules/yara"' \
      --replace-fail 'hashes_path = "rules/ioc/hashes.txt"' \
                     'hashes_path = "'"$out"'/share/rustinel/rules/ioc/hashes.txt"' \
      --replace-fail 'ips_path = "rules/ioc/ips.txt"' \
                     'ips_path = "'"$out"'/share/rustinel/rules/ioc/ips.txt"' \
      --replace-fail 'domains_path = "rules/ioc/domains.txt"' \
                     'domains_path = "'"$out"'/share/rustinel/rules/ioc/domains.txt"' \
      --replace-fail 'paths_regex_path = "rules/ioc/paths_regex.txt"' \
                     'paths_regex_path = "'"$out"'/share/rustinel/rules/ioc/paths_regex.txt"' \
      --replace-fail 'directory = "logs"' \
                     'directory = "'${logDir}'"' \
      --replace 'directory = "captures"' \
                'directory = "'${captureDir}'"'

    # Unmodified bundled config for reference / customization.
    install -Dm644 config.toml $out/share/rustinel/config.example.toml

    # Inject the store config only when the user has not set RUSTINEL_CONFIG
    # and no managed config exists at /etc/rustinel/config.toml. This lets a
    # hand-rolled systemd unit (or `rustinel setup`) own config discovery via
    # the managed path, and keeps `rustinel rules install` (which writes to
    # /var/lib/rustinel/rules/current) effective when the user manages the
    # config there. The env-var discovery branch returns Some without an
    # existence check, so `--set`/`--set-default` would shadow the managed
    # path unconditionally; the conditional `--run` guards both.
    wrapProgram $out/bin/rustinel \
      --run 'if [ -z "''${RUSTINEL_CONFIG:-}" ] && [ ! -e /etc/rustinel/config.toml ]; then export RUSTINEL_CONFIG='"$out"'/share/rustinel/config.toml; fi'

    runHook postInstall
  '';

  passthru = {
    # Fetch the release archive for an arbitrary target system using the
    # *local* stdenv's fetchurl. fetchurl only needs bash + curl, so a
    # derivation built here (on e.g. x86_64-linux) can fetch and verify the
    # SRI hash of any target arch's archive without QEMU/emulation. Used by
    # CI (.github/workflows/nix.yml) to catch a broken URL or stale hash for
    # the non-native architecture.
    srcFor =
      targetSystem:
      fetchurl {
        url = "https://github.com/Karib0u/rustinel/releases/download/v${version}/rustinel-${version}-${
          archMap.${targetSystem} or (throw "Unsupported system: ${targetSystem}")
        }.tar.gz";
        hash = hashes.${targetSystem} or (throw "Unsupported system: ${targetSystem}");
      };
  };

  meta = {
    description = "Open-source endpoint detection engine using eBPF, Sigma, YARA, and IOC matching";
    homepage = "https://github.com/Karib0u/rustinel";
    license = lib.licenses.asl20;
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
    mainProgram = "rustinel";
  };
}
