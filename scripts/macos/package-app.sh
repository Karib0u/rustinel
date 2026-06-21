#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

binary=""
output=""
profile="${MACOS_PROVISIONING_PROFILE:-}"
identity="${MACOS_SIGN_IDENTITY:-}"
bundle_id="${MACOS_BUNDLE_ID:-}"
version=""
adhoc=0

usage() {
  cat <<'EOF'
Build and sign the app-like bundle required by a macOS daemon that uses the
Endpoint Security restricted entitlement.

Usage:
  package-app.sh --binary PATH --output PATH [options]

Required:
  --binary PATH       Compiled rustinel Mach-O binary
  --output PATH       Destination app bundle, normally Rustinel.app

Distribution signing:
  --profile PATH      Developer ID provisioning profile with Endpoint Security
  --identity NAME     Developer ID Application signing identity

Options:
  --bundle-id ID      Bundle identifier. Default: derived from the profile
  --version VERSION   Bundle version. Default: Cargo package version
  --adhoc             Ad-hoc sign without a profile for a SIP-disabled test Mac
  -h, --help          Show this help

The profile and identity can also be supplied with
MACOS_PROVISIONING_PROFILE and MACOS_SIGN_IDENTITY.
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      binary="${2:?missing value for --binary}"
      shift 2
      ;;
    --output)
      output="${2:?missing value for --output}"
      shift 2
      ;;
    --profile)
      profile="${2:?missing value for --profile}"
      shift 2
      ;;
    --identity)
      identity="${2:?missing value for --identity}"
      shift 2
      ;;
    --bundle-id)
      bundle_id="${2:?missing value for --bundle-id}"
      shift 2
      ;;
    --version)
      version="${2:?missing value for --version}"
      shift 2
      ;;
    --adhoc)
      adhoc=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "$binary" ]] || fail "--binary is required"
[[ -f "$binary" ]] || fail "binary not found: $binary"
[[ -n "$output" ]] || fail "--output is required"
[[ "$output" != "/" ]] || fail "refusing to use / as the output"

if [[ -z "$version" ]]; then
  version="$(
    sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_root/Cargo.toml" | head -n 1
  )"
fi
[[ -n "$version" ]] || fail "could not determine the package version"

if [[ "$adhoc" -eq 1 ]]; then
  [[ -z "$profile" ]] || fail "--adhoc cannot be combined with --profile"
  [[ -z "$identity" || "$identity" == "-" ]] ||
    fail "--adhoc cannot be combined with a signing identity"
  identity="-"
  if [[ -z "$bundle_id" ]]; then
    bundle_id="com.rustinel.agent"
  fi
else
  [[ -n "$profile" ]] || fail "--profile is required for an entitled build"
  [[ -f "$profile" ]] || fail "provisioning profile not found: $profile"
  [[ -n "$identity" ]] || fail "--identity is required for an entitled build"
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

entitlements="$tmp_dir/rustinel.entitlements"
cp "$repo_root/packaging/macos/rustinel.entitlements" "$entitlements"

if [[ "$adhoc" -eq 0 ]]; then
  profile_plist="$tmp_dir/profile.plist"
  security cms -D -i "$profile" > "$profile_plist"

  profile_es="$(
    /usr/libexec/PlistBuddy \
      -c 'Print :Entitlements:com.apple.developer.endpoint-security.client' \
      "$profile_plist" 2>/dev/null || true
  )"
  [[ "$profile_es" == "true" ]] ||
    fail "profile does not authorize Endpoint Security"

  app_identifier="$(
    /usr/libexec/PlistBuddy \
      -c 'Print :Entitlements:com.apple.application-identifier' \
      "$profile_plist"
  )"
  app_id_prefix="$(
    /usr/libexec/PlistBuddy \
      -c 'Print :ApplicationIdentifierPrefix:0' \
      "$profile_plist"
  )"
  team_id="$(
    /usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$profile_plist"
  )"
  profile_bundle_id="${app_identifier#"${app_id_prefix}."}"

  [[ "$profile_bundle_id" != "$app_identifier" ]] ||
    fail "profile App ID has an unexpected prefix: $app_identifier"
  if [[ -z "$bundle_id" ]]; then
    [[ "$profile_bundle_id" != "*" ]] ||
      fail "a wildcard profile requires --bundle-id"
    bundle_id="$profile_bundle_id"
  fi
  expected_app_identifier="${app_id_prefix}.${bundle_id}"

  if [[ "$app_identifier" != "$expected_app_identifier" &&
        "$app_identifier" != "${app_id_prefix}.*" ]]; then
    fail "profile App ID $app_identifier does not match $bundle_id"
  fi

  /usr/libexec/PlistBuddy \
    -c "Add :com.apple.application-identifier string $expected_app_identifier" \
    "$entitlements"
  /usr/libexec/PlistBuddy \
    -c "Add :com.apple.developer.team-identifier string $team_id" \
    "$entitlements"
fi

rm -rf "$output"
mkdir -p "$output/Contents/MacOS"
cp "$binary" "$output/Contents/MacOS/rustinel"
chmod 755 "$output/Contents/MacOS/rustinel"

info_plist="$output/Contents/Info.plist"
plutil -create xml1 "$info_plist"
plutil -insert CFBundleDevelopmentRegion -string en "$info_plist"
plutil -insert CFBundleDisplayName -string Rustinel "$info_plist"
plutil -insert CFBundleExecutable -string rustinel "$info_plist"
plutil -insert CFBundleIdentifier -string "$bundle_id" "$info_plist"
plutil -insert CFBundleInfoDictionaryVersion -string 6.0 "$info_plist"
plutil -insert CFBundleName -string Rustinel "$info_plist"
plutil -insert CFBundlePackageType -string APPL "$info_plist"
plutil -insert CFBundleShortVersionString -string "$version" "$info_plist"
plutil -insert CFBundleVersion -string "$version" "$info_plist"
plutil -insert LSBackgroundOnly -bool true "$info_plist"
plutil -insert LSMinimumSystemVersion -string 11.0 "$info_plist"

if [[ "$adhoc" -eq 0 ]]; then
  cp "$profile" "$output/Contents/embedded.provisionprofile"
fi

if [[ "$identity" == "-" ]]; then
  codesign --force --options runtime --timestamp=none \
    --entitlements "$entitlements" \
    --sign - \
    "$output"
else
  codesign --force --options runtime --timestamp \
    --entitlements "$entitlements" \
    --sign "$identity" \
    "$output"
fi

codesign --verify --strict --verbose=2 "$output"
if [[ "$adhoc" -eq 0 ]]; then
  signed_team_id="$(
    codesign --display --verbose=4 "$output" 2>&1 |
      sed -n 's/^TeamIdentifier=//p'
  )"
  [[ "$signed_team_id" == "$team_id" ]] ||
    fail "signed Team ID $signed_team_id does not match profile Team ID $team_id"
fi
codesign --display --verbose=2 "$output"
codesign --display --entitlements - "$output"

echo "Created signed app bundle: $output"
