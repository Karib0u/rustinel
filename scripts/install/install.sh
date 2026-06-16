#!/usr/bin/env sh
set -eu

repo="${RUSTINEL_REPO:-Karib0u/rustinel}"
version="${RUSTINEL_VERSION:-latest}"
install_dir="${RUSTINEL_INSTALL_DIR:-$PWD/rustinel}"
run_after_install=0
force=0

usage() {
  cat <<'EOF'
Install a published Rustinel release archive for this host.

This script only installs release binaries. It does not install Rust, Cargo, or
build Rustinel from source. If no release asset exists for this OS/architecture,
follow the source build guide:
  https://docs.rustinel.io/getting-started/#compile-from-source

Usage:
  install.sh [--dir PATH] [--version VERSION] [--run] [--force]

Options:
  --dir PATH         Install directory. Default: ./rustinel
  --version VERSION  Release version such as 1.0.2 or v1.0.2. Default: latest
  --run              Start Rustinel after installation
  --force            Replace the install directory if it already exists
  -h, --help         Show this help

Environment:
  RUSTINEL_REPO         GitHub repo. Default: Karib0u/rustinel
  RUSTINEL_VERSION      Release version. Default: latest
  RUSTINEL_INSTALL_DIR  Install directory. Default: ./rustinel
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dir)
      install_dir="${2:?missing value for --dir}"
      shift 2
      ;;
    --version)
      version="${2:?missing value for --version}"
      shift 2
      ;;
    --run)
      run_after_install=1
      shift
      ;;
    --force)
      force=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

need curl
need tar

os="$(uname -s)"
arch="$(uname -m)"

case "$os:$arch" in
  Linux:x86_64|Linux:amd64)
    target="x86_64-unknown-linux-musl"
    ;;
  Linux:aarch64|Linux:arm64)
    target="aarch64-unknown-linux-musl"
    ;;
  Darwin:arm64|Darwin:aarch64)
    target="aarch64-apple-darwin"
    ;;
  Darwin:x86_64|Darwin:amd64)
    target="x86_64-apple-darwin"
    ;;
  *)
    echo "Unsupported platform: $os $arch" >&2
    exit 1
    ;;
esac

if [ "$version" = "latest" ]; then
  api_url="https://api.github.com/repos/$repo/releases/latest"
  tag="$(curl -fsSL "$api_url" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  if [ -z "$tag" ]; then
    echo "Could not resolve latest release from $api_url" >&2
    exit 1
  fi
  version="${tag#v}"
else
  version="${version#v}"
fi

asset="rustinel-$version-$target.tar.gz"
checksums="rustinel-$version-checksums-sha256.txt"
base_url="https://github.com/$repo/releases/download/v$version"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

echo "Downloading $asset"
if ! curl -fsIL "$base_url/$asset" >/dev/null 2>&1; then
  echo "No published release asset found for this host: $asset" >&2
  echo "Release page: https://github.com/$repo/releases/tag/v$version" >&2
  echo "Source build guide: https://docs.rustinel.io/getting-started/#compile-from-source" >&2
  exit 1
fi
curl -fL "$base_url/$asset" -o "$tmp_dir/$asset"
curl -fL "$base_url/$checksums" -o "$tmp_dir/$checksums"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$tmp_dir" && grep " $asset\$" "$checksums" | sha256sum -c -)
elif command -v shasum >/dev/null 2>&1; then
  (cd "$tmp_dir" && grep " $asset\$" "$checksums" | shasum -a 256 -c -)
else
  echo "No sha256sum or shasum found; skipping checksum verification" >&2
fi

tar xzf "$tmp_dir/$asset" -C "$tmp_dir"
package_dir="$tmp_dir/rustinel-$version-$target"

if [ ! -d "$package_dir" ]; then
  echo "Archive did not contain expected directory: rustinel-$version-$target" >&2
  exit 1
fi

if [ -e "$install_dir" ]; then
  if [ "$force" -eq 1 ]; then
    rm -rf "$install_dir"
  else
    echo "Install directory already exists: $install_dir" >&2
    echo "Pass --force to replace it, or choose another --dir." >&2
    exit 1
  fi
fi

mkdir -p "$(dirname "$install_dir")"
mkdir -p "$install_dir"
cp -R "$package_dir/." "$install_dir/"

if [ "$os" = "Darwin" ]; then
  cat <<EOF

Rustinel $version installed to:
  $install_dir

macOS requires a one-time approval before Endpoint Security can start:
  1. Grant Full Disk Access to:  $install_dir/Rustinel.app
     (System Settings > Privacy & Security > Full Disk Access)
  2. cd "$install_dir" && sudo ./rustinel run
  3. Trigger the demo in another terminal:  whoami
  4. Read the alert:  cat logs/alerts.json.*

Before approval the agent exits with a NotPermitted error and opens the Full
Disk Access pane for you; grant access, then run it again.

EOF
else
  cat <<EOF

Rustinel $version installed to:
  $install_dir

Try the bundled demo rule:
  cd "$install_dir"
  sudo ./rustinel run
  whoami
  cat logs/alerts.json.*

EOF
fi

if [ "$run_after_install" -eq 1 ]; then
  cd "$install_dir"
  if [ "$os" = "Darwin" ]; then
    echo "Starting Rustinel. On macOS the first run needs Full Disk Access for" >&2
    echo "$install_dir/Rustinel.app; if it exits with NotPermitted, grant access" >&2
    echo "in System Settings > Privacy & Security > Full Disk Access, then re-run." >&2
  fi
  if [ "$(id -u)" -eq 0 ]; then
    exec ./rustinel run
  else
    exec sudo ./rustinel run
  fi
fi
