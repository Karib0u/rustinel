#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--version" ]]; then
  exec "$GITHUB_WORKSPACE/target/release/rustinel" --version
fi

# The atomic harness starts this wrapper in its prepared engine directory.
# Install its configuration and run the engine through the generated unit.
cleanup() {
  systemctl stop rustinel.service || true
  /opt/rustinel/rustinel service uninstall || true
}
trap cleanup EXIT
trap 'exit 0' TERM INT

install -D -m 755 "$GITHUB_WORKSPACE/target/release/rustinel" /opt/rustinel/rustinel
install -d -m 755 /etc/rustinel
sed -E \
  -e 's# = "([^"]+/[^"]+)"# = "/opt/rustinel/\1"#' \
  -e 's#directory = "logs"#directory = "/opt/rustinel/logs"#' \
  config.toml > /etc/rustinel/config.toml
chmod 600 /etc/rustinel/config.toml

/opt/rustinel/rustinel service install
if ! systemctl start rustinel.service; then
  journalctl -u rustinel.service --no-pager -n 80
  exit 1
fi
sleep 3
if grep -E 'Failed to load (Sigma|YARA|IOC)' /opt/rustinel/logs/rustinel.log*; then
  exit 1
fi
while systemctl is-active --quiet rustinel.service; do
  sleep 1
done
journalctl -u rustinel.service --no-pager -n 80
exit 1
