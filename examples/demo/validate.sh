#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

pass=0
fail=0

assert_eq() {
  local label="$1"
  local expected="$2"
  local actual="$3"

  if [[ "$expected" == "$actual" ]]; then
    echo "PASS: $label"
    pass=$((pass + 1))
  else
    echo "FAIL: $label" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    fail=$((fail + 1))
  fi
}

assert_exit() {
  local label="$1"
  local expected="$2"
  shift 2
  set +e
  "$@" >/dev/null 2>&1
  local status=$?
  set -e

  if [[ "$status" -eq "$expected" ]]; then
    echo "PASS: $label"
    pass=$((pass + 1))
  else
    echo "FAIL: $label (exit $status, expected $expected)" >&2
    fail=$((fail + 1))
  fi
}

tmpdir=""
cleanup() {
  if [[ -n "$tmpdir" && -d "$tmpdir" ]]; then
    rm -rf "$tmpdir"
  fi
}
trap cleanup EXIT

tmpdir="$(mktemp -d)"

cat >"$tmpdir/config.toml" <<'EOF'
[alerts]
directory = "custom-alerts"
filename = "demo-alerts.json"
EOF

config_lines="$(read_alerts_config "$tmpdir")"
alerts_dir="${config_lines%%$'\n'*}"
alerts_filename="${config_lines#*$'\n'}"
assert_eq "reads custom alerts.directory" "$tmpdir/custom-alerts" "$alerts_dir"
assert_eq "reads custom alerts.filename" "demo-alerts.json" "$alerts_filename"

today_file="$(today_alert_file "$alerts_dir" "$alerts_filename")"
expected_today="$tmpdir/custom-alerts/demo-alerts.json.$(today_date)"
assert_eq "builds today's alert file path" "$expected_today" "$today_file"

cat >"$tmpdir/config.toml" <<'EOF'
[alerts]
directory = "/var/log/rustinel"
filename = "alerts.json"
EOF

config_lines="$(read_alerts_config "$tmpdir")"
alerts_dir="${config_lines%%$'\n'*}"
assert_eq "preserves absolute alerts.directory" "/var/log/rustinel" "$alerts_dir"

assert_exit "run-local-demo.sh --help exits 0" 0 \
  "$SCRIPT_DIR/run-local-demo.sh" --help

assert_exit "unknown --siem value exits 2" 2 \
  "$SCRIPT_DIR/run-local-demo.sh" --root "$tmpdir" --trigger-only --siem invalid

echo
echo "Validation summary: $pass passed, $fail failed"
if [[ "$fail" -gt 0 ]]; then
  exit 1
fi
