#!/bin/bash
# Validate the macOS BPF capture lifecycle (supervisor reconcile and restart).
#
# Usage: scripts/macos/test-bpf-lifecycle.sh [--profile PATH] [--identity NAME]
#
# Run as your normal user: it builds and signs without root, and calls sudo
# itself only for the two privileged phases (you will be prompted once).
#
#   1. Live unit test: worker failure isolation, restart with backoff, and
#      removal of a vanished interface, using real /dev/bpf devices.
#   2. End to end: the signed Rustinel.app runs, a fake `feth` interface is
#      created and destroyed, and telemetry.json must show it appear (active),
#      then disappear without a restart. The terminal needs Full Disk Access
#      for the Endpoint Security client; see docs/macos-permissions.md.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

profile="${MACOS_PROVISIONING_PROFILE:-$HOME/src/misc/Rustinel_Developer_ID_v2.provisionprofile}"
identity="${MACOS_SIGN_IDENTITY:-Developer ID Application: Theo Foucher (37TYDYTJ3M)}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) profile="${2:?}"; shift 2 ;;
    --identity) identity="${2:?}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

app="$repo_root/target/release/Rustinel.app"
work="$(mktemp -d "${TMPDIR:-/tmp}/rustinel-bpf-lifecycle.XXXXXX")"
agent_pid=""
cleanup() {
  [[ -n "$agent_pid" ]] && sudo kill -INT "$agent_pid" 2>/dev/null || true
  sudo ifconfig feth0 destroy 2>/dev/null || true
  sudo ifconfig feth1 destroy 2>/dev/null || true
}
trap cleanup EXIT

echo "== build"
test_bin="$(cargo test --lib --no-run --message-format=json 2>/dev/null \
  | python3 -c 'import sys,json
for l in sys.stdin:
    try: m=json.loads(l)
    except ValueError: continue
    if m.get("executable") and m.get("target",{}).get("kind")==["lib"] and m.get("profile",{}).get("test"):
        print(m["executable"])')"
cargo build --release
scripts/macos/package-app.sh --binary target/release/rustinel --output "$app" \
  --profile "$profile" --identity "$identity"

echo "== phase 1: live supervisor test (root)"
sudo "$test_bin" --ignored --nocapture live_supervisor

echo "== phase 2: end to end with the signed app (root)"
logs=/var/log/rustinel-bpf-lifecycle   # root-owned, as the input trust policy requires
export EDR__LOGGING__DIRECTORY="$logs"
export EDR__TELEMETRY__SNAPSHOT_INTERVAL_SECS=1
sudo rm -rf "$logs"
sudo mkdir -p "$logs"
sudo -E "$app/Contents/MacOS/rustinel" run >"$work/agent.out" 2>&1 &
agent_pid=$!

iface_state() { # prints "active", "inactive", or "absent" for $1
  sudo python3 - "$logs/telemetry.json" "$1" <<'PY'
import json, sys
try:
    bpf = json.load(open(sys.argv[1]))["macos_collectors"]["bpf"]["interfaces"]
except Exception:
    print("absent"); raise SystemExit
i = bpf.get(sys.argv[2])
print("absent" if i is None else ("active" if i["active"] else "inactive"))
PY
}
wait_for() { # wait_for IFACE STATE TIMEOUT
  for _ in $(seq 1 "$3"); do
    [[ "$(iface_state "$1")" == "$2" ]] && return 0
    sleep 1
  done
  echo "FAIL: $1 did not become $2 within ${3}s (is $(iface_state "$1"))" >&2
  echo "--- agent output"; tail -30 "$work/agent.out" >&2
  exit 1
}

wait_for lo0 active 30
echo "ok: agent capturing lo0"
sudo ifconfig feth1 create
sudo ifconfig feth0 create
sudo ifconfig feth0 peer feth1
sudo ifconfig feth0 inet 10.77.0.1/24 up
sudo ifconfig feth1 up
wait_for feth0 active 20   # reconcile interval is 5s
echo "ok: new interface feth0 began capture without a restart"
wait_for lo0 active 5
sudo ifconfig feth0 destroy
sudo ifconfig feth1 destroy
wait_for feth0 absent 20
echo "ok: removed interface cleared from telemetry"
wait_for lo0 active 5
echo "ok: healthy interface lo0 unaffected"
echo "PASS (agent output: $work/agent.out)"
