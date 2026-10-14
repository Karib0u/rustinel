#!/bin/bash
# Validate macOS ParentImage for a parent that predates the agent (#756).
#
# Usage: scripts/macos/test-parent-image-seeding.sh [--profile PATH] [--identity NAME] [--no-build]
#
# Run as your normal user; sudo is called for the agent only. The terminal
# needs Full Disk Access (see docs/macos-permissions.md).
#
#   1. A long-lived /bin/sh is started BEFORE the agent (never exec-observed).
#   2. The agent starts with the example whoami Sigma rule.
#   3. That old shell runs /usr/bin/whoami (child of a seeded parent).
#   4. A shell started AFTER the agent runs whoami (control: exec observed).
#   Both alerts must carry the same non-empty process.parent.executable (macOS runs /bin/sh as /bin/bash).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

profile="${MACOS_PROVISIONING_PROFILE:-$HOME/src/misc/Rustinel_Developer_ID_v2.provisionprofile}"
identity="${MACOS_SIGN_IDENTITY:-Developer ID Application: Theo Foucher (37TYDYTJ3M)}"
build=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) profile="${2:?}"; shift 2 ;;
    --identity) identity="${2:?}"; shift 2 ;;
    --no-build) build=0; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

app="$repo_root/target/release/Rustinel.app"
work="$(mktemp -d "${TMPDIR:-/tmp}/rustinel-parent-seed.XXXXXX")"
logs="$work/logs"
agent_pid=""
old_pid=""
cleanup() {
  [[ -n "$old_pid" ]] && kill "$old_pid" 2>/dev/null || true
  [[ -n "$agent_pid" ]] && sudo kill -INT "$agent_pid" 2>/dev/null || true
  sleep 1
  sudo rm -rf "$work" 2>/dev/null || true
}
trap cleanup EXIT

if [[ $build -eq 1 ]]; then
  echo "== build and sign"
  cargo build --release
  rm -rf "$app"
  scripts/macos/package-app.sh --binary target/release/rustinel --output "$app" \
    --profile "$profile" --identity "$identity" >/dev/null
fi

echo "== long-lived parent, started before the agent"
mkfifo "$work/old.fifo"
/bin/sh -c 'while read -r c; do /usr/bin/whoami >/dev/null; echo done; done < "$1" > "$2"' sh "$work/old.fifo" "$work/old.out" &
old_pid=$!
exec 3>"$work/old.fifo"
sleep 1
echo "old parent pid $old_pid"

sudo mkdir -p "$logs"
cat > "$work/config.toml" <<CFG
[scanner]
sigma_enabled = true
sigma_rules_path = "$repo_root/rules/sigma"
yara_enabled = false
[logging]
directory = "$logs"
[alerts]
directory = "$logs"
[dedup]
enabled = false
CFG

echo "== start agent (sudo)"
sudo "$app/Contents/MacOS/rustinel" run --config "$work/config.toml" >"$work/agent.out" 2>&1 &
agent_pid=$!
for _ in $(seq 1 60); do
  grep -q "Agent ready" "$work/agent.out" 2>/dev/null && break
  if ! sudo kill -0 "$agent_pid" 2>/dev/null; then
    echo "agent exited early:"; cat "$work/agent.out"; exit 1
  fi
  sleep 1
done
grep -q "Agent ready" "$work/agent.out" || { echo "agent never subscribed:"; cat "$work/agent.out"; exit 1; }
sleep 2

echo "== child of the pre-existing parent"
echo go >&3
sleep 1
echo "== control: parent started after the agent"
/bin/sh -c '/usr/bin/whoami >/dev/null'
sleep 4

alerts=$(sudo sh -c "cat '$logs'/alerts.json* 2>/dev/null" || true)
echo "$alerts" | python3 -I -c '
import json, sys
rows = []
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: rows.append(json.loads(line))
    except ValueError: pass
def get(d, path):
    for k in path:
        if not isinstance(d, dict): return None
        d = d.get(k)
    return d
who = [r for r in rows if "whoami" in json.dumps(r)]
print(f"whoami alerts: {len(who)}")
parents = []
for r in who:
    p = get(r, ["process","parent","executable"])
    if p is None: p = r.get("process.parent.executable")
    parents.append(p)
    print("  parent executable:", p)
ok = len(who) >= 2 and None not in parents and len(set(parents)) == 1
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
'
