#!/bin/bash
# Record Endpoint Security fixtures for the ESF decoder tests (#739).
#
# Usage: scripts/macos/record-esf-fixtures.sh [--profile PATH] [--identity NAME] [--no-build] [--app PATH]
#
# Run as your normal user; sudo is called for the agent only. The terminal needs
# Full Disk Access (see docs/macos-permissions.md).
#
# Starts a signed agent with RUSTINEL_ESF_RECORD set, runs two small workloads
# under a fixed directory, and writes tests/fixtures/esf/{process,file}_lifecycle.json
# with provenance. Review the files before committing them.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

profile="${MACOS_PROVISIONING_PROFILE:-$HOME/src/misc/Rustinel_Developer_ID_v2.provisionprofile}"
identity="${MACOS_SIGN_IDENTITY:-Developer ID Application: Theo Foucher (37TYDYTJ3M)}"
build=1
app="$repo_root/target/release/Rustinel.app"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) profile="${2:?}"; shift 2 ;;
    --identity) identity="${2:?}"; shift 2 ;;
    --app) app="${2:?}"; build=0; shift 2 ;;
    --no-build) build=0; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# A fixed path keeps the user name and a random temp suffix out of the fixtures.
workdir=/private/tmp/rustinel-esf-fixture
work="$(mktemp -d "${TMPDIR:-/tmp}/rustinel-esf-record.XXXXXX")"
logs="$work/logs"
rec="$work/rec.ndjson"
raw_dir="$HOME/rustinel-validate/esf-fixtures/raw"
agent_pid=""
cleanup() {
  [[ -n "$agent_pid" ]] && sudo kill -INT "$agent_pid" 2>/dev/null || true
  sleep 1
  rm -rf "$workdir" 2>/dev/null || true
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

rm -rf "$workdir"
mkdir -p "$workdir"

echo "== start agent (sudo) with the recorder armed but gated"
: > "$rec"
sudo env RUSTINEL_ESF_RECORD="$rec" "$app/Contents/MacOS/rustinel" run \
  --config "$work/config.toml" >"$work/agent.out" 2>&1 &
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

# Prepare helpers outside the recording window.
cp /bin/echo "$workdir/adhoc-echo"
codesign --force -s - "$workdir/adhoc-echo" >/dev/null 2>&1
printf '#!/bin/sh\necho script-ran\n' > "$workdir/hello.sh"
chmod +x "$workdir/hello.sh"

record() {
  local name="$1"; shift
  : > "$rec"
  touch "$rec.on"
  # The recorder rechecks its gate at most every 50 ms; let it open first.
  sleep 0.5
  "$@"
  sleep 3
  rm -f "$rec.on"
  sleep 1
  cp "$rec" "$work/$name.ndjson"
  mkdir -p "$raw_dir"
  cp "$rec" "$raw_dir/$name.ndjson"
}

process_workload() {
  cd "$workdir"
  # exec with arguments and a working directory, a script with a shebang, and an ad-hoc signed binary
  /usr/bin/env RUSTINEL_FIXTURE=1 /bin/echo rustinel-esf-fixture >/dev/null
  "$workdir/hello.sh" >/dev/null
  "$workdir/adhoc-echo" adhoc >/dev/null
  /usr/bin/true
}

file_workload() {
  cd "$workdir"
  /bin/sh -c 'echo first > created.txt; mv created.txt renamed.txt; echo second >> renamed.txt; rm renamed.txt'
  /bin/sh -c 'echo x > keep.txt; mv keep.txt other.txt; mv other.txt keep.txt'
}

echo "== record process workload"
record process process_workload
echo "== record file workload"
record file file_workload

sudo kill -INT "$agent_pid" 2>/dev/null || true
agent_pid=""

echo "== write fixtures"
out="$repo_root/tests/fixtures/esf"
mkdir -p "$out"
macos="$(sw_vers -productVersion) ($(sw_vers -buildVersion))"
arch="$(uname -m)"
today="$(date +%F)"
python3 -I - "$work/process.ndjson" "$out/process_lifecycle.json" "$workdir" "$macos" "$arch" "$today" process <<'PY'
import json, sys
src, dst, marker, macos, arch, today, kind = sys.argv[1:]
rows = [json.loads(l) for l in open(src) if l.strip()]
pids = set()
keep = []
for r in rows:
    ev = r["event"]
    if "Exec" in ev:
        t = ev["Exec"]["target"]
        text = json.dumps(ev["Exec"])
        if marker in text or "rustinel-esf-fixture" in text or t["executable"]["path"] == "/usr/bin/true":
            pids.add(t["pid"])
            keep.append(r)
for r in rows:
    if r["event"] == "Exit" and r["actor"]["pid"] in pids:
        keep.append(r)
keep.sort(key=lambda r: (r["time"]["sec"], r["time"]["nsec"]))
file_rows = []
doc = {
    "provenance": {
        "macos": macos, "arch": arch, "date": today,
        "scenario": "Exec with arguments and cwd (env, echo), a shebang script, an ad-hoc signed binary, and their exits, run from a fixed directory",
    },
    "records": keep,
}
json.dump(doc, open(dst, "w"), indent=1)
print(f"{dst}: {len(keep)} records")
PY
python3 -I - "$work/file.ndjson" "$out/file_lifecycle.json" "$workdir" "$macos" "$arch" "$today" <<'PY'
import json, sys
src, dst, marker, macos, arch, today = sys.argv[1:]
rows = [json.loads(l) for l in open(src) if l.strip()]
keep = [r for r in rows if marker in json.dumps(r["event"])]
doc = {
    "provenance": {
        "macos": macos, "arch": arch, "date": today,
        "scenario": "Create, write-close, rename and unlink of files under a fixed directory by /bin/sh and /bin/mv and /bin/rm",
    },
    "records": keep,
}
json.dump(doc, open(dst, "w"), indent=1)
print(f"{dst}: {len(keep)} records")
PY
echo "Review $out before committing: recordings hold paths and uids from this Mac."
