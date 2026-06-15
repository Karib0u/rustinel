#!/usr/bin/env bash
set -euo pipefail

ROOT=""
TRIGGER_ONLY=0
TIMEOUT_SECS=15
SIEM=""

usage() {
  cat <<'EOF'
Verify the bundled whoami demo end-to-end.

Rustinel must already be running (for example: sudo ./rustinel run).

Usage:
  run-local-demo.sh [--root PATH] [--trigger-only] [--timeout SECS] [--siem NAME]

Options:
  --root PATH       Rustinel install directory (default: auto-detect)
  --trigger-only    Skip agent and prerequisite checks
  --timeout SECS    Seconds to wait for a new alert (default: 15)
  --siem NAME       Print next-step commands for elastic or splunk
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      ROOT="${2:?missing value for --root}"
      shift 2
      ;;
    --trigger-only)
      TRIGGER_ONLY=1
      shift
      ;;
    --timeout)
      TIMEOUT_SECS="${2:?missing value for --timeout}"
      shift 2
      ;;
    --siem)
      SIEM="${2:?missing value for --siem}"
      shift 2
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

detect_root() {
  local dir="$PWD"
  while [[ "$dir" != "/" ]]; do
    if [[ -f "$dir/config.toml" ]]; then
      printf '%s' "$dir"
      return 0
    fi
    dir="$(dirname "$dir")"
  done

  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -f "$script_dir/../../config.toml" ]]; then
    cd "$script_dir/../.." && pwd
    return 0
  fi

  return 1
}

find_binary() {
  local root="$1"
  local candidate
  for candidate in \
    "$root/rustinel" \
    "$root/target/release/rustinel" \
    "$root/target/debug/rustinel"; do
    if [[ -x "$candidate" ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

agent_running() {
  pgrep -x rustinel >/dev/null 2>&1
}

alert_glob() {
  local root="$1"
  printf '%s/logs/alerts.json*' "$root"
}

alert_line_count() {
  local root="$1"
  shopt -s nullglob
  local total=0
  local file
  for file in $(alert_glob "$root"); do
    if [[ -f "$file" ]]; then
      total=$((total + $(wc -l < "$file" | tr -d ' ')))
    fi
  done
  shopt -u nullglob
  echo "$total"
}

latest_alert_line() {
  local root="$1"
  shopt -s nullglob
  local latest_file=""
  local file
  for file in $(alert_glob "$root"); do
    if [[ -f "$file" ]]; then
      if [[ -z "$latest_file" || "$file" -nt "$latest_file" ]]; then
        latest_file="$file"
      fi
    fi
  done
  shopt -u nullglob

  if [[ -z "$latest_file" ]]; then
    return 1
  fi

  tail -n 1 "$latest_file"
}

print_alert() {
  local line="$1"
  if command -v python3 >/dev/null 2>&1; then
    printf '%s\n' "$line" | python3 -m json.tool
  elif command -v jq >/dev/null 2>&1; then
    printf '%s\n' "$line" | jq .
  else
    printf '%s\n' "$line"
  fi
}

print_siem_hint() {
  local root="$1"
  local name="$2"
  case "$name" in
    elastic)
      cat <<EOF

Next — Elastic SIEM demo:
  cd examples/siem/elastic
  docker compose up -d elasticsearch kibana
  export RUSTINEL_ALERTS_DIR=$root/logs
  docker compose up filebeat

Kibana: http://localhost:5601 — search: event.kind : "alert"
EOF
      ;;
    splunk)
      cat <<EOF

Next — Splunk SIEM demo:
  cd examples/siem/splunk
  docker compose up -d
  python3 send-alerts.py $root/logs/alerts.json.\$(date +%Y-%m-%d)

Splunk Web: http://localhost:8000 — search: index=main source=rustinel event.kind=alert
EOF
      ;;
    *)
      echo "Unknown SIEM: $name (expected elastic or splunk)" >&2
      exit 2
      ;;
  esac
}

now_ms() {
  if date +%s%N >/dev/null 2>&1; then
    echo $(( $(date +%s%N) / 1000000 ))
  else
    echo $(( $(date +%s) * 1000 ))
  fi
}

if [[ -z "$ROOT" ]]; then
  if ! ROOT="$(detect_root)"; then
    echo "Could not find Rustinel install directory (expected config.toml)." >&2
    echo "Run from the install directory or pass --root PATH." >&2
    exit 1
  fi
fi

ROOT="$(cd "$ROOT" && pwd)"

if [[ "$TRIGGER_ONLY" -eq 0 ]]; then
  if [[ ! -f "$ROOT/config.toml" ]]; then
    echo "Missing config.toml in $ROOT" >&2
    exit 1
  fi

  if ! find_binary "$ROOT" >/dev/null; then
    echo "Rustinel binary not found under $ROOT" >&2
    echo "Build with: cargo build --release" >&2
    echo "Or install a release: https://github.com/Karib0u/rustinel/releases" >&2
    exit 1
  fi

  if ! agent_running; then
    echo "Rustinel agent is not running." >&2
    echo "Start it in another terminal:" >&2
    echo "  cd $ROOT && sudo ./rustinel run" >&2
    exit 1
  fi

  echo "Rustinel install: $ROOT"
  echo "Agent: running"
fi

before="$(alert_line_count "$ROOT")"
echo "Firing bundled demo trigger (whoami)..."
whoami >/dev/null

start_ms="$(now_ms)"
deadline_ms=$(( start_ms + TIMEOUT_SECS * 1000 ))
found=0

while [[ "$(now_ms)" -lt "$deadline_ms" ]]; do
  after="$(alert_line_count "$ROOT")"
  if [[ "$after" -gt "$before" ]]; then
    found=1
    break
  fi
  sleep 0.2
done

if [[ "$found" -ne 1 ]]; then
  echo "No new alert within ${TIMEOUT_SECS}s." >&2
  echo "Check logs under $ROOT/logs/ and confirm Sigma rules are loaded." >&2
  exit 1
fi

if ! line="$(latest_alert_line "$ROOT")"; then
  echo "Alert count increased but no alert line could be read." >&2
  exit 1
fi

echo "Latest alert:"
print_alert "$line"

if [[ -n "$SIEM" ]]; then
  print_siem_hint "$ROOT" "$SIEM"
fi

echo "Demo succeeded."
