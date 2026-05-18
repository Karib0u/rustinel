#!/usr/bin/env bash
set -euo pipefail

MODE="with-agent"
AGENT_PATH="./target/release/rustinel"
AGENT_ARGS="run"
PROCESS_NAME="rustinel"
OUTPUT_DIR="./target/rustinel-bench"
IDLE_SECONDS=60
PROCESS_LAUNCHES=500
FILE_COUNT=2000
FILE_SIZE_BYTES=1024
ALERT_GLOB="./logs/alerts.json*"
ALERT_RULE_NAME="Rustinel Benchmark Whoami Linux"
SIGMA_RULES_PATH="./rules/sigma"
YARA_RULES_PATH="./rules/yara"
IOC_RULES_PATH="./rules/ioc"
SKIP_CARGO=0
NO_ALERT_LATENCY=0
NO_BENCHMARK_TRIGGER_RULE=0
PROCESS_ONLY=0
FILE_ONLY=0
CARGO_ONLY=0
KEEP_AGENT=0
EFFECTIVE_SIGMA_RULES_PATH="$SIGMA_RULES_PATH"

usage() {
  cat <<'USAGE'
Usage: scripts/bench/linux.sh [options]

Options:
  --mode baseline|with-agent
  --agent PATH
  --agent-args ARGS
  --process-name NAME
  --output-dir DIR
  --idle-seconds N
  --process-launches N
  --file-count N
  --file-size-bytes N
  --alert-glob GLOB
  --alert-rule-name NAME
  --sigma-rules-path DIR
  --yara-rules-path DIR
  --ioc-rules-path DIR
  --skip-cargo
  --no-alert-latency
  --no-benchmark-trigger-rule
  --process-only
  --file-only
  --cargo-only
  --keep-agent
  -h, --help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --agent) AGENT_PATH="$2"; shift 2 ;;
    --agent-args) AGENT_ARGS="$2"; shift 2 ;;
    --process-name) PROCESS_NAME="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --idle-seconds) IDLE_SECONDS="$2"; shift 2 ;;
    --process-launches) PROCESS_LAUNCHES="$2"; shift 2 ;;
    --file-count) FILE_COUNT="$2"; shift 2 ;;
    --file-size-bytes) FILE_SIZE_BYTES="$2"; shift 2 ;;
    --alert-glob) ALERT_GLOB="$2"; shift 2 ;;
    --alert-rule-name) ALERT_RULE_NAME="$2"; shift 2 ;;
    --sigma-rules-path) SIGMA_RULES_PATH="$2"; shift 2 ;;
    --yara-rules-path) YARA_RULES_PATH="$2"; shift 2 ;;
    --ioc-rules-path) IOC_RULES_PATH="$2"; shift 2 ;;
    --skip-cargo) SKIP_CARGO=1; shift ;;
    --no-alert-latency) NO_ALERT_LATENCY=1; shift ;;
    --no-benchmark-trigger-rule) NO_BENCHMARK_TRIGGER_RULE=1; shift ;;
    --process-only) PROCESS_ONLY=1; shift ;;
    --file-only) FILE_ONLY=1; shift ;;
    --cargo-only) CARGO_ONLY=1; shift ;;
    --keep-agent) KEEP_AGENT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "$MODE" != "baseline" && "$MODE" != "with-agent" ]]; then
  echo "--mode must be baseline or with-agent" >&2
  exit 2
fi

selector_count=$((PROCESS_ONLY + FILE_ONLY + CARGO_ONLY))
if [[ "$selector_count" -gt 1 ]]; then
  echo "Use only one of --process-only, --file-only, or --cargo-only." >&2
  exit 2
fi
RUN_PROCESS_WORKLOAD=1
RUN_FILE_WORKLOAD=1
RUN_CARGO_WORKLOAD=1
WORKLOAD_MODE="all"
if [[ "$PROCESS_ONLY" -eq 1 ]]; then
  RUN_FILE_WORKLOAD=0
  RUN_CARGO_WORKLOAD=0
  WORKLOAD_MODE="process-only"
elif [[ "$FILE_ONLY" -eq 1 ]]; then
  RUN_PROCESS_WORKLOAD=0
  RUN_CARGO_WORKLOAD=0
  WORKLOAD_MODE="file-only"
elif [[ "$CARGO_ONLY" -eq 1 ]]; then
  RUN_PROCESS_WORKLOAD=0
  RUN_FILE_WORKLOAD=0
  WORKLOAD_MODE="cargo-only"
fi
if [[ "$SKIP_CARGO" -eq 1 ]]; then
  RUN_CARGO_WORKLOAD=0
fi

EFFECTIVE_SIGMA_RULES_PATH="$SIGMA_RULES_PATH"
timestamp="$(date -u +%Y%m%d-%H%M%S)"
RUN_DIR="$OUTPUT_DIR/$MODE-linux-$timestamp"
mkdir -p "$RUN_DIR"
SAMPLES_PATH="$RUN_DIR/resource-samples.csv"
STEPS_PATH="$RUN_DIR/workload-steps.jsonl"
SUMMARY_PATH="$RUN_DIR/summary.json"
AGENT_STDOUT="$RUN_DIR/agent.stdout.log"
STARTED_AGENT_PID=""
VALIDATION_ERRORS=()

now_iso() {
  date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
}

now_ms() {
  local ns
  ns="$(date +%s%N)"
  echo $((ns / 1000000))
}

find_pids() {
  pgrep -x "$PROCESS_NAME" 2>/dev/null || true
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

add_validation_error() {
  VALIDATION_ERRORS+=("$1")
}

validation_errors_json() {
  local first=1 error
  for error in "${VALIDATION_ERRORS[@]}"; do
    if [[ "$first" -eq 0 ]]; then
      printf ','
    fi
    printf '"%s"' "$(json_escape "$error")"
    first=0
  done
}

idle_has_agent_samples() {
  awk -F, 'NR > 1 && $2 == "idle" && ($3 + 0) > 0 { found = 1 } END { exit found ? 0 : 1 }' "$SAMPLES_PATH"
}

alert_line_count() {
  shopt -s nullglob
  local total=0
  local file
  for file in $ALERT_GLOB; do
    if [[ -f "$file" ]]; then
      if [[ -n "$ALERT_RULE_NAME" ]]; then
        total=$((total + $(grep -F -c "\"rule.name\":\"$ALERT_RULE_NAME\"" "$file" 2>/dev/null || true)))
      else
        total=$((total + $(wc -l < "$file")))
      fi
    fi
  done
  shopt -u nullglob
  echo "$total"
}

prepare_benchmark_sigma_corpus() {
  local source_path="$1"
  local dest="$RUN_DIR/sigma-benchmark"
  mkdir -p "$dest"
  if [[ -d "$source_path" ]]; then
    cp -a "$source_path"/. "$dest"/
  fi
  cat > "$dest/rustinel_benchmark_whoami_linux.yml" <<YAML
title: $ALERT_RULE_NAME
id: 5223d875-9423-45a6-9645-a2db3ac7b83d
status: test
description: Stable Linux whoami trigger used by Rustinel benchmark latency checks.
author: Rustinel
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: '/whoami'
  condition: selection
level: low
YAML
  EFFECTIVE_SIGMA_RULES_PATH="$dest"
}

count_rule_files() {
  local path="$1"
  shift
  if [[ ! -d "$path" ]]; then
    echo 0
    return
  fi
  find "$path" -type f "$@" | wc -l | tr -d ' '
}

count_ioc_lines() {
  local path="$1"
  if [[ ! -d "$path" ]]; then
    echo 0
    return
  fi
  awk '{
    line = $0
    sub(/^[ \t]+/, "", line)
    sub(/[ \t]+$/, "", line)
    if (line != "" && substr(line, 1, 1) != "#") count++
  } END { print count + 0 }' "$path"/* 2>/dev/null
}

percentile_index() {
  local count="$1"
  if [[ "$count" -le 1 ]]; then
    echo 1
  else
    awk -v n="$count" 'BEGIN { i = int(n * 0.95); if (i < 1) i = 1; if (i > n) i = n; print i }'
  fi
}

summarize_samples() {
  local label="$1"
  local temp_file="$2"
  local seconds="$3"
  local count avg p95 rss_avg rss_max threads_max
  count="$(wc -l < "$temp_file" | tr -d ' ')"
  if [[ "$count" -eq 0 ]]; then
    printf '{"label":"%s","seconds":%s,"cpu_avg_percent":0,"cpu_p95_percent":0,"rss_avg_mb":0,"rss_max_mb":0,"threads_max":0}' "$label" "$seconds"
    return
  fi
  avg="$(awk '{ sum += $1 } END { printf "%.3f", sum / NR }' "$temp_file")"
  local pidx
  pidx="$(percentile_index "$count")"
  p95="$(sort -n "$temp_file" | awk -v i="$pidx" 'NR == i { printf "%.3f", $1 }')"
  rss_avg="$(awk '{ sum += $2 } END { printf "%.3f", sum / NR }' "$temp_file")"
  rss_max="$(awk 'BEGIN { max = 0 } { if ($2 > max) max = $2 } END { printf "%.3f", max }' "$temp_file")"
  threads_max="$(awk 'BEGIN { max = 0 } { if ($3 > max) max = $3 } END { print max }' "$temp_file")"
  printf '{"label":"%s","seconds":%s,"cpu_avg_percent":%s,"cpu_p95_percent":%s,"rss_avg_mb":%s,"rss_max_mb":%s,"threads_max":%s}' "$label" "$seconds" "$avg" "$p95" "$rss_avg" "$rss_max" "$threads_max"
}

RESOURCE_SUMMARIES=()

sample_agent_resources() {
  local label="$1"
  local seconds="$2"
  local temp_file="$RUN_DIR/$label.samples.tmp"
  local pids
  pids="$(find_pids | tr '\n' ' ')"
  local logical_cpus
  logical_cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
  local clk_tck
  clk_tck="$(getconf CLK_TCK 2>/dev/null || echo 100)"
  local page_size
  page_size="$(getconf PAGESIZE 2>/dev/null || echo 4096)"
  local previous_ticks=""
  local previous_time_cs=""
  : > "$temp_file"

  for ((i = 0; i <= seconds; i++)); do
    local pid_count cpu rss_kb rss_mb threads total_ticks uptime uptime_int uptime_frac now_cs
    pid_count=0
    cpu="0.000"
    rss_kb=0
    threads=0
    total_ticks=0
    read -r uptime _ < /proc/uptime || uptime="0.00"
    uptime_int="${uptime%%.*}"
    uptime_frac="${uptime#*.}"
    uptime_frac="${uptime_frac:0:2}"
    while [[ ${#uptime_frac} -lt 2 ]]; do
      uptime_frac="${uptime_frac}0"
    done
    now_cs=$((10#$uptime_int * 100 + 10#$uptime_frac))

    if [[ -n "${pids// }" ]]; then
      local pid stat rest fields proc_ticks proc_threads proc_rss_pages
      for pid in $pids; do
        [[ -r "/proc/$pid/stat" ]] || continue
        pid_count=$((pid_count + 1))
        read -r stat < "/proc/$pid/stat" || continue
        rest="${stat#*) }"
        read -r -a fields <<< "$rest"
        proc_ticks=$((fields[11] + fields[12]))
        proc_threads="${fields[17]:-0}"
        proc_rss_pages="${fields[21]:-0}"
        total_ticks=$((total_ticks + proc_ticks))
        threads=$((threads + proc_threads))
        rss_kb=$((rss_kb + (proc_rss_pages * page_size / 1024)))
      done
      if [[ -n "$previous_ticks" && -n "$previous_time_cs" ]]; then
        local delta_ticks delta_cs cpu_milli whole frac
        delta_ticks=$((total_ticks - previous_ticks))
        delta_cs=$((now_cs - previous_time_cs))
        if [[ "$delta_ticks" -gt 0 && "$delta_cs" -gt 0 && "$logical_cpus" -gt 0 ]]; then
          cpu_milli=$((delta_ticks * 100000 / clk_tck * 100 / delta_cs / logical_cpus))
          whole=$((cpu_milli / 1000))
          frac=$((cpu_milli % 1000))
          printf -v cpu '%d.%03d' "$whole" "$frac"
        fi
      fi
    fi

    printf -v rss_mb '%d.%03d' $((rss_kb / 1024)) $(((rss_kb % 1024) * 1000 / 1024))
    local sample_time
    printf -v sample_time '%(%Y-%m-%dT%H:%M:%SZ)T' -1
    printf '%s,%s,%s,%s,%s,%s\n' "$sample_time" "$label" "$pid_count" "$cpu" "$rss_mb" "$threads" >> "$SAMPLES_PATH"
    if [[ "$i" -gt 0 ]]; then
      printf '%s %s %s\n' "$cpu" "$rss_mb" "$threads" >> "$temp_file"
    fi
    previous_ticks="$total_ticks"
    previous_time_cs="$now_cs"
    if [[ "$i" -lt "$seconds" ]]; then
      sleep 1
    fi
  done

  RESOURCE_SUMMARIES+=("$(summarize_samples "$label" "$temp_file" "$seconds")")
  rm -f "$temp_file"
}

run_step() {
  local name="$1"
  shift
  echo "Running $name..."
  local start end status error
  start="$(now_ms)"
  status="ok"
  error=""
  if ! "$@"; then
    status="error"
    error="command failed"
  fi
  end="$(now_ms)"
  printf '{"name":"%s","status":"%s","duration_ms":%s,"error":"%s"}\n' \
    "$(json_escape "$name")" "$status" "$((end - start))" "$(json_escape "$error")" >> "$STEPS_PATH"
}

workload_process_launch() {
  for ((i = 0; i < PROCESS_LAUNCHES; i++)); do
    /bin/sh -c ':' >/dev/null
  done
}

workload_file_io() {
  local work_dir="$RUN_DIR/file-io"
  rm -rf "$work_dir"
  mkdir -p "$work_dir"
  for ((i = 0; i < FILE_COUNT; i++)); do
    dd if=/dev/zero of="$work_dir/sample-$i.bin" bs="$FILE_SIZE_BYTES" count=1 status=none
  done
  find "$work_dir" -type f -print0 | xargs -0 cat >/dev/null
  rm -rf "$work_dir"
}

workload_cargo_build() {
  if [[ "$SKIP_CARGO" -eq 1 ]]; then
    return 0
  fi
  command -v cargo >/dev/null 2>&1 || return 1
  cargo build --locked --release
}

measure_alert_latency() {
  if [[ "$NO_ALERT_LATENCY" -eq 1 ]]; then
    echo "null"
    return
  fi

  local before start after elapsed
  before="$(alert_line_count)"
  start="$(now_ms)"
  whoami >/dev/null || true
  while [[ $(( $(now_ms) - start )) -lt 15000 ]]; do
    sleep 0.1
    after="$(alert_line_count)"
    if [[ "$after" -gt "$before" ]]; then
      elapsed=$(( $(now_ms) - start ))
      echo "$elapsed"
      return
    fi
  done
  echo "null"
}

cleanup() {
  if [[ -n "$STARTED_AGENT_PID" && "$KEEP_AGENT" -eq 0 ]]; then
    echo "Stopping Rustinel process $STARTED_AGENT_PID"
    kill "$STARTED_AGENT_PID" 2>/dev/null || true
    sleep 2
    kill -9 "$STARTED_AGENT_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

sudo_refresh() {
  if [[ -n "${SUDO_ASKPASS:-}" ]]; then
    sudo -A -v
  else
    sudo -v
  fi
}

echo "timestamp,label,pid_count,cpu_percent,rss_mb,threads" > "$SAMPLES_PATH"
: > "$STEPS_PATH"

echo "Writing benchmark output to $RUN_DIR"

if [[ "$MODE" == "with-agent" ]]; then
  if [[ -z "$(find_pids)" ]]; then
    if [[ ! -x "$AGENT_PATH" ]]; then
      echo "Agent not found or not executable: $AGENT_PATH" >&2
      echo "Build first with cargo build --release or pass --agent PATH." >&2
      exit 1
    fi
    if [[ "$NO_BENCHMARK_TRIGGER_RULE" -eq 0 ]]; then
      prepare_benchmark_sigma_corpus "$SIGMA_RULES_PATH"
      echo "Using benchmark Sigma corpus: $EFFECTIVE_SIGMA_RULES_PATH"
    fi
    echo "Starting Rustinel: $AGENT_PATH $AGENT_ARGS"
    if [[ "$EUID" -eq 0 ]]; then
      setsid env \
        EDR__SCANNER__SIGMA_RULES_PATH="$EFFECTIVE_SIGMA_RULES_PATH" \
        EDR__SCANNER__YARA_RULES_PATH="$YARA_RULES_PATH" \
        EDR__IOC__HASHES_PATH="$IOC_RULES_PATH/hashes.txt" \
        EDR__IOC__IPS_PATH="$IOC_RULES_PATH/ips.txt" \
        EDR__IOC__DOMAINS_PATH="$IOC_RULES_PATH/domains.txt" \
        EDR__IOC__PATHS_REGEX_PATH="$IOC_RULES_PATH/paths_regex.txt" \
        "$AGENT_PATH" $AGENT_ARGS > "$AGENT_STDOUT" 2>&1 &
    else
      sudo_refresh
      if [[ -n "${SUDO_ASKPASS:-}" ]]; then
        setsid sudo -A -E env \
          EDR__SCANNER__SIGMA_RULES_PATH="$EFFECTIVE_SIGMA_RULES_PATH" \
          EDR__SCANNER__YARA_RULES_PATH="$YARA_RULES_PATH" \
          EDR__IOC__HASHES_PATH="$IOC_RULES_PATH/hashes.txt" \
          EDR__IOC__IPS_PATH="$IOC_RULES_PATH/ips.txt" \
          EDR__IOC__DOMAINS_PATH="$IOC_RULES_PATH/domains.txt" \
          EDR__IOC__PATHS_REGEX_PATH="$IOC_RULES_PATH/paths_regex.txt" \
          "$AGENT_PATH" $AGENT_ARGS > "$AGENT_STDOUT" 2>&1 &
      else
        setsid sudo -E env \
          EDR__SCANNER__SIGMA_RULES_PATH="$EFFECTIVE_SIGMA_RULES_PATH" \
          EDR__SCANNER__YARA_RULES_PATH="$YARA_RULES_PATH" \
          EDR__IOC__HASHES_PATH="$IOC_RULES_PATH/hashes.txt" \
          EDR__IOC__IPS_PATH="$IOC_RULES_PATH/ips.txt" \
          EDR__IOC__DOMAINS_PATH="$IOC_RULES_PATH/domains.txt" \
          EDR__IOC__PATHS_REGEX_PATH="$IOC_RULES_PATH/paths_regex.txt" \
          "$AGENT_PATH" $AGENT_ARGS > "$AGENT_STDOUT" 2>&1 &
      fi
    fi
    STARTED_AGENT_PID="$!"
    sleep 5
    if [[ -z "$(find_pids)" ]]; then
      add_validation_error "with-agent mode did not observe an agent process after startup"
    fi
  else
    echo "Using existing $PROCESS_NAME process: $(find_pids | tr '\n' ' ')"
    if [[ "$NO_BENCHMARK_TRIGGER_RULE" -eq 0 ]]; then
      echo "Warning: benchmark trigger rule cannot be injected into an already-running agent. Restart Rustinel or pass --no-benchmark-trigger-rule if the existing config already contains the trigger rule." >&2
    fi
  fi
fi

sample_agent_resources "idle" "$IDLE_SECONDS"
if [[ "$MODE" == "with-agent" ]] && ! idle_has_agent_samples; then
  add_validation_error "with-agent idle samples did not observe pid_count > 0"
fi
if [[ "$RUN_PROCESS_WORKLOAD" -eq 1 ]]; then
  run_step "process_launch_$PROCESS_LAUNCHES" workload_process_launch
  sample_agent_resources "post_process_launch_idle" 10
fi
if [[ "$RUN_FILE_WORKLOAD" -eq 1 ]]; then
  run_step "file_io_${FILE_COUNT}x${FILE_SIZE_BYTES}" workload_file_io
fi
if [[ "$RUN_CARGO_WORKLOAD" -eq 1 ]]; then
  run_step "cargo_build_release" workload_cargo_build
fi
ALERT_LATENCY_MS="$(measure_alert_latency)"
if [[ "$MODE" == "with-agent" && "$NO_ALERT_LATENCY" -eq 0 && "$ALERT_LATENCY_MS" == "null" ]]; then
  add_validation_error "with-agent alert latency was null"
fi
if grep -q '"status":"error"' "$STEPS_PATH"; then
  add_validation_error "one or more workload steps failed"
fi

RUN_VALID="true"
if [[ "${#VALIDATION_ERRORS[@]}" -gt 0 ]]; then
  RUN_VALID="false"
fi

steps_json="$(paste -sd, "$STEPS_PATH")"
resources_json="$(IFS=,; echo "${RESOURCE_SUMMARIES[*]}")"
validation_errors="$(validation_errors_json)"
os_name="$(uname -srvmo | sed 's/"/\\"/g')"
cpu_name="$(awk -F: '/model name|Hardware/ { gsub(/^[ \t]+/, "", $2); print $2; exit }' /proc/cpuinfo 2>/dev/null | sed 's/"/\\"/g')"
logical_cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
total_memory_mb="$(awk '/MemTotal/ { printf "%.0f", $2 / 1024 }' /proc/meminfo 2>/dev/null || echo 0)"
sigma_rule_files="$(count_rule_files "$EFFECTIVE_SIGMA_RULES_PATH" \( -name '*.yml' -o -name '*.yaml' \))"
yara_rule_files="$(count_rule_files "$YARA_RULES_PATH" \( -name '*.yar' -o -name '*.yara' \))"
ioc_non_comment_lines="$(count_ioc_lines "$IOC_RULES_PATH")"

cat > "$SUMMARY_PATH" <<JSON
{
  "generated_at": "$(now_iso)",
  "platform": "linux",
  "mode": "$(json_escape "$MODE")",
  "agent_path": "$(json_escape "$AGENT_PATH")",
  "process_name": "$(json_escape "$PROCESS_NAME")",
  "machine": {
    "os": "$os_name",
    "cpu": "$cpu_name",
    "logical_cpus": $logical_cpus,
    "total_memory_mb": $total_memory_mb
  },
  "rule_inventory": {
    "sigma_rules_path": "$(json_escape "$SIGMA_RULES_PATH")",
    "effective_sigma_rules_path": "$(json_escape "$EFFECTIVE_SIGMA_RULES_PATH")",
    "sigma_rule_files": $sigma_rule_files,
    "yara_rules_path": "$(json_escape "$YARA_RULES_PATH")",
    "yara_rule_files": $yara_rule_files,
    "ioc_rules_path": "$(json_escape "$IOC_RULES_PATH")",
    "ioc_non_comment_lines": $ioc_non_comment_lines,
    "note": "Counts describe the configured rule corpus on disk. Runtime logs contain parser skips and loaded-rule details."
  },
  "parameters": {
    "idle_seconds": $IDLE_SECONDS,
    "process_launches": $PROCESS_LAUNCHES,
    "file_count": $FILE_COUNT,
    "file_size_bytes": $FILE_SIZE_BYTES,
    "alert_rule_name": "$(json_escape "$ALERT_RULE_NAME")",
    "benchmark_trigger_rule": $([[ "$NO_BENCHMARK_TRIGGER_RULE" -eq 0 ]] && echo true || echo false),
    "workload_mode": "$(json_escape "$WORKLOAD_MODE")"
  },
  "resource_summaries": [$resources_json],
  "workload_steps": [$steps_json],
  "alert_latency_ms": $ALERT_LATENCY_MS,
  "valid": $RUN_VALID,
  "validation_errors": [$validation_errors],
  "samples_csv": "$(json_escape "$SAMPLES_PATH")",
  "notes": [
    "Run once with --mode baseline and once with --mode with-agent on the same machine.",
    "Alert latency is null when no new alert line appears within 15 seconds."
  ]
}
JSON

echo "Summary: $SUMMARY_PATH"
echo "Samples: $SAMPLES_PATH"
if [[ "$RUN_VALID" != "true" ]]; then
  echo "Invalid benchmark run: ${VALIDATION_ERRORS[*]}" >&2
  exit 1
fi
