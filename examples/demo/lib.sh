#!/usr/bin/env bash
# Shared helpers for examples/demo scripts.

read_toml_value() {
  local section="$1"
  local key="$2"
  local file="$3"

  awk -v section="[$section]" -v key="$key" '
    BEGIN { in_section = 0 }
    $0 == section { in_section = 1; next }
    /^\[/ { in_section = 0 }
    in_section && $1 == key {
      line = $0
      sub(/^[^=]*=[ \t]*/, "", line)
      sub(/[ \t]*#.*$/, "", line)
      gsub(/^[ \t]+|[ \t]+$/, "", line)
      gsub(/^"/, "", line)
      gsub(/"$/, "", line)
      gsub(/^'\''/, "", line)
      gsub(/'\''$/, "", line)
      print line
      exit
    }
  ' "$file"
}

read_alerts_config() {
  local root="$1"
  local config_file="$root/config.toml"
  local alerts_dir alerts_filename

  if [[ ! -f "$config_file" ]]; then
    return 1
  fi

  alerts_dir="$(read_toml_value alerts directory "$config_file")"
  alerts_filename="$(read_toml_value alerts filename "$config_file")"

  [[ -z "$alerts_dir" ]] && alerts_dir="logs"
  [[ -z "$alerts_filename" ]] && alerts_filename="alerts.json"

  if [[ "$alerts_dir" != /* ]]; then
    alerts_dir="$root/$alerts_dir"
  fi

  printf '%s\n%s\n' "$alerts_dir" "$alerts_filename"
}

today_date() {
  date +%Y-%m-%d
}

today_alert_file() {
  local alerts_dir="$1"
  local alerts_filename="$2"

  printf '%s/%s.%s' "$alerts_dir" "$alerts_filename" "$(today_date)"
}

now_ms() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import time; print(int(time.time() * 1000))'
  else
    echo $(( $(date +%s) * 1000 ))
  fi
}

alert_file_line_count() {
  local file="$1"

  if [[ ! -f "$file" ]]; then
    echo 0
    return
  fi

  wc -l <"$file" | tr -d ' '
}

latest_alert_line() {
  local alerts_dir="$1"
  local alerts_filename="$2"
  local today_file latest_file="" file

  today_file="$(today_alert_file "$alerts_dir" "$alerts_filename")"
  if [[ -f "$today_file" ]]; then
    tail -n 1 "$today_file"
    return 0
  fi

  shopt -s nullglob
  local files=("$alerts_dir/$alerts_filename".*)
  for file in "${files[@]}"; do
    if [[ -z "$latest_file" || "$file" -nt "$latest_file" ]]; then
      latest_file="$file"
    fi
  done
  shopt -u nullglob

  if [[ -z "$latest_file" ]]; then
    return 1
  fi

  tail -n 1 "$latest_file"
}
