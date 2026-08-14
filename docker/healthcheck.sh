#!/bin/sh
# Container health probe.
#
# `rustinel doctor` exits 2 when any check fails, and inside a container one
# check always fails by design: `native_service` looks for a systemd unit, while
# the container runtime is the supervisor here. Ignore those check IDs and treat
# everything else as authoritative. Warnings (exit code 1) stay healthy.
#
# Override the ignore list with RUSTINEL_HEALTHCHECK_IGNORE (space separated).

set -u

IGNORE="${RUSTINEL_HEALTHCHECK_IGNORE:-native_service}"

report=$(rustinel doctor --json 2>/dev/null) || true

if [ -z "$report" ]; then
    echo "healthcheck: rustinel doctor produced no output"
    exit 1
fi

echo "$report" | awk -v ignore=" $IGNORE " '
    /"id":/ {
        id = $0
        sub(/.*"id"[ ]*:[ ]*"/, "", id)
        sub(/".*/, "", id)
        next
    }
    /"status"[ ]*:[ ]*"fail"/ {
        if (id != "" && index(ignore, " " id " ") == 0) {
            print "healthcheck: failed check " id
            failed = 1
        }
    }
    END { exit failed ? 1 : 0 }
'
