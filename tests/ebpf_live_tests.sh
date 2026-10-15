#!/usr/bin/env bash
# Run the root-gated live Linux eBPF tests that are #[ignore]d for plain `cargo test`.
#
# Build as the invoking user, then run the test executables under sudo so the
# target directory never ends up root-owned. Needs the eBPF object in
# ebpf/rustinel-ebpf.o, root via sudo, kernel BTF, tracefs, and docker.
#
# RUSTINEL_LIVE_SUDO overrides the privilege wrapper; set it to an empty string
# when already running as root.
set -euo pipefail

read -ra sudo_cmd <<<"${RUSTINEL_LIVE_SUDO-sudo -E}"

cd "$(dirname "$0")/.."

cargo build --locked --example memory_target
declare -A bins
while read -r name executable; do
  bins[$name]=$executable
done < <(
  cargo test --locked --no-run --message-format=json \
    --test linux_task_identity --test linux_socket_tuple \
    --test linux_file_paths --test linux_container_context |
    jq -r 'select(.reason == "compiler-artifact" and .target.kind == ["test"] and .executable != null) | "\(.target.name) \(.executable)"'
)

run() {
  local target=$1
  shift
  echo "::group::$target $*"
  "${sudo_cmd[@]}" "${bins[$target]}" --ignored --exact --test-threads=1 "$@"
  echo "::endgroup::"
}

run linux_task_identity live_task_identity_matches_proc
run linux_task_identity live_ebpf_process_reaches_yara_memory_scan
run linux_socket_tuple live_tuple_and_connection_churn
run linux_file_paths bare_read_only_reuse_cannot_consume_an_old_directory_index_entry
run linux_container_context live_container_context_reaches_sigma

# A tmpfs over /sys/kernel/btf in a private mount namespace hides kernel BTF
# from the test only; the host and later steps keep seeing it.
run_without_btf() {
  local target=$1
  shift
  echo "::group::$target (BTF hidden) $*"
  "${sudo_cmd[@]}" unshare --mount --propagation private bash -c '
    mount -t tmpfs none /sys/kernel/btf
    exec "$@"
  ' _ "${bins[$target]}" --ignored --exact --test-threads=1 "$@"
  echo "::endgroup::"
}

run_without_btf linux_task_identity live_without_btf_keeps_base_telemetry
run_without_btf linux_socket_tuple live_without_socket_btf_uses_syscall_fallback
