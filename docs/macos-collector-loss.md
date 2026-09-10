# macOS collector loss

The telemetry snapshot includes `macos_collectors.esf` and
`macos_collectors.bpf` when those collectors run. Older snapshots remain readable.

ESF records received callbacks, global sequence gaps in `kernel_dropped`, and
gaps by native event type in `kernel_dropped_by_event_type`. These are two views
of the same losses and must not be added together. Accounting happens before
normalization and filtering. Each new client establishes sequence baselines on
its first observed message, so losses before those baselines cannot be counted.
Unsupported sequence fields do not advance a baseline.

BPF polls `BIOCGSTATS` at startup, every second while reading, and at shutdown.
`kernel_received` is the accumulated `bs_recv` count before the capture filter,
not the number of detection events. `kernel_dropped` accumulates `bs_drop`
with 32-bit wraparound handling. `stats_polls` counts successful samples and
`stats_errors` exposes failures, which doctor reports as a warning.

Doctor reports ESF and BPF kernel loss independently of pipeline channel
shedding. Ingress and detector queue losses remain in the existing channel
counters. All counts are cumulative for the agent run.

## Deliberate overload check

Use a disposable test Mac with a signed, entitled agent running as root and
Full Disk Access granted. Start it with `RUSTINEL_BPF_INTERFACE=lo0` and telemetry
enabled. Wait for a snapshot containing both collectors. Then run:

```sh
sudo python3 scripts/macos/test-collector-loss.py AGENT_PID /path/to/telemetry.json
```

Use the actual snapshot path under the configured logs directory. The script
suspends the agent for ten seconds while producing local file activity and
loopback UDP packets, resumes it in a cleanup handler, then waits up to two
minutes for both kernel-loss totals to increase. No external traffic is sent.
The test intentionally interrupts detection, so do not use a production agent.
Afterward, run doctor against the same logs directory and verify the two kernel
warnings are separate from any pipeline channel drops.

A passing unit test does not replace this privileged check. The live test needs
the ES entitlement and access to BPF devices.

## Interface coverage and attribution

By default the sensor opens one BPF device for every interface marked UP and
RUNNING at startup, including loopback and active VPN tunnels. Each capture
thread drains its own device; all interfaces share one bounded attribution
queue and socket inventory. A failed device open, unsupported link type, or
capture-thread failure degrades only that interface. If no device can start,
the runtime reports network capture as unavailable.

Set `RUSTINEL_BPF_INTERFACE=lo0` to restrict capture for a local test, or use a
comma-separated list such as `en0,utun0,lo0`. Empty entries are ignored. The
snapshot's `macos_collectors.bpf.interfaces` map reports each selected name,
whether its capture thread is active, its DLT, startup/runtime errors, and
received/drop/statistics totals. Aggregate BPF counters are the sum of device
observations, not unique packets across interfaces. Doctor emits a separate
diagnostic for each interface.

The parser supports Ethernet (DLT_EN10MB), native-endian loopback (DLT_NULL),
network-endian loopback (DLT_LOOP), and raw IP (DLT_RAW). Both loopback formats
have a four-byte family prefix; the IP version identifies the payload.
Unsupported link types are reported rather than silently discarded.

DNS over UDP and TCP uses the same asynchronous attribution worker as TCP
connection events. The inventory indexes both protocols, local addresses and
ports, and remote endpoints. Unconnected UDP sockets match their bound local
endpoint. Multiple matching PIDs leave ownership unknown. The socket may have
closed before the scan, and a shared resolver socket identifies the resolver
process, not necessarily the application that asked it to resolve a name.

### Current limitations

- Interface selection happens at startup. Restart after connecting a VPN,
  bringing up another interface, or replacing a failed capture device.
- A packet visible on multiple interfaces can produce duplicate events.
- IP fragments and IPv6 extension headers are not reassembled. DNS over TCP
  must fit in a captured segment; stream reassembly is not implemented.
- Attribution remains best-effort and uses an inventory cached for 250 ms.
  A full attribution queue emits events without ownership, while a full
  sensor channel sheds and counts the event in pipeline telemetry.

### Combined validation

For the combined #430/#432 check, start the entitled test agent without an
interface override, verify that loopback and the expected active Wi-Fi,
Ethernet, and VPN interfaces appear in the snapshot, and run the overload
script. Check that the aggregate drop counters equal the sum of per-interface
counters and that doctor reports failures and loss by interface.

To check failure isolation, run with `RUSTINEL_BPF_INTERFACE=lo0,missing430`.
Loopback must remain active and produce DNS events while `missing430` is
reported unavailable. A physical interface or VPN that is absent or has no
test traffic cannot be treated as validated by the loopback test alone.

### Validation on 2026-09-10

The signed test app ran as a temporary LaunchDaemon with Full Disk Access.
All 25 enumerated interfaces opened successfully, including eight utun devices
using DLT_NULL and DLT_RAW. Real loopback BPF capture produced a DNS query with
the test process's PID. A separate run with `lo0,missing430` retained working
DNS capture and reported the missing interface as unavailable.

The ten-second overload run measured 182,552 ESF global sequence gaps and
1,553,168 BPF kernel drops. Per-type ESF gaps summed to the global count, and
per-interface BPF totals reconciled with the aggregate counters. Doctor warned
about both kernel sources while reporting zero pipeline channel drops.
The temporary service was stopped and unloaded afterward.

Concurrent packet counters advanced on en0, loopback, bridge100, and vmenet0.
The utun devices opened but had no observed traffic during this run; traffic
through those tunnels was not exercised in the overload run. The subsequent
NordVPN test below covers the VPN path; physical Ethernet remains pending.

### NordVPN validation on 2026-09-10

After NordVPN connected, the route to the controlled test destination used
`utun8` (DLT_NULL). The signed agent was restarted for each of two cases:
VPN-only capture and default all-interface capture. Each case sent three DNS
queries for `rustinel-vpn-432.invalid` and opened one TCP connection to
`1.1.1.1:443`. Narrow temporary Sigma rules produced all four expected alerts,
with the correct probe process PID and BPF provider. DNS replies were received.

VPN-only capture counted 365 packets on utun8. With 26 interfaces active,
utun8 counted 1,312 packets, en0 counted 1,323, and loopback counted 30 during
the probe window. These counts include ambient traffic, not just the probes.
Both runs had zero additional ESF, BPF, or pipeline channel drops. Both temporary
daemons were stopped and unloaded. Physical Ethernet traffic is the remaining
hardware-dependent validation check.

### Ethernet software-path validation without an adapter

No physical Ethernet adapter was available. Instead, the BPF record test feeds
synthetic Ethernet and VLAN-tagged Ethernet DNS records through the production
record reader, link parser, attribution worker, and normalizer. Both IPv4 and
IPv6 are covered, using a real local UDP socket for PID/image lookup. The same
test also covers RAW, NULL, and LOOP framing, for ten combinations in total.
The fixture checksums are omitted because these buffers are decoded directly,
not transmitted.

This test also exposed an outdated availability contract that hid DNS
ProcessId and Image from Sigma despite their presence in the event payload.
Both fields are now conditional on successful socket attribution; the
generated compatibility baseline and documentation have been updated.

Together with real en0 capture using DLT_EN10MB, these checks cover the shared
Ethernet software path. A cable, USB adapter driver, and physical link behavior
have not been tested and are not claimed as validated.
