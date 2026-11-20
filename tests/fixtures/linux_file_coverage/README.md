# Linux file sensor coverage fixtures

The live native baseline checks successful create, write-intent open, rename, unlink, mkdir and rmdir, plus expected failures.
It verifies the filesystem result separately from the normalized event and compares the complete set of fixture events.
The manifest must report a complete capture with zero loss.

The synthetic io_uring snapshot checks per-lifetime counts, unattributed submissions, and map saturation.
The synthetic IA32 exits check that selected successful file operations count, while failed and native calls are excluded.
The live eBPF smoke test checks hook attachment and reports unavailable kernel prerequisites explicitly.
On the x86-64 CI runner it also compares the submission count for a completed `fio` write job and the counts for i386 BusyBox create, rename, mkdir and unlink to the expected per-process totals.
The count report is saved in `activity-coverage.json`.

The live capture records coverage for a 32-bit TCP connection, DNS lookup and process exec.
It checks the TCP destination port and exec arguments and records the DNS field observation after verifying the lookup succeeded.
Results are saved in `file-coverage.json`.

Extend the group with an anonymous temporary file publication case when coverage for `O_TMPFILE` and `linkat` is implemented (#146).
