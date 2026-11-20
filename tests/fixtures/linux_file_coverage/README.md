# Linux file sensor coverage fixtures

The live native baseline checks successful create, write-intent open, rename, unlink, mkdir and rmdir, plus expected failures.
It verifies the filesystem result separately from the normalized event and compares the complete set of fixture events.
The manifest must report a complete capture with zero loss.

The synthetic io_uring snapshot checks per-lifetime counts, unattributed submissions, and map saturation.
The synthetic IA32 exits check that selected successful file operations count, while failed and native calls are excluded.
The live eBPF smoke test checks hook attachment and reports unavailable kernel prerequisites explicitly.
Live operation coverage for both paths remains pending.

Extend the group with an anonymous temporary file publication case when coverage for `O_TMPFILE` and `linkat` is implemented (#146).
