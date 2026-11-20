# Linux file sensor coverage fixtures

The live native baseline checks successful create, write-intent open, rename,
unlink, mkdir and rmdir, plus expected failures. It verifies the filesystem
result separately from the normalized event and compares the complete set of
fixture events. The manifest must report a complete capture with zero loss.

The io_uring and IA32 activity coverage belongs in this fixture group. Live
validation of those file paths is pending. Extend the group with a separate
anonymous temporary file publication case when coverage for `O_TMPFILE` and
`linkat` is implemented (#146).
