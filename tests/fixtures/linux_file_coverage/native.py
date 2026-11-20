"""Benign file operations with independent checks of their filesystem results."""

from collections import Counter
import os


def run(root, completed):
    original = root / "original"
    renamed = root / "renamed"
    directory = root / "directory"
    missing = root / "missing"
    missing_target = root / "missing-target"

    root.mkdir()
    with original.open("xb") as handle:
        handle.write(b"created")
    assert original.read_bytes() == b"created"
    completed.append(("create", 11, str(original), None))

    # Open with write intent, without O_CREAT. This is the source of the
    # normalized modify event on Linux.
    with original.open("r+b") as handle:
        handle.write(b"changed")
    assert original.read_bytes() == b"changed"
    completed.append(("modify", 65, str(original), None))

    original.rename(renamed)
    assert not original.exists() and renamed.read_bytes() == b"changed"
    completed.append(("rename", 71, str(renamed), str(original)))

    renamed.unlink()
    assert not renamed.exists()
    completed.append(("unlink", 23, str(renamed), None))

    directory.mkdir()
    assert directory.is_dir()
    completed.append(("mkdir", 11, str(directory), None))

    directory.rmdir()
    assert not directory.exists()
    completed.append(("rmdir", 23, str(directory), None))

    for name, operation, paths in (
        ("failed_modify", lambda: missing.open("r+b").close(), (missing,)),
        ("failed_unlink", missing.unlink, (missing,)),
        ("failed_rename", lambda: missing.rename(missing_target), (missing, missing_target)),
    ):
        try:
            operation()
        except FileNotFoundError:
            assert all(not path.exists() for path in paths)
            completed.append((name, None, str(paths[-1]), None))
        else:
            raise AssertionError(f"{name} unexpectedly succeeded")


def compare(events, root, completed):
    observed = Counter()
    process_ids = set()
    for event in events:
        if event.get("category") != "File" or event.get("provider") != "ebpf":
            continue
        fields = event["fields"]
        target = fields.get("TargetFilename")
        if target and os.path.dirname(target) == str(root):
            observed[event["event_id"], target, fields.get("SourceFilename")] += 1
            process_ids.add(fields.get("ProcessId", ""))

    expected = Counter(
        (event_id, target, source)
        for _, event_id, target, source in completed
        if event_id is not None
    )
    return {
        "matches": observed == expected and len(process_ids) == 1 and "" not in process_ids,
        "expected": [list(event) for event in expected.elements()],
        "observed": [list(event) for event in observed.elements()],
        "observed_process_ids": sorted(process_ids),
    }
