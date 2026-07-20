import json

import pytest
import storage

@pytest.fixture
def mock_data_dir(tmp_path, monkeypatch):
    """Isolate DATA_DIR for storage tests."""
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    return tmp_path

def test_list_domains_empty(mock_data_dir):
    """Verify it returns an empty list when DATA_DIR is empty."""
    assert storage.list_domains() == []

def test_list_domains_basic(mock_data_dir):
    """Verify it lists valid .jsonl files and sorts them."""
    (mock_data_dir / "zebra.jsonl").touch()
    (mock_data_dir / "apple.jsonl").touch()
    (mock_data_dir / "banana.jsonl").touch()

    assert storage.list_domains() == ["apple", "banana", "zebra"]

def test_list_domains_filtering(mock_data_dir):
    """Verify it ignores directories and files that don't match FILENAME_RE."""
    (mock_data_dir / "valid.jsonl").touch()
    (mock_data_dir / "invalid.txt").touch()
    (mock_data_dir / "no_ext").touch()
    (mock_data_dir / "subdir.jsonl").mkdir()
    (mock_data_dir / ".hidden.jsonl").touch() # Should be ignored (starts with dot)

    assert storage.list_domains() == ["valid"]

def test_list_domains_prefix(mock_data_dir):
    """Verify the prefix parameter correctly filters results."""
    (mock_data_dir / "apple.jsonl").touch()
    (mock_data_dir / "apricot.jsonl").touch()
    (mock_data_dir / "banana.jsonl").touch()

    # Empty prefix
    assert storage.list_domains("") == ["apple", "apricot", "banana"]

    # Matching prefix
    assert storage.list_domains("ap") == ["apple", "apricot"]

    # Non-matching prefix
    assert storage.list_domains("cherry") == []

def test_list_domains_special_chars(mock_data_dir):
    """Verify it handles allowed special characters in filenames."""
    # FILENAME_RE: [a-z0-9._-]+
    names = ["my.domain", "my_domain", "my-domain", "123.456"]
    for name in names:
        (mock_data_dir / f"{name}.jsonl").touch()

    assert storage.list_domains() == sorted(names)

def test_list_domains_os_error(mock_data_dir, monkeypatch):
    """Verify it returns an empty list and logs an error when os.scandir fails."""
    def mock_scandir(path):
        raise OSError("Access denied")

    # Patch storage.os to be more specific
    monkeypatch.setattr(storage.os, "scandir", mock_scandir)

    assert storage.list_domains() == []

def test_read_last_line_nonexistent(mock_data_dir):
    """Verify it returns None for a non-existent domain."""
    assert storage.read_last_line("nonexistent") is None

def test_read_last_line_empty(mock_data_dir):
    """Verify it returns None for an empty file."""
    (mock_data_dir / "empty.jsonl").touch()
    assert storage.read_last_line("empty") is None

def test_read_last_line_single_line(mock_data_dir):
    """Verify it returns the single line from a file."""
    storage.write_payload("single", ["{\"line\": 1}"])
    assert storage.read_last_line("single") == "{\"line\": 1}"

def test_read_last_line_multiple_lines(mock_data_dir):
    """Verify it returns the last line from a multi-line file."""
    storage.write_payload("multiple", ["{\"line\": 1}", "{\"line\": 2}"])
    assert storage.read_last_line("multiple") == "{\"line\": 2}"

def test_read_last_line_invalid_domain(mock_data_dir):
    """Verify it raises StorageError for an invalid domain name."""
    with pytest.raises(storage.StorageError, match="invalid target"):
        storage.read_last_line("domain with spaces")


def _unique_line(event_id: str, value: str) -> str:
    return json.dumps(
        {"payload": {"event_id": event_id, "value": value}}, sort_keys=True
    )


def test_payload_fingerprint_is_fixed_width_and_length_bound():
    small = storage._payload_fingerprint(b"payload")
    large_payload = b"payload" * 100_000
    large = storage._payload_fingerprint(large_payload)

    assert len(small) == 40
    assert len(large) == 40
    assert int.from_bytes(small[:8], "big") == len(b"payload")
    assert int.from_bytes(large[:8], "big") == len(large_payload)
    assert small[8:] != large[8:]


def test_write_payload_unique_groups_verifies_index_hits_against_ledger(
    mock_data_dir, monkeypatch
):
    storage.write_payload("agent.ledger", [_unique_line("existing", "same")])
    calls = []
    real_fingerprint = storage._payload_fingerprint

    def counted_fingerprint(payload):
        calls.append(payload)
        return real_fingerprint(payload)

    monkeypatch.setattr(storage, "_payload_fingerprint", counted_fingerprint)
    result = storage.write_payload_unique_groups(
        "agent.ledger",
        [("batch", [_unique_line("existing", "same"), _unique_line("new", "value")])],
    )

    assert result["written"] == 1
    assert result["skipped"] == 1
    existing_payload = b'{"event_id":"existing","value":"same"}'
    new_payload = b'{"event_id":"new","value":"value"}'
    assert calls.count(new_payload) == 1
    assert calls.count(existing_payload) == 3


def test_write_payload_unique_groups_scans_once_and_allocates_counts(mock_data_dir):
    storage.write_payload("agent.ledger", [_unique_line("existing", "same")])
    result = storage.write_payload_unique_groups(
        "agent.ledger",
        [
            ("first", [_unique_line("existing", "same"), _unique_line("new-a", "a")]),
            ("second", [_unique_line("new-a", "a"), _unique_line("new-b", "b")]),
        ],
    )
    assert result["target_scans"] == 1
    assert result["target_records_scanned"] == 1
    assert result["target_identity_index_entries"] == 1
    assert result["written"] == 2
    assert result["skipped"] == 2
    assert result["groups"] == [
        {"group_id": "first", "requested": 2, "written": 1, "skipped": 1},
        {"group_id": "second", "requested": 2, "written": 1, "skipped": 1},
    ]
    assert len((mock_data_dir / "agent.ledger.jsonl").read_text().splitlines()) == 3


def test_write_payload_unique_groups_indexes_history_with_bounded_fingerprints(
    mock_data_dir,
):
    historical = [
        _unique_line(f"old-{index}", "x" * 2048)
        for index in range(128)
    ]
    historical.append(_unique_line("candidate", "same"))
    storage.write_payload("agent.ledger", historical)

    result = storage.write_payload_unique_groups(
        "agent.ledger",
        [("batch", [_unique_line("candidate", "same"), _unique_line("new", "value")])],
    )

    assert result["target_records_scanned"] == 129
    assert result["target_identity_index_entries"] == 129
    assert result["written"] == 1
    assert result["skipped"] == 1


def test_write_payload_unique_groups_rejects_unrelated_historical_conflict(
    mock_data_dir,
):
    storage.write_payload(
        "agent.ledger",
        [_unique_line("damaged", "first"), _unique_line("damaged", "second")],
    )

    with pytest.raises(storage.StorageError, match="conflicting event_id: damaged"):
        storage.write_payload_unique_groups(
            "agent.ledger", [("batch", [_unique_line("new", "value")])]
        )


def test_scan_domain_accepts_crlf_record_boundary(mock_data_dir):
    first = b'{"id":1}\r\n'
    second = b'{"id":2}\r\n'
    (mock_data_dir / "agent.ledger.jsonl").write_bytes(first + second)

    records = list(storage.scan_domain("agent.ledger", start_offset=len(first)))

    assert records[0][:2] == (len(first), len(first) + len(second))
    assert json.loads(records[0][2]) == {"id": 2}


def test_scan_domain_accepts_boundary_after_empty_record(mock_data_dir):
    prefix = b'{"id":1}\n\n'
    final = b'{"id":3}\n'
    (mock_data_dir / "agent.ledger.jsonl").write_bytes(prefix + final)

    assert [
        json.loads(item[2])
        for item in storage.scan_domain("agent.ledger", start_offset=len(prefix))
    ] == [{"id": 3}]


def test_scan_domain_rejects_boolean_cursor(mock_data_dir):
    storage.write_payload("agent.ledger", ['{"id":1}'])

    with pytest.raises(storage.StorageCursorError, match="non-negative integer"):
        list(storage.scan_domain("agent.ledger", start_offset=True))


def test_scan_domain_accepts_integer_subclass_cursor(mock_data_dir):
    class Cursor(int):
        pass

    first = '{"id":1}'
    storage.write_payload("agent.ledger", [first, '{"id":2}'])
    boundary = Cursor(len(first.encode("utf-8")) + 1)

    assert [item[2] for item in storage.scan_domain("agent.ledger", boundary)] == [
        '{"id":2}'
    ]


def test_scan_domain_cursor_beyond_eof_remains_retryable(mock_data_dir):
    storage.write_payload("agent.ledger", ['{"id":1}'])

    assert list(storage.scan_domain("agent.ledger", start_offset=10_000)) == []
    assert list(storage.scan_domain("agent.ledger", start_offset=1 << 100)) == []


def test_scan_domain_rejects_cursor_inside_record(mock_data_dir):
    storage.write_payload("agent.ledger", ['{"id":1}', '{"id":2}'])

    with pytest.raises(storage.StorageCursorError, match="record boundary"):
        list(storage.scan_domain("agent.ledger", start_offset=1))


def test_scan_domain_accepts_emitted_record_boundary(mock_data_dir):
    first = '{"id":1}'
    storage.write_payload("agent.ledger", [first, '{"id":2}'])
    boundary = len(first.encode("utf-8")) + 1

    assert list(storage.scan_domain("agent.ledger", start_offset=boundary)) == [
        (boundary, boundary + len('{"id":2}'.encode("utf-8")) + 1, '{"id":2}')
    ]


def test_write_payload_unique_groups_rejects_cross_group_conflict_before_write(
    mock_data_dir,
):
    with pytest.raises(storage.StorageError, match="conflicting event_id"):
        storage.write_payload_unique_groups(
            "agent.ledger",
            [
                ("first", [_unique_line("same", "a")]),
                ("second", [_unique_line("same", "b")]),
            ],
        )
    target = mock_data_dir / "agent.ledger.jsonl"
    assert not target.exists() or target.read_text() == ""


def test_write_payload_unique_wrapper_retains_tuple_contract(mock_data_dir):
    assert storage.write_payload_unique(
        "agent.ledger", [_unique_line("one", "a"), _unique_line("one", "a")]
    ) == (1, 1)


def test_write_payload_rolls_back_short_write(mock_data_dir, monkeypatch):
    original = b'{"existing":1}\n'
    target = mock_data_dir / "agent.ledger.jsonl"
    target.write_bytes(original)
    real_write = storage.os.write

    def short_write(fd, payload):
        prefix = max(1, len(payload) // 2)
        return real_write(fd, payload[:prefix])

    monkeypatch.setattr(storage.os, "write", short_write)

    with pytest.raises(storage.StorageError, match="append failed"):
        storage.write_payload("agent.ledger", ['{"new":2}'])

    assert target.read_bytes() == original
    assert storage.read_domain_snapshot("agent.ledger") == original


def test_write_payload_rolls_back_enospc_after_prior_record(mock_data_dir, monkeypatch):
    original = b'{"existing":1}\n'
    target = mock_data_dir / "agent.ledger.jsonl"
    target.write_bytes(original)
    real_write = storage.os.write
    calls = 0

    def fail_second_write(fd, payload):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError(28, "No space left on device")
        return real_write(fd, payload)

    monkeypatch.setattr(storage.os, "write", fail_second_write)

    with pytest.raises(storage.StorageFullError, match="insufficient storage"):
        storage.write_payload("agent.ledger", ['{"new":2}', '{"new":3}'])

    assert target.read_bytes() == original


def test_unique_group_append_rolls_back_without_weakening_conflicts(
    mock_data_dir, monkeypatch
):
    first = _unique_line("existing", "same")
    storage.write_payload("agent.ledger", [first])
    target = mock_data_dir / "agent.ledger.jsonl"
    original = target.read_bytes()
    real_write = storage.os.write

    def short_write(fd, payload):
        real_write(fd, payload[:4])
        return 4

    monkeypatch.setattr(storage.os, "write", short_write)
    with pytest.raises(storage.StorageError, match="append failed"):
        storage.write_payload_unique_groups(
            "agent.ledger", [("new", [_unique_line("new", "value")])]
        )
    assert target.read_bytes() == original

    monkeypatch.setattr(storage.os, "write", real_write)
    with pytest.raises(storage.StorageError, match="conflicting event_id"):
        storage.write_payload_unique_groups(
            "agent.ledger", [("conflict", [_unique_line("existing", "different")])]
        )
    assert target.read_bytes() == original


def test_append_rollback_failure_is_distinct(mock_data_dir, monkeypatch):
    target = mock_data_dir / "agent.ledger.jsonl"
    target.write_bytes(b'{"existing":1}\n')

    def fail_write(fd, payload):
        raise OSError(28, "No space left on device")

    def fail_rollback(fd, target_path, pre_append_size):
        raise OSError(5, "rollback failed")

    monkeypatch.setattr(storage.os, "write", fail_write)
    monkeypatch.setattr(storage, "_rollback_append", fail_rollback)

    with pytest.raises(
        storage.StorageRecoveryError, match="ledger integrity is uncertain"
    ):
        storage.write_payload("agent.ledger", ['{"new":2}'])


def test_append_detects_target_replacement_and_fails_closed(
    mock_data_dir, monkeypatch
):
    target = mock_data_dir / "agent.ledger.jsonl"
    original = b'{"existing":1}\n'
    target.write_bytes(original)
    displaced = mock_data_dir / "displaced.jsonl"
    real_write = storage.os.write
    replaced = False

    def replace_after_write(fd, payload):
        nonlocal replaced
        written = real_write(fd, payload)
        if not replaced:
            target.rename(displaced)
            target.write_bytes(b'{"replacement":true}\n')
            replaced = True
        return written

    monkeypatch.setattr(storage.os, "write", replace_after_write)

    with pytest.raises(storage.StorageRecoveryError):
        storage.write_payload("agent.ledger", ['{"new":2}'])

    assert target.read_bytes() == b'{"replacement":true}\n'
    assert displaced.read_bytes() == original


def test_append_rollback_happens_before_domain_lock_release(
    mock_data_dir, monkeypatch
):
    from filelock import FileLock, Timeout

    target = mock_data_dir / "agent.ledger.jsonl"
    target.write_bytes(b'{"existing":1}\n')
    lock_path = storage.get_lock_path(target)
    real_truncate = storage.os.ftruncate
    lock_was_held = False

    def checked_truncate(fd, size):
        nonlocal lock_was_held
        contender = FileLock(str(lock_path), timeout=0)
        try:
            contender.acquire()
        except Timeout:
            lock_was_held = True
        else:
            contender.release()
        real_truncate(fd, size)

    def fail_write(fd, payload):
        raise OSError(5, "simulated append failure")

    monkeypatch.setattr(storage.os, "write", fail_write)
    monkeypatch.setattr(storage.os, "ftruncate", checked_truncate)

    with pytest.raises(storage.StorageError, match="append failed"):
        storage.write_payload("agent.ledger", ['{"new":2}'])

    assert lock_was_held


def test_write_payload_serializes_across_processes(mock_data_dir):
    import os
    import subprocess
    import sys

    code = (
        "import storage; "
        "storage.write_payload('agent.ledger', "
        "['{\\\"process\\\":' + __import__('sys').argv[1] + '}'])"
    )
    env = os.environ.copy()
    env["CHRONIK_DATA_DIR"] = str(mock_data_dir)
    processes = [
        subprocess.Popen([sys.executable, "-c", code, str(index)], env=env)
        for index in range(8)
    ]
    assert [process.wait(timeout=20) for process in processes] == [0] * 8

    target = mock_data_dir / "agent.ledger.jsonl"
    lines = target.read_bytes().splitlines(keepends=True)
    assert len(lines) == 8
    assert all(line.endswith(b"\n") for line in lines)
    assert {json.loads(line)["process"] for line in lines} == set(range(8))


def test_commit_fsync_failure_rolls_back_and_is_recovery_error(
    mock_data_dir, monkeypatch
):
    original = b'{"existing":1}\n'
    target = mock_data_dir / "agent.ledger.jsonl"
    target.write_bytes(original)
    real_fsync = storage.os.fsync
    calls = 0

    def fail_first_fsync(fd):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError(5, "simulated durability failure")
        return real_fsync(fd)

    monkeypatch.setattr(storage.os, "fsync", fail_first_fsync)

    with pytest.raises(storage.StorageRecoveryError, match="durability sync failed"):
        storage.write_payload("agent.ledger", ['{"new":2}'])

    assert target.read_bytes() == original
