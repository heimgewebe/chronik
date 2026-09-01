import fcntl
import hashlib
import json
import os
import queue
import threading
from contextlib import contextmanager

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


def _fingerprint_for_unique_line(line: str) -> bytes:
    _, canonical = storage._parse_unique_payload(line, "event_id")
    return storage._payload_fingerprint(canonical)


def test_verify_payload_unique_groups_reports_verified_missing_and_conflicting(
    mock_data_dir,
):
    first = _unique_line("first", "same")
    second = _unique_line("second", "same")
    storage.write_payload_unique_groups(
        "agent.ledger", [("seed", [first, second])]
    )
    before = (mock_data_dir / "agent.ledger.jsonl").read_bytes()

    result = storage.verify_payload_unique_groups(
        "agent.ledger",
        [
            ("verified", [("first", _fingerprint_for_unique_line(first))]),
            ("missing", [("absent", _fingerprint_for_unique_line(_unique_line("absent", "x")))]),
            ("conflicting", [("second", _fingerprint_for_unique_line(_unique_line("second", "different")))]),
        ],
    )

    assert result["identity_index_mode"] == "steady"
    assert result["target_records_scanned"] == 0
    assert result["groups"] == [
        {"group_id": "verified", "requested": 1, "verified": True, "missing": 0, "conflicting": 0},
        {"group_id": "missing", "requested": 1, "verified": False, "missing": 1, "conflicting": 0},
        {"group_id": "conflicting", "requested": 1, "verified": False, "missing": 0, "conflicting": 1},
    ]
    assert (mock_data_dir / "agent.ledger.jsonl").read_bytes() == before


def test_verify_payload_unique_groups_missing_ledger_is_read_only(mock_data_dir):
    fingerprint = _fingerprint_for_unique_line(_unique_line("absent", "value"))
    result = storage.verify_payload_unique_groups(
        "agent.ledger", [("candidate", [("absent", fingerprint)])]
    )

    assert result["identity_index_mode"] == "absent"
    assert result["target_records_scanned"] == 0
    assert result["groups"] == [
        {"group_id": "candidate", "requested": 1, "verified": False, "missing": 1, "conflicting": 0}
    ]
    assert not (mock_data_dir / "agent.ledger.jsonl").exists()
    assert not (mock_data_dir / ".chronik-identity-index-v1").exists()


def test_verify_payload_unique_groups_rejects_replaced_ledger_after_lock(
    mock_data_dir, monkeypatch
):
    line = _unique_line("first", "same")
    target = mock_data_dir / "agent.ledger.jsonl"
    target.write_text(line + "\n", encoding="utf-8")
    fingerprint = _fingerprint_for_unique_line(line)

    @contextmanager
    def replacing_fd_lock(_fd, path, *, exclusive):
        assert exclusive is False
        path.unlink()
        path.write_text(_unique_line("replacement", "different") + "\n", encoding="utf-8")
        yield

    monkeypatch.setattr(storage, "_fd_lock", replacing_fd_lock)
    with pytest.raises(storage.StorageRecoveryError, match="target identity changed"):
        storage.verify_payload_unique_groups(
            "agent.ledger", [("candidate", [("first", fingerprint)])]
        )
    assert not (mock_data_dir / ".chronik-identity-index-v1").exists()


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


def test_hash_domain_snapshot_hashes_complete_records_and_exact_prefix(
    mock_data_dir,
):
    first = b"one\n"
    second = b"two\n"
    complete = first + second
    (mock_data_dir / "agent.ledger.jsonl").write_bytes(complete + b"partial")

    complete_bytes, snapshot_sha256, prefix_sha256 = storage.hash_domain_snapshot(
        "agent.ledger", prefix_offset=len(first)
    )

    assert complete_bytes == len(complete)
    assert snapshot_sha256 == hashlib.sha256(complete).hexdigest()
    assert prefix_sha256 == hashlib.sha256(first).hexdigest()


def test_hash_domain_snapshot_rejects_non_boundary_prefix_and_invalid_offset(
    mock_data_dir,
):
    raw = b"one\ntwo\n"
    (mock_data_dir / "agent.ledger.jsonl").write_bytes(raw)

    complete_bytes, snapshot_sha256, prefix_sha256 = storage.hash_domain_snapshot(
        "agent.ledger", prefix_offset=2
    )
    assert complete_bytes == len(raw)
    assert snapshot_sha256 == hashlib.sha256(raw).hexdigest()
    assert prefix_sha256 is None

    with pytest.raises(storage.StorageError, match="non-negative integer"):
        storage.hash_domain_snapshot("agent.ledger", prefix_offset=-1)
    with pytest.raises(storage.StorageError, match="non-negative integer"):
        storage.hash_domain_snapshot("agent.ledger", prefix_offset=True)


def test_hash_domain_snapshot_empty_or_missing_domain(mock_data_dir):
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    assert storage.hash_domain_snapshot("agent.ledger") == (0, empty_sha256, None)
    assert storage.hash_domain_snapshot("agent.ledger", prefix_offset=0) == (
        0,
        empty_sha256,
        empty_sha256,
    )


def test_scan_domain_bytes_preserves_raw_record_bytes_and_offsets(mock_data_dir):
    first = b'{"value":"\xff"}\n'
    second = b'{"id":2}\r\n'
    (mock_data_dir / "agent.ledger.jsonl").write_bytes(first + second)

    assert list(storage.scan_domain_bytes("agent.ledger")) == [
        (0, len(first), first[:-1]),
        (len(first), len(first) + len(second), second[:-1]),
    ]


def test_committed_readers_need_no_writable_sidecar(mock_data_dir):
    raw = b'{"id":1}\n{"id":2}\n'
    target = mock_data_dir / "agent.ledger.jsonl"
    target.write_bytes(raw)
    lock_path = storage.get_lock_path(target)
    assert not lock_path.exists()

    original_mode = mock_data_dir.stat().st_mode & 0o777
    os.chmod(mock_data_dir, 0o500)
    try:
        assert list(storage.scan_domain_bytes("agent.ledger")) == [
            (0, len(b'{"id":1}\n'), b'{"id":1}'),
            (len(b'{"id":1}\n'), len(raw), b'{"id":2}'),
        ]
        assert storage.read_domain_snapshot("agent.ledger") == raw
        assert storage.hash_domain_snapshot("agent.ledger")[:2] == (
            len(raw),
            hashlib.sha256(raw).hexdigest(),
        )
    finally:
        os.chmod(mock_data_dir, original_mode)

    assert not lock_path.exists()


def test_scan_domain_decodes_raw_records_with_existing_replacement_semantics(
    mock_data_dir,
):
    raw = b'{"value":"\xff"}\n'
    (mock_data_dir / "agent.ledger.jsonl").write_bytes(raw)

    assert list(storage.scan_domain("agent.ledger")) == [
        (0, len(raw), '{"value":"\ufffd"}')
    ]


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


def _assert_reader_excludes_rolled_back_append(
    mock_data_dir, monkeypatch, reader, expected
):
    original = b'{"existing":1}\n'
    transient = b'{"transient":2}\n'
    target = mock_data_dir / "agent.ledger.jsonl"
    target.write_bytes(original)

    real_fsync = storage.os.fsync
    fsync_calls = 0
    transient_exposed = threading.Event()
    release_writer = threading.Event()
    progress = queue.Queue()
    writer_outcome = queue.Queue()
    reader_outcome = queue.Queue()
    reader_thread_name = "read-committed-regression-reader"

    def fail_commit_fsync(fd):
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 1:
            assert target.read_bytes() == original + transient
            transient_exposed.set()
            if not release_writer.wait(timeout=5):
                raise AssertionError("reader did not attempt a committed read")
            raise OSError(5, "simulated durability failure")
        return real_fsync(fd)

    real_fd_lock = storage._fd_lock

    @contextmanager
    def observed_fd_lock(fd, target_path, *, exclusive):
        if threading.current_thread().name == reader_thread_name:
            progress.put("lock-attempt")
        with real_fd_lock(fd, target_path, exclusive=exclusive):
            yield

    def write_transient_record():
        try:
            storage.write_payload("agent.ledger", [transient[:-1].decode("utf-8")])
        except BaseException as exc:
            writer_outcome.put(exc)
        else:
            writer_outcome.put(None)

    def run_reader():
        try:
            reader_outcome.put((reader(), None))
        except BaseException as exc:
            reader_outcome.put((None, exc))
        progress.put("read-complete")

    monkeypatch.setattr(storage.os, "fsync", fail_commit_fsync)
    monkeypatch.setattr(storage, "_fd_lock", observed_fd_lock)

    writer_thread = threading.Thread(target=write_transient_record)
    writer_thread.start()
    assert transient_exposed.wait(timeout=5)
    assert target.read_bytes() == original + transient

    reader_thread = threading.Thread(target=run_reader, name=reader_thread_name)
    reader_thread.start()
    try:
        assert progress.get(timeout=5) == "lock-attempt"
        assert reader_outcome.empty()
    finally:
        release_writer.set()
        writer_thread.join(timeout=5)
        reader_thread.join(timeout=5)

    assert not writer_thread.is_alive()
    assert not reader_thread.is_alive()
    writer_error = writer_outcome.get_nowait()
    assert isinstance(writer_error, storage.StorageRecoveryError)
    assert "durability sync failed" in str(writer_error)
    value, reader_error = reader_outcome.get_nowait()
    assert reader_error is None
    assert value == expected
    assert target.read_bytes() == original


def test_scan_domain_excludes_transient_append_rolled_back_after_fsync_failure(
    mock_data_dir, monkeypatch
):
    _assert_reader_excludes_rolled_back_append(
        mock_data_dir,
        monkeypatch,
        lambda: list(storage.scan_domain("agent.ledger")),
        [(0, len(b'{"existing":1}\n'), '{"existing":1}')],
    )


def test_committed_stream_releases_locks_before_yielding_records(
    mock_data_dir, monkeypatch
):
    first = b'{"id":1}\n'
    second = b'{"id":2}\n'
    target = mock_data_dir / "agent.ledger.jsonl"
    target.write_bytes(first + second)
    monkeypatch.setattr(storage, "LOCK_TIMEOUT", 0.2)

    stream = storage.scan_domain_bytes("agent.ledger")
    assert next(stream) == (0, len(first), first[:-1])

    outcome = queue.Queue()

    def append_after_reader_yield():
        try:
            storage.write_payload("agent.ledger", ['{"id":3}'])
        except BaseException as exc:
            outcome.put(exc)
        else:
            outcome.put(None)

    writer = threading.Thread(target=append_after_reader_yield)
    writer.start()
    writer.join(timeout=1)
    try:
        assert not writer.is_alive()
        assert outcome.get_nowait() is None
        assert list(stream) == [(len(first), len(first) + len(second), second[:-1])]
    finally:
        stream.close()
        if writer.is_alive():
            writer.join(timeout=1)

    assert target.read_bytes() == first + second + b'{"id":3}\n'


def test_hash_domain_snapshot_excludes_transient_append_rolled_back_after_fsync_failure(
    mock_data_dir, monkeypatch
):
    original = b'{"existing":1}\n'
    _assert_reader_excludes_rolled_back_append(
        mock_data_dir,
        monkeypatch,
        lambda: storage.hash_domain_snapshot(
            "agent.ledger", prefix_offset=len(original)
        ),
        (
            len(original),
            hashlib.sha256(original).hexdigest(),
            hashlib.sha256(original).hexdigest(),
        ),
    )


def test_read_domain_snapshot_excludes_transient_append_rolled_back_after_fsync_failure(
    mock_data_dir, monkeypatch
):
    _assert_reader_excludes_rolled_back_append(
        mock_data_dir,
        monkeypatch,
        lambda: storage.read_domain_snapshot("agent.ledger"),
        b'{"existing":1}\n',
    )


@pytest.mark.parametrize("reader_name", ["scan", "snapshot", "hash"])
def test_committed_reader_lock_timeout_is_storage_busy(
    mock_data_dir, monkeypatch, reader_name
):
    target = mock_data_dir / "agent.ledger.jsonl"
    target.write_bytes(b'{"existing":1}\n')
    holder = os.open(target, os.O_RDWR | os.O_CLOEXEC)
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    monkeypatch.setattr(storage, "LOCK_TIMEOUT", 0)

    try:
        with pytest.raises(storage.StorageBusyError, match="busy, try again"):
            if reader_name == "scan":
                list(storage.scan_domain("agent.ledger"))
            elif reader_name == "snapshot":
                storage.read_domain_snapshot("agent.ledger")
            else:
                storage.hash_domain_snapshot("agent.ledger")
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)


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
