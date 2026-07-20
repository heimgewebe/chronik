import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

import identity_index
import storage


@pytest.fixture
def mock_data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    return tmp_path


def _line(event_id: str, value: str) -> str:
    return json.dumps(
        {"payload": {"event_id": event_id, "value": value}}, sort_keys=True
    )


def _write(domain: str, *lines: str):
    return storage.write_payload_unique_groups(domain, [("batch", list(lines))])


def _target(data_dir: Path, domain: str = "agent.ledger") -> Path:
    return data_dir / f"{domain}.jsonl"


def _index_path(data_dir: Path, domain: str = "agent.ledger") -> Path:
    return identity_index.index_path_for_target(_target(data_dir, domain))


def test_missing_index_rebuilds_once_then_steady_state_skips_full_scan(mock_data_dir):
    storage.write_payload(
        "agent.ledger", [_line(f"old-{index}", str(index)) for index in range(50)]
    )

    rebuilt = _write(
        "agent.ledger", _line("old-1", "1"), _line("new-1", "value")
    )
    steady = _write("agent.ledger", _line("new-2", "value"))

    assert rebuilt["identity_index_mode"] == "rebuild"
    assert rebuilt["identity_index_full_rebuild"] is True
    assert rebuilt["target_scans"] == 1
    assert rebuilt["target_records_scanned"] == 50
    assert rebuilt["written"] == 1
    assert rebuilt["skipped"] == 1
    assert rebuilt["identity_index_offset"] == _target(mock_data_dir).stat().st_size - len(
        (_line("new-2", "value") + "\n").encode()
    )

    assert steady["identity_index_mode"] == "steady"
    assert steady["identity_index_full_rebuild"] is False
    assert steady["target_scans"] == 0
    assert steady["target_records_scanned"] == 0
    assert steady["written"] == 1
    assert steady["identity_index_offset"] == _target(mock_data_dir).stat().st_size


def test_plain_ledger_append_uses_verified_catchup(mock_data_dir):
    _write("agent.ledger", _line("seed", "same"))
    storage.write_payload("agent.ledger", [_line("external", "same")])

    result = _write(
        "agent.ledger", _line("external", "same"), _line("new", "value")
    )

    assert result["identity_index_mode"] == "verify-catchup"
    assert result["target_records_scanned"] == 2
    assert result["written"] == 1
    assert result["skipped"] == 1


def test_invalid_historical_line_is_chained_but_not_indexed(mock_data_dir):
    _write("agent.ledger", _line("seed", "same"))
    storage.write_payload("agent.ledger", ["not-json"])

    result = _write("agent.ledger", _line("new", "value"))

    assert result["identity_index_mode"] == "verify-catchup"
    assert result["target_records_scanned"] == 2
    assert result["written"] == 1


def test_historical_record_without_identity_is_chained_but_not_indexed(
    mock_data_dir,
):
    storage.write_payload(
        "agent.ledger",
        [json.dumps({"payload": {"value": "missing identity"}}, sort_keys=True)],
    )

    result = _write("agent.ledger", _line("new", "value"))

    assert result["identity_index_mode"] == "rebuild"
    assert result["target_records_scanned"] == 1
    assert result["target_identity_index_entries"] == 0
    assert result["identity_index_entries_after"] == 1


def test_rebuild_preserves_global_historical_conflict_detection(mock_data_dir):
    storage.write_payload(
        "agent.ledger", [_line("damaged", "first"), _line("damaged", "second")]
    )

    with pytest.raises(storage.StorageError, match="conflicting event_id: damaged"):
        _write("agent.ledger", _line("new", "value"))


def test_truncated_ledger_fails_closed(mock_data_dir):
    _write("agent.ledger", _line("seed", "same"))
    _target(mock_data_dir).write_bytes(b"")

    with pytest.raises(storage.StorageRecoveryError, match="truncated"):
        _write("agent.ledger", _line("new", "value"))


def test_replaced_ledger_inode_fails_closed(mock_data_dir):
    _write("agent.ledger", _line("seed", "same"))
    replacement = mock_data_dir / "replacement.jsonl"
    replacement.write_text(_line("seed", "same") + "\n", encoding="utf-8")
    os.replace(replacement, _target(mock_data_dir))

    with pytest.raises(storage.StorageRecoveryError, match="identity changed"):
        _write("agent.ledger", _line("new", "value"))


def test_same_size_prefix_mutation_triggers_full_verification(mock_data_dir):
    first = _line("first", "a")
    second = _line("second", "b")
    _write("agent.ledger", first, second)
    target = _target(mock_data_dir)
    raw = target.read_bytes()
    mutated = raw.replace(b'"value": "a"', b'"value": "z"', 1)
    assert len(mutated) == len(raw)
    target.write_bytes(mutated)

    with pytest.raises(storage.StorageRecoveryError, match="prefix verification failed"):
        _write("agent.ledger", _line("new", "value"))


def test_prefix_mutation_plus_append_fails_verified_catchup(mock_data_dir):
    first = _line("first", "a")
    second = _line("second", "b")
    _write("agent.ledger", first, second)
    target = _target(mock_data_dir)
    raw = target.read_bytes()
    mutated = raw.replace(b'"value": "a"', b'"value": "z"', 1)
    assert len(mutated) == len(raw)
    target.write_bytes(mutated)
    with target.open("ab") as handle:
        handle.write((_line("external", "same") + "\n").encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())

    with pytest.raises(storage.StorageRecoveryError, match="prefix verification failed"):
        _write("agent.ledger", _line("new", "value"))


def test_incomplete_ledger_tail_fails_closed(mock_data_dir):
    _write("agent.ledger", _line("seed", "same"))
    with _target(mock_data_dir).open("ab") as handle:
        handle.write(b'{"payload":')
        handle.flush()
        os.fsync(handle.fileno())

    with pytest.raises(storage.StorageRecoveryError, match="incomplete final record"):
        _write("agent.ledger", _line("new", "value"))


def test_corrupt_database_is_not_silently_rebuilt(mock_data_dir):
    _write("agent.ledger", _line("seed", "same"))
    _index_path(mock_data_dir).write_bytes(b"not a sqlite database")

    with pytest.raises(storage.StorageRecoveryError, match="identity index"):
        _write("agent.ledger", _line("new", "value"))


def test_same_name_trigger_definition_mutation_fails_closed(mock_data_dir):
    _write("agent.ledger", _line("seed", "same"))
    with sqlite3.connect(_index_path(mock_data_dir)) as connection:
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            """
            UPDATE sqlite_master
            SET sql = ?
            WHERE type = 'trigger' AND name = 'identities_count_insert'
            """,
            (
                "CREATE TRIGGER identities_count_insert "
                "AFTER INSERT ON identities BEGIN SELECT 1; END",
            ),
        )
        connection.execute("PRAGMA writable_schema=OFF")

    with pytest.raises(
        storage.StorageRecoveryError,
        match="schema definitions mismatch",
    ):
        _write("agent.ledger", _line("new", "value"))


def test_symlinked_database_is_rejected(mock_data_dir):
    storage.write_payload("agent.ledger", [_line("seed", "same")])
    index_path = _index_path(mock_data_dir)
    index_path.parent.mkdir(mode=0o700)
    decoy = mock_data_dir / "decoy.sqlite3"
    decoy.write_bytes(b"")
    index_path.symlink_to(decoy)

    with pytest.raises(storage.StorageRecoveryError, match="regular file"):
        _write("agent.ledger", _line("new", "value"))


def test_insecure_index_directory_is_rejected(mock_data_dir):
    storage.write_payload("agent.ledger", [_line("seed", "same")])
    index_root = mock_data_dir / identity_index.INDEX_DIR_NAME
    index_root.mkdir(mode=0o700)
    index_root.chmod(0o755)

    with pytest.raises(storage.StorageRecoveryError, match="not private"):
        _write("agent.ledger", _line("new", "value"))


def test_general_storage_write_does_not_reset_index_after_ledger_loss(mock_data_dir):
    _write("agent.ledger", _line("seed", "same"))
    _target(mock_data_dir).unlink()

    with pytest.raises(
        storage.StorageRecoveryError,
        match="identity changed|truncated behind the index",
    ):
        _write("agent.ledger", _line("seed", "same"))


def test_batch_replay_recovers_after_failed_general_write_left_empty_ledger(
    mock_data_dir,
):
    _write("agent.ledger", _line("seed", "same"))
    _target(mock_data_dir).unlink()
    with pytest.raises(storage.StorageRecoveryError):
        _write("agent.ledger", _line("seed", "same"))
    assert _target(mock_data_dir).stat().st_size == 0

    result = storage.write_payload_unique_groups(
        "agent.ledger",
        [("replay", [_line("seed", "same")])],
        authoritative_replay=True,
    )

    assert result["identity_index_mode"] == "rebuild"
    assert result["written"] == 1


def test_authoritative_replay_resets_only_derived_index_for_empty_ledger(
    mock_data_dir,
):
    _write("agent.ledger", _line("seed", "same"))
    _target(mock_data_dir).unlink()

    result = storage.write_payload_unique_groups(
        "agent.ledger",
        [("replay", [_line("seed", "same")])],
        authoritative_replay=True,
    )

    assert result["identity_index_mode"] == "rebuild"
    assert result["written"] == 1
    assert result["skipped"] == 0


def test_authoritative_replay_rejects_nonempty_ledger(mock_data_dir):
    _write("agent.ledger", _line("seed", "same"))

    with pytest.raises(
        storage.StorageRecoveryError,
        match="requires an empty reconstructed ledger",
    ):
        storage.write_payload_unique_groups(
            "agent.ledger",
            [("replay", [_line("new", "value")])],
            authoritative_replay=True,
        )


def test_authoritative_replay_rejects_symlinked_index_artifact(mock_data_dir):
    _write("agent.ledger", _line("seed", "same"))
    _target(mock_data_dir).unlink()
    index_path = _index_path(mock_data_dir)
    index_path.unlink()
    decoy = mock_data_dir / "decoy.sqlite3"
    decoy.write_bytes(b"")
    index_path.symlink_to(decoy)

    with pytest.raises(storage.StorageRecoveryError, match="regular file"):
        storage.write_payload_unique_groups(
            "agent.ledger",
            [("replay", [_line("seed", "same")])],
            authoritative_replay=True,
        )


def test_deleted_index_is_rebuilt_from_unchanged_ledger(mock_data_dir):
    _write("agent.ledger", _line("seed", "same"))
    _index_path(mock_data_dir).unlink()

    result = _write(
        "agent.ledger", _line("seed", "same"), _line("new", "value")
    )

    assert result["identity_index_mode"] == "rebuild"
    assert result["target_records_scanned"] == 1
    assert result["written"] == 1
    assert result["skipped"] == 1


def test_index_stage_failure_rolls_back_the_ledger(mock_data_dir, monkeypatch):
    _write("agent.ledger", _line("seed", "same"))
    target = _target(mock_data_dir)
    before = target.read_bytes()
    real_stage = identity_index.IdentityIndex.stage_append

    def fail_stage(self, **kwargs):
        raise identity_index.IdentityIndexCorruptError("synthetic stage failure")

    monkeypatch.setattr(identity_index.IdentityIndex, "stage_append", fail_stage)
    with pytest.raises(storage.StorageRecoveryError, match="synthetic stage failure"):
        _write("agent.ledger", _line("new", "value"))
    assert target.read_bytes() == before

    monkeypatch.setattr(identity_index.IdentityIndex, "stage_append", real_stage)
    recovered = _write("agent.ledger", _line("new", "value"))
    assert recovered["identity_index_mode"] == "verify"
    assert recovered["written"] == 1


def test_hard_crash_after_ledger_append_recovers_lagging_index(
    mock_data_dir,
):
    _write("agent.ledger", _line("seed", "same"))
    child = """
import json
import os
from pathlib import Path

import identity_index
import storage

storage.DATA_DIR = Path(os.environ["CRASH_DATA_DIR"])
real_stage = identity_index.IdentityIndex.stage_append


def crash_after_stage(self, **kwargs):
    real_stage(self, **kwargs)
    os._exit(73)


identity_index.IdentityIndex.stage_append = crash_after_stage
line = json.dumps(
    {"payload": {"event_id": "crash-event", "value": "durable"}},
    sort_keys=True,
)
storage.write_payload_unique_groups(
    "agent.ledger",
    [("crash", [line])],
)
"""
    environment = os.environ.copy()
    environment["CRASH_DATA_DIR"] = str(mock_data_dir)
    crashed = subprocess.run(
        [sys.executable, "-c", child],
        cwd=Path(__file__).parents[1],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert crashed.returncode == 73, crashed.stderr
    assert _line("crash-event", "durable") in _target(mock_data_dir).read_text()

    recovered = _write("agent.ledger", _line("crash-event", "durable"))

    assert recovered["identity_index_mode"] == "verify-catchup"
    assert recovered["written"] == 0
    assert recovered["skipped"] == 1


def test_uncertain_index_commit_leaves_recoverable_ledger_ahead(
    mock_data_dir, monkeypatch
):
    _write("agent.ledger", _line("seed", "same"))
    real_commit = identity_index.IdentityIndex.commit

    def fail_commit(self):
        raise identity_index.IdentityIndexCommitUncertain("synthetic commit uncertainty")

    monkeypatch.setattr(identity_index.IdentityIndex, "commit", fail_commit)
    with pytest.raises(storage.StorageRecoveryError, match="commit outcome uncertain"):
        _write("agent.ledger", _line("new", "value"))
    assert _line("new", "value") in _target(mock_data_dir).read_text()

    monkeypatch.setattr(identity_index.IdentityIndex, "commit", real_commit)
    recovered = _write("agent.ledger", _line("new", "value"))
    assert recovered["identity_index_mode"] == "verify-catchup"
    assert recovered["target_records_scanned"] == 2
    assert recovered["written"] == 0
    assert recovered["skipped"] == 1


def test_state_hash_tampering_is_rejected_before_use(mock_data_dir):
    _write("agent.ledger", _line("first", "a"), _line("second", "b"))
    with sqlite3.connect(_index_path(mock_data_dir)) as connection:
        connection.execute(
            "UPDATE index_state SET chain_digest = ? WHERE identity_key = ?",
            (b"x" * 32, "event_id"),
        )

    with pytest.raises(storage.StorageRecoveryError, match="state digest mismatch"):
        _write("agent.ledger", _line("third", "c"))


def test_deleted_identity_row_breaks_count_binding(mock_data_dir):
    _write("agent.ledger", _line("first", "a"), _line("second", "b"))
    with sqlite3.connect(_index_path(mock_data_dir)) as connection:
        connection.execute(
            "DELETE FROM identities WHERE identity_key = ? AND identity = ?",
            ("event_id", "first"),
        )

    with pytest.raises(storage.StorageRecoveryError, match="count binding mismatch"):
        _write("agent.ledger", _line("first", "a"))


def test_tampered_identity_row_digest_fails_closed(mock_data_dir):
    _write("agent.ledger", _line("first", "a"))
    with sqlite3.connect(_index_path(mock_data_dir)) as connection:
        connection.execute(
            "UPDATE identities SET fingerprint = ? WHERE identity_key = ? AND identity = ?",
            (b"x" * 40, "event_id", "first"),
        )

    with pytest.raises(storage.StorageRecoveryError, match="row digest mismatch"):
        _write("agent.ledger", _line("first", "a"))


def test_tampered_identity_row_offset_fails_closed(mock_data_dir):
    _write("agent.ledger", _line("first", "a"))
    with sqlite3.connect(_index_path(mock_data_dir)) as connection:
        connection.execute(
            "UPDATE identities SET record_start = 1 WHERE identity_key = ? AND identity = ?",
            ("event_id", "first"),
        )

    with pytest.raises(storage.StorageRecoveryError, match="row digest mismatch"):
        _write("agent.ledger", _line("first", "a"))


def test_lookup_chunks_more_than_sqlite_parameter_limit(mock_data_dir):
    lines = [_line(f"event-{index}", str(index)) for index in range(1201)]
    first = _write("agent.ledger", *lines)
    second = _write("agent.ledger", *lines)

    assert first["written"] == 1201
    assert second["identity_index_mode"] == "steady"
    assert second["written"] == 0
    assert second["skipped"] == 1201


def test_large_allowed_payload_keeps_fixed_width_index_fingerprint(mock_data_dir):
    value = "x" * 700_000
    result = _write("agent.ledger", _line("large", value))

    assert result["written"] == 1
    with sqlite3.connect(_index_path(mock_data_dir)) as connection:
        fingerprint = connection.execute(
            "SELECT fingerprint FROM identities WHERE identity_key = ? AND identity = ?",
            ("event_id", "large"),
        ).fetchone()[0]
    assert len(fingerprint) == 40
