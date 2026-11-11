"""Recovery happens only in the import service preflight, after exact PR311 proof."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

import identity_index
import storage
from tools import identity_index_boot_recovery as boot
from tools import identity_index_recovery


@pytest.fixture
def locations(tmp_path, monkeypatch):
    state = tmp_path / "chronik"
    state.mkdir(mode=0o700)
    data = state / "data"
    data.mkdir(mode=0o700)
    monkeypatch.setattr(storage, "DATA_DIR", data)
    return data, state / "manual-recovery-copies"


def _append(domain, event):
    line = json.dumps({"payload": {"event_id": event, "value": "unchanged"}})
    return storage.write_payload_unique_groups(domain, [(event, [line])])


def _drift(data, domain):
    target = data / f"{domain}.jsonl"
    with identity_index.open_identity_index(target, timeout=storage.LOCK_TIMEOUT) as index:
        state = index._load_state("event_id")
        assert state is not None
        old = replace(state, ledger_dev=state.ledger_dev + 123)
        index.connection.execute("BEGIN IMMEDIATE")
        index._store_state(old)
        index.commit()
    return old.ledger_dev


def _read_device(data, domain):
    target = data / f"{domain}.jsonl"
    with sqlite3.connect(identity_index.index_path_for_target(target)) as db:
        return int(db.execute(
            "SELECT ledger_dev FROM index_state WHERE identity_key = 'event_id'"
        ).fetchone()[0])



def test_pristine_data_dir_does_not_block_first_import(tmp_path):
    data = tmp_path / "chronik" / "data"
    backup = data.parent / "manual-recovery-copies"
    assert not data.exists()
    assert boot.recover_before_import(data, backup) == {
        "schema_version": 1, "status": "not_initialized", "recoveries": [],
    }
    assert not data.exists()
    assert not backup.exists()

def test_healthy_index_no_writes_or_backup_directory(locations):
    data, backup = locations
    _append("agent.ledger", "one")
    ledger = data / "agent.ledger.jsonl"
    index = identity_index.index_path_for_target(ledger)
    before = (ledger.read_bytes(), index.read_bytes())
    assert boot.recover_before_import(data, backup) == {
        "schema_version": 1, "status": "steady", "recoveries": [],
    }
    assert not backup.exists()
    assert (ledger.read_bytes(), index.read_bytes()) == before


def test_reboot_stdev_drift_repairs_both_indexes_with_durable_preimages(locations):
    data, backup = locations
    originals = {}
    for domain in boot.DOMAINS:
        _append(domain, domain)
        target = data / f"{domain}.jsonl"
        originals[domain] = (target.read_bytes(), target.stat().st_ino)
        _drift(data, domain)
        with pytest.raises(storage.StorageRecoveryError, match="ledger identity changed"):
            _append(domain, "new-" + domain)
    result = boot.recover_before_import(data, backup)
    assert result["status"] == "recovered"
    assert len(result["recoveries"]) == 2
    assert backup.is_dir()
    assert len(list(backup.iterdir())) == 2
    for receipt in result["recoveries"]:
        domain = receipt["domain"]
        ledger = data / f"{domain}.jsonl"
        before, inode = originals[domain]
        assert receipt["status"] == "verified"
        assert receipt["new_ledger_device"] == ledger.stat().st_dev
        assert receipt["verified_identities"] == 1
        assert ledger.read_bytes() == before
        assert ledger.stat().st_ino == inode
        saved = Path(receipt["backup_directory"])
        assert (saved / "ledger.jsonl").read_bytes() == before
        assert json.loads((saved / "verified-recovery.json").read_text()) == receipt
        assert _read_device(data, domain) == ledger.stat().st_dev
        assert _append(domain, domain)["skipped"] == 1
    assert boot.recover_before_import(data, backup)["status"] == "steady"
    assert len(list(backup.iterdir())) == 2


def test_missing_index_is_left_to_normal_importer(locations):
    data, backup = locations
    storage.write_payload("agent.ledger", [json.dumps({"payload": {"event_id": "legacy"}})])
    assert boot.recover_before_import(data, backup)["status"] == "steady"
    assert not backup.exists()
    assert _append("agent.ledger", "new")["written"] == 1


@pytest.mark.parametrize("domain", boot.DOMAINS)
@pytest.mark.parametrize("initial_index", ["zero_byte", "empty_sqlite"])
def test_interrupted_before_schema_creation_is_normal_bootstrap(
    locations, domain, initial_index
):
    data, backup = locations
    _append(domain, "original")
    ledger = data / f"{domain}.jsonl"
    index = identity_index.index_path_for_target(ledger)
    before_ledger = ledger.read_bytes()
    if initial_index == "zero_byte":
        index.write_bytes(b"")
    else:
        index.unlink()
        with sqlite3.connect(index) as db:
            assert db.execute("SELECT name FROM sqlite_master").fetchall() == []
    index.chmod(0o600)
    before_index = index.read_bytes()

    assert boot.recover_before_import(data, backup) == {
        "schema_version": 1, "status": "steady", "recoveries": [],
    }
    assert not backup.exists()
    assert ledger.read_bytes() == before_ledger
    assert index.read_bytes() == before_index

    result = _append(domain, "after-initialization")
    assert result["written"] == 1
    assert result["identity_index_mode"] == "rebuild"
    assert _read_device(data, domain) == ledger.stat().st_dev
    assert ledger.read_bytes().startswith(before_ledger)


@pytest.mark.parametrize("foreign_schema", ["foreign_table", "foreign_version", "foreign_application"])
def test_missing_index_state_with_foreign_schema_remains_blocked(locations, foreign_schema):
    data, backup = locations
    _append("agent.ledger", "original")
    ledger = data / "agent.ledger.jsonl"
    index = identity_index.index_path_for_target(ledger)
    index.unlink()
    with sqlite3.connect(index) as db:
        if foreign_schema == "foreign_table":
            db.execute("CREATE TABLE unrelated (value TEXT)")
        elif foreign_schema == "foreign_version":
            db.execute("PRAGMA user_version=7")
        else:
            db.execute("PRAGMA application_id=7")
    index.chmod(0o600)
    before = (ledger.read_bytes(), index.read_bytes())
    with pytest.raises(identity_index_recovery.RecoveryRejected, match="foreign or partial schema"):
        boot.recover_before_import(data, backup)
    assert (ledger.read_bytes(), index.read_bytes()) == before
    assert not backup.exists()


@pytest.mark.parametrize("domain", boot.DOMAINS)
def test_valid_index_schema_without_state_is_left_to_importer(locations, domain):
    # A process can crash between committing the SQLite schema and writing
    # the initial index_state record. This is a recoverable normal bootstrap.
    data, backup = locations
    storage.write_payload(
        domain, [json.dumps({"payload": {"event_id": "original", "value": "old"}})]
    )
    target = data / f"{domain}.jsonl"
    with identity_index.open_identity_index(target, timeout=storage.LOCK_TIMEOUT) as index:
        assert index._load_state("event_id") is None
    index_path = identity_index.index_path_for_target(target)
    before = (target.read_bytes(), index_path.read_bytes())

    assert boot.recover_before_import(data, backup) == {
        "schema_version": 1, "status": "steady", "recoveries": [],
    }
    assert not backup.exists()
    assert (target.read_bytes(), index_path.read_bytes()) == before

    imported = _append(domain, "new")
    assert imported["written"] == 1
    assert imported["identity_index_mode"] == "rebuild"
    assert _read_device(data, domain) == target.stat().st_dev


@pytest.mark.parametrize("domain", boot.DOMAINS)
def test_hot_sqlite_delete_journal_is_recovered_by_normal_importer(locations, domain):
    data, backup = locations
    _append(domain, "original")
    target = data / f"{domain}.jsonl"
    index = identity_index.index_path_for_target(target)
    journal = Path(str(index) + "-journal")
    before_ledger = target.read_bytes()
    # Reproduce an actual interrupted SQLite DELETE-journal transaction:
    # the child exits without COMMIT and leaves a hot rollback journal.
    child_script = (
        "import os,sqlite3,sys\n"
        "from pathlib import Path\n"
        "db=sqlite3.connect(sys.argv[1])\n"
        "db.execute('PRAGMA cache_size=1')\n"
        "db.execute('BEGIN IMMEDIATE')\n"
        "db.execute(\"UPDATE index_state SET ledger_dev='999' WHERE identity_key='event_id'\")\n"
        "db.execute('CREATE TABLE crash_bulk (payload BLOB)')\n"
        "for _ in range(1000): db.execute('INSERT INTO crash_bulk VALUES(zeroblob(4096))')\n"
        "assert Path(sys.argv[1]+'-journal').stat().st_size>0\n"
        "os._exit(83)\n"
    )
    child = subprocess.run(
        [sys.executable, "-c", child_script, str(index)],
        capture_output=True, text=True, check=False,
    )
    assert child.returncode == 83, child.stderr
    assert journal.is_file()
    before_index = (index.read_bytes(), journal.read_bytes())

    with sqlite3.connect(index.as_uri() + "?mode=ro", uri=True) as db:
        with pytest.raises(sqlite3.OperationalError, match="readonly database"):
            db.execute("SELECT ledger_dev FROM index_state").fetchone()

    assert boot.recover_before_import(data, backup)["recoveries"] == []
    assert (index.read_bytes(), journal.read_bytes()) == before_index
    assert not backup.exists()
    assert target.read_bytes() == before_ledger

    # The unchanged importer performs SQLite's normal crash rollback before
    # synchronizing: the incomplete '999' update must not be observed.
    result = _append(domain, "after-crash")
    assert result["written"] == 1
    assert _read_device(data, domain) == target.stat().st_dev
    assert not journal.exists()
    assert target.read_bytes().startswith(before_ledger)


def test_nonrecoverable_sqlite_corruption_remains_fail_closed(locations):
    data, backup = locations
    _append("agent.ledger", "original")
    target = data / "agent.ledger.jsonl"
    index = identity_index.index_path_for_target(target)
    before_ledger = target.read_bytes()
    index.write_bytes(b"not a sqlite database")
    index.chmod(0o600)
    before_index = index.read_bytes()
    with pytest.raises(identity_index_recovery.RecoveryRejected, match="cannot be read"):
        boot.recover_before_import(data, backup)
    assert target.read_bytes() == before_ledger
    assert index.read_bytes() == before_index
    assert not backup.exists()


@pytest.mark.parametrize("mutation", ["replace_inode", "bad_state_digest", "missing_ledger_tail"])
def test_drift_with_nondevice_damage_fails_closed(locations, mutation):
    data, backup = locations
    _append("agent.ledger", "one")
    ledger = data / "agent.ledger.jsonl"
    index = identity_index.index_path_for_target(ledger)
    old_dev = _drift(data, "agent.ledger")
    if mutation == "replace_inode":
        replacement = data / "replacement"
        replacement.write_bytes(ledger.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, ledger)
    elif mutation == "bad_state_digest":
        with sqlite3.connect(index) as db:
            db.execute("UPDATE index_state SET state_digest = ? WHERE identity_key = 'event_id'",
                       (b"x" * 32,))
    else:
        with ledger.open("ab") as stream:
            stream.write(b"broken"); stream.flush(); os.fsync(stream.fileno())
    before = (ledger.read_bytes(), index.read_bytes())
    with pytest.raises((identity_index_recovery.RecoveryRejected,
                        identity_index.IdentityIndexError)):
        boot.recover_before_import(data, backup)
    assert (ledger.read_bytes(), index.read_bytes()) == before
    assert _read_device(data, "agent.ledger") == old_dev
    if backup.exists():
        assert not list(backup.iterdir())


def test_symlinked_index_fails_closed_before_backup(locations):
    data, backup = locations
    _append("agent.ledger", "one")
    ledger = data / "agent.ledger.jsonl"
    index = identity_index.index_path_for_target(ledger)
    saved = data / "stored-index"
    index.rename(saved)
    index.symlink_to(saved)
    with pytest.raises(identity_index_recovery.RecoveryRejected, match="private"):
        boot.recover_before_import(data, backup)
    assert not backup.exists()


def test_rejects_wrong_backup_location_before_any_write(locations):
    data, backup = locations
    _append("agent.ledger", "one")
    _drift(data, "agent.ledger")
    before = (data / "agent.ledger.jsonl").read_bytes()
    with pytest.raises(identity_index_recovery.RecoveryRejected, match="backup root"):
        boot.recover_before_import(data, data / "wrong-directory")
    assert (data / "agent.ledger.jsonl").read_bytes() == before
    assert not backup.exists()


def test_cli_explicit_enable_required_without_mutations(locations):
    data, backup = locations
    with pytest.raises(SystemExit) as err:
        boot.main(["--data-dir", str(data), "--backup-root", str(backup)])
    assert err.value.code == 2
    assert not backup.exists()


def test_import_unit_routes_preflight_before_normal_import():
    service = (
        Path(__file__).resolve().parents[1]
        / "deploy/systemd/user/chronik-outbox-import.service"
    ).read_text()
    assert "ExecStartPre=" in service
    assert "tools/identity_index_boot_recovery.py" in service
    assert "--backup-root %h/.local/state/chronik/manual-recovery-copies --apply" in service
    assert service.index("ExecStartPre=") < service.index("\nExecStart=")
    assert "ReadWritePaths=%h/.local/state/chronik" in service
    assert "TimeoutStartSec=180s" in service