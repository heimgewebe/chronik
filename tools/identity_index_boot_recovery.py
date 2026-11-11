#!/usr/bin/env python3
"""Bounded pre-import repair for a Linux st_dev renumbering after reboot.

The normal index and importer remain fail-closed. Only the explicit PR #311
backup/ledger/SQLite verification and CAS path may change a derived index.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import identity_index  # noqa: E402
import storage  # noqa: E402
from tools import identity_index_recovery  # noqa: E402


DOMAINS = ("agent.ledger", "knowledge.ledger")


def _stored_device_readonly(index_path: Path) -> int | None:
    try:
        os.lstat(index_path)
    except FileNotFoundError:
        return None  # A truly missing index is rebuilt by ordinary import.
    identity_index_recovery._private_file(index_path)
    try:
        with sqlite3.connect(index_path.as_uri() + "?mode=ro", uri=True) as db:
            db.execute("PRAGMA query_only=ON")
            try:
                row = db.execute(
                    "SELECT ledger_dev FROM index_state WHERE identity_key = ?",
                    ("event_id",),
                ).fetchone()
            except sqlite3.OperationalError as exc:
                if str(exc).strip().lower() != "no such table: index_state":
                    raise
                # SQLite created the file but the very first schema transaction
                # never committed. Only an uninitialized, otherwise empty
                # database may be initialized by the ordinary importer.
                objects = db.execute(
                    "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
                ).fetchall()
                version = db.execute("PRAGMA user_version").fetchone()
                application = db.execute("PRAGMA application_id").fetchone()
                if objects or version != (0,) or application != (0,):
                    raise identity_index_recovery.RecoveryRejected(
                        "existing identity index has foreign or partial schema"
                    ) from exc
                return None
    except sqlite3.OperationalError as exc:
        if str(exc).strip().lower() == "attempt to write a readonly database":
            # A hot SQLite DELETE journal requires its normal writable rollback.
            # The unchanged importer owns that crash-recovery path.
            return None
        raise identity_index_recovery.RecoveryRejected(
            "existing identity index state cannot be read without mutation"
        ) from exc
    except sqlite3.DatabaseError as exc:
        raise identity_index_recovery.RecoveryRejected(
            "existing identity index state cannot be read without mutation"
        ) from exc
    if row is None:
        # An interrupted first import can leave a valid SQLite schema
        # without its first index_state row. Normal synchronize() rebuilds it.
        return None
    if not isinstance(row[0], str) or not row[0].isdigit():
        raise identity_index_recovery.RecoveryRejected(
            "existing identity index has no canonical device identity"
        )
    return int(row[0])


def _ensure_private_backup_root(backup_root: Path) -> None:
    # No parent creation or symlink traversal: only the already private
    # Chronik state directory is authorized to contain these preimages.
    identity_index_recovery._private_dir(backup_root.parent)
    try:
        backup_root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    identity_index_recovery._private_dir(backup_root)
    identity_index._fsync_directory(backup_root.parent)


def recover_before_import(data_dir: Path, backup_root: Path) -> dict:
    if not os.path.lexists(data_dir):
        # A pristine installation has no ledger/index identity to repair.
        # The normal importer, not this recovery preflight, owns bootstrap.
        return {"schema_version": 1, "status": "not_initialized", "recoveries": []}
    data_dir = data_dir.resolve(strict=True)
    if backup_root != data_dir.parent / "manual-recovery-copies":
        raise identity_index_recovery.RecoveryRejected(
            "backup root must be the private Chronik manual-recovery-copies directory"
        )
    storage.DATA_DIR = data_dir
    recovered: list[dict] = []
    for domain in DOMAINS:
        ledger_path = storage.safe_target_path(domain)
        try:
            os.lstat(ledger_path)
        except FileNotFoundError:
            continue  # Importer still owns creation/reconstruction rules.
        identity_index_recovery._private_file(ledger_path)
        index_path = identity_index.index_path_for_target(ledger_path)
        stored_device = _stored_device_readonly(index_path)
        if stored_device is None:
            continue
        current_device = ledger_path.stat().st_dev
        if stored_device == current_device:
            continue  # Normal steady state: zero backup and zero index write.
        _ensure_private_backup_root(backup_root)
        # Full prefix chain, every event fingerprint/offset, inode and every
        # other metadata, fsynced preimage, and an exact metadata-only CAS.
        receipt = identity_index_recovery.recover_device_only(
            domain, backup_root=backup_root, expected_old_device=stored_device
        )
        if receipt.get("status") != "verified":
            raise identity_index_recovery.RecoveryRejected(
                "device-only recovery did not return a verified receipt"
            )
        recovered.append(receipt)
    return {"schema_version": 1, "status": "recovered" if recovered else "steady", "recoveries": recovered}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--backup-root", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    if not args.apply:
        parser.error("--apply is required; this is an explicitly enabled service preflight")
    try:
        result = recover_before_import(args.data_dir, args.backup_root)
    except (
        identity_index_recovery.RecoveryRejected,
        identity_index.IdentityIndexError,
        storage.StorageError,
        sqlite3.DatabaseError,
        OSError,
        ValueError,
    ) as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    if result["recoveries"]:
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())