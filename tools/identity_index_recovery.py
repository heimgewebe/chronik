"""Explicit, fail-closed device-only recovery for Chronik's derived SQLite index.

This tool never changes ledger JSONL and is deliberately NOT called by ingestion.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
from typing import BinaryIO

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import identity_index
import storage


class RecoveryRejected(RuntimeError):
    """Recovery preconditions or durable readback are not established."""


def _private_file(path: Path) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise RecoveryRejected("required source is unavailable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_nlink != 1
    ):
        raise RecoveryRejected("source file is not private, regular and single-linked")
    return info


def _private_dir(path: Path) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise RecoveryRejected("private backup root is missing or inaccessible") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RecoveryRejected("backup root must be a private real directory")


def _stat_key(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_mode,
        info.st_uid,
        info.st_nlink,
    )


def _check_unchanged(path: Path, original: os.stat_result) -> None:
    if _stat_key(_private_file(path)) != _stat_key(original):
        raise RecoveryRejected("source identity changed while preparing recovery")


def _copy_exact(source: BinaryIO, dest: Path, size: int) -> str:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    digest = hashlib.sha256()
    fd = os.open(dest, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            remaining = size
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise RecoveryRejected("source ended during backup")
                out.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            if source.read(1):
                raise RecoveryRejected("source grew during backup")
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        try:
            os.unlink(dest)
        except OSError:
            pass
        raise
    return digest.hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as inp:
        for chunk in iter(lambda: inp.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(directory: Path, filename: str, data: dict) -> Path:
    path = directory / filename
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(data, out, sort_keys=True, separators=(",", ":"))
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    identity_index._fsync_directory(directory)
    return path


def _verify_index_contents(index: identity_index.IdentityIndex, fh: BinaryIO,
                           state: identity_index.IndexState) -> int:
    check = list(index.connection.execute("PRAGMA integrity_check"))
    if check != [("ok",)]:
        raise RecoveryRejected("SQLite integrity_check failed")
    index._verify_full_prefix_contents(fh, state)
    seen: dict[str, bytes] = {}
    for start, end, raw in index._records(fh, 0, state.indexed_offset):
        try:
            event_id, canonical = storage._parse_unique_payload(raw, state.identity_key)
        except (TypeError, ValueError):
            continue  # Matches the established index's treatment of historic v0 records.
        if not event_id:
            continue
        fingerprint = storage._payload_fingerprint(canonical)
        previous = seen.get(event_id)
        if previous is not None:
            if previous != fingerprint:
                raise RecoveryRejected("conflicting duplicate identity in ledger")
            continue
        row = index._read_identity_row(state.identity_key, event_id)
        if row != (fingerprint, start, end):
            raise RecoveryRejected("identity/fingerprint/range or row digest disagrees with ledger")
        seen[event_id] = fingerprint
    if len(seen) != state.identity_count:
        raise RecoveryRejected("index contains extra/missing ledger identities")
    return len(seen)


def _copy_sources(fh: BinaryIO, ledger_path: Path, ledger_stat: os.stat_result,
                  index_path: Path, index_stat: os.stat_result,
                  backup_root: Path) -> tuple[Path, dict]:
    _private_dir(backup_root)
    directory = Path(tempfile.mkdtemp(prefix="chronik-device-recovery-", dir=backup_root))
    _private_dir(directory)
    try:
        fh.seek(0)
        ledger_hash = _copy_exact(fh, directory / "ledger.jsonl", ledger_stat.st_size)
        index_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        index_fd = os.open(index_path, index_flags)
        with os.fdopen(index_fd, "rb") as inp:
            if _stat_key(os.fstat(inp.fileno())) != _stat_key(index_stat):
                raise RecoveryRejected("index changed before backup")
            index_hash = _copy_exact(inp, directory / "identity-index.sqlite3", index_stat.st_size)
        identity_index._fsync_directory(directory)
        identity_index._fsync_directory(backup_root)
        if (
            _hash_file(directory / "ledger.jsonl") != ledger_hash
            or _hash_file(directory / "identity-index.sqlite3") != index_hash
        ):
            raise RecoveryRejected("recovery copy failed readback")
        _check_unchanged(ledger_path, ledger_stat)
        _check_unchanged(index_path, index_stat)
        if _hash_file(ledger_path) != ledger_hash or _hash_file(index_path) != index_hash:
            raise RecoveryRejected("source bytes changed during backup")
        manifest = {
            "schema_version": 1,
            "ledger_sha256": ledger_hash,
            "index_sha256": index_hash,
            "ledger_size": ledger_stat.st_size,
            "index_size": index_stat.st_size,
            "source_ledger_device": ledger_stat.st_dev,
            "source_ledger_inode": ledger_stat.st_ino,
            "source_index_device": index_stat.st_dev,
            "source_index_inode": index_stat.st_ino,
        }
        _write_json(directory, "preimage.json", manifest)
        return directory, manifest
    except BaseException:
        # Preserve any partial copies for investigation; never report a verified backup.
        raise


def recover_device_only(
    domain: str, *, backup_root: Path, expected_old_device: int,
    identity_key: str = "event_id",
) -> dict:
    """Explicitly rebind only ledger_dev after a verified and durable preimage.

    A caller must verify backup/restore policy separately. No automatic retry.
    """
    if isinstance(expected_old_device, bool) or expected_old_device < 0:
        raise RecoveryRejected("expected old device must be a nonnegative integer")
    ledger_path = storage.safe_target_path(domain)
    if not ledger_path.exists():
        raise RecoveryRejected("ledger is absent; recovery cannot create it")
    index_path = identity_index.index_path_for_target(ledger_path)
    _private_file(ledger_path)
    _private_file(index_path)
    _private_dir(backup_root)

    # Existing canonical sidecar FileLock + exclusive locked ledger fd.
    with storage._locked_open(ledger_path, "a+") as fh:
        original_ledger = storage._target_stat_for_fd(ledger_path, fh.fileno())
        _private_file(ledger_path)
        identity_index.IdentityIndex._require_complete_tail(fh, original_ledger.st_size)
        original_index = _private_file(index_path)
        with identity_index.open_identity_index(
            ledger_path, timeout=storage.LOCK_TIMEOUT
        ) as index:
            state = index._load_state(identity_key)
            if state is None:
                raise RecoveryRejected("index does not contain the expected identity state")
            if state.ledger_dev != expected_old_device:
                raise RecoveryRejected("old device CAS does not match the index")
            if state.ledger_dev == original_ledger.st_dev:
                raise RecoveryRejected("no device drift; refusing unnecessary mutation")
            if (
                state.ledger_ino != original_ledger.st_ino
                or state.ledger_mtime_ns != original_ledger.st_mtime_ns
                or state.ledger_ctime_ns != original_ledger.st_ctime_ns
                or state.indexed_offset != original_ledger.st_size
            ):
                raise RecoveryRejected("more than device identity changed")
            if state.record_count < state.identity_count:
                raise RecoveryRejected("index record/count contradiction")
            verified_identities = _verify_index_contents(index, fh, state)
            _check_unchanged(ledger_path, original_ledger)
            _check_unchanged(index_path, original_index)
            directory, preimage = _copy_sources(
                fh, ledger_path, original_ledger, index_path, original_index, backup_root
            )
            # Snapshot is durable before entering the sole mutating transaction.
            _check_unchanged(ledger_path, original_ledger)
            _check_unchanged(index_path, original_index)
            if _hash_file(ledger_path) != preimage["ledger_sha256"]:
                raise RecoveryRejected("ledger bytes changed before CAS")
            updated = replace(state, ledger_dev=original_ledger.st_dev)
            try:
                index.connection.execute("BEGIN IMMEDIATE")
                cursor = index.connection.execute(
                    """
                    UPDATE index_state
                    SET ledger_dev = ?, state_digest = ?
                    WHERE identity_key = ? AND ledger_dev = ? AND ledger_ino = ?
                      AND ledger_mtime_ns = ? AND ledger_ctime_ns = ?
                      AND indexed_offset = ? AND chain_digest = ? AND record_count = ?
                      AND identity_count = ? AND last_record_start = ?
                      AND last_record_digest = ? AND state_digest = ?
                    """,
                    (
                        str(updated.ledger_dev), identity_index._state_digest(updated),
                        state.identity_key, str(state.ledger_dev), str(state.ledger_ino),
                        str(state.ledger_mtime_ns), str(state.ledger_ctime_ns),
                        state.indexed_offset, state.chain_digest, state.record_count,
                        state.identity_count, state.last_record_start,
                        state.last_record_digest, identity_index._state_digest(state),
                    ),
                )
                if cursor.rowcount != 1:
                    raise RecoveryRejected("index CAS was not uniquely satisfied")
                index.commit()
            except BaseException:
                index.rollback()
                raise

            post = index._load_state(identity_key)
            if post != updated:
                raise RecoveryRejected("post-commit state disagrees with CAS")
            fresh_ledger = storage._target_stat_for_fd(ledger_path, fh.fileno())
            if _stat_key(fresh_ledger) != _stat_key(original_ledger):
                raise RecoveryRejected("ledger identity changed after CAS")
            index._verify_state_binding(fh, fresh_ledger, post)
            _verify_index_contents(index, fh, post)
            if _hash_file(ledger_path) != preimage["ledger_sha256"]:
                raise RecoveryRejected("ledger bytes changed during recovery")
            receipt = {
                "schema_version": 1,
                "status": "verified",
                "domain": domain,
                "identity_key": identity_key,
                "old_ledger_device": state.ledger_dev,
                "new_ledger_device": updated.ledger_dev,
                "ledger_inode": original_ledger.st_ino,
                "ledger_sha256": preimage["ledger_sha256"],
                "preimage_index_sha256": preimage["index_sha256"],
                "record_count": state.record_count,
                "verified_identities": verified_identities,
                "backup_directory": str(directory),
            }
            _write_json(directory, "verified-recovery.json", receipt)
            return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--backup-root", type=Path, required=True)
    parser.add_argument("--expected-old-device", type=int, required=True)
    parser.add_argument("--apply", action="store_true", help="explicitly authorize index metadata CAS")
    args = parser.parse_args()
    if not args.apply:
        parser.error("--apply is required; normal imports never invoke recovery")
    storage.DATA_DIR = args.data_dir.resolve(strict=True)
    try:
        receipt = recover_device_only(
            args.domain,
            backup_root=args.backup_root.resolve(strict=True),
            expected_old_device=args.expected_old_device,
        )
    except (RecoveryRejected, storage.StorageError, identity_index.IdentityIndexError,
            sqlite3.DatabaseError, OSError, ValueError) as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc)}, sort_keys=True),
              file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
