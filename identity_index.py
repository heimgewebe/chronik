"""Ledger-bound persistent identity index for Chronik JSONL storage.

The JSONL ledger remains the event authority.  This SQLite database is only a
rebuildable acceleration structure.  The writer orders effects as ledger first,
index second, so a crash can leave the index behind but can never make it claim
an event that was not durably appended to the ledger.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence

INDEX_SCHEMA_VERSION = 1
INDEX_APPLICATION_ID = 0x43485249  # "CHRI"
INDEX_DIR_NAME = ".chronik-identity-index-v1"
ZERO_DIGEST = b"\x00" * 32


class IdentityIndexError(Exception):
    """Base class for persistent identity-index failures."""


class IdentityIndexCorruptError(IdentityIndexError):
    """Raised when an existing index artifact cannot be trusted."""


class IdentityIndexDriftError(IdentityIndexError):
    """Raised when ledger identity or indexed-prefix binding has drifted."""


class IdentityIndexCommitUncertain(IdentityIndexError):
    """Raised when SQLite cannot establish the outcome of the final commit."""


@dataclass(frozen=True)
class IndexState:
    identity_key: str
    ledger_dev: int
    ledger_ino: int
    ledger_mtime_ns: int
    ledger_ctime_ns: int
    indexed_offset: int
    chain_digest: bytes
    record_count: int
    identity_count: int
    last_record_start: int
    last_record_digest: bytes


@dataclass(frozen=True)
class IndexSyncResult:
    mode: str
    records_scanned: int
    entry_count: int
    state: IndexState


PayloadParser = Callable[[str | bytes, str], tuple[str | None, bytes]]
PayloadFingerprint = Callable[[bytes], bytes]


def _digest_fields(*fields: object) -> bytes:
    digest = hashlib.sha256()
    for field in fields:
        if isinstance(field, bytes):
            encoded = field
        else:
            encoded = str(field).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big", signed=False))
        digest.update(encoded)
    return digest.digest()


def _identity_row_digest(
    identity_key: str,
    identity: str,
    fingerprint: bytes,
    record_start: int,
    record_end: int,
) -> bytes:
    return _digest_fields(
        "chronik-identity-row-v1",
        identity_key,
        identity,
        fingerprint,
        record_start,
        record_end,
    )


def _state_digest(state: IndexState) -> bytes:
    return _digest_fields(
        "chronik-identity-state-v1",
        state.identity_key,
        state.ledger_dev,
        state.ledger_ino,
        state.ledger_mtime_ns,
        state.ledger_ctime_ns,
        state.indexed_offset,
        state.chain_digest,
        state.record_count,
        state.identity_count,
        state.last_record_start,
        state.last_record_digest,
    )


def index_path_for_target(target_path: Path) -> Path:
    """Return the deterministic private SQLite path for one ledger."""
    digest = hashlib.sha256(target_path.name.encode("utf-8")).hexdigest()
    return target_path.parent / INDEX_DIR_NAME / f"{digest}.sqlite3"


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(path, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise IdentityIndexError("identity index directory sync failed") from exc


def _ensure_private_index_root(data_dir: Path) -> Path:
    root = data_dir / INDEX_DIR_NAME
    created = False
    try:
        os.mkdir(root, 0o700)
        created = True
    except FileExistsError:
        pass
    except OSError as exc:
        raise IdentityIndexError("identity index directory creation failed") from exc

    try:
        info = os.lstat(root)
    except OSError as exc:
        raise IdentityIndexError("identity index directory unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise IdentityIndexCorruptError("identity index directory is not a real directory")
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise IdentityIndexCorruptError("identity index directory is not private")
    if created:
        _fsync_directory(data_dir)
    return root


def reset_identity_index_for_authoritative_replay(target_path: Path) -> bool:
    """Remove only the derived index before a proven full-source ledger replay.

    The caller must hold the ledger writer lock and must separately prove that
    the opened ledger is empty.  This function never removes or rewrites ledger
    bytes and rejects unsafe index paths instead of following them.
    """
    root = target_path.parent / INDEX_DIR_NAME
    try:
        root_info = os.lstat(root)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise IdentityIndexError("identity index directory unavailable") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise IdentityIndexCorruptError("identity index directory is not a real directory")
    if root_info.st_uid != os.geteuid() or root_info.st_mode & 0o077:
        raise IdentityIndexCorruptError("identity index directory is not private")

    database = index_path_for_target(target_path)
    removed = False
    for candidate in (
        database,
        Path(str(database) + "-journal"),
        Path(str(database) + "-wal"),
        Path(str(database) + "-shm"),
    ):
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise IdentityIndexError("identity index artifact unavailable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise IdentityIndexCorruptError("identity index artifact is not a regular file")
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise IdentityIndexCorruptError("identity index artifact is not private")
        try:
            os.unlink(candidate)
        except OSError as exc:
            raise IdentityIndexError("identity index reset failed") from exc
        removed = True
    if removed:
        _fsync_directory(root)
    return removed


def _validate_existing_database_path(path: Path) -> os.stat_result | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise IdentityIndexError("identity index metadata unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise IdentityIndexCorruptError("identity index is not a regular file")
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise IdentityIndexCorruptError("identity index file is not private")
    return info


def _table_columns(connection: sqlite3.Connection, table: str) -> list[tuple[str, str, int]]:
    rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
    return [(str(row[1]), str(row[2]).upper(), int(row[5])) for row in rows]


class IdentityIndex:
    """One securely validated SQLite acceleration database."""

    def __init__(self, target_path: Path, *, timeout: int) -> None:
        self.target_path = target_path
        self.root = _ensure_private_index_root(target_path.parent)
        self.path = index_path_for_target(target_path)
        before = _validate_existing_database_path(self.path)
        existed = before is not None
        try:
            self.connection = sqlite3.connect(
                self.path,
                timeout=max(1, timeout),
                isolation_level=None,
            )
        except sqlite3.DatabaseError as exc:
            raise IdentityIndexCorruptError("identity index cannot be opened") from exc
        except OSError as exc:
            raise IdentityIndexError("identity index cannot be opened") from exc

        try:
            if not existed:
                os.chmod(self.path, 0o600)
            after = _validate_existing_database_path(self.path)
            if after is None:
                raise IdentityIndexCorruptError("identity index disappeared after open")
            if before is not None and (before.st_dev, before.st_ino) != (
                after.st_dev,
                after.st_ino,
            ):
                raise IdentityIndexCorruptError("identity index identity changed during open")
            self._configure()
            self._initialize_or_validate_schema()
            if not existed:
                _fsync_directory(self.root)
        except BaseException:
            self.connection.close()
            raise

    def _configure(self) -> None:
        try:
            mode = self.connection.execute("PRAGMA journal_mode=DELETE").fetchone()
            if not mode or str(mode[0]).lower() != "delete":
                raise IdentityIndexCorruptError("identity index journal mode is unsafe")
            self.connection.execute("PRAGMA synchronous=FULL")
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute("PRAGMA trusted_schema=OFF")
            self.connection.execute("PRAGMA busy_timeout=30000")
        except sqlite3.DatabaseError as exc:
            raise IdentityIndexCorruptError("identity index configuration failed") from exc

    def _initialize_or_validate_schema(self) -> None:
        try:
            user_version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
            application_id = int(
                self.connection.execute("PRAGMA application_id").fetchone()[0]
            )
            tables = {
                str(row[0])
                for row in self.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
                if not str(row[0]).startswith("sqlite_")
            }
            if user_version == 0 and application_id == 0 and not tables:
                self.connection.execute("BEGIN IMMEDIATE")
                try:
                    self.connection.execute(
                        """
                        CREATE TABLE identities (
                            identity_key TEXT NOT NULL,
                            identity TEXT NOT NULL,
                            fingerprint BLOB NOT NULL CHECK(length(fingerprint) = 40),
                            record_start INTEGER NOT NULL CHECK(record_start >= 0),
                            record_end INTEGER NOT NULL CHECK(record_end > record_start),
                            row_digest BLOB NOT NULL CHECK(length(row_digest) = 32),
                            PRIMARY KEY(identity_key, identity)
                        ) WITHOUT ROWID
                        """
                    )
                    self.connection.execute(
                        """
                        CREATE TABLE identity_counts (
                            identity_key TEXT PRIMARY KEY,
                            entry_count INTEGER NOT NULL CHECK(entry_count >= 0)
                        ) WITHOUT ROWID
                        """
                    )
                    self.connection.execute(
                        """
                        CREATE TRIGGER identities_count_insert
                        AFTER INSERT ON identities
                        BEGIN
                            INSERT INTO identity_counts(identity_key, entry_count)
                            VALUES (NEW.identity_key, 1)
                            ON CONFLICT(identity_key) DO UPDATE SET
                                entry_count = entry_count + 1;
                        END
                        """
                    )
                    self.connection.execute(
                        """
                        CREATE TRIGGER identities_count_delete
                        AFTER DELETE ON identities
                        BEGIN
                            UPDATE identity_counts
                            SET entry_count = entry_count - 1
                            WHERE identity_key = OLD.identity_key;
                        END
                        """
                    )
                    self.connection.execute(
                        """
                        CREATE TABLE index_state (
                            identity_key TEXT PRIMARY KEY,
                            ledger_dev TEXT NOT NULL,
                            ledger_ino TEXT NOT NULL,
                            ledger_mtime_ns TEXT NOT NULL,
                            ledger_ctime_ns TEXT NOT NULL,
                            indexed_offset INTEGER NOT NULL CHECK(indexed_offset >= 0),
                            chain_digest BLOB NOT NULL CHECK(length(chain_digest) = 32),
                            record_count INTEGER NOT NULL CHECK(record_count >= 0),
                            identity_count INTEGER NOT NULL CHECK(identity_count >= 0),
                            last_record_start INTEGER NOT NULL,
                            last_record_digest BLOB NOT NULL CHECK(length(last_record_digest) = 32),
                            state_digest BLOB NOT NULL CHECK(length(state_digest) = 32)
                        ) WITHOUT ROWID
                        """
                    )
                    self.connection.execute(
                        f"PRAGMA application_id={INDEX_APPLICATION_ID}"
                    )
                    self.connection.execute(
                        f"PRAGMA user_version={INDEX_SCHEMA_VERSION}"
                    )
                    self.connection.commit()
                except BaseException:
                    self.connection.rollback()
                    raise
                user_version = INDEX_SCHEMA_VERSION
                application_id = INDEX_APPLICATION_ID
                tables = {"identities", "identity_counts", "index_state"}

            triggers = {
                str(row[0])
                for row in self.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                )
            }
            if user_version != INDEX_SCHEMA_VERSION:
                raise IdentityIndexCorruptError("identity index schema version mismatch")
            if application_id != INDEX_APPLICATION_ID:
                raise IdentityIndexCorruptError("identity index application id mismatch")
            if tables != {"identities", "identity_counts", "index_state"}:
                raise IdentityIndexCorruptError("identity index schema tables mismatch")
            if triggers != {"identities_count_insert", "identities_count_delete"}:
                raise IdentityIndexCorruptError("identity index schema triggers mismatch")
            if _table_columns(self.connection, "identities") != [
                ("identity_key", "TEXT", 1),
                ("identity", "TEXT", 2),
                ("fingerprint", "BLOB", 0),
                ("record_start", "INTEGER", 0),
                ("record_end", "INTEGER", 0),
                ("row_digest", "BLOB", 0),
            ]:
                raise IdentityIndexCorruptError("identity table schema mismatch")
            if _table_columns(self.connection, "identity_counts") != [
                ("identity_key", "TEXT", 1),
                ("entry_count", "INTEGER", 0),
            ]:
                raise IdentityIndexCorruptError("identity count schema mismatch")
            if _table_columns(self.connection, "index_state") != [
                ("identity_key", "TEXT", 1),
                ("ledger_dev", "TEXT", 0),
                ("ledger_ino", "TEXT", 0),
                ("ledger_mtime_ns", "TEXT", 0),
                ("ledger_ctime_ns", "TEXT", 0),
                ("indexed_offset", "INTEGER", 0),
                ("chain_digest", "BLOB", 0),
                ("record_count", "INTEGER", 0),
                ("identity_count", "INTEGER", 0),
                ("last_record_start", "INTEGER", 0),
                ("last_record_digest", "BLOB", 0),
                ("state_digest", "BLOB", 0),
            ]:
                raise IdentityIndexCorruptError("identity index state schema mismatch")
        except sqlite3.DatabaseError as exc:
            raise IdentityIndexCorruptError("identity index schema is unreadable") from exc

    def close(self) -> None:
        self.connection.close()

    def _identity_count(self, identity_key: str) -> int:
        try:
            row = self.connection.execute(
                "SELECT entry_count FROM identity_counts WHERE identity_key = ?",
                (identity_key,),
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise IdentityIndexCorruptError("identity index count cannot be read") from exc
        if row is None:
            return 0
        try:
            value = int(row[0])
        except (TypeError, ValueError, OverflowError) as exc:
            raise IdentityIndexCorruptError("identity index count is invalid") from exc
        if value < 0:
            raise IdentityIndexCorruptError("identity index count is negative")
        return value

    def _read_identity_row(
        self, identity_key: str, identity: str
    ) -> tuple[bytes, int, int] | None:
        try:
            row = self.connection.execute(
                """
                SELECT fingerprint, record_start, record_end, row_digest
                FROM identities WHERE identity_key = ? AND identity = ?
                """,
                (identity_key, identity),
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise IdentityIndexCorruptError("identity index row cannot be read") from exc
        if row is None:
            return None
        try:
            fingerprint = bytes(row[0])
            record_start = int(row[1])
            record_end = int(row[2])
            row_digest = bytes(row[3])
        except (TypeError, ValueError, OverflowError) as exc:
            raise IdentityIndexCorruptError("identity index row has invalid values") from exc
        if (
            len(fingerprint) != 40
            or record_start < 0
            or record_end <= record_start
            or len(row_digest) != 32
            or row_digest
            != _identity_row_digest(
                identity_key,
                identity,
                fingerprint,
                record_start,
                record_end,
            )
        ):
            raise IdentityIndexCorruptError("identity index row digest mismatch")
        return fingerprint, record_start, record_end

    def _insert_identity(
        self,
        *,
        identity_key: str,
        identity: str,
        fingerprint: bytes,
        record_start: int,
        record_end: int,
    ) -> None:
        try:
            self.connection.execute(
                """
                INSERT INTO identities(
                    identity_key, identity, fingerprint,
                    record_start, record_end, row_digest
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    identity_key,
                    identity,
                    fingerprint,
                    record_start,
                    record_end,
                    _identity_row_digest(
                        identity_key,
                        identity,
                        fingerprint,
                        record_start,
                        record_end,
                    ),
                ),
            )
        except sqlite3.DatabaseError as exc:
            raise IdentityIndexCorruptError("identity index row insert failed") from exc

    def _verify_identity_against_ledger(
        self,
        fh,
        *,
        state: IndexState,
        identity_key: str,
        identity: str,
        row: tuple[bytes, int, int],
        parse_payload: PayloadParser,
        fingerprint_payload: PayloadFingerprint,
    ) -> bytes:
        fingerprint, record_start, record_end = row
        if record_end > state.indexed_offset:
            raise IdentityIndexCorruptError("identity index row exceeds indexed ledger")
        fh.seek(record_start)
        raw = fh.read(record_end - record_start)
        if len(raw) != record_end - record_start or not raw.endswith(b"\n"):
            raise IdentityIndexCorruptError("identity index ledger range is incomplete")
        try:
            observed_identity, canonical_payload = parse_payload(raw, identity_key)
        except (TypeError, ValueError) as exc:
            raise IdentityIndexCorruptError(
                "identity index row references an invalid ledger record"
            ) from exc
        if observed_identity != identity:
            raise IdentityIndexCorruptError("identity index row identity mismatch")
        if fingerprint_payload(canonical_payload) != fingerprint:
            raise IdentityIndexCorruptError("identity index row fingerprint mismatch")
        return fingerprint

    def _load_state(self, identity_key: str) -> IndexState | None:
        try:
            row = self.connection.execute(
                """
                SELECT ledger_dev, ledger_ino, ledger_mtime_ns, ledger_ctime_ns,
                       indexed_offset, chain_digest, record_count, identity_count,
                       last_record_start, last_record_digest, state_digest
                FROM index_state WHERE identity_key = ?
                """,
                (identity_key,),
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise IdentityIndexCorruptError("identity index state cannot be read") from exc
        if row is None:
            return None
        try:
            state = IndexState(
                identity_key=identity_key,
                ledger_dev=int(row[0]),
                ledger_ino=int(row[1]),
                ledger_mtime_ns=int(row[2]),
                ledger_ctime_ns=int(row[3]),
                indexed_offset=int(row[4]),
                chain_digest=bytes(row[5]),
                record_count=int(row[6]),
                identity_count=int(row[7]),
                last_record_start=int(row[8]),
                last_record_digest=bytes(row[9]),
            )
            stored_digest = bytes(row[10])
        except (TypeError, ValueError, OverflowError) as exc:
            raise IdentityIndexCorruptError("identity index state has invalid values") from exc
        if (
            state.indexed_offset < 0
            or state.record_count < 0
            or state.identity_count < 0
            or state.identity_count > state.record_count
            or len(state.chain_digest) != 32
            or len(state.last_record_digest) != 32
            or len(stored_digest) != 32
            or stored_digest != _state_digest(state)
            or (state.indexed_offset == 0 and state.last_record_start != -1)
            or (
                state.indexed_offset > 0
                and not 0 <= state.last_record_start < state.indexed_offset
            )
        ):
            raise IdentityIndexCorruptError("identity index state digest mismatch")
        if self._identity_count(identity_key) != state.identity_count:
            raise IdentityIndexCorruptError("identity index count binding mismatch")
        return state

    @staticmethod
    def _ledger_stat(fh) -> os.stat_result:
        try:
            info = os.fstat(fh.fileno())
        except OSError as exc:
            raise IdentityIndexDriftError("ledger stat unavailable") from exc
        if not stat.S_ISREG(info.st_mode):
            raise IdentityIndexDriftError("ledger is not a regular file")
        return info

    @staticmethod
    def _require_complete_tail(fh, size: int) -> None:
        if size == 0:
            return
        fh.seek(size - 1)
        if fh.read(1) != b"\n":
            raise IdentityIndexDriftError("ledger has an incomplete final record")

    @staticmethod
    def _verify_state_binding(
        fh, ledger: os.stat_result, state: IndexState
    ) -> bool:
        if (state.ledger_dev, state.ledger_ino) != (ledger.st_dev, ledger.st_ino):
            raise IdentityIndexDriftError("ledger identity changed")
        if state.indexed_offset > ledger.st_size:
            raise IdentityIndexDriftError("ledger was truncated behind the index")
        metadata_changed = state.indexed_offset == ledger.st_size and (
            state.ledger_mtime_ns != ledger.st_mtime_ns
            or state.ledger_ctime_ns != ledger.st_ctime_ns
        )
        if state.indexed_offset == 0:
            if state.record_count != 0 or state.last_record_digest != ZERO_DIGEST:
                raise IdentityIndexCorruptError("empty index state is inconsistent")
            return metadata_changed
        fh.seek(state.indexed_offset - 1)
        if fh.read(1) != b"\n":
            raise IdentityIndexDriftError("indexed offset is not a record boundary")
        fh.seek(state.last_record_start)
        raw = fh.read(state.indexed_offset - state.last_record_start)
        if not raw.endswith(b"\n") or hashlib.sha256(raw).digest() != state.last_record_digest:
            raise IdentityIndexDriftError("indexed ledger boundary digest changed")
        return metadata_changed

    @staticmethod
    def _records(fh, start: int, end: int) -> Iterator[tuple[int, int, bytes]]:
        fh.seek(start)
        while fh.tell() < end:
            record_start = fh.tell()
            raw = fh.readline(end - record_start)
            if not raw or not raw.endswith(b"\n"):
                raise IdentityIndexDriftError("ledger contains an incomplete record")
            record_end = fh.tell()
            if record_end > end:
                raise IdentityIndexDriftError("ledger record crossed snapshot boundary")
            yield record_start, record_end, raw
        if fh.tell() != end:
            raise IdentityIndexDriftError("ledger snapshot boundary is inconsistent")

    def _apply_records(
        self,
        fh,
        *,
        identity_key: str,
        start: int,
        end: int,
        chain_digest: bytes,
        record_count: int,
        last_record_start: int,
        last_record_digest: bytes,
        parse_payload: PayloadParser,
        fingerprint_payload: PayloadFingerprint,
    ) -> tuple[bytes, int, int, bytes, int]:
        scanned = 0
        chain = chain_digest
        last_start = last_record_start
        last_digest = last_record_digest
        for record_start, record_end, raw in self._records(fh, start, end):
            scanned += 1
            chain = hashlib.sha256(chain + raw).digest()
            last_start = record_start
            last_digest = hashlib.sha256(raw).digest()
            try:
                identity, canonical_payload = parse_payload(raw, identity_key)
            except (TypeError, ValueError):
                continue
            if not identity:
                continue
            fingerprint = fingerprint_payload(canonical_payload)
            row = self._read_identity_row(identity_key, identity)
            if row is None:
                self._insert_identity(
                    identity_key=identity_key,
                    identity=identity,
                    fingerprint=fingerprint,
                    record_start=record_start,
                    record_end=record_end,
                )
            elif row[0] != fingerprint:
                raise IdentityIndexDriftError(
                    f"conflicting {identity_key}: {identity}"
                )
        return chain, record_count + scanned, last_start, last_digest, scanned

    def _store_state(self, state: IndexState) -> None:
        try:
            self.connection.execute(
                """
                INSERT INTO index_state(
                    identity_key, ledger_dev, ledger_ino,
                    ledger_mtime_ns, ledger_ctime_ns, indexed_offset,
                    chain_digest, record_count, identity_count,
                    last_record_start, last_record_digest, state_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(identity_key) DO UPDATE SET
                    ledger_dev=excluded.ledger_dev,
                    ledger_ino=excluded.ledger_ino,
                    ledger_mtime_ns=excluded.ledger_mtime_ns,
                    ledger_ctime_ns=excluded.ledger_ctime_ns,
                    indexed_offset=excluded.indexed_offset,
                    chain_digest=excluded.chain_digest,
                    record_count=excluded.record_count,
                    identity_count=excluded.identity_count,
                    last_record_start=excluded.last_record_start,
                    last_record_digest=excluded.last_record_digest,
                    state_digest=excluded.state_digest
                """,
                (
                    state.identity_key,
                    str(state.ledger_dev),
                    str(state.ledger_ino),
                    str(state.ledger_mtime_ns),
                    str(state.ledger_ctime_ns),
                    state.indexed_offset,
                    state.chain_digest,
                    state.record_count,
                    state.identity_count,
                    state.last_record_start,
                    state.last_record_digest,
                    _state_digest(state),
                ),
            )
        except sqlite3.DatabaseError as exc:
            raise IdentityIndexCorruptError("identity index state update failed") from exc

    def synchronize(
        self,
        fh,
        *,
        identity_key: str,
        parse_payload: PayloadParser,
        fingerprint_payload: PayloadFingerprint,
    ) -> IndexSyncResult:
        ledger = self._ledger_stat(fh)
        self._require_complete_tail(fh, ledger.st_size)
        state = self._load_state(identity_key)
        mode = "steady"
        start = ledger.st_size
        if state is None:
            mode = "rebuild"
            start = 0
            state = IndexState(
                identity_key=identity_key,
                ledger_dev=ledger.st_dev,
                ledger_ino=ledger.st_ino,
                ledger_mtime_ns=ledger.st_mtime_ns,
                ledger_ctime_ns=ledger.st_ctime_ns,
                indexed_offset=0,
                chain_digest=ZERO_DIGEST,
                record_count=0,
                identity_count=0,
                last_record_start=-1,
                last_record_digest=ZERO_DIGEST,
            )
        else:
            metadata_changed = self._verify_state_binding(fh, ledger, state)
            start = state.indexed_offset
            if start < ledger.st_size:
                mode = "verify-catchup"
            elif metadata_changed:
                mode = "verify"

        scanned = 0
        if mode != "steady":
            try:
                if mode == "verify":
                    scanned = self._verify_full_prefix_contents(fh, state)
                    chain = state.chain_digest
                    record_count = state.record_count
                    last_start = state.last_record_start
                    last_digest = state.last_record_digest
                else:
                    prefix_scanned = 0
                    if mode == "verify-catchup":
                        prefix_scanned = self._verify_full_prefix_contents(fh, state)
                    self.connection.execute("BEGIN IMMEDIATE")
                    if mode == "rebuild":
                        self.connection.execute(
                            "DELETE FROM identities WHERE identity_key = ?", (identity_key,)
                        )
                    chain, record_count, last_start, last_digest, tail_scanned = self._apply_records(
                        fh,
                        identity_key=identity_key,
                        start=start,
                        end=ledger.st_size,
                        chain_digest=state.chain_digest,
                        record_count=state.record_count,
                        last_record_start=state.last_record_start,
                        last_record_digest=state.last_record_digest,
                        parse_payload=parse_payload,
                        fingerprint_payload=fingerprint_payload,
                    )
                    scanned = prefix_scanned + tail_scanned
                identity_count = self._identity_count(identity_key)
                if not self.connection.in_transaction:
                    self.connection.execute("BEGIN IMMEDIATE")
                state = IndexState(
                    identity_key=identity_key,
                    ledger_dev=ledger.st_dev,
                    ledger_ino=ledger.st_ino,
                    ledger_mtime_ns=ledger.st_mtime_ns,
                    ledger_ctime_ns=ledger.st_ctime_ns,
                    indexed_offset=ledger.st_size,
                    chain_digest=chain,
                    record_count=record_count,
                    identity_count=identity_count,
                    last_record_start=last_start,
                    last_record_digest=last_digest,
                )
                self._store_state(state)
                self.commit()
            except IdentityIndexError:
                self.connection.rollback()
                raise
            except sqlite3.DatabaseError as exc:
                self.connection.rollback()
                raise IdentityIndexCorruptError("identity index synchronization failed") from exc
            except BaseException:
                self.connection.rollback()
                raise

        fh.seek(0, os.SEEK_END)
        return IndexSyncResult(
            mode=mode,
            records_scanned=scanned,
            entry_count=state.identity_count,
            state=state,
        )

    def _verify_full_prefix_contents(self, fh, state: IndexState) -> int:
        chain = ZERO_DIGEST
        records = 0
        last_start = -1
        last_digest = ZERO_DIGEST
        for record_start, _, raw in self._records(fh, 0, state.indexed_offset):
            records += 1
            chain = hashlib.sha256(chain + raw).digest()
            last_start = record_start
            last_digest = hashlib.sha256(raw).digest()
        if (
            chain != state.chain_digest
            or records != state.record_count
            or last_start != state.last_record_start
            or last_digest != state.last_record_digest
        ):
            raise IdentityIndexDriftError("ledger prefix verification failed")
        fh.seek(0, os.SEEK_END)
        return records

    def verify_full_prefix(self, fh, state: IndexState) -> None:
        """Explicitly verify the complete ledger prefix against the stored chain."""
        ledger = self._ledger_stat(fh)
        self._verify_state_binding(fh, ledger, state)
        self._verify_full_prefix_contents(fh, state)

    def lookup(
        self,
        fh,
        *,
        state: IndexState,
        identity_key: str,
        identities: Iterable[str],
        parse_payload: PayloadParser,
        fingerprint_payload: PayloadFingerprint,
    ) -> dict[str, bytes]:
        unique = list(dict.fromkeys(identities))
        found: dict[str, bytes] = {}
        try:
            for offset in range(0, len(unique), 500):
                chunk = unique[offset : offset + 500]
                if not chunk:
                    continue
                placeholders = ",".join("?" for _ in chunk)
                rows = self.connection.execute(
                    f"SELECT identity, fingerprint, record_start, record_end, row_digest "
                    f"FROM identities WHERE identity_key = ? "
                    f"AND identity IN ({placeholders})",
                    (identity_key, *chunk),
                )
                for identity_value, fingerprint_value, start_value, end_value, digest_value in rows:
                    identity = str(identity_value)
                    try:
                        fingerprint = bytes(fingerprint_value)
                        record_start = int(start_value)
                        record_end = int(end_value)
                        row_digest = bytes(digest_value)
                    except (TypeError, ValueError, OverflowError) as exc:
                        raise IdentityIndexCorruptError(
                            "identity index row has invalid values"
                        ) from exc
                    if (
                        len(fingerprint) != 40
                        or record_start < 0
                        or record_end <= record_start
                        or len(row_digest) != 32
                        or row_digest
                        != _identity_row_digest(
                            identity_key,
                            identity,
                            fingerprint,
                            record_start,
                            record_end,
                        )
                    ):
                        raise IdentityIndexCorruptError(
                            "identity index row digest mismatch"
                        )
                    found[identity] = self._verify_identity_against_ledger(
                        fh,
                        state=state,
                        identity_key=identity_key,
                        identity=identity,
                        row=(fingerprint, record_start, record_end),
                        parse_payload=parse_payload,
                        fingerprint_payload=fingerprint_payload,
                    )
        except IdentityIndexError:
            raise
        except sqlite3.DatabaseError as exc:
            raise IdentityIndexCorruptError("identity index lookup failed") from exc
        finally:
            fh.seek(0, os.SEEK_END)
        return found

    def begin_append(self) -> None:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
        except sqlite3.DatabaseError as exc:
            raise IdentityIndexError("identity index append transaction failed") from exc

    def stage_append(
        self,
        *,
        state: IndexState,
        ledger_stat: os.stat_result,
        identity_key: str,
        rows: Sequence[tuple[str, bytes]],
        raw_records: Sequence[bytes],
    ) -> IndexState:
        if (ledger_stat.st_dev, ledger_stat.st_ino) != (
            state.ledger_dev,
            state.ledger_ino,
        ):
            raise IdentityIndexDriftError("ledger identity changed during append")
        expected_size = state.indexed_offset + sum(len(raw) for raw in raw_records)
        if ledger_stat.st_size != expected_size:
            raise IdentityIndexDriftError("ledger append size does not match index plan")
        if len(rows) != len(raw_records):
            raise IdentityIndexDriftError("identity index append plan length mismatch")
        chain = state.chain_digest
        last_start = state.last_record_start
        last_digest = state.last_record_digest
        cursor = state.indexed_offset
        for (identity, fingerprint), raw in zip(rows, raw_records):
            if not raw.endswith(b"\n"):
                raise IdentityIndexDriftError("planned ledger record is incomplete")
            record_start = cursor
            record_end = cursor + len(raw)
            existing = self._read_identity_row(identity_key, identity)
            if existing is None:
                self._insert_identity(
                    identity_key=identity_key,
                    identity=identity,
                    fingerprint=fingerprint,
                    record_start=record_start,
                    record_end=record_end,
                )
            elif existing[0] != fingerprint:
                raise IdentityIndexDriftError(
                    f"conflicting {identity_key}: {identity}"
                )
            chain = hashlib.sha256(chain + raw).digest()
            last_start = record_start
            last_digest = hashlib.sha256(raw).digest()
            cursor = record_end
        identity_count = self._identity_count(identity_key)
        next_state = IndexState(
            identity_key=identity_key,
            ledger_dev=ledger_stat.st_dev,
            ledger_ino=ledger_stat.st_ino,
            ledger_mtime_ns=ledger_stat.st_mtime_ns,
            ledger_ctime_ns=ledger_stat.st_ctime_ns,
            indexed_offset=ledger_stat.st_size,
            chain_digest=chain,
            record_count=state.record_count + len(raw_records),
            identity_count=identity_count,
            last_record_start=last_start,
            last_record_digest=last_digest,
        )
        self._store_state(next_state)
        return next_state

    def rollback(self) -> None:
        try:
            if self.connection.in_transaction:
                self.connection.rollback()
        except sqlite3.DatabaseError as exc:
            raise IdentityIndexCommitUncertain("identity index rollback failed") from exc

    def commit(self) -> None:
        try:
            self.connection.commit()
            _fsync_directory(self.root)
        except (sqlite3.DatabaseError, IdentityIndexError) as exc:
            raise IdentityIndexCommitUncertain(
                "identity index commit outcome is uncertain"
            ) from exc


@contextmanager
def open_identity_index(target_path: Path, *, timeout: int) -> Iterator[IdentityIndex]:
    index = IdentityIndex(target_path, timeout=timeout)
    try:
        yield index
    finally:
        index.close()
