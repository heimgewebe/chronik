"""Local, idempotent coding-history import and evidence-bound queries."""
from __future__ import annotations

import fcntl
import hashlib
import heapq
import json
import os
import stat
import tempfile
import time
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable

from jsonschema import Draft7Validator

import storage
from canonical_ingest import build_envelope

DOMAIN = "agent.ledger"
SCHEMA_PATH = Path(__file__).resolve().parent / "docs" / "chronik" / "agent-run-event-v0.schema.json"
DOES_NOT_ESTABLISH = ["current_git_state", "current_ci_state", "current_runtime_state", "safe_retry"]
GRABOWSKI_SOURCE_REPO = "heimgewebe/grabowski"
GRABOWSKI_COMPONENT = "grabowski"
HIGH_VALUE_KINDS = frozenset({"agent.run.started", "agent.run.completed", "agent.run.blocked"})
OPERATIONS = frozenset({"implement", "review", "merge", "deploy", "runtime_verify", "recovery", "other"})
TASK_CLASSES = frozenset({"coding", "review", "merge", "deploy", "runtime_verify", "recovery", "maintenance", "diagnostic", "other"})
OUTCOMES = frozenset({"started", "completed", "blocked", "failed", "reverted", "outcome_unknown"})
MAX_INTEGRITY_DIAGNOSTICS = 20
HISTORY_VALIDATION_CHECKPOINT_FILENAME = ".history-validation-prefix.v1.json"
HISTORY_VALIDATION_CHECKPOINT_SCHEMA = "chronik-history-validation-prefix.v1"
HISTORY_VALIDATION_CONTRACT = "agent-run-event-v0+utc-timestamp-v1"
GRABOWSKI_TERMINAL_KINDS = frozenset({"agent.run.completed", "agent.run.blocked"})
GRABOWSKI_BUNDLE_DIRNAME = "bundles"
GRABOWSKI_BUNDLE_ENTRY_SCHEMA = "chronik-grabowski-outbox-bundle-source.v1"
GRABOWSKI_BUNDLE_MANIFEST_SCHEMA = "chronik-grabowski-outbox-bundle-manifest.v1"
GRABOWSKI_ARCHIVE_INDEX_FILENAME = "archive-index.v1.json"
GRABOWSKI_ARCHIVE_INDEX_SCHEMA = "chronik-grabowski-outbox-archive-index.v1"
GRABOWSKI_WRITER_COMPACTION_LOCK_FILENAME = ".writer-compaction.lock"
GRABOWSKI_SOURCE_INDEX_FILENAME = "source-index.v1.json"
GRABOWSKI_SOURCE_INDEX_SCHEMA = "chronik-grabowski-source-index.v1"
GRABOWSKI_DELTA_INDEX_FILENAME = "delta-source-index.v1.json"
GRABOWSKI_DELTA_INDEX_SCHEMA = "chronik-grabowski-delta-source-index.v1"
GRABOWSKI_DELTA_OVERLAY_FILENAME = "delta-source-overlay.v1.json"
GRABOWSKI_DELTA_OVERLAY_SCHEMA = "chronik-grabowski-delta-source-overlay.v1"
GRABOWSKI_DELTA_OVERLAY_MAX_RECORDS = 2048
GRABOWSKI_STEADY_CHECKPOINT_FILENAME = "steady-import-checkpoint.v1.json"
GRABOWSKI_STEADY_CHECKPOINT_SCHEMA = "chronik-grabowski-steady-import-checkpoint.v1"
DEFAULT_COMPACTION_MAX_SOURCES = 256
DEFAULT_COMPACTION_MAX_BYTES = 64 * 1024 * 1024


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _payload_fingerprint(value: dict[str, Any]) -> bytes:
    canonical = canonical_bytes(value)
    return len(canonical).to_bytes(8, "big", signed=False) + hashlib.sha256(
        canonical
    ).digest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def configure_data_dir(path: Path, *, create: bool) -> Path:
    candidate = path.expanduser()
    if create:
        candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = candidate.resolve(strict=not create)
    if not resolved.is_dir():
        raise ValueError("Chronik data directory is not a directory")
    storage.DATA_DIR = resolved
    return resolved


@lru_cache(maxsize=1)
def _validator() -> Draft7Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema)


def validate_event(event: dict[str, Any]) -> datetime:
    errors = sorted(_validator().iter_errors(event), key=lambda error: list(error.absolute_path))
    if errors:
        error = errors[0]
        path = "/".join(str(part) for part in error.absolute_path) or "<root>"
        raise ValueError(f"invalid coding event at {path}: {error.message}")
    return _parse_timestamp(event["ts"], field="ts")


def _envelope_lines(events: Iterable[dict[str, Any]]) -> list[str]:
    return [
        json.dumps(
            build_envelope(DOMAIN, event),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        for event in events
    ]


def import_events(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    values = [dict(event) for event in events]
    for event in values:
        validate_event(event)
    written, skipped = storage.write_payload_unique(DOMAIN, _envelope_lines(values))
    receipt = {
        "schema_version": "chronik-import-receipt.v1",
        "domain": DOMAIN,
        "event_ids": sorted(event["event_id"] for event in values),
        "requested": len(values),
        "imported": written,
        "skipped_existing": skipped,
        "recorded_at": utc_now(),
        "source_sha256": sha256_bytes(b"\n".join(canonical_bytes(event) for event in values)),
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
    return receipt


def _parse_jsonl_snapshot(path: Path, raw: bytes) -> list[dict[str, Any]]:
    if raw and not raw.endswith(b"\n"):
        raise ValueError(f"incomplete JSONL tail: {path}")
    events: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(raw.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            value = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at {path}:{line_number}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"event must be an object at {path}:{line_number}")
        events.append(value)
    return events


def _read_jsonl_snapshot(path: Path) -> tuple[bytes, list[dict[str, Any]]]:
    raw = path.read_bytes()
    return raw, _parse_jsonl_snapshot(path, raw)


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


_FILE_IDENTITY_FIELDS = (
    "device",
    "inode",
    "mode",
    "links",
    "uid",
    "size",
    "mtime_ns",
    "ctime_ns",
)


def _file_identity_from_document(value: object) -> tuple[int, ...]:
    if not isinstance(value, dict) or set(value) != set(_FILE_IDENTITY_FIELDS):
        raise ValueError("invalid source-index file identity")
    identity = tuple(value[field] for field in _FILE_IDENTITY_FIELDS)
    if any(type(item) is not int or item < 0 for item in identity):
        raise ValueError("invalid source-index file identity values")
    if not stat.S_ISREG(identity[2]):
        raise ValueError("source-index identity is not a regular file")
    return identity


def _legacy_receipt_path(source: Path, receipt_dir: Path) -> Path:
    source_key = sha256_bytes(str(source.resolve()).encode("utf-8"))
    return receipt_dir / f"{source_key}.receipt.json"


def _receipt_path(
    source: Path, receipt_dir: Path, source_sha256: str | None = None
) -> Path:
    digest = source_sha256
    if digest is None:
        digest = sha256_bytes(source.read_bytes())
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("source_sha256 must be a SHA-256 hex digest")
    source_key = sha256_bytes(
        canonical_bytes(
            {
                "source_path": str(source.resolve()),
                "source_sha256": digest,
            }
        )
    )
    return receipt_dir / f"{source_key}.receipt.json"

def _load_receipt(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid import receipt: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"invalid import receipt object: {path}")
    return value


def _load_previous_receipt(
    source: Path,
    *,
    receipt_dir: Path,
    source_sha256: str,
) -> tuple[Path, Path, dict[str, Any] | None]:
    receipt_path = _receipt_path(source, receipt_dir, source_sha256)
    previous_receipt_path = receipt_path
    try:
        previous = _load_receipt(receipt_path)
    except ValueError:
        previous = None
    if previous is None and not receipt_path.exists():
        legacy_path = _legacy_receipt_path(source, receipt_dir)
        try:
            legacy = _load_receipt(legacy_path)
        except ValueError:
            legacy = None
        if legacy is not None:
            previous = legacy
            previous_receipt_path = legacy_path
            receipt_path = legacy_path
    return receipt_path, previous_receipt_path, previous


def _validate_grabowski_source(event: dict[str, Any]) -> None:
    validate_event(event)
    source = event.get("source")
    if not isinstance(source, dict):
        raise ValueError("event.source must be an object")
    if source.get("repo") != GRABOWSKI_SOURCE_REPO or source.get("component") != GRABOWSKI_COMPONENT:
        raise ValueError("outbox event is not produced by canonical Grabowski")
    if event.get("kind") not in HIGH_VALUE_KINDS:
        raise ValueError(f"unsupported operator-memory kind: {event.get('kind')}")


def _prepare_grabowski_source_bytes(
    source: Path,
    raw: bytes,
    *,
    receipt_dir: Path,
    source_origin: str,
    source_identity: tuple[int, ...] | None = None,
    source_mtime_ns: int | None = None,
    bundle_manifest_path: Path | None = None,
) -> dict[str, Any]:
    events = _parse_jsonl_snapshot(source, raw)
    if not events:
        raise ValueError(f"outbox contains no events: {source}")
    for event in events:
        _validate_grabowski_source(event)
    source_sha256 = sha256_bytes(raw)
    receipt_path, previous_receipt_path, previous = _load_previous_receipt(
        source,
        receipt_dir=receipt_dir,
        source_sha256=source_sha256,
    )
    return {
        "source": source,
        "raw": raw,
        "events": events,
        "source_sha256": source_sha256,
        "source_bytes": len(raw),
        "event_ids": [event["event_id"] for event in events],
        "event_fingerprints": [
            (event["event_id"], _payload_fingerprint(event)) for event in events
        ],
        "receipt_path": receipt_path,
        "previous_receipt_path": previous_receipt_path,
        "previous_receipt": previous,
        "source_unchanged": previous is not None and previous.get("source_sha256") == source_sha256,
        "source_origin": source_origin,
        "source_identity": source_identity,
        "source_mtime_ns": source_mtime_ns,
        "bundle_manifest_path": bundle_manifest_path,
    }


def _prepare_grabowski_outbox_source(source: Path, *, receipt_dir: Path) -> dict[str, Any]:
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"outbox source must be a regular file: {source}")
    raw = source.read_bytes()
    after = source.lstat()
    if _file_identity(before) != _file_identity(after):
        raise ValueError(f"outbox source changed while reading: {source}")
    return _prepare_grabowski_source_bytes(
        source,
        raw,
        receipt_dir=receipt_dir,
        source_origin="loose",
        source_identity=_file_identity(after),
        source_mtime_ns=after.st_mtime_ns,
    )


def _prepared_event_ids(prepared: dict[str, Any]) -> list[str]:
    event_ids = prepared.get("event_ids")
    if not isinstance(event_ids, list) or not all(
        isinstance(event_id, str) and event_id for event_id in event_ids
    ):
        raise ValueError("prepared source has invalid event IDs")
    return event_ids


def _prepared_event_count(prepared: dict[str, Any]) -> int:
    return len(_prepared_event_ids(prepared))


def _prepared_source_bytes(prepared: dict[str, Any]) -> int:
    source_bytes = prepared.get("source_bytes")
    if type(source_bytes) is not int or source_bytes < 1:
        raise ValueError("prepared source has invalid byte count")
    return source_bytes


def _receipt_matches_prepared_source(
    prepared: dict[str, Any], receipt: dict[str, Any] | None
) -> bool:
    """Return whether an existing receipt is intact and bound to these source bytes."""
    if not isinstance(receipt, dict):
        return False
    source = prepared["source"]
    event_ids = _prepared_event_ids(prepared)
    source_bytes = _prepared_source_bytes(prepared)
    expected = {
        "schema_version": "chronik-grabowski-outbox-import.v1",
        "domain": DOMAIN,
        "source_path": str(source.resolve()),
        "source_sha256": prepared["source_sha256"],
        "source_bytes": source_bytes,
        "selection_contract": sorted(HIGH_VALUE_KINDS),
        "event_ids": sorted(event_ids),
        "requested": len(event_ids),
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        return False
    for key in (
        "imported",
        "skipped_existing",
        "batch_target_scans",
        "batch_target_records_scanned",
    ):
        value = receipt.get(key)
        if type(value) is not int or value < 0:
            return False
    if receipt["imported"] + receipt["skipped_existing"] != len(event_ids):
        return False
    recorded_at = receipt.get("recorded_at")
    if not isinstance(recorded_at, str):
        return False
    try:
        _parse_timestamp(recorded_at, field="recorded_at")
    except ValueError:
        return False
    claimed_digest = receipt.get("receipt_sha256")
    if not isinstance(claimed_digest, str):
        return False
    unsigned = dict(receipt)
    unsigned.pop("receipt_sha256", None)
    return claimed_digest == sha256_bytes(canonical_bytes(unsigned))


def _steady_checkpoint_path(receipt_dir: Path) -> Path:
    return receipt_dir / GRABOWSKI_STEADY_CHECKPOINT_FILENAME


def _inventory_fingerprint(
    paths: Iterable[Path], *, private: bool
) -> dict[str, Any] | None:
    digest = hashlib.sha256()
    count = 0
    for path in sorted(paths, key=lambda item: str(item)):
        try:
            info = path.lstat()
        except OSError:
            return None
        if not stat.S_ISREG(info.st_mode):
            return None
        if private and (
            info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1
        ):
            return None
        material = canonical_bytes(
            {
                "path": str(path.absolute()),
                "identity": list(_file_identity(info)),
            }
        )
        digest.update(len(material).to_bytes(8, "big", signed=False))
        digest.update(material)
        count += 1
    return {"count": count, "sha256": digest.hexdigest()}


def _directory_identity(path: Path) -> dict[str, int] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {
            "device": -1,
            "inode": -1,
            "mode": 0,
            "links": 0,
            "uid": os.geteuid(),
            "size": 0,
            "mtime_ns": 0,
            "ctime_ns": 0,
        }
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        return None
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "mode": int(info.st_mode),
        "links": int(info.st_nlink),
        "uid": int(info.st_uid),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "ctime_ns": int(info.st_ctime_ns),
    }


def _stable_source_inventory_identity(
    *,
    source_dir: Path,
    bundle_dir: Path,
    sources: list[Path],
    manifests: list[Path],
    bundle_files: list[Path],
) -> dict[str, Any] | None:
    source_dir_before = _directory_identity(source_dir)
    bundle_dir_before = _directory_identity(bundle_dir)
    if source_dir_before is None or bundle_dir_before is None:
        return None
    fingerprint = _inventory_fingerprint(
        [*sources, *manifests, *bundle_files], private=False
    )
    source_dir_after = _directory_identity(source_dir)
    bundle_dir_after = _directory_identity(bundle_dir)
    if (
        fingerprint is None
        or source_dir_after is None
        or bundle_dir_after is None
        or source_dir_before != source_dir_after
        or bundle_dir_before != bundle_dir_after
    ):
        return None
    return {
        "artifacts": fingerprint,
        "source_dir": source_dir_after,
        "bundle_dir": bundle_dir_after,
    }


def _private_file_identity(path: Path) -> dict[str, Any] | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        return None
    return dict(zip(_FILE_IDENTITY_FIELDS, _file_identity(info)))


def _steady_fast_identity(
    *,
    source_dir: Path,
    bundle_dir: Path,
    sources: list[Path],
    manifests: list[Path],
    bundle_files: list[Path],
    receipt_dir: Path,
    source_index_path: Path,
    delta_index_path: Path,
    delta_overlay_path: Path,
    initial_source_inventory: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    source_inventory = initial_source_inventory or _stable_source_inventory_identity(
        source_dir=source_dir,
        bundle_dir=bundle_dir,
        sources=sources,
        manifests=manifests,
        bundle_files=bundle_files,
    )
    if source_inventory is None:
        return None
    receipt_paths = (
        list(receipt_dir.glob("*.receipt.json")) if receipt_dir.is_dir() else []
    )
    receipt_inventory = _inventory_fingerprint(receipt_paths, private=True)
    source_index_identity = _private_file_identity(source_index_path)
    delta_index_identity = _private_file_identity(delta_index_path)
    delta_overlay_identity = _private_file_identity(delta_overlay_path)
    try:
        target_identity = storage.read_unique_storage_checkpoint_identity(DOMAIN)
    except storage.StorageError:
        return None
    if (
        receipt_inventory is None
        or source_index_identity is None
        or delta_index_identity is None
        or delta_overlay_identity is None
        or target_identity is None
    ):
        return None

    # Close the metadata race window opened while receipts and target state were
    # observed. Any source or receipt drift since the first fingerprint must
    # enter the existing full reconciliation path.
    final_source_inventory = _stable_source_inventory_identity(
        source_dir=source_dir,
        bundle_dir=bundle_dir,
        sources=sources,
        manifests=manifests,
        bundle_files=bundle_files,
    )
    final_receipt_paths = (
        list(receipt_dir.glob("*.receipt.json")) if receipt_dir.is_dir() else []
    )
    final_receipt_inventory = _inventory_fingerprint(
        final_receipt_paths, private=True
    )
    if (
        final_source_inventory != source_inventory
        or final_receipt_inventory != receipt_inventory
    ):
        return None
    final_source_index_identity = _private_file_identity(source_index_path)
    final_delta_index_identity = _private_file_identity(delta_index_path)
    final_delta_overlay_identity = _private_file_identity(delta_overlay_path)
    try:
        final_target_identity = storage.read_unique_storage_checkpoint_identity(DOMAIN)
    except storage.StorageError:
        return None
    if (
        final_source_index_identity != source_index_identity
        or final_delta_index_identity != delta_index_identity
        or final_delta_overlay_identity != delta_overlay_identity
        or final_target_identity != target_identity
    ):
        return None
    return {
        "source_inventory": final_source_inventory,
        "receipt_inventory": final_receipt_inventory,
        "source_index_identity": final_source_index_identity,
        "delta_index_identity": final_delta_index_identity,
        "delta_overlay_identity": final_delta_overlay_identity,
        "target_identity": final_target_identity,
    }


def _delta_candidate_identity(
    *,
    checkpoint: dict[str, Any],
    source_dir: Path,
    bundle_dir: Path,
    sources: list[Path],
    manifests: list[Path],
    bundle_files: list[Path],
    receipt_dir: Path,
    source_index_path: Path,
    delta_index_path: Path,
    delta_overlay_path: Path,
    source_inventory: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    del receipt_dir
    prior = checkpoint.get("identity")
    if (
        not isinstance(prior, dict)
        or not isinstance(prior.get("delta_index_identity"), dict)
    ):
        return None
    source_inventory = source_inventory or _stable_source_inventory_identity(
        source_dir=source_dir,
        bundle_dir=bundle_dir,
        sources=sources,
        manifests=manifests,
        bundle_files=bundle_files,
    )
    if source_inventory is None or source_inventory == prior.get("source_inventory"):
        return None
    source_index_identity = _private_file_identity(source_index_path)
    delta_index_identity = _private_file_identity(delta_index_path)
    delta_overlay_identity = _private_file_identity(delta_overlay_path)
    if (
        source_index_identity != prior.get("source_index_identity")
        or delta_index_identity != prior.get("delta_index_identity")
        or delta_overlay_identity != prior.get("delta_overlay_identity")
    ):
        return None
    return {
        "source_inventory": source_inventory,
        "source_index_identity": source_index_identity,
        "delta_index_identity": delta_index_identity,
        "delta_overlay_identity": delta_overlay_identity,
    }


def _load_steady_checkpoint(
    path: Path, *, source_dir: Path
) -> dict[str, Any] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        return None
    try:
        raw, _ = _read_immutable_artifact_snapshot(path, label="steady import checkpoint")
        if not raw.endswith(b"\n"):
            return None
        document = json.loads(raw)
        if not isinstance(document, dict):
            return None
        expected = {
            "schema_version",
            "source_dir",
            "selection_contract",
            "identity",
            "summary",
            "recorded_at",
            "historical_only",
            "does_not_establish",
            "checkpoint_sha256",
        }
        if set(document) != expected:
            return None
        claimed = document.get("checkpoint_sha256")
        unsigned = dict(document)
        unsigned.pop("checkpoint_sha256")
        if (
            document.get("schema_version") != GRABOWSKI_STEADY_CHECKPOINT_SCHEMA
            or document.get("source_dir") != str(source_dir.resolve())
            or document.get("selection_contract") != sorted(HIGH_VALUE_KINDS)
            or document.get("historical_only") is not True
            or document.get("does_not_establish") != DOES_NOT_ESTABLISH
            or not isinstance(claimed, str)
            or claimed != sha256_bytes(canonical_bytes(unsigned))
            or not isinstance(document.get("identity"), dict)
            or not isinstance(document.get("summary"), dict)
        ):
            return None
        recorded_at = document.get("recorded_at")
        if not isinstance(recorded_at, str):
            return None
        _parse_timestamp(recorded_at, field="steady_checkpoint.recorded_at")
        return document
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _steady_summary_from_result(result: dict[str, Any]) -> dict[str, Any]:
    source_count = int(result["sources_after_deduplication"])
    event_count = int(result["events_imported"]) + int(result["events_skipped_existing"])
    return {
        "files_seen": int(result["files_seen"]),
        "loose_files_seen": int(result["loose_files_seen"]),
        "bundle_manifests_seen": int(result["bundle_manifests_seen"]),
        "bundles_valid": int(result["bundles_valid"]),
        "bundled_sources_seen": int(result["bundled_sources_seen"]),
        "sources_seen_total": int(result["sources_seen_total"]),
        "sources_after_deduplication": source_count,
        "orphan_bundles": int(result["orphan_bundles"]),
        "files_imported_or_confirmed": source_count,
        "files_unchanged": source_count,
        "receipts_written": 0,
        "receipts_reused": (
            0 if int(result.get("receipts_deferred", 0)) else source_count
        ),
        "receipts_deferred": int(result.get("receipts_deferred", 0)),
        "loose_sources_imported_or_confirmed": int(result["loose_files_seen"]),
        "bundled_sources_imported_or_confirmed": int(result["bundled_sources_seen"]),
        "events_imported": 0,
        "events_skipped_existing": event_count,
        "target_scans": 0,
        "target_records_scanned": 0,
        "identity_index_mode": "steady",
        "identity_index_full_rebuild": False,
        "identity_index_entries_after": int(result["identity_index_entries_after"]),
        "source_index_mode": (
            "deferred_delta"
            if result.get("source_index_mode") == "deferred_delta"
            else "steady"
        ),
        "source_index_file_bytes": int(result["source_index_file_bytes"]),
        "sources_reused": source_count,
        "sources_revalidated": 0,
        "sources_changed": 0,
        "sources_added": 0,
        "sources_removed": 0,
        "source_bytes_read": 0,
        "source_bytes_hashed": 0,
        "source_events_validated": 0,
    }


def _publish_steady_checkpoint(
    path: Path,
    *,
    source_dir: Path,
    identity: dict[str, Any],
    summary: dict[str, Any],
    previous: dict[str, Any] | None,
) -> bool:
    semantic = {
        "schema_version": GRABOWSKI_STEADY_CHECKPOINT_SCHEMA,
        "source_dir": str(source_dir.resolve()),
        "selection_contract": sorted(HIGH_VALUE_KINDS),
        "identity": identity,
        "summary": summary,
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }
    if previous is not None and all(
        previous.get(key) == value for key, value in semantic.items()
    ):
        return False
    document = {**semantic, "recorded_at": utc_now()}
    document["checkpoint_sha256"] = sha256_bytes(canonical_bytes(document))
    raw = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    _atomic_write(path, raw)
    _fsync_directory(path.parent)
    return True


def _steady_fast_result(
    checkpoint: dict[str, Any],
    *,
    source_dir: Path,
    receipt_dir: Path,
    source_index_path: Path,
    import_started_ns: int,
    phase_ns: Counter[str],
    counters: Counter[str],
) -> dict[str, Any]:
    summary = dict(checkpoint["summary"])
    counters["steady_fast_path_hits"] += 1
    counters["sources_reused"] = int(summary["sources_reused"])
    elapsed_ns = time.perf_counter_ns() - import_started_ns
    telemetry = {
        "schema_version": "chronik-grabowski-import-telemetry.v1",
        "elapsed_seconds": round(elapsed_ns / 1_000_000_000, 6),
        "phases_seconds": {
            name: round(value / 1_000_000_000, 6)
            for name, value in sorted(phase_ns.items())
        },
        "counters": dict(sorted(counters.items())),
    }
    return {
        "schema_version": "chronik-grabowski-outbox-batch.v2",
        "source_dir": str(source_dir),
        "receipt_dir": str(receipt_dir),
        **summary,
        "source_index_path": str(source_index_path),
        "source_index_written": False,
        "elapsed_seconds": telemetry["elapsed_seconds"],
        "import_telemetry": telemetry,
        "bundle_inventory": [],
        "bundle_inventory_omitted": True,
        "steady_fast_path": True,
        "delta_fast_path": False,
        "steady_checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "errors": [],
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }


def _delta_index_path(receipt_dir: Path) -> Path:
    return receipt_dir / GRABOWSKI_DELTA_INDEX_FILENAME


def _delta_overlay_path(receipt_dir: Path) -> Path:
    return receipt_dir / GRABOWSKI_DELTA_OVERLAY_FILENAME


def _load_delta_overlay(
    path: Path,
    *,
    source_dir: Path,
    base_index_sha256: str,
) -> tuple[dict[str, Any] | None, int, str]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None, 0, "rebuild_missing"
    except OSError:
        return None, 0, "rebuild_invalid"
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        return None, int(info.st_size), "rebuild_invalid"
    try:
        raw, _ = _read_immutable_artifact_snapshot(path, label="delta source overlay")
        if not raw.endswith(b"\n"):
            raise ValueError("incomplete delta source overlay")
        document = json.loads(raw)
        expected = {
            "schema_version",
            "source_dir",
            "base_index_sha256",
            "records",
            "record_count",
            "recorded_at",
            "historical_only",
            "does_not_establish",
            "overlay_sha256",
        }
        if not isinstance(document, dict) or set(document) != expected:
            raise ValueError("invalid delta-overlay fields")
        claimed = document.get("overlay_sha256")
        unsigned = dict(document)
        unsigned.pop("overlay_sha256")
        if (
            document.get("schema_version") != GRABOWSKI_DELTA_OVERLAY_SCHEMA
            or document.get("source_dir") != str(source_dir.resolve())
            or document.get("base_index_sha256") != base_index_sha256
            or document.get("historical_only") is not True
            or document.get("does_not_establish") != DOES_NOT_ESTABLISH
            or not isinstance(claimed, str)
            or claimed != sha256_bytes(canonical_bytes(unsigned))
        ):
            raise ValueError("delta-overlay contract or digest mismatch")
        recorded_at = document.get("recorded_at")
        if not isinstance(recorded_at, str):
            raise ValueError("invalid delta-overlay timestamp")
        _parse_timestamp(recorded_at, field="delta_source_overlay.recorded_at")
        raw_records = document.get("records")
        if not isinstance(raw_records, list):
            raise ValueError("invalid delta-overlay records")
        if len(raw_records) > GRABOWSKI_DELTA_OVERLAY_MAX_RECORDS:
            raise ValueError("delta-overlay compaction threshold exceeded")
        resolved_source_dir = source_dir.resolve()
        records = [
            _validate_delta_source_record(
                item, resolved_source_dir=resolved_source_dir
            )
            for item in raw_records
        ]
        paths = [item["source_path"] for item in records]
        if paths != sorted(set(paths)) or document.get("record_count") != len(records):
            raise ValueError("delta-overlay records are not unique and sorted")
        document["_records"] = records
        return document, len(raw), "steady"
    except (OSError, ValueError, json.JSONDecodeError):
        return None, int(info.st_size), "rebuild_invalid"


def _publish_delta_overlay(
    path: Path,
    *,
    source_dir: Path,
    base_index_sha256: str,
    records: list[dict[str, Any]],
) -> tuple[bool, int]:
    normalized = sorted(records, key=lambda item: item["source_path"])
    if len(normalized) > GRABOWSKI_DELTA_OVERLAY_MAX_RECORDS:
        raise ValueError("delta-overlay compaction threshold exceeded")
    document = {
        "schema_version": GRABOWSKI_DELTA_OVERLAY_SCHEMA,
        "source_dir": str(source_dir.resolve()),
        "base_index_sha256": base_index_sha256,
        "records": normalized,
        "record_count": len(normalized),
        "recorded_at": utc_now(),
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }
    document["overlay_sha256"] = sha256_bytes(canonical_bytes(document))
    raw = canonical_bytes(document) + b"\n"
    _atomic_write(path, raw)
    readback, _ = _read_immutable_artifact_snapshot(path, label="delta source overlay")
    if readback != raw:
        raise ValueError("delta source overlay readback mismatch")
    return True, len(raw)


def _validate_delta_source_record(
    value: object, *, resolved_source_dir: Path
) -> dict[str, Any]:
    expected = {
        "source_path",
        "source_sha256",
        "source_bytes",
        "event_count",
        "source_identity",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("invalid delta-index source fields")
    source_path = value.get("source_path")
    if not isinstance(source_path, str):
        raise ValueError("invalid delta-index source path")
    source = Path(source_path)
    if (
        not source.is_absolute()
        or source.parent != resolved_source_dir
        or not source.name.endswith(".jsonl")
    ):
        raise ValueError("delta-index source escapes the source directory")
    source_sha256 = value.get("source_sha256")
    if not isinstance(source_sha256, str) or len(source_sha256) != 64:
        raise ValueError("invalid delta-index source digest")
    try:
        bytes.fromhex(source_sha256)
    except ValueError as exc:
        raise ValueError("invalid delta-index source digest") from exc
    source_bytes = value.get("source_bytes")
    event_count = value.get("event_count")
    if type(source_bytes) is not int or source_bytes < 1:
        raise ValueError("invalid delta-index source byte count")
    if type(event_count) is not int or event_count < 1:
        raise ValueError("invalid delta-index source event count")
    validated = dict(value)
    validated["_identity"] = _file_identity_from_document(value.get("source_identity"))
    return validated


def _validate_delta_bundle_record(
    value: object, *, resolved_source_dir: Path, resolved_bundle_dir: Path
) -> dict[str, Any]:
    expected = {
        "manifest_path",
        "manifest_identity",
        "bundle_path",
        "bundle_identity",
        "source_paths",
        "source_count",
        "event_count",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("invalid delta-index bundle fields")
    manifest_path = value.get("manifest_path")
    bundle_path = value.get("bundle_path")
    if not isinstance(manifest_path, str) or not isinstance(bundle_path, str):
        raise ValueError("invalid delta-index bundle paths")
    manifest = Path(manifest_path)
    bundle = Path(bundle_path)
    if (
        not manifest.is_absolute()
        or manifest.parent != resolved_bundle_dir
        or not manifest.name.endswith(".manifest.json")
        or not bundle.is_absolute()
        or bundle.parent != resolved_bundle_dir
        or not bundle.name.endswith(".bundle.jsonl")
    ):
        raise ValueError("delta-index bundle escapes the bundle directory")
    source_paths = value.get("source_paths")
    if not isinstance(source_paths, list) or not source_paths:
        raise ValueError("delta-index bundle has no source paths")
    for source_path in source_paths:
        if not isinstance(source_path, str):
            raise ValueError("invalid delta-index archived source path")
        source = Path(source_path)
        if not source.is_absolute() or source.parent != resolved_source_dir:
            raise ValueError("delta-index archived source escapes source directory")
    source_count = value.get("source_count")
    event_count = value.get("event_count")
    if (
        type(source_count) is not int
        or source_count != len(source_paths)
        or type(event_count) is not int
        or event_count < source_count
    ):
        raise ValueError("invalid delta-index bundle counts")
    validated = dict(value)
    validated["_manifest_identity"] = _file_identity_from_document(
        value.get("manifest_identity")
    )
    validated["_bundle_identity"] = _file_identity_from_document(
        value.get("bundle_identity")
    )
    return validated


def _load_delta_index(
    path: Path, *, source_dir: Path, bundle_dir: Path
) -> tuple[dict[str, Any] | None, int, str]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None, 0, "rebuild_missing"
    except OSError:
        return None, 0, "rebuild_invalid"
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        return None, int(info.st_size), "rebuild_invalid"
    try:
        raw, _ = _read_immutable_artifact_snapshot(path, label="delta source index")
        if not raw.endswith(b"\n"):
            raise ValueError("incomplete delta source index")
        document = json.loads(raw)
        expected = {
            "schema_version",
            "source_dir",
            "selection_contract",
            "loose_sources",
            "bundles",
            "source_count",
            "event_count",
            "recorded_at",
            "historical_only",
            "does_not_establish",
            "index_sha256",
        }
        if not isinstance(document, dict) or set(document) != expected:
            raise ValueError("invalid delta-index fields")
        claimed = document.get("index_sha256")
        unsigned = dict(document)
        unsigned.pop("index_sha256")
        if (
            document.get("schema_version") != GRABOWSKI_DELTA_INDEX_SCHEMA
            or document.get("source_dir") != str(source_dir.resolve())
            or document.get("selection_contract") != sorted(HIGH_VALUE_KINDS)
            or document.get("historical_only") is not True
            or document.get("does_not_establish") != DOES_NOT_ESTABLISH
            or not isinstance(claimed, str)
            or claimed != sha256_bytes(canonical_bytes(unsigned))
        ):
            raise ValueError("delta-index contract or digest mismatch")
        recorded_at = document.get("recorded_at")
        if not isinstance(recorded_at, str):
            raise ValueError("invalid delta-index timestamp")
        _parse_timestamp(recorded_at, field="delta_source_index.recorded_at")
        raw_loose = document.get("loose_sources")
        raw_bundles = document.get("bundles")
        if not isinstance(raw_loose, list) or not isinstance(raw_bundles, list):
            raise ValueError("invalid delta-index inventories")
        resolved_source_dir = source_dir.resolve()
        resolved_bundle_dir = bundle_dir.resolve()
        loose = [
            _validate_delta_source_record(
                item, resolved_source_dir=resolved_source_dir
            )
            for item in raw_loose
        ]
        bundles = [
            _validate_delta_bundle_record(
                item,
                resolved_source_dir=resolved_source_dir,
                resolved_bundle_dir=resolved_bundle_dir,
            )
            for item in raw_bundles
        ]
        loose_paths = [item["source_path"] for item in loose]
        manifest_paths = [item["manifest_path"] for item in bundles]
        if loose_paths != sorted(set(loose_paths)) or manifest_paths != sorted(
            set(manifest_paths)
        ):
            raise ValueError("delta-index inventories are not unique and sorted")
        source_count = len(loose) + sum(int(item["source_count"]) for item in bundles)
        event_count = sum(int(item["event_count"]) for item in loose) + sum(
            int(item["event_count"]) for item in bundles
        )
        if (
            document.get("source_count") != source_count
            or document.get("event_count") != event_count
        ):
            raise ValueError("delta-index aggregate counts mismatch")
        document["_loose_sources"] = loose
        document["_bundles"] = bundles
        return document, len(raw), "steady"
    except (OSError, ValueError, json.JSONDecodeError):
        return None, int(info.st_size), "rebuild_invalid"


def _delta_source_record_from_source_record(record: dict[str, Any]) -> dict[str, Any]:
    fingerprints = record.get("event_fingerprints")
    if not isinstance(fingerprints, list) or not fingerprints:
        raise ValueError("source record lacks event fingerprints")
    return {
        "source_path": record["source_path"],
        "source_sha256": record["source_sha256"],
        "source_bytes": record["source_bytes"],
        "event_count": len(fingerprints),
        "source_identity": record["source_identity"],
    }


def _delta_bundle_record_from_source_record(record: dict[str, Any]) -> dict[str, Any]:
    sources = record.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("bundle source record has no sources")
    source_paths = sorted(str(item["source_path"]) for item in sources)
    event_count = sum(len(item["event_fingerprints"]) for item in sources)
    return {
        "manifest_path": record["manifest_path"],
        "manifest_identity": record["manifest_identity"],
        "bundle_path": record["bundle_path"],
        "bundle_identity": record["bundle_identity"],
        "source_paths": source_paths,
        "source_count": len(source_paths),
        "event_count": event_count,
    }


def _publish_delta_index(
    path: Path,
    *,
    source_dir: Path,
    loose_sources: list[dict[str, Any]],
    bundles: list[dict[str, Any]],
) -> tuple[bool, int]:
    normalized_loose = sorted(loose_sources, key=lambda item: item["source_path"])
    normalized_bundles = sorted(bundles, key=lambda item: item["manifest_path"])
    document = {
        "schema_version": GRABOWSKI_DELTA_INDEX_SCHEMA,
        "source_dir": str(source_dir.resolve()),
        "selection_contract": sorted(HIGH_VALUE_KINDS),
        "loose_sources": normalized_loose,
        "bundles": normalized_bundles,
        "source_count": len(normalized_loose)
        + sum(int(item["source_count"]) for item in normalized_bundles),
        "event_count": sum(int(item["event_count"]) for item in normalized_loose)
        + sum(int(item["event_count"]) for item in normalized_bundles),
        "recorded_at": utc_now(),
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }
    document["index_sha256"] = sha256_bytes(canonical_bytes(document))
    raw = canonical_bytes(document) + b"\n"
    existing = None
    try:
        existing = path.read_bytes()
    except FileNotFoundError:
        pass
    if existing == raw:
        return False, len(raw)
    _atomic_write(path, raw)
    readback, _ = _read_immutable_artifact_snapshot(path, label="delta source index")
    if readback != raw:
        raise ValueError("delta source index readback mismatch")
    return True, len(raw)


def _source_index_path(receipt_dir: Path) -> Path:
    return receipt_dir / GRABOWSKI_SOURCE_INDEX_FILENAME


def _validate_source_index_event_fingerprints(value: object) -> list[tuple[str, bytes]]:
    if not isinstance(value, list) or not value:
        raise ValueError("source-index event fingerprints must be a non-empty list")
    result: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"event_id", "fingerprint"}:
            raise ValueError("invalid source-index event fingerprint")
        event_id = item.get("event_id")
        fingerprint_hex = item.get("fingerprint")
        if (
            not isinstance(event_id, str)
            or not event_id
            or event_id in seen
            or not isinstance(fingerprint_hex, str)
            or len(fingerprint_hex) != 80
        ):
            raise ValueError("invalid source-index event fingerprint values")
        try:
            fingerprint = bytes.fromhex(fingerprint_hex)
        except ValueError as exc:
            raise ValueError("invalid source-index payload fingerprint") from exc
        if len(fingerprint) != 40:
            raise ValueError("invalid source-index payload fingerprint length")
        seen.add(event_id)
        result.append((event_id, fingerprint))
    return result


def _validate_source_index_source_record(
    value: object,
    *,
    source_dir: Path,
    loose: bool,
) -> dict[str, Any]:
    expected = {
        "source_path",
        "source_sha256",
        "source_bytes",
        "event_fingerprints",
    }
    if loose:
        expected.add("source_identity")
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("invalid source-index source fields")
    source_path = value.get("source_path")
    if not isinstance(source_path, str):
        raise ValueError("invalid source-index source path")
    source = Path(source_path)
    resolved_dir = source_dir.resolve()
    if (
        not source.is_absolute()
        or source.parent != resolved_dir
        or source.name in {"", ".", ".."}
        or not source.name.endswith(".jsonl")
    ):
        raise ValueError("source-index source escapes the outbox directory")
    source_sha256 = value.get("source_sha256")
    if (
        not isinstance(source_sha256, str)
        or len(source_sha256) != 64
        or any(character not in "0123456789abcdef" for character in source_sha256)
    ):
        raise ValueError("invalid source-index source digest")
    source_bytes = value.get("source_bytes")
    if type(source_bytes) is not int or source_bytes < 1:
        raise ValueError("invalid source-index source byte count")
    fingerprints = _validate_source_index_event_fingerprints(
        value.get("event_fingerprints")
    )
    validated = dict(value)
    validated["_fingerprints"] = fingerprints
    if loose:
        validated["_identity"] = _file_identity_from_document(
            value.get("source_identity")
        )
    return validated


def _validate_source_index_bundle_record(
    value: object,
    *,
    source_dir: Path,
    bundle_dir: Path,
) -> dict[str, Any]:
    expected = {
        "manifest_path",
        "manifest_identity",
        "bundle_path",
        "bundle_identity",
        "metadata",
        "sources",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("invalid source-index bundle fields")
    manifest_path = value.get("manifest_path")
    bundle_path = value.get("bundle_path")
    resolved_bundle_dir = bundle_dir.resolve()
    if not isinstance(manifest_path, str) or not isinstance(bundle_path, str):
        raise ValueError("invalid source-index bundle paths")
    manifest = Path(manifest_path)
    bundle = Path(bundle_path)
    if (
        not manifest.is_absolute()
        or manifest.parent != resolved_bundle_dir
        or not manifest.name.endswith(".manifest.json")
        or not bundle.is_absolute()
        or bundle.parent != resolved_bundle_dir
        or not bundle.name.endswith(".bundle.jsonl")
    ):
        raise ValueError("source-index bundle escapes the bundle directory")
    manifest_identity = _file_identity_from_document(value.get("manifest_identity"))
    bundle_identity = _file_identity_from_document(value.get("bundle_identity"))
    raw_sources = value.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ValueError("source-index bundle has no sources")
    sources = [
        _validate_source_index_source_record(
            item,
            source_dir=source_dir,
            loose=False,
        )
        for item in raw_sources
    ]
    metadata = value.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("invalid source-index bundle metadata")
    if (
        metadata.get("manifest_path") != manifest_path
        or metadata.get("bundle_path") != bundle_path
        or metadata.get("source_count") != len(sources)
        or metadata.get("event_count")
        != sum(len(item["_fingerprints"]) for item in sources)
    ):
        raise ValueError("source-index bundle inventory mismatch")
    validated = dict(value)
    validated["_manifest_identity"] = manifest_identity
    validated["_bundle_identity"] = bundle_identity
    validated["_sources"] = sources
    return validated


def _load_grabowski_source_index(
    path: Path,
    *,
    source_dir: Path,
    bundle_dir: Path,
) -> tuple[dict[str, Any] | None, int, str]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None, 0, "rebuild_missing"
    except OSError:
        return None, 0, "rebuild_invalid"
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        return None, 0, "rebuild_invalid"
    try:
        raw, _ = _read_immutable_artifact_snapshot(path, label="source index")
        if not raw.endswith(b"\n"):
            raise ValueError("incomplete source index")
        document = json.loads(raw)
        expected = {
            "schema_version",
            "source_dir",
            "selection_contract",
            "loose_sources",
            "bundles",
            "recorded_at",
            "historical_only",
            "does_not_establish",
            "index_sha256",
        }
        if not isinstance(document, dict) or set(document) != expected:
            raise ValueError("invalid source-index fields")
        claimed = document.get("index_sha256")
        unsigned = dict(document)
        unsigned.pop("index_sha256")
        if (
            document.get("schema_version") != GRABOWSKI_SOURCE_INDEX_SCHEMA
            or document.get("source_dir") != str(source_dir.resolve())
            or document.get("selection_contract") != sorted(HIGH_VALUE_KINDS)
            or document.get("historical_only") is not True
            or document.get("does_not_establish") != DOES_NOT_ESTABLISH
            or not isinstance(claimed, str)
            or claimed != sha256_bytes(canonical_bytes(unsigned))
        ):
            raise ValueError("source-index contract or digest mismatch")
        recorded_at = document.get("recorded_at")
        if not isinstance(recorded_at, str):
            raise ValueError("invalid source-index timestamp")
        _parse_timestamp(recorded_at, field="source_index.recorded_at")
        raw_loose = document.get("loose_sources")
        raw_bundles = document.get("bundles")
        if not isinstance(raw_loose, list) or not isinstance(raw_bundles, list):
            raise ValueError("invalid source-index inventories")
        loose = [
            _validate_source_index_source_record(
                item,
                source_dir=source_dir,
                loose=True,
            )
            for item in raw_loose
        ]
        bundles = [
            _validate_source_index_bundle_record(
                item,
                source_dir=source_dir,
                bundle_dir=bundle_dir,
            )
            for item in raw_bundles
        ]
        loose_paths = [item["source_path"] for item in loose]
        manifest_paths = [item["manifest_path"] for item in bundles]
        if loose_paths != sorted(set(loose_paths)) or manifest_paths != sorted(
            set(manifest_paths)
        ):
            raise ValueError("source-index inventories are not unique and sorted")
        document["_loose_sources"] = loose
        document["_bundles"] = bundles
        return document, len(raw), "steady"
    except (OSError, ValueError, json.JSONDecodeError):
        return None, int(info.st_size), "rebuild_invalid"


def _source_index_source_record(prepared: dict[str, Any], *, loose: bool) -> dict[str, Any]:
    record = {
        "source_path": str(prepared["source"].resolve()),
        "source_sha256": prepared["source_sha256"],
        "source_bytes": _prepared_source_bytes(prepared),
        "event_fingerprints": [
            {"event_id": event_id, "fingerprint": fingerprint.hex()}
            for event_id, fingerprint in prepared["event_fingerprints"]
        ],
    }
    if loose:
        identity = prepared.get("source_identity")
        if not isinstance(identity, tuple) or len(identity) != len(_FILE_IDENTITY_FIELDS):
            raise ValueError("loose source lacks a stable file identity")
        record["source_identity"] = dict(zip(_FILE_IDENTITY_FIELDS, identity))
    return record


def _source_index_bundle_record(
    prepared_sources: list[dict[str, Any]], metadata: dict[str, Any]
) -> dict[str, Any]:
    public_metadata = {
        key: metadata[key]
        for key in (
            "manifest_path",
            "manifest_sha256",
            "bundle_path",
            "bundle_sha256",
            "bundle_bytes",
            "source_count",
            "event_count",
            "sources",
        )
    }
    return {
        "manifest_path": metadata["manifest_path"],
        "manifest_identity": metadata["manifest_identity"],
        "bundle_path": metadata["bundle_path"],
        "bundle_identity": metadata["bundle_identity"],
        "metadata": public_metadata,
        "sources": [
            _source_index_source_record(prepared, loose=False)
            for prepared in prepared_sources
        ],
    }


def _cached_prepared_source(
    record: dict[str, Any],
    *,
    receipt_dir: Path,
    source_origin: str,
    bundle_manifest_path: Path | None = None,
) -> dict[str, Any]:
    source = Path(record["source_path"])
    source_sha256 = record["source_sha256"]
    receipt_path, previous_receipt_path, previous = _load_previous_receipt(
        source,
        receipt_dir=receipt_dir,
        source_sha256=source_sha256,
    )
    fingerprints = list(record["_fingerprints"])
    return {
        "source": source,
        "raw": None,
        "events": None,
        "source_sha256": source_sha256,
        "source_bytes": record["source_bytes"],
        "event_ids": [event_id for event_id, _ in fingerprints],
        "event_fingerprints": fingerprints,
        "receipt_path": receipt_path,
        "previous_receipt_path": previous_receipt_path,
        "previous_receipt": previous,
        "source_unchanged": previous is not None
        and previous.get("source_sha256") == source_sha256,
        "source_origin": source_origin,
        "source_identity": record.get("_identity"),
        "source_mtime_ns": (
            record["_identity"][-2] if source_origin == "loose" else None
        ),
        "bundle_manifest_path": bundle_manifest_path,
        "source_index_cached": True,
    }


def _file_matches_source_index(path: Path, expected: tuple[int, ...]) -> bool:
    try:
        current = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(current.st_mode) and _file_identity(current) == expected


def _checkpoint_allows_source_only_delta(
    checkpoint: dict[str, Any], current_identity: dict[str, Any]
) -> bool:
    """Return whether source-only drift can enter the read-only delta preflight."""
    prior_identity = checkpoint.get("identity")
    if (
        not isinstance(prior_identity, dict)
        or not isinstance(prior_identity.get("delta_index_identity"), dict)
        or current_identity.get("source_inventory")
        == prior_identity.get("source_inventory")
    ):
        return False
    return all(
        current_identity.get(key) == prior_identity.get(key)
        for key in (
            "source_index_identity",
            "delta_index_identity",
            "delta_overlay_identity",
        )
    )


def _try_checkpoint_delta_import(
    *,
    checkpoint: dict[str, Any],
    current_identity: dict[str, Any],
    delta_index: dict[str, Any],
    delta_overlay: dict[str, Any],
    source_dir: Path,
    bundle_dir: Path,
    sources: list[Path],
    manifests: list[Path],
    bundle_files: list[Path],
    receipt_dir: Path,
    source_index_path: Path,
    delta_index_path: Path,
    delta_overlay_path: Path,
    import_started_ns: int,
    phase_ns: Counter[str],
    counters: Counter[str],
    measured_phase: Any,
) -> dict[str, Any] | None:
    """Reconcile a source-only loose-file delta against a prior full checkpoint.

    The private delta index and overlay are accelerators only. The prior
    checkpoint must still bind those cache projections, the canonical source
    index, and the authoritative ledger/identity-index target. A checkpoint from
    a full reconciliation also binds the complete receipt inventory; consecutive
    delta checkpoints explicitly defer re-attesting receipts for unchanged old
    sources. Any removal, bundle drift, path-generation overlap, cache/target
    drift, or pre-effect race falls back to the normal full reconciliation path.
    """
    if not _checkpoint_allows_source_only_delta(checkpoint, current_identity):
        return None
    summary = checkpoint.get("summary")
    if not isinstance(summary, dict):
        return None
    raw_loose = delta_index.get("loose_sources")
    raw_bundles = delta_index.get("bundles")
    cached_loose_items = delta_index.get("_loose_sources")
    cached_bundle_items = delta_index.get("_bundles")
    raw_overlay_records = delta_overlay.get("records")
    cached_overlay_records = delta_overlay.get("_records")
    if not all(
        isinstance(value, list)
        for value in (
            raw_loose,
            raw_bundles,
            cached_loose_items,
            cached_bundle_items,
            raw_overlay_records,
            cached_overlay_records,
        )
    ):
        return None

    cached_loose = {item["source_path"]: item for item in cached_loose_items}
    cached_loose.update(
        {item["source_path"]: item for item in cached_overlay_records}
    )
    cached_bundles = {item["manifest_path"]: item for item in cached_bundle_items}
    current_loose = {str(path.resolve()): path for path in sources}
    current_manifests = {str(path.resolve()): path for path in manifests}
    current_bundle_files = {str(path.resolve()): path for path in bundle_files}
    if (
        len(current_loose) != len(sources)
        or len(current_manifests) != len(manifests)
        or len(current_bundle_files) != len(bundle_files)
        or not set(cached_loose).issubset(current_loose)
        or set(cached_bundles) != set(current_manifests)
        or {item["bundle_path"] for item in cached_bundle_items}
        != set(current_bundle_files)
    ):
        return None

    bundle_source_paths: set[str] = set()
    for bundle in cached_bundle_items:
        manifest_path = current_manifests[bundle["manifest_path"]]
        bundle_path = current_bundle_files[bundle["bundle_path"]]
        counters["source_artifacts_metadata_checked"] += 2
        if not (
            _file_matches_source_index(manifest_path, bundle["_manifest_identity"])
            and _file_matches_source_index(bundle_path, bundle["_bundle_identity"])
        ):
            return None
        bundle_source_paths.update(bundle["source_paths"])
    if set(current_loose) & bundle_source_paths:
        # Multiple generations of one source path are valid after compaction,
        # but they require the canonical full merge to assign generation receipts.
        return None

    try:
        prior_source_count = int(summary["sources_after_deduplication"])
        prior_event_count = int(summary["events_imported"]) + int(
            summary["events_skipped_existing"]
        )
        combined_source_count = len(cached_loose) + sum(
            int(item["source_count"]) for item in cached_bundle_items
        )
        combined_event_count = sum(
            int(item["event_count"]) for item in cached_loose.values()
        ) + sum(int(item["event_count"]) for item in cached_bundle_items)
        if (
            int(summary["files_seen"]) != len(cached_loose)
            or int(summary["bundle_manifests_seen"]) != len(cached_bundle_items)
            or int(summary["bundled_sources_seen"])
            != sum(int(item["source_count"]) for item in cached_bundle_items)
            or combined_source_count != prior_source_count
            or combined_event_count != prior_event_count
        ):
            return None
    except (KeyError, TypeError, ValueError):
        return None

    delta_prepared: list[dict[str, Any]] = []
    changed_old_event_count = 0
    added_count = 0
    changed_count = 0
    with measured_phase("delta_source_discovery"):
        for resolved, source in current_loose.items():
            cached = cached_loose.get(resolved)
            counters["source_artifacts_metadata_checked"] += 1
            if cached is not None and _file_matches_source_index(
                source, cached["_identity"]
            ):
                continue
            try:
                prepared = _prepare_grabowski_outbox_source(
                    source, receipt_dir=receipt_dir
                )
            except (OSError, ValueError, storage.StorageError):
                return None
            if cached is None:
                added_count += 1
            else:
                changed_count += 1
                changed_old_event_count += int(cached["event_count"])
            delta_prepared.append(prepared)
            counters["source_bytes_read"] += _prepared_source_bytes(prepared)
            counters["source_bytes_hashed"] += _prepared_source_bytes(prepared)
            counters["source_events_validated"] += _prepared_event_count(prepared)
    if not delta_prepared:
        return None
    try:
        delta_prepared = _merge_prepared_grabowski_sources(delta_prepared)
    except ValueError:
        return None
    if len(delta_prepared) != added_count + changed_count:
        return None
    projected_overlay_paths = {
        str(item["source_path"]) for item in raw_overlay_records
    }
    projected_overlay_paths.update(
        str(prepared["source"].resolve()) for prepared in delta_prepared
    )
    if len(projected_overlay_paths) > GRABOWSKI_DELTA_OVERLAY_MAX_RECORDS:
        # Compact/rebuild before any ledger effect instead of accepting the
        # delta and discovering the bounded-overlay limit only afterwards.
        counters["delta_overlay_capacity_fallbacks"] += 1
        return None

    # Bind the authoritative state immediately before the ledger effect. Source
    # files already read by this run are immutable snapshots; a later source
    # change is deliberately the next delta. Receipts are non-authoritative and
    # are fully re-attested by the next full/steady reconciliation.
    with measured_phase("delta_anchor_recheck"):
        source_inventory = current_identity.get("source_inventory")
        source_index_identity = _private_file_identity(source_index_path)
        delta_index_identity = _private_file_identity(delta_index_path)
        delta_overlay_identity = _private_file_identity(delta_overlay_path)
        try:
            target_identity = storage.read_unique_storage_checkpoint_identity(DOMAIN)
        except storage.StorageError:
            return None
        prior_identity = checkpoint["identity"]
        if (
            source_inventory is None
            or source_index_identity != prior_identity.get("source_index_identity")
            or delta_index_identity != prior_identity.get("delta_index_identity")
            or delta_overlay_identity != prior_identity.get("delta_overlay_identity")
            or target_identity != prior_identity.get("target_identity")
        ):
            return None

    errors: list[dict[str, str]] = []
    delta_results: list[dict[str, Any]] = []
    grouped: dict[str, object] | None = None
    receipt_writes_succeeded = True
    ledger_reconciled = False
    with measured_phase("delta_ledger_reconcile"):
        try:
            delta_results, grouped, receipt_errors = _import_prepared_grabowski_sources(
                delta_prepared
            )
            ledger_reconciled = True
            receipt_writes_succeeded = not receipt_errors
            errors.extend(
                {
                    "source_path": source_path,
                    "error": f"receipt write failed after ledger update: {exc}",
                }
                for source_path, exc in receipt_errors
            )
        except (OSError, ValueError, storage.StorageError) as exc:
            receipt_writes_succeeded = False
            errors.append({"source_path": "<batch>", "error": str(exc)})

    delta_overlay_written = False
    if ledger_reconciled and receipt_writes_succeeded:
        updated_overlay = {
            item["source_path"]: dict(item) for item in raw_overlay_records
        }
        for prepared in delta_prepared:
            source_record = _source_index_source_record(prepared, loose=True)
            updated_overlay[str(prepared["source"].resolve())] = (
                _delta_source_record_from_source_record(source_record)
            )
        with measured_phase("delta_overlay_publish"):
            try:
                delta_overlay_written, _ = _publish_delta_overlay(
                    delta_overlay_path,
                    source_dir=source_dir,
                    base_index_sha256=str(delta_index["index_sha256"]),
                    records=list(updated_overlay.values()),
                )
                if delta_overlay_written:
                    counters["delta_overlay_writes"] += 1
            except (OSError, ValueError) as exc:
                errors.append(
                    {
                        "source_path": str(delta_overlay_path),
                        "error": f"delta overlay update failed after ledger reconciliation: {exc}",
                    }
                )

    bundle_source_count = sum(
        int(item["source_count"]) for item in cached_bundle_items
    )
    current_source_count = prior_source_count + added_count
    bypassed_source_count = prior_source_count - changed_count
    bypassed_event_count = prior_event_count - changed_old_event_count
    target_scans = int(grouped.get("target_scans", 0)) if grouped is not None else None
    target_records_scanned = (
        int(grouped.get("target_records_scanned", 0))
        if grouped is not None
        else None
    )
    identity_index_mode = (
        str(grouped.get("identity_index_mode", "unknown"))
        if grouped is not None
        else None
    )
    identity_index_full_rebuild = (
        bool(grouped.get("identity_index_full_rebuild", False))
        if grouped is not None
        else None
    )
    identity_index_entries_after = (
        int(grouped.get("identity_index_entries_after", 0))
        if grouped is not None
        else None
    )
    prior_source_index_identity = checkpoint["identity"].get("source_index_identity")
    source_index_file_bytes = (
        int(prior_source_index_identity.get("size", 0))
        if isinstance(prior_source_index_identity, dict)
        else 0
    )
    base_result = {
        "schema_version": "chronik-grabowski-outbox-batch.v2",
        "source_dir": str(source_dir),
        "receipt_dir": str(receipt_dir),
        "files_seen": len(sources),
        "loose_files_seen": len(sources),
        "bundle_manifests_seen": len(manifests),
        "bundles_valid": len(cached_bundle_items),
        "bundled_sources_seen": bundle_source_count,
        "sources_seen_total": len(sources) + bundle_source_count,
        "sources_after_deduplication": current_source_count,
        "orphan_bundles": 0,
        "files_imported_or_confirmed": bypassed_source_count + len(delta_results),
        "files_unchanged": bypassed_source_count
        + sum(1 for result in delta_results if result.get("unchanged") is True),
        "receipts_written": sum(
            1 for result in delta_results if result.get("receipt_written") is True
        ),
        "receipts_reused": sum(
            1 for result in delta_results if result.get("receipt_reused") is True
        ),
        "receipts_deferred": bypassed_source_count,
        "loose_sources_imported_or_confirmed": len(cached_loose)
        - changed_count
        + len(delta_results),
        "bundled_sources_imported_or_confirmed": bundle_source_count,
        "events_imported": sum(int(result.get("imported", 0)) for result in delta_results),
        "events_skipped_existing": bypassed_event_count
        + sum(int(result.get("skipped_existing", 0)) for result in delta_results),
        "target_scans": target_scans,
        "target_records_scanned": target_records_scanned,
        "identity_index_mode": identity_index_mode,
        "identity_index_full_rebuild": identity_index_full_rebuild,
        "identity_index_entries_after": identity_index_entries_after,
        "source_index_path": str(source_index_path),
        "source_index_mode": "deferred_delta",
        "source_index_written": False,
        "source_index_file_bytes": source_index_file_bytes,
        "sources_reused": bypassed_source_count,
        "sources_revalidated": len(delta_prepared),
        "sources_changed": changed_count,
        "sources_added": added_count,
        "sources_removed": 0,
        "source_bytes_read": counters["source_bytes_read"],
        "source_bytes_hashed": counters["source_bytes_hashed"],
        "source_events_validated": counters["source_events_validated"],
        "bundle_inventory": [],
        "bundle_inventory_omitted": True,
        "errors": errors,
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }

    if (
        not errors
        and identity_index_entries_after is not None
        and delta_overlay_written
    ):
        with measured_phase("delta_checkpoint_publish"):
            final_source_index_identity = _private_file_identity(source_index_path)
            final_delta_index_identity = _private_file_identity(delta_index_path)
            final_delta_overlay_identity = _private_file_identity(delta_overlay_path)
            try:
                final_target_identity = storage.read_unique_storage_checkpoint_identity(DOMAIN)
            except storage.StorageError:
                final_target_identity = None
            if all(
                value is not None
                for value in (
                    source_inventory,
                    final_source_index_identity,
                    final_delta_index_identity,
                    final_delta_overlay_identity,
                    final_target_identity,
                )
            ):
                checkpoint_identity = {
                    "source_inventory": source_inventory,
                    "source_index_identity": final_source_index_identity,
                    "delta_index_identity": final_delta_index_identity,
                    "delta_overlay_identity": final_delta_overlay_identity,
                    "target_identity": final_target_identity,
                    "receipt_inventory_deferred": True,
                }
                if _publish_steady_checkpoint(
                    _steady_checkpoint_path(receipt_dir),
                    source_dir=source_dir,
                    identity=checkpoint_identity,
                    summary=_steady_summary_from_result(base_result),
                    previous=checkpoint,
                ):
                    counters["steady_checkpoint_writes"] += 1
                else:
                    counters["steady_checkpoint_reuses"] += 1

    counters["delta_fast_path_hits"] += 1
    elapsed_ns = time.perf_counter_ns() - import_started_ns
    telemetry = {
        "schema_version": "chronik-grabowski-import-telemetry.v1",
        "elapsed_seconds": round(elapsed_ns / 1_000_000_000, 6),
        "phases_seconds": {
            name: round(value / 1_000_000_000, 6)
            for name, value in sorted(phase_ns.items())
        },
        "counters": dict(sorted(counters.items())),
    }
    return {
        **base_result,
        "elapsed_seconds": telemetry["elapsed_seconds"],
        "import_telemetry": telemetry,
        "steady_fast_path": False,
        "delta_fast_path": True,
    }


def _source_index_semantic(document: dict[str, Any]) -> dict[str, Any]:
    return {
        key: document[key]
        for key in (
            "schema_version",
            "source_dir",
            "selection_contract",
            "loose_sources",
            "bundles",
            "historical_only",
            "does_not_establish",
        )
    }


def _publish_grabowski_source_index(
    path: Path,
    *,
    source_dir: Path,
    loose_sources: list[dict[str, Any]],
    bundles: list[dict[str, Any]],
    previous: dict[str, Any] | None,
) -> tuple[bool, int]:
    semantic = {
        "schema_version": GRABOWSKI_SOURCE_INDEX_SCHEMA,
        "source_dir": str(source_dir.resolve()),
        "selection_contract": sorted(HIGH_VALUE_KINDS),
        "loose_sources": sorted(loose_sources, key=lambda item: item["source_path"]),
        "bundles": sorted(bundles, key=lambda item: item["manifest_path"]),
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }
    if previous is not None and _source_index_semantic(previous) == semantic:
        return False, int(path.stat().st_size)
    document = {
        **semantic,
        "recorded_at": utc_now(),
    }
    document["index_sha256"] = sha256_bytes(canonical_bytes(document))
    raw = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    _atomic_write(path, raw)
    _fsync_directory(path.parent)
    return True, len(raw)


def _ledger_payloads_by_event_id() -> tuple[dict[str, bytes], int]:
    """Read one complete ledger snapshot and bind every event id to its payload."""
    snapshot = storage.read_domain_snapshot(DOMAIN)
    payloads: dict[str, bytes] = {}
    records_scanned = 0
    for line_number, raw_line in enumerate(snapshot.splitlines(), start=1):
        if not raw_line.strip():
            continue
        records_scanned += 1
        try:
            value = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise storage.StorageError(
                f"invalid ledger JSON at record {line_number}"
            ) from exc
        payload = value.get("payload", value) if isinstance(value, dict) else None
        if not isinstance(payload, dict):
            raise storage.StorageError(
                f"invalid ledger payload at record {line_number}"
            )
        event_id = payload.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise storage.StorageError(
                f"ledger record {line_number} has no event_id"
            )
        canonical = canonical_bytes(payload)
        previous = payloads.get(event_id)
        if previous is not None and previous != canonical:
            raise storage.StorageError(f"conflicting event_id in ledger: {event_id}")
        payloads.setdefault(event_id, canonical)
    return payloads, records_scanned


def _bundle_source_record(
    prepared: dict[str, Any], *, offset: int
) -> dict[str, Any]:
    events = prepared["events"]
    record = {
        "schema_version": GRABOWSKI_BUNDLE_ENTRY_SCHEMA,
        "source_path": str(prepared["source"].resolve()),
        "source_name": prepared["source"].name,
        "offset": offset,
        "source_sha256": prepared["source_sha256"],
        "source_bytes": len(prepared["raw"]),
        "event_ids": [event["event_id"] for event in events],
        "terminal_kind": events[-1]["kind"],
    }
    record["record_sha256"] = sha256_bytes(canonical_bytes(record))
    return record


def _decode_bundle_source(
    record: dict[str, Any],
    bundle_raw: bytes,
    *,
    expected_offset: int,
    source_dir: Path,
    receipt_dir: Path,
    manifest_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    expected_keys = {
        "schema_version",
        "source_path",
        "source_name",
        "offset",
        "source_sha256",
        "source_bytes",
        "event_ids",
        "terminal_kind",
        "record_sha256",
    }
    if set(record) != expected_keys:
        raise ValueError(f"invalid bundle source fields: {manifest_path}")
    if record["schema_version"] != GRABOWSKI_BUNDLE_ENTRY_SCHEMA:
        raise ValueError(f"unsupported bundle source schema: {manifest_path}")
    claimed_record_sha256 = record.get("record_sha256")
    if not isinstance(claimed_record_sha256, str):
        raise ValueError(f"invalid bundle source digest: {manifest_path}")
    unsigned = dict(record)
    unsigned.pop("record_sha256")
    if claimed_record_sha256 != sha256_bytes(canonical_bytes(unsigned)):
        raise ValueError(f"bundle source digest mismatch: {manifest_path}")
    source_path = record.get("source_path")
    source_name = record.get("source_name")
    if not isinstance(source_path, str) or not isinstance(source_name, str):
        raise ValueError(f"invalid bundled source identity: {manifest_path}")
    original_source = Path(source_path)
    if (
        not original_source.is_absolute()
        or original_source.name != source_name
        or Path(source_name).name != source_name
        or source_name in {"", ".", ".."}
        or not source_name.endswith(".jsonl")
    ):
        raise ValueError(f"invalid bundled source identity: {manifest_path}")
    offset = record.get("offset")
    source_bytes = record.get("source_bytes")
    if (
        type(offset) is not int
        or offset != expected_offset
        or type(source_bytes) is not int
        or source_bytes < 1
        or offset + source_bytes > len(bundle_raw)
    ):
        raise ValueError(f"invalid bundle source byte range: {manifest_path}")
    raw = bundle_raw[offset : offset + source_bytes]
    source_sha256 = record.get("source_sha256")
    if not isinstance(source_sha256, str) or source_sha256 != sha256_bytes(raw):
        raise ValueError(f"bundled source digest mismatch: {manifest_path}")
    source = source_dir.resolve() / source_name
    prepared = _prepare_grabowski_source_bytes(
        source,
        raw,
        receipt_dir=receipt_dir,
        source_origin="bundle",
        bundle_manifest_path=manifest_path,
    )
    expected_event_ids = [event["event_id"] for event in prepared["events"]]
    if record.get("event_ids") != expected_event_ids:
        raise ValueError(f"bundled event id list mismatch: {manifest_path}")
    terminal_kind = record.get("terminal_kind")
    if (
        terminal_kind not in GRABOWSKI_TERMINAL_KINDS
        or prepared["events"][-1]["kind"] != terminal_kind
    ):
        raise ValueError(f"bundled source is not terminal: {manifest_path}")
    return prepared, dict(record)


def _load_grabowski_bundle(
    manifest_path: Path,
    *,
    source_dir: Path,
    receipt_dir: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    manifest_raw, manifest_identity = _read_immutable_artifact_snapshot(
        manifest_path, label="bundle manifest"
    )
    if not manifest_raw.endswith(b"\n"):
        raise ValueError(f"incomplete bundle manifest: {manifest_path}")
    try:
        manifest = json.loads(manifest_raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid bundle manifest JSON: {manifest_path}") from exc
    expected_manifest_keys = {
        "schema_version",
        "domain",
        "bundle_file",
        "bundle_sha256",
        "bundle_bytes",
        "source_count",
        "event_count",
        "sources",
        "created_at",
        "historical_only",
        "does_not_establish",
        "manifest_sha256",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_manifest_keys:
        raise ValueError(f"invalid bundle manifest fields: {manifest_path}")
    if (
        manifest["schema_version"] != GRABOWSKI_BUNDLE_MANIFEST_SCHEMA
        or manifest["domain"] != DOMAIN
        or manifest["historical_only"] is not True
        or manifest["does_not_establish"] != DOES_NOT_ESTABLISH
    ):
        raise ValueError(f"invalid bundle manifest contract: {manifest_path}")
    claimed_manifest_sha256 = manifest.get("manifest_sha256")
    if not isinstance(claimed_manifest_sha256, str):
        raise ValueError(f"invalid manifest digest: {manifest_path}")
    unsigned_manifest = dict(manifest)
    unsigned_manifest.pop("manifest_sha256")
    if claimed_manifest_sha256 != sha256_bytes(canonical_bytes(unsigned_manifest)):
        raise ValueError(f"bundle manifest digest mismatch: {manifest_path}")
    created_at = manifest.get("created_at")
    if not isinstance(created_at, str):
        raise ValueError(f"invalid bundle creation timestamp: {manifest_path}")
    _parse_timestamp(created_at, field="created_at")
    bundle_file = manifest.get("bundle_file")
    bundle_sha256 = manifest.get("bundle_sha256")
    if not isinstance(bundle_file, str) or Path(bundle_file).name != bundle_file:
        raise ValueError(f"invalid bundle filename: {manifest_path}")
    if not isinstance(bundle_sha256, str) or len(bundle_sha256) != 64:
        raise ValueError(f"invalid bundle digest: {manifest_path}")
    expected_prefix = f"grabowski-{bundle_sha256}"
    if (
        bundle_file != f"{expected_prefix}.bundle.jsonl"
        or manifest_path.name != f"{expected_prefix}.manifest.json"
    ):
        raise ValueError(f"bundle filename is not digest-bound: {manifest_path}")
    bundle_path = manifest_path.parent / bundle_file
    if bundle_path.parent.resolve() != manifest_path.parent.resolve():
        raise ValueError(f"bundle path escapes bundle directory: {manifest_path}")
    bundle_raw, bundle_identity = _read_immutable_artifact_snapshot(
        bundle_path, label="bundle file"
    )
    bundle_bytes = manifest.get("bundle_bytes")
    if type(bundle_bytes) is not int or bundle_bytes < 1 or bundle_bytes != len(bundle_raw):
        raise ValueError(f"bundle byte count mismatch: {bundle_path}")
    if sha256_bytes(bundle_raw) != bundle_sha256:
        raise ValueError(f"bundle digest mismatch: {bundle_path}")
    if not bundle_raw.endswith(b"\n"):
        raise ValueError(f"incomplete bundle JSONL: {bundle_path}")
    source_records = manifest.get("sources")
    if not isinstance(source_records, list) or not source_records:
        raise ValueError(f"empty bundle is forbidden: {manifest_path}")
    prepared_sources: list[dict[str, Any]] = []
    validated_records: list[dict[str, Any]] = []
    names: set[str] = set()
    original_paths: set[str] = set()
    expected_offset = 0
    for record in source_records:
        if not isinstance(record, dict):
            raise ValueError(f"bundle source must be an object: {manifest_path}")
        prepared, validated = _decode_bundle_source(
            record,
            bundle_raw,
            expected_offset=expected_offset,
            source_dir=source_dir,
            receipt_dir=receipt_dir,
            manifest_path=manifest_path,
        )
        source_name = validated["source_name"]
        source_path = validated["source_path"]
        if source_name in names or source_path in original_paths:
            raise ValueError(f"duplicate source in bundle: {manifest_path}")
        names.add(source_name)
        original_paths.add(source_path)
        prepared_sources.append(prepared)
        validated_records.append(validated)
        expected_offset += validated["source_bytes"]
    if expected_offset != len(bundle_raw):
        raise ValueError(f"bundle has unassigned trailing bytes: {bundle_path}")
    source_count = manifest.get("source_count")
    event_count = manifest.get("event_count")
    if (
        type(source_count) is not int
        or source_count != len(prepared_sources)
        or type(event_count) is not int
        or event_count != sum(len(item["events"]) for item in prepared_sources)
    ):
        raise ValueError(f"bundle manifest inventory mismatch: {manifest_path}")
    return prepared_sources, {
        "manifest_path": str(manifest_path),
        "manifest_sha256": claimed_manifest_sha256,
        "bundle_path": str(bundle_path),
        "bundle_sha256": bundle_sha256,
        "bundle_bytes": bundle_bytes,
        "source_count": source_count,
        "event_count": event_count,
        "sources": validated_records,
        "manifest_bytes": len(manifest_raw),
        "manifest_identity": dict(zip(_FILE_IDENTITY_FIELDS, manifest_identity)),
        "bundle_identity": dict(zip(_FILE_IDENTITY_FIELDS, bundle_identity)),
    }


def _grabowski_archive_index_document(
    bundle_metadata: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    metadata = sorted(bundle_metadata, key=lambda item: item["manifest_path"])
    manifests = [
        {
            "file": Path(item["manifest_path"]).name,
            "sha256": item["manifest_sha256"],
        }
        for item in metadata
    ]
    sources: list[dict[str, Any]] = []
    seen_generations: set[tuple[str, str]] = set()
    for manifest_index, item in enumerate(metadata):
        for source in item["sources"]:
            source_name = source["source_name"]
            source_sha256 = source["source_sha256"]
            generation = (source_name, source_sha256)
            if generation in seen_generations:
                raise ValueError(
                    f"duplicate archived source generation: {source_name} {source_sha256}"
                )
            seen_generations.add(generation)
            sources.append(
                {
                    "source_name": source_name,
                    "source_sha256": source_sha256,
                    "event_ids": list(source["event_ids"]),
                    "manifest_index": manifest_index,
                }
            )
    sources.sort(key=lambda item: (item["source_name"], item["source_sha256"]))
    index = {
        "schema_version": GRABOWSKI_ARCHIVE_INDEX_SCHEMA,
        "domain": DOMAIN,
        "manifest_count": len(manifests),
        "source_count": len(sources),
        "manifests": manifests,
        "sources": sources,
        "historical_only": True,
        "authoritative": False,
        "reconstructible": True,
        "does_not_establish": [
            *DOES_NOT_ESTABLISH,
            "bundle_or_source_authority",
            "future_outbox_write_suppression",
        ],
    }
    index["index_sha256"] = sha256_bytes(canonical_bytes(index))
    return index


def _validate_grabowski_archive_index(
    raw: bytes,
    *,
    path: Path,
    expected: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not raw.endswith(b"\n"):
        raise ValueError(f"incomplete archive index: {path}")
    try:
        index = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid archive index JSON: {path}") from exc
    expected_keys = {
        "schema_version",
        "domain",
        "manifest_count",
        "source_count",
        "manifests",
        "sources",
        "historical_only",
        "authoritative",
        "reconstructible",
        "does_not_establish",
        "index_sha256",
    }
    if not isinstance(index, dict) or set(index) != expected_keys:
        raise ValueError(f"invalid archive index fields: {path}")
    if (
        index["schema_version"] != GRABOWSKI_ARCHIVE_INDEX_SCHEMA
        or index["domain"] != DOMAIN
        or index["historical_only"] is not True
        or index["authoritative"] is not False
        or index["reconstructible"] is not True
        or index["does_not_establish"]
        != [
            *DOES_NOT_ESTABLISH,
            "bundle_or_source_authority",
            "future_outbox_write_suppression",
        ]
    ):
        raise ValueError(f"invalid archive index contract: {path}")
    claimed_sha256 = index.get("index_sha256")
    if not isinstance(claimed_sha256, str):
        raise ValueError(f"invalid archive index digest: {path}")
    unsigned = dict(index)
    unsigned.pop("index_sha256")
    if claimed_sha256 != sha256_bytes(canonical_bytes(unsigned)):
        raise ValueError(f"archive index digest mismatch: {path}")

    def valid_sha256(value: Any) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value)
        )

    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise ValueError(f"invalid archive index manifests: {path}")
    manifest_files: list[str] = []
    for manifest in manifests:
        if not isinstance(manifest, dict) or set(manifest) != {"file", "sha256"}:
            raise ValueError(f"invalid archive index manifest fields: {path}")
        manifest_file = manifest.get("file")
        if (
            not isinstance(manifest_file, str)
            or Path(manifest_file).name != manifest_file
            or not manifest_file.endswith(".manifest.json")
            or not valid_sha256(manifest.get("sha256"))
        ):
            raise ValueError(f"invalid archive index manifest contract: {path}")
        manifest_files.append(manifest_file)
    if manifest_files != sorted(manifest_files) or len(manifest_files) != len(
        set(manifest_files)
    ):
        raise ValueError(f"archive index manifests are not unique and sorted: {path}")

    sources = index.get("sources")
    if not isinstance(sources, list):
        raise ValueError(f"invalid archive index sources: {path}")
    generations: list[tuple[str, str]] = []
    source_keys = {"source_name", "source_sha256", "event_ids", "manifest_index"}
    for source in sources:
        if not isinstance(source, dict) or set(source) != source_keys:
            raise ValueError(f"invalid archive index source fields: {path}")
        source_name = source.get("source_name")
        event_ids = source.get("event_ids")
        manifest_index = source.get("manifest_index")
        if (
            not isinstance(source_name, str)
            or Path(source_name).name != source_name
            or not source_name.endswith(".jsonl")
            or not valid_sha256(source.get("source_sha256"))
            or not isinstance(event_ids, list)
            or not event_ids
            or len(event_ids) != len(set(event_ids))
            or any(
                not isinstance(event_id, str)
                or not event_id.startswith("sha256:")
                or not valid_sha256(event_id.removeprefix("sha256:"))
                for event_id in event_ids
            )
            or type(manifest_index) is not int
            or manifest_index < 0
            or manifest_index >= len(manifests)
        ):
            raise ValueError(f"invalid archive index source contract: {path}")
        generations.append((source_name, source["source_sha256"]))
    if generations != sorted(generations) or len(generations) != len(
        set(generations)
    ):
        raise ValueError(
            f"archive index source generations are not unique and sorted: {path}"
        )
    if (
        type(index.get("manifest_count")) is not int
        or index["manifest_count"] != len(manifests)
        or type(index.get("source_count")) is not int
        or index["source_count"] != len(sources)
    ):
        raise ValueError(f"archive index inventory mismatch: {path}")
    if expected is not None and index != expected:
        raise ValueError(f"archive index readback mismatch: {path}")
    return index


def _refresh_grabowski_archive_index(
    *,
    source_dir: Path,
    bundle_dir: Path,
    receipt_dir: Path,
) -> dict[str, Any] | None:
    manifest_paths = (
        sorted(bundle_dir.glob("*.manifest.json")) if bundle_dir.is_dir() else []
    )
    if not manifest_paths:
        return None
    metadata: list[dict[str, Any]] = []
    for manifest_path in manifest_paths:
        _, item = _load_grabowski_bundle(
            manifest_path,
            source_dir=source_dir,
            receipt_dir=receipt_dir,
        )
        metadata.append(item)
    index = _grabowski_archive_index_document(metadata)
    index_path = bundle_dir / GRABOWSKI_ARCHIVE_INDEX_FILENAME
    raw = canonical_bytes(index) + b"\n"
    published = True
    try:
        existing_state = index_path.lstat()
    except FileNotFoundError:
        existing = None
    else:
        if not stat.S_ISREG(existing_state.st_mode):
            raise ValueError(f"archive index must be a regular file: {index_path}")
        existing = index_path.read_bytes()
    if existing == raw:
        published = False
    else:
        _atomic_write(index_path, raw)
        _fsync_directory(bundle_dir)
    readback = _read_immutable_artifact(index_path, label="archive index")
    validated = _validate_grabowski_archive_index(
        readback, path=index_path, expected=index
    )
    return {
        "path": str(index_path),
        "index_sha256": validated["index_sha256"],
        "file_sha256": sha256_bytes(readback),
        "manifest_count": validated["manifest_count"],
        "source_count": validated["source_count"],
        "published": published,
    }


def _merge_prepared_grabowski_sources(
    prepared_sources: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for prepared in prepared_sources:
        source_path = str(prepared["source"].resolve())
        source_sha256 = prepared.get("source_sha256")
        if not isinstance(source_sha256, str):
            raise ValueError(f"prepared source lacks SHA-256 identity: {source_path}")
        key = (source_path, source_sha256)
        previous = merged.get(key)
        if previous is None:
            merged[key] = prepared
            continue
        if (
            _prepared_source_bytes(previous) != _prepared_source_bytes(prepared)
            or previous["event_fingerprints"] != prepared["event_fingerprints"]
        ):
            raise ValueError(f"source SHA-256 collision or cache drift: {source_path}")
        if (
            previous.get("source_origin") == "bundle"
            and prepared.get("source_origin") == "loose"
        ):
            merged[key] = prepared
    result = [merged[key] for key in sorted(merged)]
    generation_counts = Counter(str(item["source"].resolve()) for item in result)
    for prepared in result:
        source_path = str(prepared["source"].resolve())
        if generation_counts[source_path] <= 1:
            continue
        prepared["receipt_path"] = _receipt_path(
            prepared["source"],
            prepared["receipt_path"].parent,
            prepared["source_sha256"],
        )
    return result


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_bundle_directory(source_dir: Path, bundle_dir: Path) -> None:
    try:
        bundle_dir.mkdir(mode=0o700)
    except FileExistsError:
        pass
    try:
        bundle_state = bundle_dir.lstat()
    except OSError as exc:
        raise ValueError(f"cannot inspect bundle directory: {bundle_dir}") from exc
    if not stat.S_ISDIR(bundle_state.st_mode):
        raise ValueError(f"bundle directory must be a real directory: {bundle_dir}")
    if bundle_dir.resolve().parent != source_dir.resolve():
        raise ValueError(f"bundle directory escapes source directory: {bundle_dir}")
    _fsync_directory(source_dir)


def _read_immutable_artifact_snapshot(
    path: Path, *, label: str
) -> tuple[bytes, tuple[int, ...]]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot inspect {label}: {path}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{label} must be a regular file: {path}")
    try:
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot read {label}: {path}") from exc
    if _file_identity(before) != _file_identity(after):
        raise ValueError(f"{label} changed while reading: {path}")
    return raw, _file_identity(after)


def _read_immutable_artifact(path: Path, *, label: str) -> bytes:
    raw, _ = _read_immutable_artifact_snapshot(path, label=label)
    return raw


def _publish_immutable(path: Path, data: bytes) -> bool:
    """Publish bytes without replacing an existing immutable artifact."""
    try:
        parent_state = path.parent.lstat()
    except OSError as exc:
        raise ValueError(f"cannot inspect artifact directory: {path.parent}") from exc
    if not stat.S_ISDIR(parent_state.st_mode):
        raise ValueError(f"artifact directory must be a real directory: {path.parent}")
    try:
        existing_state = path.lstat()
    except FileNotFoundError:
        existing = None
    else:
        if not stat.S_ISREG(existing_state.st_mode):
            raise ValueError(f"immutable artifact must be a regular file: {path}")
        existing = path.read_bytes()
    if existing is not None:
        if existing != data:
            raise ValueError(f"immutable artifact conflict: {path}")
        return False
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != data:
                raise ValueError(f"immutable artifact conflict: {path}")
            return False
        _fsync_directory(path.parent)
        if path.read_bytes() != data:
            raise OSError(f"immutable artifact readback failed: {path}")
        return True
    finally:
        temporary.unlink(missing_ok=True)


def _source_still_matches(prepared: dict[str, Any]) -> bool:
    source = prepared["source"]
    expected_identity = prepared.get("source_identity")
    if expected_identity is None:
        return False
    try:
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode):
            return False
        raw = source.read_bytes()
        after = source.lstat()
    except OSError:
        return False
    return (
        _file_identity(before) == expected_identity
        and _file_identity(after) == expected_identity
        and sha256_bytes(raw) == prepared["source_sha256"]
    )


def _unlink_loose_source(path: Path) -> None:
    path.unlink()


def _write_grabowski_outbox_receipt(
    prepared: dict[str, Any],
    *,
    written: int,
    skipped: int,
    target_scans: int,
    target_records_scanned: int,
) -> dict[str, Any]:
    source = prepared["source"]
    event_ids = _prepared_event_ids(prepared)
    source_bytes = _prepared_source_bytes(prepared)
    receipt_path = prepared["receipt_path"]
    previous_receipt = prepared.get("previous_receipt")
    if (
        prepared["source_unchanged"]
        and written == 0
        and skipped == len(event_ids)
        and prepared.get("previous_receipt_path") == receipt_path
        and _receipt_matches_prepared_source(prepared, previous_receipt)
    ):
        # The authoritative ledger was still scanned above. Reusing this intact
        # source-bound receipt only suppresses an identical filesystem rewrite.
        return {
            "schema_version": previous_receipt["schema_version"],
            "domain": previous_receipt["domain"],
            "source_path": previous_receipt["source_path"],
            "source_sha256": previous_receipt["source_sha256"],
            "source_bytes": previous_receipt["source_bytes"],
            "selection_contract": previous_receipt["selection_contract"],
            "event_ids": previous_receipt["event_ids"],
            "requested": previous_receipt["requested"],
            "imported": written,
            "skipped_existing": skipped,
            "batch_target_scans": target_scans,
            "batch_target_records_scanned": target_records_scanned,
            "recorded_at": previous_receipt["recorded_at"],
            "historical_only": previous_receipt["historical_only"],
            "does_not_establish": previous_receipt["does_not_establish"],
            "receipt_sha256": previous_receipt["receipt_sha256"],
            "receipt_digest_scope": "persisted_receipt",
            "unchanged": True,
            "receipt_path": str(receipt_path),
            "receipt_reused": True,
            "receipt_written": False,
            "source_origin": prepared.get("source_origin", "loose"),
            "bundle_manifest_path": (
                str(prepared["bundle_manifest_path"])
                if prepared.get("bundle_manifest_path") is not None
                else None
            ),
        }
    receipt = {
        "schema_version": "chronik-grabowski-outbox-import.v1",
        "domain": DOMAIN,
        "source_path": str(source.resolve()),
        "source_sha256": prepared["source_sha256"],
        "source_bytes": source_bytes,
        "selection_contract": sorted(HIGH_VALUE_KINDS),
        "event_ids": sorted(event_ids),
        "requested": len(event_ids),
        "imported": written,
        "skipped_existing": skipped,
        "batch_target_scans": target_scans,
        "batch_target_records_scanned": target_records_scanned,
        "recorded_at": utc_now(),
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
    _atomic_write(
        receipt_path,
        json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8") + b"\n",
    )
    return {
        **receipt,
        "unchanged": prepared["source_unchanged"],
        "receipt_path": str(receipt_path),
        "receipt_digest_scope": "persisted_receipt",
        "receipt_reused": False,
        "receipt_written": True,
        "source_origin": prepared.get("source_origin", "loose"),
        "bundle_manifest_path": (
            str(prepared["bundle_manifest_path"])
            if prepared.get("bundle_manifest_path") is not None
            else None
        ),
    }


def _import_prepared_grabowski_sources(
    prepared_sources: list[dict[str, Any]],
    *,
    authoritative_replay: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, object], list[tuple[str, Exception]]]:
    materialized_groups: list[tuple[str, list[str]]] = []
    verified_existing_groups: list[tuple[str, list[tuple[str, bytes]]]] = []
    for index, prepared in enumerate(prepared_sources):
        group_id = str(index)
        if prepared.get("source_index_cached") is True:
            verified_existing_groups.append(
                (group_id, list(prepared["event_fingerprints"]))
            )
            continue
        events = prepared.get("events")
        if not isinstance(events, list):
            raise storage.StorageError("validated source events are unavailable")
        materialized_groups.append((group_id, _envelope_lines(events)))
    grouped = storage.write_payload_unique_groups(
        DOMAIN,
        materialized_groups,
        authoritative_replay=authoritative_replay,
        verified_existing_groups=verified_existing_groups,
    )
    raw_group_results = grouped.get("groups")
    if not isinstance(raw_group_results, list):
        raise storage.StorageError("grouped write omitted per-source results")
    group_results = {
        str(item.get("group_id")): item
        for item in raw_group_results
        if isinstance(item, dict)
    }
    target_scans = int(grouped.get("target_scans", 0))
    target_records_scanned = int(grouped.get("target_records_scanned", 0))
    results: list[dict[str, Any]] = []
    receipt_errors: list[tuple[str, Exception]] = []
    for index, prepared in enumerate(prepared_sources):
        stats = group_results.get(str(index))
        if stats is None:
            raise storage.StorageError(f"grouped write omitted source group {index}")
        written = int(stats.get("written", 0))
        skipped = int(stats.get("skipped", 0))
        try:
            result = _write_grabowski_outbox_receipt(
                prepared,
                written=written,
                skipped=skipped,
                target_scans=target_scans,
                target_records_scanned=target_records_scanned,
            )
        except (OSError, ValueError, storage.StorageError) as exc:
            result = {
                "source_path": str(prepared["source"].resolve()),
                "imported": written,
                "skipped_existing": skipped,
                "unchanged": prepared["source_unchanged"],
                "receipt_reused": False,
                "receipt_written": False,
                "source_origin": prepared.get("source_origin", "loose"),
                "bundle_manifest_path": (
                    str(prepared["bundle_manifest_path"])
                    if prepared.get("bundle_manifest_path") is not None
                    else None
                ),
            }
            receipt_errors.append((str(prepared["source"]), exc))
        results.append(result)
    return results, grouped, receipt_errors


def import_grabowski_outbox_file(source: Path, *, receipt_dir: Path) -> dict[str, Any]:
    prepared = _prepare_grabowski_outbox_source(source, receipt_dir=receipt_dir)
    results, _, receipt_errors = _import_prepared_grabowski_sources([prepared])
    if receipt_errors:
        raise receipt_errors[0][1]
    return results[0]


def import_grabowski_outbox(
    *,
    outbox_root: Path,
    receipt_dir: Path,
    allow_steady_fast_path: bool = False,
) -> dict[str, Any]:
    import_started_ns = time.perf_counter_ns()
    phase_ns: Counter[str] = Counter()
    counters: Counter[str] = Counter()

    @contextmanager
    def measured_phase(name: str):
        started_ns = time.perf_counter_ns()
        try:
            yield
        finally:
            phase_ns[name] += time.perf_counter_ns() - started_ns

    source_dir = outbox_root.expanduser() / "grabowski" / "chronik-outbox"
    bundle_dir = source_dir / GRABOWSKI_BUNDLE_DIRNAME
    source_index_path = _source_index_path(receipt_dir)
    delta_index_path = _delta_index_path(receipt_dir)
    delta_overlay_path = _delta_overlay_path(receipt_dir)
    with measured_phase("inventory"):
        sources = sorted(source_dir.glob("*.jsonl")) if source_dir.is_dir() else []
        manifests = (
            sorted(bundle_dir.glob("*.manifest.json"))
            if bundle_dir.is_dir()
            else []
        )
        bundle_files = (
            sorted(bundle_dir.glob("*.bundle.jsonl"))
            if bundle_dir.is_dir()
            else []
        )
    counters["loose_sources_discovered"] = len(sources)
    counters["bundle_manifests_discovered"] = len(manifests)
    counters["bundle_files_discovered"] = len(bundle_files)

    steady_checkpoint_path = _steady_checkpoint_path(receipt_dir)
    prior_steady_checkpoint = _load_steady_checkpoint(
        steady_checkpoint_path, source_dir=source_dir
    )
    delta_candidate_identity: dict[str, Any] | None = None
    if allow_steady_fast_path and prior_steady_checkpoint is not None:
        with measured_phase("steady_fast_path"):
            initial_source_inventory = _stable_source_inventory_identity(
                source_dir=source_dir,
                bundle_dir=bundle_dir,
                sources=sources,
                manifests=manifests,
                bundle_files=bundle_files,
            )
            prior_identity = prior_steady_checkpoint.get("identity")
            if initial_source_inventory is not None and isinstance(prior_identity, dict):
                if initial_source_inventory == prior_identity.get("source_inventory"):
                    current_fast_identity = _steady_fast_identity(
                        source_dir=source_dir,
                        bundle_dir=bundle_dir,
                        sources=sources,
                        manifests=manifests,
                        bundle_files=bundle_files,
                        receipt_dir=receipt_dir,
                        source_index_path=source_index_path,
                        delta_index_path=delta_index_path,
                        delta_overlay_path=delta_overlay_path,
                        initial_source_inventory=initial_source_inventory,
                    )
                    if (
                        current_fast_identity is not None
                        and current_fast_identity == prior_identity
                    ):
                        return _steady_fast_result(
                            prior_steady_checkpoint,
                            source_dir=source_dir,
                            receipt_dir=receipt_dir,
                            source_index_path=source_index_path,
                            import_started_ns=import_started_ns,
                            phase_ns=phase_ns,
                            counters=counters,
                        )
                else:
                    current_fast_identity = _delta_candidate_identity(
                        checkpoint=prior_steady_checkpoint,
                        source_dir=source_dir,
                        bundle_dir=bundle_dir,
                        sources=sources,
                        manifests=manifests,
                        bundle_files=bundle_files,
                        receipt_dir=receipt_dir,
                        source_index_path=source_index_path,
                        delta_index_path=delta_index_path,
                        delta_overlay_path=delta_overlay_path,
                        source_inventory=initial_source_inventory,
                    )
                    if (
                        current_fast_identity is not None
                        and _checkpoint_allows_source_only_delta(
                            prior_steady_checkpoint, current_fast_identity
                        )
                    ):
                        delta_candidate_identity = current_fast_identity
            counters["steady_fast_path_fallbacks"] += 1

    target_path = storage.safe_target_path(DOMAIN)
    target_missing_or_empty = not target_path.exists() or target_path.stat().st_size == 0
    if delta_candidate_identity is not None and not target_missing_or_empty:
        with measured_phase("delta_index_load"):
            delta_index, delta_index_bytes, delta_index_mode = _load_delta_index(
                delta_index_path,
                source_dir=source_dir,
                bundle_dir=bundle_dir,
            )
            delta_overlay = None
            delta_overlay_bytes = 0
            delta_overlay_mode = "rebuild_missing"
            if delta_index is not None and delta_index_mode == "steady":
                delta_overlay, delta_overlay_bytes, delta_overlay_mode = (
                    _load_delta_overlay(
                        delta_overlay_path,
                        source_dir=source_dir,
                        base_index_sha256=str(delta_index["index_sha256"]),
                    )
                )
        counters["delta_index_bytes_read"] = delta_index_bytes
        counters["delta_overlay_bytes_read"] = delta_overlay_bytes
        if (
            delta_index is not None
            and delta_index_mode == "steady"
            and delta_overlay is not None
            and delta_overlay_mode == "steady"
        ):
            delta_result = _try_checkpoint_delta_import(
                checkpoint=prior_steady_checkpoint,
                current_identity=delta_candidate_identity,
                delta_index=delta_index,
                delta_overlay=delta_overlay,
                source_dir=source_dir,
                bundle_dir=bundle_dir,
                sources=sources,
                manifests=manifests,
                bundle_files=bundle_files,
                receipt_dir=receipt_dir,
                source_index_path=source_index_path,
                delta_index_path=delta_index_path,
                delta_overlay_path=delta_overlay_path,
                import_started_ns=import_started_ns,
                phase_ns=phase_ns,
                counters=counters,
                measured_phase=measured_phase,
            )
            if delta_result is not None:
                return delta_result
        if delta_index_mode == "rebuild_invalid":
            counters["delta_index_invalid"] += 1
        if delta_overlay_mode == "rebuild_invalid":
            counters["delta_overlay_invalid"] += 1
        counters["delta_fast_path_fallbacks"] += 1

    with measured_phase("source_index_load"):
        source_index, source_index_bytes, source_index_mode = (
            _load_grabowski_source_index(
                source_index_path,
                source_dir=source_dir,
                bundle_dir=bundle_dir,
            )
        )
    counters["source_index_bytes_read"] = source_index_bytes
    if source_index_mode == "rebuild_invalid":
        counters["source_index_invalid"] = 1
    cache_allowed = source_index is not None and not target_missing_or_empty
    if source_index is not None and target_missing_or_empty:
        source_index_mode = "authoritative_rebuild"

    cached_loose = {
        item["source_path"]: item
        for item in (source_index or {}).get("_loose_sources", [])
    }
    cached_bundles = {
        item["manifest_path"]: item
        for item in (source_index or {}).get("_bundles", [])
    }
    all_prepared: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    bundle_metadata: list[dict[str, Any]] = []
    loose_index_records: list[dict[str, Any]] = []
    bundle_index_records: list[dict[str, Any]] = []
    referenced_bundle_paths: set[str] = set()
    with measured_phase("source_discovery"):
        for source in sources:
            resolved_source = str(source.resolve())
            cached = cached_loose.get(resolved_source)
            counters["source_artifacts_metadata_checked"] += 1
            try:
                if (
                    cache_allowed
                    and cached is not None
                    and _file_matches_source_index(source, cached["_identity"])
                ):
                    prepared = _cached_prepared_source(
                        cached,
                        receipt_dir=receipt_dir,
                        source_origin="loose",
                    )
                    counters["sources_reused"] += 1
                else:
                    if cached is None:
                        counters["sources_added"] += 1
                    else:
                        counters["sources_changed"] += 1
                    prepared = _prepare_grabowski_outbox_source(
                        source, receipt_dir=receipt_dir
                    )
                    counters["sources_revalidated"] += 1
                    counters["source_bytes_read"] += _prepared_source_bytes(prepared)
                    counters["source_bytes_hashed"] += _prepared_source_bytes(prepared)
                    counters["source_events_validated"] += _prepared_event_count(prepared)
                all_prepared.append(prepared)
                loose_index_records.append(
                    _source_index_source_record(prepared, loose=True)
                )
            except (OSError, ValueError, storage.StorageError) as exc:
                errors.append({"source_path": str(source), "error": str(exc)})
        for manifest_path in manifests:
            resolved_manifest = str(manifest_path.resolve())
            cached = cached_bundles.get(resolved_manifest)
            counters["source_artifacts_metadata_checked"] += 1
            try:
                cached_bundle_path = (
                    Path(cached["bundle_path"]) if cached is not None else None
                )
                bundle_cache_hit = (
                    cache_allowed
                    and cached is not None
                    and _file_matches_source_index(
                        manifest_path, cached["_manifest_identity"]
                    )
                    and cached_bundle_path is not None
                    and _file_matches_source_index(
                        cached_bundle_path, cached["_bundle_identity"]
                    )
                )
                counters["source_artifacts_metadata_checked"] += 1
                if bundle_cache_hit:
                    bundled = [
                        _cached_prepared_source(
                            item,
                            receipt_dir=receipt_dir,
                            source_origin="bundle",
                            bundle_manifest_path=manifest_path,
                        )
                        for item in cached["_sources"]
                    ]
                    metadata = dict(cached["metadata"])
                    bundle_index_record = {
                        key: cached[key]
                        for key in (
                            "manifest_path",
                            "manifest_identity",
                            "bundle_path",
                            "bundle_identity",
                            "metadata",
                            "sources",
                        )
                    }
                    counters["sources_reused"] += len(bundled)
                else:
                    bundled, loaded_metadata = _load_grabowski_bundle(
                        manifest_path,
                        source_dir=source_dir,
                        receipt_dir=receipt_dir,
                    )
                    metadata = {
                        key: loaded_metadata[key]
                        for key in (
                            "manifest_path",
                            "manifest_sha256",
                            "bundle_path",
                            "bundle_sha256",
                            "bundle_bytes",
                            "source_count",
                            "event_count",
                            "sources",
                        )
                    }
                    bundle_index_record = _source_index_bundle_record(
                        bundled, loaded_metadata
                    )
                    if cached is None:
                        counters["sources_added"] += len(bundled)
                    else:
                        counters["sources_changed"] += len(bundled)
                    counters["sources_revalidated"] += len(bundled)
                    counters["source_bytes_read"] += int(
                        loaded_metadata["bundle_bytes"]
                    )
                    counters["source_bytes_hashed"] += 2 * int(
                        loaded_metadata["bundle_bytes"]
                    )
                    counters["source_events_validated"] += int(
                        loaded_metadata["event_count"]
                    )
                    counters["manifest_bytes_read"] += int(
                        loaded_metadata["manifest_bytes"]
                    )
                all_prepared.extend(bundled)
                bundle_metadata.append(metadata)
                bundle_index_records.append(bundle_index_record)
                referenced_bundle_paths.add(str(Path(metadata["bundle_path"]).resolve()))
            except (OSError, ValueError, storage.StorageError) as exc:
                errors.append({"source_path": str(manifest_path), "error": str(exc)})
    orphan_bundles = [
        path
        for path in bundle_files
        if str(path.resolve()) not in referenced_bundle_paths
    ]
    errors.extend(
        {
            "source_path": str(path),
            "error": "orphan bundle has no valid manifest and was ignored",
        }
        for path in orphan_bundles
    )
    target_scans: int | None = 0
    target_records_scanned: int | None = 0
    identity_index_mode: str | None = "unused"
    identity_index_full_rebuild: bool | None = False
    identity_index_entries_after: int | None = 0
    prepared_sources: list[dict[str, Any]] = []
    receipt_writes_succeeded = True
    merge_succeeded = False
    with measured_phase("source_merge"):
        try:
            prepared_sources = _merge_prepared_grabowski_sources(all_prepared)
            merge_succeeded = True
        except ValueError as exc:
            target_scans = None
            target_records_scanned = None
            identity_index_mode = None
            identity_index_full_rebuild = None
            identity_index_entries_after = None
            errors.append({"source_path": "<batch>", "error": str(exc)})
    ledger_reconciled = not prepared_sources and merge_succeeded
    if prepared_sources and target_scans is not None:
        with measured_phase("ledger_reconcile"):
            try:
                authoritative_replay = target_missing_or_empty and not errors
                results, grouped, receipt_errors = _import_prepared_grabowski_sources(
                    prepared_sources,
                    authoritative_replay=authoritative_replay,
                )
                ledger_reconciled = True
                receipt_writes_succeeded = not receipt_errors
                target_scans = int(grouped.get("target_scans", 0))
                target_records_scanned = int(
                    grouped.get("target_records_scanned", 0)
                )
                identity_index_mode = str(
                    grouped.get("identity_index_mode", "unknown")
                )
                identity_index_full_rebuild = bool(
                    grouped.get("identity_index_full_rebuild", False)
                )
                identity_index_entries_after = int(
                    grouped.get("identity_index_entries_after", 0)
                )
                errors.extend(
                    {
                        "source_path": source_path,
                        "error": f"receipt write failed after ledger update: {exc}",
                    }
                    for source_path, exc in receipt_errors
                )
            except (OSError, ValueError, storage.StorageError) as exc:
                target_scans = None
                target_records_scanned = None
                identity_index_mode = None
                identity_index_full_rebuild = None
                identity_index_entries_after = None
                errors.append({"source_path": "<batch>", "error": str(exc)})

    source_index_written = False
    source_index_file_bytes = source_index_bytes
    if (
        ledger_reconciled
        and receipt_writes_succeeded
        and (loose_index_records or bundle_index_records or source_index is not None)
    ):
        with measured_phase("source_index_publish"):
            try:
                source_index_written, source_index_file_bytes = (
                    _publish_grabowski_source_index(
                        source_index_path,
                        source_dir=source_dir,
                        loose_sources=loose_index_records,
                        bundles=bundle_index_records,
                        previous=source_index,
                    )
                )
            except (OSError, ValueError) as exc:
                errors.append(
                    {
                        "source_path": str(source_index_path),
                        "error": f"source index update failed after ledger reconciliation: {exc}",
                    }
                )
    if source_index is not None:
        previous_source_count = len(source_index.get("_loose_sources", [])) + sum(
            len(item["_sources"]) for item in source_index.get("_bundles", [])
        )
        current_source_count = len(loose_index_records) + sum(
            len(item["sources"]) for item in bundle_index_records
        )
        counters["sources_removed"] = max(0, previous_source_count - current_source_count)
    if source_index_written:
        counters["source_index_writes"] = 1
        if source_index_mode == "steady":
            source_index_mode = "updated"
    elif source_index is not None and source_index_mode == "steady":
        counters["source_index_reuses"] = 1

    delta_index_written = False
    if ledger_reconciled and receipt_writes_succeeded and not errors:
        with measured_phase("delta_index_publish"):
            try:
                delta_loose_records = [
                    _delta_source_record_from_source_record(item)
                    for item in loose_index_records
                ]
                delta_bundle_records = [
                    _delta_bundle_record_from_source_record(item)
                    for item in bundle_index_records
                ]
                delta_index_written, _ = _publish_delta_index(
                    delta_index_path,
                    source_dir=source_dir,
                    loose_sources=delta_loose_records,
                    bundles=delta_bundle_records,
                )
                if delta_index_written:
                    counters["delta_index_writes"] += 1
            except (OSError, ValueError) as exc:
                errors.append(
                    {
                        "source_path": str(delta_index_path),
                        "error": f"delta index update failed after ledger reconciliation: {exc}",
                    }
                )

    delta_overlay_written = False
    if ledger_reconciled and receipt_writes_succeeded and not errors:
        with measured_phase("delta_overlay_publish"):
            try:
                published_delta_index, _, published_delta_mode = _load_delta_index(
                    delta_index_path,
                    source_dir=source_dir,
                    bundle_dir=bundle_dir,
                )
                if published_delta_index is None or published_delta_mode != "steady":
                    raise ValueError("published delta index is not readable")
                delta_overlay_written, _ = _publish_delta_overlay(
                    delta_overlay_path,
                    source_dir=source_dir,
                    base_index_sha256=str(published_delta_index["index_sha256"]),
                    records=[],
                )
                if delta_overlay_written:
                    counters["delta_overlay_writes"] += 1
            except (OSError, ValueError) as exc:
                errors.append(
                    {
                        "source_path": str(delta_overlay_path),
                        "error": f"delta overlay reset failed after full reconciliation: {exc}",
                    }
                )

    bundled_sources_seen = sum(int(item["source_count"]) for item in bundle_metadata)
    base_result = {
        "schema_version": "chronik-grabowski-outbox-batch.v2",
        "source_dir": str(source_dir),
        "receipt_dir": str(receipt_dir),
        "files_seen": len(sources),
        "loose_files_seen": len(sources),
        "bundle_manifests_seen": len(manifests),
        "bundles_valid": len(bundle_metadata),
        "bundled_sources_seen": bundled_sources_seen,
        "sources_seen_total": len(sources) + bundled_sources_seen,
        "sources_after_deduplication": len(prepared_sources),
        "orphan_bundles": len(orphan_bundles),
        "files_imported_or_confirmed": len(results),
        "files_unchanged": sum(1 for result in results if result.get("unchanged") is True),
        "receipts_written": sum(1 for result in results if result.get("receipt_written") is True),
        "receipts_reused": sum(1 for result in results if result.get("receipt_reused") is True),
        "receipts_deferred": 0,
        "loose_sources_imported_or_confirmed": sum(
            1 for result in results if result.get("source_origin") == "loose"
        ),
        "bundled_sources_imported_or_confirmed": sum(
            1 for result in results if result.get("source_origin") == "bundle"
        ),
        "events_imported": sum(int(result.get("imported", 0)) for result in results),
        "events_skipped_existing": sum(int(result.get("skipped_existing", 0)) for result in results),
        "target_scans": target_scans,
        "target_records_scanned": target_records_scanned,
        "identity_index_mode": identity_index_mode,
        "identity_index_full_rebuild": identity_index_full_rebuild,
        "identity_index_entries_after": identity_index_entries_after,
        "source_index_path": str(source_index_path),
        "source_index_mode": source_index_mode,
        "source_index_written": source_index_written,
        "source_index_file_bytes": source_index_file_bytes,
        "sources_reused": counters["sources_reused"],
        "sources_revalidated": counters["sources_revalidated"],
        "sources_changed": counters["sources_changed"],
        "sources_added": counters["sources_added"],
        "sources_removed": counters["sources_removed"],
        "source_bytes_read": counters["source_bytes_read"],
        "source_bytes_hashed": counters["source_bytes_hashed"],
        "source_events_validated": counters["source_events_validated"],
        "bundle_inventory": bundle_metadata,
        "errors": errors,
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }
    if (
        not errors
        and ledger_reconciled
        and receipt_writes_succeeded
        and identity_index_entries_after is not None
    ):
        with measured_phase("steady_checkpoint_publish"):
            source_inventory = _stable_source_inventory_identity(
                source_dir=source_dir,
                bundle_dir=bundle_dir,
                sources=sources,
                manifests=manifests,
                bundle_files=bundle_files,
            )
            receipt_paths = (
                list(receipt_dir.glob("*.receipt.json"))
                if receipt_dir.is_dir()
                else []
            )
            receipt_inventory = _inventory_fingerprint(receipt_paths, private=True)
            source_index_identity = _private_file_identity(source_index_path)
            delta_index_identity = _private_file_identity(delta_index_path)
            delta_overlay_identity = _private_file_identity(delta_overlay_path)
            try:
                target_identity = storage.read_unique_storage_checkpoint_identity(DOMAIN)
            except storage.StorageError:
                target_identity = None
            if (
                source_inventory is not None
                and receipt_inventory is not None
                and source_index_identity is not None
                and delta_index_identity is not None
                and delta_overlay_identity is not None
                and target_identity is not None
            ):
                checkpoint_identity = {
                    "source_inventory": source_inventory,
                    "receipt_inventory": receipt_inventory,
                    "source_index_identity": source_index_identity,
                    "delta_index_identity": delta_index_identity,
                    "delta_overlay_identity": delta_overlay_identity,
                    "target_identity": target_identity,
                }
                checkpoint_summary = _steady_summary_from_result(base_result)
                if _publish_steady_checkpoint(
                    steady_checkpoint_path,
                    source_dir=source_dir,
                    identity=checkpoint_identity,
                    summary=checkpoint_summary,
                    previous=prior_steady_checkpoint,
                ):
                    counters["steady_checkpoint_writes"] += 1
                else:
                    counters["steady_checkpoint_reuses"] += 1
    elapsed_ns = time.perf_counter_ns() - import_started_ns
    telemetry = {
        "schema_version": "chronik-grabowski-import-telemetry.v1",
        "elapsed_seconds": round(elapsed_ns / 1_000_000_000, 6),
        "phases_seconds": {
            name: round(value / 1_000_000_000, 6)
            for name, value in sorted(phase_ns.items())
        },
        "counters": dict(sorted(counters.items())),
    }
    return {
        **base_result,
        "elapsed_seconds": telemetry["elapsed_seconds"],
        "import_telemetry": telemetry,
        "steady_fast_path": False,
        "delta_fast_path": False,
    }



@contextmanager
def _grabowski_writer_compaction_lock(source_dir: Path):
    source_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        source_stat = source_dir.stat(follow_symlinks=False)
    except OSError as exc:
        raise ValueError("Grabowski outbox directory cannot be inspected safely") from exc
    if (
        not stat.S_ISDIR(source_stat.st_mode)
        or source_stat.st_uid != os.geteuid()
        or source_stat.st_mode & 0o022
    ):
        raise ValueError(
            "Grabowski outbox directory must be real, owned, and not broadly writable"
        )
    lock_path = source_dir / GRABOWSKI_WRITER_COMPACTION_LOCK_FILENAME
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != os.geteuid()
            or file_stat.st_nlink != 1
        ):
            raise ValueError(
                "Grabowski writer-compaction lock must be a private owned file"
            )
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield lock_path
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def compact_grabowski_outbox(
    *,
    outbox_root: Path,
    receipt_dir: Path,
    grace_seconds: int = 86400,
    max_sources: int = DEFAULT_COMPACTION_MAX_SOURCES,
    max_bytes: int = DEFAULT_COMPACTION_MAX_BYTES,
    apply: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(apply, bool):
        raise ValueError("apply must be a boolean")
    source_dir = outbox_root.expanduser() / "grabowski" / "chronik-outbox"
    if apply:
        with _grabowski_writer_compaction_lock(source_dir):
            return _compact_grabowski_outbox_unlocked(
                outbox_root=outbox_root,
                receipt_dir=receipt_dir,
                grace_seconds=grace_seconds,
                max_sources=max_sources,
                max_bytes=max_bytes,
                apply=apply,
                now=now,
            )
    return _compact_grabowski_outbox_unlocked(
        outbox_root=outbox_root,
        receipt_dir=receipt_dir,
        grace_seconds=grace_seconds,
        max_sources=max_sources,
        max_bytes=max_bytes,
        apply=apply,
        now=now,
    )


def _compact_grabowski_outbox_unlocked(
    *,
    outbox_root: Path,
    receipt_dir: Path,
    grace_seconds: int = 86400,
    max_sources: int = DEFAULT_COMPACTION_MAX_SOURCES,
    max_bytes: int = DEFAULT_COMPACTION_MAX_BYTES,
    apply: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    if type(grace_seconds) is not int or grace_seconds < 0:
        raise ValueError("grace_seconds must be a non-negative integer")
    if type(max_sources) is not int or max_sources < 1:
        raise ValueError("max_sources must be a positive integer")
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    if not isinstance(apply, bool):
        raise ValueError("apply must be a boolean")
    observed_at = now or datetime.now(timezone.utc)
    if observed_at.tzinfo is None:
        raise ValueError("now must include a timezone")
    observed_at = observed_at.astimezone(timezone.utc)
    source_dir = outbox_root.expanduser() / "grabowski" / "chronik-outbox"
    bundle_dir = source_dir / GRABOWSKI_BUNDLE_DIRNAME
    all_sources = sorted(source_dir.glob("*.jsonl")) if source_dir.is_dir() else []
    sources = all_sources[:max_sources]
    deferred_sources = len(all_sources) - len(sources)
    skipped: Counter[str] = Counter()
    errors: list[dict[str, str]] = []
    eligible: list[dict[str, Any]] = []
    eligible_bytes = 0
    ledger_payloads, ledger_records_scanned = _ledger_payloads_by_event_id()
    observed_ns = int(observed_at.timestamp() * 1_000_000_000)
    grace_ns = grace_seconds * 1_000_000_000
    for source in sources:
        try:
            prepared = _prepare_grabowski_outbox_source(
                source, receipt_dir=receipt_dir
            )
        except (OSError, ValueError, storage.StorageError) as exc:
            skipped["invalid_source"] += 1
            errors.append({"source_path": str(source), "error": str(exc)})
            continue
        if prepared["events"][-1]["kind"] not in GRABOWSKI_TERMINAL_KINDS:
            skipped["nonterminal"] += 1
            continue
        source_mtime_ns = prepared.get("source_mtime_ns")
        if (
            type(source_mtime_ns) is not int
            or observed_ns - source_mtime_ns < grace_ns
        ):
            skipped["grace_pending"] += 1
            continue
        if not _receipt_matches_prepared_source(
            prepared, prepared.get("previous_receipt")
        ):
            skipped["receipt_invalid_or_missing"] += 1
            continue
        if any(
            ledger_payloads.get(event["event_id"]) != canonical_bytes(event)
            for event in prepared["events"]
        ):
            skipped["ledger_unconfirmed"] += 1
            continue
        prepared_bytes = _prepared_source_bytes(prepared)
        if eligible_bytes + prepared_bytes > max_bytes:
            skipped["compaction_byte_bound"] += 1
            continue
        eligible.append(prepared)
        eligible_bytes += prepared_bytes
    if deferred_sources:
        skipped["compaction_source_bound"] += deferred_sources
    result: dict[str, Any] = {
        "schema_version": "chronik-grabowski-outbox-compaction.v1",
        "mode": "apply" if apply else "dry-run",
        "source_dir": str(source_dir),
        "receipt_dir": str(receipt_dir),
        "bundle_dir": str(bundle_dir),
        "grace_seconds": grace_seconds,
        "max_sources": max_sources,
        "max_bytes": max_bytes,
        "observed_at": observed_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "loose_sources_seen": len(all_sources),
        "loose_sources_considered": len(sources),
        "loose_sources_deferred": deferred_sources,
        "eligible_sources": len(eligible),
        "eligible_events": sum(len(item["events"]) for item in eligible),
        "eligible_source_bytes": sum(len(item["raw"]) for item in eligible),
        "skipped_by_reason": dict(sorted(skipped.items())),
        "ledger_records_scanned": ledger_records_scanned,
        "bundle_path": None,
        "bundle_sha256": None,
        "bundle_bytes": 0,
        "manifest_path": None,
        "manifest_sha256": None,
        "archive_index_path": str(bundle_dir / GRABOWSKI_ARCHIVE_INDEX_FILENAME),
        "archive_index_sha256": None,
        "archive_index_file_sha256": None,
        "archive_index_published": False,
        "archive_manifests_indexed": 0,
        "archived_sources_indexed": 0,
        "bundle_published": False,
        "manifest_published": False,
        "bundle_reused": False,
        "sources_removed": 0,
        "loose_sources_remaining": len(all_sources),
        "errors": errors,
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }
    if not apply:
        return result
    if not eligible:
        try:
            archive_index = _refresh_grabowski_archive_index(
                source_dir=source_dir,
                bundle_dir=bundle_dir,
                receipt_dir=receipt_dir,
            )
        except (OSError, ValueError, storage.StorageError) as exc:
            errors.append(
                {
                    "source_path": str(bundle_dir / GRABOWSKI_ARCHIVE_INDEX_FILENAME),
                    "error": str(exc),
                }
            )
        else:
            if archive_index is not None:
                result.update(
                    {
                        "archive_index_path": archive_index["path"],
                        "archive_index_sha256": archive_index["index_sha256"],
                        "archive_index_file_sha256": archive_index["file_sha256"],
                        "archive_index_published": archive_index["published"],
                        "archive_manifests_indexed": archive_index["manifest_count"],
                        "archived_sources_indexed": archive_index["source_count"],
                    }
                )
        return result
    stable: list[dict[str, Any]] = []
    for prepared in eligible:
        if _source_still_matches(prepared):
            stable.append(prepared)
        else:
            skipped["source_changed_before_publish"] += 1
            errors.append(
                {
                    "source_path": str(prepared["source"]),
                    "error": "source changed before bundle publication",
                }
            )
    result["skipped_by_reason"] = dict(sorted(skipped.items()))
    result["eligible_sources"] = len(stable)
    result["eligible_events"] = sum(len(item["events"]) for item in stable)
    result["eligible_source_bytes"] = sum(len(item["raw"]) for item in stable)
    if not stable:
        return result
    entries: list[dict[str, Any]] = []
    bundle_parts: list[bytes] = []
    bundle_offset = 0
    for item in stable:
        entries.append(_bundle_source_record(item, offset=bundle_offset))
        bundle_parts.append(item["raw"])
        bundle_offset += len(item["raw"])
    bundle_raw = b"".join(bundle_parts)
    bundle_sha256 = sha256_bytes(bundle_raw)
    prefix = f"grabowski-{bundle_sha256}"
    bundle_path = bundle_dir / f"{prefix}.bundle.jsonl"
    manifest_path = bundle_dir / f"{prefix}.manifest.json"
    result.update(
        {
            "bundle_path": str(bundle_path),
            "bundle_sha256": bundle_sha256,
            "bundle_bytes": len(bundle_raw),
            "manifest_path": str(manifest_path),
        }
    )
    failure_path = manifest_path
    try:
        _ensure_bundle_directory(source_dir, bundle_dir)
        result["bundle_published"] = _publish_immutable(bundle_path, bundle_raw)
        if manifest_path.exists():
            loaded, metadata = _load_grabowski_bundle(
                manifest_path,
                source_dir=source_dir,
                receipt_dir=receipt_dir,
            )
            result["bundle_reused"] = True
        else:
            manifest = {
                "schema_version": GRABOWSKI_BUNDLE_MANIFEST_SCHEMA,
                "domain": DOMAIN,
                "bundle_file": bundle_path.name,
                "bundle_sha256": bundle_sha256,
                "bundle_bytes": len(bundle_raw),
                "source_count": len(entries),
                "event_count": sum(len(item["events"]) for item in stable),
                "sources": entries,
                "created_at": utc_now(),
                "historical_only": True,
                "does_not_establish": DOES_NOT_ESTABLISH,
            }
            manifest["manifest_sha256"] = sha256_bytes(canonical_bytes(manifest))
            manifest_raw = (
                json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
                + b"\n"
            )
            result["manifest_published"] = _publish_immutable(
                manifest_path, manifest_raw
            )
            loaded, metadata = _load_grabowski_bundle(
                manifest_path,
                source_dir=source_dir,
                receipt_dir=receipt_dir,
            )
        expected_sources = entries
        if metadata["sources"] != expected_sources:
            raise ValueError("published bundle inventory does not match selection")
        loaded_by_path = {
            str(item["source"].resolve()): item["raw"] for item in loaded
        }
        if loaded_by_path != {
            str(item["source"].resolve()): item["raw"] for item in stable
        }:
            raise ValueError("published bundle readback does not match source bytes")
        result["manifest_sha256"] = metadata["manifest_sha256"]
        failure_path = bundle_dir / GRABOWSKI_ARCHIVE_INDEX_FILENAME
        archive_index = _refresh_grabowski_archive_index(
            source_dir=source_dir,
            bundle_dir=bundle_dir,
            receipt_dir=receipt_dir,
        )
        if archive_index is None:
            raise ValueError("archive index was not created for published bundle")
        result.update(
            {
                "archive_index_path": archive_index["path"],
                "archive_index_sha256": archive_index["index_sha256"],
                "archive_index_file_sha256": archive_index["file_sha256"],
                "archive_index_published": archive_index["published"],
                "archive_manifests_indexed": archive_index["manifest_count"],
                "archived_sources_indexed": archive_index["source_count"],
            }
        )
    except (OSError, ValueError, storage.StorageError) as exc:
        errors.append({"source_path": str(failure_path), "error": str(exc)})
        return result
    removed = 0
    for prepared in stable:
        source = prepared["source"]
        if not _source_still_matches(prepared):
            skipped["source_changed_before_remove"] += 1
            errors.append(
                {
                    "source_path": str(source),
                    "error": "source changed after bundle publication and was retained",
                }
            )
            continue
        try:
            _unlink_loose_source(source)
        except OSError as exc:
            skipped["unlink_failed"] += 1
            errors.append({"source_path": str(source), "error": f"unlink failed: {exc}"})
        else:
            removed += 1
    if removed:
        try:
            _fsync_directory(source_dir)
        except OSError as exc:
            errors.append(
                {
                    "source_path": str(source_dir),
                    "error": f"source directory fsync failed after removal: {exc}",
                }
            )
    result["sources_removed"] = removed
    result["loose_sources_remaining"] = (
        len(list(source_dir.glob("*.jsonl"))) if source_dir.is_dir() else 0
    )
    result["skipped_by_reason"] = dict(sorted(skipped.items()))
    return result


@lru_cache(maxsize=1)
def _history_validation_schema_sha256() -> str:
    return sha256_bytes(SCHEMA_PATH.read_bytes())


def _history_validation_checkpoint_path() -> Path:
    return storage.DATA_DIR / HISTORY_VALIDATION_CHECKPOINT_FILENAME


def _load_history_validation_checkpoint(raw_snapshot: bytes) -> int:
    """Return a previously validated byte prefix, or zero on any doubt."""
    path = _history_validation_checkpoint_path()
    try:
        before = path.lstat()
    except OSError:
        return 0
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_mode & 0o077
    ):
        return 0
    try:
        raw = path.read_bytes()
        after = path.lstat()
    except OSError:
        return 0
    if _file_identity(before) != _file_identity(after):
        return 0
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return 0
    expected_keys = {
        "schema_version",
        "domain",
        "validation_contract",
        "event_schema_sha256",
        "validated_bytes",
        "prefix_sha256",
        "record_count",
        "checkpoint_sha256",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        return 0
    checkpoint_sha256 = document.get("checkpoint_sha256")
    semantic = {key: value for key, value in document.items() if key != "checkpoint_sha256"}
    if (
        not isinstance(checkpoint_sha256, str)
        or checkpoint_sha256 != sha256_bytes(canonical_bytes(semantic))
        or document.get("schema_version") != HISTORY_VALIDATION_CHECKPOINT_SCHEMA
        or document.get("domain") != DOMAIN
        or document.get("validation_contract") != HISTORY_VALIDATION_CONTRACT
        or document.get("event_schema_sha256") != _history_validation_schema_sha256()
    ):
        return 0
    validated_bytes = document.get("validated_bytes")
    record_count = document.get("record_count")
    prefix_sha256 = document.get("prefix_sha256")
    if (
        not isinstance(validated_bytes, int)
        or isinstance(validated_bytes, bool)
        or validated_bytes <= 0
        or validated_bytes > len(raw_snapshot)
        or not isinstance(record_count, int)
        or isinstance(record_count, bool)
        or record_count < 0
        or not isinstance(prefix_sha256, str)
        or len(prefix_sha256) != 64
        or raw_snapshot[validated_bytes - 1 : validated_bytes] != b"\n"
        or sha256_bytes(raw_snapshot[:validated_bytes]) != prefix_sha256
    ):
        return 0
    return validated_bytes


def _publish_history_validation_checkpoint(
    raw_snapshot: bytes, *, snapshot_sha256: str, record_count: int
) -> None:
    """Best-effort publication of reconstructible validation evidence."""
    if not raw_snapshot:
        return
    document: dict[str, Any] = {
        "schema_version": HISTORY_VALIDATION_CHECKPOINT_SCHEMA,
        "domain": DOMAIN,
        "validation_contract": HISTORY_VALIDATION_CONTRACT,
        "event_schema_sha256": _history_validation_schema_sha256(),
        "validated_bytes": len(raw_snapshot),
        "prefix_sha256": snapshot_sha256,
        "record_count": record_count,
    }
    document["checkpoint_sha256"] = sha256_bytes(canonical_bytes(document))
    try:
        _atomic_write(
            _history_validation_checkpoint_path(),
            canonical_bytes(document) + b"\n",
        )
    except OSError:
        # This file is only a reconstructible accelerator. Query correctness
        # must never depend on being able to persist it.
        return


def _scan_record_snapshot(
    visit: Callable[[dict[str, Any], datetime, int], None],
) -> dict[str, Any]:
    """Validate complete records from one byte-bound snapshot and visit each once."""
    diagnostics: list[dict[str, Any]] = []
    invalid_record_count = 0
    total_record_count = 0
    valid_record_count = 0
    raw_snapshot = storage.read_domain_snapshot(DOMAIN)
    complete_bytes = len(raw_snapshot)
    snapshot_sha256 = sha256_bytes(raw_snapshot)
    trusted_validated_bytes = _load_history_validation_checkpoint(raw_snapshot)
    start_offset = 0

    while start_offset < complete_bytes:
        newline_at = raw_snapshot.find(b"\n", start_offset)
        if newline_at < 0:
            break
        content = raw_snapshot[start_offset:newline_at]
        next_offset = newline_at + 1
        if not content.strip():
            start_offset = next_offset
            continue
        total_record_count += 1
        try:
            line = content.decode("utf-8")
            envelope = json.loads(line)
            if not isinstance(envelope, dict):
                raise ValueError("envelope must be an object")
            payload = envelope.get("payload")
            if not isinstance(payload, dict):
                raise ValueError("payload must be an object")
            if next_offset <= trusted_validated_bytes:
                event_at = _parse_timestamp(payload.get("ts"), field="ts")
            else:
                event_at = validate_event(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            invalid_record_count += 1
            if len(diagnostics) < MAX_INTEGRITY_DIAGNOSTICS:
                diagnostics.append(
                    {
                        "offset": start_offset,
                        "next_offset": next_offset,
                        "error": str(exc),
                    }
                )
            start_offset = next_offset
            continue
        row = {"received_at": envelope.get("received_at"), "payload": payload}
        visit(row, event_at, valid_record_count)
        valid_record_count += 1
        start_offset = next_offset

    integrity_valid = invalid_record_count == 0
    if integrity_valid and trusted_validated_bytes < complete_bytes:
        _publish_history_validation_checkpoint(
            raw_snapshot,
            snapshot_sha256=snapshot_sha256,
            record_count=total_record_count,
        )

    return {
        "domain": DOMAIN,
        "sha256": snapshot_sha256,
        "complete_bytes": complete_bytes,
        "total_record_count": total_record_count,
        "valid_record_count": valid_record_count,
        "invalid_record_count": invalid_record_count,
        "integrity_valid": integrity_valid,
        "diagnostics": diagnostics,
        "diagnostics_truncated": invalid_record_count > len(diagnostics),
    }


def _retain_latest(
    heap: list[tuple[datetime, str, int, dict[str, Any]]],
    *,
    event_at: datetime,
    event_id: str,
    sequence: int,
    value: dict[str, Any],
    limit: int,
) -> None:
    """Keep only the newest bounded candidates using the public ordering contract."""
    # The former stable reverse sort kept the earlier row first when public
    # keys were equal. Negating the scan sequence preserves that exact contract.
    candidate_key = (event_at, event_id, -sequence)
    candidate = (*candidate_key, value)
    if len(heap) < limit:
        heapq.heappush(heap, candidate)
    elif candidate_key > heap[0][:3]:
        heapq.heapreplace(heap, candidate)


def _event_operation(event: dict[str, Any]) -> str | None:
    data = event.get("data")
    subject = event.get("subject")
    if isinstance(data, dict) and data.get("operation"):
        return data["operation"]
    if isinstance(subject, dict):
        return subject.get("operation")
    return None


def _event_task_class(event: dict[str, Any]) -> str | None:
    data = event.get("data")
    return data.get("task_class") if isinstance(data, dict) else None


def _event_source_component(event: dict[str, Any]) -> str | None:
    """Return the canonical producer component without a subject fallback."""
    source = event.get("source")
    return source.get("component") if isinstance(source, dict) else None


def _event_subject_component(event: dict[str, Any]) -> str | None:
    """Return the task-context component from the event subject."""
    subject = event.get("subject")
    return subject.get("component") if isinstance(subject, dict) else None


def _target(*, repo: str | None, host: str | None) -> dict[str, str]:
    if repo is not None:
        return {"scope": "repository", "repo": repo}
    assert host is not None
    return {"scope": "host", "host": host}


def _matches_target(subject: dict[str, Any], *, repo: str | None, host: str | None) -> bool:
    if repo is not None:
        return subject.get("scope") != "host" and subject.get("repo") == repo
    return subject.get("scope") == "host" and subject.get("host") == host


def validate_query(*, repo: str | None = None, host: str | None = None, component: str | None = None, subject_component: str | None = None, operation: str | None = None, task_class: str | None = None, outcome: str | None = None, since: str | None = None, limit: int = 20) -> datetime | None:
    if (repo is None) == (host is None):
        raise ValueError("exactly one of repo or host is required")
    if repo is not None and not repo.strip():
        raise ValueError("repo must not be empty")
    if host is not None and not host.strip():
        raise ValueError("host must not be empty")
    if limit < 1 or limit > 500:
        raise ValueError("limit 1..500 is required")
    if operation is not None and operation not in OPERATIONS:
        raise ValueError(f"unsupported operation: {operation}")
    if task_class is not None and task_class not in TASK_CLASSES:
        raise ValueError(f"unsupported task_class: {task_class}")
    if outcome is not None and outcome not in OUTCOMES:
        raise ValueError(f"unsupported outcome: {outcome}")
    return _parse_timestamp(since, field="since") if since is not None else None


def query_history(
    *,
    repo: str | None = None,
    host: str | None = None,
    component: str | None = None,
    subject_component: str | None = None,
    operation: str | None = None,
    task_class: str | None = None,
    outcome: str | None = None,
    since: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    since_at = validate_query(
        repo=repo,
        host=host,
        component=component,
        subject_component=subject_component,
        operation=operation,
        task_class=task_class,
        outcome=outcome,
        since=since,
        limit=limit,
    )
    selected: list[tuple[datetime, str, int, dict[str, Any]]] = []

    def consider(row: dict[str, Any], event_at: datetime, sequence: int) -> None:
        event = row["payload"]
        subject = event["subject"]
        if not _matches_target(subject, repo=repo, host=host):
            return
        if component and _event_source_component(event) != component:
            return
        if subject_component and _event_subject_component(event) != subject_component:
            return
        if operation and _event_operation(event) != operation:
            return
        if task_class and _event_task_class(event) != task_class:
            return
        if outcome:
            data = event.get("data")
            actual_outcome = (
                data.get("outcome") or data.get("result")
                if isinstance(data, dict)
                else None
            )
            if actual_outcome != outcome:
                return
        if since_at is not None and event_at < since_at:
            return
        _retain_latest(
            selected,
            event_at=event_at,
            event_id=event["event_id"],
            sequence=sequence,
            value=row,
            limit=limit,
        )

    ledger_snapshot = _scan_record_snapshot(consider)
    selected.sort(key=lambda item: item[:3], reverse=True)
    selected_rows = [item[3] for item in selected]
    query = {
        "repo": repo,
        "host": host,
        "component": component,
        "operation": operation,
        "task_class": task_class,
        "outcome": outcome,
        "since": since,
        "limit": limit,
    }
    if subject_component is not None:
        query["subject_component"] = subject_component
    return {
        "schema_version": "chronik-coding-history.v1",
        "query": query,
        "target": _target(repo=repo, host=host),
        "events": [row["payload"] for row in selected_rows],
        "event_ids": [row["payload"]["event_id"] for row in selected_rows],
        "ledger_snapshot": ledger_snapshot,
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }


def operator_summary(*, since: str | None = None, limit: int = 20) -> dict[str, Any]:
    if limit < 1 or limit > 500:
        raise ValueError("limit 1..500 is required")
    since_at = _parse_timestamp(since, field="since") if since is not None else None
    event_count = 0
    kind_counts: Counter[str] = Counter()
    repo_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    target_counts: Counter[str] = Counter()
    operation_counts: Counter[str] = Counter()
    task_class_counts: Counter[str] = Counter()
    blocker_counts: Counter[str] = Counter()
    recent_heap: list[tuple[datetime, str, int, dict[str, Any]]] = []

    def summarize(row: dict[str, Any], event_at: datetime, sequence: int) -> None:
        nonlocal event_count
        event = row["payload"]
        if since_at is not None and event_at < since_at:
            return
        event_count += 1
        subject = event.get("subject", {})
        data = event.get("data", {})
        kind_counts[event["kind"]] += 1
        repo_counts[subject.get("repo", "unknown")] += 1
        if subject.get("scope") == "host" and subject.get("host"):
            host_counts[subject["host"]] += 1
            target_counts[f"host:{subject['host']}"] += 1
        else:
            target_counts[f"repository:{subject.get('repo', 'unknown')}"] += 1
        operation_counts[_event_operation(event) or "unspecified"] += 1
        task_class_counts[_event_task_class(event) or "unspecified"] += 1
        if event.get("kind") == "agent.run.blocked":
            blocker_counts[data.get("blocker_code", "unspecified")] += 1
        _retain_latest(
            recent_heap,
            event_at=event_at,
            event_id=event["event_id"],
            sequence=sequence,
            value=event,
            limit=limit,
        )

    ledger_snapshot = _scan_record_snapshot(summarize)
    recent_heap.sort(key=lambda item: item[:3], reverse=True)
    recent = []
    for _, _, _, event in recent_heap:
        subject = event.get("subject", {})
        recent.append(
            {
                "event_id": event["event_id"],
                "ts": event["ts"],
                "kind": event["kind"],
                "run_id": event.get("source", {}).get("run_id"),
                "target": (
                    {"scope": "host", "host": subject.get("host")}
                    if subject.get("scope") == "host"
                    else {"scope": "repository", "repo": subject.get("repo")}
                ),
                "subject": subject,
                "operation": _event_operation(event),
                "task_class": _event_task_class(event),
                "data": event.get("data", {}),
            }
        )
    return {
        "schema_version": "chronik-operator-summary.v1",
        "since": since,
        "event_count": event_count,
        "limit": limit,
        "counts_by_kind": dict(sorted(kind_counts.items())),
        "counts_by_subject_repo": dict(sorted(repo_counts.items())),
        "counts_by_subject_host": dict(sorted(host_counts.items())),
        "counts_by_target": dict(sorted(target_counts.items())),
        "counts_by_operation": dict(sorted(operation_counts.items())),
        "counts_by_task_class": dict(sorted(task_class_counts.items())),
        "blocked_by_code": dict(sorted(blocker_counts.items())),
        "recent": recent,
        "ledger_snapshot": ledger_snapshot,
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def freeze_history(output: Path, **filters: Any) -> dict[str, Any]:
    history = query_history(**filters)
    ledger_snapshot = history["ledger_snapshot"]
    if not ledger_snapshot["integrity_valid"]:
        raise ValueError("cannot freeze history from a ledger with invalid records")
    body = b"".join(canonical_bytes(event) + b"\n" for event in history["events"])
    _atomic_write(output, body)
    receipt = {
        "schema_version": "chronik-history-cohort-receipt.v1",
        "domain": DOMAIN,
        "query": history["query"],
        "target": history["target"],
        "event_ids": history["event_ids"],
        "event_count": len(history["event_ids"]),
        "cohort_path": str(output),
        "cohort_sha256": sha256_bytes(body),
        "query_sha256": sha256_bytes(canonical_bytes(history["query"])),
        "ledger_snapshot_sha256": ledger_snapshot["sha256"],
        "ledger_snapshot_complete_bytes": ledger_snapshot["complete_bytes"],
        "generated_at": utc_now(),
        "redaction_contract": "agent-run-event.v0 allow-list",
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
    receipt_path = output.with_suffix(output.suffix + ".receipt.json")
    _atomic_write(receipt_path, json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    return receipt
