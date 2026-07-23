"""Local, idempotent coding-history import and evidence-bound queries."""
from __future__ import annotations

import fcntl
import hashlib
import heapq
import json
import os
import stat
import tempfile
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
GRABOWSKI_TERMINAL_KINDS = frozenset({"agent.run.completed", "agent.run.blocked"})
GRABOWSKI_BUNDLE_DIRNAME = "bundles"
GRABOWSKI_BUNDLE_ENTRY_SCHEMA = "chronik-grabowski-outbox-bundle-source.v1"
GRABOWSKI_BUNDLE_MANIFEST_SCHEMA = "chronik-grabowski-outbox-bundle-manifest.v1"
GRABOWSKI_ARCHIVE_INDEX_FILENAME = "archive-index.v1.json"
GRABOWSKI_ARCHIVE_INDEX_SCHEMA = "chronik-grabowski-outbox-archive-index.v1"
GRABOWSKI_WRITER_COMPACTION_LOCK_FILENAME = ".writer-compaction.lock"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)


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
    source_identity: tuple[int, int, int, int] | None = None,
    source_mtime_ns: int | None = None,
    bundle_manifest_path: Path | None = None,
) -> dict[str, Any]:
    events = _parse_jsonl_snapshot(source, raw)
    if not events:
        raise ValueError(f"outbox contains no events: {source}")
    for event in events:
        _validate_grabowski_source(event)
    source_sha256 = sha256_bytes(raw)
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
    return {
        "source": source,
        "raw": raw,
        "events": events,
        "source_sha256": source_sha256,
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
    before = source.stat()
    raw = source.read_bytes()
    after = source.stat()
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


def _receipt_matches_prepared_source(
    prepared: dict[str, Any], receipt: dict[str, Any] | None
) -> bool:
    """Return whether an existing receipt is intact and bound to these source bytes."""
    if not isinstance(receipt, dict):
        return False
    source = prepared["source"]
    raw = prepared["raw"]
    events = prepared["events"]
    expected = {
        "schema_version": "chronik-grabowski-outbox-import.v1",
        "domain": DOMAIN,
        "source_path": str(source.resolve()),
        "source_sha256": prepared["source_sha256"],
        "source_bytes": len(raw),
        "selection_contract": sorted(HIGH_VALUE_KINDS),
        "event_ids": sorted(event["event_id"] for event in events),
        "requested": len(events),
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
    if receipt["imported"] + receipt["skipped_existing"] != len(events):
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
    manifest_raw = _read_immutable_artifact(
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
    bundle_raw = _read_immutable_artifact(bundle_path, label="bundle file")
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
        if previous["raw"] != prepared["raw"]:
            raise ValueError(f"source SHA-256 collision: {source_path}")
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


def _read_immutable_artifact(path: Path, *, label: str) -> bytes:
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
        before = source.stat()
        raw = source.read_bytes()
        after = source.stat()
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
    raw = prepared["raw"]
    events = prepared["events"]
    receipt_path = prepared["receipt_path"]
    previous_receipt = prepared.get("previous_receipt")
    if (
        prepared["source_unchanged"]
        and written == 0
        and skipped == len(events)
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
        "source_bytes": len(raw),
        "selection_contract": sorted(HIGH_VALUE_KINDS),
        "event_ids": sorted(event["event_id"] for event in events),
        "requested": len(events),
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
    grouped = storage.write_payload_unique_groups(
        DOMAIN,
        [
            (str(index), _envelope_lines(prepared["events"]))
            for index, prepared in enumerate(prepared_sources)
        ],
        authoritative_replay=authoritative_replay,
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


def import_grabowski_outbox(*, outbox_root: Path, receipt_dir: Path) -> dict[str, Any]:
    source_dir = outbox_root.expanduser() / "grabowski" / "chronik-outbox"
    bundle_dir = source_dir / GRABOWSKI_BUNDLE_DIRNAME
    sources = sorted(source_dir.glob("*.jsonl")) if source_dir.is_dir() else []
    manifests = sorted(bundle_dir.glob("*.manifest.json")) if bundle_dir.is_dir() else []
    bundle_files = sorted(bundle_dir.glob("*.bundle.jsonl")) if bundle_dir.is_dir() else []
    all_prepared: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    bundle_metadata: list[dict[str, Any]] = []
    referenced_bundle_paths: set[str] = set()
    for source in sources:
        try:
            all_prepared.append(
                _prepare_grabowski_outbox_source(source, receipt_dir=receipt_dir)
            )
        except (OSError, ValueError, storage.StorageError) as exc:
            errors.append({"source_path": str(source), "error": str(exc)})
    for manifest_path in manifests:
        try:
            bundled, metadata = _load_grabowski_bundle(
                manifest_path,
                source_dir=source_dir,
                receipt_dir=receipt_dir,
            )
            all_prepared.extend(bundled)
            bundle_metadata.append(metadata)
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
    try:
        prepared_sources = _merge_prepared_grabowski_sources(all_prepared)
    except ValueError as exc:
        target_scans = None
        target_records_scanned = None
        identity_index_mode = None
        identity_index_full_rebuild = None
        identity_index_entries_after = None
        errors.append({"source_path": "<batch>", "error": str(exc)})
    if prepared_sources and target_scans is not None:
        try:
            target_path = storage.safe_target_path(DOMAIN)
            target_missing_or_empty = (
                not target_path.exists() or target_path.stat().st_size == 0
            )
            authoritative_replay = target_missing_or_empty and not errors
            results, grouped, receipt_errors = _import_prepared_grabowski_sources(
                prepared_sources,
                authoritative_replay=authoritative_replay,
            )
            target_scans = int(grouped.get("target_scans", 0))
            target_records_scanned = int(grouped.get("target_records_scanned", 0))
            identity_index_mode = str(grouped.get("identity_index_mode", "unknown"))
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
    bundled_sources_seen = sum(int(item["source_count"]) for item in bundle_metadata)
    return {
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
        "bundle_inventory": bundle_metadata,
        "errors": errors,
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
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
                apply=apply,
                now=now,
            )
    return _compact_grabowski_outbox_unlocked(
        outbox_root=outbox_root,
        receipt_dir=receipt_dir,
        grace_seconds=grace_seconds,
        apply=apply,
        now=now,
    )


def _compact_grabowski_outbox_unlocked(
    *,
    outbox_root: Path,
    receipt_dir: Path,
    grace_seconds: int = 86400,
    apply: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    if type(grace_seconds) is not int or grace_seconds < 0:
        raise ValueError("grace_seconds must be a non-negative integer")
    if not isinstance(apply, bool):
        raise ValueError("apply must be a boolean")
    observed_at = now or datetime.now(timezone.utc)
    if observed_at.tzinfo is None:
        raise ValueError("now must include a timezone")
    observed_at = observed_at.astimezone(timezone.utc)
    source_dir = outbox_root.expanduser() / "grabowski" / "chronik-outbox"
    bundle_dir = source_dir / GRABOWSKI_BUNDLE_DIRNAME
    sources = sorted(source_dir.glob("*.jsonl")) if source_dir.is_dir() else []
    skipped: Counter[str] = Counter()
    errors: list[dict[str, str]] = []
    eligible: list[dict[str, Any]] = []
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
        eligible.append(prepared)
    result: dict[str, Any] = {
        "schema_version": "chronik-grabowski-outbox-compaction.v1",
        "mode": "apply" if apply else "dry-run",
        "source_dir": str(source_dir),
        "receipt_dir": str(receipt_dir),
        "bundle_dir": str(bundle_dir),
        "grace_seconds": grace_seconds,
        "observed_at": observed_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "loose_sources_seen": len(sources),
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
        "loose_sources_remaining": len(sources),
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

    return {
        "domain": DOMAIN,
        "sha256": snapshot_sha256,
        "complete_bytes": complete_bytes,
        "total_record_count": total_record_count,
        "valid_record_count": valid_record_count,
        "invalid_record_count": invalid_record_count,
        "integrity_valid": invalid_record_count == 0,
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
