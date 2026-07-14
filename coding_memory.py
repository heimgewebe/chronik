"""Local, idempotent coding-history import and frozen query receipts."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft7Validator

import storage
from canonical_ingest import build_envelope

DOMAIN = "agent.ledger"
SCHEMA_PATH = Path(__file__).resolve().parent / "docs" / "chronik" / "agent-run-event-v0.schema.json"
DOES_NOT_ESTABLISH = ["current_git_state", "current_ci_state", "current_runtime_state", "safe_retry"]
GRABOWSKI_SOURCE_REPO = "heimgewebe/grabowski"
GRABOWSKI_COMPONENT = "grabowski"
HIGH_VALUE_KINDS = frozenset({"agent.run.started", "agent.run.completed", "agent.run.blocked"})


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


def _validator() -> Draft7Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema)


def validate_event(event: dict[str, Any]) -> None:
    errors = sorted(_validator().iter_errors(event), key=lambda error: list(error.absolute_path))
    if errors:
        error = errors[0]
        path = "/".join(str(part) for part in error.absolute_path) or "<root>"
        raise ValueError(f"invalid coding event at {path}: {error.message}")
    _parse_timestamp(event["ts"], field="ts")


def import_events(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    values = [dict(event) for event in events]
    for event in values:
        validate_event(event)
    lines = [json.dumps(build_envelope(DOMAIN, event), sort_keys=True, separators=(",", ":"), ensure_ascii=False) for event in values]
    written, skipped = storage.write_payload_unique(DOMAIN, lines)
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


def _read_jsonl_snapshot(path: Path) -> tuple[bytes, list[dict[str, Any]]]:
    raw = path.read_bytes()
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
    return raw, events


def _receipt_path(source: Path, receipt_dir: Path) -> Path:
    source_key = sha256_bytes(str(source.resolve()).encode("utf-8"))
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


def import_grabowski_outbox_file(source: Path, *, receipt_dir: Path) -> dict[str, Any]:
    raw, events = _read_jsonl_snapshot(source)
    source_sha256 = sha256_bytes(raw)
    receipt_path = _receipt_path(source, receipt_dir)
    previous = _load_receipt(receipt_path)
    source_unchanged = previous is not None and previous.get("source_sha256") == source_sha256
    if not events:
        raise ValueError(f"outbox contains no events: {source}")
    for event in events:
        _validate_grabowski_source(event)
    imported = import_events(events)
    receipt = {
        "schema_version": "chronik-grabowski-outbox-import.v1",
        "domain": DOMAIN,
        "source_path": str(source.resolve()),
        "source_sha256": source_sha256,
        "source_bytes": len(raw),
        "selection_contract": sorted(HIGH_VALUE_KINDS),
        "event_ids": sorted(event["event_id"] for event in events),
        "requested": imported["requested"],
        "imported": imported["imported"],
        "skipped_existing": imported["skipped_existing"],
        "recorded_at": utc_now(),
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
    _atomic_write(receipt_path, json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    return {**receipt, "unchanged": source_unchanged, "receipt_path": str(receipt_path)}


def import_grabowski_outbox(*, outbox_root: Path, receipt_dir: Path) -> dict[str, Any]:
    source_dir = outbox_root.expanduser() / "grabowski" / "chronik-outbox"
    sources = sorted(source_dir.glob("*.jsonl")) if source_dir.is_dir() else []
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for source in sources:
        try:
            results.append(import_grabowski_outbox_file(source, receipt_dir=receipt_dir))
        except (OSError, ValueError, storage.StorageError) as exc:
            errors.append({"source_path": str(source), "error": str(exc)})
    return {
        "schema_version": "chronik-grabowski-outbox-batch.v1",
        "source_dir": str(source_dir),
        "receipt_dir": str(receipt_dir),
        "files_seen": len(sources),
        "files_imported_or_confirmed": len(results),
        "files_unchanged": sum(1 for result in results if result.get("unchanged") is True),
        "events_imported": sum(int(result.get("imported", 0)) for result in results),
        "events_skipped_existing": sum(int(result.get("skipped_existing", 0)) for result in results),
        "errors": errors,
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }


def _records() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for _, _, line in storage.scan_domain(DOMAIN):
        try:
            envelope = json.loads(line)
        except json.JSONDecodeError:
            continue
        payload = envelope.get("payload") if isinstance(envelope, dict) else None
        if not isinstance(payload, dict):
            continue
        try:
            validate_event(payload)
        except ValueError:
            continue
        rows.append({"received_at": envelope.get("received_at"), "payload": payload})
    return rows


def validate_query(*, repo: str, component: str | None = None, operation: str | None = None, outcome: str | None = None, since: str | None = None, limit: int = 20) -> datetime | None:
    if not repo or limit < 1 or limit > 500:
        raise ValueError("repo and limit 1..500 are required")
    return _parse_timestamp(since, field="since") if since is not None else None


def query_history(*, repo: str, component: str | None = None, operation: str | None = None, outcome: str | None = None, since: str | None = None, limit: int = 20) -> dict[str, Any]:
    since_at = validate_query(repo=repo, component=component, operation=operation, outcome=outcome, since=since, limit=limit)
    selected: list[dict[str, Any]] = []
    for row in _records():
        event = row["payload"]
        subject = event["subject"]
        data = event.get("data", {})
        if subject.get("repo") != repo:
            continue
        if component and subject.get("component") != component:
            continue
        if operation and subject.get("operation") != operation:
            continue
        actual_outcome = data.get("outcome") or data.get("result")
        if outcome and actual_outcome != outcome:
            continue
        event_at = _parse_timestamp(event["ts"], field="ts")
        if since_at is not None and event_at < since_at:
            continue
        selected.append({**row, "event_at": event_at})
    selected.sort(key=lambda row: (row["event_at"], row["payload"]["event_id"]), reverse=True)
    selected = selected[:limit]
    query = {"repo": repo, "component": component, "operation": operation, "outcome": outcome, "since": since, "limit": limit}
    return {
        "schema_version": "chronik-coding-history.v1",
        "query": query,
        "events": [row["payload"] for row in selected],
        "event_ids": [row["payload"]["event_id"] for row in selected],
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }


def operator_summary(*, since: str | None = None, limit: int = 20) -> dict[str, Any]:
    if limit < 1 or limit > 500:
        raise ValueError("limit 1..500 is required")
    since_at = _parse_timestamp(since, field="since") if since is not None else None
    selected: list[tuple[datetime, dict[str, Any]]] = []
    for row in _records():
        event = row["payload"]
        event_at = _parse_timestamp(event["ts"], field="ts")
        if since_at is not None and event_at < since_at:
            continue
        selected.append((event_at, event))
    selected.sort(key=lambda item: (item[0], item[1]["event_id"]), reverse=True)
    kind_counts = Counter(event["kind"] for _, event in selected)
    repo_counts = Counter(event.get("subject", {}).get("repo", "unknown") for _, event in selected)
    blocker_counts = Counter(
        event.get("data", {}).get("blocker_code", "unspecified")
        for _, event in selected
        if event.get("kind") == "agent.run.blocked"
    )
    recent = []
    for _, event in selected[:limit]:
        recent.append(
            {
                "event_id": event["event_id"],
                "ts": event["ts"],
                "kind": event["kind"],
                "run_id": event.get("source", {}).get("run_id"),
                "subject": event.get("subject", {}),
                "data": event.get("data", {}),
            }
        )
    return {
        "schema_version": "chronik-operator-summary.v1",
        "since": since,
        "event_count": len(selected),
        "counts_by_kind": dict(sorted(kind_counts.items())),
        "counts_by_subject_repo": dict(sorted(repo_counts.items())),
        "blocked_by_code": dict(sorted(blocker_counts.items())),
        "recent": recent,
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
    body = b"".join(canonical_bytes(event) + b"\n" for event in history["events"])
    _atomic_write(output, body)
    receipt = {
        "schema_version": "chronik-history-cohort-receipt.v1",
        "domain": DOMAIN,
        "query": history["query"],
        "event_ids": history["event_ids"],
        "event_count": len(history["event_ids"]),
        "cohort_path": str(output),
        "cohort_sha256": sha256_bytes(body),
        "query_sha256": sha256_bytes(canonical_bytes(history["query"])),
        "generated_at": utc_now(),
        "redaction_contract": "agent-run-event.v0 allow-list",
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
    receipt_path = output.with_suffix(output.suffix + ".receipt.json")
    _atomic_write(receipt_path, json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    return receipt