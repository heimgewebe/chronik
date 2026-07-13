"""Local, idempotent coding-history import and frozen query receipts."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft7Validator

import storage
from canonical_ingest import build_envelope

DOMAIN = "agent.ledger"
SCHEMA_PATH = Path(__file__).resolve().parent / "docs" / "chronik" / "agent-run-event-v0.schema.json"
DOES_NOT_ESTABLISH = ["current_git_state", "current_ci_state", "current_runtime_state", "safe_retry"]


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def query_history(*, repo: str, component: str | None = None, operation: str | None = None, outcome: str | None = None, since: str | None = None, limit: int = 20) -> dict[str, Any]:
    if not repo or limit < 1 or limit > 500:
        raise ValueError("repo and limit 1..500 are required")
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
        if since and event.get("ts", "") < since:
            continue
        selected.append(row)
    selected.sort(key=lambda row: (row["payload"]["ts"], row["payload"]["event_id"]), reverse=True)
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


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
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
