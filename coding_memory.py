"""Local, idempotent coding-history import and evidence-bound queries."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
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
OPERATIONS = frozenset({"implement", "review", "merge", "deploy", "runtime_verify", "recovery", "other"})
TASK_CLASSES = frozenset({"coding", "review", "merge", "deploy", "runtime_verify", "recovery", "maintenance", "diagnostic", "other"})
OUTCOMES = frozenset({"started", "completed", "blocked", "failed", "reverted", "outcome_unknown"})
MAX_INTEGRITY_DIAGNOSTICS = 20


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


def validate_event(event: dict[str, Any]) -> None:
    errors = sorted(_validator().iter_errors(event), key=lambda error: list(error.absolute_path))
    if errors:
        error = errors[0]
        path = "/".join(str(part) for part in error.absolute_path) or "<root>"
        raise ValueError(f"invalid coding event at {path}: {error.message}")
    _parse_timestamp(event["ts"], field="ts")


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


def _prepare_grabowski_outbox_source(source: Path, *, receipt_dir: Path) -> dict[str, Any]:
    raw, events = _read_jsonl_snapshot(source)
    if not events:
        raise ValueError(f"outbox contains no events: {source}")
    for event in events:
        _validate_grabowski_source(event)
    source_sha256 = sha256_bytes(raw)
    receipt_path = _receipt_path(source, receipt_dir)
    previous = _load_receipt(receipt_path)
    return {
        "source": source,
        "raw": raw,
        "events": events,
        "source_sha256": source_sha256,
        "receipt_path": receipt_path,
        "source_unchanged": previous is not None and previous.get("source_sha256") == source_sha256,
    }


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
    }


def _import_prepared_grabowski_sources(
    prepared_sources: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, object], list[tuple[str, Exception]]]:
    grouped = storage.write_payload_unique_groups(
        DOMAIN,
        [
            (str(index), _envelope_lines(prepared["events"]))
            for index, prepared in enumerate(prepared_sources)
        ],
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
    sources = sorted(source_dir.glob("*.jsonl")) if source_dir.is_dir() else []
    prepared_sources: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    target_scans: int | None = 0
    target_records_scanned: int | None = 0
    for source in sources:
        try:
            prepared_sources.append(
                _prepare_grabowski_outbox_source(source, receipt_dir=receipt_dir)
            )
        except (OSError, ValueError, storage.StorageError) as exc:
            errors.append({"source_path": str(source), "error": str(exc)})
    if prepared_sources:
        try:
            results, grouped, receipt_errors = _import_prepared_grabowski_sources(
                prepared_sources
            )
            target_scans = int(grouped.get("target_scans", 0))
            target_records_scanned = int(grouped.get("target_records_scanned", 0))
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
            errors.append({"source_path": "<batch>", "error": str(exc)})
    return {
        "schema_version": "chronik-grabowski-outbox-batch.v1",
        "source_dir": str(source_dir),
        "receipt_dir": str(receipt_dir),
        "files_seen": len(sources),
        "files_imported_or_confirmed": len(results),
        "files_unchanged": sum(1 for result in results if result.get("unchanged") is True),
        "events_imported": sum(int(result.get("imported", 0)) for result in results),
        "events_skipped_existing": sum(int(result.get("skipped_existing", 0)) for result in results),
        "target_scans": target_scans,
        "target_records_scanned": target_records_scanned,
        "errors": errors,
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }


def _record_snapshot() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    invalid_record_count = 0
    total_record_count = 0
    raw_snapshot = storage.read_domain_snapshot(DOMAIN)
    complete_bytes = len(raw_snapshot)
    snapshot_sha256 = sha256_bytes(raw_snapshot)
    start_offset = 0

    complete_lines = raw_snapshot.split(b"\n")[:-1] if raw_snapshot else []
    for content in complete_lines:
        next_offset = start_offset + len(content) + 1
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
            validate_event(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            invalid_record_count += 1
            if len(diagnostics) < MAX_INTEGRITY_DIAGNOSTICS:
                diagnostics.append({
                    "offset": start_offset,
                    "next_offset": next_offset,
                    "error": str(exc),
                })
            start_offset = next_offset
            continue
        rows.append({"received_at": envelope.get("received_at"), "payload": payload})
        start_offset = next_offset

    ledger_snapshot = {
        "domain": DOMAIN,
        "sha256": snapshot_sha256,
        "complete_bytes": complete_bytes,
        "total_record_count": total_record_count,
        "valid_record_count": len(rows),
        "invalid_record_count": invalid_record_count,
        "integrity_valid": invalid_record_count == 0,
        "diagnostics": diagnostics,
        "diagnostics_truncated": invalid_record_count > len(diagnostics),
    }
    return rows, ledger_snapshot


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


def _target(*, repo: str | None, host: str | None) -> dict[str, str]:
    if repo is not None:
        return {"scope": "repository", "repo": repo}
    assert host is not None
    return {"scope": "host", "host": host}


def _matches_target(subject: dict[str, Any], *, repo: str | None, host: str | None) -> bool:
    if repo is not None:
        return subject.get("scope") != "host" and subject.get("repo") == repo
    return subject.get("scope") == "host" and subject.get("host") == host


def validate_query(*, repo: str | None = None, host: str | None = None, component: str | None = None, operation: str | None = None, task_class: str | None = None, outcome: str | None = None, since: str | None = None, limit: int = 20) -> datetime | None:
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


def query_history(*, repo: str | None = None, host: str | None = None, component: str | None = None, operation: str | None = None, task_class: str | None = None, outcome: str | None = None, since: str | None = None, limit: int = 20) -> dict[str, Any]:
    since_at = validate_query(repo=repo, host=host, component=component, operation=operation, task_class=task_class, outcome=outcome, since=since, limit=limit)
    rows, ledger_snapshot = _record_snapshot()
    selected: list[dict[str, Any]] = []
    for row in rows:
        event = row["payload"]
        subject = event["subject"]
        data = event.get("data", {})
        if not _matches_target(subject, repo=repo, host=host):
            continue
        if component and _event_source_component(event) != component:
            continue
        if operation and _event_operation(event) != operation:
            continue
        if task_class and _event_task_class(event) != task_class:
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
    query = {"repo": repo, "host": host, "component": component, "operation": operation, "task_class": task_class, "outcome": outcome, "since": since, "limit": limit}
    return {
        "schema_version": "chronik-coding-history.v1",
        "query": query,
        "target": _target(repo=repo, host=host),
        "events": [row["payload"] for row in selected],
        "event_ids": [row["payload"]["event_id"] for row in selected],
        "ledger_snapshot": ledger_snapshot,
        "historical_only": True,
        "does_not_establish": DOES_NOT_ESTABLISH,
    }


def operator_summary(*, since: str | None = None, limit: int = 20) -> dict[str, Any]:
    if limit < 1 or limit > 500:
        raise ValueError("limit 1..500 is required")
    since_at = _parse_timestamp(since, field="since") if since is not None else None
    rows, ledger_snapshot = _record_snapshot()
    selected: list[tuple[datetime, dict[str, Any]]] = []
    for row in rows:
        event = row["payload"]
        event_at = _parse_timestamp(event["ts"], field="ts")
        if since_at is not None and event_at < since_at:
            continue
        selected.append((event_at, event))
    selected.sort(key=lambda item: (item[0], item[1]["event_id"]), reverse=True)
    kind_counts = Counter(event["kind"] for _, event in selected)
    repo_counts = Counter(event.get("subject", {}).get("repo", "unknown") for _, event in selected)
    host_counts = Counter(
        event.get("subject", {}).get("host")
        for _, event in selected
        if event.get("subject", {}).get("scope") == "host" and event.get("subject", {}).get("host")
    )
    target_counts = Counter()
    operation_counts = Counter()
    task_class_counts = Counter()
    for _, event in selected:
        subject = event.get("subject", {})
        if subject.get("scope") == "host":
            target_counts[f"host:{subject.get('host', 'unknown')}"] += 1
        else:
            target_counts[f"repository:{subject.get('repo', 'unknown')}"] += 1
        operation_counts[_event_operation(event) or "unspecified"] += 1
        task_class_counts[_event_task_class(event) or "unspecified"] += 1
    blocker_counts = Counter(
        event.get("data", {}).get("blocker_code", "unspecified")
        for _, event in selected
        if event.get("kind") == "agent.run.blocked"
    )
    recent = []
    for _, event in selected[:limit]:
        subject = event.get("subject", {})
        recent.append(
            {
                "event_id": event["event_id"],
                "ts": event["ts"],
                "kind": event["kind"],
                "run_id": event.get("source", {}).get("run_id"),
                "target": {"scope": "host", "host": subject.get("host")} if subject.get("scope") == "host" else {"scope": "repository", "repo": subject.get("repo")},
                "subject": subject,
                "operation": _event_operation(event),
                "task_class": _event_task_class(event),
                "data": event.get("data", {}),
            }
        )
    return {
        "schema_version": "chronik-operator-summary.v1",
        "since": since,
        "event_count": len(selected),
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
