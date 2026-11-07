"""Bounded, evidence-bound semantic knowledge in Chronik's existing JSONL ledger.

Chronik records history; neither this module nor its receipts grant operator authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from canonical_ingest import build_envelope
import storage

DOMAIN = "knowledge.ledger"
VERSION = "chronik-knowledge-event.v1"
KIND = "knowledge.insight.published.v1"
TYPES = frozenset({
    "decision", "root_cause", "repair", "refutation", "open_problem",
    "requirement", "operation", "observation",
})
STATES = frozenset({
    "observed", "hypothesis", "confirmed", "refuted", "decided",
    "implemented", "production_verified", "superseded",
})
RELATIONS = frozenset({"supersedes", "refutes", "confirms", "amends"})
REQUIRED = frozenset({
    "schema_version", "event_id", "record_key", "kind", "ts", "source",
    "subject", "knowledge_type", "epistemic_status", "statement",
    "evidence_refs", "relations",
})
SOURCE_KEYS = frozenset({"system", "component"})
SUBJECT_KEYS = frozenset({"repo", "host", "service", "component", "pr_number", "task_id"})
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9:/._@#-]{0,239}\Z")
KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,159}\Z")
# Guard common credential formats, not a substitute for explicit data minimization.
SECRETS = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?i:github_pat_[A-Za-z0-9_]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|"
    r"Bearer\s+\S+|(?:password|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*\S+)"
)
MAX_ENTRY_BYTES = 16 * 1024
MAX_EVENTS_PER_IMPORT = 200


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _text(value: Any, maximum: int, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{label} must be a nonempty bounded string")
    if "\x00" in value or SECRETS.search(value):
        raise ValueError(f"{label} contains forbidden raw or credential-like data")
    return value


def _timestamp(value: Any) -> datetime:
    _text(value, 40, "ts")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("ts must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("ts must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def identity(source: dict[str, Any], record_key: str) -> str:
    return "sha256:" + digest(canonical([source, record_key]))


def validate(event: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(event, dict) or set(event) != REQUIRED:
        raise ValueError("unexpected or missing knowledge fields")
    if event["schema_version"] != VERSION or event["kind"] != KIND:
        raise ValueError("unsupported knowledge event contract")
    _timestamp(event["ts"])
    record_key = _text(event["record_key"], 160, "record_key")
    if not KEY.fullmatch(record_key):
        raise ValueError("record_key must be a stable opaque reference")
    source = event["source"]
    if not isinstance(source, dict) or set(source) != SOURCE_KEYS:
        raise ValueError("source requires system and component")
    source = {name: _text(source[name], 100, f"source.{name}") for name in SOURCE_KEYS}
    if not KEY.fullmatch(source["system"]) or not KEY.fullmatch(source["component"]):
        raise ValueError("invalid source identity")
    if event["event_id"] != identity(source, record_key):
        raise ValueError("event_id does not match source and record_key")
    subject = event["subject"]
    if (not isinstance(subject, dict) or not subject or
            not set(subject).issubset(SUBJECT_KEYS)):
        raise ValueError("subject needs a bounded target")
    for name, value in subject.items():
        if name == "pr_number":
            if type(value) is not int or value < 1:
                raise ValueError("pr_number must be positive integer")
        else:
            _text(value, 200, "subject." + name)
            if not KEY.fullmatch(value):
                raise ValueError("invalid subject reference")
    if not isinstance(event["knowledge_type"], str) or event["knowledge_type"] not in TYPES:
        raise ValueError("unsupported knowledge type")
    if not isinstance(event["epistemic_status"], str) or event["epistemic_status"] not in STATES:
        raise ValueError("unsupported epistemic status")
    statement = _text(event["statement"], 900, "statement")
    if "\n" in statement or "\r" in statement:
        raise ValueError("statement must be a single minimized sentence")
    refs = event["evidence_refs"]
    if (not isinstance(refs, list) or not 1 <= len(refs) <= 8
            or any(not isinstance(ref, str) for ref in refs)
            or len(set(refs)) != len(refs)):
        raise ValueError("each knowledge entry needs 1-8 distinct evidence refs")
    for ref in refs:
        _text(ref, 240, "evidence_ref")
        if not REF.fullmatch(ref):
            raise ValueError("invalid evidence reference")
    relations = event["relations"]
    if not isinstance(relations, list) or len(relations) > 8:
        raise ValueError("invalid knowledge relations")
    seen = set()
    for relation in relations:
        if (not isinstance(relation, dict) or set(relation) != {"type", "event_id"}
                or not isinstance(relation["type"], str)
                or relation["type"] not in RELATIONS
                or not isinstance(relation["event_id"], str)
                or not SHA.fullmatch(relation["event_id"])
                or relation["event_id"] == event["event_id"]):
            raise ValueError("invalid knowledge relation")
        pair = (relation["type"], relation["event_id"])
        if pair in seen:
            raise ValueError("duplicate knowledge relation")
        seen.add(pair)
    if len(canonical(event)) > MAX_ENTRY_BYTES:
        raise ValueError("knowledge event exceeds size budget")
    return event


def build(*, record_key: str, ts: str, source: dict[str, str],
          subject: dict[str, Any], knowledge_type: str, epistemic_status: str,
          statement: str, evidence_refs: list[str],
          relations: list[dict[str, str]] | None = None) -> dict[str, Any]:
    event = {
        "schema_version": VERSION, "record_key": record_key, "kind": KIND,
        "ts": ts, "source": source, "subject": subject,
        "knowledge_type": knowledge_type, "epistemic_status": epistemic_status,
        "statement": statement, "evidence_refs": evidence_refs,
        "relations": [] if relations is None else relations,
    }
    event["event_id"] = identity(source, record_key)
    return validate(event)


def _atomic_write(path: Path, raw: bytes) -> bool:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        existing = _read_regular(path)
        if existing != raw:
            raise ValueError("existing identity has different payload")
        return False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        dirfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        return True
    except BaseException:
        # An incomplete or uncertain write remains visible for explicit recovery.
        raise


def capture(event: dict[str, Any], outbox_root: Path) -> dict[str, Any]:
    validate(event)
    path = outbox_root / "knowledge" / (event["event_id"][7:] + ".json")
    created = _atomic_write(path, canonical(event) + b"\n")
    return {"event_id": event["event_id"], "queued": True,
            "new": created, "path": str(path), "ledger_verified": False}


def _read_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("secure outbox read requires O_NOFOLLOW")
    descriptor = os.open(path, flags | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        file_stat = os.fstat(handle.fileno())
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > MAX_ENTRY_BYTES + 1:
            raise ValueError("outbox entry is not a bounded regular file")
        raw = handle.read(MAX_ENTRY_BYTES + 2)
        if len(raw) > MAX_ENTRY_BYTES + 1:
            raise ValueError("outbox entry exceeds size limit")
        return raw


def _read_outbox(path: Path) -> dict[str, Any]:
    raw = _read_regular(path)
    if not raw.endswith(b"\n") or len(raw) > MAX_ENTRY_BYTES + 1:
        raise ValueError("invalid outbox record")
    event = validate(json.loads(raw))
    if path.name != event["event_id"][7:] + ".json":
        raise ValueError("outbox filename and identity mismatch")
    return event


def _read_ledger() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    raw = storage.read_domain_snapshot(DOMAIN)
    ledger: dict[str, dict[str, Any]] = {}
    for line in raw.splitlines():
        try:
            envelope = json.loads(line)
            event = validate(envelope["payload"])
            if envelope["domain"] != DOMAIN:
                raise ValueError("domain mismatch")
            prior = ledger.get(event["event_id"])
            if prior is not None:
                raise ValueError("duplicate canonical event identity")
            ledger[event["event_id"]] = event
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid committed knowledge ledger record") from exc
    return ledger, {
        "domain": DOMAIN, "complete_bytes": len(raw), "sha256": digest(raw),
        "integrity_valid": True, "record_count": len(ledger),
    }


def get(event_id: str) -> dict[str, Any]:
    if not isinstance(event_id, str) or not SHA.fullmatch(event_id):
        raise ValueError("invalid event ID")
    ledger, snapshot = _read_ledger()
    event = ledger.get(event_id)
    return {
        "found": event is not None, "event_id": event_id, "event": event,
        "ledger_snapshot": snapshot, "historical_only": True,
        "superseded_by": [
            newer["event_id"] for newer in ledger.values()
            if any(r["type"] == "supersedes" and r["event_id"] == event_id
                   for r in newer["relations"])
        ],
    }


def search(*, repo: str | None = None, host: str | None = None,
           knowledge_type: str | None = None, epistemic_status: str | None = None,
           keyword: str | None = None, limit: int = 20) -> dict[str, Any]:
    """Bounded historical recall; requires at least one selector."""
    if not any((repo, host, knowledge_type, epistemic_status, keyword)):
        raise ValueError("knowledge search needs at least one selector")
    if type(limit) is not int or not 1 <= limit <= 20:
        raise ValueError("knowledge search limit must be between 1 and 20")
    for name, value in (("repo", repo), ("host", host), ("keyword", keyword)):
        if value is not None:
            _text(value, 200, name)
    if knowledge_type is not None and knowledge_type not in TYPES:
        raise ValueError("unsupported knowledge type")
    if epistemic_status is not None and epistemic_status not in STATES:
        raise ValueError("unsupported epistemic status")
    ledger, snapshot = _read_ledger()
    matching = [
        event for event in ledger.values()
        if (repo is None or event["subject"].get("repo") == repo)
        and (host is None or event["subject"].get("host") == host)
        and (knowledge_type is None or event["knowledge_type"] == knowledge_type)
        and (epistemic_status is None or event["epistemic_status"] == epistemic_status)
        and (keyword is None or keyword.casefold() in (
            event["statement"] + " " + " ".join(event["evidence_refs"])
        ).casefold())
    ]
    matching.sort(key=lambda event: (_timestamp(event["ts"]), event["event_id"]), reverse=True)
    successors = {
        relation["event_id"]: event["event_id"]
        for event in ledger.values()
        for relation in event["relations"]
        if relation["type"] == "supersedes"
    }
    return {
        "schema_version": "chronik-knowledge-search.v1",
        "historical_only": True, "matching_count": len(matching),
        "returned": min(len(matching), limit),
        "has_more": len(matching) > limit,
        "events": [
            {"event": value, "superseded_by": successors.get(value["event_id"])}
            for value in matching[:limit]
        ],
        "ledger_snapshot": snapshot,
        "does_not_establish": ["current_git_state", "current_runtime_state",
                               "task_completion", "unrecorded_knowledge"],
    }


def _line(event: dict[str, Any]) -> str:
    # Stable received_at makes replays byte-identical for the identity index.
    envelope = build_envelope(DOMAIN, event, received_at=_timestamp(event["ts"]))
    return canonical(envelope).decode("utf-8")


def import_pending(outbox_root: Path, data_dir: Path,
                   *, max_events: int = MAX_EVENTS_PER_IMPORT) -> dict[str, Any]:
    if not data_dir.is_dir():
        raise ValueError("Chronik data directory unavailable")
    if not 1 <= max_events <= MAX_EVENTS_PER_IMPORT:
        raise ValueError("invalid import budget")
    storage.DATA_DIR = data_dir.resolve(strict=True)
    queued = outbox_root / "knowledge"
    paths = sorted(queued.glob("*.json")) if queued.is_dir() else []
    ledger, _ = _read_ledger()
    imported = already_present = verified = 0
    # Only new/uncertain ledger writes use the per-cycle import budget.
    # Retained already-imported source records must not starve later entries.
    new_attempts = 0
    verified_event_ids: list[str] = []
    errors: list[dict[str, str]] = []
    recovered_after_uncertain_write: list[str] = []
    for path in paths:
        event = None
        try:
            event = _read_outbox(path)
            old = ledger.get(event["event_id"])
            if old is not None and canonical(old) != canonical(event):
                raise ValueError("canonical identity conflict")
            if old is not None:
                # _read_ledger already proved this identity in one coherent
                # committed snapshot; no per-entry full-ledger re-read needed.
                already_present += 1
                verified_event_ids.append(event["event_id"])
                verified += 1
                continue
            if new_attempts >= max_events:
                continue
            new_attempts += 1
            count, skipped = storage.write_payload_unique(
                DOMAIN, [_line(event)], identity_key="event_id")
            imported += count
            already_present += skipped
            # A successful append alone never proves canonical knowledge.
            readback = get(event["event_id"])
            if not readback["found"] or canonical(readback["event"]) != canonical(event):
                raise ValueError("canonical readback mismatch")
            ledger[event["event_id"]] = event
            verified_event_ids.append(event["event_id"])
            verified += 1
        except storage.StorageError as exc:
            # A failed commit may already have appended the canonical ledger.
            # Resolve the exact identity through readback before any later replay.
            if event is not None:
                try:
                    observed = get(event["event_id"])
                    if (observed["found"] and
                            canonical(observed["event"]) == canonical(event)):
                        ledger[event["event_id"]] = event
                        verified_event_ids.append(event["event_id"])
                        recovered_after_uncertain_write.append(event["event_id"])
                        verified += 1
                        continue
                except (OSError, ValueError, storage.StorageError):
                    pass
            errors.append({"event_id": path.stem, "error": type(exc).__name__})
        except (OSError, ValueError) as exc:
            errors.append({"event_id": path.stem, "error": type(exc).__name__})
    _, snapshot = _read_ledger()
    return {
        "schema_version": "chronik-knowledge-import-receipt.v1",
        "requested": len(paths), "processed": verified + len(errors),
        "imported": imported, "already_present": already_present,
        "verified": verified, "verified_event_ids": verified_event_ids,
        "resolved_after_uncertain_write": recovered_after_uncertain_write,
        "pending": max(0, len(paths)-verified),
        "errors": errors, "ledger_snapshot": snapshot,
        "receipt_sha256": digest(canonical([verified_event_ids, errors, snapshot])),
    }


def coverage(outbox_root: Path, data_dir: Path) -> dict[str, Any]:
    if not data_dir.is_dir():
        raise ValueError("Chronik data directory unavailable")
    storage.DATA_DIR = data_dir.resolve(strict=True)
    ledger, snapshot = _read_ledger()
    root = outbox_root / "knowledge"
    paths = sorted(root.glob("*.json")) if root.is_dir() else []
    verified, pending, invalid = [], [], []
    for path in paths:
        try:
            entry = _read_outbox(path)
            existing = ledger.get(entry["event_id"])
            if existing is None:
                pending.append(entry["event_id"])
            elif canonical(existing) != canonical(entry):
                invalid.append(entry["event_id"])
            else:
                verified.append(entry["event_id"])
        except (OSError, ValueError):
            invalid.append(path.name)
    return {
        "schema_version": "chronik-knowledge-coverage.v1",
        "verified": verified, "pending": pending, "invalid": invalid,
        "unobservable_sources": "not_audited",
        "ledger_snapshot": snapshot,
    }