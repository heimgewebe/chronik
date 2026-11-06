"""Read-only, evidence-bound search over the canonical Chronik agent.ledger.

No alternate journal, ingestion path or persisted search database is created.
The scan validates the committed ledger through the existing Chronik reader.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import heapq
import json
import re
from datetime import datetime
from typing import Any

import coding_memory

SCHEMA_VERSION = "chronik-agent-search.v1"
MAX_PAGE_SIZE = 100
EVENT_ID_RE = re.compile(r"(?:sha256:[a-f0-9]{64}|[0-9A-HJKMNP-TV-Z]{26})\Z")
FILTER_NAMES = (
    "event_id", "repo", "host", "component", "subject_component", "kind",
    "operation", "task_class", "outcome", "pr_number", "bureau_task_id",
    "run_id", "task_id", "since", "until", "keyword",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: str | None, name: str) -> datetime | None:
    return coding_memory._parse_timestamp(value, field=name) if value is not None else None


def _cursor_decode(value: str | None, query_sha256: str) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        if len(value) > 4096:
            raise ValueError("cursor too long")
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        token = json.loads(raw)
        after = token["after"]
        if (
            token.get("v") != 1
            or token.get("query_sha256") != query_sha256
            or not isinstance(token.get("ledger_sha256"), str)
            or not isinstance(after, list)
            or len(after) != 3
            or not isinstance(after[0], str)
            or not isinstance(after[1], str)
            or type(after[2]) is not int
        ):
            raise ValueError("invalid cursor binding")
        _timestamp(after[0], "cursor timestamp")
        return token
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error) as exc:
        raise ValueError("invalid or mismatched search cursor") from exc


def _cursor_encode(query_sha256: str, ledger_sha256: str, after: tuple[str, str, int]) -> str:
    data = _canonical({
        "v": 1,
        "query_sha256": query_sha256,
        "ledger_sha256": ledger_sha256,
        "after": list(after),
    })
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _matches(event: dict[str, Any], filters: dict[str, Any], at: datetime,
             since: datetime | None, until: datetime | None) -> bool:
    source = event.get("source") or {}
    subject = event.get("subject") or {}
    data = event.get("data") or {}
    if filters["event_id"] and event.get("event_id") != filters["event_id"]:
        return False
    # A host-scoped event may have no subject.repo; source.repo remains authoritative.
    if filters["repo"] and filters["repo"] not in (source.get("repo"), subject.get("repo")):
        return False
    if filters["host"] and subject.get("host") != filters["host"]:
        return False
    if filters["component"] and source.get("component") != filters["component"]:
        return False
    if filters["subject_component"] and subject.get("component") != filters["subject_component"]:
        return False
    if filters["kind"] and event.get("kind") != filters["kind"]:
        return False
    if filters["operation"] and coding_memory._event_operation(event) != filters["operation"]:
        return False
    if filters["task_class"] and coding_memory._event_task_class(event) != filters["task_class"]:
        return False
    actual_outcome = data.get("outcome") or data.get("result") or coding_memory.V1_KIND_RESULT.get(event.get("kind"))
    if filters["outcome"] and actual_outcome != filters["outcome"]:
        return False
    if filters["pr_number"] is not None and subject.get("pr_number") != filters["pr_number"]:
        return False
    if filters["bureau_task_id"] and subject.get("bureau_task_id") != filters["bureau_task_id"]:
        return False
    if filters["run_id"] and source.get("run_id") != filters["run_id"]:
        return False
    if filters["task_id"]:
        evidence = event.get("evidence_refs") or []
        if "grabowski-task:" + filters["task_id"] not in evidence:
            return False
    if since is not None and at < since:
        return False
    if until is not None and at > until:
        return False
    if filters["keyword"]:
        # Only structured, schema-validated fields; never scan raw commands or logs.
        safe_fields = (event.get("kind"), source, subject, data.get("summary"),
                       data.get("blocker_code"), data.get("operation"))
        haystack = _canonical(safe_fields).decode("utf-8").casefold()
        if filters["keyword"].casefold() not in haystack:
            return False
    return True


def search_events(
    *, event_id: str | None = None, repo: str | None = None,
    host: str | None = None, component: str | None = None,
    subject_component: str | None = None, kind: str | None = None,
    operation: str | None = None, task_class: str | None = None,
    outcome: str | None = None, pr_number: int | None = None,
    bureau_task_id: str | None = None, run_id: str | None = None,
    task_id: str | None = None, since: str | None = None,
    until: str | None = None, keyword: str | None = None,
    cursor: str | None = None, limit: int = 20,
) -> dict[str, Any]:
    """Search all committed events, sorted newest first, with cursor-bound pages.

    The page's absence of a match is globally exhaustive only when the ledger
    scan completed with integrity and matching_count == 0.
    """
    filters = {
        "event_id": event_id, "repo": repo, "host": host, "component": component,
        "subject_component": subject_component, "kind": kind, "operation": operation,
        "task_class": task_class, "outcome": outcome, "pr_number": pr_number,
        "bureau_task_id": bureau_task_id, "run_id": run_id, "task_id": task_id,
        "since": since, "until": until, "keyword": keyword,
    }
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
        raise ValueError("limit must be in 1..100")
    if not any(value is not None and value != "" for value in filters.values()):
        raise ValueError("at least one search selector is required")
    for name, value in filters.items():
        if isinstance(value, str) and (not value.strip() or len(value) > 500):
            raise ValueError("invalid selector " + name)
    if event_id is not None and EVENT_ID_RE.fullmatch(event_id) is None:
        raise ValueError("invalid event_id")
    if pr_number is not None and (type(pr_number) is not int or pr_number < 1):
        raise ValueError("pr_number must be a positive integer")
    if operation is not None and operation not in coding_memory.OPERATIONS:
        raise ValueError("unsupported operation")
    if task_class is not None and task_class not in coding_memory.TASK_CLASSES:
        raise ValueError("unsupported task_class")
    if outcome is not None and outcome not in coding_memory.OUTCOMES:
        raise ValueError("unsupported outcome")
    since_at, until_at = _timestamp(since, "since"), _timestamp(until, "until")
    if since_at and until_at and since_at > until_at:
        raise ValueError("since is after until")
    qsha = _sha256(filters)
    prior = _cursor_decode(cursor, qsha)
    after = tuple(prior["after"]) if prior else None
    selected: list[tuple[str, str, int, dict[str, Any]]] = []
    matching_count = 0
    remaining_count = 0
    seen_ids: set[str] = set()

    def visit(row: dict[str, Any], at: datetime, sequence: int) -> None:
        nonlocal matching_count, remaining_count
        event = row["payload"]
        eid = event["event_id"]
        if eid in seen_ids:
            raise ValueError("duplicate canonical event_id in ledger")
        seen_ids.add(eid)
        if not _matches(event, filters, at, since_at, until_at):
            return
        matching_count += 1
        key = (at.isoformat(), eid, -sequence)
        if after is not None and key >= after:
            return
        remaining_count += 1
        item = {
            "event": event,
            "event_id": eid,
            "canonical_event_sha256": _sha256(event),
            "event_ref": "chronik:agent.ledger:" + eid,
        }
        entry = (*key, item)
        if len(selected) < limit + 1:
            heapq.heappush(selected, entry)
        elif key > selected[0][:3]:
            heapq.heapreplace(selected, entry)

    ledger_snapshot = coding_memory._scan_record_snapshot(visit)
    if not ledger_snapshot["integrity_valid"]:
        raise ValueError("Chronik ledger has invalid rows; refusing incomplete evidence")
    if prior and prior["ledger_sha256"] != ledger_snapshot["sha256"]:
        raise ValueError("stale search cursor: ledger changed; restart search")
    selected.sort(key=lambda item: item[:3], reverse=True)
    page = selected[:limit]
    has_more = remaining_count > limit
    next_cursor = (
        _cursor_encode(qsha, ledger_snapshot["sha256"], page[-1][:3])
        if has_more and page else None
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "query": filters,
        "query_sha256": qsha,
        "events": [item[3] for item in page],
        "returned": len(page),
        "matching_count": matching_count,
        "remaining_from_cursor": remaining_count,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "search_exhaustive": True,
        "result_scope": "complete_committed_agent_ledger_snapshot",
        "ledger_snapshot": ledger_snapshot,
        "historical_only": True,
        "does_not_establish": coding_memory.DOES_NOT_ESTABLISH,
    }


def get_event(event_id: str) -> dict[str, Any] | None:
    """Return a unique stored event and its exact payload/snapshot binding."""
    result = search_events(event_id=event_id, limit=1)
    if not result["events"]:
        return None
    return {
        **result["events"][0],
        "ledger_snapshot": result["ledger_snapshot"],
        "historical_only": True,
        "does_not_establish": coding_memory.DOES_NOT_ESTABLISH,
    }