#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "docs/chronik/operator-event-policy-v1.json"
SCHEMA = ROOT / "docs/chronik/operator-event-v1.schema.json"
FIXTURES = ROOT / "tests/fixtures/operator-events"


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be object")
    return value


def validate_policy() -> dict[str, Any]:
    policy = load(POLICY)
    allowed = policy.get("allowed")
    if not isinstance(allowed, list) or not allowed:
        raise ValueError("allowed event list missing")
    event_types = [entry.get("event_type") for entry in allowed]
    expected = {"operator.lifecycle", "operator.deployment", "operator.failure", "operator.policy_block", "operator.recovery"}
    if set(event_types) != expected or len(event_types) != len(expected):
        raise ValueError("allowed event types must equal the bounded five-type allowlist")
    forbidden = set(policy.get("forbidden", []))
    required_forbidden = {"git.commit", "git.diff", "git.patch", "bureau.task.updated", "operator.stdout", "operator.stderr", "operator.secret"}
    if not required_forbidden <= forbidden:
        raise ValueError("forbidden duplicate/raw event set incomplete")
    for entry in allowed:
        if not entry.get("consumer") or not entry.get("query_use"):
            raise ValueError(f"{entry.get('event_type')}: named consumer and query use required")
        if not isinstance(entry.get("retention_days"), int) or not 1 <= entry["retention_days"] <= 365:
            raise ValueError(f"{entry.get('event_type')}: retention must be bounded to 1..365 days")
    boundary = policy.get("boundary", {})
    if not boundary or not all(value is True for value in boundary.values()):
        raise ValueError("all non-authority boundaries must be true")
    redaction = policy.get("redaction", {})
    if redaction.get("raw_log_storage") is not False:
        raise ValueError("raw log storage must remain false")
    return policy


def _walk_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(key.lower())
            keys.update(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_walk_keys(child))
    return keys


def validate_event(path: Path) -> dict[str, Any]:
    policy = validate_policy()
    payload = load(path)
    schema = load(SCHEMA)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)
    forbidden_keys = set(policy["redaction"]["forbidden_payload_keys"])
    present = _walk_keys(payload)
    leaked = sorted(forbidden_keys & present)
    if leaked:
        raise ValueError(f"{path}: forbidden payload keys present: {leaked}")
    return payload


def query_events(path: Path, *, event_type: str) -> list[dict[str, Any]]:
    policy = validate_policy()
    allowed = {entry["event_type"] for entry in policy["allowed"]}
    if event_type not in allowed:
        raise ValueError(f"event type not allowed: {event_type}")
    matches: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{number}: invalid JSON") from exc
        if payload.get("event_type") == event_type:
            matches.append(payload)
    return matches


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", type=Path)
    parser.add_argument("--query-jsonl", type=Path)
    parser.add_argument("--event-type")
    args = parser.parse_args()
    if args.event:
        result = validate_event(args.event)
        output = {"status": "valid", "event_type": result["event_type"]}
    elif args.query_jsonl:
        if not args.event_type:
            parser.error("--event-type is required with --query-jsonl")
        matches = query_events(args.query_jsonl, event_type=args.event_type)
        output = {"status": "valid", "matches": len(matches), "events": matches}
    else:
        policy = validate_policy()
        fixtures = sorted(FIXTURES.glob("*.valid.json"))
        for path in fixtures:
            validate_event(path)
        output = {"status": "valid", "allowed": len(policy["allowed"]), "fixtures": len(fixtures)}
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
