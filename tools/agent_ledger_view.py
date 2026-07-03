"""Demo view for Chronik Agent Ledger v0 events.

The view is intentionally read-only and producer-agnostic. It accepts raw
`agent-run-event.v0` objects, Chronik `/v1/events` response objects, or JSONL
lines containing Chronik envelopes.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import jsonschema

from tools.chronik_outbox import validate_event


@dataclass(frozen=True)
class AgentRunViewRow:
    repo: str
    branch: str
    result: str
    blocker_code: str
    evidence_ref: str
    ts: str


@dataclass(frozen=True)
class AgentRunLaneRow:
    repo: str
    run_id: str
    branch: str
    result: str
    blocker_code: str
    evidence_ref: str
    ts: str


def parse_ts(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError(f"expected UTC Z timestamp, got {value!r}")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def extract_payload(record: dict[str, Any]) -> dict[str, Any] | None:
    payload = record.get("payload")
    if isinstance(payload, dict):
        return payload
    return record


def load_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    if path.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    loaded = json.loads(text)
    if isinstance(loaded, dict) and isinstance(loaded.get("events"), list):
        return loaded["events"]
    if isinstance(loaded, list):
        return loaded
    if isinstance(loaded, dict):
        return [loaded]
    raise ValueError(f"unsupported JSON payload in {path}")


def iter_agent_run_events(records: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    for record in records:
        payload = extract_payload(record)
        if payload is None:
            continue
        try:
            validate_event(payload)
        except jsonschema.exceptions.ValidationError:
            continue
        yield payload


def build_view(records: Iterable[dict[str, Any]]) -> list[AgentRunViewRow]:
    latest_by_repo: dict[str, tuple[datetime, AgentRunViewRow]] = {}
    for event in iter_agent_run_events(records):
        subject = event["subject"]
        repo = subject["repo"]
        data = event.get("data", {})
        evidence_refs = event.get("evidence_refs", [])
        row = AgentRunViewRow(
            repo=repo,
            branch=subject.get("branch", ""),
            result=data.get("result", ""),
            blocker_code=data.get("blocker_code", ""),
            evidence_ref=evidence_refs[0] if evidence_refs else "",
            ts=event["ts"],
        )
        event_ts = parse_ts(event["ts"])
        current = latest_by_repo.get(repo)
        if current is None or event_ts >= current[0]:
            latest_by_repo[repo] = (event_ts, row)
    return [entry[1] for entry in sorted(latest_by_repo.values(), key=lambda item: item[1].repo)]


def build_run_view(records: Iterable[dict[str, Any]]) -> list[AgentRunLaneRow]:
    latest_by_run: dict[tuple[str, str], tuple[datetime, AgentRunLaneRow]] = {}
    for event in iter_agent_run_events(records):
        subject = event["subject"]
        source = event["source"]
        repo = subject["repo"]
        run_id = source["run_id"]
        data = event.get("data", {})
        evidence_refs = event.get("evidence_refs", [])
        row = AgentRunLaneRow(
            repo=repo,
            run_id=run_id,
            branch=subject.get("branch", ""),
            result=data.get("result", ""),
            blocker_code=data.get("blocker_code", ""),
            evidence_ref=evidence_refs[0] if evidence_refs else "",
            ts=event["ts"],
        )
        event_ts = parse_ts(event["ts"])
        key = (repo, run_id)
        current = latest_by_run.get(key)
        if current is None or event_ts >= current[0]:
            latest_by_run[key] = (event_ts, row)
    return [
        entry[1]
        for entry in sorted(
            latest_by_run.values(),
            key=lambda item: (item[1].repo, item[1].run_id),
        )
    ]


def format_table(rows: list[AgentRunViewRow | AgentRunLaneRow]) -> str:
    headers = ["repo", "branch", "result", "blocker_code", "evidence_ref", "ts"]
    if rows and hasattr(rows[0], "run_id"):
        headers = ["repo", "run_id", "branch", "result", "blocker_code", "evidence_ref", "ts"]
    values = [[getattr(row, header) for header in headers] for row in rows]
    widths = [len(header) for header in headers]
    for value_row in values:
        for index, value in enumerate(value_row):
            widths[index] = max(widths[index], len(value))

    lines = ["  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))]
    lines.append("  ".join("-" * width for width in widths))
    for value_row in values:
        lines.append("  ".join(value.ljust(widths[index]) for index, value in enumerate(value_row)))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render the Agent Ledger v0 demo view")
    parser.add_argument("input", nargs="+", help="JSON or JSONL files containing raw events or Chronik /v1/events output")
    parser.add_argument("--format", choices=["table", "json"], default="table")
    parser.add_argument("--view", choices=["repo", "run"], default="repo")
    args = parser.parse_args(argv)

    records: list[dict[str, Any]] = []
    for input_path in args.input:
        records.extend(load_records(Path(input_path)))

    rows = build_run_view(records) if args.view == "run" else build_view(records)
    if args.format == "json":
        print(json.dumps([asdict(row) for row in rows], indent=2, sort_keys=True))
    else:
        print(format_table(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
