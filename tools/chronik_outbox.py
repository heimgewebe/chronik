"""Outbox helper for Chronik agent-run events.

This module is producer-agnostic. It validates and stores local
``agent-run-event.v0`` payloads, can flush them to Chronik, and can compact
files that already have successful flush receipts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlencode

import httpx
import jsonschema
from jsonschema import Draft7Validator

DOMAIN = "agent.ledger"
DEFAULT_STATE_ROOT = Path(".local/state")
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "chronik" / "agent-run-event-v0.schema.json"
SAFE_PART = re.compile(r"[^A-Za-z0-9_.-]+")


class OutboxError(RuntimeError):
    """Raised for expected outbox failures."""


@dataclass(frozen=True)
class OutboxFileStatus:
    path: Path
    events: int
    bytes: int
    flushed: bool


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_schema() -> dict[str, Any]:
    schema = load_json(SCHEMA_PATH)
    Draft7Validator.check_schema(schema)
    return schema


def validate_event(event: dict[str, Any]) -> None:
    jsonschema.validate(event, load_schema())


def safe_part(value: str, label: str) -> str:
    cleaned = SAFE_PART.sub("_", value.strip()).strip("._-")
    if not cleaned:
        raise OutboxError(f"{label} is empty after sanitization")
    return cleaned[:160]


def producer_and_run_id(event: dict[str, Any]) -> tuple[str, str]:
    try:
        source = event["source"]
        component = source["component"]
        run_id = source["run_id"]
    except (KeyError, TypeError) as exc:
        raise OutboxError("event.source.component and event.source.run_id are required") from exc
    return safe_part(str(component), "producer"), safe_part(str(run_id), "run_id")


def outbox_path(event: dict[str, Any], state_root: Path = DEFAULT_STATE_ROOT) -> Path:
    producer, run_id = producer_and_run_id(event)
    return state_root / producer / "chronik-outbox" / f"{producer}_{run_id}.jsonl"


def receipt_path(path: Path) -> Path:
    return path.parent / ".flushed" / f"{path.name}.receipt.json"


def append_event(event: dict[str, Any], state_root: Path = DEFAULT_STATE_ROOT) -> Path:
    validate_event(event)
    path = outbox_path(event, state_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")))
        handle.write("\n")
    return path


def iter_outbox_files(state_root: Path = DEFAULT_STATE_ROOT) -> Iterable[Path]:
    yield from sorted(state_root.glob("*/chronik-outbox/*.jsonl"))


def read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise OutboxError(f"{path}:{line_number}: invalid jsonl") from exc
            validate_event(event)
            events.append(event)
    return events


def status(state_root: Path = DEFAULT_STATE_ROOT) -> list[OutboxFileStatus]:
    entries: list[OutboxFileStatus] = []
    for path in iter_outbox_files(state_root):
        event_count = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
        entries.append(
            OutboxFileStatus(
                path=path,
                events=event_count,
                bytes=path.stat().st_size,
                flushed=receipt_path(path).exists(),
            )
        )
    return entries


def token_from_env() -> str:
    token_blob = os.environ.get("CHRONIK_TOKEN", "")
    tokens = [token.strip() for token in re.split(r"[,\n]+", token_blob) if token.strip()]
    if not tokens:
        raise OutboxError("CHRONIK_TOKEN is required for flush")
    return tokens[0]


def post_json(url: str, payload: list[dict[str, Any]], token: str, timeout: float) -> tuple[int, str]:
    headers = {"Content-Type": "application/json", "X-Auth": token}
    with httpx.Client(timeout=timeout) as client:
        response = client.post(url, json=payload, headers=headers)
    return response.status_code, response.text


def flush_file(
    path: Path,
    *,
    base_url: str,
    token: str | None = None,
    timeout: float = 5.0,
    sender: Callable[[str, list[dict[str, Any]], str, float], tuple[int, str]] | None = None,
) -> Path:
    events = read_events(path)
    if not events:
        raise OutboxError(f"{path} contains no events")
    resolved_token = token or token_from_env()
    url = f"{base_url.rstrip('/')}/v1/ingest?{urlencode({'domain': DOMAIN})}"
    status_code, text = (sender or post_json)(url, events, resolved_token, timeout)
    if not 200 <= status_code < 300:
        raise OutboxError(f"flush failed for {path}: HTTP {status_code}: {text}")

    receipt = receipt_path(path)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(
        json.dumps(
            {
                "domain": DOMAIN,
                "source_path": str(path),
                "event_count": len(events),
                "flushed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "status_code": status_code,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return receipt


def flush_all(
    *,
    state_root: Path = DEFAULT_STATE_ROOT,
    base_url: str,
    token: str | None = None,
    timeout: float = 5.0,
    sender: Callable[[str, list[dict[str, Any]], str, float], tuple[int, str]] | None = None,
) -> list[Path]:
    receipts: list[Path] = []
    for path in iter_outbox_files(state_root):
        if receipt_path(path).exists():
            continue
        receipts.append(flush_file(path, base_url=base_url, token=token, timeout=timeout, sender=sender))
    return receipts


def compact(state_root: Path = DEFAULT_STATE_ROOT) -> list[Path]:
    removed: list[Path] = []
    for path in iter_outbox_files(state_root):
        if receipt_path(path).exists():
            path.unlink()
            removed.append(path)
    return removed


def print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Chronik agent ledger outbox v0")
    parser.add_argument("--state-root", default=str(DEFAULT_STATE_ROOT))
    subparsers = parser.add_subparsers(dest="command", required=True)

    append_parser = subparsers.add_parser("append")
    append_parser.add_argument("event_file")

    subparsers.add_parser("status")

    flush_parser = subparsers.add_parser("flush")
    flush_parser.add_argument("--base-url", default=os.environ.get("CHRONIK_URL", "http://localhost:8788"))
    flush_parser.add_argument("--timeout", type=float, default=5.0)

    subparsers.add_parser("compact")

    args = parser.parse_args(argv)
    state_root = Path(args.state_root)

    try:
        if args.command == "append":
            path = append_event(load_json(Path(args.event_file)), state_root)
            print_json({"appended": str(path)})
        elif args.command == "status":
            print_json({"files": [entry.__dict__ for entry in status(state_root)]})
        elif args.command == "flush":
            receipts = flush_all(state_root=state_root, base_url=args.base_url, timeout=args.timeout)
            print_json({"receipts": [str(receipt) for receipt in receipts]})
        elif args.command == "compact":
            removed = compact(state_root)
            print_json({"removed": [str(path) for path in removed]})
    except (OutboxError, jsonschema.exceptions.ValidationError) as exc:
        print(f"chronik-outbox: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
