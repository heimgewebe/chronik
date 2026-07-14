#!/usr/bin/env python3
"""Import, query, summarize and freeze Chronik coding history locally."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
root_path = str(ROOT)
if root_path in sys.path:
    sys.path.remove(root_path)
sys.path.insert(0, root_path)

import coding_memory


def load(path: Path):
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    value = json.loads(text)
    return value if isinstance(value, list) else [value]


def filters(args):
    return {
        "repo": args.repo,
        "component": args.component,
        "operation": args.operation,
        "outcome": args.outcome,
        "since": args.since,
        "limit": args.limit,
    }


def empty_query(query_filters):
    return {
        "schema_version": "chronik-coding-history.v1",
        "query": query_filters,
        "events": [],
        "event_ids": [],
        "historical_only": True,
        "does_not_establish": coding_memory.DOES_NOT_ESTABLISH,
    }


def empty_summary(since, limit):
    return {
        "schema_version": "chronik-operator-summary.v1",
        "since": since,
        "event_count": 0,
        "counts_by_kind": {},
        "counts_by_subject_repo": {},
        "blocked_by_code": {},
        "recent": [],
        "limit": limit,
        "historical_only": True,
        "does_not_establish": coding_memory.DOES_NOT_ESTABLISH,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default=str(Path.home() / ".local/state/chronik"))
    sub = parser.add_subparsers(dest="command", required=True)

    imp = sub.add_parser("import")
    imp.add_argument("input", type=Path)

    outbox = sub.add_parser("import-outbox")
    outbox.add_argument("--outbox-root", type=Path, default=Path.home() / ".local/state")
    outbox.add_argument("--receipt-dir", type=Path)

    summary = sub.add_parser("summary")
    summary.add_argument("--since")
    summary.add_argument("--limit", type=int, default=20)

    for name in ("query", "freeze"):
        command = sub.add_parser(name)
        command.add_argument("--repo", required=True)
        command.add_argument("--component")
        command.add_argument("--operation", choices=["implement", "review", "merge", "deploy", "runtime_verify", "recovery"])
        command.add_argument("--outcome", choices=["completed", "blocked", "failed", "reverted", "outcome_unknown", "started"])
        command.add_argument("--since")
        command.add_argument("--limit", type=int, default=20)
        if name == "freeze":
            command.add_argument("--output", required=True, type=Path)

    args = parser.parse_args(argv)
    try:
        data_path = Path(args.data_dir).expanduser()
        query_filters = filters(args) if args.command in {"query", "freeze"} else None
        if query_filters is not None:
            coding_memory.validate_query(**query_filters)
        if args.command == "summary" and (args.limit < 1 or args.limit > 500):
            raise ValueError("limit 1..500 is required")

        if args.command == "query" and not data_path.exists():
            result = empty_query(query_filters)
        elif args.command == "summary" and not data_path.exists():
            result = empty_summary(args.since, args.limit)
        else:
            coding_memory.configure_data_dir(
                data_path,
                create=args.command in {"import", "import-outbox", "freeze"},
            )
            if args.command == "import":
                result = coding_memory.import_events(load(args.input))
            elif args.command == "import-outbox":
                receipt_dir = args.receipt_dir or data_path / "import-receipts"
                result = coding_memory.import_grabowski_outbox(
                    outbox_root=args.outbox_root,
                    receipt_dir=receipt_dir.expanduser(),
                )
            elif args.command == "query":
                result = coding_memory.query_history(**query_filters)
            elif args.command == "summary":
                result = coding_memory.operator_summary(since=args.since, limit=args.limit)
            else:
                result = coding_memory.freeze_history(args.output, **query_filters)
    except (OSError, ValueError) as exc:
        print(f"chronik-coding-memory: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, indent=2, sort_keys=True))
    if args.command == "import-outbox" and result["errors"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
