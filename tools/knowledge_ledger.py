#!/usr/bin/env python3
"""Authenticated local operator entry for bounded Chronik knowledge records.

This CLI deliberately does not collect chats, prompts, logs or process output.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import knowledge_ledger as knowledge  # noqa: E402
import storage  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir", type=Path,
        default=Path.home() / ".local/state/chronik/data")
    parser.add_argument(
        "--outbox-root", type=Path,
        default=Path.home() / ".local/state/grabowski/chronik-outbox")
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    capture.add_argument("--record", type=Path, required=True,
                         help="Path to one explicitly minimized JSON record")
    importer = commands.add_parser("import-pending")
    importer.add_argument("--limit", type=int, default=200)
    search = commands.add_parser("search")
    search.add_argument("--repo")
    search.add_argument("--host")
    search.add_argument("--knowledge-type")
    search.add_argument("--epistemic-status")
    search.add_argument("--keyword")
    search.add_argument("--limit", type=int, default=20)
    lookup = commands.add_parser("get")
    lookup.add_argument("--event-id", required=True)
    commands.add_parser("coverage")
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            if args.record.stat().st_size > knowledge.MAX_ENTRY_BYTES:
                raise ValueError("source record is larger than knowledge budget")
            obj = json.loads(args.record.read_text(encoding="utf-8"))
            if not isinstance(obj, dict):
                raise ValueError("record must be a JSON object")
            if "event_id" not in obj:
                event = knowledge.build(**obj)
            else:
                event = knowledge.validate(obj)
            result = knowledge.capture(event, args.outbox_root)
        elif args.command == "import-pending":
            result = knowledge.import_pending(
                args.outbox_root, args.data_dir, max_events=args.limit)
        elif args.command in {"get", "search"}:
            if not args.data_dir.is_dir():
                raise ValueError("Chronik data directory unavailable")
            storage.DATA_DIR = args.data_dir.resolve(strict=True)
            if args.command == "get":
                result = knowledge.get(args.event_id)
            else:
                result = knowledge.search(
                    repo=args.repo, host=args.host,
                    knowledge_type=args.knowledge_type,
                    epistemic_status=args.epistemic_status,
                    keyword=args.keyword, limit=args.limit)
        else:
            result = knowledge.coverage(args.outbox_root, args.data_dir)
    except (OSError, ValueError, TypeError, KeyError, storage.StorageError) as exc:
        print("chronik-knowledge: " + type(exc).__name__ + ": " + str(exc),
              file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if not result.get("errors") and not result.get("invalid") else 1


if __name__ == "__main__":
    raise SystemExit(main())