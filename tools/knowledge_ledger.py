#!/usr/bin/env python3
"""Authenticated local operator entry for bounded Chronik knowledge records.

This CLI deliberately does not collect chats, prompts, logs or process output.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _use_installed_runtime() -> None:
    """Use the same managed Python as Chronik's import service, only for installed releases."""
    source = Path(__file__).resolve()
    if source.parent.name != "tools" or source.parents[2].name != "releases":
        return
    python = source.parents[3] / "runtime-python" / "bin" / "python3"
    if not python.is_file():
        raise SystemExit(f"chronik-knowledge: installed runtime unavailable: {python}")
    if (Path(sys.executable).resolve() != python.resolve()
            or Path(sys.prefix).resolve() != python.parent.parent.resolve()):
        os.execv(str(python), [str(python), str(source), *sys.argv[1:]])


if __name__ == "__main__":
    _use_installed_runtime()


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
    search.add_argument("--component", help="exact subject.component")
    search.add_argument("--since", help="ISO-8601 lower bound for ts (inclusive)")
    search.add_argument("--until", help="ISO-8601 upper bound for ts (inclusive)")
    search.add_argument("--current-only", action="store_true",
                        help="hide events superseded by a newer event")
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
                    keyword=args.keyword, component=args.component,
                    since=args.since, until=args.until,
                    current_only=args.current_only, limit=args.limit)
        else:
            result = knowledge.coverage(args.outbox_root, args.data_dir)
    except (OSError, ValueError, TypeError, KeyError, storage.StorageError) as exc:
        print("chronik-knowledge: " + type(exc).__name__ + ": " + str(exc),
              file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    if args.command == "get" and not result["found"]:
        return 3  # distinguishable from success: absent is not verified
    return 0 if not result.get("errors") and not result.get("invalid") else 1


if __name__ == "__main__":
    raise SystemExit(main())