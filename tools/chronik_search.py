#!/usr/bin/env python3
"""Read-only CLI for exact Chronik event recall and paginated searches."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import coding_memory  # noqa: E402
import chronik_search  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path.home() / ".local/state/chronik/data")
    sub = parser.add_subparsers(dest="command", required=True)
    get = sub.add_parser("get")
    get.add_argument("--event-id", required=True)
    search = sub.add_parser("search")
    for name in chronik_search.FILTER_NAMES:
        search.add_argument("--" + name.replace("_", "-"), type=int if name == "pr_number" else str)
    search.add_argument("--limit", type=int, default=20)
    search.add_argument("--cursor")
    args = parser.parse_args(argv)
    try:
        if not args.data_dir.is_dir():
            raise ValueError("Chronik data directory not available (no directory created)")
        coding_memory.configure_data_dir(args.data_dir, create=False)
        if args.command == "get":
            result = chronik_search.get_event(args.event_id)
        else:
            result = chronik_search.search_events(
                **{name: getattr(args, name) for name in chronik_search.FILTER_NAMES},
                limit=args.limit, cursor=args.cursor,
            )
    except (OSError, ValueError, coding_memory.storage.StorageError) as exc:
        print("chronik-search: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())