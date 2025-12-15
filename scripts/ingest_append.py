#!/usr/bin/env python3
"""CLI helper to append JSON payloads in the same format as the API."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure root directory is in sys.path so we can import storage
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from storage import (
    DATA_DIR,
    DomainError,
    StorageError,
    safe_target_path,
    sanitize_domain,
    write_payload,
)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: ingest_append.py <domain> <json-payload>", file=sys.stderr)
        return 2

    _, domain, raw_payload = argv

    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError as exc:
        print(f"invalid json payload: {exc}", file=sys.stderr)
        return 1

    try:
        dom = sanitize_domain(domain)
        # Check target path availability/validity before we proceed,
        # also needed for printing the path at the end.
        target_path = safe_target_path(dom, data_dir=DATA_DIR)
    except DomainError:
        print("invalid domain", file=sys.stderr)
        return 1

    lines = []
    if isinstance(payload, dict):
        # Single object
        item = dict(payload)
        item["domain"] = dom
        lines.append(json.dumps(item, ensure_ascii=False))
    elif isinstance(payload, list):
        # Batch of objects
        for item in payload:
            if not isinstance(item, dict):
                print("payload list must contain only JSON objects", file=sys.stderr)
                return 1
            item = dict(item)
            item["domain"] = dom
            lines.append(json.dumps(item, ensure_ascii=False))
    else:
        print("payload must be a JSON object or array of objects", file=sys.stderr)
        return 1

    try:
        # Use write_payload to handle file locking and safe writing
        write_payload(dom, lines)
    except StorageError as exc:
        print(f"storage error: {exc}", file=sys.stderr)
        return 1

    print(str(target_path))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv))
