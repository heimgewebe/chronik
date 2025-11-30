#!/usr/bin/env python3
"""CLI helper to append JSON payloads in the same format as the API."""

from __future__ import annotations

import json
import sys

from storage import DATA_DIR, DomainError, safe_target_path, sanitize_domain


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
        target_path = safe_target_path(dom, data_dir=DATA_DIR)
    except DomainError:
        print("invalid domain", file=sys.stderr)
        return 1

    if not isinstance(payload, dict):
        print("payload must be a JSON object", file=sys.stderr)
        return 1

    payload = dict(payload)
    payload["domain"] = dom

    target_path.parent.mkdir(parents=True, exist_ok=True)

    with target_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")

    print(str(target_path))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv))
