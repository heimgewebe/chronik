#!/usr/bin/env python3
"""Validate one Chronik operator outcome export without mutating runtime state."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from jsonschema.exceptions import SchemaError, ValidationError  # noqa: E402
from operator_outcome_export import validate_operator_outcome_export  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        value = json.loads(args.path.read_text(encoding="utf-8"))
        receipt = validate_operator_outcome_export(value)
    except (OSError, ValueError, json.JSONDecodeError, ValidationError, SchemaError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
