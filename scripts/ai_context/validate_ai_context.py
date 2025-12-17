#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import yaml
except Exception as e:
    print("ERROR: PyYAML missing. Install with: pip install pyyaml", file=sys.stderr)
    raise


PLACEHOLDER_RE = re.compile(r"\b(TODO|TBD|FIXME|lorem|ipsum)\b", re.IGNORECASE)


def err(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)


def die(msg: str) -> None:
    err(msg)
    raise SystemExit(2)


def load_yaml(p: Path) -> Dict[str, Any]:
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except Exception as e:
        die(f"{p}: YAML parse failed: {e}")
    if not isinstance(data, dict):
        die(f"{p}: top-level must be a mapping/object")
    return data


def get_str(d: Dict[str, Any], path: str) -> str:
    cur: Any = d
    for k in path.split("."):
        if not isinstance(cur, dict) or k not in cur:
            return ""
        cur = cur[k]
    return cur if isinstance(cur, str) else ""


def get_list(d: Dict[str, Any], path: str) -> List[Any]:
    cur: Any = d
    for k in path.split("."):
        if not isinstance(cur, dict) or k not in cur:
            return []
        cur = cur[k]
    return cur if isinstance(cur, list) else []


def has_placeholders(obj: Any) -> bool:
    if isinstance(obj, str):
        return bool(PLACEHOLDER_RE.search(obj))
    if isinstance(obj, list):
        return any(has_placeholders(x) for x in obj)
    if isinstance(obj, dict):
        return any(has_placeholders(v) for v in obj.values())
    return False


def validate_one(p: Path) -> List[str]:
    d = load_yaml(p)
    errs: List[str] = []

    # Backwards-compatible: v1.0 has these keys; v1.1 adds more, but we keep required minimal.
    name = get_str(d, "project.name")
    summary = get_str(d, "project.summary")
    role = get_str(d, "project.role")

    if not name.strip():
        errs.append("missing project.name")
    if not summary.strip():
        errs.append("missing project.summary")
    if not role.strip():
        errs.append("missing project.role")

    do = get_list(d, "ai_guidance.do")
    dont = get_list(d, "ai_guidance.dont")
    if len(do) == 0:
        errs.append("ai_guidance.do must not be empty")
    if len(dont) == 0:
        errs.append("ai_guidance.dont must not be empty")

    if has_placeholders(d):
        errs.append("contains placeholders (TODO/TBD/FIXME/lorem/ipsum)")

    return errs


def validate_templates(dir_path: Path) -> int:
    if not dir_path.exists() or not dir_path.is_dir():
        die(f"templates dir missing: {dir_path}")
    problems: List[Tuple[Path, List[str]]] = []
    files = sorted(dir_path.glob("*.ai-context.yml"))
    if not files:
        die(f"no template files found in {dir_path}")
    for p in files:
        errs = validate_one(p)
        if errs:
            problems.append((p, errs))
    if problems:
        for p, errs in problems:
            for e in errs:
                err(f"{p}: {e}")
        return 2
    print("ai-context template validation OK")
    return 0


def validate_file(file_path: Path) -> int:
    if not file_path.exists():
        die(f"file missing: {file_path}")
    errs = validate_one(file_path)
    if errs:
        for e in errs:
            err(f"{file_path}: {e}")
        return 2
    print("ai-context file validation OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", help="Validate a single .ai-context.yml file")
    ap.add_argument("--templates-dir", help="Validate templates directory (metarepo)")
    args = ap.parse_args()

    if not args.file and not args.templates_dir:
        die("provide --file and/or --templates-dir")

    rc = 0
    if args.file:
        rc = max(rc, validate_file(Path(args.file)))
    if args.templates_dir:
        rc = max(rc, validate_templates(Path(args.templates_dir)))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
