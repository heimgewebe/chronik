"""Read-only local summary for Agent Ledger roots."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tools import chronik_outbox


def discover(base: Path) -> list[Path]:
    return sorted(path for path in base.glob("agent-run-ledger-*") if path.is_dir())


def summarize(root: Path) -> dict[str, Any]:
    preview = chronik_outbox.preview(root)
    results: dict[str, int] = {}
    for row in preview["run_view"]:
        result = str(row.get("result", ""))
        results[result] = results.get(result, 0) + 1
    return {
        "root": str(root),
        "event_count": preview["event_count"],
        "file_count": len(preview["files"]),
        "repo_rows": len(preview["repo_view"]),
        "run_rows": len(preview["run_view"]),
        "results": results,
        "receipt_count": sum(1 for _ in root.rglob("*.receipt.json")),
        "read_only": preview["mutates_remote"] is False,
    }


def markdown(items: list[dict[str, Any]]) -> str:
    lines = ["# Agent Ledger Local Summary", ""]
    lines.append("| root | events | files | repo rows | run rows | results | receipts | read only |")
    lines.append("| --- | ---: | ---: | ---: | ---: | --- | ---: | --- |")
    for item in items:
        results = ", ".join(f"{key}:{value}" for key, value in sorted(item["results"].items())) or "-"
        lines.append(
            "| "
            + " | ".join(
                [
                    Path(str(item["root"])).name,
                    str(item["event_count"]),
                    str(item["file_count"]),
                    str(item["repo_rows"]),
                    str(item["run_rows"]),
                    results,
                    str(item["receipt_count"]),
                    str(item["read_only"]).lower(),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render a read-only Agent Ledger local summary")
    parser.add_argument("roots", nargs="*")
    parser.add_argument("--base", default=str(Path.home() / ".local/state/grabowski"))
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    args = parser.parse_args(argv)

    roots = [Path(root) for root in args.roots] if args.roots else discover(Path(args.base))
    items = [summarize(root) for root in roots]
    if args.format == "json":
        print(json.dumps(items, indent=2, sort_keys=True))
    else:
        print(markdown(items), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
