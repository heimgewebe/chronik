#!/usr/bin/env python3
"""Import, query, summarize and freeze Chronik coding history locally."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
root_path = str(ROOT)
if root_path in sys.path:
    sys.path.remove(root_path)
sys.path.insert(0, root_path)

import coding_memory  # noqa: E402


OUTBOX_SUMMARY_KEYS = (
    "files_seen",
    "loose_files_seen",
    "bundle_manifests_seen",
    "bundles_valid",
    "bundled_sources_seen",
    "sources_seen_total",
    "sources_after_deduplication",
    "orphan_bundles",
    "files_imported_or_confirmed",
    "files_unchanged",
    "receipts_written",
    "receipts_reused",
    "loose_sources_imported_or_confirmed",
    "bundled_sources_imported_or_confirmed",
    "events_imported",
    "events_skipped_existing",
    "target_scans",
    "target_records_scanned",
    "identity_index_mode",
    "identity_index_full_rebuild",
    "identity_index_entries_after",
)
OUTBOX_SUMMARY_ERROR_LIMIT = 3
OUTBOX_SUMMARY_SOURCE_LIMIT = 160
OUTBOX_SUMMARY_ERROR_TEXT_LIMIT = 320
OUTBOX_SUMMARY_LABEL_LIMIT = 96
OUTBOX_SUMMARY_MAX_BYTES = 4096


def _encoded_length(text: str) -> int:
    """Bytes this string costs inside the emitted summary line, quotes included."""
    return len(json.dumps(text).encode("utf-8"))


def _bounded_text(value: object, limit: int) -> str:
    """Truncate so the JSON-encoded form stays within ``limit`` bytes.

    Escaping expands non-ASCII and control characters (one code point can cost
    twelve bytes as an escaped surrogate pair), so a character count is not a
    size bound for the journal line.
    """
    text = str(value)
    if _encoded_length(text) <= limit:
        return text
    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if _encoded_length(text[:middle] + "…") <= limit:
            low = middle
        else:
            high = middle - 1
    return text[:low] + "…"


def _bounded_label(value: object) -> object:
    return _bounded_text(value, OUTBOX_SUMMARY_LABEL_LIMIT) if isinstance(value, str) else value


def outbox_summary(result: dict) -> dict:
    errors = result.get("errors") if isinstance(result.get("errors"), list) else []
    summary = {
        "schema_version": "chronik-grabowski-outbox-summary.v1",
        "result_schema_version": _bounded_label(result.get("schema_version")),
        **{key: _bounded_label(result.get(key)) for key in OUTBOX_SUMMARY_KEYS},
        "error_count": len(errors),
        "error_samples": [
            {
                "source_path": _bounded_text(
                    item.get("source_path", "<unknown>"),
                    OUTBOX_SUMMARY_SOURCE_LIMIT,
                ),
                "error": _bounded_text(
                    item.get("error", "unknown error"),
                    OUTBOX_SUMMARY_ERROR_TEXT_LIMIT,
                ),
            }
            for item in errors[:OUTBOX_SUMMARY_ERROR_LIMIT]
            if isinstance(item, dict)
        ],
        "errors_truncated": len(errors) > OUTBOX_SUMMARY_ERROR_LIMIT,
        "historical_only": result.get("historical_only") is True,
    }
    return summary


def _encode_summary(summary: dict) -> str:
    return json.dumps(summary, sort_keys=True, separators=(",", ":"))


def _emitted_bytes(line: str) -> int:
    """Journal cost of the line, including the terminator ``print`` appends."""
    return len(line.encode("utf-8")) + 1


def outbox_summary_line(result: dict) -> str:
    """Render one summary line that stays below the hard journal size bound."""
    summary = outbox_summary(result)
    line = _encode_summary(summary)
    while _emitted_bytes(line) >= OUTBOX_SUMMARY_MAX_BYTES and summary["error_samples"]:
        summary["error_samples"] = summary["error_samples"][:-1]
        summary["errors_truncated"] = True
        line = _encode_summary(summary)
    if _emitted_bytes(line) >= OUTBOX_SUMMARY_MAX_BYTES:
        line = _encode_summary(
            {
                "schema_version": summary["schema_version"],
                "error_count": summary["error_count"],
                "error_samples": [],
                "errors_truncated": True,
                "historical_only": summary["historical_only"],
            }
        )
    return line


def load(path: Path):
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    value = json.loads(text)
    return value if isinstance(value, list) else [value]


def filters(args):
    query_filters = {
        "repo": args.repo,
        "host": args.host,
        "component": args.component,
        "operation": args.operation,
        "task_class": args.task_class,
        "outcome": args.outcome,
        "since": args.since,
        "limit": args.limit,
    }
    if args.subject_component is not None:
        query_filters["subject_component"] = args.subject_component
    return query_filters


def empty_snapshot():
    return {
        "domain": coding_memory.DOMAIN,
        "sha256": hashlib.sha256(b"").hexdigest(),
        "complete_bytes": 0,
        "total_record_count": 0,
        "valid_record_count": 0,
        "invalid_record_count": 0,
        "integrity_valid": True,
        "diagnostics": [],
        "diagnostics_truncated": False,
    }


def empty_query(query_filters):
    target = (
        {"scope": "repository", "repo": query_filters["repo"]}
        if query_filters["repo"] is not None
        else {"scope": "host", "host": query_filters["host"]}
    )
    return {
        "schema_version": "chronik-coding-history.v1",
        "query": query_filters,
        "target": target,
        "events": [],
        "event_ids": [],
        "ledger_snapshot": empty_snapshot(),
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
        "counts_by_subject_host": {},
        "counts_by_target": {},
        "counts_by_operation": {},
        "counts_by_task_class": {},
        "blocked_by_code": {},
        "recent": [],
        "limit": limit,
        "ledger_snapshot": empty_snapshot(),
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
    outbox.add_argument(
        "--output-mode",
        choices=("full", "summary"),
        default="full",
        help="Emit the full result or one bounded single-line summary.",
    )

    compact = sub.add_parser("compact-outbox")
    compact.add_argument("--outbox-root", type=Path, default=Path.home() / ".local/state")
    compact.add_argument("--receipt-dir", type=Path)
    compact.add_argument("--grace-seconds", type=int, default=86400)
    compact.add_argument("--apply", action="store_true")

    summary = sub.add_parser("summary")
    summary.add_argument("--since")
    summary.add_argument("--limit", type=int, default=20)

    for name in ("query", "freeze"):
        command = sub.add_parser(name)
        target = command.add_mutually_exclusive_group(required=True)
        target.add_argument("--repo")
        target.add_argument("--host")
        command.add_argument("--component", help="Filter canonical producer source.component")
        command.add_argument("--subject-component", help="Filter task-context subject.component")
        command.add_argument("--operation", choices=sorted(coding_memory.OPERATIONS))
        command.add_argument("--task-class", choices=sorted(coding_memory.TASK_CLASSES))
        command.add_argument("--outcome", choices=sorted(coding_memory.OUTCOMES))
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
            elif args.command == "compact-outbox":
                receipt_dir = args.receipt_dir or data_path / "import-receipts"
                result = coding_memory.compact_grabowski_outbox(
                    outbox_root=args.outbox_root,
                    receipt_dir=receipt_dir.expanduser(),
                    grace_seconds=args.grace_seconds,
                    apply=args.apply,
                )
            elif args.command == "query":
                result = coding_memory.query_history(**query_filters)
            elif args.command == "summary":
                result = coding_memory.operator_summary(since=args.since, limit=args.limit)
            else:
                result = coding_memory.freeze_history(args.output, **query_filters)
    except (OSError, ValueError, coding_memory.storage.StorageError) as exc:
        print(f"chronik-coding-memory: {exc}", file=sys.stderr)
        return 2

    if args.command == "import-outbox" and args.output_mode == "summary":
        print(outbox_summary_line(result))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    if args.command in {"import-outbox", "compact-outbox"} and result["errors"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
