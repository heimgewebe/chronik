#!/usr/bin/env python3
"""Deterministic scaling benchmark for the direct Grabowski outbox importer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import coding_memory  # noqa: E402
import storage  # noqa: E402

DEFAULT_TIERS = (
    {
        "name": "representative",
        "source_files": 200,
        "preexisting_events": 500,
        "max_seconds": 5.0,
    },
    {
        "name": "projected",
        "source_files": 1000,
        "preexisting_events": 5000,
        "max_seconds": 30.0,
    },
)
TIMER_BUDGET_SECONDS = 60.0
MAX_TARGET_SCANS = 1


def synthetic_event(label: str, kind: str = "agent.run.completed") -> dict:
    event_id = "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()
    result = {
        "agent.run.started": "started",
        "agent.run.completed": "completed",
        "agent.run.blocked": "blocked",
    }[kind]
    data = {"result": result, "operation": "implement", "task_class": "coding"}
    if kind == "agent.run.blocked":
        data["blocker_code"] = "benchmark"
    return {
        "schema_version": "agent-run-event.v0",
        "event_id": event_id,
        "kind": kind,
        "ts": "2026-07-15T00:00:00Z",
        "source": {
            "repo": "heimgewebe/grabowski",
            "component": "grabowski",
            "run_id": label,
        },
        "subject": {"scope": "repository", "repo": "heimgewebe/chronik"},
        "trust_tier": "declared" if kind == "agent.run.started" else "observed",
        "status": "active",
        "caused_by": [],
        "evidence_refs": ["benchmark:" + label],
        "data": data,
    }


def _measure(outbox_root: Path, receipt_dir: Path) -> dict:
    tracemalloc.start()
    started = time.perf_counter()
    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox_root,
        receipt_dir=receipt_dir,
    )
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "elapsed_seconds": round(elapsed, 6),
        "peak_memory_bytes": peak,
        "target_scans": result["target_scans"],
        "target_records_scanned": result["target_records_scanned"],
        "events_imported": result["events_imported"],
        "events_skipped_existing": result["events_skipped_existing"],
        "errors": result["errors"],
    }


def _measure_compaction(outbox_root: Path, receipt_dir: Path) -> dict:
    started = time.perf_counter()
    result = coding_memory.compact_grabowski_outbox(
        outbox_root=outbox_root,
        receipt_dir=receipt_dir,
        grace_seconds=0,
        apply=True,
    )
    elapsed = time.perf_counter() - started
    return {
        "elapsed_seconds": round(elapsed, 6),
        "eligible_sources": result["eligible_sources"],
        "eligible_events": result["eligible_events"],
        "sources_removed": result["sources_removed"],
        "loose_sources_remaining": result["loose_sources_remaining"],
        "bundle_bytes": result["bundle_bytes"],
        "bundle_sha256": result["bundle_sha256"],
        "archive_index_bytes": (
            Path(result["archive_index_path"]).stat().st_size
            if result["archive_index_sha256"] is not None
            else 0
        ),
        "archive_index_sha256": result["archive_index_sha256"],
        "archive_manifests_indexed": result["archive_manifests_indexed"],
        "archived_sources_indexed": result["archived_sources_indexed"],
        "ledger_records_scanned": result["ledger_records_scanned"],
        "errors": result["errors"],
    }


def benchmark_tier(
    *,
    name: str,
    source_files: int,
    preexisting_events: int,
    max_seconds: float,
) -> dict:
    with tempfile.TemporaryDirectory(prefix="chronik-outbox-benchmark-") as temp:
        temp_root = Path(temp)
        data_dir = temp_root / "data"
        data_dir.mkdir()
        storage.DATA_DIR = data_dir
        if preexisting_events:
            coding_memory.import_events(
                synthetic_event(f"existing-{index}")
                for index in range(preexisting_events)
            )
        outbox_root = temp_root / "state"
        source_dir = outbox_root / "grabowski" / "chronik-outbox"
        source_dir.mkdir(parents=True)
        for index in range(source_files):
            values = (
                synthetic_event(f"{name}-{index}-started", "agent.run.started"),
                synthetic_event(f"{name}-{index}-completed"),
            )
            (source_dir / f"grabowski_task-{index:06d}-a1.jsonl").write_text(
                "".join(json.dumps(value, sort_keys=True) + "\n" for value in values),
                encoding="utf-8",
            )
        receipt_dir = temp_root / "receipts"
        first = _measure(outbox_root, receipt_dir)
        repeat = _measure(outbox_root, receipt_dir)
        loose_files_before = len(list(source_dir.glob("*.jsonl")))
        compaction = _measure_compaction(outbox_root, receipt_dir)
        loose_files_after = len(list(source_dir.glob("*.jsonl")))
        bundled_repeat = _measure(outbox_root, receipt_dir)
        worst_seconds = max(
            first["elapsed_seconds"],
            repeat["elapsed_seconds"],
            bundled_repeat["elapsed_seconds"],
        )
        loose_seconds = repeat["elapsed_seconds"]
        bundled_seconds = bundled_repeat["elapsed_seconds"]
        speedup_ratio = (
            round(loose_seconds / bundled_seconds, 3)
            if bundled_seconds > 0
            else None
        )
        passed = (
            not first["errors"]
            and not repeat["errors"]
            and not compaction["errors"]
            and not bundled_repeat["errors"]
            and first["target_scans"] <= MAX_TARGET_SCANS
            and repeat["target_scans"] <= MAX_TARGET_SCANS
            and bundled_repeat["target_scans"] <= MAX_TARGET_SCANS
            and compaction["sources_removed"] == source_files
            and compaction["archive_index_sha256"] is not None
            and compaction["archive_manifests_indexed"] == 1
            and compaction["archived_sources_indexed"] == source_files
            and loose_files_before == source_files
            and loose_files_after == 0
            and worst_seconds <= max_seconds
            and worst_seconds <= TIMER_BUDGET_SECONDS
        )
        return {
            "name": name,
            "source_files": source_files,
            "source_events": source_files * 2,
            "preexisting_events": preexisting_events,
            "max_seconds": max_seconds,
            "timer_budget_seconds": TIMER_BUDGET_SECONDS,
            "max_target_scans": MAX_TARGET_SCANS,
            "first": first,
            "repeat": repeat,
            "compaction": compaction,
            "bundled_repeat": bundled_repeat,
            "loose_files_before": loose_files_before,
            "loose_files_after": loose_files_after,
            "loose_repeat_seconds": loose_seconds,
            "bundled_repeat_seconds": bundled_seconds,
            "loose_to_bundled_speedup_ratio": speedup_ratio,
            "worst_seconds": worst_seconds,
            "passed": passed,
        }


def run_benchmark(tiers: tuple[dict, ...] = DEFAULT_TIERS) -> dict:
    results = [benchmark_tier(**tier) for tier in tiers]
    return {
        "schema_version": "chronik-outbox-import-benchmark.v2",
        "machine": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
        "thresholds": {
            "max_target_scans": MAX_TARGET_SCANS,
            "timer_budget_seconds": TIMER_BUDGET_SECONDS,
        },
        "tiers": results,
        "passed": all(result["passed"] for result in results),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name")
    parser.add_argument("--source-files", type=int)
    parser.add_argument("--preexisting-events", type=int)
    parser.add_argument("--max-seconds", type=float)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    values = (args.name, args.source_files, args.preexisting_events, args.max_seconds)
    if any(value is not None for value in values):
        if any(value is None for value in values):
            parser.error(
                "custom tier requires --name, --source-files, "
                "--preexisting-events and --max-seconds"
            )
        if (
            args.source_files < 1
            or args.preexisting_events < 0
            or args.max_seconds <= 0
        ):
            parser.error(
                "tier sizes and threshold must be positive, "
                "except preexisting events may be zero"
            )
        tiers = (
            {
                "name": args.name,
                "source_files": args.source_files,
                "preexisting_events": args.preexisting_events,
                "max_seconds": args.max_seconds,
            },
        )
    else:
        tiers = DEFAULT_TIERS
    report = run_benchmark(tiers)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
