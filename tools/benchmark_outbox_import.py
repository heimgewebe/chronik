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
        worst_seconds = max(first["elapsed_seconds"], repeat["elapsed_seconds"])
        passed = (
            not first["errors"]
            and not repeat["errors"]
            and first["target_scans"] <= MAX_TARGET_SCANS
            and repeat["target_scans"] <= MAX_TARGET_SCANS
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
            "worst_seconds": worst_seconds,
            "passed": passed,
        }


def run_benchmark(tiers: tuple[dict, ...] = DEFAULT_TIERS) -> dict:
    results = [benchmark_tier(**tier) for tier in tiers]
    return {
        "schema_version": "chronik-outbox-import-benchmark.v1",
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
