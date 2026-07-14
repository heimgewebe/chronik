import json
from pathlib import Path

import pytest

import coding_memory
import storage


def event(kind: str, suffix: str, *, source_repo: str = "heimgewebe/grabowski") -> dict:
    outcome = {
        "agent.run.started": {"result": "started"},
        "agent.run.completed": {"result": "completed"},
        "agent.run.blocked": {"result": "blocked", "blocker_code": "task-failed"},
    }[kind]
    return {
        "schema_version": "agent-run-event.v0",
        "event_id": "sha256:" + suffix * 64,
        "kind": kind,
        "ts": f"2026-07-14T10:00:0{len(suffix)}Z",
        "source": {
            "repo": source_repo,
            "component": "grabowski",
            "run_id": f"task-{suffix}-a1",
        },
        "subject": {"repo": "heimgewebe/grabowski"},
        "trust_tier": "observed" if kind != "agent.run.started" else "declared",
        "status": "active",
        "caused_by": [],
        "evidence_refs": [f"grabowski-task:{suffix}"],
        "data": outcome,
    }


def write_outbox(root: Path, values: list[dict], *, trailing_newline: bool = True) -> Path:
    path = root / "grabowski" / "chronik-outbox" / "grabowski_task-test-a1.jsonl"
    path.parent.mkdir(parents=True)
    body = "\n".join(json.dumps(value, sort_keys=True) for value in values)
    if trailing_newline:
        body += "\n"
    path.write_text(body, encoding="utf-8")
    return path


def configure(tmp_path: Path, monkeypatch) -> tuple[Path, Path, Path]:
    data = tmp_path / "chronik-data"
    receipts = tmp_path / "receipts"
    outbox = tmp_path / "state"
    data.mkdir()
    monkeypatch.setattr(storage, "DATA_DIR", data)
    return data, receipts, outbox


def test_batch_import_is_idempotent_and_receipt_bound(tmp_path, monkeypatch):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    source = write_outbox(outbox, [event("agent.run.started", "a"), event("agent.run.completed", "b")])

    first = coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)
    second = coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)

    assert first["events_imported"] == 2
    assert first["errors"] == []
    assert second["events_imported"] == 0
    assert second["files_unchanged"] == 1
    assert len(list(receipts.glob("*.receipt.json"))) == 1
    rows = (data / "agent.ledger.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(rows) == 2
    receipt = json.loads(next(receipts.glob("*.receipt.json")).read_text(encoding="utf-8"))
    assert receipt["source_path"] == str(source.resolve())
    assert receipt["source_sha256"]
    assert receipt["receipt_sha256"]


def test_receipt_never_replaces_target_store_verification(tmp_path, monkeypatch):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.started", "a"), event("agent.run.completed", "b")])
    coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)
    (data / "agent.ledger.jsonl").unlink()

    recovered = coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)

    assert recovered["files_unchanged"] == 1
    assert recovered["events_imported"] == 2
    assert len((data / "agent.ledger.jsonl").read_text(encoding="utf-8").splitlines()) == 2


def test_appended_source_updates_receipt_and_imports_only_new_event(tmp_path, monkeypatch):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    source = write_outbox(outbox, [event("agent.run.started", "a")])
    coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)

    with source.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event("agent.run.blocked", "c"), sort_keys=True) + "\n")
    result = coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)

    assert result["events_imported"] == 1
    assert result["events_skipped_existing"] == 1
    assert len((data / "agent.ledger.jsonl").read_text(encoding="utf-8").splitlines()) == 2


def test_import_rejects_noncanonical_producer_without_writes(tmp_path, monkeypatch):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a", source_repo="heimgewebe/other")])

    result = coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)

    assert result["files_imported_or_confirmed"] == 0
    assert "not produced by canonical Grabowski" in result["errors"][0]["error"]
    assert not (data / "agent.ledger.jsonl").exists()
    assert not receipts.exists()


def test_import_rejects_partial_jsonl_tail(tmp_path, monkeypatch):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a")], trailing_newline=False)

    result = coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)

    assert result["files_imported_or_confirmed"] == 0
    assert "incomplete JSONL tail" in result["errors"][0]["error"]
    assert not (data / "agent.ledger.jsonl").exists()


def test_operator_summary_answers_blockage_and_activity_questions(tmp_path, monkeypatch):
    data, _, _ = configure(tmp_path, monkeypatch)
    coding_memory.import_events(
        [
            event("agent.run.started", "a"),
            event("agent.run.completed", "b"),
            event("agent.run.blocked", "c"),
        ]
    )

    summary = coding_memory.operator_summary(limit=2)

    assert summary["event_count"] == 3
    assert summary["counts_by_kind"]["agent.run.blocked"] == 1
    assert summary["blocked_by_code"] == {"task-failed": 1}
    assert len(summary["recent"]) == 2
    assert summary["historical_only"] is True


def test_import_outbox_cli_returns_nonzero_on_any_invalid_source(tmp_path):
    import subprocess
    import sys

    data = tmp_path / "data"
    receipts = tmp_path / "receipts"
    outbox = tmp_path / "state"
    write_outbox(outbox, [event("agent.run.completed", "a", source_repo="heimgewebe/other")])
    root = Path(__file__).parents[1]

    result = subprocess.run(
        [
            sys.executable,
            str(root / "tools" / "coding_memory.py"),
            "--data-dir",
            str(data),
            "import-outbox",
            "--outbox-root",
            str(outbox),
            "--receipt-dir",
            str(receipts),
        ],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 2
    assert json.loads(result.stdout)["errors"]


def test_import_preserves_repository_target_identity(tmp_path, monkeypatch):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    value = event("agent.run.completed", "d")
    value["subject"] = {"scope": "repository", "repo": "heimgewebe/chronik", "branch": "fix/target"}
    value["data"].update({"operation": "implement", "task_class": "coding"})
    write_outbox(outbox, [value])

    result = coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)
    history = coding_memory.query_history(repo="heimgewebe/chronik")

    assert result["errors"] == []
    assert result["events_imported"] == 1
    assert history["events"][0]["subject"] == value["subject"]
    assert history["events"][0]["data"]["operation"] == "implement"
    assert history["events"][0]["data"]["task_class"] == "coding"


def test_import_preserves_host_scope_without_fabricated_repo(tmp_path, monkeypatch):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    value = event("agent.run.blocked", "e")
    value["subject"] = {"scope": "host", "host": "heim-pc"}
    value["data"].update({"operation": "recovery", "task_class": "recovery"})
    write_outbox(outbox, [value])

    result = coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)

    assert result["errors"] == []
    row = json.loads((data / "agent.ledger.jsonl").read_text().splitlines()[0])
    assert row["payload"]["subject"] == {"scope": "host", "host": "heim-pc"}
    assert "repo" not in row["payload"]["subject"]
