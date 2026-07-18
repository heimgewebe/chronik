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
    receipt_path = next(receipts.glob("*.receipt.json"))
    first_receipt = receipt_path.read_bytes()
    first_stat = receipt_path.stat()
    second = coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)

    assert first["events_imported"] == 2
    assert first["errors"] == []
    assert first["receipts_written"] == 1
    assert first["receipts_reused"] == 0
    assert second["events_imported"] == 0
    assert second["files_unchanged"] == 1
    assert second["receipts_written"] == 0
    assert second["receipts_reused"] == 1
    assert receipt_path.read_bytes() == first_receipt
    assert receipt_path.stat().st_ino == first_stat.st_ino
    assert receipt_path.stat().st_mtime_ns == first_stat.st_mtime_ns
    assert len(list(receipts.glob("*.receipt.json"))) == 1
    rows = (data / "agent.ledger.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(rows) == 2
    receipt = json.loads(next(receipts.glob("*.receipt.json")).read_text(encoding="utf-8"))
    assert receipt["source_path"] == str(source.resolve())
    assert receipt["source_sha256"]
    assert receipt["receipt_sha256"]


def test_reused_single_file_result_keeps_persisted_digest_separate_from_run_stats(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    source = write_outbox(
        outbox,
        [event("agent.run.started", "a"), event("agent.run.completed", "b")],
    )
    first = coding_memory.import_grabowski_outbox_file(
        source, receipt_dir=receipts
    )
    second = coding_memory.import_grabowski_outbox_file(
        source, receipt_dir=receipts
    )
    persisted = json.loads(Path(second["receipt_path"]).read_text(encoding="utf-8"))
    unsigned = dict(persisted)
    claimed = unsigned.pop("receipt_sha256")

    assert first["receipt_written"] is True
    assert first["receipt_reused"] is False
    assert second["imported"] == 0
    assert second["skipped_existing"] == 2
    assert second["receipt_written"] is False
    assert second["receipt_reused"] is True
    assert second["receipt_digest_scope"] == "persisted_receipt"
    assert second["receipt_sha256"] == claimed
    assert claimed == coding_memory.sha256_bytes(
        coding_memory.canonical_bytes(unsigned)
    )
    assert persisted["imported"] == 2
    assert persisted["skipped_existing"] == 0


def test_receipt_never_replaces_target_store_verification(tmp_path, monkeypatch):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.started", "a"), event("agent.run.completed", "b")])
    coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)
    (data / "agent.ledger.jsonl").unlink()

    recovered = coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)

    assert recovered["files_unchanged"] == 1
    assert recovered["events_imported"] == 2
    assert recovered["receipts_written"] == 1
    assert recovered["receipts_reused"] == 0
    assert (
        len((data / "agent.ledger.jsonl").read_text(encoding="utf-8").splitlines()) == 2
    )


def test_missing_receipt_is_rebuilt_after_store_verification(tmp_path, monkeypatch):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)
    receipt_path = next(receipts.glob("*.receipt.json"))
    receipt_path.unlink()

    recovered = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert recovered["events_imported"] == 0
    assert recovered["events_skipped_existing"] == 1
    assert recovered["files_unchanged"] == 0
    assert recovered["target_scans"] == 1
    assert recovered["receipts_written"] == 1
    assert recovered["receipts_reused"] == 0
    assert receipt_path.exists()
    assert len((data / "agent.ledger.jsonl").read_text().splitlines()) == 1


def test_stale_receipt_cannot_override_store_verification(tmp_path, monkeypatch):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)
    receipt_path = next(receipts.glob("*.receipt.json"))
    stale = json.loads(receipt_path.read_text())
    stale["source_sha256"] = "0" * 64
    receipt_path.write_text(json.dumps(stale), encoding="utf-8")

    recovered = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert recovered["events_imported"] == 0
    assert recovered["events_skipped_existing"] == 1
    assert recovered["files_unchanged"] == 0
    assert recovered["target_records_scanned"] == 1
    assert recovered["receipts_written"] == 1
    assert recovered["receipts_reused"] == 0
    refreshed = json.loads(receipt_path.read_text())
    assert refreshed["source_sha256"] != "0" * 64
    assert len((data / "agent.ledger.jsonl").read_text().splitlines()) == 1


def test_matching_receipt_with_invalid_timestamp_is_repaired(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)
    receipt_path = next(receipts.glob("*.receipt.json"))
    corrupt = json.loads(receipt_path.read_text())
    corrupt["recorded_at"] = "not-a-timestamp"
    unsigned = dict(corrupt)
    unsigned.pop("receipt_sha256")
    corrupt["receipt_sha256"] = coding_memory.sha256_bytes(
        coding_memory.canonical_bytes(unsigned)
    )
    receipt_path.write_text(json.dumps(corrupt), encoding="utf-8")

    recovered = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert recovered["events_imported"] == 0
    assert recovered["events_skipped_existing"] == 1
    assert recovered["receipts_written"] == 1
    assert recovered["receipts_reused"] == 0
    repaired = json.loads(receipt_path.read_text())
    assert repaired["recorded_at"] != "not-a-timestamp"


def test_matching_but_corrupt_receipt_is_repaired_after_store_verification(
    tmp_path, monkeypatch
):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    source = write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)
    receipt_path = next(receipts.glob("*.receipt.json"))
    corrupt = json.loads(receipt_path.read_text())
    corrupt["event_ids"] = ["sha256:" + "f" * 64]
    unsigned = dict(corrupt)
    unsigned.pop("receipt_sha256")
    corrupt["receipt_sha256"] = coding_memory.sha256_bytes(
        coding_memory.canonical_bytes(unsigned)
    )
    receipt_path.write_text(json.dumps(corrupt), encoding="utf-8")

    recovered = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert recovered["events_imported"] == 0
    assert recovered["events_skipped_existing"] == 1
    assert recovered["files_unchanged"] == 1
    assert recovered["receipts_written"] == 1
    assert recovered["receipts_reused"] == 0
    repaired = json.loads(receipt_path.read_text())
    assert repaired["source_path"] == str(source.resolve())
    assert repaired["event_ids"] == [event("agent.run.completed", "a")["event_id"]]
    assert len((data / "agent.ledger.jsonl").read_text().splitlines()) == 1


def test_appended_source_updates_receipt_and_imports_only_new_event(
    tmp_path, monkeypatch
):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    source = write_outbox(outbox, [event("agent.run.started", "a")])
    coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)

    with source.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event("agent.run.blocked", "c"), sort_keys=True) + "\n")
    result = coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)

    assert result["events_imported"] == 1
    assert result["events_skipped_existing"] == 1
    assert result["receipts_written"] == 1
    assert result["receipts_reused"] == 0
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

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert result["errors"] == []
    row = json.loads((data / "agent.ledger.jsonl").read_text().splitlines()[0])
    assert row["payload"]["subject"] == {"scope": "host", "host": "heim-pc"}
    assert "repo" not in row["payload"]["subject"]


def write_named_outbox(root: Path, name: str, values: list[dict]) -> Path:
    path = root / "grabowski" / "chronik-outbox" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(value, sort_keys=True) + "\n" for value in values),
        encoding="utf-8",
    )
    return path


def test_multi_file_batch_scans_target_once_and_repeat_verifies_store(
    tmp_path, monkeypatch
):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    for index, suffix in enumerate(("a", "b", "c")):
        write_named_outbox(
            outbox,
            f"grabowski_task-{index}-a1.jsonl",
            [event("agent.run.completed", suffix)],
        )
    first = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )
    second = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )
    assert first["target_scans"] == 1
    assert first["target_records_scanned"] == 0
    assert first["events_imported"] == 3
    assert first["receipts_written"] == 3
    assert first["receipts_reused"] == 0
    assert second["target_scans"] == 1
    assert second["target_records_scanned"] == 3
    assert second["events_imported"] == 0
    assert second["events_skipped_existing"] == 3
    assert second["files_unchanged"] == 3
    assert second["receipts_written"] == 0
    assert second["receipts_reused"] == 3
    assert len((data / "agent.ledger.jsonl").read_text().splitlines()) == 3


def test_batch_imports_valid_sources_while_reporting_invalid_source(
    tmp_path, monkeypatch
):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    write_named_outbox(
        outbox, "grabowski_task-valid-a1.jsonl", [event("agent.run.completed", "a")]
    )
    write_named_outbox(
        outbox,
        "grabowski_task-invalid-a1.jsonl",
        [event("agent.run.completed", "b", source_repo="heimgewebe/other")],
    )
    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )
    assert result["target_scans"] == 1
    assert result["events_imported"] == 1
    assert len(result["errors"]) == 1
    assert len(list(receipts.glob("*.receipt.json"))) == 1
    assert len((data / "agent.ledger.jsonl").read_text().splitlines()) == 1


def test_cross_file_divergent_event_id_fails_before_batch_append(tmp_path, monkeypatch):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    first = event("agent.run.completed", "a")
    second = event("agent.run.completed", "a")
    second["subject"] = {"scope": "repository", "repo": "heimgewebe/other"}
    second["data"].update({"operation": "implement", "task_class": "coding"})
    write_named_outbox(outbox, "grabowski_task-first-a1.jsonl", [first])
    write_named_outbox(outbox, "grabowski_task-second-a1.jsonl", [second])
    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )
    assert result["files_imported_or_confirmed"] == 0
    assert result["events_imported"] == 0
    assert result["target_scans"] is None
    assert result["errors"][0]["source_path"] == "<batch>"
    assert "conflicting event_id" in result["errors"][0]["error"]
    target = data / "agent.ledger.jsonl"
    assert not target.exists() or target.read_text() == ""
    assert not receipts.exists()



def test_single_file_receipt_failure_preserves_original_exception(
    tmp_path, monkeypatch
):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    source = write_outbox(outbox, [event("agent.run.completed", "a")])

    def fail_receipt_write(path: Path, payload: bytes) -> None:
        raise OSError("simulated direct receipt ENOSPC")

    monkeypatch.setattr(coding_memory, "_atomic_write", fail_receipt_write)
    with pytest.raises(OSError, match="simulated direct receipt ENOSPC"):
        coding_memory.import_grabowski_outbox_file(source, receipt_dir=receipts)

    assert len((data / "agent.ledger.jsonl").read_text().splitlines()) == 1


def test_empty_batch_reports_zero_target_scans(tmp_path, monkeypatch):
    _, receipts, outbox = configure(tmp_path, monkeypatch)

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert result["files_seen"] == 0
    assert result["target_scans"] == 0
    assert result["target_records_scanned"] == 0
    assert result["errors"] == []


def test_receipt_failure_preserves_ledger_stats_and_is_recoverable(
    tmp_path, monkeypatch
):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    source = write_outbox(outbox, [event("agent.run.completed", "a")])
    atomic_write = coding_memory._atomic_write

    def fail_receipt_write(path: Path, payload: bytes) -> None:
        raise OSError("simulated receipt ENOSPC")

    monkeypatch.setattr(coding_memory, "_atomic_write", fail_receipt_write)
    failed = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert failed["files_imported_or_confirmed"] == 1
    assert failed["events_imported"] == 1
    assert failed["events_skipped_existing"] == 0
    assert failed["target_scans"] == 1
    assert failed["target_records_scanned"] == 0
    assert failed["errors"] == [
        {
            "source_path": str(source),
            "error": "receipt write failed after ledger update: simulated receipt ENOSPC",
        }
    ]
    assert len((data / "agent.ledger.jsonl").read_text().splitlines()) == 1
    assert not receipts.exists()

    monkeypatch.setattr(coding_memory, "_atomic_write", atomic_write)
    recovered = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert recovered["events_imported"] == 0
    assert recovered["events_skipped_existing"] == 1
    assert recovered["target_scans"] == 1
    assert recovered["errors"] == []
    assert len(list(receipts.glob("*.receipt.json"))) == 1


def test_legacy_path_only_receipt_is_reused_for_a_single_generation(tmp_path, monkeypatch):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    source = write_outbox(
        outbox,
        [event("agent.run.completed", "c")],
    )
    first = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )
    assert first["errors"] == []
    generation_receipt = coding_memory._receipt_path(source, receipts)
    legacy_receipt = coding_memory._legacy_receipt_path(source, receipts)
    generation_receipt.replace(legacy_receipt)

    reused = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )
    repeated = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert reused["errors"] == []
    assert reused["receipts_written"] == 0
    assert reused["receipts_reused"] == 1
    assert not generation_receipt.exists()
    assert legacy_receipt.exists()
    assert repeated["errors"] == []
    assert repeated["receipts_written"] == 0
    assert repeated["receipts_reused"] == 1
