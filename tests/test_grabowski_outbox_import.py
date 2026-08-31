import json
import os
from pathlib import Path

import pytest

import coding_memory
import identity_index
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


def test_directory_inventory_fingerprint_preserves_existing_digest_contract(tmp_path):
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    paths = [
        receipts / "a.receipt.json",
        receipts / 'z-ä-"\\.receipt.json',
    ]
    for index, path in enumerate(paths):
        path.write_text(json.dumps({"index": index}), encoding="utf-8")
        path.chmod(0o600)
    (receipts / "ignored.txt").write_text("ignored", encoding="utf-8")

    for path in paths:
        info = path.lstat()
        assert coding_memory._inventory_material(path, info) == coding_memory.canonical_bytes(
            {
                "path": str(path.absolute()),
                "identity": list(coding_memory._file_identity(info)),
            }
        )

    legacy = coding_memory._inventory_fingerprint(paths, private=True)
    directory = coding_memory._directory_inventory_fingerprint(
        receipts, suffix=".receipt.json", private=True
    )

    assert directory == legacy
    assert directory is not None
    assert directory["count"] == 2


def test_directory_inventory_fingerprint_preserves_dotdot_path_spelling(tmp_path):
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    alias = tmp_path / "alias"
    alias.mkdir()
    receipt = receipts / "stable.receipt.json"
    receipt.write_text("{}", encoding="utf-8")
    receipt.chmod(0o600)
    aliased_receipts = alias / ".." / "receipts"
    legacy_paths = list(aliased_receipts.glob("*.receipt.json"))

    assert ".." in str(legacy_paths[0])
    assert coding_memory._directory_inventory_fingerprint(
        aliased_receipts, suffix=".receipt.json", private=True
    ) == coding_memory._inventory_fingerprint(legacy_paths, private=True)


def test_directory_inventory_fingerprint_keeps_private_file_guard(tmp_path):
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    unsafe = receipts / "unsafe.receipt.json"
    unsafe.write_text("{}", encoding="utf-8")
    unsafe.chmod(0o644)

    assert (
        coding_memory._directory_inventory_fingerprint(
            receipts, suffix=".receipt.json", private=True
        )
        is None
    )


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


def test_no_change_import_reuses_source_index_without_source_reads(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_named_outbox(
        outbox,
        "grabowski_task-first-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    write_named_outbox(
        outbox,
        "grabowski_task-second-a1.jsonl",
        [event("agent.run.completed", "b")],
    )
    first = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )
    index_path = receipts / coding_memory.GRABOWSKI_SOURCE_INDEX_FILENAME
    original_index = index_path.read_bytes()
    original_stat = index_path.stat()

    def unexpected_read(*args, **kwargs):
        raise AssertionError("unchanged loose source was read")

    monkeypatch.setattr(
        coding_memory, "_prepare_grabowski_outbox_source", unexpected_read
    )
    second = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert first["sources_revalidated"] == 2
    assert first["source_bytes_read"] > 0
    assert second["source_index_mode"] == "steady"
    assert second["sources_reused"] == 2
    assert second["sources_revalidated"] == 0
    assert second["source_bytes_read"] == 0
    assert second["source_bytes_hashed"] == 0
    assert second["source_events_validated"] == 0
    assert second["target_scans"] == 0
    assert second["target_records_scanned"] == 0
    assert second["import_telemetry"]["phases_seconds"]["source_discovery"] >= 0
    assert index_path.read_bytes() == original_index
    assert index_path.stat().st_ino == original_stat.st_ino
    assert index_path.stat().st_mtime_ns == original_stat.st_mtime_ns


def test_summary_steady_fast_path_skips_full_source_and_ledger_reconciliation(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_named_outbox(
        outbox,
        "grabowski_task-first-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    write_named_outbox(
        outbox,
        "grabowski_task-second-a1.jsonl",
        [event("agent.run.completed", "b")],
    )
    first = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    checkpoint = receipts / coding_memory.GRABOWSKI_STEADY_CHECKPOINT_FILENAME
    assert first["steady_fast_path"] is False
    assert checkpoint.is_file()

    def unexpected_full_path(*args, **kwargs):
        raise AssertionError("steady fast path entered full reconciliation")

    monkeypatch.setattr(coding_memory, "_load_grabowski_source_index", unexpected_full_path)
    monkeypatch.setattr(coding_memory, "_import_prepared_grabowski_sources", unexpected_full_path)
    second = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert second["steady_fast_path"] is True
    assert second["events_imported"] == 0
    assert second["events_skipped_existing"] == 2
    assert second["files_unchanged"] == 2
    assert second["receipts_reused"] == 2
    assert second["source_index_mode"] == "steady"
    assert second["source_bytes_read"] == 0
    assert second["source_bytes_hashed"] == 0
    assert second["source_events_validated"] == 0
    assert second["target_scans"] == 0
    assert second["target_records_scanned"] == 0
    assert second["bundle_inventory"] == []
    assert second["bundle_inventory_omitted"] is True
    assert second["import_telemetry"]["counters"]["steady_fast_path_hits"] == 1


def test_summary_delta_fast_path_reconciles_only_added_source(tmp_path, monkeypatch):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_named_outbox(
        outbox,
        "grabowski_task-first-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    write_named_outbox(
        outbox,
        "grabowski_task-second-a1.jsonl",
        [event("agent.run.completed", "b")],
    )
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    source_index_path = receipts / coding_memory.GRABOWSKI_SOURCE_INDEX_FILENAME
    source_index_before = source_index_path.read_bytes()
    delta_index_path = receipts / coding_memory.GRABOWSKI_DELTA_INDEX_FILENAME
    delta_index_before = delta_index_path.read_bytes()
    delta_overlay_path = receipts / coding_memory.GRABOWSKI_DELTA_OVERLAY_FILENAME
    delta_overlay_before = delta_overlay_path.read_bytes()
    added = write_named_outbox(
        outbox,
        "grabowski_task-third-a1.jsonl",
        [event("agent.run.completed", "c")],
    )
    original = coding_memory._import_prepared_grabowski_sources
    observed = []

    def record_batch(prepared_sources, *args, **kwargs):
        observed.append([str(item["source"].resolve()) for item in prepared_sources])
        return original(prepared_sources, *args, **kwargs)

    monkeypatch.setattr(coding_memory, "_import_prepared_grabowski_sources", record_batch)
    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert result["errors"] == []
    assert result["steady_fast_path"] is False
    assert result["delta_fast_path"] is True
    assert result["events_imported"] == 1
    assert result["events_skipped_existing"] == 2
    assert result["sources_added"] == 1
    assert result["sources_changed"] == 0
    assert result["sources_revalidated"] == 1
    assert result["sources_reused"] == 2
    assert result["files_unchanged"] == 2
    assert result["receipts_written"] == 1
    assert result["receipts_reused"] == 2
    assert result["receipts_deferred"] == 0
    assert result["target_scans"] == 0
    assert result["source_index_mode"] == "deferred_delta"
    assert result["source_index_written"] is False
    assert source_index_path.read_bytes() == source_index_before
    assert delta_index_path.read_bytes() == delta_index_before
    assert delta_overlay_path.read_bytes() != delta_overlay_before
    assert result["bundle_inventory_omitted"] is True
    assert observed == [[str(added.resolve())]]
    assert result["import_telemetry"]["counters"]["delta_fast_path_hits"] == 1

    next_result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert next_result["steady_fast_path"] is True
    assert next_result["delta_fast_path"] is False
    assert next_result["receipts_deferred"] == 0
    assert next_result["events_skipped_existing"] == 3
    steady_result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert steady_result["steady_fast_path"] is True
    assert steady_result["events_skipped_existing"] == 3


def test_summary_delta_receipt_attestation_defers_on_unrelated_receipt_drift(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    first = write_named_outbox(
        outbox,
        "grabowski_task-first-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    first_receipt = coding_memory._receipt_path(
        first, receipts, coding_memory.sha256_bytes(first.read_bytes())
    )
    write_named_outbox(
        outbox,
        "grabowski_task-second-a1.jsonl",
        [event("agent.run.completed", "b")],
    )
    original = coding_memory._import_prepared_grabowski_sources

    def mutate_unrelated_receipt(prepared_sources, *args, **kwargs):
        result = original(prepared_sources, *args, **kwargs)
        stat_before = first_receipt.stat()
        os.utime(
            first_receipt,
            ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns + 1_000_000),
        )
        return result

    monkeypatch.setattr(
        coding_memory, "_import_prepared_grabowski_sources", mutate_unrelated_receipt
    )
    delta = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert delta["errors"] == []
    assert delta["delta_fast_path"] is True
    assert delta["events_imported"] == 1
    assert delta["receipts_deferred"] == 1
    assert delta["receipts_reused"] == 0

    monkeypatch.setattr(coding_memory, "_import_prepared_grabowski_sources", original)
    repaired = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert repaired["steady_fast_path"] is False
    assert repaired["delta_fast_path"] is False
    assert repaired["events_imported"] == 0
    assert repaired["events_skipped_existing"] == 2


def test_summary_delta_fast_path_reconciles_changed_source_generation(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    source = write_named_outbox(
        outbox,
        "grabowski_task-changing-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    source.write_text(
        "\n".join(
            json.dumps(value, sort_keys=True)
            for value in [
                event("agent.run.completed", "a"),
                event("agent.run.completed", "b"),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert result["errors"] == []
    assert result["delta_fast_path"] is True
    assert result["events_imported"] == 1
    assert result["events_skipped_existing"] == 1
    assert result["sources_added"] == 0
    assert result["sources_changed"] == 1
    assert result["sources_revalidated"] == 1
    assert result["sources_reused"] == 0
    assert result["source_events_validated"] == 2
    assert result["receipts_written"] == 1
    assert result["receipts_reused"] == 0
    assert result["receipts_deferred"] == 0
    assert result["identity_index_mode"] == "steady"

    next_result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert next_result["steady_fast_path"] is True
    assert next_result["delta_fast_path"] is False
    assert next_result["events_skipped_existing"] == 2
    steady_result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert steady_result["steady_fast_path"] is True
    assert steady_result["events_skipped_existing"] == 2


def test_summary_delta_overlay_accumulates_consecutive_source_deltas(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_named_outbox(
        outbox,
        "grabowski_task-first-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    delta_index_path = receipts / coding_memory.GRABOWSKI_DELTA_INDEX_FILENAME
    delta_index_before = delta_index_path.read_bytes()
    overlay_path = receipts / coding_memory.GRABOWSKI_DELTA_OVERLAY_FILENAME

    write_named_outbox(
        outbox,
        "grabowski_task-second-a1.jsonl",
        [event("agent.run.completed", "b")],
    )
    first_delta = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert first_delta["delta_fast_path"] is True
    assert first_delta["events_imported"] == 1
    assert first_delta["sources_revalidated"] == 1
    first_overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
    assert first_overlay["record_count"] == 1

    write_named_outbox(
        outbox,
        "grabowski_task-third-a1.jsonl",
        [event("agent.run.completed", "c")],
    )
    second_delta = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert second_delta["errors"] == []
    assert second_delta["steady_fast_path"] is False
    assert second_delta["delta_fast_path"] is True
    assert second_delta["events_imported"] == 1
    assert second_delta["events_skipped_existing"] == 2
    assert second_delta["sources_added"] == 1
    assert second_delta["sources_changed"] == 0
    assert second_delta["sources_revalidated"] == 1
    assert second_delta["sources_reused"] == 2
    assert second_delta["receipts_written"] == 1
    assert second_delta["receipts_reused"] == 2
    assert second_delta["receipts_deferred"] == 0
    assert second_delta["target_scans"] == 0
    assert second_delta["source_index_mode"] == "deferred_delta"
    assert delta_index_path.read_bytes() == delta_index_before
    second_overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
    assert second_overlay["record_count"] == 2
    assert [Path(item["source_path"]).name for item in second_overlay["records"]] == [
        "grabowski_task-second-a1.jsonl",
        "grabowski_task-third-a1.jsonl",
    ]

    repair = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert repair["steady_fast_path"] is True
    assert repair["delta_fast_path"] is False
    assert repair["receipts_deferred"] == 0
    retained_overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
    assert retained_overlay["record_count"] == 2

    steady = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert steady["steady_fast_path"] is True
    assert steady["events_skipped_existing"] == 3


def test_delta_overlay_capacity_falls_back_before_next_ledger_effect(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_named_outbox(
        outbox,
        "grabowski_task-first-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    monkeypatch.setattr(coding_memory, "GRABOWSKI_DELTA_OVERLAY_MAX_RECORDS", 1)
    write_named_outbox(
        outbox,
        "grabowski_task-second-a1.jsonl",
        [event("agent.run.completed", "b")],
    )
    first_delta = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert first_delta["delta_fast_path"] is True
    overlay_path = receipts / coding_memory.GRABOWSKI_DELTA_OVERLAY_FILENAME
    assert json.loads(overlay_path.read_text(encoding="utf-8"))["record_count"] == 1

    write_named_outbox(
        outbox,
        "grabowski_task-third-a1.jsonl",
        [event("agent.run.completed", "c")],
    )
    fallback = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert fallback["errors"] == []
    assert fallback["delta_fast_path"] is False
    assert fallback["steady_fast_path"] is False
    assert fallback["events_imported"] == 1
    assert fallback["events_skipped_existing"] == 2
    assert fallback["receipts_deferred"] == 0
    assert (
        fallback["import_telemetry"]["counters"][
            "delta_overlay_capacity_fallbacks"
        ]
        == 1
    )
    delta_index = json.loads(
        (receipts / coding_memory.GRABOWSKI_DELTA_INDEX_FILENAME).read_text(
            encoding="utf-8"
        )
    )
    assert delta_index["source_count"] == 3
    assert json.loads(overlay_path.read_text(encoding="utf-8"))["record_count"] == 0


def test_corrupt_delta_overlay_falls_back_and_repairs_full_cache(tmp_path, monkeypatch):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_named_outbox(
        outbox,
        "grabowski_task-first-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    write_named_outbox(
        outbox,
        "grabowski_task-second-a1.jsonl",
        [event("agent.run.completed", "b")],
    )
    delta = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert delta["delta_fast_path"] is True

    overlay_path = receipts / coding_memory.GRABOWSKI_DELTA_OVERLAY_FILENAME
    overlay_path.write_text("{broken\n", encoding="utf-8")
    overlay_path.chmod(0o600)

    repaired = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert repaired["errors"] == []
    assert repaired["steady_fast_path"] is False
    assert repaired["delta_fast_path"] is False
    assert repaired["events_imported"] == 0
    assert repaired["events_skipped_existing"] == 2
    assert repaired["receipts_deferred"] == 0
    delta_index = json.loads(
        (receipts / coding_memory.GRABOWSKI_DELTA_INDEX_FILENAME).read_text(
            encoding="utf-8"
        )
    )
    assert delta_index["source_count"] == 2
    overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
    assert overlay["record_count"] == 0

    steady = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert steady["steady_fast_path"] is True
    assert steady["events_skipped_existing"] == 2


def test_summary_delta_fast_path_folds_exact_compaction_relocation(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    source_dir = outbox / "grabowski" / "chronik-outbox"
    write_named_outbox(
        outbox,
        "grabowski_task-first-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    write_named_outbox(
        outbox,
        "grabowski_task-second-a1.jsonl",
        [event("agent.run.completed", "b")],
    )
    first = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert first["errors"] == []
    source_index_path = receipts / coding_memory.GRABOWSKI_SOURCE_INDEX_FILENAME
    source_index_before = source_index_path.read_bytes()

    compacted = coding_memory.compact_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        grace_seconds=0,
        max_sources=2,
        apply=True,
    )
    assert compacted["errors"] == []
    assert compacted["sources_removed"] == 2
    assert list(source_dir.glob("*.jsonl")) == []

    original_import = coding_memory._import_prepared_grabowski_sources

    def unexpected_ledger_reconcile(*args, **kwargs):
        raise AssertionError("exact compaction relocation touched the ledger reconcile path")

    monkeypatch.setattr(
        coding_memory, "_import_prepared_grabowski_sources", unexpected_ledger_reconcile
    )
    original_open = coding_memory.os.open
    lock_path = source_dir / coding_memory.GRABOWSKI_WRITER_COMPACTION_LOCK_FILENAME
    lock_open_observed = False

    def observe_lock_open(path, flags, *args, **kwargs):
        nonlocal lock_open_observed
        if Path(path) == lock_path:
            lock_open_observed = True
            assert flags & os.O_ACCMODE == os.O_RDONLY
            assert flags & os.O_CREAT == 0
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(coding_memory.os, "open", observe_lock_open)
    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    monkeypatch.setattr(
        coding_memory, "_import_prepared_grabowski_sources", original_import
    )
    assert lock_open_observed is True

    assert result["errors"] == []
    assert result["steady_fast_path"] is False
    assert result["delta_fast_path"] is True
    assert result["compaction_delta_fast_path"] is True
    assert result["events_imported"] == 0
    assert result["events_skipped_existing"] == 2
    assert result["files_seen"] == 0
    assert result["bundles_valid"] == 1
    assert result["bundled_sources_seen"] == 2
    assert result["sources_after_deduplication"] == 2
    assert result["sources_revalidated"] == 2
    assert result["sources_reused"] == 0
    assert result["source_index_mode"] == "deferred_delta"
    assert result["source_index_written"] is False
    assert source_index_path.read_bytes() == source_index_before
    assert result["target_scans"] == 0
    assert result["target_records_scanned"] == 0
    assert result["import_telemetry"]["counters"][
        "compaction_delta_fast_path_hits"
    ] == 1
    assert result["import_telemetry"]["counters"][
        "compaction_sources_relocated"
    ] == 2

    delta_index = json.loads(
        (receipts / coding_memory.GRABOWSKI_DELTA_INDEX_FILENAME).read_text(
            encoding="utf-8"
        )
    )
    assert delta_index["source_count"] == 2
    assert delta_index["loose_sources"] == []
    assert len(delta_index["bundles"]) == 1
    overlay = json.loads(
        (receipts / coding_memory.GRABOWSKI_DELTA_OVERLAY_FILENAME).read_text(
            encoding="utf-8"
        )
    )
    assert overlay["record_count"] == 0

    steady = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert steady["steady_fast_path"] is True
    assert steady["events_skipped_existing"] == 2


def test_summary_compaction_delta_rejects_corrupt_new_bundle(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_named_outbox(
        outbox,
        "grabowski_task-one-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    compacted = coding_memory.compact_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        grace_seconds=0,
        max_sources=1,
        apply=True,
    )
    assert compacted["errors"] == []
    bundle = Path(compacted["bundle_path"])
    bundle.write_bytes(bundle.read_bytes() + b" ")

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert result["steady_fast_path"] is False
    assert result["delta_fast_path"] is False
    assert result.get("compaction_delta_fast_path") is not True
    assert result["bundles_valid"] == 0
    assert result["errors"]
    assert "bundle" in result["errors"][0]["error"]


def test_summary_compaction_delta_falls_back_after_receipt_inventory_drift(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    source = write_named_outbox(
        outbox,
        "grabowski_task-one-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    compacted = coding_memory.compact_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        grace_seconds=0,
        max_sources=1,
        apply=True,
    )
    assert compacted["errors"] == []
    # The generation receipt is path+source-digest bound; locate the existing
    # canonical receipt and drift only its metadata, not its content.
    receipt = next(receipts.glob("*.receipt.json"))
    before = receipt.stat()
    os.utime(receipt, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert result["errors"] == []
    assert result["steady_fast_path"] is False
    assert result["delta_fast_path"] is False
    assert result.get("compaction_delta_fast_path") is not True
    assert result["events_imported"] == 0
    assert result["events_skipped_existing"] == 1


def test_summary_compaction_delta_falls_back_on_target_identity_drift(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_named_outbox(
        outbox,
        "grabowski_task-one-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    compacted = coding_memory.compact_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        grace_seconds=0,
        max_sources=1,
        apply=True,
    )
    assert compacted["errors"] == []
    original = coding_memory.storage.read_unique_storage_checkpoint_identity
    calls = 0

    def drift_once(domain):
        nonlocal calls
        calls += 1
        current = dict(original(domain))
        if calls >= 2:
            current["test_drift"] = 1
        return current

    monkeypatch.setattr(
        coding_memory.storage, "read_unique_storage_checkpoint_identity", drift_once
    )
    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert result["errors"] == []
    assert result["steady_fast_path"] is False
    assert result["delta_fast_path"] is False
    assert result.get("compaction_delta_fast_path") is not True
    assert result["events_imported"] == 0
    assert result["events_skipped_existing"] == 1


def test_summary_compaction_delta_falls_back_when_bundle_overlaps_live_loose(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    source_dir = outbox / "grabowski" / "chronik-outbox"
    source = write_named_outbox(
        outbox,
        "grabowski_task-one-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    def keep_loose_source(path):
        assert path == source
        raise OSError("simulated unlink failure")

    monkeypatch.setattr(coding_memory, "_unlink_loose_source", keep_loose_source)
    compacted = coding_memory.compact_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        grace_seconds=0,
        max_sources=1,
        apply=True,
    )
    assert compacted["sources_removed"] == 0
    assert source.exists()
    assert len(list((source_dir / "bundles").glob("*.manifest.json"))) == 1

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert result["errors"] == []
    assert result["steady_fast_path"] is False
    assert result["delta_fast_path"] is False
    assert result.get("compaction_delta_fast_path") is not True
    assert result["sources_after_deduplication"] == 1
    assert result["events_imported"] == 0
    assert result["events_skipped_existing"] == 1


def test_summary_delta_fast_path_falls_back_on_source_removal(tmp_path, monkeypatch):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_named_outbox(
        outbox,
        "grabowski_task-first-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    removed = write_named_outbox(
        outbox,
        "grabowski_task-second-a1.jsonl",
        [event("agent.run.completed", "b")],
    )
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    removed.unlink()

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert result["errors"] == []
    assert result["delta_fast_path"] is False
    assert result["steady_fast_path"] is False
    assert result["sources_removed"] == 1
    assert result["events_imported"] == 0
    assert result["events_skipped_existing"] == 1
    assert result["import_telemetry"]["counters"]["delta_fast_path_fallbacks"] == 1


def test_corrupt_delta_index_falls_back_and_repairs_canonical_source_index(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_named_outbox(
        outbox,
        "grabowski_task-first-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    source_index_path = receipts / coding_memory.GRABOWSKI_SOURCE_INDEX_FILENAME
    source_index_before = source_index_path.read_bytes()
    delta_index_path = receipts / coding_memory.GRABOWSKI_DELTA_INDEX_FILENAME
    write_named_outbox(
        outbox,
        "grabowski_task-second-a1.jsonl",
        [event("agent.run.completed", "b")],
    )
    delta_index_path.write_text("{broken\n", encoding="utf-8")
    delta_index_path.chmod(0o600)

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert result["errors"] == []
    assert result["delta_fast_path"] is False
    assert result["steady_fast_path"] is False
    assert result["events_imported"] == 1
    assert result["sources_added"] == 1
    assert source_index_path.read_bytes() != source_index_before
    source_index = json.loads(source_index_path.read_text(encoding="utf-8"))
    assert len(source_index["loose_sources"]) == 2
    delta_index = json.loads(delta_index_path.read_text(encoding="utf-8"))
    assert delta_index["source_count"] == 2

    next_result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert next_result["steady_fast_path"] is True
    assert next_result["events_skipped_existing"] == 2


def test_summary_delta_fast_path_rechecks_authoritative_target_anchor(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_named_outbox(
        outbox,
        "grabowski_task-first-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    write_named_outbox(
        outbox,
        "grabowski_task-second-a1.jsonl",
        [event("agent.run.completed", "b")],
    )
    original = coding_memory.storage.read_unique_storage_checkpoint_identity

    def drifted_target_identity(domain):
        current = dict(original(domain))
        current["test_drift"] = 1
        return current

    monkeypatch.setattr(
        coding_memory.storage,
        "read_unique_storage_checkpoint_identity",
        drifted_target_identity,
    )
    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert result["errors"] == []
    assert result["delta_fast_path"] is False
    assert result["events_imported"] == 1
    assert result["import_telemetry"]["counters"]["delta_fast_path_fallbacks"] == 1


def test_summary_steady_fast_path_falls_back_when_source_directory_changes_mid_check(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    original = coding_memory._inventory_fingerprint
    mutated = False

    def mutate_after_snapshot(paths, *, private):
        nonlocal mutated
        result = original(paths, private=private)
        if not private and not mutated:
            mutated = True
            write_named_outbox(
                outbox,
                "grabowski_task-raced-a1.jsonl",
                [event("agent.run.completed", "b")],
            )
        return result

    monkeypatch.setattr(coding_memory, "_inventory_fingerprint", mutate_after_snapshot)
    recovered = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert recovered["steady_fast_path"] is False
    assert recovered["import_telemetry"]["counters"]["steady_fast_path_fallbacks"] == 1
    # The raced source was created after this run's initial glob; it is picked up on
    # the next normal run rather than being incorrectly certified unchanged.
    next_result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert next_result["events_imported"] == 1
    assert next_result["steady_fast_path"] is False


def test_summary_steady_fast_path_rechecks_source_after_target_identity(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    original = coding_memory.storage.read_unique_storage_checkpoint_identity
    mutated = False

    def mutate_before_return(*args, **kwargs):
        nonlocal mutated
        result = original(*args, **kwargs)
        if not mutated:
            mutated = True
            write_named_outbox(
                outbox,
                "grabowski_task-late-race-a1.jsonl",
                [event("agent.run.completed", "b")],
            )
        return result

    monkeypatch.setattr(
        coding_memory.storage,
        "read_unique_storage_checkpoint_identity",
        mutate_before_return,
    )
    recovered = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert recovered["steady_fast_path"] is False
    assert recovered["import_telemetry"]["counters"]["steady_fast_path_fallbacks"] == 1
    next_result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    assert next_result["events_imported"] == 1
    assert next_result["steady_fast_path"] is False


def test_summary_steady_fast_path_rechecks_receipts_after_target_identity(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    receipt = next(receipts.glob("*.receipt.json"))
    original = coding_memory.storage.read_unique_storage_checkpoint_identity
    mutated = False

    def mutate_before_return(*args, **kwargs):
        nonlocal mutated
        result = original(*args, **kwargs)
        if not mutated:
            mutated = True
            tampered = json.loads(receipt.read_text())
            tampered["source_sha256"] = "0" * 64
            receipt.write_text(json.dumps(tampered), encoding="utf-8")
        return result

    monkeypatch.setattr(
        coding_memory.storage,
        "read_unique_storage_checkpoint_identity",
        mutate_before_return,
    )
    recovered = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert recovered["steady_fast_path"] is False
    assert recovered["import_telemetry"]["counters"]["steady_fast_path_fallbacks"] == 1
    assert recovered["receipts_written"] == 1


def test_summary_steady_fast_path_falls_back_after_receipt_drift(tmp_path, monkeypatch):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    receipt = next(receipts.glob("*.receipt.json"))
    tampered = json.loads(receipt.read_text())
    tampered["source_sha256"] = "0" * 64
    receipt.write_text(json.dumps(tampered), encoding="utf-8")

    recovered = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert recovered["steady_fast_path"] is False
    assert recovered["import_telemetry"]["counters"]["steady_fast_path_fallbacks"] == 1
    assert recovered["receipts_written"] == 1
    repaired = json.loads(receipt.read_text())
    assert repaired["receipt_sha256"]


def test_summary_steady_fast_path_falls_back_after_source_index_drift(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    index_path = receipts / coding_memory.GRABOWSKI_SOURCE_INDEX_FILENAME
    raw = index_path.read_bytes()
    index_path.write_bytes(raw)
    index_path.chmod(0o600)

    recovered = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert recovered["steady_fast_path"] is False
    assert recovered["import_telemetry"]["counters"]["steady_fast_path_fallbacks"] == 1
    assert recovered["errors"] == []


def test_summary_steady_fast_path_falls_back_after_ledger_drift(tmp_path, monkeypatch):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    coding_memory.import_events([event("agent.run.completed", "b")])

    recovered = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert recovered["steady_fast_path"] is False
    assert recovered["import_telemetry"]["counters"]["steady_fast_path_fallbacks"] == 1
    assert recovered["target_scans"] == 0
    assert recovered["errors"] == []


def test_corrupt_steady_checkpoint_falls_back_to_full_import(tmp_path, monkeypatch):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )
    checkpoint = receipts / coding_memory.GRABOWSKI_STEADY_CHECKPOINT_FILENAME
    checkpoint.write_text("{}\n", encoding="utf-8")
    checkpoint.chmod(0o600)

    recovered = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        allow_steady_fast_path=True,
    )

    assert recovered["steady_fast_path"] is False
    assert recovered["errors"] == []
    rebuilt = json.loads(checkpoint.read_text())
    claimed = rebuilt.pop("checkpoint_sha256")
    assert claimed == coding_memory.sha256_bytes(coding_memory.canonical_bytes(rebuilt))


def test_metadata_drift_revalidates_source_even_when_size_and_mtime_match(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    source = write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)
    before = source.stat()
    replacement = json.dumps(event("agent.run.completed", "b"), sort_keys=True) + "\n"
    assert len(replacement.encode("utf-8")) == before.st_size
    source.write_text(replacement, encoding="utf-8")
    os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert result["errors"] == []
    assert result["sources_changed"] == 1
    assert result["sources_revalidated"] == 1
    assert result["sources_reused"] == 0
    assert result["source_bytes_read"] == before.st_size
    assert result["events_imported"] == 1


def test_corrupt_source_index_is_reconstructed_from_authoritative_source(
    tmp_path, monkeypatch
):
    _, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)
    index_path = receipts / coding_memory.GRABOWSKI_SOURCE_INDEX_FILENAME
    index_path.write_text("{}\n", encoding="utf-8")
    index_path.chmod(0o600)

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert result["errors"] == []
    assert result["source_index_mode"] == "rebuild_invalid"
    assert result["source_index_written"] is True
    assert result["sources_revalidated"] == 1
    assert result["sources_reused"] == 0
    assert result["source_bytes_read"] > 0
    rebuilt = json.loads(index_path.read_text())
    claimed = rebuilt.pop("index_sha256")
    assert claimed == coding_memory.sha256_bytes(coding_memory.canonical_bytes(rebuilt))


def test_source_index_never_appends_when_cached_identity_is_missing(
    tmp_path, monkeypatch
):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    write_outbox(outbox, [event("agent.run.completed", "a")])
    coding_memory.import_grabowski_outbox(outbox_root=outbox, receipt_dir=receipts)
    target = data / "agent.ledger.jsonl"
    target.unlink()
    identity_index.reset_identity_index_for_authoritative_replay(target)
    replacement = event("agent.run.completed", "b")
    coding_memory.import_events([replacement])

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert result["events_imported"] == 0
    assert result["files_imported_or_confirmed"] == 0
    assert result["target_scans"] is None
    assert result["errors"][0]["source_path"] == "<batch>"
    assert "verification-only identities are missing" in result["errors"][0]["error"]
    rows = target.read_text(encoding="utf-8").splitlines()
    assert len(rows) == 1
    assert json.loads(rows[0])["payload"]["event_id"] == replacement["event_id"]


def test_import_rejects_symlinked_loose_source(tmp_path, monkeypatch):
    data, receipts, outbox = configure(tmp_path, monkeypatch)
    external = tmp_path / "external.jsonl"
    external.write_text(
        json.dumps(event("agent.run.completed", "a"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    source_dir = outbox / "grabowski" / "chronik-outbox"
    source_dir.mkdir(parents=True)
    linked = source_dir / "grabowski_task-linked-a1.jsonl"
    linked.symlink_to(external)

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert result["events_imported"] == 0
    assert "must be a regular file" in result["errors"][0]["error"]
    assert not (data / "agent.ledger.jsonl").exists()
    assert not receipts.exists()


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
    assert recovered["source_index_mode"] == "authoritative_rebuild"
    assert recovered["sources_revalidated"] == 1
    assert recovered["sources_reused"] == 0
    assert recovered["source_bytes_read"] > 0
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
    assert recovered["target_scans"] == 0
    assert recovered["target_records_scanned"] == 0
    assert recovered["identity_index_mode"] == "steady"
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
    assert recovered["target_scans"] == 0
    assert recovered["target_records_scanned"] == 0
    assert recovered["identity_index_mode"] == "steady"
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


def test_import_outbox_cli_summary_is_single_line_and_bounded(tmp_path):
    import subprocess
    import sys

    data = tmp_path / "data"
    receipts = tmp_path / "receipts"
    outbox = tmp_path / "state"
    write_outbox(outbox, [event("agent.run.completed", "a")])
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
            "--output-mode",
            "summary",
        ],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert len(result.stdout.splitlines()) == 1
    assert len(result.stdout.encode("utf-8")) < 4096
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "chronik-grabowski-outbox-summary.v1"
    assert payload["events_imported"] == 1
    assert payload["error_count"] == 0
    assert payload["error_samples"] == []
    assert "bundle_inventory" not in payload


def test_import_outbox_cli_summary_preserves_bounded_error_signal(tmp_path):
    import subprocess
    import sys

    data = tmp_path / "data"
    receipts = tmp_path / "receipts"
    outbox = tmp_path / "state"
    write_outbox(
        outbox,
        [event("agent.run.completed", "e", source_repo="heimgewebe/other")],
    )
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
            "--output-mode",
            "summary",
        ],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 2
    assert len(result.stdout.splitlines()) == 1
    assert len(result.stdout.encode("utf-8")) < 4096
    payload = json.loads(result.stdout)
    assert payload["error_count"] == 1
    assert len(payload["error_samples"]) == 1
    assert "not produced by canonical Grabowski" in payload["error_samples"][0]["error"]
    assert payload["errors_truncated"] is False


def test_outbox_summary_has_a_hard_worst_case_size_bound():
    from tools import coding_memory as coding_memory_cli

    result = {
        "schema_version": "chronik-grabowski-outbox-batch.v2",
        **{key: 0 for key in coding_memory_cli.OUTBOX_SUMMARY_KEYS},
        "identity_index_mode": "unused",
        "identity_index_full_rebuild": False,
        "errors": [
            {
                "source_path": "/very/long/" + "source" * 200,
                "error": "failure " * 500,
            }
            for _ in range(20)
        ],
        "historical_only": True,
    }

    summary = coding_memory_cli.outbox_summary(result)
    encoded = json.dumps(summary, sort_keys=True, separators=(",", ":")).encode("utf-8")

    assert len(encoded) < 4096
    assert summary["error_count"] == 20
    assert len(summary["error_samples"]) == 3
    assert summary["errors_truncated"] is True


@pytest.mark.parametrize(
    "filler",
    [
        "s",
        "ä",  # two UTF-8 bytes, six once JSON-escaped
        "\x01",  # control character, six bytes once escaped
        "\U0001f600",  # astral plane, twelve bytes as an escaped surrogate pair
        "\n",
        '"\\',
    ],
    ids=["ascii", "latin1", "control", "astral", "newline", "quote-backslash"],
)
def test_outbox_summary_line_stays_bounded_for_any_error_text(filler):
    from tools import coding_memory as coding_memory_cli

    result = {
        "schema_version": "chronik-grabowski-outbox-batch.v2" + filler * 500,
        **{key: 0 for key in coding_memory_cli.OUTBOX_SUMMARY_KEYS},
        "identity_index_mode": filler * 500,
        "identity_index_full_rebuild": False,
        "errors": [
            {"source_path": filler * 2000, "error": filler * 5000} for _ in range(20)
        ],
        "historical_only": True,
    }

    line = coding_memory_cli.outbox_summary_line(result)

    # +1 for the newline print() appends, so the whole journal write is bounded.
    assert len(line.encode("utf-8")) + 1 < coding_memory_cli.OUTBOX_SUMMARY_MAX_BYTES
    assert coding_memory_cli.OUTBOX_SUMMARY_MAX_BYTES == 4096
    assert "\n" not in line
    payload = json.loads(line)
    assert payload["error_count"] == 20
    assert len(payload["error_samples"]) <= 3
    assert payload["errors_truncated"] is True


def test_outbox_summary_line_falls_back_when_a_counter_itself_is_oversized():
    from tools import coding_memory as coding_memory_cli

    result = {
        "schema_version": "chronik-grabowski-outbox-batch.v2",
        **{key: 0 for key in coding_memory_cli.OUTBOX_SUMMARY_KEYS},
        "files_seen": list(range(50000)),
        "identity_index_mode": "unused",
        "identity_index_full_rebuild": False,
        "errors": [{"source_path": "/a.jsonl", "error": "boom"}],
        "historical_only": True,
    }

    line = coding_memory_cli.outbox_summary_line(result)
    payload = json.loads(line)

    assert len(line.encode("utf-8")) + 1 < coding_memory_cli.OUTBOX_SUMMARY_MAX_BYTES
    assert payload["error_count"] == 1
    assert payload["errors_truncated"] is True
    assert payload["schema_version"] == "chronik-grabowski-outbox-summary.v1"
    # Dropping error samples cannot help here, so the minimal payload is used.
    assert "files_seen" not in payload


def test_outbox_summary_keeps_short_error_text_intact():
    from tools import coding_memory as coding_memory_cli

    result = {
        "schema_version": "chronik-grabowski-outbox-batch.v2",
        **{key: 0 for key in coding_memory_cli.OUTBOX_SUMMARY_KEYS},
        "identity_index_mode": "unused",
        "identity_index_full_rebuild": False,
        "errors": [{"source_path": "/a/b.jsonl", "error": "unreadable: Ümläut"}],
        "historical_only": True,
    }

    payload = json.loads(coding_memory_cli.outbox_summary_line(result))

    assert payload["error_samples"] == [
        {"source_path": "/a/b.jsonl", "error": "unreadable: Ümläut"}
    ]
    assert payload["errors_truncated"] is False
    assert payload["identity_index_mode"] == "unused"
    assert payload["result_schema_version"] == "chronik-grabowski-outbox-batch.v2"


def test_import_outbox_cli_default_output_mode_keeps_the_full_schema(tmp_path):
    import subprocess
    import sys

    data = tmp_path / "data"
    receipts = tmp_path / "receipts"
    outbox = tmp_path / "state"
    write_outbox(outbox, [event("agent.run.completed", "a")])
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

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "chronik-grabowski-outbox-batch.v2"
    assert payload["errors"] == []
    assert "bundle_inventory" in payload
    assert "error_samples" not in payload


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
    assert second["target_scans"] == 0
    assert second["target_records_scanned"] == 0
    assert second["identity_index_mode"] == "steady"
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
    assert recovered["target_scans"] == 0
    assert recovered["target_records_scanned"] == 0
    assert recovered["identity_index_mode"] == "steady"
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
