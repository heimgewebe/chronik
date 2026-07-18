import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path

import coding_memory
import storage


def event(kind: str, suffix: str) -> dict:
    outcome = {
        "agent.run.started": {"result": "started"},
        "agent.run.completed": {"result": "completed"},
        "agent.run.blocked": {"result": "blocked", "blocker_code": "task-failed"},
    }[kind]
    return {
        "schema_version": "agent-run-event.v0",
        "event_id": "sha256:" + suffix * 64,
        "kind": kind,
        "ts": "2026-07-14T10:00:00Z",
        "source": {
            "repo": "heimgewebe/grabowski",
            "component": "grabowski",
            "run_id": f"task-{suffix}-a1",
        },
        "subject": {"repo": "heimgewebe/grabowski"},
        "trust_tier": "declared" if kind == "agent.run.started" else "observed",
        "status": "active",
        "caused_by": [],
        "evidence_refs": [f"grabowski-task:{suffix}"],
        "data": outcome,
    }


def configure(tmp_path: Path, monkeypatch) -> tuple[Path, Path, Path, Path]:
    data = tmp_path / "chronik-data"
    receipts = tmp_path / "receipts"
    outbox = tmp_path / "state"
    source_dir = outbox / "grabowski" / "chronik-outbox"
    data.mkdir(parents=True)
    source_dir.mkdir(parents=True)
    monkeypatch.setattr(storage, "DATA_DIR", data)
    return data, receipts, outbox, source_dir


def write_source(source_dir: Path, name: str, values: list[dict]) -> Path:
    path = source_dir / name
    path.write_bytes(
        b"".join(
            json.dumps(value, sort_keys=True).encode("utf-8") + b"\n"
            for value in values
        )
    )
    return path


def import_first(outbox: Path, receipts: Path) -> dict:
    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )
    assert result["errors"] == []
    return result


def compact(outbox: Path, receipts: Path, *, apply: bool = False) -> dict:
    return coding_memory.compact_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        grace_seconds=0,
        apply=apply,
    )


def test_dry_run_selects_terminal_sources_without_mutation(tmp_path, monkeypatch):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    one_line = write_source(
        source_dir, "grabowski_task-one-a1.jsonl", [event("agent.run.completed", "a")]
    )
    two_line = write_source(
        source_dir,
        "grabowski_task-two-a1.jsonl",
        [event("agent.run.started", "b"), event("agent.run.blocked", "c")],
    )
    active = write_source(
        source_dir, "grabowski_task-active-a1.jsonl", [event("agent.run.started", "d")]
    )
    import_first(outbox, receipts)

    result = compact(outbox, receipts)

    assert result["mode"] == "dry-run"
    assert result["eligible_sources"] == 2
    assert result["eligible_events"] == 3
    assert result["skipped_by_reason"] == {"nonterminal": 1}
    assert result["sources_removed"] == 0
    assert one_line.exists() and two_line.exists() and active.exists()
    assert not (source_dir / "bundles").exists()


def test_apply_bundles_sources_and_replays_after_ledger_and_receipt_loss(
    tmp_path, monkeypatch
):
    data, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    write_source(
        source_dir, "grabowski_task-one-a1.jsonl", [event("agent.run.completed", "a")]
    )
    write_source(
        source_dir,
        "grabowski_task-two-a1.jsonl",
        [event("agent.run.started", "b"), event("agent.run.blocked", "c")],
    )
    import_first(outbox, receipts)

    applied = compact(outbox, receipts, apply=True)

    assert applied["errors"] == []
    assert applied["sources_removed"] == 2
    assert applied["loose_sources_remaining"] == 0
    assert Path(applied["bundle_path"]).is_file()
    assert Path(applied["manifest_path"]).is_file()
    assert applied["bundle_sha256"]
    assert applied["manifest_sha256"]

    (data / "agent.ledger.jsonl").unlink()
    for receipt in receipts.glob("*.receipt.json"):
        receipt.unlink()
    recovered = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert recovered["errors"] == []
    assert recovered["loose_files_seen"] == 0
    assert recovered["bundles_valid"] == 1
    assert recovered["bundled_sources_imported_or_confirmed"] == 2
    assert recovered["events_imported"] == 3
    assert len((data / "agent.ledger.jsonl").read_text().splitlines()) == 3
    assert len(list(receipts.glob("*.receipt.json"))) == 2


def test_repeat_apply_is_noop(tmp_path, monkeypatch):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    write_source(
        source_dir, "grabowski_task-one-a1.jsonl", [event("agent.run.completed", "a")]
    )
    import_first(outbox, receipts)
    first = compact(outbox, receipts, apply=True)

    second = compact(outbox, receipts, apply=True)

    assert first["sources_removed"] == 1
    assert second["eligible_sources"] == 0
    assert second["sources_removed"] == 0
    assert second["errors"] == []
    assert len(list((source_dir / "bundles").glob("*.manifest.json"))) == 1


def test_archive_index_is_published_and_validated_before_source_unlink(
    tmp_path, monkeypatch
):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir,
        "grabowski_task-indexed-a1.jsonl",
        [event("agent.run.started", "a"), event("agent.run.completed", "b")],
    )
    import_first(outbox, receipts)
    original_unlink = coding_memory._unlink_loose_source
    observed = {}

    def guarded_unlink(path):
        index_path = source_dir / "bundles" / coding_memory.GRABOWSKI_ARCHIVE_INDEX_FILENAME
        raw = index_path.read_bytes()
        index = coding_memory._validate_grabowski_archive_index(
            raw, path=index_path
        )
        observed.update(index)
        assert index["source_count"] == 1
        assert index["sources"][0]["source_name"] == source.name
        assert index["sources"][0]["event_ids"] == [
            event("agent.run.started", "a")["event_id"],
            event("agent.run.completed", "b")["event_id"],
        ]
        original_unlink(path)

    monkeypatch.setattr(coding_memory, "_unlink_loose_source", guarded_unlink)

    result = compact(outbox, receipts, apply=True)

    assert result["errors"] == []
    assert result["sources_removed"] == 1
    assert result["archive_index_published"] is True
    assert result["archive_manifests_indexed"] == 1
    assert result["archived_sources_indexed"] == 1
    assert result["archive_index_sha256"] == observed["index_sha256"]
    assert not source.exists()



def test_apply_holds_writer_compaction_lock_through_source_unlink(
    tmp_path, monkeypatch
):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir,
        "grabowski_task-locked-a1.jsonl",
        [event("agent.run.started", "a"), event("agent.run.completed", "b")],
    )
    import_first(outbox, receipts)
    original_unlink = coding_memory._unlink_loose_source
    observed = {}

    def guarded_unlink(path):
        lock_path = (
            source_dir / coding_memory.GRABOWSKI_WRITER_COMPACTION_LOCK_FILENAME
        )
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CLOEXEC)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                observed["blocked"] = True
            else:
                observed["blocked"] = False
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
        assert observed["blocked"] is True
        original_unlink(path)

    monkeypatch.setattr(coding_memory, "_unlink_loose_source", guarded_unlink)

    result = compact(outbox, receipts, apply=True)

    lock_path = source_dir / coding_memory.GRABOWSKI_WRITER_COMPACTION_LOCK_FILENAME
    assert result["errors"] == []
    assert result["sources_removed"] == 1
    assert observed == {"blocked": True}
    assert lock_path.is_file()
    assert lock_path.stat().st_mode & 0o777 == 0o600
    assert not source.exists()


def test_apply_rejects_symlinked_outbox_directory(tmp_path, monkeypatch):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    redirected = tmp_path / "redirected-outbox"
    source_dir.rmdir()
    redirected.mkdir()
    source_dir.symlink_to(redirected, target_is_directory=True)

    try:
        compact(outbox, receipts, apply=True)
    except ValueError as exc:
        assert "must be a real directory" in str(exc)
    else:
        raise AssertionError("symlinked outbox directory was accepted")

    assert list(redirected.iterdir()) == []


def test_dry_run_does_not_create_writer_compaction_lock(tmp_path, monkeypatch):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    write_source(
        source_dir,
        "grabowski_task-dry-lock-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    import_first(outbox, receipts)

    result = compact(outbox, receipts, apply=False)

    lock_path = source_dir / coding_memory.GRABOWSKI_WRITER_COMPACTION_LOCK_FILENAME
    assert result["mode"] == "dry-run"
    assert not lock_path.exists()


def test_repeat_apply_rebuilds_missing_archive_index_without_loose_sources(
    tmp_path, monkeypatch
):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    write_source(
        source_dir,
        "grabowski_task-rebuild-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    import_first(outbox, receipts)
    first = compact(outbox, receipts, apply=True)
    index_path = Path(first["archive_index_path"])
    original = index_path.read_bytes()
    index_path.unlink()

    rebuilt = compact(outbox, receipts, apply=True)
    unchanged = compact(outbox, receipts, apply=True)

    assert rebuilt["eligible_sources"] == 0
    assert rebuilt["sources_removed"] == 0
    assert rebuilt["archive_index_published"] is True
    assert rebuilt["archived_sources_indexed"] == 1
    assert index_path.read_bytes() == original
    assert unchanged["archive_index_published"] is False
    assert unchanged["archive_index_file_sha256"] == rebuilt["archive_index_file_sha256"]


def test_archive_index_allows_same_name_with_distinct_source_generations(
    tmp_path, monkeypatch
):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    name = "grabowski_task-generation-a1.jsonl"
    first_source = write_source(
        source_dir, name, [event("agent.run.completed", "a")]
    )
    first_raw = first_source.read_bytes()
    import_first(outbox, receipts)
    first = compact(outbox, receipts, apply=True)
    assert first["errors"] == []

    second_source = write_source(
        source_dir, name, [event("agent.run.completed", "b")]
    )
    second_raw = second_source.read_bytes()
    imported = import_first(outbox, receipts)
    second = compact(outbox, receipts, apply=True)
    repeated = compact(outbox, receipts, apply=True)

    assert imported["sources_after_deduplication"] == 2
    assert second["errors"] == []
    assert second["sources_removed"] == 1
    assert second["archive_manifests_indexed"] == 2
    assert second["archived_sources_indexed"] == 2
    assert repeated["errors"] == []
    assert repeated["archive_index_published"] is False
    index_path = Path(second["archive_index_path"])
    index = coding_memory._validate_grabowski_archive_index(
        index_path.read_bytes(), path=index_path
    )
    generations = [
        (item["source_name"], item["source_sha256"])
        for item in index["sources"]
    ]
    assert generations == sorted(
        [
            (name, coding_memory.sha256_bytes(first_raw)),
            (name, coding_memory.sha256_bytes(second_raw)),
        ]
    )
    assert len({item["manifest_index"] for item in index["sources"]}) == 2


def test_archive_index_rejects_exact_duplicate_source_generation():
    source = {
        "source_name": "grabowski_task-duplicate-a1.jsonl",
        "source_sha256": "a" * 64,
        "event_ids": ["sha256:" + "b" * 64],
    }
    metadata = [
        {
            "manifest_path": "/tmp/one.manifest.json",
            "manifest_sha256": "c" * 64,
            "sources": [source],
        },
        {
            "manifest_path": "/tmp/two.manifest.json",
            "manifest_sha256": "d" * 64,
            "sources": [source],
        },
    ]

    try:
        coding_memory._grabowski_archive_index_document(metadata)
    except ValueError as exc:
        assert "duplicate archived source generation" in str(exc)
    else:
        raise AssertionError("exact duplicate generation must fail closed")


def test_archive_index_readback_failure_retains_loose_source(tmp_path, monkeypatch):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir,
        "grabowski_task-index-failure-a1.jsonl",
        [event("agent.run.completed", "a")],
    )
    import_first(outbox, receipts)
    original_atomic_write = coding_memory._atomic_write

    def corrupt_index(path, data):
        if path.name == coding_memory.GRABOWSKI_ARCHIVE_INDEX_FILENAME:
            original_atomic_write(path, b"{broken\n")
            return
        original_atomic_write(path, data)

    monkeypatch.setattr(coding_memory, "_atomic_write", corrupt_index)

    result = compact(outbox, receipts, apply=True)

    assert result["sources_removed"] == 0
    assert source.exists()
    assert Path(result["bundle_path"]).exists()
    assert Path(result["manifest_path"]).exists()
    assert result["archive_index_sha256"] is None
    assert result["errors"][-1]["source_path"].endswith(
        coding_memory.GRABOWSKI_ARCHIVE_INDEX_FILENAME
    )
    assert "invalid archive index JSON" in result["errors"][-1]["error"]


def test_missing_corrupt_and_stale_receipts_are_not_compacted(tmp_path, monkeypatch):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    paths = [
        write_source(
            source_dir,
            f"grabowski_task-{suffix}-a1.jsonl",
            [event("agent.run.completed", suffix)],
        )
        for suffix in ("a", "b", "c")
    ]
    import_first(outbox, receipts)
    receipt_paths = [coding_memory._receipt_path(path, receipts) for path in paths]
    receipt_paths[0].unlink()
    receipt_paths[1].write_text("{broken", encoding="utf-8")
    stale = json.loads(receipt_paths[2].read_text())
    stale["source_sha256"] = "0" * 64
    unsigned = dict(stale)
    unsigned.pop("receipt_sha256")
    stale["receipt_sha256"] = coding_memory.sha256_bytes(
        coding_memory.canonical_bytes(unsigned)
    )
    receipt_paths[2].write_text(json.dumps(stale), encoding="utf-8")

    result = compact(outbox, receipts, apply=True)

    assert result["eligible_sources"] == 0
    assert result["sources_removed"] == 0
    assert result["skipped_by_reason"]["receipt_invalid_or_missing"] == 3
    assert result["errors"] == []
    assert all(path.exists() for path in paths)


def test_ledger_loss_blocks_compaction(tmp_path, monkeypatch):
    data, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir, "grabowski_task-one-a1.jsonl", [event("agent.run.completed", "a")]
    )
    import_first(outbox, receipts)
    (data / "agent.ledger.jsonl").unlink()

    result = compact(outbox, receipts, apply=True)

    assert result["eligible_sources"] == 0
    assert result["skipped_by_reason"] == {"ledger_unconfirmed": 1}
    assert source.exists()
    assert not (source_dir / "bundles").exists()


def test_corrupt_bundle_is_rejected_without_ledger_mutation(tmp_path, monkeypatch):
    data, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    write_source(
        source_dir, "grabowski_task-one-a1.jsonl", [event("agent.run.completed", "a")]
    )
    import_first(outbox, receipts)
    applied = compact(outbox, receipts, apply=True)
    bundle_path = Path(applied["bundle_path"])
    bundle_path.write_bytes(bundle_path.read_bytes() + b" ")
    (data / "agent.ledger.jsonl").unlink()

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert result["events_imported"] == 0
    assert result["bundles_valid"] == 0
    assert result["errors"]
    assert not (data / "agent.ledger.jsonl").exists()


def test_manifest_without_bundle_is_rejected(tmp_path, monkeypatch):
    data, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    write_source(
        source_dir, "grabowski_task-one-a1.jsonl", [event("agent.run.completed", "a")]
    )
    import_first(outbox, receipts)
    applied = compact(outbox, receipts, apply=True)
    Path(applied["bundle_path"]).unlink()
    (data / "agent.ledger.jsonl").unlink()

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert result["events_imported"] == 0
    assert result["errors"]
    assert "cannot inspect bundle file" in result["errors"][0]["error"]
    assert not (data / "agent.ledger.jsonl").exists()


def test_publish_failure_keeps_source(tmp_path, monkeypatch):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir, "grabowski_task-one-a1.jsonl", [event("agent.run.completed", "a")]
    )
    import_first(outbox, receipts)

    def fail_publish(path: Path, data: bytes) -> bool:
        raise OSError("simulated publish failure")

    monkeypatch.setattr(coding_memory, "_publish_immutable", fail_publish)
    result = compact(outbox, receipts, apply=True)

    assert result["sources_removed"] == 0
    assert result["errors"]
    assert source.exists()


def test_unlink_failure_keeps_source_but_publishes_replay_bundle(tmp_path, monkeypatch):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir, "grabowski_task-one-a1.jsonl", [event("agent.run.completed", "a")]
    )
    import_first(outbox, receipts)

    def fail_unlink(path: Path) -> None:
        raise OSError("simulated unlink failure")

    monkeypatch.setattr(coding_memory, "_unlink_loose_source", fail_unlink)
    result = compact(outbox, receipts, apply=True)

    assert result["sources_removed"] == 0
    assert result["skipped_by_reason"] == {"unlink_failed": 1}
    assert source.exists()
    assert Path(result["bundle_path"]).exists()
    assert Path(result["manifest_path"]).exists()
    readback = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )
    assert readback["errors"] == []
    assert readback["sources_after_deduplication"] == 1


def test_source_change_after_publish_is_retained_as_new_generation(
    tmp_path, monkeypatch
):
    data, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir, "grabowski_task-one-a1.jsonl", [event("agent.run.completed", "a")]
    )
    import_first(outbox, receipts)
    original_publish = coding_memory._publish_immutable
    changed = False

    def publish_and_change(path: Path, payload: bytes) -> bool:
        nonlocal changed
        published = original_publish(path, payload)
        if path.name.endswith(".manifest.json") and not changed:
            with source.open("ab") as handle:
                handle.write(
                    json.dumps(event("agent.run.started", "b"), sort_keys=True).encode()
                    + b"\n"
                )
            changed = True
        return published

    monkeypatch.setattr(coding_memory, "_publish_immutable", publish_and_change)
    result = compact(outbox, receipts, apply=True)

    assert result["sources_removed"] == 0
    assert result["skipped_by_reason"] == {"source_changed_before_remove": 1}
    assert source.exists()
    (data / "agent.ledger.jsonl").unlink()
    replay = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )
    assert replay["errors"] == []
    assert replay["events_imported"] == 2
    assert replay["events_skipped_existing"] == 1
    assert replay["sources_after_deduplication"] == 2
    assert replay["receipts_written"] == 1
    assert len(list(receipts.glob("*.receipt.json"))) == 2
    assert (data / "agent.ledger.jsonl").exists()


def test_same_path_same_event_id_with_changed_payload_fails_before_append(
    tmp_path, monkeypatch
):
    data, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    original = event("agent.run.completed", "c")
    source = write_source(source_dir, "grabowski_task-one-a1.jsonl", [original])
    import_first(outbox, receipts)
    compact(outbox, receipts, apply=True)
    conflicting = dict(original)
    conflicting["subject"] = {"repo": "heimgewebe/other"}
    write_source(source_dir, source.name, [conflicting])
    (data / "agent.ledger.jsonl").unlink()

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert result["events_imported"] == 0
    assert result["target_scans"] is None
    assert "conflicting event_id" in result["errors"][-1]["error"]
    assert not (data / "agent.ledger.jsonl").exists()


def test_divergent_event_id_across_bundle_and_loose_source_fails_before_append(
    tmp_path, monkeypatch
):
    data, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    original = event("agent.run.completed", "a")
    write_source(source_dir, "grabowski_task-one-a1.jsonl", [original])
    import_first(outbox, receipts)
    compact(outbox, receipts, apply=True)
    conflicting = event("agent.run.completed", "a")
    conflicting["subject"] = {"repo": "heimgewebe/other"}
    write_source(source_dir, "grabowski_task-conflict-a1.jsonl", [conflicting])
    (data / "agent.ledger.jsonl").unlink()

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert result["events_imported"] == 0
    assert result["target_scans"] is None
    assert "conflicting event_id" in result["errors"][-1]["error"]
    assert not (data / "agent.ledger.jsonl").exists()


def test_orphan_bundle_is_diagnosed_and_ignored(tmp_path, monkeypatch):
    data, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    bundle_dir = source_dir / "bundles"
    bundle_dir.mkdir()
    (bundle_dir / ("grabowski-" + "0" * 64 + ".bundle.jsonl")).write_text(
        "{}\n", encoding="utf-8"
    )

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )

    assert result["orphan_bundles"] == 1
    assert result["events_imported"] == 0
    assert "orphan bundle" in result["errors"][0]["error"]
    assert not (data / "agent.ledger.jsonl").exists()


def test_compact_cli_is_dry_run_by_default_and_apply_is_explicit(
    tmp_path, monkeypatch
):
    data, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir, "grabowski_task-one-a1.jsonl", [event("agent.run.completed", "a")]
    )
    import_first(outbox, receipts)
    root = Path(__file__).parents[1]
    base = [
        sys.executable,
        str(root / "tools" / "coding_memory.py"),
        "--data-dir",
        str(data),
        "compact-outbox",
        "--outbox-root",
        str(outbox),
        "--receipt-dir",
        str(receipts),
        "--grace-seconds",
        "0",
    ]

    dry = subprocess.run(base, text=True, capture_output=True)

    assert dry.returncode == 0
    assert json.loads(dry.stdout)["mode"] == "dry-run"
    assert source.exists() is True
    assert not (source_dir / "bundles").exists()

    applied = subprocess.run(base + ["--apply"], text=True, capture_output=True)

    assert applied.returncode == 0
    assert json.loads(applied.stdout)["sources_removed"] == 1
    assert source.exists() is False


def test_grace_period_retains_recent_terminal_source(tmp_path, monkeypatch):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir,
        "grabowski_task-recent-a1.jsonl",
        [event("agent.run.completed", "e")],
    )
    import_first(outbox, receipts)

    result = coding_memory.compact_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
        grace_seconds=86400,
        apply=True,
    )

    assert result["eligible_sources"] == 0
    assert result["sources_removed"] == 0
    assert result["skipped_by_reason"] == {"grace_pending": 1}
    assert source.exists()


def test_bundle_directory_fsync_failure_keeps_source(tmp_path, monkeypatch):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir,
        "grabowski_task-one-a1.jsonl",
        [event("agent.run.completed", "f")],
    )
    import_first(outbox, receipts)

    def fail_fsync(path: Path) -> None:
        raise OSError("simulated directory fsync failure")

    monkeypatch.setattr(coding_memory, "_fsync_directory", fail_fsync)
    result = compact(outbox, receipts, apply=True)

    assert result["sources_removed"] == 0
    assert result["errors"]
    assert source.exists()


def test_source_directory_fsync_failure_is_reported_after_safe_bundle(
    tmp_path, monkeypatch
):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir,
        "grabowski_task-one-a1.jsonl",
        [event("agent.run.completed", "1")],
    )
    import_first(outbox, receipts)
    original_fsync = coding_memory._fsync_directory
    source_dir_fsyncs = 0

    def fail_source_dir_only(path: Path) -> None:
        nonlocal source_dir_fsyncs
        if path == source_dir:
            source_dir_fsyncs += 1
            if source_dir_fsyncs == 2:
                raise OSError("simulated source directory fsync failure")
        original_fsync(path)

    monkeypatch.setattr(coding_memory, "_fsync_directory", fail_source_dir_only)
    result = compact(outbox, receipts, apply=True)

    assert result["sources_removed"] == 1
    assert source.exists() is False
    assert Path(result["bundle_path"]).exists()
    assert Path(result["manifest_path"]).exists()
    assert any("source directory fsync failed" in item["error"] for item in result["errors"])


def test_corrupt_receipt_does_not_block_authoritative_source_replay(
    tmp_path, monkeypatch
):
    data, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir,
        "grabowski_task-corrupt-receipt-a1.jsonl",
        [event("agent.run.completed", "2")],
    )
    import_first(outbox, receipts)
    receipt = coding_memory._receipt_path(source, receipts)
    receipt.write_text("{broken", encoding="utf-8")
    (data / "agent.ledger.jsonl").unlink()

    result = coding_memory.import_grabowski_outbox(
        outbox_root=outbox,
        receipt_dir=receipts,
    )

    assert result["errors"] == []
    assert result["events_imported"] == 1
    repaired = json.loads(receipt.read_text())
    assert repaired["source_sha256"] == coding_memory.sha256_bytes(source.read_bytes())


def test_bundle_replay_is_relocatable_without_original_absolute_path(
    tmp_path, monkeypatch
):
    data, receipts, outbox, source_dir = configure(tmp_path / "origin", monkeypatch)
    write_source(
        source_dir,
        "grabowski_task-portable-a1.jsonl",
        [event("agent.run.completed", "3")],
    )
    import_first(outbox, receipts)
    applied = compact(outbox, receipts, apply=True)
    assert applied["errors"] == []

    restored_root = tmp_path / "restored" / "state"
    restored_source_dir = restored_root / "grabowski" / "chronik-outbox"
    restored_bundle_dir = restored_source_dir / "bundles"
    restored_bundle_dir.mkdir(parents=True)
    for artifact in (Path(applied["bundle_path"]), Path(applied["manifest_path"])):
        (restored_bundle_dir / artifact.name).write_bytes(artifact.read_bytes())
    restored_data = tmp_path / "restored" / "chronik-data"
    restored_data.mkdir()
    restored_receipts = tmp_path / "restored" / "receipts"
    monkeypatch.setattr(storage, "DATA_DIR", restored_data)

    result = coding_memory.import_grabowski_outbox(
        outbox_root=restored_root,
        receipt_dir=restored_receipts,
    )

    assert result["errors"] == []
    assert result["events_imported"] == 1
    assert result["bundles_valid"] == 1
    assert len(list(restored_receipts.glob("*.receipt.json"))) == 1
    assert len((restored_data / "agent.ledger.jsonl").read_text().splitlines()) == 1


def test_bundle_directory_parent_is_fsynced_before_source_unlink(
    tmp_path, monkeypatch
):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir,
        "grabowski_task-parent-fsync-a1.jsonl",
        [event("agent.run.completed", "4")],
    )
    import_first(outbox, receipts)
    original_fsync = coding_memory._fsync_directory
    fsynced: list[Path] = []

    def record_fsync(path: Path) -> None:
        original_fsync(path)
        fsynced.append(path)

    def require_parent_fsync(path: Path) -> None:
        assert source_dir in fsynced
        path.unlink()

    monkeypatch.setattr(coding_memory, "_fsync_directory", record_fsync)
    monkeypatch.setattr(coding_memory, "_unlink_loose_source", require_parent_fsync)

    result = compact(outbox, receipts, apply=True)

    assert result["errors"] == []
    assert result["sources_removed"] == 1
    assert source.exists() is False


def test_symlink_bundle_directory_is_rejected_before_publication(
    tmp_path, monkeypatch
):
    _, receipts, outbox, source_dir = configure(tmp_path, monkeypatch)
    source = write_source(
        source_dir,
        "grabowski_task-symlink-a1.jsonl",
        [event("agent.run.completed", "5")],
    )
    import_first(outbox, receipts)
    outside = tmp_path / "outside-bundles"
    outside.mkdir()
    (source_dir / "bundles").symlink_to(outside, target_is_directory=True)

    result = compact(outbox, receipts, apply=True)

    assert result["sources_removed"] == 0
    assert result["errors"]
    assert "real directory" in result["errors"][0]["error"]
    assert source.exists()
    assert list(outside.iterdir()) == []
