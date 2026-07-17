import json
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


def test_source_change_after_publish_is_retained_and_import_fails_closed(
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
    failed_import = coding_memory.import_grabowski_outbox(
        outbox_root=outbox, receipt_dir=receipts
    )
    assert failed_import["events_imported"] == 0
    assert failed_import["target_scans"] is None
    assert "conflicting loose and bundled source bytes" in failed_import["errors"][-1]["error"]
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
