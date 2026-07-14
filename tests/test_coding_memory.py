import hashlib, json
from pathlib import Path
import pytest
import coding_memory, storage

def event(event_id="sha256:"+"a"*64, repo="heimgewebe/example", component="api", operation="implement", outcome="completed", ts="2026-07-13T10:00:00Z"):
    return {"schema_version":"agent-run-event.v0","event_id":event_id,"kind":"agent.run.completed","ts":ts,"source":{"repo":"heimgewebe/grabowski","component":"grabowski","run_id":"task-test-a1"},"subject":{"repo":repo,"component":component,"operation":operation,"bureau_task_id":"CCM-V1-T001","pr_number":1},"trust_tier":"observed","status":"active","caused_by":[],"evidence_refs":["grabowski-task:test"],"data":{"result":"completed","outcome":outcome}}

def setup(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,"DATA_DIR",tmp_path); return tmp_path

def test_import_is_idempotent_and_uses_canonical_envelope(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); first=coding_memory.import_events([event()]); second=coding_memory.import_events([event()])
    assert first["imported"]==1 and second["imported"]==0 and second["skipped_existing"]==1
    row=json.loads((tmp_path/"agent.ledger.jsonl").read_text().splitlines()[0])
    assert row["domain"]=="agent.ledger" and row["payload"]["subject"]["repo"]=="heimgewebe/example"
    assert "quality" in row and "retention" in row


def test_import_rejects_divergent_event_id_before_partial_write(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch)
    with pytest.raises(storage.StorageError, match="conflicting event_id"):
        coding_memory.import_events([event(), event(repo="heimgewebe/other")])
    target = tmp_path / "agent.ledger.jsonl"
    assert not target.exists() or target.read_text() == ""

    coding_memory.import_events([event()])
    before = target.read_bytes()
    with pytest.raises(storage.StorageError, match="conflicting event_id"):
        coding_memory.import_events([event(repo="heimgewebe/other")])
    assert target.read_bytes() == before


def test_query_compares_since_offset_in_utc(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch)
    coding_memory.import_events([event(ts="2026-07-13T08:30:00Z"), event("sha256:"+"b"*64, ts="2026-07-13T09:30:00Z")])
    result = coding_memory.query_history(repo="heimgewebe/example", since="2026-07-13T10:00:00+02:00")
    assert result["event_ids"] == ["sha256:"+"b"*64, "sha256:"+"a"*64]


def test_query_filters_and_marks_history_only(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); coding_memory.import_events([event(),event("sha256:"+"b"*64,repo="heimgewebe/other")])
    result=coding_memory.query_history(repo="heimgewebe/example",component="api",operation="implement",outcome="completed")
    assert result["event_ids"]==["sha256:"+"a"*64]
    assert result["historical_only"] is True and "current_ci_state" in result["does_not_establish"]

def test_freeze_binds_query_and_bytes(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); coding_memory.import_events([event()]); output=tmp_path/"cohort.jsonl"
    receipt=coding_memory.freeze_history(output,repo="heimgewebe/example",component=None,operation=None,outcome=None,since=None,limit=20)
    assert receipt["event_count"]==1
    assert receipt["cohort_sha256"]==hashlib.sha256(output.read_bytes()).hexdigest()
    saved=json.loads((tmp_path/"cohort.jsonl.receipt.json").read_text()); assert saved["receipt_sha256"]==receipt["receipt_sha256"]


def test_query_cli_missing_data_dir_is_read_only(tmp_path):
    import subprocess, sys
    missing = tmp_path / "missing"
    result = subprocess.run([sys.executable, str(Path(__file__).parents[1] / "tools" / "coding_memory.py"), "--data-dir", str(missing), "query", "--repo", "heimgewebe/example"], text=True, capture_output=True)
    assert result.returncode == 0
    assert not missing.exists()
    assert json.loads(result.stdout)["events"] == []


def test_query_cli_prefers_repository_module_when_pythonpath_contains_root(tmp_path):
    import os, subprocess, sys
    root = Path(__file__).parents[1]
    missing = tmp_path / "missing"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root)
    result = subprocess.run(
        [sys.executable, str(root / "tools" / "coding_memory.py"), "--data-dir", str(missing), "query", "--repo", "heimgewebe/example"],
        text=True,
        capture_output=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["events"] == []
    assert not missing.exists()


def test_query_cli_validates_filters_without_creating_data_dir(tmp_path):
    import subprocess, sys
    missing = tmp_path / "missing"
    result = subprocess.run([sys.executable, str(Path(__file__).parents[1] / "tools" / "coding_memory.py"), "--data-dir", str(missing), "query", "--repo", "heimgewebe/example", "--limit", "0"], text=True, capture_output=True)
    assert result.returncode == 2
    assert "limit 1..500" in result.stderr
    assert not missing.exists()
