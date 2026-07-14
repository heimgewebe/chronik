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


def test_query_prefers_canonical_data_operation_and_filters_task_class(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); value=event(); value["subject"]["operation"]="review"
    value["data"].update({"operation":"implement","task_class":"coding"}); coding_memory.import_events([value])
    result=coding_memory.query_history(repo="heimgewebe/example",operation="implement",task_class="coding")
    assert result["event_ids"]==[value["event_id"]]
    assert coding_memory.query_history(repo="heimgewebe/example",operation="review")["event_ids"]==[]


def test_query_supports_host_target_and_summary_dimensions(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); value=event("sha256:"+"c"*64,operation="recovery",outcome="blocked")
    value["kind"]="agent.run.blocked"; value["subject"]={"scope":"host","host":"heim-pc"}
    value["data"].update({"result":"blocked","operation":"recovery","task_class":"recovery","blocker_code":"recovery-gate"})
    coding_memory.import_events([value])
    result=coding_memory.query_history(host="heim-pc",operation="recovery",task_class="recovery",outcome="blocked")
    summary=coding_memory.operator_summary()
    assert result["target"]=={"scope":"host","host":"heim-pc"} and result["event_ids"]==[value["event_id"]]
    assert summary["counts_by_target"]=={"host:heim-pc":1}
    assert summary["counts_by_operation"]=={"recovery":1} and summary["counts_by_task_class"]=={"recovery":1}


def test_query_requires_exactly_one_target():
    with pytest.raises(ValueError,match="exactly one"): coding_memory.validate_query()
    with pytest.raises(ValueError,match="exactly one"): coding_memory.validate_query(repo="heimgewebe/example",host="heim-pc")


def test_query_binds_snapshot_and_freeze_rejects_invalid_ledger(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); coding_memory.import_events([event()]); target=tmp_path/"agent.ledger.jsonl"
    result=coding_memory.query_history(repo="heimgewebe/example")
    assert result["ledger_snapshot"]["sha256"]==hashlib.sha256(target.read_bytes()).hexdigest()
    assert result["ledger_snapshot"]["integrity_valid"] is True
    with target.open("ab") as handle: handle.write(b"not-json\n")
    degraded=coding_memory.query_history(repo="heimgewebe/example")
    assert degraded["event_ids"]==[event()["event_id"]] and degraded["ledger_snapshot"]["invalid_record_count"]==1
    with pytest.raises(ValueError,match="invalid records"): coding_memory.freeze_history(tmp_path/"bad.jsonl",repo="heimgewebe/example")


def test_additive_query_contracts_keep_v1_schema_ids(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); coding_memory.import_events([event()]); output=tmp_path/"cohort.jsonl"
    assert coding_memory.query_history(repo="heimgewebe/example")["schema_version"]=="chronik-coding-history.v1"
    assert coding_memory.operator_summary()["schema_version"]=="chronik-operator-summary.v1"
    assert coding_memory.freeze_history(output,repo="heimgewebe/example")["schema_version"]=="chronik-history-cohort-receipt.v1"


def test_query_cli_supports_host_target_without_creating_data_dir(tmp_path):
    import subprocess, sys
    missing=tmp_path/"missing"
    result=subprocess.run([sys.executable,str(Path(__file__).parents[1]/"tools"/"coding_memory.py"),"--data-dir",str(missing),"query","--host","heim-pc","--task-class","recovery"],text=True,capture_output=True)
    assert result.returncode==0,result.stderr
    assert json.loads(result.stdout)["target"]=={"scope":"host","host":"heim-pc"}
    assert not missing.exists()


def test_snapshot_hashes_original_invalid_utf8_bytes_without_collision(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); target=tmp_path/"agent.ledger.jsonl"
    first=b'{"payload":"\xff"}\n'; second=b'{"payload":"\xfe"}\n'
    target.write_bytes(first)
    first_result=coding_memory.query_history(repo="heimgewebe/example")
    target.write_bytes(second)
    second_result=coding_memory.query_history(repo="heimgewebe/example")
    first_snapshot=first_result["ledger_snapshot"]; second_snapshot=second_result["ledger_snapshot"]
    assert first_snapshot["sha256"]==hashlib.sha256(first).hexdigest()
    assert second_snapshot["sha256"]==hashlib.sha256(second).hexdigest()
    assert first_snapshot["sha256"]!=second_snapshot["sha256"]
    assert first_snapshot["invalid_record_count"]==second_snapshot["invalid_record_count"]==1
    assert first_snapshot["diagnostics"][0]["offset"]==0
    assert first_snapshot["diagnostics"][0]["next_offset"]==len(first)


def test_snapshot_excludes_incomplete_tail_but_includes_complete_corruption(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); coding_memory.import_events([event()]); target=tmp_path/"agent.ledger.jsonl"
    valid=target.read_bytes(); complete_corruption=b'not-json\n'; incomplete=b'partial-tail'
    target.write_bytes(valid+complete_corruption+incomplete)
    result=coding_memory.query_history(repo="heimgewebe/example")
    bounded=valid+complete_corruption; snapshot=result["ledger_snapshot"]
    assert snapshot["sha256"]==hashlib.sha256(bounded).hexdigest()
    assert snapshot["complete_bytes"]==len(bounded)
    assert snapshot["total_record_count"]==2
    assert snapshot["valid_record_count"]==1 and snapshot["invalid_record_count"]==1
    assert result["event_ids"]==[event()["event_id"]]


def test_query_uses_one_immutable_snapshot_even_if_file_grows_after_read(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); coding_memory.import_events([event()]); target=tmp_path/"agent.ledger.jsonl"
    original=storage.read_domain_snapshot; observed=target.read_bytes(); calls=[]
    def read_then_append(domain):
        calls.append(domain); snapshot=original(domain); target.write_bytes(snapshot+b'not-json\n'); return snapshot
    monkeypatch.setattr(storage,"read_domain_snapshot",read_then_append)
    result=coding_memory.query_history(repo="heimgewebe/example")
    assert calls==[coding_memory.DOMAIN]
    assert result["ledger_snapshot"]["sha256"]==hashlib.sha256(observed).hexdigest()
    assert result["ledger_snapshot"]["integrity_valid"] is True
    assert target.read_bytes()==observed+b'not-json\n'


def test_read_domain_snapshot_validates_offset_and_complete_boundary(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); target=tmp_path/"agent.ledger.jsonl"
    target.write_bytes(b'one\ntwo\npartial')
    assert storage.read_domain_snapshot(coding_memory.DOMAIN)==b'one\ntwo\n'
    assert storage.read_domain_snapshot(coding_memory.DOMAIN,4)==b'two\n'
    with pytest.raises(storage.StorageError,match="non-negative integer"):
        storage.read_domain_snapshot(coding_memory.DOMAIN,-1)
    with pytest.raises(storage.StorageError,match="non-negative integer"):
        storage.read_domain_snapshot(coding_memory.DOMAIN,True)


def test_snapshot_treats_only_lf_as_jsonl_record_boundary(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); target=tmp_path/"agent.ledger.jsonl"
    raw=b'bad\rstill-one-record\n'
    target.write_bytes(raw)
    result=coding_memory.query_history(repo="heimgewebe/example")
    snapshot=result["ledger_snapshot"]
    assert snapshot["sha256"]==hashlib.sha256(raw).hexdigest()
    assert snapshot["total_record_count"]==1
    assert snapshot["invalid_record_count"]==1
    assert snapshot["diagnostics"][0]["next_offset"]==len(raw)
