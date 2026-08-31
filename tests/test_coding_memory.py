import hashlib, importlib.util, json
from pathlib import Path
import pytest
import coding_memory, storage

def event(event_id="sha256:"+"a"*64, repo="heimgewebe/example", component="api", operation="implement", outcome="completed", ts="2026-07-13T10:00:00Z", source_component="grabowski"):
    return {"schema_version":"agent-run-event.v0","event_id":event_id,"kind":"agent.run.completed","ts":ts,"source":{"repo":"heimgewebe/grabowski","component":source_component,"run_id":"task-test-a1"},"subject":{"repo":repo,"component":component,"operation":operation,"bureau_task_id":"CCM-V1-T001","pr_number":1},"trust_tier":"observed","status":"active","caused_by":[],"evidence_refs":["grabowski-task:test"],"data":{"result":"completed","outcome":outcome}}

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


def test_query_history_works_when_data_directory_is_read_only(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    coding_memory.import_events([event()])
    target = tmp_path / "agent.ledger.jsonl"
    lock_path = storage.get_lock_path(target)
    if lock_path.exists():
        lock_path.unlink()
    original_mode = tmp_path.stat().st_mode & 0o777
    tmp_path.chmod(0o500)
    try:
        result = coding_memory.query_history(repo="heimgewebe/example")
    finally:
        tmp_path.chmod(original_mode)
    assert result["event_ids"] == ["sha256:" + "a" * 64]
    assert result["ledger_snapshot"]["integrity_valid"] is True
    assert not lock_path.exists()


def test_query_filters_and_marks_history_only(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); coding_memory.import_events([event(),event("sha256:"+"b"*64,repo="heimgewebe/other")])
    result=coding_memory.query_history(repo="heimgewebe/example",component="grabowski",operation="implement",outcome="completed")
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


def test_query_cli_subject_component_is_explicit_and_preserves_legacy_shape(tmp_path):
    import subprocess, sys
    missing = tmp_path / "missing"
    tool = str(Path(__file__).parents[1] / "tools" / "coding_memory.py")
    legacy = subprocess.run([sys.executable, tool, "--data-dir", str(missing), "query", "--repo", "heimgewebe/example"], text=True, capture_output=True)
    filtered = subprocess.run([sys.executable, tool, "--data-dir", str(missing), "query", "--repo", "heimgewebe/example", "--subject-component", "target-api"], text=True, capture_output=True)
    assert legacy.returncode == 0 and filtered.returncode == 0
    assert "subject_component" not in json.loads(legacy.stdout)["query"]
    assert json.loads(filtered.stdout)["query"]["subject_component"] == "target-api"
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


def test_query_component_uses_canonical_source_for_repository_target_and_combined_filters(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); value=event(component="target-api")
    value["data"]["task_class"]="coding"; coding_memory.import_events([value])
    result=coding_memory.query_history(repo="heimgewebe/example",component="grabowski",operation="implement",task_class="coding",outcome="completed")
    assert result["event_ids"]==[value["event_id"]]
    assert coding_memory.query_history(repo="heimgewebe/example",component="target-api")["event_ids"]==[]


def test_query_component_uses_canonical_source_for_host_target(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); value=event("sha256:"+"d"*64,component="target-runtime",operation="recovery",outcome="blocked")
    value["kind"]="agent.run.blocked"; value["subject"]={"scope":"host","host":"heim-pc","component":"target-runtime"}
    value["data"].update({"result":"blocked","operation":"recovery","task_class":"recovery"}); coding_memory.import_events([value])
    result=coding_memory.query_history(host="heim-pc",component="grabowski",operation="recovery",task_class="recovery",outcome="blocked")
    assert result["event_ids"]==[value["event_id"]]
    assert coding_memory.query_history(host="heim-pc",component="target-runtime")["event_ids"]==[]


def test_query_component_never_allows_subject_to_override_present_source(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); value=event(component="grabowski",source_component="other-producer")
    coding_memory.import_events([value])
    assert coding_memory.query_history(repo="heimgewebe/example",component="grabowski")["event_ids"]==[]
    assert coding_memory.query_history(repo="heimgewebe/example",component="other-producer")["event_ids"]==[value["event_id"]]


def test_query_subject_component_is_separate_from_source_component(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); value=event(component="target-api",source_component="grabowski")
    coding_memory.import_events([value])
    result=coding_memory.query_history(
        repo="heimgewebe/example",
        component="grabowski",
        subject_component="target-api",
    )
    assert result["event_ids"]==[value["event_id"]]
    assert result["query"]["component"]=="grabowski"
    assert result["query"]["subject_component"]=="target-api"
    assert coding_memory.query_history(repo="heimgewebe/example",subject_component="grabowski")["event_ids"]==[]


def test_query_subject_component_supports_host_targets(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); value=event("sha256:"+"e"*64,component="target-runtime",operation="recovery",outcome="blocked")
    value["kind"]="agent.run.blocked"; value["subject"]={"scope":"host","host":"heim-pc","component":"target-runtime"}
    value["data"].update({"result":"blocked","operation":"recovery","task_class":"recovery"}); coding_memory.import_events([value])
    assert coding_memory.query_history(host="heim-pc",subject_component="target-runtime")["event_ids"]==[value["event_id"]]
    assert coding_memory.query_history(host="heim-pc",subject_component="other")["event_ids"]==[]


def test_query_envelope_omits_subject_component_when_unused_for_v1_compatibility(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); coding_memory.import_events([event()])
    result=coding_memory.query_history(repo="heimgewebe/example",component="grabowski")
    assert "subject_component" not in result["query"]


def test_query_component_has_no_legacy_subject_fallback(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch); legacy=event(component="grabowski"); del legacy["source"]["component"]
    target=tmp_path/"agent.ledger.jsonl"; target.write_text(json.dumps({"payload":legacy})+"\n")
    result=coding_memory.query_history(repo="heimgewebe/example",component="grabowski")
    assert result["event_ids"]==[]
    assert result["ledger_snapshot"]["invalid_record_count"]==1
    assert result["ledger_snapshot"]["integrity_valid"] is False


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


def test_query_uses_one_immutable_snapshot_even_if_file_grows_during_scan(
    tmp_path, monkeypatch
):
    setup(tmp_path, monkeypatch)
    coding_memory.import_events([event()])
    target = tmp_path / "agent.ledger.jsonl"
    observed = target.read_bytes()
    original = storage.scan_domain_bytes
    calls = []

    def snapshot_forbidden(*_args, **_kwargs):
        raise AssertionError("history queries must not materialize a full domain snapshot")

    def scan_then_append(domain, start_offset=0):
        calls.append(domain)
        appended = False
        for item in original(domain, start_offset=start_offset):
            yield item
            if not appended:
                with target.open("ab") as handle:
                    handle.write(b"not-json\n")
                appended = True

    monkeypatch.setattr(storage, "read_domain_snapshot", snapshot_forbidden)
    monkeypatch.setattr(storage, "scan_domain_bytes", scan_then_append)
    result = coding_memory.query_history(repo="heimgewebe/example")

    assert calls == [coding_memory.DOMAIN]
    assert result["ledger_snapshot"]["sha256"] == hashlib.sha256(observed).hexdigest()
    assert result["ledger_snapshot"]["integrity_valid"] is True
    assert target.read_bytes() == observed + b"not-json\n"


def test_checkpoint_query_excludes_append_between_identity_and_validation_passes(
    tmp_path, monkeypatch
):
    setup(tmp_path, monkeypatch)
    coding_memory.import_events([event()])
    first = coding_memory.query_history(repo="heimgewebe/example")
    target = tmp_path / "agent.ledger.jsonl"
    observed = target.read_bytes()
    appended_event = event("sha256:" + "d" * 64)
    appended_line = coding_memory._envelope_lines([appended_event])[0].encode("utf-8") + b"\n"
    original_hash = storage.hash_domain_snapshot
    original_scan = storage.scan_domain_bytes
    calls = []

    def hash_then_append(domain, *, prefix_offset=None):
        calls.append("hash")
        result = original_hash(domain, prefix_offset=prefix_offset)
        with target.open("ab") as handle:
            handle.write(appended_line)
        return result

    def tracked_scan(domain, start_offset=0):
        calls.append("scan")
        yield from original_scan(domain, start_offset=start_offset)

    monkeypatch.setattr(storage, "hash_domain_snapshot", hash_then_append)
    monkeypatch.setattr(storage, "scan_domain_bytes", tracked_scan)
    second = coding_memory.query_history(repo="heimgewebe/example")

    assert calls == ["hash", "scan"]
    assert second["ledger_snapshot"] == first["ledger_snapshot"]
    assert second["event_ids"] == first["event_ids"]
    assert target.read_bytes() == observed + appended_line


def test_checkpoint_query_fails_closed_if_snapshot_changes_between_passes(
    tmp_path, monkeypatch
):
    setup(tmp_path, monkeypatch)
    coding_memory.import_events([event()])
    coding_memory.query_history(repo="heimgewebe/example")
    target = tmp_path / "agent.ledger.jsonl"
    original_bytes = target.read_bytes()
    changed = original_bytes.replace(
        b"heimgewebe/example", b"heimgewebe/examplf", 1
    )
    assert len(changed) == len(original_bytes) and changed != original_bytes
    checkpoint = tmp_path / coding_memory.HISTORY_VALIDATION_CHECKPOINT_FILENAME
    checkpoint_before = checkpoint.read_bytes()
    original_hash = storage.hash_domain_snapshot
    original_scan = storage.scan_domain_bytes
    calls = []

    def hash_then_change(domain, *, prefix_offset=None):
        calls.append("hash")
        result = original_hash(domain, prefix_offset=prefix_offset)
        target.write_bytes(changed)
        return result

    def tracked_scan(domain, start_offset=0):
        calls.append("scan")
        yield from original_scan(domain, start_offset=start_offset)

    monkeypatch.setattr(storage, "hash_domain_snapshot", hash_then_change)
    monkeypatch.setattr(storage, "scan_domain_bytes", tracked_scan)
    with pytest.raises(
        storage.StorageRecoveryError,
        match="history snapshot changed between checkpoint verification and validation",
    ):
        coding_memory.query_history(repo="heimgewebe/example")

    assert calls == ["hash", "scan"]
    assert checkpoint.read_bytes() == checkpoint_before


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


def test_history_validation_checkpoint_reuses_prefix_and_validates_only_append(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch)
    coding_memory.import_events([event(),event("sha256:"+"b"*64)])
    first=coding_memory.query_history(repo="heimgewebe/example")
    checkpoint=tmp_path/coding_memory.HISTORY_VALIDATION_CHECKPOINT_FILENAME
    assert checkpoint.is_file()
    assert checkpoint.stat().st_mode & 0o077 == 0
    original=coding_memory.validate_event; calls=[]
    def tracked(value):
        calls.append(value["event_id"]); return original(value)
    monkeypatch.setattr(coding_memory,"validate_event",tracked)
    second=coding_memory.query_history(repo="heimgewebe/example")
    assert second["ledger_snapshot"]==first["ledger_snapshot"]
    assert calls==[]
    coding_memory.import_events([event("sha256:"+"c"*64)])
    calls.clear()
    third=coding_memory.query_history(repo="heimgewebe/example")
    assert calls==["sha256:"+"c"*64]
    assert third["ledger_snapshot"]["integrity_valid"] is True


def test_history_validation_checkpoint_prefix_drift_forces_full_validation(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch)
    coding_memory.import_events([event(),event("sha256:"+"b"*64)])
    coding_memory.query_history(repo="heimgewebe/example")
    target=tmp_path/"agent.ledger.jsonl"
    raw=target.read_bytes()
    changed=raw.replace(b'heimgewebe/example',b'heimgewebe/examplf',1)
    assert len(changed)==len(raw) and changed!=raw
    target.write_bytes(changed)
    original=coding_memory.validate_event; calls=[]
    def tracked(value):
        calls.append(value["event_id"]); return original(value)
    monkeypatch.setattr(coding_memory,"validate_event",tracked)
    result=coding_memory.query_history(repo="heimgewebe/example")
    assert len(calls)==2
    assert result["ledger_snapshot"]["integrity_valid"] is True


def test_history_validation_checkpoint_corruption_falls_back_to_full_validation(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch)
    coding_memory.import_events([event(),event("sha256:"+"b"*64)])
    coding_memory.query_history(repo="heimgewebe/example")
    checkpoint=tmp_path/coding_memory.HISTORY_VALIDATION_CHECKPOINT_FILENAME
    checkpoint.write_bytes(b'{}\n')
    original=coding_memory.validate_event; calls=[]
    def tracked(value):
        calls.append(value["event_id"]); return original(value)
    monkeypatch.setattr(coding_memory,"validate_event",tracked)
    result=coding_memory.query_history(repo="heimgewebe/example")
    assert len(calls)==2
    assert result["ledger_snapshot"]["integrity_valid"] is True
    repaired=json.loads(checkpoint.read_text())
    assert repaired["checkpoint_sha256"]


def test_invalid_appended_record_does_not_advance_validation_checkpoint(tmp_path,monkeypatch):
    setup(tmp_path,monkeypatch)
    coding_memory.import_events([event()])
    coding_memory.query_history(repo="heimgewebe/example")
    checkpoint=tmp_path/coding_memory.HISTORY_VALIDATION_CHECKPOINT_FILENAME
    before=checkpoint.read_bytes()
    target=tmp_path/"agent.ledger.jsonl"
    with target.open("ab") as handle:
        handle.write(b'{"payload":{"schema_version":"agent-run-event.v0"}}\n')
    degraded=coding_memory.query_history(repo="heimgewebe/example")
    assert degraded["ledger_snapshot"]["invalid_record_count"]==1
    assert degraded["ledger_snapshot"]["integrity_valid"] is False
    assert checkpoint.read_bytes()==before
    with pytest.raises(ValueError,match="invalid records"):
        coding_memory.freeze_history(tmp_path/"bad-cache.jsonl",repo="heimgewebe/example")


def test_queries_keep_bounded_latest_candidates(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    values = [
        event(
            "sha256:" + format(index, "064x"),
            ts="2026-07-13T10:00:00Z",
        )
        for index in range(40)
    ]
    coding_memory.import_events(values)

    observed_heap_sizes = []
    retain_latest = coding_memory._retain_latest

    def track_heap(heap, **kwargs):
        retain_latest(heap, **kwargs)
        observed_heap_sizes.append((kwargs["limit"], len(heap)))

    monkeypatch.setattr(coding_memory, "_retain_latest", track_heap)
    history = coding_memory.query_history(repo="heimgewebe/example", limit=3)
    summary = coding_memory.operator_summary(limit=4)

    assert history["event_ids"] == [
        "sha256:" + format(index, "064x") for index in (39, 38, 37)
    ]
    assert [row["event_id"] for row in summary["recent"]] == [
        "sha256:" + format(index, "064x") for index in (39, 38, 37, 36)
    ]
    assert summary["event_count"] == 40
    assert observed_heap_sizes
    assert all(size <= limit for limit, size in observed_heap_sizes)


def test_operator_summary_count_remains_since_filtered_while_snapshot_count_is_total(
    tmp_path, monkeypatch
):
    setup(tmp_path, monkeypatch)
    coding_memory.import_events(
        [
            event(ts="2026-07-13T09:00:00Z"),
            event("sha256:" + "b" * 64, ts="2026-07-13T11:00:00Z"),
        ]
    )

    summary = coding_memory.operator_summary(since="2026-07-13T10:00:00Z")

    assert summary["event_count"] == 1
    assert summary["ledger_snapshot"]["total_record_count"] == 2
    assert [row["event_id"] for row in summary["recent"]] == [
        "sha256:" + "b" * 64
    ]


def test_equal_public_sort_keys_preserve_earlier_snapshot_order_at_limit(
    tmp_path, monkeypatch
):
    setup(tmp_path, monkeypatch)
    first = event()
    first["source"]["run_id"] = "first"
    second = event()
    second["source"]["run_id"] = "second"
    target = tmp_path / "agent.ledger.jsonl"
    target.write_text(
        json.dumps({"payload": first}) + "\n" + json.dumps({"payload": second}) + "\n",
        encoding="utf-8",
    )

    history = coding_memory.query_history(repo="heimgewebe/example", limit=1)
    summary = coding_memory.operator_summary(limit=1)

    assert history["events"][0]["source"]["run_id"] == "first"
    assert summary["recent"][0]["run_id"] == "first"


def test_queries_reuse_timestamp_parsed_during_validation(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    coding_memory.import_events(
        [
            event(),
            event("sha256:" + "b" * 64),
            event("sha256:" + "c" * 64),
        ]
    )
    parse_timestamp = coding_memory._parse_timestamp
    calls = []

    def counted_parse(value, *, field):
        calls.append((value, field))
        return parse_timestamp(value, field=field)

    monkeypatch.setattr(coding_memory, "_parse_timestamp", counted_parse)

    coding_memory.query_history(repo="heimgewebe/example")
    assert len(calls) == 3

    calls.clear()
    coding_memory.operator_summary()
    assert len(calls) == 3

def _load_coding_memory_cli():
    path = Path(__file__).parents[1] / "tools" / "coding_memory.py"
    spec = importlib.util.spec_from_file_location("chronik_coding_memory_cli_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cli_jsonl_loader_streams_without_whole_file_read(tmp_path, monkeypatch):
    cli = _load_coding_memory_cli()
    target = tmp_path / "events.jsonl"
    target.write_text('{"index":1}\n\n  {"index":2}  \n', encoding="utf-8")
    original_read_text = Path.read_text

    def guarded_read_text(path, *args, **kwargs):
        if path == target:
            raise AssertionError("JSONL input must not be materialized with Path.read_text")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    records = cli.load(target)
    assert iter(records) is records
    assert list(records) == [{"index": 1}, {"index": 2}]


def test_cli_jsonl_loader_treats_only_lf_as_record_boundary(tmp_path):
    cli = _load_coding_memory_cli()
    target = tmp_path / "events.jsonl"
    target.write_text(
        '{"text":"left\u2028right"}\n{"text":"next"}\n', encoding="utf-8"
    )

    assert list(cli.load(target)) == [
        {"text": "left\u2028right"},
        {"text": "next"},
    ]


def test_cli_regular_json_loader_keeps_existing_list_semantics(tmp_path):
    cli = _load_coding_memory_cli()
    object_path = tmp_path / "event.json"
    object_path.write_text('{"index":1}', encoding="utf-8")
    list_path = tmp_path / "events.json"
    list_path.write_text('[{"index":1},{"index":2}]', encoding="utf-8")
    empty_path = tmp_path / "empty.json"
    empty_path.write_text('  \n', encoding="utf-8")

    assert cli.load(object_path) == [{"index": 1}]
    assert cli.load(list_path) == [{"index": 1}, {"index": 2}]
    assert cli.load(empty_path) == []


def test_ledger_payload_index_streams_committed_records_without_snapshot(
    tmp_path, monkeypatch
):
    setup(tmp_path, monkeypatch)
    first = event()
    second = event("sha256:" + "b" * 64)
    coding_memory.import_events([first, second])

    def snapshot_forbidden(*_args, **_kwargs):
        raise AssertionError("ledger payload indexing must not materialize a full snapshot")

    monkeypatch.setattr(storage, "read_domain_snapshot", snapshot_forbidden)
    payloads, records_scanned = coding_memory._ledger_payloads_by_event_id()

    assert records_scanned == 2
    assert payloads[first["event_id"]] == coding_memory.canonical_bytes(first)
    assert payloads[second["event_id"]] == coding_memory.canonical_bytes(second)


def test_ledger_payload_index_treats_only_lf_as_record_boundary(
    tmp_path, monkeypatch
):
    setup(tmp_path, monkeypatch)
    first = json.dumps({"payload": event()}, separators=(",", ":")).encode("utf-8")
    second_event = event("sha256:" + "c" * 64)
    second = json.dumps({"payload": second_event}, separators=(",", ":")).encode("utf-8")
    (tmp_path / "agent.ledger.jsonl").write_bytes(first + b"\r" + second + b"\n")

    with pytest.raises(storage.StorageError, match="invalid ledger JSON at record 1"):
        coding_memory._ledger_payloads_by_event_id()


def v1_event(result="failed", event_id="sha256:"+"f"*64):
    value = event(event_id=event_id, outcome=result)
    value["schema_version"] = "agent-run-event.v1"
    value["kind"] = f"agent.run.{result}"
    value["data"]["result"] = result
    if result == "blocked":
        value["data"]["blocker_code"] = "authority-unavailable"
    return value


def test_v1_execution_failure_is_not_counted_as_blocked(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    value = v1_event("failed")
    coding_memory.import_events([value])
    history = coding_memory.query_history(repo="heimgewebe/example", outcome="failed")
    summary = coding_memory.operator_summary()
    assert history["event_ids"] == [value["event_id"]]
    assert summary["counts_by_kind"] == {"agent.run.failed": 1}
    assert summary["blocked_by_code"] == {}


def test_v1_supports_execution_failure_terminal_kinds(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    values = [
        v1_event("cancelled", "sha256:"+"1"*64),
        v1_event("timed_out", "sha256:"+"2"*64),
        v1_event("signalled", "sha256:"+"3"*64),
    ]
    coding_memory.import_events(values)
    for result, value in zip(("cancelled", "timed_out", "signalled"), values):
        assert coding_memory.query_history(
            repo="heimgewebe/example", outcome=result
        )["event_ids"] == [value["event_id"]]
    assert set(coding_memory.GRABOWSKI_TERMINAL_KINDS) >= {
        "agent.run.cancelled", "agent.run.timed_out", "agent.run.signalled"
    }


def test_v1_blocked_requires_code_and_nonblocked_rejects_code():
    blocked = v1_event("blocked")
    coding_memory.validate_event(blocked)
    missing = v1_event("blocked", "sha256:"+"4"*64)
    missing["data"].pop("blocker_code")
    with pytest.raises(ValueError, match="requires blocker_code"):
        coding_memory.validate_event(missing)
    failed = v1_event("failed", "sha256:"+"5"*64)
    failed["data"]["blocker_code"] = "not-a-real-blocker"
    with pytest.raises(ValueError, match="must not carry blocker_code"):
        coding_memory.validate_event(failed)


def test_v0_blocked_history_remains_valid_after_v1_addition(tmp_path, monkeypatch):
    setup(tmp_path, monkeypatch)
    value = event(outcome="blocked")
    value["kind"] = "agent.run.blocked"
    value["data"].update({"result": "blocked", "blocker_code": "legacy-task-failed"})
    coding_memory.import_events([value])
    assert coding_memory.query_history(
        repo="heimgewebe/example", outcome="blocked"
    )["event_ids"] == [value["event_id"]]
