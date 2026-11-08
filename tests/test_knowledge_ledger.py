from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

import knowledge_ledger as k
import storage


@pytest.fixture
def paths(tmp_path: Path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    outbox = tmp_path / "outbox"
    monkeypatch.setattr(storage, "DATA_DIR", data)
    return data, outbox


def event(key="analysis:1", *, knowledge_type="root_cause",
          epistemic_status="confirmed", relations=None, statement=None):
    return k.build(
        record_key=key, ts="2026-11-07T20:00:00Z",
        source={"system": "heimgewebe/grabowski", "component": "analysis"},
        subject={"repo": "heimgewebe/chronik", "component": "outbox"},
        knowledge_type=knowledge_type, epistemic_status=epistemic_status,
        statement=statement or "The confirmed failure was caused by a missing persistent receipt.",
        evidence_refs=["grabowski-task:0123456789abcdef"],
        relations=relations or [],
    )


def test_A_confirmed_cause_capture_import_and_exact_readback(paths):
    data, outbox = paths
    value = event()
    receipt = k.capture(value, outbox)
    assert receipt["queued"] and not receipt["ledger_verified"]
    result = k.import_pending(outbox, data)
    assert result["imported"] == 1 and result["verified"] == 1
    found = k.get(value["event_id"])
    assert found["found"] and found["event"] == value
    assert found["ledger_snapshot"]["integrity_valid"]
    assert len(found["ledger_snapshot"]["sha256"]) == 64


def test_B_refuted_hypothesis_preserved_with_relation(paths):
    data, outbox = paths
    old = event("repair:proposal", knowledge_type="repair", epistemic_status="hypothesis")
    refuted = event(
        "repair:countertest", knowledge_type="refutation", epistemic_status="refuted",
        relations=[{"type": "refutes", "event_id": old["event_id"]}])
    for value in (old, refuted):
        k.capture(value, outbox)
    assert k.import_pending(outbox, data)["verified"] == 2
    assert k.get(old["event_id"])["found"]
    assert k.get(refuted["event_id"])["event"]["relations"][0]["event_id"] == old["event_id"]


def test_C_fix_tests_are_not_automatically_production_verified(paths):
    data, outbox = paths
    value = event("fix:tested", knowledge_type="repair", epistemic_status="implemented")
    k.capture(value, outbox)
    k.import_pending(outbox, data)
    assert k.get(value["event_id"])["event"]["epistemic_status"] == "implemented"


def test_D_user_decision_with_explicit_provenance(paths):
    data, outbox = paths
    value = k.build(
        record_key="decision:user:0001", ts="2026-11-07T20:00:00+00:00",
        source={"system": "chatgpt", "component": "user-explicit-decision"},
        subject={"repo": "heimgewebe/commonthing"},
        knowledge_type="decision", epistemic_status="decided",
        statement="A user decision is historical evidence, not a deployment receipt.",
        evidence_refs=["user-decision:explicit:0001"])
    k.capture(value, outbox)
    assert k.import_pending(outbox, data)["verified"] == 1


def test_E_irrelevant_work_has_no_automatic_semantic_capture(paths):
    data, outbox = paths
    result = k.coverage(outbox, data)
    assert result["verified"] == result["pending"] == result["invalid"] == []


def test_F_chronik_outage_retains_pending_and_recovers(paths):
    data, outbox = paths
    value = event("outage:1")
    k.capture(value, outbox)
    with pytest.raises(ValueError, match="unavailable"):
        k.import_pending(outbox, data / "missing")
    assert k.coverage(outbox, data)["pending"] == [value["event_id"]]
    assert k.import_pending(outbox, data)["verified"] == 1
    assert k.coverage(outbox, data)["pending"] == []


def test_G_identical_repeated_capture_and_import_is_idempotent(paths):
    data, outbox = paths
    value = event("duplicate:1")
    assert k.capture(value, outbox)["new"]
    assert not k.capture(value, outbox)["new"]
    first = k.import_pending(outbox, data)
    second = k.import_pending(outbox, data)
    assert first["imported"] == 1 and second["imported"] == 0
    assert second["verified"] == 1
    assert k.get(value["event_id"])["ledger_snapshot"]["record_count"] == 1
    modified = dict(value, statement="Contradiction under the same stable identity.")
    with pytest.raises(ValueError, match="different payload"):
        k.capture(modified, outbox)


def test_H_superseded_relation_keeps_old_and_new_history(paths):
    data, outbox = paths
    old = event("prior:1", knowledge_type="observation", epistemic_status="observed")
    new = event(
        "prior:2", epistemic_status="confirmed",
        relations=[{"type": "supersedes", "event_id": old["event_id"]}])
    k.capture(old, outbox)
    k.capture(new, outbox)
    k.import_pending(outbox, data)
    old_read = k.get(old["event_id"])
    assert old_read["found"] and old_read["superseded_by"] == [new["event_id"]]
    assert k.get(new["event_id"])["found"]


@pytest.mark.parametrize("secret", [
    "api_key=abc123456",
    "Bearer abcdefghijklmnopqrstuvwxyz",
    "ghp_" + "z"*30,
    "-----BEGIN PRIVATE KEY-----",
])
def test_I_private_raw_credentials_refused(paths, secret):
    data, outbox = paths
    with pytest.raises(ValueError):
        event("private:1", statement="Credential: " + secret)
    assert k.coverage(outbox, data)["verified"] == []


def test_write_failure_is_a_visible_gap_without_blind_success(paths, monkeypatch):
    data, outbox = paths
    value = event("busy:1")
    k.capture(value, outbox)
    real = storage.write_payload_unique

    def unavailable(*args, **kwargs):
        raise storage.StorageBusyError("offline")

    monkeypatch.setattr(storage, "write_payload_unique", unavailable)
    failed = k.import_pending(outbox, data)
    assert failed["verified"] == 0 and failed["errors"]
    assert k.coverage(outbox, data)["pending"] == [value["event_id"]]
    monkeypatch.setattr(storage, "write_payload_unique", real)
    assert k.import_pending(outbox, data)["verified"] == 1


def test_malformed_or_uncertain_event_does_not_fake_success(paths):
    data, outbox = paths
    value = event("invalid:1")
    k.capture(value, outbox)
    target = outbox / "knowledge" / (value["event_id"][7:] + ".json")
    target.write_text('{"invalid":true}\n', encoding="utf-8")
    result = k.import_pending(outbox, data)
    assert result["errors"] and result["verified"] == 0
    assert k.coverage(outbox, data)["invalid"] == [target.name]


def test_identity_mismatch_rejected_without_ledger_write(paths):
    data, outbox = paths
    value = event("event:id")
    value["event_id"] = "sha256:" + "a"*64
    with pytest.raises(ValueError, match="event_id"):
        k.capture(value, outbox)
    assert k.coverage(outbox, data)["pending"] == []


def test_event_schema_accepts_bounded_record():
    schema = json.loads(
        (Path(__file__).parents[1] / "docs/chronik/knowledge-event-v1.schema.json").read_text())
    Draft7Validator.check_schema(schema)
    Draft7Validator(schema).validate(event("contract:test"))


def test_secret_in_evidence_ref_is_not_accepted():
    value = event("source:1")
    value["evidence_refs"] = ["api_key=supersecret123"]
    with pytest.raises(ValueError):
        k.validate(value)

def test_J_CLI_round_trip_on_independent_process(paths, tmp_path):
    import subprocess
    import sys
    data, outbox = paths
    root = Path(__file__).parents[1]
    source = tmp_path / "minimized.json"
    value = event("cli:crossprocess")
    body = {key: value[key] for key in (
        "record_key", "ts", "source", "subject",
        "knowledge_type", "epistemic_status", "statement",
        "evidence_refs", "relations"
    )}
    source.write_text(json.dumps(body), encoding="utf-8")
    base = [sys.executable, str(root / "tools/knowledge_ledger.py"),
            "--data-dir", str(data), "--outbox-root", str(outbox)]
    capture = subprocess.run(
        base + ["capture", "--record", str(source)],
        capture_output=True, text=True, check=True)
    assert json.loads(capture.stdout)["event_id"] == value["event_id"]
    importer = subprocess.run(
        base + ["import-pending"], capture_output=True, text=True, check=True)
    assert json.loads(importer.stdout)["verified"] == 1
    readback = subprocess.run(
        base + ["get", "--event-id", value["event_id"]],
        capture_output=True, text=True, check=True)
    assert json.loads(readback.stdout)["event"] == value
    covered = subprocess.run(
        base + ["coverage"], capture_output=True, text=True, check=True)
    assert json.loads(covered.stdout)["verified"] == [value["event_id"]]

def test_import_uncertain_after_durable_append_resolves_by_readback(paths, monkeypatch):
    data, outbox = paths
    value = event("uncertain:committed")
    k.capture(value, outbox)
    original = storage.write_payload_unique

    def write_then_report_uncertain(*args, **kwargs):
        original(*args, **kwargs)
        raise storage.StorageRecoveryError("post-commit outcome unknown")

    monkeypatch.setattr(storage, "write_payload_unique", write_then_report_uncertain)
    result = k.import_pending(outbox, data)
    assert result["verified"] == 1 and result["errors"] == []
    assert result["resolved_after_uncertain_write"] == [value["event_id"]]
    assert k.get(value["event_id"])["ledger_snapshot"]["record_count"] == 1


def test_search_targeted_and_supersession_in_results(paths):
    data, outbox = paths
    old = event("search:old", knowledge_type="open_problem",
                epistemic_status="observed", statement="Import receipt missing.")
    new = event("search:new", knowledge_type="repair",
                epistemic_status="confirmed", statement="Import receipt restored.",
                relations=[{"type": "supersedes", "event_id": old["event_id"]}])
    for value in (old, new):
        k.capture(value, outbox)
    k.import_pending(outbox, data)
    result = k.search(repo="heimgewebe/chronik", keyword="Import receipt")
    assert result["matching_count"] == 2
    found = {x["event"]["event_id"]: x for x in result["events"]}
    assert found[old["event_id"]]["superseded_by"] == [new["event_id"]]
    assert found[new["event_id"]]["superseded_by"] == []
    assert result["ledger_snapshot"]["integrity_valid"]
    with pytest.raises(ValueError, match="selector"):
        k.search()


def test_search_keeps_every_superseding_branch_even_when_filter_hides_them(paths):
    data, outbox = paths
    old = event("branch:old", knowledge_type="open_problem",
                epistemic_status="observed")
    first = event("branch:first", knowledge_type="repair",
                  epistemic_status="implemented",
                  relations=[{"type": "supersedes", "event_id": old["event_id"]}])
    second = event("branch:second", knowledge_type="repair",
                   epistemic_status="confirmed",
                   relations=[{"type": "supersedes", "event_id": old["event_id"]}])
    first["ts"] = "2026-11-07T20:00:00+02:00"
    second["ts"] = "2026-11-07T19:00:00Z"
    for item in (old, first, second):
        assert k.capture(item, outbox)["queued"]
    assert k.import_pending(outbox, data)["verified"] == 3
    result = k.search(repo="heimgewebe/chronik",
                      knowledge_type="open_problem", limit=1)
    assert result["matching_count"] == result["returned"] == 1
    assert result["events"][0]["event"]["event_id"] == old["event_id"]
    assert result["events"][0]["superseded_by"] == [
        second["event_id"], first["event_id"]
    ]
    assert set(k.get(old["event_id"])["superseded_by"]) == {
        first["event_id"], second["event_id"]
    }


def test_read_rejects_outbox_symlink(paths):
    data, outbox = paths
    value = event("symlink:1")
    root = outbox / "knowledge"
    root.mkdir(parents=True, exist_ok=True)
    target = data / "foreign.txt"
    target.write_text("private", encoding="utf-8")
    (root / (value["event_id"][7:] + ".json")).symlink_to(target)
    with pytest.raises((ValueError, OSError)):
        k.capture(value, outbox)
    result = k.coverage(outbox, data)
    assert result["verified"] == []
    assert len(result["invalid"]) == 1

def test_existing_outbox_import_command_also_imports_knowledge(paths, tmp_path,
                                                                monkeypatch, capsys):
    from tools import coding_memory as cli
    data, _ = paths
    root = tmp_path / "state"
    outbox = root / "grabowski" / "chronik-outbox"
    value = event("timer:integration")
    k.capture(value, outbox)

    monkeypatch.setattr(cli.coding_memory, "import_grabowski_outbox",
                        lambda **kw: {"schema_version": "agent-outbox.v2",
                                      "errors": [], "historical_only": True})
    code = cli.main(["--data-dir", str(data), "import-outbox",
                     "--outbox-root", str(root), "--output-mode", "summary"])
    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert output["knowledge_verified"] == 1
    assert output["knowledge_imported"] == 1
    assert output["knowledge_pending"] == 0
    assert k.get(value["event_id"])["found"]


def test_existing_outbox_import_surfaces_knowledge_error(paths, tmp_path,
                                                         monkeypatch, capsys):
    from tools import coding_memory as cli
    data, _ = paths
    root = tmp_path / "state"
    monkeypatch.setattr(cli.coding_memory, "import_grabowski_outbox",
                        lambda **kw: {"schema_version": "agent-outbox.v2",
                                      "errors": [], "historical_only": True})
    def offline(*args, **kwargs):
        raise storage.StorageBusyError("knowledge storage inaccessible")

    monkeypatch.setattr(cli.knowledge_ledger, "import_pending", offline)
    code = cli.main(["--data-dir", str(data), "import-outbox",
                     "--outbox-root", str(root), "--output-mode", "summary"])
    output = json.loads(capsys.readouterr().out)
    assert code == 2
    assert output["knowledge_error_count"] == 1
    assert output["error_count"] == 1
    assert output["knowledge_pending"] is None

def test_import_more_than_budget_makes_progress_across_cycles(paths):
    data, outbox = paths
    values = [event(f"backlog:{n:04d}") for n in range(205)]
    for value in values:
        k.capture(value, outbox)
    first = k.import_pending(outbox, data, max_events=200)
    assert first["imported"] == 200
    assert first["pending"] == 5
    second = k.import_pending(outbox, data, max_events=200)
    assert second["imported"] == 5
    assert second["pending"] == 0
    assert second["verified"] == 205
    assert second["ledger_snapshot"]["record_count"] == 205
    third = k.import_pending(outbox, data, max_events=200)
    assert third["imported"] == 0 and third["pending"] == 0


@pytest.mark.parametrize("attribute,invalid", [
    ("evidence_refs", [{}]),
    ("knowledge_type", {"bad": True}),
    ("epistemic_status", []),
    ("relations", [{"type": ["supersedes"], "event_id": "sha256:" + "a"*64}]),
])
def test_malformed_unhashable_inputs_become_visible_per_event_gaps(paths, attribute, invalid):
    data, outbox = paths
    bad = event("unhashable:" + attribute)
    bad[attribute] = invalid
    root = outbox / "knowledge"
    root.mkdir(parents=True, exist_ok=True)
    (root / (bad["event_id"][7:] + ".json")).write_text(json.dumps(bad) + "\n")
    good = event("unhashable:valid")
    k.capture(good, outbox)
    imported = k.import_pending(outbox, data)
    assert imported["errors"] and imported["verified"] == 1
    assert k.get(good["event_id"])["found"]
    covered = k.coverage(outbox, data)
    assert covered["invalid"] and covered["verified"] == [good["event_id"]]


def test_search_orders_absolute_instant_not_timezone_text(paths):
    data, outbox = paths
    older = k.build(
        record_key="timezone:older", ts="2026-11-07T20:00:00+02:00",
        source={"system": "heimgewebe/grabowski", "component": "analysis"},
        subject={"repo": "heimgewebe/chronik"},
        knowledge_type="observation", epistemic_status="observed",
        statement="First observation with later clock text.",
        evidence_refs=["grabowski-task:time-old"])
    newer = k.build(
        record_key="timezone:newer", ts="2026-11-07T19:00:00Z",
        source={"system": "heimgewebe/grabowski", "component": "analysis"},
        subject={"repo": "heimgewebe/chronik"},
        knowledge_type="observation", epistemic_status="observed",
        statement="Later observation with earlier clock text.",
        evidence_refs=["grabowski-task:time-new"])
    for item in (older, newer):
        k.capture(item, outbox)
    assert k.import_pending(outbox, data)["imported"] == 2
    result = k.search(repo="heimgewebe/chronik", limit=1)
    assert result["events"][0]["event"]["event_id"] == newer["event_id"]
    assert result["has_more"] is True

def test_real_timer_entrypoint_imports_knowledge_without_monkeypatch(paths, tmp_path):
    import subprocess
    import sys
    data, _ = paths
    state = tmp_path / "whole-state"
    root = state / "grabowski" / "chronik-outbox"
    wanted = event("timer:actual-entrypoint")
    k.capture(wanted, root)
    tool = Path(__file__).parents[1] / "tools" / "coding_memory.py"
    cmd = [sys.executable, str(tool), "--data-dir", str(data), "import-outbox",
           "--outbox-root", str(state), "--receipt-dir", str(data / "receipts"),
           "--output-mode", "summary"]
    first = subprocess.run(cmd, check=True, capture_output=True, text=True)
    summary = json.loads(first.stdout)
    assert summary["knowledge_imported"] == 1
    assert summary["knowledge_verified"] == 1
    assert summary["knowledge_error_count"] == 0
    assert k.get(wanted["event_id"])["found"]
    second = subprocess.run(cmd, check=True, capture_output=True, text=True)
    summary2 = json.loads(second.stdout)
    assert summary2["knowledge_imported"] == 0
    assert summary2["knowledge_verified"] == 1
    assert k.coverage(root, data)["pending"] == []


def test_subject_component_unicode_spaces_roundtrip(paths):
    data, outbox = paths
    value = k.build(
        record_key="component:unicode", ts="2026-11-08T06:40:00Z",
        source={"system": "heimgewebe/grabowski", "component": "task-terminalization"},
        subject={"repo": "heimgewebe/chronik", "component": "deploy worker – München"},
        knowledge_type="operation", epistemic_status="observed",
        statement="The task was observed; production is not verified.",
        evidence_refs=["grabowski-task:0123456789abcdef01234567"],
    )
    assert k.capture(value, outbox)["new"]
    receipt = k.import_pending(outbox, data)
    assert receipt["verified"] == 1
    assert k.get(value["event_id"])["event"]["subject"]["component"] == "deploy worker – München"


@pytest.mark.parametrize("component", [" bad", "bad ", "bad" + chr(10) + "name", "bad" + chr(127) + "name", "a"*161])
def test_invalid_component_never_enters_ledger(paths, component):
    data, outbox = paths
    with pytest.raises(ValueError, match="component"):
        k.build(
            record_key="component:invalid", ts="2026-11-08T06:40:00Z",
            source={"system": "heimgewebe/grabowski", "component": "task-terminalization"},
            subject={"repo": "heimgewebe/chronik", "component": component},
            knowledge_type="operation", epistemic_status="observed",
            statement="Invalid component must be rejected.",
            evidence_refs=["grabowski-task:0123456789abcdef01234567"],
        )
    assert k.coverage(outbox, data)["verified"] == []

@pytest.mark.parametrize("failed_sync_number", [1, 2])
def test_capture_existing_reestablishes_durability_after_uncertain_fsync(
        paths, monkeypatch, failed_sync_number):
    data, outbox = paths
    value = event(f"fsync:uncertain:{failed_sync_number}")
    real_fsync = k.os.fsync
    calls = 0

    def interrupted_fsync(fd):
        nonlocal calls
        calls += 1
        if calls == failed_sync_number:
            raise OSError("simulated initial fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(k.os, "fsync", interrupted_fsync)
    with pytest.raises(OSError, match="simulated initial"):
        k.capture(value, outbox)
    path = outbox / "knowledge" / (value["event_id"][7:] + ".json")
    assert path.read_bytes() == k.canonical(value) + b"\n"

    # The same visible bytes are NOT durable merely because they exist.
    def still_unsynced(fd):
        raise OSError("simulated retry fsync failure")

    monkeypatch.setattr(k.os, "fsync", still_unsynced)
    with pytest.raises(OSError, match="simulated retry"):
        k.capture(value, outbox)

    sync_calls = []
    def successful_fsync(fd):
        sync_calls.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(k.os, "fsync", successful_fsync)
    second = k.capture(value, outbox)
    assert second["queued"] and second["new"] is False
    assert second["ledger_verified"] is False
    assert len(sync_calls) >= 2  # file plus every containing directory
    assert k.import_pending(outbox, data)["verified"] == 1


def test_fifo_outbox_entry_is_rejected_nonblocking_without_stalling_import(
        paths, monkeypatch):
    import os
    data, outbox = paths
    bad = event("fifo:no-writer")
    fifo = outbox / "knowledge" / (bad["event_id"][7:] + ".json")
    fifo.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(fifo)
    valid = event("fifo:valid")
    k.capture(valid, outbox)

    real_open = k.os.open

    def guarded_open(path, flags, *args, **kwargs):
        # Fails promptly instead of hanging on the regression.
        if os.fspath(path) == os.fspath(fifo) and not flags & os.O_NONBLOCK:
            raise AssertionError("FIFO read would block without O_NONBLOCK")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(k.os, "open", guarded_open)
    result = k.import_pending(outbox, data)
    assert result["verified"] == 1 and result["imported"] == 1
    assert result["errors"] == [{"event_id": fifo.stem, "error": "ValueError"}]
    assert k.get(valid["event_id"])["found"]
    covered = k.coverage(outbox, data)
    assert covered["invalid"] == [fifo.name]
    assert covered["verified"] == [valid["event_id"]]


def test_first_outbox_creation_persists_ancestor_entries_and_replay(paths, monkeypatch):
    import os
    data, outbox = paths
    value = event("fsync:ancestor-first-capture")
    assert not outbox.exists()

    original_fsync = k.os.fsync
    synced = []

    def observe_fsync(fd):
        synced.append(os.readlink(f"/proc/self/fd/{fd}"))
        return original_fsync(fd)

    monkeypatch.setattr(k.os, "fsync", observe_fsync)
    first = k.capture(value, outbox)
    entry = outbox / "knowledge" / (value["event_id"][7:] + ".json")
    assert first["queued"] and first["new"]
    assert str(entry) in synced
    assert str(outbox / "knowledge") in synced
    assert str(outbox) in synced
    assert str(outbox.parent) in synced  # newly created outbox/ persisted
    assert k.import_pending(outbox, data)["verified"] == 1
    assert k.get(value["event_id"])["found"]

    # Fail while persisting the newly created directory entry, after the file
    # is visible. A retry must NOT acknowledge it without re-synchronization.
    second_outbox = outbox.parent / "crash-outbox"
    second_value = event("fsync:ancestor-replay")
    real_fsync = k.os.fsync
    failed = False

    def fail_ancestor_once(fd):
        nonlocal failed
        actual = os.readlink(f"/proc/self/fd/{fd}")
        if actual == str(second_outbox.parent) and not failed:
            failed = True
            raise OSError("new directory parent fsync uncertain")
        return original_fsync(fd)

    monkeypatch.setattr(k.os, "fsync", fail_ancestor_once)
    with pytest.raises(OSError, match="parent fsync uncertain"):
        k.capture(second_value, second_outbox)
    assert failed
    entry2 = second_outbox / "knowledge" / (second_value["event_id"][7:] + ".json")
    assert entry2.is_file()

    replay_syncs = []
    def observe_replay(fd):
        replay_syncs.append(os.readlink(f"/proc/self/fd/{fd}"))
        return original_fsync(fd)

    monkeypatch.setattr(k.os, "fsync", observe_replay)
    replay = k.capture(second_value, second_outbox)
    assert replay["queued"] and replay["new"] is False
    assert str(entry2) in replay_syncs
    assert str(second_outbox) in replay_syncs
    assert str(second_outbox.parent) in replay_syncs
    assert k.import_pending(second_outbox, data)["verified"] == 1
