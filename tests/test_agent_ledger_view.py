import json
from pathlib import Path

from tools import agent_ledger_view

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "agent-ledger"


def load_fixture(name: str):
    with (FIXTURE_DIR / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_build_view_uses_latest_event_per_repo():
    started = load_fixture("agent-run-started.v0.json")
    completed = load_fixture("agent-run-completed.v0.json")

    rows = agent_ledger_view.build_view([completed, started])

    assert len(rows) == 1
    assert rows[0].repo == "heimgewebe/chronik"
    assert rows[0].branch == "docs/agent-run-v0"
    assert rows[0].result == "completed"
    assert rows[0].evidence_ref == "github-pr:heimgewebe/chronik#193"
    assert rows[0].ts == "2026-07-02T12:05:00Z"


def test_build_view_accepts_chronik_envelope_records():
    blocked = load_fixture("agent-run-blocked.v0.json")
    rows = agent_ledger_view.build_view([{"domain": "agent.ledger", "payload": blocked}])

    assert len(rows) == 1
    assert rows[0].result == "blocked"
    assert rows[0].blocker_code == "missing-consumer-view"


def test_build_view_ignores_non_agent_records():
    assert agent_ledger_view.build_view([{"payload": {"kind": "not.agent"}}]) == []


def test_load_records_accepts_v1_events_response(tmp_path):
    completed = load_fixture("agent-run-completed.v0.json")
    path = tmp_path / "events.json"
    path.write_text(json.dumps({"events": [{"payload": completed}]}), encoding="utf-8")

    rows = agent_ledger_view.build_view(agent_ledger_view.load_records(path))

    assert len(rows) == 1
    assert rows[0].result == "completed"


def test_load_records_accepts_jsonl_envelopes(tmp_path):
    started = load_fixture("agent-run-started.v0.json")
    completed = load_fixture("agent-run-completed.v0.json")
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({"payload": started}) + "\n" + json.dumps({"payload": completed}) + "\n", encoding="utf-8")

    rows = agent_ledger_view.build_view(agent_ledger_view.load_records(path))

    assert len(rows) == 1
    assert rows[0].result == "completed"


def test_format_table_contains_expected_columns():
    row = agent_ledger_view.AgentRunViewRow(
        repo="heimgewebe/chronik",
        branch="main",
        result="blocked",
        blocker_code="missing-consumer-view",
        evidence_ref="local-run:1",
        ts="2026-07-02T12:10:00Z",
    )

    rendered = agent_ledger_view.format_table([row])

    assert "repo" in rendered
    assert "blocker_code" in rendered
    assert "heimgewebe/chronik" in rendered
    assert "missing-consumer-view" in rendered


def with_run(event, run_id, ts, result, kind=None, blocker_code=""):
    copied = json.loads(json.dumps(event))
    copied["source"]["run_id"] = run_id
    copied["ts"] = ts
    copied["data"] = {"result": result}
    if blocker_code:
        copied["data"]["blocker_code"] = blocker_code
    if kind is not None:
        copied["kind"] = kind
    return copied


def test_build_run_view_keeps_distinct_runs_for_one_repo():
    started = load_fixture("agent-run-started.v0.json")
    completed = load_fixture("agent-run-completed.v0.json")
    blocked = load_fixture("agent-run-blocked.v0.json")
    records = [
        with_run(started, "run-a", "2026-07-02T12:00:00Z", "started"),
        with_run(completed, "run-a", "2026-07-02T12:01:00Z", "completed"),
        with_run(started, "run-b", "2026-07-02T12:02:00Z", "started"),
        with_run(blocked, "run-b", "2026-07-02T12:03:00Z", "blocked", blocker_code="task-failed"),
    ]

    repo_rows = agent_ledger_view.build_view(records)
    run_rows = agent_ledger_view.build_run_view(records)

    assert len(repo_rows) == 1
    assert repo_rows[0].result == "blocked"
    assert len(run_rows) == 2
    assert [(row.run_id, row.result) for row in run_rows] == [
        ("run-a", "completed"),
        ("run-b", "blocked"),
    ]
    assert run_rows[1].blocker_code == "task-failed"


def test_run_view_table_includes_run_id_column():
    completed = load_fixture("agent-run-completed.v0.json")
    row = agent_ledger_view.build_run_view([completed])[0]

    rendered = agent_ledger_view.format_table([row])

    assert "run_id" in rendered
    assert completed["source"]["run_id"] in rendered
