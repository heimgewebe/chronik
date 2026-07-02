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
