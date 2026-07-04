import json
from pathlib import Path

from tools import agent_ledger_review, chronik_outbox

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "agent-ledger" / "agent-run-completed.v0.json"


def load_event():
    with FIXTURE.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_review_summarizes_local_root(tmp_path):
    event = load_event()
    chronik_outbox.append_event(event, tmp_path)

    summary = agent_ledger_review.summarize(tmp_path)

    assert summary["event_count"] == 1
    assert summary["file_count"] == 1
    assert summary["repo_rows"] == 1
    assert summary["run_rows"] == 1
    assert summary["results"] == {"completed": 1}
    assert summary["receipt_count"] == 0
    assert summary["read_only"] is True


def test_markdown_contains_root_and_counts(tmp_path):
    event = load_event()
    chronik_outbox.append_event(event, tmp_path)
    summary = agent_ledger_review.summarize(tmp_path)

    rendered = agent_ledger_review.markdown([summary])

    assert "Agent Ledger Local Summary" in rendered
    assert tmp_path.name in rendered
    assert "completed:1" in rendered


def test_discover_finds_agent_run_roots(tmp_path):
    wanted = tmp_path / "agent-run-ledger-demo"
    ignored = tmp_path / "other"
    wanted.mkdir()
    ignored.mkdir()

    assert agent_ledger_review.discover(tmp_path) == [wanted]
