import json
from pathlib import Path

import pytest

from tools import chronik_outbox

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "agent-ledger" / "agent-run-completed.v0.json"


def load_event():
    with FIXTURE.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_append_event_writes_one_run_file(tmp_path):
    event = load_event()
    path = chronik_outbox.append_event(event, tmp_path)

    assert path == tmp_path / "grabowski" / "chronik-outbox" / "grabowski_run-20260702-120000.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["kind"] == "agent.run.completed"


def test_append_event_rejects_invalid_payload(tmp_path):
    event = load_event()
    event["data"]["raw"] = "no"

    with pytest.raises(Exception):
        chronik_outbox.append_event(event, tmp_path)


def test_status_reports_pending_file(tmp_path):
    event = load_event()
    path = chronik_outbox.append_event(event, tmp_path)

    entries = chronik_outbox.status(tmp_path)

    assert len(entries) == 1
    assert entries[0].path == path
    assert entries[0].events == 1
    assert entries[0].bytes > 0
    assert entries[0].flushed is False


def test_flush_file_posts_agent_ledger_domain_and_writes_receipt(tmp_path):
    event = load_event()
    path = chronik_outbox.append_event(event, tmp_path)
    calls = []

    def fake_sender(url, payload, token, timeout):
        calls.append((url, payload, token, timeout))
        return 202, "ok"

    receipt = chronik_outbox.flush_file(
        path,
        base_url="http://chronik.test",
        token="secret",
        timeout=1.5,
        sender=fake_sender,
    )

    assert receipt.exists()
    assert calls[0][0] == "http://chronik.test/v1/ingest?domain=agent.ledger"
    assert calls[0][1][0]["kind"] == "agent.run.completed"
    assert calls[0][2] == "secret"
    assert calls[0][3] == 1.5
    receipt_body = json.loads(receipt.read_text(encoding="utf-8"))
    assert receipt_body["domain"] == "agent.ledger"
    assert receipt_body["event_count"] == 1


def test_compact_removes_flushed_files_only(tmp_path):
    event = load_event()
    path = chronik_outbox.append_event(event, tmp_path)
    chronik_outbox.flush_file(
        path,
        base_url="http://chronik.test",
        token="secret",
        sender=lambda url, payload, token, timeout: (202, "ok"),
    )

    removed = chronik_outbox.compact(tmp_path)

    assert removed == [path]
    assert not path.exists()
    assert chronik_outbox.receipt_path(path).exists()


def test_flush_failure_keeps_pending_file_and_no_receipt(tmp_path):
    event = load_event()
    path = chronik_outbox.append_event(event, tmp_path)

    with pytest.raises(chronik_outbox.OutboxError):
        chronik_outbox.flush_file(
            path,
            base_url="http://chronik.test",
            token="secret",
            sender=lambda url, payload, token, timeout: (503, "down"),
        )

    assert path.exists()
    assert not chronik_outbox.receipt_path(path).exists()


def test_preview_renders_views_without_receipts(tmp_path):
    completed = load_event()
    blocked = load_event()
    blocked["kind"] = "agent.run.blocked"
    blocked["event_id"] = "sha256:" + "b" * 64
    blocked["source"]["run_id"] = "run-blocked"
    blocked["ts"] = "2026-07-02T12:10:00Z"
    blocked["data"] = {"result": "blocked", "blocker_code": "task-failed"}
    completed_path = chronik_outbox.append_event(completed, tmp_path)
    blocked_path = chronik_outbox.append_event(blocked, tmp_path)
    result = chronik_outbox.preview(tmp_path)
    assert result["mutates_remote"] is False
    assert result["event_count"] == 2
    assert len(result["repo_view"]) == 1
    assert result["repo_view"][0]["result"] == "blocked"
    assert [(row["run_id"], row["result"]) for row in result["run_view"]] == [
        ("run-20260702-120000", "completed"),
        ("run-blocked", "blocked"),
    ]
    assert not chronik_outbox.receipt_path(completed_path).exists()
    assert not chronik_outbox.receipt_path(blocked_path).exists()
