import hashlib
import json
from pathlib import Path

import pytest

from tools import chronik_outbox

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "agent-ledger" / "agent-run-completed.v0.json"


def load_event():
    with FIXTURE.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def blocked_event():
    event = load_event()
    event["kind"] = "agent.run.blocked"
    event["event_id"] = "sha256:" + "b" * 64
    event["ts"] = "2026-07-02T12:10:00Z"
    event["data"] = {"result": "blocked", "blocker_code": "task-failed"}
    return event


def encoded_event(event):
    return (
        json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )


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


def test_flush_file_posts_agent_ledger_domain_and_writes_bound_receipt(tmp_path):
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
    assert receipt_body["receipt_version"] == chronik_outbox.RECEIPT_VERSION
    assert receipt_body["domain"] == "agent.ledger"
    assert receipt_body["source_path"] == str(path.resolve())
    assert receipt_body["event_count"] == 1
    assert receipt_body["source_bytes"] == path.stat().st_size
    assert receipt_body["source_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


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


def test_append_after_flush_invalidates_receipt_and_blocks_compaction(tmp_path):
    path = chronik_outbox.append_event(load_event(), tmp_path)
    chronik_outbox.flush_file(
        path,
        base_url="http://chronik.test",
        token="secret",
        sender=lambda url, payload, token, timeout: (202, "ok"),
    )

    assert chronik_outbox.append_event(blocked_event(), tmp_path) == path

    entries = chronik_outbox.status(tmp_path)
    assert len(entries) == 1
    assert entries[0].events == 2
    assert entries[0].flushed is False
    assert chronik_outbox.compact(tmp_path) == []
    assert path.exists()


def test_flush_all_sends_only_suffix_after_bound_receipt(tmp_path):
    path = chronik_outbox.append_event(load_event(), tmp_path)
    chronik_outbox.flush_file(
        path,
        base_url="http://chronik.test",
        token="secret",
        sender=lambda url, payload, token, timeout: (202, "ok"),
    )
    chronik_outbox.append_event(blocked_event(), tmp_path)
    calls = []

    def fake_sender(url, payload, token, timeout):
        calls.append(payload)
        return 202, "ok"

    receipts = chronik_outbox.flush_all(
        state_root=tmp_path,
        base_url="http://chronik.test",
        token="secret",
        sender=fake_sender,
    )

    assert receipts == [chronik_outbox.receipt_path(path)]
    assert len(calls) == 1
    assert [event["kind"] for event in calls[0]] == ["agent.run.blocked"]
    receipt = json.loads(chronik_outbox.receipt_path(path).read_text(encoding="utf-8"))
    assert receipt["event_count"] == 2
    assert receipt["source_bytes"] == path.stat().st_size
    assert chronik_outbox.status(tmp_path)[0].flushed is True
    assert chronik_outbox.compact(tmp_path) == [path]


def test_append_during_send_records_only_sent_prefix(tmp_path):
    path = chronik_outbox.append_event(load_event(), tmp_path)
    appended = blocked_event()

    def appending_sender(url, payload, token, timeout):
        with path.open("ab") as handle:
            handle.write(encoded_event(appended))
            handle.flush()
        return 202, "ok"

    receipt_path = chronik_outbox.flush_file(
        path,
        base_url="http://chronik.test",
        token="secret",
        sender=appending_sender,
    )

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["event_count"] == 1
    assert receipt["source_bytes"] < path.stat().st_size
    entry = chronik_outbox.status(tmp_path)[0]
    assert entry.events == 2
    assert entry.flushed is False
    assert chronik_outbox.compact(tmp_path) == []

    calls = []
    chronik_outbox.flush_all(
        state_root=tmp_path,
        base_url="http://chronik.test",
        token="secret",
        sender=lambda url, payload, token, timeout: (calls.append(payload) or (202, "ok")),
    )
    assert [[event["kind"] for event in payload] for payload in calls] == [["agent.run.blocked"]]
    assert chronik_outbox.status(tmp_path)[0].flushed is True


def test_non_append_change_after_send_writes_no_receipt(tmp_path):
    path = chronik_outbox.append_event(load_event(), tmp_path)

    def replacing_sender(url, payload, token, timeout):
        path.write_bytes(encoded_event(blocked_event()))
        return 202, "ok"

    with pytest.raises(chronik_outbox.OutboxError, match="non-append-only"):
        chronik_outbox.flush_file(
            path,
            base_url="http://chronik.test",
            token="secret",
            sender=replacing_sender,
        )

    assert path.exists()
    assert not chronik_outbox.receipt_path(path).exists()
    entry = chronik_outbox.status(tmp_path)[0]
    assert entry.events == 1
    assert entry.flushed is False


def test_malformed_receipt_never_authorizes_flush_or_compaction(tmp_path):
    path = chronik_outbox.append_event(load_event(), tmp_path)
    receipt = chronik_outbox.receipt_path(path)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text("{}\n", encoding="utf-8")
    calls = []

    assert chronik_outbox.status(tmp_path)[0].flushed is False
    assert chronik_outbox.compact(tmp_path) == []
    with pytest.raises(chronik_outbox.OutboxError, match="not snapshot-bound"):
        chronik_outbox.flush_all(
            state_root=tmp_path,
            base_url="http://chronik.test",
            token="secret",
            sender=lambda url, payload, token, timeout: (calls.append(payload) or (202, "ok")),
        )
    assert calls == []
    assert path.exists()


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
    blocked = blocked_event()
    blocked["source"]["run_id"] = "run-blocked"
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
