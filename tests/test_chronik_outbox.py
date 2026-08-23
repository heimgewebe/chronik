from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from threading import Lock

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


def third_event():
    event = blocked_event()
    event["event_id"] = "sha256:" + "c" * 64
    event["ts"] = "2026-07-02T12:20:00Z"
    return event


def encoded_event(event):
    return (
        json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )


def test_validate_event_reuses_compiled_validator(monkeypatch):
    event = load_event()
    load_calls = 0
    original_load_schema = chronik_outbox.load_schema

    def counted_load_schema():
        nonlocal load_calls
        load_calls += 1
        return original_load_schema()

    monkeypatch.setattr(chronik_outbox, "_EVENT_VALIDATOR", None)
    monkeypatch.setattr(chronik_outbox, "load_schema", counted_load_schema)

    chronik_outbox.validate_event(event)
    chronik_outbox.validate_event(event)

    invalid = load_event()
    invalid["data"]["raw"] = "no"
    with pytest.raises(chronik_outbox.jsonschema.exceptions.ValidationError):
        chronik_outbox.validate_event(invalid)

    assert load_calls == 1


def test_validate_event_compiles_once_on_concurrent_cold_start(monkeypatch):
    event = load_event()
    load_calls = 0
    calls_lock = Lock()
    original_load_schema = chronik_outbox.load_schema

    def counted_load_schema():
        nonlocal load_calls
        with calls_lock:
            load_calls += 1
        return original_load_schema()

    monkeypatch.setattr(chronik_outbox, "_EVENT_VALIDATOR", None)
    monkeypatch.setattr(chronik_outbox, "load_schema", counted_load_schema)

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(lambda _: chronik_outbox.validate_event(event), range(64)))

    assert load_calls == 1


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


def test_flush_file_never_uses_path_read_bytes(monkeypatch, tmp_path):
    path = chronik_outbox.append_event(load_event(), tmp_path)
    calls = []

    def reject_read_bytes(self):
        raise AssertionError(f"flush_file called Path.read_bytes for {self}")

    monkeypatch.setattr(Path, "read_bytes", reject_read_bytes)

    receipt = chronik_outbox.flush_file(
        path,
        base_url="http://chronik.test",
        token="secret",
        sender=lambda url, payload, token, timeout: (calls.append(payload) or (202, "ok")),
    )

    assert receipt.exists()
    assert len(calls) == 1
    assert calls[0][0]["event_id"] == load_event()["event_id"]


def test_flush_file_streams_many_events_with_bounded_chunk_state(monkeypatch, tmp_path):
    event = load_event()
    event_count = 2048
    events_per_chunk = 8
    raw_line = encoded_event(event)
    path = chronik_outbox.outbox_path(event, tmp_path)
    path.parent.mkdir(parents=True)
    with path.open("wb") as handle:
        for _ in range(event_count):
            handle.write(raw_line)

    def reject_materialized_snapshot(*args, **kwargs):
        raise AssertionError("flush_file used the materializing snapshot path")

    monkeypatch.setattr(chronik_outbox, "_snapshot_unlocked", reject_materialized_snapshot)
    monkeypatch.setattr(chronik_outbox, "_parse_events", reject_materialized_snapshot)
    body_limit = len(chronik_outbox._encode_ingest_body([event] * events_per_chunk))
    sent_events = 0
    sender_calls = 0
    largest_payload = 0

    def bounded_sender(url, payload, token, timeout):
        nonlocal largest_payload, sender_calls, sent_events
        assert len(chronik_outbox._encode_ingest_body(payload)) <= body_limit
        largest_payload = max(largest_payload, len(payload))
        sender_calls += 1
        sent_events += len(payload)
        return 202, "ok"

    receipt = chronik_outbox.flush_file(
        path,
        base_url="http://chronik.test",
        token="secret",
        max_body_bytes=body_limit,
        sender=bounded_sender,
    )

    assert sent_events == event_count
    assert sender_calls == event_count // events_per_chunk
    assert largest_payload == events_per_chunk
    assert json.loads(receipt.read_text(encoding="utf-8"))["event_count"] == event_count


def test_post_json_sends_exact_body_used_for_size_accounting(monkeypatch):
    payload = [load_event(), blocked_event()]
    captured = {}

    class Response:
        status_code = 202
        text = "ok"

    class Client:
        def __init__(self, *, timeout):
            captured["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, *, content, headers):
            captured["url"] = url
            captured["content"] = content
            captured["headers"] = headers
            return Response()

    monkeypatch.setattr(chronik_outbox.httpx, "Client", Client)

    status_code, text = chronik_outbox.post_json(
        "http://chronik.test/v1/ingest?domain=agent.ledger",
        payload,
        "secret",
        1.25,
    )

    assert status_code == 202
    assert text == "ok"
    assert captured["content"] == chronik_outbox._encode_ingest_body(payload)
    assert captured["timeout"] == 1.25
    assert captured["headers"]["Content-Type"] == "application/json"


def test_flush_file_chunks_requests_under_body_limit(tmp_path):
    events = [load_event(), blocked_event(), third_event()]
    path = chronik_outbox.append_event(events[0], tmp_path)
    for event in events[1:]:
        assert chronik_outbox.append_event(event, tmp_path) == path
    body_limit = max(len(chronik_outbox._encode_ingest_body([event])) for event in events)
    calls = []

    receipt = chronik_outbox.flush_file(
        path,
        base_url="http://chronik.test",
        token="secret",
        max_body_bytes=body_limit,
        sender=lambda url, payload, token, timeout: (calls.append(payload) or (202, "ok")),
    )

    assert [[event["event_id"] for event in payload] for payload in calls] == [
        [events[0]["event_id"]],
        [events[1]["event_id"]],
        [events[2]["event_id"]],
    ]
    assert all(len(chronik_outbox._encode_ingest_body(payload)) <= body_limit for payload in calls)
    receipt_body = json.loads(receipt.read_text(encoding="utf-8"))
    assert receipt_body["event_count"] == 3
    assert receipt_body["source_bytes"] == path.stat().st_size
    assert chronik_outbox.status(tmp_path)[0].flushed is True


def test_flush_file_preserves_progress_when_later_chunk_fails(tmp_path):
    events = [load_event(), blocked_event(), third_event()]
    path = chronik_outbox.append_event(events[0], tmp_path)
    for event in events[1:]:
        chronik_outbox.append_event(event, tmp_path)
    body_limit = max(len(chronik_outbox._encode_ingest_body([event])) for event in events)
    calls = []

    def failing_second_sender(url, payload, token, timeout):
        calls.append(payload)
        return (202, "ok") if len(calls) == 1 else (503, "down")

    with pytest.raises(chronik_outbox.OutboxError, match="HTTP 503: down"):
        chronik_outbox.flush_file(
            path,
            base_url="http://chronik.test",
            token="secret",
            max_body_bytes=body_limit,
            sender=failing_second_sender,
        )

    receipt_path = chronik_outbox.receipt_path(path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["event_count"] == 1
    assert receipt["source_bytes"] == len(encoded_event(events[0]))
    assert receipt["source_sha256"] == hashlib.sha256(encoded_event(events[0])).hexdigest()
    assert chronik_outbox.status(tmp_path)[0].flushed is False

    retry_calls = []
    chronik_outbox.flush_file(
        path,
        base_url="http://chronik.test",
        token="secret",
        max_body_bytes=body_limit,
        sender=lambda url, payload, token, timeout: (retry_calls.append(payload) or (202, "ok")),
    )
    assert [[event["event_id"] for event in payload] for payload in retry_calls] == [
        [events[1]["event_id"]],
        [events[2]["event_id"]],
    ]
    assert chronik_outbox.status(tmp_path)[0].flushed is True


def test_flush_file_rejects_oversized_single_event_before_sender(tmp_path):
    event = load_event()
    path = chronik_outbox.append_event(event, tmp_path)
    exact_size = len(chronik_outbox._encode_ingest_body([event]))
    calls = []

    with pytest.raises(chronik_outbox.OutboxError, match="exceeding max_body_bytes"):
        chronik_outbox.flush_file(
            path,
            base_url="http://chronik.test",
            token="secret",
            max_body_bytes=exact_size - 1,
            sender=lambda url, payload, token, timeout: (calls.append(payload) or (202, "ok")),
        )

    assert calls == []
    assert not chronik_outbox.receipt_path(path).exists()


def test_flush_file_preflights_later_oversized_event_before_any_sender(tmp_path):
    first = load_event()
    oversized = third_event()
    oversized["data"]["summary"] = "X" * 500
    path = chronik_outbox.append_event(first, tmp_path)
    chronik_outbox.append_event(oversized, tmp_path)
    body_limit = len(chronik_outbox._encode_ingest_body([first]))
    assert len(chronik_outbox._encode_ingest_body([oversized])) > body_limit
    calls = []

    with pytest.raises(chronik_outbox.OutboxError, match="event 2 .*exceeding max_body_bytes"):
        chronik_outbox.flush_file(
            path,
            base_url="http://chronik.test",
            token="secret",
            max_body_bytes=body_limit,
            sender=lambda url, payload, token, timeout: (calls.append(payload) or (202, "ok")),
        )

    assert calls == []
    assert not chronik_outbox.receipt_path(path).exists()


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


def test_non_append_change_after_progress_does_not_advance_receipt(tmp_path):
    events = [load_event(), blocked_event()]
    path = chronik_outbox.append_event(events[0], tmp_path)
    chronik_outbox.append_event(events[1], tmp_path)
    body_limit = max(len(chronik_outbox._encode_ingest_body([event])) for event in events)
    calls = 0

    def replacing_second_sender(url, payload, token, timeout):
        nonlocal calls
        calls += 1
        if calls == 2:
            path.write_bytes(encoded_event(third_event()))
        return 202, "ok"

    with pytest.raises(chronik_outbox.OutboxError, match="non-append-only"):
        chronik_outbox.flush_file(
            path,
            base_url="http://chronik.test",
            token="secret",
            max_body_bytes=body_limit,
            sender=replacing_second_sender,
        )

    receipt = json.loads(chronik_outbox.receipt_path(path).read_text(encoding="utf-8"))
    assert calls == 2
    assert receipt["event_count"] == 1
    assert receipt["source_bytes"] == len(encoded_event(events[0]))
    assert receipt["source_sha256"] == hashlib.sha256(encoded_event(events[0])).hexdigest()
    assert chronik_outbox.status(tmp_path)[0].flushed is False


def test_same_size_non_append_change_after_progress_does_not_advance_receipt(tmp_path):
    events = [load_event(), blocked_event()]
    replacement = third_event()
    assert len(encoded_event(events[1])) == len(encoded_event(replacement))
    path = chronik_outbox.append_event(events[0], tmp_path)
    chronik_outbox.append_event(events[1], tmp_path)
    body_limit = max(len(chronik_outbox._encode_ingest_body([event])) for event in events)
    calls = 0

    def replacing_second_sender(url, payload, token, timeout):
        nonlocal calls
        calls += 1
        if calls == 2:
            before_size = path.stat().st_size
            path.write_bytes(encoded_event(events[0]) + encoded_event(replacement))
            assert path.stat().st_size == before_size
        return 202, "ok"

    with pytest.raises(chronik_outbox.OutboxError, match="non-append-only"):
        chronik_outbox.flush_file(
            path,
            base_url="http://chronik.test",
            token="secret",
            max_body_bytes=body_limit,
            sender=replacing_second_sender,
        )

    receipt = json.loads(chronik_outbox.receipt_path(path).read_text(encoding="utf-8"))
    assert calls == 2
    assert receipt["event_count"] == 1
    assert receipt["source_bytes"] == len(encoded_event(events[0]))
    assert receipt["source_sha256"] == hashlib.sha256(encoded_event(events[0])).hexdigest()


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

    with pytest.raises(chronik_outbox.OutboxError, match="HTTP 503: down"):
        chronik_outbox.flush_file(
            path,
            base_url="http://chronik.test",
            token="secret",
            sender=lambda url, payload, token, timeout: (503, "down"),
        )

    assert path.exists()
    assert not chronik_outbox.receipt_path(path).exists()


@pytest.mark.parametrize("filler", ["X", "🧪", '"', "\\"])
def test_flush_failure_bounds_and_escapes_untrusted_http_body(tmp_path, filler):
    path = chronik_outbox.append_event(load_event(), tmp_path)
    body = "upstream failure\r\nSECOND-LINE\t" + filler * 5000

    with pytest.raises(chronik_outbox.OutboxError) as raised:
        chronik_outbox.flush_file(
            path,
            base_url="http://chronik.test",
            token="secret",
            sender=lambda url, payload, token, timeout: (503, body),
        )

    prefix = f"flush failed for {path}: HTTP 503: "
    message = str(raised.value)
    assert message.startswith(prefix)
    detail = message[len(prefix) :]
    assert len(detail.encode("utf-8")) <= chronik_outbox.HTTP_ERROR_DETAIL_MAX_BYTES
    assert r"\r\nSECOND-LINE\t" in detail
    assert "\r" not in message
    assert "\n" not in message
    assert "\t" not in message
    assert detail.endswith("…")
    assert path.exists()
    assert not chronik_outbox.receipt_path(path).exists()


def test_http_error_detail_escapes_unicode_separators_and_lone_surrogates():
    detail = chronik_outbox._bounded_http_error_detail(
        "first\u0085second\u2028third\u2029fourth\ud800"
    )

    assert r"\u0085" in detail
    assert r"\u2028" in detail
    assert r"\u2029" in detail
    assert r"\\ud800" in detail
    assert all(char not in detail for char in ("\u0085", "\u2028", "\u2029"))


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
