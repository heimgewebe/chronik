import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException

import app
import storage
from canonical_ingest import apply_retention_policy, build_quality_envelope
from ingest_validation import validate_and_normalize_item


RECEIVED_AT = datetime(2026, 1, 1, 12, 34, 56, 789000, tzinfo=timezone.utc)
GOLDEN_QUALITY_DISABLED = (
    Path(__file__).parent / "fixtures" / "golden-quality-disabled-v1.jsonl"
)


class _FixedDateTime:
    @classmethod
    def now(cls, tz=None):
        assert tz is timezone.utc
        return RECEIVED_AT


class _MetricRecorder:
    def __init__(self):
        self.increments = []

    def labels(self, **labels):
        recorder = self

        class _BoundMetric:
            def inc(self, amount=1):
                recorder.increments.append((labels, amount))

        return _BoundMetric()


@pytest.fixture
def process_context(monkeypatch):
    ingested = _MetricRecorder()
    signal = _MetricRecorder()
    rejected = _MetricRecorder()
    provenance_failures = _MetricRecorder()
    monkeypatch.setattr(app, "datetime", _FixedDateTime)
    monkeypatch.setattr(app, "events_ingested_total", ingested)
    monkeypatch.setattr(app, "events_signal_strength", signal)
    monkeypatch.setattr(app, "events_rejected_total", rejected)
    monkeypatch.setattr(app, "provenance_validation_failures", provenance_failures)
    return {
        "ingested": ingested,
        "signal": signal,
        "rejected": rejected,
        "provenance_failures": provenance_failures,
    }


@pytest.mark.parametrize(
    ("domain", "payload", "expected_payload", "retention", "quality", "event_type"),
    [
        pytest.param(
            "example.com",
            {
                "domain": "Example.COM",
                "event_id": "evt-ä",
                "kind": "app.debug.trace",
                "ts": "2026-01-01T10:00:00Z",
                "source": {"repo": "heimgewebe/example", "component": "api"},
                "data": {"message": "grüß"},
            },
            {
                "domain": "Example.COM",
                "event_id": "evt-ä",
                "kind": "app.debug.trace",
                "ts": "2026-01-01T10:00:00Z",
                "source": {"repo": "heimgewebe/example", "component": "api"},
                "data": {"message": "grüß"},
            },
            {"ttl_days": 7, "expires_at": "2026-01-08T12:34:56Z"},
            {"signal_strength": "high", "completeness": True},
            "app.debug.trace",
            id="generic-domain",
        ),
        pytest.param(
            "insights.daily",
            {
                "ts": "2026-01-01",
                "topics": [["chronik", 1.0]],
                "questions": [],
                "deltas": [],
                "source": "semantAH",
                "metadata": {"generated_at": "2026-01-01T10:00:00Z"},
            },
            {
                "ts": "2026-01-01",
                "topics": [["chronik", 1.0]],
                "questions": [],
                "deltas": [],
                "source": "semantAH",
                "metadata": {"generated_at": "2026-01-01T10:00:00Z"},
            },
            {"ttl_days": 30, "expires_at": "2026-01-31T12:34:56Z"},
            {"signal_strength": "medium", "completeness": False},
            "domain.insights.daily",
            id="insights-daily",
        ),
        pytest.param(
            "heimgeist",
            {
                "id": "legacy-1",
                "source": "heimgeist-worker",
                "timestamp": "2026-01-01T10:00:00Z",
                "payload": {
                    "kind": "heimgeist.insight",
                    "version": 1,
                    "data": {"note": "remember"},
                },
            },
            {
                "kind": "heimgeist.insight",
                "version": 1,
                "id": "legacy-1",
                "meta": {
                    "occurred_at": "2026-01-01T10:00:00Z",
                    "producer": "heimgeist-worker",
                },
                "data": {"note": "remember"},
            },
            {"ttl_days": 30, "expires_at": "2026-01-31T12:34:56Z"},
            {"signal_strength": "medium", "completeness": False},
            "heimgeist.insight",
            id="heimgeist-legacy-normalization",
        ),
    ],
)
def test_process_items_preserves_canonical_jsonl_and_metrics(
    monkeypatch,
    process_context,
    domain,
    payload,
    expected_payload,
    retention,
    quality,
    event_type,
):
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "0")
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "1")
    original = copy.deepcopy(payload)
    expected = {
        "domain": domain,
        "received_at": "2026-01-01T12:34:56Z",
        "payload": expected_payload,
        "retention": retention,
        "quality": quality,
    }

    normalized = validate_and_normalize_item(
        payload,
        domain,
        provenance_enforced=False,
    )
    quality_envelope = build_quality_envelope(
        domain,
        normalized,
        received_at=RECEIVED_AT,
        quality_enabled=True,
    )
    stage_line = json.dumps(
        apply_retention_policy(quality_envelope, received_at=RECEIVED_AT),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    lines = app._process_items([payload], domain)

    expected_line = json.dumps(expected, ensure_ascii=False, separators=(",", ":"))
    assert lines == [stage_line] == [expected_line]
    assert payload == original
    assert process_context["signal"].increments == [
        ({"domain": domain, "signal_strength": quality["signal_strength"]}, 1)
    ]
    assert process_context["ingested"].increments == [
        ({"domain": domain, "event_type": event_type}, 1)
    ]
    assert process_context["rejected"].increments == []
    assert process_context["provenance_failures"].increments == []


def test_process_items_quality_disabled_preserves_envelope_and_metric_counts(
    monkeypatch, process_context
):
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "0")
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "0")
    payload = {"type": "temp.event", "summary": "accepted"}

    lines = app._process_items([payload], "quality.disabled")

    assert lines == [
        '{"domain":"quality.disabled","received_at":"2026-01-01T12:34:56Z",'
        '"payload":{"type":"temp.event","summary":"accepted"},'
        '"retention":{"ttl_days":1,"expires_at":"2026-01-02T12:34:56Z"}}'
    ]
    assert process_context["signal"].increments == []
    assert process_context["ingested"].increments == [
        ({"domain": "quality.disabled", "event_type": "temp.event"}, 1)
    ]


def test_process_items_strict_provenance_failure_preserves_detail_and_metrics(
    monkeypatch, process_context
):
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "1")
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "1")

    with pytest.raises(HTTPException) as exc_info:
        app._process_items([{"kind": "test.event"}], "strict.example")

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == (
        "provenance validation failed: Missing or invalid provenance fields: "
        "source (must be an object), event_id (or id)"
    )
    assert process_context["provenance_failures"].increments == [
        ({"domain": "strict.example"}, 1)
    ]
    assert process_context["rejected"].increments == [
        ({"domain": "strict.example", "reason": "provenance"}, 1)
    ]
    assert process_context["signal"].increments == []
    assert process_context["ingested"].increments == []


def test_process_items_accepts_complete_provenance_in_strict_mode(
    monkeypatch, process_context
):
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "1")
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "0")
    payload = {
        "event_id": "strict-accepted",
        "kind": "test.strict",
        "source": {"repo": "heimgewebe/chronik", "component": "tests"},
    }

    [line] = app._process_items([payload], "strict.example")

    assert json.loads(line)["payload"] == payload
    assert process_context["provenance_failures"].increments == []
    assert process_context["rejected"].increments == []
    assert process_context["ingested"].increments == [
        ({"domain": "strict.example", "event_type": "test.strict"}, 1)
    ]


@pytest.mark.parametrize(
    ("payload", "status_code", "detail"),
    [
        ({"domain": "other.example"}, 400, "domain mismatch"),
        ({"domain": 42}, 400, "invalid payload"),
        ({"summary": "x" * 501}, 422, "summary too long (max 500)"),
    ],
)
def test_process_items_generic_validation_errors_are_stable(
    monkeypatch, process_context, payload, status_code, detail
):
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "0")

    with pytest.raises(HTTPException) as exc_info:
        app._process_items([payload], "example.com")

    assert exc_info.value.status_code == status_code
    assert exc_info.value.detail == detail
    assert process_context["signal"].increments == []
    assert process_context["ingested"].increments == []


def test_process_items_accepts_summary_at_exact_limit(monkeypatch, process_context):
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "0")
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "0")

    [line] = app._process_items([{"summary": "x" * 500}], "example.com")

    assert json.loads(line)["payload"]["summary"] == "x" * 500
    assert process_context["ingested"].increments == [
        ({"domain": "example.com", "event_type": "domain.example.com"}, 1)
    ]


def test_process_items_preserves_metrics_for_valid_prefix_of_failed_batch(
    monkeypatch, process_context
):
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "0")
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "1")

    with pytest.raises(HTTPException) as exc_info:
        app._process_items(
            [{"kind": "test.first"}, {"summary": "x" * 501}],
            "batch.example",
        )

    assert exc_info.value.status_code == 422
    assert process_context["signal"].increments == [
        ({"domain": "batch.example", "signal_strength": "low"}, 1)
    ]
    assert process_context["ingested"].increments == [
        ({"domain": "batch.example", "event_type": "test.first"}, 1)
    ]


def test_persisted_quality_disabled_matches_golden_jsonl(
    monkeypatch, process_context, tmp_path
):
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "0")
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "0")
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)

    lines = app._process_items(
        [{"type": "temp.event", "summary": "accepted"}],
        "quality.disabled",
    )
    storage.write_payload("quality.disabled", lines)

    persisted = tmp_path / "quality.disabled.jsonl"
    assert persisted.read_bytes() == GOLDEN_QUALITY_DISABLED.read_bytes()
