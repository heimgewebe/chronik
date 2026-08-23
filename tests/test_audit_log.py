import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import app
import audit_log
import storage
from audit_log import anonymize_client_ip, build_audit_event, emit_audit_event


@pytest.fixture
def audit_client(monkeypatch, tmp_path):
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    monkeypatch.setenv("CHRONIK_INTEGRITY_ENABLED", "0")
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    app.limiter.reset()

    events = []

    def capture_event(**kwargs):
        events.append(kwargs)
        return kwargs

    monkeypatch.setattr(app, "emit_audit_event", capture_event)
    try:
        with TestClient(app.app) as client:
            yield client, events
    finally:
        app.limiter.reset()


def test_audit_event_contract_anonymizes_client_ip():
    raw_ip = "203.0.113.42"
    event = build_audit_event(
        request_id="req-123",
        domain="example.com",
        action="ACCEPTED",
        reason="accepted",
        client_ip=raw_ip,
        now=datetime(2026, 8, 12, 11, 0, 0, tzinfo=timezone.utc),
    )

    assert event == {
        "timestamp": "2026-08-12T11:00:00.000Z",
        "request_id": "req-123",
        "domain": "example.com",
        "action": "ACCEPTED",
        "reason": "accepted",
        "client_ip": anonymize_client_ip(raw_ip),
    }
    assert event["client_ip"].startswith("anon:")
    assert raw_ip not in json.dumps(event)


def test_audit_ip_identifier_is_process_local_and_stable():
    key = b"test-audit-key"
    first = anonymize_client_ip("198.51.100.10", key=key)
    second = anonymize_client_ip("198.51.100.10", key=key)
    other = anonymize_client_ip("198.51.100.11", key=key)

    assert first == second
    assert first != other
    assert "198.51.100" not in first


def test_audit_emission_is_one_json_line(monkeypatch):
    messages = []
    monkeypatch.setattr(audit_log.audit_logger, "info", messages.append)

    event = emit_audit_event(
        request_id="req-1",
        domain="example.com",
        action="REJECTED",
        reason="invalid\npayload",
        client_ip="192.0.2.7",
    )

    assert len(messages) == 1
    assert "\n" not in messages[0]
    assert json.loads(messages[0]) == event
    assert "192.0.2.7" not in messages[0]


def test_audit_logging_failure_cannot_change_ingest_semantics(monkeypatch):
    def fail_log(_message):
        raise RuntimeError("logging unavailable")

    monkeypatch.setattr(audit_log.audit_logger, "info", fail_log)

    event = emit_audit_event(
        request_id="req-1",
        domain="example.com",
        action="ACCEPTED",
        reason="accepted",
        client_ip="192.0.2.8",
    )

    assert event["action"] == "ACCEPTED"


def test_successful_ingest_emits_accepted_audit_event(audit_client):
    client, events = audit_client

    response = client.post(
        "/v1/ingest?domain=example.com",
        headers={"X-Auth": "test-token", "X-Request-ID": "audit:accepted"},
        json={"data": "value"},
    )

    assert response.status_code == 202
    assert events == [
        {
            "request_id": "audit_accepted",
            "domain": "example.com",
            "action": "ACCEPTED",
            "reason": "accepted",
            "client_ip": "testclient",
        }
    ]


def test_invalid_json_emits_rejected_audit_event(audit_client):
    client, events = audit_client

    response = client.post(
        "/v1/ingest?domain=example.com",
        headers={
            "X-Auth": "test-token",
            "X-Request-ID": "audit:json",
            "Content-Type": "application/json",
        },
        content="{invalid json}",
    )

    assert response.status_code == 400
    assert events == [
        {
            "request_id": "audit_json",
            "domain": "example.com",
            "action": "REJECTED",
            "reason": "invalid json",
            "client_ip": "testclient",
        }
    ]


def test_auth_rejection_is_audited_before_endpoint_execution(audit_client):
    client, events = audit_client

    response = client.post(
        "/v1/ingest?domain=example.com",
        headers={"X-Auth": "wrong", "X-Request-ID": "audit:auth"},
        json={"data": "value"},
    )

    assert response.status_code == 403
    assert events == [
        {
            "request_id": "audit_auth",
            "domain": "example.com",
            "action": "REJECTED",
            "reason": "forbidden",
            "client_ip": "testclient",
        }
    ]
