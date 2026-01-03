import pytest
import os
from fastapi.testclient import TestClient
from app import app
import storage
from pathlib import Path

@pytest.fixture
def client(monkeypatch):
    with TestClient(app) as c:
        yield c

def test_heimgeist_valid_payload(monkeypatch, tmp_path: Path, client):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")

    payload = {
        "kind": "heimgeist.insight",
        "version": 1,
        "id": "evt-1",
        "meta": {
            "occurred_at": "2023-10-27T10:00:00Z"
            # role is optional in minimal wrapper check
        },
        "data": {"foo": "bar"}
    }
    # Canonical path
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 202
    assert response.text == "ok"

def test_heimgeist_missing_fields(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    # Missing kind, version, meta, data -> and not legacy structure
    payload = {
        "id": "evt-1"
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "invalid payload structure" in response.text

def test_heimgeist_invalid_kind(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "kind": "wrong",
        "version": 1,
        "id": "evt-1",
        "meta": {"occurred_at": "ts", "role": "r"},
        "data": {}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "invalid kind" in response.text

def test_heimgeist_invalid_version(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "kind": "heimgeist.insight",
        "version": 2,
        "id": "evt-1",
        "meta": {"occurred_at": "ts", "role": "r"},
        "data": {}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "invalid version" in response.text

def test_heimgeist_missing_meta_fields(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "kind": "heimgeist.insight",
        "version": 1,
        "id": "evt-1",
        "meta": {}, # empty
        "data": {}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "missing meta" in response.text

def test_heimgeist_invalid_data_type(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "kind": "heimgeist.insight",
        "version": 1,
        "id": "evt-1",
        "meta": {"occurred_at": "2023-10-27T10:00:00Z"},
        "data": "not-a-dict"
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "data must be a dict" in response.text

def test_other_domain_loose_validation(monkeypatch, tmp_path, client):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    # Missing id etc, should still pass for other domains
    payload = {"foo": "bar"}
    response = client.post("/v1/ingest?domain=other", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 202

def test_heimgeist_legacy_path(monkeypatch, tmp_path: Path, client):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")

    payload = {
        "kind": "heimgeist.insight",
        "version": 1,
        "id": "evt-1",
        "meta": {
            "occurred_at": "2023-10-27T10:00:00Z",
            "role": "test"
        },
        "data": {"foo": "bar"}
    }
    response = client.post("/ingest/heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 202

def test_retry_after_header_logic(client):
    from app import _on_rate_limited
    from slowapi.errors import RateLimitExceeded
    from fastapi import Request
    import asyncio

    class MockLimit:
        error_message = None
        limit = "60/minute"
        def __str__(self): return self.limit

    scope = {"type": "http", "headers": []}
    req = Request(scope)
    exc = RateLimitExceeded(MockLimit())

    # Run the handler
    loop = asyncio.new_event_loop()
    response = loop.run_until_complete(_on_rate_limited(req, exc))
    loop.close()

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"

def test_heimgeist_invalid_version_type(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "kind": "heimgeist.insight",
        "version": "1", # String instead of int
        "id": "evt-1",
        "meta": {"occurred_at": "2023-10-27T10:00:00Z", "role": "test"},
        "data": {}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "version must be an integer" in response.text

def test_heimgeist_invalid_timestamp_format(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "kind": "heimgeist.insight",
        "version": 1,
        "id": "evt-1",
        "meta": {"occurred_at": "invalid-ts", "role": "test"},
        "data": {}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "valid ISO8601" in response.text

def test_heimgeist_legacy_adapter_success(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "id": "legacy-1",
        "source": "src",
        "timestamp": "2023-10-27T10:00:00Z",
        "payload": {
            "kind": "heimgeist.insight",
            "version": 1,
            "data": {"foo": "bar"}
        }
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 202
    assert response.text == "ok"

def test_heimgeist_legacy_adapter_missing_kind(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "id": "legacy-2",
        "source": "src",
        "timestamp": "2023-10-27T10:00:00Z",
        "payload": {
            "version": 1,
            "data": {"foo": "bar"}
        }
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "legacy payload missing kind/version" in response.text


def test_heimgeist_legacy_adapter_invalid_version(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "id": "legacy-3",
        "source": "src",
        "timestamp": "2023-10-27T10:00:00Z",
        "payload": {
            "kind": "heimgeist.insight",
            "version": 0,  # Present but invalid
            "data": {"foo": "bar"}
        }
    }
    response = client.post(
        "/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"}
    )
    assert response.status_code == 400
    assert "invalid version" in response.text
