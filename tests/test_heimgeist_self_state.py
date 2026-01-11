
import pytest
from fastapi.testclient import TestClient
from app import app
import os
import json

@pytest.fixture(autouse=True)
def mock_storage(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")

@pytest.fixture
def client():
    return TestClient(app)

def test_ingest_self_state_snapshot_valid(client):
    payload = {
        "kind": "heimgeist.self_state.snapshot",
        "version": 1,
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "meta": {
            "occurred_at": "2023-10-27T10:00:00Z"
        },
        "data": {
            "confidence": 0.9,
            "fatigue": 0.1,
            "risk_tension": 0.2,
            "autonomy_level": "aware",
            "last_updated": "2023-10-27T09:59:00Z",
            "basis_signals": ["ci_passing", "low_risk"]
        }
    }
    response = client.post(
        "/v1/ingest?domain=heimgeist",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 202

def test_ingest_self_state_snapshot_missing_fields(client):
    payload = {
        "kind": "heimgeist.self_state.snapshot",
        "version": 1,
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "meta": {
            "occurred_at": "2023-10-27T10:00:00Z"
        },
        "data": {
            "confidence": 0.9,
            # Missing other fields
        }
    }
    response = client.post(
        "/v1/ingest?domain=heimgeist",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 400
    assert "schema validation failed" in response.json()["detail"]

def test_ingest_self_state_snapshot_invalid_values(client):
    payload = {
        "kind": "heimgeist.self_state.snapshot",
        "version": 1,
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "meta": {
            "occurred_at": "2023-10-27T10:00:00Z"
        },
        "data": {
            "confidence": 1.5, # Invalid > 1.0
            "fatigue": 0.1,
            "risk_tension": 0.2,
            "autonomy_level": "aware",
            "last_updated": "2023-10-27T09:59:00Z",
            "basis_signals": []
        }
    }
    response = client.post(
        "/v1/ingest?domain=heimgeist",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 400
    assert "schema validation failed" in response.json()["detail"]

def test_ingest_self_state_snapshot_invalid_enum(client):
    payload = {
        "kind": "heimgeist.self_state.snapshot",
        "version": 1,
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "meta": {
            "occurred_at": "2023-10-27T10:00:00Z"
        },
        "data": {
            "confidence": 0.5,
            "fatigue": 0.1,
            "risk_tension": 0.2,
            "autonomy_level": "skynet_active", # Invalid
            "last_updated": "2023-10-27T09:59:00Z",
            "basis_signals": []
        }
    }
    response = client.post(
        "/v1/ingest?domain=heimgeist",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 400
    assert "schema validation failed" in response.json()["detail"]

def test_ingest_heimgeist_insight_still_works(client):
    payload = {
        "kind": "heimgeist.insight",
        "version": 1,
        "id": "uuid-5678",
        "meta": {
            "occurred_at": "2023-10-27T10:00:00Z"
        },
        "data": {
            "foo": "bar" # Insight data is flexible
        }
    }
    response = client.post(
        "/v1/ingest?domain=heimgeist",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 202

def test_ingest_rejects_bundle_artifact_with_kind(client):
    """
    If someone mistakenly tries to send a bundle artifact as an event (by adding 'kind'),
    it should be rejected by the whitelist check because the kind is not allowed.
    """
    payload = {
        "kind": "heimgeist.self_state.bundle.v1",
        "version": 1,
        "id": "uuid-bundle",
        "meta": {
            "occurred_at": "2023-10-27T10:00:00Z"
        },
        "data": {
            "current": {},
            "history": []
        }
    }
    response = client.post(
        "/v1/ingest?domain=heimgeist",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 400
    assert "invalid kind" in response.json()["detail"]

def test_ingest_rejects_pure_bundle_artifact(client):
    """
    A pure bundle artifact (schema, current, history) sent to the ingest endpoint
    should fail because it lacks the required event envelope structure (kind, version, etc.).
    """
    payload = {
        "schema": "heimgeist.self_state.bundle.v1",
        "current": {
            "confidence": 0.9,
            "fatigue": 0.1,
            "risk_tension": 0.2,
            "autonomy_level": "aware",
            "last_updated": "2023-10-27T09:59:00Z",
            "basis_signals": []
        },
        "history": []
    }
    response = client.post(
        "/v1/ingest?domain=heimgeist",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "invalid payload structure" in detail or "missing fields" in detail

def test_ingest_rejects_extra_fields(client):
    """
    Event with extra fields in data must fail validation (strict schema).
    """
    payload = {
        "kind": "heimgeist.self_state.snapshot",
        "version": 1,
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "meta": {
            "occurred_at": "2023-10-27T10:00:00Z"
        },
        "data": {
            "confidence": 0.9,
            "fatigue": 0.1,
            "risk_tension": 0.2,
            "autonomy_level": "aware",
            "last_updated": "2023-10-27T09:59:00Z",
            "basis_signals": ["ci_passing", "low_risk"],
            "debug_info": "this should be rejected"
        }
    }
    response = client.post(
        "/v1/ingest?domain=heimgeist",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 400
    assert "schema validation failed" in response.json()["detail"]
    # Usually jsonschema says: 'Additional properties are not allowed ('debug_info' was unexpected)'
    # We can check for "Additional properties" if we want to be specific, or just verify rejection.
