"""Integration tests for event quality, provenance, and retention features."""

import json
import os
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    """Create test client with token configured."""
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    # Import after env is set
    from app import app
    return TestClient(app)


@pytest.fixture(autouse=True)
def setup_data_dir(tmp_path, monkeypatch):
    """Patch storage.DATA_DIR to use tmp_path."""
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)


def test_event_with_quality_markers(client, monkeypatch):
    """Test that quality markers are added to events."""
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "1")
    # Need to reload app to pick up env changes
    import importlib
    import app as app_module
    importlib.reload(app_module)
    client = TestClient(app_module.app)
    
    headers = {"X-Auth": "test-token", "Content-Type": "application/json"}
    domain = "quality.test"
    
    payload = {
        "event_id": "123",
        "kind": "test.event",
        "ts": "2026-01-04T10:00:00Z",
        "source": {"repo": "test", "component": "test"},
        "data": {"value": 42},
    }
    
    resp = client.post(f"/v1/ingest?domain={domain}", json=payload, headers=headers)
    assert resp.status_code == 202
    
    # Read back the event
    resp = client.get(f"/v1/latest?domain={domain}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    
    # Check quality markers were added
    assert "quality" in data["payload"]
    assert data["payload"]["quality"]["signal_strength"] == "high"
    assert data["payload"]["quality"]["completeness"] is True


def test_event_with_retention_metadata(client):
    """Test that retention metadata is added to events."""
    headers = {"X-Auth": "test-token", "Content-Type": "application/json"}
    domain = "retention.test"
    
    payload = {
        "event_id": "123",
        "kind": "debug.test",  # Should match *.debug.* pattern -> 7 days TTL
        "ts": "2026-01-04T10:00:00Z",
        "source": {"repo": "test", "component": "test"},
        "data": {"value": 42},
    }
    
    resp = client.post(f"/v1/ingest?domain={domain}", json=payload, headers=headers)
    assert resp.status_code == 202
    
    # Read back the event
    resp = client.get(f"/v1/latest?domain={domain}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    
    # Check retention metadata was added
    assert "retention" in data
    assert data["retention"]["ttl_days"] == 7
    assert data["retention"]["expires_at"] is not None


def test_provenance_permissive_mode(client, monkeypatch):
    """Test that events without provenance are accepted in permissive mode."""
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "0")
    # Need to reload app to pick up env changes
    import importlib
    import app as app_module
    importlib.reload(app_module)
    client = TestClient(app_module.app)
    
    headers = {"X-Auth": "test-token", "Content-Type": "application/json"}
    domain = "provenance.test"
    
    # Event without provenance
    payload = {
        "kind": "test.event",
        "data": {"value": 42},
    }
    
    resp = client.post(f"/v1/ingest?domain={domain}", json=payload, headers=headers)
    # Should be accepted in permissive mode
    assert resp.status_code == 202


def test_provenance_strict_mode_accept(client, monkeypatch):
    """Test that events with provenance are accepted in strict mode."""
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "1")
    # Need to reload app to pick up env changes
    import importlib
    import app as app_module
    importlib.reload(app_module)
    client = TestClient(app_module.app)
    
    headers = {"X-Auth": "test-token", "Content-Type": "application/json"}
    domain = "provenance.strict.test"
    
    # Event with valid provenance
    payload = {
        "event_id": "123",
        "source": {"repo": "test", "component": "test"},
        "kind": "test.event",
        "ts": "2026-01-04T10:00:00Z",
        "data": {"value": 42},
    }
    
    resp = client.post(f"/v1/ingest?domain={domain}", json=payload, headers=headers)
    assert resp.status_code == 202


def test_provenance_strict_mode_reject(client, monkeypatch):
    """Test that events without provenance are rejected in strict mode."""
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "1")
    # Need to reload app to pick up env changes
    import importlib
    import app as app_module
    importlib.reload(app_module)
    client = TestClient(app_module.app)
    
    headers = {"X-Auth": "test-token", "Content-Type": "application/json"}
    domain = "provenance.strict.test"
    
    # Event without provenance
    payload = {
        "kind": "test.event",
        "data": {"value": 42},
    }
    
    resp = client.post(f"/v1/ingest?domain={domain}", json=payload, headers=headers)
    # Should be rejected in strict mode
    assert resp.status_code == 400
    assert "provenance" in resp.text.lower()


def test_published_event_unlimited_retention(client):
    """Test that published events have unlimited retention."""
    headers = {"X-Auth": "test-token", "Content-Type": "application/json"}
    domain = "published.test"
    
    payload = {
        "event_id": "123",
        "kind": "event.published.v1",  # Should match *.published.v1 pattern -> TTL=0
        "ts": "2026-01-04T10:00:00Z",
        "source": {"repo": "test", "component": "test"},
        "data": {"value": 42},
    }
    
    resp = client.post(f"/v1/ingest?domain={domain}", json=payload, headers=headers)
    assert resp.status_code == 202
    
    # Read back the event
    resp = client.get(f"/v1/latest?domain={domain}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    
    # Check retention metadata indicates unlimited retention
    assert data["retention"]["ttl_days"] == 0
    assert data["retention"]["expires_at"] is None


def test_metrics_endpoint_accessible(client):
    """Test that metrics endpoint is accessible."""
    resp = client.get("/metrics")
    assert resp.status_code == 200
    
    # Check for our custom metrics
    metrics_text = resp.text
    assert "chronik_events_ingested_total" in metrics_text
    assert "chronik_events_rejected_total" in metrics_text
    assert "chronik_events_signal_strength_total" in metrics_text
    assert "chronik_provenance_validation_failures_total" in metrics_text
