import pytest
import os
import json
import secrets
import string
from pathlib import Path
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import app
import storage

# Setup client
client = TestClient(app.app)

@pytest.fixture
def mock_storage(monkeypatch, tmp_path):
    """Mocks storage.DATA_DIR to use a temp directory and sets auth token."""
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    return tmp_path

def create_event_file(mock_storage, domain, lines):
    """Helper to create a domain file with specific lines."""
    p = mock_storage / f"{domain}.jsonl"
    with open(p, "wb") as f:
        for line in lines:
            f.write(line)
    return p

def _test_secret() -> str:
    return "test-token"

# --- Pagination Tests ---

def test_get_events_pagination(mock_storage):
    """
    Verifies that cursor-based pagination works correctly using byte offsets.
    """
    domain = "test.pagination"
    # Create 3 events.
    # We use simple lines to calculate offsets easily.
    # L1: {"id":1} + \n -> 9 bytes
    # L2: {"id":2} + \n -> 9 bytes
    # L3: {"id":3} + \n -> 9 bytes
    e1 = b'{"id":1}\n'
    e2 = b'{"id":2}\n'
    e3 = b'{"id":3}\n'

    create_event_file(mock_storage, domain, [e1, e2, e3])

    headers = {"X-Auth": "test-token"}

    # 1. Fetch first page (limit=1)
    resp = client.get(f"/v1/events?domain={domain}&limit=1", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["events"]) == 1
    assert data["events"][0]["id"] == 1
    assert data["has_more"] is True
    # Next cursor should be len(e1) = 9
    cursor1 = data["next_cursor"]
    assert cursor1 == 9

    # 2. Fetch second page (limit=1, cursor=9)
    resp = client.get(f"/v1/events?domain={domain}&limit=1&cursor={cursor1}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["events"]) == 1
    assert data["events"][0]["id"] == 2
    assert data["has_more"] is True
    cursor2 = data["next_cursor"]
    assert cursor2 == 18  # 9 + 9

    # 3. Fetch third page (limit=1, cursor=18)
    resp = client.get(f"/v1/events?domain={domain}&limit=1&cursor={cursor2}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["events"]) == 1
    assert data["events"][0]["id"] == 3
    # Now we are at EOF, but logic says:
    # We requested limit=1. We got 1. scan_domain tried to peek next, found EOF.
    # So has_more should be False.
    assert data["has_more"] is False
    cursor3 = data["next_cursor"]
    assert cursor3 == 27 # 18 + 9

    # 4. Fetch past end
    resp = client.get(f"/v1/events?domain={domain}&limit=1&cursor={cursor3}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["events"]) == 0
    assert data["has_more"] is False
    # Next cursor should remain same (idempotent)
    assert data["next_cursor"] == cursor3

def test_get_events_boundary_condition(mock_storage):
    """
    Test reading exactly to the end of file with limit > remaining.
    """
    domain = "test.boundary"
    e1 = b'{"id":1}\n'
    e2 = b'{"id":2}\n'
    create_event_file(mock_storage, domain, [e1, e2])

    headers = {"X-Auth": "test-token"}

    # Request limit=5 (more than available)
    resp = client.get(f"/v1/events?domain={domain}&limit=5", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["events"]) == 2
    assert data["has_more"] is False
    assert data["next_cursor"] == 18 # 9+9

def test_get_events_corrupt_line_skip(mock_storage):
    """
    Verifies that corrupt JSON lines are skipped but cursor advances.
    """
    domain = "test.corrupt"
    e1 = b'{"id":1}\n'
    e2 = b'BROKEN_JSON\n' # 12 bytes
    e3 = b'{"id":3}\n'
    create_event_file(mock_storage, domain, [e1, e2, e3])

    headers = {"X-Auth": "test-token"}

    # Fetch all
    resp = client.get(f"/v1/events?domain={domain}&limit=10", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    # Should get e1 and e3. e2 skipped.
    assert len(data["events"]) == 2
    assert data["events"][0]["id"] == 1
    assert data["events"][1]["id"] == 3
    assert data["next_cursor"] == 30 # 9 + 12 + 9

def test_get_events_partial_line_at_eof(mock_storage):
    """
    Verifies that a partial line (no newline) at EOF is NOT consumed.
    """
    domain = "test.partial"
    e1 = b'{"id":1}\n'
    e_partial = b'{"id":2}' # No newline
    create_event_file(mock_storage, domain, [e1, e_partial])

    headers = {"X-Auth": "test-token"}

    # Fetch
    resp = client.get(f"/v1/events?domain={domain}&limit=10", headers=headers)
    data = resp.json()

    # Should only return e1
    assert len(data["events"]) == 1
    assert data["events"][0]["id"] == 1
    # Next cursor should point to start of e_partial (9), NOT end of e_partial
    # Because e_partial was effectively ignored/invisible to scan_domain logic
    # that demands newlines.
    assert data["next_cursor"] == 9
    assert data["has_more"] is False

def test_get_events_idempotency_at_eof(mock_storage):
    """
    Verifies that repeated calls at EOF return stable cursor and no events.
    """
    domain = "test.idem"
    create_event_file(mock_storage, domain, [b'{"a":1}\n'])

    headers = {"X-Auth": "test-token"}

    # First call
    resp = client.get(f"/v1/events?domain={domain}&limit=1", headers=headers)
    cursor = resp.json()["next_cursor"]

    # Second call
    resp2 = client.get(f"/v1/events?domain={domain}&limit=1&cursor={cursor}", headers=headers)
    data2 = resp2.json()
    assert len(data2["events"]) == 0
    assert data2["next_cursor"] == cursor
    assert data2["has_more"] is False

def test_get_events_empty_file(mock_storage):
    domain = "test.empty"
    create_event_file(mock_storage, domain, [])

    headers = {"X-Auth": "test-token"}

    resp = client.get(f"/v1/events?domain={domain}", headers=headers)
    data = resp.json()
    assert len(data["events"]) == 0
    assert data["next_cursor"] == 0
    assert data["has_more"] is False

# --- Ingest & Auth Tests (Restored) ---

def test_ingest_auth_ok(mock_storage):
    secret = "test-token"
    # mock_storage fixture already sets env var
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": secret}, json={"data": "value"}
    )
    assert response.status_code == 202
    assert response.text == "ok"


def test_ingest_auth_fail(mock_storage):
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": "wrong"}, json={"data": "value"}
    )
    assert response.status_code == 401


def test_ingest_auth_missing(mock_storage):
    response = client.post("/ingest/example.com", json={"data": "value"})
    assert response.status_code == 401


def test_sanitize_domain_ok():
    from app import _sanitize_domain
    assert _sanitize_domain("example.com") == "example.com"
    assert _sanitize_domain(" ex-ample.com ") == "ex-ample.com"


def test_sanitize_domain_bad():
    from app import _sanitize_domain
    with pytest.raises(Exception):
        _sanitize_domain("example_com")
    with pytest.raises(Exception):
        _sanitize_domain("example.com_")


def test_ingest_single_object(mock_storage, tmp_path):
    secret = "test-token"
    domain = "example.com"
    payload = {"data": "value"}
    response = client.post(
        f"/ingest/{domain}", headers={"X-Auth": secret}, json=payload
    )
    assert response.status_code == 202
    assert response.text == "ok"

    # Verify file content
    files = [f for f in tmp_path.iterdir() if f.name.endswith(".jsonl")]
    assert len(files) == 1
    target_file = files[0]
    with open(target_file, "r") as f:
        line = f.readline()
        data = json.loads(line)
        assert "received_at" in data
        assert data["domain"] == domain
        assert data["payload"] == payload


def test_health_endpoint(mock_storage):
    secret = "test-token"
    response = client.get("/health", headers={"X-Auth": secret})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_version_endpoint(mock_storage, monkeypatch):
    secret = "test-token"
    monkeypatch.setattr("app.VERSION", "1.2.3")
    response = client.get("/version", headers={"X-Auth": secret})
    assert response.status_code == 200
    assert response.json() == {"version": "1.2.3"}
