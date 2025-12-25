
import json
import os
import pytest
from fastapi.testclient import TestClient

# We mock storage.DATA_DIR to avoid writing to real disk
from storage import DATA_DIR
import app

@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)

    # Reload app to pick up environment variable changes if any (though here token is runtime lookup)
    # But monkeypatching storage.DATA_DIR in storage module is key.

    with TestClient(app.app) as c:
        yield c

def test_ingest_insights_daily_valid(client):
    payload = {
        "timestamp": "2025-12-25T10:00:00Z",
        "content": "Today was a good day.",
        "type": "daily.insight"
    }
    response = client.post(
        "/v1/ingest?domain=insights.daily",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 202
    assert response.text == "ok"

    # Verify persistence
    response = client.get(
        "/v1/tail?domain=insights.daily",
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["content"] == "Today was a good day."
    assert data[0]["domain"] == "insights.daily"

def test_ingest_insights_daily_invalid_missing_field(client):
    payload = {
        "timestamp": "2025-12-25T10:00:00Z",
        # Missing content
    }
    response = client.post(
        "/v1/ingest?domain=insights.daily",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 400
    assert "missing fields" in response.json()["detail"]

def test_ingest_insights_daily_invalid_timestamp(client):
    payload = {
        "timestamp": "invalid-ts",
        "content": "Content"
    }
    response = client.post(
        "/v1/ingest?domain=insights.daily",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 400
    assert "timestamp must be valid ISO8601" in response.json()["detail"]

def test_ingest_insights_daily_invalid_type(client):
    payload = {
        "timestamp": "2025-12-25T10:00:00Z",
        "content": "Content",
        "type": "wrong.type"
    }
    response = client.post(
        "/v1/ingest?domain=insights.daily",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 400
    assert "invalid type" in response.json()["detail"]

def test_ingest_insights_daily_append_only_order(client):
    # Ingest multiple events
    events = [
        {"timestamp": "2025-12-25T09:00:00Z", "content": "Morning"},
        {"timestamp": "2025-12-25T12:00:00Z", "content": "Noon"},
        {"timestamp": "2025-12-25T18:00:00Z", "content": "Evening"},
    ]
    for e in events:
        response = client.post(
            "/v1/ingest?domain=insights.daily",
            json=e,
            headers={"X-Auth": "test-token"}
        )
        assert response.status_code == 202

    # Read back
    response = client.get(
        "/v1/tail?domain=insights.daily&limit=10",
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    # Check order (tail returns oldest first if I recall correctly, or check implementation)
    # read_tail returns lines. app.py loads them.
    # storage.read_tail reads from end, but returns lines in order they appear in file?
    # Usually tail returns last N lines.
    # Wait, existing `read_tail` implementation reads backwards but reverses chunks?
    # Let's check logic:
    # "The `read_tail` function uses a seek-based reverse reading strategy... strictly requires limit + 1 newlines"
    # Usually `tail` returns lines in the order they were written (chronological), just the last N.

    assert data[0]["content"] == "Morning"
    assert data[1]["content"] == "Noon"
    assert data[2]["content"] == "Evening"
