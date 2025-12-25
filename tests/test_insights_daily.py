
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

    with TestClient(app.app) as c:
        yield c

def test_ingest_insights_daily_valid(client):
    payload = {
        "ts": "2025-12-25",
        "topics": [["vault", 1.0]],
        "questions": [],
        "deltas": [],
        "source": "semantAH",
        "metadata": { "generated_at": "2025-12-25T09:42:49Z" }
    }
    response = client.post(
        "/v1/ingest?domain=insights.daily",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 202
    assert response.text == "ok"

    # Verify persistence structure
    response = client.get(
        "/v1/tail?domain=insights.daily",
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    item = data[0]

    # Check wrapper fields
    assert item["domain"] == "insights.daily"
    assert "received_at" in item

    # Check payload is 1:1
    assert item["payload"]["ts"] == "2025-12-25"
    assert item["payload"]["source"] == "semantAH"
    assert item["payload"]["topics"] == [["vault", 1.0]]

def test_ingest_insights_daily_invalid_missing_field(client):
    payload = {
        "ts": "2025-12-25",
        "topics": [],
        # Missing questions, deltas, source, metadata
    }
    response = client.post(
        "/v1/ingest?domain=insights.daily",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 400
    assert "schema validation failed" in response.json()["detail"]

def test_ingest_insights_daily_invalid_type(client):
    payload = {
        "ts": 12345, # Should be string
        "topics": [],
        "questions": [],
        "deltas": [],
        "source": "semantAH",
        "metadata": { "generated_at": "2025-12-25T09:42:49Z" }
    }
    response = client.post(
        "/v1/ingest?domain=insights.daily",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 400
    assert "schema validation failed" in response.json()["detail"]

def test_ingest_insights_daily_unknown_property(client):
    # Schema has additionalProperties: false
    payload = {
        "ts": "2025-12-25",
        "topics": [],
        "questions": [],
        "deltas": [],
        "source": "semantAH",
        "metadata": { "generated_at": "2025-12-25T09:42:49Z" },
        "extra_field": "should fail"
    }
    response = client.post(
        "/v1/ingest?domain=insights.daily",
        json=payload,
        headers={"X-Auth": "test-token"}
    )
    assert response.status_code == 400
    assert "schema validation failed" in response.json()["detail"]
