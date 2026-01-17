
import pytest
import json
import os
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient

# Use monkeypatch to point storage.DATA_DIR to a tmp_path
@pytest.fixture(autouse=True)
def mock_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    # Prevent the real loop from running in background during tests if app is imported
    # But app lifespan starts it. We can patch IntegrityManager.loop
    pass

from app import app
from integrity import IntegrityManager, manager

@pytest.fixture
def client(mock_env):
    return TestClient(app)

@pytest.mark.asyncio
async def test_integrity_sync_success(monkeypatch, tmp_path):
    # Setup Override for sources
    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "sources": [
            {
                "repo": "heimgewebe/wgx",
                "summary_url": "https://example.com/wgx/summary.json",
                "enabled": True
            }
        ]
    }

    summary_data = {
        "repo": "heimgewebe/wgx",
        "status": "OK",
        "generated_at": "2023-01-01T00:00:00Z"
    }

    # Setup mocks
    mock_get = AsyncMock()
    # First call (sources) is skipped if we use override, or we can mock URL fetch
    # Let's mock the URL fetch for summary
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get.return_value = mock_response

    # Instantiate a fresh manager to test logic isolated
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    # Verify storage
    from storage import read_last_line, sanitize_domain
    # heimgewebe/wgx -> integrity.heimgewebe.wgx
    domain = "integrity.heimgewebe.wgx"
    line = read_last_line(domain)
    assert line is not None
    data = json.loads(line)
    assert data["domain"] == domain
    assert data["payload"]["repo"] == "heimgewebe/wgx"
    assert data["payload"]["status"] == "OK"
    assert data["payload"]["kind"] == "integrity.summary.published.v1"
    assert data["payload"]["url"] == "https://example.com/wgx/summary.json"


def test_integrity_view_aggregate(client):
    headers = {"X-Auth": "test-token"}

    # 1. Ingest integrity event manually to simulate stored state
    # (Since we tested sync separately)
    repo_a_payload = {
        "domain": "integrity.repo-a",
        "kind": "integrity.summary.published.v1",
        "repo": "repo-a",
        "status": "OK",
        "url": "https://example.com/repo-a/summary.json"
    }
    client.post("/v1/ingest", json=repo_a_payload, headers=headers)

    repo_b_payload = {
        "domain": "integrity.repo-b",
        "kind": "integrity.summary.published.v1",
        "repo": "repo-b",
        "status": "WARN",
        "url": "https://example.com/repo-b/summary.json"
    }
    client.post("/v1/ingest", json=repo_b_payload, headers=headers)

    # 2. Get View
    resp = client.get("/v1/integrity", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert "total_status" in data
    assert "repos" in data

    # OK + WARN -> WARN (worst of)
    assert data["total_status"] == "WARN"

    repos = data["repos"]
    assert len(repos) == 2

    # Sort order is by repo name
    assert repos[0]["repo"] == "repo-a"
    assert repos[0]["status"] == "OK"
    assert repos[1]["repo"] == "repo-b"
    assert repos[1]["status"] == "WARN"

def test_integrity_view_missing_handling(client):
    headers = {"X-Auth": "test-token"}

    # Ingest a MISSING status
    payload = {
        "domain": "integrity.repo-c",
        "kind": "integrity.summary.published.v1",
        "repo": "repo-c",
        "status": "MISSING",
    }
    client.post("/v1/ingest", json=payload, headers=headers)

    resp = client.get("/v1/integrity", headers=headers)
    data = resp.json()

    assert data["total_status"] == "MISSING"
    assert data["repos"][0]["status"] == "MISSING"

def test_integrity_view_ignores_junk(client):
    headers = {"X-Auth": "test-token"}

    # Ingest junk
    payload = {
        "domain": "integrity.junk",
        "kind": "some.other.kind",
        "repo": "junk",
        "status": "FAIL"
    }
    client.post("/v1/ingest", json=payload, headers=headers)

    resp = client.get("/v1/integrity", headers=headers)
    data = resp.json()

    # Should be empty if only junk exists (default total_status OK? or None?)
    # Implementation says defaults: total_status="OK", repos=[]
    assert data["total_status"] == "OK"
    assert len(data["repos"]) == 0
