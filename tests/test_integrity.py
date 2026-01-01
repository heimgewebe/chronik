
import pytest
from fastapi.testclient import TestClient

# Use monkeypatch to point storage.DATA_DIR to a tmp_path
@pytest.fixture(autouse=True)
def mock_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)

from app import app

@pytest.fixture
def client(mock_env):
    return TestClient(app)

def test_integrity_ingest_and_view(client):
    headers = {"X-Auth": "test-token"}

    # 1. Ingest integrity event for repo A
    repo_a_payload = {
        "domain": "integrity.repo-a",
        "kind": "integrity.summary.published.v1",
        "repo": "repo-a",
        "status": "OK",
        "url": "https://example.com/repo-a/summary.json"
    }
    resp = client.post("/v1/ingest", json=repo_a_payload, headers=headers)
    assert resp.status_code == 202

    # 2. Ingest integrity event for repo B
    repo_b_payload = {
        "domain": "integrity.repo-b",
        "kind": "integrity.summary.published.v1",
        "repo": "repo-b",
        "status": "MISSING",
        "url": "https://example.com/repo-b/summary.json"
    }
    resp = client.post("/v1/ingest", json=repo_b_payload, headers=headers)
    assert resp.status_code == 202

    # 3. Ingest junk event (wrong kind) -> should be ignored in view
    junk_payload = {
        "domain": "integrity.junk",
        "kind": "some.other.event",
        "repo": "junk-repo",
        "status": "FAIL"
    }
    resp = client.post("/v1/ingest", json=junk_payload, headers=headers)
    assert resp.status_code == 202

    # 4. Verify they are stored in separate domains (index by repo)
    # We can check via /v1/latest
    resp = client.get("/v1/latest?domain=integrity.repo-a", headers=headers)
    assert resp.status_code == 200
    data_a = resp.json()
    assert data_a["domain"] == "integrity.repo-a"
    assert data_a["payload"]["repo"] == "repo-a"

    resp = client.get("/v1/latest?domain=integrity.repo-b", headers=headers)
    assert resp.status_code == 200
    data_b = resp.json()
    assert data_b["payload"]["repo"] == "repo-b"

    # 5. Check the aggregate view
    resp = client.get("/v1/integrity", headers=headers)
    assert resp.status_code == 200
    view = resp.json()

    assert "integrity.repo-a" in view
    assert "integrity.repo-b" in view
    assert "integrity.junk" not in view  # Should be filtered out

    assert view["integrity.repo-a"]["payload"]["status"] == "OK"
    assert view["integrity.repo-b"]["payload"]["status"] == "MISSING"

    # 6. Update repo A
    repo_a_update = {
        "domain": "integrity.repo-a",
        "kind": "integrity.summary.published.v1",
        "repo": "repo-a",
        "status": "FAIL",
        "url": "https://example.com/repo-a/summary.json"
    }
    client.post("/v1/ingest", json=repo_a_update, headers=headers)

    # Check view again
    resp = client.get("/v1/integrity", headers=headers)
    view = resp.json()
    assert view["integrity.repo-a"]["payload"]["status"] == "FAIL"
    # Repo B should remain MISSING
    assert view["integrity.repo-b"]["payload"]["status"] == "MISSING"
