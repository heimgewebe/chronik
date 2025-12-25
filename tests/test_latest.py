
import os
import pytest
from fastapi.testclient import TestClient

# Must be set before importing app (due to runtime config)
# But here we use monkeypatch fixture or just rely on env not crashing
# In actual tests we patch env.

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    # Patch storage.DATA_DIR in your tests if not already done by auto-fixture
    # (Assuming there's a global conftest or similar, but for safety we check imports)
    from app import app
    return TestClient(app)

@pytest.fixture(autouse=True)
def setup_data_dir(tmp_path, monkeypatch):
    # Patch storage.DATA_DIR to use tmp_path
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)

def test_latest_ok(client, setup_data_dir):
    # 1. Ingest data
    headers = {"X-Auth": "test-token", "Content-Type": "application/json"}
    domain = "latest.test"
    payloads = [
        {"id": "1", "val": "first"},
        {"id": "2", "val": "second"}
    ]

    # Ingest first
    resp = client.post(f"/v1/ingest?domain={domain}", json=payloads[0], headers=headers)
    assert resp.status_code == 202

    # Ingest second
    resp = client.post(f"/v1/ingest?domain={domain}", json=payloads[1], headers=headers)
    assert resp.status_code == 202

    # 2. Get latest
    resp = client.get(f"/v1/latest?domain={domain}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "2"
    assert data["val"] == "second"
    assert data["domain"] == domain

def test_latest_not_found(client):
    headers = {"X-Auth": "test-token"}
    resp = client.get("/v1/latest?domain=does.not.exist", headers=headers)
    # Expect 404 because file doesn't exist
    assert resp.status_code == 404

def test_latest_empty_file(client, setup_data_dir, monkeypatch):
    # Create empty file manually
    domain = "empty.test"
    # We need to compute target path to write empty file
    from storage import safe_target_path
    path = safe_target_path(domain) # Uses monkeypatched DATA_DIR
    path.touch()

    headers = {"X-Auth": "test-token"}
    resp = client.get(f"/v1/latest?domain={domain}", headers=headers)
    assert resp.status_code == 404

def test_latest_invalid_domain(client):
    headers = {"X-Auth": "test-token"}
    resp = client.get("/v1/latest?domain=INVALID_DOMAIN!", headers=headers)
    assert resp.status_code == 400

def test_latest_auth_required(client):
    resp = client.get("/v1/latest?domain=test.com")
    # No auth header
    assert resp.status_code == 401
