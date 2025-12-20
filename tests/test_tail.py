
import json
import os
import secrets
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from filelock import FileLock

import storage
from app import app, SECRET

# Setup for testing
@pytest.fixture(scope="module")
def client():
    # Ensure CHRONIK_TOKEN is set for app import (already done if app is imported)
    # We use TestClient which makes requests to the app
    with TestClient(app) as c:
        yield c

@pytest.fixture
def auth_header():
    return {"X-Auth": SECRET}

@pytest.fixture(autouse=True)
def mock_storage(monkeypatch, tmp_path):
    # Isolate DATA_DIR for all tests
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    return tmp_path

def test_tail_auth_required(client):
    response = client.get("/v1/tail?domain=test-auth", headers={})
    assert response.status_code == 401

    response = client.get("/v1/tail?domain=test-auth", headers={"X-Auth": "wrong"})
    assert response.status_code == 401

def test_tail_limit_bounds(client, auth_header):
    # Test limit < 1
    response = client.get("/v1/tail?domain=test-limit&limit=0", headers=auth_header)
    assert response.status_code == 400
    assert "limit must be >= 1" in response.text

    # Test limit > 2000
    response = client.get("/v1/tail?domain=test-limit&limit=2001", headers=auth_header)
    assert response.status_code == 400
    assert "limit must be <= 2000" in response.text

def test_tail_non_existent_domain(client, auth_header):
    domain = f"test-missing-{secrets.token_hex(4)}"
    response = client.get(f"/v1/tail?domain={domain}", headers=auth_header)
    assert response.status_code == 200
    assert response.json() == []
    assert response.headers["X-Chronik-Lines-Returned"] == "0"
    assert response.headers["X-Chronik-Lines-Dropped"] == "0"

def test_tail_valid_data(client, auth_header):
    domain = f"test-valid-{secrets.token_hex(4)}"

    # Write some data
    data = [{"msg": f"msg {i}"} for i in range(10)]
    storage.write_payload(domain, [json.dumps(d) for d in data])

    # Read back all
    response = client.get(f"/v1/tail?domain={domain}&limit=100", headers=auth_header)
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 10
    assert results == data
    assert response.headers["X-Chronik-Lines-Returned"] == "10"
    assert response.headers["X-Chronik-Lines-Dropped"] == "0"

    # Read back limited
    response = client.get(f"/v1/tail?domain={domain}&limit=5", headers=auth_header)
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 5
    assert results == data[5:]  # Last 5 items
    assert response.headers["X-Chronik-Lines-Returned"] == "5"

def test_tail_corrupt_data(client, auth_header):
    domain = f"test-corrupt-{secrets.token_hex(4)}"

    # Write valid data
    storage.write_payload(domain, [json.dumps({"valid": 1})])

    # Write corrupt data (raw append to simulate corruption)
    path = storage.safe_target_path(domain)
    # We use open with 'a' and encoding utf-8
    with open(path, "a", encoding="utf-8") as f:
        f.write("not json\n")
        f.write("also not json\n")

    # Write more valid data
    storage.write_payload(domain, [json.dumps({"valid": 2})])

    response = client.get(f"/v1/tail?domain={domain}", headers=auth_header)
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 2
    assert results == [{"valid": 1}, {"valid": 2}]
    assert response.headers["X-Chronik-Lines-Returned"] == "2"
    assert response.headers["X-Chronik-Lines-Dropped"] == "2"

def test_tail_concurrency_lock(client, auth_header, monkeypatch):
    domain = f"test-lock-{secrets.token_hex(4)}"
    target_path = storage.safe_target_path(domain)

    # Ensure file exists
    storage.write_payload(domain, ["{}"])

    # Get the lock path using the new helper
    lock_path = storage.get_lock_path(target_path)

    # We reduce timeout to speed up test
    monkeypatch.setattr(storage, "LOCK_TIMEOUT", 0.1)

    with FileLock(str(lock_path)):
        # Now try to read
        start = time.time()
        response = client.get(f"/v1/tail?domain={domain}", headers=auth_header)
        end = time.time()

    assert response.status_code == 429
    assert "busy" in response.text

def test_tail_invalid_domain_traversal(client, auth_header):
    # Test invalid domain (path traversal)
    response = client.get("/v1/tail?domain=../invalid", headers=auth_header)
    assert response.status_code == 400
    assert "invalid domain" in response.text
