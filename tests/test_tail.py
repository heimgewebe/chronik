
import json
import secrets
import time
import os

import pytest
from fastapi.testclient import TestClient
from filelock import FileLock

import storage

@pytest.fixture(autouse=True)
def mock_storage(monkeypatch, tmp_path):
    # Isolate DATA_DIR for all tests
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    # Ensure app import does not depend on external shell/CI env.
    # app.py requires CHRONIK_TOKEN at import time (per existing test comment).
    # Set a deterministic value here so tests are hermetic.
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    return tmp_path

@pytest.fixture
def client():
    # Import app only after DATA_DIR isolation is active (autouse fixture)
    import app as app_module
    with TestClient(app_module.app) as c:
        yield c

@pytest.fixture
def auth_header():
    return {"X-Auth": os.environ["CHRONIK_TOKEN"]}

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
    assert "X-Chronik-Last-Seen-TS" in response.headers

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
    # last seen should be empty (no ts fields in this dataset)
    assert response.headers["X-Chronik-Last-Seen-TS"] == ""

    # Read back limited
    response = client.get(f"/v1/tail?domain={domain}&limit=5", headers=auth_header)
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 5
    assert results == data[5:]  # Last 5 items
    assert response.headers["X-Chronik-Lines-Returned"] == "5"
    assert "X-Chronik-Last-Seen-TS" in response.headers

def test_tail_since_filter(client, auth_header):
    domain = f"test-since-{secrets.token_hex(4)}"
    # Events with timestamps
    events = [
        {"ts": "2023-01-01T10:00:00Z", "id": 1},
        {"ts": "2023-01-01T11:00:00Z", "id": 2},
        {"ts": "2023-01-01T12:00:00Z", "id": 3},
    ]
    storage.write_payload(domain, [json.dumps(e) for e in events])

    # Since 10:30 -> should match id 2 and 3
    response = client.get(
        f"/v1/tail?domain={domain}&since=2023-01-01T10:30:00Z", headers=auth_header
    )
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 2
    assert results[0]["id"] == 2
    assert results[1]["id"] == 3

    # Invalid since format
    response = client.get(
        f"/v1/tail?domain={domain}&since=invalid-ts", headers=auth_header
    )
    assert response.status_code == 400
    assert "invalid since format" in response.text

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
    assert "X-Chronik-Last-Seen-TS" in response.headers

def test_tail_last_seen_ts_header(client, auth_header):
    domain = f"test-ts-{secrets.token_hex(4)}"
    # Mix ts + timestamp; header should reflect the max
    storage.write_payload(
        domain,
        [
            json.dumps({"event": "a", "status": "ok", "ts": "2023-01-01T00:00:00Z"}),
            json.dumps({"event": "b", "status": "ok", "timestamp": "2023-01-03T12:00:00Z"}),
            json.dumps({"event": "c", "status": "ok", "ts": "2023-01-02T00:00:00+00:00"}),
        ],
    )
    response = client.get(f"/v1/tail?domain={domain}&limit=50", headers=auth_header)
    assert response.status_code == 200
    # We only check that it's non-empty and contains the newest day "2023-01-03"
    # (exact formatting includes +00:00 due to fromisoformat normalization)
    last_seen = response.headers["X-Chronik-Last-Seen-TS"]
    assert last_seen != ""
    assert "2023-01-03" in last_seen

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
