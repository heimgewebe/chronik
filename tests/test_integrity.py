import pytest
import json
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from datetime import datetime, timezone, timedelta

# Fixtures
@pytest.fixture(autouse=True)
def mock_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    monkeypatch.setenv("CHRONIK_INTEGRITY_ENABLED", "0")

@pytest.fixture
def client(mock_env):
    from app import app
    return TestClient(app)

# Helper for unified mocking
def create_mock_response(json_data, status_code=200):
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data
    return mock

# 1. Full Sync Flow (Validation, Filtering, Normalization, Saving)
@pytest.mark.asyncio
async def test_integrity_core_sync_flow(monkeypatch, tmp_path):
    # Setup
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from integrity import IntegrityManager
    from storage import read_last_line, sanitize_domain

    sources_url = "https://meta.repo/sources.json"
    repo_ok = "heimgewebe/ok-repo"
    repo_bad = "heimgewebe/bad-repo" # e.g. status UNKNOWN -> UNCLEAR

    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [
            {"repo": repo_ok, "summary_url": f"https://{repo_ok}/summary.json", "enabled": True},
            {"repo": repo_bad, "summary_url": f"https://{repo_bad}/summary.json", "enabled": True},
            {"repo": "skip/me", "summary_url": "...", "enabled": False}
        ]
    }

    async def mock_handler(url, *args, **kwargs):
        if url == sources_url:
            return create_mock_response(sources_data)
        if repo_ok in url:
            return create_mock_response({
                "repo": repo_ok, "status": "OK", "generated_at": "2023-01-01T10:00:00Z"
            })
        if repo_bad in url:
            return create_mock_response({
                "repo": repo_bad, "status": "UNKNOWN_STATUS", "generated_at": "2023-01-01T10:00:00Z"
            })
        return create_mock_response({}, 404)

    test_manager = IntegrityManager()
    test_manager.sources_url = sources_url

    with patch("httpx.AsyncClient.get", side_effect=mock_handler):
        await test_manager.sync_all()

    # Verify OK Repo
    line = read_last_line(sanitize_domain(f"integrity.{repo_ok.replace('/', '.')}"))
    assert line
    data = json.loads(line)
    assert data["payload"]["status"] == "OK"
    assert data["payload"]["repo"] == repo_ok

    # Verify UNCLEAR Repo (Normalization)
    line = read_last_line(sanitize_domain(f"integrity.{repo_bad.replace('/', '.')}"))
    assert line
    data = json.loads(line)
    assert data["payload"]["status"] == "UNCLEAR"

# 2. Overwrite Protection & Stability
@pytest.mark.asyncio
async def test_integrity_overwrite_protection(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from integrity import IntegrityManager
    from storage import write_payload, read_last_line, sanitize_domain

    repo = "heimgewebe/stable"
    domain = sanitize_domain(f"integrity.{repo.replace('/', '.')}")

    # Initial State: Valid, Recent
    initial_ts = "2023-01-02T12:00:00Z"
    write_payload(domain, [json.dumps({
        "domain": domain,
        "kind": "integrity.summary.published.v1",
        "received_at": initial_ts,
        "payload": {"repo": repo, "status": "OK", "generated_at": initial_ts}
    })])

    # Scenario A: Fetch Fails -> Preserve State
    # Scenario B: Old Timestamp -> Skip Update

    async def mock_handler(url, *args, **kwargs):
        if "sources" in url:
             return create_mock_response({
                "apiVersion": "integrity.sources.v1", "generated_at": "2023-01-01T00:00:00Z",
                "sources": [{"repo": repo, "summary_url": "http://summary", "enabled": True}]
             })
        if "summary" in url:
            # Return OLDER timestamp
            return create_mock_response({
                "repo": repo, "status": "FAIL", "generated_at": "2020-01-01T00:00:00Z"
            })
        return create_mock_response({}, 404)

    test_manager = IntegrityManager()
    test_manager.sources_url = "http://sources"

    with patch("httpx.AsyncClient.get", side_effect=mock_handler):
        await test_manager.sync_all()

    # Assert State Preserved (still OK, still 2023)
    line = read_last_line(domain)
    data = json.loads(line)
    assert data["payload"]["status"] == "OK"
    assert data["payload"]["generated_at"] == initial_ts

# 3. Invalid Timestamps (Future/Corrupt)
@pytest.mark.asyncio
async def test_integrity_invalid_timestamp_handling(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from integrity import IntegrityManager
    from storage import read_last_line, sanitize_domain

    repo = "heimgewebe/future"
    future_ts = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    async def mock_handler(url, *args, **kwargs):
        if "sources" in url:
             return create_mock_response({
                "apiVersion": "integrity.sources.v1", "generated_at": "2023-01-01T00:00:00Z",
                "sources": [{"repo": repo, "summary_url": "http://summary", "enabled": True}]
             })
        # Future timestamp
        return create_mock_response({
            "repo": repo, "status": "OK", "generated_at": future_ts
        })

    test_manager = IntegrityManager()
    test_manager.sources_url = "http://sources"

    with patch("httpx.AsyncClient.get", side_effect=mock_handler):
        await test_manager.sync_all()

    # Assert FAIL status and Sanitized Timestamp
    line = read_last_line(sanitize_domain(f"integrity.{repo.replace('/', '.')}"))
    data = json.loads(line)
    assert data["payload"]["status"] == "FAIL"
    assert data["payload"]["generated_at_sanitized"] is True
    assert data["meta"]["error_reason"] == "Future timestamp detected"

# 4. API Aggregation View
def test_integrity_api_aggregate_view(client, monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import write_payload, sanitize_domain

    # Data Setup
    # Repo A: OK
    # Repo B: FAIL
    # Repo C: Legacy Format

    def store(repo, status, kind="integrity.summary.published.v1", legacy_payload=False):
        dom = sanitize_domain(f"integrity.{repo.replace('/', '.')}")
        payload = {"repo": repo, "status": status, "generated_at": "2023-01-01T00:00:00Z"}
        if legacy_payload:
            payload["kind"] = kind
            wrapper_kind = "legacy.wrapper"
        else:
            wrapper_kind = kind

        wrapper = {
            "domain": dom,
            "kind": wrapper_kind,
            "received_at": "2023-01-01T00:00:00Z",
            "payload": payload
        }
        write_payload(dom, [json.dumps(wrapper)])

    store("heimgewebe/a", "OK")
    store("heimgewebe/b", "FAIL")
    store("heimgewebe/c", "OK", legacy_payload=True) # Legacy

    from app import app
    with TestClient(app) as tc:
        resp = tc.get("/v1/integrity", headers={"X-Auth": "test-token"})
        assert resp.status_code == 200
        data = resp.json()

    assert data["total_status"] == "FAIL" # Worst of OK, FAIL, OK
    assert len(data["repos"]) == 3

    repos = {r["repo"]: r for r in data["repos"]}
    assert repos["heimgewebe/a"]["status"] == "OK"
    assert repos["heimgewebe/b"]["status"] == "FAIL"
    assert repos["heimgewebe/c"]["legacy"] is True

def test_integrity_legacy_payload_type(client, monkeypatch, tmp_path):
    # Verify strict backward compatibility for payload.type
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import write_payload, sanitize_domain

    repo = "heimgewebe/legacy-type"
    dom = sanitize_domain(f"integrity.{repo.replace('/', '.')}")

    # Store legacy event where payload has "type" but not "kind"
    # wrapper kind is generic or missing (simulating old ingestion)
    wrapper = {
        "domain": dom,
        "kind": "generic.wrapper",
        "received_at": "2023-01-01T00:00:00Z",
        "payload": {
            "type": "integrity.summary.published.v1",
            "repo": repo,
            "status": "OK",
            "generated_at": "2023-01-01T00:00:00Z"
        }
    }
    write_payload(dom, [json.dumps(wrapper)])

    from app import app
    with TestClient(app) as tc:
        resp = tc.get("/v1/integrity", headers={"X-Auth": "test-token"})
        assert resp.status_code == 200
        data = resp.json()

    # Should be included and marked legacy
    repos = {r["repo"]: r for r in data["repos"]}
    assert repo in repos
    assert repos[repo]["status"] == "OK"
    assert repos[repo]["legacy"] is True
