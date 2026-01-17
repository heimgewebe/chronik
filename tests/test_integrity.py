import pytest
import json
import os
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from datetime import datetime, timezone, timedelta

# Use monkeypatch to point storage.DATA_DIR to a tmp_path
@pytest.fixture(autouse=True)
def mock_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    # Disable integrity loop in app lifespan by default for tests
    monkeypatch.setenv("CHRONIK_INTEGRITY_ENABLED", "0")

@pytest.fixture
def client(mock_env):
    from app import app
    return TestClient(app)

@pytest.mark.asyncio
async def test_integrity_sync_success(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from integrity import IntegrityManager

    # Setup Override for sources
    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
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

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data

    # Simple AsyncMock that returns the response directly
    mock_get = AsyncMock(return_value=mock_response)

    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    # Patch AsyncClient to return our mock get
    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    from storage import read_last_line, sanitize_domain
    domain = sanitize_domain("integrity.heimgewebe.wgx")
    line = read_last_line(domain)
    assert line is not None
    data = json.loads(line)

    assert data["domain"] == domain
    assert data["kind"] == "integrity.summary.published.v1"

    payload = data["payload"]
    assert payload["repo"] == "heimgewebe/wgx"
    assert payload["status"] == "OK"
    assert "kind" not in payload

@pytest.mark.asyncio
async def test_integrity_sources_validation_filtering(monkeypatch, tmp_path):
    # Test that invalid source items are filtered out
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)

    # Mix of valid and invalid sources
    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [
            {"repo": "valid/repo", "summary_url": "http://ok", "enabled": True},
            {"repo": "", "summary_url": "http://bad-repo"},  # Invalid repo
            {"repo": "no/url", "summary_url": ""},           # Invalid URL
            {"repo": "bad/enabled", "summary_url": "http://skip", "enabled": "not-bool"}, # Invalid enabled type
            {"not-a-dict": True}                             # Invalid type
        ]
    }

    # Mock only the valid one being fetched
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "OK", "repo": "valid/repo"}
    mock_get = AsyncMock(return_value=mock_response)

    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    # Verify only 1 call was made (for the valid source)
    assert mock_get.call_count == 1
    args, _ = mock_get.call_args
    assert args[0] == "http://ok"

@pytest.mark.asyncio
async def test_integrity_sources_invalid_generated_at(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)

    # Missing generated_at
    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "sources": [{"repo": "repo", "summary_url": "http://url"}]
    }

    mock_get = AsyncMock()
    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    # Should have rejected sources entirely, so no fetches made
    assert mock_get.call_count == 0

@pytest.mark.asyncio
async def test_integrity_status_normalization(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import read_last_line, sanitize_domain

    repo = "heimgewebe/wgx"
    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    summary_data = {
        "repo": repo,
        "status": "GREEN",
        "generated_at": "2023-01-01T00:00:00Z"
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get = AsyncMock(return_value=mock_response)

    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    domain = sanitize_domain(f"integrity.{repo.replace('/', '.')}")
    line = read_last_line(domain)
    data = json.loads(line)
    assert data["payload"]["status"] == "UNCLEAR"

@pytest.mark.asyncio
async def test_integrity_no_overwrite_old(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import write_payload, sanitize_domain

    repo = "heimgewebe/wgx"
    domain = sanitize_domain("integrity.heimgewebe.wgx")

    # 1. Write newer entry
    existing_wrapper = {
        "domain": domain,
        "kind": "integrity.summary.published.v1",
        "received_at": "2023-01-02T12:00:00Z",
        "payload": {
            "repo": repo,
            "status": "OK",
            "generated_at": "2023-01-02T10:00:00Z",
            "url": "..."
        }
    }
    write_payload(domain, [json.dumps(existing_wrapper)])

    # 2. Sync with older report
    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    summary_data = {
        "repo": repo,
        "status": "FAIL",
        "generated_at": "2023-01-01T10:00:00Z",
        "url": "..."
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get = AsyncMock(return_value=mock_response)

    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    # 3. Verify NOT overwritten
    from storage import read_last_line
    line = read_last_line(domain)
    data = json.loads(line)
    assert data["payload"]["status"] == "OK"
    assert data["payload"]["generated_at"] == "2023-01-02T10:00:00Z"

@pytest.mark.asyncio
async def test_integrity_skip_on_equal_timestamp(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import write_payload, sanitize_domain

    repo = "heimgewebe/wgx"
    domain = sanitize_domain("integrity.heimgewebe.wgx")
    ts = "2023-01-02T10:00:00Z"

    # 1. Write existing entry
    existing_wrapper = {
        "domain": domain,
        "kind": "integrity.summary.published.v1",
        "received_at": "2023-01-02T10:00:00Z",
        "payload": {
            "repo": repo,
            "status": "OK",
            "generated_at": ts,
            "url": "..."
        }
    }
    write_payload(domain, [json.dumps(existing_wrapper)])

    # 2. Sync with same timestamp but different status
    # Expectation: Should SKIP update because timestamp is equal (stable logic)
    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    summary_data = {
        "repo": repo,
        "status": "FAIL",
        "generated_at": ts,
        "url": "..."
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get = AsyncMock(return_value=mock_response)

    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    # 3. Verify NOT overwritten (status remains OK)
    from storage import read_last_line
    line = read_last_line(domain)
    data = json.loads(line)
    assert data["payload"]["status"] == "OK"
    assert data["payload"]["generated_at"] == ts

@pytest.mark.asyncio
async def test_integrity_future_timestamp_handling(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import write_payload, sanitize_domain

    repo = "heimgewebe/wgx"
    domain = sanitize_domain("integrity.heimgewebe.wgx")

    # 1. Future timestamp (way in future) in strict Z format
    future_ts = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    summary_data = {
        "repo": repo,
        "status": "OK",
        "generated_at": future_ts,
        "url": "..."
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get = AsyncMock(return_value=mock_response)

    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    # Configure tolerance to verify config usage (default is 10)
    test_manager.future_tolerance_min = 5
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    # Verify stored as FAIL and normalized timestamp
    from storage import read_last_line
    line = read_last_line(domain)
    data = json.loads(line)
    assert data["payload"]["status"] == "FAIL"
    # Should not be the future timestamp
    assert data["payload"]["generated_at"] != future_ts
    assert data["meta"]["error_reason"] == "Future timestamp detected"


@pytest.mark.asyncio
async def test_integrity_no_overwrite_invalid_timestamp(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import write_payload, sanitize_domain

    repo = "heimgewebe/wgx"
    domain = sanitize_domain("integrity.heimgewebe.wgx")

    # Existing valid state
    existing_wrapper = {
        "domain": domain,
        "kind": "integrity.summary.published.v1",
        "received_at": "2023-01-02T12:00:00Z",
        "payload": {
            "repo": repo,
            "status": "OK",
            "generated_at": "2023-01-02T10:00:00Z",
            "url": "..."
        }
    }
    write_payload(domain, [json.dumps(existing_wrapper)])

    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    # Invalid generated_at
    summary_data = {
        "repo": repo,
        "status": "FAIL",
        "generated_at": "yolo-timestamp",
        "url": "..."
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get = AsyncMock(return_value=mock_response)

    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    # Verify not overwritten
    from storage import read_last_line
    line = read_last_line(domain)
    data = json.loads(line)
    assert data["payload"]["status"] == "OK"
    assert data["payload"]["generated_at"] == "2023-01-02T10:00:00Z"

@pytest.mark.asyncio
async def test_integrity_write_invalid_timestamp_if_empty(monkeypatch, tmp_path):
    # If no previous state exists, we should write the fail status but normalize timestamp
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import read_last_line, sanitize_domain

    repo = "heimgewebe/wgx"
    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    summary_data = {
        "repo": repo,
        "status": "OK", # Should become FAIL because timestamp invalid
        "generated_at": "yolo-timestamp",
        "url": "..."
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get = AsyncMock(return_value=mock_response)

    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    domain = sanitize_domain(f"integrity.{repo.replace('/', '.')}")
    line = read_last_line(domain)
    data = json.loads(line)

    # Status should be FAIL (due to invalid ts)
    assert data["payload"]["status"] == "FAIL"
    # Generated at should be normalized (to received_at, effectively ISO)
    assert data["payload"]["generated_at"] != "yolo-timestamp"
    # Just check it's ISO-like
    assert "T" in data["payload"]["generated_at"]
    # Path B: Explicitly marked as sanitized
    assert data["payload"]["generated_at_sanitized"] is True
    assert data["meta"]["error_reason"] == "Invalid timestamp format"

@pytest.mark.asyncio
async def test_integrity_valid_timestamp_no_sanitized_flag(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import read_last_line, sanitize_domain

    repo = "heimgewebe/wgx"
    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    summary_data = {
        "repo": repo,
        "status": "OK",
        "generated_at": "2023-01-01T12:00:00Z",
        "url": "..."
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get = AsyncMock(return_value=mock_response)

    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    domain = sanitize_domain(f"integrity.{repo.replace('/', '.')}")
    line = read_last_line(domain)
    data = json.loads(line)

    assert data["payload"]["status"] == "OK"
    assert data["payload"]["generated_at"] == "2023-01-01T12:00:00Z"
    # Flag must be absent
    assert "generated_at_sanitized" not in data["payload"]

@pytest.mark.asyncio
async def test_integrity_fetch_failure_preserves_state(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import write_payload, sanitize_domain

    repo = "heimgewebe/wgx"
    domain = sanitize_domain("integrity.heimgewebe.wgx")

    # 1. Existing OK state
    existing_wrapper = {
        "domain": domain,
        "kind": "integrity.summary.published.v1",
        "received_at": "2023-01-02T12:00:00Z",
        "payload": {
            "repo": repo,
            "status": "OK",
            "generated_at": "2023-01-02T10:00:00Z",
            "url": "..."
        }
    }
    write_payload(domain, [json.dumps(existing_wrapper)])

    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }

    # Simulate Fetch Failure (Exception)
    mock_get = AsyncMock(side_effect=Exception("Network down"))

    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    # Verify existing OK state persists (no overwrite with MISSING)
    from storage import read_last_line
    line = read_last_line(domain)
    data = json.loads(line)
    assert data["payload"]["status"] == "OK"


@pytest.mark.asyncio
async def test_integrity_json_failure_is_fail(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import read_last_line, sanitize_domain

    repo = "heimgewebe/wgx"
    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }

    # Simulate 200 but garbage JSON (httpx.Response.json raises ValueError)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = ValueError("Bad JSON")
    mock_get = AsyncMock(return_value=mock_response)

    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    domain = sanitize_domain("integrity.heimgewebe.wgx")
    line = read_last_line(domain)
    data = json.loads(line)

    # Should be FAIL (not MISSING)
    assert data["payload"]["status"] == "FAIL"
    # Check meta error reason
    assert "meta" in data
    assert "error_reason" in data["meta"]
    assert "Invalid JSON" in data["meta"]["error_reason"]

@pytest.mark.asyncio
async def test_integrity_missing_repo_is_fail(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import read_last_line, sanitize_domain

    repo = "heimgewebe/wgx"
    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }

    # Missing repo in report
    summary_data = {
        "status": "OK",
        "generated_at": "2023-01-01T00:00:00Z",
        # "repo" missing
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get = AsyncMock(return_value=mock_response)

    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    domain = sanitize_domain(f"integrity.{repo.replace('/', '.')}")
    line = read_last_line(domain)
    data = json.loads(line)

    # Should be FAIL due to missing contract field
    assert data["payload"]["status"] == "FAIL"
    # Check meta error reason
    assert "meta" in data
    assert data["meta"]["error_reason"] == "Missing or empty repo in report"
    # Repo backfilled from source for identification
    assert data["payload"]["repo"] == repo

@pytest.mark.asyncio
async def test_integrity_unknown_status_is_unclear(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import read_last_line, sanitize_domain

    repo = "heimgewebe/wgx"
    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    summary_data = {
        "repo": repo,
        "status": "WEIRD",
        "generated_at": "2023-01-01T00:00:00Z"
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get = AsyncMock(return_value=mock_response)

    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    domain = sanitize_domain(f"integrity.{repo.replace('/', '.')}")
    line = read_last_line(domain)
    data = json.loads(line)
    assert data["payload"]["status"] == "UNCLEAR"

@pytest.mark.asyncio
async def test_integrity_corrupt_current_state_overwritten(monkeypatch, tmp_path):
    # If existing data is corrupt JSON, overwrite with valid new state
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import write_payload, sanitize_domain

    repo = "heimgewebe/wgx"
    domain = sanitize_domain("integrity.heimgewebe.wgx")

    # Write garbage to domain, ensuring newline so next write appends to new line
    # storage.write_payload appends. read_last_line reads last line.
    from storage import safe_target_path
    path = safe_target_path(domain)
    with open(path, "w") as f:
        f.write("{garbage-json\n")

    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "generated_at": "2023-01-01T00:00:00Z",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    summary_data = {
        "repo": repo,
        "status": "OK",
        "generated_at": "2023-01-01T12:00:00Z",
        "url": "..."
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get = AsyncMock(return_value=mock_response)

    from integrity import IntegrityManager
    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        await test_manager.sync_all()

    from storage import read_last_line
    line = read_last_line(domain)
    data = json.loads(line)
    assert data["payload"]["status"] == "OK"

def test_integrity_view_aggregate(client, monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import write_payload, sanitize_domain
    headers = {"X-Auth": "test-token"}

    # 1. Manually write stored state with proper Envelope
    def store_integrity(repo, status):
        dom = sanitize_domain(f"integrity.{repo.replace('/', '.')}")
        wrapper = {
            "domain": dom,
            "kind": "integrity.summary.published.v1",
            "received_at": "2023-01-01T00:00:00Z",
            "payload": {
                "repo": repo,
                "status": status,
                "generated_at": "2023-01-01T00:00:00Z",
                "url": "http://foo"
            }
        }
        write_payload(dom, [json.dumps(wrapper)])

    store_integrity("repo-a", "OK")
    store_integrity("repo-b", "WARN")

    # 2. Get View - This uses app.state.integrity_manager
    # Ensure client context manages lifespan
    from app import app
    with TestClient(app) as client:
        resp = client.get("/v1/integrity", headers=headers)
        assert resp.status_code == 200
        data = resp.json()

    assert "as_of" in data
    assert data["total_status"] == "WARN"
    repos = data["repos"]
    assert len(repos) == 2
    assert repos[0]["repo"] == "repo-a"
    assert repos[1]["repo"] == "repo-b"

def test_integrity_view_empty_is_missing(client, monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    headers = {"X-Auth": "test-token"}

    # No data ingested
    from app import app
    with TestClient(app) as client:
        resp = client.get("/v1/integrity", headers=headers)
        data = resp.json()

        assert data["total_status"] == "MISSING"
        assert len(data["repos"]) == 0
        assert "as_of" in data

def test_integrity_view_ignores_junk_kind(client, monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import write_payload, sanitize_domain
    headers = {"X-Auth": "test-token"}

    # Ingest junk kind
    dom = sanitize_domain("integrity.junk")
    wrapper = {
        "domain": dom,
        "kind": "some.other.kind",
        "payload": {"repo": "junk", "status": "FAIL"}
    }
    write_payload(dom, [json.dumps(wrapper)])

    from app import app
    with TestClient(app) as client:
        resp = client.get("/v1/integrity", headers=headers)
        data = resp.json()

        assert data["total_status"] == "MISSING" # Because junk is ignored, result is empty -> MISSING
        assert len(data["repos"]) == 0

def test_integrity_view_legacy_support(client, monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import write_payload, sanitize_domain
    headers = {"X-Auth": "test-token"}

    # Ingest legacy kind (in payload, not wrapper)
    dom = sanitize_domain("integrity.legacy")
    wrapper = {
        "domain": dom,
        # No kind in wrapper
        "payload": {
            "kind": "integrity.summary.published.v1",
            "repo": "legacy",
            "status": "OK"
        }
    }
    write_payload(dom, [json.dumps(wrapper)])

    from app import app
    with TestClient(app) as client:
        resp = client.get("/v1/integrity", headers=headers)
        data = resp.json()

        assert data["total_status"] == "OK"
        assert len(data["repos"]) == 1
        assert data["repos"][0]["legacy"] is True
