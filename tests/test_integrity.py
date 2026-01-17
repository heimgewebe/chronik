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

from app import app
from integrity import IntegrityManager, manager

@pytest.fixture
def client(mock_env):
    return TestClient(app)

@pytest.mark.asyncio
async def test_integrity_sync_success(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)

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

    mock_get = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get.return_value = mock_response

    test_manager = IntegrityManager()
    test_manager.override = json.dumps(sources_data)

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
async def test_integrity_status_normalization(monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    from storage import read_last_line, sanitize_domain

    repo = "heimgewebe/wgx"
    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    summary_data = {
        "repo": repo,
        "status": "GREEN",
        "generated_at": "2023-01-01T00:00:00Z"
    }

    mock_get = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get.return_value = mock_response

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
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    summary_data = {
        "repo": repo,
        "status": "FAIL",
        "generated_at": "2023-01-01T10:00:00Z",
        "url": "..."
    }

    mock_get = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get.return_value = mock_response

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
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    summary_data = {
        "repo": repo,
        "status": "FAIL",
        "generated_at": ts,
        "url": "..."
    }

    mock_get = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get.return_value = mock_response

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

    # 1. Future timestamp (way in future)
    future_ts = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    sources_data = {
        "apiVersion": "integrity.sources.v1",
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    summary_data = {
        "repo": repo,
        "status": "OK",
        "generated_at": future_ts,
        "url": "..."
    }

    mock_get = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get.return_value = mock_response

    test_manager = IntegrityManager()
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
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    # Invalid generated_at
    summary_data = {
        "repo": repo,
        "status": "FAIL",
        "generated_at": "yolo-timestamp",
        "url": "..."
    }

    mock_get = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get.return_value = mock_response

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
        "sources": [{"repo": repo, "summary_url": "...", "enabled": True}]
    }
    summary_data = {
        "repo": repo,
        "status": "OK", # Should become FAIL because timestamp invalid
        "generated_at": "yolo-timestamp",
        "url": "..."
    }

    mock_get = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = summary_data
    mock_get.return_value = mock_response

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

    # 2. Get View
    resp = client.get("/v1/integrity", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["total_status"] == "WARN"
    repos = data["repos"]
    assert len(repos) == 2
    assert repos[0]["repo"] == "repo-a"
    assert repos[1]["repo"] == "repo-b"

def test_integrity_view_empty_is_missing(client, monkeypatch, tmp_path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    headers = {"X-Auth": "test-token"}

    # No data ingested

    resp = client.get("/v1/integrity", headers=headers)
    data = resp.json()

    assert data["total_status"] == "MISSING"
    assert len(data["repos"]) == 0

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

    resp = client.get("/v1/integrity", headers=headers)
    data = resp.json()

    assert data["total_status"] == "MISSING" # Because junk is ignored, result is empty -> MISSING
    assert len(data["repos"]) == 0
