import pytest
import os
from fastapi.testclient import TestClient
from app import app
import storage
from pathlib import Path

@pytest.fixture
def client(monkeypatch):
    with TestClient(app) as c:
        yield c

def test_heimgeist_valid_payload(monkeypatch, tmp_path: Path, client):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")

    payload = {
        "kind": "heimgeist.insight",
        "version": 1,
        "id": "evt-1",
        "meta": {
            "occurred_at": "2023-10-27T10:00:00Z",
            "role": "test"
        },
        "data": {"foo": "bar"}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 202
    assert response.text == "ok"

def test_heimgeist_missing_fields(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    # Missing kind, version, meta, data
    payload = {
        "id": "evt-1"
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "missing fields" in response.text
    assert "kind" in response.text
    assert "version" in response.text

def test_heimgeist_invalid_kind(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "kind": "wrong",
        "version": 1,
        "id": "evt-1",
        "meta": {"occurred_at": "ts", "role": "r"},
        "data": {}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "invalid kind" in response.text

def test_heimgeist_invalid_version(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "kind": "heimgeist.insight",
        "version": 2,
        "id": "evt-1",
        "meta": {"occurred_at": "ts", "role": "r"},
        "data": {}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "invalid version" in response.text

def test_heimgeist_missing_meta_fields(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "kind": "heimgeist.insight",
        "version": 1,
        "id": "evt-1",
        "meta": {}, # empty
        "data": {}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "missing meta" in response.text

def test_other_domain_loose_validation(monkeypatch, tmp_path, client):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    # Missing id etc, should still pass for other domains
    payload = {"foo": "bar"}
    response = client.post("/v1/ingest?domain=other", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 202

def test_heimgeist_legacy_path(monkeypatch, tmp_path: Path, client):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")

    payload = {
        "kind": "heimgeist.insight",
        "version": 1,
        "id": "evt-1",
        "meta": {
            "occurred_at": "2023-10-27T10:00:00Z",
            "role": "test"
        },
        "data": {"foo": "bar"}
    }
    response = client.post("/ingest/heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 202
