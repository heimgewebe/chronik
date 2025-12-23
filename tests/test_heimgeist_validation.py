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
        "id": "1",
        "timestamp": "2023-10-27T10:00:00Z",
        "source": "src",
        "payload": {"foo": "bar"}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 202
    assert response.text == "ok"

def test_heimgeist_missing_id(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "timestamp": "2023-10-27T10:00:00Z",
        "source": "src",
        "payload": {}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "missing id" in response.text

def test_heimgeist_missing_source(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "id": "1",
        "timestamp": "2023-10-27T10:00:00Z",
        "payload": {}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "missing source" in response.text

def test_heimgeist_missing_timestamp(monkeypatch, client):
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    payload = {
        "id": "1",
        "source": "src",
        "payload": {}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 400
    assert "missing timestamp" in response.text

def test_heimgeist_alternate_fields(monkeypatch, tmp_path, client):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    # using occurred_at instead of timestamp, and object instead of payload
    payload = {
        "id": "1",
        "occurred_at": "2023-10-27T10:00:00Z",
        "source": "src",
        "object": {"foo": "bar"}
    }
    response = client.post("/v1/ingest?domain=heimgeist", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 202

def test_other_domain_loose_validation(monkeypatch, tmp_path, client):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    monkeypatch.setenv("CHRONIK_TOKEN", "secret")
    # Missing id etc, should still pass for other domains
    payload = {"foo": "bar"}
    response = client.post("/v1/ingest?domain=other", json=payload, headers={"X-Auth": "secret"})
    assert response.status_code == 202
