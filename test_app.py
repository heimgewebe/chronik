import pytest
from fastapi.testclient import TestClient
from app import app, _sanitize_domain

client = TestClient(app)

def test_ingest_auth_ok(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post("/ingest/example.com", headers={"X-Auth": "secret"}, json={"data": "value"})
    assert response.status_code == 200
    assert response.text == "ok"

def test_ingest_auth_fail(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post("/ingest/example.com", headers={"X-Auth": "wrong"}, json={"data": "value"})
    assert response.status_code == 401

def test_ingest_auth_missing(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post("/ingest/example.com", json={"data": "value"})
    assert response.status_code == 401

def test_ingest_no_auth(monkeypatch):
    monkeypatch.setattr("app.SECRET", "")
    response = client.post("/ingest/example.com", json={"data": "value"})
    assert response.status_code == 200

def test_sanitize_domain_ok():
    assert _sanitize_domain("example.com") == "example.com"
    assert _sanitize_domain(" ex-ample.com ") == "ex-ample.com"

def test_sanitize_domain_bad():
    with pytest.raises(Exception):
        _sanitize_domain("example_com")
    with pytest.raises(Exception):
        _sanitize_domain("example.com_")