import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import _sanitize_domain, app

client = TestClient(app)


def test_ingest_auth_ok(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": "secret"}, json={"data": "value"}
    )
    assert response.status_code == 200
    assert response.text == "ok"


def test_ingest_auth_fail(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": "wrong"}, json={"data": "value"}
    )
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


def test_ingest_single_object(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("app.SECRET", "secret")
    monkeypatch.setattr("app.DATA", tmp_path)
    domain = "example.com"
    payload = {"data": "value"}
    response = client.post(f"/ingest/{domain}", headers={"X-Auth": "secret"}, json=payload)
    assert response.status_code == 200
    assert response.text == "ok"

    # Verify file content
    files = [f for f in tmp_path.iterdir() if f.name.endswith(".jsonl")]
    assert len(files) == 1
    target_file = files[0]
    with open(target_file, "r") as f:
        line = f.readline()
        data = json.loads(line)
        assert data == {**payload, "domain": domain}


def test_ingest_array_of_objects(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("app.SECRET", "secret")
    monkeypatch.setattr("app.DATA", tmp_path)
    domain = "example.com"
    payload = [{"data": "value1"}, {"data": "value2"}]
    response = client.post(f"/ingest/{domain}", headers={"X-Auth": "secret"}, json=payload)
    assert response.status_code == 200
    assert response.text == "ok"

    # Verify file content
    files = [f for f in tmp_path.iterdir() if f.name.endswith(".jsonl")]
    assert len(files) == 1
    target_file = files[0]
    with open(target_file, "r") as f:
        lines = f.readlines()
        assert len(lines) == 2
        data1 = json.loads(lines[0])
        assert data1 == {**payload[0], "domain": domain}
        data2 = json.loads(lines[1])
        assert data2 == {**payload[1], "domain": domain}


def test_ingest_invalid_json(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": "secret", "Content-Type": "application/json"},
        content="{invalid json}",
    )
    assert response.status_code == 400
    assert "invalid json" in response.text


def test_ingest_payload_too_large(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    # Limit is 1 MiB
    large_payload = {"key": "v" * (1024 * 1024)}
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": "secret"}, json=large_payload
    )
    assert response.status_code == 413
    assert "payload too large" in response.text


def test_ingest_invalid_payload_not_dict(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": "secret"}, json=["not-a-dict"]
    )
    assert response.status_code == 400
    assert "invalid payload" in response.text


def test_ingest_no_content_length(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    request = client.build_request(
        "POST",
        "/ingest/example.com",
        headers={"X-Auth": "secret", "Content-Type": "application/json"},
        content='{"data": "value"}',
    )
    # httpx TestClient adds this header automatically.
    del request.headers["Content-Length"]
    response = client.send(request)
    assert response.status_code == 411
    assert "length required" in response.text
