from fastapi.testclient import TestClient
from app import app
import os
import pytest

client = TestClient(app)

def test_ops_html_serving():
    response = client.get("/ops")
    assert response.status_code == 200
    assert "ACS Ops Panel" in response.text
    assert "btn-audit" in response.text

def test_ops_audit_endpoint():
    response = client.post("/api/ops/audit")
    assert response.status_code == 200
    data = response.json()
    assert data["kind"] == "audit.git"
    assert data["status"] == "error"
    assert data["repo"] == "metarepo"
    assert len(data["suggested_routines"]) > 0
    assert data["suggested_routines"][0]["id"] == "git.repair.remote-head"

def test_ops_preview_endpoint():
    payload = {
        "repo": "metarepo",
        "routine_id": "git.repair.remote-head"
    }
    response = client.post("/api/ops/routine/preview", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["kind"] == "routine.preview"
    assert data["id"] == "git.repair.remote-head"
    assert len(data["steps"]) == 2
    assert "confirm_token" in data

def test_ops_apply_endpoint():
    # 1. Get token from preview
    payload_preview = {
        "repo": "metarepo",
        "routine_id": "git.repair.remote-head"
    }
    preview_res = client.post("/api/ops/routine/preview", json=payload_preview)
    token = preview_res.json()["confirm_token"]

    # 2. Apply
    payload_apply = {
        "repo": "metarepo",
        "routine_id": "git.repair.remote-head",
        "confirm_token": token
    }
    response = client.post("/api/ops/routine/apply", json=payload_apply)
    assert response.status_code == 200
    data = response.json()
    assert data["kind"] == "routine.result"
    assert data["ok"] is True
    assert "Fetching origin" in data["stdout"]

def test_ops_apply_invalid_token():
    payload = {
        "repo": "metarepo",
        "routine_id": "git.repair.remote-head",
        "confirm_token": "invalid"
    }
    response = client.post("/api/ops/routine/apply", json=payload)
    assert response.status_code == 403
