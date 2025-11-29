import errno
import json
import os
import secrets
import string
from pathlib import Path

os.environ.setdefault("CHRONIK_TOKEN", "test-secret")

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import app as app_module
from app import _safe_target_path, _sanitize_domain, app
import storage

client = TestClient(app)


def _test_secret() -> str:
    return "".join(secrets.choice(string.ascii_letters) for i in range(16))


def test_ingest_auth_ok(monkeypatch):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": secret}, json={"data": "value"}
    )
    assert response.status_code == 202
    assert response.text == "ok"


def test_ingest_auth_fail(monkeypatch):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": "wrong"}, json={"data": "value"}
    )
    assert response.status_code == 401


def test_ingest_auth_missing(monkeypatch):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    response = client.post("/ingest/example.com", json={"data": "value"})
    assert response.status_code == 401


def test_sanitize_domain_ok():
    assert _sanitize_domain("example.com") == "example.com"
    assert _sanitize_domain(" ex-ample.com ") == "ex-ample.com"


def test_sanitize_domain_bad():
    with pytest.raises(Exception):
        _sanitize_domain("example_com")
    with pytest.raises(Exception):
        _sanitize_domain("example.com_")


def test_safe_target_path_rejects_traversal(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("app.DATA", tmp_path)
    with pytest.raises(HTTPException) as excinfo:
        _safe_target_path("../../etc/passwd", already_sanitized=True)
    assert excinfo.value.status_code == 400
    assert excinfo.value.detail == "invalid domain"


def test_secure_filename_rejects_nested_traversal():
    assert ".." not in storage.secure_filename("....test")
    assert ".." not in storage.secure_filename("..test")
    assert ".." not in storage.secure_filename("test..")
    assert ".." not in storage.secure_filename("...test...")
    assert storage.secure_filename("....test") == ".test"
    assert "/" not in storage.secure_filename("a/b")
    assert "\\" not in storage.secure_filename("a\\b")
    assert ".." not in storage.secure_filename("..")
    assert ".." not in storage.secure_filename("../")
    assert ".." not in storage.secure_filename("/..")
    assert ".." not in storage.secure_filename("a/../b")


def test_ingest_single_object(monkeypatch, tmp_path: Path):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    monkeypatch.setattr("app.DATA", tmp_path)
    domain = "example.com"
    payload = {"data": "value"}
    response = client.post(f"/ingest/{domain}", headers={"X-Auth": secret}, json=payload)
    assert response.status_code == 202
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
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    monkeypatch.setattr("app.DATA", tmp_path)
    domain = "example.com"
    payload = [{"data": "value1"}, {"data": "value2"}]
    response = client.post(f"/ingest/{domain}", headers={"X-Auth": secret}, json=payload)
    assert response.status_code == 202
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


def test_ingest_empty_array(monkeypatch, tmp_path: Path):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    monkeypatch.setattr("app.DATA", tmp_path)
    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": secret},
        json=[],
    )

    assert response.status_code == 202
    assert response.text == "ok"
    assert not any(tmp_path.iterdir())


def test_ingest_invalid_json(monkeypatch):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": secret, "Content-Type": "application/json"},
        content="{invalid json}",
    )
    assert response.status_code == 400
    assert "invalid json" in response.text


def test_ingest_payload_too_large(monkeypatch):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    # Limit is 1 MiB
    large_payload = {"key": "v" * (1024 * 1024)}
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": secret}, json=large_payload
    )
    assert response.status_code == 413
    assert "payload too large" in response.text


def test_ingest_invalid_payload_not_dict(monkeypatch):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": secret}, json=["not-a-dict"]
    )
    assert response.status_code == 400
    assert "invalid payload" in response.text


def test_ingest_domain_mismatch(monkeypatch):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": secret},
        json={"domain": "other.example", "data": "value"},
    )
    assert response.status_code == 400
    assert "domain mismatch" in response.text


def test_ingest_domain_normalized(monkeypatch, tmp_path: Path):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    monkeypatch.setattr("app.DATA", tmp_path)

    payload = {"domain": "Example.COM", "data": "value"}
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": secret}, json=payload
    )

    assert response.status_code == 202

    target_file = next(tmp_path.glob("*.jsonl"))
    with open(target_file, "r", encoding="utf-8") as fh:
        stored = json.loads(fh.readline())
    assert stored["domain"] == "example.com"
    assert stored["data"] == "value"


def test_ingest_no_content_length(monkeypatch):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    request = client.build_request(
        "POST",
        "/ingest/example.com",
        headers={"X-Auth": secret, "Content-Type": "application/json"},
        content='{"data": "value"}',
    )
    # httpx TestClient adds this header automatically.
    del request.headers["Content-Length"]
    response = client.send(request)
    assert response.status_code == 411
    assert "length required" in response.text


def test_ingest_no_content_length_unauthorized(monkeypatch):
    """Missing auth should fail before we validate content length."""
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    request = client.build_request(
        "POST",
        "/ingest/example.com",
        headers={"Content-Type": "application/json"},
        content='{"data": "value"}',
    )
    del request.headers["Content-Length"]
    response = client.send(request)
    assert response.status_code == 401
    assert "unauthorized" in response.text


def test_ingest_negative_content_length(monkeypatch):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": secret, "Content-Length": "-1"},
        json={"data": "value"},
    )
    assert response.status_code == 400
    assert "invalid content-length" in response.text


def test_health_endpoint(monkeypatch):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    response = client.get("/health", headers={"X-Auth": secret})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_version_endpoint(monkeypatch):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    monkeypatch.setattr("app.VERSION", "1.2.3")
    response = client.get("/version", headers={"X-Auth": secret})
    assert response.status_code == 200
    assert response.json() == {"version": "1.2.3"}


def test_version_endpoint_requires_auth(monkeypatch):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    response = client.get("/version")
    assert response.status_code == 401
    assert "unauthorized" in response.text


def test_target_filename_truncates_long_domain(monkeypatch, tmp_path: Path):
    long_label = "a" * 63
    domain = ".".join([long_label, long_label, long_label, "b" * 61])
    assert len(domain) == 253

    dom = _sanitize_domain(domain)
    filename = storage.target_filename(dom)
    assert filename.endswith(".jsonl")
    assert len(filename) <= 255

    prefix, hash_part_with_ext = filename.rsplit("-", 1)
    hash_part, ext = hash_part_with_ext.split(".")
    assert ext == "jsonl"
    assert len(hash_part) == 8
    assert all(ch in string.hexdigits for ch in hash_part)
    assert prefix.startswith(domain[:16])
    assert storage.target_filename(dom) == filename

    monkeypatch.setattr("app.DATA", tmp_path)
    resolved = app_module._safe_target_path(domain)
    assert resolved.name == filename
    assert resolved.parent == tmp_path


def test_target_filename_boundary_cases():
    """Test filename generation at the 255 character boundary."""
    # Domain of length 249 should NOT be truncated (249 + 6 = 255, exactly at limit)
    domain_249 = "a" * 249
    filename_249 = storage.target_filename(domain_249)
    assert filename_249 == domain_249 + ".jsonl", "Domain of length 249 should not be truncated"
    assert len(filename_249) == 255
    
    # Domain of length 248 should NOT be truncated (248 + 6 = 254, under limit)
    domain_248 = "b" * 248
    filename_248 = storage.target_filename(domain_248)
    assert filename_248 == domain_248 + ".jsonl", "Domain of length 248 should not be truncated"
    assert len(filename_248) == 254
    
    # Domain of length 250 SHOULD be truncated (250 + 6 = 256, over limit)
    domain_250 = "c" * 250
    filename_250 = storage.target_filename(domain_250)
    assert filename_250 != domain_250 + ".jsonl", "Domain of length 250 should be truncated"
    assert len(filename_250) == 255
    assert filename_250.endswith(".jsonl")
    # Should contain a hash separator
    assert "-" in filename_250


def test_metrics_endpoint_exposed():
    """Metrics endpoint should be accessible without auth."""

    response = client.get("/metrics")
    assert response.status_code == 200
    assert "http_requests" in response.text


def test_lock_timeout_returns_429(monkeypatch):
    """Lock acquisition timeout should map to 429."""

    class _DummyLock:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            from filelock import Timeout

            raise Timeout("dummy.lock")

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr("app.FileLock", _DummyLock)
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    response = client.post(
        "/ingest/example.com",
        headers={
            "X-Auth": secret,
            "Content-Length": "2",
            "Content-Type": "application/json",
        },
        content="{}",
    )
    assert response.status_code == 429
    assert "busy" in response.text


def test_path_traversal_domain_is_rejected(monkeypatch):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    response = client.post(
        "/ingest/..example.com",
        headers={
            "X-Auth": secret,
            "Content-Type": "application/json",
            "Content-Length": "2",
        },
        content="{}",
    )
    assert response.status_code == 400
    assert "invalid domain" in response.text


def test_ingest_v1_json_domain_from_query(monkeypatch, tmp_path: Path):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    monkeypatch.setattr("app.DATA", tmp_path)
    domain = "example.com"
    payload = {"data": "value"}
    response = client.post(
        f"/v1/ingest?domain={domain}",
        headers={"X-Auth": secret, "Content-Type": "application/json"},
        json=payload,
    )
    assert response.status_code == 202
    assert response.text == "ok"

    files = list(tmp_path.glob("*.jsonl"))
    assert len(files) == 1
    with open(files[0], "r") as f:
        data = json.loads(f.readline())
        assert data == {**payload, "domain": domain}


def test_ingest_v1_json_domain_from_payload(monkeypatch, tmp_path: Path):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    monkeypatch.setattr("app.DATA", tmp_path)
    domain = "example.com"
    payload = {"domain": domain, "data": "value"}
    response = client.post(
        "/v1/ingest",
        headers={"X-Auth": secret, "Content-Type": "application/json"},
        json=payload,
    )
    assert response.status_code == 202
    assert response.text == "ok"

    files = list(tmp_path.glob("*.jsonl"))
    assert len(files) == 1
    with open(files[0], "r") as f:
        data = json.loads(f.readline())
        assert data == payload


def test_ingest_v1_ndjson(monkeypatch, tmp_path: Path):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    monkeypatch.setattr("app.DATA", tmp_path)
    domain = "example.com"
    payload = [{"data": "value1"}, {"data": "value2"}]
    ndjson_payload = "\n".join(json.dumps(item) for item in payload)
    response = client.post(
        f"/v1/ingest?domain={domain}",
        headers={"X-Auth": secret, "Content-Type": "application/x-ndjson"},
        content=ndjson_payload,
    )
    assert response.status_code == 202
    assert response.text == "ok"

    files = list(tmp_path.glob("*.jsonl"))
    assert len(files) == 1
    with open(files[0], "r") as f:
        lines = f.readlines()
        assert len(lines) == 2
        data1 = json.loads(lines[0])
        assert data1 == {**payload[0], "domain": domain}
        data2 = json.loads(lines[1])
        assert data2 == {**payload[1], "domain": domain}


def test_symlink_attack_rejected_after_resolve(monkeypatch, tmp_path):
    # This is the more advanced attack: a symlink that gets resolved *by*
    # `resolve()` to a valid-looking path inside the data dir.
    # We must still reject it.
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    real_data_dir = tmp_path / "data"
    real_data_dir.mkdir()
    (real_data_dir / "legit.jsonl").touch()

    # The attacker-controlled symlink
    link_path = tmp_path / "symlink.jsonl"
    link_path.symlink_to(real_data_dir / "legit.jsonl")

    # Now, trick the code into thinking the symlink is the domain file
    # This requires us to bypass the normal filename generation.
    monkeypatch.setattr(
        "storage.target_filename", lambda domain: "symlink.jsonl"
    )

    with pytest.raises(storage.DomainError):
        storage.safe_target_path("example.com", data_dir=tmp_path)


def test_symlink_attack_rejected(monkeypatch, tmp_path):
    import os

    if not hasattr(os, "symlink") or getattr(os, "O_NOFOLLOW", 0) == 0:
        pytest.skip("platform lacks symlink or O_NOFOLLOW")

    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    monkeypatch.setattr("app.DATA", tmp_path)

    victim = tmp_path / "victim.txt"
    victim.write_text("do not touch", encoding="utf-8")
    link_name = tmp_path / "example.com.jsonl"
    os.symlink(victim, link_name)

    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": secret, "Content-Type": "application/json"},
        json={"data": "value"},
    )

    assert response.status_code in (400, 500)
    assert victim.read_text(encoding="utf-8") == "do not touch"


def test_concurrent_writes_are_serialized(monkeypatch, tmp_path):
    import concurrent.futures

    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    monkeypatch.setattr("app.DATA", tmp_path)

    def _one(i: int) -> int:
        return client.post(
            "/ingest/example.com",
            headers={"X-Auth": secret, "Content-Type": "application/json"},
            json={"i": i},
        ).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        codes = list(executor.map(_one, range(20)))

    assert all(code == 202 for code in codes)

    output = tmp_path / "example.com.jsonl"
    assert output.exists()
    lines = output.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 20


def test_disk_full_returns_507(monkeypatch, tmp_path):
    secret = _test_secret()
    monkeypatch.setattr("app.SECRET", secret)
    monkeypatch.setattr("app.DATA", tmp_path)

    original_open = app_module.os.open

    def _raise_enospc(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None:
            raise OSError(errno.ENOSPC, "No space left on device")
        return original_open(path, flags, mode)

    monkeypatch.setattr("app.os.open", _raise_enospc)

    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": secret, "Content-Type": "application/json"},
        json={},
    )

    assert response.status_code == 507
    assert "insufficient" in response.text.lower()
