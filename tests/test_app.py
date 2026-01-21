import pytest
import os
import json
import secrets
import string
import errno
import fcntl
from pathlib import Path
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import app
import storage

# --- Fixtures ---

@pytest.fixture
def client(monkeypatch):
    """Fixture for TestClient to ensure fresh app state and environment."""
    # Ensure environment variables are set before client creation if needed,
    # though here we rely on monkeypatching per test or fixture.
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    with TestClient(app.app) as c:
        yield c

@pytest.fixture
def mock_storage(monkeypatch, tmp_path):
    """Mocks storage.DATA_DIR to use a temp directory and sets auth token."""
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    return tmp_path

def create_event_file(mock_storage, domain, lines):
    """Helper to create a domain file with specific lines."""
    p = mock_storage / f"{domain}.jsonl"
    with open(p, "wb") as f:
        for line in lines:
            f.write(line)
    return p

def _test_secret() -> str:
    return "test-token"

# --- Pagination Tests (New Logic) ---

def test_get_events_pagination(client, mock_storage):
    """
    Verifies that cursor-based pagination works correctly using byte offsets.
    """
    domain = "test.pagination"
    e1 = b'{"id":1}\n'
    e2 = b'{"id":2}\n'
    e3 = b'{"id":3}\n'

    create_event_file(mock_storage, domain, [e1, e2, e3])

    headers = {"X-Auth": "test-token"}

    # 1. Fetch first page (limit=1)
    resp = client.get(f"/v1/events?domain={domain}&limit=1", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["events"]) == 1
    assert data["events"][0]["id"] == 1
    assert data["has_more"] is True
    # Next cursor should be len(e1) = 9
    cursor1 = data["next_cursor"]
    assert cursor1 == 9

    # 2. Fetch second page (limit=1, cursor=9)
    resp = client.get(f"/v1/events?domain={domain}&limit=1&cursor={cursor1}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["events"]) == 1
    assert data["events"][0]["id"] == 2
    assert data["has_more"] is True
    cursor2 = data["next_cursor"]
    assert cursor2 == 18  # 9 + 9

    # 3. Fetch third page (limit=1, cursor=18)
    resp = client.get(f"/v1/events?domain={domain}&limit=1&cursor={cursor2}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["events"]) == 1
    assert data["events"][0]["id"] == 3
    # Now we are at EOF, but logic says:
    # We requested limit=1. We got 1. scan_domain tried to peek next, found EOF.
    # So has_more should be False.
    assert data["has_more"] is False
    cursor3 = data["next_cursor"]
    assert cursor3 == 27 # 18 + 9

    # 4. Fetch past end
    resp = client.get(f"/v1/events?domain={domain}&limit=1&cursor={cursor3}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["events"]) == 0
    assert data["has_more"] is False
    # Next cursor should remain same (idempotent)
    assert data["next_cursor"] == cursor3

def test_get_events_boundary_condition(client, mock_storage):
    """
    Test reading exactly to the end of file with limit > remaining.
    """
    domain = "test.boundary"
    e1 = b'{"id":1}\n'
    e2 = b'{"id":2}\n'
    create_event_file(mock_storage, domain, [e1, e2])

    headers = {"X-Auth": "test-token"}

    # Request limit=5 (more than available)
    resp = client.get(f"/v1/events?domain={domain}&limit=5", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["events"]) == 2
    assert data["has_more"] is False
    assert data["next_cursor"] == 18 # 9+9

def test_get_events_corrupt_line_skip(client, mock_storage):
    """
    Verifies that corrupt JSON lines are skipped but cursor advances.
    """
    domain = "test.corrupt"
    e1 = b'{"id":1}\n'
    e2 = b'BROKEN_JSON\n' # 12 bytes
    e3 = b'{"id":3}\n'
    create_event_file(mock_storage, domain, [e1, e2, e3])

    headers = {"X-Auth": "test-token"}

    # Fetch all
    resp = client.get(f"/v1/events?domain={domain}&limit=10", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    # Should get e1 and e3. e2 skipped.
    assert len(data["events"]) == 2
    assert data["events"][0]["id"] == 1
    assert data["events"][1]["id"] == 3
    assert data["next_cursor"] == 30 # 9 + 12 + 9

def test_get_events_partial_line_at_eof(client, mock_storage):
    """
    Verifies that a partial line (no newline) at EOF is NOT consumed.
    """
    domain = "test.partial"
    e1 = b'{"id":1}\n'
    e_partial = b'{"id":2}' # No newline
    create_event_file(mock_storage, domain, [e1, e_partial])

    headers = {"X-Auth": "test-token"}

    # Fetch
    resp = client.get(f"/v1/events?domain={domain}&limit=10", headers=headers)
    data = resp.json()

    # Should only return e1
    assert len(data["events"]) == 1
    assert data["events"][0]["id"] == 1
    # Next cursor should point to start of e_partial (9), NOT end of e_partial
    # Because e_partial was effectively ignored/invisible to scan_domain logic
    # that demands newlines.
    assert data["next_cursor"] == 9
    assert data["has_more"] is False

def test_get_events_idempotency_at_eof(client, mock_storage):
    """
    Verifies that repeated calls at EOF return stable cursor and no events.
    """
    domain = "test.idem"
    create_event_file(mock_storage, domain, [b'{"a":1}\n'])

    headers = {"X-Auth": "test-token"}

    # First call
    resp = client.get(f"/v1/events?domain={domain}&limit=1", headers=headers)
    cursor = resp.json()["next_cursor"]

    # Second call
    resp2 = client.get(f"/v1/events?domain={domain}&limit=1&cursor={cursor}", headers=headers)
    data2 = resp2.json()
    assert len(data2["events"]) == 0
    assert data2["next_cursor"] == cursor
    assert data2["has_more"] is False

def test_get_events_empty_file(client, mock_storage):
    domain = "test.empty"
    create_event_file(mock_storage, domain, [])

    headers = {"X-Auth": "test-token"}

    resp = client.get(f"/v1/events?domain={domain}", headers=headers)
    data = resp.json()
    assert len(data["events"]) == 0
    assert data["next_cursor"] == 0
    assert data["has_more"] is False

# --- Restored Security & Robustness Tests ---

def test_ingest_auth_ok(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": secret}, json={"data": "value"}
    )
    assert response.status_code == 202
    assert response.text == "ok"


def test_ingest_auth_fail(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": "wrong"}, json={"data": "value"}
    )
    assert response.status_code == 401


def test_ingest_auth_missing(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    response = client.post("/ingest/example.com", json={"data": "value"})
    assert response.status_code == 401


def test_sanitize_domain_ok():
    from app import _sanitize_domain
    assert _sanitize_domain("example.com") == "example.com"
    assert _sanitize_domain(" ex-ample.com ") == "ex-ample.com"


def test_sanitize_domain_bad():
    from app import _sanitize_domain
    with pytest.raises(Exception):
        _sanitize_domain("example_com")
    with pytest.raises(Exception):
        _sanitize_domain("example.com_")


def test_safe_target_path_neutralizes_traversal(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    # "../../etc/passwd" becomes ".etcpasswd.jsonl"
    resolved = storage.safe_target_path("../../etc/passwd", data_dir=tmp_path)
    assert resolved.parent == tmp_path.resolve()
    assert resolved.name == ".etcpasswd.jsonl"


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


def test_ingest_single_object(monkeypatch, tmp_path: Path, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    domain = "example.com"
    payload = {"data": "value"}
    response = client.post(
        f"/ingest/{domain}", headers={"X-Auth": secret}, json=payload
    )
    assert response.status_code == 202
    assert response.text == "ok"

    # Verify file content
    files = [f for f in tmp_path.iterdir() if f.name.endswith(".jsonl")]
    assert len(files) == 1
    target_file = files[0]
    with open(target_file, "r") as f:
        line = f.readline()
        data = json.loads(line)
        # Canonical storage: always wrapped
        assert "received_at" in data
        assert data["domain"] == domain
        assert data["payload"] == payload


def test_ingest_array_of_objects(monkeypatch, tmp_path: Path, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    domain = "example.com"
    payload = [{"data": "value1"}, {"data": "value2"}]
    response = client.post(
        f"/ingest/{domain}", headers={"X-Auth": secret}, json=payload
    )
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
        assert "received_at" in data1
        assert data1["domain"] == domain
        assert data1["payload"] == payload[0]
        data2 = json.loads(lines[1])
        assert "received_at" in data2
        assert data2["domain"] == domain
        assert data2["payload"] == payload[1]


def test_ingest_empty_array(monkeypatch, tmp_path: Path, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": secret},
        json=[],
    )

    assert response.status_code == 202
    assert response.text == "ok"
    assert not any(tmp_path.iterdir())


def test_ingest_invalid_json(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": secret, "Content-Type": "application/json"},
        content="{invalid json}",
    )
    assert response.status_code == 400
    assert "invalid json" in response.text


def test_ingest_payload_too_large(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    # Limit is 1 MiB
    large_payload = {"key": "v" * (1024 * 1024)}
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": secret}, json=large_payload
    )
    assert response.status_code == 413
    assert "payload too large" in response.text


def test_ingest_invalid_payload_not_dict(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": secret}, json=["not-a-dict"]
    )
    assert response.status_code == 400
    assert "invalid payload" in response.text


def test_ingest_v1_invalid_payload_list_of_ints_no_domain(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    # Sending a list of integers (valid JSON, but invalid payload structure)
    # AND missing domain query param.
    response = client.post(
        "/v1/ingest",
        headers={"X-Auth": secret, "Content-Type": "application/json"},
        json=[1, 2, 3],
    )
    assert response.status_code == 400
    assert "invalid payload" in response.text


def test_ingest_domain_mismatch(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": secret},
        json={"domain": "other.example", "data": "value"},
    )
    assert response.status_code == 400
    assert "domain mismatch" in response.text


def test_ingest_domain_normalized(monkeypatch, tmp_path: Path, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)

    payload = {"domain": "Example.COM", "data": "value"}
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": secret}, json=payload
    )

    assert response.status_code == 202

    target_file = next(tmp_path.glob("*.jsonl"))
    with open(target_file, "r", encoding="utf-8") as fh:
        stored = json.loads(fh.readline())
    assert stored["domain"] == "example.com"
    assert stored["payload"]["data"] == "value"


def test_ingest_no_content_length(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
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


def test_ingest_no_content_length_unauthorized(monkeypatch, client):
    """Missing auth should fail before we validate content length."""
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
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


def test_ingest_negative_content_length(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": secret, "Content-Length": "-1"},
        json={"data": "value"},
    )
    assert response.status_code == 400
    assert "invalid content-length" in response.text


def test_health_endpoint(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    response = client.get("/health", headers={"X-Auth": secret})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_version_endpoint(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    monkeypatch.setattr("app.VERSION", "1.2.3")
    response = client.get("/version", headers={"X-Auth": secret})
    assert response.status_code == 200
    assert response.json() == {"version": "1.2.3"}


def test_version_endpoint_requires_auth(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    response = client.get("/version")
    assert response.status_code == 401
    assert "unauthorized" in response.text


def test_target_filename_truncates_long_domain(monkeypatch, tmp_path: Path):
    long_label = "a" * 63
    domain = ".".join([long_label, long_label, long_label, "b" * 61])
    assert len(domain) == 253

    dom = app._sanitize_domain(domain)
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

    monkeypatch.setattr("storage.DATA_DIR", tmp_path)

    resolved = storage.safe_target_path(domain, data_dir=tmp_path)
    assert resolved.name == filename
    assert resolved.parent == tmp_path


def test_target_filename_boundary_cases():
    """Test filename generation at the 255 character boundary."""
    # Domain of length 249 should NOT be truncated (249 + 6 = 255, exactly at limit)
    domain_249 = "a" * 249
    filename_249 = storage.target_filename(domain_249)
    assert (
        filename_249 == domain_249 + ".jsonl"
    ), "Domain of length 249 should not be truncated"
    assert len(filename_249) == 255

    # Domain of length 248 should NOT be truncated (248 + 6 = 254, under limit)
    domain_248 = "b" * 248
    filename_248 = storage.target_filename(domain_248)
    assert (
        filename_248 == domain_248 + ".jsonl"
    ), "Domain of length 248 should not be truncated"
    assert len(filename_248) == 254

    # Domain of length 250 SHOULD be truncated (250 + 6 = 256, over limit)
    domain_250 = "c" * 250
    filename_250 = storage.target_filename(domain_250)
    assert (
        filename_250 != domain_250 + ".jsonl"
    ), "Domain of length 250 should be truncated"
    assert len(filename_250) == 255
    assert filename_250.endswith(".jsonl")
    # Should contain a hash separator
    assert "-" in filename_250


def test_metrics_endpoint_exposed(client):
    """Metrics endpoint should be accessible without auth."""

    response = client.get("/metrics")
    assert response.status_code == 200
    assert "http_requests" in response.text


def test_lock_timeout_returns_429(monkeypatch, client):
    """Lock acquisition timeout should map to 429."""

    class _DummyLock:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            from filelock import Timeout

            raise Timeout("dummy.lock")

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr("storage.FileLock", _DummyLock)
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
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


def test_path_traversal_domain_is_rejected(monkeypatch, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
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


def test_ingest_v1_json_domain_from_query(monkeypatch, tmp_path: Path, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
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
        assert "received_at" in data
        assert data["domain"] == domain
        assert data["payload"] == payload


def test_ingest_v1_json_domain_from_payload(monkeypatch, tmp_path: Path, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
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
        # Input has domain in payload, output stores it in wrapper domain field
        # and also inside the payload? No, normalize copies input.
        # But our test payload HAS domain inside.
        assert "received_at" in data
        assert data["domain"] == domain
        assert data["payload"] == payload


def test_ingest_v1_ndjson(monkeypatch, tmp_path: Path, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)
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
        assert "received_at" in data1
        assert data1["domain"] == domain
        assert data1["payload"] == payload[0]
        data2 = json.loads(lines[1])
        assert "received_at" in data2
        assert data2["domain"] == domain
        assert data2["payload"] == payload[1]


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


def test_symlink_attack_rejected(monkeypatch, tmp_path, client):
    import os

    if not hasattr(os, "symlink") or getattr(os, "O_NOFOLLOW", 0) == 0:
        pytest.skip("platform lacks symlink or O_NOFOLLOW")

    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)

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


def test_concurrent_writes_are_serialized(monkeypatch, tmp_path, client):
    import concurrent.futures

    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)

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


def test_disk_full_returns_507(monkeypatch, tmp_path, client):
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)

    original_open = storage.os.open

    def _raise_enospc(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None:
            raise OSError(errno.ENOSPC, "No space left on device")
        return original_open(path, flags, mode)

    monkeypatch.setattr("storage.os.open", _raise_enospc)

    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": secret, "Content-Type": "application/json"},
        json={},
    )

    assert response.status_code == 507
    assert "insufficient" in response.text.lower()


def test_disk_full_during_write_returns_507(monkeypatch, tmp_path, client):
    """Test ENOSPC during the write call itself (not just open)."""
    from contextlib import contextmanager

    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)

    # Mock _locked_open to return a file-like object that fails on write
    @contextmanager
    def _mock_locked_open(*args, **kwargs):
        class MockFile:
            def write(self, data):
                raise OSError(errno.ENOSPC, "No space left on device")
        yield MockFile()

    monkeypatch.setattr("storage._locked_open", _mock_locked_open)

    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": secret, "Content-Type": "application/json"},
        json={"data": "foo"},
    )

    assert response.status_code == 507
    assert "insufficient" in response.text.lower()


def test_fd_leak_prevented_on_oserror(monkeypatch, tmp_path, client):
    """Test that file descriptors are properly closed when OSError occurs after fd is opened."""
    secret = _test_secret()
    monkeypatch.setenv("CHRONIK_TOKEN", secret)
    monkeypatch.setattr("storage.DATA_DIR", tmp_path)

    original_open = storage.os.open
    original_fdopen = storage.os.fdopen
    opened_fds = []

    def _track_open(path, flags, mode=0o600, *, dir_fd=None):
        fd = original_open(path, flags, mode, dir_fd=dir_fd)
        if dir_fd is not None and isinstance(path, str) and path.endswith(".jsonl"):
            opened_fds.append(fd)
        return fd

    def _raise_on_fdopen(fd, mode, encoding=None):
        # Simulate an error during fdopen (e.g., encoding issue)
        # This tests the fd leak scenario
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr("storage.os.open", _track_open)
    monkeypatch.setattr("storage.os.fdopen", _raise_on_fdopen)

    # This should fail with an OSError, but the fd should be closed
    try:
        response = client.post(
            "/ingest/example.com",
            headers={"X-Auth": secret, "Content-Type": "application/json"},
            json={"data": "value"},
        )
        # If we get here, the error was handled
        assert response.status_code >= 500
    except Exception:
        # Expected to fail, but fd should be closed
        pass

    # Verify that all opened fds are now closed
    for fd in opened_fds:
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
            # If we get here, the fd is still open - this is a leak!
            assert False, f"File descriptor {fd} was not closed - leak detected!"
        except OSError as e:
            # fd is closed (EBADF expected)
            assert e.errno == errno.EBADF, f"Unexpected error: {e}"
