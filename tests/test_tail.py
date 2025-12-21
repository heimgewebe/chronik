
import json
import secrets
import time
import os

import pytest
from fastapi.testclient import TestClient
from filelock import FileLock

import storage

@pytest.fixture(autouse=True)
def mock_storage(monkeypatch, tmp_path):
    # Isolate DATA_DIR for all tests
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    # Ensure app import does not depend on external shell/CI env.
    # app.py requires CHRONIK_TOKEN at import time (per existing test comment).
    # Set a deterministic value here so tests are hermetic.
    monkeypatch.setenv("CHRONIK_TOKEN", "test-token")
    return tmp_path

@pytest.fixture
def client():
    # Import app only after DATA_DIR isolation is active (autouse fixture)
    import app as app_module
    with TestClient(app_module.app) as c:
        yield c

@pytest.fixture
def auth_header():
    return {"X-Auth": os.environ["CHRONIK_TOKEN"]}

def test_tail_auth_required(client):
    response = client.get("/v1/tail?domain=test-auth", headers={})
    assert response.status_code == 401

    response = client.get("/v1/tail?domain=test-auth", headers={"X-Auth": "wrong"})
    assert response.status_code == 401

def test_tail_limit_bounds(client, auth_header):
    # Test limit < 1
    response = client.get("/v1/tail?domain=test-limit&limit=0", headers=auth_header)
    assert response.status_code == 400
    assert "limit must be >= 1" in response.text

    # Test limit > 2000
    response = client.get("/v1/tail?domain=test-limit&limit=2001", headers=auth_header)
    assert response.status_code == 400
    assert "limit must be <= 2000" in response.text

def test_tail_non_existent_domain(client, auth_header):
    domain = f"test-missing-{secrets.token_hex(4)}"
    response = client.get(f"/v1/tail?domain={domain}", headers=auth_header)
    assert response.status_code == 200
    assert response.json() == []
    assert response.headers["X-Chronik-Lines-Returned"] == "0"
    assert response.headers["X-Chronik-Lines-Dropped"] == "0"
    assert "X-Chronik-Last-Seen-TS" in response.headers

def test_tail_valid_data(client, auth_header):
    domain = f"test-valid-{secrets.token_hex(4)}"

    # Write some data
    data = [{"msg": f"msg {i}"} for i in range(10)]
    storage.write_payload(domain, [json.dumps(d) for d in data])

    # Read back all
    response = client.get(f"/v1/tail?domain={domain}&limit=100", headers=auth_header)
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 10
    assert results == data
    assert response.headers["X-Chronik-Lines-Returned"] == "10"
    assert response.headers["X-Chronik-Lines-Dropped"] == "0"
    # last seen should be empty (no ts fields in this dataset)
    assert response.headers["X-Chronik-Last-Seen-TS"] == ""

    # Read back limited
    response = client.get(f"/v1/tail?domain={domain}&limit=5", headers=auth_header)
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 5
    assert results == data[5:]  # Last 5 items
    assert response.headers["X-Chronik-Lines-Returned"] == "5"
    assert "X-Chronik-Last-Seen-TS" in response.headers

def test_tail_since_filter(client, auth_header):
    domain = f"test-since-{secrets.token_hex(4)}"
    # Events with timestamps
    events = [
        {"ts": "2023-01-01T10:00:00Z", "id": 1},
        {"ts": "2023-01-01T11:00:00Z", "id": 2},
        {"ts": "2023-01-01T12:00:00Z", "id": 3},
    ]
    storage.write_payload(domain, [json.dumps(e) for e in events])

    # Since 10:30 -> should match id 2 and 3
    response = client.get(
        f"/v1/tail?domain={domain}&since=2023-01-01T10:30:00Z", headers=auth_header
    )
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 2
    assert results[0]["id"] == 2
    assert results[1]["id"] == 3

    # Invalid since format
    response = client.get(
        f"/v1/tail?domain={domain}&since=invalid-ts", headers=auth_header
    )
    assert response.status_code == 400
    assert "invalid since format" in response.text

def test_tail_corrupt_data(client, auth_header):
    domain = f"test-corrupt-{secrets.token_hex(4)}"

    # Write valid data
    storage.write_payload(domain, [json.dumps({"valid": 1})])

    # Write corrupt data (raw append to simulate corruption)
    path = storage.safe_target_path(domain)
    # We use open with 'a' and encoding utf-8
    with open(path, "a", encoding="utf-8") as f:
        f.write("not json\n")
        f.write("also not json\n")

    # Write more valid data
    storage.write_payload(domain, [json.dumps({"valid": 2})])

    response = client.get(f"/v1/tail?domain={domain}", headers=auth_header)
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 2
    assert results == [{"valid": 1}, {"valid": 2}]
    assert response.headers["X-Chronik-Lines-Returned"] == "2"
    assert response.headers["X-Chronik-Lines-Dropped"] == "2"
    assert "X-Chronik-Last-Seen-TS" in response.headers

def test_tail_last_seen_ts_header(client, auth_header):
    domain = f"test-ts-{secrets.token_hex(4)}"
    # Mix ts + timestamp; header should reflect the max
    storage.write_payload(
        domain,
        [
            json.dumps({"event": "a", "status": "ok", "ts": "2023-01-01T00:00:00Z"}),
            json.dumps({"event": "b", "status": "ok", "timestamp": "2023-01-03T12:00:00Z"}),
            json.dumps({"event": "c", "status": "ok", "ts": "2023-01-02T00:00:00+00:00"}),
        ],
    )
    response = client.get(f"/v1/tail?domain={domain}&limit=50", headers=auth_header)
    assert response.status_code == 200
    # We only check that it's non-empty and contains the newest day "2023-01-03"
    # (exact formatting includes +00:00 due to fromisoformat normalization)
    last_seen = response.headers["X-Chronik-Last-Seen-TS"]
    assert last_seen != ""
    assert "2023-01-03" in last_seen

def test_tail_concurrency_lock(client, auth_header, monkeypatch):
    domain = f"test-lock-{secrets.token_hex(4)}"
    target_path = storage.safe_target_path(domain)

    # Ensure file exists
    storage.write_payload(domain, ["{}"])

    # Get the lock path using the new helper
    lock_path = storage.get_lock_path(target_path)

    # We reduce timeout to speed up test
    monkeypatch.setattr(storage, "LOCK_TIMEOUT", 0.1)

    with FileLock(str(lock_path)):
        # Now try to read
        start = time.time()
        response = client.get(f"/v1/tail?domain={domain}", headers=auth_header)
        end = time.time()

    assert response.status_code == 429
    assert "busy" in response.text

def test_tail_invalid_domain_traversal(client, auth_header):
    # Test invalid domain (path traversal)
    response = client.get("/v1/tail?domain=../invalid", headers=auth_header)
    assert response.status_code == 400
    assert "invalid domain" in response.text


def test_tail_robustness_utf8_split(monkeypatch, tmp_path):
    """Test behavior when a UTF-8 character is split across chunk boundary."""
    domain = "test-utf8"
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)

    # 3-byte character: € (E2 82 AC)
    # We create a file with many lines, and the boundary will fall inside the €

    # Setup: 10 lines of "pre", then 1 line with "€", then 10 lines of "post"
    lines = [f"line {i}" for i in range(10)]
    lines.append("hello € world")
    lines.extend([f"post {i}" for i in range(10)])

    storage.write_payload(domain, lines)

    target_path = storage.safe_target_path(domain)

    # We want to force a read that splits the €
    # "hello € world" + newline is approx 14-16 bytes depending on newline
    # We'll use a very small chunk size to guarantee splitting if we seek carefully?
    # Actually, easier: _tail_impl reads in chunks.
    # We can mock chunk_size in _tail_impl using partial/wrapper, but _tail_impl is internal.

    # Let's verify _tail_impl directly to control chunk_size
    with storage._locked_open(target_path, "rb") as fh:
        # Use a small chunk size (e.g., 4 bytes) which is likely to split multibyte chars
        # since lines are longer than 4 bytes.
        fetched = storage._tail_impl(fh, limit=100, chunk_size=4)

    # We expect all lines to be recovered correctly, EXCEPT possibly the very first
    # fetched line if the file was huge and we stopped exactly at a split char.
    # But here we read the whole file (limit=100 > 21 lines).
    # So the chunking will eventually read the whole file.
    # The split happens between chunks, but `buffer[0:0] = chunk` reassembles them bytes-correctly
    # BEFORE decoding.
    # WAIT: The potential issue is if we STOP reading (limit reached) exactly at a split char?
    # No, we stop reading when we have enough newlines. Newlines are ASCII.
    # So the split-char issue only happens if the file *starts* (from the perspective of our read window)
    # with a partial char.

    assert len(fetched) == 21
    assert fetched[10] == "hello € world"


def test_tail_robustness_split_char_at_window_start(monkeypatch, tmp_path):
    """Test when the read window stops exactly inside a multi-byte character."""
    domain = "test-utf8-split"
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)

    # Construct a file where the desired limit cuts off inside a multi-byte char
    # e.g. Limit 1 line. File: "trash\n€\n"
    # Reading backwards:
    # 1. Read last line "\n" (empty) -> count newlines

    # Let's make it simpler.
    # We want `buffer` to start with a partial char.
    # Line 1: "€" (E2 82 AC)
    # Line 2: "A"

    lines = ["€", "A"]
    storage.write_payload(domain, lines)
    path = storage.safe_target_path(domain)

    # We want to read 1 line ("A").
    # If we read chunks, we might read "A\n" and stop?
    # "A\n" is 2 bytes.
    # If we read "A\n", buffer is "A\n". newlines=1. limit=1. Break.
    # Decode "A\n" -> "A". Correct.

    # We need a case where we read MORE than limit newlines, but the "extra" data at start is partial.
    # File: "€\n" + "B\n" * 10
    # Limit: 10.
    # We read 11 lines worth of bytes.
    # The 11th line (oldest) is "€".
    # If we happen to read only part of "€" (e.g. "AC\n"), then buffer starts with invalid bytes.

    content = "€\n" + "B\n" * 10
    with open(path, "wb") as f:
        f.write(content.encode("utf-8"))

    # We use chunk_size such that we get the "B"s and PART of the "€".
    # "B\n" is 2 bytes. 10 lines = 20 bytes.
    # "€\n" is 4 bytes (E2 82 AC 0A).
    # Total 24 bytes.
    # If we read 22 bytes from end: 20 bytes ("B"s) + 2 bytes ("AC\n").
    # Buffer starts with AC (invalid).

    with storage._locked_open(path, "rb") as fh:
        # chunk_size=22
        # limit=10 (the B's)
        # buffer will contain "AC\n" + "B\n"*10.
        # Newlines = 1 + 10 = 11. 11 >= 10. Break.
        # Decode("AC\n...") -> should replace AC with .
        # Lines = [ "", "B", "B"...]
        # We return last 10 lines -> ["B", ..., "B"]
        # So strict correctness for the *returned* lines is preserved!

        fetched = storage._tail_impl(fh, limit=10, chunk_size=22)

    assert len(fetched) == 10
    assert all(l == "B" for l in fetched)

    # Now what if we requested 11 lines?
    # We would get the damaged line too.
    with storage._locked_open(path, "rb") as fh:
        fetched = storage._tail_impl(fh, limit=11, chunk_size=22)

    assert len(fetched) == 11
    # The first line is the damaged "€".
    # "AC" (bytes) decoded with errors='replace' -> "" or ""
    assert fetched[0].startswith("")
    assert fetched[1] == "B"


def test_tail_newlines_consistency(monkeypatch, tmp_path):
    """Test file with/without trailing newline."""
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    domain_with = "with-newline"
    domain_without = "without-newline"

    # storage.write_payload always adds newline. We manually create files.
    p1 = storage.safe_target_path(domain_with)
    with open(p1, "wb") as f:
        f.write(b"line1\nline2\n")

    p2 = storage.safe_target_path(domain_without)
    with open(p2, "wb") as f:
        f.write(b"line1\nline2")

    # Test with newline
    with storage._locked_open(p1, "rb") as fh:
        lines = storage._tail_impl(fh, limit=10)
    assert lines == ["line1", "line2"]

    with storage._locked_open(p1, "rb") as fh:
        lines = storage._tail_impl(fh, limit=1)
    assert lines == ["line2"]

    # Test without newline
    with storage._locked_open(p2, "rb") as fh:
        lines = storage._tail_impl(fh, limit=10)
    assert lines == ["line1", "line2"]

    with storage._locked_open(p2, "rb") as fh:
        lines = storage._tail_impl(fh, limit=1)
    assert lines == ["line2"]
