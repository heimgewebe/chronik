import os
import secrets
import string

import pytest
from fastapi.testclient import TestClient

# Set default tokens for when the module is first imported.
# Tests should override these for hermeticity.
default_token = os.environ.setdefault("CHRONIK_TOKEN", "test-secret")

import httpx  # noqa: E402

from app import app  # noqa: E402
from tools.hauski_ingest import IngestError, ingest_event  # noqa: E402


def test_ingest_event_hermetic(monkeypatch):
    # Ensure the app's secret matches the token we're sending.
    test_token = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    monkeypatch.setenv("CHRONIK_TOKEN", test_token)

    # Use TestClient's transport for hermetic testing
    client = TestClient(app)
    response = ingest_event(
        "example.com",
        {"event": "test", "status": "ok"},
        url="http://test",
        token=test_token,
        transport=client._transport,
    )
    assert response == "ok"


def test_ingest_event_handles_non_json_error(monkeypatch):
    """ingest_event should surface text responses even if they are not JSON."""

    class DummyClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def post(self, *args, **kwargs):
            return httpx.Response(status_code=400, content=b"oops")

    monkeypatch.setattr("tools.hauski_ingest.httpx.Client", DummyClient)

    with pytest.raises(IngestError) as excinfo:
        ingest_event(
            "example.com",
            {"event": "broken"},
            url="http://example.test",
            token="token",
            retries=0,
        )

    msg = str(excinfo.value)
    assert "400" in msg
    assert "oops" in msg
