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


class _ChronikAppTransport(httpx.BaseTransport):
    """Bridge the public TestClient API into an httpx transport for ingest tests."""

    def __init__(self) -> None:
        self._client = TestClient(app)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self._client.request(
            request.method,
            str(request.url),
            headers=dict(request.headers),
            content=request.read(),
        )
        return httpx.Response(
            status_code=response.status_code,
            headers=dict(response.headers),
            content=response.content,
            request=request,
        )

    def close(self) -> None:
        self._client.close()


def _app_transport() -> httpx.BaseTransport:
    return _ChronikAppTransport()


def test_ingest_event_hermetic(monkeypatch):
    # Ensure the app's secret matches the token we're sending.
    test_token = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    monkeypatch.setenv("CHRONIK_TOKEN", test_token)

    response = ingest_event(
        "example.com",
        {"event": "test", "status": "ok"},
        url="http://test",
        token=test_token,
        transport=_app_transport(),
    )
    assert response == "ok"


def test_ingest_event_reuses_app_transport_across_retry(monkeypatch):
    """Retryable responses must not close the app transport between attempts."""
    test_token = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    monkeypatch.setenv("CHRONIK_TOKEN", test_token)

    class RetryOnceTransport(_ChronikAppTransport):
        def __init__(self) -> None:
            super().__init__()
            self.requests = 0
            self.close_calls = 0

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            self.requests += 1
            if self.requests == 1:
                return httpx.Response(503, text="retry", request=request)
            return super().handle_request(request)

        def close(self) -> None:
            self.close_calls += 1
            super().close()

    transport = RetryOnceTransport()
    response = ingest_event(
        "example.com",
        {"event": "retry", "status": "ok"},
        url="http://test",
        token=test_token,
        transport=transport,
        retries=1,
        backoff=0,
    )

    assert response == "ok"
    assert transport.requests == 2
    assert transport.close_calls == 1


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


def test_ingest_event_without_event_field(monkeypatch):
    """ingest_event should accept payloads without an 'event' field."""
    test_token = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    monkeypatch.setenv("CHRONIK_TOKEN", test_token)

    # Payload without 'event' field should be accepted
    response = ingest_event(
        "example.com",
        {"status": "ok", "message": "hello"},
        url="http://test",
        token=test_token,
        transport=_app_transport(),
    )
    assert response == "ok"


def test_ingest_event_arbitrary_fields(monkeypatch):
    """ingest_event should accept payloads with arbitrary fields."""
    test_token = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    monkeypatch.setenv("CHRONIK_TOKEN", test_token)

    # Payload with completely different fields
    response = ingest_event(
        "example.com",
        {"foo": "bar", "baz": 123, "nested": {"key": "value"}},
        url="http://test",
        token=test_token,
        transport=_app_transport(),
    )
    assert response == "ok"


def test_ingest_event_strict_rejects_missing_fields(monkeypatch):
    """In strict mode, ingest_event should reject payloads missing required fields."""
    test_token = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    monkeypatch.setenv("CHRONIK_TOKEN", test_token)
    monkeypatch.setenv("HAUSKI_INGEST_STRICT", "1")

    # Missing all required fields
    with pytest.raises(IngestError) as excinfo:
        ingest_event(
            "example.com",
            {"status": "ok"},
            url="http://test",
            token=test_token,
            transport=_app_transport(),
        )
    assert "missing required fields" in str(excinfo.value)
    assert "kind" in str(excinfo.value)
    assert "ts" in str(excinfo.value)
    assert "source" in str(excinfo.value)


def test_ingest_event_strict_accepts_minimal_fields(monkeypatch):
    """In strict mode, ingest_event should accept payloads with minimal required fields."""
    test_token = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    monkeypatch.setenv("CHRONIK_TOKEN", test_token)
    monkeypatch.setenv("HAUSKI_INGEST_STRICT", "1")

    # Has all required fields
    response = ingest_event(
        "example.com",
        {
            "kind": "test.event",
            "ts": "2025-12-31T10:00:00Z",
            "source": "test-client",
            "data": {"value": 42},
        },
        url="http://test",
        token=test_token,
        transport=_app_transport(),
    )
    assert response == "ok"


def test_ingest_event_strict_parameter_overrides_env(monkeypatch):
    """strict parameter should override HAUSKI_INGEST_STRICT environment variable."""
    test_token = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    monkeypatch.setenv("CHRONIK_TOKEN", test_token)
    monkeypatch.setenv("HAUSKI_INGEST_STRICT", "1")

    # strict=False should override env
    response = ingest_event(
        "example.com",
        {"status": "ok"},  # Missing required fields, but strict=False
        url="http://test",
        token=test_token,
        transport=_app_transport(),
        strict=False,
    )
    assert response == "ok"


def test_ingest_event_strict_batch_validation(monkeypatch):
    """In strict mode, ingest_event should validate all items in a batch."""
    test_token = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    monkeypatch.setenv("CHRONIK_TOKEN", test_token)

    # Batch with one invalid item
    with pytest.raises(IngestError) as excinfo:
        ingest_event(
            "example.com",
            [
                {"kind": "test", "ts": "2025-12-31T10:00:00Z", "source": "test"},
                {"status": "ok"},  # Missing required fields
            ],
            url="http://test",
            token=test_token,
            transport=_app_transport(),
            strict=True,
        )
    assert "batch item 1" in str(excinfo.value)
    assert "missing required fields" in str(excinfo.value)


def test_ingest_json_alias(monkeypatch):
    """ingest_json should be an alias for ingest_event."""
    from tools.hauski_ingest import ingest_json

    test_token = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    monkeypatch.setenv("CHRONIK_TOKEN", test_token)

    # Should work exactly like ingest_event
    response = ingest_json(
        "example.com",
        {"foo": "bar"},
        url="http://test",
        token=test_token,
        transport=_app_transport(),
    )
    assert response == "ok"
