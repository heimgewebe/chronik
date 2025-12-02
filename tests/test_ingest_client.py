import asyncio
import os
import secrets
import string

import pytest

# Set default tokens for when the module is first imported.
# Tests should override these for hermeticity.
default_token = os.environ.setdefault("CHRONIK_TOKEN", "test-secret")
os.environ.setdefault("LEITSTAND_TOKEN", default_token)

import httpx  # noqa: E402

from app import app  # noqa: E402
from tools.hauski_ingest import IngestError, ingest_event  # noqa: E402


class SyncASGITransport(httpx.BaseTransport):
    def __init__(self, app):
        self._transport = httpx.ASGITransport(app=app)

    def __enter__(self):
        asyncio.run(self._transport.__aenter__())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        asyncio.run(self._transport.__aexit__(exc_type, exc_val, exc_tb))

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        async def _handle_request():
            response = await self._transport.handle_async_request(request)
            await response.aread()
            return httpx.Response(
                status_code=response.status_code,
                headers=response.headers,
                content=response.content,
                extensions=response.extensions,
            )
        return asyncio.run(_handle_request())


def test_ingest_event_hermetic(monkeypatch):
    # Ensure the app's secret matches the token we're sending.
    test_token = "".join(secrets.choice(string.ascii_letters) for _ in range(16))
    monkeypatch.setattr("app.SECRET", test_token)

    transport = SyncASGITransport(app=app)
    response = ingest_event(
        "example.com",
        {"event": "test", "status": "ok"},
        url="http://test",
        token=test_token,
        transport=transport,
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
