import asyncio
import os
import secrets
import string

# Set a default token for when the module is first imported.
# Tests should override this for hermeticity.
os.environ.setdefault("LEITSTAND_TOKEN", "test-secret")

import httpx
import pytest
from app import app
from tools.hauski_ingest import ingest_event


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
    test_token = "".join(secrets.choice(string.ascii_letters) for i in range(16))
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
