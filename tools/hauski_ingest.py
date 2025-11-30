from __future__ import annotations

import json
import os
import time
from typing import Any, Mapping, MutableMapping, Optional

import httpx

__all__ = ["ingest_event", "IngestError"]


class IngestError(RuntimeError):
    """Raised when an ingest attempt ultimately fails."""


def _get_env_with_legacy(name: str, legacy_name: str) -> str | None:
    """Get environment variable, checking legacy name as fallback."""
    return os.getenv(name) or os.getenv(legacy_name)


def ingest_event(
    domain: str,
    data: Mapping[str, Any],
    *,
    url: Optional[str] = None,
    token: Optional[str] = None,
    timeout: Optional[float] = None,
    retries: Optional[int] = None,
    backoff: Optional[float] = None,
    transport: Optional[httpx.BaseTransport] = None,
) -> str:
    """
    Send a single JSON event to Chronik.

    Args:
        domain: target domain (e.g. "example.com")
        data: JSON-serializable mapping with at least an "event" field
        url: base URL of Chronik (env CHRONIK_URL if None)
        token: shared secret for X-Auth (env CHRONIK_TOKEN if None)
        timeout: request timeout seconds (env CHRONIK_TIMEOUT, default 5)
        retries: retry count for 429/5xx/timeout (env CHRONIK_RETRIES, default 3)
        backoff: initial backoff seconds (env CHRONIK_BACKOFF, default 0.5)
        transport: optional httpx transport (e.g., httpx.ASGITransport) for in-process testing

    Returns:
        "ok" on success

    Raises:
        IngestError on permanent failure or invalid configuration
    """
    base_url = (url or _get_env_with_legacy("CHRONIK_URL", "LEITSTAND_URL") or "http://localhost:8788").rstrip("/")
    tok = token or _get_env_with_legacy("CHRONIK_TOKEN", "LEITSTAND_TOKEN")
    if not tok:
        raise IngestError("CHRONIK_TOKEN or LEITSTAND_TOKEN not set")

    if timeout is not None:
        t = float(timeout)
    else:
        timeout_str = _get_env_with_legacy("CHRONIK_TIMEOUT", "LEITSTAND_TIMEOUT")
        try:
            t = float(timeout_str) if timeout_str else 5.0
        except (ValueError, TypeError):
            t = 5.0
    
    if retries is not None:
        n = int(retries)
    else:
        retries_str = _get_env_with_legacy("CHRONIK_RETRIES", "LEITSTAND_RETRIES")
        try:
            n = int(retries_str) if retries_str else 3
        except (ValueError, TypeError):
            n = 3
    
    if backoff is not None:
        b0 = float(backoff)
    else:
        backoff_str = _get_env_with_legacy("CHRONIK_BACKOFF", "LEITSTAND_BACKOFF")
        try:
            b0 = float(backoff_str) if backoff_str else 0.5
        except (ValueError, TypeError):
            b0 = 0.5

    # Validate payload early (must be JSON-serializable mapping)
    if not isinstance(data, Mapping):
        raise IngestError("payload must be a mapping")
    if "event" not in data:
        # not strictly necessary, but helpful for consistency
        raise IngestError('payload missing required key "event"')

    # httpx client per call keeps things simple for small volumes
    url_full = f"{base_url}/ingest/{domain}"
    headers = {"X-Auth": tok, "Content-Type": "application/json"}
    payload: MutableMapping[str, Any] = dict(data)

    # Let server enforce "domain" field; if caller sets it, do not contradict path
    # (server already checks for mismatch and will 400 if different).

    for attempt in range(0, n + 1):
        try:
            # If transport is provided (e.g., ASGITransport), no real sockets are used.
            with httpx.Client(timeout=t, base_url=base_url, transport=transport) as client:
                r = client.post(url_full, headers=headers, json=payload)
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            if attempt < n:
                time.sleep(b0 * (2**attempt))
                continue
            raise IngestError(f"network/timeout after {attempt} retries") from exc

        # Fast path
        if r.status_code in (200, 202) and r.text.strip() == "ok":
            return "ok"

        # Retryable statuses
        if r.status_code in (429, 500, 502, 503, 504):
            if attempt < n:
                time.sleep(b0 * (2**attempt))
                continue
            raise IngestError(f"ingest failed with {r.status_code} after {attempt} retries: {r.text}")

        # Non-retryable: raise immediately with details
        try:
            detail = r.json()
        except json.JSONDecodeError:
            detail = r.text
        raise IngestError(f"ingest rejected: {r.status_code} {detail}")

    # Should not get here
    raise IngestError("ingest failed unexpectedly")
