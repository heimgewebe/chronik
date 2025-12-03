from __future__ import annotations

import json
import os
import time
from typing import Any, Mapping, Sequence, Union, Optional

import httpx

__all__ = ["ingest_event", "IngestError"]


class IngestError(RuntimeError):
    """Raised when an ingest attempt ultimately fails."""


def _get_env(name: str) -> str | None:
    """Get environment variable."""
    return os.getenv(name)


def _parse_env_param(
    param_value: Optional[float | int],
    env_name: str,
    default_value: float | int,
    converter_func: type[float] | type[int],
) -> float | int:
    """Parse environment parameter with error handling."""
    if param_value is not None:
        return converter_func(param_value)

    env_str = _get_env(env_name)
    try:
        return converter_func(env_str) if env_str else default_value
    except (ValueError, TypeError):
        return default_value


def ingest_event(
    domain: str,
    data: Union[Mapping[str, Any], Sequence[Mapping[str, Any]]],
    *,
    url: Optional[str] = None,
    token: Optional[str] = None,
    timeout: Optional[float] = None,
    retries: Optional[int] = None,
    backoff: Optional[float] = None,
    transport: Optional[httpx.BaseTransport] = None,
) -> str:
    """
    Send one or more JSON events to Chronik.

    Args:
        domain: target domain (e.g. "example.com")
        data: JSON-serializable mapping (event) or list of mappings (batch)
        url: base URL of Chronik (env CHRONIK_URL if None)
        token: shared secret for X-Auth (env CHRONIK_TOKEN if None)
        timeout: request timeout seconds (env CHRONIK_TIMEOUT, default 5)
        retries: retry count for 429/5xx/timeout (env CHRONIK_RETRIES, default 3)
        backoff: initial backoff seconds (env CHRONIK_BACKOFF, default 0.5)
        transport: optional httpx transport (e.g., TestClient's transport)
            for in-process testing

    Returns:
        "ok" on success

    Raises:
        IngestError on permanent failure or invalid configuration
    """
    base_url = (
        url
        or _get_env("CHRONIK_URL")
        or "http://localhost:8788"
    ).rstrip("/")
    tok = token or _get_env("CHRONIK_TOKEN")
    if not tok:
        raise IngestError("CHRONIK_TOKEN not set")

    t = _parse_env_param(
        timeout, "CHRONIK_TIMEOUT", 5.0, float
    )
    n = _parse_env_param(retries, "CHRONIK_RETRIES", 3, int)
    b0 = _parse_env_param(
        backoff, "CHRONIK_BACKOFF", 0.5, float
    )

    # Validate payload early
    if isinstance(data, Mapping):
        payload = dict(data)
        if "event" not in payload:
            raise IngestError('payload missing required key "event"')
    elif isinstance(data, Sequence) and not isinstance(data, (str, bytes)):
        payload = [dict(item) for item in data]
        if not payload:
            raise IngestError("empty batch payload")
    else:
        raise IngestError("payload must be a mapping or sequence of mappings")

    # httpx client per call keeps things simple for small volumes
    url_full = f"{base_url}/v1/ingest"
    params = {"domain": domain}
    headers = {"X-Auth": tok, "Content-Type": "application/json"}

    # Let server enforce "domain" field; if caller sets it, do not contradict path
    # (server already checks for mismatch and will 400 if different).

    for attempt in range(0, n + 1):
        try:
            # If transport is provided (e.g., TestClient transport), no real sockets
            # are used.
            with httpx.Client(
                timeout=t, base_url=base_url, transport=transport
            ) as client:
                r = client.post(
                    url_full, params=params, headers=headers, json=payload
                )
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
            raise IngestError(
                f"ingest failed with {r.status_code} "
                f"after {attempt} retries: {r.text}"
            )

        # Non-retryable: raise immediately with details
        try:
            detail = r.json()
        except (json.JSONDecodeError, ValueError):
            # httpx.Response.json() can raise ValueError if the body isn't valid JSON
            detail = r.text
        raise IngestError(f"ingest rejected: {r.status_code} {detail}")

    # Should not get here
    raise IngestError("ingest failed unexpectedly")
