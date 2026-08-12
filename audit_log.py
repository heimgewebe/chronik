"""Structured, non-authoritative audit logging for Chronik ingest decisions.

Audit events are emitted as one-line JSON to a dedicated logger. They are
observability evidence only: they do not grant append authority and never
replace Chronik's canonical JSONL ledger.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Literal

AuditAction = Literal["ACCEPTED", "REJECTED"]

_AUDIT_IP_KEY = secrets.token_bytes(32)
_MAX_REQUEST_ID = 128
_MAX_DOMAIN = 253
_MAX_REASON = 240


def _configure_audit_logger() -> logging.Logger:
    logger = logging.getLogger("chronik.audit")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


audit_logger = _configure_audit_logger()


def _bounded_text(value: str | None, *, default: str, max_length: int) -> str:
    if value is None:
        return default
    text = str(value)
    if not text:
        return default
    return text[:max_length]


def anonymize_client_ip(client_ip: str | None, *, key: bytes | None = None) -> str:
    """Return a process-local pseudonymous identifier without persisting raw IPs."""
    if not client_ip:
        return "unknown"
    digest = hmac.new(
        _AUDIT_IP_KEY if key is None else key,
        client_ip.encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).hexdigest()
    return f"anon:{digest[:20]}"


def build_audit_event(
    *,
    request_id: str | None,
    domain: str | None,
    action: AuditAction,
    reason: str | None,
    client_ip: str | None,
    now: datetime | None = None,
) -> dict[str, str]:
    """Build the stable JSON-compatible audit event contract."""
    timestamp = now or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp = timestamp.astimezone(timezone.utc)
    timestamp_text = timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    return {
        "timestamp": timestamp_text,
        "request_id": _bounded_text(
            request_id, default="unknown", max_length=_MAX_REQUEST_ID
        ),
        "domain": _bounded_text(domain, default="unknown", max_length=_MAX_DOMAIN),
        "action": action,
        "reason": _bounded_text(reason, default="unspecified", max_length=_MAX_REASON),
        "client_ip": anonymize_client_ip(client_ip),
    }


def emit_audit_event(
    *,
    request_id: str | None,
    domain: str | None,
    action: AuditAction,
    reason: str | None,
    client_ip: str | None,
) -> dict[str, str]:
    """Emit one audit event without allowing logging failure to change HTTP semantics."""
    event = build_audit_event(
        request_id=request_id,
        domain=domain,
        action=action,
        reason=reason,
        client_ip=client_ip,
    )
    try:
        audit_logger.info(
            json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        )
    except Exception:
        # Audit telemetry must never become append or response authority, even
        # when both the dedicated and fallback logging backends are unhealthy.
        try:
            logging.getLogger("chronik").exception("failed to emit ingest audit event")
        except Exception:
            pass
    return event
