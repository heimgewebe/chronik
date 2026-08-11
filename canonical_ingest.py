"""Functional envelope stages shared by the API and local importers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from quality import compute_completeness, compute_signal_strength
from retention import compute_expiry_date, get_ttl_for_event


def _as_utc(observed: datetime) -> datetime:
    if observed.tzinfo is None:
        raise ValueError("received_at must be timezone-aware")
    return observed.astimezone(timezone.utc)


def payload_event_type(payload: dict[str, Any]) -> Any:
    """Return the event type using Chronik's established field priority."""
    return payload.get("kind") or payload.get("type") or payload.get("event")


def build_quality_envelope(
    domain: str,
    payload: dict[str, Any],
    *,
    received_at: datetime | None = None,
    quality_enabled: bool = True,
) -> dict[str, Any]:
    """Build the copied base envelope and optional structural quality markers."""
    observed = _as_utc(received_at or datetime.now(timezone.utc))

    envelope: dict[str, Any] = {
        "domain": domain,
        "received_at": observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "payload": dict(payload),
    }
    if quality_enabled:
        envelope["quality"] = {
            "signal_strength": compute_signal_strength(payload).value,
            "completeness": compute_completeness(payload),
        }
    return envelope


def apply_retention_policy(
    quality_envelope: dict[str, Any], *, received_at: datetime | None = None
) -> dict[str, Any]:
    """Return an independently owned envelope ready for persistence."""
    payload = quality_envelope["payload"]
    if received_at is None:
        observed = datetime.strptime(
            quality_envelope["received_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    else:
        observed = _as_utc(received_at)
    event_type = payload_event_type(payload) or "unknown"
    expiry = compute_expiry_date(str(event_type), observed)

    envelope: dict[str, Any] = {
        "domain": quality_envelope["domain"],
        "received_at": quality_envelope["received_at"],
        "payload": dict(payload),
        "retention": {
            "ttl_days": get_ttl_for_event(str(event_type)),
            "expires_at": expiry.strftime("%Y-%m-%dT%H:%M:%SZ") if expiry else None,
        },
    }
    if "quality" in quality_envelope:
        envelope["quality"] = dict(quality_envelope["quality"])
    return envelope


def build_envelope(
    domain: str,
    payload: dict[str, Any],
    *,
    received_at: datetime | None = None,
    quality_enabled: bool = True,
) -> dict[str, Any]:
    """Compose the quality and retention stages for compatibility callers."""
    observed = received_at or datetime.now(timezone.utc)
    quality_envelope = build_quality_envelope(
        domain,
        payload,
        received_at=observed,
        quality_enabled=quality_enabled,
    )
    return apply_retention_policy(quality_envelope, received_at=observed)
