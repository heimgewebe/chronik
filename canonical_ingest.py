"""Canonical Chronik envelope construction shared by API and local importers."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from quality import compute_completeness, compute_signal_strength
from retention import compute_expiry_date, get_ttl_for_event


def build_envelope(domain: str, payload: dict[str, Any], *, received_at: datetime | None = None, quality_enabled: bool = True) -> dict[str, Any]:
    observed = received_at or datetime.now(timezone.utc)
    if observed.tzinfo is None:
        raise ValueError("received_at must be timezone-aware")
    observed = observed.astimezone(timezone.utc)
    event_type = payload.get("kind") or payload.get("type") or payload.get("event") or "unknown"
    expiry = compute_expiry_date(str(event_type), observed)
    wrapper: dict[str, Any] = {
        "domain": domain,
        "received_at": observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "payload": dict(payload),
        "retention": {
            "ttl_days": get_ttl_for_event(str(event_type)),
            "expires_at": expiry.strftime("%Y-%m-%dT%H:%M:%SZ") if expiry else None,
        },
    }
    if quality_enabled:
        wrapper["quality"] = {
            "signal_strength": compute_signal_strength(payload).value,
            "completeness": compute_completeness(payload),
        }
    return wrapper
