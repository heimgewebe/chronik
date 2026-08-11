"""Validation, normalization, and provenance stage for HTTP ingest items."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from provenance import validate_provenance
from storage import DomainError, sanitize_domain
from validation import normalize_heimgeist_item, validate_insights_daily_payload


def validate_and_normalize_item(
    entry: Any, domain: str, *, provenance_enforced: bool
) -> dict[str, Any]:
    """Return a validated outer copy without mutating the caller's item."""
    if not isinstance(entry, dict):
        raise HTTPException(status_code=400, detail="invalid payload")

    normalized = dict(entry)

    if domain == "insights.daily":
        validate_insights_daily_payload(normalized)
    elif domain == "heimgeist":
        normalized = normalize_heimgeist_item(normalized)
    else:
        summary = normalized.get("summary")
        if isinstance(summary, str) and len(summary) > 500:
            raise HTTPException(
                status_code=422, detail="summary too long (max 500)"
            )

        if "domain" in normalized:
            entry_domain = normalized["domain"]
            if not isinstance(entry_domain, str):
                raise HTTPException(status_code=400, detail="invalid payload")

            try:
                sanitized_entry_domain = sanitize_domain(entry_domain)
            except DomainError as exc:
                raise HTTPException(status_code=400, detail="invalid payload") from exc
            if sanitized_entry_domain != domain:
                raise HTTPException(status_code=400, detail="domain mismatch")

    validate_provenance(normalized, strict=provenance_enforced)
    return normalized
