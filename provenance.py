"""Event provenance validation for chronik.

Enforces that all events have clear provenance metadata:
- source.repo / source.component for the canonical event shape; or
- meta.provenance.repo / meta.provenance.component when a domain contract
  already uses top-level ``source`` for its own source label; and
- event_id: Unique identifier for the event
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class ProvenanceError(ValueError):
    """Raised when an event lacks required provenance metadata."""
    pass


def _provenance_source(payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Return the authoritative provenance object without masking malformed canonical provenance."""
    source = payload.get("source")
    if isinstance(source, dict):
        return source, "source"

    if isinstance(source, str) and source.strip():
        meta = payload.get("meta")
        if isinstance(meta, dict):
            fallback = meta.get("provenance")
            if isinstance(fallback, dict):
                return fallback, "meta.provenance"
    return None, "source or meta.provenance"


def validate_provenance(payload: dict, strict: bool = True) -> None:
    """Validate that an event has required provenance fields.
    
    Required fields:
    - source.repo/source.component for canonical events; or meta.provenance.repo/
      meta.provenance.component when top-level source is occupied by a domain schema
    - event_id: Unique event identifier
    
    Args:
        payload: The event payload to validate
        strict: If True, raises error on missing fields. If False, only logs warning.
    
    Raises:
        ProvenanceError: If strict=True and required fields are missing
    """
    if not isinstance(payload, dict):
        if strict:
            raise ProvenanceError("payload must be a dict")
        return
    
    missing_fields = []
    
    # Prefer the canonical top-level source object. Only when top-level source
    # is not an object may a domain-specific contract supply provenance under
    # meta.provenance. This deliberately does not let fallback metadata hide a
    # malformed canonical source object.
    source, source_path = _provenance_source(payload)
    if source is None:
        missing_fields.append("source (must be an object)")
    else:
        if not source.get("repo"):
            missing_fields.append(f"{source_path}.repo")
        elif not isinstance(source["repo"], str):
            missing_fields.append(f"{source_path}.repo (must be a string)")

        if not source.get("component"):
            missing_fields.append(f"{source_path}.component")
        elif not isinstance(source["component"], str):
            missing_fields.append(f"{source_path}.component (must be a string)")
    
    # Check for event_id
    event_id = payload.get("event_id") or payload.get("id")
    if not event_id:
        missing_fields.append("event_id (or id)")
    elif not isinstance(event_id, str):
        missing_fields.append("event_id (must be a string)")
    
    if missing_fields:
        error_msg = f"Missing or invalid provenance fields: {', '.join(missing_fields)}"
        if strict:
            raise ProvenanceError(error_msg)
        else:
            logger.warning(f"Provenance validation failed: {error_msg}")


def ensure_provenance(payload: dict) -> dict:
    """Ensure event has provenance fields, normalizing if needed.
    
    This function:
    1. Validates provenance (raises on missing fields)
    2. Normalizes field names (e.g., id -> event_id)
    
    Args:
        payload: The event payload
    
    Returns:
        Normalized payload with validated provenance and a normalized event_id.
        Domain-specific source fields are preserved rather than rewritten.
    
    Raises:
        ProvenanceError: If required provenance fields are missing
    """
    # Validate first (strict mode)
    validate_provenance(payload, strict=True)
    
    # Create normalized copy
    normalized = dict(payload)
    
    # Normalize event_id: prefer event_id, fall back to id
    if "event_id" not in normalized and "id" in normalized:
        normalized["event_id"] = normalized["id"]
    
    return normalized


def has_provenance(payload: dict) -> bool:
    """Check if an event has valid provenance fields.
    
    Args:
        payload: The event payload
    
    Returns:
        True if provenance is valid, False otherwise
    """
    try:
        validate_provenance(payload, strict=True)
        return True
    except ProvenanceError:
        return False
