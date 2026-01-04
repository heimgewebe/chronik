"""Event provenance validation for chronik.

Enforces that all events have clear provenance metadata:
- source.repo: Repository/system name
- source.component: Component within the system
- event_id: Unique identifier for the event
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class ProvenanceError(ValueError):
    """Raised when an event lacks required provenance metadata."""
    pass


def validate_provenance(payload: dict, strict: bool = True) -> None:
    """Validate that an event has required provenance fields.
    
    Required fields:
    - source.repo: String identifying the source repository
    - source.component: String identifying the component
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
    
    # Check for source object
    source = payload.get("source")
    if not isinstance(source, dict):
        missing_fields.append("source (must be an object)")
    else:
        # Check source.repo
        if not source.get("repo"):
            missing_fields.append("source.repo")
        elif not isinstance(source["repo"], str):
            missing_fields.append("source.repo (must be a string)")
        
        # Check source.component
        if not source.get("component"):
            missing_fields.append("source.component")
        elif not isinstance(source["component"], str):
            missing_fields.append("source.component (must be a string)")
    
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
        Normalized payload with guaranteed provenance fields
    
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
