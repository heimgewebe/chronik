"""Quality marker computation for chronik events.

This module provides rule-based (not semantic) quality assessment:
- signal_strength: Measures completeness and structure quality
- completeness: Checks if expected fields are present

Quality markers are purely structural/formal, NOT semantic interpretations.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class SignalStrength(str, Enum):
    """Event signal strength levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def compute_signal_strength(payload: dict) -> SignalStrength:
    """Compute signal strength based on structural completeness.
    
    Rule-based assessment (not semantic):
    - HIGH: Has core fields (kind/type, timestamp, source, data/payload)
    - MEDIUM: Has some core fields but incomplete
    - LOW: Missing most core fields or very sparse
    
    Args:
        payload: The event payload to assess
    
    Returns:
        Signal strength: "low", "medium", or "high"
    """
    if not isinstance(payload, dict):
        return SignalStrength.LOW
    
    # Core fields we expect for high-quality events
    has_kind = "kind" in payload or "type" in payload or "event" in payload
    has_timestamp = "ts" in payload or "timestamp" in payload or "occurred_at" in payload
    has_source = "source" in payload
    has_data = "data" in payload or "payload" in payload or len(payload) > 3
    
    # ID field is also valuable
    has_id = "id" in payload or "event_id" in payload
    
    score = sum([has_kind, has_timestamp, has_source, has_data, has_id])
    
    if score >= 4:
        return SignalStrength.HIGH
    elif score >= 2:
        return SignalStrength.MEDIUM
    else:
        return SignalStrength.LOW


def compute_completeness(payload: dict, required_fields: list[str] | None = None) -> bool:
    """Check if payload has all required fields.
    
    Recognizes common field synonyms to avoid false negatives:
    - kind/type/event (event type)
    - ts/timestamp/occurred_at (timestamp)
    - source (provenance)
    
    Args:
        payload: The event payload
        required_fields: List of required field names (optional, uses defaults if None)
    
    Returns:
        True if complete, False otherwise
    """
    if not isinstance(payload, dict):
        return False
    
    if required_fields is not None:
        # Custom required fields - check exactly as specified
        return all(field in payload for field in required_fields)
    
    # Default: check for core event fields with synonym support
    # Event type (at least one variant)
    has_kind = "kind" in payload or "type" in payload or "event" in payload
    
    # Timestamp (at least one variant)
    has_timestamp = "ts" in payload or "timestamp" in payload or "occurred_at" in payload
    
    # Source (provenance)
    has_source = "source" in payload
    
    return has_kind and has_timestamp and has_source


def add_quality_markers(payload: dict) -> dict:
    """Add quality markers to an event payload.
    
    This function augments the payload with quality metadata:
    - quality.signal_strength
    - quality.completeness
    
    Args:
        payload: The event payload (will not be modified in-place)
    
    Returns:
        New dict with quality markers added
    """
    # Don't modify the original
    enriched = dict(payload)
    
    # Compute quality markers
    signal_strength = compute_signal_strength(payload)
    completeness = compute_completeness(payload)
    
    # Add quality metadata
    enriched["quality"] = {
        "signal_strength": signal_strength.value if hasattr(signal_strength, 'value') else signal_strength,
        "completeness": completeness,
    }
    
    return enriched
