"""Retention policy management for chronik events.

This module handles:
- Loading retention policies from config/retention.yml
- Matching event types/domains to retention rules
- Computing TTL (time-to-live) for events
- Cleanup of expired events (via separate script/service)
"""

from __future__ import annotations

import fnmatch
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Final

import yaml

logger = logging.getLogger(__name__)

# Path to retention config
# This resolves to: <repo_root>/config/retention.yml
# since retention.py is at repo root level
RETENTION_CONFIG_PATH: Final[Path] = Path(__file__).parent / "config" / "retention.yml"

# Global cache for loaded policies
_RETENTION_POLICIES: list[dict] | None = None


class RetentionPolicy:
    """Represents a single retention policy rule."""
    
    def __init__(self, pattern: str, ttl_days: int, description: str = ""):
        self.pattern = pattern
        self.ttl_days = ttl_days
        self.description = description
    
    def matches(self, event_type: str) -> bool:
        """Check if this policy matches the given event type."""
        return fnmatch.fnmatch(event_type, self.pattern)
    
    def __repr__(self):
        return f"RetentionPolicy(pattern={self.pattern!r}, ttl_days={self.ttl_days})"


def load_retention_policies() -> list[RetentionPolicy]:
    """Load retention policies from config file.
    
    Returns:
        List of RetentionPolicy objects in priority order.
    
    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config is invalid
    """
    global _RETENTION_POLICIES
    
    if _RETENTION_POLICIES is not None:
        return _RETENTION_POLICIES
    
    if not RETENTION_CONFIG_PATH.exists():
        logger.warning(f"Retention config not found at {RETENTION_CONFIG_PATH}, using defaults")
        # Return default policy: 30 days for everything
        _RETENTION_POLICIES = [RetentionPolicy("*", 30, "Default retention")]
        return _RETENTION_POLICIES
    
    try:
        with open(RETENTION_CONFIG_PATH, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        
        if not config or "policies" not in config:
            raise ValueError("Invalid retention config: missing 'policies' key")
        
        policies = []
        for item in config["policies"]:
            pattern = item.get("pattern")
            ttl_days = item.get("ttl_days")
            description = item.get("description", "")
            
            if not pattern or ttl_days is None:
                logger.warning(f"Skipping invalid policy entry: {item}")
                continue
            
            policies.append(RetentionPolicy(pattern, ttl_days, description))
        
        if not policies:
            raise ValueError("No valid retention policies found in config")
        
        _RETENTION_POLICIES = policies
        logger.info(f"Loaded {len(policies)} retention policies")
        return policies
    
    except Exception as exc:
        logger.error(f"Failed to load retention policies: {exc}")
        # Fallback to default
        _RETENTION_POLICIES = [RetentionPolicy("*", 30, "Default retention (fallback)")]
        return _RETENTION_POLICIES


def get_ttl_for_event(event_type: str) -> int:
    """Get TTL in days for a given event type.
    
    Args:
        event_type: The event type/kind (e.g., "deploy.success", "debug.trace")
    
    Returns:
        TTL in days (0 means unlimited retention)
    """
    policies = load_retention_policies()
    
    for policy in policies:
        if policy.matches(event_type):
            logger.debug(f"Event type '{event_type}' matched policy: {policy}")
            return policy.ttl_days
    
    # Should not happen if config has a catch-all "*" rule
    logger.warning(f"No retention policy matched for event type: {event_type}")
    return 30  # Default fallback


def compute_expiry_date(event_type: str, received_at: datetime | None = None) -> datetime | None:
    """Compute the expiry date for an event based on retention policy.
    
    Args:
        event_type: The event type/kind
        received_at: When the event was received (defaults to now)
    
    Returns:
        Expiry datetime, or None if unlimited retention (TTL=0)
    """
    ttl_days = get_ttl_for_event(event_type)
    
    if ttl_days == 0:
        return None  # Unlimited retention
    
    if received_at is None:
        received_at = datetime.now(timezone.utc)
    
    return received_at + timedelta(days=ttl_days)


def is_expired(expiry_date: datetime | None) -> bool:
    """Check if an event has expired based on its expiry date.
    
    Args:
        expiry_date: The expiry datetime (None means never expires)
    
    Returns:
        True if expired, False otherwise
    """
    if expiry_date is None:
        return False  # Never expires
    
    return datetime.now(timezone.utc) >= expiry_date
