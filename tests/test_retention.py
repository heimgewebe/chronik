"""Tests for retention policy module."""

import pytest
from datetime import datetime, timedelta, timezone
from retention import (
    RetentionPolicy,
    load_retention_policies,
    get_ttl_for_event,
    compute_expiry_date,
    is_expired,
)


def test_retention_policy_matches():
    """Test retention policy pattern matching."""
    policy = RetentionPolicy("*.debug.*", 7, "Debug events")
    
    assert policy.matches("foo.debug.bar") is True
    assert policy.matches("debug.test") is True
    assert policy.matches("foo.prod.bar") is False


def test_load_retention_policies():
    """Test loading retention policies from config."""
    policies = load_retention_policies()
    
    # Should have at least one policy
    assert len(policies) > 0
    
    # Each policy should have required fields
    for policy in policies:
        assert policy.pattern
        assert policy.ttl_days is not None


def test_get_ttl_for_event_debug():
    """Test TTL for debug events."""
    ttl = get_ttl_for_event("foo.debug.bar")
    assert ttl == 7  # Debug events have 7 days TTL


def test_get_ttl_for_event_published():
    """Test TTL for published events."""
    ttl = get_ttl_for_event("event.published.v1")
    assert ttl == 0  # Published events have unlimited retention


def test_get_ttl_for_event_insights():
    """Test TTL for insights events."""
    ttl = get_ttl_for_event("insights.daily")
    assert ttl == 90  # Insights have 90 days TTL


def test_get_ttl_for_event_default():
    """Test TTL for unmatched events."""
    ttl = get_ttl_for_event("unknown.event.type")
    assert ttl == 30  # Default is 30 days


def test_compute_expiry_date_with_ttl():
    """Test expiry date computation for events with TTL."""
    received_at = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    expiry = compute_expiry_date("foo.debug.bar", received_at)
    
    expected = received_at + timedelta(days=7)
    assert expiry == expected


def test_compute_expiry_date_unlimited():
    """Test expiry date computation for events with unlimited retention."""
    received_at = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    expiry = compute_expiry_date("event.published.v1", received_at)
    
    assert expiry is None  # Unlimited retention


def test_compute_expiry_date_no_received_at():
    """Test expiry date computation without explicit received_at."""
    expiry = compute_expiry_date("foo.debug.bar")
    
    # Should compute relative to current time
    assert expiry is not None
    assert expiry > datetime.now(timezone.utc)


def test_is_expired_not_expired():
    """Test is_expired for non-expired event."""
    future_date = datetime.now(timezone.utc) + timedelta(days=7)
    assert is_expired(future_date) is False


def test_is_expired_expired():
    """Test is_expired for expired event."""
    past_date = datetime.now(timezone.utc) - timedelta(days=1)
    assert is_expired(past_date) is True


def test_is_expired_unlimited():
    """Test is_expired for unlimited retention (None)."""
    assert is_expired(None) is False


def test_is_expired_exactly_now():
    """Test is_expired for event expiring exactly now."""
    now = datetime.now(timezone.utc)
    # Should be considered expired (>= comparison)
    assert is_expired(now) is True


def test_retention_policy_repr():
    """Test RetentionPolicy string representation."""
    policy = RetentionPolicy("*.test.*", 7, "Test events")
    repr_str = repr(policy)
    assert "*.test.*" in repr_str
    assert "7" in repr_str
