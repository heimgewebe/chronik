"""Tests for quality marker computation module."""

import pytest
from quality import (
    SignalStrength,
    compute_signal_strength,
    compute_completeness,
    add_quality_markers,
)


def test_compute_signal_strength_high():
    """Test high signal strength for complete event."""
    payload = {
        "kind": "test.event",
        "ts": "2026-01-04T10:00:00Z",
        "source": {"repo": "test", "component": "test"},
        "data": {"value": 42},
        "event_id": "123",
    }
    assert compute_signal_strength(payload) == SignalStrength.HIGH


def test_compute_signal_strength_medium():
    """Test medium signal strength for partially complete event."""
    payload = {
        "kind": "test.event",
        "ts": "2026-01-04T10:00:00Z",
        # Missing source and data/payload
    }
    assert compute_signal_strength(payload) == SignalStrength.MEDIUM


def test_compute_signal_strength_low():
    """Test low signal strength for sparse event."""
    payload = {
        "value": 42,
        # Missing most core fields
    }
    assert compute_signal_strength(payload) == SignalStrength.LOW


def test_compute_signal_strength_empty():
    """Test low signal strength for empty event."""
    payload = {}
    assert compute_signal_strength(payload) == SignalStrength.LOW


def test_compute_signal_strength_alternative_fields():
    """Test signal strength with alternative field names."""
    # Using 'type' instead of 'kind', 'timestamp' instead of 'ts'
    payload = {
        "type": "test.event",
        "timestamp": "2026-01-04T10:00:00Z",
        "source": {"repo": "test", "component": "test"},
        "payload": {"value": 42},
        "id": "123",
    }
    assert compute_signal_strength(payload) == SignalStrength.HIGH


def test_compute_completeness_default_required():
    """Test completeness with default required fields."""
    payload = {
        "kind": "test.event",
        "ts": "2026-01-04T10:00:00Z",
        "source": {"repo": "test", "component": "test"},
    }
    assert compute_completeness(payload) is True


def test_compute_completeness_missing_fields():
    """Test completeness fails when required fields missing."""
    payload = {
        "kind": "test.event",
        # Missing 'ts' and 'source'
    }
    assert compute_completeness(payload) is False


def test_compute_completeness_custom_required():
    """Test completeness with custom required fields."""
    payload = {
        "field1": "value1",
        "field2": "value2",
    }
    assert compute_completeness(payload, required_fields=["field1", "field2"]) is True
    assert compute_completeness(payload, required_fields=["field1", "field3"]) is False


def test_add_quality_markers():
    """Test adding quality markers to event."""
    payload = {
        "kind": "test.event",
        "ts": "2026-01-04T10:00:00Z",
        "source": {"repo": "test", "component": "test"},
        "data": {"value": 42},
        "event_id": "123",
    }
    enriched = add_quality_markers(payload)
    
    # Original payload should not be modified
    assert "quality" not in payload
    
    # Enriched payload should have quality markers
    assert "quality" in enriched
    assert enriched["quality"]["signal_strength"] == SignalStrength.HIGH
    assert enriched["quality"]["completeness"] is True


def test_add_quality_markers_low_quality():
    """Test quality markers for low-quality event."""
    payload = {
        "value": 42,
    }
    enriched = add_quality_markers(payload)
    
    assert enriched["quality"]["signal_strength"] == SignalStrength.LOW
    assert enriched["quality"]["completeness"] is False


def test_compute_signal_strength_non_dict():
    """Test signal strength for non-dict payload."""
    assert compute_signal_strength("not-a-dict") == SignalStrength.LOW
    assert compute_signal_strength(None) == SignalStrength.LOW
    assert compute_signal_strength([1, 2, 3]) == SignalStrength.LOW


def test_compute_completeness_non_dict():
    """Test completeness for non-dict payload."""
    assert compute_completeness("not-a-dict") is False
    assert compute_completeness(None) is False
