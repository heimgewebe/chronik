"""Tests for metric label sanitization and cardinality protection."""

import pytest
from app import _sanitize_metric_label


def test_sanitize_metric_label_normal():
    """Test sanitization of normal event types."""
    assert _sanitize_metric_label("deploy.success") == "deploy.success"
    assert _sanitize_metric_label("test.event.v1") == "test.event.v1"
    assert _sanitize_metric_label("app_start") == "app_start"


def test_sanitize_metric_label_too_long():
    """Test truncation of very long labels."""
    long_label = "a" * 100
    sanitized = _sanitize_metric_label(long_label)
    assert len(sanitized) == 80
    assert sanitized == "a" * 80


def test_sanitize_metric_label_special_chars():
    """Test replacement of special characters."""
    assert _sanitize_metric_label("test/event") == "test_event"
    assert _sanitize_metric_label("test:event") == "test_event"
    assert _sanitize_metric_label("test@event") == "test_event"
    assert _sanitize_metric_label("test event") == "test_event"
    assert _sanitize_metric_label("test,event;data") == "test_event_data"


def test_sanitize_metric_label_empty():
    """Test handling of empty or invalid values."""
    assert _sanitize_metric_label("") == "unknown"
    assert _sanitize_metric_label(None) == "unknown"
    assert _sanitize_metric_label(123) == "unknown"


def test_sanitize_metric_label_only_special_chars():
    """Test handling of labels that become empty after sanitization."""
    assert _sanitize_metric_label("@@@") == "unknown"
    assert _sanitize_metric_label("!!!") == "unknown"
    assert _sanitize_metric_label("   ") == "unknown"


def test_sanitize_metric_label_preserves_valid_chars():
    """Test that valid characters are preserved."""
    assert _sanitize_metric_label("app.test-v1_final") == "app.test-v1_final"
    assert _sanitize_metric_label("ABC123xyz") == "ABC123xyz"


def test_sanitize_metric_label_unicode():
    """Test handling of unicode characters."""
    assert _sanitize_metric_label("test.événement") == "test._v_nement"
    assert _sanitize_metric_label("テスト") == "unknown"  # All special chars → unknown
