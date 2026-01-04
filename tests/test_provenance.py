"""Tests for provenance validation module."""

import pytest
from provenance import (
    ProvenanceError,
    validate_provenance,
    ensure_provenance,
    has_provenance,
)


def test_validate_provenance_valid():
    """Test validation of a valid event with provenance."""
    payload = {
        "event_id": "123",
        "source": {
            "repo": "heimgewebe/chronik",
            "component": "test",
        },
        "data": {"value": 42},
    }
    # Should not raise
    validate_provenance(payload, strict=True)


def test_validate_provenance_missing_source():
    """Test validation fails when source is missing."""
    payload = {
        "event_id": "123",
        "data": {"value": 42},
    }
    with pytest.raises(ProvenanceError) as exc_info:
        validate_provenance(payload, strict=True)
    assert "source" in str(exc_info.value).lower()


def test_validate_provenance_missing_repo():
    """Test validation fails when source.repo is missing."""
    payload = {
        "event_id": "123",
        "source": {
            "component": "test",
        },
        "data": {"value": 42},
    }
    with pytest.raises(ProvenanceError) as exc_info:
        validate_provenance(payload, strict=True)
    assert "repo" in str(exc_info.value).lower()


def test_validate_provenance_missing_component():
    """Test validation fails when source.component is missing."""
    payload = {
        "event_id": "123",
        "source": {
            "repo": "heimgewebe/chronik",
        },
        "data": {"value": 42},
    }
    with pytest.raises(ProvenanceError) as exc_info:
        validate_provenance(payload, strict=True)
    assert "component" in str(exc_info.value).lower()


def test_validate_provenance_missing_event_id():
    """Test validation fails when event_id is missing."""
    payload = {
        "source": {
            "repo": "heimgewebe/chronik",
            "component": "test",
        },
        "data": {"value": 42},
    }
    with pytest.raises(ProvenanceError) as exc_info:
        validate_provenance(payload, strict=True)
    assert "event_id" in str(exc_info.value).lower() or "id" in str(exc_info.value).lower()


def test_validate_provenance_id_fallback():
    """Test that 'id' field can substitute for 'event_id'."""
    payload = {
        "id": "123",  # Using 'id' instead of 'event_id'
        "source": {
            "repo": "heimgewebe/chronik",
            "component": "test",
        },
        "data": {"value": 42},
    }
    # Should not raise
    validate_provenance(payload, strict=True)


def test_validate_provenance_non_strict():
    """Test non-strict mode doesn't raise, just logs."""
    payload = {
        "data": {"value": 42},
        # Missing all provenance fields
    }
    # Should not raise in non-strict mode
    validate_provenance(payload, strict=False)


def test_ensure_provenance_normalizes_id():
    """Test ensure_provenance normalizes 'id' to 'event_id'."""
    payload = {
        "id": "123",
        "source": {
            "repo": "heimgewebe/chronik",
            "component": "test",
        },
    }
    normalized = ensure_provenance(payload)
    assert normalized["event_id"] == "123"
    assert "id" in normalized  # Original field preserved


def test_has_provenance_valid():
    """Test has_provenance returns True for valid event."""
    payload = {
        "event_id": "123",
        "source": {
            "repo": "heimgewebe/chronik",
            "component": "test",
        },
    }
    assert has_provenance(payload) is True


def test_has_provenance_invalid():
    """Test has_provenance returns False for invalid event."""
    payload = {
        "data": {"value": 42},
    }
    assert has_provenance(payload) is False


def test_validate_provenance_invalid_source_type():
    """Test validation fails when source is not a dict."""
    payload = {
        "event_id": "123",
        "source": "not-a-dict",
    }
    with pytest.raises(ProvenanceError):
        validate_provenance(payload, strict=True)


def test_validate_provenance_invalid_repo_type():
    """Test validation fails when source.repo is not a string."""
    payload = {
        "event_id": "123",
        "source": {
            "repo": 123,  # Should be string
            "component": "test",
        },
    }
    with pytest.raises(ProvenanceError):
        validate_provenance(payload, strict=True)
