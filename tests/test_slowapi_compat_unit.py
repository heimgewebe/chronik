import importlib
import sys
import types
from contextlib import contextmanager

@contextmanager
def isolated_slowapi_compat_import(mock_limits_module):
    """Context manager to import slowapi_compat in an isolated environment."""
    # Store original state and presence
    had_slowapi_compat = "slowapi_compat" in sys.modules
    had_limits = "limits" in sys.modules
    original_slowapi_compat = sys.modules.get("slowapi_compat")
    original_limits = sys.modules.get("limits")

    try:
        # Set up mocks in sys.modules
        sys.modules["limits"] = mock_limits_module
        if "slowapi_compat" in sys.modules:
            del sys.modules["slowapi_compat"]

        # Import the module
        module = importlib.import_module("slowapi_compat")
        yield module
    finally:
        # Restore original state or clean up
        if "slowapi_compat" in sys.modules:
            del sys.modules["slowapi_compat"]

        if had_slowapi_compat:
            sys.modules["slowapi_compat"] = original_slowapi_compat

        if had_limits:
            sys.modules["limits"] = original_limits
        elif "limits" in sys.modules:
            del sys.modules["limits"]


def create_fake_limits_module(rate_limit_item_class):
    """Create a real module object for 'limits'."""
    mock_limits = types.ModuleType("limits")
    mock_limits.RateLimitItem = rate_limit_item_class
    return mock_limits


def test_patch_rate_limit_item_adds_missing_attributes():
    """Test that missing attributes are correctly added to RateLimitItem."""

    class FakeRateLimitItem:
        def __str__(self):
            return "1 per minute"

    # Ensure it doesn't have the attributes initially
    assert not hasattr(FakeRateLimitItem, "error_message")
    assert not hasattr(FakeRateLimitItem, "limit")

    mock_limits = create_fake_limits_module(FakeRateLimitItem)

    with isolated_slowapi_compat_import(mock_limits) as slowapi_compat:
        # The module calls patch_rate_limit_item() on import,
        # but we call it explicitly to be sure we are testing the function logic.
        slowapi_compat.patch_rate_limit_item()

        item = FakeRateLimitItem()
        # Verify behavioral correctness
        assert item.error_message == "Rate limit exceeded: 1 per minute"
        assert item.limit is item


def test_patch_rate_limit_item_respects_existing_attributes():
    """Test that existing attributes are not overwritten by the patch."""

    class FakeRateLimitItem:
        error_message = "custom message"
        limit = "custom limit"
        def __str__(self):
            return "1 per minute"

    mock_limits = create_fake_limits_module(FakeRateLimitItem)

    with isolated_slowapi_compat_import(mock_limits) as slowapi_compat:
        slowapi_compat.patch_rate_limit_item()

        assert FakeRateLimitItem.error_message == "custom message"
        assert FakeRateLimitItem.limit == "custom limit"


def test_patch_rate_limit_item_is_idempotent():
    """Test that calling patch_rate_limit_item multiple times is safe."""

    class FakeRateLimitItem:
        def __str__(self):
            return "1 per minute"

    mock_limits = create_fake_limits_module(FakeRateLimitItem)

    with isolated_slowapi_compat_import(mock_limits) as slowapi_compat:
        # Apply patch twice
        slowapi_compat.patch_rate_limit_item()
        slowapi_compat.patch_rate_limit_item()

        item = FakeRateLimitItem()
        assert item.error_message == "Rate limit exceeded: 1 per minute"
        assert item.limit is item
