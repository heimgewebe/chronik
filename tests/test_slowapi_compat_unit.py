import importlib
import sys
from unittest.mock import MagicMock, patch

def get_isolated_slowapi_compat():
    """Import slowapi_compat in an isolated environment with mocked limits."""
    # Mock limits module
    mock_limits = MagicMock()

    # Use patch.dict to safely modify sys.modules only during the import
    with patch.dict(sys.modules, {"limits": mock_limits}):
        # Force a reload of the module to ensure it picks up the mock
        if "slowapi_compat" in sys.modules:
            del sys.modules["slowapi_compat"]

        return importlib.import_module("slowapi_compat")


def test_patch_rate_limit_item_adds_missing_attributes():
    """Test that missing attributes are correctly added to RateLimitItem."""
    slowapi_compat = get_isolated_slowapi_compat()

    class FakeRateLimitItem:
        def __str__(self):
            return "1 per minute"

    # Patch the reference in the isolated module
    with patch.object(slowapi_compat, "RateLimitItem", FakeRateLimitItem):
        slowapi_compat.patch_rate_limit_item()

        assert hasattr(FakeRateLimitItem, "error_message")
        assert hasattr(FakeRateLimitItem, "limit")

        item = FakeRateLimitItem()
        # Test the property behavior
        assert item.error_message == "Rate limit exceeded: 1 per minute"
        assert item.limit is item


def test_patch_rate_limit_item_respects_existing_attributes():
    """Test that existing attributes are not overwritten by the patch."""
    slowapi_compat = get_isolated_slowapi_compat()

    class FakeRateLimitItem:
        error_message = "custom message"
        limit = "custom limit"

    # Patch the reference in the isolated module
    with patch.object(slowapi_compat, "RateLimitItem", FakeRateLimitItem):
        slowapi_compat.patch_rate_limit_item()

        assert FakeRateLimitItem.error_message == "custom message"
        assert FakeRateLimitItem.limit == "custom limit"
