import sys
from unittest.mock import MagicMock, patch

# Mock 'limits' before importing slowapi_compat to avoid ModuleNotFoundError
mock_limits = MagicMock()
if "limits" not in sys.modules:
    sys.modules["limits"] = mock_limits

import slowapi_compat


def test_patch_rate_limit_item_adds_missing_attributes():
    """Test that missing attributes are correctly added to RateLimitItem."""

    class FakeRateLimitItem:
        def __str__(self):
            return "1 per minute"

    # Patch the reference in the module we are testing
    with patch("slowapi_compat.RateLimitItem", FakeRateLimitItem):
        slowapi_compat.patch_rate_limit_item()

        assert hasattr(FakeRateLimitItem, "error_message")
        assert hasattr(FakeRateLimitItem, "limit")

        item = FakeRateLimitItem()
        # Test the property behavior
        assert item.error_message == "Rate limit exceeded: 1 per minute"
        assert item.limit is item


def test_patch_rate_limit_item_respects_existing_attributes():
    """Test that existing attributes are not overwritten by the patch."""

    class FakeRateLimitItem:
        error_message = "custom message"
        limit = "custom limit"

    with patch("slowapi_compat.RateLimitItem", FakeRateLimitItem):
        slowapi_compat.patch_rate_limit_item()

        assert FakeRateLimitItem.error_message == "custom message"
        assert FakeRateLimitItem.limit == "custom limit"
