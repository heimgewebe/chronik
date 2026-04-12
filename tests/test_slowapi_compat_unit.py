import importlib
import sys
from unittest.mock import MagicMock, patch

def get_isolated_slowapi_compat():
    """Import slowapi_compat in an isolated environment with mocked limits."""
    # Mock limits module
    mock_limits = MagicMock()

    # Use patch.dict to safely modify sys.modules only during the import
    with patch.dict(sys.modules, {"limits": mock_limits}):
        # Force a fresh load of the module
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

        item = FakeRateLimitItem()
        # Verify behavioral correctness, not just existence
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


def test_patch_rate_limit_item_is_idempotent():
    """Test that calling patch_rate_limit_item multiple times is safe."""
    slowapi_compat = get_isolated_slowapi_compat()

    class FakeRateLimitItem:
        def __str__(self):
            return "1 per minute"

    with patch.object(slowapi_compat, "RateLimitItem", FakeRateLimitItem):
        # Apply patch twice
        slowapi_compat.patch_rate_limit_item()
        slowapi_compat.patch_rate_limit_item()

        item = FakeRateLimitItem()
        assert item.error_message == "Rate limit exceeded: 1 per minute"
        assert item.limit is item
