
import pytest
from unittest.mock import patch, mock_open
import retention
from retention import get_ttl_for_event, load_retention_policies, reload_retention_policies, RetentionPolicy

def test_lru_cache_behavior():
    """Verify that get_ttl_for_event uses the LRU cache."""
    # Reset cache and policies
    reload_retention_policies()
    get_ttl_for_event.cache_clear()

    event_type = "debug.trace"

    # First call: Cache miss
    ttl1 = get_ttl_for_event(event_type)
    info1 = get_ttl_for_event.cache_info()

    # Second call: Cache hit
    ttl2 = get_ttl_for_event(event_type)
    info2 = get_ttl_for_event.cache_info()

    assert ttl1 == ttl2
    assert info2.hits == info1.hits + 1
    assert info2.misses == info1.misses # Misses shouldn't increase

def test_cache_invalidation_on_reload():
    """Verify that reloading policies invalidates the cache."""
    # Setup initial mock config
    initial_policies = [RetentionPolicy("test.*", 7)]

    with patch("retention.load_retention_policies", return_value=initial_policies) as mock_load:
        # We mock load_retention_policies directly to simulate the return value,
        # BUT we need to test the invalidation logic which happens INSIDE load_retention_policies
        # (in the real function).
        # So we cannot mock the function we are testing.
        pass

    # Better approach: Mock the yaml loading part or use a temp file.
    # Since load_retention_policies uses RETENTION_CONFIG_PATH, we can patch that or the open call.
    # But since we modified `load_retention_policies` to call `cache_clear`, we need to actually call it.

    # 1. Reset
    get_ttl_for_event.cache_clear()
    retention._RETENTION_POLICIES = None

    # 2. Mock policies via _RETENTION_POLICIES injection first for simplicity?
    # No, load_retention_policies checks global var.

    # Let's mock yaml.safe_load to return different configs

    config_v1 = {"policies": [{"pattern": "test.event", "ttl_days": 10}]}
    config_v2 = {"policies": [{"pattern": "test.event", "ttl_days": 20}]}

    with patch("yaml.safe_load", return_value=config_v1):
        # Force reload to load v1
        load_retention_policies(force_reload=True)
        assert get_ttl_for_event("test.event") == 10
        # Call again to ensure cached
        assert get_ttl_for_event("test.event") == 10

    # Verify cache is populated
    assert get_ttl_for_event.cache_info().currsize > 0

    # 3. Change config and force reload
    with patch("yaml.safe_load", return_value=config_v2):
        # This calls load_retention_policies(force_reload=True), which should clear cache
        reload_retention_policies()

        # Verify new value is returned (cache was cleared)
        assert get_ttl_for_event("test.event") == 20

def test_force_reload_clears_cache():
    """Verify explicit force_reload=True clears cache."""
    # 1. Setup
    config_v1 = {"policies": [{"pattern": "my.event", "ttl_days": 5}]}
    config_v2 = {"policies": [{"pattern": "my.event", "ttl_days": 99}]}

    with patch("yaml.safe_load", return_value=config_v1):
        load_retention_policies(force_reload=True)
        assert get_ttl_for_event("my.event") == 5

    # 2. Update config and reload with force_reload=True
    with patch("yaml.safe_load", return_value=config_v2):
        load_retention_policies(force_reload=True)
        assert get_ttl_for_event("my.event") == 99
