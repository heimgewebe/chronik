import pytest
import yaml
import retention
from retention import get_ttl_for_event, load_retention_policies, reload_retention_policies

@pytest.fixture
def temp_retention_config(tmp_path, monkeypatch):
    """Fixture to set up a temporary retention config file."""
    config_file = tmp_path / "retention.yml"
    monkeypatch.setattr(retention, "RETENTION_CONFIG_PATH", config_file)

    # Reset global state before test
    monkeypatch.setattr(retention, "_RETENTION_POLICIES", None)
    get_ttl_for_event.cache_clear()

    yield config_file

    # Cleanup after test
    monkeypatch.setattr(retention, "_RETENTION_POLICIES", None)
    get_ttl_for_event.cache_clear()

def create_config(file_path, ttl):
    """Helper to write a retention config file."""
    config_data = {
        "policies": [
            {
                "pattern": "test.event",
                "ttl_days": ttl,
                "description": f"Test policy {ttl}"
            }
        ]
    }
    with open(file_path, "w") as f:
        yaml.dump(config_data, f)

def test_lru_cache_behavior(temp_retention_config):
    """Verify that get_ttl_for_event uses the LRU cache."""
    create_config(temp_retention_config, 10)

    # Ensure policies are loaded
    load_retention_policies(force_reload=True)

    # First call: Cache miss
    ttl1 = get_ttl_for_event("test.event")
    info1 = get_ttl_for_event.cache_info()

    # Second call: Cache hit
    ttl2 = get_ttl_for_event("test.event")
    info2 = get_ttl_for_event.cache_info()

    assert ttl1 == 10
    assert ttl2 == 10
    assert info2.hits == info1.hits + 1
    # Note: misses might not be stable if other tests ran, but hits should increment

def test_reload_invalidates_cache(temp_retention_config):
    """Verify that reloading policies invalidates the cache."""
    # 1. Initial Config
    create_config(temp_retention_config, 10)
    load_retention_policies(force_reload=True)

    assert get_ttl_for_event("test.event") == 10
    # Call again to ensure it's in cache
    assert get_ttl_for_event("test.event") == 10

    # 2. Update Config
    create_config(temp_retention_config, 20)

    # 3. Reload
    reload_retention_policies()

    # 4. Verify new TTL is returned (cache was cleared)
    assert get_ttl_for_event("test.event") == 20

def test_force_reload_invalidates_cache(temp_retention_config):
    """Verify that load_retention_policies(force_reload=True) invalidates cache."""
    # 1. Initial Config
    create_config(temp_retention_config, 5)
    load_retention_policies(force_reload=True)
    assert get_ttl_for_event("test.event") == 5

    # 2. Update Config
    create_config(temp_retention_config, 99)

    # 3. Force Reload
    load_retention_policies(force_reload=True)

    # 4. Verify new TTL
    assert get_ttl_for_event("test.event") == 99
