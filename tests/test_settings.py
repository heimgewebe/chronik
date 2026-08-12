from pathlib import Path

import pytest

from settings import DEFAULT_INTEGRITY_SOURCES_URL, Settings


RUNTIME_ENV_KEYS = (
    "CHRONIK_MAX_BODY",
    "CHRONIK_RATE_LIMIT",
    "CHRONIK_ENFORCE_PROVENANCE",
    "CHRONIK_ENABLE_QUALITY",
    "CHRONIK_LOG_LEVEL",
    "LOG_LEVEL",
    "CHRONIK_DEBUG",
    "CHRONIK_INTEGRITY_ENABLED",
    "CHRONIK_VERSION",
    "CHRONIK_TOKEN",
    "CHRONIK_DATA_DIR",
    "CHRONIK_LOCK_TIMEOUT",
    "CHRONIK_INTEGRITY_CONCURRENCY",
    "INTEGRITY_SOURCES_URL",
    "INTEGRITY_SOURCES_OVERRIDE",
    "INTEGRITY_FETCH_INTERVAL_SEC",
    "INTEGRITY_FUTURE_TOLERANCE_MIN",
)


@pytest.fixture(autouse=True)
def clean_settings_environment(monkeypatch):
    for key in RUNTIME_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_defaults_match_legacy_runtime_contract():
    settings = Settings()

    assert settings.max_payload_size == 1024 * 1024
    assert settings.rate_limit == "60/minute"
    assert settings.provenance_enforced is False
    assert settings.quality_enabled is True
    assert settings.log_level == "INFO"
    assert settings.debug_mode is False
    assert settings.integrity_enabled is True
    assert settings.version == "1.0.0"
    assert settings.token == ""
    assert settings.data_dir == Path("data").resolve()
    assert settings.lock_timeout == 30
    assert settings.integrity_concurrency_limit == 20
    assert settings.integrity_sources_url == DEFAULT_INTEGRITY_SOURCES_URL
    assert settings.integrity_sources_override is None
    assert settings.integrity_fetch_interval == 300
    assert settings.integrity_future_tolerance_min == 10


def test_empty_values_preserve_legacy_fallback_semantics(monkeypatch):
    monkeypatch.setenv("CHRONIK_MAX_BODY", "")
    monkeypatch.setenv("CHRONIK_RATE_LIMIT", "")
    monkeypatch.setenv("CHRONIK_LOG_LEVEL", "")
    monkeypatch.setenv("LOG_LEVEL", "")
    monkeypatch.setenv("CHRONIK_VERSION", "")
    monkeypatch.setenv("CHRONIK_LOCK_TIMEOUT", "")
    monkeypatch.setenv("CHRONIK_DATA_DIR", "")
    monkeypatch.setenv("INTEGRITY_SOURCES_URL", "")
    monkeypatch.setenv("INTEGRITY_SOURCES_OVERRIDE", "")

    settings = Settings()

    assert settings.max_payload_size == 1024 * 1024
    assert settings.rate_limit == "60/minute"
    assert settings.log_level == ""
    assert settings.version == "1.0.0"
    assert settings.lock_timeout == 30
    assert settings.data_dir == Path("").resolve()
    assert settings.integrity_sources_url == ""
    assert settings.integrity_sources_override == ""


def test_boolean_flags_keep_exact_existing_string_semantics(monkeypatch):
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "1")
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "0")
    monkeypatch.setenv("CHRONIK_INTEGRITY_ENABLED", "true")
    monkeypatch.setenv("CHRONIK_DEBUG", "YES")

    settings = Settings()

    assert settings.provenance_enforced is True
    assert settings.quality_enabled is False
    assert settings.integrity_enabled is False
    assert settings.debug_mode is True


def test_log_level_prefers_chronik_specific_value(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "warning")
    monkeypatch.setenv("CHRONIK_LOG_LEVEL", "debug")

    assert Settings().log_level == "DEBUG"


def test_integrity_concurrency_retains_invalid_value_fallback(monkeypatch):
    monkeypatch.setenv("CHRONIK_INTEGRITY_CONCURRENCY", "not-an-int")

    assert Settings().integrity_concurrency_limit == 20


def test_other_integer_settings_remain_fail_closed(monkeypatch):
    monkeypatch.setenv("CHRONIK_LOCK_TIMEOUT", "invalid")
    with pytest.raises(ValueError):
        _ = Settings().lock_timeout

    monkeypatch.delenv("CHRONIK_LOCK_TIMEOUT")
    monkeypatch.setenv("INTEGRITY_FETCH_INTERVAL_SEC", "")
    with pytest.raises(ValueError):
        _ = Settings().integrity_fetch_interval


def test_settings_instances_observe_environment_at_construction(monkeypatch):
    monkeypatch.setenv("CHRONIK_TOKEN", "first")
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "1")
    first = Settings()

    monkeypatch.setenv("CHRONIK_TOKEN", "second")
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "0")
    second = Settings()

    assert first.token == "first"
    assert first.quality_enabled is True
    assert second.token == "second"
    assert second.quality_enabled is False


def test_dynamic_accessors_observe_environment_without_model_rebuild(monkeypatch):
    monkeypatch.setenv("CHRONIK_TOKEN", "first")
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "0")
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "1")
    monkeypatch.setenv("CHRONIK_INTEGRITY_ENABLED", "1")

    assert Settings.current_token() == "first"
    assert Settings.provenance_enforced_now() is False
    assert Settings.quality_enabled_now() is True
    assert Settings.integrity_enabled_now() is True

    monkeypatch.setenv("CHRONIK_TOKEN", "second")
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "1")
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "0")
    monkeypatch.setenv("CHRONIK_INTEGRITY_ENABLED", "true")

    assert Settings.current_token() == "second"
    assert Settings.provenance_enforced_now() is True
    assert Settings.quality_enabled_now() is False
    assert Settings.integrity_enabled_now() is False
