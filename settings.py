"""Typed environment settings for the Chronik runtime.

Environment variable names and legacy default/empty-value semantics are kept
stable here. Pydantic-backed instances model process-start and manager configuration.
Settings that were historically re-read for every request use lightweight class
methods so runtime toggles remain observable without model-construction overhead.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_INTEGRITY_SOURCES_URL = (
    "https://github.com/heimgewebe/metarepo/releases/download/integrity/"
    "sources.v1.json"
)


class Settings(BaseSettings):
    """Chronik environment configuration with legacy-compatible semantics."""

    model_config = SettingsConfigDict(
        case_sensitive=True,
        extra="ignore",
        env_file=None,
        env_ignore_empty=False,
        frozen=True,
    )

    max_body_raw: str | None = Field(default=None, validation_alias="CHRONIK_MAX_BODY")
    rate_limit_raw: str | None = Field(
        default=None, validation_alias="CHRONIK_RATE_LIMIT"
    )
    provenance_raw: str | None = Field(
        default=None, validation_alias="CHRONIK_ENFORCE_PROVENANCE"
    )
    quality_raw: str | None = Field(
        default=None, validation_alias="CHRONIK_ENABLE_QUALITY"
    )
    chronik_log_level_raw: str | None = Field(
        default=None, validation_alias="CHRONIK_LOG_LEVEL"
    )
    fallback_log_level_raw: str | None = Field(
        default=None, validation_alias="LOG_LEVEL"
    )
    debug_raw: str | None = Field(default=None, validation_alias="CHRONIK_DEBUG")
    integrity_enabled_raw: str | None = Field(
        default=None, validation_alias="CHRONIK_INTEGRITY_ENABLED"
    )
    version_raw: str | None = Field(default=None, validation_alias="CHRONIK_VERSION")
    token_raw: str | None = Field(default=None, validation_alias="CHRONIK_TOKEN")
    data_dir_raw: str | None = Field(default=None, validation_alias="CHRONIK_DATA_DIR")
    lock_timeout_raw: str | None = Field(
        default=None, validation_alias="CHRONIK_LOCK_TIMEOUT"
    )
    integrity_concurrency_raw: str | None = Field(
        default=None, validation_alias="CHRONIK_INTEGRITY_CONCURRENCY"
    )
    integrity_sources_url_raw: str | None = Field(
        default=None, validation_alias="INTEGRITY_SOURCES_URL"
    )
    integrity_sources_override_raw: str | None = Field(
        default=None, validation_alias="INTEGRITY_SOURCES_OVERRIDE"
    )
    integrity_fetch_interval_raw: str | None = Field(
        default=None, validation_alias="INTEGRITY_FETCH_INTERVAL_SEC"
    )
    integrity_future_tolerance_raw: str | None = Field(
        default=None, validation_alias="INTEGRITY_FUTURE_TOLERANCE_MIN"
    )

    @staticmethod
    def _exact_one(raw: str | None, *, default: str) -> bool:
        return (default if raw is None else raw) == "1"

    @classmethod
    def current_token(cls) -> str:
        """Read the dynamic auth token value without constructing a settings model."""
        return os.environ.get("CHRONIK_TOKEN", "")

    @classmethod
    def provenance_enforced_now(cls) -> bool:
        """Read the dynamic provenance switch using its exact legacy semantics."""
        return cls._exact_one(os.environ.get("CHRONIK_ENFORCE_PROVENANCE"), default="0")

    @classmethod
    def quality_enabled_now(cls) -> bool:
        """Read the dynamic quality switch using its exact legacy semantics."""
        return cls._exact_one(os.environ.get("CHRONIK_ENABLE_QUALITY"), default="1")

    @classmethod
    def integrity_enabled_now(cls) -> bool:
        """Read the integrity-loop switch at lifespan start without model overhead."""
        return cls._exact_one(os.environ.get("CHRONIK_INTEGRITY_ENABLED"), default="1")

    @property
    def max_payload_size(self) -> int:
        return int(self.max_body_raw or str(1024 * 1024))

    @property
    def rate_limit(self) -> str:
        return self.rate_limit_raw or "60/minute"

    @property
    def provenance_enforced(self) -> bool:
        return self._exact_one(self.provenance_raw, default="0")

    @property
    def quality_enabled(self) -> bool:
        return self._exact_one(self.quality_raw, default="1")

    @property
    def log_level(self) -> str:
        if self.chronik_log_level_raw:
            return self.chronik_log_level_raw.upper()
        if self.fallback_log_level_raw is None:
            return "INFO"
        return self.fallback_log_level_raw.upper()

    @property
    def debug_mode(self) -> bool:
        return (self.debug_raw or "").lower() in {"1", "true", "yes", "on"}

    @property
    def integrity_enabled(self) -> bool:
        return self._exact_one(self.integrity_enabled_raw, default="1")

    @property
    def version(self) -> str:
        return self.version_raw or "1.0.0"

    @property
    def token(self) -> str:
        return "" if self.token_raw is None else self.token_raw

    @property
    def data_dir(self) -> Path:
        raw = "data" if self.data_dir_raw is None else self.data_dir_raw
        return Path(raw).resolve()

    @property
    def lock_timeout(self) -> int:
        return int(self.lock_timeout_raw or "30")

    @property
    def integrity_concurrency_limit(self) -> int:
        raw = "20" if self.integrity_concurrency_raw is None else self.integrity_concurrency_raw
        try:
            return int(raw)
        except ValueError:
            return 20

    @property
    def integrity_sources_url(self) -> str:
        if self.integrity_sources_url_raw is None:
            return DEFAULT_INTEGRITY_SOURCES_URL
        return self.integrity_sources_url_raw

    @property
    def integrity_sources_override(self) -> str | None:
        return self.integrity_sources_override_raw

    @property
    def integrity_fetch_interval(self) -> int:
        raw = "300" if self.integrity_fetch_interval_raw is None else self.integrity_fetch_interval_raw
        return int(raw)

    @property
    def integrity_future_tolerance_min(self) -> int:
        raw = "10" if self.integrity_future_tolerance_raw is None else self.integrity_future_tolerance_raw
        return int(raw)
