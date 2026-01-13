"""Validation logic for chronik payloads."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import jsonschema
from fastapi import HTTPException

logger = logging.getLogger(__name__)

# Global cache for the loaded validators
# Note: Caching is process-local. In a multi-worker environment (e.g. uvicorn workers),
# each worker will maintain its own cache.
_INSIGHTS_DAILY_VALIDATOR = None
_HEIMGEIST_SELF_STATE_SNAPSHOT_VALIDATOR = None


def prewarm_validators() -> None:
    """
    Load all validators into cache.
    Should be called at application startup to avoid latency on the first request.
    Raises exceptions if schemas are missing or invalid, ensuring fail-fast startup.
    """
    _get_insights_daily_validator()
    _get_heimgeist_self_state_snapshot_validator()
    logger.info("validators pre-warmed successfully")


def parse_iso_ts(value: str) -> datetime | None:
    """Parse ISO8601 timestamp (minimal support)."""
    # Minimal ISO parsing: supports trailing 'Z'
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def _has_ref_key(obj: Any) -> bool:
    """Recursively check for '$ref' keys in a dictionary or list."""
    if isinstance(obj, dict):
        if "$ref" in obj:
            return True
        return any(_has_ref_key(v) for v in obj.values())
    elif isinstance(obj, list):
        return any(_has_ref_key(v) for v in obj)
    return False


def _get_validator(schema_filename: str) -> jsonschema.Draft202012Validator:
    """
    Helper to load schema and create a validator.
    Assumes schemas are self-contained (no external $ref).
    """
    path = Path(__file__).parent / "docs" / schema_filename
    if not path.exists():
        logger.error(f"missing schema file: docs/{schema_filename}")
        raise HTTPException(
            status_code=500, detail="server configuration error: schema missing"
        )

    try:
        with open(path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        # Enforce self-contained assumption via precise recursive check
        if _has_ref_key(schema):
            raise ValueError(
                f"Schema {schema_filename} contains '$ref', which is not supported in this environment."
            )

        return jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )
    except Exception as exc:
        logger.error(f"failed to load schema {schema_filename}: {exc}")
        raise HTTPException(
            status_code=500, detail="server configuration error: schema invalid"
        )


def _get_insights_daily_validator() -> jsonschema.Draft202012Validator:
    global _INSIGHTS_DAILY_VALIDATOR
    if _INSIGHTS_DAILY_VALIDATOR is not None:
        return _INSIGHTS_DAILY_VALIDATOR

    _INSIGHTS_DAILY_VALIDATOR = _get_validator("insights.daily.schema.json")
    return _INSIGHTS_DAILY_VALIDATOR


def _get_heimgeist_self_state_snapshot_validator() -> jsonschema.Draft202012Validator:
    global _HEIMGEIST_SELF_STATE_SNAPSHOT_VALIDATOR
    if _HEIMGEIST_SELF_STATE_SNAPSHOT_VALIDATOR is not None:
        return _HEIMGEIST_SELF_STATE_SNAPSHOT_VALIDATOR

    _HEIMGEIST_SELF_STATE_SNAPSHOT_VALIDATOR = _get_validator(
        "heimgeist.self_state.snapshot.schema.json"
    )
    return _HEIMGEIST_SELF_STATE_SNAPSHOT_VALIDATOR


def validate_heimgeist_payload(item: dict) -> None:
    """
    Validate payload wrapper integrity.
    Mirror of metarepo/contracts/heimgeist.insight.v1.schema.json.
    """
    # Root fields
    required_root = {"kind", "version", "id", "meta", "data"}
    missing = required_root - item.keys()
    if missing:
        raise HTTPException(
            status_code=400, detail=f"missing fields: {', '.join(sorted(missing))}"
        )

    # Structure & Type strictness
    if not isinstance(item["kind"], str):
        raise HTTPException(status_code=400, detail="kind must be a string")

    valid_kinds = {"heimgeist.insight", "heimgeist.self_state.snapshot"}
    if item["kind"] not in valid_kinds:
        raise HTTPException(
            status_code=400,
            detail=f"invalid kind: expected one of: {', '.join(sorted(valid_kinds))}",
        )

    if not isinstance(item["version"], int):
        raise HTTPException(status_code=400, detail="version must be an integer")
    if item["version"] != 1:
        raise HTTPException(status_code=400, detail="invalid version: expected 1")

    if not isinstance(item["id"], str):
        raise HTTPException(status_code=400, detail="id must be a string")

    # Data field must be an object
    if not isinstance(item["data"], dict):
        raise HTTPException(status_code=400, detail="data must be a dict")

    # Specific validation for heimgeist.self_state.snapshot
    if item["kind"] == "heimgeist.self_state.snapshot":
        validator = _get_heimgeist_self_state_snapshot_validator()
        try:
            validator.validate(item)
        except jsonschema.ValidationError as exc:
            raise HTTPException(
                status_code=400, detail=f"schema validation failed: {exc.message}"
            )

    # Meta fields
    meta = item["meta"]
    if not isinstance(meta, dict):
        raise HTTPException(status_code=400, detail="meta must be a dict")

    if "occurred_at" not in meta:
        raise HTTPException(status_code=400, detail="missing meta.occurred_at")
    if not isinstance(meta["occurred_at"], str):
        raise HTTPException(status_code=400, detail="meta.occurred_at must be a string")
    if parse_iso_ts(meta["occurred_at"]) is None:
        raise HTTPException(
            status_code=400, detail="meta.occurred_at must be valid ISO8601"
        )


def normalize_heimgeist_item(item: dict) -> dict:
    """
    Normalize legacy payloads to the canonical wrapper.
    Legacy inputs: {id, source, timestamp, payload}
    Canonical wrapper: {kind, version, id, meta, data}
    """
    # 1. Check if it's already a valid Wrapper
    required_wrapper = {"kind", "version", "id", "meta", "data"}
    if required_wrapper.issubset(item.keys()):
        validate_heimgeist_payload(item)
        return item

    # 2. Legacy Adapter
    legacy_required = {"id", "source", "timestamp", "payload"}
    if legacy_required.issubset(item.keys()):
        legacy_payload = item["payload"]
        if not isinstance(legacy_payload, dict):
            raise HTTPException(status_code=400, detail="legacy payload must be a dict")

        # kind/version must be present in the nested payload
        if "kind" not in legacy_payload or "version" not in legacy_payload:
            raise HTTPException(
                status_code=400, detail="legacy payload missing kind/version"
            )

        kind = legacy_payload.get("kind")
        version = legacy_payload.get("version")

        # Prefer inner 'data', else treat stripped payload as data
        data = legacy_payload.get("data")
        if data is None:
            data = {
                k: v for k, v in legacy_payload.items() if k not in ("kind", "version")
            }

        new_item = {
            "kind": kind,
            "version": version,
            "id": item["id"],
            "meta": {
                "occurred_at": item["timestamp"],
                "producer": item["source"],
            },
            "data": data,
        }
        validate_heimgeist_payload(new_item)
        return new_item

    raise HTTPException(
        status_code=400,
        detail="invalid payload structure (neither wrapper nor valid legacy)",
    )


def validate_insights_daily_payload(item: dict) -> None:
    """
    Validate insights.daily payload against the JSON Schema.
    Uses Draft 2020-12 and FormatChecker.
    """
    validator = _get_insights_daily_validator()
    try:
        validator.validate(item)
    except jsonschema.ValidationError as exc:
        # Provide a helpful error message
        raise HTTPException(
            status_code=400, detail=f"schema validation failed: {exc.message}"
        )
