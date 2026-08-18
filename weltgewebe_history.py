"""Weltgewebe history projection contract for Chronik.

This module validates a narrow append-only historical projection. It contains no
writeback, orchestration, deployment or primary-truth mutation path.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

import jsonschema

WELTGEWEBE_HISTORY_DOMAIN = "weltgewebe.history"
WELTGEWEBE_HISTORY_SCHEMA_VERSION = "weltgewebe.history.v1"
WELTGEWEBE_HISTORY_KINDS = frozenset(
    {"domain_event", "deployment", "federation_delivery", "operator_receipt"}
)
_SCHEMA_PATH = (
    Path(__file__).parent / "docs" / "chronik" / "weltgewebe-history-event-v1.schema.json"
)


class WeltgewebeHistoryError(ValueError):
    """Raised when a Weltgewebe history projection violates its contract."""


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )


def validate_weltgewebe_history_event(payload: dict[str, Any]) -> None:
    """Validate one projection event without changing caller-owned data."""
    if not isinstance(payload, dict):
        raise WeltgewebeHistoryError("payload must be an object")
    errors = sorted(
        _validator().iter_errors(payload),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if not errors:
        return
    error = errors[0]
    location = ".".join(str(part) for part in error.absolute_path) or "$"
    raise WeltgewebeHistoryError(f"{location}: {error.message}")


def project_weltgewebe_lifecycle(
    events: Iterable[dict[str, Any]],
) -> dict[str, dict[str, str]]:
    """Derive effective lifecycle state from append-only events, read-only.

    An ``active`` event establishes itself. Redaction, revocation and deletion
    events target an earlier event id. The source events are never rewritten or
    deleted by this projection.
    """
    projection: dict[str, dict[str, str]] = {}
    for event in events:
        validate_weltgewebe_history_event(event)
        lifecycle = event["lifecycle"]
        state = str(lifecycle["state"])
        target = (
            str(event["event_id"])
            if state == "active"
            else str(lifecycle["target_event_id"])
        )
        projection[target] = {
            "state": state,
            "evidence_event_id": str(event["event_id"]),
            "authority_reference": str(lifecycle["authority_reference"]),
            "correlation_id": str(event["correlation_id"]),
        }
    return projection
