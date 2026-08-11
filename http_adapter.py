"""Permissive Pydantic adapter for Chronik's HTTP ingest boundary.

The adapter validates only transport shape: an ingest item must be a JSON object.
It deliberately defines no canonical event fields or semantic constraints. Those
remain owned by the JSON-Schema/domain validation path in ``ingest_validation``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError


class HttpPayloadShapeError(ValueError):
    """Raised when a decoded HTTP payload is not an object or object batch."""


class IngestHttpItem(BaseModel):
    """Lossless, permissive HTTP object adapter.

    No event fields are declared here on purpose. Pydantic provides the HTTP
    object boundary and generated OpenAPI shape; canonical contracts validate
    the contents later in the ingest pipeline.
    """

    model_config = ConfigDict(extra="allow")


def adapt_ingest_http_items(value: Any) -> list[dict[str, Any]]:
    """Adapt one decoded JSON object or a batch without semantic validation."""
    raw_items = value if isinstance(value, list) else [value]
    adapted: list[dict[str, Any]] = []

    for raw in raw_items:
        try:
            item = IngestHttpItem.model_validate(raw)
        except ValidationError as exc:
            raise HttpPayloadShapeError("invalid payload") from exc
        adapted.append(item.model_dump(mode="python"))

    return adapted


def ingest_request_body_openapi(*, include_ndjson: bool) -> dict[str, Any]:
    """Return request-body metadata generated from the permissive Pydantic model."""
    item_schema = IngestHttpItem.model_json_schema()
    content: dict[str, Any] = {
        "application/json": {
            "schema": {
                "oneOf": [
                    item_schema,
                    {"type": "array", "items": item_schema},
                ]
            }
        }
    }
    if include_ndjson:
        content["application/x-ndjson"] = {
            "schema": {
                "type": "string",
                "description": (
                    "One JSON object per line. Pydantic validates only the HTTP "
                    "object shape; canonical Chronik contracts validate contents."
                ),
            }
        }

    return {"requestBody": {"required": True, "content": content}}
