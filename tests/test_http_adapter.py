from __future__ import annotations

import pytest
from fastapi import HTTPException

import app
from http_adapter import HttpPayloadShapeError, adapt_ingest_http_items


def test_adapter_preserves_arbitrary_json_object_fields() -> None:
    payload = {
        "custom": "value",
        "nested": {"items": [1, True, None, {"x": 2.5}]},
        "unmodeled": 17,
    }

    assert adapt_ingest_http_items(payload) == [payload]


def test_adapter_accepts_empty_batch_and_rejects_scalar_items() -> None:
    assert adapt_ingest_http_items([]) == []

    with pytest.raises(HttpPayloadShapeError):
        adapt_ingest_http_items([{"ok": True}, "not-an-object"])


def test_canonical_validation_still_runs_after_http_adapter() -> None:
    items = app._adapt_http_items({"summary": "x" * 501})

    with pytest.raises(HTTPException) as exc_info:
        app._process_items(items, "example.com")

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail == "summary too long (max 500)"


def test_openapi_uses_permissive_pydantic_shape_for_ingest() -> None:
    operation = app.app.openapi()["paths"]["/v1/ingest"]["post"]
    content = operation["requestBody"]["content"]
    schema = content["application/json"]["schema"]

    assert "application/x-ndjson" in content
    assert len(schema["oneOf"]) == 2
    object_schema = schema["oneOf"][0]
    assert object_schema["type"] == "object"
    assert object_schema["additionalProperties"] is True
    assert object_schema.get("required", []) == []
    assert schema["oneOf"][1]["type"] == "array"
