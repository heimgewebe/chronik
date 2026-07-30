"""Validation helpers for the Chronik/Heimlern outcome export contract.

Chronik owns the transport envelope. The embedded payload remains governed by
an exact, digest-pinned mirror of Heimlern's operator.routing_outcome.v1 schema.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent
ENVELOPE_SCHEMA_PATH = ROOT / "docs/chronik/operator-routing-outcome-export-v1.schema.json"
PAYLOAD_SCHEMA_PATH = ROOT / "docs/mirrors/heimlern/operator.routing_outcome.v1.schema.json"
PAYLOAD_PIN_PATH = ROOT / "docs/mirrors/heimlern/operator.routing_outcome.v1.pin.json"

_RAW_KEYS = {"raw_log", "raw_logs", "stdout", "stderr", "command_output", "log_excerpt"}
_PRIVATE_PATH_RE = re.compile(r"(?:^|[\s\"'])/(?:home|root|Users)/")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+",
    re.IGNORECASE,
)
_SECRET_PREFIXES = (
    "Bearer ",
    "gh" + "p_",
    "gh" + "o_",
    "sk" + "-",
    "AK" + "IA",
)
_PRIVATE_KEY_MARKER = "-----BEGIN " + "PRIVATE KEY-----"


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def event_id_for(export: dict[str, Any]) -> str:
    without_id = dict(export)
    without_id.pop("event_id", None)
    return "sha256:" + sha256_json(without_id)


def _parse_utc_second(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a UTC second timestamp") from exc
    return parsed


def _walk(value: Any, *, path: str = "$"):
    """Yield ``(path, key, item)`` for every dict entry and every list element.

    List elements carry no field name, so ``key`` is ``None`` for them. They are
    still yielded: free-form arrays such as ``payload.does_not_establish`` hold
    bare strings that must pass the same redaction boundary as object values.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            yield path, key, item
            yield from _walk(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            item_path = f"{path}[{index}]"
            yield item_path, None, item
            yield from _walk(item, path=item_path)


def _validate_redaction_boundary(export: dict[str, Any]) -> None:
    for path, key, value in _walk(export):
        if key is not None and key.lower() in _RAW_KEYS:
            raise ValueError(f"raw output field is forbidden at {path}.{key}")
        if not isinstance(value, str):
            continue
        location = f"{path}.{key}" if key is not None else path
        if _PRIVATE_PATH_RE.search(value):
            raise ValueError(f"private absolute path is forbidden at {location}")
        if (
            _PRIVATE_KEY_MARKER in value
            or any(prefix in value for prefix in _SECRET_PREFIXES)
            or _SECRET_ASSIGNMENT_RE.search(value)
        ):
            raise ValueError(f"secret-shaped material is forbidden at {location}")


def validate_operator_outcome_export(export: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(export, dict):
        raise ValueError("operator outcome export must be an object")

    envelope_schema = _load_json(ENVELOPE_SCHEMA_PATH)
    payload_schema = _load_json(PAYLOAD_SCHEMA_PATH)
    pin = _load_json(PAYLOAD_PIN_PATH)
    Draft202012Validator.check_schema(envelope_schema)
    Draft202012Validator.check_schema(payload_schema)
    Draft202012Validator(envelope_schema).validate(export)

    if pin.get("authority") != "mirror_only":
        raise ValueError("Heimlern payload pin must remain mirror_only")
    expected_non_claims = {
        "chronik_payload_contract_ownership",
        "automatic_mirror_refresh",
        "routing_authority",
    }
    if set(pin.get("does_not_establish", [])) != expected_non_claims:
        raise ValueError("Heimlern payload pin non-claims are incomplete")

    mirror_sha256 = hashlib.sha256(PAYLOAD_SCHEMA_PATH.read_bytes()).hexdigest()
    if mirror_sha256 != pin["sha256"]:
        raise ValueError("Heimlern payload mirror digest does not match its pin")

    expected_contract = {
        "owner": pin["owner"],
        "source_repository": pin["source_repository"],
        "source_revision": pin["source_revision"],
        "source_path": pin["source_path"],
        "sha256": pin["sha256"],
    }
    if export["payload_contract"] != expected_contract:
        raise ValueError("payload contract identity does not match the pinned Heimlern mirror")

    Draft202012Validator(payload_schema).validate(export["payload"])
    actual_payload_sha256 = sha256_json(export["payload"])
    if export["payload_sha256"] != actual_payload_sha256:
        raise ValueError("payload_sha256 does not match canonical payload bytes")
    if export["event_id"] != event_id_for(export):
        raise ValueError("event_id does not match the canonical export identity")

    observed_at = _parse_utc_second(export["freshness"]["observed_at"], label="freshness.observed_at")
    exported_at = _parse_utc_second(export["freshness"]["exported_at"], label="freshness.exported_at")
    event_ts = _parse_utc_second(export["ts"], label="ts")
    if exported_at < observed_at:
        raise ValueError("freshness.exported_at precedes observed_at")
    if event_ts != exported_at:
        raise ValueError("ts must equal freshness.exported_at")

    _validate_redaction_boundary(export)
    return {
        "valid": True,
        "event_id": export["event_id"],
        "payload_sha256": actual_payload_sha256,
        "payload_contract_sha256": mirror_sha256,
        "authority": "transport_only",
        "consumer_must_recompute_freshness": True,
    }
