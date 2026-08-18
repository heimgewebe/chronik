from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from canonical_ingest import build_envelope
from ingest_validation import validate_and_normalize_item
from weltgewebe_history import (
    WELTGEWEBE_HISTORY_DOMAIN,
    WELTGEWEBE_HISTORY_KINDS,
    WeltgewebeHistoryError,
    project_weltgewebe_lifecycle,
    validate_weltgewebe_history_event,
)


def _event(
    *,
    kind: str = "domain_event",
    event_id: str = "wg-event-1",
    lifecycle_state: str = "active",
    target_event_id: str | None = None,
) -> dict:
    return {
        "schema_version": "weltgewebe.history.v1",
        "domain": WELTGEWEBE_HISTORY_DOMAIN,
        "event_id": event_id,
        "kind": kind,
        "ts": "2026-08-18T10:00:00Z",
        "source": {
            "origin": "weltgewebe",
            "repo": "heimgewebe/weltgewebe",
            "component": "api",
            "version": "weltgewebe.event.v1",
            "revision": "a" * 40,
        },
        "correlation_id": "correlation-1",
        "source_evidence": [
            {
                "authority": "weltgewebe",
                "reference": "outbox:42",
                "sha256": "b" * 64,
            }
        ],
        "privacy": {
            "classification": "public",
            "contains_personal_data": False,
        },
        "lifecycle": {
            "state": lifecycle_state,
            "target_event_id": target_event_id,
            "authority_reference": "policy:weltgewebe-history-v1",
        },
        "authority": {
            "primary_truth": "weltgewebe",
            "chronik_role": "historical_projection",
            "writeback_allowed": False,
        },
        "payload": {"node_id": "node-1"},
    }


def test_schema_is_valid_draft_2020_12() -> None:
    path = (
        Path(__file__).parents[1]
        / "docs"
        / "chronik"
        / "weltgewebe-history-event-v1.schema.json"
    )
    schema = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("kind", sorted(WELTGEWEBE_HISTORY_KINDS))
def test_all_four_typed_event_classes_are_accepted(kind: str) -> None:
    validate_weltgewebe_history_event(_event(kind=kind))


def test_unknown_event_class_is_rejected() -> None:
    with pytest.raises(WeltgewebeHistoryError, match="kind"):
        validate_weltgewebe_history_event(_event(kind="generic_event"))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda event: event["source"].pop("version"),
        lambda event: event.pop("correlation_id"),
        lambda event: event.update(source_evidence=[]),
        lambda event: event["source"].pop("origin"),
    ],
)
def test_provenance_contract_requires_origin_version_correlation_and_evidence(
    mutation,
) -> None:
    event = _event()
    mutation(event)
    with pytest.raises(WeltgewebeHistoryError):
        validate_weltgewebe_history_event(event)


def test_source_evidence_requires_hash_bound_reference() -> None:
    event = _event()
    event["source_evidence"][0]["sha256"] = "not-a-digest"
    with pytest.raises(WeltgewebeHistoryError, match="sha256"):
        validate_weltgewebe_history_event(event)


def test_writeback_authority_is_structurally_forbidden() -> None:
    event = _event()
    event["authority"]["writeback_allowed"] = True
    with pytest.raises(WeltgewebeHistoryError, match="writeback_allowed"):
        validate_weltgewebe_history_event(event)


@pytest.mark.parametrize("state", ["redacted", "revoked", "deleted"])
def test_lifecycle_changes_require_an_explicit_target(state: str) -> None:
    with pytest.raises(WeltgewebeHistoryError, match="target_event_id"):
        validate_weltgewebe_history_event(
            _event(event_id=f"wg-{state}-1", lifecycle_state=state)
        )


def test_active_event_cannot_target_another_event() -> None:
    with pytest.raises(WeltgewebeHistoryError, match="target_event_id"):
        validate_weltgewebe_history_event(_event(target_event_id="wg-old"))


def test_lifecycle_projection_is_append_only_and_does_not_mutate_source_events() -> None:
    active = _event()
    revoked = _event(
        event_id="wg-revocation-1",
        lifecycle_state="revoked",
        target_event_id="wg-event-1",
    )
    source = [active, revoked]
    before = copy.deepcopy(source)

    projected = project_weltgewebe_lifecycle(source)

    assert source == before
    assert projected["wg-event-1"] == {
        "state": "revoked",
        "evidence_event_id": "wg-revocation-1",
        "authority_reference": "policy:weltgewebe-history-v1",
        "correlation_id": "correlation-1",
    }


def test_http_ingest_validation_enforces_the_weltgewebe_contract() -> None:
    event = _event(kind="federation_delivery")
    normalized = validate_and_normalize_item(
        event,
        WELTGEWEBE_HISTORY_DOMAIN,
        provenance_enforced=True,
    )
    assert normalized == event

    invalid = _event()
    invalid.pop("correlation_id")
    with pytest.raises(HTTPException) as exc:
        validate_and_normalize_item(
            invalid,
            WELTGEWEBE_HISTORY_DOMAIN,
            provenance_enforced=True,
        )
    assert exc.value.status_code == 400
    assert "weltgewebe history validation failed" in str(exc.value.detail)


def test_chronik_retention_envelope_remains_authoritative_for_weltgewebe_history() -> None:
    event = _event(kind="operator_receipt")
    envelope = build_envelope(
        WELTGEWEBE_HISTORY_DOMAIN,
        event,
        received_at=datetime(2026, 8, 18, 10, 0, tzinfo=timezone.utc),
    )

    assert envelope["payload"] == event
    assert envelope["retention"]["ttl_days"] >= 0
    assert "expires_at" in envelope["retention"]
    assert envelope["payload"]["privacy"]["classification"] == "public"


@pytest.mark.parametrize(
    "primary_truth",
    ["chronik", "chronik.runtime", "heimgewebe/chronik", "heimgewebe/chronik/runtime"],
)
def test_chronik_cannot_be_primary_truth(primary_truth: str) -> None:
    event = _event()
    event["authority"]["primary_truth"] = primary_truth
    with pytest.raises(WeltgewebeHistoryError, match="primary_truth"):
        validate_weltgewebe_history_event(event)


def test_http_round_trip_persists_only_the_historical_projection(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("CHRONIK_TOKEN", "weltgewebe-test-token")
    monkeypatch.setenv("CHRONIK_ENABLE_QUALITY", "1")
    monkeypatch.setenv("CHRONIK_ENFORCE_PROVENANCE", "1")
    monkeypatch.setenv("CHRONIK_DATA_DIR", str(tmp_path))

    import storage

    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    from app import app

    client = TestClient(app)
    headers = {"X-Auth": "weltgewebe-test-token"}
    event = _event(kind="deployment")

    response = client.post(
        "/v1/ingest?domain=weltgewebe.history",
        json=event,
        headers=headers,
    )
    assert response.status_code == 202, response.text
    assert response.json()["result"] == "accepted"

    replay = client.post(
        "/v1/ingest?domain=weltgewebe.history",
        json=event,
        headers=headers,
    )
    assert replay.status_code == 202, replay.text
    assert replay.json() == {
        "domain": "weltgewebe.history",
        "result": "replayed",
        "requested": 1,
        "written": 0,
        "skipped_existing": 1,
    }

    conflicting = copy.deepcopy(event)
    conflicting["payload"]["node_id"] = "node-2"
    conflict = client.post(
        "/v1/ingest?domain=weltgewebe.history",
        json=conflicting,
        headers=headers,
    )
    assert conflict.status_code == 409, conflict.text

    readback = client.get(
        "/v1/events?domain=weltgewebe.history&limit=10",
        headers=headers,
    )
    assert readback.status_code == 200, readback.text
    body = readback.json()
    assert body["meta"]["count"] == 1
    assert body["events"][0]["payload"] == event
    assert body["events"][0]["retention"]["ttl_days"] >= 0

    invalid = _event(event_id="wg-writeback-attempt")
    invalid["authority"]["writeback_allowed"] = True
    rejected = client.post(
        "/v1/ingest?domain=weltgewebe.history",
        json=invalid,
        headers=headers,
    )
    assert rejected.status_code == 400
