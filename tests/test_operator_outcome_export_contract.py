import copy
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

import operator_outcome_export as contract
from provenance import validate_provenance

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/operator-outcome/operator-routing-outcome-export.v1.json"


def load_fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_fixture_validates_and_satisfies_chronik_provenance():
    export = load_fixture()
    receipt = contract.validate_operator_outcome_export(export)
    validate_provenance(export, strict=True)
    assert receipt["valid"] is True
    assert receipt["authority"] == "transport_only"


def test_payload_mirror_is_exactly_digest_pinned():
    pin = json.loads(contract.PAYLOAD_PIN_PATH.read_text(encoding="utf-8"))
    assert hashlib.sha256(contract.PAYLOAD_SCHEMA_PATH.read_bytes()).hexdigest() == pin["sha256"]
    assert pin["authority"] == "mirror_only"


def test_payload_digest_mismatch_is_rejected():
    export = load_fixture()
    export["payload"]["reward"] = 0.7
    with pytest.raises(ValueError, match="payload_sha256"):
        contract.validate_operator_outcome_export(export)


def test_event_identity_mismatch_is_rejected():
    export = load_fixture()
    export["event_id"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="event_id"):
        contract.validate_operator_outcome_export(export)


def test_unpinned_payload_contract_is_rejected():
    export = load_fixture()
    export["payload_contract"]["source_revision"] = "0" * 40
    export["event_id"] = contract.event_id_for(export)
    with pytest.raises(ValueError, match="pinned Heimlern mirror"):
        contract.validate_operator_outcome_export(export)


def test_raw_output_field_is_rejected_by_owner_payload_schema():
    export = load_fixture()
    export["payload"]["raw_log"] = "build output"
    export["payload_sha256"] = contract.sha256_json(export["payload"])
    export["event_id"] = contract.event_id_for(export)
    with pytest.raises(jsonschema.ValidationError):
        contract.validate_operator_outcome_export(export)


def test_secret_shaped_text_and_private_paths_are_rejected():
    for fallback in ("Authorization: Bearer secret-value", "/home/alex/private/receipt.json"):
        export = load_fixture()
        export["payload"]["friction"] = [{
            "kind": "unknown",
            "surface": "runtime",
            "resolved": False,
            "fallback": fallback,
        }]
        export["payload"]["metrics"]["friction_count"] = 1
        export["payload_sha256"] = contract.sha256_json(export["payload"])
        export["event_id"] = contract.event_id_for(export)
        with pytest.raises(ValueError, match="forbidden"):
            contract.validate_operator_outcome_export(export)


def test_secret_shaped_text_in_free_form_arrays_is_rejected():
    for leaked in ("Authorization: Bearer secret-value", "/home/alex/private/receipt.json"):
        export = load_fixture()
        export["payload"]["does_not_establish"] = ["causal_route_superiority", leaked]
        export["payload_sha256"] = contract.sha256_json(export["payload"])
        export["event_id"] = contract.event_id_for(export)
        with pytest.raises(ValueError, match="forbidden"):
            contract.validate_operator_outcome_export(export)


def test_redaction_walk_reaches_bare_strings_inside_arrays():
    located = {path: value for path, key, value in contract._walk({"a": ["first", "second"]})}
    assert located["$.a[0]"] == "first"
    assert located["$.a[1]"] == "second"


def test_redaction_walk_still_flags_raw_keys_nested_in_arrays():
    export = load_fixture()
    export["payload"]["friction"] = [{
        "kind": "unknown",
        "surface": "runtime",
        "resolved": False,
        "stdout": "build output",
    }]
    with pytest.raises(ValueError, match="raw output field is forbidden"):
        contract._validate_redaction_boundary(export)


def test_future_inverted_freshness_is_rejected_and_status_is_not_persisted():
    export = load_fixture()
    assert "status" not in export["freshness"]
    export["freshness"]["observed_at"] = "2026-07-10T22:42:00Z"
    export["event_id"] = contract.event_id_for(export)
    with pytest.raises(ValueError, match="precedes"):
        contract.validate_operator_outcome_export(export)


def test_transport_boundary_cannot_be_upgraded_to_routing_authority():
    export = copy.deepcopy(load_fixture())
    export["boundary"]["routing_authority"] = "chronik"
    export["event_id"] = contract.event_id_for(export)
    with pytest.raises(jsonschema.ValidationError):
        contract.validate_operator_outcome_export(export)


def test_pin_authority_and_non_claims_are_fail_closed(monkeypatch, tmp_path):
    pin = json.loads(contract.PAYLOAD_PIN_PATH.read_text(encoding="utf-8"))
    pin["authority"] = "canonical"
    bad_pin = tmp_path / "pin.json"
    bad_pin.write_text(json.dumps(pin), encoding="utf-8")
    monkeypatch.setattr(contract, "PAYLOAD_PIN_PATH", bad_pin)
    with pytest.raises(ValueError, match="mirror_only"):
        contract.validate_operator_outcome_export(load_fixture())


def test_cli_emits_machine_readable_validation_receipt():
    import subprocess

    completed = subprocess.run(
        [str(ROOT / "scripts/validate_operator_outcome_export.py"), str(FIXTURE)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    receipt = json.loads(completed.stdout)
    assert receipt["valid"] is True
    assert receipt["authority"] == "transport_only"
