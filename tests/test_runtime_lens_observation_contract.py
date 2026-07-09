import copy
import json
from pathlib import Path

import jsonschema
from jsonschema import Draft7Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs" / "chronik" / "runtime-lens-observation-v1.schema.json"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "runtime-lens" / "runtime-lens-observation.v1.json"


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def schema():
    loaded = load_json(SCHEMA_PATH)
    Draft7Validator.check_schema(loaded)
    return loaded


def assert_invalid(instance, loaded_schema):
    try:
        jsonschema.validate(instance, loaded_schema)
    except jsonschema.exceptions.ValidationError:
        return
    raise AssertionError("instance unexpectedly validated")


def test_runtime_lens_observation_schema_is_strict_and_bounded():
    loaded_schema = schema()
    assert loaded_schema["additionalProperties"] is False
    assert loaded_schema["properties"]["producer"]["additionalProperties"] is False
    assert loaded_schema["properties"]["subject"]["additionalProperties"] is False
    assert loaded_schema["properties"]["code_evidence"]["additionalProperties"] is False
    assert loaded_schema["properties"]["runtime_evidence"]["maxItems"] == 8
    assert loaded_schema["properties"]["code_evidence"]["properties"]["citations"]["maxItems"] == 8
    assert loaded_schema["properties"]["authority"]["properties"]["verdict_authority"]["const"] == "none"


def test_runtime_lens_fixture_validates():
    jsonschema.validate(load_json(FIXTURE_PATH), schema())


def test_runtime_lens_rejects_correctness_verdict_authority():
    loaded_schema = schema()
    event = load_json(FIXTURE_PATH)
    event["authority"]["verdict_authority"] = "runtime"
    assert_invalid(event, loaded_schema)


def test_runtime_lens_rejects_unprovenanced_runtime_evidence():
    loaded_schema = schema()
    event = load_json(FIXTURE_PATH)
    event["runtime_evidence"][0]["provenance"] = {}
    assert_invalid(event, loaded_schema)


def test_runtime_lens_rejects_action_smuggling_and_extra_fields():
    loaded_schema = schema()
    event = load_json(FIXTURE_PATH)
    event["boundary"]["repo_brief_forbidden_actions"].append("auto_fix")
    assert_invalid(event, loaded_schema)

    event = load_json(FIXTURE_PATH)
    event["runtime_evidence"][0]["raw_log"] = "not allowed"
    assert_invalid(event, loaded_schema)


def test_runtime_lens_observation_allows_drift_without_verdict():
    loaded_schema = schema()
    event = copy.deepcopy(load_json(FIXTURE_PATH))
    event["drift"] = {
        "status": "drift_observed",
        "basis": "commit_identity_mismatch",
        "summary": "Runtime identity differed from the cited snapshot; this is an observation only."
    }
    jsonschema.validate(event, loaded_schema)
    assert event["authority"]["verdict_authority"] == "none"
