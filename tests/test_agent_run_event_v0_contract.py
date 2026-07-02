import copy
import json
from pathlib import Path

import jsonschema
from jsonschema import Draft7Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs" / "chronik" / "agent-run-event-v0.schema.json"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "agent-ledger"


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


def test_agent_run_event_v0_schema_is_strict():
    loaded_schema = schema()
    assert loaded_schema["additionalProperties"] is False
    assert loaded_schema["properties"]["source"]["additionalProperties"] is False
    assert loaded_schema["properties"]["subject"]["additionalProperties"] is False
    assert loaded_schema["properties"]["data"]["additionalProperties"] is False
    assert loaded_schema["properties"]["caused_by"]["maxItems"] == 3
    assert loaded_schema["properties"]["evidence_refs"]["maxItems"] == 5


def test_agent_run_event_v0_fixtures_validate():
    loaded_schema = schema()
    fixtures = sorted(FIXTURE_DIR.glob("agent-run-*.v0.json"))
    assert fixtures
    for fixture in fixtures:
        jsonschema.validate(load_json(fixture), loaded_schema)


def test_agent_run_event_v0_rejects_extra_data_fields():
    loaded_schema = schema()
    event = load_json(FIXTURE_DIR / "agent-run-completed.v0.json")
    event["data"]["raw"] = "no"
    assert_invalid(event, loaded_schema)


def test_agent_run_event_v0_rejects_excessive_causality():
    loaded_schema = schema()
    event = load_json(FIXTURE_DIR / "agent-run-completed.v0.json")
    event["caused_by"] = [
        "01JZ0000000000000000000000",
        "01JZ0000000000000000000001",
        "01JZ0000000000000000000002",
        "01JZ0000000000000000000003",
    ]
    assert_invalid(event, loaded_schema)


def test_agent_run_event_v0_requires_corrects_for_corrected_status():
    loaded_schema = schema()
    event = copy.deepcopy(load_json(FIXTURE_DIR / "agent-run-completed.v0.json"))
    event["status"] = "corrected"
    assert_invalid(event, loaded_schema)
    event["corrects"] = ["01JZ0000000000000000000000"]
    jsonschema.validate(event, loaded_schema)
