import json
from pathlib import Path

def test_heimgeist_self_state_snapshot_schema_strictness():
    """
    Ensures that the local mirror of the Heimgeist Self-State Snapshot schema
    enforces strict validation (additionalProperties: false) to match the
    canonical metarepo contract.
    """
    schema_path = Path(__file__).parent.parent / "docs" / "heimgeist.self_state.snapshot.schema.json"
    assert schema_path.exists(), "Schema file missing"

    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # 1. Root object must not allow additional properties
    assert schema.get("additionalProperties") is False, \
        "Root schema must enforce additionalProperties: false to prevent drift"

    # 2. Data object must not allow additional properties
    # The 'data' field contains the actual Self-State payload
    data_schema = schema.get("properties", {}).get("data", {})
    assert data_schema.get("additionalProperties") is False, \
        "Data schema must enforce additionalProperties: false to prevent drift"

    # 3. Meta object is not strictly enforced in this test as root and data strictness
    # are the critical business logic requirements preventing payload drift.
