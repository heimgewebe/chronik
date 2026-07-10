from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("operator_event_policy", ROOT / "scripts/validate_operator_event_policy.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
VALID = ROOT / "tests/fixtures/operator-events/operator.failure.valid.json"


def test_policy_is_bounded_and_valid() -> None:
    policy = MODULE.validate_policy()
    assert len(policy["allowed"]) == 5
    assert "git.diff" in policy["forbidden"]
    assert policy["boundary"]["no_command_authority"] is True


def test_valid_event_and_real_query_consumer(tmp_path: Path) -> None:
    event = MODULE.validate_event(VALID)
    journal = tmp_path / "operator.jsonl"
    journal.write_text(json.dumps(event) + "\n", encoding="utf-8")
    matches = MODULE.query_events(journal, event_type="operator.failure")
    assert [item["event_id"] for item in matches] == [event["event_id"]]


def test_raw_log_key_fails_closed(tmp_path: Path) -> None:
    payload = json.loads(VALID.read_text())
    payload["stderr"] = "secret-ish raw output"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(Exception):
        MODULE.validate_event(path)


def test_forbidden_event_type_fails_closed(tmp_path: Path) -> None:
    payload = json.loads(VALID.read_text())
    payload["event_type"] = "git.commit"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(Exception):
        MODULE.validate_event(path)
