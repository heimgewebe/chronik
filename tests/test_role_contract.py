"""Guard tests: the operator-ecosystem role contract must not silently drift.

Chronik is the append-only event ledger. ``scripts/check_role.py`` enforces
that ``.ai-context.yml`` keeps that role (no worker control / orchestration
authority). These tests ensure the guard passes on the real file and actually
catches a weakened contract.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
GUARD_PATH = ROOT / "scripts" / "check_role.py"
CONTEXT_PATH = ROOT / ".ai-context.yml"


def _load_guard():
    spec = importlib.util.spec_from_file_location("check_role", GUARD_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


guard = _load_guard()


def test_real_context_passes():
    assert guard.check(CONTEXT_PATH) == []


def test_missing_file_is_reported(tmp_path):
    errors = guard.check(tmp_path / "nope.yml")
    assert errors and "missing file" in errors[0]


def test_weakened_authority_is_detected(tmp_path):
    data = yaml.safe_load(CONTEXT_PATH.read_text(encoding="utf-8"))
    data["role_contract"]["authority"] = "orchestration_control"
    target = tmp_path / ".ai-context.yml"
    target.write_text(yaml.safe_dump(data), encoding="utf-8")
    errors = guard.check(target)
    assert any("role_contract.authority" in e for e in errors)


def test_dropped_limit_is_detected(tmp_path):
    data = yaml.safe_load(CONTEXT_PATH.read_text(encoding="utf-8"))
    data["role_contract"]["limits"] = ["no_worker_control"]  # drop orchestration limit
    target = tmp_path / ".ai-context.yml"
    target.write_text(yaml.safe_dump(data), encoding="utf-8")
    errors = guard.check(target)
    assert any("no_orchestration_decisions" in e for e in errors)


def test_stale_central_store_role_is_detected(tmp_path):
    data = yaml.safe_load(CONTEXT_PATH.read_text(encoding="utf-8"))
    data["project"]["role"] = "central_event_store"
    target = tmp_path / ".ai-context.yml"
    target.write_text(yaml.safe_dump(data), encoding="utf-8")
    errors = guard.check(target)
    assert any("central_event_store" in e for e in errors)


def test_reformatting_does_not_break_guard(tmp_path):
    # Semantic (YAML) check must tolerate harmless reformatting/whitespace.
    data = yaml.safe_load(CONTEXT_PATH.read_text(encoding="utf-8"))
    target = tmp_path / ".ai-context.yml"
    target.write_text(yaml.safe_dump(data, default_flow_style=False, indent=4), encoding="utf-8")
    assert guard.check(target) == []
