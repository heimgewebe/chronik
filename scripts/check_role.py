#!/usr/bin/env python3
"""Guard: enforce chronik's operator-ecosystem role contract.

Chronik is the append-only event ledger / historical-evidence axis of the
Heimgewebe operator ecosystem. It records events, it does not own tasks, drive
workers or make orchestration decisions ("the ledger is not the lever").

The role contract that encodes this lives in ``.ai-context.yml``. This guard
fails (exit 1) if that contract silently drifts toward orchestration/worker
authority, so CI and local validation catch the regression instead of humans.

Parses the YAML semantically, so harmless reformatting/whitespace changes do
not cause false failures — only a weakened contract does.

Usage: ``python scripts/check_role.py [path-to-.ai-context.yml]``
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path

import yaml

# (section, key) -> exact value the contract must keep.
EXPECTED_VALUES: dict[tuple[str, str], str] = {
    ("project", "role"): "append_only_event_ledger",
    ("role_contract", "name"): "append_only_event_ledger",
    ("role_contract", "authority"): "historical_evidence",
    ("role_contract", "unavailable_effect"): "new_event_capture_degrades",
}

# Limits that must stay declared: chronik never controls workers or orchestrates.
REQUIRED_LIMITS = {"no_worker_control", "no_orchestration_decisions"}

# Roles that would misframe chronik as an active/central authority.
FORBIDDEN_ROLES = {"central_event_store"}


def check(path: Path) -> list[str]:
    """Return a list of contract violations (empty means the contract holds)."""
    errors: list[str] = []
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [f"missing file {path}"]
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        return [f"invalid YAML in {path}: {exc}"]
    # Only an empty document normalizes to an empty mapping; falsy scalars
    # (false, 0, "") must still be reported as "not a mapping".
    if data is None:
        data = {}

    if not isinstance(data, Mapping):
        return [f"{path} does not contain a YAML mapping"]

    # Both sections must be mappings; report explicitly instead of masking
    # a broken shape as an empty section.
    project = data.get("project")
    role_contract = data.get("role_contract")
    if not isinstance(project, Mapping):
        errors.append("project must be a YAML mapping")
        project = {}
    if not isinstance(role_contract, Mapping):
        errors.append("role_contract must be a YAML mapping")
        role_contract = {}
    sections = {"project": project, "role_contract": role_contract}

    for (sec, key), want in EXPECTED_VALUES.items():
        got = sections[sec].get(key)
        if got != want:
            errors.append(f"{sec}.{key} must be {want!r}, got {got!r}")

    limits = role_contract.get("limits")
    if not isinstance(limits, list) or not all(isinstance(item, str) for item in limits):
        errors.append("role_contract.limits must be a list of strings")
    else:
        missing = REQUIRED_LIMITS - set(limits)
        if missing:
            errors.append(
                f"role_contract.limits must include {sorted(REQUIRED_LIMITS)}, "
                f"missing {sorted(missing)}"
            )

    role = project.get("role")
    if role in FORBIDDEN_ROLES:
        errors.append(f"stale/forbidden project.role {role!r}")

    return errors


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else Path(".ai-context.yml")
    errors = check(path)
    if errors:
        for err in errors:
            print(f"role-contract: {err}", file=sys.stderr)
        return 1
    print("role-contract: OK chronik")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
