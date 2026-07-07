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
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        return [f"missing file {path}"]
    except yaml.YAMLError as exc:
        return [f"invalid YAML in {path}: {exc}"]

    if not isinstance(data, dict):
        return [f"{path} does not contain a YAML mapping"]

    def section(name: str) -> dict:
        value = data.get(name)
        return value if isinstance(value, dict) else {}

    for (sec, key), want in EXPECTED_VALUES.items():
        got = section(sec).get(key)
        if got != want:
            errors.append(f"{sec}.{key} must be {want!r}, got {got!r}")

    limits = section("role_contract").get("limits") or []
    missing = REQUIRED_LIMITS - set(limits)
    if missing:
        errors.append(
            f"role_contract.limits must include {sorted(REQUIRED_LIMITS)}, "
            f"missing {sorted(missing)}"
        )

    role = section("project").get("role")
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
