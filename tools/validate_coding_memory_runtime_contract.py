#!/usr/bin/env python3
"""Validate Chronik's static coding-memory runtime contract without importing Chronik."""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = Path("tools/coding_memory.runtime.v1.json")
EXPECTED_SCHEMA_VERSION = "chronik-coding-memory-runtime.v1"


def _normalize_distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement_map(root: Path, source: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in (root / source).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[[^]]+\])?(.+)", line)
        if match is None:
            raise ValueError(f"unsupported requirement line: {raw!r}")
        values[_normalize_distribution(match.group(1))] = match.group(2).replace(" ", "")
    return values


def _local_module(root: Path, module: str) -> Path | None:
    parts = module.split(".")
    file_candidate = root.joinpath(*parts).with_suffix(".py")
    if file_candidate.is_file():
        return file_candidate
    package_candidate = root.joinpath(*parts, "__init__.py")
    if package_candidate.is_file():
        return package_candidate
    return None


def _import_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def external_import_closure(root: Path, entrypoint: str) -> set[str]:
    pending = [root / entrypoint]
    seen: set[Path] = set()
    external: set[str] = set()
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    while pending:
        path = pending.pop()
        resolved = path.resolve()
        if resolved in seen:
            continue
        if not path.is_file():
            raise ValueError(f"runtime entrypoint/module is missing: {path.relative_to(root)}")
        seen.add(resolved)
        for imported in _import_roots(path):
            local = _local_module(root, imported)
            if local is not None:
                pending.append(local)
            elif imported not in stdlib:
                external.add(imported)
    return external


def validate_root(root: Path) -> dict[str, object]:
    contract_path = root / CONTRACT_PATH
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    if contract.get("schema_version") != EXPECTED_SCHEMA_VERSION:
        raise ValueError("coding-memory runtime schema_version mismatch")
    entrypoint = contract.get("entrypoint")
    source = contract.get("requirements_source")
    if not isinstance(entrypoint, str) or not entrypoint:
        raise ValueError("coding-memory runtime entrypoint is invalid")
    if not isinstance(source, str) or not source:
        raise ValueError("coding-memory requirements_source is invalid")

    declared_imports: set[str] = set()
    declared_distributions: set[str] = set()
    requirements = _requirement_map(root, source)
    entries = contract.get("required_distributions")
    if not isinstance(entries, list) or not entries:
        raise ValueError("coding-memory required_distributions is empty")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("coding-memory distribution entry is invalid")
        distribution = entry.get("distribution")
        specifier = entry.get("specifier")
        imports = entry.get("imports")
        if not isinstance(distribution, str) or not isinstance(specifier, str):
            raise ValueError("coding-memory distribution/specifier is invalid")
        normalized = _normalize_distribution(distribution)
        if normalized in declared_distributions:
            raise ValueError(f"duplicate coding-memory distribution: {distribution}")
        declared_distributions.add(normalized)
        if requirements.get(normalized) != specifier.replace(" ", ""):
            raise ValueError(
                f"coding-memory requirement drift for {distribution}: "
                f"contract={specifier!r} requirements={requirements.get(normalized)!r}"
            )
        if not isinstance(imports, list) or not imports or not all(isinstance(item, str) and item for item in imports):
            raise ValueError(f"coding-memory import mapping is invalid for {distribution}")
        for imported in imports:
            if imported in declared_imports:
                raise ValueError(f"duplicate coding-memory import root: {imported}")
            declared_imports.add(imported)

    observed_imports = external_import_closure(root, entrypoint)
    missing = sorted(observed_imports - declared_imports)
    stale = sorted(declared_imports - observed_imports)
    if missing or stale:
        raise ValueError(
            "coding-memory import closure drift: "
            f"missing={missing or []} stale={stale or []}"
        )
    return {
        "schema_version": EXPECTED_SCHEMA_VERSION,
        "entrypoint": entrypoint,
        "external_imports": sorted(observed_imports),
        "required_distributions": sorted(declared_distributions),
    }


def main(argv: Iterable[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if args:
        raise SystemExit("usage: validate_coding_memory_runtime_contract.py")
    try:
        result = validate_root(ROOT)
    except (OSError, ValueError, json.JSONDecodeError, SyntaxError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
