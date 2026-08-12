import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "tools" / "validate_coding_memory_runtime_contract.py"
SPEC = importlib.util.spec_from_file_location("coding_memory_runtime_validator", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def test_coding_memory_runtime_contract_is_schema_valid_and_complete():
    contract = json.loads((ROOT / "tools" / "coding_memory.runtime.v1.json").read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "docs" / "chronik" / "coding-memory-runtime-v1.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(contract)

    result = validator.validate_root(ROOT)
    assert result["external_imports"] == [
        "filelock",
        "jsonschema",
        "pydantic",
        "pydantic_settings",
        "yaml",
    ]
    assert result["required_distributions"] == [
        "filelock",
        "jsonschema",
        "pydantic",
        "pydantic-settings",
        "pyyaml",
    ]


def _fixture_root(tmp_path: Path, *, surprise: bool = False) -> Path:
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "coding_memory.py").write_text("import worker\n", encoding="utf-8")
    worker = "import known_dep\n"
    if surprise:
        worker += "import surprise_dep\n"
    worker += "raise RuntimeError('must never execute during validation')\n"
    (tmp_path / "worker.py").write_text(worker, encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("known-dep>=1\n", encoding="utf-8")
    (tmp_path / "tools" / "coding_memory.runtime.v1.json").write_text(
        json.dumps(
            {
                "schema_version": "chronik-coding-memory-runtime.v1",
                "entrypoint": "tools/coding_memory.py",
                "requirements_source": "requirements.txt",
                "python": {"requires": ">=3.10"},
                "required_distributions": [
                    {
                        "distribution": "known-dep",
                        "specifier": ">=1",
                        "imports": ["known_dep"],
                    }
                ],
                "does_not_establish": ["runtime_success_without_consumer_validation"],
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def test_runtime_contract_validation_is_static_and_does_not_execute_local_modules(tmp_path):
    root = _fixture_root(tmp_path)
    result = validator.validate_root(root)
    assert result["external_imports"] == ["known_dep"]


def test_runtime_contract_detects_new_external_import_before_consumer_drift(tmp_path):
    root = _fixture_root(tmp_path, surprise=True)
    with pytest.raises(ValueError, match=r"missing=.*surprise_dep"):
        validator.validate_root(root)
