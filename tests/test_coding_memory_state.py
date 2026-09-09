import pytest

import coding_memory_state as state


def source_record():
    return {
        "source_path": "/tmp/source.jsonl",
        "source_sha256": "a" * 64,
        "source_bytes": 10,
        "event_count": 1,
        "source_identity": {"device": 1},
    }


def delta_index_document():
    return {
        "schema_version": "chronik-grabowski-delta-source-index.v1",
        "source_dir": "/tmp",
        "selection_contract": ["agent.run.completed"],
        "loose_sources": [source_record()],
        "bundles": [],
        "source_count": 1,
        "event_count": 1,
        "recorded_at": "2026-09-09T10:00:00Z",
        "historical_only": True,
        "does_not_establish": ["current_runtime_state"],
        "index_sha256": "b" * 64,
    }


def test_delta_index_parser_preserves_valid_document():
    document = delta_index_document()

    assert state.parse_delta_index_document(document) == document


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_count", True),
        ("event_count", "1"),
        ("historical_only", 1),
        ("selection_contract", ["agent.run.completed", 1]),
        ("loose_sources", {"not": "a list"}),
    ],
)
def test_delta_index_parser_rejects_wrong_persisted_types(field, value):
    document = delta_index_document()
    document[field] = value

    with pytest.raises(ValueError):
        state.parse_delta_index_document(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_bytes", True),
        ("event_count", False),
        ("source_sha256", 7),
        ("source_path", None),
    ],
)
def test_delta_source_parser_rejects_wrong_persisted_types(field, value):
    record = source_record()
    record[field] = value

    with pytest.raises(ValueError):
        state.parse_delta_source_record(record)


def test_steady_checkpoint_parser_rejects_non_object_identity():
    document = {
        "schema_version": "chronik-grabowski-steady-import-checkpoint.v1",
        "source_dir": "/tmp",
        "selection_contract": ["agent.run.completed"],
        "identity": [],
        "summary": {},
        "recorded_at": "2026-09-09T10:00:00Z",
        "historical_only": True,
        "does_not_establish": ["current_runtime_state"],
        "checkpoint_sha256": "c" * 64,
    }

    with pytest.raises(ValueError):
        state.parse_steady_checkpoint_document(document)


def test_delta_overlay_parser_rejects_boolean_record_count():
    document = {
        "schema_version": "chronik-grabowski-delta-source-overlay.v1",
        "source_dir": "/tmp",
        "base_index_sha256": "d" * 64,
        "records": [],
        "record_count": True,
        "recorded_at": "2026-09-09T10:00:00Z",
        "historical_only": True,
        "does_not_establish": ["current_runtime_state"],
        "overlay_sha256": "e" * 64,
    }

    with pytest.raises(ValueError):
        state.parse_delta_overlay_document(document)
