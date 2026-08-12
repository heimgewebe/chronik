import json
from datetime import datetime, timezone
from unittest.mock import patch

# Importing from app inside the tests keeps patching simple and avoids unnecessary module side effects.

def test_process_tail_lines_with_malformed_json():
    """
    Test that _process_tail_lines correctly identifies and counts malformed JSON lines
    while still processing valid ones.
    """
    from app import _process_tail_lines

    lines = [
        json.dumps({"ts": "2023-01-01T10:00:00Z", "val": 1}),
        "NOT JSON",
        json.dumps({"ts": "2023-01-01T11:00:00Z", "val": 2}),
        "{ broken: json }",
        json.dumps({"ts": "2023-01-01T12:00:00Z", "val": 3}),
    ]

    since_dt = None
    dom = "test-domain"

    with patch("app.logger") as mock_logger:
        results, dropped, last_seen_dt = _process_tail_lines(lines, since_dt, dom)

    assert len(results) == 3
    assert results[0]["val"] == 1
    assert results[1]["val"] == 2
    assert results[2]["val"] == 3
    assert dropped == 2
    assert last_seen_dt == datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Verify warning was logged
    mock_logger.warning.assert_called_once()
    args, kwargs = mock_logger.warning.call_args
    assert "dropped corrupt lines" in args[0]
    assert kwargs["extra"]["dropped"] == 2
    assert kwargs["extra"]["domain"] == dom

def test_process_tail_lines_all_malformed():
    """
    Test that _process_tail_lines handles a list of only malformed JSON lines.
    """
    from app import _process_tail_lines

    lines = ["bad1", "bad2", "bad3"]
    since_dt = None
    dom = "test-domain"

    with patch("app.logger") as mock_logger:
        results, dropped, last_seen_dt = _process_tail_lines(lines, since_dt, dom)

    assert len(results) == 0
    assert dropped == 3
    assert last_seen_dt is None
    mock_logger.warning.assert_called_once()

def test_process_tail_lines_with_since_filter_ignores_legacy_timestamps():
    from app import _process_tail_lines
    lines = [
        json.dumps({"ts": "2023-01-01T11:00:00Z", "id": 1}),
        "malformed",
        json.dumps({"timestamp": "2023-01-01T12:00:00Z", "id": 2}),
    ]
    since_dt = datetime(2023, 1, 1, 10, 30, 0, tzinfo=timezone.utc)
    results, dropped, last_seen_dt = _process_tail_lines(lines, since_dt, "test-domain")
    assert results == []
    assert dropped == 1
    assert last_seen_dt is None


def test_process_tail_lines_received_at_since_is_inclusive():
    from app import _process_tail_lines
    lines = [
        json.dumps({"received_at": "2023-01-01T10:00:00Z", "id": 1}),
        json.dumps({"received_at": "2023-01-01T11:00:00Z", "id": 2}),
        json.dumps({"received_at": "2023-01-01T12:00:00Z", "id": 3}),
    ]
    since_dt = datetime(2023, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
    results, dropped, last_seen_dt = _process_tail_lines(lines, since_dt, "test-canonical")
    assert [item["id"] for item in results] == [2, 3]
    assert dropped == 0
    assert last_seen_dt == datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_process_tail_lines_until_is_exclusive():
    from app import _process_tail_lines
    lines = [
        json.dumps({"received_at": "2023-01-01T10:00:00Z", "id": 1}),
        json.dumps({"received_at": "2023-01-01T11:00:00Z", "id": 2}),
    ]
    until_dt = datetime(2023, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
    results, dropped, last_seen_dt = _process_tail_lines(
        lines, None, "test-canonical", until_dt=until_dt
    )
    assert [item["id"] for item in results] == [1]
    assert dropped == 0
    assert last_seen_dt == datetime(2023, 1, 1, 10, 0, 0, tzinfo=timezone.utc)


def test_process_tail_lines_without_timestamps():
    from app import _process_tail_lines
    lines = [
        json.dumps({"msg": "no timestamp"}),
        "corrupt",
        json.dumps({"msg": "still no timestamp"}),
    ]
    results, dropped, last_seen_dt = _process_tail_lines(lines, None, "test")
    assert len(results) == 2
    assert dropped == 1
    assert last_seen_dt is None
