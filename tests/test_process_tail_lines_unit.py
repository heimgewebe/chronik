import json
from datetime import datetime, timezone
import pytest
from unittest.mock import MagicMock, patch

# Note: We import app inside the test functions or use a runner to mock dependencies
# because fastapi and other packages might be missing in the environment.

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

def test_process_tail_lines_with_since_filter():
    """
    Test that _process_tail_lines correctly filters lines based on since_dt
    even when malformed lines are present.
    """
    from app import _process_tail_lines

    lines = [
        json.dumps({"ts": "2023-01-01T10:00:00Z", "id": 1}),
        "malformed",
        json.dumps({"ts": "2023-01-01T11:00:00Z", "id": 2}),
        json.dumps({"ts": "2023-01-01T12:00:00Z", "id": 3}),
    ]

    since_dt = datetime(2023, 1, 1, 10, 30, 0, tzinfo=timezone.utc)
    dom = "test-domain"

    results, dropped, last_seen_dt = _process_tail_lines(lines, since_dt, dom)

    assert len(results) == 2
    assert results[0]["id"] == 2
    assert results[1]["id"] == 3
    assert dropped == 1
    assert last_seen_dt == datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

def test_process_tail_lines_no_timestamps():
    """
    Test that _process_tail_lines handles valid JSON lines that lack timestamps.
    """
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
