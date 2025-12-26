
import json
import os
import storage
import pytest
from filelock import FileLock

def test_tail_splitlines_utf8_char(monkeypatch, tmp_path):
    """
    Regression test for a bug where read_tail uses splitlines() which splits
    on characters like U+2028 (Line Separator), corrupting JSON payloads
    that contain this character unescaped.
    """
    # Isolate DATA_DIR
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)

    domain = "test-splitlines"

    # Payload containing U+2028 (Line Separator)
    # This character is valid in JSON strings (not a control char < U+0020),
    # but Python's str.splitlines() treats it as a newline.
    special_char = "\u2028"
    payload_data = {"data": f"something{special_char}else"}

    # We serialize with ensure_ascii=False to keep the character as UTF-8 bytes
    line = json.dumps(payload_data, ensure_ascii=False)
    assert special_char in line

    # Write to storage
    storage.write_payload(domain, [line])

    # Read back using read_tail
    lines = storage.read_tail(domain, 1)

    assert len(lines) == 1
    read_line = lines[0]

    # If the bug is present, read_line will be the second half of the split string
    # and not valid JSON.
    try:
        obj = json.loads(read_line)
    except json.JSONDecodeError:
        pytest.fail(f"read_tail returned invalid JSON: {read_line!r}")

    assert obj == payload_data

def test_tail_splitlines_consistency_trailing_newline(monkeypatch, tmp_path):
    """
    Ensure that switching from splitlines() to split('\n') preserves behavior
    regarding trailing newlines.
    """
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    domain = "test-newlines"
    p = storage.safe_target_path(domain)

    # 1. File ending with \n (standard)
    with open(p, "wb") as f:
        f.write(b"line1\nline2\n")

    lines = storage.read_tail(domain, 10)
    assert lines == ["line1", "line2"]

    # 2. File NOT ending with \n (edge case)
    with open(p, "wb") as f:
        f.write(b"line1\nline2")

    lines = storage.read_tail(domain, 10)
    assert lines == ["line1", "line2"]

    # 3. File with empty lines
    with open(p, "wb") as f:
        f.write(b"line1\n\nline3\n")

    lines = storage.read_tail(domain, 10)
    assert lines == ["line1", "", "line3"]
