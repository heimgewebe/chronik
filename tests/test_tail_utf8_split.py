
import os
from pathlib import Path
from storage import _tail_impl

def test_tail_truncation_bug(tmp_path):
    # Setup file: "A\n€\n"
    # A = 0x41
    # \n = 0x0A
    # € = 0xE2 0x82 0xAC
    # \n = 0x0A

    content = b"A\n\xe2\x82\xac\n"
    fpath = tmp_path / "test.jsonl"
    fpath.write_bytes(content)

    # We want to retrieve the last 1 line: "€"
    limit = 1

    # We simulate a small chunk size that reads just enough to satisfy the newline count
    # reading from end:
    # chunk 1: last 2 bytes -> 0xAC 0x0A ("\xac\n")
    # Newline count in chunk is 1. Limit is 1.
    # The loop in _tail_impl checks: if buffer.count(b'\n') >= limit: break
    # So it will stop.

    with open(fpath, "rb") as fh:
        # Pass small chunk_size=2
        lines = _tail_impl(fh, limit=1, chunk_size=2)

    print(f"Lines returned: {lines}")

    # Expected: ['€']
    # Actual (predicted): [''] (replacement character)

    assert lines == ["€"], f"Expected ['€'], got {lines}"

if __name__ == "__main__":
    import pytest
    import sys
    sys.exit(pytest.main([__file__]))
