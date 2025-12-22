
import pytest
from storage import _tail_impl

def test_tail_truncation_split_utf8_euro(tmp_path):
    """
    Regression test for a bug where reading chunks in reverse could split
    a multi-byte character (Euro sign) at the chunk boundary.

    File: "A\n€\n"
    limit=1
    chunk_size=2

    Reverse read:
    1. Reads last 2 bytes: "\xac\n" -> Newline count = 1.
    If we stopped here (>= limit), we'd have "\xac\n".
    Decoding "\xac" as UTF-8 fails (or replaces).

    Fix requires reading more until > limit or start of file.
    """
    content = b"A\n\xe2\x82\xac\n" # A \n € \n
    fpath = tmp_path / "test_euro.jsonl"
    fpath.write_bytes(content)

    with open(fpath, "rb") as fh:
        # Pass small chunk_size=2 to force the split of the 3-byte Euro symbol
        lines = _tail_impl(fh, limit=1, chunk_size=2)

    assert lines == ["€"], f"Expected ['€'], got {lines}"

def test_tail_no_trailing_newline_split(tmp_path):
    """
    Test tailing a file ending with a multibyte char but NO trailing newline.
    File: "A\n€"
    limit=1
    """
    content = b"A\n\xe2\x82\xac" # A \n €
    fpath = tmp_path / "test_no_newline.jsonl"
    fpath.write_bytes(content)

    with open(fpath, "rb") as fh:
        # chunk_size=2.
        # End of file is ...\x82\xac.
        # First chunk (rev): \x82\xac. No newline.
        # Next chunk: A\n\xe2. Newline found. Total newlines=1.
        # If strict > limit check is used, it might read more or stop correctly depending on logic.
        # In this case buffer has "A\n€". count(\n) == 1.
        # If limit=1, we need count > 1 OR start of file.
        # Here we hit start of file "A...".
        lines = _tail_impl(fh, limit=1, chunk_size=2)

    assert lines == ["€"], f"Expected ['€'], got {lines}"

def test_tail_chunk_size_one(tmp_path):
    """
    Test with chunk_size=1 to ensure maximum stress on splitting.
    """
    content = b"A\n\xe2\x82\xac\n"
    fpath = tmp_path / "test_chunk_1.jsonl"
    fpath.write_bytes(content)

    with open(fpath, "rb") as fh:
        lines = _tail_impl(fh, limit=1, chunk_size=1)

    assert lines == ["€"]

def test_tail_multibyte_multiple_lines(tmp_path):
    """
    Test requesting multiple lines with multiple multibyte characters.
    File:
    Line 1: Ü1
    Line 2: €2
    Line 3: 🙃3
    """
    # Ü = \xc3\x9c (2 bytes)
    # € = \xe2\x82\xac (3 bytes)
    # 🙃 = \xf0\x9f\x99\x83 (4 bytes)

    lines_content = [
        "Ü1",
        "€2",
        "🙃3"
    ]
    content = "\n".join(lines_content).encode("utf-8") + b"\n"
    fpath = tmp_path / "test_multi.jsonl"
    fpath.write_bytes(content)

    with open(fpath, "rb") as fh:
        # chunk_size=3 to ensure we split the 4-byte emoji and 3-byte euro
        results = _tail_impl(fh, limit=2, chunk_size=3)

    assert results == ["€2", "🙃3"]

def test_tail_exact_limit_boundary(tmp_path):
    """
    Test where the file has exactly 'limit' lines.
    """
    content = b"A\nB\n"
    fpath = tmp_path / "test_exact.jsonl"
    fpath.write_bytes(content)

    with open(fpath, "rb") as fh:
        # limit=2.
        results = _tail_impl(fh, limit=2, chunk_size=10)

    assert results == ["A", "B"]
