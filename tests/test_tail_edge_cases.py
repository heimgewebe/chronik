
import pytest
import storage
import os

@pytest.fixture
def mock_storage(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    return tmp_path

def test_long_last_line(mock_storage):
    """Test reading a file with a very long last line."""
    domain = "long-line"
    path = storage.safe_target_path(domain)

    # 1MB line
    long_line = "A" * 1024 * 1024
    content = f"short\n{long_line}\n".encode("utf-8")

    with open(path, "wb") as f:
        f.write(content)

    with storage._locked_open(path, "rb") as fh:
        # Read with small chunk size to force many iterations
        lines = storage._tail_impl(fh, limit=1, chunk_size=1024)

    assert len(lines) == 1
    assert len(lines[0]) == 1024 * 1024
    assert lines[0] == long_line

def test_limit_larger_than_file_chunks(mock_storage):
    """Test requesting more lines than exist, with multiple chunks."""
    domain = "small-file"
    path = storage.safe_target_path(domain)

    # 3 lines
    content = b"1\n2\n3\n"
    with open(path, "wb") as f:
        f.write(content)

    with storage._locked_open(path, "rb") as fh:
        # Chunk size 2: reads "3\n", then "2\n", then "1\n"
        lines = storage._tail_impl(fh, limit=10, chunk_size=2)

    assert lines == ["1", "2", "3"]

def test_exact_limit_match_no_newline(mock_storage):
    """Test where the file has exactly 'limit' newlines and no trailing newline."""
    domain = "exact-limit"
    path = storage.safe_target_path(domain)

    # 2 newlines total. limit=2.
    content = b"1\n2\n3"
    with open(path, "wb") as f:
        f.write(content)

    with storage._locked_open(path, "rb") as fh:
        lines = storage._tail_impl(fh, limit=2)

    # Should get last 2 lines: "2" and "3"
    assert lines == ["2", "3"]

def test_exact_limit_match_with_newline(mock_storage):
    """Test where the file has exactly 'limit' lines ending with newline."""
    domain = "exact-limit-nl"
    path = storage.safe_target_path(domain)

    # 2 lines: "2\n", "3\n". limit=2.
    content = b"1\n2\n3\n"
    with open(path, "wb") as f:
        f.write(content)

    with storage._locked_open(path, "rb") as fh:
        lines = storage._tail_impl(fh, limit=2)

    # Should get "2", "3"
    assert lines == ["2", "3"]
