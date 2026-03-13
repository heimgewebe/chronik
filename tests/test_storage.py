import pytest
import storage

@pytest.fixture
def mock_data_dir(tmp_path, monkeypatch):
    """Isolate DATA_DIR for storage tests."""
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    return tmp_path

def test_list_domains_empty(mock_data_dir):
    """Verify it returns an empty list when DATA_DIR is empty."""
    assert storage.list_domains() == []

def test_list_domains_basic(mock_data_dir):
    """Verify it lists valid .jsonl files and sorts them."""
    (mock_data_dir / "zebra.jsonl").touch()
    (mock_data_dir / "apple.jsonl").touch()
    (mock_data_dir / "banana.jsonl").touch()

    assert storage.list_domains() == ["apple", "banana", "zebra"]

def test_list_domains_filtering(mock_data_dir):
    """Verify it ignores directories and files that don't match FILENAME_RE."""
    (mock_data_dir / "valid.jsonl").touch()
    (mock_data_dir / "invalid.txt").touch()
    (mock_data_dir / "no_ext").touch()
    (mock_data_dir / "subdir.jsonl").mkdir()
    (mock_data_dir / ".hidden.jsonl").touch() # Should be ignored (starts with dot)

    assert storage.list_domains() == ["valid"]

def test_list_domains_prefix(mock_data_dir):
    """Verify the prefix parameter correctly filters results."""
    (mock_data_dir / "apple.jsonl").touch()
    (mock_data_dir / "apricot.jsonl").touch()
    (mock_data_dir / "banana.jsonl").touch()

    # Empty prefix
    assert storage.list_domains("") == ["apple", "apricot", "banana"]

    # Matching prefix
    assert storage.list_domains("ap") == ["apple", "apricot"]

    # Non-matching prefix
    assert storage.list_domains("cherry") == []

def test_list_domains_special_chars(mock_data_dir):
    """Verify it handles allowed special characters in filenames."""
    # FILENAME_RE: [a-z0-9._-]+
    names = ["my.domain", "my_domain", "my-domain", "123.456"]
    for name in names:
        (mock_data_dir / f"{name}.jsonl").touch()

    assert storage.list_domains() == sorted(names)

def test_list_domains_os_error(mock_data_dir, monkeypatch):
    """Verify it returns an empty list and logs an error when os.scandir fails."""
    def mock_scandir(path):
        raise OSError("Access denied")

    # Patch storage.os to be more specific
    monkeypatch.setattr(storage.os, "scandir", mock_scandir)

    assert storage.list_domains() == []

def test_read_last_line_nonexistent(mock_data_dir):
    """Verify it returns None for a non-existent domain."""
    assert storage.read_last_line("nonexistent") is None

def test_read_last_line_empty(mock_data_dir):
    """Verify it returns None for an empty file."""
    (mock_data_dir / "empty.jsonl").touch()
    assert storage.read_last_line("empty") is None

def test_read_last_line_single_line(mock_data_dir):
    """Verify it returns the single line from a file."""
    storage.write_payload("single", ["{\"line\": 1}"])
    assert storage.read_last_line("single") == "{\"line\": 1}"

def test_read_last_line_multiple_lines(mock_data_dir):
    """Verify it returns the last line from a multi-line file."""
    storage.write_payload("multiple", ["{\"line\": 1}", "{\"line\": 2}"])
    assert storage.read_last_line("multiple") == "{\"line\": 2}"

def test_read_last_line_invalid_domain(mock_data_dir):
    """Verify it raises StorageError for an invalid domain name."""
    with pytest.raises(storage.StorageError, match="invalid target"):
        storage.read_last_line("domain with spaces")
