"""Shared domain and storage helpers for Chronik ingest components."""

from __future__ import annotations

import errno
import hashlib
import logging
import os
import re
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from typing import Final, Iterable, Iterator

from filelock import FileLock, Timeout

__all__ = [
    "DATA_DIR",
    "DomainError",
    "StorageError",
    "StorageFullError",
    "StorageBusyError",
    "sanitize_domain",
    "secure_filename",
    "target_filename",
    "safe_target_path",
    "write_payload",
    "read_tail",
    "read_last_line",
    "get_lock_path",
    "FILENAME_RE",
]

logger = logging.getLogger(__name__)


class DomainError(ValueError):
    """Raised when a domain does not meet the validation requirements."""


class StorageError(Exception):
    """Base class for storage-related errors."""


class StorageFullError(StorageError):
    """Raised when the storage device is full."""


class StorageBusyError(StorageError):
    """Raised when the target file is locked/busy."""


DATA_DIR: Final[Path] = Path(
    os.environ.get("CHRONIK_DATA_DIR", "data")
).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

# RFC-like FQDN validation: labels 1..63, a-z0-9 and '-' (no '_'), total ≤ 253
_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
)

_FNAME_MAX: Final[int] = 255  # typical filesystem limit (ext4, etc.)

# Central, restrictive filename check (only a-z0-9._- + .jsonl)
FILENAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-z0-9._-]+\.jsonl$", re.IGNORECASE
)

# Additional characters we remove for security (besides / and \0)
_UNSAFE_FILENAME_CHARS: Final[re.Pattern[str]] = re.compile(r"[][<>:\"|?*]")

LOCK_TIMEOUT: Final[int] = int(os.getenv("CHRONIK_LOCK_TIMEOUT") or "30")


def sanitize_domain(domain: str) -> str:
    """Normalize and validate an incoming domain name."""

    d = (domain or "").strip().lower()
    if not _DOMAIN_RE.fullmatch(d):
        raise DomainError(domain)
    return d


def _is_under(path: Path, base: Path) -> bool:
    try:
        return path.is_relative_to(base)  # Python 3.9+
    except AttributeError:
        return os.path.commonpath([str(path), str(base)]) == str(base)


def secure_filename(name: str) -> str:
    """Sanitize filenames to avoid traversal or unsupported characters."""

    s_name = name.replace("/", "").replace("\\", "")
    while ".." in s_name:
        s_name = s_name.replace("..", ".")
    return _UNSAFE_FILENAME_CHARS.sub("", s_name)


def target_filename(domain: str) -> str:
    """Return a deterministic filename for a given domain."""

    base = domain
    ext = ".jsonl"
    # Reserve 1-2 characters for safety due to encoding/filesystem limits
    if len(base) + len(ext) > _FNAME_MAX:
        h = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:8]
        # Keep as much as possible, then add '-{hash}'
        keep = max(16, (_FNAME_MAX - len(ext) - 1 - len(h)))  # 1 for '-'
        base = f"{domain[:keep]}-{h}"
    filename = secure_filename(f"{base}{ext}")
    if not FILENAME_RE.fullmatch(filename):
        raise DomainError(domain)
    return filename


def safe_target_path(domain: str, *, data_dir: Path | None = None) -> Path:
    """Return an absolute, canonical path below the data directory for the domain.
    The filename is fully sanitized; we additionally assert no path separators
    pass through.
    """

    base = (DATA_DIR if data_dir is None else data_dir).resolve(strict=True)
    fname = target_filename(domain)
    # Extra defense: enforce no separators after sanitizing (helps static analyzers)
    if "/" in fname or "\\" in fname:
        raise DomainError(domain)
    # Additional defense: reject anything that would change when interpreted as a
    # path component (e.g. trailing spaces on Windows, reserved characters, etc.).
    if fname != Path(fname).name:
        raise DomainError(domain)
    # Solution: check for symlinks on the unresolved path
    unresolved_candidate = base / fname
    if unresolved_candidate.is_symlink():
        raise DomainError(domain)

    # Now, resolve and normalize the path
    candidate = unresolved_candidate.resolve(strict=False)  # canonicalize

    # Containment check using canonical base directory and normalized paths
    if not _is_under(candidate, base):
        raise DomainError(domain)
    # TOCTOU: After resolving, check again whether the path exists and is a symlink
    if candidate.is_symlink():
        raise DomainError(domain)
    return candidate


def get_lock_path(target_path: Path) -> Path:
    """Return the lock file path for a given target file path."""
    fname = target_path.name
    lock_name = fname + ".lock"
    if len(lock_name) > 255:
        h = hashlib.sha256(fname.encode("utf-8")).hexdigest()
        lock_name = f".{h}.lock"
    return target_path.parent / lock_name


@contextmanager
def _locked_open(target_path: Path, mode: str) -> Iterator:
    """Context manager to securely open a file with locking.
    Handles FileLock, O_NOFOLLOW, O_CLOEXEC, and error mapping.
    """
    fname = target_path.name
    # Extra validation
    if target_path.parent != DATA_DIR:
        raise StorageError("invalid target path: wrong parent directory")

    lock_path = get_lock_path(target_path)

    # Determine open flags and Python mode
    if mode == "r":
        flags = os.O_RDONLY
        py_mode = "r"
        encoding = "utf-8"
    elif mode == "rb":
        flags = os.O_RDONLY
        py_mode = "rb"
        encoding = None
    elif mode == "a":
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        py_mode = "a"
        encoding = "utf-8"
    else:
        raise ValueError(f"unsupported mode: {mode}")

    flags |= getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise StorageError("platform lacks O_NOFOLLOW")
    flags |= os.O_NOFOLLOW

    try:
        with FileLock(str(lock_path), timeout=LOCK_TIMEOUT):
            # Defense-in-depth: always use trusted DATA_DIR for dirfd
            dirfd = os.open(str(DATA_DIR), os.O_RDONLY)
            try:
                fd = os.open(
                    fname,
                    flags,
                    0o600,
                    dir_fd=dirfd,
                )
                try:
                    fh = os.fdopen(fd, py_mode, encoding=encoding)
                except Exception:
                    os.close(fd)
                    raise
                with fh:
                    yield fh
            except OSError as exc:
                if exc.errno == errno.ENOSPC:
                    logger.error("disk full", extra={"file": str(target_path)})
                    raise StorageFullError("insufficient storage") from exc
                if exc.errno == errno.ELOOP:
                    logger.warning(
                        "symlink attempt rejected",
                        extra={"file": str(target_path)},
                    )
                    raise StorageError("invalid target (symlink)") from exc
                raise
            finally:
                os.close(dirfd)
    except Timeout as exc:
        logger.warning("busy (lock timeout)", extra={"file": str(target_path)})
        raise StorageBusyError("busy, try again") from exc


def read_tail(domain: str, limit: int) -> list[str]:
    """Read the last `limit` lines from the domain's storage file.
    Returns an empty list if the file does not exist.
    """
    try:
        target_path = safe_target_path(domain)
    except DomainError as exc:
        raise StorageError("invalid target path") from exc

    try:
        with _locked_open(target_path, "rb") as fh:
            return _tail_impl(fh, limit)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return []
        raise StorageError("read error") from exc


def read_last_line(domain: str) -> str | None:
    """Read the very last line from the domain's storage file.
    Returns None if the file does not exist or is empty.
    """
    lines = read_tail(domain, 1)
    return lines[0] if lines else None


def _tail_impl(fh, limit: int, chunk_size: int = 65536) -> list[str]:
    """Efficiently read the last `limit` lines from a binary file handle."""
    fh.seek(0, 2)
    file_size = fh.tell()

    if file_size == 0:
        return []

    lines: list[str] = []
    # If the file has data, the last byte might be a newline or not.
    # We want to collect 'limit' logical lines.

    # We'll build up a buffer of bytes from the end.
    buffer = bytearray()
    pointer = file_size

    while len(lines) < limit and pointer > 0:
        read_size = min(chunk_size, pointer)
        pointer -= read_size
        fh.seek(pointer)
        chunk = fh.read(read_size)

        # Prepend chunk to buffer
        buffer[0:0] = chunk

        # Count newlines in buffer to see if we have enough
        # We need (limit) newlines to ensure we have (limit) lines,
        # plus maybe one more if the last line doesn't end in newline?
        # Standard approach: split lines, check count.

        # Optimization: verify we have enough newlines before decoding fully?
        # But decoding partial UTF-8 is risky.
        # However, newlines (0x0A) are safe in UTF-8.
        # We need strictly more than 'limit' newlines to ensure the oldest line
        # we captured is complete and not a partial cut-off (which could have
        # corrupt multi-byte chars at the start).
        # Note: If we reach the start of the file (pointer == 0), the loop
        # terminates naturally, which is also a safe state (no partial prefix).
        if buffer.count(b'\n') > limit:
            break

    # Decode everything we have collected
    try:
        text = buffer.decode("utf-8")
    except UnicodeDecodeError as exc:
        # Fallback: try to decode with replacement or ignore errors
        # for the very start of the buffer which might be split char
        logger.warning(
            "utf-8 decode error during read_tail (using fallback)",
            extra={"error": str(exc)},
        )
        text = buffer.decode("utf-8", errors="replace")

    # Use split('\n') to avoid splitting on other characters like \u2028 (Line Separator)
    # which are valid in JSON strings but treated as newlines by splitlines().
    all_lines = text.split('\n')

    # If the file ends with newline (standard for write_payload), split('\n') produces
    # a trailing empty string. We remove it to match the expectation of "lines".
    if all_lines and all_lines[-1] == "":
        all_lines.pop()

    return all_lines[-limit:]


def write_payload(domain: str, lines: Iterable[str]) -> None:
    """Write lines to the domain-specific storage file.
    Handles file locking, safe path resolution, and error mapping.
    """
    # Nothing to write - return early
    if not lines:
        return

    try:
        target_path = safe_target_path(domain)
    except DomainError as exc:
        raise StorageError("invalid target path") from exc

    with _locked_open(target_path, "a") as fh:
        try:
            for line in lines:
                fh.write(line)
                fh.write("\n")
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                logger.error("disk full", extra={"file": str(target_path)})
                raise StorageFullError("insufficient storage") from exc
            raise
