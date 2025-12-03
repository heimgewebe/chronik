"""Shared domain and storage helpers for Chronik ingest components."""

from __future__ import annotations

import errno
import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Final, Iterable

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


def write_payload(domain: str, lines: Iterable[str]) -> None:
    """Write lines to the domain-specific storage file.
    Handles file locking, safe path resolution, and error mapping.
    """
    # Nothing to write - return early
    if not lines:
        return

    # safe_target_path calls sanitize_domain internally if we passed just domain,
    # but here we usually pass a domain string.
    # Note: safe_target_path expects a domain string and uses DATA_DIR by default.
    # It might raise DomainError.
    try:
        target_path = safe_target_path(domain)
    except DomainError as exc:
        raise StorageError("invalid target path") from exc

    fname = target_path.name

    # Extra validation (paranoia check duplicating some logic but keeping it safe)
    if target_path.parent != DATA_DIR:
        raise StorageError("invalid target path: wrong parent directory")

    # Prevent "File name too long" for lock files on 255-char filenames
    # We use a hidden file with a hash if the simple name would be too long.
    lock_name = fname + ".lock"
    if len(lock_name) > 255:
        # Use a deterministic hash of the filename to keep it short and unique
        h = hashlib.sha256(fname.encode("utf-8")).hexdigest()
        lock_name = f".{h}.lock"

    lock_path = target_path.parent / lock_name

    try:
        with FileLock(str(lock_path), timeout=LOCK_TIMEOUT):
            # Defense-in-depth: always use trusted DATA_DIR for dirfd
            dirfd = os.open(str(DATA_DIR), os.O_RDONLY)
            try:
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_APPEND
                    | getattr(os, "O_CLOEXEC", 0)
                )
                if not hasattr(os, "O_NOFOLLOW"):
                    # This should ideally be checked at startup
                    raise StorageError("platform lacks O_NOFOLLOW")
                flags |= os.O_NOFOLLOW

                fd = None
                try:
                    # codeql[py/uncontrolled-data-in-path-expression]:
                    # fname is validated basename; dir_fd=trusted DATA directory
                    fd = os.open(
                        fname,
                        flags,
                        0o600,
                        dir_fd=dirfd,
                    )
                    with os.fdopen(fd, "a", encoding="utf-8") as fh:
                        fd = None  # fdopen takes ownership
                        for line in lines:
                            fh.write(line)
                            fh.write("\n")
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
                    if fd is not None:
                        os.close(fd)
            finally:
                os.close(dirfd)
    except Timeout as exc:
        logger.warning("busy (lock timeout)", extra={"file": str(target_path)})
        raise StorageBusyError("busy, try again") from exc
