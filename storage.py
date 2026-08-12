"""Shared domain and storage helpers for Chronik ingest components."""

from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Final, Iterable, Iterator, NoReturn, Tuple

from filelock import FileLock, Timeout

from settings import Settings

from identity_index import (
    IdentityIndexCommitUncertain,
    IdentityIndexDriftError,
    IdentityIndexError,
    index_path_for_target,
    open_identity_index,
    reset_identity_index_for_authoritative_replay,
)

__all__ = [
    "DATA_DIR",
    "DomainError",
    "StorageError",
    "StorageCursorError",
    "StorageFullError",
    "StorageBusyError",
    "StorageConflictError",
    "StorageRequiredIdentityError",
    "StorageRecoveryError",
    "StorageMissingIdentityError",
    "sanitize_domain",
    "secure_filename",
    "target_filename",
    "safe_target_path",
    "write_payload",
    "write_payload_unique",
    "write_payload_unique_groups",
    "read_tail",
    "read_last_line",
    "read_domain_snapshot",
    "read_unique_storage_checkpoint_identity",
    "scan_domain",
    "list_domains",
    "get_lock_path",
    "FILENAME_RE",
]

logger = logging.getLogger(__name__)


class DomainError(ValueError):
    """Raised when a domain does not meet the validation requirements."""


class StorageError(Exception):
    """Base class for storage-related errors."""


class StorageCursorError(StorageError):
    """Raised when a byte cursor does not point to a JSONL record boundary."""


class StorageFullError(StorageError):
    """Raised when the storage device is full."""


class StorageBusyError(StorageError):
    """Raised when the target file is locked/busy."""


class StorageConflictError(StorageError):
    """Raised when a caller-provided identity conflicts with durable ledger truth."""

    def __init__(self, identity_key: str, identity: str) -> None:
        self.identity_key = identity_key
        self.identity = identity
        super().__init__(f"conflicting {identity_key}: {identity}")


class StorageRequiredIdentityError(StorageError):
    """Raised when an append contract requires an identity field that is absent."""

    def __init__(self, identity_key: str) -> None:
        self.identity_key = identity_key
        super().__init__(f"missing {identity_key}")


class StorageRecoveryError(StorageError):
    """Raised when append rollback or durability cannot be established."""


class StorageMissingIdentityError(StorageError):
    """Raised when a verification-only identity is absent from the ledger.

    Callers may use derived indexes to avoid rematerializing unchanged source
    payloads, but those indexes must never become append authority.  This error
    tells such callers to fail closed or revalidate the authoritative source.
    """

    def __init__(self, group_ids: Iterable[str]) -> None:
        self.group_ids = tuple(sorted(set(group_ids)))
        super().__init__(
            "verification-only identities are missing from the ledger: "
            + ", ".join(self.group_ids)
        )


_STORAGE_SETTINGS = Settings()
DATA_DIR: Final[Path] = _STORAGE_SETTINGS.data_dir
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

LOCK_TIMEOUT: Final[int] = _STORAGE_SETTINGS.lock_timeout


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
def _safe_open_read(target_path: Path) -> Iterator:
    """Securely open a file for reading without following symlinks (O_NOFOLLOW).
    Does NOT acquire a file lock.
    """
    if target_path.parent != DATA_DIR:
        raise StorageError("invalid target path: wrong parent directory")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise StorageError("platform lacks O_NOFOLLOW")
    flags |= os.O_NOFOLLOW

    # Defense-in-depth: always use trusted DATA_DIR for dirfd
    dirfd = os.open(str(DATA_DIR), os.O_RDONLY)
    try:
        fd = os.open(
            target_path.name,
            flags,
            0o600,
            dir_fd=dirfd,
        )
        try:
            fh = os.fdopen(fd, "rb")
        except OSError:
            os.close(fd)
            raise
        with fh:
            yield fh
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            logger.warning(
                "symlink attempt rejected (safe read)",
                extra={"file": str(target_path)},
            )
            raise StorageError("invalid target (symlink)") from exc
        raise
    finally:
        os.close(dirfd)


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
        py_mode = "ab"
        encoding = None
    elif mode == "a+":
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
        py_mode = "a+b"
        encoding = None
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
                except OSError:
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


def _target_stat_for_fd(target_path: Path, fd: int) -> os.stat_result:
    """Return the opened-file stat only while the path still names that file."""
    try:
        opened = os.fstat(fd)
        current = os.stat(target_path, follow_symlinks=False)
    except OSError as exc:
        raise StorageRecoveryError("target identity unavailable") from exc
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise StorageRecoveryError("target identity changed")
    return opened


def _fsync_file(fd: int) -> None:
    """Sync file contents or expose a distinct durability failure."""
    try:
        os.fsync(fd)
    except OSError as exc:
        raise StorageRecoveryError("file durability sync failed") from exc


def _fsync_parent_directory(target_path: Path) -> None:
    """Durably bind file creation and metadata changes to the trusted directory."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        dirfd = os.open(str(target_path.parent), flags)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except OSError as exc:
        raise StorageRecoveryError("directory durability sync failed") from exc


def _rollback_append(fd: int, target_path: Path, pre_append_size: int) -> None:
    """Restore and durably verify the exact byte size captured under the lock."""
    os.ftruncate(fd, pre_append_size)
    _fsync_file(fd)
    _fsync_parent_directory(target_path)
    restored = _target_stat_for_fd(target_path, fd)
    if restored.st_size != pre_append_size:
        raise OSError(
            errno.EIO,
            f"rollback size mismatch: expected {pre_append_size}, got {restored.st_size}",
        )


def _raise_append_error(exc: BaseException, target_path: Path) -> None:
    if isinstance(exc, StorageRecoveryError):
        raise exc
    if isinstance(exc, OSError):
        if exc.errno == errno.ENOSPC:
            logger.error("disk full", extra={"file": str(target_path)})
            raise StorageFullError("insufficient storage") from exc
        raise StorageError("append failed") from exc
    raise exc


def _checkpoint_file_identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "mode": int(info.st_mode),
        "links": int(info.st_nlink),
        "uid": int(info.st_uid),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "ctime_ns": int(info.st_ctime_ns),
    }


def read_unique_storage_checkpoint_identity(
    domain: str, *, identity_key: str = "event_id"
) -> dict[str, object] | None:
    """Return a cheap identity for a previously reconciled unique ledger/index pair.

    This deliberately does not synchronize, rebuild, create, or query identity rows.
    It is useful only as a compare-against-prior-success accelerator: callers must
    already possess a checkpoint written after the normal full reconciliation.
    Any metadata drift forces the caller back through that full path.
    """
    try:
        target_path = safe_target_path(domain)
    except DomainError as exc:
        raise StorageError("invalid target path") from exc
    try:
        target_info = target_path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StorageRecoveryError("target identity unavailable") from exc
    if not stat.S_ISREG(target_info.st_mode):
        raise StorageRecoveryError("target is not a regular file")

    index_path = index_path_for_target(target_path)
    try:
        index_info = index_path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StorageRecoveryError("identity index identity unavailable") from exc
    if (
        not stat.S_ISREG(index_info.st_mode)
        or index_info.st_uid != os.geteuid()
        or index_info.st_mode & 0o077
        or index_info.st_nlink != 1
    ):
        raise StorageRecoveryError("identity index identity is not private and regular")

    with _locked_open(target_path, "rb") as fh:
        opened = _target_stat_for_fd(target_path, fh.fileno())
        try:
            current_index = index_path.lstat()
        except OSError as exc:
            raise StorageRecoveryError("identity index changed during checkpoint read") from exc
        if _checkpoint_file_identity(current_index) != _checkpoint_file_identity(index_info):
            raise StorageRecoveryError("identity index changed during checkpoint read")
        return {
            "schema_version": 1,
            "identity_key": identity_key,
            "ledger": _checkpoint_file_identity(opened),
            "identity_index": _checkpoint_file_identity(current_index),
        }


def _append_jsonl_transaction(fh, target_path: Path, lines: Iterable[str]) -> None:
    """Append complete UTF-8 JSONL records or restore the exact previous bytes."""
    fh.flush()
    fd = fh.fileno()
    pre_append = _target_stat_for_fd(target_path, fd)
    pre_append_size = pre_append.st_size
    appended_bytes = 0
    try:
        for line in lines:
            payload = (line + "\n").encode("utf-8")
            written = os.write(fd, payload)
            if written != len(payload):
                raise OSError(
                    errno.EIO,
                    f"short append write: expected {len(payload)}, wrote {written}",
                )
            appended_bytes += written
        if appended_bytes == 0:
            return
        _fsync_file(fd)
        _fsync_parent_directory(target_path)
        committed = _target_stat_for_fd(target_path, fd)
        expected_size = pre_append_size + appended_bytes
        if committed.st_size != expected_size:
            raise StorageRecoveryError(
                f"append size mismatch: expected {expected_size}, got {committed.st_size}"
            )
    except BaseException as exc:
        try:
            _rollback_append(fd, target_path, pre_append_size)
        except BaseException as rollback_exc:
            logger.critical(
                "append rollback failed",
                extra={
                    "file": str(target_path),
                    "pre_append_size": pre_append_size,
                    "append_error": repr(exc),
                    "rollback_error": repr(rollback_exc),
                },
            )
            raise StorageRecoveryError(
                "append rollback failed; ledger integrity is uncertain"
            ) from rollback_exc
        _raise_append_error(exc, target_path)


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


def read_domain_snapshot(domain: str, start_offset: int = 0) -> bytes:
    """Read one byte-exact, append-stable snapshot of complete JSONL records.

    The file size is captured from the opened descriptor before reading. Bytes
    appended afterwards are outside this snapshot. An incomplete tail is
    excluded so parsing, offsets and hashes share one complete-record boundary.
    """
    if not isinstance(start_offset, int) or isinstance(start_offset, bool) or start_offset < 0:
        raise StorageError("start_offset must be a non-negative integer")
    try:
        target_path = safe_target_path(domain)
    except DomainError as exc:
        raise StorageError("invalid target path") from exc

    try:
        with _safe_open_read(target_path) as fh:
            observed_size = os.fstat(fh.fileno()).st_size
            if start_offset >= observed_size:
                return b""
            fh.seek(start_offset)
            remaining = observed_size - start_offset
            chunks: list[bytes] = []
            while remaining:
                chunk = fh.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return b""
        raise StorageError("read error") from exc

    snapshot = b"".join(chunks)
    if snapshot.endswith(b"\n"):
        return snapshot
    last_newline = snapshot.rfind(b"\n")
    return snapshot[: last_newline + 1] if last_newline >= 0 else b""


def scan_domain(domain: str, start_offset: int = 0) -> Iterator[Tuple[int, int, str]]:
    """Scan the domain file forward starting from the given byte offset.

    Yields:
        (start_offset, next_offset, line_str)

    If start_offset is beyond EOF, yields nothing.
    """
    if (
        isinstance(start_offset, bool)
        or not isinstance(start_offset, int)
        or start_offset < 0
    ):
        raise StorageCursorError("start_offset must be a non-negative integer")

    try:
        target_path = safe_target_path(domain)
    except DomainError as exc:
        raise StorageError("invalid target path") from exc

    # Open for reading without exclusive lock to avoid blocking writers during long scans.
    # Writers append atomically (mostly), so worst case is a partial read at EOF,
    # which will likely be handled as a corrupt line or ignored.
    try:
        # Use safe open to prevent symlink attacks, but no file lock
        with _safe_open_read(target_path) as fh:
            if start_offset:
                try:
                    fh.seek(start_offset - 1)
                except (OverflowError, ValueError):
                    return
                except OSError as exc:
                    if exc.errno in {errno.EINVAL, errno.EOVERFLOW}:
                        return
                    raise
                previous = fh.read(1)
                if not previous:
                    # Preserve the documented polling contract: a cursor beyond
                    # the current EOF yields no records and can be retried later.
                    return
                if previous != b"\n":
                    raise StorageCursorError(
                        "start_offset must point to a JSONL record boundary"
                    )
                # Reading the boundary byte already positions the handle exactly
                # at start_offset; a second seek would be redundant.
            while True:
                # Capture start offset before reading
                current_start = fh.tell()

                line = fh.readline()
                if not line:
                    break

                # Guard against partial writes: Only process complete lines ending with newline.
                # If we are at EOF and the line doesn't end with \n, it's likely being written.
                # We stop here and don't yield this line or advance cursor past it.
                if not line.endswith(b'\n'):
                    break

                # Current position is the start of the next line
                next_offset = fh.tell()

                # Decode
                try:
                    text = line.decode("utf-8")
                except UnicodeDecodeError:
                    text = line.decode("utf-8", errors="replace")

                # Remove trailing newline (we know it exists now)
                if text.endswith("\n"):
                    text = text[:-1]

                yield current_start, next_offset, text

    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return
        raise StorageError("read error") from exc


def list_domains(prefix: str = "") -> list[str]:
    """List domains that match the given prefix.

    This inspects the filenames in DATA_DIR.
    Note: For hashed filenames, this returns the hash-based name (the storage key),
    not the original full domain. The caller should inspect the payload if they
    need the original domain.
    """
    results = []
    try:
        for entry in os.scandir(DATA_DIR):
            name = entry.name
            if name.startswith(".") or not entry.is_file():
                continue
            if not FILENAME_RE.fullmatch(name):
                continue
            if prefix and not name.startswith(prefix):
                continue

            # Remove extension .jsonl
            domain_key = name[:-6]
            results.append(domain_key)
    except OSError as exc:
        logger.error(f"failed to scan data dir: {exc}")
        return []

    return sorted(results)


def _tail_impl(fh, limit: int, chunk_size: int = 65536) -> list[str]:
    """Efficiently read the last `limit` lines from a binary file handle."""
    if limit <= 0:
        return []

    fh.seek(0, 2)
    file_size = fh.tell()

    if file_size == 0:
        return []

    # We'll build up a buffer of bytes from the end.
    chunks: list[tuple[bytes, int]] = []
    newline_count = 0
    pointer = file_size

    while pointer > 0:
        read_size = min(chunk_size, pointer)
        pointer -= read_size
        fh.seek(pointer)
        chunk = fh.read(read_size)

        count = chunk.count(b'\n')
        chunks.append((chunk, count))
        newline_count += count

        # We need (limit) newlines to ensure we have (limit) lines.
        # If the file ends with a newline, we need limit+1 newlines to capture the
        # full preceding line. If it doesn't, we still want a buffer zone.
        # "limit + 1" is a safe heuristic to avoid partial line issues at the cut point.
        if newline_count >= limit + 1:
            break

    # Construct buffer from chunks, but only keep what's needed.
    # chunks are in reverse file order: [EndChunk, PrevChunk, ...]
    needed = limit + 1
    kept_chunks: list[bytes] = []

    for chunk, count in chunks:
        if needed > 0:
            if count < needed:
                kept_chunks.append(chunk)
                needed -= count
            else:
                # This chunk contains the cut point.
                # We need the (needed)-th newline from the end of this chunk.
                cut = len(chunk)
                for _ in range(needed):
                    cut = chunk.rfind(b"\n", 0, cut)
                    if cut == -1:
                        # Should not happen if count >= needed
                        break

                # Keep everything AFTER that newline
                suffix = chunk[cut + 1 :]
                kept_chunks.append(suffix)
                needed = 0
                # We don't need any more chunks
                break
        else:
            break

    buffer = b"".join(reversed(kept_chunks))

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
        _append_jsonl_transaction(fh, target_path, lines)


def _parse_unique_payload(
    line: str | bytes, identity_key: str
) -> tuple[str | None, bytes]:
    value = json.loads(line)
    payload = value.get("payload", value) if isinstance(value, dict) else None
    identity = payload.get(identity_key) if isinstance(payload, dict) else None
    canonical_payload = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return identity if isinstance(identity, str) else None, canonical_payload


def _payload_fingerprint(canonical_payload: bytes) -> bytes:
    """Return a fixed-width length-and-SHA-256 content identity."""
    return (
        len(canonical_payload).to_bytes(8, "big", signed=False)
        + hashlib.sha256(canonical_payload).digest()
    )


def _raise_identity_index_error(exc: IdentityIndexError) -> NoReturn:
    """Map derived-index failures without weakening ledger conflict semantics."""
    message = str(exc)
    if isinstance(exc, IdentityIndexDriftError) and message.startswith("conflicting "):
        raise StorageError(message) from exc
    raise StorageRecoveryError(f"identity index unavailable: {message}") from exc


_ParsedUniqueRow = tuple[str, str | None, bytes]
_ParsedUniqueGroup = tuple[str, list[_ParsedUniqueRow], bool]


def write_payload_unique_groups(
    domain: str,
    groups: Iterable[tuple[str, Iterable[str]]],
    *,
    identity_key: str = "event_id",
    authoritative_replay: bool = False,
    verified_existing_groups: Iterable[
        tuple[str, Iterable[tuple[str, bytes]]]
    ] = (),
) -> dict[str, object]:
    """Append grouped JSON lines through a ledger-authoritative persistent index.

    authoritative_replay is reserved for callers that have validated a complete
    source inventory and are reconstructing an absent ledger.  It may reset only
    the derived index and only while the newly opened ledger is empty.
    """
    materialized: list[tuple[str, list[str]]] = []
    materialized_verified: list[tuple[str, list[tuple[str, bytes]]]] = []
    seen_group_ids: set[str] = set()
    for group_id, lines in groups:
        if not isinstance(group_id, str) or not group_id:
            raise StorageError("group_id must be a non-empty string")
        if group_id in seen_group_ids:
            raise StorageError(f"duplicate group_id: {group_id}")
        seen_group_ids.add(group_id)
        materialized.append((group_id, list(lines)))
    for group_id, identities in verified_existing_groups:
        if not isinstance(group_id, str) or not group_id:
            raise StorageError("group_id must be a non-empty string")
        if group_id in seen_group_ids:
            raise StorageError(f"duplicate group_id: {group_id}")
        seen_group_ids.add(group_id)
        verified: list[tuple[str, bytes]] = []
        for identity, fingerprint in identities:
            if not isinstance(identity, str) or not identity:
                raise StorageRequiredIdentityError(identity_key)
            if not isinstance(fingerprint, bytes) or len(fingerprint) != 40:
                raise StorageError("invalid verification-only payload fingerprint")
            verified.append((identity, fingerprint))
        materialized_verified.append((group_id, verified))

    parsed_groups: list[_ParsedUniqueGroup] = []
    candidate_fingerprints: dict[str, bytes] = {}
    candidate_count = 0
    for group_id, lines in materialized:
        parsed_rows: list[_ParsedUniqueRow] = []
        for line in lines:
            try:
                parsed_identity, canonical_payload = _parse_unique_payload(
                    line, identity_key
                )
            except (TypeError, ValueError) as exc:
                raise StorageError("invalid JSON line") from exc
            if not parsed_identity:
                raise StorageRequiredIdentityError(identity_key)
            fingerprint = _payload_fingerprint(canonical_payload)
            previous = candidate_fingerprints.get(parsed_identity)
            if previous is None:
                candidate_fingerprints[parsed_identity] = fingerprint
            elif previous != fingerprint:
                raise StorageConflictError(identity_key, parsed_identity)
            parsed_rows.append((parsed_identity, line, fingerprint))
            candidate_count += 1
        parsed_groups.append((group_id, parsed_rows, False))
    for group_id, identities in materialized_verified:
        verified_rows: list[_ParsedUniqueRow] = []
        for identity, fingerprint in identities:
            previous = candidate_fingerprints.get(identity)
            if previous is None:
                candidate_fingerprints[identity] = fingerprint
            elif previous != fingerprint:
                raise StorageConflictError(identity_key, identity)
            verified_rows.append((identity, None, fingerprint))
            candidate_count += 1
        parsed_groups.append((group_id, verified_rows, True))

    if candidate_count == 0:
        empty_group_results = [
            {"group_id": gid, "requested": len(lines), "written": 0, "skipped": 0}
            for gid, lines in materialized
        ]
        empty_group_results.extend(
            {
                "group_id": gid,
                "requested": len(identities),
                "written": 0,
                "skipped": 0,
            }
            for gid, identities in materialized_verified
        )
        return {
            "written": 0,
            "skipped": 0,
            "target_scans": 0,
            "target_records_scanned": 0,
            "target_identity_index_entries": 0,
            "identity_index_mode": "unused",
            "identity_index_full_rebuild": False,
            "identity_index_entries_after": 0,
            "groups": empty_group_results,
        }

    del candidate_fingerprints
    try:
        target_path = safe_target_path(domain)
    except DomainError as exc:
        raise StorageError("invalid target path") from exc

    with _locked_open(target_path, "a+") as fh:
        try:
            if authoritative_replay:
                replay_stat = _target_stat_for_fd(target_path, fh.fileno())
                if replay_stat.st_size != 0:
                    raise StorageRecoveryError(
                        "authoritative replay requires an empty reconstructed ledger"
                    )
                reset_identity_index_for_authoritative_replay(target_path)
            with open_identity_index(target_path, timeout=LOCK_TIMEOUT) as index:
                sync = index.synchronize(
                    fh,
                    identity_key=identity_key,
                    parse_payload=_parse_unique_payload,
                    fingerprint_payload=_payload_fingerprint,
                )
                candidate_ids = [
                    identity
                    for _, parsed, _ in parsed_groups
                    for identity, _, _ in parsed
                ]
                existing = index.lookup(
                    fh,
                    state=sync.state,
                    identity_key=identity_key,
                    identities=candidate_ids,
                    parse_payload=_parse_unique_payload,
                    fingerprint_payload=_payload_fingerprint,
                )
                for _, parsed, _ in parsed_groups:
                    for identity, _, fingerprint in parsed:
                        previous = existing.get(identity)
                        if previous is not None and previous != fingerprint:
                            raise StorageConflictError(identity_key, identity)

                missing_verified_groups = [
                    group_id
                    for group_id, parsed, verification_only in parsed_groups
                    if verification_only
                    and any(identity not in existing for identity, _, _ in parsed)
                ]
                if missing_verified_groups:
                    raise StorageMissingIdentityError(missing_verified_groups)

                total_written = 0
                total_skipped = 0
                group_results = []
                append_lines: list[str] = []
                append_rows: list[tuple[str, bytes]] = []
                planned = set(existing)
                for group_id, parsed, verification_only in parsed_groups:
                    group_written = 0
                    group_skipped = 0
                    for row_identity, row_line, fingerprint in parsed:
                        if verification_only:
                            group_skipped += 1
                            total_skipped += 1
                            continue
                        if row_identity in planned:
                            group_skipped += 1
                            total_skipped += 1
                            continue
                        if row_line is None:
                            raise StorageError("verification-only payload cannot be appended")
                        append_lines.append(row_line)
                        append_rows.append((row_identity, fingerprint))
                        planned.add(row_identity)
                        group_written += 1
                        total_written += 1
                    group_results.append(
                        {
                            "group_id": group_id,
                            "requested": len(parsed),
                            "written": group_written,
                            "skipped": group_skipped,
                        }
                    )

                final_state = sync.state
                if append_lines:
                    pre_append = _target_stat_for_fd(target_path, fh.fileno())
                    raw_records = [(line + "\n").encode("utf-8") for line in append_lines]
                    index.begin_append()
                    ledger_appended = False
                    try:
                        _append_jsonl_transaction(fh, target_path, append_lines)
                        ledger_appended = True
                        post_append = _target_stat_for_fd(target_path, fh.fileno())
                        final_state = index.stage_append(
                            state=sync.state,
                            ledger_stat=post_append,
                            identity_key=identity_key,
                            rows=append_rows,
                            raw_records=raw_records,
                        )
                    except BaseException:
                        try:
                            index.rollback()
                        except IdentityIndexError as rollback_exc:
                            raise StorageRecoveryError(
                                "identity index rollback failed; ledger state requires inspection"
                            ) from rollback_exc
                        if ledger_appended:
                            try:
                                _rollback_append(
                                    fh.fileno(), target_path, pre_append.st_size
                                )
                            except BaseException as rollback_exc:
                                raise StorageRecoveryError(
                                    "ledger rollback after identity index failure failed"
                                ) from rollback_exc
                        raise
                    try:
                        index.commit()
                    except IdentityIndexCommitUncertain as exc:
                        # The ledger is already durable.  Do not risk making the
                        # index lead the authority by rolling the ledger back.
                        raise StorageRecoveryError(
                            "identity index commit outcome uncertain; ledger may be ahead"
                        ) from exc

                return {
                    "written": total_written,
                    "skipped": total_skipped,
                    "target_scans": 0 if sync.mode == "steady" else 1,
                    "target_records_scanned": sync.records_scanned,
                    "target_identity_index_entries": sync.entry_count,
                    "identity_index_mode": sync.mode,
                    "identity_index_full_rebuild": sync.mode == "rebuild",
                    "identity_index_entries_after": sync.entry_count + len(append_rows),
                    "identity_index_offset": final_state.indexed_offset,
                    "groups": group_results,
                }
        except StorageError:
            raise
        except IdentityIndexError as exc:
            _raise_identity_index_error(exc)


def write_payload_unique(
    domain: str, lines: Iterable[str], *, identity_key: str = "event_id"
) -> tuple[int, int]:
    """Append JSON lines once per payload identity under the domain lock."""
    result = write_payload_unique_groups(
        domain, [("single", lines)], identity_key=identity_key
    )
    groups = result["groups"]
    if (
        not isinstance(groups, list)
        or len(groups) != 1
        or not isinstance(groups[0], dict)
    ):
        raise StorageError("invalid grouped write result")
    return int(groups[0]["written"]), int(groups[0]["skipped"])
