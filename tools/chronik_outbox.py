"""Outbox helper for Chronik agent-run events.

This module is producer-agnostic. It validates and stores local
``agent-run-event.v0`` payloads, can flush them to Chronik, and can compact
files that already have successful flush receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, BinaryIO, Callable, Iterable, Iterator
from urllib.parse import urlencode

import httpx
import jsonschema
from filelock import FileLock, Timeout
from jsonschema import Draft7Validator

DOMAIN = "agent.ledger"
DEFAULT_STATE_ROOT = Path(".local/state")
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "chronik" / "agent-run-event-v0.schema.json"
SAFE_PART = re.compile(r"[^A-Za-z0-9_.-]+")
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
OUTBOX_LOCK_TIMEOUT = 10.0
RECEIPT_VERSION = 1
HTTP_ERROR_DETAIL_MAX_BYTES = 1024
DEFAULT_MAX_BODY_BYTES = 1024 * 1024
HASH_READ_BYTES = 64 * 1024


class OutboxError(RuntimeError):
    """Raised for expected outbox failures."""


@dataclass(frozen=True)
class OutboxFileStatus:
    path: Path
    events: int
    bytes: int
    flushed: bool


@dataclass(frozen=True)
class OutboxSnapshot:
    raw: bytes
    events: tuple[dict[str, Any], ...]
    sha256: str


@dataclass(frozen=True)
class ReceiptProgress:
    source_bytes: int
    event_count: int
    source_sha256: str


@dataclass(frozen=True)
class _FileState:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class _FlushSnapshot:
    source_bytes: int
    event_count: int
    sha256: str
    progress: ReceiptProgress | None
    progress_hasher: Any
    progress_line_count: int
    file_state: _FileState


@dataclass(frozen=True)
class _OutboxScan:
    source_bytes: int
    event_count: int
    sha256: str
    progress: ReceiptProgress | None


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_schema() -> dict[str, Any]:
    schema = load_json(SCHEMA_PATH)
    Draft7Validator.check_schema(schema)
    return schema


_EVENT_VALIDATOR: Draft7Validator | None = None
_EVENT_VALIDATOR_LOCK = Lock()


def _event_validator() -> Draft7Validator:
    """Compile the immutable agent-run schema exactly once per process."""
    global _EVENT_VALIDATOR
    validator = _EVENT_VALIDATOR
    if validator is not None:
        return validator
    with _EVENT_VALIDATOR_LOCK:
        validator = _EVENT_VALIDATOR
        if validator is None:
            validator = Draft7Validator(load_schema())
            _EVENT_VALIDATOR = validator
        return validator


def validate_event(event: dict[str, Any]) -> None:
    _event_validator().validate(event)


def safe_part(value: str, label: str) -> str:
    cleaned = SAFE_PART.sub("_", value.strip()).strip("._-")
    if not cleaned:
        raise OutboxError(f"{label} is empty after sanitization")
    return cleaned[:160]


def _json_single_line(value: object) -> str:
    """Render untrusted text without literal line or separator controls."""
    text = str(value).encode("utf-8", errors="backslashreplace").decode("utf-8")
    rendered = json.dumps(text, ensure_ascii=False)[1:-1]
    safe: list[str] = []
    for char in rendered:
        codepoint = ord(char)
        if 0x7F <= codepoint <= 0x9F or codepoint in {0x2028, 0x2029}:
            safe.append(f"\\u{codepoint:04x}")
        else:
            safe.append(char)
    return "".join(safe)


def _bounded_http_error_detail(value: object) -> str:
    """Return one escaped diagnostic within the HTTP error byte budget."""
    limit = HTTP_ERROR_DETAIL_MAX_BYTES
    text = str(value)
    rendered = _json_single_line(text)
    if len(rendered.encode("utf-8")) <= limit:
        return rendered

    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        candidate = _json_single_line(text[:middle] + "…")
        if len(candidate.encode("utf-8")) <= limit:
            low = middle
        else:
            high = middle - 1
    return _json_single_line(text[:low] + "…")


def producer_and_run_id(event: dict[str, Any]) -> tuple[str, str]:
    try:
        source = event["source"]
        component = source["component"]
        run_id = source["run_id"]
    except (KeyError, TypeError) as exc:
        raise OutboxError("event.source.component and event.source.run_id are required") from exc
    return safe_part(str(component), "producer"), safe_part(str(run_id), "run_id")


def outbox_path(event: dict[str, Any], state_root: Path = DEFAULT_STATE_ROOT) -> Path:
    producer, run_id = producer_and_run_id(event)
    return state_root / producer / "chronik-outbox" / f"{producer}_{run_id}.jsonl"


def receipt_path(path: Path) -> Path:
    return path.parent / ".flushed" / f"{path.name}.receipt.json"


def lock_path(path: Path) -> Path:
    return path.parent / ".locks" / f"{path.name}.lock"


def canonical_source_path(path: Path) -> str:
    return str(path.resolve())


@contextmanager
def outbox_lock(path: Path) -> Iterator[None]:
    lock = lock_path(path)
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        with FileLock(str(lock), timeout=OUTBOX_LOCK_TIMEOUT):
            yield
    except Timeout as exc:
        raise OutboxError(f"timed out waiting for outbox lock: {path}") from exc


def _parse_events(path: Path, raw: bytes) -> tuple[dict[str, Any], ...]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OutboxError(f"{path}: invalid utf-8") from exc

    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise OutboxError(f"{path}:{line_number}: invalid jsonl") from exc
        validate_event(event)
        events.append(event)
    return tuple(events)


def _snapshot_unlocked(path: Path) -> OutboxSnapshot:
    raw = path.read_bytes()
    return OutboxSnapshot(
        raw=raw,
        events=_parse_events(path, raw),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _load_receipt(path: Path) -> tuple[bool, dict[str, Any] | None]:
    receipt = receipt_path(path)
    try:
        value = load_json(receipt)
    except FileNotFoundError:
        return False, None
    except (OSError, TypeError, ValueError):
        return True, None
    return True, value if isinstance(value, dict) else None


def _receipt_header(path: Path, source_size: int) -> ReceiptProgress | None:
    exists, receipt = _load_receipt(path)
    if not exists:
        return None
    if receipt is None or receipt.get("receipt_version") != RECEIPT_VERSION:
        raise OutboxError(f"{path}: existing receipt is not snapshot-bound")

    source_bytes = receipt.get("source_bytes")
    event_count = receipt.get("event_count")
    source_sha256 = receipt.get("source_sha256")
    valid_scalars = (
        isinstance(source_bytes, int)
        and not isinstance(source_bytes, bool)
        and isinstance(event_count, int)
        and not isinstance(event_count, bool)
        and isinstance(source_sha256, str)
        and SHA256_HEX.fullmatch(source_sha256) is not None
    )
    if not valid_scalars:
        raise OutboxError(f"{path}: existing receipt has invalid snapshot fields")
    if (
        receipt.get("domain") != DOMAIN
        or receipt.get("source_path") != canonical_source_path(path)
        or source_bytes < 0
        or source_bytes > source_size
        or event_count < 0
    ):
        raise OutboxError(f"{path}: existing receipt does not match the outbox identity")

    return ReceiptProgress(
        source_bytes=source_bytes,
        event_count=event_count,
        source_sha256=source_sha256,
    )


def _fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _write_receipt_progress(path: Path, progress: ReceiptProgress, status_code: int) -> Path:
    receipt = receipt_path(path)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(
            {
                "receipt_version": RECEIPT_VERSION,
                "domain": DOMAIN,
                "source_path": canonical_source_path(path),
                "source_bytes": progress.source_bytes,
                "source_sha256": progress.source_sha256,
                "event_count": progress.event_count,
                "flushed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "status_code": status_code,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    temporary = receipt.with_name(f".{receipt.name}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, receipt)
        _fsync_directory(receipt.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return receipt


def append_event(event: dict[str, Any], state_root: Path = DEFAULT_STATE_ROOT) -> Path:
    validate_event(event)
    path = outbox_path(event, state_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )
    with outbox_lock(path):
        with path.open("ab") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    return path


def iter_outbox_files(state_root: Path = DEFAULT_STATE_ROOT) -> Iterable[Path]:
    yield from sorted(state_root.glob("*/chronik-outbox/*.jsonl"))


def read_events(path: Path) -> list[dict[str, Any]]:
    with outbox_lock(path):
        return list(_snapshot_unlocked(path).events)


def status(state_root: Path = DEFAULT_STATE_ROOT) -> list[OutboxFileStatus]:
    entries: list[OutboxFileStatus] = []
    for path in iter_outbox_files(state_root):
        try:
            with outbox_lock(path):
                scan = _scan_outbox_unlocked(path)
        except FileNotFoundError:
            continue
        entries.append(
            OutboxFileStatus(
                path=path,
                events=scan.event_count,
                bytes=scan.source_bytes,
                flushed=_receipt_covers_scan(scan),
            )
        )
    return entries


def token_from_env() -> str:
    token_blob = os.environ.get("CHRONIK_TOKEN", "")
    tokens = [token.strip() for token in re.split(r"[,\n]+", token_blob) if token.strip()]
    if not tokens:
        raise OutboxError("CHRONIK_TOKEN is required for flush")
    return tokens[0]


def _resolve_max_body_bytes(value: int | None) -> int:
    if value is None:
        raw_value = os.environ.get("CHRONIK_MAX_BODY")
        if raw_value in {None, ""}:
            value = DEFAULT_MAX_BODY_BYTES
        else:
            try:
                value = int(raw_value)
            except ValueError as exc:
                raise OutboxError("CHRONIK_MAX_BODY must be an integer") from exc
    if not isinstance(value, int) or isinstance(value, bool) or value < 2:
        raise OutboxError("max_body_bytes must be an integer of at least 2 bytes")
    return value


def _encode_json_value(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _encode_ingest_body(payload: list[dict[str, Any]]) -> bytes:
    return b"[" + b",".join(_encode_json_value(event) for event in payload) + b"]"


def _file_state(value: os.stat_result) -> _FileState:
    return _FileState(
        device=value.st_dev,
        inode=value.st_ino,
        size=value.st_size,
        mtime_ns=value.st_mtime_ns,
        ctime_ns=value.st_ctime_ns,
    )


def _bounded_lines(path: Path, handle: BinaryIO, byte_count: int) -> Iterator[bytes]:
    remaining = byte_count
    while remaining:
        raw_line = handle.readline(remaining)
        if not raw_line:
            raise OutboxError(f"{path}: source became shorter while it was being read")
        remaining -= len(raw_line)
        yield raw_line


def _parse_jsonl_line(path: Path, line_number: int, raw_line: bytes) -> Any | None:
    try:
        line = raw_line.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OutboxError(f"{path}: invalid utf-8") from exc
    if not line.strip():
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError as exc:
        raise OutboxError(f"{path}:{line_number}: invalid jsonl") from exc


def _scan_outbox_unlocked(path: Path) -> _OutboxScan:
    """Validate one fixed outbox extent without retaining its bytes or events."""
    try:
        handle = path.open("rb")
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise OutboxError(f"{path}: source cannot be read") from exc

    with handle:
        initial_state = _file_state(os.fstat(handle.fileno()))
        try:
            progress = _receipt_header(path, initial_state.size)
        except OutboxError:
            progress = None

        validator = _event_validator()
        source_hasher = hashlib.sha256()
        cursor = 0
        event_count = 0
        line_number = 0
        progress_verified = progress is None

        if progress is not None and progress.source_bytes == 0:
            if progress.source_sha256 == source_hasher.hexdigest() and progress.event_count == 0:
                progress_verified = True
            else:
                progress = None
                progress_verified = True

        for raw_line in _bounded_lines(path, handle, initial_state.size):
            line_start = cursor
            cursor += len(raw_line)
            line_number += 1
            source_hasher.update(raw_line)

            if (
                progress is not None
                and not progress_verified
                and line_start < progress.source_bytes < cursor
            ):
                progress = None
                progress_verified = True

            event = _parse_jsonl_line(path, line_number, raw_line)
            if event is not None:
                validator.validate(event)
                event_count += 1

            if progress is not None and not progress_verified and cursor == progress.source_bytes:
                if (
                    (progress.source_bytes > 0 and not raw_line.endswith(b"\n"))
                    or source_hasher.hexdigest() != progress.source_sha256
                    or event_count != progress.event_count
                ):
                    progress = None
                progress_verified = True

        final_state = _file_state(os.fstat(handle.fileno()))
        try:
            path_state = _file_state(path.stat())
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise OutboxError(f"{path}: source cannot be verified after scan") from exc
        if final_state != initial_state or path_state != initial_state:
            raise OutboxError(f"{path}: source changed while it was being scanned")

    if progress is not None and not progress_verified:
        progress = None

    return _OutboxScan(
        source_bytes=initial_state.size,
        event_count=event_count,
        sha256=source_hasher.hexdigest(),
        progress=progress,
    )


def _receipt_covers_scan(scan: _OutboxScan) -> bool:
    progress = scan.progress
    return (
        progress is not None
        and progress.source_bytes == scan.source_bytes
        and progress.event_count == scan.event_count
        and progress.source_sha256 == scan.sha256
    )


def _preflight_flush_unlocked(path: Path, body_limit: int) -> _FlushSnapshot:
    """Validate one fixed file extent without retaining its events or bytes."""
    try:
        handle = path.open("rb")
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise OutboxError(f"{path}: source cannot be read for flush") from exc

    with handle:
        initial_state = _file_state(os.fstat(handle.fileno()))
        progress = _receipt_header(path, initial_state.size)
        progress_bytes = progress.source_bytes if progress is not None else 0
        progress_events = progress.event_count if progress is not None else 0
        validator = _event_validator()
        source_hasher = hashlib.sha256()
        progress_hasher = source_hasher.copy() if progress_bytes == 0 else None
        progress_line_count = 0
        cursor = 0
        event_count = 0
        pending_event_count = 0
        line_number = 0

        if progress is not None and progress_bytes == 0:
            if source_hasher.hexdigest() != progress.source_sha256:
                raise OutboxError(f"{path}: receipt prefix hash does not match the outbox")
            if progress_events != 0:
                raise OutboxError(f"{path}: receipt event count does not match its prefix")

        for raw_line in _bounded_lines(path, handle, initial_state.size):
            line_start = cursor
            cursor += len(raw_line)
            line_number += 1
            source_hasher.update(raw_line)

            if line_start < progress_bytes < cursor:
                raise OutboxError(f"{path}: receipt ends inside a JSONL record")

            event = _parse_jsonl_line(path, line_number, raw_line)
            if event is not None:
                is_pending = line_start >= progress_bytes
                if is_pending and not raw_line.endswith(b"\n"):
                    raise OutboxError(f"{path}: pending JSONL record is not newline-terminated")
                validator.validate(event)
                event_count += 1
                if is_pending:
                    pending_event_count += 1
                    encoded_size = len(_encode_json_value(event))
                    single_size = encoded_size + 2
                    if single_size > body_limit:
                        raise OutboxError(
                            f"{path}: event {event_count} requires {single_size} request bytes, "
                            f"exceeding max_body_bytes={body_limit}"
                        )

            if progress is not None and cursor == progress_bytes:
                if progress_bytes > 0 and not raw_line.endswith(b"\n"):
                    raise OutboxError(f"{path}: receipt ends inside a JSONL record")
                if source_hasher.hexdigest() != progress.source_sha256:
                    raise OutboxError(f"{path}: receipt prefix hash does not match the outbox")
                if event_count != progress_events:
                    raise OutboxError(f"{path}: receipt event count does not match its prefix")
                progress_hasher = source_hasher.copy()
                progress_line_count = line_number

        final_state = _file_state(os.fstat(handle.fileno()))
        try:
            path_state = _file_state(path.stat())
        except OSError as exc:
            raise OutboxError(f"{path}: source cannot be verified after preflight") from exc
        if final_state != initial_state or path_state != initial_state:
            raise OutboxError(f"{path}: source changed while it was being preflighted")

    if progress_hasher is None:
        raise OutboxError(f"{path}: receipt ends inside a JSONL record")

    source_sha256 = source_hasher.hexdigest()
    covered = (
        progress is not None
        and progress.source_bytes == initial_state.size
        and progress.event_count == event_count
        and progress.source_sha256 == source_sha256
    )
    if not covered and pending_event_count == 0:
        raise OutboxError(f"{path} contains no pending events")

    return _FlushSnapshot(
        source_bytes=initial_state.size,
        event_count=event_count,
        sha256=source_sha256,
        progress=progress,
        progress_hasher=progress_hasher,
        progress_line_count=progress_line_count,
        file_state=initial_state,
    )


def _verify_flush_snapshot_unlocked(
    path: Path,
    snapshot: _FlushSnapshot,
    known_state: _FileState,
) -> _FileState | None:
    """Return a stable state iff the fixed snapshot remains a file prefix."""
    current_state = _file_state(path.stat())
    if current_state == known_state:
        return current_state
    if current_state.size < snapshot.source_bytes:
        return None

    with path.open("rb") as handle:
        opened_state = _file_state(os.fstat(handle.fileno()))
        if opened_state != current_state:
            return None
        source_hasher = hashlib.sha256()
        remaining = snapshot.source_bytes
        while remaining:
            block = handle.read(min(remaining, HASH_READ_BYTES))
            if not block:
                return None
            source_hasher.update(block)
            remaining -= len(block)
        final_state = _file_state(os.fstat(handle.fileno()))

    if final_state != opened_state or _file_state(path.stat()) != final_state:
        return None
    if source_hasher.hexdigest() != snapshot.sha256:
        return None
    return final_state


def post_json(url: str, payload: list[dict[str, Any]], token: str, timeout: float) -> tuple[int, str]:
    headers = {"Content-Type": "application/json", "X-Auth": token}
    body = _encode_ingest_body(payload)
    with httpx.Client(timeout=timeout) as client:
        response = client.post(url, content=body, headers=headers)
    return response.status_code, response.text


def _flush_file(
    path: Path,
    *,
    base_url: str,
    token: str | None = None,
    timeout: float = 5.0,
    max_body_bytes: int | None = None,
    sender: Callable[[str, list[dict[str, Any]], str, float], tuple[int, str]] | None = None,
) -> tuple[Path, bool]:
    body_limit = _resolve_max_body_bytes(max_body_bytes)
    with outbox_lock(path):
        snapshot = _preflight_flush_unlocked(path, body_limit)
        progress = snapshot.progress
        if (
            progress is not None
            and progress.source_bytes == snapshot.source_bytes
            and progress.event_count == snapshot.event_count
            and progress.source_sha256 == snapshot.sha256
        ):
            return receipt_path(path), False

    resolved_token = token or token_from_env()
    url = f"{base_url.rstrip('/')}/v1/ingest?{urlencode({'domain': DOMAIN})}"
    send = sender or post_json
    source_bytes = progress.source_bytes if progress is not None else 0
    source_event_count = progress.event_count if progress is not None else 0
    source_line_count = snapshot.progress_line_count
    source_hasher = snapshot.progress_hasher.copy()
    event_index = source_event_count
    chunk: list[dict[str, Any]] = []
    chunk_size = 2
    chunk_end_bytes = source_bytes
    chunk_end_event_count = source_event_count
    chunk_end_sha256 = source_hasher.hexdigest()
    sent_any = False
    known_state = snapshot.file_state

    def send_chunk() -> None:
        nonlocal known_state, sent_any
        if not chunk:
            return
        with outbox_lock(path):
            try:
                verified_state = _verify_flush_snapshot_unlocked(path, snapshot, known_state)
            except OSError as exc:
                raise OutboxError(f"{path}: source cannot be verified before flush") from exc
            if verified_state is None:
                raise OutboxError(f"{path}: source changed non-append-only before flush")
            known_state = verified_state

        status_code, response_text = send(url, list(chunk), resolved_token, timeout)
        if not 200 <= status_code < 300:
            detail = _bounded_http_error_detail(response_text)
            raise OutboxError(f"flush failed for {path}: HTTP {status_code}: {detail}")

        chunk_progress = ReceiptProgress(
            source_bytes=chunk_end_bytes,
            event_count=chunk_end_event_count,
            source_sha256=chunk_end_sha256,
        )
        with outbox_lock(path):
            try:
                verified_state = _verify_flush_snapshot_unlocked(path, snapshot, known_state)
            except OSError as exc:
                raise OutboxError(
                    f"flush succeeded for {path}, but the source cannot be verified; no receipt written"
                ) from exc
            if verified_state is None:
                raise OutboxError(
                    f"flush succeeded for {path}, but the source changed non-append-only; no receipt written"
                )
            known_state = verified_state
            _write_receipt_progress(path, chunk_progress, status_code)
        sent_any = True

    with outbox_lock(path):
        try:
            verified_state = _verify_flush_snapshot_unlocked(path, snapshot, known_state)
        except OSError as exc:
            raise OutboxError(f"{path}: source cannot be verified before flush") from exc
        if verified_state is None:
            raise OutboxError(f"{path}: source changed non-append-only before flush")
        known_state = verified_state
        try:
            source_handle = path.open("rb")
        except OSError as exc:
            raise OutboxError(f"{path}: source cannot be read for flush") from exc
        if _file_state(os.fstat(source_handle.fileno())) != known_state:
            source_handle.close()
            raise OutboxError(f"{path}: source changed non-append-only before flush")
        source_handle.seek(source_bytes)

    cursor = source_bytes
    line_number = source_line_count
    with source_handle:
        for raw_line in _bounded_lines(path, source_handle, snapshot.source_bytes - source_bytes):
            cursor += len(raw_line)
            line_number += 1
            source_hasher.update(raw_line)
            event = _parse_jsonl_line(path, line_number, raw_line)
            if event is None:
                continue
            if not raw_line.endswith(b"\n"):
                raise OutboxError(f"{path}: pending JSONL record is not newline-terminated")

            encoded_size = len(_encode_json_value(event))
            single_size = encoded_size + 2
            if single_size > body_limit:
                raise OutboxError(
                    f"{path}: event {event_index + 1} requires {single_size} request bytes, "
                    f"exceeding max_body_bytes={body_limit}"
                )
            candidate_size = chunk_size + encoded_size + (1 if chunk else 0)
            if chunk and candidate_size > body_limit:
                send_chunk()
                chunk = []
                chunk_size = 2

            chunk.append(event)
            chunk_size += encoded_size + (1 if len(chunk) > 1 else 0)
            event_index += 1
            chunk_end_event_count = event_index
            if event_index == snapshot.event_count:
                chunk_end_bytes = snapshot.source_bytes
                chunk_end_sha256 = snapshot.sha256
            else:
                chunk_end_bytes = cursor
                chunk_end_sha256 = source_hasher.hexdigest()

    if event_index != snapshot.event_count or source_hasher.hexdigest() != snapshot.sha256:
        raise OutboxError(f"{path}: snapshot events do not match pending JSONL records")
    if not chunk and not sent_any:
        raise OutboxError(f"{path} contains no pending events")
    send_chunk()
    return receipt_path(path), True


def flush_file(
    path: Path,
    *,
    base_url: str,
    token: str | None = None,
    timeout: float = 5.0,
    max_body_bytes: int | None = None,
    sender: Callable[[str, list[dict[str, Any]], str, float], tuple[int, str]] | None = None,
) -> Path:
    receipt, _ = _flush_file(
        path,
        base_url=base_url,
        token=token,
        timeout=timeout,
        max_body_bytes=max_body_bytes,
        sender=sender,
    )
    return receipt


def flush_all(
    *,
    state_root: Path = DEFAULT_STATE_ROOT,
    base_url: str,
    token: str | None = None,
    timeout: float = 5.0,
    max_body_bytes: int | None = None,
    sender: Callable[[str, list[dict[str, Any]], str, float], tuple[int, str]] | None = None,
) -> list[Path]:
    receipts: list[Path] = []
    for path in iter_outbox_files(state_root):
        try:
            receipt, flushed = _flush_file(
                path,
                base_url=base_url,
                token=token,
                timeout=timeout,
                max_body_bytes=max_body_bytes,
                sender=sender,
            )
        except FileNotFoundError:
            continue
        if flushed:
            receipts.append(receipt)
    return receipts


def compact(state_root: Path = DEFAULT_STATE_ROOT) -> list[Path]:
    removed: list[Path] = []
    for path in iter_outbox_files(state_root):
        try:
            with outbox_lock(path):
                scan = _scan_outbox_unlocked(path)
                if not _receipt_covers_scan(scan):
                    continue
                path.unlink()
                _fsync_directory(path.parent)
        except FileNotFoundError:
            continue
        removed.append(path)
    return removed


def preview(state_root: Path = DEFAULT_STATE_ROOT) -> dict[str, Any]:
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from tools import agent_ledger_view

    files = [entry for entry in status(state_root) if not entry.flushed]
    events: list[dict[str, Any]] = []
    for entry in files:
        events.extend(read_events(entry.path))

    repo_rows = agent_ledger_view.build_view(events)
    run_rows = agent_ledger_view.build_run_view(events)
    return {
        "domain": DOMAIN,
        "state_root": str(state_root),
        "mutates_remote": False,
        "event_count": len(events),
        "files": [
            {
                "path": str(entry.path),
                "events": entry.events,
                "bytes": entry.bytes,
                "flushed": entry.flushed,
            }
            for entry in files
        ],
        "repo_view": [row.__dict__ for row in repo_rows],
        "run_view": [row.__dict__ for row in run_rows],
    }


def print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Chronik agent ledger outbox v0")
    parser.add_argument("--state-root", default=str(DEFAULT_STATE_ROOT))
    subparsers = parser.add_subparsers(dest="command", required=True)

    append_parser = subparsers.add_parser("append")
    append_parser.add_argument("event_file")

    subparsers.add_parser("status")
    subparsers.add_parser("preview")

    flush_parser = subparsers.add_parser("flush")
    flush_parser.add_argument("--base-url", default=os.environ.get("CHRONIK_URL", "http://localhost:8788"))
    flush_parser.add_argument("--timeout", type=float, default=5.0)
    flush_parser.add_argument("--max-body-bytes", type=int, default=None)

    subparsers.add_parser("compact")

    args = parser.parse_args(argv)
    state_root = Path(args.state_root)

    try:
        if args.command == "append":
            path = append_event(load_json(Path(args.event_file)), state_root)
            print_json({"appended": str(path)})
        elif args.command == "status":
            print_json({"files": [entry.__dict__ for entry in status(state_root)]})
        elif args.command == "preview":
            print_json(preview(state_root))
        elif args.command == "flush":
            receipts = flush_all(
                state_root=state_root,
                base_url=args.base_url,
                timeout=args.timeout,
                max_body_bytes=args.max_body_bytes,
            )
            print_json({"receipts": [str(receipt) for receipt in receipts]})
        elif args.command == "compact":
            removed = compact(state_root)
            print_json({"removed": [str(path) for path in removed]})
    except (OutboxError, jsonschema.exceptions.ValidationError) as exc:
        print(f"chronik-outbox: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
