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
from typing import Any, Callable, Iterable, Iterator
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


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_schema() -> dict[str, Any]:
    schema = load_json(SCHEMA_PATH)
    Draft7Validator.check_schema(schema)
    return schema


def validate_event(event: dict[str, Any]) -> None:
    jsonschema.validate(event, load_schema())


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


def _receipt_progress(path: Path, snapshot: OutboxSnapshot) -> ReceiptProgress | None:
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
        or source_bytes > len(snapshot.raw)
        or event_count < 0
    ):
        raise OutboxError(f"{path}: existing receipt does not match the outbox identity")

    prefix = snapshot.raw[:source_bytes]
    if source_bytes > 0 and not prefix.endswith(b"\n"):
        raise OutboxError(f"{path}: receipt ends inside a JSONL record")
    if hashlib.sha256(prefix).hexdigest() != source_sha256:
        raise OutboxError(f"{path}: receipt prefix hash does not match the outbox")
    if len(_parse_events(path, prefix)) != event_count:
        raise OutboxError(f"{path}: receipt event count does not match its prefix")
    return ReceiptProgress(
        source_bytes=source_bytes,
        event_count=event_count,
        source_sha256=source_sha256,
    )


def _receipt_covers_snapshot(progress: ReceiptProgress | None, snapshot: OutboxSnapshot) -> bool:
    return (
        progress is not None
        and progress.source_bytes == len(snapshot.raw)
        and progress.event_count == len(snapshot.events)
        and progress.source_sha256 == snapshot.sha256
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
                snapshot = _snapshot_unlocked(path)
                try:
                    progress = _receipt_progress(path, snapshot)
                except OutboxError:
                    progress = None
        except FileNotFoundError:
            continue
        entries.append(
            OutboxFileStatus(
                path=path,
                events=len(snapshot.events),
                bytes=len(snapshot.raw),
                flushed=_receipt_covers_snapshot(progress, snapshot),
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


def _pending_event_end_offsets(path: Path, raw: bytes, source_bytes: int) -> Iterator[int]:
    cursor = source_bytes
    for raw_line in raw[source_bytes:].splitlines(keepends=True):
        cursor += len(raw_line)
        if not raw_line.strip():
            continue
        if not raw_line.endswith(b"\n"):
            raise OutboxError(f"{path}: pending JSONL record is not newline-terminated")
        yield cursor


def post_json(url: str, payload: list[dict[str, Any]], token: str, timeout: float) -> tuple[int, str]:
    headers = {"Content-Type": "application/json", "X-Auth": token}
    body = _encode_ingest_body(payload)
    with httpx.Client(timeout=timeout) as client:
        response = client.post(url, content=body, headers=headers)
    return response.status_code, response.text


def flush_file(
    path: Path,
    *,
    base_url: str,
    token: str | None = None,
    timeout: float = 5.0,
    max_body_bytes: int | None = None,
    sender: Callable[[str, list[dict[str, Any]], str, float], tuple[int, str]] | None = None,
) -> Path:
    body_limit = _resolve_max_body_bytes(max_body_bytes)
    with outbox_lock(path):
        snapshot = _snapshot_unlocked(path)
        progress = _receipt_progress(path, snapshot)
        if _receipt_covers_snapshot(progress, snapshot):
            return receipt_path(path)
        source_bytes = progress.source_bytes if progress is not None else 0
        source_event_count = progress.event_count if progress is not None else 0

    encoded_sizes: list[int] = []
    for pending_index, event in enumerate(
        snapshot.events[source_event_count:], start=source_event_count + 1
    ):
        encoded_size = len(_encode_json_value(event))
        single_size = encoded_size + 2
        if single_size > body_limit:
            raise OutboxError(
                f"{path}: event {pending_index} requires {single_size} request bytes, "
                f"exceeding max_body_bytes={body_limit}"
            )
        encoded_sizes.append(encoded_size)

    resolved_token = token or token_from_env()
    url = f"{base_url.rstrip('/')}/v1/ingest?{urlencode({'domain': DOMAIN})}"
    send = sender or post_json
    event_index = source_event_count
    chunk: list[dict[str, Any]] = []
    chunk_size = 2
    chunk_end_bytes = source_bytes
    chunk_end_event_count = source_event_count
    sent_any = False

    def send_chunk() -> None:
        nonlocal sent_any
        if not chunk:
            return
        with outbox_lock(path):
            try:
                current_raw = path.read_bytes()
            except OSError as exc:
                raise OutboxError(f"{path}: source cannot be verified before flush") from exc
            if not current_raw.startswith(snapshot.raw):
                raise OutboxError(f"{path}: source changed non-append-only before flush")

        status_code, response_text = send(url, list(chunk), resolved_token, timeout)
        if not 200 <= status_code < 300:
            detail = _bounded_http_error_detail(response_text)
            raise OutboxError(f"flush failed for {path}: HTTP {status_code}: {detail}")

        prefix = snapshot.raw[:chunk_end_bytes]
        chunk_progress = ReceiptProgress(
            source_bytes=chunk_end_bytes,
            event_count=chunk_end_event_count,
            source_sha256=hashlib.sha256(prefix).hexdigest(),
        )
        with outbox_lock(path):
            try:
                current_raw = path.read_bytes()
            except OSError as exc:
                raise OutboxError(
                    f"flush succeeded for {path}, but the source cannot be verified; no receipt written"
                ) from exc
            if not current_raw.startswith(snapshot.raw):
                raise OutboxError(
                    f"flush succeeded for {path}, but the source changed non-append-only; no receipt written"
                )
            _write_receipt_progress(path, chunk_progress, status_code)
        sent_any = True

    end_offsets = _pending_event_end_offsets(path, snapshot.raw, source_bytes)
    for end_offset in end_offsets:
        if event_index >= len(snapshot.events):
            raise OutboxError(f"{path}: pending JSONL records do not match the snapshot")
        event = snapshot.events[event_index]
        encoded_size = encoded_sizes[event_index - source_event_count]
        event_index += 1

        candidate_size = chunk_size + encoded_size + (1 if chunk else 0)
        if chunk and candidate_size > body_limit:
            send_chunk()
            chunk.clear()
            chunk_size = 2

        chunk.append(event)
        chunk_size += encoded_size + (1 if len(chunk) > 1 else 0)
        chunk_end_event_count = event_index
        chunk_end_bytes = len(snapshot.raw) if event_index == len(snapshot.events) else end_offset

    if event_index != len(snapshot.events):
        raise OutboxError(f"{path}: snapshot events do not match pending JSONL records")
    if not chunk and not sent_any:
        raise OutboxError(f"{path} contains no pending events")
    send_chunk()
    return receipt_path(path)


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
            with outbox_lock(path):
                snapshot = _snapshot_unlocked(path)
                progress = _receipt_progress(path, snapshot)
                if _receipt_covers_snapshot(progress, snapshot):
                    continue
        except FileNotFoundError:
            continue
        receipts.append(
            flush_file(
                path,
                base_url=base_url,
                token=token,
                timeout=timeout,
                max_body_bytes=max_body_bytes,
                sender=sender,
            )
        )
    return receipts


def compact(state_root: Path = DEFAULT_STATE_ROOT) -> list[Path]:
    removed: list[Path] = []
    for path in iter_outbox_files(state_root):
        try:
            with outbox_lock(path):
                snapshot = _snapshot_unlocked(path)
                try:
                    progress = _receipt_progress(path, snapshot)
                except OutboxError:
                    continue
                if not _receipt_covers_snapshot(progress, snapshot):
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
