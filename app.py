from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import secrets
import time
import uuid
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from filelock import FileLock, Timeout
from prometheus_fastapi_instrumentator import Instrumentator
from starlette.concurrency import run_in_threadpool
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from storage import (
    DATA_DIR,
    DomainError,
    FILENAME_RE,
    safe_target_path,
    sanitize_domain,
    target_filename,
)

# --- Runtime constants & logging ---
MAX_PAYLOAD_SIZE: Final[int] = int(
    os.getenv("CHRONIK_MAX_BODY") or str(1024 * 1024)
)
LOCK_TIMEOUT: Final[int] = int(os.getenv("CHRONIK_LOCK_TIMEOUT") or "30")
RATE_LIMIT: Final[str] = os.getenv("CHRONIK_RATE_LIMIT") or "60/minute"

LOG_LEVEL = (
    os.getenv("CHRONIK_LOG_LEVEL") or os.getenv("LOG_LEVEL", "INFO")
).upper()

_debug_val = (os.getenv("CHRONIK_DEBUG") or "").lower()
DEBUG_MODE: Final[bool] = _debug_val in {
    "1",
    "true",
    "yes",
    "on",
}
logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger("chronik")

class ExtraFormatter(logging.Formatter):
    """Formatter that adds 'extra' fields to the log message."""

    def format(self, record):
        s = super().format(record)
        if hasattr(record, "request_id"):
            extras = [
                f'{k}="{v}"'
                for k, v in record.__dict__.items()
                if k
                in {
                    "request_id",
                    "method",
                    "path",
                    "status",
                    "duration_ms",
                    "domain",
                    "file",
                }
            ]
            if extras:
                s = f"{s} {' '.join(extras)}"
        return s


# Re-configure root logger with our custom formatter
_handler = logging.StreamHandler()
_handler.setFormatter(ExtraFormatter(fmt="%(levelname)s:%(name)s:%(message)s"))
logging.getLogger().handlers = [_handler]
logging.getLogger().setLevel(LOG_LEVEL)

app = FastAPI(title="chronik-ingest", debug=DEBUG_MODE)

DATA: Final = DATA_DIR

VERSION: Final[str] = os.environ.get("CHRONIK_VERSION") or "dev"

SECRET_ENV = os.environ.get("CHRONIK_TOKEN")
if not SECRET_ENV:
    raise RuntimeError(
        "CHRONIK_TOKEN not set. Auth is required for all requests."
    )

SECRET: Final[str] = SECRET_ENV


@app.middleware("http")
async def request_id_logging(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    start = time.time()
    # Falls im Handler ein Fehler hochgeht, loggen wir konservativ 500
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        dur_ms = int((time.time() - start) * 1000)
        logger.info(
            "access",
            extra={
                "request_id": rid,
                "method": request.method,
                "path": request.url.path,
                "status": status,
                "duration_ms": dur_ms,
            },
        )


limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.exception_handler(RateLimitExceeded)
async def _on_rate_limited(request: Request, exc: RateLimitExceeded):
    return PlainTextResponse("too many requests", status_code=429)


Instrumentator().instrument(app).expose(app, endpoint="/metrics")


def _sanitize_domain(domain: str) -> str:
    try:
        return sanitize_domain(domain)
    except DomainError as exc:
        raise HTTPException(status_code=400, detail="invalid domain") from exc


def _safe_target_path(domain: str) -> Path:
    # Always sanitize and validate domain before use
    dom = _sanitize_domain(domain)
    try:
        return safe_target_path(dom, data_dir=DATA)
    except DomainError as exc:
        raise HTTPException(status_code=400, detail="invalid domain") from exc


def _require_auth(x_auth: str) -> None:
    if not x_auth or not secrets.compare_digest(x_auth, SECRET):
        raise HTTPException(status_code=401, detail="unauthorized")


def _require_auth_dep(x_auth: str = Header(default="")) -> None:
    """
    FastAPI dependency that enforces authentication.
    Using a dedicated dep allows us to control execution order at the route decorator.
    """
    _require_auth(x_auth)


def _validate_body_size(req: Request) -> None:
    """
    Validate Content-Length before reading the body. Limited by MAX_PAYLOAD_SIZE.
    Must run *after* auth to avoid leaking details to unauthenticated callers.
    """
    cl_raw = req.headers.get("content-length")
    if cl_raw:
        try:
            cl = int(cl_raw)
        except (ValueError, TypeError):  # defensive
            raise HTTPException(status_code=400, detail="invalid content-length")
        if cl < 0:
            raise HTTPException(status_code=400, detail="invalid content-length")
        if cl > MAX_PAYLOAD_SIZE:
            raise HTTPException(status_code=413, detail="payload too large")
        return

    # No content-length. Check transfer-encoding.
    te = req.headers.get("transfer-encoding", "").lower()
    if "chunked" in te:
        return  # Body size will be checked during read

    raise HTTPException(status_code=411, detail="length required")


async def _read_body_with_limit(request: Request, limit: int) -> bytes:
    """
    Reads the request body, respecting the limit.
    Raises HTTPException(413) if limit is exceeded.
    """
    data = bytearray()
    # Starlette's request.stream() yields chunks
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > limit:
            raise HTTPException(status_code=413, detail="payload too large")
    return bytes(data)


def _process_items(items: list[Any], dom: str) -> list[str]:
    lines: list[str] = []
    # Leeres Array: nichts zu tun
    if not items:
        logger.warning("empty payload array received", extra={"domain": dom})
        return lines

    # Normalisieren & validieren
    for entry in items:
        if not isinstance(entry, dict):
            raise HTTPException(status_code=400, detail="invalid payload")

        normalized = dict(entry)

        summary_val = normalized.get("summary")
        if isinstance(summary_val, str) and len(summary_val) > 500:
            raise HTTPException(status_code=422, detail="summary too long (max 500)")

        if "domain" in normalized:
            entry_domain = normalized["domain"]
            if not isinstance(entry_domain, str):
                raise HTTPException(status_code=400, detail="invalid payload")

            try:
                sanitized_entry_domain = sanitize_domain(entry_domain)
            except DomainError as exc:
                raise HTTPException(status_code=400, detail="invalid payload") from exc
            if sanitized_entry_domain != dom:
                raise HTTPException(status_code=400, detail="domain mismatch")

        normalized["domain"] = dom
        lines.append(json.dumps(normalized, ensure_ascii=False, separators=(",", ":")))
    return lines


def _write_lines_to_storage(dom: str, lines: list[str]) -> None:
    # Nothing to write - return early to avoid creating empty file
    if not lines:
        return
    target_path = _safe_target_path(dom)
    fname = target_path.name

    # Ensure fname is exactly as expected for sanitized domain
    if fname != target_filename(dom):
        raise HTTPException(status_code=400, detail="invalid target")
    if os.path.basename(fname) != fname or ".." in fname:
        raise HTTPException(status_code=400, detail="invalid target")
    if FILENAME_RE is None or not FILENAME_RE.fullmatch(fname):
        raise HTTPException(status_code=400, detail="invalid target")
    # Extra defense-in-depth: ensure resolved parent is the trusted data dir
    if target_path.parent != DATA:
        raise HTTPException(
            status_code=400, detail="invalid target path: wrong parent directory"
        )

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
            dirfd = os.open(str(DATA), os.O_RDONLY)
            try:
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_APPEND
                    | getattr(os, "O_CLOEXEC", 0)
                )
                if not hasattr(os, "O_NOFOLLOW"):
                    raise HTTPException(
                        status_code=500, detail="platform lacks O_NOFOLLOW"
                    )
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
                        raise HTTPException(
                            status_code=507, detail="insufficient storage"
                        ) from exc
                    if exc.errno == errno.ELOOP:
                        logger.warning(
                            "symlink attempt rejected",
                            extra={"file": str(target_path)},
                        )
                        raise HTTPException(
                            status_code=400, detail="invalid target"
                        ) from exc
                    raise
                finally:
                    if fd is not None:
                        os.close(fd)
            finally:
                os.close(dirfd)
    except Timeout as exc:
        logger.warning("busy (lock timeout)", extra={"file": str(target_path)})
        raise HTTPException(status_code=429, detail="busy, try again") from exc


@app.post(
    "/v1/ingest",
    # Dependency order matters: auth FIRST, then size check.
    dependencies=[Depends(_require_auth_dep), Depends(_validate_body_size)],
    status_code=202,
)
@limiter.limit(RATE_LIMIT)
async def ingest_v1(
    request: Request,
    domain: str | None = None,
):
    # Determine domain from query param or payload
    if domain:
        dom = _sanitize_domain(domain)
    else:
        dom = None

    content_type = request.headers.get("content-type", "").lower()

    try:
        raw = await _read_body_with_limit(request, MAX_PAYLOAD_SIZE)
        body = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid encoding") from exc

    items = []
    if "application/json" in content_type:
        try:
            obj = json.loads(body)
            items = obj if isinstance(obj, list) else [obj]
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="invalid json") from exc
    elif "application/x-ndjson" in content_type:
        lines = body.strip().split("\n")
        for line in lines:
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=400, detail="invalid ndjson") from exc
    else:
        raise HTTPException(status_code=415, detail="unsupported content-type")

    if not items:
        logger.warning("empty payload received")
        return PlainTextResponse("ok", status_code=202)

    # If domain was not in query, try to get it from the first item.
    if not dom:
        first_item = items[0]
        if not isinstance(first_item, dict):
            raise HTTPException(status_code=400, detail="invalid payload")

        first_item_domain = first_item.get("domain")
        if not first_item_domain or not isinstance(first_item_domain, str):
            raise HTTPException(
                status_code=400,
                detail="domain must be specified via query or payload",
            )
        dom = _sanitize_domain(first_item_domain)

    lines_to_write = _process_items(items, dom)
    await run_in_threadpool(_write_lines_to_storage, dom, lines_to_write)
    return PlainTextResponse("ok", status_code=202)


@app.post(
    "/ingest/{domain}",
    # Dependency order matters: auth FIRST, then size check.
    dependencies=[Depends(_require_auth_dep), Depends(_validate_body_size)],
    deprecated=True,
)
@limiter.limit(RATE_LIMIT)
async def ingest(
    domain: str,
    request: Request,
):
    dom = _sanitize_domain(domain)

    # JSON parsen
    try:
        raw = await _read_body_with_limit(request, MAX_PAYLOAD_SIZE)
        obj = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid json") from exc

    # Objekt oder Array → JSONL: eine kompakte Zeile pro Eintrag
    items = obj if isinstance(obj, list) else [obj]
    lines = _process_items(items, dom)
    await run_in_threadpool(_write_lines_to_storage, dom, lines)

    return PlainTextResponse("ok", status_code=202)


@app.get("/health")
async def health(x_auth: str = Header(default="")) -> dict[str, str]:
    _require_auth(x_auth)
    return {"status": "ok"}


@app.get("/version")
async def version(x_auth: str = Header(default="")) -> dict[str, Any]:
    _require_auth(x_auth)
    return {"version": VERSION}
