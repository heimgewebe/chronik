from __future__ import annotations

import errno
import json
import logging
import os
import re
import stat
import secrets
import time
import uuid
from typing import TYPE_CHECKING, Final

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from filelock import FileLock, Timeout
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from storage import (
    DATA_DIR,
    DomainError,
    safe_target_path,
    sanitize_domain,
    target_filename,
)

if TYPE_CHECKING:
    from pathlib import Path

# --- Runtime constants & logging ---
MAX_PAYLOAD_SIZE: Final[int] = int(os.getenv("LEITSTAND_MAX_BODY", str(1024 * 1024)))
LOCK_TIMEOUT: Final[int] = int(os.getenv("LEITSTAND_LOCK_TIMEOUT", "30"))
RATE_LIMIT: Final[str] = os.getenv("LEITSTAND_RATE_LIMIT", "60/minute")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
FILENAME_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9.-]{0,248}\.jsonl")

logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger("leitstand")

app = FastAPI(title="leitstand-ingest")

DATA: Final = DATA_DIR

VERSION: Final[str] = os.environ.get("LEITSTAND_VERSION", "dev")

SECRET_ENV = os.environ.get("LEITSTAND_TOKEN")
if not SECRET_ENV:
    raise RuntimeError("LEITSTAND_TOKEN not set. Auth is required for all requests.")

SECRET: Final[str] = SECRET_ENV


@app.middleware("http")
async def request_id_logging(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    start = time.time()
    status = None
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


def _safe_target_path(domain: str, *, already_sanitized: bool = False) -> "Path":
    dom = domain if already_sanitized else _sanitize_domain(domain)
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
    if not cl_raw:
        raise HTTPException(status_code=411, detail="length required")
    try:
        cl = int(cl_raw)
    except (ValueError, TypeError):  # defensive
        raise HTTPException(status_code=400, detail="invalid content-length")
    if cl < 0:
        raise HTTPException(status_code=400, detail="invalid content-length")
    if cl > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail="payload too large")


@app.post(
    "/ingest/{domain}",
    # Dependency order matters: auth FIRST, then size check.
    dependencies=[Depends(_require_auth_dep), Depends(_validate_body_size)],
)
@limiter.limit(RATE_LIMIT)
async def ingest(
    domain: str,
    request: Request,
):

    dom = _sanitize_domain(domain)
    target_path = _safe_target_path(dom, already_sanitized=True)

    # JSON parsen
    try:
        raw = await request.body()
        obj = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:  # defensive
        raise HTTPException(status_code=400, detail="invalid json") from exc

    # Objekt oder Array → JSONL: eine kompakte Zeile pro Eintrag
    items = obj if isinstance(obj, list) else [obj]
    lines: list[str] = []
    for entry in items:
        if not isinstance(entry, dict):
            raise HTTPException(status_code=400, detail="invalid payload")

        normalized = dict(entry)

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

    # Atomar via FileLock anhängen (eine Zeile pro Item)
    # CodeQL: Pfad nicht direkt aus Nutzereingabe verwenden – stattdessen
    # nur relativ zum vertrauenswürdigen DATA-Dir arbeiten (dirfd + Symlink-Block).
    # Use canonical and sanitized path components from target_path
    fname = target_path.name

    # Ensure fname is exactly as expected for sanitized domain
    if fname != target_filename(dom):
        raise HTTPException(status_code=400, detail="invalid target")
    if os.path.basename(fname) != fname or ".." in fname:
        raise HTTPException(status_code=400, detail="invalid target")
    if not FILENAME_RE.fullmatch(fname):
        raise HTTPException(status_code=400, detail="invalid target")
    # Extra defense-in-depth: ensure resolved parent is the trusted data dir
    if target_path.parent != DATA:
        raise HTTPException(status_code=400, detail="invalid target path: wrong parent directory")
    lock_path = target_path.parent / (fname + ".lock")
    try:
        with FileLock(str(lock_path), timeout=LOCK_TIMEOUT):
            # Defense-in-depth: always use trusted DATA_DIR for dirfd
            dirfd = os.open(str(DATA), os.O_RDONLY)
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
                nofollow = getattr(os, "O_NOFOLLOW", 0)
                if not nofollow:
                    raise HTTPException(status_code=500, detail="platform lacks O_NOFOLLOW")
                flags |= nofollow

                try:
                    fd = os.open(
                        str(target_path),
                        flags,
                        0o600,
                    )  # use strictly validated canonical path
                except OSError as exc:
                    if exc.errno == errno.ENOSPC:
                        logger.error("disk full", extra={"file": str(target_path)})
                        raise HTTPException(status_code=507, detail="insufficient storage") from exc
                    raise

                with os.fdopen(fd, "a", encoding="utf-8") as fh:
                    for line in lines:
                        fh.write(line)
                        fh.write("\n")
            finally:
                os.close(dirfd)
    except Timeout as exc:
        logger.warning("lock timeout", extra={"file": str(target_path)})
        raise HTTPException(status_code=503, detail="lock timeout") from exc

    return PlainTextResponse("ok", status_code=200)


@app.get("/health")
async def health(x_auth: str = Header(default="")) -> dict[str, str]:
    _require_auth(x_auth)
    return {"status": "ok"}


@app.get("/version")
async def version(x_auth: str = Header(default="")) -> dict[str, str]:
    _require_auth(x_auth)
    return {"version": VERSION}
