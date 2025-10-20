from __future__ import annotations

import json
import os
import re
import stat
import secrets
from typing import TYPE_CHECKING, Final

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from filelock import FileLock

from storage import (
    DATA_DIR,
    DomainError,
    safe_target_path,
    sanitize_domain,
    target_filename,
    _is_under,
)

if TYPE_CHECKING:
    from pathlib import Path

app = FastAPI(title="leitstand-ingest")

DATA: Final = DATA_DIR

VERSION: Final[str] = os.environ.get("LEITSTAND_VERSION", "dev")

SECRET_ENV = os.environ.get("LEITSTAND_TOKEN")
if not SECRET_ENV:
    raise RuntimeError("LEITSTAND_TOKEN not set. Auth is required for all requests.")

SECRET: Final[str] = SECRET_ENV


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
    Validate Content-Length before reading the body. Limited to 1 MiB.
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
    if cl > 1024 * 1024:
        raise HTTPException(status_code=413, detail="payload too large")


@app.post(
    "/ingest/{domain}",
    # Dependency order matters: auth FIRST, then size check.
    dependencies=[Depends(_require_auth_dep), Depends(_validate_body_size)],
)
async def ingest(
    domain: str,
    req: Request,
):

    dom = _sanitize_domain(domain)
    target_path = _safe_target_path(dom, already_sanitized=True)

    # JSON parsen
    try:
        raw = await req.body()
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

    if os.path.basename(fname) != fname or ".." in fname:
        raise HTTPException(status_code=400, detail="invalid target")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,240}\.jsonl", fname):
        raise HTTPException(status_code=400, detail="invalid target")
    # Extra normalization/containment check before file access
    access_path = target_path.resolve(strict=False)
    data_dir_resolved = DATA.resolve(strict=True)
    if not _is_under(access_path, data_dir_resolved):
        raise HTTPException(status_code=400, detail="invalid target path: path escape detected")
    lock_path = target_path.parent / (fname + ".lock")
    with FileLock(str(lock_path)):
        # Defense-in-depth: always use trusted DATA_DIR for dirfd
        if target_path.parent != DATA:
            # Should never occur; signals a logic or helper bug
            raise HTTPException(status_code=400, detail="invalid target path: wrong parent directory")
        dirfd = os.open(str(DATA), os.O_RDONLY)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            flags |= getattr(os, "O_CLOEXEC", 0)
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            if nofollow:
                flags |= nofollow
            else:
                try:
                    st = os.lstat(fname, dir_fd=dirfd)
                except FileNotFoundError:
                    pass
                else:
                    if stat.S_ISLNK(st.st_mode):
                        raise HTTPException(status_code=400, detail="invalid target")

            fd = os.open(
                fname,
                flags,
                0o600,
                dir_fd=dirfd,
            )  # codeql[py/uncontrolled-data-in-path-expression] fname is whitelisted and basename-only; dir_fd points to trusted DATA_DIR
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                for line in lines:
                    fh.write(line)
                    fh.write("\n")
        finally:
            os.close(dirfd)

    return PlainTextResponse("ok", status_code=200)


@app.get("/health")
async def health(x_auth: str = Header(default="")) -> dict[str, str]:
    _require_auth(x_auth)
    return {"status": "ok"}


@app.get("/version")
async def version(x_auth: str = Header(default="")) -> dict[str, str]:
    _require_auth(x_auth)
    return {"version": VERSION}
