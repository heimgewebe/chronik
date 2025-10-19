from __future__ import annotations

import json
import os
import secrets
from typing import TYPE_CHECKING, Final

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from filelock import FileLock

from storage import DATA_DIR, DomainError, safe_target_path, sanitize_domain

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


async def _validate_body_size(req: Request) -> None:
    # Kleines Größenlimit (1 MiB) + valide Content-Length
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


@app.post("/ingest/{domain}")
async def ingest(
    domain: str,
    req: Request,
    x_auth: str = Header(default=""),
    _size_ok: None = Depends(_validate_body_size),
):
    _require_auth(x_auth)

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
    lock_path = target_path.with_suffix(target_path.suffix + ".lock")
    with FileLock(lock_path):
        with target_path.open("a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line)
                fh.write("\n")

    return PlainTextResponse("ok", status_code=200)


@app.get("/health")
async def health(x_auth: str = Header(default="")) -> dict[str, str]:
    _require_auth(x_auth)
    return {"status": "ok"}


@app.get("/version")
async def version(x_auth: str = Header(default="")) -> dict[str, str]:
    _require_auth(x_auth)
    return {"version": VERSION}
