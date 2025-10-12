from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Final

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse

app = FastAPI(title="leitstand-ingest")

DATA = Path(os.environ.get("LEITSTAND_DATA_DIR", "data")).resolve()
DATA.mkdir(parents=True, exist_ok=True)

SECRET = os.environ.get("LEITSTAND_TOKEN", "")

_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)"
    r"(?:\.(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?))*$"
)


def _sanitize_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    if not _DOMAIN_RE.fullmatch(d):
        raise HTTPException(status_code=400, detail="invalid domain")
    return d


def _is_under(path: Path, base: Path) -> bool:
    try:
        return path.is_relative_to(base)
    except AttributeError:
        return os.path.commonpath([str(path), str(base)]) == str(base)


def _filename_from_domain(domain: str) -> str:
    """Return a deterministic, filesystem-safe filename for ``domain``."""

    digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()
    return f"{digest[:32]}.jsonl"


def _safe_target_path(domain: str) -> Path:
    name = _filename_from_domain(domain)
    candidate = (DATA / name).resolve()
    if not _is_under(candidate, DATA):
        raise HTTPException(status_code=400, detail="invalid path")
    return candidate


def _require_auth(x_auth: str) -> None:
    if SECRET and x_auth != SECRET:
        raise HTTPException(status_code=401, detail="unauthorized")


@app.post("/ingest/{domain}")
async def ingest(domain: str, req: Request, x_auth: str = Header(default="")):
    _require_auth(x_auth)
    dom = _sanitize_domain(domain)
    target_path = _safe_target_path(dom)

    try:
        raw = await req.body()
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive: decode/json errors
        raise HTTPException(status_code=400, detail="invalid json") from exc

    if isinstance(obj, dict) and "domain" not in obj:
        obj["domain"] = dom

    with target_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")

    return PlainTextResponse("ok", status_code=200)
