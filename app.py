from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from typing import Final

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from filelock import FileLock

app = FastAPI(title="leitstand-ingest")

# Datenverzeichnis resolven und anlegen
DATA: Final[Path] = Path(os.environ.get("LEITSTAND_DATA_DIR", "data")).resolve()
DATA.mkdir(parents=True, exist_ok=True)

# Token-Pflicht (kann für Tests/Entwicklung leer sein)
SECRET: Final[str | None] = os.environ.get("LEITSTAND_TOKEN")

# RFC-nahe FQDN-Validierung: labels 1..63, a-z0-9 und '-' (kein '_' ), gesamt ≤ 253
_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
)


def _sanitize_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    if not _DOMAIN_RE.fullmatch(d):
        raise HTTPException(status_code=400, detail="invalid domain")
    return d


def _is_under(path: Path, base: Path) -> bool:
    try:
        return path.is_relative_to(base)  # Py 3.9+
    except AttributeError:
        return os.path.commonpath([str(path), str(base)]) == str(base)


def _filename_from_domain(domain: str) -> str:
    """Deterministischer, dateisystem-sicherer Name (kein User-Input im Pfad)."""
    digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()
    return f"{digest[:32]}.jsonl"


def _safe_target_path(domain: str) -> Path:
    name = _filename_from_domain(domain)
    candidate = (DATA / name).resolve()
    if not _is_under(candidate, DATA):
        raise HTTPException(status_code=400, detail="invalid path")
    return candidate


def _require_auth(x_auth: str) -> None:
    if SECRET and not secrets.compare_digest(x_auth, SECRET):
        raise HTTPException(status_code=401, detail="unauthorized")


@app.post("/ingest/{domain}")
async def ingest(domain: str, req: Request, x_auth: str = Header(default="")):
    _require_auth(x_auth)

    # Kleines Größenlimit (1 MiB) + valide Content-Length
    cl_raw = req.headers.get("content-length")
    if not cl_raw:
        raise HTTPException(status_code=411, detail="length required")
    try:
        cl = int(cl_raw)
    except (ValueError, TypeError):  # defensive
        raise HTTPException(status_code=400, detail="invalid content-length")
    if cl > 1024 * 1024:
        raise HTTPException(status_code=413, detail="payload too large")

    dom = _sanitize_domain(domain)
    target_path = _safe_target_path(dom)

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
        if "domain" not in entry:
            entry = {**entry, "domain": dom}
        lines.append(json.dumps(entry, ensure_ascii=False, separators=(",", ":")))

    # Atomar via FileLock anhängen (eine Zeile pro Item)
    lock_path = target_path.with_suffix(target_path.suffix + ".lock")
    with FileLock(lock_path):
        with target_path.open("a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line)
                fh.write("\n")

    return PlainTextResponse("ok", status_code=200)
