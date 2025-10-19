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
from werkzeug.utils import secure_filename
app = FastAPI(title="leitstand-ingest")

# Datenverzeichnis resolven und anlegen
DATA: Final[Path] = Path(os.environ.get("LEITSTAND_DATA_DIR", "data")).resolve()
DATA.mkdir(parents=True, exist_ok=True)

VERSION: Final[str] = os.environ.get("LEITSTAND_VERSION", "dev")

SECRET_ENV = os.environ.get("LEITSTAND_TOKEN")
if not SECRET_ENV:
    raise RuntimeError("LEITSTAND_TOKEN not set. Auth is required for all requests.")

SECRET: Final[str] = SECRET_ENV

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
        # Ensure both paths are absolute and normalized before comparison (no Path constructor on tainted input)
        path_abs = os.path.abspath(str(path))
        base_abs = os.path.abspath(str(base))
        return os.path.commonpath([path_abs, base_abs]) == base_abs


_FNAME_MAX: Final[int] = 255  # typische FS-Grenze (ext4 etc.)

# Zusätzliche Zeichen, die wir aus Sicherheitsgründen entfernen (neben / und \0)
_UNSAFE_FILENAME_CHARS: Final[re.Pattern[str]] = re.compile(r'[][<>:"|?*]')


def _secure_filename(name: str) -> str:
    """
    Sichere Umwandlung eines Dateinamens mit werkzeug.utils.secure_filename.
    Entfernt unsichere Zeichen und verhindert Directory Traversal.
    """
    # Prevent any traversal: collapse '..', and then use werkzeug secure_filename
    name = name.replace("..", ".")
    name = secure_filename(name)
    if not name:
        raise HTTPException(status_code=400, detail="invalid filename")
    return name

def _target_filename(domain: str) -> str:
    """
    Liefert einen deterministischen, dateisystem-sicheren Dateinamen für die Domain.
    Falls die Domain + '.jsonl' länger als das FS-Limit ist, nehmen wir eine
    trunkierte Variante plus 8-stelligem SHA-256-Suffix.
    """

    base = domain
    ext = ".jsonl"
    # Reserve 1–2 Zeichen Sicherheit wegen Encoding/FS
    if len(base) + len(ext) > (_FNAME_MAX - 1):
        h = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:8]
        # so viel wie möglich behalten, dann '-{hash}'
        keep = max(16, (_FNAME_MAX - len(ext) - 1 - len(h)))  # 1 für '-'
        base = f"{domain[:keep]}-{h}"
    filename = f"{base}{ext}"
    # Sanitize filename to avoid any unwanted characters or traversal
    return _secure_filename(filename)


def _safe_target_path(domain: str) -> Path:
    candidate = (DATA / _target_filename(domain)).resolve()
    if not _is_under(candidate, DATA):
        raise HTTPException(status_code=400, detail="invalid path")
    return candidate


def _require_auth(x_auth: str) -> None:
    if not x_auth or not secrets.compare_digest(x_auth, SECRET):
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
    if cl < 0:
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

        normalized = dict(entry)

        if "domain" in normalized:
            entry_domain = normalized["domain"]
            if not isinstance(entry_domain, str):
                raise HTTPException(status_code=400, detail="invalid payload")

            sanitized_entry_domain = _sanitize_domain(entry_domain)
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
