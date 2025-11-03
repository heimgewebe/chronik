### 📄 .env.example

**Größe:** 40 B | **md5:** `999955d369e9e1946628cfbb0a923d4b`

```plaintext
LEITSTAND_TOKEN=dev
LEITSTAND_PORT=8788
```

### 📄 .gitignore

**Größe:** 29 B | **md5:** `2d5711253ee2722abcaa2604a695eaf6`

```plaintext
# runtime
__pycache__/
*.pyc
```

### 📄 LICENSE

**Größe:** 124 B | **md5:** `527dc8fd0ca0799522dace91147efe1f`

```plaintext
MIT License

Copyright (c) 2025 heimgewebe

Permission is hereby granted, free of charge, to any person obtaining a copy...
```

### 📄 Makefile

**Größe:** 470 B | **md5:** `74f06e62ecdbb763dcb26fdef1e7b7d9`

```plaintext
LEITSTAND_PORT ?= 8788

.PHONY: dev ingest-test ensure-token

dev:
	uvicorn app:app --reload --port $(LEITSTAND_PORT)

ingest-test: ensure-token
	curl --fail-with-body -sS -X POST "http://localhost:$(LEITSTAND_PORT)/ingest/aussen" \
		-H "Content-Type: application/json" \
		-H "X-Auth: $(LEITSTAND_TOKEN)" \
		-d '{"service": "demo", "status": "ok"}'

ensure-token:
	@if [ -z "$${LEITSTAND_TOKEN}" ]; then \
		echo "LEITSTAND_TOKEN is undefined" >&2; \
		exit 1; \
	fi
```

### 📄 README.md

**Größe:** 5 KB | **md5:** `46d951baeb075deabc5cdc8080970c8a`

```markdown
# leitstand

`leitstand` stellt einen sehr kleinen HTTP-Ingest-Dienst bereit, der strukturierte Ereignisse
als JSON entgegennimmt und domain-spezifisch in JSON Lines Dateien ablegt. Die Anwendung ist in
FastAPI implementiert und lässt sich lokal oder in Codespaces betreiben.

## Quickstart
```bash
git clone <repository-url>
cd leitstand
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8788
```

Sobald der Server läuft, sind die interaktiven API-Dokumente unter
`http://localhost:8788/docs` verfügbar.

### Quickstart (dev)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export LEITSTAND_TOKEN=${LEITSTAND_TOKEN:-dev}
uvicorn app:app --reload --port 8788
```

Ein erstes Ereignis kann anschließend mit folgendem Aufruf eingespielt werden:

```bash
curl -X POST "http://localhost:8788/ingest/aussen" \
     -H "Content-Type: application/json" \
     -H "X-Auth: ${LEITSTAND_TOKEN}" \
     -d '{"event": "demo", "status": "ok"}'
```

Die Datei `.env.example` liefert passende Standardwerte (Token `dev`, Port `8788`) und kann bei Bedarf nach `.env` kopiert werden. Für einen schnellen Start steht zudem `make dev` bzw. `make ingest-test` zur Verfügung.

## Voraussetzungen
* Python 3.10+
* Abhängigkeiten aus `requirements.txt`

## Installation & Start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Authentifizierungs-Token setzen (Pflicht)
export LEITSTAND_TOKEN=$(openssl rand -hex 12)
# optional: Zielverzeichnis der JSONL-Dateien anpassen
export LEITSTAND_DATA_DIR=./data
uvicorn app:app --host 0.0.0.0 --port 8788
```

In GitHub Codespaces sollte der Port 8788 veröffentlicht werden, um Anfragen an die API senden zu können.

## Konfigurations- und Umgebungsvariablen
| Variable               | Pflicht | Standard | Beschreibung |
|------------------------|:-------:|----------|--------------|
| `LEITSTAND_TOKEN`      |  ja     | ``       | Shared-Secret. Jeder Request muss den Header `X-Auth` mit exakt diesem Wert enthalten. |
| `LEITSTAND_DATA_DIR`   | nein    | `data`   | Zielverzeichnis für die pro Domain erzeugten JSONL-Dateien. Wird beim Start erstellt, falls nicht vorhanden. |
| `LEITSTAND_MAX_BODY`   | nein    | `1048576`| Maximale Größe des Request-Bodys in Bytes (Standard 1&nbsp;MiB). |
| `LEITSTAND_LOCK_TIMEOUT`| nein   | `30`     | Timeout in Sekunden beim Schreiben (FileLock). |
| `LEITSTAND_RATE_LIMIT` | nein    | `60/minute` | Rate-Limit pro Quell-IP (SlowAPI-Format). |
| `LOG_LEVEL`            | nein    | `INFO`   | Log-Level (z. B. `DEBUG`, `INFO`, `WARNING`). |

## API & Contracts

### `GET /version`
* **Header** `X-Auth`: identisch zu den anderen Endpunkten.
* **Antwort**: `{ "version": "<wert>" }`. Der Wert entspricht der Konstante `VERSION` bzw. der Umgebungsvariablen `LEITSTAND_VERSION`.

### `GET /metrics`
* **Auth**: Keine. Exponiert Prometheus-Metriken (Request-Latenz, -Zähler etc.).

### Typische Fehlercodes
* `401 Unauthorized`: Token fehlt oder stimmt nicht.
* `411 Length Required`: `Content-Length`-Header fehlt.
* `413 Payload Too Large`: Request-Body überschreitet `LEITSTAND_MAX_BODY`.
* `429 Too Many Requests`: Rate-Limit aus `LEITSTAND_RATE_LIMIT` erreicht. Die Antwort enthält zusätzlich `Retry-After` sowie die Header `X-RateLimit-Limit` und `X-RateLimit-Remaining`.
* `503 Service Unavailable`: Schreibzugriff blockiert (`LEITSTAND_LOCK_TIMEOUT` überschritten).
* `507 Insufficient Storage`: Kein freier Speicherplatz im Zielverzeichnis.

Weitere Beispiele und Details finden sich in der begleitenden Dokumentation:

* [docs/api.md](docs/api.md) – Ausführliche API-Dokumentation.
* [docs/cli-curl.md](docs/cli-curl.md) – Curl-Beispiele für Health-, Version- und Ingest-Aufrufe.
* [docs/event-contracts.md](docs/event-contracts.md) – Beschreibung des JSONL-Speicherlayouts und referenziertes Schema.

## Datenspeicherung
* Für jede Domain entsteht eine JSONL-Datei im Verzeichnis `LEITSTAND_DATA_DIR`.
* Der Dateiname entspricht der Domain (`<domain>.jsonl`). Extrem lange Domains werden automatisch gekürzt und erhalten einen 8-stelligen Hash-Suffix (z. B. `very-long…-1a2b3c4d.jsonl`), um Dateisystemlimits einzuhalten.
* Jeder Request wird unverändert (bzw. um das Feld `domain` ergänzt) als einzelne Zeile im JSONL-Format angehängt.

## Betrieb & Wartung
* Logs: `uvicorn` schreibt standardmäßig auf STDOUT; bei Bedarf Output umleiten oder in eine zentrale Log-Pipeline integrieren.
* Backups: Das Datenverzeichnis lässt sich als Ganzes sichern. Durch die reine Anhänge-Strategie eignen sich inkrementelle Backups.
* Monitoring: Ein erfolgreicher `POST` liefert Status 200. Fehlermeldungen (`400`, `401`) sollten ausgewertet werden, um Integrationsfehler zu erkennen.
* Rotierendes Secret: Wird `LEITSTAND_TOKEN` geändert, muss der neue Wert zeitgleich bei allen Clients hinterlegt werden.

## Entwicklung & Tests
* Formatierung: Standard Python Code-Formatierung (z. B. `black`) kann verwendet werden.
* Tests: Für die API können `pytest`-basierte Tests oder Integrationstests mit `httpx` genutzt werden.
* FastAPI generiert automatisch eine OpenAPI-Spezifikation unter `http://localhost:8788/docs`, sobald der Server läuft.
* `/metrics` ist für Prometheus vorgesehen; im lokalen Development bleibt der Endpunkt bewusst ohne Authentifizierung erreichbar.
```

### 📄 app.py

**Größe:** 8 KB | **md5:** `8d998c9d19b4ec97b7c5b5da461ebc47`

```python
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
```

### 📄 requirements.txt

**Größe:** 189 B | **md5:** `c1a2c76fccd80eddb127a8ce636decf1`

```plaintext
fastapi>=0.110
Werkzeug==3.1.3
uvicorn[standard]>=0.27
filelock>=3.13
prometheus-fastapi-instrumentator
slowapi
pytest
httpx
slowapi>=0.1.8,<0.2
prometheus-fastapi-instrumentator>=6.1.0,<7
```

### 📄 storage.py

**Größe:** 3 KB | **md5:** `f5659dbea6dbd724fc46b3eb4f9d6bf0`

```python
"""Shared domain and storage helpers for Leitstand ingest components."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Final

__all__ = [
    "DATA_DIR",
    "DomainError",
    "sanitize_domain",
    "secure_filename",
    "target_filename",
    "safe_target_path",
]


class DomainError(ValueError):
    """Raised when a domain does not meet the validation requirements."""


DATA_DIR: Final[Path] = Path(os.environ.get("LEITSTAND_DATA_DIR", "data")).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

# RFC-nahe FQDN-Validierung: labels 1..63, a-z0-9 und '-' (kein '_' ), gesamt ≤ 253
_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
)

_FNAME_MAX: Final[int] = 255  # typische FS-Grenze (ext4 etc.)

# Zusätzliche Zeichen, die wir aus Sicherheitsgründen entfernen (neben / und \0)
_UNSAFE_FILENAME_CHARS: Final[re.Pattern[str]] = re.compile(r"[][<>:\"|?*]")


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

    s_name = name
    while ".." in s_name:
        s_name = s_name.replace("..", ".")
    return _UNSAFE_FILENAME_CHARS.sub("", s_name)


def target_filename(domain: str) -> str:
    """Return a deterministic filename for a given domain."""

    base = domain
    ext = ".jsonl"
    # Reserve 1–2 Zeichen Sicherheit wegen Encoding/FS
    if len(base) + len(ext) > (_FNAME_MAX - 1):
        h = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:8]
        # so viel wie möglich behalten, dann '-{hash}'
        keep = max(16, (_FNAME_MAX - len(ext) - 1 - len(h)))  # 1 für '-'
        base = f"{domain[:keep]}-{h}"
    filename = f"{base}{ext}"
    return secure_filename(filename)


def safe_target_path(domain: str, *, data_dir: Path | None = None) -> Path:
    """Return an absolute, canonical path below the data directory for the domain.
    The filename is fully sanitized; we additionally assert no path separators pass through.
    """

    base = (DATA_DIR if data_dir is None else data_dir).resolve(strict=True)
    fname = target_filename(domain)
    # Extra defense: enforce no separators after sanitizing (helps static analyzers)
    if "/" in fname or "\\" in fname:
        raise DomainError(domain)
    # Solution: normalize joined path before containment check
    candidate = (base / fname).resolve(strict=False)  # canonicalize
    base_resolved = base  # already resolved above
    # Containment check using canonical base directory and normalized paths
    if not _is_under(candidate, base_resolved):
        raise DomainError(domain)
    return candidate
```

### 📄 test_app.py

**Größe:** 12 KB | **md5:** `a41d2d37ba3ab376741af3b5de69bf02`

```python
import errno
import json
import os
import string
from pathlib import Path

os.environ.setdefault("LEITSTAND_TOKEN", "test-secret")

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import app as app_module
from app import _safe_target_path, _sanitize_domain, app
import storage

client = TestClient(app)


def test_ingest_auth_ok(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": "secret"}, json={"data": "value"}
    )
    assert response.status_code == 200
    assert response.text == "ok"


def test_ingest_auth_fail(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": "wrong"}, json={"data": "value"}
    )
    assert response.status_code == 401


def test_ingest_auth_missing(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post("/ingest/example.com", json={"data": "value"})
    assert response.status_code == 401


def test_sanitize_domain_ok():
    assert _sanitize_domain("example.com") == "example.com"
    assert _sanitize_domain(" ex-ample.com ") == "ex-ample.com"


def test_sanitize_domain_bad():
    with pytest.raises(Exception):
        _sanitize_domain("example_com")
    with pytest.raises(Exception):
        _sanitize_domain("example.com_")


def test_safe_target_path_rejects_traversal(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("app.DATA", tmp_path)
    with pytest.raises(HTTPException) as excinfo:
        _safe_target_path("../../etc/passwd", already_sanitized=True)
    assert excinfo.value.status_code == 400
    assert excinfo.value.detail == "invalid domain"


def test_secure_filename_rejects_nested_traversal():
    assert ".." not in storage.secure_filename("....test")
    assert ".." not in storage.secure_filename("..test")
    assert ".." not in storage.secure_filename("test..")
    assert ".." not in storage.secure_filename("...test...")
    assert storage.secure_filename("....test") == ".test"


def test_ingest_single_object(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("app.SECRET", "secret")
    monkeypatch.setattr("app.DATA", tmp_path)
    domain = "example.com"
    payload = {"data": "value"}
    response = client.post(f"/ingest/{domain}", headers={"X-Auth": "secret"}, json=payload)
    assert response.status_code == 200
    assert response.text == "ok"

    # Verify file content
    files = [f for f in tmp_path.iterdir() if f.name.endswith(".jsonl")]
    assert len(files) == 1
    target_file = files[0]
    with open(target_file, "r") as f:
        line = f.readline()
        data = json.loads(line)
        assert data == {**payload, "domain": domain}


def test_ingest_array_of_objects(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("app.SECRET", "secret")
    monkeypatch.setattr("app.DATA", tmp_path)
    domain = "example.com"
    payload = [{"data": "value1"}, {"data": "value2"}]
    response = client.post(f"/ingest/{domain}", headers={"X-Auth": "secret"}, json=payload)
    assert response.status_code == 200
    assert response.text == "ok"

    # Verify file content
    files = [f for f in tmp_path.iterdir() if f.name.endswith(".jsonl")]
    assert len(files) == 1
    target_file = files[0]
    with open(target_file, "r") as f:
        lines = f.readlines()
        assert len(lines) == 2
        data1 = json.loads(lines[0])
        assert data1 == {**payload[0], "domain": domain}
        data2 = json.loads(lines[1])
        assert data2 == {**payload[1], "domain": domain}


def test_ingest_invalid_json(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": "secret", "Content-Type": "application/json"},
        content="{invalid json}",
    )
    assert response.status_code == 400
    assert "invalid json" in response.text


def test_ingest_payload_too_large(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    # Limit is 1 MiB
    large_payload = {"key": "v" * (1024 * 1024)}
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": "secret"}, json=large_payload
    )
    assert response.status_code == 413
    assert "payload too large" in response.text


def test_ingest_invalid_payload_not_dict(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": "secret"}, json=["not-a-dict"]
    )
    assert response.status_code == 400
    assert "invalid payload" in response.text


def test_ingest_domain_mismatch(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": "secret"},
        json={"domain": "other.example", "data": "value"},
    )
    assert response.status_code == 400
    assert "domain mismatch" in response.text


def test_ingest_domain_normalized(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("app.SECRET", "secret")
    monkeypatch.setattr("app.DATA", tmp_path)

    payload = {"domain": "Example.COM", "data": "value"}
    response = client.post(
        "/ingest/example.com", headers={"X-Auth": "secret"}, json=payload
    )

    assert response.status_code == 200

    target_file = next(tmp_path.glob("*.jsonl"))
    with open(target_file, "r", encoding="utf-8") as fh:
        stored = json.loads(fh.readline())
    assert stored["domain"] == "example.com"
    assert stored["data"] == "value"


def test_ingest_no_content_length(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    request = client.build_request(
        "POST",
        "/ingest/example.com",
        headers={"X-Auth": "secret", "Content-Type": "application/json"},
        content='{"data": "value"}',
    )
    # httpx TestClient adds this header automatically.
    del request.headers["Content-Length"]
    response = client.send(request)
    assert response.status_code == 411
    assert "length required" in response.text


def test_ingest_no_content_length_unauthorized(monkeypatch):
    """Missing auth should fail before we validate content length."""
    monkeypatch.setattr("app.SECRET", "secret")
    request = client.build_request(
        "POST",
        "/ingest/example.com",
        headers={"Content-Type": "application/json"},
        content='{"data": "value"}',
    )
    del request.headers["Content-Length"]
    response = client.send(request)
    assert response.status_code == 401
    assert "unauthorized" in response.text


def test_ingest_negative_content_length(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": "secret", "Content-Length": "-1"},
        json={"data": "value"},
    )
    assert response.status_code == 400
    assert "invalid content-length" in response.text


def test_health_endpoint(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.get("/health", headers={"X-Auth": "secret"})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_version_endpoint(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    monkeypatch.setattr("app.VERSION", "1.2.3")
    response = client.get("/version", headers={"X-Auth": "secret"})
    assert response.status_code == 200
    assert response.json() == {"version": "1.2.3"}


def test_target_filename_truncates_long_domain(monkeypatch, tmp_path: Path):
    long_label = "a" * 63
    domain = ".".join([long_label, long_label, long_label, "b" * 61])
    assert len(domain) == 253

    dom = _sanitize_domain(domain)
    filename = storage.target_filename(dom)
    assert filename.endswith(".jsonl")
    assert len(filename) <= 255

    prefix, hash_part_with_ext = filename.rsplit("-", 1)
    hash_part, ext = hash_part_with_ext.split(".")
    assert ext == "jsonl"
    assert len(hash_part) == 8
    assert all(ch in string.hexdigits for ch in hash_part)
    assert prefix.startswith(domain[:16])
    assert storage.target_filename(dom) == filename

    monkeypatch.setattr("app.DATA", tmp_path)
    resolved = app_module._safe_target_path(domain)
    assert resolved.name == filename
    assert resolved.parent == tmp_path


def test_metrics_endpoint_exposed():
    """Metrics endpoint should be accessible without auth."""

    response = client.get("/metrics")
    assert response.status_code == 200
    assert "http_requests" in response.text


def test_lock_timeout_returns_503(monkeypatch):
    """Lock acquisition timeout should map to 503."""

    class _DummyLock:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            from filelock import Timeout

            raise Timeout("dummy.lock")

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr("app.FileLock", _DummyLock)
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post(
        "/ingest/example.com",
        headers={
            "X-Auth": "secret",
            "Content-Length": "2",
            "Content-Type": "application/json",
        },
        content="{}",
    )
    assert response.status_code == 503
    assert "lock timeout" in response.text


def test_path_traversal_domain_is_rejected(monkeypatch):
    monkeypatch.setattr("app.SECRET", "secret")
    response = client.post(
        "/ingest/..example.com",
        headers={
            "X-Auth": "secret",
            "Content-Type": "application/json",
            "Content-Length": "2",
        },
        content="{}",
    )
    assert response.status_code == 400
    assert "invalid domain" in response.text


def test_symlink_attack_rejected(monkeypatch, tmp_path):
    import os

    if not hasattr(os, "symlink") or getattr(os, "O_NOFOLLOW", 0) == 0:
        pytest.skip("platform lacks symlink or O_NOFOLLOW")

    monkeypatch.setattr("app.SECRET", "secret")
    monkeypatch.setattr("app.DATA", tmp_path)

    victim = tmp_path / "victim.txt"
    victim.write_text("do not touch", encoding="utf-8")
    link_name = tmp_path / "example.com.jsonl"
    os.symlink(victim, link_name)

    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": "secret", "Content-Type": "application/json"},
        json={"data": "value"},
    )

    assert response.status_code in (400, 500)
    assert victim.read_text(encoding="utf-8") == "do not touch"


def test_concurrent_writes_are_serialized(monkeypatch, tmp_path):
    import concurrent.futures

    monkeypatch.setattr("app.SECRET", "secret")
    monkeypatch.setattr("app.DATA", tmp_path)

    def _one(i: int) -> int:
        return client.post(
            "/ingest/example.com",
            headers={"X-Auth": "secret", "Content-Type": "application/json"},
            json={"i": i},
        ).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        codes = list(executor.map(_one, range(20)))

    assert all(code == 200 for code in codes)

    output = tmp_path / "example.com.jsonl"
    assert output.exists()
    lines = output.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 20


def test_disk_full_returns_507(monkeypatch, tmp_path):
    monkeypatch.setattr("app.SECRET", "secret")
    monkeypatch.setattr("app.DATA", tmp_path)

    original_open = app_module.os.open

    def _raise_enospc(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None:
            raise OSError(errno.ENOSPC, "No space left on device")
        return original_open(path, flags, mode)

    monkeypatch.setattr("app.os.open", _raise_enospc)

    response = client.post(
        "/ingest/example.com",
        headers={"X-Auth": "secret", "Content-Type": "application/json"},
        json={},
    )

    assert response.status_code == 507
    assert "insufficient" in response.text.lower()
```

