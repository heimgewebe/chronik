# chronik

`chronik` stellt einen sehr kleinen HTTP-Ingest-Dienst bereit, der strukturierte Ereignisse
als JSON entgegennimmt und domain-spezifisch in JSON Lines Dateien ablegt. Die Anwendung ist in
FastAPI implementiert und lässt sich lokal oder in Codespaces betreiben.

- **API-Spezifikation:** siehe `docs/openapi.yaml`.
 Alte Pfade `POST /ingest/{domain}` sind **deprecated** (Ablauf 6 Monate nach Merge) und werden durch `POST /v1/ingest` ersetzt.

## 🔗 Contracts (kanonische Definitionen)

chronik folgt dem systemweiten Contract-Set aus dem **metarepo**:

**Event-Backbone**
  - `contracts/aussen.event.schema.json`
  - `contracts/event.line.schema.json`
  - `contracts/chronik-fixtures.schema.json`

Diese Schemata definieren die formale Struktur für ingestbare Events,
FIXTURES sowie interne JSONL-Zeilen. Die CI validiert chronik-Daten bereits dagegen.

chronik definiert selbst **keine** abweichenden Event-Schemata; die Contracts im
**metarepo** sind die einzige Quelle der Wahrheit für ingestbare Events und FIXTURES.
Die Trias aus `aussen.event`, `event.line` und `chronik-fixtures` bildet den
Event-Backbone: Außenwelt → Normalform → chronik-FIXTURES. Änderungen an der
Event-Struktur erfolgen immer über diese zentralen Contracts im metarepo.

## Quickstart
```bash
git clone <repository-url>
cd chronik
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
export CHRONIK_TOKEN=${CHRONIK_TOKEN:-dev}
uvicorn app:app --reload --port 8788
```

Ein erstes Ereignis kann anschließend mit folgendem Aufruf eingespielt werden:

```bash
curl -X POST "http://localhost:8788/ingest/aussen" \
     -H "Content-Type: application/json" \
     -H "X-Auth: ${CHRONIK_TOKEN}" \
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
export CHRONIK_TOKEN=$(openssl rand -hex 12)
# optional: Zielverzeichnis der JSONL-Dateien anpassen
export CHRONIK_DATA_DIR=./data
uvicorn app:app --host 0.0.0.0 --port 8788
```

In GitHub Codespaces sollte der Port 8788 veröffentlicht werden, um Anfragen an die API senden zu können.

## Konfigurations- und Umgebungsvariablen
| Variable               | Pflicht | Standard | Beschreibung |
|------------------------|:-------:|----------|--------------|
| `CHRONIK_TOKEN`      |  ja     | ``       | Shared-Secret. Jeder Request muss den Header `X-Auth` mit exakt diesem Wert enthalten. |
| `CHRONIK_DATA_DIR`   | nein    | `data`   | Zielverzeichnis für die pro Domain erzeugten JSONL-Dateien. Wird beim Start erstellt, falls nicht vorhanden. |
| `CHRONIK_MAX_BODY`   | nein    | `1048576`| Maximale Größe des Request-Bodys in Bytes (Standard 1&nbsp;MiB). |
| `CHRONIK_LOCK_TIMEOUT`| nein   | `30`     | Timeout in Sekunden beim Schreiben (FileLock). |
| `CHRONIK_RATE_LIMIT` | nein    | `60/minute` | Rate-Limit pro Quell-IP (SlowAPI-Format). |
| `CHRONIK_LOG_LEVEL`  | nein    | `INFO`   | Log-Level (z. B. `DEBUG`, `INFO`, `WARNING`). |
| `LOG_LEVEL`            | nein    | `INFO`   | Fallback Log-Level, falls `CHRONIK_LOG_LEVEL` nicht gesetzt. |

**Hinweis:** `CHRONIK_TOKEN` ist die primäre Umgebungsvariable für das Authentifizierungs-Token.

## API

Siehe die OpenAPI-Spezifikation unter [`docs/openapi.yaml`](./docs/openapi.yaml).

> **Deprecation (6 Monate):** Domainspezifische Endpoints (`/ingest/aussen`, …) sind veraltet.
> Bitte auf `POST /v1/ingest` migrieren. Die Domain wird per `event.domain` oder `?domain=aussen` bestimmt.

## Clients
- **Rust (Stub):** `clients/rust/chronik_producer`
  - Blocking (default) und optional `async` Feature.
  - Beispiel: `cargo run --example send` (läuft gegen `POST /v1/ingest`).

## Datenspeicherung
* Für jede Domain entsteht eine JSONL-Datei im Verzeichnis `CHRONIK_DATA_DIR`.
* Der Dateiname entspricht der Domain (`<domain>.jsonl`). Extrem lange Domains werden automatisch gekürzt und erhalten einen 8-stelligen Hash-Suffix (z. B. `very-long…-1a2b3c4d.jsonl`), um Dateisystemlimits einzuhalten.
* Jeder Request wird unverändert (bzw. um das Feld `domain` ergänzt) als einzelne Zeile im JSONL-Format angehängt.

## Betrieb & Wartung
* Logs: `uvicorn` schreibt standardmäßig auf STDOUT; bei Bedarf Output umleiten oder in eine zentrale Log-Pipeline integrieren.
* Backups: Das Datenverzeichnis lässt sich als Ganzes sichern. Durch die reine Anhänge-Strategie eignen sich inkrementelle Backups.
* Monitoring: Ein erfolgreicher `POST` liefert Status 202 (oder 200). Fehlermeldungen sollten ausgewertet werden:
    - `400`: Ungültige Domain, JSON, Domain Mismatch.
    - `401`: Fehlendes oder falsches Token.
    - `413`: Payload zu groß.
    - `422`: Validierungsfehler (z. B. summary zu lang).
    - `429`: Rate Limit oder Lock Timeout.
    - `507`: Speicher voll.
* Rotierendes Secret: Wird `CHRONIK_TOKEN` geändert, muss der neue Wert zeitgleich bei allen Clients hinterlegt werden.
* Rate-Limits & Locks: Bei hohem Traffic liefert der Dienst `429` mitsamt `Retry-After` sowie `X-RateLimit-*`. Wenn ein Lock nicht rechtzeitig frei wird, antwortet die API mit `503 lock timeout`.

## Entwicklung & Tests
* Formatierung: Standard Python Code-Formatierung (z. B. `black`) kann verwendet werden.
* Tests: Für die API können `pytest`-basierte Tests oder Integrationstests mit `httpx` genutzt werden.
* FastAPI generiert automatisch eine OpenAPI-Spezifikation unter `http://localhost:8788/docs`, sobald der Server läuft.
* `/metrics` ist für Prometheus vorgesehen; im lokalen Development bleibt der Endpunkt bewusst ohne Authentifizierung erreichbar.

## Client-Library (hausKI → chronik)
Für hausKI-Module gibt es eine kleine Helper-Lib unter `tools/hauski_ingest.py`, die Events zuverlässig in die Chronik schreibt:

```python
from tools.hauski_ingest import ingest_event
ingest_event("example.com", {"event": "heartbeat", "status": "ok"})
```

**Konfiguration (ENV):**
| Variable               | Default                 | Beschreibung |
|------------------------|-------------------------|--------------|
| `CHRONIK_URL`        | `http://localhost:8788` | Basis-URL der Chronik |
| `CHRONIK_TOKEN`      | — (Pflicht)             | Shared Secret für `X-Auth` |
| `CHRONIK_TIMEOUT`    | `5`                     | HTTP-Timeout in Sekunden |
| `CHRONIK_RETRIES`    | `3`                     | Anzahl Retries bei 429/5xx/Timeout |
| `CHRONIK_BACKOFF`    | `0.5`                   | Start-Backoff (Sek.) für exponentielles Backoff |

Die Library gibt bei Erfolg `"ok"` zurück oder wirft eine Exception (z. B. bei 4xx/5xx nach Retries).

### Mini-Test
```bash
python -c 'import os; os.environ["CHRONIK_TOKEN"]="dev"; from tools.hauski_ingest import ingest_event; print(ingest_event("example.com", {"event":"test","status":"ok"}))'
```

### Testen ohne echte Netzwerk-Sockets
Für hermetische Tests kann `httpx` direkt gegen die laufende FastAPI-App genutzt werden. Da `hauski_ingest` einen synchronen Client verwendet, die FastAPI-App aber asynchron ist, empfiehlt sich die Nutzung von `TestClient` aus `fastapi.testclient`:

```python
import os
os.environ["CHRONIK_TOKEN"] = "dev"
from fastapi.testclient import TestClient
from app import app  # die FastAPI-App
from tools.hauski_ingest import ingest_event

# TestClient stellt einen synchronen Transport bereit
client = TestClient(app)
print(ingest_event(
    "example.com",
    {"event":"test","status":"ok"},
    url="http://test",
    transport=client._transport
))
```