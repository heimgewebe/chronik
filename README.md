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
| `CHRONIK_TOKEN`      |  ja     | ``       | Shared-Secret(s). Jeder Request muss den Header `X-Auth` mit einem der hier hinterlegten Werte enthalten. Mehrere Tokens können durch Komma oder Zeilenumbruch getrennt werden. |
| `CHRONIK_DATA_DIR`   | nein    | `data`   | Zielverzeichnis für die pro Domain erzeugten JSONL-Dateien. Wird beim Start erstellt, falls nicht vorhanden. |
| `CHRONIK_MAX_BODY`   | nein    | `1048576`| Maximale Größe des Request-Bodys in Bytes (Standard 1&nbsp;MiB). |
| `CHRONIK_LOCK_TIMEOUT`| nein   | `30`     | Timeout in Sekunden beim Schreiben (FileLock). |
| `CHRONIK_RATE_LIMIT` | nein    | `60/minute` | Rate-Limit pro Quell-IP (SlowAPI-Format). |
| `CHRONIK_LOG_LEVEL`  | nein    | `INFO`   | Log-Level (z. B. `DEBUG`, `INFO`, `WARNING`). |
| `LOG_LEVEL`            | nein    | `INFO`   | Fallback Log-Level, falls `CHRONIK_LOG_LEVEL` nicht gesetzt. |
| `CHRONIK_ENFORCE_PROVENANCE` | nein | `0` | Provenienz-Enforcement: `1` = Events ohne Provenienz werden abgelehnt, `0` = nur Warnung. |
| `CHRONIK_ENABLE_QUALITY` | nein | `1` | Qualitätsmarker: `1` = aktiviert, `0` = deaktiviert. |

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

## Event-Qualität, Provenienz & Retention

chronik implementiert drei zentrale Invarianten für verlässliche Event-Verarbeitung:

### 1. Provenienz (Herkunft)
Events sollten ihre Herkunft dokumentieren. Bei aktiviertem Enforcement (`CHRONIK_ENFORCE_PROVENANCE=1`) werden folgende Felder zwingend erforderlich:
- `source.repo`: Repository/System-Name
- `source.component`: Komponente
- `event_id`: Eindeutiger Identifier

**Beispiel:**
```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "source": {
    "repo": "heimgewebe/wgx",
    "component": "semantAH"
  },
  "kind": "embedding.computed",
  "ts": "2026-01-04T10:00:00Z",
  "data": {"vector_dim": 768}
}
```

### 2. Qualitätsmarker (Signal Strength)
Events werden regelbasiert bewertet (nicht semantisch):
- `quality.signal_strength`: `high`, `medium`, `low` (basierend auf Vollständigkeit)
- `quality.completeness`: Boolean (alle Pflichtfelder vorhanden?)

### 3. Retention (Lebenszyklen)
Events haben definierte TTLs basierend auf Event-Typ (konfigurierbar in `config/retention.yml`):
- Debug-Events: 7 Tage
- Published Events (*.published.v*): Unbegrenzt
- Default: 30 Tage

**Gespeichertes Event-Format:**
```json
{
  "domain": "aussen",
  "received_at": "2026-01-04T10:00:05Z",
  "payload": { ... },
  "quality": {
    "signal_strength": "high",
    "completeness": true
  },
  "retention": {
    "ttl_days": 30,
    "expires_at": "2026-02-03T10:00:05Z"
  }
}
```

**Wichtig**: `quality` ist Envelope-Metadata und wird nicht in `payload` eingefügt. Der ursprüngliche Event-Payload bleibt unverändert.

**Siehe auch:** Ausführliche Dokumentation in [`docs/chronik/event-quality.md`](docs/chronik/event-quality.md)
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
* Rotierendes Secret: Durch die Unterstützung mehrerer Tokens in `CHRONIK_TOKEN` kann eine unterbrechungsfreie Rotation erfolgen (altes und neues Token gleichzeitig hinterlegen).
* Rate-Limits & Locks: Bei hohem Traffic liefert der Dienst `429` mitsamt `Retry-After` sowie `X-RateLimit-*`. Wenn ein Lock nicht rechtzeitig frei wird, antwortet die API mit `503 lock timeout`.

## Entwicklung & Tests
* One-Command-Validierung: `make validate-local` oder direkt `./scripts/validate-local.sh`. Der Befehl richtet/aktualisiert `.venv`, führt `pytest -q` aus und prüft hermetisch `/health`, `/version`, `POST /v1/ingest?domain=agent.ledger` sowie `/v1/events` gegen ein temporäres `CHRONIK_DATA_DIR`.
* Formatierung: Standard Python Code-Formatierung (z. B. `black`) kann verwendet werden.
* Tests: Für die API können `pytest`-basierte Tests oder Integrationstests mit `httpx` genutzt werden.
* **API /v1/latest:** Der Endpoint `/v1/latest` gibt den letzten Log-Eintrag zurück (standardmäßig als Wrapper mit `domain`, `received_at`, `payload`). Mit `?unwrap=1` kann direkt das innere Payload-Objekt angefordert werden.
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
| `HAUSKI_INGEST_STRICT` | `0` (permissiv)       | Strict Mode: `1` erzwingt kanonische Event-Felder (`kind`, `ts`, `source`) |

Die Library gibt bei Erfolg `"ok"` zurück oder wirft eine Exception (z. B. bei 4xx/5xx nach Retries).

### Permissiv vs. Strict Mode

**Default (permissiv):** `ingest_event` akzeptiert beliebige JSON-Objekte. Dies ist nützlich für Debug-Daten, Telemetrie oder Raw-Payloads.

```python
from tools.hauski_ingest import ingest_event
# Beliebige JSON-Struktur
ingest_event("metrics.daily", {"value": 42, "timestamp": "2025-12-31T10:00:00Z"})
```

**Strict Mode:** Erzwingt kanonische Event-Struktur mit Pflichtfeldern `kind`, `ts`, `source` für bessere Traceability und semantische Klarheit.

```python
import os
os.environ["HAUSKI_INGEST_STRICT"] = "1"

from tools.hauski_ingest import ingest_event
# Erfordert kind, ts, source
ingest_event("example.com", {
    "kind": "deploy.success",
    "ts": "2025-12-31T10:00:00Z",
    "source": "ci-pipeline",
    "data": {"version": "1.2.3"}
})

# Oder per Parameter (überschreibt ENV):
ingest_event("example.com", {"foo": "bar"}, strict=False)
```

**Alias für semantische Klarheit:** `ingest_json` ist ein Alias zu `ingest_event` für Code, der explizit beliebiges JSON sendet.

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

## Organismus-Kontext

Dieses Repository ist Teil des **Heimgewebe-Organismus**.

Die übergeordnete Architektur, Achsen, Rollen und Contracts sind zentral beschrieben im  
👉 [`metarepo/docs/heimgewebe-organismus.md`](https://github.com/heimgewebe/metarepo/blob/main/docs/heimgewebe-organismus.md)  
👉 [`metarepo/docs/heimgewebe-zielbild.md`](https://github.com/heimgewebe/metarepo/blob/main/docs/heimgewebe-zielbild.md).

Alle Rollen-Definitionen, Datenflüsse und Contract-Zuordnungen dieses Repos
sind dort verankert.