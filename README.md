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
* `429 Too Many Requests`: Rate-Limit aus `LEITSTAND_RATE_LIMIT` erreicht. Die Antwort enthält zusätzlich `Retry-After` sowie die Header `X-RateLimit-Limit` und `X-RateLimit-Remaining` (SlowAPI kümmert sich um die Berechnung dieser Werte). Ein Beispiel für einen Client-Backoff findet sich in [docs/cli-curl.md](docs/cli-curl.md).
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
* Rate-Limits & Locks: Bei hohem Traffic liefert der Dienst `429` mitsamt `Retry-After` sowie `X-RateLimit-*`. Wenn ein Lock nicht rechtzeitig frei wird, antwortet die API mit `503 lock timeout`.

## Entwicklung & Tests
* Formatierung: Standard Python Code-Formatierung (z. B. `black`) kann verwendet werden.
* Tests: Für die API können `pytest`-basierte Tests oder Integrationstests mit `httpx` genutzt werden.
* FastAPI generiert automatisch eine OpenAPI-Spezifikation unter `http://localhost:8788/docs`, sobald der Server läuft.
* `/metrics` ist für Prometheus vorgesehen; im lokalen Development bleibt der Endpunkt bewusst ohne Authentifizierung erreichbar.
