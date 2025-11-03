### 📄 docs/api.md

**Größe:** 3 KB | **md5:** `c46946680bf531c67e79927faec5f066`

```markdown
# API-Handbuch

Dieses Dokument beschreibt die HTTP-Schnittstelle des Leitstand-Ingest-Dienstes im Detail.

## Übersicht
* Basis-URL: `http://<host>:<port>` (Standard-Port 8788)
* Authentifizierung: Verpflichtender Header `X-Auth` mit dem Wert aus `LEITSTAND_TOKEN`
* Datenformat: JSON bzw. JSON Lines
* OpenAPI/Swagger: Automatisch unter `/docs` (Swagger UI) bzw. `/openapi.json` verfügbar

## Endpunkte
### `POST /ingest/{domain}`
Übernimmt beliebige JSON-Payloads und speichert sie domain-spezifisch.

| Eigenschaft    | Beschreibung |
|----------------|--------------|
| Methode        | `POST` |
| Pfadparameter  | `domain` – wird in Kleinbuchstaben umgewandelt und muss den folgenden FQDN-Regeln entsprechen:<ul><li>Gesamtlänge maximal 253 Zeichen.</li><li>Labels (Teile zwischen Punkten) dürfen 1 bis 63 Zeichen lang sein.</li><li>Labels dürfen nur aus Kleinbuchstaben, Ziffern und Bindestrichen (`-`) bestehen.</li><li>Labels dürfen nicht mit einem Bindestrich beginnen oder enden.</li></ul> |
| Header         | `Content-Type: application/json`; `X-Auth: <token>` (Pflicht). |
| Request-Body   | Gültiges JSON-Dokument. Einzelne Objekte erhalten automatisch ein Feld `domain`, sofern es fehlt. |
| Antwort        | `200 OK` (Text: `ok`) bei Erfolg. Fehlerhafte Eingaben erzeugen `400 invalid domain` / `400 invalid json`, fehlende Authentifizierung `401 unauthorized`. Bei gesetztem Rate-Limit werden zusätzlich die Header `X-RateLimit-Limit` und `X-RateLimit-Remaining` übertragen; bei `429 Too Many Requests` kommt `Retry-After` hinzu. |

#### Beispiel-Requests
```bash
curl -X POST "http://localhost:8788/ingest/example.com" \
     -H "Content-Type: application/json" \
     -H "X-Auth: ${LEITSTAND_TOKEN}" \
     -d '{"event": "deploy", "status": "success"}'
```

```bash
http POST :8788/ingest/service.internal event:=\
    "deploy" status:=\"success\" X-Auth:${LEITSTAND_TOKEN}
```

### `GET /health`
* **Header** `X-Auth`: muss ebenfalls dem Wert von `LEITSTAND_TOKEN` entsprechen.
* **Antwort**: `{ "status": "ok" }`. Kann ohne Request-Body abgefragt werden.

### `GET /version`
* **Header** `X-Auth`: identisch zu den anderen Endpunkten.
* **Antwort**: `{ "version": "<wert>" }`. Der Wert entspricht der Konstante `VERSION` bzw. der Umgebungsvariablen `LEITSTAND_VERSION`.

#### Fehlerfälle
| Status | Detail              | Ursache |
|--------|---------------------|---------|
| 400    | `invalid domain`    | Domain verletzt das erlaubte Namensschema |
| 400    | `invalid json`      | Request-Body ist kein gültiges UTF-8/JSON |
| 400    | `invalid payload`   | JSON ist kein Objekt/Array aus Objekten bzw. enthält ungültige Domains |
| 400    | `domain mismatch`   | Eingebettete `domain` unterscheidet sich von der Pfad-Domain |
| 401    | `unauthorized`      | Header `X-Auth` fehlt oder stimmt nicht |
| 411    | `length required`   | `Content-Length`-Header fehlt |
| 413    | `payload too large` | Payload überschreitet 1 MiB |

## Datenpersistenz
Alle Requests werden in Domain-spezifischen JSONL-Dateien gespeichert. Der Dateiname leitet sich aus der Domain ab (`<domain>.jsonl`) und wird nur bei extrem langen Domains mit einem 8-stelligen SHA-Suffix gekürzt. Jede Zeile repräsentiert eine Payload als JSON-String.
```

### 📄 docs/architecture.md

**Größe:** 2 KB | **md5:** `4f848c021505d7cbc57f24c63e08373e`

```markdown
# Architekturübersicht

Leitstand ist ein einfacher Ingest-Dienst, der auf Python und FastAPI basiert. Die Architektur ist darauf ausgelegt, leichtgewichtig und einfach zu betreiben zu sein.

## Komponenten

1.  **FastAPI-Anwendung (`app.py`):**
    *   Dies ist der Kern des Dienstes, der die HTTP-Endpunkte bereitstellt.
    *   Es verwendet `uvicorn` als ASGI-Server.

2.  **Ingest-Endpunkt (`/ingest/{domain}`):**
    *   Nimmt JSON-Daten per `POST`-Request entgegen.
    *   Authentifiziert Anfragen über einen Shared-Secret-Token (`LEITSTAND_TOKEN`), der im `X-Auth`-Header übergeben wird.
    *   Validiert und bereinigt den `domain`-Pfadparameter.

3.  **Speicherschicht (`storage.py`):**
    *   Eingehende Daten werden in domain-spezifischen JSON-Lines-Dateien (`.jsonl`) im `LEITSTAND_DATA_DIR`-Verzeichnis gespeichert.
    *   Die `filelock`-Bibliothek wird verwendet, um Race Conditions beim Schreiben in die Dateien zu verhindern.
    *   Die Funktion `sanitize_domain` stellt sicher, dass Domain-Namen den RFC-ähnlichen Regeln entsprechen.
    *   Die Funktion `secure_filename` sorgt für sichere Dateinamen.

## Datenfluss

1.  Ein Client sendet eine `POST`-Anfrage mit einem JSON-Body an `/ingest/{domain}`.
2.  Die FastAPI-Anwendung empfängt die Anfrage.
3.  Die Authentifizierung wird über den `X-Auth`-Header überprüft.
4.  Der `domain`-Parameter wird validiert und bereinigt.
5.  Die Größe des Request-Bodys wird überprüft (maximal 1 MiB).
6.  Der JSON-Body wird gelesen und validiert.
7.  Die Anwendung fügt dem JSON-Objekt (oder jedem Objekt in einem Array) ein `domain`-Feld hinzu.
8.  Das resultierende JSON-Objekt wird als eine einzelne Zeile in die entsprechende `<domain>.jsonl`-Datei geschrieben.
9.  Ein `FileLock` stellt sicher, dass Schreibvorgänge atomar sind.

## Design-Entscheidungen

Die wichtigsten Architekturentscheidungen sind in den [Architectural Decision Records (ADRs)](adr/README.md) dokumentiert.
```

### 📄 docs/aussen.event.schema.json

**Größe:** 623 B | **md5:** `9de3fd228a48ccd43eff035acdccd88a`

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://example.com/aussen.event.schema.json",
  "title": "Aussen Event",
  "description": "Schema for events from the 'aussen' domain.",
  "type": "object",
  "properties": {
    "event": {
      "description": "The name of the event.",
      "type": "string"
    },
    "status": {
      "description": "The status of the event.",
      "type": "string"
    },
    "domain": {
      "description": "The domain the event belongs to. This is added by the ingest service.",
      "type": "string"
    }
  },
  "required": [
    "event",
    "status"
  ]
}
```

### 📄 docs/cli-curl.md

**Größe:** 720 B | **md5:** `74475a643bde0d81b302c8b8aff136bf`

```markdown
# Curl-Cheatsheet
```bash
# Health
curl -H "X-Auth:$LEITSTAND_TOKEN" http://localhost:8788/health

# Version
curl -H "X-Auth:$LEITSTAND_TOKEN" http://localhost:8788/version

# Ingest Beispiel
curl -X POST "http://localhost:8788/ingest/example.com" \
  -H "Content-Type: application/json" -H "X-Auth: $LEITSTAND_TOKEN" \
  -d '{"event":"deploy","status":"success"}'

# Ingest Array (schreibt zwei JSONL-Zeilen)
curl -X POST "http://localhost:8788/ingest/example.com" \
  -H "Content-Type: application/json" -H "X-Auth: $LEITSTAND_TOKEN" \
  -d '[{"event":"deploy","status":"success"},{"event":"deploy","status":"rollback"}]'

# Ergebnis prüfen (jede Zeile ein Ereignis)
cat "$LEITSTAND_DATA_DIR/example.com.jsonl"

```
```

### 📄 docs/event-contracts.md

**Größe:** 2 KB | **md5:** `55b93b46fa52db5644a57c7daf0994fb`

```markdown
# Event-Contracts

Eingehende Events werden als JSON Lines (NDJSON) in `LEITSTAND_DATA_DIR` gespeichert, wobei jede Datei einer Domain entspricht.
Dieses Dokument beschreibt das empfohlene Schema für Events der Domain `aussen`.

## Schema: `aussen.event.schema.json`

Das folgende JSON-Schema definiert die Struktur für `aussen`-Events. Eine lokale Kopie befindet sich [hier](aussen.event.schema.json).

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://example.com/aussen.event.schema.json",
  "title": "Aussen Event",
  "description": "Schema for events from the 'aussen' domain.",
  "type": "object",
  "properties": {
    "event": {
      "description": "The name of the event.",
      "type": "string"
    },
    "status": {
      "description": "The status of the event.",
      "type": "string"
    },
    "domain": {
      "description": "The domain the event belongs to. This is added by the ingest service.",
      "type": "string"
    }
  },
  "required": [
    "event",
    "status"
  ]
}
```

### Felder
*   `event` (String, erforderlich): Der Name des Events (z. B. `deploy`, `build`).
*   `status` (String, erforderlich): Der Status des Events (z. B. `success`, `failure`).
*   `domain` (String): Die Domain, zu der das Event gehört. Dieses Feld wird vom Ingest-Dienst hinzugefügt.

## Beispiel

Das folgende Beispiel zeigt ein gültiges Event für die `aussen`-Domain:

```json
{"event": "deploy", "status": "success"}
```
Nach der Verarbeitung durch den Dienst wird die Zeile in `aussen.jsonl` so aussehen:

```json
{"event": "deploy", "status": "success", "domain": "aussen"}
```
```

### 📄 docs/mitschreiber-ingest.md

**Größe:** 1 KB | **md5:** `749e721d8ed91ad395b7a17d458a21df`

```markdown
# OS Context Ingest (mitschreiber → leitstand)

leitstand ist Single Point of Ingest, Audit & Panels.

## Endpoints
- `POST /ingest/os/context/state`
- `POST /ingest/os/context/text/embed`

### Auth
- Lokaler Token (env/Secret); mTLS empfohlen, wenn getrennte Prozesse/Hosts.

### Beispiel-Requests
```http
POST /ingest/os/context/state
{
  "ts": "...",
  "source": "os.context.state",
  "app": "code",
  "window": "projX/main.py — VSCode",
  "focus": true,
  "activity_rpm": 240
}
```

```http
POST /ingest/os/context/text/embed
{
  "ts": "...",
  "source": "os.context.text.embed",
  "app": "code",
  "window": "projX/main.py",
  "keyphrases": ["oauth flow", "retry policy"],
  "embedding": [0.012, -0.034, ...],
  "hash_id": "sha256:..."
}
```

## Panels

- **Now:** aktive App/Fenster/Focus.
    
- **Privacy:** Redactions/min, Drops{reason}, Rate-Limit hits.
    
- **Scribe:** Embedding-Heatmap pro App/Workspace.
    

## Retention/TTL

- `os.context.text.embed` → regulär (konfigurierbar).
    
- `os.context.text.redacted` → **nicht** persistieren; nur WAL-Debug (falls überhaupt).
    

## Hinweise

- Validierung über metarepo-Reusable (`reusable-validate-jsonl.yml`).
    
- Audit-Trail für Rejects (Blocklist, PII-Gate, RL).
```

### 📄 docs/operations.md

**Größe:** 2 KB | **md5:** `bdd46d146bd7c776314307513998ee95`

```markdown
# Betriebshandbuch

Dieses Dokument fasst die wichtigsten Betriebs- und Wartungsaufgaben für den Leitstand-Ingest-Dienst zusammen.

## Lifecycle
### Starten
```bash
uvicorn app:app --host 0.0.0.0 --port 8788
```
* Vor dem Start sicherstellen, dass `LEITSTAND_DATA_DIR` beschreibbar ist.
* `LEITSTAND_TOKEN` muss gesetzt sein (ohne Token startet der Dienst nicht).

### Stoppen
* Uvicorn-Prozess kontrolliert beenden (z. B. per `Ctrl+C`, `systemctl stop`, Kubernetes Rollout etc.).
* Warten, bis keine weiteren Schreibzugriffe auf dem Datenverzeichnis stattfinden.

## Überwachung
* **Health**: Ein Test-Request gegen `/ingest/<test-domain>` (ggf. mit Dummy-Token) sollte Status `200` liefern.
* **Logging**: Standardmäßig loggt Uvicorn nach STDOUT. Produktionsumgebungen sollten die Ausgabe an ein Log-Aggregationssystem weiterleiten.
* **Metriken**: Anzahl erfolgreicher Ingest-Requests kann über Log-Analyse oder Reverse-Proxy-Zähler ermittelt werden.

## Sicherheit
* Token regelmäßig rotieren und nur über TLS-geschützte Verbindungen übertragen.
* Datenverzeichnis vor unbefugtem Zugriff schützen (Filesystem-Rechte, Verschlüsselung).
* Eingehende Domains werden validiert; zusätzliche Allow-/Deny-Listen können vorgeschaltet werden.

## Backup & Restore
* JSONL-Dateien sind anhängende Logs. Regelmäßige inkrementelle Backups des Verzeichnisses `LEITSTAND_DATA_DIR` sind ausreichend.
* Für Wiederherstellungen Dateien in ein leeres Datenverzeichnis kopieren und Dienst neu starten.

## Fehlerbehebung
| Symptom                        | Maßnahme |
|--------------------------------|----------|
| `401 unauthorized`             | Token-Header prüfen, Abgleich mit `LEITSTAND_TOKEN`. |
| `400 invalid domain`           | Domain-Format prüfen. Nur Kleinbuchstaben, Ziffern und `-` erlaubt. |
| `400 invalid json`             | Payload auf gültiges JSON prüfen. Sonderzeichen ggf. escapen. |
| Keine neuen Dateien unter `data`| Schreibrechte des Prozesses und Pfadkonfiguration kontrollieren. |
| Dienst startet nicht           | Fehlermeldungen im Uvicorn-Log auswerten, Python-Abhängigkeiten prüfen. |

## Deployment-Hinweise
* Containerisierung: Für Docker-Deployments `LEITSTAND_DATA_DIR` als Volume mounten und `LEITSTAND_TOKEN` per Secret setzen.
* Skalierung: Da pro Request eine Datei geöffnet und beschrieben wird, sollte bei hohem Durchsatz ein vorgeschalteter Message-Broker erwogen werden.
* Infrastruktur: Reverse Proxy (z. B. Traefik, Nginx) kann TLS beenden und Auth-Token verwalten.
```

