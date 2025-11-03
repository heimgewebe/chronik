### 📄 merges/leitstand_merge_2510262237__.github_workflows.md

**Größe:** 2 KB | **md5:** `f47ffcb1517e54615ace5bf795015a70`

```markdown
### 📄 .github/workflows/validate-aussen-fixtures.yml

**Größe:** 1 KB | **md5:** `e27e39e8fcedf8853dfdcdbbf63bf675`

```yaml
name: validate (aussen fixtures)
on:
  push:
  pull_request:
  workflow_dispatch:

# Principle of least privilege
permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: false

jobs:
  fixtures:
    name: fixtures (aussen JSONL)
    # Nur laufen, wenn mind. eine Fixture existiert
    if: hashFiles('tests/fixtures/aussen/*.jsonl') != ''
    # ⚠️ Pin auf immutablen Tag/Commit (statt main)
    uses: heimgewebe/metarepo/.github/workflows/reusable-validate-jsonl.yml@contracts-v1
    with:
      # Das Reusable erwartet (Fleet-Variante) einen einzelnen Pfad:
      # Für den Anfang prüfen wir die Beispiel-Fixture. Wenn weitere Dateien dazukommen,
      # entweder weitere Jobs anlegen oder das Reusable auf Mehrfachpfade erweitern.
      jsonl_path: tests/fixtures/aussen/sample-ok.jsonl
      # ⚠️ Schema-URL ebenfalls an den gleichen Tag pinnen
      schema_url: https://raw.githubusercontent.com/heimgewebe/metarepo/contracts-v1/contracts/aussen.event.schema.json
      strict: false
      validate_formats: true
```

### 📄 .github/workflows/validate-leitstand-fixtures.yml

**Größe:** 965 B | **md5:** `31acdc7a29704c7bf3f975bbde0ee82a`

```yaml
name: validate-leitstand-fixtures
permissions:
  contents: read

on:
  push:
  pull_request:

jobs:
  fixtures:
    name: fixtures (tests/fixtures/leitstand.jsonl)
    if: hashFiles('tests/fixtures/leitstand.jsonl') != ''
    uses: heimgewebe/metarepo/.github/workflows/reusable-validate-jsonl.yml@codex/add-github-workflows
    with:
      jsonl_path: tests/fixtures/leitstand.jsonl
      schema_url: https://raw.githubusercontent.com/heimgewebe/metarepo/main/contracts/leitstand-fixtures.schema.json
      strict: false
      validate_formats: true

  demo:
    name: demo (demo/leitstand.jsonl)
    if: hashFiles('demo/leitstand.jsonl') != ''
    uses: heimgewebe/metarepo/.github/workflows/reusable-validate-jsonl.yml@codex/add-github-workflows
    with:
      jsonl_path: demo/leitstand.jsonl
      schema_url: https://raw.githubusercontent.com/heimgewebe/metarepo/main/contracts/leitstand-fixtures.schema.json
      strict: false
      validate_formats: true
```
```

### 📄 merges/leitstand_merge_2510262237__data.md

**Größe:** 150 B | **md5:** `aa828977f7b0cd59d13bf4da2ff1ec81`

```markdown
### 📄 data/.gitignore

**Größe:** 41 B | **md5:** `ec738530cd7273aa09efa2d592a876ba`

```plaintext
# Ingested data and locks
*.jsonl
*.lock
```
```

### 📄 merges/leitstand_merge_2510262237__demo.md

**Größe:** 152 B | **md5:** `88d72c6c63c70e58c3104cb67160b455`

```markdown
### 📄 demo/.gitkeep

**Größe:** 45 B | **md5:** `2ae2b7237f025a0c08b914eb3c87dc39`

```plaintext
# Placeholder to keep demo directory tracked
```
```

### 📄 merges/leitstand_merge_2510262237__docs.md

**Größe:** 12 KB | **md5:** `42106a918d83714498ba8781dc1ca3b3`

```markdown
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
```

### 📄 merges/leitstand_merge_2510262237__docs_adr.md

**Größe:** 1 KB | **md5:** `e3430bd86f449f5a835d4402dea52830`

```markdown
### 📄 docs/adr/0001-python-fastapi-panels.md

**Größe:** 340 B | **md5:** `4af2d5ce2d5fb8a77410968008b21b26`

```markdown
# ADR-0001: Python/FastAPI für Ingest & Panels
Status: Accepted
Date: 2025-10-12

## Kontext
Schnelle IO/UI-Iteration, geringe Einstiegshürde.

## Entscheidung
- Python (FastAPI) für Ingest, später Panels.

## Konsequenzen
- Schneller MVP; bei Bedarf Rust-Worker daneben.

## Alternativen
- Rust-Only: mehr Entwicklungsaufwand für UI.
```

### 📄 docs/adr/0002-data-jsonl-per-domain.md

**Größe:** 398 B | **md5:** `6de517f4f3af39e46f5946161e11df57`

```markdown
# ADR-0002: Per-Domain JSONL in `data/` + verpflichtendes Token
Status: Accepted
Date: 2025-10-12

## Kontext
Einfacher Speicher für eingehende Events.

## Entscheidung
- Append-only `data/{domain}.jsonl`
- Header `x-auth` ist verpflichtend und muss mit `LEITSTAND_TOKEN` übereinstimmen

## Konsequenzen
- Einfach zu debuggen; Logs git-ignorieren.

## Alternativen
- DB früh: unnötig für MVP.
```

### 📄 docs/adr/README.md

**Größe:** 219 B | **md5:** `ba08bde8bf1388440cc252feda49a816`

```markdown
# Architekturentscheidungsaufzeichnungen (ADR)

- [ADR-0001: Python/FastAPI für Ingest & Panels](0001-python-fastapi-panels.md)
- [ADR-0002: Per-Domain JSONL in `data/` + optional Token](0002-data-jsonl-per-domain.md)
```
```

### 📄 merges/leitstand_merge_2510262237__index.md

**Größe:** 15 KB | **md5:** `33448d27ec2ada9f59d76d2ed399cabe`

```markdown
# Ordner-Merge: leitstand

**Zeitpunkt:** 2025-10-26 22:37
**Quelle:** `/home/alex/repos/leitstand`
**Dateien (gefunden):** 28
**Gesamtgröße (roh):** 47 KB

**Exclude:** ['.gitignore']

## 📁 Struktur

- leitstand/
  - .env.example
  - .gitignore
  - .hauski-reports
  - LICENSE
  - Makefile
  - README.md
  - app.py
  - requirements.txt
  - storage.py
  - test_app.py
  - tests/
    - fixtures/
      - .gitkeep
      - aussen/
        - sample-ok.jsonl
  - demo/
    - .gitkeep
  - docs/
    - api.md
    - architecture.md
    - aussen.event.schema.json
    - cli-curl.md
    - event-contracts.md
    - mitschreiber-ingest.md
    - operations.md
    - adr/
      - 0001-python-fastapi-panels.md
      - 0002-data-jsonl-per-domain.md
      - README.md
  - .github/
    - workflows/
      - validate-aussen-fixtures.yml
      - validate-leitstand-fixtures.yml
  - .git/
    - FETCH_HEAD
    - HEAD
    - ORIG_HEAD
    - config
    - index
    - packed-refs
    - hooks/
      - pre-push
    - refs/
      - remotes/
        - origin/
          - HEAD
          - alert-autofix-10
          - alert-autofix-11
          - alert-autofix-12
          - alert-autofix-14
          - alert-autofix-20
          - alert-autofix-24
          - docs-verbesserung
          - fix-negative-content-length
          - fix-path-traversal
          - improve-security-and-robustness
          - main
          - refactor-ingest-validation
          - test-improve-secure-filename
          - refactor/
            - code-review-improvements
          - codex/
            - add-event-contracts-and-curl-cheatsheet
            - add-file-name-validation-and-security-measures
            - add-github-actions-for-validating-fixtures
            - add-production-token-requirement-for-fastapi
            - add-readme-quickstart-snippet
            - add-slowapi-and-prometheus-fastapi-instrumentator
            - add-slowapi-middleware-for-rate-limiting
            - add-validation-for-aussen-fixtures
            - add-workflow-for-validate-leitstand-fixtures
            - document-os-context-ingest-endpoints
            - find-errors-in-the-code
            - find-errors-in-the-code-jnmq9e
            - fix-integration-issues-and-update-documentation
            - harden-file-writing-with-dirfd
            - locate-errors-in-the-code
            - merge-patches-for-app.py-and-test_app.py
            - recreate-pr-with-optimizations
            - refactor-dependency-order-for-auth-and-size-check
            - uberprufen-der-dokumentation-auf-vollstandigkeit
            - update-auth-and-size-check-order
            - update-readme-and-implement-makefile-targets
            - update-readme-with-api-and-documentation-links
            - update-readme.md-with-new-parameters
          - feat/
            - improve-robustness-and-tests
      - tags/
      - heads/
        - main
        - backup/
          - main-20251017-182444
          - main-20251018-090519
          - main-20251021-124256
          - main-20251023-070601
          - main-20251025-233731
          - main-20251026-090522
    - logs/
      - HEAD
      - refs/
        - remotes/
          - origin/
            - HEAD
            - alert-autofix-10
            - alert-autofix-11
            - alert-autofix-12
            - alert-autofix-14
            - alert-autofix-20
            - alert-autofix-24
            - docs-verbesserung
            - fix-negative-content-length
            - fix-path-traversal
            - improve-security-and-robustness
            - main
            - refactor-ingest-validation
            - test-improve-secure-filename
            - refactor/
              - code-review-improvements
            - codex/
              - add-event-contracts-and-curl-cheatsheet
              - add-file-name-validation-and-security-measures
              - add-github-actions-for-validating-fixtures
              - add-production-token-requirement-for-fastapi
              - add-readme-quickstart-snippet
              - add-slowapi-and-prometheus-fastapi-instrumentator
              - add-slowapi-middleware-for-rate-limiting
              - add-validation-for-aussen-fixtures
              - add-workflow-for-validate-leitstand-fixtures
              - document-os-context-ingest-endpoints
              - find-errors-in-the-code
              - find-errors-in-the-code-jnmq9e
              - fix-integration-issues-and-update-documentation
              - harden-file-writing-with-dirfd
              - locate-errors-in-the-code
              - merge-patches-for-app.py-and-test_app.py
              - recreate-pr-with-optimizations
              - refactor-dependency-order-for-auth-and-size-check
              - uberprufen-der-dokumentation-auf-vollstandigkeit
              - update-auth-and-size-check-order
              - update-readme-and-implement-makefile-targets
              - update-readme-with-api-and-documentation-links
              - update-readme.md-with-new-parameters
            - feat/
              - improve-robustness-and-tests
        - heads/
          - main
          - backup/
            - main-20251017-182444
            - main-20251018-090519
            - main-20251021-124256
            - main-20251023-070601
            - main-20251025-233731
            - main-20251026-090522
    - objects/
      - b0/
        - 02b4654336955a49f975059431cfb17b664de2
        - 2a2252205fdb7e7cbdcc36a80ef910835f34d6
        - b7e04baa04c11862f2496022064b42f8635375
      - 48/
        - d782cfdbd4cb050a9364ef4478aa157bdab862
      - e5/
        - 05428821942aa86c8a3d5e922e0ac0784b3e85
        - d2a477f2c41e3ee9266bff3ff095b2dc651dcb
      - 0d/
        - 141d039bd6429c17e4f2a1ac10d9be817b6ea4
      - 6d/
        - ee7c22087e7418beec9b5863311511f8f1f3a8
      - 06/
        - 05e50e0a9ab4d5b32f40520b335e6e68d1d08e
      - c7/
        - 52858e2205724f7bd6409ce0cd30f1d930a3e4
      - 23/
        - 0181fd0dde6026f8c5b80ed486564e7e51058e
      - 4d/
        - 3db749a10f612a08b4dd9917f2375900e793c0
      - 78/
        - 24da42f53cca726d02e72c329325fdc0b084ee
      - b9/
        - d7caabc1b342234d6103f349922aa65d931cc9
      - 54/
        - 725a8ac2a269e92d1240738e50ce5c03f4daab
        - a400c0faa70a0c44dea3c02acf876d5b7ae983
      - 17/
        - 66543e5f1a743e6c6ca12d72c7a1b77e843188
      - a8/
        - 557b3421ec61ed43f9e9e30052834408b31c2a
      - 68/
        - ee39728cd7ff1d3940a070438bbb9ee4e6e090
      - 4f/
        - 6918bcd981b21e9577c4a23b45791ec38584d5
      - fd/
        - 57deb0051d9b6c179e78d272899d5eff225f4d
      - 77/
        - b263e9e5f18c64e57b1e9378922b4ccec8e156
      - 3e/
        - 1d0900b4ec6a2a29acb2fbce750c5d78a9815a
        - fd76d2ed202c43f32cde89ad00f3a7d1f30487
      - 2c/
        - d080f97740de737d1b6920226ac963c56af024
      - 4a/
        - 881f9b4bd2ef0ad30fe0338de113977a0d0bb2
      - 01/
        - bdd343b24579e120a1cdd0ba97110b4ff6c76d
      - dd/
        - eba2ab65b0ce44b8c7acffad096472ba6fe7c2
      - 0f/
        - 66cf8699c3c6569893e843edaa5f365334a106
      - pack/
        - pack-c4953cac03a70bf795c02c2d1e1f3e92c055a406.idx
        - pack-c4953cac03a70bf795c02c2d1e1f3e92c055a406.pack
        - pack-f993df91e5a612b96b95be5fa90ea698322052f0.idx
        - pack-f993df91e5a612b96b95be5fa90ea698322052f0.pack
      - 11/
        - 740ed232e50c47c30bd003fd2b2b987f1cd3e2
      - 92/
        - c21ac81d9a19755072aac7468bb7056ff1008f
      - e9/
        - 81b4948e7cb8306f4c067a3e117b7492e11304
        - 9931e30cc519ced01b4f55a0767903d7cf06ea
      - 18/
        - 00fbb12f1b1279ea90e6ea5e474350f6f6a5ee
        - 3f6c50ad62fe576d429c1438155e07115c9846
      - a3/
        - d4cb150363aed3746f91b22020f430bed99fa0
      - a4/
        - 8ef43b89112e8cc4cc4d8326b1b84de4900ad9
      - 2e/
        - b4b90c5acb96caf863b6bed1d99b4707fb3c96
      - e4/
        - 7757494d20abb7c837c9e2e798ca3892d96f13
      - d4/
        - 10f6a9e40011faec57844eae76c069876f050a
        - 1b62d621725da7b509c03ed7bd4da06f6d4e22
        - 3cea09f4725b4cefa8febd1b5ea561870fe977
      - aa/
        - aaa2b6af12182b5b9a3969b6044692d404abdb
      - 4b/
        - 30c4c0b663c616f86c618274e895db14201e6e
        - e4629eba70c3a43fe81be55056a1dd508a4551
      - a1/
        - 3c4ebbf668f624569eafc786f42d3d6df38ba8
      - ff/
        - c2d00ee17133bfd03209503b4bdeb41d5c3644
      - e6/
        - de82156828c601c1564ca99a93e585125e4a30
      - 5b/
        - 8a7deb70f4c575ec90a82988cc6ac77b4935bf
        - 8e2fb62d323488e6ab1f9f614f3d7fa8a571f3
      - 95/
        - 2f7eeea18e8f8b2d91338358cf1fac171bf679
        - 44850e1cedd4f936d8eed99ec7b416721c45a6
      - 61/
        - c44036b6340ea56e4c952c01e4f0703dbc79f7
      - 5f/
        - 6930daaa73b369d6ecaca6949b9ccc54749418
      - f0/
        - 1e1c038f8ea5185644a3549f63d340ce9e2e06
      - 30/
        - 75734213b4316706eead21241a1f0d94fca956
      - 7a/
        - 3d2776c0ffb57b833a5339550a229caa0f2683
      - 16/
        - b3d69a7bd8d1e18898559ac5dd619012212ac2
      - fb/
        - 5cd9255a6bd28e42d3ba663b94d109c90c9e4f
      - ed/
        - 180d38315357389cedaf9e3b14aef8730ee9b0
      - 53/
        - f60e310f312ced9269c07c440c50b52861340b
      - d9/
        - 3655c0c30814a318cdd2e8bd145c13fbef2e79
      - 03/
        - 41839220d60fe77f565085c90a3e60fe4a6f19
      - e8/
        - 5f90ed38cc680d48a2436a0c6a22b370acb952
      - 80/
        - d058f4f5f521b814be3d73b62f43c2cc688234
      - 27/
        - 16d71903e5fde29595624deba93bd0ba6408a7
      - 3a/
        - bf572311bbcaff35477d177c0422e2d2629bea
      - e2/
        - b9b52a03cc26f6a165cad18cd7b212f0ddfd00
        - f79b86605a133f316fa06ffcbf9611d78fd336
      - ce/
        - 3abb3163f65fdb4c747f7301bd9743e0a7d480
      - b3/
        - 20abc89d468c685111c0ee960229d10808e72e
      - 9c/
        - 0f8c3992d81eea4e1cc3c4311ac8daf872a725
      - 35/
        - 72f035d0b81128867e4dec92dd3719c1a7789c
        - 8c696c5c56da54014063e0b960b195f652eaec
      - 79/
        - cc14ed33388d48a0f625128b234450e275859a
      - e1/
        - 28b24dc39d853d171b98cc3b3a5c7385609dc7
        - 5f9da7784c9cc96f4778d92d3479ece7aea667
      - 39/
        - 993c6b4bb3cddd93ae2db6cf078143f06cf270
      - 58/
        - d9ad0422dac9bdd63b530458656527e6b73406
      - b1/
        - cdcc5acceeaaad2dd0cf5772ec515a8a586360
      - 85/
        - b048688ff7e97fbafaf912ea9793bffc402733
        - bf12facd0dd73e0ced36f7cf168248d1c4e50a
      - ae/
        - f1b0b1165bbb8f303a13461e24209be4bc6779
        - fdaf4aca87a0828a4a26a24c494088c97980f1
      - da/
        - b9337366cf8e0bcc8f88de03fa38a0cc86c4c4
      - f2/
        - 1ecd3fc9e3813a9d24ae8d9c72c7ed7c93d5b2
      - 7f/
        - 94df07063adf606e790e1ca9c7f56927f53f47
      - 9d/
        - fbf2b45ea214bc01e485142e188b11ea6249f1
      - 25/
        - c3cdea22eac84c7dee2d87f9ef4d74e6b8bc24
      - 6c/
        - 0eb3ff5d8d6a11f6466722c9d7eb14d0288f26
        - fdde22ec0579e5775eed79d183aacf707bcd72
      - bf/
        - a17a91e66c05c9c05035db006a3cbdaeb38180
      - c1/
        - e10a5a9db4494ff73537424b98003373323c91
      - 05/
        - 0694e339b3a2a4e697a6421783aa3145ca3294
      - db/
        - 26f0b497e43f81804de2db5b3be3346dbffea3
      - 42/
        - 3743ecab08a67648a06ab1f5b63f6b63a40030
        - daee96b65d1363ec708ca07d21a56794d9e701
      - a7/
        - 50be8baa5adbbdf9480f115495ece4be764113
        - d3e4a5dca70eb24886e20bcbac0b4dbb7ee31c
      - e3/
        - cdb8f95c70443c08fe6ba804281b7b1b42095e
      - ea/
        - fff807cba23bd394f36c3178b0349106371ec8
      - 0c/
        - 2e5fdfac7ae72001f8d7f0abcdc1da4fb5ea83
        - ae80ebe2c6f51cfcd3b26610fdbde8d5464f3e
        - f146960a4ef3ef86652c098cc47ab65154be3b
      - 93/
        - 48a6e472f8d83a7771876aea144708cd0a887b
        - 6a457a5a69e93e5c883b7bee7d0c20731c3998
      - 67/
        - 47f9beb007f2fd5bc214a9e08a9fc91ba5000f
      - info/
      - 86/
        - d234b903ef96225fbc725ff21b050f903f4b1b
      - 15/
        - 192e9fee82e5d5bfcd209a692cf05a8c03ba14
        - db5f322f2d75d0792e39852698c6ae0f13dd53
      - 40/
        - 41f16d545537ac659d14c2d282bb80150b098b
      - 88/
        - 52045c10de01503df15c593295424958e3cb13
        - c2598a76ed8b08121f6d454b0546992f6e7061
      - 4e/
        - a4a00aa5c712b73ae45b6a3ee7e02fa6f5a82b
      - cf/
        - 3038aff76f2835cc9cf1c5d06371e28037c5e7
      - 34/
        - c20bf78618bbb899f027d2b5b1c391554adee8
      - 5c/
        - 848bfedfbf42223383df8d2dad93091cd2e7db
      - d5/
        - c4f1cdcd1efb6e415e08b5bcc7b390eed24212
      - a2/
        - 6a3a3d16e2509da91bff5c4d84bd2ab6e7795d
        - d551e40dcf1099ebc1af50806035344ab60d1f
      - 5e/
        - 3617175bbffceec2c36635685d44de31dd85b0
        - 579fb0df6c2432cba404097024dcb297ae1caa
        - dc959a626849bdf21ee30faeb953767a9c5165
  - merges/
    - leitstand_merge_2510262237__index.md
  - scripts/
    - ingest_append.py
    - panel_dump.sh
    - push_leitstand.sh
  - data/
    - .gitignore

## 📦 Inhalte (Chunks)

- .env.example → `leitstand_merge_2510262237__root.md`
- .gitignore → `leitstand_merge_2510262237__root.md`
- LICENSE → `leitstand_merge_2510262237__root.md`
- Makefile → `leitstand_merge_2510262237__root.md`
- README.md → `leitstand_merge_2510262237__root.md`
- app.py → `leitstand_merge_2510262237__root.md`
- requirements.txt → `leitstand_merge_2510262237__root.md`
- storage.py → `leitstand_merge_2510262237__root.md`
- test_app.py → `leitstand_merge_2510262237__root.md`
- tests/fixtures/.gitkeep → `leitstand_merge_2510262237__tests_fixtures.md`
- tests/fixtures/aussen/sample-ok.jsonl → `leitstand_merge_2510262237__tests_fixtures_aussen.md`
- demo/.gitkeep → `leitstand_merge_2510262237__demo.md`
- docs/api.md → `leitstand_merge_2510262237__docs.md`
- docs/architecture.md → `leitstand_merge_2510262237__docs.md`
- docs/aussen.event.schema.json → `leitstand_merge_2510262237__docs.md`
- docs/cli-curl.md → `leitstand_merge_2510262237__docs.md`
- docs/event-contracts.md → `leitstand_merge_2510262237__docs.md`
- docs/mitschreiber-ingest.md → `leitstand_merge_2510262237__docs.md`
- docs/operations.md → `leitstand_merge_2510262237__docs.md`
- docs/adr/0001-python-fastapi-panels.md → `leitstand_merge_2510262237__docs_adr.md`
- docs/adr/0002-data-jsonl-per-domain.md → `leitstand_merge_2510262237__docs_adr.md`
- docs/adr/README.md → `leitstand_merge_2510262237__docs_adr.md`
- .github/workflows/validate-aussen-fixtures.yml → `leitstand_merge_2510262237__.github_workflows.md`
- .github/workflows/validate-leitstand-fixtures.yml → `leitstand_merge_2510262237__.github_workflows.md`
- scripts/ingest_append.py → `leitstand_merge_2510262237__scripts.md`
- scripts/panel_dump.sh → `leitstand_merge_2510262237__scripts.md`
- scripts/push_leitstand.sh → `leitstand_merge_2510262237__scripts.md`
- data/.gitignore → `leitstand_merge_2510262237__data.md`
```

### 📄 merges/leitstand_merge_2510262237__part001.md

**Größe:** 43 B | **md5:** `ad150e6cdda3920dbef4d54c92745d83`

```markdown
<!-- chunk:1 created:2025-10-26 22:37 -->
```

### 📄 merges/leitstand_merge_2510262237__root.md

**Größe:** 30 KB | **md5:** `e2fb14d1d4825c2a6d63a13ffec4fbc3`

```markdown
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



<<TRUNCATED: max_file_lines=800>>
```

### 📄 merges/leitstand_merge_2510262237__scripts.md

**Größe:** 3 KB | **md5:** `74a95e0a5bbbbe20bf73339667ed7c1d`

```markdown
### 📄 scripts/ingest_append.py

**Größe:** 1 KB | **md5:** `c6565895a7fe668ad36f0d4a40d7834e`

```python
#!/usr/bin/env python3
"""CLI helper to append JSON payloads in the same format as the API."""

from __future__ import annotations

import json
import sys

from storage import DATA_DIR, DomainError, safe_target_path, sanitize_domain


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: ingest_append.py <domain> <json-payload>", file=sys.stderr)
        return 2

    _, domain, raw_payload = argv

    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError as exc:
        print(f"invalid json payload: {exc}", file=sys.stderr)
        return 1

    try:
        dom = sanitize_domain(domain)
        target_path = safe_target_path(dom, data_dir=DATA_DIR)
    except DomainError:
        print("invalid domain", file=sys.stderr)
        return 1

    if not isinstance(payload, dict):
        print("payload must be a JSON object", file=sys.stderr)
        return 1

    payload = dict(payload)
    payload["domain"] = dom

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    with target_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")

    print(str(target_path))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv))
```

### 📄 scripts/panel_dump.sh

**Größe:** 122 B | **md5:** `c4c2f56243882b4edaaa010ccaa39d76`

```bash
#!/usr/bin/env bash
set -euo pipefail
domain="${1:-pc}"
file="data/${domain}.jsonl"
[ -f "$file" ] && cat "$file" || true
```

### 📄 scripts/push_leitstand.sh

**Größe:** 1 KB | **md5:** `c8f2929cb7e635a5facf735d0568b14a`

```bash
#!/usr/bin/env bash
# Push die letzten N Meldungen aus einer JSONL/JSON-Stream-Datei sicher zum Leitstand.
# Multiline/pretty-printed Einträge werden vorab zu 1-Zeilen-Objekten verdichtet.
set -euo pipefail

# Eingaben
: "${FILE:?Pfad zur JSONL/JSON-Stream-Datei fehlt (FILE)}"
: "${URL:?Basis-URL vom Leitstand fehlt (URL)}"
: "${DOMAIN:?Domain fehlt (DOMAIN)}"
: "${N:?Anzahl letzter Events fehlt (N)}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Fehlt: $1" >&2; exit 127; }; }
need jq
need curl

# 1) Kompakter JSON-Stream: Jede Zeile = ein vollständiges JSON-Objekt.
#    jq liest robuste JSON-Streams (mehrere JSON-Werte hintereinander, auch pretty-printed).
#    Danach nehmen wir die letzten N Objekte.
jq -c . "$FILE" | tail -n "$N" | while IFS= read -r line; do
  # Skip leere Zeilen (sollte mit jq -c nicht vorkommen, aber sicher ist sicher)
  [ -z "$line" ] && continue
  # 2) POST an /ingest/<domain>
  if [ -n "${LEITSTAND_TOKEN:-}" ]; then
    curl -fsS \
      -H 'content-type: application/json' \
      -H "x-auth: ${LEITSTAND_TOKEN}" \
      --data-binary "$line" \
      "${URL%/}/ingest/$DOMAIN"
  else
    curl -fsS \
      -H 'content-type: application/json' \
      --data-binary "$line" \
      "${URL%/}/ingest/$DOMAIN"
  fi
done

echo "✓ Gesendet: letzte ${N} Events aus $(basename "$FILE") → ${URL%/}/ingest/$DOMAIN" >&2
```
```

### 📄 merges/leitstand_merge_2510262237__tests_fixtures.md

**Größe:** 166 B | **md5:** `1a562c29c0c6f821b7447c548120d56a`

```markdown
### 📄 tests/fixtures/.gitkeep

**Größe:** 49 B | **md5:** `16f54d60c1407584703fff432669b8a0`

```plaintext
# Placeholder to keep fixtures directory tracked
```
```

### 📄 merges/leitstand_merge_2510262237__tests_fixtures_aussen.md

**Größe:** 246 B | **md5:** `b0e23239ae6622238fa8a92c2548e1db`

```markdown
### 📄 tests/fixtures/aussen/sample-ok.jsonl

**Größe:** 114 B | **md5:** `6430fa7237fd5e5b7b6ac45851679937`

```plaintext
{"type":"aussen.event","source":"demo","domain":"example.com","status":"ok","ingested_at":"2025-10-18T18:00:00Z"}
```
```

