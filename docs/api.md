# API-Handbuch

Dieses Dokument beschreibt die HTTP-Schnittstelle des Chronik-Ingest-Dienstes im Detail.

## Übersicht
* Basis-URL: `http://<host>:<port>` (Standard-Port 8788)
* Authentifizierung: Verpflichtender Header `X-Auth` mit dem Wert aus `CHRONIK_TOKEN`
* Datenformat: JSON bzw. Newline-Delimited JSON (NDJSON)
* OpenAPI/Swagger: Automatisch unter `/docs` (Swagger UI) bzw. `/openapi.json` verfügbar

## Endpunkte
### `POST /v1/ingest`
Zentraler Ingest-Endpunkt, der JSON-Objekte, Arrays oder NDJSON entgegennimmt. Die Domain kann über den Query-Parameter `domain` oder über das Feld `domain` im ersten Objekt mitgeliefert werden.

| Eigenschaft    | Beschreibung |
|----------------|--------------|
| Methode        | `POST` |
| Pfadparameter  | keine |
| Query-Parameter| `domain` (optional) – Ziel-Domain; wird in Kleinbuchstaben umgewandelt und muss die FQDN-Regeln erfüllen (siehe Abschnitt "Fehlerfälle" zur Domain-Validierung) |
| Header         | `Content-Type: application/json` **oder** `Content-Type: application/x-ndjson`; `X-Auth: <token>` (Pflicht). |
| Request-Body   | **JSON:** Objekt oder Array von Objekten. **NDJSON:** Zeilenweise JSON-Objekte (`\n`-getrennt); leere Zeilen werden ignoriert. Für jedes Objekt wird ein Feld `domain` ergänzt, falls es fehlt. Optionales Feld `summary` darf max. 500 Zeichen lang sein. |
| Antwort        | `202 Accepted` (Text: `ok`) bei Erfolg. Fehlerhafte Eingaben erzeugen u. a. `400 invalid json/invalid ndjson/invalid payload/domain must be specified ...`, falsche Authentifizierung `401 unauthorized`, fehlende Länge `411 length required`, zu große Payload `413 payload too large`, falscher Content-Type `415 unsupported content-type`, zu lange Summary `422 summary too long (max 500)`, Rate-Limit `429 too many requests`, Platzmangel `507 insufficient storage`. |

#### Beispiel-Requests
```bash
curl -X POST "http://localhost:8788/v1/ingest?domain=example.com" \
     -H "Content-Type: application/json" \
     -H "X-Auth: ${CHRONIK_TOKEN}" \
     -d '{"event": "deploy", "status": "success"}'
```

```bash
http POST :8788/v1/ingest \
    domain==service.internal \
    event=deploy status=success X-Auth:${CHRONIK_TOKEN}
```

### `POST /ingest/{domain}` (deprecated)
Frühere Variante, die weiterhin unterstützt wird. Die Domain wird im Pfad angegeben; der Endpunkt ist als veraltet markiert und sollte durch `/v1/ingest` ersetzt werden.

| Eigenschaft    | Beschreibung |
|----------------|--------------|
| Methode        | `POST` |
| Pfadparameter  | `domain` – wird in Kleinbuchstaben umgewandelt und muss den FQDN-Regeln entsprechen |
| Header         | `Content-Type: application/json`; `X-Auth: <token>` (Pflicht). |
| Request-Body   | JSON-Objekt oder Array aus Objekten. Jedes Objekt erhält automatisch das Feld `domain`, sofern es fehlt. Optionales Feld `summary` darf max. 500 Zeichen lang sein. |
| Antwort        | `202 Accepted` (Text: `ok`) bei Erfolg. Fehlerhafte Eingaben erzeugen `400 invalid json/invalid payload/domain mismatch`, falsche Authentifizierung `401 unauthorized`, fehlende Länge `411 length required`, zu große Payload `413 payload too large`, zu lange Summary `422 summary too long (max 500)`, Rate-Limit `429 too many requests`, Platzmangel `507 insufficient storage`. |

#### Beispiel-Request
```bash
curl -X POST "http://localhost:8788/ingest/example.com" \
     -H "Content-Type: application/json" \
     -H "X-Auth: ${CHRONIK_TOKEN}" \
     -d '{"event": "deploy", "status": "success"}'
```

### `GET /v1/events` (Consumer Pull)
Empfohlener Endpunkt für Consumer (Heimlern, Leitstand), um Events stapelweise und robust abzurufen.

| Eigenschaft    | Beschreibung |
|----------------|--------------|
| Methode        | `GET` |
| Query-Parameter| `domain` (Pflicht); `limit` (max 2000, default 100); `cursor` (Byte-Offset, default 0). |
| Antwort        | JSON-Objekt mit `events` (Liste von `base.event` Objekten), `next_cursor` (Integer oder null bei EOF), `has_more` (Boolean), `meta` (Count/Timestamp). |

### `GET /v1/tail` (deprecated)
Legacy-Endpunkt, um die letzten N Events zu lesen. Sollte durch `/v1/events` ersetzt werden.

### `GET /v1/latest` (deprecated)
Legacy-Endpunkt, um das allerletzte Event zu lesen. Sollte durch `/v1/events` ersetzt werden.

### `GET /health`
* **Header** `X-Auth`: muss dem Wert von `CHRONIK_TOKEN` entsprechen.
* **Antwort**: `{ "status": "ok" }`. Kann ohne Request-Body abgefragt werden.

### `GET /version`
* **Header** `X-Auth`: muss dem Wert von `CHRONIK_TOKEN` entsprechen.
* **Antwort**: `{ "version": "<wert>" }`. Der Wert entspricht der Konstante `VERSION` bzw. der Umgebungsvariablen `CHRONIK_VERSION`.

#### Fehlerfälle
| Status | Detail                         | Ursache |
|--------|--------------------------------|---------|
| 400    | `invalid domain`               | Domain verletzt das erlaubte Namensschema |
| 400    | `invalid json` / `invalid ndjson` | Request-Body ist kein gültiges UTF-8/JSON bzw. NDJSON |
| 400    | `invalid payload`              | JSON ist kein Objekt/Array aus Objekten bzw. enthält ungültige Domains |
| 400    | `domain mismatch`              | Eingebettete `domain` unterscheidet sich von der Pfad-/Query-Domain |
| 400    | `domain must be specified via query or payload` | Bei `/v1/ingest` fehlt die Domain sowohl in Query als auch im ersten Objekt |
| 401    | `unauthorized`                 | Header `X-Auth` fehlt oder stimmt nicht |
| 411    | `length required`              | `Content-Length`-Header fehlt |
| 413    | `payload too large`            | Payload überschreitet 1 MiB |
| 415    | `unsupported content-type`     | Content-Type ist weder JSON noch NDJSON |
| 422    | `summary too long (max 500)`   | Feld `summary` überschreitet 500 Zeichen |
| 429    | `too many requests`            | Rate-Limit überschritten |
| 507    | `insufficient storage`         | Beim Schreiben nicht genug Speicherplatz |

## Datenpersistenz
Alle Requests werden in Domain-spezifischen JSONL-Dateien gespeichert. Der Dateiname leitet sich aus der Domain ab (`<domain>.jsonl`) und wird nur bei extrem langen Domains mit einem 8-stelligen SHA-Suffix gekürzt. Jede Zeile repräsentiert eine Payload als JSON-String.
