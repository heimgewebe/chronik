# API-Handbuch

Dieses Dokument beschreibt die HTTP-Schnittstelle des Leitstand-Ingest-Dienstes im Detail.

## Übersicht
* Basis-URL: `http://<host>:<port>` (Standard-Port 8788)
* Authentifizierung: Optionaler Header `X-Auth`, sofern `LEITSTAND_TOKEN` gesetzt ist
* Datenformat: JSON bzw. JSON Lines
* OpenAPI/Swagger: Automatisch unter `/docs` (Swagger UI) bzw. `/openapi.json` verfügbar

## Endpunkte
### `POST /ingest/{domain}`
Übernimmt beliebige JSON-Payloads und speichert sie domain-spezifisch.

| Eigenschaft    | Beschreibung |
|----------------|--------------|
| Methode        | `POST` |
| Pfadparameter  | `domain` – wird in Kleinbuchstaben gewandelt und muss dem regulären Ausdruck `^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(?:\.(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?))*$` entsprechen. |
| Header         | `Content-Type: application/json`; `X-Auth: <token>` sofern `LEITSTAND_TOKEN` gesetzt ist. |
| Request-Body   | Gültiges JSON-Dokument. Einzelne Objekte erhalten automatisch ein Feld `domain`, sofern es fehlt. |
| Antwort        | `200 OK` (Text: `ok`) bei Erfolg. Fehlerhafte Eingaben erzeugen `400 invalid domain` / `400 invalid json`, fehlende Authentifizierung `401 unauthorized`. |

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

#### Fehlerfälle
| Status | Detail              | Ursache |
|--------|---------------------|---------|
| 400    | `invalid domain`    | Domain verletzt das erlaubte Namensschema |
| 400    | `invalid json`      | Request-Body ist kein gültiges UTF-8/JSON |
| 401    | `unauthorized`      | Header `X-Auth` fehlt oder stimmt nicht |

## Datenpersistenz
Alle Requests werden in Domain-spezifischen JSONL-Dateien gespeichert. Der Dateiname ergibt sich aus dem SHA-256-Hash der Domain (`<hash>[:32].jsonl`). Jede Zeile repräsentiert eine Payload als JSON-String.
