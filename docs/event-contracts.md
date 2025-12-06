# Event Contracts

Dieses Dokument beschreibt die Event-Felder, die **chronik** akzeptiert und speichert.

## 🔗 Beziehung zu den zentralen Heimgewebe-Contracts

chronik ist Teil des systemweiten Event-Backbones.
Die **kanonischen Contracts** (Draft 2020-12) liegen im **metarepo** unter:

  • `contracts/aussen.event.schema.json`
  • `contracts/event.line.schema.json`
  • `contracts/fixtures.schema.json`

→ chronik validiert seine Fixtures bereits gegen diese Schemata (siehe `.github/workflows/validate-*.yml`).

Dieses Dokument beschreibt die chronik-spezifischen Details und kontextualisiert, wie die zentralen Contracts angewendet werden.

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
