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
