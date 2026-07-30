# Agent Run Event v0

Status: draft
Domain: `agent.ledger`
Schema: [`agent-run-event-v0.schema.json`](agent-run-event-v0.schema.json)
Outbox helper: `python -m tools.chronik_outbox`

## These / Antithese / Synthese

**These:** `agent.run.*` ist der kleinste sinnvolle Ledger-Schnitt: Er zeigt, wann ein Agentenlauf begann, endete oder blockierte.

**Antithese:** Schon hier droht Logging-Inflation. Wenn das Event Rohlogs, Prompts oder Reviewtexte enthält, wird Chronik zur zweiten Ablage statt zur Zeitachse.

**Synthese:** v0 erlaubt nur drei Eventarten, kleine Payloads, stabile Evidence-Referenzen und harte Cardinality-Grenzen. Alles andere bleibt außerhalb des Contracts.

## Ingest-Domain

Agent-Run-Events werden nach Chronik über diese Domain geschrieben:

```text
POST /v1/ingest?domain=agent.ledger
```

Die Domain ist bewusst **nicht** Teil des Event-Payloads. Chronik setzt die Storage-Domain im Envelope.

## Erlaubte Kinds

- `agent.run.started`
- `agent.run.completed`
- `agent.run.blocked`

## Pflichtfelder

| Feld | Bedeutung |
|---|---|
| `schema_version` | exakt `agent-run-event.v0` |
| `event_id` | ULID oder deterministischer `sha256:<hex>` |
| `kind` | eine der drei erlaubten Eventarten |
| `ts` | UTC-Zeitpunkt mit `Z` |
| `source` | erzeugendes Repo, Komponente, Run-ID |
| `subject` | Zielrepo und optional Branch/Head |
| `trust_tier` | `observed`, `declared`, `inferred` |
| `status` | `active`, `superseded`, `corrected` |
| `caused_by` | maximal drei auslösende Event-IDs |
| `evidence_refs` | maximal fünf stabile Belegreferenzen |
| `data` | erlaubte Kurzpayload-Felder |

## Redaction-Allow-List

`data` darf nur diese Felder enthalten:

- `result`
- `blocker_code`
- `summary`
- `duration_ms`

Nicht erlaubt sind Rohlogs, Prompts, Tooloutputs, Secrets, Tokens, PII oder vollständige Review-Kommentare. Das ist keine Stilfrage, sondern Brandschutz. Papier brennt langsam; JSONL brennt rekursiv.

## Kausalität

`caused_by` darf nur gesetzt werden, wenn der Producer die auslösenden Event-IDs explizit erhalten hat, etwa aus Task-Payload, Run-Metadaten oder Environment.

Grenzen:

- `caused_by`: maximal 3 IDs
- `evidence_refs`: maximal 5 Einträge
- keine eingebetteten Belegtexte
- keine rekursive Graph-Expansion im Event

## Status und Korrektur

`trust_tier` beschreibt Herkunftsqualität. `status` beschreibt den Lebenszustand des Events.

Wenn `status` den Wert `corrected` hat, muss `corrects` mindestens eine alte Event-ID enthalten.

## Lokaler Outbox-Prototyp

`tools.chronik_outbox` stellt einen lokalen, producer-agnostischen Prototyp bereit:

```bash
python -m tools.chronik_outbox --state-root /tmp/chronik-state append tests/fixtures/agent-ledger/agent-run-completed.v0.json
python -m tools.chronik_outbox --state-root /tmp/chronik-state status
CHRONIK_TOKEN=dev python -m tools.chronik_outbox --state-root /tmp/chronik-state flush --base-url http://localhost:8788
python -m tools.chronik_outbox --state-root /tmp/chronik-state compact
```

Regeln:

- `append` validiert gegen das v0-Schema und schreibt unter einem dateigebundenen Lock in eine JSONL-Datei pro Producer/Run.
- `flush` sendet nur den noch nicht quittierten JSONL-Suffix an `POST /v1/ingest?domain=agent.ledger`.
- Ein Receipt bindet den erfolgreich gesendeten Präfix an kanonischen Quellpfad, Byteanzahl, Ereignisanzahl und SHA-256.
- Ein Append während des Netzaufrufs bleibt als neuer, nicht quittierter Suffix erhalten.
- `compact` entfernt eine Datei nur, wenn das Receipt exakt den vollständigen aktuellen Dateisnapshot abdeckt.
- Alte, beschädigte oder nicht snapshotgebundene Receipts berechtigen weder zum erneuten automatischen Flush noch zur Kompaktierung; sie erfordern eine gesonderte Prüfung.
- Kein Agentenlauf darf vom Outbox-Prototyp abhängig werden.

## Beispiele

Gültige Beispiele liegen unter:

- `tests/fixtures/agent-ledger/agent-run-started.v0.json`
- `tests/fixtures/agent-ledger/agent-run-completed.v0.json`
- `tests/fixtures/agent-ledger/agent-run-blocked.v0.json`

## Nicht-Ziele

- keine PR-Events
- keine Review-Finding-Events
- keine Bureau-Claim-Events
- keine echte Producer-Integration
- keine Runtime-Validierung in `app.py`

Dieser Contract ist ein Validierungsseam für die nächsten Schritte, nicht bereits der nächste Schritt selbst.
