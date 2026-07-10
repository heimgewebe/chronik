# Event Contracts

Dieses Dokument beschreibt die Event-Felder, die **chronik** akzeptiert und speichert.

## 🔗 Beziehung zu den zentralen Heimgewebe-Contracts

chronik ist Teil des systemweiten Event-Backbones.
Die **kanonischen Contracts** (Draft 2020-12) liegen im **metarepo** unter:

  - `contracts/aussen.event.schema.json`
  - `contracts/event.line.schema.json`
  - `contracts/chronik-fixtures.schema.json`

→ chronik validiert seine Fixtures bereits gegen diese Schemata (siehe
  `.github/workflows/validate-*.yml`).

chronik führt keine eigenen, abweichenden JSON-Schemas. Alle Änderungen an der
Event-Struktur laufen über die Contracts im **metarepo**. Dadurch wird
Contract-Drift zwischen Repos vermieden und der Event-Backbone stabil gehalten.

Dieses Dokument beschreibt die chronik-spezifischen Details und kontextualisiert, wie die zentralen Contracts angewendet werden.

## Storage Contract (JSONL)

Das Speicherformat ist **strict JSON Lines**:

1.  **Zeilentrenner ist ausschließlich LF (`\n`, U+000A).**
2.  Andere Unicode-Line-Separators (wie U+2028 oder U+2029) werden nicht als Trenner interpretiert, sondern sind Teil des JSON-Payloads.
3.  Jede Zeile muss ein vollständiges, valides JSON-Objekt enthalten.
4.  Dateien sind UTF-8-kodiert.

Diese strenge Trennung garantiert, dass Payloads mit eingebetteten Sonderzeichen nicht korrumpiert werden.

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

## Schema: `chronik.operator-routing-outcome-export.v1`

Chronik defines a strict transport envelope for the Heimlern-owned
`operator.routing_outcome.v1` payload. The envelope binds source identity, the
pinned payload-contract revision and digest, canonical payload bytes, event
identity, observation/export timestamps and evidence-reference digests. It
preserves transport-only authority and rejects raw output, secret-shaped text,
private absolute paths and automatic application. See
`docs/chronik/operator-routing-outcome-export-v1.md`.

## Schema: `runtime-lens-observation.v1` (Chronik-local contract)

Chronik defines a bounded Runtime-Lens observation contract under
`docs/chronik/runtime-lens-observation-v1.schema.json`. It links RepoBrief
snapshot citations to runtime observations without granting verdict authority to
either side. See `docs/chronik/runtime-lens-evidence-bridge-v1.md`.

Key boundaries:

- RepoBrief is code-evidence authority only.
- Runtime sources are observation authority only.
- `authority.verdict_authority` is always `none`.
- The event does not permit service restart, deploy, systemd mutation, secret
  read, runtime write, task dispatch, approval decision or correctness verdict.

## Schema: `heimgeist.self_state.snapshot` (Mirror)

Chronik spiegelt das kanonische Schema aus dem Metarepo:
`contracts/events/heimgeist.self_state.snapshot.v1.schema.json`

- **Enforced via:** Strict JSON Schema (`additionalProperties: false`).
- **Rejected:** `heimgeist.self_state.bundle.v1` (Artifact Bundle) wird explizit mit HTTP 400 abgewiesen.
- **Retention:** `ttl_days: 0` (unbegrenzt).

### Felder (Self-State Object in `data`)
- `confidence` (0.0 - 1.0)
- `fatigue` (0.0 - 1.0)
- `risk_tension` (0.0 - 1.0)
- `autonomy_level` (`dormant` | `aware` | `reflective` | `critical`)
- `last_updated` (ISO 8601 Timestamp)
- `basis_signals` (String Array)
