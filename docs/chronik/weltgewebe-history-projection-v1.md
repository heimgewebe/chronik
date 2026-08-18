# Weltgewebe History Projection v1

Status: implementation contract
Bureau task: `WELTGEWEBE-OS-V1-T007`
Domain: `weltgewebe.history`
Schema: [`weltgewebe-history-event-v1.schema.json`](weltgewebe-history-event-v1.schema.json)

## Zweck

Chronik führt für Weltgewebe einen append-only Ereignis- und Wirkungsverlauf. Dieser Verlauf ist eine historische Projektion: Er speichert belegte Aussagen über Vorgänge, ersetzt aber keine Primärwahrheit in Weltgewebe, GitHub/Deployment, der Föderation oder Grabowski.

Der Vertrag unterscheidet vier Ereignisklassen ausdrücklich:

- `domain_event` – fachliches Weltgewebe-Ereignis;
- `deployment` – Deployment-/Release-Beobachtung;
- `federation_delivery` – Föderationszustellung;
- `operator_receipt` – Grabowski-/Operator-Receipt.

## Provenienz

Jeder Eintrag muss maschinenlesbar binden:

- `source.origin` – Ursprung des Ereignisses;
- `source.repo` und `source.component` – erzeugendes Systemteil;
- `source.version` – Version des Quellvertrags;
- optional `source.revision` – konkrete Quellrevision;
- `correlation_id` – Verbindung zu demselben fachlichen Vorgang;
- mindestens einen `source_evidence`-Beleg aus `authority`, `reference` und SHA-256.

Chronik erzeugt aus fehlender Provenienz keine Ersatzwahrheit. Ein unvollständiges `weltgewebe.history`-Ereignis wird vor Persistenz abgelehnt.

## Authority Boundary

Jedes Ereignis trägt:

```json
{
  "authority": {
    "primary_truth": "weltgewebe",
    "chronik_role": "historical_projection",
    "writeback_allowed": false
  }
}
```

`writeback_allowed` ist im Schema konstant `false`. Der zugehörige Python-Code validiert und projiziert ausschließlich; er enthält keinen Netzwerk-, Git-, Queue-, Deployment- oder Weltgewebe-Schreibpfad.

Chroniks bestehende Leseoberfläche `GET /v1/events?domain=weltgewebe.history` kann den Verlauf ausgeben. Ledgerpräsenz autorisiert keine Wiederholung, Korrektur oder Mutation im Quellsystem.

## Datenschutz und Lebenszyklus

Datenschutz wird pro Ereignis explizit klassifiziert:

- `public`;
- `restricted`;
- `private`.

Zusätzlich wird festgehalten, ob der Eintrag personenbezogene Daten enthält.

Widerruf, Redaktion und Löschung werden **nicht** durch Umschreiben einer alten Ledgerzeile ausgedrückt. Stattdessen wird ein neues, belegtes Ereignis angehängt, dessen `lifecycle` auf das ältere `target_event_id` zeigt:

- `active` – ursprünglicher aktiver Eintrag; `target_event_id` ist `null`;
- `redacted` – eine Redaktionsprojektion wurde festgestellt;
- `revoked` – die Quellaussage wurde widerrufen;
- `deleted` – eine Löschprojektion wurde festgestellt.

`project_weltgewebe_lifecycle(...)` leitet daraus read-only den jeweils zuletzt beobachteten Zustand ab. Die Eingabeereignisse werden dabei weder geändert noch entfernt.

Wichtig: `deleted` bedeutet in Chronik eine historische Löschprojektion. Es behauptet nicht, dass Primärdaten im Quellsystem physisch gelöscht wurden. Dafür bleibt die jeweils benannte Primärwahrheit zuständig.

## Retention

Die tatsächliche Chronik-Aufbewahrung bleibt serverseitige Chronik-Wahrheit. Wie bei anderen Ereignissen ergänzt der kanonische Ingest-Envelope:

```json
{
  "retention": {
    "ttl_days": 30,
    "expires_at": "..."
  }
}
```

Die Werte stammen aus `config/retention.yml`; ein Weltgewebe-Produzent darf keinen eigenen TTL-Wert als Chronik-Retention durchsetzen. So bleiben fachliche Lebenszyklusprojektion und physische Ledger-Aufbewahrung getrennte Begriffe.

## Ingest

Nur die exakte Domain `weltgewebe.history` aktiviert diesen zusätzlichen Vertrag. Andere Chronik-Domains behalten ihre bisherigen Provenienz- und Ingestregeln. Das verhindert, dass T007 bestehende Eventproduzenten rückwirkend verschärft.

Verarbeitung:

```text
HTTP /v1/ingest
  -> Domain = weltgewebe.history
  -> Weltgewebe-History-Schema validieren
  -> bestehende Chronik-Provenienz validieren
  -> Quality Envelope
  -> serverseitige Retention
  -> append-only Ledger
```

## Nicht behauptet

Dieser Vertrag begründet nicht:

- fachliche Richtigkeit eines Weltgewebe-Ereignisses;
- erfolgreiche Zustellung in der Föderation;
- erfolgreichen Deploymentzustand;
- Grabowski-Taskabschluss;
- physische Löschung in einem Primärsystem;
- Schreib-, Retry-, Rollback- oder Orchestrierungsautorität.
