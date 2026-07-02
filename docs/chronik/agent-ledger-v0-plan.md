# Chronik Agent Ledger v0 – Minimalplan

Status: review-ready
Zielrepo: `heimgewebe/chronik`
Branch: `docs/chronik-agent-ledger-v0-plan`
Erstellt: 2026-07-02

## 0. These / Antithese / Synthese

**These:** Chronik kann langfristig zur zeitlichen Infrastruktur des Heimgewebe-Agentensystems werden: ein kausales Betriebsgedächtnis für Agentenläufe, Repo-Arbeit, Reviews und Evidence-Referenzen.

**Antithese:** Eine breite Integration ist aktuell nicht gerechtfertigt. Chronik ist lokal noch nicht als Dienst etabliert, ein reproduzierbarer Testpfad fehlt, es gibt kein Chronik-rLens-Bundle und noch keinen belegten Consumer. Mehr Producer ohne Leser erzeugen nur höflich sortierten Lärm.

**Synthese:** v0 muss kleiner werden: erst Readiness, dann ein enges `agent.run.*`-Eventformat, dann eine Consumer-View mit Demo-Daten, danach genau ein realer Producer. Chronik wird nur ausgebaut, wenn diese Historie eine Entscheidung nachweislich verbessert.

## 1. Zielbild und Nicht-Ziele

Chronik soll nicht „mehr Logs“ sammeln, sondern eine kleine, rekonstruierbare Zeitspur liefern:

> Was ist wann durch wen passiert, wodurch ist es belegt, worauf bezog es sich, und hat diese Vergangenheit später eine bessere Entscheidung ermöglicht?

Nicht-Ziele für v0:

- keine breite Eventfamilie jenseits `agent.run.*`
- keine harte Runtime-Abhängigkeit für Grabowski, Bureau oder andere Agenten
- keine Leitstand-UI
- keine semantische Auswertung
- keine metarepo-weite Contractmigration
- keine Duplikation von Vibe-Lab-, GitHub-, Bureau- oder Grabowski-Langtexten

## 2. Delta zu bestehenden Logs

Chronik lohnt sich nur, wenn es etwas leistet, das bestehende Logs nicht leisten.

Bestehende Logs und Run-Cards zeigen meist **was lokal passiert ist**. Chronik v0 soll nur die dünne, maschinenlesbare Querreferenz liefern:

- ein Lauf begann, endete oder blockierte
- mit welchem Repo, Branch, Head und Run-Kontext
- mit welcher kurzen Ergebnis- oder Blockerklasse
- mit stabilen Evidence-Referenzen statt kopierten Belegen
- mit Kausalbezug auf auslösende Events, sofern vorhanden

Wenn diese View keine spätere Entscheidung verbessert, wird v0 eingefroren. Ein Tagebuch, das niemand liest, ist nur Staub mit Datum.

## 3. v0-Scope

Erlaubte Eventarten in v0:

- `agent.run.started`
- `agent.run.completed`
- `agent.run.blocked`

Alles andere ist out of scope, auch wenn es plausibel klingt:

- `repo.pr.*`
- `review.finding.*`
- `bureau.claim.*`
- `artifact.bundle.*`
- `friction.recorded`

Diese Typen dürfen erst nach einem belegten v0-Nutzenfall ergänzt werden.

## 4. Organe und Rollen

| Organ | v0-Rolle | Grenze |
|---|---|---|
| Chronik | hält Eventformat, Ingest, Query/View | entscheidet und orchestriert nicht |
| rLens/Lenskit | liefert Repo-Kontext und später Bundle-Refs | speichert keine Bundles in Chronik |
| Bureau | erster geplanter Consumer der Run-Historie | erzeugt keine Tasks nur aus Chronik |
| Grabowski | erster möglicher realer Producer nach Demo-View | blockiert keinen Lauf bei Chronik-Ausfall |
| Vibe-Lab | Primärort für Evidence | Chronik kopiert keine Run-Cards |
| Steuerboard | read-only Repo-State-Kontext | kein Gate, keine Freigabe |
| metarepo/contracts | spätere Contract-Governance | keine v0-Vorbedingung |
| Leitstand, semantAH, heimlern, hausKI, Cabinet | spätere Konsumenten/Entscheidungsflächen | nicht in v0 einbinden |

## 5. Eventformat v0

### 5.1 Domain und Ingest

Outbox-Flushes müssen eine Chronik-Domain explizit setzen:

```text
POST /v1/ingest?domain=agent.ledger
```

Begründung: `POST /v1/ingest` akzeptiert Events nur, wenn die Domain per Query-Parameter oder top-level Payload-Feld angegeben ist. v0 bevorzugt die Query-Domain, damit das Eventformat nicht von Chroniks Storage-Domain-Feld abhängig wird.

### 5.2 Minimales Event

```json
{
  "schema_version": "agent-ledger.v0",
  "event_id": "01JZ0000000000000000000000",
  "kind": "agent.run.completed",
  "ts": "2026-07-02T12:00:00Z",
  "source": {
    "repo": "heimgewebe/grabowski",
    "component": "grabowski",
    "run_id": "run-20260702-120000"
  },
  "subject": {
    "repo": "heimgewebe/chronik",
    "branch": "docs/chronik-agent-ledger-v0-plan",
    "head": "2f9774273b"
  },
  "trust_tier": "declared",
  "status": "active",
  "caused_by": [],
  "evidence_refs": ["github-pr:heimgewebe/chronik#192"],
  "data": {
    "result": "completed"
  }
}
```

### 5.3 ID-Regel

`event_id` muss idempotent und möglichst zeitlich sortierbar sein.

Präferenz:

1. ULID für neue Events.
2. Deterministischer Hash nur, wenn ein Lauf dieselbe Event-ID bei Retry reproduzieren muss.

Keine UUIDv4-Pflicht, weil ein Ledger von chronologisch sortierbaren IDs profitiert.

### 5.4 Kausalität und Context Propagation

Producer dürfen `caused_by` nur setzen, wenn ihnen auslösende Event-IDs explizit übergeben wurden, z. B. per Task-Payload, Run-Metadaten oder Environment.

Cardinality-Regeln:

- `caused_by`: maximal 3 IDs
- `evidence_refs`: maximal 5 Referenzen
- keine rekursive Expansion im Event selbst

Tiefe Kausalitätsgraphen sind Query-Problem, nicht Payload-Problem. Sonst wird aus Kausalität schnell ein Wollknäuel mit Doktortitel.

### 5.5 Trust und Status

`trust_tier` beschreibt die Herkunftsqualität:

- `observed`: direkt gemessen, z. B. Git-Head oder CI-Status
- `declared`: Agent berichtet ein Ergebnis
- `inferred`: aus anderen Signalen abgeleitet

`status` beschreibt den Lebenszustand des Events:

- `active`
- `superseded`
- `corrected`

Ein Korrektur-Event mit `status: "corrected"` muss ein Feld `corrects` mit mindestens einer alten Event-ID tragen.

### 5.6 Redaction Allow-List

`data` darf in v0 nur diese Felder enthalten:

- `result`
- `blocker_code`
- `summary`
- `duration_ms`

Nicht erlaubt:

- Rohlogs
- Tooloutputs
- Prompts
- Secrets
- Tokens
- personenbezogene Freitexte
- vollständige Review-Kommentare

Maskierung muss vor dem Schreiben in die Outbox erfolgen, nicht erst beim Flush.

## 6. Outbox v0

### 6.1 Pfad und Concurrency

Ein Run schreibt in genau eine Datei:

```text
.local/state/<producer>/chronik-outbox/<producer>_<run_id>.jsonl
```

Damit konkurrieren parallele Agentenläufe nicht auf derselben Append-Datei.

### 6.2 Lifecycle

Outbox-Befehle:

- `append`: Event validieren und lokal anhängen
- `flush`: an `POST /v1/ingest?domain=agent.ledger` senden
- `status`: ungeflushte Dateien anzeigen
- `compact`: erfolgreich geflushte Events löschen oder in ein kompaktes Receipt verschieben

Flush ist fail-soft:

- kurzer Timeout
- Retry mit Backoff
- kein Agentenlauf scheitert wegen Chronik-Ausfall
- erfolgreiche Flushes werden lokal bereinigt, damit kein Disk-Spam entsteht

## 7. Phasenplan

### Phase 0 – Readiness und Blockerklärung

Akzeptanzkriterien:

- One-command local setup ist dokumentiert oder vorhanden, z. B. `scripts/setup-chronik-dev.sh`
- `python -m pytest -q` läuft reproduzierbar grün
- lokaler Smoke für `/health`, `/version`, `/v1/ingest?domain=agent.ledger` und `/v1/events` ist dokumentiert
- Zielhost ist entschieden oder bewusst offengelassen: heim-pc vs. heimserver
- `CHRONIK_DATA_DIR`-Strategie ist bekannt
- Token-/Secret-Verwaltung ist beschrieben
- Retention für `agent.ledger` ist entschieden
- Redaction-Allow-List ist akzeptiert
- Chronik-rLens-Bundle oder ein dokumentierter Ersatzpfad existiert

Ohne diese Punkte beginnt keine Producer-Integration.

### Phase 1 – Event Contract v0

Umfang:

- nur `agent.run.*`
- `schema_version`
- ULID-/ID-Regel
- Trust-/Status-Trennung
- Kausalitäts-Cardinality
- Redaction-Allow-List
- drei Beispiel-Events: started, completed, blocked
- Contract-Seam: [`agent-run-event-v0.md`](agent-run-event-v0.md) und [`agent-run-event-v0.schema.json`](agent-run-event-v0.schema.json)

Akzeptanzkriterium:

- Contract ist klein genug, dass ein synthetisches Demo-Event validiert und gelesen werden kann.

### Phase 2 – Outbox-Prototyp

Umfang:

- append/status/flush/compact
- Datei pro Run
- Flush gegen `POST /v1/ingest?domain=agent.ledger`
- Tests ohne laufenden Dienst

Akzeptanzkriterium:

- ein synthetisches Event kann lokal erzeugt, geflusht und wieder gelesen werden.

### Phase 3 – Consumer-View mit Demo-Daten

Diese Phase kommt vor dem ersten realen Producer.

View:

```text
last agent runs by repo: repo, branch, result, blocker_code, evidence_ref, ts
```

Akzeptanzkriterium:

- Bureau oder Grabowski kann die View lesen und daraus mindestens eine plausible nächste Entscheidung ableiten.

### Phase 4 – Erster realer Producer

Erst nach Phase 3 darf ein realer Producer angebunden werden.

Präferenz:

- Grabowski schreibt optional `agent.run.started/completed/blocked` in seine Outbox.

Grenzen:

- kein Lauf blockiert bei Chronik-Ausfall
- keine unredigierten Payloads
- keine zusätzlichen Eventtypen

### Phase 5 – Nutzenmessung und Exit

Messung nicht nach Kalender, sondern nach Nutzung:

- mindestens 15 reale Agentenläufe
- mindestens 3 unterschiedliche Zielrepos
- mindestens 1 dokumentierter Fall, in dem die Chronik-View eine Bureau- oder Grabowski-Entscheidung verändert hat

Pausieren, wenn:

- nach 15 Läufen kein Entscheidungsprozess die View konsultiert hat
- Events nur bestehende Logs duplizieren
- Producer ohne Consumer wachsen
- Payloads nicht zuverlässig redigiert bleiben

Ausbau erlauben, wenn:

- mindestens 3 No-Brainer-Effekte aus Abschnitt 8 messbar sind oder Cabinet/Bureau explizit einen engeren Ausbau begründet
- kein harter Runtime-Kopplungspfad entstanden ist
- Eventtypen weiter eng begrenzt bleiben

## 8. No-Brainer-Effekte

Chronik wird erst dann ein No-brainer, wenn mindestens drei Effekte belegt sind:

1. weniger Kontextverlust bei ähnlichen Folgeaufgaben
2. weniger wiederholte Debugarbeit
3. bessere Review-/Merge-Rekonstruktion
4. bessere Bureau-Priorisierung
5. bessere Evidence-Verknüpfung mit Vibe-Lab
6. brauchbares Replay eines Agentenlaufs
7. Grundlage für spätere Leitstand- oder Lern-Views

## 9. Risiken und Gegenmaßnahmen

| Risiko | Folge | Gegenmaßnahme |
|---|---|---|
| Producer vor Consumer | Event-Spam | Demo-Consumer-View vor realem Producer |
| harte Kopplung | Agentenläufe brechen | Outbox-first, Timeouts, optional |
| doppelte Wahrheit | Widerspruch zu Vibe-Lab/Bureau/GitHub | nur Evidence-Refs, keine Langtexte |
| Secret-Leaks | Sicherheitsrisiko | Allow-List vor Outbox-Write |
| Event-Inflation | `friction.recorded` wird Mülleimer | nur `agent.run.*` in v0 |
| JSONL-Suche wird teuer | schlechte Querybarkeit | View klein halten; Index/SQLite erst nach Nutzennachweis prüfen |
| Kausalitäts-Hölle | teure Graphabfragen | `caused_by` max. 3, keine Payload-Expansion |
| Schema-Drift | spätere Migration unklar | `schema_version`, additive v0-Regeln, neue Version nur mit Consumer |

## 10. Nächste PRs

1. `docs: define agent ledger minimal plan` – dieser PR.
2. `chore: make chronik local validation reproducible` – One-command setup, Tests, Smoke.
3. `docs: define agent-run event v0 examples` – Beispiele und Validation-Seam.
4. `feat: add chronik outbox prototype` – append/status/flush/compact.
5. `feat: add agent ledger demo view` – Consumer-View mit Demo-Daten.
6. `experiment: connect grabowski run outbox` – erster realer Producer.

## 11. Urteil

Der Kern bleibt stark: Chronik als kausales Betriebsgedächtnis statt Logging-Friedhof.

Die v0-Disziplin ist enger:

1. nur `agent.run.*`
2. Query-Domain `agent.ledger`
3. Consumer-View vor realem Producer
4. harte Readiness-Blocker in Phase 0
5. Redaction-Allow-List statt bloßer Secret-Hoffnung
6. klare Exit-Metrik nach 15 Läufen

Essenz:

> Erst eine kleine Vergangenheit bauen, die jemand liest. Dann erst mehr Vergangenheit produzieren.
