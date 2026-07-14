# Direct operator memory v1

Stand: 2026-07-14

## Zweck

Chronik übernimmt ausgewählte Grabowski-Laufereignisse direkt aus der lokalen
Outbox. Plexer ist für diesen Pfad weder erforderlich noch autoritativ. Chronik
bleibt ein append-only historischer Speicher und löst keine Aufgaben aus.

Der Pfad beantwortet zunächst drei belastbare Fragen:

1. Welche Agentenläufe wurden gestartet?
2. Welche Agentenläufe wurden abgeschlossen?
3. Welche Agentenläufe wurden blockiert und mit welchem Blocker-Code?

## Datenfluss

```text
Grabowski task runtime
  -> ~/.local/state/grabowski/chronik-outbox/*.jsonl
  -> chronik-outbox-import.timer
  -> tools/coding_memory.py import-outbox
  -> ~/.local/state/chronik/data/agent.ledger.jsonl
  -> query / summary / freeze
```

Der Import akzeptiert nur Ereignisse mit:

- `source.repo = heimgewebe/grabowski`
- `source.component = grabowski`
- einem der Typen `agent.run.started`, `agent.run.completed` oder
  `agent.run.blocked`
- gültigem `agent-run-event.v0`-Vertrag

## Sicherheits- und Wahrheitsmodell

- Der Quellpfad wird nur gelesen.
- Jeder Importbeleg ist an SHA-256, Größe und absoluten Pfad der gelesenen
  Quelldatei gebunden.
- Der Chronik-Speicher dedupliziert atomar über `event_id`.
- Ein vorhandener Importbeleg ersetzt niemals den Abgleich mit dem tatsächlichen Chronik-Speicher; nach Datenverlust werden Ereignisse erneut eingespielt.
- Wächst eine Outbox-Datei, wird ihr neuer Hash erkannt; bereits vorhandene
  Ereignisse werden übersprungen, neue Ereignisse werden ergänzt.
- Eine unvollständige letzte JSONL-Zeile, ungültiges JSON, Vertragsdrift oder ein
  fremder Producer führt für die betroffene Datei zu einem Fehler ohne
  Importbeleg.
- Historische Abfragen beweisen keinen aktuellen Git-, CI- oder Runtime-Zustand
  und autorisieren keinen Retry.

## Operatorzugriff

Aktivitätszusammenfassung:

```bash
python tools/coding_memory.py \
  --data-dir ~/.local/state/chronik/data \
  summary --since 2026-07-14T00:00:00Z --limit 20
```

Gefilterte Historie:

```bash
python tools/coding_memory.py \
  --data-dir ~/.local/state/chronik/data \
  query --repo heimgewebe/grabowski --outcome blocked
```

Hash-gebundene Kohorte:

```bash
python tools/coding_memory.py \
  --data-dir ~/.local/state/chronik/data \
  freeze --repo heimgewebe/grabowski \
  --output /tmp/grabowski-history.jsonl
```

## User-Service

Die Unit `chronik-outbox-import.service` ist ein gehärteter One-shot-Importer.
Der Timer startet sie alle zwei Minuten. Die Unit darf die Grabowski-Outbox nur
lesen und ausschließlich unter `~/.local/state/chronik` schreiben.

Der HTTP-Dienst `chronik.service` ist für diesen Pfad nicht erforderlich. Er
soll nur aktiviert werden, wenn ein konkreter externer Konsument den HTTP-Ingest
oder die HTTP-Abfrage benötigt.

## Bekannte Grenze

Bestehende Grabowski-Ereignisse tragen derzeit überwiegend
`subject.repo = heimgewebe/grabowski`. Damit ist die Laufhistorie belastbar,
das tatsächlich bearbeitete Zielrepository aber noch nicht immer ableitbar.
Die Producer-Korrektur gehört in Grabowski und muss getrennt von laufenden
Sicherheitsarbeiten umgesetzt und deployed werden.
