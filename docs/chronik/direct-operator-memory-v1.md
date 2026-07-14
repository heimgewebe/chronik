# Direct operator memory v1

Stand: 2026-07-14

## Zweck

Chronik übernimmt ausgewählte Grabowski-Laufereignisse direkt aus der lokalen
Outbox. Plexer ist für diesen Pfad weder erforderlich noch autoritativ. Chronik
bleibt ein append-only historischer Speicher und löst keine Aufgaben aus.

Der Pfad beantwortet belastbar:

1. Welche Agentenläufe wurden gestartet, abgeschlossen oder blockiert?
2. Welches Repository oder welcher Host war das Ziel?
3. Welche Operation und Aufgabenklasse wurde protokolliert?
4. Welche Blocker-Codes und Ergebnisse traten auf?
5. Auf welchem vollständigen Ledger-Snapshot beruht die Antwort?

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

## Zielidentität

Abfragen sind an genau ein Ziel gebunden:

- Repository: `--repo heimgewebe/chronik`
- Host: `--host heim-pc`

Legacy-Ereignisse ohne explizites `subject.scope` bleiben als
Repository-Ereignisse lesbar. Für die Operation gilt `data.operation` als
kanonisches Feld; `subject.operation` bleibt nur als Rückwärtskompatibilität.
`data.task_class` kann zusätzlich mit `--task-class` gefiltert werden.

## Sicherheits- und Wahrheitsmodell

- Der Quellpfad wird nur gelesen.
- Jeder Importbeleg ist an SHA-256, Größe und absoluten Pfad der gelesenen
  Quelldatei gebunden.
- Der Chronik-Speicher dedupliziert atomar über `event_id`.
- Ein vorhandener Importbeleg ersetzt niemals den Abgleich mit dem tatsächlichen
  Chronik-Speicher; nach Datenverlust werden Ereignisse erneut eingespielt.
- Wächst eine Outbox-Datei, wird ihr neuer Hash erkannt; bereits vorhandene
  Ereignisse werden übersprungen, neue Ereignisse werden ergänzt.
- Eine unvollständige letzte JSONL-Zeile, ungültiges JSON, Vertragsdrift oder ein
  fremder Producer führt für die betroffene Quelldatei zu einem Fehler ohne
  Importbeleg.
- Jede Abfrage liefert `ledger_snapshot` mit SHA-256, vollständiger Bytegrenze,
  gültigen und ungültigen Datensätzen sowie begrenzten Diagnosen.
- Historische Abfragen bleiben bei beschädigten Datensätzen lesbar, weisen den
  Zustand aber mit `integrity_valid = false` aus. Eine eingefrorene Kohorte wird
  in diesem Zustand verweigert, damit kein scheinbar vollständiger Beleg aus
  unvollständiger Evidenz entsteht.
- Historische Abfragen beweisen keinen aktuellen Git-, CI- oder Runtime-Zustand
  und autorisieren keinen Retry.

## Operatorzugriff

Aktivitätszusammenfassung:

```bash
python tools/coding_memory.py \
  --data-dir ~/.local/state/chronik/data \
  summary --since 2026-07-14T00:00:00Z --limit 20
```

Repository-Historie:

```bash
python tools/coding_memory.py \
  --data-dir ~/.local/state/chronik/data \
  query --repo heimgewebe/chronik \
  --operation implement --task-class coding --outcome completed
```

Host-Historie:

```bash
python tools/coding_memory.py \
  --data-dir ~/.local/state/chronik/data \
  query --host heim-pc \
  --operation recovery --task-class recovery --outcome blocked
```

Hash-gebundene Kohorte:

```bash
python tools/coding_memory.py \
  --data-dir ~/.local/state/chronik/data \
  freeze --repo heimgewebe/chronik \
  --output /tmp/chronik-history.jsonl
```

Der Receipt bindet die Kohorte sowohl an die Filter als auch an den SHA-256 des
vollständig gelesenen Ledger-Snapshots.

## User-Service

Die Unit `chronik-outbox-import.service` ist ein gehärteter One-shot-Importer.
Der Timer startet sie alle zwei Minuten. Die Unit darf die Grabowski-Outbox nur
lesen und ausschließlich unter `~/.local/state/chronik` schreiben.

Der HTTP-Dienst `chronik.service` ist für diesen Pfad nicht erforderlich. Er
soll nur aktiviert werden, wenn ein konkreter externer Konsument den HTTP-Ingest
oder die HTTP-Abfrage benötigt.

## Grenzen

Chronik bleibt historische Evidenz. `summary`, `query` und `freeze` treffen
keine Aussage darüber, ob ein Repository, Dienst, Task oder Deployment jetzt
noch denselben Zustand besitzt. Sie ersetzen weder Bureau-Wahrheit noch frische
Git-, CI-, Runtime- oder Recovery-Prüfungen.
