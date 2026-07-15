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
- Jede Abfrage liest einen einzelnen, an der letzten vollständigen JSONL-Zeile
  begrenzten Rohbyte-Snapshot. SHA-256, Bytegrenze, Parsing und Diagnosen werden
  ausschließlich aus diesem unveränderlichen Snapshot abgeleitet. Ungültiges
  UTF-8 bleibt dadurch bytegenau unterscheidbar und wird als ungültiger Datensatz
  ausgewiesen.
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

## Skalierungsvertrag

Der Import liest und validiert weiterhin jede vollständige Quelldatei. Alle
gültigen Ereignisse werden danach in **einer** gruppierten Storage-Operation
abgeglichen. Unter einem einzigen Lock wird der Ziel-Ledger höchstens einmal
vollständig gescannt. Pro Quelldatei bleiben getrennte, an Pfad, SHA-256 und
Größe gebundene Receipts erhalten.

Vor der Optimierung wurden folgende Grenzen festgelegt:

- höchstens ein Ziel-Ledger-Scan pro Batch;
- repräsentativer Tier: 200 Quelldateien, 500 bestehende Ereignisse, höchstens
  5 Sekunden;
- projizierter Tier: 1000 Quelldateien, 5000 bestehende Ereignisse, höchstens
  30 Sekunden;
- absolute Timergrenze: höchstens 60 Sekunden, also mindestens Faktor 2
  Reserve zum Zwei-Minuten-Intervall.

Reproduzierbarer Benchmark:

```bash
python tools/benchmark_outbox_import.py \
  --output /tmp/chronik-outbox-benchmark.json
```

Der Bericht enthält Maschinenkontext, Laufzeit und Peak-Speicher für Erst- und
Wiederholungsimport, Ziel-Ledger-Scans, gescannte Zieldatensätze sowie
geschriebene und übersprungene Ereignisse. Ein Importbeleg bleibt dabei reine
Evidenz: Auch der Wiederholungsimport gleicht jedes Ereignis gegen den
tatsächlichen Ledger ab und vertraut niemals nur dem Receipt.

Ein Receipt wird erst nach dem erfolgreichen Ledger-Abgleich geschrieben. Falls
dieser Evidenzschritt scheitert, bleiben die bereits bestätigten Ledger-Zahlen
in der Batch-Ausgabe erhalten und die betroffene Quelle wird zusätzlich als
Fehler gemeldet. Der nächste Lauf gleicht erneut gegen den realen Ledger ab und
kann das Receipt wiederherstellen. `target_scans = 0` bedeutet, dass keine
gültige Quelle einen Ledger-Abgleich erforderte; `null` bedeutet, dass für einen
vorbereiteten Batch keine verlässliche Scan-Telemetrie vorliegt.

## User-Service

Die Unit `chronik-outbox-import.service` ist ein gehärteter One-shot-Importer.
Der Timer startet sie alle zwei Minuten. Dieselbe One-shot-Unit wird von systemd
nicht parallel ein zweites Mal gestartet; ein noch aktiver Lauf verhindert damit
überlappende Importer. Die Unit darf die Grabowski-Outbox nur lesen und
ausschließlich unter `~/.local/state/chronik` schreiben.

Der HTTP-Dienst `chronik.service` ist für diesen Pfad nicht erforderlich. Er
soll nur aktiviert werden, wenn ein konkreter externer Konsument den HTTP-Ingest
oder die HTTP-Abfrage benötigt.

## Grenzen

Chronik bleibt historische Evidenz. `summary`, `query` und `freeze` treffen
keine Aussage darüber, ob ein Repository, Dienst, Task oder Deployment jetzt
noch denselben Zustand besitzt. Sie ersetzen weder Bureau-Wahrheit noch frische
Git-, CI-, Runtime- oder Recovery-Prüfungen.
