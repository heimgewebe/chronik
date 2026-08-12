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

Beim ersten Import oder nach rekonstruierbarem Indexverlust liest, hasht und
validiert Chronik weiterhin jede vollständige Quelldatei. Danach hält
`import-receipts/source-index.v1.json` eine private, atomar ersetzte
Discovery-Projektion. Sie bindet lose Quellen sowie Bundle und Manifest an
Gerät, Inode, Modus, Linkzahl, Eigentümer, Größe, mtime und ctime. Zu jeder
logischen Quelle enthält sie nur Pfad, Quell-SHA-256, Bytezahl, Event-IDs und
kanonische Payload-Fingerprints, niemals die Replay-Bytes.

Bei exakt unveränderten Metadaten müssen Quell- und Bundle-Bytes deshalb nicht
erneut gelesen, gehasht oder schema-validiert werden. Die gespeicherten
Fingerprints dürfen ausschließlich gegen den ledgergebundenen Identity-Index
verifiziert werden. Fehlt dort ein Cache-Ereignis, stoppt der Lauf vor einem
Append geschlossen. Ein fehlender oder leerer Ledger umgeht den Source-Index
vollständig und wird nur aus erneut gelesenen, vollständig validierten
Outbox-/Bundle-Bytes rekonstruiert. Ein fehlender, syntaktisch beschädigter,
unprivater oder digest-widersprüchlicher Source-Index wird ebenso sicher aus den
autoritativen Quellen aufgebaut. Jede Metadatenänderung revalidiert nur das
betroffene Artefakt. Ledger, Bundle und lose Quelle bleiben maßgeblich; der
Source-Index ist keine Receipt-, Historien- oder Taskautorität.

Alle gültigen Ereignisse werden in **einer** gruppierten Storage-Operation
abgeglichen. Der persistente Ledger-Identity-Index verifiziert dabei nur die
angeforderten Event-IDs an ihren ledgergebundenen Offsets. Der steady state
scannt keine vollständige Ledger-Historie. Pro Quelldatei bleiben getrennte, an
Pfad, SHA-256 und Größe gebundene Receipts erhalten.

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

Der Bericht enthält Maschinenkontext, Laufzeit und Peak-Speicher für Erstimport,
No-change, ein kleines Zwei-Ereignis-Delta, Bundle-Revalidierung und
anschließendes Bundle-No-change. Zusätzlich weist er interne Phasen,
Source-Index-Modus, wiederverwendete/revalidierte/geänderte Quellen, gelesene
und gehashte Quellbytes, validierte Ereignisse, Ziel-Ledger-Scans sowie
geschriebene und übersprungene Ereignisse aus. Reproduzierbare Zielgrenzen sind:

- No-change unter einer Sekunde im repräsentativen Fixture;
- No-change unter zwei Sekunden im projizierten 1000-Dateien-Tier;
- kleines Delta unter zwei Sekunden;
- null gelesene/gehashte Quellbytes im unveränderten Loose- und Bundle-Pfad;
- null vollständige Ledger-Datensätze im steady state und weiterhin höchstens
  ein Scan in Rebuild-/Catch-up-Sonderpfaden.

Ein Importbeleg bleibt dabei reine Evidenz. Im normalen Vollpfad gleicht auch
der Wiederholungsimport jeden Payload-Fingerprint gegen den tatsächlichen Ledger
ab und vertraut weder nur dem Receipt noch nur dem Source-Index.

Für den vom Timer verwendeten `summary`-Pfad darf ein exakt unveränderter Lauf
diesen Vollabgleich überspringen, aber nur auf Basis eines kleinen privaten
`steady-import-checkpoint.v1.json`, der **nach** einem erfolgreichen Vollabgleich
geschrieben wurde. Der Checkpoint bindet die Metadatenidentität aller losen
Quellen, Bundle-Manifeste und Bundle-Dateien, aller Import-Receipts, des
Source-Index, der privaten Delta-Projektionen sowie des Ledger- und
Identity-Index-Paares. Vor einem Fast-Return werden Source- und Receipt-Inventar
nach dem Ledger-/Index-Read ein zweites Mal abgeglichen, um Änderungen im
Prüfzeitfenster zu erkennen. Nur wenn sämtliche Identitäten exakt dem vorherigen
Vollabgleich entsprechen, werden Quellmaterialisierung, Merge und erneuter
Ledger-Abgleich ausgelassen.

Ein Source-only-Delta darf im selben `summary`-Pfad enger verarbeitet werden.
Dafür muss der vorherige erfolgreiche Checkpoint weiterhin exakt den
kanonischen Source-Index, einen privaten `delta-source-index.v1.json`, dessen
gebundenes `delta-source-overlay.v1.json` sowie Ledger und Identity-Index
verankern. Der Delta-Index enthält nur rekonstruierbare Metadaten; das auf 2048
Einträge begrenzte Overlay hält ausschließlich seit dem letzten Vollabgleich
neue oder geänderte lose Quellen. Vor dem Ledger-Effekt werden diese Cache- und
Target-Identitäten nochmals geprüft. Nur die tatsächlich neuen oder geänderten
Quellen werden aus ihren stabil gelesenen Bytes validiert und gegen den
autoritativen Identity-Index abgeglichen. Entfernte Quellen, Bundle-Drift,
Generationsüberlappungen, beschädigte Projektionen, überschrittene
Overlay-Grenzen oder irgendeine Autoritätsdrift fallen deterministisch auf den
Vollpfad zurück.

Import-Receipts bleiben auch dabei reine Evidenz. Ein Delta-Lauf behauptet für
übersprungene Altquellen deshalb keine aktuelle Receipt-Wiederverwendung,
sondern zählt sie als `receipts_deferred`. Der nächste Lauf ohne neue
Source-Änderung führt einmal den Vollabgleich aus, attestiert bzw. repariert die
Receipts und setzt Delta-Basis und Overlay wieder zusammen. Erst der folgende
exakt unveränderte Lauf darf wieder den No-change-Fast-Return nehmen.
`--output-mode full` verwendet weder No-change- noch Delta-Fast-Path.

Checkpoint, Delta-Index und Overlay sind rekonstruierbare
Beschleunigungsprojektionen. Sie sind weder Replay- noch Historienautorität und
begründen insbesondere keine aktuelle Git-, CI-, Runtime-, Task- oder
Retry-Wahrheit.

Ein Receipt wird erst nach dem erfolgreichen Ledger-Abgleich geschrieben. Falls
dieser Evidenzschritt scheitert, bleiben die bereits bestätigten Ledger-Zahlen
in der Batch-Ausgabe erhalten und die betroffene Quelle wird zusätzlich als
Fehler gemeldet. Der nächste Lauf gleicht erneut gegen den realen Ledger ab und
kann das Receipt wiederherstellen. Auch ein syntaktisch beschädigtes Receipt
wird dabei wie fehlende Evidenz behandelt und nach dem Ledger-Abgleich ersetzt.
`target_scans = 0` bedeutet, dass keine
gültige Quelle einen Ledger-Abgleich erforderte; `null` bedeutet, dass für einen
vorbereiteten Batch keine verlässliche Scan-Telemetrie vorliegt.

## User-Service

Die Unit `chronik-outbox-import.service` ist ein gehärteter One-shot-Importer.
Der Timer startet sie alle zwei Minuten. Dieselbe One-shot-Unit wird von systemd
nicht parallel ein zweites Mal gestartet; ein noch aktiver Lauf verhindert damit
überlappende Importer. Die Unit darf die Grabowski-Outbox nur lesen und
ausschließlich unter `~/.local/state/chronik` schreiben. Für systemd nutzt die
Unit `import-outbox --output-mode summary`: Pro Lauf entsteht genau ein kompakter
JSON-Einzeiler mit Zählern. Nur dieser Summary-Pfad aktiviert den oben
beschriebenen No-change- und Source-only-Delta-Pfad; nicht sicher als Delta
klassifizierbarer Drift führt im selben Lauf zurück in den normalen vollständigen
Abgleich. Dateiinventare werden nicht ausgegeben; höchstens
drei gekürzte Fehlerstichproben bleiben sichtbar. Die Zeile bleibt garantiert
unter 4096 Bytes: Gekürzt wird nach der JSON-kodierten Bytelänge, nicht nach
Zeichenzahl, weil Escaping ein Zeichen auf bis zu zwölf Bytes ausdehnen kann.
Reicht das nicht, entfallen zusätzlich Fehlerstichproben; `errors_truncated`
bleibt dann `true`. Die aggregierte `error_count` und der Exitcode `2` bei
Fehlern bleiben in jedem Fall erhalten. Zusätzlich begrenzt die Unit die
Journalrate unabhängig vom User-Manager auf 200 Meldungen je 30 Sekunden. Der
CLI-Standard bleibt `full`, damit bestehende interaktive und maschinelle Aufrufer
kompatibel bleiben.

Der HTTP-Dienst `chronik.service` ist für diesen Pfad nicht erforderlich. Er
soll nur aktiviert werden, wenn ein konkreter externer Konsument den HTTP-Ingest
oder die HTTP-Abfrage benötigt.

## Grenzen

Chronik bleibt historische Evidenz. `summary`, `query` und `freeze` treffen
keine Aussage darüber, ob ein Repository, Dienst, Task oder Deployment jetzt
noch denselben Zustand besitzt. Sie ersetzen weder Bureau-Wahrheit noch frische
Git-, CI-, Runtime- oder Recovery-Prüfungen.

## Receipt-Wiederverwendung und Replay-Autorität

Im normalen Vollpfad gleicht jeder Outbox-Import die Event-IDs mit dem maßgeblichen Chronik-Ledger ab. Der exakt-unveränderte `summary`-Fast-Path darf diesen erneuten Einzelabgleich nur überspringen, solange sein nach einem erfolgreichen Vollabgleich geschriebener Checkpoint unveränderte Source-, Receipt-, Source-Index-, Ledger- und Identity-Index-Identitäten belegt; jede Drift fällt auf den Vollpfad zurück. Sind dort die Quellbytes unverändert, alle angeforderten Events im Ledger vorhanden und der vorhandene quellgebundene Receipt durch seinen SHA-256-Digest intakt, wird die Receipt-Datei nicht ersetzt. Die Batch-Telemetrie trennt `receipts_written` und `receipts_reused`.

`receipt_sha256` im Laufergebnis bindet ausdrücklich die unveränderte Receipt-Datei (`receipt_digest_scope=persisted_receipt`), nicht die aktuellen Laufzähler. `imported`, `skipped_existing` und die Scan-Zähler beschreiben den aktuellen Lauf.

Ein Quellpfad darf nach einer Kompaktierung erneut verwendet werden. Chronik identifiziert deshalb jede Importgeneration durch den kanonischen Quellpfad zusammen mit dem exakten Quell-SHA-256. Generationsgebundene Receipts verwenden beide Werte. Intakte ältere, nur pfadgebundene Receipts bleiben bei einem eindeutigen Quellpfad ohne Dateivermehrung nutzbar; erst wenn mehrere Generationen desselben Pfades gleichzeitig vorliegen, werden sie nach der Ledgerprüfung auf SHA-gebundene Receiptpfade angehoben. Receipts bleiben nichtautoritativ. Byteidentische Generationen werden dedupliziert. Mehrere byteverschiedene Generationen dürfen nebeneinander bestehen, aber der gruppierte Ledger-Writer verwirft weiterhin vor jedem Append jede wiederholte `event_id` mit abweichendem kanonischem Payload.
Der rekonstruierbare Archive-Index verwendet dieselbe Generationsidentität: `(source_name, source_sha256)` muss eindeutig und sortiert sein. Derselbe Dateiname darf deshalb in mehreren Bundles vorkommen, sofern die Quell-SHA-256 verschieden ist; eine exakt doppelte Generation scheitert geschlossen.

Receipts bleiben nicht maßgeblich. Fehlen Ledger-Daten, werden sie trotz intaktem Receipt aus der Grabowski-Outbox rekonstruiert. Die Quelldateien bleiben deshalb Replay-Evidenz; Löschen oder Kompaktieren benötigt einen eigenen Verlustwiederherstellungsvertrag und folgt nicht aus der Receipt-Wiederverwendung.

## Terminalitätsgebundene Outbox-Kompaktierung

`compact-outbox` begrenzt die Zahl loser Grabowski-Quelldateien, ohne Receipts
oder einen zusätzlichen Index zur Wahrheit zu erheben. Der Befehl läuft
standardmäßig nur als Dry-run:

```bash
python tools/coding_memory.py \
  --data-dir ~/.local/state/chronik \
  compact-outbox \
  --outbox-root ~/.local/state \
  --receipt-dir ~/.local/state/chronik/import-receipts \
  --grace-seconds 86400
```

Jeder Aufruf betrachtet standardmäßig höchstens 256 lose Quellen und erzeugt
höchstens 64 MiB Bundle-Bytes. Die Grenzen sind mit `--max-sources` und
`--max-bytes` explizit enger oder weiter setzbar. Nicht betrachtete oder wegen
der Bytegrenze zurückgestellte Quellen bleiben unverändert liegen und werden
unter `loose_sources_deferred` beziehungsweise `skipped_by_reason` gezählt.
Damit sind CPU-/Validierungsarbeit und das neu veröffentlichte Bundle pro Lauf
begrenzt; wiederholte Apply-Läufe arbeiten deterministisch weiter.

Erst `--apply` erlaubt die Veröffentlichung eines Bundles und das anschließende
Entfernen geeigneter loser Quellen. Der Import-Timer führt diese Kompaktierung
nicht implizit aus.

Vor dem ersten Entfernen veröffentlicht Chronik zusätzlich
`bundles/archive-index.v1.json`. Diese kompakte, atomar ersetzte Projektion
ordnet jeden archivierten Quelldateinamen seinem Quell-Digest, seinen Event-IDs
und dem gebundenen Manifest zu. Chronik rekonstruiert und validiert den Index
bei jedem Apply aus sämtlichen gültigen Bundle-Manifesten; fehlt er, wird er
auch dann wiederhergestellt, wenn keine lose Quelle mehr kompaktierbar ist.
Ein beschädigter, widersprüchlicher oder nicht lesbar zurückgeprüfter Index
blockiert das Entfernen der Quelle.

Der Archivindex ist keine zusätzliche Historien- oder Taskautorität. Die
unveränderlichen Bundle-Dateien und ihre Manifeste bleiben die maßgebliche
Replay-Evidenz. Der Index ist eine rekonstruierbare Schreibschutzprojektion,
damit der Grabowski-Produzent nach einer Kompaktierung denselben logischen
Quellpfad nicht erneut als verkürzte Teilhistorie anlegt.

### Autoritätsgrenzen

- Der Chronik-Ledger bleibt die operative Import- und Abfrageautorität.
- Eine lose Grabowski-JSONL-Datei oder ein vollständig validiertes Bundle enthält
  die Replay-Evidenz, aus der ein verlorener Ledger wiederhergestellt werden
  kann.
- Ein Import-Receipt belegt nur einen früheren Abgleich. Es darf weder einen
  fehlenden Ledger ersetzen noch allein eine Quelle löschbar machen.
- Bundle und Manifest begründen keine aktuelle Task-, Git-, Dienst- oder
  Deployment-Wahrheit.

Ein Bundle besteht aus einer unveränderlichen JSONL-Datei und einem kanonisch
SHA-256-gebundenen Manifest. Die Bundle-Datei ist selbst gültiges JSONL und
besteht aus den unveränderten,
direkt aneinandergereihten Quellbytes. Das Manifest bindet für jede Quelle den
Bytebereich, deren SHA-256, die ursprüngliche Reihenfolge der Ereignisse und
einen eigenen Digest. Dateinamen, Bundle-Digest, Manifest-Digest,
Quellinventar und Ereignis-IDs werden beim Lesen erneut geprüft. Der streng
validierte Quelldateiname erlaubt einen Restore unter einem anderen
Outbox-Wurzelpfad; der ursprüngliche absolute Pfad bleibt nur gebundene
Provenienz. Unvollständige, verwaiste oder korrupte Artefakte werden nicht
importiert.

### Auswahlvertrag

Eine lose Quelle ist nur kompaktierbar, wenn alle folgenden Bedingungen zugleich
erfüllt sind:

1. Die Datei ist vollständiges und gültiges Grabowski-JSONL.
2. Das letzte Ereignis ist `agent.run.completed` oder `agent.run.blocked`.
   Eine Datei mit ausschließlich `agent.run.started` bleibt aktiv und wird nie
   kompaktifiziert.
3. Die konfigurierte Grace-Periode seit der letzten Dateiänderung ist abgelaufen.
4. Das vorhandene Receipt ist intakt und exakt an Quellpfad, Quellbytes,
   Quell-SHA-256 und Ereignis-IDs gebunden.
5. Jedes Ereignis ist mit identischem kanonischem Payload im tatsächlichen
   Chronik-Ledger vorhanden.
6. Geräte-ID, Inode, Größe, Änderungszeit und SHA-256 bleiben während Auswahl,
   Veröffentlichung und Entfernung unverändert.

Fehlt nur eine Bedingung, bleibt die Quelle liegen. Die Ausgabe zählt die Gründe
unter `skipped_by_reason` und meldet Fehler mit dem betroffenen Pfad.

### Publish-, Crash- und Race-Vertrag

Der Import-Timer führt die Compaction nicht im Zwei-Minuten-Importpfad aus. Eine getrennte `chronik-outbox-compact.timer`-Unit plant sie alle 15 Minuten mit niedriger CPU-/I/O-Priorität. Pro Lauf gelten dieselben harten Standardgrenzen von 256 Quellen und 64 MiB; der Produzent und der Compactor teilen den bestehenden `.writer-compaction.lock`, sodass eine laufende Compaction keinen konkurrierenden Grabowski-Writer überschreibt. Die Unit ist nur ein deploybares Artefakt: Installation, Enable/Start und jede Änderung des Live-Runtimes bleiben an den separaten Runtime-Aktivierungsvertrag gebunden.

Der Apply-Pfad legt zuerst ein echtes, nicht verlinktes Bundleverzeichnis an
und synchronisiert dessen Eintrag im Outbox-Verzeichnis. Danach veröffentlicht
er zuerst die Bundle-Datei und anschließend das Manifest.
Beide Artefakte werden über eine temporäre Datei geschrieben, per `fsync`
gesichert, ohne Ersetzen eines vorhandenen Artefakts veröffentlicht, das
Verzeichnis wird synchronisiert und die Bytes werden vollständig zurückgelesen.
Erst nach erfolgreichem Manifest-Readback werden die ausgewählten Quellen erneut
gegen ihre ursprüngliche Dateiidentität und ihren SHA-256 geprüft und einzeln
entfernt. Danach wird auch das Quellverzeichnis synchronisiert.

Daraus folgen definierte Crashzustände:

- **Nur Bundle vorhanden:** Das Bundle ist verwaist, wird diagnostiziert und
  ignoriert. Die losen Quellen bleiben Replay-Evidenz.
- **Bundle und Manifest vorhanden, Quellen noch vorhanden:** Import liest beide
  Darstellungen, dedupliziert nur bei exakt gleichen Quellbytes und schlägt bei
  Abweichung vor jeder Ledgermutation fehl.
- **Nur ein Teil der Quellen entfernt:** Das gültige Bundle deckt alle
  ausgewählten Quellen ab; verbliebene identische Quellen werden dedupliziert.
- **Quelle während des Laufs verändert:** Sie wird nicht entfernt. Weichen lose
  und gebündelte Bytes danach ab, stoppt der Import fail-closed.
- **Fehler beim Entfernen oder Verzeichnis-`fsync`:** Der Fehler wird gemeldet.
  Bereits entfernte Quellen sind durch das zuvor vollständig validierte Bundle
  replayfähig; nicht entfernte Quellen bleiben erhalten.

Wiederholtes `--apply` ist sicher: Sind keine geeigneten losen Quellen mehr
vorhanden, entsteht kein neues Bundle und es wird nichts entfernt.

### Wiederherstellung und Rollback

Zur Wiederherstellung dürfen Ledger und Receipts in einer isolierten
Testumgebung fehlen. `import-outbox` liest dann die gültigen Bundles, rekonstruiert
alle enthaltenen Ereignisse im leeren Ledger und erzeugt die nichtautoritativen
Receipts erneut. Ein Restore gilt erst als belegt, wenn Ereigniszahl, Event-IDs
und Ledger-Integrität mit dem Bundle-Inventar übereinstimmen.

Ein Rollback der Anwendungsversion löscht keine Bundles. Solange eine ältere
Chronik-Version Bundles nicht versteht, müssen sie zusammen mit dem letzten
Ledger-Backup erhalten bleiben; die bereits entfernten losen Quellen können aus
den manifestgebundenen Original-Bytebereichen des Bundles rekonstruiert
werden. Für das
Löschen oder Zusammenführen vorhandener Bundles gibt es in diesem Vertrag keine
automatische Retentionsregel.

Der Outbox-Benchmark misst deshalb getrennt Wiederholungsimporte mit vielen losen
Dateien, die einmalige Kompaktierung und den anschließenden Import desselben
Ereignisbestands aus dem Bundle. Er verlangt weiterhin höchstens einen
vollständigen Ziel-Ledger-Scan je Importlauf.
