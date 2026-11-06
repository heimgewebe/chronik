# Chronik: beweisgebundene Agentensuche

Chronik bleibt die kanonische append-only Quelle; die neue Suche erzeugt **kein
zweites Archiv und keine zusätzliche Ereigniserfassung**.

## Aufruf

Mit der bestehenden Chronik-Python-Umgebung und dem privaten Ledger:

    python tools/chronik_search.py --data-dir ~/.local/state/chronik/data search --repo heimgewebe/grabowski --since 2026-11-01T00:00:00Z
    python tools/chronik_search.py --data-dir ~/.local/state/chronik search --pr-number 959 --limit 20
    python tools/chronik_search.py --data-dir ~/.local/state/chronik/data get --event-id sha256:e45c8247a2c5d6064761d85c5954d3d17a54713516ddf83dbe826fc2563c324d

HTTP (bestehendes X-Auth, nur wenn der neue Chronik-Service deployed ist):

    GET /v1/chronik/search?repo=heimgewebe/grabowski&limit=20
    GET /v1/chronik/events/{event_id}

Auch HTTP schreibt keine Ereignisse. Es ist keine frei erreichbare öffentliche Schnittstelle; Geheimnisse sind nur über den bestehenden Secret-Mechanismus zu konfigurieren. Das neue API-Release kann zunächst unabhängig vom produktiven CLI-Leseweg getestet werden.

Unterstützte exakte Felder: event_id, repo, host, component (kanonischer
Producer), subject_component, kind, operation, task_class, outcome, pr_number,
bureau_task_id, run_id, task_id sowie since/until und keyword in
schemavalidierten Kontextfeldern. Filter werden UND-verknüpft.
Repositorysuche berücksichtigt ausdrücklich sowohl source.repo als auch
subject.repo: Host-Ereignisse dürfen nicht verschwinden, weil subject.repo fehlt.

Suchergebnisse sind neueste zuerst. next_cursor führt zur nächsten Seite;
has_more kennzeichnet weitere Treffer, matching_count die Treffermenge des
vollständig überprüften Ledger-Snapshots. Der Cursor bindet Filter, Position
und Snapshot-SHA-256. Bei zwischenzeitlicher Änderung des Ledgers muss die
Suche bewusst neu begonnen werden. Das ist keine globale Aussage über die
Abwesenheit zukünftiger Ereignisse.

Jeder Treffer enthält eine kanonische event_id, eine hashgebundene
Quellenreferenz, den gespeicherten Inhalt und den SHA-256 der kanonischen
Ereignisdaten. Die Ledger-Snapshot-SHA-256 und Validierungszähler sind
beigelegt. Diese Hashes **beweisen allein weder die externe Herkunft einer
Behauptung noch den tatsächlichen Erfolg eines Deployments**.

## Agentenregel

Vor einer aufwendigen Wiederholungsuntersuchung eines früheren Incidents
projekt- oder hostbezogen Chronik abfragen, dann bei Bedarf den exakten
Ereignisbeleg laden. Beobachtung, Hypothese, nachgewiesene Ursache,
GitHub-Merge und reale Runtime-Aktivierung getrennt berichten.
Chronik liefert Historie, keine gegenwärtige Betriebswahrheit.
Für aktuelle Behauptungen GitHub, tatsächliche Prozesse und Logs separat
über ihre Primärwerkzeuge prüfen.

Normale Starts, Erfolge und gewöhnliche Abbrüche bleiben ohne Opt-in
ereignisarm. Grabowski failed, timed_out und outcome_unknown werden seit
PR #1717 automatisch in der vorhandenen Outbox erfasst; diese Änderung wird
hier **nicht** erneut implementiert.

## Betriebs- und Sicherheitsgrenzen

Die Suche liest das vorhandene private Ledger über die bestehende Chronik-
Validierungsroutine. Sie erstellt keine eigene Datenbank. Die vorhandene
reproduzierbare Validierungs-Checkpoint-Datei kann durch den bestehenden
Chronik-Reader erneuert werden; das JSONL-Ledger bleibt unverändert.
Der CLI-Befehl besitzt keine Schreib-/Ingestfunktion.

Für ein eigenständiges ChatGPT-Plugin ist zusätzlich eine authentifizierte,
von ChatGPT erreichbare Tool-Verbindung erforderlich. Eine lokale CLI oder
ein Repository-Merge belegt **keine** erfolgreiche Installation in einem
anderen ChatGPT-Thread. Solange diese Verbindung fehlt, ist das bestehende
Grabowski-Plugin der erreichbare historische Leseweg mit dessen begrenztem
Provider-Fenster.