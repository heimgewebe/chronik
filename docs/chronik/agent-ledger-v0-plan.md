# Chronik Agent Ledger v0 – Ausbauplan

Status: draft
Zielrepo: `heimgewebe/chronik`
Branch: `docs/chronik-agent-ledger-v0-plan`
Erstellt: 2026-07-02

## 0. These / Antithese / Synthese

**These:** Chronik kann langfristig zur zeitlichen Infrastruktur des Heimgewebe-Agentensystems werden: ein kausales Betriebsgedächtnis, das Agentenläufe, Repo-Änderungen, Review-Findings, Bureau-Claims, Bundle-Artefakte und spätere Korrekturen nachvollziehbar verbindet.

**Antithese:** Eine harte Integration wäre aktuell nicht gerechtfertigt. Der Dienst läuft lokal nicht als `chronik.service`, Port `8788` ist nicht sichtbar, ein lokaler Testlauf scheitert ohne eingerichtete Dependencies, es gibt kein rLens-Bundle und keine aktive Grabowski-Kopplung. Wer jetzt alles fest verdrahtet, baut kein Gedächtnis, sondern einen dekorativen Fehlerverstärker.

**Synthese:** Chronik wird nicht durch mehr Logging wertvoll, sondern durch eine reversible, fail-soft und konsumentengetriebene Entwicklung: erst Outbox, minimale Eventfamilien, Kausalbezüge und eine konkrete Consumer-View; erst danach stärkere Kopplung.

## 1. Zielbild

Chronik soll vom leichten Append-only-Ingest zu einem **Causality Ledger** für das Heimgewebe-Agentenökosystem wachsen.

Nicht Ziel:

> Chronik speichert möglichst viele Events.

Ziel:

> Chronik beantwortet: Was ist wann durch wen passiert, wodurch wurde es belegt, was folgte daraus, welche frühere Ursache oder Entscheidung hängt daran, und welche wiederkehrende Reibung wird sichtbar?

Chronik bleibt dabei **nicht** Orchestrator, Planner, Dashboard oder semantische Deutungsschicht.

Rollenabgrenzung:

| Organ | Aufgabe | Chronik-Beziehung |
|---|---|---|
| Grabowski | Ausführung, Repo-/Systemoperationen | erzeugt Lauf- und Ergebnisereignisse; liest relevante Vorgeschichte |
| Bureau | Claims, Aufgabenaufnahme, Plan-/Statuslogik | erzeugt Claim-/Taskereignisse; nutzt Chronik für Laufhistorie |
| Vibe-Lab | Evidence, Experimente, Run-Cards | bleibt Primärort für Belege; Chronik verweist auf Evidence |
| rLens/Lenskit | Kontextpakete, Repo-Lesbarkeit | erzeugt Bundle-/Freshness-Events; Chronik verweist auf Bundle-Artefakte |
| semantAH / heimlern | Bedeutung, Muster, Lernen | spätere Konsumenten, nicht v0-Abhängigkeit |
| Leitstand | Sichtbarkeit, Lagebild | spätere View-Oberfläche, nicht v0-Abhängigkeit |

Merksatz: Chronik ist die Zeitachse, nicht das Gehirn. Ein Gehirn mit Tagebuch ist nützlich; ein Tagebuch, das glaubt, es sei ein Gehirn, wird schnell Romanfigur.

## 2. Alternative Sinnachse

Die Leitfrage wird bewusst verschoben:

Nicht: **Wie integrieren wir Chronik stärker?**

Sondern: **Welche Systemereignisse dürfen nicht länger ohne rekonstruierbare Zeitspur geschehen?**

Dadurch entsteht eine andere Priorität: Nicht jedes Repo soll sofort nach Chronik schreiben. Zuerst werden jene Ereignisse erfasst, bei denen fehlende Erinnerung realen Schaden erzeugt:

1. Agentenlauf wurde begonnen, aber nie abgeschlossen.
2. PR wurde gemerged, obwohl Review-Findings unklar waren.
3. Ein Blocker taucht wiederholt auf, wird aber jedes Mal neu entdeckt.
4. Bundle-/Kontext-Freshness ist unklar.
5. Bureau-Task und tatsächliche Ausführung laufen auseinander.
6. Ein Override wurde getroffen, aber später ist nicht mehr sichtbar warum.

## 3. No-Brainer-Bedingungen

Chronik-Integration wird erst dann zum No-brainer, wenn mindestens drei dieser Effekte messbar eintreten:

1. **Kontextverlust sinkt:** Grabowski kann beim Start eines ähnlichen Tasks relevante frühere Events anzeigen.
2. **Doppelte Arbeit sinkt:** Wiederkehrende Blocker/Friction werden erkannt, bevor erneut Debugzeit verbrannt wird.
3. **Review-Gates werden belastbarer:** Findings, Overrides, Restpunkte und Merge-Entscheidungen sind historisch sichtbar.
4. **Bureau plant besser:** Tasks können nach echter Laufhistorie, nicht nur nach Dokumentenlage priorisiert werden.
5. **Vibe-Lab wird gestützt:** Run-Cards erhalten maschinenlesbare Eventanker, ohne Evidence zu ersetzen.
6. **Replay wird möglich:** Ein Agentenlauf lässt sich anhand von Events und Artefaktrefs rekonstruieren.
7. **Leitstand bekommt Lagebilder:** Nicht nur statische Reports, sondern zeitliche Betriebszustände.

Wenn diese Effekte nicht entstehen, bleibt Chronik optionales Logging und darf nicht weiter ausgedehnt werden.

## 4. Designprinzipien

### 4.1 Fail-soft vor Pflichtpfad

Kein Agentenlauf darf scheitern, nur weil Chronik nicht erreichbar ist.

Pflicht:

- lokale Outbox vor HTTP-Push
- idempotente `event_id`
- Retry mit Backoff
- Flush später möglich
- harte Timeouts
- keine synchrone Merge-/Review-Blockade durch Chronik

### 4.2 Outbox-first

Producer schreiben zunächst lokal in eine Outbox-Datei, z. B.:

```text
.local/state/<producer>/chronik-outbox/*.jsonl
```

Ein Flush-Befehl überträgt Events an `POST /v1/ingest`.

Vorteile:

- Chronik-Ausfall blockiert nicht.
- Events bleiben prüfbar.
- Tests können ohne laufenden Dienst arbeiten.
- Migration zu Servicebetrieb bleibt möglich.

### 4.3 Kleine Eventfamilien

v0 darf maximal diese Eventfamilien einführen:

- `agent.run.started`
- `agent.run.completed`
- `agent.run.blocked`
- `repo.pr.created`
- `repo.pr.reviewed`
- `repo.pr.merged`
- `review.finding.recorded`
- `bureau.claim.created`
- `artifact.bundle.created`
- `context.pack.created`
- `friction.recorded`

Neue Eventtypen brauchen einen Consumer-Nachweis oder ein klares Diagnoseziel.

### 4.4 Kausalität statt flacher Timeline

Jedes Event kann Kausalbezüge tragen:

```json
{
  "event_id": "...",
  "kind": "agent.run.completed",
  "ts": "2026-07-02T12:00:00Z",
  "source": {
    "repo": "heimgewebe/grabowski",
    "component": "grabowski"
  },
  "subject": {
    "repo": "heimgewebe/chronik",
    "branch": "docs/chronik-agent-ledger-v0-plan"
  },
  "caused_by": ["event:..."],
  "evidence_refs": ["repo:path@sha256:..."],
  "data": {}
}
```

Kausalbezüge sind optional, aber wenn vorhanden, müssen sie stabil referenzierbar sein.

### 4.5 Trust-Tiers

Nicht jedes Event ist gleich belastbar.

Erlaubte `trust_tier`:

- `observed`: direkt gemessen, z. B. Git-Head, CI-Status, Service-State
- `declared`: Agent berichtet Ergebnis
- `inferred`: System leitet Zustand ab
- `corrected`: spätere Korrektur eines früheren Events
- `superseded`: alte Deutung wurde ersetzt

Regel: Chronik löscht Irrtümer nicht still. Chronik markiert sie. Ein Gedächtnis, das Fehler heimlich glättet, ist keine Infrastruktur, sondern PR-Abteilung.

### 4.6 Evidence bleibt extern

Chronik speichert keine langen Belege und keine vollständigen Run-Cards.

Chronik speichert:

- kurze Eventdaten
- Hashes
- Pfade
- PR-Nummern
- Bundle-Stems
- Run-IDs
- kurze Reason-Codes

Vibe-Lab, Repo-Dokumente, PRs und Artefakte bleiben Primärbelege.

## 5. Phasenplan

## Phase 0 – Readiness und Stop/Go

Ziel: Beweisen, dass Chronik lokal reproduzierbar prüfbar ist.

Umfang:

1. venv-/Dependency-Pfad dokumentieren oder automatisieren.
2. `python -m pytest -q` reproduzierbar grün machen.
3. Metrics-Workflow-Fehler bewerten: reparieren, deaktivieren oder dokumentiert aus dem Ledger-Scope nehmen.
4. `/health`, `/version`, `/v1/ingest`, `/v1/events` lokal smoke-testen.
5. rLens-Bundle für Chronik erzeugen.

Akzeptanzkriterien:

- lokaler Testbefehl dokumentiert und grün
- keine fehlenden Import-Dependencies im Standardpfad
- Healthcheck-Befehl dokumentiert
- rLens-Context-Pack für Chronik verfügbar

Stop-Kriterium:

- Wenn Tests nur durch lokale Sonderzustände grün werden, keine Integrationsarbeit beginnen.

## Phase 1 – Agent Event Contract v0

Ziel: Minimalen, contracts-kompatiblen Eventvertrag formulieren.

Umfang:

1. Neues Doku-/Schema-Konzept: `agent.ledger.event.v0`.
2. Feldgruppen definieren:
   - identity: `event_id`, `kind`, `ts`
   - source: `repo`, `component`, optional `run_id`
   - subject: Repo, PR, branch, task, artifact
   - causality: `caused_by`, `supersedes`, `blocks`, `unblocks`
   - trust: `trust_tier`, `confidence`
   - evidence: `evidence_refs`
   - payload: `data`
3. Validierungsregeln definieren, aber nicht zu früh überverengen.
4. Secret-/Redaction-Regeln festlegen.

Akzeptanzkriterien:

- maximal eine neue Eventfamilie-Doku oder Schema-Datei
- Beispiel-Events für Started/Completed/Blocked
- Validierungsentscheidung dokumentiert: lokal in Chronik vs. metarepo Contract

Stop-Kriterium:

- Wenn kein konkreter Consumer für v0 benannt wird, Contract nur dokumentieren, nicht implementieren.

## Phase 2 – Outbox-Client

Ziel: Schreiben ohne Runtime-Zwang.

Umfang:

1. Kleine Python-Lib oder CLI:
   - `chronik-outbox append`
   - `chronik-outbox flush`
   - `chronik-outbox status`
2. Idempotente Event-IDs.
3. Lokaler JSONL-Spool.
4. HTTP-Flush mit Retry/Timeout.
5. Fehler bleiben lokal sichtbar.

Akzeptanzkriterien:

- Tests ohne laufenden Chronik-Dienst
- Flush-Test gegen FastAPI TestClient oder lokalen Dienst
- Ausfall von Chronik blockiert Producer nicht

Stop-Kriterium:

- Wenn Outbox mehr Komplexität erzeugt als direkter Eventnutzen, Phase 2 einfrieren und nur Doku behalten.

## Phase 3 – Ein Producer: Grabowski oder Bureau

Ziel: Genau ein realer Producer schreibt Events.

Empfohlener erster Producer: **Grabowski**, aber nur für bounded Events:

- `agent.run.started`
- `agent.run.completed`
- `agent.run.blocked`
- optional `friction.recorded`

Alternative erster Producer: **Bureau**, wenn Claim-/Task-Historie wichtiger ist.

Entscheidungskriterium:

| Kriterium | Grabowski zuerst | Bureau zuerst |
|---|---:|---:|
| viele reale Läufe | hoch | mittel |
| klare Eventpunkte | hoch | hoch |
| Risiko harter Kopplung | mittel | niedrig |
| direkter Nutzen für nächste Agentenläufe | hoch | mittel |
| Planungsnutzen | mittel | hoch |

Empfehlung: Grabowski schreibt Outbox; Bureau liest erst später.

Akzeptanzkriterien:

- ein echter Agentenlauf erzeugt 2–3 Events
- Events enthalten Repo, Branch, Run-ID, Ergebnis, Evidenzref
- Eventschreiben ist optional/fail-soft
- keine Secrets in Payloads

Stop-Kriterium:

- Wenn Events nur Duplikate existierender Logs ohne neue Abfragefähigkeit sind, Producer nicht ausweiten.

## Phase 4 – Erste Consumer-View

Ziel: Nutzen beweisen.

Eine einzige View bauen:

> Letzte Agentenläufe pro Repo mit Ergebnis, Blocker und Evidence-Ref.

Mögliche Ausgabe:

```text
repo                last_run              result      blocker              evidence
heimgewebe/chronik  2026-07-02T12:00Z     blocked     missing-deps          run:...
heimgewebe/lenskit  2026-07-02T11:40Z     completed   -                    pr:...
```

Akzeptanzkriterien:

- Grabowski oder Bureau kann diese View lesen.
- Die View hilft bei mindestens einem Folge-Task nachweisbar.
- Keine UI nötig; CLI/JSON reicht.

Stop-Kriterium:

- Wenn niemand die View nutzt, keine weiteren Producer anbinden.

## Phase 5 – Evidence-Verknüpfung mit Vibe-Lab

Ziel: Events mit Run-Cards und Receipts verbinden, ohne Vibe-Lab zu ersetzen.

Umfang:

1. `evidence_refs` für Vibe-Lab-Pfade standardisieren.
2. Run-Card kann optional Chronik-Event-ID nennen.
3. Chronik-Event kann Run-Card-Pfad/hash nennen.
4. Keine doppelten Langtexte.

Akzeptanzkriterien:

- Ein Vibe-Lab-Run und seine Chronik-Events sind wechselseitig auffindbar.
- Event bleibt klein.
- Evidence bleibt Primärquelle.

## Phase 6 – Auswertung und stärkere Integration

Ziel: Nach realer Nutzung entscheiden.

Messfenster: 30 Tage oder mindestens 20 reale Events aus mindestens 5 Läufen.

Auswertung:

- Wie oft wurde die Chronik-View genutzt?
- Hat sie eine Entscheidung geändert?
- Hat sie doppelte Arbeit verhindert?
- Wurden Events falsch, doppelt oder nutzlos geschrieben?
- Gab es Secret-/Payload-Probleme?
- War Betrieb stabil?

Go-Kriterien für Ausbau:

- mindestens 2 belegte Fälle, in denen Chronik-Kontext eine Entscheidung verbessert hat
- keine harten Producer-Blockaden durch Chronik-Ausfall
- Eventtypen bleiben unter Kontrolle
- ein Consumer existiert wirklich

No-Go:

- Events werden nur gesammelt, aber nicht gelesen
- Payloads sind unredigiert oder zu groß
- Chronik wird zur Pflichtdependency
- Producer divergieren semantisch

## 6. Integrationsmatrix

| Reposystem | v0-Aktion | v1-Aktion | Nicht tun |
|---|---|---|---|
| chronik | Readiness, Contract, Outbox | Views, replay-nahe Queries | semantische Bewertung übernehmen |
| grabowski | optionaler Outbox-Producer | liest letzte relevante Läufe | Lauf blockieren, wenn Chronik down ist |
| bureau | späterer Consumer | Claim-/Task-Historie schreiben | automatisch Tasks nur aus Events erzeugen |
| vibe-lab | Evidence-Refs | Run-Card-Verknüpfung | Evidence in Chronik duplizieren |
| lenskit/rLens | Bundle-Events | Freshness-/Context-Pack-Events | komplette Bundles in Chronik speichern |
| leitstand | später View-Anzeige | Lagebild | eigene Wahrheit erzeugen |
| semantAH/heimlern | später Pattern-Consumer | Friction-/Policy-Lernen | v0 blockieren |

## 7. Risiken und Gegenmaßnahmen

| Risiko | Folge | Gegenmaßnahme |
|---|---|---|
| Event-Spam | Rauschen, keine Entscheidungen | maximal 5–10 Eventtypen in v0 |
| harte Kopplung | Agentenläufe brechen bei Chronik-Ausfall | Outbox-first, Timeouts, optional |
| doppelte Wahrheit | Vibe-Lab/Bureau/Chronik widersprechen sich | Evidence-Refs, Trust-Tiers, Korrektur-Events |
| Secret-Leaks | Sicherheitsrisiko | Redaction-Regeln, keine Rohlogs, Payload-Limits |
| Schema-Overengineering | langsame Umsetzung | v0 dokumentarisch klein halten |
| Consumer fehlt | Nutzen bleibt hypothetisch | Phase 4 vor Ausbau verpflichtend |
| falsche Sicherheit | Event = Beweis wird verwechselt | Trust-Tiers und Evidence-Refs erzwingen |

## 8. Nutzenhypothesen

### Hypothese H1 – weniger Kontextverlust

Wenn Grabowski vor einem neuen Repo-Task die letzten Chronik-Events zu Repo/Branch/Tasktyp lesen kann, sinkt wiederholte Kontextklärung.

Messung:

- Anzahl manuell nachgereichter Kontextblöcke
- Anzahl wiederentdeckter Blocker
- qualitative Fallnotiz in Vibe-Lab oder Bureau

### Hypothese H2 – bessere Review-Historie

Wenn PR-Reviews und Findings als kleine Events erfasst werden, werden Overrides und Restpunkte später rekonstruierbar.

Messung:

- PR mit Finding → Fix → Merge ist nachvollziehbar
- Merge-Entscheidung referenziert Findings/Evidence

### Hypothese H3 – Bureau plant realistischer

Wenn Bureau Laufereignisse lesen kann, kann es Tasks nach realer Reibung priorisieren.

Messung:

- mindestens ein Bureau-Task wird aufgrund Chronik-Historie anders priorisiert

## 9. Minimaler erster Slice

Name: `chronik-agent-ledger-v0-readiness`

Umfang:

1. Chronik-Testumgebung stabilisieren.
2. rLens-Bundle erzeugen.
3. Agent-Ledger-v0-Doku/Schemagrundlage erstellen.
4. Outbox-Format definieren, noch ohne breite Producer-Integration.
5. Eine Demo-Outbox-Datei mit 3 Events erzeugen.
6. Eine einfache Query/View skizzieren: letzte Agentenläufe pro Repo.

Nicht enthalten:

- kein systemd-Pflichtbetrieb
- keine Grabowski-Pflichtintegration
- keine Semantik-/ML-Auswertung
- keine Leitstand-UI
- keine metarepo-weite Contract-Migration ohne Review

## 10. Reihenfolge der nächsten konkreten PRs

### PR 1 – docs: define agent ledger plan

Inhalt:

- dieser Plan
- Verweis aus `docs/PLAN_OPTIMIERUNG.md` oder `docs/architecture.md`

Risiko: niedrig.

### PR 2 – chore: make chronik local validation reproducible

Inhalt:

- dokumentierter venv/test command
- ggf. `requirements-dev.txt` ergänzen
- lokale Importfehler beseitigen

Risiko: niedrig bis mittel.

### PR 3 – docs/contracts: define agent ledger event v0 examples

Inhalt:

- Eventfelder
- Beispiele
- Trust-Tiers
- Redaction-Regeln

Risiko: mittel, weil Contract-Semantik langlebig wird.

### PR 4 – feat: add outbox writer prototype

Inhalt:

- lokaler Append
- Flush-Befehl
- Tests ohne laufenden Dienst

Risiko: mittel.

### PR 5 – integration experiment: one producer

Inhalt:

- Grabowski oder Bureau erzeugt optional Events
- fail-soft
- 30-Tage-Auswertung festlegen

Risiko: mittel bis hoch; erst nach PR 1–4.

## 11. Entscheidungslogik

Stärkere Integration ist erlaubt, wenn:

- Phase 0 grün ist
- ein Consumer benannt ist
- Outbox funktioniert
- Events klein und redigiert bleiben
- ein messbarer Nutzenfall dokumentiert ist

Stärkere Integration ist verboten, wenn:

- Chronik als Pflichtdienst vor Producer-Läufen nötig wird
- niemand Events liest
- Eventtypen unkontrolliert wachsen
- Evidence dupliziert statt referenziert wird
- Secret-Safety unklar ist

## 12. Epistemische Leere

Folgende Informationen fehlen und sind für spätere Entscheidungen nötig:

- tatsächlicher Zielhost für Chronik-Betrieb: heim-pc oder heimserver
- produktiver `CHRONIK_DATA_DIR`
- Token-/Secret-Verwaltung
- reale Consumer-Priorität: Grabowski, Bureau oder Leitstand zuerst
- gewünschte Retention pro Agent-Eventfamilie
- erwartetes Eventvolumen
- Datenschutz-/Redaction-Policy für Agentenpayloads

Ohne diese Informationen darf v0 nicht als Produktionsintegration verkauft werden.

## 13. Vorläufiges Urteil

Chronik kann langfristig ein No-brainer werden, aber nur als **kausales, fail-softes Betriebsgedächtnis**.

Kurzfristig lautet die richtige Strategie:

1. Readiness beweisen.
2. Eventvertrag klein halten.
3. Outbox statt Pflichtdienst.
4. Einen Producer anbinden.
5. Einen Consumer-View bauen.
6. Nutzen messen.
7. Erst dann ausweiten.

Essenz:

> Nicht Chronik überall anschließen. Erst eine Vergangenheit bauen, die jemand tatsächlich nutzt.
