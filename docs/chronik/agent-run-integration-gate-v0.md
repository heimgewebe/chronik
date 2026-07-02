# Agent Run Integration Gate v0

Status: draft
Scope: erste echte `agent.run.*`-Schreibanbindung nach Chronik

## These / Antithese / Synthese

**These:** Nach Readiness, Contract, Outbox und Demo-View ist eine erste echte Schreibanbindung technisch möglich.

**Antithese:** Technisch möglich heißt nicht architektonisch erlaubt. Eine frühe Anbindung kann Chronik zur impliziten Pflichtinfrastruktur machen und damit genau den fail-soft-Grundsatz verletzen.

**Synthese:** Eine echte Schreibanbindung darf erst erfolgen, wenn sie dieses Gate erfüllt: outbox-only, optional, klein, redigiert, messbar und jederzeit abschaltbar.

## 1. Zulässiger erster Kandidat

Erster Kandidat ist **Grabowski**, weil dort Agentenläufe klar beginnen, enden oder blockieren.

Zulässig sind nur diese Events:

- `agent.run.started`
- `agent.run.completed`
- `agent.run.blocked`

Nicht zulässig:

- PR-Events
- Review-Finding-Events
- Bureau-Claim-Events
- Friction-Mülleimer-Events
- Rohlogs, Prompts, Tooloutputs oder vollständige Reviewtexte

## 2. Harte Preflight-Kriterien

Ein Integrations-PR darf erst geöffnet werden, wenn alle Punkte erfüllt sind:

1. `make validate-local` ist grün.
2. `agent-run-event-v0.schema.json` validiert die erzeugten Events.
3. `tools.chronik_outbox` wird genutzt; keine direkte Chronik-HTTP-Abhängigkeit im Laufpfad.
4. `tools.agent_ledger_view` kann die erzeugten Demo-Events lesen.
5. Eventschreiben ist standardmäßig deaktivierbar oder klar optional.
6. Ein Chronik-Ausfall darf den Agentenlauf nicht blockieren.
7. Payload-Felder folgen strikt der Redaction-Allow-List.
8. Evidence wird referenziert, nicht kopiert.
9. Es gibt mindestens einen Test, der Chronik-Ausfall oder Flush-Fehler als nicht blockierend beweist.
10. Es gibt einen Test, der zeigt, dass keine zusätzlichen Eventarten geschrieben werden.

## 3. Runtime-Regeln

Eine echte Schreibanbindung muss folgende Regeln einhalten:

- Nur in lokale Outbox schreiben.
- Keine synchrone Netzwerkpflicht im Hauptlauf.
- Kein Retry-Loop im Agentenlauf selbst.
- Kein Crash bei fehlendem Chronik-Token.
- Kein Crash bei fehlendem Outbox-Verzeichnis.
- Kein Secret, Prompt, Tooloutput oder Rohlog im Event.
- Keine Eventtypen außerhalb `agent.run.*`.
- Keine automatische Bureau-Task-Erzeugung.
- Keine automatische Leitstand-Anzeige.

Kurz: Der Agent darf Chronik füttern, aber Chronik darf ihn nicht an der Leine führen.

## 4. Organ-Reihenfolge

| Organ | Gate-Rolle | Grenze |
|---|---|---|
| Chronik | Contract, Outbox, Demo-View | kein Orchestrator |
| Grabowski | erster möglicher Schreiber | nur optional und outbox-only |
| Bureau | späterer Leser | keine Autotasks aus Events |
| Vibe-Lab | Evidence-Primärort | keine Langtexte in Chronik |
| rLens/Lenskit | Kontext- und Bundle-Referenzen | keine Bundle-Kopie in Chronik |
| Steuerboard | read-only Repo-State-Kontext | kein Gate, keine Freigabe |
| Cabinet | spätere Ausbau-/Freeze-Entscheidung | nicht vor Nutzennachweis |
| Leitstand, semantAH, heimlern, hausKI | spätere Konsumenten | nicht im ersten Integrations-PR |

## 5. Akzeptanzkriterien für den ersten Integrations-PR

Ein erster Integrations-PR ist nur akzeptabel, wenn er:

- genau einen Schreiber betrifft
- genau drei Eventarten maximal schreiben kann
- lokale Outbox-Dateien erzeugt
- bei Flush-/Chronik-Fehlern weiterläuft
- erzeugte Events per Demo-View sichtbar macht
- Tests für Erfolg und Ausfall enthält
- keine bestehende Laufsemantik verändert
- keine neue dauerhafte Dienstabhängigkeit einführt

## 6. Messfenster nach Integration

Nach der ersten echten Schreibanbindung wird nicht sofort erweitert.

Auswertung erst nach:

- mindestens 15 realen Agentenläufen
- mindestens 3 unterschiedlichen Zielrepos
- mindestens 1 dokumentierter Fall, in dem die Demo-View eine Folgeentscheidung verbessert hat

Pausieren oder zurückbauen, wenn:

- niemand die View liest
- Events nur bestehende Logs duplizieren
- Eventtypen wachsen
- Payloads zu groß werden
- Chronik-Ausfall Läufe blockiert
- Evidence kopiert statt referenziert wird

## 7. Explizite Nicht-Freigabe

Dieses Gate erlaubt **noch nicht**:

- Bureau-Consumer
- Leitstand-UI
- semantische Auswertung
- metarepo-Contractmigration
- systemd-Pflichtbetrieb
- Chronik als Merge- oder Review-Gate

## 8. Nächster erlaubter Schritt

Erst nach diesem Gate ist folgender Slice zulässig:

```text
experiment: connect grabowski run outbox
```

Auch dieser Slice bleibt ein Experiment. Er beweist nur, dass ein Schreiber fail-soft Ereignisse erzeugen kann. Er beweist noch nicht, dass Chronik langfristig nützlich ist.
