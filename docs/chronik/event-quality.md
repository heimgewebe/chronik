# chronik: Event Quality, Provenance & Retention

## Überblick

chronik implementiert drei zentrale Invarianten für die Event-Verarbeitung:

1. **Provenienz**: Jedes Event muss seine Herkunft dokumentieren
2. **Qualität**: Events werden strukturell bewertet (nicht semantisch)
3. **Retention**: Events haben definierte Lebenszyklen

Diese Funktionen stellen sicher, dass chronik als verlässlicher Event-Backbone dient, ohne selbst interpretierend zu werden.

## 1. Event-Provenienz

### Ziel
Jedes Event muss klar nachvollziehbar sein: Woher kommt es? Welche Komponente hat es erzeugt? Wie ist es identifizierbar?

### Pflichtfelder

Wenn Provenienz-Enforcement aktiviert ist (`CHRONIK_ENFORCE_PROVENANCE=1`), werden folgende Felder zwingend erforderlich:

- **`source.repo`** (string): Repository/System-Name (z.B. `"heimgewebe/wgx"`)
- **`source.component`** (string): Komponente innerhalb des Systems (z.B. `"semantAH"`, `"hausKI"`)
- **`event_id`** (string): Eindeutiger Event-Identifier (UUID oder deterministisch)

### Beispiel

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "source": {
    "repo": "heimgewebe/wgx",
    "component": "semantAH"
  },
  "kind": "embedding.computed",
  "ts": "2026-01-04T10:00:00Z",
  "data": {
    "vector_dim": 768
  }
}
```

### Konfiguration

```bash
# Provenienz erzwingen (Events ohne Provenienz werden abgelehnt)
export CHRONIK_ENFORCE_PROVENANCE=1

# Standard: Provenienz wird geprüft, aber nur gewarnt (kein Reject)
export CHRONIK_ENFORCE_PROVENANCE=0
```

**Hinweis**: Die ENV-Variablen werden zur Laufzeit ausgelesen (nicht beim Import eingefroren), sodass Tests flexibel zwischen Modi wechseln können.

### Verhalten

- **Strict Mode** (`ENFORCE_PROVENANCE=1`):
  - Events ohne Provenienz → HTTP 400
  - Metrik `chronik_provenance_validation_failures_total` wird erhöht
  
- **Permissive Mode** (`ENFORCE_PROVENANCE=0`, Default):
  - Events ohne Provenienz → Warnung im Log
  - Event wird akzeptiert (Backward Compatibility)

## 2. Qualitätsmarker

### Ziel
Strukturelle Bewertung von Events basierend auf Vollständigkeit und Form, **nicht** auf semantischem Inhalt.

### Marker

chronik fügt jedem Event automatisch ein `quality`-Objekt **auf Envelope-Ebene** hinzu (nicht im payload):

```json
{
  "domain": "aussen",
  "received_at": "2026-01-04T10:00:00Z",
  "payload": {
    // Original event data - unverändert
  },
  "quality": {
    "signal_strength": "high",
    "completeness": true
  },
  "retention": { ... }
}
```

**Wichtig**: Das `quality`-Objekt ist Envelope-Metadata und wird **nicht** in das `payload`-Feld eingefügt. Der ursprüngliche Event-Payload bleibt unverändert.

#### signal_strength

Regelbasierte Bewertung der Event-Struktur:

- **`high`**: Event hat alle Kern-Felder (kind/type, timestamp, source, data, id)
- **`medium`**: Event hat einige Kern-Felder, aber unvollständig
- **`low`**: Event fehlen die meisten Kern-Felder oder ist sehr spärlich

**Wichtig**: Dies ist keine semantische Bewertung. Ein Event mit allen Feldern hat `high`, auch wenn der Inhalt unsinnig ist.

#### completeness

Boolean-Flag: `true`, wenn alle erwarteten Pflichtfelder vorhanden sind.

### Konfiguration

```bash
# Qualitätsmarker aktivieren (Standard)
export CHRONIK_ENABLE_QUALITY=1

# Qualitätsmarker deaktivieren
export CHRONIK_ENABLE_QUALITY=0
```

### Metriken

Prometheus-Metriken für Signal Strength:

```
chronik_events_signal_strength_total{domain="aussen",signal_strength="high"} 1234
chronik_events_signal_strength_total{domain="aussen",signal_strength="medium"} 56
chronik_events_signal_strength_total{domain="aussen",signal_strength="low"} 12
```

## 3. Retention-Regeln

### Ziel
Definierte Lebenszyklen für Events: Debug-Events verschwinden nach 7 Tagen, kanonische Events bleiben unbegrenzt.

### Konfiguration

Retention-Policies sind in `config/retention.yml` definiert:

```yaml
policies:
  # Use dot-delimited patterns to avoid false matches
  - pattern: "debug.*"
    ttl_days: 7
    description: "Debug events - 7 days retention"
  
  - pattern: "*.debug"
    ttl_days: 7
    description: "Debug events (suffix) - 7 days retention"
  
  - pattern: "*.published.v1"
    ttl_days: 0
    description: "Canonical published events - unlimited retention"
  
  - pattern: "*"
    ttl_days: 30
    description: "Default retention"
```

**Wichtig:** Policies werden beim Start geladen und gecached. Änderungen an `retention.yml` erfordern einen Neustart.

### Pattern-Matching

- Policies verwenden `fnmatch`-Patterns (Unix-Wildcard-Syntax)
- First-Match-Wins: Erste passende Policy wird angewendet
- `ttl_days: 0` bedeutet unbegrenzte Retention

**Pattern-Strategie (Drift-Vermeidung):**
- ✅ **Empfohlen**: `debug.*`, `*.debug`, `*.debug.*` (dot-delimited)
  - Matcht nur: "debug.trace", "app.debug", "app.debug.trace"
  - Matcht NICHT: "debugger", "debugging" (keine Zufallstreffer)
  
- ⚠️ **Zu breit**: `*debug*` (catch-all)
  - Matcht auch: "debugger", "contest", "undebugable"
  - Risiko: Retention wird von Sprachzufällen gesteuert

**Pattern-Beispiele:**
- `debug.*` matcht "debug.test", "debug.trace"
- `*.debug` matcht "app.debug", "service.debug"
- `*.debug.*` matcht "app.debug.trace"
- `*debug*` matcht ALLES mit "debug" (inkl. "debugger", "undebugable")

**Event Type Bestimmung:**
- Retention-Policy basiert auf `kind`, `type` oder `event` Feld im Event
- Falls keines vorhanden: "unknown" → Default-Policy (30 Tage)
- Domain wird NICHT als Event-Typ verwendet (unterschiedliche Zwecke)

### Retention-Metadaten

chronik fügt jedem Event automatisch Retention-Informationen hinzu:

```json
{
  "domain": "aussen",
  "received_at": "2026-01-04T10:00:00Z",
  "payload": { ... },
  "retention": {
    "ttl_days": 30,
    "expires_at": "2026-02-03T10:00:00Z"
  }
}
```

- **`ttl_days`**: Time-To-Live in Tagen (0 = unbegrenzt)
- **`expires_at`**: Berechnetes Ablaufdatum (ISO 8601, `null` bei TTL=0)

### Cleanup

**Hinweis**: Das automatische Löschen abgelaufener Events ist noch nicht implementiert. Dies kann über ein separates Cleanup-Script erfolgen:

```python
from retention import is_expired
from datetime import datetime

# Beispiel: Events filtern
for event in events:
    expiry = event.get("retention", {}).get("expires_at")
    if expiry and is_expired(datetime.fromisoformat(expiry)):
        # Event ist abgelaufen
        pass
```

## 4. Metriken & Monitoring

### Prometheus-Metriken

chronik exportiert folgende zusätzliche Metriken unter `/metrics`:

#### Event-Ingestion
```
chronik_events_ingested_total{domain="aussen",event_type="deploy.success"} 1234
```

#### Event-Rejections
```
chronik_events_rejected_total{domain="aussen",reason="provenance"} 5
chronik_events_rejected_total{domain="aussen",reason="schema"} 2
```

#### Provenienz-Failures
```
chronik_provenance_validation_failures_total{domain="aussen"} 5
```

#### Signal Strength
```
chronik_events_signal_strength_total{domain="aussen",signal_strength="high"} 1234
chronik_events_signal_strength_total{domain="aussen",signal_strength="medium"} 56
chronik_events_signal_strength_total{domain="aussen",signal_strength="low"} 12
```

### Monitoring-Strategie

1. **Provenienz-Failures überwachen**: Hohe Rate → Clients passen sich nicht an
2. **Signal Strength Distribution**: Hoher Anteil `low` → Datenqualität prüfen
3. **Reject Rate**: Steigende Rejects → Breaking Changes in Contracts?

## 5. Was chronik NICHT tut

### Keine semantische Interpretation
- chronik bewertet nur Struktur, nicht Bedeutung
- Ein Event `{"kind": "nonsense", "ts": "2026-01-04T10:00:00Z", "source": {...}}` ist strukturell `high`, auch wenn semantisch unsinnig

### Kein automatisches Lernen
- chronik speichert nur, interpretiert nicht
- Semantisches Verständnis ist Aufgabe nachgelagerter Systeme (semantAH, heimgeist)

### Keine Garantie von Richtigkeit
- chronik garantiert formale Korrektheit, nicht inhaltliche
- "Garbage in, formally correct garbage out"

## 6. Migration & Backward Compatibility

### Schrittweise Einführung

1. **Phase 1** (aktuell): Provenienz optional
   - `CHRONIK_ENFORCE_PROVENANCE=0` (Default)
   - Events ohne Provenienz werden akzeptiert
   - Warnung im Log

2. **Phase 2**: Clients anpassen
   - Clients fügen Provenienz-Felder hinzu
   - Monitoring: Provenienz-Coverage steigt

3. **Phase 3**: Enforcement aktivieren
   - `CHRONIK_ENFORCE_PROVENANCE=1`
   - Events ohne Provenienz werden abgelehnt

### Breaking Changes vermeiden

- Neue Felder (`quality`, `retention`) werden **zusätzlich** hinzugefügt
- Bestehendes `payload`-Feld bleibt unverändert
- Konsumenten können neue Felder ignorieren

## 7. Beispiel-Workflow

### Event senden (mit Provenienz)

```bash
curl -X POST "http://localhost:8788/v1/ingest?domain=aussen" \
  -H "Content-Type: application/json" \
  -H "X-Auth: ${CHRONIK_TOKEN}" \
  -d '{
    "event_id": "550e8400-e29b-41d4-a716-446655440000",
    "source": {
      "repo": "heimgewebe/wgx",
      "component": "test-client"
    },
    "kind": "test.event",
    "ts": "2026-01-04T10:00:00Z",
    "data": {"status": "ok"}
  }'
```

### Gespeichertes Event (mit Quality + Retention)

```json
{
  "domain": "aussen",
  "received_at": "2026-01-04T10:00:05Z",
  "payload": {
    "event_id": "550e8400-e29b-41d4-a716-446655440000",
    "source": {
      "repo": "heimgewebe/wgx",
      "component": "test-client"
    },
    "kind": "test.event",
    "ts": "2026-01-04T10:00:00Z",
    "data": {"status": "ok"}
  },
  "quality": {
    "signal_strength": "high",
    "completeness": true
  },
  "retention": {
    "ttl_days": 7,
    "expires_at": "2026-01-11T10:00:05Z"
  }
}
```

## 8. Ungewissheit & Offene Punkte

### Implementationsstand: 0.85
- ✅ Provenienz-Validierung
- ✅ Qualitätsmarker
- ✅ Retention-Policies
- ✅ Metriken
- ⏳ Automatischer Cleanup (TTL-Enforcement)
- ⏳ Event-Index (SQLite)

### Kritische nächste Schritte
1. Retention-Cleanup-Script implementieren
2. Event-Index für schnelle Queries (Zeit, Typ, Repo)
3. Integration-Tests mit allen nachgelagerten Systemen

### Unbeleuchtete Punkte
- **Cold Storage**: Archivierung alter Events für historische Analysen
- **HMAC-Signaturen**: Event-Integrität (Schutz vor Manipulation)
- **Event-Taxonomie**: Zentrale Typen-Registry (gehört ins metarepo)

---

**Verdichtete Essenz**:  
chronik wird nicht klüger, sondern strenger. Genau das macht alle anderen klüger.
