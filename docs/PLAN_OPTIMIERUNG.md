# Optimierungsplan für heimgewebe/chronik

Dieser Plan basiert auf einer Architektur- und Code-Evaluierung und definiert Maßnahmen zur Weiterentwicklung des Repositories. Ziel ist die Verbesserung von Wartbarkeit, Sicherheit und Skalierbarkeit unter Beibehaltung des Lean-Ansatzes (ADR-0001, ADR-0002).

## 1. Wartbarkeit & Code-Qualität (Kurzfristig)

Die Priorität liegt auf der Entkopplung der monolithischen Verarbeitungslogik und der Modernisierung der Validierung unter Wahrung der Contracts-First-Strategie.

### 1.1 Modularisierung der Ingest-Logik
Die Funktion `_process_items` in `app.py` vereint aktuell Validierung, Normalisierung, Provenance-Checks, Qualitätsberechnung und Retention-Logik.
**Maßnahme:** Aufspaltung in dedizierte funktionale Stages (keine komplexe Klassenarchitektur):
- `IngestValidationStage` (funktional): Kapselt Schema- und Provenance-Prüfungen.
- `QualityPipelineStage`: Wendet die Logik aus `quality.py` an.
- `RetentionService`: Kapselt die TTL-Berechnung (nutzt intern `retention.RetentionPolicy`).

### 1.2 Einsatz von Pydantic (als Adapter)
Aktuell erfolgt die Input-Validierung teilweise manuell oder über `jsonschema`.
**Maßnahme:** Nutzung von Pydantic-Modellen für die HTTP-Schicht (DX, OpenAPI).
- **Wichtig:** JSON Schema/Contracts bleiben die kanonische "Single Source of Truth". Pydantic dient lediglich als Adapter für die HTTP-Schnittstelle und darf die Schema-Validierung nicht ersetzen oder aufweichen.
- Vorteile: Automatische Generierung von OpenAPI-Doku, präzisere 400/422 Fehlermeldungen.

### 1.3 Test-Automatisierung & CI
Im Ordner `tests/` existiert bereits eine umfangreiche Testsuite.
**Maßnahme:**
- **CI prüfen & ergänzen:** Sicherstellen, dass die Tests (`pytest`) und Linter (`ruff`, `mypy`) in den GitHub Actions Workflows bei jedem Push laufen.
- **Golden Fixtures:** Einführung von "Golden Tests" (Snapshot-Tests). Diese vergleichen die persistierte JSONL-Struktur bis auf explizit volatile Felder (z.B. `received_at`, `request_id`, generierte `uuid`s), um unbeabsichtigte Semantikänderungen durch Refactorings zu verhindern.

### 1.4 Konfigurationsmanagement
**Maßnahme:** Einführung einer zentralen `Settings`-Klasse (z.B. mit `pydantic-settings`), um `os.getenv`-Aufrufe zu bündeln und typisiert bereitzustellen.

## 2. Sicherheit & Observability (Mittelfristig)

### 2.1 Audit-Logging
**Maßnahme:** Einführung eines strukturierten Audit-Logs (JSON-Format) für Ingest-Entscheidungen.
- Protokollierung von: `timestamp`, `request_id`, `domain`, `action` (ACCEPTED/REJECTED), `reason`, `client_ip` (anonymisiert).

### 2.2 Auth & Abuse Protection
Gemäß ADR-0002 ist der Header `x-auth` (case-insensitiv) verpflichtend.
**Maßnahme:** Härtung der Authentifizierung:
- **Rate Limiting:** Konsequente Anwendung von Limits (SlowAPI) zum Schutz vor Brute-Force/DoS.
- **Statuscodes:** Klare Trennung der Semantik:
    - **401:** Header fehlt oder ist leer.
    - **403:** Header vorhanden, aber Token ungültig.
- **Token:** Vorbereitung für Token-Rotation oder Multi-Token-Support (optional).

### 2.3 Differenzierteres Fehler-Handling
**Maßnahme:** Klare Trennung von Client-Fehlern (Validierung -> 400/422) und Server-Fehlern (Storage -> 500/507).
- Storage-Exceptions (`StorageError`) dürfen nicht unmaskiert an den Client gelangen.

## 3. Performance & Skalierbarkeit (Langfristig / Bei Bedarf)

Die aktuelle Architektur (File-based, FileLock) ist für das MVP angemessen (ADR-0002). Optimierungen erfolgen messwertgetrieben.

### 3.1 Verzeichnis-Sharding
Sollte die Anzahl der Domains stark steigen (> 10.000, messwertgetrieben), kann das flache `data/`-Verzeichnis zum Flaschenhals werden.
**Maßnahme (Optional):** Einführung einer Verzeichnisstruktur basierend auf Domain-Präfixen (z.B. `data/h/heimgeist.jsonl`).

### 3.2 Asynchrones Dateimanagement
Aktuell nutzt `storage.py` synchrones I/O innerhalb von `run_in_threadpool`. Da `FileLock` synchron ist, bringt `aiofiles` allein keinen vollen Async-Gewinn.
**Maßnahme (Optional):** Monitoring der I/O-Last im Threadpool. Nur bei Engpässen Umstellung auf asynchrone Patterns prüfen.

### 3.3 Query-Erweiterungen
**Maßnahme:** Erweiterung der `/v1/tail` API um Zeitfilter (`since`, `until`).
- **Semantik:** Filter beziehen sich strikt auf `received_at` (Server-Empfangszeit), um Eindeutigkeit zu gewährleisten.
- **Format:** ISO8601 mit UTC (`Z`).
- **Grenzen:** `since` (inklusiv), `until` (exklusiv).

## 4. Abgrenzung (Out of Scope)

Folgende Punkte werden **nicht** umgesetzt:
- **Datenbank-Backend:** Gemäß ADR-0002 bleibt Chronik dateibasiert.
- **Edit/Delete-API:** Chronik ist ein Append-Only Log. Korrekturen erfolgen durch Kompensations-Events.
