# Optimierungsplan für heimgewebe/chronik

Dieser Plan basiert auf einer Architektur- und Code-Evaluierung und definiert Maßnahmen zur Weiterentwicklung des Repositories. Ziel ist die Verbesserung von Wartbarkeit, Sicherheit und Skalierbarkeit unter Beibehaltung des Lean-Ansatzes (ADR-0001, ADR-0002).

## 1. Wartbarkeit & Code-Qualität (Kurzfristig)

Die Priorität liegt auf der Entkopplung der monolithischen Verarbeitungslogik und der Modernisierung der Validierung.

### 1.1 Modularisierung der Ingest-Logik
Die Funktion `_process_items` in `app.py` vereint aktuell Validierung, Normalisierung, Provenance-Checks, Qualitätsberechnung und Retention-Logik.
**Maßnahme:** Aufspaltung in dedizierte Komponenten:
- `IngestValidator`: Kapselt Schema- und Provenance-Prüfungen.
- `QualityAssessor`: Isoliert die Logik aus `quality.py` und deren Anwendung.
- `RetentionPolicy`: Kapselt die TTL-Berechnung.

### 1.2 Einsatz von Pydantic
Aktuell erfolgt die Input-Validierung teilweise manuell oder über `jsonschema`.
**Maßnahme:** Nutzung von Pydantic-Modellen für Request-Bodies in FastAPI.
- Vorteile: Automatische Generierung von OpenAPI-Doku, präzisere Fehlermeldungen, weniger Boilerplate-Code in `app.py`.

### 1.3 Test-Automatisierung & CI
Entgegen der Evaluierung existieren bereits umfangreiche Tests im Ordner `tests/` (z.B. Integrity, Schema, Quality).
**Maßnahme:**
- Sicherstellen, dass diese Tests in einer CI-Pipeline (z.B. GitHub Actions) bei jedem Push ausgeführt werden.
- Erweiterung der Tests um Szenarien für die neuen Module (nach Refactoring).

### 1.4 Konfigurationsmanagement
**Maßnahme:** Einführung einer zentralen `Settings`-Klasse (z.B. mit `pydantic-settings`), um `os.getenv`-Aufrufe zu bündeln und typisiert bereitzustellen.

## 2. Sicherheit & Observability (Mittelfristig)

### 2.1 Audit-Logging
**Maßnahme:** Einführung eines strukturierten Audit-Logs (JSON-Format) für Ingest-Entscheidungen.
- Protokollierung von: `timestamp`, `request_id`, `domain`, `action` (ACCEPTED/REJECTED), `reason`, `client_ip` (anonymisiert).
- Dies ergänzt das bestehende Request-Logging.

### 2.2 Differenzierteres Fehler-Handling
**Maßnahme:** Klare Trennung von Client-Fehlern (Validierung -> 400/422) und Server-Fehlern (Storage -> 500/507).
- Sicherstellen, dass Storage-Exceptions (`StorageError`) nicht unmaskiert an den Client durchgereicht werden, aber im Server-Log mit Stacktrace erscheinen.

## 3. Performance & Skalierbarkeit (Langfristig / Bei Bedarf)

Die aktuelle Architektur (File-based, FileLock) ist für das MVP angemessen (ADR-0002). Optimierungen erfolgen nur bei messbaren Engpässen.

### 3.1 Verzeichnis-Sharding
Sollte die Anzahl der Domains stark steigen (> 10.000), kann das flache `data/`-Verzeichnis zum Flaschenhals werden.
**Maßnahme (Optional):** Einführung einer Verzeichnisstruktur basierend auf Domain-Präfixen (z.B. `data/h/heimgeist.jsonl`).

### 3.2 Asynchrones Dateimanagement
Aktuell nutzt `storage.py` synchrones I/O innerhalb von `run_in_threadpool`.
**Maßnahme (Optional):** Evaluierung von `aiofiles` für echte asynchrone Dateioperationen, falls der Threadpool limitiert. Hinweis: `FileLock` ist synchron, was eine vollständige Umstellung erschwert.

### 3.3 Query-Erweiterungen
**Maßnahme:** Erweiterung der `/v1/tail` API um Zeitfilter (`since`, `until`) und eventuell einfache Typ-Filter, um Clients das Parsen unnötiger Daten zu ersparen.

## 4. Abgrenzung (Out of Scope)

Folgende Punkte aus der Evaluierung werden **nicht** umgesetzt, da sie den Architektur-Entscheidungen widersprechen:
- **Datenbank-Backend:** Gemäß ADR-0002 bleibt Chronik dateibasiert. Komplexere Abfragen gehören in nachgelagerte Systeme (Data Lake / Warehouse).
- **Edit/Delete-API:** Chronik ist ein Append-Only Log ("Wahrheit zum Empfangszeitpunkt"). Korrekturen erfolgen durch neue Events ("Compensating Transactions").
