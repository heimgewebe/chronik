# Integrity Contracts

This document defines the contracts for the Integrity Loop within the Heimgewebe architecture.

## Overview

The Integrity Loop ensures that the system's health and coherence are continuously monitored and reported.
- **Producers** (Repos) generate `summary.json` reports.
- **Chronik** pulls these reports as an Orchestrator.
- **Leitstand** visualizes the aggregated state.

## Report Format (`summary.json`)

Each repository participating in the fleet MUST provide a `summary.json` (via Release Asset or defined URL).

**Schema:**
```json
{
  "repo": "owner/name",
  "status": "OK" | "WARN" | "FAIL" | "MISSING" | "UNCLEAR",
  "generated_at": "ISO8601 Timestamp",
  "url": "Optional link to detailed report",
  "counts": { ... },
  "details": { ... }
}
```

## Chronik Ingestion Logic

Chronik acts as a **Pull Orchestrator**. It fetches the `summary.json` from the sources defined in `metarepo`.

### Validation & Sanitization (Path B)

Chronik validates the report. To ensure downstream parseability while maintaining semantic honesty, the following sanitization rules apply:

1.  **Status Normalization:**
    -   Only `OK`, `WARN`, `FAIL`, `MISSING`, `UNCLEAR` are accepted.
    -   Any other value is normalized to `UNCLEAR`.

2.  **Timestamp Sanitization (`generated_at`):**
    -   If `generated_at` is missing, unparseable, or in the future (> 10 mins):
        -   The report status is forced to `FAIL`.
        -   The `generated_at` field is sanitized to the current `received_at` (Chronik time) to ensure parseability.
        -   **Crucially**, a flag `generated_at_sanitized: true` is added to the payload.
    -   If `generated_at` is valid:
        -   The value is preserved as-is.
        -   The `generated_at_sanitized` flag MUST NOT be present.

3.  **Stability:**
    -   Chronik employs "Optimistic Concurrency Control": it will NOT overwrite a newer report with an older one (based on `generated_at`).
    -   Fetch failures (Network/HTTP) result in `MISSING` status but do **not** overwrite an existing valid state.

## API View (`GET /v1/integrity`)

Returns an aggregated view of the system state.

```json
{
  "total_status": "OK" | "WARN" | "FAIL" | "MISSING",
  "repos": [
    {
      "repo": "owner/name",
      "status": "OK",
      "generated_at": "2023-01-01T12:00:00Z",
      "generated_at_sanitized": false,
      "url": "..."
    }
  ]
}
```
