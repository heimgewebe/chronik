# Heimgeist Event Specification (Sync-Punkt A)

Domain: heimgeist

Wrapper: { kind: "heimgeist.insight", version: 1, id, meta: { occurred_at, role }, data }

ID: evt-${insight.id}

Timestamp: meta.occurred_at (ISO8601)

Transport: POST /ingest/heimgeist (+ Header X-Auth)
