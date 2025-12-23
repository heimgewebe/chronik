# Heimgeist Event Specification

Source of Truth: `metarepo/contracts/heimgeist.insight.v1.schema.json`

This file is a derived explanation of the metarepo contract.

Wrapper: { kind: "heimgeist.insight", version: 1, id, meta: { occurred_at }, data }

ID: evt-${insight.id}

Timestamp: meta.occurred_at (ISO8601)

Transport: POST /v1/ingest?domain=heimgeist (Canonical)
