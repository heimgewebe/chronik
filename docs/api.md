# Chronik API

## Ingest

### POST /ingest/:domain/:kind

Accepts NDJSON or single JSON payload. Wraps it in a standard envelope and appends to storage.

## Reading Events

### GET /v1/events

Retrieve events for a given domain using a robust, cursor-based pagination mechanism.

**Parameters:**
*   `domain` (required): The domain to read from (e.g., `heimgeist.self_state.snapshot`).
*   `limit` (optional, default 100): Maximum number of events to return.
*   `cursor` (optional, default 0): The byte offset to start reading from.

**Response:**
```json
{
  "events": [ ... ],
  "next_cursor": 12345,
  "has_more": true,
  "limit": 100
}
```

*   `next_cursor`: An integer representing the byte offset for the next page. Always returned (even at EOF).
*   `has_more`: Boolean indicating if more events *might* be available (specifically, if the `limit` was reached). If `false`, you have reached the end of the known valid stream.
*   **Partial Lines**: If the file ends with a partial line (missing newline), it is strictly ignored until a newline is appended.

## Legacy Endpoints (Deprecated)

### GET /v1/tail (Deprecated)
Use `/v1/events` instead.

### GET /v1/latest (Deprecated)
Use `/v1/events` with `limit=1` (and iterate backwards if needed, though `/v1/events` is forward-only currently).
