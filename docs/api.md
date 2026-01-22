# Chronik API

## Ingest

### POST /v1/ingest

Accepts NDJSON or single JSON payload. Wraps it in a standard envelope and appends to storage. The domain can be specified via the `domain` query parameter or within the payload.

### POST /ingest/:domain (Deprecated)

Legacy endpoint. Use `/v1/ingest` instead.

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
  "limit": 100,
  "meta": {
      "count": 10,
      "generated_at": "..."
  }
}
```

*   `next_cursor`: An integer representing the byte offset for the next page. Always returned (even at EOF).
*   `has_more`: Boolean indicating if at least one more **valid** event exists after this batch. If `false`, you have reached the end of the known valid stream.
*   `limit`: The limit used for this request.
*   **Partial Lines**: If the file ends with a partial line (missing newline), it is strictly ignored until a newline is appended.

## Legacy Endpoints (Deprecated)

### GET /v1/tail (Deprecated)
Use `/v1/events` instead.

### GET /v1/latest (Deprecated)
Use `/v1/events` with `limit=1` (and iterate backwards if needed, though `/v1/events` is forward-only currently).
