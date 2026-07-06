# chronik service

Phase 0 makes chronik a local user service before further producer or consumer work.

Scope: systemd user unit, local FastAPI runtime on port 8788, explicit data directory, authenticated health/version check, and a real append/read smoke through v1 ingest and v1 events.

Not part of this slice: producer rollout, semantic consumer migration, and read-index construction.

Default locations: user unit under the systemd user directory, repository under the local repos directory, configuration under the local chronik config directory, and data under the local chronik state directory.

Acceptance: health returns ok, version returns a version payload, ingest accepts one generated agent.ledger event, and events returns the same event with a byte cursor.

Boundary: the service is only the store runtime. It must not dispatch tasks, mutate GitHub, or promote Bureau state by itself.
