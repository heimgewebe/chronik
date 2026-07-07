# chronik service

Phase 0 makes chronik a local user service before further producer or consumer work.

Scope: systemd user unit, local FastAPI runtime on port 8788, explicit data directory, authenticated health/version check, and a real append/read smoke through v1 ingest and v1 events. Runtime activation itself remains a follow-up.

Not part of this slice: producer rollout, semantic consumer migration, read-index construction, backup work, and live service activation.

Default locations: user unit under the systemd user directory, repository under the local repos directory, service configuration under `~/.config/chronik/chronik.env`, and data under `~/.local/state/chronik/data`. The repository `.env.example` is development-only; do not copy its development token into a persistent service. Use `deploy/systemd/user/chronik.env.example` as the service template and replace the token.

Acceptance: health returns ok, version returns a version payload, ingest accepts one generated agent.ledger event, and events returns the same event with a byte cursor. The service runner fails before starting uvicorn when `CHRONIK_TOKEN` is missing, so authenticated endpoints do not degrade into a running-but-unusable service.

Boundary: the service is only the store runtime. It must not dispatch tasks, mutate GitHub, or promote Bureau state by itself.
