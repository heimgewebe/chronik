# Chronik operator runbook

Chronik is the append-only event ledger and historical evidence axis. It is a store and evidence surface, not an orchestrator.

## Authority boundary

Chronik may record validated events and expose historical evidence. It must not dispatch tasks, control workers, mutate GitHub state, promote Bureau verification, restart services, deploy code, or decide orchestration outcomes.

## Phase 0 service bootstrap

The Phase 0 service files are documented in `docs/chronik-service.md`. The bootstrap PR only prepares artifacts:

- `deploy/systemd/user/chronik.service`
- `deploy/systemd/user/chronik.env.example`
- `scripts/run-chronik-service.sh`
- `docs/chronik-service.md`

Preparing these files does not mean the service is installed, enabled, started, healthy, or authorized for runtime use.

## Configuration

Use `deploy/systemd/user/chronik.env.example` as the persistent service template. Replace the placeholder token with a strong local token before any service activation. Do not use `CHRONIK_TOKEN=dev` for a persistent user service.

Default service paths:

- repository: `~/repos/chronik`
- service env file: `~/.config/chronik/chronik.env`
- data directory: `~/.local/state/chronik/data`
- bind host: `127.0.0.1`
- bind port: `8788`

## Safe validation

Repository-only validation:

```bash
python3 scripts/check_role.py .ai-context.yml
python3 -m pytest -q tests/test_service_artifacts.py tests/test_chronik_outbox.py tests/test_agent_ledger_view.py
```

These checks do not start or enable a user service.

## Runtime activation gate

Any command that installs, enables, starts, restarts, deploys, or wires Chronik as a live service is a separate runtime action. It requires explicit approval and should include:

1. current Git head and clean worktree evidence,
2. non-secret env-file existence and permission checks,
3. a health/version smoke,
4. one append/read smoke against `agent.ledger`,
5. rollback steps for stopping/disabling the user service.

Do not print tokens or secret env values in receipts.

## Related documents

- `docs/operator-ecosystem-alignment.md` for ecosystem semantics.
- `docs/chronik-service.md` for service bootstrap scope.
- `docs/operations.md` for broader maintenance notes.
- `docs/openapi.yaml` for HTTP API shape.
