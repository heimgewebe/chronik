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

Preparing or reviewing this gate performs no service, deployment, fleet, or secret action. Every listed effect requires explicit approval:

- `systemctl enable`, `systemctl start`, `systemctl restart`, or another user-service state change;
- installing or deploying a unit, runner, environment file, or repository revision;
- any fleet mutation, including copying artifacts or changing a remote host;
- secret handling, including creating, reading, replacing, copying, or deleting an environment or token file.

Approval must identify the target host, unit, source revision, intended effects, and secret paths without disclosing secret values. Approval for one target or effect does not authorize another.

A proposed activation must freeze and review this evidence before execution:

1. the exact Git head and a clean source worktree;
2. the target host, unit name, bind address, port, and data directory;
3. non-secret file metadata and permissions for the unit, runner, and environment file;
4. a health/version smoke after separately approved activation;
5. one append/read smoke against `agent.ledger` using a generated non-secret event;
6. rollback triggers and the exact stop, disable, file-restore, daemon-reload, process, and port checks.

The rollback plan must restore the previous hash-bound artifacts or remove only files created by the approved activation, then prove that the exact unit is inactive and disabled and that no Chronik process or listener remains. Rollback execution is itself part of the approved runtime action; this preparation task does not execute it.

Receipts must contain hashes and non-secret metadata only. They must not contain tokens, secret environment values, or environment-file contents.

## Related documents

- `docs/operator-ecosystem-alignment.md` for ecosystem semantics.
- `docs/chronik-service.md` for service bootstrap scope.
- `docs/operations.md` for broader maintenance notes.
- `docs/openapi.yaml` for HTTP API shape.
