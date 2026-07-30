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
./scripts/setup-venv.sh
./.venv/bin/python scripts/check_role.py .ai-context.yml
./.venv/bin/python -m pytest -q tests/test_service_artifacts.py tests/test_chronik_outbox.py tests/test_agent_ledger_view.py
```

These checks do not start or enable a user service.

## Runtime activation gate

Preparing or reviewing this gate performs no service, deployment, fleet, or secret action.

### Effects requiring separate approval

Each effect below is a separate runtime action and requires its own explicit approval:

- `systemctl enable`, `systemctl start`, `systemctl restart`, or another user-service state change.
- Installation or deployment of a unit file, runner, environment file, package, or repository revision.
- Any fleet mutation, including copying artifacts or changing a remote host.
- Secret handling, including creating, reading, replacing, copying, or deleting an environment or token file.

Approval must identify the target host, unit, exact source revision, intended effects, and secret paths without disclosing secret values. Approval for one target or effect does not authorize another.

### Evidence required before approval

The approval request must bind immutable review-time evidence:

1. The exact Git commit ID and proof of a clean source worktree.
2. The target host, unit name, bind address, port, data directory, and destination paths.
3. SHA-256 hashes of every non-secret artifact proposed for installation or deployment, including the unit file, runner, package, or repository export as applicable.
4. Non-secret file metadata and permissions for all affected files. For a secret environment file, record only its path, owner, group, mode, size, and existence state.
5. A complete rollback plan with explicit triggers, previous artifact identities, and the exact stop, disable, restore, daemon-reload, process, and port checks.

This evidence must be reviewed before approval. Any source, artifact, target, permission, or rollback-plan drift invalidates the approval request and requires a new review.

### Approved execution boundary

Execution may begin only after an approval matches the frozen evidence and explicitly authorizes every intended effect. The executor must fail closed if the source revision, artifact hashes, target identity, permissions, or requested effects differ from the approved record.

Preparing or reviewing this gate does not execute the activation or its rollback.

### Verification after approved activation

Only after the separately approved activation has executed:

- Run an authenticated health/version smoke test.
- Run one append/read smoke test against `agent.ledger` using a generated non-secret event.
- Record the exact unit state, process identity, and listener state for the approved host and port.

These runtime smokes are post-activation verification. They are not pre-approval preparation checks.

### Rollback plan and execution

The rollback plan is reviewed before approval. The activation approval must also authorize execution of that exact rollback when a documented trigger occurs.

The rollback must restore the previous hash-bound non-secret artifacts or remove only files created by the approved activation. It must then prove that the exact unit is inactive and disabled and that no Chronik process or listener remains on the approved port.

Preparing or reviewing the rollback plan does not execute it. Rollback execution occurs only within the separately approved runtime action and only when an approved trigger occurs.

### Receipt requirements

Receipts must bind the exact Git commit ID and SHA-256 hashes of installed or restored non-secret artifacts, together with target paths, non-secret metadata, command outcomes, unit state, process checks, and listener checks.

For secret files, receipts may contain only paths and non-secret metadata. They must not contain tokens, secret values, environment-file contents, or hashes derived from secret contents.

## Related documents

- `docs/operator-ecosystem-alignment.md` for ecosystem semantics.
- `docs/chronik-service.md` for service bootstrap scope.
- `docs/operations.md` for broader maintenance notes.
- `docs/openapi.yaml` for HTTP API shape.
