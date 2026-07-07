# AGENTS.md

## Role

Chronik is the append-only event ledger and historical evidence axis for the operator ecosystem. It records and serves events; it does not orchestrate workers, own task truth, or make completion decisions.

## Operating boundaries

- Do not treat ledger presence as Bureau task completion or verification.
- Do not add worker control, queue dispatch, GitHub mutation, service restart, deploy, or fleet mutation paths here.
- Do not manually edit generated JSONL ledger files. Add fixtures or tests instead.
- Do not copy development token values into persistent service configuration.
- Runtime activation of the user service requires an explicit separate approval gate.

## Expected checks

Before proposing repository changes, run the narrowest relevant checks. For operator-role or service-bootstrap changes, use:

```bash
python3 scripts/check_role.py .ai-context.yml
python3 -m pytest -q tests/test_service_artifacts.py tests/test_chronik_outbox.py tests/test_agent_ledger_view.py
```

For broader application changes, prefer:

```bash
python3 -m pytest -q
```

## Key documents

- `.ai-context.yml` defines the machine-readable role contract.
- `docs/operator-ecosystem-alignment.md` explains the ecosystem boundary.
- `docs/chronik-service.md` defines the Phase 0 local service bootstrap.
- `docs/runbook.md` is the operator runbook entrypoint.
- `docs/operations.md` contains the broader operations notes.
