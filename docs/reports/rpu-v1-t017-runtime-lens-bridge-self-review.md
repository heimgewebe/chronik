# RPU-V1-T017 Runtime-Lens Bridge Self-Review

Status: review-ready
Task: `RPU-V1-T017`
Repo: `heimgewebe/chronik`
Branch: `feat/runtime-lens-evidence-bridge-v1`

## Scope checked

This change defines a Chronik-local Runtime-Lens observation bridge between RepoBrief code evidence and runtime observations.

Changed surfaces:

- `docs/chronik/runtime-lens-evidence-bridge-v1.md`
- `docs/chronik/runtime-lens-observation-v1.schema.json`
- `tests/fixtures/runtime-lens/runtime-lens-observation.v1.json`
- `tests/test_runtime_lens_observation_contract.py`
- `docs/event-contracts.md`

## Review findings

### Material findings fixed

- The draft used `producer`, but Chronik strict provenance validates `source.repo` and `source.component`; the event now uses the live-compatible `source` object.
- Boundary arrays previously allowed omission of named forbidden actions; exact full-set cardinalities are now required.
- `non_claims` previously allowed omission of two declared safeguards; all eight are now required.

### Accepted

- The schema requires explicit runtime evidence source, timestamp and provenance anchor.
- RepoBrief authority is constrained to snapshot/code evidence.
- Runtime evidence authority is constrained to observation only.
- `authority.verdict_authority` is fixed to `none`.
- The schema rejects extra fields and action-smuggling values.
- Drift may be reported as `drift_observed`, but the event still cannot become a correctness verdict.

### Risks

- This is a contract/documentation slice, not an ingest endpoint specialization. Chronik still accepts generic payloads at the storage layer.
- The schema is Chronik-local for now. It is not yet promoted to a metarepo canonical contract.
- A future producer must be tested separately against the same schema before writing real events.

### Boundary check

This change does not add:

- service restart;
- deploy;
- systemd mutation;
- secret read;
- runtime write;
- Git mutation beyond this repository change;
- PR merge authority;
- correctness verdict authority.

## Validation

- `/home/alex/repos/chronik/.venv/bin/python -m pytest -q`: 253 passed, 1 warning.
- `/home/alex/repos/chronik/.venv/bin/python scripts/check_role.py`: role-contract OK.
- The fixture passes `validate_provenance(..., strict=True)`.
- `git diff --check`: passed.

## Does not establish

- runtime correctness;
- code correctness;
- test sufficiency;
- review completeness;
- merge readiness;
- security correctness;
- deployment safety;
- metarepo contract promotion.
