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

- `python3 -m pytest -q tests/test_runtime_lens_observation_contract.py`: 6 passed.
- `python3 -m pytest -q`: failed with system Python before collection because project dependencies such as `filelock` and `limits` were missing.
- `.venv/bin/python -m pytest -q`: 251 passed, 1 warning.
- `make validate-local`: passed; includes `251 passed, 1 warning` and local validation smoke.
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
