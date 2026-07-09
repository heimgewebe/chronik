# Runtime-Lens Evidence Bridge v1

Status: accepted
Bureau task: `RPU-V1-T017`
Schema: [`runtime-lens-observation-v1.schema.json`](runtime-lens-observation-v1.schema.json)
Domain: `runtime.lens`

## Dialectic

**Thesis:** Agents need one small bridge between RepoBrief code citations and runtime observations. Otherwise every drift claim gets reconstructed ad hoc from logs, screenshots, service status, and snapshot metadata.

**Antithesis:** If the bridge is too strong, RepoBrief quietly becomes runtime authority and Chronik becomes an operations lever. That would collapse separate evidence layers into a false verdict path.

**Synthesis:** Chronik may store a bounded `runtime.lens.observation` event. The event links code evidence to runtime evidence, labels both authority sources, and records drift only as an observation. It must not restart services, deploy, read secrets, mutate Git, approve changes, or claim correctness.

## Purpose

The bridge answers one narrow question:

> What code snapshot was cited, what runtime observation was seen, and what drift relationship was observed between them?

It does not answer:

- whether the code is correct;
- whether the runtime is healthy enough for production;
- whether tests are sufficient;
- whether a pull request is merge-ready;
- whether a deployment is safe.

## Event shape

A valid bridge event uses:

```text
schema_version = runtime-lens-observation.v1
kind           = runtime.lens.observation
domain         = runtime.lens
```

The payload has five authority-bearing sections:

| Section | Role | Boundary |
|---|---|---|
| `code_evidence` | RepoBrief snapshot identity and citations | code evidence only |
| `runtime_evidence` | observed runtime source, timestamp and provenance | runtime observation only |
| `drift` | relation between code identity and runtime identity | observation, not verdict |
| `authority` | fixed labels for code/runtime/verdict authority | verdict authority is `none` |
| `boundary` | forbidden actions for RepoBrief and Chronik | prevents authority smuggling |

## Runtime evidence sources

Allowed runtime evidence sources are deliberately coarse:

- `service_status`
- `service_log_excerpt`
- `deployment_identity`
- `health_endpoint`
- `metrics_snapshot`
- `manual_observation`
- `grabowski_receipt`

Every runtime evidence item must have:

- `observed_at` as UTC timestamp;
- `authority_label` as `observed_runtime`, `declared_runtime`, or `inferred_runtime`;
- at least one provenance anchor: `artifact_sha256`, `command_sha256`, `receipt_sha256`, or `uri`;
- a bounded summary.

## Drift semantics

`drift.status` is intentionally not a pass/fail field.

| Value | Meaning |
|---|---|
| `aligned_observed` | code and runtime identity appeared aligned in the cited observation |
| `drift_observed` | a mismatch was observed |
| `unknown` | evidence was present but insufficient |
| `not_checked` | the event records inputs but no drift check |

`drift.basis` names the observed relation, such as `commit_identity_match`, `commit_identity_mismatch`, `runtime_newer_than_snapshot`, `snapshot_newer_than_runtime`, or `inconclusive`.

## Authority rules

### RepoBrief may provide

- snapshot stem;
- repository identity;
- commit identity;
- manifest hash;
- cited file ranges;
- source content hashes.

### RepoBrief must not provide

- service restart;
- deploy;
- systemd mutation;
- secret read;
- runtime write;
- Git mutation;
- PR merge.

### Chronik may provide

- append-only event storage;
- queryable event history;
- bounded historical views.

### Chronik must not provide

- task dispatch;
- approval decision;
- service restart;
- deploy;
- correctness verdict.

## Non-claims

A valid `runtime.lens.observation` event does not establish:

- `runtime_correctness`
- `code_correctness`
- `test_sufficiency`
- `review_completeness`
- `merge_readiness`
- `security_correctness`
- `regression_absence`
- `deployment_safety`

## Example

See [`tests/fixtures/runtime-lens/runtime-lens-observation.v1.json`](../../tests/fixtures/runtime-lens/runtime-lens-observation.v1.json).

## Consequence

The bridge is useful when agents need to say, with bounded evidence:

> This RepoBrief snapshot says X at commit C; this runtime observation says service S ran identity R at time T; the identity relation was observed as D.

The bridge is unsafe if used to say:

> Therefore the runtime is correct, the deployment is good, or the PR may be merged.
