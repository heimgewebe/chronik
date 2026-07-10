# Operator Routing Outcome Export v1

Status: accepted contract slice  
Bureau task: `CHRONIK-HEIMLERN-OUTCOME-BRIDGE-V1-T002`  
Chronik envelope: `chronik.operator-routing-outcome-export.v1`  
Heimlern payload: `operator.routing_outcome.v1`

## Decision

Chronik owns the append-only transport envelope and historical query path. Heimlern owns the routing-outcome payload and all offline interpretation. Grabowski owns execution receipts and may later produce the redacted source material. None of these roles grants live routing authority.

This separation avoids two competing payload contracts:

- the canonical payload remains in `heimgewebe/heimlern`;
- Chronik carries an exact, digest-pinned mirror only for local validation;
- every export names the canonical repository, revision, path and schema digest;
- consumers reject drift instead of silently accepting a different payload shape.

## Envelope guarantees

A valid export contains:

- deterministic `event_id` derived from canonical export bytes excluding `event_id`;
- Chronik-compatible `source.repo`, `source.component`, `source.revision` and `source.run_id`;
- exact Heimlern payload-contract identity;
- canonical payload SHA-256;
- observation and export timestamps;
- digest-bound evidence references;
- fixed transport-only authority and no-auto-apply boundaries.

The validator checks both schemas, mirror identity, payload digest, event identity, timestamp ordering and a bounded redaction screen. Raw output fields, secret-shaped text and private absolute paths are rejected.

## Freshness rule

Append-only history must not store a mutable `fresh` or `stale` verdict. The envelope records `observed_at` and `exported_at`; `consumer_must_recompute=true` requires Heimlern or another reader to compute freshness against its own review time and policy.

## Mirror rule

`docs/mirrors/heimlern/operator.routing_outcome.v1.schema.json` is byte-identical to:

- repository: `heimgewebe/heimlern`
- revision: `6d70e4900377c92b540d07bd6b71fe36677c2ba5`
- path: `contracts/operator.routing_outcome.v1.schema.json`
- SHA-256: `cff1f19814d33dd0ba084b3b5d9e2d4b6c36b1276dab35c3256912b5c457712d`

The adjacent pin file is authoritative only for the local mirror identity. It does not transfer payload ownership to Chronik and does not refresh automatically.

## Validation

```bash
scripts/validate_operator_outcome_export.py tests/fixtures/operator-outcome/operator-routing-outcome-export.v1.json
python -m pytest -q tests/test_operator_outcome_export_contract.py
```

The fixture at `tests/fixtures/operator-outcome/operator-routing-outcome-export.v1.json` is fixture-equivalent evidence only. It does not prove production samples, runtime deployment, route superiority or permission to apply policy.

## Non-claims

This slice does not establish:

- routing-policy superiority;
- sufficient production sample size;
- automatic application permission;
- Chronik runtime readiness;
- a live Grabowski producer;
- Heimlern consumer readiness.
