# Chronik Coding Memory v1

Chronik records a narrow, append-only history of coding and operator outcomes. It is historical evidence, not live Git, CI, runtime or retry truth.

## Local path

```text
Grabowski task outbox -> tools/coding_memory.py import -> agent.ledger JSONL
                                              -> query/freeze -> hash-bound cohort receipt
```

No Plexer, Heimlern, Leitstand or long-running Chronik service is required. API and CLI use the same canonical envelope constructor. Imports are idempotent by `event_id` under the domain file lock.

## Runtime contract

`tools/coding_memory.runtime.v1.json` is the producer-owned, machine-readable runtime contract for the coding-memory CLI. It is deliberately a static release asset: a consumer can inspect the entrypoint, Python requirement and complete external import/distribution mapping **without executing Chronik code first**.

The contract is checked against two independent sources of truth:

- `requirements.txt` must contain the same distribution specifier for every declared runtime dependency;
- `tools/validate_coding_memory_runtime_contract.py` follows the local Python import closure from `tools/coding_memory.py` with the AST and fails if a non-stdlib import appears without a contract mapping, or if a declared import is no longer reachable.

The current closure declares `filelock`, `jsonschema`, `pydantic`, `pydantic-settings` and `PyYAML`. Consumers may resolve those constraints into their own reproducible lock, but must validate that their selected distributions satisfy the producer contract. The contract does not prove what is installed in a consumer environment and does not by itself prove runtime success.

`import-outbox` maintains a private, reconstructible `source-index.v1.json` next
to the import receipts. The projection binds loose files and immutable bundle
artifacts to full filesystem identity (including size, mtime and ctime) and
stores only event IDs plus payload fingerprints. An unchanged index entry may
verify that those exact payloads are already in the authoritative ledger; it
may never supply bytes for an append. Missing or empty ledgers therefore bypass
the projection and replay the validated Outbox/Bundle bytes. Missing, corrupt
or drifted projections are rebuilt from those same authoritative sources.

The import result contains `chronik-grabowski-import-telemetry.v1` with total
elapsed time, internal phase timings and source/change/event/byte counters. The
bounded service summary exposes the main counters without emitting source
inventories.

## Work context

`subject` may carry `repo`, `component`, `operation`, `bureau_task_id` and `pr_number`. `data.outcome` may be `completed`, `blocked`, `failed`, `reverted` or `outcome_unknown`. Payloads remain allow-listed and contain no raw logs, prompts, commands or secrets.

This runtime work does not synthesize richer outcomes: Chronik preserves only
validated producer claims and evidence fields owned by the existing event
contract. A receipt, Source-Index hit or ledger presence never upgrades an
unknown outcome to a fact.

## Frozen history brief

`freeze` writes an exact JSONL cohort and a sibling receipt containing query parameters, event IDs, SHA-256 digests, generation time and the mandatory boundary:

- historical only;
- does not establish current Git state;
- does not establish current CI state;
- does not establish current runtime state;
- does not establish a safe retry.

A Vibe-Lab experiment may cite the receipt as `chronik:<receipt_sha256>`. It must not copy mutable live-state claims from Chronik or auto-apply a policy.
