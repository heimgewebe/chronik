# Chronik Coding Memory v1

Chronik records a narrow, append-only history of coding and operator outcomes. It is historical evidence, not live Git, CI, runtime or retry truth.

## Local path

```text
Grabowski task outbox -> tools/coding_memory.py import -> agent.ledger JSONL
                                              -> query/freeze -> hash-bound cohort receipt
```

No Plexer, Heimlern, Leitstand or long-running Chronik service is required. API and CLI use the same canonical envelope constructor. Imports are idempotent by `event_id` under the domain file lock.

## Work context

`subject` may carry `repo`, `component`, `operation`, `bureau_task_id` and `pr_number`. `data.outcome` may be `completed`, `blocked`, `failed`, `reverted` or `outcome_unknown`. Payloads remain allow-listed and contain no raw logs, prompts, commands or secrets.

## Frozen history brief

`freeze` writes an exact JSONL cohort and a sibling receipt containing query parameters, event IDs, SHA-256 digests, generation time and the mandatory boundary:

- historical only;
- does not establish current Git state;
- does not establish current CI state;
- does not establish current runtime state;
- does not establish a safe retry.

A Vibe-Lab experiment may cite the receipt as `chronik:<receipt_sha256>`. It must not copy mutable live-state claims from Chronik or auto-apply a policy.
