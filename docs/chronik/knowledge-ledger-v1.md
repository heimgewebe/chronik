# Chronik: semantic knowledge ledger v1

Chronik is an **append-only history**, never a task scheduler, operator
authority, or source of current Git/CI/runtime truth.

This contract is intentionally separate from `agent.ledger`: a completed task
is not necessarily a validated root cause, a successful fix or a user decision.
The new domain is `knowledge.ledger`, the event kind is
`knowledge.insight.published.v1` (unlimited retention under the existing
published-event retention rule). No new server or database is required.

## Knowledge boundaries

Capture only durable discoveries that influence future work:

- `decision`, `requirement`: explicit authoritative choices and stable rules
- `root_cause`: evidence-confirmed cause, distinct from an assistant hypothesis
- `repair`: concrete fix with `implemented` versus `production_verified`
- `refutation`: a disproved hypothesis or failed countertest
- `open_problem`: a meaningful unresolved limitation
- `operation`: impactful merge, deployment, rollback or migration
- `observation`: bounded evidence without an unwarranted stronger conclusion

Statuses: `observed`, `hypothesis`, `confirmed`, `refuted`,
`decided`, `implemented`, `production_verified`, `superseded`.
They are assertions by the event producer and **not** independent proof of
truth. Each event carries 1–8 direct evidence references, a producer identity,
target scope, original timestamp, and a stable record key. A source
`heimgewebe/grabowski` is the producer, not necessarily the subject repository.

Supersession, contradiction, confirmation and amendment are new events with
`supersedes`, `refutes`, `confirms`, or `amends` references, never
mutations of older records. The ledger query reports successors without
discarding historical counterevidence. Repeated use of a record key by the
same source with different content fails rather than inventing a new record.

A successful CI check must **not** be labelled `production_verified`. A
user-declared decision can be `decided` before implementation.

## Local write and read protocol

The canonical operator starts `tools/knowledge_ledger.py` through the
authorized Grabowski execution path. Example (paths relative to checkout):

```sh
python tools/knowledge_ledger.py --outbox-root ~/.local/state/grabowski/chronik-outbox capture --record /path/to/minimized-record.json
python tools/knowledge_ledger.py --data-dir ~/.local/state/chronik/data --outbox-root ~/.local/state/grabowski/chronik-outbox import-pending
python tools/knowledge_ledger.py --data-dir ~/.local/state/chronik/data get --event-id 'sha256:...'
python tools/knowledge_ledger.py --data-dir ~/.local/state/chronik/data search --repo heimgewebe/chronik
python tools/knowledge_ledger.py --data-dir ~/.local/state/chronik/data search --repo heimgewebe/chronik --since 2026-11-01T00:00:00Z --current-only
python tools/knowledge_ledger.py --data-dir ~/.local/state/chronik/data --outbox-root ~/.local/state/grabowski/chronik-outbox coverage
```

Record file fields (no `event_id` required when capturing; it is derived
deterministically from `source` and `record_key`):

```json
{
  "record_key": "analysis:failure:001",
  "ts": "2026-11-07T20:00:00Z",
  "source": {"system": "heimgewebe/grabowski", "component": "analysis"},
  "subject": {"repo": "heimgewebe/chronik", "component": "outbox"},
  "knowledge_type": "root_cause",
  "epistemic_status": "confirmed",
  "statement": "Import receipt was absent after a verified write failure.",
  "evidence_refs": ["grabowski-task:actual-task-id"],
  "relations": []
}
```

Search selectors are AND-combined: `--repo`, `--host`, `--component`
(exact `subject.component`), `--knowledge-type`, `--epistemic-status`,
`--keyword`, and the inclusive, timezone-aware `--since`/`--until` window.
`--current-only` hides events superseded by a newer event and reports their
number as `hidden_superseded`; the history itself is unchanged.

`get` exits with status 3 when the event is not in the committed ledger
(`"found": false`), so callers cannot mistake absence for a verified import.

Minimize and verify content *before* capture. Capture validates identity,
bounds, refs and common credential-like patterns; it does not provide magical
detection of every private datum. No raw chats, prompts, task logs or secrets.

## Persistence and error states

1. `capture` creates one source-key-bound, fsynced outbox JSON file with
   create-exclusive semantics. Its response explicitly sets
   `ledger_verified=false`. Failed/uncertain writes are never success.
2. `import-pending` uses Chronik's existing
   `storage.write_payload_unique` and its durable identity index.
3. Each imported identity is compared with an independent read of the
   canonical committed JSONL ledger. The receipt includes event ID (through
   the capture/get contract), `verified`, error count, and SHA-256 ledger
   snapshot. The full outbox is retained for idempotent recovery.
4. `coverage` compares valid outbox entries to the canonical ledger and
   reports `pending`, `invalid` and `verified` identities separately.

A missing or broken Chronik datastore does not erase a successfully captured
outbox record. Retry an explicitly pending record after restoration; never
infer success from a write response alone.

## Important implementation and observation boundaries

**Integrated in this source branch:** the existing `tools/coding_memory.py`
`import-outbox` command now imports both the technical `agent.ledger`
and semantic `knowledge.ledger` during the same timer cycle.
Counters and errors appear in the existing bounded journal summary; no new
worker or timer is needed. This remains **unavailable in production until
the Chronik revision is deployed**. Grabowski terminalization still needs a
semantically justified capture signal; ChatGPT cannot capture new threads
automatically through the mere existence of a plugin instruction.

`coverage` audits only entries already visible in its outbox. It does not
prove that every user statement or task produced a record; sources outside
the tracked workflow remain `not_audited`.

Until an authorized merged revision and a real post-deployment
capture/import/get cycle are verified, local tests and PR CI are development
evidence only, **not production acceptance**.