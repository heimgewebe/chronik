# Agent Run Pilot Evaluation v0

Status: draft
Date: 2026-07-03
Scope: Grabowski task-local Agent Ledger pilot evaluated with the Chronik run view

## Thesis / antithesis / synthesis

**Thesis:** The task-local Grabowski writer and Chronik run view now form a useful observation path for individual agent runs.

**Antithesis:** Automatic flushing or downstream orchestration would turn an observation seam into hidden control-plane coupling.

**Synthesis:** Keep the path opt-in and local. Use the run view for evaluation. Defer export and consumer integration until separate gates prove value and safety.

## Inputs

Pilot state root:

```text
/home/alex/.local/state/grabowski/agent-run-ledger-pilot-20260703T133632Z
```

Pilot tasks:

| task | command | final state |
| --- | --- | --- |
| `d912051c875c4ad8b90d531f` | `true` | `completed` |
| `1ede90d5bfdf4d72aef8bc7a` | `false` | `failed` |
| `942e1160183c4e3eae724cbd` | `sleep 0.1` | `completed` |

Observed files/events:

- JSONL files: 3
- events: 6
- event kinds: `agent.run.started`, `agent.run.completed`, `agent.run.blocked`

## Repo view finding

The repo-level view keeps one latest row per `subject.repo`.

For this pilot it returned:

```text
heimgewebe/grabowski -> completed
```

That is useful as a latest-state summary, but it hides the failed `false` task because a later run completed.

## Run view finding

The run-level view groups by `(subject.repo, source.run_id)`.

For this pilot it preserved three rows:

| result | blocker_code | evidence_ref |
| --- | --- | --- |
| `blocked` | `task-failed` | `grabowski-task:1ede90d5bfdf4d72aef8bc7a` |
| `completed` |  | `grabowski-task:942e1160183c4e3eae724cbd` |
| `completed` |  | `grabowski-task:d912051c875c4ad8b90d531f` |

This fixes the main pilot problem: failed runs remain visible even when later runs succeed.

## Organ boundaries

Chronik stores and renders agent-run events. It must not trigger tasks or make orchestration decisions.

Grabowski may emit task-local events only when explicitly opted in. It must remain operational if event writing fails. Global writer activation stays off by default.

Bureau, Leitstand, semantAH, heimlern, and hausKI are not activated by this pilot. They must not consume these events until a separate consumer gate exists.

## Decision

Do not enable automatic export.

Do not make Chronik a runtime dependency for Grabowski.

Do not add downstream consumers yet.

Proceed only to a controlled manual export slice if there is a concrete review target.

## Next admissible slice

A safe next slice is a manual export dry-run/runbook:

1. read a selected task-local outbox root;
2. validate every event against `agent-run-event.v0`;
3. render both repo and run views before sending;
4. require an explicit target endpoint and auth configuration at invocation time;
5. send only validated event payloads;
6. record receipts without copying raw operational transcripts;
7. leave global writer activation off.

This is a user-invoked export path, not a daemon and not a retry loop.

## Stop conditions

Stop and do not export if:

- any event fails schema validation;
- event payloads include sensitive or transcript-like material;
- target configuration is missing;
- Chronik is unavailable;
- the run view cannot show blocked and completed runs separately;
- any downstream consumer would be triggered automatically.

## Current conclusion

The pilot supports the run-view addition and a future manual export path. It does not support default-on collection, auto-export, or consumer automation.

## Second pilot: real Chronik maintenance tasks

Date: 2026-07-03
State root:

```text
/home/alex/.local/state/grabowski/agent-run-ledger-real-20260703T185817Z
```

This pilot used task-local Grabowski Agent Ledger opt-in for real Chronik maintenance work.

| task | command | final state |
| --- | --- | --- |
| `c233acc24cec49618f827320` | `py_compile tools/chronik_outbox.py tools/agent_ledger_view.py` | `completed` |
| `d3edc8ca61a84e25be5af6ba` | `pytest tests/test_chronik_outbox.py tests/test_agent_ledger_view.py -q` | `completed` |
| `425ab2c86ab4476ebe4cd7f0` | `make validate-local` | `completed` |

Preview result:

- JSONL files: 3
- events: 6
- repo view rows: 1
- run view rows: 3
- remote mutation: false
- receipt files: 0
- default production outbox files after the pilot: 0

### Updated decision

The second pilot supports local preview as the next normal operator habit. It still does not justify automatic transfer or downstream consumer activation.

Proceed only with explicit manual transfer when there is a concrete target and review reason. Until then, these outbox roots are local evidence, not Chronik production data.
