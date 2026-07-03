# Agent Run Manual Preview v0

Status: draft
Date: 2026-07-03
Scope: selected task-local Agent Ledger outbox roots

## Rule

Run preview before any manual transfer.

```bash
python tools/chronik_outbox.py --state-root <OUTBOX_ROOT> preview
```

The preview validates pending JSONL files and renders both views without remote mutation and without flush receipts.

## Gates

Proceed only if:

1. the outbox root was explicitly selected;
2. all pending events validate;
3. repo and run views render;
4. blocked and completed runs remain separate in the run view;
5. target configuration is explicit at invocation time;
6. no downstream consumer is triggered automatically.

## Non-goals

This is not a daemon, not a retry loop, not default-on collection, and not a Bureau or Leitstand integration.

## Decision

Manual transfer remains a deliberate operator action. The next operational step is previewing a selected pilot root, not enabling automation.
