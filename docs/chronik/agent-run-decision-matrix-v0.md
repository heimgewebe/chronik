# Agent Run Decision Matrix v0

Status: accepted
Date: 2026-07-03
Scope: decision after two Grabowski task-local Agent Ledger pilots

## Facts

- Grabowski runtime is healthy on `775f8603b79936e079e1e6e81bde97f5d3818b5a`.
- Two local pilot roots exist.
- Global Grabowski-Chronik activation is unset.
- Default production outbox file count is 0.
- Chronik target configuration is absent.
- Chronik auth configuration is absent.

## Matrix

Scores: 1 poor, 3 acceptable, 5 strong.

| Option | Evidence value | Safety | Reversibility | Coupling risk | Readiness | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A. Keep local evidence only | 4 | 5 | 5 | 5 | 5 | 24 |
| B. Make preview the normal gate | 5 | 5 | 5 | 5 | 5 | 25 |
| C. Move one selected root now | 4 | 3 | 3 | 3 | 2 | 15 |
| D. Automate movement | 3 | 1 | 2 | 1 | 1 | 8 |
| E. Add consumers now | 2 | 1 | 2 | 1 | 1 | 7 |

## Decision

Choose **B. Make preview the normal gate**.

Do not move the pilot roots now.

Do not automate movement.

Do not add consumers now.

## Future gate

A future manual move requires:

1. selected outbox root;
2. successful preview;
3. reviewed repo and run views;
4. explicit target configuration;
5. explicit auth configuration;
6. concrete review reason;
7. no automatic downstream action.

## Next state

Local evidence remains the source of truth. Preview is the normal review step. Movement remains a separate operator decision.
