# CHRONIK-ECOSYSTEM-CLOSEOUT-V1-T010 proof

## Scope and identities

- Bureau task: `CHRONIK-ECOSYSTEM-CLOSEOUT-V1-T010`
- Bureau task merge: `bebabf6480504c4ffc8872c2ca69022286b72a49`
- Chronik implementation base: `362dc58521d11951242d115f0213e8db8140a057`
- Source optimization diff: `c909225be10731e4bb2f74f06ceaa8d05a60d086409f53858e8d5db24f683780`
- Runtime deployment: not part of this proof and not authorized by this task phase.

## Truth boundary

The append-only JSONL ledger remains the only event authority. The SQLite file
under `.chronik-identity-index-v1/` is a derived acceleration structure. It can
be deleted and rebuilt without changing ledger bytes. The index cannot authorize
an event that is absent from the ledger.

A stored identity consists of:

- the identity key and identity value;
- the full 40-byte payload fingerprint (8-byte canonical payload length plus the
  full 32-byte SHA-256 digest);
- the exact first ledger record byte range that established the identity;
- a SHA-256 digest over the complete index-row binding.

The index state binds:

- ledger device and inode;
- ledger `mtime_ns` and `ctime_ns`;
- processed byte offset;
- a SHA-256 record chain over the processed prefix;
- total ledger record count;
- exact indexed-identity count;
- last record byte start and SHA-256 digest;
- a SHA-256 digest over all state fields.

Trigger-maintained identity counts are compared with the state-bound count in
O(1). Every candidate hit is re-read from its exact ledger byte range and its
identity and full payload fingerprint are recomputed before it is trusted.

## Operating modes

- `rebuild`: no state exists; scan the complete ledger and derive the index.
- `steady`: verify file identity, metadata, boundary, state digest, identity
  count and candidate rows without scanning ledger history.
- `verify`: metadata changed without growth; verify the complete stored prefix
  before rebinding metadata.
- `verify-catchup`: the ledger is ahead of the index; verify the complete old
  prefix, then index the tail. This is an exceptional recovery or legacy-append
  path, not the ordinary write path.
- `unused`: no candidate records were supplied.

The returned storage and outbox-import results expose the mode, rebuild flag,
records scanned and entry count. A steady-state grouped write reports zero full
ledger scans and zero historical records scanned.

## Crash and rollback ordering

The writer holds the existing ledger file lock for ledger and index operations.
The effect order is:

1. synchronize and verify the derived index against the durable ledger;
2. check candidates with full fingerprints and ledger-backed index hits;
3. begin an immediate SQLite transaction;
4. append and fsync the JSONL ledger through the existing rollback-capable
   append transaction;
5. stage index rows and the new ledger-bound state;
6. commit SQLite with `synchronous=FULL` and fsync the private index directory.

Consequences:

- failure before the ledger append leaves both stores unchanged;
- append failure uses the existing ledger rollback and rolls back SQLite;
- index staging failure rolls back SQLite and truncates/fsyncs the ledger to its
  exact pre-append size;
- a hard crash after durable ledger append but before SQLite commit leaves only
  a lagging index; the next run uses `verify-catchup`;
- an uncertain SQLite commit never triggers ledger rollback, because that could
  let an actually committed index lead the ledger. The call fails and the next
  run establishes either `steady` or `verify-catchup` from the ledger.

## Corruption and drift checks

Focused tests cover:

- malformed or schema-foreign SQLite files;
- symlinked or non-private index paths;
- ledger truncation and inode replacement;
- same-size in-place ledger changes;
- prefix mutation combined with a later append;
- incomplete final JSONL records;
- state-hash manipulation;
- identity-row fingerprint and offset manipulation;
- identity-row deletion through the trigger-bound count mismatch;
- historical conflicts unrelated to the current candidates;
- invalid JSON and records without the configured identity;
- failed index staging, uncertain index commit and ledger rollback;
- a real child-process hard crash after durable ledger append and before the
  SQLite commit, followed by automatic lagging-index recovery;
- more than the SQLite parameter limit of candidate identities;
- a canonical payload of roughly 700 kB with a fixed-width index fingerprint.

A corrupted existing index is not silently replaced. A missing index is rebuilt.
A missing ledger remains fail-closed for general storage callers.

The Grabowski outbox batch importer has one narrower recovery permission: after
it has validated a complete, error-free source inventory, it may reset only the
derived index while reconstructing a missing or empty ledger. Direct single-file
imports and ordinary storage callers cannot request this recovery path.

## Deterministic scale measurement

Local synthetic measurement on the implementation worktree:

- 100,000 unique historical events;
- each historical `value` contains 128 ASCII bytes;
- one duplicate and one new candidate during rebuild;
- one duplicate and one new candidate during steady state;
- Python allocation peak measured with `tracemalloc` around each grouped write;
- elapsed time measured with `time.perf_counter`;
- temporary ledger and index removed after measurement.

Observed raw values:

| phase | elapsed seconds | Python peak bytes | ledger records scanned | written | skipped |
|---|---:|---:|---:|---:|---:|
| rebuild | 3.6420401600189507 | 62,691 | 100,000 | 1 | 1 |
| steady | 0.0028964472003281116 | 29,065 | 0 | 1 | 1 |

Artifact sizes after the steady write:

- ledger: 18,188,996 bytes;
- SQLite index: 11,890,688 bytes;
- indexed identities after the steady write: 100,002.

This measurement proves the local algorithmic path and bounded Python
allocation for this fixture. It does not establish production latency, RSS,
filesystem durability beyond the tested platform, or live importer throughput.

## Verification

The uncommitted implementation snapshot passed:

- 61 focused persistent-index and storage tests, including the hard-crash
  subprocess case;
- 52 focused outbox-import, compaction and benchmark-contract tests;
- the complete Chronik suite: 408 passed, one existing Starlette/httpx2
  deprecation warning;
- `compileall` for `identity_index.py`, `storage.py` and `coding_memory.py`;
- the Chronik role contract;
- `git diff --check`.

These results bind the implementation snapshot at the time this proof was
written. They must be repeated against the final commit after any rebase or
content change and do not establish GitHub CI, merge or deployment on their own.

## Compatibility and rollback

Existing ledgers need no migration. The first indexed write derives the database
from the ledger. Older Chronik versions ignore the private index directory and
continue using the JSONL ledger. Rollback therefore consists of reverting the
code and, if desired, securely removing the derived index files; no ledger record
is rewritten or deleted.

## Residual boundaries

- `verify-catchup` intentionally performs an O(history) prefix verification. It
  is exceptional; the ordinary `steady` path remains independent of total
  history except for candidate-record reads.
- The index protects against accidental corruption and unauthorized index-only
  mutation within the process trust boundary. A same-user adversary able to
  rewrite both ledger and index and recompute every digest is outside this local
  integrity model.
- SQLite schema shape, state digests, trigger-bound counts and accessed rows are
  checked. The steady path does not perform an O(index) database-wide integrity
  scan on every call; unread-page corruption is detected when accessed or during
  explicit database diagnostics.
- The index adds disk usage in exchange for exact candidate lookups and
  ledger-backed corruption checks.
- No production deployment or activation evidence is claimed here.
