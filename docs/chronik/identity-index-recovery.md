# Chronik: explicit device-only identity-index recovery

Target: [issue #307](https://github.com/heimgewebe/chronik/issues/307).

Chronik keeps the JSONL ledger authoritative. Its SQLite identity index is an
acceleration structure. Import and compaction must still **fail closed** when
the recorded ledger device or inode differs from the currently opened file.

The new \`tools/identity_index_recovery.py\` is an **operator-invoked recovery
command**, never an automatic fallback, and it never writes JSONL.

## When it is permitted

Only when the **sole** drift is the ledger's \`st_dev\` (e.g. after a verified
mount-device renumbering), while the previous inode, size, nanosecond mtime and
ctime all match. Any unindexed append, truncation, modified bytes, changed
inode, incomplete last line, or broken index rejects recovery.

First check the independent backup/restore condition. An isolated copy on the
same host is *not* equivalent to an off-host Restic backup.

## How to run it

Stop or coordinate normal writers if necessary. The command itself acquires
the canonical sidecar FileLock and **exclusive ledger-fd flock**. Other
lock-compliant writers will wait or fail. Use the old device ID from the
indexed state, not the new \`stat\` output.

Before preparing a recovery, inspect the candidate device IDs without
opening the index for writing or creating a backup:

    python tools/identity_index_recovery.py --data-dir ~/.local/state/chronik/data --domain agent.ledger --inspect

The status device_drift_candidate means only the state digest and comparable
stat fields were checked; it is NOT a verified recovery or permission to retry
an import. Use old_ledger_device as the explicit CAS preimage below only after
checking independent backup/restore readiness. Other drift and malformed
index metadata fail closed. The inspect mode rejects mutation arguments and
does not change ledger or SQLite source bytes.

Create a separate, private and owned \`0700\` directory for backups.
Then, through an authorized Grabowski operator path:

\`\`\`sh
python tools/identity_index_recovery.py \
  --data-dir ~/.local/state/chronik/data \
  --domain agent.ledger \
  --backup-root ~/.local/state/chronik/manual-recovery-copies \
  --expected-old-device OLD_DEV_NUMBER \
  --apply
\`\`\`

\`--apply\` is required for any recovery mutation. Only exact device-only drift is admitted.
Use the same command for other affected ledgers with their actual domain
and old device. Do not edit SQLite manually or bypass integrity checks.

## Verified preconditions and effects

Under the two writer locks the command:

1. Requires private, regular, single-linked ledger and index files; validates
   the existing SQLite application ID, schema version, journal mode and
   integrity using a **read-only** connection before any writable index open.
   A zero-byte or uninitialized index is rejected without creating a schema.
   The normal index reader then checks full schema, state digest and count binding.
2. Checks \`PRAGMA integrity_check\`, the complete indexed JSONL chain,
   every record's final boundary, and *all* identity/fingerprint/range/row
   digests against actual ledger payloads. Duplicate identities must have
   identical fingerprints.
3. Revalidates file identity and content and creates fsync-complete private
   copies of both source files; reads the copies back and writes a durable
   preimage manifest.
4. Runs one \`BEGIN IMMEDIATE\` SQLite compare-and-swap bound to the complete
   old state and updates **only** \`ledger_dev\` and the binding \`state_digest\`.
5. Reads back the new state, ledger identity, chain, identities and unchanged
   ledger hash, then writes \`verified-recovery.json\` beside the preimages.

Failed or uncertain operations are not success. An interrupted transaction
remains subject to SQLite rollback and authoritative readback. Recovery
copies are deliberately retained; the tool does not delete or restore
production data.

## Test contract and limits

The isolated test matrix includes the positive simulated device mismatch
with normal import failing before and succeeding after recovery, successful
backup and index readback, wrong CAS, changed inode, modified bytes, truncated
ledger, incomplete last line, corrupted state, row digest and database,
missing backup root, failed backup write, failed SQLite commit, and denied
writer lock, and checks that empty or truncated SQLite source remains byte-identical
on rejection. It does **not** claim a physical mount renumbering or off-host
restore on production.

On a target system, use a freshly verified Restic snapshot and retain
the previous files until a separate restore has succeeded. A successful
CLI exit does not prove unrelated Chronik consumers or their access paths.