# WorkGraph Migration v1 Contract

## Purpose And Authority

`workgraph_migrate.py` is the standalone, standard-library migration boundary
for GoalBuddy board schema compatibility. GoalBuddy `state.yaml` remains
canonical. The migrator has no Parent, acceptance, provider, billing, network,
installation, or publication authority. Its receipts always declare
`authority_effect: none` and `acceptance_effect: none`.

The pinned current board schema is version 2. Version 3 is the recognized next
fixture. The only mutation is forward `2 -> 3` on an explicitly selected,
canonical local goal root. The live `codexmax-workgraph-v1` board remains v2
while GoalBuddy's official checker is v2-only.

## CLI And Receipts

```text
python3 workgraph_migrate.py inspect <absolute-goal-root>
python3 workgraph_migrate.py migrate <absolute-goal-root> --to-version 3
python3 workgraph_migrate.py recover <absolute-goal-root>
```

Success exits 0. Stable validation, version, path, backup, journal, divergence,
and storage errors exit 2. Stdout is one canonical, key-sorted JSON receipt
using protocol `workgraph_migration` and receipt schema version 1. Application
release names are never accepted as schema versions.

`inspect` reports current/next capabilities and hashes without writing.
`migrate` reports source and result versions/hashes, exact history inventory
and digest, backup path, journal phase, and outcome. `recover` returns the same
bindings and one explicit forward-recovery outcome. Errors never use an empty
success receipt.

## Version And Path Gate

The goal root must be an absolute canonical non-symlink directory. The board
must be the unique regular, non-symlink, single-link `<root>/state.yaml`. The
runtime accepts exactly one unambiguous top-level integer `version` scalar.
Missing, duplicate, boolean, quoted, malformed, unsupported, same-version,
downgrade, and target-other-than-3 requests fail before mutation.

Every history file beneath `.goalbuddy-board` must be a canonical regular
single-link file. Directory and file symlinks, hardlinks, aliases, special
files, traversal, and identity changes fail closed. Migrator-owned lock,
journal, temporary, and backup paths are excluded from the preserved-history
inventory; all other known and unknown sidecar files are included without
interpreting their contents.

## Byte Preservation

The board transformation replaces only the scalar bytes in the one top-level
`version: 2` line with `3`, preserving the line ending and every other byte.
The runtime does not parse and reserialize YAML.

Activity, updates, frontend receipts, recovery receipts, evidence and
attachment files, and unknown sidecar files are never rewritten. Their path,
size, and SHA-256 rows form a deterministic inventory digest before and after
replacement. Consequently role/model/route identity, unknown identity,
evidence references, correction links, rejected reviews, applied rows,
superseded rows, reconciliation history, and preserved failure bytes remain
unchanged.

## Backup And Atomic Migration

Before state replacement, the runtime acquires a stable sidecar lock and
creates a non-overwriting backup at:

```text
.goalbuddy-board/migration-backups/v2-to-v3-<source-board-sha256>/
```

The backup contains exact `state.yaml`, exact copies of every inventoried
history file under `.goalbuddy-board/`, and canonical `manifest.json`. Files
and directories are fsynced before the temporary backup directory is atomically
renamed. An existing final backup is never overwritten.

If interruption occurs after that rename but before the first journal write,
`migrate` and `recover` may adopt only the exact canonical hash-keyed backup
whose manifest, source board, history inventory, and every copied history byte
match the still-current v2 source. A missing, divergent, aliased, or tampered
backup is never adopted or overwritten.

After the backup is durable, a canonical migration journal binds source and
result board hashes, prepared result bytes, source/target versions, history
inventory, backup path, manifest hash, and phase. The phases are
`backup_ready`, `state_prepared`, `state_replaced`, and `complete`. The prepared
state is fsynced to a sibling temporary file, atomically replaces `state.yaml`,
and the goal-root directory is fsynced. History is reverified before terminal
success and immediately after any caller-controlled pre-replace hook, before
canonical state replacement. Processes that mutate history concurrently are
required to honor the same sidecar lock; non-cooperative races after the final
userspace comparison are outside the local locking guarantee.

## Forward Recovery And Refusal

Recovery never downgrades. For a valid nonterminal journal it may replace the
exact still-current v2 source with the journal-bound v3 result, or finalize an
already-replaced exact v3 result. A terminal exact operation is idempotently
reported as `already_complete`. Corrupt journals, stale or divergent boards,
changed history, changed identity, missing journals, conflicting backups, and
unsupported versions fail without rewriting canonical or historical data.
Before replacement, recovery verifies the canonical hash-keyed backup path,
manifest, exact backed-up v2 state, and every backed-up history file. It derives
the only permitted v3 bytes by applying the byte-only version transform to that
verified v2 backup and requires the journal bytes and hash to match exactly.
Malformed, aliased, traversing, or NUL-containing backup paths fail through the
canonical JSON error envelope before filesystem use.

## Compatibility Matrix

| Consumer | v2 | v3 |
| --- | --- | --- |
| GoalBuddy official checker | canonical and required | unsupported today |
| Existing adapter snapshot | read/write capability | readable, migration required |
| Existing adapter apply/recover | accepted behavior | explicit refusal |
| Existing WorkGraph tool facade | accepted operations; migration false | snapshot exposes adapter boundary |
| Standalone migrator inspect | forward capability | already-next capability |
| Standalone migrator migrate | durable forward `2 -> 3` | repeat/downgrade refusal |
| Standalone migrator recover | finish exact planned migration | finalize exact result only |

No GoalBuddy frontend or tool-facade source change is part of this contract.
T009 proof uses isolated temporary copies. T010 owns fresh-repository dogfood;
T999 owns final functional-oracle reproduction and Parent acceptance.

## Proof Boundary

T009 can prove local forward migration, backup, atomic replacement, recovery,
refusal, and byte preservation. It does not prove installation, remote or
distributed locking, future GoalBuddy checker adoption, live-board migration,
provider behavior, dogfood, publication, or final goal acceptance.
