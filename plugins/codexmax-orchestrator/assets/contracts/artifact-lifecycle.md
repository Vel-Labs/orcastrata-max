# Artifact Lifecycle Contract

## Purpose

Codexmax stores each worker attempt in one provider-neutral runtime tree:

```text
.codexmax/runs/<goal>/<task>/<attempt>/
```

Provider, model, route, role, runtime, and usage are manifest metadata. They
must not create provider-owned top-level folders. GoalBuddy state and repository
source remain outside this lifecycle.

## Lifecycle

The only forward lifecycle is:

```text
staged -> provider_complete -> quality_checked -> integrated
       -> parent_accepted -> cleanup_planned -> reaped
```

The CLI binds a regular single-link provider result, quality receipt,
integration receipt, compact handoff, Parent acceptance, and cleanup plan in
that order. A transition from any other state fails closed.

`record-result` binds the complete `raw/` tree, not only the named result. The
manifest snapshot records every regular file descriptor, every descendant
directory (including empty directories), entry and byte counts, and a canonical
tree digest. The named provider-result descriptor must be a member of that
snapshot.

Before `quality-check`, `integrate`, `handoff`, Parent `accept`, and
`plan-cleanup`, one reusable validation gate rebuilds the raw snapshot and
rechecks every previously bound descriptor. The same gate validates the bound
cleanup plan before execute mode. File mutation, deletion, same-byte inode
replacement, directory drift, or an unplanned raw peer aborts before a new
manifest state is persisted. The gate also runs immediately before each
post-result manifest write, so newly bound receipts are validated before their
state transition is published.

The invoking Parent is the only acceptance authority. The compact handoff is the normal
Parent read surface and is capped at 16 KiB. It contains hashes and concise
claims, never raw transcript content. Raw evidence is retrieved only for a
named disputed claim.

## Usage truth

Every usage field has `status`, `value`, and `unknown_reason`. Missing input,
output, total-token, or cost telemetry is `unknown` with a null value. The CLI
does not infer a total, coerce unknown to zero, or estimate cost.

Reported `cost_usd` is a JSON number. Its CLI input uses one canonical fixed
decimal form: `0`, a non-zero integer without leading zeros, or that integer
form followed by one to six decimal places whose final digit is non-zero.
Signs, exponent notation, leading zeros, trailing fractional zeros, more than
nine integer digits, and more than six fractional digits are rejected. This
keeps one deterministic input spelling while preserving a numeric schema type.

## Safety boundary

- Goal, task, and attempt are single canonical identifiers. Absolute paths,
  separators, traversal, empty segments, and aliases are rejected.
- Attempt files must be regular and single-link. Symlinks, hardlinks, FIFOs,
  sockets, devices, and unsafe directory components are rejected.
- Configured file, directory, total-entry, and byte caps are checked as the
  attempt advances and immediately before cleanup planning. Traversal streams
  directory entries and rejects overflow before appending to any collection;
  empty directories therefore cannot bypass the sprawl boundary.
- Cleanup candidates are only regular single-link files beneath the attempt's
  `raw/` directory. The lifecycle manifest, compact handoff, Parent acceptance,
  cleanup plan, and `accepted/` receipts are never candidates.
- A cleanup plan is non-destructive and requires a hash-bound Parent acceptance.
  It records path, digest, size, device, inode, modification time, and link
  count for each candidate.
- Cleanup execution is a separate command. It requires the exact gate printed
  by `plan-cleanup` and revalidates the plan plus every candidate before the
  first unlink. Any identity or descriptor drift aborts the operation.

## Destructive-action boundary

This product surface can execute a previously planned cleanup only after its
explicit gate. The artifact-lifecycle implementation tranche does not
authorize executing cleanup against existing repository evidence. Destructive
tests must use disposable temporary fixtures.
