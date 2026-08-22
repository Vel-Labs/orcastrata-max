# Parent Child Closeout Contract

## Purpose

This contract makes Parent-owned Codex descendant cleanup a deterministic gate
inside terminal GoalBuddy `T999`. It complements the broader Terminal Lifecycle
Contract by compiling exact native child actions from complete Parent-history
pagination and the live collaboration inventory.

## Host boundary

Repository Python never invokes Codex Desktop tools. The Parent uses native host
functions to collect inputs and execute the returned exact actions:

1. Read the Parent task from the newest page through every older-turn cursor.
2. Extract every `subAgentActivity` child using its opaque `agentThreadId`,
   `agentPath`, and event kind.
3. List the current collaboration tree.
4. Run `plan` and perform every returned sequence-1 interrupt before sequence-2
   archive.
5. List the collaboration tree again and run `confirm` with action-index
   digests. This receipt reconciles enumeration only; it is not authoritative
   proof that native actions occurred.
6. Only a receipt with `closeout_complete: true` and
   `terminal_lifecycle_allowed: true` permits entry into the broader Terminal
   Lifecycle gate. This pre-gate always keeps `board_mutation_allowed: false`;
   only Terminal Lifecycle `ready` may permit the GoalBuddy mutation.

## Enumeration requirements

History pages form a closed cursor chain: the first request cursor is null,
each next request cursor equals the prior response cursor, and the final page
has `has_more: false` with no next cursor. Incomplete pagination fails closed.
Opaque thread IDs and agent paths are identities; titles and summaries are
untrusted presentation only.

Every live non-Parent collaboration path must be present in the recovered
history. A live child omitted by history fails with
`parent_child_closeout_inventory_incomplete`. The Parent ID or path appearing as
a child fails with `parent_child_closeout_parent_mutation_forbidden`.

Pages are normalized newest-first. Repeated older events may verify an existing
child identity but cannot replace its latest event kind.

## Action policy

- Active children compile `interrupt_agent`, then
  `archive_thread`.
- Terminal or unloaded children compile `archive_thread`.
- Nested child persistence is forbidden. Intentional persistent sessions are
  top-level Terminal Lifecycle resources and require externally anchored prior
  operator authority there; a caller-supplied child authority fails as
  `parent_child_closeout_child_persistence_forbidden`.
- Unknown status, ownership conflict, incomplete history, missing action
  receipt, failed action, or active post-inventory child blocks completion.
- Archive removes the terminal record from the active sidebar; it does not
  substitute for interrupting an executing child.

`ParentChildCloseoutPlan` and `ParentChildCloseoutReceipt` are mandatory inputs
to the Terminal Lifecycle compiler. The broader gate binds every descendant to
the authoritative pre/post inventories and every requested child action to the
anchored `ParentTerminalActionReceipt`. Only that combined proof may permit a
board transition.

## CLI

```sh
python3 plugins/codexmax-orchestrator/scripts/compile_parent_child_closeout.py \
  --input parent-child-closeout-request.json
```

Success is one canonical JSON artifact on stdout. Failure is one canonical
error on stderr with exit status 2.
