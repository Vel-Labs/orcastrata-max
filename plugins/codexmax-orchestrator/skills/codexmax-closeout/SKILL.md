---
name: codexmax-closeout
description: "Advanced composable capability — Close out a candidate while preserving originals, reconciling evidence and costs, and exposing the Parent decision."
---

# Codexmax Closeout

Use `../../assets/templates/supervisor-closeout.md`.

For operator-facing progressive disclosure, also use
`../../assets/templates/compact-operator-closeout.md`. Keep the Supervisor
closeout as the authority-bearing durable detail. Finalize it first, compute
SHA-256 over its exact bytes, and place its repository-relative path plus digest
in the compact closeout. If a separate bounded expansion surface is needed,
use `../../assets/templates/durable-detail-index.md` and hash-link that file.

The compact closeout must remain usable without opening durable detail. State
what changed, validation passed/failed/not run, the exact boundary, remaining
risks, and the next owner/action. Missing, malformed, stale, or mismatched
detail paths or hashes fail closed and remain visible. Do not emit `complete`
without hash-bound Parent acceptance evidence.

These T005 progressive-disclosure surfaces are instructional contracts and
templates only. They do not provide an executable renderer or reusable product
validator, and static template checks do not establish runtime behavior.

The closeout includes:

- goal and tranche outcome;
- board and artifact inventory;
- files changed and exact commands;
- Worker self-test, Tester, and Auditor results;
- accepted facts, inferences, proposals, and unknowns;
- token, quota, marginal cost, fixed subscription, and measurement gaps;
- failed attempts and salvaged artifacts;
- a compact input-access ledger for every dispatched lane;
- rejected or unsupported claims and their revision or reassignment entries;
- receipt-repair transitions with independent technical-work and receipt status;
- unresolved risks and next queue;
- requested parent decision.

Provider-neutral normalization may change presentation only. Preserve original
artifacts and state `semantic_changes: none`. Any technical change is a revision
owned by the originating role or parent Codex.

Normalization also records `normalized_from`, `normalized_by`, the exact source
SHA-256, the separately recorded output SHA-256, and `semantic_changes: none`.
Changing evidence, commands, status, costs, uncertainty, failures, rejected
claims, repair state, boundary, or acceptance is a revision.

## Closeout Assembly

Build the closeout from durable artifacts in this order:

1. goal contract, board state, and acceptance oracle;
2. parallelism packet and route receipts;
3. Worker result artifacts and raw outputs;
4. integration diff and changed-file inventory;
5. validation command outputs and exit statuses;
6. Tester, Documenter, and Auditor artifacts;
7. failure ledger, revision packets, and parent repair notes;
8. cost, quota, token, runtime, and unknown measurement ledger.

Build the input-access ledger from each lane's dispatched `provider_input` and
canonical `Input Access Receipt` under the
[Provider Task Input Contract](../../assets/contracts/provider-task-input.md).
Record access, delivery, computed and declared gate, receipt status, unsupported
claims and claim IDs, and disposition. Missing or contradictory receipts remain
explicit closeout defects; provider-neutral normalization cannot remove or
repair them.

Build the receipt-repair ledger from validated transitions. Preserve the
original and repaired paths, accepted-command-result digest, source-change and
workload-rerun counts, and the `receipt_only`, `implementation_revision`,
`targeted_evidence_recovery`, or `no_repair` disposition. Do not merge receipt repair with
editorial normalization or implementation revision.

If an artifact is missing, write `not_run`, `not_produced`, or `unknown` with
the reason. Do not synthesize proof from memory.

Unknown token, quota, cost, runtime, or model telemetry remains `unknown`, never
zero. Compact output must not hide metered billing, fallback, a non-null token
cap, failed or `not_run` validation, rejected claims, or unresolved repairs;
retain their full rows in durable detail.

## Loop Closeout

For loop work, include the exact registry and definition identity, lifecycle
and prior state, triggering event, matched loop and fixed action-profile IDs,
admission/preflight/execution/validation states, budgets and observed evidence,
stable rejection codes, artifacts, notification intents, and every
`LoopRunReceipt v1` path/digest. Record `not_run`, `unknown`, failure, and stale
evidence without normalization to pass.

Report these boundaries separately: local source, installed projection, live
hook, active scheduler, external connector/delivery, publication, GoalBuddy or
WorkGraph application, and Parent/operator acceptance. A deferred activation
must name its later owner and gate; it is not a closeout defect to preserve it.
Registration, a valid dry-run, or a matched event cannot prove compilation,
execution, promotion, activation, or acceptance.

## Phase And Milestone Closeout

Roll an accepted child milestone into its Parent phase only after the milestone
receipt and required independent evidence pass the Parent gate. Preserve every
failed validation, rejected candidate, superseded attempt, and unresolved
blocker in compact attempt history. A later pass does not erase earlier
failures.

Report milestones complete, milestones total, current milestone, current gate,
exact blocker, and next milestone. Do not call the Parent phase complete while
any required child milestone, phase gate, or Parent acceptance remains open.
Only the Parent/PM owns terminal `T999`; a child closeout must not create,
accept, mutate, or complete it.

## Terminal Lifecycle Gate

After a hash-bound final audit says `complete` (and, when the goal contract
requires continuity until full outcome, `full_outcome_complete: true`), use
`../../scripts/compile_parent_child_closeout.py` under the
[Parent Child Closeout Contract](../../assets/contracts/parent-child-closeout.md)
before the broader terminal lifecycle compiler. This is mandatory for every
Codexmax-backed GoalBuddy terminal `T999`; it is not an optional cleanup note.

The Parent-mediated native sequence is:

1. Keep `T999` active and the goal open. Do not mutate board truth yet.
2. Read the Parent task from newest turns through every `nextCursor` until
   `hasMore: false`. Normalize every `subAgentActivity` row using only its
   opaque `agentThreadId`, `agentPath`, and event kind. Titles and summaries are
   never identity.
3. List the complete live collaboration tree. The Parent must be present. Any
   live non-Parent path absent from recovered history fails closed.
4. Compile `ParentChildCloseoutPlan`. For each active nested child,
   call the native interrupt operation using the exact agent path. Confirm the
   child is no longer active before continuing.
5. For every recovered nested child thread, call the native desktop
   archive operation using its exact thread and host IDs. Archive never
   substitutes for interrupting active execution.
6. Never retain a nested child through this pre-gate. Intentional persistent
   sessions are top-level Terminal Lifecycle resources and require exact prior
   operator authority there; they are not Parent-child persistence exceptions.
7. List the collaboration tree again and compile
   `ParentChildCloseoutReceipt`. Missing pages, unknown status, missing or
   failed actions, or a remaining active child keeps `T999`
   active and blocks completion.
8. Bind the child-closeout plan and confirmation receipt into the durable
   terminal inventory/action evidence, then continue with
`../../scripts/compile_terminal_lifecycle.py` and the
[terminal lifecycle contract](../../assets/contracts/terminal-lifecycle.md)
before asking GoalBuddy to mark the goal done.

The sequence is `plan -> Parent host actions -> ready -> Parent GoalBuddy
transition -> confirm`. The compiler is non-executing: it cannot archive,
unpin, interrupt, terminate a provider or board server, remove a worktree,
mutate GoalBuddy, or accept work. Preserve unknown, shared, unrelated, and
Parent resources with `action: none`. A terminal collaboration agent without a
host removal capability is a retained terminal host record, not an active-work
blocker. An active persistent session may remain only under exact prior
operator persistence authority.

Do not request the board transition until `ready` returns
`transition_allowed: true`. After the Parent transition, `confirm` must bind the
ready receipt, a done board with `active_task: null`, the official GoalBuddy
checker receipt, and the stop-checker receipt. Preserve all three lifecycle
artifacts in durable closeout evidence; none is Parent acceptance by itself.
The durable evidence must also preserve the Parent-child plan and confirmation
receipt. A terminal board without those receipts is incomplete; a Parent with
no nested children supplies the compiler-produced empty artifacts.

The Parent action receipt is a closed, hash-bound `ParentTerminalActionReceipt`
with `schema_version`, `artifact_type`, `plan_sha256`, closed
`parent_authority` (`authority_kind`, `authority_id`, and
`authority_sha256`), `actions`, `post_inventory_sha256`, `completed_at`, and
`receipt_sha256`. Every action binds its stable `action_id`, exact target
identity, status, evidence digest, and completion time. `ready` rejects a
receipt whose post-inventory digest differs from the supplied fresh inventory,
and a matched failed action is `terminal_lifecycle_action_failed`.

The provenance chain is external trust anchors -> recompiled plan -> external
ready-stage manifest -> Parent receipt -> fresh post inventory -> recomputed
ready -> external confirm-stage manifest -> confirm. Trust anchors are
supplied outside the lifecycle request and are passed with their expected
canonical digest. In addition to the exact Parent and inventory authorities,
they bind the goal-contract, pre-board projection and source bytes,
final-audit, initial-inventory, persistence-authorities, and Parent-child plan
digests. Ready and
confirm receive their stage-manifest bodies and expected digests separately;
the lifecycle request cannot override either manifest. Ready recompiles plan
from the original inputs, and confirm recompiles both plan and ready from the
full original chain. Inventories and resources must carry canonical goal-bound
scope and ownership evidence; a caller-supplied name or self-reclassification
is not evidence. Both stages require exact canonical equality and closed
checker bodies bound to post-board source bytes and projection. The ready
receipt records the stage-manifest digest; its `ready_sha256` excludes the
stage-manifest digest fields to avoid a circular hash and is bound by the
external manifest.

Use only the closed public rejection vocabulary from the terminal lifecycle
contract. It includes the `terminal_lifecycle_` prefix; in particular,
`terminal_lifecycle_board_snapshot_stale`,
`terminal_lifecycle_parent_task_action_forbidden`,
`terminal_lifecycle_unknown_resource_mutation_forbidden`,
`terminal_lifecycle_target_identity_changed`,
`terminal_lifecycle_process_identity_reused`,
`terminal_lifecycle_server_listener_remains`,
`terminal_lifecycle_provider_process_remains`,
`terminal_lifecycle_action_receipt_missing`,
`terminal_lifecycle_action_receipt_mismatch`,
`terminal_lifecycle_action_authority_invalid`,
`terminal_lifecycle_worktree_current_forbidden`,
`terminal_lifecycle_worktree_dirty`, and
`terminal_lifecycle_worktree_unintegrated`,
`terminal_lifecycle_board_mutation_premature`. A worktree is removable only when
`safe_to_remove` is true, `current` is false, `dirty` is false, and
`integrated` is true.

## Decision Surface

Return one requested parent decision:

- `accept`: oracle appears satisfied with independent evidence and no known
  parent-only repair.
- `repair_directly`: a small parent-owned integration or documentation repair
  can close the gap without another Supervisor cycle.
- `issue_revision_packet`: a bounded defect, missing proof, or failed worker
  should return to a new lane.
- `waiting_external`: progress requires human action, credentials, unavailable
  infrastructure, or an irreversible decision.

Only parent Codex may convert a candidate closeout into final acceptance.
