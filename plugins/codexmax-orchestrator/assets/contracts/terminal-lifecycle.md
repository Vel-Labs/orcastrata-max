# Terminal Lifecycle Gate Contract

## Mandatory Parent-child pre-gate

For a Codexmax-backed GoalBuddy terminal `T999`, run the
[Parent Child Closeout Contract](parent-child-closeout.md) before this broader
resource gate. The resulting `ParentChildCloseoutPlan` and
`ParentChildCloseoutReceipt` are mandatory durable inputs. A Parent with no
children supplies the compiler-produced empty artifacts rather than omitting
the gate.

The Parent-child plan digest is part of the external
`TerminalLifecycleTrustAnchors` body, so the lifecycle request cannot replace
complete Parent-history enumeration with a caller-forged empty plan. Plan
validates every listed child against matching goal-owned visible-thread and
collaboration-agent records in the authoritative initial inventory. Nested
child persistence is forbidden; intentional persistent sessions remain
top-level Terminal Lifecycle resources.

The child plan's Parent thread ID must equal the anchored Parent authority ID
and exactly match one active shared `parent_thread` target. Its Parent path and
host must exactly match one active shared collaboration identity on that host.
Those protected Parent identities may never appear as a descendant or child
action target. Coverage is reverse as well as forward: every goal-owned visible
thread on the Parent host and every goal-owned collaboration path nested below
the Parent path must appear exactly once as one descendant pair. An empty plan
cannot omit an authoritative child. Unrelated top-level persistent sessions
are outside this pairing rule and remain governed by their own prior operator
authority.

The Parent-child gate recovers historical descendants from complete Parent
history pagination, reconciles them with the live collaboration tree,
interrupts every active nested child, archives every recovered nested child
thread, and confirms a fresh post-action inventory.
Repository code compiles and verifies; Parent Codex performs native host calls.

Do not mark the board done before both gates permit transition. A child archive
receipt cannot prove process termination, and an interrupt receipt cannot prove
the sidebar record was archived. Incomplete history, an unknown live child, a
failed native action, or a remaining active child keeps `T999` active.

`compile_terminal_lifecycle.py` is a deterministic, non-executing gate between
a complete final audit and a GoalBuddy transition to `done`. It compiles exact
Parent host actions, validates their receipts against a fresh inventory, and
confirms the post-transition board. It never performs a host action, mutates a
board, accepts work, calls a provider, or accesses credentials.

## Three immutable stages

1. `plan` first consumes an external, canonical TerminalLifecycleTrustAnchors
   v1 body. The body is closed to schema_version, artifact_type, goal_id,
   exact parent_authority, exact inventory_authority, sorted allowed
   persistence-authority artifact digests, the externally compiled
   `parent_child_closeout_plan_sha256`, and the six exact plan-input
   identities: `goal_contract_sha256`,
   `pre_transition_board_projection_sha256`,
   `pre_transition_board_source_sha256`, `final_audit_sha256`,
   `initial_inventory_sha256`, and `persistence_authorities_sha256`. Its
   expected sha256 is supplied separately and exact canonical bytes are
   verified. The lifecycle request cannot define or override those
   authorities or identities. Plan then binds canonical goal, board, and
   final-audit snapshots by canonical SHA-256 and preserves safe relative
   `board_path` and `accepted_final_audit_path` in the emitted plan. The final audit must say
   `decision: complete`; `full_outcome_complete: true` is additionally required
   when `continuous_until_full_outcome` is true. Every task except the named
   terminal task must already be terminal: `done`, or `blocked` with its
   GoalBuddy-required receipt preserved. `queued` and `active` tasks remain
   nonterminal and fail closed. Confirm requires every historical `done` or
   `blocked` status to remain unchanged while only the named terminal task
   moves from `active` to `done`. A complete resource inventory is classified
   and converted into exact Parent-only actions.
2. `ready` receives all original plan inputs and recompiles `plan` from them;
   a self-hashed but different supplied plan is rejected. It also requires an
   externally supplied, canonical `TerminalLifecycleReadyStageManifest` and
   separately supplied expected manifest sha256. The manifest binds the trust
   anchor, plan, Parent receipt, post-inventory, pre-board source, and the
   expected ready receipt digest. Ready verifies one exact anchored Parent
   action receipt, an unchanged pre-transition board, and a fresh complete
   post-action inventory. Inventories carry the anchored inventory authority
   and goal-bound scope evidence. Every resource carries canonical goal-bound
   ownership evidence; non-goal-owned resource records cannot drift.
   The Parent-child receipt is an enumeration reconciliation artifact, not
   host proof. Ready independently maps every child interrupt/archive to the
   anchored `ParentTerminalActionReceipt`, requires interrupt completion no
   later than archive completion after complete bijective reconciliation, and
   verifies each child is terminal or
   absent in the authoritative post inventory.
   `transition_allowed` is true only when every exclusively goal-owned resource
   is terminal or absent, except a persistent session retained under explicit
   prior operator authority.
3. `confirm` receives the trust context, original plan inputs, plan, Parent
   receipt, pre/post inventories, pre-transition board, ready-stage manifest,
   ready receipt, post-transition board, and closed checker receipts. It also
   requires an externally supplied, canonical
   `TerminalLifecycleConfirmStageManifest` and separately supplied expected
   manifest sha256. That manifest binds the trust anchor, ready-stage manifest
   and ready receipt, pre/post board source identities, post-board projection,
   and both checker receipt digests. Confirm recomputes plan and ready from
   those exact inputs and requires canonical equality with the supplied
   artifacts. It binds the ready receipt to a legal done transition with
   unchanged task IDs/types, `active_task: null`, and passing official and
   stop checkers before emitting `terminal_confirmed: true`.

Every artifact uses exact closed fields and a canonical `sha256:` digest. JSON
with duplicate keys or non-finite values is rejected.

The external trust body is closed to
`{schema_version, artifact_type, goal_id, parent_authority,
inventory_authority, allowed_persistence_authority_sha256s,
goal_contract_sha256, pre_transition_board_projection_sha256,
pre_transition_board_source_sha256, final_audit_sha256,
initial_inventory_sha256, persistence_authorities_sha256,
parent_child_closeout_plan_sha256}`. Its supplied
expected digest is not request-controlled. Inventory bodies are closed and
include exact inventory authority and goal-bound scope_evidence. Resource
bodies include exact ownership_evidence with goal_id, source_id, source_kind,
and a digest of its canonical body; caller, self-attested, and name-only
ownership evidence is rejected. The emitted plan binds
trust_anchors_sha256 and all six input identities, and preserves each complete
resource record. Both board snapshots include `source_sha256`, the digest of
the exact GoalBuddy `state.yaml` bytes, separately from the canonical board
projection digest.

## External stage manifests

`TerminalLifecycleReadyStageManifest` is closed to
`{schema_version, artifact_type, trust_anchors_sha256, plan_sha256,
parent_action_receipt_sha256, post_inventory_sha256,
pre_transition_board_source_sha256, ready_receipt_sha256}`. Its canonical
body digest is supplied independently as `--expected-stage-manifest-sha256`;
the ready request cannot replace or override it. Ready recomputes the receipt
and requires its `ready_sha256` to equal the externally bound
`ready_receipt_sha256`. To avoid a digest cycle, `ready_sha256` is the digest
of the ready receipt with both `ready_sha256` and
`ready_stage_manifest_sha256` omitted; the receipt still records the verified
stage-manifest digest.

`TerminalLifecycleConfirmStageManifest` is closed to
`{schema_version, artifact_type, trust_anchors_sha256,
ready_stage_manifest_sha256, ready_receipt_sha256,
pre_transition_board_source_sha256, post_transition_board_source_sha256,
post_transition_board_projection_sha256, official_checker_receipt_sha256,
stop_checker_receipt_sha256}`. Confirm verifies its separately supplied
canonical digest, validates the supplied ready-stage manifest against that
digest, recomputes ready from the complete original inputs, and requires
canonical equality before checking the terminal transition.

Both stage manifests are library arguments and CLI inputs, never lifecycle
request fields. A missing, malformed, stale, or mismatched external manifest
fails closed as `terminal_lifecycle_schema_invalid` or the applicable closed
binding code. The official checker must have ID
`goalbuddy_official_checker`; the stop checker must have ID
`goalbuddy_stop_checker`. Each closed checker receipt binds both the exact
post-transition board source sha256 and canonical projection sha256, and the
two checker evidence and receipt digests must be distinct.

## Resource and ownership policy

Resource classes are `native_visible_thread`, `collaboration_agent`,
`provider_process`, `board_server`, `worktree`, `persistent_session`, and
`parent_thread`. Ownership is `goal_owned`, `shared`, `unrelated`, or
`unknown`; lifecycle is `active`, `terminal`, `absent`, or `unknown`.

- `shared`, `unrelated`, and `unknown` ownership always compile to `none` and
  may not appear as mutated in the Parent receipt.
- Parent threads always compile to `none`; Parent thread mutation is forbidden.
- Active goal-owned provider processes, board servers, collaboration agents,
  visible disposable tasks, and removable worktrees compile only to supported
  exact Parent actions. Unsupported active cleanup fails closed.
- A terminal collaboration agent with no archive/remove capability becomes
  `retained_terminal_host_record` and does not block completion.
- Visible disposable tasks compile archive and/or unpin only when the inventory
  explicitly reports those capabilities.
- Active persistent sessions compile `retain_persistent` only when a matching,
  prior, explicit operator persistence authority is present and still valid.
- Worktree removal requires an exact path/digest target, explicit remove
  capability, `safe_to_remove: true`, `current: false`, `dirty: false`, and
  `integrated: true`. Current, dirty, and unintegrated worktrees fail with
  distinct public codes.

Provider/server PIDs bind their process start identity; PID reuse fails closed.
Targets cannot change between plan, action receipt, and post-action inventory.
Provider processes or listeners that remain active block transition.
Persistence authority artifacts are closed canonical bodies with a
self-recomputed artifact_sha256; their artifact digest must be listed in the
external trust anchors before use.

## Authority boundary

The compiler emits instructions only. Archive, unpin, interrupt, provider or
server termination, worktree removal, and GoalBuddy mutation remain Parent host
actions. The gate cannot authorize persistence, installation, publication,
provider use, acceptance, or mutation of unknown resources.

Stable public rejection codes are explicitly closed and prefixed:
`terminal_lifecycle_schema_invalid`,
`terminal_lifecycle_board_snapshot_stale`,
`terminal_lifecycle_final_audit_missing`,
`terminal_lifecycle_final_audit_not_complete`,
`terminal_lifecycle_full_outcome_missing`,
`terminal_lifecycle_nonterminal_tasks`,
`terminal_lifecycle_inventory_incomplete`,
`terminal_lifecycle_ownership_ambiguous`,
`terminal_lifecycle_owned_resource_active`,
`terminal_lifecycle_owned_resource_unknown`,
`terminal_lifecycle_parent_task_action_forbidden`,
`terminal_lifecycle_persistence_authority_missing`,
`terminal_lifecycle_unknown_resource_mutation_forbidden`,
`terminal_lifecycle_action_receipt_missing`,
`terminal_lifecycle_action_receipt_mismatch`,
`terminal_lifecycle_action_authority_invalid`,
`terminal_lifecycle_action_failed`,
`terminal_lifecycle_target_identity_changed`,
`terminal_lifecycle_process_identity_reused`,
`terminal_lifecycle_server_listener_remains`,
`terminal_lifecycle_provider_process_remains`,
`terminal_lifecycle_worktree_current_forbidden`,
`terminal_lifecycle_worktree_dirty`,
`terminal_lifecycle_worktree_unintegrated`,
`terminal_lifecycle_worktree_unsafe`,
`terminal_lifecycle_post_inventory_missing`,
`terminal_lifecycle_plan_digest_mismatch`,
`terminal_lifecycle_board_mutation_premature`,
`terminal_lifecycle_official_checker_failed`,
`terminal_lifecycle_stop_checker_failed`,
`terminal_lifecycle_terminal_state_mismatch`,
`terminal_lifecycle_parent_child_plan_missing`,
`terminal_lifecycle_parent_child_plan_mismatch`,
`terminal_lifecycle_parent_child_receipt_missing`,
`terminal_lifecycle_parent_child_receipt_mismatch`, and
`terminal_lifecycle_parent_child_action_order_invalid`.

The plan action schema is closed and includes `action_id`, `resource_id`,
`resource_class`, `action`, `exact_target_identity`, and `reason`. `action_id`
is derived from the resource ID, action, and exact target identity. A
`ParentTerminalActionReceipt` is closed to `schema_version`, `artifact_type`,
`plan_sha256`, `parent_authority`, `actions`, `post_inventory_sha256`,
`completed_at`, and `receipt_sha256`. `parent_authority` is exactly
`{authority_kind, authority_id, authority_sha256}` and must equal the external
anchor. Each receipt action is exactly
`{action_id, status, exact_target_identity, evidence, completed_at}`; the
evidence object is a closed canonical ParentHostActionEvidence body with
`{artifact_type, action_id, status, exact_target_identity, completed_at, evidence_sha256}`;
its digest is recomputed. Required actions must report
their matching successful status, and a matching `failed` status returns
`terminal_lifecycle_action_failed`. The receipt's post-inventory digest must
equal the fresh inventory supplied to `ready`.

## CLI

```sh
python3 plugins/codexmax-orchestrator/scripts/compile_terminal_lifecycle.py \
  --input terminal-lifecycle-request.json \
  --trust-anchors terminal-lifecycle-trust-anchors.json \
  --expected-trust-anchors-sha256 sha256:... \
  [--stage-manifest terminal-lifecycle-stage-manifest.json \
   --expected-stage-manifest-sha256 sha256:...]
```

The request's `operation` is `plan`, `ready`, or `confirm`. Plan requires only
the external trust-anchor arguments. Ready and confirm require both external
stage-manifest arguments. Success is one canonical JSON object on stdout.
Rejection is one canonical JSON object on stderr with exit status 2.
