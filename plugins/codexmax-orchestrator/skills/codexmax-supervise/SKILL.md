---
name: codexmax-supervise
description: "Advanced composable capability — Supervise a delegated board, bounded workers, receipt integration, failed-work adaptation, and candidate closeout."
---

# Codexmax Supervise

## Supervisor Loop

For deterministic local execution, first read
`../../assets/contracts/supervisor-execution-loop.md`. Use
`../../scripts/run_goalbuddy_supervisor.py` to bind the locked goal and current
GoalBuddy board, append hash-chained structured lifecycle events, and emit only
a candidate board delta. Never reconstruct the board from transcript or edit
`state.yaml` from this runtime.

Runtime schema v2 keeps phase and repair count per lane and derives a separate
aggregate closeout phase. Schema-v1 state may migrate deterministically, but its
append-only event history is not rewritten. Concurrent lane progress is
permitted only after dependency, independence, writer-count, and normalized
scope checks establish disjoint eligibility. GoalBuddy remains board truth.

1. Read the parent contract and parallelism packet.
2. Verify provider input compatibility, write ownership, and dependencies before
   dispatch.
3. Run independent read-only work broadly; run concurrent writers only with
   disjoint files or isolated worktrees.
4. Require every builder to self-test and return exact commands.
5. Return defects to a builder or provider-diverse repair Worker.
6. Start independent Tester work after integration prerequisites exist.
7. Start documentation from durable Worker and Tester evidence.
8. Run randomized final audit after documentation exists.
9. Return `candidate_complete`, `needs_parent_repair`, or `waiting_external`
   with a full closeout packet. Never claim final acceptance.

For material repair, require the sequence: worker self-test → independent
finding → changed repair → retest. A separate Tester and Auditor are not
mandatory when one independent reviewer supplies the required proof. Record
expected and actual lane, PM, review, and repair costs when known; preserve
unknown honestly.

For scheduler-backed artifact lanes, verify the compiled envelope and exact
binding digests, current fenced lease, ledger interval, legacy return manifest,
and passing deterministic quality receipt before applying any bundled event.
Transport success alone is not a result. `DispatchScheduleManifest v1` is an
unapplied evidence wrapper whose Supervisor, GoalBuddy, and acceptance flags
remain false; never treat it as an apply instruction. Stop on stale fencing,
scope overlap, unknown-required allowance, rejected quality, or
`execution_unknown`.

For a semantic Worker bundle, read
`../../assets/contracts/dispatch-application.md` and use
`../../scripts/apply_scheduled_dispatch.py`; do not hand-append its two event
rows. The gate serializes the scheduler and Supervisor runtime pair, resumes
only its exact manifest-bound recovery prefix, records completion after both
Supervisor events, and creates a non-accepting application receipt. A Tester,
Documenter, or Auditor reference must not enter that Worker-only gate. Read
`../../assets/contracts/role-lifecycle.md`, compile its strict target-lane
packet with `../../scripts/compile_role_lifecycle.py`, and apply it only through
`../../scripts/apply_role_lifecycle.py`. Stop on any stale phase, descriptor,
profile, independence, source, trusted-command, lease, or cursor binding.

Do not stop because one Worker fails. Preserve useful partial artifacts, revise
the packet, substitute a provider, or escalate the specific decision to parent.

Read `../../assets/contracts/execution-continuity.md` for long-horizon
continuation. At milestones, failed attempts, forecast crossings, and context
pressure, run `../../scripts/assess_execution_continuity.py` against a durable
input record. A soft forecast miss triggers progress assessment, packet
optimization, reforecasting, and current-run or rollover continuation. It does
not trigger an operator token-ceiling request. Only an explicit operator cap or
another consequential authority boundary may do that.

Within existing authority, prefer the applicable bounded action: repair a
known validation defect, revise an ineffective packet, split coupled work,
reroute an incompatible lane, or persist a rollover pack and continue in a
fresh run. Before declaring `needs_parent_repair`, record why every unused
strategy is inapplicable. Before `waiting_external`, prove useful authorized
local work is exhausted.

## Evidence And Token Efficiency

Max turns is a safety ceiling, not an efficiency target. Keep a normal ceiling
of 15 to 20 turns when the provider exposes one; do not lower it to force
completion. Control context growth through bounded evidence access instead:

- read provider-neutral receipts and test summaries before raw evidence;
- never read the Supervisor's own live raw transcript;
- do not read a `*-raw.*`, `raw/*.jsonl`, or other raw transcript wholesale;
- inspect raw evidence only for a named disputed claim, using a parser or a
  bounded excerpt of at most 8 KiB by default;
- cap normal command output returned to the Supervisor at 16 KiB; redirect or
  summarize larger output into an artifact and return its path, digest, and
  bounded findings;
- do not run an unbounded search across report or raw-transcript trees;
- resolve `<plugin-root>` with `<plugin-root> = Path(SKILL.md).parents[2]`, then
  use `python3 <plugin-root>/scripts/bounded_evidence.py search` for receipt discovery so `raw/**`,
  `*-raw.*`, and `*.jsonl` remain excluded, locators use opaque root labels and
  root-relative paths, and returned output stays at or below 16 KiB;
- redirect accumulated service logs to a preserved single-link regular `.log`,
  `.out`, or `.txt` file of at most one MiB beneath an explicitly authorized
  root and return only the metadata-only
  `python3 <plugin-root>/scripts/bounded_evidence.py service-log --root <authorized-root> <root-relative-log>`
  locator/size/opaque-identity receipt; this command never reads or returns log
  content, rejects duplicate roots before path access, and uses nonblocking
  no-follow descriptor checks;
- treat every search failure as opaque; never return a supplied root or `rg`
  stderr in its failure receipt;
- require separately authorized claim-specific sanitization, parsing, or
  excerpting before any raw service-log content access;
- preserving raw evidence does not authorize ingesting all of it into context.

Record cumulative command count, command-output characters, largest command
output, raw-read count, self-transcript-read count, cumulative input tokens,
cached input tokens, uncached input tokens, output tokens, and reasoning tokens
when exposed. Run `scripts/summarize_supervisor_usage.py` against Codex JSONL
when available. At 10 commands, 128 KiB of returned command output, or one
million cumulative input tokens, pause for an efficiency checkpoint: compact
evidence, delegate remaining inspection, or issue a narrower packet. Crossing a
checkpoint is not failure and does not reduce the max-turn ceiling.

Apply a separate progress classification to bounded write Workers. Read-only
lanes are exempt. At the first 10-command, 128-KiB returned-output, or 15-minute
threshold, require an authorized file change or kind `expected_artifact`
explicitly accepted by the Supervisor. Record the first transition's path, command index,
and wall time. If none exists, record `checkpoint_required_no_progress`, preserve
the process receipt, and narrow, reassign, or continue only with an explicit
reason. Worker-authored claims and out-of-scope files never satisfy the gate.
Lane mode and both path allowlists come from the packet-derived progress policy;
the runtime receipt cannot override them or the fixed 10-command, 128-KiB, and
15-minute thresholds. A transition counts only when its normalized path belongs
to the matching policy list and a separately stored Supervisor-owned receipt
matches a policy-anchored SHA-256. That receipt binds Supervisor and Worker
process/session ids, transcript path/hash, actual command hash/index, path, and
wall time. For `authorized_file_change`, it also verifies an explicit `create`,
`modify`, or `delete` transition whose before/after states name the same
normalized logical path and satisfy absent-to-present, unequal
present-to-present, or present-to-actually-absent semantics. For
`expected_artifact`, it verifies the existing regular artifact and hash. `accepted_by: supervisor` or
`authorized: true` self-attestation is forbidden.

The Supervisor coordinates lanes and may edit only its board, packets, and
closeout artifacts by default. Source implementation requires a dispatched
Worker. Direct source implementation is allowed only after an explicit
`parent_repair` transition records why delegation is no longer the safest
route, the exact write scope, and the required independent retest.

## Execution Board

Maintain a board or ledger with one row per lane:

- task id, role, objective, dependency state, and active status;
- provider, model, runtime, route id, and fallback history;
- input-compatibility decision and reason plus read-receipt status;
- read scope, write scope, and owned artifact path;
- start time, stop time, wall time, token, quota, and cost measurements or
  `unknown`;
- cumulative command-output and efficiency-checkpoint measurements or
  `unknown`;
- self-test command status and independent verification status;
- disposition: usable, needs revision, needs reassignment, parent repair, or
  waiting external.

Qualify telemetry fields by host. Preserve measured values and use `unknown`
for unavailable provider/model/runtime, token, quota, cost, wall-time, native
session, and child identity fields. Do not transfer final acceptance to a
Worker or Supervisor.

The board is execution state, not acceptance. Parent/PM still decides final
acceptance.

When the Parent supplies `controller_execution`, keep its task scope, role
model/effort references, repair authority, reviewer requirement, and reporting
policy bound to the same projection receipt. The controller owns only internal
readiness, proposal application, validation, and changed-hypothesis repair.
Require independent review before candidate closeout. Do not mark internal
readiness as a GoalBuddy checkpoint or final acceptance. Report routine
progress through the run receipt and surface exceptions and the final candidate
to Parent. Pass the emitted assignment text to the native host tool and record
the returned child ID. Scope is an instruction; actual enforcement depends on independently configured
host permissions; the projection grants no sandbox.

### Phase And Milestone Rollup

For a phase container with a depth-one milestone board, report these six fields
from validated board state: milestones complete, milestones total, current
milestone, current gate, exact blocker, and next milestone. Keep one milestone
active unless the accepted board contract permits safe parallel work. Never
infer phase completion from a child status summary.

Keep repair evidence compact. Record package identity, attempt identity,
candidate identity, validation identity and result, repair disposition, and the
receipt path or digest. Append a new attempt record after failure. Do not erase
or rewrite a failed attempt when a later candidate passes.

When presenting usage to the operator, show only lanes that were actually
invoked. Preserve unknown input, cached-input, output, reasoning, and total
tokens. Add one short notice for configured lanes that were available but not
called; do not list every unused model.

The local runtime projection is also execution state, not board truth. Its
event log is append-only structured evidence. A changed locked-plan hash,
changed board hash, changed active task, incomplete dependency, auxiliary
acceptance claim, transcript field, or event-chain mismatch fails closed.

Emit the versioned continuity projection needed by an eventual Orcastrata/AOL
operator client: oracle movement, active checkpoint, lanes and routes,
forecast versus usage, explicit cap, external-cost authority, repairs,
rollover identity, commits, validation, pending GoalBuddy transition, and the
exact decision owner. The client remains a projection and typed-command
surface; it does not mutate GoalBuddy or Codexmax runtime truth directly.

For Parent synchronization, read
`../../assets/contracts/parent-supervisor-synchronization.md`. Relay only
records selected from a fully verified Supervisor-loop hash chain. Surface
side-task user comments and authority-change requests as typed Parent-audience
deltas, pause before authority-sensitive progress, and require a distinct
Parent resume after any response. Never ingest a full transcript, let a Worker
write the synchronization stream, treat open/message requests as native host
success, apply an authority response to execution, or turn candidate closeout
into acceptance.

For restart and recovery controls, read
`../../assets/contracts/supervisor-recovery.md` and use
`../../scripts/recover_supervisor_runtime.py`. Recovery must replay and pin the
current T012 state, reverify the accepted T005 event and cursor predecessor,
and reconcile against GoalBuddy before work continues. A stale task, stale or
duplicate Supervisor, corrupt or truncated history, mismatched epoch or cursor,
or unresolved authority is a fail-closed condition. Preserve the original
failure and require a fresh T012 repair assignment before acknowledging repair.
For T006 progress, use only the recovery-aware T012 `apply` operation with the
pinned recovery and sync histories, exact Supervisor ID/epoch, and a unique
transition ID. Do not dispatch a repair after `revise` until Parent has emitted
the explicit repair-assignment authorization for the preserved failure.
Require that event to bind the exact predecessor/repair IDs, fresh expected and
result artifact, read/write scope, route profile, task, lane, repair role,
write mode, authorization action, and recovery epoch. Never reuse it for a
second repair; stop, board change, or epoch change invalidates or expires it.

## Dispatch Rules

### Headless Dispatch Handoff

For an authorized headless lane, read
`../../assets/contracts/headless-provider-dispatch.md` and treat
`dispatch-return-manifest.json` plus `supervisor-event-bundle.json` as an
untrusted, unapplied handoff. Before using it:

1. Require schema version 1, `manifest_type: DispatchReturnManifest`,
   `bundle_type: SupervisorEventBundle`, equal `dispatch_id` and
   `semantic_role`, and literal false values for `accepted`,
   `applied_to_supervisor`, and `applied_to_goalbuddy` where those fields are
   defined.
2. Resolve the manifest's `supervisor_handoff.path` beneath the authorized
   repository, reject symlinks, hard links, and non-regular files, and
   recompute its byte count and SHA-256 before parsing the bundle.
3. Recompute the normalized artifact descriptor and the final route-packet
   SHA-256. Require exact matches with the manifest artifact and bundle
   binding, including `supervisor_assignment_id`, `supervisor_lane_id`,
   expected artifact path/hash, and route-packet hash.
4. Require a previously accepted normal `assignment_created` lifecycle event
   with the same assignment ID, lane ID, expected artifact, semantic role, and
   authorized scope. A dispatcher-created bundle never creates its own
   assignment authority.
5. Re-run the normal Supervisor event validator at the lane's current lifecycle
   phase. Hash agreement proves byte identity, not claim truth, independence,
   validation success, or acceptance.

Only a semantic Worker handoff may supply its bundled `route_resolved` and
`worker_result` events, and only after the matching
`assignment_created` event and all checks above. Apply them in order through
the normal lifecycle runtime; scheduler-owned bundles must go through
`apply_scheduled_dispatch.py`. Never append trusted-looking bundle rows directly
to an event log.

Planner and Architect outputs remain advisory references. Convert a verified
role-labelled Tester, Documenter, or Auditor reference only through the
role-lifecycle compiler, which constructs `independent_test`, `documentation_result`, or `audit_result`
respectively after revalidating every
field and lifecycle prerequisite required by the Supervisor contract. Do not
hand-construct or hand-append these events, do not relabel any of them as
`worker_result`, and do not apply an empty reference merely because its
artifact hash matches. Provider output is never trusted command evidence.

The dispatcher and this handoff never mutate GoalBuddy, advance its active
task, apply a candidate delta, or claim Parent acceptance. A valid handoff only
adds verified execution evidence to the one Supervisor truth surface.

- Read `../../assets/contracts/provider-task-input.md` and run its pre-dispatch
  compatibility gate for every lane that needs source-backed claims.
- Require explicit `source_access`, `input_delivery`, command executability, and
  named source categories. Treat missing or unverified capability as `unknown`;
  never infer it from provider or role identity.
- Reject or reassign path-only work sent to an embedded-only route. When an
  embedded fact pack is compatible, require claim IDs, source labels, hashes or
  `unknown`, and explicit omissions.
- Dispatch read-only scouting before write work when file ownership or risk is
  unclear.
- Dispatch write workers only after confirming disjoint file ownership,
  isolated worktrees, or a single Integrator.
- Before retrying, resuming, or reassigning a lane, terminate and reap every
  superseded process that can write the same write scope or result-artifact path.
  Record its process or session identity, terminal status, and preserved raw
  output before dispatching the replacement. A resumed process counts as the
  same active lane and must not overlap its original process.
- Every replacement receipt records replacement-only identity provenance and
  complete keys for actual provider, model, runtime, route id, commands,
  command-output characters, token counts, wall time, and first transition.
  Unavailable values use a null value with a reason; literal placeholder
  identity strings are invalid. Never inherit predecessor
  identity or accounting.
- If a superseded process cannot be proven terminal, do not start a replacement
  on the same write scope or artifact path. Isolate the replacement in a
  separate worktree and distinct artifact path, or escalate the collision to
  parent repair.
- Compute replacement overlap from Parent-owned predecessor and replacement
  scope sets, never from the replacement receipt boolean. When scopes overlap,
  verify beneath the evidence root a Parent-owned, hash-anchored structured
  receipt whose predecessor identity is terminal and reaped. Replacement
  process and session identities must both be distinct. Every referenced
  evidence file must have exactly one filesystem link; hard-linked evidence
  fails closed.
- Keep provider identity and role identity separate in every packet.
- Preserve original Worker artifacts even when a Documenter normalizes them.
- Start documentation as soon as enough durable Worker and Tester evidence
  exists; do not wait for perfect success when a truthful partial closeout is
  needed.
- Run failure-pattern analysis after repeated failures, same-root defects, or a
  long checklist with little progress.

## Integration Gate

Before returning a closeout, check:

- all changed files are in authorized scope;
- every provider result has a read receipt covering every named source category;
- receipt `source_access`, actual `input_delivery`, and `read_status` support
  each material evidence claim;
- embedded facts remain labeled `received_embedded` and are never promoted to a
  local-file observation;
- claims based on `unavailable`, `not_supplied`, `not_read`, or `unknown` source
  rows are rejected or revised;
- commands recorded as `not_run` remain `not_run` and are never represented as
  validation passes;
- Worker claims match the diff and recorded command output;
- every reassigned or retried lane has a terminal superseded-process receipt,
  with no unresolved same-scope process still able to overwrite accepted work;
- every write Worker that crossed a progress threshold has a valid progress
  receipt, and every replacement passes `replacement_receipt_errors` without
  inherited identity or missing unknown reasons;
- validation failures are either repaired, assigned to revision, or surfaced as
  parent repair;
- result artifacts use the provider-neutral headings and status vocabulary;
- raw transcripts, command logs, or original worker outputs are preserved when
  they exist;
- fresh-task or install proof is not confused with cache inspection unless the
  packet explicitly allows cache-only proof.

A missing or contradictory input-access receipt is a revision or reassignment
event. Provider confidence, polished prose, or role fit cannot repair evidence
the lane did not receive or read.

## Receipt-Only Repair

Classify technical work and receipt validity separately. When preserved command
evidence proves the technical work `valid` but its result receipt is `invalid`
or `missing`, issue a `receipt_only` transition. Preserve the original artifact,
verify original and repaired regular-file hashes beneath the evidence root,
require exactly one filesystem link per evidence file, require distinct
resolved files/inodes, forbid source-file edits and workload command reruns,
and require verified, distinct before/after source-tree and closed
command-ledger manifests plus identical accepted-command-result digests.
Empty Worker-reported change and rerun lists do not prove either negative.

Use `implementation_revision` for invalid technical work and
`targeted_evidence_recovery` when technical validity is unknown. A receipt-only
repair cannot create missing input access or change test outcomes. Use
`no_repair` for valid work with a valid or not-applicable receipt; valid work
with an unknown receipt requires `targeted_evidence_recovery`. Run
`receipt_repair_transition_errors` before integrating the corrected receipt.
