---
name: codexmax-assignment
description: "Advanced composable capability — Assign bounded dependency-aware task packets with ownership, validation, correction routes, budgets, and handoffs."
---

# Codexmax Assignment

Use `../../assets/templates/parallelism-packet.yaml` and the
[Provider Task Input Contract](../../assets/contracts/provider-task-input.md).

Every task defines:

- task id and objective;
- Parent phase id, depth-one child milestone id, and child board path when the
  task belongs to a phase-to-milestone hierarchy;
- dependencies and parallel group;
- allowed read and write scope;
- preferred and fallback routes;
- expected artifact and handoff owner;
- self-test and independent validation;
- correction route and retry cap;
- token, quota, cost, and wall-time budget;
- lane mode plus the bounded write-Worker progress receipt path and transition
  allowlist;
- stop conditions.

For a native Codex child, also create and persist the
[Codex Collaboration Runtime Projection](../../assets/contracts/codex-runtime-projection.md)
before `spawn_agent`. The assignment must name the child task ID, semantic role,
selected route and authority, requested native agent type, Parent model and
effort, history projection, and fallback. Do not use a native fixed role when
its model or reasoning conflicts with the selected route. A missing or
`approval_required` projection blocks the spawn.

For a native Claude child, pass the same bounded assignment packet, role, scope,
effective preferences, and capability receipt through the observed Claude
host-native Agent surface only. The invoking chat is the Parent/PM. Use the
documented Agent surface, session-only `--agents` configuration, and full model
ID or `inherit` as described at
https://code.claude.com/docs/en/sub-agents. These are usable only after current
host preflight exposes and authorizes them. Do not invent a Claude tool name,
worker API, model enum, runtime, or child-ID field. Missing or unsupported
Claude capability returns `resolution_need` or an explicit unsupported result
and does not substitute another route.

When the GoalBuddy Supervisor execution loop dispatches the packet, wrap it in
an `assignment_created` event defined by
`../../assets/contracts/supervisor-execution-loop.md`. The assignment task ID
must equal GoalBuddy's active task, and every read/write scope must be equal to
or narrower than that task's `allowed_files`. Include
`accept_checkpoint`, `accept_goal`, `mutate_goalbuddy`, and
`create_desktop_chat` in `forbidden_actions` for local internal lanes.

A repair assignment uses a fresh assignment ID and distinct result artifact.
The append-only event chain retains the predecessor assignment, route receipts,
artifacts, and failures; replacement prose cannot overwrite them.

Keep package identity, attempt identity, candidate identity, validation
identity, and repair identity in separate fields. Do not overload the task id,
phase id, or milestone id with those identities. A child assignment forbids
phase acceptance, milestone acceptance, GoalBuddy board mutation, and `T999`
creation or completion. Only the Parent/PM can perform those actions.

Parallel read-only tasks may overlap. Concurrent writers require disjoint files
or isolated worktrees. One Integrator owns shared boundaries and merge truth.

## Packet Construction

Create task packets from accepted goal facts, not from private reasoning. Each
packet must include:

- read-first files in order;
- explicit authority boundary and forbidden claims;
- allowed write scope with exact paths or globs;
- dependency gates and parallel group;
- required result artifact path;
- raw transcript or raw command receipt path when applicable;
- self-test commands and expected independent tester;
- result headings and evidence language required by the provider-neutral
  writing contract;
- correction route, retry cap, wall-time budget, and stop-if conditions.

Every provider-neutral task also has a complete `provider_input` block before
dispatch: `required_source_access`, `source_access`, `input_delivery`,
`source_backed_claims_required`, `commands_required`, `commands_executable`,
`named_source_categories`, `embedded_fact_pack`, `read_receipt_required`, and
`compatibility_gate.decision` plus `compatibility_gate.reason`. Use explicit
empty lists or `null` only where the contract permits them; do not infer a
capability from provider or role identity.

Compute compatibility with the canonical contract logic after route, tool, and
billing checks and before dispatch. Record the computed decision and exact
reason in the packet, require the declared values to match, and do not dispatch
an `incompatible` or unresolved required route. Every dispatched packet
requires the result's canonical `Input Access Receipt`, with exactly one source
row per named category and supported claim IDs for material claims. Paths-only
delivery can yield `read_local`; embedded delivery yields
`received_embedded`, never `read_local`.

For implementation waves, assign shared contracts, templates, tests, and docs
to at most one writer unless the files are split by exact path. If two workers
need the same file, sequence them through an Integrator or issue a revision
packet after the first result is known.

## Bounded Worker Progress

Classify every lane as `write_worker` or `read_only`. Read-only lanes remain
exempt from file-transition requirements. A bounded write Worker uses the
packet's 10-command, 128-KiB returned-output, and 15-minute no-progress
thresholds. At the first crossed threshold, a progress receipt must name either
an authorized file change or an `expected_artifact` explicitly accepted by the
Supervisor. Worker prose and unscoped file churn are not progress transitions.

The packet-derived progress policy, not the Worker receipt, owns lane mode,
authorized transition paths, Supervisor-accepted expected-artifact paths, and
the fixed 10-command, 128-KiB, and 15-minute thresholds. Dispatch it separately
from the runtime receipt. The policy also owns the evidence root, transcript
hash, Worker and Supervisor process/session identities, and SHA-256 descriptors
for separate Supervisor-owned transition receipts. Each transition receipt
must bind the allowed path to the actual transcript and command identity. An
authorized file change additionally declares `create`, `modify`, or `delete`
and binds both states to the same normalized logical path. Create requires
trusted absent-to-verified-present state, modify requires unequal verified
present-state hashes, and delete requires verified-present-to-actually-absent
state. An `expected_artifact` binds an existing regular artifact descriptor and hash.
Every transcript, transition receipt, snapshot, artifact, terminal receipt, and
repair evidence file must have exactly one filesystem link. Hard-linked
evidence fails closed even when its path and hash otherwise match.
Self-declared authorization, acceptance, or threshold overrides fail closed.

The receipt records threshold crossings plus the command index and wall time to
the first accepted transition. With no accepted transition, the lane becomes
`checkpoint_required_no_progress` and must be narrowed, reassigned, or continued
only through an explicit Supervisor rationale; the max-turn ceiling is unchanged.

## Worker Result Requirements

Every Worker packet requires the Worker to return:

- identity: provider, model, runtime, route id, role, task id, and artifact
  status;
- outcome: what changed, proof boundary, and requested state transition;
- input access: declared access, actual delivery, command capability, computed
  compatibility decision/reason, category read rows, and explicit unknowns;
- evidence: paths, commands, exit statuses, and relevant observations;
- validation: exact commands run, not run, or not applicable with reasons;
- risks and gaps: untested surfaces, unknown costs or tokens, and remaining
  acceptance gaps;
- handoff: produced, not produced, safe to use, must verify, next owner, and
  parent decision requested.

## Material Repair Sequence

For material repair, require the sequence: worker self-test → independent
finding → changed repair → retest. A separate Tester and Auditor are not
mandatory when one independent reviewer supplies the required proof. Record
expected and actual lane, PM, review, and repair costs when known; preserve
unknown honestly.

Native collaboration results additionally retain the pre-spawn projection
receipt and the canonical child ID returned by Codex. Record
`runtime_surface: codex_collaboration` and `provider_dispatch: false`; do not
describe the child as an external-provider execution.

Do not ask a Worker to infer final acceptance. Worker outputs remain
`ready_for_review`, `candidate_complete`, `needs_revision`,
`needs_reassignment`, `needs_parent_repair`, or `waiting_external`.
