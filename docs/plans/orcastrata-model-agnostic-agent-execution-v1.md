# Orcastrata Model-Agnostic Agent Execution V1

Plan ID: `orcastrata-model-agnostic-agent-execution-v1`
Plan Mode: `execution_authorized`
Plan Lifecycle: `done`
Execution Authority: `granted`
Roadmap Origin: `standalone operator request`

## TL;DR

Repair the installed 1.0.3 external-agent journey before expanding scope. Keep
transport code controlled. Let operators declare exact models over approved
transports. Prove read-only execution, automatic routing, controlled writes,
explicit fan-out, and installed behavior with real provider receipts.

## Plan Identity and Lifecycle

- Owner: Steven and Parent Codex
- Audience: Orcastrata implementers and reviewers
- Created: 2026-08-28
- Last updated: 2026-08-28
- Source request: current Codex task
- Proof boundary: local

## Selected Roadmap Sources

Standalone. The requested outcomes share one adapter, routing, execution, and
installed acceptance boundary.

## Current Task

<!-- codexmax-current-task:start -->
`T999` is complete. Luna accepted the exact installed 1.0.4 candidate. Parent
reconciled goal-owned children and confirmed a terminal collaboration tree.
<!-- codexmax-current-task:end -->

## Phase-To-Milestone Hierarchy

- Parent phase: `orcastrata-model-agnostic-agent-execution-v1`
- Child board: `docs/goals/orcastrata-model-agnostic-agent-execution-v1/state.yaml`
- Child milestones: T010, T020, T030, T040, T050, T060, T070, T080
- Active milestone: none
- Split triggers: read-only execution, automatic routing, write authority,
  fan-out, installed provider calls, and final audit are separate gates.
- Dependencies: T010 -> T020 -> T030 -> T040 -> T050/T060 -> T070 -> T080 -> T999
- Independently useful outcomes: generic model onboarding; real read execution;
  automatic routing; controlled writes; explicit fan-out; installed acceptance.

## High-Level Task Ledger

<!-- codexmax-task-ledger:start -->
| ID | Task | Status | Depends on | Unlocks | Parallel mode | Write owner | Gate/proof | Receipt |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T010 | Freeze base, oracle, and authority | done | — | T020 | serial | Parent | Valid plan and board | T010 receipt |
| T020 | Declarative exact-model candidates | done | T010 | T030 | serial | Luna Worker | 5 focused tests and diff check | T020 Worker receipt |
| T030 | Installed read-only execution journey | done | T020 | T040 | serial | Luna Worker plus Parent | Installed DeepSeek task | T030 Worker and live receipts |
| T040 | Automatic compatible route selection | done | T030 | T050, T060 | serial | Luna Worker plus Parent | Installed ordinary prompt invoked exact route | T040 Worker and live receipts |
| T050 | Controlled isolated writes | done | T040 | T070 | serial | Luna Worker | Exact diff and Parent review | T050 Parent acceptance receipt |
| T060 | Explicit adversarial fan-out | done | T040 | T070 | serial | Luna Worker | Distinct lane receipts and synthesis | T060 Parent acceptance receipt |
| T070 | Package, install, and live validation | done | T050, T060 | T080 | serial | Parent | Installed provider journeys | T070 installed acceptance and 1.0.4 fan-out addendum |
| T080 | Independent final audit | done | T070 | T999 | independent_gate | Luna Judge | ACCEPT or REVISE | T080 independent Luna ACCEPT |
| T999 | Terminal lifecycle closeout | done | T080 | — | serial | Parent | Clean child inventory and checker | T999 Parent closeout |
<!-- codexmax-task-ledger:end -->

## Objective and Acceptance Oracle

### Objective

Make installed Orcastrata configure and execute models as agents without a
source-code change for each exact model.

### Acceptance Oracle

The exact installed successor must configure a non-hardcoded model over an
approved transport, execute and validate real read and controlled-write tasks,
route an ordinary task to a compatible worker, run explicit three-model
fan-out, and report exact invoked identity and truthful usage.

## Current-State Assessment

The 1.0.3 package has process builders, response validators, task-scoped live
dispatch, fan-out scaffolding, and adapter configuration. Its public defaults
are disabled examples. Onboarding produces configured but unqualified
bindings. Model and adapter compatibility are hardcoded. The positive
task-scoped test mocks the provider process. Native Luna works through Codex
collaboration and bypasses these external seams.

## Scope and Non-Goals

### In Scope

- Approved-transport model declaration.
- Exact session/model discovery and task-scoped preflight.
- Real task-scoped read-only execution.
- Automatic capability-based selection.
- Isolated controlled writes.
- Explicit multi-model fan-out.
- Package, reversible install, real-provider validation, and rollback.

### Non-Goals

- Arbitrary user executable, endpoint, module, URL, environment, or argv loading.
- Credential inspection or login automation.
- AOL protected production or shared-tree production writes.
- Push, publication, unrelated cleanup, or mutation of the dirty checkout.

## Implementation Architecture and Data Flow

`operator request -> approved transport -> declarative exact-model candidate ->
session/model discovery -> capability evidence -> task grant -> task_scoped_live
or isolated controlled-write execution -> identity/schema/effect validation ->
Parent acceptance -> invoked-model and usage receipt`

Transport code remains package-owned. Models become data. Capability remains
evidence-owned. Task grants remain authority. Explicit route selection forbids
fallback. Automatic routing selects only a fresh compatible route.

## Critical Path and Parallel Waves

- Critical path: T010 -> T020 -> T030 -> T040 -> T050/T060 -> T070 -> T080 -> T999
- Parallel waves: T050 and T060 are architecturally independent but remain
  serial because they touch shared dispatcher and receipt surfaces.
- Serialized ownership: adapter registry, resolver, dispatcher, routing skill,
  package manifest, and board state.

## Progressive Phases and Gates

1. T020 exits when a non-hardcoded exact model can be configured through an
   approved transport without arbitrary execution fields.
2. T030 exits only after one real installed DeepSeek read-only task succeeds.
3. T040 exits when an ordinary task selects and reports an exact compatible route.
4. T050 and T060 prove writes and fan-out separately.
5. T070 freezes, installs, runs live acceptance, and proves rollback.
6. T080 independently accepts or revises the exact installed candidate.
7. T999 closes goal-owned children before board completion.

## Detailed Task Contracts

### T010 — Freeze the successor contract

- **Objective and rationale:** Select the exact base and freeze the oracle before product writes.
- **Inputs and prerequisites:** User authority, 1.0.3 release identity, dirty-tree inventory, and Luna architecture receipts.
- **Deliverables:** Valid charter, board, implementation plan, and first Worker packet.
- **Allowed files:** `docs/goals/orcastrata-model-agnostic-agent-execution-v1/**` and `docs/plans/orcastrata-model-agnostic-agent-execution-v1.md`.
- **Excluded files:** Product source, installed plugin files, and the dirty main checkout.
- **Dependencies and unlocks:** Depends on none; unlocks T020.
- **Parallel mode and write owner:** `serial`; Parent.
- **Implementation steps:** Record authority, base identity, scope, tasks, validation, and stop rules.
- **Validation commands:** GoalBuddy checker, implementation-plan validator, and `git diff --check`.
- **Acceptance evidence:** T010 receipt plus passing validators.
- **Stop and escalation conditions:** Stop if the base or dirty ownership is ambiguous.
- **Rollback or recovery:** Remove only newly added governance files before product work starts.
- **Documentation obligations:** Keep goal, board, plan, and receipt aligned.
- **Next-owner handoff:** T020 Luna Worker.

### T020 — Declarative exact-model candidates

- **Objective and rationale:** Add new exact models through approved transports without source changes per model.
- **Inputs and prerequisites:** T010 receipt and current adapter/config contracts.
- **Deliverables:** Generic model candidate authoring, conservative migration, contracts, and focused tests.
- **Allowed files:** Adapter registry, config resolver, their contracts/templates/tests, and T020 notes listed in the board.
- **Excluded files:** Dispatcher, fan-out, package identity, installed plugin, and dirty main checkout.
- **Dependencies and unlocks:** Depends on T010; unlocks T030.
- **Parallel mode and write owner:** `serial`; one Luna Worker.
- **Implementation steps:** Separate approved transport identity from declarative exact model identity and retain closed execution fields.
- **Validation commands:** `python3 -B -m unittest tests.test_adapter_registry tests.test_codexmax_config -q` and `git diff --check`.
- **Acceptance evidence:** Focused positive, migration, and forbidden-field tests plus Worker receipt.
- **Stop and escalation conditions:** Stop if extensibility requires arbitrary executable configuration or unsafe identity migration.
- **Rollback or recovery:** Revert only the T020 candidate changes; preserve T010.
- **Documentation obligations:** Update adapter and configuration contracts.
- **Next-owner handoff:** T030 Luna Worker.

### T030 — Installed read-only execution journey

- **Objective and rationale:** Make one operator path reach a real task-scoped provider process and validated artifact.
- **Inputs and prerequisites:** Accepted T020 candidate and existing DeepSeek Command Code session.
- **Deliverables:** Configuration-to-preflight-to-dispatch flow, truthful receipt states, and real acceptance packet.
- **Allowed files:** Configuration/session verification, task-scoped dispatcher, operator skill/docs, direct tests, and T030 notes.
- **Excluded files:** Protected production, shared-tree writes, credentials, push, and publication.
- **Dependencies and unlocks:** Depends on T020; unlocks T040.
- **Parallel mode and write owner:** `serial`; one Luna Worker.
- **Implementation steps:** Compile exact binding and task grant, run fixed preflight, call once, and validate identity/schema/artifact.
- **Validation commands:** Focused config/session/dispatch tests, package parity, then one installed DeepSeek read-only task.
- **Acceptance evidence:** Non-mocked installed manifest with exact route and `provider_called` truth.
- **Stop and escalation conditions:** Stop on prompt, identity drift, metered fallback, credential request, or uncertain execution.
- **Rollback or recovery:** Preserve the attempt and uninstall only the successor candidate.
- **Documentation obligations:** Document the ordinary-language operator journey and proof limits.
- **Next-owner handoff:** T040 Luna Worker.

### T040 — Automatic compatible route selection

- **Objective and rationale:** Let normal delegation use an eligible worker without requiring the operator to name Luna.
- **Inputs and prerequisites:** Accepted T030 installed read-only journey and capability evidence.
- **Deliverables:** Capability selector, exact invoked-model receipt, and no-substitution behavior.
- **Allowed files:** Route resolver, orchestration skill, routing contracts/tests, and T040 notes.
- **Excluded files:** New transports, production authority, and provider-specific capability invention.
- **Dependencies and unlocks:** Depends on T030; unlocks T050 and T060.
- **Parallel mode and write owner:** `serial`; one Luna Worker.
- **Implementation steps:** Select only fresh compatible candidates and keep explicit selections exact.
- **Validation commands:** Focused resolver/orchestration tests and one installed ordinary-prompt journey.
- **Acceptance evidence:** Receipt that distinguishes considered, selected, called, and completed routes.
- **Stop and escalation conditions:** Stop on silent substitution, unknown-as-eligible, or model-name authority inference.
- **Rollback or recovery:** Restore prior route policy without changing accepted T030 execution.
- **Documentation obligations:** Explain automatic selection versus explicit route requests.
- **Next-owner handoff:** T050 and T060 serial Workers.

### T050 — Controlled isolated writes

- **Objective and rationale:** Allow task-owned development writes without conflating them with protected production.
- **Inputs and prerequisites:** Accepted T040 selection and exact write grant.
- **Deliverables:** Isolated worktree execution, exact before/after evidence, validation, and Parent review receipt.
- **Allowed files:** Scoped-work execution, change receipts, direct tests, operator docs, and T050 notes.
- **Excluded files:** Shared-tree production writes, AOL, and credential material.
- **Dependencies and unlocks:** Depends on T040; unlocks T070.
- **Parallel mode and write owner:** `serial`; one Luna Worker.
- **Implementation steps:** Bind one worktree and write scope, execute once, validate diff, and require Parent acceptance.
- **Validation commands:** Focused scoped-work tests and one installed controlled-write canary.
- **Acceptance evidence:** Exact changed-file receipt, validation result, and rollback proof.
- **Stop and escalation conditions:** Stop on out-of-scope mutation or uncertain diff custody.
- **Rollback or recovery:** Discard only the isolated canary worktree after retaining evidence.
- **Documentation obligations:** Separate development write proof from T062 production.
- **Next-owner handoff:** T070 Parent.

### T060 — Explicit adversarial fan-out

- **Objective and rationale:** Run named models as distinct reviewers rather than fallback alternatives.
- **Inputs and prerequisites:** Accepted T040 routing and at least two eligible exact routes.
- **Deliverables:** Exact route-set compiler, immutable multi-binding configuration, isolated assignments, bounded execution, and Parent synthesis receipt.
- **Allowed files:** Fan-out controller, adapter-binding authoring path, route-set schema, direct tests, operator docs, and T060 notes.
- **Excluded files:** Silent hedging, implicit fallback, shared evidence directories, and provider acceptance authority.
- **Dependencies and unlocks:** Depends on T040; unlocks T070.
- **Parallel mode and write owner:** `serial`; one Luna Worker.
- **Implementation steps:** Author all exact bindings without hand-edited YAML, freeze candidate/rubric, issue one assignment per route, validate each result, and synthesize in Parent.
- **Validation commands:** Focused fan-out tests and one installed multi-model review with available routes.
- **Acceptance evidence:** Per-lane manifests plus Parent synthesis and missing-lane disclosure.
- **Stop and escalation conditions:** Stop on route substitution, shared mutable custody, or unbounded concurrency.
- **Rollback or recovery:** Preserve terminal lane evidence and rerun only through a new authorized attempt.
- **Documentation obligations:** Distinguish fallback order from explicit fan-out.
- **Next-owner handoff:** T070 Parent.

### T070 — Package, install, and live validation

- **Objective and rationale:** Prove the exact integrated candidate from the installed projection.
- **Inputs and prerequisites:** Accepted T050 and T060 source candidates and current provider sessions.
- **Deliverables:** Immutable package, reversible install, real provider journeys, truthful telemetry, and rollback.
- **Allowed files:** Package metadata/manifest, acceptance packets, T070 receipts, and local installed projection.
- **Excluded files:** Push, publication, dependency download, credential inspection, and protected production.
- **Dependencies and unlocks:** Depends on T050 and T060; unlocks T080.
- **Parallel mode and write owner:** `serial`; Parent.
- **Implementation steps:** Freeze bytes, validate package, install once, preflight and run bounded routes, then prove rollback.
- **Validation commands:** Focused and consumer tests, full suite once, parity, installed loader, live journeys, and uninstall/rollback checks.
- **Acceptance evidence:** Exact install identity, provider manifests, usage receipts, and rollback receipt.
- **Stop and escalation conditions:** Stop on package drift, prompt, unknown billing path, identity mismatch, or rollback failure.
- **Rollback or recovery:** Restore the exact predecessor plugin and verify inventory.
- **Documentation obligations:** Record operator steps and actual provider limitations.
- **Next-owner handoff:** T080 Luna Judge.

### T080 — Independent final audit

- **Objective and rationale:** Prevent source, synthetic, or one-provider proof from being promoted to the complete vision.
- **Inputs and prerequisites:** Frozen T070 candidate and complete claim-to-receipt set.
- **Deliverables:** ACCEPT or REVISE verdict and exact finding matrix.
- **Allowed files:** T080 audit notes only.
- **Excluded files:** Product edits, provider calls, installation, and board acceptance.
- **Dependencies and unlocks:** Depends on T070; unlocks T999 only on ACCEPT.
- **Parallel mode and write owner:** `independent_gate`; Luna Judge.
- **Implementation steps:** Recompute identities, inspect diffs and receipts, and challenge every oracle claim.
- **Validation commands:** Read-only validators and receipt/hash checks.
- **Acceptance evidence:** Independent signed-off audit receipt.
- **Stop and escalation conditions:** REVISE on any missing installed, model, write, fan-out, telemetry, or rollback proof.
- **Rollback or recovery:** Return exact findings to Parent without modifying the candidate.
- **Documentation obligations:** State proof boundary and remaining risks.
- **Next-owner handoff:** T999 Parent after ACCEPT, otherwise a changed-hypothesis repair.

### T999 — Terminal lifecycle closeout

- **Objective and rationale:** Close goal-owned workers and state only after final acceptance.
- **Inputs and prerequisites:** T080 ACCEPT, child history, collaboration inventory, and installed inventory.
- **Deliverables:** ParentChildCloseoutReceipt, Terminal Lifecycle ready/confirm receipts, and done board.
- **Allowed files:** Goal board, plan status, closeout notes, and accepted final receipt.
- **Excluded files:** Product changes, provider calls, new scope, and unrelated task cleanup.
- **Dependencies and unlocks:** Depends on T080; unlocks none.
- **Parallel mode and write owner:** `serial`; Parent.
- **Implementation steps:** Enumerate, interrupt, archive, validate, mark done, run checkers, and confirm.
- **Validation commands:** Official checker, stop checker, plan renderer/validator, and fresh child inventory.
- **Acceptance evidence:** `full_outcome_complete: true` with terminal lifecycle receipts.
- **Stop and escalation conditions:** Leave T999 active on incomplete cleanup or missing final proof.
- **Rollback or recovery:** Restore active T999 state if post-mutation confirmation fails.
- **Documentation obligations:** Record final changed files, commands, validation, assumptions, and risks.
- **Next-owner handoff:** Operator closeout.

## Validation Ladder

1. Focused adapter, configuration, routing, dispatch, and fan-out tests.
2. Consumer tests for configuration resolution, route selection, receipts, and package parity.
3. Repository validators and one full suite at frozen package scope.
4. Reversible local plugin installation and installed parity.
5. Real bounded provider tasks with fresh preflight and no fallback.
6. Independent Luna audit of the exact installed candidate and receipts.

## GoalBuddy-backed Terminal T999 Contract

T999 remains active until Parent enumerates goal-owned child history and the
live collaboration tree, interrupts active non-persistent children, archives
terminal non-persistent children, preserves only explicitly authorized
persistent sessions, and validates fresh post-cleanup inventory. Parent records
a `ParentChildCloseoutReceipt`, obtains Terminal Lifecycle `ready`, then sets
`goal.status: done`, clears `active_task`, runs the official and stop checkers,
and obtains Terminal Lifecycle `confirm`. Any failed cleanup leaves T999 active.

## Risks, Blockers, and Stop Conditions

- Runtime versions can drift. Bind the exact observed runtime and model.
- A generic transport must not become arbitrary shell execution.
- Usage can remain unknown when a provider does not emit counters.
- Grok remains blocked until effective isolation is proven.
- After two identical failures without a changed hypothesis, redesign the milestone.
- Never use source-only or mocked proof for installed acceptance.

## Change-Control Protocol

Record new paths, providers, transports, authority, or proof claims as a dated
plan and board revision. Validate both before continuing.

## Handover Notes

T010 selected the clean 1.0.3 release base. T020 added declarative exact-model
candidates over approved transports. T030 proved installed exact DeepSeek
execution. T040 proved installed automatic selection with no model or provider
argument. T060 proves explicit fan-out, including one successful installed
MiniMax lane and truthful DeepSeek and Grok timeout receipts. T050 proves one
guarded isolated write and bound rollback. T070 froze and installed 1.0.4,
proved source-stage-cache parity, and completed fresh installed automatic-read
and controlled-write journeys. The dirty main checkout remains unchanged.
Luna accepted the final candidate. Parent closed all goal-owned children.
T080 recorded the independent ACCEPT verdict. T999 recorded terminal child
inventory and the full-outcome closeout.
Newly unblocked: none.

## Roadmap-Return Contract

Return the accepted outcome, installed proof boundary, changed surfaces,
validation, provider receipts, independent audit, deferred production work,
and remaining risks. Do not edit another roadmap or AOL board.

## Decision and Progress History

| Date | Decision or transition | Evidence | Owner |
| --- | --- | --- | --- |
| 2026-08-28 | Selected clean 1.0.3 base and activated T020 | T010 receipt | Parent |
| 2026-08-28 | Accepted declarative exact-model candidates and activated T030 | T020 Worker receipt and 5 focused tests | Parent |
| 2026-08-28 | Accepted installed exact DeepSeek read-only execution and activated T040 | Installed T030 manifest and artifact | Parent |
| 2026-08-28 | Accepted installed automatic selection and activated T060 | Installed T040 manifest and artifact | Parent |
| 2026-08-28 | Accepted truthful installed fan-out and activated T050 | T060 Parent acceptance receipt | Parent |
| 2026-08-28 | Accepted installed controlled write and rollback and activated T070 | T050 Parent acceptance receipt | Parent |
| 2026-08-28 | Froze and installed 1.0.4 and activated T080 | T070 installed acceptance receipt | Parent |
| 2026-08-28 | Reopened T070 after Luna REVISE and ran final 1.0.4 fan-out | Three installed lane manifests and T070 fan-out acceptance | Parent |
| 2026-08-28 | Luna accepted the repaired installed 1.0.4 candidate and activated T999 | T080 independent Luna audit | Judge and Parent |
| 2026-08-28 | Reconciled terminal child inventory and closed the goal | T999 Parent closeout | Parent |
