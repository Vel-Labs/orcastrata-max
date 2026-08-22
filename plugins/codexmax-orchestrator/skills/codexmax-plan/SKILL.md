---
name: codexmax-plan
description: "Advanced planning — Interview the operator and compile a durable goal contract, acceptance oracle, constraints, and first execution packet."
---

# Codexmax Plan

## Guided Planning Boundary

Use this skill after the guided front door classifies work as `guided_plan`, or
when the operator explicitly requests planning. Read the
[Guided Journey Contract](../../assets/contracts/guided-journey.md). Planning
receives an ordinary-language outcome plus discovered repository and GoalBuddy
context; it must not request a user-authored goal, assignment, route, evidence,
validation, closeout, or other mega-prompt.

Recommend safe defaults. Ask zero questions when discovery and existing
authority determine the plan. Otherwise ask one to three questions at a time,
and only when an answer can change scope, proof, architecture, route authority,
risk, cost, or the first checkpoint. Preferences or implementation details that
cannot change one of those dimensions are non-material and must not be asked.

Before execution, return a concise
[Execution Preview](../../assets/templates/execution-preview.md) covering
outcome, scope and writes, external calls, billing and fallback, validation,
and stop rule. Reuse existing goal or checkpoint authority; pause only for new
or expanded authority. A previously authorized external route still requires a
fresh preflight for provider input, route health, billing, token cap, and
fallback before dispatch.

## Feature-Level Implementation Planning

Read the
[Implementation Planning Contract](../../assets/contracts/implementation-planning.md)
when the operator asks for an implementation plan, asks to plan a selected
feature or functionality in detail, or selects one or more roadmap items for
implementation. A roadmap selects outcomes; this skill specifies how one
selected outcome will be built and proved. Do not route a targeted feature back
through broad roadmap compilation merely because its source is a roadmap.

Use the
[Implementation Plan Template](../../assets/templates/implementation-plan.md).
Choose exactly one mode:

- `document_only` for bounded work that does not need persistent execution
  state;
- `board_prepared` when the plan spans sessions, has four or more tasks, uses
  gates, parallel or tandem lanes, external constraints, persistent handoffs,
  GoalBuddy, or `/goal`;
- `execution_authorized` only when the operator has explicitly authorized
  execution within the recorded scope.

Multiple roadmap items belong in one implementation plan only when they share
one acceptance oracle, architecture boundary, and delivery sequence. Otherwise
split them. Preserve roadmap provenance and return accepted evidence to the
roadmap owner at closeout; never silently edit or complete the roadmap.

## Method

1. Read discovered repository rules, GoalBuddy state, accepted artifacts,
   current proof boundary, and effective config provenance.
2. Interpret the requested outcome and likely misfire.
3. Ask only material questions, one to three at a time, or ask none when safe
   defaults suffice.
4. Record scope, non-goals, authority, budgets, provider permissions, and proof.
5. Define an observable acceptance oracle.
6. Define the first bounded tranche and its stop conditions.
7. Compile a dependency DAG and identify safe parallel groups.
8. For implementation planning, select the adaptive output mode, compile the
   standalone Markdown plan, and add GoalBuddy state only when the contract's
   board criteria apply.
9. Validate the plan with
   `../../scripts/validate_implementation_plan.py`; a board-backed plan must
   also pass the official GoalBuddy checker before execution or a clean
   transition is claimed.
10. Present the concise execution preview before execution unless the user already
   explicitly approved the supplied plan.
11. Generate the detailed goal, assignment, route, evidence, validation, and
   closeout artifacts internally after preview and authority gates.

Planning is not completion. The output must be usable by a fresh Supervisor
without private reasoning or transcript reconstruction.

## Required Contract Fields

Every durable plan or checkpoint contract records:

- goal id, checkpoint id, source prompt or board path, and active date;
- owner outcome, audience, current state, and likely misfire;
- acceptance oracle with observable proof, not intent or confidence;
- in-scope files, out-of-scope files, forbidden actions, and credential or
  network limits;
- authority boundary between human, parent Codex, Supervisor, PM, Worker,
  Tester, Documenter, and Auditor;
- provider permissions, billing policy, quota policy, fallback policy, and
  model lanes allowed;
- validation ladder, independent verification requirement, and proof boundary;
- stop rule for time, token, cost, attempt, or external dependency limits;
- closeout path, result template, and required evidence language.

Implementation plans additionally record:

- plan id, `document_only | board_prepared | execution_authorized`, lifecycle,
  execution authority, and roadmap origin;
- TL;DR, current task, current-state assessment, architecture and data flow;
- critical path, dependencies, downstream unlocks, progressive phases, and
  gates;
- task status, `serial | parallel_read_only | parallel_disjoint_write |
  tandem_handoff | independent_gate`, and explicit write owner;
- rollback or recovery, documentation obligation, next-owner handoff, and
  roadmap-return contract.

Parallel writes require explicit non-overlapping ownership. Otherwise retain
one writer. For a board-backed plan, use only GoalBuddy's canonical task statuses
`queued`, `active`, `blocked`, and `done`; never write `completed` as a
board or ledger status.

## Input Access Planning

Use the [Provider Task Input Contract](../../assets/contracts/provider-task-input.md)
for every source-backed lane. Record durably:

- named source categories, source labels, required/optional status, and the
  expected `source_basis` for material claims;
- `required_source_access`, expected `source_access`, and `input_delivery`,
  including per-category modes when either mode is `mixed`;
- whether source-backed claims and commands are required, whether command
  execution is available, and the required result read receipt;
- the route owner that computes the pre-dispatch compatibility decision and
  reason; and
- every unresolved access, delivery, command, fact-pack, or receipt capability
  as `unknown`, with its revision, reassignment, or resolution owner.

A provider name, role hypothesis, path listing, or prior successful run does
not resolve capability information. Unknown required capability remains visible
in the plan and cannot be treated as a compatible assignment.

## Question Discipline

Ask a question only when the answer could change scope, proof, architecture,
provider routing, risk, cost, or the first checkpoint. Prefer option-backed
questions with a recommended option, a conservative alternative, an ambitious
option, and a free-form path when the operator interface supports it.

Ask zero questions when safe defaults and discovered authority suffice. Never
ask the operator for orchestration jargon, packet fields, or a full internal
prompt. One round contains no more than three questions.

If execution is already explicitly approved, record unresolved details as
`Assumption:`, `Deferred:`, or `Blocker:` and continue only when the assumption
does not change a hard boundary.

## Fresh-Supervisor Readiness

The plan is ready for `$codexmax-orchestrator:codexmax-assignment` only when a fresh Supervisor can
answer these without chat history:

- what to read first;
- what may be changed;
- which routes are preferred and which fallbacks are allowed;
- what commands prove or disprove the checkpoint;
- where Worker and closeout artifacts must be written;
- when to revise, reassign, repair in parent, or wait externally.

## Plan Projection And Existing Plans

GoalBuddy remains machine truth. The Markdown current-task and task-ledger
regions are bounded human-facing projections. After a GoalBuddy owner
transition, run the official checker, then use
`../../scripts/render_implementation_plan_status.py` to update only those
regions, add the receipt and handover, and rerun the implementation-plan
validator. Generate operator status from the validated files, not chat memory.

Audit existing implementation plans without rewriting them. Return exact
structural, canonical-status, dependency, receipt, current-task, and handover
gaps. Repair requires separate explicit authority.
