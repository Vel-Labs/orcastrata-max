# <Implementation Plan Title>

Plan ID: `<plan-id>`
Plan Mode: `document_only`
Plan Lifecycle: `draft`
Execution Authority: `not_granted`
Roadmap Origin: `<roadmap path and item IDs, or standalone>`

## TL;DR

<Outcome, approach, proof, and largest known constraint.>

## Plan Identity and Lifecycle

- Owner: <operator>
- Audience: <implementers and reviewers>
- Created: <YYYY-MM-DD>
- Last updated: <YYYY-MM-DD>
- Source request: <durable source or concise request>
- Proof boundary: <local, installed, pushed, published, or complete>

## Selected Roadmap Sources

<Name every selected roadmap item and why the items share one oracle,
architecture boundary, and delivery sequence. Use `standalone` when no roadmap
item exists.>

## Current Task

<!-- codexmax-current-task:start -->
No active task. This document-only plan has not created execution state.
<!-- codexmax-current-task:end -->

## Phase-To-Milestone Hierarchy

- Parent phase: <Parent task id and phase outcome>
- Child board: <depth-one child board path, or not applicable>
- Child milestones: <ordered milestone ids and outcomes>
- Active milestone: <exactly one milestone id, or none before execution>
- Split triggers: <material gates, independent outcomes, ownership changes, or
  validation boundaries that forbid one flat mega-task or giga-task>
- Dependencies: <milestone dependency order>
- Independently useful outcomes: <usable result produced by each milestone>

Use the Parent task as a phase container. Put bounded executable milestones in
one depth-one child board. Do not create child `T999` tasks. Reserve terminal
`T999` for Parent/PM lifecycle closeout.

## High-Level Task Ledger

<!-- codexmax-task-ledger:start -->
| ID | Task | Status | Depends on | Unlocks | Parallel mode | Write owner | Gate/proof | Receipt |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T001 | <First vertical slice> | planned | — | T002 | serial | <owner> | <proof> | — |
| T002 | <Independent verification> | planned | T001 | — | independent_gate | <owner> | <proof> | — |
<!-- codexmax-task-ledger:end -->

## Objective and Acceptance Oracle

### Objective

<Observable product or system outcome.>

### Acceptance Oracle

<Evidence that proves the selected feature works.>

## Current-State Assessment

<Observed implementation, seams, accepted artifacts, gaps, and likely misfire.>

## Scope and Non-Goals

### In Scope

- <bounded implementation area>

### Non-Goals

- <explicit exclusion>

## Implementation Architecture and Data Flow

<Components, interfaces, state transitions, authority boundaries, and data
flow.>

## Critical Path and Parallel Waves

- Critical path: T001 -> T002
- Parallel waves: <safe read-only, disjoint-write, tandem, or gate groups>
- Serialized ownership: <files or components with one writer>

## Progressive Phases and Gates

<Parent phase order, child milestones, entry conditions, exit gates, blockers,
and external decisions. Keep one milestone active unless the accepted board
contract permits safe parallel work.>

## Detailed Task Contracts

### T001 — <First vertical slice>

- **Objective and rationale:** <why this task exists>
- **Inputs and prerequisites:** <durable inputs>
- **Deliverables:** <artifacts or behavior>
- **Allowed files:** <bounded paths>
- **Excluded files:** <forbidden paths>
- **Dependencies and unlocks:** depends on none; unlocks T002
- **Parallel mode and write owner:** `serial`; <owner>
- **Implementation steps:** <decision-complete steps>
- **Validation commands:** <exact commands or review>
- **Acceptance evidence:** <receipt or proof>
- **Stop and escalation conditions:** <named conditions>
- **Rollback or recovery:** <recovery action>
- **Documentation obligations:** <docs and records>
- **Next-owner handoff:** <next task and owner>

### T002 — <Independent verification>

- **Objective and rationale:** <why this task exists>
- **Inputs and prerequisites:** <durable inputs>
- **Deliverables:** <artifacts or behavior>
- **Allowed files:** <bounded paths>
- **Excluded files:** <forbidden paths>
- **Dependencies and unlocks:** depends on T001; unlocks none
- **Parallel mode and write owner:** `independent_gate`; <owner>
- **Implementation steps:** <decision-complete steps>
- **Validation commands:** <exact commands or review>
- **Acceptance evidence:** <receipt or proof>
- **Stop and escalation conditions:** <named conditions>
- **Rollback or recovery:** <recovery action>
- **Documentation obligations:** <docs and records>
- **Next-owner handoff:** <closeout or successor>

## Validation Ladder

1. <focused validation>
2. <repository validation>
3. <independent verification>

## GoalBuddy-backed Terminal T999 Contract

When Plan Mode creates or updates GoalBuddy execution state, reserve terminal
`T999` for Parent/PM lifecycle closeout after the final independent audit. Its
contract must require:

- complete Parent-history pagination and opaque descendant-ID inventory;
- fresh live collaboration inventory;
- interrupt of every active non-persistent child before archive;
- archive of every terminal non-persistent child thread;
- explicit authority for every retained persistent session;
- `ParentChildCloseoutReceipt` with `terminal_lifecycle_allowed: true` and
  `board_mutation_allowed: false`;
- Terminal Lifecycle `ready` before board mutation;
- `goal.status: done`, `active_task: null`, official checker, stop checker, and
  Terminal Lifecycle `confirm` after mutation.

Any failed or incomplete cleanup leaves `T999` active. The plan must never put
terminal cleanup after goal completion.

## Risks, Blockers, and Stop Conditions

- <risk, mitigation, and stop rule>

## Change-Control Protocol

Record new scope, tasks, paths, providers, authority, or proof requirements as a
dated revision. Revalidate the plan and board before execution continues.

## Handover Notes

<For every completed transition, record outcome, receipt, validation, newly
unblocked tasks, still-blocked tasks, next owner, and first action.>

## Roadmap-Return Contract

Return accepted outcome, proof boundary, changed surfaces, validation,
independent review, deferred work, remaining risks, and newly unlocked roadmap
items. Do not edit the roadmap without its owner's authority.

## Decision and Progress History

| Date | Decision or transition | Evidence | Owner |
| --- | --- | --- | --- |
| <YYYY-MM-DD> | Plan drafted | <path> | <owner> |
