# Orcastrata Native Interface V1 Implementation Plan

Plan ID: `orcastrata-native-interface-v1`
Plan Mode: `execution_authorized`
Plan Lifecycle: `done`
Execution Authority: `granted`
Roadmap Origin: `standalone user request`

## TL;DR

Expose the ten existing Orcastrata workflows as native
`/orcastrata-(task)` command TOML files. Add one read-only plugin hook program
for session and subagent context. Preserve all existing skills and runtime
services. Prove the installed command and hook surfaces in an isolated Codex
home. The main constraint is hook trust: source and package proof do not prove
activation until the installed plugin hash is trusted.

## Plan Identity and Lifecycle

- Owner: Parent/PM
- Audience: Orcastrata maintainers and operators
- Created: 2026-09-01
- Last updated: 2026-09-01
- Source request: current Codex task and `goal.md`
- Proof boundary: isolated clean installation and fresh supported hook event

## Selected Roadmap Sources

Standalone. The work shares one oracle and one plugin boundary: expose the
accepted Orcastrata runtime through native Codex controls without adding a new
runtime.

## Current Task

<!-- codexmax-current-task:start -->
No active task. T999 accepted the final candidate and closed the board.
<!-- codexmax-current-task:end -->

## Phase-To-Milestone Hierarchy

- Parent phase: current visible Codex task owns integration and acceptance.
- Child board: `docs/goals/orcastrata-native-interface-v1/state.yaml`.
- Child milestones: T010 plan; T020 adversarial review; T030 implementation;
  T040 acceptance; T999 lifecycle closeout.
- Active milestone: none; the board is complete.
- Split triggers: provider review is read-only; implementation has one writer;
  installed acceptance follows the candidate freeze.
- Dependencies: T010 -> T020 -> T030 -> T040 -> T999.
- Independently useful outcomes: a validated plan, review evidence, a package
  candidate, installation proof, and a terminal receipt.

## High-Level Task Ledger

<!-- codexmax-task-ledger:start -->
| ID | Task | Status | Depends on | Unlocks | Parallel mode | Write owner | Gate/proof | Receipt |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T010 | Freeze the implementation plan | done | — | T020 | serial | Parent/PM | Plan and board validators pass | Validated plan and board |
| T020 | Exact three-lane adversarial review | done | T010 | T030 | parallel_read_only | External reviewers | Exact route receipts or truthful rejection | MiniMax review; Grok rejection; DeepSeek timeout |
| T030 | Implement native commands and hooks | done | T020 | T040 | serial | Parent/PM | Focused command and hook tests pass | Focused tests and source parity pass |
| T040 | Audit package and installed behavior | done | T030 | T999 | independent_gate | Parent/PM | Package, isolated install, and fresh hook proof | Installed 1.2.0 acceptance passed |
| T999 | Close Parent lifecycle | done | T040 | — | serial | Parent/PM | Terminal lifecycle and GoalBuddy checks pass | Zero-active-child closeout receipt |
<!-- codexmax-task-ledger:end -->

## Objective and Acceptance Oracle

### Objective

Give operators a consistent native command family and automatic PM context for
the existing Orcastrata runtime.

### Acceptance Oracle

An isolated installed plugin exposes these commands:

- `/orcastrata-orchestrate`
- `/orcastrata-discover`
- `/orcastrata-plan`
- `/orcastrata-route`
- `/orcastrata-assignment`
- `/orcastrata-supervise`
- `/orcastrata-audit`
- `/orcastrata-closeout`
- `/orcastrata-config`
- `/orcastrata-loop`

Each command delegates to its existing skill. A fresh `SessionStart` and
`SubagentStart` hook returns concise `additionalContext`. It does not mutate a
board, call a provider, schedule work, or copy repository context.

## Current-State Assessment

The plugin already has accepted skills, automatic routing, exact routing,
fan-out, supervision, verification, closeout, GoalBuddy, and WorkGraph
contracts. Its manifest has no live hook entry. The existing
`codex_loop_hook.py` is a source-fixture adapter with `installed: false`; it is
not the correct place for operator context. The installed Ponytail package
proves the current native pattern: top-level `commands/*.toml`, a manifest
`hooks` path, and lifecycle hook JSON. Reuse that platform shape.

## Scope and Non-Goals

### In Scope

- Thin native TOML aliases for existing public skills.
- One plugin hook JSON file and `hooks/orcastrata_context.py`.
- Session and subagent PM guidance with strict output bounds.
- Manifest, operator docs, focused tests, package parity, and isolated install.

### Non-Goals

- No new orchestrator, issue tracker, scheduler, agent runtime, or merge bot.
- No automatic GitHub issue or PR mutation.
- No prompt parser for slash aliases.
- No rename or removal of existing `codexmax-*` skills.
- No AOL integration in this tranche.

## Implementation Architecture and Data Flow

Native command TOML -> existing `$codexmax-orchestrator:codexmax-*` skill ->
existing Orcastrata services. Plugin lifecycle event -> one hook program ->
bounded `additionalContext` for the Parent or delegated agent. GoalBuddy stays
the execution ledger. WorkGraph stays the dependency model. The Parent remains
the only merge and acceptance owner.

## Critical Path and Parallel Waves

- Critical path: T010 -> T020 -> T030 -> T040 -> T999.
- Parallel waves: the three T020 provider lanes use the same frozen candidate
  and rubric and may run independently.
- Serialized ownership: manifest, commands, hooks, docs, tests, and board state
  have one Parent writer.

## Progressive Phases and Gates

T010 ends only when both validators pass. T020 ends after every exact lane has
one completed receipt or one truthful rejection; no model substitution is
allowed. T030 starts from the revised frozen plan and ends on focused tests.
T040 starts from one frozen package candidate and proves source, package,
installation, native command discovery, and hook output. T999 starts after the
final audit and owns terminal cleanup and board mutation.

## Detailed Task Contracts

### T010 — Freeze the implementation plan

- **Objective and rationale:** Define the smallest decision-complete change before code or provider review.
- **Inputs and prerequisites:** Current plugin manifest, skills, source-only loop adapter, installed Ponytail command and hook pattern, current Codex documentation.
- **Deliverables:** This plan, goal contract, and valid board state.
- **Allowed files:** `docs/goals/orcastrata-native-interface-v1/`.
- **Excluded files:** All plugin source and installed Codex state.
- **Dependencies and unlocks:** Depends on none; unlocks T020.
- **Parallel mode and write owner:** `serial`; Parent/PM.
- **Implementation steps:** Record command set, hook events, compatibility boundary, validation ladder, and stop rules; run both validators.
- **Validation commands:** `validate_implementation_plan.py` and official `check-goal-state.mjs`.
- **Acceptance evidence:** Validator JSON with `status: valid` and GoalBuddy `ok: true`.
- **Stop and escalation conditions:** Stop if the native command surface cannot be proved from an installed current plugin pattern.
- **Rollback or recovery:** Remove only this new goal directory before any dependent work.
- **Documentation obligations:** Keep this file as the single canonical plan and handoff record.
- **Next-owner handoff:** Parent advances T020 with the frozen plan digest.

### T020 — Exact three-lane adversarial review

- **Objective and rationale:** Challenge architecture, context growth, command semantics, hook safety, and proof quality before code.
- **Inputs and prerequisites:** Valid T010 plan and one frozen candidate/prompt/rubric.
- **Deliverables:** Exact MiniMax-M3, Grok 4.6, and DeepSeek V4 Pro receipts or truthful route rejections, plus Parent synthesis.
- **Allowed files:** `docs/goals/orcastrata-native-interface-v1/notes/adversarial/` and this plan.
- **Excluded files:** Plugin implementation and provider credentials.
- **Dependencies and unlocks:** Depends on T010; unlocks T030.
- **Parallel mode and write owner:** `parallel_read_only`; providers advise, Parent alone records synthesis.
- **Implementation steps:** Run one no-retry lane per exact model; inspect outputs; accept only cited, applicable findings; revise this plan once.
- **Validation commands:** `run_adversarial_provider_fanout.py` with exact requests and `--allow-provider-call`.
- **Acceptance evidence:** Aggregate receipt, lane artifacts, and a dated decision-history entry.
- **Stop and escalation conditions:** Record route failure without substitution; proceed if at least one valid review exists, or Parent performs the review if all exact lanes reject.
- **Rollback or recovery:** Provider output remains evidence only and cannot mutate source.
- **Documentation obligations:** Record agreement, disagreement, rejected advice, and changed decisions.
- **Next-owner handoff:** Parent freezes the revised plan and advances T030.

### T030 — Implement native commands and hooks

- **Objective and rationale:** Add the operator surface at the native plugin boundary while reusing existing runtime behavior.
- **Inputs and prerequisites:** Accepted T020 synthesis and unchanged existing skills.
- **Deliverables:** Ten command TOMLs, hook JSON, `hooks/orcastrata_context.py`, manifest wiring, concise docs, and focused tests.
- **Allowed files:** `plugins/codexmax-orchestrator/.codex-plugin/plugin.json`; `plugins/codexmax-orchestrator/.codex-plugin/release-manifest.json`; `plugins/codexmax-orchestrator/CHANGELOG.md`; `plugins/codexmax-orchestrator/commands/`; `plugins/codexmax-orchestrator/hooks/`; `plugins/codexmax-orchestrator/assets/contracts/codex-loop-hooks.md`; `plugins/codexmax-orchestrator/README.md`; `plugins/codexmax-orchestrator/GETTING_STARTED.md`; `plugins/codexmax-orchestrator/scripts/verify_release_parity.py`; focused `tests/` files.
- **Excluded files:** Existing routing, provider, GoalBuddy, WorkGraph, scheduler, and write-guard implementations.
- **Dependencies and unlocks:** Depends on T020; unlocks T040.
- **Parallel mode and write owner:** `serial`; Parent/PM.
- **Implementation steps:** Add thin command prompts; assert exactly one existing skill token per command; add manifest hook path; implement event-specific bounded context with stdlib JSON I/O in `hooks/orcastrata_context.py`; document static, installed, trusted, and live proof separately; add one focused test module.
- **Validation commands:** Focused unit tests for command inventory, skill targets, hook input/output, bounds, and non-mutation.
- **Acceptance evidence:** Focused green receipt and scoped diff.
- **Stop and escalation conditions:** Stop if a command needs duplicated workflow logic or a hook needs repository reads, provider calls, or board writes.
- **Rollback or recovery:** Revert the added command and hook files and the manifest/docs lines as one bounded diff.
- **Documentation obligations:** Replace the obsolete “no live hook” claim and list exact commands and trust behavior.
- **Next-owner handoff:** Parent freezes the package candidate for T040.

### T040 — Audit package and installed behavior

- **Objective and rationale:** Prove the user-visible surface, not only source shape.
- **Inputs and prerequisites:** Frozen T030 candidate and focused green tests.
- **Deliverables:** Package parity, isolated installation, command discovery, fresh hook output, and independent verdict.
- **Allowed files:** Read-only repository plus task-owned evidence under the goal directory; isolated temporary Codex home.
- **Excluded files:** User Codex home, dirty main checkout, network publication, and production configuration.
- **Dependencies and unlocks:** Depends on T030; unlocks T999.
- **Parallel mode and write owner:** `independent_gate`; Parent/PM audit after implementation freeze.
- **Implementation steps:** Run package checks; stage/install in an isolated home; inspect discovered commands; invoke the hook with real event JSON; if the host supports a fresh local task canary, run it after trust is explicit.
- **Validation commands:** Focused tests, package validator, isolated install command, command inventory check, and hook subprocess canary.
- **Acceptance evidence:** One final acceptance receipt that distinguishes source, package, installed, trusted, and fresh-session proof.
- **Stop and escalation conditions:** Do not claim live activation if host trust cannot be completed in the isolated environment.
- **Rollback or recovery:** Delete only the task-owned temporary installation after recording deterministic evidence.
- **Documentation obligations:** Record exact commands, candidate identity, results, skipped proof, and residual risk.
- **Next-owner handoff:** Parent advances T999 only on ACCEPT.

### T999 — Close Parent lifecycle

- **Objective and rationale:** Integrate the final audit and close execution state without orphaned agents or an inaccurate board.
- **Inputs and prerequisites:** Accepted T040 audit and complete task receipts.
- **Deliverables:** ParentChildCloseoutReceipt, final board state, and final user handoff.
- **Allowed files:** This goal directory.
- **Excluded files:** Plugin implementation after the accepted candidate freeze.
- **Dependencies and unlocks:** Depends on T040; unlocks none.
- **Parallel mode and write owner:** `serial`; Parent/PM.
- **Implementation steps:** Enumerate child history and live agents; interrupt active non-persistent children; archive terminal non-persistent child tasks when applicable; confirm terminal readiness; set all receipts, `goal.status: done`, and `active_task: null`; rerun official and stop checks.
- **Validation commands:** Official GoalBuddy checker, stop checker when present, and terminal lifecycle confirm.
- **Acceptance evidence:** Terminal lifecycle receipt with `terminal_lifecycle_allowed: true`, final audit `decision: complete`, and green final validators.
- **Stop and escalation conditions:** Leave T999 active if any child identity, cleanup, receipt, or final check is incomplete.
- **Rollback or recovery:** Restore T999 to active and the goal to active if final validation fails.
- **Documentation obligations:** Record final outcome, changed files, commands, results, assumptions, and remaining risks once.
- **Next-owner handoff:** Return the accepted result to the user; AOL adoption remains a separate decision.

## Validation Ladder

1. Plan and GoalBuddy structural validation.
2. Focused command and hook behavior tests.
3. Consumer/package parity checks for changed plugin surfaces.
4. Isolated clean installation and native command inventory.
5. Fresh trusted hook canary when the local host exposes the required trust step.
6. Final independent Parent audit and terminal board checks.

## GoalBuddy-backed Terminal T999 Contract

T999 owns complete Parent-history pagination, opaque descendant-ID inventory,
fresh collaboration inventory, active non-persistent child interruption,
terminal non-persistent child archival, explicit authority for retained
persistent sessions, and a `ParentChildCloseoutReceipt`. Terminal Lifecycle
must report `ready` before board mutation and `confirm` afterward. Any incomplete
cleanup leaves T999 active.

## Risks, Blockers, and Stop Conditions

- Hooks add context every session. Keep output static, event-specific, and well
  below the platform spill threshold.
- Hook trust is hash-bound. Package or source proof is not activation proof.
- Command files are aliases. A command that duplicates workflow policy fails
  the design rule.
- Existing skill IDs are compatibility API and remain unchanged.
- External model identity, usage, or completion remains `unknown` unless the
  route receipt proves it.

## Change-Control Protocol

Record any new command, hook event, provider, source path, authority, or proof
requirement as a dated plan revision. Revalidate the plan and board before
implementation continues.

## Handover Notes

T010 and T020 are complete. MiniMax-M3 returned REVISE with 672 input tokens,
806 output tokens, and 128 cache-read tokens. Grok was not called because exact
identity was unverifiable. DeepSeek Pro was called once and timed out at 300
seconds; tokens and cost remain unknown. The Parent accepted exact skill-token
tests, a named hook program, and explicit separation of static, installed,
trusted, and live proof. The Parent rejected MiniMax's claim that concise
normative hook context is a second runtime: Codex hooks are the native context
boundary, and they perform no routing, mutation, or acceptance action. Newly unblocked:
T030. T030 completed with focused tests and 1.2.0 source-package parity. Newly
unblocked: T040. T040 accepted the isolated 1.2.0 install, 404-file cache
parity, ten-command inventory, and installed hook subprocess. Newly unblocked:
T999. T999 completed. The live collaboration inventory contained only the
Parent plus two completed pre-goal Ponytail research agents; no active child
required interruption and this board created no addressable child task. All
milestones are done. Newly unblocked: none.

## Roadmap-Return Contract

Return the accepted command set, hook behavior, compatibility boundary,
validation proof, external-review synthesis, deferred AOL work, and remaining
risk. Do not edit an AOL roadmap in this goal.

## Decision and Progress History

| Date | Decision or transition | Evidence | Owner |
| --- | --- | --- | --- |
| 2026-09-01 | Plan drafted with native TOML aliases and one bounded hook program | Installed Ponytail plugin pattern, current Orcastrata manifest and contracts | Parent/PM |
| 2026-09-01 | T010 accepted; T020 activated | Codexmax plan validator `status: valid`; GoalBuddy `ok: true` | Parent/PM |
| 2026-09-01 | T020 reviewed; plan revised; T030 activated | MiniMax-M3 REVISE; Grok identity rejection; DeepSeek Pro timeout | Parent/PM |
| 2026-09-01 | Added the 1.2.0 release identity to T030 | Native commands and hooks are a new public feature; 1.1.1 cannot identify the changed package | Parent/PM |
| 2026-09-01 | T030 accepted; T040 activated | Focused native-interface tests and 1.2.0 source parity passed | Parent/PM |
| 2026-09-01 | T040 accepted; T999 activated | Isolated plugin-manager install, package cache parity, ten commands, installed hook output | Parent/PM |
| 2026-09-01 | Added `/orcastrata-assignment` during final scope audit | Every existing public workflow now has one prefixed native command | Parent/PM |
| 2026-09-01 | T999 completed; board closed | Zero-active-child inventory and final GoalBuddy validation | Parent/PM |
