# Orcastrata Standalone GitHub Umbrella Workflow V1

Plan ID: `orcastrata-aol-github-umbrella-v1`
Plan Mode: `execution_authorized`
Plan Lifecycle: `accepted`
Execution Authority: `granted`
Roadmap Origin: `standalone open-source Orcastrata request`

## TL;DR

Orcastrata will run the GitHub umbrella workflow as an independent open-source
feature. It will use the local authenticated `gh` CLI through a fixed-argument,
credential-blind adapter. Existing GoalBuddy and WorkGraph contracts remain the
durable execution truth. GitHub is a synchronized work surface. AOL is not a
runtime dependency. The operator authorized the exact repository execution path
through terminal closeout, subject to the frozen identity, scope, audit, and
merge gates in this plan.

## Plan Identity and Lifecycle

- Owner: Parent/PM
- Audience: Orcastrata implementers, reviewers, and operators
- Created: 2026-09-01
- Last updated: 2026-09-02
- Source request: current Codex task and sibling `goal.md`
- Proof boundary: T050A is accepted locally; T050B through T999 has standing
  authority for `github.com/Vel-Labs/orcastrata-max` only

The stable Plan ID retains the earlier `aol` term for provenance. It does not
mean AOL owns this implementation board.

## Standing Execution Authority

The 2026-09-02 operator grant authorizes T050B through T999 only for
`github.com/Vel-Labs/orcastrata-max`. Before the first write, Orcastrata must
record the active local `gh` username and confirm `WRITE` or `ADMIN` permission
for that exact repository. It must not inspect, expose, refresh, or replace
credentials.

The grant covers Orcastrata-managed issues, labels, bodies, necessary comments,
local branches, exact commits, non-force pushes, board-created pull requests,
bounded native Codex workers, repair of those pull requests, read-only audits,
one-at-a-time guarded merges, isolated package installation, full validation,
standalone dogfood, and board closeout. It does not cover auto-merge, force push,
history rewriting, arbitrary `gh` commands, external providers, schedules,
deployments, release publication, repository settings, secrets, AOL source,
another repository, or unrelated issues and pull requests. An unknown external
outcome must be reconciled before retry.

## Selected Roadmap Sources

Standalone successor to Orcastrata Native Interface V1. All tasks share the
standalone Orcastrata runtime, one test-repository oracle, and one delivery
sequence. The separate AOL handoff is not an implementation task on this board.

## Current Task

<!-- codexmax-current-task:start -->
T080 is active. T070 passed focused, package, live read, and independent-audit
gates. PR #12 remains open and unmerged. T080 now adds the narrow guarded-merge
effect and must re-read every merge gate at the current head before any effect.
Credentials, other repositories, AOL source, external providers,
schedules, deployments, release publication, auto-merge, force push, history
rewriting, and repository settings remain forbidden.
<!-- codexmax-current-task:end -->

## Phase-To-Milestone Hierarchy

- Parent phase: the visible Parent owns plan integration and final acceptance.
- Child board: `docs/goals/orcastrata-aol-github-umbrella-v1/state.yaml`.
- Child milestones: T010 plan; T020 admission; T030 reads; T040 umbrella state;
  T050 issues; T060 workers and PRs; T070 audit-full; T080 guarded merge; T090
  dogfood acceptance; T999 closeout.
- Active milestone: T080.
- Split triggers: credentials, a second transport, schedules, default merge,
  AOL implementation, or any cross-repository write.
- Dependencies: T010 -> T020 -> T030 -> T040 -> T050 -> T060 and T070 -> T080 -> T090 -> T999.
- Independently useful outcomes: read-only GitHub reuse, umbrella preview,
  synchronized issues, bounded PR execution, umbrella audit, and guarded merge.

## High-Level Task Ledger

<!-- codexmax-task-ledger:start -->
| ID | Task | Status | Depends on | Unlocks | Parallel mode | Write owner | Gate/proof | Receipt |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T010 | Review and correct the standalone plan | done | — | T020 | parallel_read_only | Parent/PM | Plan and board valid; provider evidence retained | Adversarial receipt and operator correction |
| T020 | Operator implementation admission | done | T010 | T030 | serial | Parent/PM | T030 source and read-only local authority accepted | Operator proceed instruction |
| T030 | Local `gh` capability and reads | done | T020 | T040 | serial | Orcastrata implementer | Credential-blind fake and real read proof | `t030-live-read-receipt.json` |
| T040 | Umbrella state and projection | done | T030 | T050 | serial | Orcastrata implementer | WorkGraph and GoalBuddy round-trip proof | `t040-projection-receipt.json` |
| T050 | Issue creation and reconciliation | done | T040 | T060, T070 | serial | Orcastrata implementer | T050A local fake-`gh`; exact-repository T050B canary and reconciliation | `t050a-local-simulation-receipt.json`; `t050b-execution-receipt.json` |
| T060 | Bounded workers and PR lifecycle | done | T050 | T080 | parallel_disjoint_write | One worker per owned branch and path set | PR lifecycle receipts | `t060-pr-lifecycle-receipt.json` |
| T070 | Scoped audit and audit-full | done | T050 | T080 | independent_gate | Independent auditor | Read-only typed verdicts | `t070-audit-full-receipt.json` |
| T080 | Explicit guarded merge | active | T060, T070 | T090 | serial | Orcastrata effect executor | Standing operator grant plus fresh per-PR gates | — |
| T090 | Standalone dogfood acceptance | queued | T080 | T999 | independent_gate | Independent auditor | Package, security, and end-to-end proof | — |
| T999 | Parent lifecycle closeout | queued | T090 | — | serial | Parent/PM | Terminal lifecycle and final checks | — |
<!-- codexmax-task-ledger:end -->

## Objective and Acceptance Oracle

### Objective

Let an Orcastrata operator turn one approved outcome into an umbrella issue and
dependency graph, create and reconcile GitHub issues, run bounded workers for
ready issues, monitor and repair PRs, audit the complete result, and optionally
perform one explicitly confirmed guarded merge.

### Acceptance Oracle

One authorized test repository must prove all of these behaviors:

1. The operator supplies the exact GitHub host and `owner/repository`.
2. Orcastrata checks `gh` readiness without reading or storing a token.
3. GoalBuddy owns accepted board state. WorkGraph describes dependency work.
4. Preview precedes every issue mutation. Repeated requests do not duplicate issues.
5. Reconciliation records GitHub state without silently replacing local acceptance truth.
6. Each worker receives one bounded issue packet and owns one branch and path set.
7. PR monitoring can route repair but cannot merge.
8. `/orcastrata-audit` keeps its current semantics. `/orcastrata-audit-full`
   returns a separate read-only umbrella verdict.
9. Merge is optional, covered by the standing grant, and bound to fresh checks, reviews,
   conflict state, issue acceptance, head/base SHAs, and audit receipts.
10. Each external effect has a prepare record, stable idempotency key,
    before/after observation, and recovery status.

## Current-State Assessment

- Orcastrata already has native commands, hooks, routing, GoalBuddy, WorkGraph,
  execution events, and receipts. Reuse these surfaces.
- The standalone GoalBuddy facade already exposes closed capability, snapshot,
  apply, and recovery operations. It does not grant authority.
- GitHub automation and `/orcastrata-audit-full` do not exist in the current
  candidate.
- Local `gh` authentication is available as a host capability. Authentication
  is readiness evidence, not permission to write.
- The likely misfire is a new generic orchestration or connector layer. One
  narrow `gh` path is sufficient for V1.

## Scope and Non-Goals

### In Scope

- Credential-blind local `gh` discovery and a closed operation set.
- Existing GoalBuddy and WorkGraph integration for umbrella and dependency state.
- Issue create/reconcile, bounded worker and PR lifecycle, scoped audit,
  audit-full, and optional explicit merge.
- Token, latency, correction, and accepted-outcome measurements where the
  runtime reports them. Missing counters stay `unknown`.

### Non-Goals

- No AOL dependency or AOL source change.
- No token scraping, `gh auth token`, credential-file access, or shell interpolation.
- No GitHub-only canonical board and no direct mutation from hooks.
- No new OAuth client, generic transport framework, scheduler, hourly babysitter,
  GitHub auto-merge, or default autonomous merge in V1.
- No Graph Engineering ownership of execution. It can index accepted artifacts later.

## Implementation Architecture and Data Flow

```text
operator-approved outcome and repository
  -> Orcastrata plan and WorkGraph
  -> GoalBuddy accepted board state
  -> deterministic GitHub projection preview
  -> explicit operator action authority
  -> fixed-argv local gh operation
  -> GitHub issue or PR observation
  -> reconciliation and immutable receipt
  -> dependency-ready bounded worker
  -> owned branch and PR
  -> PR monitor and bounded repair
  -> scoped audit plus /orcastrata-audit-full
  -> optional fresh standing-authority guarded merge
  -> final receipts and GoalBuddy acceptance
```

The adapter accepts only typed operations. T030 includes `probeCapability`,
`readRepository`, `listIssues`, `readIssue`, `readPullRequest`,
`listPullRequestChecks`, and `readPullRequestDiffSummary`. It contains no write
symbol. Resolve the trusted `gh` executable once per run. Use argument arrays,
minimum JSON fields, bounded output, and redacted diagnostics. The operator,
not Git remotes, supplies repository authority. Allow `gh` to use its own
credential store, but never inspect that store from Orcastrata.

Before a later effect, persist a prepare record. Derive stable effect identity
from the Orcastrata project or board ID, child work ID, repository, and operation
kind. Do not include mutable revision data. Pin transport after prepare. An
unknown effect outcome blocks retry until reconciliation reports applied or not
applied.

Worker packets contain one issue contract, dependency receipts, repository
rules, owned branch, allowed paths, and validation commands. Before push, check
the branch ref, reject force push, and compare the complete diff path set with
the packet. Hooks can observe and route. They cannot create GitHub effects.

## Critical Path and Parallel Waves

- Critical path: T010 -> T020 -> T030 -> T040 -> T050 -> T060 -> T080 -> T090 -> T999.
- Audit path: T050 -> T070 -> T080.
- Parallel waves: T060 workers may run only for ready issues with disjoint
  branches and path sets. T070 stays read-only and independent.
- Serialized ownership: shared schemas, GoalBuddy transitions, integration
  branches, GitHub effects, merge, and final acceptance.

## Progressive Phases and Gates

1. Validate the corrected plan and retain review provenance.
2. Obtain exact operator authority for one implementation tranche.
3. Prove read-only `gh` behavior before adding write operations.
4. Prove umbrella projection through existing GoalBuddy and WorkGraph contracts.
5. Prove one idempotent issue-write canary in an authorized test repository.
6. Prove bounded issue-to-PR execution without merge authority.
7. Prove independent scoped and umbrella audits.
8. Prove one explicit guarded merge and unknown-outcome recovery.
9. Run package, security, consumer, and standalone end-to-end acceptance.
10. Complete Parent lifecycle closeout.

## Detailed Task Contracts

### T010 — Review and correct the standalone plan

- **Objective and rationale:** Preserve the useful adversarial findings and separate open Orcastrata from closed AOL.
- **Inputs and prerequisites:** Current candidate, operator correction, provider artifacts, GoalBuddy and WorkGraph contracts.
- **Deliverables:** Corrected plan, separate AOL handoff, board, manifest, and review receipt.
- **Allowed files:** `docs/goals/orcastrata-aol-github-umbrella-v1/`.
- **Excluded files:** Plugin implementation, AOL source, credentials, and GitHub state.
- **Dependencies and unlocks:** Depends on none; unlocks T020.
- **Parallel mode and write owner:** `parallel_read_only`; Parent/PM writes synthesis only.
- **Implementation steps:** Retain exact review artifacts, correct product ownership, and validate durable files.
- **Validation commands:** Run plan validator, official GoalBuddy checker, manifest verification, JSON parsing, and `git diff --check`.
- **Acceptance evidence:** Valid receipts and a recorded architecture correction.
- **Stop and escalation conditions:** Stop if the correction would change provider evidence or grant implementation authority.
- **Rollback or recovery:** Restore the prior docs from Git history or the recorded manifest; do not alter provider artifacts.
- **Documentation obligations:** Record that no provider reviewed the post-review product split.
- **Next-owner handoff:** T020 Parent/PM requests exact tranche authority.

### T020 — Operator implementation admission

- **Objective and rationale:** Convert the prepared plan into one bounded authorized tranche.
- **Inputs and prerequisites:** Accepted T010 receipt and current clean implementation target.
- **Deliverables:** Exact paths, effects, test repository, and authority packet.
- **Allowed files:** Board and authority receipt only.
- **Excluded files:** Source and external systems before approval.
- **Dependencies and unlocks:** Depends on T010; unlocks T030.
- **Parallel mode and write owner:** `serial`; Parent/PM.
- **Implementation steps:** Present T030 scope and record the operator decision.
- **Validation commands:** Official GoalBuddy checker and implementation-plan validator.
- **Acceptance evidence:** Explicit authority for T030 or an unchanged prepared board.
- **Stop and escalation conditions:** Stop on ambiguous repository, host, write scope, or checkout.
- **Rollback or recovery:** Leave T020 active and perform no implementation.
- **Documentation obligations:** Record granted and forbidden actions.
- **Next-owner handoff:** T030 Orcastrata implementer.

### T030 — Local gh capability and reads

- **Objective and rationale:** Prove the smallest useful GitHub seam without mutation.
- **Inputs and prerequisites:** T020 authority, exact repository, current adapter and receipt patterns.
- **Deliverables:** Closed read-only adapter, redacted receipts, and focused tests.
- **Allowed files:** Exact Orcastrata adapter, contract, test, and command files admitted by T020.
- **Excluded files:** AOL, write operations, credentials, hooks with effects, and generic transport layers.
- **Dependencies and unlocks:** Depends on T020; unlocks T040.
- **Parallel mode and write owner:** `serial`; Orcastrata implementer.
- **Implementation steps:** Resolve `gh`; validate input; run fixed argv; parse bounded JSON; redact errors; emit receipts.
- **Validation commands:** Focused fake-`gh` tests, package checks, and one authorized isolated real-`gh` read.
- **Acceptance evidence:** Credential-blind exact-repository reads and negative trust-boundary tests.
- **Stop and escalation conditions:** Stop on credential access, shell text, write symbols, or identity ambiguity.
- **Rollback or recovery:** Remove the read adapter and retain receipts; no external state exists.
- **Documentation obligations:** Document supported operations and non-authority.
- **Next-owner handoff:** T040 Orcastrata implementer.

### T040 — Umbrella state and projection

- **Objective and rationale:** Express umbrella work through existing state contracts.
- **Inputs and prerequisites:** T030 receipts, WorkGraph v1, GoalBuddy board and facade contracts.
- **Deliverables:** Umbrella work items, dependency validation, and deterministic GitHub preview.
- **Allowed files:** Existing WorkGraph, GoalBuddy integration, fixtures, and public command docs.
- **Excluded files:** AOL state, GitHub writes, duplicate board stores, and new generic graph engines.
- **Dependencies and unlocks:** Depends on T030; unlocks T050.
- **Parallel mode and write owner:** `serial`; Orcastrata implementer.
- **Implementation steps:** Map issue packets to WorkGraph, keep GoalBuddy canonical, and render a stable preview.
- **Validation commands:** Focused graph, board, projection, package, and round-trip tests.
- **Acceptance evidence:** One valid dependency graph and byte-stable preview with no GitHub effect.
- **Stop and escalation conditions:** Stop if a new truth store or incompatible schema is required.
- **Rollback or recovery:** Remove projection code; preserve existing board compatibility.
- **Documentation obligations:** Define state ownership and projection fields.
- **Next-owner handoff:** T050 Orcastrata implementer.

### T050 — Issue creation and reconciliation

- **Objective and rationale:** Add recoverable GitHub issue effects after read and preview proof.
- **Inputs and prerequisites:** T040 projection, explicit test-repository write authority, and stable item IDs.
- **Deliverables:** Prepare, create, observe, reconcile, and unknown-outcome behavior.
- **Allowed files:** Narrow issue operations, receipts, reconciliation logic, and focused tests.
- **Excluded files:** PR push, merge, auto-merge, schedules, AOL, and arbitrary `gh` execution.
- **Dependencies and unlocks:** Depends on T040; unlocks T060 and T070.
- **Parallel mode and write owner:** `serial`; Orcastrata implementer.
- **Implementation steps:** Persist prepare; invoke once; observe; bind external ID; reconcile zero, one, or multiple matches.
- **Validation commands:** Fake-`gh` fault tests and one authorized idempotent test-repository canary.
- **Acceptance evidence:** No duplicate issue across replay and resolved unknown outcomes.
- **Stop and escalation conditions:** Stop on multiple marker matches, missing prepare state, or transport drift.
- **Rollback or recovery:** Reconcile before retry; close test issues only with separate authority.
- **Documentation obligations:** Document marker, identity, and recovery rules.
- **Next-owner handoff:** T060 worker implementation and T070 auditor implementation.

### T060 — Bounded workers and PR lifecycle

- **Objective and rationale:** Execute ready issues without umbrella context creep or merge authority.
- **Inputs and prerequisites:** T050 issue identities and dependency-ready WorkGraph items.
- **Deliverables:** Bounded packets, branch leases, PR observation, repair routing, and push guards.
- **Allowed files:** Worker packet, lease, PR monitor, repair, guard, receipt, and focused test surfaces.
- **Excluded files:** Merge, force push, schedules, shared branch ownership, and AOL.
- **Dependencies and unlocks:** Depends on T050; unlocks T080.
- **Parallel mode and write owner:** `parallel_disjoint_write`; one worker per owned branch and allowed path set.
- **Implementation steps:** Lease ready issue; verify branch and diff; push; observe PR; route bounded repair; record receipts.
- **Validation commands:** Focused packet, lease, path, branch, PR-state, and failure-routing tests plus authorized dogfood.
- **Acceptance evidence:** Disjoint workers produce reviewable PRs without scope or merge violations.
- **Stop and escalation conditions:** Stop on path overlap, branch drift, force push, dependency change, or repeated failure signature.
- **Rollback or recovery:** Revoke lease, preserve branch and receipts, and route Parent repair.
- **Documentation obligations:** Define packet limits and operator-invoked babysitting.
- **Next-owner handoff:** T080 after T070 also passes.

### T070 — Scoped audit and audit-full

- **Objective and rationale:** Add an independent umbrella gate without changing existing audit semantics.
- **Inputs and prerequisites:** T050 issue state, current verify command, frozen acceptance criteria, and PR observations when present.
- **Deliverables:** `/orcastrata-audit-full`, typed findings, and immutable verdict receipts.
- **Allowed files:** Audit skill or command, read-only evidence aggregation, schemas, tests, and docs.
- **Excluded files:** GitHub mutation, worker repair, merge, schedules, and AOL Assurance.
- **Dependencies and unlocks:** Depends on T050; unlocks T080.
- **Parallel mode and write owner:** `independent_gate`; independent auditor.
- **Implementation steps:** Preserve `/orcastrata-audit`; aggregate receipts; fetch only stale or failed details; return ACCEPT, REVISE, or BLOCKED.
- **Validation commands:** Focused audit fixtures, package validation, and independent review.
- **Acceptance evidence:** Correct verdicts for closure, stale evidence, conflicts, and missing receipts.
- **Stop and escalation conditions:** Stop if the command gains write authority or replaces Parent acceptance.
- **Rollback or recovery:** Remove only the new command and preserve existing verify behavior.
- **Documentation obligations:** Document the semantic difference between the two audit commands.
- **Next-owner handoff:** T080 after T060 also passes.

### T080 — Explicit guarded merge

- **Objective and rationale:** Permit one safe optional merge without autonomous default behavior.
- **Inputs and prerequisites:** Accepted T060 and T070 receipts plus the standing exact-repository merge grant.
- **Deliverables:** Fresh precondition check, one merge effect, reconciliation, and recovery receipt.
- **Allowed files:** Narrow merge operation, confirmation surface, receipts, recovery, and tests.
- **Excluded files:** Auto-merge, scheduled merge, force push, AOL, and policy inference from authentication.
- **Dependencies and unlocks:** Depends on T060 and T070; unlocks T090.
- **Parallel mode and write owner:** `serial`; Orcastrata effect executor.
- **Implementation steps:** Bind exact SHAs and gates; re-read; compare; merge once under the standing grant; reconcile outcome.
- **Validation commands:** Fake-`gh` stale-state and unknown-outcome tests plus one standing-authority exact-repository canary.
- **Acceptance evidence:** Merge occurs only with current bindings and the recorded standing grant.
- **Stop and escalation conditions:** Stop on stale evidence, conflict, failed checks, review change, or unknown outcome.
- **Rollback or recovery:** Do not retry unknown effects; reconcile and report. Revert needs separate authority.
- **Documentation obligations:** Document merge gates, expiry, and recovery.
- **Next-owner handoff:** T090 independent auditor.

### T090 — Standalone dogfood acceptance

- **Objective and rationale:** Prove the open-source package works without AOL.
- **Inputs and prerequisites:** T080 candidate, clean installation target, and authorized test repository.
- **Deliverables:** Package, security, consumer, real-interface, cost, and end-to-end receipts.
- **Allowed files:** Read-only source and test surfaces; one canonical acceptance receipt.
- **Excluded files:** Repairs, production repositories, AOL implementation, and publication.
- **Dependencies and unlocks:** Depends on T080; unlocks T999.
- **Parallel mode and write owner:** `independent_gate`; independent auditor.
- **Implementation steps:** Install candidate in isolation; run the full operator journey; compare evidence with the oracle.
- **Validation commands:** Focused checks, justified full suite, package/install check, real command journey, and adversarial review.
- **Acceptance evidence:** Independent ACCEPT, REVISE, or BLOCKED verdict with token and latency fields or `unknown`.
- **Stop and escalation conditions:** Stop on product defect, credential exposure, external-scope breach, or unapproved effect.
- **Rollback or recovery:** Preserve failure evidence and return bounded repair work to Parent.
- **Documentation obligations:** Record exact candidate, environment, commands, results, and remaining risks.
- **Next-owner handoff:** T999 Parent/PM on ACCEPT; otherwise Parent routes repair.

### T999 — Parent lifecycle closeout

- **Objective and rationale:** Close execution only after proof and child cleanup.
- **Inputs and prerequisites:** Accepted T090 receipt and authoritative board history.
- **Deliverables:** ParentChildCloseoutReceipt, final board state, and roadmap-return packet.
- **Allowed files:** Goal directory, canonical receipt, and authorized roadmap return.
- **Excluded files:** Product repair, external effects, and unapproved roadmap edits.
- **Dependencies and unlocks:** Depends on T090; unlocks none.
- **Parallel mode and write owner:** `serial`; Parent/PM.
- **Implementation steps:** Inventory children; interrupt active non-persistent children; archive terminal children; validate inventory; close board.
- **Validation commands:** Terminal Lifecycle ready and confirm, official GoalBuddy checker, stop checker, plan validator, and manifest verification.
- **Acceptance evidence:** Clean child inventory, `goal.status: done`, `active_task: null`, and passing final checks.
- **Stop and escalation conditions:** Keep T999 active on incomplete cleanup, missing authority, or failed proof.
- **Rollback or recovery:** Restore active T999 state and repair the missing lifecycle evidence.
- **Documentation obligations:** Record final scope, files, commands, proof, deferred AOL work, and risks.
- **Next-owner handoff:** Open-source release owner and separate AOL integration owner.

## Validation Ladder

1. Focused tests for each changed contract and trust boundary.
2. Consumer tests for GoalBuddy, WorkGraph, commands, hooks, and package install.
3. Justified full repository suite and isolated standalone dogfood.
4. Independent audit against the complete acceptance oracle.

## GoalBuddy-backed Terminal T999 Contract

T999 stays active until the Parent inventories all addressable child tasks and
live agents, interrupts active non-persistent children, archives terminal
non-persistent children by exact ID, records authority for retained persistent
sessions, and validates a fresh inventory. The Parent then obtains Terminal
Lifecycle `ready`, changes the board to `done` with `active_task: null`, runs the
official and stop checkers, and obtains Terminal Lifecycle `confirm`. Any failed
step leaves T999 active.

## Risks, Blockers, and Stop Conditions

- Local `gh` can use an authenticated identity that differs from operator intent.
  Bind the exact host, repository, safe account identity, and permission before effects.
- GitHub effects are not atomic with local state. Prepare before effect and
  reconcile unknown outcomes before retry.
- Umbrella context can grow without bound. Default every agent to one issue
  packet and use receipt references for broader evidence.
- A scheduler changes authority and recovery behavior. Keep V1 operator-invoked.
- AOL integration has a different owner and oracle. Keep it off this board.

## Change-Control Protocol

Record new scope, tasks, paths, providers, transport, automation, authority, or
proof requirements as a dated revision. Revalidate the plan and board before
execution continues. Do not edit frozen provider artifacts.

## Handover Notes

- T010 is done. It retained the exact Grok and MiniMax review artifacts and the
  failed DeepSeek identity receipt. The operator then corrected the product
  boundary. The Parent split the standalone Orcastrata plan from the closed AOL
  handoff. No provider reviewed that later split. T020 is done. The operator
  admitted T030 source implementation and read-only local validation. T030 is
  newly unblocked and active. T040 through T999 remain blocked by dependencies.
- T030 now has a source candidate. The closed adapter, contract, skill route,
  focused tests, and release manifest are present. Eight adapter tests and three
  native-interface tests pass. Release parity passes for 406 package files. The
  official GoalBuddy checker and plan validator pass without warnings. The
  independent follow-up audit reports no blocking implementation finding. At
  that checkpoint, no exact operator-bound host and `owner/repository` had been
  supplied for the isolated live read.
- The operator then bound `github.com/Vel-Labs/orcastrata-max`. The live
  `probeCapability` receipt passed with default branch `main` and viewer
  permission `ADMIN`. The adapter reported no GitHub mutation, local mutation,
  authority grant, acceptance grant, or Orcastrata credential access. T030 has
  candidate was accepted. T030 is done.
- T040 passed deterministic projection, package, GoalBuddy, and independent
  audit gates. T050A passed local implementation, fake-`gh` validation, and
  independent audit. The operator then granted standing execution authority for
  T050B through T999 on `github.com/Vel-Labs/orcastrata-max` only. T050 remains
  active until fresh username and repository permission proof, the real board
  projection, live reconciliation, and the issue canary pass.
- T050 completed after eleven exact issue effects reconciled without duplicate
  or unknown outcomes. T060 completed after one bounded native worker, one
  same-scope repair, 28 focused and consumer tests, 413-file package parity,
  independent ACCEPT, an exact non-force push, and PR #12 creation and live
  reconciliation. T070 completed after 30 focused tests, 415-file package
  parity, complete issue-marker and PR-scope observations, and an independent
  ACCEPT. T080 is newly unblocked and active. PR #12 remains unmerged. Its
  COMMENTED review is not approval evidence, so T080 must read repository
  review policy and all other merge gates fresh. T090 and T999 remain blocked.

## Roadmap-Return Contract

Return the accepted standalone Orcastrata outcome, exact candidate, proof
boundary, changed surfaces, validation, review, token and latency observations,
deferred work, risks, and release implications. Give AOL owners the separate
handoff only after Orcastrata dogfood acceptance. Do not edit either roadmap
without owner authority.

## Decision and Progress History

| Date | Decision or transition | Evidence | Owner |
| --- | --- | --- | --- |
| 2026-09-01 | Initial combined plan reviewed | Exact Grok and MiniMax artifacts; DeepSeek identity failure | Parent/PM |
| 2026-09-01 | Split standalone Orcastrata from downstream AOL integration | Operator correction and corrected durable artifacts | Parent/PM |
| 2026-09-01 | Admit and build T030 source candidate | Focused tests, package parity, official board check, and independent audit | Parent/PM |
| 2026-09-01 | Complete T030 live read candidate | `t030-live-read-receipt.json` | Parent/PM |
| 2026-09-01 | Accept T030 and admit T040 | Operator instruction to proceed | Parent/PM |
| 2026-09-01 | Accept T040 and admit local-only T050A | Operator instruction; no live GitHub writes | Parent/PM |
