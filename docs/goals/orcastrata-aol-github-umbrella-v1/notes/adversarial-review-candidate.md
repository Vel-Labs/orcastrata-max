# Frozen Adversarial Review Candidate

Candidate: Orcastrata to AOL GitHub Umbrella Integration V1
Full plan: `notes/aol-integration-handoff.md`
Execution authority: not granted

## Outcome

Let AOL own a durable umbrella project graph and synchronize it to GitHub
issues. Orcastrata executes dependency-ready issues through bounded workers,
monitors their PRs, routes smallest-unit repairs, and produces scoped and
umbrella audit receipts. AOL Assurance admits GitHub effects and final merge.
GitHub is an external synchronized surface, not canonical work truth.

## Observed Current State

- Orcastrata 1.2.0 candidate has native commands, hooks, GoalBuddy, WorkGraph,
  provider fan-out, supervision, events, and receipts. It has no GitHub
  automation or `/orcastrata-audit-full`.
- AOL already has a GitHub OAuth/API connector with device flow, Keychain token
  storage, issue ingestion, comment posting, health checks, and normalization.
- AOL already supports symbolic inherited runtime credential references for
  Codex without copying tokens.
- AOL Assurance has a strict consumer frozen to Orcastrata 1.0.0. A new version
  needs a versioned consumer revision, not loosened constants.
- The AOL checkout is dirty with unrelated work. Later implementation must use
  a clean linked worktree.

## Ownership

- AOL Work/GoalBuddy: umbrella, issues, dependencies, successors, canonical state.
- AOL Core: route, economics, provider, capability, and effect admission.
- Orcastrata: worker assignment, attempts, repair, PR monitoring, execution receipts.
- GitHub: external issue, PR, branch, check, review, and merge state.
- AOL Assurance/operator policy: acceptance and merge admission.
- Graph Engineering: later indexing and recall of accepted artifacts, not execution.

## GitHub Transport

Use one operation-shaped transport boundary because two real transports exist.
On a trusted local host, prefer authenticated `gh`. In hosted or non-`gh`
posture, retain AOL's existing OAuth/API connector. Do not silently switch after
a possibly started effect.

Local readiness uses fixed argv arrays:

```text
command -v gh
gh auth status --hostname github.com
git remote get-url origin
gh repo view --json nameWithOwner,viewerPermission,defaultBranchRef
```

Never run `gh auth token`, inspect GitHub credential files, interpolate shell
text, or persist credential output. Authentication is readiness only. Each
operation also needs exact repository scope, current permission, AOL action
decision, output/time bounds, and redaction.

Initial operations: capability probe, repo read, issue list/read/create, PR
read, check list, bounded diff summary. Merge operations do not exist until the
late guarded-merge milestone.

## Synchronization

AOL owns stable umbrella and child IDs, dependencies, acceptance, validation,
non-goals, guardrails, projection revision, external GitHub IDs, last observed
revision, and reconciliation status. Projection compiles deterministic GitHub
intent. Reconciliation separately records observed GitHub state.

Each issue effect uses an idempotency key derived from workspace, umbrella
revision, child ID, repository, and operation. The receipt and a machine marker
in the issue body bind the key. A repeated request reuses the matching issue or
fails closed on ambiguity. External edits create reconciliation proposals; they
cannot directly change GoalBuddy dependencies, authority, acceptance, or done state.

Unknown effect outcome fences retry until reconciliation proves whether GitHub
applied it. Batches execute one issue at a time and persist each remote identity
before the next effect.

## Context Control

- Coordinator: graph summaries, readiness, budgets, receipt references.
- Worker: one issue, dependency outputs, repo rules, allowed paths, validation.
- PR monitor: PR identity, branch ownership, checks, unresolved reviews, deltas.
- PR auditor: frozen criteria, bounded diff, tests, review state, receipts.
- Audit-full: aggregate receipts first; fetch detail only for missing, stale,
  failed, or contradictory gates.

Full issue comments, CI logs, and diffs are not default context. Measure input
tokens, fetched bytes, tool output bytes, latency, retries, and accepted-result cost.

## Audit and Merge

`/orcastrata-audit` checks one PR against one issue contract.
`/orcastrata-audit-full` is read-only and checks graph closure, dependencies,
all required PR verdicts, CI/reviews, cross-PR integration, docs, migrations,
security/authority, reconciliation drift, and the umbrella oracle. It returns
`ACCEPT`, `REVISE`, or `BLOCKED`; it cannot write or merge.

PR babysitting starts as operator-invoked or event-driven. Each worker owns one
leased branch and explicit file scope. It cannot change another branch, broaden
scope, rewrite shared history, or merge. Scheduled wakeups come only after the
event and authority contracts are proven.

Merge is an AOL effect and defaults to operator confirmation. It requires
current repo, target branch, head SHA, merge method, required checks and
approvals, zero blocking threads, no conflict, issue acceptance, scoped audits,
current audit-full digest, projection revision, and unexpired action decision.
Unknown outcome blocks retry until reconciliation.

## Milestones

1. Freeze and review the plan.
2. Obtain exact implementation authority.
3. Implement credential-blind local `gh` discovery and narrow reads.
4. Implement AOL-owned umbrella state and deterministic no-write preview.
5. Implement consent-gated idempotent issue writes and reconciliation.
6. Implement bounded issue workers and event-driven PR monitoring.
7. Implement scoped audit and read-only audit-full.
8. Implement guarded merge and unknown-outcome recovery.
9. Run consumer, security, real-interface, token, and end-to-end acceptance.
10. Close Parent lifecycle.

The first implementation authority should cover milestone 3 only. Milestone 3
must pass fake-process negative tests and one isolated real read-only `gh`
canary. It must not change OAuth, write GitHub, schedule work, or add merge.

## Required Review

Find concrete defects in credential blindness, duplicate-truth prevention,
transport selection, idempotency, unknown-outcome recovery, AOL/Orcastrata
ownership, context budgets, audit independence, merge safety, validation, and
fresh-implementer readiness. Prefer deletion or consolidation over new layers.
Return a verdict, blockers, high-value changes, rejected complexity, and the
smallest safe first tranche.
