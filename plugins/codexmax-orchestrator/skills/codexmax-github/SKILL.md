---
name: codexmax-github
description: "Parent-owned local repository handoff or admitted board-backed GitHub workflow through issues, pull requests, audit, guarded merge, and T999 closeout."
---

# Orcastrata GitHub Workflow

Use this skill for an optional local issue/PR handoff or an explicitly selected
GitHub-backed GoalBuddy or WorkGraph project. The admitted board-backed route
composes existing Orcastrata stages and retains their validators and effect
boundaries.

## Ordinary Local Repository Handoff

Ordinary bounded native repository work may remain board-free, including useful
parallel workers and a local PR draft. Use the native route in
`$codexmax-orchestrator:codexmax-orchestrate`; the Parent owns scope, integration,
verification, and final acceptance. Preserve any explicitly selected durable
GoalBuddy or WorkGraph workflow. A local handoff does not migrate that project.

When a local handoff is useful or requested:

1. Record an issue-like task with the actual request, allowed paths, acceptance
   checks, exclusions, and worker ownership. Label it local; invent no remote
   issue number, board state, lifecycle marker, or lease.
2. Inspect repository instructions and record the worktree, branch, upstream
   (or absent), base/HEAD, and current diff before changing source. Preserve
   unrelated work and bind the returned diff to that observed baseline.
3. Complete and verify the authorized change. Return changed paths, exact
   checks, results, failed or skipped checks, and unresolved limits to Parent.
4. Prepare a local PR title/body describing the defect, resulting behavior,
   diff, verification, and incomplete evidence. Distinguish implemented,
   verified, and Parent-accepted work. A draft proves no remote PR, live
   authentication, installed host activation, or merge readiness.

This route creates no board or claim store and invokes no GitHub effect adapter.
Repository remotes and local drafts grant no network, push, publication, or merge
authority. An explicitly authorized remote handoff requires the relevant
supported surface and its own checks. Do not fabricate durable inputs to call
`github_issue_effect.py` or `github_pr_lifecycle.py` for a board-free task.

## Board-Backed Admission

Require the exact lowercase host and `owner/repository`. The task grant must
name the allowed read and write effects. Authentication, the current directory,
and Git remotes do not grant authority. Use the currently authenticated local
`gh` identity only. Never inspect, expose, refresh, or replace credentials.

Use `scripts/github_cli_read.py` for read-only observations. Before any write,
verify that the current username matches the grant and that it has `WRITE` or
`ADMIN` permission for the exact repository. Stop on an identity, repository,
permission, or authority mismatch.

## Parent Workflow

1. Keep GoalBuddy as canonical board truth and WorkGraph as dependency truth.
2. Build `scripts/github_umbrella_projection.py` output from the validated board
   and WorkGraph. Do not create a second board.
   To build an opt-in local index from saved projection receipts, create an
   explicit catalog manifest and run:

   ```text
   python3 scripts/umbrella_catalog.py --manifest <manifest.json> --root <source-root> --jsonl-out <umbrella-catalog.jsonl> --markdown-out <umbrella-catalog.md>
   ```

   The catalog is a derived snapshot. Validate its source and digests before
   consequential use. On missing, stale, ambiguous, or unrepresented data,
   read GoalBuddy and WorkGraph directly or defer. The catalog does not grant
   GitHub authority and does not change the write checks below. Do not inject
   catalog content into every task or turn. Use it only when catalog-first
   retrieval is requested and measured as useful. The closed contract and
   consumer fixtures are in `assets/contracts/umbrella-catalog-v1.md` and
   `assets/templates/umbrella-catalog-v1-*.json`.
3. Prepare each issue with `scripts/github_issue_effect.py`. Apply it with
   `scripts/github_issue_live.py` only when issue writes are authorized.
4. Dispatch only ready WorkGraph items. Give each Worker one issue, one branch,
   one lease, and one exact path allowlist. The Parent owns integration.
5. Use `scripts/github_pr_lifecycle.py` to publish, observe, or repair each
   bounded pull request. It cannot merge.
6. Invoke `$codexmax-orchestrator:codexmax-audit-full` against the frozen
   candidate. The audit is independent, read-only, and advisory.
7. If merge authority is explicit, use `scripts/github_guarded_merge.py` with
   the exact `--expected-host`, `--expected-repository`, `--expected-user`, and
   active merge task. Merge one pull request at a time only after every fresh
   gate passes. Never use auto-merge.
8. After the final audit and merge result, invoke
   `$codexmax-orchestrator:codexmax-closeout` for terminal `T999` cleanup and
   Parent acceptance.

## Synchronization Cadence

For an admitted GitHub-backed project, keep the managed umbrella current at
high-signal boundaries: accepted plan, issue creation, task start or completion,
material blocker, pull-request creation or review state, independent audit,
guarded merge, and terminal closeout. Use one necessary comment or state update
per boundary. Keep low-level command logs, retries, and evidence in local
receipts.

Do not use a lifecycle hook to perform GitHub writes. Hooks can load guidance,
but they cannot supply task-local repository authority. Ordinary language that
asks Orcastrata to run a GitHub-backed project should select this skill; the
effect scripts and gates still control every read and write.

An external effect with an unknown result must reconcile before retry. Preserve
failed attempts. Do not modify unrelated issues, pull requests, branches, or
repository settings. Do not publish a release, deploy, schedule work, or call
an external provider unless the task grant separately authorizes that effect.

## Stop Conditions

Stop on multiple marker matches, stale or conflicting board state, scope
overlap, an expired lease, an unresolved conflict, a failing required gate, an
unknown result that cannot reconcile, or authority outside the task grant.
Otherwise continue through the board without requesting routine approval.
