---
name: codexmax-audit-full
description: "Read-only umbrella audit across GoalBuddy, WorkGraph, GitHub observations, receipts, scope, and package evidence."
---

# Codexmax Audit Full

Use this skill only for the full umbrella gate. Use
`$codexmax-orchestrator:codexmax-verify` for the existing focused audit. Do not
change `/orcastrata-audit` semantics.

Read the accepted goal, GoalBuddy board, WorkGraph, issue and pull-request
packets, effect receipts, worker receipts, and package manifest. Reuse their
existing validators. Use `../../scripts/github_cli_read.py` only when a required
GitHub observation is missing, stale, or failed. The repository and authority
must already be explicit. Do not infer either from Git state.

Check, in order:

1. GoalBuddy goal, active task, dependencies, and acceptance oracle agree.
2. WorkGraph readiness, leases, ownership, and dependency edges agree with the
   board and worker packets.
3. Each managed issue and pull request has one identity, expected scope, and
   current repository observation. Match managed issues by the normalized
   `orcastrata_markers` field. Reject missing, malformed, or duplicate markers.
4. Pull-request base and head SHAs, changed paths, conflict state, required
   checks, reviews, and dependency gates match their receipts. Read reviews
   with `listPullRequestReviews`. Compare the complete changed-path identity by
   `total_count` and `filenames_sha256`; the capped item list is not complete
   scope evidence.
5. Every external effect has prepare, before, after, reconciliation, and known
   recovery state. Multiple marker matches or an unknown outcome fail closed.
6. Required focused, consumer, package, and independent evidence is present.
   Use `../../scripts/verify_release_parity.py` only when package parity is part
   of the requested gate.

For each evidence item, report its source path or GitHub identity, observed
time, observed revision or SHA, comparison time, current revision or SHA, and
freshness as `current`, `stale`, or `unknown`. Do not invent a time-to-live.
Evidence is current only when the governing contract's revision and identity
still match. A missing comparison is `unknown`.

Return one advisory verdict:

- `ACCEPT`: all required evidence is present, current, passing, in scope, and
  mutually consistent.
- `REVISE`: a bounded implementation or evidence defect can be repaired within
  existing authority.
- `BLOCKED`: required authority or an external prerequisite is absent, or
  identity, scope, dependency, conflict, marker, or effect state is ambiguous.

List typed findings with `code`, `severity`, `subject`, `evidence`,
`freshness`, and `required_action`. Preserve failures and unknowns. State that
the verdict is read-only and advisory. Only the Parent can accept the work.

Never repair, mutate, merge, comment, push, schedule, call a provider, access
credentials, touch AOL, or grant acceptance. Stop if any required check cannot
remain read-only.
