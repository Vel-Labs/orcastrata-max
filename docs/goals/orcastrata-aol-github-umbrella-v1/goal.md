# Orcastrata Standalone GitHub Umbrella Workflow V1

## Objective

Add a standalone GitHub umbrella workflow to the open-source Orcastrata
project. Orcastrata uses the authenticated local `gh` CLI as a credential-blind
execution surface. It keeps dependency and run truth in its existing GoalBuddy
and WorkGraph contracts. It does not depend on AOL.

The stable directory and plan ID retain the earlier `aol` name for provenance.
The implementation board now owns only the Orcastrata feature. The separate AOL
handoff describes a later closed-source product integration.

## Acceptance Oracle

The goal is accepted only when an authorized test repository proves the
standalone journey: operator-bound repository discovery, idempotent umbrella
issue projection, bounded issue workers, branch and path guards, PR monitoring,
scoped audit, `/orcastrata-audit-full`, reconciliation, and one explicitly
confirmed guarded merge. T010 proves only that the corrected plan is ready.

## Authority

The user authorized T050B through T999 for `Vel-Labs/orcastrata-max`. This grant
includes exact-repository GitHub issue and pull-request writes, local branches,
commits, non-force pushes, bounded native workers, independent audits, isolated
installation, full validation, standalone dogfood, and one-at-a-time guarded
merges after all required gates pass.

## Scope

Write only board-owned Orcastrata source, tests, plans, and receipts in this
worktree. Use only `Vel-Labs/orcastrata-max` for GitHub effects. Treat AOL as a
separate downstream consumer. Do not change AOL source.

## Stop Rule

Do not read, expose, refresh, or replace credentials. Stop on identity mismatch,
multiple marker matches, unexpected repository state, unresolved merge conflict,
failing required gates, scope overlap, credential failure, or authority outside
the grant. Do not use auto-merge, force push, history rewriting, arbitrary `gh`
commands, external model providers, schedules, deployments, releases, repository
settings, secrets, AOL source, another repository, or unrelated issues and pull
requests.
