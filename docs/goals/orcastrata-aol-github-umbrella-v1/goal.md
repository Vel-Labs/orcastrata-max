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

The user authorized planning and adversarial review. Implementation, GitHub
mutation, installation, merge, push, publication, automation, and scheduled PR
babysitting are not authorized.

## Scope

Write only planning and review evidence in this Orcastrata worktree. Treat AOL
as a separate downstream consumer. Do not change AOL source.

## Stop Rule

Do not treat terminal authentication as action authority. Do not read or copy a
GitHub token. Do not make GitHub the only canonical run truth. Do not implement
or run GitHub mutations until the operator accepts an exact tranche.
