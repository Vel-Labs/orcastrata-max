# Orcastrata GitHub Issue Effect V1

## Purpose

`scripts/github_issue_effect.py` prepares and simulates one idempotent GitHub
issue effect. T050A has no live execution path. Its CLI can prepare a receipt,
but `simulateApply` requires an injected fake runner.

## Source And Identity

`prepare` consumes one successful
`orcastrata_github_umbrella_projection_receipt_v1` and one stable ID. It verifies
the projection digest, all-false effect boundary, GoalBuddy board digest, exact
target, unique preview item, size limits, and exact marker. It then returns a
checksum-bound prepare receipt. The prepare receipt grants no authority.

The effect ID binds the graph, target, GoalBuddy board digest, projection
digest, stable ID, and exact title, body, and labels payload digest. The stable
ID and payload digest are recomputed when the prepare receipt is consumed.

## Simulation

`simulateApply` accepts only a valid prepare receipt and an injected fake runner.
It uses fixed `gh api` argument arrays:

1. Search the exact repository for the stable body marker.
2. Bind one exact existing issue only when its marker, title, and labels match.
3. Simulate one create only when no exact match exists.
4. Fail closed when search results drift or multiple exact matches exist.
5. Return `unknown` and require reconciliation after any uncertain simulated
   create result. It never retries an uncertain effect.

Every simulation receipt reports `simulation_only: true`, `github_called: false`,
`github_mutated: false`, and `live_execution_available: false`.

## Live T050B Gate

`scripts/github_issue_live.py` is the separate live wrapper. It accepts one
already-persisted prepare receipt, one absolute effect-state path, and the exact
operator-bound host, repository, and expected username. It resolves `gh` once,
uses the read adapter's cleaned environment and bounded process runner, verifies
the current username, repository identity, `WRITE` or `ADMIN` permission, and
active repository state, and then permits only the exact search and create argv
produced by the simulation core.

The wrapper observes before every effect. On zero matches, it writes an
`effect_started` state bound to the effect and prepare digests before POST. A
started or unknown state can reconcile only. It never sends a second POST when
reconciliation still finds zero matches. An uncertain POST result persists
`unknown` and requires reconciliation. The live wrapper reports actual command
count and whether mutation is false, true, or unknown. It does not grant
authority or acceptance and does not read credential material.

## Exclusions

This contract does not support arbitrary commands, credential inspection,
comments, edits, closing, branches, pull requests, pushes, merges, schedules,
providers, AOL, retry of unknown effects, or acceptance.
