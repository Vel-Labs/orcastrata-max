---
name: codexmax-loop
description: "Advanced composable capability — Inspect, validate, match, dry-run, and govern LoopRegistry workflows without granting execution or activation authority."
---

# Codexmax Loop

## Trigger And Route

Use this advanced capability when an authorized orchestration packet explicitly
needs loop-level inspection, policy validation, event matching, dry-run proof,
lifecycle review, or receipt verification. Ordinary natural-language requests
such as “make this a loop,” recurring checks, hook requests, and event-driven
validation start at `$codexmax-orchestrator:codexmax-orchestrate`; Orchestrate
may compose this skill after its normal preview and authority gates.

This is not another public first-run choice. It does not create board truth,
compile commands, execute action profiles, install hooks, activate schedules,
or decide acceptance.

## Read Order

1. Workspace and nearest repository `AGENTS.md`.
2. Current GoalBuddy goal, board, assignment, and accepted receipts if present.
3. Workspace `_ops/README.md`, `_ops/loops/README.md`, and the selected
   `_ops/loops/registry.yaml`.
4. [Loop Registry Contract](../../assets/contracts/loop-registry.md).
5. [Loop Event And Receipt Contract](../../assets/contracts/loop-events.md).
6. Referenced WorkGraph, GoalBuddy, source, and authority artifacts in their
   owner systems.

## Safe Operations

Resolve `<plugin-root>` as `Path(SKILL.md).parents[2]`. Use the checked-in
`<plugin-root>/scripts/loopctl.py`; do not substitute an installed-cache copy.
Supply the registry and event as canonical absolute regular-file paths.

```sh
python3 <plugin-root>/scripts/loopctl.py list --registry <absolute-registry> --json
python3 <plugin-root>/scripts/loopctl.py show --registry <absolute-registry> <loop-id> --json
python3 <plugin-root>/scripts/loopctl.py validate --registry <absolute-registry> --json
python3 <plugin-root>/scripts/loopctl.py status --registry <absolute-registry> <loop-id> --json
python3 <plugin-root>/scripts/loopctl.py match --registry <absolute-registry> --event <event.json> --evaluation-time <RFC3339-UTC> --json
python3 <plugin-root>/scripts/loopctl.py dry-run --registry <absolute-registry> --event <event.json> --evaluation-time <RFC3339-UTC> --json
python3 <plugin-root>/scripts/loopctl.py verify-receipt <receipt.json> --json
```

The accepted T020 boundary is deterministic local validation, matching,
receipt verification, and dry-run only. Every output has `executed: false`
where applicable. Compile and run are unavailable until T040 separately binds
fixed source-owned profiles, current authority, WorkGraph references, budgets,
and append-only receipts. Never invent a `loopctl run` or compile command.

## Lifecycle Procedure

1. Inspect the exact registry and definition references before reading an
   event or recommending a transition.
2. Validate before show/match/dry-run claims. Reject unknown fields, unsafe
   paths, stale identity, unbound profiles, ambiguous authority, widened scope,
   stale/duplicate/recursive events, and command-like input.
3. Preserve the frozen transition graph: forward promotion is
   `proposed -> dry_run -> pilot -> active`; eligible states may pause, fail, or
   retire; paused resumes only to its recorded prior state; failed returns only
   to `dry_run` with repair evidence; retired is terminal.
4. Treat registration, `valid: true`, and `admission: matched` as policy or
   preview states, never permission to execute or promote.
5. Require fresh operator-approved evidence for promotion. GoalBuddy remains
   board truth, WorkGraph owns dependencies and evidence edges, and Parent or
   the named operator owns acceptance.
6. Verify the resulting `LoopRunReceipt v1`. Preserve stable rejection codes,
   `not_run`, `unknown`, `rejected`, and unproved flags exactly.

## Failure Routing

- Invalid schema, path, reference, event, scope, action, budget, or proof:
  retain exact stable codes and return a bounded repair request.
- Missing or stale authority: stop at `authority_missing` or
  `authority_stale`; configuration and lifecycle cannot self-authorize.
- Unavailable compiler/action/hook/scheduler: mark deferred and hand to the
  separately authorized T040/T050/T070 owner; do not simulate it.
- Failed or unknown validation: keep `fail`, `not_run`, or `unknown` and route
  through `$codexmax-orchestrator:codexmax-verify`.
- Candidate closeout: route through
  `$codexmax-orchestrator:codexmax-closeout`; only Parent decides acceptance.

## Proof Boundary

Report local source, installed projection, live hook, active scheduler,
external connector, publication, and acceptance as separate facts. This skill
proves none of the latter six. It never authorizes network, credentials,
packages, external services, notification delivery, publishing, or direct
GoalBuddy/WorkGraph mutation.

## Output Contract

Return exact registry/event/receipt paths, operation, lifecycle, matched loop
and fixed profile IDs, stable errors, command result, proof state, assumptions,
remaining risks, and next owner. Commands not run remain `not_run`; missing
evidence remains `unknown`.
