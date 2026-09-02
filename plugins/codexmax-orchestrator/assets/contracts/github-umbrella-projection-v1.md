# Orcastrata GitHub Umbrella Projection V1

## Purpose

`scripts/github_umbrella_projection.py` renders one deterministic GitHub
umbrella preview and bounded child issue packets. It consumes a valid WorkGraph
document and a canonical GoalBuddy snapshot. It does not create another board.

## Input

The closed JSON request contains:

- `schema_version: 1`;
- `artifact_type: orcastrata_github_umbrella_projection_request_v1`;
- exact lowercase GitHub `host` and exact `owner/repository` target;
- one complete WorkGraph v1 document;
- one `workgraph_goalbuddy_adapter` snapshot;
- display-only umbrella metadata;
- one display-only metadata row for every WorkGraph item.

WorkGraph owns objectives, scope, acceptance conditions, validations,
dependencies, evidence relationships, and stop rules. GoalBuddy owns board
status and the active task. Presentation metadata supplies only titles, labels,
and non-goals. It cannot grant authority or change execution state.

The GoalBuddy task ID set must equal the WorkGraph item ID set. Missing,
duplicate, extra, cyclic, malformed, or contradictory inputs fail closed.

## Output

A successful receipt contains:

- exact target, graph ID and graph digest;
- GoalBuddy board digest, owner, and active task;
- stable umbrella and issue markers;
- deterministic Markdown bodies;
- issue titles, labels, dependencies, readiness, scope, non-goals, acceptance,
  validation, stop condition, and GoalBuddy status;
- one projection digest;
- an all-false effect boundary.

Items are sorted by stable WorkGraph ID. An item is ready only when its
GoalBuddy status is `queued` or `active` and every `blocked_by` item is `done`.
Stable markers normalize GitHub's case-insensitive repository identity before
hashing. Repository case changes cannot create a second identity. The preview
never changes GoalBuddy or WorkGraph.

## Effect Boundary

The projection uses only standard-library local computation and the existing
WorkGraph validator. It does not call `gh`, GitHub, Git, a provider, a model, a
hook, a connector, or a network service. It does not create issues, branches,
commits, pull requests, schedules, authority, or acceptance.
