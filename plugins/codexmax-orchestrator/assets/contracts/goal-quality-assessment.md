# Goal-Quality Assessment Contract

## Purpose

`assess_goal_quality.py` is a local, repository-aware intake gate. It reads an
explicit repository root plus one durable goal document and one durable state
document. It returns either `ready` or `needs_intake`; it does not create a
GoalBuddy task, grant authority, infer execution approval, or accept a
checkpoint or goal.

## Inputs And Boundary

The CLI requires all three inputs:

```text
--repo-root <directory> --goal-path <relative-markdown-path> --state-path <relative-yaml-or-json-path>
```

- `repo_root` must be a real directory, not a symbolic link.
- Goal and state paths are repository-relative, contain no `..` component, and
  must resolve to regular non-symlink files inside that root.
- The goal source is Markdown. The state source is JSON or a conservative YAML
  mapping/sequence subset sufficient for identity and checkpoint metadata.
- Transcript text, chat history, implicit current directories, external data,
  and hidden provider context are unsupported input. Supplying `--transcript`
  is a clear `unsupported_input:transcript` error.

The assessor records only normalized repository-relative paths and SHA-256
digests. It never reads a source after its path fails the root and symlink
gate.

## Required Readiness Claims

`ready` requires each of these goal-document observations:

| Claim ID | Requirement | Expected durable section |
| --- | --- | --- |
| GQ-001 | objective | `Objective` |
| GQ-002 | acceptance oracle | `Acceptance Oracle` or `Functional Oracle` |
| GQ-003 | scope/write boundary | `Scope` |
| GQ-004 | authority boundary | `Authority` or `Non-Negotiable Constraints` |
| GQ-005 | validation plan | `Validation` or `Validation Plan` |
| GQ-006 | first-checkpoint readiness | `First Checkpoint` or `Checkpoints` with first `T###` item |

Every observed claim includes a precise goal heading citation. Missing required
claims are `inferred_gap` records. The result exposes explicit `unknown` and
`operator_decision` records as separate classifications; unknown native
Desktop behavior is never promoted by a local quality result.

## State Reconciliation

The optional state identity fields `goal_id` (or `goal.slug`) and
`first_checkpoint` are read when present. If a goal `Goal ID:` marker and state
`goal_id` disagree, or state `first_checkpoint` disagrees with the first goal
checkpoint, assessment fails with `contradictory_sources:<field>`. Missing
optional state metadata is reported as an unknown rather than fabricated.

## Result Shape

Successful assessments emit canonical, key-sorted JSON with:

```text
schema_version, status, sources, claims, gaps, unknowns,
operator_decisions, questions, recommendations
```

`status` is `ready` only when all six required claims are observed and the
durable sources agree. Otherwise it is `needs_intake`. Questions are stable,
actionable, and capped at three; recommendations retain every discovered gap.
The output has no heuristic score.

## Fail-Clear Errors

The runtime returns JSON with `status: error` and one of these stable codes:

- `repository_root_invalid`
- `repository_root_symlink_forbidden`
- `path_absolute_forbidden:<label>`
- `path_parent_escape_forbidden:<label>`
- `input_symlink_forbidden:<label>`
- `path_outside_root:<label>`
- `input_missing:<label>`
- `input_not_regular:<label>`
- `goal_malformed:<detail>`
- `state_malformed:<detail>`
- `contradictory_sources:<field>`
- `unsupported_input:transcript`

The error channel is local validation evidence, not a fallback or a claim that
the goal is ready.

## Authority And Handoff

The assessor may recommend bounded intake questions, but Parent Codex remains
the only authority to change scope, grant authority, approve execution, or
accept T002. A `ready` result is only a source-cited intake handoff for later
T003 work; it is not Desktop bridge, GoalBuddy, installation, or final UX
proof.
