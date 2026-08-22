# Iterative Intake Feedback Contract

## Identity

- Goal: `codexmax-desktop-supervision-v1`.
- Checkpoint: `T003`.
- Artifact: local iterative intake contract.
- Authority: Parent Codex remains the sole scope, authority, and acceptance
  authority.

## Outcome

- Outcome: define the bounded durable intake state and mutation behavior used
  by the T003 local runtime.
- Proof boundary: contract and local runtime behavior only; no Desktop bridge,
  GoalBuddy mutation, installed projection, checkpoint acceptance, or goal
  acceptance.
- Requested state transition: `ready_for_review` with Builder implementation.

## Evidence

- T003 Parent contract defines object, lifecycle, authority, replay, and
  adversarial acceptance requirements.
- T003 Scout result maps the exclusive product/test seam and existing
  guided-journey compatibility constraints.
- The runtime and focused tests implement this contract in the authorized T003
  paths only.

## Purpose

`manage_intake_feedback.py` manages a durable, append-preserving local intake
record. It records questions, answers, comments, concerns, suggestions,
assumptions, decisions, and authority proposals without treating transcript
text, a side comment, or a suggestion as authority.

## Inputs And Boundary

The runtime requires explicit repository-relative paths:

```text
--repo-root <directory> --state-path <relative-json-path> --action-path <relative-json-path> --write
```

- The repository root must be a real directory, not a symbolic link.
- State and action paths contain no `..`, resolve to regular non-symlink files
  inside the root, and are never inferred from the current directory.
- The template is JSON-compatible YAML; runtime state and action documents are
  UTF-8 JSON so parsing remains deterministic without a general YAML engine.
- Transcript content, hidden provider context, and implicit authority are not
  inputs. Supplying `--transcript` fails clearly.

## State Shape

The state has stable `intake_id`, append-only `rounds`, append-only `records`,
and append-only `action_log`. Every record has a unique `item_id`, `kind`,
`round_id`, `classification`, `status`, `provenance`, `created_at`, and optional
links/payload. Reapplying an action ID with identical canonical content is an
idempotent no-op; a different payload for the same action ID fails closed.

Allowed record kinds are `question`, `answer`, `comment`, `concern`,
`suggestion`, `assumption`, `decision`, and `authority_proposal`.

## Round And Authority Rules

- `open_round` records explicit material dimensions and safe defaults.
- A round may contain zero material questions when safe defaults suffice; it
  may contain at most three material questions otherwise.
- Non-material questions must be `suppressed` or `informational`; they cannot
  block the round.
- Suggestions, concerns, comments, and authority proposals stay distinct.
  A suggestion may be accepted only through a later Parent-provenance decision.
- An authority proposal is always `pending`; an `approved` proposal or an
  `authority_granted` payload fails with `authority_self_grant_forbidden`.
- A decision that changes authority requires `provenance.authority_source` to
  be `parent_control`; no Worker or side chat can manufacture that authority.

## Result Shape

Successful operations emit canonical key-sorted JSON with `status: ok`, the
updated state, and whether an action was applied or replayed. Stable error JSON
uses `status: error` and one explicit error code. The result is local evidence,
not a scope change, execution approval, checkpoint acceptance, or goal
acceptance.

## Fail-Clear Errors

- `repository_root_invalid`
- `repository_root_symlink_forbidden`
- `path_absolute_forbidden:<label>`
- `path_parent_escape_forbidden:<label>`
- `input_symlink_forbidden:<label>`
- `path_outside_root:<label>`
- `input_missing:<label>`
- `input_not_regular:<label>`
- `input_not_utf8`
- `state_malformed:<detail>`
- `action_malformed:<detail>`
- `duplicate_item_id:<id>`
- `conflicting_replay:<action_id>`
- `material_question_limit:<round_id>`
- `nonmaterial_question_blocking:<item_id>`
- `authority_self_grant_forbidden`
- `unknown_record_kind:<kind>`
- `unsupported_input:transcript`

## Authority And Handoff

Parent Codex alone changes scope, grants authority, approves execution, and
accepts checkpoints or goals. This runtime may preserve an authority proposal
or Parent-provenance decision but never promotes either into acceptance.

## Validation

- Focused mutation tests exercise multi-round records, question bounds,
  provenance, replay, malformed input, root containment, symlink rejection,
  transcript rejection, and deterministic output.
- Repository validation and the complete local unit suite remain required
  Builder checks.
- Artifact style and `git diff --check` are required before handoff.

## Risks And Gaps

- The JSON-compatible YAML template intentionally avoids declaring a general
  YAML parser or accepting arbitrary YAML input.
- This local contract does not prove Parent/Supervisor Desktop synchronization
  or make a side comment into authority.

## Handoff

- Produced: bounded T003 intake contract.
- Not produced: shared guided-journey edits, GoalBuddy mutation, Desktop proof,
  installed projection proof, or acceptance.
- Validated: contract structure against focused runtime tests.
- Not validated: independent T003-J functional audit or Parent acceptance.
- Safe to use: as the local source contract for the T003 Builder result.
- Must verify: complete suite, repository validator, independent mutation audit,
  and scope containment.
- Next owner: T003 Supervisor, then T003-J Tester/Auditor.
- Requested state transition: `ready_for_review`.
- Parent decision requested: none until candidate closeout.
