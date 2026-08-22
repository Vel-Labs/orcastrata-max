# Codexmax WorkGraph v1 Work Item Contract

Clarity lint is progressive. A `direct` item reports only missing direct
fields; it never requires bounded or governed placeholders. Bounded and
governed items report their exact tier-specific missing fields in
`summary.clarity_lint`.

## Purpose And Authority Boundary

WorkGraph v1 is a versioned, deterministic description of execution work. One
document can describe goals, checkpoints, tickets, tasks, subtasks, tests,
audits, and decision requests. It does not replace GoalBuddy board truth.
GoalBuddy `state.yaml` remains the canonical accepted task and checkpoint
state, and Parent Codex remains the only acceptance authority.

`workgraph.py` is the executable validator for this contract. The exchange
schema is `assets/templates/workgraph-schema.json`. Unsupported versions,
unknown fields, invalid graph references, and authority ambiguity fail closed.
Validation produces a candidate technical receipt only; it never grants write
scope, changes `state.yaml`, or accepts a Work Item.

## Document Shape

A WorkGraph document contains exactly:

- `schema_version`: integer `1`;
- `graph_id`: a nonempty stable identifier;
- `evidence`: structured evidence and expected-artifact references;
- `work_items`: one or more Work Items.

Every object is strict. Unrecognized fields are errors rather than ignored
forward extensions. A future protocol version must negotiate and migrate
explicitly instead of being treated as v1.

## Work Item Identity And Kinds

Every Work Item has one unique `id` and one kind:

`goal`, `checkpoint`, `ticket`, `task`, `subtask`, `test`, `audit`, or
`decision`.

WorkGraph execution status is limited to `queued`, `active`, `blocked`,
`ready_for_review`, `candidate_complete`, `needs_revision`,
`needs_reassignment`, `needs_parent_repair`, and `waiting_external`.
`accepted` and `done` are deliberately absent: accepted board state belongs to
GoalBuddy and its Parent-reviewed update path.

## Progressive Clarity Tiers

Requirements only grow as the tier grows.

| Tier | Required fields | Intended use |
| --- | --- | --- |
| `direct` | identity, kind, objective, execution status, scope, done condition, validation | one low-risk bounded change with no governance ceremony |
| `bounded` | every direct field plus relationships, owner role, expected artifacts, retry policy, and stop rule | a dependency-aware delegated work packet |
| `governed` | every bounded field plus identity provenance, external/provider policy, authority, independent verification, receipts, recovery, and pending Parent acceptance | high-consequence or acceptance-bearing checkpoints |

The word `identity` in the direct row means the stable Work Item `id`, not a
provider identity packet. Provider and runtime identity is governed-only.
Making a direct item valid must not require placeholder governed fields.

## Relationship Semantics

The five relationship lists are separate namespaces and retain their
direction:

- `parent_of`: the source Work Item contains the target Work Item;
- `blocked_by`: the source Work Item cannot proceed until the target Work Item;
- `related_to`: symmetric context that never blocks readiness;
- `produces`: the source Work Item produces a target evidence/artifact ID;
- `consumes`: the source Work Item consumes a target evidence/artifact ID.

Work Item relations target existing Work Item IDs. Artifact-flow relations
target existing evidence IDs. Self references, missing targets, duplicate
references, containment cycles, dependency cycles, multiple parents,
non-reciprocal contextual links, and producing and consuming the same evidence
from one item are invalid. `related_to` is never interpreted as `blocked_by`.

T004 adds runtime readiness, claims, leases, and recovery. This T002 contract
only validates the static graph and does not claim runtime scheduling.

## Scope, Validation, Retry, And Stop

Scope contains explicit `read` and `write` lists. They describe the packet but
do not grant authority. Validation rows have a unique ID, kind, instruction,
and expected result; validation text is not a recorded pass. Bounded and
governed items name positive retry limits, a no-improvement window, expected
artifact IDs, an owner role, and a nonempty stop rule.

## Evidence References

Evidence records contain:

- unique `id`;
- `kind`: `artifact`, `command_result`, `receipt`, or `source_reference`;
- nonempty `locator`;
- `digest`: literal `unknown` or `sha256:` plus 64 lowercase hexadecimal
  characters;
- `state`: `expected`, `observed`, `validated`, or `rejected`;
- unique `claim_ids`;
- `authority_effect: none`;
- `acceptance_effect: none`.

Validated evidence requires a SHA-256 digest. Evidence can support a claim but
cannot grant scope, provider access, capability, state mutation, or acceptance.
Expected artifacts must exist in the evidence registry and appear in their
Work Item's `produces` relationship. Governed receipt references must name
evidence of kind `receipt`.

## Governed Identity Provenance

Governed items keep role identity separate from agent, provider, model, route,
runtime, billing, source-access, command, token, cost, and capability facts.
Each fact is a `{value, provenance}` pair. Unknown values use literal
`unknown` with provenance `unknown`. Known values require known provenance.

Identity provenance may be `declared`, `parent_assigned`,
`runtime_observed`, or `receipt_backed`. A declared model or provider never
upgrades capability. Capability and token/cost measurements can be known only
with `runtime_observed` or `receipt_backed` provenance. Capability keys are
independently recorded for filesystem, browser, command, network, connector,
and billing access. Missing telemetry remains `unknown`; zero is valid only
when an observed or receipt-backed measurement reports zero.

## Governed Authority And Parent Acceptance

Authority is explicit and must be `operator_issued` with an `operator:` source
or `parent_issued` with a `parent:` source. It names a structured receipt ID,
write scope, and forbidden actions. The receipt ID must exist, have evidence
kind `receipt`, and appear in the Work Item receipt list; scoped writes must be
contained by the authority write list. In a WorkGraph document, `may_accept` and
`may_mutate_canonical_state` are always false. A Worker-authored or declared
authority row is invalid.

Provider policy records source access, input delivery, command executability,
billing, token limit, and fallback separately. Names and configuration do not
prove any of them. A null token limit is allowed and does not relax retry,
recovery, independent-verification, or stop controls.

Governed items require Tester or Auditor independence, durable failed-attempt
and changed-file preservation, an explicit failure route, and a Parent
acceptance requirement whose only v1 WorkGraph status is `pending`. Accepted
state must be reconciled from canonical GoalBuddy state rather than promoted
inside this execution document.

## Determinism And Failure Behavior

Library entry point:

```python
receipt = validate_document(document)
```

CLI entry point:

```sh
python3 <plugin-root>/scripts/workgraph.py validate <workgraph-document.json>
```

Both paths are import-safe and deterministic. Successful validation exits `0`.
Malformed JSON, unavailable input, or contract failure exits `2`. CLI output
is one canonical, key-sorted JSON object. Errors are stable strings sorted and
deduplicated. The receipt includes graph ID, schema version, Work Item and
evidence counts, clarity-tier counts, status, errors, and the exact input-file
SHA-256 when a file was read.

Validation does not mutate the input object or source file. It does not execute
embedded commands, read evidence locators, infer provider capability, inspect
GoalBuddy state, or make an acceptance decision.

## Deterministic Fixtures

- `workgraph-direct.json`: minimal direct task without bounded or governed
  ceremony;
- `workgraph-bounded.json`: dependency and artifact-flow example;
- `workgraph-governed.json`: unknown-honest identity, receipt, recovery,
  independent verification, and Parent-pending example;
- `workgraph-adversarial.json`: deterministic mutation cases with exact
  expected errors;
- `workgraph-schema.json`: version-pinned exchange schema.

The focused suite validates both library and CLI behavior, all positive
fixtures, every Work Item kind, tier progression, graph direction, duplicate
IDs, evidence non-authority, self-granted authority rejection, identity and
capability separation, malformed input, deterministic output, and input
immutability.
