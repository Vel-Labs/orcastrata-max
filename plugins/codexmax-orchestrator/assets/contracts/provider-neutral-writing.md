# Provider-Neutral Writing Contract

## Purpose

Outputs from different providers should read like one coherent engineering
system without erasing provider identity, evidence, uncertainty, or defects.
This contract governs result artifacts, handoffs, boards, test receipts,
documentation, and audits. It does not alter raw transcripts.

## Authority Order

When instructions conflict, use this order:

1. repository and workspace contracts;
2. run-local task and acceptance criteria;
3. role packet;
4. this writing contract;
5. provider defaults or stylistic habits.

## Canonical Voice

- Use direct, factual engineering prose.
- Lead with outcome and proof boundary.
- Prefer active voice and concrete subjects.
- Keep paragraphs short and headings descriptive.
- Name exact files, commands, statuses, and remaining gaps.
- Separate observed fact, inference, proposal, and decision.
- Use `unknown`, `not_run`, or `not_applicable` instead of filling gaps.
- Use first person only for explicit actions or assumptions, not personality.

Avoid:

- greetings, congratulations, reassurance, or conversational filler;
- provider self-reference such as "as an AI";
- marketing language and unsupported quality adjectives;
- decorative symbols, emoji, fake quotations, or theatrical narration;
- declaring success from intent, confidence, or a file listing;
- relabeling a failed check as partial success.

## Standard Result Shape

Every result artifact uses these top-level headings in this order. Role-specific
sections may appear between `Outcome` and `Evidence`.

```text
# <Role> Result: <Run ID>

## Identity
## Outcome
## Evidence
## Validation
## Risks And Gaps
## Handoff
```

`## Input Access Receipt` is the canonical role-specific section for every
provider-neutral lane result and appears between `Outcome` and `Evidence`. Its
fields and enums come from the
[Provider Task Input Contract](provider-task-input.md). Missing fields,
contradictory rows, and explicit unknowns remain visible and fail closed at
integration; prose elsewhere in the artifact cannot repair the receipt.

Required identity fields:

- run id;
- task id or round;
- provider;
- model;
- runtime;
- route id;
- role;
- artifact status.

## Canonical Operational Status

Use:

- `assigned`
- `pending`
- `in_progress`
- `ready_for_review`
- `candidate_complete`
- `needs_revision`
- `needs_reassignment`
- `needs_parent_repair`
- `waiting_external`
- `accepted`
- `rejected`

Only the parent arbiter may emit `accepted` or terminal `rejected`. Worker-level
failure is a revision or reassignment event. Use `waiting_external` only when
progress requires a credential, approval, physical action, unavailable service,
or another condition no model can resolve.

Legacy benchmark mappings:

| Legacy | Current |
| --- | --- |
| `blocked` | `waiting_external` or `needs_parent_repair`, with reason |
| `done` | `candidate_complete` until parent acceptance |
| `needs_rerun` | `needs_revision` or `needs_reassignment` |

Do not rewrite historical artifacts solely to update vocabulary.

## Evidence Language

- `Observed:` means directly read or returned by a command.
- `Validated:` means a named check ran and its result is recorded.
- `Inferred:` means evidence supports a conclusion but does not directly prove it.
- `Proposed:` means no implementation or acceptance is claimed.
- `Unknown:` names a measurement or fact that is unavailable.

Material claims require a path plus line, section, command, or durable receipt.
Commands are copied exactly. Summaries may follow but cannot replace raw command
evidence owned by the runtime or arbiter.

Each material claim records one stable claim ID, one named source category, and
one canonical source basis. Exactly one receipt source row must list the claim
ID in `supported_claim_ids`, and its access, delivery, and read status must
support that basis.

## Validation Execution And Result Matrix

The following is the complete allowed matrix. These pairs define command-state
consistency only; `completed/pass` additionally requires
`commands_executable: yes`.

<!-- validation-execution-result-pairs:start -->
```json
{
  "allowed": [
    ["completed", "pass"],
    ["completed", "fail"],
    ["completed", "not_run"],
    ["completed", "not_applicable"],
    ["failed", "fail"],
    ["failed", "not_run"],
    ["failed", "not_applicable"],
    ["not_run", "not_run"],
    ["not_applicable", "not_applicable"]
  ]
}
```
<!-- validation-execution-result-pairs:end -->

| Execution status | `pass` | `fail` | `not_run` | `not_applicable` |
| --- | --- | --- | --- | --- |
| `completed` | allowed | allowed | allowed | allowed |
| `failed` | rejected | allowed | allowed | allowed |
| `not_run` | rejected | rejected | allowed | rejected |
| `not_applicable` | rejected | rejected | rejected | allowed |

The conservative `completed/not_run`, `completed/not_applicable`,
`failed/not_run`, and `failed/not_applicable` compatibility pairs are preserved
for backwards compatibility. They do not assert successful validation.

## Code And Product Writing

When changing source code, documentation, comments, errors, or user-facing copy:

- preserve repository naming and domain vocabulary;
- prefer existing helpers, schemas, and message patterns;
- keep comments about decisions or constraints, not obvious mechanics;
- do not introduce a new tone or terminology for one provider's patch;
- treat public copy and error messages as owned interfaces;
- include tests or readback checks for materially changed messages.

## Handoff Shape

Every handoff states:

- produced;
- not produced;
- validated;
- not validated;
- safe to use;
- must verify;
- next owner;
- requested state transition;
- parent decision requested.

The handoff must be usable without access to private reasoning or the worker's
conversation history.

## Normalization Boundary

The Documenter or parent Codex may create a normalized derivative after Worker
and Tester artifacts exist. Normalization may change headings, ordering,
grammar, and canonical terminology. It must not:

- overwrite raw transcripts or original result artifacts;
- add evidence, validation, or acceptance;
- remove failures, caveats, dissent, or provider/runtime identity;
- change commands, token counts, costs, paths, or test outcomes;
- convert `unknown` or `not_run` into a positive claim.
- convert `received_embedded` into `read_local` or `read_connector`;
- convert unknown or unverified access, delivery, command capability, or gate
  state into a demonstrated capability;
- remove a missing or contradictory input-access receipt or rejected claim.

Record `normalized_from`, `normalized_by`, and `semantic_changes: none`. If a
technical meaning changes, it is a revision and must return to the originating
role or parent, not an editorial normalization.

## Receipt-Only Repair Boundary

Work validity and receipt validity are independent. Route `valid` technical
work with an `invalid` or `missing` receipt to `receipt_only`; route `invalid`
technical work to `implementation_revision`; route `unknown` technical work to
`targeted_evidence_recovery`. Valid work with a valid or not-applicable receipt
uses `no_repair`; a valid but unknown receipt uses targeted recovery. Validate the transition with
`receipt_repair_transition_errors` from the repository validator.

A receipt-only repair:

- verifies the original and repaired artifacts as hash-matching regular files
  beneath one evidence root, with exactly one filesystem link per evidence
  file and distinct resolved paths and file identities; hard-linked evidence
  fails closed;
- changes no source file and reruns no source workload;
- verifies distinct before/after source-tree and closed command-ledger
  manifests, rejects empty manifest payloads, and preserves an exact digest of
  the already accepted command results; and
- corrects only contradicted or missing fields reconstructable from preserved evidence.

Receipt-only repair cannot manufacture a missing input-access observation,
change a test result, or turn unknown technical work into valid work. Provider
output and failed normalization attempts remain preserved. Original and repaired
paths must remain distinct after lexical `.` and `..` normalization.
Worker-authored empty change or rerun lists are declarations only and never
substitute for the manifest evidence.

## Automated Check

Run:

```sh
python3 scripts/validate_artifact_style.py <artifact> [<artifact> ...]
```

The checker catches structural and lexical drift. Passing it does not prove
technical correctness, writing quality, or acceptance.
