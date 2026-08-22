---
name: codexmax-verify
description: "Public Audit entry — Verify self-tests, independent testing, claim evidence, and Parent acceptance without hiding failures."
---

# Codexmax Verify

Read the [Provider Task Input Contract](../../assets/contracts/provider-task-input.md)
and reuse its fail-closed validation logic. Do not create a second compatibility
or receipt engine.

Select the smallest verification set that can detect a material defect:

```text
changed behavior -> focused proof -> risk-based independent check when useful
-> Parent review -> release/global proof only when the boundary requires it
```

- Builder runs focused repository-native checks for the changed behavior.
- Add Tester only when independent reproduction, a user path, or a distinct
  negative or boundary case can change the acceptance decision.
- Add Documenter only when user-facing instructions or a durable handoff
  changed. Documentation does not create technical proof.
- Add Auditor for high-consequence changes, release gates, or material claims
  whose independence changes confidence.
- Parent Codex reviews the diff and evidence and decides acceptance.
- Run the repository full suite once only for a frozen release candidate,
  migration or destructive scope, shared-runtime change with unknown global
  impact, or another named repository-wide acceptance boundary.

Do not add a lane, test, fixture, receipt, or rerun only to make the process
look complete. Reuse a passing result when the tested source and relevant
environment are unchanged. A changed hypothesis can justify a new focused run;
an unchanged failure does not justify repetition.

A passing style validator is not technical proof. A passing unit test is not
proof of untested workflows. Record `not_run`, `not_applicable`, and `unknown`
without converting them to success.

## Loop Evidence Checks

For LoopRegistry work, read the frozen registry and event contracts, then use
`$codexmax-orchestrator:codexmax-loop` to validate the exact registry, event,
match/dry-run result, and `LoopRunReceipt v1`. Check lifecycle transitions,
source/reference identity, contained scope, fixed profile IDs, freshness,
dedupe/recursion guards, budgets, validation rows, artifact state, and proof
booleans. Retain every stable rejection code.

The accepted T020 boundary proves only deterministic local validation,
matching, receipt verification, and dry-run. `matched` is not `admitted`;
`executed: false` is not execution proof; an unknown digest cannot satisfy
`proved`; and `not_run`, `unknown`, `rejected`, or failed evidence never becomes
pass through prose. Installed projection, live hook, active scheduler,
connector delivery, publication, GoalBuddy transition, WorkGraph application,
and Parent acceptance require separate current evidence.

For scheduler-backed lifecycle work, use the strict
`TrustedCommandReceipt v1` and role packet in
[the role-lifecycle contract](../../assets/contracts/role-lifecycle.md).
Worker self-test commands must equal the frozen assignment; a scheduled Tester
pass must agree with separate controller-recorded passing command rows. A
provider artifact, prose assertion, route identity, or transport success cannot
stand in for this evidence.

## Input Receipt Checks

For each material claim, require a stable claim ID and exactly one named source
row in the lane's `Input Access Receipt`. The row must list the ID in
`supported_claim_ids`; its read status, declared access, actual delivery, and
the claim's `source_basis` must agree:

- `local_file` requires `read_local` with declared local-filesystem access;
- `connector` requires `read_connector` with declared connector access;
- `embedded` requires `received_embedded` and remains an embedded fact.

Use the package-local `provider_input_compatibility_gate_errors` helper in
`../../scripts/provider_input_compatibility.py` and validate the returned
artifact with `../../scripts/validate_dispatch_artifact.py`. Recompute the
packet gate and fail closed on missing, duplicate, unsupported, unavailable,
not-read, unknown, or contradictory rows. Preserve rejected claims and their
revision route in the closeout rather than silently dropping them.
When repository source is available, also run its
`provider_result_receipt_errors` validation. An installed package must use the
package-local artifact validator and must not depend on a repository-only
path.

Validate command rows against the canonical execution/result matrix in the
[Provider-Neutral Writing Contract](../../assets/contracts/provider-neutral-writing.md).
A `pass` requires completed execution and `commands_executable: yes`; command
capability alone is never a pass, and `not_run` remains `not_run`.

## Evidence Checks

For each material claim, also require at least one durable proof surface:

- file path plus relevant section or line;
- exact command and exit status;
- raw command log or transcript path;
- test name and result;
- install, invocation, deployment, or runtime receipt;
- independent Tester or Auditor artifact.

Classify each claim as `Observed:`, `Validated:`, `Inferred:`, `Proposed:`, or
`Unknown:`. Inference is allowed only when the evidence is named and the gap is
clear.

## Receipt Repair Checks

Run `receipt_repair_transition_errors` for every declared repair. A
`receipt_only` transition requires valid technical work, an invalid or missing
receipt, hash-verified original and repaired regular files beneath the evidence
root, exactly one filesystem link per evidence file, distinct resolved
files/inodes, verified distinct source-tree and command-ledger manifests before
and after, and identical accepted-command-result digests. Hard-linked evidence
and empty self-reported source-change or workload-rerun lists are not evidence.
Invalid work must use `implementation_revision`; unknown work must use
`targeted_evidence_recovery`; valid work with a valid or not-applicable receipt
must use `no_repair`, while a valid but unknown receipt requires targeted
recovery. Missing input-access evidence cannot be repaired
by prose.

## Negative And Boundary Proof

Independent testing should add one useful negative, boundary, or user-path
check when practical. Examples:

- invalid task packet or missing required field;
- forbidden write scope;
- failed route fallback;
- style or schema violation;
- cache-only install evidence when fresh invocation is required;
- command failure that must remain visible in closeout.

## Acceptance Rules

- Only the final Owner or Parent session may run the acceptance full suite. Its
  receipt must bind the exact frozen source revision and record one run for that
  revision.
- A Worker, Tester, Documenter, or Auditor full-suite result is
  non-authoritative, must remain disclosed as wasted work, and cannot satisfy
  the acceptance gate.
- A report-only correction after the Owner pass receives artifact validation
  only. An implementation repair creates a new source revision and returns to
  focused proof before one new Owner full-suite run.
- Worker self-test can make an artifact reviewable, not accepted.
- Tester reproduction can make behavior credible, not accepted.
- Documenter normalization can make evidence readable, not accepted.
- Auditor review can recommend acceptance, repair, revision, or waiting
  external, not decide final completion.
- Parent Codex accepts only after comparing the closeout to the goal oracle,
  allowed scope, validation ladder, and residual risks.
