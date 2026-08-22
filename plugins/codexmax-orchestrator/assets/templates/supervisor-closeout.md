# Supervisor Closeout: <Goal Or Checkpoint>

## Identity

- Goal:
- Checkpoint:
- Parent task:
- Supervisor task:
- Routes used:
- Status: `candidate_complete | needs_revision | needs_reassignment | needs_parent_repair | waiting_external`
- Proof boundary:
- Local-only or installed/published boundary:

## Outcome

- Outcome:
- Acceptance oracle result:
- Proof boundary:
- Requested parent decision: `accept | repair_directly | issue_revision_packet | waiting_external`

## Board And Artifacts

| Task | Owner | Route | Status | Artifact | Validation |
| --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |

## Files Changed

-

## Route And Cost Ledger

| Lane | Provider | Model | Runtime | Route ID | Billing basis | Tokens | Quota | Marginal cost | Wall time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  | `unknown` | `unknown` | `unknown` | `unknown` |

## Commands And Validation

| Command | Exit status | Result | Evidence |
| --- | --- | --- | --- |
|  |  |  |  |

## Verification Chain

- Worker self-test:
- Independent Tester:
- Documenter normalization:
- Randomized Auditor:

## Input Access Ledger

Use the [Provider Task Input Contract](../contracts/provider-task-input.md).

| Lane | Required access | Actual delivery | Computed gate | Declared gate | Receipt status | Unsupported claim IDs | Disposition |
| --- | --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  |  | `complete | missing | contradictory | unknown` |  |  |

## Rejected Claims And Revisions

| Claim ID or receipt | Rejection reason | Preserved evidence | Revision or reassignment | Retest obligation |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

## Receipt Repair Ledger

| Lane | Technical work | Receipt | Transition | Original | Repaired | Command-results digest | Source/workload mutation |
| --- | --- | --- | --- | --- | --- | --- | --- |
|  | `valid | invalid | unknown | not_applicable` | `valid | invalid | missing | unknown | not_applicable` | `receipt_only | implementation_revision | targeted_evidence_recovery | no_repair` |  |  |  | `none | detected` |

## Cost And Capacity

- Subscription routes consumed:
- Metered incremental cost:
- Local compute measurement:
- API-equivalent value:
- Quota and token gaps:

## Supervisor Efficiency

- Max-turn safety ceiling:
- Commands completed:
- Command-output characters:
- Largest command output:
- Raw-transcript reads:
- Self-transcript reads:
- Cumulative input tokens:
- Cached input tokens:
- Uncached input tokens:
- Output and reasoning tokens:
- Efficiency checkpoints crossed:
- Compaction, delegation, or narrowing actions:
- Usage summary artifact:

## Worker Progress And Reassignment Ledger

| Lane | Mode | Thresholds crossed | First transition path | Command index | Wall time | No-progress action |
| --- | --- | --- | --- | --- | --- | --- |
|  | `write_worker | read_only` |  | `unknown` | `unknown` | `unknown` |  |

For every replacement, record the predecessor terminal receipt, same-scope
status, replacement-only identity provenance, actual provider, model, runtime,
route id, commands, command-output characters, token counts, wall time, and
first transition. Every unavailable value uses `unknown` with a reason. Never inherit identity or accounting from the predecessor.

## Failed Attempts And Salvage

-

## Risks And Unknowns

-

## Parent Handoff

- Produced:
- Not produced:
- Safe to use:
- Must verify:
- Suggested direct parent repair:
- Suggested next queue:
- Requested parent decision: `accept | repair_directly | issue_revision_packet | waiting_external`

## Normalization Receipt

- normalized_from:
- normalized_by:
- original_artifacts_preserved:
- semantic_changes: none
