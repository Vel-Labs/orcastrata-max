# Milestone Update

- Outcome and status: <outcome; canonical operational status>
- Proof boundary: <local | installed | pushed | published | waiting_external | complete>; <exact limitation>
- Material failure or blocker: <decision-relevant failure, rejected claim, validation gap, or external condition; none only when none is known>
- Decision needed: <operator or Parent decision; none when existing authority covers the next action>
- Next action: <owner and action>
- Durable detail: <repository-relative normalized path>
- Detail SHA-256: <64 lowercase hexadecimal characters>
- Detail integrity: <verified | failed: reason>
- Milestones complete: <integer>
- Milestones total: <integer>
- Current milestone: <milestone id and outcome, or none>
- Current gate: <gate name and status>
- Exact blocker: <exact blocker, or none>
- Next milestone: <milestone id and outcome, or none>

## Compact Attempt History

| Package | Attempt | Candidate | Validation | Repair | Receipt |
| --- | --- | --- | --- | --- | --- |
| <package identity> | <attempt identity> | <candidate identity> | <validation identity and result> | <repair identity or none> | <path or digest> |

Append an attempt row after each failure or repair. Do not replace a failed row
when a later candidate passes.

Keep this surface usable without opening durable detail. Do not add raw
transcripts or complete command, claim, provider, or telemetry ledgers. Keep
every decision-relevant exception visible and verify the detail digest against
the current file before emitting `verified`.

This is an instructional template, not an executable renderer or reusable
validator. Its fields do not prove runtime behavior.
