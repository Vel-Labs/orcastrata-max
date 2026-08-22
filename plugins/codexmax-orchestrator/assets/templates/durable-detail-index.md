# Durable Detail Index: <Run Or Checkpoint>

## Identity And Boundary

- Proof boundary: <local | installed | pushed | published | waiting_external | complete>; <exact limitation>
- Parent acceptance evidence: <repository-relative path plus SHA-256, or not_applicable>
- Changed files: <complete inventory>

## Route And Cost Ledger

| Lane | Provider | Model | Route ID | Runtime | Billing basis | Fallback | Token cap | Tokens | Quota | Marginal cost | Runtime measurement |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
|  |  | `unknown` |  |  |  |  | `null | non-null value` | `unknown` | `unknown` | `unknown` | `unknown` |

## Commands And Validation

| Exact command | Exit status | Execution status | Result | Evidence path | Evidence SHA-256 |
| --- | ---: | --- | --- | --- | --- |
|  |  | `completed | failed | not_run | not_applicable` | `pass | fail | not_run | not_applicable` |  |  |

## Input Access And Claims

| Lane | Source category | Source label | Read status | Claim IDs | Source basis | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  |  | `local_file | connector | embedded` |  |

## Failures, Rejections, Repairs, And Risks

| ID | Kind | Observed state | Preserved evidence | Disposition | Remaining risk |
| --- | --- | --- | --- | --- | --- |
|  | `failure | validation_gap | rejected_claim | revision | repair | risk` |  |  |  |  |

## Normalization Receipt

- normalized_from: <repository-relative source path>
- normalized_by: <role or tool identity>
- source_sha256: <64 lowercase hexadecimal characters>
- output_sha256: <64 lowercase hexadecimal characters recorded by the separate compact summary or index receipt>
- semantic_changes: none

Unknown telemetry remains `unknown`, never zero. Preserve original artifacts.
Use the authority-bearing Supervisor closeout rather than this index to request
Parent acceptance; a compact summary may hash-link either artifact.

This is an instructional template, not an executable renderer or reusable
validator. Its fields do not prove runtime behavior.
