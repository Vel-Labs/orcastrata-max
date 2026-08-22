# <Role> Result: <Run ID>

## Identity

- Run ID:
- Task ID or round:
- Provider:
- Model:
- Runtime:
- Route ID:
- Preferred route:
- Fallback route used:
- Role:
- Artifact status: `assigned | pending | in_progress | ready_for_review | candidate_complete | needs_revision | needs_reassignment | needs_parent_repair | waiting_external`
- Billing basis: `native_included | subscription | local_compute | metered_api | unknown`
- Token measurements:
- Quota measurements:
- Marginal cost:
- Runtime measurements:

## Outcome

- Outcome:
- Proof boundary:
- Requested state transition:

## <Role-Specific Work>

-

## Input Access Receipt

- Declared source access: `local_filesystem | embedded_only | connector_resource | mixed | none | unknown | unverified`
- Actual input delivery: `paths_only | embedded_fact_pack | connector_references | mixed | none | unknown | unverified`
- Commands executable: `yes | no | unknown`
- Compatibility gate decision: `compatible | incompatible | not_required | unknown`
- Compatibility gate reason: `unknown`
- Sources observed: `[]`
- Sources unavailable: `[]`
- Sources not supplied: `[]`
- Explicit unknowns: `[]`

The three source disposition lists contain named source category IDs. They must
be mutually consistent and agree with the read-status rows below. Include
exactly one complete row per named category, including categories that were
unavailable or not supplied.

| Source category | Source label | Read status | Supported claim IDs | Evidence |
| --- | --- | --- | --- | --- |
|  |  | `read_local | read_connector | received_embedded | unavailable | not_supplied | not_read | unknown | unverified` |  |  |

## Evidence And Claims

| Claim ID | Claim | Classification | Source category | Source basis | Evidence | Disposition |
| --- | --- | --- | --- | --- | --- | --- |
|  |  | `Observed | Validated | Inferred | Proposed | Unknown` |  | `local_file | connector | embedded` |  |  |

## Validation

| Command or check | Exit status | Execution status | Result | Evidence boundary |
| --- | --- | --- | --- | --- |
|  |  | `completed | failed | not_run | not_applicable` | `pass | fail | not_run | not_applicable` |  |

## Files Changed

-

## Route And Cost Ledger

| Lane | Provider | Model | Route ID | Billing basis | Tokens | Quota | Marginal cost | Runtime |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
|  |  |  |  |  | `unknown` | `unknown` | `unknown` | `unknown` |

## Risks And Gaps

- Risk:
- Unknown:
- Untested surface:

## Handoff

- Produced:
- Not produced:
- Validated:
- Not validated:
- Safe to use:
- Must verify:
- Next owner:
- Requested state transition:
- Parent decision requested:
