# Provider Normalized Events v1

## Boundary

`scripts/provider_event_normalizer.py` converts provider transport evidence into
one closed event vocabulary. It validates evidence. It grants no capability,
eligibility, task authority, retry, fallback, acceptance, fold, or board
mutation.

The vocabulary is:

1. `admission_observed`
2. `binding_observed`
3. `spawn_observed`
4. `response_observed`
5. `tool_request_observed`
6. `tool_result_observed`
7. `artifact_validation_observed`
8. `mutation_reconciliation_observed`
9. `receipt_finalization_observed`
10. `attempt_terminal_observed`

No extension event is valid. The terminal states are `succeeded`, `rejected`,
and `execution_unknown`.

## Exact Attempt Binding

Every event binds all of these values:

- route name and provider;
- exact model;
- provider transport;
- adapter ID and adapter version;
- universal qualification ID and canonical digest;
- capability-card digest and adapter-harness digest;
- lane ID, lane profile, and mutation mode;
- task-grant ID and digest;
- lease ID, fencing token, and digest;
- worktree path and identity digest;
- evidence root;
- attempt ID and attempt index;
- capability, qualification, grant, execution-binding, and effective expiry;
- effective capability and its digest;
- timestamp;
- raw evidence and its digest.

The effective expiry is the minimum of the other four expiries. The effective
capability is the exact intersection of lane requirements, adapter support,
current model qualification, and task-grant capability.

The qualification binds the exact adapter ID, adapter version, provider
transport, provider, and model. Its evidence digests include the exact adapter
harness digest. The capability card names the same qualification digest.

## Provider Facts

Normalization preserves provider-specific identity, billing, safety, and
mutation facts as four separate objects. It also preserves the complete bounded
raw evidence object and records its canonical digest. A generic event cannot
replace or erase these facts.

## Ordering And Uncertainty

Events for one attempt use one immutable binding. Event types occur at most
once and in vocabulary order. A tool result requires an earlier tool request.
Mutation reconciliation is valid only for a scoped-write lane.

`possible` or `unknown` mutation cannot terminate as `succeeded` or `rejected`.
It terminates as `execution_unknown`. Normalized events always keep retry,
fallback, hedging, authority, Parent acceptance, GoalBuddy mutation, and fold
false.

The schema is
`assets/templates/provider-normalized-event-v1-schema.json`.
