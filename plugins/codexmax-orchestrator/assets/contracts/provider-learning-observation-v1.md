# Provider Learning Observation v1

## Boundary

`ProviderLearningObservationV1` is an append-only, source-local, shadow-only
record. It consumes one digest-valid T179 `attempt_terminal_observed` event
from a semantically validated Supervisor receipt. The exact complete event
must occur once in that receipt.
Creation and append also require the separately retained
`expected_receipt_sha256`. They pass this anchor to Supervisor validation. A
coherent whole-receipt and event rewrite fails against the stale retained
anchor even when the attacker recomputes all internal digests.
It does not copy the normalized event's `raw_evidence` object. It records only
the closed event facts, event digest, raw-evidence digest, provider-facts
digest, exact binding digest, and a privacy-safe binding projection.

The projection contains the exact route, provider, model, transport, adapter
ID, adapter version, qualification ID and digest, capability-card digest,
adapter-harness digest, lane profile, effective primitives, and capability
digest. The source facts also retain the Supervisor receipt digest.
The lane profile is the task class. Create and append derive the observed stage
from the normalized event's `stage`. The stage must be one of the nine closed
T180 stages. A caller cannot select the stage or task class.

The learner has three dispositions: `propose`, `abstain`, and `reject`. A
proposal is a non-executing repair suggestion. It cannot perform a runtime
action, widen authority, enable a route, request a retry, substitute a
provider, accept or fold work, or mutate GoalBuddy. All related effect fields
are constant `false`.

## Fact And Inference Split

The `observed` object contains only these closed facts derived from the stored
source projection and terminal facts:

- stage;
- symptom;
- mutation state;
- retry safety;
- evidence status;
- outcome.

The stages are `admission`, `authentication`, `transport`, `response`,
`tool_request`, `tool_execution`, `artifact_validation`,
`mutation_reconciliation`, and `receipt_finalization`. Each stage has one
closed failure symptom. This keeps admission, authentication, transport,
response, tool-request, tool-execution, artifact-validation,
mutation-reconciliation, and receipt-finalization failures distinct.

The `inferred` object contains only probable fault domain, confidence, and
proposed repair. An inferred cause never changes an observed fact. Unknown
evidence produces unknown confidence. It does not become zero or known.

The Python validator recomputes outcome, symptom, retry safety, dimensions,
probable fault, confidence, proposed repair, learner disposition, reason,
conditional repair, and all effects. It rejects a mismatch even when every
changed value is in the closed vocabulary and the observation digest was
recomputed. It also parses both timestamps as RFC3339 UTC values.

## Conditional Repair

The learner may propose only when all these facts are true:

- the terminal outcome is a known failure;
- the stage is admission, authentication, or transport;
- mutation state is `none`;
- retry safety is `safe_pre_execution`;
- evidence status is `known`.

The proposal names the same adapter ID and version. It requires a new Parent
decision. It sets `same_provider_only` to true. It keeps `retry_allowed` and
`provider_substitution` false.

Possible, confirmed, or unknown mutation always prevents a proposal. An
`execution_unknown` terminal state always prevents a proposal. Failures after
execution starts also prevent a proposal. The learner abstains in each case.
Invalid or authority-bearing candidate artifacts are rejected by validation.

## Append-Only Chain

Each JSON Lines row has a monotonic sequence, the prior row digest, and its own
canonical digest. The first row uses the all-zero SHA-256 value. Append takes
an exact expected head under an exclusive file lock. A stale head, duplicate
observation ID, changed prior row, malformed row, or digest mismatch fails
closed. Existing bytes are not rewritten.

Self-consistency is not provenance. An actor that controls the complete ledger
can replace source facts and recompute the complete self-chain. A trusted
caller must retain the accepted head outside the ledger. Ledger consumption
must require this external expected head. All public ledger read, verify, and
aggregate functions require it. CLI `verify` and `aggregate` also require
`--expected-head`. A self-consistent ledger with a different head fails
as `external_head_mismatch`. The external head is the provenance checkpoint;
the self-chain is only the same-ledger integrity check.

## Performance Aggregation

Aggregation produces separate tables for exact model, transport, adapter
version, effective primitive, and task class. It also produces a joint identity
bucket keyed by the exact model, transport, adapter version, primitive, and
task class tuple. Each bucket records success, failure, unknown outcome, closed
failure tags, and these measurements:

- quality score;
- turns;
- latency in milliseconds;
- input, output, and total tokens;
- cost in US dollars.

Each measurement is either known with a nonnegative value or unknown with a
closed reason. Aggregation counts unknown values separately. A bucket with no
known values reports null sum and average. It never converts unknown to zero.

## Privacy

Learning artifacts reject prompt, credential, secret, private-configuration,
browser-profile, transcript, message, content, body, and raw-evidence fields at
any depth. Task class and identity values are bounded descriptors. Provider raw
evidence stays outside the learning ledger and is referenced only by digest.

## Proof Boundary

This contract, schema, source, and focused tests prove only local shadow
behavior. They do not prove provider execution, route quality, installation,
service operation, production learning, runtime repair, acceptance, or release.

The JSON Schema closes the artifact vocabulary and encodes feasible
conditional invariants. JSON Schema cannot compare arbitrary sibling values or
prove that a projection came from the named external event digest. Consumers
must run `validate_observation` for semantic self-consistency and must compare
the ledger against the accepted external head for provenance.
