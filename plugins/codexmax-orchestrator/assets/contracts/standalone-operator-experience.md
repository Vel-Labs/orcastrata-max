# Standalone Operator Experience v1

## Proof and authority boundary

The standalone CLI is a deterministic, structured-output client over accepted
Runtime Foundation, planner, execution-gateway, and Runtime Evidence truth. Its
proof boundary is `synthetic_local`. It does not start or bind a service, call a
provider or network, authenticate, allocate capacity, acquire a lease, dispatch
or mutate a run, write a journal, persist or activate policy, grant authority,
or accept work.

Every successful receipt contains `side_effect_free: true`, a source digest,
and explicit false effect guarantees. Exit `0` means that the input was valid
and the requested view was produced. It is not runtime, quality, Parent,
installation, release, native-route, provider, or AOL acceptance. Typed input
failure exits `2`; a fixture suite with mismatches exits `1`.

## Commands and source truth

| Command | Accepted truth | No-effect result |
| --- | --- | --- |
| `serve` | Accepted closed runtime manifest only; precomputed results unsupported | Says foreground start is separately required; starts nothing. |
| `status` | Accepted closed runtime manifest only; precomputed results unsupported | Declarative lifecycle contract, health, and endpoint view. |
| `routes` | Planner request/result | Every route, hard gates, exact blockers, and separate presentation planes. |
| `plan` | Planner request/result | Same route truth plus selected route and child preview; creates no lease. |
| `run` | Verified gateway state and run ID | Current immutable run view only. |
| `cancel` | Verified gateway state and run ID | Cancel request preview only; state is unchanged. |
| `recover` | Verified gateway state and run ID | Recovery request preview only; state is unchanged. |
| `delegate` | Runtime Evidence packet/receipt | Accepted or denied delegation decision; no child is created. |
| `lineage` | Runtime Evidence packet/receipt | Lineage, checkpoint, and append-only recovery view. |
| `journal` | Runtime Evidence packet/receipt | Scoped journal view; messages remain untrusted and non-executable. |
| `policy-propose` | Closed proposal input | Deterministic diff, validation, explanation, and forward rollback metadata. |

`routes` and `plan` display all planner candidates, including blocked routes.
They do not infer capability from a model or service name. The four read/write
planes remain separate:

1. `observed_capability`: exact positive, active, fresh capability evidence;
2. `role_policy`: the role may request the capability on this route;
3. `task_requirement`: task evidence is bound to the exact task profile;
4. `human_authority`: current task-scoped authority is active and bound.

Billing and health are separate hard-gate planes. `capacity_admitted` is always
false in CLI plan output because planning does not allocate capacity. Preference
is shown only after hard gates pass and cannot repair a failed gate.

## Request and receipt envelope

One input is a closed JSON object:

```json
{
  "cli_version": 1,
  "artifact_type": "standalone_runtime_cli_request_v1",
  "command": "status",
  "input": {}
}
```

Unknown fields, duplicate JSON keys, non-finite values, unsupported versions,
and malformed upstream artifacts fail closed. Inputs are copied and must remain
unchanged. Digests use UTF-8 canonical JSON with sorted keys, compact separators,
and no ASCII escaping.

Precomputed runtime service results are not accepted at all. `serve` and
`status` consume only the closed accepted runtime manifest and display only its
validated declarative truth. Lifecycle operation results and `runtime_json`
identity require the upstream service's filesystem/request boundary and cannot
be reconstructed from a caller-rehashed result, so they remain outside this
no-effect CLI input. A planner result must arrive in a
closed `runtime_plan_binding_v1` envelope with its complete planner request and
result digest; the CLI reruns the accepted planner and requires byte-semantic
JSON equality. A Runtime Evidence receipt similarly requires a closed
`runtime_evidence_binding_v1` envelope with its complete source packet and
receipt digest; the CLI reruns normalization and requires exact equality.

Precomputed runtime results and bare planner or evidence results, partial results, extra nested
fields, missing fields, altered digests, fabricated authority/effects,
executable journal claims, and eligibility contradictions fail closed. These
bindings prove deterministic integrity and source continuity, not signer
authenticity.

For `run`, `cancel`, and `recover`, `input` contains exactly `gateway_state` and
`run_id`. The gateway state is verified, including its event chain and state
digest, before the run is displayed. The CLI intentionally does not call the
gateway mutation functions.

## Policy proposal workflow

Policy is never edited or activated by this CLI. `policy-propose` consumes one
closed proposal input with proposal identity, append sequence, real-calendar
UTC timestamp, previous-proposal digest, the complete ordered predecessor chain,
base and proposed policy objects, explanation, and a rollback reason. Sequence
one must reference the all-zero predecessor digest and an empty chain. Sequence
N requires exactly N-1 predecessor proposals beginning at sequence one. Every
member is closed and canonical-digest-valid; all predecessor IDs and the new ID are unique, sequences adjacent,
times increasing, predecessor digests exact, and each base-policy digest equals
the previous proposed-policy digest. Every proposal also requires nonempty
explanation and rollback reason, lexicographically ordered unique changes, a
rollback target equal to the base-policy digest, and inverse changes exactly
equal to the reversed operation-inverted forward diff.

The result is a `standalone_runtime_policy_proposal_v1` object conforming to
`standalone-runtime-policy-proposal-schema.json`. Changes are a deterministic,
lexicographically ordered JSON-pointer diff. The rollback is not history
rewriting: it is inverse change metadata for a future separately reviewed
forward proposal. The proposal records `dry_run: true`, `append_only: true`,
and false persistence, activation, authority, and acceptance claims. A no-op
proposal fails with `policy_no_change`.

## Safety and parity requirements

- Runtime and API versions are consumed, not invented or upgraded by the CLI.
- Capacity is shown as `not_admitted` and not required for plan preview; it is
  never presented as a failed plan gate or as an allocated lease.
- Run, delegation, lineage, recovery, and journal facts come only from their
  verified source artifacts.
- Denied children remain denied. Journal content never becomes an instruction.
- Recalled evidence, foreign lineage, unknown usage, and acceptance claims keep
  the fail-closed behavior of Runtime Evidence.
- `serve` never hides a daemon or endpoint bind; the accepted foreground owner
  must be started separately under its own authority.
- CLI/UI/API parity means equivalent semantic fields and blockers, not that a
  client can manufacture missing runtime effects.
