# Supported-host Responses-seals family store v1

## Status

This contract defines the first-party store for the complete accepted T066
ledger. The store is repository-owned. It is source-local in T091.

The store does not create an available fact. It does not authenticate a
principal. It does not promote a structural decision into fact authority.

## Fixed operations

The store exposes these fixed operation methods:

| Method | Accepted input | Owner-derived output | Required retained dependency |
| --- | --- | --- | --- |
| `issue_responses_context` | Exact identity, request, dependency, selection, supervision, runtime, route, catalog-import-head, and native-import-head digests | Responses context digest and exact T066 decision | Current catalog-selection and native-supervision imports |
| `verify_responses_bridge` | Exact context decision, action receipt, effect request, effect receipt, and action-import-head digests | Bridge digest and exact T066 decision | Current context and retained action evidence |
| `commit_or_verify_record` | Fixed `commit` or `verify` mode, exact context decision, bridge decision, and record digests | Record seal and exact T066 decision | Current matching context and bridge |
| `seal_or_verify_projection` | Fixed `seal` or `verify` mode, exact context decision, record decision, and projection digests | Projection seal and exact T066 decision | Current matching context and record |

The store derives the record and projection seals. A caller cannot submit a
seal in `commit` or `seal` mode. A caller can submit only the expected digest
in `verify` mode. The store compares it with the owner-derived digest.

The bridge method requires a prior `retain_registered_action_evidence` call.
That call retains only the exact T072 action receipt digest and its exact T066
context decision digest. It does not accept an action value or an action
result.

Every exact closed T066 transition retains `dependency_import_heads`. A
context transition retains exactly the current catalog-selection and native-
supervision heads. A bridge transition adds the exact current registered-
action head. Record, projection, and revoke transitions retain the unchanged
current map. The sealed owner state retains the same current map. Recovery
replays the map progression and rejects a changed, missing, unknown, rolled-
back, or unbound head. Cross-owner export copies the selected transition map
unchanged, including after restart.

## Accepted T066 ledger

The persisted `t066-ledger.json` value is the complete
`supported_host_responses_seals_ledger_v1` value. The store uses the accepted
T066 APIs without changing their schema:

- `new_ledger`;
- `validate_structural_decision`;
- `validate_ledger`;
- `issue_decision`;
- `revoke_decision`;
- `recover_ledger`.

Each operation transition contains the complete canonical predecessor ledger
bytes and the complete canonical successor ledger bytes. It contains the
exact sequence, head, byte digest, decision digest, and owner artifact. The
store revalidates every retained transition and every T066 event after a
restart.

The canonical representation is UTF-8 JSON with sorted keys, compact
separators, and one final line feed. A semantically equal but byte-different
file is invalid.

## Store files

One store root contains these files:

- `manifest.json`: fixed repository-owned identity and operation set;
- `t066-ledger.json`: complete current accepted T066 ledger;
- `anchor.json`: current sequence, head, and exact ledger byte digest;
- `owner-state.json`: retained action evidence and complete transition
  artifacts;
- `pending.json`: temporary crash-recovery intent;
- `.lock`: local compare-and-swap serialization lock.

Each JSON file uses mode `0600`. The store root uses mode `0700` when the store
creates it. The store rejects symbolic links for the root and store files.

The source-local anchor is co-located with the store. It is not external
authority by itself. Parent integration must bind each returned predecessor
and successor transition to the accepted T089 journal and the protected T088
service boundary. The later independent anchor retains the integrated
sequence and head.

## Compare-and-swap, retry, and recovery

The store owns the current head. A caller cannot provide a family state or a
family head.

The store holds an exclusive local lock. It reads and validates the current
ledger, owner state, and anchor. It constructs one exact T066 successor with
the current internal head. It writes `pending.json` before it publishes the
owner state, ledger, and anchor.

After a process interruption, recovery accepts each current file only when it
equals the exact pending predecessor or exact pending successor. Recovery then
publishes the complete successor set and removes the pending intent. An
unknown intermediate value is a collision and fails closed.

An exact repeated issue request returns the retained transition. It does not
append a second event. T066 rejects a duplicate decision, decision identity
collision, digest replay, stale head, duplicate revocation, and malformed
chain.

## Dependency and revocation rules

The store requires exact retained dependencies:

- a bridge binds one current context and one retained action receipt digest;
- a record binds one current context and a bridge issued for that context;
- a projection binds one current context and a record issued for that context;
- each successor replaces the T066 dependency receipt digest with the digest
  of its exact predecessor decision references;
- each successor carries forward the exact identity, request, selection,
  supervision, runtime, route, and action bindings that apply to its chain.

Revocation appends the exact accepted T066 revoke event. Revocation survives a
restart. A revoked context cannot be used for a later action retention, bridge,
record, or projection transition. Duplicate revocation fails closed.

## Authority boundary

The public methods do not accept:

- a complete positive value;
- a caller ledger, family state, sequence, or head;
- a generic mechanism name;
- a producer principal or canonical source override;
- a callback;
- a fixture or test projector;
- a certificate as fact authority;
- a promotion or availability state.

The owner artifacts use the exact proof boundary
`source_local_structural_mechanism_only`. Their self-digests provide integrity
inside the complete T066 chain. They do not prove an external observation.

Tests can use scalar digest fixtures only inside a temporary root. Those
fixtures remain test inputs. They cannot enter a production store or become a
positive producer result through this module.

## Safety boundary

The module performs local file operations inside the explicit store root. It
does not read environment variables. It does not use a socket, service,
network, provider, browser, keychain, certificate, private key, credential, or
credential path. It does not install or start a service.

T091 tests prove source-local construction, persistence, canonical
serialization, full-chain restart recovery, interrupted-publication recovery,
exact retry, collision rejection, revocation, rollback rejection, fork
rejection, truncation rejection, malformed-ledger rejection, and all four
operation semantics. They do not prove installed, live, TLS, external-anchor,
or external-observation behavior.
