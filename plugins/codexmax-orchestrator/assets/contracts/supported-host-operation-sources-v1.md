# Supported-host operation sources v1

## Authority boundary

Six first-party source owners implement twelve fixed operation adapters. The
operation endpoint selects the owner, source ID, principal, raw schema, and
accepted mechanism. A caller cannot select these values.

The writer query has exactly three fields:

```text
identity
operation_body
dependency_receipts
```

An adapter does not accept `owner_state`, a positive value, a fact key, a source
digest, an expiry, a seal, a final receipt, or a principal. A certificate can
authenticate the observation principal. It cannot make an observation true.

## Exact raw schemas

Each raw schema is exact closed. Unknown fields fail before journal mutation.
The fixed endpoint supplies the operation.

| Schema | Exact fields |
| --- | --- |
| `catalog_configuration` | `schema_version`, `artifact_type`, `observation_id`, `public_bundle`, `configured_bindings`, `qualification_inputs`, `receiver_admission`, `observed_at` |
| `selection_transition` | `schema_version`, `artifact_type`, `observation_id`, `transition_kind`, `receiver_transition`, `catalog_lineage`, `observed_at` |
| `responses_request` | `schema_version`, `artifact_type`, `observation_id`, `receiver_ingress`, `dependency_identities`, `observed_at` |
| `native_topology` | `schema_version`, `artifact_type`, `observation_id`, `native_host`, `children`, `edges`, `cursor`, `lifecycle`, `identity_evidence`, `observed_at` |
| `executor_action` | `schema_version`, `artifact_type`, `observation_id`, `action_receipt`, `executor_start_id`, `executor_session_id`, `challenge`, `observed_at` |
| `reconciliation` | `schema_version`, `artifact_type`, `observation_id`, `predecessor`, `outcome`, `receipt`, `epoch`, `stable_resource`, `observed_cas`, `receiver_time` |

Nested authority-field injection also fails. This includes a fact, positive
value, source digest, expiry, seal, principal, canonical source ID, and final
receipt.

## Fixed adapter matrix

| Operation | Owner | Raw schema | Accepted mechanism |
| --- | --- | --- | --- |
| `read_operator_preset_bundle` | `catalog_selection` | `catalog_configuration` | T067 catalog selection |
| `read_operator_selection_head` | `catalog_selection` | `selection_transition` | T067 catalog selection |
| `read_operator_selection_mutation` | `catalog_selection` | `selection_transition` | T067 catalog selection |
| `commit_operator_selection` | `catalog_selection` | `selection_transition` | T067 catalog selection |
| `read_operator_supervision` | `native_supervision` | `native_topology` | T068 native supervision |
| `issue_responses_context` | `responses_seals` | `responses_request` | T066 responses seals |
| `verify_effect_authority` | `effect_authority` | `responses_request` | T064 effect authority |
| `invoke_registered_action` | `registered_action` | `executor_action` | T072 registered action |
| `verify_responses_bridge` | `responses_seals` | `responses_request` | T066 responses seals |
| `commit_or_verify_record` | `responses_seals` | `responses_request` | T066 responses seals |
| `seal_or_verify_projection` | `responses_seals` | `responses_request` | T066 responses seals |
| `read_operator_recovery_lease_grant` | `recovery` | `reconciliation` | T069 and T078 recovery |

`commit_operator_selection` derives command authorization only. The accepted
receiver creates a mutation and the successor head.

## Concrete family engines

The module constructs one fixed engine for each of the six owners. The public
API accepts no mechanism object, complete value, family state, family head,
callback, module name, principal override, or source override.

Each engine derives its value from the exact raw schema and exact three-field
query. It also derives a sealed concrete-family decision. The decision binds
the operation, fixed mechanism, identity digest, operation-body digest, sorted
dependency digest, raw digest, retained family predecessor, owner start and
session, owner time, expiry, and derived-value digest.

The store owns the family state. It checks the retained predecessor and
publishes the successor under the same owner lock as the source journal. It
then calls unchanged v8 `prepare_positive_source_material_v1`. The v8 function
remains final authority for the key, value, dependency, time, and positive
source digest.

## Executable owner runners

The protected-service integration exports one fixed runner for each owner:
`serve_catalog_selection_owner_once`, `serve_native_supervision_owner_once`,
`serve_responses_seals_owner_once`, `serve_effect_authority_owner_once`,
`serve_registered_action_owner_once`, and `serve_recovery_owner_once`.

Each runner receives one inherited writer descriptor, one inherited family
observation descriptor, and one inherited root descriptor. It does
not receive a writer root, anchor root, or another source-owner root.

The observation request binds the joint authority, fixed channel, external
peer, peer start and session, source start and session, operation, challenge,
exact raw schema, and request digest. The handler revalidates the descriptor
fingerprint and exact peer UID and group set before and after the exchange.
The acknowledgement reports only retained state, reason, observation ID, and
journal event digest. It never returns a fact value, fact key, source digest,
receipt, head, CAS value, principal, or promotion state.

The runner records and validates the raw observation through the exact fixed
adapter. It returns only the adapter result through the authenticated writer
channel. The writer never receives the raw observation and never opens the
owner root.

`check_operation_source_runner` and the `--check-only` command validate the
six public service records and fixed operation list. They open no descriptor
or root. The mutually exclusive `--execute-live` mode accepts public joint
authority plus inherited writer, observation, and root descriptor numbers. It
accepts no root path, mechanism, callback, complete value, credential, or
credential path.

## Journal contract

The journal uses these ordered event types:

1. `raw_observation`
2. `decision_issue`
3. `derived_value`
4. `revoke`
5. `consume`

The adapter persists raw bytes before family derivation. A failed derivation
therefore leaves a reviewable raw event and no positive event. A decision binds
the raw-event digest and the family expected-head transition. A derived event
binds the decision digest and the exact v8 material.

Each event binds the owner, operation, identity digest, operation-body digest,
accepted dependency digest, raw digest, family mechanism, family predecessor
and successor, source predecessor, owner times, and canonical event digest.
The store publishes one sealed pending transaction, one numbered no-replace
commit, the reconstructable head, and the family state. It then removes the
pending transaction. Restart completes only the exact event-ahead pending
transaction. It repairs a stale head cache. It rejects a changed pending
record, gap, fork, truncation, unrelated residue, or non-canonical file.
Exact raw retry is idempotent under the owner lock. Changed raw or query bytes
for the same observation ID are a collision.

Only recovery can record consumption. Parent integration must require a
matching use observation before it invokes that transition. Revoked, consumed,
or expired derived state is unavailable.

## Source-local boundary

A source-local temp root uses the sealed scope
`source_local_quarantine_non_production`. It executes raw retention, concrete
family derivation, family CAS, decision retention, unchanged v8 validation,
derived retention, and restart recovery. It returns only
`QuarantinedDerivedResult`. That type has no production serializer or
promotion method. Its digest also binds the quarantine scope.

Source-local tests prove schema closure, fixed routing, raw-first ordering,
family CAS, v8 validation, idempotence, collision rejection, crash recovery,
and non-promotion.
They do not prove a live receiver, native host, executor, public certificate,
service account, production root, or journey. Those are later T060 and T062
evidence.

## T092 accepted-family runtime integration

The earlier concrete family engines remain quarantine and migration evidence.
They are not the supported T092 family stores. The supported runtime uses six
fixed factory functions. Each factory constructs one role-local accepted
family store and one role-local cross-owner artifact store. The family root
and artifact root stay distinct. Both bind the fixed joint-authority digest.
No factory accepts an edge, artifact bytes, ledger bytes, family head, source,
principal, callback, or promotion state.

The accepted stores are T067 catalog-selection, T068 native-supervision, T066
responses-seals, split T064 effect-authority, split T072 registered-action,
and split T069 recovery. The effect-authority factory also receives the
responses-owner operation-state reader. It uses that reader only to resolve a
complete context identity whose digest is already bound by the imported T066
artifact.

`ResponsesSealsAcceptedRuntimeAdapter` reads only the fixed current imports.
It binds the catalog-selection and native-supervision import heads into the
T066 context inputs and exact closed transition. It binds the registered-
action import head and complete artifact bytes into the retained action
evidence and exact closed bridge transition. The responses-seals owner state
persists the exact edge-to-head map. Later T066 record and projection
transitions retain the current map unchanged.
An absent, expired, wrong-edge, wrong-operation, non-issue, or non-quarantine
import fails closed.

All accepted-family and cross-owner artifacts remain
`source_local_quarantine_non_production` during source-local validation. No
factory or adapter has a production serializer or T082 promotion path.

## T093 integrated quarantine

`acquire_accepted` is the integrated accepted-family path. It executes the
selected T091 family store. It retains the exact family predecessor and
successor. It runs unchanged v8 material validation. It appends the T089
decision and derived events. It always returns `QuarantinedDerivedResult`.
This rule also applies when the T089 journal is service-owned.

The twelve-operation runtime uses all eight T092 edges. Each dependent family
reads the fixed imported projection and current import head. The responses
adapter accepts only the exact T091 event kind for each imported operation.
T092 still validates the complete predecessor bytes, successor bytes,
transition bytes, producer anchor, producer identity, consumer identity,
freshness, operation, and edge before the adapter can use the projection.

## T096 runner-owned live result boundary

The module exports no `SourceDerivedFact`, permit, promotion helper, sentinel,
or reconstitution function. `acquire` and `acquire_accepted` return only
non-serializable retained material. Source-local retained material cannot enter
the writer path.

The selected owner runner can write an available response only after it validates the
live joint authority, current selected UID, GID, exact supplemental groups,
current session, inherited root identity, and the before and after witness for
the writer, raw-observation, and exact role artifact channels. It also requires
complete accepted-family derivation and all current required imports. The
closed result crosses only the authenticated writer channel. The writer derives
the exact T082 request.

The owner CLI uses `--artifact-fds-json`. The map must contain exactly the
fixed edges for the selected role. Missing, extra, wrong-role, non-integer,
negative, duplicate, or reused descriptors fail before socket wrapping.

The owner never changes process cwd. It copies the authenticated inherited
descriptor tree into non-authoritative process scratch. It publishes every
durable change back with `dir_fd` operations while it holds the descriptor-root
lock. It never resolves or reopens the inherited descriptor as a pathname.

Producer edges use two phases. The runner first commits the export to its T092
journal. It then returns the source response. A later fixed channel exchange
serves only that retained export. The consumer imports the retained bytes before
its operation. No placeholder dependency receipt is accepted.
