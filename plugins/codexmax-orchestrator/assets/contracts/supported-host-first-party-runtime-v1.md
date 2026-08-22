# First-party supported-host runtime v1

Status: OS-bound protected-service read path implemented; live promotion pending

## Runtime identity

The implementation is `FirstPartySupportedHostRuntimeV1`.
Its runtime ID is
`codexmax-first-party-authoritative-supported-host-runtime-v1`.
It binds one authenticated `DeploymentAdmissionV2`. The admission supplies the
candidate descriptor, archive, sidecar, source, verified root, launched child,
generation, nonce, expiry, installer, writer, anchor, revocation, and commit
facts. No runner member contains or authorizes its own archive digest. Runtime
pins the protocol. It does not pin runner v23 or any predecessor digest.

Production construction does not accept an identity mapping, digest set,
literal admission label, certificate, callback, fixture, or simulated result.
It accepts only `OsBoundDeploymentAdmissionV2Source`. The runtime constructor
also requires the public profile to project the same verified selected-candidate
descriptor. Candidate, archive, sidecar, source, generation, and descriptor
digest mismatches fail before runtime materialization.
consumes that source once. The source requires one preconnected AF_UNIX channel
to the distinct bootstrap account. The transaction binds equal protected-writer
and independent-anchor commit digests. A plain mapping remains data. It is
never authority. The old runner-v23 admission source is not a fallback.

## Operation ownership

The runtime owns these exact operation routes:

| Operation | Source | Principal | Public namespace | Dependency |
|---|---|---|---|---|
| `read_operator_preset_bundle` | `operator-catalog-publisher` | `first-party-catalog-selection-producer-v1` | `catalog` | `open_operator_listener` |
| `read_operator_selection_head` | `operator-selection-ledger` | `first-party-catalog-selection-producer-v1` | `selection` | `read_operator_preset_bundle` |
| `read_operator_selection_mutation` | `operator-selection-mutation-history` | `first-party-catalog-selection-producer-v1` | `selection` | `read_operator_selection_head` |
| `commit_operator_selection` | `operator-selection-commit-authority` | `first-party-catalog-selection-producer-v1` | `selection` | `read_operator_selection_mutation` |
| `read_operator_supervision` | `native-desktop-inventory-authority` | `first-party-native-supervision-producer-v1` | `native_inventory` | `commit_operator_selection` |
| `issue_responses_context` | `responses-context-issuer` | `first-party-responses-seals-producer-v1` | `responses` | `read_operator_supervision` |
| `verify_effect_authority` | `effect-authority-ledger` | `first-party-effect-authority-producer-v1` | `authority` | `issue_responses_context` |
| `invoke_registered_action` | `registered-action-observation-store` | `first-party-registered-action-producer-v1` | `registered_action` | `verify_effect_authority` |
| `verify_responses_bridge` | `responses-bridge-observation-store` | `first-party-responses-seals-producer-v1` | `responses` | context and action receipts |
| `commit_or_verify_record` | `record-lineage-authority` | `first-party-responses-seals-producer-v1` | `responses` | `verify_responses_bridge` |
| `seal_or_verify_projection` | `projection-seal-authority` | `first-party-responses-seals-producer-v1` | `responses` | `commit_or_verify_record` |
| `read_operator_recovery_lease_grant` | `recovery-lease-authority` | `first-party-recovery-producer-v1` | `recovery` | `seal_or_verify_projection` |

These are the exact T082 namespace tokens. The runtime uses them directly. It
does not change the accepted T082 bytes.

## Promotion gates

The runtime returns a typed unavailable result until all gates are live:

1. The public profile contains real public certificate metadata.
2. The package-host receiver owns and corroborates the live TLS handshake.
3. The operation principal matches the exact operation route.
4. A protected writer publishes an exact CAS event.
5. An independent anchor retains the exact writer statement.
6. The operation has all exact receiver receipt dependencies.
7. The fact is current, not revoked, and not consumed.

Production reads use only `OsBoundProtectedFactSource`. The runtime passes the
exact operation body and dependency receipt set to separately authenticated
writer and anchor channels. It returns a validated protected fact only after
both kernel peer checks, both challenge exchanges, exact T082 validation, and
anchor reconciliation pass.

The writer routes each request to one of six fixed executable source-owner
runners. Each owner receives its raw observation on a separate joint-authority
channel, records it before derivation, validates it through the accepted family
mechanism, and returns only the derived source result. The runtime and writer
cannot submit or inspect the raw observation. The writer cannot open any owner
root.
Pending T082 or T083 evidence remains unavailable. The explicit test-only
runtime and devices can exercise the algorithm, but their result retains a
test-only classification and cannot enter the production producer path.

## Persistence behavior

The runtime has no public append method. It sends a request-only query to the
protected writer. The writer reads the fixed source owner and derives the exact
T082 store, source, principal, operation, candidate, profile, expected sequence,
expected head, generation, payload, record ID, and nonce. The protected writer
and independent anchor own restart, rollback, fork, replay, collision,
revocation, and consumption evidence.

The runtime does not open a file, socket, process, environment, credential, or
network endpoint. It can receive preconnected OS-bound service clients. A
source-local socket pair remains pending because its peer has the caller UID.

## Proof boundary

Source-local tests prove route closure, pending behavior, store-derived reads,
restart, and protocol integration. They do not prove a live handshake,
protected writer device, independent production anchor, installation, or
external fact.

## T093 integrated source-local runtime

`QuarantinedAcceptedFamilyRuntimeV1` creates six distinct role roots below one
temporary runtime root. Each role root contains its T089 operation journal,
its T091 family store, and its T092 artifact store. The runtime fixes all
twelve operation-to-owner routes and all eight cross-owner edges.

The integrated journey executes all twelve accepted family transitions. It
retains all eight producer export heads and consumer import heads. It then
runs the unchanged v8 material validator for each operation. Every result
remains non-serializable quarantine material. This is source-local mechanism
readiness. It is not installed, credential, service-account, external
observer, live socket, T082 publication, or journey evidence.

## T096 later-live execution seam

The six owner runners now have one live-only response seam. It requires the live
joint authority, current selected service identity and inherited root, exact
role artifact descriptor set, stable authenticated channel witnesses,
complete accepted derivation, and current required imports. Source-local and
incomplete-channel execution stays quarantine. No importable helper can convert
quarantine into an available result. The protected writer alone converts the
validated authenticated response into unchanged T082 material.

The root boundary uses the inherited directory descriptor. It does not use cwd
or descriptor-to-path reopening. Repository tests remain source-local simulated
live proof. They are not external execution evidence.

The integration journey runs all twelve operations through the six fixed owner
runners. It uses authenticated simulated raw and writer socket channels. It
retains and later transfers all eight T092 artifacts in dependency order. Each
consumer dependency map uses the actual earlier source-local T082 writer
receipt. The non-authoritative writer journey retains exact writer and anchor
receipts and proves parity in the independent anchor store. It cannot become
production-ready and does not prove distinct service accounts.
