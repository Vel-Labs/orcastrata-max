# Supported-host protected service v1

`OsBoundDeploymentAdmissionV2Source` requires an opaque
`VerifiedSelectedCandidate`. It rejects an admission that differs from the
descriptor-bound candidate, immutable bytes, generation, expiry, lineage,
installer, protected receiver transaction, writer, or anchor. The former
static runner-v26 source, evidence validator, and writer or anchor bind command
are retired and always reject authority consumption.

Status: later-executable service plane implemented; live service identity pending

## Joint nine-role authority

The production boundary has nine separately owned macOS services:

- `protected_writer` acquires the canonical fact and creates the exact T082 append request and writer receipt.
- `independent_anchor` retains and corroborates the exact T082 anchor receipt.
- `opaque_tls_agent` owns credential use outside the workspace and submits the unchanged v8 receiver frame.
- `catalog_selection`, `native_supervision`, `responses_seals`, `effect_authority`, `registered_action`, and `recovery` own the twelve fixed operation sources.

One exact closed and canonically sealed authority binds the protocol, authority
ID, execution scope, nine role records, external peers, fixed channel policies,
and authority digest. Each role binds its role and service IDs, build digest,
UID, GID, exact supplemental groups, root identity, service start, session,
expiry, and exact inbound and outbound channel IDs. Service IDs, UIDs, GIDs,
root identities, starts, and sessions are pairwise unique. A supplemental group
cannot equal any role primary GID or any other supplemental group.

Structural validation opens nothing. It does not compare all roles with the
current process. Live validation checks only the selected role. It requires the
exact current UID, GID, supplemental group set, session expiry, and inherited
root descriptor. The root descriptor must be a directory. Its UID, GID,
device, and inode must match the selected role's sealed root identity. The
runner does not open a path supplied by a caller.

Each inherited AF_UNIX descriptor is startup plumbing only. The client and
server capture the same full descriptor fingerprint and exact Darwin
`LOCAL_PEERCRED` witness at admission. They re-read both before and after the
one-use exchange. The witness contains the exact peer UID and sorted group set.
A group membership test is not sufficient. A changed descriptor, peer, group
set, start, session, expiry, protocol, channel, direction, request type, or
response type fails closed. A source-local socket pair has no live authority.

The fixed channel graph permits the writer to contact the independent anchor
and the six operation owners. It does not permit the writer to open their
roots. The runtime can contact only the writer, anchor, and opaque TLS agent.
Each external observer can contact only its operation-family owner. The opaque
TLS agent can contact only the credential agent. A caller cannot select or add
a role, source, channel, direction, peer, or channel policy.

The module also implements executable service-side framed dispatch. The protected writer accepts only the exact request-only operation query. It reads the fixed operation owner and derives the exact T082 request. It sends each writer statement to the independent anchor through an OS-bound framed client. It commits only the returned exact T082 anchor receipt. Public generic append, revoke, consume, and recovery commands are forbidden. The independent anchor processes writer-only retain and exact corroboration requests against its separately owned root. Both services can answer the fact-query protocol from their current persisted state. They do not accept caller-created facts or receipts as authority.

The opaque TLS service has a narrow later-executable port to an externally provisioned credential agent. The port accepts only opaque receiver bytes and public bindings. It accepts no private value or private-value location. The external request and response both bind `supported_host_opaque_credential_agent_v1`. It checks the current external-agent socket fingerprint, UID, GID, agent start, agent session, protocol, build, challenge, principal, operation, server leaf, and request and response digests. Without that preconnected external agent, it returns `live_credential_agent_unavailable`.

Writer, anchor, TLS, source-owner, and external-agent handlers recheck the
shared descriptor fingerprint and exact peer witness before and after each
frame. Direct object construction stays pending or fails closed. Darwin peer
credentials do not prove PID or code-sign identity. A same-UID compromised
process remains inside the operating-system account trust boundary.

Deployment admission uses one additional inherited AF_UNIX descriptor owned by
the distinct bootstrap account. The bootstrap returns closed, current, canonically
sealed `DeploymentAdmissionV2` for the selected descriptor, archive,
sidecar, source, verified root, launched child, generation, nonce, expiry,
installer, protected receiver transaction, writer, anchor, revocation, and commit identities. Digest syntax
alone cannot admit a runner. Both sides
read the complete bounded frame and reject trailing bytes, replay, reuse, and
swapped request or response digests. The protected writer and independent
anchor commit digests must be present and equal. The production runtime
constructor consumes the exact source once. No Python token, result class, key, registry, sentinel,
classification, issuer, or validator represents authority. A source cannot be
reused.

The writer-to-source protocol is exact closed. Its request binds the joint
authority digest, fixed channel, source owner, source service and build,
writer start and session, expected source start and session, challenge,
operation, request-only query, candidate, profile, time, and request digest.
Its response binds the same exchange to the source start and session. An
available response contains only the operation-derived fact key and value,
times, source digest, observation ID, and journal event digest. An unavailable
response contains none of those positive fields. Both endpoints compare the
same admitted descriptor and exact peer witness before and after the frame.

Each source owner also has one fixed external observation channel. The exact
request binds the joint authority, family peer, peer start and session,
selected owner, source start and session, operation, challenge, raw
observation, and request digest. The server validates the operation-specific
raw schema before journal mutation. It then calls only the fixed operation
adapter. The acknowledgement carries retained state only. It cannot carry a
positive fact, source digest, principal, receipt, head, or CAS value.

The module exports six fixed owner runners. Each runner joins one writer
handler, one raw-observation handler, one service-owned operation journal, and
one accepted family mechanism object. The runner opens its own inherited root
only. The protected writer receives only six preconnected source descriptors.
It never receives the six owner-root paths or descriptors.

## Protocol

Frames use a four-byte network-order length and canonical UTF-8 JSON. The maximum frame size is public configuration. Each request binds a fresh challenge, client session, client service start, expected service start and session, protocol version, service identity and build, principal, operation, candidate, profile, operation body, dependency receipt set, time, body digest, and request digest. A response must return the configured current service start and session.

Each available fact comes from the writer's current persisted record. It retains the exact T082 `protected_durable_append_request_v1`, `protected_durable_append_receipt_v1`, and `protected_anchor_receipt_v1`. It also contains one closed payload-derived view. The writer excludes revoked and consumed facts. It requires an exact operation, principal, candidate, profile, operation-body digest, dependency-receipt digest, and freshness match. The client validates the exact T082 schemas and seals. It then reconciles the writer view with a response from the independently authenticated anchor channel.

The TLS-agent request contains the unchanged v8 receiver frame as opaque bytes. It binds the exact principal, operation, expected public server-leaf digest, challenge, client session, service start, service session, protocol, and service build. The response repeats these bindings and adds the receiver-frame digest and response digest. No private value or private-value location enters this protocol.

## Failure boundary

Partial, oversized, non-canonical, replayed, swapped, downgraded, stale-session, wrong-build, wrong-principal, wrong-operation, forked-anchor, mutated-receipt, or truncated input fails closed. Unexpected channel failures become typed producer errors. They do not publish to the receiver.

Source-local socket pairs run under the caller UID. They are always pending and send no request. Temp roots remain explicitly non-production. Source-local tests prove parsing, bindings, exact T082 reuse, service-owned persistence algorithms, restart reconciliation, and fail-closed behavior only. They do not prove launchd ownership, distinct service accounts, external protected roots, TLS, installation, or live receipts.

## Service runner

The module supplies the joint authority validator and selected-role validator
for the executable entrypoints. Check-only validation reads public values only.
It opens no descriptor or root and cannot promote a source-local authority.
Live mode requires explicit external authorization, nine external service
accounts, inherited root and channel descriptors, current sessions, and the
fixed joint authority. The protected writer receives six source descriptors.
It never receives or opens a source-owner root. No role binds, listens,
connects, discovers credential locations, or opens another role's root.

The canonical complete validator is in
`supported_host_operator_supervisor_v1.py`. The lifecycle and protected-service
surfaces call that same import-closed function. Runtime checks can add selected
process and descriptor checks after the canonical validation. They cannot use
a weaker public authority validator. Operation-source configuration uses the
same canonical one-row and exact-set functions before runtime construction.

Each source-owner check-only command is implemented in
`supported_host_operation_sources_v1.py`. It validates public configuration
only. It lists the exact fixed adapters for that owner and reports every live
input as missing. Source-local validation does not invoke an owner runner.

The packaged protected-service entrypoint handles `--check-only` before it
loads the live dependency graph. This makes the standalone plugin preflight
import-closed. An extracted runner resolves `codexmax_package_host` only from
its sibling `src` directory. It does not search an installation, workspace,
environment variable, or network location. Live mode still loads the complete
fixed runtime graph and keeps all authenticated descriptor gates.

## T092 cross-owner accepted-ledger channels

The joint authority contains eight additional fixed role-to-role channels.
Their channel IDs equal the frozen edge IDs. The consumer is the channel
client. The producer is the channel server. Every channel uses the closed
`supported_host_cross_owner_request_v1` and
`supported_host_cross_owner_response_v1` frame types.

The module exports one producer and one consumer handler for each edge. Each
handler accepts only its fixed W1 store type. The producer selects complete
accepted predecessor, successor, transition, anchor, and imported-head bytes
from its recovered family store. The consumer imports through expected-head
CAS. Neither handler accepts an edge, role, artifact, ledger, family head,
source, principal, or promotion state from its caller.

The joint authority derives every W1 `ServiceIdentity`. It fixes the service
ID, build, root digest, start, session, expiry, UID, GID, and supplemental
groups. The consumer passes both complete authority-derived identities to the
fixed import method. The import requires exact identity equality before it
persists the artifact. It compares the primary GID and supplemental groups as
separate exact fields. The handler checks the T088 descriptor and peer witness
before and after the W1 exchange. W1 then checks its own descriptor witness
before and after the request or response. A source-local channel remains
quarantine.

The eight channels are catalog-selection to responses-selection,
native-supervision to responses-context, responses-context to
effect-authority, effect-authority to registered-action, registered-action to
responses-bridge, responses-projection to recovery, native-supervision to
recovery, and effect-authority to recovery. The writer does not relay any
artifact and cannot open any family or artifact root.

## T093 inherited-root owner execution

Each fixed source-owner runner resolves and verifies its inherited root
descriptor. It constructs the selected T091 family store and T092 artifact
store only below that root. It does not accept or open another root.
Optional inherited artifact channels must belong to the selected role. The
runner imports consumer edges before family execution and serves producer
edges after family execution through the fixed T092 entry points. It derives
the import challenge and expected current import head. It does not accept an
edge method, store, family, identity, or artifact from the caller.

The runner calls `OperationSourceStore.acquire_accepted`. A complete accepted
derivation remains `accepted_family_quarantine_non_promotable`. The raw
observer receives `retained_unavailable`. The writer receives typed
unavailable. Neither channel receives the derived value, accepted ledger,
artifact bytes, source digest, or promotion state.

## T096 runner-owned live seam

The live owner CLI requires one exact role-filtered artifact descriptor map.
The direct runner can accept an incomplete map only for permanent quarantine
compatibility. An incomplete map can never return an available result.

The owner validates distinct root, writer, raw-observation, and artifact
descriptors. It captures each authenticated channel witness before work. It
imports each required consumer artifact, runs complete accepted derivation,
serves each required producer artifact, and compares every witness again. Only
an exact match permits the runner to write the closed available response.

The root stays descriptor-relative. The runner does not call `fchdir`, use cwd,
or resolve the descriptor to a path. It uses an internal scratch view only for
the accepted family algorithms. The inherited role root is read, locked, and
published only with `dir_fd` operations.
The writer remains the only component that derives and appends exact T082
material. Source-local tests use temporary roots and simulated peer witnesses.
They do not start a real service or production socket.

The writer constructs `PreconnectedOperationSourceClient` with the public joint
authority. The client constructs the authenticated exchange internally. It
accepts no exchange callback. The writer consumes only the validated response
read from that channel. It does not trust a caller-created result class.

## T096 ordered export and source-local journey

A producer runner retains each required export before it returns its source
response. It does not wait for the future consumer. The writer can therefore
append and anchor the producer T082 receipt first. A later fixed authenticated
exchange serves the already-retained export. The consumer imports it before
its own accepted derivation. This order prevents a dependency cycle and lets
the consumer query bind the actual producer writer receipt.

`SourceLocalProtectedWriterJourney` proves the full writer and independent
anchor call graph with source-local stores. It calls the authenticated source
client, exact T082 request builder, writer begin, real anchor retain, writer
commit, and protected-record validator. It is always `production_ready=false`.
It cannot accept service-owned stores or prove distinct production accounts.
