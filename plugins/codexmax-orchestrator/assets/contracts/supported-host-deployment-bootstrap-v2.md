# Supported-host deployment bootstrap v2

Status: R3 ledger draft implemented; Darwin descriptor-exec launch blocked

## Authority boundary

The bootstrap is separately governed source. The runner archive allowlist must
exclude it. The bootstrap reads only inherited regular-file and directory
descriptors. It does not discover a repository path. It does not accept a
caller mapping, callback, certificate, fixture, self-digest, or Python object
as production authority.

The bootstrap validates a closed candidate descriptor. The descriptor binds
the candidate ID, protocol, archive, sidecar, source identity, extracted-root
manifest, entrypoint, and monotonic generation. The archive, sidecar, and
candidate descriptor reads bind device, inode, size, modification time, and
link count before and after each read. Symlinks, hardlinks, drift, noncanonical
JSON, and digest substitutions fail closed.

The bootstrap validates the extracted generation through an inherited root
descriptor. The root manifest has a sorted and unique inventory. Each member
binds path, size, read-only mode, and SHA-256. Links, extra members, missing
members, root substitution, and entrypoint substitution fail closed.

## Fixed launch operation

`VerifiedRootLaunchOperation` revalidates the root immediately before launch.
It opens the entrypoint only through inherited directory descriptors. It
verifies the open executable descriptor against the root manifest. It uses no
shell and no caller child identity.

The operation requires an operating-system `execve` form that accepts the
verified executable descriptor. It refuses a pathname reopen. The current
Darwin Python runtime does not expose descriptor-based `execve`. Darwin also
refuses execution through `/dev/fd/<fd>`. The operation therefore returns
`deployment_descriptor_exec_unavailable` before it starts a child. This is a
hard source gate. A native bootstrap executable or another approved immutable
descriptor-exec mechanism is required before R3 can complete.

When descriptor execution is available, the operation derives PID from the
fork result. It derives UID and GID from the bootstrap process. It derives the
root and entrypoint device and inode values from open descriptors. It derives
the executable digest from the open entrypoint descriptor. It derives a start
identity from these OS observations and a monotonic observation value.

## Durable deployment ledger

`DurableDeploymentLedger` uses one inherited directory descriptor. It does not
discover a ledger path. Each event is an absent-only, durable, canonical JSON
record. Each record binds its sequence and previous event digest. The mutable
`HEAD.json` pointer is published only after the committed event is durable.
Restart recovery validates the complete event chain and reconciles a missing
head from the latest durable commit.

The ledger records these event kinds:

- `reserved`
- `launched`
- `writer_receipt`
- `anchor_receipt`
- `committed`
- `admission_issued`
- `revoked`
- `aborted`

Reservation consumes the nonce digest. A reused nonce fails before another
record is written. A candidate generation must be exactly one higher than the
current committed generation. Rollback is therefore a new higher generation.
Revocation is terminal for the pending transaction. A crash can leave a typed
pending transaction. It does not advance the committed head.

Source-local fixture phases use
`source_local_fixture_non_authoritative`. They can test restart and crash
reconciliation. They cannot create `CommittedDeploymentTransaction` and
cannot issue admission.

## DeploymentAdmissionV2

`DeploymentAdmissionV2` uses protocol
`supported_host_deployment_admission_v2`. It binds these facts:

- Candidate descriptor, archive, sidecar, source, and root-manifest digests.
- Verified root device and inode.
- Child PID, UID, GID, start ID, and executable digest.
- Candidate ID and monotonic generation.
- Fresh nonce, observation time, and expiry time.
- Installer build, start, and session identity.
- Protected-writer and independent-anchor service starts and sessions.
- Revocation state and previous commit digest.
- Equal protected-writer and independent-anchor commit digests.

The runtime receives one canonical admission frame over one inherited AF_UNIX
channel. Kernel peer credentials must match the distinct bootstrap account.
The channel is one-use. A partial frame, trailing frame, substituted socket,
same-UID peer, stale session, expired admission, replayed lineage, downgrade,
or revocation fails closed.

## DeploymentCommitV2

`DeploymentCommitV2` binds the verified candidate, root, entrypoint, derived
child identity, generation, consumed nonce digest, previous committed head,
installer identity, and revocation state.

The bootstrap sends the same canonical commit through two distinct one-use
AF_UNIX channels. One channel is for the protected writer. The other channel
is for the independent anchor. Each peer returns its own closed receipt. Each
receipt binds the full commit digest and exact request digest. Equal
caller-provided digest strings are not receipts. Same-UID peers, reused
channels, substituted descriptors, truncated frames, and divergent receipt
bindings fail closed.

The final admission binds both distinct receipt digests and the durable ledger
head. A plain mapping or source-local fixture cannot satisfy the exact opaque
committed-transaction type.

Rollback is a new higher-generation transaction with external authorization.
Old admission evidence is never reusable.

## Migration

Runner v23 remains an explicit legacy migration baseline. It does not authorize
the next generation. Runtime pins this protocol and the authenticated
transaction. Runtime does not pin runner v23 or any predecessor digest.

## Source-local proof boundary

Source-local tests prove closed schemas, canonical encoding, descriptor-bound
reads, extracted-root validation, nonce replay, revocation, monotonic
generation, event-chain recovery, crash residue, head substitution, and the
fail-closed Darwin launch gate. Source-local validation always returns
`production_admission_issued: false`.

Source-local tests do not prove bootstrap provenance, distinct OS accounts,
real child launch binding, protected-writer and independent-anchor
independence, production restart reconciliation, installation, TLS,
credentials, a production socket, or a live journey.
