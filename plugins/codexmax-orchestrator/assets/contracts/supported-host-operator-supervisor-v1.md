# Supported-host operator supervisor v1

The supervisor has no compile-time current runner digest. Each live lifecycle
verb supplies inherited descriptor, archive, and sidecar FDs. The supervisor
derives the selected candidate from those stable reads before it prepares any
service descriptor.

Status: source-local command plane ready; external execution pending

The supervisor fixes nine service roles and fourteen journey operations. It
accepts only inherited descriptors for services, deployment admission, the
runtime root, and the opaque credential agent. It accepts no credential,
private value, credential path, service-root path, socket path, endpoint, or
caller-selected role.

Check-only mode returns a pending authenticated-candidate selection,
DeploymentAdmissionV2 compatibility, and the legacy runner v23 migration
baseline. It does not claim that a compile-time candidate is current. The
supervisor does not treat public metadata as runtime authority. It opens no
descriptor and performs no
write, process, socket, network, install, or external action.

During a later authorized run, the separate bootstrap verifies the selected
bytes and extracted root. It binds the launched child and records the commit
with the protected writer and independent anchor. Its one-request inherited
AF_UNIX channel serves `DeploymentAdmissionV2` to the runtime. Exact bounded
frame reads reject truncation, trailing data, replay, reuse, and response
swaps. The
supervisor passes fixed inherited descriptors to the nine role runners. It
does not produce facts, receipts, admissions, or credential results.

The four post-start commands consume one canonical public request from an
inherited regular-file descriptor. The bootstrap validates the selected
archive and sidecar and the complete role descriptor inventory before it
reports a missing opaque credential agent or distinct live service account.

The supervisor module also owns the import-closed pure authority validator.
The validator uses only the Python standard library. It validates every joint
role, external peer, fixed channel policy, root identity, service identity,
build digest, UID, GID, supplemental group, start ID, session ID, expiry, and
allowed channel. It also validates the exact six-member operation-source
service set and its cross-role bindings. The lifecycle `start` command calls
this validator before it verifies live descriptors or enters an external
action gate. A rejection cannot advance the source-local journal.

The deployment request and response endpoints use the same 65,536-byte frame
limit. Protected-service and operation-source data frames use a separate
4,194,304-byte maximum because their bounded fact payloads are larger. The
deployment protocol never uses the larger data-frame limit.

Source-local lifecycle tests use a separate non-authoritative temp-root
journal. Each record has an append-only sequence, a previous-record seal, and
a canonical SHA-256 seal. Expected-head compare-and-swap prevents replay.
The committed pointer changes only after record, head, and anchor publication.
Restart recovery repairs head and anchor from the committed pointer. It keeps
typed publication residue when a fault writes a record but does not commit it.
Seal, exact pointer shape, nonnegative sequence, collision, rollback, and
truncation failures are typed. This test journal can
never issue production admission or fact authority.
