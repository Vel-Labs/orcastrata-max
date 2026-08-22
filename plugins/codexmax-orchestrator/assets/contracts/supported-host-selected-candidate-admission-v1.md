# Supported-host selected-candidate admission v1

Status: source candidate; not production ready

## Boundary

The installer receives three inherited regular-file descriptors. They identify
one candidate descriptor, one runner archive, and one runner sidecar. The
installer reads each descriptor with stable device, inode, size, modification
time, and link-count checks.

The descriptor binds these values:

- Candidate ID, target, and runner artifact type.
- Archive, sidecar, and source identity SHA-256 values.
- Deployment protocol, bootstrap source, minimum generation, previous commit,
  and legacy migration candidate.
- Generation, issue time, expiry time, and challenge SHA-256.
- Installer, protected receiver, protected writer, and independent anchor
  build, start, and session identities.

The descriptor does not contain `descriptor_sha256`. The verifier computes the
descriptor SHA-256 from the canonical descriptor bytes after it verifies the
archive and sidecar. Thus, the descriptor digest is not embedded in any byte
sequence whose digest the descriptor declares.

The candidate ID, runner artifact type, target version, and generation must
name the same positive generation. The sidecar artifact type, target, archive
digest, and source identity must match the descriptor. The current
source-local preservation fixture uses exact runner v32 bytes. The protocol
remains version-neutral.

## Authority

`VerifiedSelectedCandidate` is the source-local representation of the
descriptor-bound reads. Its public projection has no admission authority.
Production runtime authority requires both this opaque value and one-use
`OsBoundDeploymentAdmissionV2Source` evidence from the distinct bootstrap UID.

The admission must repeat the exact descriptor digest, candidate, archive,
sidecar, source identity, protocol, bootstrap source, generation, expiry,
previous commit, installer, writer, and anchor bindings. A plain mapping,
callback, certificate, fixture, self-digest, path, or stale admission cannot
replace either input.

The protected receiver is bound by the selected descriptor and by the receiver
transaction that carries the one-use admission. The receiver and admission
state remain pending until live launchd and distinct-UID facts exist.

The installer request must present the challenge whose SHA-256 is in the
selected descriptor. A different fresh-looking challenge is a binding error.

The former runner v26 installer-evidence port and its writer or anchor bind
command are reject-only lineage seams. They cannot return production-ready
authority.

## Lifecycle

The lifecycle and supervisor accept a candidate descriptor FD for every live
verb. They verify the same descriptor, archive, and sidecar before they prepare
the service descriptors. The runtime rejects a public profile whose selected
descriptor does not match the authenticated admission. The journey exposes the
same opaque binding check before a live journey.

Source-local validation does not launch a process. It does not open a network
connection. It does not call a provider. It returns `production_ready=false`.
