# Supported-host Darwin launch authority v1

Status: source-local protocol implemented; production authority pending

## Authority boundary

This contract defines `LaunchProofV3`. It does not create launch authority.
Source-local code can validate shape, binding parity, freshness, and replay
inputs. It cannot prove a live macOS fact.

The receiver must independently own each live observation. A caller mapping,
callback, fixture, certificate, digest, Python class, object, sentinel, or
source-local simulation is not authority. A complete source-local envelope
returns `pending_receiver_owned_live_attestation`.

The protocol does not launch a process. It does not reopen a pathname. It does
not inspect a host. It does not write a ledger. It does not issue an admission.

## Closed LaunchProofV3 schema

The envelope uses:

- `schema_version`: `3`.
- `artifact_type`: `codexmax_darwin_launch_proof_v3`.
- `protocol_version`: `supported_host_darwin_launch_proof_v3`.
- `candidate_id` and `candidate_descriptor_sha256`.
- `generation`, `nonce_sha256`, and `r3_transaction_digest`.
- All live observation fields in the next section.
- `proof_sha256`, which is the canonical digest with this field set to an empty
  string.

The schema is closed. An extra field or a missing field is invalid. A
self-consistent digest only protects canonical transport. It does not prove
provenance or authority.

## Receiver-owned live observations

The proof binds these facts:

- Immutable generation manifest digest and generation.
- Absolute generation-root path.
- Ancestor-chain digest.
- Root device, inode, mode, UID, GID, and ACL digest.
- Entrypoint device, inode, and digest.
- Fixed launchd label, domain, job digest, program, arguments digest, and
  generation.
- Distinct service ID, UID, GID, group-set digest, and generation.
- Static team ID, signing ID, CDHash digest, designated-requirement digest, and
  executable digest.
- Fresh challenge digest, response digest, generation, and issue time.
- Audit-token digest, PID, effective UID, effective GID, process start ID, and
  generation.
- Live team ID, signing ID, CDHash digest, designated-requirement digest,
  executable digest, and generation.
- Service start ID, session ID, and instance generation.
- Observation time and expiry time.

Each field can be `null` while the receiver observation is missing. Each
missing field has the exact state `pending_<field>_observation`. The field order
in `LIVE_OBSERVATION_FIELDS` gives deterministic precedence when more than one
observation is missing. The no-envelope source boundary reports
`pending_generation_manifest_sha256_observation` and lists all live observation
fields as missing. An empty mapping is an invalid envelope.

## Fixed parity rules

The generation must be exactly one higher than the previous R3 committed
generation. Rollback uses a new higher generation and a fresh nonce. All
generation fields must equal the reserved generation.

The static executable digest must equal the entrypoint digest. The live code
identity must equal the static code identity. The audit-token effective UID and
GID must equal the distinct service UID and GID. The protected generation root
UID must differ from the service UID.

The challenge time must not be later than the observation time. The observation
must not be in the future. The expiry must be later than both the observation
and the current receiver time.

The assessor validates each relationship as soon as all inputs for that
relationship are present. An unrelated missing field cannot hide a same-UID,
generation, manifest, code-identity, challenge, start, session, freshness, or
expiry failure. Only the remaining uncheckable observations can cause pending.

The receiver clock must be a timezone-aware `datetime`. Another value fails
with `darwin_launch_clock_invalid`. A timezone-naive `datetime` fails with
`darwin_launch_clock_timezone_required`.

## Mandatory rejection

Reject these substitutions:

- Path, ancestor-chain, root vnode, or entrypoint vnode.
- Manifest, generation, nonce, or R3 transaction.
- launchd label, domain, job configuration, program, or arguments.
- Service UID, GID, group set, ID, start, or session.
- Static or live code identity.
- Audit token, PID, effective identity, or process start.
- Challenge, response, time, observation, or expiry.

Reject proof replay, nonce replay, rollback, generation gaps, mixed-generation
evidence, same-UID root and service identity, stale evidence, expired evidence,
and identity parity failure.

A PID-only, label-only, signature-only, or same-UID claim cannot satisfy the
closed schema. A source-local complete envelope remains pending. PID reuse and
service restart fail through changed process-start, service-start, or session
bindings. No rejection or pending result can advance the R3 ledger.

## Live proof split

T060 must prove the protected generation root, absent-only publication,
ancestor invariants, distinct service account, fixed launchd job, static code
identity, audit-token process identity, and live code identity on macOS.

T062 must prove challenge freshness, launch and service sessions, restart,
crash recovery, revocation, forward-generation rollback, PID reuse rejection,
service restart rejection, and mixed-generation rejection.

Only receiver-owned live proof can cross this boundary. Source-local R6 remains
pending.
