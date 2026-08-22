# Supported-host native supervision mechanism v1

## Status

This contract defines a pure repository-local structural candidate for
`read_operator_supervision`. A structural candidate is not native evidence and
does not grant supervision authority.

## Candidate

The candidate is one closed canonical JSON-like value. It contains:

- one exact native host identity with identity and authentication receipt
  digests;
- one or more authenticated native child identities;
- exact parent edges;
- one observation cursor;
- one predecessor candidate digest;
- exact source, candidate, manifest, generation, service-start, identity,
  operation-body, and dependency-receipt bindings;
- observed and expiry times;
- one canonical SHA-256 candidate digest.

All schema versions, generations, and cursor sequences use exact integers.
Boolean and floating-point values are invalid.

## Topology

The native host is the only root. Every child has exactly one parent. Parent
and child identifiers must exist in the candidate. Child identifiers are
unique. The topology must be connected and acyclic. Every edge digest binds
the exact parent and child identifiers.

Lifecycle state is one of `starting`, `running`, `stopping`, or `stopped`.
An unknown state cannot become a live or running state.

## Continuity

The root candidate has cursor sequence one, no previous event digest, and no
previous candidate digest.

A successor increments the cursor by exactly one. It binds the prior event
digest and the complete prior candidate digest. It retains the exact native
host identity and bindings. Rollback, a skipped cursor, a forked event chain,
or predecessor drift is invalid.

Before continuity comparison, the validator checks the complete predecessor
record non-recursively at `$.previous`. It validates forbidden fields, every
outer and nested closed shape, exact integers, identities, authentication
digests, topology, edge seals, cursor fields, bindings, timestamp order and
maximum lifetime, root or later predecessor fields, and the recomputed
candidate digest. A historical predecessor may be expired. Validation does not
follow its predecessor and does not claim a durable anchor.

## Freshness

All times use exact second-resolution UTC. The observed time cannot be in the
future. Expiry must be later than observation and later than validation time.
The candidate lifetime cannot exceed five minutes.

One canonical temporal helper parses each record timestamp exactly once. It
requires expiry after observation and permits an exact five-minute maximum
lifetime. A current record must have `observed_at <= now` and
`expires_at > now`. A historical predecessor may be expired, but its
observation cannot be in the future. Its observation must be earlier than or
equal to the successor observation. Equality at the observation boundary is
valid. Equality at the current expiry boundary is expired.

## Exclusions

The mechanism rejects collaboration thread, task, and agent metadata. It
rejects synthetic, test, fixture, caller-selected, default, or relabeled native
identities. It rejects environment, path, endpoint, private-key, credential,
provider, and live-status fields.

The native-identity policy normalizes identifiers to lowercase and rejects an
ineligible token at any substring position. The same policy protects the host
and every child. Thus `default-native-root`, `DEFAULT-worker`, and other
default-labeled identities are ineligible.

The mechanism performs no Desktop observation. It performs no file,
environment, socket, process, service, provider, credential, or network I/O.

## Source boundary

`SupervisionSource` implements the accepted T063 source protocol. It always
returns the shared `UnavailableFact` with operation
`read_operator_supervision`, source `native-desktop-inventory-authority`, and
reason `canonical_source_not_implemented`.

The accepted producer client normalizes this result to unavailable and sends
an empty fact payload. The source has no positive fact class or return path.
It does not advance readiness.

## Proof boundary

This mechanism does not prove a real native host, authenticated child,
Desktop topology, process state, observation cursor, durable continuity,
public certificate, private identity, service, credential, or external
execution.
