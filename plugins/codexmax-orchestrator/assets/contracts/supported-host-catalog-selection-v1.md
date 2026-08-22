# Supported-host catalog and selection mechanism v1

## Status

This contract defines a repository-local structural mechanism. It does not
define a positive fact source. It does not grant catalog qualification,
selection authority, mutation ownership, or commit authority.

## Decision variants

The ledger accepts four exact variants:

- `catalog_candidate` for `read_operator_preset_bundle`
- `selection_head_candidate` for `read_operator_selection_head`
- `mutation_query_authorization_candidate` for
  `read_operator_selection_mutation`
- `commit_authorization_candidate` for `commit_operator_selection`

Each decision binds the exact identity digest, operation-body digest,
dependency-receipt-set digest, source digest, candidate digest, manifest
digest, and generation.

`issue_decision` requires these expected values, the expected ledger and
operation, the expected head, and the current UTC time. It performs complete
structural validation before it appends. Prior caller validation is not
trusted. Full-chain validation independently checks catalog and head payload
generation against the enclosing decision generation.

Every operation boundary first requires a string and then requires membership
in the closed four-operation set. Malformed stored, expected, constructed, or
read operations return `canonical_operation_invalid` at their exact operation
path. Revocation reasons first require a string. Malformed reasons return
`ledger_revoke_invalid` at `$.reason`.

The mechanism has one typed validator for each closed enum domain:

- operation;
- decision variant;
- decision source identifier;
- ledger event type;
- revocation reason.

Each validator requires a string before it performs membership or an
operation-keyed table lookup. The same validators protect public decisions,
direct issue, stored events, full-chain recovery, payload dispatch, source
construction, and source reads.

## Catalog candidate

A catalog candidate contains at least two presets. Preset identifiers are
unique. Each preset contains only its identifier, family identifier,
definition digest, and qualification-input digest. The qualification-set
digest covers the sorted qualification-input digests. It does not state that
any preset is qualified.

Generation one is the root. It has a null predecessor and an empty history.
Generation N has exactly N minus one history rows. History starts at generation
one. Each row binds its predecessor to the prior row digest. The current
predecessor equals the final history digest.

## Selection head candidate

A selection-head candidate binds the catalog digest, bundle digest, catalog
generation, binding digest, selection digest, and selection version. All
versions and generations use exact positive integers.

## Intent-only authorization

A mutation-query authorization contains only a submission identifier and its
digest. It cannot assert an absent, exact, collision, mutation, head, or result
state.

A commit authorization contains only the submission identity, current
selection digest, requested selection digest, and expected selection version.
It cannot contain a mutation, successor head, or result. The package host
receiver remains the sole owner of committed mutations and successor heads.

## Ledger and recovery

The ledger uses closed JSON-like values and canonical JSON SHA-256 seals.
Every event binds its exact sequence, predecessor, expected head, decision,
operation, and time. Issue and revoke transitions use expected-head
compare-and-swap. Full-chain validation rejects forks, digest drift, time
regression, duplicate decisions, replay, identity collisions, and duplicate
revocation.

Recovery requires an exact externally retained sequence and head digest. A
resealed proper prefix is invalid.

## Source boundary

The four source adapters return the shared T063 `UnavailableFact` type. Each
result contains the exact operation, canonical source identifier, and
`canonical_source_not_implemented` reason. The accepted producer client
normalizes each result to a closed unavailable outcome and submits no positive
fact. The mechanism has no positive fact class or positive return path. Fixtures,
defaults, fallback routes, mutable overlays, certificates, caller routes,
receiver indexes, historical receipts, provider inference, and self-digests
cannot become authority.

## Safety boundary

The mechanism performs no file, environment, endpoint, socket, process,
service, credential, provider, or network I/O. It does not prove a named
producer, durable external anchor, qualified catalog, committed selection,
public certificate, private identity, service, or external execution.
