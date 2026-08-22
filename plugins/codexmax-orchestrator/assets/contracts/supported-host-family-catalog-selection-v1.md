# Supported-host family catalog-selection ledger v1

## Status

This module is the fixed first-party owner for the complete accepted T067
catalog-selection ledger. It constructs and retains the exact T067 bytes. It
does not replace or change the accepted T067 validator.

Source-local execution uses
`source_local_quarantine_non_production`. Source-local output cannot promote to
a production fact or enter T082.

## Fixed authority

The module fixes these values in repository source:

- owner: `catalog_selection`
- principal: `first-party-catalog-selection-producer-v1`
- ledger: `first-party-catalog-selection-ledger-v1`
- accepted mechanism: `supported_host_catalog_selection_v1`

A caller cannot select the owner, principal, ledger identifier, source
identifier, mechanism, current head, source digest, candidate digest, manifest
digest, callback, fixture, result, or promotion state.

The four public mutation methods are operation-specific:

- `publish_catalog`
- `observe_selection_head`
- `observe_mutation_query`
- `authorize_commit`

The methods accept only the exact query bindings and the operation-specific
source observation fields. They do not accept an already built T067 decision,
payload, ledger, or head.

## Operation semantics

`publish_catalog` constructs the catalog generation, predecessor, complete
history, and qualification-set digest. It does not accept those derived
values.

`observe_selection_head` requires a retained active catalog. The owner derives
the exact catalog digest and generation from that retained catalog.

`observe_mutation_query` requires a retained active selection head. Its T067
payload contains only the submission identifier and digest. It does not state
an absent, exact, collision, mutation, head, or result fact.

`authorize_commit` requires a matching retained mutation-query observation and
an active selection head. The owner derives the current selection digest and
expected selection version. The payload is intent-only. The receiver remains
the only owner of the committed mutation and successor head.

Each method enforces its fixed dependency-receipt set. The owner derives all
T067 query-binding digests. It also derives the fixed source, candidate, and
manifest digests.

## Complete ledger retention

The store writes a canonical full-ledger snapshot for genesis and for every
T067 issue or revoke event. Each successor artifact contains the exact retained
ledger bytes. `revalidate_successor` checks the byte digest, canonical JSON,
complete T067 chain, sequence, head, operation, and decision digest.

The owner publishes snapshots with create-only file operations. It synchronizes
each file and directory. It atomically replaces a sealed anchor after the
snapshot is durable. One owner lock protects recovery, exact retry, collision
checks, expected-head compare-and-swap, snapshot publication, and anchor
publication.

Recovery validates every snapshot byte-for-byte. It validates every full T067
chain. It requires a gap-free snapshot sequence. Each successor must contain
the exact predecessor event list. Recovery rejects noncanonical bytes, digest
drift, a fork, a gap, rollback against the retained anchor, truncation, and an
anchor mismatch.

An exact acquisition retry returns the original retained successor bytes. A
changed operation observation or query binding under the same acquisition
identifier is a collision. Revocation is a complete T067 event. It survives
restart. A revoked acquisition cannot regain authority through exact retry.
T067 has no consumption transition, so this family module does not invent one.

## Integration boundary

`LedgerSuccessor` supplies the complete predecessor and successor head,
complete canonical ledger bytes, byte digest, operation, acquisition
identifier, and decision digest. Parent integration can bind these artifacts
into the T089 crash-reconcilable journal. Parent integration must not summarize
or replace the retained T067 bytes.

The module performs no network, socket, service, credential, certificate,
provider, browser, keychain, installation, publication, AOL, or production
action. Temp-root tests are source-local only. Test observations cannot become
production authority.
