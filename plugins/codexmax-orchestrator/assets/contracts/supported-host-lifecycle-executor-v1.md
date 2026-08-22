# Supported host lifecycle executor V1

`supported_host_lifecycle_tool_v1.py` remains check-only.
`supported_host_lifecycle_executor_v1.py` is the separate executor entrypoint.

The local harness uses this fixed sequence:

`PRECHECKED -> VERIFIED -> INSTALLED -> COMMITTED -> ADMITTED -> STARTED -> HANDSHAKE_VALIDATED -> JOURNEY_RUNNING -> STOPPED -> INVENTORIED -> RECONCILED -> CLEANED`

Each journal event binds one candidate generation, nonce, descriptor inventory,
protected-writer receipt, independent-anchor receipt, receiver observation, and
previous event digest. The journal uses compare-and-swap revision and state
checks. It rejects replay, rollback, mixed generation, descriptor substitution,
out-of-order transitions, and partial crash residue without advancing.

Local harness events are non-authoritative. They always report
`production_ready=false`.

Live mode accepts a validated public provisioning packet, an inherited journal
descriptor, an identifier-only opaque credential-agent reference, and an
inherited receiver-owned receipt descriptor. This candidate has no exact
OS-authenticated backend. Live mode therefore returns
`external_backend_not_packaged` after it validates the receipt shape. A caller
mapping or receipt cannot create the missing backend or production authority.

`supported_host_public_provisioning_v1.py` validates public intent for one CA,
one server certificate, six client certificates, eleven distinct service
identities, fixed descriptor roles, root and launch policy, and joint writer and
anchor approval. It rejects private material, private locations, paths,
endpoints, secret-like values, and extra fields. It never mints authority.
