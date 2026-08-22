# Supported-host service store v1

Status: source-local implementation complete; live service-account evidence pending

## Owners

The protected writer owns one fixed writer root. The independent anchor owns a different fixed anchor root. The writer never receives an anchor-store object and never opens the anchor root. It requests retention through the framed, kernel-authenticated anchor-service client. The direct in-process anchor gateway exists only for temp-root tests and rejects a service-owned anchor.

A service process can create a service-owned root only when its effective UID and GID equal its configured service account. Each root and namespace directory uses mode `0700`. Each manifest, head, pending intent, event, anchor record, and namespace lock uses mode `0600`. Each manifest has a canonical digest.

The writer manifest contains the exact twelve-operation map. Each row binds one operation to its protocol namespace, canonical source ID, and producer principal ID. A namespace can hold more than one operation. This is required for the four responses-seal operations and the three selection operations. The store validates the operation row on append and recovery.

`create_source_local` creates a temp-root store with the permanent scope `source_local_temp_root_non_production`. This scope only removes authority. It cannot grant authority. A caller cannot change that root into a service-owned root. Live authority also requires the current AF_UNIX peer checks in the protected-service protocol.

## Exact T082 transaction

The writer accepts an exact `protected_durable_append_request_v1`. It checks the configured namespace owner, producer principal, expected sequence, expected generation, expected head, record ID, nonce, transition target, and event kind.

The writer holds one process lock for the namespace from expected-head validation through the anchor response and local commit. It publishes an absent-only pending intent and creates the T082 writer statement. The independent anchor checks its own current head. It retains the exact request and statement. It creates the exact `protected_anchor_receipt_v1`. The writer then creates the exact `protected_durable_append_receipt_v1`, publishes the immutable event with an atomic no-replace link, publishes the successor head atomically, and removes the completed pending intent. Files and parent directories are synchronized at each publication boundary.

The same transaction supports `fact`, `revoke`, and `consume`. Consumption is limited to the recovery namespace by the T082 schema. Revocation and consumption records survive restart.

## Recovery and rejection

Recovery scans every canonical sequence name and validates every T082 request, writer receipt, and anchor receipt. It rebuilds the writer head and anchor head. It rejects rollback, fork, replay, record collision, nonce collision, transition replay, missing transition targets, truncation, extra residue, non-canonical JSON, links, wrong modes, and changed ownership.

An interrupted exact pending intent can continue only when the independent anchor has retained the matching exact request and writer statement. An event that exists before head publication can continue only with that pending intent. A pending intent without an anchor remains a typed recovery failure. It is not discarded or relabeled as success.

## Proof boundary

Temp-root tests prove the persistence algorithm, exact T082 continuity, atomic publication boundaries, restart reconciliation, and fail-closed behavior. They do not prove a distinct live account, a fixed external root, launchd ownership, a live AF_UNIX peer, credential-agent operation, or a positive receiver binding.
