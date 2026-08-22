# Provider subscription qualification V1

The public qualification interface is pending-only. It validates one exact
configured binding, task profile, task, authority digest, challenge digest,
issue time, expiry, route, executable descriptor identity, and AF_UNIX kernel
peer. It reports only unknown availability, health, and callability. It never
grants authorization.

The governed host supplies an executable descriptor and a connected receiver
descriptor. The interface does not accept an executable path, PATH lookup,
arbitrary argument vector, environment, callback, token, closure key,
transaction mapping, protected-writer receipt, or independent-anchor receipt.
It binds executable device, inode, mode, owner, size, modification time, and
SHA-256 before and after inspection. It binds the AF_UNIX descriptor and kernel
peer UID/GID before and after inspection.

The request is validated before descriptor inspection. Its exact interval must
equal the declared TTL and cannot exceed 300 seconds. Future and expired
requests fail. The request task-profile digest must equal the effective binding
task-profile digest.

The public result is always `pending_receiver_owned_qualification`. It has
`authorization_granted=false` and `serializable_authority=false`. It creates no
protected transaction, registry receipt, preflight observation, provider call,
retry, or fallback. The preflight broker and resolver may display this pending
status. They cannot use it to authorize dispatch.

The adapter registry has no detached qualification application function. It
rejects every detached `qualified` mapping. Copying, serializing, modifying, or
reusing a pending projection cannot change a configured binding.

The live dispatcher also fails closed before provider execution for external
subscription routes. Its current detail is
`pending_receiver_owned_qualification:os_bound_protected_transaction_required`.
It makes zero provider calls and does not fall back.

A future positive path must consume one non-serializable protected transaction
inside the same live dispatch operation. The existing OS-bound protected
service must own it. That transaction must bind byte-equal protected-writer and
independent-anchor ledger receipts and authoritative service start/session and
generation. No current Python or public API represents this object. T062 owns
that external protected-service evidence.
