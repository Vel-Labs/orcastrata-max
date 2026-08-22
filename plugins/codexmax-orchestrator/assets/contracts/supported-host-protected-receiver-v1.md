# Supported-host protected receiver v1

Status: source implemented; live host facts and production authority pending.

## Authority and process boundary

The production receiver is a fixed launchd job. It runs as a distinct non-login
UID. The client connects only to
`/var/run/codexmax/protected-provider-receiver-v1.sock`. A dispatch request
contains only a task selector and receiver-owned freshness bindings. These are
the expected generation, fresh challenge, service start, and service session.
It cannot contain a route, provider, model,
executable, path, token, certificate, callback, or authority mapping.

The protected receiver owns the task, authority, route, provider, exact model,
billing basis, authentication status, health, challenge, one-attempt status,
and raw-result custody. No positive authority crosses the socket as a reusable
object. The source-local client never trusts a terminal response. It validates
the closed response and then returns only `pending_host_facts`. It cannot
authorize a caller-side provider process or make the CLI exit zero.

The client checks the kernel peer UID and socket identity before and after the
exchange. The peer must use the configured distinct receiver UID. A same-UID
peer stays pending before the request is sent. A peer, socket, challenge,
selector, generation, service-start, or service-session change fails closed.

## Immutable launch binding

The native component exposes only one collector ABI. It accepts a protected
root descriptor. It opens the fixed
`provider-runner` entrypoint with descriptor-relative `openat` and
`O_NOFOLLOW`. It collects before and after root and entrypoint vnode, owner,
mode, size, time, and process facts itself. Zero facts, symlinks, writable root
modes, owner mismatch, same-UID operation, or fact drift fail closed. The
source candidate returns typed pending when audit-token, process-start, or code
identity primitives are unavailable. It cannot accept a caller-filled positive
attestation struct. Fact validation is a file-local helper. It is reachable
only after the collector has opened descriptors and collected the facts. The
public header and object symbol table expose no caller-filled fact validator.
Native adversarial builds can enable a compile-time test hook. The hook mutates
collector-owned facts or open descriptors after the first snapshot. It is not
compiled into the production object. It is not declared in the production
header and does not add a production ABI symbol.

The production receiver also binds the immutable generation and manifest. It binds the
fixed launchd label, domain, job, program, arguments, distinct UID and GID,
static code identity, live code identity, audit token, PID, process-start fact,
service start, service session, and fresh challenge.

The protected root UID must differ from the service UID. Before and after vnode
facts must be byte-equal. Static and live code identity must be byte-equal. A
path, PATH lookup, PID, digest string, certificate, self-digest, or `/dev/fd`
assumption is not sufficient authority.

## Durable one-use transaction

The protected writer and independent anchor are the only durable authority.
They retain separate closed records for each transition. The anchor binds the
exact writer record digest. Both records bind the same transition digest:

```text
pending_host_facts -> generation_reserved -> launch_attested
-> transaction_issued -> transaction_consuming
-> consumed_success | consumed_failure
```

`revoked` is terminal before consumption. The receiver commits
`transaction_consuming` before it attempts a provider process. A restart that
finds `transaction_consuming` must append and synchronize `consumed_failure`
through the writer and anchor path. It must not retry. Source-local recovery can
exercise this durable algorithm, but it reports `production_ready=false` and
`authority_issued=false`.
Replay, fork, rollback, generation drift, binding drift, writer and anchor
divergence, process reuse, session drift, and vnode substitution fail closed.

The transaction binding digest covers the task, authority, generation,
challenge, launchd identity, vnode facts, code identity, audit and process
identity, service session, route, provider, model, billing, authentication,
health, executable, attempt, and raw-result custody descriptor.

## Lifecycle and proof boundary

Live lifecycle verbs delegate to this fixed backend. They stay pending with no
state advance when the backend or exact host facts are absent. Local harnesses
can validate journal mechanics and native parity only. They always report
`production_ready=false`. T062 owns real macOS, launchd, account, code-sign,
audit-token, provider, and lifecycle evidence.

The packaged console entrypoint imports package-owned code. It does not resolve
or load a mutable checkout-relative script.

Every live dispatcher adapter uses the protected-receiver gate before any
provider capture path. This rule applies to the complete registered adapter
set and to future adapter IDs. Native Codex and OpenCode are not exceptions.

Source-local restart recovery holds an exclusive advisory lock from journal
read through failure append, file synchronization, and final revalidation.
Concurrent recovery therefore serializes on one current journal state.
