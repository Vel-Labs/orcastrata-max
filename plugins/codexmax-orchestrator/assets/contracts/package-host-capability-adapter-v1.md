# Package host capability adapter V1

The package contains one stdlib-only leaf adapter shared by the effect gateway,
Responses bridge, runtime service, and operator binding. Production resolves
only package-relative trust and capability data whose exact bytes are listed in
the release manifest. No public production constructor, mutable singleton,
request, workspace manifest,
environment variable, or caller parameter can supply a package root, socket,
URL, SSL context, CA, verifier, registry, handler, model, provider, or secret.
The only alternate-root loader is `_for_test`; it requires a closed trust
document with `test_only:true`; it is a scoped context that restores the fixed
production adapter on normal and exceptional exit. The private implementation
constructor cannot associate an alternate root with production mode. This
module boundary assumes the running Python process is not compromised; names
alone are not the trust boundary. The cryptographic boundary is the fixed,
release-pinned root plus TLS-authenticated host.

Source data is intentionally `configured:false`, so it fails closed without
opening a socket. T060 selects, writes, and proves the exact supported-host
trust, public-CA, and capability bytes; T065 independently audits those bytes;
T070 only inventories and manifest-pins bytes already accepted by T060 and
T065. The package CA contains no private key. Test CA,
certificate, and private-key material exists only below
`tests/fixtures/package-host-capability/` and is non-production.

Configured transport is exactly TLS 1.3 over `AF_UNIX` `SOCK_STREAM` with
`CERT_REQUIRED`, hostname checking, the pinned CA digest, and exact DNS SAN.
Same-uid socket possession, plaintext AF_UNIX, TCP/UDP, wrong CA, wrong SAN,
stale/cross-identity response, and replay do not authenticate a host. The
attacker model excludes modification of pinned package bytes, compromise of the
host private key, or compromise of the running process.

The closed protocol binds a random session nonce and per-request nonce, one of
fourteen semantic operations, exact workspace/source/candidate identity,
operation-specific closed body, issuance/expiry, request digest, correlated
response, and response digest. Responses are fresh for at most 60 seconds and
are accepted once. The fourteen operations are `verify_effect_authority`,
`invoke_registered_action`, `issue_responses_context`,
`verify_responses_bridge`, `read_capability_admission`,
`commit_or_verify_record`, `seal_or_verify_projection`,
`open_operator_listener`, veto-only `read_operator_supervision`,
`read_operator_preset_bundle`, `read_operator_selection_head`, side-effect-free
`read_operator_selection_mutation`, `commit_operator_selection`, and private
`read_operator_recovery_lease_grant`. The recovery read binds admission,
binding, selection, predecessor request/receipt, reconciliation, no-successor,
expected CAS, and current time, and returns only an externally TLS-sealed
`effect_kernel_recovery_lease_grant_v1`. Its complete fresh lease and reserved
ordinary authority ID never come from browser, caller, workspace, CLI, URL, or
environment input. Listener
admission is endpoint-free and binds the exact five-route digest with
`host_binds_http:false`; only the package HTTP server binds numeric loopback.
Supervision requests contain only admitted binding/thread/selection facts and
return unavailable or a TLS-authenticated monotonic receipt. There is no
generic command or transport operation.

The preset catalog operation resolves only current with a null digest or exact
history by an artifact-derived digest. It validates the sealed qualified
catalog against the immutable action allowlist. Selection lookup returns only
absent, collision, or the original externally sealed mutation; it never changes
the head. Commit validation binds the complete current head, catalog, thread,
version, and submission context. Catalog and thread generations are independent.

Action registrations are data-only immutable allowlist rows with no `test_only`
marker or caller handler. Gateway production execution mints a private package
binding and alone may call `invoke_registered_action`, after validating the
exact action/tool/transport/parameter snapshot. Raw registries and verifiers
remain exclusive to the explicit test execution entry. The gateway remains the
only effect/state writer.
Record seals and projection seals are host-authorized but never replace local
closed-shape, digest, authority, and cross-lineage validation.

Proof is source-local plus a temporary local TLS-over-AF_UNIX fixture. It is not
installed-host, real-host-certificate, provider/native, browser, public, AOL, or
T075 evidence.
