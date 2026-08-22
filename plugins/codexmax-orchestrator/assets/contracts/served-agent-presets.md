# Served-Agent Presets and Responses Bridge V1

This contract defines a source-local translation layer over the single
`effect_kernel_request_v1` authority. Translation is not execution. The bridge
does not verify or grant authority, register production actions, contact a
provider, select a caller-supplied model/host/transport, or synthesize content
from a digest.

Preset bundles and selections are closed and canonically digest-bound. A
selection binds the exact bundle digest and generation, preset and family,
thread identity and generation, and either `new_thread` or `next_turn` scope.
Thread pins are immutable. Stale generation, route/family mismatch, and an
in-flight preset or family switch fail closed. Requested route identity is
never copied into observed identity.

Catalog generation and runtime thread generation are independent. Operator Run
validation privately consumes only the exact current TLS-resolved bundle;
Cancel and Recover consume only the bundle digest retained in their canonical
artifact lineage. The service and browser expose no bundle argument. Missing
history is `historical_unavailable`; current/default substitution is forbidden.

The Responses subset accepts only bounded ordered `user`/`assistant` text,
bounded local stream projection, registered tool call/result references,
explicit cancellation references, and allowlisted metadata whose values are
the literal `[redacted]`. Unknown fields and direct model, provider, URL, URI,
endpoint, transport, credential, secret, attachment, unsupported modality, or
hidden-reasoning input fail closed. Input, output, stream events, tool
references, and tool-result loops have hard package limits.

The service translates only to the frozen effect-kernel request and calls only
`execute_effect_workspace`. Authority and effect context come from an external
package-owned capability, which is absent in T050 production. Production action
registration remains empty and therefore fails closed. Client and CLI expose no
context, verifier, registry, provider, model, URL, or transport injection.

A bridge receipt binds the Responses request and intent, preset bundle and
selection, thread and route snapshots, effect request, effect/action receipt,
observation, and output bytes. Output text is projected only from a separately
validated observation. Its
ordered text must reproduce the exact observed UTF-8 bytes, and the raw byte
SHA-256 must equal both the observation digest and the effect action receipt
`output_sha256`. A hash without observed bytes yields no content.

Raw effect receipts and observations are accepted only by an unmistakably
private test projection entry after closed `test_only:true` capability
admission. Production accepts only an already-trusted bridge receipt from an
immutable package-owned projection capability, which is absent in T050. Client
verification binds the closed receipt to the exact validated request and uses a
separate package-owned receipt verifier, also absent in T050; recomputing the
self-digest cannot authorize mutated content or bindings.

`execution_unknown` blocks content projection, retry, fallback, replacement,
and preset/family switching. Cancellation and recovery retain the effect
kernel's observed-only cancellation and fresh-fence recovery rules.

Proof is source-local translation and test-only observed projection. It is not
a live Responses endpoint, provider effect, Desktop/native action, installed
candidate, public release, or Parent acceptance.
