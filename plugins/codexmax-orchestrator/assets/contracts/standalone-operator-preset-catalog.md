# Standalone operator configured preset catalog V1

`read_operator_preset_bundle` is a closed pinned-TLS package-host operation.
Current lookup uses `selector:"current"` with a null digest. Historical lookup
uses only a bundle digest derived from a canonical persisted artifact. No
browser, request, CLI, URL, environment, or workspace configuration can supply
bundle bytes, route identity, adapter data, transport, model, provider, secret,
or credential material.

The externally sealed `standalone_operator_configured_preset_bundle_receipt_v1`
binds exact package/admission/effect-state identity, policy/registry/capability
digests, a strictly monotonic catalog generation and predecessor, the complete
closed served-agent bundle and digest, qualified configured bindings, freshness,
canonical receipt digest, and host seal. Every configured binding must match an
exact bundle preset and package action registration by adapter, route, action,
tool, and transport, with non-null adapter-binding, route-identity, and
qualification-certificate digests. Configured-only or nearest-route fallback is
never active.

Current bundles may replay byte-identically or advance by exactly one chained
generation. Historical bytes remain addressable by exact digest; absence is
`historical_unavailable`, never substitution with the current or default
bundle. `preset.catalog` and `preset.select` are both required. The singleton
default bundle remains only the legacy resolver for its own historical records.
Fixture catalogs prove mechanics only, not provider qualification or product
configuration.
