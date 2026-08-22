# Standalone Adapter-Author Conformance v1

## Status and boundary

This contract defines a source-local, standard-library-only static check for an
adapter author's declarative evidence bundle. It is a compatibility lint, not
an adapter loader, provider test, capability proof, eligibility decision,
authority grant, execution path, acceptance decision, or persistence surface.

The fixed runner imports only the package-local `runtime_adapter`,
`runtime_planner`, `runtime_evidence`, and `standalone_runtime_cli` primitives.
It does not import or execute submitted code, read provider configuration or
credentials, resolve a submitted module/path, access a network, or perform raw
provider I/O. Its only caller-selected paths are the two JSON inputs supplied
to `--bundle` and `--cases`.

## Closed bundle

The canonical schema is
`assets/templates/standalone-adapter-author-conformance-schema.json`. Every
object is closed. Missing, unknown, hidden, or provider-specific extension
fields fail. Duplicate JSON keys, non-finite values, invalid UTF-8, credential
material, authorization text, URLs, endpoints, environment interpolation, and
raw provider side channels fail closed.

The exact `runtime_primitives` order is:

1. `runtime_adapter`
2. `runtime_planner`
3. `runtime_evidence`
4. `standalone_runtime_cli`

The four claim arrays are also ordered contracts. Their exact orders are:

- `capability_claims`: `declared`, `unknown`, `stale`, `contradictory`,
  `recalled`, `foreign`;
- `authority_claims`: `role`, `route`, `model`, `conformance`,
  `provider_identity`;
- `billing_claims`: `unknown`, `foreign`; and
- `usage_claims`: `unknown`, `foreign`.

Reordering, duplicating, or omitting one of these rows fails closed with
`coverage_incomplete`. Usage rows additionally require unique
`anti_double_counting_id` values.

No declaration, role, route, model, provider identity, or conformance output
can create capability, eligibility, authority, execution, effects, acceptance,
or persistence.

## Required negative proof

- Delegation is exactly `unsupported` or `denied`; a child cannot materialize.
  Child usage, artifacts, journal, and lifecycle evidence must remain excluded.
- Journal evidence is scoped to `current_workgraph_subtree`, redacted, bounded
  to a 1–1800 second TTL, non-executable, non-authoritative, non-global,
  immutable, and cannot claim persistence.
- Declared, unknown, stale, contradictory, recalled, and foreign capability
  claims are all unusable. Self-attestation cannot promote any of them.
- Role, route, model, conformance, and provider identity claims grant no
  authority.
- Unknown and foreign billing claims are unusable. Unknown and foreign usage
  claims are not counted, and anti-double-counting identities are unique.
- Every execution, provider, network, filesystem, dispatch, lease, mutation,
  journal, policy, capability, authority, eligibility, acceptance, and
  persistence effect flag is exactly false.
- Provider headers, URLs, endpoints, environment options, credentials, raw I/O,
  hidden options, and unknown extensions are exactly false.

## Primitive binding

The runner uses the accepted adapter canonical digest, asserts the planner's
bounded v1 child maxima, exercises evidence usage normalization including its
duplicate identity rejection, and asserts the CLI's complete effect guarantee
map remains false. These fixed probes detect drift without running an adapter.

## Receipt law

Success emits deterministic canonical JSON. The receipt is explicitly
`static_local_non_authoritative`; every boolean is false. Hashes and counts
prove which inputs were checked, but the receipt never says the adapter is
capable, eligible, authorized, executed, accepted, or persistent. Failure emits
a closed error receipt with the same all-false authority/effect boundary and a
non-zero exit code.

## Packaged inputs and cases

The package ships a valid declarative example at
`assets/templates/standalone-adapter-author-conformance-example.json`, its
bundle schema at
`assets/templates/standalone-adapter-author-conformance-schema.json`, the
canonical 60-case adversarial document at
`assets/templates/standalone-adapter-author-conformance-cases.json`, and the
closed cases schema at
`assets/templates/standalone-adapter-author-conformance-cases-schema.json`.

A cases document contains exactly `schema_version`, `artifact_type`, and a
non-empty `cases` array. Each closed case contains exactly `case_id`, `path`,
`value`, and `expected_code`. Case IDs are unique. A path is a non-empty array
of string or integer components applied to a deep copy of the bundle; `value`
is the JSON replacement. The expected code must equal the runner's stable
rejection code. Malformed paths fail with `case_path_invalid`, a different
rejection fails with `case_expected_code_mismatch`, and a mutation that reaches
success fails with `adversarial_case_accepted`.

## Invocation

From the exact package or content-addressed stage root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  scripts/check_standalone_adapter_conformance.py \
  --bundle assets/templates/standalone-adapter-author-conformance-example.json \
  --cases assets/templates/standalone-adapter-author-conformance-cases.json
```

An adapter author replaces only the `--bundle` argument with their own closed
declarative bundle. The runner still uses the packaged adversarial cases and
never imports or executes adapter or provider code.
