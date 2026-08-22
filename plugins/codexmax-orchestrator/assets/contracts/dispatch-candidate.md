# Dispatch candidate compiler contract

## Boundary

`compile_dispatch_candidate.py` turns one strict draft route into one scheduler
candidate bound to a current `PreflightBroker v1` observation. It is a local,
deterministic binding step. It never probes a provider, starts a process, uses
the network, inspects authentication, or grants dispatch authority.

The broker observation remains callability evidence only. Task authority,
read/write scope, source compatibility, authentication, quota, billing
permission, capability, independence, and acceptance must be re-evaluated from
the task-specific resolver packet and other admission inputs for every attempt.

## Strict draft

The input is one JSON object containing exactly:

- `name`, `provider`, `exact_model`, `route_id`, `runtime`, `runtime_host`,
  `reasoning`, `billing_basis`, and `independence_group` as non-empty strings;
- positive integer `concurrency_limit`;
- non-negative integer `allowance_units`;
- non-negative integer or the exact string `unknown` for `token_reservation`;
- boolean `cash_reservation_required`;
- repository-relative `evidence_path`;
- object `resolver_packet` and its canonical `sha256:` digest in
  `resolver_packet_sha256`.

Unknown and duplicate JSON fields fail closed. The output-only fields
`adapter_id`, `adapter_sha256`, `preflight_key_sha256`,
`preflight_observation`, and `preflight_binding` are explicitly forbidden in a
draft, so a caller cannot substitute adapter or broker evidence. A
caller-supplied `resolver_packet.adapter_evidence` is also forbidden.

The compiler derives the exact broker key from `provider`, `exact_model`,
`route_id`, `runtime`, and `reasoning`, plus fixed proof mode
`scheduler_artifact_only`. No aliases or caller-selected proof mode are used.

## Locked broker read

`preflight_broker.read_current_observation(path, key, now=...)` is the public
read API. Under the broker's sibling lock it verifies the complete state and
hash chain, selects the canonical exact-key entry, and requires:

```text
observed_at <= now < expires_at
```

It returns the exact observation, key digest, broker `state_sha256`, and SHA-256
of the canonical complete entry. A missing entry, missing observation,
future-dated observation, expired observation, corrupt state, or unsafe state
file fails closed. The CLI exposes the same operation as `preflight_broker.py
current`.

## Compiled binding

Compilation preserves every validated draft field and injects only:

```json
{
  "adapter_id": "canonical dispatcher adapter id",
  "adapter_sha256": "sha256:<dispatcher-source-digest>",
  "preflight_key_sha256": "sha256:<exact-key-digest>",
  "preflight_observation": {
    "schema_version": 1,
    "availability": "available|unavailable|unknown",
    "health": "healthy|unhealthy|unknown",
    "callability": "callable|not_callable|unknown",
    "receipt_descriptor": "non-secret descriptor",
    "receipt_digest": "sha256:<receipt-digest>",
    "key": {},
    "observed_at": "UTC timestamp",
    "expires_at": "UTC timestamp"
  },
  "preflight_binding": {
    "state_path": "repository/relative/broker-state.json",
    "state_sha256": "sha256:<complete-state-digest>",
    "entry_sha256": "sha256:<canonical-entry-digest>"
  }
}
```

The compiler derives `adapter_id` by applying the product-owned dispatcher's
closed adapter selection to the exact route identity and derives
`adapter_sha256` from the regular, single-link dispatcher source bytes. It
The resolver independently repeats that derivation from the same product-owned
dispatcher bytes; the assignment-bound resolver packet is not modified. Route
configuration, draft fields, Worker prose, and broker observations cannot
attest adapter identity.

`state_path` is canonical and repository-relative. The named state must already
exist inside the declared repository root. An outside path, `..`, symlink in
any path component, hard link, directory, device, socket, FIFO, or other
non-regular state path is rejected. The state itself is opened without
following a final symlink and must have exactly one link.

A scheduler must re-read the bound path through the locked broker API at
admission time and require the same key, observation, state digest, and entry
digest. A changed or expired binding is not eligible. Binding is evidence, not
permission, and `unknown` is never promoted.

## CLI

```sh
python3 plugins/codexmax-orchestrator/scripts/compile_dispatch_candidate.py \
  --input candidate-draft.json \
  --repo-root /absolute/repository/root \
  --broker-state runtime/preflight-broker.json \
  --now 2026-07-27T12:00:00Z
```

Successful output is canonical JSON on stdout. A rejection is typed canonical
JSON on stderr with exit status 2.
