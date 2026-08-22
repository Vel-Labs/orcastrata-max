# Visible Provider Bridge Operator Runbook

This runbook covers the evidence boundary for an operator-driven visible
provider dispatch. It does not authorize provider, network, authentication,
installation, billing, or Codex Desktop host actions.

## Before compilation

1. Parent Sol derives the trusted authority record from the active goal's
   approved authority boundary. Do not accept an authority record or digest
   produced only by the assignment, worker, or provider.
2. Parent records current live concurrency and confirms it is within the exact
   authority ceiling. Unknown, stale, or inferred concurrency fails closed.
3. Confirm the route, exact model, runtime, subscription billing, artifact-only
   scope, no external writes, no credential action, and current preflight all
   match the trusted record. A mismatch requires a new Parent decision.
4. Treat quota as normally requiring `available`. Literal `unknown` may cross
   pre-dispatch only for exact `worker_deepseek_v4_flash` when the trusted
   authority binds `quota_observability: unsupported`, billing is exactly
   subscription-only, the profile contains one route, and every attempt and
   circuit ceiling is one. Any provider refusal or quota error is terminal.

## Evidence to retain

- The digest-valid task state and schedule manifest.
- The raw provider return, including exact route identity, the one-attempt
  record, usage or literal unknown values, and
  `external_call_performed: true` for any selected success.
- The raw artifact and the existing artifact validator's immutable byte-level
  evidence. Matching descriptors alone are not raw-byte validation.
- The deterministic quality receipt and reconciliation packet. Both remain
  `accepted: false` with `sol_decision: pending` until Parent Sol reviews them.

## No-call finalization

After a completed single live attempt, run
`finalize_visible_provider_dispatch.py` with the preserved task state,
admission, envelope, assignment, execution binding, ledger, return manifest,
Supervisor event bundle, and raw provider artifact. Name three new output
paths for the quality receipt, final schedule manifest, and visible
reconciliation receipt. None may alias an input or contain pre-existing
partial bytes.

The command is strictly post-dispatch. It must report
`provider_call_performed: false`, `runner_imported: false`,
`runner_invoked: false`, `accepted: false`, and `sol_decision: pending`.
An exact replay returns `already_finalized`; changed or partial outputs fail as
a collision. Identity drift, descriptor/hash mismatch, missing bytes, more
than one attempt, fallback, non-live proof, or inconsistent event evidence
fails closed. Do not rerun the provider to repair finalization evidence.

A selected successful return with a missing, false, or non-boolean
`external_call_performed` marker is rejected. Do not relabel synthetic or local
fixture evidence as a performed provider call.

## Codex Desktop host boundary

Compilation emits only a presentation request with
`host_action_performed: false`. Set `host_action_performed: true` only from
real host evidence after Codex Desktop actually creates or operates the task.
A title, provider label, local fixture, or compiled request does not prove task
creation, sidebar visibility, message delivery, readback, or archive behavior.

## Proof boundary

Local validation proves only deterministic compilation, reconciliation, and
fail-closed invariants in the checked source tree. It does not prove Codex
Desktop sidebar behavior, installation or installed-byte parity, a live
provider call, provider authentication or quota, external native-model hosting,
or Parent Sol acceptance. Those claims require separate fresh host and provider
evidence and a Parent decision.
