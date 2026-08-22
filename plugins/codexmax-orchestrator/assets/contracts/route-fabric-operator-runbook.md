# Route Fabric Operator Runbook

This is a local, non-executing operating guide. Configuration inspection does
not qualify a route, launch a provider, install software, change subscriptions,
or transfer acceptance from Sol Parent.

## Inspect and validate

From the repository root, use the absolute repository path when invoking the
resolver:

```sh
python3 plugins/codexmax-orchestrator/scripts/resolve_codexmax_config.py --help
python3 plugins/codexmax-orchestrator/scripts/resolve_codexmax_config.py \
  roles --repo-root /absolute/path/to/codexmax-orchestrator --json
python3 plugins/codexmax-orchestrator/scripts/resolve_codexmax_config.py \
  validate --repo-root /absolute/path/to/codexmax-orchestrator
```

`roles --json` reports gateway/provider, exact model, reasoning, billing, and
identity/capability status separately. The six route slots are an ordered
candidate list, not proof of callability. `worker_commandcode_*` routes are
Command Code gateway candidates with distinct underlying model slugs. The
separately configured Claude, MiniMax, and Grok routes are never aliases.

## Qualify or onboard a route

1. Add or inspect only a bounded candidate entry; keep identity and capability
   fields unknown or unverified until evidence exists.
2. Run the existing fresh preflight for the exact provider, model, runtime,
   billing basis, input profile, and adapter. Do not infer identity from
   provider prose or a model name.
3. Retain the preflight, capability-card, qualification-certificate, route,
   and usage receipts with their SHA-256 bindings. A certificate is eligibility
   evidence, not dispatch or acceptance authority.
4. Validate trajectory, decision, clean-handoff, and correction-economics
   receipts through the local Route Fabric. Unknown tokens, quota, latency, and
   cash remain unknown with reasons; never substitute zero.
5. Admit and launch only through the existing scheduler and provider adapter,
   after fresh preflight and task-scoped authority. One attempt, retry, and
   fallback ownership remain with the scheduler.

## Observe, disable, recall, and roll back

- Inspect receipts by operation with the local Route Fabric CLI. Preserve raw
  provider bytes, ledger order, and prior digests; never normalize or overwrite
  them. Each request is one frozen JSON object passed to:
  `python3 plugins/codexmax-orchestrator/scripts/route_fabric.py --input
  /path/to/request.json`. The bounded operations are
  `validate_capability_card`, `effective_certificate_status`,
  `validate_recall_chain`, `derive_trajectory_signals`, `build_recall_event`,
  `build_clean_handoff`, `calculate_correction_economics`, and
  `choose_advisory_action`.
- Disable a route through a versioned configuration overlay setting its
  `enabled` field to `false`, then run `validate`. This prevents new admission;
  it does not delete history or alter old receipts.

  Example existing artifact: `/absolute/path/to/config-overlays/2026-08-05-route-disable-v1.yaml`

  ```yaml
  schema_version: 3
  route_registry:
    routes:
      worker_commandcode_grok_4_5:
        enabled: false
  ```

  Validate that artifact without executing work:

  ```sh
  python3 <plugin-root>/scripts/resolve_codexmax_config.py \
    validate \
    --repo-root <absolute-repository-root> \
    --workspace-config /absolute/path/to/config-overlays/2026-08-05-route-disable-v1.yaml
  ```
- Recall a certificate by appending a matching, authority-bound, hash-chained
  recall event. Effective status is derived as `recalled > expired > stale >
  active`; do not mutate or reissue the certificate to add recall IDs.

  The exact local request envelope, with placeholders replaced only by existing
  hash-bound values, is:

  ```json
  {
    "schema_version": 1,
    "operation": "build_recall_event",
    "payload": {
      "subject_scope": "route",
      "subject_id": "<EXACT_ROUTE_ID>",
      "subject_sha256": "<SHA256_ROUTE_SUBJECT>",
      "reason_code": "<BOUNDED_RECALL_REASON>",
      "created_at": "<UTC_TIMESTAMP>",
      "authority_sha256": "<SHA256_RECALL_AUTHORITY>",
      "previous_event_sha256": "<SHA256_PREVIOUS_EVENT_OR_INITIAL_HEAD>"
    }
  }
  ```

  Validate an existing frozen request artifact with:

  ```sh
  python3 plugins/codexmax-orchestrator/scripts/route_fabric.py \
    --input /absolute/path/to/t070-recall-request-v1.json
  ```

  The command constructs one event receipt; persistence is append-only and
  external. It does not call a provider or alter the issued certificate.
- Roll back by selecting the prior reviewed configuration artifact and
  revalidating it. Keep both old and new files, receipts, and hashes immutable;
  rollback is not a release or installation claim.

  For example, validate the named prior artifact without overwriting it:

  ```sh
  python3 <plugin-root>/scripts/resolve_codexmax_config.py \
    validate \
    --repo-root <absolute-repository-root> \
    --workspace-config /absolute/path/to/config-archive/codexmax.config.2026-08-05T120000Z.yaml
  ```

  After onboarding, inspect the effective six-slot identities without dispatch:

  ```sh
  python3 <plugin-root>/scripts/resolve_codexmax_config.py \
    roles \
    --repo-root <absolute-repository-root> \
    --workspace-config /absolute/path/to/config-overlays/2026-08-05-route-onboard-v1.yaml \
    --json
  ```

## Boundaries and stop rules

Command Code is a multi-model gateway; gateway identity and exact underlying
model identity must both remain in receipts. External providers remain
external attempts, never native Codex Desktop subagent identities. OpenCode/
Qwopus is reference-only and cannot be enabled in the default configuration.
Sage remains local-only; no API, proxy, credential import, or telemetry sink is
authorized by this goal.

Stop immediately on identity drift, stale or missing preflight, execution
unknown, authority/credential/billing/retention uncertainty, schema or digest
drift, raw-source leakage, silent or identity-changing provider fallback, or a request to mutate acceptance
or GoalBuddy. Sol Parent reviews and accepts; configuration and Workers never
self-accept.

Any future Sage experiment needs a new GoalBuddy task and explicit operator
authority covering endpoint, billing, secret bootstrap, retention/deletion,
no-training terms, frozen schemas, call cap, and stop conditions. Every field
needs necessity review; use unlinkable experiment-scoped commitments and a
quarantined shadow-only response sink that cannot influence routing, admission,
budgets, retries, fallback, mutation, authorization, or acceptance.
