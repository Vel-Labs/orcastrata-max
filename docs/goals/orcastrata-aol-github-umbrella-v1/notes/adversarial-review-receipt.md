# Adversarial Review Receipt

Date: 2026-09-01
Task: `orcastrata-aol-github-umbrella-v1-t010-r2`
Frozen input SHA-256: `sha256:0e7050b615ab7e5a896aa9a94e2118a931647e62f7ed379f6a0ace809336da36`
Candidate file SHA-256: `8aff33cc376f564a91e39ff69e45f641ef7543d5dd98d6a7355f97ff7c98d82b`

## Exact Lanes

| Lane | Exact request | Call | Result | Elapsed | Tokens | Artifact |
| --- | --- | --- | --- | --- | --- | --- |
| Grok | `Use xai/grok-4.6 through Command Code` | yes | completed; `REVISE` | 257,701 ms | unknown; provider did not report | `adversarial-r2/fanout/lane-01-a0b61af9fe73/result.json` |
| DeepSeek | `Use deepseek/deepseek-v4-pro through Command Code` | no | rejected; exact identity unverifiable | not applicable | not applicable | no provider artifact |
| MiniMax | `Use minimaxai/minimax-m3 through Command Code` | yes | completed; `REVISE` | 66,552 ms | unknown; provider did not report | `adversarial-r2/fanout/lane-03-7181e131da13/result.json` |

No lane used fallback, substitution, or retry. The initial `r1` packet was
rejected before any provider call because two route strings were malformed and
the full plan exceeded the task prompt ceiling. `r2` used the same decisions in
the bounded frozen candidate.

## Agreement

- Bind the target repository from operator authority. Do not use `origin` as authority.
- Keep T030 strictly read-only and remove all write and merge symbols.
- Persist an intent/prepare record before every GitHub effect.
- Keep revision out of the stable idempotency identity.
- Pin one transport per effect and forbid switching after prepare.
- Keep GitHub access in AOL. Orcastrata consumes versioned observations and returns receipts.
- Make worker branch and path restrictions executable before push.
- Exclude GitHub auto-merge and bind exact merge preconditions.

## Disagreement and Parent Decision

- MiniMax proposed HMAC-signed readiness logs. Rejected. This adds a new key
  lifecycle before existing immutable digests and AOL Assurance prove inadequate.
- MiniMax proposed blocking `gh` from its credential files. Rejected. AOL must
  not inspect credentials, but the trusted `gh` process must be able to use its
  own authenticated store.
- MiniMax proposed a generic transport interface and new readiness command in
  T030. Narrowed. Extend the existing GitHub connector owner with one local
  read-only path and route it through existing operator surfaces.
- Grok proposed treating token measurement as telemetry rather than a gate.
  Accepted. Missing provider counters remain `unknown`.

## Fresh Hypotheses Retained for Implementation

- A credential-bearing repository locator must fail before `gh` invocation.
- Ambient token override variables should not silently change which identity
  the inherited-session probe represents.
- Unknown prepare state must block both retries and later write effects until
  reconciliation returns `applied` or `not_applied`.
- `/orcastrata-audit` must retain its existing verification semantics.
  `/orcastrata-audit-full` is a separate umbrella evidence gate and cannot
  replace AOL Assurance.

## Post-review Operator Correction

The frozen candidate incorrectly placed the standalone GitHub umbrella runtime
inside AOL's control path. The operator corrected the product boundary after
the provider calls:

- open-source Orcastrata must implement and run the workflow independently;
- closed-source AOL is a later consumer that can embed, invoke, or reimplement
  the accepted Orcastrata behavior under AOL-owned product contracts.

The Parent applied this correction in the durable plan and separated the AOL
handoff. The provider results remain useful for transport, idempotency, worker
scope, and audit boundaries. They do not review or validate this later product
split.

## Parent Verdict

`ACCEPT_CORRECTED_PLAN`

T010 is complete after the operator correction. T020 is the only active task.
Implementation authority is not granted.
