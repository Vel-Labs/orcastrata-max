# Protected Command Code session v1

## Status

This is a pending-only source boundary. It does not read a credential, call a
protected service, launch Command Code, call DeepSeek, or qualify a route.

One shared session layer supports exactly two immutable bindings:

| Route | Route ID | Exact model |
|---|---|---|
| `worker_deepseek_v4_flash` | `commandcode-subscription-deepseek-v4-flash` | `deepseek/deepseek-v4-flash` |
| `worker_deepseek_v4_pro` | `commandcode-subscription-deepseek-v4-pro` | `deepseek/deepseek-v4-pro` |

Both bindings require Command Code `1.23.2` and subscription billing. No other
route, route ID, model, runtime, or billing basis is valid. A failure for one
binding cannot select the other binding.

## Public request

The closed request binds an explicit task, route, route ID, exact model, mode,
Command Code version `1.23.2`, subscription billing, the observed Command Code
link, package, entry, Node, sandbox, and worktree descriptor identities, the
exact argv and environment digests, an opaque credential-reference digest,
challenge, expiry, sequence, protected writer, and independent anchor.

The task value must use the closed identifier format. The task, route, route ID,
model, runtime, billing basis, mode, descriptor identities, argv, environment,
and opaque reference digest must match again at capability inspection.
Cross-model substitution fails before any protected service call.

For scoped write, the prepared session also binds the complete validated
`CommandCodeScopedWriteGrant` by `scoped_write_grant_sha256`. That grant binds
the exact task, route, model, attempt, session, worktree, path, content,
read-mutate-read sequence, and guard, settings, descriptor, assignment, and
state digests. Read-only preparation rejects a supplied scoped-write grant.

The public `capability_checksum_sha256` and prepared checksum are consistency
checks only. A caller can compute both. They do not prove provenance or grant
provider, credential, launcher, service, or route authority.

## Protected boundary

A future launch requires a kernel-authenticated distinct-UID service. That
service must issue an unforgeable one-use capability after it verifies the
bound task, route, model, descriptors, argv, environment, worktree, challenge,
writer, and anchor. The service must durably enter `consuming` before launch.
A restart in `consuming` becomes `execution_unknown`. All terminal states
forbid retry.

The future launcher receives inherited Node, entry, sandbox, and worktree
descriptors. It receives bound argv and environment digests and the opaque
service capability. It does not accept a pathname, `PATH`, shell, ambient
environment, or raw authentication reference. This source contains no launcher
implementation.

The maximum turn count is 20. The mandatory flags are `--no-session`,
`--no-skills`, `--skip-onboarding`, and `--no-auto-update`. Read-only mode uses
`plan`. Scoped-write mode requires the validated guarded grant and uses
`--yolo --tools-enable read_file,write_file,edit_file`. The `--tools-enable`
value is non-authoritative. The mandatory `PreToolUse` guard supplies the
allowlist. No mode grants shell, `--tools-all`, retry, fallback, hedge, model
substitution, or proof promotion.

## Privacy boundary

The public prepared dataclass, its representation, and `dataclasses.asdict`
contain only the credential-reference digest. They contain no raw reference,
reference path, prompt, argv values, or environment values.

## Proof boundary

Source-local fixtures can fabricate every public claim and recompute every
checksum. A canonical fabricated request still returns
`pending_distinct_uid_service_capability` with zero service, launcher, and
provider calls. Missing receiver facts start no provider process. No live
session, model entitlement, provider availability, provider callability,
subscription allowance, or route qualification follows from this contract.
