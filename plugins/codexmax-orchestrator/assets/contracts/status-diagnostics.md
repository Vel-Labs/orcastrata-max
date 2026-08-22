# Codexmax Status, Diagnostics, And Support Contract

## Boundary

`codexmax_status.py` is a deterministic repository-local, read-only status and
support surface. GoalBuddy remains canonical board truth. The command cannot
mutate GoalBuddy, grant scope or acceptance authority, dispatch a provider,
invoke a subprocess or network route, read credentials or transcripts, select
billing, install a plugin, or prove installed or native Desktop behavior.

Native visible Desktop supervision is fixed as `experimental/unavailable`.
Status output cannot promote that capability from configuration, cache
presence, a runtime state, or a support receipt.

## Command

All inputs are explicit absolute canonical paths beneath one canonical
repository root:

```sh
python3 plugins/codexmax-orchestrator/scripts/codexmax_status.py status \
  --repository-root "$PWD" \
  --board "$PWD/docs/goals/<goal>/state.yaml" \
  --inventory "$PWD/reports/<run>/t001/release-inventory.json"
```

Optional `--journey-state` and `--recovery-state` inputs project durable resume
and recovery state. Their absence is `not_run`; a named absent input is
`missing`. `valid`, `stale`, `invalid`, `unreadable`, `missing`, `not_run`, and
`unknown` remain distinct. Invalid, unreadable, ambiguous, aliased, or
contradictory state never becomes a resumable success.

## Compact Status Shape

The status projection always exposes:

- outcome and canonical operational status;
- exact local proof boundary and limitation;
- one material failure or `none`;
- the decision needed or `none`;
- GoalBuddy-backed next-ready task and action;
- source and installed versions plus evidence state and relation;
- a recovery action that never reconstructs state from transcript;
- provider, model, route, runtime, billing, quota, tokens, and marginal cost as
  literal `unknown` when no verified measurement exists; and
- explicit read-only capabilities with `acceptance_authority: false` and
  `board_mutated: false`.

The release inventory is projected through an allowlist. Its source-manifest
row must hash-match the current source manifest. A stale receipt cannot supply
an installed version. Its last reported installed version and relation may
remain visible under explicit `last_reported_*` names. A version mismatch and
same-version content drift are different failures. Reported parity remains
receipt evidence only; it does not prove the current cache unless the owning
release checkpoint separately revalidates it.

## Stable Descriptor And Input Rules

Every input is bounded to 4 MiB and must be a unique regular file with one
filesystem link. Paths must be absolute, lexically canonical, free of `..`,
contained by the repository, and resolve without a final or parent symlink.
Inputs are opened with `O_NOFOLLOW` when available. `fstat`, `lstat`, resolved
name, device, inode, link count, and size are compared before and after the
bounded descriptor read. Hardlinks, duplicates, substitutions, invalid UTF-8,
duplicate JSON keys, unsupported versions, oversized input, and unreadable
files fail closed with stable error classes.

The command imports only the local GoalBuddy snapshot parser. It never calls a
mutation entry point. It does not execute validation text, recovery actions,
provider commands, the local-install probe, the configuration resolver, or a
subprocess. Projections extract only named scalar, status, count, digest, and
boolean fields; raw input objects and exception text never enter output.

Optional saved configuration and local-install receipts are projected rather
than embedded. Configuration output contributes only execution-started state,
token/spend limits, silent-fallback policy, and route availability/billing
counts. Local-install output contributes only probe status, named proof-level
statuses, and an installed version when the manual installed-cache proof is
`present`. Neither receipt is executed, and its paths, messages, history,
exceptions, command output, and credential-adjacent fields are excluded.

Route availability and configuration billing basis are validated against the
owning schema enums before they can become output keys or values. Unsupported
nominal values project only as `unknown`, mark the receipt invalid, and never
echo the original string. Spend limits are either null or finite positive
numbers; integer spend limits and token limits must also fit the exact JSON
integer range, `1..9007199254740991`. Token limits are otherwise null or
positive non-boolean integers. Invalid or oversized budgets fail closed.

JSON parsing rejects `NaN`, `Infinity`, and `-Infinity` constants. Canonical
serialization always uses `allow_nan: false`, so no non-standard numeric token
can enter status, failure, support, or export output.

Unexpected internal projection exceptions are converted to the stable
`internal_projection_error` failure receipt. Exception types, messages, values,
and tracebacks are never emitted.

## Redaction And Telemetry

Default output contains only repository-relative allowlisted locators. It
never includes an absolute local path, environment variable, credential,
authorization header, key, cookie, raw exception, command output, raw
transcript, thread identifier, process identifier, or arbitrary message.

Telemetry collection is disabled. The command makes no upload, background
write, network call, or automatic retention decision. Unknown identity,
billing, quota, token, cost, and runtime values remain `unknown`, never zero,
empty, omitted, or inferred. A future opt-in collector requires a separate
contract and authority; this command contains none.

## Support Bundle And Retention

`support-bundle` constructs a new allowlisted normalized object from the status
projection. It does not sanitize, copy, or embed arbitrary input objects. The
bundle inventories each section, its provenance class, redaction mode, and
excluded content. It states that telemetry and upload are disabled.

Without `--output`, the bundle is written only to stdout. File export requires
the explicit flag and a missing destination beneath an existing canonical
repository parent. It uses exclusive creation, mode `0600`, `O_NOFOLLOW` when
available, `fsync`, post-write identity verification, and no overwrite.

Retention is operator-managed: delete the file after the support case closes.
Codexmax performs no automatic upload, expiration, deletion, or retention.

## Failure And Recovery

- Stale journey or recovery hashes: do not resume; inspect current durable
  state and repair only under existing authority.
- Invalid, unreadable, missing, aliased, or ambiguous state: do not replace or
  infer it; inspect the owning contract.
- Interrupted recovery transition: use the owning snapshot or reconciliation
  path before resume. The status command does not run that path.
- Conflicting journey and recovery projections: preserve both source files and
  require a bounded Parent/operator repair decision.
- Source/cache drift: keep the contradiction visible and route parity repair to
  the owning immutable release checkpoint.

No recovery action mutates GoalBuddy or grants authority. Parent Codex remains
the only acceptance authority.

## Exit And Serialization

Output is one canonical, key-sorted JSON object with no implicit timestamp.
Exit `0` means the read-only projection has no material failure, exit `1` means
attention is required, and exit `2` means fail-closed invalid or unreadable
input. Exit status never implies Parent acceptance.
