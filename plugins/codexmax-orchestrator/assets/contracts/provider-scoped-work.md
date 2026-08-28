# Provider Scoped Work Contract

## Boundary

Codexmax keeps provider capability and task authority separate.

A `RouteCapabilityCard v1` records the original capability set. A
`RouteCapabilityCard v2` also binds the exact adapter harness and its
demonstrated behavior and tool ceilings. Both record the maximum capability that a fresh,
task-scoped qualification demonstrated. It does not grant that capability to a
task. CLI presence, an authenticated session, a requested model label, and a
historical result cannot create a capability card.

A `TaskExecutionGrant v1` records the original authority set. A
`TaskExecutionGrant v2` also binds the Parent task intent, named tools,
browser, search, connector, validation, and no-retry policy. It records the
exact authority for one task. Effective
authority is the intersection of the card and the grant. An unknown or expired
card denies the requested capability.

Behavior resolution follows `provider-flexible-execution.md`. Reasoning,
verbosity, context, token, turn, latency, and cost controls are not authority.

## Native route ownership

- DeepSeek V4 Pro and DeepSeek V4 Flash use Command Code.
- Claude Sonnet uses Claude Code. Command Code is prohibited for this route.
- MiniMax uses `mmx`. Command Code is prohibited for this route.
- Grok 4.5 and Grok 4.6 use Grok CLI. Command Code is prohibited for these routes.

The runtime, provider, exact model, route ID, subscription billing basis, and
host identity must match the fresh qualification. No adapter may substitute a
provider or use a metered fallback.

## Task grant

The task grant binds these facts:

- task ID, route name, grant ID, lease ID, and fencing token;
- access mode: `none`, `read_only`, or `scoped_write`;
- exact read and write scopes;
- exact command argument arrays;
- network and billing policy;
- isolated worktree or exclusive shared-tree mode;
- base tree digest, issue time, and expiry.

Version 2 also binds the task-intent digest, tool allowlist, browser, search,
and connector policy, validation commands, and `preserve_and_stop` handling for
an unknown execution result.

Version 2 requires the exact task intent at dispatch. Artifact-only, read-only,
and scoped-write intent must match the grant authority class. The dispatcher
rejects an envelope mutation-mode or write-scope mismatch before lease or
process start. Version 1 requires the explicit `legacy_schema_v1` migration
marker.

An external writer uses an isolated managed worktree by default. A shared tree
requires one explicit exclusive writer. The scheduler rejects overlapping
active write scopes. Path traversal, symlink workspaces, stale base trees,
expired leases, route substitution, billing fallback, and writes outside scope
fail closed.

## Input delivery

A qualified local-filesystem route receives source paths and reads the source
directly. The Parent does not copy the same source into an embedded fact pack.
Embedded fact packs remain valid for routes whose demonstrated capability is
embedded-only.

## Change receipt

A write-capable provider returns a `ProviderChangeReceipt v1`. It binds exact
route identity, capability and grant digests, base and result trees, changed
paths, diff digest, commands, validation, duration, usage facts, and explicit
unknowns. It always records `accepted_by_parent: false`.

The Parent reviews the actual diff and validation evidence. The Parent does not
reimplement accepted provider changes from prose. The provider cannot accept
its own work or mutate GoalBuddy.

## Current qualification boundary

Built-in adapters and route cards are configuration candidates. They are not
current qualification receipts. Write mode stays unavailable until a fresh
host transaction proves local read/write and command capability for the exact
runtime and model. MiniMax `mmx` is a message API CLI. It does not gain
repository write authority without a separately qualified adapter-owned tool
loop.

The Claude Code `2.1.232` source seam binds one read-only or guarded
scoped-write attempt to the exact task, session, isolated worktree, settings,
empty MCP configuration, guard, target, content, and artifact digests. It uses
the exact `claude-sonnet-5` route and a maximum of 20 turns. Billing remains
unknown. Managed settings cannot be disabled by this seam. The route is spawn
ineligible and cannot become capability, subscription, package, T062, or
protected-production proof.

The Grok CLI `1.0.4` source seam follows the same task-grant boundary without
inventing a hook. Built-in tool restrictions do not mint authority. The seam
binds one exact task, attempt, session, isolated clean-root set, sandbox,
target, content transition, and Parent-observed read-mutate-read sequence.
Billing and effective clean-session isolation remain unknown. The stale
`1.0.3` resolver identity is rejected. Spawn, provider, T062, and production
flags remain false.

The separate `minimax_mmx_tool_loop` candidate supplies an adapter-owned JSON
text protocol without widening `minimax_mmx`. It exposes only
descriptor-scoped `read_file` and `write_file`. Commands remain disabled. T115
observed the read flow. T117 observed one exact write in an isolated governed
task envelope. That observation does not qualify production writes. The route
stays disabled until the protected receiver proves the complete final-result
and reconciliation lifecycle.


## Task-scoped canary writes

The operator-facing development write seam is limited to one exact regular file in a separate canary worktree. The grant records the target and its exact before digest. The adapter may perform one provider attempt. Reconciliation rejects a missing change, a changed path outside the grant, or a before/after digest mismatch. The receipt starts with `accepted_by_parent: false`.

Rollback restores the captured before bytes and verifies the original digest. This canary proof does not authorize a shared-tree write, protected production, or T062. The Parent must inspect and accept the actual diff separately.

The operator-facing canary uses `isolated_development_live_write`. It requires
an external linked Git worktree and one existing regular target. The runner
derives the capability card, task intent, task grant, one-attempt binding,
guard, settings, descriptor, assignment, state, and deterministic replacement
bytes. The provider performs the edit. The runner accepts no mutation callback
or caller-supplied authority.

The dispatcher excludes Command Code control files from the user-change
inventory only after it binds their initial digests. After execution, it
revalidates each immutable control file and requires the exact terminal
read-write-read state. It then requires the target to be the only changed user
path. A drift, extra path, invalid result, or uncertain mutation stops without
retry or fallback.

The linked worktree is an explicit V1 operator prerequisite. The runner does
not create it. A successful canary removes only its own control files after
reconciliation. A failed or uncertain canary retains the controls and worktree
for forensic review. Do not reuse that worktree for a new task.
