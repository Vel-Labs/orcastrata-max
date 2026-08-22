# Protected Claude guarded session v1

## Status

This pending-only source seam does not start Claude Code or call a provider. It
grants no authentication or billing authority.

The only binding is `worker_claude_code_sonnet_5`, route
`claude-code-subscription-sonnet-5`, model `claude-sonnet-5`, and Claude Code
`2.1.232`. Billing is `unknown`. The route is not spawn eligible until a
separate subscription receipt exists and managed settings absence is proved.

## Binding

The closed request binds the task grant, task, attempt, session, isolated
worktree, task settings, empty MCP configuration, assignment, and mode. Scoped
write also binds the guard, descriptor, runtime state, exact target, before
and after content, and `Read -> Write|Edit -> Read`. Each artifact uses an
exact SHA-256 digest.

Read-only argv uses `dontAsk`, `--safe-mode`, and `--tools Read`.
Scoped-write argv uses `acceptEdits`, task settings, and
`--tools Read,Write,Edit`. Both modes use the exact model, `--max-turns 20`,
stream JSON, no session persistence, no Chrome, no slash commands, no ambient
setting sources, strict empty MCP configuration, and Parent turn counting.
The scoped-write `PreToolUse` guard is the write authority. `acceptEdits` is
not authority.

No mode permits shell, browser, web, connectors, MCP tools, plugins, skills,
agents, sessions, retry, fallback, hedge, substitution, or proof promotion.

## Proof boundary

Source tests can fabricate all request values and digests. A valid request
still returns `pending_subscription_and_managed_settings_evidence` with
`spawn_eligible: false`, `provider_called: false`, and
`protected_production: false`. Managed settings cannot be disabled from this
source seam. Same-user time-of-check to time-of-use risk remains. This is not
provider, subscription, installed, release, T062, or protected-production
proof.
