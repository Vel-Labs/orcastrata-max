# Protected Grok clean session v1

## Status

This is a pending-only source seam for Grok CLI `1.0.4`. It does not inspect
authentication, start Grok, or call a provider.

The only binding is route `worker_grok_4_6`, route ID
`grok-subscription-4-6`, and model `grok-4.6`. Billing is `unknown`. The
current resolver still reports Grok CLI `1.0.3`. The seam rejects that stale
identity. A later package task must refresh the resolver separately.

## Closed session

The request binds one task, grant, attempt, session, isolated worktree, clean
HOME, clean configuration root, clean project root, assignment, and mode by
exact SHA-256 values. Read-only and scoped-write modes are separate.
Scoped write also binds one exact target, before and after content, mutation
tool, and `read_file -> write_file|edit_file -> read_file` sequence.

The fixed argv uses the exact model, at most 20 turns, strict sandbox,
streaming JSON, one session ID, and only the required file tools. It disables
web search, memory, subagents, and plan mode. It disallows shell, web, and MCP
tools. It disables auto-update. The built-in `--tools` restriction is not task
authority. The validated task grant and Parent reconciliation are authority.

No Grok hook is assumed or invented. The seam also grants no custom endpoint,
plugin, skill, session reuse, extra directory, retry, fallback, or hedge.

## Proof boundary

Clean-root digests are source bindings. They do not prove effective runtime
isolation. Billing remains unknown until a separate accepted OAuth
subscription receipt excludes API-key, custom-endpoint, and metered routes.
Therefore clean-session isolation, OAuth subscription, spawn eligibility,
provider calls, protected production, and T062 remain false.
