# Orcastrata Max

**Give one agent the outcome. Add more inference only when it helps.**

Orcastrata Max is an open orchestration layer for governed tasks across
supported host surfaces. It keeps one visible
task responsible for the result from request through verification. This task
is the Parent. It can use native Codex or selected configured tools.

You can make an exact tool and model request in ordinary language:

```text
Use MiniMax-M3 through OpenCode.
```

Native Codex is enough for normal use. Orcastrata Max does not increase your
Codex plan limits or include external tool accounts.

> Orcastrata is the product family. Orcastrata Max is this plugin.
> `codexmax-orchestrator` and the `codexmax-*` skill names remain V1
> compatibility IDs.

## Why Orcastrata Max

Orcastrata Max provides three plain outcomes:

1. One visible Parent owns the result, integration, and final answer.
2. Extra inference joins only when it can improve the result.
3. Every worker stays inside the access approved for its task.

Use it to debug a defect, build a bounded feature, clean up a repository,
research options before a change, or review completed work. Tool and model
choices are exact and fail closed. Provider authentication stays with the
provider's installed tool. Tests match the risk of the change.

Natural-language role preferences resolve through effective configuration and
current host capability. Exact preferences fail closed when unavailable and
never silently substitute a route.

## The 60-Second Native Path

After the plugin is installed, start a new Codex task and ask for the work:

```text
Use Orcastrata Max to fix the import bug and verify the user-visible result.
```

Native Codex needs no Orcastrata Max configuration. The Parent keeps simple
work direct and uses bounded workers only when they improve confidence or
speed.

You can add clear limits in the same request:

```text
Keep this task native to Codex.
```

```text
Use extra workers only when they materially help. Honor my task-specific model
preferences.
```

```text
Show only the models and tools you used. Keep missing token values unknown.
```

If automatic selection is unavailable, invoke the compatibility skill:

```text
Use $codexmax-orchestrator:codexmax-orchestrate to fix the import bug and
verify the user-visible result.
```

No second provider account is required for native work.

## Native Routing And Provider Limits

Native fixed roles are bound to the exact Codex `agent_type`, model, reasoning
effort, inheritance mode, fallback policy, and route authority. If a fixed-role
request or default-inheritance projection conflicts with the selected route,
Orcastrata Max fails closed and returns an approval preview instead of silently
coercing the route. Explicit route receipts record the effective projection
before a child is started.

An eligible native or provider `usage_limit`, `quota_exhausted`, or
`rate_limit` result can request a new exact Orcastrata route within existing
authority. An exact-route lock remains exact. Rotation creates a new recorded
selection; it never silently changes a running worker's model or crosses from
native Codex collaboration into external-provider dispatch.

### Runtime ownership boundary

Orcastrata Max is an orchestration layer, not a model. In an active Orcastrata
task, the Parent projects the selected semantic role onto an allowed native
Codex agent type, exact model, and reasoning effort before it calls
`spawn_agent`. Codex still owns that tool and executes the child. Installation
does not globally intercept unrelated Codex tasks or spawns.

For a configured and freshly verified OpenCode or Command Code route,
Orcastrata owns the adapter-dispatch decision. The external tool still owns its
authentication, provider session, quota, billing, and runtime. Standalone and
provider-neutral contracts in the package are architecture and qualification
substrate, not generic live-harness proof.

Read the complete
[Runtime Support And Ownership](plugins/codexmax-orchestrator/RUNTIME_SUPPORT.md)
matrix before relying on a native or external route.

## Choose An Exact Tool And Model

If OpenCode or Command Code is already installed and configured, say:

```text
Use MiniMax-M3 through OpenCode.
```

or:

```text
Use deepseek/deepseek-v4-pro through Command Code.
```

Orcastrata Max verifies the existing tool session and exact model. It then
shows the selected tool, model, task access, and billing basis before it sends
work. If a check fails, configure that exact tool and try again, or ask to
continue with native Codex. Orcastrata Max does not switch tools, models,
routes, or billing paths silently.

An external request can send the authorized task content through the selected
tool. That tool uses your account, privacy terms, quota, and billing. Orcastrata
Max does not add an external account or increase your Codex plan limits.

The pairing applies only to the current task. Saving it as a preference is a
separate configuration change and requires your approval.

## First-Time Setup

Orcastrata Max starts native-first. It can then ask whether you want to add an
optional configured tool.

- Choose **None** to continue with native Codex.
- Choose **OpenCode** or **Command Code** to add that tool.
- Complete sign-in with the provider tool itself if that tool is not ready.
- Return to the original task. Orcastrata Max verifies readiness before use.

Orcastrata Max never collects API keys or automates login. A failed optional
route does not block native work unless you explicitly required that exact
tool and model.

Project context and usage records are optional. Ask before creating project
files:

```text
Set up bounded project context and usage for this folder. Show me the changes
before you create them.
```

For a truthful readout, ask:

```text
Show usage for this task. List only tools and models that were used. Mark
missing values as unknown.
```

Worker count never estimates tokens. Work can be complete even when a host does
not report every token counter.

Read [Getting Started](plugins/codexmax-orchestrator/GETTING_STARTED.md) for the
complete first-use conversation.

Provider workers receive bounded inputs under the
[provider task input contract](plugins/codexmax-orchestrator/assets/contracts/provider-task-input.md).

## Trust Model

The Parent owns the outcome and accepts the final result. Your request selects
an exact tool or model when you name one. Each worker receives only its approved
task scope. Model capability or reasoning effort never grants extra access.

## Support Matrix

| Surface | V1 status |
| --- | --- |
| Orcastrata-governed native Codex task | Projection before the Parent calls `spawn_agent`; Codex executes the child |
| Unrelated native Codex task or spawn | Not globally intercepted |
| OpenCode exact tool/model selection | Adapter dispatch after fresh verification of a configured route |
| Command Code exact tool/model selection | Adapter dispatch after fresh verification of a configured route |
| Standalone/provider-neutral contracts | Not generic installed live-harness proof |
| Automatic provider login or credential storage | Not supported |
| Persistent tool/model preference | Optional; approval required |
| Claude session-only plugin path | Candidate-supported; requires authorized host validation and strict manifest validation |
| Grok, standalone MiniMax, or other host-native packages | Roadmap; not public V1 support |
| AOL protected production admission | Separate future gate |

## What V1 Does Not Do

V1 does not increase Codex plan limits, provide external accounts, automate
provider login, silently substitute routes, or save a tool/model pairing
without approval. It does not provide an Orcastrata model, globally intercept
Codex `spawn_agent`, or make an arbitrary harness operational merely because a
contract or adapter candidate is packaged. Claude has a session-only candidate
path that requires authorized host validation and strict manifest validation.
Grok, standalone MiniMax, and other host-native packages remain future work.
Choosing None during optional setup
creates no file.

Interactive native Codex token counters can remain unknown. V1 usage readouts
are on demand. Recurring reports remain future work. Configured provider names
outside OpenCode and Command Code are candidates, not supported V1 exact
external-tool routes.

## Public Skills

| Need | Compatibility invocation |
| --- | --- |
| Run governed work | `$codexmax-orchestrator:codexmax-orchestrate` |
| Explore a repository first | `$codexmax-orchestrator:codexmax-discover` |
| Inspect configuration | `$codexmax-orchestrator:codexmax-config` |
| Select an eligible route | `$codexmax-orchestrator:codexmax-route` |
| Audit completed work | `$codexmax-orchestrator:codexmax-verify` |

Planning, assignment, supervision, closeout, and loop skills remain available
for advanced composition. Most users should start with Orchestrate.

## Install

Use the exact public install, update, verify, and uninstall commands in
[Getting Started](plugins/codexmax-orchestrator/GETTING_STARTED.md). Start a new
Codex task after installation or update so the host reloads the skill inventory.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing the runtime. Keep diffs
small. Add tests only for a distinct behavior, regression, authority boundary,
or user journey. Do not stage the whole repository by default.

Use [GitHub Issues](https://github.com/Vel-Labs/orcastrata-max/issues) for
support. Use
[GitHub private vulnerability reporting](https://github.com/Vel-Labs/orcastrata-max/security/advisories/new).
Never put secrets or private task content in a public issue.

## Roadmap

V1 is native-first for Codex with a session-only Claude candidate path and
configured OpenCode and Command Code routes. Claude host validation remains
separate from installed-loader or adoption proof. AOL custom integration is a
separate boundary. Broader host packages and an Orcastrata family index remain
future work. Manual source invocation of a Codex candidate and session-only
Claude validation do not prove installed-loader adoption.

- [Product roadmap](plugins/codexmax-orchestrator/ROADMAP.md)
- [Security policy](SECURITY.md)
- [Privacy](PRIVACY.md)
- [Support](SUPPORT.md)
- [Apache-2.0 license](LICENSE)

## Read Next

| If you are... | Read... |
| --- | --- |
| Starting a native task | [Getting Started](plugins/codexmax-orchestrator/GETTING_STARTED.md) |
| Using OpenCode or Command Code | [Getting Started](plugins/codexmax-orchestrator/GETTING_STARTED.md) and [Privacy](PRIVACY.md) |
| Preparing a safe issue | [Support](SUPPORT.md) |
| Checking future hosts and deferrals | [Roadmap](plugins/codexmax-orchestrator/ROADMAP.md) |

Orcastrata Max is open source software from Vel Labs. It is not a hosted model
provider, credential broker, or substitute for reviewing changes before use.
