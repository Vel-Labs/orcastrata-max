# Orcastrata Max

**Give one agent the outcome. Add more inference only when it helps.**

Orcastrata Max is an open orchestration plugin for Codex. It keeps one visible
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
Use extra workers only when they materially help. Do not use Terra.
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
| Native Codex Parent and workers | Primary path |
| OpenCode exact tool/model selection | Supported for configured connections |
| Command Code exact tool/model selection | Supported for configured connections |
| Automatic provider login or credential storage | Not supported |
| Persistent tool/model preference | Optional; approval required |
| Claude or other host-native packages | Roadmap |
| AOL protected production admission | Separate future gate |

## What V1 Does Not Do

V1 does not increase Codex plan limits, provide external accounts, automate
provider login, silently substitute routes, or save a tool/model pairing
without approval. Choosing None during optional setup creates no file.

Interactive native Codex token counters can remain unknown. V1 usage readouts
are on demand. Recurring reports and Claude or other non-Codex host packages
are future work. Configured provider names outside OpenCode and Command Code are
candidates, not supported V1 exact external-tool routes.

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

V1 is native-first for Codex with configured OpenCode and Command Code routes.
Future work can add host-neutral packaging and an Orcastrata family index
without duplicating this repository.

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
