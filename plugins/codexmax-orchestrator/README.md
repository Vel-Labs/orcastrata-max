# Orcastrata Max

**One Parent owns the result. Extra inference joins only when it helps.**

Orcastrata Max is the open orchestration plugin for Codex. It keeps one visible
task responsible for planning, useful delegation, integration, and
verification. This task is the Parent.

The package ID remains `codexmax-orchestrator`. The installed skills retain
their `codexmax-*` names as V1 compatibility IDs.

The [Codex Collaboration Runtime Projection](assets/contracts/codex-runtime-projection.md)
prevents semantic routing from collapsing into Codex agent-type defaults. It
records the exact native `agent_type`, model, reasoning effort, inheritance,
fallback, and route authority before a child spawn. Fixed roles must match the
selected route exactly; otherwise Orcastrata returns an approval preview and
stops. Native collaboration is recorded separately from provider dispatch.

This is Parent-governed spawning, not global interception. Codex still owns
`spawn_agent` and executes native children. Orcastrata does not provide model
weights or replace a Codex model with an Orcastrata model. A native spawn
outside an active Orcastrata task path continues under Codex defaults. See
[Runtime Support And Ownership](RUNTIME_SUPPORT.md) for the exact harness
matrix.

Local verification distinguishes three proof classes: `install_state`,
`manual_installed_cache_invocation`, and `automatic_skill_loader`. The
compatibility option `--fresh-invocation-proof` proves only the manual cache
class. Automatic loading requires a separate fresh no-tool JSONL smoke through
`--automatic-loader-proof` and the exact receipt in the orchestrate skill.

## Start In 60 Seconds

After installation, start a new Codex task and ask for the work you want:

```text
Use Orcastrata Max to improve this project's onboarding and verify the result.
```

Native Codex works without another account or configuration file. If needed,
invoke the compatibility skill directly:

```text
Use $codexmax-orchestrator:codexmax-orchestrate to improve this project's
onboarding and verify the result.
```

The visible Parent task remains responsible for the outcome and final answer.
Orcastrata Max does not increase Codex plan limits or include external tool
accounts.

In plain language, Orcastrata Max helps you get three outcomes:

1. One Parent stays responsible for the result.
2. Extra inference joins only when it can improve the result.
3. Every worker stays inside the access approved for its task.

Examples include debugging a defect, building a bounded feature, cleaning up a
repository, researching options before a change, and reviewing completed work.

## Use An Exact Tool And Model

For an existing configured OpenCode or Command Code installation, say:

```text
Use MiniMax-M3 through OpenCode.
```

or:

```text
Use deepseek/deepseek-v4-pro through Command Code.
```

Orcastrata Max checks the existing tool session and exact model. It shows the
selected tool, model, task access, and billing basis before it sends work. If a
check fails, configure that exact tool and try again, or ask to continue with
native Codex. It does not substitute another tool, model, route, or billing
path.

An external request can send authorized task content through that tool. The
tool uses your existing account, privacy terms, quota, and billing.

The tool/model pairing is temporary. Saving it as a preference is optional and
requires separate approval.

## Authority Is Task-Local

The Parent owns the outcome and final answer. Each worker receives only the
access approved for its task. Model identity and reasoning effort never grant
extra file access.

Orcastrata Max does not read, copy, refresh, or store provider credentials.
Authentication remains in the provider tool that you configured.

## Main Skills

| Need | Compatibility invocation |
| --- | --- |
| Run work | `$codexmax-orchestrator:codexmax-orchestrate` |
| Explore first | `$codexmax-orchestrator:codexmax-discover` |
| Inspect setup | `$codexmax-orchestrator:codexmax-config` |
| Choose a route | `$codexmax-orchestrator:codexmax-route` |
| Audit a result | `$codexmax-orchestrator:codexmax-verify` |

The package also includes planning, assignment, supervision, closeout, and loop
skills for advanced workflows.

## Support Matrix

| Surface | V1 status |
| --- | --- |
| Orcastrata-governed native Codex task | Projection before the Parent calls `spawn_agent`; Codex executes the child |
| Unrelated native Codex task or spawn | Not globally intercepted |
| Configured OpenCode route | Exact adapter dispatch after fresh verification |
| Configured Command Code route | Exact adapter dispatch after fresh verification |
| Standalone/provider-neutral contracts | Architecture and qualification substrate; not generic live harness proof |
| Claude, Grok, standalone MiniMax, or other host packages | Roadmap; not public V1 support |
| Provider login or credential storage | Not supported |
| Saved tool/model preference | Approval required |

## First Use

On first use, Orcastrata Max explains the native default and can ask whether you
want to add OpenCode or Command Code. **None** is a valid answer. Native work
does not wait for optional setup, and choosing None creates no file.

If you add a tool, use its own trusted sign-in flow when authentication is
needed. Orcastrata Max runs fresh task-scoped checks before dispatch.

Read [Getting Started](GETTING_STARTED.md) for the complete flow and
[ROADMAP.md](ROADMAP.md) for the product boundary.

Project context and usage records are optional. Ask Orcastrata Max to preview
them before it creates project files. Ask for a used-only usage readout in
ordinary language. It lists only invoked tools and models, keeps missing values
unknown, and never estimates tokens from worker count.

V1 supports exact external requests through configured OpenCode and Command
Code installations. Claude, Grok, standalone MiniMax, and other host packages
are future work. Their names in configuration do not prove a usable V1 route.

Provider workers receive bounded inputs under the
[provider task input contract](assets/contracts/provider-task-input.md).

## Public Project

The public source is
[Vel-Labs/orcastrata-max](https://github.com/Vel-Labs/orcastrata-max).
Install, update, verify, and uninstall commands are in
[Getting Started](GETTING_STARTED.md).

Use [GitHub Issues](https://github.com/Vel-Labs/orcastrata-max/issues) for
support. Use
[GitHub private vulnerability reporting](https://github.com/Vel-Labs/orcastrata-max/security/advisories/new).

Orcastrata Max is licensed under [Apache-2.0](LICENSE). It is local software,
not a hosted provider or credential service.

## Read Next

| If you are... | Read... |
| --- | --- |
| Starting your first task | [Getting Started](GETTING_STARTED.md) |
| Checking data and account boundaries | [Privacy](PRIVACY.md) |
| Preparing a safe issue | [Support](SUPPORT.md) |
| Checking current limits and future hosts | [Roadmap](ROADMAP.md) |
