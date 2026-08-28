# Getting Started With Orcastrata Max

Orcastrata Max is native-first for Codex. After installation, it can begin work
without a second model account, API key, or project configuration file.

The V1 package and skill names use the compatibility ID
`codexmax-orchestrator`. Keep that ID in explicit skill invocations.

Orcastrata Max provides three plain outcomes:

1. One Parent stays responsible for the result.
2. It adds extra inference only when that can improve the result.
3. Each worker stays inside the approved task access.

Use it to debug a defect, build a bounded feature, clean up a repository,
research options before a change, or review completed work. You ask once. The
Parent remains responsible, even when it uses one or more useful workers.

## 1. Install The Public Release

Add the public Git marketplace and install Orcastrata Max:

```sh
codex plugin marketplace add Vel-Labs/orcastrata-max --ref main --json
codex plugin add codexmax-orchestrator@codexmax-orchestrator --json
codex plugin list --marketplace codexmax-orchestrator --json
```

The final command must show the installed and enabled version you expected.
If it does not, stop. Do not guess which package Codex loaded.

To update to a later published version, refresh the Git marketplace and
reinstall the plugin:

```sh
codex plugin marketplace upgrade codexmax-orchestrator --json
codex plugin remove codexmax-orchestrator@codexmax-orchestrator --json
codex plugin add codexmax-orchestrator@codexmax-orchestrator --json
```

To uninstall Orcastrata Max and its marketplace entry:

```sh
codex plugin remove codexmax-orchestrator@codexmax-orchestrator --json
codex plugin marketplace remove codexmax-orchestrator --json
```

Start a new Codex task after installation so the host reloads its skill
inventory.

The first conversation uses the currently installed package. It does not need
to search old plugin caches, reports, goals, archives, or memory. If Codex shows
an older package or an ambiguous skill identity, use the normal update or
reinstall command. Start a new task. Do not delete caches manually.

## 2. Make A Native Request

Ask for the result you want:

```text
Use Orcastrata Max to fix the import bug and verify the user-visible result.
```

If automatic selection is unavailable, use:

```text
Use $codexmax-orchestrator:codexmax-orchestrate to fix the import bug and
verify the user-visible result.
```

Orcastrata Max keeps the visible task responsible for the outcome, integration,
verification, and final answer. This task is the Parent.

Add limits in ordinary language when you want them:

```text
Keep this task native to Codex.
```

```text
Use extra workers only when they materially help. Do not use Terra.
```

```text
Use Sol high for the Parent and Luna high for useful workers.
```

```text
Show usage for this task. List only tools and models that were used. Keep
missing token values unknown.
```

Native Codex needs no external account or setup file. Orcastrata Max does not
increase your Codex plan limits.

If the requested native model or effort is unavailable, Orcastrata Max reports
the mismatch and does not substitute another choice silently. You can approve
an available native route, change the request, or stop that part of the work.

### Native agent-type defaults

Codex native agent types can carry their own fixed model defaults. Orcastrata
Max projects each semantic role onto an allowed native `agent_type`, exact
model, and reasoning effort before spawning. A fixed-role mismatch fails
closed. A `default` worker is allowed only when inheritance is explicit and
unambiguous; otherwise Orcastrata shows an approval preview instead of silently
inheriting the Parent model. The dispatch receipt records the semantic role,
native type, exact model, effort, inheritance, fallback, runtime surface, and
route authority.

Native Codex collaboration is not provider dispatch. If an eligible native
route returns `usage_limit`, `quota_exhausted`, or `rate_limit`, Orcastrata asks
its route resolver for another allowed model and records the new projection.
An exact-route lock remains exact and does not rotate. External-provider
failures remain governed by the provider dispatch and retry contracts.

### Where Orcastrata governance applies

Orcastrata governs this native projection only when the task has loaded or
explicitly invoked Orcastrata Max. Codex still owns `spawn_agent` and executes
the native child. The plugin does not globally intercept unrelated Codex
spawns, register an Orcastrata model, or replace native model weights.

OpenCode and Command Code use a different boundary: for a configured and
freshly verified exact route, Orcastrata owns the adapter-dispatch decision.
The external tool still owns its provider session, authentication, quota,
billing, and runtime. Standalone and provider-neutral contracts in the package
are not proof of a live generic harness. Read the complete
[Runtime Support And Ownership](RUNTIME_SUPPORT.md) matrix before relying on a
non-Codex route.

### Complete native example

This transcript shows the expected interaction. It is an example, not evidence
that an installed package or live task ran.

```text
User: Use Orcastrata Max to debug the failed import and verify the fix. Keep
this task native to Codex.

Orcastrata Max: I will keep this Parent task responsible for the result.
Native Codex is ready and needs no second account. Would you like to add an
already-configured OpenCode or Command Code installation? You can answer
"None," and I will continue now.

User: None.

Orcastrata Max: I will stay on the native Codex path. Choosing None creates no
file. I will inspect the failure, make only the needed changes, and run the
focused check that covers the user-visible import behavior.

[The Parent inspects the project, repairs the import, and runs the focused
check.]

Orcastrata Max: The import now succeeds in the focused check.
- Parent: native Codex
- Additional tools and models used: none
- Token values: unknown; the host did not provide counters
- Files changed: src/imports.py and tests/test_imports.py
- Validation: python -m pytest tests/test_imports.py; 3 passed
- Remaining risk: the full test suite was not run
```

## 3. Choose An Exact Tool And Model

If OpenCode or Command Code is already installed and configured, ask for the
exact pairing:

```text
Use MiniMax-M3 through OpenCode.
```

or:

```text
Use deepseek/deepseek-v4-pro through Command Code.
```

You can include the bounded task in the same request:

```text
Use deepseek/deepseek-v4-pro through Command Code to review this patch. Read
only.
```

Use one exact tool-and-model clause. A second route clause fails. A request to
save, remember, persist, or make the pairing a default also stops for separate
approval.

Orcastrata Max checks the tool and verifies the existing session and exact
model. For Command Code, a model that has no saved binding can use an in-memory
binding on the package-owned generic transport. This does not save a profile.
An existing disabled binding remains disabled. OpenCode requires a saved
provider binding. Orcastrata does not read credentials, start login, or refresh
authentication.

Before dispatch, you receive a preview like this:

```text
Tool: OpenCode
Model: MiniMax-M3
Route: worker_minimax_m3_opencode
Authority: current task grant only
Persistence: none
Fallback: disabled
```

The actual preview also identifies the tool runtime and billing basis. The
route is the exact tool-and-model path selected for this task. The task grant
is the approved read and write scope.

An external route can send the authorized task content through the selected
tool. That tool uses your existing account, privacy terms, quota, and billing.
Orcastrata Max does not include that account or increase your Codex plan limits.

If the requested tool or model cannot be verified exactly, dispatch stops. You
can configure that exact tool and try again, or ask to continue with native
Codex. Orcastrata Max does not silently use another tool, model, route, or
billing path.

OpenCode and Command Code are the only public V1 exact external-tool surfaces.
The exact model is data within an approved transport. For example, Command
Code can expose compatible DeepSeek, MiniMax, or Grok models without a new
source-code route for each model. A new transport still needs a package-owned
adapter and qualification. A provider name in configuration is only a
candidate. It does not prove an installed, authenticated, or eligible route.

### Configure and run a model

Ask Orcastrata to create an immutable binding candidate:

```text
Configure minimaxai/minimax-m3 through Command Code as an Orcastrata worker.
Then run a read-only review with that exact model.
```

Orcastrata uses only model identity and package-controlled transport fields.
It does not accept an executable, endpoint, URL, argv, environment, token, or
secret from this request. The default declaration is task-local. A fresh
session and exact-model probe must pass before the task gets authority or
starts. Ask separately if you want to save the pairing.

For normal work, do not name a model:

```text
Use Orcastrata Max to review this change with a compatible available worker.
```

Automatic selection uses the task role. It probes enabled candidates first.
It can then inspect the fixed Command Code model catalog and create temporary
generic-transport candidates. It starts one compatible route and reports the
exact provider and model. It does not save discovery or treat an ordered list
as fan-out.

For an adversarial review, name the route set explicitly:

```text
Use DeepSeek Pro, MiniMax M3, and Grok 4.6 as separate adversarial reviewers.
Give each the same frozen candidate and rubric. Continue the other lanes if
one times out. Do not substitute or retry a failed lane.
```

Each lane gets a distinct task, evidence directory, artifact, and receipt.
The Parent performs synthesis. A timed-out lane remains a timed-out lane.

Implementation uses a pre-created linked development worktree. The provider
reads the task and returns a unified diff. It receives no repository write or
shell authority. Orcastrata validates the patch against an exact allowlist of
existing regular files, applies it, runs exact Parent-authorized validation
commands, and returns a durable rollback receipt. The older one-file
read-edit-read path remains a fixed security canary only. Neither lane grants
shared-tree or protected-production write authority.

### Complete exact external-route example

The success and failure branches below show the required V1 interaction. They
are illustrative transcripts, not claims of live provider execution.

```text
User: Use deepseek/deepseek-v4-pro through Command Code to review this patch.

Orcastrata Max: I will verify the existing Command Code session, the exact
deepseek/deepseek-v4-pro model, and the approved task access. I will not log in
or substitute another route.

Orcastrata Max: Route preview
Tool: Command Code
Model: deepseek/deepseek-v4-pro
Runtime and billing: existing Command Code account
Authority: read-only review of the current patch
Persistence: none
Fallback: disabled

User: Continue with that preview.

Success branch:
Orcastrata Max: The verified route completed the review.
- Tool and model used: Command Code, deepseek/deepseek-v4-pro
- Result: one missing error-path test was returned to the Parent
- Usage: unknown; Command Code did not report counters for this example
- Final acceptance: still owned by the Parent

Fail-closed branch:
Orcastrata Max: Dispatch did not run. The existing Command Code session or the
exact deepseek/deepseek-v4-pro model could not be verified. No other tool or
model was used. Configure that exact pairing in Command Code and retry, or ask
me to continue with native Codex.

User: Continue with native Codex.

Orcastrata Max: I will use native Codex for this task. I did not save the
external pairing or create a fallback preference.
```

## 4. Understand Read And Write Access

The approved task scope controls authority:

| Decision | Control |
| --- | --- |
| Tool and model | Your exact request or eligible task route |
| Maximum operations | Current tool capability |
| Actual file access | The approved task scope |
| Final acceptance | The Parent task |

A model never receives write access because it is more capable or uses more
reasoning. A worker can write only when its task approves the exact scope.

## 5. Optional First-Time Setup

On first use, Orcastrata Max can explain its native defaults and ask whether
you want to add an optional tool.

```text
I will keep this Parent task responsible for the outcome. Native Codex is
ready. Do you want to add a configured OpenCode or Command Code installation?
"None" is valid, and native work does not wait for this choice.
```

If you choose **None**, work continues with native Codex. Orcastrata Max does
not create a configuration file only to record that answer.

If you choose a tool, Orcastrata Max previews its configuration. It does not
collect secrets. Complete any required authentication inside that tool's own
trusted sign-in flow. Then return to the original task.

A failed optional setup does not block native work. An explicit exact-tool
request does fail closed because substitution would violate your instruction.

## 6. Save A Pairing Only When You Want It

The default pairing is task-local. To reuse it later, ask separately to save it.
Orcastrata Max must show the configuration change and receive approval before
it writes a persistent preference.

## Advanced Options

Most users can stop here. The next three sections are for maintainers and
operators who want project context, machine-readable usage, or local telemetry.

Treat a nonzero exit or typed error from an advanced command as a failure. Do
not infer success from partial output. Correct the named input and retry the
same command, or continue without that optional feature.

## 7. Add Project Context And Managed Usage

Project context is opt-in. Native-only work creates no project files. When you
want Orcastrata Max to remember bounded project guidance, start in chat:

```text
Set up bounded project context and usage for this folder. Use AGENTS.md as the
context file. Show me the proposed files before you create them.
```

Orcastrata Max explains the project marker and asks for approval before it
writes. You do not need a terminal command for ordinary use. The following CLI
is an optional advanced equivalent:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  <plugin-root>/scripts/orcastrata_project.py init \
  --project-root <project-root> \
  --project-id <stable-project-id> \
  --context-file AGENTS.md \
  --skill-id codexmax-orchestrate
```

The marker stores hashes, not copied context. Orcastrata Max reads the nearest
valid marker for the current folder. To review more than one project, create a
workspace marker with explicit project roots; it never scans unregistered
directories. Installed skill IDs are references only and are not executable
project authority.

The actual CLI can create that explicit workspace marker:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  <plugin-root>/scripts/orcastrata_project.py init-workspace \
  --workspace-root <workspace-root> \
  --workspace-id <stable-workspace-id> \
  --project <project-id>=<relative-project-root>
```

If initialization does not return a success receipt, do not treat project
context as active. Check the named path or input, then retry, or continue
without project context. Native work does not depend on this setup.

Managed dispatch usage is written only for initialized projects to
`.orcastrata/usage/dispatch.jsonl`. Ask for a used-only readout. It includes
input, cached-input, output, reasoning, and total tokens when the provider
reports them. Direct counters are `observed`. If a receipt omits total tokens,
Orcastrata Max can record a `derived` input-plus-output total. Unknown values
remain unknown with a reason. Models that were not called are not listed.

Work status and accounting status are separate. A completed task can remain
unaccounted when its usage record fails or the host omits counters. Usage
coverage applies only to Orcastrata-managed executions. Worker count never
estimates tokens. Keep unavailable accounting fields `unknown` with the stated
reason; do not turn an accounting failure into a work failure.

Use these exact CLI shapes for on-demand readouts from the actual V1 usage
tool:

```sh
# This initialized project, across all recorded months.
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  <plugin-root>/scripts/project_usage.py \
  --project-root <project-root>

# This initialized project, for one month.
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  <plugin-root>/scripts/project_usage.py \
  --project-root <project-root> \
  --month 2026-08

# All projects in one explicit workspace registry, for one month.
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  <plugin-root>/scripts/project_usage.py \
  --workspace-root <workspace-root> \
  --month 2026-08
```

The workspace command reads only projects registered in
`.orcastrata/workspace.json`. It does not scan other folders.

## 8. Import A Bounded Native Usage Receipt

A supported native receipt can add usage metadata without saving its
transcript. Stream the host events directly into the importer:

```sh
codex exec --json <ordinary-task-prompt> | \
  PYTHONDONTWRITEBYTECODE=1 python3 -B \
  <plugin-root>/scripts/project_usage.py \
  --project-root <project-root> \
  --import-codex-json - \
  --task-id <stable-task-id>
```

The importer reads the stream once. It stores a source digest and line count,
not prompts, responses, commands, stdout, stderr, or transcript bytes. It
writes only bounded accounting metadata to
`.orcastrata/usage/dispatch.jsonl`. Identical imports are idempotent.

## 9. Inspect Local Loop Telemetry

When a project is configured, you can request a read-only metadata snapshot:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  <plugin-root>/scripts/orcastrata_telemetry_snapshot.py \
  --project-root <project-root>
```

Add `--receipt <path>` once for each loop receipt that you want to inspect.
Each receipt must have its adjacent `.trace.json` companion. The command
verifies the ledger chain and returns its exact cursor, managed dispatch rows,
scoped accounting coverage, and root or nested loop ancestry. Loop receipts
stay adjacent evidence and do not become ledger rows. The command prints JSON
to stdout and does not write, upload, start a server, or read transcript
content.

## Useful Follow-Up Requests

```text
Use $codexmax-orchestrator:codexmax-discover to map useful improvements. Do not
change files yet.
```

```text
Use $codexmax-orchestrator:codexmax-config to explain the effective routes.
```

```text
Use $codexmax-orchestrator:codexmax-verify to audit the completed work.
```

```text
Show usage for this task. List only tools and models that were used. Explain
which values are observed, derived, or unknown.
```

```text
Prepare a sanitized support report for this problem. Include the package and
host versions, the smallest reproduction, and the exact error code. Replace
private paths and task content with placeholders. Do not include credentials,
prompts, responses, source code, hashes, or unneeded execution metadata. Show
me the report before I share it.
```

## V1 Limits

Orcastrata Max V1 does not:

- increase Codex subscription or plan limits;
- provide, authenticate, or pay for external accounts;
- support exact external routes other than configured OpenCode and Command
  Code installations;
- silently substitute a tool, model, route, or billing path;
- save a tool/model pairing without separate approval;
- create a file when you choose None during optional setup;
- guarantee token counters that a host does not report;
- automatically account for interactive native Codex collaboration;
- globally intercept native Codex `spawn_agent` calls;
- provide an Orcastrata model or replace native model weights;
- turn provider-neutral contracts into a live generic harness;
- run recurring monthly reports; or
- provide Claude or other non-Codex host packages.

Project, month, and registered-workspace usage readouts are on-demand V1
features. Recurring reports and non-Codex host packages are future work.

## Get Help

Use [GitHub Issues](https://github.com/Vel-Labs/orcastrata-max/issues) for
support.
Use
[GitHub private vulnerability reporting](https://github.com/Vel-Labs/orcastrata-max/security/advisories/new)
for security reports. Never put credentials or private task content in an
issue.

Read the [package README](README.md), [security policy](SECURITY.md),
[privacy policy](PRIVACY.md), and [roadmap](ROADMAP.md) for more detail.

## Read Next

| If you are... | Read... |
| --- | --- |
| A new or native-only user | Sections 1, 2, 5, and 6 above |
| An OpenCode or Command Code user | Section 3 and [Privacy](PRIVACY.md) |
| A project maintainer | Sections 7 through 9 above |
| Preparing a safe issue | [Support](SUPPORT.md) |
| Checking deferrals and future hosts | [Roadmap](ROADMAP.md) |
