# Explicit Tool And Model Routing

## User request

The public request form is:

```text
Use <exact model> through <OpenCode or Command Code> [bounded task text].
```

The model text is case-sensitive and exact. The tool name is `OpenCode` or
`Command Code`. The request contains one leading route clause and at most 4,096
characters. A second route clause fails before dispatch. A request to persist,
save, remember, or make the pairing a default requires separate approval.
Incidental task words do not request persistence. Orcastrata Max does not guess
or silently replace the tool, model, route, billing path, or adapter binding.

## Task-local selection

`explicit-route preview` resolves one enabled configured adapter binding. It
runs two fixed, bounded adapter-owned commands against the tool's existing
session. Command Code uses `commandcode status --json` and
`commandcode --list-models`. OpenCode uses `opencode providers list` and the
non-refreshing generic command `opencode models`. The OpenCode parser strips
ANSI output, requires the bounded credential listing to end with a positive
credential count, and binds the requested provider through the exact
`provider/model` token. It does not retain or emit the credential-store path.
The Command Code parser requires the exact documented status keys and types,
requires `authenticated=true`, records the sanitized observed tool version,
and extracts exact first-column model tokens while ignoring bounded header and
blank lines. It does not retain or emit the status user, provider, or model
values. A failure emits only a fixed probe stage. It never emits tool output.
Bounded OpenCode stderr is
accepted only when it contains no authentication prompt or error marker.
Output that is not machine-verifiable fails with `identity_unverifiable`. The
probe does not log in, refresh authentication, inspect credential material,
create a profile, or run the requested task. A missing session, zero credential
count, credential prompt, nonzero result, absent exact model token, malformed or
oversized output, or timeout fails closed.

The resulting `ExplicitToolModelSelection v1` binds:

- task ID and task-grant digest;
- exact public tool, model, provider, route, runtime, and billing identity;
- the sanitized observed Command Code version when that tool was requested;
- effective-config, adapter, and binding digests;
- a non-secret digest of the bounded probe output; and
- `persistence: none` and all no-substitution controls.

The preview grants no authority and starts no task execution. The model or tool
identity never supplies read or write access. The normal task grant remains the
only authority source.

## Execution

Put the complete selection in the normal route packet as
`explicit_selection`. Set `task_grant_sha256` to the same task-grant digest.
Restrict the selected task profile, preflight map, and attempt-result map to the
one selected route. The route resolver verifies the selection digest, task,
grant, and exact route identity. It rejects every fallback-bearing packet.

The existing candidate compiler carries and validates the complete selection
and its digest. The scheduler re-runs the task-bound resolver, revalidates that
selection, and admits one route. `run-one` revalidates the selection against
the task grant and exact route before process start. It then checks that the
adapter argv contains the selected exact model. No second dispatcher or
authentication path exists.

## Persistence

The V1 selection expires with the task and is not saved. If the operator asks
to save or remember the pairing, stop and request approval for a separate
adapter-binding preference change. A conversational request alone does not
authorize that write.

## Proof boundary

Focused source tests can prove parsing, configured-binding selection, fixed
probe behavior, digest binding, single-route resolution, and fail-closed
substitution. They do not prove an installed tool session, live provider
availability, provider execution, billing, installation, or publication.
