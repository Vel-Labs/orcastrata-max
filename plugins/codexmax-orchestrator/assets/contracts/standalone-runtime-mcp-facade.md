# Standalone Runtime MCP Facade v1

## Boundary

`scripts/standalone_runtime_mcp.py` is an optional, standard-library-only,
newline-delimited JSON-RPC 2.0 facade. It communicates only through the
launching process's stdin/stdout. It is not a network server, runtime,
authority, provider adapter, MCP dependency, board adapter, or persistence
surface.

The facade imports exactly the fixed sibling `standalone_runtime_cli` and
verifies its raw SHA-256 identity (`d280030d…c8cf`) before every tool dispatch.
It never selects a path, module, executable, environment, provider,
credential, GoalBuddy board, AOL state, installer, or publisher.

## Protocol and lifecycle

The fixed MCP protocol version is `2025-06-18`. One process owns one session
with exact states `created -> initializing -> ready`:

1. `initialize` is the only request accepted in `created`;
2. a successful response moves to `initializing`;
3. the exact `notifications/initialized` notification moves to `ready`;
4. `ping`, `tools/list`, and `tools/call` are accepted only in `ready`.

Requests are closed JSON-RPC objects with `jsonrpc: "2.0"`, a non-null string
or integer ID, a fixed method, and only that method's exact params. Batches are
rejected as one invalid request before dispatch. Notifications never dispatch;
unknown notifications are ignored and only the exact initialized notification
can advance state.

Messages are strict UTF-8 JSON with duplicate keys and non-finite numbers
rejected. The maximum payload is 1 MiB, maximum nesting depth is 32, and
maximum recursively counted JSON items is 10,000. Responses are compact,
sorted-key, UTF-8 canonical JSON followed by one newline.

## Fixed tools

| MCP tool | Anchored CLI command | Meaning |
| --- | --- | --- |
| `codexmax_status_v1` | `status` | Validate an accepted runtime manifest and return status truth. |
| `codexmax_plan_v1` | `plan` | Validate planner input/binding and return a plan preview. |
| `codexmax_run_preview_v1` | `run` | Validate gateway state and inspect a run; no execution occurs. |

Each `tools/call` has exactly `name` and `arguments`; `arguments` has exactly
`input`. The facade constructs the closed CLI request itself. It exposes no
`serve`, `cancel`, `recover`, `delegate`, `journal`, `policy-propose`, or other
CLI command.

## Receipt and errors

A successful tool result is possible only after the facade independently
reconstructs the complete command-specific receipt body from the canonical
submitted `arguments.input`. Digest syntax or a self-consistent forged digest
is never sufficient. `source_sha256` must equal the accepted CLI canonical
digest of that exact input, every required payload must be present, and no
extra root or nested payload is permitted. Semantic comparison happens before
the exact CLI receipt digest is recomputed and checked.

For `status`, the accepted runtime manifest is independently revalidated and
the only payloads are the complete runtime plus the exact lifecycle, health,
and endpoint status projection. For `plan`, the planner source/binding is
independently revalidated, full plan consistency is rerun, route presentation
is reconstructed, selection and child preview must be exact, and
`execution_started` is false. For `run`, gateway state and run identity are
independently verified, the complete canonical run must match, and the only
preview is exactly `requested: true`, `performed: false`,
`operation: inspect_run`, and `requires_separate_admission: false`.

The exact CLI v1/result/command discriminators, `synthetic_local`, structured
output, and `side_effect_free: true` remain mandatory. Recursive validation
rejects added positive effect, provider, credential, authority, acceptance, or
execution claims. These eleven effect guarantees are exactly false: service
start, network, provider, lease, dispatch, run mutation, journal write, policy
persistence, policy activation, authority, and acceptance.

CLI domain rejections become deterministic MCP tool results with
`isError: true`; their original code, path, input, and exception text are not
echoed. Protocol errors use stable JSON-RPC codes/messages. Unexpected failures
emit only `-32603 Internal error`. Neither path can create effects or authority.

The capability schema is
`assets/templates/standalone-runtime-mcp-capabilities-schema.json`. This is
source-local proof only; it is not install, publication, provider, runtime,
GoalBuddy, AOL, or release acceptance.
