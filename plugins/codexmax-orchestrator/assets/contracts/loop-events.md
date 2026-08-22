# Loop Event And Run Receipt Contract

## Boundary

`LoopEvent v1` is the provider-neutral input to registry matching.
`LoopRunReceipt v1` is the immutable result of validation, matching, admission,
optional fixed-profile execution, and proof recording. Neither artifact grants
authority, mutates GoalBuddy, installs a hook, activates a schedule, or proves
Parent acceptance.

An admitted run also writes an adjacent `LoopRunTraceV1` companion. The trace
binds the receipt ID, loop identity, event digest, source, and origin. The
receipt artifact row binds the exact trace file bytes. The telemetry snapshot
computes the exact receipt file digest after it validates the pair. The trace
records only run ancestry, event identity, execution status, and output
descriptors. It is optional observability evidence. It does not replace,
extend, or authorize a `LoopRunReceipt v1`.

Both are strict UTF-8 JSON objects. Unknown fields, duplicate keys, non-finite
numbers, unsupported versions, oversized inputs, and command-bearing data fail
closed. Event limits are 65,536 bytes, depth 16, 2,048 nodes, 256 items per
array/object, and 4,096 UTF-8 bytes per string. Receipt limits are 262,144
bytes, depth 16, 4,096 nodes, 256 items per array/object, and 16,384 UTF-8 bytes
per string. At most 64 ordered errors are emitted. Canonical serialization is
JSON with UTF-8, sorted keys, compact separators, and a trailing newline.
Digests use those bytes.

## LoopEvent v1

An event has exactly these fields:

| Field | Rule |
| --- | --- |
| `schema_version` | integer `1` |
| `artifact_type` | exact `LoopEvent` |
| `event_id` | stable ID, unique across retained event history |
| `event_type` | canonical event type |
| `occurred_at` | RFC3339 UTC timestamp supplied by the adapter |
| `observed_at` | RFC3339 UTC timestamp, not before `occurred_at` |
| `source` | exact adapter/source identity mapping |
| `origin` | exact run ancestry and recursion mapping |
| `workspace_root` | exact `.` |
| `subject` | exact normalized subject references |
| `requested_scope` | exact requested read/write lists |
| `authority` | current board/receipt references and mutation mode |
| `dedupe_key` | stable ID independent of `event_id` |

Canonical event types are `manual.requested`, `session.start`,
`prompt.submitted`, `file.changed`, `run.completed`, `run.failed`,
`goal.state_changed`, `schedule.tick`, `git.pre_commit`, and `git.post_commit`.
Provider-specific event names normalize to one of these values before matching.

All IDs use lowercase ASCII `^[a-z0-9][a-z0-9._:-]{0,127}$`; loop and adapter
IDs additionally use lower kebab case. `source` contains exactly `adapter_id`,
`source_event_id`, and `trust`. Trust is `local_adapter`, `fixture`, or
`generic_stdin`, and never grants authority.
Adapters may keep raw provider payloads outside the normalized artifact, but raw
data is not match or authority input.

`generic_stdin` input is validate/match/dry-run-only. Non-dry-run admission
requires a separate current execution-authority receipt supplied by the trusted
caller outside stdin and digest-bound into the result. Event content cannot
select or assert that receipt.

`origin` contains exactly `run_id`, `loop_id`, `depth`, and `ancestry`.
`run_id` and `loop_id` may be null only for an external/manual root event;
`depth` is integer `0..8`; `ancestry` is an ordered unique list of loop IDs.
For a loop-originated event, `loop_id` is non-null, occurs last in ancestry,
and depth equals ancestry length. A candidate loop matching its own origin or
ancestry, repeated ancestry, inconsistent depth, or depth over the definition's
maximum is `recursive_event`.

`subject` contains exactly `paths`, `goalbuddy_board`, and `workgraph`. Paths are
unique logical path objects with exact `root_id` and `path`. The two references
are known-digest logical locators or null. The fixed-root, lexical/resolved
containment, symlink, hard-link, alias, and regular-file rules in
`loop-registry.md` apply before matching.

`requested_scope` contains exact `read` and `write` logical path lists. It cannot be
wider than the matched definition and current authority. `authority` contains
exactly `board`, `receipt`, and `mutation_mode`; references are known-digest
logical locators or null. Mutation mode is `advisory_report_only` or
`automatic_read_only`. Missing/unknown required authority is rejection, not a
default grant.

An event is fresh only when the trusted caller supplies an RFC3339 UTC
evaluation time, `occurred_at <= observed_at`, neither timestamp is more than 5
seconds after evaluation, observed transport delay is at most 300 seconds, and
event age is at most the definition's `freshness_seconds` (capped at 86,400).
Future, missing, malformed, out-of-order, delayed, or expired time is
`event_stale`. Event input cannot supply evaluation time.

Deduplication rejects an event when either its `event_id` remains in the
code-owned ledger for 86,400 seconds after first observation or its
`dedupe_key` was admitted inside the loop's dedupe window. Retention uses the
trusted evaluation time. Debounce may combine
eligible path observations before admission, but never changes event identity,
authority, or scope. Duplicate and debounced-away events execute nothing.

## LoopRunReceipt v1

A receipt has exactly these top-level fields:

- `schema_version`: integer `1`;
- `artifact_type`: exact `LoopRunReceipt`;
- `receipt_id`: stable unique ID;
- `recorded_at`: RFC3339 UTC;
- `event`: identity and digest mapping;
- `registry`: ID, definition version, loop ID, lifecycle, and digests;
- `admission`: decision, ordered rejection codes, authority evidence;
- `action`: fixed action-profile and command-identity evidence;
- `execution`: status, result, timing, attempt, output, and failure evidence;
- `validation`: required-check execution and result evidence;
- `budget`: configured and observed budget evidence;
- `artifacts`: bounded local artifact references;
- `notification_intents`: bounded local intent references;
- `proof_boundary`: exact proof-level booleans and summary;
- `acceptance`: exact acceptance state and authority.

### Event and registry evidence

`event` contains exactly `event_id`, `event_type`, `dedupe_key`, and
`event_sha256`. `registry` contains exactly `registry_id`, `registry_sha256`,
`loop_id`, `definition_version`, and `lifecycle`. A rejected pre-match receipt
uses null loop/version/lifecycle values but still records the registry digest
when it was validly read. Digests are `sha256:<64 lowercase hex>` or `unknown`;
unknown cannot satisfy a proof gate.

### Admission and action evidence

`admission` contains exactly `decision`, `preflight_status`, `rejection_codes`,
`authority_receipt`, `authority_sha256`, and `scope_decision`. The receipt
reference is a digest-bound logical locator or null. Decision is `matched`,
`admitted`, or `rejected`; preflight status is `not_run`, `passed`, or
`rejected`; scope decision is `contained`, `widened`, or `unknown`. `matched`
with `preflight_status: not_run` is a non-executing preview, not admission.
`admitted` requires `passed`, no rejection codes, contained scope, known current
authority, and a bound compatible action. Rejected receipts contain one or more
sorted unique stable codes.

`action` contains exactly `action_profile_id`, `profile_schema_version`,
`profile_sha256`, `command_identity`, and `capability_decision`. A pre-match or
unknown-action rejection may use null IDs/versions and unknown digests.
Capability decision is `compatible`, `incompatible`, or `unknown`. The receipt
never records registry/event-provided command text. `command_identity` is a
stable source-owned identifier or null; it is not an argv or executable path.

A `matched`/`not_run` dry-run preview may record a known `action_profile_id` while leaving
`profile_schema_version` and `command_identity` null, `profile_sha256` unknown,
and `capability_decision` unknown. That state means the profile is unbound: it
cannot execute, validate as pass, or advance proof beyond `not_run`. Only T040
source binding may populate those fields before execution.

### Execution evidence

`execution` contains exactly:

- `status`: `completed`, `failed`, or `not_run`;
- `result`: `pass`, `fail`, `rejected`, `not_run`, or `unknown`;
- `attempt`: integer `0..10`; zero only for `not_run`;
- `started_at`, `finished_at`: RFC3339 UTC or null;
- `duration_ms`: nonnegative integer or `unknown`;
- `output`: exact `captured_chars`, `truncated`, `sha256`, and `artifact_path`;
- `failure_code`: stable code or null.

`pass` requires completed execution, known timing, compatible capability,
known source profile digest, and required proof artifacts. `failed` pairs with
`fail`; rejected admission pairs with `not_run` and `rejected`. An unexecuted
check remains `not_run` regardless of prose confidence. Output is bounded by
the profile and loop caps; truncation is explicit and the digest covers the
complete captured bounded output.

`validation` is a nonempty list of exact `validation_id`, `execution_status`,
`result`, `evidence_path`, and `evidence_sha256` rows. Execution status is
`completed`, `failed`, `not_run`, or `not_applicable`; result is `pass`, `fail`,
`not_run`, or `not_applicable`. Only `completed` may pair with `pass`; `failed`
pairs with `fail`; `not_run` pairs with `not_run`; `not_applicable` pairs with
`not_applicable`. Rejected admission records mandatory validations as
`not_run`, never pass.

### Budget, artifacts, proof, and acceptance

`budget` contains exactly `max_attempts`, `timeout_seconds`,
`max_output_bytes`, `explicit_token_cap`, `external_cash_authorized`,
`observed_tokens`, `observed_external_cash_usd`, and `evidence_status`.
Observed values are nonnegative numbers or `unknown`; evidence status is
`known`, `partial`, or `unknown`. Unknown required evidence cannot pass a hard
budget gate.

Every `artifacts` and `notification_intents` row has exactly `artifact_id`,
`path`, `sha256`, and `state`. State is `expected`, `written`, `validated`,
`not_written`, or `rejected`. Expected and not-written rows use `path: null` and
`sha256: unknown`. Written or validated rows use a root-qualified contained
logical locator resolved by the code-owned sink; validated also requires a
known digest. Notification rows are local intent artifacts, not delivery proof.

`proof_boundary` contains exactly `state`, `local_source`, `installed`, `live_hook`,
`scheduler_active`, `external_connector`, `published`, and `summary`. State is
`unknown`, `not_run`, `rejected`, `failed`, `candidate`, or `proved`. Only
`proved` may support acceptance and requires every mandatory validation row to
pass with known fresh evidence. Only
`local_source` may be true in this tranche. Transport or execution success
cannot change the other booleans.

`acceptance` contains exactly `state` and `authority`. State is `not_requested`,
`candidate`, `accepted`, or `rejected`; authority is `Parent`, `operator`, or
`none`. A runtime-created receipt defaults to `not_requested`/`none`. Only a
separate current Parent/operator acceptance artifact may set acceptance.

## Command And Authority Rejection

The forbidden key and value rules from `loop-registry.md` apply recursively to
events. A caller cannot supply a command, argv, executable, cwd, environment,
profile digest, capability decision, or acceptance assertion. Command-bearing,
scope-widening, unauthorized, stale, duplicate, recursive, or path-escaping
events emit a rejected/not-run receipt when safe to do so and execute nothing.

Receipts are evidence, not caller input to execution. Replaying a receipt cannot
authorize another run, promote lifecycle, or mutate a board.

The local snapshot API may read explicit receipt/trace pairs and the verified
dispatch ledger cursor. It reads metadata only and prints one closed JSON
snapshot to stdout. It does not write a ledger, retain content, upload data, or
start a service.

## Proof Boundary

The contract and canonical templates prove only the data vocabulary. Adapter
parity, parser behavior, action resolution, execution, append durability,
installed hooks, schedule activation, and external delivery require later
exact-source proof.
