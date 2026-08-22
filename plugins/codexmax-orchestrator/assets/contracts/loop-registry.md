# Loop Registry Contract

## Boundary

`LoopRegistry v1` is a strict declarative policy and reference schema. It names
typed triggers, contained scope, current authority evidence, fixed action
profiles, budgets, proof, artifacts, lifecycle, and stop rules. It never stores
or constructs commands and never grants authority.

Codexmax source owns validation, matching, action-profile lookup, fixed argv,
execution, and receipts. `_ops/loops` owns only workspace intent. GoalBuddy owns
board truth and WorkGraph owns dependency/evidence relationships. Hooks and
harness adapters own event normalization only.

Unsupported schema versions, unknown fields, duplicate keys, unsafe YAML
features, malformed objects, and missing required fields fail closed.

### Safe YAML and resource limits

The parser accepts only UTF-8 YAML 1.2 block mappings, block sequences, and
null, boolean, integer, plain-string, or double-quoted-string scalars. The exact
tokens `[]` and `{}` are permitted only as explicit empty collections. It
rejects aliases, anchors, tags, merge keys, directives, duplicate keys,
nonempty flow collections, single-quoted or multiline scalars, block scalars
(`|` or `>`), tabs, NUL, C0/C1 controls except LF, non-finite numbers,
implicit timestamps, and custom object construction.

Limits are 262,144 input bytes, nesting depth 16, 4,096 parsed nodes, 256 loop
definitions, 256 items per sequence, 256 keys per mapping, 4,096 UTF-8 bytes per
scalar, and 64 emitted errors. Limit failures use `input_too_large`,
`structure_too_deep`, `node_limit_exceeded`, `collection_limit_exceeded`, or
`scalar_too_large`. Parsing never fetches includes or resolves environment
variables.

## Registry Shape

The registry is one mapping with exactly these fields:

| Field | Type and rule |
| --- | --- |
| `schema_version` | integer `1` |
| `registry_id` | stable ID, `^[a-z][a-z0-9-]{0,63}$` |
| `workspace_root` | exact `.` |
| `mode` | exact `advisory_report_only` in v1 |
| `logical_root_ids` | exact ordered list `workspace`, `codexmax_repo` |
| `contract_refs` | exact `registry` and `events` digest-bound logical locators |
| `action_profile_contract` | exact profile-reference mapping below |
| `loops` | list of zero or more unique loop definitions |

The action-profile contract has exactly `schema_version: 1`,
`resolution: version_bound_codexmax_source`, and `allowed_profile_ids`.
Allowed IDs are unique stable IDs. They are policy references, not proof that a
profile exists or is currently available. At admission, Codexmax must resolve
the ID from the exact current source and bind its digest and capability. An
unknown, missing, stale, disabled, or unbound profile is rejected.

Both top-level contract references use `root_id: codexmax_repo`, a
repository-relative `path`, and a known current sha256 digest. Unknown digest,
workspace-root aliasing, stale content, symlink/hard-link identity, or any other
logical root fails closed before definitions are read.

The v1 fixed profile vocabulary is:

- `ops-config-fast`
- `goalbuddy-board-fast`
- `skill-contract-fast`
- `codexmax-loop-focused`
- `codexmax-repository-full`
- `git-diff-sanity`
- `receipt-completeness`

## Loop Definition Shape

Every list entry has exactly these fields:

| Field | Rule |
| --- | --- |
| `loop_schema_version` | integer `1` |
| `loop_id` | unique stable lower-kebab ID |
| `definition_version` | positive integer; increases on any semantic change |
| `owner_path` | contained workspace-relative path |
| `lifecycle` | lifecycle mapping |
| `loop_type` | `manual`, `goal`, `time`, or `event` |
| `contract_refs` | authority/source reference mapping |
| `trigger` | typed match, freshness, debounce, dedupe, and recursion policy |
| `scope` | exact allowed reads/writes, mutation mode, and forbidden actions |
| `graph` | optional WorkGraph and GoalBuddy references only |
| `action_profile_ids` | nonempty ordered unique list from the registry allowlist |
| `budget` | attempts, time, output, concurrency, tokens, cash, improvement |
| `proof` | required evidence freshness and receipt/artifact destinations |
| `notification` | local notification intent only |
| `stop_conditions` | nonempty unique canonical stop reasons |

### Lifecycle

`lifecycle` contains exactly `state`, `prior_state`, `changed_at`, and
`promotion_evidence`.

- states: `proposed`, `dry_run`, `pilot`, `active`, `paused`, `failed`,
  `retired`;
- `changed_at`: RFC3339 UTC or `null` only for a never-promoted `proposed` loop;
- `prior_state`: `null` for `proposed`, otherwise the prior canonical state;
- `promotion_evidence`: empty for `proposed`; otherwise one or more contained
  regular-file references with `path` and `sha256:<64 lowercase hex>`.

Allowed forward transitions are `proposed -> dry_run -> pilot -> active`.
`dry_run`, `pilot`, and `active` may transition to `paused`, `failed`, or
`retired`. `paused` may resume only to its recorded prior state after fresh
review. `failed` may transition only to `dry_run` with repair evidence.
`retired` is terminal. Transition evidence does not grant authority or
acceptance; the operator and current board remain authoritative.

### Contract references

`contract_refs` contains exactly `source_paths`, `authority_board`, and
`authority_receipt`. Source paths are nonempty unique logical locators; the
other values are logical locators or null.

A logical locator has exactly `root_id`, `path`, and `sha256`. Root is
`workspace` or `codexmax_repo`; path is a nonempty POSIX-relative path; digest
is `sha256:<64 lowercase hex>` or `unknown`. GoalBuddy and WorkGraph references
always require a known digest. Other source references may retain `unknown`
only while `proposed` and cannot be admitted.

Logical roots are fixed in Codexmax source and cannot be defined, remapped, or
added by registry input. Lexical containment is checked before access and
resolved containment after opening. Absolute, drive/UNC, empty-component, `.`,
`..`, backslash, NUL, case-alias, symlink-component, special-file, device/inode
alias, and unexpected hard-link-count inputs are rejected.

Any digest required for automatic admission must be known and current.
References are read at admission and cannot copy, mutate, or override their
source truth. Missing regular files, directories, aliases, symlinks, traversal,
and digest mismatch reject the definition.

### Trigger

`trigger` contains exactly:

- `event_types`: nonempty unique subset of the LoopEvent v1 vocabulary;
- `source_adapters`: nonempty unique stable adapter IDs;
- `path_match`: exact `include` and `exclude` lists of normalized
  logical patterns; both lists are explicit;
- `debounce_seconds`: integer `0..3600`;
- `dedupe_window_seconds`: integer `1..86400`;
- `freshness_seconds`: integer `1..86400`;
- `max_recursion_depth`: integer `0..8`.

Globs match paths only. They may not expand to commands, cwd, executables, or
scope. A path-sensitive event with no included subject path is not a match.
Matches are ordered by `loop_id`; registry order cannot change the result.
Each logical pattern contains exactly `root_id` and `pattern`; fixed-root and
lexical containment rules apply before glob matching.

### Scope and authority

`scope` contains exactly:

- `allowed_reads`: unique normalized contained logical patterns;
- `allowed_writes`: unique normalized contained logical patterns;
- `mutation_mode`: `advisory_report_only` or `automatic_read_only`;
- `forbidden_actions`: unique nonempty list containing all v1 mandatory
  forbiddances.

The mandatory forbiddances are `arbitrary_command`, `network`, `credentials`,
`install`, `delete`, `move`, `rename`, `publish`, `push`,
`scheduler_activation`, `hook_installation`, `goalbuddy_mutation`, and
`authority_widening`.

`automatic_read_only` admits only fixed profiles whose source-owned capability
is read-only apart from their append-only receipt. It never authorizes a source
write. Event-requested scope must be equal to or narrower than registered
scope and current board authority. Empty or unknown current authority never
satisfies admission.

### Graph references

`graph` contains exactly `workgraph` and `goalbuddy_board`, each a known-digest
logical locator or `null`. The paths are references only. A referenced WorkGraph
must pass its current schema, identity, direction, and acyclic checks. A static
cycle fails closed. A GoalBuddy reference cannot replace or mutate board truth.
Runtime retries and recurrence are append-only transitions, not graph edges.

### Budget

`budget` contains exactly:

- `max_attempts`: integer `1..10`;
- `no_improvement_window`: integer `1..max_attempts`;
- `timeout_seconds`: integer `1..3600`;
- `max_output_bytes`: integer `1024..1048576`;
- `max_concurrency`: integer `1..4`;
- `token_forecast`: positive integer or `null`;
- `explicit_token_cap`: positive integer or `null`;
- `external_cash_authorized`: exact `false` in v1.

Forecasts are not caps. A null explicit cap does not remove other bounds.
Unknown required token/cost evidence rejects execution. No-improvement counts
completed attempts without evidence-backed oracle movement.

### Proof, artifacts, and notification intent

`proof` contains exactly `required_freshness_seconds`, `receipt_sink_id`,
`report_root`, and `required_artifact_ids`. Receipt sink is exact
`local_loop_receipts_v1`; its location, atomic write, and append policy are
code-owned and caller input cannot select or widen it. Report root has exact
`root_id` and `path`. Existing symlinks, hard links, aliases, or path escape
fail closed. Missing required proof is `not_run`, never `pass`.

`notification` contains exactly `mode` and `intent_path`. The only v1 mode is
`dashboard_only`; the path is a contained local artifact destination or null.
It cannot name an audience, credential, webhook, address, provider, or connector.

Canonical stop conditions are `operator_stop`, `scope_widening`,
`authority_missing`, `source_unavailable`, `stale_event`, `duplicate_event`,
`recursive_event`, `budget_exhausted`, `no_improvement`, `action_unavailable`,
`validation_failed`, and `unsafe_input`.

## No-Command Invariant

Registry YAML, definitions, event JSON, and prompts may not contain a command,
argv, executable, interpreter, shell expression, caller-selected cwd,
environment expansion, command substitution, or arbitrary parameters. Keys
such as `command`, `commands`, `argv`, `executable`, `shell`, `script`, `cwd`,
and `environment` are forbidden at every depth. NUL, backticks, `$(`, shell
metacharacters, unresolved variables, and command-like values reject the input.

Only source-owned action profiles may contain fixed argv. Runtime invokes them
without a shell after exact version, digest, capability, scope, and authority
admission. The receipt records a stable `command_identity`, never a
configuration-supplied command.

## Stable Rejection Codes

Validation and matching return ordered unique codes:

- `schema_invalid`, `schema_version_unsupported`, `unknown_field`,
  `duplicate_key`, `duplicate_loop_id`, `input_too_large`,
  `structure_too_deep`, `node_limit_exceeded`, `collection_limit_exceeded`,
  `scalar_too_large`, `yaml_feature_forbidden`;
- `reference_missing`, `reference_stale`, `reference_symlink`,
  `reference_hardlink`, `path_invalid`, `path_escape`;
- `action_profile_unknown`, `action_profile_unbound`, `command_input_forbidden`;
- `authority_missing`, `authority_ambiguous`, `authority_stale`,
  `scope_widening`, `capability_unknown`;
- `event_stale`, `event_duplicate`, `recursive_event`, `origin_invalid`,
  `event_unauthorized`, `generic_stdin_dry_run_only`, `ambiguous_match`;
- `static_cycle`, `budget_invalid`, `budget_unknown`, `proof_unknown`.

Multiple errors are sorted lexicographically. Rejection executes nothing and
emits a bounded LoopRunReceipt with `decision: rejected` and
`execution.status: not_run`.

## Proof Boundary

The templates and fixtures freeze the T010 contract only. They do not prove a
validator, matcher, profile implementation, event adapter, hook installation,
scheduler activation, external connector, or completed run.
