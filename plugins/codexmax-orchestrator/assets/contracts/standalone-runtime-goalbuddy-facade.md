# Standalone Runtime GoalBuddy Facade v1

This optional standard-library facade exposes four closed operations:
`capabilities`, `snapshot`, `apply`, and `recover`. GoalBuddy remains canonical
board truth. The facade is an exact-envelope relay, not a board parser, patch
engine, authority system, status projector, CAS implementation, lock, WAL,
ledger, recovery engine, cursor, migration layer, or acceptance path.

Before its first lazy WorkGraph execution, the facade opens the fixed package-
sibling WorkGraph core, dependencies, activity, updates, GoalBuddy adapter,
notes, and CLI with no-follow descriptors. Every anchor must be a unique,
single-link regular file whose open descriptor and canonical name retain the
same device/inode identity before and after reading and after the full closure
loads. The raw descriptor bytes must match the seven frozen SHA-256 values.

The one deliberate loader exception is narrow: the facade compiles and executes
only those already descriptor-read, hash-pinned bytes, assigns their exact fixed
sibling filenames, and services only the closed WorkGraph internal module-name
map. This prevents a pathname swap or substituted import loader from changing
executed bytes. It accepts no caller-, argument-, environment-, configuration-,
URI-, module-, path-, or executable-selected source. All delegated behavior
flows only through that pinned `workgraph_cli.execute` with an exact WorkGraph
tool-api request.

The exported operation function privately captures this real pinned loader and
its delegator once during facade initialization; the loader's module-global
name is then erased. Delegation never accepts or authenticates a returned
module, callable, token, handler alias, or self-reported identity from a public
attribute. Copying a token and synchronizing forged execute/error/handler
aliases therefore supplies no execution path: later replacement of any such
module attribute is disconnected from the captured closure.

## Envelopes

Every request contains exactly `schema_version`, `artifact_type`, `operation`,
and `arguments`. Version is integer `1`; artifact type is
`standalone_runtime_goalbuddy_request_v1`.

- `capabilities` takes `{}` and reports only facade support and non-authority.
- `snapshot` takes exactly `board_path` and delegates canonical snapshot.
- `apply` takes exactly `board_path`, `updates_path`, `journal_path`,
  `update_id`, and `timestamp`.
- `recover` takes exactly `board_path`, `updates_path`, `journal_path`, and
  `timestamp`.

Snapshot, apply, and recover receipts embed the exact WorkGraph success or
error receipt and its prefixed canonical JSON SHA-256. The facade does not
reinterpret outcomes, infer status, discard details, turn failure into success,
or replace the canonical receipt with a summary.

Before outer status or digest construction, every delegated receipt is checked
as a closed WorkGraph envelope. Protocol must be exactly `workgraph_tool_api`,
schema must be integer `1`, operation must match the submitted operation, and
status must be exactly `ok` or `error`. Success requires the exact frozen
WorkGraph capability document, false acceptance/provider authority, and a
non-empty object result. Error requires a non-empty stable error code and may
carry only its exact optional canonical details. Missing, extra, malformed,
mismatched, or substituted-handler output fails with a stable facade error;
raw lookup exceptions cannot escape.

Capabilities and snapshot are read-only and carry an exact all-false facade
effect map. Apply and recover explicitly state that the canonical adapter owns
all mutation truth, that partial WAL effects may exist after delegation, and
that the embedded receipt is the only effect truth. A delegation error never
claims that the board, journal, or updates ledger remained unchanged.

## Authority and proof boundary

Capabilities do not grant write permission. Apply and recover remain available
only through the canonical adapter's existing path validation, Parent-reviewed
authority, status-sensitive board validation, compare-and-swap, locking, WAL,
updates ledger, and idempotent recovery rules. Schema v3 remains snapshot-only;
migration stays unavailable.

Tests use disposable copies of synthetic WorkGraph fixtures. The facade never
touches a real board, network, provider, service, subprocess, credentials,
installation, publication, AOL, or acceptance state. Successful local tests
prove only optional source-local interoperability with the frozen WorkGraph
closure.
