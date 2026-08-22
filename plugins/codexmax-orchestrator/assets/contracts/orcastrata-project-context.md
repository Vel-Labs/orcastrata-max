# Orcastrata Project Context Contract

Orcastrata Max uses an explicit, project-local `.orcastrata/` directory. The
directory is created only after an explicit first-use setup or operator
command. Native-only work does not create it.

## Project marker

`.orcastrata/project.json` contains a stable project ID, bounded context file
pointers, installed skill IDs as references, scope exclusions, and the
metadata-only ledger path `.orcastrata/usage/dispatch.jsonl`.

Context files are regular, single-link files below the project root. V1 allows
20 files and 256 KiB total. A changed or missing file fails closed. Credentials,
prompts, responses, stdout, and stderr are never context or ledger inputs.

## Workspace marker

An optional `.orcastrata/workspace.json` registers projects by explicit
relative roots. Workspace review reads registered projects only. It does not
crawl sibling directories, infer projects from names, follow symlinks, or
execute project-provided skills. Each registered project must contain a
matching valid marker.

The nearest valid project marker controls review of the current folder. No
marker means `not_configured`; it is not permission to scan a wider workspace.
The workspace discovery command accepts one workspace root and visits only the
project roots in its validated registry.

## Usage

Dispatch results append to the existing hash-chained DispatchLedger engine. The
project ledger is a projection of dispatch metadata, not a second accounting
truth. Managed rows identify `execution_owner: orcastrata_managed`. A host can
import a bounded `codex exec --json` stream for an explicit task ID. The import
consumes only `turn.completed` usage, records a source digest and line count,
and never stores prompts, responses, commands, stdout, stderr, or transcript
bytes. Imported rows identify `execution_owner: host_native`.

Each token field keeps its measurement boundary. Direct host counters are
`observed`. If `total_tokens` is absent but observed input and output exist,
the importer records `derived` with method `input_plus_output`; cached input
and reasoning are never added again. Missing values remain `unknown` with a
reason. Identical receipt imports are idempotent under the ledger lock;
conflicting accounting or source evidence fails closed. Readouts show only
lanes and asks that were used.

The readout includes: “Additional configured models were available, but were
not used or called.”

## Local telemetry snapshot

An operator may request a read-only `OrcastrataTelemetrySnapshotV1` for one
configured project. The command verifies the existing ledger and returns its
exact event-count/head-hash cursor, a managed-dispatch-only projection, and
explicit adjacent receipt/trace pairs. It prints one closed JSON object to
stdout and performs no writes.

`LoopRunTraceV1` records root or nested ancestry and binds the exact canonical
receipt digest. The snapshot never includes prompts, responses, stdout, stderr,
commands, credentials, provider payloads, or transcript content. It is not a
second ledger, tokenizer, retention system, learning input, uploader, server,
or authority mechanism.
