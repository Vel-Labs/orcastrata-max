# Trajectory Memory v1

Trajectory Memory is a local, append-only, descriptor-only evidence ledger. It
does not store prompts, messages, transcripts, freeform response bodies, or any
authority-bearing instruction. Consumers may use its bounded query results as
evidence descriptors only; the ledger never grants execution or acceptance
authority.

## Isolation and binding

Each ledger is stored at `<root>/<namespace>/<arm>.jsonl`. Namespace and arm are
strict path-safe descriptors. `init` writes the immutable first hash-chain row,
binding that ledger to exactly one namespace, one experiment arm, and one
`sha256:` source-corpus digest. Every event repeats the binding. Verification
rejects any mismatch, so a query cannot cross a namespace, arm, or corpus.

The initialization row has sequence `0`, a zero previous hash, and a canonical
SHA-256 `event_hash`. Event sequences begin at `1`. Hashes cover canonical
UTF-8 JSON with sorted keys and compact separators, excluding only the row's
own `event_hash` field.

## Event schema

The event template is the complete append schema. Unknown or missing keys are
rejected. IDs, tags, and artifact locators are bounded descriptor tokens, not
freeform prose. References explicitly repeat namespace and arm, must match the
current ledger, and must name a prior event. Artifact references contain only a
path-like locator and digest.

Usage contains exactly `input_tokens`, `output_tokens`, `total_tokens`, and
`wall_time_ms`. Each is either:

```json
{"status":"known","value":12,"reason":null}
```

or:

```json
{"status":"unknown","value":null,"reason":"not_exposed"}
```

Unknown reasons are `not_exposed`, `not_reported`, or `not_applicable`.
Unknown values are never coerced to zero. Recursive raw-content field names,
including `prompt`, `message`, `transcript`, `response`, `body`, `text`, and
`content`, are rejected even before normal schema validation.

## Append and concurrency

Append takes a required `expected_head`. Under an advisory exclusive lock it
verifies the complete ledger, checks the source binding, checks duplicate IDs
and prior references, then compares the current head. A changed head fails with
`stale_head`; the caller must re-read and deliberately retry. The write uses
append mode and `fsync`; existing bytes are never rewritten.

## Bounded query

The query template is the complete query schema. A query addresses exactly one
namespace, arm, and corpus digest. Filters are exact descriptor matches for
event type, task ID, outcome, or any tag. `after_sequence` is non-negative,
filter lists contain at most 32 unique items, and `limit` is 1 through 100.
`max_bytes` is a positive integer capped at 1,000,000 bytes. Results are
deterministically ordered by sequence (`asc` or `desc`) and capped after
filtering. Query verifies the chain before returning events.

Each retrieval returns `query_sha256`, the lowercase SHA-256 of the canonical
validated query, including `limit` and `max_bytes`. `retrieval_sha256` is the
lowercase SHA-256 of the canonical returned receipt projection containing every
top-level receipt field except `retrieval_sha256` itself. Thus the retrieval
digest binds the query digest, ledger head, binding, truncation metadata, and
returned events without a hash self-reference.

The final canonical receipt, including the 64-byte retrieval digest, must be no
larger than `max_bytes`. The implementation evaluates deterministic event
prefixes from the query's ordered, limit-capped candidates and returns the
largest prefix that fits. `truncation` reports whether truncation occurred, its
reason (`none`, `limit`, or `max_bytes`), total matched count, limit-candidate
count, and returned count. If even the zero-event receipt cannot fit, query
fails with `max_bytes_too_small`; it never emits an over-budget retrieval.

## CLI

All successful and failed operations emit one machine-readable JSON object and
use exit code `2` for protocol errors.

```sh
python3 trajectory_memory.py init --root STORE --namespace GOAL --arm ARM --source-corpus-sha256 sha256:...
python3 trajectory_memory.py append --root STORE --event event.json --expected-head HEX
python3 trajectory_memory.py query --root STORE --query query.json
python3 trajectory_memory.py verify --root STORE --namespace GOAL --arm ARM --source-corpus-sha256 sha256:...
```

`verify` detects malformed records, duplicate JSON keys and event IDs, invalid
sequences, truncated writes, binding drift, broken links, and hash tampering.
