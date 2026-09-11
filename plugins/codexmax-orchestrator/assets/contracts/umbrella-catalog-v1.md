# Orcastrata Umbrella Catalog V1

The catalog is a local, source-only snapshot. The builder consumes one explicit
JSON manifest and saved `orcastrata_github_umbrella_projection_receipt_v1`
files. It does not discover repositories or call GitHub, networks, or
providers.

Each manifest entry contains a repository-relative `path`, raw receipt
`raw_sha256`, semantic `projection_sha256`, catalog-owned `summary`, and owned
namespaced `tags`, `sensitivity`, and `exportable`. The record title comes from
the validated projection `preview.umbrella.title`. Absolute paths, traversal,
symlinks, unknown fields, duplicate sources or identities, stale receipts, and
non-success or effectful receipts fail closed. `public` and `internal` records
may be exportable. `restricted` records must set `exportable` to false.
Record references are named `github_repository`, `projection`, `workgraph_id`,
and `goalbuddy_owner`. Graph, board, projection, and raw receipt hashes remain
under `digests`.

The manifest is builder input. The valid and invalid JSON fixtures describe
catalog generations for downstream adapter consumers.

The builder emits a complete generation envelope. Records are sorted by
`umbrella_id`; record identity and `record_sha256` exclude generation time.
JSON is canonical UTF-8 JSONL and Markdown is generated from the same records.
Each output is written through a temporary file and atomically replaced. The
outputs share the catalog digest; this is not a pairwise filesystem transaction.

GoalBuddy remains lifecycle authority. WorkGraph remains dependency, scope,
validation, and evidence authority. Consumer adapters must treat the catalog
as a source snapshot and must not write back to it.

Validation proves contract shape and digest consistency only. It does not
cryptographically authenticate a locally forged manifest and receipt pair.
