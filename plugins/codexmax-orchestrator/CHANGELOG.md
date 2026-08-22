# Changelog

## 1.0.0 - 2026-08-21

- Add the local, read-only `OrcastrataTelemetrySnapshotV1` API.
- Add exact Loop receipt and trace-file bindings with root or nested lineage.
- Keep content, commands, paths, credentials, and transcripts out of snapshots.
- Keep exact human-readable model identity in verified dispatch receipts. Use
  privacy-safe stable model references in telemetry snapshots.

## 1.0.0-rc.8 - 2026-08-21

- Keep default route identity and capability evidence unverified or unknown
  until fresh task-local preflight.
- Remove unshipped historical route locators from the default configuration.
- Remove the unused T085 workflow snapshot builder and frozen snapshot.

## 1.0.0-rc.7 - 2026-08-21

- Import bounded native Codex action usage into the project DispatchLedger
  without storing transcripts.
- Label token measurements as observed, derived, or unknown.
- Make multi-turn imports fail closed and idempotent.
- Defer the advanced guided-journey contract for clear first-use and direct
  tasks.

## 1.0.0-rc.6 - 2026-08-21

- Add explicit Orcastrata project context, registered-workspace discovery, and
  append-only usage reporting with used-only model readouts.

## 1.0.0-rc.5 - 2026-08-21

- Ignore disabled example bindings when one enabled exact tool/model binding is
  available.
- Keep multiple enabled exact bindings ambiguous and fail closed.

## 1.0.0-rc.4 - 2026-08-21

- Reduce the first-use orchestration skill from 38 KB to less than 6 KB.
- Route advanced dispatch and evidence work to their dedicated skills and
  contracts instead of loading that detail on every first use.
- Replace duplicate-prose tests with focused front-door and canonical-contract
  checks.

## 1.0.0-rc.3 - 2026-08-21

- Remove the final machine-specific supported-host and historical canary test
  dependencies found by the rejected RC2 boundary run.

## 1.0.0-rc.2 - 2026-08-21

- Repair the public identity checks and explicit Loop workspace-root flow found
  by the rejected RC1 boundary run.

## 1.0.0-rc.1 - 2026-08-21

- Add native-first Orcastrata Max onboarding.
- Add exact OpenCode and Command Code tool/model selection.
- Fail closed on session, model, route, grant, or command mismatch.
- Keep task grants as the only read/write authority.
- Add Apache-2.0 licensing and public support, security, and privacy guidance.

This candidate is not a published or installed release until separate receipts
prove those states.
