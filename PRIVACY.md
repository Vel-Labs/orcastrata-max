# Privacy

Orcastrata Max runs locally and does not add product analytics, advertising, or
a hosted account service.

A provider call can send only the task content authorized for the selected
route. Review task scope before execution. Orcastrata Max does not read, copy,
refresh, or store provider credentials.

Local receipts can contain paths, hashes, model output, and execution metadata.
Review and sanitize them before publication. Do not store credentials, cookies,
private keys, browser profiles, or password-manager data in project artifacts.

The optional local telemetry snapshot is operator-owned and metadata-only. It
verifies the existing dispatch ledger and reads explicit receipt/trace pairs.
It does not run a server, upload data, collect product analytics, create a
second ledger, tokenize content, or retain prompts, responses, stdout, stderr,
commands, credentials, or provider payloads. Missing host or provider counters
remain `unknown`.

Support uses GitHub. Information submitted to GitHub is subject to GitHub's
privacy terms.
