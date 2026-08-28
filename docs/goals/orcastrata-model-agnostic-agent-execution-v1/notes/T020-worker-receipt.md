# T020 Worker Receipt

## Result

Implemented declarative exact-model candidates over existing approved Worker
transport routes. A candidate can set `route.exact_model` without adding a
route-registry row or package source route. The approved route name remains the
transport anchor. Provider, runtime, billing, and independence identity stay
package-owned. Candidates always start `configured` and still require fresh
qualification.

Binding identity now includes the supplied exact model, while legacy bindings
retain their existing derived IDs when no model override is supplied. Unsafe
model values continue to fail the existing secret/location scanner. No launch,
credential, endpoint, environment, module, path, or authority fields were
added.

## Files changed

- `plugins/codexmax-orchestrator/scripts/adapter_registry.py`
- `plugins/codexmax-orchestrator/scripts/resolve_codexmax_config.py`
- `plugins/codexmax-orchestrator/assets/contracts/adapter-registry.md`
- `plugins/codexmax-orchestrator/assets/contracts/codexmax-config.md`
- `tests/test_adapter_registry.py`
- `tests/test_codexmax_config.py`

## Validation

- `python3 -B -m unittest tests.test_adapter_registry tests.test_codexmax_config -q` — 5 tests passed.
- `git diff --check` — passed.
- Direct resolver authoring check — a `vendor/model-x` candidate was accepted
  over `worker_deepseek_v4_pro` and remained `configured`.

## Assumptions and risks

- The approved Worker route is the transport implementation selector. Later
  qualification and dispatch must pass the binding's exact model identity to
  the transport adapter.
- Existing route rows remain unchanged. This task does not prove runtime model
  discovery, qualification, provider execution, package parity, or install
  behavior; T030 owns those proofs.
