# Orcastrata Dynamic Routing V2 Implementation Plan

## Product Boundary

The visible Parent model is the normal user-selected model. Worker models are a
routing implementation detail unless the user explicitly selects an exact
route or requests fan-out.

## Critical Path

`T010 -> T020 -> T030/T040 -> T050 -> T060 -> T999`

T030 and T040 may progress in parallel only after the shared execution service
is stable. The Parent integrates both before cleanup.

## Acceptance Ladder

1. Characterize current exact, automatic, fan-out, configuration, receipt, and
   write-canary behavior.
2. Run focused tests for each changed boundary.
3. Run consumer tests for dispatcher, resolver, configuration, and packaging.
4. Build one frozen package and verify source-stage-install parity inside a
   workspace-owned clean profile.
5. Run a fresh normal request without a worker model, an exact override, a
   three-model fan-out, and a real isolated implementation with rollback.
6. Obtain one independent final audit of the exact candidate.

## Reduction Rule

Delete an artifact or compatibility surface only after reference mapping and a
replacement characterization test. Keep one canonical closeout receipt. Raw
provider logs remain runtime evidence and do not belong in the product commit.

## Proof Limits

A unit test does not prove natural-language invocation. A provider probe does
not prove quota. A canary edit does not prove implementation. A local source
run does not prove a clean installed package. A successful worker result does
not transfer Parent acceptance.

