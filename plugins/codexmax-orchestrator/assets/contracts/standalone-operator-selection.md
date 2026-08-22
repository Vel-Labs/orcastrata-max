# Standalone operator selection V1

Select is host-owned configuration state, never a Responses request or effect.
The sealed head binds exact package/admission/effect-state identity, positive
selection-state version, catalog receipt/bundle/generation, and the existing
closed served-preset selection. Catalog generation and runtime thread generation
are independent.

`read_operator_selection_mutation` is side-effect free and returns only absent,
collision, or the original sealed mutation for an exact submission ID and full
canonical submission digest. Only absent proceeds under the shared effect lock
to fresh binding, catalog, head, supervision, lifecycle, projection, and CAS
validation followed by one `commit_operator_selection` call. Stale, unavailable,
or mismatched state is never bypassed.

A successful changed preset mints a fresh host thread and higher thread
generation. The mutation binds every original identity, binding, head, thread,
selection version, previous selection, catalog, target, bundle generation,
submission, freshness, digest, and external seal. Select writes neither effect
state nor the immutable historic binding record. Its transport receipt reports
only `unknown_until_status_refresh`; a fresh status read is authoritative.
