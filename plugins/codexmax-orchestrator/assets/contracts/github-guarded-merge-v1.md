# GitHub Guarded Merge V1

`github_guarded_merge.py` owns one exact pull-request merge seam for the host,
repository, and local `gh` username named by the operator's task grant.

The CLI accepts one absolute, non-symlink execution directory and one canonical
`TNNN` task identifier. It also requires exact expected host, repository, and
username arguments. Those arguments must match the persisted request before
any GitHub call. `T080` is the default for compatibility. The task
identifier can contain only `T` and exactly three digits. The adapter derives
`notes/<lower-task>-effects/` for the request, state, independent audit, and
merge lock. It derives
`notes/<lower-task>-audit-runtime-projection.final.json` for the auditor
projection. The request binds the exact byte digests of the two evidence files.
The caller cannot select an arbitrary filesystem path.

The adapter uses the existing GoalBuddy parser and calls its canonical schema
and invariant validator. It requires the selected task to be active and every
canonical dependency of that task to be done with an approved, passing receipt.
It hashes and validates a separate task audit artifact from the exact bounded
read-only auditor identity and Codex collaboration runtime. The request also
binds the exact byte digest of the canonical auditor runtime projection. The
projection must identify `<task>-A01`, the same runtime child, the collaboration
surface, the independent-auditor role, and no provider dispatch.
The audit must bind the same board digest, pull-request number, base SHA, head
SHA, complete filename digest, and file count. Request assertions alone cannot
satisfy dependency or audit gates.

Before merge, the adapter reads the current identity and repository permission.
It then reads the exact pull request, applicable branch rules, check runs,
reviews, and complete diff summary. V1 rejects an exact branch that reports
active classic protection. It does not read the classic protection endpoint.
Every observation binds the expected base and head SHA. Required checks bind
both context and app ID when GitHub supplies an app ID. Unknown rules, equal
review timestamps, code-owner review, last-push approval, and
conversation-resolution policies fail closed. The adapter re-reads the exact
pull request immediately before effect.

An exclusive execution-directory lock serializes every effect attempt. The
adapter persists `effect_started` before one fixed `PUT` to the exact merge
endpoint. The PUT includes only the expected head SHA. An unknown outcome is
not retried. A later call must first prove that the exact pull request is merged
or unmerged. An unmerged reconciliation returns without a merge, so a separate
call is required to retry. A merged reconciliation records the merge commit.
Drift, malformed merged state, read failure, or evidence failure during pending
reconciliation preserves `reconcile_required`. This also applies after
`effect_started` and before the merge PUT. An exact externally merged state is
bound as merged. An exact closed-unmerged state is bound as reconciled and
requires a separate call before any retry.

The adapter never grants acceptance. It never reads credentials, changes
repository settings, selects a merge method, runs auto-merge, deletes a branch,
comments, force-pushes, schedules work, deploys, publishes, or calls a provider.
