# GitHub PR Lifecycle V1

`github_pr_lifecycle.py` owns one bounded issue-to-PR execution seam.

The request binds one host, repository, user, issue, base SHA, head branch,
worktree, exact repository `origin`, active WorkGraph lease, and exact path allowlist.
The lease registry remains canonical. The adapter does not create a second
claim store or accept an arbitrary command.

Persisted state also binds the worktree, base SHA, allowed paths, lease claim,
fencing token, and board SHA. A changed binding cannot reuse a lifecycle ID.

`publish` and `repair` permit only these local effects:

- create the exact head branch from the bound base;
- stage only allowlisted paths;
- create one commit;
- push the exact head ref without force;
- reconcile or create the bound pull request.

`observe` reads the pull request, changed paths, checks, and reviews. It returns
`ready_for_audit` or `repair`. A failed check, requested change, draft or closed
pull request, changed binding, or path outside the lease routes to repair.

The adapter writes durable state before pull-request creation. An unknown
create outcome cannot cause another POST. A later call must first reconcile the
exact base and head. Multiple matches fail closed.

Every discovered or created pull request must contain the exact issue link and
stable lifecycle marker. Its head SHA must equal the committed or reconciled
head SHA before the adapter binds it or returns audit readiness.

The adapter also writes the committed SHA before push. An unknown push can
continue only after the exact remote head resolves to that SHA.

The adapter never merges, comments, changes repository settings, reads
credentials, runs a provider, schedules work, or grants acceptance.
