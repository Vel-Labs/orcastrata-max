# Orcastrata GitHub CLI Read Contract V1

## Purpose

`scripts/github_cli_read.py` exposes eight read-only GitHub operations through
the installed local `gh` CLI. It is a standalone Orcastrata surface. It has no
AOL dependency.

## Request

The JSON request contains exactly `schema_version`, `artifact_type`,
`operation`, and `arguments`. Version is `1`. Artifact type is
`orcastrata_github_read_request_v1`.

Every operation requires a lowercase DNS `host` and an `owner/repository`
locator. URLs, credential-bearing locators, ports, arbitrary endpoints,
commands, executables, and environment values are not accepted.

Operations are closed:

- `probeCapability`: `host`, `repository`;
- `readRepository`: `host`, `repository`;
- `listIssues`: `host`, `repository`, `limit` from 1 through 100;
- `readIssue`: `host`, `repository`, positive `number`;
- `readPullRequest`: `host`, `repository`, positive `number`;
- `listPullRequestChecks`: `host`, `repository`, positive `number`;
- `listPullRequestReviews`: `host`, `repository`, positive `number`;
- `readPullRequestDiffSummary`: `host`, `repository`, positive `number`.

## Execution Boundary

The adapter resolves `gh` once and uses its absolute executable path. Every
invocation uses a fixed argument array and `shell=False`. GitHub REST endpoints
are built only from validated owner, repository, issue or PR number, and an
operation-owned suffix. Output, error output, item count, input size, and run
time are bounded.

Orcastrata removes ambient GitHub token and target overrides. It never invokes
`gh auth token` or reads credential files. The trusted `gh` process can use its
own authenticated configuration through `HOME`, `XDG_CONFIG_HOME`, or
`GH_CONFIG_DIR`. Auth output and error output are never returned.

## Receipt and Authority

The receipt artifact is `orcastrata_github_read_receipt_v1`. Successful
receipts contain the operation, exact target, allowlisted normalized data,
command count, and an all-false effect boundary. Failure receipts contain only
a stable error code and path. They do not contain raw command output.

List receipts include their item limit and `possibly_more`. A bounded first
page never claims complete repository coverage when another page can exist.
Pull-request review reads use complete CLI pagination and project only the
state, commit SHA, reviewer login, and submitted time. They never return review
bodies. Issue reads return only valid Orcastrata umbrella and issue marker
identities, never the issue body. Malformed or duplicate marker identities fail
closed.

Pull-request diff reads also use complete CLI pagination. They retain at most
100 metadata rows and report `total_count` plus `filenames_sha256`. The digest
is SHA-256 over canonical JSON for the complete sorted unique filename list.
Duplicate filenames, incomplete CLI pagination, malformed projected rows, and
output-limit failures fail closed.

Capability and read receipts prove only point-in-time access. They do not grant
GitHub write authority, GoalBuddy acceptance, merge authority, billing
authority, or permission for another repository.
