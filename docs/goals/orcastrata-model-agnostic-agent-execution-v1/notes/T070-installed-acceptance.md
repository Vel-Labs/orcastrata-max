# T070 Installed Acceptance

Status: accepted for independent audit

Orcastrata Max 1.0.4 is installed from the isolated successor worktree. The
source, immutable stage, and clean installed cache each contain 389 manifest
files and share tree SHA-256
`d2bf88fdda87c8fbc25775415568b0b1052a91631dad1fbf33942528f21659dd`.
The release-manifest SHA-256 is
`5437cc9ed2ed008015382e6977473793f21ff355c19fda135fd12cc3ebdb1786`.

The final installed automatic task used no provider or model argument. It
freshly probed Command Code 1.38.1, selected
`minimaxai/minimax-m3`, and completed one read-only task in 3,024 ms. The
response identity matched. No fallback or retry occurred. Evidence is at
`/Users/steven/Workspace/40_Code/_worktrees/orcastrata-t050-live-canary-v7/T070-installed-auto-read/`.

The final installed controlled-write task used exact MiniMax M3 through
Command Code. It completed one guarded read-edit-read sequence in 8,980 ms.
It changed only `orcastrata-canary.txt`. The change receipt is at
`/Users/steven/Workspace/40_Code/_worktrees/T070-live-write-evidence-v1/provider-change-receipt.json`.
The Parent ran the digest-bound rollback and restored
`sha256:5959b9a77eb51290e15bbca40228b2d1af6e565add2119658c911364b8ea12e8`.

The accepted three-model fan-out remains the T060 installed receipt. It
admitted and started exact DeepSeek Pro, MiniMax M3, and Grok 4.6 lanes from
one frozen input. MiniMax completed. DeepSeek and Grok timed out. Orcastrata
did not retry, substitute, or misreport either timeout.

Tokens, quota, cost, and provider-network accounting remain unknown when the
provider did not report them. This is an installed local candidate. It is not
published, and it does not grant protected-production or shared-tree writes.
