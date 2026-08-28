# T050 Parent Acceptance

Status: accepted

The installed Orcastrata candidate completed one controlled development write.
It used `minimaxai/minimax-m3` through Command Code 1.38.1 in the isolated
`orcastrata-t050-live-canary-v7` worktree.

The provider used one exact read-edit-read sequence. The catch-all
`PreToolUse` guard rejected all tools outside that sequence. The edit was
accepted only because applying the proposed replacement to the bound before
bytes produced the precommitted after bytes.

The dispatch took 11,522 ms. It changed only `orcastrata-canary.txt`. The
response identity matched `worker_commandcode_model`, Command Code, and
`minimaxai/minimax-m3`. No fallback or retry occurred. Token, quota, cost, and
provider-network accounting remain unknown because Command Code did not report
them.

Evidence is retained at
`/Users/steven/Workspace/40_Code/_worktrees/T050-live-evidence-v7/`.
The dispatch manifest and change receipt are present. The generated guard,
settings, descriptor, state, and assignment files were absent after success.

The rollback blob was bound to both the before and after SHA-256 values. The
Parent ran the rollback. It restored the target from
`sha256:605da500529179303782f9c90be7473605895b04da53569f1507eabfbe3fccb5`
to
`sha256:5959b9a77eb51290e15bbca40228b2d1af6e565add2119658c911364b8ea12e8`.

This proof applies only to isolated development worktrees. It does not grant
shared-tree or protected-production write authority.
