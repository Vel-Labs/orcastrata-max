# Installed Package Agent Guide

- Start with the user's ordinary-language outcome.
- Keep one Parent responsible for integration and final acceptance.
- Use independent workers only when they add material value.
- Treat `Use model X through tool Y` as exact and fail closed on mismatch.
- Public V1 exact-tool requests support only OpenCode and Command Code. Other
  provider entries are configured candidates, not supported routes.
- Preview the selected task-local route before execution.
- Do not log in, copy credentials, or silently substitute a route.
- Before an external call, verify authority to send the task content and use
  the selected account, privacy terms, quota, and billing path.
- Task grants control read and write access. Model identity does not.
- Do not persist a tool/model pairing without explicit approval.
- Use `$codexmax-orchestrator:codexmax-orchestrate` for route and accounting
  rules and `$codexmax-orchestrator:codexmax-config` for configuration.
- Use focused validation during work.
- Run the full suite only at a package or release freeze.
- Preserve unrelated changes and never use blanket Git staging.
- Keep work status separate from accounting. Report missing usage as `unknown`.
- Report the exact proof boundary when work is complete.
