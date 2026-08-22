#!/usr/bin/env python3
"""Pending-only source seam for guarded Claude Code 2.1.232 sessions."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from typing import Any, Mapping


_SPEC = importlib.util.spec_from_file_location("claude_guard_policy", Path(__file__).with_name("provider_execution_policy.py"))
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("provider execution policy unavailable")
_POLICY = importlib.util.module_from_spec(_SPEC); _SPEC.loader.exec_module(_POLICY)
ROUTE_NAME = "worker_claude_code_sonnet_5"
BINDING = _POLICY.CLAUDE_ROUTE_BINDINGS[ROUTE_NAME]
MAX_TURNS = 20
SHA = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:@+-]{1,127}\Z")
REQUEST_FIELDS = {
    "schema_version", "task_id", "route_name", "route_id", "model", "runtime",
    "billing_basis", "mode", "prompt", "task_grant_sha256", "attempt_id",
    "session_id", "worktree_path", "settings_sha256", "mcp_sha256",
    "assignment_sha256", "scoped_write_grant", "subscription_receipt_sha256",
}


class ProtectedClaudeError(ValueError): pass


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise ProtectedClaudeError("claude_digest_invalid:" + field)
    return value


@dataclass(frozen=True)
class PreparedClaudeSession:
    task_id: str
    route_name: str
    route_id: str
    model: str
    runtime: str
    billing_basis: str
    mode: str
    task_grant_sha256: str
    attempt_id: str
    session_id: str
    worktree_path: str
    settings_sha256: str
    mcp_sha256: str
    assignment_sha256: str
    scoped_write_grant_sha256: str
    argv_sha256: str
    observed_turns_max: int
    managed_settings_absence_proved: bool
    spawn_eligible: bool
    provider_called: bool
    protected_production: bool
    prepared_sha256: str


def _argv(prompt: str, mode: str) -> list[str]:
    result = [
        "claude", "-p", prompt, "--model", BINDING["model"],
        "--permission-mode", "acceptEdits" if mode == "scoped_write" else "dontAsk",
        "--max-turns", "20", "--output-format", "stream-json", "--verbose",
        "--include-hook-events", "--no-session-persistence", "--no-chrome",
        "--disable-slash-commands", "--setting-sources", "",
        "--strict-mcp-config", "--mcp-config", ".claude/empty-mcp.json",
    ]
    if mode == "scoped_write":
        result += ["--settings", ".claude/settings.json", "--tools", "Read,Write,Edit"]
    else:
        result += ["--safe-mode", "--tools", "Read"]
    return result


def prepare_session(value: Any) -> PreparedClaudeSession:
    if not isinstance(value, Mapping) or set(value) != REQUEST_FIELDS:
        raise ProtectedClaudeError("claude_prepare_shape_invalid")
    row = dict(value)
    if (
        row["schema_version"] != 1 or row["route_name"] != ROUTE_NAME
        or any(row[field] != BINDING[field] for field in ("route_id", "model", "runtime", "billing_basis"))
        or row["mode"] not in {"read_only", "scoped_write"}
    ):
        raise ProtectedClaudeError("claude_prepare_identity_invalid")
    for field in ("task_id", "attempt_id", "session_id"):
        if not isinstance(row[field], str) or IDENTIFIER.fullmatch(row[field]) is None:
            raise ProtectedClaudeError("claude_prepare_identifier_invalid:" + field)
    if not isinstance(row["prompt"], str) or not row["prompt"] or "\x00" in row["prompt"] or len(row["prompt"].encode()) > 131072:
        raise ProtectedClaudeError("claude_prepare_prompt_invalid")
    for field in ("task_grant_sha256", "settings_sha256", "mcp_sha256", "assignment_sha256"):
        _digest(row[field], field)
    path = row["worktree_path"]
    if not isinstance(path, str) or path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/")):
        raise ProtectedClaudeError("claude_prepare_worktree_invalid")
    if row["subscription_receipt_sha256"] is not None:
        raise ProtectedClaudeError("claude_subscription_receipt_not_accepted")
    if row["mode"] == "read_only":
        if row["scoped_write_grant"] is not None:
            raise ProtectedClaudeError("claude_read_only_guard_forbidden")
        guard_sha = _sha({"mode": "read_only", "guard": None})
    else:
        try:
            guard = _POLICY.validate_claude_scoped_write_grant(
                row["scoped_write_grant"], route_name=ROUTE_NAME, model=BINDING["model"],
                task_id=row["task_id"], task_grant_sha256=row["task_grant_sha256"],
                attempt_id=row["attempt_id"], session_id=row["session_id"],
                worktree_path=row["worktree_path"],
            )
        except _POLICY.ExecutionPolicyError as exc:
            raise ProtectedClaudeError("claude_scoped_write_guard_invalid:" + exc.path) from exc
        if guard["settings_sha256"] != row["settings_sha256"] or guard["mcp_sha256"] != row["mcp_sha256"] or guard["assignment_sha256"] != row["assignment_sha256"]:
            raise ProtectedClaudeError("claude_guard_artifact_binding_mismatch")
        guard_sha = guard["grant_sha256"]
    payload = {
        "task_id": row["task_id"], "route_name": ROUTE_NAME, **dict(BINDING),
        "mode": row["mode"], "task_grant_sha256": row["task_grant_sha256"],
        "attempt_id": row["attempt_id"], "session_id": row["session_id"],
        "worktree_path": row["worktree_path"], "settings_sha256": row["settings_sha256"],
        "mcp_sha256": row["mcp_sha256"], "assignment_sha256": row["assignment_sha256"],
        "scoped_write_grant_sha256": guard_sha, "argv_sha256": _sha(_argv(row["prompt"], row["mode"])),
        "observed_turns_max": MAX_TURNS, "managed_settings_absence_proved": False,
        "spawn_eligible": False, "provider_called": False,
        "protected_production": False,
    }
    return PreparedClaudeSession(**payload, prepared_sha256=_sha(payload))


def inspect_pending(prepared: PreparedClaudeSession) -> dict[str, Any]:
    if not isinstance(prepared, PreparedClaudeSession):
        raise ProtectedClaudeError("claude_prepared_invalid")
    payload = asdict(prepared); supplied = payload.pop("prepared_sha256")
    if supplied != _sha(payload):
        raise ProtectedClaudeError("claude_prepared_digest_mismatch")
    if prepared.spawn_eligible or prepared.provider_called or prepared.protected_production or prepared.billing_basis != "unknown" or prepared.managed_settings_absence_proved:
        raise ProtectedClaudeError("claude_prepared_proof_promotion")
    return {
        "status": "pending_subscription_and_managed_settings_evidence",
        "spawn_eligible": False, "provider_called": False, "retry_allowed": False,
        "billing_basis": "unknown", "managed_settings_absence_proved": False,
        "route_id": prepared.route_id, "model": prepared.model,
        "protected_production": False, "t062_proved": False,
    }


class ObservedSession:
    """Parent-side source model for exact turns and read-mutate-read order."""
    def __init__(self, prepared: PreparedClaudeSession, mutation_tool: str = "Write") -> None:
        if mutation_tool not in {"Write", "Edit"}: raise ProtectedClaudeError("claude_observer_mutation_invalid")
        self.prepared = prepared; self.turns = 0; self.index = 0
        self.sequence = ("Read", mutation_tool, "Read"); self.terminal = False

    def event(self, value: Mapping[str, Any]) -> None:
        if value.get("model") not in (None, self.prepared.model): raise ProtectedClaudeError("claude_observer_model_substitution")
        if value.get("session_id") not in (None, self.prepared.session_id): raise ProtectedClaudeError("claude_observer_session_substitution")
        if value.get("attempt_id") not in (None, self.prepared.attempt_id): raise ProtectedClaudeError("claude_observer_attempt_substitution")
        if value.get("type") == "assistant":
            self.turns += 1
            if self.turns > MAX_TURNS: raise ProtectedClaudeError("claude_observer_turn_limit")
        if value.get("type") == "tool":
            if self.index >= 3 or value.get("name") != self.sequence[self.index]: raise ProtectedClaudeError("claude_observer_order_invalid")
            self.index += 1
        if value.get("type") == "result":
            if self.index != 3: raise ProtectedClaudeError("claude_observer_terminal_before_sequence")
            self.terminal = True
