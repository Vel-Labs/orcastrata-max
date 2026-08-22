#!/usr/bin/env python3
"""Pending-only source seam for one Grok CLI 1.0.4 task session."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from typing import Any, Mapping


_SPEC = importlib.util.spec_from_file_location("grok_guard_policy", Path(__file__).with_name("provider_execution_policy.py"))
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("provider execution policy unavailable")
_POLICY = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_POLICY)
ROUTE_NAME = "worker_grok_4_6"
BINDING = _POLICY.GROK_ROUTE_BINDINGS[ROUTE_NAME]
SHA = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:@+-]{1,127}\Z")
REQUEST_FIELDS = {
    "schema_version", "task_id", "route_name", "route_id", "model", "runtime",
    "billing_basis", "mode", "prompt", "task_grant_sha256", "attempt_id",
    "session_id", "worktree_path", "home_sha256", "config_sha256",
    "project_sha256", "assignment_sha256", "scoped_write_grant",
    "subscription_receipt_sha256",
}


class GrokCleanSessionError(ValueError): pass


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise GrokCleanSessionError("grok_digest_invalid:" + field)
    return value


@dataclass(frozen=True)
class PreparedGrokSession:
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
    home_sha256: str
    config_sha256: str
    project_sha256: str
    assignment_sha256: str
    scoped_write_grant_sha256: str
    argv_sha256: str
    observed_turns_max: int
    clean_session_isolation_proved: bool
    oauth_subscription_proved: bool
    spawn_eligible: bool
    provider_called: bool
    protected_production: bool
    prepared_sha256: str


def argv(prompt: str, mode: str, session_id: str) -> list[str]:
    tools = ["read_file"] if mode == "read_only" else list(_POLICY.GROK_FILE_TOOLS)
    return [
        "grok", "--single", prompt, "--model", BINDING["model"],
        "--max-turns", "20", "--disable-web-search", "--no-memory",
        "--no-subagents", "--no-plan", "--tools", ",".join(tools),
        "--disallowed-tools", "shell,web_search,web_fetch,mcp",
        "--sandbox", "strict", "--session-id", session_id,
        "--output-format", "streaming-json", "--no-auto-update",
    ]


def prepare_clean_session(value: Any) -> PreparedGrokSession:
    if not isinstance(value, Mapping) or set(value) != REQUEST_FIELDS:
        raise GrokCleanSessionError("grok_request_shape_invalid")
    row = dict(value)
    if (
        row["schema_version"] != 1 or row["route_name"] != ROUTE_NAME
        or any(row[field] != BINDING[field] for field in ("route_id", "model", "runtime", "billing_basis"))
        or row["mode"] not in {"read_only", "scoped_write"}
    ):
        raise GrokCleanSessionError("grok_request_identity_invalid")
    for field in ("task_id", "attempt_id", "session_id"):
        if not isinstance(row[field], str) or IDENTIFIER.fullmatch(row[field]) is None:
            raise GrokCleanSessionError("grok_request_identifier_invalid:" + field)
    if not isinstance(row["prompt"], str) or not row["prompt"] or "\x00" in row["prompt"] or len(row["prompt"].encode()) > 131072:
        raise GrokCleanSessionError("grok_prompt_invalid")
    for field in ("task_grant_sha256", "home_sha256", "config_sha256", "project_sha256", "assignment_sha256"):
        _digest(row[field], field)
    path = row["worktree_path"]
    if not isinstance(path, str) or path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/")):
        raise GrokCleanSessionError("grok_worktree_invalid")
    if len({row["home_sha256"], row["config_sha256"], row["project_sha256"]}) != 3:
        raise GrokCleanSessionError("grok_clean_root_alias_invalid")
    if row["subscription_receipt_sha256"] is not None:
        raise GrokCleanSessionError("grok_subscription_receipt_not_accepted")
    if row["mode"] == "read_only":
        if row["scoped_write_grant"] is not None:
            raise GrokCleanSessionError("grok_read_only_guard_forbidden")
        grant_sha = _sha({"mode": "read_only", "guard": None})
    else:
        try:
            guard = _POLICY.validate_grok_scoped_write_grant(
                row["scoped_write_grant"], route_name=ROUTE_NAME,
                model=BINDING["model"], task_id=row["task_id"],
                task_grant_sha256=row["task_grant_sha256"],
                attempt_id=row["attempt_id"], session_id=row["session_id"],
                worktree_path=row["worktree_path"],
            )
        except _POLICY.ExecutionPolicyError as exc:
            raise GrokCleanSessionError("grok_scoped_write_grant_invalid:" + exc.path) from exc
        for field in ("home_sha256", "config_sha256", "project_sha256", "assignment_sha256"):
            if guard[field] != row[field]:
                raise GrokCleanSessionError("grok_clean_artifact_binding_mismatch:" + field)
        grant_sha = guard["grant_sha256"]
    payload = {
        "task_id": row["task_id"], "route_name": ROUTE_NAME, **dict(BINDING),
        "mode": row["mode"], "task_grant_sha256": row["task_grant_sha256"],
        "attempt_id": row["attempt_id"], "session_id": row["session_id"],
        "worktree_path": row["worktree_path"], "home_sha256": row["home_sha256"],
        "config_sha256": row["config_sha256"], "project_sha256": row["project_sha256"],
        "assignment_sha256": row["assignment_sha256"],
        "scoped_write_grant_sha256": grant_sha,
        "argv_sha256": _sha(argv(row["prompt"], row["mode"], row["session_id"])),
        "observed_turns_max": 20, "clean_session_isolation_proved": False,
        "oauth_subscription_proved": False, "spawn_eligible": False,
        "provider_called": False, "protected_production": False,
    }
    return PreparedGrokSession(**payload, prepared_sha256=_sha(payload))


def inspect_pending(prepared: PreparedGrokSession) -> dict[str, Any]:
    if not isinstance(prepared, PreparedGrokSession):
        raise GrokCleanSessionError("grok_prepared_invalid")
    payload = asdict(prepared)
    supplied = payload.pop("prepared_sha256")
    if supplied != _sha(payload):
        raise GrokCleanSessionError("grok_prepared_digest_mismatch")
    if any((prepared.clean_session_isolation_proved, prepared.oauth_subscription_proved, prepared.spawn_eligible, prepared.provider_called, prepared.protected_production)):
        raise GrokCleanSessionError("grok_prepared_proof_promotion")
    return {
        "status": "pending_oauth_subscription_and_clean_session_evidence",
        "billing_basis": "unknown", "clean_session_isolation_proved": False,
        "oauth_subscription_proved": False, "spawn_eligible": False,
        "provider_called": False, "retry_allowed": False,
        "protected_production": False, "t062_proved": False,
    }


__all__ = ["BINDING", "GrokCleanSessionError", "PreparedGrokSession", "argv", "inspect_pending", "prepare_clean_session"]
