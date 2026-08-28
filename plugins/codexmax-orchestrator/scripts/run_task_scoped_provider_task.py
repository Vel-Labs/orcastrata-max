#!/usr/bin/env python3
"""Run one bounded, read-only provider task from an exact model request.

This is the operator seam for configured external agents. It composes the
existing session probe and headless dispatcher. It does not authenticate,
inspect credentials, invent transports, or retry a route.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import sys
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

SCRIPT = Path(__file__).resolve()
PLUGIN_ROOT = SCRIPT.parents[1]


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SESSION = _load("codexmax_task_scoped_session", SCRIPT.with_name("verify_configured_tool_session.py"))
DISPATCH = _load("codexmax_task_scoped_dispatch", SCRIPT.with_name("run_headless_provider_dispatch.py"))
CONFIG = _load("codexmax_task_scoped_config", SCRIPT.with_name("resolve_codexmax_config.py"))

MAX_TEXT = 16384
MAX_SCOPE_ITEMS = 64
SAFE_ID = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _text(value: Any, field: str, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > limit:
        raise ValueError(f"{field}_invalid")
    if any(ord(c) < 32 and c not in "\t\n\r" for c in value):
        raise ValueError(f"{field}_invalid")
    return value


def _relative_scope(values: Sequence[str]) -> list[str]:
    if not isinstance(values, (list, tuple)) or not values or len(values) > MAX_SCOPE_ITEMS:
        raise ValueError("read_scope_invalid")
    result: list[str] = []
    for raw in values:
        value = _text(raw, "read_scope", 512)
        path = Path(value)
        if path.is_absolute() or ".." in path.parts or "\\" in value or value.startswith("./"):
            raise ValueError("read_scope_invalid")
        result.append(path.as_posix())
    if len(set(result)) != len(result):
        raise ValueError("read_scope_invalid")
    return sorted(result)


def _task_grant(*, task_id: str, request: str, prompt: str, repo_root: Path,
                scope: list[str], evidence: str, artifact: str) -> dict[str, Any]:
    body = {"schema_version": 1, "authority_source": "operator_invocation",
            "task_id": task_id, "request": request, "prompt_sha256":
            "sha256:" + hashlib.sha256(prompt.encode()).hexdigest(),
            "repo_root": str(repo_root), "read_scope": scope,
            "evidence_directory": evidence, "expected_artifact": artifact,
            "billing_basis": "subscription", "allow_provider_call": True}
    return {
        **body,
        "task_grant_sha256": "sha256:" + hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _read_only_profile(route_name: str) -> dict[str, Any]:
    """Create the fixed task-scoped profile; values are not operator supplied."""
    return {
        "profile_schema_version": CONFIG.TASK_PROFILE_SCHEMA_VERSION,
        "required_source_access": "local_filesystem",
        "commands_required": False,
        "write_required": False,
        "browser_required": False,
        "web_search_required": False,
        "connector_required": False,
        "billing_ceiling": "non_metered",
        "consequence_floor": "medium",
        "independence_required": False,
        "primary_route": route_name,
        "secondary_01": "none", "secondary_02": "none", "secondary_03": "none",
        "secondary_04": "none", "secondary_05": "none",
    }


def _preflight(task_id: str, route: Mapping[str, Any], probe: Mapping[str, Any], scope: list[str], now: str) -> dict[str, Any]:
    # Session probing proves exact identity and usable authentication. The
    # read-only capability is bounded to the declared scope and this process.
    expiry = datetime.fromisoformat(now[:-1] + "+00:00").timestamp() + 300
    expires = datetime.fromtimestamp(expiry, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    evidence = "configured_tool_session_probe:" + str(probe["output_sha256"])
    return {
        "preflight_id": f"task-scoped:{task_id}", "task_id": task_id, "fresh": True,
        "observed_at": now, "expires_at": expires,
        "provider": route["provider"], "model": route["exact_model"], "route": route["route_id"],
        "runtime": route["runtime"], "reasoning": route["reasoning"], "billing": route["billing_basis"],
        "token_limit": None, "availability": "available", "health": "healthy",
        "authentication": "verified", "identity_status": "known_exact", "capability_status": "verified",
        "identity_evidence": evidence, "capability_evidence": "task_scoped_read_only:" + evidence,
        # Command Code's authenticated status is the only bounded quota
        # observation available to this adapter. Preserve this as route
        # availability, not as a token or spend estimate.
        "quota": "available", "credential_access_required": False,
        "source_access": "local_filesystem", "input_delivery": "paths_only", "commands_executable": "no",
        "local_file_access": "read_only", "browser_access": "no", "web_search_access": "no",
        "connector_access": "no", "network_access": "provider_only", "citation_support": "no",
        "write_access": "none", "read_scope": scope, "write_scope": [],
        "authority_scope": scope, "consequence_floor": "medium", "independence_group": route["independence_group"],
    }


def build_assignment(
    *, request: str, task_id: str, prompt: str,
    repo_root: Path, read_scope: Sequence[str], evidence_directory: str,
    expected_artifact: str, probe_runner: Callable[..., Any],
    effective: dict[str, Any], allow_provider_call: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if allow_provider_call is not True:
        raise ValueError("task_scoped_provider_call_not_authorized")
    repo_root = repo_root.resolve(strict=True)
    task_id = _text(task_id, "task_id", 128)
    if SAFE_ID.fullmatch(task_id) is None:
        raise ValueError("task_id_invalid")
    prompt = _text(prompt, "prompt")
    scope = _relative_scope(read_scope)
    if scope != ["."]:
        raise ValueError("read_scope_must_be_repo_root")
    evidence_directory = _text(evidence_directory, "evidence_directory", 1024)
    expected_artifact = _text(expected_artifact, "expected_artifact", 1024)
    tool, model = SESSION.parse_request(request)
    binding_id, binding, route = SESSION._configured_binding(effective, tool, model)
    provider_id, model_token = SESSION._probe_identity(tool, route, model)
    probe = SESSION.probe_existing_session(tool, provider_id, model_token, runner=probe_runner)
    execution_prompt = (
        prompt
        + "\n\nExecution boundary: the provider may read the repository root (.) only. "
          "No narrower read-scope enforcement is claimed."
    )
    grant = _task_grant(task_id=task_id, request=request, prompt=execution_prompt,
        repo_root=repo_root, scope=scope, evidence=evidence_directory, artifact=expected_artifact)
    selection = SESSION.compile_selection(
        request, task_id=task_id, task_grant_sha256=grant["task_grant_sha256"],
        effective_config=effective, probe_runner=probe_runner, session_probe=probe,
    )
    now = _now()
    route_name = binding["route"]["route_name"]
    registry = copy.deepcopy(effective["route_registry"])
    registry["routes"][route_name]["exact_model"] = binding["route"]["exact_model"]
    profile_name = "task_scoped_read_only"
    registry["task_profiles"][profile_name] = _read_only_profile(route_name)
    route_packet = {
        "schema_version": 2, "task_id": task_id, "role": "worker", "profile": profile_name,
        "resolution_time": now, "token_limit": None, "allowed_billing": ["subscription"],
        "read_scope": scope, "write_scope": [], "authority_scope": scope,
        "requirements": {"commands": False, "local_files": True, "browser": False, "web_search": False, "connector": False, "write": False},
        "provider_input": {
            "source_access": "local_filesystem", "input_delivery": "paths_only", "required_source_access": ["local_filesystem"],
            "source_backed_claims_required": True, "commands_executable": "no", "commands_required": False,
            "named_source_categories": [{"category_id": "repository", "required": True, "source_label": "Repository paths"}],
            "read_receipt_required": True, "compatibility_gate": {"decision": "compatible", "reason": "compatible"},
        },
        "independence_required": False, "independence_exclusions": [], "consequence_floor": "medium",
        "controls": {"circuit_breaker_threshold": 1, "max_attempts_per_checkpoint": 1, "max_attempts_per_route": 1, "no_improvement_window": 1},
        "preflights": {route_name: _preflight(task_id, route, probe, scope, now)}, "attempt_results": {},
        "explicit_selection": selection, "task_grant_sha256": grant["task_grant_sha256"],
        "parent_capability": {"cost_ceiling": 1, "effort_ceiling": 1},
        "registry": registry,
    }
    schema = {
        "type": "object", "additionalProperties": False,
        "required": ["route_identity", "content"],
        "properties": {
            "content": {"type": "string", "minLength": 1, "maxLength": 65536},
            "route_identity": {"type": "object", "additionalProperties": False,
                "required": ["declared_route", "actual_provider", "actual_model", "fallback_used", "retry_count"],
                "properties": {"declared_route": {"type": "string"}, "actual_provider": {"type": "string"},
                    "actual_model": {"type": "string"}, "fallback_used": {"const": False}, "retry_count": {"const": 0}}},
        },
    }
    assignment = {
        "schema_version": 1, "dispatch_id": f"task-scoped-{task_id}-{uuid.uuid4().hex[:12]}",
        "supervisor_assignment_id": f"assignment-{task_id}", "supervisor_lane_id": f"lane-{task_id}",
        "semantic_role": "worker", "prompt": execution_prompt, "working_directory": ".",
        "expected_artifact": expected_artifact, "evidence_directory": evidence_directory,
        "dispatch_output_scope": [evidence_directory + "/**", str(Path(expected_artifact).parent) + "/**"],
        "proof_mode": "task_scoped_live",
        "authority": {"provider_call_authorized": True, "network_authorized": True, "billing_authorized": True,
            "credential_mechanism_authorized": True, "scope_authorized": True, "retention_authorized": True},
        "route_packet": route_packet, "response_schema": schema,
    }
    return assignment, {"configured": True, "selected": False, "binding_id": binding_id, "selection": selection, "probe": probe,
        "authority_source": "operator_invocation", "task_grant": grant,
        "task_grant_sha256": grant["task_grant_sha256"]}


def run_task(
    *, repo_root: Path, request: str, task_id: str, prompt: str,
    read_scope: Sequence[str], evidence_directory: str, expected_artifact: str,
    workspace_config: Path | None, allow_provider_call: bool,
    probe_runner: Callable[..., Any],
    timeout_seconds: float = 60.0,
) -> dict[str, Any]:
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not 1 <= timeout_seconds <= 300
    ):
        raise ValueError("timeout_seconds_invalid")
    repo_root = Path(repo_root).resolve(strict=True)
    if allow_provider_call is not True:
        return {"configured": False, "selected": False, "called": False, "completed": False,
                "rejected": True, "reason": "task_scoped_provider_call_not_authorized"}
    # Resolve the workspace overlay before selection. The same exact effective
    # object must govern assignment construction and dispatch accounting.
    effective = DISPATCH._effective_config(repo_root, workspace_config)
    assignment, lifecycle = build_assignment(
        repo_root=repo_root, request=request, task_id=task_id, prompt=prompt,
        read_scope=read_scope, evidence_directory=evidence_directory,
        expected_artifact=expected_artifact, probe_runner=probe_runner,
        effective=effective, allow_provider_call=True,
    )
    checked = DISPATCH._require_assignment(assignment, repo_root)
    packet = copy.deepcopy(checked["route_packet"])
    try:
        preview = DISPATCH._resolve_pre_dispatch(packet)
    except (DISPATCH.DispatchError, DISPATCH._route.ResolutionError) as exc:
        lifecycle.update({
            "selected": False, "called": False, "completed": False,
            "rejected": True, "reason": exc.code,
        })
        return lifecycle
    lifecycle["route_resolution"] = preview
    if preview.get("status") != "dispatch_required":
        lifecycle.update({
            "selected": False, "called": False, "completed": False,
            "rejected": True,
            "reason": preview.get("stop_reason", preview.get("status", "pre_dispatch_rejected")),
        })
        return lifecycle
    lifecycle["selected"] = True
    # The derived profile is fixed by build_assignment and is already bound to
    # the exact route. No route resolver fallback is possible.
    result = DISPATCH.run_dispatch(
        checked, packet, repo_root, {}, effective=effective, allow_provider_call=True,
        allow_simulated_process=False, timeout=float(timeout_seconds), stdout_limit=1024 * 1024,
        stderr_limit=256 * 1024,
    )
    attempts = result.get("attempts") or []
    called = any(attempt.get("returncode") is not None for attempt in attempts)
    artifact_ok = isinstance(result.get("artifact"), dict)
    identity_ok = bool(attempts and attempts[-1].get("response_identity_validated") is True)
    completed = result.get("status") == "selected" and artifact_ok and identity_ok
    lifecycle.update({"called": called, "completed": completed, "rejected": not completed,
                      "usage": result.get("usage"), "manifest": result})
    return lifecycle


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--request", required=True, help="Use MODEL through Command Code or OpenCode")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--workspace-config", type=Path, required=True)
    parser.add_argument("--allow-provider-call", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--read-scope", action="append", required=True)
    parser.add_argument("--evidence-directory", default="reports/task-scoped")
    parser.add_argument("--expected-artifact", default="reports/task-scoped/result.json")
    args = parser.parse_args(argv)
    try:
        result = run_task(**vars(args), probe_runner=__import__("subprocess").run)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("completed") else 2
    except (ValueError, SESSION.ExplicitSelectionError, DISPATCH.DispatchError, OSError) as exc:
        print(json.dumps({"status": "rejected", "code": getattr(exc, "code", "task_scoped_rejected"), "detail": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
