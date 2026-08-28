#!/usr/bin/env python3
"""Internal service for one task-scoped provider execution.

The public runners are compatibility adapters.  This module owns the common
config, probe, assignment, pre-dispatch, dispatch, and receipt lifecycle.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

MAX_TEXT = 16384
MAX_SCOPE_ITEMS = 64
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


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
    body = {
        "schema_version": 1, "authority_source": "operator_invocation", "task_id": task_id,
        "request": request,
        "prompt_sha256": "sha256:" + hashlib.sha256(prompt.encode()).hexdigest(),
        "repo_root": str(repo_root), "read_scope": scope,
        "evidence_directory": evidence, "expected_artifact": artifact,
        "billing_basis": "subscription", "allow_provider_call": True,
    }
    return {
        **body,
        "task_grant_sha256": "sha256:" + hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _read_only_profile(route_name: str, config: Any) -> dict[str, Any]:
    return {
        "profile_schema_version": config.TASK_PROFILE_SCHEMA_VERSION,
        "required_source_access": "local_filesystem", "commands_required": False,
        "write_required": False, "browser_required": False, "web_search_required": False,
        "connector_required": False, "billing_ceiling": "non_metered",
        "consequence_floor": "medium", "independence_required": False,
        "primary_route": route_name,
        "secondary_01": "none", "secondary_02": "none", "secondary_03": "none",
        "secondary_04": "none", "secondary_05": "none",
    }


def _preflight(task_id: str, route: Mapping[str, Any], probe: Mapping[str, Any],
               scope: list[str], now: str) -> dict[str, Any]:
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
        # Model visibility proves entitlement, not remaining provider quota.
        "quota": "unknown", "credential_access_required": False,
        "source_access": "local_filesystem", "input_delivery": "paths_only", "commands_executable": "no",
        "local_file_access": "read_only", "browser_access": "no", "web_search_access": "no",
        "connector_access": "no", "network_access": "provider_only", "citation_support": "no",
        "write_access": "none", "read_scope": scope, "write_scope": [],
        "authority_scope": scope, "consequence_floor": "medium",
        "independence_group": route["independence_group"],
    }


def build_assignment(*, request: str, task_id: str, prompt: str, repo_root: Path,
                     read_scope: Sequence[str], evidence_directory: str,
                     expected_artifact: str, probe_runner: Callable[..., Any],
                     effective: dict[str, Any], allow_provider_call: bool,
                     session_module: Any, config_module: Any,
                     session_probe: Mapping[str, Any] | None = None,
                     now: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
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
    tool, model = session_module.parse_request(request)
    binding_id, binding, route = session_module._configured_binding(effective, tool, model)
    provider_id, model_token = session_module._probe_identity(tool, route, model)
    probe = dict(session_probe) if session_probe is not None else session_module.probe_existing_session(
        tool, provider_id, model_token, runner=probe_runner
    )
    execution_prompt = (
        prompt + "\n\nExecution boundary: the provider may read the repository root (.) only. "
        "No narrower read-scope enforcement is claimed."
    )
    grant = _task_grant(task_id=task_id, request=request, prompt=execution_prompt,
                        repo_root=repo_root, scope=scope, evidence=evidence_directory,
                        artifact=expected_artifact)
    selection = session_module.compile_selection(
        request, task_id=task_id, task_grant_sha256=grant["task_grant_sha256"],
        effective_config=effective, probe_runner=probe_runner, session_probe=probe,
    )
    resolution_time = now or _now()
    route_name = binding["route"]["route_name"]
    registry = copy.deepcopy(effective["route_registry"])
    registry["routes"][route_name]["exact_model"] = binding["route"]["exact_model"]
    profile_name = "task_scoped_read_only"
    registry["task_profiles"][profile_name] = _read_only_profile(route_name, config_module)
    route_packet = {
        "schema_version": 2, "task_id": task_id, "role": "worker", "profile": profile_name,
        "resolution_time": resolution_time, "token_limit": None, "allowed_billing": ["subscription"],
        "read_scope": scope, "write_scope": [], "authority_scope": scope,
        "requirements": {"commands": False, "local_files": True, "browser": False,
                          "web_search": False, "connector": False, "write": False},
        "provider_input": {
            "source_access": "local_filesystem", "input_delivery": "paths_only",
            "required_source_access": ["local_filesystem"], "source_backed_claims_required": True,
            "commands_executable": "no", "commands_required": False,
            "named_source_categories": [{"category_id": "repository", "required": True,
                                          "source_label": "Repository paths"}],
            "read_receipt_required": True,
            "compatibility_gate": {"decision": "compatible", "reason": "compatible"},
        },
        "independence_required": False, "independence_exclusions": [], "consequence_floor": "medium",
        "controls": {"circuit_breaker_threshold": 1, "max_attempts_per_checkpoint": 1,
                      "max_attempts_per_route": 1, "no_improvement_window": 1},
        "preflights": {route_name: _preflight(task_id, route, probe, scope, resolution_time)},
        "attempt_results": {}, "explicit_selection": selection,
        "task_grant_sha256": grant["task_grant_sha256"],
        "parent_capability": {"cost_ceiling": 1, "effort_ceiling": 1}, "registry": registry,
    }
    identity_fields = {
        "declared_route": {"type": "string"}, "actual_provider": {"type": "string"},
        "actual_model": {"type": "string"}, "fallback_used": {"const": False},
        "retry_count": {"const": 0},
    }
    schema = {
        "type": "object", "additionalProperties": False, "required": ["route_identity", "content"],
        "properties": {"content": {"type": "string", "minLength": 1, "maxLength": 65536},
                        "route_identity": {"type": "object", "additionalProperties": False,
                                            "required": list(identity_fields), "properties": identity_fields}},
    }
    assignment = {
        "schema_version": 1, "dispatch_id": f"task-scoped-{task_id}-{uuid.uuid4().hex[:12]}",
        "supervisor_assignment_id": f"assignment-{task_id}", "supervisor_lane_id": f"lane-{task_id}",
        "semantic_role": "worker", "prompt": execution_prompt, "working_directory": ".",
        "expected_artifact": expected_artifact, "evidence_directory": evidence_directory,
        "dispatch_output_scope": [evidence_directory + "/**", str(Path(expected_artifact).parent) + "/**"],
        "proof_mode": "task_scoped_live",
        "authority": {"provider_call_authorized": True, "network_authorized": True,
                       "billing_authorized": True, "credential_mechanism_authorized": True,
                       "scope_authorized": True, "retention_authorized": True},
        "route_packet": route_packet, "response_schema": schema,
    }
    return assignment, {"configured": True, "selected": False, "binding_id": binding_id,
                        "selection": selection, "probe": probe, "authority_source": "operator_invocation",
                        "task_grant": grant, "task_grant_sha256": grant["task_grant_sha256"]}


def task_local_exact_config(*, effective: Mapping[str, Any], request: str,
                            session_module: Any, config_module: Any) -> tuple[Mapping[str, Any], bool]:
    """Declare a new exact Command Code model for this task only.

    A known transport can accept a new model selector after the fixed session
    probe verifies that selector.  The overlay is never written to workspace or
    user configuration.  An existing disabled binding remains an explicit
    operator denial and is not bypassed.
    """
    tool, model = session_module.parse_request(request)
    try:
        session_module._configured_binding(effective, tool, model)
        return effective, False
    except session_module.ExplicitSelectionError as exc:
        shipped_disabled_example = (
            exc.code == "requested_binding_disabled"
            and isinstance(exc.detail, str)
            and exc.detail.startswith("example_")
        )
        if (
            tool != "Command Code"
            or (exc.code != "requested_model_not_configured" and not shipped_disabled_example)
        ):
            raise
    if session_module.MODEL_TOKEN_RE.fullmatch(model) is None:
        raise session_module.ExplicitSelectionError("requested_model_invalid", model)
    overlay = copy.deepcopy(dict(effective))
    binding = config_module._build_authored_binding(
        adapter_type="commandcode", route_name="worker_commandcode_model",
        credential_kind="host_managed", opaque_id="task-local",
        enabled=True, concurrency_cap=1, token_cap=12000, exact_model=model,
    )
    overlay["adapter_registry"]["bindings"][binding["binding_id"]] = binding
    return overlay, True


def _attempt_started(attempt: Mapping[str, Any]) -> bool:
    return (
        attempt.get("returncode") is not None
        or attempt.get("process_started") is True
        or attempt.get("started") is True
        or attempt.get("provider_process_started") is True
    )


def durable_attempt_started(root: Path, evidence_directory: str,
                            result: Mapping[str, Any] | None = None) -> bool:
    """Return true only when an attempt record or durable attempt files exist."""
    if isinstance(result, Mapping):
        attempts = result.get("attempts")
        if isinstance(attempts, list) and any(isinstance(item, Mapping) and _attempt_started(item) for item in attempts):
            return True
        for key in ("manifest", "dispatch_manifest"):
            nested = result.get(key)
            if isinstance(nested, Mapping) and durable_attempt_started(root, evidence_directory, nested):
                return True
    resolved_root = Path(root).resolve()
    target = resolved_root / evidence_directory
    try:
        target.relative_to(resolved_root)
    except ValueError:
        return False
    try:
        if not target.is_dir():
            return False
        for attempt_dir in target.glob("attempt-*"):
            if not attempt_dir.is_dir():
                continue
            # The dispatcher persists the synthetic stderr marker for a
            # spawn failure too.  That marker is durable evidence that the
            # process did not start, not evidence of a provider attempt.
            stderr = attempt_dir / "stderr.bin"
            if stderr.is_file():
                try:
                    if stderr.read_bytes() in {b"FileNotFoundError", b"PermissionError", b"OSError"}:
                        continue
                except OSError:
                    continue
            if any((attempt_dir / name).is_file() for name in ("stdout.bin", "stderr.bin", "attempt.json")):
                return True
    except OSError:
        return False
    return False


def _identity_schema_ok(result: Mapping[str, Any]) -> tuple[bool, bool]:
    attempts = result.get("attempts")
    if not isinstance(attempts, list) or not attempts or not isinstance(attempts[-1], Mapping):
        return False, False
    attempt = attempts[-1]
    expected = attempt.get("expected_response_identity")
    identity_ok = (
        isinstance(expected, Mapping)
        and set(expected) == {"declared_route", "actual_provider", "actual_model", "fallback_used", "retry_count"}
        and all(isinstance(expected.get(field), str) and expected[field] for field in ("declared_route", "actual_provider", "actual_model"))
        and expected.get("fallback_used") is False
        and expected.get("retry_count") == 0
        and attempt.get("response_identity_validated") is True
    )
    observed = attempt.get("response_identity")
    if observed is not None and observed != expected:
        identity_ok = False
    schema_ok = isinstance(result.get("artifact"), dict)
    return identity_ok, schema_ok


def truthful_receipt(lifecycle: Mapping[str, Any], result: Mapping[str, Any] | None,
                     *, root: Path, evidence_directory: str,
                     error: BaseException | None = None) -> dict[str, Any]:
    """Build the small compatibility receipt without losing started evidence."""
    out = dict(lifecycle)
    attempts = result.get("attempts") if isinstance(result, Mapping) else None
    called = isinstance(attempts, list) and any(
        isinstance(item, Mapping) and _attempt_started(item) for item in attempts
    )
    if not called:
        called = durable_attempt_started(root, evidence_directory, result)
    completed = False
    identity_ok = False
    schema_ok = False
    if isinstance(result, Mapping):
        identity_ok, schema_ok = _identity_schema_ok(result)
        completed = result.get("status") == "selected" and schema_ok and identity_ok
    out.update({"called": called, "completed": completed, "rejected": not completed,
                "identity_validated": identity_ok, "schema_validated": schema_ok})
    if isinstance(result, Mapping):
        out.update({"usage": result.get("usage"), "manifest": result})
    if error is not None:
        out.setdefault("reason", getattr(error, "code", type(error).__name__))
    return out


def execute_task(*, repo_root: Path, request: str, task_id: str, prompt: str,
                 read_scope: Sequence[str], evidence_directory: str,
                 expected_artifact: str, workspace_config: Path | None,
                 allow_provider_call: bool, probe_runner: Callable[..., Any],
                 timeout_seconds: float = 60.0, session_module: Any,
                 dispatch_module: Any, config_module: Any,
                 assignment_builder: Callable[..., Any] | None = None,
                 session_probe: Mapping[str, Any] | None = None,
                 effective_config: dict[str, Any] | None = None,
                 lifecycle_extra: Mapping[str, Any] | None = None,
                 allow_task_local_binding: bool = False) -> dict[str, Any]:
    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 300:
        raise ValueError("timeout_seconds_invalid")
    repo_root = Path(repo_root).resolve(strict=True)
    if allow_provider_call is not True:
        return {"configured": False, "selected": False, "called": False, "completed": False,
                "rejected": True, "reason": "task_scoped_provider_call_not_authorized"}
    effective = effective_config if effective_config is not None else dispatch_module._effective_config(repo_root, workspace_config)
    task_local_binding = False
    if allow_task_local_binding:
        effective, task_local_binding = task_local_exact_config(
            effective=effective, request=request, session_module=session_module,
            config_module=config_module,
        )
    builder = assignment_builder or build_assignment
    kwargs = dict(request=request, task_id=task_id, prompt=prompt, repo_root=repo_root,
                  read_scope=read_scope, evidence_directory=evidence_directory,
                  expected_artifact=expected_artifact, probe_runner=probe_runner,
                  effective=effective, allow_provider_call=True,
                  session_module=session_module, config_module=config_module)
    if session_probe is not None:
        kwargs["session_probe"] = session_probe
    try:
        assignment, lifecycle = builder(**kwargs)
    except TypeError:
        # Existing test and extension seams may expose the pre-service builder
        # signature. They still receive the same effective config object.
        kwargs.pop("session_module", None)
        kwargs.pop("config_module", None)
        assignment, lifecycle = builder(**kwargs)
    if lifecycle_extra:
        lifecycle.update(copy.deepcopy(dict(lifecycle_extra)))
    lifecycle.setdefault("task_local_binding", task_local_binding)
    lifecycle["binding_persisted"] = (
        False if lifecycle.get("task_local_binding") is True else None
    )
    checked = dispatch_module._require_assignment(assignment, repo_root)
    packet = copy.deepcopy(checked["route_packet"])
    try:
        preview = dispatch_module._resolve_pre_dispatch(packet)
    except (dispatch_module.DispatchError, dispatch_module._route.ResolutionError) as exc:
        lifecycle.update({"selected": False, "called": False, "completed": False,
                          "rejected": True, "reason": exc.code})
        return lifecycle
    lifecycle["route_resolution"] = preview
    if preview.get("status") != "dispatch_required":
        lifecycle.update({"selected": False, "called": False, "completed": False,
                          "rejected": True,
                          "reason": preview.get("stop_reason", preview.get("status", "pre_dispatch_rejected"))})
        return lifecycle
    lifecycle["selected"] = True
    try:
        result = dispatch_module.run_dispatch(
            checked, packet, repo_root, {}, effective=effective, allow_provider_call=True,
            allow_simulated_process=False, timeout=float(timeout_seconds),
            stdout_limit=1024 * 1024, stderr_limit=256 * 1024,
        )
    except Exception as exc:
        return truthful_receipt(lifecycle, None, root=repo_root,
                                evidence_directory=evidence_directory, error=exc)
    receipt = truthful_receipt(lifecycle, result, root=repo_root,
                               evidence_directory=evidence_directory)
    return receipt


class ProviderTaskExecutionService:
    """Dependency-injected facade used by all compatibility runners."""

    def __init__(self, *, session_module: Any, dispatch_module: Any, config_module: Any):
        self.session = session_module
        self.dispatch = dispatch_module
        self.config = config_module

    def resolve_config(self, repo_root: Path, workspace_config: Path | None) -> dict[str, Any]:
        return self.dispatch._effective_config(Path(repo_root).resolve(strict=True), workspace_config)

    def probe_exact(self, request: str, effective: Mapping[str, Any],
                    probe_runner: Callable[..., Any]) -> dict[str, Any]:
        tool, model = self.session.parse_request(request)
        _, _, route = self.session._configured_binding(effective, tool, model)
        provider_id, model_token = self.session._probe_identity(tool, route, model)
        return self.session.probe_existing_session(tool, provider_id, model_token, runner=probe_runner)

    def build_assignment(self, **kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        kwargs.setdefault("session_module", self.session)
        kwargs.setdefault("config_module", self.config)
        return build_assignment(**kwargs)

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("assignment_builder", self.build_assignment)
        return execute_task(session_module=self.session, dispatch_module=self.dispatch,
                            config_module=self.config, **kwargs)

    run = execute
