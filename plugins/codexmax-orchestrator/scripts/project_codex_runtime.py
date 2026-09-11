#!/usr/bin/env python3
"""Project an Orcastrata route into a fail-closed Codex collaboration spawn.

This module never calls ``spawn_agent`` or an external provider. The caller
persists an accepted receipt before dispatch and records the canonical child ID
returned by the collaboration runtime.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
SEMANTIC_ROLES = {"planner", "architect", "worker", "tester", "documenter", "auditor"}
SUPPORTED_MODELS = {
    "gpt-5.6-sol": {"low", "medium", "high", "xhigh", "max", "ultra"},
    "gpt-5.6-terra": {"low", "medium", "high", "xhigh", "max", "ultra"},
    "gpt-5.6-luna": {"low", "medium", "high", "xhigh", "max"},
    "gpt-5.3-codex-spark": {"low", "medium", "high", "xhigh"},
}
FIXED_AGENT_TYPES = {
    "codex_planner": {
        "model": "gpt-5.6-terra", "reasoning_effort": "high",
        "semantic_roles": {"planner"},
    },
    "codex_integrator": {
        "model": "gpt-5.6-sol", "reasoning_effort": "medium",
        "semantic_roles": {"worker"},
    },
    "codex_architect": {
        "model": "gpt-5.6-terra", "reasoning_effort": "xhigh",
        "semantic_roles": {"planner", "architect"},
    },
    "codex_auditor": {
        "model": "gpt-5.6-terra", "reasoning_effort": "xhigh",
        "semantic_roles": {"tester", "auditor"},
    },
    "codex_luna_analyst": {
        "model": "gpt-5.6-luna", "reasoning_effort": "medium",
        "semantic_roles": {"tester", "documenter", "auditor"},
    },
    "spark_scout": {
        "model": "gpt-5.3-codex-spark", "reasoning_effort": "low",
        "semantic_roles": {"planner"},
    },
    "spark_test_triage": {
        "model": "gpt-5.3-codex-spark", "reasoning_effort": "low",
        "semantic_roles": {"tester"},
    },
    "spark_diff_reviewer": {
        "model": "gpt-5.3-codex-spark", "reasoning_effort": "medium",
        "semantic_roles": {"tester", "auditor"},
    },
    "spark_doc_draft": {
        "model": "gpt-5.3-codex-spark", "reasoning_effort": "low",
        "semantic_roles": {"documenter"},
    },
    "spark_prompt_compressor": {
        "model": "gpt-5.3-codex-spark", "reasoning_effort": "low",
        "semantic_roles": {"documenter"},
    },
}
AGENT_TYPES = {"default", *FIXED_AGENT_TYPES}
ROUTE_ROTATION_POLICIES = {"automatic_within_authority", "forbidden"}
ROTATABLE_FAILURE_CODES = {"usage_limit", "quota_exhausted", "rate_limit"}


class ProjectionError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProjectionError("invalid_packet", f"{field} must be an object")
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProjectionError("invalid_packet", f"{field} must be a non-empty string")
    return value.strip()


def _load_config_receipt(path: str, packet: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Load and bind one resolver receipt without treating it as authority."""
    receipt_path = Path(path)
    raw = receipt_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectionError("config_receipt_invalid", str(exc)) from exc
    if not isinstance(receipt, dict):
        raise ProjectionError("config_receipt_invalid", "receipt must be an object")
    effective = _mapping(receipt.get("effective_config"), "config_receipt.effective_config")
    provenance = _mapping(receipt.get("provenance"), "config_receipt.provenance")
    role_preferences = _mapping(effective.get("role_preferences"), "config_receipt.role_preferences")
    roles = _mapping(role_preferences.get("roles"), "config_receipt.role_preferences.roles")
    role = _string(packet.get("semantic_role"), "semantic_role")
    preference = _mapping(roles.get(role), f"config_receipt.role_preferences.roles.{role}")
    for field in ("selection_mode", "exact_model", "reasoning_effort"):
        path_key = f"role_preferences.roles.{role}.{field}"
        row = _mapping(provenance.get(path_key), f"config_receipt.provenance.{path_key}")
        if row.get("value") != preference.get(field):
            raise ProjectionError("config_receipt_drift", path_key)
        lifetime = row.get("lifetime")
        if isinstance(lifetime, str) and lifetime.startswith(("goal:", "checkpoint:")):
            context = _mapping(packet.get("config_context"), "config_context")
            expected = context.get("goal_id" if lifetime.startswith("goal:") else "checkpoint_id")
            if expected != lifetime.split(":", 1)[1]:
                raise ProjectionError("config_receipt_scope_mismatch", path_key)
    compiled = {"preference": preference, "source": "config_receipt", "lifetime": {
        field: _mapping(provenance[f"role_preferences.roles.{role}.{field}"], "provenance").get("lifetime")
        for field in ("selection_mode", "exact_model", "reasoning_effort")
    }}
    if packet.get("controller_execution") is not None:
        controller = _mapping(role_preferences.get("controller"), "config_receipt.role_preferences.controller")
        worker_preference = _mapping(roles.get("worker"), "config_receipt.role_preferences.roles.worker")
        execution_preferences: dict[str, Any] = {}
        for execution_role, source_role, preference_row in (
            ("controller", "controller", controller),
            ("worker", "worker", worker_preference),
            ("reviewer", "auditor", _mapping(roles.get("auditor"), "config_receipt.role_preferences.roles.auditor")),
        ):
            if execution_role == "controller":
                preference_row = controller
            for field in ("selection_mode", "exact_model", "reasoning_effort"):
                path_key = (
                    "role_preferences.controller." + field
                    if execution_role == "controller"
                    else f"role_preferences.roles.{source_role}.{field}"
                )
                row = _mapping(provenance.get(path_key), f"config_receipt.provenance.{path_key}")
                if row.get("value") != preference_row.get(field):
                    raise ProjectionError("config_receipt_drift", path_key)
                lifetime = row.get("lifetime")
                if isinstance(lifetime, str) and lifetime.startswith(("goal:", "checkpoint:")):
                    context = _mapping(packet.get("config_context"), "config_context")
                    expected = context.get("goal_id" if lifetime.startswith("goal:") else "checkpoint_id")
                    if expected != lifetime.split(":", 1)[1]:
                        raise ProjectionError("config_receipt_scope_mismatch", path_key)
            execution_preferences[execution_role] = {
                "selection_mode": preference_row.get("selection_mode", "default"),
                "requested": copy.deepcopy(preference_row),
                "source": "config_receipt",
                "lifetime": {
                    field: _mapping(provenance[
                        "role_preferences.controller." + field
                        if execution_role == "controller"
                        else f"role_preferences.roles.{source_role}.{field}"
                    ], "provenance").get("lifetime")
                    for field in ("selection_mode", "exact_model", "reasoning_effort")
                },
            }
        compiled["execution_preferences"] = execution_preferences
    return compiled, digest


def _compile_role_preference(packet: dict[str, Any], compiled: dict[str, Any], digest: str) -> dict[str, Any]:
    """Apply an exact or prefer native preference; leave fallback to route resolution."""
    result = copy.deepcopy(packet)
    _validate_host_snapshot(result.get("host_snapshot"))
    preference = compiled["preference"]
    mode = preference.get("selection_mode", "default")
    model = preference.get("exact_model", "unknown")
    effort = preference.get("reasoning_effort", "unknown")
    result["config_receipt_sha256"] = digest
    result["role_preference"] = {"requested": copy.deepcopy(preference), "source": compiled["source"], "lifetime": compiled["lifetime"]}
    if mode == "exact":
        if not isinstance(model, str) or not model.strip() or model.strip() in {"unknown", "unset", "unverified"}:
            raise ProjectionError("resolution_need", "exact role preference has no usable model")
        route = dict(_mapping(result.get("selected_route"), "selected_route"))
        route["special_route_required"] = True
        route["exact_model"] = model.strip()
        effort_valid = isinstance(effort, str) and effort.strip() not in {"", "unknown", "unset", "unverified"}
        if effort_valid:
            route["reasoning_effort"] = effort.strip()
        result["selected_route"] = route
        result["role_preference"]["effective"] = {
            "exact_model": model.strip(),
            "reasoning_effort": route.get("reasoning_effort", "unknown"),
        }
    elif mode == "prefer":
        host_snapshot = result.get("host_snapshot")
        supported_pairs = None
        if isinstance(host_snapshot, dict):
            supported_pairs = host_snapshot.get("supported_pairs")
        model_valid = isinstance(model, str) and model.strip() and model.strip() not in {"unknown", "unset", "unverified"}
        effort_valid = isinstance(effort, str) and effort.strip() and effort.strip() not in {"", "unknown", "unset", "unverified"}
        if model_valid and supported_pairs is not None:
            existing_route = result.get("selected_route", {})
            desired_effort = effort.strip() if effort_valid else existing_route.get("reasoning_effort", "unknown")
            pair_found = any(
                item.get("exact_model") == model.strip() and item.get("reasoning_effort") == desired_effort
                for item in supported_pairs
            )
            if pair_found:
                route = dict(_mapping(result.get("selected_route"), "selected_route"))
                route["special_route_required"] = True
                route["exact_model"] = model.strip()
                route["reasoning_effort"] = desired_effort
                result["selected_route"] = route
                result["role_preference"]["effective"] = {
                    "exact_model": model.strip(),
                    "reasoning_effort": desired_effort,
                }
                result["role_preference"]["fulfilled"] = True
            else:
                result["role_preference"]["fulfilled"] = False
                existing_route = result.get("selected_route", {})
                result["role_preference"]["effective"] = {
                    "exact_model": existing_route.get("exact_model", "unknown"),
                    "reasoning_effort": existing_route.get("reasoning_effort", "unknown"),
                }
        else:
            result["role_preference"]["fulfilled"] = False
            existing_route = result.get("selected_route", {})
            result["role_preference"]["effective"] = {
                "exact_model": existing_route.get("exact_model", "unknown"),
                "reasoning_effort": existing_route.get("reasoning_effort", "unknown"),
            }
    return result


def _compile_execution_preferences(
    packet: dict[str, Any], compiled: dict[str, Any], digest: str
) -> dict[str, Any]:
    """Compile controller, worker, and auditor preferences into one package."""
    result = copy.deepcopy(packet)
    _validate_host_snapshot(result.get("host_snapshot"))
    package = _mapping(result.get("controller_execution"), "controller_execution")
    preferences = _mapping(compiled.get("execution_preferences"), "execution_preferences")
    roles = _mapping(package.get("roles"), "controller_execution.roles")
    controller_fulfilled: bool | None = None
    for role_name in ("controller", "worker", "reviewer"):
        preference = copy.deepcopy(_mapping(preferences.get(role_name), f"execution_preferences.{role_name}"))
        requested = _mapping(preference.get("requested"), f"execution_preferences.{role_name}.requested")
        mode = preference.get("selection_mode", "default")
        model = requested.get("exact_model")
        effort = requested.get("reasoning_effort")
        model_valid = isinstance(model, str) and model.strip() not in {"", "unknown", "unset", "unverified"}
        effort_valid = isinstance(effort, str) and effort.strip() not in {"", "unknown", "unset", "unverified"}
        role = _mapping(roles.get(role_name), f"controller_execution.roles.{role_name}")
        controller_route_requested = False
        if mode == "exact":
            if not model_valid:
                raise ProjectionError("resolution_need", f"exact {role_name} preference is unavailable")
            role["model"] = model.strip()
            if effort_valid:
                role["reasoning_effort"] = effort.strip()
            controller_route_requested = role_name == "controller"
            if role_name == "controller":
                controller_fulfilled = True
        elif mode == "prefer" and model_valid:
            snapshot = result.get("host_snapshot") if isinstance(result.get("host_snapshot"), dict) else {}
            role_capabilities = snapshot.get("role_capabilities")
            supported = snapshot.get("supported_pairs") if role.get("runtime_surface") == "codex_collaboration" else None
            desired_effort = effort.strip() if effort_valid else role.get("reasoning_effort", "unknown")
            if role.get("runtime_surface") != "codex_collaboration" and isinstance(role_capabilities, dict):
                supported = [
                    {"exact_model": entry.get("model"), "reasoning_effort": entry.get("reasoning_effort")}
                    for entry in role_capabilities.get(role_name, [])
                    if isinstance(entry, dict) and entry.get("runtime_surface") == role.get("runtime_surface")
                ]
            if _capability_supported(supported, model.strip(), desired_effort):
                role["model"] = model.strip()
                role["reasoning_effort"] = desired_effort
                controller_route_requested = role_name == "controller"
                if role_name == "controller":
                    controller_fulfilled = True
            elif role_name == "controller":
                controller_fulfilled = False
        role["preference"] = preference
        if controller_route_requested:
            route = dict(_mapping(result.get("selected_route"), "selected_route"))
            route["special_route_required"] = True
            route["exact_model"] = role["model"]
            route["reasoning_effort"] = role["reasoning_effort"]
            result["selected_route"] = route
    result["config_receipt_sha256"] = digest
    result["controller_execution"]["roles"] = roles
    controller_preference = copy.deepcopy(roles["controller"].get("preference"))
    if controller_preference is not None:
        controller_preference["effective"] = {
            "exact_model": roles["controller"]["model"],
            "reasoning_effort": roles["controller"]["reasoning_effort"],
        }
        result["role_preference"] = controller_preference
        if controller_fulfilled is not None:
            result["role_preference"]["fulfilled"] = controller_fulfilled
    return result


def _bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ProjectionError("invalid_packet", f"{field} must be a boolean")
    return value


def _fork_turns(value: Any) -> str:
    if value in {"none", "all"}:
        return value
    if isinstance(value, str) and value.isdigit() and int(value) > 0:
        return value
    raise ProjectionError(
        "invalid_packet",
        "native_request.fork_turns must be none, all, or a positive integer string",
    )


def _validate_supported_pairs(value: Any) -> list[dict[str, str]] | None:
    """Validate an optional packet-bound host capability catalog."""
    if value is None:
        return None
    if not isinstance(value, list):
        raise ProjectionError("invalid_packet", "host_snapshot.supported_pairs must be a list")
    if len(value) > 64:
        raise ProjectionError("invalid_packet", "host_snapshot.supported_pairs exceeds bounded limit")
    pairs: list[dict[str, str]] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise ProjectionError("invalid_packet", "host_snapshot.supported_pairs entry must be an object")
        pairs.append({
            "exact_model": _string(entry.get("exact_model"), "host_snapshot.supported_pairs[].exact_model"),
            "reasoning_effort": _string(entry.get("reasoning_effort"), "host_snapshot.supported_pairs[].reasoning_effort"),
        })
    return pairs


def _validate_host_snapshot(value: Any) -> dict[str, Any] | None:
    """Validate every capability surface before preference compilation."""
    if value is None:
        return None
    snapshot = _mapping(value, "host_snapshot")
    supported_pairs = _validate_supported_pairs(snapshot.get("supported_pairs"))
    role_capabilities = snapshot.get("role_capabilities")
    if role_capabilities is not None:
        if not isinstance(role_capabilities, dict):
            raise ProjectionError("invalid_packet", "host_snapshot.role_capabilities must be an object")
        if len(role_capabilities) > 3:
            raise ProjectionError("invalid_packet", "host_snapshot.role_capabilities exceeds bounded limit")
        for role_name, entries in role_capabilities.items():
            if role_name not in {"controller", "worker", "reviewer"}:
                raise ProjectionError("invalid_packet", f"host_snapshot.role_capabilities.{role_name} is unsupported")
            if not isinstance(entries, list) or len(entries) > 64:
                raise ProjectionError("invalid_packet", f"host_snapshot.role_capabilities.{role_name} must be a bounded list")
            for entry in entries:
                entry = _mapping(entry, f"host_snapshot.role_capabilities.{role_name}[]")
                _string(entry.get("runtime_surface"), f"host_snapshot.role_capabilities.{role_name}[].runtime_surface")
                _string(entry.get("model"), f"host_snapshot.role_capabilities.{role_name}[].model")
                _string(entry.get("reasoning_effort"), f"host_snapshot.role_capabilities.{role_name}[].reasoning_effort")
                if "endpoint" in entry:
                    _string(entry.get("endpoint"), f"host_snapshot.role_capabilities.{role_name}[].endpoint")
    return {**snapshot, "supported_pairs": supported_pairs}


def _capability_supported(pairs: list[dict[str, str]] | None, model: str, effort: str) -> bool:
    if pairs is None:
        return False
    return any(item["exact_model"] == model and item["reasoning_effort"] == effort for item in pairs)


def _string_list(value: Any, field: str, *, allow_empty: bool = False, preserve_tokens: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ProjectionError("invalid_packet", f"{field} must be a non-empty list")
    if preserve_tokens:
        result = []
        for item in value:
            if not isinstance(item, str):
                raise ProjectionError("invalid_packet", f"{field}[] must be a string")
            if "\x00" in item:
                raise ProjectionError("invalid_packet", f"{field}[] must not contain NUL bytes")
            result.append(item)
        return result
    result = [_string(item, f"{field}[]") for item in value]
    if len(set(result)) != len(result):
        raise ProjectionError("invalid_packet", f"{field} must not contain duplicates")
    return result


def _command_list(value: Any, field: str) -> list[list[str]]:
    if not isinstance(value, list) or not value:
        raise ProjectionError("invalid_packet", f"{field} must be a non-empty list")
    commands: list[list[str]] = []
    for index, command in enumerate(value):
        commands.append(_string_list(command, f"{field}[{index}]", preserve_tokens=True))
    return commands


def _validate_controller_execution(
    value: Any, host_snapshot: dict[str, Any] | None,
    *, child_task_id: str | None = None,
    effective_native_identity: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Validate the optional controller-owned execution package."""
    if value is None:
        return None
    package = copy.deepcopy(_mapping(value, "controller_execution"))
    required = {
        "enabled", "scope", "roles", "repair_authority",
        "final_acceptance_authority", "reporting",
    }
    if set(package) != required or package.get("enabled") is not True:
        raise ProjectionError("invalid_packet", "controller_execution must be enabled with the frozen fields")
    scope = _mapping(package["scope"], "controller_execution.scope")
    if set(scope) != {"task_id", "objective", "allowed_files", "validation", "exclusions"}:
        raise ProjectionError("invalid_packet", "controller_execution.scope fields are incomplete")
    scope["task_id"] = _string(scope["task_id"], "controller_execution.scope.task_id")
    scope["objective"] = _string(scope["objective"], "controller_execution.scope.objective")
    scope["allowed_files"] = _string_list(scope["allowed_files"], "controller_execution.scope.allowed_files")
    scope["validation"] = _command_list(scope["validation"], "controller_execution.scope.validation")
    scope["exclusions"] = _string_list(scope["exclusions"], "controller_execution.scope.exclusions", allow_empty=True)
    if child_task_id is not None and scope["task_id"] != child_task_id:
        raise ProjectionError(
            "controller_execution_scope_mismatch",
            "controller_execution.scope.task_id must equal child_task_id",
        )
    roles = _mapping(package["roles"], "controller_execution.roles")
    if set(roles) != {"controller", "worker", "reviewer"}:
        raise ProjectionError("invalid_packet", "controller_execution.roles must name controller, worker, reviewer")
    supported_pairs = host_snapshot.get("supported_pairs") if isinstance(host_snapshot, dict) else None
    role_capabilities = host_snapshot.get("role_capabilities") if isinstance(host_snapshot, dict) else None
    for role_name in ("controller", "worker", "reviewer"):
        role = _mapping(roles[role_name], f"controller_execution.roles.{role_name}")
        allowed_role_fields = {"runtime_surface", "model", "reasoning_effort", "preference", "endpoint"}
        if not set(role).issubset(allowed_role_fields) or "runtime_surface" not in role or "model" not in role or "reasoning_effort" not in role:
            raise ProjectionError("invalid_packet", f"controller_execution.roles.{role_name} fields are incomplete")
        role["runtime_surface"] = _string(role["runtime_surface"], f"controller_execution.roles.{role_name}.runtime_surface")
        role["model"] = _string(role["model"], f"controller_execution.roles.{role_name}.model")
        role["reasoning_effort"] = _string(role["reasoning_effort"], f"controller_execution.roles.{role_name}.reasoning_effort")
        if "endpoint" in role:
            role["endpoint"] = _string(role["endpoint"], f"controller_execution.roles.{role_name}.endpoint")
        if "preference" in role:
            preference = _mapping(role["preference"], f"controller_execution.roles.{role_name}.preference")
            if set(preference) != {"selection_mode", "requested", "source", "lifetime"}:
                raise ProjectionError("invalid_packet", f"controller_execution.roles.{role_name}.preference fields are incomplete")
            _enum = preference.get("selection_mode")
            if _enum not in {"default", "prefer", "exact"}:
                raise ProjectionError("invalid_packet", f"controller_execution.roles.{role_name}.preference.selection_mode is unsupported")
            _mapping(preference.get("requested"), f"controller_execution.roles.{role_name}.preference.requested")
            _string(preference.get("source"), f"controller_execution.roles.{role_name}.preference.source")
            lifetime = preference.get("lifetime")
            if not isinstance(lifetime, dict) or set(lifetime) != {"selection_mode", "exact_model", "reasoning_effort"}:
                raise ProjectionError("invalid_packet", f"controller_execution.roles.{role_name}.preference.lifetime is invalid")
            for field in ("selection_mode", "exact_model", "reasoning_effort"):
                if not isinstance(lifetime[field], str):
                    raise ProjectionError("invalid_packet", f"controller_execution.roles.{role_name}.preference.lifetime.{field} is invalid")
        if role["runtime_surface"] == "codex_collaboration":
            available = supported_pairs
        else:
            available = None
            if isinstance(role_capabilities, dict):
                entries = role_capabilities.get(role_name)
                if isinstance(entries, list):
                    available = [
                        {"exact_model": item.get("model"), "reasoning_effort": item.get("reasoning_effort")}
                        for item in entries if isinstance(item, dict) and item.get("runtime_surface") == role["runtime_surface"]
                    ]
        if not _capability_supported(available, role["model"], role["reasoning_effort"]):
            raise ProjectionError(
                "controller_execution_capability_unavailable",
                f"{role_name}:{role['runtime_surface']}:{role['model']}:{role['reasoning_effort']}",
            )
    if effective_native_identity is not None:
        native_model = _string(effective_native_identity.get("exact_model"), "effective_native_identity.exact_model")
        native_effort = _string(effective_native_identity.get("reasoning_effort"), "effective_native_identity.reasoning_effort")
        controller = roles["controller"]
        if (
            controller["runtime_surface"] != "codex_collaboration"
            or controller["model"] != native_model
            or controller["reasoning_effort"] != native_effort
        ):
            raise ProjectionError(
                "controller_execution_route_mismatch",
                "controller role must match the effective native model and reasoning effort",
            )
    if package["repair_authority"] != "controller":
        raise ProjectionError("invalid_packet", "controller_execution.repair_authority must be controller")
    if package["final_acceptance_authority"] != "parent":
        raise ProjectionError("invalid_packet", "controller_execution.final_acceptance_authority must be parent")
    if package["reporting"] != "exceptions_and_final_only":
        raise ProjectionError("invalid_packet", "controller_execution.reporting must be exceptions_and_final_only")
    package["assignment_text"] = "\n".join((
        f"Objective: {scope['objective']}",
        f"Task ID: {scope['task_id']}",
        f"Allowed files: {json.dumps(scope['allowed_files'], ensure_ascii=False)}",
        f"Validation commands: {json.dumps(scope['validation'], ensure_ascii=False)}",
        f"Exclusions: {json.dumps(scope['exclusions'], ensure_ascii=False)}",
        "Roles: " + "; ".join(
            f"{name} runtime={roles[name]['runtime_surface']} model={roles[name]['model']} reasoning_effort={roles[name]['reasoning_effort']}"
            + (f" endpoint={roles[name]['endpoint']}" if "endpoint" in roles[name] else "")
            for name in ("controller", "worker", "reviewer")
        ),
        f"Repair authority: {package['repair_authority']}",
        f"Final acceptance authority: {package['final_acceptance_authority']}",
        "Reporting: exceptions_and_final_only",
        "Fresh independent reviewer required before Parent final acceptance.",
        "Scope is an instruction; actual enforcement depends on independently configured host permissions; the projection grants no sandbox.",
    ))
    return package


def _controller_package_for_identity(
    packet: dict[str, Any], host_snapshot: dict[str, Any] | None,
    model: Any, effort: Any,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Validate the package after route/request shapes and effective identity exist."""
    try:
        package = _validate_controller_execution(
            packet.get("controller_execution"), host_snapshot,
            child_task_id=packet["child_task_id"],
            effective_native_identity={"exact_model": model, "reasoning_effort": effort},
        )
        return package, None
    except ProjectionError as exc:
        if exc.code != "controller_execution_capability_unavailable":
            raise
        result = _resolution_need(packet=packet, reason=exc.code, model=str(model), effort=str(effort))
        result["resolution_preview"]["unavailable_role"] = exc.detail
        return None, result


def _exact_native_identity(model: Any, effort: Any, supported_pairs: list[dict[str, str]] | None = None) -> tuple[str, str]:
    model = _string(model, "selected_route.exact_model")
    effort = _string(effort, "selected_route.reasoning_effort")
    if supported_pairs is None:
        raise ProjectionError("native_capability_unverified", f"{model}:{effort}")
    if any(item["exact_model"] == model and item["reasoning_effort"] == effort for item in supported_pairs):
        return model, effort
    raise ProjectionError("native_model_unsupported", f"{model}:{effort}")


def _approval_preview(
    *, packet: dict[str, Any], reason: str, model: str, effort: str
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "approval_required",
        "reason": reason,
        "dispatch_performed": False,
        "provider_dispatch": False,
        "approval_preview": {
            "child_task_id": packet["child_task_id"],
            "semantic_role": packet["semantic_role"],
            "requested_native_agent_type": packet["native_request"]["agent_type"],
            "requested_fork_turns": packet["native_request"]["fork_turns"],
            "change": "use configurable default agent with an explicit native model binding",
            "native_agent_type": "default",
            "exact_model": model,
            "reasoning_effort": effort,
            "fork_turns": "none",
            "fallback": "forbidden",
            "route_authority": packet["route_authority"],
            "authority_required": "operator mapping-change approval",
        },
    }


def _resolution_need(
    *, packet: dict[str, Any], reason: str, model: str, effort: str
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "resolution_need",
        "reason": reason,
        "dispatch_performed": False,
        "provider_dispatch": False,
        "resolution_preview": {
            "child_task_id": packet["child_task_id"],
            "semantic_role": packet["semantic_role"],
            "requested_native_agent_type": packet["native_request"]["agent_type"],
            "requested_fork_turns": packet["native_request"]["fork_turns"],
            "exact_model": model,
            "reasoning_effort": effort,
            "route_authority": packet["route_authority"],
        },
    }


def _receipt(
    *, packet: dict[str, Any], agent_type: str, model: str, effort: str,
    selection_mode: str, fallback: str, approval_reference: str | None,
    effective_fork_turns: str,
) -> dict[str, Any]:
    parent_runtime = packet.get("parent_runtime")
    parent_identity = None
    if isinstance(parent_runtime, dict):
        parent_identity = {key: parent_runtime.get(key) for key in ("exact_model", "reasoning_effort")}
    receipt = {
        "ledger_schema_version": SCHEMA_VERSION,
        "child_task_id": packet["child_task_id"],
        "runtime_child_id": None,
        "runtime_child_id_status": "pending_spawn",
        "semantic_role": packet["semantic_role"],
        "requested_native_agent_type": packet["native_request"]["agent_type"],
        "native_agent_type": agent_type,
        "exact_model": model,
        "reasoning_effort": effort,
        "selection_mode": selection_mode,
        "requested_fork_turns": packet["native_request"]["fork_turns"],
        "effective_fork_turns": effective_fork_turns,
        "runtime_surface": "codex_collaboration",
        "fallback": fallback,
        "route_authority": packet["route_authority"],
        "route_id": packet["selected_route"]["route_id"],
        "special_route_required": packet["selected_route"]["special_route_required"],
        "route_rotation_policy": packet["selected_route"]["route_rotation_policy"],
        "provider_dispatch": False,
        "projection_status": "ready",
        "dispatch_status": "projected_not_dispatched",
        "approval_reference": approval_reference,
        "parent_runtime_identity": parent_identity,
        "config_receipt_sha256": packet.get("config_receipt_sha256"),
        "role_preference": packet.get("role_preference"),
    }
    if packet.get("controller_execution") is not None:
        receipt["controller_execution"] = copy.deepcopy(packet["controller_execution"])
        receipt["controller_spawn"] = {
            "role": "controller",
            "child_task_id": packet["child_task_id"],
            "runtime_child_id": None,
            "status": "pending_spawn",
        }
    return receipt


def project_codex_runtime(raw_packet: Any) -> dict[str, Any]:
    packet = dict(_mapping(raw_packet, "packet"))
    if packet.get("schema_version") != SCHEMA_VERSION:
        raise ProjectionError("unsupported_schema", str(packet.get("schema_version")))
    packet["child_task_id"] = _string(packet.get("child_task_id"), "child_task_id")
    packet["semantic_role"] = _string(packet.get("semantic_role"), "semantic_role")
    if packet["semantic_role"] not in SEMANTIC_ROLES:
        raise ProjectionError("semantic_role_unsupported", packet["semantic_role"])
    if packet.get("runtime_surface") != "codex_collaboration":
        raise ProjectionError("runtime_surface_mismatch", str(packet.get("runtime_surface")))
    packet["route_authority"] = _string(packet.get("route_authority"), "route_authority")
    host_snapshot = packet.get("host_snapshot")
    host_catalog_bound = host_snapshot is not None
    supported_pairs = None
    route = dict(_mapping(packet.get("selected_route"), "selected_route"))
    route["route_id"] = _string(route.get("route_id"), "selected_route.route_id")
    route["special_route_required"] = _bool(
        route.get("special_route_required"), "selected_route.special_route_required"
    )
    route["route_rotation_policy"] = _string(
        route.get("route_rotation_policy"),
        "selected_route.route_rotation_policy",
    )
    if route["route_rotation_policy"] not in ROUTE_ROTATION_POLICIES:
        raise ProjectionError(
            "route_rotation_policy_unsupported", route["route_rotation_policy"]
        )
    packet["selected_route"] = route
    request = dict(_mapping(packet.get("native_request"), "native_request"))
    requested_agent_type = _string(request.get("agent_type"), "native_request.agent_type")
    if requested_agent_type not in AGENT_TYPES:
        raise ProjectionError("native_agent_type_unsupported", requested_agent_type)
    fork_turns = _fork_turns(request.get("fork_turns"))
    request["agent_type"] = requested_agent_type
    request["fork_turns"] = fork_turns
    packet["native_request"] = request
    if host_catalog_bound:
        host_snapshot = _validate_host_snapshot(host_snapshot)
        supported_pairs = host_snapshot["supported_pairs"]
    approved = _bool(
        request.get("mapping_change_approved", False),
        "native_request.mapping_change_approved",
    )
    approval_reference = request.get("approval_reference")
    if approved:
        approval_reference = _string(approval_reference, "native_request.approval_reference")
        approved_authority = _string(
            request.get("approval_route_authority"),
            "native_request.approval_route_authority",
        )
        if approved_authority != packet["route_authority"]:
            raise ProjectionError(
                "approval_route_authority_mismatch", approved_authority
            )
    elif approval_reference is not None:
        raise ProjectionError("approval_reference_without_approval", str(approval_reference))
    elif request.get("approval_route_authority") is not None:
        raise ProjectionError(
            "approval_route_authority_without_approval",
            str(request.get("approval_route_authority")),
        )

    parent = dict(_mapping(packet.get("parent_runtime"), "parent_runtime"))
    parent_model = parent.get("exact_model")
    parent_effort = parent.get("reasoning_effort")
    expected_fallback = "forbidden" if route["special_route_required"] else "not_applicable"
    fallback = _string(route.get("fallback"), "selected_route.fallback")
    if fallback != expected_fallback:
        raise ProjectionError("fallback_not_authorized", fallback)

    if not route["special_route_required"]:
        if requested_agent_type != "default":
            raise ProjectionError("native_default_fixed_role_forbidden", requested_agent_type)
        if host_catalog_bound and (supported_pairs is None or not _capability_supported(supported_pairs, str(parent_model), str(parent_effort))):
            return _resolution_need(packet=packet, reason="parent_capability_unsupported", model=str(parent_model), effort=str(parent_effort))
        try:
            model, effort = _exact_native_identity(parent_model, parent_effort, supported_pairs)
        except ProjectionError:
            return _resolution_need(
                packet=packet, reason="native_identity_unresolved",
                model=str(parent_model), effort=str(parent_effort),
            )
        packet["controller_execution"], controller_result = _controller_package_for_identity(
            packet, host_snapshot if isinstance(host_snapshot, dict) else None, model, effort
        )
        if controller_result is not None:
            return controller_result
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "ready",
            "reason": "explicit_safe_native_default",
            "dispatch_performed": False,
            "provider_dispatch": False,
            "spawn_projection": {"agent_type": "default", "fork_turns": fork_turns},
            "dispatch_receipt": _receipt(
                packet=packet, agent_type="default", model=model, effort=effort,
                selection_mode="inherited", fallback=fallback,
                approval_reference=approval_reference,
                effective_fork_turns=fork_turns,
            ),
        }

    if host_catalog_bound and supported_pairs is None:
        return _resolution_need(packet=packet, reason="child_capability_unsupported", model=str(route.get("exact_model")), effort=str(route.get("reasoning_effort")))
    try:
        model, effort = _exact_native_identity(route.get("exact_model"), route.get("reasoning_effort"), supported_pairs)
    except ProjectionError:
        return _resolution_need(
            packet=packet, reason="native_identity_unresolved",
            model=str(route.get("exact_model")), effort=str(route.get("reasoning_effort")),
        )
    if host_catalog_bound and (supported_pairs is None or not _capability_supported(supported_pairs, model, effort)):
        return _resolution_need(packet=packet, reason="child_capability_unsupported", model=model, effort=effort)
    if requested_agent_type in FIXED_AGENT_TYPES:
        fixed = FIXED_AGENT_TYPES[requested_agent_type]
        fixed_matches = fixed["model"] == model and fixed["reasoning_effort"] == effort
        role_matches = packet["semantic_role"] in fixed["semantic_roles"]
        if not fixed_matches or not role_matches:
            reason = "fixed_role_model_conflict" if not fixed_matches else "fixed_role_semantic_conflict"
            return _resolution_need(packet=packet, reason=reason, model=model, effort=effort)
        else:
            packet["controller_execution"], controller_result = _controller_package_for_identity(
                packet, host_snapshot if isinstance(host_snapshot, dict) else None, model, effort
            )
            if controller_result is not None:
                return controller_result
            return {
                "schema_version": SCHEMA_VERSION,
                "status": "ready",
                "reason": "fixed_native_identity_matches_route",
                "dispatch_performed": False,
                "provider_dispatch": False,
                "spawn_projection": {
                    "agent_type": requested_agent_type,
                    "fork_turns": fork_turns,
                },
                "dispatch_receipt": _receipt(
                    packet=packet, agent_type=requested_agent_type, model=model,
                    effort=effort, selection_mode="fixed_native",
                    fallback=fallback, approval_reference=approval_reference,
                    effective_fork_turns=fork_turns,
                ),
            }

    if fork_turns == "all":
        if parent_model == model and parent_effort == effort:
            selection_mode = "inherited"
            spawn = {"agent_type": "default", "fork_turns": "all"}
        elif not approved:
            return _resolution_need(
                packet=packet, reason="default_inheritance_model_ambiguous",
                model=model, effort=effort,
            )
        else:
            selection_mode = "explicit"
            spawn = {
                "agent_type": "default", "fork_turns": "none",
                "model": model, "reasoning_effort": effort,
            }
    else:
        selection_mode = "explicit"
        spawn = {
            "agent_type": "default", "fork_turns": fork_turns,
            "model": model, "reasoning_effort": effort,
        }

    packet["controller_execution"], controller_result = _controller_package_for_identity(
        packet, host_snapshot if isinstance(host_snapshot, dict) else None, model, effort
    )
    if controller_result is not None:
        return controller_result
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "ready",
        "reason": "exact_native_route_projected",
        "dispatch_performed": False,
        "provider_dispatch": False,
        "spawn_projection": spawn,
        "dispatch_receipt": _receipt(
            packet=packet, agent_type="default", model=model, effort=effort,
            selection_mode=selection_mode, fallback=fallback,
            approval_reference=approval_reference,
            effective_fork_turns=spawn["fork_turns"],
        ),
    }


def record_spawn_result(raw_projection: Any, runtime_child_id: Any) -> dict[str, Any]:
    """Bind an actual collaboration child ID to one ready pre-spawn receipt."""

    projection = copy.deepcopy(_mapping(raw_projection, "projection"))
    if projection.get("status") != "ready":
        raise ProjectionError("projection_not_ready", str(projection.get("status")))
    if projection.get("dispatch_performed") is not False:
        raise ProjectionError("projection_already_dispatched", str(projection.get("dispatch_performed")))
    receipt = _mapping(projection.get("dispatch_receipt"), "dispatch_receipt")
    if receipt.get("projection_status") != "ready":
        raise ProjectionError("projection_receipt_not_ready", str(receipt.get("projection_status")))
    if receipt.get("runtime_child_id") is not None or receipt.get("runtime_child_id_status") != "pending_spawn":
        raise ProjectionError("runtime_child_id_already_recorded", str(receipt.get("runtime_child_id")))
    if receipt.get("provider_dispatch") is not False:
        raise ProjectionError("provider_dispatch_boundary_violated", str(receipt.get("provider_dispatch")))
    receipt["runtime_child_id"] = _string(runtime_child_id, "runtime_child_id")
    receipt["runtime_child_id_status"] = "recorded"
    receipt["dispatch_status"] = "spawned"
    if isinstance(receipt.get("controller_spawn"), dict):
        receipt["controller_spawn"]["runtime_child_id"] = receipt["runtime_child_id"]
        receipt["controller_spawn"]["status"] = "recorded"
    projection["dispatch_performed"] = True
    return projection


def record_spawn_failure(
    raw_projection: Any, runtime_child_id: Any, failure_code: Any
) -> dict[str, Any]:
    """Preserve one failed native attempt and request Orcastrata rerouting."""

    projection = copy.deepcopy(_mapping(raw_projection, "projection"))
    if projection.get("status") != "ready":
        raise ProjectionError("projection_not_ready", str(projection.get("status")))
    if projection.get("dispatch_performed") is not False:
        raise ProjectionError(
            "projection_already_dispatched", str(projection.get("dispatch_performed"))
        )
    receipt = _mapping(projection.get("dispatch_receipt"), "dispatch_receipt")
    if receipt.get("projection_status") != "ready":
        raise ProjectionError(
            "projection_receipt_not_ready", str(receipt.get("projection_status"))
        )
    if receipt.get("runtime_child_id") is not None or receipt.get("runtime_child_id_status") != "pending_spawn":
        raise ProjectionError(
            "runtime_child_id_already_recorded", str(receipt.get("runtime_child_id"))
        )
    if receipt.get("provider_dispatch") is not False:
        raise ProjectionError(
            "provider_dispatch_boundary_violated", str(receipt.get("provider_dispatch"))
        )
    failure_code = _string(failure_code, "failure_code")
    receipt["runtime_child_id"] = _string(runtime_child_id, "runtime_child_id")
    receipt["runtime_child_id_status"] = "recorded"
    receipt["dispatch_status"] = "failed"
    receipt["failure_code"] = failure_code
    receipt["failed_model"] = receipt["exact_model"]
    receipt["failed_route_id"] = receipt["route_id"]
    receipt["automatic_substitution"] = False
    if isinstance(receipt.get("controller_spawn"), dict):
        receipt["controller_spawn"]["runtime_child_id"] = receipt["runtime_child_id"]
        receipt["controller_spawn"]["status"] = "failed"
    projection["dispatch_performed"] = True
    if (
        failure_code in ROTATABLE_FAILURE_CODES
        and receipt["route_rotation_policy"] == "automatic_within_authority"
    ):
        projection["status"] = "rotation_required"
        receipt["rotation_status"] = "route_resolution_required"
        receipt["rotation_reason"] = "usage_capacity_failure"
    else:
        projection["status"] = "failed_no_rotation"
        receipt["rotation_status"] = "forbidden_or_not_applicable"
        receipt["rotation_reason"] = failure_code
    return projection


def _read_packet(path: str | None) -> Any:
    if path is None or path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", nargs="?", default="-", help="JSON packet path or - for stdin")
    parser.add_argument("--receipt", help="exclusive-create path for the projection JSON")
    parser.add_argument("--finalize", action="store_true", help="treat packet as a ready projection")
    parser.add_argument("--record-failure", action="store_true", help="record a failed native spawn")
    parser.add_argument("--runtime-child-id", help="canonical child ID returned by spawn_agent")
    parser.add_argument("--failure-code", help="normalized native failure code")
    parser.add_argument("--config-receipt", help="resolver JSON receipt consumed for role preference")
    args = parser.parse_args(argv)
    try:
        raw = _read_packet(args.packet)
        if args.config_receipt:
            packet = dict(_mapping(raw, "packet"))
            _validate_host_snapshot(packet.get("host_snapshot"))
            compiled, digest = _load_config_receipt(args.config_receipt, packet)
            if packet.get("controller_execution") is not None:
                raw = _compile_execution_preferences(packet, compiled, digest)
            else:
                raw = _compile_role_preference(packet, compiled, digest)
        if args.finalize and args.record_failure:
            raise ProjectionError("finalize_mode_conflict", "choose one finalization mode")
        if args.record_failure:
            result = record_spawn_failure(
                raw, args.runtime_child_id, args.failure_code
            )
        elif args.finalize:
            result = record_spawn_result(raw, args.runtime_child_id)
        else:
            if args.runtime_child_id is not None or args.failure_code is not None:
                raise ProjectionError(
                    "finalization_fields_without_mode",
                    str(args.runtime_child_id or args.failure_code),
                )
            result = project_codex_runtime(raw)
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.receipt:
            with Path(args.receipt).open("x", encoding="utf-8") as handle:
                handle.write(encoded)
        sys.stdout.write(encoded)
        return 0 if result["status"] in {"ready", "rotation_required"} else 3
    except (OSError, json.JSONDecodeError, ProjectionError) as error:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "status": "rejected",
            "error": getattr(error, "code", error.__class__.__name__),
            "detail": getattr(error, "detail", str(error)),
            "dispatch_performed": False,
            "provider_dispatch": False,
        }
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
