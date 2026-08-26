#!/usr/bin/env python3
"""Project an Orcastrata route into a fail-closed Codex collaboration spawn.

This module never calls ``spawn_agent`` or an external provider. The caller
persists an accepted receipt before dispatch and records the canonical child ID
returned by the collaboration runtime.
"""

from __future__ import annotations

import argparse
import copy
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


def _exact_native_identity(model: Any, effort: Any) -> tuple[str, str]:
    model = _string(model, "selected_route.exact_model")
    effort = _string(effort, "selected_route.reasoning_effort")
    if model not in SUPPORTED_MODELS:
        raise ProjectionError("native_model_unsupported", model)
    if effort not in SUPPORTED_MODELS[model]:
        raise ProjectionError("native_reasoning_unresolved", f"{model}:{effort}")
    return model, effort


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


def _receipt(
    *, packet: dict[str, Any], agent_type: str, model: str, effort: str,
    selection_mode: str, fallback: str, approval_reference: str | None,
    effective_fork_turns: str,
) -> dict[str, Any]:
    return {
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
    }


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
        model, effort = _exact_native_identity(parent_model, parent_effort)
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

    model, effort = _exact_native_identity(route.get("exact_model"), route.get("reasoning_effort"))
    if requested_agent_type in FIXED_AGENT_TYPES:
        fixed = FIXED_AGENT_TYPES[requested_agent_type]
        fixed_matches = fixed["model"] == model and fixed["reasoning_effort"] == effort
        role_matches = packet["semantic_role"] in fixed["semantic_roles"]
        if not fixed_matches or not role_matches:
            reason = "fixed_role_model_conflict" if not fixed_matches else "fixed_role_semantic_conflict"
            if not approved:
                return _approval_preview(packet=packet, reason=reason, model=model, effort=effort)
            requested_agent_type = "default"
            fork_turns = "none"
        else:
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
            return _approval_preview(
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
    args = parser.parse_args(argv)
    try:
        raw = _read_packet(args.packet)
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
