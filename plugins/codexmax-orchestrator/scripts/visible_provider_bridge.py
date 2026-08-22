#!/usr/bin/env python3
"""Compile a deterministic, non-executing visible-provider assignment request."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
QUALIFIED_ROUTES = {
    "worker_deepseek_v4_flash",
    "worker_deepseek_v4_pro",
    "worker_minimax_m3",
}
UNQUALIFIED_ROUTES = {
    "worker_claude_sonnet_5": "claude_route_not_qualified",
    "worker_grok_4_5": "grok_route_not_qualified",
}
ASSIGNMENT_FIELDS = {
    "schema_version", "assignment_id", "dispatch_id", "goal_id", "task_id",
    "semantic_role", "objective", "requested_route", "native_host",
    "visible_task", "standing_authority", "route_packet",
}
NATIVE_HOST_FIELDS = {"provider", "model", "reasoning", "role"}
VISIBLE_TASK_FIELDS = {
    "title", "host_kind", "presentation_exception_authorized",
    "host_action_requested", "host_action_performed", "request_provenance",
}
VISIBLE_PROVENANCE_FIELDS = {
    "request_id", "requested_by", "requested_at", "assignment_id",
    "dispatch_id", "semantic_role",
}
AUTHORITY_FIELDS = {
    "authority_id", "goal_id", "status", "billing_allowed",
    "external_write_access", "credential_action", "metered_fallback",
    "maximum_parallel_workers", "automatic_dispatch",
    "fresh_automatic_preflight", "duplicate_human_approval_inside_scope",
    "route", "authority_sha256",
}
AUTHORITY_ROUTE_FIELDS = {
    "route_name", "provider", "exact_model", "route_id", "runtime",
    "reasoning", "billing_basis", "quota_observability",
}


def _load_sibling(name: str) -> Any:
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(f"codexmax_visible_{name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RESOLVER = _load_sibling("resolve_worker_route")
RUNNER = _load_sibling("run_headless_provider_dispatch")


class BridgeError(ValueError):
    """A deterministic fail-closed bridge rejection."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _strict(value: Any, field: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise BridgeError("shape_invalid", field)
    return value


def _text(value: Any, field: str) -> str:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BridgeError("identity_invalid", field)
    return value


def _timestamp(value: Any, field: str) -> datetime:
    _text(value, field)
    if not value.endswith("Z"):
        raise BridgeError("timestamp_invalid", field)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BridgeError("timestamp_invalid", field) from exc
    if parsed.isoformat().endswith("+00:00") is False:
        raise BridgeError("timestamp_invalid", field)
    return parsed


def _validate_native_host(value: Any) -> dict[str, Any]:
    host = copy.deepcopy(_strict(value, "native_host", NATIVE_HOST_FIELDS))
    for field in NATIVE_HOST_FIELDS:
        _text(host[field], f"native_host.{field}")
    if host != {
        "provider": "OpenAI",
        "model": "gpt-5.3-codex-spark",
        "reasoning": "medium",
        "role": "visible_bridge_host",
    }:
        raise BridgeError("native_host_unqualified", "Spark medium is the frozen host")
    return host


def _validate_visible_task(
    value: Any, *, assignment_id: str, dispatch_id: str, semantic_role: str
) -> dict[str, Any]:
    visible = copy.deepcopy(_strict(value, "visible_task", VISIBLE_TASK_FIELDS))
    _text(visible["title"], "visible_task.title")
    if visible["host_kind"] != "codex_desktop_task":
        raise BridgeError("visible_host_kind_invalid")
    if visible["presentation_exception_authorized"] is not True:
        raise BridgeError("presentation_exception_not_authorized")
    if visible["host_action_requested"] is not True:
        raise BridgeError("host_action_not_requested")
    if visible["host_action_performed"] is not False:
        raise BridgeError("unproven_host_action")
    provenance = _strict(
        visible["request_provenance"],
        "visible_task.request_provenance",
        VISIBLE_PROVENANCE_FIELDS,
    )
    for field in VISIBLE_PROVENANCE_FIELDS - {"requested_at"}:
        _text(provenance[field], f"visible_task.request_provenance.{field}")
    _timestamp(provenance["requested_at"], "visible_task.request_provenance.requested_at")
    if provenance != {
        "request_id": provenance["request_id"],
        "requested_by": "Parent Codex",
        "requested_at": provenance["requested_at"],
        "assignment_id": assignment_id,
        "dispatch_id": dispatch_id,
        "semantic_role": semantic_role,
    }:
        raise BridgeError("visible_request_provenance_mismatch")
    return visible


def _configured_route(route_name: str) -> dict[str, Any]:
    routes = RESOLVER._config.DEFAULTS["route_registry"]["routes"]
    if route_name in UNQUALIFIED_ROUTES:
        raise BridgeError(UNQUALIFIED_ROUTES[route_name], route_name)
    if route_name not in QUALIFIED_ROUTES:
        raise BridgeError("route_not_locally_qualified", route_name)
    route = routes.get(route_name)
    if not isinstance(route, dict):
        raise BridgeError("route_registry_missing", route_name)
    return route


def _route_identity(route_name: str, route: dict[str, Any]) -> dict[str, Any]:
    return {
        "route_name": route_name,
        "provider": route["provider"],
        "exact_model": route["exact_model"],
        "route_id": route["route_id"],
        "runtime": route["runtime"],
        "reasoning": route["reasoning"],
        "billing_basis": route["billing_basis"],
        "quota_observability": route["quota_observability"],
    }


def _validate_authority(
    value: Any,
    trusted_record: Any,
    *,
    goal_id: str,
    expected_route: dict[str, Any],
) -> dict[str, Any]:
    authority = copy.deepcopy(_strict(value, "standing_authority", AUTHORITY_FIELDS))
    supplied_digest = authority["authority_sha256"]
    if not isinstance(supplied_digest, str) or SHA256.fullmatch(supplied_digest) is None:
        raise BridgeError("authority_digest_invalid")
    payload = {key: authority[key] for key in AUTHORITY_FIELDS - {"authority_sha256"}}
    if digest(payload) != supplied_digest:
        raise BridgeError("authority_digest_mismatch")
    if trusted_record is None:
        raise BridgeError("authority_unproven", "trusted authority record is required")
    try:
        trusted = copy.deepcopy(
            _strict(trusted_record, "trusted_authority_record", AUTHORITY_FIELDS)
        )
    except BridgeError as exc:
        raise BridgeError("authority_unproven", exc.detail) from exc
    trusted_digest = trusted.get("authority_sha256")
    trusted_payload = {
        key: trusted[key] for key in AUTHORITY_FIELDS - {"authority_sha256"}
    }
    if (
        not isinstance(trusted_digest, str)
        or SHA256.fullmatch(trusted_digest) is None
        or digest(trusted_payload) != trusted_digest
        or trusted_digest != supplied_digest
        or trusted != authority
    ):
        raise BridgeError("authority_unproven", "packet does not match trusted record")
    route = _strict(authority["route"], "standing_authority.route", AUTHORITY_ROUTE_FIELDS)
    expected = {
        "authority_id": authority["authority_id"],
        "goal_id": goal_id,
        "status": "approved",
        "billing_allowed": ["subscription"],
        "external_write_access": "none",
        "credential_action": "forbidden",
        "metered_fallback": "forbidden",
        "maximum_parallel_workers": 3,
        "automatic_dispatch": True,
        "fresh_automatic_preflight": "required",
        "duplicate_human_approval_inside_scope": "forbidden",
        "route": expected_route,
        "authority_sha256": supplied_digest,
    }
    _text(authority["authority_id"], "standing_authority.authority_id")
    if authority != expected or route != expected_route:
        raise BridgeError("authority_scope_mismatch")
    return authority


def _validate_resolution(
    packet: Any, *, task_id: str, requested_route: str, expected_route: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(packet, dict):
        raise BridgeError("route_packet_invalid")
    packet = copy.deepcopy(packet)
    if packet.get("task_id") != task_id:
        raise BridgeError("task_identity_mismatch", "route_packet.task_id")
    if packet.get("resolution_phase") != "pre_dispatch":
        raise BridgeError("fresh_preflight_required", "pre_dispatch phase required")
    if packet.get("allowed_billing") != ["subscription"]:
        raise BridgeError("billing_boundary_mismatch")
    if packet.get("attempt_results") != {}:
        raise BridgeError("prior_attempts_forbidden")
    controls = packet.get("controls")
    if not isinstance(controls, dict) or any(
        controls.get(field) != 1
        for field in (
            "max_attempts_per_checkpoint", "max_attempts_per_route",
            "circuit_breaker_threshold", "no_improvement_window",
        )
    ):
        raise BridgeError("single_attempt_controls_required")
    if packet.get("requirements", {}).get("write") is not False:
        raise BridgeError("external_write_forbidden")
    if set(packet.get("preflights", {})) != {requested_route}:
        raise BridgeError("exact_preflight_required", requested_route)
    preflight = packet["preflights"][requested_route]
    if not isinstance(preflight, dict):
        raise BridgeError("fresh_preflight_required")
    expected_preflight = {
        "provider": expected_route["provider"],
        "model": expected_route["exact_model"],
        "route": expected_route["route_id"],
        "runtime": expected_route["runtime"],
        "reasoning": expected_route["reasoning"],
        "billing": expected_route["billing_basis"],
    }
    if any(preflight.get(field) != value for field, value in expected_preflight.items()):
        raise BridgeError("preflight_identity_mismatch")
    if (
        preflight.get("fresh") is not True
        or preflight.get("authentication") not in {"verified", "not_required"}
        or preflight.get("quota") not in {"available", "unknown"}
        or preflight.get("credential_access_required") is not False
        or preflight.get("write_access") != "none"
    ):
        raise BridgeError("preflight_not_qualified")
    if preflight.get("quota") == "unknown" and not (
        requested_route == "worker_deepseek_v4_flash"
        and expected_route["quota_observability"] == "unsupported"
    ):
        raise BridgeError("quota_unknown_not_qualified")
    resolution_time = _timestamp(packet.get("resolution_time"), "route_packet.resolution_time")
    observed_at = _timestamp(preflight.get("observed_at"), "preflight.observed_at")
    expires_at = _timestamp(preflight.get("expires_at"), "preflight.expires_at")
    if preflight.get("task_id") != task_id:
        raise BridgeError("task_identity_mismatch", "preflight.task_id")
    if observed_at > resolution_time or resolution_time >= expires_at:
        raise BridgeError("preflight_not_current")
    try:
        receipt = RESOLVER.resolve_worker_route(packet)
    except Exception as exc:
        raise BridgeError("resolver_rejected", str(exc)) from exc
    next_attempt = receipt.get("next_attempt")
    if (
        receipt.get("status") != "dispatch_required"
        or receipt.get("external_call_performed") is not False
        or receipt.get("failover_used") is not False
        or receipt.get("attempts") != []
        or not isinstance(next_attempt, dict)
        or next_attempt.get("route_name") != requested_route
    ):
        raise BridgeError("resolver_did_not_bind_exact_route")
    identity = next_attempt.get("identity")
    if not isinstance(identity, dict):
        raise BridgeError("resolver_identity_missing")
    if any(
        identity.get(field) != expected_route[target]
        for field, target in {
            "provider": "provider", "model": "exact_model", "route": "route_id",
            "runtime": "runtime", "reasoning": "reasoning", "billing": "billing_basis",
        }.items()
    ):
        raise BridgeError("resolver_identity_mismatch")
    try:
        adapter = RUNNER._adapter_id(requested_route, identity)
    except Exception as exc:
        raise BridgeError("provider_adapter_unavailable", str(exc)) from exc
    return receipt, {"adapter_id": adapter, "identity": copy.deepcopy(identity)}


def compile_visible_provider_assignment(
    value: Any, trusted_authority_record: Any = None
) -> dict[str, Any]:
    """Validate one assignment and compile a non-executing host request."""

    assignment = copy.deepcopy(_strict(value, "assignment", ASSIGNMENT_FIELDS))
    if assignment["schema_version"] != SCHEMA_VERSION:
        raise BridgeError("unsupported_schema", str(assignment["schema_version"]))
    for field in (
        "assignment_id", "dispatch_id", "goal_id", "task_id", "semantic_role",
        "objective", "requested_route",
    ):
        _text(assignment[field], field)
    if assignment["semantic_role"] not in {
        "planner", "architect", "worker", "tester", "documenter", "auditor"
    }:
        raise BridgeError("semantic_role_invalid")

    route = _configured_route(assignment["requested_route"])
    exact_route = _route_identity(assignment["requested_route"], route)
    authority = _validate_authority(
        assignment["standing_authority"],
        trusted_authority_record,
        goal_id=assignment["goal_id"],
        expected_route=exact_route,
    )
    native_host = _validate_native_host(assignment["native_host"])
    visible_task = _validate_visible_task(
        assignment["visible_task"],
        assignment_id=assignment["assignment_id"],
        dispatch_id=assignment["dispatch_id"],
        semantic_role=assignment["semantic_role"],
    )
    resolver_receipt, adapter = _validate_resolution(
        assignment["route_packet"],
        task_id=assignment["task_id"],
        requested_route=assignment["requested_route"],
        expected_route=exact_route,
    )

    state = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "VisibleProviderTaskState",
        "status": "ready_for_visible_host_action",
        "lifecycle_phase": "preflight_passed",
        "assignment_identity": {
            "goal_id": assignment["goal_id"],
            "task_id": assignment["task_id"],
            "assignment_id": assignment["assignment_id"],
            "dispatch_id": assignment["dispatch_id"],
            "semantic_role": assignment["semantic_role"],
        },
        "native_host": {
            **native_host,
            "host_task_id": None,
            "host_action_performed": False,
        },
        "visible_task_request": visible_task,
        "external_execution": {
            **exact_route,
            "adapter_id": adapter["adapter_id"],
            "execution_id": None,
            "provider_call_started": False,
            "external_write_access": "none",
        },
        "standing_authority": {
            "authority_id": authority["authority_id"],
            "authority_sha256": authority["authority_sha256"],
            "trusted_authority_sha256": authority["authority_sha256"],
            "human_approval_required": False,
            "fresh_automatic_preflight_verified": True,
            "quota_observability": exact_route["quota_observability"],
        },
        "dispatch_binding": {
            "route_packet_sha256": digest(assignment["route_packet"]),
            "resolver_receipt_sha256": digest(resolver_receipt),
            "resolver_receipt": resolver_receipt,
            "attempt_limit": 1,
            "retry_allowed": False,
            "fallback_allowed": False,
            "hedging_allowed": False,
            "required_existing_chain": [
                "DispatchTaskEnvelope", "DispatchSchedulePlan",
                "DispatchExecutionBinding", "DispatchReturnManifest",
                "ArtifactQualityReceipt", "DispatchScheduleManifest",
            ],
        },
        "usage": {
            "tokens": {"value": "unknown", "reason": "provider_not_started"},
            "quota": {"value": "unknown", "reason": "provider_not_started"},
            "cost": {"value": "unknown", "reason": "provider_not_started"},
            "wall_time_ms": {"value": "unknown", "reason": "provider_not_started"},
        },
        "quality": {
            "transport_succeeded": False,
            "deterministic_quality_accepted": False,
            "sol_decision": "pending",
        },
        "mutations": {
            "source_mutated": False,
            "goalbuddy_mutated": False,
            "supervisor_mutated": False,
        },
    }
    state["state_sha256"] = digest(state)
    return state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assignment", type=Path, required=True)
    parser.add_argument("--trusted-authority", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        assignment = json.loads(args.assignment.read_text(encoding="utf-8"))
        trusted_authority = json.loads(
            args.trusted_authority.read_text(encoding="utf-8")
        )
        result = compile_visible_provider_assignment(assignment, trusted_authority)
    except (OSError, json.JSONDecodeError, BridgeError) as exc:
        if isinstance(exc, BridgeError):
            error = {"status": "rejected", "code": exc.code, "detail": exc.detail}
        else:
            error = {"status": "rejected", "code": type(exc).__name__, "detail": str(exc)}
        print(json.dumps(error, indent=2, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
