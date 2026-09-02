#!/usr/bin/env python3
"""Deterministic, fail-closed Worker route resolution and failover simulation.

This module never calls a provider. It consumes fresh preflight facts and
recorded attempt outcomes, then emits a complete route-resolution receipt.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True


SCRIPT_PATH = Path(__file__).resolve()
PLUGIN_ROOT = SCRIPT_PATH.parents[1]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _adapter_evidence(
    route_name: str, route: dict[str, Any],
    explicit_selection: dict[str, Any] | None = None,
) -> dict[str, str]:
    path = PLUGIN_ROOT / "scripts" / "run_headless_provider_dispatch.py"
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ResolutionError("adapter_evidence_unreadable", path.name) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ResolutionError("adapter_evidence_unsafe", path.name)
    dispatcher = _load_module("codexmax_resolver_dispatcher", path)
    identity = {
        "provider": route["provider"], "model": route["exact_model"],
        "route": route["route_id"], "runtime": route["runtime"],
        "reasoning": route["reasoning"], "billing": route["billing_basis"],
    }
    try:
        adapter_id = dispatcher._adapter_id(route_name, identity)
        source_bytes = path.read_bytes()
    except Exception as error:
        raise ResolutionError("adapter_identity_unresolved", route_name) from error
    adapter_sha256 = "sha256:" + hashlib.sha256(source_bytes).hexdigest()
    if explicit_selection is not None:
        card = _config.ADAPTER_REGISTRY.APPROVED_ADAPTER_CARDS.get(adapter_id)
        if (
            explicit_selection.get("adapter_type") != adapter_id
            or not isinstance(card, dict)
            or explicit_selection.get("adapter_sha256") != card.get("adapter_sha256")
        ):
            raise ResolutionError("explicit_selection_adapter_mismatch", route_name)
        adapter_sha256 = explicit_selection["adapter_sha256"]
    return {
        "route_name": route_name,
        "adapter_id": adapter_id,
        "adapter_sha256": adapter_sha256,
    }


_config = _load_module(
    "codexmax_resolve_config_for_route_runtime",
    PLUGIN_ROOT / "scripts" / "resolve_codexmax_config.py",
)
_provider_input_validator = _load_module(
    "codexmax_provider_input_validator_for_route_runtime",
    PLUGIN_ROOT / "scripts" / "provider_input_compatibility.py",
)
_explicit_tool_model = _load_module(
    "codexmax_explicit_tool_model_for_route_runtime",
    PLUGIN_ROOT / "scripts" / "verify_configured_tool_session.py",
)


SCHEMA_VERSION = 1
PACKET_SCHEMA_VERSION = 2
RESOLUTION_PHASES = {"evidence", "pre_dispatch"}
EXPLICIT_ESCALATION_REASONS = {
    "material_architecture_risk",
    "repeated_failure_redesign",
    "final_completion_audit",
}
SAFE_BILLING = {"native_included", "subscription", "local_compute"}
SUCCESS_OUTCOMES = {"success"}
RETRYABLE_OUTCOMES = {
    "model_start_failure",
    "rate_limit",
    "quota_exhausted",
    "validation_failure",
    "weak_output",
    "stale_context",
    "no_improvement",
    "provider_failure",
}
HARD_STOP_OUTCOMES = {
    "authority_violation",
    "billing_violation",
    "credential_prompt",
    "scope_violation",
    "source_access_violation",
}
ALL_OUTCOMES = SUCCESS_OUTCOMES | RETRYABLE_OUTCOMES | HARD_STOP_OUTCOMES
CONSEQUENCE_RANK = {"low": 0, "medium": 1, "high": 2, "highest": 3}

PREFLIGHT_REQUIRED_FIELDS = {
    "preflight_id",
    "task_id",
    "fresh",
    "observed_at",
    "expires_at",
    "provider",
    "model",
    "route",
    "runtime",
    "reasoning",
    "billing",
    "token_limit",
    "availability",
    "health",
    "authentication",
    "identity_status",
    "capability_status",
    "identity_evidence",
    "capability_evidence",
    "quota",
    "credential_access_required",
    "source_access",
    "input_delivery",
    "commands_executable",
    "local_file_access",
    "browser_access",
    "web_search_access",
    "connector_access",
    "network_access",
    "citation_support",
    "write_access",
    "read_scope",
    "write_scope",
    "authority_scope",
    "consequence_floor",
    "independence_group",
}


class ResolutionError(ValueError):
    """Raised for malformed or unsupported deterministic input."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _unknown_accounting(reason: str = "not_reported_by_fixture") -> dict[str, str]:
    return {"value": "unknown", "reason": reason}


def _normalize_accounting(value: Any, reason: str) -> Any:
    if value is None:
        return _unknown_accounting(reason)
    return copy.deepcopy(value)


def _require_mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ResolutionError("invalid_packet", f"{field} must be an object")
    return value


def _require_nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ResolutionError("invalid_packet", f"{field} must be a non-empty string")
    return value.strip()


def _parse_utc_timestamp(value: Any, field: str) -> dt.datetime:
    text = _require_nonempty_string(value, field)
    if not text.endswith("Z"):
        raise ResolutionError("invalid_packet", f"{field} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ResolutionError("invalid_packet", f"{field} must be an ISO-8601 UTC timestamp") from exc
    if parsed.utcoffset() != dt.timedelta(0):
        raise ResolutionError("invalid_packet", f"{field} must be UTC")
    return parsed


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ResolutionError("invalid_packet", f"{field} must be an array of non-empty strings")
    if len(value) != len(set(value)):
        raise ResolutionError("invalid_packet", f"{field} must not contain duplicates")
    return sorted(value)


def _effective_registry(packet: dict[str, Any]) -> dict[str, Any]:
    registry = packet.get("registry")
    if registry is None:
        return copy.deepcopy(_config.DEFAULTS["route_registry"])
    registry = copy.deepcopy(_require_mapping(registry, "registry"))
    # Route-registry v1 gained one additive fallback slot. Preserve explicit
    # full registries produced by the earlier five-slot implementation by
    # normalizing only the absent trailing slot to the fail-closed `none`.
    profiles = registry.get("task_profiles")
    if isinstance(profiles, dict):
        for profile in profiles.values():
            if isinstance(profile, dict) and profile.get("profile_schema_version") == 1:
                profile["profile_schema_version"] = _config.TASK_PROFILE_SCHEMA_VERSION
                profile.setdefault("secondary_05", "none")
    routes = registry.get("routes")
    if isinstance(routes, dict):
        for route in routes.values():
            if isinstance(route, dict):
                route.setdefault("quota_observability", "unknown")
                route.setdefault("escalation_policy", "ordinary")
    try:
        _config.validate_route_registry(registry, partial=False)
    except _config.ConfigError as exc:
        raise ResolutionError("invalid_registry", str(exc)) from exc
    return copy.deepcopy(registry)


def _ordered_profile_routes(registry: dict[str, Any], profile_name: str) -> list[str]:
    profile = registry["task_profiles"].get(profile_name)
    if profile is None:
        raise ResolutionError("unknown_profile", profile_name)
    secondaries = [profile[f"secondary_{index:02d}"] for index in range(1, 6)]
    return [profile["primary_route"], *(route for route in secondaries if route != "none")]


def resolve_capability_candidates(
    effective_config: dict[str, Any], *, lane_name: str,
    currently_qualified_routes: list[str],
) -> dict[str, Any]:
    """Apply user order/subset to exact compatible evidence without granting eligibility."""
    try:
        _config.validate_config(effective_config, partial=False)
    except _config.ConfigError as exc:
        raise ResolutionError("invalid_registry", str(exc)) from exc
    if lane_name not in _config.LANE_NAMES:
        raise ResolutionError("unknown_lane_profile", lane_name)
    qualified = _string_list(currently_qualified_routes, "currently_qualified_routes")
    compatible = set(_config._lane_candidate_defaults(lane_name))
    external = sorted(set(qualified) - compatible)
    if external:
        raise ResolutionError("qualification_route_incompatible", external[0])
    lane = effective_config["capability_preferences"]["lanes"][lane_name]
    ordered = [lane[field] for field in _config.ROLE_ROUTE_FIELDS if lane[field] != "none"]
    candidates = [route for route in ordered if route in qualified]
    return {
        "schema_version": 1,
        "lane_profile": lane_name,
        "required_primitives": copy.deepcopy(
            _config.ADAPTER_REGISTRY.LANE_PROFILES[lane_name]["required_primitives"]
        ),
        "ordered_candidates": candidates,
        "user_concurrency_limit": lane["user_concurrency_limit"],
        "qualification_required": True,
        "eligibility_granted": False,
        "authority_granted": False,
        "provider_called": False,
        "execution_started": False,
        "acceptance_granted": False,
    }


def _profile_requirement_floor(profile: dict[str, Any]) -> dict[str, Any]:
    required_source = profile["required_source_access"]
    return {
        "required_source_access": required_source,
        "commands": profile["commands_required"],
        "local_files": required_source == "local_filesystem",
        "write": profile["write_required"],
        "browser": profile["browser_required"],
        "web_search": profile["web_search_required"],
        "connector": profile["connector_required"],
        "billing_ceiling": profile["billing_ceiling"],
        "consequence_floor": profile["consequence_floor"],
        "independence_required": profile["independence_required"],
    }


def _bind_profile_requirements(
    packet: dict[str, Any], registry: dict[str, Any], profile_name: str
) -> dict[str, Any]:
    profile = registry["task_profiles"].get(profile_name)
    if profile is None:
        raise ResolutionError("unknown_profile", profile_name)
    floor = _profile_requirement_floor(profile)
    errors: list[str] = []

    required_access = packet["provider_input"].get("required_source_access")
    if not isinstance(required_access, list) or floor["required_source_access"] not in required_access:
        errors.append("required_source_access")
    if packet["provider_input"].get("source_backed_claims_required") is not True:
        errors.append("source_backed_claims_required")

    for field in ("commands", "local_files", "write", "browser", "web_search", "connector"):
        if floor[field] and not packet["requirements"][field]:
            errors.append(field)
    if packet["provider_input"].get("commands_required") is not packet["requirements"]["commands"]:
        errors.append("commands_provider_input_mismatch")

    if floor["billing_ceiling"] != "non_metered":
        errors.append("unsupported_profile_billing_ceiling")
    if not packet["allowed_billing"]:
        errors.append("allowed_billing_empty")
    if not set(packet["allowed_billing"]).issubset(SAFE_BILLING):
        errors.append("billing_ceiling")

    if CONSEQUENCE_RANK[packet["consequence_floor"]] < CONSEQUENCE_RANK[floor["consequence_floor"]]:
        errors.append("consequence_floor")

    effective_independence = floor["independence_required"] or packet["role"] in {"tester", "auditor"}
    if effective_independence and not packet["independence_required"]:
        errors.append("independence_required")
    if packet["independence_required"] and not packet["independence_exclusions"]:
        errors.append("independence_exclusions_empty")

    if errors:
        raise ResolutionError(
            "profile_requirement_weakened",
            f"{profile_name}:" + ",".join(sorted(set(errors))),
        )
    return floor


def _identity_snapshot(
    route_name: str, route: dict[str, Any], preflight: dict[str, Any],
    adapter_evidence: dict[str, str] | None = None,
) -> dict[str, Any]:
    identity = {
        "route_name": route_name,
        "provider": preflight["provider"],
        "model": preflight["model"],
        "route": preflight["route"],
        "runtime": preflight["runtime"],
        "reasoning": preflight["reasoning"],
        "billing": preflight["billing"],
        "quota_observability": route["quota_observability"],
        "token_limit": preflight["token_limit"],
        "source_access": preflight["source_access"],
        "input_delivery": preflight["input_delivery"],
        "commands_executable": preflight["commands_executable"],
        "local_file_access": preflight["local_file_access"],
        "browser_access": preflight["browser_access"],
        "web_search_access": preflight["web_search_access"],
        "connector_access": preflight["connector_access"],
        "network_access": preflight["network_access"],
        "citation_support": preflight["citation_support"],
        "write_access": preflight["write_access"],
        "read_scope": sorted(preflight["read_scope"]),
        "write_scope": sorted(preflight["write_scope"]),
        "authority_scope": sorted(preflight["authority_scope"]),
        "consequence_floor": preflight["consequence_floor"],
        "independence_group": preflight["independence_group"],
        "preflight_id": preflight["preflight_id"],
        "observed_at": preflight["observed_at"],
        "expires_at": preflight["expires_at"],
    }
    if adapter_evidence is not None:
        identity["adapter_id"] = adapter_evidence["adapter_id"]
        identity["adapter_sha256"] = adapter_evidence["adapter_sha256"]
    return identity


def _identity_mismatch_reasons(route: dict[str, Any], preflight: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    field_map = {
        "provider": "provider",
        "model": "exact_model",
        "route": "route_id",
        "runtime": "runtime",
        "reasoning": "reasoning",
        "billing": "billing_basis",
    }
    for preflight_field, route_field in field_map.items():
        expected = route[route_field]
        actual = preflight[preflight_field]
        if route_field == "reasoning" and expected == "task_selected":
            allowed = _config.NATIVE_REASONING_EFFORTS.get(route["exact_model"], ())
            if actual not in allowed:
                reasons.append("identity_mismatch:reasoning")
        elif expected not in (None, "unknown") and expected != actual:
            reasons.append(f"identity_mismatch:{preflight_field}")
    return reasons


def _escalation_authorized(
    packet: dict[str, Any], route_name: str, route: dict[str, Any]
) -> bool:
    if route.get("escalation_policy", "ordinary") != "explicit_only":
        return True
    selection = packet.get("explicit_selection")
    if isinstance(selection, dict) and selection.get("route_name") == route_name:
        return True
    if route.get("route_kind") == "worker":
        return False
    return (
        packet.get("escalation_reason") in EXPLICIT_ESCALATION_REASONS
        and isinstance(packet.get("task_grant_sha256"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", packet["task_grant_sha256"]) is not None
    )


def _route_capability_decision(
    packet: dict[str, Any], route_name: str, route: dict[str, Any],
    preflight: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate one route against provider-neutral Parent rank ceilings."""
    policy = _config.CAPABILITY_MODEL_DEFAULTS["reasoning"]["route_capability_policy"]
    row = policy["routes"].get(route_name)
    reasons: list[str] = []
    if not isinstance(row, dict):
        return {"authorized": False, "reasons": ["route_capability_policy_missing"]}
    fingerprint = _config.route_identity_fingerprint(route)
    base_route = _config.ROUTE_DEFAULTS.get(route_name)
    selection = packet.get("explicit_selection")
    transport_fields = {
        "route_kind", "provider", "route_id", "runtime", "reasoning",
        "billing_basis", "availability", "health", "authentication",
        "identity_status", "capability_status", "quota_observability",
        "source_access", "input_delivery",
        "commands_executable", "local_file_access", "browser_access",
        "web_search_access", "connector_access", "write_access",
        "recommended_role", "consequence_floor", "independence_group",
        "identity_evidence", "capability_evidence", "escalation_policy",
    }
    selection_matches = isinstance(selection, dict) and all((
        selection.get("route_name") == route_name,
        selection.get("requested_model") == route.get("exact_model"),
        selection.get("provider") == route.get("provider"),
        selection.get("route_id") == route.get("route_id"),
        selection.get("runtime") == route.get("runtime"),
        selection.get("billing_basis") == route.get("billing_basis"),
    ))
    transport_matches = isinstance(base_route, dict) and all(
        route.get(field) == base_route.get(field) for field in transport_fields
    )
    package_row_matches = (
        isinstance(base_route, dict)
        and row.get("route_fingerprint") == _config.route_identity_fingerprint(base_route)
    )
    explicit_generic_identity = bool(
        selection_matches and transport_matches and package_row_matches
        and base_route.get("exact_model") == "unknown"
        and route.get("exact_model") not in {"unknown", "unverified", ""}
    )
    if row["route_fingerprint"] != fingerprint:
        if not (selection_matches and transport_matches and package_row_matches):
            reasons.append("route_capability_fingerprint_mismatch")
    if row["identity_binding"] != "complete" and not explicit_generic_identity:
        reasons.append("route_capability_identity_incomplete")

    effort_rank = row["effort_rank"]
    if row["effort_mode"] == "native_preflight":
        effort_rank = _config.REASONING_RANK.get(preflight.get("reasoning"))
        if effort_rank is None:
            reasons.append("route_capability_effort_unknown")
    parent = packet["parent_capability"]
    escalation_required = (
        row["cost_rank"] > parent["cost_ceiling"]
        or effort_rank is None
        or effort_rank > parent["effort_ceiling"]
    )
    approval = packet.get("capability_escalation")
    approval_digest = None
    escalation_approved = False
    if isinstance(approval, dict):
        approval_digest = "sha256:" + hashlib.sha256(
            json.dumps(approval, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        escalation_approved = bool(
            approval["route_name"] == route_name
            and approval["route_fingerprint"] == fingerprint
            and approval["cost_rank"] == row["cost_rank"]
            and approval["effort_rank"] == effort_rank
            and approval["task_grant_sha256"] == packet.get("task_grant_sha256")
            and approval["operator_approved"] is True
            and approval["prework_status"] == "attempted_exhausted"
            and approval["approval_reference"].strip()
            and bool(approval["prework_evidence"])
        )
    if escalation_required and not escalation_approved:
        reasons.append("capability_escalation_approval_required")
    return {
        "schema_version": 2,
        "route_name": route_name,
        "route_fingerprint": fingerprint,
        "cost_rank": row["cost_rank"],
        "effort_rank": effort_rank,
        "parent_cost_ceiling": parent["cost_ceiling"],
        "parent_effort_ceiling": parent["effort_ceiling"],
        "escalation_required": escalation_required,
        "escalation_approved": escalation_approved,
        "approval_digest": approval_digest,
        "task_grant_sha256": packet.get("task_grant_sha256"),
        "authorized": not reasons,
        "reasons": reasons,
    }


def _provider_input_reasons(provider_input: dict[str, Any], preflight: dict[str, Any]) -> list[str]:
    bound = copy.deepcopy(provider_input)
    bound["source_access"] = preflight["source_access"]
    bound["input_delivery"] = preflight["input_delivery"]
    bound["commands_executable"] = preflight["commands_executable"]
    errors = _provider_input_validator.provider_input_compatibility_gate_errors(
        bound,
        require_declared_gate=True,
    )
    return [f"provider_input:{error}" for error in errors]


def _eligibility_reasons(
    packet: dict[str, Any],
    route_name: str,
    route: dict[str, Any],
    preflight: Any,
) -> tuple[list[str], dict[str, Any] | None]:
    reasons: list[str] = []
    escalation_authorized = _escalation_authorized(packet, route_name, route)
    if route["route_kind"] != "worker":
        reasons.append("control_route_not_worker_eligible")
    if not isinstance(preflight, dict):
        return reasons + ["fresh_preflight_missing"], None

    missing = sorted(PREFLIGHT_REQUIRED_FIELDS - set(preflight))
    if missing:
        return reasons + [f"preflight_missing:{field}" for field in missing], preflight

    capability = _route_capability_decision(packet, route_name, route, preflight)
    reasons.extend(capability["reasons"])
    if route.get("escalation_policy", "ordinary") == "explicit_only" and not (
        escalation_authorized or capability["escalation_approved"]
    ):
        reasons.append("explicit_escalation_required")
    if not route["enabled"] and not (
        escalation_authorized or capability["escalation_approved"]
    ):
        reasons.append("route_disabled")

    reasons.extend(_identity_mismatch_reasons(route, preflight))
    if preflight["task_id"] != packet["task_id"]:
        reasons.append("preflight_task_mismatch")
    if preflight["fresh"] is not True:
        reasons.append("preflight_not_fresh")
    try:
        observed_at = _parse_utc_timestamp(preflight["observed_at"], "preflight.observed_at")
        expires_at = _parse_utc_timestamp(preflight["expires_at"], "preflight.expires_at")
        resolution_time = _parse_utc_timestamp(packet["resolution_time"], "resolution_time")
        if observed_at > resolution_time:
            reasons.append("preflight_observed_after_resolution")
        if expires_at < resolution_time:
            reasons.append("preflight_expired")
        if expires_at < observed_at:
            reasons.append("preflight_window_invalid")
    except ResolutionError:
        reasons.append("preflight_timestamp_invalid")
    if preflight["availability"] != "available":
        reasons.append("route_not_available")
    if preflight["health"] != "healthy":
        reasons.append("route_not_healthy")
    if preflight["authentication"] not in {"verified", "not_required"}:
        reasons.append("authentication_not_verified")
    if preflight["identity_status"] != "known_exact":
        reasons.append("preflight_identity_not_known_exact")
    if preflight["capability_status"] != "verified":
        reasons.append("preflight_capability_not_verified")
    if not isinstance(preflight["identity_evidence"], str) or not preflight["identity_evidence"]:
        reasons.append("identity_evidence_missing")
    if not isinstance(preflight["capability_evidence"], str) or not preflight["capability_evidence"]:
        reasons.append("capability_evidence_missing")
    unknown_quota_exception = (
        preflight["quota"] == "unknown"
        and route_name == "worker_deepseek_v4_flash"
        and route["quota_observability"] == "unsupported"
        and route["provider"] == "Command Code"
        and route["exact_model"] == "deepseek/deepseek-v4-flash"
        and route["route_id"] == "commandcode-subscription-deepseek-v4-flash"
        and route["runtime"] == "Command Code"
        and route["billing_basis"] == "subscription"
        and preflight["provider"] == route["provider"]
        and preflight["model"] == route["exact_model"]
        and preflight["route"] == route["route_id"]
        and preflight["runtime"] == route["runtime"]
        and preflight["billing"] == "subscription"
        and packet["allowed_billing"] == ["subscription"]
        and packet["resolution_phase"] == "pre_dispatch"
        and all(
            packet["controls"][field] == 1
            for field in (
                "max_attempts_per_checkpoint", "max_attempts_per_route",
                "circuit_breaker_threshold", "no_improvement_window",
            )
        )
    )
    task_scoped_unknown_quota = (
        preflight["quota"] == "unknown"
        and packet.get("profile") == "task_scoped_read_only"
        and isinstance(packet.get("explicit_selection"), dict)
        and packet["explicit_selection"].get("route_name") == route_name
        and route["billing_basis"] == "subscription"
        and preflight["billing"] == "subscription"
        and packet["allowed_billing"] == ["subscription"]
        and packet["resolution_phase"] == "pre_dispatch"
        and all(
            packet["controls"][field] == 1
            for field in (
                "max_attempts_per_checkpoint", "max_attempts_per_route",
                "circuit_breaker_threshold", "no_improvement_window",
            )
        )
    )
    if preflight["quota"] != "available" and not (
        unknown_quota_exception or task_scoped_unknown_quota
    ):
        reasons.append("quota_not_available")
    if preflight["credential_access_required"] is not False:
        reasons.append("credential_access_required")
    if preflight["billing"] not in SAFE_BILLING:
        reasons.append("metered_or_unknown_billing")
    if preflight["billing"] not in packet["allowed_billing"]:
        reasons.append("billing_boundary_mismatch")
    if preflight["token_limit"] != packet["token_limit"]:
        reasons.append("token_limit_mismatch")

    for value_field in ("provider", "model", "route", "runtime"):
        if preflight[value_field] in (None, "", "unknown"):
            reasons.append(f"preflight_identity_unknown:{value_field}")

    reasons.extend(_provider_input_reasons(packet["provider_input"], preflight))

    requirements = packet["requirements"]
    boolean_tools = (
        ("commands", "commands_executable"),
        ("browser", "browser_access"),
        ("web_search", "web_search_access"),
        ("connector", "connector_access"),
    )
    for requirement, field in boolean_tools:
        if requirements[requirement] and preflight[field] != "yes":
            reasons.append(f"required_capability_missing:{requirement}")

    if requirements["local_files"]:
        accepted = {"read_only", "read_write"}
        if preflight["local_file_access"] not in accepted:
            reasons.append("required_capability_missing:local_files")
    if requirements["write"]:
        if preflight["write_access"] != "scoped":
            reasons.append("required_capability_missing:write")
        if preflight["local_file_access"] != "read_write":
            reasons.append("required_capability_missing:local_write")
    if any(requirements[name] for name in ("browser", "web_search", "connector")):
        if preflight["network_access"] != "authorized":
            reasons.append("network_access_not_authorized")
    if requirements["web_search"] and preflight["citation_support"] != "yes":
        reasons.append("required_capability_missing:citation_support")

    for field in ("read_scope", "write_scope", "authority_scope"):
        try:
            actual = _string_list(preflight[field], f"preflight.{field}")
        except ResolutionError:
            reasons.append(f"invalid_preflight:{field}")
            continue
        if actual != packet[field]:
            reasons.append(f"{field}_mismatch")

    required_floor = packet["consequence_floor"]
    actual_floor = preflight["consequence_floor"]
    if actual_floor not in CONSEQUENCE_RANK:
        reasons.append("invalid_consequence_floor")
    elif CONSEQUENCE_RANK[actual_floor] < CONSEQUENCE_RANK[required_floor]:
        reasons.append("consequence_floor_downgrade")

    if packet["independence_required"]:
        if preflight["independence_group"] in packet["independence_exclusions"]:
            reasons.append("independence_conflict")

    return reasons, preflight


def _validate_packet(packet: Any) -> dict[str, Any]:
    packet = _require_mapping(packet, "packet")
    input_schema_version = packet.get("schema_version")
    if input_schema_version not in {1, PACKET_SCHEMA_VERSION}:
        raise ResolutionError("unsupported_schema", str(packet.get("schema_version")))
    if "reasoning_escalation" in packet:
        raise ResolutionError(
            "legacy_escalation_shape_rejected",
            "model-based reasoning escalation is not authoritative",
        )
    if input_schema_version == 1:
        if "parent_capability" in packet:
            raise ResolutionError(
                "legacy_escalation_shape_rejected",
                "schema-v1 model-based capability fields are not authoritative",
            )
        packet["schema_version"] = PACKET_SCHEMA_VERSION
        packet["parent_capability"] = {
            "cost_ceiling": 1,
            "effort_ceiling": 1,
        }
    for field in ("task_id", "role"):
        _require_nonempty_string(packet.get(field), field)
    packet.setdefault("resolution_phase", "evidence")
    if packet["resolution_phase"] not in RESOLUTION_PHASES:
        raise ResolutionError(
            "invalid_packet",
            "resolution_phase must be evidence or pre_dispatch",
        )
    _parse_utc_timestamp(packet.get("resolution_time"), "resolution_time")
    if packet["role"] not in {"worker", "tester", "auditor", "parent", "supervisor"}:
        raise ResolutionError("invalid_packet", "role is unsupported")
    packet.setdefault("token_limit", None)
    packet["allowed_billing"] = _string_list(packet.get("allowed_billing"), "allowed_billing")
    if not set(packet["allowed_billing"]).issubset(SAFE_BILLING):
        raise ResolutionError("invalid_packet", "allowed_billing cannot authorize metered or unknown billing")
    packet["read_scope"] = _string_list(packet.get("read_scope"), "read_scope")
    packet["write_scope"] = _string_list(packet.get("write_scope"), "write_scope")
    packet["authority_scope"] = _string_list(packet.get("authority_scope"), "authority_scope")
    packet["independence_exclusions"] = _string_list(
        packet.get("independence_exclusions", []), "independence_exclusions"
    )
    packet.setdefault("independence_required", False)
    if type(packet["independence_required"]) is not bool:
        raise ResolutionError("invalid_packet", "independence_required must be a boolean")
    if packet.get("consequence_floor") not in CONSEQUENCE_RANK:
        raise ResolutionError("invalid_packet", "consequence_floor is unsupported")
    requirements = _require_mapping(packet.get("requirements"), "requirements")
    required_requirement_fields = {"commands", "local_files", "browser", "web_search", "connector", "write"}
    if set(requirements) != required_requirement_fields:
        raise ResolutionError("invalid_packet", "requirements must declare every supported capability exactly once")
    if any(type(requirements[field]) is not bool for field in required_requirement_fields):
        raise ResolutionError("invalid_packet", "requirements values must be booleans")
    packet["provider_input"] = _require_mapping(packet.get("provider_input"), "provider_input")
    packet["preflights"] = _require_mapping(packet.get("preflights"), "preflights")
    packet["attempt_results"] = _require_mapping(packet.get("attempt_results"), "attempt_results")
    if "adapter_evidence" in packet:
        raise ResolutionError("hand_authored_adapter_identity_forbidden", "adapter_evidence")
    if "explicit_selection" in packet:
        try:
            selection = _explicit_tool_model.validate_selection(packet["explicit_selection"])
        except _explicit_tool_model.ExplicitSelectionError as exc:
            raise ResolutionError(exc.code, exc.detail) from exc
        if selection["task_id"] != packet["task_id"]:
            raise ResolutionError("explicit_selection_task_mismatch", "task_id")
        if packet.get("task_grant_sha256") != selection["task_grant_sha256"]:
            raise ResolutionError("explicit_selection_grant_mismatch", "task_grant_sha256")
        packet["explicit_selection"] = selection
    escalation_reason = packet.get("escalation_reason")
    if escalation_reason is not None and escalation_reason not in EXPLICIT_ESCALATION_REASONS:
        raise ResolutionError("invalid_packet", "escalation_reason is unsupported")
    parent_capability = packet.get("parent_capability")
    parent_capability = _require_mapping(parent_capability, "parent_capability")
    if set(parent_capability) != {"cost_ceiling", "effort_ceiling"}:
        raise ResolutionError("invalid_packet", "parent_capability fields are incomplete")
    policy = _config.CAPABILITY_MODEL_DEFAULTS["reasoning"]["route_capability_policy"]
    for field, package_ceiling in (
        ("cost_ceiling", policy["default_parent_cost_ceiling"]),
        ("effort_ceiling", policy["default_parent_effort_ceiling"]),
    ):
        value = parent_capability[field]
        if type(value) is not int or value < 0 or value > package_ceiling:
            raise ResolutionError("invalid_packet", f"parent_capability.{field} exceeds package ceiling")
    capability_escalation = packet.get("capability_escalation")
    if capability_escalation is not None:
        capability_escalation = _require_mapping(
            capability_escalation, "capability_escalation"
        )
        required = {
            "route_name", "route_fingerprint", "cost_rank", "effort_rank",
            "operator_approved", "approval_reference", "prework_status",
            "prework_evidence", "task_grant_sha256",
        }
        if set(capability_escalation) != required:
            raise ResolutionError("invalid_packet", "capability_escalation fields are incomplete")
        for field in ("route_name", "route_fingerprint", "approval_reference", "task_grant_sha256"):
            _require_nonempty_string(
                capability_escalation[field], f"capability_escalation.{field}"
            )
        if re.fullmatch(r"[0-9a-f]{64}", capability_escalation["route_fingerprint"]) is None:
            raise ResolutionError("invalid_packet", "capability_escalation.route_fingerprint is invalid")
        if capability_escalation["task_grant_sha256"] != packet.get("task_grant_sha256"):
            raise ResolutionError("invalid_packet", "capability_escalation task grant mismatch")
        if re.fullmatch(r"sha256:[0-9a-f]{64}", capability_escalation["task_grant_sha256"]) is None:
            raise ResolutionError("invalid_packet", "capability_escalation.task_grant_sha256 is invalid")
        for field in ("cost_rank", "effort_rank"):
            if type(capability_escalation[field]) is not int or capability_escalation[field] < 0:
                raise ResolutionError("invalid_packet", f"capability_escalation.{field} is invalid")
        if type(capability_escalation["operator_approved"]) is not bool:
            raise ResolutionError("invalid_packet", "capability_escalation.operator_approved must be a boolean")
        if capability_escalation["prework_status"] != "attempted_exhausted":
            raise ResolutionError("invalid_packet", "capability_escalation.prework_status must be attempted_exhausted")
        capability_escalation["prework_evidence"] = _string_list(
            capability_escalation["prework_evidence"], "capability_escalation.prework_evidence"
        )
        if not capability_escalation["prework_evidence"]:
            raise ResolutionError("invalid_packet", "capability_escalation.prework_evidence must not be empty")
    controls = _require_mapping(packet.get("controls"), "controls")
    for field in ("max_attempts_per_checkpoint", "max_attempts_per_route", "circuit_breaker_threshold", "no_improvement_window"):
        if type(controls.get(field)) is not int or controls[field] <= 0:
            raise ResolutionError("invalid_packet", f"controls.{field} must be a positive integer")
    if controls["max_attempts_per_checkpoint"] > 3:
        raise ResolutionError("invalid_packet", "max_attempts_per_checkpoint exceeds repository ceiling 3")
    if controls["max_attempts_per_route"] > controls["max_attempts_per_checkpoint"]:
        raise ResolutionError("invalid_packet", "max_attempts_per_route exceeds checkpoint ceiling")
    return packet


def _attempt_receipt(
    *,
    index: int,
    route_name: str,
    identity: dict[str, Any],
    outcome: dict[str, Any],
    circuit_state: str,
) -> dict[str, Any]:
    return {
        "attempt_index": index,
        "route_name": route_name,
        "identity": copy.deepcopy(identity),
        "outcome": outcome["outcome"],
        "detail": outcome.get("detail", "not_reported_by_fixture"),
        "circuit_state": circuit_state,
        "tokens": _normalize_accounting(outcome.get("tokens"), "provider_tokens_not_reported"),
        "quota": _normalize_accounting(outcome.get("quota"), "provider_quota_not_reported"),
        "cost": _normalize_accounting(outcome.get("cost"), "provider_cost_not_reported"),
        "wall_time_ms": _normalize_accounting(outcome.get("wall_time_ms"), "wall_time_not_reported"),
    }


def _control_route_receipt(packet: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
    route_name = _require_nonempty_string(packet.get("control_route"), "control_route")
    route = registry["routes"].get(route_name)
    if route is None or route["route_kind"] != "control":
        raise ResolutionError("invalid_control_route", route_name)
    if not _escalation_authorized(packet, route_name, route):
        return {
            "schema_version": SCHEMA_VERSION,
            "task_id": packet["task_id"],
            "role": packet["role"],
            "profile": None,
            "status": "rejected",
            "preferred_route": route_name,
            "ordered_routes": [route_name],
            "selected_route": None,
            "failover_used": False,
            "considerations": [{
                "order": 1,
                "route_name": route_name,
                "eligible": False,
                "reasons": ["explicit_escalation_required"],
                "preflight_id": None,
            }],
            "attempts": [],
            "actual_route": None,
            "failed_preferred_route": None,
            "stop_reason": "explicit_escalation_required",
            "external_call_performed": False,
        }
    preflight = packet["preflights"].get(route_name)
    attempts: list[dict[str, Any]] = []
    if isinstance(preflight, dict) and PREFLIGHT_REQUIRED_FIELDS.issubset(preflight):
        identity = _identity_snapshot(route_name, route, preflight)
        outcomes = packet["attempt_results"].get(route_name, [])
        if outcomes:
            outcome = _require_mapping(outcomes[0], f"attempt_results.{route_name}[0]")
            if outcome.get("outcome") not in ALL_OUTCOMES:
                raise ResolutionError("invalid_outcome", str(outcome.get("outcome")))
            attempts.append(
                _attempt_receipt(index=1, route_name=route_name, identity=identity, outcome=outcome, circuit_state="closed")
            )
    return {
        "schema_version": SCHEMA_VERSION,
        "task_id": packet["task_id"],
        "role": packet["role"],
        "profile": None,
        "status": "parent_decision_required",
        "preferred_route": route_name,
        "ordered_routes": [route_name],
        "selected_route": None,
        "failover_used": False,
        "considerations": [],
        "attempts": attempts,
        "actual_route": None,
        "failed_preferred_route": attempts[0] if attempts and attempts[0]["outcome"] != "success" else None,
        "stop_reason": "automatic_control_route_failover_forbidden",
        "external_call_performed": False,
    }


def resolve_worker_route(raw_packet: Any) -> dict[str, Any]:
    """Resolve a Worker route using only deterministic supplied facts."""

    packet = _validate_packet(copy.deepcopy(raw_packet))
    registry = _effective_registry(packet)
    if packet["role"] in {"parent", "supervisor"}:
        return _control_route_receipt(packet, registry)

    profile_name = _require_nonempty_string(packet.get("profile"), "profile")
    _bind_profile_requirements(packet, registry, profile_name)
    ordered_routes = _ordered_profile_routes(registry, profile_name)
    selection = packet.get("explicit_selection")
    if isinstance(selection, dict):
        route_name = selection["route_name"]
        route = registry["routes"].get(route_name)
        if not isinstance(route, dict):
            raise ResolutionError("explicit_selection_route_missing", route_name)
        expected = {
            "requested_model": route["exact_model"],
            "route_id": route["route_id"],
            "provider": route["provider"],
            "runtime": route["runtime"],
            "billing_basis": route["billing_basis"],
        }
        for field, value in expected.items():
            if selection.get(field) != value:
                raise ResolutionError("explicit_selection_identity_mismatch", field)
        if ordered_routes != [route_name]:
            raise ResolutionError("explicit_selection_fallback_forbidden", profile_name)
        if set(packet["preflights"]) != {route_name} or set(packet["attempt_results"]) - {route_name}:
            raise ResolutionError("explicit_selection_route_set_mismatch", route_name)
    flash_preflight = packet["preflights"].get("worker_deepseek_v4_flash")
    flash_route = registry["routes"].get("worker_deepseek_v4_flash")
    if (
        isinstance(flash_preflight, dict)
        and flash_preflight.get("quota") == "unknown"
        and isinstance(flash_route, dict)
        and flash_route.get("quota_observability") == "unsupported"
        and ordered_routes != ["worker_deepseek_v4_flash"]
    ):
        raise ResolutionError(
            "unknown_quota_exception_rejected",
            "quota unknown requires exactly one DeepSeek Flash route",
        )
    preferred_route = ordered_routes[0]
    considerations: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    selected_route: str | None = None
    actual_route: dict[str, Any] | None = None
    failed_preferred_route: dict[str, Any] | None = None
    stop_reason = "no_eligible_route"
    hard_stop = False
    total_attempts = 0
    next_attempt: dict[str, Any] | None = None
    selected_capability_authority: dict[str, Any] | None = None

    for order, route_name in enumerate(ordered_routes, start=1):
        route = registry["routes"][route_name]
        reasons, preflight = _eligibility_reasons(packet, route_name, route, packet["preflights"].get(route_name))
        capability_authority = (
            _route_capability_decision(packet, route_name, route, preflight)
            if isinstance(preflight, dict) and PREFLIGHT_REQUIRED_FIELDS.issubset(preflight)
            else None
        )
        considerations.append(
            {
                "order": order,
                "route_name": route_name,
                "eligible": not reasons,
                "reasons": reasons,
                "preflight_id": preflight.get("preflight_id") if isinstance(preflight, dict) else None,
                "capability_authority": capability_authority,
            }
        )
        if reasons:
            continue

        adapter_evidence = (
            _adapter_evidence(route_name, route, selection)
            if packet["resolution_phase"] == "pre_dispatch" else None
        )
        identity = _identity_snapshot(route_name, route, preflight, adapter_evidence)
        route_outcomes = packet["attempt_results"].get(route_name)
        if not isinstance(route_outcomes, list) or not route_outcomes:
            stop_reason = f"eligible_route_missing_attempt_result:{route_name}"
            if packet["resolution_phase"] == "pre_dispatch":
                next_attempt = {
                    "attempt_index": total_attempts + 1,
                    "route_attempt_index": 1,
                    "route_name": route_name,
                    "identity": copy.deepcopy(identity),
                    "capability_authority": copy.deepcopy(capability_authority),
                }
                selected_capability_authority = copy.deepcopy(capability_authority)
                stop_reason = "dispatch_required"
            break

        route_failures = 0
        no_improvement_count = 0
        for route_attempt_index, raw_outcome in enumerate(route_outcomes, start=1):
            if total_attempts >= packet["controls"]["max_attempts_per_checkpoint"]:
                stop_reason = "checkpoint_attempt_budget_exhausted"
                break
            if route_attempt_index > packet["controls"]["max_attempts_per_route"]:
                stop_reason = f"route_attempt_budget_exhausted:{route_name}"
                break
            outcome = _require_mapping(raw_outcome, f"attempt_results.{route_name}[{route_attempt_index - 1}]")
            outcome_name = outcome.get("outcome")
            if outcome_name not in ALL_OUTCOMES:
                raise ResolutionError("invalid_outcome", str(outcome_name))

            total_attempts += 1
            if outcome_name in RETRYABLE_OUTCOMES:
                route_failures += 1
            if outcome_name == "no_improvement":
                no_improvement_count += 1
            else:
                no_improvement_count = 0

            circuit_state = "closed"
            if route_failures >= packet["controls"]["circuit_breaker_threshold"]:
                circuit_state = "open_failure_threshold"
            if no_improvement_count >= packet["controls"]["no_improvement_window"]:
                circuit_state = "open_no_improvement"
            attempt = _attempt_receipt(
                index=total_attempts,
                route_name=route_name,
                identity=identity,
                outcome=outcome,
                circuit_state=circuit_state,
            )
            attempts.append(attempt)
            if route_name == preferred_route and outcome_name != "success" and failed_preferred_route is None:
                failed_preferred_route = copy.deepcopy(attempt)

            if outcome_name == "success":
                selected_route = route_name
                selected_capability_authority = copy.deepcopy(capability_authority)
                actual_route = {
                    **copy.deepcopy(identity),
                    "attempt_index": total_attempts,
                    "tokens": copy.deepcopy(attempt["tokens"]),
                    "quota": copy.deepcopy(attempt["quota"]),
                    "cost": copy.deepcopy(attempt["cost"]),
                    "wall_time_ms": copy.deepcopy(attempt["wall_time_ms"]),
                }
                stop_reason = "selected_eligible_route"
                break
            if outcome_name in HARD_STOP_OUTCOMES:
                stop_reason = f"hard_stop:{outcome_name}"
                hard_stop = True
                break
            if circuit_state != "closed":
                stop_reason = f"circuit_open:{route_name}:{circuit_state}"
                break

        if selected_route is not None or hard_stop:
            break
        if total_attempts >= packet["controls"]["max_attempts_per_checkpoint"]:
            stop_reason = "checkpoint_attempt_budget_exhausted"
            break
        if (
            packet["resolution_phase"] == "pre_dispatch"
            and len(route_outcomes) < packet["controls"]["max_attempts_per_route"]
            and route_failures < packet["controls"]["circuit_breaker_threshold"]
            and no_improvement_count < packet["controls"]["no_improvement_window"]
        ):
            next_attempt = {
                "attempt_index": total_attempts + 1,
                "route_attempt_index": len(route_outcomes) + 1,
                "route_name": route_name,
                "identity": copy.deepcopy(identity),
                "capability_authority": copy.deepcopy(capability_authority),
            }
            selected_capability_authority = copy.deepcopy(capability_authority)
            stop_reason = "dispatch_required"
            break

    if selected_route is not None:
        status = "selected"
    elif hard_stop:
        status = "hard_stop"
    elif next_attempt is not None:
        status = "dispatch_required"
    elif any(item["eligible"] for item in considerations):
        status = "attempts_exhausted"
    else:
        status = "no_eligible_route"

    receipt = {
        "schema_version": SCHEMA_VERSION,
        "task_id": packet["task_id"],
        "role": packet["role"],
        "profile": profile_name,
        "status": status,
        "preferred_route": preferred_route,
        "ordered_routes": ordered_routes,
        "selected_route": selected_route,
        "failover_used": selected_route is not None and selected_route != preferred_route,
        "controls": copy.deepcopy(packet["controls"]),
        "considerations": considerations,
        "attempts": attempts,
        "actual_route": actual_route,
        "failed_preferred_route": failed_preferred_route,
        "stop_reason": stop_reason,
        "external_call_performed": False,
        "capability_authority": selected_capability_authority,
    }
    if packet["resolution_phase"] == "pre_dispatch":
        receipt["resolution_phase"] = "pre_dispatch"
        receipt["next_attempt"] = next_attempt
    if isinstance(selection, dict):
        receipt["explicit_selection_sha256"] = selection["selection_sha256"]
        receipt["fallback_allowed"] = False
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True, help="deterministic JSON input packet")
    args = parser.parse_args(argv)
    try:
        packet = json.loads(args.packet.read_text(encoding="utf-8"))
        receipt = resolve_worker_route(packet)
    except (OSError, json.JSONDecodeError, ResolutionError) as exc:
        if isinstance(exc, ResolutionError):
            error = {"status": "invalid_input", "code": exc.code, "detail": exc.detail}
        else:
            error = {"status": "invalid_input", "code": type(exc).__name__, "detail": str(exc)}
        print(json.dumps(error, indent=2, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] in {
        "selected", "parent_decision_required", "dispatch_required"
    } else 3


if __name__ == "__main__":
    raise SystemExit(main())
