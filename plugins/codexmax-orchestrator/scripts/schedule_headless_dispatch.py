#!/usr/bin/env python3
"""Deterministically plan and account for one Codexmax dispatch attempt.

This module never starts a provider process.  It is the admission boundary
between a compiled DispatchTaskEnvelope and the one-attempt dispatcher seam.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
CEILING_WRITE_WORKERS = 2
SHA = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
ROLES_WITH_DIVERSITY = {"worker", "tester", "documenter", "auditor"}
TERMINAL_LEASE_EVENTS = {"lease_released", "lease_expired", "lease_recovered"}


class ScheduleError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _load_sibling(name: str) -> Any:
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(f"codexmax_{name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


LEDGER = _load_sibling("dispatch_ledger")
BROKER = _load_sibling("preflight_broker")
RESOLVER = _load_sibling("resolve_worker_route")
CANDIDATE = _load_sibling("compile_dispatch_candidate")
FABRIC = _load_sibling("route_fabric")


def _semantic_task_profile(role: str, mutation_mode: str = "artifact_only") -> str:
    try:
        return RESOLVER._config.semantic_task_profile(
            RESOLVER._config.DEFAULTS, role, mutation_mode=mutation_mode
        )
    except RESOLVER._config.ConfigError as exc:
        raise ScheduleError("policy_invalid", str(exc)) from exc


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Any, *, prefixed: bool = True) -> str:
    result = hashlib.sha256(canonical_json(value)).hexdigest()
    return "sha256:" + result if prefixed else result


def _timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ScheduleError("invalid_timestamp", field)
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ScheduleError("invalid_timestamp", field) from exc
    return parsed.astimezone(dt.timezone.utc)


def _raw_sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise ScheduleError("binding_invalid", field)
    return value.removeprefix("sha256:")


def _positive(value: Any, field: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ScheduleError("policy_invalid", field)
    return value


def _strict(value: Any, field: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ScheduleError("shape_invalid", field)
    return value


def _normalize_scope(value: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        raise ScheduleError("scope_invalid", str(value))
    parts: list[str] = []
    for part in value.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            raise ScheduleError("scope_invalid", value)
        if any(marker in part for marker in ("*", "?", "[", "]")):
            break
        parts.append(part)
    # A leading glob conservatively means the complete repository scope.
    return "/".join(parts) or "."


def scopes_overlap(left: str, right: str) -> bool:
    a, b = _normalize_scope(left), _normalize_scope(right)
    if "." in {a, b}:
        return True
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


BINDING_NAMES = ("board", "config", "authority", "workgraph", "supervisor")


def _verified_file_descriptor(repo_root: Path, value: Any, field: str) -> dict[str, Any]:
    descriptor = _strict(value, field, {"path", "sha256"})
    relative = descriptor["path"]
    expected = descriptor["sha256"]
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts or "\\" in relative:
        raise ScheduleError("binding_source_invalid", field)
    _raw_sha(expected, f"{field}.sha256")
    root = repo_root.resolve(strict=True)
    named = root / relative
    try:
        named_stat = named.lstat()
        resolved = named.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ScheduleError("binding_source_unreadable", field) from exc
    if stat.S_ISLNK(named_stat.st_mode) or not stat.S_ISREG(named_stat.st_mode) or named_stat.st_nlink != 1:
        raise ScheduleError("binding_source_unsafe", field)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor_fd = os.open(named, flags)
        try:
            before = os.fstat(descriptor_fd)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor_fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(descriptor_fd)
        finally:
            os.close(descriptor_fd)
    except OSError as exc:
        raise ScheduleError("binding_source_unreadable", field) from exc
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink) or before.st_nlink != 1:
        raise ScheduleError("binding_source_changed", field)
    actual = "sha256:" + hashlib.sha256(b"".join(chunks)).hexdigest()
    if actual != expected:
        raise ScheduleError("binding_source_digest_mismatch", field)
    return {"path": relative, "sha256": actual, "size_bytes": before.st_size}


def verify_binding_sources(repo_root: Path, sources: Any, bindings: dict[str, Any]) -> dict[str, Any]:
    source_map = _strict(sources, "binding_sources", set(BINDING_NAMES))
    verified: dict[str, Any] = {}
    for name in BINDING_NAMES:
        verified[name] = _verified_file_descriptor(repo_root, source_map[name], f"binding_sources.{name}")
        if verified[name]["sha256"] != bindings[f"{name}_sha256"]:
            raise ScheduleError("binding_source_envelope_mismatch", name)
    return verified


def validate_policy(value: Any) -> dict[str, Any]:
    policy = _strict(value, "scheduler", {
        "schema_version", "activation", "global_active_limit", "lease_ttl_seconds",
        "maximum_queue_age_seconds", "provider_concurrency_default",
        "runtime_host_concurrency_default",
        "provider_concurrency_limits", "runtime_host_concurrency_limits",
        "allowance_limits", "token_capacity", "diversity_min_quality_observations",
        "role_rank_displacement", "unknown_cost_policy", "hedging_enabled",
        "direct_repository_writes_enabled", "artifact_quality_policy",
    })
    if policy["schema_version"] != SCHEMA_VERSION:
        raise ScheduleError("policy_invalid", "schema_version")
    if policy["activation"] != "explicit_only" or policy["unknown_cost_policy"] != "preserve_unknown_and_reject_cash":
        raise ScheduleError("policy_invalid", "unsafe activation or unknown-cost policy")
    if policy["hedging_enabled"] is not False or type(policy["direct_repository_writes_enabled"]) is not bool:
        raise ScheduleError("policy_invalid", "unsafe hedging or write policy")
    _positive(policy["global_active_limit"], "global_active_limit")
    _positive(policy["lease_ttl_seconds"], "lease_ttl_seconds")
    _positive(policy["maximum_queue_age_seconds"], "maximum_queue_age_seconds")
    _positive(policy["provider_concurrency_default"], "provider_concurrency_default")
    _positive(policy["runtime_host_concurrency_default"], "runtime_host_concurrency_default")
    for field in ("provider_concurrency_limits", "runtime_host_concurrency_limits", "allowance_limits"):
        if not isinstance(policy[field], dict):
            raise ScheduleError("policy_invalid", field)
        for key, limit in policy[field].items():
            if not isinstance(key, str) or not key:
                raise ScheduleError("policy_invalid", field)
            _positive(limit, f"{field}.{key}")
    if policy["token_capacity"] is not None:
        _positive(policy["token_capacity"], "token_capacity")
    _positive(policy["diversity_min_quality_observations"], "diversity_min_quality_observations", allow_zero=True)
    if set(policy["role_rank_displacement"]) != {"planner", "architect", "worker", "tester", "documenter", "auditor"}:
        raise ScheduleError("policy_invalid", "role_rank_displacement")
    for role, displacement in policy["role_rank_displacement"].items():
        if displacement not in {0, 1} or role in {"planner", "architect"} and displacement != 0:
            raise ScheduleError("policy_invalid", f"role_rank_displacement.{role}")
    if not isinstance(policy["artifact_quality_policy"], str) or not policy["artifact_quality_policy"]:
        raise ScheduleError("policy_invalid", "artifact_quality_policy")
    return policy


ROUTE_KEYS = {
    "name", "provider", "exact_model", "route_id", "runtime", "runtime_host",
    "reasoning", "billing_basis", "independence_group", "adapter_id",
    "adapter_sha256", "concurrency_limit",
    "allowance_units", "token_reservation", "cash_reservation_required",
    "evidence_path", "preflight_key_sha256", "preflight_observation",
    "resolver_packet_sha256", "resolver_packet", "preflight_binding",
    "explicit_selection", "explicit_selection_sha256",
}


def validate_route(value: Any) -> dict[str, Any]:
    required = ROUTE_KEYS - {"explicit_selection", "explicit_selection_sha256"}
    if not isinstance(value, dict) or not required.issubset(value) or set(value) - ROUTE_KEYS:
        raise ScheduleError("shape_invalid", "candidate fields")
    route = copy.deepcopy(value)
    route.setdefault("explicit_selection", None)
    route.setdefault("explicit_selection_sha256", None)
    for field in {
        "name", "provider", "exact_model", "route_id", "runtime", "runtime_host",
        "reasoning", "billing_basis", "independence_group", "adapter_id", "evidence_path",
    }:
        if not isinstance(route[field], str) or not route[field].strip():
            raise ScheduleError("route_invalid", field)
    _positive(route["concurrency_limit"], "candidate.concurrency_limit")
    _positive(route["allowance_units"], "candidate.allowance_units", allow_zero=True)
    if route["token_reservation"] != "unknown":
        _positive(route["token_reservation"], "candidate.token_reservation", allow_zero=True)
    if not isinstance(route["cash_reservation_required"], bool):
        raise ScheduleError("route_invalid", "cash_reservation_required")
    if SHA.fullmatch(route["preflight_key_sha256"]) is None:
        raise ScheduleError("route_invalid", "preflight_key_sha256")
    if SHA.fullmatch(route["adapter_sha256"]) is None:
        raise ScheduleError("route_invalid", "adapter_sha256")
    if SHA.fullmatch(route["resolver_packet_sha256"]) is None or not isinstance(route["resolver_packet"], dict):
        raise ScheduleError("route_invalid", "resolver_packet")
    if digest(route["resolver_packet"]) != route["resolver_packet_sha256"]:
        raise ScheduleError("resolver_packet_digest_mismatch", route["name"])
    selection = route["explicit_selection"]
    if selection is None:
        if route["explicit_selection_sha256"] is not None or route["resolver_packet"].get("explicit_selection") is not None:
            raise ScheduleError("explicit_selection_binding_mismatch", route["name"])
    else:
        try:
            selection = CANDIDATE.EXPLICIT_SELECTION.validate_selection(selection)
        except CANDIDATE.EXPLICIT_SELECTION.ExplicitSelectionError as exc:
            raise ScheduleError(exc.code, exc.detail) from exc
        if (
            route["explicit_selection_sha256"] != selection["selection_sha256"]
            or route["resolver_packet"].get("explicit_selection") != selection
            or route["resolver_packet"].get("task_grant_sha256") != selection["task_grant_sha256"]
        ):
            raise ScheduleError("explicit_selection_binding_mismatch", route["name"])
        expected = {
            "route_name": route["name"], "requested_model": route["exact_model"],
            "route_id": route["route_id"], "provider": route["provider"],
            "runtime": route["runtime"], "billing_basis": route["billing_basis"],
            "adapter_type": route["adapter_id"], "adapter_sha256": route["adapter_sha256"],
        }
        for field, expected_value in expected.items():
            if selection.get(field) != expected_value:
                raise ScheduleError("explicit_selection_route_mismatch", field)
        route["explicit_selection"] = selection
    observation = route["preflight_observation"]
    if not isinstance(observation, dict):
        raise ScheduleError("preflight_invalid", route["name"])
    key = observation.get("key")
    try:
        BROKER._verify_observation(observation, BROKER.normalize_key(key))
    except BROKER.PreflightBrokerError as exc:
        raise ScheduleError("preflight_invalid", exc.code) from exc
    if BROKER.key_sha256(key) != route["preflight_key_sha256"]:
        raise ScheduleError("preflight_binding_mismatch", route["name"])
    binding = _strict(
        route["preflight_binding"], "candidate.preflight_binding",
        {"state_path", "state_sha256", "entry_sha256"},
    )
    state_path = binding["state_path"]
    if (
        not isinstance(state_path, str) or not state_path
        or Path(state_path).is_absolute() or ".." in Path(state_path).parts
        or "\\" in state_path
    ):
        raise ScheduleError("preflight_binding_path_invalid", route["name"])
    for field in ("state_sha256", "entry_sha256"):
        if not isinstance(binding[field], str) or SHA.fullmatch(binding[field]) is None:
            raise ScheduleError("preflight_binding_invalid", field)
    expected_key = {
        "provider": route["provider"], "exact_model": route["exact_model"],
        "route_id": route["route_id"], "runtime": route["runtime"],
        "reasoning": route["reasoning"],
        "proof_mode": (
            "scheduler_scoped_write"
            if route["resolver_packet"].get("profile") == "semantic_worker_implementation"
            else "scheduler_artifact_only"
        ),
    }
    if key != expected_key:
        raise ScheduleError("preflight_route_mismatch", route["name"])
    return route


def _advisory_route_matches(route: dict[str, Any], identity: dict[str, Any]) -> bool:
    bindings = {
        "route_name": "name", "provider": "provider", "exact_model": "exact_model",
        "route_id": "route_id", "runtime": "runtime", "runtime_host": "runtime_host",
        "reasoning": "reasoning", "billing_basis": "billing_basis",
        "independence_group": "independence_group",
        "adapter_id": "adapter_id", "adapter_sha256": "adapter_sha256",
    }
    return all(route.get(candidate_field) == identity[fabric_field] for fabric_field, candidate_field in bindings.items())


def consume_route_fabric_advisory(
    *, advisory: dict[str, Any] | None, envelope: dict[str, Any],
    candidates: list[dict[str, Any]], ledger_head_before: str,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Consume a validated advisory as a scheduler constraint, never a target."""
    if advisory is None:
        return None, candidates
    try:
        validated = FABRIC.validate_scheduler_advisory(
            advisory,
            assignment_id=envelope["assignment_id"],
            envelope_sha256=digest(envelope),
            ledger_head_before=ledger_head_before,
        )
    except FABRIC.FabricError as exc:
        raise ScheduleError(exc.code, exc.detail) from exc
    decision = validated["decision"]
    identity = decision["current_route_identity"]
    matching = [
        route for route in candidates
        if isinstance(route, dict) and _advisory_route_matches(route, identity)
    ]
    if len(matching) != 1:
        raise ScheduleError("advisory_route_identity_mismatch", identity["route_name"])
    action = decision["action"]
    if action == "human_gate":
        raise ScheduleError("advisory_requires_parent", ",".join(decision["reason_codes"]))
    if action == "clean_handoff":
        raise ScheduleError("advisory_handoff_required", ",".join(decision["reason_codes"]))
    if action == "unavailable":
        raise ScheduleError("advisory_unavailable", ",".join(decision["reason_codes"]))
    if action == "switch":
        filtered = [route for route in candidates if not _advisory_route_matches(route, identity)]
        if not filtered:
            raise ScheduleError("advisory_no_alternate", identity["route_name"])
        candidates = filtered
        effect = "exclude_current_route"
    elif action == "continue":
        effect = "normal_scheduler_selection"
    else:
        raise ScheduleError("advisory_action_invalid", action)
    return {
        "advisory_sha256": validated["advisory_sha256"],
        "decision_sha256": decision["decision_sha256"],
        "action": action,
        "effect": effect,
    }, candidates


def _verify_broker_binding(
    route: dict[str, Any], repo_root: Path, now: str,
) -> tuple[bool, str]:
    """Re-read the exact broker entry; copied observations cannot admit."""

    binding = route["preflight_binding"]
    try:
        safe_path, relative_path = CANDIDATE.resolve_broker_state_path(
            repo_root, Path(binding["state_path"]),
        )
        if relative_path != binding["state_path"]:
            return False, "broker_binding_mismatch:state_path"
        current = BROKER.read_current_observation(
            safe_path,
            route["preflight_observation"]["key"],
            now=now,
        )
    except (
        BROKER.PreflightBrokerError, CANDIDATE.CandidateError,
        OSError, RuntimeError,
    ) as exc:
        code = getattr(exc, "code", "preflight_state_unreadable")
        return False, f"broker_binding_rejected:{code}"
    expected = {
        "key_sha256": route["preflight_key_sha256"],
        "observation": route["preflight_observation"],
        "state_sha256": binding["state_sha256"],
        "entry_sha256": binding["entry_sha256"],
    }
    for field, value in expected.items():
        if current.get(field) != value:
            return False, f"broker_binding_mismatch:{field}"
    return True, "eligible"


def _verify_task_bound_resolver(route: dict[str, Any], envelope: dict[str, Any], now: str) -> tuple[bool, str]:
    packet = copy.deepcopy(route["resolver_packet"])
    selection = route.get("explicit_selection")
    if isinstance(selection, dict):
        authority_sha256 = envelope.get("bindings", {}).get("authority_sha256")
        if not isinstance(authority_sha256, str):
            return False, "explicit_selection_authority_missing"
        normalized_authority = authority_sha256 if authority_sha256.startswith("sha256:") else "sha256:" + authority_sha256
        if selection.get("task_grant_sha256") != normalized_authority:
            return False, "explicit_selection_grant_mismatch"
    expected_role = envelope["semantic_role"] if envelope["semantic_role"] in {"worker", "tester", "auditor"} else "worker"
    expected_authority = sorted(set(envelope["scope"].get("authority_read", [])) | set(envelope["scope"].get("authority_write", [])))
    exact = {
        "task_id": envelope["task_id"], "role": expected_role, "resolution_phase": "pre_dispatch",
        "resolution_time": now, "token_limit": envelope["budget"].get("token_limit"),
        "read_scope": sorted(envelope["scope"].get("requested_read", [])),
        "write_scope": sorted(envelope["scope"].get("requested_write", [])),
        "authority_scope": expected_authority, "consequence_floor": envelope["consequence"],
        "independence_required": envelope["independence"]["required"],
        "independence_exclusions": sorted(envelope["independence"]["exclusions"]),
    }
    for field, expected in exact.items():
        if packet.get(field) != expected:
            return False, f"resolver_{field}_mismatch"
    provider_input = packet.get("provider_input")
    if not isinstance(provider_input, dict):
        return False, "resolver_provider_input_missing"
    if envelope["source"].get("source_mode") not in provider_input.get("required_source_access", []):
        return False, "resolver_source_mode_mismatch"
    if provider_input.get("commands_required") is not bool(envelope.get("commands")):
        return False, "resolver_commands_mismatch"
    registry = packet.get("registry")
    profile_name = packet.get("profile")
    if not isinstance(registry, dict) or not isinstance(profile_name, str):
        return False, "resolver_registry_missing"
    try:
        ordered = RESOLVER._ordered_profile_routes(registry, profile_name)
    except Exception:
        return False, "resolver_registry_invalid"
    if ordered != [route["name"]] or set(packet.get("preflights", {})) != {route["name"]} or packet.get("attempt_results") != {}:
        return False, "resolver_not_single_route"
    try:
        receipt = RESOLVER.resolve_worker_route(packet)
    except RESOLVER.ResolutionError as exc:
        return False, f"resolver_rejected:{exc.code}"
    next_attempt = receipt.get("next_attempt")
    if receipt.get("status") != "dispatch_required" or receipt.get("stop_reason") != "dispatch_required" or not isinstance(next_attempt, dict):
        reasons = receipt.get("considerations", [{}])[0].get("reasons", [])
        return False, "resolver_ineligible:" + ",".join(reasons)
    capability = next_attempt.get("capability_authority")
    if not isinstance(capability, dict) or capability.get("authorized") is not True:
        return False, "resolver_capability_authority_missing"
    if capability.get("route_name") != route["name"]:
        return False, "resolver_capability_route_mismatch"
    if capability.get("escalation_required") is True:
        authority_sha256 = envelope.get("bindings", {}).get("authority_sha256")
        if not isinstance(authority_sha256, str):
            return False, "capability_escalation_authority_missing"
        normalized = (
            authority_sha256
            if authority_sha256.startswith("sha256:")
            else "sha256:" + authority_sha256
        )
        if (
            capability.get("escalation_approved") is not True
            or capability.get("task_grant_sha256") != normalized
            or not isinstance(capability.get("approval_digest"), str)
        ):
            return False, "capability_escalation_authority_mismatch"
    identity = next_attempt.get("identity", {})
    expected_identity = {
        "route_name": route["name"], "provider": route["provider"], "model": route["exact_model"],
        "route": route["route_id"], "runtime": route["runtime"], "reasoning": route["reasoning"],
        "billing": route["billing_basis"],
        "adapter_id": route["adapter_id"], "adapter_sha256": route["adapter_sha256"],
    }
    if next_attempt.get("route_name") != route["name"] or any(identity.get(field) != value for field, value in expected_identity.items()):
        return False, "resolver_next_attempt_mismatch"
    return True, "eligible"


def _validate_envelope(envelope: Any, bindings: Any, now: str) -> dict[str, Any]:
    if not isinstance(envelope, dict) or envelope.get("schema_version") != 1 or envelope.get("artifact_type") != "DispatchTaskEnvelope":
        raise ScheduleError("envelope_invalid", "DispatchTaskEnvelope v1 required")
    supplied = _strict(bindings, "bindings", {
        "board_sha256", "config_sha256", "authority_sha256", "workgraph_sha256", "supervisor_sha256",
    })
    if envelope.get("bindings") != supplied:
        raise ScheduleError("binding_mismatch", "envelope")
    for field, value in supplied.items():
        _raw_sha(value, field)
    execution = envelope.get("execution")
    if not isinstance(execution, dict) or execution.get("hedge_requested") is not False:
        raise ScheduleError("hedging_deferred")
    queue = envelope.get("queue")
    if not isinstance(queue, dict):
        raise ScheduleError("envelope_invalid", "queue")
    instant = _timestamp(now, "now")
    enqueued = _timestamp(queue.get("enqueued_at"), "queue.enqueued_at")
    deadline = _timestamp(queue.get("deadline"), "queue.deadline")
    max_age = _positive(queue.get("max_queue_age_seconds"), "max_queue_age_seconds")
    if instant >= deadline:
        raise ScheduleError("deadline_expired")
    if instant < enqueued:
        raise ScheduleError("enqueue_from_future")
    if (instant - enqueued).total_seconds() > max_age:
        raise ScheduleError("queue_age_expired")
    if envelope.get("mutation_mode") not in {"read_only", "artifact_only", "scoped_write"}:
        raise ScheduleError("mutation_mode_ineligible", str(envelope.get("mutation_mode")))
    required = {
        "envelope_id", "goal_id", "checkpoint_id", "task_id", "assignment_id",
        "semantic_role", "scope", "budget", "independence", "quality_policy",
    }
    if any(field not in envelope for field in required):
        raise ScheduleError("envelope_invalid", "missing scheduler field")
    if not isinstance(envelope["scope"], dict) or not isinstance(envelope["scope"].get("requested_write"), list):
        raise ScheduleError("envelope_invalid", "scope")
    if not isinstance(envelope["budget"], dict) or not isinstance(envelope["budget"].get("accounting"), dict):
        raise ScheduleError("envelope_invalid", "budget")
    if envelope["semantic_role"] not in {"planner", "architect", "worker", "tester", "documenter", "auditor"}:
        raise ScheduleError("envelope_invalid", "semantic_role")
    expected_task_class = _semantic_task_profile(
        envelope["semantic_role"], envelope["mutation_mode"]
    )
    if envelope.get("task_class") != expected_task_class:
        raise ScheduleError("task_class_role_mismatch", envelope["semantic_role"])
    if envelope["mutation_mode"] == "scoped_write" and not envelope["scope"]["requested_write"]:
        raise ScheduleError("scoped_write_invalid", "write scope required")
    if not isinstance(envelope["budget"].get("allowance_class"), str):
        raise ScheduleError("envelope_invalid", "budget.allowance_class")
    if not isinstance(envelope["quality_policy"], dict) or not isinstance(envelope["quality_policy"].get("policy_id"), str):
        raise ScheduleError("envelope_invalid", "quality_policy")
    return envelope


def _observation_callable(route: dict[str, Any], now: str) -> tuple[bool, str]:
    observation = route["preflight_observation"]
    try:
        if _timestamp(observation.get("expires_at"), "preflight.expires_at") <= _timestamp(now, "now"):
            return False, "preflight_expired"
    except ScheduleError:
        return False, "preflight_invalid"
    if observation.get("availability") != "available":
        return False, "route_unavailable"
    if observation.get("health") != "healthy":
        return False, "route_unhealthy"
    if observation.get("callability") != "callable":
        return False, "route_not_callable"
    return True, "eligible"


def _active_rows(verified: dict[str, Any], now: str) -> dict[str, dict[str, Any]]:
    active: dict[str, dict[str, Any]] = {}
    for row in verified["rows"]:
        lease_id = row["lease"].get("lease_id")
        if row["event_type"] == "lease_granted" and lease_id:
            active[lease_id] = row
        elif row["event_type"] in TERMINAL_LEASE_EVENTS and lease_id:
            active.pop(lease_id, None)
    _timestamp(now, "now")
    # Expiry alone never frees capacity.  A deterministic recover/expire event
    # must fence the old owner before a successor admission can proceed.
    return active


def _resource_rejection(
    route: dict[str, Any], envelope: dict[str, Any], policy: dict[str, Any],
    active: dict[str, dict[str, Any]], board_max_write_workers: int,
    config_max_write_workers: int,
) -> str | None:
    _positive(board_max_write_workers, "board_max_write_workers")
    _positive(config_max_write_workers, "config_max_write_workers")
    rows = list(active.values())
    writer = envelope["mutation_mode"] == "scoped_write"
    if writer:
        if not policy["direct_repository_writes_enabled"]:
            return "scoped_write_disabled"
        writer_limit = min(CEILING_WRITE_WORKERS, board_max_write_workers, config_max_write_workers)
        active_writers = [row for row in rows if row["lease"].get("writer") is True]
        if len(active_writers) >= writer_limit:
            return "writer_capacity"
        requested = envelope["scope"]["requested_write"]
        for row in active_writers:
            if any(
                scopes_overlap(left, right)
                for left in requested for right in row["lease"].get("write_scopes", [])
            ):
                return "writer_scope_overlap"
    if len(rows) >= policy["global_active_limit"]:
        return "global_capacity"
    if sum(row["route"].get("route_name") == route["name"] for row in rows) >= route["concurrency_limit"]:
        return "route_capacity"
    provider_limit = policy["provider_concurrency_limits"].get(route["provider"], policy["provider_concurrency_default"])
    if sum(row["route"].get("provider") == route["provider"] for row in rows) >= provider_limit:
        return "provider_capacity"
    host_limit = policy["runtime_host_concurrency_limits"].get(route["runtime_host"], policy["runtime_host_concurrency_default"])
    if sum(row["route"].get("runtime_host") == route["runtime_host"] for row in rows) >= host_limit:
        return "runtime_host_capacity"
    independence = envelope.get("independence", {})
    if independence.get("required"):
        blocked = set(independence.get("exclusions", [])) | {independence.get("group")}
        if route["independence_group"] in blocked:
            return "independence_ineligible"
        active_groups = {row["route"].get("independence_group") for row in rows}
        if route["independence_group"] in active_groups:
            return "independence_in_use"
    allowance_class = envelope["budget"]["allowance_class"]
    allowance_limit = policy["allowance_limits"].get(allowance_class)
    if allowance_limit is None:
        return "allowance_unconfigured"
    reserved = sum(
        row["accounting"].get("allowance_units_reserved", 0)
        for row in rows if row["accounting"].get("allowance_class") == allowance_class
    )
    if reserved + route["allowance_units"] > allowance_limit:
        return "allowance_capacity"
    if route["cash_reservation_required"]:
        cost = envelope["budget"]["accounting"]["cost"].get("value", "unknown")
        if cost == "unknown" or envelope["budget"].get("external_cash_authorized") is not True:
            return "cash_reservation_ineligible"
    token_capacity = policy["token_capacity"]
    if token_capacity is not None:
        if route["token_reservation"] == "unknown":
            return "token_reservation_unknown"
        token_reserved = sum(
            row["accounting"].get("token_reservation", 0)
            for row in rows if isinstance(row["accounting"].get("token_reservation"), int)
        )
        if token_reserved + route["token_reservation"] > token_capacity:
            return "token_capacity"
    return None


def _history_conflicts(verified: dict[str, Any], envelope: dict[str, Any], route: dict[str, Any]) -> str | None:
    for row in verified["rows"]:
        if row["event_type"] != "lease_granted":
            continue
        if row["evidence"].get("idempotency_key") == envelope["envelope_id"]:
            return "idempotency_key_reused"
        if row["evidence"].get("output_path") == route["evidence_path"]:
            return "evidence_path_reused"
    return None


def eligible_routes(
    *, envelope: dict[str, Any], candidates: list[dict[str, Any]], policy: dict[str, Any],
    verified: dict[str, Any], now: str, board_max_write_workers: int,
    config_max_write_workers: int, repo_root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    active = _active_rows(verified, now)
    eligible: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    names: set[str] = set()
    for raw in candidates:
        route = validate_route(copy.deepcopy(raw))
        if route["name"] in names:
            raise ScheduleError("candidate_duplicate", route["name"])
        names.add(route["name"])
        ok, reason = _verify_broker_binding(route, repo_root, now)
        if ok:
            ok, reason = _observation_callable(route, now)
        if ok:
            ok, reason = _verify_task_bound_resolver(route, envelope, now)
        if ok:
            reason = _history_conflicts(verified, envelope, route) or _resource_rejection(
                route, envelope, policy, active, board_max_write_workers, config_max_write_workers,
            ) or "eligible"
            ok = reason == "eligible"
        (eligible if ok else rejected).append(route if ok else {"name": route["name"], "reason": reason})
    return eligible, rejected


def select_route(envelope: dict[str, Any], eligible: list[dict[str, Any]], verified: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    if not eligible:
        raise ScheduleError("no_eligible_route")
    role = envelope["semantic_role"]
    accepted: dict[str, int] = {}
    route_accepted: dict[str, int] = {}
    total = 0
    for row in verified["rows"]:
        if row["event_type"] == "quality_accepted":
            provider = row["route"].get("provider", "unknown")
            accepted[provider] = accepted.get(provider, 0) + 1
            route_name = row["route"].get("route_name", "unknown")
            route_accepted[route_name] = route_accepted.get(route_name, 0) + 1
            total += 1
    displacement = policy["role_rank_displacement"][role] if role in ROLES_WITH_DIVERSITY else 0
    if total < policy["diversity_min_quality_observations"] or displacement == 0 or len(eligible) == 1:
        return eligible[0]
    window = eligible[: displacement + 1]
    return min(
        enumerate(window),
        key=lambda pair: (
            accepted.get(pair[1]["provider"], 0),
            route_accepted.get(pair[1]["name"], 0),
            pair[0],
            pair[1]["name"],
        ),
    )[1]


def plan(
    *, envelope: dict[str, Any], bindings: dict[str, Any], candidates: list[dict[str, Any]],
    binding_sources: dict[str, Any], repo_root: Path,
    policy: dict[str, Any], ledger_path: Path, now: str,
    board_max_write_workers: int, config_max_write_workers: int,
    route_fabric_advisory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(candidates, list) or not candidates:
        raise ScheduleError("candidates_invalid", "ordered nonempty array required")
    explicit_count = sum(
        isinstance(candidate, dict) and candidate.get("explicit_selection") is not None
        for candidate in candidates
    )
    if explicit_count and (explicit_count != 1 or len(candidates) != 1):
        raise ScheduleError("explicit_selection_candidate_set_mismatch")
    envelope = _validate_envelope(copy.deepcopy(envelope), bindings, now)
    verified_sources = verify_binding_sources(repo_root, binding_sources, envelope["bindings"])
    policy = validate_policy(copy.deepcopy(policy))
    if envelope["queue"]["max_queue_age_seconds"] > policy["maximum_queue_age_seconds"]:
        raise ScheduleError("queue_policy_exceeded")
    if envelope["quality_policy"]["policy_id"] != policy["artifact_quality_policy"]:
        raise ScheduleError("quality_policy_mismatch")
    verified = LEDGER.verify_ledger(ledger_path)
    advisory_receipt, candidates = consume_route_fabric_advisory(
        advisory=route_fabric_advisory,
        envelope=envelope,
        candidates=candidates,
        ledger_head_before=verified["head_hash"],
    )
    eligible, rejected = eligible_routes(
        envelope=envelope, candidates=candidates, policy=policy, verified=verified, now=now,
        board_max_write_workers=board_max_write_workers,
        config_max_write_workers=config_max_write_workers,
        repo_root=repo_root,
    )
    chosen = select_route(envelope, eligible, verified, policy) if eligible else None
    result = {
        "schema_version": 1, "artifact_type": "DispatchSchedulePlan",
        "created_at": now, "envelope_sha256": digest(envelope),
        "identity": {
            "goal_id": envelope["goal_id"], "checkpoint_id": envelope["checkpoint_id"],
            "task_id": envelope["task_id"], "assignment_id": envelope["assignment_id"],
        },
        "bindings": copy.deepcopy(bindings), "ledger_head_before": verified["head_hash"],
        "binding_sources": verified_sources, "ledger_sequence_before": verified["event_count"],
        "eligible_routes": [row["name"] for row in eligible], "rejected_routes": rejected,
        "selected_route": copy.deepcopy(chosen), "provider_call_started": False,
    }
    if advisory_receipt is not None:
        result["route_fabric_advisory"] = advisory_receipt
    result["plan_sha256"] = digest(result)
    return result


def _event(envelope: dict[str, Any], bindings: dict[str, Any], event_type: str, now: str, *, route: dict[str, Any], lease: dict[str, Any], accounting: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    if LEDGER.TIMESTAMP.fullmatch(now) is None:
        raise ScheduleError("invalid_ledger_timestamp", now)
    seed = [event_type, envelope["envelope_id"], route.get("name"), lease.get("lease_id"), lease.get("fencing_token"), now]
    return {
        "schema_version": 1, "event_id": hashlib.sha256(canonical_json(seed)).hexdigest(),
        "event_type": event_type, "timestamp": now,
        "goal_id": envelope["goal_id"], "checkpoint_id": envelope["checkpoint_id"],
        "task_id": envelope["task_id"], "assignment_id": envelope["assignment_id"],
        "envelope_sha256": digest(envelope),
        "config_sha256": "sha256:" + _raw_sha(bindings["config_sha256"], "config_sha256"),
        "board_sha256": "sha256:" + _raw_sha(bindings["board_sha256"], "board_sha256"),
        "route": route, "lease": lease, "accounting": accounting, "evidence": evidence,
    }


def _append_under_scheduler_lock(path: Path, event: dict[str, Any]) -> dict[str, Any]:
    return LEDGER.append_event(path, event)


def admit(
    *, envelope: dict[str, Any], bindings: dict[str, Any], candidates: list[dict[str, Any]],
    binding_sources: dict[str, Any], repo_root: Path,
    policy: dict[str, Any], ledger_path: Path, now: str, lease_id: str,
    workgraph_claim_token: str, workgraph_fencing_token: int,
    board_max_write_workers: int, config_max_write_workers: int,
    route_fabric_advisory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(lease_id, str) or not lease_id or not isinstance(workgraph_claim_token, str) or not workgraph_claim_token:
        raise ScheduleError("authority_invalid")
    _positive(workgraph_fencing_token, "workgraph_fencing_token")
    scheduler_lock = ledger_path.with_name(ledger_path.name + ".scheduler.lock")
    scheduler_lock.parent.mkdir(parents=True, exist_ok=True)
    with scheduler_lock.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        scheduled = plan(
            envelope=envelope, bindings=bindings, candidates=candidates, policy=policy,
            binding_sources=binding_sources, repo_root=repo_root,
            ledger_path=ledger_path, now=now, board_max_write_workers=board_max_write_workers,
            config_max_write_workers=config_max_write_workers,
            route_fabric_advisory=route_fabric_advisory,
        )
        route = scheduled["selected_route"]
        if route is None:
            raise ScheduleError("no_eligible_route", json.dumps(scheduled["rejected_routes"], sort_keys=True))
        if verify_binding_sources(repo_root, binding_sources, envelope["bindings"]) != scheduled["binding_sources"]:
            raise ScheduleError("binding_source_changed", "between plan and admission")
        broker_ok, broker_reason = _verify_broker_binding(route, repo_root, now)
        if not broker_ok:
            raise ScheduleError("broker_binding_changed", broker_reason)
        if any(row["lease"].get("lease_id") == lease_id for row in LEDGER.verify_ledger(ledger_path)["rows"]):
            raise ScheduleError("lease_id_reused", lease_id)
        instant = _timestamp(now, "now")
        expires_at = (instant + dt.timedelta(seconds=policy["lease_ttl_seconds"])).isoformat().replace("+00:00", "Z")
        previous_tokens = [
            row["lease"].get("fencing_token", 0) for row in LEDGER.verify_ledger(ledger_path)["rows"]
            if row["task_id"] == envelope["task_id"]
        ]
        fence = max([workgraph_fencing_token, *previous_tokens], default=workgraph_fencing_token)
        if fence != workgraph_fencing_token:
            raise ScheduleError("workgraph_fencing_stale", str(workgraph_fencing_token))
        writer = envelope["mutation_mode"] == "scoped_write"
        lease = {
            "lease_id": lease_id, "fencing_token": fence, "workgraph_claim_token": workgraph_claim_token,
            "workgraph_fencing_token": workgraph_fencing_token, "granted_at": now, "expires_at": expires_at,
            "writer": writer,
            "artifact_only": envelope["mutation_mode"] == "artifact_only",
            "write_scopes": (
                sorted(_normalize_scope(path) for path in envelope["scope"]["requested_write"])
                if writer else []
            ),
            "artifact_scopes": (
                sorted(_normalize_scope(path) for path in envelope["scope"]["requested_write"])
                if envelope["mutation_mode"] == "artifact_only" else []
            ),
        }
        route_event = {
            "route_name": route["name"], "provider": route["provider"], "exact_model": route["exact_model"],
            "route_id": route["route_id"], "runtime": route["runtime"], "runtime_host": route["runtime_host"],
            "reasoning": route["reasoning"], "independence_group": route["independence_group"],
            "preflight_key_sha256": route["preflight_key_sha256"],
            "preflight_receipt_digest": route["preflight_observation"].get("receipt_digest"),
        }
        accounting = {
            "allowance_class": envelope["budget"]["allowance_class"],
            "allowance_units_reserved": route["allowance_units"],
            "token_reservation": route["token_reservation"], "observed_tokens": "unknown",
            "observed_cost": "unknown",
        }
        evidence = {
            "output_path": route["evidence_path"], "idempotency_key": envelope["envelope_id"],
            "authority_sha256": bindings["authority_sha256"], "workgraph_sha256": bindings["workgraph_sha256"],
            "supervisor_sha256": bindings["supervisor_sha256"], "plan_sha256": scheduled["plan_sha256"],
        }
        record = _append_under_scheduler_lock(ledger_path, _event(
            envelope, bindings, "lease_granted", now, route=route_event, lease=lease,
            accounting=accounting, evidence=evidence,
        ))
        return {
            **scheduled, "status": "admitted", "lease": lease,
            "reserved_usage": accounting, "observed_usage": {"tokens": "unknown", "cost": "unknown"},
            "ledger_sequence_after": record["sequence"], "ledger_head_after": record["event_hash"],
        }


def _find_active(verified: dict[str, Any], lease_id: str) -> dict[str, Any]:
    active: dict[str, dict[str, Any]] = {}
    for row in verified["rows"]:
        current = row["lease"].get("lease_id")
        if row["event_type"] == "lease_granted" and current:
            active[current] = row
        elif row["event_type"] in TERMINAL_LEASE_EVENTS and current:
            active.pop(current, None)
    if lease_id not in active:
        raise ScheduleError("lease_not_active", lease_id)
    return active[lease_id]


def release(*, ledger_path: Path, lease_id: str, fencing_token: int, now: str) -> dict[str, Any]:
    scheduler_lock = ledger_path.with_name(ledger_path.name + ".scheduler.lock")
    scheduler_lock.parent.mkdir(parents=True, exist_ok=True)
    with scheduler_lock.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        active = _find_active(LEDGER.verify_ledger(ledger_path), lease_id)
        if active["lease"].get("fencing_token") != fencing_token:
            raise ScheduleError("stale_release", lease_id)
        event = {key: copy.deepcopy(active[key]) for key in LEDGER.EVENT_FIELDS}
        event["event_id"] = hashlib.sha256(canonical_json(["release", lease_id, fencing_token, now])).hexdigest()
        event["event_type"] = "lease_released"
        event["timestamp"] = now
        event["lease"]["released_at"] = now
        record = _append_under_scheduler_lock(ledger_path, event)
        return {"schema_version": 1, "status": "released", "lease_id": lease_id, "fencing_token": fencing_token, "ledger_head_after": record["event_hash"]}


def recover(*, ledger_path: Path, lease_id: str, fencing_token: int, now: str) -> dict[str, Any]:
    scheduler_lock = ledger_path.with_name(ledger_path.name + ".scheduler.lock")
    scheduler_lock.parent.mkdir(parents=True, exist_ok=True)
    with scheduler_lock.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        active = _find_active(LEDGER.verify_ledger(ledger_path), lease_id)
        if active["lease"].get("fencing_token") != fencing_token:
            raise ScheduleError("stale_recovery", lease_id)
        if _timestamp(active["lease"]["expires_at"], "lease.expires_at") > _timestamp(now, "now"):
            raise ScheduleError("lease_not_expired", lease_id)
        event = {key: copy.deepcopy(active[key]) for key in LEDGER.EVENT_FIELDS}
        new_fence = fencing_token + 1
        event["event_id"] = hashlib.sha256(canonical_json(["recover", lease_id, new_fence, now])).hexdigest()
        event["event_type"] = "lease_recovered"
        event["timestamp"] = now
        event["lease"]["recovered_at"] = now
        event["lease"]["prior_fencing_token"] = fencing_token
        event["lease"]["fencing_token"] = new_fence
        record = _append_under_scheduler_lock(ledger_path, event)
        return {"schema_version": 1, "status": "recovered", "lease_id": lease_id, "prior_fencing_token": fencing_token, "next_fencing_token": new_fence, "ledger_head_after": record["event_hash"]}


def execution_unknown(*, ledger_path: Path, lease_id: str, fencing_token: int, now: str, reason: str) -> dict[str, Any]:
    if not isinstance(reason, str) or not reason.strip():
        raise ScheduleError("execution_unknown_reason_invalid")
    scheduler_lock = ledger_path.with_name(ledger_path.name + ".scheduler.lock")
    scheduler_lock.parent.mkdir(parents=True, exist_ok=True)
    with scheduler_lock.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        active = _find_active(LEDGER.verify_ledger(ledger_path), lease_id)
        if active["lease"].get("fencing_token") != fencing_token:
            raise ScheduleError("stale_execution_unknown", lease_id)
        event = {key: copy.deepcopy(active[key]) for key in LEDGER.EVENT_FIELDS}
        event["event_id"] = hashlib.sha256(canonical_json(["execution_unknown", lease_id, fencing_token, now, reason])).hexdigest()
        event["event_type"] = "execution_unknown"
        event["timestamp"] = now
        event["evidence"] = {
            **event["evidence"], "execution_unknown_reason": reason,
            "possibly_started": True, "automatic_retry_allowed": False,
        }
        record = _append_under_scheduler_lock(ledger_path, event)
        return {
            "schema_version": 1, "status": "execution_unknown", "lease_id": lease_id,
            "fencing_token": fencing_token, "automatic_retry_allowed": False,
            "ledger_sequence_after": record["sequence"], "ledger_head_after": record["event_hash"],
        }


def _verified_artifact_descriptor(repo_root: Path, value: Any, field: str, artifact_kind: str) -> dict[str, Any]:
    descriptor = _strict(value, field, {"path", "sha256", "size_bytes", "artifact_kind"})
    if descriptor["artifact_kind"] != artifact_kind:
        raise ScheduleError("artifact_descriptor_kind_mismatch", field)
    _positive(descriptor["size_bytes"], f"{field}.size_bytes", allow_zero=True)
    verified = _verified_file_descriptor(
        repo_root, {"path": descriptor["path"], "sha256": descriptor["sha256"]}, field,
    )
    if verified["size_bytes"] != descriptor["size_bytes"]:
        raise ScheduleError("artifact_descriptor_size_mismatch", field)
    try:
        artifact = json.loads((repo_root.resolve(strict=True) / descriptor["path"]).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScheduleError("artifact_descriptor_content_invalid", field) from exc
    if not isinstance(artifact, dict) or artifact.get("schema_version") != 1:
        raise ScheduleError("artifact_descriptor_schema_mismatch", field)
    kind_checks = {
        "DispatchReturnManifest": ("manifest_type", "DispatchReturnManifest"),
        "SupervisorEventBundle": ("bundle_type", "SupervisorEventBundle"),
    }
    if artifact_kind in kind_checks:
        kind_field, expected_kind = kind_checks[artifact_kind]
        if artifact.get(kind_field) != expected_kind:
            raise ScheduleError("artifact_descriptor_content_kind_mismatch", field)
    elif artifact_kind == "ArtifactQualityReceipt":
        required = {
            "policy_id", "artifact", "checks_executed", "arbitrary_commands_executed",
            "model_judgment_used", "accepted", "findings", "receipt_sha256",
        }
        if not required.issubset(artifact):
            raise ScheduleError("artifact_descriptor_content_kind_mismatch", field)
        supplied_receipt_digest = artifact.get("receipt_sha256")
        receipt_payload = copy.deepcopy(artifact)
        receipt_payload.pop("receipt_sha256", None)
        if supplied_receipt_digest != digest(receipt_payload, prefixed=False):
            raise ScheduleError("quality_receipt_digest_mismatch", field)
    return {**descriptor, "sha256": verified["sha256"]}


def schedule_manifest(
    *, admission: dict[str, Any], repo_root: Path, ledger_path: Path,
    return_manifest: dict[str, Any], quality_receipt: dict[str, Any],
    supervisor_event_bundle: dict[str, Any],
    visible_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    required_admission = {
        "plan_sha256", "envelope_sha256", "identity", "bindings", "lease", "selected_route",
        "ledger_head_before", "ledger_head_after", "ledger_sequence_before", "ledger_sequence_after",
        "reserved_usage", "observed_usage",
    }
    if not isinstance(admission, dict) or any(field not in admission for field in required_admission):
        raise ScheduleError("admission_invalid", "manifest binding fields missing")
    if (
        admission.get("schema_version") != 1
        or admission.get("artifact_type") != "DispatchSchedulePlan"
        or admission.get("status") != "admitted"
    ):
        raise ScheduleError("admission_invalid", "admitted DispatchSchedulePlan v1 required")
    _raw_sha(admission["plan_sha256"], "plan_sha256")
    _raw_sha(admission["envelope_sha256"], "envelope_sha256")
    identity = _strict(admission["identity"], "identity", {"goal_id", "checkpoint_id", "task_id", "assignment_id"})
    bindings = _strict(admission["bindings"], "bindings", {f"{name}_sha256" for name in BINDING_NAMES})
    for field, value in bindings.items():
        _raw_sha(value, field)
    before_sequence = admission["ledger_sequence_before"]
    after_sequence = admission["ledger_sequence_after"]
    if not isinstance(before_sequence, int) or isinstance(before_sequence, bool) or not isinstance(after_sequence, int) or isinstance(after_sequence, bool) or after_sequence != before_sequence + 1:
        raise ScheduleError("admission_ledger_range_invalid")
    verified_ledger = LEDGER.verify_ledger(ledger_path)
    if after_sequence > verified_ledger["event_count"]:
        raise ScheduleError("admission_ledger_range_invalid")
    after_row = verified_ledger["rows"][after_sequence - 1]
    expected_before_head = LEDGER.ZERO_HASH if before_sequence == 0 else verified_ledger["rows"][before_sequence - 1]["event_hash"]
    if admission["ledger_head_before"] != expected_before_head or admission["ledger_head_after"] != after_row["event_hash"]:
        raise ScheduleError("admission_ledger_head_mismatch")
    if (
        after_row["event_type"] != "lease_granted"
        or after_row["envelope_sha256"] != admission["envelope_sha256"]
        or after_row["config_sha256"] != bindings["config_sha256"]
        or after_row["board_sha256"] != bindings["board_sha256"]
        or any(after_row[field] != identity[field] for field in ("goal_id", "checkpoint_id", "task_id", "assignment_id"))
    ):
        raise ScheduleError("admission_ledger_binding_mismatch")
    plan_fields = {
        "schema_version", "artifact_type", "created_at", "envelope_sha256", "identity",
        "bindings", "ledger_head_before", "binding_sources", "ledger_sequence_before",
        "eligible_routes", "rejected_routes", "selected_route", "provider_call_started",
    }
    if not plan_fields.issubset(admission):
        raise ScheduleError("admission_invalid", "plan fields missing")
    plan_payload = {field: copy.deepcopy(admission[field]) for field in plan_fields}
    if digest(plan_payload) != admission["plan_sha256"]:
        raise ScheduleError("admission_plan_digest_mismatch")
    if admission["lease"] != after_row["lease"]:
        raise ScheduleError("admission_lease_binding_mismatch")
    selected = admission["selected_route"]
    if not isinstance(selected, dict):
        raise ScheduleError("admission_route_binding_mismatch")
    try:
        expected_adapter_id, expected_adapter_sha256 = CANDIDATE._adapter_evidence(selected)
    except CANDIDATE.CandidateError as exc:
        raise ScheduleError("admission_adapter_evidence_invalid", exc.code) from exc
    if (
        selected.get("adapter_id") != expected_adapter_id
        or selected.get("adapter_sha256") != expected_adapter_sha256
    ):
        raise ScheduleError("admission_adapter_identity_mismatch", selected.get("name", "unknown"))
    route_fields = {
        "name": "route_name", "provider": "provider", "exact_model": "exact_model",
        "route_id": "route_id", "runtime": "runtime", "runtime_host": "runtime_host",
        "reasoning": "reasoning", "independence_group": "independence_group",
        "preflight_key_sha256": "preflight_key_sha256",
    }
    if any(selected.get(source) != after_row["route"].get(target) for source, target in route_fields.items()):
        raise ScheduleError("admission_route_binding_mismatch")
    if (
        after_row["route"].get("preflight_receipt_digest")
        != selected.get("preflight_observation", {}).get("receipt_digest")
        or after_row["evidence"].get("output_path") != selected.get("evidence_path")
        or after_row["evidence"].get("plan_sha256") != admission["plan_sha256"]
        or after_row["evidence"].get("authority_sha256") != bindings["authority_sha256"]
        or after_row["evidence"].get("workgraph_sha256") != bindings["workgraph_sha256"]
        or after_row["evidence"].get("supervisor_sha256") != bindings["supervisor_sha256"]
        or admission["reserved_usage"] != after_row["accounting"]
    ):
        raise ScheduleError("admission_evidence_binding_mismatch")
    descriptors = {
        "return_manifest": _verified_artifact_descriptor(repo_root, return_manifest, "return_manifest", "DispatchReturnManifest"),
        "quality_receipt": _verified_artifact_descriptor(repo_root, quality_receipt, "quality_receipt", "ArtifactQualityReceipt"),
        "supervisor_event_bundle": _verified_artifact_descriptor(repo_root, supervisor_event_bundle, "supervisor_event_bundle", "SupervisorEventBundle"),
    }
    try:
        returned = json.loads(
            (repo_root.resolve(strict=True) / descriptors["return_manifest"]["path"])
            .read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScheduleError("return_manifest_identity_unreadable") from exc
    dispatch_id = returned.get("dispatch_id") if isinstance(returned, dict) else None
    semantic_role = returned.get("semantic_role") if isinstance(returned, dict) else None
    bound_visible_identity = None
    if visible_identity is not None:
        bound_visible_identity = _strict(
            visible_identity, "visible_identity", {"dispatch_id", "semantic_role"}
        )
        if (
            not isinstance(dispatch_id, str)
            or not dispatch_id.strip()
            or bound_visible_identity["dispatch_id"] != dispatch_id
        ):
            raise ScheduleError("return_manifest_identity_invalid", "dispatch_id")
        if (
            semantic_role not in RESOLVER._config.ROLE_NAMES
            or bound_visible_identity["semantic_role"] != semantic_role
        ):
            raise ScheduleError("return_manifest_identity_invalid", "semantic_role")
    result = {
        "schema_version": 1, "artifact_type": "DispatchScheduleManifest",
        "schedule_plan_sha256": admission.get("plan_sha256"),
        "envelope_sha256": admission["envelope_sha256"],
        "identity": copy.deepcopy(identity),
        "bindings": copy.deepcopy(bindings),
        "lease": copy.deepcopy(admission.get("lease")),
        "selected_route": {
            key: copy.deepcopy(value) for key, value in admission["selected_route"].items()
            if key not in {"preflight_observation", "resolver_packet"}
        },
        "ledger": {
            "sequence_start": admission["ledger_sequence_before"] + 1,
            "sequence_end": admission["ledger_sequence_after"],
            "head_before": admission["ledger_head_before"], "head_after": admission["ledger_head_after"],
        },
        "usage": {"reserved": copy.deepcopy(admission["reserved_usage"]), "observed": copy.deepcopy(admission["observed_usage"])},
        **descriptors,
        "transport_succeeded": False, "quality_accepted": False,
        "supervisor_applied": False, "goalbuddy_applied": False, "accepted": False,
    }
    if bound_visible_identity is not None:
        result["visible_identity"] = copy.deepcopy(bound_visible_identity)
    result["manifest_sha256"] = digest(result)
    return result


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScheduleError("input_unreadable", str(path)) from exc


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--binding-sources", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--now", required=True)
    parser.add_argument("--board-max-write-workers", type=int, required=True)
    parser.add_argument("--config-max-write-workers", type=int, required=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan_parser = commands.add_parser("plan"); _common(plan_parser)
    admit_parser = commands.add_parser("admit"); _common(admit_parser)
    admit_parser.add_argument("--lease-id", required=True); admit_parser.add_argument("--workgraph-claim-token", required=True); admit_parser.add_argument("--workgraph-fencing-token", type=int, required=True)
    for name in ("release", "recover", "execution_unknown"):
        child = commands.add_parser(name); child.add_argument("--ledger", type=Path, required=True); child.add_argument("--lease-id", required=True); child.add_argument("--fencing-token", type=int, required=True); child.add_argument("--now", required=True)
    commands.choices["execution_unknown"].add_argument("--reason", required=True)
    manifest_parser = commands.add_parser("manifest"); manifest_parser.add_argument("--admission", type=Path, required=True); manifest_parser.add_argument("--repo-root", type=Path, required=True); manifest_parser.add_argument("--ledger", type=Path, required=True); manifest_parser.add_argument("--return-manifest", type=Path, required=True); manifest_parser.add_argument("--quality-receipt", type=Path, required=True); manifest_parser.add_argument("--supervisor-event-bundle", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in {"plan", "admit"}:
            kwargs = dict(envelope=_read(args.envelope), bindings=_read(args.bindings), binding_sources=_read(args.binding_sources), repo_root=args.repo_root, candidates=_read(args.candidates), policy=_read(args.policy), ledger_path=args.ledger, now=args.now, board_max_write_workers=args.board_max_write_workers, config_max_write_workers=args.config_max_write_workers)
            result = plan(**kwargs) if args.command == "plan" else admit(**kwargs, lease_id=args.lease_id, workgraph_claim_token=args.workgraph_claim_token, workgraph_fencing_token=args.workgraph_fencing_token)
        elif args.command in {"release", "recover"}:
            result = (release if args.command == "release" else recover)(ledger_path=args.ledger, lease_id=args.lease_id, fencing_token=args.fencing_token, now=args.now)
        elif args.command == "execution_unknown":
            result = execution_unknown(ledger_path=args.ledger, lease_id=args.lease_id, fencing_token=args.fencing_token, now=args.now, reason=args.reason)
        else:
            result = schedule_manifest(admission=_read(args.admission), repo_root=args.repo_root, ledger_path=args.ledger, return_manifest=_read(args.return_manifest), quality_receipt=_read(args.quality_receipt), supervisor_event_bundle=_read(args.supervisor_event_bundle))
    except (ScheduleError, LEDGER.LedgerError, BROKER.PreflightBrokerError) as exc:
        code = getattr(exc, "code", "scheduler_error")
        print(json.dumps({"status": "rejected", "error": code, "detail": getattr(exc, "detail", str(exc))}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
