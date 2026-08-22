#!/usr/bin/env python3
"""Deterministic, side-effect-free route planning and child-plan preview.

The planner consumes snapshots accepted by ``runtime_adapter.py``.  It exposes
every route, applies hard gates before weights, and previews (but never admits,
dispatches, or executes) one bounded v1 child.
"""

from __future__ import annotations

from datetime import datetime
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


PLANNER_VERSION = 1
REQUEST_TYPE = "runtime_planner_request_v1"
CASES_TYPE = "runtime_planner_cases_v1"
AUTHORITY_DOMAIN = "codexmax-runtime-planning-authority-v1"
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

ROOT_FIELDS = {
    "planner_version", "artifact_type", "workspace_id", "adapter_snapshot",
    "role_policy", "task", "planning_authority", "child_preview",
}
ROLE_FIELDS = {
    "role_id", "required_capabilities", "allowed_route_ids",
    "allowed_billing_bases", "max_external_cost_microunits",
    "affinity_weights",
}
TASK_FIELDS = {
    "task_id", "source_scope_sha256", "task_profile_sha256",
    "evaluation_manifest_sha256", "required_capabilities",
    "required_route_id", "fallback_requested",
}
AUTHORITY_FIELDS = {
    "authority_id", "workspace_id", "task_id", "source_scope_sha256",
    "issued_at", "expires_at", "revoked", "allowed_route_ids",
    "allowed_capabilities", "allowed_billing_bases", "fallback_allowed",
    "max_external_cost_microunits", "authority_sha256",
}
AUTHORITY_VIEW_FIELDS = {
    "scope_paths", "tools", "effects", "disclosure_refs", "providers",
    "billing_bases", "route_ids", "network_access", "egress_allowed",
    "fallback_allowed", "retention_seconds",
}
PARENT_FIELDS = {
    "run_id", "root_run_id", "workspace_id", "depth", "ancestor_run_ids",
    "total_children", "active_children", "active_descendants", "authority",
    "remaining_limits",
}
CHILD_FIELDS = {
    "run_id", "parent_run_id", "root_run_id", "workspace_id", "depth",
    "route_id", "cycle_check", "authority", "limits",
}
LIMIT_FIELDS = {
    "attempts", "runtime_seconds", "uninterrupted_action_seconds", "tokens",
    "disclosure_bytes", "journal_messages", "message_bytes", "ttl_seconds",
    "external_cost_microunits",
}
SET_AUTHORITY_FIELDS = {
    "scope_paths", "tools", "effects", "disclosure_refs", "providers",
    "billing_bases", "route_ids",
}
V1_MAXIMA = {
    "depth": 1,
    "total_children": 1,
    "active_children": 1,
    "active_descendants": 1,
}
V1_CHILD_LIMIT_MAXIMA = {
    "attempts": 1,
    "runtime_seconds": 300,
    "uninterrupted_action_seconds": 60,
    "tokens": 10000,
    "disclosure_bytes": 32768,
    "journal_messages": 10,
    "message_bytes": 2048,
    "ttl_seconds": 1800,
    "external_cost_microunits": 0,
}


class PlannerError(ValueError):
    """Stable typed failure for malformed planner input."""

    def __init__(self, code: str, path: str):
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def _load_adapter_module() -> Any:
    path = Path(__file__).with_name("runtime_adapter.py")
    spec = importlib.util.spec_from_file_location("codexmax_runtime_adapter", path)
    if spec is None or spec.loader is None:
        raise PlannerError("adapter_module_unavailable", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ADAPTER = _load_adapter_module()


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PlannerError("object_required", path)
    unknown = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if unknown:
        raise PlannerError("unknown_field", f"{path}.{unknown[0]}")
    if missing:
        raise PlannerError("missing_field", f"{path}.{missing[0]}")
    return value


def _identifier(value: Any, path: str, *, none_allowed: bool = False) -> str:
    if none_allowed and value == "none":
        return value
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise PlannerError("identifier_invalid", path)
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise PlannerError("digest_invalid", path)
    return value


def _boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise PlannerError("boolean_required", path)
    return value


def _integer(value: Any, path: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise PlannerError("integer_invalid", path)
    return value


def _timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise PlannerError("timestamp_invalid", path)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PlannerError("timestamp_invalid", path) from exc


def _string_array(value: Any, path: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise PlannerError("array_required", path)
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_identifier(item, f"{path}[{index}]"))
    if len(result) != len(set(result)):
        raise PlannerError("array_duplicate", path)
    return result


def _portable_path_array(value: Any, path: str) -> list[str]:
    if not isinstance(value, list):
        raise PlannerError("array_required", path)
    result: list[str] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, str) or not item or "\\" in item or "%" in item:
            raise PlannerError("scope_path_invalid", item_path)
        parts = item.split("/")
        if item.startswith("/") or any(part in {"", ".", ".."} for part in parts):
            raise PlannerError("scope_path_invalid", item_path)
        result.append(item)
    if len(result) != len(set(result)):
        raise PlannerError("array_duplicate", path)
    return result


def _authority_digest(authority: Mapping[str, Any]) -> str:
    body = {key: copy.deepcopy(value) for key, value in authority.items() if key != "authority_sha256"}
    return ADAPTER.canonical_digest({"domain": AUTHORITY_DOMAIN, "authority": body})


def _validate_role(value: Any) -> dict[str, Any]:
    role = _closed(value, ROLE_FIELDS, "$.role_policy")
    _identifier(role["role_id"], "$.role_policy.role_id")
    required = _string_array(role["required_capabilities"], "$.role_policy.required_capabilities")
    allowed_routes = _string_array(role["allowed_route_ids"], "$.role_policy.allowed_route_ids", nonempty=True)
    billing = _string_array(role["allowed_billing_bases"], "$.role_policy.allowed_billing_bases", nonempty=True)
    if not set(billing) <= {"free", "subscription", "metered"}:
        raise PlannerError("billing_basis_invalid", "$.role_policy.allowed_billing_bases")
    _integer(role["max_external_cost_microunits"], "$.role_policy.max_external_cost_microunits")
    weights = role["affinity_weights"]
    if not isinstance(weights, dict) or set(weights) != set(allowed_routes):
        raise PlannerError("affinity_weight_route_set_mismatch", "$.role_policy.affinity_weights")
    for route_id, weight in weights.items():
        _identifier(route_id, f"$.role_policy.affinity_weights.{route_id}")
        _integer(weight, f"$.role_policy.affinity_weights.{route_id}")
    if not required:
        raise PlannerError("capability_requirement_missing", "$.role_policy.required_capabilities")
    return role


def _validate_task(value: Any) -> dict[str, Any]:
    task = _closed(value, TASK_FIELDS, "$.task")
    _identifier(task["task_id"], "$.task.task_id")
    for field in ("source_scope_sha256", "task_profile_sha256", "evaluation_manifest_sha256"):
        _digest(task[field], f"$.task.{field}")
    _string_array(task["required_capabilities"], "$.task.required_capabilities", nonempty=True)
    _identifier(task["required_route_id"], "$.task.required_route_id", none_allowed=True)
    _boolean(task["fallback_requested"], "$.task.fallback_requested")
    return task


def _validate_authority(value: Any, evaluated_at: datetime) -> dict[str, Any]:
    authority = _closed(copy.deepcopy(value), AUTHORITY_FIELDS, "$.planning_authority")
    for field in ("authority_id", "workspace_id", "task_id"):
        _identifier(authority[field], f"$.planning_authority.{field}")
    _digest(authority["source_scope_sha256"], "$.planning_authority.source_scope_sha256")
    issued = _timestamp(authority["issued_at"], "$.planning_authority.issued_at")
    expires = _timestamp(authority["expires_at"], "$.planning_authority.expires_at")
    _boolean(authority["revoked"], "$.planning_authority.revoked")
    _string_array(authority["allowed_route_ids"], "$.planning_authority.allowed_route_ids", nonempty=True)
    _string_array(authority["allowed_capabilities"], "$.planning_authority.allowed_capabilities", nonempty=True)
    billing = _string_array(authority["allowed_billing_bases"], "$.planning_authority.allowed_billing_bases", nonempty=True)
    if not set(billing) <= {"free", "subscription", "metered"}:
        raise PlannerError("billing_basis_invalid", "$.planning_authority.allowed_billing_bases")
    _boolean(authority["fallback_allowed"], "$.planning_authority.fallback_allowed")
    _integer(authority["max_external_cost_microunits"], "$.planning_authority.max_external_cost_microunits")
    _digest(authority["authority_sha256"], "$.planning_authority.authority_sha256")
    if expires <= issued:
        raise PlannerError("authority_window_invalid", "$.planning_authority")
    if authority["authority_sha256"] != _authority_digest(authority):
        raise PlannerError("authority_digest_mismatch", "$.planning_authority.authority_sha256")
    authority["_active"] = issued <= evaluated_at < expires and not authority["revoked"]
    return authority


def _gate(code: str, passed: bool) -> dict[str, Any]:
    return {"code": code, "passed": bool(passed)}


def _validate_authority_view(value: Any, path: str) -> dict[str, Any]:
    row = _closed(value, AUTHORITY_VIEW_FIELDS, path)
    row["scope_paths"] = _portable_path_array(row["scope_paths"], f"{path}.scope_paths")
    for field in SET_AUTHORITY_FIELDS - {"scope_paths"}:
        row[field] = _string_array(row[field], f"{path}.{field}")
    for field in ("network_access", "egress_allowed", "fallback_allowed"):
        _boolean(row[field], f"{path}.{field}")
    _integer(row["retention_seconds"], f"{path}.retention_seconds")
    return row


def _validate_limits(value: Any, path: str) -> dict[str, int]:
    row = _closed(value, LIMIT_FIELDS, path)
    for field in LIMIT_FIELDS:
        _integer(row[field], f"{path}.{field}", minimum=0 if field == "external_cost_microunits" else 1)
    return row


def preview_child(value: Any, *, workspace_id: str, eligible_route_ids: set[str]) -> dict[str, Any]:
    """Return a denial-complete preview; malformed or unknown limits never pass."""
    reasons: list[str] = []
    if value == "none":
        return {"requested": False, "admissible": False, "reasons": ["child_preview_not_requested"], "child_run_id": None, "route_id": None}
    if not isinstance(value, dict):
        return {"requested": True, "admissible": False, "reasons": ["child_preview_object_required"], "child_run_id": None, "route_id": None}
    unknown = sorted(set(value) - {"parent", "child"})
    missing = sorted({"parent", "child"} - set(value))
    reasons.extend(f"child_preview_unknown_field:{field}" for field in unknown)
    reasons.extend(f"child_preview_missing_field:{field}" for field in missing)
    if reasons:
        return {"requested": True, "admissible": False, "reasons": reasons, "child_run_id": None, "route_id": None}
    try:
        parent = _closed(copy.deepcopy(value["parent"]), PARENT_FIELDS, "$.child_preview.parent")
        child = _closed(copy.deepcopy(value["child"]), CHILD_FIELDS, "$.child_preview.child")
        for field in ("run_id", "root_run_id", "workspace_id"):
            _identifier(parent[field], f"$.child_preview.parent.{field}")
        for field in ("run_id", "parent_run_id", "root_run_id", "workspace_id", "route_id"):
            _identifier(child[field], f"$.child_preview.child.{field}")
        ancestors = _string_array(parent["ancestor_run_ids"], "$.child_preview.parent.ancestor_run_ids")
        for field in ("depth", "total_children", "active_children", "active_descendants"):
            _integer(parent[field], f"$.child_preview.parent.{field}")
        _integer(child["depth"], "$.child_preview.child.depth")
        _boolean(child["cycle_check"], "$.child_preview.child.cycle_check")
        parent_authority = _validate_authority_view(parent["authority"], "$.child_preview.parent.authority")
        child_authority = _validate_authority_view(child["authority"], "$.child_preview.child.authority")
        remaining = _validate_limits(parent["remaining_limits"], "$.child_preview.parent.remaining_limits")
        limits = _validate_limits(child["limits"], "$.child_preview.child.limits")
    except PlannerError as exc:
        return {"requested": True, "admissible": False, "reasons": [f"{exc.code}:{exc.path}"], "child_run_id": value.get("child", {}).get("run_id") if isinstance(value.get("child"), dict) else None, "route_id": value.get("child", {}).get("route_id") if isinstance(value.get("child"), dict) else None}

    if parent["workspace_id"] != workspace_id or child["workspace_id"] != workspace_id:
        reasons.append("child_workspace_mismatch")
    cycle = (
        child["run_id"] in set(ancestors) | {parent["run_id"], parent["root_run_id"]}
        or child["parent_run_id"] != parent["run_id"]
        or child["root_run_id"] != parent["root_run_id"]
        or not child["cycle_check"]
    )
    if cycle:
        reasons.append("child_lineage_cycle_or_mismatch")
    if parent["depth"] != 0 or child["depth"] != parent["depth"] + 1 or child["depth"] > V1_MAXIMA["depth"]:
        reasons.append("child_depth_exceeded")
    if parent["total_children"] + 1 > V1_MAXIMA["total_children"]:
        reasons.append("child_fanout_exceeded")
    if parent["active_children"] + 1 > V1_MAXIMA["active_children"] or parent["active_descendants"] + 1 > V1_MAXIMA["active_descendants"]:
        reasons.append("child_concurrency_exceeded")
    for field in sorted(SET_AUTHORITY_FIELDS):
        if not set(child_authority[field]) <= set(parent_authority[field]):
            reasons.append(f"child_authority_widened:{field}")
    for field in ("network_access", "egress_allowed", "fallback_allowed"):
        if child_authority[field] and not parent_authority[field]:
            reasons.append(f"child_authority_widened:{field}")
    if child_authority["retention_seconds"] > parent_authority["retention_seconds"]:
        reasons.append("child_authority_widened:retention_seconds")
    if child["route_id"] not in set(child_authority["route_ids"]):
        reasons.append("child_route_not_authorized")
    if child["route_id"] not in eligible_route_ids:
        reasons.append("child_route_unavailable")
    for field in sorted(LIMIT_FIELDS):
        if limits[field] > remaining[field] or limits[field] > V1_CHILD_LIMIT_MAXIMA[field]:
            reasons.append(f"child_limit_exceeded:{field}")
    return {
        "requested": True,
        "admissible": not reasons,
        "reasons": reasons or ["child_preview_all_gates_passed"],
        "child_run_id": child["run_id"],
        "route_id": child["route_id"],
    }


def plan(request: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one request and return a deterministic non-authoritative plan."""
    original = copy.deepcopy(request)
    root = _closed(request, ROOT_FIELDS, "$")
    if type(root["planner_version"]) is not int or root["planner_version"] != PLANNER_VERSION:
        raise PlannerError("version_unsupported", "$.planner_version")
    if root["artifact_type"] != REQUEST_TYPE:
        raise PlannerError("artifact_type_invalid", "$.artifact_type")
    workspace_id = _identifier(root["workspace_id"], "$.workspace_id")
    role = _validate_role(root["role_policy"])
    task = _validate_task(root["task"])
    try:
        adapter_receipt = ADAPTER.validate_adapter_snapshot(root["adapter_snapshot"])
    except ADAPTER.AdapterSnapshotError as exc:
        raise PlannerError(f"adapter_{exc.code}", exc.path) from exc
    evaluated_at = _timestamp(root["adapter_snapshot"]["evaluated_at"], "$.adapter_snapshot.evaluated_at")
    authority = _validate_authority(root["planning_authority"], evaluated_at)

    capabilities_required = sorted(set(role["required_capabilities"]) | set(task["required_capabilities"]))
    identities = {row["adapter_identity_sha256"]: row for row in root["adapter_snapshot"]["route_snapshots"]}
    adapters = {row["adapter_identity_sha256"]: row for row in root["adapter_snapshot"]["adapter_snapshots"]}
    health = {row["adapter_identity_sha256"]: row for row in root["adapter_snapshot"]["health_snapshots"]}
    billing = {row["adapter_identity_sha256"]: row for row in root["adapter_snapshot"]["billing_snapshots"]}
    conformance = {row["adapter_identity_sha256"]: row for row in root["adapter_snapshot"]["conformance_snapshots"]}
    capabilities: dict[tuple[str, str], dict[str, Any]] = {}
    for row in root["adapter_snapshot"]["capability_snapshots"]:
        capabilities[(row["adapter_identity_sha256"], row["capability_id"])] = row

    candidates: list[dict[str, Any]] = []
    for digest, route in sorted(identities.items(), key=lambda item: (item[1]["identity"]["route_id"], item[0])):
        identity = route["identity"]
        route_id = identity["route_id"]
        cap_rows = [capabilities.get((digest, capability)) for capability in capabilities_required]
        task_bound = all(
            row is not None
            and row["task_profile_sha256"] == task["task_profile_sha256"]
            and row["evaluation_manifest_sha256"] == task["evaluation_manifest_sha256"]
            for row in cap_rows
        )
        proof = all(
            row is not None
            and row["provenance"] == "observed"
            and row["polarity"] == "positive"
            and row["derived_state"] == "active"
            and row["proof_usable"] is True
            and row["contradiction_evidence_sha256"] == "none"
            and row["invalidation_evidence_sha256"] == "none"
            and row["recall_evidence_sha256"] == "none"
            and evaluated_at < _timestamp(row["expires_at"], "capability.expires_at")
            for row in cap_rows
        )
        authority_bound = (
            authority["_active"]
            and authority["workspace_id"] == workspace_id
            and authority["task_id"] == task["task_id"]
            and authority["source_scope_sha256"] == task["source_scope_sha256"]
            and route_id in authority["allowed_route_ids"]
            and set(capabilities_required) <= set(authority["allowed_capabilities"])
        )
        role_route = route_id in role["allowed_route_ids"] and (
            task["required_route_id"] == "none" or route_id == task["required_route_id"]
        )
        basis = billing[digest]["basis"]
        billing_ok = (
            basis != "unknown"
            and basis != "metered"
            and basis in role["allowed_billing_bases"]
            and basis in authority["allowed_billing_bases"]
            and role["max_external_cost_microunits"] <= authority["max_external_cost_microunits"]
        )
        fallback_ok = not task["fallback_requested"] or authority["fallback_allowed"]
        health_ok = (
            health[digest]["status"] == "healthy"
            and health[digest]["provenance"] == "observed"
            and health[digest]["fresh"] is True
            and evaluated_at < _timestamp(health[digest]["expires_at"], "health.expires_at")
        )
        gates = [
            _gate("identity_and_schema_valid", True),
            _gate("route_visible", route["visible"] is True and adapters[digest]["declared_visible"] is True),
            _gate("adapter_conformant", conformance[digest]["conformant"] is True),
            _gate("task_evidence_exactly_bound", task_bound),
            _gate("observed_positive_active_fresh_capability", proof),
            _gate("planning_authority_active_and_bound", authority_bound),
            _gate("role_and_route_compatible", role_route),
            _gate("billing_within_ceilings", billing_ok),
            _gate("fallback_within_ceiling", fallback_ok),
            _gate("health_observed_healthy_fresh", health_ok),
        ]
        eligible = all(gate["passed"] for gate in gates)
        reasons = [gate["code"] for gate in gates if not gate["passed"]]
        candidates.append({
            "route_id": route_id,
            "adapter_identity_sha256": digest,
            "identity": copy.deepcopy(identity),
            "visible": bool(route["visible"]),
            "eligible": eligible,
            "hard_gates": gates,
            "reasons": reasons or ["eligible_all_hard_gates_passed"],
            "weight": role["affinity_weights"][route_id] if eligible else None,
            "rank": None,
        })

    eligible = sorted(
        (candidate for candidate in candidates if candidate["eligible"]),
        key=lambda candidate: (-candidate["weight"], candidate["route_id"], candidate["adapter_identity_sha256"]),
    )
    for rank, candidate in enumerate(eligible, start=1):
        candidate["rank"] = rank
    selected = eligible[0] if eligible else None
    preview = preview_child(
        root["child_preview"],
        workspace_id=workspace_id,
        eligible_route_ids={candidate["route_id"] for candidate in eligible},
    )
    if request != original:
        raise PlannerError("input_mutated", "$")
    return {
        "artifact_type": "runtime_plan_result_v1",
        "planner_version": PLANNER_VERSION,
        "workspace_id": workspace_id,
        "request_sha256": ADAPTER.canonical_digest(request),
        "adapter_snapshot_sha256": adapter_receipt["snapshot_sha256"],
        "role_id": role["role_id"],
        "task_id": task["task_id"],
        "candidates": candidates,
        "selected": None if selected is None else {
            "route_id": selected["route_id"],
            "adapter_identity_sha256": selected["adapter_identity_sha256"],
            "weight": selected["weight"],
            "rank": selected["rank"],
        },
        "child_preview": preview,
        "execution_started": False,
        "provider_called": False,
        "authority_granted": False,
        "child_dispatched": False,
        "acceptance_granted": False,
        "side_effect_free": True,
    }


def load_json(path: str | Path) -> Any:
    try:
        return ADAPTER.load_snapshot(path)
    except ADAPTER.AdapterSnapshotError as exc:
        raise PlannerError(exc.code, exc.path) from exc


def run_cases(document: Any, source: Path) -> dict[str, Any]:
    root = _closed(document, {"schema_version", "artifact_type", "adapter_snapshot_path", "cases"}, "$")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise PlannerError("version_unsupported", "$.schema_version")
    if root["artifact_type"] != CASES_TYPE:
        raise PlannerError("artifact_type_invalid", "$.artifact_type")
    if not isinstance(root["adapter_snapshot_path"], str) or not root["adapter_snapshot_path"]:
        raise PlannerError("string_required", "$.adapter_snapshot_path")
    adapter_path = (source.parent / root["adapter_snapshot_path"]).resolve()
    adapter_snapshot = load_json(adapter_path)
    if not isinstance(root["cases"], list) or not root["cases"]:
        raise PlannerError("array_required", "$.cases")
    results = []
    names: set[str] = set()
    for index, item in enumerate(root["cases"]):
        path = f"$.cases[{index}]"
        case = _closed(item, {"name", "request", "expected_selected_route_id", "expected_child_admissible"}, path)
        name = _identifier(case["name"], f"{path}.name")
        if name in names:
            raise PlannerError("case_name_duplicate", f"{path}.name")
        names.add(name)
        request = copy.deepcopy(case["request"])
        if not isinstance(request, dict):
            raise PlannerError("object_required", f"{path}.request")
        request["adapter_snapshot"] = copy.deepcopy(adapter_snapshot)
        result = plan(request)
        expected_route = case["expected_selected_route_id"]
        if expected_route is not None:
            _identifier(expected_route, f"{path}.expected_selected_route_id")
        expected_child = _boolean(case["expected_child_admissible"], f"{path}.expected_child_admissible")
        actual_route = None if result["selected"] is None else result["selected"]["route_id"]
        passed = actual_route == expected_route and result["child_preview"]["admissible"] == expected_child
        results.append({
            "name": name,
            "passed": passed,
            "selected_route_id": actual_route,
            "child_admissible": result["child_preview"]["admissible"],
            "result_sha256": ADAPTER.canonical_digest(result),
        })
    return {
        "artifact_type": "runtime_planner_cases_receipt_v1",
        "valid": all(row["passed"] for row in results),
        "case_count": len(results),
        "cases": results,
        "execution_started": False,
        "provider_called": False,
        "authority_granted": False,
        "child_dispatched": False,
        "acceptance_granted": False,
        "side_effect_free": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args(argv)
    try:
        document = load_json(args.input)
        result = run_cases(document, args.input) if isinstance(document, dict) and document.get("artifact_type") == CASES_TYPE else plan(document)
    except (PlannerError, OSError) as exc:
        if isinstance(exc, PlannerError):
            failure = {"status": "fail", "code": exc.code, "path": exc.path}
        else:
            failure = {"status": "fail", "code": "planner_input_read_failed", "path": str(args.input)}
        print(json.dumps(failure, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("valid", True) else 1


if __name__ == "__main__":
    sys.exit(main())
