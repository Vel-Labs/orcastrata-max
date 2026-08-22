#!/usr/bin/env python3
"""Compile and reconcile bounded provider fan-out without calling providers.

The one-provider dispatcher remains one-attempt. This controller only creates
independent lane plans. It can replace a lane attempt after a classified
pre-provider failure. Parent review remains external to this module.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
MAX_LANES = 8
MAX_ATTEMPTS = 3
MUTATION_MODES = {"read_only", "artifact_only", "scoped_write"}
PRE_PROVIDER_RETRY_CLASSES = {
    "lease_expired_before_spawn",
    "preflight_expired_before_spawn",
    "protected_capability_expired_before_spawn",
    "evidence_collision_before_claim",
}
FINAL_STATUSES = {"candidate_ready", "rejected", "pending", "execution_unknown"}
AUDIT_STATUSES = {"not_run", "passed", "failed"}
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def _load_reconciler() -> Any:
    path = Path(__file__).with_name("reconcile_visible_provider_result.py")
    spec = importlib.util.spec_from_file_location("codexmax_provider_fanout_reconciler", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RECONCILER = _load_reconciler()


def _load_sibling(name: str) -> Any:
    path = Path(__file__).with_name(name)
    spec = importlib.util.spec_from_file_location(f"codexmax_provider_fanout_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


AUTHORITY = _load_sibling("provider_work_authority.py")


class FanoutError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FanoutError("duplicate_json_key", key)
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FanoutError("invalid_json", str(path)) from exc
    if not isinstance(value, dict):
        raise FanoutError("invalid_document", "top level must be an object")
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_value(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _strict(value: Any, field: str, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FanoutError("invalid_field", f"{field} must be an object")
    optional = optional or set()
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required - optional)
    if missing:
        raise FanoutError("missing_field", f"{field}: {', '.join(missing)}")
    if unknown:
        raise FanoutError("unknown_field", f"{field}: {', '.join(unknown)}")
    return value


def _text(value: Any, field: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise FanoutError("invalid_field", f"{field} must be a non-empty trimmed string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise FanoutError("invalid_field", f"{field} has invalid syntax")
    return value


def _sha(value: Any, field: str) -> str:
    text = _text(value, field)
    if SHA_RE.fullmatch(text) is None:
        raise FanoutError("invalid_sha256", field)
    return text


def _positive_int(value: Any, field: str, ceiling: int) -> int:
    if type(value) is not int or value < 1 or value > ceiling:
        raise FanoutError("invalid_field", f"{field} must be 1..{ceiling}")
    return value


def _timestamp(value: Any, field: str) -> dt.datetime:
    text = _text(value, field)
    if not text.endswith("Z"):
        raise FanoutError("invalid_timestamp", field)
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise FanoutError("invalid_timestamp", field) from exc
    if parsed.utcoffset() != dt.timedelta(0):
        raise FanoutError("invalid_timestamp", field)
    return parsed


def _relative_path(value: Any, field: str) -> str:
    text = _text(value, field, PATH_RE)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or text.startswith("./") or "//" in text or "\\" in text:
        raise FanoutError("invalid_path", field)
    return path.as_posix()


def _scope_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list):
        raise FanoutError("invalid_field", f"{field} must be an array")
    result = [_relative_path(item, f"{field}[]") for item in value]
    if len(result) != len(set(result)):
        raise FanoutError("scope_collision", field)
    return sorted(result)


def _scopes_overlap(left: str, right: str) -> bool:
    left_parts = Path(left).parts
    right_parts = Path(right).parts
    shorter = min(len(left_parts), len(right_parts))
    return left_parts[:shorter] == right_parts[:shorter]


def _descriptor(value: Any, field: str, root: Path) -> dict[str, Any]:
    row = _strict(value, field, {"path", "sha256"})
    relative = _relative_path(row["path"], f"{field}.path")
    expected = _sha(row["sha256"], f"{field}.sha256")
    candidate = root.resolve() / relative
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve())
        stat = resolved.stat()
    except (OSError, RuntimeError, ValueError) as exc:
        raise FanoutError("artifact_descriptor_invalid", field) from exc
    if candidate.is_symlink() or not resolved.is_file() or stat.st_nlink != 1:
        raise FanoutError("artifact_descriptor_invalid", field)
    actual = "sha256:" + hashlib.sha256(resolved.read_bytes()).hexdigest()
    if actual != expected:
        raise FanoutError("artifact_digest_mismatch", field)
    return row


def _json_descriptor(value: Any, field: str, root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    descriptor = _descriptor(value, field, root)
    document = load_json(root.resolve() / descriptor["path"])
    return descriptor, document


def _lane(value: Any, index: int, *, artifact_root: Path, now: dt.datetime) -> dict[str, Any]:
    field = f"lanes[{index}]"
    lane = _strict(
        value,
        field,
        {
            "lane_id", "task_id", "route_name", "provider", "model",
            "harness_sha256", "mutation_mode", "independence_group",
            "worktree_path", "worktree_identity_sha256", "base_tree_sha256",
            "evidence_directory", "evidence_root_identity_sha256",
            "capability_card_sha256", "preflight_sha256", "lease_sha256",
            "fence_token_sha256", "execution_binding_sha256", "grant_sha256",
            "scope_sha256", "read_scope", "write_scope", "max_attempts",
            "task_state_descriptor",
            "capability_card_descriptor", "task_grant_descriptor",
            "execution_binding_descriptor",
        },
    )
    for name in ("lane_id", "task_id", "route_name", "provider", "model", "independence_group"):
        _text(lane[name], f"{field}.{name}", ID_RE)
    lane["worktree_path"] = _relative_path(lane["worktree_path"], f"{field}.worktree_path")
    lane["evidence_directory"] = _relative_path(lane["evidence_directory"], f"{field}.evidence_directory")
    for name in (
        "harness_sha256", "worktree_identity_sha256", "base_tree_sha256",
        "evidence_root_identity_sha256", "capability_card_sha256", "preflight_sha256",
        "lease_sha256", "fence_token_sha256", "execution_binding_sha256",
        "grant_sha256", "scope_sha256",
    ):
        _sha(lane[name], f"{field}.{name}")
    lane["read_scope"] = _scope_list(lane["read_scope"], f"{field}.read_scope")
    lane["write_scope"] = _scope_list(lane["write_scope"], f"{field}.write_scope")
    if lane["mutation_mode"] not in MUTATION_MODES:
        raise FanoutError("invalid_mutation_mode", field)
    if lane["mutation_mode"] == "read_only" and lane["write_scope"]:
        raise FanoutError("write_scope_forbidden", field)
    if lane["mutation_mode"] == "scoped_write" and not lane["write_scope"]:
        raise FanoutError("write_scope_required", field)
    _positive_int(lane["max_attempts"], f"{field}.max_attempts", MAX_ATTEMPTS)
    descriptor, state = _json_descriptor(lane["task_state_descriptor"], f"{field}.task_state_descriptor", artifact_root)
    try:
        state = RECONCILER._validate_state(state)
    except RECONCILER.ReconciliationError as exc:
        raise FanoutError("task_state_invalid", f"{field}:{exc.code}") from exc
    assignment = state["assignment_identity"]
    route = state["external_execution"]
    if (
        assignment.get("task_id") != lane["task_id"]
        or route.get("route_name") != lane["route_name"]
        or route.get("provider") != lane["provider"]
        or route.get("exact_model") != lane["model"]
        or state.get("standing_authority", {}).get("fresh_automatic_preflight_verified") is not True
        or state.get("dispatch_binding", {}).get("attempt_limit") != 1
        or state.get("dispatch_binding", {}).get("fallback_allowed") is not False
        or state.get("dispatch_binding", {}).get("hedging_allowed") is not False
    ):
        raise FanoutError("task_state_binding_mismatch", field)
    lane["task_state_descriptor"] = descriptor
    capability_descriptor, capability = _json_descriptor(lane["capability_card_descriptor"], f"{field}.capability_card_descriptor", artifact_root)
    grant_descriptor, grant = _json_descriptor(lane["task_grant_descriptor"], f"{field}.task_grant_descriptor", artifact_root)
    try:
        authority = AUTHORITY.effective_authority(capability, grant, now=now.isoformat().replace("+00:00", "Z"))
    except AUTHORITY.ProviderWorkError as exc:
        raise FanoutError("authority_invalid", f"{field}:{exc.code}") from exc
    if (
        authority["task_id"] != lane["task_id"]
        or authority["route_name"] != lane["route_name"]
        or authority["access_mode"] != ("read_only" if lane["mutation_mode"] == "artifact_only" else lane["mutation_mode"])
        or authority["read_scope"] != lane["read_scope"]
        or authority["write_scope"] != lane["write_scope"]
        or authority["base_tree_sha256"] != lane["base_tree_sha256"]
        or authority["capability_sha256"] != lane["capability_card_sha256"]
        or authority["grant_sha256"] != lane["grant_sha256"]
    ):
        raise FanoutError("authority_binding_mismatch", field)
    lane["capability_card_descriptor"] = capability_descriptor
    lane["task_grant_descriptor"] = grant_descriptor
    binding_descriptor, binding = _json_descriptor(lane["execution_binding_descriptor"], f"{field}.execution_binding_descriptor", artifact_root)
    _strict(binding, f"{field}.execution_binding", {
        "schema_version", "lease_id", "fencing_token", "attempt_id", "task_id", "assignment_id",
        "route_name", "envelope_sha256", "preflight_sha256", "receiver_qualification_sha256",
        "authority_sha256", "effective_config_sha256", "evidence_directory", "expires_at", "execution_mode",
    })
    if (
        binding["schema_version"] != 1
        or binding["task_id"] != lane["task_id"]
        or binding["route_name"] != lane["route_name"]
        or binding["lease_id"] != authority["lease_id"]
        or binding["fencing_token"] != authority["fencing_token"]
        or binding["preflight_sha256"] != lane["preflight_sha256"]
        or binding["evidence_directory"] != lane["evidence_directory"]
        or binding["execution_mode"] != "single_resolved_attempt"
        or lane["lease_sha256"] != sha256_value({"lease_id": binding["lease_id"]})
        or lane["fence_token_sha256"] != sha256_value({"fencing_token": binding["fencing_token"]})
        or lane["execution_binding_sha256"] != binding_descriptor["sha256"]
    ):
        raise FanoutError("execution_binding_mismatch", field)
    lane["execution_binding_descriptor"] = binding_descriptor
    return lane


def _attempt_id(fanout_id: str, lane_id: str, attempt_index: int) -> str:
    return f"{fanout_id}:{lane_id}:a{attempt_index}"


def validate_plan(value: dict[str, Any], *, now: dt.datetime, artifact_root: Path) -> dict[str, Any]:
    compiled = value.get("artifact_type") == "ProviderFanoutPlan"
    required = {
        "schema_version", "artifact_type", "fanout_id", "parent_task_id",
        "created_at", "expires_at", "concurrency_limit", "bindings", "binding_descriptors", "lanes", "retry_policy",
    }
    if compiled:
        required |= {"execution_waves", "initial_attempts", "plan_sha256"}
    plan = _strict(value, "plan", required)
    if plan["schema_version"] != SCHEMA_VERSION or plan["artifact_type"] not in {
        "ProviderFanoutPlanDraft", "ProviderFanoutPlan",
    }:
        raise FanoutError("unsupported_schema", "ProviderFanoutPlan v1 required")
    _text(plan["fanout_id"], "fanout_id", ID_RE)
    _text(plan["parent_task_id"], "parent_task_id", ID_RE)
    created = _timestamp(plan["created_at"], "created_at")
    expires = _timestamp(plan["expires_at"], "expires_at")
    if created > now or expires <= now or expires <= created:
        raise FanoutError("stale_plan", "created_at or expires_at")
    concurrency = _positive_int(plan["concurrency_limit"], "concurrency_limit", MAX_LANES)
    bindings = _strict(plan["bindings"], "bindings", {"candidate_sha256", "board_sha256", "config_sha256", "parent_authority_sha256"})
    for name, binding in bindings.items():
        _sha(binding, f"bindings.{name}")
    binding_descriptors = _strict(plan["binding_descriptors"], "binding_descriptors", {
        "candidate", "board", "config", "parent_authority",
    })
    for name, descriptor_value in binding_descriptors.items():
        descriptor = _descriptor(descriptor_value, f"binding_descriptors.{name}", artifact_root)
        if descriptor["sha256"] != bindings[f"{name}_sha256"]:
            raise FanoutError("plan_binding_descriptor_mismatch", name)
        binding_descriptors[name] = descriptor
    if not isinstance(plan["lanes"], list) or len(plan["lanes"]) < 2 or len(plan["lanes"]) > MAX_LANES:
        raise FanoutError("invalid_lane_count", "lanes must contain 2..8 rows")
    lanes = [_lane(row, index, artifact_root=artifact_root, now=now) for index, row in enumerate(plan["lanes"])]
    for key in (
        "lane_id", "task_id", "route_name", "independence_group", "worktree_path",
        "worktree_identity_sha256", "evidence_directory", "evidence_root_identity_sha256",
        "lease_sha256", "fence_token_sha256", "execution_binding_sha256",
    ):
        values = [row[key] for row in lanes]
        if len(values) != len(set(values)):
            raise FanoutError("lane_collision", key)
    writes = [(lane["lane_id"], scope) for lane in lanes for scope in lane["write_scope"]]
    for index, (left_lane, left_scope) in enumerate(writes):
        for right_lane, right_scope in writes[index + 1:]:
            if left_lane != right_lane and _scopes_overlap(left_scope, right_scope):
                raise FanoutError("write_scope_overlap", f"{left_lane}:{right_lane}")
    policy = _strict(plan["retry_policy"], "retry_policy", {"policy_id", "maximum_attempts", "allowed_failure_classes", "route_fallback_allowed", "hedging_allowed"})
    if policy["policy_id"] != "scheduler_pre_provider_retry_v1":
        raise FanoutError("unsupported_retry_policy", str(policy["policy_id"]))
    _positive_int(policy["maximum_attempts"], "retry_policy.maximum_attempts", MAX_ATTEMPTS)
    if policy["maximum_attempts"] != MAX_ATTEMPTS:
        raise FanoutError("unsafe_retry_policy", "maximum_attempts must equal 3")
    if not isinstance(policy["allowed_failure_classes"], list) or set(policy["allowed_failure_classes"]) != PRE_PROVIDER_RETRY_CLASSES:
        raise FanoutError("unsafe_retry_policy", "allowed_failure_classes must be exact")
    if policy["route_fallback_allowed"] is not False or policy["hedging_allowed"] is not False:
        raise FanoutError("unsafe_retry_policy", "fallback and hedging must remain false")
    if any(lane["max_attempts"] > policy["maximum_attempts"] for lane in lanes):
        raise FanoutError("unsafe_retry_policy", "lane maximum exceeds policy")
    if compiled:
        if plan["plan_sha256"] != sha256_value({key: plan[key] for key in plan if key != "plan_sha256"}):
            raise FanoutError("plan_digest_mismatch", "plan_sha256")
        expected_waves, expected_attempts = _expected_execution(plan)
        if plan["execution_waves"] != expected_waves:
            raise FanoutError("execution_wave_mismatch", "execution_waves")
        if plan["initial_attempts"] != expected_attempts:
            raise FanoutError("initial_attempt_mismatch", "initial_attempts")
    return plan


def _expected_execution(plan: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    lanes = plan["lanes"]
    concurrent = [row["lane_id"] for row in lanes if row["mutation_mode"] != "scoped_write"]
    writes = [row["lane_id"] for row in lanes if row["mutation_mode"] == "scoped_write"]
    waves: list[dict[str, Any]] = []
    limit = plan["concurrency_limit"]
    for offset in range(0, len(concurrent), limit):
        waves.append({"wave_index": len(waves) + 1, "mode": "concurrent_no_repository_write", "lane_ids": concurrent[offset:offset + limit]})
    for lane_id in writes:
        waves.append({"wave_index": len(waves) + 1, "mode": "serialized_scoped_write", "lane_ids": [lane_id]})
    attempts = []
    for row in lanes:
        attempts.append({
            "lane_id": row["lane_id"],
            "attempt_index": 1,
            "attempt_id": _attempt_id(plan["fanout_id"], row["lane_id"], 1),
            "route_name": row["route_name"],
            "provider": row["provider"],
            "model": row["model"],
            "harness_sha256": row["harness_sha256"],
            "worktree_identity_sha256": row["worktree_identity_sha256"],
            "evidence_root_identity_sha256": row["evidence_root_identity_sha256"],
            "capability_card_sha256": row["capability_card_sha256"],
            "preflight_sha256": row["preflight_sha256"],
            "lease_sha256": row["lease_sha256"],
            "fence_token_sha256": row["fence_token_sha256"],
            "execution_binding_sha256": row["execution_binding_sha256"],
            "grant_sha256": row["grant_sha256"],
            "scope_sha256": row["scope_sha256"],
        })
    return waves, attempts


def compile_plan(value: dict[str, Any], *, now: dt.datetime, artifact_root: Path) -> dict[str, Any]:
    draft = validate_plan(value, now=now, artifact_root=artifact_root)
    waves, initial = _expected_execution(draft)
    compiled = dict(draft)
    compiled["artifact_type"] = "ProviderFanoutPlan"
    compiled["execution_waves"] = waves
    compiled["initial_attempts"] = initial
    compiled["plan_sha256"] = sha256_value(compiled)
    return validate_plan(compiled, now=now, artifact_root=artifact_root)


def _lane_by_id(plan: dict[str, Any], lane_id: str) -> dict[str, Any]:
    matches = [row for row in plan["lanes"] if row["lane_id"] == lane_id]
    if len(matches) != 1:
        raise FanoutError("unknown_lane", lane_id)
    return matches[0]


def classify_retry(
    plan: dict[str, Any], failure_descriptor: dict[str, Any], fresh_attempt: dict[str, Any],
    *, now: dt.datetime, artifact_root: Path,
) -> dict[str, Any]:
    validate_plan(plan, now=now, artifact_root=artifact_root)
    if plan["artifact_type"] != "ProviderFanoutPlan":
        raise FanoutError("compiled_plan_required", "retry")
    verified_failure_descriptor, row = _json_descriptor(
        failure_descriptor, "failure_receipt_descriptor", artifact_root
    )
    row = _strict(
        row,
        "failure_receipt",
        {
            "schema_version", "artifact_type", "receipt_sha256",
            "lane_id", "attempt_id", "attempt_index", "route_name", "provider", "model",
            "harness_sha256", "worktree_identity_sha256", "evidence_root_identity_sha256",
            "capability_card_sha256", "preflight_sha256", "lease_sha256", "fence_token_sha256",
            "execution_binding_sha256", "grant_sha256", "scope_sha256",
            "failure_class", "provider_process_started", "external_call_performed",
            "mutation_started", "execution_unknown", "receipt_finalized", "terminal_status",
        },
    )
    if row["schema_version"] != 1 or row["artifact_type"] != "FanoutPreProviderFailureReceipt":
        raise FanoutError("failure_receipt_type_invalid", "failure_receipt")
    supplied_receipt_sha = _sha(row["receipt_sha256"], "failure_receipt.receipt_sha256")
    if supplied_receipt_sha != sha256_value({key: row[key] for key in row if key != "receipt_sha256"}):
        raise FanoutError("failure_receipt_digest_mismatch", "failure_receipt")
    lane_id = _text(row["lane_id"], "outcome.lane_id", ID_RE)
    lane = _lane_by_id(plan, lane_id)
    index = _positive_int(row["attempt_index"], "outcome.attempt_index", MAX_ATTEMPTS)
    if row["attempt_id"] != _attempt_id(plan["fanout_id"], lane_id, index):
        raise FanoutError("attempt_identity_mismatch", lane_id)
    for field in (
        "route_name", "provider", "model", "harness_sha256", "worktree_identity_sha256",
        "evidence_root_identity_sha256", "capability_card_sha256", "preflight_sha256",
        "lease_sha256", "fence_token_sha256", "execution_binding_sha256", "grant_sha256", "scope_sha256",
    ):
        if row[field] != lane[field]:
            raise FanoutError("attempt_binding_mismatch", field)
    booleans = ("provider_process_started", "mutation_started", "execution_unknown", "receipt_finalized")
    if any(type(row[field]) is not bool for field in booleans):
        raise FanoutError("invalid_field", "retry booleans")
    if row["external_call_performed"] not in {False, True, "unknown"}:
        raise FanoutError("invalid_field", "external_call_performed")
    retryable = (
        row["failure_class"] in PRE_PROVIDER_RETRY_CLASSES
        and row["provider_process_started"] is False
        and row["external_call_performed"] is False
        and row["mutation_started"] is False
        and row["execution_unknown"] is False
        and row["receipt_finalized"] is True
        and row["terminal_status"] == "failed_certain_pre_provider"
        and index < lane["max_attempts"]
    )
    reason = "retry_allowed_pre_provider" if retryable else "retry_forbidden"
    fresh = _strict(fresh_attempt, "fresh_attempt", {
        "attempt_index", "attempt_id", "route_name", "provider", "model", "harness_sha256",
        "worktree_identity_sha256", "capability_card_sha256", "grant_sha256", "scope_sha256",
        "preflight_sha256", "lease_sha256", "fence_token_sha256", "execution_binding_sha256",
        "evidence_directory", "evidence_root_identity_sha256",
    })
    expected_next_index = index + 1
    invariant_fields = (
        "route_name", "provider", "model", "harness_sha256", "worktree_identity_sha256",
        "capability_card_sha256", "grant_sha256", "scope_sha256",
    )
    if any(fresh[name] != lane[name] for name in invariant_fields):
        raise FanoutError("fresh_attempt_invariant_mismatch", lane_id)
    if fresh["attempt_index"] != expected_next_index or fresh["attempt_id"] != _attempt_id(plan["fanout_id"], lane_id, expected_next_index):
        raise FanoutError("fresh_attempt_identity_mismatch", lane_id)
    for name in ("preflight_sha256", "lease_sha256", "fence_token_sha256", "execution_binding_sha256", "evidence_root_identity_sha256"):
        _sha(fresh[name], f"fresh_attempt.{name}")
        if fresh[name] == row[name]:
            raise FanoutError("fresh_attempt_binding_reused", name)
    fresh["evidence_directory"] = _relative_path(fresh["evidence_directory"], "fresh_attempt.evidence_directory")
    if fresh["evidence_directory"] == lane["evidence_directory"]:
        raise FanoutError("fresh_attempt_binding_reused", "evidence_directory")
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "ProviderFanoutRetryDecision",
        "fanout_id": plan["fanout_id"],
        "lane_id": lane_id,
        "prior_attempt_id": row["attempt_id"],
        "failure_receipt_descriptor": verified_failure_descriptor,
        "retry_allowed": retryable,
        "reason": reason,
        "next_attempt": None,
    }
    if retryable:
        result["next_attempt"] = fresh
    result["decision_sha256"] = sha256_value(result)
    return result


def _unknown_or_number(value: Any, field: str) -> Any:
    if value == "unknown":
        return value
    if type(value) not in {int, float} or value < 0 or not math.isfinite(value):
        raise FanoutError("invalid_telemetry", field)
    return value


def aggregate(plan: dict[str, Any], lane_receipts: list[dict[str, Any]], *, now: dt.datetime, artifact_root: Path) -> dict[str, Any]:
    validate_plan(plan, now=now, artifact_root=artifact_root)
    if plan["artifact_type"] != "ProviderFanoutPlan":
        raise FanoutError("compiled_plan_required", "aggregate")
    if not isinstance(lane_receipts, list) or len(lane_receipts) != len(plan["lanes"]):
        raise FanoutError("lane_receipt_count_mismatch", "one receipt per lane required")
    receipt_ids: set[str] = set()
    lane_ids: set[str] = set()
    artifact_paths: set[str] = set()
    summaries: list[dict[str, Any]] = []
    fold_candidates: list[dict[str, Any]] = []
    for index, value in enumerate(lane_receipts):
        field = f"lane_receipts[{index}]"
        receipt = _strict(
            value,
            field,
            {
                "receipt_id", "lane_id", "task_id", "route_name", "provider", "model",
                "harness_sha256", "worktree_identity_sha256", "evidence_root_identity_sha256",
                "capability_card_sha256", "preflight_sha256", "lease_sha256", "fence_token_sha256",
                "execution_binding_sha256", "grant_sha256", "scope_sha256",
                "attempts", "final_status", "artifact_sha256", "diff_sha256", "audit_status",
                "telemetry", "artifact_descriptors", "accepted_by_parent", "board_mutation_performed", "fold_performed",
            },
        )
        receipt_id = _text(receipt["receipt_id"], f"{field}.receipt_id", ID_RE)
        lane_id = _text(receipt["lane_id"], f"{field}.lane_id", ID_RE)
        if receipt_id in receipt_ids or lane_id in lane_ids:
            raise FanoutError("lane_receipt_collision", lane_id)
        receipt_ids.add(receipt_id)
        lane_ids.add(lane_id)
        lane = _lane_by_id(plan, lane_id)
        for name in (
            "task_id", "route_name", "provider", "model", "harness_sha256",
            "worktree_identity_sha256", "evidence_root_identity_sha256", "capability_card_sha256",
            "preflight_sha256", "lease_sha256", "fence_token_sha256", "execution_binding_sha256",
            "grant_sha256", "scope_sha256",
        ):
            if receipt[name] != lane[name]:
                raise FanoutError("lane_receipt_binding_mismatch", name)
        if receipt["final_status"] not in FINAL_STATUSES or receipt["audit_status"] not in AUDIT_STATUSES:
            raise FanoutError("invalid_lane_status", lane_id)
        if receipt["accepted_by_parent"] is not False or receipt["board_mutation_performed"] is not False or receipt["fold_performed"] is not False:
            raise FanoutError("parent_boundary_violation", lane_id)
        if not isinstance(receipt["attempts"], list) or not receipt["attempts"] or len(receipt["attempts"]) > lane["max_attempts"]:
            raise FanoutError("invalid_attempt_history", lane_id)
        for attempt_index, attempt in enumerate(receipt["attempts"], start=1):
            attempt = _strict(attempt, f"{field}.attempts[{attempt_index - 1}]", {"attempt_id", "attempt_index", "status", "provider_process_started", "external_call_performed", "mutation_started", "execution_unknown", "retry_classification", "failure_receipt_descriptor", "retry_decision_descriptor"})
            if attempt["attempt_index"] != attempt_index or attempt["attempt_id"] != _attempt_id(plan["fanout_id"], lane_id, attempt_index):
                raise FanoutError("attempt_history_gap", lane_id)
            if attempt["status"] not in FINAL_STATUSES | {"failed_certain_pre_provider"}:
                raise FanoutError("invalid_attempt_status", lane_id)
            for boolean_field in ("provider_process_started", "mutation_started", "execution_unknown"):
                if type(attempt[boolean_field]) is not bool:
                    raise FanoutError("invalid_attempt_history", boolean_field)
            if attempt["external_call_performed"] not in {False, True, "unknown"}:
                raise FanoutError("invalid_attempt_history", "external_call_performed")
            if attempt_index < len(receipt["attempts"]):
                failure_descriptor, failure_document = _json_descriptor(
                    attempt["failure_receipt_descriptor"], f"{field}.attempts[].failure_receipt_descriptor", artifact_root
                )
                decision_descriptor, decision_document = _json_descriptor(
                    attempt["retry_decision_descriptor"], f"{field}.attempts[].retry_decision_descriptor", artifact_root
                )
                if not (
                    attempt["status"] == "failed_certain_pre_provider"
                    and attempt["provider_process_started"] is False
                    and attempt["external_call_performed"] is False
                    and attempt["mutation_started"] is False
                    and attempt["execution_unknown"] is False
                    and attempt["retry_classification"] == "retry_allowed_pre_provider"
                ):
                    raise FanoutError("unsafe_retry_history", lane_id)
                if (
                    failure_document.get("artifact_type") != "FanoutPreProviderFailureReceipt"
                    or failure_document.get("attempt_id") != attempt["attempt_id"]
                    or failure_document.get("receipt_sha256") != sha256_value({key: failure_document[key] for key in failure_document if key != "receipt_sha256"})
                    or decision_document.get("artifact_type") != "ProviderFanoutRetryDecision"
                    or decision_document.get("prior_attempt_id") != attempt["attempt_id"]
                    or decision_document.get("failure_receipt_descriptor") != failure_descriptor
                    or decision_document.get("retry_allowed") is not True
                    or decision_document.get("decision_sha256") != sha256_value({key: decision_document[key] for key in decision_document if key != "decision_sha256"})
                    or decision_document.get("next_attempt", {}).get("attempt_id") != _attempt_id(plan["fanout_id"], lane_id, attempt_index + 1)
                ):
                    raise FanoutError("retry_evidence_invalid", lane_id)
            elif attempt["failure_receipt_descriptor"] != "unknown" or attempt["retry_decision_descriptor"] != "unknown":
                raise FanoutError("terminal_retry_evidence_forbidden", lane_id)
        final_attempt = receipt["attempts"][-1]
        if final_attempt["status"] != receipt["final_status"]:
            raise FanoutError("final_attempt_status_mismatch", lane_id)
        if receipt["final_status"] == "candidate_ready" and not (
            final_attempt["provider_process_started"] is True
            and final_attempt["external_call_performed"] is True
            and final_attempt["execution_unknown"] is False
        ):
            raise FanoutError("candidate_execution_proof_missing", lane_id)
        if receipt["final_status"] == "execution_unknown" and final_attempt["execution_unknown"] is not True:
            raise FanoutError("execution_unknown_proof_missing", lane_id)
        artifact = receipt["artifact_sha256"]
        diff = receipt["diff_sha256"]
        if artifact != "unknown":
            _sha(artifact, f"{field}.artifact_sha256")
        if diff != "unknown":
            _sha(diff, f"{field}.diff_sha256")
        if receipt["final_status"] == "candidate_ready" and artifact == "unknown":
            raise FanoutError("candidate_artifact_missing", lane_id)
        if lane["mutation_mode"] == "scoped_write" and receipt["final_status"] == "candidate_ready" and diff == "unknown":
            raise FanoutError("candidate_diff_missing", lane_id)
        descriptors = _strict(receipt["artifact_descriptors"], f"{field}.artifact_descriptors", {"task_state", "dispatch_return", "schedule_manifest", "quality_receipt", "reconciliation_receipt"})
        verified_descriptors: dict[str, dict[str, Any]] = {}
        documents: dict[str, dict[str, Any]] = {}
        for name, descriptor_value in descriptors.items():
            verified_descriptors[name], documents[name] = _json_descriptor(
                descriptor_value, f"{field}.artifact_descriptors.{name}", artifact_root
            )
        for descriptor in verified_descriptors.values():
            if descriptor["path"] in artifact_paths:
                raise FanoutError("artifact_descriptor_collision", descriptor["path"])
            artifact_paths.add(descriptor["path"])
        _, planned_task_state = _json_descriptor(
            lane["task_state_descriptor"], f"plan.lanes.{lane_id}.task_state_descriptor", artifact_root
        )
        if documents["task_state"].get("state_sha256") != planned_task_state.get("state_sha256"):
            raise FanoutError("task_state_descriptor_mismatch", lane_id)
        try:
            recomputed = RECONCILER.reconcile_visible_provider_result(
                documents["task_state"], documents["schedule_manifest"],
                documents["dispatch_return"], documents["quality_receipt"],
            )
        except RECONCILER.ReconciliationError as exc:
            raise FanoutError("lane_evidence_invalid", f"{lane_id}:{exc.code}") from exc
        if documents["reconciliation_receipt"] != recomputed:
            raise FanoutError("reconciliation_mismatch", lane_id)
        derived_status = {
            "candidate_ready_for_sol_review": "candidate_ready",
            "terminal_execution_unknown": "execution_unknown",
            "quality_rejected": "rejected",
            "terminal_dispatch_failure": "rejected",
        }.get(recomputed.get("status"))
        if derived_status != receipt["final_status"]:
            raise FanoutError("lane_status_not_evidence_derived", lane_id)
        if receipt["final_status"] == "candidate_ready":
            if lane["mutation_mode"] == "scoped_write":
                raise FanoutError("scoped_write_candidate_unsupported", lane_id)
            returned_artifact = documents["dispatch_return"].get("artifact")
            if not isinstance(returned_artifact, dict):
                raise FanoutError("candidate_artifact_missing", lane_id)
            returned_sha = returned_artifact.get("sha256")
            if isinstance(returned_sha, str) and not returned_sha.startswith("sha256:"):
                returned_sha = "sha256:" + returned_sha
            if artifact != returned_sha:
                raise FanoutError("candidate_artifact_digest_mismatch", lane_id)
        telemetry = _strict(receipt["telemetry"], f"{field}.telemetry", {"turns", "attempts", "latency_ms", "process_count", "tokens", "quota", "cost"})
        for name, telemetry_value in telemetry.items():
            _unknown_or_number(telemetry_value, f"{field}.telemetry.{name}")
        for name in ("turns", "attempts", "process_count"):
            if telemetry[name] != "unknown" and type(telemetry[name]) is not int:
                raise FanoutError("invalid_telemetry", f"{field}.telemetry.{name}")
        if telemetry["attempts"] != len(receipt["attempts"]):
            raise FanoutError("attempt_telemetry_mismatch", lane_id)
        summary = {
            "lane_id": lane_id,
            "receipt_id": receipt_id,
            "final_status": receipt["final_status"],
            "audit_status": receipt["audit_status"],
            "attempt_count": len(receipt["attempts"]),
            "artifact_sha256": artifact,
            "diff_sha256": diff,
            "telemetry": telemetry,
            "artifact_descriptors": verified_descriptors,
        }
        summaries.append(summary)
        if receipt["final_status"] == "candidate_ready" and receipt["audit_status"] == "passed":
            fold_candidates.append({"lane_id": lane_id, "receipt_id": receipt_id, "artifact_sha256": artifact, "diff_sha256": diff})
    expected_lane_ids = {row["lane_id"] for row in plan["lanes"]}
    if lane_ids != expected_lane_ids:
        raise FanoutError("lane_receipt_set_mismatch", "lane IDs")
    result = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "ProviderFanoutAggregateReceipt",
        "fanout_id": plan["fanout_id"],
        "plan_sha256": plan["plan_sha256"],
        "lanes": sorted(summaries, key=lambda row: row["lane_id"]),
        "fold_candidates": sorted(fold_candidates, key=lambda row: row["lane_id"]),
        "accepted_by_parent": False,
        "board_mutation_performed": False,
        "fold_performed": False,
        "aggregate_sha256": "pending",
    }
    result["aggregate_sha256"] = sha256_value({key: result[key] for key in result if key != "aggregate_sha256"})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("compile", "retry", "aggregate"):
        command = sub.add_parser(name)
        command.add_argument("--plan", type=Path, required=True)
        command.add_argument("--artifact-root", type=Path, required=True)
        if name == "retry":
            command.add_argument("--failure-receipt", type=Path, required=True)
            command.add_argument("--fresh-attempt", type=Path, required=True)
        if name == "aggregate":
            command.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    now = dt.datetime.now(dt.timezone.utc)
    try:
        plan = load_json(args.plan)
        if args.command == "compile":
            result = compile_plan(plan, now=now, artifact_root=args.artifact_root)
        elif args.command == "retry":
            failure_path = args.failure_receipt.resolve()
            try:
                failure_relative = failure_path.relative_to(args.artifact_root.resolve()).as_posix()
            except ValueError as exc:
                raise FanoutError("invalid_path", "failure receipt outside artifact root") from exc
            failure_descriptor = {
                "path": failure_relative,
                "sha256": "sha256:" + hashlib.sha256(failure_path.read_bytes()).hexdigest(),
            }
            result = classify_retry(
                plan, failure_descriptor, load_json(args.fresh_attempt), now=now,
                artifact_root=args.artifact_root,
            )
        else:
            receipts = load_json(args.receipts)
            rows = _strict(receipts, "receipts", {"lane_receipts"})["lane_receipts"]
            result = aggregate(plan, rows, now=now, artifact_root=args.artifact_root)
    except FanoutError as exc:
        print(json.dumps({"ok": False, "error": {"code": exc.code, "detail": exc.detail}}, sort_keys=True))
        return 2
    except (KeyError, TypeError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": {"code": "invalid_input", "detail": type(exc).__name__}}, sort_keys=True))
        return 2
    print(json.dumps({"ok": True, "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
