#!/usr/bin/env python3
"""Reconcile immutable provider evidence into a Sol-pending review packet."""

from __future__ import annotations

import argparse
import copy
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
RAW_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _load_bridge() -> Any:
    path = Path(__file__).with_name("visible_provider_bridge.py")
    spec = importlib.util.spec_from_file_location("codexmax_visible_bridge_reconcile", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BRIDGE = _load_bridge()


class ReconciliationError(ValueError):
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


def _validate_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReconciliationError("task_state_invalid")
    state = copy.deepcopy(value)
    supplied = state.pop("state_sha256", None)
    if not isinstance(supplied, str) or SHA256.fullmatch(supplied) is None:
        raise ReconciliationError("task_state_digest_invalid")
    if digest(state) != supplied:
        raise ReconciliationError("task_state_digest_mismatch")
    state["state_sha256"] = supplied
    if (
        state.get("schema_version") != SCHEMA_VERSION
        or state.get("artifact_type") != "VisibleProviderTaskState"
        or state.get("status") != "ready_for_visible_host_action"
        or state.get("lifecycle_phase") != "preflight_passed"
        or state.get("quality", {}).get("sol_decision") != "pending"
        or state.get("mutations") != {
            "source_mutated": False,
            "goalbuddy_mutated": False,
            "supervisor_mutated": False,
        }
    ):
        raise ReconciliationError("task_state_not_reconcilable")
    return state


def _validate_schedule(value: Any, state: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReconciliationError("schedule_manifest_invalid")
    manifest = copy.deepcopy(value)
    supplied = manifest.get("manifest_sha256")
    if not isinstance(supplied, str) or SHA256.fullmatch(supplied) is None:
        raise ReconciliationError("schedule_manifest_digest_invalid")
    payload = {key: manifest[key] for key in manifest if key != "manifest_sha256"}
    if digest(payload) != supplied:
        raise ReconciliationError("schedule_manifest_digest_mismatch")
    if manifest.get("schema_version") != 1 or manifest.get("artifact_type") != "DispatchScheduleManifest":
        raise ReconciliationError("schedule_manifest_type_invalid")
    identity = manifest.get("identity")
    visible = manifest.get("visible_identity")
    assignment = state["assignment_identity"]
    if not isinstance(identity, dict) or any(
        identity.get(field) != assignment[field]
        for field in ("goal_id", "task_id", "assignment_id")
    ) or not isinstance(visible, dict) or any(
        visible.get(field) != assignment[field]
        for field in ("dispatch_id", "semantic_role")
    ):
        raise ReconciliationError("schedule_identity_mismatch")
    selected = manifest.get("selected_route")
    external = state["external_execution"]
    route_fields = {
        "name": "route_name", "provider": "provider", "exact_model": "exact_model",
        "route_id": "route_id", "runtime": "runtime", "reasoning": "reasoning",
    }
    if not isinstance(selected, dict) or any(
        selected.get(field) != external[target]
        for field, target in route_fields.items()
    ):
        raise ReconciliationError("schedule_route_mismatch")
    if any(manifest.get(field) is not False for field in (
        "supervisor_applied", "goalbuddy_applied", "accepted"
    )):
        raise ReconciliationError("schedule_claims_forbidden_mutation")
    return manifest


def _unknown_or_observed(value: Any, field: str) -> Any:
    if value == "unknown":
        return {"value": "unknown", "reason": f"{field}_not_reported"}
    if isinstance(value, dict) and set(value) == {"value", "reason"}:
        if value["value"] == 0 and value["reason"] == "unknown":
            raise ReconciliationError("unknown_accounting_erased", field)
        return copy.deepcopy(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
        return copy.deepcopy(value)
    raise ReconciliationError("usage_invalid", field)


def _validate_return(value: Any, state: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReconciliationError("return_manifest_invalid")
    manifest = copy.deepcopy(value)
    if (
        manifest.get("schema_version") != 1
        or manifest.get("manifest_type") != "DispatchReturnManifest"
        or manifest.get("dispatch_id") != state["assignment_identity"]["dispatch_id"]
        or manifest.get("accepted") is not False
        or manifest.get("applied_to_goalbuddy") is not False
        or manifest.get("applied_to_supervisor") is not False
    ):
        raise ReconciliationError("return_manifest_boundary_invalid")
    attempts = manifest.get("attempts")
    if not isinstance(attempts, list) or len(attempts) > 1:
        raise ReconciliationError("single_attempt_boundary_violated")
    external_call_performed = manifest.get("external_call_performed")
    if external_call_performed not in {True, False}:
        raise ReconciliationError("external_call_marker_invalid")
    selected_success = (
        manifest.get("status") == "selected"
        and len(attempts) == 1
        and isinstance(attempts[0], dict)
        and attempts[0].get("outcome") == "success"
    )
    if selected_success and external_call_performed is not True:
        raise ReconciliationError("external_call_not_performed")
    route = state["external_execution"]
    selected = manifest.get("selected_route")
    if selected not in {None, route["route_name"]}:
        raise ReconciliationError("return_route_mismatch")
    if attempts:
        attempt = attempts[0]
        identity = attempt.get("identity") if isinstance(attempt, dict) else None
        if (
            not isinstance(attempt, dict)
            or attempt.get("route_name") != route["route_name"]
            or not isinstance(identity, dict)
            or any(
                identity.get(field) != route[target]
                for field, target in {
                    "provider": "provider", "model": "exact_model",
                    "route": "route_id", "runtime": "runtime", "reasoning": "reasoning",
                }.items()
            )
        ):
            raise ReconciliationError("attempt_identity_mismatch")
        expected = attempt.get("expected_response_identity")
        if expected != {
            "declared_route": route["route_name"],
            "actual_provider": route["provider"],
            "actual_model": route["exact_model"],
            "fallback_used": False,
            "retry_count": 0,
        }:
            raise ReconciliationError("response_identity_mismatch")
    failure = manifest.get("failure")
    if failure is not None:
        if (
            not isinstance(failure, dict)
            or failure.get("category") not in {"provider_failure", "execution_unknown"}
            or failure.get("retryable") is not False
        ):
            raise ReconciliationError("failure_classification_invalid")
        if not attempts or attempts[0].get("outcome") != failure["category"]:
            raise ReconciliationError("failure_classification_mismatch")
    usage = manifest.get("usage")
    if not isinstance(usage, dict) or set(usage) != {"tokens", "quota", "cost"}:
        raise ReconciliationError("usage_invalid")
    return manifest


def _validate_quality(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReconciliationError("quality_receipt_invalid")
    quality = copy.deepcopy(value)
    supplied = quality.pop("receipt_sha256", None)
    if not isinstance(supplied, str) or RAW_SHA256.fullmatch(supplied) is None:
        raise ReconciliationError("quality_receipt_digest_invalid")
    if hashlib.sha256(canonical_json(quality)).hexdigest() != supplied:
        raise ReconciliationError("quality_receipt_digest_mismatch")
    quality["receipt_sha256"] = supplied
    if (
        quality.get("schema_version") != 1
        or quality.get("checks_executed") is not True
        or quality.get("arbitrary_commands_executed") is not False
        or quality.get("model_judgment_used") is not False
        or not isinstance(quality.get("accepted"), bool)
    ):
        raise ReconciliationError("quality_receipt_boundary_invalid")
    return quality


def _artifact_descriptor(value: Any, *, source: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ReconciliationError("artifact_descriptor_invalid", source)
    size_field = "bytes" if source == "return" else "size_bytes"
    if set(value) != {"path", "sha256", size_field}:
        raise ReconciliationError("artifact_descriptor_invalid", source)
    path = value["path"]
    artifact_sha256 = value["sha256"]
    size = value[size_field]
    if (
        not isinstance(path, str)
        or not path
        or path != path.strip()
        or not isinstance(artifact_sha256, str)
        or (
            RAW_SHA256.fullmatch(artifact_sha256) is None
            and SHA256.fullmatch(artifact_sha256) is None
        )
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
    ):
        raise ReconciliationError("artifact_descriptor_invalid", source)
    return {
        "path": path,
        "sha256": artifact_sha256.removeprefix("sha256:"),
        "size_bytes": size,
    }


def _bind_artifacts(returned: dict[str, Any], quality: dict[str, Any]) -> None:
    returned_descriptor = _artifact_descriptor(returned.get("artifact"), source="return")
    quality_descriptor = _artifact_descriptor(quality.get("artifact"), source="quality")
    success_candidate = returned.get("status") == "selected"
    if success_candidate:
        if returned_descriptor is None or quality_descriptor is None:
            raise ReconciliationError("artifact_descriptor_required")
        if returned_descriptor != quality_descriptor:
            raise ReconciliationError("artifact_descriptor_mismatch")
        expected = quality.get("expected_descriptor")
        if expected is None or expected != quality_descriptor:
            raise ReconciliationError("artifact_expected_descriptor_mismatch")
    elif (
        returned_descriptor is not None
        or quality_descriptor is not None
        or quality.get("expected_descriptor") is not None
        or quality.get("accepted") is not False
    ):
        raise ReconciliationError("failure_artifact_boundary_invalid")


def reconcile_visible_provider_result(
    task_state: Any, schedule_manifest: Any, return_manifest: Any, quality_receipt: Any
) -> dict[str, Any]:
    """Validate immutable evidence and emit a packet that only Sol may decide."""

    state = _validate_state(task_state)
    schedule = _validate_schedule(schedule_manifest, state)
    returned = _validate_return(return_manifest, state)
    quality = _validate_quality(quality_receipt)
    _bind_artifacts(returned, quality)
    attempts = returned["attempts"]
    transport_succeeded = (
        returned.get("status") == "selected"
        and returned.get("selected_route") == state["external_execution"]["route_name"]
        and len(attempts) == 1
        and attempts[0].get("outcome") == "success"
        and attempts[0].get("response_identity_validated") is True
        and returned.get("artifact") is not None
    )
    failure_category = (
        returned.get("failure", {}).get("category")
        if isinstance(returned.get("failure"), dict)
        else None
    )
    if failure_category == "execution_unknown":
        status = "terminal_execution_unknown"
        phase = "execution_state_unknown"
    elif transport_succeeded and not quality["accepted"]:
        status = "quality_rejected"
        phase = "quality_failed"
    elif transport_succeeded and quality["accepted"]:
        status = "candidate_ready_for_sol_review"
        phase = "quality_pending_sol_review"
    else:
        status = "terminal_dispatch_failure"
        phase = "provider_output_recorded"

    usage = {
        field: _unknown_or_observed(returned["usage"][field], field)
        for field in ("tokens", "quota", "cost")
    }
    wall_time = attempts[0].get("elapsed_time_ms") if attempts else "unknown"
    usage["wall_time_ms"] = _unknown_or_observed(wall_time, "wall_time_ms")
    result = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "VisibleProviderReconciliation",
        "status": status,
        "lifecycle_phase": phase,
        "assignment_identity": copy.deepcopy(state["assignment_identity"]),
        "native_host": copy.deepcopy(state["native_host"]),
        "external_execution": {
            **copy.deepcopy(state["external_execution"]),
            "external_call_performed": returned["external_call_performed"],
            "attempt_count": len(attempts),
            "fallback_used": False,
            "retry_count": 0,
        },
        "evidence": {
            "task_state_sha256": state["state_sha256"],
            "schedule_manifest_sha256": schedule["manifest_sha256"],
            "return_manifest_sha256": digest(returned),
            "quality_receipt_sha256": quality["receipt_sha256"],
            "artifact": copy.deepcopy(returned.get("artifact")),
            "failure": copy.deepcopy(returned.get("failure")),
        },
        "usage": usage,
        "quality": {
            "transport_succeeded": transport_succeeded,
            "deterministic_quality_accepted": quality["accepted"],
            "quality_findings": copy.deepcopy(quality.get("findings", [])),
            "sol_decision": "pending",
            "accepted": False,
        },
        "mutations": {
            "source_mutated": False,
            "goalbuddy_mutated": False,
            "supervisor_mutated": False,
        },
        "retry_allowed": False,
        "fallback_allowed": False,
        "diagnostics": {
            "terminal_class": failure_category or (
                "none" if transport_succeeded else "provider_failure"
            ),
            "execution_unknown": failure_category == "execution_unknown",
            "provider_failure": failure_category == "provider_failure",
            "retry_allowed": False,
            "operator_action": (
                "inspect_immutable_execution_evidence"
                if failure_category == "execution_unknown"
                else "none"
            ),
        },
    }
    result["reconciliation_sha256"] = digest(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-state", type=Path, required=True)
    parser.add_argument("--schedule-manifest", type=Path, required=True)
    parser.add_argument("--return-manifest", type=Path, required=True)
    parser.add_argument("--quality-receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = reconcile_visible_provider_result(
            json.loads(args.task_state.read_text(encoding="utf-8")),
            json.loads(args.schedule_manifest.read_text(encoding="utf-8")),
            json.loads(args.return_manifest.read_text(encoding="utf-8")),
            json.loads(args.quality_receipt.read_text(encoding="utf-8")),
        )
    except (OSError, json.JSONDecodeError, ReconciliationError) as exc:
        if isinstance(exc, ReconciliationError):
            error = {"status": "rejected", "code": exc.code, "detail": exc.detail}
        else:
            error = {"status": "rejected", "code": type(exc).__name__, "detail": str(exc)}
        print(json.dumps(error, indent=2, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
