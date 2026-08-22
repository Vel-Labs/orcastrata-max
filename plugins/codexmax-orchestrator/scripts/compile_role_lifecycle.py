#!/usr/bin/env python3
"""Compile hash-bound Supervisor lifecycle packets without applying them."""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import importlib.util
import json
import re
from pathlib import Path
import sys
from typing import Any

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
STAGE_TO_ROLE = {
    "tester": "tester",
    "documenter": "documenter",
    "auditor": "auditor",
}
STAGE_TO_EVENT = {
    "worker_self_test": "worker_self_test",
    "tester": "independent_test",
    "documenter": "documentation_result",
    "auditor": "audit_result",
    "candidate_closeout": "candidate_closeout",
}
STAGE_PHASE = {
    "worker_self_test": {"result_received", "repair_result_received"},
    "tester": {"self_tested"},
    "documenter": {"independently_tested"},
    "auditor": {"documented"},
    "candidate_closeout": {"audited"},
}
ROLE_PROFILES = {
    "tester": "semantic_independent_artifact",
    "documenter": "semantic_document_artifact",
    "auditor": "semantic_embedded_audit",
}
RESULT_MARKER = re.compile(r"(?m)^lifecycle_result:\s*(pass|fail)\s*$")
DOCUMENT_MARKER = re.compile(r"(?m)^semantic_changes:\s*none\s*$")


def _load(name: str, filename: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


APPLICATION = _load("codexmax_application_for_lifecycle_compile", "apply_scheduled_dispatch.py")
SUPERVISOR = APPLICATION.SUPERVISOR
RUNNER = _load("codexmax_runner_for_lifecycle_compile", "run_headless_provider_dispatch.py")


class LifecycleCompileError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def digest(value: Any, *, prefixed: bool = False) -> str:
    result = hashlib.sha256(canonical_json(value)).hexdigest()
    return "sha256:" + result if prefixed else result


def _read_json(path: Path, field: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleCompileError("input_unreadable", field) from exc
    if not isinstance(value, dict):
        raise LifecycleCompileError("input_shape_invalid", field)
    return value


def _descriptor(root: Path, path: Path, kind: str) -> dict[str, Any]:
    relative = APPLICATION._relative_path(root, path, kind)
    _, raw = APPLICATION._inside_regular(root, relative, kind)
    return {
        "path": relative,
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "artifact_kind": kind,
    }


def _descriptor_value(root: Path, descriptor: Any, field: str) -> tuple[dict[str, Any], bytes]:
    if not isinstance(descriptor, dict) or set(descriptor) != {
        "path", "sha256", "size_bytes", "artifact_kind",
    }:
        raise LifecycleCompileError("descriptor_invalid", field)
    _, raw = APPLICATION._inside_regular(root, descriptor["path"], field)
    expected = {
        "path": descriptor["path"],
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "artifact_kind": descriptor["artifact_kind"],
    }
    if descriptor != expected:
        raise LifecycleCompileError("descriptor_mismatch", field)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleCompileError("descriptor_json_invalid", field) from exc
    if not isinstance(value, dict):
        raise LifecycleCompileError("descriptor_json_invalid", field)
    return value, raw


def _runtime_snapshot(
    *, root: Path, goal_path: Path, board_path: Path, state_path: Path,
    event_log_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes]:
    with SUPERVISOR.open_supervisor_lock(state_path, root) as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
        board = SUPERVISOR.inspect_goalbuddy(goal_path, board_path)
        state = SUPERVISOR.migrate_runtime_state(SUPERVISOR._load_state(state_path))
        log = SUPERVISOR.verify_event_log(event_log_path)
        state_relative = APPLICATION._relative_path(root, state_path, "supervisor_state")
        _, state_raw = APPLICATION._inside_regular(root, state_relative, "supervisor_state")
    if (
        state.get("event_sequence") != log["event_count"]
        or state.get("last_event_hash") != log["last_event_hash"]
        or state.get("last_event_id") != log["last_event_id"]
    ):
        raise LifecycleCompileError("runtime_state_event_log_mismatch")
    if state.get("board_sha256") != board["board_sha256"] or state.get("goal_sha256") != board["goal_sha256"]:
        raise LifecycleCompileError("board_or_goal_drift")
    return board, state, log, state_raw


def _target_lane(state: dict[str, Any], lane_id: str, stage: str) -> dict[str, Any]:
    lane = state.get("lanes", {}).get(lane_id)
    if not isinstance(lane, dict):
        raise LifecycleCompileError("target_lane_missing", lane_id)
    if lane.get("phase") not in STAGE_PHASE[stage]:
        raise LifecycleCompileError("target_lane_phase_mismatch", str(lane.get("phase")))
    return lane


def _trusted_receipt(
    value: dict[str, Any], *, lane: dict[str, Any], purpose: str,
) -> dict[str, Any]:
    fields = {
        "schema_version", "artifact_type", "authority", "provider_generated",
        "purpose", "target_lane_id", "target_assignment_id", "commands",
        "result", "receipt_sha256",
    }
    if set(value) != fields or value.get("schema_version") != 1 or value.get("artifact_type") != "TrustedCommandReceipt":
        raise LifecycleCompileError("trusted_receipt_invalid", "shape")
    supplied = value["receipt_sha256"]
    payload = copy.deepcopy(value)
    payload.pop("receipt_sha256")
    if supplied != digest(payload, prefixed=True):
        raise LifecycleCompileError("trusted_receipt_invalid", "digest")
    if (
        value.get("authority") != "trusted_local_runtime"
        or value.get("provider_generated") is not False
        or value.get("purpose") != purpose
        or value.get("target_lane_id") != lane.get("lane_id")
        or value.get("target_assignment_id") != lane.get("assignment_id")
    ):
        raise LifecycleCompileError("trusted_receipt_binding_mismatch")
    try:
        commands = SUPERVISOR._command_rows(value.get("commands"), "trusted_receipt.commands")
    except SUPERVISOR.LoopError as exc:
        raise LifecycleCompileError("trusted_receipt_invalid", f"{exc.code}:{exc.detail}") from exc
    if any(set(row) != {"command", "execution_status", "result"} for row in commands):
        raise LifecycleCompileError("trusted_receipt_invalid", "command shape")
    passed = all(row["execution_status"] == "completed" and row["result"] == "pass" for row in commands)
    if value.get("result") != ("pass" if passed else "fail"):
        raise LifecycleCompileError("trusted_receipt_result_mismatch")
    if purpose == "worker_self_test" and [row["command"] for row in commands] != lane.get("self_test"):
        raise LifecycleCompileError("trusted_receipt_command_mismatch")
    return copy.deepcopy(value)


def _artifact_bytes(root: Path, returned: dict[str, Any]) -> tuple[str, bytes]:
    artifact = returned.get("artifact", {})
    relative = artifact.get("path")
    if not isinstance(relative, str):
        raise LifecycleCompileError("role_artifact_missing")
    _, raw = APPLICATION._inside_regular(root, relative, "role_artifact")
    if artifact.get("sha256") != "sha256:" + hashlib.sha256(raw).hexdigest() or artifact.get("bytes") != len(raw):
        raise LifecycleCompileError("role_artifact_descriptor_mismatch")
    return relative, raw


def _lifecycle_semantic_view(
    *, artifact_raw: bytes, assignment: dict[str, Any], manifest: dict[str, Any],
    returned: dict[str, Any],
) -> dict[str, Any]:
    """Expose only bound lifecycle content while preserving raw provider evidence."""

    try:
        schema = RUNNER._validate_response_schema(copy.deepcopy(assignment.get("response_schema")))
    except Exception as exc:
        raise LifecycleCompileError("lifecycle_response_schema_invalid", str(exc)) from exc
    if set(schema.get("properties", {})) != {"route_identity", "content"} or set(
        schema.get("required", [])
    ) != {"route_identity", "content"}:
        raise LifecycleCompileError("lifecycle_response_schema_invalid", "exact fields required")
    content_schema = schema["properties"]["content"]
    if content_schema.get("type") != "string" or content_schema.get("minLength", 0) < 1:
        raise LifecycleCompileError("lifecycle_response_schema_invalid", "content must be nonempty string")

    selected = manifest.get("selected_route")
    if not isinstance(selected, dict):
        raise LifecycleCompileError("lifecycle_response_identity_invalid", "selected route")
    route_name = selected.get("name")
    try:
        expected_identity = RUNNER._expected_response_identity(
            route_name,
            {"provider": selected.get("provider"), "model": selected.get("exact_model")},
        )
    except Exception as exc:
        raise LifecycleCompileError("lifecycle_response_identity_invalid", str(exc)) from exc

    attempts = returned.get("attempts")
    resolution = returned.get("route_resolution")
    resolution_attempts = resolution.get("attempts") if isinstance(resolution, dict) else None
    actual_route = resolution.get("actual_route") if isinstance(resolution, dict) else None
    if (
        not isinstance(attempts, list)
        or len(attempts) != 1
        or not isinstance(attempts[0], dict)
        or attempts[0].get("attempt_index") != 1
        or attempts[0].get("route_name") != route_name
        or attempts[0].get("outcome") != "success"
        or attempts[0].get("response_identity_validated") is not True
        or attempts[0].get("expected_response_identity") != expected_identity
        or not isinstance(resolution, dict)
        or resolution.get("status") != "selected"
        or resolution.get("selected_route") != route_name
        or resolution.get("preferred_route") != route_name
        or resolution.get("failover_used") is not False
        or not isinstance(resolution_attempts, list)
        or len(resolution_attempts) != 1
        or not isinstance(resolution_attempts[0], dict)
        or resolution_attempts[0].get("attempt_index") != 1
        or resolution_attempts[0].get("route_name") != route_name
        or resolution_attempts[0].get("outcome") != "success"
        or not isinstance(actual_route, dict)
        or actual_route.get("attempt_index") != 1
        or actual_route.get("provider") != selected.get("provider")
        or actual_route.get("model") != selected.get("exact_model")
    ):
        raise LifecycleCompileError("lifecycle_attempt_binding_invalid")

    value, parse_failure = RUNNER._strict_json_object(artifact_raw)
    if parse_failure:
        raise LifecycleCompileError("lifecycle_response_invalid", parse_failure)
    assert value is not None
    schema_failure = RUNNER._schema_finding(value, schema)
    if schema_failure:
        raise LifecycleCompileError("lifecycle_response_schema_mismatch", schema_failure)
    if value.get("route_identity") != expected_identity:
        raise LifecycleCompileError("lifecycle_response_identity_mismatch")
    return {"content": value["content"]}


def _scheduled_inputs(
    *, root: Path, manifest_path: Path, envelope_path: Path, assignment_path: Path,
    workspace_config: Path | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], str, dict[str, Any]]:
    manifest_input = _read_json(manifest_path, "schedule_manifest")
    envelope = _read_json(envelope_path, "task_envelope")
    manifest = APPLICATION._verify_manifest(manifest_input, envelope)
    returned, quality, bundle = APPLICATION._verify_result(
        root, manifest, envelope, allow_role_reference=True,
    )
    role = envelope.get("semantic_role")
    if role not in STAGE_TO_ROLE.values() or bundle.get("semantic_role") != role:
        raise LifecycleCompileError("scheduled_role_invalid", str(role))
    assignment_value = _read_json(assignment_path, "assignment")
    try:
        assignment = RUNNER._require_assignment(copy.deepcopy(assignment_value), root)
        effective = RUNNER._effective_config(root, workspace_config)
        packet = RUNNER._prepare_packet(
            assignment, effective, scheduler_mode=True,
            scheduler_route=manifest["selected_route"]["name"],
        )
    except Exception as exc:
        raise LifecycleCompileError("assignment_invalid", str(exc)) from exc
    returned_resolution = returned.get("route_resolution")
    resolution_attempts = returned_resolution.get("attempts") if isinstance(returned_resolution, dict) else None
    selected_route = manifest["selected_route"]["name"]
    if (
        not isinstance(resolution_attempts, list)
        or len(resolution_attempts) != 1
        or not isinstance(resolution_attempts[0], dict)
        or resolution_attempts[0].get("route_name") != selected_route
    ):
        raise LifecycleCompileError("scheduled_role_resolution_invalid")
    attempt = resolution_attempts[0]
    required_outcome = ("outcome", "detail", "tokens", "quota", "cost")
    if not set(required_outcome).issubset(attempt):
        raise LifecycleCompileError("scheduled_role_resolution_invalid", "attempt outcome")
    packet["attempt_results"] = {
        selected_route: [{field: copy.deepcopy(attempt[field]) for field in required_outcome}]
    }
    try:
        recomputed_resolution = RUNNER._resolve_pre_dispatch(copy.deepcopy(packet))
    except Exception as exc:
        raise LifecycleCompileError("scheduled_role_resolution_invalid", str(exc)) from exc
    if (
        assignment["supervisor_assignment_id"] != manifest["identity"]["assignment_id"]
        or assignment["semantic_role"] != role
        or assignment["expected_artifact"] != returned.get("artifact", {}).get("path")
        or digest(effective, prefixed=True) != returned.get("effective_config_sha256")
        or recomputed_resolution != returned_resolution
        or digest(packet, prefixed=True) != bundle.get("binding", {}).get("route_packet_sha256")
        or packet.get("profile") != ROLE_PROFILES[role]
    ):
        raise LifecycleCompileError("scheduled_role_binding_mismatch")
    artifact_path, artifact_raw = _artifact_bytes(root, returned)
    semantic_view = _lifecycle_semantic_view(
        artifact_raw=artifact_raw,
        assignment=assignment,
        manifest=manifest,
        returned=returned,
    )
    return manifest, envelope, assignment_value, packet, returned, quality, artifact_path, semantic_view


def _base_packet(
    *, stage: str, created_at: str, lane: dict[str, Any], board: dict[str, Any],
    state: dict[str, Any], state_raw: bytes, inputs: dict[str, Any],
    sources: list[dict[str, Any]], events: list[dict[str, Any]],
    dispatch_identity: dict[str, Any] | None,
) -> dict[str, Any]:
    result = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "RoleLifecyclePacket",
        "stage": stage,
        "created_at": created_at,
        "target": {
            "lane_id": lane["lane_id"],
            "assignment_id": lane["assignment_id"],
            "task_id": lane["task_id"],
            "lane_mode": lane["lane_mode"],
            "work_kind": lane["work_kind"],
            "phase_before": lane["phase"],
        },
        "dispatch_identity": copy.deepcopy(dispatch_identity),
        "bindings": {
            "goal_sha256": board["goal_sha256"],
            "board_sha256": board["board_sha256"],
            "supervisor_state_sha256": "sha256:" + hashlib.sha256(state_raw).hexdigest(),
            "supervisor_event_sequence": state["event_sequence"],
            "supervisor_event_hash": state["last_event_hash"],
        },
        "inputs": inputs,
        "source_artifacts": sources,
        "events": events,
        "applied_to_supervisor": False,
        "applied_to_goalbuddy": False,
        "accepted": False,
        "acceptance_authority": "Parent Codex",
    }
    result["packet_sha256"] = digest(result, prefixed=True)
    return result


def compile_scheduled(
    *, stage: str, manifest_path: Path, envelope_path: Path, assignment_path: Path,
    target_lane_id: str, trusted_command_receipt_path: Path | None,
    root: Path, goal_path: Path, board_path: Path, state_path: Path,
    event_log_path: Path, created_at: str, workspace_config: Path | None = None,
) -> dict[str, Any]:
    if stage not in STAGE_TO_ROLE:
        raise LifecycleCompileError("stage_invalid", stage)
    root = root.resolve(strict=True)
    manifest, envelope, _, route_packet, returned, _, artifact_path, semantic_view = _scheduled_inputs(
        root=root, manifest_path=manifest_path, envelope_path=envelope_path,
        assignment_path=assignment_path, workspace_config=workspace_config,
    )
    if envelope["semantic_role"] != STAGE_TO_ROLE[stage]:
        raise LifecycleCompileError("stage_role_mismatch")
    board, state, _, state_raw = _runtime_snapshot(
        root=root, goal_path=goal_path, board_path=board_path,
        state_path=state_path, event_log_path=event_log_path,
    )
    lane = _target_lane(state, target_lane_id, stage)
    marker_result: str | None = None
    trusted = None
    trusted_descriptor = None
    if stage in {"tester", "auditor"}:
        matches = RESULT_MARKER.findall(semantic_view["content"])
        if len(matches) != 1:
            raise LifecycleCompileError("role_result_marker_invalid", stage)
        marker_result = matches[0]
    if stage == "tester":
        if trusted_command_receipt_path is None:
            raise LifecycleCompileError("trusted_receipt_required", stage)
        trusted_value = _read_json(trusted_command_receipt_path, "trusted_command_receipt")
        trusted = _trusted_receipt(trusted_value, lane=lane, purpose="independent_test")
        trusted_descriptor = _descriptor(root, trusted_command_receipt_path, "TrustedCommandReceipt")
        if marker_result != trusted["result"]:
            raise LifecycleCompileError("role_result_trusted_result_mismatch")
    elif trusted_command_receipt_path is not None:
        raise LifecycleCompileError("trusted_receipt_unexpected", stage)
    if stage == "documenter" and len(DOCUMENT_MARKER.findall(semantic_view["content"])) != 1:
        raise LifecycleCompileError("documentation_semantic_change")
    if stage in {"tester", "auditor"}:
        builder_group = lane.get("route_identity", {}).get("independence_group")
        if (
            route_packet.get("independence_required") is not True
            or not isinstance(builder_group, str)
            or builder_group not in route_packet.get("independence_exclusions", [])
        ):
            raise LifecycleCompileError("role_not_independent", stage)
    payload: dict[str, Any]
    if stage == "tester":
        payload = {
            "route_packet": route_packet,
            "artifact": artifact_path,
            "result": marker_result,
            "trusted_commands": trusted["commands"],
        }
    elif stage == "documenter":
        required_sources = [lane.get("current_work_artifact"), lane.get("independent_test_artifact")]
        if not all(isinstance(item, str) for item in required_sources):
            raise LifecycleCompileError("documentation_sources_missing")
        payload = {
            "artifact": artifact_path,
            "derived_from": required_sources,
            "semantic_changes": "none",
        }
    else:
        payload = {"route_packet": route_packet, "artifact": artifact_path, "result": marker_result}
    event = {
        "schema_version": 1,
        "event_id": "lifecycle-" + digest([manifest["manifest_sha256"], target_lane_id, stage])[:32],
        "timestamp": created_at,
        "event_type": STAGE_TO_EVENT[stage],
        "lane_id": target_lane_id,
        "payload": payload,
    }
    try:
        SUPERVISOR.transition_runtime(copy.deepcopy(state), board, event, root)
    except SUPERVISOR.LoopError as exc:
        raise LifecycleCompileError("supervisor_preflight_rejected", f"{exc.code}:{exc.detail}") from exc
    inputs = {
        "schedule_manifest": _descriptor(root, manifest_path, "DispatchScheduleManifest"),
        "task_envelope": _descriptor(root, envelope_path, "DispatchTaskEnvelope"),
        "assignment": _descriptor(root, assignment_path, "HeadlessDispatchAssignment"),
        "trusted_command_receipt": trusted_descriptor,
        "closeout_artifact": None,
    }
    sources = [
        {
            "path": artifact_path,
            "sha256": returned["artifact"]["sha256"],
            "size_bytes": returned["artifact"]["bytes"],
            "artifact_kind": "ProviderRoleArtifact",
        }
    ]
    for source in payload.get("derived_from", []):
        descriptor = next((item for item in lane.get("artifacts", []) if item.get("path") == source), None)
        if not isinstance(descriptor, dict):
            raise LifecycleCompileError("documentation_source_descriptor_missing", source)
        sources.append({
            "path": descriptor["path"],
            "sha256": "sha256:" + descriptor["sha256"],
            "size_bytes": descriptor["size_bytes"],
            "artifact_kind": "SupervisorPredecessorArtifact",
        })
    return _base_packet(
        stage=stage, created_at=created_at, lane=lane, board=board, state=state,
        state_raw=state_raw, inputs=inputs, sources=sources, events=[event],
        dispatch_identity=manifest["identity"],
    )


def compile_self_test(
    *, trusted_command_receipt_path: Path, target_lane_id: str, root: Path,
    goal_path: Path, board_path: Path, state_path: Path, event_log_path: Path,
    created_at: str,
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    board, state, _, state_raw = _runtime_snapshot(
        root=root, goal_path=goal_path, board_path=board_path,
        state_path=state_path, event_log_path=event_log_path,
    )
    lane = _target_lane(state, target_lane_id, "worker_self_test")
    trusted_value = _read_json(trusted_command_receipt_path, "trusted_command_receipt")
    trusted = _trusted_receipt(trusted_value, lane=lane, purpose="worker_self_test")
    event = {
        "schema_version": 1,
        "event_id": "lifecycle-" + digest([trusted["receipt_sha256"], target_lane_id, "worker_self_test"])[:32],
        "timestamp": created_at,
        "event_type": "worker_self_test",
        "lane_id": target_lane_id,
        "payload": {"commands": trusted["commands"]},
    }
    try:
        SUPERVISOR.transition_runtime(copy.deepcopy(state), board, event, root)
    except SUPERVISOR.LoopError as exc:
        raise LifecycleCompileError("supervisor_preflight_rejected", f"{exc.code}:{exc.detail}") from exc
    return _base_packet(
        stage="worker_self_test", created_at=created_at, lane=lane, board=board,
        state=state, state_raw=state_raw,
        inputs={
            "schedule_manifest": None,
            "task_envelope": None,
            "assignment": None,
            "trusted_command_receipt": _descriptor(root, trusted_command_receipt_path, "TrustedCommandReceipt"),
            "closeout_artifact": None,
        },
        sources=[], events=[event], dispatch_identity=None,
    )


def compile_closeout(
    *, closeout_artifact_path: Path, target_lane_id: str, requested_parent_decision: str,
    root: Path, goal_path: Path, board_path: Path, state_path: Path,
    event_log_path: Path, created_at: str,
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    board, state, _, state_raw = _runtime_snapshot(
        root=root, goal_path=goal_path, board_path=board_path,
        state_path=state_path, event_log_path=event_log_path,
    )
    lane = _target_lane(state, target_lane_id, "candidate_closeout")
    artifact_descriptor = _descriptor(root, closeout_artifact_path, "CandidateCloseout")
    event = {
        "schema_version": 1,
        "event_id": "lifecycle-" + digest([artifact_descriptor["sha256"], target_lane_id, "candidate_closeout"])[:32],
        "timestamp": created_at,
        "event_type": "candidate_closeout",
        "lane_id": target_lane_id,
        "payload": {
            "status": "candidate_complete",
            "acceptance_claimed": False,
            "requested_parent_decision": requested_parent_decision,
            "artifact": artifact_descriptor["path"],
        },
    }
    try:
        SUPERVISOR.transition_runtime(copy.deepcopy(state), board, event, root)
    except SUPERVISOR.LoopError as exc:
        raise LifecycleCompileError("supervisor_preflight_rejected", f"{exc.code}:{exc.detail}") from exc
    sources = [copy.deepcopy(artifact_descriptor)]
    return _base_packet(
        stage="candidate_closeout", created_at=created_at, lane=lane, board=board,
        state=state, state_raw=state_raw,
        inputs={
            "schedule_manifest": None,
            "task_envelope": None,
            "assignment": None,
            "trusted_command_receipt": None,
            "closeout_artifact": artifact_descriptor,
        },
        sources=sources, events=[event], dispatch_identity=None,
    )


def validate_packet(value: Any) -> dict[str, Any]:
    fields = {
        "schema_version", "artifact_type", "stage", "created_at", "target",
        "dispatch_identity", "bindings", "inputs", "source_artifacts", "events",
        "applied_to_supervisor", "applied_to_goalbuddy", "accepted",
        "acceptance_authority", "packet_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise LifecycleCompileError("packet_invalid", "shape")
    if value.get("schema_version") != 1 or value.get("artifact_type") != "RoleLifecyclePacket":
        raise LifecycleCompileError("packet_invalid", "kind")
    supplied = value["packet_sha256"]
    payload = copy.deepcopy(value)
    payload.pop("packet_sha256")
    if supplied != digest(payload, prefixed=True):
        raise LifecycleCompileError("packet_invalid", "digest")
    if value.get("stage") not in STAGE_TO_EVENT or not isinstance(value.get("events"), list) or len(value["events"]) != 1:
        raise LifecycleCompileError("packet_invalid", "stage/events")
    stage = value["stage"]
    target = value.get("target")
    bindings = value.get("bindings")
    inputs = value.get("inputs")
    sources = value.get("source_artifacts")
    event = value["events"][0]
    if not isinstance(target, dict) or set(target) != {
        "lane_id", "assignment_id", "task_id", "lane_mode", "work_kind", "phase_before",
    }:
        raise LifecycleCompileError("packet_invalid", "target")
    if any(not isinstance(target.get(field), str) or not target[field] for field in target):
        raise LifecycleCompileError("packet_invalid", "target value")
    if target["phase_before"] not in STAGE_PHASE[stage]:
        raise LifecycleCompileError("packet_invalid", "target phase")
    if not isinstance(bindings, dict) or set(bindings) != {
        "goal_sha256", "board_sha256", "supervisor_state_sha256",
        "supervisor_event_sequence", "supervisor_event_hash",
    }:
        raise LifecycleCompileError("packet_invalid", "bindings")
    plain_digests = (bindings.get("goal_sha256"), bindings.get("board_sha256"), bindings.get("supervisor_event_hash"))
    if any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item) for item in plain_digests):
        raise LifecycleCompileError("packet_invalid", "binding digest")
    if not isinstance(bindings.get("supervisor_state_sha256"), str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", bindings["supervisor_state_sha256"],
    ):
        raise LifecycleCompileError("packet_invalid", "state digest")
    if type(bindings.get("supervisor_event_sequence")) is not int or bindings["supervisor_event_sequence"] < 0:
        raise LifecycleCompileError("packet_invalid", "event sequence")
    if not isinstance(inputs, dict) or set(inputs) != {
        "schedule_manifest", "task_envelope", "assignment",
        "trusted_command_receipt", "closeout_artifact",
    }:
        raise LifecycleCompileError("packet_invalid", "inputs")
    if not isinstance(sources, list):
        raise LifecycleCompileError("packet_invalid", "source_artifacts")

    def descriptor_valid(descriptor: Any) -> bool:
        return (
            isinstance(descriptor, dict)
            and set(descriptor) == {"path", "sha256", "size_bytes", "artifact_kind"}
            and isinstance(descriptor.get("path"), str)
            and bool(descriptor["path"])
            and isinstance(descriptor.get("artifact_kind"), str)
            and bool(descriptor["artifact_kind"])
            and isinstance(descriptor.get("sha256"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", descriptor["sha256"]) is not None
            and type(descriptor.get("size_bytes")) is int
            and descriptor["size_bytes"] >= 0
        )

    if any(not descriptor_valid(item) for item in sources):
        raise LifecycleCompileError("packet_invalid", "source descriptor")
    scheduled = stage in STAGE_TO_ROLE
    required_inputs = {
        "schedule_manifest", "task_envelope", "assignment",
    } if scheduled else ({"trusted_command_receipt"} if stage == "worker_self_test" else {"closeout_artifact"})
    for name, descriptor in inputs.items():
        if (name in required_inputs) != (descriptor is not None):
            if not (scheduled and stage == "tester" and name == "trusted_command_receipt" and descriptor is not None):
                raise LifecycleCompileError("packet_invalid", f"input presence:{name}")
        if descriptor is not None and not descriptor_valid(descriptor):
            raise LifecycleCompileError("packet_invalid", f"input descriptor:{name}")
    if scheduled:
        identity = value.get("dispatch_identity")
        if not isinstance(identity, dict) or set(identity) != {
            "goal_id", "checkpoint_id", "task_id", "assignment_id",
        } or any(not isinstance(item, str) or not item for item in identity.values()):
            raise LifecycleCompileError("packet_invalid", "dispatch_identity")
        if not sources:
            raise LifecycleCompileError("packet_invalid", "scheduled sources")
    elif value.get("dispatch_identity") is not None:
        raise LifecycleCompileError("packet_invalid", "control dispatch_identity")
    if stage != "tester" and inputs["trusted_command_receipt"] is not None and stage != "worker_self_test":
        raise LifecycleCompileError("packet_invalid", "unexpected trusted receipt")
    if stage == "tester" and inputs["trusted_command_receipt"] is None:
        raise LifecycleCompileError("packet_invalid", "tester trusted receipt")
    if stage == "worker_self_test" and sources:
        raise LifecycleCompileError("packet_invalid", "self-test sources")
    if stage == "candidate_closeout" and sources != [inputs["closeout_artifact"]]:
        raise LifecycleCompileError("packet_invalid", "closeout source")
    if not isinstance(event, dict) or set(event) != {
        "schema_version", "event_id", "timestamp", "event_type", "lane_id", "payload",
    }:
        raise LifecycleCompileError("packet_invalid", "event shape")
    try:
        SUPERVISOR._event_input(event)
    except SUPERVISOR.LoopError as exc:
        raise LifecycleCompileError("packet_invalid", f"event:{exc.code}") from exc
    if (
        event.get("event_type") != STAGE_TO_EVENT[stage]
        or event.get("lane_id") != target["lane_id"]
        or event.get("timestamp") != value.get("created_at")
        or value.get("applied_to_supervisor") is not False
        or value.get("applied_to_goalbuddy") is not False
        or value.get("accepted") is not False
        or value.get("acceptance_authority") != "Parent Codex"
    ):
        raise LifecycleCompileError("packet_invalid", "authority")
    return copy.deepcopy(value)


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target-lane", required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--goal", type=Path, required=True)
    parser.add_argument("--board", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--created-at", required=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scheduled = sub.add_parser("scheduled")
    _common(scheduled)
    scheduled.add_argument("--stage", choices=sorted(STAGE_TO_ROLE), required=True)
    scheduled.add_argument("--manifest", type=Path, required=True)
    scheduled.add_argument("--envelope", type=Path, required=True)
    scheduled.add_argument("--assignment", type=Path, required=True)
    scheduled.add_argument("--trusted-command-receipt", type=Path)
    scheduled.add_argument("--workspace-config", type=Path)
    self_test = sub.add_parser("self-test")
    _common(self_test)
    self_test.add_argument("--trusted-command-receipt", type=Path, required=True)
    closeout = sub.add_parser("closeout")
    _common(closeout)
    closeout.add_argument("--closeout-artifact", type=Path, required=True)
    closeout.add_argument(
        "--requested-parent-decision",
        choices=["accept", "repair_directly", "issue_revision_packet"],
        required=True,
    )
    args = parser.parse_args(argv)
    try:
        common = {
            "target_lane_id": args.target_lane,
            "root": args.repo_root,
            "goal_path": args.goal,
            "board_path": args.board,
            "state_path": args.state,
            "event_log_path": args.events,
            "created_at": args.created_at,
        }
        if args.command == "scheduled":
            result = compile_scheduled(
                stage=args.stage, manifest_path=args.manifest,
                envelope_path=args.envelope, assignment_path=args.assignment,
                trusted_command_receipt_path=args.trusted_command_receipt,
                workspace_config=args.workspace_config, **common,
            )
        elif args.command == "self-test":
            result = compile_self_test(
                trusted_command_receipt_path=args.trusted_command_receipt, **common,
            )
        else:
            result = compile_closeout(
                closeout_artifact_path=args.closeout_artifact,
                requested_parent_decision=args.requested_parent_decision, **common,
            )
    except (
        LifecycleCompileError, APPLICATION.ApplicationError,
        SUPERVISOR.LoopError, OSError, ValueError,
    ) as exc:
        print(json.dumps({
            "status": "rejected",
            "code": getattr(exc, "code", "lifecycle_compile_error"),
            "detail": getattr(exc, "detail", str(exc)),
        }, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
