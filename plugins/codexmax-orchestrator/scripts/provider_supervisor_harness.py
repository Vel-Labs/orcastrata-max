#!/usr/bin/env python3
"""Provider-neutral Supervisor validation around the accepted T170 controller.

This module does not schedule, dispatch, retry, accept, fold, or mutate a
GoalBuddy board. It validates one T170 plan against T178 qualification and an
exact task grant, calls the supplied T170 controller once, and normalizes the
resulting provider observations.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any, Mapping


def _load_sibling(filename: str, alias: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(alias, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REGISTRY = _load_sibling("adapter_registry.py", "codexmax_t179_adapter_registry")
AUTHORITY = _load_sibling("provider_work_authority.py", "codexmax_t179_work_authority")
FANOUT = _load_sibling("provider_fanout.py", "codexmax_t179_fanout_plan")
T170 = _load_sibling("run_provider_fanout.py", "codexmax_t179_fanout_controller")
NORMALIZER = _load_sibling("provider_event_normalizer.py", "codexmax_t179_event_normalizer")


SCHEMA_VERSION = 1
REQUEST_TYPE = "ProviderSupervisorHarnessRequestV1"
RECEIPT_TYPE = "ProviderSupervisorHarnessReceiptV1"
LANE_REQUIREMENT_FIELDS = {"qualification_id", "lane_profile", "exact_tool_allowlist"}
GRANT_PRIMITIVE_ORDER = list(REGISTRY.CAPABILITY_PRIMITIVES)
RECEIPT_FIELDS = {
    "schema_version", "artifact_type", "harness_id", "status", "failure",
    "aggregate", "normalized_events", "effective_capability_bindings",
    "controller_owner", "controller_invocations", "retry_requested_by_supervisor",
    "fallback_requested", "hedging_requested", "accepted_by_parent",
    "board_mutation_performed", "fold_performed", "application_performed",
    "receipt_sha256",
}
FALSE_RECEIPT_FLAGS = {
    "retry_requested_by_supervisor", "fallback_requested", "hedging_requested",
    "accepted_by_parent", "board_mutation_performed", "fold_performed",
    "application_performed",
}
AGGREGATE_TERMINAL_STATES = {
    "candidate_ready": "succeeded",
    "source_validated_non_promotable": "succeeded",
    "rejected": "rejected",
    "execution_unknown": "execution_unknown",
}


class HarnessError(ValueError):
    def __init__(self, code: str, path: str = "") -> None:
        super().__init__(f"{code}: {path}" if path else code)
        self.code = code
        self.path = path


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise HarnessError("closed_object_invalid", path)
    return copy.deepcopy(dict(value))


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise HarnessError("timestamp_invalid", path)
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise HarnessError("timestamp_invalid", path) from exc


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _grant_primitives(grant: dict[str, Any]) -> list[str]:
    primitives = {"artifact_output"}
    if grant["access_mode"] in {"read_only", "scoped_write"}:
        primitives.add("local_read")
    if grant["access_mode"] == "scoped_write":
        primitives.add("scoped_write")
    if grant["command_allowlist"]:
        primitives.add("command_execution")
    if grant.get("tool_allowlist"):
        primitives.add("tool_loop")
    if grant.get("browser_policy") == "allowed":
        primitives.add("browser_control")
    if grant.get("web_search_policy") == "allowed":
        primitives.add("web_search")
    if grant.get("connector_policy") == "allowed":
        primitives.add("connector_access")
    return [item for item in GRANT_PRIMITIVE_ORDER if item in primitives]


def resolve_effective_capability(
    registry_value: Mapping[str, Any], *, qualification_id: str,
    lane_profile: str, task_grant: Mapping[str, Any], evaluated_at: str,
    exact_tool_allowlist: list[str] | None = None,
) -> dict[str, Any]:
    """Compute required ∩ adapter ∩ qualification ∩ task-grant capability."""
    validation = REGISTRY.validate_universal_registry(registry_value, evaluated_at=evaluated_at)
    state = validation["qualification_states"].get(qualification_id)
    if state is None or not state["eligible"]:
        raise HarnessError("qualification_not_current", qualification_id)
    qualification = registry_value["qualifications"].get(qualification_id)
    if not isinstance(qualification, Mapping):
        raise HarnessError("qualification_missing", qualification_id)
    compatibility = copy.deepcopy(dict(qualification["compatibility"]))
    cards = [
        card for card in registry_value["adapter_capabilities"].values()
        if card["adapter_id"] == compatibility["adapter_id"]
    ]
    if len(cards) != 1:
        raise HarnessError("adapter_capability_ambiguous", qualification_id)
    adapter = cards[0]
    if (
        adapter.get("adapter_version") != compatibility.get("adapter_version")
        or adapter.get("provider_transport") != compatibility.get("provider_transport")
    ):
        raise HarnessError("qualification_adapter_binding_mismatch", qualification_id)
    grant = AUTHORITY.validate_task_grant(task_grant)
    if grant["schema_version"] != 2:
        raise HarnessError("task_grant_v2_required", grant["grant_id"])
    now = _time(evaluated_at, "evaluated_at")
    if now < _time(grant["issued_at"], "task_grant.issued_at") or now >= _time(grant["expires_at"], "task_grant.expires_at"):
        raise HarnessError("task_grant_not_current", grant["grant_id"])
    requested_tools = [] if exact_tool_allowlist is None else list(exact_tool_allowlist)
    try:
        match = REGISTRY.qualified_lane_match(
            registry_value, qualification_id=qualification_id, lane_name=lane_profile,
            evaluated_at=evaluated_at, exact_tools=requested_tools,
        )
    except REGISTRY.AdapterRegistryError as exc:
        if exc.code == "required_primitive_unqualified":
            raise HarnessError("effective_capability_incomplete", lane_profile) from exc
        if exc.code == "exact_tool_unqualified":
            raise HarnessError("effective_tool_allowlist_incomplete", qualification_id) from exc
        raise
    required = match["required_primitives"]
    supported = list(adapter["supported_primitives"])
    qualified = list(state["proved_primitives"])
    granted = _grant_primitives(grant)
    common = set(required) & set(supported) & set(qualified) & set(granted)
    effective = [item for item in REGISTRY.CAPABILITY_PRIMITIVES if item in common]
    if set(required) != set(effective):
        missing = sorted(set(required) - set(effective))
        raise HarnessError("effective_capability_incomplete", ",".join(missing))
    if requested_tools and (
        not set(requested_tools).issubset(state["exact_tool_allowlist"])
        or not set(requested_tools).issubset(grant["tool_allowlist"])
    ):
        raise HarnessError("effective_tool_allowlist_incomplete", qualification_id)
    expected_access = "scoped_write" if lane_profile in {"scoped_write", "implementation"} else "read_only"
    if grant["access_mode"] != expected_access:
        raise HarnessError("lane_grant_mutation_mismatch", lane_profile)
    core = {
        "required_primitives": required,
        "adapter_supported_primitives": supported,
        "qualified_primitives": qualified,
        "granted_primitives": granted,
        "effective_primitives": effective,
        "exact_tool_allowlist": requested_tools,
    }
    return {
        **core,
        "capability_sha256": NORMALIZER.digest(core),
        "compatibility": compatibility,
        "qualification_sha256": qualification["qualification_sha256"],
        "qualification_expires_at": qualification["expires_at"],
        "grant_expires_at": grant["expires_at"],
        "grant": grant,
    }


def _read_descriptor(root: Path, descriptor: Mapping[str, Any], path: str) -> dict[str, Any]:
    try:
        _, document = FANOUT._json_descriptor(descriptor, path, root)
    except Exception as exc:
        raise HarnessError("descriptor_invalid", path) from exc
    return document


def _lane_bindings(
    plan: dict[str, Any], registry: Mapping[str, Any], requirements: Mapping[str, Any],
    *, evaluated_at: str, artifact_root: Path,
) -> dict[str, dict[str, Any]]:
    if not isinstance(requirements, Mapping) or set(requirements) != {lane["lane_id"] for lane in plan["lanes"]}:
        raise HarnessError("lane_requirement_set_mismatch", "lane_requirements")
    attempts = {row["lane_id"]: row for row in plan["initial_attempts"]}
    bindings: dict[str, dict[str, Any]] = {}
    for lane in plan["lanes"]:
        lane_id = lane["lane_id"]
        requirement = _closed(requirements[lane_id], LANE_REQUIREMENT_FIELDS, f"lane_requirements.{lane_id}")
        if not isinstance(requirement["exact_tool_allowlist"], list):
            raise HarnessError("tool_allowlist_invalid", lane_id)
        capability_card = AUTHORITY.validate_capability_card(_read_descriptor(
            artifact_root, lane["capability_card_descriptor"], f"lanes.{lane_id}.capability_card",
        ))
        task_grant = AUTHORITY.validate_task_grant(_read_descriptor(
            artifact_root, lane["task_grant_descriptor"], f"lanes.{lane_id}.task_grant",
        ))
        execution_binding = _read_descriptor(
            artifact_root, lane["execution_binding_descriptor"], f"lanes.{lane_id}.execution_binding",
        )
        if capability_card["schema_version"] != 2 or capability_card.get("adapter_harness_sha256") != lane["harness_sha256"]:
            raise HarnessError("adapter_harness_binding_mismatch", lane_id)
        effective = resolve_effective_capability(
            registry, qualification_id=requirement["qualification_id"],
            lane_profile=requirement["lane_profile"], task_grant=task_grant,
            evaluated_at=evaluated_at,
            exact_tool_allowlist=requirement["exact_tool_allowlist"],
        )
        compatibility = effective.pop("compatibility")
        qualification_sha256 = effective.pop("qualification_sha256")
        qualification_expiry = effective.pop("qualification_expires_at")
        grant_expiry = effective.pop("grant_expires_at")
        effective.pop("grant")
        qualification = registry["qualifications"][requirement["qualification_id"]]
        adapter_cards = [
            card for card in registry["adapter_capabilities"].values()
            if card["adapter_id"] == compatibility["adapter_id"]
        ]
        if len(adapter_cards) != 1:
            raise HarnessError("adapter_capability_ambiguous", lane_id)
        adapter_card = adapter_cards[0]
        if capability_card["qualification_sha256"] != qualification_sha256:
            raise HarnessError("capability_qualification_binding_mismatch", lane_id)
        if capability_card["adapter_harness_sha256"] not in qualification["evidence_digests"]:
            raise HarnessError("qualification_harness_binding_mismatch", lane_id)
        if (
            adapter_card["adapter_id"] != compatibility["adapter_id"]
            or adapter_card["adapter_version"] != compatibility["adapter_version"]
            or adapter_card["provider_transport"] != compatibility["provider_transport"]
        ):
            raise HarnessError("qualification_adapter_binding_mismatch", lane_id)
        if (
            compatibility["provider"] != lane["provider"]
            or compatibility["exact_model"] != lane["model"]
            or task_grant["route_name"] != lane["route_name"]
            or capability_card["route_name"] != lane["route_name"]
            or capability_card["provider"] != lane["provider"]
            or capability_card["exact_model"] != lane["model"]
            or execution_binding.get("lease_id") != task_grant["lease_id"]
            or execution_binding.get("fencing_token") != task_grant["fencing_token"]
        ):
            raise HarnessError("exact_identity_binding_mismatch", lane_id)
        capability_expiry = capability_card["expires_at"]
        binding_expiry = execution_binding.get("expires_at")
        expiries = [
            _time(capability_expiry, "capability.expires_at"),
            _time(qualification_expiry, "qualification.expires_at"),
            _time(grant_expiry, "grant.expires_at"),
            _time(binding_expiry, "execution_binding.expires_at"),
        ]
        now = _time(evaluated_at, "evaluated_at")
        if now >= min(expiries):
            raise HarnessError("effective_binding_expired", lane_id)
        attempt = attempts[lane_id]
        bindings[lane_id] = {
            "route": {"name": lane["route_name"], "provider": lane["provider"]},
            "model": {"exact_model": lane["model"]},
            "transport": compatibility["provider_transport"],
            "adapter": {"id": compatibility["adapter_id"], "version": compatibility["adapter_version"]},
            "qualification": {"id": requirement["qualification_id"], "sha256": qualification_sha256},
            "capability_card_sha256": capability_card["capability_sha256"],
            "adapter_harness_sha256": capability_card["adapter_harness_sha256"],
            "lane": {
                "id": lane_id, "profile": requirement["lane_profile"],
                "mutation_mode": lane["mutation_mode"],
            },
            "grant": {"id": task_grant["grant_id"], "sha256": task_grant["grant_sha256"]},
            "lease": {
                "id": task_grant["lease_id"], "fencing_token": task_grant["fencing_token"],
                "sha256": lane["lease_sha256"],
            },
            "worktree": {"path": lane["worktree_path"], "identity_sha256": lane["worktree_identity_sha256"]},
            "evidence_root": lane["evidence_directory"],
            "attempt": {"id": attempt["attempt_id"], "index": attempt["attempt_index"]},
            "expiry": {
                "capability": capability_expiry,
                "qualification": qualification_expiry,
                "grant": grant_expiry,
                "execution_binding": binding_expiry,
                "effective": _utc(min(expiries)),
            },
            "effective_capability": effective,
        }
        NORMALIZER.validate_binding(bindings[lane_id])
    return bindings


def _normalize_rows(
    rows: Any, bindings: dict[str, dict[str, Any]], aggregate: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise HarnessError("transport_events_invalid", "transport_events")
    grouped: dict[str, list[dict[str, Any]]] = {lane_id: [] for lane_id in bindings}
    for index, row_value in enumerate(rows):
        row = _closed(row_value, {"lane_id", "event"}, f"transport_events[{index}]")
        lane_id = row["lane_id"]
        if lane_id not in bindings:
            raise HarnessError("transport_lane_unknown", str(lane_id))
        grouped[lane_id].append(NORMALIZER.normalize_transport_event(row["event"], bindings[lane_id]))
    aggregate_lanes = {row["lane_id"]: row for row in aggregate.get("lanes", [])}
    normalized: list[dict[str, Any]] = []
    for lane_id, lane_rows in grouped.items():
        sequence = NORMALIZER.validate_event_sequence(lane_rows)
        summary = aggregate_lanes.get(lane_id)
        if not isinstance(summary, Mapping):
            raise HarnessError("aggregate_lane_missing", lane_id)
        expected = AGGREGATE_TERMINAL_STATES.get(summary.get("final_status"))
        if expected is None or sequence[-1]["terminal_state"] != expected:
            raise HarnessError("terminal_reconciliation_mismatch", lane_id)
        normalized.extend(sequence)
    return normalized


def validate_supervisor_receipt(
    value: Any, *, expected_receipt_sha256: str,
) -> dict[str, Any]:
    """Semantically validate a public Supervisor receipt and all bound events."""
    if not isinstance(expected_receipt_sha256, str) or not NORMALIZER.SHA.fullmatch(expected_receipt_sha256):
        raise HarnessError("expected_receipt_digest_invalid", "expected_receipt_sha256")
    if not isinstance(value, Mapping) or value.get("receipt_sha256") != expected_receipt_sha256:
        raise HarnessError("external_receipt_anchor_mismatch", "expected_receipt_sha256")
    receipt = _closed(value, RECEIPT_FIELDS, "receipt")
    if receipt["schema_version"] != SCHEMA_VERSION or receipt["artifact_type"] != RECEIPT_TYPE:
        raise HarnessError("receipt_identity_invalid", "receipt")
    if not isinstance(receipt["harness_id"], str) or not receipt["harness_id"]:
        raise HarnessError("harness_id_invalid", "receipt.harness_id")
    supplied = receipt["receipt_sha256"]
    core = {key: copy.deepcopy(item) for key, item in receipt.items() if key != "receipt_sha256"}
    if supplied != digest(core):
        raise HarnessError("receipt_digest_mismatch", "receipt")
    if receipt["controller_owner"] != "T170" or receipt["controller_invocations"] != 1:
        raise HarnessError("controller_ownership_invalid", "receipt")
    if any(receipt[name] is not False for name in FALSE_RECEIPT_FLAGS):
        raise HarnessError("receipt_authority_boundary_violation", "receipt")
    bindings = receipt["effective_capability_bindings"]
    if not isinstance(bindings, Mapping) or not bindings:
        raise HarnessError("receipt_bindings_invalid", "receipt")
    validated_bindings = {
        lane_id: NORMALIZER.validate_binding(binding)
        for lane_id, binding in bindings.items()
    }
    if any(binding["lane"]["id"] != lane_id for lane_id, binding in validated_bindings.items()):
        raise HarnessError("receipt_lane_binding_mismatch", "receipt")
    events = receipt["normalized_events"]
    aggregate = receipt["aggregate"]
    failure = receipt["failure"]
    if aggregate is None:
        if receipt["status"] != "execution_unknown" or events != []:
            raise HarnessError("failure_receipt_reconciliation_mismatch", "receipt")
        failure = _closed(failure, {"type", "digest"}, "receipt.failure")
        if (
            not isinstance(failure["type"], str) or not failure["type"]
            or not isinstance(failure["digest"], str)
            or not NORMALIZER.SHA.fullmatch(failure["digest"])
        ):
            raise HarnessError("failure_receipt_invalid", "receipt.failure")
        return receipt
    if failure is not None or not isinstance(aggregate, Mapping):
        raise HarnessError("success_receipt_failure_invalid", "receipt")
    if (
        aggregate.get("artifact_type") != "ProviderFanoutExecutionAggregate"
        or any(aggregate.get(name) is not False for name in (
            "accepted_by_parent", "board_mutation_performed", "fold_performed", "application_performed",
        ))
    ):
        raise HarnessError("aggregate_boundary_violation", "receipt.aggregate")
    if not isinstance(events, list):
        raise HarnessError("normalized_events_invalid", "receipt.normalized_events")
    grouped = {lane_id: [] for lane_id in validated_bindings}
    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            raise HarnessError("normalized_event_invalid", f"receipt.normalized_events[{index}]")
        lane_id = event.get("binding", {}).get("lane", {}).get("id")
        if lane_id not in grouped or event.get("binding") != validated_bindings[lane_id]:
            raise HarnessError("normalized_event_binding_mismatch", f"receipt.normalized_events[{index}]")
        grouped[lane_id].append(copy.deepcopy(dict(event)))
    aggregate_lanes = aggregate.get("lanes")
    if not isinstance(aggregate_lanes, list):
        raise HarnessError("aggregate_lanes_invalid", "receipt.aggregate.lanes")
    summaries = {row.get("lane_id"): row for row in aggregate_lanes if isinstance(row, Mapping)}
    if set(summaries) != set(grouped) or len(summaries) != len(aggregate_lanes):
        raise HarnessError("aggregate_lane_set_mismatch", "receipt.aggregate.lanes")
    terminal_states = set()
    for lane_id, lane_events in grouped.items():
        sequence = NORMALIZER.validate_event_sequence(lane_events)
        terminal = sequence[-1]["terminal_state"]
        expected = AGGREGATE_TERMINAL_STATES.get(summaries[lane_id].get("final_status"))
        if expected is None or terminal != expected:
            raise HarnessError("terminal_reconciliation_mismatch", lane_id)
        terminal_states.add(terminal)
    expected_status = "execution_unknown" if "execution_unknown" in terminal_states else (
        "rejected" if "rejected" in terminal_states else "succeeded"
    )
    if receipt["status"] != expected_status:
        raise HarnessError("receipt_status_reconciliation_mismatch", "receipt.status")
    return receipt


class ProviderSupervisorHarness:
    """Validate and coordinate one exact T170 controller invocation."""

    def __init__(self, controller: Any, *, artifact_root: Path) -> None:
        if type(controller) is not T170.FanoutController:
            raise HarnessError("t170_controller_required", "controller")
        if controller.artifact_root.resolve() != artifact_root.resolve():
            raise HarnessError("artifact_root_mismatch", "controller")
        self.controller = controller
        self.artifact_root = artifact_root

    def execute(self, request_value: Any) -> dict[str, Any]:
        request = _closed(request_value, {
            "schema_version", "artifact_type", "harness_id", "evaluated_at", "plan",
            "registry", "lane_requirements", "transport_events",
        }, "request")
        if request["schema_version"] != SCHEMA_VERSION or request["artifact_type"] != REQUEST_TYPE:
            raise HarnessError("request_identity_invalid", "request")
        if not isinstance(request["harness_id"], str) or not request["harness_id"]:
            raise HarnessError("harness_id_invalid", "request.harness_id")
        now = _time(request["evaluated_at"], "request.evaluated_at")
        try:
            plan = FANOUT.validate_plan(
                copy.deepcopy(request["plan"]), now=now, artifact_root=self.artifact_root,
            )
        except Exception as exc:
            raise HarnessError("t170_plan_invalid", getattr(exc, "code", str(exc))) from exc
        bindings = _lane_bindings(
            plan, request["registry"], request["lane_requirements"],
            evaluated_at=request["evaluated_at"], artifact_root=self.artifact_root,
        )
        try:
            aggregate = self.controller.execute(plan, now=now)
        except BaseException as exc:
            failure = {"type": type(exc).__name__, "digest": digest(str(exc))}
            receipt = {
                "schema_version": SCHEMA_VERSION,
                "artifact_type": RECEIPT_TYPE,
                "harness_id": request["harness_id"],
                "status": "execution_unknown",
                "failure": failure,
                "aggregate": None,
                "normalized_events": [],
                "effective_capability_bindings": bindings,
                "controller_owner": "T170",
                "controller_invocations": 1,
                "retry_requested_by_supervisor": False,
                "fallback_requested": False,
                "hedging_requested": False,
                "accepted_by_parent": False,
                "board_mutation_performed": False,
                "fold_performed": False,
                "application_performed": False,
            }
            receipt["receipt_sha256"] = digest(receipt)
            return validate_supervisor_receipt(
                receipt, expected_receipt_sha256=receipt["receipt_sha256"],
            )
        if (
            aggregate.get("artifact_type") != "ProviderFanoutExecutionAggregate"
            or aggregate.get("accepted_by_parent") is not False
            or aggregate.get("board_mutation_performed") is not False
            or aggregate.get("fold_performed") is not False
            or aggregate.get("application_performed") is not False
        ):
            raise HarnessError("t170_aggregate_boundary_violation", "aggregate")
        normalized = _normalize_rows(request["transport_events"], bindings, aggregate)
        terminal_states = {row["terminal_state"] for row in normalized if row["event_type"] == "attempt_terminal_observed"}
        status = "execution_unknown" if "execution_unknown" in terminal_states else (
            "rejected" if "rejected" in terminal_states else "succeeded"
        )
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": RECEIPT_TYPE,
            "harness_id": request["harness_id"],
            "status": status,
            "failure": None,
            "aggregate": copy.deepcopy(dict(aggregate)),
            "normalized_events": normalized,
            "effective_capability_bindings": bindings,
            "controller_owner": "T170",
            "controller_invocations": 1,
            "retry_requested_by_supervisor": False,
            "fallback_requested": False,
            "hedging_requested": False,
            "accepted_by_parent": False,
            "board_mutation_performed": False,
            "fold_performed": False,
            "application_performed": False,
        }
        receipt["receipt_sha256"] = digest(receipt)
        return validate_supervisor_receipt(
            receipt, expected_receipt_sha256=receipt["receipt_sha256"],
        )
