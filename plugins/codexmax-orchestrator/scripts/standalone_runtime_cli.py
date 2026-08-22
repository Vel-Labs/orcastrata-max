#!/usr/bin/env python3
"""Standalone runtime CLI semantics with an explicit closed effect entry.

The module consumes already-versioned runtime, planner, execution-gateway, and
evidence objects.  It returns operator views and request previews only.  It
never binds a service, grants authority, or accepts work. The separate
``--effect-input`` entry sends a closed effect-kernel request through the fixed
client/service/gateway chain; legacy JSON views remain previews.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

import runtime_evidence as evidence
import runtime_execution_gateway as gateway
import runtime_planner as planner
import standalone_runtime_service as runtime_service
import standalone_runtime_client as runtime_client


CLI_VERSION = 1
REQUEST_TYPE = "standalone_runtime_cli_request_v1"
RECEIPT_TYPE = "standalone_runtime_cli_receipt_v1"
ERROR_TYPE = "standalone_runtime_cli_error_v1"
CASES_TYPE = "standalone_runtime_cli_cases_v1"
POLICY_PROPOSAL_TYPE = "standalone_runtime_policy_proposal_v1"
PLAN_BINDING_TYPE = "runtime_plan_binding_v1"
EVIDENCE_BINDING_TYPE = "runtime_evidence_binding_v1"
COMMANDS = (
    "serve", "status", "routes", "plan", "run", "cancel", "recover",
    "delegate", "lineage", "journal", "policy-propose",
)
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ZERO_SHA256 = "sha256:" + "0" * 64
EFFECT_GUARANTEES = {
    "service_started": False,
    "network_used": False,
    "provider_called": False,
    "lease_created": False,
    "dispatch_started": False,
    "run_mutated": False,
    "journal_written": False,
    "policy_persisted": False,
    "policy_activated": False,
    "authority_granted": False,
    "acceptance_granted": False,
}


class CliError(ValueError):
    """Stable typed failure for malformed or unsafe CLI input."""

    def __init__(self, code: str, path: str = "$"):
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def _reject_nonfinite(value: Any, path: str = "$") -> None:
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        raise CliError("nonfinite_number", path)
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_nonfinite(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_nonfinite(child, f"{path}[{index}]")


def canonical_json(value: Any) -> bytes:
    _reject_nonfinite(value)
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CliError("canonical_json_invalid") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CliError("duplicate_json_key", key)
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise CliError("nonfinite_number", value)


def load_json(path: str | Path) -> Any:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise CliError("input_read_failed", str(path)) from exc
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CliError("utf8_invalid", str(exc.start)) from exc
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except CliError:
        raise
    except json.JSONDecodeError as exc:
        raise CliError("json_invalid", f"line:{exc.lineno}:column:{exc.colno}") from exc
    _reject_nonfinite(value)
    return value


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CliError("object_required", path)
    extra = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if extra:
        raise CliError("unknown_field", f"{path}.{extra[0]}")
    if missing:
        raise CliError("missing_field", f"{path}.{missing[0]}")
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise CliError("identifier_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise CliError("digest_invalid", path)
    return value


def _timestamp(value: Any, path: str) -> str:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise CliError("timestamp_invalid", path)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise CliError("timestamp_invalid", path) from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise CliError("timestamp_invalid", path)
    return value


def _base(command: str, source: Any) -> dict[str, Any]:
    return {
        "cli_version": CLI_VERSION,
        "artifact_type": RECEIPT_TYPE,
        "command": command,
        "source_sha256": digest(source),
        "proof_boundary": "synthetic_local",
        "structured_output": True,
        "side_effect_free": True,
        "effect_guarantees": copy.deepcopy(EFFECT_GUARANTEES),
    }


def _translate(component: str, exc: Exception) -> CliError:
    code = getattr(exc, "code", "validation_failed")
    path = getattr(exc, "path", "$")
    return CliError(f"{component}_{code}", path)


def _validate_service_source(value: Any) -> dict[str, Any]:
    try:
        if isinstance(value, dict) and value.get("artifact_type") == runtime_service.ARTIFACT_TYPE:
            return runtime_service.validate_manifest(value)
    except runtime_service.RuntimeServiceError as exc:
        raise _translate("runtime", exc) from exc
    raise CliError("runtime_precomputed_result_forbidden", "$.input")


def _validate_plan_source(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CliError("plan_object_required", "$.input")
    if value.get("artifact_type") == planner.REQUEST_TYPE:
        try:
            result = planner.plan(value)
        except planner.PlannerError as exc:
            raise _translate("planner", exc) from exc
        _validate_plan_consistency(result)
        return result
    if value.get("artifact_type") != PLAN_BINDING_TYPE:
        raise CliError("plan_artifact_type_invalid", "$.input")
    binding = _closed(value, {"artifact_type", "request", "result", "result_sha256"}, "$.input")
    expected = _validate_plan_source(binding["request"])
    if not isinstance(binding["result"], dict) or binding["result"] != expected:
        raise CliError("plan_result_binding_mismatch", "$.input.result")
    if _sha(binding["result_sha256"], "$.input.result_sha256") != digest(expected):
        raise CliError("plan_result_digest_mismatch", "$.input.result_sha256")
    _validate_plan_consistency(expected)
    return copy.deepcopy(expected)


def _validate_plan_consistency(value: Mapping[str, Any]) -> None:
    expected_root = {
        "artifact_type", "planner_version", "workspace_id", "request_sha256",
        "adapter_snapshot_sha256", "role_id", "task_id", "candidates", "selected",
        "child_preview", "execution_started", "provider_called", "authority_granted",
        "child_dispatched", "acceptance_granted", "side_effect_free",
    }
    _closed(value, expected_root, "$.plan_result")
    if value["artifact_type"] != "runtime_plan_result_v1" or value["planner_version"] != planner.PLANNER_VERSION:
        raise CliError("plan_result_version_invalid", "$.plan_result")
    for field in ("request_sha256", "adapter_snapshot_sha256"):
        _sha(value[field], f"$.plan_result.{field}")
    if any(value[field] is not False for field in (
        "execution_started", "provider_called", "authority_granted", "child_dispatched", "acceptance_granted",
    )) or value["side_effect_free"] is not True:
        raise CliError("plan_effect_claimed", "$.plan_result")
    if not isinstance(value["candidates"], list):
        raise CliError("plan_candidates_invalid", "$.plan_result.candidates")
    eligible_rows: list[Mapping[str, Any]] = []
    seen_routes: set[str] = set()
    for index, candidate in enumerate(value["candidates"]):
        path = f"$.plan_result.candidates[{index}]"
        candidate = _closed(candidate, {"route_id", "adapter_identity_sha256", "identity", "visible", "eligible", "hard_gates", "reasons", "weight", "rank"}, path)
        route_id = _identifier(candidate["route_id"], f"{path}.route_id")
        if route_id in seen_routes:
            raise CliError("plan_route_duplicate", f"{path}.route_id")
        seen_routes.add(route_id)
        _sha(candidate["adapter_identity_sha256"], f"{path}.adapter_identity_sha256")
        if not isinstance(candidate["hard_gates"], list) or not candidate["hard_gates"]:
            raise CliError("plan_gates_invalid", f"{path}.hard_gates")
        gates: dict[str, bool] = {}
        for gate_index, raw_gate in enumerate(candidate["hard_gates"]):
            gate = _closed(raw_gate, {"code", "passed"}, f"{path}.hard_gates[{gate_index}]")
            code = _identifier(gate["code"], f"{path}.hard_gates[{gate_index}].code")
            if code in gates or type(gate["passed"]) is not bool:
                raise CliError("plan_gates_invalid", f"{path}.hard_gates[{gate_index}]")
            gates[code] = gate["passed"]
        derived_eligible = all(gates.values())
        derived_reasons = [gate["code"] for gate in candidate["hard_gates"] if not gate["passed"]] or ["eligible_all_hard_gates_passed"]
        if candidate["eligible"] is not derived_eligible or candidate["reasons"] != derived_reasons:
            raise CliError("plan_eligibility_contradiction", path)
        if derived_eligible:
            eligible_rows.append(candidate)
            if type(candidate["weight"]) is not int or type(candidate["rank"]) is not int:
                raise CliError("plan_ranking_invalid", path)
        elif candidate["weight"] is not None or candidate["rank"] is not None:
            raise CliError("plan_ranking_invalid", path)
    ranked = sorted(eligible_rows, key=lambda row: (-row["weight"], row["route_id"], row["adapter_identity_sha256"]))
    if [row["rank"] for row in ranked] != list(range(1, len(ranked) + 1)):
        raise CliError("plan_ranking_invalid", "$.plan_result.candidates")
    expected_selected = None if not ranked else {"route_id": ranked[0]["route_id"], "adapter_identity_sha256": ranked[0]["adapter_identity_sha256"], "weight": ranked[0]["weight"], "rank": 1}
    if value["selected"] != expected_selected:
        raise CliError("plan_selected_contradiction", "$.plan_result.selected")


def _validate_gateway_source(value: Any) -> dict[str, Any]:
    try:
        return gateway.verify_state(copy.deepcopy(value))
    except gateway.GatewayError as exc:
        raise _translate("gateway", exc) from exc


def _validate_evidence_source(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CliError("evidence_object_required", "$.input")
    if value.get("artifact_type") == evidence.PACKET_TYPE:
        try:
            return evidence.normalize_packet(value)
        except evidence.EvidenceError as exc:
            raise _translate("evidence", exc) from exc
    if value.get("artifact_type") != EVIDENCE_BINDING_TYPE:
        raise CliError("evidence_artifact_type_invalid", "$.input")
    binding = _closed(value, {"artifact_type", "packet", "receipt", "receipt_sha256"}, "$.input")
    expected = _validate_evidence_source(binding["packet"])
    if not isinstance(binding["receipt"], dict) or binding["receipt"] != expected:
        raise CliError("evidence_receipt_binding_mismatch", "$.input.receipt")
    expected_sha = evidence.canonical_digest("runtime-evidence-receipt-v1", {key: item for key, item in expected.items() if key != "receipt_sha256"})
    if expected["receipt_sha256"] != expected_sha:
        raise CliError("evidence_receipt_digest_mismatch", "$.input.receipt.receipt_sha256")
    if _sha(binding["receipt_sha256"], "$.input.receipt_sha256") != digest(expected):
        raise CliError("evidence_binding_digest_mismatch", "$.input.receipt_sha256")
    return copy.deepcopy(expected)


def _route_rows(plan_result: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for candidate in plan_result["candidates"]:
        gates = {gate["code"]: gate["passed"] for gate in candidate["hard_gates"]}
        rows.append({
            "route_id": candidate["route_id"],
            "adapter_identity_sha256": candidate["adapter_identity_sha256"],
            "identity": copy.deepcopy(candidate["identity"]),
            "visible": candidate["visible"],
            "eligible": candidate["eligible"],
            "eligibility_reasons": copy.deepcopy(candidate["reasons"]),
            "rank": candidate["rank"],
            "affinity_weight": candidate["weight"],
            "planes": {
                "observed_capability": {"required_for_plan": True, "passed": gates.get("observed_positive_active_fresh_capability", False)},
                "role_policy": {"required_for_plan": True, "passed": gates.get("role_and_route_compatible", False)},
                "task_requirement": {"required_for_plan": True, "passed": gates.get("task_evidence_exactly_bound", False)},
                "human_authority": {"required_for_plan": True, "passed": gates.get("planning_authority_active_and_bound", False)},
                "billing": {"required_for_plan": True, "passed": gates.get("billing_within_ceilings", False)},
                "health": {"required_for_plan": True, "passed": gates.get("health_observed_healthy_fresh", False)},
                "capacity": {"required_for_plan": False, "status": "not_admitted", "admitted": False},
            },
            "hard_gates": copy.deepcopy(candidate["hard_gates"]),
        })
    return rows


def _json_pointer(path: tuple[str, ...]) -> str:
    return "/" + "/".join(part.replace("~", "~0").replace("/", "~1") for part in path)


def _policy_diff(before: Any, after: Any, path: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    if isinstance(before, dict) and isinstance(after, dict):
        changes: list[dict[str, Any]] = []
        for key in sorted(set(before) | set(after)):
            child = path + (key,)
            if key not in before:
                changes.append({"op": "add", "path": _json_pointer(child), "before": None, "after": copy.deepcopy(after[key])})
            elif key not in after:
                changes.append({"op": "remove", "path": _json_pointer(child), "before": copy.deepcopy(before[key]), "after": None})
            else:
                changes.extend(_policy_diff(before[key], after[key], child))
        return changes
    if before == after:
        return []
    return [{"op": "replace", "path": _json_pointer(path), "before": copy.deepcopy(before), "after": copy.deepcopy(after)}]


def _inverse_changes(changes: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "op": {"add": "remove", "remove": "add", "replace": "replace"}[item["op"]],
            "path": item["path"],
            "before": copy.deepcopy(item["after"]),
            "after": copy.deepcopy(item["before"]),
        }
        for item in reversed(changes)
    ]


def _parsed_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _validate_predecessor_chain(value: Any, sequence: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise CliError("proposal_chain_array_required", "$.input.predecessor_chain")
    if len(value) != sequence - 1:
        raise CliError("proposal_chain_length_invalid", "$.input.predecessor_chain")
    validated: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(value):
        proposal = validate_policy_proposal(raw, path=f"$.input.predecessor_chain[{index}]")
        expected_sequence = index + 1
        if proposal["sequence"] != expected_sequence:
            raise CliError("proposal_sequence_discontinuity", f"$.input.predecessor_chain[{index}].sequence")
        if proposal["proposal_id"] in seen_ids:
            raise CliError("proposal_identity_replay", f"$.input.predecessor_chain[{index}].proposal_id")
        seen_ids.add(proposal["proposal_id"])
        if index == 0:
            if proposal["previous_proposal_sha256"] != ZERO_SHA256:
                raise CliError("proposal_chain_invalid", f"$.input.predecessor_chain[{index}].previous_proposal_sha256")
        else:
            prior = validated[-1]
            if proposal["previous_proposal_sha256"] != prior["proposal_sha256"]:
                raise CliError("proposal_predecessor_digest_mismatch", f"$.input.predecessor_chain[{index}].previous_proposal_sha256")
            if proposal["base_policy_sha256"] != prior["proposed_policy_sha256"]:
                raise CliError("proposal_base_stale", f"$.input.predecessor_chain[{index}].base_policy_sha256")
            if _parsed_timestamp(proposal["created_at"]) <= _parsed_timestamp(prior["created_at"]):
                raise CliError("proposal_time_not_monotonic", f"$.input.predecessor_chain[{index}].created_at")
        validated.append(proposal)
    return validated


def build_policy_proposal(value: Any) -> dict[str, Any]:
    row = _closed(value, {
        "proposal_id", "sequence", "created_at", "previous_proposal_sha256",
        "predecessor_chain", "base_policy", "proposed_policy", "explanation", "rollback_reason",
    }, "$.input")
    proposal_id = _identifier(row["proposal_id"], "$.input.proposal_id")
    if type(row["sequence"]) is not int or row["sequence"] < 1:
        raise CliError("sequence_invalid", "$.input.sequence")
    created_at = _timestamp(row["created_at"], "$.input.created_at")
    previous = _sha(row["previous_proposal_sha256"], "$.input.previous_proposal_sha256")
    predecessors = _validate_predecessor_chain(row["predecessor_chain"], row["sequence"])
    if row["sequence"] == 1:
        if previous != ZERO_SHA256:
            raise CliError("proposal_chain_invalid", "$.input.previous_proposal_sha256")
    else:
        validated_predecessor = predecessors[-1]
        if previous != validated_predecessor["proposal_sha256"]:
            raise CliError("proposal_predecessor_digest_mismatch", "$.input.previous_proposal_sha256")
        if row["sequence"] != validated_predecessor["sequence"] + 1:
            raise CliError("proposal_sequence_discontinuity", "$.input.sequence")
        if _parsed_timestamp(created_at) <= _parsed_timestamp(validated_predecessor["created_at"]):
            raise CliError("proposal_time_not_monotonic", "$.input.created_at")
    if proposal_id in {proposal["proposal_id"] for proposal in predecessors}:
        raise CliError("proposal_identity_replay", "$.input.proposal_id")
    if not isinstance(row["base_policy"], dict) or not isinstance(row["proposed_policy"], dict):
        raise CliError("policy_object_required", "$.input")
    for field in ("explanation", "rollback_reason"):
        if not isinstance(row[field], str) or not row[field].strip():
            raise CliError("string_required", f"$.input.{field}")
    changes = _policy_diff(row["base_policy"], row["proposed_policy"])
    if row["sequence"] > 1 and digest(row["base_policy"]) != validated_predecessor["proposed_policy_sha256"]:
        raise CliError("proposal_base_stale", "$.input.base_policy")
    if not changes:
        raise CliError("policy_no_change", "$.input.proposed_policy")
    inverse = _inverse_changes(changes)
    proposal = {
        "schema_version": 1,
        "artifact_type": POLICY_PROPOSAL_TYPE,
        "proposal_id": proposal_id,
        "sequence": row["sequence"],
        "created_at": row["created_at"],
        "previous_proposal_sha256": previous,
        "base_policy_sha256": digest(row["base_policy"]),
        "proposed_policy_sha256": digest(row["proposed_policy"]),
        "changes": changes,
        "validation": {"valid": True, "codes": ["schema_closed", "diff_deterministic", "activation_forbidden"]},
        "explanation": row["explanation"],
        "rollback": {
            "strategy": "forward_proposal",
            "target_policy_sha256": digest(row["base_policy"]),
            "reason": row["rollback_reason"],
            "inverse_changes": inverse,
            "history_rewritten": False,
        },
        "append_only": True,
        "dry_run": True,
        "policy_persisted": False,
        "policy_activated": False,
        "authority_granted": False,
        "acceptance_granted": False,
    }
    proposal["proposal_sha256"] = digest(proposal)
    return proposal


def validate_policy_proposal(value: Any, *, path: str = "$.input.predecessor_chain") -> dict[str, Any]:
    fields = {
        "schema_version", "artifact_type", "proposal_id", "sequence", "created_at",
        "previous_proposal_sha256", "base_policy_sha256", "proposed_policy_sha256",
        "changes", "validation", "explanation", "rollback", "append_only", "dry_run",
        "policy_persisted", "policy_activated", "authority_granted", "acceptance_granted",
        "proposal_sha256",
    }
    proposal = _closed(value, fields, path)
    if proposal["schema_version"] != 1 or proposal["artifact_type"] != POLICY_PROPOSAL_TYPE:
        raise CliError("proposal_version_invalid", path)
    _identifier(proposal["proposal_id"], f"{path}.proposal_id")
    if type(proposal["sequence"]) is not int or proposal["sequence"] < 1:
        raise CliError("sequence_invalid", f"{path}.sequence")
    _timestamp(proposal["created_at"], f"{path}.created_at")
    for field in ("previous_proposal_sha256", "base_policy_sha256", "proposed_policy_sha256", "proposal_sha256"):
        _sha(proposal[field], f"{path}.{field}")
    if proposal["sequence"] == 1 and proposal["previous_proposal_sha256"] != ZERO_SHA256:
        raise CliError("proposal_chain_invalid", f"{path}.previous_proposal_sha256")
    if proposal["sequence"] > 1 and proposal["previous_proposal_sha256"] == ZERO_SHA256:
        raise CliError("proposal_chain_invalid", f"{path}.previous_proposal_sha256")
    if proposal["base_policy_sha256"] == proposal["proposed_policy_sha256"]:
        raise CliError("policy_no_change", f"{path}.proposed_policy_sha256")
    if not isinstance(proposal["changes"], list) or not proposal["changes"]:
        raise CliError("proposal_changes_invalid", f"{path}.changes")
    change_paths: list[str] = []
    for index, item in enumerate(proposal["changes"]):
        change_path = f"{path}.changes[{index}]"
        change = _closed(item, {"op", "path", "before", "after"}, change_path)
        if change["op"] not in {"add", "remove", "replace"} or not isinstance(change["path"], str) or not change["path"].startswith("/"):
            raise CliError("proposal_changes_invalid", change_path)
        change_paths.append(change["path"])
    if change_paths != sorted(change_paths) or len(change_paths) != len(set(change_paths)):
        raise CliError("proposal_change_order_invalid", f"{path}.changes")
    validation = _closed(proposal["validation"], {"valid", "codes"}, f"{path}.validation")
    if validation != {"valid": True, "codes": ["schema_closed", "diff_deterministic", "activation_forbidden"]}:
        raise CliError("proposal_validation_invalid", f"{path}.validation")
    if not isinstance(proposal["explanation"], str) or not proposal["explanation"].strip():
        raise CliError("proposal_explanation_invalid", f"{path}.explanation")
    rollback = _closed(proposal["rollback"], {"strategy", "target_policy_sha256", "reason", "inverse_changes", "history_rewritten"}, f"{path}.rollback")
    _sha(rollback["target_policy_sha256"], f"{path}.rollback.target_policy_sha256")
    if not isinstance(rollback["reason"], str) or not rollback["reason"].strip():
        raise CliError("proposal_rollback_reason_invalid", f"{path}.rollback.reason")
    if rollback["strategy"] != "forward_proposal" or rollback["history_rewritten"] is not False or not isinstance(rollback["inverse_changes"], list) or not rollback["inverse_changes"]:
        raise CliError("proposal_rollback_invalid", f"{path}.rollback")
    expected_inverse = _inverse_changes(proposal["changes"])
    if rollback["inverse_changes"] != expected_inverse:
        raise CliError("proposal_inverse_mismatch", f"{path}.rollback.inverse_changes")
    if rollback["target_policy_sha256"] != proposal["base_policy_sha256"]:
        raise CliError("proposal_rollback_target_mismatch", f"{path}.rollback.target_policy_sha256")
    for field, expected in (("append_only", True), ("dry_run", True), ("policy_persisted", False), ("policy_activated", False), ("authority_granted", False), ("acceptance_granted", False)):
        if proposal[field] is not expected:
            raise CliError("proposal_effect_claimed", f"{path}.{field}")
    if proposal["proposal_sha256"] != digest({key: item for key, item in proposal.items() if key != "proposal_sha256"}):
        raise CliError("proposal_digest_mismatch", f"{path}.proposal_sha256")
    return copy.deepcopy(proposal)


def execute(request: Mapping[str, Any]) -> dict[str, Any]:
    original = copy.deepcopy(request)
    row = _closed(request, {"cli_version", "artifact_type", "command", "input"}, "$")
    if row["cli_version"] != CLI_VERSION or row["artifact_type"] != REQUEST_TYPE:
        raise CliError("version_or_type_unsupported", "$")
    if row["command"] not in COMMANDS:
        raise CliError("command_unsupported", "$.command")
    command = row["command"]
    source = row["input"]
    result = _base(command, source)

    if command in {"serve", "status"}:
        runtime = _validate_service_source(source)
        result["runtime"] = runtime
        if command == "serve":
            result["serve"] = {
                "requested": True, "started": False, "foreground_required": True,
                "instruction": "Start the accepted workspace-scoped foreground service separately.",
            }
        else:
            result["status"] = {
                "lifecycle": copy.deepcopy(runtime["lifecycle"]),
                "health": copy.deepcopy(runtime["health"]),
                "endpoint": copy.deepcopy(runtime["endpoint"]),
            }
    elif command in {"routes", "plan"}:
        plan_result = _validate_plan_source(source)
        result["role_id"] = plan_result["role_id"]
        result["task_id"] = plan_result["task_id"]
        result["routes"] = _route_rows(plan_result)
        result["selected"] = copy.deepcopy(plan_result["selected"])
        result["child_preview"] = copy.deepcopy(plan_result.get("child_preview"))
        result["execution_started"] = False
    elif command in {"run", "cancel", "recover"}:
        command_input = _closed(source, {"gateway_state", "run_id"}, "$.input")
        state = _validate_gateway_source(command_input["gateway_state"])
        run_id = _identifier(command_input["run_id"], "$.input.run_id")
        try:
            run = gateway.read_run(state, run_id)
        except gateway.GatewayError as exc:
            raise _translate("gateway", exc) from exc
        result["run"] = run
        result["operation_preview"] = {
            "requested": True,
            "performed": False,
            "operation": {"run": "inspect_run", "cancel": "cancel_run", "recover": "recover_run"}[command],
            "requires_separate_admission": command != "run",
        }
    elif command in {"delegate", "lineage", "journal"}:
        receipt = _validate_evidence_source(source)
        if command == "delegate":
            result["delegation"] = copy.deepcopy(receipt["delegation"])
            result["delegation_performed"] = False
        elif command == "lineage":
            result["lineage"] = copy.deepcopy(receipt["lineage"])
            result["checkpoint"] = copy.deepcopy(receipt["checkpoint"])
            result["recovery"] = copy.deepcopy(receipt["recovery"])
        else:
            result["journal"] = copy.deepcopy(receipt["journal"])
            result["messages_executable"] = False
            result["journal_written"] = False
    else:
        result["proposal"] = build_policy_proposal(source)

    if request != original:
        raise CliError("input_mutated")
    result["receipt_sha256"] = digest(result)
    return result


def execute_effect(workspace: str | Path, request: Mapping[str, Any]) -> dict[str, Any]:
    """Execute one closed run/cancel/recover request through the fixed client."""

    original = copy.deepcopy(request)
    try:
        result = runtime_client.StandaloneRuntimeClientV1().effect(workspace, request)
    except runtime_client.ClientError as exc:
        raise CliError(exc.code, exc.path) from exc
    if request != original:
        raise CliError("input_mutated", "$.effect_request")
    return result


def execute_responses(workspace: str | Path, request: Mapping[str, Any]) -> dict[str, Any]:
    """Translate one closed Responses request through the fixed local client."""

    original = copy.deepcopy(request)
    try:
        result = runtime_client.StandaloneRuntimeClientV1().responses(workspace, request)
    except runtime_client.ClientError as exc:
        raise CliError(exc.code, exc.path) from exc
    if request != original:
        raise CliError("input_mutated", "$.responses_request")
    return result


def run_cases(document: Any, source: Path | None = None) -> dict[str, Any]:
    row = _closed(document, {"schema_version", "artifact_type", "cases"}, "$")
    if row["schema_version"] != 1 or row["artifact_type"] != CASES_TYPE:
        raise CliError("cases_version_or_type_unsupported")
    if not isinstance(row["cases"], list) or not row["cases"]:
        raise CliError("cases_array_invalid", "$.cases")
    results: list[dict[str, Any]] = []
    passed = 0
    for index, case in enumerate(row["cases"]):
        case = _closed(case, {"name", "request", "expected_command", "expected_error"}, f"$.cases[{index}]")
        name = _identifier(case["name"], f"$.cases[{index}].name")
        try:
            receipt = execute(case["request"])
            actual_error = None
            actual_command = receipt["command"]
        except CliError as exc:
            receipt = None
            actual_error = exc.code
            actual_command = None
        ok = actual_command == case["expected_command"] and actual_error == case["expected_error"]
        passed += int(ok)
        results.append({"name": name, "passed": ok, "command": actual_command, "error": actual_error})
    output = {
        "schema_version": 1,
        "artifact_type": "standalone_runtime_cli_cases_receipt_v1",
        "source": None if source is None else str(source),
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "results": results,
        "side_effect_free": True,
        "effect_guarantees": copy.deepcopy(EFFECT_GUARANTEES),
    }
    output["receipt_sha256"] = digest(output)
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", type=Path, help="one standalone CLI request JSON")
    group.add_argument("--cases", type=Path, help="deterministic CLI fixture cases")
    group.add_argument("--effect-input", type=Path, help="one effect_kernel_request_v1 JSON")
    group.add_argument("--responses-input", type=Path, help="one standalone_responses_request_v1 JSON")
    parser.add_argument("--workspace", type=Path, help="workspace for an effect or Responses input")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        source = args.input or args.cases or args.effect_input or args.responses_input
        document = load_json(source)
        if args.effect_input:
            if args.workspace is None:
                raise CliError("workspace_required", "--workspace")
            result = execute_effect(args.workspace, document)
        elif args.responses_input:
            if args.workspace is None:
                raise CliError("workspace_required", "--workspace")
            result = execute_responses(args.workspace, document)
        elif args.input:
            if args.workspace is not None:
                raise CliError("workspace_not_allowed", "--workspace")
            result = execute(document)
        else:
            if args.workspace is not None:
                raise CliError("workspace_not_allowed", "--workspace")
            result = run_cases(document, args.cases)
    except CliError as exc:
        error = {
            "cli_version": CLI_VERSION, "artifact_type": ERROR_TYPE,
            "code": exc.code, "path": exc.path,
            "side_effect_free": args.effect_input is None and args.responses_input is None,
            "effect_guarantees": copy.deepcopy(EFFECT_GUARANTEES),
        }
        print(json.dumps(error, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result.get("failed", 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
