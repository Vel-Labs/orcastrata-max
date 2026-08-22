#!/usr/bin/env python3
"""Record shadow-only learning observations from normalized provider events."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime
import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


SCHEMA_VERSION = 1
ARTIFACT_TYPE = "ProviderLearningObservationV1"
AGGREGATE_TYPE = "ProviderLearningAggregateV1"
ZERO_SHA256 = "sha256:" + "0" * 64
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
DESCRIPTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+~-]{0,255}$")

STAGES = (
    "admission",
    "authentication",
    "transport",
    "response",
    "tool_request",
    "tool_execution",
    "artifact_validation",
    "mutation_reconciliation",
    "receipt_finalization",
)
FAILURE_SYMPTOMS = {
    "admission": "admission_failed",
    "authentication": "authentication_failed",
    "transport": "transport_failed",
    "response": "response_failed",
    "tool_request": "tool_request_failed",
    "tool_execution": "tool_execution_failed",
    "artifact_validation": "artifact_validation_failed",
    "mutation_reconciliation": "mutation_reconciliation_failed",
    "receipt_finalization": "receipt_finalization_failed",
}
FAULT_DOMAINS = {
    "admission": "admission_policy",
    "authentication": "authentication",
    "transport": "provider_transport",
    "response": "provider_response",
    "tool_request": "tool_request_contract",
    "tool_execution": "tool_execution",
    "artifact_validation": "artifact_validation",
    "mutation_reconciliation": "mutation_reconciliation",
    "receipt_finalization": "receipt_finalization",
}
REPAIRS = {
    "admission": "inspect_admission_evidence",
    "authentication": "repair_authentication_configuration",
    "transport": "repair_transport_adapter",
    "response": "repair_response_contract",
    "tool_request": "repair_tool_request_contract",
    "tool_execution": "repair_tool_execution_adapter",
    "artifact_validation": "repair_artifact_validator",
    "mutation_reconciliation": "inspect_mutation_reconciliation",
    "receipt_finalization": "repair_receipt_finalizer",
}
PRE_EXECUTION_STAGES = {"admission", "authentication", "transport"}
DISPOSITIONS = {"propose", "abstain", "reject"}
RETRY_SAFETY = {
    "safe_pre_execution", "unsafe_possible_mutation", "unsafe_execution_unknown",
    "unsafe_execution_started", "not_applicable", "unknown",
}
OUTCOMES = {"success", "failure", "unknown", "in_progress"}
LEARNER_REASONS = {
    "bounded_shadow_repair", "mutation_or_execution_uncertain", "evidence_unknown",
    "no_safe_pre_execution_repair", "invalid_or_unsafe_candidate",
}
MEASUREMENT_FIELDS = (
    "quality_score",
    "turns",
    "latency_ms",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cost_usd",
)
UNKNOWN_REASONS = {"not_exposed", "not_reported", "not_applicable"}
NORMALIZED_EVENT_FIELDS = {
    "schema_version", "artifact_type", "event_type", "stage", "terminal_state",
    "mutation_state", "timestamp", "raw_evidence", "raw_evidence_digest",
    "provider_facts", "binding", "binding_sha256", "retry_allowed",
    "fallback_allowed", "hedging_allowed", "authority_granted",
    "accepted_by_parent", "board_mutation_performed", "fold_performed",
    "event_sha256",
}
OBSERVATION_FIELDS = {
    "schema_version", "artifact_type", "observation_id", "sequence",
    "previous_observation_sha256", "recorded_at", "source_event", "observed",
    "inferred", "dimensions", "measurements", "learner", "effects",
    "observation_sha256",
}
EFFECT_FIELDS = {
    "runtime_action", "authority_expansion", "route_enablement",
    "retry_requested", "acceptance", "fold", "board_mutation",
}
FORBIDDEN_ARTIFACT_KEYS = {
    "prompt", "prompts", "credential", "credentials", "secret", "secrets",
    "private_configuration", "browser_profile", "browser_profiles",
    "transcript", "transcripts", "message", "messages", "content", "body",
    "raw_evidence",
}


def _load_sibling(filename: str, alias: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(alias, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


NORMALIZER = _load_sibling("provider_event_normalizer.py", "codexmax_t180_event_normalizer")
SUPERVISOR = _load_sibling("provider_supervisor_harness.py", "codexmax_t180_supervisor_harness")


class LearningObservationError(ValueError):
    def __init__(self, code: str, path: str = "") -> None:
        super().__init__(f"{code}: {path}" if path else code)
        self.code = code
        self.path = path


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise LearningObservationError("closed_object_invalid", path)
    return copy.deepcopy(dict(value))


def _descriptor(value: Any, path: str) -> str:
    if not isinstance(value, str) or not DESCRIPTOR.fullmatch(value):
        raise LearningObservationError("descriptor_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise LearningObservationError("digest_invalid", path)
    return value


def _timestamp(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LearningObservationError("timestamp_invalid", path)
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise LearningObservationError("timestamp_invalid", path) from exc
    return value


def _assert_no_private_fields(value: Any, path: str = "artifact") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_ARTIFACT_KEYS:
                raise LearningObservationError("private_field_forbidden", f"{path}.{key}")
            _assert_no_private_fields(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_no_private_fields(item, f"{path}[{index}]")


def _validate_normalized_event(
    value: Any, supervisor_receipt: Any, expected_receipt_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        receipt = SUPERVISOR.validate_supervisor_receipt(
            supervisor_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
    except SUPERVISOR.HarnessError as exc:
        raise LearningObservationError("supervisor_receipt_invalid", exc.code) from exc
    event = _closed(value, NORMALIZED_EVENT_FIELDS, "normalized_event")
    if event["schema_version"] != 1 or event["artifact_type"] != "ProviderNormalizedEventV1":
        raise LearningObservationError("normalized_event_required", "normalized_event")
    if event["event_type"] != "attempt_terminal_observed":
        raise LearningObservationError("terminal_normalized_event_required", "normalized_event.event_type")
    supplied = _sha(event["event_sha256"], "normalized_event.event_sha256")
    core = {key: item for key, item in event.items() if key != "event_sha256"}
    if supplied != digest(core):
        raise LearningObservationError("normalized_event_digest_mismatch", "normalized_event")
    if not isinstance(event["raw_evidence"], Mapping):
        raise LearningObservationError("raw_evidence_invalid", "normalized_event.raw_evidence")
    if event["raw_evidence_digest"] != digest(event["raw_evidence"]):
        raise LearningObservationError("raw_evidence_digest_mismatch", "normalized_event")
    if event["binding_sha256"] != digest(event["binding"]):
        raise LearningObservationError("binding_digest_mismatch", "normalized_event")
    for field in (
        "retry_allowed", "fallback_allowed", "hedging_allowed", "authority_granted",
        "accepted_by_parent", "board_mutation_performed", "fold_performed",
    ):
        if event[field] is not False:
            raise LearningObservationError("normalized_event_effect_not_false", field)
    try:
        NORMALIZER.validate_event_sequence([event])
    except NORMALIZER.NormalizationError as exc:
        raise LearningObservationError("normalized_event_invalid", exc.path) from exc
    matches = [item for item in receipt["normalized_events"] if item == event]
    if len(matches) != 1:
        raise LearningObservationError("normalized_event_not_in_supervisor_receipt", "normalized_event")
    return event, receipt


def known(value: int | float) -> dict[str, Any]:
    return {"status": "known", "value": value, "reason": None}


def unknown(reason: str) -> dict[str, Any]:
    if reason not in UNKNOWN_REASONS:
        raise LearningObservationError("unknown_reason_invalid", "reason")
    return {"status": "unknown", "value": None, "reason": reason}


def _measurement(value: Any, path: str) -> dict[str, Any]:
    row = _closed(value, {"status", "value", "reason"}, path)
    if row["status"] == "unknown":
        if row["value"] is not None or row["reason"] not in UNKNOWN_REASONS:
            raise LearningObservationError("unknown_measurement_invalid", path)
        return row
    if row["status"] != "known" or row["reason"] is not None:
        raise LearningObservationError("measurement_status_invalid", path)
    measured = row["value"]
    if isinstance(measured, bool) or not isinstance(measured, (int, float)) or measured < 0:
        raise LearningObservationError("measurement_value_invalid", path)
    if path.endswith("quality_score") and measured > 1:
        raise LearningObservationError("quality_score_invalid", path)
    if any(path.endswith(name) for name in ("turns", "latency_ms", "input_tokens", "output_tokens", "total_tokens")):
        if type(measured) is not int:
            raise LearningObservationError("integer_measurement_required", path)
    return row


def _effects() -> dict[str, bool]:
    return {field: False for field in sorted(EFFECT_FIELDS)}


def _outcome(event: Mapping[str, Any]) -> str:
    terminal = event["terminal_state"]
    if terminal == "succeeded":
        return "success"
    if terminal == "rejected":
        return "failure"
    if terminal == "execution_unknown":
        return "unknown"
    return "in_progress"


def _symptom(stage: str, outcome: str) -> str:
    if outcome == "success":
        return "success_observed"
    if outcome == "failure":
        return FAILURE_SYMPTOMS[stage]
    if outcome == "unknown":
        return "execution_unknown"
    return "no_terminal_symptom"


def _retry_safety(stage: str, outcome: str, mutation_state: str) -> str:
    if mutation_state in {"possible", "confirmed", "unknown"}:
        return "unsafe_possible_mutation"
    if outcome == "unknown":
        return "unsafe_execution_unknown"
    if outcome == "failure" and stage in PRE_EXECUTION_STAGES and mutation_state == "none":
        return "safe_pre_execution"
    if outcome == "failure":
        return "unsafe_execution_started"
    if outcome == "success":
        return "not_applicable"
    return "unknown"


def _learner(
    *, stage: str, outcome: str, mutation_state: str, retry_safety: str,
    evidence_status: str, adapter_id: str, adapter_version: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if outcome == "failure":
        inferred = {
            "probable_fault_domain": FAULT_DOMAINS[stage],
            "confidence": known(0.5) if evidence_status == "known" else unknown("not_reported"),
            "proposed_repair": REPAIRS[stage],
        }
    elif outcome == "success":
        inferred = {
            "probable_fault_domain": "none", "confidence": known(1.0),
            "proposed_repair": "none",
        }
    else:
        inferred = {
            "probable_fault_domain": "unknown", "confidence": unknown("not_reported"),
            "proposed_repair": "none",
        }
    if (
        outcome == "failure" and retry_safety == "safe_pre_execution"
        and mutation_state == "none" and evidence_status == "known"
    ):
        repair = {
            "repair_type": REPAIRS[stage],
            "target_adapter_id": adapter_id,
            "target_adapter_version": adapter_version,
            "same_provider_only": True,
            "new_parent_decision_required": True,
            "retry_allowed": False,
            "provider_substitution": False,
        }
        learner = {
            "disposition": "propose", "reason_code": "bounded_shadow_repair",
            "conditional_repair": repair,
        }
    else:
        reason = (
            "mutation_or_execution_uncertain"
            if retry_safety in {"unsafe_possible_mutation", "unsafe_execution_unknown"}
            else "evidence_unknown"
            if evidence_status == "unknown"
            else "no_safe_pre_execution_repair"
        )
        learner = {"disposition": "abstain", "reason_code": reason, "conditional_repair": None}
    return inferred, learner


def _source_projection(event: Mapping[str, Any]) -> dict[str, Any]:
    binding = event["binding"]
    route = _closed(binding.get("route"), {"name", "provider"}, "binding.route")
    model = _closed(binding.get("model"), {"exact_model"}, "binding.model")
    adapter = _closed(binding.get("adapter"), {"id", "version"}, "binding.adapter")
    lane = _closed(binding.get("lane"), {"id", "profile", "mutation_mode"}, "binding.lane")
    capability = binding.get("effective_capability")
    if not isinstance(capability, Mapping):
        raise LearningObservationError("effective_primitives_invalid", "binding.effective_capability")
    primitives = capability.get("effective_primitives")
    if not isinstance(primitives, list) or not primitives or len(primitives) != len(set(primitives)):
        raise LearningObservationError("effective_primitives_invalid", "binding.effective_capability")
    for path, value in (
        ("source.route.name", route["name"]),
        ("source.route.provider", route["provider"]),
        ("source.model.exact_model", model["exact_model"]),
        ("source.transport", binding.get("transport")),
        ("source.adapter.id", adapter["id"]),
        ("source.adapter.version", adapter["version"]),
        ("source.lane.profile", lane["profile"]),
    ):
        _descriptor(value, path)
    for index, primitive in enumerate(primitives):
        _descriptor(primitive, f"source.effective_primitives[{index}]")
    projection = {
        "route": route,
        "model": model,
        "transport": binding["transport"],
        "adapter": adapter,
        "qualification": copy.deepcopy(binding["qualification"]),
        "capability_card_sha256": _sha(binding["capability_card_sha256"], "binding.capability_card_sha256"),
        "adapter_harness_sha256": _sha(binding["adapter_harness_sha256"], "binding.adapter_harness_sha256"),
        "lane_profile": lane["profile"],
        "effective_primitives": list(primitives),
        "capability_sha256": _sha(
            capability.get("capability_sha256"),
            "binding.effective_capability.capability_sha256",
        ),
    }
    projection["projection_sha256"] = digest(projection)
    return projection


def _validate_source_projection(value: Any) -> dict[str, Any]:
    projection = _closed(value, {
        "route", "model", "transport", "adapter", "lane_profile",
        "qualification", "capability_card_sha256", "adapter_harness_sha256",
        "effective_primitives", "capability_sha256", "projection_sha256",
    }, "observation.source_event.binding_projection")
    route = _closed(projection["route"], {"name", "provider"}, "source.route")
    model = _closed(projection["model"], {"exact_model"}, "source.model")
    adapter = _closed(projection["adapter"], {"id", "version"}, "source.adapter")
    qualification = _closed(projection["qualification"], {"id", "sha256"}, "source.qualification")
    for path, value in (
        ("source.route.name", route["name"]),
        ("source.route.provider", route["provider"]),
        ("source.model.exact_model", model["exact_model"]),
        ("source.transport", projection["transport"]),
        ("source.adapter.id", adapter["id"]),
        ("source.adapter.version", adapter["version"]),
        ("source.lane_profile", projection["lane_profile"]),
        ("source.qualification.id", qualification["id"]),
    ):
        _descriptor(value, path)
    primitives = projection["effective_primitives"]
    if not isinstance(primitives, list) or not primitives or len(primitives) != len(set(primitives)):
        raise LearningObservationError("effective_primitives_invalid", "source.effective_primitives")
    for index, primitive in enumerate(primitives):
        _descriptor(primitive, f"source.effective_primitives[{index}]")
    _sha(projection["capability_sha256"], "source.capability_sha256")
    _sha(qualification["sha256"], "source.qualification.sha256")
    _sha(projection["capability_card_sha256"], "source.capability_card_sha256")
    _sha(projection["adapter_harness_sha256"], "source.adapter_harness_sha256")
    supplied = _sha(projection["projection_sha256"], "source.projection_sha256")
    core = {key: item for key, item in projection.items() if key != "projection_sha256"}
    if supplied != digest(core):
        raise LearningObservationError("source_projection_digest_mismatch", "source")
    return projection


def _dimensions_from_projection(projection: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "provider": projection["route"]["provider"],
        "exact_model": projection["model"]["exact_model"],
        "transport": projection["transport"],
        "adapter_id": projection["adapter"]["id"],
        "adapter_version": projection["adapter"]["version"],
        "primitives": list(projection["effective_primitives"]),
        "task_class": projection["lane_profile"],
    }


def create_observation(
    supervisor_receipt: Any,
    normalized_event: Any,
    *,
    expected_receipt_sha256: str,
    observation_id: str,
    sequence: int,
    previous_observation_sha256: str,
    recorded_at: str,
    measurements: Mapping[str, Any],
    evidence_status: str = "known",
) -> dict[str, Any]:
    """Create one inert observation without copying raw provider evidence."""
    event, receipt = _validate_normalized_event(
        normalized_event, supervisor_receipt, expected_receipt_sha256,
    )
    _descriptor(observation_id, "observation_id")
    if type(sequence) is not int or sequence < 1:
        raise LearningObservationError("sequence_invalid", "sequence")
    _sha(previous_observation_sha256, "previous_observation_sha256")
    _timestamp(recorded_at, "recorded_at")
    stage = event["stage"]
    if stage not in STAGES:
        raise LearningObservationError("stage_invalid", "normalized_event.stage")
    if evidence_status not in {"known", "unknown"}:
        raise LearningObservationError("evidence_status_invalid", "evidence_status")
    metric_rows = _closed(measurements, set(MEASUREMENT_FIELDS), "measurements")
    metric_rows = {
        name: _measurement(metric_rows[name], f"measurements.{name}")
        for name in MEASUREMENT_FIELDS
    }
    projection = _source_projection(event)
    dimensions = _dimensions_from_projection(projection)
    outcome = _outcome(event)
    mutation_state = event["mutation_state"]
    retry_safety = _retry_safety(stage, outcome, mutation_state)
    inferred, learner = _learner(
        stage=stage, outcome=outcome, mutation_state=mutation_state,
        retry_safety=retry_safety, evidence_status=evidence_status,
        adapter_id=dimensions["adapter_id"], adapter_version=dimensions["adapter_version"],
    )
    observation = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "observation_id": observation_id,
        "sequence": sequence,
        "previous_observation_sha256": previous_observation_sha256,
        "recorded_at": recorded_at,
        "source_event": {
            "event_type": event["event_type"],
            "provider_stage": stage,
            "terminal_state": event["terminal_state"],
            "mutation_state": mutation_state,
            "event_sha256": event["event_sha256"],
            "raw_evidence_digest": event["raw_evidence_digest"],
            "provider_facts_digest": digest(event["provider_facts"]),
            "binding_sha256": event["binding_sha256"],
            "supervisor_receipt_sha256": receipt["receipt_sha256"],
            "timestamp": event["timestamp"],
            "binding_projection": projection,
        },
        "observed": {
            "stage": stage,
            "symptom": _symptom(stage, outcome),
            "mutation_state": mutation_state,
            "retry_safety": retry_safety,
            "evidence_status": evidence_status,
            "outcome": outcome,
        },
        "inferred": inferred,
        "dimensions": dimensions,
        "measurements": metric_rows,
        "learner": learner,
        "effects": _effects(),
    }
    observation["observation_sha256"] = digest(observation)
    validate_observation(observation)
    return observation


def validate_observation(value: Any) -> dict[str, Any]:
    row = _closed(value, OBSERVATION_FIELDS, "observation")
    if row["schema_version"] != SCHEMA_VERSION or row["artifact_type"] != ARTIFACT_TYPE:
        raise LearningObservationError("observation_type_invalid", "observation")
    _descriptor(row["observation_id"], "observation.observation_id")
    if type(row["sequence"]) is not int or row["sequence"] < 1:
        raise LearningObservationError("sequence_invalid", "observation.sequence")
    _sha(row["previous_observation_sha256"], "observation.previous_observation_sha256")
    _timestamp(row["recorded_at"], "observation.recorded_at")
    source = _closed(row["source_event"], {
        "event_type", "provider_stage", "terminal_state", "mutation_state",
        "event_sha256", "raw_evidence_digest", "provider_facts_digest",
        "binding_sha256", "supervisor_receipt_sha256", "timestamp", "binding_projection",
    }, "observation.source_event")
    for name in (
        "event_sha256", "raw_evidence_digest", "provider_facts_digest", "binding_sha256",
        "supervisor_receipt_sha256",
    ):
        _sha(source[name], f"observation.source_event.{name}")
    if source["event_type"] != "attempt_terminal_observed":
        raise LearningObservationError("terminal_normalized_event_required", "observation.source_event.event_type")
    if source["provider_stage"] not in STAGES:
        raise LearningObservationError("stage_invalid", "observation.source_event.provider_stage")
    if source["terminal_state"] not in NORMALIZER.TERMINAL_STATES:
        raise LearningObservationError("terminal_state_invalid", "observation.source_event.terminal_state")
    if source["mutation_state"] not in NORMALIZER.MUTATION_STATES:
        raise LearningObservationError("mutation_state_invalid", "observation.source_event.mutation_state")
    _timestamp(source["timestamp"], "observation.source_event.timestamp")
    projection = _validate_source_projection(source["binding_projection"])
    observed = _closed(row["observed"], {
        "stage", "symptom", "mutation_state", "retry_safety", "evidence_status", "outcome",
    }, "observation.observed")
    if (
        observed["stage"] not in STAGES or observed["outcome"] not in OUTCOMES
        or observed["mutation_state"] not in NORMALIZER.MUTATION_STATES
        or observed["retry_safety"] not in RETRY_SAFETY
        or observed["evidence_status"] not in {"known", "unknown"}
    ):
        raise LearningObservationError("observed_value_invalid", "observation.observed")
    derived_outcome = _outcome(source)
    expected_observed = {
        "stage": source["provider_stage"],
        "symptom": _symptom(source["provider_stage"], derived_outcome),
        "mutation_state": source["mutation_state"],
        "retry_safety": _retry_safety(
            source["provider_stage"], derived_outcome, source["mutation_state"],
        ),
        "evidence_status": observed["evidence_status"],
        "outcome": derived_outcome,
    }
    if observed != expected_observed:
        raise LearningObservationError("observed_derivation_mismatch", "observation.observed")
    inferred = _closed(row["inferred"], {
        "probable_fault_domain", "confidence", "proposed_repair",
    }, "observation.inferred")
    if inferred["probable_fault_domain"] not in set(FAULT_DOMAINS.values()) | {"none", "unknown"}:
        raise LearningObservationError("fault_domain_invalid", "observation.inferred")
    if inferred["proposed_repair"] not in set(REPAIRS.values()) | {"none"}:
        raise LearningObservationError("proposed_repair_invalid", "observation.inferred")
    _measurement(inferred["confidence"], "observation.inferred.confidence")
    learner = _closed(row["learner"], {"disposition", "reason_code", "conditional_repair"}, "observation.learner")
    if learner["disposition"] not in DISPOSITIONS or learner["reason_code"] not in LEARNER_REASONS:
        raise LearningObservationError("disposition_invalid", "observation.learner.disposition")
    expected_inferred, expected_learner = _learner(
        stage=expected_observed["stage"], outcome=derived_outcome,
        mutation_state=expected_observed["mutation_state"],
        retry_safety=expected_observed["retry_safety"],
        evidence_status=expected_observed["evidence_status"],
        adapter_id=projection["adapter"]["id"],
        adapter_version=projection["adapter"]["version"],
    )
    if inferred != expected_inferred:
        raise LearningObservationError("inference_derivation_mismatch", "observation.inferred")
    if learner != expected_learner:
        raise LearningObservationError("learner_derivation_mismatch", "observation.learner")
    effects = _closed(row["effects"], EFFECT_FIELDS, "observation.effects")
    if effects != _effects():
        raise LearningObservationError("effect_derivation_mismatch", "observation.effects")
    dimensions = _closed(row["dimensions"], {
        "provider", "exact_model", "transport", "adapter_id", "adapter_version",
        "primitives", "task_class",
    }, "observation.dimensions")
    for name in ("provider", "exact_model", "transport", "adapter_id", "adapter_version", "task_class"):
        _descriptor(dimensions[name], f"observation.dimensions.{name}")
    if not isinstance(dimensions["primitives"], list) or not dimensions["primitives"] or len(dimensions["primitives"]) != len(set(dimensions["primitives"])):
        raise LearningObservationError("effective_primitives_invalid", "observation.dimensions.primitives")
    for index, primitive in enumerate(dimensions["primitives"]):
        _descriptor(primitive, f"observation.dimensions.primitives[{index}]")
    if dimensions != _dimensions_from_projection(projection):
        raise LearningObservationError("dimension_derivation_mismatch", "observation.dimensions")
    measurements = _closed(row["measurements"], set(MEASUREMENT_FIELDS), "observation.measurements")
    for name in MEASUREMENT_FIELDS:
        _measurement(measurements[name], f"observation.measurements.{name}")
    _assert_no_private_fields(row)
    supplied = _sha(row["observation_sha256"], "observation.observation_sha256")
    core = {key: item for key, item in row.items() if key != "observation_sha256"}
    if supplied != digest(core):
        raise LearningObservationError("observation_digest_mismatch", "observation")
    return row


def _read_ledger(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, raw in enumerate(path.read_bytes().splitlines(), start=1):
        try:
            row = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LearningObservationError("ledger_json_invalid", f"line[{line_number}]") from exc
        validate_observation(row)
        expected_previous = ZERO_SHA256 if not rows else rows[-1]["observation_sha256"]
        if row["sequence"] != line_number or row["previous_observation_sha256"] != expected_previous:
            raise LearningObservationError("ledger_chain_invalid", f"line[{line_number}]")
        if any(existing["observation_id"] == row["observation_id"] for existing in rows):
            raise LearningObservationError("observation_id_duplicate", f"line[{line_number}]")
        rows.append(row)
    return rows


def read_ledger(path: Path, *, expected_head: str) -> list[dict[str, Any]]:
    """Read a ledger only against a retained external provenance checkpoint."""
    _sha(expected_head, "expected_head")
    rows = _read_ledger(path)
    current_head = ZERO_SHA256 if not rows else rows[-1]["observation_sha256"]
    if current_head != expected_head:
        raise LearningObservationError("external_head_mismatch", "expected_head")
    return rows


def verify_ledger(path: Path, *, expected_head: str) -> dict[str, Any]:
    rows = read_ledger(path, expected_head=expected_head)
    return {"status": "valid", "count": len(rows), "head": expected_head}


def append_observation(
    path: Path, payload: Mapping[str, Any], *, expected_head: str,
    expected_receipt_sha256: str,
) -> dict[str, Any]:
    """Append one observation under a compare-and-append hash-chain lock."""
    _sha(expected_head, "expected_head")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        rows = _read_ledger(path)
        current_head = ZERO_SHA256 if not rows else rows[-1]["observation_sha256"]
        if expected_head != current_head:
            raise LearningObservationError("stale_head", "expected_head")
        if any(row["observation_id"] == payload.get("observation_id") for row in rows):
            raise LearningObservationError("observation_id_duplicate", "observation_id")
        observation = create_observation(
            payload["supervisor_receipt"], payload["normalized_event"],
            expected_receipt_sha256=expected_receipt_sha256,
            observation_id=payload["observation_id"],
            sequence=len(rows) + 1, previous_observation_sha256=current_head,
            recorded_at=payload["recorded_at"], measurements=payload["measurements"],
            evidence_status=payload.get("evidence_status", "known"),
        )
        handle.seek(0, 2)
        handle.write(canonical_json(observation) + b"\n")
        handle.flush()
        return observation


def _bucket_summary(key: Any, members: list[dict[str, Any]]) -> dict[str, Any]:
    metric_summary = {}
    for name in MEASUREMENT_FIELDS:
        known_values = [
            member["measurements"][name]["value"]
            for member in members
            if member["measurements"][name]["status"] == "known"
        ]
        unknown_count = len(members) - len(known_values)
        metric_summary[name] = {
            "status": "known" if known_values else "unknown",
            "known_count": len(known_values),
            "unknown_count": unknown_count,
            "sum": sum(known_values) if known_values else None,
            "average": (sum(known_values) / len(known_values)) if known_values else None,
        }
    failure_tags: dict[str, int] = {}
    for member in members:
        if member["observed"]["outcome"] == "failure":
            tag = member["observed"]["symptom"]
            failure_tags[tag] = failure_tags.get(tag, 0) + 1
    return {
        "key": key,
        "observation_count": len(members),
        "success_count": sum(member["observed"]["outcome"] == "success" for member in members),
        "failure_count": sum(member["observed"]["outcome"] == "failure" for member in members),
        "unknown_count": sum(member["observed"]["outcome"] == "unknown" for member in members),
        "failure_tags": failure_tags,
        "measurements": metric_summary,
    }


def _aggregate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    validated = [validate_observation(row) for row in rows]
    dimensions: dict[str, list[dict[str, Any]]] = {}
    selectors = {
        "exact_model": lambda row: [row["dimensions"]["exact_model"]],
        "transport": lambda row: [row["dimensions"]["transport"]],
        "adapter_version": lambda row: [row["dimensions"]["adapter_version"]],
        "primitive": lambda row: row["dimensions"]["primitives"],
        "task_class": lambda row: [row["dimensions"]["task_class"]],
    }
    for dimension, selector in selectors.items():
        buckets: dict[str, list[dict[str, Any]]] = {}
        for row in validated:
            for key in selector(row):
                buckets.setdefault(key, []).append(row)
        output = []
        for key in sorted(buckets):
            output.append(_bucket_summary(key, buckets[key]))
        dimensions[dimension] = output
    joint_buckets: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
    for row in validated:
        source = row["dimensions"]
        for primitive in source["primitives"]:
            key = (
                source["exact_model"], source["transport"], source["adapter_version"],
                primitive, source["task_class"],
            )
            joint_buckets.setdefault(key, []).append(row)
    joint_output = []
    for key in sorted(joint_buckets):
        joint_output.append(_bucket_summary(
            {
                "exact_model": key[0], "transport": key[1],
                "adapter_version": key[2], "primitive": key[3],
                "task_class": key[4],
            },
            joint_buckets[key],
        ))
    dimensions["joint_identity"] = joint_output
    result = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": AGGREGATE_TYPE,
        "observation_count": len(validated),
        "dimensions": dimensions,
        "effects": _effects(),
    }
    result["aggregate_sha256"] = digest(result)
    return result


def aggregate_observations(path: Path, *, expected_head: str) -> dict[str, Any]:
    """Aggregate only a ledger bound to a retained external head."""
    return _aggregate_rows(read_ledger(path, expected_head=expected_head))


def evaluate_repair_candidate(observation: Any, candidate: Any = None) -> dict[str, Any]:
    """Classify a shadow candidate without applying it or changing the ledger."""
    row = validate_observation(observation)
    if candidate is None:
        disposition = row["learner"]["disposition"]
        reason = row["learner"]["reason_code"]
        repair = copy.deepcopy(row["learner"]["conditional_repair"])
    else:
        expected_fields = {
            "repair_type", "target_adapter_id", "target_adapter_version",
            "retry_requested", "provider_substitution", "route_enablement",
            "authority_expansion",
        }
        safe = isinstance(candidate, Mapping) and set(candidate) == expected_fields
        expected = row["learner"]["conditional_repair"]
        if safe:
            safe = (
                row["learner"]["disposition"] == "propose"
                and candidate["repair_type"] == expected["repair_type"]
                and candidate["target_adapter_id"] == expected["target_adapter_id"]
                and candidate["target_adapter_version"] == expected["target_adapter_version"]
                and candidate["retry_requested"] is False
                and candidate["provider_substitution"] is False
                and candidate["route_enablement"] is False
                and candidate["authority_expansion"] is False
            )
        if safe:
            disposition = "propose"
            reason = "bounded_shadow_repair"
            repair = copy.deepcopy(expected)
        else:
            disposition = "reject"
            reason = "invalid_or_unsafe_candidate"
            repair = None
    decision = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "ProviderLearningDecisionV1",
        "observation_sha256": row["observation_sha256"],
        "disposition": disposition,
        "reason_code": reason,
        "conditional_repair": repair,
        "effects": _effects(),
    }
    decision["decision_sha256"] = digest(decision)
    return decision


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    append = subparsers.add_parser("append")
    append.add_argument("--ledger", type=Path, required=True)
    append.add_argument("--input", type=Path, required=True)
    append.add_argument("--expected-head", required=True)
    append.add_argument("--expected-receipt-sha256", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--ledger", type=Path, required=True)
    verify.add_argument("--expected-head", required=True)
    aggregate = subparsers.add_parser("aggregate")
    aggregate.add_argument("--ledger", type=Path, required=True)
    aggregate.add_argument("--expected-head", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "append":
            result = append_observation(
                args.ledger, _load(args.input), expected_head=args.expected_head,
                expected_receipt_sha256=args.expected_receipt_sha256,
            )
        elif args.command == "verify":
            result = verify_ledger(args.ledger, expected_head=args.expected_head)
        else:
            result = aggregate_observations(args.ledger, expected_head=args.expected_head)
        print(canonical_json(result).decode("utf-8"))
        return 0
    except (LearningObservationError, KeyError, OSError, json.JSONDecodeError) as exc:
        code = exc.code if isinstance(exc, LearningObservationError) else "input_invalid"
        print(canonical_json({"status": "rejected", "code": code}).decode("utf-8"))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
