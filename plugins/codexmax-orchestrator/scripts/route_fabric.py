#!/usr/bin/env python3
"""Deterministic, evidence-only Route Fabric validators and policy helpers."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
UNKNOWN = "unknown"
TRUE = "true"
FALSE = "false"
ACTIONS = {"continue", "switch", "clean_handoff", "unavailable", "human_gate"}
CERTIFICATE_STATUSES = {"recalled", "expired", "stale", "active"}
ROUTE_FIELDS = (
    "route_name", "provider", "exact_model", "route_id", "runtime", "runtime_host",
    "reasoning", "billing_basis", "independence_group", "adapter_id", "adapter_sha256",
)
SIGNAL_FIELDS = (
    "progress", "repeat_action", "repeat_error_class", "ping_pong", "rewrite_retest",
    "no_progress", "context_pressure", "budget_pressure", "provider_unavailable",
    "quality_rejected", "execution_unknown",
)
HARD_STOP_FIELDS = (
    "authority", "credential", "billing", "scope", "identity", "execution_unknown",
    "external_exhaustion", "validation_failed", "quality_rejected", "no_qualified_route",
)
FORBIDDEN_HANDOFF_KEYS = {
    "credentials", "credential", "raw_prompt", "raw_source", "raw_tool_output",
    "raw_transcript", "transcript", "provider_reasoning", "stale_narration",
}
HANDOFF_CODES = {
    "accepted_artifact", "ledger", "quality_receipt", "repair", "rewrite", "retest", "reroute",
    "revise_packet", "split_work", "validation_failed", "provider_failed", "execution_unknown",
    "context_pressure", "budget_stop", "unavailable", "next_proof",
}
USAGE_FIELDS = {"input_tokens", "output_tokens", "total_tokens", "cash_effect_usd"}
ADVISORY_DECISION_FIELDS = {
    "artifact_type", "assignment_id", "source_bindings", "current_route_identity",
    "current_certificate_sha256", "target_route_identity", "trajectory_sha256", "action",
    "reason_codes", "authorization_required", "retry_started", "fallback_started",
    "dispatch_started", "board_mutated", "accepted", "decision_sha256",
}
ADVISORY_WRAPPER_FIELDS = {
    "schema_version", "artifact_type", "decision", "bindings", "advisory_sha256",
}
ADVISORY_BINDING_FIELDS = {
    "assignment_id", "envelope_sha256", "ledger_head_before", "decision_sha256",
}


class FabricError(ValueError):
    """Stable typed failure for malformed or tampered Route Fabric input."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _reject_nonfinite_value(value: Any, path: str = "root") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise FabricError("nonfinite_number", path)
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_nonfinite_value(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_nonfinite_value(child, f"{path}[{index}]")


def canonical_json(value: Any) -> bytes:
    _reject_nonfinite_value(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_digest(value: Any, *, exclude_field: str | None = None) -> str:
    candidate = copy.deepcopy(value)
    if exclude_field is not None:
        if not isinstance(candidate, dict):
            raise FabricError("digest_input_invalid", "exclude_field requires an object")
        candidate.pop(exclude_field, None)
    return "sha256:" + hashlib.sha256(canonical_json(candidate)).hexdigest()


def _object(value: Any, field: str, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FabricError("object_required", field)
    allowed = required | (optional or set())
    unknown = sorted(set(value) - allowed)
    missing = sorted(required - set(value))
    if unknown:
        raise FabricError("unknown_field", f"{field}.{unknown[0]}")
    if missing:
        raise FabricError("missing_field", f"{field}.{missing[0]}")
    return copy.deepcopy(value)


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise FabricError("string_required", field)
    return value


def _sha(value: Any, field: str, *, allow_unknown: bool = False) -> str:
    if allow_unknown and value == UNKNOWN:
        return value
    value = _string(value, field)
    if not SHA256_RE.fullmatch(value):
        raise FabricError("digest_invalid", field)
    return value


def _timestamp(value: Any, field: str) -> str:
    value = _string(value, field)
    if not TIMESTAMP_RE.fullmatch(value):
        raise FabricError("timestamp_invalid", field)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FabricError("timestamp_invalid", field) from exc
    return value


def _bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise FabricError("boolean_required", field)
    return value


def _bool_or_unknown(value: Any, field: str) -> bool | str:
    if value == UNKNOWN:
        return UNKNOWN
    return _bool(value, field)


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FabricError("nonnegative_integer_required", field)
    return value


def _nonnegative_number(value: Any, field: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise FabricError("nonnegative_number_required", field)
    return value


def _route_identity(value: Any, field: str = "route_identity") -> dict[str, str]:
    result = _object(value, field, set(ROUTE_FIELDS))
    return {key: _string(result[key], f"{field}.{key}") for key in ROUTE_FIELDS}


def validate_route_identity(
    value: Mapping[str, Any], *, provider_prose_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate transport identity; prose may only contradict, never establish it."""
    identity = _route_identity(value)
    if provider_prose_identity is not None:
        prose = _route_identity(provider_prose_identity, "provider_prose_identity")
        if prose != identity:
            raise FabricError("identity_mismatch", "provider_prose_identity")
    return {"valid": True, "route_identity": identity, "identity_sha256": canonical_digest(identity)}


def _dict(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FabricError("object_required", field)
    return copy.deepcopy(value)


def _unique_strings(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise FabricError("string_array_required", field)
    if len(value) != len(set(value)):
        raise FabricError("duplicate_value", field)
    return list(value)


def _descriptor(value: Any, field: str) -> dict[str, Any]:
    result = _object(value, field, {"kind", "sha256"}, {"path", "size_bytes"})
    _string(result["kind"], f"{field}.kind")
    _sha(result["sha256"], f"{field}.sha256", allow_unknown=True)
    if "path" in result:
        _string(result["path"], f"{field}.path")
    if "size_bytes" in result and result["size_bytes"] != UNKNOWN:
        _nonnegative_int(result["size_bytes"], f"{field}.size_bytes")
    return result


def _handoff_descriptor(value: Any, field: str) -> dict[str, str]:
    result = _object(value, field, {"code", "sha256"})
    code = _string(result["code"], f"{field}.code")
    if len(code) > 64 or code not in HANDOFF_CODES:
        raise FabricError("handoff_code_invalid", f"{field}.code")
    _sha(result["sha256"], f"{field}.sha256")
    return {"code": code, "sha256": result["sha256"]}


def _capability_card(value: Any) -> dict[str, Any]:
    card = _object(value, "capability_card", {
        "artifact_type", "registry_entry_sha256", "provider_input_contract_sha256", "capabilities",
        "scopes", "limits", "identity_evidence", "capability_evidence", "observed_at", "expires_at",
        "card_sha256",
    })
    if card["artifact_type"] != "capability_card_v1":
        raise FabricError("artifact_type_invalid", "capability_card.artifact_type")
    _sha(card["registry_entry_sha256"], "capability_card.registry_entry_sha256")
    _sha(card["provider_input_contract_sha256"], "capability_card.provider_input_contract_sha256")
    _dict(card["capabilities"], "capability_card.capabilities")
    _dict(card["scopes"], "capability_card.scopes")
    _dict(card["limits"], "capability_card.limits")
    identity = _object(card["identity_evidence"], "capability_card.identity_evidence", {
        "route_identity", "route_identity_sha256",
    })
    route = _route_identity(identity["route_identity"], "capability_card.identity_evidence.route_identity")
    if _sha(identity["route_identity_sha256"], "capability_card.identity_evidence.route_identity_sha256") != canonical_digest(route):
        raise FabricError("identity_digest_mismatch", "capability_card.identity_evidence")
    capability = _object(card["capability_evidence"], "capability_card.capability_evidence", {
        "capabilities_sha256", "scopes_sha256", "limits_sha256",
    })
    if _sha(capability["capabilities_sha256"], "capability_card.capability_evidence.capabilities_sha256") != canonical_digest(card["capabilities"]):
        raise FabricError("capability_digest_mismatch", "capability_card.capabilities")
    if _sha(capability["scopes_sha256"], "capability_card.capability_evidence.scopes_sha256") != canonical_digest(card["scopes"]):
        raise FabricError("scope_digest_mismatch", "capability_card.scopes")
    if _sha(capability["limits_sha256"], "capability_card.capability_evidence.limits_sha256") != canonical_digest(card["limits"]):
        raise FabricError("limit_digest_mismatch", "capability_card.limits")
    observed = _timestamp(card["observed_at"], "capability_card.observed_at")
    expires = _timestamp(card["expires_at"], "capability_card.expires_at")
    if expires <= observed:
        raise FabricError("evidence_window_invalid", "capability_card")
    _sha(card["card_sha256"], "capability_card.card_sha256")
    if card["card_sha256"] != canonical_digest(card, exclude_field="card_sha256"):
        raise FabricError("card_digest_mismatch", "capability_card.card_sha256")
    return card


def validate_capability_card(
    card: Mapping[str, Any], *, expected_route: Mapping[str, Any] | None = None,
    registry_digest: str | None = None,
) -> dict[str, Any]:
    """Validate immutable observed evidence; never qualify or authorize a route."""
    value = _capability_card(card)
    route = value["identity_evidence"]["route_identity"]
    if expected_route is not None and route != _route_identity(expected_route, "expected_route"):
        raise FabricError("identity_mismatch", "capability_card.identity_evidence.route_identity")
    if registry_digest is not None and value["registry_entry_sha256"] != _sha(registry_digest, "registry_digest"):
        raise FabricError("registry_digest_mismatch", "capability_card.registry_entry_sha256")
    return {
        "valid": True,
        "artifact_type": value["artifact_type"],
        "card_sha256": value["card_sha256"],
        "route_identity": copy.deepcopy(route),
        "status": "observed",
        "findings": [],
        "dispatch_authorized": False,
        "acceptance_authorized": False,
    }


CERTIFICATE_FIELDS = {
    "artifact_type", "certificate_id", "route_identity", "task_profile_id", "task_profile_sha256",
    "provider_input_contract_sha256", "issuer", "registry_entry_sha256", "capability_card_sha256",
    "preflight_sha256", "adapter_sha256", "evaluation_manifest_sha256", "issued_at", "expires_at",
    "issuance_sha256", "recall_event_ids",
}


def _certificate(value: Any) -> dict[str, Any]:
    certificate = _object(value, "qualification_certificate", CERTIFICATE_FIELDS)
    if certificate["artifact_type"] != "qualification_certificate_v1":
        raise FabricError("artifact_type_invalid", "qualification_certificate.artifact_type")
    _string(certificate["certificate_id"], "qualification_certificate.certificate_id")
    _route_identity(certificate["route_identity"], "qualification_certificate.route_identity")
    _string(certificate["task_profile_id"], "qualification_certificate.task_profile_id")
    _sha(certificate["task_profile_sha256"], "qualification_certificate.task_profile_sha256")
    _sha(certificate["provider_input_contract_sha256"], "qualification_certificate.provider_input_contract_sha256")
    _string(certificate["issuer"], "qualification_certificate.issuer")
    for field in (
        "registry_entry_sha256", "capability_card_sha256", "preflight_sha256", "adapter_sha256",
        "evaluation_manifest_sha256", "issuance_sha256",
    ):
        _sha(certificate[field], f"qualification_certificate.{field}")
    issued = _timestamp(certificate["issued_at"], "qualification_certificate.issued_at")
    expires = _timestamp(certificate["expires_at"], "qualification_certificate.expires_at")
    if expires <= issued:
        raise FabricError("certificate_window_invalid", "qualification_certificate")
    _unique_strings(certificate["recall_event_ids"], "qualification_certificate.recall_event_ids")
    issuance_base = {key: certificate[key] for key in certificate if key != "issuance_sha256"}
    if certificate["issuance_sha256"] != canonical_digest(issuance_base):
        raise FabricError("issuance_digest_mismatch", "qualification_certificate.issuance_sha256")
    return certificate


def _certificate_subject_sha256(certificate: Mapping[str, Any]) -> str:
    """Stable certificate subject digest that excludes status/recall metadata."""
    subject = {
        key: value for key, value in certificate.items()
        if key not in {"issuance_sha256", "recall_event_ids"}
    }
    return canonical_digest(subject)


def effective_certificate_status(
    certificate: Mapping[str, Any], *, now: str, registry_entry_sha256: str | None = None,
    capability_card_sha256: str | None = None, provider_input_contract_sha256: str | None = None,
    preflight_sha256: str | None = None, adapter_sha256: str | None = None,
    evaluation_manifest_sha256: str | None = None, recall_events: list[Mapping[str, Any]] | None = None,
    recall_initial_previous: str | None = None,
) -> dict[str, Any]:
    """Derive recalled > expired > stale > active without mutating input."""
    value = _certificate(certificate)
    current = _timestamp(now, "now")
    recall_ids = set(value["recall_event_ids"])
    recalls: set[str] = set()
    if recall_events is not None:
        if not recall_events:
            if recall_ids:
                raise FabricError("recall_evidence_required", "qualification_certificate.recall_event_ids")
        elif recall_initial_previous is None:
            raise FabricError("recall_evidence_required", "qualification_certificate.recall_events")
        else:
            recall_receipt = validate_recall_chain(recall_events, initial_previous=recall_initial_previous)
            observed_ids = set(recall_receipt["event_ids"])
            if recall_ids and observed_ids != recall_ids:
                raise FabricError("recall_id_mismatch", "qualification_certificate.recall_event_ids")
            route = value["route_identity"]
            certificate_subject = _certificate_subject_sha256(value)
            for event in recall_events:
                certificate_subject_match = (
                    event["subject_scope"] == "certificate"
                    and event["subject_id"] == value["certificate_id"]
                    and event["subject_sha256"] == certificate_subject
                )
                route_subject_match = (
                    event["subject_scope"] == "route"
                    and event["subject_id"] == route["route_id"]
                    and event["subject_sha256"] == canonical_digest(route)
                )
                if not (certificate_subject_match or route_subject_match):
                    raise FabricError("recall_subject_mismatch", "qualification_certificate.recall_events")
            recalls = observed_ids
    elif recall_ids:
        raise FabricError("recall_evidence_required", "qualification_certificate.recall_event_ids")
    invalidations: list[str] = []
    if recalls:
        status = "recalled"
        invalidations.append("recall_event_present")
    elif current >= value["expires_at"]:
        status = "expired"
        invalidations.append("certificate_expired")
    else:
        comparisons = {
            "registry_entry_sha256": registry_entry_sha256,
            "capability_card_sha256": capability_card_sha256,
            "provider_input_contract_sha256": provider_input_contract_sha256,
            "preflight_sha256": preflight_sha256,
            "adapter_sha256": adapter_sha256,
            "evaluation_manifest_sha256": evaluation_manifest_sha256,
        }
        for field, expected in comparisons.items():
            if expected is not None and _sha(expected, field) != value[field]:
                invalidations.append(f"{field}_mismatch")
        status = "stale" if invalidations else "active"
    return {
        "artifact_type": "certificate_status_v1",
        "status": status,
        "certificate_sha256": canonical_digest(value),
        "invalidation_reasons": invalidations,
        "dispatch_authorized": False,
        "acceptance_authorized": False,
    }


def build_recall_event(
    subject_scope: str, subject_id: str, subject_sha256: str, reason_code: str,
    created_at: str, authority_sha256: str, previous_event_sha256: str,
) -> dict[str, Any]:
    """Construct one immutable append-only recall event; persistence is external."""
    base = {
        "subject_scope": _string(subject_scope, "subject_scope"),
        "subject_id": _string(subject_id, "subject_id"),
        "subject_sha256": _sha(subject_sha256, "subject_sha256"),
        "reason_code": _string(reason_code, "reason_code"),
        "created_at": _timestamp(created_at, "created_at"),
        "authority_sha256": _sha(authority_sha256, "authority_sha256"),
        "previous_event_sha256": _sha(previous_event_sha256, "previous_event_sha256"),
    }
    return {**base, "event_sha256": canonical_digest(base)}


def validate_recall_chain(events: list[Mapping[str, Any]], *, initial_previous: str) -> dict[str, Any]:
    previous = _sha(initial_previous, "initial_previous")
    event_ids: list[str] = []
    for index, raw in enumerate(events):
        event = _object(raw, f"recall_events[{index}]", {
            "subject_scope", "subject_id", "subject_sha256", "reason_code", "created_at",
            "authority_sha256", "previous_event_sha256", "event_sha256",
        })
        _string(event["subject_scope"], f"recall_events[{index}].subject_scope")
        _string(event["subject_id"], f"recall_events[{index}].subject_id")
        _sha(event["subject_sha256"], f"recall_events[{index}].subject_sha256")
        _string(event["reason_code"], f"recall_events[{index}].reason_code")
        _timestamp(event["created_at"], f"recall_events[{index}].created_at")
        _sha(event["authority_sha256"], f"recall_events[{index}].authority_sha256")
        if event["previous_event_sha256"] != previous:
            raise FabricError("recall_chain_mismatch", str(index))
        _sha(event["previous_event_sha256"], f"recall_events[{index}].previous_event_sha256")
        _sha(event["event_sha256"], f"recall_events[{index}].event_sha256")
        expected = canonical_digest({key: event[key] for key in (
            "subject_scope", "subject_id", "subject_sha256", "reason_code", "created_at",
            "authority_sha256", "previous_event_sha256",
        )})
        if event["event_sha256"] != expected:
            raise FabricError("recall_event_digest_mismatch", str(index))
        event_ids.append(event["event_sha256"])
        previous = event["event_sha256"]
    return {"valid": True, "event_count": len(events), "head_sha256": previous, "event_ids": event_ids}


def _signal(value: bool | None) -> str:
    if value is None:
        return UNKNOWN
    return TRUE if value else FALSE


def _aggregate_tri(values: list[Any]) -> bool | None:
    if not values:
        return None
    if any(value is True for value in values):
        return True
    if any(value == UNKNOWN for value in values):
        return None
    return False


def _outcome_bool(outcome: Mapping[str, Any], *fields: str) -> bool:
    return any(outcome.get(field) is True for field in fields)


def derive_trajectory_signals(value: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce bounded ledger/dispatch/quality facts into deterministic signals."""
    data = _object(value, "trajectory_input", {
        "assignment_id", "attempt_ids", "ledger_sequence_start", "ledger_sequence_end",
        "ledger_head_before", "ledger_head_after", "policy_sha256", "evidence", "outcomes",
        "quality", "continuity", "unknowns",
    })
    _string(data["assignment_id"], "trajectory_input.assignment_id")
    attempts = _unique_strings(data["attempt_ids"], "trajectory_input.attempt_ids")
    start = _nonnegative_int(data["ledger_sequence_start"], "trajectory_input.ledger_sequence_start")
    end = _nonnegative_int(data["ledger_sequence_end"], "trajectory_input.ledger_sequence_end")
    if end < start:
        raise FabricError("ledger_sequence_invalid", "trajectory_input")
    before = _sha(data["ledger_head_before"], "trajectory_input.ledger_head_before", allow_unknown=True)
    after = _sha(data["ledger_head_after"], "trajectory_input.ledger_head_after", allow_unknown=True)
    policy = _sha(data["policy_sha256"], "trajectory_input.policy_sha256")
    if not isinstance(data["evidence"], list):
        raise FabricError("array_required", "trajectory_input.evidence")
    evidence = [_descriptor(item, f"trajectory_input.evidence[{index}]") for index, item in enumerate(data["evidence"])]
    if not isinstance(data["outcomes"], list):
        raise FabricError("array_required", "trajectory_input.outcomes")
    outcomes = [
        _object(item, f"trajectory_input.outcomes[{index}]", {"action", "error_class", "progress"}, {
            "phase", "provider_unavailable", "execution_unknown",
        })
        for index, item in enumerate(data["outcomes"])
    ]
    for index, outcome in enumerate(outcomes):
        _string(outcome["action"], f"trajectory_input.outcomes[{index}].action")
        _string(outcome["error_class"], f"trajectory_input.outcomes[{index}].error_class")
        _bool_or_unknown(outcome["progress"], f"trajectory_input.outcomes[{index}].progress")
        for field in ("provider_unavailable", "execution_unknown"):
            if field in outcome:
                _bool_or_unknown(outcome[field], f"trajectory_input.outcomes[{index}].{field}")
        if "phase" in outcome:
            _string(outcome["phase"], f"trajectory_input.outcomes[{index}].phase")
    actions = [item["action"] for item in outcomes if isinstance(item["action"], str)]
    errors = [item["error_class"] for item in outcomes if isinstance(item["error_class"], str) and item["error_class"]]
    progress_values = [item["progress"] for item in outcomes]
    continuity = _object(data["continuity"], "trajectory_input.continuity", {
        "context_pressure", "budget_pressure",
    })
    context = _bool(continuity["context_pressure"], "trajectory_input.continuity.context_pressure")
    budget = _bool(continuity["budget_pressure"], "trajectory_input.continuity.budget_pressure")
    quality = _object(data["quality"], "trajectory_input.quality", {"accepted"})
    quality_accepted = quality["accepted"]
    if not isinstance(quality_accepted, bool) and quality_accepted != UNKNOWN:
        raise FabricError("boolean_or_unknown_required", "trajectory_input.quality.accepted")
    unknowns = _unique_strings(data["unknowns"], "trajectory_input.unknowns")
    repeated_action = len(actions) >= 2 and actions[-1] == actions[-2]
    repeated_error = len(errors) >= 2 and errors[-1] == errors[-2]
    ping_pong = len(actions) >= 4 and actions[-4:] == [actions[-4], actions[-3], actions[-4], actions[-3]]
    rewrite_retest = len(actions) >= 2 and any(
        actions[index:index + 2] in (["rewrite", "retest"], ["retest", "rewrite"])
        for index in range(len(actions) - 1)
    )
    execution_unknown = _aggregate_tri([
        item["execution_unknown"] if "execution_unknown" in item else UNKNOWN for item in outcomes
    ])
    provider_unavailable = _aggregate_tri([
        item["provider_unavailable"] if "provider_unavailable" in item else UNKNOWN for item in outcomes
    ])
    progress_state = _aggregate_tri(progress_values)
    signals = {
        "progress": _signal(progress_state),
        "repeat_action": _signal(repeated_action if actions else None),
        "repeat_error_class": _signal(repeated_error if errors else None),
        "ping_pong": _signal(ping_pong if actions else None),
        "rewrite_retest": _signal(rewrite_retest if actions else None),
        "no_progress": _signal(None if progress_state is None else not progress_state),
        "context_pressure": _signal(context),
        "budget_pressure": _signal(budget),
        "provider_unavailable": _signal(provider_unavailable),
        "quality_rejected": _signal(quality_accepted is False if quality_accepted is not UNKNOWN else None),
        "execution_unknown": _signal(execution_unknown),
    }
    base = {
        "artifact_type": "trajectory_signal_v1",
        "assignment_id": data["assignment_id"],
        "attempt_ids": attempts,
        "ledger_sequence_start": start,
        "ledger_sequence_end": end,
        "ledger_head_before": before,
        "ledger_head_after": after,
        "policy_sha256": policy,
        "evidence": evidence,
        "signals": signals,
        "unknowns": unknowns,
    }
    return {**base, "trajectory_sha256": canonical_digest(base)}


def _unknown(reason: str) -> dict[str, str]:
    return {"value": UNKNOWN, "reason": _string(reason, "unknown.reason")}


def _measurement(value: Any, field: str, *, reason: str) -> dict[str, Any]:
    if isinstance(value, dict):
        result = _object(value, field, {"value"}, {"reason"})
        if result["value"] == UNKNOWN:
            _string(result.get("reason"), f"{field}.reason")
        else:
            (_nonnegative_number if field.endswith("cash_effect_usd") else _nonnegative_int)(result["value"], f"{field}.value")
        return result
    if value == UNKNOWN or value is None:
        return _unknown(reason)
    return {"value": (_nonnegative_number if field.endswith("cash_effect_usd") else _nonnegative_int)(value, field)}


def _sum_measurements(rows: list[Mapping[str, Any]], field: str, *, reason: str) -> dict[str, Any]:
    values = [row.get(field) for row in rows]
    if not values or any(value is None or value == UNKNOWN or isinstance(value, dict) and value.get("value") == UNKNOWN for value in values):
        return _unknown(reason)
    total = 0
    for value in values:
        if isinstance(value, dict):
            value = value.get("value")
        total += (_nonnegative_number if field == "cash_effect_usd" else _nonnegative_int)(value, field)
    return {"value": total}


def calculate_correction_economics(
    rows: list[Mapping[str, Any]], *, task_family: str, route_identity: Mapping[str, Any],
) -> dict[str, Any]:
    """Produce recommendation-only economics with dimensions and unknown reasons intact."""
    if not isinstance(rows, list):
        raise FabricError("array_required", "economics.rows")
    route = _route_identity(route_identity)
    normalized = [_object(row, "economics.row", {
        "quality_accepted", "correction_attempts", "usage", "elapsed_ms", "pm_correction_ms",
        "quality_receipt_sha256s",
    }) for row in rows]
    for row in normalized:
        if row["quality_accepted"] not in (True, False, UNKNOWN):
            raise FabricError("boolean_or_unknown_required", "economics.row.quality_accepted")
        _nonnegative_int(row["correction_attempts"], "economics.row.correction_attempts")
        _measurement(row["elapsed_ms"], "economics.row.elapsed_ms", reason="elapsed_not_reported")
        _measurement(row["pm_correction_ms"], "economics.row.pm_correction_ms", reason="pm_correction_not_reported")
        usage = _object(row["usage"], "economics.row.usage", USAGE_FIELDS)
        for field in USAGE_FIELDS:
            _measurement(usage[field], f"economics.row.usage.{field}", reason=f"{field}_not_reported")
        _unique_strings(row["quality_receipt_sha256s"], "economics.row.quality_receipt_sha256s")
        for digest in row["quality_receipt_sha256s"]:
            _sha(digest, "economics.row.quality_receipt_sha256s[]")
    token_fields = ("input_tokens", "output_tokens", "total_tokens")
    tokens = {
        field: _sum_measurements([row["usage"] for row in normalized], field, reason=f"{field}_not_reported")
        for field in token_fields
    }
    quality_receipts = [digest for row in normalized for digest in row["quality_receipt_sha256s"]]
    elapsed = _sum_measurements(normalized, "elapsed_ms", reason="elapsed_not_reported")
    pm_correction = _sum_measurements(normalized, "pm_correction_ms", reason="pm_correction_not_reported")
    cash = _sum_measurements([row["usage"] for row in normalized], "cash_effect_usd", reason="cash_effect_not_reported")
    correction_attempts = sum(row["correction_attempts"] for row in normalized)
    unknowns = sorted({
        field for field, measurement in {
            "elapsed_ms": elapsed,
            "pm_correction_ms": pm_correction,
            "cash_effect": cash,
            **{f"tokens.{key}": value for key, value in tokens.items()},
        }.items() if measurement.get("value") == UNKNOWN
    })
    base = {
        "artifact_type": "correction_economics_v1",
        "task_family": _string(task_family, "economics.task_family"),
        "route_identity": route,
        "attempt_count": len(normalized),
        "correction_attempts": correction_attempts,
        "pm_correction_ms": pm_correction,
        "elapsed_ms": elapsed,
        "tokens": tokens,
        "cash_effect": cash,
        "quality_receipt_sha256s": quality_receipts,
        "unknowns": unknowns,
    }
    return {**base, "economics_sha256": canonical_digest(base)}


def _decision_input(value: Any) -> dict[str, Any]:
    data = _object(value, "decision_input", {
        "assignment_id", "current_route_identity", "current_certificate_sha256", "target_route_identity",
        "certificate_status", "signals", "hard_stops", "continuity", "candidate_ready",
        "source_bindings", "trajectory_sha256",
    }, {"provider_prose_identity"})
    _string(data["assignment_id"], "decision_input.assignment_id")
    data["current_route_identity"] = _route_identity(data["current_route_identity"], "decision_input.current_route_identity")
    _sha(data["current_certificate_sha256"], "decision_input.current_certificate_sha256")
    if data["target_route_identity"] is not None:
        raise FabricError("target_selection_forbidden", "decision_input.target_route_identity")
    if "provider_prose_identity" in data:
        validate_route_identity(data["current_route_identity"], provider_prose_identity=data["provider_prose_identity"])
    if data["certificate_status"] not in CERTIFICATE_STATUSES:
        raise FabricError("certificate_status_invalid", "decision_input.certificate_status")
    signals = _object(data["signals"], "decision_input.signals", set(SIGNAL_FIELDS))
    for field in SIGNAL_FIELDS:
        if signals[field] not in {TRUE, FALSE, UNKNOWN}:
            raise FabricError("signal_invalid", f"decision_input.signals.{field}")
    stops = _object(data["hard_stops"], "decision_input.hard_stops", set(HARD_STOP_FIELDS))
    for field in HARD_STOP_FIELDS:
        _bool(stops[field], f"decision_input.hard_stops.{field}")
    continuity = _object(data["continuity"], "decision_input.continuity", {"context_pressure", "budget_pressure"})
    _bool(continuity["context_pressure"], "decision_input.continuity.context_pressure")
    _bool(continuity["budget_pressure"], "decision_input.continuity.budget_pressure")
    if signals["execution_unknown"] == TRUE and not stops["execution_unknown"]:
        raise FabricError("safety_evidence_conflict", "execution_unknown")
    if signals["quality_rejected"] == TRUE and not stops["quality_rejected"]:
        raise FabricError("safety_evidence_conflict", "quality_rejected")
    if signals["budget_pressure"] == TRUE and not continuity["budget_pressure"]:
        raise FabricError("safety_evidence_conflict", "budget_pressure")
    if continuity["budget_pressure"] and signals["budget_pressure"] != TRUE:
        raise FabricError("safety_evidence_conflict", "budget_pressure")
    if signals["context_pressure"] == TRUE and not continuity["context_pressure"]:
        raise FabricError("safety_evidence_conflict", "context_pressure")
    if continuity["context_pressure"] and signals["context_pressure"] != TRUE:
        raise FabricError("safety_evidence_conflict", "context_pressure")
    _bool(data["candidate_ready"], "decision_input.candidate_ready")
    _unique_strings(data["source_bindings"], "decision_input.source_bindings")
    _sha(data["trajectory_sha256"], "decision_input.trajectory_sha256")
    return data


def choose_advisory_action(value: Mapping[str, Any]) -> dict[str, Any]:
    """Emit one advisory action; never choose, admit, retry, fallback, or accept."""
    data = _decision_input(value)
    stops = data["hard_stops"]
    signals = data["signals"]
    reasons: list[str] = []
    if any(stops[field] for field in ("authority", "credential", "billing", "scope", "identity", "execution_unknown")):
        action = "human_gate"
        reasons.append("hard_stop_requires_parent_or_operator")
    elif data["continuity"]["budget_pressure"] or signals["budget_pressure"] == TRUE:
        action = "human_gate"
        reasons.append("budget_pressure_requires_parent_or_operator")
    elif stops["external_exhaustion"]:
        action = "human_gate"
        reasons.append("useful_authorized_work_exhausted")
    elif data["certificate_status"] != "active" or stops["no_qualified_route"] or signals["provider_unavailable"] == TRUE:
        action = "unavailable"
        reasons.append("route_not_currently_eligible")
    elif data["continuity"]["context_pressure"]:
        action = "clean_handoff"
        reasons.append("context_pressure")
    elif stops["validation_failed"] or stops["quality_rejected"] or signals["quality_rejected"] == TRUE or any(signals[field] == TRUE for field in ("repeat_action", "repeat_error_class", "ping_pong", "rewrite_retest", "no_progress")):
        action = "switch"
        reasons.append("bounded_failure_or_repetition")
    elif data["candidate_ready"]:
        action = "human_gate"
        reasons.append("candidate_ready_for_parent_review")
    else:
        action = "continue"
        reasons.append("within_authority_and_controls")
    base = {
        "artifact_type": "route_fabric_decision_v1",
        "assignment_id": data["assignment_id"],
        "source_bindings": data["source_bindings"],
        "current_route_identity": data["current_route_identity"],
        "current_certificate_sha256": data["current_certificate_sha256"],
        "target_route_identity": None,
        "trajectory_sha256": data["trajectory_sha256"],
        "action": action,
        "reason_codes": reasons,
        "authorization_required": action == "human_gate",
        "retry_started": False,
        "fallback_started": False,
        "dispatch_started": False,
        "board_mutated": False,
        "accepted": False,
    }
    return {**base, "decision_sha256": canonical_digest(base)}


def _ledger_head(value: Any, field: str) -> str:
    value = _string(value, field)
    if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", value):
        raise FabricError("ledger_head_invalid", field)
    return value


def validate_route_fabric_decision(value: Any) -> dict[str, Any]:
    """Validate one immutable advisory decision without granting authority."""
    decision = _object(value, "route_fabric_decision", ADVISORY_DECISION_FIELDS)
    if decision["artifact_type"] != "route_fabric_decision_v1":
        raise FabricError("artifact_type_invalid", "route_fabric_decision.artifact_type")
    _string(decision["assignment_id"], "route_fabric_decision.assignment_id")
    _unique_strings(decision["source_bindings"], "route_fabric_decision.source_bindings")
    decision["current_route_identity"] = _route_identity(
        decision["current_route_identity"], "route_fabric_decision.current_route_identity"
    )
    _sha(decision["current_certificate_sha256"], "route_fabric_decision.current_certificate_sha256")
    if decision["target_route_identity"] is not None:
        raise FabricError("target_selection_forbidden", "route_fabric_decision.target_route_identity")
    _sha(decision["trajectory_sha256"], "route_fabric_decision.trajectory_sha256")
    if decision["action"] not in ACTIONS:
        raise FabricError("advisory_action_invalid", "route_fabric_decision.action")
    _unique_strings(decision["reason_codes"], "route_fabric_decision.reason_codes")
    _bool(decision["authorization_required"], "route_fabric_decision.authorization_required")
    if decision["authorization_required"] != (decision["action"] == "human_gate"):
        raise FabricError("advisory_authority_flag", "authorization_required")
    for field in ("retry_started", "fallback_started", "dispatch_started", "board_mutated", "accepted"):
        if _bool(decision[field], f"route_fabric_decision.{field}"):
            raise FabricError("advisory_authority_flag", field)
    if decision["action"] == "switch" and any(
        code in decision["reason_codes"]
        for code in {"hard_stop_requires_parent_or_operator", "budget_pressure_requires_parent_or_operator", "useful_authorized_work_exhausted"}
    ):
        raise FabricError("advisory_action_invalid", "hard stop cannot reroute")
    base = {key: decision[key] for key in ADVISORY_DECISION_FIELDS if key != "decision_sha256"}
    if _sha(decision["decision_sha256"], "route_fabric_decision.decision_sha256") != canonical_digest(base):
        raise FabricError("decision_digest_mismatch", "route_fabric_decision")
    return decision


def validate_scheduler_advisory(
    value: Any, *, assignment_id: str | None = None,
    envelope_sha256: str | None = None, ledger_head_before: str | None = None,
) -> dict[str, Any]:
    """Validate the scheduler-facing advisory and its live bindings."""
    advisory = _object(value, "route_fabric_scheduler_advisory", ADVISORY_WRAPPER_FIELDS)
    if advisory["schema_version"] != SCHEMA_VERSION:
        raise FabricError("schema_version_invalid", "route_fabric_scheduler_advisory.schema_version")
    if advisory["artifact_type"] != "RouteFabricSchedulerAdvisory":
        raise FabricError("artifact_type_invalid", "route_fabric_scheduler_advisory.artifact_type")
    decision = validate_route_fabric_decision(advisory["decision"])
    bindings = _object(advisory["bindings"], "route_fabric_scheduler_advisory.bindings", ADVISORY_BINDING_FIELDS)
    _string(bindings["assignment_id"], "route_fabric_scheduler_advisory.bindings.assignment_id")
    _sha(bindings["envelope_sha256"], "route_fabric_scheduler_advisory.bindings.envelope_sha256")
    _ledger_head(bindings["ledger_head_before"], "route_fabric_scheduler_advisory.bindings.ledger_head_before")
    _sha(bindings["decision_sha256"], "route_fabric_scheduler_advisory.bindings.decision_sha256")
    if bindings["assignment_id"] != decision["assignment_id"]:
        raise FabricError("advisory_assignment_mismatch", "decision and bindings")
    if bindings["decision_sha256"] != decision["decision_sha256"]:
        raise FabricError("advisory_decision_digest_mismatch", "bindings")
    if assignment_id is not None and bindings["assignment_id"] != assignment_id:
        raise FabricError("advisory_assignment_mismatch", "envelope")
    if envelope_sha256 is not None and bindings["envelope_sha256"] != envelope_sha256:
        raise FabricError("advisory_envelope_binding_mismatch", "envelope")
    if ledger_head_before is not None and bindings["ledger_head_before"] != ledger_head_before:
        raise FabricError("advisory_ledger_binding_mismatch", "ledger")
    base = {key: advisory[key] for key in ADVISORY_WRAPPER_FIELDS if key != "advisory_sha256"}
    if _sha(advisory["advisory_sha256"], "route_fabric_scheduler_advisory.advisory_sha256") != canonical_digest(base):
        raise FabricError("advisory_digest_mismatch", "route_fabric_scheduler_advisory")
    return {**advisory, "decision": decision, "bindings": bindings}


def _contains_forbidden_key(value: Any, path: str = "root") -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in FORBIDDEN_HANDOFF_KEYS:
                return f"{path}.{key}"
            found = _contains_forbidden_key(child, f"{path}.{key}")
            if found:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = _contains_forbidden_key(child, f"{path}[{index}]")
            if found:
                return found
    return None


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FabricError("duplicate_json_key", key)
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise FabricError("nonfinite_json_number", value)


def build_clean_handoff(value: Mapping[str, Any]) -> dict[str, Any]:
    handoff = _object(value, "clean_handoff", {
        "artifact_type", "assignment_id", "source_bindings", "accepted_artifact_descriptors",
        "attempted_strategies", "target_route_identity", "named_failures", "next_proof",
        "excluded_context",
    })
    if handoff["artifact_type"] != "clean_handoff_v1":
        raise FabricError("artifact_type_invalid", "clean_handoff.artifact_type")
    _string(handoff["assignment_id"], "clean_handoff.assignment_id")
    if not isinstance(handoff["source_bindings"], list):
        raise FabricError("array_required", "clean_handoff.source_bindings")
    source_bindings = [_handoff_descriptor(item, f"clean_handoff.source_bindings[{index}]") for index, item in enumerate(handoff["source_bindings"])]
    if not isinstance(handoff["accepted_artifact_descriptors"], list):
        raise FabricError("array_required", "clean_handoff.accepted_artifact_descriptors")
    descriptors = [_handoff_descriptor(item, f"clean_handoff.accepted_artifact_descriptors[{index}]") for index, item in enumerate(handoff["accepted_artifact_descriptors"])]
    if not isinstance(handoff["attempted_strategies"], list):
        raise FabricError("array_required", "clean_handoff.attempted_strategies")
    attempted = [_handoff_descriptor(item, f"clean_handoff.attempted_strategies[{index}]") for index, item in enumerate(handoff["attempted_strategies"])]
    if handoff["target_route_identity"] is not None:
        _route_identity(handoff["target_route_identity"], "clean_handoff.target_route_identity")
    if not isinstance(handoff["named_failures"], list) or not isinstance(handoff["next_proof"], list):
        raise FabricError("array_required", "clean_handoff bounded lists")
    failures = [_handoff_descriptor(item, f"clean_handoff.named_failures[{index}]") for index, item in enumerate(handoff["named_failures"])]
    next_proof = [_handoff_descriptor(item, f"clean_handoff.next_proof[{index}]") for index, item in enumerate(handoff["next_proof"])]
    _unique_strings(handoff["excluded_context"], "clean_handoff.excluded_context")
    if _contains_forbidden_key({
        "source_bindings": source_bindings,
        "accepted_artifact_descriptors": descriptors,
        "attempted_strategies": attempted,
        "named_failures": failures,
        "next_proof": next_proof,
    }):
        raise FabricError("handoff_sensitive_field", "bounded handoff payload")
    if any(item not in {"credentials", "raw_prompt", "raw_source", "raw_tool_output", "raw_transcript", "provider_reasoning", "stale_narration"} for item in handoff["excluded_context"]):
        raise FabricError("excluded_context_invalid", "clean_handoff.excluded_context")
    base = {
        **handoff,
        "source_bindings": source_bindings,
        "accepted_artifact_descriptors": descriptors,
        "attempted_strategies": attempted,
        "named_failures": failures,
        "next_proof": next_proof,
    }
    return {**base, "handoff_sha256": canonical_digest(base)}


def _run_operation(operation: str, payload: dict[str, Any]) -> Any:
    if operation == "validate_capability_card":
        return validate_capability_card(payload)
    if operation == "effective_certificate_status":
        request = copy.deepcopy(payload)
        if "certificate" in request:
            certificate = request["certificate"]
            now = request["now"]
            expected = {key: request[key] for key in request if key not in {"certificate", "now"}}
        else:
            now = request["now"]
            certificate = {key: request[key] for key in request if key != "now"}
            expected = {}
        return effective_certificate_status(certificate, now=now, **expected)
    if operation == "validate_recall_chain":
        return validate_recall_chain(payload["events"], initial_previous=payload["initial_previous"])
    if operation == "derive_trajectory_signals":
        return derive_trajectory_signals(payload)
    if operation == "build_recall_event":
        return build_recall_event(
            payload["subject_scope"], payload["subject_id"], payload["subject_sha256"], payload["reason_code"],
            payload["created_at"], payload["authority_sha256"], payload["previous_event_sha256"],
        )
    if operation == "build_clean_handoff":
        return build_clean_handoff(payload)
    if operation == "calculate_correction_economics":
        return calculate_correction_economics(payload["rows"], task_family=payload["task_family"], route_identity=payload["route_identity"])
    if operation == "choose_advisory_action":
        return choose_advisory_action(payload)
    if operation == "validate_route_fabric_decision":
        return validate_route_fabric_decision(payload)
    if operation == "validate_scheduler_advisory":
        return validate_scheduler_advisory(payload)
    raise FabricError("operation_invalid", operation)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        raw = json.loads(
            args.input.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
        request = _object(raw, "request", {"schema_version", "operation", "payload"})
        if request["schema_version"] != SCHEMA_VERSION:
            raise FabricError("schema_version_invalid", "request.schema_version")
        operation = _string(request["operation"], "request.operation")
        payload = _dict(request["payload"], "request.payload")
        result = _run_operation(operation, payload)
        print(json.dumps({"ok": True, "operation": operation, "result": result}, sort_keys=True))
        return 0
    except (OSError, json.JSONDecodeError, FabricError, KeyError, TypeError) as exc:
        error = {"code": exc.code, "detail": exc.detail} if isinstance(exc, FabricError) else {"code": "input_invalid", "detail": str(exc)}
        print(json.dumps({"ok": False, "error": error}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
