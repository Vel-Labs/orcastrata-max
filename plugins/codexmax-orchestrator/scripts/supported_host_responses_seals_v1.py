#!/usr/bin/env python3
"""Pure structural ledger for Responses, bridge, record, and projection decisions."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Mapping


OPERATIONS = (
    "issue_responses_context",
    "verify_responses_bridge",
    "commit_or_verify_record",
    "seal_or_verify_projection",
)
OPERATION_SET = frozenset(OPERATIONS)
DECISIONS = {
    "issue_responses_context": "context_structure_valid",
    "verify_responses_bridge": "bridge_structure_valid",
    "commit_or_verify_record": "record_structure_valid",
    "seal_or_verify_projection": "projection_structure_valid",
}
SOURCE_IDS = {
    "issue_responses_context": "responses-context-issuer",
    "verify_responses_bridge": "responses-bridge-observation-store",
    "commit_or_verify_record": "record-lineage-authority",
    "seal_or_verify_projection": "projection-seal-authority",
}
LEDGER_TYPE = "supported_host_responses_seals_ledger_v1"
EVENT_TYPE = "supported_host_responses_seals_event_v1"
DECISION_TYPE = "supported_host_responses_seals_structural_decision_v1"
UNAVAILABLE_TYPE = "supported_host_responses_seals_source_result_v1"
LEDGER_FIELDS = frozenset({
    "schema_version", "artifact_type", "ledger_id", "events", "head_sha256", "state_sha256",
})
EVENT_FIELDS = frozenset({
    "schema_version", "artifact_type", "ledger_id", "sequence", "previous_event_sha256",
    "expected_head_sha256", "event_type", "occurred_at", "operation", "decision_id",
    "decision_sha256", "decision", "reason", "event_sha256",
})
DECISION_FIELDS = frozenset({
    "schema_version", "artifact_type", "decision_id", "decision_source_id", "decision",
    "ledger_id", "operation", "bindings", "observed_at", "expires_at", "decision_sha256",
})
BINDING_FIELDS = frozenset({
    "identity_sha256", "request_sha256", "dependency_receipts_sha256", "selection_sha256",
    "supervision_sha256", "runtime_sha256", "action_sha256", "route_sha256", "output_sha256",
    "record_sha256", "projection_sha256",
})
REVOKE_REASONS = frozenset({"binding_invalidated", "request_withdrawn", "operator_revoked"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_FORBIDDEN_KEYS = frozenset({
    "private_key", "private_key_path", "credential", "credentials", "endpoint", "path",
    "environment", "env", "live", "live_status", "provider_result", "fixture", "test_projector",
})


class ResponsesSealsError(ValueError):
    """Stable non-echoing rejection for the structural mechanism."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def canonical_digest(value: Any) -> str:
    """Return the canonical JSON SHA-256 digest for one JSON-like value."""

    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise ResponsesSealsError("canonical_value_invalid", "$") from exc
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise ResponsesSealsError(code, path)
    return deepcopy(dict(value))


def _exact_version(value: Any, code: str, path: str) -> int:
    if type(value) is not int or value != 1:
        raise ResponsesSealsError(code, path)
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ResponsesSealsError("identifier_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ResponsesSealsError("digest_invalid", path)
    return value


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ResponsesSealsError("timestamp_invalid", path)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ResponsesSealsError("timestamp_invalid", path) from exc
    if parsed.utcoffset() != timedelta(0) or parsed.microsecond != 0:
        raise ResponsesSealsError("timestamp_invalid", path)
    return parsed


def _utc(value: Any, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ResponsesSealsError("utc_clock_invalid", path)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _format(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _reject_forbidden(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or key.lower() in _FORBIDDEN_KEYS:
                raise ResponsesSealsError("sensitive_field_forbidden", path + "." + str(key))
            _reject_forbidden(item, path + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_forbidden(item, f"{path}[{index}]")


def validate_bindings(value: Any, path: str = "$.bindings") -> dict[str, str]:
    row = _closed(value, BINDING_FIELDS, "bindings_shape_invalid", path)
    _reject_forbidden(row, path)
    for field in BINDING_FIELDS:
        _sha(row[field], path + "." + field)
    return row


def _genesis_head(ledger_id: str) -> str:
    return canonical_digest({"schema_version": 1, "artifact_type": "supported_host_responses_seals_genesis_v1", "ledger_id": ledger_id})


def _seal_state(state: Mapping[str, Any]) -> str:
    return canonical_digest({key: item for key, item in state.items() if key != "state_sha256"})


def new_ledger(ledger_id: str) -> dict[str, Any]:
    _identifier(ledger_id, "$.ledger_id")
    state = {
        "schema_version": 1, "artifact_type": LEDGER_TYPE, "ledger_id": ledger_id,
        "events": [], "head_sha256": _genesis_head(ledger_id), "state_sha256": "",
    }
    state["state_sha256"] = _seal_state(state)
    return state


def validate_structural_decision(
    value: Any,
    *,
    expected_ledger_id: str,
    expected_operation: str,
    expected_bindings: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Validate a closed structural decision without establishing authority."""

    row = _closed(value, DECISION_FIELDS, "decision_shape_invalid", "$.decision")
    _reject_forbidden(row, "$.decision")
    _exact_version(row["schema_version"], "decision_version_invalid", "$.decision.schema_version")
    if row["artifact_type"] != DECISION_TYPE:
        raise ResponsesSealsError("decision_version_invalid", "$.decision.artifact_type")
    _identifier(row["decision_id"], "$.decision.decision_id")
    if expected_operation not in OPERATION_SET or row["operation"] != expected_operation:
        raise ResponsesSealsError("decision_operation_mismatch", "$.decision.operation")
    if row["decision_source_id"] != SOURCE_IDS[expected_operation] or row["decision"] != DECISIONS[expected_operation]:
        raise ResponsesSealsError("decision_source_invalid", "$.decision.decision_source_id")
    if row["ledger_id"] != expected_ledger_id:
        raise ResponsesSealsError("decision_ledger_mismatch", "$.decision.ledger_id")
    bindings = validate_bindings(row["bindings"])
    expected = validate_bindings(expected_bindings, "$.expected_bindings")
    for field in BINDING_FIELDS:
        if bindings[field] != expected[field]:
            raise ResponsesSealsError("decision_binding_mismatch", "$.decision.bindings." + field)
    current = _utc(now, "$.now")
    observed = _time(row["observed_at"], "$.decision.observed_at")
    expires = _time(row["expires_at"], "$.decision.expires_at")
    if observed > current or expires <= current or expires <= observed or expires - observed > timedelta(minutes=5):
        raise ResponsesSealsError("decision_freshness_invalid", "$.decision.expires_at")
    if row["decision_sha256"] != canonical_digest({key: item for key, item in row.items() if key != "decision_sha256"}):
        raise ResponsesSealsError("decision_digest_mismatch", "$.decision.decision_sha256")
    return row


def validate_ledger(value: Any) -> dict[str, Any]:
    state = _closed(value, LEDGER_FIELDS, "ledger_shape_invalid", "$.ledger")
    _reject_forbidden(state, "$.ledger")
    _exact_version(state["schema_version"], "ledger_version_invalid", "$.ledger.schema_version")
    if state["artifact_type"] != LEDGER_TYPE:
        raise ResponsesSealsError("ledger_version_invalid", "$.ledger.artifact_type")
    ledger_id = _identifier(state["ledger_id"], "$.ledger.ledger_id")
    if not isinstance(state["events"], list):
        raise ResponsesSealsError("ledger_events_invalid", "$.ledger.events")
    previous = _genesis_head(ledger_id)
    decisions: dict[str, str] = {}
    digests: set[str] = set()
    revoked: set[str] = set()
    last_time: datetime | None = None
    for index, raw in enumerate(state["events"]):
        path = f"$.ledger.events[{index}]"
        event = _closed(raw, EVENT_FIELDS, "ledger_event_shape_invalid", path)
        _exact_version(event["schema_version"], "ledger_event_version_invalid", path + ".schema_version")
        if event["artifact_type"] != EVENT_TYPE or event["ledger_id"] != ledger_id:
            raise ResponsesSealsError("ledger_event_binding_mismatch", path)
        if type(event["sequence"]) is not int or event["sequence"] != index + 1:
            raise ResponsesSealsError("ledger_sequence_invalid", path + ".sequence")
        if event["previous_event_sha256"] != previous or event["expected_head_sha256"] != previous:
            raise ResponsesSealsError("ledger_chain_broken", path + ".previous_event_sha256")
        occurred = _time(event["occurred_at"], path + ".occurred_at")
        if last_time is not None and occurred < last_time:
            raise ResponsesSealsError("ledger_time_regression", path + ".occurred_at")
        last_time = occurred
        operation = event["operation"]
        if operation not in OPERATION_SET:
            raise ResponsesSealsError("decision_operation_mismatch", path + ".operation")
        decision_id = _identifier(event["decision_id"], path + ".decision_id")
        decision_sha = _sha(event["decision_sha256"], path + ".decision_sha256")
        if event["event_type"] == "issue":
            decision = _closed(event["decision"], DECISION_FIELDS, "decision_shape_invalid", path + ".decision")
            _exact_version(decision["schema_version"], "decision_version_invalid", path + ".decision.schema_version")
            if decision["artifact_type"] != DECISION_TYPE:
                raise ResponsesSealsError("decision_version_invalid", path + ".decision.artifact_type")
            if decision["decision_id"] != decision_id or decision["decision_sha256"] != decision_sha or decision["operation"] != operation or decision["ledger_id"] != ledger_id:
                raise ResponsesSealsError("ledger_decision_binding_mismatch", path + ".decision")
            if decision_sha != canonical_digest({key: item for key, item in decision.items() if key != "decision_sha256"}):
                raise ResponsesSealsError("decision_digest_mismatch", path + ".decision.decision_sha256")
            validate_bindings(decision["bindings"], path + ".decision.bindings")
            if decision["decision_source_id"] != SOURCE_IDS[operation] or decision["decision"] != DECISIONS[operation]:
                raise ResponsesSealsError("decision_source_invalid", path + ".decision")
            observed = _time(decision["observed_at"], path + ".decision.observed_at")
            expires = _time(decision["expires_at"], path + ".decision.expires_at")
            if expires <= observed or expires - observed > timedelta(minutes=5):
                raise ResponsesSealsError("decision_freshness_invalid", path + ".decision.expires_at")
            if event["occurred_at"] != decision["observed_at"] or event["reason"] is not None:
                raise ResponsesSealsError("ledger_decision_binding_mismatch", path)
            if decision_id in decisions:
                code = "ledger_issue_duplicate" if decisions[decision_id] == decision_sha else "ledger_decision_collision"
                raise ResponsesSealsError(code, path + ".decision_id")
            if decision_sha in digests:
                raise ResponsesSealsError("ledger_issue_replay", path + ".decision_sha256")
            decisions[decision_id] = decision_sha
            digests.add(decision_sha)
        elif event["event_type"] == "revoke":
            if event["decision"] is not None or event["reason"] not in REVOKE_REASONS:
                raise ResponsesSealsError("ledger_revoke_invalid", path)
            if decisions.get(decision_id) != decision_sha:
                raise ResponsesSealsError("ledger_revoke_target_missing", path + ".decision_sha256")
            if decision_sha in revoked:
                raise ResponsesSealsError("ledger_revoke_duplicate", path + ".decision_sha256")
            revoked.add(decision_sha)
        else:
            raise ResponsesSealsError("ledger_event_type_invalid", path + ".event_type")
        expected_event = canonical_digest({key: item for key, item in event.items() if key != "event_sha256"})
        if event["event_sha256"] != expected_event:
            raise ResponsesSealsError("ledger_event_digest_mismatch", path + ".event_sha256")
        previous = expected_event
    if state["head_sha256"] != previous:
        raise ResponsesSealsError("ledger_head_mismatch", "$.ledger.head_sha256")
    if state["state_sha256"] != _seal_state(state):
        raise ResponsesSealsError("ledger_state_digest_mismatch", "$.ledger.state_sha256")
    return state


def _append(state: Mapping[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    candidate = deepcopy(dict(state))
    event["event_sha256"] = canonical_digest({key: item for key, item in event.items() if key != "event_sha256"})
    candidate["events"].append(event)
    candidate["head_sha256"] = event["event_sha256"]
    candidate["state_sha256"] = _seal_state(candidate)
    return validate_ledger(candidate)


def issue_decision(state: Any, decision: Any, *, expected_head_sha256: str) -> dict[str, Any]:
    ledger = validate_ledger(state)
    _sha(expected_head_sha256, "$.expected_head_sha256")
    if ledger["head_sha256"] != expected_head_sha256:
        raise ResponsesSealsError("ledger_stale_head", "$.expected_head_sha256")
    row = _closed(decision, DECISION_FIELDS, "decision_shape_invalid", "$.decision")
    if row["ledger_id"] != ledger["ledger_id"] or row["decision_sha256"] != canonical_digest({key: item for key, item in row.items() if key != "decision_sha256"}):
        raise ResponsesSealsError("decision_digest_mismatch", "$.decision.decision_sha256")
    validate_bindings(row["bindings"])
    event = {
        "schema_version": 1, "artifact_type": EVENT_TYPE, "ledger_id": ledger["ledger_id"],
        "sequence": len(ledger["events"]) + 1, "previous_event_sha256": ledger["head_sha256"],
        "expected_head_sha256": expected_head_sha256, "event_type": "issue",
        "occurred_at": row["observed_at"], "operation": row["operation"],
        "decision_id": row["decision_id"], "decision_sha256": row["decision_sha256"],
        "decision": row, "reason": None, "event_sha256": "",
    }
    return _append(ledger, event)


def revoke_decision(
    state: Any, *, decision_sha256: str, reason: str, expected_head_sha256: str, occurred_at: datetime,
) -> dict[str, Any]:
    ledger = validate_ledger(state)
    _sha(decision_sha256, "$.decision_sha256")
    _sha(expected_head_sha256, "$.expected_head_sha256")
    if ledger["head_sha256"] != expected_head_sha256:
        raise ResponsesSealsError("ledger_stale_head", "$.expected_head_sha256")
    if reason not in REVOKE_REASONS:
        raise ResponsesSealsError("ledger_revoke_invalid", "$.reason")
    issue = next((item for item in ledger["events"] if item["event_type"] == "issue" and item["decision_sha256"] == decision_sha256), None)
    if issue is None:
        raise ResponsesSealsError("ledger_revoke_target_missing", "$.decision_sha256")
    event = {
        "schema_version": 1, "artifact_type": EVENT_TYPE, "ledger_id": ledger["ledger_id"],
        "sequence": len(ledger["events"]) + 1, "previous_event_sha256": ledger["head_sha256"],
        "expected_head_sha256": expected_head_sha256, "event_type": "revoke",
        "occurred_at": _format(_utc(occurred_at, "$.occurred_at")), "operation": issue["operation"],
        "decision_id": issue["decision_id"], "decision_sha256": decision_sha256,
        "decision": None, "reason": reason, "event_sha256": "",
    }
    return _append(ledger, event)


def recover_ledger(value: Any, *, trusted_sequence: int, trusted_head_sha256: str) -> dict[str, Any]:
    if type(trusted_sequence) is not int or trusted_sequence < 0:
        raise ResponsesSealsError("ledger_anchor_sequence_invalid", "$.trusted_sequence")
    _sha(trusted_head_sha256, "$.trusted_head_sha256")
    ledger = validate_ledger(value)
    if len(ledger["events"]) < trusted_sequence:
        raise ResponsesSealsError("ledger_rollback_detected", "$.ledger.events")
    if len(ledger["events"]) != trusted_sequence or ledger["head_sha256"] != trusted_head_sha256:
        raise ResponsesSealsError("ledger_anchor_head_mismatch", "$.ledger.head_sha256")
    return ledger


def current_structural_decision(
    value: Any, *, operation: str, expected_bindings: Mapping[str, Any], now: datetime,
    trusted_sequence: int, trusted_head_sha256: str,
) -> dict[str, Any]:
    ledger = recover_ledger(value, trusted_sequence=trusted_sequence, trusted_head_sha256=trusted_head_sha256)
    if operation not in OPERATION_SET:
        raise ResponsesSealsError("decision_operation_mismatch", "$.operation")
    current = _utc(now, "$.now")
    revoked = {item["decision_sha256"] for item in ledger["events"] if item["event_type"] == "revoke"}
    for event in reversed(ledger["events"]):
        if event["event_type"] == "issue" and event["operation"] == operation:
            if event["decision_sha256"] in revoked:
                raise ResponsesSealsError("decision_revoked", "$.decision")
            return validate_structural_decision(
                event["decision"], expected_ledger_id=ledger["ledger_id"], expected_operation=operation,
                expected_bindings=expected_bindings, now=current,
            )
    raise ResponsesSealsError("decision_unavailable", "$.decision")


class _UnavailableSource:
    __slots__ = ("_operation",)

    def __init__(self, operation: str) -> None:
        self._operation = operation

    def read_fact(self, operation: str, exact_identity: Any, dependency_receipts: Mapping[str, str], now: datetime) -> dict[str, Any]:
        del exact_identity, dependency_receipts, now
        if operation != self._operation:
            raise ResponsesSealsError("canonical_operation_invalid", "$.operation")
        return {
            "schema_version": 1, "artifact_type": UNAVAILABLE_TYPE, "operation": operation,
            "state": "unavailable", "reason": "canonical_positive_source_not_implemented",
            "canonical_source_id": SOURCE_IDS[operation],
        }


class ResponsesContextSource(_UnavailableSource):
    def __init__(self) -> None:
        super().__init__("issue_responses_context")


class ResponsesBridgeSource(_UnavailableSource):
    def __init__(self) -> None:
        super().__init__("verify_responses_bridge")


class RecordAuthoritySource(_UnavailableSource):
    def __init__(self) -> None:
        super().__init__("commit_or_verify_record")


class ProjectionAuthoritySource(_UnavailableSource):
    def __init__(self) -> None:
        super().__init__("seal_or_verify_projection")
