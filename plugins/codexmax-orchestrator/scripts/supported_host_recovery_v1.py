#!/usr/bin/env python3
"""Pure structural recovery reservation and lease-candidate ledger."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Mapping

from package_host_supported_host_fact_sources_v1 import UnavailableFact


OPERATION = "read_operator_recovery_lease_grant"
SOURCE_ID = "recovery-lease-authority"
LEDGER_TYPE = "supported_host_recovery_ledger_v1"
EVENT_TYPE = "supported_host_recovery_event_v1"
DECISION_TYPE = "supported_host_recovery_structural_decision_v1"
VARIANTS = frozenset({"recovery_reservation_candidate", "recovery_lease_grant_candidate"})
LEDGER_FIELDS = frozenset({"schema_version", "artifact_type", "ledger_id", "events", "head_sha256", "state_sha256"})
EVENT_FIELDS = frozenset({
    "schema_version", "artifact_type", "ledger_id", "sequence", "previous_event_sha256",
    "expected_head_sha256", "event_type", "occurred_at", "decision_id", "decision_sha256",
    "decision", "reason", "event_sha256",
})
DECISION_FIELDS = frozenset({
    "schema_version", "artifact_type", "decision_id", "decision_source_id", "ledger_id", "operation",
    "variant", "bindings", "payload", "observed_at", "expires_at", "decision_sha256",
})
BINDING_FIELDS = frozenset({
    "workspace_id", "source_sha256", "candidate_sha256", "manifest_sha256", "generation",
    "service_start_id", "dependency_receipts_sha256",
})
RESERVATION_FIELDS = frozenset({
    "reservation_id", "effect_id", "run_id", "thread_id", "lease_id",
    "predecessor_effect_state_sha256", "predecessor_effect_receipt_sha256",
    "reconciliation_decision_sha256", "fencing_token", "fencing_version",
    "t064_identity_sha256", "t066_identity_sha256",
})
GRANT_FIELDS = frozenset({
    "grant_id", "reservation_sha256", "effect_id", "run_id", "thread_id", "lease_id",
    "predecessor_effect_state_sha256", "predecessor_effect_receipt_sha256",
    "reconciliation_decision_sha256", "predecessor_fencing_token", "predecessor_fencing_version",
    "fencing_token", "fencing_version", "t064_identity_sha256", "t066_identity_sha256",
})
REVOKE_REASONS = frozenset({"reservation_cancelled", "reconciliation_invalidated", "operator_revoked"})
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_INELIGIBLE = ("fixture", "synthetic", "test", "caller", "unverified", "missing", "unknown", "default")
_FORBIDDEN_KEYS = frozenset({
    "private_key", "private_key_path", "credential", "environment", "env", "path", "endpoint",
    "provider", "live", "live_status", "fixture", "synthetic", "caller_selected", "available",
})


class RecoveryError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def canonical_digest(value: Any) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise RecoveryError("canonical_value_invalid", "$") from exc
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise RecoveryError(code, path)
    return deepcopy(dict(value))


def _id(value: Any, path: str, *, eligible: bool = False) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise RecoveryError("identifier_invalid", path)
    if eligible and any(token in value.lower() for token in _INELIGIBLE):
        raise RecoveryError("recovery_identity_ineligible", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise RecoveryError("digest_invalid", path)
    return value


def _positive(value: Any, path: str) -> int:
    if type(value) is not int or value < 1:
        raise RecoveryError("fencing_value_invalid", path)
    return value


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RecoveryError("timestamp_invalid", path)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RecoveryError("timestamp_invalid", path) from exc
    if parsed.utcoffset() != timedelta(0) or parsed.microsecond != 0:
        raise RecoveryError("timestamp_invalid", path)
    return parsed


def _utc(value: Any, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise RecoveryError("utc_clock_invalid", path)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _format(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _reject_forbidden(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or key.lower() in _FORBIDDEN_KEYS:
                raise RecoveryError("recovery_field_forbidden", path + "." + str(key))
            _reject_forbidden(item, path + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_forbidden(item, f"{path}[{index}]")


def _bindings(value: Any, path: str = "$.decision.bindings") -> dict[str, Any]:
    row = _closed(value, BINDING_FIELDS, "recovery_bindings_invalid", path)
    _id(row["workspace_id"], path + ".workspace_id", eligible=True)
    _id(row["service_start_id"], path + ".service_start_id", eligible=True)
    for field in ("source_sha256", "candidate_sha256", "manifest_sha256", "dependency_receipts_sha256"):
        _sha(row[field], path + "." + field)
    if type(row["generation"]) is not int or row["generation"] < 1:
        raise RecoveryError("recovery_generation_invalid", path + ".generation")
    return row


def _common_payload(row: Mapping[str, Any], path: str) -> None:
    for field in ("effect_id", "run_id", "thread_id", "lease_id"):
        _id(row[field], path + "." + field, eligible=True)
    for field in (
        "predecessor_effect_state_sha256", "predecessor_effect_receipt_sha256",
        "reconciliation_decision_sha256", "t064_identity_sha256", "t066_identity_sha256",
    ):
        _sha(row[field], path + "." + field)


def _payload(variant: Any, value: Any, path: str = "$.decision.payload") -> dict[str, Any]:
    if not isinstance(variant, str) or variant not in VARIANTS:
        raise RecoveryError("recovery_variant_invalid", "$.decision.variant")
    if variant == "recovery_reservation_candidate":
        row = _closed(value, RESERVATION_FIELDS, "recovery_reservation_invalid", path)
        _id(row["reservation_id"], path + ".reservation_id", eligible=True)
        _common_payload(row, path)
        _positive(row["fencing_token"], path + ".fencing_token")
        _positive(row["fencing_version"], path + ".fencing_version")
        return row
    row = _closed(value, GRANT_FIELDS, "recovery_grant_candidate_invalid", path)
    _id(row["grant_id"], path + ".grant_id", eligible=True)
    _sha(row["reservation_sha256"], path + ".reservation_sha256")
    _common_payload(row, path)
    prior_token = _positive(row["predecessor_fencing_token"], path + ".predecessor_fencing_token")
    prior_version = _positive(row["predecessor_fencing_version"], path + ".predecessor_fencing_version")
    token = _positive(row["fencing_token"], path + ".fencing_token")
    version = _positive(row["fencing_version"], path + ".fencing_version")
    if token != prior_token + 1 or version != prior_version + 1:
        raise RecoveryError("recovery_fence_mismatch", path + ".fencing_token")
    return row


def validate_decision(value: Any, *, expected_ledger_id: str, expected_bindings: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    _reject_forbidden(value, "$.decision")
    row = _closed(value, DECISION_FIELDS, "recovery_decision_invalid", "$.decision")
    if type(row["schema_version"]) is not int or row["schema_version"] != 1 or row["artifact_type"] != DECISION_TYPE:
        raise RecoveryError("recovery_decision_version_invalid", "$.decision")
    _id(row["decision_id"], "$.decision.decision_id", eligible=True)
    if row["decision_source_id"] != SOURCE_ID or row["operation"] != OPERATION:
        raise RecoveryError("recovery_decision_source_invalid", "$.decision")
    if row["ledger_id"] != expected_ledger_id:
        raise RecoveryError("recovery_ledger_mismatch", "$.decision.ledger_id")
    bindings = _bindings(row["bindings"])
    expected = _bindings(expected_bindings, "$.expected_bindings")
    for field in BINDING_FIELDS:
        if bindings[field] != expected[field]:
            raise RecoveryError("recovery_binding_mismatch", "$.decision.bindings." + field)
    _payload(row["variant"], row["payload"])
    current = _utc(now, "$.now")
    observed = _time(row["observed_at"], "$.decision.observed_at")
    expires = _time(row["expires_at"], "$.decision.expires_at")
    if observed > current or expires <= current or expires <= observed or expires - observed > timedelta(minutes=5):
        raise RecoveryError("recovery_decision_stale", "$.decision.expires_at")
    if row["decision_sha256"] != canonical_digest({key: item for key, item in row.items() if key != "decision_sha256"}):
        raise RecoveryError("recovery_decision_digest_mismatch", "$.decision.decision_sha256")
    return row


def _genesis(ledger_id: str) -> str:
    return canonical_digest({"schema_version": 1, "artifact_type": "supported_host_recovery_genesis_v1", "ledger_id": ledger_id})


def _state_sha(state: Mapping[str, Any]) -> str:
    return canonical_digest({key: item for key, item in state.items() if key != "state_sha256"})


def new_ledger(ledger_id: str) -> dict[str, Any]:
    _id(ledger_id, "$.ledger_id", eligible=True)
    row = {"schema_version": 1, "artifact_type": LEDGER_TYPE, "ledger_id": ledger_id, "events": [], "head_sha256": _genesis(ledger_id), "state_sha256": ""}
    row["state_sha256"] = _state_sha(row)
    return row


def validate_ledger(value: Any) -> dict[str, Any]:
    row = _closed(value, LEDGER_FIELDS, "recovery_ledger_invalid", "$.ledger")
    if type(row["schema_version"]) is not int or row["schema_version"] != 1 or row["artifact_type"] != LEDGER_TYPE:
        raise RecoveryError("recovery_ledger_version_invalid", "$.ledger")
    ledger_id = _id(row["ledger_id"], "$.ledger.ledger_id", eligible=True)
    if not isinstance(row["events"], list):
        raise RecoveryError("recovery_events_invalid", "$.ledger.events")
    previous = _genesis(ledger_id)
    ids: dict[str, str] = {}
    digests: set[str] = set()
    revoked: set[str] = set()
    semantic_ids: set[str] = set()
    last_occurred: datetime | None = None
    reservations: dict[str, dict[str, Any]] = {}
    consumed_reservations: set[str] = set()
    reservation_scope_fences: set[tuple[Any, ...]] = set()
    active_reservation_scopes: dict[tuple[Any, ...], tuple[tuple[int, int], str]] = {}
    last_fence_by_scope: dict[tuple[Any, ...], tuple[int, int]] = {}
    for index, raw in enumerate(row["events"]):
        path = f"$.ledger.events[{index}]"
        event = _closed(raw, EVENT_FIELDS, "recovery_event_invalid", path)
        if type(event["schema_version"]) is not int or event["schema_version"] != 1 or event["artifact_type"] != EVENT_TYPE or event["ledger_id"] != ledger_id:
            raise RecoveryError("recovery_event_version_invalid", path)
        if type(event["sequence"]) is not int or event["sequence"] != index + 1:
            raise RecoveryError("recovery_sequence_invalid", path + ".sequence")
        if event["previous_event_sha256"] != previous or event["expected_head_sha256"] != previous:
            raise RecoveryError("recovery_chain_broken", path)
        occurred = _time(event["occurred_at"], path + ".occurred_at")
        if last_occurred is not None and occurred < last_occurred:
            raise RecoveryError("recovery_event_time_regression", path + ".occurred_at")
        last_occurred = occurred
        decision_id = _id(event["decision_id"], path + ".decision_id", eligible=True)
        decision_sha = _sha(event["decision_sha256"], path + ".decision_sha256")
        if event["event_type"] == "issue":
            decision = _closed(event["decision"], DECISION_FIELDS, "recovery_decision_invalid", path + ".decision")
            if event["reason"] is not None:
                raise RecoveryError("recovery_issue_reason_invalid", path + ".reason")
            if type(decision["schema_version"]) is not int or decision["schema_version"] != 1 or decision["artifact_type"] != DECISION_TYPE:
                raise RecoveryError("recovery_decision_version_invalid", path + ".decision")
            if decision["decision_id"] != decision_id or decision["decision_sha256"] != decision_sha or decision["ledger_id"] != ledger_id:
                raise RecoveryError("recovery_event_binding_mismatch", path)
            _bindings(decision["bindings"], path + ".decision.bindings")
            payload = _payload(decision["variant"], decision["payload"], path + ".decision.payload")
            if decision["decision_source_id"] != SOURCE_ID or decision["operation"] != OPERATION:
                raise RecoveryError("recovery_decision_source_invalid", path + ".decision")
            observed = _time(decision["observed_at"], path + ".decision.observed_at")
            expires = _time(decision["expires_at"], path + ".decision.expires_at")
            if event["occurred_at"] != decision["observed_at"]:
                raise RecoveryError("recovery_event_binding_mismatch", path + ".occurred_at")
            if expires <= observed or expires - observed > timedelta(minutes=5):
                raise RecoveryError("recovery_decision_stale", path + ".decision.expires_at")
            if decision_sha != canonical_digest({key: item for key, item in decision.items() if key != "decision_sha256"}):
                raise RecoveryError("recovery_decision_digest_mismatch", path + ".decision.decision_sha256")
            if decision_id in ids:
                raise RecoveryError("recovery_issue_duplicate" if ids[decision_id] == decision_sha else "recovery_decision_collision", path + ".decision_id")
            if decision_sha in digests:
                raise RecoveryError("recovery_issue_replay", path + ".decision_sha256")
            semantic_id = payload["reservation_id"] if decision["variant"] == "recovery_reservation_candidate" else payload["grant_id"]
            if semantic_id in semantic_ids:
                raise RecoveryError("recovery_semantic_id_collision", path + ".decision.payload")
            if decision["variant"] == "recovery_reservation_candidate":
                recovery_scope = (decision["bindings"]["workspace_id"],) + tuple(
                    payload[field] for field in ("effect_id", "run_id", "thread_id", "lease_id")
                )
                fence = (payload["fencing_token"], payload["fencing_version"])
                scope_fence = recovery_scope + fence
                if scope_fence in reservation_scope_fences:
                    raise RecoveryError("recovery_reservation_fence_fork", path + ".decision.payload.fencing_token")
                if recovery_scope in active_reservation_scopes:
                    raise RecoveryError("recovery_reservation_active", path + ".decision.payload.reservation_id")
                prior_fence = last_fence_by_scope.get(recovery_scope)
                if prior_fence is not None and fence != (prior_fence[0] + 1, prior_fence[1] + 1):
                    raise RecoveryError("recovery_reservation_fence_successor_mismatch", path + ".decision.payload.fencing_token")
                reservation_scope_fences.add(scope_fence)
                active_reservation_scopes[recovery_scope] = (fence, decision_sha)
                last_fence_by_scope[recovery_scope] = fence
                reservations[decision_sha] = {
                    "payload": payload,
                    "bindings": decision["bindings"],
                    "expires_at": expires,
                    "revoked": False,
                    "recovery_scope": recovery_scope,
                }
            else:
                reservation_sha = payload["reservation_sha256"]
                reservation_record = reservations.get(reservation_sha)
                if reservation_record is None:
                    raise RecoveryError("recovery_reservation_missing", path + ".decision.payload.reservation_sha256")
                if reservation_record["revoked"]:
                    raise RecoveryError("recovery_reservation_revoked", path + ".decision.payload.reservation_sha256")
                if observed >= reservation_record["expires_at"]:
                    raise RecoveryError("recovery_reservation_expired", path + ".decision.observed_at")
                if reservation_sha in consumed_reservations:
                    raise RecoveryError("recovery_reservation_consumed", path + ".decision.payload.reservation_sha256")
                reserved = reservation_record["payload"]
                for field in BINDING_FIELDS:
                    if decision["bindings"][field] != reservation_record["bindings"][field]:
                        raise RecoveryError("recovery_grant_binding_mismatch", path + ".decision.bindings." + field)
                for field in ("effect_id", "run_id", "thread_id", "lease_id", "predecessor_effect_state_sha256", "predecessor_effect_receipt_sha256", "reconciliation_decision_sha256", "t064_identity_sha256", "t066_identity_sha256"):
                    if payload[field] != reserved[field]:
                        raise RecoveryError("recovery_predecessor_mismatch", path + ".decision.payload." + field)
                if payload["predecessor_fencing_token"] != reserved["fencing_token"] or payload["predecessor_fencing_version"] != reserved["fencing_version"]:
                    raise RecoveryError("recovery_fence_mismatch", path + ".decision.payload")
                consumed_reservations.add(reservation_sha)
                active_reservation_scopes.pop(reservation_record["recovery_scope"], None)
            ids[decision_id] = decision_sha
            digests.add(decision_sha)
            semantic_ids.add(semantic_id)
        elif event["event_type"] == "revoke":
            if event["decision"] is not None or not isinstance(event["reason"], str) or event["reason"] not in REVOKE_REASONS:
                raise RecoveryError("recovery_revoke_invalid", path + ".reason")
            if ids.get(decision_id) != decision_sha:
                raise RecoveryError("recovery_revoke_missing", path + ".decision_sha256")
            if decision_sha in revoked:
                raise RecoveryError("recovery_revoke_duplicate", path + ".decision_sha256")
            revoked.add(decision_sha)
            if decision_sha in reservations:
                reservations[decision_sha]["revoked"] = True
                active_reservation_scopes.pop(reservations[decision_sha]["recovery_scope"], None)
        else:
            raise RecoveryError("recovery_event_type_invalid", path + ".event_type")
        expected_event = canonical_digest({key: item for key, item in event.items() if key != "event_sha256"})
        if event["event_sha256"] != expected_event:
            raise RecoveryError("recovery_event_digest_mismatch", path + ".event_sha256")
        previous = expected_event
    if row["head_sha256"] != previous or row["state_sha256"] != _state_sha(row):
        raise RecoveryError("recovery_ledger_digest_mismatch", "$.ledger")
    return row


def _append(state: Mapping[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    row = deepcopy(dict(state))
    event["event_sha256"] = canonical_digest({key: item for key, item in event.items() if key != "event_sha256"})
    row["events"].append(event)
    row["head_sha256"] = event["event_sha256"]
    row["state_sha256"] = _state_sha(row)
    return validate_ledger(row)


def issue_decision(state: Any, decision: Any, *, expected_head_sha256: str, expected_bindings: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    ledger = validate_ledger(state)
    _sha(expected_head_sha256, "$.expected_head_sha256")
    if ledger["head_sha256"] != expected_head_sha256:
        raise RecoveryError("recovery_stale_head", "$.expected_head_sha256")
    row = validate_decision(decision, expected_ledger_id=ledger["ledger_id"], expected_bindings=expected_bindings, now=now)
    event = {"schema_version": 1, "artifact_type": EVENT_TYPE, "ledger_id": ledger["ledger_id"], "sequence": len(ledger["events"]) + 1, "previous_event_sha256": ledger["head_sha256"], "expected_head_sha256": expected_head_sha256, "event_type": "issue", "occurred_at": row["observed_at"], "decision_id": row["decision_id"], "decision_sha256": row["decision_sha256"], "decision": row, "reason": None, "event_sha256": ""}
    return _append(ledger, event)


def revoke_decision(state: Any, *, decision_sha256: str, reason: str, expected_head_sha256: str, occurred_at: datetime) -> dict[str, Any]:
    ledger = validate_ledger(state)
    _sha(decision_sha256, "$.decision_sha256"); _sha(expected_head_sha256, "$.expected_head_sha256")
    if ledger["head_sha256"] != expected_head_sha256:
        raise RecoveryError("recovery_stale_head", "$.expected_head_sha256")
    if not isinstance(reason, str) or reason not in REVOKE_REASONS:
        raise RecoveryError("recovery_revoke_invalid", "$.reason")
    issue = next((item for item in ledger["events"] if item["event_type"] == "issue" and item["decision_sha256"] == decision_sha256), None)
    if issue is None:
        raise RecoveryError("recovery_revoke_missing", "$.decision_sha256")
    event = {"schema_version": 1, "artifact_type": EVENT_TYPE, "ledger_id": ledger["ledger_id"], "sequence": len(ledger["events"]) + 1, "previous_event_sha256": ledger["head_sha256"], "expected_head_sha256": expected_head_sha256, "event_type": "revoke", "occurred_at": _format(_utc(occurred_at, "$.occurred_at")), "decision_id": issue["decision_id"], "decision_sha256": decision_sha256, "decision": None, "reason": reason, "event_sha256": ""}
    return _append(ledger, event)


def recover_ledger(value: Any, *, trusted_sequence: int, trusted_head_sha256: str) -> dict[str, Any]:
    if type(trusted_sequence) is not int or trusted_sequence < 0:
        raise RecoveryError("recovery_anchor_sequence_invalid", "$.trusted_sequence")
    _sha(trusted_head_sha256, "$.trusted_head_sha256")
    ledger = validate_ledger(value)
    if len(ledger["events"]) < trusted_sequence:
        raise RecoveryError("recovery_rollback_detected", "$.ledger.events")
    if len(ledger["events"]) != trusted_sequence or ledger["head_sha256"] != trusted_head_sha256:
        raise RecoveryError("recovery_anchor_head_mismatch", "$.ledger.head_sha256")
    return ledger


class RecoveryLeaseSource:
    __slots__ = ()

    def read_fact(self, operation: str, exact_identity: Any, dependency_receipts: Mapping[str, str], now: datetime) -> UnavailableFact:
        del exact_identity, dependency_receipts, now
        if not isinstance(operation, str) or operation != OPERATION:
            raise RecoveryError("canonical_operation_invalid", "$.operation")
        return UnavailableFact(operation, "canonical_source_not_implemented", SOURCE_ID)
