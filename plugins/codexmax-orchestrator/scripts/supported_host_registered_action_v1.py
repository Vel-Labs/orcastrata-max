#!/usr/bin/env python3
"""Pure registered-action admission and observation ledger.

This module performs no I/O and grants no positive fact authority.  It records
only structurally valid ``effects_v1`` artifacts.  T073 must bind a named
authenticated executor and a durable non-caller anchor before any observation
can become an available canonical fact.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Mapping

from codexmax_package_host import effects_v1
from codexmax_package_host.errors import CompanionError
from codexmax_package_host.protocol_v1 import digest, format_time, parse_time

from package_host_supported_host_fact_sources_v1 import UnavailableFact


OPERATION = "invoke_registered_action"
SOURCE_ID = "registered-action-observation-store"
UNAVAILABLE_REASON = "canonical_action_executor_not_implemented"
LEDGER_TYPE = "supported_host_registered_action_ledger_v1"
EVENT_TYPE = "supported_host_registered_action_event_v1"
ADMISSION_TYPE = "supported_host_registered_action_admission_v1"
OBSERVATION_TYPE = "supported_host_registered_action_observation_v1"
LEDGER_FIELDS = frozenset({
    "schema_version", "artifact_type", "ledger_id", "events",
    "head_sha256", "state_sha256",
})
EVENT_FIELDS = frozenset({
    "schema_version", "artifact_type", "ledger_id", "sequence",
    "previous_event_sha256", "expected_head_sha256", "event_type",
    "occurred_at", "action_id", "effect_request_sha256", "registration",
    "observation", "reason", "event_sha256",
})
ADMISSION_FIELDS = frozenset({
    "schema_version", "artifact_type", "effect_request", "admitted_at",
    "expires_at", "admission_sha256",
})
OBSERVATION_FIELDS = frozenset({
    "schema_version", "artifact_type", "observation_key", "receipt",
    "expires_at", "revoked", "observation_sha256",
})
POSITIVE_VALUE_FIELDS = frozenset({
    "variant", "registration", "observation_key", "observation",
})
REVOKE_REASONS = frozenset({
    "operator_revoked", "registration_revoked", "authority_invalidated",
})
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_INELIGIBLE = ("fixture", "synthetic", "test", "caller", "unverified", "unknown", "default")


class RegisteredActionError(ValueError):
    """A stable, non-echoing registered-action rejection."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise RegisteredActionError(code, path)
    return deepcopy(dict(value))


def _identifier(value: Any, path: str, *, eligible: bool = False) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise RegisteredActionError("identifier_invalid", path)
    if eligible and any(token in value.lower() for token in _INELIGIBLE):
        raise RegisteredActionError("registered_action_identity_ineligible", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise RegisteredActionError("digest_invalid", path)
    return value


def _time(value: Any, path: str) -> datetime:
    try:
        return parse_time(value, path)
    except CompanionError as exc:
        raise RegisteredActionError("timestamp_invalid", path) from exc


def _utc(value: Any, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise RegisteredActionError("utc_clock_invalid", path)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _registration(value: Any, action_id: str, request: Mapping[str, Any] | None, path: str) -> dict[str, Any]:
    try:
        return deepcopy(effects_v1.validate_registration(value, action_id, request))
    except CompanionError as exc:
        raise RegisteredActionError(exc.code, path) from exc


def _request(value: Any, *, action_id: str, now: datetime, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RegisteredActionError("action_request_invalid", path)
    operation = value.get("operation")
    identity = {
        "workspace_id": value.get("workspace_id"),
        "source_sha256": value.get("source_bundle", {}).get("source_sha256") if isinstance(value.get("source_bundle"), Mapping) else None,
        "candidate_sha256": value.get("source_bundle", {}).get("candidate_sha256") if isinstance(value.get("source_bundle"), Mapping) else None,
    }
    try:
        row = effects_v1.validate_effect_request(value, identity, operation, now)
    except CompanionError as exc:
        raise RegisteredActionError(exc.code, path) from exc
    if row["adapter_snapshot"]["action_id"] != action_id:
        raise RegisteredActionError("action_binding_mismatch", path + ".adapter_snapshot.action_id")
    return deepcopy(row)


def _receipt(value: Any, *, action_id: str, request: Mapping[str, Any], now: datetime, path: str) -> dict[str, Any]:
    try:
        row = effects_v1.validate_action_receipt(
            value,
            action_id=action_id,
            operation=request["operation"],
            request=request,
            now=now,
        )
    except CompanionError as exc:
        raise RegisteredActionError(exc.code, path) from exc
    observed_identity = row["observed_identity"]
    for field in ("route_id", "model", "host"):
        if observed_identity[field] == "unknown":
            raise RegisteredActionError("action_observation_identity_unknown", path + ".observed_identity." + field)
        _identifier(observed_identity[field], path + ".observed_identity." + field, eligible=True)
    return deepcopy(row)


def _genesis(ledger_id: str) -> str:
    return digest({
        "schema_version": 1,
        "artifact_type": "supported_host_registered_action_genesis_v1",
        "ledger_id": ledger_id,
    })


def _state_sha(state: Mapping[str, Any]) -> str:
    return digest({key: item for key, item in state.items() if key != "state_sha256"})


def _admission(value: Any, *, action_id: str, occurred: datetime, path: str) -> dict[str, Any]:
    row = _closed(value, ADMISSION_FIELDS, "action_admission_invalid", path)
    if type(row["schema_version"]) is not int or row["schema_version"] != 1 or row["artifact_type"] != ADMISSION_TYPE:
        raise RegisteredActionError("action_admission_version_invalid", path)
    request = _request(row["effect_request"], action_id=action_id, now=occurred, path=path + ".effect_request")
    admitted = _time(row["admitted_at"], path + ".admitted_at")
    expires = _time(row["expires_at"], path + ".expires_at")
    if admitted != occurred or admitted < _time(request["created_at"], path + ".effect_request.created_at") or expires <= admitted:
        raise RegisteredActionError("action_admission_stale", path)
    expiry_values = [
        request["authority_receipt"]["expires_at"], request["thread_snapshot"]["expires_at"],
        request["preset_snapshot"]["expires_at"], request["route_snapshot"]["expires_at"],
        request["adapter_snapshot"]["expires_at"], request["policy_snapshot"]["expires_at"],
        request["lease"]["expires_at"],
    ]
    if expires != min(_time(item, path + ".effect_request") for item in expiry_values):
        raise RegisteredActionError("action_admission_expiry_mismatch", path + ".expires_at")
    if row["admission_sha256"] != digest({key: item for key, item in row.items() if key != "admission_sha256"}):
        raise RegisteredActionError("action_admission_digest_mismatch", path + ".admission_sha256")
    return row


def _observation(value: Any, *, action_id: str, request: Mapping[str, Any], occurred: datetime, path: str) -> dict[str, Any]:
    row = _closed(value, OBSERVATION_FIELDS, "action_observation_invalid", path)
    if type(row["schema_version"]) is not int or row["schema_version"] != 1 or row["artifact_type"] != OBSERVATION_TYPE or row["revoked"] is not False:
        raise RegisteredActionError("action_observation_version_invalid", path)
    if row["observation_key"] != request["request_sha256"]:
        raise RegisteredActionError("action_binding_mismatch", path + ".observation_key")
    receipt = _receipt(row["receipt"], action_id=action_id, request=request, now=occurred, path=path + ".receipt")
    expires = _time(row["expires_at"], path + ".expires_at")
    admission_expiry = min(_time(request[name]["expires_at"], path + ".receipt") for name in (
        "authority_receipt", "thread_snapshot", "preset_snapshot", "route_snapshot",
        "adapter_snapshot", "policy_snapshot", "lease",
    ))
    if (
        _time(receipt["observed_at"], path + ".receipt.observed_at") != occurred
        or expires <= occurred
        or expires - occurred > timedelta(minutes=5)
        or expires > admission_expiry
    ):
        raise RegisteredActionError("action_observation_stale", path + ".expires_at")
    if row["observation_sha256"] != digest({key: item for key, item in row.items() if key != "observation_sha256"}):
        raise RegisteredActionError("action_observation_digest_mismatch", path + ".observation_sha256")
    return row


def new_ledger(ledger_id: str) -> dict[str, Any]:
    """Return a sealed empty ledger."""

    _identifier(ledger_id, "$.ledger_id", eligible=True)
    state = {
        "schema_version": 1,
        "artifact_type": LEDGER_TYPE,
        "ledger_id": ledger_id,
        "events": [],
        "head_sha256": _genesis(ledger_id),
        "state_sha256": "",
    }
    state["state_sha256"] = _state_sha(state)
    return state


def validate_ledger(value: Any) -> dict[str, Any]:
    """Validate the complete ledger and derive all replay state."""

    state = _closed(value, LEDGER_FIELDS, "action_ledger_invalid", "$.ledger")
    if type(state["schema_version"]) is not int or state["schema_version"] != 1 or state["artifact_type"] != LEDGER_TYPE:
        raise RegisteredActionError("action_ledger_version_invalid", "$.ledger")
    ledger_id = _identifier(state["ledger_id"], "$.ledger.ledger_id", eligible=True)
    if not isinstance(state["events"], list):
        raise RegisteredActionError("action_ledger_events_invalid", "$.ledger.events")
    previous = _genesis(ledger_id)
    last_time: datetime | None = None
    registrations: dict[str, dict[str, Any]] = {}
    registration_digests: dict[str, str] = {}
    admissions: dict[str, dict[str, Any]] = {}
    request_ids: dict[str, str] = {}
    idempotency_keys: dict[str, str] = {}
    observations: dict[str, dict[str, Any]] = {}
    receipt_ids: dict[str, str] = {}
    revoked: set[str] = set()
    for index, raw in enumerate(state["events"]):
        path = f"$.ledger.events[{index}]"
        event = _closed(raw, EVENT_FIELDS, "action_event_invalid", path)
        if type(event["schema_version"]) is not int or event["schema_version"] != 1 or event["artifact_type"] != EVENT_TYPE or event["ledger_id"] != ledger_id:
            raise RegisteredActionError("action_event_version_invalid", path)
        if type(event["sequence"]) is not int or event["sequence"] != index + 1:
            raise RegisteredActionError("action_sequence_invalid", path + ".sequence")
        if event["previous_event_sha256"] != previous or event["expected_head_sha256"] != previous:
            raise RegisteredActionError("action_chain_broken", path)
        occurred = _time(event["occurred_at"], path + ".occurred_at")
        if last_time is not None and occurred < last_time:
            raise RegisteredActionError("action_time_regression", path + ".occurred_at")
        last_time = occurred
        action_id = _identifier(event["action_id"], path + ".action_id", eligible=True)
        event_type = event["event_type"]
        if event_type == "registration":
            if event["effect_request_sha256"] is not None or event["observation"] is not None or event["reason"] is not None:
                raise RegisteredActionError("action_event_shape_invalid", path)
            registration = _registration(event["registration"], action_id, None, path + ".registration")
            registration_sha = digest(registration)
            if action_id in registrations:
                code = "action_registration_replay" if registration_digests[action_id] == registration_sha else "action_registration_collision"
                raise RegisteredActionError(code, path + ".action_id")
            registrations[action_id] = registration
            registration_digests[action_id] = registration_sha
        elif event_type == "execution_admission":
            request_sha = _sha(event["effect_request_sha256"], path + ".effect_request_sha256")
            if event["reason"] is not None or action_id not in registrations:
                raise RegisteredActionError("action_admission_registration_missing", path)
            admission = _admission(event["observation"], action_id=action_id, occurred=occurred, path=path + ".observation")
            request = admission["effect_request"]
            _registration(event["registration"], action_id, request, path + ".registration")
            if event["registration"] != registrations[action_id] or request_sha != request["request_sha256"]:
                raise RegisteredActionError("action_binding_mismatch", path)
            for key, seen, code in (
                (request["request_id"], request_ids, "action_request_id_collision"),
                (request["idempotency_key"], idempotency_keys, "action_idempotency_collision"),
            ):
                if key in seen:
                    raise RegisteredActionError("action_admission_replay" if seen[key] == request_sha else code, path)
                seen[key] = request_sha
            if request_sha in admissions:
                raise RegisteredActionError("action_admission_replay", path + ".effect_request_sha256")
            admissions[request_sha] = admission
        elif event_type == "observation":
            request_sha = _sha(event["effect_request_sha256"], path + ".effect_request_sha256")
            if event["reason"] is not None or request_sha not in admissions:
                raise RegisteredActionError("action_observation_admission_missing", path)
            request = admissions[request_sha]["effect_request"]
            _registration(event["registration"], action_id, request, path + ".registration")
            if event["registration"] != registrations.get(action_id):
                raise RegisteredActionError("action_binding_mismatch", path + ".registration")
            observation = _observation(event["observation"], action_id=action_id, request=request, occurred=occurred, path=path + ".observation")
            receipt = observation["receipt"]
            receipt_sha = receipt["receipt_sha256"]
            receipt_id = receipt["action_receipt_id"]
            if request_sha in observations:
                raise RegisteredActionError("action_observation_replay", path + ".effect_request_sha256")
            if receipt_sha in {item["receipt"]["receipt_sha256"] for item in observations.values()}:
                raise RegisteredActionError("action_receipt_replay", path + ".observation.receipt.receipt_sha256")
            if receipt_id in receipt_ids:
                raise RegisteredActionError("action_receipt_id_collision", path + ".observation.receipt.action_receipt_id")
            receipt_ids[receipt_id] = receipt_sha
            observations[request_sha] = observation
        elif event_type == "revoke":
            request_sha = _sha(event["effect_request_sha256"], path + ".effect_request_sha256")
            if event["registration"] is not None or event["observation"] is not None or event["reason"] not in REVOKE_REASONS:
                raise RegisteredActionError("action_revoke_invalid", path)
            if request_sha not in observations or request_sha in revoked:
                raise RegisteredActionError("action_revoke_target_invalid", path + ".effect_request_sha256")
            if observations[request_sha]["receipt"]["action_id"] != action_id:
                raise RegisteredActionError("action_binding_mismatch", path + ".action_id")
            revoked.add(request_sha)
        else:
            raise RegisteredActionError("action_event_type_invalid", path + ".event_type")
        event_sha = digest({key: item for key, item in event.items() if key != "event_sha256"})
        if event["event_sha256"] != event_sha:
            raise RegisteredActionError("action_event_digest_mismatch", path + ".event_sha256")
        previous = event_sha
    if state["head_sha256"] != previous:
        raise RegisteredActionError("action_ledger_head_mismatch", "$.ledger.head_sha256")
    if state["state_sha256"] != _state_sha(state):
        raise RegisteredActionError("action_ledger_state_digest_mismatch", "$.ledger.state_sha256")
    return state


def _append(state: Mapping[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    candidate = deepcopy(dict(state))
    event["event_sha256"] = digest({key: item for key, item in event.items() if key != "event_sha256"})
    candidate["events"].append(event)
    candidate["head_sha256"] = event["event_sha256"]
    candidate["state_sha256"] = _state_sha(candidate)
    return validate_ledger(candidate)


def _base_event(state: Mapping[str, Any], event_type: str, action_id: str, expected_head_sha256: str, occurred_at: datetime) -> dict[str, Any]:
    current = _utc(occurred_at, "$.occurred_at")
    _sha(expected_head_sha256, "$.expected_head_sha256")
    if state["head_sha256"] != expected_head_sha256:
        raise RegisteredActionError("action_ledger_stale_head", "$.expected_head_sha256")
    return {
        "schema_version": 1, "artifact_type": EVENT_TYPE, "ledger_id": state["ledger_id"],
        "sequence": len(state["events"]) + 1, "previous_event_sha256": state["head_sha256"],
        "expected_head_sha256": expected_head_sha256, "event_type": event_type,
        "occurred_at": format_time(current), "action_id": _identifier(action_id, "$.action_id", eligible=True),
        "effect_request_sha256": None, "registration": None, "observation": None,
        "reason": None, "event_sha256": "",
    }


def _check_head(state: Mapping[str, Any], expected_head_sha256: str) -> None:
    _sha(expected_head_sha256, "$.expected_head_sha256")
    if state["head_sha256"] != expected_head_sha256:
        raise RegisteredActionError("action_ledger_stale_head", "$.expected_head_sha256")


def record_registration(state: Any, registration: Mapping[str, Any], *, expected_head_sha256: str, occurred_at: datetime) -> dict[str, Any]:
    """Append one exact action registration with head CAS."""

    ledger = validate_ledger(state)
    _check_head(ledger, expected_head_sha256)
    action_id = registration.get("action_id") if isinstance(registration, Mapping) else None
    action_id = _identifier(action_id, "$.registration.action_id", eligible=True)
    row = _registration(registration, action_id, None, "$.registration")
    existing = [event for event in ledger["events"] if event["event_type"] == "registration" and event["action_id"] == action_id]
    if existing:
        if existing[0]["registration"] == row:
            return deepcopy(ledger)
        raise RegisteredActionError("action_registration_collision", "$.registration.action_id")
    event = _base_event(ledger, "registration", action_id, expected_head_sha256, occurred_at)
    event["registration"] = row
    return _append(ledger, event)


def record_execution_admission(state: Any, effect_request: Mapping[str, Any], *, expected_head_sha256: str, admitted_at: datetime) -> dict[str, Any]:
    """Append a validated request admission without invoking an executor."""

    ledger = validate_ledger(state)
    _check_head(ledger, expected_head_sha256)
    current = _utc(admitted_at, "$.admitted_at")
    if not isinstance(effect_request, Mapping) or not isinstance(effect_request.get("adapter_snapshot"), Mapping):
        raise RegisteredActionError("action_request_invalid", "$.effect_request")
    action_id = _identifier(effect_request["adapter_snapshot"].get("action_id"), "$.effect_request.adapter_snapshot.action_id", eligible=True)
    request = _request(effect_request, action_id=action_id, now=current, path="$.effect_request")
    registration_event = next((event for event in ledger["events"] if event["event_type"] == "registration" and event["action_id"] == action_id), None)
    if registration_event is None:
        raise RegisteredActionError("action_admission_registration_missing", "$.effect_request.adapter_snapshot.action_id")
    registration = _registration(registration_event["registration"], action_id, request, "$.registration")
    request_sha = request["request_sha256"]
    existing = [event for event in ledger["events"] if event["event_type"] == "execution_admission"]
    for prior in existing:
        prior_request = prior["observation"]["effect_request"]
        if prior["effect_request_sha256"] == request_sha:
            return deepcopy(ledger)
        if prior_request["request_id"] == request["request_id"]:
            raise RegisteredActionError("action_request_id_collision", "$.effect_request.request_id")
        if prior_request["idempotency_key"] == request["idempotency_key"]:
            raise RegisteredActionError("action_idempotency_collision", "$.effect_request.idempotency_key")
    expiry = min(_time(request[name]["expires_at"], "$.effect_request." + name + ".expires_at") for name in (
        "authority_receipt", "thread_snapshot", "preset_snapshot", "route_snapshot",
        "adapter_snapshot", "policy_snapshot", "lease",
    ))
    admission = {
        "schema_version": 1, "artifact_type": ADMISSION_TYPE, "effect_request": request,
        "admitted_at": format_time(current), "expires_at": format_time(expiry), "admission_sha256": "",
    }
    admission["admission_sha256"] = digest({key: item for key, item in admission.items() if key != "admission_sha256"})
    event = _base_event(ledger, "execution_admission", action_id, expected_head_sha256, current)
    event["effect_request_sha256"] = request_sha
    event["registration"] = registration
    event["observation"] = admission
    return _append(ledger, event)


def record_observation(state: Any, receipt: Mapping[str, Any], *, expected_head_sha256: str, observed_at: datetime, expires_at: datetime) -> dict[str, Any]:
    """Append one exact observed action receipt without inferring provider state."""

    ledger = validate_ledger(state)
    _check_head(ledger, expected_head_sha256)
    current = _utc(observed_at, "$.observed_at")
    expiry = _utc(expires_at, "$.expires_at")
    if expiry <= current or expiry - current > timedelta(minutes=5):
        raise RegisteredActionError("action_observation_stale", "$.expires_at")
    if not isinstance(receipt, Mapping):
        raise RegisteredActionError("action_observation_missing", "$.receipt")
    action_id = _identifier(receipt.get("action_id"), "$.receipt.action_id", eligible=True)
    request_sha = _sha(receipt.get("request_sha256"), "$.receipt.request_sha256")
    admission_event = next((event for event in ledger["events"] if event["event_type"] == "execution_admission" and event["effect_request_sha256"] == request_sha), None)
    if admission_event is None:
        raise RegisteredActionError("action_observation_admission_missing", "$.receipt.request_sha256")
    request = admission_event["observation"]["effect_request"]
    if expiry > _time(admission_event["observation"]["expires_at"], "$.admission.expires_at"):
        raise RegisteredActionError("action_observation_stale", "$.expires_at")
    registration = _registration(admission_event["registration"], action_id, request, "$.registration")
    row = _receipt(receipt, action_id=action_id, request=request, now=current, path="$.receipt")
    existing = next((event for event in ledger["events"] if event["event_type"] == "observation" and event["effect_request_sha256"] == request_sha), None)
    if existing is not None:
        if any(event["event_type"] == "revoke" and event["effect_request_sha256"] == request_sha for event in ledger["events"]):
            raise RegisteredActionError("action_observation_revoked", "$.receipt.request_sha256")
        if existing["observation"]["receipt"] == row and existing["observation"]["expires_at"] == format_time(expiry):
            return deepcopy(ledger)
        raise RegisteredActionError("action_observation_collision", "$.receipt.request_sha256")
    for event in ledger["events"]:
        if event["event_type"] != "observation":
            continue
        prior = event["observation"]["receipt"]
        if prior["action_receipt_id"] == row["action_receipt_id"] or prior["receipt_sha256"] == row["receipt_sha256"]:
            raise RegisteredActionError("action_receipt_replay", "$.receipt.action_receipt_id")
    observation = {
        "schema_version": 1, "artifact_type": OBSERVATION_TYPE,
        "observation_key": request_sha, "receipt": row, "expires_at": format_time(expiry),
        "revoked": False, "observation_sha256": "",
    }
    observation["observation_sha256"] = digest({key: item for key, item in observation.items() if key != "observation_sha256"})
    event = _base_event(ledger, "observation", action_id, expected_head_sha256, current)
    event["effect_request_sha256"] = request_sha
    event["registration"] = registration
    event["observation"] = observation
    return _append(ledger, event)


def revoke_observation(state: Any, *, effect_request_sha256: str, reason: str, expected_head_sha256: str, occurred_at: datetime) -> dict[str, Any]:
    """Revoke one observation with exact head CAS."""

    ledger = validate_ledger(state)
    _check_head(ledger, expected_head_sha256)
    request_sha = _sha(effect_request_sha256, "$.effect_request_sha256")
    if reason not in REVOKE_REASONS:
        raise RegisteredActionError("action_revoke_reason_invalid", "$.reason")
    target = next((event for event in ledger["events"] if event["event_type"] == "observation" and event["effect_request_sha256"] == request_sha), None)
    if target is None:
        raise RegisteredActionError("action_revoke_target_invalid", "$.effect_request_sha256")
    prior_revoke = next((event for event in ledger["events"] if event["event_type"] == "revoke" and event["effect_request_sha256"] == request_sha), None)
    if prior_revoke is not None:
        if prior_revoke["reason"] == reason:
            return deepcopy(ledger)
        raise RegisteredActionError("action_revoke_collision", "$.reason")
    event = _base_event(ledger, "revoke", target["action_id"], expected_head_sha256, occurred_at)
    event["effect_request_sha256"] = request_sha
    event["reason"] = reason
    return _append(ledger, event)


def recover_ledger(value: Any, *, trusted_minimum_sequence: int, trusted_head_sha256: str) -> dict[str, Any]:
    """Validate all history against an external sequence and head anchor."""

    if type(trusted_minimum_sequence) is not int or trusted_minimum_sequence < 0:
        raise RegisteredActionError("action_anchor_sequence_invalid", "$.trusted_minimum_sequence")
    _sha(trusted_head_sha256, "$.trusted_head_sha256")
    ledger = validate_ledger(value)
    if len(ledger["events"]) < trusted_minimum_sequence:
        raise RegisteredActionError("action_rollback_detected", "$.ledger.events")
    if ledger["head_sha256"] != trusted_head_sha256:
        raise RegisteredActionError("action_anchor_head_mismatch", "$.ledger.head_sha256")
    return ledger


def validate_positive_value(value: Any, *, effect_request: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    """Validate the future value shape without granting or returning authority."""

    row = _closed(value, POSITIVE_VALUE_FIELDS, "action_positive_value_invalid", "$.value")
    if row["variant"] != "registered_action_observation_v1":
        raise RegisteredActionError("action_positive_value_version_invalid", "$.value.variant")
    action_id = row["registration"].get("action_id") if isinstance(row["registration"], Mapping) else None
    action_id = _identifier(action_id, "$.value.registration.action_id", eligible=True)
    current = _utc(now, "$.now")
    request = _request(effect_request, action_id=action_id, now=current, path="$.effect_request")
    registration = _registration(row["registration"], action_id, request, "$.value.registration")
    observation_key = _sha(row["observation_key"], "$.value.observation_key")
    observation = _closed(row["observation"], frozenset({"receipt", "expires_at", "revoked"}), "action_positive_value_invalid", "$.value.observation")
    if observation["revoked"] is not False:
        raise RegisteredActionError("action_observation_revoked", "$.value.observation.revoked")
    expires = _time(observation["expires_at"], "$.value.observation.expires_at")
    request_expiry = min(_time(request[name]["expires_at"], "$.effect_request." + name + ".expires_at") for name in (
        "authority_receipt", "thread_snapshot", "preset_snapshot", "route_snapshot",
        "adapter_snapshot", "policy_snapshot", "lease",
    ))
    if expires <= current or expires - current > timedelta(minutes=5) or expires > request_expiry:
        raise RegisteredActionError("action_observation_stale", "$.value.observation.expires_at")
    if observation_key != request["request_sha256"]:
        raise RegisteredActionError("action_binding_mismatch", "$.value.observation")
    receipt = _receipt(observation["receipt"], action_id=action_id, request=request, now=current, path="$.value.observation.receipt")
    return {"variant": row["variant"], "registration": registration, "observation_key": observation_key, "observation": observation}


class RegisteredActionFactSource:
    """Return typed unavailable until T073 supplies real external authority."""

    __slots__ = ()

    def read_fact(self, operation: str, exact_identity: Any, dependency_receipts: Mapping[str, str], now: datetime) -> UnavailableFact:
        del exact_identity, dependency_receipts, now
        if operation != OPERATION:
            raise RegisteredActionError("canonical_operation_invalid", "$.operation")
        return UnavailableFact(operation, UNAVAILABLE_REASON, SOURCE_ID)


class UnavailableRegisteredActionExecutor:
    """A non-executing production boundary with one typed result."""

    __slots__ = ()

    def execute(self, operation: str, action_id: Any, effect_request: Any, now: datetime) -> UnavailableFact:
        del action_id, effect_request, now
        if operation != OPERATION:
            raise RegisteredActionError("canonical_operation_invalid", "$.operation")
        return UnavailableFact(operation, UNAVAILABLE_REASON, SOURCE_ID)
