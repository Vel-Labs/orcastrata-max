#!/usr/bin/env python3
"""Pure supported-host effect-authority ledger and unavailable action source."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Mapping

from codexmax_package_host.authority_v1 import (
    AUTHORITY_FIELDS,
    VERIFICATION_CONTEXT_FIELDS,
    validate_authority,
)
from codexmax_package_host.errors import CompanionError
from codexmax_package_host.protocol_v1 import digest, format_time, parse_time

from package_host_supported_host_fact_sources_v1 import UnavailableFact


LEDGER_TYPE = "supported_host_effect_authority_ledger_v1"
EVENT_TYPE = "supported_host_effect_authority_event_v1"
ISSUER_DECISION_TYPE = "supported_host_effect_authority_issue_decision_v1"
ISSUER_DECISION_SOURCE_ID = "responses-context-issuer"
AUTHORITY_SOURCE_ID = "effect-authority-ledger"
ACTION_SOURCE_ID = "registered-action-observation-store"
LEDGER_FIELDS = frozenset({
    "schema_version", "artifact_type", "ledger_id", "events",
    "head_sha256", "state_sha256",
})
EVENT_FIELDS = frozenset({
    "schema_version", "artifact_type", "ledger_id", "sequence",
    "previous_event_sha256", "expected_head_sha256", "event_type",
    "occurred_at", "authority_id", "authority_receipt_sha256",
    "authority", "request_sha256", "reason", "issuer_decision_sha256",
    "event_sha256",
})
ISSUER_DECISION_FIELDS = frozenset({
    "schema_version", "artifact_type", "decision_id", "decision_source_id",
    "decision", "ledger_id", "authority", "request_sha256", "decided_at",
    "expires_at", "decision_sha256",
})
REVOKE_REASONS = frozenset({"operator_revoked", "request_withdrawn", "binding_invalidated"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class EffectAuthorityError(ValueError):
    """A stable, non-echoing ledger rejection."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise EffectAuthorityError(code, path)
    return deepcopy(dict(value))


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise EffectAuthorityError("identifier_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise EffectAuthorityError("digest_invalid", path)
    return value


def _time(value: Any, path: str) -> datetime:
    try:
        return parse_time(value, path)
    except CompanionError as exc:
        raise EffectAuthorityError("timestamp_invalid", path) from exc


def _utc(value: Any, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise EffectAuthorityError("utc_clock_invalid", path)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _context(value: Any, path: str = "$.context") -> dict[str, Any]:
    context = _closed(value, VERIFICATION_CONTEXT_FIELDS, "authority_context_invalid", path)
    for field in ("workspace_id", "thread_id", "operation"):
        _identifier(context[field], path + "." + field)
    for field in (
        "source_sha256", "candidate_sha256", "request_intent_sha256",
        "request_sha256",
    ):
        _sha(context[field], path + "." + field)
    if type(context["thread_generation"]) is not int or context["thread_generation"] < 1:
        raise EffectAuthorityError("authority_context_invalid", path + ".thread_generation")
    _time(context["expires_at"], path + ".expires_at")
    return context


def _genesis_head(ledger_id: str) -> str:
    return digest({
        "schema_version": 1,
        "artifact_type": "supported_host_effect_authority_genesis_v1",
        "ledger_id": ledger_id,
    })


def _seal_state(state: Mapping[str, Any]) -> str:
    return digest({key: item for key, item in state.items() if key != "state_sha256"})


def new_ledger(ledger_id: str) -> dict[str, Any]:
    """Return one empty, sealed ledger value."""

    _identifier(ledger_id, "$.ledger_id")
    state = {
        "schema_version": 1,
        "artifact_type": LEDGER_TYPE,
        "ledger_id": ledger_id,
        "events": [],
        "head_sha256": _genesis_head(ledger_id),
        "state_sha256": "",
    }
    state["state_sha256"] = _seal_state(state)
    return state


def validate_ledger(value: Any) -> dict[str, Any]:
    """Validate the complete sealed state and every event in its hash chain."""

    state = _closed(value, LEDGER_FIELDS, "ledger_shape_invalid", "$.ledger")
    if type(state["schema_version"]) is not int or state["schema_version"] != 1 or state["artifact_type"] != LEDGER_TYPE:
        raise EffectAuthorityError("ledger_version_invalid", "$.ledger")
    ledger_id = _identifier(state["ledger_id"], "$.ledger.ledger_id")
    if not isinstance(state["events"], list):
        raise EffectAuthorityError("ledger_events_invalid", "$.ledger.events")
    previous = _genesis_head(ledger_id)
    authority_ids: dict[str, str] = {}
    authority_receipts: set[str] = set()
    decision_digests: set[str] = set()
    revoked: set[str] = set()
    last_time: datetime | None = None
    for index, raw in enumerate(state["events"]):
        path = f"$.ledger.events[{index}]"
        event = _closed(raw, EVENT_FIELDS, "ledger_event_shape_invalid", path)
        if type(event["schema_version"]) is not int or event["schema_version"] != 1 or event["artifact_type"] != EVENT_TYPE:
            raise EffectAuthorityError("ledger_event_version_invalid", path)
        if event["ledger_id"] != ledger_id:
            raise EffectAuthorityError("ledger_event_binding_mismatch", path + ".ledger_id")
        if type(event["sequence"]) is not int or event["sequence"] != index + 1:
            raise EffectAuthorityError("ledger_sequence_invalid", path + ".sequence")
        if event["previous_event_sha256"] != previous or event["expected_head_sha256"] != previous:
            raise EffectAuthorityError("ledger_chain_broken", path + ".previous_event_sha256")
        occurred = _time(event["occurred_at"], path + ".occurred_at")
        if last_time is not None and occurred < last_time:
            raise EffectAuthorityError("ledger_time_regression", path + ".occurred_at")
        last_time = occurred
        authority_id = _identifier(event["authority_id"], path + ".authority_id")
        receipt_sha = _sha(event["authority_receipt_sha256"], path + ".authority_receipt_sha256")
        _sha(event["request_sha256"], path + ".request_sha256")
        if event["event_type"] == "issue":
            authority = _closed(event["authority"], AUTHORITY_FIELDS, "ledger_authority_invalid", path + ".authority")
            if type(authority["schema_version"]) is not int or authority["schema_version"] != 1:
                raise EffectAuthorityError("ledger_authority_invalid", path + ".authority.schema_version")
            if authority["authority_id"] != authority_id or authority["receipt_sha256"] != receipt_sha:
                raise EffectAuthorityError("ledger_authority_binding_mismatch", path + ".authority")
            authority_context = {
                field: authority[field]
                for field in VERIFICATION_CONTEXT_FIELDS
                if field not in {"request_sha256", "expires_at"}
            }
            authority_context["request_sha256"] = event["request_sha256"]
            authority_context["expires_at"] = authority["expires_at"]
            try:
                validate_authority(authority, authority_context, occurred)
            except CompanionError as exc:
                raise EffectAuthorityError(exc.code, exc.path) from exc
            if authority["issued_at"] != event["occurred_at"]:
                raise EffectAuthorityError("ledger_authority_binding_mismatch", path + ".occurred_at")
            if authority_id in authority_ids:
                code = "ledger_issue_duplicate" if authority_ids[authority_id] == receipt_sha else "ledger_authority_collision"
                raise EffectAuthorityError(code, path + ".authority_id")
            if receipt_sha in authority_receipts:
                raise EffectAuthorityError("ledger_issue_replay", path + ".authority_receipt_sha256")
            decision_sha = _sha(event["issuer_decision_sha256"], path + ".issuer_decision_sha256")
            if decision_sha in decision_digests:
                raise EffectAuthorityError("ledger_decision_replay", path + ".issuer_decision_sha256")
            if event["reason"] is not None:
                raise EffectAuthorityError("ledger_event_shape_invalid", path + ".reason")
            authority_ids[authority_id] = receipt_sha
            authority_receipts.add(receipt_sha)
            decision_digests.add(decision_sha)
        elif event["event_type"] == "revoke":
            if event["authority"] is not None or event["issuer_decision_sha256"] is not None:
                raise EffectAuthorityError("ledger_event_shape_invalid", path)
            if event["reason"] not in REVOKE_REASONS:
                raise EffectAuthorityError("ledger_revoke_reason_invalid", path + ".reason")
            if authority_ids.get(authority_id) != receipt_sha:
                raise EffectAuthorityError("ledger_revoke_target_missing", path + ".authority_receipt_sha256")
            if receipt_sha in revoked:
                raise EffectAuthorityError("ledger_revoke_duplicate", path + ".authority_receipt_sha256")
            revoked.add(receipt_sha)
        else:
            raise EffectAuthorityError("ledger_event_type_invalid", path + ".event_type")
        expected_event_sha = digest({key: item for key, item in event.items() if key != "event_sha256"})
        if event["event_sha256"] != expected_event_sha:
            raise EffectAuthorityError("ledger_event_digest_mismatch", path + ".event_sha256")
        previous = expected_event_sha
    if state["head_sha256"] != previous:
        raise EffectAuthorityError("ledger_head_mismatch", "$.ledger.head_sha256")
    if state["state_sha256"] != _seal_state(state):
        raise EffectAuthorityError("ledger_state_digest_mismatch", "$.ledger.state_sha256")
    return state


def validate_issuer_decision(
    value: Any,
    *,
    expected_ledger_id: str,
    expected_context: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Validate structure only; this function does not establish issuer trust."""

    decision = _closed(value, ISSUER_DECISION_FIELDS, "issuer_decision_shape_invalid", "$.issuer_decision")
    if type(decision["schema_version"]) is not int or decision["schema_version"] != 1 or decision["artifact_type"] != ISSUER_DECISION_TYPE:
        raise EffectAuthorityError("issuer_decision_version_invalid", "$.issuer_decision")
    _identifier(decision["decision_id"], "$.issuer_decision.decision_id")
    if decision["decision_source_id"] != ISSUER_DECISION_SOURCE_ID or decision["decision"] != "issue":
        raise EffectAuthorityError("issuer_decision_authority_invalid", "$.issuer_decision")
    if decision["ledger_id"] != expected_ledger_id:
        raise EffectAuthorityError("issuer_decision_binding_mismatch", "$.issuer_decision.ledger_id")
    _sha(decision["request_sha256"], "$.issuer_decision.request_sha256")
    current = _utc(now, "$.now")
    decided = _time(decision["decided_at"], "$.issuer_decision.decided_at")
    expires = _time(decision["expires_at"], "$.issuer_decision.expires_at")
    if decided > current or expires <= current or expires <= decided:
        raise EffectAuthorityError("issuer_decision_stale", "$.issuer_decision.expires_at")
    try:
        context = _context(expected_context)
    except EffectAuthorityError as exc:
        raise EffectAuthorityError("issuer_decision_context_invalid", exc.path) from exc
    if decision["request_sha256"] != context["request_sha256"] or decision["expires_at"] != context["expires_at"]:
        raise EffectAuthorityError("issuer_decision_binding_mismatch", "$.issuer_decision")
    try:
        authority = validate_authority(decision["authority"], context, current)
    except CompanionError as exc:
        raise EffectAuthorityError(exc.code, exc.path) from exc
    if (
        type(authority["schema_version"]) is not int
        or authority["schema_version"] != 1
        or
        authority["issuer_id"] != decision["decision_source_id"]
        or authority["issued_at"] != decision["decided_at"]
        or authority["expires_at"] != decision["expires_at"]
    ):
        raise EffectAuthorityError("issuer_decision_binding_mismatch", "$.issuer_decision.authority")
    if decision["decision_sha256"] != digest({key: item for key, item in decision.items() if key != "decision_sha256"}):
        raise EffectAuthorityError("issuer_decision_digest_mismatch", "$.issuer_decision.decision_sha256")
    return decision


def _append(state: Mapping[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    candidate = deepcopy(dict(state))
    event["event_sha256"] = digest({key: item for key, item in event.items() if key != "event_sha256"})
    candidate["events"].append(event)
    candidate["head_sha256"] = event["event_sha256"]
    candidate["state_sha256"] = _seal_state(candidate)
    return validate_ledger(candidate)


def issue_authority(
    state: Any,
    decision: Mapping[str, Any],
    *,
    expected_head_sha256: str,
) -> dict[str, Any]:
    """Append one structurally valid event without granting fact authority."""

    ledger = validate_ledger(state)
    _sha(expected_head_sha256, "$.expected_head_sha256")
    if ledger["head_sha256"] != expected_head_sha256:
        raise EffectAuthorityError("ledger_stale_head", "$.expected_head_sha256")
    row = _closed(decision, ISSUER_DECISION_FIELDS, "issuer_decision_shape_invalid", "$.issuer_decision")
    if type(row["schema_version"]) is not int or row["schema_version"] != 1 or row["artifact_type"] != ISSUER_DECISION_TYPE:
        raise EffectAuthorityError("issuer_decision_version_invalid", "$.issuer_decision")
    if row["decision_sha256"] != digest({key: item for key, item in row.items() if key != "decision_sha256"}):
        raise EffectAuthorityError("issuer_decision_digest_mismatch", "$.issuer_decision.decision_sha256")
    if row["ledger_id"] != ledger["ledger_id"]:
        raise EffectAuthorityError("issuer_decision_binding_mismatch", "$.issuer_decision.ledger_id")
    authority = _closed(
        row["authority"],
        AUTHORITY_FIELDS,
        "issuer_decision_authority_invalid",
        "$.issuer_decision.authority",
    )
    event = {
        "schema_version": 1,
        "artifact_type": EVENT_TYPE,
        "ledger_id": ledger["ledger_id"],
        "sequence": len(ledger["events"]) + 1,
        "previous_event_sha256": ledger["head_sha256"],
        "expected_head_sha256": expected_head_sha256,
        "event_type": "issue",
        "occurred_at": row["decided_at"],
        "authority_id": authority["authority_id"],
        "authority_receipt_sha256": authority["receipt_sha256"],
        "authority": authority,
        "request_sha256": row["request_sha256"],
        "reason": None,
        "issuer_decision_sha256": row["decision_sha256"],
        "event_sha256": "",
    }
    return _append(ledger, event)


def revoke_authority(
    state: Any,
    *,
    authority_receipt_sha256: str,
    reason: str,
    expected_head_sha256: str,
    occurred_at: datetime,
) -> dict[str, Any]:
    """Append one closed revocation with exact head compare-and-swap."""

    ledger = validate_ledger(state)
    _sha(authority_receipt_sha256, "$.authority_receipt_sha256")
    _sha(expected_head_sha256, "$.expected_head_sha256")
    if ledger["head_sha256"] != expected_head_sha256:
        raise EffectAuthorityError("ledger_stale_head", "$.expected_head_sha256")
    if reason not in REVOKE_REASONS:
        raise EffectAuthorityError("ledger_revoke_reason_invalid", "$.reason")
    issue = next((item for item in ledger["events"] if item["event_type"] == "issue" and item["authority_receipt_sha256"] == authority_receipt_sha256), None)
    if issue is None:
        raise EffectAuthorityError("ledger_revoke_target_missing", "$.authority_receipt_sha256")
    event = {
        "schema_version": 1,
        "artifact_type": EVENT_TYPE,
        "ledger_id": ledger["ledger_id"],
        "sequence": len(ledger["events"]) + 1,
        "previous_event_sha256": ledger["head_sha256"],
        "expected_head_sha256": expected_head_sha256,
        "event_type": "revoke",
        "occurred_at": format_time(_utc(occurred_at, "$.occurred_at")),
        "authority_id": issue["authority_id"],
        "authority_receipt_sha256": authority_receipt_sha256,
        "authority": None,
        "request_sha256": issue["request_sha256"],
        "reason": reason,
        "issuer_decision_sha256": None,
        "event_sha256": "",
    }
    return _append(ledger, event)


def current_authority(
    state: Any,
    context: Mapping[str, Any],
    now: datetime,
    *,
    trusted_minimum_sequence: int,
    trusted_head_sha256: str,
) -> dict[str, Any]:
    """Fail closed until T066 provides a non-caller trust anchor."""

    recover_ledger(
        state,
        trusted_minimum_sequence=trusted_minimum_sequence,
        trusted_head_sha256=trusted_head_sha256,
    )
    _context(context)
    _utc(now, "$.now")
    raise EffectAuthorityError("authority_trust_anchor_unavailable", "$.authority")


def recover_ledger(
    value: Any,
    *,
    trusted_minimum_sequence: int,
    trusted_head_sha256: str,
) -> dict[str, Any]:
    """Validate state against an exact caller-held rollback anchor."""

    if type(trusted_minimum_sequence) is not int or trusted_minimum_sequence < 0:
        raise EffectAuthorityError("ledger_anchor_sequence_invalid", "$.trusted_minimum_sequence")
    _sha(trusted_head_sha256, "$.trusted_head_sha256")
    ledger = validate_ledger(value)
    if len(ledger["events"]) < trusted_minimum_sequence:
        raise EffectAuthorityError("ledger_rollback_detected", "$.ledger.events")
    if ledger["head_sha256"] != trusted_head_sha256:
        raise EffectAuthorityError("ledger_anchor_head_mismatch", "$.ledger.head_sha256")
    return ledger


class EffectAuthorityFactSource:
    """Remain unavailable until T066 provides a separately accepted trust root."""

    __slots__ = ("_state", "_context")

    def __init__(self, state: Any | None, context: Mapping[str, Any] | None) -> None:
        self._state = deepcopy(state)
        self._context = deepcopy(context)

    def read_fact(self, operation: str, exact_identity: Any, dependency_receipts: Mapping[str, str], now: datetime):
        del exact_identity, dependency_receipts, now
        if operation != "verify_effect_authority":
            raise EffectAuthorityError("canonical_operation_invalid", "$.operation")
        return UnavailableFact(
            operation,
            "canonical_authority_trust_anchor_not_implemented",
            AUTHORITY_SOURCE_ID,
        )


class RegisteredActionObservationSource:
    """T064 has no executor or observation store and cannot emit positive facts."""

    __slots__ = ()

    def read_fact(self, operation: str, exact_identity: Any, dependency_receipts: Mapping[str, str], now: datetime) -> UnavailableFact:
        del exact_identity, dependency_receipts, now
        if operation != "invoke_registered_action":
            raise EffectAuthorityError("canonical_operation_invalid", "$.operation")
        return UnavailableFact(operation, "canonical_action_executor_not_implemented", ACTION_SOURCE_ID)
