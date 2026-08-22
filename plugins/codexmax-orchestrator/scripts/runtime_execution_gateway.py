#!/usr/bin/env python3
"""RuntimeExecutionGateway v1 transitions and single effect authority.

The legacy helpers consume accepted scheduler, broker, and observation
receipts.  The effect-kernel helpers at the end of this module are the only
source-local place allowed to invoke a registered action.  Callers own
persistence and must supply the whole sealed state on every transition.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Callable

import package_host_capability_adapter as package_host


SCHEMA_VERSION = 1
ARTIFACT_TYPE = "RuntimeExecutionGatewayState"
ZERO_SHA256 = "sha256:" + "0" * 64
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")

BINDING_FIELDS = (
    "assignment_id",
    "authority_sha256",
    "route_sha256",
    "policy_sha256",
    "source_sha256",
    "lease_id",
    "fencing_token",
)
TERMINAL_OUTCOMES = {
    "cancelled",
    "completed",
    "failed",
    "unreconciled",
}
EVIDENCE_EVENT_TYPES = {
    "launch_observed",
    "run_started",
    "effect_observed",
    "receipt_observed",
    "cancel_observed",
}

EFFECT_REQUEST_TYPE = "effect_kernel_request_v1"
EFFECT_RECEIPT_TYPE = "effect_kernel_receipt_v1"
EFFECT_STATE_TYPE = "effect_kernel_state_v2"
LEGACY_EFFECT_STATE_TYPE = "effect_kernel_state_v1"
RECOVERY_PROVENANCE_FIELDS = {"grant_id", "grant_sha256", "issuer_id", "predecessor_run_id", "predecessor_effect_request_sha256", "predecessor_effect_receipt_sha256", "reconciliation_receipt_sha256", "expected_cas", "reserved_authority_id"}
_RECOVERY_PACKAGE_TOKEN = object()
_RECOVERY_REPLAY_TOKEN = object()
ACTION_RECEIPT_TYPE = "effect_kernel_action_receipt_v1"
EFFECT_OPERATIONS = {"run", "cancel", "recover"}
EFFECT_REQUEST_FIELDS = {
    "schema_version", "artifact_type", "request_id", "idempotency_key",
    "operation", "workspace_id", "goal_id", "task_id", "actor",
    "authority_receipt", "source_bundle", "thread_snapshot",
    "preset_snapshot", "route_snapshot", "adapter_snapshot",
    "policy_snapshot", "lease", "run", "cas", "input",
    "request_sha256", "created_at",
}
EFFECT_RECEIPT_FIELDS = {
    "schema_version", "artifact_type", "request_id", "request_sha256",
    "operation", "disposition", "run_id", "pre_state", "post_state",
    "state_version_before", "state_version_after", "action_receipt",
    "route_requested", "route_observed", "preset_snapshot", "lease",
    "event_ids", "proof_boundary", "unknowns", "receipt_sha256",
}
ACTION_RECEIPT_FIELDS = {
    "schema_version", "artifact_type", "action_receipt_id", "action_id",
    "effect_id", "operation", "outcome", "requested_at", "observed_at",
    "host_receipt_id", "observed_identity", "request_sha256",
    "output_sha256", "reconciled_outcome", "successor_run_id",
    "receipt_sha256",
}
AUTHORITY_RECEIPT_FIELDS = {
    "schema_version", "artifact_type", "authority_id", "issuer_id", "actor",
    "workspace_id", "goal_id", "task_id", "source_sha256",
    "candidate_sha256", "thread_id", "thread_generation", "operation",
    "request_intent_sha256", "issued_at", "expires_at", "receipt_sha256",
}
FORBIDDEN_INPUT_KEYS = {
    "url", "uri", "argv", "executable", "module", "environment", "env",
    "credential", "credentials", "token", "secret", "transport", "provider",
}
def _package_authority_verifier(authority: dict[str, Any], context: dict[str, Any]) -> bool:
    return package_host.verify_effect_authority(authority, context)


# Immutable production capabilities resolve only through the package adapter.
_PACKAGE_ACTION_REGISTRY = MappingProxyType({})
_PACKAGE_AUTHORITY_VERIFIER = _package_authority_verifier


class GatewayError(ValueError):
    """Fail-closed error with a stable machine-readable code."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _mapping(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GatewayError(code)
    return value


def _strict(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    row = _mapping(value, code)
    if set(row) != keys:
        raise GatewayError(code)
    return row


def _identifier(value: Any, code: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise GatewayError(code)
    return value


def _digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise GatewayError(code)
    return value


def _positive_int(value: Any, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise GatewayError(code)
    return value


def _timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GatewayError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GatewayError(code) from exc
    if parsed.tzinfo is None:
        raise GatewayError(code)
    return parsed.astimezone(timezone.utc)


def _receipt_digest(receipt: dict[str, Any]) -> str:
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    return digest(body)


def new_state() -> dict[str, Any]:
    state: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "runs": {},
        "idempotency_index": {},
        "state_sha256": "",
    }
    _seal(state)
    return state


def _seal(state: dict[str, Any]) -> None:
    state["state_sha256"] = digest(
        {key: value for key, value in state.items() if key != "state_sha256"}
    )


def _validate_bindings(value: Any, code: str = "binding_shape_invalid") -> dict[str, Any]:
    row = _strict(value, set(BINDING_FIELDS), code)
    _identifier(row["assignment_id"], code)
    for field in ("authority_sha256", "route_sha256", "policy_sha256", "source_sha256"):
        _digest(row[field], code)
    _identifier(row["lease_id"], code)
    _positive_int(row["fencing_token"], code)
    return row


def _validate_scheduler_receipt(value: Any, now: str) -> dict[str, Any]:
    keys = {
        "schema_version", "artifact_type", "status", *BINDING_FIELDS,
        "issued_at", "expires_at", "provider_call_started",
        "capacity_allocated", "accepted", "receipt_sha256",
    }
    row = _strict(value, keys, "scheduler_receipt_shape_invalid")
    if (
        row["schema_version"] != 1
        or row["artifact_type"] != "RuntimeSchedulerAdmissionReceipt"
        or row["status"] != "admitted"
        or row["accepted"] is not True
        or row["provider_call_started"] is not False
        or row["capacity_allocated"] is not True
    ):
        raise GatewayError("scheduler_receipt_not_accepted")
    _validate_bindings({field: row[field] for field in BINDING_FIELDS})
    issued = _timestamp(row["issued_at"], "scheduler_receipt_time_invalid")
    expires = _timestamp(row["expires_at"], "scheduler_receipt_time_invalid")
    instant = _timestamp(now, "now_invalid")
    if issued > instant or expires <= instant or expires <= issued:
        raise GatewayError("scheduler_receipt_stale")
    if row["receipt_sha256"] != _receipt_digest(row):
        raise GatewayError("scheduler_receipt_digest_mismatch")
    return row


def _validate_broker_receipt(value: Any, now: str) -> dict[str, Any]:
    keys = {
        "schema_version", "artifact_type", "status", *BINDING_FIELDS,
        "issued_at", "expires_at", "capacity_authority",
        "recalled", "accepted", "receipt_sha256",
    }
    row = _strict(value, keys, "broker_receipt_shape_invalid")
    if (
        row["schema_version"] != 1
        or row["artifact_type"] != "RuntimeBrokerLeaseReceipt"
        or row["status"] != "active"
        or row["accepted"] is not True
        or row["capacity_authority"] != "dispatch_scheduler_v1"
    ):
        raise GatewayError("broker_receipt_not_accepted")
    if row["recalled"] is True:
        raise GatewayError("route_recalled")
    if row["recalled"] is not False:
        raise GatewayError("broker_receipt_shape_invalid")
    _validate_bindings({field: row[field] for field in BINDING_FIELDS})
    issued = _timestamp(row["issued_at"], "broker_receipt_time_invalid")
    expires = _timestamp(row["expires_at"], "broker_receipt_time_invalid")
    instant = _timestamp(now, "now_invalid")
    if issued > instant or expires <= instant or expires <= issued:
        raise GatewayError("broker_receipt_stale")
    if row["receipt_sha256"] != _receipt_digest(row):
        raise GatewayError("broker_receipt_digest_mismatch")
    return row


def _event_payload(event: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in event.items() if key != "event_sha256"}


def _completion_receipt(run: dict[str, Any]) -> tuple[str, str] | None:
    completions = [event for event in run["events"] if event["event_type"] == "run_completed"]
    if run["terminal_outcome"] != "completed":
        if completions:
            raise GatewayError("completion_state_mismatch")
        return None
    if len(completions) != 1:
        raise GatewayError("completion_state_mismatch")
    payload = _strict(completions[0]["payload"], {
        "operation_id", "receipt_id", "receipt_sha256", "terminal_outcome",
    }, "completion_payload_invalid")
    _identifier(payload["operation_id"], "operation_id_invalid")
    receipt_id = _identifier(payload["receipt_id"], "receipt_id_invalid")
    receipt_sha256 = _digest(payload["receipt_sha256"], "receipt_digest_invalid")
    if payload["terminal_outcome"] != "completed":
        raise GatewayError("completion_state_mismatch")
    matching_observations = [
        event for event in run["events"]
        if event["event_type"] == "receipt_observed"
        and event["payload"].get("receipt_id") == receipt_id
        and event["payload"].get("receipt_sha256") == receipt_sha256
    ]
    if len(matching_observations) != 1:
        raise GatewayError("completion_receipt_observation_mismatch")
    return receipt_id, receipt_sha256


def _verify_run(run: Any) -> dict[str, Any]:
    keys = {
        "run_id", "idempotency_key", "create_sha256", "bindings",
        "scheduler_receipt_sha256", "broker_receipt_sha256", "created_at",
        "predecessor_run_id", "successor_run_id", "lifecycle", "terminal_outcome",
        "recall_status", "events",
    }
    row = _strict(run, keys, "run_shape_invalid")
    _identifier(row["run_id"], "run_id_invalid")
    _identifier(row["idempotency_key"], "idempotency_key_invalid")
    _digest(row["create_sha256"], "create_digest_invalid")
    _validate_bindings(row["bindings"])
    _digest(row["scheduler_receipt_sha256"], "scheduler_receipt_digest_invalid")
    _digest(row["broker_receipt_sha256"], "broker_receipt_digest_invalid")
    _timestamp(row["created_at"], "run_created_at_invalid")
    for field in ("predecessor_run_id", "successor_run_id"):
        if row[field] is not None:
            _identifier(row[field], f"{field}_invalid")
    if row["lifecycle"] not in {
        "created", "launching", "running", "cancel_requested", "recalled",
        "execution_unknown", "reconciling", "terminal",
    }:
        raise GatewayError("lifecycle_invalid")
    if row["terminal_outcome"] is not None and row["terminal_outcome"] not in TERMINAL_OUTCOMES:
        raise GatewayError("terminal_outcome_invalid")
    if (row["lifecycle"] == "terminal") != (row["terminal_outcome"] is not None):
        raise GatewayError("terminal_state_mismatch")
    if row["recall_status"] not in {"active", "recalled"}:
        raise GatewayError("recall_status_invalid")
    events = row["events"]
    if not isinstance(events, list) or not events:
        raise GatewayError("events_invalid")
    previous = ZERO_SHA256
    identifiers: set[str] = set()
    for sequence, event in enumerate(events, start=1):
        event = _strict(event, {
            "schema_version", "event_id", "event_type", "sequence", "at",
            "bindings", "payload", "previous_event_sha256", "event_sha256",
        }, "event_shape_invalid")
        if event["schema_version"] != 1 or event["sequence"] != sequence:
            raise GatewayError("event_sequence_mismatch")
        event_id = _identifier(event["event_id"], "event_id_invalid")
        if event_id in identifiers:
            raise GatewayError("event_replay_collision")
        identifiers.add(event_id)
        _timestamp(event["at"], "event_time_invalid")
        if event["bindings"] != row["bindings"]:
            raise GatewayError("event_binding_mismatch")
        if not isinstance(event["payload"], dict):
            raise GatewayError("event_payload_invalid")
        if event["previous_event_sha256"] != previous:
            raise GatewayError("event_chain_mismatch")
        if event["event_sha256"] != digest(_event_payload(event)):
            raise GatewayError("event_digest_mismatch")
        previous = event["event_sha256"]
    _completion_receipt(row)
    cancel_observations = [event for event in row["events"] if event["event_type"] == "cancel_observed"]
    if row["terminal_outcome"] == "cancelled":
        if len(cancel_observations) != 1:
            raise GatewayError("cancel_observation_missing")
    elif cancel_observations:
        raise GatewayError("cancel_state_mismatch")
    return row


def verify_state(value: Any) -> dict[str, Any]:
    state = _strict(value, {
        "schema_version", "artifact_type", "runs", "idempotency_index", "state_sha256",
    }, "state_shape_invalid")
    if state["schema_version"] != 1 or state["artifact_type"] != ARTIFACT_TYPE:
        raise GatewayError("state_version_invalid")
    if state["state_sha256"] != digest({key: val for key, val in state.items() if key != "state_sha256"}):
        raise GatewayError("state_digest_mismatch")
    runs = _mapping(state["runs"], "runs_invalid")
    index = _mapping(state["idempotency_index"], "idempotency_index_invalid")
    leases: set[tuple[str, int]] = set()
    event_ids: set[str] = set()
    launch_ids: set[str] = set()
    receipt_ids: set[str] = set()
    receipt_digests: set[str] = set()
    completion_receipt_ids: set[str] = set()
    completion_receipt_digests: set[str] = set()
    effect_ids: set[str] = set()
    for run_id, run in runs.items():
        if run_id != run.get("run_id"):
            raise GatewayError("run_key_mismatch")
        _verify_run(run)
        lease = (run["bindings"]["lease_id"], run["bindings"]["fencing_token"])
        if lease in leases:
            raise GatewayError("lease_replay_collision")
        leases.add(lease)
        for event in run["events"]:
            if event["event_id"] in event_ids:
                raise GatewayError("event_replay_collision")
            event_ids.add(event["event_id"])
            payload = event["payload"]
            identity_field = {
                "launch_observed": "launch_id",
                "receipt_observed": "receipt_id",
                "cancel_observed": "receipt_id",
                "effect_observed": "effect_id",
            }.get(event["event_type"])
            if identity_field:
                identity = _identifier(payload.get(identity_field), f"{identity_field}_invalid")
                seen = {
                    "launch_id": launch_ids,
                    "receipt_id": receipt_ids,
                    "effect_id": effect_ids,
                }[identity_field]
                if identity in seen:
                    raise GatewayError(f"{identity_field}_replay_collision")
                seen.add(identity)
                if identity_field == "receipt_id":
                    receipt_sha256 = _digest(payload.get("receipt_sha256"), "receipt_digest_invalid")
                    if event["event_type"] == "receipt_observed" and payload.get("receipt_accepted") is not True:
                        raise GatewayError("receipt_observation_invalid")
                    if event["event_type"] == "cancel_observed" and payload.get("cancelled") is not True:
                        raise GatewayError("receipt_observation_invalid")
                    if receipt_sha256 in receipt_digests:
                        raise GatewayError("receipt_digest_replay_collision")
                    receipt_digests.add(receipt_sha256)
        completion_receipt = _completion_receipt(run)
        if completion_receipt is not None:
            receipt_id, receipt_sha256 = completion_receipt
            if receipt_id in completion_receipt_ids or receipt_sha256 in completion_receipt_digests:
                raise GatewayError("completion_receipt_replay_collision")
            completion_receipt_ids.add(receipt_id)
            completion_receipt_digests.add(receipt_sha256)
    for key, entry in index.items():
        _identifier(key, "idempotency_key_invalid")
        entry = _strict(entry, {"run_id", "create_sha256"}, "idempotency_index_invalid")
        if entry["run_id"] not in runs or runs[entry["run_id"]]["create_sha256"] != entry["create_sha256"]:
            raise GatewayError("idempotency_index_mismatch")
    return state


def _append(run: dict[str, Any], event_id: str, event_type: str, at: str, payload: dict[str, Any]) -> dict[str, Any]:
    _identifier(event_id, "event_id_invalid")
    _timestamp(at, "event_time_invalid")
    for existing in run["events"]:
        if existing["event_id"] == event_id:
            candidate = {
                "schema_version": 1,
                "event_id": event_id,
                "event_type": event_type,
                "sequence": existing["sequence"],
                "at": at,
                "bindings": copy.deepcopy(run["bindings"]),
                "payload": copy.deepcopy(payload),
                "previous_event_sha256": existing["previous_event_sha256"],
            }
            if existing["event_sha256"] == digest(candidate):
                return existing
            raise GatewayError("event_replay_collision")
    event = {
        "schema_version": 1,
        "event_id": event_id,
        "event_type": event_type,
        "sequence": len(run["events"]) + 1,
        "at": at,
        "bindings": copy.deepcopy(run["bindings"]),
        "payload": copy.deepcopy(payload),
        "previous_event_sha256": run["events"][-1]["event_sha256"] if run["events"] else ZERO_SHA256,
    }
    event["event_sha256"] = digest(event)
    run["events"].append(event)
    return event


def _validated_request(value: Any) -> dict[str, Any]:
    keys = {"run_id", "idempotency_key", "bindings", "predecessor_run_id"}
    row = _strict(value, keys, "create_request_shape_invalid")
    _identifier(row["run_id"], "run_id_invalid")
    _identifier(row["idempotency_key"], "idempotency_key_invalid")
    _validate_bindings(row["bindings"])
    if row["predecessor_run_id"] is not None:
        _identifier(row["predecessor_run_id"], "predecessor_run_id_invalid")
        if row["predecessor_run_id"] == row["run_id"]:
            raise GatewayError("recovery_cycle")
    return row


def create_run(
    state_value: Any,
    request_value: Any,
    scheduler_receipt_value: Any,
    broker_receipt_value: Any,
    *,
    now: str,
) -> dict[str, Any]:
    """Create or idempotently read one bound run without causing execution."""

    state = copy.deepcopy(verify_state(state_value))
    request = _validated_request(request_value)
    scheduler = _validate_scheduler_receipt(scheduler_receipt_value, now)
    broker = _validate_broker_receipt(broker_receipt_value, now)
    bindings = request["bindings"]
    for receipt, name in ((scheduler, "scheduler"), (broker, "broker")):
        if any(receipt[field] != bindings[field] for field in BINDING_FIELDS):
            raise GatewayError(f"{name}_binding_mismatch")
    if any(scheduler[field] != broker[field] for field in BINDING_FIELDS):
        raise GatewayError("receipt_binding_mismatch")
    create_sha256 = digest({
        "request": request,
        "scheduler_receipt_sha256": scheduler["receipt_sha256"],
        "broker_receipt_sha256": broker["receipt_sha256"],
    })
    existing_index = state["idempotency_index"].get(request["idempotency_key"])
    if existing_index is not None:
        if existing_index["create_sha256"] != create_sha256:
            raise GatewayError("idempotency_collision")
        return {"state": state, "run": copy.deepcopy(state["runs"][existing_index["run_id"]]), "replayed": True}
    if request["run_id"] in state["runs"]:
        raise GatewayError("run_id_collision")
    for run in state["runs"].values():
        if (
            run["bindings"]["lease_id"] == bindings["lease_id"]
            or (
                run["scheduler_receipt_sha256"] == scheduler["receipt_sha256"]
                or run["broker_receipt_sha256"] == broker["receipt_sha256"]
            )
        ):
            raise GatewayError("lease_or_receipt_replay")
    run = {
        "run_id": request["run_id"],
        "idempotency_key": request["idempotency_key"],
        "create_sha256": create_sha256,
        "bindings": copy.deepcopy(bindings),
        "scheduler_receipt_sha256": scheduler["receipt_sha256"],
        "broker_receipt_sha256": broker["receipt_sha256"],
        "created_at": now,
        "predecessor_run_id": request["predecessor_run_id"],
        "successor_run_id": None,
        "lifecycle": "created",
        "terminal_outcome": None,
        "recall_status": "active",
        "events": [],
    }
    _append(run, f"{request['run_id']}:created", "run_created", now, {
        "create_sha256": create_sha256,
        "scheduler_receipt_sha256": scheduler["receipt_sha256"],
        "broker_receipt_sha256": broker["receipt_sha256"],
        "execution_started": False,
        "capacity_allocated_by_gateway": False,
        "ledger_written_by_gateway": False,
    })
    state["runs"][run["run_id"]] = run
    state["idempotency_index"][run["idempotency_key"]] = {
        "run_id": run["run_id"], "create_sha256": create_sha256,
    }
    _seal(state)
    return {"state": state, "run": copy.deepcopy(run), "replayed": False}


def read_run(state_value: Any, run_id: str) -> dict[str, Any]:
    state = verify_state(state_value)
    _identifier(run_id, "run_id_invalid")
    if run_id not in state["runs"]:
        raise GatewayError("run_not_found")
    return copy.deepcopy(state["runs"][run_id])


def append_evidence_event(state_value: Any, run_id: str, event_value: Any) -> dict[str, Any]:
    """Record trusted observations; this function never performs the observation."""

    state = copy.deepcopy(verify_state(state_value))
    run = state["runs"].get(run_id)
    if run is None:
        raise GatewayError("run_not_found")
    event = _strict(event_value, {"event_id", "event_type", "at", "bindings", "payload"}, "event_input_shape_invalid")
    if event["event_type"] not in EVIDENCE_EVENT_TYPES:
        raise GatewayError("event_type_not_recordable")
    if event["bindings"] != run["bindings"]:
        raise GatewayError("event_binding_mismatch")
    payload = _mapping(event["payload"], "event_payload_invalid")
    if any(existing["event_id"] == event["event_id"] for existing in run["events"]):
        result = _append(run, event["event_id"], event["event_type"], event["at"], payload)
        return {"state": state, "event": copy.deepcopy(result), "replayed": True}
    if run["recall_status"] == "recalled":
        raise GatewayError("route_recalled")
    if run["lifecycle"] in {"execution_unknown", "reconciling", "terminal"}:
        raise GatewayError("run_not_recordable")
    if run["lifecycle"] == "cancel_requested" and event["event_type"] != "cancel_observed":
        raise GatewayError("run_not_recordable")
    if event["event_type"] == "launch_observed":
        _strict(payload, {"launch_id", "launched", "provider_effect_caused_by_gateway"}, "launch_payload_invalid")
        _identifier(payload["launch_id"], "launch_id_invalid")
        if payload["launched"] is not True or payload["provider_effect_caused_by_gateway"] is not False:
            raise GatewayError("launch_observation_invalid")
        if run["lifecycle"] != "created":
            raise GatewayError("launch_sequence_invalid")
        run["lifecycle"] = "launching"
    elif event["event_type"] == "run_started":
        _strict(payload, {"started", "execution_fence"}, "run_started_payload_invalid")
        if payload["started"] is not True or payload["execution_fence"] != run["bindings"]["fencing_token"]:
            raise GatewayError("execution_fence_mismatch")
        if run["lifecycle"] != "launching":
            raise GatewayError("run_started_sequence_invalid")
        run["lifecycle"] = "running"
    elif event["event_type"] == "effect_observed":
        _strict(payload, {"effect_id", "effect_sha256", "effect_caused_by_gateway"}, "effect_payload_invalid")
        _identifier(payload["effect_id"], "effect_id_invalid")
        _digest(payload["effect_sha256"], "effect_digest_invalid")
        if payload["effect_caused_by_gateway"] is not False or run["lifecycle"] != "running":
            raise GatewayError("effect_observation_invalid")
    elif event["event_type"] == "receipt_observed":
        _strict(payload, {"receipt_id", "receipt_sha256", "receipt_accepted"}, "receipt_payload_invalid")
        _identifier(payload["receipt_id"], "receipt_id_invalid")
        _digest(payload["receipt_sha256"], "receipt_digest_invalid")
        if payload["receipt_accepted"] is not True or run["lifecycle"] not in {"launching", "running"}:
            raise GatewayError("receipt_observation_invalid")
    else:
        _strict(payload, {"operation_id", "receipt_id", "receipt_sha256", "cancelled"}, "cancel_payload_invalid")
        _identifier(payload["operation_id"], "operation_id_invalid")
        _identifier(payload["receipt_id"], "receipt_id_invalid")
        _digest(payload["receipt_sha256"], "receipt_digest_invalid")
        if payload["cancelled"] is not True or run["lifecycle"] != "cancel_requested":
            raise GatewayError("cancel_observation_invalid")
        requested = [
            candidate for candidate in run["events"]
            if candidate["event_type"] == "cancel_requested"
            and candidate["payload"].get("operation_id") == payload["operation_id"]
        ]
        if len(requested) != 1:
            raise GatewayError("cancel_observation_invalid")
    result = _append(run, event["event_id"], event["event_type"], event["at"], payload)
    if event["event_type"] == "cancel_observed":
        run["lifecycle"] = "terminal"
        run["terminal_outcome"] = "cancelled"
    _seal(state)
    verify_state(state)
    return {"state": state, "event": copy.deepcopy(result), "replayed": False}


def cancel_run(state_value: Any, run_id: str, *, operation_id: str, at: str, bindings: Any) -> dict[str, Any]:
    state = copy.deepcopy(verify_state(state_value))
    run = state["runs"].get(run_id)
    if run is None:
        raise GatewayError("run_not_found")
    if bindings != run["bindings"]:
        raise GatewayError("cancel_binding_mismatch")
    _identifier(operation_id, "operation_id_invalid")
    if run["terminal_outcome"] == "cancelled":
        if any(event["payload"].get("operation_id") == operation_id for event in run["events"]):
            return {"state": state, "run": copy.deepcopy(run), "replayed": True}
        raise GatewayError("run_already_terminal")
    if run["lifecycle"] in {"execution_unknown", "reconciling", "terminal"}:
        raise GatewayError("cancel_requires_reconciliation")
    _append(run, f"{operation_id}:requested", "cancel_requested", at, {
        "operation_id": operation_id, "effects_reversed": False, "history_rewritten": False,
    })
    run["lifecycle"] = "cancel_requested"
    _seal(state)
    return {"state": state, "run": copy.deepcopy(run), "replayed": False}


def mark_execution_unknown(state_value: Any, run_id: str, *, operation_id: str, at: str, bindings: Any, reason: str) -> dict[str, Any]:
    state = copy.deepcopy(verify_state(state_value))
    run = state["runs"].get(run_id)
    if run is None:
        raise GatewayError("run_not_found")
    if bindings != run["bindings"]:
        raise GatewayError("execution_unknown_binding_mismatch")
    _identifier(operation_id, "operation_id_invalid")
    _identifier(reason, "execution_unknown_reason_invalid")
    if run["lifecycle"] == "execution_unknown":
        if any(event["payload"].get("operation_id") == operation_id for event in run["events"]):
            return {"state": state, "run": copy.deepcopy(run), "replayed": True}
        raise GatewayError("execution_unknown_collision")
    if run["lifecycle"] not in {"launching", "running"}:
        raise GatewayError("execution_unknown_sequence_invalid")
    _append(run, f"{operation_id}:unknown", "execution_unknown", at, {
        "operation_id": operation_id, "reason": reason, "success_claimed": False,
    })
    run["lifecycle"] = "execution_unknown"
    _seal(state)
    return {"state": state, "run": copy.deepcopy(run), "replayed": False}


def recall_run(state_value: Any, run_id: str, *, recall_id: str, at: str, bindings: Any) -> dict[str, Any]:
    state = copy.deepcopy(verify_state(state_value))
    run = state["runs"].get(run_id)
    if run is None:
        raise GatewayError("run_not_found")
    if bindings != run["bindings"]:
        raise GatewayError("recall_binding_mismatch")
    _identifier(recall_id, "recall_id_invalid")
    if run["recall_status"] == "recalled":
        if any(event["payload"].get("recall_id") == recall_id for event in run["events"]):
            return {"state": state, "run": copy.deepcopy(run), "replayed": True}
        raise GatewayError("recall_collision")
    if run["lifecycle"] == "terminal":
        raise GatewayError("run_already_terminal")
    _append(run, f"{recall_id}:recalled", "run_recalled", at, {
        "recall_id": recall_id, "blocks_new_events": True, "history_deleted": False,
    })
    run["recall_status"] = "recalled"
    run["lifecycle"] = "recalled"
    _seal(state)
    return {"state": state, "run": copy.deepcopy(run), "replayed": False}


def reconcile_run(state_value: Any, run_id: str, *, operation_id: str, at: str, bindings: Any, outcome: str) -> dict[str, Any]:
    state = copy.deepcopy(verify_state(state_value))
    run = state["runs"].get(run_id)
    if run is None:
        raise GatewayError("run_not_found")
    if bindings != run["bindings"]:
        raise GatewayError("reconciliation_binding_mismatch")
    _identifier(operation_id, "operation_id_invalid")
    if outcome not in {"failed", "unreconciled"}:
        if run["lifecycle"] in {"execution_unknown", "recalled", "reconciling"} and outcome == "completed":
            raise GatewayError("execution_unknown_cannot_succeed")
        raise GatewayError("reconciliation_outcome_invalid")
    if run["lifecycle"] == "terminal":
        if run["terminal_outcome"] == outcome and any(event["payload"].get("operation_id") == operation_id for event in run["events"]):
            return {"state": state, "run": copy.deepcopy(run), "replayed": True}
        raise GatewayError("run_already_terminal")
    if run["lifecycle"] not in {"execution_unknown", "recalled", "cancel_requested"}:
        raise GatewayError("reconciliation_not_required")
    _append(run, f"{operation_id}:reconciling", "run_reconciling", at, {
        "operation_id": operation_id, "requested_outcome": outcome, "success_claimed": False,
    })
    run["lifecycle"] = "reconciling"
    _append(run, f"{operation_id}:terminal", f"run_{outcome}", at, {
        "operation_id": operation_id, "terminal_outcome": outcome, "success_claimed": False,
    })
    run["lifecycle"] = "terminal"
    run["terminal_outcome"] = outcome
    _seal(state)
    return {"state": state, "run": copy.deepcopy(run), "replayed": False}


def complete_run(state_value: Any, run_id: str, *, operation_id: str, at: str, bindings: Any, receipt_id: str, receipt_sha256: str) -> dict[str, Any]:
    state = copy.deepcopy(verify_state(state_value))
    run = state["runs"].get(run_id)
    if run is None:
        raise GatewayError("run_not_found")
    if bindings != run["bindings"]:
        raise GatewayError("completion_binding_mismatch")
    _identifier(operation_id, "operation_id_invalid")
    _identifier(receipt_id, "receipt_id_invalid")
    _digest(receipt_sha256, "receipt_digest_invalid")
    if run["terminal_outcome"] == "completed":
        if any(event["payload"].get("operation_id") == operation_id for event in run["events"]):
            return {"state": state, "run": copy.deepcopy(run), "replayed": True}
        raise GatewayError("run_already_terminal")
    if run["recall_status"] == "recalled" or run["lifecycle"] in {"execution_unknown", "reconciling", "cancel_requested", "terminal"}:
        raise GatewayError("run_cannot_complete")
    if run["lifecycle"] != "running":
        raise GatewayError("completion_sequence_invalid")
    matching_observations = [
        event for event in run["events"]
        if event["event_type"] == "receipt_observed"
        and event["payload"].get("receipt_id") == receipt_id
        and event["payload"].get("receipt_sha256") == receipt_sha256
    ]
    if len(matching_observations) != 1:
        raise GatewayError("completion_receipt_observation_mismatch")
    for existing_run in state["runs"].values():
        for event in existing_run["events"]:
            if event["event_type"] != "run_completed":
                continue
            payload = event["payload"]
            if payload.get("receipt_id") == receipt_id or payload.get("receipt_sha256") == receipt_sha256:
                raise GatewayError("completion_receipt_replay_collision")
    _append(run, f"{operation_id}:completed", "run_completed", at, {
        "operation_id": operation_id,
        "receipt_id": receipt_id,
        "receipt_sha256": receipt_sha256,
        "terminal_outcome": "completed",
    })
    run["lifecycle"] = "terminal"
    run["terminal_outcome"] = "completed"
    _seal(state)
    return {"state": state, "run": copy.deepcopy(run), "replayed": False}


def recover_run(
    state_value: Any,
    predecessor_run_id: str,
    request_value: Any,
    scheduler_receipt_value: Any,
    broker_receipt_value: Any,
    *,
    operation_id: str,
    now: str,
) -> dict[str, Any]:
    """Create a fresh fenced successor only for a known no-launch terminal run."""

    state = copy.deepcopy(verify_state(state_value))
    predecessor = state["runs"].get(predecessor_run_id)
    if predecessor is None:
        raise GatewayError("predecessor_not_found")
    _identifier(operation_id, "operation_id_invalid")
    request = _validated_request(request_value)
    if request["predecessor_run_id"] != predecessor_run_id:
        raise GatewayError("recovery_predecessor_mismatch")
    if predecessor["recall_status"] == "recalled":
        raise GatewayError("recalled_recovery_denied")
    if request["bindings"]["fencing_token"] <= predecessor["bindings"]["fencing_token"]:
        raise GatewayError("recovery_fence_not_increased")
    if request["bindings"]["lease_id"] == predecessor["bindings"]["lease_id"]:
        raise GatewayError("recovery_lease_reused")
    if predecessor["successor_run_id"] is not None:
        if predecessor["successor_run_id"] == request["run_id"]:
            replayed = create_run(state, request, scheduler_receipt_value, broker_receipt_value, now=now)
            return {**replayed, "predecessor": copy.deepcopy(predecessor), "replayed": True}
        raise GatewayError("recovery_collision")
    if predecessor["terminal_outcome"] not in {"cancelled", "failed"}:
        if predecessor["lifecycle"] in {"execution_unknown", "reconciling"} or predecessor["terminal_outcome"] == "unreconciled":
            raise GatewayError("unreconciled_recovery_denied")
        raise GatewayError("recovery_not_allowed")
    if any(event["event_type"] in {"launch_observed", "run_started", "effect_observed"} for event in predecessor["events"]):
        raise GatewayError("recovery_effect_uncertain")
    created = create_run(state, request, scheduler_receipt_value, broker_receipt_value, now=now)
    state = created["state"]
    predecessor = state["runs"][predecessor_run_id]
    predecessor["successor_run_id"] = request["run_id"]
    _append(predecessor, f"{operation_id}:recovered", "run_recovered", now, {
        "operation_id": operation_id,
        "successor_run_id": request["run_id"],
        "history_rewritten": False,
        "lease_reused": False,
        "launch_duplicated": False,
        "receipt_duplicated": False,
        "effect_duplicated": False,
    })
    _seal(state)
    verify_state(state)
    return {
        "state": state,
        "run": copy.deepcopy(state["runs"][request["run_id"]]),
        "predecessor": copy.deepcopy(predecessor),
        "replayed": False,
    }


# Single-effect kernel -----------------------------------------------------

def _closed_effect(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    row = _mapping(value, "request_shape_invalid")
    unknown = sorted(set(row) - fields)
    missing = sorted(fields - set(row))
    if unknown:
        raise GatewayError("unknown_field", unknown[0])
    if missing:
        raise GatewayError(code, missing[0])
    return row


def _effect_timestamp(value: Any, code: str) -> datetime:
    parsed = _timestamp(value, code)
    if parsed.microsecond:
        raise GatewayError(code)
    return parsed


def _finite_json(value: Any, path: str = "input", *, forbid_effect_keys: bool = False) -> None:
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        raise GatewayError("request_shape_invalid", path)
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise GatewayError("request_shape_invalid", path)
            if forbid_effect_keys and key.lower() in FORBIDDEN_INPUT_KEYS:
                raise GatewayError("direct_effect_bypass", f"{path}.{key}")
            _finite_json(child, f"{path}.{key}", forbid_effect_keys=forbid_effect_keys)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _finite_json(child, f"{path}[{index}]", forbid_effect_keys=forbid_effect_keys)
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise GatewayError("request_shape_invalid", path)


def _snapshot(value: Any, fields: set[str], stale_code: str) -> dict[str, Any]:
    row = _closed_effect(value, fields, "request_shape_invalid")
    supplied = _digest(row["snapshot_sha256"], "request_shape_invalid")
    body = {key: item for key, item in row.items() if key != "snapshot_sha256"}
    if supplied != digest(body):
        raise GatewayError(stale_code)
    return row


def effect_request_intent_sha256(value: Any) -> str:
    """Digest request semantics without authority or the full-request seal."""

    row = _mapping(value, "request_shape_invalid")
    semantics = {
        key: copy.deepcopy(item)
        for key, item in row.items()
        if key not in {"authority_receipt", "request_sha256"}
    }
    return digest(semantics)


def _validate_effect_request(
    value: Any,
    state: dict[str, Any],
    now: str,
    *,
    skip_cas: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    _finite_json(value)
    row = _closed_effect(copy.deepcopy(value), EFFECT_REQUEST_FIELDS, "request_shape_invalid")
    if row["schema_version"] != 1 or row["artifact_type"] != EFFECT_REQUEST_TYPE:
        raise GatewayError("request_shape_invalid")
    for field in ("request_id", "idempotency_key", "workspace_id", "goal_id", "task_id", "actor"):
        _identifier(row[field], "request_shape_invalid")
    if row["operation"] not in EFFECT_OPERATIONS:
        raise GatewayError("request_shape_invalid", "operation")
    created = _effect_timestamp(row["created_at"], "request_shape_invalid")
    instant = _effect_timestamp(now, "request_shape_invalid")
    if created > instant:
        raise GatewayError("request_shape_invalid", "created_at")
    supplied = _digest(row["request_sha256"], "request_shape_invalid")
    if supplied != digest({key: item for key, item in row.items() if key != "request_sha256"}):
        raise GatewayError("request_shape_invalid", "request_sha256")

    authority = _closed_effect(
        row["authority_receipt"], AUTHORITY_RECEIPT_FIELDS, "authority_missing"
    )
    if authority["schema_version"] != 1 or authority["artifact_type"] != "effect_kernel_authority_receipt_v1":
        raise GatewayError("authority_missing")
    for field in ("authority_id", "issuer_id", "actor", "workspace_id", "goal_id", "task_id", "thread_id"):
        _identifier(authority[field], "authority_missing")
    if any(authority[field] != row[field] for field in ("actor", "workspace_id", "goal_id", "task_id")):
        raise GatewayError("actor_not_authorized")
    if authority["operation"] != row["operation"]:
        raise GatewayError("actor_not_authorized")
    _digest(authority["source_sha256"], "authority_missing")
    _digest(authority["candidate_sha256"], "authority_missing")
    _positive_int(authority["thread_generation"], "authority_missing")
    _digest(authority["request_intent_sha256"], "authority_missing")
    if authority["request_intent_sha256"] != effect_request_intent_sha256(row):
        raise GatewayError("actor_not_authorized")
    issued = _effect_timestamp(authority["issued_at"], "authority_missing")
    expires = _effect_timestamp(authority["expires_at"], "authority_missing")
    if issued > created or expires <= instant or expires <= issued:
        raise GatewayError("authority_missing")
    if authority["receipt_sha256"] != digest({key: item for key, item in authority.items() if key != "receipt_sha256"}):
        raise GatewayError("authority_missing")

    source = _snapshot(row["source_bundle"], {
        "source_id", "source_sha256", "candidate_sha256", "snapshot_sha256",
    }, "source_bundle_stale")
    for field in ("source_id",):
        _identifier(source[field], "source_bundle_stale")
    for field in ("source_sha256", "candidate_sha256"):
        _digest(source[field], "source_bundle_stale")

    thread = _snapshot(row["thread_snapshot"], {
        "thread_id", "generation", "captured_at", "expires_at", "snapshot_sha256",
    }, "thread_snapshot_stale")
    _identifier(thread["thread_id"], "thread_snapshot_stale")
    _positive_int(thread["generation"], "thread_snapshot_stale")
    if (
        authority["source_sha256"] != source["source_sha256"]
        or authority["candidate_sha256"] != source["candidate_sha256"]
        or authority["thread_id"] != thread["thread_id"]
        or authority["thread_generation"] != thread["generation"]
    ):
        raise GatewayError("actor_not_authorized")
    preset = _snapshot(row["preset_snapshot"], {
        "preset_id", "captured_at", "expires_at", "snapshot_sha256",
    }, "preset_snapshot_stale")
    _identifier(preset["preset_id"], "preset_snapshot_stale")
    route = _snapshot(row["route_snapshot"], {
        "route_id", "requested_model", "requested_host", "captured_at",
        "expires_at", "snapshot_sha256",
    }, "route_snapshot_stale")
    for field in ("route_id", "requested_model", "requested_host"):
        _identifier(route[field], "route_snapshot_stale")
    adapter = _snapshot(row["adapter_snapshot"], {
        "adapter_id", "action_id", "tool_id", "transport", "qualification_status",
        "captured_at", "expires_at", "snapshot_sha256",
    }, "adapter_snapshot_stale")
    for field in ("adapter_id", "action_id", "tool_id", "transport"):
        _identifier(adapter[field], "adapter_snapshot_stale")
    if adapter["qualification_status"] != "qualified":
        raise GatewayError("adapter_snapshot_stale")
    policy = _snapshot(row["policy_snapshot"], {
        "policy_id", "active", "captured_at", "expires_at", "snapshot_sha256",
    }, "policy_snapshot_stale")
    _identifier(policy["policy_id"], "policy_snapshot_stale")
    if policy["active"] is not True:
        raise GatewayError("policy_snapshot_stale")
    for snapshot, code in (
        (thread, "thread_snapshot_stale"), (preset, "preset_snapshot_stale"),
        (route, "route_snapshot_stale"), (adapter, "adapter_snapshot_stale"),
        (policy, "policy_snapshot_stale"),
    ):
        captured = _effect_timestamp(snapshot["captured_at"], code)
        expires_at = _effect_timestamp(snapshot["expires_at"], code)
        if captured > created or expires_at <= instant or expires_at <= captured:
            raise GatewayError(code)

    lease = _closed_effect(row["lease"], {
        "lease_id", "fencing_token", "issued_at", "expires_at", "lease_sha256",
    }, "lease_expired")
    _identifier(lease["lease_id"], "lease_expired")
    _positive_int(lease["fencing_token"], "fence_mismatch")
    if lease["lease_sha256"] != digest({key: item for key, item in lease.items() if key != "lease_sha256"}):
        raise GatewayError("fence_mismatch")
    lease_issued = _effect_timestamp(lease["issued_at"], "lease_expired")
    lease_expires = _effect_timestamp(lease["expires_at"], "lease_expired")
    if lease_issued > created or lease_expires <= instant or lease_expires <= lease_issued:
        raise GatewayError("lease_expired")
    run = _closed_effect(row["run"], {"run_id", "predecessor_run_id"}, "request_shape_invalid")
    _identifier(run["run_id"], "request_shape_invalid")
    if run["predecessor_run_id"] is not None:
        _identifier(run["predecessor_run_id"], "request_shape_invalid")
    if (row["operation"] == "recover") != (run["predecessor_run_id"] is not None):
        raise GatewayError("invalid_transition")
    cas = _closed_effect(row["cas"], {"expected_state_version", "expected_thread_generation"}, "cas_mismatch")
    if type(cas["expected_state_version"]) is not int or cas["expected_state_version"] < 0:
        raise GatewayError("cas_mismatch")
    _positive_int(cas["expected_thread_generation"], "cas_mismatch")
    if not skip_cas and (
        cas["expected_state_version"] != state["state_version"]
        or cas["expected_thread_generation"] != thread["generation"]
    ):
        raise GatewayError("cas_mismatch")
    if not skip_cas and state["thread_generation"] not in (0, thread["generation"]):
        raise GatewayError("cas_mismatch")
    effect_input = _closed_effect(row["input"], {"tool_id", "parameters"}, "request_shape_invalid")
    _identifier(effect_input["tool_id"], "request_shape_invalid")
    if effect_input["tool_id"] != adapter["tool_id"] or not isinstance(effect_input["parameters"], dict):
        raise GatewayError("request_shape_invalid", "input")
    _finite_json(effect_input["parameters"], "input.parameters", forbid_effect_keys=True)
    verification_context = {
        "workspace_id": row["workspace_id"],
        "source_sha256": source["source_sha256"],
        "candidate_sha256": source["candidate_sha256"],
        "thread_id": thread["thread_id"],
        "thread_generation": thread["generation"],
        "operation": row["operation"],
        "request_intent_sha256": authority["request_intent_sha256"],
        "request_sha256": row["request_sha256"],
        "expires_at": authority["expires_at"],
    }
    return row, copy.deepcopy(authority), verification_context


def new_effect_state(workspace_id: str) -> dict[str, Any]:
    _identifier(workspace_id, "request_shape_invalid")
    state = {
        "schema_version": 1,
        "artifact_type": EFFECT_STATE_TYPE,
        "workspace_id": workspace_id,
        "state_version": 0,
        "thread_generation": 0,
        "runs": {},
        "idempotency_index": {},
        "receipt_index": {},
        "state_sha256": "",
    }
    _seal_effect_state(state)
    return state


def _seal_effect_state(state: dict[str, Any]) -> None:
    state["state_sha256"] = digest({key: item for key, item in state.items() if key != "state_sha256"})


def _validate_recovery_provenance(value: Any, code: str) -> dict[str, Any]:
    provenance = _closed_effect(value, RECOVERY_PROVENANCE_FIELDS, code)
    for field in ("grant_id", "issuer_id", "predecessor_run_id", "reserved_authority_id"):
        _identifier(provenance[field], code)
    for field in ("grant_sha256", "predecessor_effect_request_sha256", "predecessor_effect_receipt_sha256", "reconciliation_receipt_sha256"):
        _digest(provenance[field], code)
    cas = _closed_effect(
        provenance["expected_cas"],
        {"expected_state_version", "expected_thread_generation"}, code,
    )
    if any(type(cas[field]) is not int or cas[field] < 0 for field in cas):
        raise GatewayError(code)
    return provenance


def verify_effect_state(value: Any) -> dict[str, Any]:
    if isinstance(value, dict) and value.get("artifact_type") == LEGACY_EFFECT_STATE_TYPE:
        raise GatewayError("recovery_authority_unavailable")
    state = _closed_effect(value, {
        "schema_version", "artifact_type", "workspace_id", "state_version",
        "thread_generation", "runs", "idempotency_index", "receipt_index", "state_sha256",
    }, "state_shape_invalid")
    if state["schema_version"] != 1 or state["artifact_type"] != EFFECT_STATE_TYPE:
        raise GatewayError("state_shape_invalid")
    _identifier(state["workspace_id"], "state_shape_invalid")
    for field in ("state_version", "thread_generation"):
        if type(state[field]) is not int or state[field] < 0:
            raise GatewayError("state_shape_invalid")
    for field in ("runs", "idempotency_index", "receipt_index"):
        _mapping(state[field], "state_shape_invalid")
    if state["state_sha256"] != digest({key: item for key, item in state.items() if key != "state_sha256"}):
        raise GatewayError("state_digest_mismatch")
    for key, run in state["runs"].items():
        row = _closed_effect(run, {
            "run_id", "predecessor_run_id", "successor_run_id", "request_sha256",
            "lifecycle", "lease", "thread_generation",
            "route_requested", "route_observed", "preset_snapshot",
            "action_receipt_id", "action_receipt_sha256", "effect_id", "reconciled",
            "recovery_provenance",
        }, "state_shape_invalid")
        if key != row["run_id"]:
            raise GatewayError("state_shape_invalid")
        _identifier(row["run_id"], "state_shape_invalid")
        lease = _closed_effect(row["lease"], {"lease_id", "fencing_token", "issued_at", "expires_at", "lease_sha256"}, "state_shape_invalid")
        _identifier(lease["lease_id"], "state_shape_invalid")
        _positive_int(lease["fencing_token"], "state_shape_invalid")
        _effect_timestamp(lease["issued_at"], "state_shape_invalid")
        if _effect_timestamp(lease["expires_at"], "state_shape_invalid") <= _effect_timestamp(lease["issued_at"], "state_shape_invalid") or lease["lease_sha256"] != digest({key: item for key, item in lease.items() if key != "lease_sha256"}):
            raise GatewayError("state_shape_invalid")
        if row["predecessor_run_id"] is not None:
            _identifier(row["predecessor_run_id"], "state_shape_invalid")
        if row["successor_run_id"] is not None:
            _identifier(row["successor_run_id"], "state_shape_invalid")
        _digest(row["request_sha256"], "state_shape_invalid")
        _positive_int(row["thread_generation"], "state_shape_invalid")
        if row["lifecycle"] not in {"starting", "running", "cancel_requested", "cancelled", "failed", "execution_unknown"}:
            raise GatewayError("state_shape_invalid")
        if not isinstance(row["reconciled"], bool):
            raise GatewayError("state_shape_invalid")
        if row["action_receipt_sha256"] is not None:
            _digest(row["action_receipt_sha256"], "state_shape_invalid")
        for field in ("action_receipt_id", "effect_id"):
            if row[field] is not None:
                _identifier(row[field], "state_shape_invalid")
        provenance = row["recovery_provenance"]
        if row["predecessor_run_id"] is None:
            if provenance is not None:
                raise GatewayError("state_shape_invalid")
        else:
            provenance = _validate_recovery_provenance(provenance, "state_shape_invalid")
            if provenance["predecessor_run_id"] != row["predecessor_run_id"]:
                raise GatewayError("state_shape_invalid")
    for key, value in state["idempotency_index"].items():
        _identifier(key, "state_shape_invalid")
        row = _closed_effect(
            value,
            {"request_sha256", "receipt_sha256", "recovery_grant_id", "recovery_grant_sha256", "recovery_provenance", "recovery_provenance_sha256"},
            "state_shape_invalid",
        )
        _digest(row["request_sha256"], "state_shape_invalid")
        _digest(row["receipt_sha256"], "state_shape_invalid")
        if row["recovery_grant_sha256"] is not None:
            _digest(row["recovery_grant_sha256"], "state_shape_invalid")
        if row["recovery_grant_id"] is not None:
            _identifier(row["recovery_grant_id"], "state_shape_invalid")
        if (row["recovery_grant_id"] is None) != (row["recovery_grant_sha256"] is None):
            raise GatewayError("state_shape_invalid")
        if row["recovery_grant_id"] is None:
            if row["recovery_provenance"] is not None or row["recovery_provenance_sha256"] is not None:
                raise GatewayError("state_shape_invalid")
        else:
            committed = _validate_recovery_provenance(row["recovery_provenance"], "state_shape_invalid")
            _digest(row["recovery_provenance_sha256"], "state_shape_invalid")
            successors = [
                run for run in state["runs"].values()
                if run["request_sha256"] == row["request_sha256"]
                and run["recovery_provenance"] is not None
            ]
            if (
                row["recovery_provenance_sha256"] != digest(committed)
                or committed["grant_id"] != row["recovery_grant_id"]
                or committed["grant_sha256"] != row["recovery_grant_sha256"]
                or len(successors) != 1
                or successors[0]["recovery_provenance"] != committed
            ):
                raise GatewayError("state_shape_invalid")
        if row["receipt_sha256"] not in state["receipt_index"]:
            raise GatewayError("state_shape_invalid")
    for key, value in state["receipt_index"].items():
        _digest(key, "state_shape_invalid")
        receipt = _closed_effect(value, EFFECT_RECEIPT_FIELDS, "state_shape_invalid")
        if receipt["receipt_sha256"] != key or receipt["receipt_sha256"] != digest({field: item for field, item in receipt.items() if field != "receipt_sha256"}):
            raise GatewayError("state_shape_invalid")
    return state


def _validate_action_receipt(value: Any, request: dict[str, Any], now: str) -> dict[str, Any]:
    row = _closed_effect(value, ACTION_RECEIPT_FIELDS, "effect_observation_missing")
    if row["schema_version"] != 1 or row["artifact_type"] != ACTION_RECEIPT_TYPE:
        raise GatewayError("effect_observation_missing")
    for field in ("action_receipt_id", "action_id", "effect_id", "host_receipt_id"):
        _identifier(row[field], "effect_observation_missing")
    if row["action_id"] != request["adapter_snapshot"]["action_id"] or row["operation"] != request["operation"]:
        raise GatewayError("effect_observation_missing")
    if row["request_sha256"] != request["request_sha256"]:
        raise GatewayError("effect_observation_missing")
    _digest(row["output_sha256"], "effect_observation_missing")
    requested = _effect_timestamp(row["requested_at"], "effect_observation_missing")
    observed = _effect_timestamp(row["observed_at"], "effect_observation_missing")
    if requested != _effect_timestamp(request["created_at"], "request_shape_invalid") or observed < requested or observed > _effect_timestamp(now, "request_shape_invalid"):
        raise GatewayError("effect_observation_missing")
    identity = _closed_effect(row["observed_identity"], {"route_id", "model", "host"}, "effect_observation_missing")
    for field in identity:
        if identity[field] != "unknown":
            _identifier(identity[field], "effect_observation_missing")
    allowed = {"run": {"running"}, "cancel": {"cancelled"}, "recover": {"running"}}
    if row["outcome"] not in allowed[request["operation"]]:
        raise GatewayError("effect_observation_missing")
    if request["operation"] == "recover":
        if row["reconciled_outcome"] not in {"failed", "cancelled"} or row["successor_run_id"] != request["run"]["run_id"]:
            raise GatewayError("effect_observation_missing")
    elif row["reconciled_outcome"] is not None or row["successor_run_id"] is not None:
        raise GatewayError("effect_observation_missing")
    if row["receipt_sha256"] != digest({key: item for key, item in row.items() if key != "receipt_sha256"}):
        raise GatewayError("effect_observation_missing")
    return row


def _effect_receipt(
    request: dict[str, Any], *, disposition: str, pre_state: str, post_state: str,
    before: int, after: int, action_receipt: dict[str, Any] | None,
    event_ids: list[str], unknowns: list[str],
) -> dict[str, Any]:
    observed = {"route_id": "unknown", "model": "unknown", "host": "unknown"}
    if action_receipt is not None:
        observed = copy.deepcopy(action_receipt["observed_identity"])
    receipt = {
        "schema_version": 1,
        "artifact_type": EFFECT_RECEIPT_TYPE,
        "request_id": request["request_id"],
        "request_sha256": request["request_sha256"],
        "operation": request["operation"],
        "disposition": disposition,
        "run_id": request["run"]["run_id"],
        "pre_state": pre_state,
        "post_state": post_state,
        "state_version_before": before,
        "state_version_after": after,
        "action_receipt": copy.deepcopy(action_receipt),
        "route_requested": {
            "route_id": request["route_snapshot"]["route_id"],
            "model": request["route_snapshot"]["requested_model"],
            "host": request["route_snapshot"]["requested_host"],
        },
        "route_observed": observed,
        "preset_snapshot": copy.deepcopy(request["preset_snapshot"]),
        "lease": copy.deepcopy(request["lease"]),
        "event_ids": list(event_ids),
        "proof_boundary": "source_local_registered_action",
        "unknowns": list(unknowns),
        "receipt_sha256": "",
    }
    receipt["receipt_sha256"] = digest({key: item for key, item in receipt.items() if key != "receipt_sha256"})
    return receipt


def _authority_preflight_material(
    request_value: Any, *, now: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Return deterministic authority material without accepting capabilities."""
    if not isinstance(request_value, dict):
        raise GatewayError("request_shape_invalid")
    workspace_id = request_value.get("workspace_id")
    state = new_effect_state(workspace_id)
    return _validate_effect_request(
        request_value,
        state,
        now,
        skip_cas=True,
    )


def _verify_package_authority(authority: dict[str, Any], context: dict[str, Any]) -> None:
    """Verify only with the package-owned production authority capability."""

    verifier = _PACKAGE_AUTHORITY_VERIFIER
    if verifier is None or not callable(verifier):
        raise GatewayError("authority_missing")
    try:
        verified = verifier(copy.deepcopy(authority), copy.deepcopy(context))
    except package_host.HostCapabilityError as exc:
        if exc.code in {"production_capability_unavailable", "package_data_not_pinned"}:
            raise GatewayError("authority_missing") from exc
        raise GatewayError("actor_not_authorized") from exc
    except Exception as exc:
        raise GatewayError("actor_not_authorized") from exc
    if verified is not True:
        raise GatewayError("actor_not_authorized")


def preflight_effect_authority(request_value: Any, *, now: str) -> dict[str, Any]:
    """Production preflight using only package-owned authority capability."""

    request, authority, context = _authority_preflight_material(request_value, now=now)
    _verify_package_authority(authority, context)
    return request


def _preflight_recovery_request_shape(request_value: Any) -> dict[str, Any]:
    """PACKAGE INTERNAL: validate sealed Recover bytes before state/replay lookup."""

    if not isinstance(request_value, dict) or request_value.get("operation") != "recover":
        raise GatewayError("request_shape_invalid", "operation")
    request, _, _ = _authority_preflight_material(
        request_value, now=request_value.get("created_at"),
    )
    return request


def _preflight_effect_authority_for_test(
    request_value: Any,
    *,
    now: str,
    authority_verifier: Callable[[dict[str, Any], dict[str, Any]], bool],
) -> dict[str, Any]:
    """TEST ONLY: preflight with an explicitly supplied verifier."""

    request, authority, context = _authority_preflight_material(request_value, now=now)
    if authority_verifier is None or not callable(authority_verifier):
        raise GatewayError("authority_missing")
    try:
        verified = authority_verifier(copy.deepcopy(authority), copy.deepcopy(context))
    except Exception as exc:
        raise GatewayError("actor_not_authorized") from exc
    if verified is not True:
        raise GatewayError("actor_not_authorized")
    return request


def _validate_effect_receipt_artifact(
    value: Any, request: dict[str, Any], *, now: str,
) -> dict[str, Any]:
    """Validate one exact canonical effect receipt without executing an action."""

    row = _closed_effect(copy.deepcopy(value), EFFECT_RECEIPT_FIELDS, "effect_receipt_invalid")
    if row["schema_version"] != 1 or row["artifact_type"] != EFFECT_RECEIPT_TYPE:
        raise GatewayError("effect_receipt_invalid")
    if (
        row["request_id"] != request["request_id"]
        or row["request_sha256"] != request["request_sha256"]
        or row["operation"] != request["operation"]
        or row["run_id"] != request["run"]["run_id"]
        or row["state_version_before"] != request["cas"]["expected_state_version"]
        or row["state_version_after"] != row["state_version_before"] + 1
        or row["preset_snapshot"] != request["preset_snapshot"]
        or row["lease"] != request["lease"]
    ):
        raise GatewayError("effect_receipt_binding_mismatch")
    requested = {
        "route_id": request["route_snapshot"]["route_id"],
        "model": request["route_snapshot"]["requested_model"],
        "host": request["route_snapshot"]["requested_host"],
    }
    if row["route_requested"] != requested:
        raise GatewayError("effect_receipt_binding_mismatch")
    if not isinstance(row["event_ids"], list) or not row["event_ids"] or any(not isinstance(item, str) for item in row["event_ids"]):
        raise GatewayError("effect_receipt_invalid")
    if not isinstance(row["unknowns"], list) or any(not isinstance(item, str) for item in row["unknowns"]):
        raise GatewayError("effect_receipt_invalid")
    if row["proof_boundary"] != "source_local_registered_action":
        raise GatewayError("effect_receipt_invalid")
    action = row["action_receipt"]
    if action is None:
        if row["disposition"] != "execution_unknown" or row["post_state"] != "execution_unknown":
            raise GatewayError("effect_observation_missing")
        if row["route_observed"] != {"route_id": "unknown", "model": "unknown", "host": "unknown"}:
            raise GatewayError("effect_observation_missing")
    else:
        action = _validate_action_receipt(action, request, now)
        if row["disposition"] != "observed" or row["route_observed"] != action["observed_identity"]:
            raise GatewayError("effect_observation_missing")
        expected_state = {"run": "running", "cancel": "cancelled", "recover": "running"}[request["operation"]]
        if row["post_state"] != expected_state:
            raise GatewayError("effect_receipt_invalid")
    if row["receipt_sha256"] != digest({key: item for key, item in row.items() if key != "receipt_sha256"}):
        raise GatewayError("effect_receipt_digest_mismatch")
    return row


def _validate_effect_artifact_set(
    request_value: Any,
    receipt_value: Any,
    *,
    now: str,
    authority_verifier: Callable[[dict[str, Any], dict[str, Any]], bool] | None,
) -> dict[str, Any]:
    if not isinstance(request_value, dict):
        raise GatewayError("request_shape_invalid")
    workspace_id = request_value.get("workspace_id")
    state = new_effect_state(workspace_id)
    cas = request_value.get("cas")
    thread = request_value.get("thread_snapshot")
    if isinstance(cas, dict) and type(cas.get("expected_state_version")) is int and cas["expected_state_version"] >= 0:
        state["state_version"] = cas["expected_state_version"]
    if isinstance(thread, dict) and type(thread.get("generation")) is int and thread["generation"] > 0:
        state["thread_generation"] = thread["generation"]
    _seal_effect_state(state)
    request, authority, context = _validate_effect_request(request_value, state, now)
    if authority_verifier is None or not callable(authority_verifier):
        raise GatewayError("authority_missing")
    try:
        verified = authority_verifier(copy.deepcopy(authority), copy.deepcopy(context))
    except Exception as exc:
        raise GatewayError("actor_not_authorized") from exc
    if verified is not True:
        raise GatewayError("actor_not_authorized")
    receipt = _validate_effect_receipt_artifact(receipt_value, request, now=now)
    return {"request": request, "receipt": receipt, "action_receipt": copy.deepcopy(receipt["action_receipt"])}


def validate_effect_artifact_set(
    request_value: Any, receipt_value: Any, *, now: str,
) -> dict[str, Any]:
    """Production artifact validation using only package-owned authority."""

    return _validate_effect_artifact_set(
        request_value, receipt_value, now=now,
        authority_verifier=_PACKAGE_AUTHORITY_VERIFIER,
    )


def _validate_effect_artifact_set_for_test(
    request_value: Any,
    receipt_value: Any,
    *,
    now: str,
    authority_verifier: Callable[[dict[str, Any], dict[str, Any]], bool],
) -> dict[str, Any]:
    """TEST ONLY: validate authentic artifacts with explicit test authority."""

    return _validate_effect_artifact_set(
        request_value, receipt_value, now=now,
        authority_verifier=authority_verifier,
    )


_ACTION_BINDING_TOKEN = object()


class _PackageActionBinding:
    __slots__ = ("_token", "_registrations")

    def __init__(self, token: object, registrations: Any) -> None:
        if token is not _ACTION_BINDING_TOKEN:
            raise GatewayError("direct_effect_bypass")
        rows: dict[str, dict[str, Any]] = {}
        if not isinstance(registrations, (list, tuple)):
            raise GatewayError("unregistered_tool")
        for value in registrations:
            action = _closed_effect(value, {
                "action_id", "tool_id", "transport", "parameter_fields",
            }, "unregistered_tool")
            if action["action_id"] in rows:
                raise GatewayError("unregistered_tool")
            rows[action["action_id"]] = action
        self._token = token
        self._registrations = MappingProxyType(rows)

    def verify_authority(self, authority: dict[str, Any], context: dict[str, Any]) -> bool:
        return _PACKAGE_AUTHORITY_VERIFIER(authority, context)

    def action(self, action_id: str) -> dict[str, Any]:
        if action_id not in self._registrations:
            raise GatewayError("unregistered_tool")
        return copy.deepcopy(self._registrations[action_id])

    def invoke(self, action_id: str, operation: str, request: dict[str, Any]) -> dict[str, Any]:
        try:
            return package_host.invoke_registered_action(action_id, operation, request)
        except package_host.HostCapabilityError as exc:
            raise GatewayError("action_observation_missing") from exc


class _TestActionBinding:
    __slots__ = ("_token", "_registry", "_authority_verifier")

    def __init__(
        self, token: object, action_registry: Any,
        authority_verifier: Callable[[dict[str, Any], dict[str, Any]], bool] | None,
    ) -> None:
        if token is not _ACTION_BINDING_TOKEN:
            raise GatewayError("direct_effect_bypass")
        registry = _mapping(action_registry, "unregistered_tool")
        for registration in registry.values():
            if not isinstance(registration, dict) or registration.get("test_only") is not True:
                raise GatewayError("direct_effect_bypass")
        if authority_verifier is None or not callable(authority_verifier):
            raise GatewayError("authority_missing")
        self._token = token
        self._registry = registry
        self._authority_verifier = authority_verifier

    def verify_authority(self, authority: dict[str, Any], context: dict[str, Any]) -> bool:
        return self._authority_verifier(copy.deepcopy(authority), copy.deepcopy(context))

    def action(self, action_id: str) -> dict[str, Any]:
        if action_id not in self._registry:
            raise GatewayError("unregistered_tool")
        row = _closed_effect(self._registry[action_id], {
            "action_id", "tool_id", "transport", "parameter_fields", "handler", "test_only",
        }, "unregistered_tool")
        if row["test_only"] is not True or not callable(row["handler"]):
            raise GatewayError("direct_effect_bypass")
        return row

    def invoke(self, action_id: str, operation: str, request: dict[str, Any]) -> dict[str, Any]:
        return self.action(action_id)["handler"](operation, copy.deepcopy(request))


def _execute_effect_with_binding(
    state_value: Any,
    request_value: Any,
    binding: Any,
    *,
    now: str,
    recovery_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deterministic transition with one internally minted package/test binding."""

    if type(binding) not in {_PackageActionBinding, _TestActionBinding} or binding._token is not _ACTION_BINDING_TOKEN:
        raise GatewayError("direct_effect_bypass")
    state = copy.deepcopy(verify_effect_state(state_value))
    replay_key = request_value.get("idempotency_key") if isinstance(request_value, dict) else None
    has_existing_key = replay_key in state["idempotency_index"]
    request, authority, context = _validate_effect_request(
        request_value,
        state,
        now,
        skip_cas=has_existing_key,
    )
    try:
        verified = binding.verify_authority(copy.deepcopy(authority), copy.deepcopy(context))
    except Exception as exc:
        raise GatewayError("actor_not_authorized") from exc
    if verified is not True:
        raise GatewayError("actor_not_authorized")
    if request["workspace_id"] != state["workspace_id"]:
        raise GatewayError("cas_mismatch")
    request_sha = request["request_sha256"]
    if request["operation"] == "recover":
        provenance = _closed_effect(copy.deepcopy(recovery_provenance), RECOVERY_PROVENANCE_FIELDS, "recovery_authority_unavailable")
        if provenance["predecessor_run_id"] != request["run"]["predecessor_run_id"] or provenance["reserved_authority_id"] != request["authority_receipt"]["authority_id"] or provenance["expected_cas"] != request["cas"]:
            raise GatewayError("recovery_authority_unavailable")
    elif recovery_provenance is not None:
        raise GatewayError("recovery_authority_unavailable")
    existing = state["idempotency_index"].get(request["idempotency_key"])
    if existing is not None:
        expected_grant = None if request["operation"] != "recover" else provenance["grant_sha256"]
        expected_grant_id = None if request["operation"] != "recover" else provenance["grant_id"]
        expected_provenance = None if request["operation"] != "recover" else provenance
        expected_provenance_sha = None if expected_provenance is None else digest(expected_provenance)
        if existing["request_sha256"] != request_sha or existing.get("recovery_grant_id") != expected_grant_id or existing.get("recovery_grant_sha256") != expected_grant or existing.get("recovery_provenance") != expected_provenance or existing.get("recovery_provenance_sha256") != expected_provenance_sha:
            raise GatewayError("idempotency_collision")
        return {
            "state": state,
            "receipt": copy.deepcopy(state["receipt_index"][existing["receipt_sha256"]]),
            "replayed": True,
        }
    if request["request_id"] in {row["request_id"] for row in state["receipt_index"].values()}:
        raise GatewayError("receipt_replay_collision")
    action_id = request["adapter_snapshot"]["action_id"]
    action = binding.action(action_id)
    if (
        action["action_id"] != action_id
        or action["tool_id"] != request["input"]["tool_id"]
        or action["transport"] != request["adapter_snapshot"]["transport"]
    ):
        raise GatewayError("unregistered_tool")
    fields = action["parameter_fields"]
    if not isinstance(fields, (list, tuple)) or any(not isinstance(item, str) for item in fields):
        raise GatewayError("unregistered_tool")
    if set(request["input"]["parameters"]) != set(fields):
        raise GatewayError("request_shape_invalid", "input.parameters")
    operation = request["operation"]
    run_id = request["run"]["run_id"]
    predecessor_id = request["run"]["predecessor_run_id"]
    current = state["runs"].get(run_id)
    if operation == "run":
        if current is not None:
            if current["lifecycle"] == "execution_unknown":
                raise GatewayError("execution_unknown")
            raise GatewayError("in_flight_switch_denied")
        pre_state = "absent"
    elif operation == "cancel":
        if current is None:
            raise GatewayError("run_not_found")
        if current["lifecycle"] == "execution_unknown":
            raise GatewayError("execution_unknown")
        if current["lifecycle"] != "running":
            raise GatewayError("invalid_transition")
        if current["lease"] != request["lease"]:
            raise GatewayError("fence_mismatch")
        pre_state = current["lifecycle"]
        current["lifecycle"] = "cancel_requested"
    else:
        if current is not None:
            raise GatewayError("in_flight_switch_denied")
        predecessor = state["runs"].get(predecessor_id)
        if predecessor is None:
            raise GatewayError("run_not_found")
        if predecessor["lifecycle"] != "execution_unknown":
            raise GatewayError("invalid_transition")
        if predecessor["successor_run_id"] is not None:
            raise GatewayError("in_flight_switch_denied")
        if request["lease"]["lease_id"] == predecessor["lease"]["lease_id"] or request["lease"]["fencing_token"] <= predecessor["lease"]["fencing_token"]:
            raise GatewayError("recovery_requires_new_fence")
        pre_state = "execution_unknown"

    before = state["state_version"]
    event_ids = [f"{request['request_id']}:requested"]
    try:
        observed_value = binding.invoke(action_id, operation, copy.deepcopy(request))
        observed = _validate_action_receipt(observed_value, request, now)
    except GatewayError:
        observed = None
    except Exception:
        observed = None

    if observed is not None and any(
        run["action_receipt_sha256"] == observed["receipt_sha256"]
        or run["action_receipt_id"] == observed["action_receipt_id"]
        or run["effect_id"] == observed["effect_id"]
        for run in state["runs"].values()
    ):
        observed = None

    if observed is None:
        if operation == "run":
            state["runs"][run_id] = {
                "run_id": run_id, "predecessor_run_id": None, "successor_run_id": None,
                "request_sha256": request_sha, "lifecycle": "execution_unknown",
                "lease": copy.deepcopy(request["lease"]),
                "thread_generation": request["thread_snapshot"]["generation"],
                "route_requested": copy.deepcopy(request["route_snapshot"]),
                "route_observed": {"route_id": "unknown", "model": "unknown", "host": "unknown"},
                "preset_snapshot": copy.deepcopy(request["preset_snapshot"]),
                "action_receipt_id": None, "action_receipt_sha256": None,
                "effect_id": None, "reconciled": False, "recovery_provenance": None,
            }
        elif operation == "cancel":
            state["runs"][run_id]["lifecycle"] = "execution_unknown"
        # A failed recover leaves the predecessor execution_unknown and creates no successor.
        post_state = "execution_unknown"
        disposition = "execution_unknown"
        event_ids.append(f"{request['request_id']}:execution_unknown")
        unknowns = ["action_observation", "route_id", "model", "host"]
    else:
        receipt_sha = observed["receipt_sha256"]
        if operation == "run":
            state["runs"][run_id] = {
                "run_id": run_id, "predecessor_run_id": None, "successor_run_id": None,
                "request_sha256": request_sha, "lifecycle": "running",
                "lease": copy.deepcopy(request["lease"]),
                "thread_generation": request["thread_snapshot"]["generation"],
                "route_requested": copy.deepcopy(request["route_snapshot"]),
                "route_observed": copy.deepcopy(observed["observed_identity"]),
                "preset_snapshot": copy.deepcopy(request["preset_snapshot"]),
                "action_receipt_id": observed["action_receipt_id"],
                "action_receipt_sha256": receipt_sha,
                "effect_id": observed["effect_id"], "reconciled": False, "recovery_provenance": None,
            }
        elif operation == "cancel":
            current = state["runs"][run_id]
            current["lifecycle"] = "cancelled"
            current["action_receipt_id"] = observed["action_receipt_id"]
            current["action_receipt_sha256"] = receipt_sha
            current["effect_id"] = observed["effect_id"]
            current["route_observed"] = copy.deepcopy(observed["observed_identity"])
        else:
            predecessor = state["runs"][predecessor_id]
            predecessor["lifecycle"] = observed["reconciled_outcome"]
            predecessor["reconciled"] = True
            predecessor["successor_run_id"] = run_id
            state["runs"][run_id] = {
                "run_id": run_id, "predecessor_run_id": predecessor_id, "successor_run_id": None,
                "request_sha256": request_sha, "lifecycle": "running",
                "lease": copy.deepcopy(request["lease"]),
                "thread_generation": request["thread_snapshot"]["generation"],
                "route_requested": copy.deepcopy(request["route_snapshot"]),
                "route_observed": copy.deepcopy(observed["observed_identity"]),
                "preset_snapshot": copy.deepcopy(request["preset_snapshot"]),
                "action_receipt_id": observed["action_receipt_id"],
                "action_receipt_sha256": receipt_sha,
                "effect_id": observed["effect_id"], "reconciled": False,
                "recovery_provenance": copy.deepcopy(provenance),
            }
        post_state = state["runs"][run_id]["lifecycle"]
        disposition = "observed"
        event_ids.append(f"{request['request_id']}:observed")
        unknowns = [field for field, item in observed["observed_identity"].items() if item == "unknown"]

    state["state_version"] = before + 1
    state["thread_generation"] = request["thread_snapshot"]["generation"]
    receipt = _effect_receipt(
        request, disposition=disposition, pre_state=pre_state, post_state=post_state,
        before=before, after=state["state_version"], action_receipt=observed,
        event_ids=event_ids, unknowns=unknowns,
    )
    state["idempotency_index"][request["idempotency_key"]] = {
        "request_sha256": request_sha, "receipt_sha256": receipt["receipt_sha256"],
        "recovery_grant_id": None if operation != "recover" else provenance["grant_id"],
        "recovery_grant_sha256": None if operation != "recover" else provenance["grant_sha256"],
        "recovery_provenance": None if operation != "recover" else copy.deepcopy(provenance),
        "recovery_provenance_sha256": None if operation != "recover" else digest(provenance),
    }
    state["receipt_index"][receipt["receipt_sha256"]] = copy.deepcopy(receipt)
    _seal_effect_state(state)
    verify_effect_state(state)
    return {"state": state, "receipt": receipt, "replayed": False}


def _execute_effect_for_test(
    state_value: Any,
    request_value: Any,
    action_registry: Any,
    authority_verifier: Callable[[dict[str, Any], dict[str, Any]], bool] | None,
    *,
    now: str,
    recovery_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """TEST ONLY: execute with explicit test-only registrations and verifier."""

    binding = _TestActionBinding(
        _ACTION_BINDING_TOKEN, action_registry, authority_verifier,
    )
    return _execute_effect_with_binding(state_value, request_value, binding, now=now, recovery_provenance=recovery_provenance)


def execute_effect(
    state_value: Any,
    request_value: Any,
    *,
    now: str,
) -> dict[str, Any]:
    """Production execution using immutable package-owned capabilities only."""

    _, authority, context = _authority_preflight_material(request_value, now=now)
    _verify_package_authority(authority, context)
    try:
        binding = _PackageActionBinding(
            _ACTION_BINDING_TOKEN, package_host.action_registrations(),
        )
    except package_host.HostCapabilityError as exc:
        raise GatewayError("unregistered_tool") from exc
    return _execute_effect_with_binding(state_value, request_value, binding, now=now)


def _replay_recovery_from_canonical_state(
    state_value: Any, request_value: Any, *, token: object,
) -> dict[str, Any]:
    """PACKAGE INTERNAL: return only an exact completed Recover under service lock."""

    if token is not _RECOVERY_REPLAY_TOKEN:
        raise GatewayError("direct_effect_bypass")
    state = copy.deepcopy(verify_effect_state(state_value))
    if not isinstance(request_value, dict) or request_value.get("operation") != "recover":
        raise GatewayError("recovery_authority_unavailable")
    request, _, _ = _validate_effect_request(
        request_value, state, request_value.get("created_at"), skip_cas=True,
    )
    existing = state["idempotency_index"].get(request["idempotency_key"])
    if existing is None:
        raise GatewayError("recovery_authority_unavailable")
    if existing["request_sha256"] != request["request_sha256"]:
        raise GatewayError("idempotency_collision")
    receipt = state["receipt_index"].get(existing["receipt_sha256"])
    successor = state["runs"].get(request["run"]["run_id"])
    predecessor = state["runs"].get(request["run"]["predecessor_run_id"])
    provenance = None if successor is None else successor["recovery_provenance"]
    predecessor_receipt = None if provenance is None else state["receipt_index"].get(
        provenance["predecessor_effect_receipt_sha256"]
    )
    if (
        receipt is None or successor is None or predecessor is None or provenance is None
        or existing["recovery_grant_id"] != provenance["grant_id"]
        or existing["recovery_grant_sha256"] != provenance["grant_sha256"]
        or existing["recovery_provenance"] != provenance
        or existing["recovery_provenance_sha256"] != digest(provenance)
        or successor["request_sha256"] != request["request_sha256"]
        or successor["predecessor_run_id"] != request["run"]["predecessor_run_id"]
        or successor["lease"] != request["lease"]
        or successor["thread_generation"] != request["thread_snapshot"]["generation"]
        or provenance["predecessor_run_id"] != predecessor["run_id"]
        or provenance["predecessor_effect_request_sha256"] != predecessor["request_sha256"]
        or provenance["expected_cas"] != request["cas"]
        or provenance["reserved_authority_id"] != request["authority_receipt"]["authority_id"]
        or predecessor_receipt is None
        or predecessor_receipt["run_id"] != predecessor["run_id"]
        or predecessor_receipt["request_sha256"] != predecessor["request_sha256"]
        or receipt["request_sha256"] != request["request_sha256"]
        or receipt["operation"] != "recover"
        or receipt["run_id"] != successor["run_id"]
        or receipt["lease"] != successor["lease"]
        or receipt["state_version_before"] != request["cas"]["expected_state_version"]
        or receipt["state_version_after"] != receipt["state_version_before"] + 1
    ):
        raise GatewayError("recovery_authority_unavailable")
    return {"state": state, "receipt": copy.deepcopy(receipt), "replayed": True}


def _execute_recovery_with_package_grant(
    state_value: Any, request_value: Any, recovery_provenance: dict[str, Any], *, now: str, token: object,
) -> dict[str, Any]:
    """PACKAGE INTERNAL: production Recover after service TLS-grant validation."""
    if token is not _RECOVERY_PACKAGE_TOKEN:
        raise GatewayError("direct_effect_bypass")
    _, authority, context = _authority_preflight_material(request_value, now=now)
    _verify_package_authority(authority, context)
    try:
        binding = _PackageActionBinding(_ACTION_BINDING_TOKEN, package_host.action_registrations())
    except package_host.HostCapabilityError as exc:
        raise GatewayError("unregistered_tool") from exc
    return _execute_effect_with_binding(state_value, request_value, binding, now=now, recovery_provenance=recovery_provenance)
