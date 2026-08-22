#!/usr/bin/env python3
"""Dormant fixed-origin operator binding over canonical runtime receipts."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping

import package_host_capability_adapter as package_host
import runtime_execution_gateway as gateway
import served_agent_presets as presets


PROJECTION_TYPE = "standalone_operator_local_projection_v1"
PROJECTION_V2_TYPE = "standalone_operator_local_projection_v2"
PROJECTION_V3_TYPE = "standalone_operator_local_projection_v3"
SUBMISSION_TYPE = "standalone_operator_control_submission_v1"
ADMISSION_TYPE = "standalone_operator_capability_admission_v1"
RECORD_TYPE = "standalone_operator_binding_record_v1"
PROJECTION_RECEIPT_TYPE = "standalone_operator_projection_receipt_v1"
CONTROL_AUTHORITY_TYPE = "standalone_operator_control_authority_v1"
CONTROL_GRANT_TYPE = "standalone_operator_control_grant_v1"
FIXED_ROUTES = MappingProxyType({
    ("GET", "/operator/v1/"): "assets",
    ("GET", "/operator/v1/app.js"): "app_js",
    ("GET", "/operator/v1/styles.css"): "styles_css",
    ("GET", "/operator/v1/status"): "status",
    ("POST", "/operator/v1/submit"): "submit",
})
SHIPPED_CAPABILITY_IDS = frozenset({
    "operator.status", "operator.submit", "effect.run", "effect.cancel",
    "effect.recover", "preset.select", "responses.bridge", "context.issue",
    "operator.listen", "preset.catalog",
})
REQUIRED_ADMISSION_CAPABILITIES = SHIPPED_CAPABILITY_IDS
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")

ADMISSION_FIELDS = {
    "schema_version", "artifact_type", "admission_id", "issuer_id",
    "workspace_id", "source_sha256", "candidate_sha256",
    "service_instance_id", "capability_ids", "issued_at", "expires_at",
    "revoked", "binding_state_version", "binding_state_sha256",
    "durable_index_sha256", "producer_policy_sha256",
    "missing_producer_operations", "admission_sha256", "seal",
}
RECORD_FIELDS = {
    "schema_version", "artifact_type", "record_id", "workspace_id",
    "source_sha256", "candidate_sha256", "service_instance_id",
    "binding_state_version", "responses_request", "effect_request",
    "effect_receipt", "bridge_receipt", "selection", "cursor", "recovery",
    "used_view_nonces", "submission_replays", "pending_submission", "validation_seal",
    "record_sha256",
}
PROJECTION_FIELDS = {
    "schema_version", "artifact_type", "projection_id", "service_instance_id",
    "workspace_id", "source_sha256", "candidate_sha256",
    "binding_state_version", "binding_state_sha256", "selection", "run",
    "artifact_refs", "controls", "claims", "issued_at", "expires_at",
    "view_nonce", "projection_sha256", "projection_receipt",
}
CONTROL_GRANT_FIELDS = {
    "grant_id", "operation", "provenance", "run_id", "predecessor_run_id",
    "successor_run_id", "effect_operation", "lease_id", "fencing_token",
    "lease_expires_at", "cas_expected_state_version",
    "cas_expected_thread_generation", "authority_receipt_sha256",
    "effect_request_sha256", "effect_receipt_sha256", "action_receipt_sha256",
    "bridge_receipt_sha256", "cancel_observed", "recovery",
    "catalog_receipt_sha256", "bundle_sha256", "bundle_generation",
    "selection_head_receipt_sha256", "issued_at", "expires_at", "grant_sha256",
}
CONTROL_AUTHORITY_FIELDS = {
    "schema_version", "artifact_type", "workspace_id", "source_sha256",
    "candidate_sha256", "service_instance_id", "admission_id",
    "admission_seal_sha256", "binding_state_version", "binding_state_sha256",
    "selection_sha256", "effect_state_version", "effect_state_sha256",
    "grants", "issued_at", "expires_at", "authority_sha256", "sealed_by",
}
SUBMISSION_FIELDS = {
    "schema_version", "artifact_type", "submission_id", "projection_sha256",
    "view_nonce", "action", "payload",
}
TRANSPORT_RECEIPT_TYPE = "standalone_operator_control_transport_receipt_v1"
TRANSPORT_RECEIPT_FIELDS = {
    "schema_version", "artifact_type", "submission_id", "transport_accepted",
    "effect_outcome", "optimistic_state_change",
}
SELECTION_TRANSPORT_RECEIPT_TYPE = "standalone_operator_selection_transport_receipt_v1"
SELECTION_TRANSPORT_RECEIPT_FIELDS = {
    "schema_version", "artifact_type", "submission_id", "transport_accepted",
    "selection_mutation_receipt_sha256", "selection_outcome",
    "optimistic_state_change",
}


class BindingError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _identity_for_host(value: Mapping[str, Any]) -> dict[str, Any]:
    return {field: value[field] for field in ("workspace_id", "source_sha256", "candidate_sha256")}


def _package_admission_provider(identity: dict[str, Any], service_instance_id: str, now: str) -> dict[str, Any]:
    return package_host.read_capability_admission(identity, service_instance_id, now)


def _package_admission_verifier(admission: dict[str, Any], context: dict[str, Any]) -> bool:
    return all(admission.get(field) == context.get(field) for field in ("workspace_id", "source_sha256", "candidate_sha256", "service_instance_id"))


def _package_record_sealer(context: dict[str, Any]) -> str:
    identity = _identity_for_host(context)
    value = package_host.commit_or_verify_record(identity, mode="commit", record=None, context=context, seal=None)
    return value["seal"]


def _package_record_verifier(seal: dict[str, Any], context: dict[str, Any]) -> bool:
    identity = _identity_for_host(context)
    return package_host.commit_or_verify_record(identity, mode="verify", record=context.get("record"), context={key: item for key, item in context.items() if key != "record"}, seal=seal["seal"]) == {"authorized": True}


def _package_projection_sealer(context: dict[str, Any]) -> str:
    identity = _identity_for_host(context)
    return package_host.seal_or_verify_projection(identity, mode="seal", context=context, seal=None)["seal"]


def _package_control_dispatcher(action: str, payload: dict[str, Any], record: dict[str, Any] | None, identity: dict[str, Any], recovery_grant: dict[str, Any] | None = None) -> dict[str, Any]:
    if action == "recover":
        if record is None or recovery_grant is None:
            raise BindingError("recovery_authority_unavailable", "$.recovery_grant")
        return package_host._issue_responses_context_with_recovery_grant(
            None, _identity_for_host(identity), control_action=action,
            control_payload=payload, record_sha256=record["record_sha256"],
            service_instance_id=identity["service_instance_id"],
            recovery_grant_id=recovery_grant["grant_id"],
            recovery_grant_sha256=recovery_grant["grant_sha256"],
        )
    if recovery_grant is not None:
        raise BindingError("recovery_authority_unavailable", "$.recovery_grant")
    return package_host.issue_responses_context(None, _identity_for_host(identity), control_action=action, control_payload=payload, record_sha256=None if record is None else record["record_sha256"], service_instance_id=identity["service_instance_id"])


def start_package_listener(identity: dict[str, Any]) -> dict[str, Any]:
    routes = [{"method": method, "path": path, "handler": handler} for (method, path), handler in FIXED_ROUTES.items()]
    return package_host.open_operator_listener(_identity_for_host(identity), identity["service_instance_id"], routes)


_PACKAGE_CAPABILITY_ADMISSION_PROVIDER = _package_admission_provider
_PACKAGE_CAPABILITY_ADMISSION_VERIFIER = _package_admission_verifier
_PACKAGE_PROJECTION_SEALER = _package_projection_sealer
_PACKAGE_CONTROL_DISPATCHER = _package_control_dispatcher
_PACKAGE_RECORD_SEALER = _package_record_sealer
_PACKAGE_RECORD_VERIFIER = _package_record_verifier
_PACKAGE_LISTENER_STARTER = start_package_listener


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BindingError("binding_shape_invalid") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _closed(value: Any, fields: set[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise BindingError(code, path)
    return copy.deepcopy(dict(value))


def _identifier(value: Any, code: str, path: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise BindingError(code, path)
    return value


def _sha(value: Any, code: str, path: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise BindingError(code, path)
    return value


def _timestamp(value: Any, code: str, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise BindingError(code, path)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BindingError(code, path) from exc
    if parsed.tzinfo is None:
        raise BindingError(code, path)
    return parsed.astimezone(timezone.utc)


def _validate_admission(
    value: Any,
    *,
    workspace_id: str,
    source_sha256: str,
    candidate_sha256: str,
    service_instance_id: str,
    now: str,
    verifier: Callable[[dict[str, Any], dict[str, Any]], bool] | None,
) -> dict[str, Any]:
    row = _closed(value, ADMISSION_FIELDS, "production_capability_unavailable", "$.admission")
    if row["schema_version"] != 1 or row["artifact_type"] != ADMISSION_TYPE or row["revoked"] is not False:
        raise BindingError("production_capability_unavailable", "$.admission")
    for field in ("admission_id", "issuer_id", "workspace_id", "service_instance_id"):
        _identifier(row[field], "production_capability_unavailable", f"$.admission.{field}")
    for field in (
        "source_sha256", "candidate_sha256", "binding_state_sha256",
        "durable_index_sha256", "producer_policy_sha256", "admission_sha256",
        "seal",
    ):
        _sha(row[field], "production_capability_unavailable", f"$.admission.{field}")
    if (
        row["workspace_id"] != workspace_id
        or row["source_sha256"] != source_sha256
        or row["candidate_sha256"] != candidate_sha256
        or row["service_instance_id"] != service_instance_id
    ):
        raise BindingError("production_capability_unavailable", "$.admission")
    if (
        not isinstance(row["capability_ids"], list)
        or any(not isinstance(item, str) for item in row["capability_ids"])
        or row["capability_ids"] != sorted(set(row["capability_ids"]))
    ):
        raise BindingError("production_capability_unavailable", "$.admission.capability_ids")
    capabilities = set(row["capability_ids"])
    if capabilities != REQUIRED_ADMISSION_CAPABILITIES or not capabilities <= SHIPPED_CAPABILITY_IDS:
        raise BindingError("production_capability_unavailable", "$.admission.capability_ids")
    if type(row["binding_state_version"]) is not int or row["binding_state_version"] < 0:
        raise BindingError("production_capability_unavailable", "$.admission.binding_state_version")
    missing = row["missing_producer_operations"]
    if (
        not isinstance(missing, list)
        or any(not isinstance(item, str) for item in missing)
        or missing != sorted(set(missing))
        or not set(missing) <= set(package_host.SEMANTIC_OPERATIONS)
    ):
        raise BindingError("production_capability_unavailable", "$.admission.missing_producer_operations")
    expected_admission_sha256 = digest({
        key: item for key, item in row.items()
        if key not in {"admission_sha256", "seal"}
    })
    if row["admission_sha256"] != expected_admission_sha256:
        raise BindingError("production_capability_unavailable", "$.admission.admission_sha256")
    issued = _timestamp(row["issued_at"], "production_capability_unavailable", "$.admission.issued_at")
    expires = _timestamp(row["expires_at"], "production_capability_unavailable", "$.admission.expires_at")
    instant = _timestamp(now, "production_capability_unavailable", "$.now")
    if issued > instant or expires <= instant or expires <= issued:
        raise BindingError("production_capability_unavailable", "$.admission.expires_at")
    context = {
        "workspace_id": workspace_id, "source_sha256": source_sha256,
        "candidate_sha256": candidate_sha256,
        "service_instance_id": service_instance_id,
        "capability_ids": sorted(capabilities), "expires_at": row["expires_at"],
        "binding_state_version": row["binding_state_version"],
        "binding_state_sha256": row["binding_state_sha256"],
        "durable_index_sha256": row["durable_index_sha256"],
        "producer_policy_sha256": row["producer_policy_sha256"],
        "missing_producer_operations": copy.deepcopy(missing),
        "admission_sha256": row["admission_sha256"],
    }
    if verifier is None or not callable(verifier):
        raise BindingError("production_capability_unavailable", "$.admission")
    try:
        accepted = verifier(copy.deepcopy(row), copy.deepcopy(context))
    except Exception as exc:
        raise BindingError("production_capability_unavailable", "$.admission") from exc
    if accepted is not True:
        raise BindingError("production_capability_unavailable", "$.admission")
    return row


def resolve_package_admission(
    *, workspace_id: str, source_sha256: str, candidate_sha256: str,
    service_instance_id: str, now: str,
) -> dict[str, Any]:
    """Resolve only the immutable package service slots; callers inject nothing."""
    provider = _PACKAGE_CAPABILITY_ADMISSION_PROVIDER
    if provider is None or not callable(provider):
        raise BindingError("production_capability_unavailable", "$.admission")
    try:
        value = provider(
            {"workspace_id": workspace_id, "source_sha256": source_sha256, "candidate_sha256": candidate_sha256},
            service_instance_id,
            now,
        )
    except Exception as exc:
        raise BindingError("production_capability_unavailable", "$.admission") from exc
    return _validate_admission(
        value, workspace_id=workspace_id, source_sha256=source_sha256,
        candidate_sha256=candidate_sha256, service_instance_id=service_instance_id,
        now=now, verifier=_PACKAGE_CAPABILITY_ADMISSION_VERIFIER,
    )


def _resolve_package_admission_for_test(
    value: Any, *, workspace_id: str, source_sha256: str,
    candidate_sha256: str, service_instance_id: str, now: str,
    verifier: Callable[[dict[str, Any], dict[str, Any]], bool],
) -> dict[str, Any]:
    """TEST ONLY: exercise the package admission ABI with external authority."""
    return _validate_admission(
        value, workspace_id=workspace_id, source_sha256=source_sha256,
        candidate_sha256=candidate_sha256, service_instance_id=service_instance_id,
        now=now, verifier=verifier,
    )


def _artifact_set_sha256(
    responses_request: Mapping[str, Any], effect_request: Mapping[str, Any],
    effect_receipt: Mapping[str, Any], bridge_receipt: Mapping[str, Any] | None,
) -> str:
    return digest({
        "responses_request": responses_request, "effect_request": effect_request,
        "effect_receipt": effect_receipt, "bridge_receipt": bridge_receipt,
    })


def _build_record(
    *, record_id: str, service_instance_id: str, admission: dict[str, Any],
    responses_request: dict[str, Any], effect_request: dict[str, Any],
    effect_receipt: dict[str, Any], bridge_receipt: dict[str, Any] | None,
    cursor: dict[str, Any], recovery: dict[str, Any], binding_state_version: int,
    validation_sealer: Callable[[dict[str, Any]], str] | None,
) -> dict[str, Any]:
    if (
        effect_request.get("workspace_id") != admission["workspace_id"]
        or effect_request.get("source_bundle", {}).get("source_sha256") != admission["source_sha256"]
        or effect_request.get("source_bundle", {}).get("candidate_sha256") != admission["candidate_sha256"]
        or responses_request.get("workspace_id") != admission["workspace_id"]
    ):
        raise BindingError("binding_record_identity_mismatch", "$.artifacts")
    artifact_set_sha256 = _artifact_set_sha256(
        responses_request, effect_request, effect_receipt, bridge_receipt,
    )
    validation_context = {
        "artifact_set_sha256": artifact_set_sha256,
        "workspace_id": admission["workspace_id"],
        "source_sha256": admission["source_sha256"],
        "candidate_sha256": admission["candidate_sha256"],
        "service_instance_id": service_instance_id,
        "admission_seal": admission["seal"],
    }
    if validation_sealer is None or not callable(validation_sealer):
        raise BindingError("binding_record_validation_unavailable", "$.record.validation_seal")
    try:
        validation_value = validation_sealer(copy.deepcopy(validation_context))
    except Exception as exc:
        raise BindingError("binding_record_validation_unavailable", "$.record.validation_seal") from exc
    _sha(validation_value, "binding_record_validation_unavailable", "$.record.validation_seal.seal")
    record = {
        "schema_version": 1, "artifact_type": RECORD_TYPE,
        "record_id": record_id, "workspace_id": admission["workspace_id"],
        "source_sha256": admission["source_sha256"],
        "candidate_sha256": admission["candidate_sha256"],
        "service_instance_id": service_instance_id,
        "binding_state_version": binding_state_version,
        "responses_request": copy.deepcopy(responses_request),
        "effect_request": copy.deepcopy(effect_request),
        "effect_receipt": copy.deepcopy(effect_receipt),
        "bridge_receipt": copy.deepcopy(bridge_receipt),
        "selection": copy.deepcopy(responses_request["selection"]),
        "cursor": copy.deepcopy(cursor), "recovery": copy.deepcopy(recovery),
        "used_view_nonces": [], "submission_replays": [], "pending_submission": None,
        "validation_seal": {
            "artifact_set_sha256": artifact_set_sha256,
            "seal": validation_value,
        },
        "record_sha256": "",
    }
    record["record_sha256"] = digest({key: item for key, item in record.items() if key != "record_sha256"})
    return record


def _create_binding_record_for_test(
    *, record_id: str, service_instance_id: str, admission: dict[str, Any],
    responses_request: dict[str, Any], effect_request: dict[str, Any],
    effect_receipt: dict[str, Any], bridge_receipt: dict[str, Any] | None,
    now: str, authority_verifier: Callable[[dict[str, Any], dict[str, Any]], bool],
    trusted_bridge_receipt_sha256: str | None, cursor: dict[str, Any],
    recovery: dict[str, Any], validation_sealer: Callable[[dict[str, Any]], str],
    binding_state_version: int = 1,
) -> dict[str, Any]:
    """TEST ONLY: retain originals after both canonical authorities validate."""
    try:
        gateway._validate_effect_artifact_set_for_test(
            effect_request, effect_receipt, now=now,
            authority_verifier=authority_verifier,
        )
        if bridge_receipt is None:
            response, selection, _ = presets.validate_responses_request(responses_request)
            if (
                effect_receipt.get("post_state") != "execution_unknown"
                or effect_receipt.get("action_receipt") is not None
                or response["operation"] != effect_request.get("operation")
                or response["workspace_id"] != effect_request.get("workspace_id")
                or selection["preset_id"] != effect_request.get("preset_snapshot", {}).get("preset_id")
            ):
                raise BindingError("bridge_receipt_missing", "$.artifacts.bridge_receipt")
        else:
            presets._validate_responses_artifact_set_for_test(
                responses_request, effect_request, effect_receipt, bridge_receipt,
                trusted_bridge_receipt_sha256=trusted_bridge_receipt_sha256,
            )
    except (gateway.GatewayError, presets.PresetError) as exc:
        raise BindingError(getattr(exc, "code", "artifact_validation_failed"), "$.artifacts") from exc
    return _build_record(
        record_id=record_id, service_instance_id=service_instance_id,
        admission=admission, responses_request=responses_request,
        effect_request=effect_request, effect_receipt=effect_receipt,
        bridge_receipt=bridge_receipt, cursor=cursor, recovery=recovery,
        binding_state_version=binding_state_version,
        validation_sealer=validation_sealer,
    )


def create_binding_record(
    *, record_id: str, service_instance_id: str, admission: dict[str, Any],
    responses_request: dict[str, Any], effect_request: dict[str, Any],
    effect_receipt: dict[str, Any], bridge_receipt: dict[str, Any] | None,
    now: str, cursor: dict[str, Any], recovery: dict[str, Any],
    binding_state_version: int,
) -> dict[str, Any]:
    """Production retention after package-owned canonical authorities validate."""
    try:
        gateway.validate_effect_artifact_set(effect_request, effect_receipt, now=now)
        if bridge_receipt is None:
            response, selection, _ = presets.validate_responses_request(responses_request)
            if (
                effect_receipt.get("post_state") != "execution_unknown"
                or effect_receipt.get("action_receipt") is not None
                or response["operation"] != effect_request.get("operation")
                or response["workspace_id"] != effect_request.get("workspace_id")
                or selection["preset_id"] != effect_request.get("preset_snapshot", {}).get("preset_id")
            ):
                raise BindingError("bridge_receipt_missing", "$.artifacts.bridge_receipt")
        else:
            presets.validate_responses_artifact_set(
                responses_request, effect_request, effect_receipt, bridge_receipt,
            )
    except (gateway.GatewayError, presets.PresetError) as exc:
        raise BindingError(getattr(exc, "code", "artifact_validation_failed"), "$.artifacts") from exc
    return _build_record(
        record_id=record_id, service_instance_id=service_instance_id,
        admission=admission, responses_request=responses_request,
        effect_request=effect_request, effect_receipt=effect_receipt,
        bridge_receipt=bridge_receipt, cursor=cursor, recovery=recovery,
        binding_state_version=binding_state_version,
        validation_sealer=_PACKAGE_RECORD_SEALER,
    )


def _create_binding_record_with_resolved_bundle(
    *, record_id: str, service_instance_id: str, admission: dict[str, Any],
    responses_request: dict[str, Any], effect_request: dict[str, Any],
    effect_receipt: dict[str, Any], bridge_receipt: dict[str, Any] | None,
    now: str, cursor: dict[str, Any], recovery: dict[str, Any],
    binding_state_version: int, bundle: Mapping[str, Any],
) -> dict[str, Any]:
    """PACKAGE INTERNAL: retain artifacts using an exact host-resolved bundle."""
    try:
        gateway.validate_effect_artifact_set(effect_request, effect_receipt, now=now)
        if bridge_receipt is None:
            response, selection, _ = presets.validate_responses_request(responses_request, bundle)
            if effect_receipt.get("post_state") != "execution_unknown" or effect_receipt.get("action_receipt") is not None or response["operation"] != effect_request.get("operation") or response["workspace_id"] != effect_request.get("workspace_id") or selection["preset_id"] != effect_request.get("preset_snapshot", {}).get("preset_id"):
                raise BindingError("bridge_receipt_missing", "$.artifacts.bridge_receipt")
        else:
            presets._validate_responses_artifact_set_with_resolved_bundle(
                responses_request, effect_request, effect_receipt, bridge_receipt, bundle,
            )
    except (gateway.GatewayError, presets.PresetError) as exc:
        raise BindingError(getattr(exc, "code", "artifact_validation_failed"), "$.artifacts") from exc
    return _build_record(
        record_id=record_id, service_instance_id=service_instance_id,
        admission=admission, responses_request=responses_request,
        effect_request=effect_request, effect_receipt=effect_receipt,
        bridge_receipt=bridge_receipt, cursor=cursor, recovery=recovery,
        binding_state_version=binding_state_version,
        validation_sealer=_PACKAGE_RECORD_SEALER,
    )


def _validate_binding_record_structure(
    value: Any, admission: dict[str, Any],
    validation_verifier: Callable[[dict[str, Any], dict[str, Any]], bool],
) -> dict[str, Any]:
    row = _closed(value, RECORD_FIELDS, "binding_record_invalid", "$.record")
    if row["schema_version"] != 1 or row["artifact_type"] != RECORD_TYPE:
        raise BindingError("binding_record_invalid", "$.record")
    for field in ("record_id", "workspace_id", "service_instance_id"):
        _identifier(row[field], "binding_record_invalid", f"$.record.{field}")
    for field in ("source_sha256", "candidate_sha256", "record_sha256"):
        _sha(row[field], "binding_record_invalid", f"$.record.{field}")
    if any(row[field] != admission[field] for field in ("workspace_id", "source_sha256", "candidate_sha256", "service_instance_id")):
        raise BindingError("binding_record_identity_mismatch", "$.record")
    if type(row["binding_state_version"]) is not int or row["binding_state_version"] < 1:
        raise BindingError("binding_record_invalid", "$.record.binding_state_version")
    seal = _closed(row["validation_seal"], {"artifact_set_sha256", "seal"}, "binding_record_invalid", "$.record.validation_seal")
    expected_artifacts = _artifact_set_sha256(row["responses_request"], row["effect_request"], row["effect_receipt"], row["bridge_receipt"])
    if seal["artifact_set_sha256"] != expected_artifacts:
        raise BindingError("binding_record_validation_seal_mismatch", "$.record.validation_seal")
    _sha(seal["seal"], "binding_record_validation_seal_mismatch", "$.record.validation_seal.seal")
    context = {
        "artifact_set_sha256": expected_artifacts,
        "workspace_id": row["workspace_id"], "source_sha256": row["source_sha256"],
        "candidate_sha256": row["candidate_sha256"],
        "service_instance_id": row["service_instance_id"],
        "admission_seal": admission["seal"],
    }
    verifier = validation_verifier
    if verifier is _PACKAGE_RECORD_VERIFIER:
        context["record"] = copy.deepcopy(row)
    if verifier is None or not callable(verifier):
        raise BindingError("binding_record_validation_unavailable", "$.record.validation_seal")
    try:
        accepted = verifier(copy.deepcopy(seal), copy.deepcopy(context))
    except Exception as exc:
        raise BindingError("binding_record_validation_seal_mismatch", "$.record.validation_seal") from exc
    if accepted is not True:
        raise BindingError("binding_record_validation_seal_mismatch", "$.record.validation_seal")
    if row["selection"] != row["responses_request"].get("selection"):
        raise BindingError("binding_record_validation_seal_mismatch", "$.record.selection")
    cursor = _closed(row["cursor"], {"sequence", "stable", "receipt_sha256"}, "binding_record_invalid", "$.record.cursor")
    if type(cursor["sequence"]) is not int or cursor["sequence"] < 0 or cursor["stable"] is not True:
        raise BindingError("binding_record_invalid", "$.record.cursor")
    if cursor["receipt_sha256"] is not None:
        _sha(cursor["receipt_sha256"], "binding_record_invalid", "$.record.cursor.receipt_sha256")
    recovery = _closed(row["recovery"], {"reconciliation_observed", "reconciliation_receipt_sha256", "no_successor", "fresh_lease_id", "fresh_fencing_token", "successor_run_id"}, "binding_record_invalid", "$.record.recovery")
    if type(recovery["reconciliation_observed"]) is not bool or type(recovery["no_successor"]) is not bool:
        raise BindingError("binding_record_invalid", "$.record.recovery")
    if recovery["reconciliation_receipt_sha256"] is not None:
        _sha(recovery["reconciliation_receipt_sha256"], "binding_record_invalid", "$.record.recovery.reconciliation_receipt_sha256")
    for field in ("fresh_lease_id", "successor_run_id"):
        if recovery[field] is not None:
            _identifier(recovery[field], "binding_record_invalid", f"$.record.recovery.{field}")
    if recovery["fresh_fencing_token"] is not None and (type(recovery["fresh_fencing_token"]) is not int or recovery["fresh_fencing_token"] < 1):
        raise BindingError("binding_record_invalid", "$.record.recovery.fresh_fencing_token")
    if not isinstance(row["used_view_nonces"], list) or len(row["used_view_nonces"]) != len(set(row["used_view_nonces"])) or any(not isinstance(item, str) for item in row["used_view_nonces"]):
        raise BindingError("binding_record_invalid", "$.record.used_view_nonces")
    if not isinstance(row["submission_replays"], list):
        raise BindingError("binding_record_invalid", "$.record.submission_replays")
    replay_ids: set[str] = set()
    for index, value in enumerate(row["submission_replays"]):
        replay = _closed(value, {"submission_id", "submission_sha256", "transport_receipt"}, "binding_record_invalid", f"$.record.submission_replays[{index}]")
        _identifier(replay["submission_id"], "binding_record_invalid", f"$.record.submission_replays[{index}].submission_id")
        _sha(replay["submission_sha256"], "binding_record_invalid", f"$.record.submission_replays[{index}].submission_sha256")
        receipt = validate_transport_receipt(replay["transport_receipt"])
        if receipt["submission_id"] != replay["submission_id"] or replay["submission_id"] in replay_ids:
            raise BindingError("binding_record_invalid", f"$.record.submission_replays[{index}]")
        replay_ids.add(replay["submission_id"])
    if row["pending_submission"] is not None:
        pending = _closed(row["pending_submission"], {"submission_id", "submission_sha256", "view_nonce", "action"}, "binding_record_invalid", "$.record.pending_submission")
        for field in ("submission_id", "view_nonce", "action"):
            _identifier(pending[field], "binding_record_invalid", f"$.record.pending_submission.{field}")
        _sha(pending["submission_sha256"], "binding_record_invalid", "$.record.pending_submission.submission_sha256")
    if row["record_sha256"] != digest({key: item for key, item in row.items() if key != "record_sha256"}):
        raise BindingError("binding_record_digest_mismatch", "$.record.record_sha256")
    return row


def _canonical_revalidate_record(
    row: dict[str, Any], *, now: str,
    authority_verifier: Callable[[dict[str, Any], dict[str, Any]], bool] | None = None,
    trusted_bridge_receipt_sha256: str | None = None,
    resolved_bundle: Mapping[str, Any] | None = None,
) -> None:
    try:
        if authority_verifier is None:
            gateway.validate_effect_artifact_set(row["effect_request"], row["effect_receipt"], now=now)
        else:
            gateway._validate_effect_artifact_set_for_test(
                row["effect_request"], row["effect_receipt"], now=now,
                authority_verifier=authority_verifier,
            )
        if row["bridge_receipt"] is None:
            request, selection, _ = presets.validate_responses_request(row["responses_request"], presets.DEFAULT_PRESET_BUNDLE if resolved_bundle is None else resolved_bundle)
            if (
                row["effect_receipt"].get("post_state") != "execution_unknown"
                or row["effect_receipt"].get("action_receipt") is not None
                or request["operation"] != row["effect_request"].get("operation")
                or selection["preset_id"] != row["effect_request"].get("preset_snapshot", {}).get("preset_id")
            ):
                raise BindingError("bridge_receipt_missing", "$.record.bridge_receipt")
        elif trusted_bridge_receipt_sha256 is None:
            if resolved_bundle is None:
                presets.validate_responses_artifact_set(row["responses_request"], row["effect_request"], row["effect_receipt"], row["bridge_receipt"])
            else:
                presets._validate_responses_artifact_set_with_resolved_bundle(row["responses_request"], row["effect_request"], row["effect_receipt"], row["bridge_receipt"], resolved_bundle)
        else:
            presets._validate_responses_artifact_set_for_test(
                row["responses_request"], row["effect_request"],
                row["effect_receipt"], row["bridge_receipt"],
                trusted_bridge_receipt_sha256=trusted_bridge_receipt_sha256,
            )
    except (gateway.GatewayError, presets.PresetError) as exc:
        raise BindingError(getattr(exc, "code", "artifact_validation_failed"), "$.record") from exc


def validate_binding_record(value: Any, admission: dict[str, Any], *, now: str | None = None) -> dict[str, Any]:
    """Verify the host seal and re-run every canonical local validator."""
    row = _validate_binding_record_structure(value, admission, _PACKAGE_RECORD_VERIFIER)
    instant = now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _canonical_revalidate_record(row, now=instant)
    return row


def _validate_binding_record_with_resolved_bundle(
    value: Any, admission: dict[str, Any], bundle: Mapping[str, Any], *, now: str,
) -> dict[str, Any]:
    """PACKAGE INTERNAL: canonical record validation using immutable history."""
    row = _validate_binding_record_structure(value, admission, _PACKAGE_RECORD_VERIFIER)
    _canonical_revalidate_record(row, now=now, resolved_bundle=presets.validate_bundle(bundle))
    return row


def _validate_binding_record_for_test(
    value: Any, admission: dict[str, Any], validation_verifier: Callable[[dict[str, Any], dict[str, Any]], bool],
    *, now: str, authority_verifier: Callable[[dict[str, Any], dict[str, Any]], bool],
    trusted_bridge_receipt_sha256: str | None,
) -> dict[str, Any]:
    """TEST ONLY: external test authorities plus exact canonical revalidation."""
    row = _validate_binding_record_structure(value, admission, validation_verifier)
    _canonical_revalidate_record(
        row, now=now, authority_verifier=authority_verifier,
        trusted_bridge_receipt_sha256=trusted_bridge_receipt_sha256,
    )
    return row


def _control(enabled: bool, reason: str) -> dict[str, Any]:
    return {"enabled": enabled, "reason": reason}


def _derive_controls(record: dict[str, Any] | None, admission: dict[str, Any] | None, now: str, baseline: dict[str, Any] | None = None) -> dict[str, Any]:
    controls = {name: _control(False, "production capability unavailable") for name in ("run", "cancel", "recover", "select")}
    controls.update({name: _control(False, "forbidden by lifecycle policy") for name in ("retry", "fallback", "replacement")})
    if admission is None:
        return controls
    if record is None:
        if baseline is not None:
            lease = baseline["lease"]
            selection = baseline["selection"]
            current = (
                baseline["effect_state_version"] == 0
                and baseline["cas"] == {"expected_state_version": 0, "expected_thread_generation": baseline["thread_generation"]}
                and type(lease.get("fencing_token")) is int and lease["fencing_token"] > 0
                and _timestamp(lease["expires_at"], "lease_expired", "$.baseline.lease.expires_at") > _timestamp(now, "lease_expired", "$.now")
                and selection["thread_generation"] == baseline["thread_generation"]
                and selection["in_flight"] is False
                and set(baseline["capability_ids"]) == REQUIRED_ADMISSION_CAPABILITIES
            )
            if current:
                controls["run"] = _control(True, "authenticated baseline grant and current fence")
                controls["select"] = _control(True, "authenticated baseline selection is current")
        return controls
    if record["pending_submission"] is not None:
        for name in ("run", "cancel", "recover", "select"):
            controls[name] = _control(False, "dispatch outcome unknown; status reconciliation required")
        return controls
    receipt = record["effect_receipt"]
    request = record["effect_request"]
    lease = request["lease"]
    current = (
        type(lease.get("fencing_token")) is int and lease["fencing_token"] > 0
        and _timestamp(lease["expires_at"], "lease_expired", "$.record.effect_request.lease.expires_at") > _timestamp(now, "lease_expired", "$.now")
        and receipt["state_version_after"] == record["binding_state_version"]
        and request["cas"]["expected_thread_generation"] == request["thread_snapshot"]["generation"]
    )
    if not current:
        return controls
    state = receipt["post_state"]
    if state == "running" and receipt["action_receipt"] is not None:
        controls["cancel"] = _control(True, "canonical running receipt and current fence")
    recovery = record["recovery"]
    if state == "execution_unknown" and receipt["action_receipt"] is None and recovery["reconciliation_observed"] is True and recovery["reconciliation_receipt_sha256"] is not None and recovery["no_successor"] is True and recovery["successor_run_id"] is None and isinstance(recovery.get("fresh_lease_id"), str) and type(recovery.get("fresh_fencing_token")) is int and recovery["fresh_fencing_token"] > lease["fencing_token"]:
        controls["recover"] = _control(True, "reconciled unknown with fresh successor fence")
    selection = record["selection"]
    if state not in {"running", "execution_unknown", "cancel_requested"} and selection["thread_generation"] == request["thread_snapshot"]["generation"] == request["cas"]["expected_thread_generation"] and selection["in_flight"] is False:
        controls["select"] = _control(True, "selection generation current and no in-flight run")
    return controls


def _build_projection_for_test(
    *, workspace_id: str, source_sha256: str, candidate_sha256: str,
    service_instance_id: str, projection_id: str, view_nonce: str,
    issued_at: str, expires_at: str, record: dict[str, Any] | None,
    admission: dict[str, Any] | None, sealer: Callable[[dict[str, Any]], str] | None,
    baseline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    for value, path in ((projection_id, "$.projection_id"), (view_nonce, "$.view_nonce")):
        _identifier(value, "projection_shape_invalid", path)
    controls = _derive_controls(record, admission, issued_at, baseline)
    artifact_refs = {
        "standalone_responses_request_v1": None,
        "effect_kernel_request_v1": None,
        "effect_kernel_receipt_v1": None,
        "effect_kernel_action_receipt_v1": None,
        "standalone_responses_bridge_receipt_v1": None,
    }
    selection = None
    run = {"run_id": None, "lifecycle": "unavailable", "fencing_token": None, "predecessor_run_id": None, "successor_run_id": None}
    state_version = 0
    state_sha = gateway.ZERO_SHA256
    if record is None and baseline is not None:
        selection = copy.deepcopy(baseline["selection"])
        state_version = baseline["effect_state_version"]
        state_sha = baseline["effect_state_sha256"]
        run = {"run_id": None, "lifecycle": "absent", "fencing_token": baseline["lease"]["fencing_token"], "predecessor_run_id": None, "successor_run_id": None}
    if record is not None:
        receipt = record["effect_receipt"]
        action = receipt["action_receipt"]
        artifact_refs = {
            "standalone_responses_request_v1": presets.digest(record["responses_request"]),
            "effect_kernel_request_v1": record["effect_request"]["request_sha256"],
            "effect_kernel_receipt_v1": receipt["receipt_sha256"],
            "effect_kernel_action_receipt_v1": None if action is None else action["receipt_sha256"],
            "standalone_responses_bridge_receipt_v1": None if record["bridge_receipt"] is None else record["bridge_receipt"]["receipt_sha256"],
        }
        selection = copy.deepcopy(record["selection"])
        run = {
            "run_id": receipt["run_id"], "lifecycle": receipt["post_state"],
            "fencing_token": receipt["lease"]["fencing_token"],
            "predecessor_run_id": record["effect_request"]["run"]["predecessor_run_id"],
            "successor_run_id": None if record["effect_request"]["operation"] == "recover" else record["recovery"].get("successor_run_id"),
        }
        state_version = record["binding_state_version"]
        state_sha = record["record_sha256"]
    projection = {
        "schema_version": 1, "artifact_type": PROJECTION_TYPE,
        "projection_id": projection_id, "service_instance_id": service_instance_id,
        "workspace_id": workspace_id, "source_sha256": source_sha256,
        "candidate_sha256": candidate_sha256,
        "binding_state_version": state_version, "binding_state_sha256": state_sha,
        "selection": selection, "run": run, "artifact_refs": artifact_refs,
        "controls": controls,
        "claims": {
            "source_local": True, "capability_admitted": admission is not None,
            "installed": "unknown", "live": "unknown", "provider": "unknown",
            "browser": "unknown", "aol": "unavailable",
        },
        "issued_at": issued_at, "expires_at": expires_at,
        "view_nonce": view_nonce, "projection_sha256": "",
        "projection_receipt": None,
    }
    body = {key: item for key, item in projection.items() if key not in {"projection_sha256", "projection_receipt"}}
    projection["projection_sha256"] = digest(body)
    if admission is not None:
        if sealer is None or not callable(sealer):
            raise BindingError("production_capability_unavailable", "$.projection_receipt")
        seal_context = {
            "projection_sha256": projection["projection_sha256"],
            "admission_id": admission["admission_id"],
            "workspace_id": workspace_id, "source_sha256": source_sha256,
            "candidate_sha256": candidate_sha256,
            "expires_at": expires_at,
        }
        try:
            seal = sealer(copy.deepcopy(seal_context))
        except Exception as exc:
            raise BindingError("projection_not_authorized", "$.projection_receipt") from exc
        _sha(seal, "projection_not_authorized", "$.projection_receipt.seal")
        projection["projection_receipt"] = {
            "schema_version": 1, "artifact_type": PROJECTION_RECEIPT_TYPE,
            "projection_sha256": seal_context["projection_sha256"],
            "admission_id": seal_context["admission_id"],
            "workspace_id": seal_context["workspace_id"],
            "candidate_sha256": seal_context["candidate_sha256"],
            "expires_at": seal_context["expires_at"], "seal": seal,
        }
    return projection


def _build_projection_with_bundle(
    *, workspace_id: str, source_sha256: str, candidate_sha256: str,
    service_instance_id: str, projection_id: str, view_nonce: str,
    issued_at: str, expires_at: str, record: dict[str, Any] | None,
    admission: dict[str, Any] | None, baseline_bundle: Mapping[str, Any],
    sealer: Callable[[dict[str, Any]], str] | None = None,
) -> dict[str, Any]:
    """Production projection using only the package-owned projection sealer."""
    baseline = None
    if admission is not None and record is None:
        try:
            baseline = package_host.read_projection_baseline(
                {"workspace_id": workspace_id, "source_sha256": source_sha256, "candidate_sha256": candidate_sha256},
                admission["admission_id"], issued_at,
            )
            fields = {"selection", "selection_sha256", "effect_state_version", "effect_state_sha256", "thread_generation", "lease", "cas", "capability_ids", "action_id", "tool_id", "transport", "expires_at", "baseline_sha256"}
            baseline = _closed(baseline, fields, "baseline_grant_invalid", "$.baseline")
            if baseline["baseline_sha256"] != digest({key: item for key, item in baseline.items() if key != "baseline_sha256"}) or baseline["selection_sha256"] != digest(baseline["selection"]) or baseline["expires_at"] != baseline["lease"].get("expires_at"):
                raise BindingError("baseline_grant_invalid", "$.baseline")
            presets.validate_selection(baseline["selection"], baseline_bundle)
        except (package_host.HostCapabilityError, presets.PresetError) as exc:
            raise BindingError("production_capability_unavailable", "$.baseline") from exc
    return _build_projection_for_test(
        workspace_id=workspace_id, source_sha256=source_sha256,
        candidate_sha256=candidate_sha256, service_instance_id=service_instance_id,
        projection_id=projection_id, view_nonce=view_nonce, issued_at=issued_at,
        expires_at=expires_at, record=record, admission=admission,
        sealer=sealer or _PACKAGE_PROJECTION_SEALER, baseline=baseline,
    )


def build_projection(
    *, workspace_id: str, source_sha256: str, candidate_sha256: str,
    service_instance_id: str, projection_id: str, view_nonce: str,
    issued_at: str, expires_at: str, record: dict[str, Any] | None,
    admission: dict[str, Any] | None,
) -> dict[str, Any]:
    """Preserved V1 projection using the immutable legacy singleton bundle."""
    return _build_projection_with_bundle(
        workspace_id=workspace_id, source_sha256=source_sha256,
        candidate_sha256=candidate_sha256, service_instance_id=service_instance_id,
        projection_id=projection_id, view_nonce=view_nonce, issued_at=issued_at,
        expires_at=expires_at, record=record, admission=admission,
        baseline_bundle=presets.DEFAULT_PRESET_BUNDLE,
    )


def _control_grant(operation: str, provenance: str, issued_at: str, expires_at: str, **values: Any) -> dict[str, Any]:
    row = {field: None for field in CONTROL_GRANT_FIELDS}
    row.update({"operation": operation, "provenance": provenance, "issued_at": issued_at, "expires_at": expires_at})
    row.update(values)
    seed = digest({key: item for key, item in row.items() if key not in {"grant_id", "grant_sha256"}})
    row["grant_id"] = "control-" + seed[7:23]
    row["grant_sha256"] = digest({key: item for key, item in row.items() if key != "grant_sha256"})
    return row


def _derive_control_authority(
    projection: dict[str, Any], admission: dict[str, Any] | None,
    effect_state: dict[str, Any] | None, baseline: dict[str, Any] | None,
    record: dict[str, Any] | None, catalog_receipt: dict[str, Any] | None,
    head: dict[str, Any] | None, supervision: dict[str, Any],
    recovery_grant: dict[str, Any] | None, issued_at: str, expires_at: str,
) -> dict[str, Any] | None:
    if admission is None or effect_state is None or catalog_receipt is None or head is None or supervision.get("state") != "verified":
        return None
    try:
        state = gateway.verify_effect_state(effect_state)
        if state["workspace_id"] != projection["workspace_id"] or head["selection_sha256"] != digest(head["selection"]):
            return None
        fact_expiries = [expires_at, admission["expires_at"], catalog_receipt["expires_at"], head["expires_at"], supervision["receipt"]["expires_at"]]
        authority_expires = min(fact_expiries)
        if _timestamp(authority_expires, "control_authority_stale", "$.control_authority.expires_at") <= _timestamp(issued_at, "control_authority_stale", "$.control_authority.issued_at"):
            return None
        common = {
            "catalog_receipt_sha256": catalog_receipt["receipt_sha256"],
            "bundle_sha256": catalog_receipt["bundle_sha256"],
            "bundle_generation": catalog_receipt["bundle"]["generation"],
            "selection_head_receipt_sha256": head["receipt_sha256"],
        }
        grants = {name: None for name in ("run", "cancel", "recover", "select")}
        if record is None and baseline is not None and state["state_version"] == 0 and not state["runs"] and baseline["effect_state_version"] == 0 and baseline["effect_state_sha256"] == gateway.ZERO_SHA256 and baseline["selection"] == head["selection"]:
            lease = baseline["lease"]
            if lease["expires_at"] > issued_at and baseline["cas"] == {"expected_state_version": 0, "expected_thread_generation": head["selection"]["thread_generation"]}:
                grants["run"] = _control_grant(
                    "run", "authenticated_baseline", issued_at, min(authority_expires, lease["expires_at"]),
                    run_id=None, predecessor_run_id=None, successor_run_id=None,
                    effect_operation=None, lease_id=lease["lease_id"], fencing_token=lease["fencing_token"],
                    lease_expires_at=lease["expires_at"], cas_expected_state_version=0,
                    cas_expected_thread_generation=head["selection"]["thread_generation"],
                    authority_receipt_sha256=None, effect_request_sha256=None,
                    effect_receipt_sha256=None, action_receipt_sha256=None,
                    bridge_receipt_sha256=None, cancel_observed=False, recovery=None, **common,
                )
        if record is not None:
            request, receipt = record["effect_request"], record["effect_receipt"]
            run = state["runs"].get(receipt["run_id"])
            exact = (
                run is not None
                and state["state_version"] == record["binding_state_version"] == receipt["state_version_after"]
                and state["receipt_index"].get(receipt["receipt_sha256"]) == receipt
                and state["thread_generation"] == request["thread_snapshot"]["generation"] == run["thread_generation"]
                and run["request_sha256"] == request["request_sha256"]
                and run["lease"] == request["lease"]
                and record["selection"]["preset_id"] == request["preset_snapshot"]["preset_id"]
            )
            refs = projection["artifact_refs"]
            if exact and run["lifecycle"] == "running" and run["successor_run_id"] is None and request["lease"]["expires_at"] > issued_at and receipt["action_receipt"] is not None:
                grants["cancel"] = _control_grant(
                    "cancel", "canonical_running_state", issued_at, min(authority_expires, request["lease"]["expires_at"]),
                    run_id=run["run_id"], predecessor_run_id=run["predecessor_run_id"], successor_run_id=None,
                    effect_operation=request["operation"], lease_id=run["lease"]["lease_id"], fencing_token=run["lease"]["fencing_token"], lease_expires_at=run["lease"]["expires_at"],
                    cas_expected_state_version=state["state_version"], cas_expected_thread_generation=state["thread_generation"],
                    authority_receipt_sha256=request["authority_receipt"]["receipt_sha256"], effect_request_sha256=refs["effect_kernel_request_v1"], effect_receipt_sha256=refs["effect_kernel_receipt_v1"], action_receipt_sha256=refs["effect_kernel_action_receipt_v1"], bridge_receipt_sha256=refs["standalone_responses_bridge_receipt_v1"], cancel_observed=False, recovery=copy.deepcopy(run["recovery_provenance"]), **common,
                )
            recovery = record["recovery"]
            if exact and run["lifecycle"] == "execution_unknown" and receipt["action_receipt"] is None and run["successor_run_id"] is None and recovery["reconciliation_observed"] is True and recovery["reconciliation_receipt_sha256"] is not None and recovery_grant is not None and recovery_grant["predecessor_run_id"] == run["run_id"] and recovery_grant["predecessor_effect_request_sha256"] == request["request_sha256"] and recovery_grant["predecessor_effect_receipt_sha256"] == receipt["receipt_sha256"] and recovery_grant["reconciliation_receipt_sha256"] == recovery["reconciliation_receipt_sha256"] and recovery_grant["expected_cas"] == {"expected_state_version": state["state_version"], "expected_thread_generation": state["thread_generation"]}:
                lease = recovery_grant["fresh_lease"]
                grants["recover"] = _control_grant(
                    "recover", "host_recovery_lease_grant", issued_at, min(authority_expires, recovery_grant["expires_at"], lease["expires_at"]),
                    run_id=run["run_id"], predecessor_run_id=run["run_id"], successor_run_id=None,
                    effect_operation="recover", lease_id=lease["lease_id"], fencing_token=lease["fencing_token"], lease_expires_at=lease["expires_at"],
                    cas_expected_state_version=recovery_grant["expected_cas"]["expected_state_version"], cas_expected_thread_generation=recovery_grant["expected_cas"]["expected_thread_generation"],
                    authority_receipt_sha256=None, effect_request_sha256=refs["effect_kernel_request_v1"], effect_receipt_sha256=refs["effect_kernel_receipt_v1"], action_receipt_sha256=None, bridge_receipt_sha256=None, cancel_observed=False, recovery=copy.deepcopy(recovery_grant), **common,
                )
        no_inflight = not any(run["lifecycle"] in {"running", "cancel_requested", "execution_unknown"} for run in state["runs"].values())
        if no_inflight and len(catalog_receipt["bundle"]["presets"]) > 1 and head["selection"]["in_flight"] is False:
            grants["select"] = _control_grant(
                "select", "host_selection_head", issued_at, authority_expires,
                run_id=None, predecessor_run_id=None, successor_run_id=None, effect_operation=None,
                lease_id=None, fencing_token=None, lease_expires_at=None,
                cas_expected_state_version=state["state_version"], cas_expected_thread_generation=head["selection"]["thread_generation"],
                authority_receipt_sha256=None, effect_request_sha256=None, effect_receipt_sha256=None, action_receipt_sha256=None, bridge_receipt_sha256=None, cancel_observed=False, recovery=None, **common,
            )
        authority = {
            "schema_version": 1, "artifact_type": CONTROL_AUTHORITY_TYPE,
            "workspace_id": projection["workspace_id"], "source_sha256": projection["source_sha256"], "candidate_sha256": projection["candidate_sha256"],
            "service_instance_id": projection["service_instance_id"], "admission_id": admission["admission_id"], "admission_seal_sha256": admission["seal"],
            "binding_state_version": projection["binding_state_version"], "binding_state_sha256": projection["binding_state_sha256"], "selection_sha256": head["selection_sha256"],
            "effect_state_version": state["state_version"], "effect_state_sha256": state["state_sha256"], "grants": grants,
            "issued_at": issued_at, "expires_at": authority_expires, "authority_sha256": "", "sealed_by": "projection_receipt_v1",
        }
        authority["authority_sha256"] = digest({key: item for key, item in authority.items() if key != "authority_sha256"})
        return authority
    except (BindingError, gateway.GatewayError, KeyError, TypeError, ValueError):
        return None


def _derive_v3_recovered_cancel(
    state: dict[str, Any], record: dict[str, Any], grant: dict[str, Any],
) -> dict[str, Any] | None:
    """Reconstruct successor Cancel provenance from verified persisted state only."""
    request, receipt = record["effect_request"], record["effect_receipt"]
    successor = state["runs"].get(receipt.get("run_id"))
    if successor is None or successor.get("lifecycle") != "running" or request.get("operation") != "recover":
        return None
    provenance = successor.get("recovery_provenance")
    if not isinstance(provenance, dict) or set(provenance) != gateway.RECOVERY_PROVENANCE_FIELDS:
        return None
    if (
        successor.get("request_sha256") != request.get("request_sha256")
        or receipt.get("run_id") != successor.get("run_id")
        or state["receipt_index"].get(receipt.get("receipt_sha256")) != receipt
        or record.get("binding_state_version") != state.get("state_version")
        or provenance.get("predecessor_run_id") != successor.get("predecessor_run_id")
        or provenance.get("predecessor_run_id") is None
        or request.get("run", {}).get("predecessor_run_id") != provenance.get("predecessor_run_id")
        or request.get("cas") != provenance.get("expected_cas")
    ):
        return None
    predecessor = state["runs"].get(provenance["predecessor_run_id"])
    predecessor_receipt = state["receipt_index"].get(provenance["predecessor_effect_receipt_sha256"])
    if predecessor is None or predecessor_receipt is None:
        return None
    if (
        predecessor.get("run_id") != provenance["predecessor_run_id"]
        or predecessor.get("request_sha256") != provenance["predecessor_effect_request_sha256"]
        or predecessor.get("successor_run_id") != successor.get("run_id")
        or predecessor_receipt.get("run_id") != predecessor.get("run_id")
        or predecessor_receipt.get("receipt_sha256") != provenance["predecessor_effect_receipt_sha256"]
    ):
        return None
    commitments = []
    for item in state["idempotency_index"].values():
        if (
            item.get("request_sha256") == request.get("request_sha256")
            and item.get("receipt_sha256") == receipt.get("receipt_sha256")
            and item.get("recovery_grant_id") == provenance.get("grant_id")
            and item.get("recovery_grant_sha256") == provenance.get("grant_sha256")
            and item.get("recovery_provenance") == provenance
            and item.get("recovery_provenance_sha256") == digest(provenance)
        ):
            commitments.append(item)
    if len(commitments) != 1 or state["idempotency_index"].get(request.get("idempotency_key")) != commitments[0]:
        return None
    predecessor_lease = predecessor.get("lease")
    successor_lease = successor.get("lease")
    if not isinstance(predecessor_lease, dict) or not isinstance(successor_lease, dict):
        return None
    if (
        predecessor_lease.get("lease_id") == successor_lease.get("lease_id")
        or successor_lease.get("fencing_token", 0) <= predecessor_lease.get("fencing_token", 0)
        or successor_lease != request.get("lease")
    ):
        return None
    return {
        **copy.deepcopy(provenance),
        "predecessor_lease": copy.deepcopy(predecessor_lease),
        "predecessor_effect_receipt": copy.deepcopy(predecessor_receipt),
    }


def _derive_control_authority_v3(
    projection: dict[str, Any], admission: dict[str, Any] | None,
    effect_state: dict[str, Any] | None, baseline: dict[str, Any] | None,
    record: dict[str, Any] | None, catalog_receipt: dict[str, Any] | None,
    head: dict[str, Any] | None, supervision: dict[str, Any],
    recovery_grant: dict[str, Any] | None, issued_at: str, expires_at: str,
) -> dict[str, Any] | None:
    authority = _derive_control_authority(
        projection, admission, effect_state, baseline, record, catalog_receipt,
        head, supervision, recovery_grant, issued_at, expires_at,
    )
    if authority is None or record is None or authority["grants"].get("cancel") is None:
        return authority
    try:
        state = gateway.verify_effect_state(effect_state)
        cancel = authority["grants"]["cancel"]
        request, receipt = record["effect_request"], record["effect_receipt"]
        run = state["runs"].get(receipt["run_id"])
        if run is None or run.get("predecessor_run_id") is None:
            cancel["effect_operation"] = "run"
            cancel["recovery"] = None
        else:
            recovery = _derive_v3_recovered_cancel(state, record, cancel)
            if recovery is None:
                authority["grants"]["cancel"] = None
            else:
                cancel["effect_operation"] = "recover"
                cancel["cas_expected_state_version"] = recovery["expected_cas"]["expected_state_version"]
                cancel["cas_expected_thread_generation"] = recovery["expected_cas"]["expected_thread_generation"]
                cancel["recovery"] = recovery
                cancel["grant_sha256"] = digest({key: item for key, item in cancel.items() if key != "grant_sha256"})
    except (BindingError, gateway.GatewayError, KeyError, TypeError, ValueError):
        authority["grants"]["cancel"] = None
    authority["authority_sha256"] = digest({key: item for key, item in authority.items() if key != "authority_sha256"})
    return authority


def build_projection_v2(
    *, workspace_id: str, source_sha256: str, candidate_sha256: str,
    service_instance_id: str, projection_id: str, view_nonce: str,
    issued_at: str, expires_at: str, record: dict[str, Any] | None,
    admission: dict[str, Any] | None, _effect_state: dict[str, Any] | None = None,
    _recovery_grant: dict[str, Any] | None = None, sealer: Callable[[dict[str, Any]], str] | None = None,
) -> dict[str, Any]:
    """Add externally authenticated supervision as a veto-only V2 fact."""
    control_baseline = None
    if admission is not None and record is None:
        try:
            control_baseline = package_host.read_projection_baseline(
                {"workspace_id": workspace_id, "source_sha256": source_sha256, "candidate_sha256": candidate_sha256},
                admission["admission_id"], issued_at,
            )
        except package_host.HostCapabilityError:
            control_baseline = None
    catalog = {"state": "unavailable", "reason": "preset_catalog_unavailable", "receipt_sha256": None, "bundle_sha256": None, "generation": None, "presets": []}
    catalog_receipt = None
    host_identity = {"workspace_id": workspace_id, "source_sha256": source_sha256, "candidate_sha256": candidate_sha256}
    if admission is not None:
        state_version = 0 if record is None else record["binding_state_version"]
        state_sha = gateway.ZERO_SHA256 if record is None else record["record_sha256"]
        catalog_body = {"admission_id": admission["admission_id"], "service_instance_id": service_instance_id, "binding_state_version": state_version, "binding_state_sha256": state_sha, "selector": "current", "bundle_sha256": None, "now": issued_at}
        try:
            catalog_receipt = package_host.read_operator_preset_bundle(host_identity, catalog_body)
            bundle = presets.validate_bundle(catalog_receipt["bundle"])
            catalog = {
                "state": "verified", "reason": None,
                "receipt_sha256": catalog_receipt["receipt_sha256"],
                "bundle_sha256": bundle["bundle_sha256"],
                "generation": bundle["generation"],
                "presets": [{key: item[key] for key in ("preset_id", "family_id", "role")} for item in bundle["presets"]],
            }
        except (package_host.HostCapabilityError, presets.PresetError) as exc:
            catalog = {"state": "unavailable", "reason": getattr(exc, "code", "preset_catalog_unavailable"), "receipt_sha256": None, "bundle_sha256": None, "generation": None, "presets": []}
    projection = _build_projection_with_bundle(
        workspace_id=workspace_id, source_sha256=source_sha256,
        candidate_sha256=candidate_sha256, service_instance_id=service_instance_id,
        projection_id=projection_id, view_nonce=view_nonce, issued_at=issued_at,
        expires_at=expires_at, record=record, admission=admission,
        baseline_bundle=presets.DEFAULT_PRESET_BUNDLE if catalog_receipt is None else catalog_receipt["bundle"],
        sealer=sealer or _PACKAGE_PROJECTION_SEALER,
    )
    active_selection = {"state": "unavailable", "reason": "selection_head_unavailable", "head": None}
    if admission is not None:
        head_body = {"admission_id": admission["admission_id"], "service_instance_id": service_instance_id, "binding_state_version": projection["binding_state_version"], "binding_state_sha256": projection["binding_state_sha256"], "now": issued_at}
        try:
            head = package_host.read_operator_selection_head(
                {"workspace_id": workspace_id, "source_sha256": source_sha256, "candidate_sha256": candidate_sha256}, head_body,
            )
            if catalog_receipt is None or head["catalog_receipt_sha256"] != catalog_receipt["receipt_sha256"] or head["bundle_sha256"] != catalog_receipt["bundle_sha256"] or head["bundle_generation"] != catalog_receipt["bundle"]["generation"]:
                raise BindingError("selection_catalog_mismatch", "$.active_selection")
            presets.validate_selection(head["selection"], catalog_receipt["bundle"])
            active_selection = {"state": "verified", "reason": None, "head": head}
        except (package_host.HostCapabilityError, presets.PresetError, BindingError) as exc:
            active_selection = {"state": "unavailable", "reason": getattr(exc, "code", "selection_head_unavailable"), "head": None}
    artifact_sha = None if projection["selection"] is None else digest(projection["selection"])
    active_sha = None if active_selection["head"] is None else active_selection["head"]["selection_sha256"]
    artifact_selection = {"selection_sha256": artifact_sha, "relation": "unavailable" if active_sha is None or artifact_sha is None else ("current" if active_sha == artifact_sha else "historical")}
    if active_selection["state"] != "verified":
        projection["controls"]["run"] = _control(False, active_selection["reason"])
        projection["controls"]["select"] = _control(False, active_selection["reason"])
    if catalog["state"] != "verified":
        projection["controls"]["run"] = _control(False, catalog["reason"])
        projection["controls"]["select"] = _control(False, catalog["reason"])
    elif len(catalog["presets"]) == 1:
        projection["controls"]["select"] = _control(False, "preset_catalog_singleton")
    supervision = {"state": "unavailable", "reason": "supervision_unavailable", "receipt": None}
    selection = None if active_selection["head"] is None else active_selection["head"]["selection"]
    if admission is not None and selection is not None:
        body = {
            "admission_id": admission["admission_id"],
            "service_instance_id": service_instance_id,
            "binding_state_version": projection["binding_state_version"],
            "binding_state_sha256": projection["binding_state_sha256"],
            "runtime_thread_id": selection["thread_id"],
            "runtime_thread_generation": selection["thread_generation"],
            "selection_sha256": digest(selection), "now": issued_at,
        }
        try:
            supervision = package_host.read_operator_supervision(
                host_identity, body,
            )
        except package_host.HostCapabilityError as exc:
            supervision = {"state": "unavailable", "reason": exc.code, "receipt": None}
    if supervision["state"] != "verified":
        reason = supervision["reason"] or "supervision_unavailable"
        for name in ("run", "cancel", "recover", "select"):
            projection["controls"][name] = _control(False, reason)
    control_authority = _derive_control_authority(
        projection, admission, _effect_state, control_baseline,
        record, catalog_receipt, active_selection["head"], supervision,
        _recovery_grant, issued_at, expires_at,
    )
    for name in ("run", "cancel", "recover", "select"):
        grant = None if control_authority is None else control_authority["grants"][name]
        if grant is None:
            prior = projection["controls"][name]
            projection["controls"][name] = _control(False, prior["reason"] if prior["enabled"] is False else "sealed control authority unavailable")
        else:
            reasons = {
                "run": "authenticated baseline grant and current fence",
                "cancel": "canonical running receipt and current fence",
                "recover": "reconciled unknown with fresh successor fence",
                "select": "selection generation current and no in-flight run",
            }
            projection["controls"][name] = _control(True, reasons[name])
    supervision_token = supervision["receipt"]["snapshot_sha256"] if supervision["state"] == "verified" else digest(supervision)
    identity_seed = digest({"projection_id": projection["projection_id"], "view_nonce": projection["view_nonce"], "supervision": supervision_token, "active_selection": None if active_selection["head"] is None else active_selection["head"]["receipt_sha256"], "preset_catalog": catalog["receipt_sha256"], "control_authority": None if control_authority is None else control_authority["authority_sha256"]})
    projection["schema_version"] = 2
    projection["artifact_type"] = PROJECTION_V2_TYPE
    projection["projection_id"] = "projection-" + identity_seed[7:23]
    projection["view_nonce"] = "view-" + identity_seed[23:39]
    projection["supervision"] = copy.deepcopy(supervision)
    projection["active_selection"] = copy.deepcopy(active_selection)
    projection["artifact_selection"] = artifact_selection
    projection["preset_catalog"] = catalog
    projection["control_authority"] = copy.deepcopy(control_authority)
    body = {key: item for key, item in projection.items() if key not in {"projection_sha256", "projection_receipt"}}
    projection["projection_sha256"] = digest(body)
    if admission is None:
        projection["projection_receipt"] = None
        return projection
    context = {
        "projection_sha256": projection["projection_sha256"],
        "admission_id": admission["admission_id"], "workspace_id": workspace_id,
        "source_sha256": source_sha256, "candidate_sha256": candidate_sha256,
        "expires_at": expires_at,
    }
    seal = (sealer or _PACKAGE_PROJECTION_SEALER)(context)
    projection["projection_receipt"] = {
        "schema_version": 1, "artifact_type": PROJECTION_RECEIPT_TYPE,
        "projection_sha256": projection["projection_sha256"],
        "admission_id": admission["admission_id"], "workspace_id": workspace_id,
        "candidate_sha256": candidate_sha256, "expires_at": expires_at, "seal": seal,
    }
    return projection


def build_projection_v3(
    *, workspace_id: str, source_sha256: str, candidate_sha256: str,
    service_instance_id: str, projection_id: str, view_nonce: str,
    issued_at: str, expires_at: str, record: dict[str, Any] | None,
    admission: dict[str, Any] | None, _effect_state: dict[str, Any] | None = None,
    _recovery_grant: dict[str, Any] | None = None, sealer: Callable[[dict[str, Any]], str] | None = None,
) -> dict[str, Any]:
    """Current projection ABI; V2 remains available only as historical ABI."""
    projection = build_projection_v2(
        workspace_id=workspace_id, source_sha256=source_sha256,
        candidate_sha256=candidate_sha256, service_instance_id=service_instance_id,
        projection_id=projection_id, view_nonce=view_nonce, issued_at=issued_at,
        expires_at=expires_at, record=record, admission=admission,
        _effect_state=_effect_state, _recovery_grant=_recovery_grant, sealer=sealer,
    )
    projection["schema_version"] = 3
    projection["artifact_type"] = PROJECTION_V3_TYPE
    # V2 has already derived the complete baseline/select/recover authority
    # from canonical host facts. Upgrade only successor Cancel from persisted
    # state-v2 lineage; do not reconstruct authority from presentation data.
    control_authority = copy.deepcopy(projection.get("control_authority"))
    if control_authority is not None and record is not None and _effect_state is not None:
        try:
            state = gateway.verify_effect_state(_effect_state)
            cancel = control_authority["grants"].get("cancel")
            run = None if cancel is None else state["runs"].get(cancel.get("run_id"))
            if cancel is not None and run is not None and run.get("predecessor_run_id") is not None:
                recovery = _derive_v3_recovered_cancel(state, record, cancel)
                if recovery is None:
                    control_authority["grants"]["cancel"] = None
                else:
                    cancel["effect_operation"] = "recover"
                    cancel["cas_expected_state_version"] = recovery["expected_cas"]["expected_state_version"]
                    cancel["cas_expected_thread_generation"] = recovery["expected_cas"]["expected_thread_generation"]
                    cancel["recovery"] = recovery
                    cancel["grant_sha256"] = digest({key: item for key, item in cancel.items() if key != "grant_sha256"})
            control_authority["authority_sha256"] = digest({key: item for key, item in control_authority.items() if key != "authority_sha256"})
        except (BindingError, gateway.GatewayError, KeyError, TypeError, ValueError):
            control_authority["grants"]["cancel"] = None
            control_authority["authority_sha256"] = digest({key: item for key, item in control_authority.items() if key != "authority_sha256"})
    reasons = {
        "run": "authenticated baseline grant and current fence",
        "cancel": "canonical running receipt and current fence",
        "recover": "reconciled unknown with fresh successor fence",
        "select": "selection generation current and no in-flight run",
    }
    for name in ("run", "cancel", "recover", "select"):
        grant = None if control_authority is None else control_authority["grants"].get(name)
        projection["controls"][name] = _control(
            grant is not None,
            reasons[name] if grant is not None else "sealed control authority unavailable",
        )
    supervision_token = projection["supervision"]["receipt"]["snapshot_sha256"] if projection["supervision"]["state"] == "verified" else digest(projection["supervision"])
    identity_seed = digest({
        "projection_id": projection["projection_id"], "view_nonce": projection["view_nonce"],
        "supervision": supervision_token,
        "active_selection": None if projection["active_selection"]["head"] is None else projection["active_selection"]["head"]["receipt_sha256"],
        "preset_catalog": projection["preset_catalog"]["receipt_sha256"],
        "control_authority": None if control_authority is None else control_authority["authority_sha256"],
        "artifact_type": PROJECTION_V3_TYPE,
    })
    projection["projection_id"] = "projection-" + identity_seed[7:23]
    projection["view_nonce"] = "view-" + identity_seed[23:39]
    projection["control_authority"] = copy.deepcopy(control_authority)
    projection["projection_sha256"] = digest({key: item for key, item in projection.items() if key not in {"projection_sha256", "projection_receipt"}})
    if admission is None:
        projection["projection_receipt"] = None
        return projection
    context = {
        "projection_sha256": projection["projection_sha256"],
        "admission_id": admission["admission_id"], "workspace_id": workspace_id,
        "source_sha256": source_sha256, "candidate_sha256": candidate_sha256,
        "expires_at": expires_at,
    }
    projection["projection_receipt"] = {
        "schema_version": 1, "artifact_type": PROJECTION_RECEIPT_TYPE,
        "projection_sha256": projection["projection_sha256"],
        "admission_id": admission["admission_id"], "workspace_id": workspace_id,
        "candidate_sha256": candidate_sha256, "expires_at": expires_at,
        "seal": (sealer or _PACKAGE_PROJECTION_SEALER)(context),
    }
    return projection


def validate_transport_receipt(value: Any) -> dict[str, Any]:
    row = _closed(value, TRANSPORT_RECEIPT_FIELDS, "transport_receipt_invalid", "$.transport_receipt")
    if row["schema_version"] != 1 or row["artifact_type"] != TRANSPORT_RECEIPT_TYPE:
        raise BindingError("transport_receipt_invalid", "$.transport_receipt")
    _identifier(row["submission_id"], "transport_receipt_invalid", "$.transport_receipt.submission_id")
    if row["transport_accepted"] is not True or row["effect_outcome"] != "unknown_until_status_refresh" or row["optimistic_state_change"] is not False:
        raise BindingError("transport_receipt_invalid", "$.transport_receipt")
    return row


def validate_selection_transport_receipt(value: Any) -> dict[str, Any]:
    row = _closed(value, SELECTION_TRANSPORT_RECEIPT_FIELDS, "transport_receipt_invalid", "$.transport_receipt")
    if row["schema_version"] != 1 or row["artifact_type"] != SELECTION_TRANSPORT_RECEIPT_TYPE:
        raise BindingError("transport_receipt_invalid", "$.transport_receipt")
    _identifier(row["submission_id"], "transport_receipt_invalid", "$.transport_receipt.submission_id")
    _sha(row["selection_mutation_receipt_sha256"], "transport_receipt_invalid", "$.transport_receipt.selection_mutation_receipt_sha256")
    if row["transport_accepted"] is not True or row["selection_outcome"] != "unknown_until_status_refresh" or row["optimistic_state_change"] is not False:
        raise BindingError("transport_receipt_invalid", "$.transport_receipt")
    return row


def validate_submission_shape(value: Any) -> dict[str, Any]:
    row = _closed(value, SUBMISSION_FIELDS, "control_submission_invalid", "$.submission")
    if row["schema_version"] != 1 or row["artifact_type"] != SUBMISSION_TYPE:
        raise BindingError("control_submission_invalid", "$.submission")
    _identifier(row["submission_id"], "control_submission_invalid", "$.submission.submission_id")
    _sha(row["projection_sha256"], "control_submission_invalid", "$.submission.projection_sha256")
    _identifier(row["view_nonce"], "control_submission_invalid", "$.submission.view_nonce")
    if row["action"] not in {"run", "cancel", "recover", "select"}:
        raise BindingError("control_submission_invalid", "$.submission.action")
    payload_fields = {
        "run": {"message"},
        "cancel": {"run_id", "effect_receipt_sha256", "fencing_token"},
        "recover": {"predecessor_run_id", "predecessor_receipt_sha256", "predecessor_fencing_token"},
        "select": {"preset_id", "expected_generation"},
    }[row["action"]]
    payload = _closed(row["payload"], payload_fields, "control_submission_invalid", "$.submission.payload")
    if row["action"] == "run":
        if not isinstance(payload["message"], str):
            raise BindingError("control_submission_invalid", "$.submission.payload.message")
    elif row["action"] == "cancel":
        _identifier(payload["run_id"], "control_submission_invalid", "$.submission.payload.run_id")
        _sha(payload["effect_receipt_sha256"], "control_submission_invalid", "$.submission.payload.effect_receipt_sha256")
        if type(payload["fencing_token"]) is not int or payload["fencing_token"] < 1:
            raise BindingError("control_submission_invalid", "$.submission.payload.fencing_token")
    elif row["action"] == "recover":
        _identifier(payload["predecessor_run_id"], "control_submission_invalid", "$.submission.payload.predecessor_run_id")
        _sha(payload["predecessor_receipt_sha256"], "control_submission_invalid", "$.submission.payload.predecessor_receipt_sha256")
        if type(payload["predecessor_fencing_token"]) is not int or payload["predecessor_fencing_token"] < 1:
            raise BindingError("control_submission_invalid", "$.submission.payload.predecessor_fencing_token")
    else:
        _identifier(payload["preset_id"], "control_submission_invalid", "$.submission.payload.preset_id")
        if type(payload["expected_generation"]) is not int or payload["expected_generation"] < 1:
            raise BindingError("control_submission_invalid", "$.submission.payload.expected_generation")
    row["payload"] = payload
    digest(row)
    return row


def validate_submission(value: Any, projection: dict[str, Any], record: dict[str, Any] | None, *, now: str | None = None) -> dict[str, Any]:
    row = validate_submission_shape(value)
    instant = now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if _timestamp(projection["expires_at"], "stale_projection", "$.projection.expires_at") <= _timestamp(instant, "stale_projection", "$.now"):
        raise BindingError("stale_projection", "$.submission")
    if row["projection_sha256"] != projection["projection_sha256"] or row["view_nonce"] != projection["view_nonce"]:
        raise BindingError("stale_projection", "$.submission")
    if record is not None and (any(item["submission_id"] == row["submission_id"] for item in record["submission_replays"]) or row["view_nonce"] in record["used_view_nonces"]):
        raise BindingError("control_submission_replay", "$.submission")
    if projection["controls"][row["action"]]["enabled"] is not True:
        raise BindingError("control_not_available", "$.submission.action")
    payload = row["payload"]
    if row["action"] not in {"run", "select"} and record is None:
        raise BindingError("control_not_available", "$.submission.action")
    if row["action"] == "cancel" and (
        payload["run_id"] != record["effect_receipt"]["run_id"]
        or payload["effect_receipt_sha256"] != record["effect_receipt"]["receipt_sha256"]
        or payload["fencing_token"] != record["effect_receipt"]["lease"]["fencing_token"]
    ):
        raise BindingError("control_submission_stale", "$.submission.payload")
    if row["action"] == "recover" and (
        payload["predecessor_run_id"] != record["effect_receipt"]["run_id"]
        or payload["predecessor_receipt_sha256"] != record["effect_receipt"]["receipt_sha256"]
        or payload["predecessor_fencing_token"] != record["effect_receipt"]["lease"]["fencing_token"]
        or record["effect_receipt"]["post_state"] != "execution_unknown"
        or record["recovery"]["no_successor"] is not True
        or record["recovery"]["successor_run_id"] is not None
    ):
        raise BindingError("control_submission_stale", "$.submission.payload")
    if row["action"] == "select":
        active = projection.get("active_selection", {}).get("head")
        catalog = projection.get("preset_catalog", {})
        targets = {item.get("preset_id") for item in catalog.get("presets", []) if isinstance(item, Mapping)}
        if (
            not isinstance(active, Mapping)
            or payload["preset_id"] not in targets
            or payload["preset_id"] == active.get("selection", {}).get("preset_id")
            or payload["expected_generation"] != catalog.get("generation")
            or active.get("selection", {}).get("in_flight") is not False
            or (record is not None and record["effect_receipt"]["post_state"] in {"running", "cancel_requested", "execution_unknown"})
        ):
            raise BindingError("control_submission_stale", "$.submission.payload")
    return row


def apply_transport_acceptance(record_value: Any, submission: dict[str, Any]) -> dict[str, Any]:
    """Record replay state only; this is not an effect or success transition."""
    record = copy.deepcopy(dict(record_value))
    record["used_view_nonces"].append(submission["view_nonce"])
    record["pending_submission"] = {
        "submission_id": submission["submission_id"],
        "submission_sha256": digest(submission),
        "view_nonce": submission["view_nonce"],
        "action": submission["action"],
    }
    record["record_sha256"] = digest({key: item for key, item in record.items() if key != "record_sha256"})
    return record
