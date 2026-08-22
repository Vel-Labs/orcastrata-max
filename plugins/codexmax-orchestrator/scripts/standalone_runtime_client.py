#!/usr/bin/env python3
"""Strict standard-library client for the local standalone runtime read API."""

from __future__ import annotations

import copy
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping

import standalone_runtime_service as runtime_service
import runtime_execution_gateway as effect_gateway
import served_agent_presets as response_bridge


CLIENT_VERSION = 1
SUPPORTED_API_VERSION = "1"
OPENAPI_SHA256 = "bcdb0866999be39c4708c4d13f75d8513136c80603c51eea03646fd57cc9b311"
OPERATIONS = ("inspect", "reconnect", "shutdown")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
LOOPBACK = re.compile(r"^127\.0\.0\.1:([1-9][0-9]{0,4})$")
REQUEST_FIELDS = {"api_version", "workspace_id", "workspace_path_sha256"}
EFFECT_FIELDS = {
    "provider_called", "lease_created", "dispatch_started", "policy_activated",
    "ledger_written", "authority_granted", "acceptance_granted", "installed",
    "daemon_started", "network_bound",
}
FALSE_EFFECTS = {field: False for field in EFFECT_FIELDS}
BASE_RESULT_FIELDS = {
    "service_version", "artifact_type", "operation", "workspace_id",
    "workspace_path_sha256", "runtime_json_sha256", "manifest_sha256",
    "runtime_manifest", "lifecycle", "endpoint", "health", "reconnect",
    "shutdown", "recovery_instructions", "effect_guarantees",
    "runtime_json_written", "side_effect_free",
}
OPERATION_FIELDS = {
    "inspect": set(),
    "reconnect": {"reconnect_requested", "reconnected", "reconnect_observed", "original_client_required"},
    "shutdown": {"shutdown_requested", "shutdown_observed", "persistent_state_changed"},
}
KNOWN_SCHEMAS = {
    "Identifier", "Digest", "Timestamp", "WorkspaceSelection", "EffectGuarantees",
    "RuntimeManifest", "LifecycleResult", "Endpoint", "Health",
    "ReconnectCapability", "ShutdownCapability", "RuntimeResultBase",
    "InspectResult", "ReconnectResult", "ShutdownResult", "RuntimeOperationResult",
    "RuntimeError",
}
RUNTIME_MANIFEST_FIELDS = {
    "runtime_id", "runtime_version", "api_version", "source_sha256",
    "candidate_sha256", "workspace_root_sha256", "isolation_id",
    "process_mode", "endpoint_kind", "supported_transports", "health",
    "degraded_reasons", "recovery_instructions", "mandatory_model_hop",
    "model_can_admit",
}
LIFECYCLE_FIELDS = {"state", "history", "foreground"}
ENDPOINT_FIELDS = {"kind", "address", "local_only", "bound"}
HEALTH_FIELDS = {"status", "provenance", "observed_at", "expires_at", "degraded_reasons"}
RECONNECT_FIELDS = {"supported", "requires_original_client", "instruction"}
SHUTDOWN_FIELDS = {"supported", "mode", "instruction"}
LIFECYCLE_STATES = ("created", "ready", "stopping", "stopped")
LIFECYCLE_TRANSITIONS = {("created", "ready"), ("ready", "stopping"), ("stopping", "stopped")}
ENDPOINT_KINDS = {"unix_socket", "loopback_http"}
TRANSPORTS = {"local_cli", "in_process", "unix_socket", "loopback_http"}
HEALTH_STATUSES = {"healthy", "degraded", "unknown", "unavailable"}


class ClientError(ValueError):
    """Stable client failure with a machine-readable code and source path."""

    def __init__(self, code: str, path: str):
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ClientError("openapi_duplicate_key", key)
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ClientError("openapi_nonfinite_number", value)


def _closed(value: Any, fields: set[str], path: str, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ClientError(code, path)
    unknown = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if unknown:
        raise ClientError(code, f"{path}.{unknown[0]}")
    if missing:
        raise ClientError(code, f"{path}.{missing[0]}")
    return value


def _text(value: Any, path: str, code: str = "response_string_invalid") -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ClientError(code, path)
    return value


def _identifier(value: Any, path: str, code: str = "response_identifier_invalid") -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ClientError(code, path)
    return value


def _digest(value: Any, path: str, code: str = "response_digest_invalid") -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ClientError(code, path)
    return value


def _timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise ClientError("response_timestamp_invalid", path)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ClientError("response_timestamp_invalid", path) from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ClientError("response_timestamp_invalid", path)
    return parsed


def _string_array(
    value: Any,
    path: str,
    *,
    nonempty: bool = False,
    unique: bool = False,
    allowed: set[str] | None = None,
) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise ClientError("response_array_invalid", path)
    result: list[str] = []
    for index, item in enumerate(value):
        text = _text(item, f"{path}[{index}]")
        if allowed is not None and text not in allowed:
            raise ClientError("response_enum_invalid", f"{path}[{index}]")
        result.append(text)
    if unique and len(result) != len(set(result)):
        raise ClientError("response_array_duplicate", path)
    return result


def _const(value: Any, expected: Any, path: str, code: str = "response_const_invalid") -> None:
    if type(value) is not type(expected) or value != expected:
        raise ClientError(code, path)


def _enum(value: Any, allowed: set[str] | tuple[str, ...], path: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ClientError("response_enum_invalid", path)
    return value


def _validate_runtime_manifest(value: Any, workspace_id: str, workspace_digest: str) -> dict[str, Any]:
    path = "$.response.runtime_manifest"
    row = _closed(value, RUNTIME_MANIFEST_FIELDS, path, "response_shape_invalid")
    _identifier(row["runtime_id"], f"{path}.runtime_id")
    _const(row["runtime_version"], "1", f"{path}.runtime_version", "response_version_invalid")
    _const(row["api_version"], SUPPORTED_API_VERSION, f"{path}.api_version", "response_version_invalid")
    for field in ("source_sha256", "candidate_sha256", "workspace_root_sha256"):
        _digest(row[field], f"{path}.{field}")
    _identifier(row["isolation_id"], f"{path}.isolation_id")
    if row["isolation_id"] != workspace_id or row["workspace_root_sha256"] != workspace_digest:
        raise ClientError("response_workspace_mismatch", path)
    _const(row["process_mode"], "foreground", f"{path}.process_mode")
    _enum(row["endpoint_kind"], ENDPOINT_KINDS, f"{path}.endpoint_kind")
    transports = _string_array(
        row["supported_transports"], f"{path}.supported_transports",
        nonempty=True, unique=True, allowed=TRANSPORTS,
    )
    if row["endpoint_kind"] not in transports or (ENDPOINT_KINDS - {row["endpoint_kind"]}) & set(transports):
        raise ClientError("response_transport_unsafe", f"{path}.supported_transports")
    _enum(row["health"], HEALTH_STATUSES, f"{path}.health")
    _string_array(row["degraded_reasons"], f"{path}.degraded_reasons", unique=True)
    _text(row["recovery_instructions"], f"{path}.recovery_instructions")
    _const(row["mandatory_model_hop"], False, f"{path}.mandatory_model_hop", "response_effect_claimed")
    _const(row["model_can_admit"], False, f"{path}.model_can_admit", "response_effect_claimed")
    return row


def _validate_lifecycle(value: Any) -> dict[str, Any]:
    path = "$.response.lifecycle"
    row = _closed(value, LIFECYCLE_FIELDS, path, "response_shape_invalid")
    _enum(row["state"], LIFECYCLE_STATES, f"{path}.state")
    history = _string_array(row["history"], f"{path}.history", nonempty=True, allowed=set(LIFECYCLE_STATES))
    if history[-1] != row["state"] or history[0] != "created" or any(
        pair not in LIFECYCLE_TRANSITIONS for pair in zip(history, history[1:])
    ):
        raise ClientError("response_lifecycle_invalid", path)
    _const(row["foreground"], True, f"{path}.foreground")
    return row


def _validate_endpoint(value: Any, expected_kind: str) -> dict[str, Any]:
    path = "$.response.endpoint"
    row = _closed(value, ENDPOINT_FIELDS, path, "response_shape_invalid")
    _enum(row["kind"], ENDPOINT_KINDS, f"{path}.kind")
    if row["kind"] != expected_kind:
        raise ClientError("response_transport_unsafe", f"{path}.kind")
    address = _text(row["address"], f"{path}.address")
    if row["kind"] == "unix_socket":
        parts = address.split("/")
        if (
            address.startswith("/") or "\\" in address or "%" in address
            or re.match(r"^[A-Za-z]:", address)
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ClientError("response_transport_unsafe", f"{path}.address")
    else:
        match = LOOPBACK.fullmatch(address)
        if match is None or int(match.group(1)) > 65535:
            raise ClientError("response_transport_unsafe", f"{path}.address")
    _const(row["local_only"], True, f"{path}.local_only", "response_transport_unsafe")
    _const(row["bound"], False, f"{path}.bound", "response_transport_unsafe")
    return row


def _validate_health(value: Any, manifest: Mapping[str, Any]) -> dict[str, Any]:
    path = "$.response.health"
    row = _closed(value, HEALTH_FIELDS, path, "response_shape_invalid")
    _enum(row["status"], HEALTH_STATUSES, f"{path}.status")
    _enum(row["provenance"], {"observed", "declared", "unknown"}, f"{path}.provenance")
    observed = _timestamp(row["observed_at"], f"{path}.observed_at")
    expires = _timestamp(row["expires_at"], f"{path}.expires_at")
    if expires <= observed:
        raise ClientError("response_health_window_invalid", path)
    reasons = _string_array(row["degraded_reasons"], f"{path}.degraded_reasons", unique=True)
    if row["status"] != manifest["health"] or reasons != manifest["degraded_reasons"]:
        raise ClientError("response_health_mismatch", path)
    if row["status"] == "healthy" and reasons:
        raise ClientError("response_health_mismatch", path)
    if row["status"] in {"degraded", "unavailable"} and not reasons:
        raise ClientError("response_health_mismatch", path)
    if row["provenance"] == "unknown" and (row["status"] != "unknown" or not reasons):
        raise ClientError("response_health_mismatch", path)
    return row


def _validate_reconnect(value: Any) -> dict[str, Any]:
    path = "$.response.reconnect"
    row = _closed(value, RECONNECT_FIELDS, path, "response_shape_invalid")
    _const(row["supported"], True, f"{path}.supported")
    _const(row["requires_original_client"], False, f"{path}.requires_original_client")
    _text(row["instruction"], f"{path}.instruction")
    return row


def _validate_shutdown(value: Any) -> dict[str, Any]:
    path = "$.response.shutdown"
    row = _closed(value, SHUTDOWN_FIELDS, path, "response_shape_invalid")
    _const(row["supported"], True, f"{path}.supported")
    _const(row["mode"], "foreground_signal", f"{path}.mode")
    _text(row["instruction"], f"{path}.instruction")
    return row


def _validate_effects(value: Any) -> dict[str, Any]:
    path = "$.response.effect_guarantees"
    row = _closed(value, EFFECT_FIELDS, path, "response_shape_invalid")
    for field in EFFECT_FIELDS:
        _const(row[field], False, f"{path}.{field}", "response_effect_claimed")
    return row


def _load_openapi() -> dict[str, Any]:
    path = (
        Path(_load_openapi.__code__.co_filename).resolve().parent.parent
        / "assets" / "templates" / "standalone-runtime-openapi.json"
    )
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise OSError("not a regular package file")
        raw = path.read_bytes()
    except OSError as exc:
        raise ClientError("openapi_unavailable", str(path)) from exc
    if hashlib.sha256(raw).hexdigest() != OPENAPI_SHA256:
        raise ClientError("openapi_identity_mismatch", str(path))
    try:
        document = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ClientError) as exc:
        if isinstance(exc, ClientError):
            raise
        raise ClientError("openapi_invalid", str(path)) from exc
    if not isinstance(document, dict):
        raise ClientError("openapi_invalid", "$")
    if document.get("openapi") != "3.1.0" or document.get("info", {}).get("version") != "1":
        raise ClientError("openapi_version_unsupported", "$.openapi")
    if document.get("x-codexmax-runtime-version") != "1" or document.get("x-codexmax-api-version") != SUPPORTED_API_VERSION or document.get("x-codexmax-client-version") != "1":
        raise ClientError("openapi_version_unsupported", "$")
    if "servers" in document or document.get("x-codexmax-local-only") is not True or document.get("x-codexmax-network-bound") is not False:
        raise ClientError("openapi_transport_unsafe", "$")
    boundary = document.get("x-codexmax-client-transport-boundary")
    if boundary != {"default": "in_process", "supported": ["in_process", "local_cli"], "network_bound": False}:
        raise ClientError("openapi_transport_unsafe", "$.x-codexmax-client-transport-boundary")
    paths = document.get("paths")
    expected_paths = {f"/v1/workspaces/{{workspace_id}}/{operation}": operation for operation in OPERATIONS}
    if not isinstance(paths, dict) or set(paths) != set(expected_paths):
        raise ClientError("openapi_operations_invalid", "$.paths")
    expected_ids = {
        "inspect": "inspectWorkspaceRuntimeV1",
        "reconnect": "requestWorkspaceReconnectV1",
        "shutdown": "requestWorkspaceShutdownV1",
    }
    for route, operation in expected_paths.items():
        item = paths[route]
        if not isinstance(item, dict) or set(item) != {"post"} or item["post"].get("operationId") != expected_ids[operation]:
            raise ClientError("openapi_operations_invalid", f"$.paths.{route}")
    schemas = document.get("components", {}).get("schemas")
    if not isinstance(schemas, dict) or set(schemas) != KNOWN_SCHEMAS:
        raise ClientError("openapi_schemas_invalid", "$.components.schemas")
    return copy.deepcopy(document)


def _validate_selection(workspace_id: Any, selection: Any) -> dict[str, Any]:
    _identifier(workspace_id, "workspace_id", "workspace_id_invalid")
    row = _closed(copy.deepcopy(selection), REQUEST_FIELDS, "$.selection", "selection_shape_invalid")
    if row["api_version"] != SUPPORTED_API_VERSION:
        raise ClientError("api_version_unsupported", "$.selection.api_version")
    if row["workspace_id"] != workspace_id:
        raise ClientError("workspace_identity_mismatch", "$.selection.workspace_id")
    if not isinstance(row["workspace_path_sha256"], str) or DIGEST.fullmatch(row["workspace_path_sha256"]) is None:
        raise ClientError("digest_invalid", "$.selection.workspace_path_sha256")
    return row


def _validate_response(operation: str, workspace_id: str, selection: Mapping[str, Any], response: Any) -> dict[str, Any]:
    row = copy.deepcopy(response)
    if isinstance(row, dict) and row.get("artifact_type") == "standalone_runtime_service_error_v1":
        error = _closed(row, {"service_version", "artifact_type", "code", "path", "side_effect_free"}, "$.response", "response_shape_invalid")
        if type(error["service_version"]) is not int or error["service_version"] != 1 or error["side_effect_free"] is not True:
            raise ClientError("response_version_invalid", "$.response")
        code = _identifier(error["code"], "$.response.code", "response_error_code_invalid")
        path = _text(error["path"], "$.response.path", "response_error_path_invalid")
        raise ClientError(code, path)
    expected_fields = BASE_RESULT_FIELDS | OPERATION_FIELDS[operation]
    result = _closed(row, expected_fields, "$.response", "response_shape_invalid")
    if type(result["service_version"]) is not int or result["service_version"] != 1 or result["artifact_type"] != "standalone_runtime_service_result_v1":
        raise ClientError("response_version_invalid", "$.response")
    if result["operation"] != operation:
        raise ClientError("response_operation_mismatch", "$.response.operation")
    if result["workspace_id"] != workspace_id:
        raise ClientError("response_workspace_mismatch", "$.response.workspace_id")
    for field in ("workspace_path_sha256", "runtime_json_sha256", "manifest_sha256"):
        if not isinstance(result[field], str) or DIGEST.fullmatch(result[field]) is None:
            raise ClientError("response_digest_invalid", f"$.response.{field}")
    if result["workspace_path_sha256"] != selection["workspace_path_sha256"]:
        raise ClientError("response_digest_mismatch", "$.response.workspace_path_sha256")
    runtime = _validate_runtime_manifest(
        result["runtime_manifest"], workspace_id, result["workspace_path_sha256"]
    )
    _validate_lifecycle(result["lifecycle"])
    _validate_endpoint(result["endpoint"], runtime["endpoint_kind"])
    _validate_health(result["health"], runtime)
    _validate_reconnect(result["reconnect"])
    _validate_shutdown(result["shutdown"])
    _text(result["recovery_instructions"], "$.response.recovery_instructions")
    if result["recovery_instructions"] != runtime["recovery_instructions"]:
        raise ClientError("response_recovery_mismatch", "$.response.recovery_instructions")
    _validate_effects(result["effect_guarantees"])
    _const(result["runtime_json_written"], False, "$.response.runtime_json_written", "response_effect_claimed")
    _const(result["side_effect_free"], True, "$.response.side_effect_free", "response_effect_claimed")
    expected_flags = {
        "reconnect": {"reconnect_requested": True, "reconnected": False, "reconnect_observed": False, "original_client_required": False},
        "shutdown": {"shutdown_requested": True, "shutdown_observed": False, "persistent_state_changed": False},
    }
    for field, expected in expected_flags.get(operation, {}).items():
        _const(result[field], expected, f"$.response.{field}", "response_effect_claimed")
    return copy.deepcopy(result)


def _default_transport(operation: str, workspace_id: str, selection: Mapping[str, Any]) -> dict[str, Any]:
    expected = Path(_default_transport.__code__.co_filename).resolve().with_name("standalone_runtime_service.py")
    observed = Path(getattr(runtime_service, "__file__", "")).resolve()
    if observed != expected:
        raise ClientError("service_identity_mismatch", "standalone_runtime_service")
    operation_fn = {"inspect": runtime_service.inspect_workspace, "reconnect": runtime_service.reconnect_workspace, "shutdown": runtime_service.shutdown_workspace}[operation]
    try:
        return operation_fn(workspace_id)
    except runtime_service.RuntimeServiceError as exc:
        raise ClientError(exc.code, exc.path) from exc


def _validate_effect_receipt(operation: str, request: Mapping[str, Any], value: Any) -> dict[str, Any]:
    row = _closed(
        copy.deepcopy(value), effect_gateway.EFFECT_RECEIPT_FIELDS,
        "$.effect_response", "response_shape_invalid",
    )
    if row["schema_version"] != 1 or row["artifact_type"] != effect_gateway.EFFECT_RECEIPT_TYPE:
        raise ClientError("response_version_invalid", "$.effect_response")
    if row["operation"] != operation or row["request_id"] != request.get("request_id") or row["request_sha256"] != request.get("request_sha256"):
        raise ClientError("response_operation_mismatch", "$.effect_response")
    if row["run_id"] != request.get("run", {}).get("run_id"):
        raise ClientError("response_digest_mismatch", "$.effect_response.run_id")
    if row["disposition"] not in {"observed", "execution_unknown"}:
        raise ClientError("response_shape_invalid", "$.effect_response.disposition")
    for field in ("state_version_before", "state_version_after"):
        if type(row[field]) is not int or row[field] < 0:
            raise ClientError("response_shape_invalid", f"$.effect_response.{field}")
    if row["state_version_after"] != row["state_version_before"] + 1:
        raise ClientError("response_shape_invalid", "$.effect_response.state_version_after")
    for field in ("route_requested", "route_observed"):
        identity = _closed(row[field], {"route_id", "model", "host"}, f"$.effect_response.{field}", "response_shape_invalid")
        for key, item in identity.items():
            if item != "unknown":
                _identifier(item, f"$.effect_response.{field}.{key}")
    if not isinstance(row["event_ids"], list) or not row["event_ids"]:
        raise ClientError("response_shape_invalid", "$.effect_response.event_ids")
    for event_id in row["event_ids"]:
        _identifier(event_id, "$.effect_response.event_ids")
    if not isinstance(row["unknowns"], list) or any(not isinstance(item, str) for item in row["unknowns"]):
        raise ClientError("response_shape_invalid", "$.effect_response.unknowns")
    if row["proof_boundary"] != "source_local_registered_action":
        raise ClientError("response_shape_invalid", "$.effect_response.proof_boundary")
    if row["disposition"] == "observed":
        try:
            effect_gateway._validate_action_receipt(row["action_receipt"], copy.deepcopy(request), row["action_receipt"]["observed_at"])
        except (effect_gateway.GatewayError, TypeError, KeyError) as exc:
            raise ClientError("response_effect_observation_invalid", "$.effect_response.action_receipt") from exc
    elif row["action_receipt"] is not None or row["post_state"] != "execution_unknown":
        raise ClientError("response_effect_observation_invalid", "$.effect_response.action_receipt")
    supplied = _digest(row["receipt_sha256"], "$.effect_response.receipt_sha256")
    if supplied != effect_gateway.digest({key: item for key, item in row.items() if key != "receipt_sha256"}):
        raise ClientError("response_digest_mismatch", "$.effect_response.receipt_sha256")
    return row


class StandaloneRuntimeClientV1:
    """Closed v1 client over a fixed local in-process callable boundary."""

    def __init__(self, transport: Callable[[str, str, Mapping[str, Any]], Mapping[str, Any]] | None = None):
        self._openapi = _load_openapi()
        if transport is not None and not callable(transport):
            raise ClientError("transport_callable_required", "transport")
        self._transport = _default_transport if transport is None else transport

    @property
    def openapi(self) -> dict[str, Any]:
        return copy.deepcopy(self._openapi)

    def _call(self, operation: str, workspace_id: str, selection: Mapping[str, Any]) -> dict[str, Any]:
        request = _validate_selection(workspace_id, selection)
        transport_request = copy.deepcopy(request)
        try:
            raw = self._transport(operation, workspace_id, transport_request)
        except ClientError:
            raise
        except Exception as exc:
            raise ClientError("transport_failed", operation) from exc
        return _validate_response(operation, workspace_id, request, copy.deepcopy(raw))

    def inspect(self, workspace_id: str, selection: Mapping[str, Any]) -> dict[str, Any]:
        return self._call("inspect", workspace_id, selection)

    def reconnect(self, workspace_id: str, selection: Mapping[str, Any]) -> dict[str, Any]:
        return self._call("reconnect", workspace_id, selection)

    def shutdown(self, workspace_id: str, selection: Mapping[str, Any]) -> dict[str, Any]:
        return self._call("shutdown", workspace_id, selection)

    def effect(self, workspace: str | Path, request: Mapping[str, Any]) -> dict[str, Any]:
        """Use the fixed in-process service effect entry; read transport is irrelevant."""

        original = copy.deepcopy(request)
        if not isinstance(request, Mapping) or request.get("operation") not in effect_gateway.EFFECT_OPERATIONS:
            raise ClientError("effect_request_invalid", "$.effect_request.operation")
        workspace_path = Path(workspace)
        if request.get("workspace_id") != workspace_path.name:
            raise ClientError("workspace_identity_mismatch", "$.effect_request.workspace_id")
        try:
            raw = runtime_service.execute_effect_workspace(workspace_path, copy.deepcopy(request))
        except runtime_service.RuntimeServiceError as exc:
            raise ClientError(exc.code, exc.path) from exc
        if request != original:
            raise ClientError("input_mutated", "$.effect_request")
        return _validate_effect_receipt(request["operation"], request, raw)

    def run(self, workspace: str | Path, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("operation") != "run":
            raise ClientError("effect_request_invalid", "$.effect_request.operation")
        return self.effect(workspace, request)

    def cancel(self, workspace: str | Path, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("operation") != "cancel":
            raise ClientError("effect_request_invalid", "$.effect_request.operation")
        return self.effect(workspace, request)

    def recover(self, workspace: str | Path, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("operation") != "recover":
            raise ClientError("effect_request_invalid", "$.effect_request.operation")
        return self.effect(workspace, request)

    def responses(self, workspace: str | Path, request: Mapping[str, Any]) -> dict[str, Any]:
        """Use only the fixed in-process Responses bridge service entry."""

        original = copy.deepcopy(request)
        try:
            validated, _, _ = response_bridge.validate_responses_request(request)
        except response_bridge.PresetError as exc:
            raise ClientError(exc.code, exc.path) from exc
        workspace_path = Path(workspace)
        if validated["workspace_id"] != workspace_path.name:
            raise ClientError("workspace_identity_mismatch", "$.workspace_id")
        try:
            raw = runtime_service.execute_responses_workspace(workspace_path, copy.deepcopy(validated))
            result = response_bridge.verify_bridge_receipt(raw, validated)
        except runtime_service.RuntimeServiceError as exc:
            raise ClientError(exc.code, exc.path) from exc
        except response_bridge.PresetError as exc:
            raise ClientError(exc.code, exc.path) from exc
        if request != original:
            raise ClientError("input_mutated", "$.responses_request")
        return result

    def cancel_response(self, workspace: str | Path, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("operation") != "cancel":
            raise ClientError("responses_request_invalid", "$.operation")
        return self.responses(workspace, request)

    def recover_response(self, workspace: str | Path, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("operation") != "recover":
            raise ClientError("responses_request_invalid", "$.operation")
        return self.responses(workspace, request)
