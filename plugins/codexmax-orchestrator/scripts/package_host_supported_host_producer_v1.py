#!/usr/bin/env python3
"""No-I/O supported-host producer client for the accepted v8 receiver."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping

from codexmax_package_host.errors import CompanionError
from codexmax_package_host import authority_v1, catalog_v1, effects_v1, recovery_v1, responses_v1, supervision_v1
from codexmax_package_host.producer_policy_v1 import EXTERNAL_OPERATIONS
from codexmax_package_host.producer_v1 import (
    BINDING_REQUEST_FIELDS,
    BINDING_REQUEST_TYPE,
    RECEIPT_FIELDS,
    RECEIPT_TYPE,
    operation_payload_schema_sha256,
    validate_receiver_binding_envelope_v1,
    validate_producer_policy,
)
from codexmax_package_host.protocol_v1 import BODY_FIELDS, canonical_json, decode_frame, digest, format_time, parse_time

from package_host_supported_host_fact_sources_v1 import (
    AvailableFact,
    CanonicalFactSource,
    EXTERNAL_OPERATION_SET,
    FACT_RESULT_TYPE,
    UnavailableFact,
)
from supported_host_protected_fact_store_v1 import StoreDerivedAvailableFact
from supported_host_protected_service_v1 import OsBoundOpaqueTlsTransport, ValidatedProtectedFact
from supported_host_first_party_runtime_v1 import FirstPartySupportedHostRuntimeV1


CONFIG_TYPE = "package_host_supported_host_producer_config_v1"
CONFIG_FIELDS = frozenset({
    "schema_version", "artifact_type", "producer_policy",
    "expected_host_profile_id", "expected_host_profile_sha256",
    "server_leaf_sha256", "binding_lifetime_seconds",
})
IDENTITY_FIELDS = frozenset({
    "workspace_id", "source_sha256", "candidate_sha256", "manifest_sha256",
    "generation", "host_id", "service_instance_id", "service_start_id",
})
UNAVAILABLE_RESULT_FIELDS = frozenset({
    "schema_version", "artifact_type", "operation", "state", "reason",
    "canonical_source_id",
})
AVAILABLE_RESULT_FIELDS = frozenset({
    "schema_version", "artifact_type", "operation", "state", "key", "value",
    "observed_at", "expires_at", "canonical_source_id", "source_digest",
})
REQUEST_PREIMAGE_TYPE = "package_host_supported_host_request_digest_preimage_v1"
RESPONSE_PREIMAGE_TYPE = "package_host_supported_host_response_digest_preimage_v1"
LOCAL_OUTCOME_TYPE = "package_host_supported_host_client_outcome_v1"
REQUEST_PREIMAGE_FIELDS = frozenset({
    "schema_version", "artifact_type", "correlation_id", "evidence_id",
    "operation", "identity", "source_result", "dependency_receipt_sha256",
    "observed_at", "expires_at", "operation_body", "operation_body_sha256",
    "previous_durable_index_sha256", "previous_readiness_sha256",
    "predecessor_admission_sha256",
    "policy_sha256", "host_profile_identity",
})
RESPONSE_PREIMAGE_FIELDS = REQUEST_PREIMAGE_FIELDS | frozenset({
    "request_sha256", "intended_unavailable_outcome",
})
LOCAL_OUTCOME_FIELDS = frozenset({
    "schema_version", "artifact_type", "operation", "state", "reason",
    "canonical_source_id", "request_digest_preimage",
    "response_digest_preimage", "receiver_receipt", "receiver_envelope",
})
RECEIVER_RESPONSE_FIELDS = frozenset({"receipt", "envelope"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_FORBIDDEN_SOURCE_KEY_TOKENS = (
    "private_key", "private-key", "credential", "password", "secret",
    "bearer", "access_token", "refresh_token", "fixture", "synthetic",
    "test_only", "source_digest", "self_digest",
)
_OPERATION_VALUE_FIELDS = MappingProxyType({
    "verify_effect_authority": frozenset({"authority", "request_sha256", "revoked", "expires_at"}),
    "invoke_registered_action": frozenset({"variant", "registration", "observation_key", "observation"}),
    "issue_responses_context": frozenset({"variant", "control_row", "request_row"}),
    "verify_responses_bridge": frozenset({"body", "identity", "value", "expires_at", "revoked"}),
    "commit_or_verify_record": frozenset({"identity", "body", "opaque_seal", "expires_at", "revoked"}),
    "seal_or_verify_projection": frozenset({"identity", "body", "opaque_seal", "expires_at", "revoked"}),
    "read_operator_preset_bundle": frozenset({
        "schema_version", "artifact_type", "catalog_receipt_id", "workspace_id",
        "source_sha256", "candidate_sha256", "service_instance_id", "admission_id",
        "binding_state_version", "binding_state_sha256", "preset_policy_sha256",
        "adapter_registry_sha256", "capability_profile_sha256", "catalog_generation",
        "previous_catalog_sha256", "bundle", "bundle_sha256", "configured_bindings",
        "issued_at", "expires_at", "receipt_sha256", "seal",
    }),
    "read_operator_selection_head": frozenset({
        "schema_version", "artifact_type", "head_id", "workspace_id", "source_sha256",
        "candidate_sha256", "service_instance_id", "admission_id", "binding_state_version",
        "binding_state_sha256", "selection_state_version", "selection", "selection_sha256",
        "catalog_receipt_sha256", "bundle_sha256", "bundle_generation", "issued_at",
        "expires_at", "receipt_sha256", "seal",
    }),
    "read_operator_selection_mutation": frozenset({
        "schema_version", "artifact_type", "mutation_id", "submission_sha256", "workspace_id",
        "source_sha256", "candidate_sha256", "service_instance_id", "admission_id",
        "binding_state_version", "binding_state_sha256", "runtime_thread_id",
        "runtime_thread_generation", "selection_state_version_before", "selection_state_version_after",
        "previous_selection_sha256", "selection", "selection_sha256", "catalog_receipt_sha256",
        "bundle_sha256", "bundle_generation", "issued_at", "expires_at", "receipt_sha256", "seal",
    }),
    "commit_operator_selection": frozenset({
        "schema_version", "artifact_type", "operation",
        "operation_body_sha256", "decision",
    }),
    "read_operator_supervision": frozenset({
        "parent", "supervisor", "workers", "inventory_event", "supervisor_checkpoint",
        "host_read_event", "subscription", "recovery", "snapshot", "worker_count",
    }),
    "read_operator_recovery_lease_grant": frozenset({"grant", "predecessor_lease", "active", "revoked", "consumed"}),
})
_OPERATION_ARTIFACT_TYPES = MappingProxyType({
    "read_operator_preset_bundle": "standalone_operator_configured_preset_bundle_receipt_v1",
    "read_operator_selection_head": "standalone_operator_selection_head_receipt_v1",
    "read_operator_selection_mutation": "standalone_operator_selection_mutation_receipt_v1",
    "commit_operator_selection": "package_host_command_authorization_v1",
})
POSITIVE_SOURCE_DIGEST_TYPE = "package_host_positive_canonical_fact_digest_v1"
_ENABLED_POSITIVE_OPERATIONS = frozenset(EXTERNAL_OPERATION_SET)
_RESPONSES_PAIR_FIELDS = frozenset({"variant", "control_row", "request_row"})
_RESPONSES_PAIR_ROW_FIELDS = frozenset({"key", "value"})
_RESPONSES_INDEX_ROW_FIELDS = frozenset({"body", "identity", "value", "expires_at", "revoked"})
_ACTION_REGISTRATION_FIELDS = frozenset({"action_id", "tool_id", "transport", "parameter_fields"})
_ACTION_OBSERVATION_FIELDS = frozenset({"receipt", "expires_at", "revoked"})
_ACTION_RECEIPT_FIELDS = frozenset({
    "schema_version", "artifact_type", "action_receipt_id", "action_id", "effect_id",
    "operation", "outcome", "requested_at", "observed_at", "host_receipt_id",
    "observed_identity", "request_sha256", "output_sha256", "reconciled_outcome",
    "successor_run_id", "receipt_sha256",
})


class SupportedHostProducerError(ValueError):
    """A stable, non-echoing producer-plane rejection."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise SupportedHostProducerError(code, path)
    return deepcopy(dict(value))


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise SupportedHostProducerError("identifier_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise SupportedHostProducerError("digest_invalid", path)
    return value


def _utc(value: Any, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise SupportedHostProducerError("utc_clock_invalid", path)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _parse_time(value: Any, path: str) -> datetime:
    try:
        return parse_time(value, path)
    except CompanionError as exc:
        raise SupportedHostProducerError(exc.code, exc.path) from exc


class ValidatedPublicConfiguration:
    """Detached public data.  It contains no endpoint or key material."""

    __slots__ = ("_value", "_policy")

    def __init__(self, value: Mapping[str, Any], policy: Mapping[str, Any]) -> None:
        self._value = MappingProxyType(deepcopy(dict(value)))
        self._policy = MappingProxyType(deepcopy(dict(policy)))

    @property
    def value(self) -> Mapping[str, Any]:
        return MappingProxyType(deepcopy(dict(self._value)))

    @property
    def policy(self) -> Mapping[str, Any]:
        return MappingProxyType(deepcopy(dict(self._policy)))


class BoundServiceIdentity:
    """The exact current candidate, generation, and service-start identity."""

    __slots__ = ("_value",)

    def __init__(self, value: Mapping[str, Any]) -> None:
        self._value = MappingProxyType(deepcopy(dict(value)))

    @property
    def value(self) -> Mapping[str, Any]:
        return MappingProxyType(deepcopy(dict(self._value)))


class ValidatedDependencyReceiptDigests:
    """Digests derived only from closed positive receiver-owned receipts."""

    __slots__ = ("_value", "_receipts")

    def __init__(self, value: Mapping[str, str], receipts: Mapping[str, Mapping[str, Any]] | None = None) -> None:
        self._value = MappingProxyType(dict(value))
        self._receipts = MappingProxyType(deepcopy(dict(receipts or {})))

    @property
    def value(self) -> Mapping[str, str]:
        return MappingProxyType(dict(self._value))

    @property
    def receipts(self) -> Mapping[str, Mapping[str, Any]]:
        return MappingProxyType(deepcopy(dict(self._receipts)))


class AdmittedOpaqueTlsTransport:
    """Removed callback transport retained only for a stable rejection."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise SupportedHostProducerError("producer_os_tls_agent_required", "$.transport")


class TestOnlyInMemoryReceiverTransport:
    """Explicit source-local receiver harness. It is not a production transport."""

    __slots__ = ("_exchange", "_server_leaf_sha256", "_verified", "_used", "_origin")

    def __init__(self, exchange: Callable[[bytes], Any], server_leaf_sha256: str, *, verified: bool = True) -> None:
        if not callable(exchange):
            raise SupportedHostProducerError("producer_test_transport_invalid", "$.transport")
        _sha(server_leaf_sha256, "$.transport.server_leaf_sha256")
        self._exchange = exchange
        self._server_leaf_sha256 = server_leaf_sha256
        self._verified = verified is True
        self._used = False
        self._origin = None

    def _consume(self, expected_server_leaf_sha256: str) -> Callable[[bytes], Any]:
        if self._used:
            raise SupportedHostProducerError("producer_transport_reused", "$.transport")
        self._used = True
        if self._origin is not None:
            self._origin._used = True
        if not self._verified:
            raise SupportedHostProducerError("producer_transport_unverified", "$.transport")
        if self._server_leaf_sha256 != expected_server_leaf_sha256:
            raise SupportedHostProducerError("producer_transport_peer_mismatch", "$.transport")
        return self._exchange


def validate_public_configuration(value: Mapping[str, Any]) -> ValidatedPublicConfiguration:
    """Validate and detach the closed public producer configuration."""

    config = _closed(value, CONFIG_FIELDS, "producer_config_shape_invalid", "$.config")
    if config["schema_version"] != 1 or config["artifact_type"] != CONFIG_TYPE:
        raise SupportedHostProducerError("producer_config_version_invalid", "$.config")
    _identifier(config["expected_host_profile_id"], "$.config.expected_host_profile_id")
    _sha(config["expected_host_profile_sha256"], "$.config.expected_host_profile_sha256")
    _sha(config["server_leaf_sha256"], "$.config.server_leaf_sha256")
    lifetime = config["binding_lifetime_seconds"]
    if isinstance(lifetime, bool) or not isinstance(lifetime, int) or not 1 <= lifetime <= 300:
        raise SupportedHostProducerError("producer_config_lifetime_invalid", "$.config.binding_lifetime_seconds")
    try:
        policy = validate_producer_policy(
            config["producer_policy"],
            expected_host_profile_id=config["expected_host_profile_id"],
            expected_host_profile_sha256=config["expected_host_profile_sha256"],
        )
    except CompanionError as exc:
        raise SupportedHostProducerError(exc.code, exc.path) from exc
    return ValidatedPublicConfiguration(config, policy)


def validate_bound_service_identity(value: Mapping[str, Any]) -> BoundServiceIdentity:
    """Validate and detach the exact current service binding."""

    identity = _closed(value, IDENTITY_FIELDS, "producer_identity_shape_invalid", "$.identity")
    for field in ("workspace_id", "host_id", "service_instance_id", "service_start_id"):
        _identifier(identity[field], "$.identity." + field)
    for field in ("source_sha256", "candidate_sha256", "manifest_sha256"):
        _sha(identity[field], "$.identity." + field)
    generation = identity["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise SupportedHostProducerError("producer_generation_invalid", "$.identity.generation")
    return BoundServiceIdentity(identity)


def validate_dependency_receipt_digests(
    receipts: Mapping[str, Mapping[str, Any]],
) -> ValidatedDependencyReceiptDigests:
    """Derive dependency digests from exact positive v8 receipts."""

    if not isinstance(receipts, Mapping):
        raise SupportedHostProducerError("producer_dependencies_invalid", "$.dependencies")
    validated: dict[str, str] = {}
    for operation, value in receipts.items():
        if operation not in set(EXTERNAL_OPERATIONS) | {"read_capability_admission", "open_operator_listener"}:
            raise SupportedHostProducerError("producer_dependency_operation_invalid", "$.dependencies")
        receipt = _closed(value, RECEIPT_FIELDS, "producer_dependency_receipt_shape_invalid", "$.dependencies." + operation)
        if receipt["schema_version"] != 1 or receipt["artifact_type"] != RECEIPT_TYPE or receipt["operation"] != operation:
            raise SupportedHostProducerError("producer_dependency_receipt_identity_invalid", "$.dependencies." + operation)
        payload = receipt.get("payload")
        if not isinstance(payload, Mapping) or payload.get("state") != "available":
            raise SupportedHostProducerError("producer_dependency_receipt_negative", "$.dependencies." + operation)
        _sha(receipt["receipt_sha256"], "$.dependencies." + operation + ".receipt_sha256")
        expected_digest = digest({key: item for key, item in receipt.items() if key != "receipt_sha256"})
        if receipt["receipt_sha256"] != expected_digest:
            raise SupportedHostProducerError("producer_dependency_receipt_digest_mismatch", "$.dependencies." + operation + ".receipt_sha256")
        validated[operation] = receipt["receipt_sha256"]
    return ValidatedDependencyReceiptDigests(validated, receipts)


def _policy_row(policy: Mapping[str, Any], operation: str) -> Mapping[str, Any]:
    for row in policy["evidence_policy"]:
        if row["operation"] == operation:
            return row
    raise SupportedHostProducerError("producer_operation_invalid", "$.operation")


def _principal(policy: Mapping[str, Any], operation: str) -> Mapping[str, Any]:
    principal_map = policy["supported_host_principal_map"]
    if principal_map is None:
        raise SupportedHostProducerError("producer_principal_map_pending", "$.config.producer_policy")
    matches = [item for item in principal_map["principals"] if operation in item["operation_map"]]
    if len(matches) != 1:
        raise SupportedHostProducerError("producer_principal_map_invalid", "$.operation")
    return matches[0]


def _scan_source_value(value: Any, path: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key).lower()
            child_path = path + "." + str(key)
            if any(token in key_text for token in _FORBIDDEN_SOURCE_KEY_TOKENS):
                raise SupportedHostProducerError("canonical_source_authority_forbidden", child_path)
            _scan_source_value(item, child_path)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _scan_source_value(item, f"{path}[{index}]")


def _positive_source_digest_preimage(
    operation: str,
    *,
    key: str,
    value: Mapping[str, Any],
    observed_at: str,
    expires_at: str,
    canonical_source_id: str,
    identity: Mapping[str, Any],
    dependency_receipt_sha256: list[str],
    operation_body_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": POSITIVE_SOURCE_DIGEST_TYPE,
        "operation": operation,
        "payload_schema_sha256": operation_payload_schema_sha256(operation),
        "identity": deepcopy(dict(identity)),
        "dependency_receipt_sha256": list(dependency_receipt_sha256),
        "operation_body_sha256": operation_body_sha256,
        "key": key,
        "value": deepcopy(dict(value)),
        "observed_at": observed_at,
        "expires_at": expires_at,
        "canonical_source_id": canonical_source_id,
    }


def positive_source_digest(
    operation: str,
    *,
    key: str,
    value: Mapping[str, Any],
    observed_at: datetime,
    expires_at: datetime,
    canonical_source_id: str,
    identity: BoundServiceIdentity,
    dependency_receipt_digests: ValidatedDependencyReceiptDigests,
    operation_body: Mapping[str, Any],
) -> str:
    """Compute the only accepted positive-source digest preimage."""

    if operation not in EXTERNAL_OPERATION_SET:
        raise SupportedHostProducerError("producer_operation_invalid", "$.operation")
    if not isinstance(identity, BoundServiceIdentity):
        raise SupportedHostProducerError("producer_identity_unvalidated", "$.identity")
    if not isinstance(dependency_receipt_digests, ValidatedDependencyReceiptDigests):
        raise SupportedHostProducerError("producer_dependencies_unvalidated", "$.dependencies")
    observed = format_time(_utc(observed_at, "$.observed_at"))
    expires = format_time(_utc(expires_at, "$.expires_at"))
    dependencies = dependency_receipt_digests.value
    body = _validate_operation_body(operation, operation_body)
    return accepted_positive_source_digest_v1(
        operation,
        key=_identifier(key, "$.key"),
        value=_validate_operation_value(operation, value, identity.value),
        observed_at=observed,
        expires_at=expires,
        canonical_source_id=_identifier(canonical_source_id, "$.canonical_source_id"),
        identity=identity.value,
        dependency_receipt_sha256=[dependencies[item] for item in sorted(dependencies)],
        operation_body_sha256=digest(body),
    )


def accepted_positive_source_digest_v1(
    operation: str, *, key: str, value: Mapping[str, Any], observed_at: str,
    expires_at: str, canonical_source_id: str, identity: Mapping[str, Any],
    dependency_receipt_sha256: list[str], operation_body_sha256: str,
) -> str:
    """One accepted positive-source digest implementation for owner and client."""
    return digest(_positive_source_digest_preimage(
        operation, key=key, value=value, observed_at=observed_at, expires_at=expires_at,
        canonical_source_id=canonical_source_id, identity=identity,
        dependency_receipt_sha256=dependency_receipt_sha256,
        operation_body_sha256=operation_body_sha256,
    ))


def _validate_operation_body(operation: str, value: Any) -> dict[str, Any]:
    fields = BODY_FIELDS.get(operation)
    if fields is None or operation not in EXTERNAL_OPERATION_SET:
        raise SupportedHostProducerError("producer_operation_invalid", "$.operation")
    return _closed(value, fields, "producer_operation_body_shape_invalid", "$.operation_body")


def _validate_operation_value(operation: str, value: Any, identity: Mapping[str, Any]) -> dict[str, Any]:
    if operation not in _ENABLED_POSITIVE_OPERATIONS:
        raise SupportedHostProducerError("canonical_positive_family_not_implemented", "$.source_result.operation")
    fields = _OPERATION_VALUE_FIELDS.get(operation)
    if fields is None:
        raise SupportedHostProducerError("producer_operation_invalid", "$.operation")
    if isinstance(value, Mapping):
        _scan_source_value(value, "$.source_result.value")
    result = _closed(value, fields, "canonical_source_operation_shape_invalid", "$.source_result.value")
    if "schema_version" in result and (type(result["schema_version"]) is not int or result["schema_version"] != 1):
        raise SupportedHostProducerError("canonical_source_operation_version_invalid", "$.source_result.value.schema_version")
    expected_type = _OPERATION_ARTIFACT_TYPES.get(operation)
    if expected_type is not None and result.get("artifact_type") != expected_type:
        raise SupportedHostProducerError("canonical_source_operation_version_invalid", "$.source_result.value.artifact_type")
    nested_identity = result.get("identity")
    if nested_identity is not None:
        if not isinstance(nested_identity, Mapping):
            raise SupportedHostProducerError("canonical_source_identity_mismatch", "$.source_result.value.identity")
        for field in ("workspace_id", "source_sha256", "candidate_sha256"):
            if nested_identity.get(field) != identity[field]:
                raise SupportedHostProducerError("canonical_source_identity_mismatch", "$.source_result.value.identity." + field)
    for field in ("workspace_id", "source_sha256", "candidate_sha256", "service_instance_id"):
        if field in result and result[field] != identity[field]:
            raise SupportedHostProducerError("canonical_source_identity_mismatch", "$.source_result.value." + field)
    return result


def _validate_command_authorization(
    value: Mapping[str, Any], key: str, operation_body_sha256: str,
) -> None:
    """Validate an exact body-specific authorization without result authority."""
    if (
        value["schema_version"] != 1
        or value["artifact_type"] != "package_host_command_authorization_v1"
        or value["operation"] != "commit_operator_selection"
        or value["decision"] != "authorized"
    ):
        raise SupportedHostProducerError(
            "canonical_source_command_authorization_invalid",
            "$.source_result.value",
        )
    _sha(value["operation_body_sha256"], "$.source_result.value.operation_body_sha256")
    if key != operation_body_sha256 or value["operation_body_sha256"] != operation_body_sha256:
        raise SupportedHostProducerError(
            "canonical_source_operation_body_mismatch",
            "$.source_result.value.operation_body_sha256",
        )


def _validate_effect_authority_value(
    value: Mapping[str, Any], key: str, identity: Mapping[str, Any], now: datetime,
    source_expires: datetime, operation_body: Mapping[str, Any],
) -> None:
    authority = value["authority"]
    request_sha256 = _sha(value["request_sha256"], "$.source_result.value.request_sha256")
    if value["revoked"] is not False:
        raise SupportedHostProducerError("canonical_source_observation_revoked", "$.source_result.value.revoked")
    if _parse_time(value["expires_at"], "$.source_result.value.expires_at") != source_expires:
        raise SupportedHostProducerError("canonical_source_expiry_invalid", "$.source_result.value.expires_at")
    context = operation_body["context"]
    if not isinstance(context, Mapping) or any(context.get(field) != identity[field] for field in ("workspace_id", "source_sha256", "candidate_sha256")):
        raise SupportedHostProducerError("canonical_source_identity_mismatch", "$.operation_body.context")
    try:
        validated = authority_v1.validate_authority(authority, context, now)
    except CompanionError as exc:
        raise SupportedHostProducerError(exc.code, exc.path) from exc
    if operation_body["authority"] != validated or request_sha256 != context.get("request_sha256") or key != request_sha256:
        raise SupportedHostProducerError("canonical_source_key_mismatch", "$.source_result.key")


def _validate_bridge_value(
    value: Mapping[str, Any], key: str, identity: Mapping[str, Any],
    source_expires: datetime, operation_body: Mapping[str, Any],
) -> None:
    exact_identity = {field: identity[field] for field in ("workspace_id", "source_sha256", "candidate_sha256")}
    if value["identity"] != exact_identity or value["body"] != dict(operation_body):
        raise SupportedHostProducerError("canonical_source_operation_body_mismatch", "$.source_result.value")
    if value["revoked"] is not False:
        raise SupportedHostProducerError("canonical_source_observation_revoked", "$.source_result.value.revoked")
    if _parse_time(value["expires_at"], "$.source_result.value.expires_at") != source_expires:
        raise SupportedHostProducerError("canonical_source_expiry_invalid", "$.source_result.value.expires_at")
    nested = _closed(
        value["value"], frozenset({"bridge_receipt_sha256", "disposition", "authority_granted_by_bridge", "provider_called_by_bridge"}),
        "canonical_source_operation_shape_invalid", "$.source_result.value.value",
    )
    _sha(nested["bridge_receipt_sha256"], "$.source_result.value.value.bridge_receipt_sha256")
    if nested["disposition"] == "execution_unknown" or nested["authority_granted_by_bridge"] is not False or nested["provider_called_by_bridge"] is not False:
        raise SupportedHostProducerError("canonical_source_bridge_invalid", "$.source_result.value.value")
    if key != digest({"identity": exact_identity, "body": dict(operation_body), "value": nested}):
        raise SupportedHostProducerError("canonical_source_key_mismatch", "$.source_result.key")


def _validate_catalog_selection_value(
    operation: str, value: Mapping[str, Any], key: str, identity: Mapping[str, Any],
    now: datetime, source_expires: datetime, operation_body: Mapping[str, Any],
) -> None:
    for field in ("workspace_id", "source_sha256", "candidate_sha256", "service_instance_id"):
        if value[field] != identity[field]:
            raise SupportedHostProducerError("canonical_source_identity_mismatch", "$.source_result.value." + field)
    if value["admission_id"] != operation_body["admission_id"]:
        raise SupportedHostProducerError("canonical_source_operation_body_mismatch", "$.source_result.value.admission_id")
    for field in ("binding_state_version", "binding_state_sha256"):
        if field in operation_body and value[field] != operation_body[field]:
            raise SupportedHostProducerError("canonical_source_operation_body_mismatch", "$.source_result.value." + field)
    issued = _parse_time(value["issued_at"], "$.source_result.value.issued_at")
    expires = _parse_time(value["expires_at"], "$.source_result.value.expires_at")
    if issued > now or expires != source_expires:
        raise SupportedHostProducerError("canonical_source_expiry_invalid", "$.source_result.value.expires_at")
    if value["receipt_sha256"] != digest({item: nested for item, nested in value.items() if item not in {"receipt_sha256", "seal"}}):
        raise SupportedHostProducerError("canonical_source_receipt_digest_mismatch", "$.source_result.value.receipt_sha256")
    if value["seal"] != digest({item: nested for item, nested in value.items() if item != "seal"}):
        raise SupportedHostProducerError("canonical_source_receipt_digest_mismatch", "$.source_result.value.seal")
    if operation == "read_operator_preset_bundle":
        try:
            bundle = catalog_v1.validate_bundle(value["bundle"])
            catalog_v1.validate_bindings(value["configured_bindings"], bundle)
        except CompanionError as exc:
            raise SupportedHostProducerError(exc.code, exc.path) from exc
        if value["bundle_sha256"] != bundle["bundle_sha256"]:
            raise SupportedHostProducerError("canonical_source_receipt_digest_mismatch", "$.source_result.value.bundle_sha256")
        expected_key = value["bundle_sha256"]
    elif operation == "read_operator_selection_head":
        if value["selection_sha256"] != digest(value["selection"]):
            raise SupportedHostProducerError("canonical_source_receipt_digest_mismatch", "$.source_result.value.selection_sha256")
        expected_key = value["receipt_sha256"]
    else:
        if value["submission_sha256"] != operation_body["submission_sha256"] or value["selection_sha256"] != digest(value["selection"]):
            raise SupportedHostProducerError("canonical_source_operation_body_mismatch", "$.source_result.value")
        expected_key = value["submission_sha256"]
    if key != expected_key:
        raise SupportedHostProducerError("canonical_source_key_mismatch", "$.source_result.key")


def _validate_supervision_value(
    value: Mapping[str, Any], key: str, identity: Mapping[str, Any], operation_body: Mapping[str, Any],
) -> None:
    try:
        supervision_v1.validate_inventory(value)
    except CompanionError as exc:
        raise SupportedHostProducerError(exc.code, exc.path) from exc
    if key != supervision_v1.inventory_key(operation_body, identity):
        raise SupportedHostProducerError("canonical_source_key_mismatch", "$.source_result.key")


def _validate_recovery_value(
    value: Mapping[str, Any], key: str, identity: Mapping[str, Any], now: datetime,
    source_expires: datetime, operation_body: Mapping[str, Any],
) -> None:
    try:
        reservation = recovery_v1.validate_reservation(value)
    except CompanionError as exc:
        raise SupportedHostProducerError(exc.code, exc.path) from exc
    if reservation["active"] is not True or reservation["revoked"] is not False or reservation["consumed"] is not False:
        raise SupportedHostProducerError("canonical_source_recovery_inactive", "$.source_result.value")
    grant = reservation["grant"]
    expected = {field: identity[field] for field in ("workspace_id", "source_sha256", "candidate_sha256")}
    expected.update({field: operation_body[field] for field in (
        "admission_id", "service_instance_id", "binding_state_version", "binding_state_sha256", "selection_sha256",
        "predecessor_run_id", "predecessor_effect_request_sha256", "predecessor_effect_receipt_sha256",
        "reconciliation_receipt_sha256", "expected_cas",
    )})
    if any(grant.get(field) != item for field, item in expected.items()):
        raise SupportedHostProducerError("canonical_source_operation_body_mismatch", "$.source_result.value.grant")
    if _parse_time(grant["expires_at"], "$.source_result.value.grant.expires_at") != source_expires:
        raise SupportedHostProducerError("canonical_source_expiry_invalid", "$.source_result.value.grant.expires_at")
    if grant["grant_sha256"] != digest({item: nested for item, nested in grant.items() if item not in {"grant_sha256", "seal"}}):
        raise SupportedHostProducerError("canonical_source_receipt_digest_mismatch", "$.source_result.value.grant.grant_sha256")
    if grant["seal"] != digest({item: nested for item, nested in grant.items() if item != "seal"}):
        raise SupportedHostProducerError("canonical_source_receipt_digest_mismatch", "$.source_result.value.grant.seal")
    predecessor = reservation["predecessor_lease"]
    if grant["fresh_lease"]["fencing_token"] <= predecessor["fencing_token"] or grant["fresh_lease"]["lease_id"] == predecessor["lease_id"]:
        raise SupportedHostProducerError("canonical_source_recovery_fence_invalid", "$.source_result.value.grant.fresh_lease")
    if key != recovery_v1.reservation_key(operation_body, identity):
        raise SupportedHostProducerError("canonical_source_key_mismatch", "$.source_result.key")
def _validate_action_value(
    value: Mapping[str, Any], key: str, now: datetime,
    source_observed: datetime, source_expires: datetime,
    operation_body: Mapping[str, Any], identity: Mapping[str, Any],
) -> None:
    if value["variant"] != "registered_action_observation_v1":
        raise SupportedHostProducerError("canonical_source_operation_version_invalid", "$.source_result.value.variant")
    registration = _closed(
        value["registration"], _ACTION_REGISTRATION_FIELDS,
        "canonical_source_operation_shape_invalid", "$.source_result.value.registration",
    )
    if registration["action_id"] != key:
        raise SupportedHostProducerError("canonical_source_key_mismatch", "$.source_result.key")
    for field in ("action_id", "tool_id", "transport"):
        _identifier(registration[field], "$.source_result.value.registration." + field)
    if not isinstance(registration["parameter_fields"], list) or any(
        not isinstance(item, str) or _IDENTIFIER.fullmatch(item) is None
        for item in registration["parameter_fields"]
    ):
        raise SupportedHostProducerError("canonical_source_operation_shape_invalid", "$.source_result.value.registration.parameter_fields")
    observation_key = _sha(value["observation_key"], "$.source_result.value.observation_key")
    observation = _closed(
        value["observation"], _ACTION_OBSERVATION_FIELDS,
        "canonical_source_operation_shape_invalid", "$.source_result.value.observation",
    )
    if observation["revoked"] is not False:
        raise SupportedHostProducerError("canonical_source_observation_revoked", "$.source_result.value.observation.revoked")
    observation_expires = _parse_time(observation["expires_at"], "$.source_result.value.observation.expires_at")
    if observation_expires <= now or observation_expires != source_expires:
        raise SupportedHostProducerError("canonical_source_expiry_invalid", "$.source_result.value.observation.expires_at")
    receipt = _closed(
        observation["receipt"], _ACTION_RECEIPT_FIELDS,
        "canonical_source_operation_shape_invalid", "$.source_result.value.observation.receipt",
    )
    if (
        receipt["schema_version"] != 1
        or receipt["artifact_type"] != "effect_kernel_action_receipt_v1"
        or receipt["action_id"] != key
        or receipt["request_sha256"] != observation_key
    ):
        raise SupportedHostProducerError("canonical_source_action_binding_mismatch", "$.source_result.value.observation.receipt")
    for field in ("request_sha256", "output_sha256", "receipt_sha256"):
        _sha(receipt[field], "$.source_result.value.observation.receipt." + field)
    for field in ("action_receipt_id", "action_id", "effect_id", "host_receipt_id"):
        _identifier(receipt[field], "$.source_result.value.observation.receipt." + field)
    if receipt["operation"] not in {"run", "cancel", "recover"}:
        raise SupportedHostProducerError("canonical_source_action_binding_mismatch", "$.source_result.value.observation.receipt.operation")
    expected_outcomes = {"run": "running", "cancel": "cancelled", "recover": "running"}
    if receipt["outcome"] != expected_outcomes[receipt["operation"]]:
        raise SupportedHostProducerError("canonical_source_action_binding_mismatch", "$.source_result.value.observation.receipt.outcome")
    if receipt["operation"] == "recover":
        if receipt["reconciled_outcome"] not in {"failed", "cancelled"} or not isinstance(receipt["successor_run_id"], str):
            raise SupportedHostProducerError("canonical_source_action_binding_mismatch", "$.source_result.value.observation.receipt")
        _identifier(receipt["successor_run_id"], "$.source_result.value.observation.receipt.successor_run_id")
    elif receipt["reconciled_outcome"] is not None or receipt["successor_run_id"] is not None:
        raise SupportedHostProducerError("canonical_source_action_binding_mismatch", "$.source_result.value.observation.receipt")
    observed_identity = _closed(
        receipt["observed_identity"], frozenset({"route_id", "model", "host"}),
        "canonical_source_action_identity_invalid", "$.source_result.value.observation.receipt.observed_identity",
    )
    for field, item in observed_identity.items():
        if item == "unknown":
            raise SupportedHostProducerError("canonical_source_action_identity_unknown", "$.source_result.value.observation.receipt.observed_identity." + field)
        _identifier(item, "$.source_result.value.observation.receipt.observed_identity." + field)
    if receipt["receipt_sha256"] != digest({item: nested for item, nested in receipt.items() if item != "receipt_sha256"}):
        raise SupportedHostProducerError("canonical_source_action_digest_mismatch", "$.source_result.value.observation.receipt.receipt_sha256")
    observed = _parse_time(receipt["observed_at"], "$.source_result.value.observation.receipt.observed_at")
    requested = _parse_time(receipt["requested_at"], "$.source_result.value.observation.receipt.requested_at")
    if requested > observed or observed != source_observed or observed > now or observed > observation_expires:
        raise SupportedHostProducerError("canonical_source_action_stale", "$.source_result.value.observation.receipt.observed_at")
    if operation_body["action_id"] != key or operation_body["operation"] != receipt["operation"]:
        raise SupportedHostProducerError("canonical_source_action_binding_mismatch", "$.operation_body")
    exact_identity = {field: identity[field] for field in ("workspace_id", "source_sha256", "candidate_sha256")}
    try:
        effect_request = effects_v1.validate_effect_request(
            operation_body["effect_request"], exact_identity, operation_body["operation"], now,
        )
        effects_v1.validate_registration(registration, key, effect_request)
        effects_v1.validate_action_receipt(
            receipt, action_id=key, operation=operation_body["operation"], request=effect_request, now=now,
        )
    except CompanionError as exc:
        raise SupportedHostProducerError(exc.code, exc.path) from exc


def _validate_grant_value(
    operation: str,
    value: Mapping[str, Any],
    key: str,
    identity: Mapping[str, Any],
    now: datetime,
    source_expires: datetime,
    operation_body: Mapping[str, Any],
) -> None:
    exact_identity = _closed(
        value["identity"], frozenset({"workspace_id", "source_sha256", "candidate_sha256"}),
        "canonical_source_identity_mismatch", "$.source_result.value.identity",
    )
    for field in exact_identity:
        if exact_identity[field] != identity[field]:
            raise SupportedHostProducerError("canonical_source_identity_mismatch", "$.source_result.value.identity." + field)
    expected_body_fields = (
        frozenset({"mode", "record", "context", "seal"})
        if operation == "commit_or_verify_record"
        else frozenset({"mode", "context", "seal"})
    )
    body = _closed(
        value["body"], expected_body_fields,
        "canonical_source_operation_shape_invalid", "$.source_result.value.body",
    )
    expected_mode = "commit" if operation == "commit_or_verify_record" else "seal"
    if body["mode"] != expected_mode or body["seal"] is not None or (
        operation == "commit_or_verify_record" and body["record"] is not None
    ):
        raise SupportedHostProducerError("canonical_source_operation_version_invalid", "$.source_result.value.body")
    if body != dict(operation_body):
        raise SupportedHostProducerError("canonical_source_operation_body_mismatch", "$.source_result.value.body")
    if not isinstance(body["context"], Mapping):
        raise SupportedHostProducerError("canonical_source_operation_shape_invalid", "$.source_result.value.body.context")
    if key != digest({"identity": exact_identity, "body": body}):
        raise SupportedHostProducerError("canonical_source_key_mismatch", "$.source_result.key")
    _sha(value["opaque_seal"], "$.source_result.value.opaque_seal")
    if value["revoked"] is not False:
        raise SupportedHostProducerError("canonical_source_observation_revoked", "$.source_result.value.revoked")
    expires = _parse_time(value["expires_at"], "$.source_result.value.expires_at")
    if expires <= now or expires != source_expires:
        raise SupportedHostProducerError("canonical_source_expiry_invalid", "$.source_result.value.expires_at")
    context = body["context"]
    if operation == "commit_or_verify_record":
        context = _closed(
            context,
            frozenset({
                "artifact_set_sha256", "workspace_id", "source_sha256", "candidate_sha256",
                "service_instance_id", "admission_seal",
            }),
            "canonical_source_operation_shape_invalid", "$.source_result.value.body.context",
        )
        for field in ("workspace_id", "source_sha256", "candidate_sha256", "service_instance_id"):
            if context[field] != identity[field]:
                raise SupportedHostProducerError("canonical_source_identity_mismatch", "$.source_result.value.body.context." + field)
        for field in ("artifact_set_sha256", "admission_seal"):
            _sha(context[field], "$.source_result.value.body.context." + field)
    else:
        context = _closed(
            context, frozenset({"admission_id", "artifact_set_sha256", "record_seal"}),
            "canonical_source_operation_shape_invalid", "$.source_result.value.body.context",
        )
        _identifier(context["admission_id"], "$.source_result.value.body.context.admission_id")
        for field in ("artifact_set_sha256", "record_seal"):
            _sha(context[field], "$.source_result.value.body.context." + field)


def _validate_responses_context_pair(
    value: Mapping[str, Any], key: str, identity: Mapping[str, Any],
    now: datetime, source_expires: datetime,
    operation_body: Mapping[str, Any],
) -> None:
    if key != "responses_context_pair_v1" or value["variant"] != "responses_context_pair_v1":
        raise SupportedHostProducerError("canonical_source_key_mismatch", "$.source_result.key")
    exact_identity = {field: identity[field] for field in ("workspace_id", "source_sha256", "candidate_sha256")}
    rows: dict[str, dict[str, Any]] = {}
    row_keys: dict[str, str] = {}
    for name in ("control_row", "request_row"):
        pair_row = _closed(
            value[name], _RESPONSES_PAIR_ROW_FIELDS,
            "canonical_source_operation_shape_invalid", "$.source_result.value." + name,
        )
        index_row = _closed(
            pair_row["value"], _RESPONSES_INDEX_ROW_FIELDS,
            "canonical_source_operation_shape_invalid", "$.source_result.value." + name + ".value",
        )
        if index_row["identity"] != exact_identity:
            raise SupportedHostProducerError("canonical_source_identity_mismatch", "$.source_result.value." + name + ".value.identity")
        if index_row["revoked"] is not False:
            raise SupportedHostProducerError("canonical_source_observation_revoked", "$.source_result.value." + name + ".value.revoked")
        if _parse_time(index_row["expires_at"], "$.source_result.value." + name + ".value.expires_at") != source_expires:
            raise SupportedHostProducerError("canonical_source_expiry_invalid", "$.source_result.value." + name + ".value.expires_at")
        body = _closed(
            index_row["body"], frozenset({
                "mode", "responses_request", "control_action", "control_payload",
                "record_sha256", "service_instance_id", "recovery_grant_id", "recovery_grant_sha256",
            }),
            "canonical_source_operation_shape_invalid", "$.source_result.value." + name + ".value.body",
        )
        expected_key = responses_v1.context_key(body, exact_identity)
        if pair_row["key"] != expected_key:
            raise SupportedHostProducerError("canonical_source_key_mismatch", "$.source_result.value." + name + ".key")
        rows[name] = index_row
        row_keys[name] = pair_row["key"]
    control = rows["control_row"]
    request = rows["request_row"]
    request_value = control["value"]
    try:
        validated_request, _selection, _preset = responses_v1.validate_responses_request(request_value)
    except CompanionError as exc:
        raise SupportedHostProducerError(exc.code, exc.path) from exc
    if validated_request["workspace_id"] != exact_identity["workspace_id"]:
        raise SupportedHostProducerError("canonical_source_identity_mismatch", "$.source_result.value.control_row.value.value.workspace_id")
    expected_control_body = {
        "mode": "control", "responses_request": None, "control_action": "run",
        "control_payload": {"message": identity["candidate_sha256"]},
        "record_sha256": None, "service_instance_id": identity["service_instance_id"],
        "recovery_grant_id": None, "recovery_grant_sha256": None,
    }
    expected_request_body = {
        "mode": "request", "responses_request": request_value,
        "control_action": None, "control_payload": None, "record_sha256": None,
        "service_instance_id": None, "recovery_grant_id": None, "recovery_grant_sha256": None,
    }
    if control["body"] != expected_control_body or request["body"] != expected_request_body:
        raise SupportedHostProducerError("canonical_source_responses_binding_mismatch", "$.source_result.value")
    if control["body"] != dict(operation_body):
        raise SupportedHostProducerError("canonical_source_operation_body_mismatch", "$.operation_body")
    try:
        responses_v1._validate_context_shape(request["value"], exact_identity, now)
    except CompanionError as exc:
        raise SupportedHostProducerError(exc.code, exc.path) from exc
    if row_keys["control_row"] == row_keys["request_row"]:
        raise SupportedHostProducerError("canonical_source_key_mismatch", "$.source_result.value")


def _derive_positive_key_v1(
    operation: str, value: Mapping[str, Any], identity: Mapping[str, Any],
    operation_body: Mapping[str, Any], operation_body_sha256: str,
) -> str:
    """Derive the operation key from owner state. Never accept a supplied key."""
    if operation == "commit_operator_selection":
        return operation_body_sha256
    if operation == "verify_effect_authority":
        return _sha(value.get("request_sha256"), "$.source_result.value.request_sha256")
    if operation == "verify_responses_bridge":
        return digest({
            "identity": {field: identity[field] for field in ("workspace_id", "source_sha256", "candidate_sha256")},
            "body": dict(operation_body), "value": value.get("value"),
        })
    if operation == "read_operator_preset_bundle":
        return _sha(value.get("bundle_sha256"), "$.source_result.value.bundle_sha256")
    if operation == "read_operator_selection_head":
        return _sha(value.get("receipt_sha256"), "$.source_result.value.receipt_sha256")
    if operation == "read_operator_selection_mutation":
        return _sha(value.get("submission_sha256"), "$.source_result.value.submission_sha256")
    if operation == "read_operator_supervision":
        return supervision_v1.inventory_key(operation_body, identity)
    if operation == "read_operator_recovery_lease_grant":
        return recovery_v1.reservation_key(operation_body, identity)
    if operation == "invoke_registered_action":
        registration = value.get("registration")
        if not isinstance(registration, Mapping):
            raise SupportedHostProducerError("canonical_source_operation_shape_invalid", "$.source_result.value.registration")
        return _identifier(registration.get("action_id"), "$.source_result.value.registration.action_id")
    if operation in {"commit_or_verify_record", "seal_or_verify_projection"}:
        return digest({
            "identity": {field: identity[field] for field in ("workspace_id", "source_sha256", "candidate_sha256")},
            "body": dict(operation_body),
        })
    if operation == "issue_responses_context":
        return "responses_context_pair_v1"
    raise SupportedHostProducerError("producer_operation_invalid", "$.operation")


def prepare_positive_source_material_v1(
    operation: str, *, identity: Mapping[str, Any], dependency_receipts: Mapping[str, str],
    operation_body: Mapping[str, Any], owner_value: Mapping[str, Any],
    observed_at: str, expires_at: str, canonical_source_id: str,
) -> Mapping[str, Any]:
    """Validate owner state and return the one accepted key and source digest."""
    if operation not in EXTERNAL_OPERATION_SET:
        raise SupportedHostProducerError("producer_operation_invalid", "$.operation")
    exact_identity = _closed(identity, IDENTITY_FIELDS, "canonical_source_identity_mismatch", "$.identity")
    body = _validate_operation_body(operation, operation_body)
    value = _validate_operation_value(operation, owner_value, exact_identity)
    observed = _parse_time(observed_at, "$.observed_at")
    expires = _parse_time(expires_at, "$.expires_at")
    if expires <= observed:
        raise SupportedHostProducerError("canonical_source_expiry_invalid", "$.expires_at")
    if not isinstance(dependency_receipts, Mapping) or any(
        not isinstance(name, str) or not isinstance(item, str) or _SHA256.fullmatch(item) is None
        for name, item in dependency_receipts.items()
    ):
        raise SupportedHostProducerError("producer_dependencies_invalid", "$.dependencies")
    body_sha256 = digest(body)
    key = _derive_positive_key_v1(operation, value, exact_identity, body, body_sha256)
    if operation == "invoke_registered_action":
        _validate_action_value(value, key, observed, observed, expires, body, exact_identity)
    elif operation == "issue_responses_context":
        _validate_responses_context_pair(value, key, exact_identity, observed, expires, body)
    elif operation in {"commit_or_verify_record", "seal_or_verify_projection"}:
        _validate_grant_value(operation, value, key, exact_identity, observed, expires, body)
    elif operation == "commit_operator_selection":
        _validate_command_authorization(value, key, body_sha256)
    elif operation == "verify_effect_authority":
        _validate_effect_authority_value(value, key, exact_identity, observed, expires, body)
    elif operation == "verify_responses_bridge":
        _validate_bridge_value(value, key, exact_identity, expires, body)
    elif operation in {"read_operator_preset_bundle", "read_operator_selection_head", "read_operator_selection_mutation"}:
        _validate_catalog_selection_value(operation, value, key, exact_identity, observed, expires, body)
    elif operation == "read_operator_supervision":
        _validate_supervision_value(value, key, exact_identity, body)
    elif operation == "read_operator_recovery_lease_grant":
        _validate_recovery_value(value, key, exact_identity, observed, expires, body)
    canonical_source_id = _identifier(canonical_source_id, "$.canonical_source_id")
    source_digest = accepted_positive_source_digest_v1(
        operation, key=key, value=value, observed_at=observed_at, expires_at=expires_at,
        canonical_source_id=canonical_source_id, identity=exact_identity,
        dependency_receipt_sha256=[dependency_receipts[name] for name in sorted(dependency_receipts)],
        operation_body_sha256=body_sha256,
    )
    return MappingProxyType({
        "key": key, "value": MappingProxyType(deepcopy(value)),
        "operation_body_sha256": body_sha256,
        "dependency_receipts_sha256": digest(dict(sorted(dependency_receipts.items()))),
        "source_digest": source_digest,
    })


def _normalize_source_result(
    value: Any,
    operation: str,
    now: datetime,
    max_age_seconds: int,
    identity: Mapping[str, Any],
    dependency_receipt_sha256: list[str],
    operation_body_sha256: str,
    operation_body: Mapping[str, Any],
    *, allow_test_only: bool, production_runtime: bool,
) -> dict[str, Any]:
    available_object = isinstance(value, (AvailableFact, StoreDerivedAvailableFact, ValidatedProtectedFact))
    os_validated = isinstance(value, ValidatedProtectedFact)
    if isinstance(value, UnavailableFact):
        value = value.as_mapping()
    elif available_object:
        value = {
            "schema_version": 1,
            "artifact_type": FACT_RESULT_TYPE,
            "operation": value.operation,
            "state": "available",
            "key": value.key,
            "value": deepcopy(dict(value.value)),
            "observed_at": format_time(value.observed_at),
            "expires_at": format_time(value.expires_at),
            "canonical_source_id": value.canonical_source_id,
            "source_digest": value.source_digest,
        }
    if not isinstance(value, Mapping):
        raise SupportedHostProducerError("canonical_source_result_invalid", "$.source_result")
    state = value.get("state")
    fields = UNAVAILABLE_RESULT_FIELDS if state == "unavailable" else AVAILABLE_RESULT_FIELDS if state == "available" else frozenset()
    result = _closed(value, fields, "canonical_source_result_shape_invalid", "$.source_result")
    if result["schema_version"] != 1 or result["artifact_type"] != FACT_RESULT_TYPE or result["operation"] != operation:
        raise SupportedHostProducerError("canonical_source_result_identity_invalid", "$.source_result")
    _identifier(result["canonical_source_id"], "$.source_result.canonical_source_id")
    if state == "unavailable":
        _identifier(result["reason"], "$.source_result.reason")
        return {
            "state": "unavailable",
            "fact": {},
            "reason": result["reason"],
            "canonical_source_id": result["canonical_source_id"],
        }
    if not available_object:
        raise SupportedHostProducerError("canonical_source_available_type_invalid", "$.source_result")
    if allow_test_only:
        pass
    elif not os_validated or not production_runtime:
        raise SupportedHostProducerError("canonical_source_authority_invalid", "$.source_result")
    _identifier(result["key"], "$.source_result.key")
    if not isinstance(result["value"], Mapping):
        raise SupportedHostProducerError("canonical_source_fact_invalid", "$.source_result.value")
    _sha(result["source_digest"], "$.source_result.source_digest")
    result["value"] = _validate_operation_value(operation, result["value"], identity)
    observed = _parse_time(result["observed_at"], "$.source_result.observed_at")
    expires = _parse_time(result["expires_at"], "$.source_result.expires_at")
    if observed > now or (now - observed).total_seconds() > max_age_seconds:
        raise SupportedHostProducerError("canonical_source_stale", "$.source_result.observed_at")
    if expires <= now or expires <= observed or (expires - observed).total_seconds() > max_age_seconds:
        raise SupportedHostProducerError("canonical_source_expiry_invalid", "$.source_result.expires_at")
    if operation == "invoke_registered_action":
        _validate_action_value(
            result["value"], result["key"], now, observed, expires, operation_body, identity,
        )
    if operation == "issue_responses_context":
        _validate_responses_context_pair(
            result["value"], result["key"], identity, now, expires, operation_body,
        )
    if operation in {"commit_or_verify_record", "seal_or_verify_projection"}:
        _validate_grant_value(
            operation, result["value"], result["key"], identity, now, expires, operation_body,
        )
    if operation == "commit_operator_selection":
        _validate_command_authorization(
            result["value"], result["key"], operation_body_sha256,
        )
    if operation == "verify_effect_authority":
        _validate_effect_authority_value(
            result["value"], result["key"], identity, now, expires, operation_body,
        )
    if operation == "verify_responses_bridge":
        _validate_bridge_value(
            result["value"], result["key"], identity, expires, operation_body,
        )
    if operation in {
        "read_operator_preset_bundle", "read_operator_selection_head",
        "read_operator_selection_mutation",
    }:
        _validate_catalog_selection_value(
            operation, result["value"], result["key"], identity, now, expires, operation_body,
        )
    if operation == "read_operator_supervision":
        _validate_supervision_value(result["value"], result["key"], identity, operation_body)
    if operation == "read_operator_recovery_lease_grant":
        _validate_recovery_value(
            result["value"], result["key"], identity, now, expires, operation_body,
        )
    expected_source_digest = accepted_positive_source_digest_v1(
        operation, key=result["key"], value=result["value"],
        observed_at=result["observed_at"], expires_at=result["expires_at"],
        canonical_source_id=result["canonical_source_id"], identity=identity,
        dependency_receipt_sha256=dependency_receipt_sha256,
        operation_body_sha256=operation_body_sha256,
    )
    if result["source_digest"] != expected_source_digest:
        raise SupportedHostProducerError("canonical_source_digest_mismatch", "$.source_result.source_digest")
    return {
        "state": "available", "fact": {"key": result["key"], "value": result["value"]},
        "canonical_source_id": result["canonical_source_id"], "source_digest": result["source_digest"],
    }


class ProducerClient:
    """Construct and submit one exact accepted-v8 producer binding request."""

    __slots__ = ("_config", "_source", "_identity", "_dependencies", "_clock", "_transport", "_used", "_test_only")

    def __init__(
        self,
        configuration: ValidatedPublicConfiguration,
        fact_source: CanonicalFactSource,
        identity: BoundServiceIdentity,
        dependency_receipt_digests: ValidatedDependencyReceiptDigests,
        utc_clock: Callable[[], datetime],
        transport: OsBoundOpaqueTlsTransport | TestOnlyInMemoryReceiverTransport,
        *, _test_only: bool = False,
    ) -> None:
        if not isinstance(configuration, ValidatedPublicConfiguration):
            raise SupportedHostProducerError("producer_config_unvalidated", "$.config")
        if not isinstance(identity, BoundServiceIdentity):
            raise SupportedHostProducerError("producer_identity_unvalidated", "$.identity")
        if not isinstance(fact_source, CanonicalFactSource):
            raise SupportedHostProducerError("canonical_fact_source_invalid", "$.fact_source")
        if not callable(utc_clock):
            raise SupportedHostProducerError("utc_clock_invalid", "$.clock")
        if not isinstance(dependency_receipt_digests, ValidatedDependencyReceiptDigests):
            raise SupportedHostProducerError("producer_dependencies_unvalidated", "$.dependencies")
        if not _test_only and type(fact_source) is not FirstPartySupportedHostRuntimeV1:
            raise SupportedHostProducerError("canonical_fact_source_not_first_party_runtime", "$.fact_source")
        expected_transport = TestOnlyInMemoryReceiverTransport if _test_only else OsBoundOpaqueTlsTransport
        if type(transport) is not expected_transport:
            raise SupportedHostProducerError("producer_transport_invalid", "$.transport")
        # Revalidate detached public inputs here. Python wrapper identity is not
        # an authority boundary and direct wrapper construction cannot bypass validation.
        self._config = validate_public_configuration(configuration.value)
        self._source = fact_source
        self._identity = validate_bound_service_identity(identity.value)
        self._dependencies = validate_dependency_receipt_digests(
            dependency_receipt_digests.receipts,
        ).value
        self._clock = utc_clock
        self._transport = transport
        self._used = False
        self._test_only = _test_only is True

    @classmethod
    def test_only(
        cls, configuration: ValidatedPublicConfiguration, fact_source: CanonicalFactSource,
        identity: BoundServiceIdentity,
        dependency_receipt_digests: ValidatedDependencyReceiptDigests,
        utc_clock: Callable[[], datetime],
        transport: TestOnlyInMemoryReceiverTransport,
    ) -> "ProducerClient":
        """Create an isolated fixture validator that cannot use production transport."""
        return cls(configuration, fact_source, identity, dependency_receipt_digests,
                   utc_clock, transport, _test_only=True)

    def bind(
        self,
        operation: str,
        *,
        operation_body: Mapping[str, Any],
        previous_durable_index_sha256: str,
        previous_readiness_sha256: str,
        predecessor_admission_sha256: str,
    ) -> dict[str, Any]:
        if self._used:
            raise SupportedHostProducerError("producer_client_reused", "$.client")
        self._used = True
        if operation not in EXTERNAL_OPERATION_SET:
            raise SupportedHostProducerError("producer_operation_invalid", "$.operation")
        body = _validate_operation_body(operation, operation_body)
        body_sha256 = digest(body)
        previous_durable_index_sha256 = _sha(previous_durable_index_sha256, "$.previous_durable_index_sha256")
        previous_readiness_sha256 = _sha(previous_readiness_sha256, "$.previous_readiness_sha256")
        predecessor_admission_sha256 = _sha(predecessor_admission_sha256, "$.predecessor_admission_sha256")
        now = _utc(self._clock(), "$.clock")
        policy = self._config.policy
        row = _policy_row(policy, operation)
        principal = _principal(policy, operation)
        if row.get("principal_id") != principal["principal_id"]:
            raise SupportedHostProducerError("producer_principal_map_invalid", "$.operation")
        expected_dependencies = row["dependency_operations"]
        if set(self._dependencies) != set(expected_dependencies):
            raise SupportedHostProducerError("producer_dependencies_invalid", "$.dependencies")
        lifetime = self._config.value["binding_lifetime_seconds"]
        if lifetime > row["max_age_seconds"]:
            raise SupportedHostProducerError("producer_config_lifetime_invalid", "$.config.binding_lifetime_seconds")
        try:
            production_runtime = type(self._source) is FirstPartySupportedHostRuntimeV1
            arguments = (operation, self._identity.value,
                         MappingProxyType(dict(self._dependencies)), now)
            source_result = (
                self._source.read_fact(*arguments, body)
                if production_runtime else self._source.read_fact(*arguments)
            )
        except SupportedHostProducerError:
            raise
        except Exception as exc:
            raise SupportedHostProducerError("canonical_source_failed", "$.fact_source") from exc
        ordered_dependency_digests = [self._dependencies[item] for item in sorted(self._dependencies)]
        normalized = _normalize_source_result(
            source_result, operation, now, row["max_age_seconds"],
            self._identity.value, ordered_dependency_digests,
            body_sha256,
            body,
            allow_test_only=self._test_only,
            production_runtime=production_runtime,
        )
        if normalized["canonical_source_id"] != row["evidence_source_id"]:
            raise SupportedHostProducerError("canonical_source_policy_mismatch", "$.source_result.canonical_source_id")
        payload = {
            "schema_version": 1,
            "artifact_type": "package_host_operation_fact_v1",
            "operation": operation,
            "state": normalized["state"],
            "fact": normalized["fact"],
            "fact_sha256": digest(normalized["fact"]),
        }
        if row["payload_schema_sha256"] != operation_payload_schema_sha256(operation):
            raise SupportedHostProducerError("producer_payload_schema_mismatch", "$.config.producer_policy")
        identity = self._identity.value
        observed_at = format_time(now)
        expires_at = format_time(now + timedelta(seconds=lifetime))
        source_outcome = {
            "state": normalized["state"],
            "reason": normalized.get("reason"),
            "canonical_source_id": normalized["canonical_source_id"],
        }
        source_binding = deepcopy(source_outcome)
        if normalized["state"] == "available":
            source_binding["source_digest"] = normalized["source_digest"]
        host_profile_identity = {
            "host_profile_id": self._config.value["expected_host_profile_id"],
            "host_profile_sha256": self._config.value["expected_host_profile_sha256"],
        }
        correlation_core = {
            "operation": operation,
            "identity": dict(identity),
            "source_result": source_binding,
            "dependency_receipt_sha256": [self._dependencies[item] for item in expected_dependencies],
            "observed_at": observed_at,
            "expires_at": expires_at,
            "operation_body": body,
            "operation_body_sha256": body_sha256,
            "previous_durable_index_sha256": previous_durable_index_sha256,
            "previous_readiness_sha256": previous_readiness_sha256,
            "predecessor_admission_sha256": predecessor_admission_sha256,
            "policy_sha256": policy["policy_sha256"],
            "host_profile_identity": host_profile_identity,
        }
        correlation_id = "correlation-" + digest(correlation_core).split(":", 1)[1][:32]
        evidence_id = "evidence-" + digest({
            "correlation_id": correlation_id,
            "binding": correlation_core,
        }).split(":", 1)[1][:32]
        request_preimage = {
            "schema_version": 1,
            "artifact_type": REQUEST_PREIMAGE_TYPE,
            "correlation_id": correlation_id,
            "evidence_id": evidence_id,
            **correlation_core,
        }
        request_preimage = _closed(
            request_preimage, REQUEST_PREIMAGE_FIELDS,
            "producer_request_preimage_shape_invalid", "$.request_digest_preimage",
        )
        request_sha256 = digest(request_preimage)
        response_preimage = {
            **deepcopy(request_preimage),
            "artifact_type": RESPONSE_PREIMAGE_TYPE,
            "request_sha256": request_sha256,
            "intended_unavailable_outcome": deepcopy(source_outcome),
        }
        response_preimage = _closed(
            response_preimage, RESPONSE_PREIMAGE_FIELDS,
            "producer_response_preimage_shape_invalid", "$.response_digest_preimage",
        )
        response_sha256 = digest(response_preimage)
        request = {
            "schema_version": 1,
            "artifact_type": BINDING_REQUEST_TYPE,
            "evidence_id": evidence_id,
            "operation": operation,
            **dict(identity),
            "request_sha256": request_sha256,
            "response_sha256": response_sha256,
            "dependency_receipt_sha256": [self._dependencies[item] for item in expected_dependencies],
            "observed_at": observed_at,
            "expires_at": expires_at,
            "payload": payload,
            "payload_sha256": digest(payload),
            "operation_body": body,
            "operation_body_sha256": body_sha256,
            "previous_durable_index_sha256": previous_durable_index_sha256,
            "previous_readiness_sha256": previous_readiness_sha256,
            "predecessor_admission_sha256": predecessor_admission_sha256,
            "policy_sha256": policy["policy_sha256"],
            "receipt_type": row["receipt_type"],
        }
        if set(request) != set(BINDING_REQUEST_FIELDS):
            raise SupportedHostProducerError("producer_request_shape_invalid", "$.request")
        try:
            exchange = self._transport._consume(self._config.value["server_leaf_sha256"])
            response = exchange(canonical_json(request))
        except SupportedHostProducerError:
            raise
        except Exception as exc:
            raise SupportedHostProducerError("producer_transport_failed", "$.transport") from exc
        receiver_receipt, receiver_envelope = self._validate_response(
            response, request, row, principal, now,
        )
        outcome = {
            "schema_version": 1,
            "artifact_type": LOCAL_OUTCOME_TYPE,
            "operation": operation,
            **source_outcome,
            "request_digest_preimage": request_preimage,
            "response_digest_preimage": response_preimage,
            "receiver_receipt": receiver_receipt,
            "receiver_envelope": receiver_envelope,
        }
        return _closed(outcome, LOCAL_OUTCOME_FIELDS, "producer_local_outcome_shape_invalid", "$.outcome")

    def _validate_response(
        self,
        response: bytes | bytearray | memoryview | Mapping[str, Any],
        request: Mapping[str, Any],
        row: Mapping[str, Any],
        principal: Mapping[str, Any],
        now: datetime,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            decoded = decode_frame(response)
        except CompanionError as exc:
            raise SupportedHostProducerError(exc.code, exc.path) from exc
        response_value = _closed(
            decoded, RECEIVER_RESPONSE_FIELDS,
            "producer_response_shape_invalid", "$.response",
        )
        receipt = response_value["receipt"]
        receipt = _closed(receipt, RECEIPT_FIELDS, "producer_response_shape_invalid", "$.response")
        if receipt["schema_version"] != 1 or receipt["artifact_type"] != RECEIPT_TYPE:
            raise SupportedHostProducerError("producer_response_version_invalid", "$.response")
        for field in BINDING_REQUEST_FIELDS - {"artifact_type"}:
            if receipt[field] != request[field]:
                raise SupportedHostProducerError("producer_response_binding_mismatch", "$.response." + field)
        expected_authority = {
            "producer_id": principal["principal_id"],
            "evidence_issuer_id": row["evidence_issuer_id"],
            "evidence_source_id": row["evidence_source_id"],
            "transport_submitter_leaf_sha256": principal["client_leaf_sha256"],
        }
        for field, expected in expected_authority.items():
            if receipt[field] != expected:
                raise SupportedHostProducerError("producer_response_authority_mismatch", "$.response." + field)
        _sha(receipt["receipt_sha256"], "$.response.receipt_sha256")
        expected_digest = digest({key: item for key, item in receipt.items() if key != "receipt_sha256"})
        if receipt["receipt_sha256"] != expected_digest:
            raise SupportedHostProducerError("producer_response_digest_mismatch", "$.response.receipt_sha256")
        observed = _parse_time(receipt["observed_at"], "$.response.observed_at")
        expires = _parse_time(receipt["expires_at"], "$.response.expires_at")
        if observed > now or (now - observed).total_seconds() > row["max_age_seconds"]:
            raise SupportedHostProducerError("producer_response_stale", "$.response.observed_at")
        if expires <= now or expires <= observed or (expires - observed).total_seconds() > row["max_age_seconds"]:
            raise SupportedHostProducerError("producer_response_expiry_invalid", "$.response.expires_at")
        try:
            envelope = validate_receiver_binding_envelope_v1(
                response_value["envelope"],
                expected_operation=request["operation"],
                expected_operation_body_sha256=request["operation_body_sha256"],
                expected_identity={field: request[field] for field in IDENTITY_FIELDS},
                now=int(now.timestamp()),
            )
        except CompanionError as exc:
            raise SupportedHostProducerError(exc.code, exc.path) from exc
        exact_envelope_bindings = {
            "policy_sha256": request["policy_sha256"],
            "dependency_receipt_sha256": request["dependency_receipt_sha256"],
            "producer_receipt_sha256": receipt["receipt_sha256"],
            "observed_at": receipt["observed_at"],
            "expires_at": receipt["expires_at"],
            "previous_durable_index_sha256": request["previous_durable_index_sha256"],
            "previous_readiness_sha256": request["previous_readiness_sha256"],
            "predecessor_admission_sha256": request["predecessor_admission_sha256"],
            "evidence_id": request["evidence_id"],
            "producer_id": principal["principal_id"],
        }
        for field, expected in exact_envelope_bindings.items():
            if envelope[field] != expected:
                raise SupportedHostProducerError(
                    "producer_response_envelope_binding_mismatch",
                    "$.response.envelope." + field,
                )
        return receipt, envelope
