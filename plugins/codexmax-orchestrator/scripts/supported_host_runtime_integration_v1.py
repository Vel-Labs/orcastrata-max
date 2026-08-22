#!/usr/bin/env python3
"""Closed source-local registry for the twelve supported-host operations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from types import MappingProxyType
from typing import Any, Mapping

from package_host_supported_host_fact_sources_v1 import (
    EXTERNAL_OPERATIONS,
    EXTERNAL_OPERATION_SET,
    FACT_RESULT_TYPE,
    UnavailableFact,
    t063_source_ids,
)
from supported_host_catalog_selection_v1 import (
    CatalogSource,
    SelectionCommitSource,
    SelectionHeadSource,
    SelectionMutationSource,
)
from supported_host_effect_authority_v1 import EffectAuthorityFactSource
from supported_host_recovery_v1 import RecoveryLeaseSource
from supported_host_registered_action_v1 import RegisteredActionFactSource
from supported_host_responses_seals_v1 import (
    OPERATION_SET as RESPONSES_OPERATION_SET,
    ProjectionAuthoritySource,
    RecordAuthoritySource,
    ResponsesBridgeSource,
    ResponsesContextSource,
    SOURCE_IDS as RESPONSES_SOURCE_IDS,
    UNAVAILABLE_TYPE as RESPONSES_LEGACY_UNAVAILABLE_TYPE,
)
from supported_host_supervision_v1 import SupervisionSource


AUTHENTICATION_SCHEME = "external_source_mtls_v2"
INTEGRATION_STATE = "external_gate_required"
MATRIX_TYPE = "supported_host_runtime_integration_matrix_v1"
GATE_TYPE = "supported_host_runtime_external_gate_v1"
MAX_AGE_SECONDS = 300
SERVICE_OWNED_OPERATIONS = frozenset({"read_capability_admission", "open_operator_listener"})
SEMANTIC_OPERATION_SET = EXTERNAL_OPERATION_SET | SERVICE_OWNED_OPERATIONS
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_LEGACY_RESULT_FIELDS = frozenset({
    "schema_version", "artifact_type", "operation", "state", "reason", "canonical_source_id",
})
_LEGACY_UNAVAILABLE_REASON = "canonical_positive_source_not_implemented"
_BOUNDARY_INVENTORY = (
    ("operation_input", "exact_string_external_membership", "canonical_operation_invalid", "$.operation"),
    ("source_dispatch", "lookup_after_operation_validation", "canonical_operation_invalid", "$.operation"),
    ("exact_identity", "mapping", "exact_identity_invalid", "$.exact_identity"),
    ("dependency_receipts", "mapping", "dependency_receipts_invalid", "$.dependency_receipts"),
    ("dependency_receipt_entry", "string_key_and_sha256_string", "dependency_receipts_invalid", "$.dependency_receipts"),
    ("clock", "aware_utc_datetime", "utc_clock_invalid", "$.now"),
    ("family_result", "shared_unavailable_or_legacy_mapping", "canonical_source_result_invalid", "$.source_result"),
    ("legacy_shape", "exact_six_fields", "legacy_result_shape_invalid", "$.source_result"),
    ("legacy_schema_version", "exact_int_1", "legacy_result_schema_version_invalid", "$.source_result.schema_version"),
    ("legacy_artifact_type", "exact_t066_string", "legacy_result_artifact_type_invalid", "$.source_result.artifact_type"),
    ("legacy_operation", "string_t066_membership_and_expected_match", "legacy_result_operation_invalid", "$.source_result.operation"),
    ("legacy_state", "exact_unavailable_string", "legacy_result_state_invalid", "$.source_result.state"),
    ("legacy_reason", "exact_t066_reason_string", "legacy_result_reason_invalid", "$.source_result.reason"),
    ("legacy_source", "exact_t066_source_table_string", "legacy_result_source_invalid", "$.source_result.canonical_source_id"),
    ("normalized_result", "expected_operation_source_and_nonempty_reason", "canonical_source_result_invalid", "$.source_result"),
    ("matrix_tables", "fixed_external_iteration_before_lookup", "canonical_operation_invalid", "$.operation"),
    ("external_gate", "zero_input_non_eligible_fixed_value", "canonical_source_result_invalid", "$.source_result"),
)


class RuntimeIntegrationError(ValueError):
    """A stable non-echoing runtime-integration rejection."""

    def __init__(self, code: str, location: str = "$") -> None:
        self.code = code
        self.location = location
        super().__init__(f"{code}: {location}")


_SOURCE_FACTORIES = MappingProxyType({
    "verify_effect_authority": lambda: EffectAuthorityFactSource(None, None),
    "invoke_registered_action": RegisteredActionFactSource,
    "issue_responses_context": ResponsesContextSource,
    "verify_responses_bridge": ResponsesBridgeSource,
    "commit_or_verify_record": RecordAuthoritySource,
    "seal_or_verify_projection": ProjectionAuthoritySource,
    "read_operator_preset_bundle": CatalogSource,
    "read_operator_selection_head": SelectionHeadSource,
    "read_operator_selection_mutation": SelectionMutationSource,
    "commit_operator_selection": SelectionCommitSource,
    "read_operator_supervision": SupervisionSource,
    "read_operator_recovery_lease_grant": RecoveryLeaseSource,
})

_FAMILY = MappingProxyType({
    "verify_effect_authority": "effect_authority",
    "invoke_registered_action": "registered_action",
    "issue_responses_context": "responses_and_seals",
    "verify_responses_bridge": "responses_and_seals",
    "commit_or_verify_record": "responses_and_seals",
    "seal_or_verify_projection": "responses_and_seals",
    "read_operator_preset_bundle": "catalog_and_selection",
    "read_operator_selection_head": "catalog_and_selection",
    "read_operator_selection_mutation": "catalog_and_selection",
    "commit_operator_selection": "catalog_and_selection",
    "read_operator_supervision": "native_supervision",
    "read_operator_recovery_lease_grant": "recovery",
})

_OWNER_ROLE = MappingProxyType({
    "verify_effect_authority": "effect_authority_issuer_and_ledger_owner",
    "invoke_registered_action": "registered_action_executor_and_observation_owner",
    "issue_responses_context": "responses_context_issuer",
    "verify_responses_bridge": "responses_bridge_observation_owner",
    "commit_or_verify_record": "record_lineage_authority",
    "seal_or_verify_projection": "projection_seal_authority",
    "read_operator_preset_bundle": "qualified_catalog_publisher",
    "read_operator_selection_head": "selection_ledger_owner",
    "read_operator_selection_mutation": "selection_mutation_history_owner",
    "commit_operator_selection": "selection_commit_authority",
    "read_operator_supervision": "native_desktop_inventory_authority",
    "read_operator_recovery_lease_grant": "recovery_lease_authority",
})

_PERSISTENCE = MappingProxyType({
    "verify_effect_authority": "durable_append_only_authority_ledger",
    "invoke_registered_action": "durable_action_observation_store",
    "issue_responses_context": "durable_append_only_responses_ledger",
    "verify_responses_bridge": "durable_append_only_responses_ledger",
    "commit_or_verify_record": "durable_append_only_responses_ledger",
    "seal_or_verify_projection": "durable_append_only_responses_ledger",
    "read_operator_preset_bundle": "durable_append_only_catalog_ledger",
    "read_operator_selection_head": "durable_append_only_selection_ledger",
    "read_operator_selection_mutation": "durable_append_only_selection_ledger",
    "commit_operator_selection": "durable_append_only_selection_ledger",
    "read_operator_supervision": "durable_native_inventory_event_stream",
    "read_operator_recovery_lease_grant": "durable_recovery_ledger",
})

_ANCHOR_KIND = MappingProxyType({
    "verify_effect_authority": "non_caller_ledger_sequence_and_head",
    "invoke_registered_action": "non_caller_observation_sequence_and_head",
    "issue_responses_context": "non_caller_ledger_sequence_and_head",
    "verify_responses_bridge": "non_caller_ledger_sequence_and_head",
    "commit_or_verify_record": "non_caller_ledger_sequence_and_head",
    "seal_or_verify_projection": "non_caller_ledger_sequence_and_head",
    "read_operator_preset_bundle": "non_caller_ledger_sequence_and_head",
    "read_operator_selection_head": "non_caller_ledger_sequence_and_head",
    "read_operator_selection_mutation": "non_caller_ledger_sequence_and_head",
    "commit_operator_selection": "non_caller_ledger_sequence_and_head",
    "read_operator_supervision": "native_inventory_cursor_and_predecessor",
    "read_operator_recovery_lease_grant": "stable_scope_fence_sequence_and_head",
})

_SOURCE_CLASS = MappingProxyType({
    operation: factory().__class__.__name__ for operation, factory in _SOURCE_FACTORIES.items()
})

_MISSING_PUBLIC_CATEGORIES = (
    "authenticated_producer_identity",
    "current_public_certificate_chain",
    "durable_non_caller_anchor",
    "current_canonical_source_receipt",
    "current_freshness_evidence",
    "supported_host_profile_and_principal_operation_map",
)


def _operation(value: Any, location: str = "$.operation") -> str:
    if not isinstance(value, str) or value not in EXTERNAL_OPERATION_SET:
        raise RuntimeIntegrationError("canonical_operation_invalid", location)
    return value


def _inputs(exact_identity: Any, dependency_receipts: Any, now: Any) -> datetime:
    if not isinstance(exact_identity, Mapping):
        raise RuntimeIntegrationError("exact_identity_invalid", "$.exact_identity")
    if not isinstance(dependency_receipts, Mapping):
        raise RuntimeIntegrationError("dependency_receipts_invalid", "$.dependency_receipts")
    for key, value in dependency_receipts.items():
        if not isinstance(key, str) or not isinstance(value, str) or _SHA.fullmatch(value) is None:
            raise RuntimeIntegrationError("dependency_receipts_invalid", "$.dependency_receipts")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise RuntimeIntegrationError("utc_clock_invalid", "$.now")
    return now.astimezone(timezone.utc).replace(microsecond=0)


def _validate_legacy_unavailable_result(value: Any, expected_operation: str) -> dict[str, Any]:
    """Validate the one accepted T066 legacy unavailable result."""

    if not isinstance(value, Mapping) or set(value) != set(_LEGACY_RESULT_FIELDS):
        raise RuntimeIntegrationError("legacy_result_shape_invalid", "$.source_result")
    row = dict(value)
    if type(row["schema_version"]) is not int or row["schema_version"] != 1:
        raise RuntimeIntegrationError(
            "legacy_result_schema_version_invalid", "$.source_result.schema_version",
        )
    if (
        not isinstance(row["artifact_type"], str)
        or row["artifact_type"] != RESPONSES_LEGACY_UNAVAILABLE_TYPE
    ):
        raise RuntimeIntegrationError(
            "legacy_result_artifact_type_invalid", "$.source_result.artifact_type",
        )
    operation = row["operation"]
    if not isinstance(operation, str) or operation not in RESPONSES_OPERATION_SET:
        raise RuntimeIntegrationError("legacy_result_operation_invalid", "$.source_result.operation")
    if operation != expected_operation:
        raise RuntimeIntegrationError("legacy_result_operation_invalid", "$.source_result.operation")
    if not isinstance(row["state"], str) or row["state"] != "unavailable":
        raise RuntimeIntegrationError("legacy_result_state_invalid", "$.source_result.state")
    if (
        not isinstance(row["reason"], str)
        or row["reason"] != _LEGACY_UNAVAILABLE_REASON
    ):
        raise RuntimeIntegrationError("legacy_result_reason_invalid", "$.source_result.reason")
    source_id = row["canonical_source_id"]
    if (
        not isinstance(source_id, str)
        or source_id != RESPONSES_SOURCE_IDS[operation]
        or source_id != t063_source_ids()[operation]
    ):
        raise RuntimeIntegrationError(
            "legacy_result_source_invalid", "$.source_result.canonical_source_id",
        )
    return row


def _read_from_family(
    operation: str, exact_identity: Any, dependency_receipts: Mapping[str, str], now: datetime,
) -> UnavailableFact:
    operation = _operation(operation, "$.operation")
    result = _SOURCE_FACTORIES[operation]().read_fact(operation, exact_identity, dependency_receipts, now)
    if isinstance(result, UnavailableFact):
        unavailable = result
    elif isinstance(result, Mapping):
        validated = _validate_legacy_unavailable_result(result, operation)
        unavailable = UnavailableFact(
            operation=validated["operation"],
            reason=validated["reason"],
            canonical_source_id=validated["canonical_source_id"],
        )
    else:
        raise RuntimeIntegrationError("canonical_source_result_invalid", "$.source_result")
    if (
        unavailable.operation != operation
        or unavailable.canonical_source_id != t063_source_ids()[operation]
        or not isinstance(unavailable.reason, str)
        or not unavailable.reason
    ):
        raise RuntimeIntegrationError("canonical_source_result_invalid", "$.source_result")
    return unavailable


class _IntegratedUnavailableSource:
    """Bind one operation to its fixed family source and shared unavailable type."""

    __slots__ = ("_operation",)

    def __init__(self, operation: str) -> None:
        self._operation = _operation(operation)

    def read_fact(
        self,
        operation: str,
        exact_identity: Any,
        dependency_receipts: Mapping[str, str],
        now: datetime,
    ) -> UnavailableFact:
        operation = _operation(operation)
        if operation != self._operation:
            raise RuntimeIntegrationError("canonical_operation_invalid", "$.operation")
        current = _inputs(exact_identity, dependency_receipts, now)
        return _read_from_family(operation, exact_identity, dependency_receipts, current)


def source_for(operation: str) -> _IntegratedUnavailableSource:
    """Return the fixed integrated adapter for one external operation."""

    return _IntegratedUnavailableSource(operation)


def boundary_inventory() -> tuple[Mapping[str, str], ...]:
    """Return the immutable validation and dispatch boundary inventory."""

    return tuple(MappingProxyType({
        "boundary": boundary,
        "rule": rule,
        "error_code": error_code,
        "location": location,
    }) for boundary, rule, error_code, location in _BOUNDARY_INVENTORY)


def read_fact(
    operation: str,
    exact_identity: Any,
    dependency_receipts: Mapping[str, str],
    now: datetime,
) -> UnavailableFact:
    """Read through the fixed family adapter and preserve unavailable closure."""

    operation = _operation(operation)
    return source_for(operation).read_fact(operation, exact_identity, dependency_receipts, now)


def integration_matrix() -> tuple[Mapping[str, Any], ...]:
    """Return the exact immutable twelve-row source-of-truth matrix."""

    return tuple(MappingProxyType({
        "schema_version": 1,
        "artifact_type": MATRIX_TYPE,
        "operation": operation,
        "source_family": _FAMILY[operation],
        "source_class": _SOURCE_CLASS[operation],
        "canonical_source_id": t063_source_ids()[operation],
        "canonical_owner_role": _OWNER_ROLE[operation],
        "persistence": _PERSISTENCE[operation],
        "durable_anchor_kind": _ANCHOR_KIND[operation],
        "authentication_scheme": AUTHENTICATION_SCHEME,
        "max_age_seconds": MAX_AGE_SECONDS,
        "state": INTEGRATION_STATE,
    }) for operation in EXTERNAL_OPERATIONS)


def external_gate() -> Mapping[str, Any]:
    """Return the closed public external-execution gate. It grants no eligibility."""

    return MappingProxyType({
        "schema_version": 1,
        "artifact_type": GATE_TYPE,
        "state": INTEGRATION_STATE,
        "eligible": False,
        "authentication_scheme": AUTHENTICATION_SCHEME,
        "operation_count": len(EXTERNAL_OPERATIONS),
        "operations": tuple(EXTERNAL_OPERATIONS),
        "missing_public_categories": _MISSING_PUBLIC_CATEGORIES,
    })
