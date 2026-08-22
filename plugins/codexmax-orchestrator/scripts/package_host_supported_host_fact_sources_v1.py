#!/usr/bin/env python3
"""Closed canonical fact-source types for the supported-host producer plane.

This module performs no I/O.  T063 intentionally exposes only typed
``unavailable`` adapters.  Family successors can implement the protocol, but
the producer client still validates every returned value before it creates a
binding request.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping, Protocol, runtime_checkable


EXTERNAL_OPERATIONS = (
    "commit_operator_selection",
    "commit_or_verify_record",
    "invoke_registered_action",
    "issue_responses_context",
    "read_operator_preset_bundle",
    "read_operator_recovery_lease_grant",
    "read_operator_selection_head",
    "read_operator_selection_mutation",
    "read_operator_supervision",
    "seal_or_verify_projection",
    "verify_effect_authority",
    "verify_responses_bridge",
)
EXTERNAL_OPERATION_SET = frozenset(EXTERNAL_OPERATIONS)
FACT_RESULT_TYPE = "package_host_canonical_fact_result_v1"


class CanonicalFactSourceError(ValueError):
    """A stable, non-echoing canonical source rejection."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


@dataclass(frozen=True, slots=True)
class UnavailableFact:
    """A typed result that cannot carry positive fact authority."""

    operation: str
    reason: str
    canonical_source_id: str

    def as_mapping(self) -> Mapping[str, Any]:
        return MappingProxyType({
            "schema_version": 1,
            "artifact_type": FACT_RESULT_TYPE,
            "operation": self.operation,
            "state": "unavailable",
            "reason": self.reason,
            "canonical_source_id": self.canonical_source_id,
        })


@dataclass(frozen=True, slots=True)
class AvailableFact:
    """Explicit test-fixture shape. Production rejects caller-created values."""

    operation: str
    key: str
    value: Mapping[str, Any]
    observed_at: datetime
    expires_at: datetime
    canonical_source_id: str
    source_digest: str


@runtime_checkable
class CanonicalFactSource(Protocol):
    """Read one fact from one named canonical authority."""

    def read_fact(
        self,
        operation: str,
        exact_identity: Any,
        dependency_receipts: Mapping[str, str],
        now: datetime,
        operation_body: Mapping[str, Any] | None = None,
    ) -> UnavailableFact | AvailableFact | Mapping[str, Any]: ...


_SOURCE_IDS = MappingProxyType({
    "verify_effect_authority": "effect-authority-ledger",
    "invoke_registered_action": "registered-action-observation-store",
    "issue_responses_context": "responses-context-issuer",
    "verify_responses_bridge": "responses-bridge-observation-store",
    "commit_or_verify_record": "record-lineage-authority",
    "seal_or_verify_projection": "projection-seal-authority",
    "read_operator_preset_bundle": "operator-catalog-publisher",
    "read_operator_selection_head": "operator-selection-ledger",
    "read_operator_selection_mutation": "operator-selection-mutation-history",
    "commit_operator_selection": "operator-selection-commit-authority",
    "read_operator_supervision": "native-desktop-inventory-authority",
    "read_operator_recovery_lease_grant": "recovery-lease-authority",
})


class UnavailableCanonicalFactSource:
    """The exact T063 adapter set.  Every operation remains unavailable."""

    __slots__ = ()

    def read_fact(
        self,
        operation: str,
        exact_identity: Any,
        dependency_receipts: Mapping[str, str],
        now: datetime,
        operation_body: Mapping[str, Any] | None = None,
    ) -> UnavailableFact:
        del exact_identity, dependency_receipts, now, operation_body
        if operation not in EXTERNAL_OPERATION_SET:
            raise CanonicalFactSourceError("canonical_operation_invalid", "$.operation")
        return UnavailableFact(
            operation=operation,
            reason="canonical_source_not_implemented",
            canonical_source_id=_SOURCE_IDS[operation],
        )


def t063_source_ids() -> Mapping[str, str]:
    """Return the immutable twelve-operation source routing table."""

    return _SOURCE_IDS
