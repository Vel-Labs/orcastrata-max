#!/usr/bin/env python3
"""First-party acquisition adapters for the twelve supported-host operations.

The adapter input is raw family evidence.  The fixed operation endpoint selects
the owner and accepted mechanism.  A caller cannot submit a positive fact,
source digest, receipt wrapper, principal, or journal authority.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import sys
from types import MappingProxyType
from typing import Any, Callable, Mapping


PROTOCOL_VERSION = "supported_host_operation_sources_v1"
MANIFEST_TYPE = "supported_host_operation_source_manifest_v1"
EVENT_TYPE = "supported_host_operation_source_event_v3"
HEAD_TYPE = "supported_host_operation_source_head_v1"
PENDING_TYPE = "supported_host_operation_source_pending_v1"
FAMILY_STATE_TYPE = "supported_host_concrete_family_state_v1"
SOURCE_LOCAL_SCOPE = "source_local_quarantine_non_production"
SERVICE_OWNED_SCOPE = "service_account_owned_candidate"
EMPTY_SHA256 = "sha256:" + hashlib.sha256(b"").hexdigest()
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_ROWS = (
    ("read_operator_preset_bundle", "catalog_selection", "catalog", "operator-catalog-publisher", "first-party-catalog-selection-producer-v1", ("open_operator_listener",), "catalog_configuration", "t067_catalog_selection"),
    ("read_operator_selection_head", "catalog_selection", "selection", "operator-selection-ledger", "first-party-catalog-selection-producer-v1", ("read_operator_preset_bundle",), "selection_transition", "t067_catalog_selection"),
    ("read_operator_selection_mutation", "catalog_selection", "selection", "operator-selection-mutation-history", "first-party-catalog-selection-producer-v1", ("read_operator_selection_head",), "selection_transition", "t067_catalog_selection"),
    ("commit_operator_selection", "catalog_selection", "selection", "operator-selection-commit-authority", "first-party-catalog-selection-producer-v1", ("read_operator_selection_mutation",), "selection_transition", "t067_catalog_selection"),
    ("read_operator_supervision", "native_supervision", "native_inventory", "native-desktop-inventory-authority", "first-party-native-supervision-producer-v1", ("commit_operator_selection",), "native_topology", "t068_native_supervision"),
    ("issue_responses_context", "responses_seals", "responses", "responses-context-issuer", "first-party-responses-seals-producer-v1", ("read_operator_supervision",), "responses_request", "t066_responses_seals"),
    ("verify_effect_authority", "effect_authority", "authority", "effect-authority-ledger", "first-party-effect-authority-producer-v1", ("issue_responses_context",), "responses_request", "t064_effect_authority"),
    ("invoke_registered_action", "registered_action", "registered_action", "registered-action-observation-store", "first-party-registered-action-producer-v1", ("verify_effect_authority",), "executor_action", "t072_registered_action"),
    ("verify_responses_bridge", "responses_seals", "responses", "responses-bridge-observation-store", "first-party-responses-seals-producer-v1", ("issue_responses_context", "invoke_registered_action"), "responses_request", "t066_responses_seals"),
    ("commit_or_verify_record", "responses_seals", "responses", "record-lineage-authority", "first-party-responses-seals-producer-v1", ("verify_responses_bridge",), "responses_request", "t066_responses_seals"),
    ("seal_or_verify_projection", "responses_seals", "responses", "projection-seal-authority", "first-party-responses-seals-producer-v1", ("commit_or_verify_record",), "responses_request", "t066_responses_seals"),
    ("read_operator_recovery_lease_grant", "recovery", "recovery", "recovery-lease-authority", "first-party-recovery-producer-v1", ("seal_or_verify_projection",), "reconciliation", "t069_t078_recovery"),
)

OPERATION_ROWS = MappingProxyType({operation: MappingProxyType({
    "operation": operation, "owner_id": owner, "namespace": namespace,
    "canonical_source_id": source_id, "producer_principal_id": principal,
    "dependency_operations": dependencies, "raw_schema": raw_schema,
    "accepted_mechanism": mechanism,
}) for operation, owner, namespace, source_id, principal, dependencies, raw_schema, mechanism in _ROWS})
OWNER_IDS = tuple(sorted({row[1] for row in _ROWS}))
QUERY_FIELDS = frozenset({"identity", "operation_body", "dependency_receipts"})
SOURCE_CONFIG_FIELDS = frozenset({"schema_version", "artifact_type", "protocol_version",
    "owner_id", "source_id", "source_build_sha256", "expected_uid", "expected_gid",
    "service_start_id", "service_session_id", "max_frame_bytes"})

RAW_SCHEMA_FIELDS = MappingProxyType({
    "catalog_configuration": frozenset({"schema_version", "artifact_type", "observation_id", "public_bundle", "configured_bindings", "qualification_inputs", "receiver_admission", "observed_at"}),
    "selection_transition": frozenset({"schema_version", "artifact_type", "observation_id", "transition_kind", "receiver_transition", "catalog_lineage", "observed_at"}),
    "responses_request": frozenset({"schema_version", "artifact_type", "observation_id", "receiver_ingress", "dependency_identities", "observed_at"}),
    "native_topology": frozenset({"schema_version", "artifact_type", "observation_id", "native_host", "children", "edges", "cursor", "lifecycle", "identity_evidence", "observed_at"}),
    "executor_action": frozenset({"schema_version", "artifact_type", "observation_id", "action_receipt", "executor_start_id", "executor_session_id", "challenge", "observed_at"}),
    "reconciliation": frozenset({"schema_version", "artifact_type", "observation_id", "predecessor", "outcome", "receipt", "epoch", "stable_resource", "observed_cas", "receiver_time"}),
})
RAW_ARTIFACT_TYPES = MappingProxyType({name: "supported_host_raw_" + name + "_v1" for name in RAW_SCHEMA_FIELDS})
FORBIDDEN_RAW_FIELDS = frozenset({"fact", "fact_key", "fact_value", "final_receipt", "positive_value", "principal_id", "producer_principal_id", "canonical_source_id", "owner_state", "head_sha256"})
EVENT_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "owner_id", "operation",
    "source_sequence", "previous_event_sha256", "event_kind", "observation_id",
    "raw_schema", "raw_observation", "raw_observation_sha256", "identity_sha256",
    "operation_body_sha256", "dependency_receipts_sha256", "mechanism",
    "mechanism_receipt_sha256", "family_previous_head_sha256",
    "family_successor_head_sha256", "source_predecessor_sha256", "fact_key",
    "fact_value", "observed_at", "expires_at", "target_event_sha256",
    "consumer_sha256", "transition_reason", "event_sha256",
})


class OperationSourceError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


@dataclass(frozen=True, slots=True)
class SourceUnavailable:
    operation: str
    reason: str


@dataclass(frozen=True, slots=True)
class QuarantinedDerivedResult:
    """A complete source-local result with no production serialization path."""

    operation: str
    fact_key: str
    fact_value: Mapping[str, Any]
    observed_at: str
    expires_at: str
    source_digest: str
    observation_id: str
    journal_event_sha256: str
    execution_scope: str = SOURCE_LOCAL_SCOPE
    _accepted_source_digest: str | None = None


@dataclass(frozen=True, slots=True)
class AcceptedOperationFamilyRuntime:
    """One role-local accepted family store plus its fixed artifact store."""

    owner_id: str
    family_store: Any
    artifact_store: Any
    joint_authority_sha256: str


def _accepted_runtime_identity(authority: Mapping[str, Any], owner_id: str) -> Any:
    """Derive the W1 identity. No caller-supplied identity field is accepted."""
    from supported_host_cross_owner_artifacts_v1 import ServiceIdentity

    if not isinstance(authority, Mapping) or set(authority.get("roles", {})) != {
        "protected_writer", "independent_anchor", "opaque_tls_agent", *OWNER_IDS,
    }:
        raise OperationSourceError("operation_source_joint_authority_invalid", "$.authority")
    _sha(authority.get("authority_sha256"), "$.authority.authority_sha256")
    if authority.get("authority_sha256") != _seal(_plain(authority), "authority_sha256")["authority_sha256"]:
        raise OperationSourceError("operation_source_joint_authority_digest_invalid", "$.authority.authority_sha256")
    if owner_id not in OWNER_IDS:
        raise OperationSourceError("operation_source_owner_invalid", "$.owner_id")
    role = authority["roles"].get(owner_id)
    if not isinstance(role, Mapping):
        raise OperationSourceError("operation_source_joint_role_invalid", "$.authority.roles")
    required = {
        "service_id", "service_build_sha256", "root_identity",
        "expected_service_start_id", "expected_service_session_id",
        "session_expires_at", "expected_uid", "expected_gid",
        "supplemental_groups",
    }
    if not required.issubset(role):
        raise OperationSourceError("operation_source_joint_role_invalid", "$.authority.roles." + owner_id)
    root = role["root_identity"]
    if not isinstance(root, Mapping) or not {"root_id", "device", "inode"}.issubset(root):
        raise OperationSourceError("operation_source_joint_role_invalid", "$.authority.roles." + owner_id)
    return ServiceIdentity(
        role=owner_id.replace("_", "-"), service_id=role["service_id"],
        build_sha256=role["service_build_sha256"],
        root_identity_sha256=digest({key: root[key] for key in ("root_id", "device", "inode")}),
        start_id=role["expected_service_start_id"],
        session_id=role["expected_service_session_id"],
        session_expires_at=role["session_expires_at"],
        expected_uid=role["expected_uid"],
        expected_gid=role["expected_gid"],
        supplemental_groups=tuple(role["supplemental_groups"]),
    )


def _accepted_runtime_paths(root: Path) -> tuple[Path, Path]:
    descriptor_root = (
        isinstance(root, Path)
        and len(root.parts) == 4
        and root.parts[:3] == ("/", "dev", "fd")
        and root.name.isdigit()
    )
    if not isinstance(root, Path) or not root.is_absolute() or (root.is_symlink() and not descriptor_root):
        raise OperationSourceError("operation_source_family_root_invalid", "$.root")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root / "accepted-family", root / "cross-owner-artifacts"


def create_catalog_selection_accepted_runtime(
    root: Path, authority: Mapping[str, Any],
) -> AcceptedOperationFamilyRuntime:
    from supported_host_cross_owner_artifacts_v1 import CatalogSelectionCrossOwnerStore
    from supported_host_family_catalog_selection_v1 import CatalogSelectionFamilyStore
    family_root, artifact_root = _accepted_runtime_paths(root)
    family = CatalogSelectionFamilyStore(family_root) if family_root.exists() else CatalogSelectionFamilyStore.create_source_local(family_root)
    artifacts = CatalogSelectionCrossOwnerStore(
        artifact_root, _accepted_runtime_identity(authority, "catalog_selection"),
        joint_authority_sha256=authority["authority_sha256"],
    )
    return AcceptedOperationFamilyRuntime("catalog_selection", family, artifacts, authority["authority_sha256"])


def create_native_supervision_accepted_runtime(
    root: Path, authority: Mapping[str, Any],
) -> AcceptedOperationFamilyRuntime:
    from supported_host_cross_owner_artifacts_v1 import NativeSupervisionCrossOwnerStore
    from supported_host_family_native_recovery_v1 import NativeSupervisionFamilyStore
    family_root, artifact_root = _accepted_runtime_paths(root)
    artifacts = NativeSupervisionCrossOwnerStore(
        artifact_root, _accepted_runtime_identity(authority, "native_supervision"),
        joint_authority_sha256=authority["authority_sha256"],
    )
    return AcceptedOperationFamilyRuntime("native_supervision", NativeSupervisionFamilyStore(family_root), artifacts, authority["authority_sha256"])


def create_responses_seals_accepted_runtime(
    root: Path, authority: Mapping[str, Any],
) -> AcceptedOperationFamilyRuntime:
    from supported_host_cross_owner_artifacts_v1 import ResponsesSealsCrossOwnerStore
    from supported_host_family_responses_seals_v1 import ResponsesSealsFamilyStore
    family_root, artifact_root = _accepted_runtime_paths(root)
    artifacts = ResponsesSealsCrossOwnerStore(
        artifact_root, _accepted_runtime_identity(authority, "responses_seals"),
        joint_authority_sha256=authority["authority_sha256"],
    )
    return AcceptedOperationFamilyRuntime("responses_seals", ResponsesSealsFamilyStore(family_root), artifacts, authority["authority_sha256"])


def create_effect_authority_accepted_runtime(
    root: Path, authority: Mapping[str, Any], *, operation_state_store: Any,
) -> AcceptedOperationFamilyRuntime:
    from supported_host_cross_owner_artifacts_v1 import EffectAuthorityCrossOwnerStore
    from supported_host_family_effect_action_v1 import EffectAuthorityFamilyStore
    family_root, artifact_root = _accepted_runtime_paths(root)
    artifacts = EffectAuthorityCrossOwnerStore(
        artifact_root, _accepted_runtime_identity(authority, "effect_authority"),
        joint_authority_sha256=authority["authority_sha256"],
    )
    family = EffectAuthorityFamilyStore(family_root, artifacts, operation_state_store)
    return AcceptedOperationFamilyRuntime("effect_authority", family, artifacts, authority["authority_sha256"])


def create_registered_action_accepted_runtime(
    root: Path, authority: Mapping[str, Any],
) -> AcceptedOperationFamilyRuntime:
    from supported_host_cross_owner_artifacts_v1 import RegisteredActionCrossOwnerStore
    from supported_host_family_effect_action_v1 import RegisteredActionFamilyStore
    family_root, artifact_root = _accepted_runtime_paths(root)
    artifacts = RegisteredActionCrossOwnerStore(
        artifact_root, _accepted_runtime_identity(authority, "registered_action"),
        joint_authority_sha256=authority["authority_sha256"],
    )
    return AcceptedOperationFamilyRuntime("registered_action", RegisteredActionFamilyStore(family_root, artifacts), artifacts, authority["authority_sha256"])


def create_recovery_accepted_runtime(
    root: Path, authority: Mapping[str, Any],
) -> AcceptedOperationFamilyRuntime:
    from supported_host_cross_owner_artifacts_v1 import RecoveryCrossOwnerStore
    from supported_host_family_native_recovery_v1 import RecoveryFamilyStore
    family_root, artifact_root = _accepted_runtime_paths(root)
    artifacts = RecoveryCrossOwnerStore(
        artifact_root, _accepted_runtime_identity(authority, "recovery"),
        joint_authority_sha256=authority["authority_sha256"],
    )
    return AcceptedOperationFamilyRuntime("recovery", RecoveryFamilyStore(family_root, artifacts), artifacts, authority["authority_sha256"])


class ResponsesSealsAcceptedRuntimeAdapter:
    """Bind current imported heads into the dependent T066 transitions."""

    def __init__(self, runtime: AcceptedOperationFamilyRuntime) -> None:
        if not isinstance(runtime, AcceptedOperationFamilyRuntime) or runtime.owner_id != "responses_seals":
            raise OperationSourceError("operation_source_family_runtime_invalid", "$.runtime")
        self._runtime = runtime

    @staticmethod
    def _current(projection: Any, edge_id: str, operation: str, now: datetime) -> tuple[Any, str]:
        if projection is None:
            raise OperationSourceError("operation_source_dependency_import_missing", "$.imports." + edge_id)
        values = {name: getattr(projection, name, None) for name in (
            "edge_id", "operation", "event_kind", "import_head_sha256",
            "effective_expires_at", "authority_state", "proof_boundary",
            "semantic_subject", "successor_bytes", "transition_bytes",
        )}
        expected_event_kind = {
            "commit_operator_selection": "issue",
            "read_operator_supervision": "issue",
            "issue_responses_context": "issue",
            "invoke_registered_action": "observation",
        }.get(operation)
        if (values["edge_id"] != edge_id or values["operation"] != operation
                or values["event_kind"] != expected_event_kind or values["authority_state"] != "quarantine"
                or values["proof_boundary"] != SOURCE_LOCAL_SCOPE):
            raise OperationSourceError("operation_source_dependency_import_invalid", "$.imports." + edge_id)
        if _time(values["effective_expires_at"], "$.imports.expires_at") <= now:
            raise OperationSourceError("operation_source_dependency_import_expired", "$.imports." + edge_id)
        _sha(values["import_head_sha256"], "$.imports.import_head_sha256")
        return projection, values["import_head_sha256"]

    @staticmethod
    def _bound_import_sha(projection: Any, head: str) -> str:
        return digest({
            "edge_id": projection.edge_id,
            "artifact_sha256": projection.artifact_sha256,
            "import_head_sha256": head,
            "semantic_subject": projection.semantic_subject,
            "successor_bytes_sha256": "sha256:" + hashlib.sha256(projection.successor_bytes).hexdigest(),
            "transition_bytes_sha256": "sha256:" + hashlib.sha256(projection.transition_bytes).hexdigest(),
        })

    def issue_responses_context(
        self, *, identity_sha256: str, request_sha256: str,
        dependency_receipts_sha256: str, runtime_sha256: str,
        route_sha256: str, observed_at: datetime, expires_at: datetime,
    ) -> Mapping[str, Any]:
        now = observed_at.astimezone(timezone.utc).replace(microsecond=0)
        catalog, catalog_head = self._current(
            self._runtime.artifact_store.current_catalog_selection_from_catalog_selection(),
            "catalog_selection_to_responses_selection_v1", "commit_operator_selection", now,
        )
        native, native_head = self._current(
            self._runtime.artifact_store.current_native_supervision_from_native_supervision(),
            "native_supervision_to_responses_context_v1", "read_operator_supervision", now,
        )
        return self._runtime.family_store.issue_responses_context(
            identity_sha256=identity_sha256, request_sha256=request_sha256,
            dependency_receipts_sha256=dependency_receipts_sha256,
            selection_sha256=self._bound_import_sha(catalog, catalog_head),
            supervision_sha256=self._bound_import_sha(native, native_head),
            runtime_sha256=runtime_sha256, route_sha256=route_sha256,
            catalog_import_head_sha256=catalog_head,
            native_import_head_sha256=native_head,
            observed_at=observed_at, expires_at=expires_at,
        )

    def verify_responses_bridge(
        self, *, context_decision_sha256: str, effect_request_sha256: str,
        effect_receipt_sha256: str, observed_at: datetime, expires_at: datetime,
    ) -> Mapping[str, Any]:
        now = observed_at.astimezone(timezone.utc).replace(microsecond=0)
        action, action_head = self._current(
            self._runtime.artifact_store.current_registered_action_from_registered_action(),
            "registered_action_to_responses_bridge_v1", "invoke_registered_action", now,
        )
        action_receipt_sha256 = self._bound_import_sha(action, action_head)
        self._runtime.family_store.retain_registered_action_evidence(
            context_decision_sha256=context_decision_sha256,
            action_receipt_sha256=action_receipt_sha256, observed_at=observed_at,
        )
        return self._runtime.family_store.verify_responses_bridge(
            context_decision_sha256=context_decision_sha256,
            action_receipt_sha256=action_receipt_sha256,
            effect_request_sha256=effect_request_sha256,
            effect_receipt_sha256=effect_receipt_sha256,
            action_import_head_sha256=action_head,
            observed_at=observed_at, expires_at=expires_at,
        )


class _ExactContextIdentityStore:
    """Retain full context identity bytes beside the role-local source journal.

    The imported T066 transition remains authority. This store only resolves
    the exact identity whose digest the complete imported transition names.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def retain(self, identity: Mapping[str, Any]) -> str:
        if not isinstance(identity, Mapping):
            raise OperationSourceError("operation_source_context_identity_invalid", "$.query.identity")
        identity_sha256 = _v8_digest(identity)
        path = self.root / (identity_sha256.removeprefix("sha256:") + ".json")
        data = canonical_bytes(identity)
        if path.exists():
            if path.is_symlink() or path.read_bytes() != data:
                raise OperationSourceError("operation_source_context_identity_collision", "$.context_identities")
        else:
            _write_absent(path, dict(identity))
        return identity_sha256

    def current_responses_context_identity(self, identity_sha256: str) -> Mapping[str, Any] | None:
        _sha(identity_sha256, "$.identity_sha256")
        path = self.root / (identity_sha256.removeprefix("sha256:") + ".json")
        if not path.exists():
            return None
        value = _read(path)
        if not isinstance(value, Mapping) or _v8_digest(value) != identity_sha256:
            raise OperationSourceError("operation_source_context_identity_invalid", "$.context_identities")
        return MappingProxyType(deepcopy(dict(value)))


def _required_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OperationSourceError("operation_source_accepted_input_unavailable", path)
    return value


def _required_text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise OperationSourceError("operation_source_accepted_input_unavailable", path)
    return value


def _required_sha(value: Any, path: str) -> str:
    try:
        return _sha(value, path)
    except OperationSourceError as exc:
        raise OperationSourceError("operation_source_accepted_input_unavailable", path) from exc


def _transition_heads(transition: Any) -> tuple[str, str, str]:
    """Return exact predecessor, successor, and retained transition digest."""
    if hasattr(transition, "__dataclass_fields__"):
        before_value = getattr(transition, "predecessor_head_sha256", None)
        if before_value is None:
            before_value = getattr(transition, "predecessor_candidate_sha256", None) or EMPTY_SHA256
        after_value = getattr(transition, "successor_head_sha256", None)
        if after_value is None:
            after_value = getattr(transition, "successor_candidate_sha256", None)
        before = _required_sha(before_value, "$.accepted_transition.predecessor")
        after = _required_sha(after_value, "$.accepted_transition.successor")
        material = {
            key: ({"bytes_sha256": "sha256:" + hashlib.sha256(getattr(transition, key)).hexdigest(),
                   "byte_count": len(getattr(transition, key))}
                  if isinstance(getattr(transition, key), bytes)
                  else _plain(getattr(transition, key)))
            for key in transition.__dataclass_fields__
        }
        return before, after, digest(material)
    row = _required_mapping(transition, "$.accepted_transition")
    before = row.get("predecessor_head_sha256")
    after = row.get("successor_head_sha256")
    if before is None and isinstance(row.get("predecessor_ledger_json"), str):
        before = json.loads(row["predecessor_ledger_json"])["head_sha256"]
    if after is None and isinstance(row.get("successor_ledger_json"), str):
        after = json.loads(row["successor_ledger_json"])["head_sha256"]
    return _required_sha(before, "$.accepted_transition.predecessor"), _required_sha(
        after, "$.accepted_transition.successor"
    ), digest(row)


class AcceptedFamilyOperationDriver:
    """Execute only the frozen T091 stores through T092 imports."""

    def __init__(self, runtime: AcceptedOperationFamilyRuntime, operation_store: "OperationSourceStore") -> None:
        if not isinstance(runtime, AcceptedOperationFamilyRuntime):
            raise OperationSourceError("operation_source_family_runtime_invalid", "$.runtime")
        if runtime.owner_id != operation_store.manifest["owner_id"]:
            raise OperationSourceError("operation_source_family_runtime_invalid", "$.runtime.owner_id")
        self.runtime = runtime
        self.operation_store = operation_store

    def derive(self, operation: str, raw: Mapping[str, Any], query: Mapping[str, Any], owner_now: str) -> tuple[Any, Mapping[str, Any], str, str]:
        now = _time(owner_now, "$.owner_now")
        expires = now + timedelta(seconds=30)
        family = self.runtime.family_store
        acquisition_id = raw["observation_id"]
        if self.runtime.owner_id == "catalog_selection":
            transition = self._catalog(family, operation, raw, query, acquisition_id, now)
        elif self.runtime.owner_id == "native_supervision":
            transition = self._native(family, raw, acquisition_id, now)
        elif self.runtime.owner_id == "responses_seals":
            transition = self._responses(operation, raw, query, now, expires)
        elif self.runtime.owner_id == "effect_authority":
            body = _required_mapping(query["operation_body"], "$.query.operation_body")
            self.operation_store._context_identities.retain(
                _required_mapping(body.get("context"), "$.query.operation_body.context")
            )
            transition = family.verify_effect_authority(owner_now=now)
        elif self.runtime.owner_id == "registered_action":
            transition = self._action(family, raw, query, now, expires)
        elif self.runtime.owner_id == "recovery":
            transition = self._recovery(family, raw, query, acquisition_id, now)
        else:
            raise OperationSourceError("operation_source_owner_invalid", "$.runtime.owner_id")
        value = self._value(operation, raw, query, _format_time(now), _format_time(expires))
        return transition, value, _format_time(now), _format_time(expires)

    @staticmethod
    def _catalog(family: Any, operation: str, raw: Mapping[str, Any], query: Mapping[str, Any], acquisition: str, now: datetime) -> Any:
        common = {"acquisition_id": acquisition, "identity": query["identity"],
                  "operation_body": query["operation_body"],
                  "dependency_receipts": query["dependency_receipts"], "owner_now": now}
        if operation == "read_operator_preset_bundle":
            bundle = _required_mapping(raw["public_bundle"], "$.raw_observation.public_bundle")
            presets = bundle.get("presets")
            if not isinstance(presets, list):
                raise OperationSourceError("operation_source_accepted_input_unavailable", "$.raw_observation.public_bundle.presets")
            accepted_presets = []
            for index, preset in enumerate(presets):
                item = _required_mapping(preset, f"$.raw_observation.public_bundle.presets[{index}]")
                accepted_presets.append({
                    "preset_id": _required_text(item.get("preset_id"), f"$.raw_observation.public_bundle.presets[{index}].preset_id"),
                    "family_id": _required_text(item.get("family_id"), f"$.raw_observation.public_bundle.presets[{index}].family_id"),
                    "definition_sha256": digest(item),
                    "qualification_input_sha256": digest({
                        "preset_id": item.get("preset_id"),
                        "configured_bindings": raw["configured_bindings"],
                        "qualification_inputs": raw["qualification_inputs"],
                        "receiver_admission": raw["receiver_admission"],
                    }),
                })
            return family.publish_catalog(
                catalog_id=_required_text(bundle.get("catalog_id") or bundle.get("bundle_id"), "$.raw_observation.public_bundle.catalog_id"),
                presets=accepted_presets, **common,
            )
        receiver = _required_mapping(raw["receiver_transition"], "$.raw_observation.receiver_transition")
        if operation == "read_operator_selection_head":
            return family.observe_selection_head(
                bundle_sha256=_required_sha(receiver.get("bundle_sha256"), "$.raw_observation.receiver_transition.bundle_sha256"),
                binding_sha256=_required_sha(receiver.get("binding_sha256"), "$.raw_observation.receiver_transition.binding_sha256"),
                selection_sha256=_required_sha(receiver.get("selection_sha256"), "$.raw_observation.receiver_transition.selection_sha256"),
                selection_version=receiver.get("selection_version"), **common,
            )
        submission_id = _required_text(receiver.get("submission_id"), "$.raw_observation.receiver_transition.submission_id")
        submission_sha = _required_sha(receiver.get("submission_sha256"), "$.raw_observation.receiver_transition.submission_sha256")
        if operation == "read_operator_selection_mutation":
            return family.observe_mutation_query(
                submission_id=submission_id, submission_sha256=submission_sha, **common,
            )
        return family.authorize_commit(
            submission_id=submission_id, submission_sha256=submission_sha,
            requested_selection_sha256=_required_sha(
                receiver.get("requested_selection_sha256"),
                "$.raw_observation.receiver_transition.requested_selection_sha256",
            ), **common,
        )

    @staticmethod
    def _native(family: Any, raw: Mapping[str, Any], acquisition: str, now: datetime) -> Any:
        host = _required_mapping(raw["native_host"], "$.raw_observation.native_host")
        lifecycle = _required_mapping(raw["lifecycle"], "$.raw_observation.lifecycle")
        cursor = _required_mapping(raw["cursor"], "$.raw_observation.cursor")
        evidence = _required_mapping(raw["identity_evidence"], "$.raw_observation.identity_evidence")
        children = []
        for index, child in enumerate(raw["children"]):
            item = _required_mapping(child, f"$.raw_observation.children[{index}]")
            children.append((
                _required_text(item.get("worker_id") or item.get("child_id"), f"$.raw_observation.children[{index}].worker_id"),
                _required_sha(item.get("identity_receipt_sha256"), f"$.raw_observation.children[{index}].identity_receipt_sha256"),
                _required_sha(item.get("authentication_receipt_sha256"), f"$.raw_observation.children[{index}].authentication_receipt_sha256"),
                _required_text(item.get("lifecycle_state") or item.get("state"), f"$.raw_observation.children[{index}].lifecycle_state"),
            ))
        edges = []
        for index, edge in enumerate(raw["edges"]):
            item = _required_mapping(edge, f"$.raw_observation.edges[{index}]")
            edges.append((_required_text(item.get("parent_id"), f"$.raw_observation.edges[{index}].parent_id"),
                          _required_text(item.get("child_id"), f"$.raw_observation.edges[{index}].child_id")))
        return family.observe_supervision(
            acquisition_id=acquisition,
            native_host_id=_required_text(host.get("native_host_id"), "$.raw_observation.native_host.native_host_id"),
            host_instance_id=_required_text(host.get("host_instance_id"), "$.raw_observation.native_host.host_instance_id"),
            identity_receipt_sha256=_required_sha(evidence.get("identity_receipt_sha256"), "$.raw_observation.identity_evidence.identity_receipt_sha256"),
            authentication_receipt_sha256=_required_sha(evidence.get("authentication_receipt_sha256"), "$.raw_observation.identity_evidence.authentication_receipt_sha256"),
            lifecycle_state=_required_text(lifecycle.get("state"), "$.raw_observation.lifecycle.state"),
            children=tuple(children), parent_edges=tuple(edges),
            cursor_id=_required_text(cursor.get("cursor_id"), "$.raw_observation.cursor.cursor_id"),
            cursor_event_sha256=_required_sha(cursor.get("event_sha256"), "$.raw_observation.cursor.event_sha256"),
            owner_now=now,
        )

    def _responses(self, operation: str, raw: Mapping[str, Any], query: Mapping[str, Any], now: datetime, expires: datetime) -> Any:
        adapter = ResponsesSealsAcceptedRuntimeAdapter(self.runtime)
        store = self.runtime.family_store
        transitions = store.transitions()
        if operation == "issue_responses_context":
            ingress = _required_mapping(raw["receiver_ingress"], "$.raw_observation.receiver_ingress")
            identities = _required_mapping(raw["dependency_identities"], "$.raw_observation.dependency_identities")
            context_identity = _required_mapping(
                identities.get("effect_context"),
                "$.raw_observation.dependency_identities.effect_context",
            )
            return adapter.issue_responses_context(
                identity_sha256=_v8_digest(context_identity), request_sha256=_v8_digest(raw),
                dependency_receipts_sha256=_v8_digest(dict(sorted(query["dependency_receipts"].items()))),
                runtime_sha256=_v8_digest(query["identity"]), route_sha256=_v8_digest(query["operation_body"]),
                observed_at=now, expires_at=expires,
            )
        context = next((item for item in reversed(transitions) if item["operation"] == "issue_responses_context"), None)
        if context is None:
            raise OperationSourceError("operation_source_accepted_dependency_missing", "$.accepted_family.context")
        if operation == "verify_responses_bridge":
            return adapter.verify_responses_bridge(
                context_decision_sha256=context["decision_sha256"],
                effect_request_sha256=_v8_digest(query["operation_body"]),
                effect_receipt_sha256=_v8_digest(raw), observed_at=now, expires_at=expires,
            )
        if operation == "commit_or_verify_record":
            bridge = next((item for item in reversed(transitions) if item["operation"] == "verify_responses_bridge"), None)
            if bridge is None:
                raise OperationSourceError("operation_source_accepted_dependency_missing", "$.accepted_family.bridge")
            mode = query["operation_body"].get("mode", "commit")
            return store.commit_or_verify_record(
                mode=mode, context_decision_sha256=context["decision_sha256"],
                bridge_decision_sha256=bridge["decision_sha256"],
                record_sha256=_v8_digest({"raw": raw, "body": query["operation_body"]}),
                presented_seal_sha256=query["operation_body"].get("presented_seal_sha256"),
                observed_at=now, expires_at=expires,
            )
        record = next((item for item in reversed(transitions) if item["operation"] == "commit_or_verify_record"), None)
        if record is None:
            raise OperationSourceError("operation_source_accepted_dependency_missing", "$.accepted_family.record")
        mode = query["operation_body"].get("mode", "seal")
        return store.seal_or_verify_projection(
            mode=mode, context_decision_sha256=context["decision_sha256"],
            record_decision_sha256=record["decision_sha256"],
            projection_sha256=_v8_digest({"raw": raw, "body": query["operation_body"]}),
            presented_seal_sha256=query["operation_body"].get("presented_seal_sha256"),
            observed_at=now, expires_at=expires,
        )

    @staticmethod
    def _action(family: Any, raw: Mapping[str, Any], query: Mapping[str, Any], now: datetime, expires: datetime) -> Any:
        body = _required_mapping(query["operation_body"], "$.query.operation_body")
        request = _required_mapping(body.get("effect_request"), "$.query.operation_body.effect_request")
        adapter = _required_mapping(request.get("adapter_snapshot"), "$.query.operation_body.effect_request.adapter_snapshot")
        family.retain_registered_action(
            action_id=_required_text(body.get("action_id"), "$.query.operation_body.action_id"),
            tool_id=_required_text(adapter.get("tool_id"), "$.query.operation_body.effect_request.adapter_snapshot.tool_id"),
            parameter_fields=sorted(_required_mapping(request.get("input"), "$.query.operation_body.effect_request.input").get("parameters", {})),
            owner_now=now,
        )
        family.admit_registered_action(effect_request=request, admitted_at=now)
        return family.invoke_registered_action(
            executor_receipt=_required_mapping(raw["action_receipt"], "$.raw_observation.action_receipt"),
            observed_at=now, expires_at=expires,
        )

    @staticmethod
    def _recovery(family: Any, raw: Mapping[str, Any], query: Mapping[str, Any], acquisition: str, now: datetime) -> Any:
        identity = _required_mapping(query["identity"], "$.query.identity")
        predecessor = _required_mapping(raw["predecessor"], "$.raw_observation.predecessor")
        scope = _required_mapping(raw["stable_resource"], "$.raw_observation.stable_resource")
        return family.reconcile_and_issue_grant(
            acquisition_id=acquisition,
            workspace_id=_required_text(identity.get("workspace_id"), "$.query.identity.workspace_id"),
            effect_id=_required_text(scope.get("effect_id"), "$.raw_observation.stable_resource.effect_id"),
            run_id=_required_text(scope.get("run_id"), "$.raw_observation.stable_resource.run_id"),
            thread_id=_required_text(scope.get("thread_id"), "$.raw_observation.stable_resource.thread_id"),
            lease_id=_required_text(scope.get("lease_id"), "$.raw_observation.stable_resource.lease_id"),
            predecessor_fencing_token=predecessor.get("fencing_token", 0),
            predecessor_fencing_version=predecessor.get("fencing_version", 0), owner_now=now,
        )

    @staticmethod
    def _value(operation: str, raw: Mapping[str, Any], query: Mapping[str, Any], observed: str, expires: str) -> Mapping[str, Any]:
        if OPERATION_ROWS[operation]["owner_id"] == "catalog_selection":
            return _catalog_receipt(operation, raw, query, observed, expires)
        if operation == "read_operator_supervision":
            return _native_value(raw)
        if OPERATION_ROWS[operation]["owner_id"] == "responses_seals":
            return _responses_value(operation, raw, query, expires)
        if operation == "verify_effect_authority":
            return _effect_value(raw, query, expires)
        if operation == "invoke_registered_action":
            return _action_value(raw, query, expires)
        return _recovery_value(raw)


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return deepcopy(value)


def canonical_bytes(value: Any) -> bytes:
    try:
        return (json.dumps(_plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()
    except (TypeError, ValueError) as exc:
        raise OperationSourceError("operation_source_json_invalid") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _v8_digest(value: Any) -> str:
    """Use the immutable accepted v8 canonical JSON digest."""
    from codexmax_package_host.protocol_v1 import digest as protocol_digest
    return protocol_digest(_plain(value))


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    row = deepcopy(dict(value))
    row[field] = ""
    row[field] = digest(row)
    return row


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise OperationSourceError(code, path)
    return deepcopy(dict(value))


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise OperationSourceError("operation_source_digest_invalid", path)
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise OperationSourceError("operation_source_identifier_invalid", path)
    return value


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise OperationSourceError("operation_source_time_invalid", path)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _reject_named_authority(value: Any, path: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise OperationSourceError("operation_source_key_invalid", path)
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            if any(normalized == re.sub(r"[^a-z0-9]", "", item) for item in FORBIDDEN_RAW_FIELDS):
                raise OperationSourceError("operation_source_authority_field_forbidden", path + "." + key)
            _reject_named_authority(child, path + "." + key)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_named_authority(child, f"{path}[{index}]")


def validate_query(operation: str, value: Any) -> Mapping[str, Any]:
    if operation not in OPERATION_ROWS:
        raise OperationSourceError("operation_source_operation_invalid", "$.operation")
    row = _closed(value, QUERY_FIELDS, "operation_query_shape_invalid", "$.query")
    if not isinstance(row["identity"], Mapping) or not isinstance(row["operation_body"], Mapping):
        raise OperationSourceError("operation_query_value_invalid", "$.query")
    expected = set(OPERATION_ROWS[operation]["dependency_operations"])
    if not isinstance(row["dependency_receipts"], Mapping) or set(row["dependency_receipts"]) != expected:
        raise OperationSourceError("operation_query_dependencies_invalid", "$.query.dependency_receipts")
    for name, value_digest in row["dependency_receipts"].items():
        _sha(value_digest, "$.query.dependency_receipts." + name)
    if set(row["operation_body"]).intersection({"producer_principal_id", "canonical_source_id", "fact_value", "positive_value", "owner_value", "family_head"}):
        raise OperationSourceError("operation_source_authority_field_forbidden", "$.query.operation_body")
    return MappingProxyType(row)


def validate_raw_observation(operation: str, value: Any) -> Mapping[str, Any]:
    if operation not in OPERATION_ROWS:
        raise OperationSourceError("operation_source_operation_invalid", "$.operation")
    schema = OPERATION_ROWS[operation]["raw_schema"]
    row = _closed(value, RAW_SCHEMA_FIELDS[schema], "operation_source_raw_shape_invalid", "$.raw_observation")
    if row["schema_version"] != 1 or row["artifact_type"] != RAW_ARTIFACT_TYPES[schema]:
        raise OperationSourceError("operation_source_raw_identity_invalid", "$.raw_observation")
    _identifier(row["observation_id"], "$.raw_observation.observation_id")
    observed_field = "receiver_time" if schema == "reconciliation" else "observed_at"
    _time(row[observed_field], "$.raw_observation." + observed_field)
    _reject_named_authority(row, "$.raw_observation")
    if schema == "selection_transition" and row["transition_kind"] not in {"head", "mutation", "commit_intent"}:
        raise OperationSourceError("operation_source_transition_kind_invalid", "$.raw_observation.transition_kind")
    if schema == "native_topology" and not isinstance(row["children"], list):
        raise OperationSourceError("operation_source_raw_value_invalid", "$.raw_observation.children")
    if schema == "reconciliation" and (type(row["epoch"]) is not int or row["epoch"] < 1):
        raise OperationSourceError("operation_source_raw_value_invalid", "$.raw_observation.epoch")
    return MappingProxyType(row)


def exact_operation_owner_map() -> Mapping[str, Mapping[str, Any]]:
    return OPERATION_ROWS


def writer_operation_owners() -> Mapping[str, Mapping[str, str]]:
    return MappingProxyType({operation: MappingProxyType({
        "namespace": row["namespace"], "canonical_source_id": row["canonical_source_id"],
        "producer_principal_id": row["producer_principal_id"],
    }) for operation, row in OPERATION_ROWS.items()})


def _read(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperationSourceError("operation_source_file_invalid", str(path)) from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise OperationSourceError("operation_source_file_type_invalid", str(path))
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise OperationSourceError("operation_source_file_not_canonical", str(path))
    return value


def _write_absent(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise OperationSourceError("operation_source_publication_collision", str(path))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        data = canonical_bytes(value)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_directory(path.parent)


def _replace(path: Path, value: Mapping[str, Any]) -> None:
    temp = path.parent / (".replace-" + secrets.token_hex(16))
    _write_absent(temp, value)
    os.replace(temp, path)
    _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _unlink(path: Path) -> None:
    path.unlink()
    _fsync_directory(path.parent)


def _initial_family_state(owner_id: str) -> dict[str, Any]:
    return _seal({
        "schema_version": 1,
        "artifact_type": FAMILY_STATE_TYPE,
        "owner_id": owner_id,
        "sequence": 0,
        "head_sha256": digest({"family_genesis": owner_id}),
        "last_operation": None,
        "last_decision_sha256": None,
        "state_sha256": "",
    }, "state_sha256")


def _validate_family_state(value: Any, owner_id: str) -> dict[str, Any]:
    fields = frozenset({"schema_version", "artifact_type", "owner_id", "sequence", "head_sha256", "last_operation", "last_decision_sha256", "state_sha256"})
    row = _closed(value, fields, "operation_source_family_state_invalid", "$.family_state")
    if row["schema_version"] != 1 or row["artifact_type"] != FAMILY_STATE_TYPE or row["owner_id"] != owner_id:
        raise OperationSourceError("operation_source_family_state_invalid", "$.family_state")
    if type(row["sequence"]) is not int or row["sequence"] < 0:
        raise OperationSourceError("operation_source_family_state_invalid", "$.family_state.sequence")
    _sha(row["head_sha256"], "$.family_state.head_sha256")
    if row["sequence"] == 0:
        if row["last_operation"] is not None or row["last_decision_sha256"] is not None:
            raise OperationSourceError("operation_source_family_state_invalid", "$.family_state")
    else:
        if OPERATION_ROWS.get(row["last_operation"], {}).get("owner_id") != owner_id:
            raise OperationSourceError("operation_source_family_state_invalid", "$.family_state.last_operation")
        _sha(row["last_decision_sha256"], "$.family_state.last_decision_sha256")
    if row["state_sha256"] != _seal(row, "state_sha256")["state_sha256"]:
        raise OperationSourceError("operation_source_family_state_invalid", "$.family_state.state_sha256")
    return row


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _exact_identity(query: Mapping[str, Any]) -> dict[str, Any]:
    identity = query["identity"]
    required = ("workspace_id", "source_sha256", "candidate_sha256")
    if any(not isinstance(identity.get(field), str) for field in required):
        raise OperationSourceError("operation_source_identity_incomplete", "$.query.identity")
    return {field: identity[field] for field in required}


def _catalog_receipt(operation: str, raw: Mapping[str, Any], query: Mapping[str, Any], observed: str, expires: str) -> dict[str, Any]:
    identity = query["identity"]
    body = query["operation_body"]
    transition = raw.get("receiver_transition", {})
    lineage = raw.get("catalog_lineage", {})
    common = {
        "schema_version": 1,
        "workspace_id": identity["workspace_id"],
        "source_sha256": identity["source_sha256"],
        "candidate_sha256": identity["candidate_sha256"],
        "service_instance_id": identity["service_instance_id"],
        "admission_id": body["admission_id"],
        "binding_state_version": body.get("binding_state_version", transition.get("binding_state_version")),
        "binding_state_sha256": body.get("binding_state_sha256", transition.get("binding_state_sha256")),
        "issued_at": observed,
        "expires_at": expires,
    }
    if operation == "read_operator_preset_bundle":
        inputs = raw["qualification_inputs"]
        value = {**common,
            "artifact_type": "standalone_operator_configured_preset_bundle_receipt_v1",
            "catalog_receipt_id": raw["observation_id"],
            "preset_policy_sha256": inputs["preset_policy_sha256"],
            "adapter_registry_sha256": inputs["adapter_registry_sha256"],
            "capability_profile_sha256": inputs["capability_profile_sha256"],
            "catalog_generation": raw["public_bundle"]["generation"],
            "previous_catalog_sha256": inputs.get("previous_catalog_sha256"),
            "bundle": raw["public_bundle"], "bundle_sha256": raw["public_bundle"]["bundle_sha256"],
            "configured_bindings": raw["configured_bindings"], "receipt_sha256": "", "seal": ""}
    elif operation == "read_operator_selection_head":
        value = {**common, "artifact_type": "standalone_operator_selection_head_receipt_v1",
            "head_id": raw["observation_id"], "selection_state_version": transition["selection_state_version"],
            "selection": transition["selection"], "selection_sha256": _v8_digest(transition["selection"]),
            "catalog_receipt_sha256": lineage["catalog_receipt_sha256"], "bundle_sha256": lineage["bundle_sha256"],
            "bundle_generation": lineage["bundle_generation"], "receipt_sha256": "", "seal": ""}
    elif operation == "read_operator_selection_mutation":
        value = {**common, "artifact_type": "standalone_operator_selection_mutation_receipt_v1",
            "mutation_id": raw["observation_id"], "submission_sha256": body["submission_sha256"],
            "runtime_thread_id": transition["runtime_thread_id"], "runtime_thread_generation": transition["runtime_thread_generation"],
            "selection_state_version_before": transition["selection_state_version_before"],
            "selection_state_version_after": transition["selection_state_version_after"],
            "previous_selection_sha256": transition["previous_selection_sha256"],
            "selection": transition["selection"], "selection_sha256": _v8_digest(transition["selection"]),
            "catalog_receipt_sha256": lineage["catalog_receipt_sha256"], "bundle_sha256": lineage["bundle_sha256"],
            "bundle_generation": lineage["bundle_generation"], "receipt_sha256": "", "seal": ""}
    else:
        return {"schema_version": 1, "artifact_type": "package_host_command_authorization_v1",
            "operation": operation, "operation_body_sha256": _v8_digest(body), "decision": "authorized"}
    value["receipt_sha256"] = _v8_digest({key: item for key, item in value.items() if key not in {"receipt_sha256", "seal"}})
    value["seal"] = _v8_digest({key: item for key, item in value.items() if key != "seal"})
    return value


def _responses_value(operation: str, raw: Mapping[str, Any], query: Mapping[str, Any], expires: str) -> dict[str, Any]:
    identity = _exact_identity(query)
    body = deepcopy(dict(query["operation_body"]))
    ingress = raw["receiver_ingress"]
    if operation == "verify_responses_bridge":
        nested = {"bridge_receipt_sha256": digest({"observation": raw["observation_id"], "ingress": ingress}),
            "disposition": ingress.get("disposition", "completed"),
            "authority_granted_by_bridge": False, "provider_called_by_bridge": False}
        return {"body": body, "identity": identity, "value": nested, "expires_at": expires, "revoked": False}
    if operation in {"commit_or_verify_record", "seal_or_verify_projection"}:
        return {"identity": identity, "body": body,
            "opaque_seal": digest({"owner": OPERATION_ROWS[operation]["canonical_source_id"], "identity": identity, "body": body, "ingress": ingress}),
            "expires_at": expires, "revoked": False}
    if operation == "issue_responses_context":
        from codexmax_package_host import responses_v1
        request = ingress["responses_request"]
        context = ingress["context"]
        control_body = body
        request_body = {"mode": "request", "responses_request": request, "control_action": None,
            "control_payload": None, "record_sha256": None, "service_instance_id": None,
            "recovery_grant_id": None, "recovery_grant_sha256": None}
        control = {"body": control_body, "identity": identity, "value": request, "expires_at": expires, "revoked": False}
        request_row = {"body": request_body, "identity": identity, "value": context, "expires_at": expires, "revoked": False}
        return {"variant": "responses_context_pair_v1",
            "control_row": {"key": responses_v1.context_key(control_body, identity), "value": control},
            "request_row": {"key": responses_v1.context_key(request_body, identity), "value": request_row}}
    raise OperationSourceError("operation_source_operation_invalid", "$.operation")


def _effect_value(raw: Mapping[str, Any], query: Mapping[str, Any], expires: str) -> dict[str, Any]:
    body = query["operation_body"]
    context = body["context"]
    authority = body["authority"]
    return {"authority": deepcopy(dict(authority)), "request_sha256": context["request_sha256"],
        "revoked": False, "expires_at": expires}


def _action_value(raw: Mapping[str, Any], query: Mapping[str, Any], expires: str) -> dict[str, Any]:
    body = query["operation_body"]
    request = body["effect_request"]
    adapter = request["adapter_snapshot"]
    registration = {"action_id": body["action_id"], "tool_id": adapter["tool_id"],
        "transport": adapter["transport"], "parameter_fields": sorted(request["input"]["parameters"])}
    return {"variant": "registered_action_observation_v1", "registration": registration,
        "observation_key": raw["action_receipt"]["request_sha256"],
        "observation": {"receipt": deepcopy(dict(raw["action_receipt"])), "expires_at": expires, "revoked": False}}


def _native_value(raw: Mapping[str, Any]) -> dict[str, Any]:
    parent = {key: deepcopy(value) for key, value in raw["native_host"].items()
              if key not in {"native_host_id", "host_instance_id"}}
    supervisor = {key: deepcopy(value) for key, value in raw["lifecycle"].items() if key != "state"}
    workers = [{key: deepcopy(value) for key, value in item.items()
                if key not in {"worker_id", "child_id", "authentication_receipt_sha256", "lifecycle_state", "state"}}
               for item in raw["children"]]
    cursor = {key: deepcopy(value) for key, value in raw["cursor"].items()
              if key not in {"cursor_id", "event_sha256"}}
    return {"parent": parent, "supervisor": supervisor, "workers": workers,
        "inventory_event": cursor, "supervisor_checkpoint": raw["identity_evidence"].get("supervisor_checkpoint"),
        "host_read_event": raw["identity_evidence"].get("host_read_event"),
        "subscription": raw["identity_evidence"].get("subscription"), "recovery": raw["identity_evidence"].get("recovery"),
        "snapshot": raw["identity_evidence"].get("snapshot"), "worker_count": len(raw["children"])}


def _recovery_value(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {"grant": deepcopy(dict(raw["outcome"])), "predecessor_lease": deepcopy(dict(raw["predecessor"])),
        "active": True, "revoked": False, "consumed": False}


class _ConcreteFamilyEngine:
    OWNER_ID = ""

    def derive(self, operation: str, raw: Mapping[str, Any], query: Mapping[str, Any], family_state: Mapping[str, Any], owner_now: str) -> tuple[dict[str, Any], dict[str, Any], str, str]:
        state = _validate_family_state(family_state, self.OWNER_ID)
        observed_field = "receiver_time" if OPERATION_ROWS[operation]["raw_schema"] == "reconciliation" else "observed_at"
        _time(raw[observed_field], "$.raw_observation." + observed_field)
        observed = _format_time(_time(owner_now, "$.owner_now"))
        expires = _format_time(_time(observed, "$.owner_now") + timedelta(seconds=30))
        value = self._derive_value(operation, raw, query, observed, expires)
        decision = _seal({"schema_version": 1, "artifact_type": "supported_host_concrete_family_decision_v1",
            "owner_id": self.OWNER_ID, "operation": operation, "mechanism": OPERATION_ROWS[operation]["accepted_mechanism"],
            "identity_sha256": _v8_digest(query["identity"]), "operation_body_sha256": _v8_digest(query["operation_body"]),
            "dependency_receipts_sha256": _v8_digest(dict(sorted(query["dependency_receipts"].items()))),
            "raw_observation_sha256": digest(raw), "family_previous_head_sha256": state["head_sha256"],
            "source_start_id": self._manifest["service_start_id"], "source_session_id": self._manifest["service_session_id"],
            "observed_at": observed, "expires_at": expires, "value_sha256": digest(value), "decision_sha256": ""}, "decision_sha256")
        successor = digest({"scope": self._manifest["execution_scope"], "decision": decision,
            "previous": state["head_sha256"], "sequence": state["sequence"] + 1})
        next_state = _seal({"schema_version": 1, "artifact_type": FAMILY_STATE_TYPE, "owner_id": self.OWNER_ID,
            "sequence": state["sequence"] + 1, "head_sha256": successor, "last_operation": operation,
            "last_decision_sha256": decision["decision_sha256"], "state_sha256": ""}, "state_sha256")
        return decision, value, observed, expires, next_state

    def __init__(self, manifest: Mapping[str, Any]) -> None:
        if manifest["owner_id"] != self.OWNER_ID:
            raise OperationSourceError("operation_source_owner_store_invalid", "$.manifest")
        self._manifest = manifest


class CatalogSelectionEngine(_ConcreteFamilyEngine):
    OWNER_ID = "catalog_selection"
    def _derive_value(self, operation, raw, query, observed, expires):
        return _catalog_receipt(operation, raw, query, observed, expires)


class NativeSupervisionEngine(_ConcreteFamilyEngine):
    OWNER_ID = "native_supervision"
    def _derive_value(self, operation, raw, query, observed, expires):
        del operation, query, observed, expires
        return _native_value(raw)


class ResponsesSealsEngine(_ConcreteFamilyEngine):
    OWNER_ID = "responses_seals"
    def _derive_value(self, operation, raw, query, observed, expires):
        del observed
        return _responses_value(operation, raw, query, expires)


class EffectAuthorityEngine(_ConcreteFamilyEngine):
    OWNER_ID = "effect_authority"
    def _derive_value(self, operation, raw, query, observed, expires):
        del operation, observed
        return _effect_value(raw, query, expires)


class RegisteredActionEngine(_ConcreteFamilyEngine):
    OWNER_ID = "registered_action"
    def _derive_value(self, operation, raw, query, observed, expires):
        del operation, observed
        return _action_value(raw, query, expires)


class RecoveryEngine(_ConcreteFamilyEngine):
    OWNER_ID = "recovery"
    def _derive_value(self, operation, raw, query, observed, expires):
        del operation, query, observed, expires
        return _recovery_value(raw)


FAMILY_ENGINES = MappingProxyType({engine.OWNER_ID: engine for engine in (
    CatalogSelectionEngine, NativeSupervisionEngine, ResponsesSealsEngine,
    EffectAuthorityEngine, RegisteredActionEngine, RecoveryEngine)})


class OperationSourceStore:
    """Append-only raw, decision, and derived event journal for one owner."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.manifest = MappingProxyType(_read(root / "manifest.json"))
        if self.manifest.get("artifact_type") != MANIFEST_TYPE or self.manifest.get("protocol_version") != PROTOCOL_VERSION:
            raise OperationSourceError("operation_source_manifest_invalid", "$.manifest")
        if self.manifest.get("manifest_sha256") != _seal(self.manifest, "manifest_sha256")["manifest_sha256"]:
            raise OperationSourceError("operation_source_manifest_invalid", "$.manifest")
        self.source_local = self.manifest["execution_scope"] == SOURCE_LOCAL_SCOPE
        if not self.source_local and self.manifest["execution_scope"] != SERVICE_OWNED_SCOPE:
            raise OperationSourceError("operation_source_scope_invalid", "$.manifest")
        if not self.source_local and (os.geteuid(), os.getegid()) != (self.manifest["service_uid"], self.manifest["service_gid"]):
            raise OperationSourceError("operation_source_process_identity_mismatch", "$.manifest")
        identity_root = root / "accepted-context-identities"
        if not identity_root.is_dir() or identity_root.is_symlink():
            raise OperationSourceError("operation_source_context_identity_store_invalid", "$.context_identities")
        self._context_identities = _ExactContextIdentityStore(identity_root)
        self.recover()

    @classmethod
    def create_source_local(cls, root: Path, **identity: Any) -> "OperationSourceStore":
        return cls._create(root, SOURCE_LOCAL_SCOPE, **identity)

    @classmethod
    def create_service_owned(cls, root: Path, **identity: Any) -> "OperationSourceStore":
        return cls._create(root, SERVICE_OWNED_SCOPE, **identity)

    @classmethod
    def _create(cls, root: Path, scope: str, *, owner_id: str, source_id: str,
                source_build_sha256: str, service_uid: int, service_gid: int,
                service_start_id: str, service_session_id: str) -> "OperationSourceStore":
        if owner_id not in OWNER_IDS or source_id != owner_id.replace("_", "-") + "-owner-v1":
            raise OperationSourceError("operation_source_owner_identity_invalid", "$.identity")
        _sha(source_build_sha256, "$.identity.source_build_sha256")
        _identifier(service_start_id, "$.identity.service_start_id")
        _identifier(service_session_id, "$.identity.service_session_id")
        if scope == SERVICE_OWNED_SCOPE and (os.geteuid(), os.getegid()) != (service_uid, service_gid):
            raise OperationSourceError("operation_source_process_identity_mismatch", "$.identity")
        if not root.is_absolute() or root.exists() or root.is_symlink():
            raise OperationSourceError("operation_source_root_invalid", "$.root")
        root.mkdir(mode=0o700)
        (root / "events").mkdir(mode=0o700)
        (root / "accepted-context-identities").mkdir(mode=0o700)
        manifest = _seal({"schema_version": 1, "artifact_type": MANIFEST_TYPE,
            "protocol_version": PROTOCOL_VERSION, "owner_id": owner_id, "source_id": source_id,
            "source_build_sha256": source_build_sha256, "service_uid": service_uid,
            "service_gid": service_gid, "service_start_id": service_start_id,
            "service_session_id": service_session_id, "execution_scope": scope,
            "manifest_sha256": ""}, "manifest_sha256")
        _write_absent(root / "manifest.json", manifest)
        _write_absent(root / ".journal.lock", {"schema_version": 1, "owner_id": owner_id})
        _write_absent(root / "head.json", {"schema_version": 1, "artifact_type": HEAD_TYPE,
            "owner_id": owner_id, "sequence": 0, "head_sha256": EMPTY_SHA256})
        _write_absent(root / "family-state.json", _initial_family_state(owner_id))
        return cls(root)

    @contextmanager
    def _lock(self):
        fd = os.open(self.root / ".journal.lock", os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def recover(self) -> tuple[Mapping[str, Any], ...]:
        head = _read(self.root / "head.json")
        names = sorted(path.name for path in (self.root / "events").iterdir())
        if names != [f"{index:020d}.json" for index in range(1, len(names) + 1)]:
            raise OperationSourceError("operation_source_truncation_or_fork", "$.events")
        rows: list[dict[str, Any]] = []
        previous = EMPTY_SHA256
        raw_by_id: dict[str, dict[str, Any]] = {}
        decision_by_id: dict[str, dict[str, Any]] = {}
        derived_digests: set[str] = set()
        raw_digests: set[str] = set()
        terminal: set[str] = set()
        for index, name in enumerate(names, 1):
            row = _closed(_read(self.root / "events" / name), EVENT_FIELDS, "operation_source_event_shape_invalid", "$.event")
            if row["source_sequence"] != index or row["previous_event_sha256"] != previous or row["source_predecessor_sha256"] != previous:
                raise OperationSourceError("operation_source_fork", "$.event")
            if row["event_sha256"] != _seal(row, "event_sha256")["event_sha256"]:
                raise OperationSourceError("operation_source_event_digest_mismatch", "$.event")
            if OPERATION_ROWS.get(row["operation"], {}).get("owner_id") != self.manifest["owner_id"]:
                raise OperationSourceError("operation_source_owner_mismatch", "$.event")
            kind = row["event_kind"]
            if kind == "raw_observation":
                if row["observation_id"] in raw_by_id or row["raw_observation"] is None:
                    raise OperationSourceError("operation_source_observation_collision", "$.event")
                validate_raw_observation(row["operation"], row["raw_observation"])
                if row["raw_observation_sha256"] != digest(row["raw_observation"]):
                    raise OperationSourceError("operation_source_raw_digest_mismatch", "$.event")
                raw_by_id[row["observation_id"]] = row
                raw_digests.add(row["raw_observation_sha256"])
            elif kind == "decision_issue":
                raw = raw_by_id.get(row["observation_id"])
                if raw is None or row["target_event_sha256"] != raw["event_sha256"] or row["observation_id"] in decision_by_id:
                    raise OperationSourceError("operation_source_decision_order_invalid", "$.event")
                decision_by_id[row["observation_id"]] = row
            elif kind == "derived_value":
                decision = decision_by_id.get(row["observation_id"])
                if decision is None or row["target_event_sha256"] != decision["event_sha256"] or row["fact_value"] is None:
                    raise OperationSourceError("operation_source_derived_order_invalid", "$.event")
                derived_digests.add(row["event_sha256"])
            elif kind in {"revoke", "consume"}:
                if row["target_event_sha256"] not in derived_digests or row["target_event_sha256"] in terminal:
                    raise OperationSourceError("operation_source_transition_invalid", "$.event")
                terminal.add(row["target_event_sha256"])
                if kind == "consume" and row["operation"] != "read_operator_recovery_lease_grant":
                    raise OperationSourceError("operation_source_consumption_invalid", "$.event")
                if kind == "consume" and row["consumer_sha256"] not in raw_digests:
                    raise OperationSourceError("operation_source_consumption_observation_missing", "$.event")
                if kind == "revoke" and (not isinstance(row["transition_reason"], str) or row["consumer_sha256"] is not None):
                    raise OperationSourceError("operation_source_revocation_invalid", "$.event")
            else:
                raise OperationSourceError("operation_source_event_kind_invalid", "$.event")
            previous = row["event_sha256"]
            rows.append(row)
        expected_head = {"schema_version": 1, "artifact_type": HEAD_TYPE,
            "owner_id": self.manifest["owner_id"], "sequence": len(rows),
            "head_sha256": previous}
        pending_path = self.root / ".pending-transaction.json"
        if pending_path.exists():
            pending = _read(pending_path)
            required = frozenset({"schema_version", "artifact_type", "owner_id", "prior_head", "event_name",
                "event", "successor_head", "prior_family_state", "successor_family_state",
                "event_kind", "operation", "observation_id", "query_sha256",
                "family_previous_head_sha256", "family_successor_head_sha256", "pending_sha256"})
            row = _closed(pending, required, "operation_source_pending_invalid", "$.pending")
            if row["artifact_type"] != PENDING_TYPE or row["owner_id"] != self.manifest["owner_id"] or row["pending_sha256"] != _seal(row, "pending_sha256")["pending_sha256"]:
                raise OperationSourceError("operation_source_pending_invalid", "$.pending")
            if row["event_name"] != f"{row['successor_head']['sequence']:020d}.json" or row["successor_head"] != expected_head:
                raise OperationSourceError("operation_source_pending_mismatch", "$.pending")
            committed = _read(self.root / "events" / row["event_name"])
            if committed != row["event"]:
                raise OperationSourceError("operation_source_pending_mismatch", "$.pending.event")
            _replace(self.root / "head.json", row["successor_head"])
            _replace(self.root / "family-state.json", row["successor_family_state"])
            _unlink(pending_path)
            head = row["successor_head"]
        elif head != expected_head:
            family = _validate_family_state(_read(self.root / "family-state.json"), self.manifest["owner_id"])
            if family["sequence"] > len([item for item in rows if item["event_kind"] == "decision_issue"]):
                raise OperationSourceError("operation_source_head_rollback_or_fork", "$.head")
            _replace(self.root / "head.json", expected_head)
            head = expected_head
        if head != expected_head:
            raise OperationSourceError("operation_source_head_rollback_or_fork", "$.head")
        family = _validate_family_state(_read(self.root / "family-state.json"), self.manifest["owner_id"])
        decisions = [item for item in rows if item["event_kind"] == "decision_issue"]
        if family["sequence"] != len(decisions):
            raise OperationSourceError("operation_source_family_state_fork", "$.family_state.sequence")
        if decisions and (family["head_sha256"] != decisions[-1]["family_successor_head_sha256"] or family["last_decision_sha256"] != decisions[-1]["mechanism_receipt_sha256"]):
            raise OperationSourceError("operation_source_family_state_fork", "$.family_state.head_sha256")
        return tuple(MappingProxyType(row) for row in rows)

    def _append(self, *, successor_family_state: Mapping[str, Any] | None = None,
                test_fault: str | None = None, **values: Any) -> Mapping[str, Any]:
        with self._lock():
            return self._append_locked(successor_family_state=successor_family_state, test_fault=test_fault, **values)

    def _append_locked(self, *, successor_family_state: Mapping[str, Any] | None = None,
                       test_fault: str | None = None, **values: Any) -> Mapping[str, Any]:
            rows = self.recover()
            previous = rows[-1]["event_sha256"] if rows else EMPTY_SHA256
            row = _seal({"schema_version": 1, "artifact_type": EVENT_TYPE,
                "protocol_version": PROTOCOL_VERSION, "owner_id": self.manifest["owner_id"],
                "source_sequence": len(rows) + 1, "previous_event_sha256": previous,
                "source_predecessor_sha256": previous, "event_sha256": "", **_plain(values)}, "event_sha256")
            prior_head = {"schema_version": 1, "artifact_type": HEAD_TYPE,
                "owner_id": self.manifest["owner_id"], "sequence": len(rows), "head_sha256": previous}
            next_head = {"schema_version": 1, "artifact_type": HEAD_TYPE,
                "owner_id": self.manifest["owner_id"], "sequence": len(rows) + 1,
                "head_sha256": row["event_sha256"]}
            prior_family = _validate_family_state(_read(self.root / "family-state.json"), self.manifest["owner_id"])
            next_family = prior_family if successor_family_state is None else _validate_family_state(successor_family_state, self.manifest["owner_id"])
            pending = _seal({"schema_version": 1, "artifact_type": PENDING_TYPE,
                "owner_id": self.manifest["owner_id"], "prior_head": prior_head,
                "event_name": f"{len(rows) + 1:020d}.json", "event": row,
                "successor_head": next_head, "prior_family_state": prior_family,
                "successor_family_state": next_family, "event_kind": row["event_kind"],
                "operation": row["operation"], "observation_id": row["observation_id"],
                "query_sha256": digest({"identity_sha256": row["identity_sha256"],
                    "operation_body_sha256": row["operation_body_sha256"],
                    "dependency_receipts_sha256": row["dependency_receipts_sha256"]}),
                "family_previous_head_sha256": row["family_previous_head_sha256"],
                "family_successor_head_sha256": row["family_successor_head_sha256"],
                "pending_sha256": ""}, "pending_sha256")
            _write_absent(self.root / ".pending-transaction.json", pending)
            if test_fault == "after_pending":
                raise OperationSourceError("injected_operation_source_after_pending", "$.fault")
            _write_absent(self.root / "events" / pending["event_name"], row)
            if test_fault == "after_commit":
                raise OperationSourceError("injected_operation_source_after_commit", "$.fault")
            _replace(self.root / "head.json", next_head)
            if test_fault == "after_head":
                raise OperationSourceError("injected_operation_source_after_head", "$.fault")
            _replace(self.root / "family-state.json", next_family)
            if test_fault == "after_state":
                raise OperationSourceError("injected_operation_source_after_state", "$.fault")
            _unlink(self.root / ".pending-transaction.json")
            if test_fault == "after_pending_removal":
                raise OperationSourceError("injected_operation_source_after_pending_removal", "$.fault")
            self.recover()
            return MappingProxyType(row)

    def append_raw(self, operation: str, raw: Mapping[str, Any], query: Mapping[str, Any]) -> Mapping[str, Any]:
        validated_raw = validate_raw_observation(operation, raw)
        validated_query = validate_query(operation, query)
        with self._lock():
            existing = [row for row in self.recover() if row["event_kind"] == "raw_observation" and row["observation_id"] == validated_raw["observation_id"]]
            if existing:
                same = existing[0]["raw_observation_sha256"] == digest(validated_raw)
                same = same and existing[0]["identity_sha256"] == _v8_digest(validated_query["identity"])
                same = same and existing[0]["operation_body_sha256"] == _v8_digest(validated_query["operation_body"])
                same = same and existing[0]["dependency_receipts_sha256"] == _v8_digest(dict(sorted(validated_query["dependency_receipts"].items())))
                if same:
                    return existing[0]
                raise OperationSourceError("operation_source_observation_collision", "$.raw_observation.observation_id")
            observed_field = "receiver_time" if OPERATION_ROWS[operation]["raw_schema"] == "reconciliation" else "observed_at"
            return self._append_locked(operation=operation, event_kind="raw_observation",
                observation_id=validated_raw["observation_id"], raw_schema=OPERATION_ROWS[operation]["raw_schema"],
                raw_observation=validated_raw, raw_observation_sha256=digest(validated_raw),
                identity_sha256=_v8_digest(validated_query["identity"]),
                operation_body_sha256=_v8_digest(validated_query["operation_body"]),
                dependency_receipts_sha256=_v8_digest(dict(sorted(validated_query["dependency_receipts"].items()))),
                mechanism=OPERATION_ROWS[operation]["accepted_mechanism"], mechanism_receipt_sha256=None,
                family_previous_head_sha256=None, family_successor_head_sha256=None,
                fact_key=None, fact_value=None, observed_at=validated_raw[observed_field], expires_at=None,
                target_event_sha256=None, consumer_sha256=None, transition_reason=None)

    def current_responses_context_identity(self, identity_sha256: str) -> Mapping[str, Any] | None:
        """Resolve only an exact identity retained in this role-local root."""
        return self._context_identities.current_responses_context_identity(identity_sha256)

    def acquire(self, operation: str, raw: Mapping[str, Any], query: Mapping[str, Any], *, owner_now: str | None = None) -> SourceUnavailable | QuarantinedDerivedResult:
        observed_field = "receiver_time" if OPERATION_ROWS[operation]["raw_schema"] == "reconciliation" else "observed_at"
        if owner_now is None:
            if not self.source_local:
                raise OperationSourceError("operation_source_owner_clock_missing", "$.owner_now")
            owner_now = raw[observed_field]
        raw_event = self.append_raw(operation, raw, query)
        rows = self.recover()
        retained = next((item for item in rows if item["event_kind"] == "derived_value" and item["observation_id"] == raw_event["observation_id"]), None)
        if retained is not None:
            terminal = next((item for item in rows if item["event_kind"] in {"revoke", "consume"} and item["target_event_sha256"] == retained["event_sha256"]), None)
            if terminal is not None:
                return SourceUnavailable(operation, "source_fact_" + ("revoked" if terminal["event_kind"] == "revoke" else "consumed"))
            if _time(retained["expires_at"], "$.retained.expires_at") <= _time(owner_now, "$.owner_now"):
                return SourceUnavailable(operation, "source_fact_expired")
            from package_host_supported_host_producer_v1 import prepare_positive_source_material_v1
            retained_material = prepare_positive_source_material_v1(operation, identity=query["identity"],
                dependency_receipts=query["dependency_receipts"], operation_body=query["operation_body"],
                owner_value=retained["fact_value"], observed_at=retained["observed_at"], expires_at=retained["expires_at"],
                canonical_source_id=OPERATION_ROWS[operation]["canonical_source_id"])
            retained_digest = digest({
                "scope": SOURCE_LOCAL_SCOPE, "accepted_v8_source_digest": retained_material["source_digest"],
                "derived_event_sha256": retained["event_sha256"]})
            return QuarantinedDerivedResult(operation, retained["fact_key"], MappingProxyType(_plain(retained["fact_value"])),
                retained["observed_at"], retained["expires_at"], retained_digest,
                raw_event["observation_id"], retained["event_sha256"], SOURCE_LOCAL_SCOPE,
                retained_material["source_digest"] if not self.source_local else None)
        family = _validate_family_state(_read(self.root / "family-state.json"), self.manifest["owner_id"])
        engine = FAMILY_ENGINES[self.manifest["owner_id"]](self.manifest)
        mechanism_receipt, value, observed_at, expires_at, successor_state = engine.derive(
            operation, raw, query, family, owner_now)
        previous_head = family["head_sha256"]
        successor_head = successor_state["head_sha256"]
        mechanism_receipt_sha = validate_accepted_mechanism_receipt(operation, mechanism_receipt,
            raw_observation=raw, query=query)
        decision = self._append(operation=operation, event_kind="decision_issue",
            observation_id=raw_event["observation_id"], raw_schema=raw_event["raw_schema"], raw_observation=None,
            raw_observation_sha256=raw_event["raw_observation_sha256"], identity_sha256=raw_event["identity_sha256"],
            operation_body_sha256=raw_event["operation_body_sha256"], dependency_receipts_sha256=raw_event["dependency_receipts_sha256"],
            mechanism=OPERATION_ROWS[operation]["accepted_mechanism"], mechanism_receipt_sha256=mechanism_receipt_sha,
            family_previous_head_sha256=previous_head, family_successor_head_sha256=successor_head,
            fact_key=None, fact_value=None, observed_at=observed_at, expires_at=expires_at,
            target_event_sha256=raw_event["event_sha256"], consumer_sha256=None, transition_reason=None,
            successor_family_state=successor_state)
        try:
            from package_host_supported_host_producer_v1 import prepare_positive_source_material_v1
            material = prepare_positive_source_material_v1(operation, identity=query["identity"],
                dependency_receipts=query["dependency_receipts"], operation_body=query["operation_body"],
                owner_value=value, observed_at=observed_at, expires_at=expires_at,
                canonical_source_id=OPERATION_ROWS[operation]["canonical_source_id"])
        except Exception as exc:
            raise OperationSourceError("operation_source_v8_material_invalid", "$.mechanism_outcome") from exc
        derived = self._append(operation=operation, event_kind="derived_value",
            observation_id=raw_event["observation_id"], raw_schema=raw_event["raw_schema"], raw_observation=None,
            raw_observation_sha256=raw_event["raw_observation_sha256"], identity_sha256=raw_event["identity_sha256"],
            operation_body_sha256=material["operation_body_sha256"], dependency_receipts_sha256=material["dependency_receipts_sha256"],
            mechanism=OPERATION_ROWS[operation]["accepted_mechanism"], mechanism_receipt_sha256=mechanism_receipt_sha,
            family_previous_head_sha256=previous_head, family_successor_head_sha256=successor_head,
            fact_key=material["key"], fact_value=material["value"], observed_at=observed_at, expires_at=expires_at,
            target_event_sha256=decision["event_sha256"], consumer_sha256=None, transition_reason=None)
        return QuarantinedDerivedResult(operation, material["key"], MappingProxyType(_plain(material["value"])),
            observed_at, expires_at, digest({"scope": SOURCE_LOCAL_SCOPE, "accepted_v8_source_digest": material["source_digest"],
                "derived_event_sha256": derived["event_sha256"]}), raw_event["observation_id"], derived["event_sha256"],
            SOURCE_LOCAL_SCOPE, material["source_digest"] if not self.source_local else None)

    def acquire_accepted(
        self, operation: str, raw: Mapping[str, Any], query: Mapping[str, Any], *,
        accepted_runtime: AcceptedOperationFamilyRuntime, owner_now: str | None = None,
    ) -> SourceUnavailable | QuarantinedDerivedResult:
        """Execute the complete accepted family and retain exact v8 material.

        This method always returns non-serializable retained material. Only the
        service runner can promote it after its live before/after checks pass.
        """
        validated_query = validate_query(operation, query)
        observed_field = "receiver_time" if OPERATION_ROWS[operation]["raw_schema"] == "reconciliation" else "observed_at"
        if owner_now is None:
            owner_now = raw[observed_field]
        raw_event = self.append_raw(operation, raw, validated_query)
        rows = self.recover()
        retained = next((item for item in rows if item["event_kind"] == "derived_value" and item["observation_id"] == raw_event["observation_id"]), None)
        if retained is not None:
            terminal = next((item for item in rows if item["event_kind"] in {"revoke", "consume"} and item["target_event_sha256"] == retained["event_sha256"]), None)
            if terminal is not None:
                return SourceUnavailable(operation, "source_fact_" + ("revoked" if terminal["event_kind"] == "revoke" else "consumed"))
            if _time(retained["expires_at"], "$.retained.expires_at") <= _time(owner_now, "$.owner_now"):
                return SourceUnavailable(operation, "source_fact_expired")
            from package_host_supported_host_producer_v1 import prepare_positive_source_material_v1
            return QuarantinedDerivedResult(
                operation, retained["fact_key"], MappingProxyType(_plain(retained["fact_value"])),
                retained["observed_at"], retained["expires_at"],
                digest({"scope": SOURCE_LOCAL_SCOPE, "accepted_v8_source_digest": digest(retained["fact_value"]),
                        "derived_event_sha256": retained["event_sha256"]}),
                raw_event["observation_id"], retained["event_sha256"], SOURCE_LOCAL_SCOPE,
                prepare_positive_source_material_v1(
                    operation, identity=validated_query["identity"],
                    dependency_receipts=validated_query["dependency_receipts"],
                    operation_body=validated_query["operation_body"],
                    owner_value=retained["fact_value"],
                    observed_at=retained["observed_at"], expires_at=retained["expires_at"],
                    canonical_source_id=OPERATION_ROWS[operation]["canonical_source_id"],
                )["source_digest"] if not self.source_local else None,
            )
        transition, value, observed_at, expires_at = AcceptedFamilyOperationDriver(
            accepted_runtime, self
        ).derive(operation, raw, validated_query, owner_now)
        previous_head, successor_head, mechanism_receipt_sha = _transition_heads(transition)
        prior_state = _validate_family_state(_read(self.root / "family-state.json"), self.manifest["owner_id"])
        successor_state = _seal({
            "schema_version": 1, "artifact_type": FAMILY_STATE_TYPE,
            "owner_id": self.manifest["owner_id"], "sequence": prior_state["sequence"] + 1,
            "head_sha256": successor_head, "last_operation": operation,
            "last_decision_sha256": mechanism_receipt_sha, "state_sha256": "",
        }, "state_sha256")
        decision = self._append(
            operation=operation, event_kind="decision_issue", observation_id=raw_event["observation_id"],
            raw_schema=raw_event["raw_schema"], raw_observation=None,
            raw_observation_sha256=raw_event["raw_observation_sha256"], identity_sha256=raw_event["identity_sha256"],
            operation_body_sha256=raw_event["operation_body_sha256"], dependency_receipts_sha256=raw_event["dependency_receipts_sha256"],
            mechanism=OPERATION_ROWS[operation]["accepted_mechanism"], mechanism_receipt_sha256=mechanism_receipt_sha,
            family_previous_head_sha256=previous_head, family_successor_head_sha256=successor_head,
            fact_key=None, fact_value=None, observed_at=observed_at, expires_at=expires_at,
            target_event_sha256=raw_event["event_sha256"], consumer_sha256=None, transition_reason=None,
            successor_family_state=successor_state,
        )
        try:
            from package_host_supported_host_producer_v1 import prepare_positive_source_material_v1
            material = prepare_positive_source_material_v1(
                operation, identity=validated_query["identity"],
                dependency_receipts=validated_query["dependency_receipts"],
                operation_body=validated_query["operation_body"], owner_value=value,
                observed_at=observed_at, expires_at=expires_at,
                canonical_source_id=OPERATION_ROWS[operation]["canonical_source_id"],
            )
        except Exception as exc:
            raise OperationSourceError("operation_source_v8_material_invalid", "$.accepted_family") from exc
        derived = self._append(
            operation=operation, event_kind="derived_value", observation_id=raw_event["observation_id"],
            raw_schema=raw_event["raw_schema"], raw_observation=None,
            raw_observation_sha256=raw_event["raw_observation_sha256"], identity_sha256=raw_event["identity_sha256"],
            operation_body_sha256=material["operation_body_sha256"], dependency_receipts_sha256=material["dependency_receipts_sha256"],
            mechanism=OPERATION_ROWS[operation]["accepted_mechanism"], mechanism_receipt_sha256=mechanism_receipt_sha,
            family_previous_head_sha256=previous_head, family_successor_head_sha256=successor_head,
            fact_key=material["key"], fact_value=material["value"], observed_at=observed_at,
            expires_at=expires_at, target_event_sha256=decision["event_sha256"],
            consumer_sha256=None, transition_reason=None,
        )
        return QuarantinedDerivedResult(
            operation, material["key"], MappingProxyType(_plain(material["value"])),
            observed_at, expires_at,
            digest({"scope": SOURCE_LOCAL_SCOPE, "accepted_v8_source_digest": material["source_digest"],
                    "derived_event_sha256": derived["event_sha256"]}),
            raw_event["observation_id"], derived["event_sha256"], SOURCE_LOCAL_SCOPE,
            material["source_digest"] if not self.source_local else None,
        )

    def record_transition(self, *, target_event_sha256: str, event_kind: str,
                          occurred_at: str, reason: str | None = None,
                          use_observation_sha256: str | None = None) -> Mapping[str, Any]:
        """Persist a revocation or a recovery consumption transition."""
        _sha(target_event_sha256, "$.target_event_sha256")
        _time(occurred_at, "$.occurred_at")
        with self._lock():
            rows = self.recover()
            target = next((row for row in rows if row["event_sha256"] == target_event_sha256 and row["event_kind"] == "derived_value"), None)
            if target is None:
                raise OperationSourceError("operation_source_transition_invalid", "$.target_event_sha256")
            existing = next((row for row in rows if row["event_kind"] in {"revoke", "consume"} and row["target_event_sha256"] == target_event_sha256), None)
            if existing is not None:
                if existing["event_kind"] == event_kind and existing["consumer_sha256"] == use_observation_sha256 and existing["transition_reason"] == reason:
                    return existing
                raise OperationSourceError("operation_source_transition_collision", "$.target_event_sha256")
            if event_kind == "revoke":
                if not isinstance(reason, str) or not reason or use_observation_sha256 is not None:
                    raise OperationSourceError("operation_source_revocation_invalid", "$.transition")
            elif event_kind == "consume":
                if target["operation"] != "read_operator_recovery_lease_grant" or reason is not None:
                    raise OperationSourceError("operation_source_consumption_invalid", "$.transition")
                _sha(use_observation_sha256, "$.use_observation_sha256")
                if not any(row["event_kind"] == "raw_observation" and row["raw_observation_sha256"] == use_observation_sha256 for row in rows):
                    raise OperationSourceError("operation_source_consumption_observation_missing", "$.transition")
            else:
                raise OperationSourceError("operation_source_transition_invalid", "$.event_kind")
            return self._append_locked(operation=target["operation"], event_kind=event_kind,
                observation_id=target["observation_id"], raw_schema=target["raw_schema"], raw_observation=None,
                raw_observation_sha256=target["raw_observation_sha256"], identity_sha256=target["identity_sha256"],
                operation_body_sha256=target["operation_body_sha256"], dependency_receipts_sha256=target["dependency_receipts_sha256"],
                mechanism=target["mechanism"], mechanism_receipt_sha256=target["mechanism_receipt_sha256"],
                family_previous_head_sha256=target["family_previous_head_sha256"], family_successor_head_sha256=target["family_successor_head_sha256"],
                fact_key=None, fact_value=None, observed_at=occurred_at, expires_at=target["expires_at"],
                target_event_sha256=target_event_sha256, consumer_sha256=use_observation_sha256,
                transition_reason=reason)


def validate_accepted_mechanism_receipt(operation: str, value: Any, *,
                                        raw_observation: Mapping[str, Any] | None = None,
                                        query: Mapping[str, Any] | None = None) -> str:
    """Validate the fixed engine decision. It cannot contain a family ledger."""
    del raw_observation
    if query is None:
        raise OperationSourceError("operation_source_mechanism_receipt_invalid", "$.mechanism_receipt")
    exact_query = validate_query(operation, query)
    fields = frozenset({"schema_version", "artifact_type", "owner_id", "operation", "mechanism",
        "identity_sha256", "operation_body_sha256", "dependency_receipts_sha256",
        "raw_observation_sha256", "family_previous_head_sha256", "source_start_id",
        "source_session_id", "observed_at", "expires_at", "value_sha256", "decision_sha256"})
    row = _closed(value, fields, "operation_source_mechanism_receipt_invalid", "$.mechanism_receipt")
    expected = OPERATION_ROWS[operation]
    if row["schema_version"] != 1 or row["artifact_type"] != "supported_host_concrete_family_decision_v1" or row["owner_id"] != expected["owner_id"] or row["operation"] != operation or row["mechanism"] != expected["accepted_mechanism"]:
        raise OperationSourceError("operation_source_mechanism_receipt_invalid", "$.mechanism_receipt")
    if row["identity_sha256"] != _v8_digest(exact_query["identity"]) or row["operation_body_sha256"] != _v8_digest(exact_query["operation_body"]) or row["dependency_receipts_sha256"] != _v8_digest(dict(sorted(exact_query["dependency_receipts"].items()))):
        raise OperationSourceError("operation_source_mechanism_binding_mismatch", "$.mechanism_receipt")
    for field in ("raw_observation_sha256", "family_previous_head_sha256", "value_sha256"):
        _sha(row[field], "$.mechanism_receipt." + field)
    _identifier(row["source_start_id"], "$.mechanism_receipt.source_start_id")
    _identifier(row["source_session_id"], "$.mechanism_receipt.source_session_id")
    if _time(row["expires_at"], "$.mechanism_receipt.expires_at") <= _time(row["observed_at"], "$.mechanism_receipt.observed_at"):
        raise OperationSourceError("operation_source_mechanism_time_invalid", "$.mechanism_receipt")
    if row["decision_sha256"] != _seal(row, "decision_sha256")["decision_sha256"]:
        raise OperationSourceError("operation_source_mechanism_receipt_invalid", "$.mechanism_receipt.decision_sha256")
    return row["decision_sha256"]


class OperationSourceOwner:
    OWNER_ID = ""
    OPERATIONS: frozenset[str] = frozenset()

    def __init__(self, store: OperationSourceStore, owner_now: str | None = None) -> None:
        if store.manifest["owner_id"] != self.OWNER_ID:
            raise OperationSourceError("operation_source_owner_store_invalid", "$.store")
        self._store = store
        self._owner_now = owner_now

    def _acquire(self, operation: str, raw: Mapping[str, Any], identity: Mapping[str, Any],
                 operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str]) -> SourceUnavailable | QuarantinedDerivedResult:
        if operation not in self.OPERATIONS:
            raise OperationSourceError("operation_source_owner_mismatch", "$.operation")
        return self._store.acquire(operation, raw, {"identity": identity, "operation_body": operation_body,
            "dependency_receipts": dependency_receipts}, owner_now=self._owner_now)


def _adapter(operation: str, raw_name: str) -> Callable[..., SourceUnavailable | QuarantinedDerivedResult]:
    def common(self: OperationSourceOwner, raw: Mapping[str, Any], identity: Mapping[str, Any],
               operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str]) -> SourceUnavailable | QuarantinedDerivedResult:
        return self._acquire(operation, raw, identity, operation_body, dependency_receipts)
    if raw_name == "catalog_configuration":
        def acquire(self: OperationSourceOwner, *, identity: Mapping[str, Any], operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str], catalog_configuration: Mapping[str, Any]) -> SourceUnavailable | QuarantinedDerivedResult:
            return common(self, catalog_configuration, identity, operation_body, dependency_receipts)
    elif raw_name == "selection_transition":
        def acquire(self: OperationSourceOwner, *, identity: Mapping[str, Any], operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str], selection_transition: Mapping[str, Any]) -> SourceUnavailable | QuarantinedDerivedResult:
            return common(self, selection_transition, identity, operation_body, dependency_receipts)
    elif raw_name == "responses_request":
        def acquire(self: OperationSourceOwner, *, identity: Mapping[str, Any], operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str], responses_request: Mapping[str, Any]) -> SourceUnavailable | QuarantinedDerivedResult:
            return common(self, responses_request, identity, operation_body, dependency_receipts)
    elif raw_name == "native_topology":
        def acquire(self: OperationSourceOwner, *, identity: Mapping[str, Any], operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str], native_topology: Mapping[str, Any]) -> SourceUnavailable | QuarantinedDerivedResult:
            return common(self, native_topology, identity, operation_body, dependency_receipts)
    elif raw_name == "executor_action":
        def acquire(self: OperationSourceOwner, *, identity: Mapping[str, Any], operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str], executor_action: Mapping[str, Any]) -> SourceUnavailable | QuarantinedDerivedResult:
            return common(self, executor_action, identity, operation_body, dependency_receipts)
    elif raw_name == "reconciliation":
        def acquire(self: OperationSourceOwner, *, identity: Mapping[str, Any], operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str], reconciliation: Mapping[str, Any]) -> SourceUnavailable | QuarantinedDerivedResult:
            return common(self, reconciliation, identity, operation_body, dependency_receipts)
    else:
        raise AssertionError(raw_name)
    acquire.__name__ = "acquire_" + operation
    return acquire


class CatalogSelectionOwner(OperationSourceOwner):
    OWNER_ID = "catalog_selection"
    OPERATIONS = frozenset(operation for operation, row in OPERATION_ROWS.items() if row["owner_id"] == "catalog_selection")


class NativeSupervisionOwner(OperationSourceOwner):
    OWNER_ID = "native_supervision"
    OPERATIONS = frozenset({"read_operator_supervision"})


class ResponsesSealsOwner(OperationSourceOwner):
    OWNER_ID = "responses_seals"
    OPERATIONS = frozenset(operation for operation, row in OPERATION_ROWS.items() if row["owner_id"] == "responses_seals")


class EffectAuthorityOwner(OperationSourceOwner):
    OWNER_ID = "effect_authority"
    OPERATIONS = frozenset({"verify_effect_authority"})


class RegisteredActionOwner(OperationSourceOwner):
    OWNER_ID = "registered_action"
    OPERATIONS = frozenset({"invoke_registered_action"})


class RecoveryOwner(OperationSourceOwner):
    OWNER_ID = "recovery"
    OPERATIONS = frozenset({"read_operator_recovery_lease_grant"})


OWNER_TYPES = MappingProxyType({owner.OWNER_ID: owner for owner in (CatalogSelectionOwner,
    NativeSupervisionOwner, ResponsesSealsOwner, EffectAuthorityOwner, RegisteredActionOwner, RecoveryOwner)})
for _operation, _row in OPERATION_ROWS.items():
    setattr(OWNER_TYPES[_row["owner_id"]], "acquire_" + _operation, _adapter(_operation, _row["raw_schema"]))


def validate_source_service_configuration(value: Any) -> Mapping[str, Any]:
    row = _closed(value, SOURCE_CONFIG_FIELDS, "operation_source_config_shape_invalid", "$.config")
    if row["schema_version"] != 1 or row["artifact_type"] != "supported_host_operation_source_config_v1" or row["protocol_version"] != PROTOCOL_VERSION:
        raise OperationSourceError("operation_source_config_identity_invalid", "$.config")
    if row["owner_id"] not in OWNER_IDS or row["source_id"] != row["owner_id"].replace("_", "-") + "-owner-v1":
        raise OperationSourceError("operation_source_config_identity_invalid", "$.config")
    _sha(row["source_build_sha256"], "$.config.source_build_sha256")
    _identifier(row["service_start_id"], "$.config.service_start_id")
    _identifier(row["service_session_id"], "$.config.service_session_id")
    for field in ("expected_uid", "expected_gid", "max_frame_bytes"):
        if type(row[field]) is not int or row[field] < 1:
            raise OperationSourceError("operation_source_config_value_invalid", "$.config." + field)
    if row["max_frame_bytes"] > 4 * 1024 * 1024:
        raise OperationSourceError("operation_source_config_value_invalid", "$.config.max_frame_bytes")
    return MappingProxyType(row)


def validate_source_service_set(value: Any) -> Mapping[str, Mapping[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != set(OWNER_IDS):
        raise OperationSourceError("operation_source_service_set_invalid", "$.services")
    rows = {owner: validate_source_service_configuration(value[owner]) for owner in OWNER_IDS}
    if any(rows[owner]["owner_id"] != owner for owner in OWNER_IDS):
        raise OperationSourceError("operation_source_service_set_invalid", "$.services")
    for field, code in (("source_id", "operation_source_service_identity_collision"),
                        ("expected_uid", "operation_source_service_account_collision"),
                        ("expected_gid", "operation_source_service_account_collision"),
                        ("service_start_id", "operation_source_service_start_collision"),
                        ("service_session_id", "operation_source_service_session_collision")):
        if len({row[field] for row in rows.values()}) != len(rows):
            raise OperationSourceError(code, "$.services")
    return MappingProxyType(rows)


def _peer_credentials(channel: socket.socket) -> tuple[int, tuple[int, ...]] | None:
    option = getattr(socket, "LOCAL_PEERCRED", None)
    level = getattr(socket, "SOL_LOCAL", None)
    if option is None or level is None:
        return None
    raw = channel.getsockopt(level, option, 256)
    if len(raw) < 12:
        raise OperationSourceError("operation_source_peer_malformed", "$.channel")
    version, uid, count = struct.unpack_from("=IIh2x", raw, 0)
    if version == 0 or count < 0 or count > 16 or len(raw) < 12 + 4 * count:
        raise OperationSourceError("operation_source_peer_malformed", "$.channel")
    groups = struct.unpack_from(f"={count}I", raw, 12) if count else ()
    return uid, groups


class PreconnectedOperationSourceClient:
    """Compatible writer-side handle for the Parent-owned joint channel layer.

    T088 does not define the joint channel witness. Until that layer supplies
    an authenticated exchange callback, this handle returns typed unavailable.
    """

    __slots__ = ("_socket", "_config", "_fingerprint", "_used", "_joint_authority")

    def __init__(self, channel: socket.socket, configuration: Mapping[str, Any], *,
                 joint_authority: Mapping[str, Any] | None = None) -> None:
        if type(channel) is not socket.socket or channel.family != socket.AF_UNIX:
            raise OperationSourceError("operation_source_channel_invalid", "$.channel")
        self._socket = channel
        self._config = validate_source_service_configuration(configuration)
        info = os.fstat(channel.fileno())
        self._fingerprint = (info.st_dev, info.st_ino, channel.fileno())
        self._used = False
        self._joint_authority = None if joint_authority is None else MappingProxyType(_plain(joint_authority))

    def read(self, *, operation: str, query: Mapping[str, Any], candidate_sha256: str,
             profile_sha256: str, request_challenge: str, requested_at: str) -> SourceUnavailable | Mapping[str, Any]:
        if self._used:
            raise OperationSourceError("operation_source_channel_reused", "$.channel")
        self._used = True
        row = OPERATION_ROWS.get(operation)
        if row is None or row["owner_id"] != self._config["owner_id"]:
            raise OperationSourceError("operation_source_owner_mismatch", "$.operation")
        validate_query(operation, query)
        _sha(candidate_sha256, "$.candidate_sha256")
        _sha(profile_sha256, "$.profile_sha256")
        _identifier(request_challenge, "$.request_challenge")
        _time(requested_at, "$.requested_at")
        info = os.fstat(self._socket.fileno())
        if (info.st_dev, info.st_ino, self._socket.fileno()) != self._fingerprint:
            raise OperationSourceError("operation_source_socket_replaced", "$.channel")
        credentials = _peer_credentials(self._socket)
        if credentials is None:
            return SourceUnavailable(operation, "kernel_peer_credentials_not_supported")
        if credentials[0] != self._config["expected_uid"] or self._config["expected_gid"] not in credentials[1]:
            return SourceUnavailable(operation, "operation_source_peer_mismatch")
        if self._joint_authority is None:
            return SourceUnavailable(operation, "joint_role_channel_not_integrated")
        from supported_host_protected_service_v1 import JointOperationSourceExchange
        result = JointOperationSourceExchange(
            self._socket, self._joint_authority, self._config["owner_id"],
        )(operation=operation, query=query, candidate_sha256=candidate_sha256,
          profile_sha256=profile_sha256, request_challenge=request_challenge,
          requested_at=requested_at)
        if not isinstance(result, (SourceUnavailable, Mapping)):
            raise OperationSourceError("operation_source_result_invalid", "$.channel")
        return result


def check_operation_source_runner(owner_id: str, service_set: Any) -> Mapping[str, Any]:
    """Validate public owner wiring without opening a descriptor or root."""
    services = validate_source_service_set(service_set)
    if owner_id not in OWNER_IDS:
        raise OperationSourceError("operation_source_owner_identity_invalid", "$.owner")
    row = services[owner_id]
    return MappingProxyType({
        "schema_version": 1,
        "artifact_type": "supported_host_operation_source_runner_check_v1",
        "protocol_version": PROTOCOL_VERSION,
        "owner_id": owner_id,
        "source_id": row["source_id"],
        "operations": tuple(sorted(OWNER_TYPES[owner_id].OPERATIONS)),
        "state": "check_only_non_production",
        "missing_live_inputs": (
            "joint_authority", "inherited_writer_descriptor",
            "inherited_raw_observation_descriptor", "service_owned_root",
            "exact_role_artifact_descriptors",
        ),
        "descriptors_opened": False,
        "store_opened": False,
        "service_executed": False,
        "production_ready": False,
    })


def operation_source_runner_main(argv: list[str] | None = None) -> int:
    """Run no-I/O preflight or one inherited-descriptor owner exchange."""
    parser = argparse.ArgumentParser(prog="supported_host_operation_sources_v1")
    parser.add_argument("--owner", choices=OWNER_IDS, required=True)
    parser.add_argument("--service-public-json", required=True)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--execute-live", action="store_true")
    parser.add_argument("--joint-authority-json")
    parser.add_argument("--writer-fd", type=int)
    parser.add_argument("--raw-observation-fd", type=int)
    parser.add_argument("--root-fd", type=int)
    parser.add_argument("--artifact-fds-json")
    parser.add_argument("--current-time")
    try:
        args = parser.parse_args(argv)
        if args.check_only == args.execute_live:
            raise OperationSourceError("operation_source_runner_mode_invalid", "$.mode")
        raw = sys.stdin.read() if args.service_public_json == "-" else args.service_public_json
        service_set = json.loads(raw)
        if args.check_only:
            if any(value is not None for value in (args.joint_authority_json, args.writer_fd, args.raw_observation_fd, args.root_fd, args.artifact_fds_json, args.current_time)):
                raise OperationSourceError("operation_source_check_only_input_forbidden", "$.check_only")
            checked = check_operation_source_runner(args.owner, service_set)
        else:
            if args.joint_authority_json is None or any(value is None for value in (args.writer_fd, args.raw_observation_fd, args.root_fd, args.artifact_fds_json, args.current_time)):
                raise OperationSourceError("operation_source_live_input_missing", "$.execute_live")
            services = validate_source_service_set(service_set)
            from supported_host_protected_service_v1 import (
                OPERATION_SOURCE_OWNER_RUNNERS, _ROLE_ARTIFACT_EDGES,
            )
            artifact_fds = json.loads(args.artifact_fds_json)
            required_edges = set(_ROLE_ARTIFACT_EDGES[args.owner])
            if (
                not isinstance(artifact_fds, Mapping)
                or set(artifact_fds) != required_edges
                or any(type(value) is not int or value < 0 for value in artifact_fds.values())
            ):
                raise OperationSourceError("operation_source_artifact_fds_invalid", "$.artifact_fds")
            all_fds = [args.writer_fd, args.raw_observation_fd, args.root_fd, *artifact_fds.values()]
            if len(all_fds) != len(set(all_fds)):
                raise OperationSourceError("operation_source_descriptor_reused", "$.artifact_fds")
            writer = socket.socket(fileno=args.writer_fd)
            raw_channel = socket.socket(fileno=args.raw_observation_fd)
            artifact_channels = {
                edge_id: socket.socket(fileno=descriptor)
                for edge_id, descriptor in artifact_fds.items()
            }
            checked = OPERATION_SOURCE_OWNER_RUNNERS[args.owner](writer_channel=writer,
                raw_observation_channel=raw_channel, authority=json.loads(args.joint_authority_json),
                source_configuration=services[args.owner], inherited_root_fd=args.root_fd,
                now=args.current_time, artifact_channels=artifact_channels)
        print(json.dumps(_plain(checked), sort_keys=True, separators=(",", ":")))
        return 0
    except BaseException as exc:
        print(json.dumps({"status": "failed", "error": getattr(exc, "code", "operation_source_runner_invalid")}, sort_keys=True, separators=(",", ":")))
        return 2


__all__ = ["AcceptedOperationFamilyRuntime", "CatalogSelectionEngine", "CatalogSelectionOwner", "EffectAuthorityEngine", "EffectAuthorityOwner",
    "NativeSupervisionOwner", "OPERATION_ROWS", "OWNER_IDS", "OWNER_TYPES", "OperationSourceError",
    "OperationSourceOwner", "OperationSourceStore", "PROTOCOL_VERSION", "QUERY_FIELDS",
    "RAW_ARTIFACT_TYPES", "RAW_SCHEMA_FIELDS", "RecoveryOwner", "RegisteredActionOwner",
    "ResponsesSealsOwner", "SERVICE_OWNED_SCOPE", "SOURCE_LOCAL_SCOPE",
    "SourceUnavailable", "QuarantinedDerivedResult", "PreconnectedOperationSourceClient", "ResponsesSealsAcceptedRuntimeAdapter", "canonical_bytes", "check_operation_source_runner", "digest", "exact_operation_owner_map", "operation_source_runner_main",
    "create_catalog_selection_accepted_runtime", "create_native_supervision_accepted_runtime", "create_responses_seals_accepted_runtime", "create_effect_authority_accepted_runtime", "create_registered_action_accepted_runtime", "create_recovery_accepted_runtime",
    "validate_accepted_mechanism_receipt", "validate_query", "validate_raw_observation",
    "validate_source_service_configuration", "validate_source_service_set", "writer_operation_owners"]


if __name__ == "__main__":
    raise SystemExit(operation_source_runner_main())
