#!/usr/bin/env python3
"""First-party supported-host runtime with explicit live-evidence gates."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping

from package_host_supported_host_fact_sources_v1 import UnavailableFact
from supported_host_protected_fact_store_v1 import (
    ProtectedFactStoreClientV1, StoreDerivedAvailableFact, TEST_CLASSIFICATION,
)
from supported_host_protected_service_v1 import (
    OsBoundProtectedFactSource, OsBoundDeploymentAdmissionV2Source,
    ProtectedServiceError, ValidatedProtectedFact, validate_service_set,
)
from supported_host_durable_store_v1 import ProtectedDurableWriter
from supported_host_operation_sources_v1 import (
    OWNER_IDS, OPERATION_ROWS as SOURCE_OPERATION_ROWS, AcceptedOperationFamilyRuntime,
    OperationSourceStore, QuarantinedDerivedResult,
    create_catalog_selection_accepted_runtime, create_effect_authority_accepted_runtime,
    create_native_supervision_accepted_runtime, create_recovery_accepted_runtime,
    create_registered_action_accepted_runtime, create_responses_seals_accepted_runtime,
)
from supported_host_public_profile_v1 import (
    HANDSHAKE_PENDING_STATE, PENDING_STATE, RUNTIME_ID,
    CURRENT_DEPLOYMENT_ADMISSION_IDENTITY,
    validate_public_profile, validate_receiver_handshake_evidence,
)


RUNTIME_TYPE = "codexmax_first_party_supported_host_runtime_v1"
STORE_ID = "codexmax-first-party-supported-host-store-v1"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")

_ROWS = tuple(
    (
        operation, source["canonical_source_id"], source["owner_id"],
        source["producer_principal_id"], source["namespace"],
        source["dependency_operations"],
    )
    for operation, source in SOURCE_OPERATION_ROWS.items()
)

OPERATION_ROWS = MappingProxyType({
    operation: MappingProxyType({
        "operation": operation,
        "canonical_source_id": source_id,
        "runtime_owner": owner,
        "producer_principal_id": principal,
        "durable_namespace": namespace,
        "sequence_head_owner": principal + ":" + namespace,
        "dependency_operations": dependencies,
        "authentication_boundary": "receiver_owned_mtls_handshake_v1",
        "request_shape": "accepted_v8_operation_body_v1",
        "result_shape": "operation_specific_closed_positive_fact_v1",
        "freshness_rule": "observed_at_not_future_expires_at_future_max_policy_age",
        "restart_behavior": "recover_protected_writer_envelope_and_independent_anchor",
        "replay_collision_behavior": "reject_nonce_record_head_or_generation_reuse",
        "revocation_behavior": "append_only_revocation_precedes_unavailable",
        "consumption_behavior": "recovery_grants_are_one_use_and_persist_consumption",
        "unavailable_behavior": "typed_unavailable_without_publication",
        "promotion_condition": "receiver_live_handshake_and_protected_writer_anchor_and_exact_dependency_receipts",
    })
    for operation, source_id, owner, principal, namespace, dependencies in _ROWS
})

PRINCIPAL_IDS = tuple(sorted({row[3] for row in _ROWS}))
DURABLE_NAMESPACES = ("authority", "registered_action", "responses", "catalog", "selection", "native_inventory", "recovery")


class FirstPartyRuntimeError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


_ARTIFACT_ROLES = MappingProxyType({
    "catalog_selection_to_responses_selection_v1": ("catalog_selection", "responses_seals"),
    "native_supervision_to_responses_context_v1": ("native_supervision", "responses_seals"),
    "responses_context_to_effect_authority_v1": ("responses_seals", "effect_authority"),
    "effect_authority_to_registered_action_v1": ("effect_authority", "registered_action"),
    "registered_action_to_responses_bridge_v1": ("registered_action", "responses_seals"),
    "responses_projection_to_recovery_v1": ("responses_seals", "recovery"),
    "native_supervision_to_recovery_v1": ("native_supervision", "recovery"),
    "effect_authority_to_recovery_v1": ("effect_authority", "recovery"),
})


def _mutable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _mutable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mutable(item) for item in value]
    return deepcopy(value)


class QuarantinedAcceptedFamilyRuntimeV1:
    """One temp-root integration of the six accepted role-local runtimes."""

    __slots__ = ("root", "authority", "operation_stores", "family_runtimes")

    def __init__(self, root: Path, authority: Mapping[str, Any]) -> None:
        from supported_host_protected_service_v1 import validate_joint_service_authority

        joint = validate_joint_service_authority(authority)
        if joint["execution_scope"] != "source_local_test":
            raise FirstPartyRuntimeError("accepted_runtime_scope_invalid", "$.authority.execution_scope")
        if not isinstance(root, Path) or not root.is_absolute() or root.exists() or root.is_symlink():
            raise FirstPartyRuntimeError("accepted_runtime_root_invalid", "$.root")
        root.mkdir(mode=0o700)
        plain_joint = _mutable(joint)
        stores = {}
        for owner_id in OWNER_IDS:
            role = joint["roles"][owner_id]
            stores[owner_id] = OperationSourceStore.create_source_local(
                root / owner_id, owner_id=owner_id,
                source_id=owner_id.replace("_", "-") + "-owner-v1",
                source_build_sha256=role["service_build_sha256"],
                service_uid=role["expected_uid"], service_gid=role["expected_gid"],
                service_start_id=role["expected_service_start_id"],
                service_session_id=role["expected_service_session_id"],
            )
        runtimes = {
            "catalog_selection": create_catalog_selection_accepted_runtime(root / "catalog_selection", plain_joint),
            "native_supervision": create_native_supervision_accepted_runtime(root / "native_supervision", plain_joint),
            "responses_seals": create_responses_seals_accepted_runtime(root / "responses_seals", plain_joint),
            "effect_authority": create_effect_authority_accepted_runtime(
                root / "effect_authority", plain_joint,
                operation_state_store=stores["effect_authority"],
            ),
            "registered_action": create_registered_action_accepted_runtime(root / "registered_action", plain_joint),
            "recovery": create_recovery_accepted_runtime(root / "recovery", plain_joint),
        }
        self.root = root
        self.authority = joint
        self.operation_stores = MappingProxyType(stores)
        self.family_runtimes = MappingProxyType(runtimes)

    def execute(
        self, operation: str, raw_observation: Mapping[str, Any], query: Mapping[str, Any],
        *, owner_now: str,
    ) -> QuarantinedDerivedResult | Any:
        row = SOURCE_OPERATION_ROWS.get(operation)
        if row is None:
            raise FirstPartyRuntimeError("runtime_operation_invalid", "$.operation")
        owner = row["owner_id"]
        return self.operation_stores[owner].acquire_accepted(
            operation, raw_observation, query,
            accepted_runtime=self.family_runtimes[owner], owner_now=owner_now,
        )

    def transfer(self, edge_id: str, *, observed_at: datetime, expires_at: datetime) -> Any:
        from supported_host_cross_owner_artifacts_v1 import transfer_source_local_artifact
        from supported_host_protected_service_v1 import cross_owner_service_identity

        roles = _ARTIFACT_ROLES.get(edge_id)
        if roles is None:
            raise FirstPartyRuntimeError("accepted_runtime_edge_invalid", "$.edge_id")
        producer, consumer = roles
        return transfer_source_local_artifact(
            edge_id=edge_id,
            producer_store=self.family_runtimes[producer].artifact_store,
            consumer_store=self.family_runtimes[consumer].artifact_store,
            family_store=self.family_runtimes[producer].family_store,
            producer_identity=cross_owner_service_identity(self.authority, producer),
            consumer_identity=cross_owner_service_identity(self.authority, consumer),
            joint_authority_sha256=self.authority["authority_sha256"],
            observed_at=observed_at, expires_at=expires_at,
        )

    def describe(self) -> Mapping[str, Any]:
        return MappingProxyType({
            "schema_version": 1,
            "artifact_type": "codexmax_quarantined_accepted_family_runtime_v1",
            "execution_scope": "source_local_quarantine_non_production",
            "operation_count": 12, "owner_count": 6, "artifact_edge_count": 8,
            "operations": tuple(SOURCE_OPERATION_ROWS), "owners": OWNER_IDS,
            "artifact_edges": tuple(_ARTIFACT_ROLES), "production_ready": False,
        })


class FirstPartySupportedHostRuntimeV1:
    """Executable owner and persistence boundary. Source-local state stays pending."""

    __slots__ = ("_profile", "_identity", "_materialized_identity", "_handshakes", "_writer", "_store", "_protected_source", "_clock", "_test_only")

    def __init__(
        self, *, public_profile: Mapping[str, Any], exact_identity: Mapping[str, Any] | None = None,
        runner_admission_source: OsBoundDeploymentAdmissionV2Source | None = None,
        receiver_handshake_evidence: Mapping[str, Mapping[str, Any]] | None,
        protected_writer: ProtectedDurableWriter | None, utc_clock,
        protected_fact_store_client: ProtectedFactStoreClientV1 | None = None,
        protected_service_fact_source: OsBoundProtectedFactSource | None = None,
        protected_service_configurations: Mapping[str, Mapping[str, Any]] | None = None,
        _test_only: bool = False,
    ) -> None:
        now = self._now(utc_clock)
        self._profile = validate_public_profile(public_profile, now=now)
        materialized = {
            "workspace_id", "source_sha256", "candidate_sha256", "manifest_sha256",
            "generation", "host_id", "service_instance_id", "service_start_id",
        }
        admitted = materialized | {
            "runner_candidate_id", "runner_archive_sha256", "runner_manifest_sha256",
            "runner_source_identity_sha256", "runner_target", "runner_installer_identity",
            "runner_admission_services", "deployment_admission_sha256",
            "candidate_descriptor_sha256", "root_manifest_sha256", "child_pid",
            "child_uid", "child_gid", "child_executable_sha256", "nonce",
            "expires_at", "revocation_state", "previous_commit_sha256",
            "deployment_commit_sha256", "writer_receipt_sha256",
            "anchor_receipt_sha256", "ledger_head_sha256",
        }
        self._test_only = _test_only is True
        if self._test_only:
            if runner_admission_source is not None or not isinstance(exact_identity, Mapping):
                raise FirstPartyRuntimeError("test_runtime_identity_invalid", "$.identity")
            identity = dict(exact_identity)
            if not materialized.issubset(identity):
                raise FirstPartyRuntimeError("runtime_identity_shape_invalid", "$.identity")
        else:
            if exact_identity is not None:
                raise FirstPartyRuntimeError("runtime_plain_admission_forbidden", "$.identity")
            if type(runner_admission_source) is not OsBoundDeploymentAdmissionV2Source:
                raise FirstPartyRuntimeError("deployment_admission_v2_source_required", "$.source")
            try:
                admission = dict(runner_admission_source._consume_authenticated_admission(now=now))
            except ProtectedServiceError as exc:
                raise FirstPartyRuntimeError(exc.code, exc.path) from exc
            selected = self._profile["candidate"]
            if (
                selected.get("state") != "selected_descriptor_verified_non_authorizing"
                or selected.get("descriptor_sha256") != admission["candidate_descriptor_sha256"]
                or selected.get("candidate_id") != admission["candidate_id"]
                or selected.get("archive_sha256") != admission["archive_sha256"]
                or selected.get("sidecar_sha256") != admission["sidecar_sha256"]
                or selected.get("source_identity_sha256") != admission["source_identity_sha256"]
                or selected.get("generation") != admission["generation"]
            ):
                raise FirstPartyRuntimeError("runtime_selected_candidate_admission_mismatch", "$.candidate")
            identity = {
                "workspace_id": "codexmax-external-workspace-v1",
                "source_sha256": admission["source_identity_sha256"],
                "candidate_sha256": admission["archive_sha256"],
                "manifest_sha256": admission["sidecar_sha256"],
                "generation": admission["generation"],
                "host_id": CURRENT_DEPLOYMENT_ADMISSION_IDENTITY["host_id"],
                "service_instance_id": "codexmax-external-service-v1",
                "service_start_id": admission["child_start_id"],
                "runner_candidate_id": admission["candidate_id"],
                "runner_archive_sha256": admission["archive_sha256"],
                "runner_manifest_sha256": admission["sidecar_sha256"],
                "runner_source_identity_sha256": admission["source_identity_sha256"],
                "runner_target": f"verified-root:{admission['verified_root_device']}:{admission['verified_root_inode']}",
                "runner_installer_identity": admission["installer_identity"],
                "runner_admission_services": {
                    "protected_writer": {"service_start_id": admission["writer_service_start_id"], "service_session_id": admission["writer_service_session_id"]},
                    "independent_anchor": {"service_start_id": admission["anchor_service_start_id"], "service_session_id": admission["anchor_service_session_id"]},
                },
                "deployment_admission_sha256": admission["admission_sha256"],
                "candidate_descriptor_sha256": admission["candidate_descriptor_sha256"],
                "root_manifest_sha256": admission["root_manifest_sha256"],
                "child_pid": admission["child_pid"], "child_uid": admission["child_uid"],
                "child_gid": admission["child_gid"], "child_executable_sha256": admission["child_executable_sha256"],
                "nonce": admission["nonce_sha256"], "expires_at": admission["expires_at"],
                "revocation_state": admission["revocation_state"],
                "previous_commit_sha256": admission["previous_committed_head_sha256"],
                "deployment_commit_sha256": admission["deployment_commit_sha256"],
                "writer_receipt_sha256": admission["writer_receipt_sha256"],
                "anchor_receipt_sha256": admission["anchor_receipt_sha256"],
                "ledger_head_sha256": admission["ledger_head_sha256"],
            }
            if set(identity) != admitted:
                raise FirstPartyRuntimeError("runtime_authority_identity_shape_invalid", "$.authority")
        if (
            identity["host_id"] != CURRENT_DEPLOYMENT_ADMISSION_IDENTITY["host_id"]
            or any(
                not isinstance(identity[field], str) or _SHA.fullmatch(identity[field]) is None
                for field in (
                    "candidate_sha256", "manifest_sha256", "source_sha256",
                    *(("runner_archive_sha256", "runner_manifest_sha256", "runner_source_identity_sha256") if not self._test_only else ()),
                )
            )
        ):
            raise FirstPartyRuntimeError("runtime_candidate_identity_mismatch", "$.identity")
        self._identity = deepcopy(identity)
        self._materialized_identity = {
            field: self._identity[field]
            for field in (
                "workspace_id", "source_sha256", "candidate_sha256", "manifest_sha256",
                "generation", "host_id", "service_instance_id", "service_start_id",
            )
        }
        self._handshakes: dict[str, Mapping[str, Any]] = {}
        evidence = {} if receiver_handshake_evidence is None else receiver_handshake_evidence
        if not isinstance(evidence, Mapping) or not set(evidence).issubset(PRINCIPAL_IDS):
            raise FirstPartyRuntimeError("runtime_handshake_inventory_invalid", "$.handshakes")
        for principal, row in evidence.items():
            validated = validate_receiver_handshake_evidence(row, self._profile, now=now)
            if validated["principal_id"] != principal:
                raise FirstPartyRuntimeError("runtime_handshake_principal_mismatch", "$.handshakes." + principal)
            self._handshakes[principal] = validated
        self._writer = protected_writer
        if protected_fact_store_client is not None and type(protected_fact_store_client) is not ProtectedFactStoreClientV1:
            raise FirstPartyRuntimeError("protected_fact_store_client_invalid", "$.store")
        self._store = protected_fact_store_client
        if protected_service_fact_source is not None and type(protected_service_fact_source) is not OsBoundProtectedFactSource:
            raise FirstPartyRuntimeError("protected_service_fact_source_invalid", "$.protected_service")
        if protected_service_fact_source is not None:
            if protected_service_configurations is None:
                raise FirstPartyRuntimeError("protected_service_set_required", "$.protected_service")
            try:
                services = validate_service_set(protected_service_configurations)
            except Exception as exc:
                raise FirstPartyRuntimeError("protected_service_set_invalid", "$.protected_service") from exc
            if any(dict(services[name]) != dict(protected_service_fact_source._service_set[name]) for name in services):
                raise FirstPartyRuntimeError("protected_service_set_mismatch", "$.protected_service")
        elif protected_service_configurations is not None:
            raise FirstPartyRuntimeError("protected_service_source_required", "$.protected_service")
        self._protected_source = protected_service_fact_source
        self._clock = utc_clock

    @classmethod
    def test_only(cls, **values: Any) -> "FirstPartySupportedHostRuntimeV1":
        """Construct a source-local runtime that cannot produce authority."""
        values["_test_only"] = True
        return cls(**values)

    @staticmethod
    def _now(clock) -> datetime:
        value = clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
            raise FirstPartyRuntimeError("runtime_clock_invalid", "$.clock")
        return value.astimezone(timezone.utc).replace(microsecond=0)

    def describe(self) -> Mapping[str, Any]:
        return MappingProxyType({
            "schema_version": 1, "artifact_type": RUNTIME_TYPE, "runtime_id": RUNTIME_ID,
            "candidate": dict(CURRENT_DEPLOYMENT_ADMISSION_IDENTITY), "operations": tuple(OPERATION_ROWS),
            "principals": PRINCIPAL_IDS, "durable_namespaces": DURABLE_NAMESPACES,
            "profile_state": self._profile["state"],
            "production_ready": bool(
                self._protected_source is not None
                and self._profile["state"] != PENDING_STATE
                and not self._test_only
            ),
        })

    def read_fact(
        self, operation: str, exact_identity: Any,
        dependency_receipts: Mapping[str, str], now: datetime,
        operation_body: Mapping[str, Any] | None = None,
    ) -> UnavailableFact | StoreDerivedAvailableFact | ValidatedProtectedFact:
        if not hasattr(self, "_materialized_identity") or not hasattr(self, "_test_only"):
            raise FirstPartyRuntimeError("runtime_not_admitted", "$.runtime")
        row = OPERATION_ROWS.get(operation)
        if row is None:
            raise FirstPartyRuntimeError("runtime_operation_invalid", "$.operation")
        if not isinstance(exact_identity, Mapping) or dict(exact_identity) != self._materialized_identity:
            raise FirstPartyRuntimeError("runtime_identity_mismatch", "$.identity")
        if abs((self._now(lambda: now) - self._now(self._clock)).total_seconds()) > 5:
            raise FirstPartyRuntimeError("runtime_clock_drift", "$.now")
        if not isinstance(dependency_receipts, Mapping) or set(dependency_receipts) != set(row["dependency_operations"]):
            return UnavailableFact(operation, "dependency_receipts_unavailable", row["canonical_source_id"])
        if any(not isinstance(value, str) or _SHA.fullmatch(value) is None for value in dependency_receipts.values()):
            return UnavailableFact(operation, "dependency_receipts_invalid", row["canonical_source_id"])
        if self._profile["state"] == PENDING_STATE and not self._test_only:
            reason = "public_deployment_identity_pending"
        elif row["producer_principal_id"] not in self._handshakes and not self._test_only:
            reason = "receiver_owned_tls_handshake_pending"
        elif not self._test_only and self._handshakes[row["producer_principal_id"]]["state"] != "pending_receiver_owned_live_validation":
            reason = "receiver_owned_tls_handshake_invalid"
        elif self._test_only and self._store is None:
            reason = "protected_fact_store_pending"
        elif not self._test_only and self._protected_source is None:
            reason = "protected_service_channel_pending"
        elif operation_body is None or not isinstance(operation_body, Mapping):
            reason = "operation_body_unavailable"
        elif self._test_only and self._store.classification != TEST_CLASSIFICATION:
            reason = "protected_fact_store_classification_invalid"
        elif not self._test_only:
            return self._protected_source.read_fact(
                operation, self._materialized_identity, dependency_receipts,
                self._now(lambda: now), operation_body,
            )
        else:
            read = self._store.read_fact(
                operation=operation, canonical_source_id=row["canonical_source_id"],
                producer_principal_id=row["producer_principal_id"],
                namespace=row["durable_namespace"], identity=self._materialized_identity,
                profile_sha256=self._profile["profile_sha256"],
                operation_body=operation_body,
                dependency_receipts=dependency_receipts, now=self._now(lambda: now),
            )
            if read.state == "available":
                return self._store.promote(read)
            reason = read.reason or "protected_fact_unavailable"
        return UnavailableFact(operation, reason, row["canonical_source_id"])

__all__ = [
    "DURABLE_NAMESPACES", "FirstPartyRuntimeError", "FirstPartySupportedHostRuntimeV1",
    "OPERATION_ROWS", "PRINCIPAL_IDS", "QuarantinedAcceptedFamilyRuntimeV1", "RUNTIME_TYPE", "STORE_ID",
]
