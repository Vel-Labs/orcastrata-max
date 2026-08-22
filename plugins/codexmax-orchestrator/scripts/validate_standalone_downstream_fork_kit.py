#!/usr/bin/env python3
"""Validate one static downstream fork-kit envelope without effects."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any, Mapping


SCHEMA_VERSION = 2
ARTIFACT_TYPE = "standalone_downstream_fork_kit_v2"
RECEIPT_TYPE = "standalone_downstream_fork_kit_receipt_v2"
PACKAGE_NAME = "codexmax-orchestrator"
UPSTREAM_VERSION = "0.6.0-rc.6+codex.20260816"
UPSTREAM_MANIFEST_SHA256 = "c7abb4abc0d6ec92b631bfcee9cd0a40e58c45caad8df065fc21610ad4b59865"
UPSTREAM_TREE_SHA256 = "c40a9f18462faa917963121f18db022044af90d877e8d087a5e860ae0938cc92"
UPSTREAM_MANIFEST_ROWS = 362
UPSTREAM_PHYSICAL_FILES = 363
ZERO_DIGEST = "sha256:" + "0" * 64
OVERLAY_CLASSES = ["client_adapter", "read_model_projection"]
FORBIDDEN_AUTHORITIES = ["capacity", "assignment_authority", "acceptance"]
SHARED_COMPONENTS = [
    "runtime", "event", "receipt", "adapter", "route_identity",
    "assignment_authority", "delegation", "task_journal", "capacity_authority",
]
EVIDENCE_ROWS = [
    {
        "category": "installed_journey",
        "path": "reports/codexmax-standalone-product-completion-v1/t080/T080-installed-journey-receipt.md",
        "sha256": "sha256:50a5752c1d90235b11a700cf9e5f5117442025da957c0f2e477bdd3dad37e21d",
        "proof_scope": "installed_task_scoped_usability",
    },
    {
        "category": "provider_dispatch",
        "path": "reports/codexmax-standalone-product-completion-v1/t080/provider/evidence/dispatch-return-manifest.json",
        "sha256": "sha256:ebce35fd9690f5957dc191ddc6b82f3c33684339ecacdaa8153cb10c5fdaed55",
        "proof_scope": "one_task_scoped_provider_attempt",
    },
    {
        "category": "compact_telemetry",
        "path": "reports/codexmax-standalone-product-completion-v1/t080/compact-telemetry/deepseek-pro.json",
        "sha256": "sha256:ce3d664fddbcac7a001249ab124cbefc2ad4f03a4565a978ac2db4f68b4da727",
        "proof_scope": "advisory_observation_only",
    },
    {
        "category": "advisory_evaluation",
        "path": "reports/provider-evaluation-suite-v1/V2-parent-acceptance.json",
        "sha256": "sha256:2e9127d590930d556f4b0d1d8492a96ee7c8d0cc8f75f81f991d104ab7f90169",
        "proof_scope": "bounded_advisory_evaluation",
    },
    {
        "category": "real_work_dogfood",
        "path": "reports/codexmax-standalone-product-completion-v1/t233/T233-real-work-dogfood-receipt.md",
        "sha256": "sha256:7edb1f6a9b1a7ffa7935e1d05f9367f05da19d37cb7d6ceebade69777e22f63a",
        "proof_scope": "parent_reviewed_task_scoped_dogfood",
    },
    {
        "category": "deferred_enterprise",
        "path": "reports/codexmax-standalone-product-completion-v1/t062/T062-R4-current-live-proof-audit.json",
        "sha256": "sha256:9d87d42844d1d86f1c664127aa92c91e97f6f9530ef974f8033e4a0ae6888463",
        "proof_scope": "blocked_external_deferred_to_aol",
    },
]
OVERLAY_FALSE_FIELDS = [
    "implementation_included", "executable_logic_included", "grants_capability",
    "grants_authority", "allocates_capacity", "creates_lease",
    "normalizes_billing", "counts_usage", "creates_receipt_truth",
    "accepts_work", "mutates_board_truth", "mutates_policy_truth",
    "calls_provider", "changes_shared_components",
]
HANDOFF_FALSE_FIELDS = [
    "aol_admitted", "c50_accepted", "c60_accepted", "joined_execution",
    "product_accepted", "assurance_claimed", "economics_claimed",
    "home_now_truth_claimed", "broker_write_authority",
    "goalbuddy_write_authority", "provider_called", "network_used",
    "service_started", "installed", "published",
]
SANITIZATION_TRUE_FIELDS = [
    "raw_prompts_excluded", "raw_transcripts_excluded",
    "raw_provider_output_excluded", "credentials_excluded",
    "auth_material_excluded", "private_environment_excluded",
    "secret_bearing_paths_excluded", "broker_write_authority_excluded",
    "goalbuddy_write_authority_excluded",
]
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,127}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
UNSAFE_TEXT = re.compile(
    r"(?i)(?:https?://|wss?://|bearer\s|api[_-]?key|password|passwd|secret\s*[:=]|"
    r"credential\s*[:=]|authorization\s*[:=]|-----begin|\$\{|sk-[a-z0-9])"
)


class ForkKitError(ValueError):
    def __init__(self, code: str, path: str = "$"):
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ForkKitError("duplicate_json_key", key)
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ForkKitError("nonfinite_number", value)


def _reject_floats(value: Any, path: str = "$") -> None:
    if isinstance(value, float):
        raise ForkKitError("float_forbidden", path)
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_floats(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_floats(child, f"{path}[{index}]")


def canonical_bytes(value: Any) -> bytes:
    _reject_floats(value)
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def load_json(path: str | Path) -> Any:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ForkKitError("input_read_failed", str(path)) from exc
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except ForkKitError:
        raise
    except UnicodeDecodeError as exc:
        raise ForkKitError("utf8_invalid", f"byte:{exc.start}") from exc
    except json.JSONDecodeError as exc:
        raise ForkKitError("json_invalid", f"line:{exc.lineno}:column:{exc.colno}") from exc
    _reject_floats(value)
    return value


def _decode_json(raw: bytes, path: str) -> Any:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except ForkKitError:
        raise
    except UnicodeDecodeError as exc:
        raise ForkKitError("utf8_invalid", f"{path}:byte:{exc.start}") from exc
    except json.JSONDecodeError as exc:
        raise ForkKitError("json_invalid", f"{path}:line:{exc.lineno}:column:{exc.colno}") from exc
    _reject_floats(value)
    return value


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ForkKitError("object_required", path)
    extra = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if extra:
        raise ForkKitError("unknown_field", f"{path}.{extra[0]}")
    if missing:
        raise ForkKitError("missing_field", f"{path}.{missing[0]}")
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ForkKitError("identifier_invalid", path)
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ForkKitError("digest_invalid", path)
    return value


def _integer(value: Any, path: str) -> int:
    if type(value) is not int:
        raise ForkKitError("integer_invalid", path)
    return value


def _false(value: Any, code: str, path: str) -> None:
    if value is not False:
        raise ForkKitError(code, path)


def _true(value: Any, code: str, path: str) -> None:
    if value is not True:
        raise ForkKitError(code, path)


def _scan_unsafe(value: Any, path: str = "$") -> None:
    if isinstance(value, str) and UNSAFE_TEXT.search(value):
        raise ForkKitError("unsafe_text", path)
    if isinstance(value, dict):
        for key, child in value.items():
            _scan_unsafe(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_unsafe(child, f"{path}[{index}]")


def _without(value: Mapping[str, Any], key: str) -> dict[str, Any]:
    return {name: child for name, child in value.items() if name != key}


def rehash_kit(document: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deep-copied kit with all canonical digest fields recomputed."""
    root = copy.deepcopy(document)
    previous = ZERO_DIGEST
    for row in root["divergence_ledger"]["entries"]:
        row["previous_entry_sha256"] = previous
        row["entry_sha256"] = digest(_without(row, "entry_sha256"))
        previous = row["entry_sha256"]
    ledger = root["divergence_ledger"]
    ledger["entry_count"] = len(ledger["entries"])
    ledger["ledger_sha256"] = digest(_without(ledger, "ledger_sha256"))
    handoff = root["handoff"]
    handoff["proposal_sha256"] = digest(_without(handoff, "proposal_sha256"))
    integrity = root["integrity"]
    integrity["upstream_anchor_sha256"] = digest(root["upstream_anchor"])
    integrity["overlay_policy_sha256"] = digest(root["overlay_policy"])
    integrity["divergence_ledger_sha256"] = ledger["ledger_sha256"]
    integrity["compatibility_sha256"] = digest(root["compatibility"])
    integrity["lifecycle_sha256"] = digest(root["lifecycle"])
    integrity["external_mappings_sha256"] = digest(root["external_mappings"])
    integrity["evidence_catalog_sha256"] = digest(root["evidence_catalog"])
    integrity["handoff_sha256"] = handoff["proposal_sha256"]
    integrity["kit_sha256"] = digest({
        **root,
        "integrity": _without(integrity, "kit_sha256"),
    })
    return root


def _validate_fork_identity(value: Any) -> dict[str, Any]:
    fork = _closed(value, {
        "state", "distribution_id", "fork_commit", "fork_tree_sha256", "build_id",
    }, "$.fork_identity")
    _identifier(fork["distribution_id"], "$.fork_identity.distribution_id")
    if fork["state"] == "proposed_not_created":
        if any(fork[key] is not None for key in ("fork_commit", "fork_tree_sha256", "build_id")):
            raise ForkKitError("proposed_fork_identity_forbidden", "$.fork_identity")
    elif fork["state"] == "candidate_created_not_admitted":
        if not isinstance(fork["fork_commit"], str) or HEX40.fullmatch(fork["fork_commit"]) is None:
            raise ForkKitError("candidate_commit_invalid", "$.fork_identity.fork_commit")
        _digest(fork["fork_tree_sha256"], "$.fork_identity.fork_tree_sha256")
        _identifier(fork["build_id"], "$.fork_identity.build_id")
    else:
        raise ForkKitError("fork_state_invalid", "$.fork_identity.state")
    return fork


def _validate_overlays(value: Any) -> dict[str, Any]:
    policy = _closed(value, {
        "allowed_classes", "forbidden_duplicate_authorities", "declarations",
    }, "$.overlay_policy")
    if policy["allowed_classes"] != OVERLAY_CLASSES:
        raise ForkKitError("overlay_class_set_invalid", "$.overlay_policy.allowed_classes")
    if policy["forbidden_duplicate_authorities"] != FORBIDDEN_AUTHORITIES:
        raise ForkKitError("duplicate_authority_set_invalid", "$.overlay_policy.forbidden_duplicate_authorities")
    if not isinstance(policy["declarations"], list) or len(policy["declarations"]) != 2:
        raise ForkKitError("overlay_declarations_invalid", "$.overlay_policy.declarations")
    expected_modes = ["translate_only", "project_only"]
    fields = {"overlay_class", "mode", *OVERLAY_FALSE_FIELDS}
    for index, raw in enumerate(policy["declarations"]):
        path = f"$.overlay_policy.declarations[{index}]"
        row = _closed(raw, fields, path)
        if row["overlay_class"] != OVERLAY_CLASSES[index] or row["mode"] != expected_modes[index]:
            raise ForkKitError("overlay_declaration_mismatch", path)
        for field in OVERLAY_FALSE_FIELDS:
            _false(row[field], "overlay_boundary_invalid", f"{path}.{field}")
    return policy


def _validate_ledger(value: Any) -> dict[str, Any]:
    ledger = _closed(value, {
        "ledger_id", "previous_ledger_sha256", "entry_count", "entries", "ledger_sha256",
    }, "$.divergence_ledger")
    _identifier(ledger["ledger_id"], "$.divergence_ledger.ledger_id")
    if ledger["previous_ledger_sha256"] != ZERO_DIGEST:
        raise ForkKitError("ledger_predecessor_invalid", "$.divergence_ledger.previous_ledger_sha256")
    if not isinstance(ledger["entries"], list) or len(ledger["entries"]) != 2:
        raise ForkKitError("divergence_entries_invalid", "$.divergence_ledger.entries")
    if _integer(ledger["entry_count"], "$.divergence_ledger.entry_count") != len(ledger["entries"]):
        raise ForkKitError("divergence_count_mismatch", "$.divergence_ledger.entry_count")
    previous = ZERO_DIGEST
    fields = {
        "divergence_id", "sequence", "previous_entry_sha256", "classification",
        "overlay_class", "applied", "shared_component_changes", "patch_sha256",
        "compatibility_impact", "upstream_return_status", "entry_sha256",
    }
    seen: set[str] = set()
    for index, raw in enumerate(ledger["entries"]):
        path = f"$.divergence_ledger.entries[{index}]"
        row = _closed(raw, fields, path)
        identity = _identifier(row["divergence_id"], f"{path}.divergence_id")
        if identity in seen:
            raise ForkKitError("divergence_id_duplicate", f"{path}.divergence_id")
        seen.add(identity)
        if _integer(row["sequence"], f"{path}.sequence") != index + 1:
            raise ForkKitError("divergence_sequence_invalid", f"{path}.sequence")
        if row["previous_entry_sha256"] != previous:
            raise ForkKitError("divergence_chain_invalid", f"{path}.previous_entry_sha256")
        if row["classification"] != "overlay_declaration" or row["overlay_class"] != OVERLAY_CLASSES[index]:
            raise ForkKitError("divergence_classification_invalid", path)
        _false(row["applied"], "applied_divergence_forbidden", f"{path}.applied")
        if row["shared_component_changes"] != []:
            raise ForkKitError("shared_component_change_forbidden", f"{path}.shared_component_changes")
        if row["patch_sha256"] is not None:
            raise ForkKitError("proposed_patch_forbidden", f"{path}.patch_sha256")
        if row["compatibility_impact"] != "none" or row["upstream_return_status"] != "not_applicable":
            raise ForkKitError("divergence_boundary_invalid", path)
        expected = digest(_without(row, "entry_sha256"))
        if row["entry_sha256"] != expected:
            raise ForkKitError("divergence_entry_digest_mismatch", f"{path}.entry_sha256")
        previous = row["entry_sha256"]
    if ledger["ledger_sha256"] != digest(_without(ledger, "ledger_sha256")):
        raise ForkKitError("divergence_ledger_digest_mismatch", "$.divergence_ledger.ledger_sha256")
    return ledger


def _validate_compatibility(value: Any) -> dict[str, Any]:
    compatibility = _closed(value, {
        "component_versions", "unknown_versions_fail_closed",
        "shared_component_changes_allowed", "compatibility_status",
        "shared_conformance",
    }, "$.compatibility")
    versions = _closed(compatibility["component_versions"], set(SHARED_COMPONENTS), "$.compatibility.component_versions")
    if list(versions) != SHARED_COMPONENTS:
        raise ForkKitError("component_order_invalid", "$.compatibility.component_versions")
    for name, version in versions.items():
        if _integer(version, f"$.compatibility.component_versions.{name}") != 1:
            raise ForkKitError("component_version_unsupported", f"$.compatibility.component_versions.{name}")
    _true(compatibility["unknown_versions_fail_closed"], "compatibility_boundary_invalid", "$.compatibility.unknown_versions_fail_closed")
    _false(compatibility["shared_component_changes_allowed"], "compatibility_boundary_invalid", "$.compatibility.shared_component_changes_allowed")
    if compatibility["compatibility_status"] != "not_run":
        raise ForkKitError("compatibility_status_invalid", "$.compatibility.compatibility_status")
    conformance = _closed(compatibility["shared_conformance"], {
        "status", "receipt_sha256", "passed", "proves_aol_admission",
    }, "$.compatibility.shared_conformance")
    if conformance["status"] != "not_run" or conformance["receipt_sha256"] is not None:
        raise ForkKitError("conformance_status_invalid", "$.compatibility.shared_conformance")
    _false(conformance["passed"], "conformance_claim_forbidden", "$.compatibility.shared_conformance.passed")
    _false(conformance["proves_aol_admission"], "conformance_claim_forbidden", "$.compatibility.shared_conformance.proves_aol_admission")
    return compatibility


def _validate_lifecycle(value: Any) -> dict[str, Any]:
    lifecycle = _closed(value, {"upgrade", "backport", "upstream_return", "rollback"}, "$.lifecycle")
    upgrade = _closed(lifecycle["upgrade"], {"status", "requires_new_identity", "performed", "authority_granted"}, "$.lifecycle.upgrade")
    if upgrade["status"] != "not_performed":
        raise ForkKitError("upgrade_status_invalid", "$.lifecycle.upgrade.status")
    _true(upgrade["requires_new_identity"], "upgrade_boundary_invalid", "$.lifecycle.upgrade.requires_new_identity")
    _false(upgrade["performed"], "lifecycle_effect_forbidden", "$.lifecycle.upgrade.performed")
    _false(upgrade["authority_granted"], "lifecycle_authority_forbidden", "$.lifecycle.upgrade.authority_granted")
    backport = _closed(lifecycle["backport"], {"status", "patch_sha256", "performed", "authority_granted"}, "$.lifecycle.backport")
    if backport["status"] != "not_proposed" or backport["patch_sha256"] is not None:
        raise ForkKitError("backport_status_invalid", "$.lifecycle.backport")
    _false(backport["performed"], "lifecycle_effect_forbidden", "$.lifecycle.backport.performed")
    _false(backport["authority_granted"], "lifecycle_authority_forbidden", "$.lifecycle.backport.authority_granted")
    upstream_return = _closed(lifecycle["upstream_return"], {"status", "patch_sha256", "submitted", "merged", "accepted"}, "$.lifecycle.upstream_return")
    if upstream_return["status"] != "proposed_unsubmitted" or upstream_return["patch_sha256"] is not None:
        raise ForkKitError("upstream_return_status_invalid", "$.lifecycle.upstream_return")
    for field in ("submitted", "merged", "accepted"):
        _false(upstream_return[field], "upstream_return_claim_forbidden", f"$.lifecycle.upstream_return.{field}")
    rollback = _closed(lifecycle["rollback"], {"status", "target", "performed", "authority_granted", "history_rewritten"}, "$.lifecycle.rollback")
    if rollback["status"] != "not_performed" or rollback["target"] != "exact_upstream_anchor":
        raise ForkKitError("rollback_target_invalid", "$.lifecycle.rollback")
    for field in ("performed", "authority_granted", "history_rewritten"):
        _false(rollback[field], "rollback_boundary_invalid", f"$.lifecycle.rollback.{field}")
    return lifecycle


def _validate_mappings(value: Any) -> list[dict[str, Any]]:
    expected = [
        ("route_fabric_decision_v1", "RouteDecision", "AOL Core"),
        ("runtime_quality_receipt_v1", "Assurance", "AOL Core"),
        ("correction_economics_v1", "economics", "AOL Core"),
        ("execution_continuity_v1", "Home/Now", "AOL Home/Now"),
    ]
    if not isinstance(value, list) or len(value) != len(expected):
        raise ForkKitError("external_mapping_set_invalid", "$.external_mappings")
    fields = {
        "source_artifact", "external_semantic", "external_owner", "mapping_mode",
        "mapping_status", "implementation_included", "truth_claimed",
        "authority_granted", "acceptance_claimed",
    }
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        path = f"$.external_mappings[{index}]"
        row = _closed(raw, fields, path)
        actual = (row["source_artifact"], row["external_semantic"], row["external_owner"])
        if actual != expected[index]:
            raise ForkKitError("external_mapping_set_invalid", path)
        if row["mapping_mode"] != "reference_only" or row["mapping_status"] != "external_owner_unimplemented":
            raise ForkKitError("external_mapping_boundary_invalid", path)
        for field in ("implementation_included", "truth_claimed", "authority_granted", "acceptance_claimed"):
            _false(row[field], "external_mapping_claim_forbidden", f"{path}.{field}")
        result.append(row)
    return result


def _validate_evidence_catalog(value: Any) -> dict[str, Any]:
    catalog = _closed(value, {
        "status", "verification_required", "source_count", "sources",
        "execution_authority", "routing_authority", "provider_qualification",
        "protected_production", "aol_admission",
    }, "$.evidence_catalog")
    if catalog["status"] != "hash_bound_reference_only":
        raise ForkKitError("evidence_catalog_status_invalid", "$.evidence_catalog.status")
    _true(catalog["verification_required"], "evidence_verification_required", "$.evidence_catalog.verification_required")
    if _integer(catalog["source_count"], "$.evidence_catalog.source_count") != len(EVIDENCE_ROWS):
        raise ForkKitError("evidence_count_mismatch", "$.evidence_catalog.source_count")
    for field in (
        "execution_authority", "routing_authority", "provider_qualification",
        "protected_production", "aol_admission",
    ):
        _false(catalog[field], "evidence_authority_claim_forbidden", f"$.evidence_catalog.{field}")
    if not isinstance(catalog["sources"], list) or len(catalog["sources"]) != len(EVIDENCE_ROWS):
        raise ForkKitError("evidence_source_set_invalid", "$.evidence_catalog.sources")
    fields = {
        "category", "path", "sha256", "proof_scope", "grants_authority",
        "affects_routing", "proves_provider_qualification",
        "proves_protected_production", "proves_aol_admission",
    }
    for index, raw in enumerate(catalog["sources"]):
        path = f"$.evidence_catalog.sources[{index}]"
        row = _closed(raw, fields, path)
        expected = EVIDENCE_ROWS[index]
        for field in ("category", "path", "sha256", "proof_scope"):
            if row[field] != expected[field]:
                raise ForkKitError("evidence_source_mismatch", f"{path}.{field}")
        _relative_path(row["path"])
        _digest(row["sha256"], f"{path}.sha256")
        for field in (
            "grants_authority", "affects_routing", "proves_provider_qualification",
            "proves_protected_production", "proves_aol_admission",
        ):
            _false(row[field], "evidence_authority_claim_forbidden", f"{path}.{field}")
    return catalog


def _validate_handoff(value: Any) -> dict[str, Any]:
    handoff = _closed(value, {
        "target_label", "status", "sanitization", *HANDOFF_FALSE_FIELDS,
        "proposal_sha256",
    }, "$.handoff")
    if handoff["target_label"] != "AOL" or handoff["status"] != "proposed_not_admitted":
        raise ForkKitError("handoff_status_invalid", "$.handoff")
    sanitization = _closed(handoff["sanitization"], set(SANITIZATION_TRUE_FIELDS), "$.handoff.sanitization")
    for field in SANITIZATION_TRUE_FIELDS:
        _true(sanitization[field], "sanitization_required", f"$.handoff.sanitization.{field}")
    for field in HANDOFF_FALSE_FIELDS:
        _false(handoff[field], "handoff_claim_forbidden", f"$.handoff.{field}")
    if handoff["proposal_sha256"] != digest(_without(handoff, "proposal_sha256")):
        raise ForkKitError("handoff_digest_mismatch", "$.handoff.proposal_sha256")
    return handoff


def validate_kit(document: Mapping[str, Any]) -> dict[str, Any]:
    original = copy.deepcopy(document)
    root = _closed(document, {
        "schema_version", "artifact_type", "kit_id", "upstream_anchor",
        "fork_identity", "overlay_policy", "divergence_ledger", "compatibility",
        "lifecycle", "external_mappings", "evidence_catalog", "handoff", "integrity",
    }, "$")
    if type(root["schema_version"]) is not int or root["schema_version"] != SCHEMA_VERSION:
        raise ForkKitError("version_unsupported", "$.schema_version")
    if root["artifact_type"] != ARTIFACT_TYPE:
        raise ForkKitError("artifact_type_invalid", "$.artifact_type")
    _identifier(root["kit_id"], "$.kit_id")
    anchor = _closed(root["upstream_anchor"], {
        "package_name", "version", "release_manifest_sha256", "source_tree_sha256",
        "manifest_payload_rows", "physical_files",
    }, "$.upstream_anchor")
    expected_anchor = {
        "package_name": PACKAGE_NAME,
        "version": UPSTREAM_VERSION,
        "release_manifest_sha256": "sha256:" + UPSTREAM_MANIFEST_SHA256,
        "source_tree_sha256": "sha256:" + UPSTREAM_TREE_SHA256,
        "manifest_payload_rows": UPSTREAM_MANIFEST_ROWS,
        "physical_files": UPSTREAM_PHYSICAL_FILES,
    }
    if anchor != expected_anchor:
        raise ForkKitError("upstream_anchor_mismatch", "$.upstream_anchor")
    _validate_fork_identity(root["fork_identity"])
    _validate_overlays(root["overlay_policy"])
    ledger = _validate_ledger(root["divergence_ledger"])
    compatibility = _validate_compatibility(root["compatibility"])
    lifecycle = _validate_lifecycle(root["lifecycle"])
    mappings = _validate_mappings(root["external_mappings"])
    evidence_catalog = _validate_evidence_catalog(root["evidence_catalog"])
    handoff = _validate_handoff(root["handoff"])
    integrity = _closed(root["integrity"], {
        "digest_algorithm", "canonicalization", "upstream_anchor_sha256",
        "overlay_policy_sha256", "divergence_ledger_sha256",
        "compatibility_sha256", "lifecycle_sha256", "external_mappings_sha256",
        "evidence_catalog_sha256", "handoff_sha256", "kit_sha256",
        "signature_state", "authenticity_claimed",
    }, "$.integrity")
    if integrity["digest_algorithm"] != "sha256" or integrity["canonicalization"] != "sorted_ascii_no_floats_v1":
        raise ForkKitError("integrity_profile_invalid", "$.integrity")
    expected_digests = {
        "upstream_anchor_sha256": digest(anchor),
        "overlay_policy_sha256": digest(root["overlay_policy"]),
        "divergence_ledger_sha256": ledger["ledger_sha256"],
        "compatibility_sha256": digest(compatibility),
        "lifecycle_sha256": digest(lifecycle),
        "external_mappings_sha256": digest(mappings),
        "evidence_catalog_sha256": digest(evidence_catalog),
        "handoff_sha256": handoff["proposal_sha256"],
    }
    for field, expected in expected_digests.items():
        if integrity[field] != expected:
            raise ForkKitError("integrity_digest_mismatch", f"$.integrity.{field}")
    if integrity["signature_state"] not in {"not_configured", "unknown"}:
        raise ForkKitError("signature_state_invalid", "$.integrity.signature_state")
    _false(integrity["authenticity_claimed"], "authenticity_claim_forbidden", "$.integrity.authenticity_claimed")
    expected_kit = digest({**root, "integrity": _without(integrity, "kit_sha256")})
    if integrity["kit_sha256"] != expected_kit:
        raise ForkKitError("kit_digest_mismatch", "$.integrity.kit_sha256")
    _scan_unsafe(root)
    if document != original:
        raise ForkKitError("input_mutated")
    return root


def _root_path(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise ForkKitError("stage_path_invalid", str(path))
    lexical = Path(os.path.abspath(path))
    try:
        named = lexical.lstat()
        resolved = lexical.resolve(strict=True)
    except OSError as exc:
        raise ForkKitError("stage_unavailable", str(path)) from exc
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode) or resolved != lexical:
        raise ForkKitError("stage_alias_forbidden", str(path))
    return lexical


def _repo_root_path(value: str | Path) -> Path:
    try:
        return _root_path(value)
    except ForkKitError as exc:
        raise ForkKitError("repo_root_invalid", str(value)) from exc


def _relative_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ForkKitError("manifest_path_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        raise ForkKitError("manifest_path_invalid", value)
    return path


def _read_stage_regular(path: Path, root: Path, relative: str) -> bytes:
    try:
        path.relative_to(root)
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise ForkKitError("upstream_payload_unavailable", relative) from exc
    if (
        stat.S_ISLNK(named.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or named.st_nlink != 1
        or resolved != path
    ):
        raise ForkKitError("upstream_payload_alias_forbidden", relative)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ForkKitError("upstream_payload_unavailable", relative) from exc
    try:
        before = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > 8 * 1024 * 1024:
                raise ForkKitError("upstream_payload_oversize", relative)
            chunks.append(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ForkKitError("upstream_payload_changed", relative)
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _verify_runtime_semantic_sets(root: Path) -> None:
    relative = "assets/templates/standalone-runtime-contract-schema.json"
    raw = _read_stage_regular(root / relative, root, relative)
    schema = _decode_json(raw, relative)
    try:
        fork = schema["$defs"]["downstreamFork"]["properties"]
        overlays = set(fork["overlay_classes"]["items"]["enum"])
        authorities = set(fork["forbidden_duplicate_authorities"]["items"]["enum"])
        components = set(schema["$defs"]["conformanceVersions"]["required"])
    except (KeyError, TypeError) as exc:
        raise ForkKitError("upstream_runtime_contract_shape_invalid", relative) from exc
    if overlays != set(OVERLAY_CLASSES):
        raise ForkKitError("upstream_overlay_set_mismatch", relative)
    if authorities != set(FORBIDDEN_AUTHORITIES):
        raise ForkKitError("upstream_authority_set_mismatch", relative)
    if components != set(SHARED_COMPONENTS):
        raise ForkKitError("upstream_component_set_mismatch", relative)


def verify_upstream_stage(value: str | Path, anchor: Mapping[str, Any]) -> dict[str, Any]:
    root = _root_path(value)
    manifest_path = root / ".codex-plugin" / "release-manifest.json"
    manifest_raw = _read_stage_regular(
        manifest_path, root, ".codex-plugin/release-manifest.json",
    )
    if hashlib.sha256(manifest_raw).hexdigest() != UPSTREAM_MANIFEST_SHA256:
        raise ForkKitError("upstream_manifest_digest_mismatch")
    manifest = _decode_json(manifest_raw, ".codex-plugin/release-manifest.json")
    if set(manifest) != {
        "schema_version", "package", "files", "t001_inventory_sha256",
        "release_status",
    }:
        raise ForkKitError("upstream_manifest_shape_invalid")
    if manifest["schema_version"] != 1 or manifest["package"] != {"name": PACKAGE_NAME, "version": UPSTREAM_VERSION}:
        raise ForkKitError("upstream_manifest_identity_mismatch")
    release_status = manifest["release_status"]
    if not isinstance(release_status, dict) or not release_status or any(
        type(value) is not bool or value for value in release_status.values()
    ):
        raise ForkKitError("upstream_release_status_invalid")
    rows = manifest["files"]
    if not isinstance(rows, list) or len(rows) != UPSTREAM_MANIFEST_ROWS:
        raise ForkKitError("upstream_manifest_count_mismatch")
    actual_rows: list[dict[str, Any]] = []
    expected_paths: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "size"}:
            raise ForkKitError("upstream_manifest_row_invalid", f"$.files[{index}]")
        relative = _relative_path(row["path"])
        expected_paths.add(relative.as_posix())
        file_path = root.joinpath(*relative.parts)
        raw = _read_stage_regular(file_path, root, relative.as_posix())
        actual = {"path": relative.as_posix(), "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        if row != actual:
            raise ForkKitError("upstream_payload_mismatch", relative.as_posix())
        actual_rows.append(actual)
    physical: list[str] = []
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            path = Path(directory) / name
            if path.is_symlink():
                raise ForkKitError("upstream_tree_alias_forbidden", str(path.relative_to(root)))
        for name in files:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                raise ForkKitError("upstream_tree_alias_forbidden", str(path.relative_to(root)))
            physical.append(path.relative_to(root).as_posix())
    expected_physical = expected_paths | {".codex-plugin/release-manifest.json"}
    if set(physical) != expected_physical or len(physical) != UPSTREAM_PHYSICAL_FILES:
        raise ForkKitError("upstream_physical_inventory_mismatch")
    tree_sha256 = hashlib.sha256(canonical_bytes(actual_rows)).hexdigest()
    if tree_sha256 != UPSTREAM_TREE_SHA256:
        raise ForkKitError("upstream_tree_digest_mismatch")
    _verify_runtime_semantic_sets(root)
    if anchor != {
        "package_name": PACKAGE_NAME, "version": UPSTREAM_VERSION,
        "release_manifest_sha256": "sha256:" + UPSTREAM_MANIFEST_SHA256,
        "source_tree_sha256": "sha256:" + UPSTREAM_TREE_SHA256,
        "manifest_payload_rows": UPSTREAM_MANIFEST_ROWS,
        "physical_files": UPSTREAM_PHYSICAL_FILES,
    }:
        raise ForkKitError("upstream_anchor_mismatch")
    return {"manifest_payload_rows": len(rows), "physical_files": len(physical), "tree_sha256": "sha256:" + tree_sha256}


def verify_evidence_catalog(repo_root: str | Path, catalog: Mapping[str, Any]) -> int:
    root = _repo_root_path(repo_root)
    for index, row in enumerate(catalog["sources"]):
        relative = _relative_path(row["path"])
        raw = _read_stage_regular(root.joinpath(*relative.parts), root, relative.as_posix())
        if "sha256:" + hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ForkKitError("evidence_digest_mismatch", f"$.evidence_catalog.sources[{index}]")
    return len(catalog["sources"])


def run(kit: Mapping[str, Any], upstream_stage: str | Path, repo_root: str | Path) -> dict[str, Any]:
    validated = validate_kit(kit)
    stage = verify_upstream_stage(upstream_stage, validated["upstream_anchor"])
    evidence_count = verify_evidence_catalog(repo_root, validated["evidence_catalog"])
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": RECEIPT_TYPE,
        "status": "pass",
        "proof_boundary": "static_local_non_authoritative",
        "kit_id": validated["kit_id"],
        "kit_sha256": validated["integrity"]["kit_sha256"],
        "upstream_release_manifest_sha256": validated["upstream_anchor"]["release_manifest_sha256"],
        "upstream_source_tree_sha256": stage["tree_sha256"],
        "manifest_payload_rows": stage["manifest_payload_rows"],
        "physical_files": stage["physical_files"],
        "evidence_sources_verified": evidence_count,
        "fork_created": False,
        "aol_admitted": False,
        "authority_granted": False,
        "execution_started": False,
        "provider_called": False,
        "network_used": False,
        "filesystem_mutated": False,
        "board_mutated": False,
        "policy_mutated": False,
        "broker_write_authority": False,
        "assurance_claimed": False,
        "economics_claimed": False,
        "home_now_truth_claimed": False,
        "joined_execution": False,
        "acceptance_granted": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kit", required=True)
    parser.add_argument("--upstream-stage", required=True)
    parser.add_argument("--repo-root", required=True)
    args = parser.parse_args(argv)
    try:
        receipt = run(load_json(args.kit), args.upstream_stage, args.repo_root)
    except ForkKitError as exc:
        error = {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": "standalone_downstream_fork_kit_error_v2",
            "status": "failed",
            "code": exc.code,
            "path": exc.path,
            "authority_granted": False,
            "execution_started": False,
            "provider_called": False,
            "network_used": False,
            "filesystem_mutated": False,
            "aol_admitted": False,
            "acceptance_granted": False,
        }
        print(canonical_bytes(error).decode("ascii"))
        return 2
    print(canonical_bytes(receipt).decode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
