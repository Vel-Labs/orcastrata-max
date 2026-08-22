#!/usr/bin/env python3
"""Self-contained provider-input compatibility gate for packaged runtimes.

This module is the canonical runtime implementation shared by repository
validation and isolated plugin route resolution. It performs no I/O.
"""

from __future__ import annotations

import re


SOURCE_ACCESS_VALUES = {
    "local_filesystem", "embedded_only", "connector_resource", "mixed",
    "none", "unknown", "unverified",
}
INPUT_DELIVERY_VALUES = {
    "paths_only", "embedded_fact_pack", "connector_references", "mixed",
    "none", "unknown", "unverified",
}
COMMAND_EXECUTABLE_VALUES = {"yes", "no", "unknown"}
COMPATIBILITY_DECISION_VALUES = {
    "compatible", "incompatible", "not_required", "unknown",
}
FACT_REPRESENTATION_VALUES = {"verbatim", "normalized"}
OMISSION_REASON_VALUES = {"unavailable", "not_supplied", "excluded", "unknown"}
DEMONSTRATED_SOURCE_ACCESS = {
    "local_filesystem", "embedded_only", "connector_resource",
}
SUPPORTED_FACT_PACK_SCHEMA_VERSIONS = {1}
MAX_EMBEDDED_FACT_CHARS = 4000
STABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-fA-F]{64}$")


def _is_stable_id(value: object) -> bool:
    return isinstance(value, str) and STABLE_ID_PATTERN.fullmatch(value) is not None


def _error_value(value: object) -> str:
    return value if isinstance(value, str) else f"<{type(value).__name__}>"


def _is_enum(value: object, allowed: set[str]) -> bool:
    return isinstance(value, str) and value in allowed


def _named_source_category_error(categories: object) -> str | None:
    if not isinstance(categories, list):
        return "named_source_categories_invalid"
    seen: set[str] = set()
    for index, category in enumerate(categories):
        if not isinstance(category, dict):
            return f"named_source_category_invalid:{index}"
        category_id = category.get("category_id")
        if not _is_stable_id(category_id):
            return f"named_source_category_id_invalid:{index}"
        if category_id in seen:
            return f"named_source_category_duplicate:{category_id}"
        seen.add(category_id)
        if not isinstance(category.get("source_label"), str) or not category[
            "source_label"
        ].strip():
            return f"named_source_category_label_invalid:{category_id}"
        if not isinstance(category.get("required"), bool):
            return f"named_source_category_required_invalid:{category_id}"
        if "access_mode" in category:
            mode = category["access_mode"]
            if not isinstance(mode, str) or mode not in SOURCE_ACCESS_VALUES or mode == "mixed":
                return f"invalid_category_access_mode:{category_id}:{mode}"
        if "input_delivery" in category:
            mode = category["input_delivery"]
            if (
                not isinstance(mode, str)
                or mode not in INPUT_DELIVERY_VALUES
                or mode == "mixed"
            ):
                return f"invalid_category_input_delivery:{category_id}:{mode}"
    return None


def _embedded_fact_pack_error(pack: object, categories: list[dict]) -> str | None:
    if not isinstance(pack, dict):
        return "embedded_fact_pack_missing"
    schema_version = pack.get("schema_version")
    if (
        type(schema_version) is not int
        or schema_version not in SUPPORTED_FACT_PACK_SCHEMA_VERSIONS
    ):
        return "embedded_fact_pack_schema_version_unsupported"
    if not _is_stable_id(pack.get("pack_id")):
        return "embedded_fact_pack_id_invalid"
    if "facts" not in pack or not isinstance(pack["facts"], list):
        return "embedded_fact_pack_facts_invalid"
    if "omissions" not in pack or not isinstance(pack["omissions"], list):
        return "embedded_fact_pack_omissions_invalid"

    category_rows = {category["category_id"]: category for category in categories}
    required = {
        category_id
        for category_id, category in category_rows.items()
        if category["required"] is True
    }
    omitted: set[str] = set()
    for index, omission in enumerate(pack["omissions"]):
        if not isinstance(omission, dict):
            return f"embedded_omission_invalid:{index}"
        category_id = omission.get("category_id")
        if not _is_stable_id(category_id):
            return f"embedded_omission_category_invalid:{index}"
        if category_id not in category_rows:
            return f"embedded_omission_category_unknown:{category_id}"
        if category_id in omitted:
            return f"embedded_omission_category_duplicate:{category_id}"
        omitted.add(category_id)
        if not isinstance(omission.get("source_label"), str) or not omission[
            "source_label"
        ].strip():
            return f"embedded_omission_source_label_invalid:{category_id}"
        if omission["source_label"] != category_rows[category_id]["source_label"]:
            return f"embedded_omission_source_label_mismatch:{category_id}"
        if not _is_enum(omission.get("reason"), OMISSION_REASON_VALUES):
            return f"embedded_omission_reason_invalid:{category_id}"

    omitted_required = sorted(required & omitted)
    if omitted_required:
        return f"required_category_omitted:{omitted_required[0]}"

    delivered: set[str] = set()
    claim_ids: set[str] = set()
    for index, fact in enumerate(pack["facts"]):
        if not isinstance(fact, dict):
            return f"embedded_fact_invalid:{index}"
        claim_id = fact.get("claim_id")
        if not _is_stable_id(claim_id):
            return f"embedded_fact_claim_id_invalid:{index}"
        if claim_id in claim_ids:
            return f"embedded_fact_claim_id_duplicate:{claim_id}"
        claim_ids.add(claim_id)
        category_id = fact.get("category_id")
        if not _is_stable_id(category_id):
            return f"embedded_fact_category_invalid:{claim_id}"
        if category_id not in category_rows:
            return f"embedded_fact_category_unknown:{claim_id}:{category_id}"
        delivered.add(category_id)
        if not _is_enum(fact.get("representation"), FACT_REPRESENTATION_VALUES):
            return f"embedded_fact_representation_invalid:{claim_id}"
        fact_text = fact.get("fact")
        if not isinstance(fact_text, str) or not fact_text.strip():
            return f"embedded_fact_text_invalid:{claim_id}"
        if len(fact_text) > MAX_EMBEDDED_FACT_CHARS:
            return f"embedded_fact_text_too_long:{claim_id}"
        if not isinstance(fact.get("source_label"), str) or not fact[
            "source_label"
        ].strip():
            return f"embedded_fact_source_label_invalid:{claim_id}"
        if fact["source_label"] != category_rows[category_id]["source_label"]:
            return f"embedded_fact_source_label_mismatch:{claim_id}"
        content_hash = fact.get("content_hash")
        if content_hash != "unknown" and (
            not isinstance(content_hash, str)
            or SHA256_PATTERN.fullmatch(content_hash) is None
        ):
            return f"embedded_fact_content_hash_invalid:{claim_id}"
        uncertainty = fact.get("uncertainty")
        if not isinstance(uncertainty, str) or not uncertainty.strip():
            return f"embedded_fact_uncertainty_invalid:{claim_id}"

    delivered_and_omitted = sorted(delivered & omitted)
    if delivered_and_omitted:
        return f"embedded_category_delivered_and_omitted:{delivered_and_omitted[0]}"
    missing_required = sorted(required - delivered)
    if missing_required:
        return f"required_category_not_delivered:{missing_required[0]}"
    missing = sorted(set(category_rows) - delivered - omitted)
    if missing:
        return f"named_category_not_delivered_or_omitted:{missing[0]}"
    return None


def provider_input_compatibility_decision(provider_input: dict) -> tuple[bool, str]:
    if not isinstance(provider_input, dict):
        return False, "provider_input_invalid"

    source_required_value = provider_input.get("source_backed_claims_required", False)
    commands_required_value = provider_input.get("commands_required", False)
    if not isinstance(source_required_value, bool):
        return False, "source_backed_claims_required_invalid"
    if not isinstance(commands_required_value, bool):
        return False, "commands_required_invalid"
    source_required = source_required_value
    commands_required = commands_required_value
    access = provider_input.get("source_access", "unknown")
    delivery = provider_input.get("input_delivery", "unknown")
    commands_executable = provider_input.get("commands_executable", "unknown")

    if not _is_enum(access, SOURCE_ACCESS_VALUES):
        return False, f"invalid_source_access:{_error_value(access)}"
    if not _is_enum(delivery, INPUT_DELIVERY_VALUES):
        return False, f"invalid_input_delivery:{_error_value(delivery)}"
    if not _is_enum(commands_executable, COMMAND_EXECUTABLE_VALUES):
        return False, f"invalid_commands_executable:{_error_value(commands_executable)}"
    if "compatibility_gate" in provider_input:
        gate = provider_input["compatibility_gate"]
        if not isinstance(gate, dict):
            return False, "compatibility_gate_invalid"
        declared_decision = gate.get("decision", "unknown")
        if not _is_enum(declared_decision, COMPATIBILITY_DECISION_VALUES):
            return False, (
                "invalid_compatibility_gate_decision:"
                f"{_error_value(declared_decision)}"
            )
        declared_reason = gate.get("reason", "unknown")
        if not isinstance(declared_reason, str) or not declared_reason.strip():
            return False, "invalid_compatibility_gate_reason"

    required_access = provider_input.get("required_source_access", [])
    if not isinstance(required_access, list):
        return False, "required_source_access_invalid"
    seen_required_access: set[str] = set()
    for required_mode in required_access:
        if not _is_enum(required_mode, SOURCE_ACCESS_VALUES):
            return False, (
                "invalid_required_source_access:"
                f"{_error_value(required_mode)}"
            )
        if required_mode in seen_required_access:
            return False, "required_source_access_duplicate"
        seen_required_access.add(required_mode)

    categories = provider_input.get("named_source_categories", [])
    category_error = _named_source_category_error(categories)
    if category_error:
        return False, category_error
    if source_required:
        if access in {"none", "unknown", "unverified"}:
            return False, "required_source_access_unavailable"
        if delivery in {"none", "unknown", "unverified"}:
            return False, "required_input_delivery_unavailable"
        if delivery == "paths_only" and access not in {"local_filesystem", "mixed"}:
            return False, "paths_only_requires_local_filesystem"
        if delivery == "connector_references" and access not in {
            "connector_resource",
            "mixed",
        }:
            return False, "connector_references_require_connector_access"
        if provider_input.get("read_receipt_required") is not True:
            return False, "read_receipt_required_not_true"
        if not required_access:
            return False, "required_source_access_missing"
        for required_mode in required_access:
            if required_mode in {"none", "unknown", "unverified"}:
                return False, f"required_source_access_not_demonstrable:{required_mode}"
        if not categories:
            return False, "named_source_categories_missing"

        if access == "mixed" or delivery == "mixed":
            if any(
                not category.get("access_mode")
                or not category.get("input_delivery")
                for category in categories
            ):
                return False, "mixed_requires_per_category_capability"

        if access == "mixed":
            demonstrated_access = {
                category.get("access_mode")
                for category in categories
                if category.get("required") is True
                and category.get("access_mode") in DEMONSTRATED_SOURCE_ACCESS
            }
        else:
            demonstrated_access = {access}
        if access == "mixed" and len(demonstrated_access) < 2:
            return False, "mixed_source_access_requires_multiple_modes"
        if delivery == "mixed":
            demonstrated_delivery = {
                category.get("input_delivery")
                for category in categories
                if category.get("required") is True
                and category.get("input_delivery")
                in {"paths_only", "embedded_fact_pack", "connector_references"}
            }
            if len(demonstrated_delivery) < 2:
                return False, "mixed_input_delivery_requires_multiple_modes"
        for required_mode in required_access:
            if required_mode == "mixed":
                if access != "mixed" or len(demonstrated_access) < 2:
                    return False, "required_source_access_mismatch:mixed"
            elif required_mode not in demonstrated_access:
                return False, f"required_source_access_mismatch:{required_mode}"

        for category in categories:
            category_id = category["category_id"]
            category_access = category.get("access_mode", access)
            category_delivery = category.get("input_delivery", delivery)
            if access != "mixed" and category_access != access:
                return False, f"category_access_mode_mismatch:{category_id}"
            if delivery != "mixed" and category_delivery != delivery:
                return False, f"category_input_delivery_mismatch:{category_id}"
            if category.get("required") is True and category_access not in (
                DEMONSTRATED_SOURCE_ACCESS
            ):
                return False, f"required_category_access_unavailable:{category_id}"
            if category_delivery == "paths_only" and category_access != "local_filesystem":
                return False, f"category_paths_require_local_access:{category_id}"
            if (
                category_delivery == "connector_references"
                and category_access != "connector_resource"
            ):
                return False, f"category_connector_requires_connector_access:{category_id}"
            if (
                category_delivery == "embedded_fact_pack"
                and category_access != "embedded_only"
            ):
                return False, f"category_embedded_requires_embedded_access:{category_id}"

    elif provider_input.get("read_receipt_required") is not True:
        return False, "read_receipt_required_not_true"

    embedded_categories = [
        category
        for category in categories
        if category.get("input_delivery", delivery) == "embedded_fact_pack"
    ]
    if embedded_categories:
        pack_error = _embedded_fact_pack_error(
            provider_input.get("embedded_fact_pack"), embedded_categories
        )
        if pack_error:
            return False, pack_error

    if commands_required and commands_executable != "yes":
        return False, "required_commands_not_executable"
    if not source_required and not commands_required:
        return True, "not_required"
    return True, "compatible"


def provider_input_compatibility_gate_errors(
    provider_input: dict, *, require_declared_gate: bool = False
) -> list[str]:
    compatible, computed_reason = provider_input_compatibility_decision(provider_input)
    computed_decision = (
        "not_required"
        if compatible and computed_reason == "not_required"
        else "compatible"
        if compatible
        else "incompatible"
    )
    if not isinstance(provider_input, dict):
        return ["provider_input_invalid"]
    gate = provider_input.get("compatibility_gate")
    if not isinstance(gate, dict):
        return ["compatibility_gate_missing"] if require_declared_gate else []

    errors: list[str] = []
    declared_decision = gate.get("decision", "unknown")
    declared_reason = gate.get("reason", "unknown")
    if (
        not isinstance(declared_decision, str)
        or declared_decision not in COMPATIBILITY_DECISION_VALUES
    ):
        errors.append(f"invalid_compatibility_gate_decision:{declared_decision}")
    if not isinstance(declared_reason, str) or not declared_reason.strip():
        errors.append("invalid_compatibility_gate_reason")

    blank_source_free_template = (
        not require_declared_gate
        and provider_input.get("source_backed_claims_required", False) is False
        and provider_input.get("commands_required", False) is False
        and declared_decision == "unknown"
        and declared_reason == "unknown"
    )
    if blank_source_free_template:
        return errors
    if declared_decision != computed_decision:
        errors.append(
            "compatibility_gate_decision_mismatch:"
            f"{declared_decision}:{computed_decision}"
        )
    if declared_reason != computed_reason:
        errors.append(
            f"compatibility_gate_reason_mismatch:{declared_reason}:{computed_reason}"
        )
    if require_declared_gate and computed_decision == "incompatible":
        errors.append(f"compatibility_gate_blocks_dispatch:{computed_reason}")
    return errors

