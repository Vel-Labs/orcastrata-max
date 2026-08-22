#!/usr/bin/env python3
"""Plan the next Codexmax validation action without executing it."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
HEX = set("0123456789abcdef")
ROLES = {"worker", "tester", "documenter", "auditor", "owner"}


class EfficientValidationError(ValueError):
    """Stable invalid-input failure."""


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EfficientValidationError(f"{field}_must_be_object")
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise EfficientValidationError(f"{field}_must_be_boolean")
    return value


def _enum(value: Any, field: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise EfficientValidationError(f"{field}_invalid")
    return value


def _revision(value: Any, field: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or len(value) != 64 or set(value) - HEX:
        raise EfficientValidationError(f"{field}_must_be_sha256")
    return value


def _run_count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EfficientValidationError(
            "full_validation.run_count_for_revision_must_be_nonnegative_integer"
        )
    return value


def plan(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the next validation and advisory actions for one source revision."""

    if payload.get("schema_version") != SCHEMA_VERSION:
        raise EfficientValidationError("schema_version_must_equal_1")

    actor = _mapping(payload.get("actor"), "actor")
    change = _mapping(payload.get("change"), "change")
    evidence = _mapping(payload.get("evidence"), "evidence")
    focused = _mapping(payload.get("focused_validation"), "focused_validation")
    review = _mapping(payload.get("parent_review"), "parent_review")
    freeze = _mapping(payload.get("source_freeze"), "source_freeze")
    full = _mapping(payload.get("full_validation"), "full_validation")
    artifact = _mapping(payload.get("artifact_validation"), "artifact_validation")
    advisory = _mapping(payload.get("external_advisory"), "external_advisory")

    actor_role = _enum(actor.get("role"), "actor.role", ROLES)
    change_class = _enum(change.get("class"), "change.class", {"source", "artifact_only"})
    current_revision = _revision(change.get("source_revision"), "change.source_revision")
    acceptance_ready = _boolean(
        evidence.get("acceptance_matrix_ready"), "evidence.acceptance_matrix_ready"
    )
    durable_ready = _boolean(
        evidence.get("durable_receipt_ready"), "evidence.durable_receipt_ready"
    )

    focused_status = _enum(
        focused.get("status"), "focused_validation.status", {"not_run", "pass", "fail"}
    )
    focused_revision = _revision(
        focused.get("source_revision"), "focused_validation.source_revision", optional=True
    )
    review_status = _enum(
        review.get("status"),
        "parent_review.status",
        {"not_run", "approved", "changes_requested"},
    )
    review_revision = _revision(
        review.get("source_revision"), "parent_review.source_revision", optional=True
    )
    frozen = _boolean(freeze.get("frozen"), "source_freeze.frozen")
    freeze_revision = _revision(
        freeze.get("source_revision"), "source_freeze.source_revision", optional=True
    )
    full_status = _enum(
        full.get("status"), "full_validation.status", {"not_run", "pass", "fail"}
    )
    full_revision = _revision(
        full.get("source_revision"), "full_validation.source_revision", optional=True
    )
    full_run_count = _run_count(full.get("run_count_for_revision"))
    full_executed_by = full.get("executed_by_role")
    if full_executed_by is not None:
        full_executed_by = _enum(
            full_executed_by, "full_validation.executed_by_role", ROLES
        )
    artifact_status = _enum(
        artifact.get("status"), "artifact_validation.status", {"not_run", "pass", "fail"}
    )

    requested = _boolean(advisory.get("requested"), "external_advisory.requested")
    gate_class = _enum(
        advisory.get("gate_class"),
        "external_advisory.gate_class",
        {"none", "routine", "major"},
    )
    advisory_authority = _boolean(
        advisory.get("authority_recorded"), "external_advisory.authority_recorded"
    )

    for status, revision, field in (
        (focused_status, focused_revision, "focused_validation"),
        (review_status, review_revision, "parent_review"),
        (full_status, full_revision, "full_validation"),
    ):
        if status == "not_run" and revision is not None:
            raise EfficientValidationError(f"{field}.source_revision_requires_result")
        if status != "not_run" and revision is None:
            raise EfficientValidationError(f"{field}.source_revision_required")
    if frozen != (freeze_revision is not None):
        raise EfficientValidationError("source_freeze_binding_invalid")
    if (full_status == "not_run") != (full_run_count == 0):
        raise EfficientValidationError("full_validation.run_count_status_mismatch")
    if (full_status == "not_run") != (full_executed_by is None):
        raise EfficientValidationError("full_validation.executor_status_mismatch")
    if not requested and gate_class != "none":
        raise EfficientValidationError("external_advisory.gate_class_requires_request")
    if requested and gate_class == "none":
        raise EfficientValidationError("external_advisory.request_requires_gate_class")

    focused_matches = focused_revision == current_revision
    review_matches = review_revision == current_revision
    freeze_matches = freeze_revision == current_revision
    full_revision_matches = full_revision == current_revision
    full_matches = full_revision_matches and full_executed_by == "owner"
    source_ladder_ready = (
        focused_matches
        and focused_status == "pass"
        and review_matches
        and review_status == "approved"
        and freeze_matches
        and frozen
    )
    warnings: list[str] = []
    if full_revision_matches and full_executed_by != "owner":
        warnings.append("non_owner_full_validation_ignored")
    if full_matches and full_run_count > 1:
        warnings.append("redundant_full_validation_for_same_revision")
    for matches, revision, field in (
        (focused_matches, focused_revision, "stale_focused_validation_ignored"),
        (review_matches, review_revision, "stale_parent_review_ignored"),
        (freeze_matches, freeze_revision, "stale_source_freeze_ignored"),
        (full_revision_matches, full_revision, "stale_full_validation_ignored"),
    ):
        if revision is not None and not matches:
            warnings.append(field)

    if not acceptance_ready:
        action = "define_acceptance_matrix"
    elif not durable_ready:
        action = "materialize_durable_receipt"
    elif (
        source_ladder_ready
        and full_matches
        and full_status == "pass"
        and change_class == "artifact_only"
    ):
        if artifact_status == "fail":
            action = "repair_artifact_failure"
        elif artifact_status != "pass":
            action = "run_artifact_validation"
        else:
            action = "candidate_closeout"
    elif focused_matches and focused_status == "fail":
        action = "repair_focused_failure"
    elif not focused_matches or focused_status != "pass":
        action = "run_focused_validation"
    elif review_matches and review_status == "changes_requested":
        action = "parent_revision_required"
    elif not review_matches or review_status != "approved":
        action = "parent_diff_review"
    elif not freeze_matches or not frozen:
        action = "freeze_source"
    elif full_matches and full_status == "fail":
        action = "repair_full_failure"
    elif not full_matches or full_status != "pass":
        action = "run_full_validation"
    elif change_class == "artifact_only" and artifact_status == "fail":
        action = "repair_artifact_failure"
    elif change_class == "artifact_only" and artifact_status != "pass":
        action = "run_artifact_validation"
    else:
        action = "candidate_closeout"

    if actor_role != "owner":
        if action == "parent_diff_review":
            action = "handoff_to_owner_for_review"
        elif action == "freeze_source":
            action = "handoff_to_owner_for_source_freeze"
        elif action == "run_full_validation":
            action = "handoff_to_owner_for_full_validation"
        elif action == "candidate_closeout":
            action = "handoff_to_owner_for_acceptance"

    if not requested:
        advisory_action = "not_requested"
    elif gate_class == "routine":
        advisory_action = "skip_routine_advisory"
    elif not advisory_authority:
        advisory_action = "request_advisory_authority"
    else:
        advisory_action = "major_advisory_allowed"

    return {
        "schema_version": SCHEMA_VERSION,
        "actor_role": actor_role,
        "validation_action": action,
        "external_advisory_action": advisory_action,
        "full_suite_authorized": action == "run_full_validation",
        "full_suite_owner": "owner",
        "candidate_ready_for_parent": action == "candidate_closeout",
        "source_revision": current_revision,
        "warnings": warnings,
        "board_mutated": False,
        "commands_executed": False,
        "acceptance_claimed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
        result = plan(_mapping(payload, "root"))
    except (OSError, json.JSONDecodeError, EfficientValidationError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"ok": True, "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
