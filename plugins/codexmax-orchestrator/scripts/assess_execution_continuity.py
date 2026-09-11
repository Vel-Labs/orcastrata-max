#!/usr/bin/env python3
"""Deterministically classify the next Codexmax execution-continuity action."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1


class ContinuityError(ValueError):
    """Stable invalid-input failure."""


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContinuityError(f"{field}_must_be_object")
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ContinuityError(f"{field}_must_be_boolean")
    return value


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContinuityError(f"{field}_must_be_nonnegative_integer")
    return value


def _optional_nonnegative_int(value: Any, field: str) -> int | None:
    if value is None:
        return None
    return _nonnegative_int(value, field)


def _optional_boolean(value: Any, field: str, default: bool = False) -> bool:
    if value is None:
        return default
    return _boolean(value, field)


def assess(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic action without mutating board or runtime state."""

    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ContinuityError("schema_version_must_equal_1")

    authority = _mapping(payload.get("authority"), "authority")
    progress = _mapping(payload.get("progress"), "progress")
    usage = _mapping(payload.get("usage"), "usage")
    signals = _mapping(payload.get("signals"), "signals")
    options = _mapping(payload.get("optimization_options"), "optimization_options")
    decision = _mapping(payload.get("decision_context", {}), "decision_context")

    expansion_fields = (
        "scope_expansion",
        "action_expansion",
        "billing_expansion",
        "cost_authority_expansion",
        "reserved_human_decision",
    )
    expansions = [field for field in expansion_fields if _boolean(authority.get(field), field)]
    operator_stop = _boolean(authority.get("operator_stop"), "operator_stop")

    observed = _optional_nonnegative_int(usage.get("observed_tokens"), "observed_tokens")
    forecast = _optional_nonnegative_int(usage.get("token_forecast"), "token_forecast")
    explicit_cap = _optional_nonnegative_int(usage.get("explicit_token_cap"), "explicit_token_cap")
    if explicit_cap == 0:
        raise ContinuityError("explicit_token_cap_must_be_positive_or_null")

    satisfied = _nonnegative_int(progress.get("oracle_satisfied"), "oracle_satisfied")
    previous = _nonnegative_int(progress.get("oracle_previously_satisfied"), "oracle_previously_satisfied")
    total = _nonnegative_int(progress.get("oracle_total"), "oracle_total")
    if satisfied > total or previous > total:
        raise ContinuityError("oracle_counts_exceed_total")
    no_improvement = _nonnegative_int(
        progress.get("consecutive_no_improvement_attempts"),
        "consecutive_no_improvement_attempts",
    )
    no_improvement_window = _nonnegative_int(
        progress.get("no_improvement_window"),
        "no_improvement_window",
    )
    if no_improvement_window == 0:
        raise ContinuityError("no_improvement_window_must_be_positive")

    context_pressure = _boolean(signals.get("context_pressure"), "context_pressure")
    validation_failed = _boolean(signals.get("validation_failed"), "validation_failed")
    candidate_ready = _boolean(signals.get("candidate_ready"), "candidate_ready")
    external_exhaustion = _boolean(
        signals.get("useful_local_work_exhausted"),
        "useful_local_work_exhausted",
    )
    failed_attempt = _boolean(signals.get("failed_attempt"), "failed_attempt")
    delegation_only = _optional_boolean(
        signals.get("delegation_only_candidate"),
        "delegation_only_candidate",
    )
    execution_unknown_signal = _optional_boolean(
        signals.get("execution_unknown"),
        "execution_unknown",
    )
    integration_complete = _optional_boolean(
        signals.get("integration_complete"),
        "integration_complete",
        True,
    )
    task_transition_complete = _optional_boolean(
        signals.get("task_transition_complete"),
        "task_transition_complete",
        True,
    )

    available = {
        name: _boolean(options.get(name), name)
        for name in ("revise_packet", "split_work", "reroute", "repair")
    }

    decision_owner = decision.get("decision_owner", "pm")
    if decision_owner not in {"pm", "human"}:
        raise ContinuityError("decision_owner_must_be_pm_or_human")
    execution_unknown_decision = _optional_boolean(
        decision.get("execution_unknown"),
        "execution_unknown",
    )
    escalation_class = decision.get("escalation_class", "none")
    allowed_escalation_classes = {
        "none",
        "technical_implementation",
        "human_fact",
        "material_product_decision",
        "external_action",
        "credential_action",
        "material_oracle_change",
        "authority_expansion",
        "terminal_platform_error",
        "architecture_exhausted",
    }
    if escalation_class not in allowed_escalation_classes:
        raise ContinuityError("escalation_class_invalid")
    safe_successor = decision.get("safe_successor")
    if safe_successor is not None and safe_successor not in {
        "continue_current",
        "continue_rollover",
        "revise_packet",
        "split_work",
        "reroute",
        "repair",
    }:
        raise ContinuityError("safe_successor_invalid")

    human_fact_required = _optional_boolean(
        decision.get("human_fact_required"),
        "human_fact_required",
    )
    product_decision_required = _optional_boolean(
        decision.get("material_product_decision_required"),
        "material_product_decision_required",
    )
    external_action_required = _optional_boolean(
        decision.get("external_action_required"),
        "external_action_required",
    )
    credential_action_required = _optional_boolean(
        decision.get("credential_action_required"),
        "credential_action_required",
    )
    oracle_change_required = _optional_boolean(
        decision.get("material_oracle_change_required"),
        "material_oracle_change_required",
    )
    authority_expansion_required = _optional_boolean(
        decision.get("authority_expansion_required"),
        "authority_expansion_required",
    )
    terminal_platform_error = _optional_boolean(
        decision.get("terminal_platform_error"),
        "terminal_platform_error",
    )
    architecture_exhausted = _optional_boolean(
        decision.get("architecture_path_exhausted"),
        "architecture_path_exhausted",
    )
    redesign_exhausted = _optional_boolean(
        decision.get("redesign_exhausted"),
        "redesign_exhausted",
    )
    task_split_exhausted = _optional_boolean(
        decision.get("task_split_exhausted"),
        "task_split_exhausted",
    )
    repair_budget_exhausted = _optional_boolean(
        decision.get("repair_budget_exhausted"),
        "repair_budget_exhausted",
    )

    human_gate_reasons = []
    for required, reason in (
        (human_fact_required, "human_fact_required"),
        (product_decision_required, "material_product_decision_required"),
        (external_action_required, "external_action_required"),
        (credential_action_required, "credential_action_required"),
        (oracle_change_required, "material_oracle_change_required"),
        (authority_expansion_required, "authority_expansion_required"),
    ):
        if required:
            human_gate_reasons.append(reason)

    if decision_owner == "human" and not human_gate_reasons:
        raise ContinuityError("human_gate_must_be_consequential")
    if human_gate_reasons and safe_successor is not None:
        raise ContinuityError("human_gate_cannot_have_safe_pm_successor")
    if human_gate_reasons and decision_owner != "human":
        raise ContinuityError("consequential_human_gate_requires_human_owner")
    if safe_successor is not None and (terminal_platform_error or architecture_exhausted):
        raise ContinuityError("terminal_condition_cannot_have_safe_successor")
    if architecture_exhausted and not (redesign_exhausted and task_split_exhausted):
        raise ContinuityError("architecture_exhaustion_requires_redesign_and_task_split")

    reason_codes: list[str] = []
    action = "continue_current"
    decision_required = False
    stop_allowed = False

    if operator_stop:
        action = "request_authority"
        decision_required = True
        stop_allowed = True
        reason_codes.append("operator_stop")
    elif expansions:
        action = "request_authority"
        decision_required = True
        stop_allowed = True
        reason_codes.extend(expansions)
    elif explicit_cap is not None and observed is not None and observed >= explicit_cap:
        action = "explicit_cap_reached"
        decision_required = True
        stop_allowed = True
        reason_codes.append("operator_authored_token_cap_reached")
    elif human_gate_reasons:
        action = "waiting_external" if (
            human_fact_required or external_action_required or credential_action_required
        ) else "request_authority"
        decision_required = True
        stop_allowed = True
        reason_codes.extend(human_gate_reasons)
    elif terminal_platform_error:
        action = "waiting_external"
        stop_allowed = True
        reason_codes.append("terminal_platform_error")
    elif safe_successor is not None:
        action = safe_successor
        reason_codes.append("pm_owned_safe_successor_selected")
    elif external_exhaustion:
        action = "waiting_external"
        decision_required = True
        stop_allowed = True
        reason_codes.append("useful_authorized_local_work_exhausted")
    elif delegation_only or not integration_complete or not task_transition_complete:
        action = "repair"
        reason_codes.append("delegation_requires_parent_integration_and_transition")
    elif validation_failed:
        for candidate in ("repair", "revise_packet", "split_work", "reroute"):
            if available[candidate]:
                action = candidate
                reason_codes.append(f"validation_failed_{candidate}_selected")
                break
        else:
            action = "needs_parent_repair"
            stop_allowed = architecture_exhausted
            reason_codes.append(
                "architecture_paths_exhausted" if architecture_exhausted
                else "validation_failed_requires_pm_successor"
            )
    elif repair_budget_exhausted:
        for candidate in ("revise_packet", "split_work", "reroute"):
            if available[candidate]:
                action = candidate
                reason_codes.append("repair_budget_exhausted_strategy_changed")
                break
        else:
            action = "needs_parent_repair"
            stop_allowed = architecture_exhausted
            reason_codes.append(
                "architecture_paths_exhausted" if architecture_exhausted
                else "repair_budget_exhausted_requires_redesign_or_split"
            )
    elif execution_unknown_signal or execution_unknown_decision:
        action = "needs_parent_repair"
        stop_allowed = True
        reason_codes.append("execution_unknown")
    elif candidate_ready:
        action = "candidate_closeout"
        reason_codes.append("candidate_ready_for_parent_review")
    elif no_improvement >= no_improvement_window:
        for candidate in ("revise_packet", "split_work", "reroute", "repair"):
            if available[candidate]:
                action = candidate
                reason_codes.append("no_improvement_strategy_selected")
                break
        else:
            action = "needs_parent_repair"
            stop_allowed = architecture_exhausted
            reason_codes.append(
                "architecture_paths_exhausted" if architecture_exhausted
                else "no_improvement_requires_pm_successor"
            )
    elif failed_attempt:
        for candidate in ("revise_packet", "reroute", "split_work", "repair"):
            if available[candidate]:
                action = candidate
                reason_codes.append("failed_attempt_strategy_selected")
                break
        else:
            action = "needs_parent_repair"
            stop_allowed = architecture_exhausted
            reason_codes.append(
                "architecture_paths_exhausted" if architecture_exhausted
                else "failed_attempt_requires_pm_successor"
            )
    elif context_pressure:
        action = "continue_rollover"
        reason_codes.append("context_pressure")
    elif forecast is not None and observed is not None and observed >= forecast:
        action = "continue_current"
        reason_codes.append("soft_forecast_crossed_reforecast_required")
    elif satisfied > previous:
        action = "continue_current"
        reason_codes.append("oracle_progress")
    else:
        reason_codes.append("within_authority_and_controls")

    return {
        "schema_version": SCHEMA_VERSION,
        "action": action,
        "operator_decision_required": decision_required,
        "decision_owner": "human" if decision_required else "pm",
        "escalation_class": escalation_class,
        "safe_successor": safe_successor,
        "human_fact_required": human_fact_required,
        "material_product_decision_required": product_decision_required,
        "stop_allowed": stop_allowed,
        "reason_codes": reason_codes,
        "forecast_is_authority": False,
        "explicit_cap_is_authority": explicit_cap is not None,
        "board_mutated": False,
        "acceptance_claimed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
        result = assess(_mapping(payload, "root"))
    except (OSError, json.JSONDecodeError, ContinuityError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"ok": True, "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
