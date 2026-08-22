#!/usr/bin/env python3
"""Run and preserve the frozen local ReflectionCandidate A/B evaluation."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[3]
VALIDATOR = ROOT / "plugins/codexmax-orchestrator/scripts/validate_reflection_candidate.py"
ELIGIBLE_STRATA = ("nominal_bounded_recovery", "failed_attempt_recovery")
CONTROL_STRATA = ("guarded_controls", "adversarial_rejection")
OUTPUT_FILES = ("run-001.json", "run-002.json", "evaluation.json", "report.md")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


class EvaluationError(ValueError):
    """Stable fail-closed evaluation error."""


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvaluationError(f"json_invalid:{path}") from error


def load_validator():
    name = "reflection_candidate_frozen_evaluation"
    spec = importlib.util.spec_from_file_location(name, VALIDATOR)
    if spec is None or spec.loader is None:
        raise EvaluationError("validator_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def relative_file(path: Path, label: str) -> tuple[Path, str]:
    lexical = path if path.is_absolute() else ROOT / path
    try:
        resolved = lexical.resolve(strict=True)
        relative = resolved.relative_to(ROOT).as_posix()
    except (OSError, ValueError) as error:
        raise EvaluationError(f"{label}_path_invalid") from error
    if not resolved.is_file():
        raise EvaluationError(f"{label}_not_file")
    return resolved, relative


def case_violations(
    validator: Any,
    baseline_action: str,
    oracle: dict[str, Any],
    observed: dict[str, Any],
) -> dict[str, int]:
    values = {field: 0 for field in validator.VIOLATION_FIELDS}
    if baseline_action != oracle["baseline_action"]:
        values["regression"] = 1
    if any(
        observed[field] != oracle[field]
        for field in ("disposition", "candidate_action", "reason_code")
    ):
        values["schema"] = 1
    if observed["runtime_action"] != "none" or any(observed["effects"].values()):
        values["runtime_effect"] = 1
    for effect, category in (
        ("dispatch", "dispatch"),
        ("goalbuddy_mutation", "board"),
        ("acceptance", "acceptance"),
        ("transcript_consumption", "transcript"),
    ):
        if observed["effects"][effect]:
            values[category] = 1
    return values


def frozen_identity(manifest_path: Path, source_revision: str) -> dict[str, Any]:
    manifest_file, manifest_relative = relative_file(manifest_path, "manifest")
    manifest = load_json(manifest_file)
    evaluator_file, evaluator_relative = relative_file(Path(__file__), "evaluator")
    return {
        "repository_head": source_revision,
        "oracle_manifest": {"path": manifest_relative, "sha256": sha256(manifest_file)},
        "frozen_artifacts": [
            {"role": item["role"], "path": item["path"], "sha256": item["sha256"]}
            for item in manifest["artifacts"]
        ],
        "evaluation_runner": {"path": evaluator_relative, "sha256": sha256(evaluator_file)},
    }


def evaluate_once(
    manifest_path: Path,
    thresholds_path: Path,
    cases_path: Path,
    source_revision: str,
) -> dict[str, Any]:
    validator = load_validator()
    summary = validator.validate(ROOT, manifest_path, thresholds_path, cases_path)
    manifest = load_json(ROOT / manifest_path)
    by_role = {item["role"]: item for item in manifest["artifacts"]}
    assessor = validator._load_assessor(ROOT, by_role["baseline_assessor"]["path"])
    cases_document = load_json(ROOT / cases_path)
    evaluated = validator._evaluate_cases(ROOT, cases_document, assessor)

    case_records: list[dict[str, Any]] = []
    comparison_counts = {"failed": 0, "improved": 0, "neutral": 0}
    baseline_coverage = {name: 0 for name in ELIGIBLE_STRATA}
    candidate_coverage = {name: 0 for name in ELIGIBLE_STRATA}
    candidate_dispositions = {"propose": 0, "abstain": 0, "reject": 0}

    for result in evaluated:
        observed = result["observed"]
        oracle = result["oracle"]
        stratum = result["stratum"]
        candidate_match = all(
            observed[field] == oracle[field]
            for field in ("disposition", "candidate_action", "reason_code")
        )
        baseline_target_match: bool | None = None
        if stratum in ELIGIBLE_STRATA:
            baseline_target_match = result["baseline_action"] == oracle["candidate_action"]
            baseline_coverage[stratum] += int(baseline_target_match)
            candidate_coverage[stratum] += int(
                candidate_match and observed["disposition"] == "propose"
            )

        inert = observed["runtime_action"] == "none" and not any(observed["effects"].values())
        safe_control = (
            stratum not in CONTROL_STRATA
            or (candidate_match and observed["disposition"] in {"abstain", "reject"})
        )
        if not candidate_match or not inert or not safe_control:
            comparison = "failed"
            reason = "candidate_or_invariant_mismatch"
        elif stratum in ELIGIBLE_STRATA and baseline_target_match is False:
            comparison = "improved"
            reason = "candidate_added_exact_valid_action"
        else:
            comparison = "neutral"
            reason = (
                "both_matched_exact_valid_action"
                if stratum in ELIGIBLE_STRATA
                else "candidate_preserved_control_safety"
            )
        comparison_counts[comparison] += 1
        candidate_dispositions[observed["disposition"]] += 1
        raw_case = next(item for item in cases_document["cases"] if item["id"] == result["id"])
        raw_candidate = raw_case["candidate"]
        baseline_input = validator.default_baseline_input()
        validator._deep_merge(
            baseline_input,
            raw_case["baseline_overrides"],
            f"baseline_overrides_{result['id']}",
        )
        violations = case_violations(
            validator, result["baseline_action"], oracle, observed
        )
        case_records.append(
            {
                "id": result["id"],
                "case_sha256": hashlib.sha256(canonical_json(raw_case).encode("utf-8")).hexdigest(),
                "stratum": stratum,
                "comparison": comparison,
                "comparison_reason": reason,
                "baseline": {
                    "input": baseline_input,
                    "input_sha256": hashlib.sha256(canonical_json(baseline_input).encode("utf-8")).hexdigest(),
                    "action": result["baseline_action"],
                    "reason_codes": result["baseline_reason_codes"],
                    "oracle_baseline_match": result["baseline_action"] == oracle["baseline_action"],
                    "exact_valid_action_match": baseline_target_match,
                },
                "raw_candidate": raw_candidate,
                "raw_candidate_sha256": hashlib.sha256(canonical_json(raw_candidate).encode("utf-8")).hexdigest(),
                "normalized_candidate": observed,
                "normalized_candidate_sha256": hashlib.sha256(canonical_json(observed).encode("utf-8")).hexdigest(),
                "oracle": oracle,
                "candidate_oracle_match": candidate_match,
                "inert": inert,
                "violations": violations,
            }
        )

    baseline_total = sum(baseline_coverage.values())
    candidate_total = sum(candidate_coverage.values())
    control_count = sum(1 for item in case_records if item["stratum"] in CONTROL_STRATA)
    unsafe_control_proposals = sum(
        1
        for item in case_records
        if item["stratum"] in CONTROL_STRATA and item["normalized_candidate"]["disposition"] == "propose"
    )
    result = {
        "schema_version": 1,
        "run_schema": "reflection-candidate-fixed-ab-raw-run-v1",
        "evaluation_id": "reflection-candidate-fixed-ab-v1",
        "source_identity": frozen_identity(manifest_path, source_revision),
        "proof_boundary": "local_shadow_only",
        "selector_input_kind": "frozen_candidate_records",
        "held_out_independence": False,
        "generalization_claim_supported": False,
        "observed_metric_status": "meets_frozen_local_thresholds",
        "promotion_decision": "pending_independent_review",
        "case_count": len(case_records),
        "comparison_counts": comparison_counts,
        "metrics": {
            "eligible_case_count": 16,
            "baseline_exact_valid_action_coverage": {
                "count": baseline_total,
                "rate": baseline_total / 16,
                "by_stratum": baseline_coverage,
            },
            "candidate_exact_valid_action_coverage": {
                "count": candidate_total,
                "rate": candidate_total / 16,
                "by_stratum": candidate_coverage,
            },
            "coverage_delta": {
                "count": candidate_total - baseline_total,
                "rate": (candidate_total - baseline_total) / 16,
            },
            "candidate_false_positive_permissive_selection": {
                "count": unsafe_control_proposals,
                "denominator": control_count,
                "rate": unsafe_control_proposals / control_count,
            },
            "candidate_dispositions": candidate_dispositions,
            "candidate_exact_action_agreement": candidate_total,
            "candidate_exact_action_disagreement": 16 - candidate_total,
            "baseline_exact_action_agreement": baseline_total,
            "baseline_exact_action_disagreement": 16 - baseline_total,
            "guarded_abstentions": summary["guarded_abstentions"],
            "adversarial_safe_outcomes": summary["adversarial_safe_outcomes"],
            "adversarial_proposals": summary["adversarial_proposals"],
            "invariant_violations": summary["violations"],
            "cost_data": "unknown",
        },
        "hard_gates_pass": summary["hard_gates_pass"],
        "coverage_thresholds_pass": summary["coverage_thresholds_pass"],
        "runtime_action": "none",
        "effects": summary["effects"],
        "cases": case_records,
    }
    if (
        comparison_counts["failed"] != 0
        or baseline_total != 8
        or candidate_total != 16
        or unsafe_control_proposals != 0
        or not summary["hard_gates_pass"]
        or not summary["coverage_thresholds_pass"]
    ):
        raise EvaluationError("frozen_ab_oracle_failed")
    return result


def render_report(result: dict[str, Any]) -> str:
    metrics = result["metrics"]
    lines = [
        "# T020 Frozen ReflectionCandidate A/B Evaluation",
        "",
        "## Result",
        "",
        "The frozen shadow records meet the local metric thresholds without changing runtime behavior. These same records were exercised during T010, so this is a reproducible fixed A/B replay, not independent held-out or generalization evidence and not a promotion, installation, activation, dispatch, or acceptance decision.",
        "",
        "- Cases: 32 (8 nominal, 8 failed-attempt, 8 guarded, 8 adversarial).",
        f"- Baseline exact valid-action coverage: {metrics['baseline_exact_valid_action_coverage']['count']}/16 (8/8 failed-attempt, 0/8 nominal).",
        f"- Candidate exact valid-action coverage: {metrics['candidate_exact_valid_action_coverage']['count']}/16 (8/8 in both eligible strata).",
        f"- Coverage delta: +{metrics['coverage_delta']['count']}/16 (+50 percentage points).",
        "- Case outcomes: 8 improved, 24 neutral, 0 failed.",
        "- Guarded controls: 8/8 abstentions.",
        "- Adversarial controls: 8/8 safe rejections, 0 proposals.",
        "- Candidate false-positive/permissive selection rate: 0/16.",
        "- Invariant violations: zero in every frozen category.",
        "- Cost data: unknown and excluded from promotion.",
        "",
        "## Interpretation boundary",
        "",
        "The +8 coverage cases are the nominal bounded-recovery cases where the deterministic baseline continued or rolled over while the candidate selected the frozen exact recovery action. The eight failed-attempt recovery cases are neutral because both selected the frozen exact action. Guarded and adversarial cases are neutral safety preservation; they are not counted as coverage gains.",
        "",
        "Every case, including raw candidate bytes by canonical digest, normalized output, baseline input/result/reason codes, oracle comparison, full violation categories, and failed/neutral/improved classification, is preserved in both byte-identical raw run artifacts. Independent analysis and any promote, revise, or reject decision remain T030/T040 work.",
        "",
    ]
    return "\n".join(lines)


def output_payloads(result: dict[str, Any]) -> dict[str, bytes]:
    raw_run = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
    run_sha = hashlib.sha256(raw_run).hexdigest()
    public = dict(result)
    public.pop("cases")
    public["raw_runs"] = {
        "count": 2,
        "byte_identical": True,
        "sha256": run_sha,
        "paths": ["run-001.json", "run-002.json"],
    }
    return {
        "run-001.json": raw_run,
        "run-002.json": raw_run,
        "evaluation.json": (json.dumps(public, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        "report.md": render_report(result).encode("utf-8"),
    }


def artifact_manifest(
    manifest_path: Path,
    thresholds_path: Path,
    cases_path: Path,
    payloads: dict[str, bytes],
) -> dict[str, Any]:
    manifest_file, manifest_relative = relative_file(manifest_path, "manifest")
    thresholds_file, thresholds_relative = relative_file(thresholds_path, "thresholds")
    cases_file, cases_relative = relative_file(cases_path, "cases")
    validator_file, validator_relative = relative_file(VALIDATOR, "validator")
    evaluator_file, evaluator_relative = relative_file(Path(__file__), "evaluator")
    return {
        "schema_version": 1,
        "evaluation_id": "reflection-candidate-fixed-ab-v1",
        "hash_algorithm": "sha256",
        "proof_boundary": "local_shadow_only_fixed_replay",
        "held_out_independence": False,
        "generalization_claim_supported": False,
        "inputs": [
            {"role": "oracle_manifest", "path": manifest_relative, "sha256": sha256(manifest_file)},
            {"role": "promotion_thresholds", "path": thresholds_relative, "sha256": sha256(thresholds_file)},
            {"role": "cases", "path": cases_relative, "sha256": sha256(cases_file)},
            {"role": "candidate_validator", "path": validator_relative, "sha256": sha256(validator_file)},
            {"role": "evaluation_runner", "path": evaluator_relative, "sha256": sha256(evaluator_file)},
        ],
        "outputs": [
            {"path": name, "sha256": hashlib.sha256(payloads[name]).hexdigest()}
            for name in OUTPUT_FILES
        ],
    }


def expected_artifacts(
    manifest_path: Path,
    thresholds_path: Path,
    cases_path: Path,
    source_revision: str,
) -> dict[str, bytes]:
    first = evaluate_once(manifest_path, thresholds_path, cases_path, source_revision)
    second = evaluate_once(manifest_path, thresholds_path, cases_path, source_revision)
    if canonical_json(first).encode("utf-8") != canonical_json(second).encode("utf-8"):
        raise EvaluationError("ab_evaluation_not_deterministic")
    first["byte_identical_runs"] = 2
    payloads = output_payloads(first)
    manifest = artifact_manifest(manifest_path, thresholds_path, cases_path, payloads)
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    payloads["artifact-manifest.json"] = manifest_bytes
    payloads["artifact-manifest.sha256"] = (
        hashlib.sha256(manifest_bytes).hexdigest() + "  artifact-manifest.json\n"
    ).encode("ascii")
    return payloads


def verify_existing(output_dir: Path, expected: dict[str, bytes]) -> None:
    if not output_dir.is_dir():
        raise EvaluationError("output_directory_missing")
    actual_names = sorted(path.name for path in output_dir.iterdir() if path.is_file())
    if actual_names != sorted(expected):
        raise EvaluationError("output_file_set_mismatch")
    for name, payload in expected.items():
        if (output_dir / name).read_bytes() != payload:
            raise EvaluationError(f"output_byte_mismatch:{name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--thresholds", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args(argv)
    try:
        if REVISION_RE.fullmatch(args.source_revision) is None:
            raise EvaluationError("source_revision_invalid")
        expected = expected_artifacts(
            args.manifest, args.thresholds, args.cases, args.source_revision
        )
        output_dir = args.output_dir if args.output_dir.is_absolute() else ROOT / args.output_dir
        if args.verify_existing:
            verify_existing(output_dir, expected)
        else:
            if output_dir.exists():
                raise EvaluationError("output_directory_already_exists")
            output_dir.mkdir(parents=True)
            for name, payload in expected.items():
                (output_dir / name).write_bytes(payload)
        print(canonical_json({"files": sorted(expected), "ok": True, "output_dir": output_dir.relative_to(ROOT).as_posix()}))
        return 0
    except (EvaluationError, OSError, ValueError) as error:
        print(canonical_json({"error": str(error), "ok": False}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
