#!/usr/bin/env python3
"""Assess durable repository goal inputs without transcript reconstruction."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Sequence


class AssessmentError(ValueError):
    """A deterministic, fail-clear assessment input error."""


REQUIRED_CLAIMS = (
    ("GQ-001", "objective", ("objective",)),
    ("GQ-002", "acceptance_oracle", ("acceptance oracle", "functional oracle")),
    ("GQ-003", "scope_write_boundary", ("scope",)),
    ("GQ-004", "authority_boundary", ("authority", "non-negotiable constraints")),
    ("GQ-005", "validation_plan", ("validation", "validation plan")),
    ("GQ-006", "first_checkpoint_readiness", ("first checkpoint", "checkpoints")),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _normalized_path(root: Path, candidate: Path, label: str) -> tuple[Path, str]:
    if candidate.is_absolute():
        raise AssessmentError(f"path_absolute_forbidden:{label}")
    if ".." in candidate.parts:
        raise AssessmentError(f"path_parent_escape_forbidden:{label}")
    current = root
    for part in candidate.parts:
        current = current / part
        if current.is_symlink():
            raise AssessmentError(f"input_symlink_forbidden:{label}")
    try:
        resolved = current.resolve(strict=True)
        relative = resolved.relative_to(root)
    except FileNotFoundError as error:
        raise AssessmentError(f"input_missing:{label}") from error
    except ValueError as error:
        raise AssessmentError(f"path_outside_root:{label}") from error
    if not resolved.is_file():
        raise AssessmentError(f"input_not_regular:{label}")
    return resolved, relative.as_posix()


def _repository_root(value: Path) -> Path:
    if value.is_symlink():
        raise AssessmentError("repository_root_symlink_forbidden")
    resolved = value.resolve()
    if not resolved.is_dir():
        raise AssessmentError("repository_root_invalid")
    return resolved


def _sections(goal_text: str) -> dict[str, tuple[str, int, str]]:
    matches = list(re.finditer(r"(?m)^(#{1,6})\s+(.+?)\s*$", goal_text))
    if not matches:
        raise AssessmentError("goal_malformed:headings_missing")
    result: dict[str, tuple[str, int, str]] = {}
    lines = goal_text.splitlines()
    for index, match in enumerate(matches):
        title = match.group(2).strip()
        normalized = re.sub(r"\s+", " ", title.lower())
        if normalized in result:
            raise AssessmentError(f"goal_malformed:duplicate_heading:{normalized}")
        start = match.end()
        level = len(match.group(1))
        end = len(goal_text)
        for later in matches[index + 1:]:
            if len(later.group(1)) <= level:
                end = later.start()
                break
        body = goal_text[start:end].strip()
        line = goal_text[:match.start()].count("\n") + 1
        result[normalized] = (title, line, body)
    if not lines or not lines[0].lstrip().startswith("#"):
        raise AssessmentError("goal_malformed:title_missing")
    return result


def _scalar(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value[0:1] in {"'", '"'} and value[-1:] == value[0:1]:
        return value[1:-1]
    return value.split(" #", 1)[0].rstrip()


def _state_metadata(state_text: str, suffix: str) -> dict[str, str]:
    if suffix == ".json":
        try:
            value = json.loads(state_text)
        except json.JSONDecodeError as error:
            raise AssessmentError("state_malformed:json") from error
        if not isinstance(value, dict):
            raise AssessmentError("state_malformed:root_not_mapping")
        metadata: dict[str, str] = {}
        for key in ("goal_id", "first_checkpoint", "active_checkpoint", "active_task"):
            if isinstance(value.get(key), str) and value[key].strip():
                metadata[key] = value[key].strip()
        goal = value.get("goal")
        if "goal_id" not in metadata and isinstance(goal, dict) and isinstance(goal.get("slug"), str):
            metadata["goal_id"] = goal["slug"].strip()
        return metadata

    metadata: dict[str, str] = {}
    top_key: str | None = None
    seen_top: set[str] = set()
    for number, raw in enumerate(state_text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw:
            raise AssessmentError(f"state_malformed:tabs_line_{number}")
        indent = len(raw) - len(raw.lstrip(" "))
        text = raw.strip()
        if text.startswith("- "):
            continue
        if ":" not in text:
            raise AssessmentError(f"state_malformed:line_{number}")
        key, raw_value = text.split(":", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", key):
            raise AssessmentError(f"state_malformed:key_line_{number}")
        value = _scalar(raw_value)
        if any(marker in value for marker in ("[", "]", "{", "}")) and value.count("[") != value.count("]"):
            raise AssessmentError(f"state_malformed:collection_line_{number}")
        if indent == 0:
            if key in seen_top:
                raise AssessmentError(f"state_malformed:duplicate_key:{key}")
            seen_top.add(key)
            top_key = key if not value else None
            if key in {"goal_id", "first_checkpoint", "active_checkpoint", "active_task"} and value:
                metadata[key] = value
        elif indent >= 2 and top_key == "goal" and key == "slug" and value and "goal_id" not in metadata:
            metadata["goal_id"] = value
    return metadata


def _goal_identifier(goal_text: str) -> str | None:
    match = re.search(r"(?im)^\s*goal\s+id\s*:\s*`?([^`\n]+?)`?\s*$", goal_text)
    return match.group(1).strip() if match else None


def _first_checkpoint(body: str) -> str | None:
    match = re.search(r"(?m)^\s*(?:\d+\.\s*|[-*]\s*)?(T\d{3})\b", body)
    return match.group(1) if match else None


def _source(path: Path, relative: str, kind: str) -> dict[str, str]:
    return {"kind": kind, "path": relative, "sha256": _sha256(path)}


def assess(
    repo_root: Path,
    goal_path: Path,
    state_path: Path,
    *,
    transcript: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic assessment or raise ``AssessmentError``."""
    if transcript is not None:
        raise AssessmentError("unsupported_input:transcript")
    root = _repository_root(repo_root)
    goal, goal_relative = _normalized_path(root, goal_path, "goal")
    state, state_relative = _normalized_path(root, state_path, "state")
    if goal.suffix.lower() not in {".md", ".markdown"}:
        raise AssessmentError("goal_malformed:markdown_required")
    if state.suffix.lower() not in {".yaml", ".yml", ".json"}:
        raise AssessmentError("state_malformed:yaml_or_json_required")
    try:
        goal_text = goal.read_text(encoding="utf-8")
        state_text = state.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise AssessmentError("input_not_utf8") from error

    sections = _sections(goal_text)
    metadata = _state_metadata(state_text, state.suffix.lower())
    goal_id = _goal_identifier(goal_text)
    state_goal_id = metadata.get("goal_id")
    if goal_id and state_goal_id and goal_id != state_goal_id:
        raise AssessmentError("contradictory_sources:goal_id")

    claims: list[dict[str, str]] = []
    gaps: list[dict[str, str]] = []
    first_goal_checkpoint: str | None = None
    for claim_id, requirement, headings in REQUIRED_CLAIMS:
        found: tuple[str, int, str] | None = None
        heading_name = ""
        for heading in headings:
            if heading in sections:
                found = sections[heading]
                heading_name = heading
                break
        if found is not None and requirement == "first_checkpoint_readiness":
            first_goal_checkpoint = _first_checkpoint(found[2])
            if first_goal_checkpoint is None:
                found = None
        if found is None or not found[2].strip():
            gap = {
                "classification": "inferred_gap",
                "claim_id": claim_id,
                "requirement": requirement,
                "reason": f"durable_section_missing_or_empty:{headings[0]}",
            }
            claims.append(gap)
            gaps.append(gap)
            continue
        claims.append({
            "citation": f"{goal_relative}#{found[0]}:L{found[1]}",
            "classification": "observed",
            "claim_id": claim_id,
            "requirement": requirement,
        })

    state_first = metadata.get("first_checkpoint")
    if state_first and first_goal_checkpoint and state_first != first_goal_checkpoint:
        raise AssessmentError("contradictory_sources:first_checkpoint")
    claims.append({
        "citation": state_relative,
        "classification": "observed" if metadata else "unknown",
        "claim_id": "GQ-007",
        "requirement": "durable_state_metadata",
    })
    unknowns = [{
        "classification": "unknown",
        "id": "GQ-U001",
        "reason": "native_desktop_functional_behavior_is_outside_local_goal_quality_assessment",
    }]
    if not metadata:
        unknowns.append({
            "classification": "unknown",
            "id": "GQ-U002",
            "reason": "state_identity_and_checkpoint_metadata_not_present",
        })
    operator_decisions = [{
        "classification": "operator_decision",
        "id": "GQ-D001",
        "reason": "parent_codex_acceptance_required; assessment_does_not_grant_scope_or_authority",
    }]
    questions = [
        f"Provide a durable {gap['requirement'].replace('_', ' ')} section or reference for {gap['claim_id']}."
        for gap in gaps[:3]
    ]
    recommendations = [
        f"Add or repair durable evidence for {gap['requirement']} ({gap['claim_id']})."
        for gap in gaps
    ]
    return {
        "claims": claims,
        "gaps": gaps,
        "operator_decisions": operator_decisions,
        "questions": questions,
        "recommendations": recommendations,
        "schema_version": 1,
        "sources": [_source(goal, goal_relative, "goal_markdown"), _source(state, state_relative, "goal_state")],
        "status": "ready" if not gaps else "needs_intake",
        "unknowns": unknowns,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--goal-path", required=True, type=Path)
    parser.add_argument("--state-path", required=True, type=Path)
    parser.add_argument("--transcript", help="Rejected: transcript context is unsupported.")
    args = parser.parse_args(argv)
    try:
        result = assess(args.repo_root, args.goal_path, args.state_path, transcript=args.transcript)
    except AssessmentError as error:
        print(_canonical({"error": str(error), "schema_version": 1, "status": "error"}))
        return 2
    print(_canonical(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
