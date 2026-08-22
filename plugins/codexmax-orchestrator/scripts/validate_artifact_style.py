#!/usr/bin/env python3
"""Validate provider-neutral result artifact structure and lexical discipline."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


REQUIRED_HEADINGS = (
    "Identity",
    "Outcome",
    "Evidence",
    "Validation",
    "Risks And Gaps",
    "Handoff",
)

CANONICAL_STATUSES = {
    "assigned",
    "pending",
    "in_progress",
    "ready_for_review",
    "candidate_complete",
    "needs_revision",
    "needs_reassignment",
    "needs_parent_repair",
    "waiting_external",
    "accepted",
    "rejected",
}

LEGACY_OR_VARIANT_STATUSES = {
    "blocked": "waiting_external or needs_parent_repair",
    "done": "candidate_complete",
    "needs_rerun": "needs_revision or needs_reassignment",
    "in-progress": "in_progress",
    "ready-for-review": "ready_for_review",
    "complete": "candidate_complete",
    "completed": "candidate_complete",
}

FILLER_PATTERNS = (
    r"\bas an ai\b",
    r"\bi hope this helps\b",
    r"\bfeel free to\b",
    r"\bcertainly[!,.]",
    r"\babsolutely[!,.]",
    r"\bhere(?:'s| is) (?:a|the) comprehensive\b",
)

UNSUPPORTED_SUCCESS_PATTERNS = (
    r"\bfully complete\b",
    r"\bproduction[- ]ready\b",
    r"\bguaranteed to\b",
    r"\bworks perfectly\b",
)

STATUS_FIELD_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:artifact\s+)?status\s*:\s*`?([a-z_-]+)`?"
)
ROLE_FIELD_RE = re.compile(r"(?im)^\s*(?:[-*]\s*)?role\s*:\s*`?([^`\n]+)`?")


@dataclass(frozen=True)
class Finding:
    path: str
    severity: str
    code: str
    message: str


def heading_positions(text: str) -> dict[str, int]:
    positions: dict[str, int] = {}
    for match in re.finditer(r"(?m)^##\s+(.+?)\s*$", text):
        positions.setdefault(match.group(1), match.start())
    return positions


def validate(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    label = str(path)
    if not path.is_file():
        return [Finding(label, "error", "missing_file", "Artifact does not exist.")]

    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return [Finding(label, "error", "empty_file", "Artifact is empty.")]

    positions = heading_positions(text)
    missing = [heading for heading in REQUIRED_HEADINGS if heading not in positions]
    if missing:
        findings.append(
            Finding(label, "error", "missing_headings", f"Missing headings: {', '.join(missing)}")
        )
    else:
        ordered = [positions[heading] for heading in REQUIRED_HEADINGS]
        if ordered != sorted(ordered):
            findings.append(
                Finding(label, "error", "heading_order", "Standard headings are out of order.")
            )

    role_match = ROLE_FIELD_RE.search(text)
    role = role_match.group(1).strip().lower() if role_match else "unknown"
    for status in STATUS_FIELD_RE.findall(text):
        if status not in CANONICAL_STATUSES:
            replacement = LEGACY_OR_VARIANT_STATUSES.get(status, "a canonical operational status")
            findings.append(
                Finding(label, "error", "status_vocabulary", f"Status {status!r} must map to {replacement}.")
            )
        elif status in {"accepted", "rejected"} and not any(
            marker in role for marker in ("arbiter", "parent codex", "final judge")
        ):
            findings.append(
                Finding(
                    label,
                    "error",
                    "acceptance_authority",
                    f"Role {role!r} cannot emit terminal status {status!r}.",
                )
            )

    lowered = text.lower()
    for pattern in FILLER_PATTERNS:
        if re.search(pattern, lowered):
            findings.append(
                Finding(label, "warning", "provider_filler", f"Provider-style filler matched {pattern!r}.")
            )

    for pattern in UNSUPPORTED_SUCCESS_PATTERNS:
        if re.search(pattern, lowered):
            findings.append(
                Finding(label, "warning", "unsupported_success", f"Unqualified success language matched {pattern!r}.")
            )

    if "\u2014" in text:
        findings.append(Finding(label, "warning", "em_dash", "Use ASCII punctuation in benchmark artifacts."))

    if re.search(r"[\U0001F300-\U0001FAFF]", text):
        findings.append(Finding(label, "warning", "decorative_unicode", "Remove emoji or decorative symbols."))

    if not re.search(r"(?im)^\s*[-*]\s+proof boundary\s*:", text):
        findings.append(
            Finding(label, "warning", "proof_boundary", "Outcome should state an explicit Proof boundary field.")
        )

    required_handoff = (
        "Produced",
        "Not produced",
        "Validated",
        "Not validated",
        "Safe to use",
        "Must verify",
        "Next owner",
        "Requested state transition",
        "Parent decision requested",
    )
    for field in required_handoff:
        if not re.search(rf"(?im)^\s*[-*]\s+{re.escape(field)}\s*:", text):
            findings.append(
                Finding(label, "error", "handoff_field", f"Missing Handoff field: {field}.")
            )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+", type=Path)
    parser.add_argument("--strict", action="store_true", help="Treat warnings as failures.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    args = parser.parse_args()

    findings = [finding for path in args.artifacts for finding in validate(path)]
    if args.json:
        print(json.dumps([asdict(finding) for finding in findings], indent=2))
    elif findings:
        for finding in findings:
            print(f"{finding.severity.upper()} {finding.path} {finding.code}: {finding.message}")
    else:
        print(f"artifact_style=ok files={len(args.artifacts)}")

    has_error = any(finding.severity == "error" for finding in findings)
    has_warning = any(finding.severity == "warning" for finding in findings)
    return 1 if has_error or (args.strict and has_warning) else 0


if __name__ == "__main__":
    raise SystemExit(main())
