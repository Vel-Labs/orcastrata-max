#!/usr/bin/env python3
"""Return bounded native hook context without reading or changing workspace state."""

import json
import sys


CONTEXT = {
    "SessionStart": (
        "ORCASTRATA: Parent/PM owns integration, acceptance and the final answer. "
        "Bounded native work may be board-free; parallelism alone needs no board. "
        "Preserve selected GoalBuddy board and governed WorkGraph dependency authority. "
        "Delegate only useful bounded work. Keep disclosure and external-effect limits. "
        "Local issue/PR evidence stays board-free. Board-backed execution uses GitHub workflow; authentication grants no authority."
    ),
    "SubagentStart": (
        "ORCASTRATA WORKER: Own only the assigned packet. Do not widen scope, merge, or "
        "change canonical board state. Return changed files, checks, evidence, and blockers "
        "to the Parent/PM."
    ),
}


def hook_output(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict) or payload.get("hook_event_name") not in CONTEXT:
        return {}
    event = payload["hook_event_name"]
    return {
        "hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": CONTEXT[event],
        }
    }


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = None
    sys.stdout.write(json.dumps(hook_output(payload), separators=(",", ":")))


if __name__ == "__main__":
    main()
