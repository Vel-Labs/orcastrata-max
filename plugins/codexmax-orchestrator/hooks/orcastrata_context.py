#!/usr/bin/env python3
"""Return bounded native hook context without reading or changing workspace state."""

import json
import sys


CONTEXT = {
    "SessionStart": (
        "ORCASTRATA: The visible Codex task is Parent/PM. Keep GoalBuddy as board truth "
        "and WorkGraph as dependency truth. Delegate only bounded useful work. The Parent "
        "owns integration, acceptance, and the final answer."
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
