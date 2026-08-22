#!/usr/bin/env python3
"""Parent observer for a pending Grok read-mutate-read session."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from typing import Any, Mapping


_SPEC = importlib.util.spec_from_file_location("grok_clean_session", Path(__file__).with_name("protected_grok_clean_session_v1.py"))
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("Grok clean session unavailable")
SESSION = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = SESSION
_SPEC.loader.exec_module(SESSION)


class ProtectedGrokExecutorError(ValueError): pass


class ObservedSession:
    """Validate one synthetic or future raw event stream without launching."""
    def __init__(self, prepared: Any, *, target_path: str, before: str, after: str, mutation_tool: str = "write_file") -> None:
        SESSION.inspect_pending(prepared)
        if prepared.mode != "scoped_write" or mutation_tool not in {"write_file", "edit_file"}:
            raise ProtectedGrokExecutorError("grok_observer_mode_invalid")
        self.prepared = prepared
        self.target_path = target_path
        self.before = before
        self.after = after
        self.sequence = ("read_file", mutation_tool, "read_file")
        self.index = 0
        self.turns = 0
        self.terminal = False

    def event(self, value: Mapping[str, Any]) -> None:
        if value.get("model") not in (None, self.prepared.model):
            raise ProtectedGrokExecutorError("grok_observer_model_substitution")
        if value.get("task_id") not in (None, self.prepared.task_id):
            raise ProtectedGrokExecutorError("grok_observer_task_substitution")
        if value.get("attempt_id") not in (None, self.prepared.attempt_id):
            raise ProtectedGrokExecutorError("grok_observer_attempt_substitution")
        if value.get("session_id") not in (None, self.prepared.session_id):
            raise ProtectedGrokExecutorError("grok_observer_session_substitution")
        if value.get("type") in {"assistant", "turn"}:
            self.turns += 1
            if self.turns > 20:
                raise ProtectedGrokExecutorError("grok_observer_turn_limit")
        if value.get("type") == "tool_call":
            tool = value.get("tool")
            arguments = value.get("arguments")
            if self.index >= 3 or tool != self.sequence[self.index] or not isinstance(arguments, Mapping) or arguments.get("path") != self.target_path:
                raise ProtectedGrokExecutorError("grok_observer_sequence_invalid")
            if tool == "write_file" and arguments.get("content") != self.after:
                raise ProtectedGrokExecutorError("grok_observer_write_content_invalid")
            if tool == "edit_file" and (arguments.get("old") != self.before or arguments.get("new") != self.after):
                raise ProtectedGrokExecutorError("grok_observer_edit_content_invalid")
            self.index += 1
        if value.get("type") == "result":
            if self.index != 3 or self.terminal:
                raise ProtectedGrokExecutorError("grok_observer_terminal_invalid")
            self.terminal = True

    def receipt(self) -> dict[str, Any]:
        if not self.terminal or self.index != 3:
            raise ProtectedGrokExecutorError("grok_observer_incomplete")
        return {
            "task_id": self.prepared.task_id, "attempt_id": self.prepared.attempt_id,
            "session_id": self.prepared.session_id, "model": self.prepared.model,
            "turns": self.turns, "sequence": list(self.sequence),
            "provider_called": False, "accepted_by_parent": False,
            "protected_production": False, "t062_proved": False,
        }


class SourceLocalOneUseJournal:
    def __init__(self) -> None: self.state = "issued"
    def begin(self) -> None:
        if self.state == "consuming":
            self.state = "execution_unknown"
            raise ProtectedGrokExecutorError("grok_execution_unknown_no_retry")
        if self.state != "issued": raise ProtectedGrokExecutorError("grok_replay_forbidden")
        self.state = "consuming"
    def finish(self) -> None:
        if self.state != "consuming": raise ProtectedGrokExecutorError("grok_finish_invalid")
        self.state = "consumed"
    def interrupt(self) -> None:
        if self.state != "consuming": raise ProtectedGrokExecutorError("grok_interrupt_invalid")
        self.state = "execution_unknown"


__all__ = ["ObservedSession", "ProtectedGrokExecutorError", "SourceLocalOneUseJournal"]
