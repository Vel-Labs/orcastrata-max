"""Focused filesystem checks for the C5 recovery journal boundary."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "plugins/codexmax-orchestrator/scripts/recover_supervisor_runtime.py"
SPEC = importlib.util.spec_from_file_location("recover_supervisor_runtime_c5", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
ASSESS_SCRIPT = ROOT / "plugins/codexmax-orchestrator/scripts/assess_execution_continuity.py"
ASSESS_SPEC = importlib.util.spec_from_file_location("assess_execution_continuity_c5", ASSESS_SCRIPT)
assert ASSESS_SPEC is not None and ASSESS_SPEC.loader is not None
assessor = importlib.util.module_from_spec(ASSESS_SPEC)
ASSESS_SPEC.loader.exec_module(assessor)


def _entry(state_path: Path, cursor_path: Path) -> dict:
    state = {"schema_version": 1, "goal_slug": "fixture", "checkpoint_id": "T006", "supervisor_id": "sup", "supervisor_epoch": 1, "board_sha256": "a" * 64}
    event = {
        "schema_version": 1, "sequence": 2, "event_id": "evt-2", "timestamp": "2026-01-01T00:00:01Z",
        "goal_slug": "fixture", "checkpoint_id": "T006", "source_role": "parent", "actor_id": "parent",
        "event_type": "pause", "payload": {}, "previous_event_hash": "b" * 64,
        "state_before_hash": "c" * 64, "state_after_hash": "d" * 64,
        "proof_boundary": "local_not_native", "board_mutated": False, "transcript_used": False,
        "native_side_proof": False, "acceptance_claimed": False, "event_hash": "e" * 64,
    }
    return {
        "schema_version": 1, "operation": "event_state_transition", "state_path": str(state_path),
        "before_state_sha256": "f" * 64, "before_state_projection_sha256": "0" * 64,
        "after_state_sha256": "1" * 64, "updated_state": state, "event_record": event,
        "predecessor_heads": {
            "event": {"event_count": 1, "last_event_id": "evt-1", "last_event_hash": "b" * 64},
            "cursor": {"cursor_sequence": 1, "cursor_hash": "2" * 64, "last_event_sequence": 1,
                       "last_event_id": "evt-1", "last_event_hash": "b" * 64},
        },
        "cursor_path": str(cursor_path),
        "runtime_identity": {"goal_slug": "fixture", "checkpoint_id": "T006", "supervisor_id": "sup",
                              "supervisor_epoch": 1, "board_sha256": "a" * 64},
    }


def _assessor_payload(*, signal_unknown=None, decision_unknown=None) -> dict:
    signals = {
        "context_pressure": False,
        "validation_failed": False,
        "candidate_ready": True,
        "useful_local_work_exhausted": False,
        "failed_attempt": False,
        "integration_complete": True,
        "task_transition_complete": True,
    }
    if signal_unknown is not None:
        signals["execution_unknown"] = signal_unknown
    decision_context = {}
    if decision_unknown is not None:
        decision_context["execution_unknown"] = decision_unknown
    return {
        "schema_version": 1,
        "authority": {
            "scope_expansion": False,
            "action_expansion": False,
            "billing_expansion": False,
            "cost_authority_expansion": False,
            "reserved_human_decision": False,
            "operator_stop": False,
        },
        "progress": {
            "oracle_satisfied": 1,
            "oracle_previously_satisfied": 0,
            "oracle_total": 1,
            "consecutive_no_improvement_attempts": 0,
            "no_improvement_window": 3,
        },
        "usage": {},
        "signals": signals,
        "optimization_options": {
            "revise_packet": True,
            "split_work": True,
            "reroute": True,
            "repair": True,
        },
        "decision_context": decision_context,
    }
class RecoveryJournalBoundaryTest(unittest.TestCase):
    def _fixture(self, initialize=True):
        root = Path(tempfile.mkdtemp(prefix="c5-recovery-"))
        goal = root / "goal.md"
        board_t005 = root / "board-t005.yaml"
        board_t006 = root / "board-t006.yaml"
        goal.write_text("# fixture\n", encoding="utf-8")

        def board(active: str) -> str:
            t005 = "active" if active == "T005" else "done"
            t006 = "active" if active == "T006" else "queued"
            receipt = "    receipt:\n      decision: accept\n      accepted_by: Parent Codex\n" if t005 == "done" else ""
            return (
                "version: 2\n"
                "goal:\n  slug: fixture\n  status: active\n"
                "rules:\n  pm_owns_state: true\n  one_active_task: true\n"
                "  parent_codex_final_acceptance: true\n  max_write_workers: 1\n"
                f"active_task: {active}\n"
                "tasks:\n"
                f"  - id: T005\n    status: {t005}\n    objective: sync\n"
                "    dependencies: []\n    allowed_files: [artifact.txt]\n"
                "    verify: [local]\n    stop_if: [invalid]\n" + receipt +
                f"  - id: T006\n    status: {t006}\n    objective: recovery\n"
                "    dependencies: [T005]\n    allowed_files: [artifact.txt]\n"
                "    verify: [local]\n    stop_if: [invalid]\n"
            )

        board_t005.write_text(board("T005"), encoding="utf-8")
        board_t006.write_text(board("T006"), encoding="utf-8")
        (root / "artifact.txt").write_text("fixture\n", encoding="utf-8")
        paths = {name: root / name for name in (
            "loop-state.json", "loop-events.jsonl", "sync-state.json", "sync-events.jsonl",
            "sync-cursor.jsonl", "inventory.json", "recovery-state.json",
            "recovery-events.jsonl", "recovery-cursor.jsonl",
        )}
        timestamp = "2026-01-01T00:00:00Z"
        runtime._sync.initialize_files(goal, board_t005, paths["sync-state.json"], paths["sync-events.jsonl"],
                                       paths["sync-cursor.jsonl"], "parent", "sup", timestamp)
        runtime._loop.initialize_files(goal, board_t006, paths["loop-state.json"], paths["loop-events.jsonl"], "loop-init", timestamp)
        paths["inventory.json"].write_text(json.dumps({
            "schema_version": 1, "goal_slug": "fixture", "transcript_used": False,
            "board_reconstructed_from_transcript": False, "authority_reconstructed_from_transcript": False,
            "supervisors": [{"supervisor_id": "sup", "goal_slug": "fixture", "checkpoint_id": "T006",
                              "epoch": 1, "status": "active", "disclosed": False, "terminal": False}],
        }), encoding="utf-8")
        if initialize:
            runtime.initialize_files(goal, board_t006, paths["loop-state.json"], paths["loop-events.jsonl"],
                                     paths["sync-state.json"], paths["sync-events.jsonl"], paths["sync-cursor.jsonl"],
                                     paths["inventory.json"], paths["recovery-state.json"], paths["recovery-events.jsonl"],
                                     paths["recovery-cursor.jsonl"], root, timestamp)
        return {"root": root, "goal": goal, "board": board_t006, **paths}

    def _cli(self, fixture, command, event=None):
        args = [sys.executable, str(SCRIPT), command, "--goal", str(fixture["goal"]), "--board", str(fixture["board"]),
                "--loop-state", str(fixture["loop-state.json"]), "--loop-events", str(fixture["loop-events.jsonl"]),
                "--sync-state", str(fixture["sync-state.json"]), "--sync-events", str(fixture["sync-events.jsonl"]),
                "--sync-cursor", str(fixture["sync-cursor.jsonl"]), "--state", str(fixture["recovery-state.json"]),
                "--events", str(fixture["recovery-events.jsonl"]), "--cursor", str(fixture["recovery-cursor.jsonl"]),
                "--repository-root", str(fixture["root"])]
        if command == "initialize":
            args += ["--inventory", str(fixture["inventory.json"]), "--timestamp", "2026-01-01T00:00:00Z"]
        if command == "apply":
            args += ["--event", str(event)]
        return subprocess.run(args, cwd=fixture["root"], capture_output=True, text=True, check=False)

    def _apply(self, fixture, event):
        return runtime.apply_event_files(fixture["goal"], fixture["board"], fixture["loop-state.json"], fixture["loop-events.jsonl"],
                                         fixture["sync-state.json"], fixture["sync-events.jsonl"], fixture["sync-cursor.jsonl"],
                                         fixture["recovery-state.json"], fixture["recovery-events.jsonl"], fixture["recovery-cursor.jsonl"],
                                         event, fixture["root"])

    def _reconcile(self, fixture):
        event = fixture["root"] / "reconcile.json"
        event.write_text(json.dumps({
            "schema_version": 1, "event_id": "reconcile-1", "timestamp": "2026-01-01T00:00:01Z",
            "source_role": "parent", "actor_id": "parent", "event_type": "goalbuddy_reconciled",
            "payload": {"reconciliation_id": "reconcile-action", "inventory": {
                "schema_version": 1, "goal_slug": "fixture", "transcript_used": False,
                "board_reconstructed_from_transcript": False, "authority_reconstructed_from_transcript": False,
                "supervisors": [{"supervisor_id": "sup", "goal_slug": "fixture", "checkpoint_id": "T006",
                                  "epoch": 1, "status": "active", "disclosed": False, "terminal": False}],
            }},
        }), encoding="utf-8")
        self._apply(fixture, event)

    def test_real_initialize_and_restart_after_event_append(self):
        fixture = self._fixture()
        self._reconcile(fixture)
        event = fixture["root"] / "pause.json"
        event.write_text(json.dumps({
            "schema_version": 1, "event_id": "pause-1", "timestamp": "2026-01-01T00:00:02Z",
            "source_role": "parent", "actor_id": "parent", "event_type": "pause",
            "payload": {"control_id": "pause-action", "reason": "test"},
        }), encoding="utf-8")
        original = runtime._append

        def crash(path, value, *, create=False):
            original(path, value, create=create)
            if path == fixture["recovery-events.jsonl"] and value.get("event_id") == "pause-1":
                raise RuntimeError("injected event append crash")

        runtime._append = crash
        try:
            with self.assertRaisesRegex(RuntimeError, "injected event append crash"):
                self._apply(fixture, event)
        finally:
            runtime._append = original
        self.assertTrue(runtime._journal_path(fixture["recovery-state.json"]).exists())
        snapshot = runtime.snapshot_files(fixture["goal"], fixture["board"], fixture["loop-state.json"], fixture["loop-events.jsonl"],
                                          fixture["sync-state.json"], fixture["sync-events.jsonl"], fixture["sync-cursor.jsonl"],
                                          fixture["recovery-state.json"], fixture["recovery-events.jsonl"], fixture["recovery-cursor.jsonl"], fixture["root"])
        self.assertEqual(snapshot["status"], "paused")
        self.assertFalse(runtime._journal_path(fixture["recovery-state.json"]).exists())
        self.assertEqual(runtime.verify_event_log(fixture["recovery-events.jsonl"])["event_count"], 3)

    def test_cli_initialize_apply_and_restarted_snapshot(self):
        fixture = self._fixture(initialize=False)
        result = self._cli(fixture, "initialize")
        self.assertEqual(result.returncode, 0, result.stderr)
        reconcile = fixture["root"] / "reconcile-cli.json"
        reconcile.write_text(json.dumps({
            "schema_version": 1, "event_id": "reconcile-1", "timestamp": "2026-01-01T00:00:01Z",
            "source_role": "parent", "actor_id": "parent", "event_type": "goalbuddy_reconciled",
            "payload": {"reconciliation_id": "reconcile-action", "inventory": {
                "schema_version": 1, "goal_slug": "fixture", "transcript_used": False,
                "board_reconstructed_from_transcript": False, "authority_reconstructed_from_transcript": False,
                "supervisors": [{"supervisor_id": "sup", "goal_slug": "fixture", "checkpoint_id": "T006",
                                  "epoch": 1, "status": "active", "disclosed": False, "terminal": False}],
            }},
        }), encoding="utf-8")
        result = self._cli(fixture, "apply", reconcile)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["state"]["event_sequence"], 2)
        pause = fixture["root"] / "pause-cli.json"
        pause.write_text(json.dumps({
            "schema_version": 1, "event_id": "pause-cli", "timestamp": "2026-01-01T00:00:02Z",
            "source_role": "parent", "actor_id": "parent", "event_type": "pause",
            "payload": {"control_id": "pause-cli-action", "reason": "test"},
        }), encoding="utf-8")
        original = runtime._append

        def crash(path, value, *, create=False):
            original(path, value, create=create)
            if path == fixture["recovery-events.jsonl"] and value.get("event_id") == "pause-cli":
                raise RuntimeError("injected event append crash")

        runtime._append = crash
        try:
            with self.assertRaises(RuntimeError):
                self._apply(fixture, pause)
        finally:
            runtime._append = original
        result = self._cli(fixture, "snapshot")
        self.assertEqual(result.returncode, 0, result.stderr)
        snapshot = json.loads(result.stdout)
        self.assertEqual(snapshot["status"], "paused")
        self.assertEqual(snapshot["event_count"], 3)
        state = json.loads(fixture["recovery-state.json"].read_text(encoding="utf-8"))
        records = runtime.verify_event_log(fixture["recovery-events.jsonl"])
        self.assertEqual(state["last_event_hash"], records["last_event_hash"])
        self.assertEqual(snapshot["cursor_head"]["cursor_sequence"], 1)
        self.assertFalse(runtime._journal_path(fixture["recovery-state.json"]).exists())

    def test_real_cursor_append_crash_restores_once(self):
        fixture = self._fixture()
        self._reconcile(fixture)
        pause = fixture["root"] / "pause.json"
        pause.write_text(json.dumps({
            "schema_version": 1, "event_id": "pause-1", "timestamp": "2026-01-01T00:00:02Z",
            "source_role": "parent", "actor_id": "parent", "event_type": "pause",
            "payload": {"control_id": "pause-action", "reason": "test"},
        }), encoding="utf-8")
        self._apply(fixture, pause)
        event = fixture["root"] / "cursor-recovered.json"
        event.write_text(json.dumps({
            "schema_version": 1, "event_id": "cursor-1", "timestamp": "2026-01-01T00:00:03Z",
            "source_role": "parent", "actor_id": "parent", "event_type": "cursor_recovered",
            "payload": {"recovery_id": "cursor-action"},
        }), encoding="utf-8")
        original = runtime._append

        def crash(path, value, *, create=False):
            original(path, value, create=create)
            if path == fixture["recovery-cursor.jsonl"] and value.get("cursor_sequence") == 2:
                raise RuntimeError("injected cursor append crash")

        runtime._append = crash
        try:
            with self.assertRaisesRegex(RuntimeError, "injected cursor append crash"):
                self._apply(fixture, event)
        finally:
            runtime._append = original
        snapshot = runtime.snapshot_files(fixture["goal"], fixture["board"], fixture["loop-state.json"], fixture["loop-events.jsonl"],
                                          fixture["sync-state.json"], fixture["sync-events.jsonl"], fixture["sync-cursor.jsonl"],
                                          fixture["recovery-state.json"], fixture["recovery-events.jsonl"], fixture["recovery-cursor.jsonl"], fixture["root"])
        self.assertEqual(snapshot["cursor_head"]["cursor_sequence"], 2)
        self.assertEqual(runtime.verify_event_log(fixture["recovery-events.jsonl"])["event_count"], 4)
        self.assertFalse(runtime._journal_path(fixture["recovery-state.json"]).exists())

    def test_real_loop_prepare_commit_and_retry_do_not_duplicate(self):
        fixture = self._fixture()
        self._reconcile(fixture)
        loop_event = {
            "schema_version": 1, "event_id": "assignment-1", "timestamp": "2026-01-01T00:00:02Z",
            "event_type": "assignment_created", "lane_id": "worker-a", "payload": {"assignment": {
                "schema_version": 1, "assignment_id": "assignment-1", "lane_id": "worker-a", "task_id": "T006",
                "role": "worker", "lane_mode": "write_worker", "objective": "fixture", "dependencies": [],
                "read_scope": ["artifact.txt"], "write_scope": ["artifact.txt"],
                "forbidden_actions": ["accept_checkpoint", "accept_goal", "mutate_goalbuddy", "create_desktop_chat"],
                "route_profile": "fixture", "expected_artifact": "artifact.txt", "self_test": ["local"],
                "independent_test_required": True, "retry_cap": 1,
            }},
        }
        loop_event_path = fixture["root"] / "loop-event.json"
        loop_event_path.write_text(json.dumps(loop_event), encoding="utf-8")
        runtime._loop.apply_event_files(
            fixture["goal"], fixture["board"], fixture["loop-state.json"], fixture["loop-events.jsonl"],
            loop_event_path, fixture["root"], recovery_control={
                "state_path": str(fixture["recovery-state.json"]),
                "events_path": str(fixture["recovery-events.jsonl"]),
                "cursor_path": str(fixture["recovery-cursor.jsonl"]),
                "sync_state_path": str(fixture["sync-state.json"]),
                "sync_events_path": str(fixture["sync-events.jsonl"]),
                "sync_cursor_path": str(fixture["sync-cursor.jsonl"]),
                "transition_id": "transition-1", "supervisor_id": "sup", "supervisor_epoch": 1,
            },
        )
        retry = runtime.complete_loop_transition_files(
            fixture["goal"], fixture["board"], fixture["loop-state.json"], fixture["loop-events.jsonl"],
            fixture["sync-state.json"], fixture["sync-events.jsonl"], fixture["sync-cursor.jsonl"],
            fixture["recovery-state.json"], fixture["recovery-events.jsonl"], fixture["recovery-cursor.jsonl"],
            fixture["root"], "transition-1",
        )
        self.assertEqual(retry["status"], "already_committed")
        self.assertEqual(runtime.verify_event_log(fixture["recovery-events.jsonl"])["event_count"], 4)

    def test_real_conflicting_append_keeps_journal_and_state(self):
        fixture = self._fixture()
        self._reconcile(fixture)
        event = fixture["root"] / "pause.json"
        event.write_text(json.dumps({
            "schema_version": 1, "event_id": "pause-1", "timestamp": "2026-01-01T00:00:02Z",
            "source_role": "parent", "actor_id": "parent", "event_type": "pause",
            "payload": {"control_id": "pause-action", "reason": "test"},
        }), encoding="utf-8")
        original = runtime._append

        def crash(path, value, *, create=False):
            original(path, value, create=create)
            if path == fixture["recovery-events.jsonl"] and value.get("event_id") == "pause-1":
                raise RuntimeError("injected event append crash")

        runtime._append = crash
        try:
            with self.assertRaises(RuntimeError):
                self._apply(fixture, event)
        finally:
            runtime._append = original
        with fixture["recovery-events.jsonl"].open("a", encoding="utf-8") as stream:
            stream.write("{}\n")
        with self.assertRaisesRegex(runtime.RecoveryError, "recovery_outcome_uncertain"):
            runtime.snapshot_files(fixture["goal"], fixture["board"], fixture["loop-state.json"], fixture["loop-events.jsonl"],
                                   fixture["sync-state.json"], fixture["sync-events.jsonl"], fixture["sync-cursor.jsonl"],
                                   fixture["recovery-state.json"], fixture["recovery-events.jsonl"], fixture["recovery-cursor.jsonl"], fixture["root"])
        self.assertTrue(runtime._journal_path(fixture["recovery-state.json"]).exists())

    def test_assessor_execution_unknown_blocks_candidate_closeout(self):
        cases = (
            ("absent", _assessor_payload(), "candidate_closeout", "candidate_ready_for_parent_review"),
            ("false_signal", _assessor_payload(signal_unknown=False), "candidate_closeout", "candidate_ready_for_parent_review"),
            ("true_signal", _assessor_payload(signal_unknown=True), "needs_parent_repair", "execution_unknown"),
            ("true_decision", _assessor_payload(decision_unknown=True), "needs_parent_repair", "execution_unknown"),
        )
        for name, payload, expected_action, expected_reason in cases:
            with self.subTest(name=name):
                result = assessor.assess(payload)
                self.assertEqual(result["action"], expected_action)
                self.assertIn(expected_reason, result["reason_codes"])

        for location in ("signals", "decision_context"):
            with self.subTest(location=location):
                payload = _assessor_payload()
                payload[location]["execution_unknown"] = "unknown"
                with self.assertRaisesRegex(assessor.ContinuityError, "execution_unknown_must_be_boolean"):
                    assessor.assess(payload)


    def test_valid_entry_requires_hash_bound_state_and_paths(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            entry = _entry(root / "state.json", root / "cursor.jsonl")
            runtime._validate_journal_entry(entry)
            invalid = dict(entry)
            invalid["after_state_sha256"] = "short"
            with self.assertRaisesRegex(runtime.RecoveryError, "journal_entry_invalid"):
                runtime._validate_journal_entry(invalid)

    def test_malformed_pending_journal_fails_closed_and_is_preserved(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state_path = root / "state.json"
            cursor_path = root / "cursor.jsonl"
            events_path = root / "events.jsonl"
            state_path.write_text(json.dumps({"untrusted": True}), encoding="utf-8")
            events_path.write_text("", encoding="utf-8")
            cursor_path.write_text("", encoding="utf-8")
            journal_path = runtime._journal_path(state_path)
            journal_path.write_text("{\"schema_version\": 1,", encoding="utf-8")
            with self.assertRaisesRegex(runtime.RecoveryError, "recovery_journal_unreadable|recovery_outcome_uncertain"):
                runtime._recover_pending_journal(state_path, events_path, cursor_path)
            self.assertTrue(journal_path.exists())

    def test_state_missing_with_pending_journal_is_uncertain_without_replay(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state_path = root / "state.json"
            cursor_path = root / "cursor.jsonl"
            events_path = root / "events.jsonl"
            events_path.write_text("", encoding="utf-8")
            cursor_path.write_text("", encoding="utf-8")
            journal_path = runtime._journal_path(state_path)
            journal_path.write_text(json.dumps(_entry(state_path, cursor_path)), encoding="utf-8")
            with self.assertRaisesRegex(runtime.RecoveryError, "recovery_outcome_uncertain"):
                runtime._recover_pending_journal(state_path, events_path, cursor_path)
            self.assertFalse(state_path.exists())
            self.assertTrue(journal_path.exists())


if __name__ == "__main__":
    unittest.main()
