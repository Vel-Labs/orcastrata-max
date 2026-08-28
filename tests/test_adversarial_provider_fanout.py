import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "adversarial_provider_fanout_tested",
    ROOT / "plugins/codexmax-orchestrator/scripts/run_adversarial_provider_fanout.py",
)
fanout = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(fanout)


class FanoutTests(unittest.TestCase):
    def test_cli_maps_repeated_request_flags_to_requests(self):
        with patch.object(fanout, "run_fanout", return_value={"completed": True}) as run:
            code = fanout.main([
                "--repo-root", ".", "--task-id", "T060-cli",
                "--request", "m1 through Command Code",
                "--request", "m2 through Command Code",
                "--prompt", "p", "--candidate", "c", "--rubric", "r",
                "--read-scope", ".",
            ])
        self.assertEqual(code, 0)
        self.assertEqual(
            run.call_args.kwargs["requests"],
            ["m1 through Command Code", "m2 through Command Code"],
        )

    def test_each_exact_request_gets_one_isolated_lane_and_frozen_digest(self):
        calls = []

        def runner(**kwargs):
            calls.append(kwargs)
            return {"configured": True, "selected": True, "called": True,
                    "completed": True, "rejected": False,
                    "usage": "unknown", "binding_id": kwargs["request"]}

        with tempfile.TemporaryDirectory() as directory:
            result = fanout.run_fanout(
                repo_root=Path(directory), task_id="T060",
                requests=["deepseek/deepseek-v4-pro through Command Code",
                          "minimaxai/minimax-m3 through Command Code",
                          "xai/grok-4.6 through Command Code"],
                prompt="Find correctness risks.", candidate="candidate-v1",
                rubric="Evidence, severity, and remediation.", read_scope=["."],
                evidence_directory="reports", workspace_config=None,
                allow_provider_call=True, task_runner=runner)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result["lane_count"], 3)
        self.assertEqual(result["completed_lane_count"], 3)
        self.assertTrue(result["completed"])
        self.assertTrue(result["parent_synthesis_required"])
        self.assertTrue(result["no_substitution"])
        self.assertEqual(len({call["task_id"] for call in calls}), 3)
        self.assertEqual(len({call["evidence_directory"] for call in calls}), 3)
        self.assertEqual(len({call["expected_artifact"] for call in calls}), 3)
        self.assertTrue(all(call["timeout_seconds"] == 60.0 for call in calls))
        self.assertEqual(len({call["prompt"] for call in calls}), 1)
        self.assertEqual(len({lane["frozen_input_sha256"] for lane in result["lanes"]}), 1)
        self.assertIn("prompt_sha256", result["frozen_input"])
        self.assertNotIn("prompt", result["frozen_input"])

    def test_failure_is_recorded_and_does_not_stop_later_explicit_lane(self):
        calls = []

        def runner(**kwargs):
            calls.append(kwargs["request"])
            if len(calls) == 1:
                return {"configured": True, "selected": False, "called": False,
                        "completed": False, "rejected": True,
                        "reason": "session_probe_failed"}
            return {"configured": True, "selected": True, "called": True,
                    "completed": True, "rejected": False}

        with tempfile.TemporaryDirectory() as directory:
            result = fanout.run_fanout(
                repo_root=Path(directory), task_id="T060", requests=["m1 through Command Code", "m2 through Command Code"],
                prompt="review", candidate="candidate", rubric="rubric", read_scope=["."],
                evidence_directory="reports", workspace_config=None,
                allow_provider_call=True, task_runner=runner)
        self.assertEqual(calls, ["m1 through Command Code", "m2 through Command Code"])
        self.assertFalse(result["completed"])
        self.assertEqual(result["called_lane_count"], 1)
        self.assertEqual(result["completed_lane_count"], 1)
        self.assertEqual(result["rejected_lane_count"], 1)
        self.assertEqual(result["lanes"][0]["result"]["reason"], "session_probe_failed")

    def test_duplicate_requests_are_rejected_before_execution(self):
        with self.assertRaisesRegex(ValueError, "requests_must_be_unique"):
            fanout.run_fanout(
                repo_root=Path("."), task_id="T060", requests=["m through Command Code"] * 2,
                prompt="p", candidate="c", rubric="r", read_scope=["."],
                evidence_directory="reports", workspace_config=None,
                allow_provider_call=False, task_runner=lambda **kwargs: {})

    def test_timeout_is_bounded_before_any_lane(self):
        with self.assertRaisesRegex(ValueError, "timeout_seconds_invalid"):
            fanout.run_fanout(
                repo_root=Path("."), task_id="T060", requests=["m through Command Code"],
                prompt="p", candidate="c", rubric="r", read_scope=["."],
                evidence_directory="reports", workspace_config=None,
                allow_provider_call=True, timeout_seconds=301,
                task_runner=lambda **kwargs: self.fail("lane must not start"))


if __name__ == "__main__":
    unittest.main()
