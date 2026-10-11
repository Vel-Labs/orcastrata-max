"""Occupied evidence stops before admission; safe pre-spawn retries still work."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "fanout_recovery_test", ROOT / "plugins/codexmax-orchestrator/scripts/run_provider_fanout.py")
fanout = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fanout
SPEC.loader.exec_module(fanout)


class FanoutRecoveryTests(unittest.TestCase):
    def controller(self, root, max_attempts):
        lane = {"lane_id": "recovery", "route_name": "fixture-route", "provider": "local-fixture",
                "model": "synthetic/sprint-model", "max_attempts": max_attempts,
                "evidence_directory": "lane", "worktree_path": "fixture-worktree",
                "worktree_identity_sha256": fanout.digest("worktree"),
                "capability_card_sha256": fanout.digest("card"), "grant_sha256": fanout.digest("grant")}
        executor = mock.Mock(spec=["admit", "bind", "run_one"])
        executor.admit.side_effect = lambda row, attempt: {
            "selected_route": {"name": row["route_name"], "provider": row["provider"], "exact_model": row["model"]},
            "lease": {"lease_id": attempt["attempt_id"], "fencing_token": attempt["attempt_index"]}}
        executor.bind.side_effect = lambda row, attempt, admission: {
            "attempt_id": attempt["attempt_id"], "route_name": row["route_name"],
            "preflight_sha256": fanout.digest([attempt["attempt_id"], "preflight"])}
        # This local sentinel records reaching execution; it never calls a provider.
        executor.run_one.side_effect = RuntimeError("local execution sentinel")
        controller = fanout.FanoutController.source_local_controller(
            executor=executor, artifact_root=root, task_cap=1, fleet_cap=1,
            worktree_probe=lambda row, index: {"path": row["worktree_path"],
                "identity_sha256": row["worktree_identity_sha256"], "clean": True})
        return controller, lane, executor

    def test_occupied_attempt_requires_recovery_and_preserves_all_evidence(self):
        for maximum in (1, 3):
            for content in (None, b"unclassified retained effect evidence"):
                with self.subTest(maximum=maximum, content=content), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    controller, lane, executor = self.controller(root, maximum)
                    occupied = root / "lane/attempt-001"
                    occupied.mkdir(parents=True)
                    if content is not None:
                        (occupied / "partial-output.bin").write_bytes(content)
                    before = {p.relative_to(root): p.read_bytes() if p.is_file() else None
                              for p in root.rglob("*")}
                    caught = None
                    try:
                        controller._run_lane({"fanout_id": "replay-regression"}, lane)
                    except fanout.ExecutionError as error:
                        caught = error.code
                    self.assertEqual(caught, "retained_evidence_requires_recovery")
                    executor.admit.assert_not_called()
                    executor.bind.assert_not_called()
                    executor.run_one.assert_not_called()
                    self.assertEqual({p.relative_to(root): p.read_bytes() if p.is_file() else None
                                      for p in root.rglob("*")}, before)

    def test_fresh_pre_spawn_expiration_still_retries_same_route_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            controller, lane, executor = self.controller(root, 3)
            executor.pre_spawn_check = mock.Mock(side_effect=[
                fanout.ExecutionError("preflight_expired_before_spawn"), None])
            records = controller._run_lane({"fanout_id": "retry-regression"}, lane)
            self.assertEqual([r["status"] for r in records], ["failed_certain_pre_provider", "execution_unknown"])
            self.assertEqual(executor.run_one.call_count, 1)
            self.assertEqual(executor.run_one.call_args.args[1]["attempt_index"], 2)
            self.assertEqual([r["route"]["name"] for r in records], [lane["route_name"]] * 2)
            decision = root / "lane/attempt-002/retry-decision.json"
            self.assertTrue(decision.is_file())
            self.assertFalse((root / "lane/attempt-003").exists())


if __name__ == "__main__":
    unittest.main()
