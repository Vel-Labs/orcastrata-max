import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "plugins" / "codexmax-orchestrator" / "scripts"))
import manage_artifact_lifecycle as lifecycle


class LifecycleAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="c3-lifecycle-"))
        self.attempt = self.tmp / "attempt"
        self.attempt.mkdir()
        self.manifest = {
            "state": "integrated",
            "identity": {"task_id": "C3-04B"},
            "worker": {"model": "Qwopus"},
            "usage": {},
            "evidence": {"compact_handoff": {"path": "compact-worker-handoff.json", "sha256": "a" * 64}},
        }
        self.handoff = {"path": "compact-worker-handoff.json", "sha256": "a" * 64}

    def _accept(self, authority):
        args = argparse.Namespace(authority=authority, acceptance_id="accept-1")
        manifest = {**self.manifest, "evidence": {**self.manifest["evidence"]}}
        with patch.object(lifecycle, "_existing", return_value=(self.attempt, manifest)), \
             patch.object(lifecycle, "_validate_bound_evidence"), \
             patch.object(lifecycle, "_descriptor", return_value=self.handoff), \
             patch.object(lifecycle, "_write_json", return_value={"path": "parent-acceptance.json"}), \
             patch.object(lifecycle, "_save_manifest"):
            result = lifecycle.accept(args)
        return result, manifest

    def test_parent_and_legacy_alias_emit_canonical_parent(self):
        for authority in ("parent", "parent_sol"):
            with self.subTest(authority=authority):
                result, manifest = self._accept(authority)
                self.assertEqual(result["status"], "accepted")
                self.assertEqual(manifest["evidence"]["parent_acceptance"]["path"], "parent-acceptance.json")


    def test_real_prepare_to_accept_journey_and_bound_handoff(self):
        fixture_root = Path(__file__).parents[1] / "docs" / "qwopus-loop" / "run" / "lifecycle-test-fixture"
        shutil.rmtree(fixture_root, ignore_errors=True)
        fixture_root.mkdir(parents=True)
        script = Path(__file__).parents[1] / "plugins" / "codexmax-orchestrator" / "scripts" / "manage_artifact_lifecycle.py"

        def run(attempt, command, *extra, check=True):
            args = [sys.executable, str(script), command, "--root", str(fixture_root), "--goal", "fixture-goal", "--task", "fixture-task", "--attempt", attempt, *extra]
            return subprocess.run(args, check=check, text=True, capture_output=True)

        try:
            for attempt, authority in (("attempt-parent", "parent"), ("attempt-legacy", "parent_sol"), ("attempt-drift", "drift")):
                run(attempt, "prepare", "--provider", "local", "--model", "Qwopus", "--route", "studio", "--role", "worker", "--runtime", "local")
                attempt_root = fixture_root / ".codexmax" / "runs" / "fixture-goal" / "fixture-task" / attempt
                (attempt_root / "raw" / "result.json").write_text(json.dumps({"status": "candidate_ready", "finding": "bounded"}) + "\n")
                run(attempt, "record-result")
                (attempt_root / "accepted" / "quality-check.json").write_text("{\"status\":\"passed\"}\n")
                run(attempt, "quality-check")
                (attempt_root / "accepted" / "integration.json").write_text("{\"status\":\"integrated\"}\n")
                run(attempt, "integrate")
                run(attempt, "handoff", "--summary", "fixture handoff")
                handoff_path = attempt_root / "compact-worker-handoff.json"
                if authority == "drift":
                    # A changed handoff descriptor is rejected before acceptance.
                    handoff_path.write_text("tampered\n")
                    failed = run(attempt, "status", check=False)
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertIn("descriptor_drift", failed.stdout + failed.stderr)
                    continue
                run(attempt, "accept", "--authority", authority, "--acceptance-id", "accept-" + attempt)
                acceptance = json.loads((attempt_root / "parent-acceptance.json").read_text())
                self.assertEqual(acceptance["authority"], "Parent")
        finally:
            shutil.rmtree(fixture_root, ignore_errors=True)

    def test_worker_and_supervisor_cannot_accept(self):
        for authority in ("worker", "supervisor"):
            with self.subTest(authority=authority):
                with self.assertRaises(lifecycle.LifecycleError) as ctx:
                    self._accept(authority)
                self.assertEqual(ctx.exception.code, "acceptance_authority_invalid")


if __name__ == "__main__":
    unittest.main()
