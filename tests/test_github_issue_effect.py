import ast
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

from tests.test_github_umbrella_projection import projection, request as projection_request


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "plugins/codexmax-orchestrator/scripts/github_issue_effect.py"
SPEC = importlib.util.spec_from_file_location("github_issue_effect", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
effect = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(effect)


class QueueRunner:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, argv):
        self.calls.append(list(argv))
        return self.responses.pop(0)


def result(value=None, *, returncode=0, timed_out=False, exceeded=None):
    return {
        "returncode": returncode,
        "stdout": json.dumps(value if value is not None else {}).encode(),
        "timed_out": timed_out,
        "exceeded": exceeded,
    }


def prepare():
    projection_receipt = projection.execute(projection_request())
    stable_id = projection_receipt["preview"]["umbrella"]["stable_id"]
    request = {
        "artifact_type": effect.REQUEST_TYPE,
        "operation": "prepare",
        "schema_version": 1,
        "value": {"projection": projection_receipt, "stable_id": stable_id},
    }
    return effect.execute(request)


def apply_request(prepared=None):
    return {
        "artifact_type": effect.REQUEST_TYPE,
        "operation": "simulateApply",
        "schema_version": 1,
        "value": {"prepare": prepared or prepare()},
    }


def issue(prepared, number=7):
    packet = prepared["prepared"]
    return {
        "body": packet["body"],
        "html_url": (
            f"https://{packet['target']['host']}/"
            f"{packet['target']['repository']}/issues/{number}"
        ),
        "labels": [{"name": label} for label in packet["labels"]],
        "node_id": f"I_{number}",
        "number": number,
        "title": packet["title"],
    }


class GithubIssueEffectTests(unittest.TestCase):
    def assert_simulation_only(self, receipt):
        self.assertEqual(receipt["effect_boundary"], effect.SIMULATION_BOUNDARY)
        self.assertFalse(receipt["effect_boundary"]["github_called"])
        self.assertFalse(receipt["effect_boundary"]["github_mutated"])

    def test_prepare_binds_projection_without_commands(self):
        receipt = prepare()
        self.assertEqual(receipt["status"], "prepared")
        self.assertEqual(receipt["command_count"], 0)
        self.assertEqual(receipt["prepare_sha256"], effect._digest(receipt["prepared"]))
        self.assertIn(
            f"<!-- {receipt['prepared']['stable_id']} -->",
            receipt["prepared"]["body"],
        )
        self.assert_simulation_only(receipt)

    def test_missing_marker_simulates_one_create_with_fixed_argv(self):
        prepared = prepare()
        runner = QueueRunner(
            result({"items": [], "total_count": 0}),
            result(issue(prepared)),
        )
        receipt = effect.execute(apply_request(prepared), runner=runner)
        self.assertEqual(receipt["status"], "bound")
        self.assertEqual(receipt["outcome"], "simulated_created")
        self.assertEqual(receipt["command_count"], 2)
        self.assertEqual(runner.calls[0][0:6], [
            "<fake-gh>", "api", "--hostname", "github.com", "--method", "GET",
        ])
        self.assertIn("search/issues", runner.calls[0])
        self.assertEqual(runner.calls[1][0:6], [
            "<fake-gh>", "api", "--hostname", "github.com", "--method", "POST",
        ])
        self.assertIn("repos/Vel-Labs/orcastrata-max/issues", runner.calls[1])
        self.assert_simulation_only(receipt)

    def test_replay_reconciles_one_existing_issue_without_create(self):
        prepared = prepare()
        runner = QueueRunner(result({"items": [issue(prepared)], "total_count": 1}))
        first = effect.execute(apply_request(prepared), runner=runner)
        second_runner = QueueRunner(result({"items": [issue(prepared)], "total_count": 1}))
        second = effect.execute(apply_request(prepared), runner=second_runner)
        self.assertEqual(first["outcome"], "reconciled_existing")
        self.assertEqual(first["issue"], second["issue"])
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(len(second_runner.calls), 1)
        self.assertFalse(any("POST" in call for call in runner.calls + second_runner.calls))

    def test_multiple_or_drifted_markers_fail_before_create(self):
        prepared = prepare()
        multiple = QueueRunner(result({
            "items": [issue(prepared, 7), issue(prepared, 8)], "total_count": 2,
        }))
        receipt = effect.execute(apply_request(prepared), runner=multiple)
        self.assertEqual(receipt["error"]["code"], "marker_ambiguous")
        self.assertEqual(len(multiple.calls), 1)

        drifted = issue(prepared)
        drifted["body"] = "search matched without exact marker"
        drift = QueueRunner(result({"items": [drifted], "total_count": 1}))
        receipt = effect.execute(apply_request(prepared), runner=drift)
        self.assertEqual(receipt["error"]["code"], "marker_search_drift")
        self.assertEqual(len(drift.calls), 1)

        label_drift = issue(prepared)
        label_drift["labels"] = [{"name": "unexpected-label"}]
        drift = QueueRunner(result({"items": [label_drift], "total_count": 1}))
        receipt = effect.execute(apply_request(prepared), runner=drift)
        self.assertEqual(receipt["error"]["code"], "issue_payload_drift")
        self.assertEqual(len(drift.calls), 1)

    def test_uncertain_create_requires_reconcile_and_never_retries(self):
        prepared = prepare()
        runner = QueueRunner(
            result({"items": [], "total_count": 0}),
            result(timed_out=True),
        )
        receipt = effect.execute(apply_request(prepared), runner=runner)
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(receipt["error"]["code"], "effect_outcome_unknown")
        self.assertTrue(receipt["reconcile_required"])
        self.assertEqual(len(runner.calls), 2)

        malformed = QueueRunner(
            result({"items": [], "total_count": 0}),
            {"returncode": 0, "stdout": b"not-json", "timed_out": False, "exceeded": None},
        )
        receipt = effect.execute(apply_request(prepared), runner=malformed)
        self.assertEqual(receipt["status"], "unknown")
        self.assertTrue(receipt["reconcile_required"])
        self.assertEqual(len(malformed.calls), 2)

    def test_tampering_and_missing_fake_runner_fail_closed(self):
        prepared = prepare()
        tampered = copy.deepcopy(prepared)
        tampered["prepared"]["title"] = "Changed after prepare"
        receipt = effect.execute(apply_request(tampered), runner=QueueRunner())
        self.assertEqual(receipt["error"]["code"], "prepare_invalid")

        receipt = effect.execute(apply_request(prepared))
        self.assertEqual(receipt["error"]["code"], "simulation_runner_required")
        self.assertEqual(receipt["command_count"], 0)

        target_drift = projection.execute(projection_request())
        target_drift["target"]["repository"] = "Vel-Labs/other-repository"
        request = {
            "artifact_type": effect.REQUEST_TYPE,
            "operation": "prepare",
            "schema_version": 1,
            "value": {
                "projection": target_drift,
                "stable_id": target_drift["preview"]["umbrella"]["stable_id"],
            },
        }
        receipt = effect.execute(request)
        self.assertEqual(receipt["error"]["code"], "stable_id_target_mismatch")

        forged = copy.deepcopy(prepared)
        forged["prepared"]["target"]["repository"] = "Vel-Labs/other-repository"
        forged["prepared"]["effect_id"] = effect._digest({
            "board_sha256": forged["prepared"]["board_sha256"],
            "graph_id": forged["prepared"]["graph_id"],
            "payload_sha256": forged["prepared"]["payload_sha256"],
            "projection_sha256": forged["prepared"]["projection_sha256"],
            "stable_id": forged["prepared"]["stable_id"],
            "target": forged["prepared"]["target"],
        })
        forged["prepare_sha256"] = effect._digest(forged["prepared"])
        receipt = effect.execute(apply_request(forged), runner=QueueRunner())
        self.assertEqual(receipt["error"]["code"], "prepare_invalid")

        payload_drift = copy.deepcopy(prepared)
        original_effect_id = payload_drift["prepared"]["effect_id"]
        payload_drift["prepared"]["title"] = "Changed after prepare"
        payload_drift["prepared"]["payload_sha256"] = effect._digest({
            "body": payload_drift["prepared"]["body"],
            "labels": payload_drift["prepared"]["labels"],
            "title": payload_drift["prepared"]["title"],
        })
        payload_drift["prepare_sha256"] = effect._digest(payload_drift["prepared"])
        self.assertEqual(payload_drift["prepared"]["effect_id"], original_effect_id)
        receipt = effect.execute(apply_request(payload_drift), runner=QueueRunner())
        self.assertEqual(receipt["error"]["code"], "prepare_invalid")

    def test_cli_has_no_live_apply_or_process_capability(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps(apply_request()),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(
            json.loads(completed.stdout)["error"]["code"],
            "simulation_runner_required",
        )

        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(imports & {"os", "requests", "socket", "subprocess", "urllib"})
        self.assertNotIn("shutil.which", SCRIPT.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
