import ast
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).parents[1]
PLUGIN = ROOT / "plugins/codexmax-orchestrator"
SCRIPT = PLUGIN / "scripts/github_umbrella_projection.py"
TEMPLATE = PLUGIN / "assets/templates/workgraph-bounded.json"
DIRECT_TEMPLATE = PLUGIN / "assets/templates/workgraph-direct.json"
SPEC = importlib.util.spec_from_file_location("github_umbrella_projection", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
projection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(projection)
ADAPTER_SCRIPT = PLUGIN / "scripts/workgraph_goalbuddy_adapter.py"
ADAPTER_SPEC = importlib.util.spec_from_file_location("workgraph_goalbuddy_adapter", ADAPTER_SCRIPT)
assert ADAPTER_SPEC is not None and ADAPTER_SPEC.loader is not None
adapter = importlib.util.module_from_spec(ADAPTER_SPEC)
ADAPTER_SPEC.loader.exec_module(adapter)


def snapshot(statuses=None, active_task="WI-SETUP"):
    statuses = statuses or {"WI-BUILD": "queued", "WI-SETUP": "active"}
    return {
        "active_task": active_task,
        "board_sha256": "sha256:" + "a" * 64,
        "canonical_owner": "GoalBuddy",
        "capabilities": {
            "apply": True,
            "migration_available": False,
            "migration_required": False,
            "pinned_current_schema_version": 2,
            "recognized_next_schema_version": 3,
            "recover": True,
            "snapshot": True,
        },
        "operation": "snapshot",
        "protocol": "workgraph_goalbuddy_adapter",
        "schema_version": 1,
        "state_schema_version": 2,
        "status": "ok",
        "task_statuses": [
            {"status": status, "task_id": task_id}
            for task_id, status in sorted(statuses.items())
        ],
    }


def request():
    graph = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    return {
        "artifact_type": projection.REQUEST_TYPE,
        "goalbuddy_snapshot": snapshot(),
        "presentation": {
            "umbrella": {
                "acceptance_criteria": ["Every bounded issue is complete."],
                "labels": ["orcastrata"],
                "non_goals": ["Do not merge pull requests."],
                "outcome": "Deliver the bounded project.",
                "title": "Bounded project",
            },
            "issues": [
                {
                    "labels": ["build"],
                    "non_goals": ["Do not change setup."],
                    "title": "Build output",
                    "work_item_id": "WI-BUILD",
                },
                {
                    "labels": ["setup"],
                    "non_goals": ["Do not build output."],
                    "title": "Prepare setup",
                    "work_item_id": "WI-SETUP",
                },
            ],
        },
        "schema_version": 1,
        "target": {"host": "github.com", "repository": "Vel-Labs/orcastrata-max"},
        "workgraph": graph,
    }


class GithubUmbrellaProjectionTests(unittest.TestCase):
    def test_valid_preview_is_complete_and_has_no_effects(self):
        payload = request()
        original = copy.deepcopy(payload)
        receipt = projection.execute(payload)

        self.assertEqual(receipt["status"], "ok")
        self.assertEqual(payload, original)
        self.assertTrue(all(value is False for value in receipt["effect_boundary"].values()))
        issues = receipt["preview"]["issues"]
        self.assertEqual([row["work_item_id"] for row in issues], ["WI-BUILD", "WI-SETUP"])
        self.assertFalse(issues[0]["ready"])
        self.assertTrue(issues[1]["ready"])
        for heading in (
            "## Outcome", "## Scope", "## Non-goals", "## Acceptance criteria",
            "## Validation", "## Dependencies", "## Stop condition", "## Orcastrata state",
        ):
            self.assertIn(heading, issues[0]["body"])
        self.assertIn("GoalBuddy status: `queued`", issues[0]["body"])
        self.assertNotIn("GoalBuddy status: `blocked`", issues[0]["body"])

    def test_projection_is_deterministic_and_stable_across_display_edits(self):
        first = request()
        second = copy.deepcopy(first)
        second["workgraph"]["work_items"].reverse()
        second["goalbuddy_snapshot"]["task_statuses"].reverse()
        second["presentation"]["issues"].reverse()
        first_receipt = projection.execute(first)
        second_receipt = projection.execute(second)
        self.assertEqual(first_receipt["preview"], second_receipt["preview"])
        self.assertEqual(first_receipt["projection_sha256"], second_receipt["projection_sha256"])

        edited = request()
        edited["presentation"]["umbrella"]["title"] = "Renamed project"
        edited["presentation"]["issues"][0]["title"] = "Renamed issue"
        edited_receipt = projection.execute(edited)
        self.assertEqual(
            first_receipt["preview"]["umbrella"]["stable_id"],
            edited_receipt["preview"]["umbrella"]["stable_id"],
        )
        self.assertEqual(
            first_receipt["preview"]["issues"][0]["stable_id"],
            edited_receipt["preview"]["issues"][0]["stable_id"],
        )

        recased = request()
        recased["target"]["repository"] = "vel-labs/ORCASTRATA-MAX"
        recased_receipt = projection.execute(recased)
        self.assertEqual(
            first_receipt["preview"]["umbrella"]["stable_id"],
            recased_receipt["preview"]["umbrella"]["stable_id"],
        )
        self.assertEqual(
            [row["stable_id"] for row in first_receipt["preview"]["issues"]],
            [row["stable_id"] for row in recased_receipt["preview"]["issues"]],
        )

    def test_real_goalbuddy_snapshot_round_trip_is_read_only(self):
        board = """version: 2

goal:
  status: active

active_task: WI-SETUP

tasks:
  - id: WI-SETUP
    type: pm
    status: active
  - id: WI-BUILD
    type: worker
    status: queued
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.yaml"
            path.write_text(board, encoding="utf-8")
            payload = request()
            payload["goalbuddy_snapshot"] = adapter.snapshot(path)
            receipt = projection.execute(payload)
            self.assertEqual(receipt["status"], "ok")
            self.assertEqual(path.read_text(encoding="utf-8"), board)
            self.assertEqual([item.name for item in Path(directory).iterdir()], ["state.yaml"])

    def test_invalid_graph_and_unbounded_items_fail_closed(self):
        cyclic = request()
        cyclic["workgraph"]["work_items"][0]["relationships"]["blocked_by"] = ["WI-BUILD"]
        self.assertEqual(projection.execute(cyclic)["error"]["code"], "workgraph_invalid")

        direct = request()
        direct_graph = json.loads(DIRECT_TEMPLATE.read_text(encoding="utf-8"))
        direct["workgraph"] = direct_graph
        direct_id = direct_graph["work_items"][0]["id"]
        direct["goalbuddy_snapshot"] = snapshot({direct_id: "active"}, direct_id)
        direct["presentation"]["issues"] = [{
            "labels": [], "non_goals": ["No extra work."],
            "title": "Direct", "work_item_id": direct_id,
        }]
        self.assertEqual(projection.execute(direct)["error"]["code"], "workgraph_item_not_bounded")

    def test_goalbuddy_and_metadata_mismatches_fail_closed(self):
        missing_task = request()
        missing_task["goalbuddy_snapshot"] = snapshot({"WI-SETUP": "active"})
        self.assertEqual(
            projection.execute(missing_task)["error"]["code"],
            "goalbuddy_workgraph_task_mismatch",
        )

        bad_active = request()
        bad_active["goalbuddy_snapshot"]["active_task"] = "WI-BUILD"
        self.assertEqual(projection.execute(bad_active)["error"]["code"], "goalbuddy_snapshot_invalid")

        duplicate_metadata = request()
        duplicate_metadata["presentation"]["issues"][1]["work_item_id"] = "WI-BUILD"
        self.assertEqual(
            projection.execute(duplicate_metadata)["error"]["code"],
            "issue_metadata_duplicate",
        )

    def test_more_than_fifteen_items_fails_closed(self):
        payload = request()
        graph = json.loads(DIRECT_TEMPLATE.read_text(encoding="utf-8"))
        base = graph["work_items"][0]
        graph["work_items"] = []
        statuses = {}
        issues = []
        for index in range(16):
            item = copy.deepcopy(base)
            item["id"] = f"WI-{index:02d}"
            graph["work_items"].append(item)
            statuses[item["id"]] = "queued"
            issues.append({
                "labels": [], "non_goals": ["No extra work."],
                "title": item["id"], "work_item_id": item["id"],
            })
        payload["workgraph"] = graph
        payload["goalbuddy_snapshot"] = snapshot(statuses, None)
        payload["presentation"]["issues"] = issues
        self.assertEqual(
            projection.execute(payload)["error"]["code"],
            "workgraph_item_count_invalid",
        )

    def test_cli_and_source_boundaries_are_local_and_fail_closed(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input='{"schema_version":1,"schema_version":1}',
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "error")

        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(imports & {"requests", "socket", "subprocess", "urllib"})


if __name__ == "__main__":
    unittest.main()
