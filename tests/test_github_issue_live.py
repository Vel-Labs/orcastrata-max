import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.test_github_issue_effect import issue, prepare, result


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "plugins/codexmax-orchestrator/scripts/github_issue_live.py"
SPEC = importlib.util.spec_from_file_location("github_issue_live", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
live = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(live)


class QueueRunner:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, argv, environment):
        self.calls.append((list(argv), dict(environment)))
        return self.responses.pop(0)


def repository(permission="ADMIN"):
    return {
        "archived": False,
        "default_branch": "main",
        "disabled": False,
        "full_name": "Vel-Labs/orcastrata-max",
        "permissions": {
            "admin": permission == "ADMIN",
            "push": permission in {"ADMIN", "WRITE"},
            "pull": True,
        },
    }


class GithubIssueLiveTests(unittest.TestCase):
    def run_live(self, runner, prepared=None, **overrides):
        receipt = prepared or prepare()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prepare.json"
            state = (Path(directory) / "state.json").resolve()
            path.write_text(json.dumps(receipt), encoding="utf-8")
            return live.execute(
                path,
                state,
                expected_host=overrides.get("host", "github.com"),
                expected_repository=overrides.get("repository", "Vel-Labs/orcastrata-max"),
                expected_user=overrides.get("user", "velcrafting"),
                resolver=lambda: "/trusted/gh",
                runner=runner,
                environment_source={"HOME": "/safe", "GH_TOKEN": "must-not-pass"},
            )

    def test_missing_marker_creates_once_after_identity_and_permission(self):
        prepared = prepare()
        runner = QueueRunner(
            result({"login": "velcrafting"}),
            result(repository()),
            result({"items": [], "total_count": 0}),
            result(issue(prepared)),
        )
        receipt = self.run_live(runner, prepared)
        self.assertEqual(receipt["outcome"], "created")
        self.assertEqual(receipt["command_count"], 4)
        self.assertTrue(receipt["effect_boundary"]["github_mutated"])
        self.assertEqual([call[0][6] for call in runner.calls], ["user", "repos/Vel-Labs/orcastrata-max", "search/issues", "repos/Vel-Labs/orcastrata-max/issues"])
        self.assertEqual([call[0][5] for call in runner.calls], ["GET", "GET", "GET", "POST"])
        self.assertNotIn("GH_TOKEN", runner.calls[0][1])

    def test_replay_binds_existing_without_post(self):
        prepared = prepare()
        runner = QueueRunner(
            result({"login": "velcrafting"}),
            result(repository("WRITE")),
            result({"items": [issue(prepared)], "total_count": 1}),
        )
        receipt = self.run_live(runner, prepared)
        self.assertEqual(receipt["outcome"], "reconciled_existing")
        self.assertFalse(receipt["effect_boundary"]["github_mutated"])
        self.assertEqual(len(runner.calls), 3)

    def test_identity_permission_and_target_fail_before_search(self):
        mismatched = QueueRunner(result({"login": "someone-else"}), result(repository()))
        self.assertEqual(self.run_live(mismatched)["error"]["code"], "identity_mismatch")
        self.assertEqual(len(mismatched.calls), 2)

        readonly = QueueRunner(result({"login": "velcrafting"}), result(repository("READ")))
        self.assertEqual(self.run_live(readonly)["error"]["code"], "repository_write_permission_required")
        self.assertEqual(len(readonly.calls), 2)

        no_calls = QueueRunner()
        self.assertEqual(self.run_live(no_calls, repository="Vel-Labs/other")["error"]["code"], "authority_target_mismatch")
        self.assertEqual(no_calls.calls, [])

    def test_unknown_create_requires_reconciliation(self):
        prepared = prepare()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prepare.json"
            state = (Path(directory) / "state.json").resolve()
            path.write_text(json.dumps(prepared), encoding="utf-8")
            first_runner = QueueRunner(
                result({"login": "velcrafting"}),
                result(repository()),
                result({"items": [], "total_count": 0}),
                result(timed_out=True),
            )
            first = live.execute(
                path, state, expected_host="github.com",
                expected_repository="Vel-Labs/orcastrata-max",
                expected_user="velcrafting", resolver=lambda: "/trusted/gh",
                runner=first_runner,
            )
            replay_runner = QueueRunner(
                result({"login": "velcrafting"}),
                result(repository()),
                result({"items": [], "total_count": 0}),
            )
            replay = live.execute(
                path, state, expected_host="github.com",
                expected_repository="Vel-Labs/orcastrata-max",
                expected_user="velcrafting", resolver=lambda: "/trusted/gh",
                runner=replay_runner,
            )
        self.assertEqual(first["status"], "unknown")
        self.assertTrue(first["reconcile_required"])
        self.assertEqual(first["effect_boundary"]["github_mutated"], "unknown")
        self.assertEqual(replay["error"]["code"], "prior_effect_requires_reconciliation")
        self.assertEqual(len(replay_runner.calls), 3)
        self.assertFalse(any(call[0][5] == "POST" for call in replay_runner.calls))

    def test_inactive_repository_and_precommand_error_are_truthful(self):
        inactive = repository()
        inactive["archived"] = True
        runner = QueueRunner(result({"login": "velcrafting"}), result(inactive))
        receipt = self.run_live(runner)
        self.assertEqual(receipt["error"]["code"], "repository_inactive")
        self.assertEqual(receipt["command_count"], 2)
        self.assertTrue(receipt["effect_boundary"]["github_called"])

        receipt = self.run_live(QueueRunner(), repository="Vel-Labs/other")
        self.assertEqual(receipt["command_count"], 0)
        self.assertFalse(receipt["effect_boundary"]["github_called"])

    def test_successful_post_with_final_state_failure_is_unknown(self):
        prepared = prepare()
        runner = QueueRunner(
            result({"login": "velcrafting"}),
            result(repository()),
            result({"items": [], "total_count": 0}),
            result(issue(prepared)),
        )
        real_write = live._write_state
        writes = 0

        def fail_final(path, value, *, initial):
            nonlocal writes
            writes += 1
            if writes == 2:
                raise OSError("simulated final state failure")
            return real_write(path, value, initial=initial)

        with mock.patch.object(live, "_write_state", side_effect=fail_final):
            receipt = self.run_live(runner, prepared)
        self.assertEqual(receipt["status"], "unknown")
        self.assertTrue(receipt["reconcile_required"])
        self.assertEqual(receipt["effect_boundary"]["github_mutated"], "unknown")

    def test_prepare_path_must_be_regular_and_checksum_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.json"
            target.write_text(json.dumps(prepare()), encoding="utf-8")
            alias = Path(directory) / "alias.json"
            alias.symlink_to(target)
            receipt = live.execute(
                alias,
                (Path(directory) / "state.json").resolve(),
                expected_host="github.com",
                expected_repository="Vel-Labs/orcastrata-max",
                expected_user="velcrafting",
                resolver=lambda: "/trusted/gh",
                runner=QueueRunner(),
            )
        self.assertEqual(receipt["status"], "error")


if __name__ == "__main__":
    unittest.main()
