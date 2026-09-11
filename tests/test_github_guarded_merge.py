import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

from tests.test_github_cli_read import QueueRunner, json_lines, result
from tests.test_github_issue_live import repository


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "plugins/codexmax-orchestrator/scripts/github_guarded_merge.py"
SPEC = importlib.util.spec_from_file_location("github_guarded_merge", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
merge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(merge)

HEAD = "b" * 40
BASE = "a" * 40
MARKER = "orcastrata:lifecycle:T060-BASE-PR:issue:7"
FILENAME = "src/app.py"
SCOPE = "sha256:" + hashlib.sha256(json.dumps([FILENAME], separators=(",", ":")).encode()).hexdigest()


def request():
    return {
        "schema_version": 1,
        "artifact_type": merge.REQUEST_TYPE,
        "target": {"host": "github.com", "repository": "Vel-Labs/orcastrata-max"},
        "expected_user": "velcrafting",
        "pull_request": {
            "number": 12,
            "base": "main",
            "expected_base_sha": BASE,
            "expected_head_sha": HEAD,
            "lifecycle_marker": MARKER,
        },
        "scope": {"total_count": 1, "filenames_sha256": SCOPE},
        "evidence": {
            "goalbuddy_sha256": "sha256:" + "0" * 64,
            "independent_audit_sha256": "sha256:" + "0" * 64,
            "independent_auditor_id": "/root/t080_guarded_merge_audit",
            "auditor_projection_sha256": "sha256:" + "0" * 64,
        },
    }


def pull(*, head=HEAD, base=BASE, marker=MARKER, mergeable=True, state="clean", merged=False, merge_sha=None, pr_state=None):
    return {
        "base": {"ref": "main", "sha": base},
        "body": f"Closes #7\n<!-- {marker} -->",
        "draft": False,
        "head": {"ref": "feature", "sha": head},
        "mergeable": mergeable,
        "mergeable_state": state,
        "merge_commit_sha": merge_sha,
        "merged": merged,
        "number": 12,
        "state": pr_state or ("closed" if merged else "open"),
        "title": "Feature",
        "updated_at": "2026-09-02T00:00:00Z",
    }


def diff_row():
    return {"additions": 1, "changes": 1, "deletions": 0, "filename": FILENAME, "status": "modified"}


def board(status="done", *, valid=True, task_id="T080"):
    active_fields = """    allowed_files:
      - src/app.py
    verify:
      - test
    stop_if:
      - unsafe
""" if valid else ""
    return f"""version: 2
goal:
  slug: guarded-merge-test
  status: active
active_task: {task_id}
rules:
  pm_owns_state: true
tasks:
  - id: T060
    type: worker
    status: {status}
    allowed_files:
      - src/app.py
    receipt:
      result: {status}
      decision: approved
      changed_files:
        - src/app.py
      commands:
        - command: test
          status: pass
      summary: done
  - id: T070
    type: auditor
    status: done
    receipt:
      result: done
      decision: approved
      commands:
        - command: audit
          status: pass
  - id: {task_id}
    type: worker
    status: active
    dependencies:
      - T060
      - T070
{active_fields}
""".encode()


def audit(payload, board_sha, task_id="T080"):
    return {
        "schema_version": 1,
        "artifact_type": merge.AUDIT_TYPE,
        "task_id": task_id,
        "auditor": {
            "read_only": True,
            "runtime_child_id": payload["evidence"]["independent_auditor_id"],
            "runtime_surface": "codex_collaboration",
        },
        "verdict": "ACCEPT",
        "board_sha256": board_sha,
        "pull_request": {
            "number": payload["pull_request"]["number"],
            "base_sha": payload["pull_request"]["expected_base_sha"],
            "head_sha": payload["pull_request"]["expected_head_sha"],
            "total_count": payload["scope"]["total_count"],
            "filenames_sha256": payload["scope"]["filenames_sha256"],
        },
    }


def rules(*, approvals=0, app_id=None, last_push=False):
    rows = []
    if app_id is not None:
        rows.append({
            "type": "required_status_checks",
            "parameters": {"required_status_checks": [{"context": "test", "integration_id": app_id}]},
        })
    if approvals or last_push:
        rows.append({
            "type": "pull_request",
            "parameters": {
                "required_approving_review_count": approvals,
                "dismiss_stale_reviews_on_push": True,
                "require_code_owner_review": False,
                "require_last_push_approval": last_push,
                "required_review_thread_resolution": False,
            },
        })
    return rows


def ready_responses(*, pull_value=None, rule_rows=None, checks=None, reviews=None, final_pull=None, check_pull=None, review_pull=None, diff_pull=None, merge_result=None, repository_value=None):
    pull_value = pull_value or pull()
    final_pull = final_pull or pull_value
    checks = checks or []
    reviews = reviews or []
    responses = [
        result({"login": "velcrafting"}), result(repository_value or repository()),
        result(pull_value),
        result({"name": "main", "protected": False}), result(rule_rows or []),
        result(check_pull or pull_value), result({"total_count": len(checks), "check_runs": checks}),
        result(review_pull or pull_value), result(json_lines(reviews)),
        result(diff_pull or pull_value), result(json_lines([diff_row()])),
        result(final_pull),
    ]
    if merge_result is not None:
        responses.append(merge_result)
    return responses


class GithubGuardedMergeTests(unittest.TestCase):
    def prepare(
        self, directory, payload=None, *, task_id="T080",
        dependency_status="done", audit_verdict="ACCEPT", valid_board=True,
    ):
        root = Path(directory).resolve()
        _, request_name, _, audit_name, projection_name = merge._task_artifacts(task_id)
        (root / f"notes/{task_id.lower()}-effects").mkdir(parents=True)
        payload = payload or request()
        board_raw = board(dependency_status, valid=valid_board, task_id=task_id)
        board_sha = merge._bytes_digest(board_raw)
        audit_value = audit(payload, board_sha, task_id)
        audit_value["verdict"] = audit_verdict
        audit_raw = json.dumps(audit_value, sort_keys=True, separators=(",", ":")).encode()
        projection = {
            "schema_version": 1,
            "status": "ready",
            "dispatch_performed": True,
            "provider_dispatch": False,
            "dispatch_receipt": {
                "child_task_id": f"{task_id}-A01",
                "runtime_child_id": payload["evidence"]["independent_auditor_id"],
                "runtime_surface": "codex_collaboration",
                "semantic_role": "independent_auditor",
                "provider_dispatch": False,
            },
        }
        projection_raw = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()
        payload["evidence"] = {
            "goalbuddy_sha256": board_sha,
            "independent_audit_sha256": merge._bytes_digest(audit_raw),
            "independent_auditor_id": payload["evidence"]["independent_auditor_id"],
            "auditor_projection_sha256": merge._bytes_digest(projection_raw),
        }
        (root / merge.BOARD_NAME).write_bytes(board_raw)
        (root / audit_name).write_bytes(audit_raw)
        (root / projection_name).write_bytes(projection_raw)
        (root / request_name).write_text(json.dumps(payload), encoding="utf-8")
        return root, payload

    def execute(self, root, runner):
        return merge.execute(
            root,
            expected_host="github.com",
            expected_repository="Vel-Labs/orcastrata-max",
            expected_user="velcrafting",
            runner=runner,
            resolver=lambda: "/trusted/gh",
            environment_source={"HOME": "/safe", "GH_TOKEN": "must-not-pass"},
        )

    def write_state(self, root, payload, status):
        (root / merge.STATE_NAME).write_text(json.dumps(merge._state(payload, status)), encoding="utf-8")

    def test_one_exact_merge_after_evidence_and_fresh_bound_gates(self):
        checks = [{"app": {"id": 7, "name": "CI"}, "conclusion": "success", "name": "test", "status": "completed"}]
        reviews = [{"commit_id": HEAD, "reviewer": "reviewer", "state": "APPROVED", "submitted_at": "2026-09-02T01:00:00Z"}]
        runner = QueueRunner(*ready_responses(
            rule_rows=rules(approvals=1, app_id=7), checks=checks, reviews=reviews,
            merge_result=result({"merged": True, "sha": "e" * 40}),
        ))
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.prepare(directory)
            receipt = self.execute(root, runner)
            saved = json.loads((root / merge.STATE_NAME).read_text())
        self.assertEqual(receipt["outcome"], "merged")
        self.assertEqual(saved["status"], "bound")
        self.assertEqual(runner.calls[-1][0], [
            "/trusted/gh", "api", "--hostname", "github.com", "--method", "PUT",
            "repos/Vel-Labs/orcastrata-max/pulls/12/merge", "-f", f"sha={HEAD}",
        ])
        self.assertNotIn("GH_TOKEN", runner.calls[-1][1])

    def test_operator_bound_target_supports_another_repository(self):
        payload = request()
        payload["target"] = {"host": "github.com", "repository": "Acme/widgets"}
        repository_value = repository()
        repository_value["full_name"] = "Acme/widgets"
        runner = QueueRunner(*ready_responses(
            repository_value=repository_value,
            merge_result=result({"merged": True, "sha": "e" * 40}),
        ))
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.prepare(directory, payload)
            receipt = merge.execute(
                root,
                expected_host="github.com",
                expected_repository="Acme/widgets",
                expected_user="velcrafting",
                runner=runner,
                resolver=lambda: "/trusted/gh",
                environment_source={"HOME": "/safe"},
            )
        self.assertEqual(receipt["outcome"], "merged")
        self.assertEqual(runner.calls[-1][0][6], "repos/Acme/widgets/pulls/12/merge")

    def test_operator_bound_target_mismatch_stops_before_github(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.prepare(directory)
            runner = QueueRunner()
            receipt = merge.execute(
                root,
                expected_host="github.com",
                expected_repository="Acme/widgets",
                expected_user="velcrafting",
                runner=runner,
                resolver=lambda: "/trusted/gh",
            )
        self.assertEqual(receipt["error"]["code"], "authority_target_mismatch")
        self.assertEqual(runner.calls, [])

    def test_selected_task_derives_paths_and_binds_board_and_auditor(self):
        payload = request()
        payload["evidence"]["independent_auditor_id"] = "/root/t090_guarded_merge_audit"
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.prepare(directory, payload, task_id="T090")
            receipt = merge.execute(
                root,
                expected_host="github.com",
                expected_repository="Vel-Labs/orcastrata-max",
                expected_user="velcrafting",
                task_id="T090",
                runner=QueueRunner(*ready_responses(
                    merge_result=result({"merged": True, "sha": "e" * 40}),
                )),
                resolver=lambda: "/trusted/gh",
                environment_source={"HOME": "/safe"},
            )
            saved = json.loads((root / "notes/t090-effects/merge-state.json").read_text())
        self.assertEqual(receipt["outcome"], "merged")
        self.assertEqual(saved["status"], "bound")

    def test_selected_task_rejects_cross_task_evidence(self):
        cases = (
            ("board", "goalbuddy_task_binding_mismatch"),
            ("audit", "independent_audit_binding_mismatch"),
            ("projection", "auditor_projection_invalid"),
        )
        for evidence, code in cases:
            with self.subTest(evidence=evidence), tempfile.TemporaryDirectory() as directory:
                root, payload = self.prepare(directory, task_id="T090")
                request_path = root / "notes/t090-effects/merge-request.json"
                if evidence == "board":
                    board_raw = board(task_id="T080")
                    audit_path = root / "notes/t090-effects/independent-audit.json"
                    audit_value = json.loads(audit_path.read_text())
                    audit_value["board_sha256"] = merge._bytes_digest(board_raw)
                    audit_raw = json.dumps(audit_value, sort_keys=True, separators=(",", ":")).encode()
                    (root / merge.BOARD_NAME).write_bytes(board_raw)
                    audit_path.write_bytes(audit_raw)
                    payload["evidence"]["goalbuddy_sha256"] = merge._bytes_digest(board_raw)
                    payload["evidence"]["independent_audit_sha256"] = merge._bytes_digest(audit_raw)
                elif evidence == "audit":
                    audit_path = root / "notes/t090-effects/independent-audit.json"
                    audit_value = json.loads(audit_path.read_text())
                    audit_value["task_id"] = "T080"
                    audit_raw = json.dumps(audit_value, sort_keys=True, separators=(",", ":")).encode()
                    audit_path.write_bytes(audit_raw)
                    payload["evidence"]["independent_audit_sha256"] = merge._bytes_digest(audit_raw)
                else:
                    projection_path = root / "notes/t090-audit-runtime-projection.final.json"
                    projection = json.loads(projection_path.read_text())
                    projection["dispatch_receipt"]["child_task_id"] = "T080-A01"
                    projection_raw = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()
                    projection_path.write_bytes(projection_raw)
                    payload["evidence"]["auditor_projection_sha256"] = merge._bytes_digest(projection_raw)
                request_path.write_text(json.dumps(payload), encoding="utf-8")
                runner = QueueRunner()
                receipt = merge.execute(
                    root,
                    expected_host="github.com",
                    expected_repository="Vel-Labs/orcastrata-max",
                    expected_user="velcrafting",
                    task_id="T090",
                    runner=runner,
                    resolver=lambda: "/trusted/gh",
                )
            self.assertEqual(receipt["error"]["code"], code)
            self.assertEqual(runner.calls, [])

    def test_task_identifier_is_closed(self):
        for task_id in ("t090", "T90", "T090-A01", "T1000", "T090/../T080"):
            with self.subTest(task_id=task_id), tempfile.TemporaryDirectory() as directory:
                runner = QueueRunner()
                receipt = merge.execute(
                    Path(directory).resolve(),
                    expected_host="github.com",
                    expected_repository="Vel-Labs/orcastrata-max",
                    expected_user="velcrafting",
                    task_id=task_id,
                    runner=runner,
                    resolver=lambda: "/trusted/gh",
                )
            self.assertEqual(receipt["error"]["code"], "task_id_invalid")
            self.assertEqual(runner.calls, [])

    def test_stale_scope_conflict_checks_review_marker_and_observation_drift_fail(self):
        cases = [
            ("head_sha_mismatch", ready_responses(pull_value=pull(head="f" * 40))),
            ("pull_request_conflict_or_unready", ready_responses(pull_value=pull(mergeable=False, state="dirty"))),
            ("board_marker_mismatch", ready_responses(pull_value=pull(marker="orcastrata:lifecycle:OTHER:issue:7"))),
            ("checks_not_green", ready_responses(checks=[{"app": {"id": 1, "name": "CI"}, "conclusion": None, "name": "test", "status": "in_progress"}])),
            ("required_check_missing", ready_responses(rule_rows=rules(app_id=9), checks=[{"app": {"id": 1, "name": "CI"}, "conclusion": "success", "name": "test", "status": "completed"}])),
            ("required_review_policy_unmet", ready_responses(rule_rows=rules(approvals=1))),
            ("check_binding_mismatch", ready_responses(check_pull=pull(head="f" * 40))),
            ("review_binding_mismatch", ready_responses(review_pull=pull(head="f" * 40))),
            ("diff_binding_mismatch", ready_responses(diff_pull=pull(head="f" * 40))),
            ("merge_reconciliation_required", ready_responses(final_pull=pull(head="f" * 40))),
        ]
        for code, responses in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                root, _ = self.prepare(directory)
                runner = QueueRunner(*responses)
                receipt = self.execute(root, runner)
                self.assertEqual(receipt["error"]["code"], code)
                self.assertFalse(any("--method" in argv and argv[argv.index("--method") + 1] == "PUT" for argv, _ in runner.calls))

        payload = request()
        payload["scope"]["total_count"] = 2
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.prepare(directory, payload)
            receipt = self.execute(root, QueueRunner(*ready_responses()))
        self.assertEqual(receipt["error"]["code"], "scope_mismatch")

    def test_final_read_after_effect_started_preserves_or_resolves_reconciliation(self):
        cases = [
            (
                "read_failure",
                ready_responses()[:-1] + [result(timed_out=True)],
                "unknown",
                "merge_reconciliation_required",
                "effect_started",
            ),
            (
                "externally_merged",
                ready_responses(final_pull=pull(merged=True, merge_sha="e" * 40)),
                "bound",
                "reconciled_merged",
                "bound",
            ),
            (
                "closed_unmerged",
                ready_responses(final_pull=pull(pr_state="closed")),
                "ready",
                "reconciled_unmerged",
                "reconciled_unmerged",
            ),
        ]
        for label, responses, status, outcome, saved_status in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root, _ = self.prepare(directory)
                runner = QueueRunner(*responses)
                receipt = self.execute(root, runner)
                saved = json.loads((root / merge.STATE_NAME).read_text())
                self.assertEqual(receipt["status"], status)
                self.assertEqual(receipt.get("outcome", receipt.get("error", {}).get("code")), outcome)
                self.assertEqual(saved["status"], saved_status)
                self.assertFalse(any(
                    "--method" in argv and argv[argv.index("--method") + 1] == "PUT"
                    for argv, _ in runner.calls
                ))

    def test_canonical_dependency_and_audit_files_are_verified(self):
        for dependency_status, audit_verdict, code in (
            ("queued", "ACCEPT", "dependency_not_ready"),
            ("done", "REVISE", "independent_audit_binding_mismatch"),
        ):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                root, _ = self.prepare(directory, dependency_status=dependency_status, audit_verdict=audit_verdict)
                runner = QueueRunner()
                receipt = self.execute(root, runner)
                self.assertEqual(receipt["error"]["code"], code)
                self.assertEqual(runner.calls, [])

        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.prepare(directory, valid_board=False)
            runner = QueueRunner()
            receipt = self.execute(root, runner)
            self.assertEqual(receipt["error"]["code"], "goalbuddy_state_invalid")
            self.assertEqual(runner.calls, [])

        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.prepare(directory)
            (root / merge.AUDIT_NAME).write_text("{}", encoding="utf-8")
            receipt = self.execute(root, QueueRunner())
        self.assertEqual(receipt["error"]["code"], "independent_audit_digest_mismatch")

        with tempfile.TemporaryDirectory() as directory:
            root, payload = self.prepare(directory)
            projection_path = root / merge.AUDITOR_PROJECTION_NAME
            projection = json.loads(projection_path.read_text())
            projection["dispatch_receipt"]["runtime_child_id"] = "/root/other_auditor"
            projection_raw = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()
            projection_path.write_bytes(projection_raw)
            payload["evidence"]["auditor_projection_sha256"] = merge._bytes_digest(projection_raw)
            (root / merge.REQUEST_NAME).write_text(json.dumps(payload), encoding="utf-8")
            receipt = self.execute(root, QueueRunner())
        self.assertEqual(receipt["error"]["code"], "auditor_projection_invalid")

    def test_rulesets_equal_review_timestamp_and_last_push_fail_closed(self):
        unsupported = [{"type": "required_deployments", "parameters": {}}]
        equal_reviews = [
            {"commit_id": HEAD, "reviewer": "reviewer", "state": "APPROVED", "submitted_at": "2026-09-02T01:00:00Z"},
            {"commit_id": HEAD, "reviewer": "reviewer", "state": "CHANGES_REQUESTED", "submitted_at": "2026-09-02T01:00:00Z"},
        ]
        cases = [
            ("github_branch_rule_unsupported", ready_responses(rule_rows=unsupported)),
            ("review_timestamp_ambiguous", ready_responses(reviews=equal_reviews)),
            ("merge_policy_unsupported", ready_responses(rule_rows=rules(last_push=True))),
        ]
        for code, responses in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                root, _ = self.prepare(directory)
                receipt = self.execute(root, QueueRunner(*responses))
                self.assertEqual(receipt["error"]["code"], code)

    def test_unknown_reconciliation_precedes_retry_gates_and_preserves_unknown_on_drift(self):
        cases = [
            (pull(head="f" * 40), "merge_reconciliation_required"),
            (pull(merged=True, merge_sha=None), "merge_reconciliation_required"),
        ]
        for observed, code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                root, payload = self.prepare(directory)
                self.write_state(root, payload, "unknown")
                runner = QueueRunner(result({"login": "velcrafting"}), result(repository()), result(observed))
                receipt = self.execute(root, runner)
                self.assertEqual(receipt["error"]["code"], code)
                self.assertTrue(receipt["reconcile_required"])
                self.assertEqual(len(runner.calls), 3)

        with tempfile.TemporaryDirectory() as directory:
            root, payload = self.prepare(directory)
            self.write_state(root, payload, "unknown")
            (root / merge.REQUEST_NAME).write_text("{}", encoding="utf-8")
            receipt = self.execute(root, QueueRunner())
            self.assertEqual(receipt["error"]["code"], "merge_reconciliation_required")
            self.assertTrue(receipt["reconcile_required"])

        with tempfile.TemporaryDirectory() as directory:
            root, payload = self.prepare(directory)
            self.write_state(root, payload, "unknown")
            closed = pull(pr_state="closed")
            reconciled = self.execute(root, QueueRunner(result({"login": "velcrafting"}), result(repository()), result(closed)))
            self.assertEqual(reconciled["outcome"], "reconciled_unmerged")
            self.assertFalse(reconciled["reconcile_required"])
            failed = self.execute(root, QueueRunner(*ready_responses(checks=[{"app": {"id": 1}, "conclusion": "failure", "name": "test", "status": "completed"}])))
            self.assertEqual(failed["error"]["code"], "checks_not_green")
            self.assertFalse(failed["reconcile_required"])

    def test_unknown_effect_reconciles_then_retries_and_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.prepare(directory)
            first = self.execute(root, QueueRunner(*ready_responses(merge_result=result(timed_out=True))))
            self.assertTrue(first["reconcile_required"])
            reconciled = self.execute(root, QueueRunner(result({"login": "velcrafting"}), result(repository()), result(pull())))
            self.assertEqual(reconciled["outcome"], "reconciled_unmerged")
            retried = self.execute(root, QueueRunner(*ready_responses(merge_result=result({"merged": True, "sha": "e" * 40}))))
            self.assertEqual(retried["outcome"], "merged")
            replay = self.execute(root, QueueRunner(
                result({"login": "velcrafting"}), result(repository()),
                result(pull(merged=True, merge_sha="e" * 40)),
            ))
            self.assertEqual(replay["outcome"], "reconciled_merged")

    def test_exclusive_lock_and_directory_boundary_block_a_second_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.prepare(directory)
            descriptor = os.open(root / merge.LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                runner = QueueRunner()
                receipt = self.execute(root, runner)
            finally:
                os.close(descriptor)
            self.assertEqual(receipt["error"]["code"], "merge_effect_in_progress")
            self.assertTrue(receipt["reconcile_required"])
            self.assertEqual(runner.calls, [])

        relative = merge.execute(
            Path("relative"),
            expected_host="github.com",
            expected_repository="Vel-Labs/orcastrata-max",
            expected_user="velcrafting",
            runner=QueueRunner(),
            resolver=lambda: "/trusted/gh",
        )
        self.assertEqual(relative["error"]["code"], "execution_directory_invalid")


if __name__ == "__main__":
    unittest.main()
