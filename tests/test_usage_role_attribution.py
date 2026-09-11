import json
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "plugins/codexmax-orchestrator/scripts"))
import dispatch_ledger
import project_usage


class UsageRoleAttributionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        marker = self.root / ".orcastrata/project.json"
        marker.parent.mkdir()
        marker.write_text(json.dumps({
            "schema_version": 1, "manifest_type": "orcastrata_project_v1",
            "project_id": "usage-fixture", "display_name": "Usage fixture",
            "context": {"files": [], "max_files": 20, "max_bytes": 262144},
            "skills": [], "scope": {"root": ".", "exclusions": []},
            "usage": {"ledger": ".orcastrata/usage/dispatch.jsonl", "privacy": "metadata_only"},
        }))

    def tearDown(self):
        self.tmp.cleanup()

    def manifest(self, attempts, dispatch_id="dispatch-1", status="completed"):
        return {"dispatch_id": dispatch_id, "external_call_performed": True,
                "semantic_role": "reviewer", "supervisor_assignment_id": "assign-1",
                "status": status, "work_status": status,
                "effective_config_sha256": "sha256:" + "a" * 64, "attempts": attempts}

    def attempt(self, ident, outcome="completed", model="gpt-test", usage=None):
        value = {"attempt_id": ident, "process_started": True, "outcome": outcome,
                 "identity": {"provider": "local", "model": model}, "route_name": "fixture"}
        if usage is not None:
            value["usage"] = usage
        return value

    def ledger(self):
        return self.root / ".orcastrata/usage/dispatch.jsonl"

    def test_each_started_attempt_is_readable_with_role_assignment_model(self):
        project_usage.append_dispatch_manifest(self.root, self.manifest([
            self.attempt("a1", usage={"input_tokens": 2, "output_tokens": 3, "total_tokens": 5}),
            self.attempt("a2", outcome="execution_unknown", model="gpt-other"),
        ], status="execution_unknown"))
        rows = project_usage.readout(self.ledger(), project_id="usage-fixture")["used_lanes"]
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["attempt_identity"] for row in rows}, {"a1", "a2"})
        self.assertEqual(rows[0]["semantic_role"], "reviewer")
        self.assertEqual(rows[0]["assignment_id"], "assign-1")
        self.assertEqual(rows[0]["model"], "gpt-test")
        self.assertEqual(rows[1]["status"], "execution_unknown")

    def test_replay_is_idempotent_and_conflict_is_rejected(self):
        first = self.manifest([self.attempt("a1")])
        project_usage.append_dispatch_manifest(self.root, first)
        project_usage.append_dispatch_manifest(self.root, first)
        self.assertEqual(dispatch_ledger.verify_ledger(self.ledger())["event_count"], 1)
        conflict = self.manifest([self.attempt("a1", model="different")])
        with self.assertRaises(dispatch_ledger.LedgerError):
            project_usage.append_dispatch_manifest(self.root, conflict)

    def test_attempt_without_usage_stays_unknown(self):
        project_usage.append_dispatch_manifest(self.root, self.manifest([self.attempt("a1")]))
        row = project_usage.readout(self.ledger(), project_id="usage-fixture")["used_lanes"][0]
        self.assertEqual(row["usage"]["total_tokens"]["value"], "unknown")
        self.assertEqual(row["usage_source"], "attempt_usage_not_reported")
        self.assertEqual(row["accounting_status"], "accounted")

    def test_cumulative_manifest_keeps_prior_attempt_idempotent_and_skips_unstarted(self):
        first = self.manifest([self.attempt("a1", usage={"input_tokens": 2, "output_tokens": 3, "total_tokens": 5})])
        project_usage.append_dispatch_manifest(self.root, first)
        cumulative = self.manifest([
            self.attempt("a1", usage={"input_tokens": 2, "output_tokens": 3, "total_tokens": 5}),
            {"attempt_id": "a2", "outcome": "not_started"},
            self.attempt("a3", usage={"input_tokens": 11, "output_tokens": 13, "total_tokens": 24}),
        ])
        project_usage.append_dispatch_manifest(self.root, cumulative)
        rows = project_usage.readout(self.ledger(), project_id="usage-fixture")["used_lanes"]
        self.assertEqual({row["attempt_identity"] for row in rows}, {"a1", "a3"})
        by_id = {row["attempt_identity"]: row for row in rows}
        self.assertEqual(by_id["a1"]["usage"]["total_tokens"]["value"], 5)
        self.assertEqual(by_id["a3"]["usage"]["total_tokens"]["value"], 24)

    def test_incomplete_native_import_is_accounted_with_unknown_counters(self):
        result = project_usage.import_codex_exec_json(self.root, "native-task", io.StringIO(
            json.dumps({"type": "turn.completed", "action_id": "turn-1"}) + "\n"
        ))
        self.assertEqual(result["completed_turns"], 1)
        row = project_usage.readout(self.ledger(), project_id="usage-fixture")["used_lanes"][0]
        self.assertEqual(row["usage"]["total_tokens"]["value"], "unknown")

    def test_started_native_turn_without_completion_is_preserved_as_unknown(self):
        result = project_usage.import_codex_exec_json(self.root, "native-task", io.StringIO(
            json.dumps({"type": "turn.started", "turn_id": "turn-open"}) + "\n"
            + json.dumps({"type": "item.completed", "id": "item-1"}) + "\n"
            + json.dumps({"type": "turn.completed", "turn_id": "turn-done", "usage": {"total_tokens": 7}}) + "\n"
        ))
        self.assertEqual(result["completed_turns"], 1)
        summary = project_usage.readout(self.ledger(), project_id="usage-fixture")
        self.assertEqual(len(summary["used_lanes"]), 2)
        unknown = [row for row in summary["used_lanes"] if row["status"] == "execution_unknown"]
        self.assertEqual(len(unknown), 1)
        self.assertEqual(summary["accounting_coverage"]["complete"], False)

    def test_native_no_id_turns_failed_usage_and_eof_keep_distinct_ordinals(self):
        source = "".join(json.dumps(event) + "\n" for event in (
            {"type": "turn.started", "timestamp": "2026-09-10T10:00:00Z"},
            {"type": "item.completed", "id": "private-item"},
            {"type": "turn.completed", "timestamp": "2026-09-10T10:00:01Z",
             "usage": {"total_tokens": 3}},
            {"type": "turn.started", "timestamp": "2026-09-10T10:01:00Z"},
            {"type": "turn.failed", "timestamp": "2026-09-10T10:01:01Z",
             "outcome": "provider_failed",
             "usage": {"input_tokens": 4, "output_tokens": 5, "total_tokens": 9}},
            {"type": "turn.started", "timestamp": "2026-09-10T10:02:00Z"},
        ))
        first = project_usage.import_codex_exec_json(self.root, "native-sequence", io.StringIO(source))
        second = project_usage.import_codex_exec_json(self.root, "native-sequence", io.StringIO(source))
        self.assertEqual(first["completed_turns"], 1)
        self.assertEqual(first["appended"], 3)
        self.assertEqual(second["appended"], 0)
        self.assertEqual(second["idempotent"], 3)
        rows = project_usage.readout(self.ledger(), project_id="usage-fixture")["used_lanes"]
        by_action = {row["action_id"]: row for row in rows}
        self.assertEqual(set(by_action), {"turn-1", "turn-2", "turn-3"})
        self.assertEqual(by_action["turn-1"]["work_status"], "completed")
        self.assertEqual(by_action["turn-1"]["usage"]["total_tokens"]["value"], 3)
        self.assertEqual(by_action["turn-2"]["work_status"], "execution_unknown")
        self.assertEqual(by_action["turn-2"]["attempt_outcome"], "failed")
        self.assertEqual(by_action["turn-2"]["usage"]["total_tokens"]["value"], 9)
        self.assertEqual(by_action["turn-3"]["work_status"], "execution_unknown")
        self.assertEqual(by_action["turn-3"]["attempt_outcome"], "execution_unknown")
        self.assertEqual(by_action["turn-3"]["usage"]["total_tokens"]["value"], "unknown")
        native_rows = dispatch_ledger.verify_ledger(self.ledger())["rows"]
        failed = next(row for row in native_rows if row["assignment_id"] == "native-sequence:turn-2")
        self.assertEqual(failed["evidence"]["attempt_outcome"], "failed")
        self.assertEqual(failed["accounting"]["token_usage"]["total_tokens"]["value"], 9)
        self.assertEqual(len(native_rows), 3)

    def test_managed_attempt_evidence_survives_mutable_overall_status(self):
        usage = {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5}
        project_usage.append_dispatch_manifest(
            self.root, self.manifest([self.attempt("stable", usage=usage)], status="completed")
        )
        project_usage.append_dispatch_manifest(
            self.root, self.manifest([self.attempt("stable", usage=usage)], status="execution_unknown")
        )
        rows = project_usage.readout(self.ledger(), project_id="usage-fixture")["used_lanes"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "completed")
        self.assertEqual(rows[0]["work_status"], "completed")
        self.assertEqual(rows[0]["usage"]["total_tokens"]["value"], 5)
        self.assertEqual(rows[0]["accounting_status"], "accounted")

    def test_managed_attempt_usage_provenance_survives_aggregate_update(self):
        usage = {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5}
        first = self.manifest([self.attempt("provenance", usage=usage)])
        project_usage.append_dispatch_manifest(self.root, first)
        second = self.manifest([self.attempt("provenance", usage=usage)])
        second["usage"] = {"tokens": {"value": usage, "reason": "aggregate_manifest"}}
        project_usage.append_dispatch_manifest(self.root, second)
        rows = project_usage.readout(self.ledger(), project_id="usage-fixture")["used_lanes"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["usage_source"], "provider_manifest")
        self.assertEqual(rows[0]["usage"]["total_tokens"]["value"], 5)

    def test_managed_failed_attempt_retains_per_attempt_usage_and_outcome(self):
        project_usage.append_dispatch_manifest(self.root, self.manifest([
            self.attempt("failed", outcome="failed",
                         usage={"input_tokens": 4, "output_tokens": 5, "total_tokens": 9}),
        ], status="completed"))
        row = project_usage.readout(self.ledger(), project_id="usage-fixture")["used_lanes"][0]
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["work_status"], "failed")
        self.assertEqual(row["usage"]["total_tokens"]["value"], 9)
        self.assertEqual(row["accounting_status"], "accounted")
        ledger_row = dispatch_ledger.verify_ledger(self.ledger())["rows"][0]
        self.assertEqual(ledger_row["evidence"]["attempt_outcome"], "failed")

    def test_cli_import_then_restart_readout_roundtrip(self):
        source_path = self.root / "host-exec.jsonl"
        source_path.write_text(
            json.dumps({"type": "turn.started"}) + "\n"
            + json.dumps({"type": "turn.completed", "usage": {"total_tokens": 12}}) + "\n"
        )
        script = Path(__file__).parents[1] / "plugins/codexmax-orchestrator/scripts/project_usage.py"
        env = {**os.environ, "PYTHONPATH": str(script.parent)}
        imported = subprocess.run(
            [sys.executable, str(script), "--project-root", str(self.root),
             "--task-id", "cli-native", "--import-codex-json", str(source_path)],
            text=True, capture_output=True, env=env, check=False,
        )
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertEqual(json.loads(imported.stdout)["completed_turns"], 1)
        restarted = subprocess.run(
            [sys.executable, str(script), "--ledger", str(self.ledger()), "--project-id", "usage-fixture"],
            text=True, capture_output=True, env=env, check=False,
        )
        self.assertEqual(restarted.returncode, 0, restarted.stderr)
        readout = json.loads(restarted.stdout)
        self.assertEqual(len(readout["used_lanes"]), 1)
        self.assertEqual(readout["used_lanes"][0]["ask_id"], "cli-native")
        self.assertEqual(readout["used_lanes"][0]["usage"]["total_tokens"]["value"], 12)

    def test_native_same_attempt_changed_usage_is_rejected(self):
        project_usage.import_codex_exec_json(self.root, "native-conflict", io.StringIO(
            json.dumps({"type": "turn.completed", "action_id": "turn-a",
                        "usage": {"total_tokens": 4}}) + "\n"
        ))
        with self.assertRaises(dispatch_ledger.LedgerError):
            project_usage.import_codex_exec_json(self.root, "native-conflict", io.StringIO(
                json.dumps({"type": "turn.completed", "action_id": "turn-a",
                            "usage": {"total_tokens": 5}}) + "\n"
            ))

    def test_cli_readout_uses_the_same_ledger(self):
        project_usage.append_dispatch_manifest(self.root, self.manifest([self.attempt("cli-1")]))
        script = Path(__file__).parents[1] / "plugins/codexmax-orchestrator/scripts/project_usage.py"
        env = {**os.environ, "PYTHONPATH": str(script.parent)}
        result = subprocess.run(
            [sys.executable, str(script), "--ledger", str(self.ledger()), "--project-id", "usage-fixture"],
            text=True, capture_output=True, env=env, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["used_lanes"][0]["attempt_identity"], "cli-1")
