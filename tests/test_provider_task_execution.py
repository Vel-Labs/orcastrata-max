import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "provider_task_execution_tested",
    ROOT / "plugins/codexmax-orchestrator/scripts/provider_task_execution.py",
)
service = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(service)


class ProviderTaskExecutionServiceTests(unittest.TestCase):
    def test_one_dispatch_uses_the_resolved_config_and_validates_identity(self):
        effective = {"marker": "same-object"}
        dispatch = Mock()
        dispatch._effective_config.return_value = effective
        assignment = {"route_packet": {"task_id": "T100"}}
        dispatch._require_assignment.return_value = assignment
        dispatch._resolve_pre_dispatch.return_value = {
            "status": "dispatch_required", "next_attempt": {"route_name": "worker"},
        }
        dispatch.run_dispatch.return_value = {
            "status": "selected", "artifact": {},
            "attempts": [{
                "returncode": 0,
                "expected_response_identity": {
                    "declared_route": "worker", "actual_provider": "provider",
                    "actual_model": "model", "fallback_used": False, "retry_count": 0,
                },
                "response_identity_validated": True,
            }],
            "usage": {"tokens": 1},
        }
        dispatch.DispatchError = RuntimeError
        dispatch._route = Mock()
        config = Mock()
        session = Mock()

        def builder(**kwargs):
            self.assertIs(kwargs["effective"], effective)
            return assignment, {"configured": True, "selected": False}

        with tempfile.TemporaryDirectory() as directory:
            result = service.execute_task(
                repo_root=Path(directory), request="Use model through Command Code",
                task_id="T100", prompt="p", read_scope=["."],
                evidence_directory="reports", expected_artifact="reports/result.json",
                workspace_config=None, allow_provider_call=True, probe_runner=Mock(),
                session_module=session, dispatch_module=dispatch, config_module=config,
                assignment_builder=builder,
            )
        dispatch.run_dispatch.assert_called_once()
        self.assertIs(dispatch.run_dispatch.call_args.kwargs["effective"], effective)
        self.assertTrue(result["called"])
        self.assertTrue(result["completed"])

    def test_started_attempt_remains_called_when_result_validation_fails(self):
        receipt = service.truthful_receipt(
            {"selected": True},
            {"status": "failed", "attempts": [{"returncode": 1, "response_identity_validated": False}]},
            root=Path("."), evidence_directory="reports",
        )
        self.assertTrue(receipt["called"])
        self.assertFalse(receipt["completed"])

    def test_durable_attempt_files_prove_start_but_spawn_marker_does_not(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            started = root / "reports" / "attempt-001"
            started.mkdir(parents=True)
            (started / "stdout.bin").write_bytes(b"output")
            self.assertTrue(service.durable_attempt_started(root, "reports"))
            failed = root / "failed" / "attempt-001"
            failed.mkdir(parents=True)
            (failed / "stdout.bin").write_bytes(b"")
            (failed / "stderr.bin").write_bytes(b"FileNotFoundError")
            self.assertFalse(service.durable_attempt_started(root, "failed"))


if __name__ == "__main__":
    unittest.main()
