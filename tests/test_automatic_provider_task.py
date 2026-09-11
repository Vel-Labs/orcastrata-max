import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("automatic_provider_task_tested", ROOT / "plugins/codexmax-orchestrator/scripts/run_automatic_provider_task.py")
auto = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(auto)


def configured(model="deepseek/deepseek-v4-pro", opaque="automatic-test"):
    effective = copy.deepcopy(auto.TASK.CONFIG.DEFAULTS)
    binding = auto.TASK.CONFIG._build_authored_binding(
        adapter_type="commandcode", route_name="worker_deepseek_v4_pro",
        credential_kind="host_managed", opaque_id=opaque, enabled=True,
        concurrency_cap=None, token_cap=1, exact_model=model)
    effective["adapter_registry"]["bindings"][binding["binding_id"]] = binding
    return effective


def probe_runner(argv, **kwargs):
    model = "deepseek/deepseek-v4-pro"
    if list(argv) == ["commandcode", "status", "--json"]:
        out = json.dumps({"authenticated": True, "context_window": 128000,
            "model": model, "provider": "Command Code", "user": "operator", "version": "1.37.0"})
    else:
        out = model + "\n"
    return subprocess.CompletedProcess(argv, 0, out, "")


class AutomaticSelectorTests(unittest.TestCase):
    def test_commandcode_catalog_does_not_create_automatic_candidates(self):
        effective = copy.deepcopy(auto.TASK.CONFIG.DEFAULTS)

        def catalog(argv, **kwargs):
            self.fail(f"automatic routing must not inspect the CommandCode catalog: {argv}")

        with tempfile.TemporaryDirectory(dir=ROOT) as directory, \
             patch.object(auto.DISPATCH, "_effective_config", return_value=effective), \
             patch.object(auto.DISPATCH, "run_dispatch") as dispatch:
            result = auto.run_automatic_task(
                repo_root=Path(directory), task_id="T040", prompt="document",
                read_scope=["."], evidence_directory="reports",
                expected_artifact="reports/result.json", workspace_config=None,
                allow_provider_call=True, role="documenter", probe_runner=catalog,
            )
        self.assertFalse(result["selected"])
        self.assertEqual(result["reason"], "no_eligible_configured_worker")
        dispatch.assert_not_called()

    def test_generic_commandcode_binding_is_explicit_only(self):
        effective = configured()
        generic = auto.TASK.CONFIG._build_authored_binding(
            adapter_type="commandcode", route_name="worker_commandcode_model",
            credential_kind="host_managed", opaque_id="explicit-only", enabled=True,
            concurrency_cap=1, token_cap=1, exact_model="gpt-5.6-luna")
        effective["adapter_registry"]["bindings"][generic["binding_id"]] = generic
        row = next(row for row in auto._candidates(effective)
                   if row["binding_id"] == generic["binding_id"])
        self.assertEqual(row["reason"], "not_in_package_worker_priority")
        self.assertFalse(row["pre_probe_eligible"])

    def test_disabled_only_and_no_binding(self):
        empty = copy.deepcopy(auto.TASK.CONFIG.DEFAULTS)
        self.assertFalse(any(row["reason"] == "eligible_for_session_probe" for row in auto._candidates(empty)))
        disabled = configured()
        for binding in disabled["adapter_registry"]["bindings"].values():
            binding["enabled"] = False
        rows = auto._candidates(disabled)
        row = next(row for row in rows if row["binding_id"] != "example_commandcode_deepseek")
        self.assertEqual(row["reason"], "binding_or_route_disabled")
        self.assertTrue(row["configured"])

    def test_actual_deepseek_binding_is_eligible(self):
        rows = auto._candidates(configured())
        row = next(row for row in rows if row["binding_id"] != "example_commandcode_deepseek")
        self.assertEqual(row["route_name"], "worker_deepseek_v4_pro")
        self.assertEqual(row["reason"], "eligible_for_session_probe")

    def test_package_order_not_model_name_order(self):
        effective = configured()
        binding = auto.TASK.CONFIG._build_authored_binding(
            adapter_type="commandcode", route_name="worker_deepseek_v4_flash",
            credential_kind="host_managed", opaque_id="second", enabled=True,
            concurrency_cap=None, token_cap=1, exact_model="deepseek/deepseek-v4-flash")
        effective["adapter_registry"]["bindings"][binding["binding_id"]] = binding
        rows = [row for row in auto._candidates(effective) if row["reason"] == "eligible_for_session_probe"]
        self.assertEqual(rows[0]["route_name"], "worker_deepseek_v4_pro")

    def test_probe_failure_then_success_dispatches_once(self):
        effective = configured()
        second = auto.TASK.CONFIG._build_authored_binding(
            adapter_type="commandcode", route_name="worker_deepseek_v4_flash",
            credential_kind="host_managed", opaque_id="second", enabled=True,
            concurrency_cap=None, token_cap=1, exact_model="deepseek/deepseek-v4-flash")
        effective["adapter_registry"]["bindings"][second["binding_id"]] = second
        effective["headless_dispatch"]["role_priorities"]["worker"]["route_02"] = "worker_deepseek_v4_flash"
        calls = []
        def probe(tool, provider, token, **kwargs):
            calls.append(token)
            if len(calls) == 1:
                raise auto.SESSION.ExplicitSelectionError("identity_unverifiable")
            return {"output_sha256": "sha256:" + "a" * 64}
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, \
             patch.object(auto.DISPATCH, "_effective_config", return_value=effective), \
             patch.object(auto.SESSION, "probe_existing_session", side_effect=probe), \
             patch.object(auto.TASK, "build_assignment", return_value=({"route_packet": {}, "proof_mode": "task_scoped_live"}, {"configured": True})), \
             patch.object(auto.DISPATCH, "_require_assignment", side_effect=lambda value, root: value), \
             patch.object(auto.DISPATCH, "_resolve_pre_dispatch", return_value={"status": "dispatch_required"}), \
             patch.object(auto.DISPATCH, "run_dispatch", return_value={
                 "status": "selected", "attempts": [{
                     "returncode": 0,
                     "expected_response_identity": {
                         "declared_route": "worker", "actual_provider": "provider",
                         "actual_model": "model", "fallback_used": False, "retry_count": 0,
                     },
                     "response_identity_validated": True,
                 }], "artifact": {}, "usage": {}}) as dispatch:
            result = auto.run_automatic_task(repo_root=Path(directory), task_id="T040", prompt="p", read_scope=["."], evidence_directory="reports", expected_artifact="reports/result.json", workspace_config=Path("config"), allow_provider_call=True, probe_runner=probe_runner)
        dispatch.assert_called_once()
        self.assertTrue(result["completed"])
        self.assertEqual(len(calls), 2)

    def test_started_provider_failure_has_no_second_dispatch_and_unknown_usage(self):
        effective = configured()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, \
             patch.object(auto.DISPATCH, "_effective_config", return_value=effective), \
             patch.object(auto.SESSION, "probe_existing_session", return_value={"output_sha256": "sha256:" + "a" * 64}), \
             patch.object(auto.TASK, "build_assignment", return_value=({"route_packet": {}, "proof_mode": "task_scoped_live"}, {"configured": True})), \
             patch.object(auto.DISPATCH, "_require_assignment", side_effect=lambda value, root: value), \
             patch.object(auto.DISPATCH, "_resolve_pre_dispatch", return_value={"status": "dispatch_required"}), \
             patch.object(auto.DISPATCH, "run_dispatch", return_value={"status": "failed", "attempts": [{"returncode": 1, "response_identity_validated": False}], "usage": None}) as dispatch:
            result = auto.run_automatic_task(repo_root=Path(directory), task_id="T040", prompt="p", read_scope=["."], evidence_directory="reports", expected_artifact="reports/result.json", workspace_config=Path("config"), allow_provider_call=True, probe_runner=probe_runner)
        dispatch.assert_called_once()
        self.assertTrue(result["called"])
        self.assertFalse(result["completed"])
        self.assertIsNone(result["usage"])


if __name__ == "__main__":
    unittest.main()
