import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "plugins/codexmax-orchestrator/scripts/run_task_scoped_provider_task.py"
spec = importlib.util.spec_from_file_location("task_scoped_provider_task_test", SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

MODEL = "vendor/model-x"
REQUEST = f"Use {MODEL} through Command Code"


def effective_with_model(model=MODEL):
    effective = copy.deepcopy(module.CONFIG.DEFAULTS)
    binding = module.CONFIG._build_authored_binding(
        adapter_type="commandcode",
        route_name="worker_commandcode_model",
        credential_kind="host_managed",
        opaque_id="task-scoped-test",
        enabled=True,
        concurrency_cap=None,
        token_cap=1,
        exact_model=model,
    )
    effective["adapter_registry"]["bindings"][binding["binding_id"]] = binding
    return effective


class Completed:
    returncode = 0
    stderr = ""


def probe_runner(argv, **kwargs):
    row = Completed()
    if argv == ["commandcode", "status", "--json"]:
        row.stdout = json.dumps({
            "authenticated": True,
            "context_window": 128000,
            "model": MODEL,
            "provider": "Command Code",
            "user": "operator",
            "version": "1.37.0",
        })
    else:
        row.stdout = MODEL + "\n"
    return row


def task_kwargs(root):
    return {
        "repo_root": root,
        "request": REQUEST,
        "task_id": "T030-test",
        "prompt": "Return the bounded result.",
        "read_scope": ["."],
        "evidence_directory": "reports/task-scoped-test",
        "expected_artifact": "reports/task-scoped-test/result.json",
        "workspace_config": None,
        "allow_provider_call": True,
        "probe_runner": probe_runner,
    }


def build_kwargs(root):
    values = task_kwargs(root)
    values.pop("workspace_config")
    values["effective"] = effective_with_model()
    return values


def capture_result(payload, *, returncode=0):
    return {
        "returncode": returncode,
        "stdout": json.dumps(payload).encode(),
        "stderr": b"",
        "timed_out": False,
        "output_limit_stream": None,
        "elapsed_time_ms": 1,
    }


class TaskScopedProviderTaskTests(unittest.TestCase):
    def test_unconfigured_commandcode_model_gets_task_local_binding_only(self):
        effective = copy.deepcopy(module.CONFIG.DEFAULTS)
        original = copy.deepcopy(effective)
        overlay, created = module.SERVICE.task_local_exact_config(
            effective=effective, request=REQUEST, session_module=module.SESSION,
            config_module=module.CONFIG,
        )
        self.assertTrue(created)
        self.assertEqual(effective, original)
        binding_id, binding, _ = module.SESSION._configured_binding(
            overlay, "Command Code", MODEL,
        )
        self.assertEqual(binding["route"]["exact_model"], MODEL)
        self.assertIn(binding_id, overlay["adapter_registry"]["bindings"])

    def test_existing_disabled_binding_is_not_bypassed(self):
        effective = effective_with_model()
        for binding in effective["adapter_registry"]["bindings"].values():
            if binding.get("route", {}).get("exact_model") == MODEL:
                binding["enabled"] = False
        with self.assertRaisesRegex(module.SESSION.ExplicitSelectionError, "requested_binding_disabled"):
            module.SERVICE.task_local_exact_config(
                effective=effective, request=REQUEST, session_module=module.SESSION,
                config_module=module.CONFIG,
            )

    def test_shipped_disabled_example_is_not_an_operator_denial(self):
        effective = copy.deepcopy(module.CONFIG.DEFAULTS)
        request = "Use deepseek/deepseek-v4-pro through Command Code"
        overlay, created = module.SERVICE.task_local_exact_config(
            effective=effective, request=request, session_module=module.SESSION,
            config_module=module.CONFIG,
        )
        self.assertTrue(created)
        _, binding, _ = module.SESSION._configured_binding(
            overlay, "Command Code", "deepseek/deepseek-v4-pro",
        )
        self.assertTrue(binding["enabled"])

    def test_timeout_is_bounded_before_configuration_or_dispatch(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, \
             mock.patch.object(module.DISPATCH, "_effective_config") as resolve:
            with self.assertRaisesRegex(ValueError, "timeout_seconds_invalid"):
                module.run_task(**{**task_kwargs(Path(directory)), "timeout_seconds": 301})
        resolve.assert_not_called()

    def test_scope_is_repository_root_only(self):
        with self.assertRaisesRegex(ValueError, "read_scope_invalid"):
            module._relative_scope(["../outside"])
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            values = build_kwargs(Path(directory))
            values["read_scope"] = ["plugins"]
            with self.assertRaisesRegex(ValueError, "read_scope_must_be_repo_root"):
                module.build_assignment(**values)

    def test_explicit_call_gate_precedes_config_and_assignment(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            with mock.patch.object(module.DISPATCH, "_effective_config", side_effect=AssertionError("must not resolve")):
                result = module.run_task(**{**task_kwargs(Path(directory)), "allow_provider_call": False})
            values = build_kwargs(Path(directory))
            values["allow_provider_call"] = False
            with self.assertRaisesRegex(ValueError, "task_scoped_provider_call_not_authorized"):
                module.build_assignment(**values)
        self.assertEqual(result["reason"], "task_scoped_provider_call_not_authorized")
        self.assertFalse(result["selected"])
        self.assertFalse(result["called"])

    def test_workspace_config_is_resolved_before_build_and_same_effective_is_dispatched(self):
        effective = effective_with_model()
        seen = {}
        workspace = ROOT / "workspace-config-test.json"

        def build(**kwargs):
            seen["build_effective"] = kwargs["effective"]
            return ({"route_packet": {}, "proof_mode": "task_scoped_live"}, {"configured": True})

        with tempfile.TemporaryDirectory(dir=ROOT) as directory, \
             mock.patch.object(module.DISPATCH, "_effective_config", return_value=effective) as resolve, \
             mock.patch.object(module, "build_assignment", side_effect=build), \
             mock.patch.object(module.DISPATCH, "_require_assignment", side_effect=lambda value, root: value), \
             mock.patch.object(module.DISPATCH, "_resolve_pre_dispatch", return_value={"status": "dispatch_required"}), \
             mock.patch.object(module.DISPATCH, "run_dispatch", return_value={
                 "status": "selected", "attempts": [{
                     "returncode": 0,
                     "expected_response_identity": {
                         "declared_route": "worker", "actual_provider": "provider",
                         "actual_model": "model", "fallback_used": False, "retry_count": 0,
                     },
                     "response_identity_validated": True,
                 }],
                 "artifact": {"path": "result.json"}, "usage": {},
             }) as dispatch:
            result = module.run_task(**{**task_kwargs(Path(directory)), "workspace_config": workspace})

        resolve.assert_called_once_with(Path(directory).resolve(), workspace)
        self.assertIs(seen["build_effective"], effective)
        self.assertIs(dispatch.call_args.kwargs["effective"], effective)
        self.assertTrue(result["completed"])

    def test_valid_explicit_model_overlay_reuses_package_rank(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            assignment, _ = module.build_assignment(**build_kwargs(Path(directory)))
            checked = module.DISPATCH._require_assignment(assignment, Path(directory).resolve())
            receipt = module.DISPATCH._resolve_pre_dispatch(copy.deepcopy(checked["route_packet"]))
        self.assertEqual(receipt["status"], "dispatch_required")
        self.assertTrue(receipt["next_attempt"]["capability_authority"]["authorized"])

    def test_arbitrary_model_overlay_cannot_inherit_package_rank(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            assignment, _ = module.build_assignment(**build_kwargs(Path(directory)))
            packet = copy.deepcopy(assignment["route_packet"])
            packet.pop("explicit_selection")
            receipt = module.DISPATCH._resolve_pre_dispatch(packet)
        self.assertEqual(receipt["status"], "no_eligible_route")
        self.assertIn(
            "route_capability_fingerprint_mismatch",
            receipt["considerations"][0]["reasons"],
        )

    def test_pre_call_rejection_does_not_dispatch(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, \
             mock.patch.object(module.DISPATCH, "_effective_config", return_value=effective_with_model()), \
             mock.patch.object(module.DISPATCH, "_resolve_pre_dispatch", return_value={
                 "status": "no_eligible_route", "stop_reason": "identity_mismatch:model"
             }), \
             mock.patch.object(module.DISPATCH, "run_dispatch") as dispatch:
            result = module.run_task(**task_kwargs(Path(directory)))
        dispatch.assert_not_called()
        self.assertFalse(result["selected"])
        self.assertFalse(result["called"])
        self.assertEqual(result["reason"], "identity_mismatch:model")

    def test_generic_model_propagates_to_packet_argv_identity_and_artifact(self):
        effective = effective_with_model()
        captured = {}

        def capture(argv, cwd, deadline, stdout_limit, stderr_limit):
            captured["argv"] = argv
            return capture_result({
                "route_identity": {
                    "declared_route": "worker_commandcode_model",
                    "actual_provider": "Command Code",
                    "actual_model": MODEL,
                    "fallback_used": False,
                    "retry_count": 0,
                },
                "content": "bounded result",
            })

        with tempfile.TemporaryDirectory(dir=ROOT) as directory, \
             mock.patch.object(module.DISPATCH, "_effective_config", return_value=effective), \
             mock.patch.object(module.DISPATCH, "_capture", side_effect=capture):
            result = module.run_task(**task_kwargs(Path(directory)))

        selection = result["selection"]
        manifest = result["manifest"]
        self.assertEqual(selection["requested_model"], MODEL)
        self.assertEqual(result["authority_source"], "operator_invocation")
        self.assertEqual(result["task_grant"]["read_scope"], ["."])
        self.assertEqual(result["task_grant"]["repo_root"], str(Path(directory).resolve()))
        self.assertEqual(result["task_grant"]["billing_basis"], "subscription")
        self.assertEqual(captured["argv"][captured["argv"].index("--model") + 1], MODEL)
        self.assertEqual(manifest["attempts"][0]["expected_response_identity"]["actual_model"], MODEL)
        self.assertEqual(manifest["attempts"][0]["identity"]["model"], MODEL)
        self.assertIsInstance(manifest["artifact"], dict)
        self.assertTrue(result["called"])
        self.assertTrue(result["completed"])

    def test_spawn_failure_is_not_called(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, \
             mock.patch.object(module.DISPATCH, "_effective_config", return_value=effective_with_model()), \
             mock.patch.object(module.DISPATCH, "_capture", side_effect=FileNotFoundError("missing")):
            result = module.run_task(**task_kwargs(Path(directory)))
        self.assertTrue(result["selected"])
        self.assertFalse(result["called"])
        self.assertFalse(result["completed"])

    def test_started_invalid_result_is_called_but_not_completed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory, \
             mock.patch.object(module.DISPATCH, "_effective_config", return_value=effective_with_model()), \
             mock.patch.object(module.DISPATCH, "_capture", return_value=capture_result({})):
            result = module.run_task(**task_kwargs(Path(directory)))
        self.assertTrue(result["selected"])
        self.assertTrue(result["called"])
        self.assertFalse(result["completed"])

    def test_completion_requires_manifest_artifact_and_validated_identity(self):
        base = {
            "status": "selected",
            "attempts": [{"returncode": 0, "response_identity_validated": True}],
            "artifact": {"path": "result.json"},
            "usage": {},
        }
        for missing in ("artifact", "identity"):
            manifest = copy.deepcopy(base)
            if missing == "artifact":
                manifest["artifact"] = None
            else:
                manifest["attempts"][0]["response_identity_validated"] = False
            with self.subTest(missing=missing), tempfile.TemporaryDirectory(dir=ROOT) as directory, \
                 mock.patch.object(module.DISPATCH, "_effective_config", return_value=effective_with_model()), \
                 mock.patch.object(module.DISPATCH, "_resolve_pre_dispatch", return_value={"status": "dispatch_required"}), \
                 mock.patch.object(module.DISPATCH, "run_dispatch", return_value=manifest):
                result = module.run_task(**task_kwargs(Path(directory)))
            self.assertTrue(result["called"])
            self.assertFalse(result["completed"])


if __name__ == "__main__":
    unittest.main()
