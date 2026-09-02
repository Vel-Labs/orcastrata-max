import copy
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


session = load(
    "configured_tool_session_test",
    "plugins/codexmax-orchestrator/scripts/verify_configured_tool_session.py",
)
config = load(
    "configured_tool_session_config_test",
    "plugins/codexmax-orchestrator/scripts/resolve_codexmax_config.py",
)


def effective_with_model(model="vendor/model-x"):
    effective = copy.deepcopy(config.DEFAULTS)
    binding = config._build_authored_binding(
        adapter_type="commandcode",
        route_name="worker_commandcode_model",
        credential_kind="host_managed",
        opaque_id="configured-session-test",
        enabled=True,
        concurrency_cap=None,
        token_cap=1,
        exact_model=model,
    )
    effective["adapter_registry"]["bindings"][binding["binding_id"]] = binding
    return effective, binding


class ConfiguredToolSessionTests(unittest.TestCase):
    def test_request_requires_one_exact_tool_clause(self):
        self.assertEqual(
            session.parse_request("Use deepseek/deepseek-v4-pro through Command Code"),
            ("Command Code", "deepseek/deepseek-v4-pro"),
        )
        with self.assertRaisesRegex(session.ExplicitSelectionError, "explicit_request_malformed"):
            session.parse_request("Use model X through Command Code and model Y through OpenCode")

    def test_configured_binding_matches_exact_declared_model(self):
        effective, expected = effective_with_model()
        binding_id, binding, route = session._configured_binding(
            effective, "Command Code", "vendor/model-x"
        )
        self.assertEqual(binding_id, expected["binding_id"])
        self.assertEqual(binding["route"]["exact_model"], "vendor/model-x")
        self.assertEqual(route["exact_model"], "vendor/model-x")
        self.assertEqual(
            effective["route_registry"]["routes"]["worker_commandcode_model"]["exact_model"],
            "unknown",
        )

    def test_configured_binding_rejects_model_and_transport_mismatch(self):
        effective, binding = effective_with_model()
        with self.assertRaisesRegex(session.ExplicitSelectionError, "requested_model_not_configured"):
            session._configured_binding(effective, "Command Code", "vendor/not-configured")

        effective["adapter_registry"]["bindings"][binding["binding_id"]]["route"]["runtime"] = "other-runtime"
        with self.assertRaisesRegex(session.ExplicitSelectionError, "requested_binding_route_mismatch: runtime"):
            session._configured_binding(effective, "Command Code", "vendor/model-x")

    def test_session_probe_runs_only_fixed_status_and_model_commands(self):
        calls = []

        class Completed:
            returncode = 0
            stderr = ""

        def runner(argv, **kwargs):
            calls.append(argv)
            row = Completed()
            if argv == ["commandcode", "status", "--json"]:
                row.stdout = '{"authenticated":true,"context_window":128000,"model":"vendor/model-x","provider":"Command Code","user":"operator","version":"1.37.0"}'
            else:
                row.stdout = "vendor/model-x\n"
            return row

        probe = session.probe_existing_session(
            "Command Code", "commandcode", "vendor/model-x", runner=runner
        )
        self.assertTrue(probe["existing_session_verified"])
        self.assertEqual(calls, [["commandcode", "status", "--json"], ["commandcode", "--list-models"]])
        self.assertFalse(probe["credential_material_accessed"])
        self.assertFalse(probe["provider_execution_started"])


if __name__ == "__main__":
    unittest.main()
