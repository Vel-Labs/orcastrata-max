import importlib.util
import argparse
from pathlib import Path
import sys
import tempfile
import unittest


_PATH = Path(__file__).parents[1] / "plugins/codexmax-orchestrator/scripts/resolve_codexmax_config.py"
_SPEC = importlib.util.spec_from_file_location("resolve_codexmax_config", _PATH)
config = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
sys.modules["resolve_codexmax_config"] = config
_SPEC.loader.exec_module(config)


class DeclarativeModelConfigTests(unittest.TestCase):
    def test_automatic_worker_defaults_keep_commandcode_generic_explicit_only(self):
        worker = config.ROLE_PRIORITY_DEFAULTS["worker"]
        implementation = config.TASK_PROFILE_DEFAULTS["semantic_worker_implementation"]
        selected = {worker[field] for field in config.ROLE_ROUTE_FIELDS}
        candidates = {implementation[field] for field in config.PROFILE_ROUTE_FIELDS}
        self.assertNotIn("worker_commandcode_model", selected | candidates)
        self.assertIn("worker_grok_4_6", selected & candidates)

    def test_authored_binding_accepts_exact_model_without_route_row(self):
        binding = config._build_authored_binding(
            adapter_type="commandcode", route_name="worker_commandcode_model",
            credential_kind="host_managed", opaque_id="test-host", enabled=False,
            concurrency_cap=None, token_cap=100, exact_model="vendor/model-x",
        )
        self.assertEqual(binding["route"]["exact_model"], "vendor/model-x")
        self.assertEqual(binding["qualification"]["status"], "configured")

    def test_authored_binding_keeps_approved_route_identity(self):
        binding = config._build_authored_binding(
            adapter_type="commandcode", route_name="worker_commandcode_model",
            credential_kind="host_managed", opaque_id="test-host", enabled=False,
            concurrency_cap=None, token_cap=100, exact_model="vendor/model-x",
        )
        route = config.ROUTE_DEFAULTS["worker_commandcode_model"]
        for field in ("provider", "route_id", "runtime", "reasoning", "billing_basis", "independence_group"):
            self.assertEqual(binding["route"][field], route[field])

    def test_generic_commandcode_route_accepts_any_exact_model_identity(self):
        binding = config._build_authored_binding(
            adapter_type="commandcode", route_name="worker_commandcode_model",
            credential_kind="host_managed", opaque_id="test-host", enabled=True,
            concurrency_cap=1, token_cap=100, exact_model="xai/future-model",
        )
        self.assertEqual(binding["route"]["provider"], "Command Code")
        self.assertEqual(binding["route"]["route_id"], "commandcode-subscription-exact-model")
        self.assertEqual(binding["route"]["exact_model"], "xai/future-model")

    def test_generic_route_requires_model_and_specific_route_cannot_be_relabeled(self):
        with self.assertRaisesRegex(config.ValidationError, "requires --exact-model"):
            config._build_authored_binding(
                adapter_type="commandcode", route_name="worker_commandcode_model",
                credential_kind="host_managed", opaque_id="test-host", enabled=True,
                concurrency_cap=1, token_cap=100,
            )
        with self.assertRaisesRegex(config.UnsafeOverrideError, "generic transport route"):
            config._build_authored_binding(
                adapter_type="commandcode", route_name="worker_deepseek_v4_pro",
                credential_kind="host_managed", opaque_id="test-host", enabled=True,
                concurrency_cap=1, token_cap=100, exact_model="xai/grok-4.6",
            )

    def test_add_can_extend_an_immutable_overlay_with_a_second_exact_model(self):
        def args(output, model, opaque_id, input_path=None):
            return argparse.Namespace(
                binding_action="add", input=input_path, output=output,
                adapter_type="commandcode", route="worker_commandcode_model",
                exact_model=model, credential_kind="host_managed",
                opaque_id=opaque_id, enabled=True, concurrency_cap=1,
                token_cap=100, write_new=True,
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            first = root / "first.yaml"
            second = root / "second.yaml"
            first_receipt = config.author_adapter_binding(
                args(first, "deepseek/deepseek-v4-pro", "commandcode-default")
            )
            first_bytes = first.read_bytes()
            second_receipt = config.author_adapter_binding(
                args(second, "minimaxai/minimax-m3", "commandcode-default", first)
            )

            self.assertEqual(first_receipt["binding_count"], 1)
            self.assertEqual(second_receipt["binding_count"], 2)
            self.assertEqual(first.read_bytes(), first_bytes)
            self.assertFalse(second_receipt["input_mutated"])


if __name__ == "__main__":
    unittest.main()
