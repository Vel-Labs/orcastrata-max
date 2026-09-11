import json
import sys
import tempfile
import os
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "plugins" / "codexmax-orchestrator" / "scripts"))

from project_codex_runtime import (
    project_codex_runtime, record_spawn_result, ProjectionError,
    _compile_role_preference, _compile_execution_preferences, _load_config_receipt,
)


def test_matching_fixed_projection():
    """Test that a matching fixed agent type produces a ready projection."""
    packet = {
        "schema_version": 1,
        "child_task_id": "C3-03-MATCH",
        "semantic_role": "planner",
        "runtime_surface": "codex_collaboration",
        "route_authority": "parent",
        "selected_route": {
            "route_id": "codex-terra-high",
            "special_route_required": True,
            "route_rotation_policy": "forbidden",
            "fallback": "forbidden",
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
        "native_request": {
            "agent_type": "codex_planner",
            "fork_turns": "none",
            "mapping_change_approved": False,
        },
        "parent_runtime": {
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
    }
    packet["host_snapshot"] = {"supported_pairs": [{"exact_model": "gpt-5.6-terra", "reasoning_effort": "high"}]}
    result = project_codex_runtime(packet)
    assert result["status"] == "ready"
    assert result["dispatch_performed"] is False
    assert result["provider_dispatch"] is False
    assert result["spawn_projection"]["agent_type"] == "codex_planner"
    assert result["dispatch_receipt"]["exact_model"] == "gpt-5.6-terra"
    assert result["dispatch_receipt"]["reasoning_effort"] == "high"


def test_model_conflict_returns_resolution_need():
    """Test that a model conflict returns resolution_need instead of approval_required."""
    packet = {
        "schema_version": 1,
        "child_task_id": "C3-03-CONFLICT",
        "semantic_role": "planner",
        "runtime_surface": "codex_collaboration",
        "route_authority": "parent",
        "selected_route": {
            "route_id": "codex-sol-high",
            "special_route_required": True,
            "route_rotation_policy": "forbidden",
            "fallback": "forbidden",
            "exact_model": "gpt-5.6-sol",
            "reasoning_effort": "high",
        },
        "native_request": {
            "agent_type": "codex_planner",
            "fork_turns": "none",
            "mapping_change_approved": False,
        },
        "parent_runtime": {
            "exact_model": "gpt-5.6-astra",
            "reasoning_effort": "high",
        },
    }
    packet["host_snapshot"] = {"supported_pairs": [{"exact_model": "gpt-5.6-sol", "reasoning_effort": "high"}]}
    result = project_codex_runtime(packet)
    assert result["status"] == "resolution_need"
    assert result["dispatch_performed"] is False
    assert result["provider_dispatch"] is False
    assert result["reason"] == "fixed_role_model_conflict"
    assert "resolution_preview" in result
    assert result["resolution_preview"]["exact_model"] == "gpt-5.6-sol"
    assert result["resolution_preview"]["reasoning_effort"] == "high"


def test_semantic_role_conflict_returns_resolution_need():
    """Test that a semantic role conflict returns resolution_need."""
    packet = {
        "schema_version": 1,
        "child_task_id": "C3-03-ROLE-CONFLICT",
        "semantic_role": "worker",
        "runtime_surface": "codex_collaboration",
        "route_authority": "parent",
        "selected_route": {
            "route_id": "codex-terra-high",
            "special_route_required": True,
            "route_rotation_policy": "forbidden",
            "fallback": "forbidden",
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
        "native_request": {
            "agent_type": "codex_planner",
            "fork_turns": "none",
            "mapping_change_approved": False,
        },
        "parent_runtime": {
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
    }
    packet["host_snapshot"] = {"supported_pairs": [{"exact_model": "gpt-5.6-terra", "reasoning_effort": "high"}]}
    result = project_codex_runtime(packet)
    assert result["status"] == "resolution_need"
    assert result["dispatch_performed"] is False
    assert result["provider_dispatch"] is False
    assert result["reason"] == "fixed_role_semantic_conflict"


def test_no_dispatch_on_resolution_need():
    """Test that resolution_need does not perform dispatch."""
    packet = {
        "schema_version": 1,
        "child_task_id": "C3-03-NO-DISPATCH",
        "semantic_role": "planner",
        "runtime_surface": "codex_collaboration",
        "route_authority": "parent",
        "selected_route": {
            "route_id": "codex-sol-high",
            "special_route_required": True,
            "route_rotation_policy": "forbidden",
            "fallback": "forbidden",
            "exact_model": "gpt-5.6-sol",
            "reasoning_effort": "high",
        },
        "native_request": {
            "agent_type": "codex_planner",
            "fork_turns": "none",
            "mapping_change_approved": False,
        },
        "parent_runtime": {
            "exact_model": "gpt-5.6-astra",
            "reasoning_effort": "high",
        },
    }
    packet["host_snapshot"] = {"supported_pairs": [{"exact_model": "gpt-5.6-sol", "reasoning_effort": "high"}]}
    result = project_codex_runtime(packet)
    assert result["status"] == "resolution_need"
    assert result["dispatch_performed"] is False
    assert result["provider_dispatch"] is False


def test_child_id_finalization():
    """Test that child ID finalization works for ready projections."""
    packet = {
        "schema_version": 1,
        "child_task_id": "C3-03-FINALIZE",
        "semantic_role": "planner",
        "runtime_surface": "codex_collaboration",
        "route_authority": "parent",
        "selected_route": {
            "route_id": "codex-terra-high",
            "special_route_required": True,
            "route_rotation_policy": "forbidden",
            "fallback": "forbidden",
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
        "native_request": {
            "agent_type": "codex_planner",
            "fork_turns": "none",
            "mapping_change_approved": False,
        },
        "parent_runtime": {
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
    }
    packet["host_snapshot"] = {"supported_pairs": [{"exact_model": "gpt-5.6-terra", "reasoning_effort": "high"}]}
    projection = project_codex_runtime(packet)
    assert projection["status"] == "ready"
    finalized = record_spawn_result(projection, "child-C3-03-001")
    assert finalized["dispatch_performed"] is True
    assert finalized["dispatch_receipt"]["runtime_child_id"] == "child-C3-03-001"
    assert finalized["dispatch_receipt"]["runtime_child_id_status"] == "recorded"
    assert finalized["dispatch_receipt"]["dispatch_status"] == "spawned"
    assert finalized["dispatch_receipt"]["provider_dispatch"] is False


if __name__ == "__main__":
    test_matching_fixed_projection()
    test_model_conflict_returns_resolution_need()
    test_semantic_role_conflict_returns_resolution_need()
    test_no_dispatch_on_resolution_need()
    test_child_id_finalization()
    print("All tests passed.")
def test_unknown_child_route_returns_resolution_need():
    """Test that an unknown child route model returns resolution_need without dispatch."""
    packet = {
        "schema_version": 1,
        "child_task_id": "C3-03-UNKNOWN-ROUTE",
        "semantic_role": "planner",
        "runtime_surface": "codex_collaboration",
        "route_authority": "parent",
        "selected_route": {
            "route_id": "codex-unknown-high",
            "special_route_required": True,
            "route_rotation_policy": "forbidden",
            "fallback": "forbidden",
            "exact_model": "gpt-9.9-unknown",
            "reasoning_effort": "high",
        },
        "native_request": {
            "agent_type": "default",
            "fork_turns": "none",
            "mapping_change_approved": False,
        },
        "parent_runtime": {
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
    }
    result = project_codex_runtime(packet)
    assert result["status"] == "resolution_need"
    assert result["dispatch_performed"] is False
    assert result["provider_dispatch"] is False
    assert result["reason"] == "native_identity_unresolved"
    assert "resolution_preview" in result
    assert result["resolution_preview"]["exact_model"] == "gpt-9.9-unknown"
    assert result["resolution_preview"]["reasoning_effort"] == "high"


def test_explicit_eligible_child_with_unknown_parent_remains_ready():
    """Test that an explicit eligible child model/effort with unknown Parent identity and fork_turns none remains ready."""
    packet = {
        "schema_version": 1,
        "child_task_id": "C3-03-EXPLICIT-UNKNOWN-PARENT",
        "semantic_role": "planner",
        "runtime_surface": "codex_collaboration",
        "route_authority": "parent",
        "selected_route": {
            "route_id": "codex-terra-high",
            "special_route_required": True,
            "route_rotation_policy": "forbidden",
            "fallback": "forbidden",
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
        "native_request": {
            "agent_type": "default",
            "fork_turns": "none",
            "mapping_change_approved": False,
        },
        "parent_runtime": {
            "exact_model": "gpt-9.9-unknown",
            "reasoning_effort": "high",
        },
    }
    packet["host_snapshot"] = {"supported_pairs": [{"exact_model": "gpt-5.6-terra", "reasoning_effort": "high"}]}
    result = project_codex_runtime(packet)
    assert result["status"] == "ready"
    assert result["dispatch_performed"] is False
    assert result["provider_dispatch"] is False
    assert result["spawn_projection"]["agent_type"] == "default"
    assert result["spawn_projection"]["fork_turns"] == "none"
    assert result["dispatch_receipt"]["exact_model"] == "gpt-5.6-terra"
    assert result["dispatch_receipt"]["reasoning_effort"] == "high"


def test_full_history_inheritance_with_unknown_parent_returns_resolution_need():
    """Test that full-history inheritance with unknown Parent identity returns resolution_need."""
    packet = {
        "schema_version": 1,
        "child_task_id": "C3-03-FORK-UNKNOWN-PARENT",
        "semantic_role": "planner",
        "runtime_surface": "codex_collaboration",
        "route_authority": "parent",
        "selected_route": {
            "route_id": "codex-terra-high",
            "special_route_required": True,
            "route_rotation_policy": "forbidden",
            "fallback": "forbidden",
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
        "native_request": {
            "agent_type": "default",
            "fork_turns": "all",
            "mapping_change_approved": False,
        },
        "parent_runtime": {
            "exact_model": "gpt-9.9-unknown",
            "reasoning_effort": "high",
        },
    }
    packet["host_snapshot"] = {"supported_pairs": [{"exact_model": "gpt-5.6-terra", "reasoning_effort": "high"}]}
    result = project_codex_runtime(packet)
    assert result["status"] == "resolution_need"
    assert result["dispatch_performed"] is False
    assert result["provider_dispatch"] is False
    assert result["reason"] == "default_inheritance_model_ambiguous"

# The worker proposal uses plain assertion functions. Expose them to unittest
# discovery so the focused command executes every C3-03 projection case.
import unittest as _unittest


def load_tests(loader, tests, pattern):
    names = [name for name in globals() if name.startswith("test_")]
    suite = _unittest.TestSuite()
    for name in sorted(names):
        suite.addTest(_unittest.FunctionTestCase(globals()[name], description=name))
    return suite


def _host_catalog_packet(model, effort, *, parent_model='gpt-9.9-unknown', parent_effort='high', special=True, fork='none'):
    return {
        'schema_version': 1,
        'child_task_id': 'C3-05-HOST-CATALOG',
        'semantic_role': 'planner',
        'runtime_surface': 'codex_collaboration',
        'route_authority': 'parent',
        'selected_route': {
            'route_id': 'host-catalog-route', 'special_route_required': special,
            'route_rotation_policy': 'forbidden', 'fallback': 'forbidden' if special else 'not_applicable',
            'exact_model': model if special else None,
            'reasoning_effort': effort if special else None,
        },
        'native_request': {'agent_type': 'default', 'fork_turns': fork, 'mapping_change_approved': False},
        'parent_runtime': {'exact_model': parent_model, 'reasoning_effort': parent_effort},
        'host_snapshot': {'supported_pairs': [{'exact_model': model, 'reasoning_effort': effort}]},
    }


def test_host_catalog_allows_observed_astra_child():
    result = project_codex_runtime(_host_catalog_packet('gpt-6-astra', 'high'))
    assert result['status'] == 'ready'
    assert result['dispatch_receipt']['exact_model'] == 'gpt-6-astra'
    assert result['dispatch_receipt']['reasoning_effort'] == 'high'


def test_host_catalog_missing_pairs_fails_closed():
    packet = _host_catalog_packet('gpt-6-astra', 'high')
    packet['host_snapshot'] = {}
    result = project_codex_runtime(packet)
    assert result['status'] == 'resolution_need'
    assert result['reason'] == 'child_capability_unsupported'
    assert result['dispatch_performed'] is False
    assert result['provider_dispatch'] is False


def test_known_route_without_host_catalog_fails_closed():
    packet = _host_catalog_packet('gpt-5.6-terra', 'high')
    packet.pop('host_snapshot')
    result = project_codex_runtime(packet)
    assert result['status'] == 'resolution_need'
    assert result['dispatch_performed'] is False
    assert result['provider_dispatch'] is False


def test_host_catalog_malformed_pairs_raise_typed_error():
    packet = _host_catalog_packet('gpt-6-astra', 'high')
    packet['host_snapshot']['supported_pairs'] = [{'exact_model': 'gpt-6-astra'}]
    try:
        project_codex_runtime(packet)
    except ProjectionError as exc:
        assert exc.code == 'invalid_packet'
    else:
        raise AssertionError('malformed host catalog must fail closed')


def test_resolver_receipt_compiles_exact_native_preference():
    run = Path(__file__).parent.parent / "docs" / "qwopus-loop" / "run"
    packet = json.loads((run / "c3-07-config-packet.json").read_text())
    compiled, digest = _load_config_receipt(
        str(run / "c3-07-config-receipt-exact.json"), packet
    )
    projected = project_codex_runtime(_compile_role_preference(packet, compiled, digest))
    assert projected["status"] == "ready"
    receipt = projected["dispatch_receipt"]
    assert receipt["config_receipt_sha256"] == digest
    assert receipt["role_preference"]["requested"]["selection_mode"] == "exact"
    assert receipt["exact_model"] == "gpt-5.6-luna"
    assert receipt["reasoning_effort"] == "medium"
    assert receipt["parent_runtime_identity"] == {"exact_model": "unknown", "reasoning_effort": "unknown"}



def test_prefer_supported_pair_applies_preference():
    """Test that prefer mode applies the preference when the pair is supported."""
    packet = {
        "schema_version": 1,
        "child_task_id": "C3-07-PREFER-SUPPORTED",
        "semantic_role": "planner",
        "runtime_surface": "codex_collaboration",
        "route_authority": "parent",
        "selected_route": {
            "route_id": "codex-terra-high",
            "special_route_required": True,
            "route_rotation_policy": "forbidden",
            "fallback": "forbidden",
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
        "native_request": {
            "agent_type": "default",
            "fork_turns": "none",
            "mapping_change_approved": False,
        },
        "parent_runtime": {
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
        "host_snapshot": {
            "supported_pairs": [
                {"exact_model": "gpt-5.6-terra", "reasoning_effort": "high"},
                {"exact_model": "gpt-5.6-luna", "reasoning_effort": "medium"},
            ]
        },
    }
    config_receipt = {
        "effective_config": {
            "role_preferences": {
                "roles": {
                    "planner": {
                        "selection_mode": "prefer",
                        "exact_model": "gpt-5.6-luna",
                        "reasoning_effort": "medium",
                    }
                }
            }
        },
        "provenance": {
            "role_preferences.roles.planner.selection_mode": {"value": "prefer", "lifetime": "goal:test-goal"},
            "role_preferences.roles.planner.exact_model": {"value": "gpt-5.6-luna", "lifetime": "goal:test-goal"},
            "role_preferences.roles.planner.reasoning_effort": {"value": "medium", "lifetime": "goal:test-goal"},
        },
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config_receipt, f)
        config_path = f.name
    try:
        packet["config_context"] = {"goal_id": "test-goal"}
        compiled, digest = _load_config_receipt(config_path, packet)
        projected = project_codex_runtime(_compile_role_preference(packet, compiled, digest))
        assert projected["status"] == "ready"
        receipt = projected["dispatch_receipt"]
        assert receipt["exact_model"] == "gpt-5.6-luna"
        assert receipt["reasoning_effort"] == "medium"
        assert receipt["role_preference"]["requested"]["selection_mode"] == "prefer"
        assert receipt["role_preference"]["effective"]["exact_model"] == "gpt-5.6-luna"
        assert receipt["role_preference"]["effective"]["reasoning_effort"] == "medium"
        assert receipt["role_preference"]["fulfilled"] is True
    finally:
        os.unlink(config_path)


def test_prefer_unsupported_pair_preserves_route():
    """Test that prefer mode preserves the existing route when the pair is not supported."""
    packet = {
        "schema_version": 1,
        "child_task_id": "C3-07-PREFER-UNSUPPORTED",
        "semantic_role": "planner",
        "runtime_surface": "codex_collaboration",
        "route_authority": "parent",
        "selected_route": {
            "route_id": "codex-terra-high",
            "special_route_required": True,
            "route_rotation_policy": "forbidden",
            "fallback": "forbidden",
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
        "native_request": {
            "agent_type": "default",
            "fork_turns": "none",
            "mapping_change_approved": False,
        },
        "parent_runtime": {
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
        "host_snapshot": {
            "supported_pairs": [
                {"exact_model": "gpt-5.6-terra", "reasoning_effort": "high"},
            ]
        },
    }
    config_receipt = {
        "effective_config": {
            "role_preferences": {
                "roles": {
                    "planner": {
                        "selection_mode": "prefer",
                        "exact_model": "gpt-5.6-luna",
                        "reasoning_effort": "medium",
                    }
                }
            }
        },
        "provenance": {
            "role_preferences.roles.planner.selection_mode": {"value": "prefer", "lifetime": "goal:test-goal"},
            "role_preferences.roles.planner.exact_model": {"value": "gpt-5.6-luna", "lifetime": "goal:test-goal"},
            "role_preferences.roles.planner.reasoning_effort": {"value": "medium", "lifetime": "goal:test-goal"},
        },
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config_receipt, f)
        config_path = f.name
    try:
        packet["config_context"] = {"goal_id": "test-goal"}
        compiled, digest = _load_config_receipt(config_path, packet)
        projected = project_codex_runtime(_compile_role_preference(packet, compiled, digest))
        assert projected["status"] == "ready"
        receipt = projected["dispatch_receipt"]
        assert receipt["exact_model"] == "gpt-5.6-terra"
        assert receipt["reasoning_effort"] == "high"
        assert receipt["role_preference"]["requested"]["selection_mode"] == "prefer"
        assert receipt["role_preference"]["requested"]["exact_model"] == "gpt-5.6-luna"
        assert receipt["role_preference"]["effective"]["exact_model"] == "gpt-5.6-terra"
        assert receipt["role_preference"]["effective"]["reasoning_effort"] == "high"
        assert receipt["role_preference"]["fulfilled"] is False
    finally:
        os.unlink(config_path)


def test_prefer_model_without_effort_keeps_existing_effort():
    packet = _host_catalog_packet('gpt-5.6-terra', 'high')
    packet['host_snapshot']['supported_pairs'].append(
        {'exact_model': 'gpt-5.6-luna', 'reasoning_effort': 'high'}
    )
    compiled = {
        'preference': {
            'selection_mode': 'prefer',
            'exact_model': 'gpt-5.6-luna',
            'reasoning_effort': 'unknown',
        },
        'source': 'config_receipt',
        'lifetime': {'selection_mode': 'file', 'exact_model': 'file', 'reasoning_effort': 'file'},
    }
    projected = project_codex_runtime(_compile_role_preference(packet, compiled, 'receipt-digest'))
    assert projected['status'] == 'ready'
    assert projected['dispatch_receipt']['exact_model'] == 'gpt-5.6-luna'
    assert projected['dispatch_receipt']['reasoning_effort'] == 'high'


def test_exact_unavailable_returns_resolution_need():
    """Test that exact mode returns resolution_need when the model is not supported."""
    packet = {
        "schema_version": 1,
        "child_task_id": "C3-07-EXACT-UNAVAILABLE",
        "semantic_role": "planner",
        "runtime_surface": "codex_collaboration",
        "route_authority": "parent",
        "selected_route": {
            "route_id": "codex-terra-high",
            "special_route_required": True,
            "route_rotation_policy": "forbidden",
            "fallback": "forbidden",
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
        "native_request": {
            "agent_type": "default",
            "fork_turns": "none",
            "mapping_change_approved": False,
        },
        "parent_runtime": {
            "exact_model": "gpt-5.6-terra",
            "reasoning_effort": "high",
        },
        "host_snapshot": {
            "supported_pairs": [
                {"exact_model": "gpt-5.6-terra", "reasoning_effort": "high"},
            ]
        },
    }
    config_receipt = {
        "effective_config": {
            "role_preferences": {
                "roles": {
                    "planner": {
                        "selection_mode": "exact",
                        "exact_model": "gpt-5.6-luna",
                        "reasoning_effort": "medium",
                    }
                }
            }
        },
        "provenance": {
            "role_preferences.roles.planner.selection_mode": {"value": "exact", "lifetime": "goal:test-goal"},
            "role_preferences.roles.planner.exact_model": {"value": "gpt-5.6-luna", "lifetime": "goal:test-goal"},
            "role_preferences.roles.planner.reasoning_effort": {"value": "medium", "lifetime": "goal:test-goal"},
        },
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config_receipt, f)
        config_path = f.name
    try:
        packet["config_context"] = {"goal_id": "test-goal"}
        compiled, digest = _load_config_receipt(config_path, packet)
        projected = project_codex_runtime(_compile_role_preference(packet, compiled, digest))
        assert projected["status"] == "resolution_need"
        assert projected["reason"] == "native_identity_unresolved"
        assert projected["dispatch_performed"] is False
        assert projected["provider_dispatch"] is False
    finally:
        os.unlink(config_path)


def _controller_packet():
    packet = _host_catalog_packet('gpt-5.6-terra', 'high', parent_model='gpt-5.6-sol', parent_effort='medium')
    packet['host_snapshot']['supported_pairs'].extend([
        {'exact_model': 'gpt-5.6-sol', 'reasoning_effort': 'medium'},
        {'exact_model': 'gpt-5.6-luna', 'reasoning_effort': 'medium'},
    ])
    packet['controller_execution'] = {
        'enabled': True,
        'scope': {
            'task_id': 'C3-05-HOST-CATALOG',
            'objective': 'bounded implementation',
            'allowed_files': ['plugins/example.py'],
            'validation': [['python3', '-m', 'unittest', 'tests.test_example']],
            'exclusions': ['Parent acceptance'],
        },
        'roles': {
            'controller': {'runtime_surface': 'codex_collaboration', 'model': 'gpt-5.6-terra', 'reasoning_effort': 'high'},
            'worker': {'runtime_surface': 'codex_collaboration', 'model': 'gpt-5.6-sol', 'reasoning_effort': 'medium'},
            'reviewer': {'runtime_surface': 'codex_collaboration', 'model': 'gpt-5.6-luna', 'reasoning_effort': 'medium'},
        },
        'repair_authority': 'controller',
        'final_acceptance_authority': 'parent',
        'reporting': 'exceptions_and_final_only',
    }
    return packet


def test_controller_execution_is_opt_in_and_projects_scope_and_roles():
    result = project_codex_runtime(_controller_packet())
    assert result['status'] == 'ready'
    package = result['dispatch_receipt']['controller_execution']
    assert package['scope']['task_id'] == 'C3-05-HOST-CATALOG'
    assert package['roles']['worker']['model'] == 'gpt-5.6-sol'
    assert package['final_acceptance_authority'] == 'parent'


def test_controller_execution_unavailable_pair_returns_resolution_need():
    packet = _controller_packet()
    packet['controller_execution']['roles']['reviewer']['model'] = 'gpt-9.9-unavailable'
    result = project_codex_runtime(packet)
    assert result['status'] == 'resolution_need'
    assert result['reason'] == 'controller_execution_capability_unavailable'
    assert result['dispatch_performed'] is False
    assert result['resolution_preview']['unavailable_role'].startswith('reviewer:')


def test_controller_execution_unavailable_effort_returns_resolution_need():
    packet = _controller_packet()
    packet['controller_execution']['roles']['worker']['reasoning_effort'] = 'xhigh'
    result = project_codex_runtime(packet)
    assert result['status'] == 'resolution_need'
    assert result['reason'] == 'controller_execution_capability_unavailable'
    assert 'worker:' in result['resolution_preview']['unavailable_role']


def test_controller_execution_cannot_take_parent_acceptance():
    packet = _controller_packet()
    packet['controller_execution']['final_acceptance_authority'] = 'controller'
    try:
        project_codex_runtime(packet)
    except ProjectionError as exc:
        assert exc.code == 'invalid_packet'
        assert 'final_acceptance_authority' in exc.detail
    else:
        raise AssertionError('controller must not own final acceptance')


def test_controller_execution_supports_mixed_native_controller_and_local_worker():
    packet = _controller_packet()
    packet['controller_execution']['roles']['worker'] = {
        'runtime_surface': 'local_qwopus',
        'model': 'Jackrong/Qwopus3.8-27B-Flash-GGUF',
        'reasoning_effort': 'bounded',
    }
    packet['host_snapshot']['role_capabilities'] = {
        'worker': [{
            'runtime_surface': 'local_qwopus',
            'model': 'Jackrong/Qwopus3.8-27B-Flash-GGUF',
            'reasoning_effort': 'bounded',
        }]
    }
    result = project_codex_runtime(packet)
    assert result['status'] == 'ready'
    assert result['dispatch_receipt']['controller_execution']['roles']['worker']['runtime_surface'] == 'local_qwopus'


def test_controller_execution_native_only_does_not_require_local_capability():
    result = project_codex_runtime(_controller_packet())
    assert result['status'] == 'ready'
    assert 'role_capabilities' not in result['dispatch_receipt']['controller_execution']


def test_controller_execution_omission_preserves_default_receipt():
    packet = _host_catalog_packet('gpt-5.6-terra', 'high', parent_model='gpt-5.6-terra')
    result = project_codex_runtime(packet)
    assert result['status'] == 'ready'
    assert 'controller_execution' not in result['dispatch_receipt']


def test_controller_execution_validates_route_before_unavailable_role_preview():
    packet = _controller_packet()
    packet['selected_route'] = {'route_id': 'bad-route'}
    packet['controller_execution']['roles']['reviewer']['model'] = 'gpt-9.9-unavailable'
    try:
        project_codex_runtime(packet)
    except ProjectionError as exc:
        assert exc.code == 'invalid_packet'
        assert 'selected_route.special_route_required' in exc.detail
    else:
        raise AssertionError('malformed route must fail before capability preview')


def test_controller_execution_validates_native_request_before_unavailable_role_preview():
    packet = _controller_packet()
    packet['native_request'] = {'agent_type': 'bad-agent'}
    packet['controller_execution']['roles']['reviewer']['model'] = 'gpt-9.9-unavailable'
    try:
        project_codex_runtime(packet)
    except ProjectionError as exc:
        assert exc.code == 'native_agent_type_unsupported'
    else:
        raise AssertionError('malformed native request must fail before capability preview')


def test_controller_execution_binds_scope_and_effective_controller_identity():
    packet = _controller_packet()
    packet['controller_execution']['scope']['task_id'] = 'other-task'
    try:
        project_codex_runtime(packet)
    except ProjectionError as exc:
        assert exc.code == 'controller_execution_scope_mismatch'
    else:
        raise AssertionError('scope must bind to child_task_id')
    packet = _controller_packet()
    packet['selected_route']['exact_model'] = 'gpt-5.6-sol'
    packet['selected_route']['reasoning_effort'] = 'medium'
    try:
        project_codex_runtime(packet)
    except ProjectionError as exc:
        assert exc.code == 'controller_execution_route_mismatch'
    else:
        raise AssertionError('controller must match effective native identity')


def test_controller_assignment_preserves_json_command_arrays_and_spawn_binding():
    packet = _controller_packet()
    packet['controller_execution']['scope']['validation'] = [['', '  ', 'x', 'x']]
    result = project_codex_runtime(packet)
    assignment = result['dispatch_receipt']['controller_execution']['assignment_text']
    assert '["", "  ", "x", "x"]' in assignment
    assert 'Scope is an instruction; actual enforcement depends on independently configured host permissions; the projection grants no sandbox.' in assignment
    spawned = record_spawn_result(result, 'native-controller-child-1')
    assert spawned['dispatch_receipt']['controller_spawn'] == {
        'role': 'controller', 'child_task_id': 'C3-05-HOST-CATALOG',
        'runtime_child_id': 'native-controller-child-1', 'status': 'recorded',
    }


def test_config_receipt_compiles_controller_worker_and_auditor_preferences():
    packet = _controller_packet()
    packet['semantic_role'] = 'worker'
    packet['selected_route']['exact_model'] = 'gpt-5.6-terra'
    packet['selected_route']['reasoning_effort'] = 'high'
    roles = {}
    provenance = {}
    values = {
        'controller': ('gpt-5.6-terra', 'high'),
        'worker': ('gpt-5.6-sol', 'medium'),
        'auditor': ('gpt-5.6-luna', 'medium'),
    }
    for role, (model, effort) in values.items():
        path_prefix = 'role_preferences.controller' if role == 'controller' else f'role_preferences.roles.{role}'
        roles[role] = {'selection_mode': 'exact', 'exact_model': model, 'reasoning_effort': effort}
        for field, value in roles[role].items():
            provenance[f'{path_prefix}.{field}'] = {'value': value, 'lifetime': 'plugin'}
    receipt = {'effective_config': {'role_preferences': {'roles': roles, 'controller': roles['controller']}}, 'provenance': provenance}
    with tempfile.NamedTemporaryFile('w', delete=False) as handle:
        json.dump(receipt, handle)
        config_path = handle.name
    try:
        compiled, digest = _load_config_receipt(config_path, packet)
        compiled_packet = _compile_execution_preferences(packet, compiled, digest)
        result = project_codex_runtime(compiled_packet)
        package = result['dispatch_receipt']['controller_execution']
        assert package['roles']['controller']['model'] == 'gpt-5.6-terra'
        assert package['roles']['worker']['model'] == 'gpt-5.6-sol'
        assert package['roles']['reviewer']['model'] == 'gpt-5.6-luna'
        assert package['roles']['reviewer']['preference']['source'] == 'config_receipt'
        assert result['dispatch_receipt']['role_preference']['requested']['exact_model'] == 'gpt-5.6-terra'
        assert result['dispatch_receipt']['role_preference']['effective']['exact_model'] == 'gpt-5.6-terra'
    finally:
        os.unlink(config_path)


def _execution_compiled(controller, worker, reviewer):
    def entry(mode, model, effort):
        return {
            'selection_mode': mode,
            'requested': {
                'selection_mode': mode,
                'exact_model': model,
                'reasoning_effort': effort,
            },
            'source': 'config_receipt',
            'lifetime': {
                'selection_mode': 'plugin',
                'exact_model': 'plugin',
                'reasoning_effort': 'plugin',
            },
        }
    return {'execution_preferences': {
        'controller': entry(*controller),
        'worker': entry(*worker),
        'reviewer': entry(*reviewer),
    }}


def test_execution_package_keeps_controller_route_when_prefer_is_unavailable_and_worker_is_local():
    packet = _controller_packet()
    packet['controller_execution']['roles']['worker'] = {
        'runtime_surface': 'local_qwopus',
        'model': 'Jackrong/Qwopus3.8-27B-Flash-GGUF',
        'reasoning_effort': 'bounded',
    }
    packet['host_snapshot']['role_capabilities'] = {
        'worker': [{
            'runtime_surface': 'local_qwopus',
            'model': 'Jackrong/Qwopus3.8-27B-Flash-GGUF',
            'reasoning_effort': 'bounded',
        }]
    }
    compiled = _execution_compiled(
        ('prefer', 'gpt-9.9-unavailable', 'unknown'),
        ('exact', 'Jackrong/Qwopus3.8-27B-Flash-GGUF', 'bounded'),
        ('default', 'unknown', 'unknown'),
    )
    result = project_codex_runtime(_compile_execution_preferences(packet, compiled, 'digest'))
    assert result['status'] == 'ready'
    assert result['dispatch_receipt']['exact_model'] == 'gpt-5.6-terra'
    assert result['dispatch_receipt']['role_preference']['fulfilled'] is False
    assert result['dispatch_receipt']['controller_execution']['roles']['worker']['runtime_surface'] == 'local_qwopus'


def test_execution_model_only_preferences_inherit_role_effort():
    packet = _controller_packet()
    compiled = _execution_compiled(
        ('exact', 'gpt-5.6-terra', 'unknown'),
        ('prefer', 'gpt-5.6-sol', 'unknown'),
        ('default', 'unknown', 'unknown'),
    )
    result = project_codex_runtime(_compile_execution_preferences(packet, compiled, 'digest'))
    assert result['status'] == 'ready'
    roles = result['dispatch_receipt']['controller_execution']['roles']
    assert roles['controller']['reasoning_effort'] == 'high'
    assert roles['worker']['reasoning_effort'] == 'medium'
    assert result['dispatch_receipt']['role_preference']['effective']['reasoning_effort'] == 'high'


def test_cli_rejects_malformed_host_catalog_as_structured_error():
    packet = _controller_packet()
    packet['host_snapshot']['supported_pairs'] = ['bad-entry']
    with tempfile.NamedTemporaryFile('w', delete=False) as handle:
        json.dump(packet, handle)
        packet_path = handle.name
    try:
        script = Path(__file__).parent.parent / 'plugins' / 'codexmax-orchestrator' / 'scripts' / 'project_codex_runtime.py'
        completed = subprocess.run(
            [sys.executable, str(script), packet_path],
            capture_output=True, text=True, check=False,
        )
        payload = json.loads(completed.stdout)
        assert completed.returncode == 2
        assert payload['status'] == 'rejected'
        assert payload['error'] == 'invalid_packet'
        assert 'supported_pairs entry' in payload['detail']
    finally:
        os.unlink(packet_path)
