from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from worldforge.agent_harness_contracts import (
    AGENT_CAPABILITY_GRANT_FORMAT,
    AGENT_HARNESS_VERSION,
    AGENT_WORKER_ACTIVATION_FORMAT,
    AgentHarnessContractError,
    canonical_agent_harness_hash,
    validate_agent_harness_document,
    validate_agent_harness_documents,
)
from worldforge.contract_catalog import load_contract_catalog

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples/multigenre-contracts/agent-harness-minimal"
CAPABILITIES = ["artifact.read", "project.read", "tool.invoke"]
TOOLS = ["source.read", "world.validate"]


def _hash(value: dict[str, object]) -> str:
    payload = copy.deepcopy(value)
    payload.pop("content_hash", None)
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    ).hexdigest()


def _seal(value: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(value)
    result["content_hash"] = _hash(result)
    return result


def _activation() -> dict[str, object]:
    return _seal(
        {
            "format": AGENT_WORKER_ACTIVATION_FORMAT,
            "format_version": AGENT_HARNESS_VERSION,
            "activation_id": "activation_01",
            "execution_id": "execution_01",
            "role": {"id": "author", "revision": 1, "content_hash": "1" * 64},
            "work_order": {
                "id": "work_order_01",
                "revision": 1,
                "content_hash": "2" * 64,
                "capability_ids": CAPABILITIES,
                "tool_ids": TOOLS,
            },
            "runtime": {"id": "harness_runtime", "revision": 1, "content_hash": "3" * 64},
            "prompt": {"id": "prompt_01", "content_hash": "4" * 64},
            "input": {"id": "input_01", "content_hash": "5" * 64},
            "context_mode": "fresh",
            "requested_capability_ids": CAPABILITIES,
            "requested_tool_ids": TOOLS,
            "content_hash": "",
        }
    )


def _grant(activation: dict[str, object]) -> dict[str, object]:
    return _seal(
        {
            "format": AGENT_CAPABILITY_GRANT_FORMAT,
            "format_version": AGENT_HARNESS_VERSION,
            "grant_id": "grant_01",
            "execution_id": "execution_01",
            "activation": {"id": "activation_01", "content_hash": activation["content_hash"]},
            "role": copy.deepcopy(activation["role"]),
            "work_order": copy.deepcopy(activation["work_order"]),
            "runtime": copy.deepcopy(activation["runtime"]),
            "policy": {"capability_ids": CAPABILITIES, "tool_ids": TOOLS},
            "role_capability_ids": CAPABILITIES,
            "role_tool_ids": TOOLS,
            "effective_capability_ids": CAPABILITIES,
            "effective_tool_ids": TOOLS,
            "content_hash": "",
        }
    )


class AgentHarnessContractTests(unittest.TestCase):
    def test_fixture_documents_are_canonical_and_validate_together(self) -> None:
        activation = json.loads((FIXTURES / "worker-activation.json").read_text(encoding="utf-8"))
        grant = json.loads((FIXTURES / "capability-grant.json").read_text(encoding="utf-8"))
        self.assertEqual(canonical_agent_harness_hash(activation), activation["content_hash"])
        self.assertEqual(canonical_agent_harness_hash(grant), grant["content_hash"])
        self.assertEqual(
            json.dumps(
                activation, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode(),
            (FIXTURES / "worker-activation.json").read_bytes(),
        )
        self.assertEqual(
            json.dumps(grant, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(),
            (FIXTURES / "capability-grant.json").read_bytes(),
        )
        aggregate = validate_agent_harness_documents(activation, grant)
        self.assertEqual("activation_01", aggregate.activation["activation_id"])
        self.assertEqual("grant_01", aggregate.grant["grant_id"])

    def test_schema_contract_is_closed_and_hash_bound(self) -> None:
        activation = _activation()
        validate_agent_harness_document(activation, expected_format=AGENT_WORKER_ACTIVATION_FORMAT)
        unknown = _seal({**activation, "raw_prompt": "forbidden"})
        with self.assertRaisesRegex(AgentHarnessContractError, "unknown fields"):
            validate_agent_harness_document(unknown)
        tampered = copy.deepcopy(activation)
        tampered["content_hash"] = "0" * 64
        with self.assertRaisesRegex(AgentHarnessContractError, "content hash"):
            validate_agent_harness_document(tampered)
        self.assertEqual("agent_harness_invalid", AgentHarnessContractError("x").reason_code)

    def test_boolean_version_is_not_an_integer_discriminator(self) -> None:
        activation = _activation()
        activation["format_version"] = True
        with self.assertRaisesRegex(AgentHarnessContractError, "format or format_version"):
            validate_agent_harness_document(_seal(activation))

    def test_integral_float_literals_normalize_like_javascript_numbers(self) -> None:
        activation = json.loads(
            json.dumps(_activation(), separators=(",", ":")).replace(
                '"format_version":1', '"format_version":1.0'
            )
        )
        validated = validate_agent_harness_document(activation)
        self.assertEqual(1, validated["format_version"])
        self.assertIsInstance(validated["format_version"], int)
        exponent_version = json.loads(
            json.dumps(_activation(), separators=(",", ":")).replace(
                '"format_version":1', '"format_version":1e0'
            )
        )
        self.assertEqual(1, validate_agent_harness_document(exponent_version)["format_version"])
        nested_revision = json.loads(
            json.dumps(_activation(), separators=(",", ":")).replace(
                '"revision":1', '"revision":1.0', 1
            )
        )
        self.assertEqual(1, validate_agent_harness_document(nested_revision)["role"]["revision"])

    def test_non_integral_and_unsafe_float_numbers_fail_closed(self) -> None:
        for value in (1.5, float("nan"), float("inf"), 9_007_199_254_740_992.0):
            with self.subTest(value=value):
                activation = _activation()
                activation["format_version"] = value
                with self.assertRaisesRegex(AgentHarnessContractError, "number"):
                    validate_agent_harness_document(activation)
        nested_revision = _activation()
        nested_revision["role"]["revision"] = 1.5
        with self.assertRaisesRegex(AgentHarnessContractError, "number"):
            validate_agent_harness_document(nested_revision)

    def test_sorted_unique_capabilities_and_intersection_are_exact(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        validate_agent_harness_documents(activation, grant)
        duplicate = copy.deepcopy(grant)
        duplicate["effective_capability_ids"] = ["project.read", "project.read"]
        with self.assertRaisesRegex(AgentHarnessContractError, "sorted unique"):
            validate_agent_harness_document(_seal(duplicate))
        incorrect = copy.deepcopy(grant)
        incorrect["effective_capability_ids"] = ["artifact.read", "project.read"]
        with self.assertRaisesRegex(AgentHarnessContractError, "three-way intersection"):
            validate_agent_harness_document(_seal(incorrect))

    def test_capability_and_array_bounds_fail_closed(self) -> None:
        activation = _activation()
        bad_capability = copy.deepcopy(activation)
        bad_capability["requested_capability_ids"] = ["memory.execute"]
        bad_capability["work_order"]["capability_ids"] = ["memory.execute"]
        with self.assertRaisesRegex(AgentHarnessContractError, "unsupported capability"):
            validate_agent_harness_document(_seal(bad_capability))
        unsorted_tools = copy.deepcopy(activation)
        unsorted_tools["requested_tool_ids"] = list(reversed(TOOLS))
        unsorted_tools["work_order"]["tool_ids"] = list(reversed(TOOLS))
        with self.assertRaisesRegex(AgentHarnessContractError, "sorted unique"):
            validate_agent_harness_document(_seal(unsorted_tools))
        too_many_tools = copy.deepcopy(activation)
        tools = [f"tool.capability_{index:02d}" for index in range(65)]
        too_many_tools["requested_tool_ids"] = tools
        too_many_tools["work_order"]["tool_ids"] = tools
        with self.assertRaisesRegex(AgentHarnessContractError, "bounded string array"):
            validate_agent_harness_document(_seal(too_many_tools))
        maximum_tool_id = f"tool.{('aa.' * 338)}aaaaa"
        self.assertEqual(1024, len(maximum_tool_id))
        bounded_tool = copy.deepcopy(activation)
        bounded_tool["requested_tool_ids"] = [maximum_tool_id]
        bounded_tool["work_order"]["tool_ids"] = [maximum_tool_id]
        validate_agent_harness_document(_seal(bounded_tool))
        oversized_tool = copy.deepcopy(bounded_tool)
        oversized_tool["requested_tool_ids"] = [f"{maximum_tool_id}x"]
        oversized_tool["work_order"]["tool_ids"] = [f"{maximum_tool_id}x"]
        with self.assertRaisesRegex(AgentHarnessContractError, "invalid tool ID"):
            validate_agent_harness_document(_seal(oversized_tool))

    def test_safe_integer_boundaries_and_pair_bindings_fail_closed(self) -> None:
        activation = _activation()
        activation["role"]["revision"] = 9_007_199_254_740_991
        validate_agent_harness_document(_seal(activation))
        unsafe = _activation()
        unsafe["role"]["revision"] = 9_007_199_254_740_992
        with self.assertRaisesRegex(AgentHarnessContractError, "JavaScript-safe"):
            validate_agent_harness_document(_seal(unsafe))
        grant = _grant(_activation())
        execution_mismatch = copy.deepcopy(grant)
        execution_mismatch["execution_id"] = "execution_02"
        with self.assertRaisesRegex(AgentHarnessContractError, "execution binding"):
            validate_agent_harness_documents(_activation(), _seal(execution_mismatch))
        role_mismatch = copy.deepcopy(grant)
        role_mismatch["role"]["revision"] = 2
        with self.assertRaisesRegex(AgentHarnessContractError, "role binding"):
            validate_agent_harness_documents(_activation(), _seal(role_mismatch))
        work_order_mismatch = copy.deepcopy(grant)
        work_order_mismatch["work_order"]["revision"] = 2
        with self.assertRaisesRegex(AgentHarnessContractError, "work_order binding"):
            validate_agent_harness_documents(_activation(), _seal(work_order_mismatch))

    def test_pair_rejects_lineage_runtime_and_requested_set_mismatches(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        changed_runtime = copy.deepcopy(grant)
        changed_runtime["runtime"]["id"] = "other_runtime"
        with self.assertRaisesRegex(AgentHarnessContractError, "runtime binding"):
            validate_agent_harness_documents(activation, _seal(changed_runtime))
        changed_requested = copy.deepcopy(activation)
        changed_requested["requested_tool_ids"] = ["source.read"]
        with self.assertRaisesRegex(AgentHarnessContractError, "requested tools"):
            validate_agent_harness_document(_seal(changed_requested))
        changed_lineage = copy.deepcopy(grant)
        changed_lineage["activation"]["content_hash"] = "f" * 64
        with self.assertRaisesRegex(AgentHarnessContractError, "activation binding"):
            validate_agent_harness_documents(activation, _seal(changed_lineage))

    def test_forbidden_surfaces_and_safe_bounds_fail_closed(self) -> None:
        activation = _activation()
        for field in ("endpoint", "command", "env", "filesystem_path", "stderr", "transcript"):
            with self.subTest(field=field):
                value = _seal({**activation, field: "unsafe"})
                with self.assertRaises(AgentHarnessContractError):
                    validate_agent_harness_document(value)
        too_deep: dict[str, object] = _activation()
        cursor = too_deep
        for _ in range(65):
            child: dict[str, object] = {}
            cursor["nested"] = child
            cursor = child
        with self.assertRaisesRegex(AgentHarnessContractError, "depth"):
            validate_agent_harness_document(too_deep)
        oversized = {**activation, "raw": "x" * (1024 * 1024)}
        with self.assertRaisesRegex(AgentHarnessContractError, "byte limit"):
            validate_agent_harness_document(oversized)

    def test_schema_catalog_and_generated_types_are_coherent(self) -> None:
        catalog = load_contract_catalog(ROOT)
        entries = {entry["id"]: entry for entry in catalog["contracts"]}
        expected = {
            "agent-worker-activation": (
                AGENT_WORKER_ACTIVATION_FORMAT,
                "AgentWorkerActivationV1",
            ),
            "agent-capability-grant": (
                AGENT_CAPABILITY_GRANT_FORMAT,
                "AgentCapabilityGrantV1",
            ),
        }
        generated = (ROOT / "apps/studio/src/generated/world-forge-contracts.d.ts").read_text(
            encoding="utf-8"
        )
        for contract_id, (format_name, generated_type) in expected.items():
            with self.subTest(contract=contract_id):
                entry = entries[contract_id]
                self.assertEqual(format_name, entry["format"])
                self.assertEqual(1, entry["version"])
                self.assertIn("tests/test_agent_harness_contracts.py", entry["tests"])
                self.assertIn(generated_type, generated)
                schema = json.loads((ROOT / entry["schema"]).read_text(encoding="utf-8"))
                self.assertEqual(
                    f"https://world-forge.local/schemas/{Path(entry['schema']).name}",
                    schema["$id"],
                )
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(format_name, schema["properties"]["format"]["const"])
                self.assertEqual(
                    AGENT_HARNESS_VERSION,
                    schema["properties"]["format_version"]["const"],
                )


if __name__ == "__main__":
    unittest.main()
