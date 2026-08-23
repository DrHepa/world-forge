from __future__ import annotations

import copy
import json
import subprocess
import unittest
from pathlib import Path

from worldforge.codebase_memory_benchmark import (
    CODEBASE_MEMORY_BENCHMARK_ARMS,
    CODEBASE_MEMORY_BENCHMARK_GATE_IDS,
    CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT,
    CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT,
    CODEBASE_MEMORY_BENCHMARK_REPORT_FORMAT,
    CodebaseMemoryBenchmarkError,
    canonical_codebase_memory_benchmark_hash,
    validate_codebase_memory_benchmark_document,
    validate_codebase_memory_benchmark_documents,
)
from worldforge.contract_catalog import load_contract_catalog

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples/multigenre-contracts/codebase-memory-benchmark-minimal"
SHA = "1" * 64


def _seal(document: dict[str, object]) -> dict[str, object]:
    document["content_hash"] = canonical_codebase_memory_benchmark_hash(document)
    return document


def _plan() -> dict[str, object]:
    return _seal(
        {
            "format": CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT,
            "format_version": 1,
            "benchmark_id": "benchmark_01",
            "source_binding": {
                "revision": "83efe261faf2ed3309da2ae66da20755d96f16df",
                "tree_hash": "2" * 64,
                "checkout_id_hash": "3" * 64,
            },
            "task_set": [
                {
                    "task_id": "navigation_01",
                    "category": "structural_navigation",
                    "task_spec_hash": "4" * 64,
                    "rubric_hash": "5" * 64,
                    "repetitions": 1,
                },
                {
                    "task_id": "other_01",
                    "category": "other",
                    "task_spec_hash": "6" * 64,
                    "rubric_hash": "7" * 64,
                    "repetitions": 1,
                },
            ],
            "arms": list(CODEBASE_MEMORY_BENCHMARK_ARMS),
            "gates": {
                "full_net_token_reduction_basis_points": 3000,
                "structural_net_token_reduction_basis_points": 5000,
                "maximum_quality_loss_basis_points": 200,
                "maximum_critical_omissions": 0,
                "maximum_incremental_p95_ms": 5000,
                "require_tree_unchanged": True,
                "require_zero_unauthorized_egress": True,
            },
            "token_accounting_version": "net_tokens_v1",
            "latency_percentile_method": "nearest_rank",
            "authorized_egress_policy_hash": "8" * 64,
            "tree_guard_policy_hash": "9" * 64,
            "content_hash": SHA,
        }
    )


def _plan_ref(plan: dict[str, object]) -> dict[str, object]:
    return {
        "format": CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT,
        "format_version": 1,
        "id": plan["benchmark_id"],
        "content_hash": plan["content_hash"],
    }


def _observation(
    plan: dict[str, object],
    task_id: str,
    arm: str,
    *,
    state: str = "completed",
    candidate_state: str | None = None,
    reason_codes: list[str] | None = None,
) -> dict[str, object]:
    source_modes = {
        "A_direct_reads": "direct_reads",
        "B_existing_memory": "existing_memory",
        "C_memory_candidate_index": "memory_candidate_index",
    }
    candidate_hash = None
    refresh: int | None = None
    if arm == "C_memory_candidate_index":
        candidate_state = candidate_state or "available"
        if candidate_state != "absent":
            candidate_hash = "a" * 64
        if candidate_state == "available" and state == "completed":
            refresh = 120
    observation_id = f"{task_id}_{arm[0].lower()}_01"
    return _seal(
        {
            "format": CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT,
            "format_version": 1,
            "observation_id": observation_id,
            "plan": _plan_ref(plan),
            "task_id": task_id,
            "repetition_index": 1,
            "arm": arm,
            "state": state,
            "source_mode": source_modes[arm],
            "candidate_state": candidate_state,
            "measurements": {
                "input_tokens": 1000,
                "output_tokens": 100,
                "cached_input_tokens": 100,
                "task_wall_ms": 250,
                "incremental_refresh_ms": refresh,
                "quality_basis_points": 9000,
                "critical_omission_count": 0,
                "final_direct_verification": "pass" if state == "completed" else "unobserved",
                "tree_guard": "pass" if state == "completed" else "unobserved",
                "egress_guard": "pass" if state == "completed" else "unobserved",
            },
            "recorder_identity_hash": "b" * 64,
            "rubric_evidence_hash": "c" * 64,
            "toolchain_identity_hash": "d" * 64,
            "candidate_index_identity_hash": candidate_hash,
            "candidate_index_content_hash": candidate_hash,
            "reason_codes": reason_codes or [],
            "content_hash": SHA,
        }
    )


def _observations(plan: dict[str, object]) -> list[dict[str, object]]:
    values = []
    for task in ("navigation_01", "other_01"):
        for arm in CODEBASE_MEMORY_BENCHMARK_ARMS:
            values.append(_observation(plan, task, arm))
    return values


def _observation_ref(value: dict[str, object]) -> dict[str, object]:
    return {
        "format": CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT,
        "format_version": 1,
        "id": value["observation_id"],
        "content_hash": value["content_hash"],
    }


def _report(plan: dict[str, object], observations: list[dict[str, object]]) -> dict[str, object]:
    refs = sorted(
        (_observation_ref(item) for item in observations),
        key=lambda item: str(item["id"]).encode("utf-8"),
    )
    return _seal(
        {
            "format": CODEBASE_MEMORY_BENCHMARK_REPORT_FORMAT,
            "format_version": 1,
            "report_id": "report_01",
            "plan": _plan_ref(plan),
            "observation_refs": refs,
            "arm_summaries": [
                {
                    "arm": arm,
                    "total_net_tokens": 2000,
                    "quality_basis_points": 9000,
                    "critical_omission_count": 0,
                    "task_wall_p95_ms": 250,
                    "incremental_refresh_p95_ms": 120
                    if arm == "C_memory_candidate_index"
                    else None,
                }
                for arm in CODEBASE_MEMORY_BENCHMARK_ARMS
            ],
            "gates": [
                {"gate_id": gate_id, "passed": False, "reason_codes": ["not_measured"]}
                for gate_id in CODEBASE_MEMORY_BENCHMARK_GATE_IDS
            ],
            "decision": "not_evaluable",
            "reason_codes": ["candidate_evidence_incomplete"],
            "content_hash": SHA,
        }
    )


class CodebaseMemoryBenchmarkTests(unittest.TestCase):
    def test_valid_documents_and_complete_aggregate_are_deep_copied(self) -> None:
        plan = _plan()
        observations = _observations(plan)
        report = _report(plan, observations)
        aggregate = validate_codebase_memory_benchmark_documents(plan, observations, report)
        self.assertEqual("benchmark_01", aggregate.plan["benchmark_id"])
        self.assertEqual(6, len(aggregate.observations))
        self.assertEqual("not_evaluable", aggregate.report["decision"])
        self.assertEqual(
            {
                "arm",
                "total_net_tokens",
                "quality_basis_points",
                "critical_omission_count",
                "task_wall_p95_ms",
                "incremental_refresh_p95_ms",
            },
            set(aggregate.report["arm_summaries"][0]),
        )
        plan["benchmark_id"] = "mutated"
        self.assertEqual("benchmark_01", aggregate.plan["benchmark_id"])

    def test_fixed_arms_gates_and_sorted_tasks_cannot_be_weakened(self) -> None:
        mutations = []
        plan = _plan()
        plan["arms"] = list(reversed(CODEBASE_MEMORY_BENCHMARK_ARMS))
        mutations.append(plan)
        plan = _plan()
        plan["gates"]["maximum_critical_omissions"] = 1  # type: ignore[index]
        mutations.append(plan)
        plan = _plan()
        plan["task_set"] = list(reversed(plan["task_set"]))  # type: ignore[arg-type]
        mutations.append(plan)
        for value in mutations:
            with self.subTest(value=value):
                with self.assertRaises(CodebaseMemoryBenchmarkError):
                    validate_codebase_memory_benchmark_document(_seal(value))

    def test_boolean_discriminators_and_gate_thresholds_are_not_integers(self) -> None:
        boolean_version = _plan()
        boolean_version["format_version"] = True
        boolean_threshold = _plan()
        boolean_threshold["gates"]["maximum_critical_omissions"] = False  # type: ignore[index]
        numeric_guard = _plan()
        numeric_guard["gates"]["require_tree_unchanged"] = 1  # type: ignore[index]
        for value in (boolean_version, boolean_threshold, numeric_guard):
            with self.subTest(value=value):
                with self.assertRaises(CodebaseMemoryBenchmarkError):
                    validate_codebase_memory_benchmark_document(_seal(value))

    def test_observation_arm_source_candidate_state_and_nullability_are_coherent(self) -> None:
        plan = _plan()
        bad_source = _observation(plan, "navigation_01", "A_direct_reads")
        bad_source["source_mode"] = "existing_memory"
        direct_candidate = _observation(plan, "navigation_01", "A_direct_reads")
        direct_candidate["candidate_state"] = "available"
        absent_hash = _observation(
            plan,
            "navigation_01",
            "C_memory_candidate_index",
            candidate_state="absent",
            state="incomplete",
            reason_codes=["candidate_absent"],
        )
        absent_hash["candidate_index_identity_hash"] = "e" * 64
        incomplete_without_reason = _observation(
            plan, "navigation_01", "B_existing_memory", state="incomplete"
        )
        bad_refresh = _observation(plan, "navigation_01", "A_direct_reads")
        bad_refresh["measurements"]["incremental_refresh_ms"] = 1  # type: ignore[index]
        for value in (
            bad_source,
            direct_candidate,
            absent_hash,
            incomplete_without_reason,
            bad_refresh,
        ):
            with self.subTest(value=value):
                with self.assertRaises(CodebaseMemoryBenchmarkError):
                    validate_codebase_memory_benchmark_document(_seal(value))

    def test_measurements_reject_bool_fraction_unsafe_cache_and_accept_integral_float(self) -> None:
        plan = _plan()
        accepted = _observation(plan, "navigation_01", "A_direct_reads")
        accepted["measurements"]["input_tokens"] = 1000.0  # type: ignore[index]
        self.assertEqual(
            1000,
            validate_codebase_memory_benchmark_document(_seal(accepted))["measurements"][
                "input_tokens"
            ],
        )
        for invalid in (True, 1.5, 9_007_199_254_740_992):
            value = _observation(plan, "navigation_01", "A_direct_reads")
            value["measurements"]["input_tokens"] = invalid  # type: ignore[index]
            with self.subTest(invalid=invalid):
                with self.assertRaises(CodebaseMemoryBenchmarkError):
                    validate_codebase_memory_benchmark_document(_seal(value))
        cached = _observation(plan, "navigation_01", "A_direct_reads")
        cached["measurements"]["cached_input_tokens"] = 1001  # type: ignore[index]
        with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "cached"):
            validate_codebase_memory_benchmark_document(_seal(cached))

    def test_hash_size_depth_forbidden_fields_duplicates_and_bounds_fail_closed(self) -> None:
        plan = _plan()
        tampered = copy.deepcopy(plan)
        tampered["benchmark_id"] = "benchmark_02"
        with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "content hash"):
            validate_codebase_memory_benchmark_document(tampered)
        for forbidden_field in ("transcript", "token", "api_key"):
            forbidden = _plan()
            forbidden["metadata"] = {forbidden_field: "raw"}
            with self.subTest(forbidden_field=forbidden_field):
                with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "forbidden"):
                    validate_codebase_memory_benchmark_document(_seal(forbidden))
        duplicate = _plan()
        duplicate["task_set"] = [  # type: ignore[index]
            duplicate["task_set"][0],
            duplicate["task_set"][0],
        ]
        with self.assertRaises(CodebaseMemoryBenchmarkError):
            validate_codebase_memory_benchmark_document(_seal(duplicate))
        too_many_tasks = _plan()
        template = too_many_tasks["task_set"][0]  # type: ignore[index]
        too_many_tasks["task_set"] = [
            {**template, "task_id": f"task_{index:02d}"}  # type: ignore[misc]
            for index in range(65)
        ]
        with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "64"):
            validate_codebase_memory_benchmark_document(_seal(too_many_tasks))
        too_many_repetitions = _plan()
        too_many_repetitions["task_set"][0]["repetitions"] = 65  # type: ignore[index]
        with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "64"):
            validate_codebase_memory_benchmark_document(_seal(too_many_repetitions))
        oversized = _plan()
        oversized["token_accounting_version"] = "a" * (1024 * 1024)
        with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "byte limit"):
            validate_codebase_memory_benchmark_document(_seal(oversized))
        deep: object = "leaf"
        for _ in range(65):
            deep = [deep]
        with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "depth"):
            canonical_codebase_memory_benchmark_hash({"nested": deep})

    def test_aggregate_rejects_missing_duplicate_wrong_task_repetition_arm_and_refs(self) -> None:
        plan = _plan()
        observations = _observations(plan)
        cases = []
        cases.append((observations[:-1], _report(plan, observations[:-1])))
        duplicate = observations[:-1] + [copy.deepcopy(observations[0])]
        cases.append((duplicate, _report(plan, duplicate)))
        wrong_task = copy.deepcopy(observations)
        wrong_task[0]["task_id"] = "unknown_01"
        cases.append((wrong_task, _report(plan, wrong_task)))
        wrong_repetition = copy.deepcopy(observations)
        wrong_repetition[0]["repetition_index"] = 2
        cases.append((wrong_repetition, _report(plan, wrong_repetition)))
        wrong_ref = _report(plan, observations)
        wrong_ref["observation_refs"][0]["content_hash"] = "f" * 64  # type: ignore[index]
        cases.append((observations, _seal(wrong_ref)))
        for values, result in cases:
            with self.subTest(values=values):
                with self.assertRaises(CodebaseMemoryBenchmarkError):
                    validate_codebase_memory_benchmark_documents(plan, values, result)
        wrong_arm = copy.deepcopy(observations)
        wrong_arm[0]["arm"] = "C_memory_candidate_index"
        wrong_arm[0]["source_mode"] = "memory_candidate_index"
        wrong_arm[0]["candidate_state"] = "available"
        wrong_arm[0]["candidate_index_identity_hash"] = "a" * 64
        wrong_arm[0]["candidate_index_content_hash"] = "a" * 64
        wrong_arm[0]["measurements"]["incremental_refresh_ms"] = 120  # type: ignore[index]
        wrong_arm[0] = _seal(wrong_arm[0])
        with self.assertRaises(CodebaseMemoryBenchmarkError):
            validate_codebase_memory_benchmark_documents(plan, wrong_arm, _report(plan, wrong_arm))

    def test_report_decision_and_exact_gate_semantics_fail_closed(self) -> None:
        plan = _plan()
        observations = _observations(plan)
        report = _report(plan, observations)
        adopt = copy.deepcopy(report)
        adopt["decision"] = "adopt"
        adopt["reason_codes"] = []
        for gate in adopt["gates"]:  # type: ignore[union-attr]
            gate["passed"] = True
            gate["reason_codes"] = []
        validate_codebase_memory_benchmark_document(_seal(adopt))
        broken_adopt = copy.deepcopy(adopt)
        broken_adopt["gates"][0]["passed"] = False  # type: ignore[index]
        reject_without_failure = copy.deepcopy(adopt)
        reject_without_failure["decision"] = "reject"
        not_evaluable_without_reason = copy.deepcopy(report)
        not_evaluable_without_reason["reason_codes"] = []
        duplicate_gate = copy.deepcopy(report)
        duplicate_gate["gates"][1]["gate_id"] = duplicate_gate["gates"][0][  # type: ignore[index]
            "gate_id"
        ]
        for value in (
            broken_adopt,
            reject_without_failure,
            not_evaluable_without_reason,
            duplicate_gate,
        ):
            with self.subTest(value=value):
                with self.assertRaises(CodebaseMemoryBenchmarkError):
                    validate_codebase_memory_benchmark_document(_seal(value))

    def test_synthetic_fixtures_are_canonical_truthful_and_aggregate_valid(self) -> None:
        plan = json.loads((FIXTURES / "plan.json").read_text(encoding="utf-8"))
        observations = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(FIXTURES.glob("observation-*.json"))
        ]
        report = json.loads((FIXTURES / "report.json").read_text(encoding="utf-8"))
        aggregate = validate_codebase_memory_benchmark_documents(plan, observations, report)
        self.assertEqual(6, len(aggregate.observations))
        self.assertEqual("not_evaluable", aggregate.report["decision"])
        candidate_states = {
            item["candidate_state"]
            for item in aggregate.observations
            if item["arm"] == "C_memory_candidate_index"
        }
        self.assertEqual({"absent", "incomplete"}, candidate_states)
        for path in FIXTURES.glob("*.json"):
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
                + "\n",
                path.read_text(encoding="utf-8"),
            )

    def test_catalog_generated_types_and_ajv_helper_are_synchronized(self) -> None:
        entries = {entry["id"]: entry for entry in load_contract_catalog(ROOT)["contracts"]}
        expected = {
            "codebase-memory-benchmark-plan": (
                CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT,
                "WorldForgeCodebaseMemoryBenchmarkPlanV1",
            ),
            "codebase-memory-benchmark-observation": (
                CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT,
                "WorldForgeCodebaseMemoryBenchmarkObservationV1",
            ),
            "codebase-memory-benchmark-report": (
                CODEBASE_MEMORY_BENCHMARK_REPORT_FORMAT,
                "WorldForgeCodebaseMemoryBenchmarkReportV1",
            ),
        }
        generated = (ROOT / "apps/studio/src/generated/world-forge-contracts.d.ts").read_text()
        for contract_id, (format_name, type_name) in expected.items():
            entry = entries[contract_id]
            self.assertEqual(format_name, entry["format"])
            self.assertIn(type_name, generated)
            schema = json.loads((ROOT / entry["schema"]).read_text())
            self.assertTrue(schema["x-world-forge-codebase-memory-benchmark-coherent"])
        plan_declaration = generated[
            generated.index(
                "export interface WorldForgeCodebaseMemoryBenchmarkPlanV1"
            ) : generated.index("export interface WorldForgeCodebaseMemoryBenchmarkObservationV1")
        ]
        self.assertIn("full_net_token_reduction_basis_points: 3000;", plan_declaration)
        self.assertIn("require_zero_unauthorized_egress: true;", plan_declaration)
        report_declaration = generated[
            generated.index("export type WorldForgeCodebaseMemoryBenchmarkReportV1") :
        ]
        for arm in CODEBASE_MEMORY_BENCHMARK_ARMS:
            self.assertIn(f'{{ arm: "{arm}" }}', report_declaration)
        for gate_id in CODEBASE_MEMORY_BENCHMARK_GATE_IDS:
            self.assertIn(f'{{ gate_id: "{gate_id}" }}', report_declaration)
        helper = ROOT / "apps/studio/scripts/codebase-memory-benchmark-validation.mjs"
        completed = subprocess.run(
            ["node", str(helper), "--self-test"],
            cwd=ROOT / "apps/studio",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_contract_foundation_adds_no_evaluator_cli_network_or_path_api(self) -> None:
        source = (ROOT / "src/worldforge/codebase_memory_benchmark.py").read_text()
        for forbidden_import in ("import pathlib", "import socket", "import subprocess", "urllib"):
            self.assertNotIn(forbidden_import, source)
        self.assertNotIn("def evaluate_", source)
        self.assertNotIn(
            "codebase-memory-benchmark",
            (ROOT / "src/worldforge/__main__.py").read_text(),
        )
        entries = {entry["id"]: entry for entry in load_contract_catalog(ROOT)["contracts"]}
        for contract_id in (
            "codebase-memory-benchmark-plan",
            "codebase-memory-benchmark-observation",
            "codebase-memory-benchmark-report",
        ):
            self.assertEqual([], entries[contract_id]["cli_commands"])


if __name__ == "__main__":
    unittest.main()
