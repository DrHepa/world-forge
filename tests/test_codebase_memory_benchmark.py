from __future__ import annotations

import copy
import json
import subprocess
import unittest
from collections.abc import Sequence
from pathlib import Path
from unittest import mock

import worldforge.codebase_memory_benchmark as benchmark_module
from worldforge.codebase_memory_benchmark import (
    CODEBASE_MEMORY_BENCHMARK_ARMS,
    CODEBASE_MEMORY_BENCHMARK_GATE_IDS,
    CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT,
    CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT,
    CODEBASE_MEMORY_BENCHMARK_REPORT_FORMAT,
    MAX_BENCHMARK_TRIALS_PER_ARM,
    MAX_CODEBASE_MEMORY_BENCHMARK_CRITICAL_OMISSIONS_PER_ARM,
    MAX_CODEBASE_MEMORY_BENCHMARK_DOCUMENT_BYTES,
    MAX_CODEBASE_MEMORY_BENCHMARK_NET_TOKENS_PER_ARM,
    MAX_CODEBASE_MEMORY_BENCHMARK_OBSERVATION_REFERENCES,
    MAX_CODEBASE_MEMORY_BENCHMARK_REDUCTION_BASIS_POINTS,
    MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER,
    MAX_CRITICAL_OMISSIONS_PER_OBSERVATION,
    CodebaseMemoryBenchmarkError,
    canonical_codebase_memory_benchmark_bytes,
    canonical_codebase_memory_benchmark_hash,
    evaluate_codebase_memory_benchmark,
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


def _plan_with_repetitions(repetitions: list[int]) -> dict[str, object]:
    plan = _plan()
    plan["benchmark_id"] = "benchmark_" + "x" * 54
    plan["task_set"] = [
        {
            "task_id": f"task_{index:02d}_" + "x" * 56,
            "category": "structural_navigation" if index == 0 else "other",
            "task_spec_hash": f"{index % 10}" * 64,
            "rubric_hash": f"{(index + 1) % 10}" * 64,
            "repetitions": count,
        }
        for index, count in enumerate(repetitions)
    ]
    return _seal(plan)


def _maximum_inventory_observations(
    plan: dict[str, object],
) -> list[dict[str, object]]:
    observations: list[dict[str, object]] = []
    for task_index, task in enumerate(plan["task_set"]):  # type: ignore[union-attr]
        task_id = task["task_id"]
        for repetition in range(1, task["repetitions"] + 1):
            for arm_index, arm in enumerate(CODEBASE_MEMORY_BENCHMARK_ARMS):
                observation = _observation(plan, task_id, arm)
                prefix = f"obs_{task_index:02d}_{repetition:02d}_{arm_index}_"
                observation["observation_id"] = prefix + "x" * (64 - len(prefix))
                observation["repetition_index"] = repetition
                measurements = observation["measurements"]
                measurements["input_tokens"] = 0  # type: ignore[index]
                measurements["output_tokens"] = 0  # type: ignore[index]
                measurements["cached_input_tokens"] = 0  # type: ignore[index]
                if arm == "A_direct_reads" and task_index == 0 and repetition == 1:
                    measurements["input_tokens"] = 1  # type: ignore[index]
                if arm == "C_memory_candidate_index":
                    measurements["input_tokens"] = (  # type: ignore[index]
                        MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER
                    )
                    measurements["output_tokens"] = (  # type: ignore[index]
                        MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER
                    )
                    measurements["critical_omission_count"] = (  # type: ignore[index]
                        MAX_CRITICAL_OMISSIONS_PER_OBSERVATION
                    )
                observations.append(_seal(observation))
    return observations


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
                    "observation_count": 2,
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
                {
                    "gate_id": gate_id,
                    "measured_value": None,
                    "passed": False,
                    "reason_codes": ["not_measured"],
                }
                for gate_id in CODEBASE_MEMORY_BENCHMARK_GATE_IDS
            ],
            "decision": "not_evaluable",
            "reason_codes": ["candidate_evidence_incomplete"],
            "content_hash": SHA,
        }
    )


class CodebaseMemoryBenchmarkTests(unittest.TestCase):
    def test_inventory_preflights_count_and_rejects_duplicates_incrementally(self) -> None:
        plan = _plan()
        observations = _observations(plan)
        original_validator = benchmark_module.validate_codebase_memory_benchmark_document
        observation_validator_calls: list[object] = []

        def instrumented_validator(
            value: object, *, expected_format: str | None = None
        ) -> dict[str, object]:
            if expected_format == CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT:
                observation_validator_calls.append(value)
            return original_validator(value, expected_format=expected_format)

        with mock.patch.object(
            benchmark_module,
            "validate_codebase_memory_benchmark_document",
            side_effect=instrumented_validator,
        ):
            with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "count"):
                evaluate_codebase_memory_benchmark(plan, observations[:-1])
        self.assertEqual([], observation_validator_calls)

        with mock.patch.object(
            benchmark_module,
            "validate_codebase_memory_benchmark_document",
            side_effect=instrumented_validator,
        ):
            with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "count"):
                validate_codebase_memory_benchmark_documents(plan, observations[:-1], {})
        self.assertEqual([], observation_validator_calls)

        duplicate_second = [observations[0], copy.deepcopy(observations[0]), *observations[2:]]
        observation_validator_calls.clear()
        with mock.patch.object(
            benchmark_module,
            "validate_codebase_memory_benchmark_document",
            side_effect=instrumented_validator,
        ):
            with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "duplicated"):
                evaluate_codebase_memory_benchmark(plan, duplicate_second)
        self.assertEqual(2, len(observation_validator_calls))

        observation_validator_calls.clear()
        with mock.patch.object(
            benchmark_module,
            "validate_codebase_memory_benchmark_document",
            side_effect=instrumented_validator,
        ):
            with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "duplicated"):
                validate_codebase_memory_benchmark_documents(plan, duplicate_second, {})
        self.assertEqual(2, len(observation_validator_calls))

    def test_inventory_closure_does_not_trust_custom_sequence_length(self) -> None:
        plan = _plan()
        observations = _observations(plan)
        expected_report = evaluate_codebase_memory_benchmark(plan, observations)

        class RecordedSequence(Sequence[object]):
            def __init__(
                self,
                values: list[object],
                *,
                reported_length: int = 6,
                repeat_forever: bool = False,
                failure: Exception | None = None,
            ) -> None:
                self.values = values
                self.reported_length = reported_length
                self.repeat_forever = repeat_forever
                self.failure = failure
                self.yield_count = 0
                self.length_calls = 0

            def __len__(self) -> int:
                self.length_calls += 1
                return self.reported_length if self.length_calls == 1 else 0

            def __getitem__(self, index: int) -> object:
                return self.values[index]

            def __iter__(self):  # type: ignore[no-untyped-def]
                for value in self.values:
                    self.yield_count += 1
                    yield value
                if self.failure is not None:
                    raise self.failure
                while self.repeat_forever:
                    self.yield_count += 1
                    yield self.values[0]

        omitted_candidate = RecordedSequence(list(observations[:-1]))
        with self.assertRaises(CodebaseMemoryBenchmarkError):
            evaluate_codebase_memory_benchmark(plan, omitted_candidate)
        self.assertEqual(5, omitted_candidate.yield_count)

        empty = RecordedSequence([])
        with self.assertRaises(CodebaseMemoryBenchmarkError) as empty_error:
            evaluate_codebase_memory_benchmark(plan, empty)
        self.assertNotIsInstance(empty_error.exception.__cause__, ZeroDivisionError)
        self.assertEqual(0, empty.yield_count)

        infinite = RecordedSequence(list(observations), repeat_forever=True)
        original_validator = benchmark_module.validate_codebase_memory_benchmark_document
        observation_validation_count = 0

        def count_observation_validation(
            value: object, *, expected_format: str | None = None
        ) -> dict[str, object]:
            nonlocal observation_validation_count
            if expected_format == CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT:
                observation_validation_count += 1
            return original_validator(value, expected_format=expected_format)

        with mock.patch.object(
            benchmark_module,
            "validate_codebase_memory_benchmark_document",
            side_effect=count_observation_validation,
        ):
            with self.assertRaises(CodebaseMemoryBenchmarkError):
                evaluate_codebase_memory_benchmark(plan, infinite)
        self.assertEqual(7, infinite.yield_count)
        self.assertEqual(6, observation_validation_count)

        changing_length = RecordedSequence(list(observations))
        self.assertEqual(expected_report, evaluate_codebase_memory_benchmark(plan, changing_length))
        self.assertEqual(6, changing_length.yield_count)
        self.assertEqual(0, len(changing_length))

        lying_short_length = RecordedSequence(list(observations), reported_length=0)
        self.assertEqual(
            expected_report,
            evaluate_codebase_memory_benchmark(plan, lying_short_length),
        )
        self.assertEqual(6, lying_short_length.yield_count)

        unexpected = copy.deepcopy(observations)
        unexpected[0]["task_id"] = "unexpected_task"
        _seal(unexpected[0])
        unexpected_sequence = RecordedSequence(unexpected)
        with self.assertRaises(CodebaseMemoryBenchmarkError):
            evaluate_codebase_memory_benchmark(plan, unexpected_sequence)
        self.assertEqual(1, unexpected_sequence.yield_count)

        for failure in (RuntimeError("iterator failed"), MemoryError()):
            failing = RecordedSequence([observations[0]], failure=failure)
            with self.subTest(failure=type(failure).__name__):
                with self.assertRaises(CodebaseMemoryBenchmarkError):
                    evaluate_codebase_memory_benchmark(plan, failing)
                self.assertEqual(1, failing.yield_count)

        incomplete_for_aggregate = RecordedSequence(list(observations[:-1]))
        with mock.patch.object(
            benchmark_module,
            "_evaluate_validated_codebase_memory_benchmark",
            side_effect=AssertionError("incomplete inventory reached evaluation"),
        ):
            with self.assertRaises(CodebaseMemoryBenchmarkError):
                validate_codebase_memory_benchmark_documents(
                    plan,
                    incomplete_for_aggregate,
                    expected_report,
                )
        self.assertEqual(5, incomplete_for_aggregate.yield_count)

    def test_memory_errors_at_validation_and_sequence_boundaries_are_normalized(self) -> None:
        plan = _plan()
        observations = _observations(plan)

        class LengthMemoryError(list[object]):
            def __len__(self) -> int:
                raise MemoryError

        class IterationMemoryError(Sequence[object]):
            def __len__(self) -> int:
                return len(observations)

            def __getitem__(self, index: int) -> object:
                if index == 1:
                    raise MemoryError
                if index >= len(observations):
                    raise IndexError
                return observations[index]

        with self.assertRaises(CodebaseMemoryBenchmarkError) as length_error:
            evaluate_codebase_memory_benchmark(plan, LengthMemoryError(observations))
        self.assertIs(type(length_error.exception), CodebaseMemoryBenchmarkError)

        with self.assertRaises(CodebaseMemoryBenchmarkError) as iteration_error:
            evaluate_codebase_memory_benchmark(plan, IterationMemoryError())
        self.assertIs(type(iteration_error.exception), CodebaseMemoryBenchmarkError)

        with mock.patch.object(
            benchmark_module,
            "_normalize_json_numbers",
            side_effect=MemoryError,
        ):
            with self.assertRaises(CodebaseMemoryBenchmarkError) as validation_error:
                validate_codebase_memory_benchmark_document(plan)
        self.assertIs(type(validation_error.exception), CodebaseMemoryBenchmarkError)

        report = evaluate_codebase_memory_benchmark(plan, observations)
        with mock.patch.object(
            benchmark_module,
            "_evaluate_validated_codebase_memory_benchmark",
            side_effect=MemoryError,
        ):
            with self.assertRaises(CodebaseMemoryBenchmarkError) as evaluator_error:
                evaluate_codebase_memory_benchmark(plan, observations)
            with self.assertRaises(CodebaseMemoryBenchmarkError) as aggregate_error:
                validate_codebase_memory_benchmark_documents(plan, observations, report)
        self.assertIs(type(evaluator_error.exception), CodebaseMemoryBenchmarkError)
        self.assertIs(type(aggregate_error.exception), CodebaseMemoryBenchmarkError)

    def test_valid_documents_and_complete_aggregate_are_deep_copied(self) -> None:
        plan = _plan()
        observations = _observations(plan)
        report = evaluate_codebase_memory_benchmark(plan, observations)
        aggregate = validate_codebase_memory_benchmark_documents(plan, observations, report)
        self.assertEqual("benchmark_01", aggregate.plan["benchmark_id"])
        self.assertEqual(6, len(aggregate.observations))
        self.assertEqual("reject", aggregate.report["decision"])
        self.assertEqual(
            {
                "arm",
                "observation_count",
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

    def test_aggregate_report_must_equal_the_deterministic_evaluator(self) -> None:
        plan = _plan()
        observations = _observations(plan)
        expected = evaluate_codebase_memory_benchmark(plan, observations)

        mutations: list[dict[str, object]] = []
        changed_id = copy.deepcopy(expected)
        changed_id["report_id"] = "forged_report"
        mutations.append(_seal(changed_id))

        changed_summary = copy.deepcopy(expected)
        changed_summary["arm_summaries"][0]["total_net_tokens"] += 1
        mutations.append(_seal(changed_summary))

        changed_gate = copy.deepcopy(expected)
        changed_gate["gates"][0]["measured_value"] += 1
        mutations.append(_seal(changed_gate))

        forged_adopt = copy.deepcopy(expected)
        forged_adopt["decision"] = "adopt"
        forged_adopt["reason_codes"] = []
        measured_values = [3000, 0, 5000, 200, 5000, True, True]
        for gate, measured_value in zip(forged_adopt["gates"], measured_values, strict=True):
            gate["measured_value"] = measured_value
            gate["passed"] = True
            gate["reason_codes"] = []
        mutations.append(_seal(forged_adopt))

        for mutation in mutations:
            with self.subTest(mutation=mutation):
                validate_codebase_memory_benchmark_document(mutation)
                with self.assertRaisesRegex(
                    CodebaseMemoryBenchmarkError, "deterministic evaluator"
                ):
                    validate_codebase_memory_benchmark_documents(plan, observations, mutation)

        fixture_plan = json.loads((FIXTURES / "plan.json").read_text(encoding="utf-8"))
        fixture_observations = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(FIXTURES.glob("observation-*.json"))
        ]
        absent_adopt = json.loads((FIXTURES / "report.json").read_text(encoding="utf-8"))
        absent_adopt["decision"] = "adopt"
        absent_adopt["reason_codes"] = []
        for gate, measured_value in zip(absent_adopt["gates"], measured_values, strict=True):
            gate["measured_value"] = measured_value
            gate["passed"] = True
            gate["reason_codes"] = []
        _seal(absent_adopt)
        validate_codebase_memory_benchmark_document(absent_adopt)
        with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "deterministic evaluator"):
            validate_codebase_memory_benchmark_documents(
                fixture_plan, fixture_observations, absent_adopt
            )

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

        bounded = _observation(plan, "navigation_01", "A_direct_reads")
        bounded["measurements"]["input_tokens"] = (  # type: ignore[index]
            MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER
        )
        bounded["measurements"]["cached_input_tokens"] = (  # type: ignore[index]
            MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER
        )
        validate_codebase_memory_benchmark_document(_seal(bounded))
        bounded["measurements"]["input_tokens"] = (  # type: ignore[index]
            MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER + 1
        )
        with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "10000000"):
            validate_codebase_memory_benchmark_document(_seal(bounded))

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
        measured_values = (3000, 0, 5000, 200, 5000, True, True)
        for gate, measured_value in zip(adopt["gates"], measured_values, strict=True):  # type: ignore[arg-type]
            gate["measured_value"] = measured_value
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

    def test_report_measured_value_domains_match_each_immutable_gate(self) -> None:
        plan = _plan()
        observations = _observations(plan)
        report = _report(plan, observations)
        report["decision"] = "adopt"
        report["reason_codes"] = []
        measured_values = [3000, 0, 5000, 200, 5000, True, True]
        for gate, measured_value in zip(report["gates"], measured_values, strict=True):
            gate["measured_value"] = measured_value
            gate["passed"] = True
            gate["reason_codes"] = []
        validate_codebase_memory_benchmark_document(_seal(report))

        invalid_values = {
            0: (-MAX_CODEBASE_MEMORY_BENCHMARK_REDUCTION_BASIS_POINTS - 1, 10_001),
            1: (-1,),
            2: (-1,),
            3: (-10_001, 10_001),
            4: (-MAX_CODEBASE_MEMORY_BENCHMARK_REDUCTION_BASIS_POINTS - 1, 10_001),
            5: (1,),
            6: (0,),
        }
        for gate_index, values in invalid_values.items():
            for invalid in values:
                forged = copy.deepcopy(report)
                forged["gates"][gate_index]["measured_value"] = invalid  # type: ignore[index]
                with self.subTest(gate_index=gate_index, invalid=invalid):
                    with self.assertRaises(CodebaseMemoryBenchmarkError):
                        validate_codebase_memory_benchmark_document(_seal(forged))

        lower_bound = copy.deepcopy(report)
        lower_bound["decision"] = "reject"
        lower_bound["gates"][0] = {  # type: ignore[index]
            "gate_id": "full_net_token_reduction",
            "measured_value": -MAX_CODEBASE_MEMORY_BENCHMARK_REDUCTION_BASIS_POINTS,
            "passed": False,
            "reason_codes": ["full_token_reduction_below_threshold"],
        }
        validate_codebase_memory_benchmark_document(_seal(lower_bound))

    def test_evaluator_adopts_at_exact_thresholds_and_uses_recorded_metrics(self) -> None:
        plan = _plan()
        observations = _observations(plan)
        for observation in observations:
            measurements = observation["measurements"]
            arm = observation["arm"]
            task_id = observation["task_id"]
            if arm == "A_direct_reads":
                measurements["input_tokens"] = 900  # type: ignore[index]
                measurements["output_tokens"] = 100  # type: ignore[index]
            elif arm == "B_existing_memory":
                measurements["input_tokens"] = 900_000  # type: ignore[index]
                measurements["output_tokens"] = 100_000  # type: ignore[index]
                measurements["quality_basis_points"] = 0  # type: ignore[index]
            else:
                measurements["input_tokens"] = 400 if task_id == "navigation_01" else 800  # type: ignore[index]
                measurements["output_tokens"] = 100  # type: ignore[index]
                measurements["cached_input_tokens"] = measurements["input_tokens"]  # type: ignore[index]
                measurements["quality_basis_points"] = 8800  # type: ignore[index]
                measurements["incremental_refresh_ms"] = 5000  # type: ignore[index]
            _seal(observation)

        original_plan = copy.deepcopy(plan)
        original_observations = copy.deepcopy(observations)
        report = evaluate_codebase_memory_benchmark(plan, observations)

        self.assertEqual("adopt", report["decision"])
        self.assertEqual([], report["reason_codes"])
        self.assertEqual(
            [3000, 0, 5000, 200, 5000, True, True],
            [gate["measured_value"] for gate in report["gates"]],
        )
        self.assertEqual(
            [2000, 2_000_000, 1400],
            [summary["total_net_tokens"] for summary in report["arm_summaries"]],
        )
        self.assertEqual([2, 2, 2], [item["observation_count"] for item in report["arm_summaries"]])
        self.assertEqual(5000, report["arm_summaries"][2]["incremental_refresh_p95_ms"])
        self.assertEqual(original_plan, plan)
        self.assertEqual(original_observations, observations)
        self.assertEqual(report, evaluate_codebase_memory_benchmark(plan, observations))
        validate_codebase_memory_benchmark_documents(plan, observations, report)

    def test_evaluator_reports_negative_quality_loss_as_no_loss(self) -> None:
        plan = _plan()
        observations = _observations(plan)
        for observation in observations:
            measurements = observation["measurements"]
            if observation["arm"] == "C_memory_candidate_index":
                measurements["input_tokens"] = 100  # type: ignore[index]
                measurements["output_tokens"] = 0  # type: ignore[index]
                measurements["cached_input_tokens"] = 0  # type: ignore[index]
                measurements["quality_basis_points"] = 9500  # type: ignore[index]
            _seal(observation)
        report = evaluate_codebase_memory_benchmark(plan, observations)
        quality_gate = next(
            gate for gate in report["gates"] if gate["gate_id"] == "maximum_quality_loss"
        )
        self.assertEqual(-500, quality_gate["measured_value"])
        self.assertTrue(quality_gate["passed"])

    def test_evaluator_rejects_each_failed_gate_with_stable_reason(self) -> None:
        expected = {
            "full_net_token_reduction": "full_token_reduction_below_threshold",
            "maximum_critical_omissions": "critical_omissions_exceeded",
            "maximum_incremental_p95": "incremental_p95_exceeded",
            "maximum_quality_loss": "quality_loss_exceeded",
            "structural_net_token_reduction": "structural_token_reduction_below_threshold",
            "tree_unchanged": "tree_changed",
            "zero_unauthorized_egress": "unauthorized_egress",
        }
        for gate_id, reason in expected.items():
            plan = _plan()
            observations = _observations(plan)
            for observation in observations:
                measurements = observation["measurements"]
                if observation["arm"] == "C_memory_candidate_index":
                    measurements["input_tokens"] = 100  # type: ignore[index]
                    measurements["output_tokens"] = 0  # type: ignore[index]
                    measurements["cached_input_tokens"] = 0  # type: ignore[index]
                    measurements["quality_basis_points"] = 9000  # type: ignore[index]
                    measurements["incremental_refresh_ms"] = 1  # type: ignore[index]
                if (
                    gate_id == "full_net_token_reduction"
                    and observation["arm"] == "C_memory_candidate_index"
                    and observation["task_id"] == "other_01"
                ):
                    measurements["input_tokens"] = 3000  # type: ignore[index]
                elif (
                    gate_id == "maximum_critical_omissions"
                    and observation["arm"] == "C_memory_candidate_index"
                ):
                    measurements["critical_omission_count"] = 1  # type: ignore[index]
                elif (
                    gate_id == "maximum_incremental_p95"
                    and observation["arm"] == "C_memory_candidate_index"
                ):
                    measurements["incremental_refresh_ms"] = 5001  # type: ignore[index]
                elif (
                    gate_id == "maximum_quality_loss"
                    and observation["arm"] == "C_memory_candidate_index"
                ):
                    measurements["quality_basis_points"] = 8799  # type: ignore[index]
                elif (
                    gate_id == "structural_net_token_reduction"
                    and observation["arm"] == "C_memory_candidate_index"
                    and observation["task_id"] == "navigation_01"
                ):
                    measurements["input_tokens"] = 600  # type: ignore[index]
                elif gate_id == "tree_unchanged":
                    measurements["tree_guard"] = "fail"  # type: ignore[index]
                elif gate_id == "zero_unauthorized_egress":
                    measurements["egress_guard"] = "fail"  # type: ignore[index]
                _seal(observation)
            report = evaluate_codebase_memory_benchmark(plan, observations)
            with self.subTest(gate_id=gate_id):
                self.assertEqual("reject", report["decision"])
                gate = next(item for item in report["gates"] if item["gate_id"] == gate_id)
                self.assertFalse(gate["passed"])
                self.assertEqual([reason], gate["reason_codes"])
                self.assertIn(reason, report["reason_codes"])

    def test_evaluator_returns_not_evaluable_for_untrusted_or_incomplete_evidence(self) -> None:
        cases = []
        for state, candidate_state, reasons, expected_reason in (
            ("incomplete", "incomplete", ["candidate_incomplete"], "candidate_evidence_incomplete"),
            ("invalid", "untrusted", ["candidate_untrusted"], "candidate_evidence_untrusted"),
        ):
            plan = _plan()
            observations = _observations(plan)
            observations[2] = _observation(
                plan,
                "navigation_01",
                "C_memory_candidate_index",
                state=state,
                candidate_state=candidate_state,
                reason_codes=reasons,
            )
            cases.append((plan, observations, expected_reason))
        for plan, observations, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason):
                report = evaluate_codebase_memory_benchmark(plan, observations)
                self.assertEqual("not_evaluable", report["decision"])
                self.assertIn(expected_reason, report["reason_codes"])
                self.assertTrue(all(gate["measured_value"] is None for gate in report["gates"]))
                self.assertIsNone(report["arm_summaries"][2]["incremental_refresh_p95_ms"])

        plan = _plan()
        observations = _observations(plan)
        observations[5]["candidate_index_identity_hash"] = "e" * 64
        _seal(observations[5])
        mismatch = evaluate_codebase_memory_benchmark(plan, observations)
        self.assertEqual("not_evaluable", mismatch["decision"])
        self.assertIn("candidate_identity_mismatch", mismatch["reason_codes"])

        plan = _plan()
        observations = _observations(plan)
        for index in (2, 5):
            observations[index] = _observation(
                plan,
                observations[index]["task_id"],
                "C_memory_candidate_index",
                state="incomplete",
                candidate_state="absent",
                reason_codes=["candidate_absent"],
            )
        absent = evaluate_codebase_memory_benchmark(plan, observations)
        self.assertIn("candidate_evidence_absent", absent["reason_codes"])
        self.assertNotIn("candidate_identity_mismatch", absent["reason_codes"])

    def test_evaluator_returns_not_evaluable_for_direct_unobserved_and_zero_denominators(
        self,
    ) -> None:
        mutations = []
        plan = _plan()
        observations = _observations(plan)
        observations[0]["measurements"]["final_direct_verification"] = "fail"  # type: ignore[index]
        mutations.append((plan, observations, "final_direct_verification_failed"))
        plan = _plan()
        observations = _observations(plan)
        observations[0]["measurements"]["tree_guard"] = "unobserved"  # type: ignore[index]
        mutations.append((plan, observations, "tree_guard_unobserved"))
        plan = _plan()
        observations = _observations(plan)
        for observation in observations:
            if observation["arm"] == "A_direct_reads":
                observation["measurements"]["input_tokens"] = 0  # type: ignore[index]
                observation["measurements"]["output_tokens"] = 0  # type: ignore[index]
                observation["measurements"]["cached_input_tokens"] = 0  # type: ignore[index]
        mutations.append((plan, observations, "zero_full_baseline_denominator"))
        plan = _plan()
        observations = _observations(plan)
        for observation in observations:
            if observation["arm"] == "A_direct_reads" and observation["task_id"] == "navigation_01":
                observation["measurements"]["input_tokens"] = 0  # type: ignore[index]
                observation["measurements"]["output_tokens"] = 0  # type: ignore[index]
                observation["measurements"]["cached_input_tokens"] = 0  # type: ignore[index]
        mutations.append((plan, observations, "zero_structural_baseline_denominator"))
        for plan, observations, expected_reason in mutations:
            for observation in observations:
                _seal(observation)
            with self.subTest(expected_reason=expected_reason):
                report = evaluate_codebase_memory_benchmark(plan, observations)
                self.assertEqual("not_evaluable", report["decision"])
                self.assertIn(expected_reason, report["reason_codes"])

    def test_evaluator_uses_half_up_mean_nearest_rank_p95_and_repetitions(self) -> None:
        plan = _plan()
        plan["task_set"][0]["repetitions"] = 2  # type: ignore[index]
        _seal(plan)
        observations = _observations(plan)
        for arm in CODEBASE_MEMORY_BENCHMARK_ARMS:
            observations.append(_observation(plan, "navigation_01", arm))
            observations[-1]["repetition_index"] = 2
            observations[-1]["observation_id"] = f"navigation_01_{arm[0].lower()}_02"
        arm_indexes = {arm: 0 for arm in CODEBASE_MEMORY_BENCHMARK_ARMS}
        wall_values = [1, 2, 100]
        for index, observation in enumerate(observations):
            arm = observation["arm"]
            observation["measurements"]["task_wall_ms"] = wall_values[arm_indexes[arm]]  # type: ignore[index]
            arm_indexes[arm] += 1
            observation["measurements"]["quality_basis_points"] = 9000 + (index % 2)  # type: ignore[index]
            _seal(observation)
        report = evaluate_codebase_memory_benchmark(plan, observations)
        self.assertEqual([3, 3, 3], [item["observation_count"] for item in report["arm_summaries"]])
        self.assertEqual(
            [100, 100, 100], [item["task_wall_p95_ms"] for item in report["arm_summaries"]]
        )
        self.assertIn(9000, [item["quality_basis_points"] for item in report["arm_summaries"]])

        half_up_plan = _plan()
        half_up_observations = _observations(half_up_plan)
        for observation in half_up_observations:
            if observation["task_id"] == "other_01":
                observation["measurements"]["quality_basis_points"] = 9001  # type: ignore[index]
            _seal(observation)
        half_up_report = evaluate_codebase_memory_benchmark(half_up_plan, half_up_observations)
        self.assertEqual(
            [9001, 9001, 9001],
            [item["quality_basis_points"] for item in half_up_report["arm_summaries"]],
        )

    def test_plan_total_trials_are_bounded_across_tasks(self) -> None:
        accepted_corpus = (
            [64, 64, 64, 64],
            [4] * 64,
            [64, 63, 63, 63, 3],
        )
        for repetitions in accepted_corpus:
            with self.subTest(accepted=sum(repetitions), repetitions=repetitions):
                self.assertEqual(MAX_BENCHMARK_TRIALS_PER_ARM, sum(repetitions))
                validate_codebase_memory_benchmark_document(_plan_with_repetitions(repetitions))
        for repetitions in ([64, 64, 64, 64, 1], [5] * 52):
            with self.subTest(rejected=sum(repetitions), repetitions=repetitions):
                self.assertGreater(sum(repetitions), MAX_BENCHMARK_TRIALS_PER_ARM)
                with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "256"):
                    validate_codebase_memory_benchmark_document(_plan_with_repetitions(repetitions))

    def test_critical_omissions_have_a_portable_per_observation_bound(self) -> None:
        plan = _plan()
        observation = _observation(plan, "navigation_01", "C_memory_candidate_index")
        observation["measurements"]["critical_omission_count"] = (  # type: ignore[index]
            MAX_CRITICAL_OMISSIONS_PER_OBSERVATION
        )
        validate_codebase_memory_benchmark_document(_seal(observation))
        observation["measurements"]["critical_omission_count"] = (  # type: ignore[index]
            MAX_CRITICAL_OMISSIONS_PER_OBSERVATION + 1
        )
        with self.assertRaisesRegex(CodebaseMemoryBenchmarkError, "1000000"):
            validate_codebase_memory_benchmark_document(_seal(observation))

        observation_schema = json.loads(
            (ROOT / "schemas/codebase-memory-benchmark-observation.schema.json").read_text(
                encoding="utf-8"
            )
        )
        report_schema = json.loads(
            (ROOT / "schemas/codebase-memory-benchmark-report.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            MAX_CRITICAL_OMISSIONS_PER_OBSERVATION,
            observation_schema["$defs"]["critical_omission_counter"]["maximum"],
        )
        self.assertEqual(
            3 * MAX_BENCHMARK_TRIALS_PER_ARM,
            report_schema["properties"]["observation_refs"]["maxItems"],
        )
        self.assertEqual(
            MAX_BENCHMARK_TRIALS_PER_ARM,
            report_schema["$defs"]["arm_summary"]["properties"]["observation_count"]["maximum"],
        )

    def test_maximum_legal_inventory_evaluates_under_the_document_limit(self) -> None:
        plan = _plan_with_repetitions([64, 64, 64, 64])
        observations = _maximum_inventory_observations(plan)
        self.assertEqual(3 * MAX_BENCHMARK_TRIALS_PER_ARM, len(observations))

        original_validator = benchmark_module.validate_codebase_memory_benchmark_document
        observation_validation_count = 0

        def count_observation_validation(
            value: object, *, expected_format: str | None = None
        ) -> dict[str, object]:
            nonlocal observation_validation_count
            if expected_format == CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT:
                observation_validation_count += 1
            return original_validator(value, expected_format=expected_format)

        with mock.patch.object(
            benchmark_module,
            "validate_codebase_memory_benchmark_document",
            side_effect=count_observation_validation,
        ):
            report = evaluate_codebase_memory_benchmark(plan, observations)
        self.assertEqual(3 * MAX_BENCHMARK_TRIALS_PER_ARM, observation_validation_count)

        maximum_arm_tokens = (
            MAX_BENCHMARK_TRIALS_PER_ARM * 2 * MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER
        )
        self.assertEqual(
            maximum_arm_tokens,
            report["arm_summaries"][2]["total_net_tokens"],
        )
        self.assertEqual(
            MAX_BENCHMARK_TRIALS_PER_ARM * MAX_CRITICAL_OMISSIONS_PER_OBSERVATION,
            report["arm_summaries"][2]["critical_omission_count"],
        )
        self.assertEqual("reject", report["decision"])
        self.assertEqual(
            (maximum_arm_tokens - 1) * 10_000,
            MAX_CODEBASE_MEMORY_BENCHMARK_REDUCTION_BASIS_POINTS,
        )
        self.assertEqual(
            -MAX_CODEBASE_MEMORY_BENCHMARK_REDUCTION_BASIS_POINTS,
            report["gates"][0]["measured_value"],
        )
        report_bytes = canonical_codebase_memory_benchmark_bytes(report)
        maximum_reference = {
            "content_hash": "f" * 64,
            "format": CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT,
            "format_version": 1,
            "id": "a" * 64,
        }
        maximum_reference_bytes = len(
            json.dumps(
                maximum_reference,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
        self.assertEqual(235, maximum_reference_bytes)
        maximum_reference_region = 3 * MAX_BENCHMARK_TRIALS_PER_ARM * maximum_reference_bytes + (
            3 * MAX_BENCHMARK_TRIALS_PER_ARM - 1
        )
        conservative_report_bound = maximum_reference_region + 64 * 1024
        self.assertLess(conservative_report_bound, 256 * 1024)
        self.assertEqual(183_256, len(report_bytes))
        self.assertLess(len(report_bytes), conservative_report_bound)
        self.assertLess(len(report_bytes), MAX_CODEBASE_MEMORY_BENCHMARK_DOCUMENT_BYTES)
        self.assertEqual(3 * MAX_BENCHMARK_TRIALS_PER_ARM, len(report["observation_refs"]))
        validate_codebase_memory_benchmark_documents(plan, observations, report)

    def test_report_arm_summary_maxima_are_exact_and_synchronized(self) -> None:
        plan = _plan()
        observations = _observations(plan)
        report = _report(plan, observations)
        for summary in report["arm_summaries"]:
            summary["observation_count"] = MAX_BENCHMARK_TRIALS_PER_ARM
            summary["total_net_tokens"] = MAX_CODEBASE_MEMORY_BENCHMARK_NET_TOKENS_PER_ARM
            summary["critical_omission_count"] = (
                MAX_CODEBASE_MEMORY_BENCHMARK_CRITICAL_OMISSIONS_PER_ARM
            )
        validate_codebase_memory_benchmark_document(_seal(report))

        boundaries = (
            (
                "observation_count",
                MAX_BENCHMARK_TRIALS_PER_ARM + 1,
            ),
            (
                "total_net_tokens",
                MAX_CODEBASE_MEMORY_BENCHMARK_NET_TOKENS_PER_ARM + 1,
            ),
            (
                "critical_omission_count",
                MAX_CODEBASE_MEMORY_BENCHMARK_CRITICAL_OMISSIONS_PER_ARM + 1,
            ),
        )
        for field, invalid in boundaries:
            mutation = copy.deepcopy(report)
            mutation["arm_summaries"][0][field] = invalid
            with self.subTest(field=field):
                with self.assertRaises(CodebaseMemoryBenchmarkError):
                    validate_codebase_memory_benchmark_document(_seal(mutation))

        schema = json.loads(
            (ROOT / "schemas/codebase-memory-benchmark-report.schema.json").read_text(
                encoding="utf-8"
            )
        )
        properties = schema["$defs"]["arm_summary"]["properties"]
        self.assertEqual(
            MAX_BENCHMARK_TRIALS_PER_ARM,
            properties["observation_count"]["maximum"],
        )
        self.assertEqual(
            MAX_CODEBASE_MEMORY_BENCHMARK_NET_TOKENS_PER_ARM,
            properties["total_net_tokens"]["maximum"],
        )
        self.assertEqual(
            MAX_CODEBASE_MEMORY_BENCHMARK_CRITICAL_OMISSIONS_PER_ARM,
            properties["critical_omission_count"]["maximum"],
        )
        self.assertEqual(
            MAX_CODEBASE_MEMORY_BENCHMARK_OBSERVATION_REFERENCES,
            schema["properties"]["observation_refs"]["maxItems"],
        )

    def test_worst_case_valid_inventory_keeps_totals_and_reductions_safe(self) -> None:
        plan = _plan()
        observations = _observations(plan)
        for observation in observations:
            measurements = observation["measurements"]
            measurements["input_tokens"] = 0  # type: ignore[index]
            measurements["output_tokens"] = 0  # type: ignore[index]
            measurements["cached_input_tokens"] = 0  # type: ignore[index]
            if observation["arm"] == "A_direct_reads" and observation["task_id"] == "navigation_01":
                measurements["input_tokens"] = 1  # type: ignore[index]
            if observation["arm"] == "C_memory_candidate_index":
                measurements["input_tokens"] = (  # type: ignore[index]
                    MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER
                )
                measurements["output_tokens"] = (  # type: ignore[index]
                    MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER
                )
            _seal(observation)
        report = evaluate_codebase_memory_benchmark(plan, observations)
        expected_candidate_total = 4 * MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER
        self.assertEqual(
            expected_candidate_total,
            report["arm_summaries"][2]["total_net_tokens"],
        )
        expected_reduction = (1 - expected_candidate_total) * 10_000
        self.assertEqual(
            (MAX_BENCHMARK_TRIALS_PER_ARM * 2 * MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER - 1)
            * 10_000,
            MAX_CODEBASE_MEMORY_BENCHMARK_REDUCTION_BASIS_POINTS,
        )
        self.assertLess(MAX_CODEBASE_MEMORY_BENCHMARK_REDUCTION_BASIS_POINTS, 9_007_199_254_740_991)
        self.assertEqual(
            expected_reduction,
            report["gates"][0]["measured_value"],
        )
        validate_codebase_memory_benchmark_documents(plan, observations, report)

    def test_synthetic_inputs_evaluate_byte_identically_to_report_fixture(self) -> None:
        plan = json.loads((FIXTURES / "plan.json").read_text(encoding="utf-8"))
        observations = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(FIXTURES.glob("observation-*.json"))
        ]
        expected = json.loads((FIXTURES / "report.json").read_text(encoding="utf-8"))
        actual = evaluate_codebase_memory_benchmark(plan, observations)
        self.assertEqual(expected, actual)
        self.assertEqual(
            json.dumps(actual, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n",
            (FIXTURES / "report.json").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            (FIXTURES / "report.json").read_bytes(),
            canonical_codebase_memory_benchmark_bytes(actual),
        )

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
            self.assertIn(f'gate_id: "{gate_id}"', report_declaration)
        self.assertIn("observation_count: number;", generated)
        self.assertIn("@maxItems 768", generated)
        self.assertIn('via the `definition` "critical_omission_counter"', generated)
        self.assertIn("measured_value: number | boolean | null;", generated)
        self.assertIn(
            'gate_id: "tree_unchanged"; measured_value: boolean | null',
            report_declaration,
        )
        helper = ROOT / "apps/studio/scripts/codebase-memory-benchmark-validation.mjs"
        completed = subprocess.run(
            ["node", str(helper), "--self-test"],
            cwd=ROOT / "apps/studio",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_evaluator_module_adds_no_network_process_or_path_api(self) -> None:
        source = (ROOT / "src/worldforge/codebase_memory_benchmark.py").read_text()
        for forbidden_import in ("import pathlib", "import socket", "import subprocess", "urllib"):
            self.assertNotIn(forbidden_import, source)
        self.assertIn("def evaluate_codebase_memory_benchmark", source)
        entries = {entry["id"]: entry for entry in load_contract_catalog(ROOT)["contracts"]}
        for contract_id in (
            "codebase-memory-benchmark-plan",
            "codebase-memory-benchmark-observation",
            "codebase-memory-benchmark-report",
        ):
            self.assertEqual(
                ["evaluate-codebase-memory-benchmark"],
                entries[contract_id]["cli_commands"],
            )


if __name__ == "__main__":
    unittest.main()
