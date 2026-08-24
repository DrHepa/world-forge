"""Closed recorded-result contracts for optional codebase-memory benchmarks.

This module validates identities and supplied evidence, and can deterministically
evaluate that recorded evidence.  It never executes a benchmark or contacts a tool.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

CODEBASE_MEMORY_BENCHMARK_VERSION = 1
CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT = "world-forge.codebase_memory_benchmark_plan"
CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT = "world-forge.codebase_memory_benchmark_observation"
CODEBASE_MEMORY_BENCHMARK_REPORT_FORMAT = "world-forge.codebase_memory_benchmark_report"
MAX_CODEBASE_MEMORY_BENCHMARK_DOCUMENT_BYTES = 1024 * 1024
MAX_CODEBASE_MEMORY_BENCHMARK_JSON_DEPTH = 64
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_BENCHMARK_TRIALS_PER_ARM = 256
MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER = 10_000_000
MAX_CRITICAL_OMISSIONS_PER_OBSERVATION = 1_000_000
_MAX_OBSERVATIONS_PER_ARM = MAX_BENCHMARK_TRIALS_PER_ARM
MAX_CODEBASE_MEMORY_BENCHMARK_OBSERVATION_REFERENCES = 3 * MAX_BENCHMARK_TRIALS_PER_ARM
MAX_CODEBASE_MEMORY_BENCHMARK_NET_TOKENS_PER_ARM = (
    _MAX_OBSERVATIONS_PER_ARM * 2 * MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER
)
MAX_CODEBASE_MEMORY_BENCHMARK_CRITICAL_OMISSIONS_PER_ARM = (
    _MAX_OBSERVATIONS_PER_ARM * MAX_CRITICAL_OMISSIONS_PER_OBSERVATION
)
MAX_CODEBASE_MEMORY_BENCHMARK_REDUCTION_BASIS_POINTS = (
    MAX_CODEBASE_MEMORY_BENCHMARK_NET_TOKENS_PER_ARM - 1
) * 10_000

CODEBASE_MEMORY_BENCHMARK_ARMS = (
    "A_direct_reads",
    "B_existing_memory",
    "C_memory_candidate_index",
)
CODEBASE_MEMORY_BENCHMARK_GATE_IDS = (
    "full_net_token_reduction",
    "maximum_critical_omissions",
    "maximum_incremental_p95",
    "maximum_quality_loss",
    "structural_net_token_reduction",
    "tree_unchanged",
    "zero_unauthorized_egress",
)

_FORMAT_SET = frozenset(
    {
        CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT,
        CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT,
        CODEBASE_MEMORY_BENCHMARK_REPORT_FORMAT,
    }
)
_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PLAN_FIELDS = frozenset(
    {
        "format",
        "format_version",
        "benchmark_id",
        "source_binding",
        "task_set",
        "arms",
        "gates",
        "token_accounting_version",
        "latency_percentile_method",
        "authorized_egress_policy_hash",
        "tree_guard_policy_hash",
        "content_hash",
    }
)
_SOURCE_BINDING_FIELDS = frozenset({"revision", "tree_hash", "checkout_id_hash"})
_TASK_FIELDS = frozenset({"task_id", "category", "task_spec_hash", "rubric_hash", "repetitions"})
_GATE_POLICY_FIELDS = frozenset(
    {
        "full_net_token_reduction_basis_points",
        "structural_net_token_reduction_basis_points",
        "maximum_quality_loss_basis_points",
        "maximum_critical_omissions",
        "maximum_incremental_p95_ms",
        "require_tree_unchanged",
        "require_zero_unauthorized_egress",
    }
)
_FIXED_GATE_POLICY = {
    "full_net_token_reduction_basis_points": 3000,
    "structural_net_token_reduction_basis_points": 5000,
    "maximum_quality_loss_basis_points": 200,
    "maximum_critical_omissions": 0,
    "maximum_incremental_p95_ms": 5000,
    "require_tree_unchanged": True,
    "require_zero_unauthorized_egress": True,
}
_REFERENCE_FIELDS = frozenset({"format", "format_version", "id", "content_hash"})
_OBSERVATION_FIELDS = frozenset(
    {
        "format",
        "format_version",
        "observation_id",
        "plan",
        "task_id",
        "repetition_index",
        "arm",
        "state",
        "source_mode",
        "candidate_state",
        "measurements",
        "recorder_identity_hash",
        "rubric_evidence_hash",
        "toolchain_identity_hash",
        "candidate_index_identity_hash",
        "candidate_index_content_hash",
        "reason_codes",
        "content_hash",
    }
)
_MEASUREMENT_FIELDS = frozenset(
    {
        "input_tokens",
        "output_tokens",
        "cached_input_tokens",
        "task_wall_ms",
        "incremental_refresh_ms",
        "quality_basis_points",
        "critical_omission_count",
        "final_direct_verification",
        "tree_guard",
        "egress_guard",
    }
)
_REPORT_FIELDS = frozenset(
    {
        "format",
        "format_version",
        "report_id",
        "plan",
        "observation_refs",
        "arm_summaries",
        "gates",
        "decision",
        "reason_codes",
        "content_hash",
    }
)
_ARM_SUMMARY_FIELDS = frozenset(
    {
        "arm",
        "observation_count",
        "total_net_tokens",
        "quality_basis_points",
        "critical_omission_count",
        "task_wall_p95_ms",
        "incremental_refresh_p95_ms",
    }
)
_GATE_RECORD_FIELDS = frozenset({"gate_id", "measured_value", "passed", "reason_codes"})
_SOURCE_MODES = {
    "A_direct_reads": "direct_reads",
    "B_existing_memory": "existing_memory",
    "C_memory_candidate_index": "memory_candidate_index",
}
_FORBIDDEN_FIELDS = frozenset(
    {
        "prompt",
        "prompts",
        "answer",
        "answers",
        "source_excerpt",
        "source_excerpts",
        "transcript",
        "transcripts",
        "path",
        "paths",
        "host",
        "hosts",
        "url",
        "urls",
        "endpoint",
        "endpoints",
        "command",
        "commands",
        "argv",
        "env",
        "environment",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "api_key",
        "token",
        "tokens",
        "api_token",
        "access_token",
        "refresh_token",
        "network_log",
        "network_logs",
        "error",
        "error_text",
        "stderr",
        "stdout",
    }
)


class CodebaseMemoryBenchmarkError(ValueError):
    """Raised when a codebase-memory benchmark document is invalid."""

    def __init__(
        self, detail: str, *, reason_code: str = "codebase_memory_benchmark_invalid"
    ) -> None:
        if reason_code != "codebase_memory_benchmark_invalid":
            raise ValueError("unknown codebase-memory benchmark reason code")
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class CodebaseMemoryBenchmarkDocuments:
    """Structurally resolved plan, observation inventory, and report."""

    plan: dict[str, Any]
    observations: tuple[dict[str, Any], ...]
    report: dict[str, Any]


def _error(detail: str) -> None:
    raise CodebaseMemoryBenchmarkError(detail)


def _normalize_json_numbers(value: object, *, context: str) -> object:
    active: set[int] = set()

    def normalize(current: object, depth: int) -> object:
        if isinstance(current, (dict, list)):
            if depth > MAX_CODEBASE_MEMORY_BENCHMARK_JSON_DEPTH:
                _error(f"{context} JSON depth exceeds {MAX_CODEBASE_MEMORY_BENCHMARK_JSON_DEPTH}")
            identity = id(current)
            if identity in active:
                _error(f"{context} JSON container cycle is unsupported")
            active.add(identity)
            try:
                if isinstance(current, dict):
                    result: dict[str, object] = {}
                    for key, item in current.items():
                        if not isinstance(key, str):
                            _error(f"{context} JSON object keys must be strings")
                        result[key] = normalize(item, depth + 1)
                    return result
                return [normalize(item, depth + 1) for item in current]
            finally:
                active.remove(identity)
        if current is None or isinstance(current, bool):
            return current
        if isinstance(current, int):
            if not -MAX_SAFE_INTEGER <= current <= MAX_SAFE_INTEGER:
                _error(f"{context} JSON integer is outside the JavaScript-safe range")
            return current
        if isinstance(current, float):
            if (
                not math.isfinite(current)
                or not current.is_integer()
                or not -MAX_SAFE_INTEGER <= current <= MAX_SAFE_INTEGER
            ):
                _error(f"{context} JSON number must be a finite JavaScript-safe integer")
            return int(current)
        if isinstance(current, str):
            try:
                current.encode("utf-8")
            except UnicodeError as exc:
                raise CodebaseMemoryBenchmarkError(
                    f"{context} strings must be valid UTF-8"
                ) from exc
            return current
        _error(f"{context} contains unsupported JSON value {type(current).__name__}")

    return normalize(value, 1)


def _canonical_bytes(value: Mapping[str, object], *, omit_content_hash: bool) -> bytes:
    payload = dict(value)
    if omit_content_hash:
        payload.pop("content_hash", None)
    normalized = _normalize_json_numbers(
        payload, context="codebase-memory benchmark canonical JSON"
    )
    try:
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise CodebaseMemoryBenchmarkError(
            f"could not encode canonical codebase-memory benchmark JSON: {exc}"
        ) from exc
    if len(encoded) > MAX_CODEBASE_MEMORY_BENCHMARK_DOCUMENT_BYTES:
        _error(
            "codebase-memory benchmark document exceeds "
            f"{MAX_CODEBASE_MEMORY_BENCHMARK_DOCUMENT_BYTES}-byte limit"
        )
    return encoded


def canonical_codebase_memory_benchmark_hash(value: Mapping[str, object]) -> str:
    """Return the canonical SHA-256 excluding only top-level ``content_hash``."""

    return hashlib.sha256(_canonical_bytes(value, omit_content_hash=True)).hexdigest()


def canonical_codebase_memory_benchmark_bytes(value: Mapping[str, object]) -> bytes:
    """Return canonical compact sorted UTF-8 file bytes with one final newline."""

    return _canonical_bytes(value, omit_content_hash=False) + b"\n"


def _object(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _error(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        _error(f"{context} must be an array")
    return value


def _exact(value: Mapping[str, object], fields: frozenset[str], context: str) -> None:
    unknown, missing = set(value) - fields, fields - set(value)
    if unknown:
        _error(f"{context} contains unknown fields: {', '.join(sorted(unknown))}")
    if missing:
        _error(f"{context} is missing fields: {', '.join(sorted(missing))}")


def _id(value: object, context: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        _error(f"{context} must be a portable lowercase ID")
    return value


def _revision(value: object, context: str) -> str:
    if not isinstance(value, str) or _REVISION_RE.fullmatch(value) is None:
        _error(f"{context} must be a portable revision")
    return value


def _hash(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _error(f"{context} must be a lowercase SHA-256")
    return value


def _integer(
    value: object,
    context: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_SAFE_INTEGER,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        _error(f"{context} must be a JavaScript-safe integer between {minimum} and {maximum}")
    return value


def _nullable_integer(
    value: object, context: str, *, minimum: int = 0, maximum: int = MAX_SAFE_INTEGER
) -> int | None:
    if value is None:
        return None
    return _integer(value, context, minimum=minimum, maximum=maximum)


def _reason_codes(value: object, context: str) -> list[str]:
    values = _array(value, context)
    if len(values) > 64:
        _error(f"{context} must contain at most 64 reason codes")
    codes = [_id(item, f"{context}/{index}") for index, item in enumerate(values)]
    if codes != sorted(set(codes), key=lambda item: item.encode("utf-8")):
        _error(f"{context} must be sorted and unique")
    return codes


def _reject_forbidden_fields(value: object) -> None:
    if isinstance(value, list):
        for item in value:
            _reject_forbidden_fields(item)
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        if key in _FORBIDDEN_FIELDS:
            _error(f"codebase-memory benchmark contains forbidden field {key}")
        _reject_forbidden_fields(item)


def _reference(value: object, context: str, *, expected_format: str) -> dict[str, Any]:
    reference = _object(value, context)
    _exact(reference, _REFERENCE_FIELDS, context)
    version = reference.get("format_version")
    if (
        reference.get("format") != expected_format
        or isinstance(version, bool)
        or version != CODEBASE_MEMORY_BENCHMARK_VERSION
    ):
        _error(f"{context} format or format_version is unsupported")
    _id(reference.get("id"), f"{context}.id")
    _hash(reference.get("content_hash"), f"{context}.content_hash")
    return reference


def _validate_common(document: dict[str, Any], expected_format: str) -> None:
    version = document.get("format_version")
    if (
        document.get("format") != expected_format
        or isinstance(version, bool)
        or version != CODEBASE_MEMORY_BENCHMARK_VERSION
    ):
        _error("codebase-memory benchmark format or format_version is unsupported")
    _hash(document.get("content_hash"), "content_hash")
    if canonical_codebase_memory_benchmark_hash(document) != document.get("content_hash"):
        _error("codebase-memory benchmark content hash does not match canonical contents")


def _validate_plan(document: dict[str, Any]) -> None:
    _exact(document, _PLAN_FIELDS, "benchmark plan")
    _validate_common(document, CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT)
    _id(document.get("benchmark_id"), "benchmark_id")
    source = _object(document.get("source_binding"), "source_binding")
    _exact(source, _SOURCE_BINDING_FIELDS, "source_binding")
    _revision(source.get("revision"), "source_binding.revision")
    _hash(source.get("tree_hash"), "source_binding.tree_hash")
    _hash(source.get("checkout_id_hash"), "source_binding.checkout_id_hash")
    tasks = _array(document.get("task_set"), "task_set")
    if not 1 <= len(tasks) <= 64:
        _error("task_set must contain between 1 and 64 tasks")
    task_ids: list[str] = []
    for index, raw_task in enumerate(tasks):
        task = _object(raw_task, f"task_set/{index}")
        _exact(task, _TASK_FIELDS, f"task_set/{index}")
        task_ids.append(_id(task.get("task_id"), f"task_set/{index}.task_id"))
        if task.get("category") not in {"structural_navigation", "other"}:
            _error(f"task_set/{index}.category is unsupported")
        _hash(task.get("task_spec_hash"), f"task_set/{index}.task_spec_hash")
        _hash(task.get("rubric_hash"), f"task_set/{index}.rubric_hash")
        _integer(task.get("repetitions"), f"task_set/{index}.repetitions", minimum=1, maximum=64)
    if task_ids != sorted(set(task_ids), key=lambda item: item.encode("utf-8")):
        _error("task_set must be sorted unique by task_id")
    if sum(task["repetitions"] for task in tasks) > MAX_BENCHMARK_TRIALS_PER_ARM:
        _error(
            f"task_set repetitions must total at most {MAX_BENCHMARK_TRIALS_PER_ARM} trials per arm"
        )
    if document.get("arms") != list(CODEBASE_MEMORY_BENCHMARK_ARMS):
        _error("benchmark arms must be the exact immutable canonical arms")
    gates = _object(document.get("gates"), "gates")
    _exact(gates, _GATE_POLICY_FIELDS, "gates")
    for field in (
        "full_net_token_reduction_basis_points",
        "structural_net_token_reduction_basis_points",
        "maximum_quality_loss_basis_points",
        "maximum_critical_omissions",
        "maximum_incremental_p95_ms",
    ):
        _integer(gates.get(field), f"gates.{field}")
    for field in ("require_tree_unchanged", "require_zero_unauthorized_egress"):
        if not isinstance(gates.get(field), bool):
            _error(f"gates.{field} must be a boolean")
    if gates != _FIXED_GATE_POLICY:
        _error("benchmark gates must be the exact immutable canonical gates")
    _id(document.get("token_accounting_version"), "token_accounting_version")
    if document.get("latency_percentile_method") != "nearest_rank":
        _error("latency_percentile_method must be nearest_rank")
    _hash(document.get("authorized_egress_policy_hash"), "authorized_egress_policy_hash")
    _hash(document.get("tree_guard_policy_hash"), "tree_guard_policy_hash")


def _validate_observation(document: dict[str, Any]) -> None:
    _exact(document, _OBSERVATION_FIELDS, "benchmark observation")
    _validate_common(document, CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT)
    _id(document.get("observation_id"), "observation_id")
    _reference(document.get("plan"), "plan", expected_format=CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT)
    _id(document.get("task_id"), "task_id")
    _integer(document.get("repetition_index"), "repetition_index", minimum=1, maximum=64)
    arm = document.get("arm")
    if arm not in CODEBASE_MEMORY_BENCHMARK_ARMS:
        _error("observation arm is unsupported")
    state = document.get("state")
    if state not in {"completed", "failed", "incomplete", "invalid"}:
        _error("observation state is unsupported")
    if document.get("source_mode") != _SOURCE_MODES[arm]:
        _error("observation source_mode does not match its arm")
    candidate_state = document.get("candidate_state")
    identity_hash = document.get("candidate_index_identity_hash")
    content_hash = document.get("candidate_index_content_hash")
    if arm != "C_memory_candidate_index":
        if candidate_state is not None or identity_hash is not None or content_hash is not None:
            _error("non-candidate arms require null candidate state and identity hashes")
    else:
        if candidate_state not in {"available", "absent", "untrusted", "incomplete"}:
            _error("candidate arm requires a canonical candidate_state")
        if candidate_state == "absent":
            if identity_hash is not None or content_hash is not None:
                _error("absent candidate requires null candidate index identity hashes")
        else:
            _hash(identity_hash, "candidate_index_identity_hash")
            _hash(content_hash, "candidate_index_content_hash")
        if candidate_state in {"absent", "incomplete"} and state != "incomplete":
            _error("absent or incomplete candidate requires incomplete observation state")
        if candidate_state == "untrusted" and state != "invalid":
            _error("untrusted candidate requires invalid observation state")
        if candidate_state != "available" and state == "completed":
            _error("completed candidate observation requires an available candidate")
    measurements = _object(document.get("measurements"), "measurements")
    _exact(measurements, _MEASUREMENT_FIELDS, "measurements")
    input_tokens = _integer(
        measurements.get("input_tokens"),
        "measurements.input_tokens",
        maximum=MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER,
    )
    _integer(
        measurements.get("output_tokens"),
        "measurements.output_tokens",
        maximum=MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER,
    )
    cached_tokens = _integer(
        measurements.get("cached_input_tokens"),
        "measurements.cached_input_tokens",
        maximum=MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER,
    )
    if cached_tokens > input_tokens:
        _error("measurements.cached_input_tokens cannot exceed input_tokens")
    _integer(measurements.get("task_wall_ms"), "measurements.task_wall_ms")
    refresh = _nullable_integer(
        measurements.get("incremental_refresh_ms"), "measurements.incremental_refresh_ms"
    )
    requires_refresh = (
        arm == "C_memory_candidate_index"
        and candidate_state == "available"
        and state == "completed"
    )
    if requires_refresh != (refresh is not None):
        _error(
            "incremental_refresh_ms is required only for completed available candidate observations"
        )
    _integer(
        measurements.get("quality_basis_points"),
        "measurements.quality_basis_points",
        maximum=10_000,
    )
    _integer(
        measurements.get("critical_omission_count"),
        "measurements.critical_omission_count",
        maximum=MAX_CRITICAL_OMISSIONS_PER_OBSERVATION,
    )
    for field in ("final_direct_verification", "tree_guard", "egress_guard"):
        if measurements.get(field) not in {"pass", "fail", "unobserved"}:
            _error(f"measurements.{field} is unsupported")
    for field in (
        "recorder_identity_hash",
        "rubric_evidence_hash",
        "toolchain_identity_hash",
    ):
        _hash(document.get(field), field)
    reason_codes = _reason_codes(document.get("reason_codes"), "reason_codes")
    if (state == "completed") != (not reason_codes):
        _error("completed observations require no reasons; other states require reason codes")


def _validate_report(document: dict[str, Any]) -> None:
    _exact(document, _REPORT_FIELDS, "benchmark report")
    _validate_common(document, CODEBASE_MEMORY_BENCHMARK_REPORT_FORMAT)
    _id(document.get("report_id"), "report_id")
    _reference(document.get("plan"), "plan", expected_format=CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT)
    references = _array(document.get("observation_refs"), "observation_refs")
    maximum_references = MAX_CODEBASE_MEMORY_BENCHMARK_OBSERVATION_REFERENCES
    if not 1 <= len(references) <= maximum_references:
        _error(f"observation_refs must contain between 1 and {maximum_references} references")
    reference_ids = []
    for index, item in enumerate(references):
        reference = _reference(
            item,
            f"observation_refs/{index}",
            expected_format=CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT,
        )
        reference_ids.append(reference["id"])
    if reference_ids != sorted(set(reference_ids), key=lambda item: item.encode("utf-8")):
        _error("observation_refs must be sorted unique by id")
    summaries = _array(document.get("arm_summaries"), "arm_summaries")
    if len(summaries) != len(CODEBASE_MEMORY_BENCHMARK_ARMS):
        _error("arm_summaries must contain the exact three canonical arms")
    for index, (raw_summary, expected_arm) in enumerate(
        zip(summaries, CODEBASE_MEMORY_BENCHMARK_ARMS, strict=True)
    ):
        summary = _object(raw_summary, f"arm_summaries/{index}")
        _exact(summary, _ARM_SUMMARY_FIELDS, f"arm_summaries/{index}")
        if summary.get("arm") != expected_arm:
            _error("arm_summaries must use the exact canonical arm order")
        _integer(
            summary.get("observation_count"),
            f"arm_summaries/{index}.observation_count",
            minimum=1,
            maximum=MAX_BENCHMARK_TRIALS_PER_ARM,
        )
        _integer(
            summary.get("total_net_tokens"),
            f"arm_summaries/{index}.total_net_tokens",
            maximum=MAX_CODEBASE_MEMORY_BENCHMARK_NET_TOKENS_PER_ARM,
        )
        _integer(
            summary.get("quality_basis_points"),
            f"arm_summaries/{index}.quality_basis_points",
            maximum=10_000,
        )
        _integer(
            summary.get("critical_omission_count"),
            f"arm_summaries/{index}.critical_omission_count",
            maximum=MAX_CODEBASE_MEMORY_BENCHMARK_CRITICAL_OMISSIONS_PER_ARM,
        )
        _integer(summary.get("task_wall_p95_ms"), f"arm_summaries/{index}.task_wall_p95_ms")
        refresh = _nullable_integer(
            summary.get("incremental_refresh_p95_ms"),
            f"arm_summaries/{index}.incremental_refresh_p95_ms",
        )
        if expected_arm != "C_memory_candidate_index" and refresh is not None:
            _error("only the candidate arm may report incremental_refresh_p95_ms")
    gates = _array(document.get("gates"), "gates")
    if len(gates) != len(CODEBASE_MEMORY_BENCHMARK_GATE_IDS):
        _error("report gates must contain the exact seven canonical gate IDs")
    passed: list[bool] = []
    measured_values: list[int | bool | None] = []
    for index, (raw_gate, expected_id) in enumerate(
        zip(gates, CODEBASE_MEMORY_BENCHMARK_GATE_IDS, strict=True)
    ):
        gate = _object(raw_gate, f"gates/{index}")
        _exact(gate, _GATE_RECORD_FIELDS, f"gates/{index}")
        if gate.get("gate_id") != expected_id:
            _error("report gates must use the exact canonical gate ID order")
        measured_value = gate.get("measured_value")
        if expected_id in {"tree_unchanged", "zero_unauthorized_egress"}:
            if measured_value is not None and not isinstance(measured_value, bool):
                _error(f"gates/{index}.measured_value must be a boolean or null")
        elif measured_value is not None:
            minimum, maximum = (
                -MAX_CODEBASE_MEMORY_BENCHMARK_REDUCTION_BASIS_POINTS,
                10_000,
            )
            if expected_id in {"maximum_critical_omissions", "maximum_incremental_p95"}:
                minimum, maximum = 0, MAX_SAFE_INTEGER
            if expected_id == "maximum_quality_loss":
                minimum, maximum = -10_000, 10_000
            _integer(
                measured_value,
                f"gates/{index}.measured_value",
                minimum=minimum,
                maximum=maximum,
            )
        if not isinstance(gate.get("passed"), bool):
            _error(f"gates/{index}.passed must be a boolean")
        reasons = _reason_codes(gate.get("reason_codes"), f"gates/{index}.reason_codes")
        if gate["passed"] == bool(reasons):
            _error("passed gates require no reasons and failed gates require reason codes")
        passed.append(gate["passed"])
        measured_values.append(measured_value)
    decision = document.get("decision")
    if decision not in {"adopt", "reject", "not_evaluable"}:
        _error("report decision is unsupported")
    reasons = _reason_codes(document.get("reason_codes"), "reason_codes")
    if decision == "not_evaluable":
        if any(value is not None for value in measured_values):
            _error("not_evaluable gates require null measured values")
        if any(gate["passed"] or gate["reason_codes"] != ["not_measured"] for gate in gates):
            _error("not_evaluable gates must be failed with only not_measured")
    else:
        if any(value is None for value in measured_values):
            _error("evaluable reports require every gate measured value")
        expected_passes = (
            measured_values[0] >= _FIXED_GATE_POLICY["full_net_token_reduction_basis_points"],
            measured_values[1] <= _FIXED_GATE_POLICY["maximum_critical_omissions"],
            measured_values[2] <= _FIXED_GATE_POLICY["maximum_incremental_p95_ms"],
            measured_values[3] <= _FIXED_GATE_POLICY["maximum_quality_loss_basis_points"],
            measured_values[4] >= _FIXED_GATE_POLICY["structural_net_token_reduction_basis_points"],
            measured_values[5] is True,
            measured_values[6] is True,
        )
        if tuple(passed) != expected_passes:
            _error("gate pass states do not match immutable thresholds")
    if decision == "adopt" and (not all(passed) or reasons):
        _error("adopt requires every gate passed and no report reason codes")
    if decision == "reject" and all(passed):
        _error("reject requires at least one failed gate")
    if decision == "not_evaluable" and not reasons:
        _error("not_evaluable requires at least one report reason code")


def validate_codebase_memory_benchmark_document(
    value: object, *, expected_format: str | None = None
) -> dict[str, Any]:
    """Validate one closed recorded-result document without external effects."""

    try:
        normalized = _normalize_json_numbers(value, context="codebase-memory benchmark document")
        document = _object(normalized, "codebase-memory benchmark document")
        _reject_forbidden_fields(document)
        _canonical_bytes(document, omit_content_hash=False)
        format_name = document.get("format")
        if expected_format is not None and format_name != expected_format:
            _error(f"codebase-memory benchmark document format must be {expected_format}")
        if format_name not in _FORMAT_SET:
            _error("codebase-memory benchmark format or format_version is unsupported")
        validators = {
            CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT: _validate_plan,
            CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT: _validate_observation,
            CODEBASE_MEMORY_BENCHMARK_REPORT_FORMAT: _validate_report,
        }
        validators[format_name](document)
        return copy.deepcopy(document)
    except MemoryError:
        _error("codebase-memory benchmark document exceeds available validation memory")


def _expected_plan_reference(plan: Mapping[str, object]) -> dict[str, object]:
    return {
        "format": CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT,
        "format_version": CODEBASE_MEMORY_BENCHMARK_VERSION,
        "id": plan["benchmark_id"],
        "content_hash": plan["content_hash"],
    }


def _expected_observation_reference(observation: Mapping[str, object]) -> dict[str, object]:
    return {
        "format": CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT,
        "format_version": CODEBASE_MEMORY_BENCHMARK_VERSION,
        "id": observation["observation_id"],
        "content_hash": observation["content_hash"],
    }


def _validated_plan_and_observation_inventory(
    plan: object, observations: Sequence[object]
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...], list[dict[str, object]]]:
    plan_value = validate_codebase_memory_benchmark_document(
        plan, expected_format=CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT
    )
    if isinstance(observations, (str, bytes, bytearray)) or not isinstance(observations, Sequence):
        _error("observations must be a sequence")
    try:
        task_repetitions = {task["task_id"]: task["repetitions"] for task in plan_value["task_set"]}
        remaining_expected = {
            (task_id, repetition, arm)
            for task_id, repetitions in task_repetitions.items()
            for repetition in range(1, repetitions + 1)
            for arm in CODEBASE_MEMORY_BENCHMARK_ARMS
        }
        expected_count = len(remaining_expected)
        try:
            reported_count = len(observations)
        except Exception as exc:
            raise CodebaseMemoryBenchmarkError(
                "could not inspect the observation inventory"
            ) from exc
        # Exact built-ins cannot lie about length. Custom Sequence lengths are hints only.
        if type(observations) in (list, tuple) and reported_count != expected_count:
            _error("observation count does not match the planned inventory")
        expected_plan_ref = _expected_plan_reference(plan_value)
        observation_values: list[dict[str, Any]] = []
        actual_inventory: set[tuple[str, int, str]] = set()
        observation_ids: set[str] = set()
        references: list[dict[str, object]] = []
        actual_count = 0
        try:
            iterator = iter(observations)
        except Exception as exc:
            raise CodebaseMemoryBenchmarkError(
                "could not iterate the observation inventory"
            ) from exc
        while True:
            try:
                item = next(iterator)
            except StopIteration:
                break
            except Exception as exc:
                raise CodebaseMemoryBenchmarkError(
                    "could not iterate the observation inventory"
                ) from exc
            actual_count += 1
            if actual_count > expected_count:
                _error("observation count exceeds the planned inventory")
            observation = validate_codebase_memory_benchmark_document(
                item, expected_format=CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT
            )
            if observation["plan"] != expected_plan_ref:
                _error("observation plan reference does not resolve exactly")
            task_id = observation["task_id"]
            repetition = observation["repetition_index"]
            arm = observation["arm"]
            key = (task_id, repetition, arm)
            if observation["observation_id"] in observation_ids:
                _error("observation_id is duplicated")
            if key in actual_inventory:
                _error("observation task, repetition, and arm identity is duplicated")
            if key not in remaining_expected:
                _error("observation task, repetition, and arm identity is not planned")
            actual_inventory.add(key)
            observation_ids.add(observation["observation_id"])
            remaining_expected.remove(key)
            references.append(_expected_observation_reference(observation))
            observation_values.append(observation)
        if actual_count != expected_count or remaining_expected:
            _error("observation inventory does not cover every planned task, repetition, and arm")
        return (
            plan_value,
            tuple(observation_values),
            sorted(references, key=lambda item: str(item["id"]).encode("utf-8")),
        )
    except MemoryError:
        _error("observation inventory exceeds available validation memory")


def _nearest_rank_95(values: Sequence[int]) -> int:
    ordered = sorted(values)
    return ordered[(95 * len(ordered) + 99) // 100 - 1]


def _mean_half_up(values: Sequence[int]) -> int:
    return (2 * sum(values) + len(values)) // (2 * len(values))


def _report_id(plan: Mapping[str, object]) -> str:
    return f"report_{str(plan['content_hash'])[:32]}"


def _evaluate_validated_codebase_memory_benchmark(
    plan_value: dict[str, Any],
    observation_values: Sequence[dict[str, Any]],
    references: list[dict[str, object]],
) -> dict[str, Any]:
    by_arm = {
        arm: tuple(item for item in observation_values if item["arm"] == arm)
        for arm in CODEBASE_MEMORY_BENCHMARK_ARMS
    }
    summaries: list[dict[str, object]] = []
    totals: dict[str, int] = {}
    for arm in CODEBASE_MEMORY_BENCHMARK_ARMS:
        arm_observations = by_arm[arm]
        net_tokens = [
            item["measurements"]["input_tokens"] + item["measurements"]["output_tokens"]
            for item in arm_observations
        ]
        total = sum(net_tokens)
        if total > MAX_SAFE_INTEGER:
            _error("aggregate total_net_tokens exceeds the JavaScript-safe range")
        omissions = sum(
            item["measurements"]["critical_omission_count"] for item in arm_observations
        )
        if omissions > MAX_SAFE_INTEGER:
            _error("aggregate critical omissions exceed the JavaScript-safe range")
        refresh_values = [
            item["measurements"]["incremental_refresh_ms"]
            for item in arm_observations
            if item["measurements"]["incremental_refresh_ms"] is not None
        ]
        totals[arm] = total
        summaries.append(
            {
                "arm": arm,
                "observation_count": len(arm_observations),
                "total_net_tokens": total,
                "quality_basis_points": _mean_half_up(
                    [item["measurements"]["quality_basis_points"] for item in arm_observations]
                ),
                "critical_omission_count": omissions,
                "task_wall_p95_ms": _nearest_rank_95(
                    [item["measurements"]["task_wall_ms"] for item in arm_observations]
                ),
                "incremental_refresh_p95_ms": (
                    _nearest_rank_95(refresh_values)
                    if arm == "C_memory_candidate_index"
                    and len(refresh_values) == len(arm_observations)
                    else None
                ),
            }
        )

    not_evaluable: set[str] = set()
    candidate_identity: set[tuple[str, str]] = set()
    for observation in observation_values:
        state = observation["state"]
        if state != "completed":
            not_evaluable.add(f"observation_state_{state}")
        measurements = observation["measurements"]
        direct = measurements["final_direct_verification"]
        if direct != "pass":
            not_evaluable.add(
                "final_direct_verification_failed"
                if direct == "fail"
                else "final_direct_verification_unobserved"
            )
        for field in ("tree_guard", "egress_guard"):
            if measurements[field] == "unobserved":
                not_evaluable.add(f"{field}_unobserved")
        if observation["arm"] == "C_memory_candidate_index":
            candidate_state = observation["candidate_state"]
            if candidate_state != "available":
                not_evaluable.add(f"candidate_evidence_{candidate_state}")
            else:
                candidate_identity.add(
                    (
                        observation["candidate_index_identity_hash"],
                        observation["candidate_index_content_hash"],
                    )
                )
    if len(candidate_identity) > 1:
        not_evaluable.add("candidate_identity_mismatch")
    full_denominator = totals["A_direct_reads"]
    if full_denominator == 0:
        not_evaluable.add("zero_full_baseline_denominator")
    task_categories = {task["task_id"]: task["category"] for task in plan_value["task_set"]}
    structural_a = sum(
        item["measurements"]["input_tokens"] + item["measurements"]["output_tokens"]
        for item in by_arm["A_direct_reads"]
        if task_categories[item["task_id"]] == "structural_navigation"
    )
    structural_c = sum(
        item["measurements"]["input_tokens"] + item["measurements"]["output_tokens"]
        for item in by_arm["C_memory_candidate_index"]
        if task_categories[item["task_id"]] == "structural_navigation"
    )
    if structural_a == 0:
        not_evaluable.add("zero_structural_baseline_denominator")

    if not_evaluable:
        gates = [
            {
                "gate_id": gate_id,
                "measured_value": None,
                "passed": False,
                "reason_codes": ["not_measured"],
            }
            for gate_id in CODEBASE_MEMORY_BENCHMARK_GATE_IDS
        ]
        decision = "not_evaluable"
        report_reasons = sorted(not_evaluable, key=lambda item: item.encode("utf-8"))
    else:
        full_reduction = (
            (full_denominator - totals["C_memory_candidate_index"]) * 10_000 // full_denominator
        )
        structural_reduction = (structural_a - structural_c) * 10_000 // structural_a
        quality_loss = summaries[0]["quality_basis_points"] - summaries[2]["quality_basis_points"]
        measured_values: tuple[int | bool, ...] = (
            full_reduction,
            summaries[2]["critical_omission_count"],
            summaries[2]["incremental_refresh_p95_ms"],
            quality_loss,
            structural_reduction,
            all(item["measurements"]["tree_guard"] == "pass" for item in observation_values),
            all(item["measurements"]["egress_guard"] == "pass" for item in observation_values),
        )
        thresholds = (
            full_reduction >= _FIXED_GATE_POLICY["full_net_token_reduction_basis_points"],
            summaries[2]["critical_omission_count"]
            <= _FIXED_GATE_POLICY["maximum_critical_omissions"],
            summaries[2]["incremental_refresh_p95_ms"]
            <= _FIXED_GATE_POLICY["maximum_incremental_p95_ms"],
            quality_loss <= _FIXED_GATE_POLICY["maximum_quality_loss_basis_points"],
            structural_reduction
            >= _FIXED_GATE_POLICY["structural_net_token_reduction_basis_points"],
            measured_values[5] is True,
            measured_values[6] is True,
        )
        failure_reasons = (
            "full_token_reduction_below_threshold",
            "critical_omissions_exceeded",
            "incremental_p95_exceeded",
            "quality_loss_exceeded",
            "structural_token_reduction_below_threshold",
            "tree_changed",
            "unauthorized_egress",
        )
        gates = [
            {
                "gate_id": gate_id,
                "measured_value": measured_value,
                "passed": passed,
                "reason_codes": [] if passed else [failure_reason],
            }
            for gate_id, measured_value, passed, failure_reason in zip(
                CODEBASE_MEMORY_BENCHMARK_GATE_IDS,
                measured_values,
                thresholds,
                failure_reasons,
                strict=True,
            )
        ]
        report_reasons = sorted(
            (gate["reason_codes"][0] for gate in gates if not gate["passed"]),
            key=lambda item: item.encode("utf-8"),
        )
        decision = "adopt" if not report_reasons else "reject"

    report: dict[str, Any] = {
        "format": CODEBASE_MEMORY_BENCHMARK_REPORT_FORMAT,
        "format_version": CODEBASE_MEMORY_BENCHMARK_VERSION,
        "report_id": _report_id(plan_value),
        "plan": _expected_plan_reference(plan_value),
        "observation_refs": references,
        "arm_summaries": summaries,
        "gates": gates,
        "decision": decision,
        "reason_codes": report_reasons,
        "content_hash": "0" * 64,
    }
    report["content_hash"] = canonical_codebase_memory_benchmark_hash(report)
    return validate_codebase_memory_benchmark_document(
        report, expected_format=CODEBASE_MEMORY_BENCHMARK_REPORT_FORMAT
    )


def evaluate_codebase_memory_benchmark(
    plan: object, observations: Sequence[object]
) -> dict[str, Any]:
    """Purely evaluate a complete inventory of supplied recorded evidence."""

    plan_value, observation_values, references = _validated_plan_and_observation_inventory(
        plan, observations
    )
    try:
        return _evaluate_validated_codebase_memory_benchmark(
            plan_value,
            observation_values,
            references,
        )
    except MemoryError:
        _error("benchmark evaluation exceeds available validation memory")


def validate_codebase_memory_benchmark_documents(
    plan: object, observations: Sequence[object], report: object
) -> CodebaseMemoryBenchmarkDocuments:
    """Resolve exact lineage, inventory, and deterministic report authority."""

    plan_value, observation_values, expected_refs = _validated_plan_and_observation_inventory(
        plan, observations
    )
    report_value = validate_codebase_memory_benchmark_document(
        report, expected_format=CODEBASE_MEMORY_BENCHMARK_REPORT_FORMAT
    )
    try:
        expected_report = _evaluate_validated_codebase_memory_benchmark(
            plan_value,
            observation_values,
            expected_refs,
        )
    except MemoryError:
        _error("benchmark evaluation exceeds available validation memory")
    if report_value != expected_report:
        _error("report does not equal the deterministic evaluator output")
    return CodebaseMemoryBenchmarkDocuments(
        plan=plan_value,
        observations=observation_values,
        report=report_value,
    )


__all__ = [
    "CODEBASE_MEMORY_BENCHMARK_ARMS",
    "CODEBASE_MEMORY_BENCHMARK_GATE_IDS",
    "CODEBASE_MEMORY_BENCHMARK_OBSERVATION_FORMAT",
    "CODEBASE_MEMORY_BENCHMARK_PLAN_FORMAT",
    "CODEBASE_MEMORY_BENCHMARK_REPORT_FORMAT",
    "CODEBASE_MEMORY_BENCHMARK_VERSION",
    "CodebaseMemoryBenchmarkDocuments",
    "CodebaseMemoryBenchmarkError",
    "MAX_BENCHMARK_TRIALS_PER_ARM",
    "MAX_CODEBASE_MEMORY_BENCHMARK_CRITICAL_OMISSIONS_PER_ARM",
    "MAX_CODEBASE_MEMORY_BENCHMARK_DOCUMENT_BYTES",
    "MAX_CODEBASE_MEMORY_BENCHMARK_NET_TOKENS_PER_ARM",
    "MAX_CODEBASE_MEMORY_BENCHMARK_OBSERVATION_REFERENCES",
    "MAX_CODEBASE_MEMORY_BENCHMARK_REDUCTION_BASIS_POINTS",
    "MAX_CODEBASE_MEMORY_BENCHMARK_TOKEN_COUNTER",
    "MAX_CRITICAL_OMISSIONS_PER_OBSERVATION",
    "canonical_codebase_memory_benchmark_bytes",
    "canonical_codebase_memory_benchmark_hash",
    "evaluate_codebase_memory_benchmark",
    "validate_codebase_memory_benchmark_document",
    "validate_codebase_memory_benchmark_documents",
]
