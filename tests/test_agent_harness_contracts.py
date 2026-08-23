from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from worldforge.agent_harness_contracts import (
    AGENT_CAPABILITY_GRANT_FORMAT,
    AGENT_EVENT_FORMAT,
    AGENT_EXECUTION_RECEIPT_FORMAT,
    AGENT_HARNESS_VERSION,
    AGENT_MEMORY_PROJECTION_FORMAT,
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
BASELINE_FIXTURE_SHA256 = {
    "worker-activation.json": "f8224c8b22ee2836dd14785536abb6c9ed399cc7cce0e63ae49a18fbc044e39f",
    "capability-grant.json": "9aa237725ff3600c8085d29a48248124b529ad73dd68e603ba2a7cd99a14407c",
    "event-00.json": "058655ed59983e612dfd1435066140d36f591dd767c2de03bb451a1b3991c279",
    "event-01.json": "bd6a12671cb8089dcd609a893d5c25c61e4c6ea6f15b78803efb62931d366ac1",
    "execution-receipt.json": "dcaa37f483f21203107ea16bc8330b5bd75374aa1124a4ddda16efe4917247d0",
}
EVENT_SUBJECT_FORMATS = {
    "worker.activated": AGENT_WORKER_ACTIVATION_FORMAT,
    "grant.issued": AGENT_CAPABILITY_GRANT_FORMAT,
    "execution.started": AGENT_WORKER_ACTIVATION_FORMAT,
    "execution.cancel_requested": AGENT_WORKER_ACTIVATION_FORMAT,
    "execution.receipt_recorded": AGENT_EXECUTION_RECEIPT_FORMAT,
    "memory.projected": AGENT_MEMORY_PROJECTION_FORMAT,
}


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
            "execution_id": activation["execution_id"],
            "activation": {
                "id": activation["activation_id"],
                "content_hash": activation["content_hash"],
            },
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


def _receipt(
    activation: dict[str, object],
    grant: dict[str, object],
    *,
    invocations: int = 1,
) -> dict[str, object]:
    tool_invocations = [
        {
            "invocation_id": f"invocation_{index:03d}",
            "sequence": index,
            "tool_id": TOOLS[index % len(TOOLS)],
            "request_hash": f"{(index % 9) + 1}" * 64,
            "outcome": "succeeded",
            "result_artifacts": [],
            "failure_codes": [],
        }
        for index in range(invocations)
    ]
    return _seal(
        {
            "format": AGENT_EXECUTION_RECEIPT_FORMAT,
            "format_version": AGENT_HARNESS_VERSION,
            "receipt_id": "receipt_01",
            "execution_id": activation["execution_id"],
            "activation": {
                "id": activation["activation_id"],
                "content_hash": activation["content_hash"],
            },
            "grant": {"id": grant["grant_id"], "content_hash": grant["content_hash"]},
            "runtime_binding": copy.deepcopy(activation["runtime"]),
            "prompt_identities": [copy.deepcopy(activation["prompt"])],
            "tool_invocations": tool_invocations,
            "result_artifacts": [
                {"id": "artifact_01", "content_hash": "a" * 64},
                {"id": "artifact_02", "content_hash": "b" * 64},
            ],
            "usage": {
                "input_tokens": 3,
                "output_tokens": 2,
                "cached_input_tokens": 1,
                "duration_ms": 5,
                "cost_minor_units": 0,
                "currency": "USD",
            },
            "outcome": "succeeded",
            "failure_codes": [],
            "replay_support": "not_claimed",
            "content_hash": "",
        }
    )


def _subject(
    event_type: str,
    activation: dict[str, object],
    grant: dict[str, object],
    receipt: dict[str, object] | None = None,
    projection: dict[str, object] | None = None,
) -> dict[str, object]:
    if event_type == "grant.issued":
        identifier, content_hash = grant["grant_id"], grant["content_hash"]
    elif event_type == "execution.receipt_recorded":
        if receipt is None:
            raise AssertionError("receipt subject requires a receipt")
        identifier, content_hash = receipt["receipt_id"], receipt["content_hash"]
    elif event_type == "memory.projected":
        if projection is None:
            identifier, content_hash = "projection_01", "c" * 64
        else:
            identifier, content_hash = projection["projection_id"], projection["content_hash"]
    else:
        identifier, content_hash = activation["activation_id"], activation["content_hash"]
    return {
        "format": EVENT_SUBJECT_FORMATS[event_type],
        "format_version": AGENT_HARNESS_VERSION,
        "id": identifier,
        "content_hash": content_hash,
    }


def _event(
    event_type: str,
    sequence: int,
    previous_event_hash: str | None,
    activation: dict[str, object],
    grant: dict[str, object],
    receipt: dict[str, object] | None = None,
    projection: dict[str, object] | None = None,
) -> dict[str, object]:
    return _seal(
        {
            "format": AGENT_EVENT_FORMAT,
            "format_version": AGENT_HARNESS_VERSION,
            "event_id": f"event_{sequence:02d}",
            "log_id": "log_01",
            "execution_id": activation["execution_id"],
            "sequence": sequence,
            "previous_event_hash": previous_event_hash,
            "event_type": event_type,
            "subject": _subject(event_type, activation, grant, receipt, projection),
            "content_hash": "",
        }
    )


def _event_chain(
    event_types: list[str],
    activation: dict[str, object],
    grant: dict[str, object],
    receipt: dict[str, object] | None = None,
    projection: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    previous: str | None = None
    for sequence, event_type in enumerate(event_types):
        event = _event(event_type, sequence, previous, activation, grant, receipt, projection)
        result.append(event)
        previous = event["content_hash"]
    return result


def _projection(
    activation: dict[str, object],
    receipt: dict[str, object],
    source_events: list[dict[str, object]],
    *,
    entries: int = 1,
) -> dict[str, object]:
    source_refs = [
        {
            "format": AGENT_EVENT_FORMAT,
            "format_version": AGENT_HARNESS_VERSION,
            "id": event["event_id"],
            "content_hash": event["content_hash"],
        }
        for event in source_events
    ]
    source_ids = [event["event_id"] for event in source_events]
    memory_entries = [
        {
            "entry_id": f"entry_{index:02d}",
            "kind": "decision" if index % 2 == 0 else "discovery",
            "subject_id": f"subject_{index:02d}",
            "value_hash": f"{(index % 9) + 1}" * 64,
            "source_event_ids": source_ids,
        }
        for index in range(entries)
    ]
    return _seal(
        {
            "format": AGENT_MEMORY_PROJECTION_FORMAT,
            "format_version": AGENT_HARNESS_VERSION,
            "projection_id": "projection_01",
            "execution_id": activation["execution_id"],
            "receipt": {
                "format": AGENT_EXECUTION_RECEIPT_FORMAT,
                "format_version": AGENT_HARNESS_VERSION,
                "id": receipt["receipt_id"],
                "content_hash": receipt["content_hash"],
            },
            "source_events": source_refs,
            "review": {
                "review_id": "review_01",
                "reviewer_id": "reviewer_01",
                "policy_id": "memory_policy",
                "policy_version": 1,
                "policy_hash": "d" * 64,
                "receipt_content_hash": receipt["content_hash"],
                "decision": "approved",
            },
            "entries": memory_entries,
            "content_hash": "",
        }
    )


class AgentHarnessContractTests(unittest.TestCase):
    def test_all_seven_fixtures_are_canonical_and_aggregate_valid(self) -> None:
        fixture_names = {
            "worker-activation.json",
            "capability-grant.json",
            "event-00.json",
            "event-01.json",
            "execution-receipt.json",
            "memory-projection.json",
            "event-02.json",
        }
        self.assertEqual(fixture_names, {path.name for path in FIXTURES.glob("*.json")})
        documents = {
            name: json.loads((FIXTURES / name).read_text(encoding="utf-8"))
            for name in fixture_names
        }
        for name, document in documents.items():
            with self.subTest(fixture=name):
                self.assertEqual(canonical_agent_harness_hash(document), document["content_hash"])
                self.assertEqual(
                    json.dumps(
                        document, ensure_ascii=False, separators=(",", ":"), sort_keys=True
                    ).encode(),
                    (FIXTURES / name).read_bytes(),
                )
        for name, expected_sha256 in BASELINE_FIXTURE_SHA256.items():
            with self.subTest(baseline_fixture=name):
                self.assertEqual(
                    expected_sha256,
                    hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest(),
                )
        aggregate = validate_agent_harness_documents(
            documents["worker-activation.json"],
            documents["capability-grant.json"],
            [
                documents["event-00.json"],
                documents["event-01.json"],
                documents["event-02.json"],
            ],
            documents["execution-receipt.json"],
            documents["memory-projection.json"],
        )
        self.assertEqual([0, 1, 2], [event["sequence"] for event in aggregate.events])
        self.assertEqual("receipt_01", aggregate.receipt["receipt_id"])
        self.assertEqual("projection_01", aggregate.projection["projection_id"])

    def test_activation_schema_contract_is_closed_and_hash_bound(self) -> None:
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

    def test_each_event_type_has_one_exact_subject_format(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        for event_type, expected_format in EVENT_SUBJECT_FORMATS.items():
            with self.subTest(event_type=event_type):
                event = _event(event_type, 0, None, activation, grant, receipt)
                self.assertEqual(
                    expected_format, validate_agent_harness_document(event)["subject"]["format"]
                )
                wrong = copy.deepcopy(event)
                wrong["subject"]["format"] = "world-forge.agent_worker_activation"
                if wrong["subject"]["format"] == expected_format:
                    wrong["subject"]["format"] = "world-forge.agent_capability_grant"
                with self.assertRaisesRegex(AgentHarnessContractError, "subject format"):
                    validate_agent_harness_document(_seal(wrong))

    def test_complete_event_chain_is_one_log_execution_and_exact_hash_chain(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        events = _event_chain(
            [
                "worker.activated",
                "grant.issued",
                "execution.started",
                "execution.cancel_requested",
                "execution.receipt_recorded",
            ],
            activation,
            grant,
            receipt,
        )
        aggregate = validate_agent_harness_documents(activation, grant, events, receipt)
        self.assertEqual(list(range(5)), [event["sequence"] for event in aggregate.events])
        self.assertEqual({"log_01"}, {event["log_id"] for event in aggregate.events})
        self.assertEqual({"execution_01"}, {event["execution_id"] for event in aggregate.events})
        self.assertEqual(5, len({event["event_id"] for event in aggregate.events}))
        self.assertEqual(
            [None, *[event["content_hash"] for event in aggregate.events[:-1]]],
            [event["previous_event_hash"] for event in aggregate.events],
        )

    def test_event_chain_mutations_fail_closed(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        events = _event_chain(["worker.activated", "grant.issued"], activation, grant)
        mutations: list[tuple[str, list[dict[str, object]]]] = []
        for name, mutate in (
            ("different_log", lambda values: values[1].__setitem__("log_id", "log_02")),
            (
                "different_execution",
                lambda values: values[1].__setitem__("execution_id", "execution_02"),
            ),
            ("duplicate_event_id", lambda values: values[1].__setitem__("event_id", "event_00")),
            ("gap", lambda values: values[1].__setitem__("sequence", 2)),
            (
                "wrong_previous_hash",
                lambda values: values[1].__setitem__("previous_event_hash", "f" * 64),
            ),
        ):
            values = copy.deepcopy(events)
            mutate(values)
            values[1] = _seal(values[1])
            mutations.append((name, values))
        first_not_zero = [_event("worker.activated", 1, "f" * 64, activation, grant)]
        mutations.append(("first_not_zero", first_not_zero))
        for name, values in mutations:
            with self.subTest(mutation=name):
                with self.assertRaisesRegex(AgentHarnessContractError, "event log|event chain"):
                    validate_agent_harness_documents(activation, grant, values)

    def test_exact_resolved_event_subject_lineage_rejects_id_and_hash_mutations(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        resolved_types = [
            "worker.activated",
            "execution.started",
            "execution.cancel_requested",
            "grant.issued",
            "execution.receipt_recorded",
        ]
        mutation_count = 0
        for event_type in resolved_types:
            for field, value in (("id", "wrong_subject"), ("content_hash", "f" * 64)):
                mutation_count += 1
                with self.subTest(event_type=event_type, field=field):
                    event = _event(event_type, 0, None, activation, grant, receipt)
                    event["subject"][field] = value
                    event = _seal(event)
                    with self.assertRaisesRegex(
                        AgentHarnessContractError, "subject lineage|receipt event subject"
                    ):
                        validate_agent_harness_documents(activation, grant, [event], receipt)
        self.assertEqual(10, mutation_count)

    def test_memory_projection_subject_is_reserved_format_only(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        event = _event("memory.projected", 0, None, activation, grant)
        validated = validate_agent_harness_document(event)
        self.assertEqual(AGENT_MEMORY_PROJECTION_FORMAT, validated["subject"]["format"])
        self.assertEqual("projection_01", validated["subject"]["id"])

    def test_receipt_recorded_requires_supplied_exact_receipt(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        event = _event("execution.receipt_recorded", 0, None, activation, grant, receipt)
        with self.assertRaisesRegex(AgentHarnessContractError, "requires a supplied receipt"):
            validate_agent_harness_documents(activation, grant, [event])
        wrong_receipt = copy.deepcopy(receipt)
        wrong_receipt["receipt_id"] = "receipt_02"
        wrong_receipt = _seal(wrong_receipt)
        with self.assertRaisesRegex(AgentHarnessContractError, "receipt event subject"):
            validate_agent_harness_documents(activation, grant, [event], wrong_receipt)

    def test_receipt_lineage_is_exact_and_invoked_tools_are_effectively_granted(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        validate_agent_harness_documents(activation, grant, receipt=receipt)
        lineage_mutations = (
            ("execution_id", "execution_02"),
            ("activation.id", "activation_02"),
            ("activation.content_hash", "f" * 64),
            ("grant.id", "grant_02"),
            ("grant.content_hash", "f" * 64),
            ("runtime_binding.id", "other_runtime"),
            ("runtime_binding.revision", 2),
            ("runtime_binding.content_hash", "f" * 64),
            ("prompt_identities.0.id", "prompt_02"),
            ("prompt_identities.0.content_hash", "f" * 64),
        )
        for path, value in lineage_mutations:
            with self.subTest(path=path):
                mutated = copy.deepcopy(receipt)
                cursor: object = mutated
                parts = path.split(".")
                for part in parts[:-1]:
                    cursor = cursor[int(part)] if part.isdigit() else cursor[part]
                cursor[parts[-1]] = value
                with self.assertRaisesRegex(AgentHarnessContractError, "receipt lineage"):
                    validate_agent_harness_documents(activation, grant, receipt=_seal(mutated))
        ungranted = copy.deepcopy(receipt)
        ungranted["tool_invocations"][0]["tool_id"] = "memory.lookup"
        with self.assertRaisesRegex(AgentHarnessContractError, "ungranted tool"):
            validate_agent_harness_documents(activation, grant, receipt=_seal(ungranted))

    def test_receipt_accepts_128_contiguous_unique_invocations_and_rejects_bounds(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        maximum = _receipt(activation, grant, invocations=128)
        validated = validate_agent_harness_documents(activation, grant, receipt=maximum)
        self.assertEqual(
            list(range(128)), [item["sequence"] for item in validated.receipt["tool_invocations"]]
        )
        too_many = _receipt(activation, grant, invocations=129)
        with self.assertRaisesRegex(AgentHarnessContractError, "bounded"):
            validate_agent_harness_document(too_many)
        gap = copy.deepcopy(maximum)
        gap["tool_invocations"][64]["sequence"] = 65
        with self.assertRaisesRegex(AgentHarnessContractError, "contiguous"):
            validate_agent_harness_document(_seal(gap))
        duplicate = copy.deepcopy(maximum)
        duplicate["tool_invocations"][1]["invocation_id"] = duplicate["tool_invocations"][0][
            "invocation_id"
        ]
        with self.assertRaisesRegex(AgentHarnessContractError, "invocation IDs"):
            validate_agent_harness_document(_seal(duplicate))

    def test_receipt_outcome_failure_code_rules_fail_closed(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        mutations = (
            ("receipt_success_with_failure", lambda value: value["failure_codes"].append("failed")),
            ("receipt_failure_without_code", lambda value: value.__setitem__("outcome", "failed")),
            (
                "invocation_success_with_failure",
                lambda value: value["tool_invocations"][0]["failure_codes"].append("failed"),
            ),
            (
                "invocation_failure_without_code",
                lambda value: value["tool_invocations"][0].__setitem__("outcome", "failed"),
            ),
            ("duplicate_receipt_codes", lambda value: value["failure_codes"].extend(["a1", "a1"])),
            (
                "unsorted_invocation_codes",
                lambda value: value["tool_invocations"][0]["failure_codes"].extend(["z1", "a1"]),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                value = copy.deepcopy(receipt)
                mutate(value)
                with self.assertRaises(AgentHarnessContractError):
                    validate_agent_harness_document(_seal(value))

    def test_receipt_refs_are_sorted_unique_and_closed(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        mutations = (
            ("unsorted", lambda refs: refs.reverse()),
            ("duplicate_id", lambda refs: refs.append(copy.deepcopy(refs[0]))),
            ("nested_raw", lambda refs: refs[0].__setitem__("raw_output", "forbidden")),
        )
        for target in ("prompt_identities", "result_artifacts"):
            for name, mutate in mutations:
                with self.subTest(target=target, mutation=name):
                    value = copy.deepcopy(receipt)
                    if target == "prompt_identities" and name == "unsorted":
                        value[target].append({"id": "prompt_02", "content_hash": "9" * 64})
                    mutate(value[target])
                    with self.assertRaises(AgentHarnessContractError):
                        validate_agent_harness_document(_seal(value))
        nested_invocation = copy.deepcopy(receipt)
        nested_invocation["tool_invocations"][0]["raw_response"] = "forbidden"
        with self.assertRaisesRegex(AgentHarnessContractError, "unknown fields"):
            validate_agent_harness_document(_seal(nested_invocation))

    def test_receipt_usage_joint_cost_and_cache_rules_include_zero_cost(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        self.assertEqual(0, validate_agent_harness_document(receipt)["usage"]["cost_minor_units"])
        null_cost = copy.deepcopy(receipt)
        null_cost["usage"]["cost_minor_units"] = None
        null_cost["usage"]["currency"] = None
        validate_agent_harness_document(_seal(null_cost))
        mutations = (
            ("cached_gt_input", "cached_input_tokens", 4, None),
            ("cost_without_currency", "cost_minor_units", 1, ("currency", None)),
            ("currency_without_cost", "currency", "USD", ("cost_minor_units", None)),
            ("bad_currency", "currency", "usd", None),
            ("wrong_replay", "replay_support", "claimed", None),
        )
        for name, field, value, companion in mutations:
            with self.subTest(mutation=name):
                mutated = copy.deepcopy(receipt)
                target = mutated["usage"] if field in mutated["usage"] else mutated
                target[field] = value
                if companion is not None:
                    mutated["usage"][companion[0]] = companion[1]
                with self.assertRaises(AgentHarnessContractError):
                    validate_agent_harness_document(_seal(mutated))

    def test_receipt_numeric_forms_match_javascript_safe_integer_semantics(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        for literal in ("3.0", "3e0"):
            with self.subTest(accepted_literal=literal):
                parsed = json.loads(
                    json.dumps(receipt, separators=(",", ":")).replace(
                        '"input_tokens":3', f'"input_tokens":{literal}'
                    )
                )
                self.assertEqual(
                    3, validate_agent_harness_document(parsed)["usage"]["input_tokens"]
                )
        for value in (True, 1.5, 9_007_199_254_740_992.0):
            with self.subTest(rejected_value=value):
                mutated = copy.deepcopy(receipt)
                mutated["usage"]["input_tokens"] = value
                with self.assertRaisesRegex(AgentHarnessContractError, "integer|number"):
                    validate_agent_harness_document(_seal(mutated))

    def test_receipt_canonical_hash_size_and_forbidden_raw_surfaces_fail_closed(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        self.assertEqual(receipt["content_hash"], canonical_agent_harness_hash(receipt))
        tampered = copy.deepcopy(receipt)
        tampered["content_hash"] = "0" * 64
        with self.assertRaisesRegex(AgentHarnessContractError, "content hash"):
            validate_agent_harness_document(tampered)
        oversized = copy.deepcopy(receipt)
        oversized["raw"] = "x" * (1024 * 1024)
        with self.assertRaisesRegex(AgentHarnessContractError, "byte limit"):
            validate_agent_harness_document(_seal(oversized))
        for location in ("usage", "runtime_binding", "activation", "grant"):
            with self.subTest(location=location):
                forbidden = copy.deepcopy(receipt)
                forbidden[location]["transcript"] = "forbidden"
                with self.assertRaisesRegex(AgentHarnessContractError, "unknown fields"):
                    validate_agent_harness_document(_seal(forbidden))

    def test_projection_document_and_incremental_aggregate_are_valid(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        events = _event_chain(["worker.activated", "grant.issued"], activation, grant)
        projection = _projection(activation, receipt, events)
        validated = validate_agent_harness_document(
            projection, expected_format=AGENT_MEMORY_PROJECTION_FORMAT
        )
        self.assertEqual("projection_01", validated["projection_id"])
        aggregate = validate_agent_harness_documents(activation, grant, events, receipt, projection)
        self.assertEqual("projection_01", aggregate.projection["projection_id"])

    def test_projection_receipt_execution_and_review_lineage_fail_closed(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        events = _event_chain(["worker.activated", "grant.issued"], activation, grant)
        projection = _projection(activation, receipt, events)
        with self.assertRaisesRegex(AgentHarnessContractError, "requires a supplied receipt"):
            validate_agent_harness_documents(activation, grant, events, projection=projection)
        mutations = (
            ("execution", lambda value: value.__setitem__("execution_id", "execution_02")),
            ("receipt_id", lambda value: value["receipt"].__setitem__("id", "receipt_02")),
            (
                "receipt_hash",
                lambda value: (
                    value["receipt"].__setitem__("content_hash", "f" * 64),
                    value["review"].__setitem__("receipt_content_hash", "f" * 64),
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                value = copy.deepcopy(projection)
                mutate(value)
                with self.assertRaisesRegex(AgentHarnessContractError, "projection lineage"):
                    validate_agent_harness_documents(
                        activation, grant, events, receipt, _seal(value)
                    )
        review_mismatch = copy.deepcopy(projection)
        review_mismatch["review"]["receipt_content_hash"] = "f" * 64
        with self.assertRaisesRegex(AgentHarnessContractError, "review receipt_content_hash"):
            validate_agent_harness_document(_seal(review_mismatch))
        rejected = copy.deepcopy(projection)
        rejected["review"]["decision"] = "rejected"
        with self.assertRaisesRegex(AgentHarnessContractError, "approved"):
            validate_agent_harness_document(_seal(rejected))
        for field, value in (
            ("format", AGENT_EVENT_FORMAT),
            ("format_version", 2),
        ):
            with self.subTest(receipt_ref_field=field):
                wrong_ref = copy.deepcopy(projection)
                wrong_ref["receipt"][field] = value
                with self.assertRaisesRegex(AgentHarnessContractError, "receipt"):
                    validate_agent_harness_document(_seal(wrong_ref))

    def test_projection_source_event_refs_resolve_exactly_and_are_bounded(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        events = _event_chain(["worker.activated", "grant.issued"], activation, grant)
        projection = _projection(activation, receipt, events)
        document_mutations = (
            ("empty", lambda value: value.__setitem__("source_events", [])),
            (
                "duplicate",
                lambda value: value["source_events"].append(
                    copy.deepcopy(value["source_events"][0])
                ),
            ),
            ("unsorted", lambda value: value["source_events"].reverse()),
            (
                "wrong_format",
                lambda value: value["source_events"][0].__setitem__(
                    "format", AGENT_EXECUTION_RECEIPT_FORMAT
                ),
            ),
            (
                "wrong_version",
                lambda value: value["source_events"][0].__setitem__("format_version", 2),
            ),
        )
        for name, mutate in document_mutations:
            with self.subTest(document_mutation=name):
                value = copy.deepcopy(projection)
                mutate(value)
                with self.assertRaises(AgentHarnessContractError):
                    validate_agent_harness_document(_seal(value))
        oversized = copy.deepcopy(projection)
        oversized["source_events"] = [
            {
                "format": AGENT_EVENT_FORMAT,
                "format_version": 1,
                "id": f"event_{index:03d}",
                "content_hash": f"{(index % 9) + 1}" * 64,
            }
            for index in range(65)
        ]
        oversized["entries"][0]["source_event_ids"] = ["event_000"]
        with self.assertRaisesRegex(AgentHarnessContractError, "bounded"):
            validate_agent_harness_document(_seal(oversized))
        aggregate_mutations = (
            ("unresolved", "id", "event_00x"),
            ("wrong_hash", "content_hash", "f" * 64),
        )
        for name, field, value in aggregate_mutations:
            with self.subTest(aggregate_mutation=name):
                changed = copy.deepcopy(projection)
                changed["source_events"][0][field] = value
                if field == "id":
                    changed["entries"][0]["source_event_ids"][0] = value
                with self.assertRaisesRegex(AgentHarnessContractError, "source event"):
                    validate_agent_harness_documents(
                        activation, grant, events, receipt, _seal(changed)
                    )

    def test_projection_entries_and_source_ids_are_sorted_unique_bounded_subsets(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        events = _event_chain(["worker.activated", "grant.issued"], activation, grant)
        projection = _projection(activation, receipt, events, entries=2)
        entry_mutations = (
            ("empty_entries", lambda value: value.__setitem__("entries", [])),
            ("unsorted_entries", lambda value: value["entries"].reverse()),
            (
                "duplicate_entry",
                lambda value: value["entries"].append(copy.deepcopy(value["entries"][0])),
            ),
            (
                "empty_source_ids",
                lambda value: value["entries"][0].__setitem__("source_event_ids", []),
            ),
            (
                "unsorted_source_ids",
                lambda value: value["entries"][0]["source_event_ids"].reverse(),
            ),
            (
                "duplicate_source_ids",
                lambda value: value["entries"][0]["source_event_ids"].append("event_00"),
            ),
            (
                "unsupported_kind",
                lambda value: value["entries"][0].__setitem__("kind", "claim"),
            ),
        )
        for name, mutate in entry_mutations:
            with self.subTest(mutation=name):
                value = copy.deepcopy(projection)
                mutate(value)
                with self.assertRaises(AgentHarnessContractError):
                    validate_agent_harness_document(_seal(value))
        oversized_entries = _projection(activation, receipt, events, entries=65)
        with self.assertRaisesRegex(AgentHarnessContractError, "bounded"):
            validate_agent_harness_document(oversized_entries)
        oversized_ids = copy.deepcopy(projection)
        oversized_ids["entries"][0]["source_event_ids"] = [
            f"event_{index:03d}" for index in range(65)
        ]
        with self.assertRaisesRegex(AgentHarnessContractError, "bounded"):
            validate_agent_harness_document(_seal(oversized_ids))
        outside_subset = copy.deepcopy(projection)
        outside_subset["entries"][0]["source_event_ids"] = ["event_99"]
        with self.assertRaisesRegex(AgentHarnessContractError, "subset"):
            validate_agent_harness_documents(
                activation, grant, events, receipt, _seal(outside_subset)
            )

    def test_projection_forbidden_surfaces_hash_and_byte_limit_fail_closed(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        events = _event_chain(["worker.activated", "grant.issued"], activation, grant)
        projection = _projection(activation, receipt, events)
        forbidden_fields = (
            "memory_text",
            "prompt",
            "transcript",
            "rationale",
            "path",
            "url",
            "endpoint",
            "command",
            "env",
            "stderr",
            "secret",
            "credentials",
            "token",
            "provider_payload",
            "executable",
            "executable_content",
        )
        for field in forbidden_fields:
            with self.subTest(forbidden_field=field):
                value = copy.deepcopy(projection)
                value["entries"][0][field] = "forbidden"
                with self.assertRaisesRegex(AgentHarnessContractError, "forbidden fields"):
                    validate_agent_harness_document(_seal(value))
        nested_locations = ("receipt", "source_events", "review")
        for location in nested_locations:
            with self.subTest(nested_location=location):
                value = copy.deepcopy(projection)
                target = (
                    value[location][0] if isinstance(value[location], list) else value[location]
                )
                target["raw"] = "forbidden"
                with self.assertRaisesRegex(AgentHarnessContractError, "unknown fields"):
                    validate_agent_harness_document(_seal(value))
        tampered = copy.deepcopy(projection)
        tampered["content_hash"] = "0" * 64
        with self.assertRaisesRegex(AgentHarnessContractError, "content hash"):
            validate_agent_harness_document(tampered)
        oversized = copy.deepcopy(projection)
        oversized["raw"] = "x" * (1024 * 1024)
        with self.assertRaisesRegex(AgentHarnessContractError, "byte limit"):
            validate_agent_harness_document(_seal(oversized))

    def test_projection_policy_version_uses_javascript_safe_integer_semantics(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        events = _event_chain(["worker.activated", "grant.issued"], activation, grant)
        projection = _projection(activation, receipt, events)
        for literal in ("1.0", "1e0"):
            with self.subTest(accepted_literal=literal):
                parsed = json.loads(
                    json.dumps(projection, separators=(",", ":")).replace(
                        '"policy_version":1', f'"policy_version":{literal}'
                    )
                )
                self.assertEqual(
                    1,
                    validate_agent_harness_document(parsed)["review"]["policy_version"],
                )
        for value in (True, 1.5, 9_007_199_254_740_992.0):
            with self.subTest(rejected_value=value):
                changed = copy.deepcopy(projection)
                changed["review"]["policy_version"] = value
                with self.assertRaisesRegex(AgentHarnessContractError, "integer|number"):
                    validate_agent_harness_document(_seal(changed))

    def test_memory_event_requires_exact_supplied_projection(self) -> None:
        activation = _activation()
        grant = _grant(activation)
        receipt = _receipt(activation, grant)
        source_events = _event_chain(["worker.activated", "grant.issued"], activation, grant)
        projection = _projection(activation, receipt, source_events)
        events = _event_chain(
            ["worker.activated", "grant.issued", "memory.projected"],
            activation,
            grant,
            receipt,
            projection,
        )
        with self.assertRaisesRegex(AgentHarnessContractError, "requires a supplied projection"):
            validate_agent_harness_documents(activation, grant, events, receipt)
        for field, value in (("id", "projection_02"), ("content_hash", "f" * 64)):
            with self.subTest(field=field):
                changed_events = copy.deepcopy(events)
                changed_events[2]["subject"][field] = value
                changed_events[2] = _seal(changed_events[2])
                with self.assertRaisesRegex(AgentHarnessContractError, "projection event subject"):
                    validate_agent_harness_documents(
                        activation, grant, changed_events, receipt, projection
                    )

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

    def test_non_integral_and_unsafe_float_numbers_fail_closed(self) -> None:
        for value in (1.5, float("nan"), float("inf"), 9_007_199_254_740_992.0):
            with self.subTest(value=value):
                activation = _activation()
                activation["format_version"] = value
                with self.assertRaisesRegex(AgentHarnessContractError, "number"):
                    validate_agent_harness_document(activation)

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
        too_many_tools = copy.deepcopy(activation)
        tools = [f"tool.capability_{index:02d}" for index in range(65)]
        too_many_tools["requested_tool_ids"] = tools
        too_many_tools["work_order"]["tool_ids"] = tools
        with self.assertRaisesRegex(AgentHarnessContractError, "bounded string array"):
            validate_agent_harness_document(_seal(too_many_tools))

    def test_safe_integer_and_pair_bindings_fail_closed(self) -> None:
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

    def test_schema_catalog_and_generated_types_cover_all_five_contracts_exactly(self) -> None:
        catalog = load_contract_catalog(ROOT)
        entries = {entry["id"]: entry for entry in catalog["contracts"]}
        expected = {
            "agent-worker-activation": (
                AGENT_WORKER_ACTIVATION_FORMAT,
                "ImmutableAgentWorkerActivationV1",
            ),
            "agent-capability-grant": (
                AGENT_CAPABILITY_GRANT_FORMAT,
                "ImmutableAgentCapabilityGrantV1",
            ),
            "agent-event": (AGENT_EVENT_FORMAT, "ImmutableAgentEventV1"),
            "agent-execution-receipt": (
                AGENT_EXECUTION_RECEIPT_FORMAT,
                "ImmutableAgentExecutionReceiptV1",
            ),
            "agent-memory-projection": (
                AGENT_MEMORY_PROJECTION_FORMAT,
                "ImmutableAgentMemoryProjectionV1",
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
                self.assertTrue(schema["x-world-forge-agent-harness-coherent"])
        self.assertEqual(
            [
                "examples/multigenre-contracts/agent-harness-minimal/event-00.json",
                "examples/multigenre-contracts/agent-harness-minimal/event-01.json",
                "examples/multigenre-contracts/agent-harness-minimal/event-02.json",
            ],
            entries["agent-event"]["fixtures"],
        )
        event_schema = json.loads((ROOT / "schemas/agent-event.schema.json").read_text())
        branches = event_schema["oneOf"]
        mapping = {
            branch["properties"]["event_type"]["const"]: branch["properties"]["subject"]["$ref"]
            for branch in branches
        }
        self.assertEqual(
            {
                event_type: f"#/$defs/subject_{event_type.replace('.', '_')}"
                for event_type in EVENT_SUBJECT_FORMATS
            },
            mapping,
        )
        event_type_start = generated.index("export type ImmutableAgentEventV1 =")
        event_type_end = generated.index("export type ReasonCodes", event_type_start)
        event_declaration = generated[event_type_start:event_type_end]
        subject_types = {
            "worker.activated": "SubjectWorkerActivated",
            "grant.issued": "SubjectGrantIssued",
            "execution.started": "SubjectExecutionStarted",
            "execution.cancel_requested": "SubjectExecutionCancelRequested",
            "execution.receipt_recorded": "SubjectExecutionReceiptRecorded",
            "memory.projected": "SubjectMemoryProjected",
        }
        for event_type, subject_format in EVENT_SUBJECT_FORMATS.items():
            with self.subTest(generated_event_type=event_type):
                self.assertIn(f'event_type: "{event_type}";', event_declaration)
                self.assertIn(f"subject: {subject_types[event_type]};", event_declaration)
                subject_start = generated.index(f"export interface {subject_types[event_type]} {{")
                subject_end = generated.index("}\n", subject_start)
                self.assertIn(
                    f'format: "{subject_format}";',
                    generated[subject_start:subject_end],
                )
        self.assertNotIn("format: string;", event_declaration)
        projection_schema = json.loads(
            (ROOT / "schemas/agent-memory-projection.schema.json").read_text()
        )
        self.assertFalse(projection_schema["additionalProperties"])
        for definition in ("entry", "event_ref", "receipt_ref", "review"):
            with self.subTest(closed_projection_definition=definition):
                self.assertFalse(projection_schema["$defs"][definition]["additionalProperties"])
        projection_start = generated.index("export interface ImmutableAgentMemoryProjectionV1")
        projection_end = generated.index(
            "type GenericAssetRuntimeForbiddenFieldName", projection_start
        )
        projection_declarations = generated[projection_start:projection_end]
        for exact_fragment in (
            'format: "world-forge.agent_memory_projection";',
            "format_version: 1;",
            "entries: [Entry, ...Entry[]];",
            "receipt: ReceiptRef;",
            "review: Review2;",
            "source_events: [EventRef, ...EventRef[]];",
            "export interface Entry {",
            'kind: "decision" | "constraint" | "discovery" | "preference";',
            "source_event_ids: [string, ...string[]];",
            "export interface ReceiptRef {",
            'format: "world-forge.agent_execution_receipt";',
            "export interface Review2 {",
            'decision: "approved";',
            "export interface EventRef {",
            'format: "world-forge.agent_event";',
        ):
            with self.subTest(generated_projection_fragment=exact_fragment):
                self.assertIn(exact_fragment, projection_declarations)
        self.assertNotIn("[k: string]", projection_declarations)


if __name__ == "__main__":
    unittest.main()
