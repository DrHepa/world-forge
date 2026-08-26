from __future__ import annotations

import copy
import hashlib
import json
import traceback
import unittest
from collections.abc import Iterator, Mapping
from dataclasses import replace
from pathlib import Path

import worldforge.agent_harness as agent_harness
from tests.agent_harness_fakes import (
    FakeArtifactPort,
    FakeCancellation,
    FakeClock,
    FakeJournal,
    FakeMemoryPort,
    FakeProvider,
    FakeTool,
)
from worldforge.agent_harness import (
    AgentExecutionKernel,
    CapabilityBroker,
    ExecutionLimits,
    ExecutionRequest,
    KernelError,
)
from worldforge.agent_harness.approvals import (
    ApprovalError,
    ExecutionApprovalDecision,
    InMemoryHumanApprovalAuthority,
)
from worldforge.agent_harness.capability_broker import BrokerError
from worldforge.agent_harness.ports import (
    ArtifactProposal,
    MemoryProposal,
    ProviderTurnResult,
    ProviderUsage,
    ToolCall,
    ToolResult,
)
from worldforge.agent_harness.worker_registry import fixed_runtime_identity
from worldforge.agent_harness_contracts import (
    MAX_SAFE_INTEGER,
    canonical_agent_harness_hash,
    validate_agent_harness_documents,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples/multigenre-contracts/agent-harness-minimal"
BASELINE = {
    path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in FIXTURES.glob("*.json")
}


def _documents(*, capabilities: list[str] | None = None, tools: list[str] | None = None):
    activation = json.loads((FIXTURES / "worker-activation.json").read_text())
    grant = json.loads((FIXTURES / "capability-grant.json").read_text())
    activation["runtime"] = fixed_runtime_identity()
    grant["runtime"] = fixed_runtime_identity()
    if capabilities is not None or tools is not None:
        capabilities = (
            capabilities if capabilities is not None else activation["work_order"]["capability_ids"]
        )
        tools = tools if tools is not None else activation["work_order"]["tool_ids"]
        capabilities = sorted(capabilities)
        tools = sorted(tools)
        activation["work_order"]["capability_ids"] = capabilities
        activation["work_order"]["tool_ids"] = tools
        activation["requested_capability_ids"] = capabilities
        activation["requested_tool_ids"] = tools
        grant["work_order"] = copy.deepcopy(activation["work_order"])
        grant["policy"] = {"capability_ids": capabilities, "tool_ids": tools}
        grant["role_capability_ids"] = capabilities
        grant["role_tool_ids"] = tools
        grant["effective_capability_ids"] = capabilities
        grant["effective_tool_ids"] = tools
    activation["content_hash"] = canonical_agent_harness_hash(activation)
    grant["activation"] = {
        "id": activation["activation_id"],
        "content_hash": activation["content_hash"],
    }
    grant["content_hash"] = canonical_agent_harness_hash(grant)
    return activation, grant


def _documents_with_requested_but_ineffective_source_read():
    activation, grant = _documents()
    grant["role_tool_ids"] = ["world.validate"]
    grant["effective_tool_ids"] = ["world.validate"]
    grant["content_hash"] = canonical_agent_harness_hash(grant)
    validate_agent_harness_documents(activation, grant)
    return activation, grant


def _usage(**changes: object) -> ProviderUsage:
    values = dict(
        input_tokens=3, output_tokens=2, cached_input_tokens=1, cost_minor_units=0, currency="USD"
    )
    values.update(changes)
    return ProviderUsage(**values)


def _request(activation, grant, **limit_changes: object) -> ExecutionRequest:
    limits = dict(
        max_turns=4,
        max_tool_calls=4,
        max_total_tokens=100,
        max_cost_minor_units=10,
        currency="USD",
        max_duration_ms=100,
        deadline_ms=2_000,
    )
    limits.update(limit_changes)
    return ExecutionRequest(
        activation=activation,
        grant=grant,
        log_id="log_kernel_01",
        receipt_id="receipt_kernel_01",
        event_id_prefix="kernel_event",
        invocation_id_prefix="kernel_invocation",
        limits=ExecutionLimits(**limits),
        private_input={"secret": "PRIVATE_INPUT"},
    )


def _kernel(
    provider,
    *,
    tools=(),
    artifact_port=None,
    memory_port=None,
    clock=None,
    cancellation=None,
    journal=None,
):
    clock = clock or FakeClock()
    cancellation = cancellation or FakeCancellation()
    journal = journal or FakeJournal()
    authority = InMemoryHumanApprovalAuthority()

    class LegacyTestBroker(CapabilityBroker):
        def preflight(self, execution_id, **kwargs):
            kwargs["exposed_tools"] = None
            return super().preflight(execution_id, **kwargs)

    class AutoApprovingTestKernel(AgentExecutionKernel):
        def execute(self, request):
            prepared = replace(request, approval_id="approval_legacy_test_01")
            try:
                review = self.prepare_approval_review(prepared)
            except KernelError as exc:
                if exc.reason_code not in {
                    "approval_required",
                    "private_field_invalid",
                    "provider_runtime_binding_invalid",
                }:
                    raise
            else:
                decision = ExecutionApprovalDecision.create(
                    review=review,
                    reviewer_id="reviewer_legacy_test",
                    outcome="approved",
                    approved_tool_ids=tuple(
                        tool_id for tool_id, _descriptor_hash in review.tool_candidates
                    ),
                    expires_at_ms=MAX_SAFE_INTEGER,
                )
                try:
                    authority.decide(
                        decision,
                        expected_generation=0,
                        expected_review_hash=review.content_hash,
                    )
                except ApprovalError as exc:
                    if exc.reason_code != "approval_stale":
                        raise
            return super().execute(prepared)

    broker = LegacyTestBroker(
        tools=tools,
        artifact_port=artifact_port,
        memory_port=memory_port,
    )
    return AutoApprovingTestKernel(
        provider=provider,
        broker=broker,
        journal=journal,
        clock=clock,
        cancellation=cancellation,
        approval_authority=authority,
    ), journal


class AgentExecutionKernelTests(unittest.TestCase):
    def test_internal_package_export_surface_is_deliberately_small(self) -> None:
        self.assertEqual(
            {
                "AgentExecutionKernel",
                "AgentExecutionCoordinator",
                "AgentEventLog",
                "CapabilityBroker",
                "ExecutionLimits",
                "ExecutionRequest",
                "InMemoryMemoryApprovalAuthority",
                "InMemoryMemoryProposalSource",
                "KernelError",
                "MemoryProjectionCoordinator",
                "OneShotProviderSupervisor",
            },
            set(agent_harness.__all__),
        )

    def test_success_builds_exact_chain_and_canonical_receipt(self) -> None:
        activation, grant = _documents()
        provider = FakeProvider(
            [ProviderTurnResult(private_output="PRIVATE_RESULT", usage=_usage(), completed=True)]
        )
        kernel, journal = _kernel(provider)
        result = kernel.execute(_request(activation, grant))
        self.assertEqual("succeeded", result.outcome)
        self.assertEqual(
            ["worker.activated", "grant.issued", "execution.started", "execution.receipt_recorded"],
            [event["event_type"] for event in result.events],
        )
        self.assertEqual(
            [None, *[event["content_hash"] for event in result.events[:-1]]],
            [event["previous_event_hash"] for event in result.events],
        )
        aggregate = validate_agent_harness_documents(
            activation, grant, result.events, result.receipt
        )
        self.assertEqual("receipt_kernel_01", aggregate.receipt["receipt_id"])
        self.assertEqual(journal.receipt, result.receipt)
        self.assertEqual("PRIVATE_RESULT", result.private_output)
        self.assertEqual(fixed_runtime_identity(), result.receipt["runtime_binding"])

    def test_provider_runtime_binding_is_exact_before_any_execution_authority(self) -> None:
        activation, grant = _documents()

        class HostileBinding(dict):
            def __init__(self) -> None:
                super().__init__(fixed_runtime_identity())
                self.touched: list[str] = []

            def __iter__(self):
                self.touched.append("iter")
                raise AssertionError("hostile runtime binding iterated")

            def __getitem__(self, key):
                self.touched.append("getitem")
                raise AssertionError("hostile runtime binding indexed")

            def keys(self):
                self.touched.append("keys")
                raise AssertionError("hostile runtime binding keys read")

        class HostileString(str):
            def __eq__(self, _other: object) -> bool:
                raise AssertionError("hostile runtime string compared")

        class HostileInt(int):
            def __le__(self, _other: object) -> bool:
                raise AssertionError("hostile runtime revision compared")

        hostile = HostileBinding()
        cases: tuple[tuple[str, object], ...] = (
            ("mapping_subclass", hostile),
            ("missing_field", {"id": "runtime", "revision": 1}),
            (
                "extra_field",
                {**fixed_runtime_identity(), "provider": "PRIVATE_PROVIDER"},
            ),
            (
                "bool_revision",
                {**fixed_runtime_identity(), "revision": True},
            ),
            (
                "invalid_id",
                {**fixed_runtime_identity(), "id": "Invalid-Runtime"},
            ),
            (
                "invalid_hash",
                {**fixed_runtime_identity(), "content_hash": "f" * 63},
            ),
            (
                "id_subclass",
                {**fixed_runtime_identity(), "id": HostileString("portable_runtime")},
            ),
            (
                "revision_subclass",
                {**fixed_runtime_identity(), "revision": HostileInt(1)},
            ),
            (
                "hash_subclass",
                {**fixed_runtime_identity(), "content_hash": HostileString("f" * 64)},
            ),
        )
        for label, binding in cases:
            with self.subTest(binding=label):
                journal = FakeJournal()
                provider = FakeProvider([], runtime_binding=binding)
                with self.assertRaises(KernelError) as raised:
                    AgentExecutionKernel(
                        provider=provider,
                        broker=CapabilityBroker(),
                        journal=journal,
                        clock=FakeClock(),
                        cancellation=FakeCancellation(),
                    )
                self.assertEqual("provider_runtime_binding_invalid", raised.exception.reason_code)
                self.assertEqual([], journal.operations)
                self.assertEqual([], provider.requests)
                self.assertEqual(1, provider.runtime_binding_reads)
        self.assertEqual([], hostile.touched)

        class RaisingProvider(FakeProvider):
            @property
            def runtime_binding(self) -> object:
                raise RuntimeError("PRIVATE_RUNTIME_BINDING_FAILURE")

        with self.assertRaises(KernelError) as raised:
            AgentExecutionKernel(
                provider=RaisingProvider([]),
                broker=CapabilityBroker(),
                journal=FakeJournal(),
                clock=FakeClock(),
                cancellation=FakeCancellation(),
            )
        self.assertEqual("provider_runtime_binding_invalid", raised.exception.reason_code)
        self.assertNotIn("PRIVATE", str(raised.exception))

    def test_provider_runtime_mismatch_is_durable_provider_failure_without_authority(
        self,
    ) -> None:
        activation, grant = _documents(
            capabilities=["artifact.propose", "tool.invoke"], tools=["source.read"]
        )
        provider = FakeProvider(
            [
                ProviderTurnResult(
                    "MUST_NOT_RETURN",
                    _usage(),
                    tool_calls=(ToolCall("source.read", {"private": 1}),),
                    artifact_proposals=(ArtifactProposal("PRIVATE_PROPOSAL"),),
                    completed=True,
                )
            ],
            runtime_binding={
                "id": "different_runtime",
                "revision": 1,
                "content_hash": "f" * 64,
            },
        )

        class ObservingBroker(CapabilityBroker):
            def __init__(self) -> None:
                super().__init__(
                    tools=(FakeTool("source.read", "tool.invoke", ToolResult("unused")),),
                    artifact_port=FakeArtifactPort(
                        [{"id": "artifact_unused", "content_hash": "a" * 64}]
                    ),
                )
                self.activation_calls = 0

            def activate(self, execution_id):
                self.activation_calls += 1
                return super().activate(execution_id)

        broker = ObservingBroker()
        journal = FakeJournal()
        kernel = AgentExecutionKernel(
            provider=provider,
            broker=broker,
            journal=journal,
            clock=FakeClock(),
            cancellation=FakeCancellation(),
        )
        result = kernel.execute(_request(activation, grant))
        self.assertEqual("failed", result.outcome)
        self.assertEqual(["provider_failed"], result.receipt["failure_codes"])
        self.assertEqual(activation["runtime"], result.receipt["runtime_binding"])
        self.assertEqual(["begin", "finalize"], journal.operations)
        self.assertEqual(0, broker.activation_calls)
        self.assertEqual([], provider.requests)
        self.assertEqual(1, provider.runtime_binding_reads)

    def test_new_runtime_mismatch_preserves_cancel_and_deadline_precedence(self) -> None:
        activation, grant = _documents()
        binding = {
            "id": "different_runtime",
            "revision": 1,
            "content_hash": "f" * 64,
        }
        cases = (
            (
                "execution_cancelled",
                FakeClock(),
                FakeCancellation(cancel_on_check=2),
                {},
            ),
            (
                "execution_deadline_exceeded",
                FakeClock(now_ms=2_000),
                FakeCancellation(),
                {"deadline_ms": 2_000},
            ),
        )
        for code, clock, cancellation, limits in cases:
            with self.subTest(code=code):
                provider = FakeProvider([], runtime_binding=dict(binding))
                kernel, journal = _kernel(
                    provider,
                    clock=clock,
                    cancellation=cancellation,
                )
                result = kernel.execute(_request(activation, grant, **limits))
                self.assertEqual("cancelled", result.outcome)
                self.assertEqual([code], result.receipt["failure_codes"])
                self.assertEqual("begin", journal.operations[0])
                self.assertEqual([], provider.requests)

    def test_provider_runtime_binding_is_snapshotted_once_against_later_mutation(
        self,
    ) -> None:
        activation, grant = _documents()
        exposed = fixed_runtime_identity()
        provider = FakeProvider(
            [ProviderTurnResult("ran", _usage(), completed=True)],
            runtime_binding=exposed,
        )
        kernel, _ = _kernel(provider)
        exposed.clear()
        exposed.update(
            id="mutated_runtime",
            revision=2,
            content_hash="f" * 64,
        )
        with self.assertRaises(AttributeError):
            kernel.provider = FakeProvider(  # type: ignore[misc]
                [ProviderTurnResult("replacement", _usage(), completed=True)]
            )
        result = kernel.execute(_request(activation, grant))
        self.assertEqual("succeeded", result.outcome)
        self.assertEqual(fixed_runtime_identity(), result.receipt["runtime_binding"])
        self.assertEqual(1, provider.runtime_binding_reads)

    def test_provider_endpoint_is_frozen_with_its_validated_runtime_binding(self) -> None:
        activation, grant = _documents()
        endpoint: dict[str, object] = {}
        original_calls: list[object] = []
        replacement_calls: list[object] = []

        def original_turn(request, *, boundary):
            del boundary
            original_calls.append(request)
            return ProviderTurnResult("original", _usage(), completed=True)

        def replacement_turn(request, *, boundary):
            del boundary
            replacement_calls.append(request)
            return ProviderTurnResult("replacement", _usage(), completed=True)

        endpoint["turn"] = original_turn

        class MutableEndpointProvider:
            def __init__(self) -> None:
                self.binding_reads = 0
                self.turn_reads = 0

            @property
            def runtime_binding(self) -> object:
                self.binding_reads += 1
                return fixed_runtime_identity()

            @property
            def turn(self):
                self.turn_reads += 1
                return endpoint["turn"]

        provider = MutableEndpointProvider()
        kernel = AgentExecutionKernel(
            provider=provider,  # type: ignore[arg-type]
            broker=CapabilityBroker(),
            journal=FakeJournal(),
            clock=FakeClock(),
            cancellation=FakeCancellation(),
        )
        replacement = FakeProvider(
            [replacement_turn],
            runtime_binding={
                "id": "replacement_runtime",
                "revision": 1,
                "content_hash": "f" * 64,
            },
        )
        endpoint["turn"] = replacement_turn
        with self.assertRaises(AttributeError):
            kernel._provider = replacement  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            kernel.provider = replacement  # type: ignore[misc]

        result = kernel.execute(_request(activation, grant))

        self.assertEqual("succeeded", result.outcome)
        self.assertEqual("original", result.private_output)
        self.assertEqual(1, provider.binding_reads)
        self.assertEqual(1, provider.turn_reads)
        self.assertEqual(1, len(original_calls))
        self.assertEqual([], replacement_calls)
        self.assertEqual([], replacement.requests)
        self.assertEqual(0, replacement.runtime_binding_reads)

    def test_private_provider_authority_rejects_ordinary_replacement(self) -> None:
        kernel, _ = _kernel(
            FakeProvider([ProviderTurnResult("original", _usage(), completed=True)])
        )

        with self.assertRaises(AttributeError):
            kernel._provider_authority = object()  # type: ignore[attr-defined]
        with self.assertRaises(AttributeError):
            del kernel._provider_authority  # type: ignore[attr-defined]
        with self.assertRaises(AttributeError):
            kernel._provider_authority.turn = lambda *_args, **_kwargs: None  # type: ignore[attr-defined,misc]

    def test_journal_begin_is_first_and_binds_only_closed_request_evidence(self) -> None:
        activation, grant = _documents()
        provider = FakeProvider(
            [ProviderTurnResult(private_output="PRIVATE_RESULT", usage=_usage(), completed=True)]
        )
        kernel, journal = _kernel(provider)
        result = kernel.execute(_request(activation, grant))
        self.assertEqual("succeeded", result.outcome)
        self.assertEqual("begin", journal.operations[0])
        self.assertEqual(
            (str(activation["execution_id"]), "log_kernel_01"),
            journal.begin_calls[0][:2],
        )
        self.assertEqual(activation, journal.begin_calls[0][2])
        self.assertEqual(grant, journal.begin_calls[0][3])
        self.assertRegex(journal.begin_calls[0][4], r"^[0-9a-f]{64}$")
        self.assertNotIn("PRIVATE_INPUT", json.dumps(journal.begin_calls[0]))

    def test_cancellation_after_durable_begin_precedes_broker_and_provider(self) -> None:
        activation, grant = _documents()
        token = FakeCancellation()

        class CancellingBeginJournal(FakeJournal):
            def begin_execution(self, *args, **kwargs):
                result = super().begin_execution(*args, **kwargs)
                token.cancelled = True
                return result

        provider = FakeProvider([])
        journal = CancellingBeginJournal()
        kernel, _ = _kernel(provider, cancellation=token, journal=journal)
        result = kernel.execute(_request(activation, grant))
        self.assertEqual("cancelled", result.outcome)
        self.assertEqual([], provider.requests)
        self.assertEqual(
            ["begin", "append", "finalize"],
            journal.operations,
        )

    def test_duplicate_or_ambiguous_begin_never_reexecutes_or_writes_later_records(self) -> None:
        activation, grant = _documents()
        for begin_result, expected in (
            (False, "execution_already_recorded"),
            (ValueError(), "journal_begin_ambiguous"),
        ):
            with self.subTest(expected=expected):
                journal = FakeJournal()
                journal.begin_result = begin_result
                provider = FakeProvider(
                    [ProviderTurnResult("PRIVATE_RESULT", _usage(), completed=True)]
                )
                kernel, _ = _kernel(provider, journal=journal)
                with self.assertRaisesRegex(KernelError, expected):
                    kernel.execute(_request(activation, grant))
                self.assertEqual([], provider.requests)
                self.assertEqual(["begin"], journal.operations)
                self.assertEqual([], journal.events)
                self.assertIsNone(journal.receipt)

    def test_begin_mutation_is_detected_and_request_fingerprint_binds_private_hash(self) -> None:
        activation, grant = _documents()

        class MutatingJournal(FakeJournal):
            def begin_execution(self, execution_id, log_id, activation, grant, **kwargs):
                activation["execution_id"] = "execution_forged"
                return super().begin_execution(execution_id, log_id, activation, grant, **kwargs)

        kernel, journal = _kernel(FakeProvider([]), journal=MutatingJournal())
        with self.assertRaisesRegex(KernelError, "journal_corrupt"):
            kernel.execute(_request(activation, grant))
        self.assertEqual(["begin"], journal.operations)

        fingerprints = []
        for private_input in ({"secret": "first"}, {"secret": "second"}):
            local_journal = FakeJournal()
            local_kernel, _ = _kernel(
                FakeProvider([ProviderTurnResult("done", _usage(), completed=True)]),
                journal=local_journal,
            )
            local_kernel.execute(replace(_request(activation, grant), private_input=private_input))
            fingerprints.append(local_journal.begin_calls[0][4])
        self.assertNotEqual(*fingerprints)

        private_input = {"value": "original"}

        class InputMutatingBeginJournal(FakeJournal):
            def begin_execution(self, *args, **kwargs):
                result = super().begin_execution(*args, **kwargs)
                private_input["value"] = "MUTATED_DURING_BEGIN"
                return result

        mutating_journal = InputMutatingBeginJournal()
        mutating_provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
        mutating_kernel, _ = _kernel(
            mutating_provider,
            journal=mutating_journal,
        )
        mutating_kernel.execute(replace(_request(activation, grant), private_input=private_input))
        self.assertEqual({"value": "original"}, mutating_provider.requests[0].private_input)

    def test_fresh_history_and_caller_isolation_hold_across_reuse(self) -> None:
        activation, grant = _documents()
        shared = {"nested": ["PRIVATE_INPUT"]}
        request = replace(_request(activation, grant), private_input=shared)

        def mutate_input(turn):
            turn.private_input["nested"].append("MUTATED_BY_ADAPTER")
            return ProviderTurnResult("first", _usage(), completed=True)

        provider = FakeProvider(
            [
                mutate_input,
                ProviderTurnResult("second", _usage(), completed=True),
            ]
        )
        first, _ = _kernel(provider)
        first.execute(request)
        second, _ = _kernel(provider)
        second.execute(_request(activation, grant))
        self.assertEqual([(), ()], [call.history for call in provider.requests])
        self.assertEqual({"nested": ["PRIVATE_INPUT"]}, shared)

    def test_malformed_and_oversized_private_provider_fields_fail_with_bounded_codes(self) -> None:
        activation, grant = _documents()
        cases = (
            (
                replace(
                    _request(activation, grant),
                    private_input={"private": "x" * (64 * 1024)},
                ),
                FakeProvider([]),
                "private_field_invalid",
            ),
            (
                _request(activation, grant),
                FakeProvider(
                    [ProviderTurnResult("private", _usage(), completed=1)]  # type: ignore[arg-type]
                ),
                "provider_result_invalid",
            ),
            (
                _request(activation, grant),
                FakeProvider(
                    [
                        ProviderTurnResult(
                            "private",
                            _usage(),
                            tool_calls=(ToolCall("INVALID", {}),),
                            completed=True,
                        )
                    ]
                ),
                "tool_call_invalid",
            ),
        )
        for request, provider, code in cases:
            with self.subTest(code=code):
                result = _kernel(provider)[0].execute(request)
                self.assertEqual([code], result.receipt["failure_codes"])
                self.assertEqual(code, str(KernelError(code)))

    def test_tool_routing_enforces_registry_capability_and_hash_only_evidence(self) -> None:
        activation, grant = _documents()
        tool = FakeTool(
            "source.read", "tool.invoke", ToolResult(private_output={"SECRET_TOOL_RESULT": 1})
        )
        provider = FakeProvider(
            [
                ProviderTurnResult(
                    "done",
                    _usage(),
                    tool_calls=(ToolCall("source.read", {"SECRET_ARGUMENT": 1}),),
                    completed=True,
                )
            ]
        )
        kernel, _ = _kernel(provider, tools=(tool,))
        result = kernel.execute(_request(activation, grant))
        invocation = result.receipt["tool_invocations"][0]
        self.assertEqual(
            ("kernel_invocation_000", 0, "source.read", "succeeded"),
            (
                invocation["invocation_id"],
                invocation["sequence"],
                invocation["tool_id"],
                invocation["outcome"],
            ),
        )
        public = json.dumps({"events": result.events, "receipt": result.receipt})
        self.assertNotIn("SECRET_ARGUMENT", public)
        self.assertNotIn("SECRET_TOOL_RESULT", public)
        self.assertRegex(invocation["request_hash"], r"^[0-9a-f]{64}$")

    def test_tool_adapter_descriptors_are_snapshotted_before_untrusted_routing(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])

        class VolatileTool:
            tool_id = "source.read"
            summary = "Read source."
            input_schema = {"type": "object"}

            def __init__(self, second_value: object) -> None:
                self.reads = 0
                self.second_value = second_value
                self.calls: list[ToolCall] = []

            @property
            def required_capability_id(self):
                self.reads += 1
                if self.reads == 1:
                    return "tool.invoke"
                if isinstance(self.second_value, BaseException):
                    raise self.second_value
                return self.second_value

            def invoke(self, call: ToolCall) -> ToolResult:
                self.calls.append(call)
                return ToolResult("sealed")

        for forged in (BrokerError("private_secret"), "private_secret"):
            with self.subTest(forged=type(forged).__name__):
                tool = VolatileTool(forged)
                result = _kernel(
                    FakeProvider(
                        [
                            ProviderTurnResult(
                                "done",
                                _usage(),
                                tool_calls=(ToolCall("source.read", {}),),
                                completed=True,
                            )
                        ]
                    ),
                    tools=(tool,),
                )[0].execute(_request(activation, grant))
                self.assertEqual("succeeded", result.outcome)
                self.assertEqual(1, tool.reads)
                self.assertEqual(1, len(tool.calls))
                self.assertNotIn("private_secret", json.dumps(result.receipt))

    def test_unknown_ineffective_and_incompatible_tools_fail_without_false_invocation(
        self,
    ) -> None:
        ineffective = _documents_with_requested_but_ineffective_source_read()
        cases = (
            (
                _documents(),
                (),
                ToolCall("other.tool", {}),
            ),
            (
                ineffective,
                (FakeTool("source.read", "tool.invoke", ToolResult("x")),),
                ToolCall("source.read", {}),
            ),
            (
                _documents(),
                (FakeTool("source.read", "memory.read", ToolResult("x")),),
                ToolCall("source.read", {}),
            ),
        )
        for documents, tools, call in cases:
            with self.subTest(tool_id=call.tool_id, tools=tools):
                activation, grant = documents
                provider = FakeProvider(
                    [ProviderTurnResult("private", _usage(), tool_calls=(call,), completed=True)]
                )
                kernel, _ = _kernel(provider, tools=tools)
                result = kernel.execute(_request(activation, grant))
                self.assertEqual("failed", result.outcome)
                self.assertEqual(["tool_not_authorized"], result.receipt["failure_codes"])
                self.assertEqual([], result.receipt["tool_invocations"])
                validate_agent_harness_documents(activation, grant, result.events, result.receipt)

    def test_artifact_and_memory_proposals_require_exact_capabilities_and_return_only_refs(
        self,
    ) -> None:
        activation, grant = _documents(
            capabilities=["artifact.propose", "memory.propose"], tools=[]
        )
        artifact = FakeArtifactPort([{"id": "artifact_closed", "content_hash": "a" * 64}])
        memory = FakeMemoryPort([{"id": "memory_closed", "content_hash": "b" * 64}])
        provider = FakeProvider(
            [
                ProviderTurnResult(
                    "done",
                    _usage(),
                    artifact_proposals=(ArtifactProposal({"PRIVATE_ARTIFACT": 1}),),
                    memory_proposals=(MemoryProposal({"PRIVATE_MEMORY": 1}),),
                    completed=True,
                )
            ]
        )
        kernel, _ = _kernel(provider, artifact_port=artifact, memory_port=memory)
        result = kernel.execute(_request(activation, grant))
        self.assertEqual(
            [{"id": "artifact_closed", "content_hash": "a" * 64}],
            result.receipt["result_artifacts"],
        )
        self.assertNotIn("memory.projected", [event["event_type"] for event in result.events])
        self.assertNotIn("PRIVATE_MEMORY", json.dumps(result.receipt))

    def test_missing_proposal_capability_fails_without_calling_port(self) -> None:
        activation, grant = _documents()
        artifact = FakeArtifactPort([{"id": "artifact_closed", "content_hash": "a" * 64}])
        provider = FakeProvider(
            [
                ProviderTurnResult(
                    "done",
                    _usage(),
                    artifact_proposals=(ArtifactProposal("private"),),
                    completed=True,
                )
            ]
        )
        kernel, _ = _kernel(provider, artifact_port=artifact)
        result = kernel.execute(_request(activation, grant))
        self.assertEqual("failed", result.outcome)
        self.assertEqual([], artifact.proposals)
        self.assertEqual(["artifact_capability_denied"], result.receipt["failure_codes"])

    def test_cancellation_before_provider_and_after_provider_suppresses_side_effects(self) -> None:
        activation, grant = _documents(capabilities=["artifact.propose"], tools=[])
        cases = []
        already_cancelled = FakeCancellation()
        already_cancelled.cancelled = True
        cases.append((already_cancelled, None, 0))
        cancelled_by_provider = FakeCancellation()

        def cancel_after_provider(_request):
            cancelled_by_provider.cancelled = True
            return ProviderTurnResult(
                "discard",
                _usage(),
                artifact_proposals=(ArtifactProposal("private"),),
                completed=True,
            )

        cases.append((cancelled_by_provider, cancel_after_provider, 1))
        for token, action, expected_provider_calls in cases:
            with self.subTest(expected_provider_calls=expected_provider_calls):
                artifact = FakeArtifactPort([{"id": "artifact_closed", "content_hash": "a" * 64}])
                provider = FakeProvider(
                    [
                        action
                        or ProviderTurnResult(
                            "discard", _usage(), artifact_proposals=(), completed=True
                        )
                    ]
                )
                kernel, _ = _kernel(
                    provider,
                    artifact_port=artifact,
                    cancellation=token,
                )
                result = kernel.execute(_request(activation, grant))
                self.assertEqual("cancelled", result.outcome)
                self.assertEqual(expected_provider_calls, len(provider.requests))
                self.assertEqual([], artifact.proposals)
                self.assertEqual(
                    1, [e["event_type"] for e in result.events].count("execution.cancel_requested")
                )

    def test_cancellation_is_checked_before_broker_activation_and_first_journal_append(
        self,
    ) -> None:
        activation, grant = _documents()
        token = FakeCancellation()
        token.cancelled = True

        class ObservingBroker(CapabilityBroker):
            checked_before_activation = False
            activation_calls = 0

            def activate(self, execution_id):
                self.activation_calls += 1
                self.checked_before_activation = token.checks > 0
                return super().activate(execution_id)

        broker = ObservingBroker()
        journal = FakeJournal()
        kernel = AgentExecutionKernel(
            provider=FakeProvider([]),
            broker=broker,
            journal=journal,
            clock=FakeClock(),
            cancellation=token,
        )
        result = kernel.execute(_request(activation, grant))
        self.assertEqual(0, broker.activation_calls)
        self.assertEqual("cancelled", result.outcome)
        self.assertEqual(
            ["execution.cancel_requested", "execution.receipt_recorded"],
            [event["event_type"] for event in result.events],
        )

    def test_cancellation_after_tool_boundary_discards_result_and_suppresses_later_proposal(
        self,
    ) -> None:
        activation, grant = _documents(
            capabilities=["artifact.propose", "tool.invoke"], tools=["source.read"]
        )
        token = FakeCancellation()

        def cancel_in_tool(_call):
            token.cancelled = True
            return ToolResult("PRIVATE_TOOL_RESULT")

        tool = FakeTool("source.read", "tool.invoke", cancel_in_tool)
        artifact = FakeArtifactPort([{"id": "artifact_closed", "content_hash": "a" * 64}])
        provider = FakeProvider(
            [
                ProviderTurnResult(
                    "discard",
                    _usage(),
                    tool_calls=(ToolCall("source.read", {"secret": 1}),),
                    artifact_proposals=(ArtifactProposal("private"),),
                    completed=True,
                )
            ]
        )
        kernel, _ = _kernel(provider, tools=(tool,), artifact_port=artifact, cancellation=token)
        result = kernel.execute(_request(activation, grant))
        self.assertEqual("cancelled", result.outcome)
        self.assertEqual([], artifact.proposals)
        self.assertEqual("cancelled", result.receipt["tool_invocations"][0]["outcome"])

    def test_cancellation_inside_each_boundary_suppresses_later_normal_side_effects(
        self,
    ) -> None:
        activation, grant = _documents(
            capabilities=["artifact.propose", "memory.propose", "tool.invoke"],
            tools=["source.read"],
        )

        journal_token = FakeCancellation()

        class CancellingJournal(FakeJournal):
            def append_event(self, *args, **kwargs):
                super().append_event(*args, **kwargs)
                if len(self.events) == 1:
                    journal_token.cancelled = True

        provider = FakeProvider([ProviderTurnResult("unused", _usage(), completed=True)])
        journal_kernel, _ = _kernel(
            provider,
            cancellation=journal_token,
            journal=CancellingJournal(),
        )
        journal_result = journal_kernel.execute(_request(activation, grant))
        self.assertEqual(0, len(provider.requests))
        self.assertEqual(
            ["worker.activated", "execution.cancel_requested", "execution.receipt_recorded"],
            [event["event_type"] for event in journal_result.events],
        )

        provider_token = FakeCancellation()

        def cancel_in_provider(_request):
            provider_token.cancelled = True
            return ProviderTurnResult(
                "discard",
                _usage(input_tokens=7, output_tokens=5, cached_input_tokens=2),
                tool_calls=(ToolCall("source.read", {}),),
                completed=True,
            )

        tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
        provider_result = _kernel(
            FakeProvider([cancel_in_provider]),
            tools=(tool,),
            cancellation=provider_token,
        )[0].execute(_request(activation, grant))
        self.assertEqual("cancelled", provider_result.outcome)
        self.assertEqual(7, provider_result.receipt["usage"]["input_tokens"])
        self.assertEqual(5, provider_result.receipt["usage"]["output_tokens"])
        self.assertEqual([], tool.calls)

        tool_token = FakeCancellation()
        artifact = FakeArtifactPort([{"id": "artifact_closed", "content_hash": "a" * 64}])

        def cancel_in_tool(_call):
            tool_token.cancelled = True
            return ToolResult("discard")

        tool = FakeTool("source.read", "tool.invoke", cancel_in_tool)
        tool_result = _kernel(
            FakeProvider(
                [
                    ProviderTurnResult(
                        "discard",
                        _usage(),
                        tool_calls=(ToolCall("source.read", {}),),
                        artifact_proposals=(ArtifactProposal("unused"),),
                        completed=True,
                    )
                ]
            ),
            tools=(tool,),
            artifact_port=artifact,
            cancellation=tool_token,
        )[0].execute(_request(activation, grant))
        self.assertEqual("cancelled", tool_result.outcome)
        self.assertEqual([], artifact.proposals)

        proposal_token = FakeCancellation()
        memory = FakeMemoryPort([{"id": "memory_closed", "content_hash": "b" * 64}])

        class CancellingArtifactPort(FakeArtifactPort):
            def propose(self, proposal):
                identity = super().propose(proposal)
                proposal_token.cancelled = True
                return identity

        artifact = CancellingArtifactPort([{"id": "artifact_closed", "content_hash": "a" * 64}])
        proposal_result = _kernel(
            FakeProvider(
                [
                    ProviderTurnResult(
                        "discard",
                        _usage(),
                        artifact_proposals=(ArtifactProposal("accepted"),),
                        memory_proposals=(MemoryProposal("must_not_run"),),
                        completed=True,
                    )
                ]
            ),
            artifact_port=artifact,
            memory_port=memory,
            cancellation=proposal_token,
        )[0].execute(_request(activation, grant))
        self.assertEqual("cancelled", proposal_result.outcome)
        self.assertEqual(1, len(artifact.proposals))
        self.assertEqual([], memory.proposals)

        for result in (journal_result, provider_result, tool_result, proposal_result):
            self.assertEqual(
                1,
                [event["event_type"] for event in result.events].count(
                    "execution.cancel_requested"
                ),
            )

    def test_boundary_exception_then_cancellation_has_deterministic_cancel_precedence(
        self,
    ) -> None:
        activation, grant = _documents(
            capabilities=["artifact.propose", "memory.propose", "tool.invoke"],
            tools=["source.read"],
        )

        provider_token = FakeCancellation()

        def cancel_and_raise_provider(_request):
            provider_token.cancelled = True
            raise RuntimeError("PRIVATE_PROVIDER_FAILURE")

        provider_result = _kernel(
            FakeProvider([cancel_and_raise_provider]), cancellation=provider_token
        )[0].execute(_request(activation, grant))
        self.assertEqual(
            ("cancelled", ["execution_cancelled"]),
            (
                provider_result.outcome,
                provider_result.receipt["failure_codes"],
            ),
        )

        tool_token = FakeCancellation()

        def cancel_and_raise_tool(_call):
            tool_token.cancelled = True
            raise RuntimeError("PRIVATE_TOOL_FAILURE")

        tool = FakeTool("source.read", "tool.invoke", cancel_and_raise_tool)
        tool_result = _kernel(
            FakeProvider(
                [
                    ProviderTurnResult(
                        "discard",
                        _usage(),
                        tool_calls=(ToolCall("source.read", {}),),
                        completed=True,
                    )
                ]
            ),
            tools=(tool,),
            cancellation=tool_token,
        )[0].execute(_request(activation, grant))
        self.assertEqual("cancelled", tool_result.outcome)
        self.assertEqual(
            ("cancelled", ["execution_cancelled"]),
            (
                tool_result.receipt["tool_invocations"][0]["outcome"],
                tool_result.receipt["tool_invocations"][0]["failure_codes"],
            ),
        )

        class CancellingArtifactPort(FakeArtifactPort):
            def propose(self, proposal):
                self.proposals.append(proposal)
                artifact_token.cancelled = True
                raise RuntimeError("PRIVATE_ARTIFACT_FAILURE")

        artifact_token = FakeCancellation()
        artifact = CancellingArtifactPort([])
        artifact_result = _kernel(
            FakeProvider(
                [
                    ProviderTurnResult(
                        "discard",
                        _usage(),
                        artifact_proposals=(ArtifactProposal("private"),),
                        completed=True,
                    )
                ]
            ),
            artifact_port=artifact,
            cancellation=artifact_token,
        )[0].execute(_request(activation, grant))
        self.assertEqual("cancelled", artifact_result.outcome)
        self.assertEqual(["execution_cancelled"], artifact_result.receipt["failure_codes"])

        class CancellingMemoryPort(FakeMemoryPort):
            def propose(self, proposal):
                self.proposals.append(proposal)
                memory_token.cancelled = True
                raise RuntimeError("PRIVATE_MEMORY_FAILURE")

        memory_token = FakeCancellation()
        memory = CancellingMemoryPort([])
        memory_result = _kernel(
            FakeProvider(
                [
                    ProviderTurnResult(
                        "discard",
                        _usage(),
                        memory_proposals=(MemoryProposal("private"),),
                        completed=True,
                    )
                ]
            ),
            memory_port=memory,
            cancellation=memory_token,
        )[0].execute(_request(activation, grant))
        self.assertEqual("cancelled", memory_result.outcome)
        self.assertEqual(["execution_cancelled"], memory_result.receipt["failure_codes"])

        for result in (provider_result, tool_result, artifact_result, memory_result):
            public = json.dumps({"events": result.events, "receipt": result.receipt})
            self.assertIn("execution.cancel_requested", public)
            self.assertNotIn("PRIVATE_", public)

    def test_journal_exception_then_cancellation_stops_without_further_unsafe_writes(
        self,
    ) -> None:
        activation, grant = _documents()
        token = FakeCancellation()

        class CancellingFailOnceJournal(FakeJournal):
            failed = False

            def append_event(self, execution_id, event, **kwargs):
                if not self.failed:
                    self.failed = True
                    token.cancelled = True
                    raise ValueError("PRIVATE_TRANSIENT_APPEND")
                super().append_event(execution_id, event, **kwargs)

        kernel, journal = _kernel(
            FakeProvider([ProviderTurnResult("unused", _usage(), completed=True)]),
            cancellation=token,
            journal=CancellingFailOnceJournal(),
        )
        with self.assertRaisesRegex(KernelError, "journal_append_ambiguous"):
            kernel.execute(_request(activation, grant))
        self.assertEqual(["begin"], journal.operations)
        self.assertEqual([], journal.events)
        self.assertIsNone(journal.receipt)

    def test_provider_exception_then_exact_deadline_records_deadline_cancellation(self) -> None:
        activation, grant = _documents()
        clock = FakeClock(1_000)

        def reach_deadline_and_raise(_request):
            clock.value = 2_000
            raise RuntimeError("PRIVATE_PROVIDER_FAILURE")

        result = _kernel(FakeProvider([reach_deadline_and_raise]), clock=clock)[0].execute(
            _request(activation, grant, deadline_ms=2_000)
        )
        self.assertEqual("cancelled", result.outcome)
        self.assertEqual(["execution_deadline_exceeded"], result.receipt["failure_codes"])
        self.assertIn(
            "execution.cancel_requested", [event["event_type"] for event in result.events]
        )
        self.assertNotIn("PRIVATE_PROVIDER_FAILURE", json.dumps(result.receipt))

    def test_cancellation_is_checked_again_before_atomic_finalization(self) -> None:
        activation, grant = _documents()

        class FinalizationCancellation(FakeCancellation):
            def is_cancelled(self) -> bool:
                stack = traceback.extract_stack()
                return len(stack) >= 3 and stack[-3].name == "_finalize_result"

        token = FinalizationCancellation()
        provider = FakeProvider([ProviderTurnResult("discard", _usage(), completed=True)])
        kernel, journal = _kernel(provider, cancellation=token)
        result = kernel.execute(_request(activation, grant))
        self.assertEqual("cancelled", result.outcome)
        self.assertEqual("cancelled", journal.receipt["outcome"])
        self.assertEqual("execution.cancel_requested", result.events[-2]["event_type"])

    def test_exact_deadline_reached_only_at_finalization_cannot_succeed(self) -> None:
        activation, grant = _documents()

        class FinalCheckClock(FakeClock):
            def now_ms(self) -> int:
                stack = traceback.extract_stack()
                if (
                    len(stack) >= 4
                    and stack[-4].name == "_finalize_result"
                    and stack[-3].name == "_cancellation_reason"
                ):
                    return 2_000
                return 1_000

        provider = FakeProvider([ProviderTurnResult("discard", _usage(), completed=True)])
        result = _kernel(provider, clock=FinalCheckClock())[0].execute(
            _request(activation, grant, deadline_ms=2_000)
        )
        self.assertEqual("cancelled", result.outcome)
        self.assertEqual(["execution_deadline_exceeded"], result.receipt["failure_codes"])
        self.assertIsNone(result.private_output)

    def test_budget_boundaries_are_inclusive_and_deadline_is_exclusive(self) -> None:
        activation, grant = _documents()
        exact = FakeProvider(
            [
                ProviderTurnResult(
                    "ok",
                    _usage(
                        input_tokens=4, output_tokens=6, cached_input_tokens=0, cost_minor_units=10
                    ),
                    completed=True,
                )
            ]
        )
        result = _kernel(exact)[0].execute(
            _request(activation, grant, max_total_tokens=10, max_cost_minor_units=10)
        )
        self.assertEqual("succeeded", result.outcome)
        over = FakeProvider(
            [
                ProviderTurnResult(
                    "no",
                    _usage(input_tokens=4, output_tokens=7, cached_input_tokens=0),
                    completed=True,
                )
            ]
        )
        self.assertEqual(
            "failed",
            _kernel(over)[0].execute(_request(activation, grant, max_total_tokens=10)).outcome,
        )
        unreported = FakeProvider(
            [
                ProviderTurnResult(
                    "no billing claim",
                    _usage(cost_minor_units=None, currency=None),
                    completed=True,
                )
            ]
        )
        self.assertEqual(
            ["provider_usage_invalid"],
            _kernel(unreported)[0].execute(_request(activation, grant)).receipt["failure_codes"],
        )
        at_deadline = FakeClock(2_000)
        provider = FakeProvider([ProviderTurnResult("never", _usage(), completed=True)])
        cancelled = _kernel(provider, clock=at_deadline)[0].execute(_request(activation, grant))
        self.assertEqual(("cancelled", 0), (cancelled.outcome, len(provider.requests)))

    def test_no_cost_limits_finalize_canonical_receipts_for_early_outcomes(self) -> None:
        activation, grant = _documents()
        cancelled = FakeCancellation()
        cancelled.cancelled = True
        cases = (
            (
                "pre_cancel",
                FakeProvider([]),
                _request(
                    activation,
                    grant,
                    max_cost_minor_units=None,
                    currency=None,
                ),
                FakeClock(),
                cancelled,
                "cancelled",
                "execution_cancelled",
            ),
            (
                "initial_deadline",
                FakeProvider([]),
                _request(
                    activation,
                    grant,
                    max_cost_minor_units=None,
                    currency=None,
                ),
                FakeClock(2_000),
                FakeCancellation(),
                "cancelled",
                "execution_deadline_exceeded",
            ),
            (
                "invalid_private_input",
                FakeProvider([]),
                replace(
                    _request(
                        activation,
                        grant,
                        max_cost_minor_units=None,
                        currency=None,
                    ),
                    private_input=object(),
                ),
                FakeClock(),
                FakeCancellation(),
                "failed",
                "private_field_invalid",
            ),
            (
                "provider_exception",
                FakeProvider([RuntimeError("PRIVATE_PROVIDER_FAILURE")]),
                _request(
                    activation,
                    grant,
                    max_cost_minor_units=None,
                    currency=None,
                ),
                FakeClock(),
                FakeCancellation(),
                "failed",
                "provider_failed",
            ),
            (
                "invalid_provider_result",
                FakeProvider([object()]),
                _request(
                    activation,
                    grant,
                    max_cost_minor_units=None,
                    currency=None,
                ),
                FakeClock(),
                FakeCancellation(),
                "failed",
                "provider_result_invalid",
            ),
            (
                "invalid_usage",
                FakeProvider(
                    [
                        ProviderTurnResult(
                            "discard",
                            _usage(cost_minor_units=1, currency="USD"),
                            completed=True,
                        )
                    ]
                ),
                _request(
                    activation,
                    grant,
                    max_cost_minor_units=None,
                    currency=None,
                ),
                FakeClock(),
                FakeCancellation(),
                "failed",
                "provider_usage_invalid",
            ),
        )

        for label, provider, request, clock, token, outcome, reason_code in cases:
            with self.subTest(label=label):
                journal = FakeJournal()
                result = _kernel(
                    provider,
                    clock=clock,
                    cancellation=token,
                    journal=journal,
                )[0].execute(request)
                self.assertEqual(outcome, result.outcome)
                self.assertEqual([reason_code], result.receipt["failure_codes"])
                self.assertEqual(
                    (None, None),
                    (
                        result.receipt["usage"]["cost_minor_units"],
                        result.receipt["usage"]["currency"],
                    ),
                )
                self.assertEqual(result.receipt, journal.receipt)
                self.assertEqual(list(result.events), journal.events)
                if label == "invalid_private_input":
                    self.assertIsNone(journal.begin_calls[0][4])
                self.assertEqual(
                    canonical_agent_harness_hash(result.receipt),
                    result.receipt["content_hash"],
                )
                aggregate = validate_agent_harness_documents(
                    activation,
                    grant,
                    result.events,
                    result.receipt,
                )
                self.assertEqual(result.receipt, aggregate.receipt)

    def test_no_cost_limits_account_unpriced_usage_and_reject_any_cost_claim(self) -> None:
        activation, grant = _documents()
        request = _request(
            activation,
            grant,
            max_cost_minor_units=None,
            currency=None,
        )
        unpriced = _kernel(
            FakeProvider(
                [
                    ProviderTurnResult(
                        "ok",
                        _usage(
                            input_tokens=7,
                            output_tokens=5,
                            cached_input_tokens=2,
                            cost_minor_units=None,
                            currency=None,
                        ),
                        completed=True,
                    )
                ]
            )
        )[0].execute(request)
        self.assertEqual("succeeded", unpriced.outcome)
        self.assertEqual(
            (7, 5, 2, None, None),
            (
                unpriced.receipt["usage"]["input_tokens"],
                unpriced.receipt["usage"]["output_tokens"],
                unpriced.receipt["usage"]["cached_input_tokens"],
                unpriced.receipt["usage"]["cost_minor_units"],
                unpriced.receipt["usage"]["currency"],
            ),
        )
        validate_agent_harness_documents(activation, grant, unpriced.events, unpriced.receipt)

        for reported_cost in (0, 7):
            with self.subTest(reported_cost=reported_cost):
                result = _kernel(
                    FakeProvider(
                        [
                            ProviderTurnResult(
                                "discard",
                                _usage(
                                    cost_minor_units=reported_cost,
                                    currency="USD",
                                ),
                                completed=True,
                            )
                        ]
                    )
                )[0].execute(request)
                self.assertEqual("failed", result.outcome)
                self.assertEqual(["provider_usage_invalid"], result.receipt["failure_codes"])
                self.assertEqual(
                    (0, 0, 0, None, None),
                    (
                        result.receipt["usage"]["input_tokens"],
                        result.receipt["usage"]["output_tokens"],
                        result.receipt["usage"]["cached_input_tokens"],
                        result.receipt["usage"]["cost_minor_units"],
                        result.receipt["usage"]["currency"],
                    ),
                )
                validate_agent_harness_documents(
                    activation,
                    grant,
                    result.events,
                    result.receipt,
                )

    def test_usage_type_overflow_currency_and_cached_counts_fail_closed(self) -> None:
        activation, grant = _documents()

        class ForgedInt(int):
            pass

        class ForgedCurrency(str):
            pass

        usages = (
            _usage(input_tokens=True),
            _usage(input_tokens=ForgedInt(3)),
            _usage(output_tokens=MAX_SAFE_INTEGER + 1),
            _usage(input_tokens=1, cached_input_tokens=2),
            _usage(currency="EUR"),
            _usage(currency=ForgedCurrency("USD")),
            _usage(input_tokens=MAX_SAFE_INTEGER, output_tokens=1, cached_input_tokens=0),
        )
        for usage in usages:
            with self.subTest(usage=usage):
                result = _kernel(
                    FakeProvider([ProviderTurnResult("private", usage, completed=True)])
                )[0].execute(_request(activation, grant, max_total_tokens=MAX_SAFE_INTEGER))
                self.assertEqual("failed", result.outcome)
                self.assertIn(
                    result.receipt["failure_codes"][0],
                    {"provider_usage_invalid", "provider_currency_mismatch"},
                )

    def test_usage_is_accounted_before_cancellation_and_budget_failure_has_precedence(
        self,
    ) -> None:
        activation, grant = _documents()
        cases = (
            (
                _usage(input_tokens=70, output_tokens=40, cached_input_tokens=0),
                "token_budget_exceeded",
                (70, 40),
            ),
            (
                _usage(input_tokens=True),
                "provider_usage_invalid",
                (0, 0),
            ),
        )
        for usage, code, accounted in cases:
            with self.subTest(code=code):
                token = FakeCancellation()

                def cancel_with_usage(_request, usage=usage, token=token):
                    token.cancelled = True
                    return ProviderTurnResult("discard", usage, completed=True)

                result = _kernel(FakeProvider([cancel_with_usage]), cancellation=token)[0].execute(
                    _request(activation, grant, max_total_tokens=100)
                )
                self.assertEqual("failed", result.outcome)
                self.assertEqual([code], result.receipt["failure_codes"])
                self.assertEqual(accounted[0], result.receipt["usage"]["input_tokens"])
                self.assertEqual(accounted[1], result.receipt["usage"]["output_tokens"])
                self.assertNotIn(
                    "execution.cancel_requested", [event["event_type"] for event in result.events]
                )

        token = FakeCancellation()

        def cancel_with_cost(_request):
            token.cancelled = True
            return ProviderTurnResult("discard", _usage(cost_minor_units=11), completed=True)

        cost_result = _kernel(FakeProvider([cancel_with_cost]), cancellation=token)[0].execute(
            _request(activation, grant, max_cost_minor_units=10)
        )
        self.assertEqual(["cost_budget_exceeded"], cost_result.receipt["failure_codes"])
        self.assertEqual(11, cost_result.receipt["usage"]["cost_minor_units"])

    def test_usage_precedes_nested_provider_result_validation(self) -> None:
        activation, grant = _documents()
        cases = (
            (
                ProviderTurnResult(
                    "discard",
                    _usage(input_tokens=7, output_tokens=5, cached_input_tokens=2),
                    tool_calls=[ToolCall("source.read", {})],
                    completed=True,
                ),
                100,
                "provider_result_invalid",
                (7, 5),
            ),
            (
                ProviderTurnResult(
                    "discard",
                    _usage(input_tokens=True),
                    tool_calls=[ToolCall("source.read", {})],
                    completed=True,
                ),
                100,
                "provider_usage_invalid",
                (0, 0),
            ),
            (
                ProviderTurnResult(
                    "discard",
                    _usage(input_tokens=70, output_tokens=40, cached_input_tokens=0),
                    tool_calls=[ToolCall("source.read", {})],
                    completed=True,
                ),
                100,
                "token_budget_exceeded",
                (70, 40),
            ),
        )
        for turn, max_tokens, code, accounted in cases:
            with self.subTest(code=code):
                result = _kernel(FakeProvider([turn]))[0].execute(
                    _request(activation, grant, max_total_tokens=max_tokens)
                )
                self.assertEqual([code], result.receipt["failure_codes"])
                self.assertEqual(accounted[0], result.receipt["usage"]["input_tokens"])
                self.assertEqual(accounted[1], result.receipt["usage"]["output_tokens"])

    def test_valid_usage_is_accounted_before_cancel_precedes_malformed_nested_result(
        self,
    ) -> None:
        activation, grant = _documents()
        token = FakeCancellation()

        def cancel_with_malformed_nested_result(_request):
            token.cancelled = True
            return ProviderTurnResult(
                "discard",
                _usage(input_tokens=7, output_tokens=5, cached_input_tokens=2),
                tool_calls=[ToolCall("source.read", {})],
                completed=True,
            )

        result = _kernel(FakeProvider([cancel_with_malformed_nested_result]), cancellation=token)[
            0
        ].execute(_request(activation, grant))
        self.assertEqual("cancelled", result.outcome)
        self.assertEqual(["execution_cancelled"], result.receipt["failure_codes"])
        self.assertEqual(7, result.receipt["usage"]["input_tokens"])
        self.assertEqual(5, result.receipt["usage"]["output_tokens"])

    def test_provider_boundary_cancellation_precedes_invalid_top_level_result(self) -> None:
        activation, grant = _documents()
        token = FakeCancellation()

        def cancel_with_invalid_result(_request):
            token.cancelled = True
            return object()

        result = _kernel(FakeProvider([cancel_with_invalid_result]), cancellation=token)[0].execute(
            _request(activation, grant)
        )
        self.assertEqual("cancelled", result.outcome)
        self.assertEqual(["execution_cancelled"], result.receipt["failure_codes"])

    def test_missing_exact_usage_fields_fail_with_bounded_code(self) -> None:
        activation, grant = _documents()
        missing_usage = object.__new__(ProviderUsage)
        usage_result = _kernel(
            FakeProvider([ProviderTurnResult("discard", missing_usage, completed=True)])
        )[0].execute(_request(activation, grant))
        self.assertEqual(["provider_usage_invalid"], usage_result.receipt["failure_codes"])

    def test_missing_exact_tool_result_fields_fail_with_bounded_code(self) -> None:
        activation, grant = _documents()
        missing_tool_result = object.__new__(ToolResult)
        tool = FakeTool("source.read", "tool.invoke", missing_tool_result)
        tool_result = _kernel(
            FakeProvider(
                [
                    ProviderTurnResult(
                        "discard",
                        _usage(),
                        tool_calls=(ToolCall("source.read", {}),),
                        completed=True,
                    )
                ]
            ),
            tools=(tool,),
        )[0].execute(_request(activation, grant))
        self.assertEqual(["tool_result_invalid"], tool_result.receipt["failure_codes"])

    def test_provider_result_is_deeply_preflighted_before_any_adapter_side_effect(self) -> None:
        activation, grant = _documents(
            capabilities=["artifact.propose", "memory.propose", "tool.invoke"],
            tools=["source.read", "world.validate"],
        )
        tool = FakeTool("source.read", "tool.invoke", ToolResult("x"))
        second_tool = FakeTool("world.validate", "tool.invoke", ToolResult("x"))
        artifact = FakeArtifactPort(
            [{"id": f"artifact_{index:02d}", "content_hash": "a" * 64} for index in range(64)]
        )
        memory = FakeMemoryPort(
            [{"id": f"memory_{index:02d}", "content_hash": "b" * 64} for index in range(64)]
        )

        class ForgedToolCall(ToolCall):
            pass

        class ForgedUsage(ProviderUsage):
            pass

        class ForgedArtifactProposal(ArtifactProposal):
            pass

        class ForgedMemoryProposal(MemoryProposal):
            pass

        missing_fields = object.__new__(ProviderTurnResult)

        cases = (
            (object(), "provider_result_invalid"),
            (missing_fields, "provider_result_invalid"),
            (
                ProviderTurnResult("x", ForgedUsage(1, 1, 0, 0, "USD"), completed=True),
                "provider_usage_invalid",
            ),
            (
                ProviderTurnResult("x", _usage(), tool_calls=[ToolCall("source.read", {})]),
                "provider_result_invalid",
            ),
            (
                ProviderTurnResult(
                    "x",
                    _usage(),
                    tool_calls=(ToolCall("source.read", {}), object()),
                    completed=True,
                ),
                "provider_result_invalid",
            ),
            (
                ProviderTurnResult(
                    "x",
                    _usage(),
                    artifact_proposals=(ForgedArtifactProposal("x"),),
                    completed=True,
                ),
                "provider_result_invalid",
            ),
            (
                ProviderTurnResult(
                    "x",
                    _usage(),
                    memory_proposals=(ForgedMemoryProposal("x"),),
                    completed=True,
                ),
                "provider_result_invalid",
            ),
            (
                ProviderTurnResult(
                    "x",
                    _usage(),
                    tool_calls=(ForgedToolCall("source.read", {}),),
                    completed=True,
                ),
                "provider_result_invalid",
            ),
            (
                ProviderTurnResult(
                    "x",
                    _usage(),
                    artifact_proposals=tuple(ArtifactProposal(index) for index in range(65)),
                    completed=True,
                ),
                "provider_result_invalid",
            ),
            (
                ProviderTurnResult(
                    "x",
                    _usage(),
                    memory_proposals=tuple(MemoryProposal(index) for index in range(65)),
                    completed=True,
                ),
                "provider_result_invalid",
            ),
            (
                ProviderTurnResult(
                    "x",
                    _usage(),
                    tool_calls=(ToolCall("source.read", {}),),
                    artifact_proposals=(ArtifactProposal("x" * (64 * 1024)),),
                    completed=True,
                ),
                "provider_result_invalid",
            ),
        )
        for turn, expected_code in cases:
            with self.subTest(turn_type=type(turn).__name__, expected_code=expected_code):
                tool.calls.clear()
                second_tool.calls.clear()
                artifact.proposals.clear()
                memory.proposals.clear()
                result = _kernel(
                    FakeProvider([turn]),
                    tools=(tool, second_tool),
                    artifact_port=artifact,
                    memory_port=memory,
                )[0].execute(_request(activation, grant))
                self.assertEqual("failed", result.outcome)
                self.assertEqual([expected_code], result.receipt["failure_codes"])
                self.assertEqual([], tool.calls)
                self.assertEqual([], second_tool.calls)
                self.assertEqual([], artifact.proposals)
                self.assertEqual([], memory.proposals)

        over_tool_batch = ProviderTurnResult(
            "x",
            _usage(),
            tool_calls=(ToolCall("source.read", {}), ToolCall("world.validate", {})),
            completed=True,
        )
        result = _kernel(FakeProvider([over_tool_batch]), tools=(tool, second_tool))[0].execute(
            _request(activation, grant, max_tool_calls=1)
        )
        self.assertEqual(["tool_budget_exceeded"], result.receipt["failure_codes"])
        self.assertEqual([], tool.calls)
        self.assertEqual([], second_tool.calls)

    def test_cumulative_private_history_is_bounded_before_the_next_provider_call(self) -> None:
        activation, grant = _documents()
        provider = FakeProvider(
            [
                ProviderTurnResult("a" * 40_000, _usage(), completed=False),
                ProviderTurnResult("b" * 40_000, _usage(), completed=False),
            ]
        )
        result = _kernel(provider)[0].execute(
            _request(activation, grant, max_turns=3, max_total_tokens=100)
        )
        self.assertEqual(["private_field_invalid"], result.receipt["failure_codes"])
        self.assertEqual(2, len(provider.requests))

    def test_provider_turn_and_request_values_are_sealed_before_later_boundaries(self) -> None:
        activation, grant = _documents(
            capabilities=["artifact.propose", "tool.invoke"],
            tools=["source.read", "world.validate"],
        )
        second_arguments = {"value": "original"}
        proposal_payload = {"value": "original"}
        provider_output = {"value": "original"}

        def mutate_provider_aliases(_call):
            second_arguments["value"] = "MUTATED_BY_TOOL"
            proposal_payload["value"] = "MUTATED_BY_TOOL"
            provider_output["value"] = "MUTATED_BY_TOOL"
            return ToolResult("first")

        first_tool = FakeTool("source.read", "tool.invoke", mutate_provider_aliases)
        second_tool = FakeTool("world.validate", "tool.invoke", ToolResult("second"))
        artifact = FakeArtifactPort([{"id": "artifact_closed", "content_hash": "a" * 64}])
        turn = ProviderTurnResult(
            provider_output,
            _usage(),
            tool_calls=(
                ToolCall("source.read", {"step": 1}),
                ToolCall("world.validate", second_arguments),
            ),
            artifact_proposals=(ArtifactProposal(proposal_payload),),
            completed=True,
        )
        result = _kernel(
            FakeProvider([turn]),
            tools=(first_tool, second_tool),
            artifact_port=artifact,
        )[0].execute(_request(activation, grant))
        self.assertEqual({"value": "original"}, second_tool.calls[0].private_arguments)
        self.assertEqual({"value": "original"}, artifact.proposals[0].private_payload)
        self.assertEqual({"value": "original"}, result.private_output)
        expected_hash = hashlib.sha256(b'world.validate\0{"value":"original"}').hexdigest()
        self.assertEqual(expected_hash, result.receipt["tool_invocations"][1]["request_hash"])

        private_input = {"value": "original"}

        class InputMutatingJournal(FakeJournal):
            def append_event(self, execution_id, event, **kwargs):
                super().append_event(execution_id, event, **kwargs)
                private_input["value"] = "MUTATED_BY_JOURNAL"

        provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
        request = replace(_request(activation, grant), private_input=private_input)
        _kernel(provider, journal=InputMutatingJournal())[0].execute(request)
        self.assertEqual({"value": "original"}, provider.requests[0].private_input)

    def test_all_tool_and_proposal_authority_is_preflighted_as_one_batch(self) -> None:
        activation, grant = _documents(capabilities=["artifact.propose"], tools=[])
        artifact = FakeArtifactPort([{"id": "artifact_closed", "content_hash": "a" * 64}])
        memory = FakeMemoryPort([{"id": "memory_closed", "content_hash": "b" * 64}])
        turn = ProviderTurnResult(
            "x",
            _usage(),
            artifact_proposals=(ArtifactProposal("would_be_valid"),),
            memory_proposals=(MemoryProposal("not_authorized"),),
            completed=True,
        )
        result = _kernel(FakeProvider([turn]), artifact_port=artifact, memory_port=memory)[
            0
        ].execute(_request(activation, grant))
        self.assertEqual(["memory_capability_denied"], result.receipt["failure_codes"])
        self.assertEqual([], artifact.proposals)
        self.assertEqual([], memory.proposals)

    def test_duplicate_or_malformed_proposal_identities_fail_with_bounded_codes(self) -> None:
        activation, grant = _documents(capabilities=["artifact.propose"], tools=[])
        proposals = (ArtifactProposal("one"), ArtifactProposal("two"))
        duplicate = {"id": "artifact_closed", "content_hash": "a" * 64}
        port = FakeArtifactPort([duplicate, duplicate])
        result = _kernel(
            FakeProvider(
                [
                    ProviderTurnResult(
                        "discard", _usage(), artifact_proposals=proposals, completed=True
                    )
                ]
            ),
            artifact_port=port,
        )[0].execute(_request(activation, grant))
        self.assertEqual(["artifact_result_invalid"], result.receipt["failure_codes"])
        self.assertEqual(2, len(port.proposals))
        self.assertNotIn("artifact_closed", json.dumps(result.receipt["result_artifacts"]))

        malformed = FakeArtifactPort(
            [{"id": "artifact_closed", "content_hash": "PRIVATE_INVALID_HASH"}]
        )
        result = _kernel(
            FakeProvider(
                [
                    ProviderTurnResult(
                        "discard",
                        _usage(),
                        artifact_proposals=(ArtifactProposal("one"),),
                        completed=True,
                    )
                ]
            ),
            artifact_port=malformed,
        )[0].execute(_request(activation, grant))
        self.assertEqual(["artifact_result_invalid"], result.receipt["failure_codes"])
        self.assertNotIn("PRIVATE_INVALID_HASH", json.dumps(result.receipt))

    def test_proposal_count_caps_apply_across_the_whole_execution(self) -> None:
        for capability, proposal_name in (
            ("artifact.propose", "artifact_proposals"),
            ("memory.propose", "memory_proposals"),
        ):
            with self.subTest(capability=capability):
                activation, grant = _documents(capabilities=[capability], tools=[])
                first = tuple(
                    ArtifactProposal(index)
                    if capability == "artifact.propose"
                    else MemoryProposal(index)
                    for index in range(64)
                )
                second = (
                    ArtifactProposal(64)
                    if capability == "artifact.propose"
                    else MemoryProposal(64),
                )
                provider = FakeProvider(
                    [
                        ProviderTurnResult(
                            "continue",
                            _usage(),
                            completed=False,
                            **{proposal_name: first},
                        ),
                        ProviderTurnResult(
                            "stop",
                            _usage(),
                            completed=True,
                            **{proposal_name: second},
                        ),
                    ]
                )
                identities = [
                    {"id": f"result_{index:02d}", "content_hash": "a" * 64} for index in range(65)
                ]
                artifact = (
                    FakeArtifactPort(identities) if capability == "artifact.propose" else None
                )
                memory = FakeMemoryPort(identities) if capability == "memory.propose" else None
                result = _kernel(provider, artifact_port=artifact, memory_port=memory)[0].execute(
                    _request(activation, grant, max_turns=2)
                )
                self.assertEqual(["provider_result_invalid"], result.receipt["failure_codes"])
                called = artifact.proposals if artifact is not None else memory.proposals
                self.assertEqual(64, len(called))

    def test_execution_limit_types_and_structural_bounds_reject_before_activation(self) -> None:
        activation, grant = _documents()
        for changes in ({"max_turns": True}, {"max_turns": 65}, {"max_tool_calls": 129}):
            with self.subTest(changes=changes):
                kernel, journal = _kernel(FakeProvider([]))
                with self.assertRaises(KernelError) as raised:
                    kernel.execute(_request(activation, grant, **changes))
                self.assertEqual("execution_limits_invalid", raised.exception.reason_code)
                self.assertEqual([], journal.events)

    def test_hostile_activation_and_grant_inputs_fail_before_clock_or_activation(self) -> None:
        activation, grant = _documents()

        class HostileDocument(dict):
            def items(self):
                raise BrokerError("private_secret")

        class CountingClock(FakeClock):
            def __init__(self) -> None:
                super().__init__()
                self.calls = 0

            def now_ms(self) -> int:
                self.calls += 1
                return super().now_ms()

        class CountingBroker(CapabilityBroker):
            def __init__(self) -> None:
                super().__init__()
                self.activations = 0

            def activate(self, execution_id):
                self.activations += 1
                return super().activate(execution_id)

        for hostile_activation, hostile_grant in (
            (HostileDocument(activation), grant),
            (activation, HostileDocument(grant)),
        ):
            with self.subTest(
                activation_type=type(hostile_activation).__name__,
                grant_type=type(hostile_grant).__name__,
            ):
                clock = CountingClock()
                broker = CountingBroker()
                journal = FakeJournal()
                kernel = AgentExecutionKernel(
                    provider=FakeProvider([]),
                    broker=broker,
                    journal=journal,
                    clock=clock,
                    cancellation=FakeCancellation(),
                )
                request = replace(
                    _request(activation, grant),
                    activation=hostile_activation,
                    grant=hostile_grant,
                )
                with self.assertRaises(KernelError) as raised:
                    kernel.execute(request)
                self.assertEqual("execution_request_invalid", raised.exception.reason_code)
                self.assertNotIn("private_secret", str(raised.exception))
                self.assertEqual(0, clock.calls)
                self.assertEqual(0, broker.activations)
                self.assertEqual([], journal.events)

    def test_hostile_nested_public_scalars_and_request_id_subclasses_are_rejected(
        self,
    ) -> None:
        activation, grant = _documents()

        class HostileStr(str):
            def encode(self, *_args, **_kwargs):
                raise BrokerError("private_secret")

            def __str__(self) -> str:
                raise BrokerError("private_secret")

        class HostileInt(int):
            def __eq__(self, _other: object) -> bool:
                raise BrokerError("private_secret")

        class CountingClock(FakeClock):
            def __init__(self) -> None:
                super().__init__()
                self.calls = 0

            def now_ms(self) -> int:
                self.calls += 1
                return super().now_ms()

        hostile_activation = copy.deepcopy(activation)
        hostile_activation["execution_id"] = HostileStr(activation["execution_id"])
        hostile_grant = copy.deepcopy(grant)
        hostile_grant["format_version"] = HostileInt(1)
        cases = (
            replace(_request(activation, grant), activation=hostile_activation),
            replace(_request(activation, grant), grant=hostile_grant),
            replace(_request(activation, grant), log_id=HostileStr("log_kernel_01")),
            replace(
                _request(activation, grant),
                receipt_id=HostileStr("receipt_kernel_01"),
            ),
            replace(
                _request(activation, grant),
                event_id_prefix=HostileStr("kernel_event"),
            ),
            replace(
                _request(activation, grant),
                invocation_id_prefix=HostileStr("kernel_invocation"),
            ),
        )
        for request in cases:
            with self.subTest(request=request):
                clock = CountingClock()
                kernel, journal = _kernel(FakeProvider([]), clock=clock)
                with self.assertRaises(KernelError) as raised:
                    kernel.execute(request)
                self.assertEqual("execution_request_invalid", raised.exception.reason_code)
                self.assertNotIn("private_secret", str(raised.exception))
                self.assertEqual(0, clock.calls)
                self.assertEqual([], journal.events)

    def test_limit_fields_require_exact_builtins_before_clock_or_arithmetic(self) -> None:
        activation, grant = _documents()

        class HostileInt(int):
            def __ge__(self, _other: object) -> bool:
                raise BrokerError("private_secret")

            def __le__(self, _other: object) -> bool:
                raise BrokerError("private_secret")

        class HostileCurrency(str):
            pass

        cases = (
            {"max_turns": HostileInt(4)},
            {"max_tool_calls": HostileInt(4)},
            {"max_total_tokens": HostileInt(100)},
            {"max_duration_ms": HostileInt(100)},
            {"deadline_ms": HostileInt(2_000)},
            {"max_cost_minor_units": HostileInt(10)},
            {"currency": 7},
            {"currency": HostileCurrency("USD")},
        )
        for changes in cases:
            with self.subTest(changes=changes):

                class CountingClock(FakeClock):
                    def __init__(self) -> None:
                        super().__init__()
                        self.calls = 0

                    def now_ms(self) -> int:
                        self.calls += 1
                        return super().now_ms()

                clock = CountingClock()
                kernel, journal = _kernel(FakeProvider([]), clock=clock)
                with self.assertRaises(KernelError) as raised:
                    kernel.execute(_request(activation, grant, **changes))
                self.assertEqual("execution_limits_invalid", raised.exception.reason_code)
                self.assertNotIn("private_secret", str(raised.exception))
                self.assertEqual(0, clock.calls)
                self.assertEqual([], journal.events)

    def test_clock_and_broker_activation_inputs_require_exact_builtin_ids(self) -> None:
        activation, grant = _documents()

        class HostileInt(int):
            def __ge__(self, _other: object) -> bool:
                raise BrokerError("private_secret")

        class PlainIntSubclass(int):
            pass

        for value in (HostileInt(1_000), PlainIntSubclass(1_000)):
            with self.subTest(clock_value_type=type(value).__name__):
                kernel, journal = _kernel(FakeProvider([]), clock=FakeClock(value))
                with self.assertRaises(KernelError) as raised:
                    kernel.execute(_request(activation, grant))
                self.assertEqual("clock_invalid", raised.exception.reason_code)
                self.assertNotIn("private_secret", str(raised.exception))
                self.assertEqual([], journal.events)

        class HostileStr(str):
            pass

        broker = CapabilityBroker()
        with self.assertRaises(BrokerError) as raised:
            broker.activate(HostileStr("execution_kernel_01"))
        self.assertEqual("execution_invalid", raised.exception.reason_code)

    def test_turn_tool_and_duplicate_call_limits_fail_closed(self) -> None:
        activation, grant = _documents()
        duplicate = ToolCall("source.read", {"same": 1})
        provider = FakeProvider(
            [ProviderTurnResult("x", _usage(), tool_calls=(duplicate, duplicate), completed=True)]
        )
        result = _kernel(
            provider, tools=(FakeTool("source.read", "tool.invoke", ToolResult("x")),)
        )[0].execute(_request(activation, grant))
        self.assertEqual(["duplicate_tool_call"], result.receipt["failure_codes"])
        two_turns = FakeProvider(
            [
                ProviderTurnResult("one", _usage(), completed=False),
                ProviderTurnResult("two", _usage(), completed=False),
            ]
        )
        result = _kernel(two_turns)[0].execute(_request(activation, grant, max_turns=1))
        self.assertEqual(["turn_budget_exceeded"], result.receipt["failure_codes"])

    def test_boundary_exceptions_are_normalized_without_private_leakage(self) -> None:
        activation, grant = _documents()
        for error in (
            RuntimeError("PRIVATE_PROVIDER_TRACE"),
            BrokerError("private_secret"),
        ):
            with self.subTest(boundary="provider", error=type(error).__name__):
                result = _kernel(FakeProvider([error]))[0].execute(_request(activation, grant))
                public = json.dumps({"events": result.events, "receipt": result.receipt})
                self.assertEqual(["provider_failed"], result.receipt["failure_codes"])
                self.assertNotIn("PRIVATE_PROVIDER_TRACE", public)
                self.assertNotIn("private_secret", public)

        for error in (
            RuntimeError("PRIVATE_TOOL_TRACE"),
            BrokerError("private_secret"),
        ):
            with self.subTest(boundary="tool", error=type(error).__name__):
                tool = FakeTool("source.read", "tool.invoke", error)
                provider = FakeProvider(
                    [
                        ProviderTurnResult(
                            "x",
                            _usage(),
                            tool_calls=(ToolCall("source.read", {"PRIVATE_ARGUMENT": 1}),),
                            completed=True,
                        )
                    ]
                )
                result = _kernel(provider, tools=(tool,))[0].execute(_request(activation, grant))
                public = json.dumps({"events": result.events, "receipt": result.receipt})
                self.assertEqual(["tool_failed"], result.receipt["failure_codes"])
                self.assertNotIn("PRIVATE", public)
                self.assertNotIn("private_secret", public)

    def test_proposal_exceptions_are_normalized_and_never_retry_ambiguous_side_effects(
        self,
    ) -> None:
        cases = (
            (
                ["artifact.propose"],
                FakeArtifactPort(
                    [
                        RuntimeError("PRIVATE_ARTIFACT_FAILURE"),
                        BrokerError("private_secret"),
                    ]
                ),
                None,
                dict(artifact_proposals=(ArtifactProposal("PRIVATE_ARTIFACT"),)),
                "artifact_proposal_failed",
            ),
            (
                ["memory.propose"],
                None,
                FakeMemoryPort(
                    [
                        RuntimeError("PRIVATE_MEMORY_FAILURE"),
                        BrokerError("private_secret"),
                    ]
                ),
                dict(memory_proposals=(MemoryProposal("PRIVATE_MEMORY"),)),
                "memory_proposal_failed",
            ),
        )
        for capabilities, artifact, memory, proposals, code in cases:
            with self.subTest(code=code):
                activation, grant = _documents(capabilities=capabilities, tools=[])
                provider = FakeProvider(
                    [ProviderTurnResult("discard", _usage(), completed=True, **proposals)]
                )
                kernel, _ = _kernel(provider, artifact_port=artifact, memory_port=memory)
                result = kernel.execute(_request(activation, grant))
                self.assertEqual([code], result.receipt["failure_codes"])
                self.assertNotIn("PRIVATE", json.dumps(result.receipt))
                called = artifact.proposals if artifact is not None else memory.proposals
                self.assertEqual(1, len(called))

                second = _kernel(
                    FakeProvider(
                        [ProviderTurnResult("discard", _usage(), completed=True, **proposals)]
                    ),
                    artifact_port=artifact,
                    memory_port=memory,
                )[0].execute(_request(activation, grant))
                self.assertEqual([code], second.receipt["failure_codes"])
                self.assertNotIn("private_secret", json.dumps(second.receipt))

    def test_malicious_mapping_identities_cannot_supply_public_reason_codes(self) -> None:
        class HostileIdentity(Mapping):
            def __init__(self, mode: str) -> None:
                self.mode = mode

            def __getitem__(self, key: object) -> object:
                if self.mode == "getitem":
                    raise BrokerError("private_secret")
                return {
                    "id": "closed_identity",
                    "content_hash": "a" * 64,
                }[key]

            def __iter__(self) -> Iterator[str]:
                if self.mode == "iter":
                    raise BrokerError("private_secret")
                return iter(("id", "content_hash"))

            def __len__(self) -> int:
                return 2

        class HostileIdentityPort:
            def __init__(self, identity: Mapping) -> None:
                self.identity = identity
                self.proposals: list[object] = []

            def propose(self, proposal):
                self.proposals.append(proposal)
                return self.identity

        for capability, proposal_name, expected_code in (
            ("artifact.propose", "artifact_proposals", "artifact_result_invalid"),
            ("memory.propose", "memory_proposals", "memory_result_invalid"),
        ):
            for mode in ("iter", "getitem"):
                with self.subTest(capability=capability, mode=mode):
                    activation, grant = _documents(capabilities=[capability], tools=[])
                    port = HostileIdentityPort(HostileIdentity(mode))
                    proposal = (
                        ArtifactProposal("private")
                        if capability == "artifact.propose"
                        else MemoryProposal("private")
                    )
                    result = _kernel(
                        FakeProvider(
                            [
                                ProviderTurnResult(
                                    "discard",
                                    _usage(),
                                    completed=True,
                                    **{proposal_name: (proposal,)},
                                )
                            ]
                        ),
                        artifact_port=port if capability == "artifact.propose" else None,
                        memory_port=port if capability == "memory.propose" else None,
                    )[0].execute(_request(activation, grant))
                    self.assertEqual([expected_code], result.receipt["failure_codes"])
                    self.assertNotIn("private_secret", json.dumps(result.receipt))

        class ForgedIdentityString(str):
            pass

        activation, grant = _documents(capabilities=["artifact.propose"], tools=[])
        forged = FakeArtifactPort(
            [
                {
                    "id": ForgedIdentityString("artifact_closed"),
                    "content_hash": ForgedIdentityString("a" * 64),
                }
            ]
        )
        result = _kernel(
            FakeProvider(
                [
                    ProviderTurnResult(
                        "discard",
                        _usage(),
                        artifact_proposals=(ArtifactProposal("private"),),
                        completed=True,
                    )
                ]
            ),
            artifact_port=forged,
        )[0].execute(_request(activation, grant))
        self.assertEqual(["artifact_result_invalid"], result.receipt["failure_codes"])
        self.assertNotIn("artifact_closed", json.dumps(result.receipt["result_artifacts"]))

    def test_base_exception_control_signals_propagate_after_kernel_cleanup(self) -> None:
        activation, grant = _documents()

        class ControlSignal(BaseException):
            pass

        provider = FakeProvider([ControlSignal("PRIVATE_CONTROL")])
        kernel, _ = _kernel(provider)
        with self.assertRaises(ControlSignal):
            kernel.execute(_request(activation, grant))
        kernel.journal = FakeJournal()
        provider.script.append(ProviderTurnResult("recovered", _usage(), completed=True))
        recovered = kernel.execute(_request(activation, grant))
        self.assertEqual("succeeded", recovered.outcome)

    def test_control_signal_policy_is_consistent_for_tool_and_proposal_ports(self) -> None:
        class ControlSignal(BaseException):
            pass

        cases = (
            (
                ["tool.invoke"],
                ["source.read"],
                (FakeTool("source.read", "tool.invoke", ControlSignal("PRIVATE_TOOL")),),
                None,
                None,
                dict(tool_calls=(ToolCall("source.read", {}),)),
            ),
            (
                ["artifact.propose"],
                [],
                (),
                FakeArtifactPort([ControlSignal("PRIVATE_ARTIFACT")]),
                None,
                dict(artifact_proposals=(ArtifactProposal("private"),)),
            ),
            (
                ["memory.propose"],
                [],
                (),
                None,
                FakeMemoryPort([ControlSignal("PRIVATE_MEMORY")]),
                dict(memory_proposals=(MemoryProposal("private"),)),
            ),
        )
        for capabilities, tools, adapters, artifact, memory, turn_values in cases:
            with self.subTest(capabilities=capabilities):
                activation, grant = _documents(capabilities=capabilities, tools=tools)
                provider = FakeProvider(
                    [ProviderTurnResult("discard", _usage(), completed=True, **turn_values)]
                )
                kernel, _ = _kernel(
                    provider,
                    tools=adapters,
                    artifact_port=artifact,
                    memory_port=memory,
                )
                with self.assertRaises(ControlSignal):
                    kernel.execute(_request(activation, grant))
                kernel.journal = FakeJournal()
                provider.script.append(ProviderTurnResult("recovered", _usage(), completed=True))
                self.assertEqual("succeeded", kernel.execute(_request(activation, grant)).outcome)

    def test_journal_compare_append_corruption_rejects_and_finalize_is_atomic(self) -> None:
        activation, grant = _documents()
        journal = FakeJournal()
        journal.fail_next = True
        kernel, _ = _kernel(
            FakeProvider([ProviderTurnResult("x", _usage(), completed=True)]), journal=journal
        )
        with self.assertRaises(KernelError) as raised:
            kernel.execute(_request(activation, grant))
        self.assertEqual("journal_append_ambiguous", raised.exception.reason_code)
        self.assertIsNone(journal.receipt)

    def test_journal_ambiguity_wins_over_secondary_clock_failure(self) -> None:
        activation, grant = _documents()

        class SecondaryFailClock(FakeClock):
            def __init__(self) -> None:
                super().__init__()
                self.fail = False

            def now_ms(self) -> int:
                if self.fail:
                    raise RuntimeError("PRIVATE_SECONDARY_CLOCK_FAILURE")
                return super().now_ms()

        append_clock = SecondaryFailClock()

        class FailingAppendJournal(FakeJournal):
            def append_event(self, execution_id, event, **kwargs):
                append_clock.fail = True
                super().append_event(execution_id, event, **kwargs)

        append_journal = FailingAppendJournal()
        append_journal.fail_next = True
        append_provider = FakeProvider(
            [ProviderTurnResult("must_not_run", _usage(), completed=True)]
        )
        append_kernel, _ = _kernel(
            append_provider,
            journal=append_journal,
            clock=append_clock,
        )
        with self.assertRaises(KernelError) as raised:
            append_kernel.execute(_request(activation, grant))
        self.assertEqual("journal_append_ambiguous", raised.exception.reason_code)
        self.assertEqual(["begin", "append"], append_journal.operations)
        self.assertEqual([], append_journal.events)
        self.assertIsNone(append_journal.receipt)
        self.assertEqual([], append_provider.requests)

        finalize_clock = SecondaryFailClock()

        class FailingFinalizeJournal(FakeJournal):
            def finalize(self, execution_id, receipt, event, **kwargs):
                self.operations.append("finalize")
                finalize_clock.fail = True
                raise ValueError("PRIVATE_FINALIZATION_FAILURE")

        finalize_journal = FailingFinalizeJournal()
        finalize_provider = FakeProvider(
            [ProviderTurnResult("must_not_return", _usage(), completed=True)]
        )
        finalize_kernel, _ = _kernel(
            finalize_provider,
            journal=finalize_journal,
            clock=finalize_clock,
        )
        with self.assertRaises(KernelError) as raised:
            finalize_kernel.execute(_request(activation, grant))
        self.assertEqual("journal_finalization_ambiguous", raised.exception.reason_code)
        self.assertEqual("finalize", finalize_journal.operations[-1])
        self.assertEqual(1, finalize_journal.operations.count("finalize"))
        self.assertIsNone(finalize_journal.receipt)
        self.assertEqual(1, len(finalize_provider.requests))

    def test_successful_journal_mutation_is_checked_before_a_failing_clock(self) -> None:
        activation, grant = _documents()

        class SecondaryFailClock(FakeClock):
            def __init__(self) -> None:
                super().__init__()
                self.fail = False

            def now_ms(self) -> int:
                if self.fail:
                    raise RuntimeError("PRIVATE_SECONDARY_CLOCK_FAILURE")
                return super().now_ms()

        append_clock = SecondaryFailClock()

        class MutatingAppendJournal(FakeJournal):
            def append_event(self, execution_id, event, **kwargs):
                super().append_event(execution_id, event, **kwargs)
                event["subject"]["id"] = "private_mutation"
                append_clock.fail = True

        append_journal = MutatingAppendJournal()
        append_provider = FakeProvider(
            [ProviderTurnResult("must_not_run", _usage(), completed=True)]
        )
        append_kernel, _ = _kernel(
            append_provider,
            journal=append_journal,
            clock=append_clock,
        )
        with self.assertRaises(KernelError) as raised:
            append_kernel.execute(_request(activation, grant))
        self.assertEqual("journal_corrupt", raised.exception.reason_code)
        self.assertEqual(["begin", "append"], append_journal.operations)
        self.assertEqual([], append_provider.requests)
        self.assertIsNone(append_journal.receipt)

        finalize_clock = SecondaryFailClock()

        class MutatingFinalizeJournal(FakeJournal):
            def finalize(self, execution_id, receipt, event, **kwargs):
                super().finalize(execution_id, receipt, event, **kwargs)
                receipt["outcome"] = "failed"
                event["subject"]["content_hash"] = "f" * 64
                finalize_clock.fail = True

        finalize_journal = MutatingFinalizeJournal()
        finalize_provider = FakeProvider(
            [ProviderTurnResult("must_not_return", _usage(), completed=True)]
        )
        finalize_kernel, _ = _kernel(
            finalize_provider,
            journal=finalize_journal,
            clock=finalize_clock,
        )
        with self.assertRaises(KernelError) as raised:
            finalize_kernel.execute(_request(activation, grant))
        self.assertEqual("journal_corrupt", raised.exception.reason_code)
        self.assertEqual("finalize", finalize_journal.operations[-1])
        self.assertEqual(1, finalize_journal.operations.count("finalize"))
        self.assertEqual(1, len(finalize_provider.requests))

    def test_journal_append_mutation_cannot_hide_behind_overloaded_equality(self) -> None:
        activation, grant = _documents()

        class AlwaysEqual:
            def __eq__(self, _other: object) -> bool:
                return True

        class HostileEqualMapping(Mapping):
            def __init__(self) -> None:
                self.items_calls = 0

            def __getitem__(self, _key: object) -> object:
                raise BrokerError("private_secret")

            def __iter__(self) -> Iterator[str]:
                raise BrokerError("private_secret")

            def __len__(self) -> int:
                return 2

            def __eq__(self, _other: object) -> bool:
                return True

            def items(self):
                self.items_calls += 1
                raise BrokerError("private_secret")

        for replacement in (AlwaysEqual(), HostileEqualMapping()):
            with self.subTest(replacement=type(replacement).__name__):

                class AliasingMutatingAppendJournal(FakeJournal):
                    def __init__(self, active_replacement: object) -> None:
                        super().__init__()
                        self.active_replacement = active_replacement

                    def append_event(self, execution_id, event, **kwargs):
                        if kwargs["expected_sequence"] != len(self.events):
                            raise ValueError("private sequence mismatch")
                        self.events.append(event)
                        if kwargs["expected_sequence"] == 0:
                            event["subject"] = self.active_replacement

                provider = FakeProvider(
                    [ProviderTurnResult("must_not_run", _usage(), completed=True)]
                )
                kernel, journal = _kernel(
                    provider,
                    journal=AliasingMutatingAppendJournal(replacement),
                )
                with self.assertRaises(KernelError) as raised:
                    kernel.execute(_request(activation, grant))
                self.assertEqual("journal_corrupt", raised.exception.reason_code)
                self.assertEqual([], provider.requests)
                self.assertNotIn("private_secret", str(raised.exception))
                self.assertIs(journal.events[0]["subject"], replacement)
                if isinstance(replacement, HostileEqualMapping):
                    self.assertEqual(0, replacement.items_calls)

    def test_journal_finalize_mutation_cannot_hide_behind_overloaded_equality(self) -> None:
        activation, grant = _documents()

        class AlwaysEqual:
            def __eq__(self, _other: object) -> bool:
                return True

        class HostileEqualMapping(Mapping):
            def __init__(self) -> None:
                self.items_calls = 0

            def __getitem__(self, _key: object) -> object:
                raise BrokerError("private_secret")

            def __iter__(self) -> Iterator[str]:
                raise BrokerError("private_secret")

            def __len__(self) -> int:
                return 2

            def __eq__(self, _other: object) -> bool:
                return True

            def items(self):
                self.items_calls += 1
                raise BrokerError("private_secret")

        for replacement in (AlwaysEqual(), HostileEqualMapping()):
            with self.subTest(replacement=type(replacement).__name__):

                class AliasingMutatingFinalizeJournal(FakeJournal):
                    def __init__(self, active_replacement: object) -> None:
                        super().__init__()
                        self.active_replacement = active_replacement

                    def finalize(self, execution_id, receipt, event, **kwargs):
                        if self.receipt is not None:
                            raise ValueError("private duplicate receipt")
                        self.receipt = receipt
                        self.events.append(event)
                        receipt["runtime_binding"] = self.active_replacement
                        event["subject"] = self.active_replacement

                provider = FakeProvider(
                    [ProviderTurnResult("must_not_return", _usage(), completed=True)]
                )
                kernel, journal = _kernel(
                    provider,
                    journal=AliasingMutatingFinalizeJournal(replacement),
                )
                with self.assertRaises(KernelError) as raised:
                    kernel.execute(_request(activation, grant))
                self.assertEqual("journal_corrupt", raised.exception.reason_code)
                self.assertEqual(1, len(provider.requests))
                self.assertNotIn("private_secret", str(raised.exception))
                self.assertIs(journal.receipt["runtime_binding"], replacement)
                self.assertIs(journal.events[-1]["subject"], replacement)
                if isinstance(replacement, HostileEqualMapping):
                    self.assertEqual(0, replacement.items_calls)

        class MutatingAppendJournal(FakeJournal):
            def append_event(self, execution_id, event, **kwargs):
                event["subject"]["id"] = "private_mutation"
                super().append_event(execution_id, event, **kwargs)

        kernel, _ = _kernel(
            FakeProvider([ProviderTurnResult("x", _usage(), completed=True)]),
            journal=MutatingAppendJournal(),
        )
        with self.assertRaises(KernelError) as raised:
            kernel.execute(_request(activation, grant))
        self.assertEqual("journal_corrupt", raised.exception.reason_code)

        class MutatingFinalizeJournal(FakeJournal):
            def finalize(self, execution_id, receipt, event, **kwargs):
                super().finalize(execution_id, receipt, event, **kwargs)
                receipt["outcome"] = "failed"
                receipt["failure_codes"] = ["private_secret"]
                event["subject"]["content_hash"] = "f" * 64

        kernel, journal = _kernel(
            FakeProvider([ProviderTurnResult("x", _usage(), completed=True)]),
            journal=MutatingFinalizeJournal(),
        )
        with self.assertRaises(KernelError) as raised:
            kernel.execute(_request(activation, grant))
        self.assertEqual("journal_corrupt", raised.exception.reason_code)
        self.assertIsNotNone(journal.receipt)

        class FailingFinalizeJournal(FakeJournal):
            def finalize(self, execution_id, receipt, event, **kwargs):
                raise ValueError("PRIVATE_ATOMIC_FAILURE")

        kernel, journal = _kernel(
            FakeProvider([ProviderTurnResult("x", _usage(), completed=True)]),
            journal=FailingFinalizeJournal(),
        )
        with self.assertRaises(KernelError) as raised:
            kernel.execute(_request(activation, grant))
        self.assertEqual("journal_finalization_ambiguous", raised.exception.reason_code)
        self.assertNotIn(
            "PRIVATE_ATOMIC_FAILURE",
            "".join(traceback.format_exception_only(raised.exception)),
        )
        self.assertIsNone(journal.receipt)

        token = FakeCancellation()

        class CancellingFinalizeJournal(FakeJournal):
            def finalize(self, execution_id, receipt, event, **kwargs):
                token.cancelled = True
                raise ValueError("PRIVATE_CANCEL_DURING_FINALIZE")

        kernel, journal = _kernel(
            FakeProvider([ProviderTurnResult("x", _usage(), completed=True)]),
            journal=CancellingFinalizeJournal(),
            cancellation=token,
        )
        with self.assertRaises(KernelError) as raised:
            kernel.execute(_request(activation, grant))
        self.assertEqual("journal_finalization_ambiguous", raised.exception.reason_code)
        self.assertNotIn(
            "PRIVATE_CANCEL_DURING_FINALIZE",
            "".join(traceback.format_exception_only(raised.exception)),
        )
        self.assertIsNone(journal.receipt)

    def test_journal_never_receives_kernel_owned_records_and_late_mutation_is_isolated(
        self,
    ) -> None:
        activation, grant = _documents()

        class AliasingJournal(FakeJournal):
            def append_event(self, execution_id, event, **kwargs):
                if kwargs["expected_sequence"] != len(self.events):
                    raise ValueError("private sequence mismatch")
                self.events.append(event)

            def finalize(self, execution_id, receipt, event, **kwargs):
                self.receipt = receipt
                self.events.append(event)

        journal = AliasingJournal()
        result = _kernel(
            FakeProvider([ProviderTurnResult("x", _usage(), completed=True)]), journal=journal
        )[0].execute(_request(activation, grant))
        expected_public = json.dumps(
            {"events": result.events, "receipt": result.receipt}, sort_keys=True
        )
        journal.events[0]["subject"]["id"] = "late_private_mutation"
        journal.receipt["failure_codes"] = ["late_private_mutation"]
        self.assertEqual(
            expected_public,
            json.dumps({"events": result.events, "receipt": result.receipt}, sort_keys=True),
        )
        validate_agent_harness_documents(activation, grant, result.events, result.receipt)

    def test_same_kernel_reentrancy_is_rejected_and_adapter_cannot_control_ids(self) -> None:
        activation, grant = _documents()
        holder = {}

        def nested(_request):
            with self.assertRaises(KernelError) as raised:
                holder["kernel"].execute(_request_factory())
            self.assertEqual("execution_reentrant", raised.exception.reason_code)
            return ProviderTurnResult("ok", _usage(), completed=True)

        def _request_factory():
            return _request(activation, grant)

        provider = FakeProvider([nested])
        kernel, _ = _kernel(provider)
        holder["kernel"] = kernel
        result = kernel.execute(_request_factory())
        self.assertEqual("receipt_kernel_01", result.receipt["receipt_id"])
        self.assertTrue(
            all(event["event_id"].startswith("kernel_event_") for event in result.events)
        )

    def test_shared_broker_activation_conflict_is_bounded_and_does_not_release_owner(self) -> None:
        activation, grant = _documents()
        broker = CapabilityBroker()
        token = FakeCancellation()
        clock = FakeClock()
        second_provider = FakeProvider([])
        second = AgentExecutionKernel(
            provider=second_provider,
            broker=broker,
            journal=FakeJournal(),
            clock=clock,
            cancellation=token,
        )

        def nested(_request):
            with self.assertRaises(KernelError) as raised:
                second.execute(_request_factory())
            self.assertEqual("execution_reentrant", raised.exception.reason_code)
            return ProviderTurnResult("owner_ok", _usage(), completed=True)

        def _request_factory():
            return _request(activation, grant)

        first = AgentExecutionKernel(
            provider=FakeProvider([nested]),
            broker=broker,
            journal=FakeJournal(),
            clock=clock,
            cancellation=token,
        )
        self.assertEqual("succeeded", first.execute(_request_factory()).outcome)
        second_provider.script.append(ProviderTurnResult("later_ok", _usage(), completed=True))
        second.journal = FakeJournal()
        self.assertEqual("succeeded", second.execute(_request_factory()).outcome)

    def test_deterministic_fresh_runs_are_byte_identical_without_replay_claim(self) -> None:
        activation, grant = _documents()
        outputs = []
        for _ in range(2):
            provider = FakeProvider([ProviderTurnResult("same", _usage(), completed=True)])
            result = _kernel(provider, clock=FakeClock())[0].execute(_request(activation, grant))
            outputs.append(
                json.dumps(
                    {"events": result.events, "receipt": result.receipt},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            self.assertEqual("not_claimed", result.receipt["replay_support"])
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(
            BASELINE,
            {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in FIXTURES.glob("*.json")
            },
        )


if __name__ == "__main__":
    unittest.main()
