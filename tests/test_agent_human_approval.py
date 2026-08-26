from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace

from tests.agent_harness_fakes import (
    FakeArtifactPort,
    FakeCancellation,
    FakeClock,
    FakeJournal,
    FakeMemoryPort,
    FakeProvider,
    FakeTool,
)
from tests.test_agent_execution_kernel import (
    _documents,
    _ProviderAutoApprovingKernel,
    _request,
    _usage,
)
from worldforge.agent_harness import (
    AgentEventLog,
    AgentExecutionCoordinator,
    AgentExecutionKernel,
    OneShotProviderSupervisor,
)
from worldforge.agent_harness.approvals import (
    ApprovalError,
    ExecutionApprovalDecision,
    ExecutionApprovalReview,
    InMemoryHumanApprovalAuthority,
)
from worldforge.agent_harness.capability_broker import CapabilityBroker
from worldforge.agent_harness.kernel import KernelError
from worldforge.agent_harness.ports import (
    ArtifactProposal,
    MemoryProposal,
    ProviderToolDefinition,
    ProviderToolSummary,
    ProviderTurnRequest,
    ProviderTurnResult,
    ToolCall,
    ToolResult,
)
from worldforge.agent_harness.worker_protocol import (
    WorkerProtocolError,
    build_request_frame,
    build_result_frame,
    parse_request_frame,
    parse_result_frame,
)


def _review(**changes: object) -> ExecutionApprovalReview:
    values: dict[str, object] = {
        "approval_id": "approval_execution_01",
        "execution_id": "execution_01",
        "activation_hash": "a" * 64,
        "grant_hash": "b" * 64,
        "private_input_hash": "c" * 64,
        "runtime_id": "worldforge_conformance_provider",
        "runtime_revision": 1,
        "runtime_content_hash": "d" * 64,
        "max_turns": 4,
        "max_tool_calls": 8,
        "max_total_tokens": 100,
        "max_cost_minor_units": 25,
        "currency": "USD",
        "max_duration_ms": 5_000,
        "deadline_ms": 10_000,
        "tool_candidates": (
            ("source.read", "e" * 64),
            ("world.validate", "f" * 64),
        ),
    }
    values.update(changes)
    return ExecutionApprovalReview.create(**values)


def _decision(
    review: ExecutionApprovalReview,
    **changes: object,
) -> ExecutionApprovalDecision:
    values: dict[str, object] = {
        "review": review,
        "reviewer_id": "reviewer_local_01",
        "outcome": "approved",
        "approved_tool_ids": ("source.read",),
        "expires_at_ms": 2_000,
    }
    values.update(changes)
    return ExecutionApprovalDecision.create(**values)


class HumanApprovalAuthorityTests(unittest.TestCase):
    def test_atomic_snapshot_is_detached_and_preserves_exact_authority_state(self) -> None:
        authority = InMemoryHumanApprovalAuthority()
        review = _review()

        missing = authority.snapshot(review)
        self.assertEqual("missing", missing.state)
        self.assertIsNone(missing.prepared_review)
        self.assertIsNone(missing.current_decision)
        self.assertEqual(0, missing.generation)
        self.assertEqual(review.content_hash, missing.review_hash)
        self.assertIsNone(missing.decision_hash)

        authority.prepare(review, expected_generation=0)
        prepared = authority.snapshot(review)
        self.assertEqual("prepared", prepared.state)
        self.assertEqual(review, prepared.prepared_review)
        self.assertEqual(0, prepared.generation)

        decision = _decision(review)
        authority.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        approved = authority.snapshot(review)
        self.assertEqual("approved", approved.state)
        self.assertEqual(decision, approved.current_decision)
        self.assertEqual(1, approved.generation)
        self.assertEqual(decision.content_hash, approved.decision_hash)

        object.__setattr__(approved.prepared_review, "grant_hash", "0" * 64)
        object.__setattr__(approved.current_decision, "outcome", "denied")
        fresh = authority.snapshot(review)
        self.assertEqual(review, fresh.prepared_review)
        self.assertEqual(decision, fresh.current_decision)

        authority.revoke(
            review.approval_id,
            expected_generation=1,
            expected_decision_hash=decision.content_hash,
        )
        revoked = authority.snapshot(review)
        self.assertEqual("revoked", revoked.state)
        self.assertEqual(2, revoked.generation)

    def test_prepare_decide_and_revoke_are_exact_idempotent_cas(self) -> None:
        authority = InMemoryHumanApprovalAuthority()
        review = _review()
        decision = _decision(review)

        self.assertEqual(review, authority.prepare(review, expected_generation=0))
        self.assertEqual(review, authority.prepare(review, expected_generation=0))
        self.assertEqual(
            decision,
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            ),
        )
        self.assertEqual(
            decision,
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            ),
        )
        approved = authority.check(review, now_ms=1_999)
        self.assertEqual(("source.read",), approved.approved_tool_ids)
        self.assertEqual(decision.content_hash, approved.decision_hash)

        authority.revoke(
            review.approval_id,
            expected_generation=1,
            expected_decision_hash=decision.content_hash,
        )
        authority.revoke(
            review.approval_id,
            expected_generation=1,
            expected_decision_hash=decision.content_hash,
        )
        with self.assertRaisesRegex(ApprovalError, "approval_revoked"):
            authority.check(review, now_ms=1_999)

        changed = _review(grant_hash="0" * 64)
        with self.assertRaisesRegex(ApprovalError, "approval_stale"):
            authority.prepare(changed, expected_generation=0)

    def test_approved_subset_expiry_deny_and_missing_default_deny(self) -> None:
        review = _review()
        with self.assertRaisesRegex(ApprovalError, "approval_required"):
            InMemoryHumanApprovalAuthority().check(review, now_ms=0)

        expired = InMemoryHumanApprovalAuthority()
        expired.prepare(review, expected_generation=0)
        decision = _decision(review, expires_at_ms=2_000)
        expired.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        with self.assertRaisesRegex(ApprovalError, "approval_expired"):
            expired.check(review, now_ms=2_000)

        denied = InMemoryHumanApprovalAuthority()
        denied.prepare(review, expected_generation=0)
        denial = _decision(
            review,
            outcome="denied",
            approved_tool_ids=(),
            expires_at_ms=None,
        )
        denied.decide(
            denial,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        with self.assertRaisesRegex(ApprovalError, "approval_denied"):
            denied.check(review, now_ms=0)

        with self.assertRaisesRegex(ApprovalError, "approval_decision_invalid"):
            _decision(review, approved_tool_ids=("unregistered.tool",))

    def test_exact_builtin_validation_alias_isolation_and_concurrent_decision_cas(self) -> None:
        candidate_list = [("source.read", "e" * 64)]
        with self.assertRaisesRegex(ApprovalError, "approval_review_invalid"):
            _review(tool_candidates=candidate_list)

        review = _review(tool_candidates=tuple(candidate_list))
        candidate_list[0] = ("forged.tool", "0" * 64)

        isolated = InMemoryHumanApprovalAuthority()
        returned_review = isolated.prepare(review, expected_generation=0)
        object.__setattr__(returned_review, "grant_hash", "0" * 64)
        self.assertEqual(review, isolated.prepare(review, expected_generation=0))
        decision = _decision(review)
        returned_decision = isolated.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        object.__setattr__(returned_decision, "outcome", "denied")
        self.assertEqual(
            ("source.read",),
            isolated.check(review, now_ms=1).approved_tool_ids,
        )

        authority = InMemoryHumanApprovalAuthority()
        authority.prepare(review, expected_generation=0)
        decisions = (
            _decision(review, reviewer_id="reviewer_first"),
            _decision(review, reviewer_id="reviewer_second"),
        )
        barrier = threading.Barrier(3)
        outcomes: list[str] = []

        def decide(value: ExecutionApprovalDecision) -> None:
            barrier.wait()
            try:
                authority.decide(
                    value,
                    expected_generation=0,
                    expected_review_hash=review.content_hash,
                )
            except ApprovalError as exc:
                outcomes.append(exc.reason_code)
            else:
                outcomes.append("approved")

        threads = [threading.Thread(target=decide, args=(value,)) for value in decisions]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=2)
        self.assertCountEqual(["approved", "approval_stale"], outcomes)
        self.assertEqual(("source.read",), authority.check(review, now_ms=1).approved_tool_ids)

        for changes in (
            {"max_turns": 65},
            {"max_tool_calls": 129},
            {"runtime_revision": True},
            {"deadline_ms": -1},
            {"tool_candidates": (("aa." + "bb." * 400 + "cc", "e" * 64),)},
        ):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ApprovalError, "approval_review_invalid"):
                    _review(**changes)

        forged = replace(review, private_input_hash="0" * 64)
        with self.assertRaisesRegex(ApprovalError, "approval_review_invalid"):
            authority.fingerprint_hashes(forged)

        forged_generation = replace(review)
        object.__setattr__(forged_generation, "generation", False)
        with self.assertRaisesRegex(ApprovalError, "approval_review_invalid"):
            authority.fingerprint_hashes(forged_generation)

        class TextAlias(str):
            pass

        forged_decision = _decision(review)
        object.__setattr__(forged_decision, "outcome", TextAlias("approved"))
        rejecting_authority = InMemoryHumanApprovalAuthority()
        rejecting_authority.prepare(review, expected_generation=0)
        with self.assertRaisesRegex(ApprovalError, "approval_decision_invalid"):
            rejecting_authority.decide(
                forged_decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )


class ToolDescriptorSnapshotTests(unittest.TestCase):
    def test_broker_snapshots_exact_bounded_descriptors_and_catalog_hash(self) -> None:
        schema = {
            "type": "object",
            "properties": {"path": {"type": "string", "maxLength": 256}},
            "required": ["path"],
            "additionalProperties": False,
        }
        tool = FakeTool(
            "source.read",
            "tool.invoke",
            ToolResult("ok"),
            summary="Read one project-owned source document.",
            input_schema=schema,
        )
        broker = CapabilityBroker(tools=(tool,))
        catalog = broker.eligible_tool_catalog(
            effective_capabilities=frozenset({"tool.invoke"}),
            effective_tools=frozenset({"source.read"}),
        )
        self.assertRegex(catalog.catalog_hash, r"^[0-9a-f]{64}$")
        self.assertEqual(("source.read",), tuple(item.tool_id for item in catalog.descriptors))
        descriptor = catalog.descriptors[0]
        original_definition = descriptor.definition_document()
        self.assertEqual(schema, original_definition["input_schema"])
        self.assertEqual(
            {
                "tool_id": "source.read",
                "summary": "Read one project-owned source document.",
                "descriptor_hash": descriptor.descriptor_hash,
            },
            descriptor.summary_document(),
        )

        schema["required"].append("MUTATED")
        tool.tool_id = "forged.tool"
        tool.required_capability_id = "memory.read"
        tool.summary = "MUTATED"
        tool.input_schema = {"type": "null"}
        self.assertEqual(original_definition, descriptor.definition_document())
        self.assertEqual(
            catalog,
            broker.eligible_tool_catalog(
                effective_capabilities=frozenset({"tool.invoke"}),
                effective_tools=frozenset({"source.read"}),
            ),
        )

        approved = catalog.approved(("source.read",))
        object.__setattr__(approved.descriptors[0], "summary", "FORGED APPROVED")
        self.assertEqual(original_definition, catalog.descriptors[0].definition_document())

        object.__setattr__(catalog.descriptors[0], "summary", "FORGED CATALOG")
        fresh = broker.eligible_tool_catalog(
            effective_capabilities=frozenset({"tool.invoke"}),
            effective_tools=frozenset({"source.read"}),
        )
        self.assertEqual(original_definition, fresh.descriptors[0].definition_document())

    def test_descriptor_validation_rejects_hostile_types_cycles_and_bounds(self) -> None:
        cycle: dict[str, object] = {}
        cycle["self"] = cycle
        deep_schema: dict[str, object] = {}
        cursor = deep_schema
        for _index in range(33):
            nested: dict[str, object] = {}
            cursor["nested"] = nested
            cursor = nested
        cases = (
            {"summary": 1, "input_schema": {}},
            {"summary": "ok", "input_schema": cycle},
            {"summary": "ok", "input_schema": deep_schema},
            {"summary": "x" * 2_000, "input_schema": {}},
            {"summary": "ok", "input_schema": {"type": object()}},
            {"summary": "ok", "input_schema": []},
        )
        for case in cases:
            with self.subTest(case=type(case["input_schema"]).__name__):
                tool = FakeTool(
                    "source.read",
                    "tool.invoke",
                    ToolResult("unused"),
                    summary=case["summary"],
                    input_schema=case["input_schema"],
                )
                with self.assertRaisesRegex(ValueError, "invalid tool adapter"):
                    CapabilityBroker(tools=(tool,))

        valid = FakeTool(
            "source.read",
            "tool.invoke",
            ToolResult("ok"),
            summary="Read source.",
            input_schema={"type": "object"},
        )
        broker = CapabilityBroker(tools=(valid,))
        hidden = broker.eligible_tool_catalog(
            effective_capabilities=frozenset({"tool.invoke"}),
            effective_tools=frozenset({"other.tool"}),
        )
        incompatible = broker.eligible_tool_catalog(
            effective_capabilities=frozenset({"project.read"}),
            effective_tools=frozenset({"source.read"}),
        )
        self.assertEqual((), hidden.descriptors)
        self.assertEqual(hidden, incompatible)

    def test_tool_adapters_must_supply_exact_summary_and_schema_properties(self) -> None:
        class BaseAdapter:
            tool_id = "source.read"
            required_capability_id = "tool.invoke"

            def invoke(self, _call):
                return ToolResult("unused")

        class MissingSummary(BaseAdapter):
            input_schema = {"type": "object"}

        class MissingSchema(BaseAdapter):
            summary = "Read source."

        class ExplodingSummary(BaseAdapter):
            input_schema = {"type": "object"}

            @property
            def summary(self):
                raise RuntimeError("must not escape")

        class ExplodingSchema(BaseAdapter):
            summary = "Read source."

            @property
            def input_schema(self):
                raise RuntimeError("must not escape")

        class TextAlias(str):
            pass

        class MappingAlias(dict):
            pass

        hostile = (
            MissingSummary(),
            MissingSchema(),
            ExplodingSummary(),
            ExplodingSchema(),
            FakeTool(
                "source.read",
                "tool.invoke",
                ToolResult("unused"),
                summary=TextAlias("Read source."),
                input_schema={"type": "object"},
            ),
            FakeTool(
                "source.read",
                "tool.invoke",
                ToolResult("unused"),
                summary="Read source.",
                input_schema=MappingAlias(type="object"),
            ),
        )
        for adapter in hostile:
            with self.subTest(adapter=type(adapter).__name__):
                with self.assertRaisesRegex(ValueError, "invalid tool adapter"):
                    CapabilityBroker(tools=(adapter,))


def _approval_kernel(
    provider: FakeProvider,
    tools: tuple[FakeTool, ...],
    *,
    authority: InMemoryHumanApprovalAuthority | None = None,
    journal: object | None = None,
    clock: FakeClock | None = None,
    cancellation: FakeCancellation | None = None,
) -> tuple[AgentExecutionKernel, InMemoryHumanApprovalAuthority]:
    authority = authority or InMemoryHumanApprovalAuthority()
    kernel = _ProviderAutoApprovingKernel(
        provider=provider,
        broker=CapabilityBroker(tools=tools),
        journal=journal or FakeJournal(),
        clock=clock or FakeClock(),
        cancellation=cancellation or FakeCancellation(),
        approval_authority=authority,
    )
    return kernel, authority


def _approve(
    kernel: AgentExecutionKernel,
    authority: InMemoryHumanApprovalAuthority,
    request,
    *,
    approved_tool_ids: tuple[str, ...],
    expires_at_ms: int = 2_000,
) -> tuple[ExecutionApprovalReview, ExecutionApprovalDecision]:
    review = kernel.prepare_approval_review(request)
    decision = ExecutionApprovalDecision.create(
        review=review,
        reviewer_id="reviewer_local_01",
        outcome="approved",
        approved_tool_ids=approved_tool_ids,
        expires_at_ms=expires_at_ms,
    )
    authority.decide(
        decision,
        expected_generation=0,
        expected_review_hash=review.content_hash,
    )
    return review, decision


class KernelApprovalAndProgressiveExposureTests(unittest.TestCase):
    def test_decision_arriving_inside_begin_is_not_adopted_by_that_execution(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
        provider = FakeProvider([ProviderTurnResult("must not run", _usage(), completed=True)])
        authority = InMemoryHumanApprovalAuthority()
        holder: dict[str, object] = {}

        class DecidingBeginJournal(AgentEventLog):
            def begin_execution(self, *args, **kwargs):
                begun = super().begin_execution(*args, **kwargs)
                if begun:
                    authority.decide(
                        holder["decision"],
                        expected_generation=0,
                        expected_review_hash=holder["review"].content_hash,
                    )
                return begun

        with tempfile.TemporaryDirectory() as temporary, DecidingBeginJournal(temporary) as journal:
            kernel = _ProviderAutoApprovingKernel(
                provider=provider,
                broker=CapabilityBroker(tools=(tool,)),
                journal=journal,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                approval_authority=authority,
            )
            review = kernel.prepare_approval_review(request)
            holder["review"] = review
            holder["decision"] = _decision(review)

            result = kernel.execute(request)

            self.assertEqual("failed", result.outcome)
            self.assertEqual(["tool_not_authorized"], result.receipt["failure_codes"])
            self.assertEqual([], provider.requests)
            self.assertEqual([], tool.calls)
            replayed = journal.replay_records("execution_01")
            self.assertEqual("terminal", replayed.state)
            self.assertIsNotNone(replayed.receipt_bytes)

            retry_provider = FakeProvider([])
            retry_kernel = _ProviderAutoApprovingKernel(
                provider=retry_provider,
                broker=CapabilityBroker(tools=(tool,)),
                journal=journal,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                approval_authority=authority,
            )
            with self.assertRaisesRegex(KernelError, "journal_begin_ambiguous"):
                retry_kernel.execute(request)
            self.assertEqual([], retry_provider.requests)

    def test_concurrent_decision_during_begin_remains_outside_the_execution_snapshot(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        provider = FakeProvider([ProviderTurnResult("must not run", _usage(), completed=True)])
        authority = InMemoryHumanApprovalAuthority()
        begin_entered = threading.Event()
        decision_finished = threading.Event()

        class BlockingBeginJournal(FakeJournal):
            def begin_execution(self, *args, **kwargs):
                begun = super().begin_execution(*args, **kwargs)
                begin_entered.set()
                if not decision_finished.wait(2):
                    raise RuntimeError("decision thread did not finish")
                return begun

        journal = BlockingBeginJournal()
        kernel = _ProviderAutoApprovingKernel(
            provider=provider,
            broker=CapabilityBroker(
                tools=(FakeTool("source.read", "tool.invoke", ToolResult("unused")),)
            ),
            journal=journal,
            clock=FakeClock(),
            cancellation=FakeCancellation(),
            approval_authority=authority,
        )
        review = kernel.prepare_approval_review(request)
        decision = _decision(review)

        def decide() -> None:
            begin_entered.wait(2)
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            decision_finished.set()

        thread = threading.Thread(target=decide)
        thread.start()
        try:
            result = kernel.execute(request)
        finally:
            thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(["tool_not_authorized"], result.receipt["failure_codes"])
        self.assertEqual([], provider.requests)
        self.assertIsNotNone(journal.receipt)

    def test_approved_tools_are_summarized_then_exposed_only_on_next_turn(self) -> None:
        activation, grant = _documents(
            capabilities=["tool.invoke"],
            tools=["source.read", "world.validate"],
        )
        source = FakeTool(
            "source.read",
            "tool.invoke",
            ToolResult({"document": "PRIVATE_TOOL_OUTPUT"}),
            summary="Read one source document.",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        )
        hidden = FakeTool(
            "world.validate",
            "tool.invoke",
            ToolResult("must not run"),
            summary="Validate one world.",
            input_schema={"type": "object"},
        )
        provider = FakeProvider(
            [
                ProviderTurnResult(
                    "request schema",
                    _usage(),
                    tool_exposure_requests=("source.read",),
                    completed=False,
                ),
                ProviderTurnResult(
                    "complete",
                    _usage(),
                    tool_calls=(ToolCall("source.read", {"path": "PRIVATE_PATH"}),),
                    completed=True,
                ),
            ]
        )
        kernel, authority = _approval_kernel(provider, (source, hidden))
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        review, _decision_value = _approve(
            kernel,
            authority,
            request,
            approved_tool_ids=("source.read",),
        )

        result = kernel.execute(request)

        self.assertEqual("succeeded", result.outcome)
        self.assertEqual(2, len(provider.requests))
        initial, following = provider.requests
        self.assertEqual(("source.read",), tuple(item.tool_id for item in initial.tool_summaries))
        self.assertFalse(hasattr(initial.tool_summaries[0], "input_schema"))
        self.assertEqual((), initial.exposed_tools)
        self.assertEqual(("source.read",), tuple(item.tool_id for item in following.tool_summaries))
        self.assertEqual(("source.read",), tuple(item.tool_id for item in following.exposed_tools))
        self.assertEqual(
            {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
            following.exposed_tools[0].input_schema,
        )
        self.assertEqual(1, len(source.calls))
        self.assertEqual([], hidden.calls)
        private_documents = json.dumps(
            [
                [item.summary for item in initial.tool_summaries],
                [item.input_schema for item in following.exposed_tools],
            ]
        )
        self.assertNotIn(review.approval_id, private_documents)
        self.assertNotIn("reviewer_local_01", private_documents)

    def test_default_deny_subset_nonoracle_and_same_turn_escalation_have_no_effects(self) -> None:
        activation, grant = _documents(
            capabilities=["tool.invoke"],
            tools=["source.read", "world.validate"],
        )
        source = FakeTool("source.read", "tool.invoke", ToolResult("source"))
        world = FakeTool("world.validate", "tool.invoke", ToolResult("world"))

        missing_provider = FakeProvider([])
        missing = _ProviderAutoApprovingKernel(
            provider=missing_provider,
            broker=CapabilityBroker(tools=(source, world)),
            journal=FakeJournal(),
            clock=FakeClock(),
            cancellation=FakeCancellation(),
        )
        missing_result = missing.execute(_request(activation, grant))
        self.assertEqual(["tool_not_authorized"], missing_result.receipt["failure_codes"])
        self.assertEqual([], missing_provider.requests)

        provider = FakeProvider(
            [
                ProviderTurnResult(
                    "escalate",
                    _usage(),
                    tool_calls=(ToolCall("source.read", {}),),
                    tool_exposure_requests=("source.read",),
                    completed=True,
                )
            ]
        )
        kernel, authority = _approval_kernel(provider, (source, world))
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        _approve(kernel, authority, request, approved_tool_ids=("source.read",))
        result = kernel.execute(request)
        self.assertEqual(["provider_result_invalid"], result.receipt["failure_codes"])
        self.assertEqual([], result.receipt["tool_invocations"])
        self.assertEqual([], source.calls)
        self.assertEqual([], world.calls)

        already_exposed_provider = FakeProvider(
            [
                ProviderTurnResult(
                    "expose",
                    _usage(),
                    tool_exposure_requests=("source.read",),
                    completed=False,
                ),
                ProviderTurnResult(
                    "re-request and invoke",
                    _usage(),
                    tool_calls=(ToolCall("source.read", {}),),
                    tool_exposure_requests=("source.read",),
                    completed=True,
                ),
            ]
        )
        already_kernel, already_authority = _approval_kernel(
            already_exposed_provider,
            (source, world),
        )
        already_request = replace(
            _request(activation, grant),
            approval_id="approval_execution_03",
        )
        _approve(
            already_kernel,
            already_authority,
            already_request,
            approved_tool_ids=("source.read",),
        )
        already_result = already_kernel.execute(already_request)
        self.assertEqual(["provider_result_invalid"], already_result.receipt["failure_codes"])
        self.assertEqual([], already_result.receipt["tool_invocations"])
        self.assertEqual([], source.calls)
        self.assertEqual([], world.calls)

    def test_exposed_definitions_preserve_ordered_unique_request_history(self) -> None:
        activation, grant = _documents(
            capabilities=["tool.invoke"],
            tools=["source.read", "world.validate"],
        )
        source = FakeTool("source.read", "tool.invoke", ToolResult("source"))
        world = FakeTool("world.validate", "tool.invoke", ToolResult("world"))

        same_turn_seen: list[tuple[str, ...]] = []

        def capture_same_turn(turn_request):
            same_turn_seen.append(tuple(item.tool_id for item in turn_request.exposed_tools))
            return ProviderTurnResult("done", _usage(), completed=True)

        same_turn_provider = FakeProvider(
            [
                ProviderTurnResult(
                    "request reversed catalog order",
                    _usage(),
                    tool_exposure_requests=("world.validate", "source.read"),
                    completed=False,
                ),
                capture_same_turn,
            ]
        )
        same_kernel, same_authority = _approval_kernel(
            same_turn_provider,
            (source, world),
        )
        same_request = replace(
            _request(activation, grant),
            approval_id="approval_exposure_order_01",
        )
        _approve(
            same_kernel,
            same_authority,
            same_request,
            approved_tool_ids=("source.read", "world.validate"),
        )
        self.assertEqual("succeeded", same_kernel.execute(same_request).outcome)
        self.assertEqual([("world.validate", "source.read")], same_turn_seen)

        cross_turn_seen: list[tuple[str, ...]] = []

        def request_second(turn_request):
            cross_turn_seen.append(tuple(item.tool_id for item in turn_request.exposed_tools))
            return ProviderTurnResult(
                "request source",
                _usage(),
                tool_exposure_requests=("source.read",),
                completed=False,
            )

        def capture_cross_turn(turn_request):
            cross_turn_seen.append(tuple(item.tool_id for item in turn_request.exposed_tools))
            return ProviderTurnResult("done", _usage(), completed=True)

        cross_provider = FakeProvider(
            [
                ProviderTurnResult(
                    "request world",
                    _usage(),
                    tool_exposure_requests=("world.validate",),
                    completed=False,
                ),
                request_second,
                capture_cross_turn,
            ]
        )
        cross_kernel, cross_authority = _approval_kernel(cross_provider, (source, world))
        cross_request = replace(
            _request(activation, grant),
            approval_id="approval_exposure_order_02",
        )
        _approve(
            cross_kernel,
            cross_authority,
            cross_request,
            approved_tool_ids=("source.read", "world.validate"),
        )
        self.assertEqual("succeeded", cross_kernel.execute(cross_request).outcome)
        self.assertEqual(
            [("world.validate",), ("world.validate", "source.read")],
            cross_turn_seen,
        )

        hidden_provider = FakeProvider(
            [
                ProviderTurnResult(
                    "hidden",
                    _usage(),
                    tool_exposure_requests=("world.validate",),
                    completed=True,
                )
            ]
        )
        hidden_kernel, hidden_authority = _approval_kernel(
            hidden_provider,
            (source, world),
        )
        hidden_request = replace(
            _request(activation, grant),
            approval_id="approval_execution_02",
        )
        _approve(
            hidden_kernel,
            hidden_authority,
            hidden_request,
            approved_tool_ids=("source.read",),
        )
        hidden_result = hidden_kernel.execute(hidden_request)
        self.assertEqual(["tool_not_authorized"], hidden_result.receipt["failure_codes"])
        self.assertEqual([], hidden_result.receipt["tool_invocations"])
        self.assertEqual([], source.calls)
        self.assertEqual([], world.calls)

    def test_exact_terminal_duplicate_is_evidence_only_after_revoke(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        tool = FakeTool("source.read", "tool.invoke", ToolResult("ok"))
        provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            kernel, authority = _approval_kernel(provider, (tool,), journal=log)
            review, decision = _approve(
                kernel,
                authority,
                request,
                approved_tool_ids=("source.read",),
            )
            coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=log)
            first = coordinator.execute(request)
            self.assertEqual("executed", first.disposition)
            authority.revoke(
                review.approval_id,
                expected_generation=1,
                expected_decision_hash=decision.content_hash,
            )
            second = coordinator.execute(request)
            self.assertEqual("existing_terminal", second.disposition)
            self.assertEqual(1, len(provider.requests))
            self.assertEqual([], tool.calls)

    def test_unused_approval_identifier_and_authority_presence_still_bind_fingerprint(
        self,
    ) -> None:
        activation, grant = _documents(capabilities=[], tools=[])
        first_request = replace(
            _request(activation, grant),
            approval_id="approval_unused_first",
        )
        changed_request = replace(first_request, approval_id="approval_unused_second")
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            provider = FakeProvider([ProviderTurnResult("done", _usage(), completed=True)])
            kernel = _ProviderAutoApprovingKernel(
                provider=provider,
                broker=CapabilityBroker(),
                journal=log,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
            )
            coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=log)
            first = coordinator.execute(first_request)
            duplicate = coordinator.execute(first_request)
            self.assertEqual("executed", first.disposition)
            self.assertEqual("existing_terminal", duplicate.disposition)
            with self.assertRaisesRegex(KernelError, "journal_begin_ambiguous"):
                coordinator.execute(changed_request)
            self.assertEqual(1, len(provider.requests))

        fingerprints: list[str] = []
        for authority in (None, InMemoryHumanApprovalAuthority()):
            journal = FakeJournal()
            kernel = _ProviderAutoApprovingKernel(
                provider=FakeProvider([ProviderTurnResult("done", _usage(), completed=True)]),
                broker=CapabilityBroker(),
                journal=journal,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                approval_authority=authority,
            )
            self.assertEqual("succeeded", kernel.execute(_request(activation, grant)).outcome)
            fingerprint = journal.begin_calls[0][-1]
            assert fingerprint is not None
            fingerprints.append(fingerprint)
        self.assertNotEqual(*fingerprints)

    def test_same_execution_with_a_different_decision_conflicts_before_provider(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            first_provider = FakeProvider(
                [ProviderTurnResult("complete", _usage(), completed=True)]
            )
            first_kernel, first_authority = _approval_kernel(
                first_provider,
                (tool,),
                journal=log,
            )
            first_review = first_kernel.prepare_approval_review(request)
            first_decision = _decision(first_review, reviewer_id="reviewer_first")
            first_authority.decide(
                first_decision,
                expected_generation=0,
                expected_review_hash=first_review.content_hash,
            )
            self.assertEqual("succeeded", first_kernel.execute(request).outcome)

            changed_provider = FakeProvider([])
            changed_kernel, changed_authority = _approval_kernel(
                changed_provider,
                (tool,),
                journal=log,
            )
            changed_review = changed_kernel.prepare_approval_review(request)
            changed_decision = _decision(changed_review, reviewer_id="reviewer_second")
            changed_authority.decide(
                changed_decision,
                expected_generation=0,
                expected_review_hash=changed_review.content_hash,
            )
            with self.assertRaisesRegex(Exception, "journal_begin_ambiguous"):
                changed_kernel.execute(request)
            self.assertEqual([], changed_provider.requests)

    def test_revocation_before_and_after_provider_and_tool_boundaries_fails_closed(self) -> None:
        activation, grant = _documents(
            capabilities=["artifact.propose", "tool.invoke"],
            tools=["source.read"],
        )
        request = replace(_request(activation, grant), approval_id="approval_execution_01")

        before_provider = FakeProvider([])
        before_tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
        kernel, authority = _approval_kernel(before_provider, (before_tool,))
        review, decision = _approve(kernel, authority, request, approved_tool_ids=("source.read",))
        authority.revoke(
            review.approval_id,
            expected_generation=1,
            expected_decision_hash=decision.content_hash,
        )
        result = kernel.execute(request)
        self.assertEqual(["tool_not_authorized"], result.receipt["failure_codes"])
        self.assertEqual([], before_provider.requests)
        self.assertEqual([], before_tool.calls)

        during_provider = FakeProvider([])
        during_tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
        during_kernel, during_authority = _approval_kernel(during_provider, (during_tool,))
        during_review, during_decision = _approve(
            during_kernel,
            during_authority,
            request,
            approved_tool_ids=("source.read",),
        )

        def revoke_in_provider(_turn):
            during_authority.revoke(
                during_review.approval_id,
                expected_generation=1,
                expected_decision_hash=during_decision.content_hash,
            )
            return ProviderTurnResult("discard", _usage(), completed=True)

        during_provider.script.append(revoke_in_provider)
        result = during_kernel.execute(request)
        self.assertEqual(["tool_not_authorized"], result.receipt["failure_codes"])
        self.assertEqual(3, result.receipt["usage"]["input_tokens"])
        self.assertEqual([], during_tool.calls)

        after_tool_provider = FakeProvider([])
        holder: dict[str, object] = {}

        def revoke_in_tool(_call):
            holder["authority"].revoke(
                holder["review"].approval_id,
                expected_generation=1,
                expected_decision_hash=holder["decision"].content_hash,
            )
            return ToolResult("discard")

        after_tool = FakeTool("source.read", "tool.invoke", revoke_in_tool)
        after_kernel, after_authority = _approval_kernel(after_tool_provider, (after_tool,))
        after_review, after_decision = _approve(
            after_kernel,
            after_authority,
            request,
            approved_tool_ids=("source.read",),
        )
        holder.update(authority=after_authority, review=after_review, decision=after_decision)
        after_tool_provider.script.extend(
            [
                ProviderTurnResult(
                    "expose",
                    _usage(),
                    tool_exposure_requests=("source.read",),
                    completed=False,
                ),
                ProviderTurnResult(
                    "invoke",
                    _usage(),
                    tool_calls=(ToolCall("source.read", {}),),
                    completed=True,
                ),
            ]
        )
        result = after_kernel.execute(request)
        self.assertEqual(["tool_not_authorized"], result.receipt["failure_codes"])
        self.assertEqual(1, len(after_tool.calls))
        self.assertEqual(
            ["tool_not_authorized"],
            result.receipt["tool_invocations"][0]["failure_codes"],
        )

    def test_whole_batch_preflight_and_approval_precedence_are_deterministic(self) -> None:
        activation, grant = _documents(
            capabilities=["tool.invoke"],
            tools=["source.read", "world.validate"],
        )
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        source = FakeTool("source.read", "tool.invoke", ToolResult("source"))
        world = FakeTool("world.validate", "tool.invoke", ToolResult("world"))
        provider = FakeProvider(
            [
                ProviderTurnResult(
                    "expose source",
                    _usage(),
                    tool_exposure_requests=("source.read",),
                    completed=False,
                ),
                ProviderTurnResult(
                    "mixed batch",
                    _usage(),
                    tool_calls=(
                        ToolCall("source.read", {}),
                        ToolCall("world.validate", {}),
                    ),
                    completed=True,
                ),
            ]
        )
        kernel, authority = _approval_kernel(provider, (source, world))
        _approve(
            kernel,
            authority,
            request,
            approved_tool_ids=("source.read", "world.validate"),
        )
        result = kernel.execute(request)
        self.assertEqual(["tool_not_authorized"], result.receipt["failure_codes"])
        self.assertEqual([], source.calls)
        self.assertEqual([], world.calls)
        self.assertEqual([], result.receipt["tool_invocations"])

        token = FakeCancellation()
        cancel_provider = FakeProvider([])
        cancel_tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
        cancel_kernel, cancel_authority = _approval_kernel(
            cancel_provider,
            (cancel_tool,),
            cancellation=token,
        )
        cancel_review, cancel_decision = _approve(
            cancel_kernel,
            cancel_authority,
            request,
            approved_tool_ids=("source.read",),
        )
        cancel_authority.revoke(
            cancel_review.approval_id,
            expected_generation=1,
            expected_decision_hash=cancel_decision.content_hash,
        )
        token.cancelled = True
        cancelled = cancel_kernel.execute(request)
        self.assertEqual("cancelled", cancelled.outcome)
        self.assertEqual(["execution_cancelled"], cancelled.receipt["failure_codes"])

        budget_provider = FakeProvider([])
        budget_tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
        budget_kernel, budget_authority = _approval_kernel(budget_provider, (budget_tool,))
        budget_review, budget_decision = _approve(
            budget_kernel,
            budget_authority,
            request,
            approved_tool_ids=("source.read",),
        )

        def revoke_with_over_budget(_turn):
            budget_authority.revoke(
                budget_review.approval_id,
                expected_generation=1,
                expected_decision_hash=budget_decision.content_hash,
            )
            return ProviderTurnResult(
                "discard",
                _usage(input_tokens=101, output_tokens=0, cached_input_tokens=0),
                completed=True,
            )

        budget_provider.script.append(revoke_with_over_budget)
        budget_result = budget_kernel.execute(request)
        self.assertEqual(["token_budget_exceeded"], budget_result.receipt["failure_codes"])
        self.assertEqual(101, budget_result.receipt["usage"]["input_tokens"])

    def test_revocation_after_proposal_and_runtime_mismatch_precede_safely(self) -> None:
        activation, grant = _documents(
            capabilities=["artifact.propose", "tool.invoke"],
            tools=["source.read"],
        )
        request = replace(_request(activation, grant), approval_id="approval_execution_01")
        holder: dict[str, object] = {}

        class RevokingArtifactPort(FakeArtifactPort):
            def propose(self, proposal):
                result = super().propose(proposal)
                holder["authority"].revoke(
                    holder["review"].approval_id,
                    expected_generation=1,
                    expected_decision_hash=holder["decision"].content_hash,
                )
                return result

        port = RevokingArtifactPort([{"id": "artifact_closed", "content_hash": "a" * 64}])
        provider = FakeProvider(
            [
                ProviderTurnResult(
                    "proposal",
                    _usage(),
                    artifact_proposals=(ArtifactProposal({"secret": "PRIVATE_PROPOSAL"}),),
                    completed=True,
                )
            ]
        )
        authority = InMemoryHumanApprovalAuthority()
        kernel = _ProviderAutoApprovingKernel(
            provider=provider,
            broker=CapabilityBroker(
                tools=(FakeTool("source.read", "tool.invoke", ToolResult("unused")),),
                artifact_port=port,
            ),
            journal=FakeJournal(),
            clock=FakeClock(),
            cancellation=FakeCancellation(),
            approval_authority=authority,
        )
        review, decision = _approve(
            kernel,
            authority,
            request,
            approved_tool_ids=("source.read",),
        )
        holder.update(authority=authority, review=review, decision=decision)
        result = kernel.execute(request)
        self.assertEqual(["tool_not_authorized"], result.receipt["failure_codes"])
        self.assertEqual(1, len(port.proposals))

        mismatch_provider = FakeProvider(
            [],
            runtime_binding={"id": "other_runtime", "revision": 1, "content_hash": "0" * 64},
        )
        mismatch = _ProviderAutoApprovingKernel(
            provider=mismatch_provider,
            broker=CapabilityBroker(
                tools=(FakeTool("source.read", "tool.invoke", ToolResult("unused")),)
            ),
            journal=FakeJournal(),
            clock=FakeClock(),
            cancellation=FakeCancellation(),
        )
        mismatch_result = mismatch.execute(_request(activation, grant))
        self.assertEqual(["provider_failed"], mismatch_result.receipt["failure_codes"])
        self.assertEqual([], mismatch_provider.requests)

    def test_revocation_after_failed_effects_wins_at_the_post_effect_boundary(self) -> None:
        activation, grant = _documents(
            capabilities=["artifact.propose", "memory.propose", "tool.invoke"],
            tools=["source.read"],
        )
        request = replace(_request(activation, grant), approval_id="approval_execution_01")

        def build_kernel(provider, tool, *, artifact_port=None, memory_port=None):
            authority = InMemoryHumanApprovalAuthority()
            kernel = _ProviderAutoApprovingKernel(
                provider=provider,
                broker=CapabilityBroker(
                    tools=(tool,),
                    artifact_port=artifact_port,
                    memory_port=memory_port,
                ),
                journal=FakeJournal(),
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                approval_authority=authority,
            )
            review, decision = _approve(
                kernel,
                authority,
                request,
                approved_tool_ids=("source.read",),
            )
            return kernel, authority, review, decision

        tool_holder: dict[str, object] = {}

        def revoke_then_fail_tool(_call):
            tool_holder["authority"].revoke(
                tool_holder["review"].approval_id,
                expected_generation=1,
                expected_decision_hash=tool_holder["decision"].content_hash,
            )
            raise RuntimeError("private tool failure")

        failing_tool = FakeTool("source.read", "tool.invoke", revoke_then_fail_tool)
        tool_provider = FakeProvider(
            [
                ProviderTurnResult(
                    "expose",
                    _usage(),
                    tool_exposure_requests=("source.read",),
                    completed=False,
                ),
                ProviderTurnResult(
                    "invoke",
                    _usage(),
                    tool_calls=(ToolCall("source.read", {}),),
                    completed=True,
                ),
            ]
        )
        tool_kernel, tool_authority, tool_review, tool_decision = build_kernel(
            tool_provider,
            failing_tool,
        )
        tool_holder.update(
            authority=tool_authority,
            review=tool_review,
            decision=tool_decision,
        )
        tool_result = tool_kernel.execute(request)
        self.assertEqual(["tool_not_authorized"], tool_result.receipt["failure_codes"])
        self.assertEqual(
            ["tool_not_authorized"],
            tool_result.receipt["tool_invocations"][0]["failure_codes"],
        )

        class RevokingFailingArtifactPort(FakeArtifactPort):
            def __init__(self, holder):
                super().__init__([])
                self.holder = holder

            def propose(self, proposal):
                self.proposals.append(proposal)
                self.holder["authority"].revoke(
                    self.holder["review"].approval_id,
                    expected_generation=1,
                    expected_decision_hash=self.holder["decision"].content_hash,
                )
                raise RuntimeError("private artifact failure")

        class RevokingFailingMemoryPort(FakeMemoryPort):
            def __init__(self, holder):
                super().__init__([])
                self.holder = holder

            def propose(self, proposal):
                self.proposals.append(proposal)
                self.holder["authority"].revoke(
                    self.holder["review"].approval_id,
                    expected_generation=1,
                    expected_decision_hash=self.holder["decision"].content_hash,
                )
                raise RuntimeError("private memory failure")

        for proposal_kind in ("artifact", "memory"):
            with self.subTest(proposal_kind=proposal_kind):
                holder: dict[str, object] = {}

                if proposal_kind == "artifact":
                    port = RevokingFailingArtifactPort(holder)
                    provider_result = ProviderTurnResult(
                        "propose",
                        _usage(),
                        artifact_proposals=(ArtifactProposal({"value": "private"}),),
                        completed=True,
                    )
                    broker_ports = {"artifact_port": port}
                else:
                    port = RevokingFailingMemoryPort(holder)
                    provider_result = ProviderTurnResult(
                        "propose",
                        _usage(),
                        memory_proposals=(MemoryProposal({"value": "private"}),),
                        completed=True,
                    )
                    broker_ports = {"memory_port": port}

                provider = FakeProvider([provider_result])
                inert_tool = FakeTool("source.read", "tool.invoke", ToolResult("unused"))
                kernel, authority, review, decision = build_kernel(
                    provider,
                    inert_tool,
                    **broker_ports,
                )
                holder.update(authority=authority, review=review, decision=decision)
                result = kernel.execute(request)
                self.assertEqual(["tool_not_authorized"], result.receipt["failure_codes"])
                self.assertEqual(1, len(port.proposals))

    def test_fingerprint_binds_approval_catalog_without_persisting_metadata(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(
            _request(activation, grant),
            approval_id="approval_private_sentinel",
        )
        first_tool = FakeTool(
            "source.read",
            "tool.invoke",
            ToolResult("unused"),
            summary="First descriptor summary.",
            input_schema={"type": "object"},
        )
        first_provider = FakeProvider([ProviderTurnResult("complete", _usage(), completed=True)])
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            first_authority = InMemoryHumanApprovalAuthority()
            first_kernel = _ProviderAutoApprovingKernel(
                provider=first_provider,
                broker=CapabilityBroker(tools=(first_tool,)),
                journal=log,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                approval_authority=first_authority,
            )
            review = first_kernel.prepare_approval_review(request)
            decision = ExecutionApprovalDecision.create(
                review=review,
                reviewer_id="reviewer_private_sentinel",
                outcome="approved",
                approved_tool_ids=("source.read",),
                expires_at_ms=2_000,
            )
            first_authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            result = first_kernel.execute(request)
            self.assertEqual("succeeded", result.outcome)
            private_sentinels = (
                "approval_private_sentinel",
                "reviewer_private_sentinel",
                review.content_hash,
                decision.content_hash,
            )
            worker_view = repr(first_provider.requests)
            public_view = json.dumps({"events": result.events, "receipt": result.receipt})
            for sentinel in private_sentinels:
                self.assertNotIn(sentinel, worker_view)
                self.assertNotIn(sentinel, public_view)
                for suffix in ("", "-wal", "-shm", "-journal"):
                    path = type(log.database_path)(f"{log.database_path}{suffix}")
                    if path.exists():
                        self.assertNotIn(sentinel.encode("ascii"), path.read_bytes())

            changed_tool = FakeTool(
                "source.read",
                "tool.invoke",
                ToolResult("unused"),
                summary="Changed descriptor summary.",
                input_schema={"type": "object"},
            )
            changed_provider = FakeProvider([])
            changed_authority = InMemoryHumanApprovalAuthority()
            changed_kernel = _ProviderAutoApprovingKernel(
                provider=changed_provider,
                broker=CapabilityBroker(tools=(changed_tool,)),
                journal=log,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                approval_authority=changed_authority,
            )
            changed_review = changed_kernel.prepare_approval_review(request)
            changed_decision = ExecutionApprovalDecision.create(
                review=changed_review,
                reviewer_id="reviewer_changed",
                outcome="approved",
                approved_tool_ids=("source.read",),
                expires_at_ms=2_000,
            )
            changed_authority.decide(
                changed_decision,
                expected_generation=0,
                expected_review_hash=changed_review.content_hash,
            )
            with self.assertRaisesRegex(Exception, "journal_begin_ambiguous"):
                changed_kernel.execute(request)
            self.assertEqual([], changed_provider.requests)


class ProgressiveExposureProtocolTests(unittest.TestCase):
    @staticmethod
    def _authenticated_frame(document: dict[str, object], key: bytes) -> bytes:
        body = {name: value for name, value in document.items() if name != "mac"}
        canonical = json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        document["mac"] = hmac.new(key, canonical, hashlib.sha256).hexdigest()
        payload = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return len(payload).to_bytes(4, "big") + payload

    def test_tool_context_and_exposure_requests_round_trip_with_schema_hash_binding(self) -> None:
        tool = FakeTool(
            "source.read",
            "tool.invoke",
            ToolResult("ok"),
            summary="Read source.",
            input_schema={"type": "object", "required": ["path"]},
        )
        descriptor = (
            CapabilityBroker(tools=(tool,))
            .eligible_tool_catalog(
                effective_capabilities=frozenset({"tool.invoke"}),
                effective_tools=frozenset({"source.read"}),
            )
            .descriptors[0]
        )
        request = ProviderTurnRequest(
            "execution_protocol_01",
            0,
            {"secret": "PRIVATE_INPUT"},
            (),
            (descriptor.provider_summary(),),
            (descriptor.provider_definition(),),
        )
        key = b"k" * 32
        nonce = "ab" * 32
        frame = build_request_frame(request, key=key, nonce=nonce)
        parsed = parse_request_frame(frame, key=key)
        self.assertEqual(request, parsed.request)

        result = ProviderTurnResult(
            "next",
            _usage(),
            tool_exposure_requests=("source.read",),
            completed=False,
        )
        result_frame = build_result_frame(
            result,
            key=key,
            nonce=nonce,
            request_hash=parsed.request_hash,
        )
        self.assertEqual(
            result,
            parse_result_frame(
                result_frame,
                key=key,
                nonce=nonce,
                request_hash=parsed.request_hash,
            ),
        )

        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_result_invalid"):
            build_result_frame(
                replace(
                    result,
                    tool_calls=(ToolCall("source.read", {}),),
                    tool_exposure_requests=("source.read",),
                ),
                key=key,
                nonce=nonce,
                request_hash=parsed.request_hash,
            )

        document = json.loads(frame[4:])
        document["request"]["tool_summaries"][0]["summary"] = "Forged summary."
        canonical_request = json.dumps(
            document["request"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        document["request_hash"] = hashlib.sha256(canonical_request).hexdigest()
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_request_invalid"):
            parse_request_frame(self._authenticated_frame(document, key), key=key)

        document = json.loads(frame[4:])
        document["request"]["exposed_tools"][0]["input_schema"] = {"type": "null"}
        canonical_request = json.dumps(
            document["request"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        document["request_hash"] = hashlib.sha256(canonical_request).hexdigest()
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_request_invalid"):
            parse_request_frame(self._authenticated_frame(document, key), key=key)

        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_result_invalid"):
            build_result_frame(
                replace(
                    result,
                    tool_exposure_requests=("source.read", "source.read"),
                ),
                key=key,
                nonce=nonce,
                request_hash=parsed.request_hash,
            )

        overlong_tool_id = "aa." + "bb." * 400 + "cc"
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_request_invalid"):
            build_request_frame(
                replace(
                    request,
                    tool_summaries=(ProviderToolSummary(overlong_tool_id, "Summary.", "a" * 64),),
                    exposed_tools=(),
                ),
                key=key,
                nonce=nonce,
            )

        descriptor_body = {
            "tool_id": "source.read",
            "required_capability_id": "unknown.capability",
            "summary": "Summary.",
            "input_schema": {"type": "object"},
        }
        descriptor_hash = hashlib.sha256(
            json.dumps(
                descriptor_body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_request_invalid"):
            build_request_frame(
                replace(
                    request,
                    tool_summaries=(
                        ProviderToolSummary("source.read", "Summary.", descriptor_hash),
                    ),
                    exposed_tools=(
                        ProviderToolDefinition(
                            "source.read",
                            "unknown.capability",
                            "Summary.",
                            {"type": "object"},
                            descriptor_hash,
                        ),
                    ),
                ),
                key=key,
                nonce=nonce,
            )

        deep_schema: dict[str, object] = {}
        cursor = deep_schema
        for _index in range(33):
            nested = {}
            cursor["nested"] = nested
            cursor = nested
        descriptor_body = {
            "tool_id": "source.read",
            "required_capability_id": "tool.invoke",
            "summary": "Summary.",
            "input_schema": deep_schema,
        }
        descriptor_hash = hashlib.sha256(
            json.dumps(
                descriptor_body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_request_invalid"):
            build_request_frame(
                replace(
                    request,
                    tool_summaries=(
                        ProviderToolSummary("source.read", "Summary.", descriptor_hash),
                    ),
                    exposed_tools=(
                        ProviderToolDefinition(
                            "source.read",
                            "tool.invoke",
                            "Summary.",
                            deep_schema,
                            descriptor_hash,
                        ),
                    ),
                ),
                key=key,
                nonce=nonce,
            )
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_result_invalid"):
            build_result_frame(
                replace(result, tool_exposure_requests=(overlong_tool_id,)),
                key=key,
                nonce=nonce,
                request_hash=parsed.request_hash,
            )

        exact_tool_id = ".".join(["a" + "b" * 63, *("a" + "b" * 62 for _index in range(15))])
        self.assertEqual(1024, len(exact_tool_id))
        exact_result = replace(
            result,
            tool_calls=(ToolCall(exact_tool_id, {"value": 1}),),
            tool_exposure_requests=(),
        )
        exact_frame = build_result_frame(
            exact_result,
            key=key,
            nonce=nonce,
            request_hash=parsed.request_hash,
        )
        self.assertEqual(
            exact_result,
            parse_result_frame(
                exact_frame,
                key=key,
                nonce=nonce,
                request_hash=parsed.request_hash,
            ),
        )

        overlong_call_id = f"{exact_tool_id}.aa"
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_result_invalid"):
            build_result_frame(
                replace(
                    result,
                    tool_calls=(ToolCall(overlong_call_id, {}),),
                    tool_exposure_requests=(),
                ),
                key=key,
                nonce=nonce,
                request_hash=parsed.request_hash,
            )

        class TextAlias(str):
            pass

        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_result_invalid"):
            build_result_frame(
                replace(
                    result,
                    tool_calls=(ToolCall(TextAlias("source.read"), {}),),
                    tool_exposure_requests=(),
                ),
                key=key,
                nonce=nonce,
                request_hash=parsed.request_hash,
            )

        hostile_document = json.loads(exact_frame[4:])
        hostile_document["result"]["tool_calls"][0]["tool_id"] = overlong_call_id
        hostile_result = json.dumps(
            hostile_document["result"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        hostile_document["result_hash"] = hashlib.sha256(hostile_result).hexdigest()
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_result_invalid"):
            parse_result_frame(
                self._authenticated_frame(hostile_document, key),
                key=key,
                nonce=nonce,
                request_hash=parsed.request_hash,
            )

        descriptor_body = {
            "tool_id": "source.read",
            "required_capability_id": overlong_tool_id,
            "summary": "Summary.",
            "input_schema": {"type": "object"},
        }
        descriptor_hash = hashlib.sha256(
            json.dumps(
                descriptor_body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(WorkerProtocolError, "worker_protocol_request_invalid"):
            build_request_frame(
                replace(
                    request,
                    tool_summaries=(
                        ProviderToolSummary("source.read", "Summary.", descriptor_hash),
                    ),
                    exposed_tools=(
                        ProviderToolDefinition(
                            "source.read",
                            overlong_tool_id,
                            "Summary.",
                            {"type": "object"},
                            descriptor_hash,
                        ),
                    ),
                ),
                key=key,
                nonce=nonce,
            )


@unittest.skipUnless(sys.platform.startswith("linux"), "native worker containment is Linux-only")
class NativeApprovalRevocationTests(unittest.TestCase):
    def test_revocation_stops_a_blocked_worker_and_proves_domain_cleanup(self) -> None:
        class RealtimeClock:
            def __init__(self) -> None:
                self.origin = time.monotonic()

            def now_ms(self) -> int:
                return 1_000 + int((time.monotonic() - self.origin) * 1_000)

        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(
            _request(
                activation,
                grant,
                max_duration_ms=5_000,
                deadline_ms=10_000,
            ),
            approval_id="approval_blocked_worker_01",
            private_input={
                "__worldforge_conformance__": {
                    "action": "sleep",
                    "milliseconds": 3_000,
                }
            },
        )
        supervisor = OneShotProviderSupervisor(turn_timeout_ms=5_000)
        authority = InMemoryHumanApprovalAuthority()
        kernel = _ProviderAutoApprovingKernel(
            provider=supervisor,
            broker=CapabilityBroker(
                tools=(FakeTool("source.read", "tool.invoke", ToolResult("unused")),)
            ),
            journal=FakeJournal(),
            clock=RealtimeClock(),
            cancellation=FakeCancellation(),
            approval_authority=authority,
        )
        review, decision = _approve(
            kernel,
            authority,
            request,
            approved_tool_ids=("source.read",),
            expires_at_ms=10_000,
        )
        captured: dict[str, object] = {}

        def execute() -> None:
            try:
                captured["result"] = kernel.execute(request)
            except BaseException as exc:
                captured["error"] = exc

        thread = threading.Thread(target=execute)
        started = time.monotonic()
        thread.start()
        deadline = time.monotonic() + 2
        while supervisor.active_worker_pid is None and time.monotonic() < deadline:
            time.sleep(0.01)
        worker_pid = supervisor.active_worker_pid
        self.assertIsNotNone(worker_pid)
        authority.revoke(
            review.approval_id,
            expected_generation=1,
            expected_decision_hash=decision.content_hash,
        )
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", captured)
        result = captured["result"]
        self.assertEqual("failed", result.outcome)
        self.assertEqual(["tool_not_authorized"], result.receipt["failure_codes"])
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(1, supervisor.spawn_count)
        self.assertIsNone(supervisor.active_worker_pid)
        self.assertIsNone(supervisor.active_broker_pid)
        self.assertFalse(os.path.exists(f"/proc/{worker_pid}"))

    def test_expiry_stops_a_blocked_worker_and_proves_domain_cleanup(self) -> None:
        class RealtimeClock:
            def __init__(self) -> None:
                self.origin = time.monotonic()

            def now_ms(self) -> int:
                return 1_000 + int((time.monotonic() - self.origin) * 1_000)

        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(
            _request(
                activation,
                grant,
                max_duration_ms=5_000,
                deadline_ms=10_000,
            ),
            approval_id="approval_expiring_worker_01",
            private_input={
                "__worldforge_conformance__": {
                    "action": "sleep",
                    "milliseconds": 3_000,
                }
            },
        )
        supervisor = OneShotProviderSupervisor(turn_timeout_ms=5_000)
        authority = InMemoryHumanApprovalAuthority()
        kernel = _ProviderAutoApprovingKernel(
            provider=supervisor,
            broker=CapabilityBroker(
                tools=(FakeTool("source.read", "tool.invoke", ToolResult("unused")),)
            ),
            journal=FakeJournal(),
            clock=RealtimeClock(),
            cancellation=FakeCancellation(),
            approval_authority=authority,
        )
        _approve(
            kernel,
            authority,
            request,
            approved_tool_ids=("source.read",),
            expires_at_ms=1_300,
        )
        captured: dict[str, object] = {}

        def execute() -> None:
            try:
                captured["result"] = kernel.execute(request)
            except BaseException as exc:
                captured["error"] = exc

        thread = threading.Thread(target=execute)
        started = time.monotonic()
        thread.start()
        deadline = time.monotonic() + 2
        while supervisor.active_worker_pid is None and time.monotonic() < deadline:
            time.sleep(0.01)
        worker_pid = supervisor.active_worker_pid
        self.assertIsNotNone(worker_pid)
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", captured)
        result = captured["result"]
        self.assertEqual("failed", result.outcome)
        self.assertEqual(["tool_not_authorized"], result.receipt["failure_codes"])
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(1, supervisor.spawn_count)
        self.assertIsNone(supervisor.active_worker_pid)
        self.assertIsNone(supervisor.active_broker_pid)
        self.assertFalse(os.path.exists(f"/proc/{worker_pid}"))

    def test_real_worker_requests_schema_then_parent_invokes_on_the_next_turn(self) -> None:
        activation, grant = _documents(capabilities=["tool.invoke"], tools=["source.read"])
        request = replace(
            _request(
                activation,
                grant,
                max_turns=3,
                max_duration_ms=5_000,
                deadline_ms=10_000,
            ),
            approval_id="approval_native_exposure_01",
            private_input={
                "__worldforge_conformance__": {
                    "turn_plan": [
                        {
                            "tool_exposure_requests": ["source.read"],
                            "completed": False,
                        },
                        {
                            "tool_calls": [
                                {
                                    "tool_id": "source.read",
                                    "private_arguments": {"path": "PRIVATE_NATIVE_PATH"},
                                }
                            ],
                            "completed": True,
                        },
                    ]
                }
            },
        )
        tool = FakeTool(
            "source.read",
            "tool.invoke",
            ToolResult({"value": "PRIVATE_NATIVE_RESULT"}),
            summary="Read source.",
            input_schema={"type": "object", "required": ["path"]},
        )
        supervisor = OneShotProviderSupervisor(turn_timeout_ms=3_000)
        authority = InMemoryHumanApprovalAuthority()
        kernel = _ProviderAutoApprovingKernel(
            provider=supervisor,
            broker=CapabilityBroker(tools=(tool,)),
            journal=FakeJournal(),
            clock=FakeClock(),
            cancellation=FakeCancellation(),
            approval_authority=authority,
        )
        _approve(
            kernel,
            authority,
            request,
            approved_tool_ids=("source.read",),
            expires_at_ms=10_000,
        )
        result = kernel.execute(request)
        self.assertEqual("succeeded", result.outcome)
        self.assertEqual(2, supervisor.spawn_count)
        self.assertEqual(1, len(tool.calls))
        self.assertEqual({"path": "PRIVATE_NATIVE_PATH"}, tool.calls[0].private_arguments)
        self.assertEqual([], result.receipt["failure_codes"])


if __name__ == "__main__":
    unittest.main()
