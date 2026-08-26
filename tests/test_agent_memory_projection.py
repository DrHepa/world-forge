from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from tests.test_agent_event_log import (
    _commit_wal_then_crash,
    _leave_hot_rollback_journal_then_crash,
    _store_byte_evidence,
    _terminal_records,
)
from worldforge.agent_harness import (
    InMemoryMemoryApprovalAuthority as ExportedMemoryApprovalAuthority,
)
from worldforge.agent_harness import (
    InMemoryMemoryProposalSource as ExportedMemoryProposalSource,
)
from worldforge.agent_harness import MemoryProjectionCoordinator as ExportedCoordinator
from worldforge.agent_harness.approvals import ExecutionApprovalReview
from worldforge.agent_harness.event_log import (
    AGENT_EVENT_LOG_DATABASE_NAME,
    AGENT_EVENT_LOG_SCHEMA_VERSION,
    AgentEventLog,
    AgentEventLogConflict,
    AgentEventLogCorrupt,
    AgentEventLogError,
    AgentEventLogIndeterminate,
    _memory_projection_event_id,
)
from worldforge.agent_harness.memory_approvals import (
    InMemoryMemoryApprovalAuthority,
    MemoryApprovalError,
    MemoryProjectionDecision,
    MemoryProjectionReview,
)
from worldforge.agent_harness.memory_projection import (
    InMemoryMemoryProposalSource,
    LosslessMemoryProjectionCompiler,
    MemoryProjectionCoordinator,
    MemoryProjectionError,
)
from worldforge.agent_harness.records import build_event
from worldforge.agent_harness.usage import build_legacy_usage_accounting
from worldforge.agent_harness_contracts import (
    AGENT_MEMORY_PROJECTION_FORMAT,
    canonical_agent_harness_hash,
    validate_agent_harness_document,
    validate_agent_harness_documents,
)


def _proposal_source() -> InMemoryMemoryProposalSource:
    source = InMemoryMemoryProposalSource()
    source.propose(
        execution_id="execution_01",
        kind="decision",
        subject_id="combat_policy",
        value={"mode": "turn_based"},
    )
    source.propose(
        execution_id="execution_01",
        kind="discovery",
        subject_id="world_fact",
        value="the_gate_is_closed",
    )
    return source


def _memory_review(**changes: object) -> MemoryProjectionReview:
    values: dict[str, object] = {
        "review_id": "memory_review_01",
        "execution_id": "execution_01",
        "receipt_id": "receipt_01",
        "receipt_content_hash": "a" * 64,
        "source_event_chain": (
            ("event_00", "1" * 64),
            ("event_01", "2" * 64),
        ),
        "candidate_snapshot": _proposal_source().snapshot("execution_01"),
    }
    values.update(changes)
    return MemoryProjectionReview.create(**values)


def _memory_decision(
    review: MemoryProjectionReview,
    **changes: object,
) -> MemoryProjectionDecision:
    values: dict[str, object] = {
        "review": review,
        "reviewer_id": "memory_reviewer_01",
        "outcome": "approved",
        "approved_proposal_ids": (review.candidate_proposals[0][0],),
        "expires_at_ms": 2_000,
    }
    values.update(changes)
    return MemoryProjectionDecision.create(**values)


class MemoryProposalSourceTests(unittest.TestCase):
    def test_private_runtime_exports_are_exact(self) -> None:
        self.assertIs(InMemoryMemoryProposalSource, ExportedMemoryProposalSource)
        self.assertIs(InMemoryMemoryApprovalAuthority, ExportedMemoryApprovalAuthority)
        self.assertIs(MemoryProjectionCoordinator, ExportedCoordinator)

    def test_proposals_are_code_identified_exact_deduplicated_and_detached(self) -> None:
        source = InMemoryMemoryProposalSource()
        value = {"nested": ["keep", {"count": 2}], "enabled": True}

        first = source.propose(
            execution_id="execution_01",
            kind="decision",
            subject_id="combat_policy",
            value=value,
        )
        value["nested"][1]["count"] = 99
        duplicate = source.propose(
            execution_id="execution_01",
            kind="decision",
            subject_id="combat_policy",
            value={"enabled": True, "nested": ["keep", {"count": 2}]},
        )

        self.assertEqual(first, duplicate)
        self.assertEqual("execution_01", first.execution_id)
        self.assertEqual("decision", first.kind)
        self.assertEqual("combat_policy", first.subject_id)
        self.assertRegex(first.proposal_id, r"^[a-z][a-z0-9_]{1,63}$")
        self.assertRegex(first.value_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(first.content_hash, r"^[0-9a-f]{64}$")
        self.assertEqual(1, len(source.snapshot("execution_01").proposals))
        copied = source.private_value("execution_01", first.proposal_id)
        self.assertEqual({"enabled": True, "nested": ["keep", {"count": 2}]}, copied)
        copied["nested"][1]["count"] = 100
        self.assertEqual(
            2,
            source.private_value("execution_01", first.proposal_id)["nested"][1]["count"],
        )

    def test_different_values_remain_distinct_for_later_approval_conflict_check(self) -> None:
        source = InMemoryMemoryProposalSource()
        first = source.propose(
            execution_id="execution_01",
            kind="preference",
            subject_id="camera_mode",
            value="fixed",
        )
        second = source.propose(
            execution_id="execution_01",
            kind="preference",
            subject_id="camera_mode",
            value="follow",
        )

        snapshot = source.snapshot("execution_01")
        self.assertNotEqual(first.proposal_id, second.proposal_id)
        self.assertEqual(
            tuple(
                sorted(
                    (first.proposal_id, second.proposal_id),
                    key=lambda item: item.encode("utf-8"),
                )
            ),
            tuple(item.proposal_id for item in snapshot.proposals),
        )
        self.assertRegex(snapshot.content_hash, r"^[0-9a-f]{64}$")

    def test_hostile_values_bounds_aliases_and_raw_repr_fail_closed(self) -> None:
        source = InMemoryMemoryProposalSource()
        sentinel = "RAW_MEMORY_SENTINEL"
        identity = source.propose(
            execution_id="execution_01",
            kind="discovery",
            subject_id="world_fact",
            value={"secret": sentinel},
        )
        self.assertNotIn(sentinel, repr(identity))
        self.assertNotIn(sentinel, repr(source.snapshot("execution_01")))
        self.assertNotIn(sentinel, repr(source))

        cyclic: list[object] = []
        cyclic.append(cyclic)
        hostile = (
            dict(execution_id="Execution", kind="decision", subject_id="subject_01", value=1),
            dict(execution_id="execution_01", kind="summary", subject_id="subject_01", value=1),
            dict(
                execution_id="execution_01",
                kind="decision",
                subject_id="subject-with-dash",
                value=1,
            ),
            dict(
                execution_id="execution_01",
                kind="decision",
                subject_id="subject_01",
                value=1.5,
            ),
            dict(
                execution_id="execution_01",
                kind="decision",
                subject_id="subject_01",
                value=(1, 2),
            ),
            dict(
                execution_id="execution_01",
                kind="decision",
                subject_id="subject_01",
                value=cyclic,
            ),
            dict(
                execution_id="execution_01",
                kind="decision",
                subject_id="subject_01",
                value={"x": [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]},
            ),
        )
        for values in hostile:
            with self.subTest(values={key: type(value).__name__ for key, value in values.items()}):
                with self.assertRaisesRegex(
                    MemoryProjectionError, "memory_proposal_invalid"
                ) as raised:
                    source.propose(**values)
                self.assertNotIn(sentinel, str(raised.exception))

        bounded = InMemoryMemoryProposalSource()
        for index in range(64):
            bounded.propose(
                execution_id="execution_01",
                kind="constraint",
                subject_id=f"subject_{index:02d}",
                value=index,
            )
        with self.assertRaisesRegex(MemoryProjectionError, "memory_proposal_bound_exceeded"):
            bounded.propose(
                execution_id="execution_01",
                kind="constraint",
                subject_id="subject_overflow",
                value=65,
            )
        with self.assertRaisesRegex(MemoryProjectionError, "memory_proposal_bound_exceeded"):
            InMemoryMemoryProposalSource().propose(
                execution_id="execution_01",
                kind="constraint",
                subject_id="oversized_value",
                value="x" * (64 * 1024),
            )

    def test_encoding_failures_leave_no_raw_value_in_the_exception_graph(self) -> None:
        sentinel = "RAW_MEMORY_SENTINEL_EXCEPTION_GRAPH_01"
        source = InMemoryMemoryProposalSource()

        with self.assertRaisesRegex(MemoryProjectionError, "memory_proposal_invalid") as raised:
            source.propose(
                execution_id="execution_01",
                kind="discovery",
                subject_id="world_fact",
                value={"secret": f"{sentinel}\ud800"},
            )

        pending: list[BaseException] = [raised.exception]
        visited: set[int] = set()
        evidence: list[str] = []
        while pending:
            current = pending.pop()
            if id(current) in visited:
                continue
            visited.add(id(current))
            evidence.extend((str(current), repr(current), repr(current.args)))
            if current.__context__ is not None:
                pending.append(current.__context__)
            if current.__cause__ is not None:
                pending.append(current.__cause__)
        self.assertNotIn(sentinel, "\n".join(evidence))

    def test_mutated_identity_aliases_cannot_enter_a_review(self) -> None:
        class TextAlias(str):
            pass

        source = _proposal_source()
        snapshot = source.snapshot("execution_01")
        object.__setattr__(
            snapshot.proposals[0],
            "content_hash",
            TextAlias(snapshot.proposals[0].content_hash),
        )

        with self.assertRaisesRegex(
            MemoryApprovalError,
            "memory_approval_review_invalid",
        ):
            MemoryProjectionReview.create(
                review_id="memory_review_01",
                execution_id="execution_01",
                receipt_id="receipt_01",
                receipt_content_hash="a" * 64,
                source_event_chain=(("event_01", "1" * 64),),
                candidate_snapshot=snapshot,
            )

    def test_concurrent_exact_proposals_create_one_candidate(self) -> None:
        source = InMemoryMemoryProposalSource()
        identities: list[object] = []
        failures: list[BaseException] = []
        gate = threading.Barrier(9)

        def propose() -> None:
            try:
                gate.wait()
                identities.append(
                    source.propose(
                        execution_id="execution_01",
                        kind="constraint",
                        subject_id="budget_limit",
                        value={"turns": 4},
                    )
                )
            except BaseException as exc:
                failures.append(exc)

        threads = [threading.Thread(target=propose) for _ in range(8)]
        for thread in threads:
            thread.start()
        gate.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual([], failures)
        self.assertEqual(8, len(identities))
        self.assertEqual(1, len(set(identities)))
        self.assertEqual(1, len(source.snapshot("execution_01").proposals))


class MemoryApprovalAuthorityTests(unittest.TestCase):
    def test_review_binds_terminal_lineage_candidates_and_fixed_policy(self) -> None:
        review = _memory_review()

        self.assertEqual("execution_01", review.execution_id)
        self.assertEqual("receipt_01", review.receipt_id)
        self.assertEqual("2" * 64, review.pre_projection_event_head_hash)
        self.assertEqual(2, len(review.source_event_chain))
        self.assertEqual(2, len(review.candidate_proposals))
        self.assertEqual(
            tuple(sorted(review.candidate_proposals, key=lambda item: item[0].encode("utf-8"))),
            review.candidate_proposals,
        )
        self.assertEqual("lossless_hash_projection", review.policy_id)
        self.assertEqual(1, review.policy_version)
        self.assertRegex(review.policy_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(review.content_hash, r"^[0-9a-f]{64}$")

    def test_policy_identity_rejects_subclasses_without_hostile_equality(self) -> None:
        sentinel = "RAW_MEMORY_SENTINEL_POLICY_EQ_01"

        class HostilePolicy(str):
            def __eq__(self, other: object) -> bool:
                raise RuntimeError(sentinel)

            def __ne__(self, other: object) -> bool:
                raise RuntimeError(sentinel)

        review = _memory_review()
        object.__setattr__(review, "policy_id", HostilePolicy(review.policy_id))

        with self.assertRaisesRegex(MemoryApprovalError, "memory_approval_review_invalid"):
            InMemoryMemoryApprovalAuthority().prepare(review, expected_generation=0)

    def test_prepare_decide_snapshot_check_and_revoke_are_detached_exact_cas(self) -> None:
        authority = InMemoryMemoryApprovalAuthority()
        review = _memory_review()
        decision = _memory_decision(review)

        self.assertEqual("missing", authority.snapshot(review).state)
        self.assertEqual(review, authority.prepare(review, expected_generation=0))
        self.assertEqual(review, authority.prepare(review, expected_generation=0))
        prepared = authority.snapshot(review)
        self.assertEqual("prepared", prepared.state)
        self.assertEqual(review, prepared.prepared_review)
        self.assertEqual(
            decision,
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            ),
        )
        approved_snapshot = authority.snapshot(review)
        checked = authority.check_snapshot(review, approved_snapshot, now_ms=1_999)
        self.assertEqual(decision.approved_proposal_ids, checked.approved_proposal_ids)
        self.assertEqual(decision.content_hash, checked.decision_hash)

        object.__setattr__(approved_snapshot.prepared_review, "receipt_id", "receipt_tampered")
        object.__setattr__(approved_snapshot.current_decision, "outcome", "denied")
        fresh = authority.snapshot(review)
        self.assertEqual(review, fresh.prepared_review)
        self.assertEqual(decision, fresh.current_decision)

        authority.revoke(
            review.review_id,
            expected_generation=1,
            expected_decision_hash=decision.content_hash,
        )
        authority.revoke(
            review.review_id,
            expected_generation=1,
            expected_decision_hash=decision.content_hash,
        )
        with self.assertRaisesRegex(MemoryApprovalError, "memory_approval_revoked"):
            authority.check(review, now_ms=1_999)

    def test_subset_deny_expiry_stale_and_tool_approval_types_fail_closed(self) -> None:
        review = _memory_review()
        candidates = tuple(item[0] for item in review.candidate_proposals)
        with self.assertRaisesRegex(MemoryApprovalError, "memory_approval_decision_invalid"):
            _memory_decision(review, approved_proposal_ids=("proposal_not_present",))
        with self.assertRaisesRegex(MemoryApprovalError, "memory_approval_decision_invalid"):
            _memory_decision(review, approved_proposal_ids=tuple(reversed(candidates)))
        with self.assertRaisesRegex(MemoryApprovalError, "memory_approval_decision_invalid"):
            _memory_decision(review, approved_proposal_ids=())

        denied = InMemoryMemoryApprovalAuthority()
        denied.prepare(review, expected_generation=0)
        denial = _memory_decision(
            review,
            outcome="denied",
            approved_proposal_ids=(),
            expires_at_ms=None,
        )
        denied.decide(
            denial,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        with self.assertRaisesRegex(MemoryApprovalError, "memory_approval_denied"):
            denied.check(review, now_ms=0)

        expired = InMemoryMemoryApprovalAuthority()
        expired.prepare(review, expected_generation=0)
        decision = _memory_decision(review)
        expired.decide(
            decision,
            expected_generation=0,
            expected_review_hash=review.content_hash,
        )
        with self.assertRaisesRegex(MemoryApprovalError, "memory_approval_expired"):
            expired.check(review, now_ms=2_000)

        changed = _memory_review(receipt_content_hash="b" * 64)
        with self.assertRaisesRegex(MemoryApprovalError, "memory_approval_stale"):
            expired.prepare(changed, expected_generation=0)
        with self.assertRaisesRegex(MemoryApprovalError, "memory_approval_check_failed"):
            expired.check_snapshot(
                review,
                expired.snapshot(review),
                now_ms=False,
            )

        tool_review = ExecutionApprovalReview.create(
            approval_id="approval_01",
            execution_id="execution_01",
            activation_hash="1" * 64,
            grant_hash="2" * 64,
            private_input_hash="3" * 64,
            runtime_id="runtime_01",
            runtime_revision=1,
            runtime_content_hash="4" * 64,
            max_turns=1,
            max_tool_calls=0,
            max_total_tokens=1,
            max_cost_minor_units=None,
            currency=None,
            max_duration_ms=1,
            deadline_ms=None,
            tool_candidates=(),
        )
        with self.assertRaisesRegex(MemoryApprovalError, "memory_approval_review_invalid"):
            expired.prepare(tool_review, expected_generation=0)

    def test_concurrent_decisions_have_one_exact_winner(self) -> None:
        authority = InMemoryMemoryApprovalAuthority()
        review = _memory_review()
        authority.prepare(review, expected_generation=0)
        first = _memory_decision(review, reviewer_id="reviewer_first")
        second = _memory_decision(review, reviewer_id="reviewer_second")
        results: list[MemoryProjectionDecision] = []
        failures: list[MemoryApprovalError] = []
        gate = threading.Barrier(3)

        def decide(value: MemoryProjectionDecision) -> None:
            gate.wait()
            try:
                results.append(
                    authority.decide(
                        value,
                        expected_generation=0,
                        expected_review_hash=review.content_hash,
                    )
                )
            except MemoryApprovalError as exc:
                failures.append(exc)

        threads = [threading.Thread(target=decide, args=(value,)) for value in (first, second)]
        for thread in threads:
            thread.start()
        gate.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(1, len(results))
        self.assertEqual(["memory_approval_stale"], [item.reason_code for item in failures])
        self.assertIn(authority.snapshot(review).current_decision, (first, second))


class LosslessMemoryProjectionCompilerTests(unittest.TestCase):
    @staticmethod
    def _lineage() -> tuple[
        dict[str, object],
        dict[str, object],
        tuple[dict[str, object], ...],
        dict[str, object],
    ]:
        activation, grant, events, receipt_event, receipt = _terminal_records()
        return activation, grant, tuple([*events, receipt_event]), receipt

    @staticmethod
    def _review_for(
        source: InMemoryMemoryProposalSource,
        events: tuple[dict[str, object], ...],
        receipt: dict[str, object],
    ) -> MemoryProjectionReview:
        return MemoryProjectionReview.create(
            review_id="memory_review_01",
            execution_id=receipt["execution_id"],
            receipt_id=receipt["receipt_id"],
            receipt_content_hash=receipt["content_hash"],
            source_event_chain=tuple(
                (event["event_id"], event["content_hash"]) for event in events
            ),
            candidate_snapshot=source.snapshot(receipt["execution_id"]),
        )

    def test_compaction_is_hash_only_deterministic_and_insertion_order_independent(self) -> None:
        _activation, _grant, events, receipt = self._lineage()
        first_source = InMemoryMemoryProposalSource()
        second_source = InMemoryMemoryProposalSource()
        values = (
            ("decision", "combat_policy", {"mode": "turn_based"}),
            ("discovery", "world_fact", "RAW_MEMORY_SENTINEL"),
            ("constraint", "budget_limit", 4),
        )
        for source, ordered in ((first_source, values), (second_source, tuple(reversed(values)))):
            for kind, subject_id, value in ordered:
                source.propose(
                    execution_id=receipt["execution_id"],
                    kind=kind,
                    subject_id=subject_id,
                    value=value,
                )

        first_review = self._review_for(first_source, events, receipt)
        second_review = self._review_for(second_source, events, receipt)
        self.assertEqual(first_review, second_review)
        approved = tuple(item[0] for item in first_review.candidate_proposals)
        decision = _memory_decision(
            first_review,
            approved_proposal_ids=approved,
        )
        compiler = LosslessMemoryProjectionCompiler()

        first = compiler.compile(
            source=first_source,
            review=first_review,
            decision=decision,
            receipt=receipt,
            source_events=events,
        )
        second = compiler.compile(
            source=second_source,
            review=second_review,
            decision=decision,
            receipt=receipt,
            source_events=events,
        )

        self.assertEqual(first, second)
        self.assertEqual(
            first,
            validate_agent_harness_document(
                first,
                expected_format=AGENT_MEMORY_PROJECTION_FORMAT,
            ),
        )
        self.assertEqual(3, len(first["entries"]))
        self.assertEqual(
            sorted(
                (entry["entry_id"] for entry in first["entries"]),
                key=lambda item: item.encode("utf-8"),
            ),
            [entry["entry_id"] for entry in first["entries"]],
        )
        source_ids = sorted(
            (event["event_id"] for event in events),
            key=lambda item: item.encode("utf-8"),
        )
        self.assertEqual(source_ids, [item["id"] for item in first["source_events"]])
        self.assertTrue(all(entry["source_event_ids"] == source_ids for entry in first["entries"]))
        self.assertNotIn("RAW_MEMORY_SENTINEL", repr(first))
        self.assertNotIn("RAW_MEMORY_SENTINEL", str(first))

    def test_exact_duplicates_compact_once_and_unapproved_candidates_are_absent(self) -> None:
        _activation, _grant, events, receipt = self._lineage()
        source = InMemoryMemoryProposalSource()
        included = source.propose(
            execution_id=receipt["execution_id"],
            kind="preference",
            subject_id="camera_mode",
            value="fixed",
        )
        duplicate = source.propose(
            execution_id=receipt["execution_id"],
            kind="preference",
            subject_id="camera_mode",
            value="fixed",
        )
        excluded = source.propose(
            execution_id=receipt["execution_id"],
            kind="discovery",
            subject_id="optional_fact",
            value="not_approved",
        )
        review = self._review_for(source, events, receipt)
        decision = _memory_decision(review, approved_proposal_ids=(included.proposal_id,))

        projection = LosslessMemoryProjectionCompiler().compile(
            source=source,
            review=review,
            decision=decision,
            receipt=receipt,
            source_events=events,
        )

        self.assertEqual(included, duplicate)
        self.assertEqual(1, len(projection["entries"]))
        self.assertEqual(included.value_hash, projection["entries"][0]["value_hash"])
        self.assertNotEqual(excluded.value_hash, projection["entries"][0]["value_hash"])

    def test_multiple_approved_hashes_for_one_kind_and_subject_conflict(self) -> None:
        _activation, _grant, events, receipt = self._lineage()
        source = InMemoryMemoryProposalSource()
        source.propose(
            execution_id=receipt["execution_id"],
            kind="preference",
            subject_id="camera_mode",
            value="fixed",
        )
        source.propose(
            execution_id=receipt["execution_id"],
            kind="preference",
            subject_id="camera_mode",
            value="follow",
        )
        review = self._review_for(source, events, receipt)
        decision = _memory_decision(
            review,
            approved_proposal_ids=tuple(item[0] for item in review.candidate_proposals),
        )

        with self.assertRaisesRegex(MemoryProjectionError, "memory_projection_value_conflict"):
            LosslessMemoryProjectionCompiler().compile(
                source=source,
                review=review,
                decision=decision,
                receipt=receipt,
                source_events=events,
            )

    def test_compiler_rejects_stale_candidates_receipt_and_event_lineage(self) -> None:
        _activation, _grant, events, receipt = self._lineage()
        source = InMemoryMemoryProposalSource()
        included = source.propose(
            execution_id=receipt["execution_id"],
            kind="decision",
            subject_id="combat_policy",
            value="turn_based",
        )
        review = self._review_for(source, events, receipt)
        decision = _memory_decision(review, approved_proposal_ids=(included.proposal_id,))
        compiler = LosslessMemoryProjectionCompiler()

        source.propose(
            execution_id=receipt["execution_id"],
            kind="discovery",
            subject_id="late_candidate",
            value="late",
        )
        with self.assertRaisesRegex(MemoryProjectionError, "memory_projection_stale"):
            compiler.compile(
                source=source,
                review=review,
                decision=decision,
                receipt=receipt,
                source_events=events,
            )

        fresh_source = InMemoryMemoryProposalSource()
        fresh = fresh_source.propose(
            execution_id=receipt["execution_id"],
            kind="decision",
            subject_id="combat_policy",
            value="turn_based",
        )
        fresh_review = self._review_for(fresh_source, events, receipt)
        fresh_decision = _memory_decision(
            fresh_review,
            approved_proposal_ids=(fresh.proposal_id,),
        )
        changed_receipt = dict(receipt)
        changed_receipt["content_hash"] = "f" * 64
        for changed_events, changed in (
            (events, changed_receipt),
            (events[:-1], receipt),
            (tuple(reversed(events)), receipt),
        ):
            with self.subTest(
                event_count=len(changed_events),
                receipt_hash=changed["content_hash"],
            ):
                with self.assertRaises(MemoryProjectionError):
                    compiler.compile(
                        source=fresh_source,
                        review=fresh_review,
                        decision=fresh_decision,
                        receipt=changed,
                        source_events=changed_events,
                    )


class MemoryProjectionEventLogTests(unittest.TestCase):
    @staticmethod
    def _terminalize(
        log: AgentEventLog,
        *,
        outcome: str = "succeeded",
        request_fingerprint: str = "a" * 64,
    ) -> tuple[
        dict[str, object],
        dict[str, object],
        tuple[dict[str, object], ...],
        dict[str, object],
    ]:
        activation, grant, prefix, receipt_event, receipt = _terminal_records(outcome=outcome)
        log.begin_execution(
            activation["execution_id"],
            "log_durable_01",
            activation,
            grant,
            request_fingerprint=request_fingerprint,
        )
        for sequence, event in enumerate(prefix):
            log.append_event(
                activation["execution_id"],
                event,
                expected_sequence=sequence,
                expected_previous_hash=(
                    None if sequence == 0 else prefix[sequence - 1]["content_hash"]
                ),
                expected_generation=sequence,
            )
        log.finalize(
            activation["execution_id"],
            receipt,
            receipt_event,
            build_legacy_usage_accounting(receipt),
            expected_sequence=len(prefix),
            expected_previous_hash=prefix[-1]["content_hash"],
            expected_generation=len(prefix),
        )
        return activation, grant, tuple([*prefix, receipt_event]), receipt

    @staticmethod
    def _projection_records(
        activation: dict[str, object],
        events: tuple[dict[str, object], ...],
        receipt: dict[str, object],
    ) -> tuple[dict[str, object], dict[str, object], str]:
        source = InMemoryMemoryProposalSource()
        proposal = source.propose(
            execution_id=activation["execution_id"],
            kind="decision",
            subject_id="combat_policy",
            value={"mode": "turn_based"},
        )
        review = MemoryProjectionReview.create(
            review_id="memory_review_01",
            execution_id=activation["execution_id"],
            receipt_id=receipt["receipt_id"],
            receipt_content_hash=receipt["content_hash"],
            source_event_chain=tuple(
                (event["event_id"], event["content_hash"]) for event in events
            ),
            candidate_snapshot=source.snapshot(activation["execution_id"]),
        )
        decision = _memory_decision(
            review,
            approved_proposal_ids=(proposal.proposal_id,),
        )
        projection = LosslessMemoryProjectionCompiler().compile(
            source=source,
            review=review,
            decision=decision,
            receipt=receipt,
            source_events=events,
        )
        fingerprint = "f" * 64
        event = build_event(
            event_id=_memory_projection_event_id(fingerprint),
            log_id="log_durable_01",
            execution_id=activation["execution_id"],
            sequence=len(events),
            previous_event_hash=events[-1]["content_hash"],
            event_type="memory.projected",
            subject_format=AGENT_MEMORY_PROJECTION_FORMAT,
            subject_id=projection["projection_id"],
            subject_hash=projection["content_hash"],
        )
        return projection, event, fingerprint

    def test_projection_is_atomic_post_terminal_replayable_and_exact_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            activation, grant, events, receipt = self._terminalize(log)
            projection, event, fingerprint = self._projection_records(
                activation,
                events,
                receipt,
            )

            first = log.record_memory_projection(
                activation["execution_id"],
                projection,
                event,
                request_fingerprint=fingerprint,
                expected_sequence=len(events),
                expected_previous_hash=events[-1]["content_hash"],
                expected_generation=len(events),
            )
            second = log.record_memory_projection(
                activation["execution_id"],
                projection,
                event,
                request_fingerprint=fingerprint,
                expected_sequence=len(events),
                expected_previous_hash=events[-1]["content_hash"],
                expected_generation=len(events),
            )
            replay = log.replay_records(activation["execution_id"])

            self.assertEqual(projection, first)
            self.assertEqual(first, second)
            self.assertEqual("terminal", replay.state)
            self.assertEqual(len(events) + 1, replay.next_sequence)
            self.assertEqual(len(events) + 1, replay.generation)
            self.assertEqual(event["content_hash"], replay.head_hash)
            self.assertEqual(projection, json.loads(replay.projection_bytes))
            self.assertEqual(receipt, json.loads(replay.receipt_bytes))
            self.assertFalse(
                log.begin_execution(
                    activation["execution_id"],
                    "log_durable_01",
                    activation,
                    grant,
                    request_fingerprint="a" * 64,
                )
            )
            self.assertEqual(3, AGENT_EVENT_LOG_SCHEMA_VERSION)
            self.assertEqual(3, log.schema_version)
            validate_agent_harness_documents(
                activation,
                grant,
                [json.loads(item) for item in replay.event_bytes],
                receipt,
                projection,
            )
            stored = log.connection.execute(
                "SELECT request_fingerprint, projection_json FROM memory_projections"
            ).fetchone()
            self.assertEqual(fingerprint, stored["request_fingerprint"])
            self.assertEqual(replay.projection_bytes, stored["projection_json"])

    def test_exact_projection_retry_is_evidence_only_without_post_commit_hook(self) -> None:
        armed = False
        post_commit_calls = 0

        def fault(stage: str) -> None:
            nonlocal post_commit_calls
            if stage == "after_projection_commit" and armed:
                post_commit_calls += 1
                raise RuntimeError("unexpected duplicate commit hook")

        with (
            tempfile.TemporaryDirectory() as temporary,
            AgentEventLog(
                temporary,
                fault_hook=fault,
            ) as log,
        ):
            activation, _grant, events, receipt = self._terminalize(log)
            projection, event, fingerprint = self._projection_records(
                activation,
                events,
                receipt,
            )
            arguments = {
                "request_fingerprint": fingerprint,
                "expected_sequence": len(events),
                "expected_previous_hash": events[-1]["content_hash"],
                "expected_generation": len(events),
            }
            self.assertEqual(
                projection,
                log.record_memory_projection(
                    activation["execution_id"],
                    projection,
                    event,
                    **arguments,
                ),
            )
            before = log.replay_records(activation["execution_id"])
            armed = True

            self.assertEqual(
                projection,
                log.record_memory_projection(
                    activation["execution_id"],
                    projection,
                    event,
                    **arguments,
                ),
            )
            self.assertEqual(0, post_commit_calls)
            self.assertEqual(before, log.replay_records(activation["execution_id"]))

            with self.assertRaisesRegex(
                AgentEventLogConflict,
                "event_log_projection_conflict",
            ):
                log.record_memory_projection(
                    activation["execution_id"],
                    projection,
                    event,
                    **{**arguments, "expected_generation": len(events) + 1},
                )
            self.assertEqual(0, post_commit_calls)
            self.assertEqual(before, log.replay_records(activation["execution_id"]))

    def test_direct_injection_and_non_succeeded_projection_are_rejected(self) -> None:
        for outcome in ("failed", "cancelled"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                with AgentEventLog(temporary) as log:
                    activation, _grant, events, receipt = self._terminalize(log, outcome=outcome)
                    # The public projection itself refuses failed/cancelled receipts; use a
                    # valid succeeded fixture from another execution only to prove the store
                    # checks its own terminal outcome before any write.
                    good_activation, _good_grant, good_events, good_receipt = (
                        MemoryProjectionEventLogTests._standalone_succeeded_lineage()
                    )
                    projection, _event, fingerprint = self._projection_records(
                        good_activation,
                        good_events,
                        good_receipt,
                    )
                    projection = dict(projection)
                    projection["execution_id"] = activation["execution_id"]
                    with self.assertRaises(AgentEventLogConflict):
                        log.record_memory_projection(
                            activation["execution_id"],
                            projection,
                            build_event(
                                event_id=_memory_projection_event_id(fingerprint),
                                log_id="log_durable_01",
                                execution_id=activation["execution_id"],
                                sequence=len(events),
                                previous_event_hash=events[-1]["content_hash"],
                                event_type="memory.projected",
                                subject_format=AGENT_MEMORY_PROJECTION_FORMAT,
                                subject_id="projection_rejected",
                                subject_hash="f" * 64,
                            ),
                            request_fingerprint=fingerprint,
                            expected_sequence=len(events),
                            expected_previous_hash=events[-1]["content_hash"],
                            expected_generation=len(events),
                        )
                    self.assertIsNone(
                        log.replay_records(activation["execution_id"]).projection_bytes
                    )

        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            activation, _grant, events, receipt = self._terminalize(log)
            projection, event, _fingerprint = self._projection_records(
                activation,
                events,
                receipt,
            )
            with self.assertRaisesRegex(AgentEventLogConflict, "event_log_lifecycle_conflict"):
                log.append_event(
                    activation["execution_id"],
                    event,
                    expected_sequence=len(events),
                    expected_previous_hash=events[-1]["content_hash"],
                    expected_generation=len(events),
                )
            self.assertIsNone(log.replay_records(activation["execution_id"]).projection_bytes)

    def test_privileged_record_rejects_projection_that_omits_terminal_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            activation, _grant, events, receipt = self._terminalize(log)
            projection, _event, fingerprint = self._projection_records(
                activation,
                events,
                receipt,
            )
            retained_source = dict(projection["source_events"][0])
            changed_projection = {
                **projection,
                "source_events": [retained_source],
                "entries": [
                    {
                        **entry,
                        "source_event_ids": [retained_source["id"]],
                    }
                    for entry in projection["entries"]
                ],
            }
            changed_projection["content_hash"] = canonical_agent_harness_hash(changed_projection)
            changed_event = build_event(
                event_id=_memory_projection_event_id(fingerprint),
                log_id="log_durable_01",
                execution_id=activation["execution_id"],
                sequence=len(events),
                previous_event_hash=events[-1]["content_hash"],
                event_type="memory.projected",
                subject_format=AGENT_MEMORY_PROJECTION_FORMAT,
                subject_id=changed_projection["projection_id"],
                subject_hash=changed_projection["content_hash"],
            )
            before = log.replay_records(activation["execution_id"])

            with self.assertRaisesRegex(
                AgentEventLogConflict,
                "event_log_lifecycle_conflict",
            ):
                log.record_memory_projection(
                    activation["execution_id"],
                    changed_projection,
                    changed_event,
                    request_fingerprint=fingerprint,
                    expected_sequence=len(events),
                    expected_previous_hash=events[-1]["content_hash"],
                    expected_generation=len(events),
                )

            self.assertEqual(before, log.replay_records(activation["execution_id"]))

    @staticmethod
    def _standalone_succeeded_lineage() -> tuple[
        dict[str, object],
        dict[str, object],
        tuple[dict[str, object], ...],
        dict[str, object],
    ]:
        activation, grant, prefix, receipt_event, receipt = _terminal_records()
        return activation, grant, tuple([*prefix, receipt_event]), receipt

    def test_projection_duplicate_conflicts_on_any_changed_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            activation, _grant, events, receipt = self._terminalize(log)
            projection, event, fingerprint = self._projection_records(
                activation,
                events,
                receipt,
            )
            log.record_memory_projection(
                activation["execution_id"],
                projection,
                event,
                request_fingerprint=fingerprint,
                expected_sequence=len(events),
                expected_previous_hash=events[-1]["content_hash"],
                expected_generation=len(events),
            )
            changed_projection = dict(projection)
            changed_projection["projection_id"] = "projection_changed"
            changed_projection["content_hash"] = canonical_agent_harness_hash(changed_projection)
            for values in (
                dict(request_fingerprint="e" * 64),
                dict(projection=changed_projection),
                dict(expected_previous_hash="d" * 64),
                dict(expected_generation=len(events) + 1),
                dict(expected_sequence=len(events) + 1),
            ):
                arguments = {
                    "projection": projection,
                    "event": event,
                    "request_fingerprint": fingerprint,
                    "expected_sequence": len(events),
                    "expected_previous_hash": events[-1]["content_hash"],
                    "expected_generation": len(events),
                }
                arguments.update(values)
                with self.subTest(values=values):
                    with self.assertRaises(AgentEventLogConflict):
                        log.record_memory_projection(
                            activation["execution_id"],
                            **arguments,
                        )

    def test_projection_faults_are_atomic_or_exactly_reconciled(self) -> None:
        stages = (
            "before_projection_table_insert",
            "after_projection_table_insert",
            "before_projection_event_insert",
            "after_projection_event_insert",
            "before_projection_state_update",
            "after_projection_state_update",
            "before_projection_commit",
            "after_projection_commit",
        )
        for stage in stages:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                fired = False

                def fault(current: str, selected_stage: str = stage) -> None:
                    nonlocal fired
                    if current == selected_stage and not fired:
                        fired = True
                        raise RuntimeError(selected_stage)

                with AgentEventLog(temporary, fault_hook=fault) as log:
                    activation, _grant, events, receipt = self._terminalize(log)
                    projection, event, fingerprint = self._projection_records(
                        activation,
                        events,
                        receipt,
                    )
                    if stage == "after_projection_commit":
                        result = log.record_memory_projection(
                            activation["execution_id"],
                            projection,
                            event,
                            request_fingerprint=fingerprint,
                            expected_sequence=len(events),
                            expected_previous_hash=events[-1]["content_hash"],
                            expected_generation=len(events),
                        )
                        self.assertEqual(projection, result)
                        self.assertEqual(
                            projection,
                            json.loads(
                                log.replay_records(activation["execution_id"]).projection_bytes
                            ),
                        )
                    else:
                        with self.assertRaisesRegex(
                            AgentEventLogIndeterminate,
                            "event_log_projection_indeterminate",
                        ):
                            log.record_memory_projection(
                                activation["execution_id"],
                                projection,
                                event,
                                request_fingerprint=fingerprint,
                                expected_sequence=len(events),
                                expected_previous_hash=events[-1]["content_hash"],
                                expected_generation=len(events),
                            )
                        replay = log.replay_records(activation["execution_id"])
                        self.assertIsNone(replay.projection_bytes)
                        self.assertEqual(len(events), replay.next_sequence)

    def test_projection_domain_faults_reconcile_and_control_signals_propagate(self) -> None:
        for stage in ("before_projection_commit", "after_projection_commit"):
            with self.subTest(kind="domain", stage=stage), tempfile.TemporaryDirectory() as root:
                fired = False

                def domain_fault(current: str, selected: str = stage) -> None:
                    nonlocal fired
                    if current == selected and not fired:
                        fired = True
                        raise AgentEventLogCorrupt("fault_hook_agent_error")

                with AgentEventLog(root, fault_hook=domain_fault) as log:
                    activation, _grant, events, receipt = self._terminalize(log)
                    projection, event, fingerprint = self._projection_records(
                        activation,
                        events,
                        receipt,
                    )
                    arguments = {
                        "request_fingerprint": fingerprint,
                        "expected_sequence": len(events),
                        "expected_previous_hash": events[-1]["content_hash"],
                        "expected_generation": len(events),
                    }
                    if stage == "after_projection_commit":
                        self.assertEqual(
                            projection,
                            log.record_memory_projection(
                                activation["execution_id"],
                                projection,
                                event,
                                **arguments,
                            ),
                        )
                        self.assertEqual(
                            projection,
                            json.loads(
                                log.replay_records(activation["execution_id"]).projection_bytes
                            ),
                        )
                    else:
                        with self.assertRaisesRegex(
                            AgentEventLogIndeterminate,
                            "event_log_projection_indeterminate",
                        ):
                            log.record_memory_projection(
                                activation["execution_id"],
                                projection,
                                event,
                                **arguments,
                            )
                        self.assertIsNone(
                            log.replay_records(activation["execution_id"]).projection_bytes
                        )

        class ControlSignal(BaseException):
            pass

        for stage in ("before_projection_commit", "after_projection_commit"):
            with self.subTest(kind="base", stage=stage), tempfile.TemporaryDirectory() as root:
                signal = ControlSignal(stage)
                fired = False

                def control_fault(
                    current: str,
                    selected: str = stage,
                    selected_signal: BaseException = signal,
                ) -> None:
                    nonlocal fired
                    if current == selected and not fired:
                        fired = True
                        raise selected_signal

                with AgentEventLog(root, fault_hook=control_fault) as log:
                    activation, _grant, events, receipt = self._terminalize(log)
                    projection, event, fingerprint = self._projection_records(
                        activation,
                        events,
                        receipt,
                    )
                    with self.assertRaises(ControlSignal) as raised:
                        log.record_memory_projection(
                            activation["execution_id"],
                            projection,
                            event,
                            request_fingerprint=fingerprint,
                            expected_sequence=len(events),
                            expected_previous_hash=events[-1]["content_hash"],
                            expected_generation=len(events),
                        )
                    self.assertIs(signal, raised.exception)
                    replay = log.replay_records(activation["execution_id"])
                    self.assertEqual(
                        stage == "after_projection_commit",
                        replay.projection_bytes is not None,
                    )

    def test_exact_finalize_retry_after_projection_is_evidence_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            activation, _grant, events, receipt = self._terminalize(log)
            projection, projection_event, fingerprint = self._projection_records(
                activation,
                events,
                receipt,
            )
            log.record_memory_projection(
                activation["execution_id"],
                projection,
                projection_event,
                request_fingerprint=fingerprint,
                expected_sequence=len(events),
                expected_previous_hash=events[-1]["content_hash"],
                expected_generation=len(events),
            )
            before = log.replay_records(activation["execution_id"])
            terminal_event = events[-1]

            log.finalize(
                activation["execution_id"],
                receipt,
                terminal_event,
                build_legacy_usage_accounting(receipt),
                expected_sequence=len(events) - 1,
                expected_previous_hash=events[-2]["content_hash"],
                expected_generation=len(events) - 1,
            )
            self.assertEqual(before, log.replay_records(activation["execution_id"]))

            changed_event = build_event(
                event_id="durable_event_conflicting_retry",
                log_id=terminal_event["log_id"],
                execution_id=activation["execution_id"],
                sequence=len(events) - 1,
                previous_event_hash=events[-2]["content_hash"],
                event_type="execution.receipt_recorded",
                subject_format=terminal_event["subject"]["format"],
                subject_id=terminal_event["subject"]["id"],
                subject_hash=terminal_event["subject"]["content_hash"],
            )
            changed_receipt = {**receipt, "receipt_id": "receipt_conflicting_retry"}
            changed_receipt["content_hash"] = canonical_agent_harness_hash(changed_receipt)
            for conflicting_receipt, conflicting_event in (
                (receipt, changed_event),
                (changed_receipt, terminal_event),
            ):
                with self.subTest(
                    receipt_id=conflicting_receipt["receipt_id"],
                    event_id=conflicting_event["event_id"],
                ):
                    with self.assertRaisesRegex(
                        AgentEventLogConflict,
                        "event_log_finalize_conflict",
                    ):
                        log.finalize(
                            activation["execution_id"],
                            conflicting_receipt,
                            conflicting_event,
                            build_legacy_usage_accounting(conflicting_receipt),
                            expected_sequence=len(events) - 1,
                            expected_previous_hash=events[-2]["content_hash"],
                            expected_generation=len(events) - 1,
                        )
            self.assertEqual(before, log.replay_records(activation["execution_id"]))

    def test_exact_finalize_retry_after_projection_skips_commit_fault_boundary(self) -> None:
        armed = False
        crossed: list[str] = []

        def fault(stage: str) -> None:
            if armed and stage == "after_finalize_commit":
                crossed.append(stage)
                raise RuntimeError(stage)

        with (
            tempfile.TemporaryDirectory() as temporary,
            AgentEventLog(
                temporary,
                fault_hook=fault,
            ) as log,
        ):
            activation, _grant, events, receipt = self._terminalize(log)
            projection, projection_event, fingerprint = self._projection_records(
                activation,
                events,
                receipt,
            )
            log.record_memory_projection(
                activation["execution_id"],
                projection,
                projection_event,
                request_fingerprint=fingerprint,
                expected_sequence=len(events),
                expected_previous_hash=events[-1]["content_hash"],
                expected_generation=len(events),
            )
            before = log.replay_records(activation["execution_id"])
            armed = True

            log.finalize(
                activation["execution_id"],
                receipt,
                events[-1],
                build_legacy_usage_accounting(receipt),
                expected_sequence=len(events) - 1,
                expected_previous_hash=events[-2]["content_hash"],
                expected_generation=len(events) - 1,
            )

            self.assertEqual([], crossed)
            self.assertEqual(before, log.replay_records(activation["execution_id"]))

    @staticmethod
    def _downgrade_exact_v1(root: Path) -> None:
        connection = sqlite3.connect(root / AGENT_EVENT_LOG_DATABASE_NAME)
        try:
            connection.execute("DROP TABLE usage_accounting")
            connection.execute("DROP TABLE memory_projections")
            connection.execute("UPDATE schema_meta SET value = '1' WHERE key = 'schema_version'")
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            connection.close()

    @staticmethod
    def _downgrade_exact_v2(root: Path) -> None:
        connection = sqlite3.connect(root / AGENT_EVENT_LOG_DATABASE_NAME)
        try:
            connection.execute("DROP TABLE usage_accounting")
            connection.execute("UPDATE schema_meta SET value = '2' WHERE key = 'schema_version'")
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            connection.close()

    @staticmethod
    def _byte_evidence(root: Path) -> dict[str, bytes]:
        return {
            path.name: path.read_bytes()
            for path in sorted(root.iterdir(), key=lambda item: item.name)
        }

    def test_exact_v1_ordinary_open_migrates_transactionally_to_v3(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root) as log:
                activation, _grant, events, receipt = self._terminalize(log)
                before = log.replay_records(activation["execution_id"])
            self._downgrade_exact_v1(root)
            raw = sqlite3.connect(root / AGENT_EVENT_LOG_DATABASE_NAME)
            try:
                self.assertEqual(
                    "1",
                    raw.execute(
                        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                    ).fetchone()[0],
                )
                self.assertIsNone(
                    raw.execute(
                        "SELECT name FROM sqlite_schema WHERE name = 'memory_projections'"
                    ).fetchone()
                )
            finally:
                raw.close()

            with AgentEventLog(root) as migrated:
                self.assertEqual(3, migrated.schema_version)
                replay = migrated.replay_records(activation["execution_id"])
                self.assertEqual(before, replay)
                self.assertIsNone(replay.projection_bytes)
                self.assertEqual(len(events), replay.next_sequence)
                self.assertEqual(receipt, json.loads(replay.receipt_bytes))
                self.assertIsNotNone(
                    migrated.connection.execute(
                        "SELECT name FROM sqlite_schema WHERE name = 'memory_projections'"
                    ).fetchone()
                )
                self.assertIsNotNone(replay.usage_accounting_bytes)

    def test_v1_recovery_open_is_accepted_and_byte_preserving_without_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root) as log:
                activation, _grant, _events, _receipt = self._terminalize(log)
            self._downgrade_exact_v1(root)
            before = self._byte_evidence(root)

            with AgentEventLog.recovery(root) as recovery:
                self.assertEqual(1, recovery.schema_version)
                replay = recovery.replay_records(activation["execution_id"])
                self.assertEqual("terminal", replay.state)
                self.assertIsNone(replay.projection_bytes)

            self.assertEqual(before, self._byte_evidence(root))
            raw = sqlite3.connect(root / AGENT_EVENT_LOG_DATABASE_NAME)
            try:
                self.assertEqual(
                    "1",
                    raw.execute(
                        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                    ).fetchone()[0],
                )
                self.assertIsNone(
                    raw.execute(
                        "SELECT name FROM sqlite_schema WHERE name = 'memory_projections'"
                    ).fetchone()
                )
            finally:
                raw.close()

    def test_exact_v2_terminal_migrates_to_v3_with_conservative_accounting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root) as log:
                activation, _grant, _events, receipt = self._terminalize(log)
            self._downgrade_exact_v2(root)

            with AgentEventLog(root) as migrated:
                self.assertEqual(3, migrated.schema_version)
                replay = migrated.replay_records(activation["execution_id"])
                accounting = json.loads(replay.usage_accounting_bytes)
                self.assertEqual("legacy_receipt_totals", accounting["record_mode"])
                self.assertEqual(receipt["content_hash"], accounting["receipt_hash"])
                self.assertNotIn("observed", replay.usage_accounting_bytes.decode("utf-8"))

    def test_recovery_reads_preserve_v1_v2_wal_and_reject_hot_journal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v1-wal"
            with AgentEventLog(root) as log:
                activation, _grant, _events, _receipt = self._terminalize(log)
                database = log.database_path
            self._downgrade_exact_v1(root)
            _commit_wal_then_crash(database, "valid")
            before = _store_byte_evidence(root)
            parent_namespace = {path.name for path in root.parent.iterdir()}
            with AgentEventLog.recovery(root) as recovery:
                self.assertEqual(1, recovery.schema_version)
                replay = recovery.replay_records(activation["execution_id"])
                self.assertEqual("terminal", replay.state)
                self.assertIsNone(replay.projection_bytes)
                self.assertEqual((), recovery.list_open(limit=10))
                self.assertEqual(before, _store_byte_evidence(root))
            self.assertEqual(before, _store_byte_evidence(root))
            self.assertEqual(parent_namespace, {path.name for path in root.parent.iterdir()})

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v2-wal"
            with AgentEventLog(root) as log:
                activation, _grant, events, receipt = self._terminalize(log)
                projection, event, fingerprint = self._projection_records(
                    activation,
                    events,
                    receipt,
                )
                log.record_memory_projection(
                    activation["execution_id"],
                    projection,
                    event,
                    request_fingerprint=fingerprint,
                    expected_sequence=len(events),
                    expected_previous_hash=events[-1]["content_hash"],
                    expected_generation=len(events),
                )
                database = log.database_path
            self._downgrade_exact_v2(root)
            _commit_wal_then_crash(database, "valid")
            before = _store_byte_evidence(root)
            parent_namespace = {path.name for path in root.parent.iterdir()}
            with AgentEventLog.recovery(root) as recovery:
                self.assertEqual(2, recovery.schema_version)
                replay = recovery.replay_records(activation["execution_id"])
                self.assertEqual(projection, json.loads(replay.projection_bytes))
                self.assertEqual((), recovery.list_open(limit=10))
                self.assertEqual(before, _store_byte_evidence(root))
            self.assertEqual(before, _store_byte_evidence(root))
            self.assertEqual(parent_namespace, {path.name for path in root.parent.iterdir()})

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v3-hot-journal"
            with AgentEventLog(root) as log:
                self._terminalize(log)
                database = log.database_path
            _leave_hot_rollback_journal_then_crash(database)
            before = _store_byte_evidence(root)
            parent_namespace = {path.name for path in root.parent.iterdir()}
            with self.assertRaisesRegex(
                AgentEventLogError,
                "event_log_recovery_rollback_journal_unsupported",
            ):
                AgentEventLog.recovery(root)
            self.assertEqual(before, _store_byte_evidence(root))
            self.assertEqual(parent_namespace, {path.name for path in root.parent.iterdir()})

    def test_v1_migration_fault_rolls_back_without_partial_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root):
                pass
            self._downgrade_exact_v1(root)

            def fault(stage: str) -> None:
                if stage == "before_schema_v3_migration_commit":
                    raise RuntimeError(stage)

            with self.assertRaisesRegex(RuntimeError, "before_schema_v3_migration_commit"):
                AgentEventLog(root, fault_hook=fault)

            raw = sqlite3.connect(root / AGENT_EVENT_LOG_DATABASE_NAME)
            try:
                self.assertEqual(
                    "1",
                    raw.execute(
                        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                    ).fetchone()[0],
                )
                self.assertIsNone(
                    raw.execute(
                        "SELECT name FROM sqlite_schema WHERE name = 'memory_projections'"
                    ).fetchone()
                )
            finally:
                raw.close()

            with AgentEventLog(root) as migrated:
                self.assertEqual(3, migrated.schema_version)

    def test_projection_table_event_and_state_tamper_fail_replay(self) -> None:
        mutations = {
            "projection_hash": (
                "UPDATE memory_projections SET projection_hash = ?",
                ("e" * 64,),
            ),
            "projection_json": (
                "UPDATE memory_projections SET projection_json = ?",
                (sqlite3.Binary(b"{}"),),
            ),
            "projection_event": (
                "UPDATE events SET event_hash = ? WHERE sequence = 4",
                ("e" * 64,),
            ),
            "projection_state": (
                "UPDATE executions SET head_hash = ?",
                ("e" * 64,),
            ),
            "projection_missing": ("DELETE FROM memory_projections", ()),
        }
        for name, (statement, parameters) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "store"
                with AgentEventLog(root) as log:
                    activation, _grant, events, receipt = self._terminalize(log)
                    projection, event, fingerprint = self._projection_records(
                        activation,
                        events,
                        receipt,
                    )
                    log.record_memory_projection(
                        activation["execution_id"],
                        projection,
                        event,
                        request_fingerprint=fingerprint,
                        expected_sequence=len(events),
                        expected_previous_hash=events[-1]["content_hash"],
                        expected_generation=len(events),
                    )
                raw = sqlite3.connect(root / AGENT_EVENT_LOG_DATABASE_NAME)
                try:
                    raw.execute(statement, parameters)
                    raw.commit()
                finally:
                    raw.close()
                with AgentEventLog(root) as reopened:
                    with self.assertRaises(AgentEventLogCorrupt):
                        reopened.replay_records(activation["execution_id"])

    def test_recovery_rejects_physically_swapped_projection_indexes_without_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root) as log:
                activation, _grant, events, receipt = self._terminalize(log)
                projection, event, fingerprint = self._projection_records(
                    activation,
                    events,
                    receipt,
                )
                log.record_memory_projection(
                    activation["execution_id"],
                    projection,
                    event,
                    request_fingerprint=fingerprint,
                    expected_sequence=len(events),
                    expected_previous_hash=events[-1]["content_hash"],
                    expected_generation=len(events),
                )
                database = log.database_path

            raw = sqlite3.connect(database)
            try:
                rootpages = dict(
                    raw.execute(
                        "SELECT name, rootpage FROM sqlite_schema WHERE name IN (?, ?)",
                        (
                            "sqlite_autoindex_memory_projections_2",
                            "sqlite_autoindex_memory_projections_3",
                        ),
                    )
                )
                self.assertEqual(2, len(rootpages))
                raw.execute("PRAGMA writable_schema = ON")
                raw.execute(
                    "UPDATE sqlite_schema SET rootpage = ? WHERE name = ?",
                    (
                        rootpages["sqlite_autoindex_memory_projections_3"],
                        "sqlite_autoindex_memory_projections_2",
                    ),
                )
                raw.execute(
                    "UPDATE sqlite_schema SET rootpage = ? WHERE name = ?",
                    (
                        rootpages["sqlite_autoindex_memory_projections_2"],
                        "sqlite_autoindex_memory_projections_3",
                    ),
                )
                raw.commit()
            finally:
                raw.close()
            before = {
                path.name: (path.stat().st_ino, path.stat().st_size, path.read_bytes())
                for path in root.iterdir()
            }

            with self.assertRaisesRegex(AgentEventLogCorrupt, "event_log_storage_corrupt"):
                AgentEventLog.recovery(root)

            self.assertEqual(
                before,
                {
                    path.name: (path.stat().st_ino, path.stat().st_size, path.read_bytes())
                    for path in root.iterdir()
                },
            )

    def test_concurrent_exact_recording_has_one_projection_and_one_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root) as log:
                activation, _grant, events, receipt = self._terminalize(log)
            projection, event, fingerprint = self._projection_records(
                activation,
                events,
                receipt,
            )
            results: list[dict[str, object]] = []
            failures: list[BaseException] = []
            gate = threading.Barrier(3)

            def record() -> None:
                try:
                    with AgentEventLog(root) as thread_log:
                        gate.wait()
                        results.append(
                            thread_log.record_memory_projection(
                                activation["execution_id"],
                                projection,
                                event,
                                request_fingerprint=fingerprint,
                                expected_sequence=len(events),
                                expected_previous_hash=events[-1]["content_hash"],
                                expected_generation=len(events),
                            )
                        )
                except BaseException as exc:
                    failures.append(exc)

            threads = [threading.Thread(target=record) for _ in range(2)]
            for thread in threads:
                thread.start()
            gate.wait()
            for thread in threads:
                thread.join(timeout=10)

            self.assertEqual([], failures)
            self.assertEqual([projection, projection], results)
            with AgentEventLog(root) as verified:
                replay = verified.replay_records(activation["execution_id"])
                projected_events = [
                    item for item in replay.event_bytes if b"memory.projected" in item
                ]
                self.assertEqual(1, len(projected_events))
                self.assertEqual(
                    1,
                    verified.connection.execute(
                        "SELECT COUNT(*) FROM memory_projections"
                    ).fetchone()[0],
                )

    def test_raw_candidate_never_reaches_sqlite_sidecars_or_public_evidence(self) -> None:
        sentinel = b"RAW_MEMORY_SENTINEL_7d93"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root) as log:
                activation, _grant, events, receipt = self._terminalize(log)
                source = InMemoryMemoryProposalSource()
                proposal = source.propose(
                    execution_id=activation["execution_id"],
                    kind="discovery",
                    subject_id="private_fact",
                    value=sentinel.decode("ascii"),
                )
                review = MemoryProjectionReview.create(
                    review_id="memory_review_01",
                    execution_id=activation["execution_id"],
                    receipt_id=receipt["receipt_id"],
                    receipt_content_hash=receipt["content_hash"],
                    source_event_chain=tuple(
                        (item["event_id"], item["content_hash"]) for item in events
                    ),
                    candidate_snapshot=source.snapshot(activation["execution_id"]),
                )
                decision = _memory_decision(
                    review,
                    approved_proposal_ids=(proposal.proposal_id,),
                )
                projection = LosslessMemoryProjectionCompiler().compile(
                    source=source,
                    review=review,
                    decision=decision,
                    receipt=receipt,
                    source_events=events,
                )
                event = build_event(
                    event_id=_memory_projection_event_id("f" * 64),
                    log_id="log_durable_01",
                    execution_id=activation["execution_id"],
                    sequence=len(events),
                    previous_event_hash=events[-1]["content_hash"],
                    event_type="memory.projected",
                    subject_format=AGENT_MEMORY_PROJECTION_FORMAT,
                    subject_id=projection["projection_id"],
                    subject_hash=projection["content_hash"],
                )
                log.record_memory_projection(
                    activation["execution_id"],
                    projection,
                    event,
                    request_fingerprint="f" * 64,
                    expected_sequence=len(events),
                    expected_previous_hash=events[-1]["content_hash"],
                    expected_generation=len(events),
                )
                log.connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchall()
                self.assertNotIn(sentinel.decode("ascii"), repr(projection))
                self.assertNotIn(sentinel.decode("ascii"), repr(review))
                self.assertNotIn(sentinel.decode("ascii"), repr(decision))
                for path in root.iterdir():
                    self.assertNotIn(sentinel, path.read_bytes(), path.name)


class MemoryProjectionCoordinatorTests(unittest.TestCase):
    @staticmethod
    def _source(execution_id: str) -> InMemoryMemoryProposalSource:
        source = InMemoryMemoryProposalSource()
        source.propose(
            execution_id=execution_id,
            kind="decision",
            subject_id="combat_policy",
            value={"mode": "turn_based"},
        )
        source.propose(
            execution_id=execution_id,
            kind="discovery",
            subject_id="world_fact",
            value="gate_closed",
        )
        return source

    def test_prepare_review_then_approved_project_records_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            activation, grant, events, receipt = MemoryProjectionEventLogTests._terminalize(log)
            source = self._source(activation["execution_id"])
            authority = InMemoryMemoryApprovalAuthority()
            coordinator = MemoryProjectionCoordinator(
                source=source,
                approval_authority=authority,
                event_log=log,
            )

            review = coordinator.prepare_review(
                activation["execution_id"],
                review_id="memory_review_01",
            )
            self.assertEqual(
                tuple((item["event_id"], item["content_hash"]) for item in events),
                review.source_event_chain,
            )
            decision = _memory_decision(
                review,
                approved_proposal_ids=tuple(
                    proposal_id for proposal_id, _hash in review.candidate_proposals
                ),
            )
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            snapshot = authority.snapshot(review)

            first = coordinator.project(
                review,
                expected_approval=snapshot,
                now_ms=1_999,
            )
            before_duplicate = log.replay_records(activation["execution_id"])
            second = coordinator.project(
                review,
                expected_approval=snapshot,
                now_ms=1_999,
            )
            after_duplicate = log.replay_records(activation["execution_id"])

            self.assertEqual(first, second)
            self.assertEqual(before_duplicate, after_duplicate)
            self.assertEqual(first, json.loads(after_duplicate.projection_bytes))
            self.assertEqual(receipt, json.loads(after_duplicate.receipt_bytes))
            validate_agent_harness_documents(
                activation,
                grant,
                [json.loads(item) for item in after_duplicate.event_bytes],
                receipt,
                first,
            )

    def test_prepare_rejects_non_succeeded_states_without_effects(self) -> None:
        for state in ("open", "failed", "cancelled", "recovery_required"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "store"
                log = AgentEventLog(root)
                activation: dict[str, object]
                if state == "open" or state == "recovery_required":
                    activation, grant, _prefix, _receipt_event, _receipt = _terminal_records()
                    log.begin_execution(
                        activation["execution_id"],
                        "log_durable_01",
                        activation,
                        grant,
                        request_fingerprint="a" * 64,
                    )
                    log.close()
                    if state == "recovery_required":
                        with AgentEventLog.recovery(root) as recovery:
                            recovery.mark_recovery_required(
                                activation["execution_id"],
                                expected_sequence=0,
                                expected_previous_hash=None,
                                expected_generation=0,
                            )
                    log = AgentEventLog(root)
                else:
                    activation, _grant, _events, _receipt = (
                        MemoryProjectionEventLogTests._terminalize(log, outcome=state)
                    )
                self.addCleanup(log.close)
                source = self._source(activation["execution_id"])
                coordinator = MemoryProjectionCoordinator(
                    source=source,
                    approval_authority=InMemoryMemoryApprovalAuthority(),
                    event_log=log,
                )
                before = log.replay_records(activation["execution_id"])
                with self.assertRaises(MemoryProjectionError):
                    coordinator.prepare_review(
                        activation["execution_id"],
                        review_id="memory_review_01",
                    )
                after = log.replay_records(activation["execution_id"])
                self.assertEqual(before, after)
                self.assertIsNone(after.projection_bytes)

    def test_project_checks_exact_snapshot_revocation_expiry_and_candidate_staleness(self) -> None:
        scenarios = ("revoked", "expired", "stale_candidate")
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                with AgentEventLog(temporary) as log:
                    activation, _grant, _events, _receipt = (
                        MemoryProjectionEventLogTests._terminalize(log)
                    )
                    source = self._source(activation["execution_id"])
                    authority = InMemoryMemoryApprovalAuthority()
                    coordinator = MemoryProjectionCoordinator(
                        source=source,
                        approval_authority=authority,
                        event_log=log,
                    )
                    review = coordinator.prepare_review(
                        activation["execution_id"],
                        review_id="memory_review_01",
                    )
                    decision = _memory_decision(review)
                    authority.decide(
                        decision,
                        expected_generation=0,
                        expected_review_hash=review.content_hash,
                    )
                    snapshot = authority.snapshot(review)
                    now = 1_999
                    if scenario == "revoked":
                        authority.revoke(
                            review.review_id,
                            expected_generation=1,
                            expected_decision_hash=decision.content_hash,
                        )
                    elif scenario == "expired":
                        now = 2_000
                    else:
                        source.propose(
                            execution_id=activation["execution_id"],
                            kind="preference",
                            subject_id="late_candidate",
                            value="late",
                        )
                    before = log.replay_records(activation["execution_id"])
                    with self.assertRaises((MemoryProjectionError, MemoryApprovalError)):
                        coordinator.project(
                            review,
                            expected_approval=snapshot,
                            now_ms=now,
                        )
                    after = log.replay_records(activation["execution_id"])
                    self.assertEqual(before, after)
                    self.assertIsNone(after.projection_bytes)

    def test_project_holds_approval_and_candidate_snapshots_through_atomic_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root) as setup_log:
                activation, _grant, _events, _receipt = MemoryProjectionEventLogTests._terminalize(
                    setup_log
                )
            source = self._source(activation["execution_id"])
            authority = InMemoryMemoryApprovalAuthority()
            with AgentEventLog(root) as review_log:
                review_coordinator = MemoryProjectionCoordinator(
                    source=source,
                    approval_authority=authority,
                    event_log=review_log,
                )
                review = review_coordinator.prepare_review(
                    activation["execution_id"],
                    review_id="memory_review_01",
                )
            decision = _memory_decision(review)
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            snapshot = authority.snapshot(review)
            at_commit = threading.Event()
            release_commit = threading.Event()
            revoke_started = threading.Event()
            revoke_finished = threading.Event()
            proposal_started = threading.Event()
            proposal_finished = threading.Event()
            projection_results: list[dict[str, object]] = []
            failures: list[BaseException] = []

            def fault(stage: str) -> None:
                if stage == "before_projection_commit":
                    at_commit.set()
                    if not release_commit.wait(timeout=5):
                        raise RuntimeError("projection_test_timeout")

            def project() -> None:
                try:
                    with AgentEventLog(root, fault_hook=fault) as project_log:
                        projection_results.append(
                            MemoryProjectionCoordinator(
                                source=source,
                                approval_authority=authority,
                                event_log=project_log,
                            ).project(
                                review,
                                expected_approval=snapshot,
                                now_ms=1_999,
                            )
                        )
                except BaseException as exc:
                    failures.append(exc)

            def revoke() -> None:
                revoke_started.set()
                try:
                    authority.revoke(
                        review.review_id,
                        expected_generation=1,
                        expected_decision_hash=decision.content_hash,
                    )
                except BaseException as exc:
                    failures.append(exc)
                finally:
                    revoke_finished.set()

            def add_proposal() -> None:
                proposal_started.set()
                try:
                    source.propose(
                        execution_id=activation["execution_id"],
                        kind="preference",
                        subject_id="late_candidate",
                        value="late",
                    )
                except BaseException as exc:
                    failures.append(exc)
                finally:
                    proposal_finished.set()

            project_thread = threading.Thread(target=project)
            project_thread.start()
            self.assertTrue(at_commit.wait(timeout=5))
            revoke_thread = threading.Thread(target=revoke)
            proposal_thread = threading.Thread(target=add_proposal)
            revoke_thread.start()
            proposal_thread.start()
            self.assertTrue(revoke_started.wait(timeout=5))
            self.assertTrue(proposal_started.wait(timeout=5))
            self.assertFalse(revoke_finished.wait(timeout=0.05))
            self.assertFalse(proposal_finished.wait(timeout=0.05))

            release_commit.set()
            for thread in (project_thread, revoke_thread, proposal_thread):
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

            self.assertEqual([], failures)
            self.assertEqual(1, len(projection_results))
            self.assertTrue(revoke_finished.is_set())
            self.assertTrue(proposal_finished.is_set())
            with AgentEventLog(root) as verified:
                replay = verified.replay_records(activation["execution_id"])
                self.assertEqual(
                    projection_results[0],
                    json.loads(replay.projection_bytes),
                )

    def test_project_conflicts_if_durable_projection_fingerprint_is_changed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            activation, _grant, _events, _receipt = MemoryProjectionEventLogTests._terminalize(log)
            source = self._source(activation["execution_id"])
            authority = InMemoryMemoryApprovalAuthority()
            coordinator = MemoryProjectionCoordinator(
                source=source,
                approval_authority=authority,
                event_log=log,
            )
            review = coordinator.prepare_review(
                activation["execution_id"],
                review_id="memory_review_01",
            )
            decision = _memory_decision(review)
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            snapshot = authority.snapshot(review)
            coordinator.project(review, expected_approval=snapshot, now_ms=1_999)
            log.connection.execute(
                "UPDATE memory_projections SET request_fingerprint = ?",
                ("e" * 64,),
            )
            log.connection.commit()

            with self.assertRaisesRegex(
                AgentEventLogCorrupt,
                "event_log_projection_corrupt",
            ):
                log.replay_records(activation["execution_id"])

    def test_exact_recorded_duplicate_is_evidence_only_after_revoke_and_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            activation, _grant, _events, _receipt = MemoryProjectionEventLogTests._terminalize(log)
            source = self._source(activation["execution_id"])
            authority = InMemoryMemoryApprovalAuthority()
            coordinator = MemoryProjectionCoordinator(
                source=source,
                approval_authority=authority,
                event_log=log,
            )
            review = coordinator.prepare_review(
                activation["execution_id"],
                review_id="memory_review_01",
            )
            decision = _memory_decision(review)
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            snapshot = authority.snapshot(review)
            projection = coordinator.project(
                review,
                expected_approval=snapshot,
                now_ms=1_999,
            )
            recorded = log.replay_records(activation["execution_id"])
            authority.revoke(
                review.review_id,
                expected_generation=1,
                expected_decision_hash=decision.content_hash,
            )

            duplicate = coordinator.project(
                review,
                expected_approval=snapshot,
                now_ms=9_999,
            )

            self.assertEqual(projection, duplicate)
            self.assertEqual(recorded, log.replay_records(activation["execution_id"]))


if __name__ == "__main__":
    unittest.main()
