from __future__ import annotations

import dis
import hashlib
import inspect
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from contextlib import nullcontext
from dataclasses import replace
from functools import partial
from pathlib import Path
from types import FrameType
from unittest import mock

from worldforge.agent_harness.approvals import (
    ApprovalError,
    ExecutionApprovalDecision,
    ExecutionApprovalReview,
    InMemoryHumanApprovalAuthority,
)
from worldforge.agent_harness_contracts import MAX_SAFE_INTEGER
from worldforge.studio.authenticated_human_decisions import (
    StudioAuthenticatedHumanDecisionAuthority,
    _canonical_utc_timestamp,
    _event_document,
    _event_mac,
    _immediate_interrupted_primary,
    _note_indeterminate_cleanup,
)
from worldforge.studio.errors import StudioError
from worldforge.studio.storage import StudioStore, encode_json, utc_now


class _TextSubclass(str):
    pass


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
        "tool_candidates": (("source.read", "e" * 64), ("world.validate", "f" * 64)),
    }
    values.update(changes)
    return ExecutionApprovalReview.create(**values)


def _decision(
    review: ExecutionApprovalReview, **changes: object
) -> ExecutionApprovalDecision:
    values: dict[str, object] = {
        "review": review,
        "reviewer_id": "director_local",
        "outcome": "approved",
        "approved_tool_ids": ("source.read",),
        "expires_at_ms": 2_000,
    }
    values.update(changes)
    return ExecutionApprovalDecision.create(**values)


def _forge_authenticated_transition(
    store: StudioStore,
    authority: StudioAuthenticatedHumanDecisionAuthority,
    *,
    event_type: str,
    review: ExecutionApprovalReview,
    decision: ExecutionApprovalDecision,
    state: str,
    generation: int,
) -> None:
    previous = store.connection.execute(
        "SELECT content_hash FROM studio_authenticated_human_decision_events "
        "ORDER BY event_id DESC LIMIT 1"
    ).fetchone()["content_hash"]
    created_at = utc_now()
    document = _event_document(
        event_type=event_type,
        review=review,
        decision=decision,
        state=state,
        generation=generation,
        previous_hash=previous,
        updated_at=created_at,
    )
    content_json = encode_json(document)
    content_hash = hashlib.sha256(content_json.encode("utf-8")).hexdigest()
    with store.connection:
        store.connection.execute(
            "UPDATE studio_authenticated_human_decisions SET "
            "review_hash = ?, review_json = ?, decision_hash = ?, decision_json = ?, "
            "state = ?, generation = ?, last_event_hash = ?, updated_at = ? "
            "WHERE approval_id = ?",
            (
                review.content_hash,
                encode_json(review.as_document()),
                decision.content_hash,
                encode_json(decision.as_document()),
                state,
                generation,
                content_hash,
                created_at,
                review.approval_id,
            ),
        )
        store.connection.execute(
            "INSERT INTO studio_authenticated_human_decision_events "
            "(credential_id, approval_id, generation, event_type, content_json, "
            "content_hash, previous_hash, mac, created_at) "
            "VALUES ('director_local', ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                review.approval_id,
                generation,
                event_type,
                content_json,
                content_hash,
                previous,
                _event_mac(authority._event_key, document),
                created_at,
            ),
        )


def _forge_approved_projection_without_event(
    store: StudioStore,
    review: ExecutionApprovalReview,
    decision: ExecutionApprovalDecision,
) -> None:
    with sqlite3.connect(store.database_path) as writer:
        writer.execute(
            "UPDATE studio_authenticated_human_decisions SET "
            "review_hash = ?, review_json = ?, decision_hash = ?, decision_json = ?, "
            "state = 'approved', generation = 1 WHERE approval_id = ?",
            (
                review.content_hash,
                encode_json(review.as_document()),
                decision.content_hash,
                encode_json(decision.as_document()),
                review.approval_id,
            ),
        )


def _append_authenticated_duplicate_decision_event(
    store: StudioStore,
    authority: StudioAuthenticatedHumanDecisionAuthority,
    review: ExecutionApprovalReview,
    decision: ExecutionApprovalDecision,
) -> None:
    with sqlite3.connect(store.database_path) as writer:
        previous_hash = writer.execute(
            "SELECT content_hash FROM studio_authenticated_human_decision_events "
            "ORDER BY event_id DESC LIMIT 1"
        ).fetchone()[0]
        created_at = utc_now()
        document = _event_document(
            event_type="decided",
            review=review,
            decision=decision,
            state="approved",
            generation=1,
            previous_hash=previous_hash,
            updated_at=created_at,
        )
        content_json = encode_json(document)
        content_hash = hashlib.sha256(content_json.encode("utf-8")).hexdigest()
        writer.execute(
            "INSERT INTO studio_authenticated_human_decision_events "
            "(credential_id, approval_id, generation, event_type, content_json, "
            "content_hash, previous_hash, mac, created_at) "
            "VALUES ('director_local', ?, 1, 'decided', ?, ?, ?, ?, ?)",
            (
                review.approval_id,
                content_json,
                content_hash,
                previous_hash,
                _event_mac(authority._event_key, document),
                created_at,
            ),
        )


def _insert_authenticated_foreign_credential_event(
    store: StudioStore,
    authority: StudioAuthenticatedHumanDecisionAuthority,
    *,
    placement: str,
) -> int:
    foreign_review = _review(
        approval_id=f"approval_foreign_{placement}",
        execution_id=f"execution_foreign_{placement}",
    )
    with sqlite3.connect(store.database_path) as writer:
        foreign_keys = writer.execute("PRAGMA foreign_keys").fetchone()[0]
        previous_hash = (
            "0" * 64
            if placement == "before"
            else writer.execute(
                "SELECT content_hash FROM studio_authenticated_human_decision_events "
                "ORDER BY event_id DESC LIMIT 1"
            ).fetchone()[0]
        )
        created_at = utc_now()
        document = _event_document(
            event_type="prepared",
            review=foreign_review,
            decision=None,
            state="prepared",
            generation=0,
            previous_hash=previous_hash,
            updated_at=created_at,
        )
        content_json = encode_json(document)
        content_hash = hashlib.sha256(content_json.encode("utf-8")).hexdigest()
        columns = (
            "event_id, credential_id, approval_id, generation, event_type, content_json, "
            "content_hash, previous_hash, mac, created_at"
            if placement == "before"
            else "credential_id, approval_id, generation, event_type, content_json, "
            "content_hash, previous_hash, mac, created_at"
        )
        values = (
            "?, ?, ?, 0, 'prepared', ?, ?, ?, ?, ?"
            if placement == "before"
            else "?, ?, 0, 'prepared', ?, ?, ?, ?, ?"
        )
        parameters: tuple[object, ...] = (
            (0, "foreign_director", foreign_review.approval_id)
            if placement == "before"
            else ("foreign_director", foreign_review.approval_id)
        ) + (
            content_json,
            content_hash,
            previous_hash,
            _event_mac(authority._event_key, document),
            created_at,
        )
        writer.execute(
            f"INSERT INTO studio_authenticated_human_decision_events ({columns}) "
            f"VALUES ({values})",
            parameters,
        )
    return foreign_keys


def _add_private_schema_view(store: StudioStore) -> None:
    with sqlite3.connect(store.database_path) as writer:
        writer.execute(
            "CREATE VIEW studio_authenticated_human_extra_view AS "
            "SELECT credential_id FROM studio_authenticated_human_credentials"
        )


class _CommitFaultConnection:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        effect_then_raise: bool,
        rollback_then_raise: bool = False,
        error: sqlite3.Error | None = None,
    ) -> None:
        self._connection = connection
        self._effect_then_raise = effect_then_raise
        self._rollback_then_raise = rollback_then_raise
        self._error = (
            sqlite3.OperationalError("injected ambiguous commit")
            if error is None
            else error
        )
        self._commit_faulted = False
        self._rollback_faulted = False

    def __getattr__(self, name: str) -> object:
        return getattr(self._connection, name)

    def commit(self) -> None:
        if not self._commit_faulted:
            self._commit_faulted = True
            if self._effect_then_raise:
                self._connection.commit()
            raise self._error
        self._connection.commit()

    def rollback(self) -> None:
        if self._rollback_then_raise and not self._rollback_faulted:
            self._rollback_faulted = True
            raise sqlite3.OperationalError("injected rollback failure")
        self._connection.rollback()


class _RollbackFaultConnection:
    def __init__(
        self, connection: sqlite3.Connection, *, effect_then_raise: bool
    ) -> None:
        self._connection = connection
        self._effect_then_raise = effect_then_raise
        self._rollback_faulted = False

    def __getattr__(self, name: str) -> object:
        return getattr(self._connection, name)

    def rollback(self) -> None:
        if not self._rollback_faulted:
            self._rollback_faulted = True
            if self._effect_then_raise:
                self._connection.rollback()
            raise sqlite3.OperationalError("injected ambiguous rollback")
        self._connection.rollback()


class _SequencedTransactionFaultConnection:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        commit_faults: tuple[tuple[BaseException, bool], ...] = (),
        rollback_faults: tuple[tuple[BaseException, bool], ...] = (),
    ) -> None:
        self._connection = connection
        self._commit_faults = list(commit_faults)
        self._rollback_faults = list(rollback_faults)

    def __getattr__(self, name: str) -> object:
        return getattr(self._connection, name)

    def commit(self) -> None:
        if not self._commit_faults:
            self._connection.commit()
            return
        error, effect_then_raise = self._commit_faults.pop(0)
        if effect_then_raise:
            self._connection.commit()
        raise error

    def rollback(self) -> None:
        if not self._rollback_faults:
            self._connection.rollback()
            return
        error, effect_then_raise = self._rollback_faults.pop(0)
        if effect_then_raise:
            self._connection.rollback()
        raise error


class _SimulatedCrash(BaseException):
    pass


class _BaseExceptionFaultConnection:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        faults: dict[str, tuple[BaseException, bool]],
    ) -> None:
        self._connection = connection
        self._faults = dict(faults)

    def __getattr__(self, name: str) -> object:
        return getattr(self._connection, name)

    def execute(
        self, sql: str, parameters: tuple[object, ...] = ()
    ) -> sqlite3.Cursor:
        key = "begin" if sql in {"BEGIN", "BEGIN IMMEDIATE"} else "execute"
        fault = self._faults.pop(key, None)
        if fault is None:
            return self._connection.execute(sql, parameters)
        crash, effect_then_raise = fault
        if effect_then_raise:
            self._connection.execute(sql, parameters)
        raise crash

    def commit(self) -> None:
        fault = self._faults.pop("commit", None)
        if fault is None:
            self._connection.commit()
            return
        crash, effect_then_raise = fault
        if effect_then_raise:
            self._connection.commit()
        raise crash

    def rollback(self) -> None:
        fault = self._faults.pop("rollback", None)
        if fault is None:
            self._connection.rollback()
            return
        crash, effect_then_raise = fault
        if effect_then_raise:
            self._connection.rollback()
        raise crash

    def close(self) -> None:
        fault = self._faults.pop("close", None)
        if fault is None:
            self._connection.close()
            return
        crash, effect_then_raise = fault
        if effect_then_raise:
            self._connection.close()
        raise crash


class StudioAuthenticatedHumanDecisionAuthorityTests(unittest.TestCase):
    _PASSPHRASE = "director passphrase with enough UTF-8 bytes"

    def _enrolled(
        self, directory: str
    ) -> tuple[StudioStore, StudioAuthenticatedHumanDecisionAuthority]:
        store = StudioStore(Path(directory) / "studio")
        return (
            store,
            StudioAuthenticatedHumanDecisionAuthority.enroll(
                store, passphrase=self._PASSPHRASE
            ),
        )

    def _restore_fault_connection(
        self,
        store: StudioStore,
        raw: sqlite3.Connection,
        fault: _BaseExceptionFaultConnection,
        authority: StudioAuthenticatedHumanDecisionAuthority | None = None,
    ) -> None:
        if authority is not None and authority._connection is fault:
            authority._connection = raw
        if store._authenticated_human_decision_connection_instance is fault:
            store._authenticated_human_decision_connection_instance = raw
        try:
            if raw.in_transaction:
                raw.rollback()
        except sqlite3.Error:
            pass

    def _source_line(
        self,
        function: object,
        source_text: str,
        *,
        occurrence: int = 1,
        after_source_text: str | None = None,
        after_occurrence: int = 1,
    ) -> int:
        source, start = inspect.getsourcelines(function)
        after_index = -1
        if after_source_text is not None:
            matches = [
                index
                for index, line in enumerate(source)
                if line.strip() == after_source_text
            ]
            after_index = matches[after_occurrence - 1]
        matches = [
            index
            for index, line in enumerate(source)
            if index > after_index and line.strip() == source_text
        ]
        return start + matches[occurrence - 1]

    def _opcode_before_source_line(
        self, function: object, source_text: str, *, occurrence: int = 1
    ) -> int:
        target_line = self._source_line(
            function, source_text, occurrence=occurrence
        )
        instructions = list(dis.get_instructions(function))
        target_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.starts_line == target_line
        )
        return instructions[target_index - 1].offset

    def _store_fast_for_source_line(
        self, function: object, source_text: str, local_name: str
    ) -> int:
        target_line = self._source_line(function, source_text)
        return next(
            instruction.offset
            for instruction in dis.get_instructions(function)
            if instruction.opname == "STORE_FAST"
            and instruction.argval == local_name
            and instruction.positions.lineno == target_line
        )

    def _store_fast_offsets_in_source_range(
        self,
        function: object,
        local_name: str,
        *,
        start_source_text: str,
        end_source_text: str,
    ) -> frozenset[int]:
        start_line = self._source_line(function, start_source_text)
        end_line = self._source_line(function, end_source_text)
        offsets = frozenset(
            instruction.offset
            for instruction in dis.get_instructions(function)
            if instruction.opname == "STORE_FAST"
            and instruction.argval == local_name
            and instruction.positions.lineno is not None
            and start_line <= instruction.positions.lineno < end_line
        )
        self.assertTrue(offsets)
        return offsets

    def _run_with_trace_interruption(
        self,
        operation: object,
        *,
        function: object,
        error: BaseException,
        target_line: int | None = None,
        target_offset: int | None = None,
        target_offsets: frozenset[int] | None = None,
    ) -> tuple[bool, BaseException | None, object]:
        targets = tuple(
            target is not None
            for target in (target_line, target_offset, target_offsets)
        )
        self.assertEqual(1, sum(targets))
        code = function.__code__
        fired = False

        def interrupt(
            frame: FrameType, event: str, _arg: object
        ) -> object:
            nonlocal fired
            if frame.f_code is code:
                if target_offset is not None or target_offsets is not None:
                    frame.f_trace_opcodes = True
                matches_line = event == "line" and frame.f_lineno == target_line
                matches_opcode = event == "opcode" and (
                    frame.f_lasti == target_offset
                    or (
                        target_offsets is not None
                        and frame.f_lasti in target_offsets
                    )
                )
                if not fired and (matches_line or matches_opcode):
                    fired = True
                    sys.settrace(None)
                    raise error
            return interrupt

        previous_trace = sys.gettrace()
        raised = None
        try:
            sys.settrace(interrupt)
            try:
                operation()
            except BaseException as exc:
                raised = exc
        finally:
            sys.settrace(previous_trace)
        return fired, raised, previous_trace

    def _primary_failure_has_precedence(
        self,
        raised: BaseException | None,
        primary: BaseException,
        *,
        operation: str,
        primary_kind: str,
    ) -> bool:
        if primary_kind == "sqlite":
            expected_code = (
                "invalid_state" if operation == "unlock" else "internal_error"
            )
            return (
                isinstance(raised, StudioError)
                and raised.code == expected_code
                and raised.__cause__ is primary
            )
        if primary_kind == "runtime" and operation in {"enroll", "unlock"}:
            expected_message = (
                "credential enrollment failed"
                if operation == "enroll"
                else "authenticated decision audit failed"
            )
            return (
                isinstance(raised, StudioError)
                and raised.message == expected_message
                and raised.__cause__ is primary
            )
        return raised is primary

    def _connection_is_closed_or_idle(self, connection: sqlite3.Connection) -> bool:
        try:
            return not connection.in_transaction
        except sqlite3.ProgrammingError:
            return True

    def test_bootstrap_begin_and_body_baseexceptions_rollback_and_reraise(self) -> None:
        for operation in ("enroll", "unlock"):
            for fault_point in ("begin", "body"):
                for effect_then_raise in (False, True):
                    with (
                        self.subTest(
                            operation=operation,
                            fault_point=fault_point,
                            effect_then_raise=effect_then_raise,
                        ),
                        tempfile.TemporaryDirectory() as directory,
                    ):
                        store = StudioStore(Path(directory) / "studio")
                        existing = None
                        try:
                            if operation == "unlock":
                                existing = StudioAuthenticatedHumanDecisionAuthority.enroll(
                                    store, passphrase=self._PASSPHRASE
                                )
                            raw = store._authenticated_human_decision_connection()
                            original = _SimulatedCrash(
                                f"{operation} {fault_point} interruption"
                            )
                            fault = _BaseExceptionFaultConnection(
                                raw,
                                faults={"begin": (original, effect_then_raise)}
                                if fault_point == "begin"
                                else {},
                            )
                            store._authenticated_human_decision_connection_instance = fault
                            if existing is not None:
                                existing._connection = fault
                            try:
                                if fault_point == "begin":
                                    patcher = mock.patch(
                                        "worldforge.studio.authenticated_human_decisions."
                                        "_verify_authenticated_human_decision_v6"
                                    )
                                elif effect_then_raise:
                                    patcher = mock.patch.object(
                                        StudioAuthenticatedHumanDecisionAuthority,
                                        "_audit_in_transaction",
                                        side_effect=original,
                                    )
                                else:
                                    patcher = mock.patch(
                                        "worldforge.studio.authenticated_human_decisions."
                                        "_verify_authenticated_human_decision_v6",
                                        side_effect=original,
                                    )
                                with patcher, self.assertRaises(_SimulatedCrash) as raised:
                                    if operation == "enroll":
                                        StudioAuthenticatedHumanDecisionAuthority.enroll(
                                            store, passphrase=self._PASSPHRASE
                                        )
                                    else:
                                        StudioAuthenticatedHumanDecisionAuthority.unlock(
                                            store, passphrase=self._PASSPHRASE
                                        )
                                self.assertIs(original, raised.exception)
                                self.assertFalse(raw.in_transaction)
                                self.assertFalse(
                                    store._authenticated_human_decision_connection_unavailable
                                )
                                self.assertEqual(
                                    0 if operation == "enroll" else 1,
                                    store.connection.execute(
                                        "SELECT COUNT(*) FROM "
                                        "studio_authenticated_human_credentials"
                                    ).fetchone()[0],
                                )
                                if existing is not None:
                                    self.assertEqual(
                                        "missing", existing.snapshot(_review()).state
                                    )
                            finally:
                                self._restore_fault_connection(
                                    store, raw, fault, existing
                                )
                        finally:
                            store.close()

    def test_bootstrap_commit_and_rollback_baseexceptions_invalidate_store(self) -> None:
        for operation in ("enroll", "unlock"):
            for fault_point in ("commit", "rollback"):
                for effect_then_raise in (False, True):
                    with (
                        self.subTest(
                            operation=operation,
                            fault_point=fault_point,
                            effect_then_raise=effect_then_raise,
                        ),
                        tempfile.TemporaryDirectory() as directory,
                    ):
                        store = StudioStore(Path(directory) / "studio")
                        existing = None
                        try:
                            if operation == "unlock":
                                existing = StudioAuthenticatedHumanDecisionAuthority.enroll(
                                    store, passphrase=self._PASSPHRASE
                                )
                            raw = store._authenticated_human_decision_connection()
                            original = _SimulatedCrash(
                                f"{operation} {fault_point} interruption"
                            )
                            cleanup = _SimulatedCrash("cleanup interruption")
                            faults = {
                                fault_point: (
                                    original if fault_point == "commit" else cleanup,
                                    effect_then_raise,
                                )
                            }
                            if fault_point == "rollback":
                                faults["close"] = (
                                    _SimulatedCrash("close interruption"),
                                    effect_then_raise,
                                )
                            fault = _BaseExceptionFaultConnection(raw, faults=faults)
                            store._authenticated_human_decision_connection_instance = fault
                            if existing is not None:
                                existing._connection = fault
                            try:
                                patcher = (
                                    mock.patch.object(
                                        StudioAuthenticatedHumanDecisionAuthority,
                                        "_audit_in_transaction",
                                        side_effect=original,
                                    )
                                    if fault_point == "rollback"
                                    else mock.patch(
                                        "worldforge.studio.authenticated_human_decisions."
                                        "_verify_authenticated_human_decision_v6"
                                    )
                                )
                                with patcher, self.assertRaises(_SimulatedCrash) as raised:
                                    if operation == "enroll":
                                        StudioAuthenticatedHumanDecisionAuthority.enroll(
                                            store, passphrase=self._PASSPHRASE
                                        )
                                    else:
                                        StudioAuthenticatedHumanDecisionAuthority.unlock(
                                            store, passphrase=self._PASSPHRASE
                                        )
                                self.assertIs(original, raised.exception)
                                self.assertIsNone(
                                    store._authenticated_human_decision_connection_instance
                                )
                                self.assertTrue(
                                    store._authenticated_human_decision_connection_unavailable
                                )
                                with self.assertRaisesRegex(StudioError, "unavailable"):
                                    store._authenticated_human_decision_connection()
                                expected_credentials = (
                                    int(effect_then_raise)
                                    if operation == "enroll"
                                    and fault_point == "commit"
                                    else int(operation == "unlock")
                                )
                                self.assertEqual(
                                    expected_credentials,
                                    store.connection.execute(
                                        "SELECT COUNT(*) FROM "
                                        "studio_authenticated_human_credentials"
                                    ).fetchone()[0],
                                )
                            finally:
                                self._restore_fault_connection(
                                    store, raw, fault, existing
                                )
                                try:
                                    raw.close()
                                except sqlite3.Error:
                                    pass
                        finally:
                            store.close()

    def test_live_read_baseexceptions_cleanup_retain_anchor_or_poison(self) -> None:
        for fault_point in ("begin", "body", "commit", "rollback"):
            for effect_then_raise in (False, True):
                with (
                    self.subTest(
                        fault_point=fault_point,
                        effect_then_raise=effect_then_raise,
                    ),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    data_dir = Path(directory) / "studio"
                    primary = StudioStore(data_dir)
                    secondary = None
                    try:
                        first = StudioAuthenticatedHumanDecisionAuthority.enroll(
                            primary, passphrase=self._PASSPHRASE
                        )
                        secondary = StudioStore(data_dir, mode="secondary")
                        second = StudioAuthenticatedHumanDecisionAuthority.unlock(
                            secondary, passphrase=self._PASSPHRASE
                        )
                        review = _review()
                        second.prepare(review, expected_generation=0)
                        observed = primary.connection.execute(
                            "SELECT event_id, content_hash FROM "
                            "studio_authenticated_human_decision_events"
                        ).fetchone()
                        initial_anchor = first._anchor
                        original = _SimulatedCrash(
                            f"read {fault_point} interruption"
                        )
                        cleanup = _SimulatedCrash("read rollback interruption")
                        faults: dict[str, tuple[BaseException, bool]] = {}
                        if fault_point in {"begin", "commit"}:
                            faults[fault_point] = (original, effect_then_raise)
                        elif fault_point == "rollback":
                            faults["rollback"] = (cleanup, effect_then_raise)
                        raw = first._connection
                        fault = _BaseExceptionFaultConnection(raw, faults=faults)
                        first._connection = fault
                        primary._authenticated_human_decision_connection_instance = fault
                        if fault_point == "rollback" or (
                            fault_point == "body" and effect_then_raise
                        ):
                            patcher = mock.patch.object(
                                first,
                                "_snapshot_in_transaction",
                                side_effect=original,
                            )
                        elif fault_point == "body":
                            patcher = mock.patch.object(
                                first,
                                "_audit_in_transaction",
                                side_effect=original,
                            )
                        else:
                            patcher = nullcontext()
                        try:
                            with patcher, self.assertRaises(_SimulatedCrash) as raised:
                                first.snapshot(review)
                            self.assertIs(original, raised.exception)
                            self.assertFalse(raw.in_transaction)
                            audited = fault_point in {"commit", "rollback"} or (
                                fault_point == "body" and effect_then_raise
                            )
                            expected_anchor = (
                                (observed["event_id"], observed["content_hash"])
                                if audited
                                else (
                                    initial_anchor.event_id,
                                    initial_anchor.content_hash,
                                )
                            )
                            self.assertEqual(
                                expected_anchor,
                                (first._anchor.event_id, first._anchor.content_hash),
                            )
                            if fault_point == "rollback":
                                self.assertTrue(first._poisoned)
                                with self.assertRaisesRegex(StudioError, "unavailable"):
                                    first.snapshot(review)
                            else:
                                self.assertFalse(first._poisoned)
                                self.assertEqual(
                                    "prepared", first.snapshot(review).state
                                )
                        finally:
                            self._restore_fault_connection(
                                primary, raw, fault, first
                            )
                    finally:
                        if secondary is not None:
                            secondary.close()
                        primary.close()

    def test_live_write_begin_body_and_rollback_baseexceptions_fail_closed(self) -> None:
        for fault_point in ("begin", "body", "rollback"):
            for effect_then_raise in (False, True):
                with (
                    self.subTest(
                        fault_point=fault_point,
                        effect_then_raise=effect_then_raise,
                    ),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    store, authority = self._enrolled(directory)
                    try:
                        review = _review()
                        initial_anchor = authority._anchor
                        original = _SimulatedCrash(
                            f"write {fault_point} interruption"
                        )
                        cleanup = _SimulatedCrash("write rollback interruption")
                        faults: dict[str, tuple[BaseException, bool]] = {}
                        if fault_point == "begin":
                            faults["begin"] = (original, effect_then_raise)
                        elif fault_point == "rollback":
                            faults["rollback"] = (cleanup, effect_then_raise)
                        raw = authority._connection
                        fault = _BaseExceptionFaultConnection(raw, faults=faults)
                        authority._connection = fault
                        store._authenticated_human_decision_connection_instance = fault
                        if fault_point == "body" and not effect_then_raise:
                            patcher = mock.patch.object(
                                authority, "_row", side_effect=original
                            )
                        elif fault_point in {"body", "rollback"}:
                            insert_projection = authority._insert_projection

                            def insert_then_crash(
                                *args: object, **kwargs: object
                            ) -> bool:
                                insert_projection(*args, **kwargs)
                                raise original

                            patcher = mock.patch.object(
                                authority,
                                "_insert_projection",
                                side_effect=insert_then_crash,
                            )
                        else:
                            patcher = nullcontext()
                        try:
                            with patcher, self.assertRaises(_SimulatedCrash) as raised:
                                authority.prepare(review, expected_generation=0)
                            self.assertIs(original, raised.exception)
                            self.assertFalse(raw.in_transaction)
                            self.assertEqual(
                                (
                                    initial_anchor.event_id,
                                    initial_anchor.content_hash,
                                ),
                                (
                                    authority._anchor.event_id,
                                    authority._anchor.content_hash,
                                ),
                            )
                            self.assertEqual(
                                0,
                                store.connection.execute(
                                    "SELECT COUNT(*) FROM "
                                    "studio_authenticated_human_decisions"
                                ).fetchone()[0],
                            )
                            self.assertEqual(
                                0,
                                store.connection.execute(
                                    "SELECT COUNT(*) FROM "
                                    "studio_authenticated_human_decision_events"
                                ).fetchone()[0],
                            )
                            if fault_point == "rollback":
                                self.assertTrue(authority._poisoned)
                                with self.assertRaisesRegex(StudioError, "unavailable"):
                                    authority.snapshot(review)
                            else:
                                self.assertFalse(authority._poisoned)
                                self.assertEqual(
                                    "missing", authority.snapshot(review).state
                                )
                        finally:
                            self._restore_fault_connection(
                                store, raw, fault, authority
                            )
                    finally:
                        store.close()

    def test_live_write_commit_baseexceptions_reconcile_and_reraise(self) -> None:
        for effect_then_raise in (False, True):
            with (
                self.subTest(effect_then_raise=effect_then_raise),
                tempfile.TemporaryDirectory() as directory,
            ):
                store, authority = self._enrolled(directory)
                try:
                    entry_review = _review()
                    tentative_review = _review(
                        approval_id="approval_execution_02",
                        execution_id="execution_02",
                    )
                    authority.prepare(entry_review, expected_generation=0)
                    original = _SimulatedCrash("write commit interruption")
                    raw = authority._connection
                    fault = _BaseExceptionFaultConnection(
                        raw,
                        faults={"commit": (original, effect_then_raise)},
                    )
                    authority._connection = fault
                    store._authenticated_human_decision_connection_instance = fault
                    try:
                        with self.assertRaises(_SimulatedCrash) as raised:
                            authority.prepare(
                                tentative_review, expected_generation=0
                            )
                        self.assertIs(original, raised.exception)
                        self.assertFalse(raw.in_transaction)
                        events = store.connection.execute(
                            "SELECT event_id, content_hash FROM "
                            "studio_authenticated_human_decision_events "
                            "ORDER BY event_id"
                        ).fetchall()
                        self.assertEqual(1 + int(effect_then_raise), len(events))
                        self.assertEqual(
                            (events[-1]["event_id"], events[-1]["content_hash"]),
                            (authority._anchor.event_id, authority._anchor.content_hash),
                        )
                        self.assertFalse(authority._poisoned)
                        authority.prepare(tentative_review, expected_generation=0)
                        self.assertEqual(
                            2,
                            store.connection.execute(
                                "SELECT COUNT(*) FROM "
                                "studio_authenticated_human_decision_events"
                            ).fetchone()[0],
                        )
                    finally:
                        self._restore_fault_connection(
                            store, raw, fault, authority
                        )
                finally:
                    store.close()

    def test_reconciliation_baseexceptions_poison_and_preserve_commit_crash(self) -> None:
        cases = (("audit", False), ("rollback", False), ("rollback", True))
        for fault_point, effect_then_raise in cases:
            with (
                self.subTest(
                    fault_point=fault_point,
                    effect_then_raise=effect_then_raise,
                ),
                tempfile.TemporaryDirectory() as directory,
            ):
                store, authority = self._enrolled(directory)
                try:
                    entry_review = _review()
                    tentative_review = _review(
                        approval_id="approval_execution_02",
                        execution_id="execution_02",
                    )
                    authority.prepare(entry_review, expected_generation=0)
                    entry = authority._anchor
                    original = _SimulatedCrash("write commit interruption")
                    cleanup = _SimulatedCrash(
                        f"reconciliation {fault_point} interruption"
                    )
                    faults: dict[str, tuple[BaseException, bool]] = {
                        "commit": (original, fault_point == "audit")
                    }
                    if fault_point == "rollback":
                        faults["rollback"] = (cleanup, effect_then_raise)
                    raw = authority._connection
                    fault = _BaseExceptionFaultConnection(raw, faults=faults)
                    authority._connection = fault
                    store._authenticated_human_decision_connection_instance = fault
                    real_audit = authority._audit_in_transaction
                    audit_count = 0

                    def interrupt_reconciliation_audit(
                        *args: object, **kwargs: object
                    ) -> object:
                        nonlocal audit_count
                        audit_count += 1
                        if audit_count == 3:
                            raise cleanup
                        return real_audit(*args, **kwargs)

                    patcher = (
                        mock.patch.object(
                            authority,
                            "_audit_in_transaction",
                            side_effect=interrupt_reconciliation_audit,
                        )
                        if fault_point == "audit"
                        else nullcontext()
                    )
                    try:
                        with patcher, self.assertRaises(_SimulatedCrash) as raised:
                            authority.prepare(
                                tentative_review, expected_generation=0
                            )
                        self.assertIs(original, raised.exception)
                        self.assertFalse(raw.in_transaction)
                        self.assertTrue(authority._poisoned)
                        self.assertEqual(
                            (entry.event_id, entry.content_hash),
                            (authority._anchor.event_id, authority._anchor.content_hash),
                        )
                        self.assertEqual(
                            2 if fault_point == "audit" else 1,
                            store.connection.execute(
                                "SELECT COUNT(*) FROM "
                                "studio_authenticated_human_decision_events"
                            ).fetchone()[0],
                        )
                        with self.assertRaisesRegex(StudioError, "unavailable"):
                            authority.snapshot(entry_review)
                    finally:
                        self._restore_fault_connection(
                            store, raw, fault, authority
                        )
                finally:
                    store.close()

    def test_read_post_commit_anchor_publication_baseexception_fails_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            primary = StudioStore(data_dir)
            secondary = None
            try:
                first = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    primary, passphrase=self._PASSPHRASE
                )
                secondary = StudioStore(data_dir, mode="secondary")
                second = StudioAuthenticatedHumanDecisionAuthority.unlock(
                    secondary, passphrase=self._PASSPHRASE
                )
                review = _review()
                second.prepare(review, expected_generation=0)
                observed = primary.connection.execute(
                    "SELECT event_id, content_hash FROM "
                    "studio_authenticated_human_decision_events"
                ).fetchone()
                original = _SimulatedCrash("read anchor publication interruption")

                with (
                    mock.patch.object(first, "_advance_anchor", side_effect=original),
                    self.assertRaises(_SimulatedCrash) as raised,
                ):
                    first.snapshot(review)

                self.assertIs(original, raised.exception)
                publication_safe = first._poisoned or (
                    first._anchor.event_id,
                    first._anchor.content_hash,
                ) == (observed["event_id"], observed["content_hash"])
                with sqlite3.connect(primary.database_path) as writer:
                    writer.execute(
                        "DELETE FROM studio_authenticated_human_decision_events"
                    )
                    writer.execute(
                        "DELETE FROM studio_authenticated_human_decisions"
                    )
                rollback_error = None
                try:
                    first.snapshot(review)
                except StudioError as exc:
                    rollback_error = exc
                self.assertEqual(
                    (True, "invalid_state"),
                    (
                        publication_safe,
                        None if rollback_error is None else rollback_error.code,
                    ),
                )
            finally:
                if secondary is not None:
                    secondary.close()
                primary.close()

    def test_write_post_commit_anchor_publication_baseexception_fails_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            try:
                review = _review()
                original = _SimulatedCrash("write anchor publication interruption")

                with (
                    mock.patch.object(
                        authority, "_advance_anchor", side_effect=original
                    ),
                    self.assertRaises(_SimulatedCrash) as raised,
                ):
                    authority.prepare(review, expected_generation=0)

                self.assertIs(original, raised.exception)
                observed = store.connection.execute(
                    "SELECT event_id, content_hash FROM "
                    "studio_authenticated_human_decision_events"
                ).fetchone()
                self.assertEqual(
                    (1, 1),
                    (
                        store.connection.execute(
                            "SELECT COUNT(*) FROM "
                            "studio_authenticated_human_decisions"
                        ).fetchone()[0],
                        store.connection.execute(
                            "SELECT COUNT(*) FROM "
                            "studio_authenticated_human_decision_events"
                        ).fetchone()[0],
                    ),
                )
                publication_safe = authority._poisoned or (
                    authority._anchor.event_id,
                    authority._anchor.content_hash,
                ) == (observed["event_id"], observed["content_hash"])
                with sqlite3.connect(store.database_path) as writer:
                    writer.execute(
                        "DELETE FROM studio_authenticated_human_decision_events"
                    )
                    writer.execute(
                        "DELETE FROM studio_authenticated_human_decisions"
                    )
                rollback_error = None
                try:
                    authority.snapshot(review)
                except StudioError as exc:
                    rollback_error = exc
                self.assertEqual(
                    (True, "invalid_state"),
                    (
                        publication_safe,
                        None if rollback_error is None else rollback_error.code,
                    ),
                )
            finally:
                store.close()

    def test_ordinary_failure_anchor_publication_baseexceptions_fail_closed(
        self,
    ) -> None:
        cases = (
            ("read_body_domain", "domain", 1),
            ("read_body_sqlite", "sqlite", 1),
            ("read_commit_sqlite", "sqlite", 1),
            ("write_body_domain", "domain", 1),
            ("write_body_sqlite", "sqlite", 1),
            ("write_reconcile_entry", "sqlite", 1),
            ("write_reconcile_observed", "sqlite", 2),
        )
        # A BEGIN failure has no audited head, so it has no anchor-publication site.
        for case, outcome_kind, crash_on_advance in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as directory,
            ):
                data_dir = Path(directory) / "studio"
                primary = StudioStore(data_dir)
                secondary = None
                try:
                    first = StudioAuthenticatedHumanDecisionAuthority.enroll(
                        primary, passphrase=self._PASSPHRASE
                    )
                    secondary = StudioStore(data_dir, mode="secondary")
                    second = StudioAuthenticatedHumanDecisionAuthority.unlock(
                        secondary, passphrase=self._PASSPHRASE
                    )
                    observed_review = _review()
                    tentative_review = _review(
                        approval_id="approval_execution_02",
                        execution_id="execution_02",
                    )
                    second.prepare(observed_review, expected_generation=0)
                    raw = first._connection
                    if outcome_kind == "domain":
                        primary_error: BaseException = ApprovalError("approval_stale")
                    else:
                        primary_error = sqlite3.OperationalError(
                            f"injected {case} failure"
                        )
                    fault_connection = None
                    if case in {
                        "read_commit_sqlite",
                        "write_reconcile_entry",
                        "write_reconcile_observed",
                    }:
                        fault_connection = _CommitFaultConnection(
                            raw,
                            effect_then_raise=False,
                            error=primary_error
                            if isinstance(primary_error, sqlite3.Error)
                            else None,
                        )
                        first._connection = fault_connection
                        primary._authenticated_human_decision_connection_instance = (
                            fault_connection
                        )
                    crash = _SimulatedCrash(
                        f"{case} anchor publication interruption"
                    )
                    real_advance = first._advance_anchor
                    advance_calls = 0

                    def advance_or_crash(head: object) -> None:
                        nonlocal advance_calls
                        advance_calls += 1
                        if advance_calls == crash_on_advance:
                            raise crash
                        real_advance(head)  # type: ignore[arg-type]

                    if case in {"read_body_domain", "read_body_sqlite"}:
                        body_patcher = mock.patch.object(
                            first,
                            "_snapshot_in_transaction",
                            side_effect=primary_error,
                        )
                        operation = partial(first.snapshot, observed_review)
                    elif case in {"write_body_domain", "write_body_sqlite"}:
                        body_patcher = mock.patch.object(
                            first, "_row", side_effect=primary_error
                        )
                        operation = partial(
                            first.prepare,
                            tentative_review,
                            expected_generation=0,
                        )
                    elif case == "read_commit_sqlite":
                        body_patcher = nullcontext()
                        operation = partial(first.snapshot, observed_review)
                    else:
                        body_patcher = nullcontext()
                        operation = partial(
                            first.prepare,
                            tentative_review,
                            expected_generation=0,
                        )

                    raised = None
                    try:
                        with body_patcher, mock.patch.object(
                            first,
                            "_advance_anchor",
                            side_effect=advance_or_crash,
                        ):
                            try:
                                operation()
                            except BaseException as exc:
                                raised = exc
                    finally:
                        if fault_connection is not None:
                            first._connection = raw
                            primary._authenticated_human_decision_connection_instance = (
                                raw
                            )

                    transaction_closed = not raw.in_transaction
                    if raw.in_transaction:
                        raw.rollback()
                    if outcome_kind == "domain":
                        precedence_preserved = raised is primary_error
                    else:
                        precedence_preserved = (
                            isinstance(raised, StudioError)
                            and raised.code == "internal_error"
                            and raised.message
                            == "authenticated decision transaction failed"
                            and raised.__cause__ is primary_error
                        )
                    poisoned = first._poisoned
                    with sqlite3.connect(primary.database_path) as writer:
                        writer.execute(
                            "DELETE FROM studio_authenticated_human_decision_events"
                        )
                        writer.execute(
                            "DELETE FROM studio_authenticated_human_decisions"
                        )
                    rollback_error = None
                    try:
                        first.snapshot(observed_review)
                    except StudioError as exc:
                        rollback_error = exc
                    self.assertEqual(
                        (True, True, True, "invalid_state"),
                        (
                            precedence_preserved,
                            transaction_closed,
                            poisoned,
                            None if rollback_error is None else rollback_error.code,
                        ),
                    )
                finally:
                    if secondary is not None:
                        secondary.close()
                    primary.close()

    def test_post_commit_line_gap_interruptions_retain_head_or_poison(self) -> None:
        cases = (
            ("read", RuntimeError("read post-commit gap")),
            ("read", _SimulatedCrash("read post-commit gap")),
            ("write", RuntimeError("write post-commit gap")),
            ("write", _SimulatedCrash("write post-commit gap")),
        )
        for operation_kind, original in cases:
            with (
                self.subTest(
                    operation=operation_kind,
                    error_type=type(original).__name__,
                ),
                tempfile.TemporaryDirectory() as directory,
            ):
                data_dir = Path(directory) / "studio"
                primary = StudioStore(data_dir)
                secondary = None
                try:
                    first = StudioAuthenticatedHumanDecisionAuthority.enroll(
                        primary, passphrase=self._PASSPHRASE
                    )
                    review = _review()
                    if operation_kind == "read":
                        secondary = StudioStore(data_dir, mode="secondary")
                        second = StudioAuthenticatedHumanDecisionAuthority.unlock(
                            secondary, passphrase=self._PASSPHRASE
                        )
                        second.prepare(review, expected_generation=0)
                        operation = partial(first.snapshot, review)
                        transaction_method = (
                            StudioAuthenticatedHumanDecisionAuthority._read_transaction
                        )
                        target_source = "self._publish_anchor_after_commit(head)"
                    else:
                        operation = partial(
                            first.prepare, review, expected_generation=0
                        )
                        transaction_method = (
                            StudioAuthenticatedHumanDecisionAuthority._write_transaction
                        )
                        target_source = "self._publish_anchor_after_commit(final)"
                    transaction = transaction_method.__wrapped__
                    source, start = inspect.getsourcelines(transaction)
                    target_line = next(
                        start + offset
                        for offset, line in enumerate(source)
                        if line.strip() == target_source
                    )
                    fired = False

                    def interrupt_gap(
                        frame: FrameType, event: str, _arg: object
                    ) -> object:
                        nonlocal fired
                        if (
                            not fired
                            and event == "line"
                            and frame.f_code is transaction.__code__
                            and frame.f_lineno == target_line
                        ):
                            fired = True
                            sys.settrace(None)
                            raise original
                        return interrupt_gap

                    previous_trace = sys.gettrace()
                    raised = None
                    try:
                        sys.settrace(interrupt_gap)
                        try:
                            operation()
                        except BaseException as exc:
                            raised = exc
                    finally:
                        sys.settrace(previous_trace)

                    tail = primary.connection.execute(
                        "SELECT event_id, content_hash FROM "
                        "studio_authenticated_human_decision_events "
                        "ORDER BY event_id DESC LIMIT 1"
                    ).fetchone()
                    anchored = (
                        first._anchor.event_id,
                        first._anchor.content_hash,
                    ) == (tail["event_id"], tail["content_hash"])
                    safe_state = first._poisoned or anchored
                    transaction_closed = not first._connection.in_transaction
                    with sqlite3.connect(primary.database_path) as writer:
                        writer.execute(
                            "DELETE FROM studio_authenticated_human_decision_events"
                        )
                        writer.execute(
                            "DELETE FROM studio_authenticated_human_decisions"
                        )
                    rollback_error = None
                    try:
                        first.snapshot(review)
                    except StudioError as exc:
                        rollback_error = exc
                    self.assertEqual(
                        (True, True, True, True, "invalid_state"),
                        (
                            raised is original,
                            fired,
                            transaction_closed,
                            safe_state,
                            None if rollback_error is None else rollback_error.code,
                        ),
                    )
                    self.assertIs(previous_trace, sys.gettrace())
                finally:
                    if secondary is not None:
                        secondary.close()
                    primary.close()

    def test_reconciliation_cleanup_interruptions_preserve_primary_failure(
        self,
    ) -> None:
        cases = tuple(
            (primary_kind, cleanup_site, initial_commit_effect)
            for primary_kind in ("ordinary", "baseexception")
            for cleanup_site in (
                "audit",
                "rollback",
                "commit_before_effect",
                "commit_after_effect",
            )
            for initial_commit_effect in (
                (False, True)
                if cleanup_site == "commit_after_effect"
                else (False,)
            )
        )
        for primary_kind, cleanup_site, initial_commit_effect in cases:
            with (
                self.subTest(
                    primary=primary_kind,
                    cleanup=cleanup_site,
                    initial_commit_effect=initial_commit_effect,
                ),
                tempfile.TemporaryDirectory() as directory,
            ):
                data_dir = Path(directory) / "studio"
                primary = StudioStore(data_dir)
                secondary = None
                try:
                    first = StudioAuthenticatedHumanDecisionAuthority.enroll(
                        primary, passphrase=self._PASSPHRASE
                    )
                    secondary = StudioStore(data_dir, mode="secondary")
                    second = StudioAuthenticatedHumanDecisionAuthority.unlock(
                        secondary, passphrase=self._PASSPHRASE
                    )
                    observed_review = _review()
                    tentative_review = _review(
                        approval_id="approval_execution_02",
                        execution_id="execution_02",
                    )
                    second.prepare(observed_review, expected_generation=0)
                    if primary_kind == "ordinary":
                        original: BaseException = sqlite3.OperationalError(
                            "initial ambiguous commit"
                        )
                    else:
                        original = _SimulatedCrash("initial commit interruption")
                    cleanup = _SimulatedCrash(
                        f"reconciliation {cleanup_site} interruption"
                    )
                    commit_faults = [(original, initial_commit_effect)]
                    rollback_faults: list[tuple[BaseException, bool]] = []
                    if cleanup_site.startswith("commit_"):
                        commit_faults.append(
                            (cleanup, cleanup_site == "commit_after_effect")
                        )
                    elif cleanup_site == "rollback":
                        rollback_faults.append((cleanup, False))
                    raw = first._connection
                    fault = _SequencedTransactionFaultConnection(
                        raw,
                        commit_faults=tuple(commit_faults),
                        rollback_faults=tuple(rollback_faults),
                    )
                    first._connection = fault
                    primary._authenticated_human_decision_connection_instance = fault
                    real_audit = first._audit_in_transaction
                    audit_calls = 0

                    def audit_or_interrupt(
                        *args: object, **kwargs: object
                    ) -> object:
                        nonlocal audit_calls
                        audit_calls += 1
                        if cleanup_site == "audit" and audit_calls == 3:
                            raise cleanup
                        return real_audit(*args, **kwargs)

                    raised = None
                    try:
                        with mock.patch.object(
                            first,
                            "_audit_in_transaction",
                            side_effect=audit_or_interrupt,
                        ):
                            try:
                                first.prepare(
                                    tentative_review, expected_generation=0
                                )
                            except BaseException as exc:
                                raised = exc
                    finally:
                        first._connection = raw
                        primary._authenticated_human_decision_connection_instance = raw

                    transaction_closed = not raw.in_transaction
                    if raw.in_transaction:
                        raw.rollback()
                    if primary_kind == "ordinary":
                        precedence_preserved = (
                            isinstance(raised, StudioError)
                            and raised.code == "internal_error"
                            and raised.message
                            == "authenticated decision transaction failed"
                            and raised.__cause__ is original
                        )
                    else:
                        precedence_preserved = raised is original
                    tail = primary.connection.execute(
                        "SELECT event_id, content_hash FROM "
                        "studio_authenticated_human_decision_events "
                        "ORDER BY event_id DESC LIMIT 1"
                    ).fetchone()
                    safe_state = first._poisoned or (
                        first._anchor.event_id,
                        first._anchor.content_hash,
                    ) == (tail["event_id"], tail["content_hash"])
                    lifecycle_correct = (
                        not first._poisoned
                        and (
                            first._anchor.event_id,
                            first._anchor.content_hash,
                        )
                        == (tail["event_id"], tail["content_hash"])
                        if cleanup_site == "commit_after_effect"
                        else first._poisoned
                    )
                    retry_idempotent = True
                    if not first._poisoned:
                        try:
                            first.prepare(
                                tentative_review, expected_generation=0
                            )
                            before_retry = primary.connection.execute(
                                "SELECT COUNT(*) FROM "
                                "studio_authenticated_human_decision_events"
                            ).fetchone()[0]
                            first.prepare(
                                tentative_review, expected_generation=0
                            )
                            after_retry = primary.connection.execute(
                                "SELECT COUNT(*) FROM "
                                "studio_authenticated_human_decision_events"
                            ).fetchone()[0]
                            retry_idempotent = before_retry == after_retry == 2
                        except (ApprovalError, StudioError):
                            retry_idempotent = False
                    with sqlite3.connect(primary.database_path) as writer:
                        writer.execute(
                            "DELETE FROM studio_authenticated_human_decision_events"
                        )
                        writer.execute(
                            "DELETE FROM studio_authenticated_human_decisions"
                        )
                    rollback_error = None
                    try:
                        first.snapshot(observed_review)
                    except StudioError as exc:
                        rollback_error = exc
                    self.assertEqual(
                        (True, True, True, True, True, "invalid_state"),
                        (
                            precedence_preserved,
                            transaction_closed,
                            safe_state,
                            lifecycle_correct,
                            retry_idempotent,
                            None if rollback_error is None else rollback_error.code,
                        ),
                    )
                finally:
                    if secondary is not None:
                        secondary.close()
                    primary.close()

    def test_bootstrap_transaction_regions_have_no_unprotected_line_or_opcode_gap(
        self,
    ) -> None:
        cases = tuple(
            (operation, stage, error_kind)
            for operation in ("enroll", "unlock")
            for stage in ("post_begin", "pre_commit")
            for error_kind in ("ordinary", "baseexception")
        )
        for operation, stage, error_kind in cases:
            with (
                self.subTest(operation=operation, stage=stage, error=error_kind),
                tempfile.TemporaryDirectory() as directory,
            ):
                store = StudioStore(Path(directory) / "studio")
                try:
                    if operation == "unlock":
                        StudioAuthenticatedHumanDecisionAuthority.enroll(
                            store, passphrase=self._PASSPHRASE
                        )
                    raw = store._authenticated_human_decision_connection()
                    original: BaseException = (
                        RuntimeError(f"{operation} {stage} interruption")
                        if error_kind == "ordinary"
                        else _SimulatedCrash(f"{operation} {stage} interruption")
                    )
                    function = getattr(
                        StudioAuthenticatedHumanDecisionAuthority, operation
                    ).__func__
                    if stage == "post_begin":
                        target_line = self._source_line(
                            function,
                            "_verify_authenticated_human_decision_v6(connection)",
                        )
                        target_offset = None
                    else:
                        try:
                            target_line = self._source_line(
                                function,
                                "try:",
                                after_source_text=(
                                    "head = authority._audit_in_transaction()"
                                ),
                            )
                        except IndexError:
                            target_line = self._source_line(
                                function, 'phase = "commit"'
                            )
                        target_offset = None
                    call = partial(
                        getattr(StudioAuthenticatedHumanDecisionAuthority, operation),
                        store,
                        passphrase=self._PASSPHRASE,
                    )
                    fired, raised, previous_trace = self._run_with_trace_interruption(
                        call,
                        function=function,
                        error=original,
                        target_line=target_line,
                        target_offset=target_offset,
                    )
                    transaction_closed = self._connection_is_closed_or_idle(raw)
                    if not transaction_closed:
                        raw.rollback()
                    if error_kind == "baseexception":
                        precedence = raised is original
                    else:
                        expected_message = (
                            "credential enrollment failed"
                            if operation == "enroll"
                            else "authenticated decision audit failed"
                        )
                        precedence = (
                            isinstance(raised, StudioError)
                            and raised.message == expected_message
                            and raised.__cause__ is original
                        )
                    credential_count = store.connection.execute(
                        "SELECT COUNT(*) FROM studio_authenticated_human_credentials"
                    ).fetchone()[0]
                    store_usable = not (
                        store._authenticated_human_decision_connection_unavailable
                    )
                    self.assertEqual(
                        (True, True, True, int(operation == "unlock"), True),
                        (
                            fired,
                            precedence,
                            transaction_closed,
                            credential_count,
                            store_usable,
                        ),
                    )
                    self.assertIs(previous_trace, sys.gettrace())
                finally:
                    store.close()

    def test_live_read_transaction_region_interruptions_stabilize_exact_state(
        self,
    ) -> None:
        function = StudioAuthenticatedHumanDecisionAuthority._read_transaction.__wrapped__
        for stage in ("post_begin", "pre_commit"):
            for error_type in (RuntimeError, _SimulatedCrash):
                with (
                    self.subTest(stage=stage, error=error_type.__name__),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    data_dir = Path(directory) / "studio"
                    primary = StudioStore(data_dir)
                    secondary = None
                    try:
                        first = StudioAuthenticatedHumanDecisionAuthority.enroll(
                            primary, passphrase=self._PASSPHRASE
                        )
                        secondary = StudioStore(data_dir, mode="secondary")
                        second = StudioAuthenticatedHumanDecisionAuthority.unlock(
                            secondary, passphrase=self._PASSPHRASE
                        )
                        review = _review()
                        second.prepare(review, expected_generation=0)
                        initial_anchor = first._anchor
                        tail = primary.connection.execute(
                            "SELECT event_id, content_hash FROM "
                            "studio_authenticated_human_decision_events"
                        ).fetchone()
                        original = error_type(f"read {stage} interruption")
                        if stage == "post_begin":
                            target_line = self._source_line(
                                function, 'phase = "body"'
                            )
                            target_offset = None
                        else:
                            target_line = self._source_line(
                                function, 'phase = "commit"'
                            )
                            target_offset = None
                        fired, raised, previous_trace = (
                            self._run_with_trace_interruption(
                                partial(first.snapshot, review),
                                function=function,
                                error=original,
                                target_line=target_line,
                                target_offset=target_offset,
                            )
                        )
                        transaction_closed = self._connection_is_closed_or_idle(
                            first._connection
                        )
                        if not transaction_closed:
                            first._connection.rollback()
                        expected_anchor = (
                            (initial_anchor.event_id, initial_anchor.content_hash)
                            if stage == "post_begin"
                            else (tail["event_id"], tail["content_hash"])
                        )
                        anchored = (
                            first._anchor.event_id,
                            first._anchor.content_hash,
                        ) == expected_anchor
                        stable = first._poisoned or anchored
                        with sqlite3.connect(primary.database_path) as writer:
                            writer.execute(
                                "DELETE FROM studio_authenticated_human_decision_events"
                            )
                            writer.execute(
                                "DELETE FROM studio_authenticated_human_decisions"
                            )
                        rollback_error = None
                        rollback_state = None
                        try:
                            rollback_state = first.snapshot(review).state
                        except StudioError as exc:
                            rollback_error = exc
                        rollback_safe = (
                            rollback_error is not None
                            and rollback_error.code == "invalid_state"
                            if stage == "pre_commit" or first._poisoned
                            else rollback_error is None
                            and rollback_state == "missing"
                        )
                        self.assertEqual(
                            (True, True, True, True, True),
                            (
                                fired,
                                raised is original,
                                transaction_closed,
                                stable,
                                rollback_safe,
                            ),
                        )
                        self.assertIs(previous_trace, sys.gettrace())
                    finally:
                        if secondary is not None:
                            secondary.close()
                        primary.close()

    def test_completed_audit_result_store_opcode_retains_head_or_poisons(
        self,
    ) -> None:
        for transaction_kind in ("read", "write"):
            for error_type in (RuntimeError, _SimulatedCrash):
                with (
                    self.subTest(
                        transaction=transaction_kind,
                        error=error_type.__name__,
                    ),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    data_dir = Path(directory) / "studio"
                    primary = StudioStore(data_dir)
                    secondary = None
                    try:
                        first = StudioAuthenticatedHumanDecisionAuthority.enroll(
                            primary, passphrase=self._PASSPHRASE
                        )
                        observed_review = _review()
                        if transaction_kind == "read":
                            function = getattr(
                                StudioAuthenticatedHumanDecisionAuthority,
                                "_read_transaction",
                            ).__wrapped__
                            source_text = (
                                "head = self._audit_in_transaction(observed_heads)"
                            )
                            local_name = "head"
                            warm_operation = partial(first.snapshot, observed_review)
                        else:
                            function = getattr(
                                StudioAuthenticatedHumanDecisionAuthority,
                                "_write_transaction",
                            ).__wrapped__
                            source_text = (
                                "entry = self._audit_in_transaction(observed_entries)"
                            )
                            local_name = "entry"
                            warm_operation = partial(
                                first.prepare,
                                _review(
                                    approval_id="approval_warmup",
                                    execution_id="execution_warmup",
                                ),
                                expected_generation=0,
                            )
                        warmed, warm_error, _previous = (
                            self._run_with_trace_interruption(
                                warm_operation,
                                function=function,
                                error=AssertionError("unreachable warm-up offset"),
                                target_offset=-1,
                            )
                        )
                        self.assertEqual((False, None), (warmed, warm_error))
                        if transaction_kind == "read":
                            self.assertEqual(
                                "missing", first.snapshot(observed_review).state
                            )
                        secondary = StudioStore(data_dir, mode="secondary")
                        second = StudioAuthenticatedHumanDecisionAuthority.unlock(
                            secondary, passphrase=self._PASSPHRASE
                        )
                        second.prepare(observed_review, expected_generation=0)
                        observed = primary.connection.execute(
                            "SELECT event_id, content_hash FROM "
                            "studio_authenticated_human_decision_events "
                            "ORDER BY event_id DESC LIMIT 1"
                        ).fetchone()
                        if transaction_kind == "read":
                            operation = partial(first.snapshot, observed_review)
                        else:
                            operation = partial(
                                first.prepare,
                                _review(
                                    approval_id="approval_execution_02",
                                    execution_id="execution_02",
                                ),
                                expected_generation=0,
                            )
                        original = error_type(
                            f"{transaction_kind} audit result store interruption"
                        )
                        target_offset = self._store_fast_for_source_line(
                            function, source_text, local_name
                        )
                        fired, raised, previous_trace = (
                            self._run_with_trace_interruption(
                                operation,
                                function=function,
                                error=original,
                                target_offset=target_offset,
                            )
                        )
                        transaction_closed = self._connection_is_closed_or_idle(
                            first._connection
                        )
                        if not transaction_closed:
                            first._connection.rollback()
                        anchored = (
                            first._anchor.event_id,
                            first._anchor.content_hash,
                        ) == (observed["event_id"], observed["content_hash"])
                        with sqlite3.connect(primary.database_path) as writer:
                            writer.execute(
                                "DELETE FROM studio_authenticated_human_decision_events "
                                "WHERE event_id >= ?",
                                (observed["event_id"],),
                            )
                            writer.execute(
                                "DELETE FROM studio_authenticated_human_decisions "
                                "WHERE approval_id = ?",
                                (observed_review.approval_id,),
                            )
                        rollback_error = None
                        try:
                            first.snapshot(observed_review)
                        except StudioError as exc:
                            rollback_error = exc
                        self.assertEqual(
                            (True, True, True, True, "invalid_state"),
                            (
                                fired,
                                raised is original,
                                transaction_closed,
                                first._poisoned or anchored,
                                None
                                if rollback_error is None
                                else rollback_error.code,
                            ),
                        )
                        self.assertIs(previous_trace, sys.gettrace())
                    finally:
                        if secondary is not None:
                            secondary.close()
                        primary.close()

    def test_audit_result_recovery_interruption_preserves_latched_primary(
        self,
    ) -> None:
        primary_cases = (
            ("sqlite", sqlite3.OperationalError),
            ("domain", ApprovalError),
            ("baseexception", _SimulatedCrash),
        )
        for transaction_kind in ("read", "write"):
            for primary_kind, primary_type in primary_cases:
                for cleanup_type in (RuntimeError, _SimulatedCrash):
                    with (
                        self.subTest(
                            transaction=transaction_kind,
                            primary=primary_kind,
                            cleanup=cleanup_type.__name__,
                        ),
                        tempfile.TemporaryDirectory() as directory,
                    ):
                        store, authority = self._enrolled(directory)
                        try:
                            review = _review()
                            primary_error: BaseException = (
                                ApprovalError("approval_stale")
                                if primary_type is ApprovalError
                                else primary_type("audit return interruption")
                            )
                            cleanup = cleanup_type(
                                "audit result recovery interruption"
                            )
                            real_audit = authority._audit_in_transaction

                            def audit_then_raise(
                                *args: object, **kwargs: object
                            ) -> object:
                                real_audit(*args, **kwargs)
                                raise primary_error

                            if transaction_kind == "read":
                                function = getattr(
                                    StudioAuthenticatedHumanDecisionAuthority,
                                    "_read_transaction",
                                ).__wrapped__
                                recovery_text = (
                                    "if head is None and observed_heads:"
                                )
                                operation = partial(authority.snapshot, review)
                            else:
                                function = getattr(
                                    StudioAuthenticatedHumanDecisionAuthority,
                                    "_write_transaction",
                                ).__wrapped__
                                recovery_text = (
                                    "if entry is None and observed_entries:"
                                )
                                operation = partial(
                                    authority.prepare,
                                    review,
                                    expected_generation=0,
                                )
                            occurrence = {
                                "sqlite": 1,
                                "domain": 2,
                                "baseexception": 3,
                            }[primary_kind]
                            target_line = self._source_line(
                                function,
                                recovery_text,
                                occurrence=occurrence,
                            )
                            with mock.patch.object(
                                authority,
                                "_audit_in_transaction",
                                side_effect=audit_then_raise,
                            ):
                                fired, raised, previous_trace = (
                                    self._run_with_trace_interruption(
                                        operation,
                                        function=function,
                                        error=cleanup,
                                        target_line=target_line,
                                    )
                                )
                            if primary_kind == "sqlite":
                                precedence = (
                                    isinstance(raised, StudioError)
                                    and raised.code == "internal_error"
                                    and raised.__cause__ is primary_error
                                )
                            else:
                                precedence = raised is primary_error
                            transaction_closed = self._connection_is_closed_or_idle(
                                authority._connection
                            )
                            if not transaction_closed:
                                authority._connection.rollback()
                            later_error = None
                            try:
                                authority.snapshot(review)
                            except StudioError as exc:
                                later_error = exc
                            self.assertEqual(
                                (True, True, True, True, "invalid_state"),
                                (
                                    fired,
                                    precedence,
                                    transaction_closed,
                                    authority._poisoned,
                                    None
                                    if later_error is None
                                    else later_error.code,
                                ),
                            )
                            self.assertIs(previous_trace, sys.gettrace())
                        finally:
                            store.close()

    def test_live_cleanup_handler_interruptions_never_replace_latched_primary(
        self,
    ) -> None:
        cases = tuple(
            (transaction_kind, primary_kind, cleanup_type)
            for transaction_kind in ("read", "write")
            for primary_kind in ("domain", "sqlite")
            for cleanup_type in (RuntimeError, _SimulatedCrash)
        )
        for transaction_kind, primary_kind, cleanup_type in cases:
            with (
                self.subTest(
                    transaction=transaction_kind,
                    primary=primary_kind,
                    cleanup=cleanup_type.__name__,
                ),
                tempfile.TemporaryDirectory() as directory,
            ):
                store, authority = self._enrolled(directory)
                try:
                    review = _review()
                    primary_error: BaseException = (
                        ApprovalError("approval_stale")
                        if primary_kind == "domain"
                        else sqlite3.OperationalError("latched transaction failure")
                    )
                    cleanup = cleanup_type("cleanup handler interruption")
                    if transaction_kind == "read":
                        function = (
                            StudioAuthenticatedHumanDecisionAuthority._read_transaction.__wrapped__
                        )
                        occurrence = 2 if primary_kind == "domain" else 1
                        target_line = self._source_line(
                            function,
                            "self._retain_anchor_during_failure(head, exc)",
                            occurrence=occurrence,
                        )
                        patcher = mock.patch.object(
                            authority,
                            "_snapshot_in_transaction",
                            side_effect=primary_error,
                        )
                        operation = partial(authority.snapshot, review)
                    else:
                        function = (
                            StudioAuthenticatedHumanDecisionAuthority._write_transaction.__wrapped__
                        )
                        occurrence = 2 if primary_kind == "domain" else 1
                        target_line = self._source_line(
                            function,
                            "self._retain_anchor_during_failure(entry, exc)",
                            occurrence=occurrence,
                        )
                        patcher = mock.patch.object(
                            authority, "_row", side_effect=primary_error
                        )
                        operation = partial(
                            authority.prepare, review, expected_generation=0
                        )
                    with patcher:
                        fired, raised, previous_trace = (
                            self._run_with_trace_interruption(
                                operation,
                                function=function,
                                error=cleanup,
                                target_line=target_line,
                            )
                        )
                    transaction_closed = self._connection_is_closed_or_idle(
                        authority._connection
                    )
                    if not transaction_closed:
                        authority._connection.rollback()
                    if primary_kind == "domain":
                        precedence = raised is primary_error
                    else:
                        precedence = (
                            isinstance(raised, StudioError)
                            and raised.code == "internal_error"
                            and raised.__cause__ is primary_error
                        )
                    later_error = None
                    try:
                        authority.snapshot(review)
                    except StudioError as exc:
                        later_error = exc
                    self.assertEqual(
                        (True, True, True, True, "invalid_state"),
                        (
                            fired,
                            precedence,
                            transaction_closed,
                            authority._poisoned,
                            None if later_error is None else later_error.code,
                        ),
                    )
                    self.assertIs(previous_trace, sys.gettrace())
                finally:
                    store.close()

    def test_live_write_and_reconciliation_regions_have_no_unprotected_gap(
        self,
    ) -> None:
        function = StudioAuthenticatedHumanDecisionAuthority._write_transaction.__wrapped__
        for stage in ("post_begin", "pre_commit"):
            for error_type in (RuntimeError, _SimulatedCrash):
                with (
                    self.subTest(stage=stage, error=error_type.__name__),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    store, authority = self._enrolled(directory)
                    try:
                        review = _review()
                        original = error_type(f"write {stage} interruption")
                        if stage == "post_begin":
                            target_line = self._source_line(
                                function, 'phase = "body"'
                            )
                            target_offset = None
                        else:
                            target_line = self._source_line(
                                function, 'phase = "commit"'
                            )
                            target_offset = None
                        fired, raised, previous_trace = (
                            self._run_with_trace_interruption(
                                partial(
                                    authority.prepare,
                                    review,
                                    expected_generation=0,
                                ),
                                function=function,
                                error=original,
                                target_line=target_line,
                                target_offset=target_offset,
                            )
                        )
                        transaction_closed = self._connection_is_closed_or_idle(
                            authority._connection
                        )
                        if not transaction_closed:
                            authority._connection.rollback()
                        stable = authority._poisoned or authority._anchor.event_id == 0
                        projection_count = store.connection.execute(
                            "SELECT COUNT(*) FROM studio_authenticated_human_decisions"
                        ).fetchone()[0]
                        later_error = None
                        try:
                            authority.snapshot(review)
                        except StudioError as exc:
                            later_error = exc
                        usable_or_poisoned = (
                            later_error is not None
                            if authority._poisoned
                            else authority.snapshot(review).state == "missing"
                        )
                        self.assertEqual(
                            (True, True, True, True, 0, True),
                            (
                                fired,
                                raised is original,
                                transaction_closed,
                                stable,
                                projection_count,
                                usable_or_poisoned,
                            ),
                        )
                        self.assertIs(previous_trace, sys.gettrace())
                    finally:
                        store.close()

        reconciliation = (
            StudioAuthenticatedHumanDecisionAuthority._reconcile_failed_write_commit
        )
        for primary_kind in ("sqlite", "baseexception"):
            for cleanup_type in (RuntimeError, _SimulatedCrash):
                with (
                    self.subTest(
                        stage="reconciliation_pre_commit",
                        primary=primary_kind,
                        cleanup=cleanup_type.__name__,
                    ),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    store, authority = self._enrolled(directory)
                    try:
                        review = _review()
                        primary_error = (
                            sqlite3.OperationalError("latched commit failure")
                            if primary_kind == "sqlite"
                            else _SimulatedCrash("latched commit interruption")
                        )
                        cleanup = cleanup_type(
                            "reconciliation pre-commit interruption"
                        )
                        raw = authority._connection
                        fault = _SequencedTransactionFaultConnection(
                            raw, commit_faults=((primary_error, False),)
                        )
                        authority._connection = fault
                        store._authenticated_human_decision_connection_instance = fault
                        target_line = self._source_line(
                            reconciliation, "commit_started = True"
                        )
                        fired, raised, previous_trace = (
                            self._run_with_trace_interruption(
                                partial(
                                    authority.prepare,
                                    review,
                                    expected_generation=0,
                                ),
                                function=reconciliation,
                                error=cleanup,
                                target_line=target_line,
                            )
                        )
                        authority._connection = raw
                        store._authenticated_human_decision_connection_instance = raw
                        transaction_closed = not raw.in_transaction
                        if raw.in_transaction:
                            raw.rollback()
                        if primary_kind == "sqlite":
                            precedence = (
                                isinstance(raised, StudioError)
                                and raised.code == "internal_error"
                                and raised.__cause__ is primary_error
                            )
                        else:
                            precedence = raised is primary_error
                        self.assertEqual(
                            (True, True, True, True),
                            (
                                fired,
                                precedence,
                                transaction_closed,
                                authority._poisoned,
                            ),
                        )
                        self.assertIs(previous_trace, sys.gettrace())
                    finally:
                        store.close()

        for primary_kind in ("sqlite", "baseexception"):
            for cleanup_type in (RuntimeError, _SimulatedCrash):
                with (
                    self.subTest(
                        stage="after_reconciliation",
                        primary=primary_kind,
                        cleanup=cleanup_type.__name__,
                    ),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    store, authority = self._enrolled(directory)
                    try:
                        review = _review()
                        primary_error: BaseException = (
                            sqlite3.OperationalError("latched commit failure")
                            if primary_kind == "sqlite"
                            else _SimulatedCrash("latched commit interruption")
                        )
                        cleanup = cleanup_type(
                            "post-reconciliation handler interruption"
                        )
                        raw = authority._connection
                        fault = _SequencedTransactionFaultConnection(
                            raw, commit_faults=((primary_error, False),)
                        )
                        authority._connection = fault
                        store._authenticated_human_decision_connection_instance = fault
                        if primary_kind == "sqlite":
                            target_line = self._source_line(
                                function,
                                "_raise_latched_failure(failure)",
                                after_source_text=(
                                    "self._reconcile_failed_write_commit(entry, final, exc)"
                                ),
                                after_occurrence=1,
                            )
                        else:
                            target_line = self._source_line(
                                function,
                                "_raise_latched_failure(failure)",
                                after_source_text=(
                                    "self._reconcile_failed_write_commit(entry, final, exc)"
                                ),
                                after_occurrence=3,
                            )
                        fired, raised, previous_trace = (
                            self._run_with_trace_interruption(
                                partial(
                                    authority.prepare,
                                    review,
                                    expected_generation=0,
                                ),
                                function=function,
                                error=cleanup,
                                target_line=target_line,
                            )
                        )
                        authority._connection = raw
                        store._authenticated_human_decision_connection_instance = raw
                        transaction_closed = not raw.in_transaction
                        if raw.in_transaction:
                            raw.rollback()
                        if primary_kind == "sqlite":
                            precedence = (
                                isinstance(raised, StudioError)
                                and raised.code == "internal_error"
                                and raised.__cause__ is primary_error
                            )
                        else:
                            precedence = raised is primary_error
                        later_error = None
                        try:
                            authority.snapshot(review)
                        except StudioError as exc:
                            later_error = exc
                        self.assertEqual(
                            (True, True, True, True, "invalid_state"),
                            (
                                fired,
                                precedence,
                                transaction_closed,
                                authority._poisoned,
                                None if later_error is None else later_error.code,
                            ),
                        )
                        self.assertIs(previous_trace, sys.gettrace())
                    finally:
                        store.close()

    def test_handler_binding_and_failure_latch_interruptions_preserve_primary(
        self,
    ) -> None:
        enroll_function = StudioAuthenticatedHumanDecisionAuthority.enroll.__func__
        with tempfile.TemporaryDirectory() as warm_directory:
            warm_store = StudioStore(Path(warm_directory) / "studio")
            try:
                warmed, warm_error, _previous = self._run_with_trace_interruption(
                    partial(
                        StudioAuthenticatedHumanDecisionAuthority.enroll,
                        warm_store,
                        passphrase=self._PASSPHRASE,
                    ),
                    function=enroll_function,
                    error=AssertionError("unreachable warm-up offset"),
                    target_offset=-1,
                )
                self.assertEqual((False, None), (warmed, warm_error))
            finally:
                warm_store.close()
        cases = tuple(
            (operation, primary_kind, latch_site)
            for operation in ("enroll", "unlock", "read", "write")
            for primary_kind in ("domain", "sqlite", "runtime", "baseexception")
            for latch_site in ("exception_binding", "failure_latch")
        )
        for operation, primary_kind, latch_site in cases:
            with (
                self.subTest(
                    operation=operation,
                    primary=primary_kind,
                    latch_site=latch_site,
                ),
                tempfile.TemporaryDirectory() as directory,
            ):
                data_dir = Path(directory) / "studio"
                store = StudioStore(data_dir)
                authority = None
                try:
                    if operation == "unlock":
                        StudioAuthenticatedHumanDecisionAuthority.enroll(
                            store, passphrase=self._PASSPHRASE
                        )
                    elif operation in {"read", "write"}:
                        authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                            store, passphrase=self._PASSPHRASE
                        )
                    raw = store._authenticated_human_decision_connection()
                    if primary_kind == "domain":
                        primary: BaseException = (
                            StudioError("invalid_state", "primary domain failure")
                            if operation in {"enroll", "unlock"}
                            else ApprovalError("approval_stale")
                        )
                    elif primary_kind == "sqlite":
                        primary = sqlite3.OperationalError("primary sqlite failure")
                    elif primary_kind == "runtime":
                        primary = RuntimeError("primary ordinary failure")
                    else:
                        primary = _SimulatedCrash("primary interruption")
                    secondary = _SimulatedCrash("failure latch interruption")
                    if operation in {"enroll", "unlock"}:
                        function = getattr(
                            StudioAuthenticatedHumanDecisionAuthority, operation
                        ).__func__
                        range_start = "except BaseException as exc:"
                        patcher = mock.patch(
                            "worldforge.studio.authenticated_human_decisions."
                            "_verify_authenticated_human_decision_v6",
                            side_effect=primary,
                        )
                        call = partial(
                            getattr(
                                StudioAuthenticatedHumanDecisionAuthority, operation
                            ),
                            store,
                            passphrase=self._PASSPHRASE,
                        )
                    else:
                        self.assertIsNotNone(authority)
                        function = getattr(
                            StudioAuthenticatedHumanDecisionAuthority,
                            f"_{operation}_transaction",
                        ).__wrapped__
                        range_start = "except sqlite3.Error as exc:"
                        patcher = mock.patch.object(
                            authority, "_audit_in_transaction", side_effect=primary
                        )
                        review = _review()
                        call = (
                            partial(authority.snapshot, review)
                            if operation == "read"
                            else partial(
                                authority.prepare,
                                review,
                                expected_generation=0,
                            )
                        )
                    target_offsets = self._store_fast_offsets_in_source_range(
                        function,
                        "exc" if latch_site == "exception_binding" else "failure",
                        start_source_text=range_start,
                        end_source_text="except BaseException as escaped:",
                    )
                    observed_contexts: list[BaseException | None] = []

                    def observe_cleanup(error: BaseException) -> None:
                        observed_contexts.append(secondary.__context__)
                        _note_indeterminate_cleanup(error)

                    with patcher, mock.patch(
                        "worldforge.studio.authenticated_human_decisions."
                        "_note_indeterminate_cleanup",
                        side_effect=observe_cleanup,
                    ):
                        fired, raised, previous_trace = (
                            self._run_with_trace_interruption(
                                call,
                                function=function,
                                error=secondary,
                                target_offsets=target_offsets,
                            )
                        )
                    context_is_primary = bool(observed_contexts) and (
                        observed_contexts[0] is primary
                    )
                    transaction_closed = self._connection_is_closed_or_idle(raw)
                    if not transaction_closed:
                        raw.rollback()
                    precedence = self._primary_failure_has_precedence(
                        raised,
                        primary,
                        operation=operation,
                        primary_kind=primary_kind,
                    )
                    if operation in {"enroll", "unlock"}:
                        failed_closed = (
                            store._authenticated_human_decision_connection_unavailable
                        )
                        followup_rejected = failed_closed
                        credential_count = store.connection.execute(
                            "SELECT COUNT(*) FROM "
                            "studio_authenticated_human_credentials"
                        ).fetchone()[0]
                        state_exact = credential_count == int(operation == "unlock")
                    else:
                        failed_closed = bool(authority._poisoned)
                        followup_error = None
                        try:
                            authority.snapshot(_review())
                        except StudioError as exc:
                            followup_error = exc
                        followup_rejected = (
                            followup_error is not None
                            and followup_error.code == "invalid_state"
                        )
                        state_exact = (
                            store.connection.execute(
                                "SELECT COUNT(*) FROM "
                                "studio_authenticated_human_decision_events"
                            ).fetchone()[0]
                            == 0
                        )
                    self.assertEqual(
                        (True, True, True, True, True, True, True),
                        (
                            fired,
                            context_is_primary,
                            precedence,
                            transaction_closed,
                            failed_closed,
                            followup_rejected,
                            state_exact,
                        ),
                    )
                    self.assertIs(previous_trace, sys.gettrace())
                finally:
                    store.close()

    def test_immediate_primary_recovery_is_closed_and_rejects_cycles(self) -> None:
        primary = RuntimeError("primary")
        older = ValueError("older context")
        primary.__context__ = older
        secondary = _SimulatedCrash("secondary")
        secondary.__context__ = primary
        self.assertIs(primary, _immediate_interrupted_primary(secondary))

        self_referential = _SimulatedCrash("self-referential")
        self_referential.__context__ = self_referential
        self.assertIsNone(_immediate_interrupted_primary(self_referential))

        cycle_primary = RuntimeError("cycle primary")
        cycle_secondary = _SimulatedCrash("cycle secondary")
        cycle_secondary.__context__ = cycle_primary
        cycle_primary.__context__ = cycle_secondary
        self.assertIsNone(_immediate_interrupted_primary(cycle_secondary))

        cause_primary = RuntimeError("cause primary")
        cause_secondary = _SimulatedCrash("cause secondary")
        cause_secondary.__context__ = cause_primary
        cause_primary.__cause__ = cause_secondary
        self.assertIsNone(_immediate_interrupted_primary(cause_secondary))

    def test_write_commit_handler_entry_interruptions_preserve_primary(
        self,
    ) -> None:
        function = (
            StudioAuthenticatedHumanDecisionAuthority._write_transaction.__wrapped__
        )
        for occurrence, primary_kind in enumerate(
            ("sqlite", "runtime", "baseexception"), start=1
        ):
            with (
                self.subTest(primary=primary_kind),
                tempfile.TemporaryDirectory() as directory,
            ):
                store, authority = self._enrolled(directory)
                raw = authority._connection
                primary: BaseException
                if primary_kind == "sqlite":
                    primary = sqlite3.OperationalError("primary commit failure")
                elif primary_kind == "runtime":
                    primary = RuntimeError("primary commit failure")
                else:
                    primary = _SimulatedCrash("primary commit interruption")
                secondary = _SimulatedCrash("commit handler entry interruption")
                fault = _SequencedTransactionFaultConnection(
                    raw, commit_faults=((primary, False),)
                )
                authority._connection = fault
                store._authenticated_human_decision_connection_instance = fault
                try:
                    target_offset = self._opcode_before_source_line(
                        function,
                        "self._reconcile_failed_write_commit(entry, final, exc)",
                        occurrence=occurrence,
                    )
                    observed_contexts: list[BaseException | None] = []

                    def observe_cleanup(error: BaseException) -> None:
                        observed_contexts.append(secondary.__context__)
                        _note_indeterminate_cleanup(error)

                    with mock.patch(
                        "worldforge.studio.authenticated_human_decisions."
                        "_note_indeterminate_cleanup",
                        side_effect=observe_cleanup,
                    ):
                        fired, raised, previous_trace = (
                            self._run_with_trace_interruption(
                                partial(
                                    authority.prepare,
                                    _review(),
                                    expected_generation=0,
                                ),
                                function=function,
                                error=secondary,
                                target_offset=target_offset,
                            )
                        )
                    context_is_primary = bool(observed_contexts) and (
                        observed_contexts[0] is primary
                    )
                    transaction_closed = not raw.in_transaction
                    if raw.in_transaction:
                        raw.rollback()
                    precedence = self._primary_failure_has_precedence(
                        raised,
                        primary,
                        operation="write",
                        primary_kind=primary_kind,
                    )
                    projection_count = store.connection.execute(
                        "SELECT COUNT(*) FROM "
                        "studio_authenticated_human_decisions"
                    ).fetchone()[0]
                    followup_error = None
                    try:
                        authority.snapshot(_review())
                    except StudioError as exc:
                        followup_error = exc
                    self.assertEqual(
                        (True, True, True, True, True, 0, "invalid_state"),
                        (
                            fired,
                            context_is_primary,
                            precedence,
                            transaction_closed,
                            authority._poisoned,
                            projection_count,
                            None if followup_error is None else followup_error.code,
                        ),
                    )
                    self.assertIs(previous_trace, sys.gettrace())
                finally:
                    authority._connection = raw
                    store._authenticated_human_decision_connection_instance = raw
                    if raw.in_transaction:
                        raw.rollback()
                    store.close()

    def test_explicit_enrollment_persists_only_fixed_scrypt_verifier_and_unlocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            row = store.connection.execute(
                "SELECT credential_id, kdf_name, kdf_n, kdf_r, kdf_p, kdf_dklen, "
                "kdf_maxmem, salt, verifier FROM studio_authenticated_human_credentials"
            ).fetchone()
            self.assertEqual("director_local", row["credential_id"])
            self.assertEqual("scrypt", row["kdf_name"])
            self.assertEqual((32768, 8, 1, 32, 67108864), tuple(row)[2:7])
            self.assertEqual(32, len(row["salt"]))
            self.assertEqual(32, len(row["verifier"]))
            self.assertNotIn(self._PASSPHRASE.encode("utf-8"), store.database_path.read_bytes())
            with self.assertRaisesRegex(StudioError, "credential already enrolled"):
                StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=self._PASSPHRASE
                )
            with self.assertRaisesRegex(StudioError, "authentication failed"):
                StudioAuthenticatedHumanDecisionAuthority.unlock(
                    store, passphrase="wrong passphrase with enough UTF-8 bytes"
                )

            store.close()
            reopened = StudioStore(Path(directory) / "studio")
            self.addCleanup(reopened.close)
            unlocked = StudioAuthenticatedHumanDecisionAuthority.unlock(
                reopened, passphrase=self._PASSPHRASE
            )
            self.assertIsNotNone(unlocked)
            self.assertEqual("missing", unlocked.snapshot(_review()).state)

    def test_fresh_unlock_rejects_malformed_credential_created_at(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            store, _authority = self._enrolled(directory)
            store.close()
            with sqlite3.connect(data_dir / "studio.sqlite3") as writer:
                writer.execute(
                    "UPDATE studio_authenticated_human_credentials "
                    "SET created_at = 'not-a-timestamp'"
                )

            with StudioStore(data_dir) as reopened:
                with self.assertRaises(StudioError):
                    StudioAuthenticatedHumanDecisionAuthority.unlock(
                        reopened, passphrase=self._PASSPHRASE
                    )

    def test_fresh_unlock_rejects_different_canonical_credential_created_at(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            store, _authority = self._enrolled(directory)
            store.close()
            with sqlite3.connect(data_dir / "studio.sqlite3") as writer:
                writer.execute(
                    "UPDATE studio_authenticated_human_credentials SET created_at = ?",
                    ("2000-01-01T00:00:00.000000Z",),
                )

            with StudioStore(data_dir) as reopened:
                with self.assertRaises(StudioError):
                    StudioAuthenticatedHumanDecisionAuthority.unlock(
                        reopened, passphrase=self._PASSPHRASE
                    )

    def test_fresh_unlock_rejects_every_fixed_credential_envelope_drift(
        self,
    ) -> None:
        mutations: tuple[tuple[str, object], ...] = (
            ("credential_id", "director_other"),
            ("kdf_name", "scrypt_other"),
            ("kdf_n", 16_384),
            ("kdf_r", 4),
            ("kdf_p", 2),
            ("kdf_dklen", 31),
            ("kdf_maxmem", 33_554_432),
            ("salt", bytes(range(32))),
            ("created_at", "2000-01-01T00:00:00.000000Z"),
        )
        for column, value in mutations:
            with self.subTest(column=column), tempfile.TemporaryDirectory() as directory:
                data_dir = Path(directory) / "studio"
                store, _authority = self._enrolled(directory)
                store.close()
                with sqlite3.connect(data_dir / "studio.sqlite3") as writer:
                    writer.execute("PRAGMA ignore_check_constraints = ON")
                    writer.execute(
                        f"UPDATE studio_authenticated_human_credentials "
                        f'SET "{column}" = ?',
                        (value,),
                    )

                with StudioStore(data_dir) as reopened:
                    with self.assertRaises(StudioError):
                        StudioAuthenticatedHumanDecisionAuthority.unlock(
                            reopened, passphrase=self._PASSPHRASE
                        )

    def test_canonical_timestamp_accepts_year_one_independently_of_strftime(
        self,
    ) -> None:
        canonical = "0001-01-01T00:00:00.000000Z"
        self.assertEqual(canonical, _canonical_utc_timestamp(canonical))
        for invalid in (
            "0000-01-01T00:00:00.000000Z",
            "10000-01-01T00:00:00.000000Z",
            "0001-01-01T00:00:00.00000Z",
            "0001-01-01T00:00:00.000000+00:00",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                _canonical_utc_timestamp(invalid)

    def test_mixed_case_authority_prefix_objects_fail_private_open_and_live_use(
        self,
    ) -> None:
        objects = (
            (
                "table",
                "CREATE TABLE Studio_Authenticated_Human_extra_table (value TEXT)",
            ),
            (
                "index",
                "CREATE INDEX Studio_Authenticated_Human_extra_index "
                "ON schema_meta(value)",
            ),
            (
                "view",
                "CREATE VIEW Studio_Authenticated_Human_extra_view AS "
                "SELECT value FROM schema_meta",
            ),
            (
                "trigger",
                "CREATE TRIGGER Studio_Authenticated_Human_extra_trigger "
                "AFTER UPDATE ON schema_meta BEGIN SELECT 1; END",
            ),
        )
        expected = (
            "invalid_state",
            "Authenticated decision database schema is invalid",
        )
        observed: dict[str, tuple[str, str]] = {}
        for object_type, sql in objects:
            with tempfile.TemporaryDirectory() as directory:
                store = StudioStore(Path(directory) / "studio")
                try:
                    with sqlite3.connect(store.database_path) as writer:
                        writer.execute(sql)
                    try:
                        store._authenticated_human_decision_connection()
                    except StudioError as exc:
                        observed[f"{object_type}:private_open"] = (
                            exc.code,
                            exc.message,
                        )
                    else:
                        observed[f"{object_type}:private_open"] = ("accepted", "")
                finally:
                    store.close()

            with tempfile.TemporaryDirectory() as directory:
                store, authority = self._enrolled(directory)
                try:
                    with sqlite3.connect(store.database_path) as writer:
                        writer.execute(sql)
                    review = _review(
                        approval_id=f"approval_mixed_{object_type}",
                        execution_id=f"execution_mixed_{object_type}",
                    )
                    for operation, invoke in (
                        ("read", lambda: authority.snapshot(review)),
                        (
                            "write",
                            lambda: authority.prepare(review, expected_generation=0),
                        ),
                    ):
                        try:
                            invoke()
                        except StudioError as exc:
                            observed[f"{object_type}:{operation}"] = (
                                exc.code,
                                exc.message,
                            )
                        else:
                            observed[f"{object_type}:{operation}"] = ("accepted", "")
                finally:
                    store.close()

        self.assertEqual(3 * len(objects), len(observed))
        self.assertTrue(all(result == expected for result in observed.values()), observed)

    def test_persisted_decisions_require_fixed_director_reviewer_on_live_and_reopen(
        self,
    ) -> None:
        observed: dict[str, str] = {}
        for outcome in ("approved", "denied"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                data_dir = Path(directory) / "studio"
                store, authority = self._enrolled(directory)
                review = _review()
                authority.prepare(review, expected_generation=0)
                decision = _decision(
                    review,
                    reviewer_id="other_director",
                    outcome=outcome,
                    approved_tool_ids=("source.read",) if outcome == "approved" else (),
                    expires_at_ms=2_000 if outcome == "approved" else None,
                )
                _forge_authenticated_transition(
                    store,
                    authority,
                    event_type="decided",
                    review=review,
                    decision=decision,
                    state=outcome,
                    generation=1,
                )
                try:
                    authority.snapshot(review)
                except StudioError as exc:
                    observed[f"{outcome}:live"] = exc.code
                else:
                    observed[f"{outcome}:live"] = "accepted"
                store.close()
                with StudioStore(data_dir) as reopened:
                    try:
                        StudioAuthenticatedHumanDecisionAuthority.unlock(
                            reopened, passphrase=self._PASSPHRASE
                        )
                    except StudioError as exc:
                        observed[f"{outcome}:reopen"] = exc.code
                    else:
                        observed[f"{outcome}:reopen"] = "accepted"

        self.assertEqual(
            {
                "approved:live": "invalid_state",
                "approved:reopen": "invalid_state",
                "denied:live": "invalid_state",
                "denied:reopen": "invalid_state",
            },
            observed,
        )

    def test_event_audit_rejects_noncanonical_or_invalid_authenticated_timestamps(
        self,
    ) -> None:
        timestamps = (
            "not-a-timestamp",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00.000Z",
            "2026-01-01T00:00:00.0000000Z",
            "2026-01-01T00:00:00.000000+00:00",
            "2026-01-01T00:00:00.000000z",
            "2026-02-30T00:00:00.000000Z",
        )
        for timestamp in timestamps:
            with self.subTest(timestamp=timestamp), tempfile.TemporaryDirectory() as directory:
                data_dir = Path(directory) / "studio"
                store, authority = self._enrolled(directory)
                review = _review()
                authority.prepare(review, expected_generation=0)
                row = store.connection.execute(
                    "SELECT content_json FROM "
                    "studio_authenticated_human_decision_events WHERE event_type = 'prepared'"
                ).fetchone()
                document = json.loads(row["content_json"])
                document["updated_at"] = timestamp
                content_json = encode_json(document)
                content_hash = hashlib.sha256(content_json.encode("utf-8")).hexdigest()
                database_path = store.database_path
                event_key = authority._event_key
                store.close()
                with sqlite3.connect(database_path) as writer:
                    writer.execute(
                        "UPDATE studio_authenticated_human_decision_events SET "
                        "content_json = ?, content_hash = ?, mac = ?, created_at = ? "
                        "WHERE event_type = 'prepared'",
                        (
                            content_json,
                            content_hash,
                            _event_mac(event_key, document),
                            timestamp,
                        ),
                    )
                    writer.execute(
                        "UPDATE studio_authenticated_human_decisions SET "
                        "last_event_hash = ?, updated_at = ? WHERE approval_id = ?",
                        (content_hash, timestamp, review.approval_id),
                    )

                with StudioStore(data_dir) as reopened:
                    with self.assertRaises(StudioError):
                        StudioAuthenticatedHumanDecisionAuthority.unlock(
                            reopened, passphrase=self._PASSPHRASE
                        )

    def test_exact_authority_inputs_reject_before_any_transaction_or_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            prepared = _review(
                approval_id="approval_input_prepared",
                execution_id="execution_input_prepared",
            )
            approved = _review(
                approval_id="approval_input_approved",
                execution_id="execution_input_approved",
            )
            prepared_decision = _decision(prepared)
            approved_decision = _decision(approved)
            authority.prepare(prepared, expected_generation=0)
            authority.prepare(approved, expected_generation=0)
            authority.decide(
                approved_decision,
                expected_generation=0,
                expected_review_hash=approved.content_hash,
            )
            before = (
                tuple(
                    store.connection.execute(
                        "SELECT * FROM studio_authenticated_human_decisions "
                        "ORDER BY approval_id"
                    ).fetchall()
                ),
                tuple(
                    store.connection.execute(
                        "SELECT * FROM studio_authenticated_human_decision_events "
                        "ORDER BY event_id"
                    ).fetchall()
                ),
            )

            write_cases: list[tuple[str, str, object]] = []
            for invalid_hash in (
                _TextSubclass(prepared.content_hash),
                "A" * 64,
                "g" * 64,
                "a" * 63,
            ):
                write_cases.append(
                    (
                        f"decide_review_hash_{invalid_hash!r}",
                        "approval_stale",
                        lambda invalid_hash=invalid_hash: authority.decide(
                            prepared_decision,
                            expected_generation=0,
                            expected_review_hash=invalid_hash,
                        ),
                    )
                )
            for invalid_id in (
                _TextSubclass(approved.approval_id),
                "A_bad",
                "bad-id",
                "a",
                "a" * 65,
            ):
                write_cases.append(
                    (
                        f"revoke_approval_id_{invalid_id!r}",
                        "approval_stale",
                        lambda invalid_id=invalid_id: authority.revoke(
                            invalid_id,
                            expected_generation=1,
                            expected_decision_hash=approved_decision.content_hash,
                        ),
                    )
                )
            for invalid_hash in (
                _TextSubclass(approved_decision.content_hash),
                "A" * 64,
                "g" * 64,
                "a" * 63,
            ):
                write_cases.append(
                    (
                        f"revoke_decision_hash_{invalid_hash!r}",
                        "approval_stale",
                        lambda invalid_hash=invalid_hash: authority.revoke(
                            approved.approval_id,
                            expected_generation=1,
                            expected_decision_hash=invalid_hash,
                        ),
                    )
                )
            for operation, invoke in (
                (
                    "prepare_generation_bool",
                    lambda: authority.prepare(prepared, expected_generation=True),
                ),
                (
                    "decide_generation_negative",
                    lambda: authority.decide(
                        prepared_decision,
                        expected_generation=-1,
                        expected_review_hash=prepared.content_hash,
                    ),
                ),
                (
                    "revoke_generation_too_large",
                    lambda: authority.revoke(
                        approved.approval_id,
                        expected_generation=MAX_SAFE_INTEGER + 1,
                        expected_decision_hash=approved_decision.content_hash,
                    ),
                ),
            ):
                write_cases.append((operation, "approval_stale", invoke))

            for field in (
                "approval_id",
                "execution_id",
                "activation_hash",
                "grant_hash",
                "private_input_hash",
                "runtime_id",
                "runtime_content_hash",
                "content_hash",
            ):
                invalid_review = replace(
                    prepared,
                    **{field: _TextSubclass(getattr(prepared, field))},
                )
                write_cases.append(
                    (
                        f"prepare_review_{field}_subclass",
                        "approval_review_invalid",
                        lambda invalid_review=invalid_review: authority.prepare(
                            invalid_review, expected_generation=0
                        ),
                    )
                )
            for field in (
                "approval_id",
                "execution_id",
                "review_hash",
                "reviewer_id",
                "content_hash",
            ):
                invalid_decision = replace(
                    prepared_decision,
                    **{field: _TextSubclass(getattr(prepared_decision, field))},
                )
                write_cases.append(
                    (
                        f"decide_{field}_subclass",
                        "approval_decision_invalid",
                        lambda invalid_decision=invalid_decision: authority.decide(
                            invalid_decision,
                            expected_generation=0,
                            expected_review_hash=prepared.content_hash,
                        ),
                    )
                )

            for name, reason, invoke in write_cases:
                with self.subTest(name=name), mock.patch.object(
                    authority,
                    "_write_transaction",
                    side_effect=AssertionError("invalid input entered write transaction"),
                ):
                    with self.assertRaises(ApprovalError) as raised:
                        invoke()  # type: ignore[operator]
                    self.assertEqual(reason, raised.exception.reason_code)

            invalid_snapshot_review = replace(
                prepared,
                approval_id=_TextSubclass(prepared.approval_id),
            )
            for operation, invoke in (
                ("snapshot", lambda: authority.snapshot(invalid_snapshot_review)),
                (
                    "check_review",
                    lambda: authority.check(invalid_snapshot_review, now_ms=0),
                ),
            ):
                with self.subTest(operation=operation), mock.patch.object(
                    authority,
                    "_read_transaction",
                    side_effect=AssertionError("invalid input entered read transaction"),
                ):
                    with self.assertRaises(ApprovalError):
                        invoke()

            for now_ms in (True, -1, MAX_SAFE_INTEGER + 1, 10**100):
                with self.subTest(now_ms=now_ms), mock.patch.object(
                    authority,
                    "snapshot",
                    side_effect=AssertionError("invalid time reached snapshot"),
                ):
                    with self.assertRaises(ApprovalError) as raised:
                        authority.check(approved, now_ms=now_ms)
                    self.assertEqual(
                        "approval_check_failed",
                        raised.exception.reason_code,
                    )

            after = (
                tuple(
                    store.connection.execute(
                        "SELECT * FROM studio_authenticated_human_decisions "
                        "ORDER BY approval_id"
                    ).fetchall()
                ),
                tuple(
                    store.connection.execute(
                        "SELECT * FROM studio_authenticated_human_decision_events "
                        "ORDER BY event_id"
                    ).fetchall()
                ),
            )
            self.assertEqual(before, after)

    def test_durable_authority_exposes_harness_fingerprint_hash_parity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)
            self.assertEqual(
                (review.content_hash, None),
                authority.fingerprint_hashes(review),
            )
            authority.prepare(review, expected_generation=0)
            self.assertEqual(
                (review.content_hash, None),
                authority.fingerprint_hashes(review),
            )
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            self.assertEqual(
                (review.content_hash, decision.content_hash),
                authority.fingerprint_hashes(review),
            )

    def test_exact_prepare_replay_matches_in_memory_after_every_transition(self) -> None:
        for state in ("prepared", "approved", "denied", "revoked"):
            with (
                self.subTest(state=state),
                tempfile.TemporaryDirectory() as directory,
                StudioStore(Path(directory) / "studio") as store,
            ):
                durable = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    store, passphrase=self._PASSPHRASE
                )
                in_memory = InMemoryHumanApprovalAuthority()
                review = _review()
                replay = replace(review)
                mismatch = _review(runtime_revision=2)
                authorities = (in_memory, durable)
                for authority in authorities:
                    authority.prepare(review, expected_generation=0)
                if state != "prepared":
                    decision = _decision(
                        review,
                        outcome=state if state != "revoked" else "approved",
                        approved_tool_ids=()
                        if state == "denied"
                        else ("source.read",),
                        expires_at_ms=None if state == "denied" else 2_000,
                    )
                    for authority in authorities:
                        authority.decide(
                            decision,
                            expected_generation=0,
                            expected_review_hash=review.content_hash,
                        )
                    if state == "revoked":
                        for authority in authorities:
                            authority.revoke(
                                review.approval_id,
                                expected_generation=1,
                                expected_decision_hash=decision.content_hash,
                            )

                memory_before = in_memory.snapshot(review)
                durable_before = durable.snapshot(review)
                persisted_before = (
                    tuple(
                        tuple(row)
                        for row in store.connection.execute(
                            "SELECT * FROM studio_authenticated_human_decisions "
                            "ORDER BY approval_id"
                        ).fetchall()
                    ),
                    tuple(
                        tuple(row)
                        for row in store.connection.execute(
                            "SELECT * FROM studio_authenticated_human_decision_events "
                            "ORDER BY event_id"
                        ).fetchall()
                    ),
                )

                self.assertEqual(
                    in_memory.prepare(replay, expected_generation=0),
                    durable.prepare(replay, expected_generation=0),
                )
                self.assertEqual(review, durable.prepare(replay, expected_generation=0))
                self.assertEqual(memory_before, in_memory.snapshot(review))
                self.assertEqual(durable_before, durable.snapshot(review))
                self.assertEqual(
                    persisted_before,
                    (
                        tuple(
                            tuple(row)
                            for row in store.connection.execute(
                                "SELECT * FROM studio_authenticated_human_decisions "
                                "ORDER BY approval_id"
                            ).fetchall()
                        ),
                        tuple(
                            tuple(row)
                            for row in store.connection.execute(
                                "SELECT * FROM "
                                "studio_authenticated_human_decision_events "
                                "ORDER BY event_id"
                            ).fetchall()
                        ),
                    ),
                )
                with self.assertRaisesRegex(ApprovalError, "approval_stale"):
                    in_memory.prepare(mismatch, expected_generation=0)
                with self.assertRaisesRegex(ApprovalError, "approval_stale"):
                    durable.prepare(mismatch, expected_generation=0)
                self.assertEqual(durable_before, durable.snapshot(review))

    def test_durable_check_snapshot_preserves_no_late_adoption_and_live_equality(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)
            authority.prepare(review, expected_generation=0)
            prepared = authority.snapshot(review)
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            with self.assertRaisesRegex(ApprovalError, "approval_required"):
                authority.check_snapshot(review, prepared, now_ms=1_999)

            approved = authority.snapshot(review)
            self.assertEqual(
                ("source.read",),
                authority.check_snapshot(review, approved, now_ms=1_999).approved_tool_ids,
            )
            with self.assertRaisesRegex(ApprovalError, "approval_expired"):
                authority.check_snapshot(review, approved, now_ms=2_000)
            alternate = _decision(review, approved_tool_ids=("world.validate",))
            stale = replace(
                approved,
                current_decision=alternate,
                decision_hash=alternate.content_hash,
            )
            with self.assertRaisesRegex(ApprovalError, "approval_stale"):
                authority.check_snapshot(review, stale, now_ms=1_999)
            authority.revoke(
                review.approval_id,
                expected_generation=1,
                expected_decision_hash=decision.content_hash,
            )
            with self.assertRaisesRegex(ApprovalError, "approval_revoked"):
                authority.check_snapshot(review, approved, now_ms=1_999)

            tamper_review = _review(
                approval_id="approval_snapshot_tamper",
                execution_id="execution_snapshot_tamper",
            )
            tamper_decision = _decision(tamper_review)
            authority.prepare(tamper_review, expected_generation=0)
            authority.decide(
                tamper_decision,
                expected_generation=0,
                expected_review_hash=tamper_review.content_hash,
            )
            tamper_snapshot = authority.snapshot(tamper_review)
            alternate_tamper = _decision(
                tamper_review,
                approved_tool_ids=("world.validate",),
            )
            with sqlite3.connect(store.database_path) as writer:
                writer.execute(
                    "UPDATE studio_authenticated_human_decisions SET "
                    "decision_hash = ?, decision_json = ? WHERE approval_id = ?",
                    (
                        alternate_tamper.content_hash,
                        encode_json(alternate_tamper.as_document()),
                        tamper_review.approval_id,
                    ),
                )
            with self.assertRaisesRegex(
                StudioError,
                "authenticated decision audit failed",
            ):
                authority.check_snapshot(
                    tamper_review,
                    tamper_snapshot,
                    now_ms=1_999,
                )

    def test_durable_check_snapshot_audits_before_no_late_adoption_result(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)
            authority.prepare(review, expected_generation=0)
            prepared = authority.snapshot(review)
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            alternate = _decision(review, approved_tool_ids=("world.validate",))
            with sqlite3.connect(store.database_path) as writer:
                writer.execute(
                    "UPDATE studio_authenticated_human_decisions SET "
                    "decision_hash = ?, decision_json = ? WHERE approval_id = ?",
                    (
                        alternate.content_hash,
                        encode_json(alternate.as_document()),
                        review.approval_id,
                    ),
                )

            with self.assertRaisesRegex(
                StudioError,
                "authenticated decision audit failed",
            ):
                authority.check_snapshot(review, prepared, now_ms=1_999)

    def test_rejects_non_explicit_or_invalid_passphrases_without_creating_credential(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StudioStore(Path(directory) / "studio")
            self.addCleanup(store.close)
            for passphrase in ("x" * 15, "x" * 1025):
                with self.subTest(passphrase_length=len(passphrase)):
                    with self.assertRaisesRegex(StudioError, "passphrase invalid"):
                        StudioAuthenticatedHumanDecisionAuthority.enroll(
                            store, passphrase=passphrase
                        )
            with self.assertRaisesRegex(StudioError, "credential not enrolled"):
                StudioAuthenticatedHumanDecisionAuthority.unlock(
                    store, passphrase=self._PASSPHRASE
                )
            spaced = " director passphrase with enough UTF-8 bytes "
            StudioAuthenticatedHumanDecisionAuthority.enroll(store, passphrase=spaced)
            StudioAuthenticatedHumanDecisionAuthority.unlock(store, passphrase=spaced)
            with self.assertRaisesRegex(StudioError, "authentication failed"):
                StudioAuthenticatedHumanDecisionAuthority.unlock(
                    store, passphrase=spaced.strip()
                )

    def test_persists_exact_harness_review_decision_and_one_use_expiry_cas(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)

            self.assertEqual(review, authority.prepare(review, expected_generation=0))
            self.assertEqual(review, authority.prepare(review, expected_generation=0))
            with self.assertRaisesRegex(ApprovalError, "approval_decision_invalid"):
                authority.decide(
                    _decision(review, reviewer_id="other_director"),
                    expected_generation=0,
                    expected_review_hash=review.content_hash,
                )
            self.assertEqual(
                decision,
                authority.decide(
                    decision,
                    expected_generation=0,
                    expected_review_hash=review.content_hash,
                ),
            )
            self.assertEqual(
                ("source.read",), authority.check(review, now_ms=1_999).approved_tool_ids
            )
            with self.assertRaisesRegex(ApprovalError, "approval_expired"):
                authority.check(review, now_ms=2_000)

            snapshot = authority.snapshot(review)
            self.assertEqual(("approved", 1, decision.content_hash), (
                snapshot.state, snapshot.generation, snapshot.decision_hash
            ))
            self.assertEqual(
                2,
                store.connection.execute(
                    "SELECT COUNT(*) FROM studio_authenticated_human_decision_events"
                ).fetchone()[0],
            )
            authority.revoke(
                review.approval_id,
                expected_generation=1,
                expected_decision_hash=decision.content_hash,
            )
            self.assertEqual(("revoked", 2), (
                authority.snapshot(review).state,
                authority.snapshot(review).generation,
            ))
            self.assertEqual(
                3,
                store.connection.execute(
                    "SELECT COUNT(*) FROM studio_authenticated_human_decision_events"
                ).fetchone()[0],
            )

    def test_fails_closed_for_concurrent_or_tampered_persistent_state_and_on_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            authority.prepare(review, expected_generation=0)
            decisions = (
                _decision(review),
                _decision(
                    review,
                    outcome="denied",
                    approved_tool_ids=(),
                    expires_at_ms=None,
                ),
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
                    outcomes.append("accepted")

            threads = [threading.Thread(target=decide, args=(value,)) for value in decisions]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=2)
            self.assertCountEqual(["accepted", "approval_stale"], outcomes)

            store.connection.execute(
                "UPDATE studio_authenticated_human_decision_events "
                "SET content_hash = ? WHERE event_id = 1",
                ("0" * 64,),
            )
            store.connection.commit()
            with self.assertRaisesRegex(StudioError, "authenticated decision audit failed"):
                StudioAuthenticatedHumanDecisionAuthority.unlock(
                    store, passphrase=self._PASSPHRASE
                )

            altered = replace(review, grant_hash="0" * 64)
            with self.assertRaisesRegex(ApprovalError, "approval_review_invalid"):
                authority.snapshot(altered)

    def test_unlock_rejects_event_reassigned_to_another_existing_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            first = _review()
            second = _review(
                approval_id="approval_execution_02",
                execution_id="execution_02",
            )
            authority.prepare(first, expected_generation=0)
            authority.prepare(second, expected_generation=0)
            store.connection.execute(
                "UPDATE studio_authenticated_human_decision_events "
                "SET approval_id = ? WHERE event_id = 1",
                (second.approval_id,),
            )
            store.connection.commit()

            with self.assertRaisesRegex(
                StudioError, "authenticated decision audit failed"
            ):
                StudioAuthenticatedHumanDecisionAuthority.unlock(
                    store, passphrase=self._PASSPHRASE
                )

    def test_complete_audit_rejects_hidden_foreign_credential_event_before_or_after_tail(
        self,
    ) -> None:
        observed: dict[str, str] = {}
        for placement in ("before", "after"):
            with tempfile.TemporaryDirectory() as directory:
                data_dir = Path(directory) / "studio"
                store, authority = self._enrolled(directory)
                try:
                    review = _review()
                    decision = _decision(review)
                    authority.prepare(review, expected_generation=0)
                    authority.decide(
                        decision,
                        expected_generation=0,
                        expected_review_hash=review.content_hash,
                    )
                    live = StudioAuthenticatedHumanDecisionAuthority.unlock(
                        store, passphrase=self._PASSPHRASE
                    )
                    self.assertEqual(
                        0,
                        _insert_authenticated_foreign_credential_event(
                            store,
                            authority,
                            placement=placement,
                        ),
                    )
                    for operation, invoke in (
                        ("snapshot", lambda: live.snapshot(review)),
                        ("check", lambda: live.check(review, now_ms=1_999)),
                    ):
                        try:
                            invoke()
                        except StudioError as exc:
                            observed[f"{placement}:live_{operation}"] = exc.code
                        else:
                            observed[f"{placement}:live_{operation}"] = "accepted"
                finally:
                    store.close()

                with StudioStore(data_dir) as reopened:
                    try:
                        StudioAuthenticatedHumanDecisionAuthority.unlock(
                            reopened, passphrase=self._PASSPHRASE
                        )
                    except StudioError as exc:
                        observed[f"{placement}:reopen_unlock"] = exc.code
                    else:
                        observed[f"{placement}:reopen_unlock"] = "accepted"

        self.assertEqual(
            {
                "before:live_snapshot": "invalid_state",
                "before:live_check": "invalid_state",
                "before:reopen_unlock": "invalid_state",
                "after:live_snapshot": "invalid_state",
                "after:live_check": "invalid_state",
                "after:reopen_unlock": "invalid_state",
            },
            observed,
        )

    def test_event_audit_rejects_authenticated_unknown_top_level_field(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            store, authority = self._enrolled(directory)
            review = _review()
            decision = _decision(review)
            authority.prepare(review, expected_generation=0)
            live = StudioAuthenticatedHumanDecisionAuthority.unlock(
                store, passphrase=self._PASSPHRASE
            )
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            row = store.connection.execute(
                "SELECT content_json FROM studio_authenticated_human_decision_events "
                "WHERE event_type = 'decided'"
            ).fetchone()
            document = json.loads(row["content_json"])
            document["unexpected"] = "authenticated-but-undefined"
            content_json = encode_json(document)
            content_hash = hashlib.sha256(content_json.encode("utf-8")).hexdigest()
            with sqlite3.connect(store.database_path) as writer:
                writer.execute(
                    "UPDATE studio_authenticated_human_decision_events SET "
                    "content_json = ?, content_hash = ?, mac = ? "
                    "WHERE event_type = 'decided'",
                    (
                        content_json,
                        content_hash,
                        _event_mac(authority._event_key, document),
                    ),
                )
                writer.execute(
                    "UPDATE studio_authenticated_human_decisions SET "
                    "last_event_hash = ? WHERE approval_id = ?",
                    (content_hash, review.approval_id),
                )

            observed: dict[str, str] = {}
            for operation, invoke in (
                ("live_snapshot", lambda: live.snapshot(review)),
                ("live_check", lambda: live.check(review, now_ms=1_999)),
            ):
                try:
                    invoke()
                except StudioError as exc:
                    observed[operation] = exc.code
                else:
                    observed[operation] = "accepted"
            store.close()
            with StudioStore(data_dir) as reopened:
                try:
                    StudioAuthenticatedHumanDecisionAuthority.unlock(
                        reopened, passphrase=self._PASSPHRASE
                    )
                except StudioError as exc:
                    observed["reopen_unlock"] = exc.code
                else:
                    observed["reopen_unlock"] = "accepted"

            self.assertEqual(
                {
                    "live_snapshot": "invalid_state",
                    "live_check": "invalid_state",
                    "reopen_unlock": "invalid_state",
                },
                observed,
            )

    def test_authority_entrypoints_reverify_private_schema_inside_transactions(
        self,
    ) -> None:
        expected = (
            "invalid_state",
            "Authenticated decision database schema is invalid",
        )
        observed: dict[str, tuple[str, str] | int] = {}

        with tempfile.TemporaryDirectory() as directory:
            store = StudioStore(Path(directory) / "studio")
            try:
                store._authenticated_human_decision_connection()
                _add_private_schema_view(store)
                try:
                    StudioAuthenticatedHumanDecisionAuthority.enroll(
                        store, passphrase=self._PASSPHRASE
                    )
                except StudioError as exc:
                    observed["enroll"] = (exc.code, exc.message)
                else:
                    observed["enroll"] = ("accepted", "")
                observed["enroll_rows"] = store.connection.execute(
                    "SELECT COUNT(*) FROM studio_authenticated_human_credentials"
                ).fetchone()[0]
            finally:
                store.close()

        with tempfile.TemporaryDirectory() as directory:
            store, _authority = self._enrolled(directory)
            try:
                _add_private_schema_view(store)
                try:
                    StudioAuthenticatedHumanDecisionAuthority.unlock(
                        store, passphrase=self._PASSPHRASE
                    )
                except StudioError as exc:
                    observed["unlock"] = (exc.code, exc.message)
                else:
                    observed["unlock"] = ("accepted", "")
            finally:
                store.close()

        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            try:
                review = _review()
                decision = _decision(review)
                authority.prepare(review, expected_generation=0)
                authority.decide(
                    decision,
                    expected_generation=0,
                    expected_review_hash=review.content_hash,
                )
                _add_private_schema_view(store)
                next_review = _review(
                    approval_id="approval_execution_schema_drift",
                    execution_id="execution_schema_drift",
                )
                for operation, invoke in (
                    ("snapshot", lambda: authority.snapshot(review)),
                    ("check", lambda: authority.check(review, now_ms=1_999)),
                    (
                        "write",
                        lambda: authority.prepare(next_review, expected_generation=0),
                    ),
                ):
                    try:
                        invoke()
                    except StudioError as exc:
                        observed[operation] = (exc.code, exc.message)
                    else:
                        observed[operation] = ("accepted", "")
            finally:
                store.close()

        self.assertEqual(
            {
                "enroll": expected,
                "enroll_rows": 0,
                "unlock": expected,
                "snapshot": expected,
                "check": expected,
                "write": expected,
            },
            observed,
        )

    def test_live_authority_rejects_disabled_constraint_pragmas(self) -> None:
        expected = (
            "invalid_state",
            "Authenticated decision database schema is invalid",
        )
        observed: dict[str, tuple[str, str] | int] = {}
        for pragma, value, altered in (
            ("foreign_keys", "OFF", 0),
            ("ignore_check_constraints", "ON", 1),
        ):
            with tempfile.TemporaryDirectory() as directory:
                store, authority = self._enrolled(directory)
                try:
                    review = _review()
                    decision = _decision(review)
                    authority.prepare(review, expected_generation=0)
                    authority.decide(
                        decision,
                        expected_generation=0,
                        expected_review_hash=review.content_hash,
                    )
                    authority._connection.execute(f"PRAGMA {pragma} = {value}")
                    observed[f"{pragma}:value"] = authority._connection.execute(
                        f"PRAGMA {pragma}"
                    ).fetchone()[0]
                    next_review = _review(
                        approval_id=f"approval_execution_{pragma}",
                        execution_id=f"execution_{pragma}",
                    )
                    for operation, invoke in (
                        ("snapshot", lambda: authority.snapshot(review)),
                        ("check", lambda: authority.check(review, now_ms=1_999)),
                        (
                            "write",
                            lambda: authority.prepare(next_review, expected_generation=0),
                        ),
                    ):
                        try:
                            invoke()
                        except StudioError as exc:
                            observed[f"{pragma}:{operation}"] = (exc.code, exc.message)
                        else:
                            observed[f"{pragma}:{operation}"] = ("accepted", "")
                finally:
                    store.close()

            self.assertEqual(altered, observed[f"{pragma}:value"])
            for operation in ("snapshot", "check", "write"):
                self.assertEqual(expected, observed[f"{pragma}:{operation}"])

    def test_unlock_rejects_decision_not_bound_to_exact_prepared_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            prepared = _review()
            authority.prepare(prepared, expected_generation=0)
            never_prepared = _review(grant_hash="9" * 64)
            forged_decision = _decision(never_prepared)
            _forge_authenticated_transition(
                store,
                authority,
                event_type="decided",
                review=never_prepared,
                decision=forged_decision,
                state="approved",
                generation=1,
            )

            with self.assertRaisesRegex(
                StudioError, "authenticated decision audit failed"
            ):
                StudioAuthenticatedHumanDecisionAuthority.unlock(
                    store, passphrase=self._PASSPHRASE
                )

    def test_unlock_rejects_revocation_not_bound_to_exact_generation_one_decision(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            approved = _decision(review)
            authority.prepare(review, expected_generation=0)
            authority.decide(
                approved,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            never_decided = _decision(review, approved_tool_ids=("world.validate",))
            _forge_authenticated_transition(
                store,
                authority,
                event_type="revoked",
                review=review,
                decision=never_decided,
                state="revoked",
                generation=2,
            )

            with self.assertRaisesRegex(
                StudioError, "authenticated decision audit failed"
            ):
                StudioAuthenticatedHumanDecisionAuthority.unlock(
                    store, passphrase=self._PASSPHRASE
                )

    def test_unrelated_store_commit_cannot_split_authority_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            projection_inserted = threading.Event()
            continue_prepare = threading.Event()
            original_insert = authority._insert_projection

            def paused_insert(*args: object, **kwargs: object) -> bool:
                inserted = original_insert(*args, **kwargs)
                projection_inserted.set()
                if not continue_prepare.wait(timeout=2):
                    raise RuntimeError("prepare barrier timed out")
                return inserted

            def failed_append(*args: object, **kwargs: object) -> None:
                raise sqlite3.OperationalError("injected event append failure")

            authority._insert_projection = paused_insert  # type: ignore[method-assign]
            authority._append = failed_append  # type: ignore[method-assign]
            outcome: list[object] = []

            def prepare() -> None:
                try:
                    authority.prepare(review, expected_generation=0)
                except Exception as exc:
                    outcome.append(exc)
                else:
                    outcome.append("prepared")

            thread = threading.Thread(target=prepare)
            thread.start()
            self.assertTrue(projection_inserted.wait(timeout=2))
            store.connection.commit()
            continue_prepare.set()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(1, len(outcome))
            self.assertIsInstance(outcome[0], StudioError)
            self.assertEqual(
                0,
                store.connection.execute(
                    "SELECT COUNT(*) FROM studio_authenticated_human_decisions"
                ).fetchone()[0],
            )
            self.assertEqual(
                0,
                store.connection.execute(
                    "SELECT COUNT(*) FROM studio_authenticated_human_decision_events"
                ).fetchone()[0],
            )

    def test_unlock_audit_reads_events_and_projection_from_one_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            primary = StudioStore(data_dir)
            secondary = None
            try:
                first = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    primary, passphrase=self._PASSPHRASE
                )
                review = _review()
                decision = _decision(review)
                first.prepare(review, expected_generation=0)
                secondary = StudioStore(data_dir, mode="secondary")
                projection_read = threading.Event()
                continue_audit = threading.Event()

                def authorizer(
                    action: int,
                    first_argument: str | None,
                    _second_argument: str | None,
                    _database: str | None,
                    _trigger: str | None,
                ) -> int:
                    if (
                        action == sqlite3.SQLITE_READ
                        and first_argument == "studio_authenticated_human_decisions"
                        and not projection_read.is_set()
                    ):
                        projection_read.set()
                        if not continue_audit.wait(timeout=2):
                            return sqlite3.SQLITE_DENY
                    return sqlite3.SQLITE_OK

                original_connect = sqlite3.connect

                def coordinated_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
                    connection = original_connect(*args, **kwargs)
                    connection.set_authorizer(authorizer)
                    return connection

                secondary.connection.set_authorizer(authorizer)
                outcome: list[tuple[str, object]] = []

                def unlock() -> None:
                    try:
                        authority = StudioAuthenticatedHumanDecisionAuthority.unlock(
                            secondary, passphrase=self._PASSPHRASE
                        )
                        outcome.append(("unlocked", authority.snapshot(review).state))
                    except Exception as exc:
                        outcome.append(("failed", exc))

                with mock.patch(
                    "worldforge.studio.authenticated_human_decisions.sqlite3.connect",
                    side_effect=coordinated_connect,
                ):
                    thread = threading.Thread(target=unlock)
                    thread.start()
                    self.assertTrue(projection_read.wait(timeout=2))
                    first.decide(
                        decision,
                        expected_generation=0,
                        expected_review_hash=review.content_hash,
                    )
                    continue_audit.set()
                    thread.join(timeout=3)
                self.assertFalse(thread.is_alive())
                self.assertEqual([("unlocked", "approved")], outcome)
            finally:
                if secondary is not None:
                    secondary.connection.set_authorizer(None)
                    secondary.close()
                primary.close()

    def test_live_snapshot_rejects_approved_projection_without_authenticated_event(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)
            authority.prepare(review, expected_generation=0)
            unlocked = StudioAuthenticatedHumanDecisionAuthority.unlock(
                store, passphrase=self._PASSPHRASE
            )
            _forge_approved_projection_without_event(store, review, decision)

            with self.assertRaisesRegex(
                StudioError, "authenticated decision audit failed"
            ):
                unlocked.snapshot(review)

    def test_live_check_rejects_approved_projection_without_authenticated_event(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)
            authority.prepare(review, expected_generation=0)
            unlocked = StudioAuthenticatedHumanDecisionAuthority.unlock(
                store, passphrase=self._PASSPHRASE
            )
            _forge_approved_projection_without_event(store, review, decision)

            with self.assertRaisesRegex(
                StudioError, "authenticated decision audit failed"
            ):
                unlocked.check(review, now_ms=1_999)

    def test_live_check_rejects_projection_rollback_while_revocation_event_remains(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)
            authority.prepare(review, expected_generation=0)
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            approved = store.connection.execute(
                "SELECT review_hash, review_json, decision_hash, decision_json, state, "
                "generation, last_event_hash, updated_at FROM "
                "studio_authenticated_human_decisions WHERE approval_id = ?",
                (review.approval_id,),
            ).fetchone()
            authority.revoke(
                review.approval_id,
                expected_generation=1,
                expected_decision_hash=decision.content_hash,
            )
            unlocked = StudioAuthenticatedHumanDecisionAuthority.unlock(
                store, passphrase=self._PASSPHRASE
            )
            with sqlite3.connect(store.database_path) as writer:
                writer.execute(
                    "UPDATE studio_authenticated_human_decisions SET "
                    "review_hash = ?, review_json = ?, decision_hash = ?, decision_json = ?, "
                    "state = ?, generation = ?, last_event_hash = ?, updated_at = ? "
                    "WHERE approval_id = ?",
                    (*tuple(approved), review.approval_id),
                )

            with self.assertRaisesRegex(
                StudioError, "authenticated decision audit failed"
            ):
                unlocked.check(review, now_ms=1_999)

    def test_live_anchor_rejects_coherent_revocation_suffix_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)
            authority.prepare(review, expected_generation=0)
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            unlocked = StudioAuthenticatedHumanDecisionAuthority.unlock(
                store, passphrase=self._PASSPHRASE
            )
            approved = store.connection.execute(
                "SELECT review_hash, review_json, decision_hash, decision_json, state, "
                "generation, last_event_hash, updated_at FROM "
                "studio_authenticated_human_decisions WHERE approval_id = ?",
                (review.approval_id,),
            ).fetchone()
            unlocked.revoke(
                review.approval_id,
                expected_generation=1,
                expected_decision_hash=decision.content_hash,
            )
            with sqlite3.connect(store.database_path) as writer:
                writer.execute(
                    "DELETE FROM studio_authenticated_human_decision_events "
                    "WHERE event_type = 'revoked'"
                )
                writer.execute(
                    "UPDATE studio_authenticated_human_decisions SET "
                    "review_hash = ?, review_json = ?, decision_hash = ?, decision_json = ?, "
                    "state = ?, generation = ?, last_event_hash = ?, updated_at = ? "
                    "WHERE approval_id = ?",
                    (*tuple(approved), review.approval_id),
                )

            with self.assertRaisesRegex(
                StudioError, "authenticated decision audit failed"
            ):
                unlocked.check(review, now_ms=1_999)

    def test_live_check_rejects_approved_event_tail_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)
            authority.prepare(review, expected_generation=0)
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            unlocked = StudioAuthenticatedHumanDecisionAuthority.unlock(
                store, passphrase=self._PASSPHRASE
            )
            with sqlite3.connect(store.database_path) as writer:
                writer.execute(
                    "DELETE FROM studio_authenticated_human_decision_events "
                    "WHERE event_type = 'decided'"
                )

            with self.assertRaisesRegex(
                StudioError, "authenticated decision audit failed"
            ):
                unlocked.check(review, now_ms=1_999)

    def test_live_snapshot_rejects_middle_event_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)
            authority.prepare(review, expected_generation=0)
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            authority.revoke(
                review.approval_id,
                expected_generation=1,
                expected_decision_hash=decision.content_hash,
            )
            unlocked = StudioAuthenticatedHumanDecisionAuthority.unlock(
                store, passphrase=self._PASSPHRASE
            )
            with sqlite3.connect(store.database_path) as writer:
                writer.execute(
                    "DELETE FROM studio_authenticated_human_decision_events "
                    "WHERE event_type = 'decided'"
                )

            with self.assertRaisesRegex(
                StudioError, "authenticated decision audit failed"
            ):
                unlocked.snapshot(review)

    def test_live_snapshot_rejects_event_row_reordering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)
            authority.prepare(review, expected_generation=0)
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            unlocked = StudioAuthenticatedHumanDecisionAuthority.unlock(
                store, passphrase=self._PASSPHRASE
            )
            with sqlite3.connect(store.database_path) as writer:
                writer.execute(
                    "UPDATE studio_authenticated_human_decision_events "
                    "SET event_id = -1 WHERE event_id = 1"
                )
                writer.execute(
                    "UPDATE studio_authenticated_human_decision_events "
                    "SET event_id = 1 WHERE event_id = 2"
                )
                writer.execute(
                    "UPDATE studio_authenticated_human_decision_events "
                    "SET event_id = 2 WHERE event_id = -1"
                )

            with self.assertRaisesRegex(
                StudioError, "authenticated decision audit failed"
            ):
                unlocked.snapshot(review)

    def test_live_snapshot_rejects_authenticated_duplicate_transition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)
            authority.prepare(review, expected_generation=0)
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            unlocked = StudioAuthenticatedHumanDecisionAuthority.unlock(
                store, passphrase=self._PASSPHRASE
            )
            _append_authenticated_duplicate_decision_event(
                store, authority, review, decision
            )

            with self.assertRaisesRegex(
                StudioError, "authenticated decision audit failed"
            ):
                unlocked.snapshot(review)

    def test_transition_audits_forged_projection_before_mutating(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)
            authority.prepare(review, expected_generation=0)
            unlocked = StudioAuthenticatedHumanDecisionAuthority.unlock(
                store, passphrase=self._PASSPHRASE
            )
            _forge_approved_projection_without_event(store, review, decision)

            with self.assertRaisesRegex(
                StudioError, "authenticated decision audit failed"
            ):
                unlocked.revoke(
                    review.approval_id,
                    expected_generation=1,
                    expected_decision_hash=decision.content_hash,
                )
            self.assertEqual(
                1,
                store.connection.execute(
                    "SELECT COUNT(*) FROM studio_authenticated_human_decision_events"
                ).fetchone()[0],
            )

    def test_live_authority_and_reopen_reject_tampered_credential_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            store, authority = self._enrolled(directory)
            review = _review()
            authority.prepare(review, expected_generation=0)
            unlocked = StudioAuthenticatedHumanDecisionAuthority.unlock(
                store, passphrase=self._PASSPHRASE
            )
            try:
                with sqlite3.connect(store.database_path) as writer:
                    writer.execute(
                        "UPDATE studio_authenticated_human_credentials SET verifier = ?",
                        (b"x" * 32,),
                    )
                with self.assertRaisesRegex(
                    StudioError, "authenticated decision audit failed"
                ):
                    unlocked.snapshot(review)
            finally:
                store.close()

            with StudioStore(data_dir) as reopened:
                with self.assertRaisesRegex(StudioError, "authentication failed"):
                    StudioAuthenticatedHumanDecisionAuthority.unlock(
                        reopened, passphrase=self._PASSPHRASE
                    )

    def test_dedicated_authority_connection_has_exact_config_and_closes_with_store(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            connection = authority._connection
            self.assertIsNot(store.connection, connection)
            self.assertIs(sqlite3.Row, connection.row_factory)
            self.assertEqual(1, connection.execute("PRAGMA foreign_keys").fetchone()[0])
            self.assertEqual(5_000, connection.execute("PRAGMA busy_timeout").fetchone()[0])
            self.assertEqual("wal", connection.execute("PRAGMA journal_mode").fetchone()[0])
            self.assertEqual(2, connection.execute("PRAGMA synchronous").fetchone()[0])
            store.close()
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")

    def test_reopen_unlock_audits_every_valid_projection_state(self) -> None:
        cases = (
            ("prepared", 0, None, False),
            ("approved", 1, _decision, False),
            (
                "denied",
                1,
                lambda review: _decision(
                    review,
                    outcome="denied",
                    approved_tool_ids=(),
                    expires_at_ms=None,
                ),
                False,
            ),
            ("revoked", 2, _decision, True),
        )
        for expected_state, expected_generation, decision_factory, revoke in cases:
            with self.subTest(state=expected_state), tempfile.TemporaryDirectory() as directory:
                data_dir = Path(directory) / "studio"
                with StudioStore(data_dir) as store:
                    authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                        store, passphrase=self._PASSPHRASE
                    )
                    review = _review()
                    authority.prepare(review, expected_generation=0)
                    decision = None
                    if decision_factory is not None:
                        decision = decision_factory(review)
                        authority.decide(
                            decision,
                            expected_generation=0,
                            expected_review_hash=review.content_hash,
                        )
                    if revoke:
                        assert decision is not None
                        authority.revoke(
                            review.approval_id,
                            expected_generation=1,
                            expected_decision_hash=decision.content_hash,
                        )

                with StudioStore(data_dir) as reopened:
                    unlocked = StudioAuthenticatedHumanDecisionAuthority.unlock(
                        reopened, passphrase=self._PASSPHRASE
                    )
                    snapshot = unlocked.snapshot(review)
                    self.assertEqual(expected_state, snapshot.state)
                    self.assertEqual(expected_generation, snapshot.generation)
                    self.assertEqual(
                        None if decision is None else decision.content_hash,
                        snapshot.decision_hash,
                    )

    def test_independent_store_connections_allow_only_one_generation_zero_decision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            primary = StudioStore(data_dir)
            secondary = None
            try:
                first = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    primary, passphrase=self._PASSPHRASE
                )
                secondary = StudioStore(data_dir, mode="secondary")
                second = StudioAuthenticatedHumanDecisionAuthority.unlock(
                    secondary, passphrase=self._PASSPHRASE
                )
                review = _review()
                first.prepare(review, expected_generation=0)
                decisions = (
                    _decision(review),
                    _decision(
                        review,
                        outcome="denied",
                        approved_tool_ids=(),
                        expires_at_ms=None,
                    ),
                )
                barrier = threading.Barrier(3)
                outcomes: list[tuple[str, str]] = []

                def decide(
                    authority: StudioAuthenticatedHumanDecisionAuthority,
                    decision: ExecutionApprovalDecision,
                ) -> None:
                    barrier.wait(timeout=2)
                    try:
                        authority.decide(
                            decision,
                            expected_generation=0,
                            expected_review_hash=review.content_hash,
                        )
                    except ApprovalError as exc:
                        outcomes.append(("rejected", exc.reason_code))
                    except Exception as exc:
                        outcomes.append(("unexpected", type(exc).__name__))
                    else:
                        outcomes.append(("accepted", decision.content_hash))

                threads = [
                    threading.Thread(target=decide, args=(authority, decision))
                    for authority, decision in zip((first, second), decisions, strict=True)
                ]
                for thread in threads:
                    thread.start()
                barrier.wait(timeout=2)
                for thread in threads:
                    thread.join(timeout=3)
                self.assertFalse(any(thread.is_alive() for thread in threads))
                self.assertEqual(1, sum(kind == "accepted" for kind, _value in outcomes))
                self.assertEqual([("rejected", "approval_stale")], [
                    outcome for outcome in outcomes if outcome[0] != "accepted"
                ])
                self.assertEqual(
                    2,
                    primary.connection.execute(
                        "SELECT COUNT(*) FROM studio_authenticated_human_decision_events"
                    ).fetchone()[0],
                )
                projection = primary.connection.execute(
                    "SELECT state, generation, decision_hash "
                    "FROM studio_authenticated_human_decisions WHERE approval_id = ?",
                    (review.approval_id,),
                ).fetchone()
                self.assertEqual(1, projection["generation"])
                self.assertIn(projection["state"], {"approved", "denied"})
                self.assertIn(
                    projection["decision_hash"],
                    {decision.content_hash for decision in decisions},
                )
            finally:
                if secondary is not None:
                    secondary.close()
                primary.close()

    def test_self_hashed_decision_cannot_approve_tool_outside_prepared_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            authority.prepare(review, expected_generation=0)
            decision = replace(
                _decision(review),
                approved_tool_ids=("source.read", "world.delete"),
                content_hash="0" * 64,
            )
            document = decision.as_document()
            del document["content_hash"]
            decision = replace(
                decision,
                content_hash=hashlib.sha256(
                    json.dumps(
                        document,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode("utf-8")
                ).hexdigest(),
            )

            with self.assertRaisesRegex(ApprovalError, "approval_invalid"):
                authority.decide(
                    decision,
                    expected_generation=0,
                    expected_review_hash=review.content_hash,
                )
            projection = authority.snapshot(review)
            self.assertEqual(("prepared", 0, None), (
                projection.state,
                projection.generation,
                projection.decision_hash,
            ))
            self.assertEqual(
                1,
                store.connection.execute(
                    "SELECT COUNT(*) FROM studio_authenticated_human_decision_events"
                ).fetchone()[0],
            )

    def test_revoke_between_snapshot_and_check_cannot_authorize_stale_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            review = _review()
            decision = _decision(review)
            authority.prepare(review, expected_generation=0)
            authority.decide(
                decision,
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            original_snapshot = authority.snapshot
            snapshot_taken = threading.Event()
            continue_check = threading.Event()

            def paused_snapshot(value: object) -> object:
                snapshot = original_snapshot(value)
                snapshot_taken.set()
                if not continue_check.wait(timeout=2):
                    raise RuntimeError("check barrier timed out")
                return snapshot

            authority.snapshot = paused_snapshot  # type: ignore[method-assign]
            outcome: list[tuple[str, object]] = []

            def check() -> None:
                try:
                    result = authority.check(review, now_ms=1_999)
                except ApprovalError as exc:
                    outcome.append(("rejected", exc.reason_code))
                else:
                    outcome.append(("authorized", result.approved_tool_ids))

            thread = threading.Thread(target=check)
            thread.start()
            self.assertTrue(snapshot_taken.wait(timeout=2))
            authority.revoke(
                review.approval_id,
                expected_generation=1,
                expected_decision_hash=decision.content_hash,
            )
            continue_check.set()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual([("rejected", "approval_revoked")], outcome)

    def test_closed_store_is_terminal_for_existing_authority_and_unlock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            review = _review()
            private_connection = authority._connection
            store.close()
            store.close()

            operations = (
                ("snapshot", lambda: authority.snapshot(review)),
                (
                    "prepare",
                    lambda: authority.prepare(review, expected_generation=0),
                ),
                (
                    "unlock",
                    lambda: StudioAuthenticatedHumanDecisionAuthority.unlock(
                        store, passphrase=self._PASSPHRASE
                    ),
                ),
            )
            for name, operation in operations:
                with self.subTest(operation=name):
                    with self.assertRaisesRegex(StudioError, "closed"):
                        operation()
                    self.assertIsNone(
                        store._authenticated_human_decision_connection_instance
                    )
            with self.assertRaises(sqlite3.ProgrammingError):
                private_connection.execute("SELECT 1")

    def test_context_closed_store_cannot_enroll_or_create_private_connection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store: StudioStore
            with StudioStore(Path(directory) / "studio") as store:
                pass

            with mock.patch(
                "worldforge.studio.storage.sqlite3.connect", wraps=sqlite3.connect
            ) as connect:
                with self.assertRaisesRegex(StudioError, "closed"):
                    StudioAuthenticatedHumanDecisionAuthority.enroll(
                        store, passphrase=self._PASSPHRASE
                    )
            self.assertEqual(0, connect.call_count)
            self.assertIsNone(store._authenticated_human_decision_connection_instance)

    def test_read_commit_error_retains_successfully_audited_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            primary = StudioStore(data_dir)
            secondary = None
            try:
                first = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    primary, passphrase=self._PASSPHRASE
                )
                secondary = StudioStore(data_dir, mode="secondary")
                second = StudioAuthenticatedHumanDecisionAuthority.unlock(
                    secondary, passphrase=self._PASSPHRASE
                )
                review = _review()
                second.prepare(review, expected_generation=0)
                observed = primary.connection.execute(
                    "SELECT event_id, content_hash FROM "
                    "studio_authenticated_human_decision_events"
                ).fetchone()
                raw_connection = first._connection
                fault_connection = _CommitFaultConnection(
                    raw_connection, effect_then_raise=True
                )
                first._connection = fault_connection
                primary._authenticated_human_decision_connection_instance = fault_connection
                try:
                    with self.assertRaisesRegex(StudioError, "transaction failed"):
                        first.snapshot(review)
                finally:
                    first._connection = raw_connection
                    primary._authenticated_human_decision_connection_instance = raw_connection

                self.assertEqual(
                    (observed["event_id"], observed["content_hash"]),
                    (first._anchor.event_id, first._anchor.content_hash),
                )
                with sqlite3.connect(primary.database_path) as writer:
                    writer.execute(
                        "DELETE FROM studio_authenticated_human_decision_events"
                    )
                    writer.execute("DELETE FROM studio_authenticated_human_decisions")
                with self.assertRaisesRegex(
                    StudioError, "authenticated decision audit failed"
                ):
                    first.snapshot(review)
            finally:
                if secondary is not None:
                    secondary.close()
                primary.close()

    def test_write_commit_error_reconciles_exact_entry_or_final_head(self) -> None:
        for effect_then_raise, expected_event_count in ((False, 1), (True, 2)):
            with (
                self.subTest(effect_then_raise=effect_then_raise),
                tempfile.TemporaryDirectory() as directory,
            ):
                data_dir = Path(directory) / "studio"
                primary = StudioStore(data_dir)
                secondary = None
                try:
                    first = StudioAuthenticatedHumanDecisionAuthority.enroll(
                        primary, passphrase=self._PASSPHRASE
                    )
                    secondary = StudioStore(data_dir, mode="secondary")
                    second = StudioAuthenticatedHumanDecisionAuthority.unlock(
                        secondary, passphrase=self._PASSPHRASE
                    )
                    entry_review = _review()
                    tentative_review = _review(
                        approval_id="approval_execution_02",
                        execution_id="execution_02",
                    )
                    second.prepare(entry_review, expected_generation=0)
                    raw_connection = first._connection
                    fault_connection = _CommitFaultConnection(
                        raw_connection, effect_then_raise=effect_then_raise
                    )
                    first._connection = fault_connection
                    primary._authenticated_human_decision_connection_instance = (
                        fault_connection
                    )
                    try:
                        with self.assertRaisesRegex(
                            StudioError, "transaction failed"
                        ):
                            first.prepare(tentative_review, expected_generation=0)
                    finally:
                        first._connection = raw_connection
                        primary._authenticated_human_decision_connection_instance = (
                            raw_connection
                        )

                    events = primary.connection.execute(
                        "SELECT event_id, content_hash FROM "
                        "studio_authenticated_human_decision_events ORDER BY event_id"
                    ).fetchall()
                    self.assertEqual(expected_event_count, len(events))
                    self.assertEqual(
                        (events[-1]["event_id"], events[-1]["content_hash"]),
                        (first._anchor.event_id, first._anchor.content_hash),
                    )
                    first.prepare(tentative_review, expected_generation=0)
                    self.assertEqual(
                        2,
                        primary.connection.execute(
                            "SELECT COUNT(*) FROM "
                            "studio_authenticated_human_decision_events"
                        ).fetchone()[0],
                    )
                    with sqlite3.connect(primary.database_path) as writer:
                        writer.execute(
                            "DELETE FROM studio_authenticated_human_decision_events"
                        )
                        writer.execute("DELETE FROM studio_authenticated_human_decisions")
                    with self.assertRaisesRegex(
                        StudioError, "authenticated decision audit failed"
                    ):
                        first.snapshot(entry_review)
                finally:
                    if secondary is not None:
                        secondary.close()
                    primary.close()

    def test_failed_write_commit_cleanup_poisons_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            raw_connection = authority._connection
            fault_connection = _CommitFaultConnection(
                raw_connection,
                effect_then_raise=False,
                rollback_then_raise=True,
            )
            authority._connection = fault_connection
            store._authenticated_human_decision_connection_instance = fault_connection
            try:
                with self.assertRaisesRegex(StudioError, "transaction failed"):
                    authority.prepare(_review(), expected_generation=0)
            finally:
                authority._connection = raw_connection
                store._authenticated_human_decision_connection_instance = raw_connection
                if raw_connection.in_transaction:
                    raw_connection.rollback()

            with self.assertRaisesRegex(StudioError, "unavailable"):
                authority.snapshot(_review())
            self.assertEqual(
                0,
                store.connection.execute(
                    "SELECT COUNT(*) FROM studio_authenticated_human_decision_events"
                ).fetchone()[0],
            )

    def test_read_body_error_with_uncertain_rollback_retains_head_and_poisons(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            primary = StudioStore(data_dir)
            secondary = None
            try:
                first = StudioAuthenticatedHumanDecisionAuthority.enroll(
                    primary, passphrase=self._PASSPHRASE
                )
                secondary = StudioStore(data_dir, mode="secondary")
                second = StudioAuthenticatedHumanDecisionAuthority.unlock(
                    secondary, passphrase=self._PASSPHRASE
                )
                review = _review()
                second.prepare(review, expected_generation=0)
                observed = primary.connection.execute(
                    "SELECT event_id, content_hash FROM "
                    "studio_authenticated_human_decision_events"
                ).fetchone()
                raw_connection = first._connection
                fault_connection = _RollbackFaultConnection(
                    raw_connection, effect_then_raise=True
                )
                first._connection = fault_connection
                primary._authenticated_human_decision_connection_instance = fault_connection
                try:
                    with (
                        mock.patch.object(
                            first,
                            "_snapshot_in_transaction",
                            side_effect=ApprovalError("approval_stale"),
                        ),
                        self.assertRaisesRegex(StudioError, "transaction failed"),
                    ):
                        first.snapshot(review)
                finally:
                    first._connection = raw_connection
                    primary._authenticated_human_decision_connection_instance = raw_connection

                self.assertEqual(
                    (observed["event_id"], observed["content_hash"]),
                    (first._anchor.event_id, first._anchor.content_hash),
                )
                with sqlite3.connect(primary.database_path) as writer:
                    writer.execute(
                        "DELETE FROM studio_authenticated_human_decision_events"
                    )
                    writer.execute("DELETE FROM studio_authenticated_human_decisions")
                with self.assertRaisesRegex(StudioError, "unavailable"):
                    first.snapshot(review)
            finally:
                if secondary is not None:
                    secondary.close()
                primary.close()

    def test_write_body_error_with_uncertain_rollback_retains_head_and_poisons(self) -> None:
        for effect_then_raise in (False, True):
            with (
                self.subTest(effect_then_raise=effect_then_raise),
                tempfile.TemporaryDirectory() as directory,
            ):
                data_dir = Path(directory) / "studio"
                primary = StudioStore(data_dir)
                secondary = None
                try:
                    first = StudioAuthenticatedHumanDecisionAuthority.enroll(
                        primary, passphrase=self._PASSPHRASE
                    )
                    secondary = StudioStore(data_dir, mode="secondary")
                    second = StudioAuthenticatedHumanDecisionAuthority.unlock(
                        secondary, passphrase=self._PASSPHRASE
                    )
                    review = _review()
                    second.prepare(review, expected_generation=0)
                    observed = primary.connection.execute(
                        "SELECT event_id, content_hash FROM "
                        "studio_authenticated_human_decision_events"
                    ).fetchone()
                    raw_connection = first._connection
                    fault_connection = _RollbackFaultConnection(
                        raw_connection, effect_then_raise=effect_then_raise
                    )
                    first._connection = fault_connection
                    primary._authenticated_human_decision_connection_instance = (
                        fault_connection
                    )
                    try:
                        with self.assertRaisesRegex(
                            StudioError, "transaction failed"
                        ):
                            first.prepare(
                                _review(runtime_revision=2),
                                expected_generation=0,
                            )
                    finally:
                        first._connection = raw_connection
                        primary._authenticated_human_decision_connection_instance = (
                            raw_connection
                        )
                        if raw_connection.in_transaction:
                            raw_connection.rollback()

                    self.assertEqual(
                        (observed["event_id"], observed["content_hash"]),
                        (first._anchor.event_id, first._anchor.content_hash),
                    )
                    with sqlite3.connect(primary.database_path) as writer:
                        writer.execute(
                            "DELETE FROM studio_authenticated_human_decision_events"
                        )
                        writer.execute("DELETE FROM studio_authenticated_human_decisions")
                    with self.assertRaisesRegex(StudioError, "unavailable"):
                        first.snapshot(review)
                finally:
                    if secondary is not None:
                        secondary.close()
                    primary.close()

    def test_enroll_domain_error_with_uncertain_rollback_invalidates_store(self) -> None:
        for effect_then_raise in (False, True):
            with (
                self.subTest(effect_then_raise=effect_then_raise),
                tempfile.TemporaryDirectory() as directory,
            ):
                store, authority = self._enrolled(directory)
                raw_connection = authority._connection
                fault_connection = _RollbackFaultConnection(
                    raw_connection, effect_then_raise=effect_then_raise
                )
                store._authenticated_human_decision_connection_instance = fault_connection
                try:
                    with self.assertRaisesRegex(
                        StudioError, "credential enrollment failed"
                    ):
                        StudioAuthenticatedHumanDecisionAuthority.enroll(
                            store, passphrase=self._PASSPHRASE
                        )
                    self.assertIsNone(
                        store._authenticated_human_decision_connection_instance
                    )
                    with self.assertRaisesRegex(StudioError, "unavailable"):
                        store._authenticated_human_decision_connection()
                    with self.assertRaisesRegex(StudioError, "unavailable"):
                        authority.snapshot(_review())
                    with self.assertRaises(sqlite3.ProgrammingError):
                        raw_connection.execute("SELECT 1")
                finally:
                    store.close()

    def test_unlock_domain_error_with_uncertain_rollback_invalidates_store(self) -> None:
        for effect_then_raise in (False, True):
            with (
                self.subTest(effect_then_raise=effect_then_raise),
                tempfile.TemporaryDirectory() as directory,
            ):
                store, authority = self._enrolled(directory)
                raw_connection = authority._connection
                fault_connection = _RollbackFaultConnection(
                    raw_connection, effect_then_raise=effect_then_raise
                )
                store._authenticated_human_decision_connection_instance = fault_connection
                try:
                    with self.assertRaisesRegex(StudioError, "authentication failed"):
                        StudioAuthenticatedHumanDecisionAuthority.unlock(
                            store,
                            passphrase="wrong passphrase with enough UTF-8 bytes",
                        )
                    self.assertIsNone(
                        store._authenticated_human_decision_connection_instance
                    )
                    with self.assertRaisesRegex(StudioError, "unavailable"):
                        StudioAuthenticatedHumanDecisionAuthority.unlock(
                            store, passphrase=self._PASSPHRASE
                        )
                    with self.assertRaisesRegex(StudioError, "unavailable"):
                        authority.snapshot(_review())
                    with self.assertRaises(sqlite3.ProgrammingError):
                        raw_connection.execute("SELECT 1")
                finally:
                    store.close()

    def test_enroll_commit_error_invalidates_store_without_acknowledging(self) -> None:
        for effect_then_raise in (False, True):
            with (
                self.subTest(effect_then_raise=effect_then_raise),
                tempfile.TemporaryDirectory() as directory,
            ):
                store = StudioStore(Path(directory) / "studio")
                raw_connection = store._authenticated_human_decision_connection()
                fault_connection = _CommitFaultConnection(
                    raw_connection, effect_then_raise=effect_then_raise
                )
                store._authenticated_human_decision_connection_instance = fault_connection
                try:
                    with self.assertRaisesRegex(
                        StudioError, "credential enrollment failed"
                    ):
                        StudioAuthenticatedHumanDecisionAuthority.enroll(
                            store, passphrase=self._PASSPHRASE
                        )
                    self.assertIsNone(
                        store._authenticated_human_decision_connection_instance
                    )
                    with self.assertRaisesRegex(StudioError, "unavailable"):
                        store._authenticated_human_decision_connection()
                    with self.assertRaises(sqlite3.ProgrammingError):
                        raw_connection.execute("SELECT 1")
                finally:
                    store.close()

    def test_unlock_commit_error_invalidates_store_without_returning_authority(self) -> None:
        for effect_then_raise in (False, True):
            with (
                self.subTest(effect_then_raise=effect_then_raise),
                tempfile.TemporaryDirectory() as directory,
            ):
                store, authority = self._enrolled(directory)
                raw_connection = authority._connection
                fault_connection = _CommitFaultConnection(
                    raw_connection, effect_then_raise=effect_then_raise
                )
                store._authenticated_human_decision_connection_instance = fault_connection
                try:
                    with self.assertRaisesRegex(
                        StudioError, "authenticated decision audit failed"
                    ):
                        StudioAuthenticatedHumanDecisionAuthority.unlock(
                            store, passphrase=self._PASSPHRASE
                        )
                    self.assertIsNone(
                        store._authenticated_human_decision_connection_instance
                    )
                    with self.assertRaisesRegex(StudioError, "unavailable"):
                        StudioAuthenticatedHumanDecisionAuthority.unlock(
                            store, passphrase=self._PASSPHRASE
                        )
                    with self.assertRaisesRegex(StudioError, "unavailable"):
                        authority.snapshot(_review())
                    with self.assertRaises(sqlite3.ProgrammingError):
                        raw_connection.execute("SELECT 1")
                finally:
                    store.close()

    def test_wrong_passphrase_with_proved_rollback_does_not_poison_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authority = self._enrolled(directory)
            self.addCleanup(store.close)
            with self.assertRaisesRegex(StudioError, "authentication failed"):
                StudioAuthenticatedHumanDecisionAuthority.unlock(
                    store,
                    passphrase="wrong passphrase with enough UTF-8 bytes",
                )
            unlocked = StudioAuthenticatedHumanDecisionAuthority.unlock(
                store, passphrase=self._PASSPHRASE
            )
            self.assertEqual("missing", unlocked.snapshot(_review()).state)
            self.assertEqual("missing", authority.snapshot(_review()).state)


if __name__ == "__main__":
    unittest.main()
