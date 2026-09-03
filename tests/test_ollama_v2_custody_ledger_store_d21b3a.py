from __future__ import annotations

import hashlib
import inspect
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from tests.test_ollama_v2_native_execution_contracts_d21 import _materials
from worldforge.provider_evidence.ollama_v2_custody_ledger_store import (
    CustodyLedgerReferenceCommitNotAppliedError,
    CustodyLedgerReferenceConflictError,
    CustodyLedgerReferenceCorruptionError,
    CustodyLedgerReferenceEventDocument,
    CustodyLedgerReferenceInvalidStateError,
    CustodyLedgerReferenceTransition,
    OllamaV2CustodyLedgerReferenceStore,
    parse_custody_ledger_reference_event,
)
from worldforge.provider_evidence.ollama_v2_native_execution_contracts import (
    CUSTODY_LEDGER_NAME,
    OllamaV2C2AuthorizationReferenceD2,
    OllamaV2DispatchEnvelopeD2,
    OllamaV2NativeExecutionBindingD2,
    OllamaV2NativeReservationD2,
    OllamaV2SourceBundleDescriptorD2,
)


def _c2(
    suffix: str,
    binding: OllamaV2NativeExecutionBindingD2,
    reservation: OllamaV2NativeReservationD2,
    *,
    consumption_id: str | None = None,
) -> OllamaV2C2AuthorizationReferenceD2:
    return OllamaV2C2AuthorizationReferenceD2.create(
        binding,
        reservation,
        review_id=f"review-c2-{suffix}",
        review_hash=hashlib.sha256(f"review-c2-{suffix}".encode()).hexdigest(),
        decision_id=f"decision-c2-{suffix}",
        decision_hash=hashlib.sha256(f"decision-c2-{suffix}".encode()).hexdigest(),
        consumption_id=consumption_id or f"consume-c2-{suffix}",
        consumption_hash=hashlib.sha256(f"consume-c2-{suffix}".encode()).hexdigest(),
    )


def _dispatch(
    suffix: str,
    binding: OllamaV2NativeExecutionBindingD2,
    reservation: OllamaV2NativeReservationD2,
    c2: OllamaV2C2AuthorizationReferenceD2,
) -> OllamaV2DispatchEnvelopeD2:
    sequence = binding.controller_anchor_sequence + 1
    return OllamaV2DispatchEnvelopeD2.create(
        binding,
        reservation,
        c2,
        current_controller_generation=binding.controller_anchor_generation,
        current_controller_sequence=sequence,
        current_controller_head_hash=hashlib.sha256(
            f"dispatch-controller-head-{suffix}".encode()
        ).hexdigest(),
    )


class D21B3ACustodyLedgerStoreTests(unittest.TestCase):
    def _root(self, parent: Path, name: str = "reference") -> Path:
        root = parent / name
        root.mkdir(mode=0o700)
        return root

    def _reserve(
        self,
        store: OllamaV2CustodyLedgerReferenceStore,
        suffix: str,
    ) -> tuple[OllamaV2NativeExecutionBindingD2, OllamaV2NativeReservationD2]:
        binding = _materials(suffix, effect_ordinal=0)["binding"]
        self.assertIs(type(binding), OllamaV2NativeExecutionBindingD2)
        transition = store.reserve(binding)
        reservation = transition.snapshot.active_reservation
        self.assertIs(type(reservation), OllamaV2NativeReservationD2)
        return binding, reservation

    def test_surface_round_trip_and_intent_only_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                binding, reservation = self._reserve(store, "b3a-surface")
                c2 = _c2("b3a-surface", binding, reservation)
                referenced = store.attach_c2_reference(c2)
                dispatch = _dispatch("b3a-surface", binding, reservation, c2)
                committed = store.commit_dispatch_intent(dispatch)

                self.assertEqual(referenced.event.event_type, "c2.referenced")
                self.assertEqual(referenced.event.subject_id, reservation.reservation_id)
                self.assertIsNone(referenced.event.binding)
                self.assertEqual(committed.event.event_type, "dispatch.committed")
                self.assertEqual(committed.event.subject_id, c2.reference_id)
                self.assertIsNone(committed.event.binding)
                self.assertEqual(
                    parse_custody_ledger_reference_event(referenced.event.to_bytes()),
                    referenced.event,
                )
                self.assertEqual(
                    parse_custody_ledger_reference_event(committed.event.to_bytes()),
                    committed.event,
                )
                method_doc = inspect.getdoc(store.commit_dispatch_intent) or ""
                self.assertIn("intent", method_doc.casefold())
                self.assertIn("does not execute", method_doc.casefold())
                for forbidden in (
                    "ack",
                    "dispatch",
                    "execute",
                    "observe",
                    "record",
                    "release",
                    "retry",
                    "tombstone",
                    "witness",
                ):
                    self.assertFalse(hasattr(store, forbidden))

    def test_legal_flow_loaders_exact_graph_and_source_suffixes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                binding, reservation = self._reserve(store, "b3a-flow")
                c2 = _c2("b3a-flow", binding, reservation)
                referenced = store.attach_c2_reference(c2)
                source_one = _materials("b3a-source-one", effect_ordinal=2)["source"]
                store.register_source(source_one)
                self.assertEqual(store.snapshot().head.active_state, "c2_referenced")
                dispatch = _dispatch("b3a-flow", binding, reservation, c2)
                committed = store.commit_dispatch_intent(dispatch)
                source_two = _materials("b3a-source-two", effect_ordinal=4)["source"]
                store.register_source(source_two)

                snapshot = store.snapshot()
                self.assertTrue(referenced.committed_now)
                self.assertTrue(committed.committed_now)
                self.assertEqual(snapshot.head.active_state, "dispatch_committed")
                self.assertEqual(snapshot.active_binding.to_bytes(), binding.to_bytes())
                self.assertEqual(snapshot.active_reservation.to_bytes(), reservation.to_bytes())
                self.assertEqual(snapshot.active_c2_reference.to_bytes(), c2.to_bytes())
                self.assertEqual(snapshot.active_dispatch_intent.to_bytes(), dispatch.to_bytes())
                self.assertEqual(store.load_c2_reference(c2.reference_id), c2)
                self.assertEqual(store.load_dispatch_intent(dispatch.dispatch_id), dispatch)
                self.assertIsNone(store.load_c2_reference("c2ref-missing"))
                self.assertIsNone(store.load_dispatch_intent("dispatch-missing"))
                self.assertEqual(snapshot.head.event_sequence, 5)
                connection = sqlite3.connect(root / CUSTODY_LEDGER_NAME)
                try:
                    rows = connection.execute(
                        "SELECT event_type, binding_hash, binding_json "
                        "FROM ollama_v2_custody_events ORDER BY sequence"
                    ).fetchall()
                finally:
                    connection.close()
                self.assertEqual(
                    [row[0] for row in rows],
                    [
                        "reservation.held",
                        "c2.referenced",
                        "source.registered",
                        "dispatch.committed",
                        "source.registered",
                    ],
                )
                self.assertEqual(rows[1][1:], (None, None))
                self.assertEqual(rows[3][1:], (None, None))

    def test_illegal_transitions_and_transplants_fail_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = self._root(parent)
            foreign_root = self._root(parent, "foreign")
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                foreign = _materials("b3a-foreign", effect_ordinal=0)
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceConflictError,
                    "reference_c2_state_conflict",
                ):
                    store.attach_c2_reference(foreign["c2"])
                binding, reservation = self._reserve(store, "b3a-local")
                local_c2 = _c2("b3a-local", binding, reservation)
                local_dispatch = _dispatch("b3a-local", binding, reservation, local_c2)
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceConflictError,
                    "reference_dispatch_state_conflict",
                ):
                    store.commit_dispatch_intent(local_dispatch)
                before = store.snapshot()
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceConflictError,
                    "reference_c2_active_mismatch",
                ):
                    store.attach_c2_reference(foreign["c2"])
                self.assertEqual(store.snapshot(), before)
                store.attach_c2_reference(local_c2)

                with OllamaV2CustodyLedgerReferenceStore(
                    foreign_root, mode="create"
                ) as foreign_store:
                    foreign_binding, foreign_reservation = self._reserve(
                        foreign_store, "b3a-other"
                    )
                    foreign_c2 = _c2(
                        "b3a-other", foreign_binding, foreign_reservation
                    )
                    foreign_dispatch = _dispatch(
                        "b3a-other", foreign_binding, foreign_reservation, foreign_c2
                    )
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceConflictError,
                    "reference_dispatch_active_mismatch",
                ):
                    store.commit_dispatch_intent(foreign_dispatch)
                self.assertEqual(store.snapshot().head.active_state, "c2_referenced")

    def test_exact_duplicates_and_reopen_are_permanent_nonowners(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                binding, reservation = self._reserve(store, "b3a-duplicate")
                c2 = _c2("b3a-duplicate", binding, reservation)
                first_c2 = store.attach_c2_reference(c2)
                duplicate_c2 = store.attach_c2_reference(c2)
                dispatch = _dispatch("b3a-duplicate", binding, reservation, c2)
                first_dispatch = store.commit_dispatch_intent(dispatch)
                duplicate_dispatch = store.commit_dispatch_intent(dispatch)
                self.assertTrue(first_c2.committed_now)
                self.assertFalse(duplicate_c2.committed_now)
                self.assertTrue(first_dispatch.committed_now)
                self.assertFalse(duplicate_dispatch.committed_now)
                self.assertEqual(first_c2.event, duplicate_c2.event)
                self.assertEqual(first_dispatch.event, duplicate_dispatch.event)
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as reopened:
                self.assertFalse(reopened.attach_c2_reference(c2).committed_now)
                self.assertFalse(reopened.commit_dispatch_intent(dispatch).committed_now)
                self.assertEqual(reopened.head().event_sequence, 3)

    def test_one_use_consumption_reference_and_dispatch_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                binding, reservation = self._reserve(store, "b3a-unique")
                first = _c2("b3a-unique-a", binding, reservation)
                same_consumption = _c2(
                    "b3a-unique-b",
                    binding,
                    reservation,
                    consumption_id=first.consumption_id,
                )
                store.attach_c2_reference(first)
                with self.assertRaises(CustodyLedgerReferenceConflictError):
                    store.attach_c2_reference(same_consumption)
                first_dispatch = _dispatch(
                    "b3a-unique-a", binding, reservation, first
                )
                other_dispatch = _dispatch(
                    "b3a-unique-b", binding, reservation, first
                )
                store.commit_dispatch_intent(first_dispatch)
                with self.assertRaises(CustodyLedgerReferenceConflictError):
                    store.commit_dispatch_intent(other_dispatch)
                self.assertEqual(store.head().event_sequence, 3)

    def test_same_root_concurrency_has_one_direct_owner_per_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                binding, reservation = self._reserve(store, "b3a-concurrency")
            c2 = _c2("b3a-concurrency", binding, reservation)

            def attach(_: int) -> bool:
                with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                    return store.attach_c2_reference(c2).committed_now

            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertEqual(sorted(pool.map(attach, range(2))), [False, True])

            dispatch = _dispatch("b3a-concurrency", binding, reservation, c2)

            def commit(_: int) -> bool:
                with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                    return store.commit_dispatch_intent(dispatch).committed_now

            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertEqual(sorted(pool.map(commit, range(2))), [False, True])
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                self.assertEqual(store.snapshot().active_dispatch_intent, dispatch)

    def test_event_identities_ignore_source_prefix_positions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            direct_root = self._root(parent, "direct")
            shifted_root = self._root(parent, "shifted")
            prefix = _materials("b3a-position-prefix", effect_ordinal=2)["source"]
            with OllamaV2CustodyLedgerReferenceStore(
                direct_root, mode="create"
            ) as direct:
                binding, reservation = self._reserve(direct, "b3a-position")
                c2 = _c2("b3a-position", binding, reservation)
                direct_c2 = direct.attach_c2_reference(c2).event
                dispatch = _dispatch("b3a-position", binding, reservation, c2)
                direct_dispatch = direct.commit_dispatch_intent(dispatch).event
            with OllamaV2CustodyLedgerReferenceStore(
                shifted_root, mode="create"
            ) as shifted:
                shifted.register_source(prefix)
                shifted_binding, shifted_reservation = self._reserve(
                    shifted, "b3a-position"
                )
                shifted_c2 = shifted.attach_c2_reference(
                    _c2("b3a-position", shifted_binding, shifted_reservation)
                ).event
                shifted_dispatch = shifted.commit_dispatch_intent(
                    _dispatch(
                        "b3a-position",
                        shifted_binding,
                        shifted_reservation,
                        shifted_c2.artifact,
                    )
                ).event
            self.assertEqual(binding, shifted_binding)
            self.assertEqual(reservation, shifted_reservation)
            self.assertEqual(direct_c2.event_id, shifted_c2.event_id)
            self.assertNotEqual(direct_c2.event_hash, shifted_c2.event_hash)
            self.assertEqual(direct_dispatch.event_id, shifted_dispatch.event_id)
            self.assertNotEqual(direct_dispatch.event_hash, shifted_dispatch.event_hash)

    def test_competing_c2_references_have_one_same_root_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                binding, reservation = self._reserve(store, "b3a-c2-race")
            references = (
                _c2("b3a-c2-race-a", binding, reservation),
                _c2("b3a-c2-race-b", binding, reservation),
            )

            def attach(reference: OllamaV2C2AuthorizationReferenceD2) -> str:
                try:
                    with OllamaV2CustodyLedgerReferenceStore(
                        root, mode="open"
                    ) as store:
                        result = store.attach_c2_reference(reference)
                        return f"owner:{result.event.artifact_id}"
                except CustodyLedgerReferenceConflictError as exc:
                    return f"conflict:{exc.reason_code}"

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = tuple(pool.map(attach, references))
            self.assertEqual(sum(result.startswith("owner:") for result in results), 1)
            self.assertEqual(
                sum(
                    result == "conflict:reference_c2_active_mismatch"
                    for result in results
                ),
                1,
            )
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                active = store.snapshot().active_c2_reference
                self.assertIn(active, references)
                self.assertEqual(store.head().event_sequence, 2)

    def test_commit_loss_reconciliation_never_returns_dispatch_owner(self) -> None:
        source = _materials("b3a-commit-suffix", effect_ordinal=2)["source"]
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            committed_root = self._root(parent, "committed")
            with OllamaV2CustodyLedgerReferenceStore(
                committed_root, mode="create"
            ) as store:
                binding, reservation = self._reserve(store, "b3a-commit")
                c2 = _c2("b3a-commit", binding, reservation)
                store.attach_c2_reference(c2)
                dispatch = _dispatch("b3a-commit", binding, reservation, c2)
                original = store._commit

                def commit_then_suffix_then_raise() -> None:
                    original()
                    with OllamaV2CustodyLedgerReferenceStore(
                        committed_root, mode="open"
                    ) as other:
                        other.register_source(source)
                    raise RuntimeError("lost reply")

                with mock.patch.object(
                    store, "_commit", side_effect=commit_then_suffix_then_raise
                ):
                    reconciled = store.commit_dispatch_intent(dispatch)
                self.assertFalse(reconciled.committed_now)
                self.assertEqual(reconciled.snapshot.head.active_state, "dispatch_committed")
                self.assertEqual(reconciled.snapshot.head.event_sequence, 4)

            absent_root = self._root(parent, "absent")
            with OllamaV2CustodyLedgerReferenceStore(absent_root, mode="create") as store:
                binding, reservation = self._reserve(store, "b3a-not-applied")
                c2 = _c2("b3a-not-applied", binding, reservation)
                with mock.patch.object(
                    store, "_commit", side_effect=RuntimeError("before commit")
                ):
                    with self.assertRaises(CustodyLedgerReferenceCommitNotAppliedError):
                        store.attach_c2_reference(c2)
                self.assertEqual(store.snapshot().head.active_state, "reserved")

    def test_commit_loss_returns_repositioned_c2_and_dispatch_winners(self) -> None:
        for stage in ("c2", "dispatch"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                source = _materials(
                    f"b3a-repositioned-{stage}-source", effect_ordinal=2
                )["source"]
                with OllamaV2CustodyLedgerReferenceStore(
                    root, mode="create"
                ) as store:
                    binding, reservation = self._reserve(
                        store, f"b3a-repositioned-{stage}"
                    )
                    c2 = _c2(f"b3a-repositioned-{stage}", binding, reservation)
                    dispatch = None
                    if stage == "dispatch":
                        store.attach_c2_reference(c2)
                        dispatch = _dispatch(
                            "b3a-repositioned-dispatch",
                            binding,
                            reservation,
                            c2,
                        )
                        artifact = dispatch
                        event_type = "dispatch.committed"
                        subject_id = c2.reference_id
                    else:
                        artifact = c2
                        event_type = "c2.referenced"
                        subject_id = reservation.reservation_id
                    head = store.head()
                    provisional = CustodyLedgerReferenceEventDocument.create(
                        sequence=head.event_sequence + 1,
                        event_type=event_type,
                        artifact=artifact,
                        binding=None,
                        previous_event_hash=head.event_head_hash,
                        subject_id=subject_id,
                    )
                    historical_winners = []

                    def rollback_then_competing_winner_then_raise(
                        root: Path = root,
                        source: OllamaV2SourceBundleDescriptorD2 = source,
                        stage: str = stage,
                        c2: OllamaV2C2AuthorizationReferenceD2 = c2,
                        dispatch: OllamaV2DispatchEnvelopeD2 | None = dispatch,
                        historical_winners: list[
                            CustodyLedgerReferenceTransition
                        ] = historical_winners,
                    ) -> None:
                        store._rollback()
                        with OllamaV2CustodyLedgerReferenceStore(
                            root, mode="open"
                        ) as other:
                            other.register_source(source)
                            if stage == "c2":
                                winner = other.attach_c2_reference(c2)
                            else:
                                assert dispatch is not None
                                winner = other.commit_dispatch_intent(dispatch)
                            self.assertTrue(winner.committed_now)
                            historical_winners.append(winner)
                        raise RuntimeError("lost reply after competing winner")

                    with mock.patch.object(
                        store,
                        "_commit",
                        side_effect=rollback_then_competing_winner_then_raise,
                    ):
                        if stage == "c2":
                            reconciled = store.attach_c2_reference(c2)
                        else:
                            reconciled = store.commit_dispatch_intent(dispatch)
                    expected_sequence = provisional.sequence + 1
                    self.assertEqual(len(historical_winners), 1)
                    historical_winner = historical_winners[0]
                    self.assertFalse(reconciled.committed_now)
                    self.assertEqual(reconciled.event, historical_winner.event)
                    self.assertEqual(reconciled.snapshot, historical_winner.snapshot)
                    self.assertEqual(reconciled.event.event_id, provisional.event_id)
                    self.assertEqual(reconciled.event.sequence, expected_sequence)
                    self.assertNotEqual(reconciled.event, provisional)
                    self.assertEqual(
                        reconciled.snapshot.head.event_sequence,
                        expected_sequence,
                    )
                    self.assertEqual(
                        reconciled.snapshot.head.event_head_hash,
                        reconciled.event.event_hash,
                    )
                    self.assertFalse(reconciled.snapshot.head.poisoned)
                    if stage == "c2":
                        retry = store.attach_c2_reference(c2)
                    else:
                        retry = store.commit_dispatch_intent(dispatch)
                    self.assertFalse(retry.committed_now)
                    self.assertEqual(retry.event, reconciled.event)
                    self.assertEqual(retry.snapshot, reconciled.snapshot)

    def test_abrupt_process_reopen_cannot_reclaim_dispatch_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                binding, reservation = self._reserve(store, "b3a-abrupt")
                c2 = _c2("b3a-abrupt", binding, reservation)
                store.attach_c2_reference(c2)
                dispatch = _dispatch("b3a-abrupt", binding, reservation, c2)
            script = f"""
import os
from pathlib import Path
from worldforge.provider_evidence.ollama_v2_custody_ledger_store import (
    OllamaV2CustodyLedgerReferenceStore,
)
from worldforge.provider_evidence.ollama_v2_native_execution_contracts import (
    OllamaV2DispatchEnvelopeD2,
)
root = Path({str(root)!r})
with OllamaV2CustodyLedgerReferenceStore(root, mode='open') as store:
    snapshot = store.snapshot()
    dispatch = OllamaV2DispatchEnvelopeD2.create(
        snapshot.active_binding,
        snapshot.active_reservation,
        snapshot.active_c2_reference,
        current_controller_generation={dispatch.current_controller_generation!r},
        current_controller_sequence={dispatch.current_controller_sequence!r},
        current_controller_head_hash={dispatch.current_controller_head_hash!r},
    )
    result = store.commit_dispatch_intent(dispatch)
    if not result.committed_now:
        raise SystemExit(70)
    os._exit(41)
"""
            environment = dict(os.environ)
            environment["PYTHONPATH"] = "src"
            process = subprocess.run(
                [sys.executable, "-c", script],
                cwd=Path(__file__).resolve().parents[1],
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(process.returncode, 41, process.stderr)
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as reopened:
                duplicate = reopened.commit_dispatch_intent(dispatch)
                self.assertFalse(duplicate.committed_now)
                self.assertEqual(duplicate.snapshot.head.active_state, "dispatch_committed")

    def test_semantic_replay_rejects_wrong_c2_subject_and_foreign_dispatch(self) -> None:
        for case in ("c2-subject", "foreign-dispatch"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                root = self._root(parent)
                with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                    binding, reservation = self._reserve(store, f"b3a-replay-{case}")
                    c2 = _c2(f"b3a-replay-{case}", binding, reservation)
                    head = store.head()
                    if case == "c2-subject":
                        event = CustodyLedgerReferenceEventDocument.create(
                            sequence=head.event_sequence + 1,
                            event_type="c2.referenced",
                            artifact=c2,
                            binding=None,
                            previous_event_hash=head.event_head_hash,
                            subject_id="reservation-foreign",
                        )
                        next_state = "c2_referenced"
                    else:
                        store.attach_c2_reference(c2)
                        head = store.head()
                        foreign_root = self._root(parent, "foreign")
                        with OllamaV2CustodyLedgerReferenceStore(
                            foreign_root, mode="create"
                        ) as foreign_store:
                            foreign_binding, foreign_reservation = self._reserve(
                                foreign_store, "b3a-replay-foreign"
                            )
                            foreign_c2 = _c2(
                                "b3a-replay-foreign",
                                foreign_binding,
                                foreign_reservation,
                            )
                            foreign_dispatch = _dispatch(
                                "b3a-replay-foreign",
                                foreign_binding,
                                foreign_reservation,
                                foreign_c2,
                            )
                        event = CustodyLedgerReferenceEventDocument.create(
                            sequence=head.event_sequence + 1,
                            event_type="dispatch.committed",
                            artifact=foreign_dispatch,
                            binding=None,
                            previous_event_hash=head.event_head_hash,
                            subject_id=c2.reference_id,
                        )
                        next_state = "dispatch_committed"
                connection = sqlite3.connect(root / CUSTODY_LEDGER_NAME)
                try:
                    connection.execute(
                        """INSERT INTO ollama_v2_custody_events(
                            sequence, event_id, event_type, subject_id, subject_stage,
                            artifact_id, artifact_type, artifact_hash, artifact_json,
                            binding_hash, binding_json, previous_event_hash, event_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            event.sequence,
                            event.event_id,
                            event.event_type,
                            event.subject_id,
                            event.subject_stage,
                            event.artifact_id,
                            event.artifact_type,
                            event.artifact_hash,
                            event.artifact.to_bytes(),
                            None,
                            None,
                            event.previous_event_hash,
                            event.event_hash,
                        ),
                    )
                    connection.execute(
                        """UPDATE ollama_v2_custody_head
                        SET active_state = ?, event_sequence = ?, event_head_hash = ?
                        WHERE scope = ?""",
                        (next_state, event.sequence, event.event_hash, head.scope),
                    )
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceCorruptionError,
                    "reference_(c2|dispatch)_graph_invalid",
                ):
                    OllamaV2CustodyLedgerReferenceStore(root, mode="open")

    def test_wrong_types_and_closed_store_fail_in_reference_domain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            store = OllamaV2CustodyLedgerReferenceStore(root, mode="create")
            binding, reservation = self._reserve(store, "b3a-invalid")
            c2 = _c2("b3a-invalid", binding, reservation)
            dispatch = _dispatch("b3a-invalid", binding, reservation, c2)
            with self.assertRaisesRegex(
                CustodyLedgerReferenceInvalidStateError,
                "reference_c2_invalid",
            ):
                store.attach_c2_reference(dispatch)  # type: ignore[arg-type]
            with self.assertRaisesRegex(
                CustodyLedgerReferenceInvalidStateError,
                "reference_dispatch_invalid",
            ):
                store.commit_dispatch_intent(c2)  # type: ignore[arg-type]
            store.close()
            for call in (
                lambda: store.load_c2_reference(c2.reference_id),
                lambda: store.load_dispatch_intent(dispatch.dispatch_id),
                lambda: store.attach_c2_reference(c2),
                lambda: store.commit_dispatch_intent(dispatch),
            ):
                with self.assertRaisesRegex(Exception, "reference_store_closed"):
                    call()


if __name__ == "__main__":
    unittest.main()
