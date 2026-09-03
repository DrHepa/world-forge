from __future__ import annotations

import dataclasses
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from unittest import mock

import worldforge.provider_evidence.ollama_v2_custody_ledger_store as ledger_module
from tests.test_ollama_v2_custody_ledger_store_d21b3a import _c2, _dispatch
from tests.test_ollama_v2_native_execution_contracts_d21 import _materials
from worldforge.provider_evidence.ollama_v2_controller_contracts import project_effect
from worldforge.provider_evidence.ollama_v2_custody_ledger_store import (
    CustodyLedgerReferenceConflictError,
    CustodyLedgerReferenceCorruptionError,
    CustodyLedgerReferenceDuplicateMismatchError,
    CustodyLedgerReferenceRelease,
    CustodyLedgerReferenceTombstone,
    OllamaV2CustodyLedgerReferenceStore,
    parse_custody_ledger_reference_event,
)
from worldforge.provider_evidence.ollama_v2_native_execution_contracts import (
    OllamaV2CustodyLedgerRecordD2,
    OllamaV2ManagerReloadWitnessD2,
    OllamaV2MutationAckD2,
    OllamaV2NativeExecutionContractError,
    canonical_ollama_v2_native_execution_bytes,
    parse_ollama_v2_native_execution_contract,
)


class D21B3BCustodyLedgerStoreTests(unittest.TestCase):
    def _root(self, parent: Path, name: str = "reference") -> Path:
        root = parent / name
        root.mkdir(mode=0o700)
        return root

    def _dispatch_ready(
        self,
        store: OllamaV2CustodyLedgerReferenceStore,
        suffix: str,
        *,
        effect_ordinal: int = 0,
        phase: str = "apply",
    ) -> tuple[dict[str, object], object, object]:
        material = _materials(
            suffix,
            effect_ordinal=effect_ordinal,
            phase=phase,
            previous_fence_sequence=0,
        )
        binding = material["binding"]
        source = material["source"]
        if source is not None:
            store.register_source(source)
        reservation = store.reserve(binding).snapshot.active_reservation
        assert reservation is not None
        c2 = _c2(suffix, binding, reservation)
        store.attach_c2_reference(c2)
        dispatch = _dispatch(suffix, binding, reservation, c2)
        store.commit_dispatch_intent(dispatch)
        return material, reservation, dispatch

    def test_ordinary_full_chain_advances_record_then_releases_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                material, reservation, dispatch = self._dispatch_ready(
                    store,
                    "b3b-ordinary",
                )
                ack = OllamaV2MutationAckD2.create(
                    dispatch,
                    correlation_hash="a" * 64,
                    acknowledged_at_ms=1_800_000_400_000,
                )
                acknowledged = store.record_mutation_ack(ack)
                record = OllamaV2CustodyLedgerRecordD2.create(
                    material["binding"],
                    reservation,
                    dispatch,
                    ack,
                    observed_snapshot=material["before"],
                    reload_witness=None,
                )
                observed = store.record_effect_observation(record)
                competitor = _materials(
                    "b3b-ordinary-blocked",
                    effect_ordinal=0,
                )["binding"]
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceConflictError,
                    "reference_active_reservation_conflict",
                ):
                    store.reserve(competitor)
                tombstoned = store.tombstone_observed_record(record.record_id)
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceConflictError,
                    "reference_active_reservation_conflict",
                ):
                    store.reserve(competitor)
                released = store.release_tombstoned_record(
                    tombstoned.event.artifact.tombstone_id
                )

                self.assertEqual("mutation.acknowledged", acknowledged.event.event_type)
                self.assertEqual(dispatch.dispatch_id, acknowledged.event.subject_id)
                self.assertEqual("effect.observed", observed.event.event_type)
                self.assertEqual(ack.ack_id, observed.event.subject_id)
                self.assertEqual("reservation.tombstoned", tombstoned.event.event_type)
                self.assertEqual(record.record_id, tombstoned.event.subject_id)
                self.assertIs(
                    type(tombstoned.event.artifact),
                    CustodyLedgerReferenceTombstone,
                )
                self.assertEqual("reservation.released", released.event.event_type)
                self.assertEqual(
                    tombstoned.event.artifact.tombstone_id,
                    released.event.subject_id,
                )
                self.assertIs(
                    type(released.event.artifact),
                    CustodyLedgerReferenceRelease,
                )
                self.assertEqual("idle", released.snapshot.head.active_state)
                self.assertEqual(
                    record.record_sequence,
                    released.snapshot.head.record_sequence,
                )
                self.assertEqual(
                    record.content_hash,
                    released.snapshot.head.record_head_hash,
                )
                self.assertIsNone(released.snapshot.active_reservation)
                self.assertEqual(ack, store.load_mutation_ack(ack.ack_id))
                self.assertEqual(record, store.load_record(record.record_id))
                self.assertEqual(
                    tombstoned.event,
                    parse_custody_ledger_reference_event(tombstoned.event.to_bytes()),
                )
                self.assertEqual(
                    released.event,
                    parse_custody_ledger_reference_event(released.event.to_bytes()),
                )

    def test_ordinary_rollback_matches_apply_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                material, reservation, dispatch = self._dispatch_ready(
                    store,
                    "b3b-ordinary-rollback",
                    phase="rollback",
                )
                ack = OllamaV2MutationAckD2.create(
                    dispatch,
                    correlation_hash="1" * 64,
                    acknowledged_at_ms=1_800_000_450_000,
                )
                store.record_mutation_ack(ack)
                record = OllamaV2CustodyLedgerRecordD2.create(
                    material["binding"],
                    reservation,
                    dispatch,
                    ack,
                    observed_snapshot=material["before"],
                    reload_witness=None,
                )
                store.record_effect_observation(record)
                tombstone = store.tombstone_observed_record(
                    record.record_id
                ).event.artifact
                released = store.release_tombstoned_record(tombstone.tombstone_id)
                self.assertEqual("idle", released.snapshot.head.active_state)
                self.assertEqual(
                    record.content_hash,
                    released.snapshot.head.record_head_hash,
                )

    def test_manager_witness_is_required_for_apply_and_rollback(self) -> None:
        for phase in ("apply", "rollback"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                    material, reservation, dispatch = self._dispatch_ready(
                        store,
                        f"b3b-manager-{phase}",
                        effect_ordinal=8,
                        phase=phase,
                    )
                    ack = OllamaV2MutationAckD2.create(
                        dispatch,
                        correlation_hash="b" * 64,
                        acknowledged_at_ms=1_800_000_500_000,
                    )
                    store.record_mutation_ack(ack)
                    observed_snapshot = project_effect(
                        material["before"],
                        material["controller_plan"],
                        material["effect"],
                        material["controller_plan"].operation_id,
                    )
                    witness = OllamaV2ManagerReloadWitnessD2.create(
                        material["binding"],
                        dispatch,
                        ack,
                        before_snapshot=material["before"],
                        observed_snapshot=observed_snapshot,
                        observed_at_ms=1_800_000_500_001,
                        manager_observation_hash="c" * 64,
                    )
                    record = OllamaV2CustodyLedgerRecordD2.create(
                        material["binding"],
                        reservation,
                        dispatch,
                        ack,
                        observed_snapshot=observed_snapshot,
                        reload_witness=witness,
                    )
                    with self.assertRaisesRegex(
                        CustodyLedgerReferenceConflictError,
                        "reference_observation_state_conflict",
                    ):
                        store.record_effect_observation(record)
                    witnessed = store.record_manager_reload_witness(witness)
                    observed = store.record_effect_observation(record)

                    self.assertEqual("manager.witnessed", witnessed.event.event_type)
                    self.assertEqual(ack.ack_id, witnessed.event.subject_id)
                    self.assertEqual("witnessed", witnessed.snapshot.head.active_state)
                    self.assertEqual("observed", observed.snapshot.head.active_state)
                    self.assertEqual(witness.witness_id, observed.event.subject_id)
                    self.assertEqual(
                        witness,
                        store.load_manager_reload_witness(witness.witness_id),
                    )

    def test_ordinary_effect_rejects_manager_witness(self) -> None:
        manager = _materials("b3b-foreign-manager", effect_ordinal=8)
        observed_snapshot = project_effect(
            manager["before"],
            manager["controller_plan"],
            manager["effect"],
            manager["controller_plan"].operation_id,
        )
        witness = OllamaV2ManagerReloadWitnessD2.create(
            manager["binding"],
            manager["dispatch"],
            manager["ack"],
            before_snapshot=manager["before"],
            observed_snapshot=observed_snapshot,
            observed_at_ms=1_800_000_550_000,
            manager_observation_hash="f" * 64,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                self._dispatch_ready(store, "b3b-no-witness")
                before = store.snapshot()
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceConflictError,
                    "reference_manager_witness_not_required",
                ):
                    store.record_manager_reload_witness(witness)
                self.assertEqual(before, store.snapshot())

    def test_old_manager_witness_duplicate_returns_latest_later_cycle_snapshot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                material, reservation, dispatch = self._dispatch_ready(
                    store,
                    "b3b-old-witness",
                    effect_ordinal=8,
                )
                ack = OllamaV2MutationAckD2.create(
                    dispatch,
                    correlation_hash="1" * 64,
                    acknowledged_at_ms=1_800_000_575_000,
                )
                store.record_mutation_ack(ack)
                observed_snapshot = project_effect(
                    material["before"],
                    material["controller_plan"],
                    material["effect"],
                    material["controller_plan"].operation_id,
                )
                witness = OllamaV2ManagerReloadWitnessD2.create(
                    material["binding"],
                    dispatch,
                    ack,
                    before_snapshot=material["before"],
                    observed_snapshot=observed_snapshot,
                    observed_at_ms=1_800_000_575_001,
                    manager_observation_hash="2" * 64,
                )
                witnessed = store.record_manager_reload_witness(witness)
                record = OllamaV2CustodyLedgerRecordD2.create(
                    material["binding"],
                    reservation,
                    dispatch,
                    ack,
                    observed_snapshot=observed_snapshot,
                    reload_witness=witness,
                )
                store.record_effect_observation(record)
                tombstone = store.tombstone_observed_record(
                    record.record_id
                ).event.artifact
                store.release_tombstoned_record(tombstone.tombstone_id)

                self._dispatch_ready(store, "b3b-after-old-witness")
                later_snapshot = store.snapshot()
                retry = store.record_manager_reload_witness(witness)
                self.assertFalse(retry.committed_now)
                self.assertEqual(witnessed.event, retry.event)
                self.assertEqual(later_snapshot, retry.snapshot)
                self.assertEqual(later_snapshot, store.snapshot())

                changed = object.__new__(OllamaV2ManagerReloadWitnessD2)
                for field in dataclasses.fields(witness):
                    object.__setattr__(
                        changed,
                        field.name,
                        (
                            "3" * 64
                            if field.name == "manager_observation_hash"
                            else getattr(witness, field.name)
                        ),
                    )
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceDuplicateMismatchError,
                    "reference_duplicate_mismatch",
                ):
                    store.record_manager_reload_witness(changed)
                self.assertEqual(later_snapshot, store.snapshot())

    def test_release_retains_history_and_old_binding_never_allocates_new_fence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                material = _materials(
                    "b3b-cycle-one",
                    effect_ordinal=8,
                    previous_fence_sequence=0,
                )
                binding = material["binding"]
                reserved = store.reserve(binding)
                reservation = reserved.snapshot.active_reservation
                assert reservation is not None
                c2 = _c2("b3b-cycle-one", binding, reservation)
                referenced = store.attach_c2_reference(c2)
                dispatch = _dispatch(
                    "b3b-cycle-one",
                    binding,
                    reservation,
                    c2,
                )
                dispatched = store.commit_dispatch_intent(dispatch)
                ack = OllamaV2MutationAckD2.create(
                    dispatch,
                    correlation_hash="d" * 64,
                    acknowledged_at_ms=1_800_000_600_000,
                )
                acknowledged = store.record_mutation_ack(ack)
                observed_snapshot = project_effect(
                    material["before"],
                    material["controller_plan"],
                    material["effect"],
                    material["controller_plan"].operation_id,
                )
                witness = OllamaV2ManagerReloadWitnessD2.create(
                    material["binding"],
                    dispatch,
                    ack,
                    before_snapshot=material["before"],
                    observed_snapshot=observed_snapshot,
                    observed_at_ms=1_800_000_600_001,
                    manager_observation_hash="e" * 64,
                )
                witnessed = store.record_manager_reload_witness(witness)
                record = OllamaV2CustodyLedgerRecordD2.create(
                    material["binding"],
                    reservation,
                    dispatch,
                    ack,
                    observed_snapshot=observed_snapshot,
                    reload_witness=witness,
                )
                observed = store.record_effect_observation(record)
                tombstoned = store.tombstone_observed_record(record.record_id)
                tombstone = tombstoned.event.artifact
                released = store.release_tombstoned_record(tombstone.tombstone_id)

                old = store.reserve(binding)
                self.assertFalse(old.committed_now)
                self.assertEqual(reservation, old.event.artifact)
                self.assertEqual("idle", old.snapshot.head.active_state)
                self.assertEqual(1, old.snapshot.head.fence_generation)

                second_material = _materials("b3b-cycle-two", effect_ordinal=0)
                fresh = second_material["binding"]
                second = store.reserve(fresh)
                second_reservation = second.snapshot.active_reservation
                assert second_reservation is not None
                self.assertTrue(second.committed_now)
                self.assertEqual(2, second_reservation.fence_generation)
                self.assertEqual(
                    record.record_sequence,
                    second_reservation.previous_fence_sequence,
                )
                self.assertEqual(
                    record.content_hash,
                    second_reservation.previous_fence_hash,
                )
                self.assertEqual(ack, store.load_mutation_ack(ack.ack_id))
                self.assertEqual(record, store.load_record(record.record_id))
                self.assertEqual(
                    tombstone,
                    store.load_tombstone(tombstone.tombstone_id),
                )
                self.assertEqual(
                    released.event.artifact,
                    store.load_release(released.event.artifact.release_id),
                )

                def assert_historical_retries(
                    expected_snapshot,
                    retries,
                ) -> None:
                    for expected_event, action in retries:
                        retry = action()
                        self.assertFalse(retry.committed_now)
                        self.assertEqual(expected_event, retry.event)
                        self.assertEqual(expected_snapshot, retry.snapshot)
                        self.assertEqual(expected_snapshot, store.snapshot())

                early_retries = (
                    (reserved.event, partial(store.reserve, binding)),
                    (referenced.event, partial(store.attach_c2_reference, c2)),
                    (
                        dispatched.event,
                        partial(store.commit_dispatch_intent, dispatch),
                    ),
                )
                assert_historical_retries(store.snapshot(), early_retries)

                second_c2 = _c2("b3b-cycle-two", fresh, second_reservation)
                store.attach_c2_reference(second_c2)
                assert_historical_retries(store.snapshot(), early_retries)
                second_dispatch = _dispatch(
                    "b3b-cycle-two",
                    fresh,
                    second_reservation,
                    second_c2,
                )
                store.commit_dispatch_intent(second_dispatch)
                later_snapshot = store.snapshot()
                assert_historical_retries(
                    later_snapshot,
                    (
                        *early_retries,
                        (
                            acknowledged.event,
                            partial(store.record_mutation_ack, ack),
                        ),
                        (
                            witnessed.event,
                            partial(store.record_manager_reload_witness, witness),
                        ),
                        (
                            observed.event,
                            partial(store.record_effect_observation, record),
                        ),
                        (
                            tombstoned.event,
                            partial(store.tombstone_observed_record, record.record_id),
                        ),
                        (
                            released.event,
                            partial(
                                store.release_tombstoned_record,
                                tombstone.tombstone_id,
                            ),
                        ),
                    ),
                )

                def unsafe_clone(value, **changes):
                    result = object.__new__(type(value))
                    for field in dataclasses.fields(value):
                        object.__setattr__(
                            result,
                            field.name,
                            changes.get(field.name, getattr(value, field.name)),
                        )
                    return result

                changed_identity_artifacts = (
                    unsafe_clone(binding, availability="tampered"),
                    unsafe_clone(c2, review_hash="f" * 64),
                    unsafe_clone(dispatch, current_controller_head_hash="f" * 64),
                )
                changed_actions = (
                    store.reserve,
                    store.attach_c2_reference,
                    store.commit_dispatch_intent,
                )
                for action, changed in zip(
                    changed_actions,
                    changed_identity_artifacts,
                    strict=True,
                ):
                    with self.assertRaisesRegex(
                        CustodyLedgerReferenceDuplicateMismatchError,
                        "reference_duplicate_mismatch",
                    ):
                        action(changed)
                    self.assertEqual(later_snapshot, store.snapshot())

                foreign = _materials("b3b-cycle-foreign", effect_ordinal=0)
                for action, artifact in (
                    (store.reserve, foreign["binding"]),
                    (store.attach_c2_reference, foreign["c2"]),
                    (store.commit_dispatch_intent, foreign["dispatch"]),
                ):
                    with self.assertRaises(CustodyLedgerReferenceConflictError):
                        action(artifact)
                    self.assertEqual(later_snapshot, store.snapshot())

                second_ack = OllamaV2MutationAckD2.create(
                    second_dispatch,
                    correlation_hash="a" * 64,
                    acknowledged_at_ms=1_800_000_600_001,
                )
                store.record_mutation_ack(second_ack)
                second_record = OllamaV2CustodyLedgerRecordD2.create(
                    fresh,
                    second_reservation,
                    second_dispatch,
                    second_ack,
                    observed_snapshot=second_material["before"],
                    reload_witness=None,
                )
                store.record_effect_observation(second_record)
                second_tombstone = store.tombstone_observed_record(
                    second_record.record_id
                ).event.artifact
                second_release = store.release_tombstoned_record(
                    second_tombstone.tombstone_id
                ).event.artifact
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as reopened:
                self.assertEqual("idle", reopened.head().active_state)
                self.assertEqual(2, reopened.head().record_sequence)
                self.assertEqual(record, reopened.load_record(record.record_id))
                self.assertEqual(
                    second_record,
                    reopened.load_record(second_record.record_id),
                )
                self.assertEqual(
                    released.event.artifact,
                    reopened.load_release(released.event.artifact.release_id),
                )
                self.assertEqual(
                    second_release,
                    reopened.load_release(second_release.release_id),
                )

    def test_store_local_documents_are_exact_backward_only_non_native_metadata(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                material, reservation, dispatch = self._dispatch_ready(
                    store,
                    "b3b-metadata",
                )
                ack = OllamaV2MutationAckD2.create(
                    dispatch,
                    correlation_hash="e" * 64,
                    acknowledged_at_ms=1_800_000_700_000,
                )
                store.record_mutation_ack(ack)
                record = OllamaV2CustodyLedgerRecordD2.create(
                    material["binding"],
                    reservation,
                    dispatch,
                    ack,
                    observed_snapshot=material["before"],
                    reload_witness=None,
                )
                store.record_effect_observation(record)
                tombstone_event = store.tombstone_observed_record(
                    record.record_id
                ).event
                tombstone = tombstone_event.artifact
                release_event = store.release_tombstoned_record(
                    tombstone.tombstone_id
                ).event
                release = release_event.artifact

                class EqualText(str):
                    pass

                class EqualInteger(int):
                    pass

                class EqualMapping(dict):
                    pass

                for marker_name, marker_type, marker, string_fields in (
                    (
                        "tombstone",
                        CustodyLedgerReferenceTombstone,
                        tombstone,
                        (
                            "format",
                            "scope",
                            "tombstone_id",
                            "record_hash",
                            "content_hash",
                        ),
                    ),
                    (
                        "release",
                        CustodyLedgerReferenceRelease,
                        release,
                        (
                            "format",
                            "scope",
                            "release_id",
                            "tombstone_hash",
                            "content_hash",
                        ),
                    ),
                ):
                    self.assertEqual(
                        marker,
                        marker_type.from_document(marker.to_document()),
                    )
                    for field in string_fields:
                        with self.subTest(marker=marker_name, field=field):
                            hostile = marker.to_document()
                            hostile[field] = EqualText(hostile[field])
                            with self.assertRaisesRegex(
                                Exception,
                                f"reference_{marker_name}_invalid",
                            ):
                                marker_type.from_document(hostile)
                    for replacement in (True, EqualInteger(1)):
                        with self.subTest(
                            marker=marker_name,
                            format_version=type(replacement).__name__,
                        ):
                            hostile = marker.to_document()
                            hostile["format_version"] = replacement
                            with self.assertRaisesRegex(
                                Exception,
                                f"reference_{marker_name}_invalid",
                            ):
                                marker_type.from_document(hostile)
                    with self.subTest(marker=marker_name, mapping="subclass"):
                        with self.assertRaisesRegex(
                            Exception,
                            f"reference_{marker_name}_invalid",
                        ):
                            marker_type.from_document(
                                EqualMapping(marker.to_document())
                            )
                    with self.subTest(marker=marker_name, key="subclass"):
                        hostile = {
                            (
                                EqualText(key)
                                if key == "format"
                                else key
                            ): value
                            for key, value in marker.to_document().items()
                        }
                        with self.assertRaisesRegex(
                            Exception,
                            f"reference_{marker_name}_invalid",
                        ):
                            marker_type.from_document(hostile)
                    with self.subTest(marker=marker_name, keys="unknown"):
                        hostile = marker.to_document()
                        hostile["unknown"] = "forbidden"
                        with self.assertRaisesRegex(
                            Exception,
                            f"reference_{marker_name}_invalid",
                        ):
                            marker_type.from_document(hostile)
                    with self.subTest(marker=marker_name, keys="missing"):
                        hostile = marker.to_document()
                        del hostile["content_hash"]
                        with self.assertRaisesRegex(
                            Exception,
                            f"reference_{marker_name}_invalid",
                        ):
                            marker_type.from_document(hostile)

                self.assertEqual(
                    {"tombstone_id", "record_hash"},
                    {field.name for field in dataclasses.fields(tombstone)},
                )
                self.assertEqual(
                    {"release_id", "tombstone_hash"},
                    {field.name for field in dataclasses.fields(release)},
                )
                self.assertEqual(record.content_hash, tombstone.record_hash)
                self.assertEqual(tombstone.content_hash, release.tombstone_hash)
                self.assertNotIn("event", tombstone.to_document())
                self.assertNotIn("native", release.to_document())
                with self.assertRaises(OllamaV2NativeExecutionContractError):
                    parse_ollama_v2_native_execution_contract(tombstone.to_bytes())
                with self.assertRaises(OllamaV2NativeExecutionContractError):
                    parse_ollama_v2_native_execution_contract(release.to_bytes())
                with self.assertRaisesRegex(
                    Exception,
                    "reference_tombstone_invalid",
                ):
                    dataclasses.replace(tombstone, record_hash="f" * 64)
                with self.assertRaisesRegex(
                    Exception,
                    "reference_release_invalid",
                ):
                    dataclasses.replace(release, tombstone_hash="f" * 64)
                hostile = tombstone_event.to_document()
                hostile["artifact"]["extra"] = "forbidden"
                with self.assertRaisesRegex(Exception, "reference_tombstone_invalid"):
                    parse_custody_ledger_reference_event(
                        canonical_ollama_v2_native_execution_bytes(hostile)
                    )
                hostile_release = release_event.to_document()
                hostile_release["artifact"]["extra"] = "forbidden"
                with self.assertRaisesRegex(Exception, "reference_release_invalid"):
                    parse_custody_ledger_reference_event(
                        canonical_ollama_v2_native_execution_bytes(hostile_release)
                    )
                for field, replacement in (
                    ("format", "wrong"),
                    ("format_version", 2),
                    ("scope", "wrong"),
                    ("tombstone_id", "0" * 64),
                    ("record_hash", "0" * 64),
                ):
                    with self.subTest(field=field):
                        hostile = tombstone_event.to_document()
                        hostile["artifact"][field] = replacement
                        with self.assertRaisesRegex(
                            Exception,
                            "reference_(event_document|tombstone)_invalid",
                        ):
                            parse_custody_ledger_reference_event(
                                canonical_ollama_v2_native_execution_bytes(hostile)
                            )
                noncanonical = json.dumps(
                    tombstone_event.to_document(),
                    indent=2,
                ).encode("utf-8")
                with self.assertRaisesRegex(
                    Exception,
                    "reference_event_document_invalid",
                ):
                    parse_custody_ledger_reference_event(noncanonical)

    def test_reopen_each_prefix_and_semantic_tampering_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            store = OllamaV2CustodyLedgerReferenceStore(root, mode="create")
            material, reservation, dispatch = self._dispatch_ready(store, "b3b-reopen")
            ack = OllamaV2MutationAckD2.create(
                dispatch,
                correlation_hash="1" * 64,
                acknowledged_at_ms=1_800_000_800_000,
            )
            record = OllamaV2CustodyLedgerRecordD2.create(
                material["binding"],
                reservation,
                dispatch,
                ack,
                observed_snapshot=material["before"],
                reload_witness=None,
            )
            transitions = [store.record_mutation_ack(ack)]
            store.close()
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                self.assertEqual("acknowledged", store.head().active_state)
                transitions.append(store.record_effect_observation(record))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                self.assertEqual("observed", store.head().active_state)
                transitions.append(store.tombstone_observed_record(record.record_id))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                self.assertEqual("tombstoned", store.head().active_state)
                tombstone = transitions[-1].event.artifact
                transitions.append(
                    store.release_tombstoned_record(tombstone.tombstone_id)
                )
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                self.assertEqual("idle", store.head().active_state)
                self.assertEqual(7, store.head().event_sequence)

            connection = sqlite3.connect(root / "custody-ledger.sqlite3")
            try:
                connection.execute(
                    "UPDATE ollama_v2_custody_events "
                    "SET subject_id = 'record-crossed' "
                    "WHERE event_type = 'reservation.tombstoned'"
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(
                CustodyLedgerReferenceCorruptionError,
                "reference_event_semantic_replay_invalid|"
                "reference_tombstone_graph_invalid",
            ):
                OllamaV2CustodyLedgerReferenceStore(root, mode="open")

    def test_commit_loss_at_every_stage_reconciles_after_source_suffix(self) -> None:
        for stage in ("ack", "witness", "observation", "tombstone", "release"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                store = OllamaV2CustodyLedgerReferenceStore(root, mode="create")
                manager = stage == "witness"
                material, reservation, dispatch = self._dispatch_ready(
                    store,
                    f"b3b-loss-{stage}",
                    effect_ordinal=8 if manager else 0,
                )
                ack = OllamaV2MutationAckD2.create(
                    dispatch,
                    correlation_hash="2" * 64,
                    acknowledged_at_ms=1_800_000_900_000,
                )
                observed_snapshot = material["before"]
                witness = None
                if stage != "ack":
                    store.record_mutation_ack(ack)
                if manager:
                    observed_snapshot = project_effect(
                        material["before"],
                        material["controller_plan"],
                        material["effect"],
                        material["controller_plan"].operation_id,
                    )
                    witness = OllamaV2ManagerReloadWitnessD2.create(
                        material["binding"],
                        dispatch,
                        ack,
                        before_snapshot=material["before"],
                        observed_snapshot=observed_snapshot,
                        observed_at_ms=1_800_000_900_001,
                        manager_observation_hash="3" * 64,
                    )
                record = OllamaV2CustodyLedgerRecordD2.create(
                    material["binding"],
                    reservation,
                    dispatch,
                    ack,
                    observed_snapshot=observed_snapshot,
                    reload_witness=witness,
                )
                if stage in {"tombstone", "release"}:
                    store.record_effect_observation(record)
                tombstone = None
                if stage == "release":
                    tombstone = store.tombstone_observed_record(
                        record.record_id
                    ).event.artifact
                if stage == "ack":
                    action = partial(store.record_mutation_ack, ack)
                    expected = "mutation.acknowledged"
                elif stage == "witness":
                    action = partial(store.record_manager_reload_witness, witness)
                    expected = "manager.witnessed"
                elif stage == "observation":
                    action = partial(store.record_effect_observation, record)
                    expected = "effect.observed"
                elif stage == "tombstone":
                    action = partial(store.tombstone_observed_record, record.record_id)
                    expected = "reservation.tombstoned"
                else:
                    action = partial(
                        store.release_tombstoned_record,
                        tombstone.tombstone_id,
                    )
                    expected = "reservation.released"
                suffix_source = _materials(
                    f"b3b-loss-source-{stage}", effect_ordinal=2
                )["source"]
                original = store._commit

                def commit_suffix_raise(
                    original=original,
                    root=root,
                    suffix_source=suffix_source,
                ) -> None:
                    original()
                    with OllamaV2CustodyLedgerReferenceStore(
                        root,
                        mode="open",
                    ) as other:
                        other.register_source(suffix_source)
                    raise RuntimeError("lost reply")

                with mock.patch.object(
                    store,
                    "_commit",
                    side_effect=commit_suffix_raise,
                ):
                    reconciled = action()
                self.assertFalse(reconciled.committed_now)
                self.assertEqual(expected, reconciled.event.event_type)
                self.assertEqual(
                    suffix_source,
                    store.load_source(suffix_source.descriptor_id),
                )
                self.assertEqual(
                    reconciled.event.sequence + 1,
                    store.head().event_sequence,
                )
                store.close()

    def test_same_input_concurrency_has_one_owner_and_no_partial_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                _, _, dispatch = self._dispatch_ready(store, "b3b-concurrent")
            ack = OllamaV2MutationAckD2.create(
                dispatch,
                correlation_hash="4" * 64,
                acknowledged_at_ms=1_800_001_000_000,
            )

            def persist(_: int) -> bool:
                with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                    return store.record_mutation_ack(ack).committed_now

            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertEqual([False, True], sorted(pool.map(persist, range(2))))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                self.assertEqual("acknowledged", store.head().active_state)
                self.assertEqual(ack, store.load_mutation_ack(ack.ack_id))

    def test_unequal_ack_contenders_conflict_without_partial_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                _, _, dispatch = self._dispatch_ready(store, "b3b-unequal")
            contenders = tuple(
                OllamaV2MutationAckD2.create(
                    dispatch,
                    correlation_hash=character * 64,
                    acknowledged_at_ms=1_800_001_100_000,
                )
                for character in ("5", "6")
            )

            def persist(ack: OllamaV2MutationAckD2) -> tuple[str, bool]:
                try:
                    with OllamaV2CustodyLedgerReferenceStore(
                        root,
                        mode="open",
                    ) as store:
                        return ack.ack_id, store.record_mutation_ack(ack).committed_now
                except CustodyLedgerReferenceConflictError:
                    return ack.ack_id, False

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = tuple(pool.map(persist, contenders))
            self.assertEqual(1, sum(committed for _, committed in results))
            winner_id = next(ack_id for ack_id, committed in results if committed)
            loser_id = next(ack_id for ack_id, committed in results if not committed)
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                self.assertEqual("acknowledged", store.head().active_state)
                self.assertEqual(4, store.head().event_sequence)
                self.assertIsNotNone(store.load_mutation_ack(winner_id))
                self.assertIsNone(store.load_mutation_ack(loser_id))

    def test_same_input_concurrency_has_one_owner_at_every_later_stage(
        self,
    ) -> None:
        for stage in ("ack", "witness", "observation", "tombstone", "release"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                manager = stage == "witness"
                with OllamaV2CustodyLedgerReferenceStore(
                    root,
                    mode="create",
                ) as store:
                    material, reservation, dispatch = self._dispatch_ready(
                        store,
                        f"b3b-concurrent-{stage}",
                        effect_ordinal=8 if manager else 0,
                    )
                    ack = OllamaV2MutationAckD2.create(
                        dispatch,
                        correlation_hash="b" * 64,
                        acknowledged_at_ms=1_800_001_150_000,
                    )
                    observed_snapshot = material["before"]
                    witness = None
                    if stage != "ack":
                        store.record_mutation_ack(ack)
                    if manager:
                        observed_snapshot = project_effect(
                            material["before"],
                            material["controller_plan"],
                            material["effect"],
                            material["controller_plan"].operation_id,
                        )
                        witness = OllamaV2ManagerReloadWitnessD2.create(
                            material["binding"],
                            dispatch,
                            ack,
                            before_snapshot=material["before"],
                            observed_snapshot=observed_snapshot,
                            observed_at_ms=1_800_001_150_001,
                            manager_observation_hash="c" * 64,
                        )
                    record = OllamaV2CustodyLedgerRecordD2.create(
                        material["binding"],
                        reservation,
                        dispatch,
                        ack,
                        observed_snapshot=observed_snapshot,
                        reload_witness=witness,
                    )
                    if stage in {"tombstone", "release"}:
                        store.record_effect_observation(record)
                    tombstone = None
                    if stage == "release":
                        tombstone = store.tombstone_observed_record(
                            record.record_id
                        ).event.artifact

                def persist(
                    _: int,
                    *,
                    root=root,
                    stage=stage,
                    ack=ack,
                    witness=witness,
                    record=record,
                    tombstone=tombstone,
                ) -> bool:
                    with OllamaV2CustodyLedgerReferenceStore(
                        root,
                        mode="open",
                    ) as store:
                        if stage == "ack":
                            result = store.record_mutation_ack(ack)
                        elif stage == "witness":
                            result = store.record_manager_reload_witness(witness)
                        elif stage == "observation":
                            result = store.record_effect_observation(record)
                        elif stage == "tombstone":
                            result = store.tombstone_observed_record(record.record_id)
                        else:
                            result = store.release_tombstoned_record(
                                tombstone.tombstone_id
                            )
                        return result.committed_now

                with ThreadPoolExecutor(max_workers=2) as pool:
                    self.assertEqual(
                        [False, True],
                        sorted(pool.map(persist, range(2))),
                    )

    def test_source_interleavings_are_lifecycle_neutral_and_bindings_stay_null(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                material, reservation, dispatch = self._dispatch_ready(
                    store,
                    "b3b-sources",
                )
                ack = OllamaV2MutationAckD2.create(
                    dispatch,
                    correlation_hash="7" * 64,
                    acknowledged_at_ms=1_800_001_200_000,
                )
                record = OllamaV2CustodyLedgerRecordD2.create(
                    material["binding"],
                    reservation,
                    dispatch,
                    ack,
                    observed_snapshot=material["before"],
                    reload_witness=None,
                )
                actions = (
                    lambda: store.record_mutation_ack(ack),
                    lambda: store.record_effect_observation(record),
                    lambda: store.tombstone_observed_record(record.record_id),
                )
                for ordinal, action in enumerate(actions):
                    before = store.head()
                    source = _materials(
                        f"b3b-source-interleave-{ordinal}",
                        effect_ordinal=2,
                    )["source"]
                    store.register_source(source)
                    after = store.head()
                    self.assertEqual(before.active_state, after.active_state)
                    self.assertEqual(before.record_sequence, after.record_sequence)
                    self.assertEqual(before.record_head_hash, after.record_head_hash)
                    action()
                tombstone = store.snapshot().active_tombstone
                assert tombstone is not None
                store.release_tombstoned_record(tombstone.tombstone_id)

            connection = sqlite3.connect(root / "custody-ledger.sqlite3")
            try:
                rows = connection.execute(
                    "SELECT binding_hash, binding_json "
                    "FROM ollama_v2_custody_events "
                    "WHERE event_type IN "
                    "('mutation.acknowledged', 'effect.observed', "
                    "'reservation.tombstoned', 'reservation.released')"
                ).fetchall()
            finally:
                connection.close()
            self.assertEqual([(None, None)] * 4, rows)

    def test_abrupt_process_exit_reopens_each_lifecycle_prefix(self) -> None:
        expected_states = {
            "ack": "acknowledged",
            "witness": "witnessed",
            "observation": "observed",
            "tombstone": "tombstoned",
            "release": "idle",
        }
        for stage, expected_state in expected_states.items():
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                manager = stage == "witness"
                suffix = f"b3b-abrupt-{stage}"
                with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                    self._dispatch_ready(
                        store,
                        suffix,
                        effect_ordinal=8 if manager else 0,
                    )
                code = f"""
import os
from pathlib import Path
from tests.test_ollama_v2_native_execution_contracts_d21 import _materials
from worldforge.provider_evidence.ollama_v2_controller_contracts import (
    project_effect,
)
from worldforge.provider_evidence.ollama_v2_custody_ledger_store import (
    OllamaV2CustodyLedgerReferenceStore,
)
from worldforge.provider_evidence.ollama_v2_native_execution_contracts import (
    OllamaV2CustodyLedgerRecordD2,
    OllamaV2ManagerReloadWitnessD2,
    OllamaV2MutationAckD2,
)
root = Path({str(root)!r})
material = _materials(
    {suffix!r},
    effect_ordinal={8 if manager else 0},
    previous_fence_sequence=0,
)
store = OllamaV2CustodyLedgerReferenceStore(root, mode='open')
snapshot = store.snapshot()
dispatch = snapshot.active_dispatch_intent
reservation = snapshot.active_reservation
ack = OllamaV2MutationAckD2.create(
    dispatch,
    correlation_hash='8' * 64,
    acknowledged_at_ms=1800001300000,
)
store.record_mutation_ack(ack)
observed_snapshot = material['before']
witness = None
if {manager!r}:
    observed_snapshot = project_effect(
        material['before'],
        material['controller_plan'],
        material['effect'],
        material['controller_plan'].operation_id,
    )
    witness = OllamaV2ManagerReloadWitnessD2.create(
        material['binding'],
        dispatch,
        ack,
        before_snapshot=material['before'],
        observed_snapshot=observed_snapshot,
        observed_at_ms=1800001300001,
        manager_observation_hash='9' * 64,
    )
    store.record_manager_reload_witness(witness)
if {stage in {'observation', 'tombstone', 'release'}!r}:
    record = OllamaV2CustodyLedgerRecordD2.create(
        material['binding'],
        reservation,
        dispatch,
        ack,
        observed_snapshot=observed_snapshot,
        reload_witness=witness,
    )
    store.record_effect_observation(record)
if {stage in {'tombstone', 'release'}!r}:
    tombstone = store.tombstone_observed_record(record.record_id).event.artifact
if {stage == 'release'!r}:
    store.release_tombstoned_record(tombstone.tombstone_id)
os._exit(41)
"""
                environment = dict(os.environ)
                environment["PYTHONPATH"] = (
                    str(Path(__file__).resolve().parents[1] / "src")
                    + os.pathsep
                    + str(Path(__file__).resolve().parents[1])
                )
                process = subprocess.run(
                    [sys.executable, "-c", code],
                    cwd=Path(__file__).resolve().parents[1],
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(41, process.returncode, process.stderr)
                with OllamaV2CustodyLedgerReferenceStore(
                    root,
                    mode="open",
                ) as reopened:
                    self.assertEqual(expected_state, reopened.head().active_state)

    def test_public_surface_cannot_execute_or_redispatch_effects(self) -> None:
        forbidden = {
            "execute_effect",
            "retry_effect",
            "redispatch_effect",
            "call_provider",
            "call_service",
            "call_host",
        }
        self.assertTrue(forbidden.isdisjoint(vars(OllamaV2CustodyLedgerReferenceStore)))
        self.assertNotIn("OllamaV2ControllerStore", ledger_module.__all__)


if __name__ == "__main__":
    unittest.main()
