from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import worldforge.provider_evidence.ollama_v2_custody_ledger_store as ledger_module
from tests.test_ollama_v2_controller_store import (
    _plan as _controller_plan,
    _request as _controller_request,
)
from tests.test_ollama_v2_native_execution_contracts_d21 import _materials
from worldforge.provider_evidence.ollama_v2_custody_ledger_store import (
    CustodyLedgerReferenceCommitNotAppliedError,
    CustodyLedgerReferenceClosedError,
    CustodyLedgerReferenceConflictError,
    CustodyLedgerReferenceCorruptionError,
    CustodyLedgerReferenceDuplicateMismatchError,
    CustodyLedgerReferenceEventDocument,
    CustodyLedgerReferenceInvalidStateError,
    CustodyLedgerReferenceRecoveryRequiredError,
    CustodyLedgerReferenceSnapshot,
    CustodyLedgerReferenceTransition,
    OllamaV2CustodyLedgerReferenceStore,
    parse_custody_ledger_reference_event,
)
from worldforge.provider_evidence.ollama_v2_controller_contracts import (
    AuthorizationConsumption,
    OperationSnapshot,
)
from worldforge.provider_evidence.ollama_v2_native_execution_contracts import (
    CUSTODY_LEDGER_NAME,
    CUSTODY_LOCK_NAME,
    OllamaV2NativeExecutionBindingD2,
    OllamaV2NativeReservationD2,
    OllamaV2SourceBundleDescriptorD2,
)
from worldforge.provider_evidence.ollama_v2_controller_store import (
    OllamaV2ControllerStore,
)


def _unsafe_rehashed_event_clone(
    event: CustodyLedgerReferenceEventDocument,
    **changes: object,
) -> CustodyLedgerReferenceEventDocument:
    clone = object.__new__(CustodyLedgerReferenceEventDocument)
    for name in event.__dataclass_fields__:
        object.__setattr__(clone, name, changes.get(name, getattr(event, name)))
    if "event_id" not in changes:
        identity = ledger_module._event_identity_payload(
            event_type=clone.event_type,
            subject_id=clone.subject_id,
            subject_stage=clone.subject_stage,
            artifact_id=clone.artifact_id,
            artifact_type=clone.artifact_type,
            artifact_hash=clone.artifact_hash,
            binding_hash=clone.binding_hash,
        )
        object.__setattr__(clone, "event_id", ledger_module._reference_event_id(identity))
    if "event_hash" not in changes:
        object.__setattr__(clone, "event_hash", clone._computed_event_hash())
    return clone


class D21B2CustodyLedgerStoreTests(unittest.TestCase):
    def _root(self, parent: Path, name: str = "reference") -> Path:
        root = parent / name
        root.mkdir(mode=0o700)
        return root

    def test_surface_types_event_roundtrip_and_later_lifecycle_absence(self) -> None:
        material = _materials("b2-surface", effect_ordinal=2)
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                transition = store.register_source(material["source"])
                self.assertIs(type(transition), CustodyLedgerReferenceTransition)
                self.assertIs(type(transition.snapshot), CustodyLedgerReferenceSnapshot)
                self.assertIs(type(transition.event), CustodyLedgerReferenceEventDocument)
                self.assertTrue(transition.committed_now)
                self.assertEqual(
                    parse_custody_ledger_reference_event(transition.event.to_bytes()),
                    transition.event,
                )
                self.assertEqual(transition.event.event_type, "source.registered")
                self.assertEqual(transition.event.artifact, material["source"])
                self.assertIsNone(transition.event.binding)
                self.assertEqual(store.load_event(transition.event.event_id), transition.event)
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
            for call in (
                lambda: store.load_event(transition.event.event_id),
                lambda: store.load_source(material["source"].descriptor_id),
                lambda: store.register_source(material["source"]),
                lambda: store.reserve(material["binding"]),
            ):
                with self.assertRaises(CustodyLedgerReferenceClosedError):
                    call()

    def test_source_registration_is_exact_idempotent_and_counter_independent(self) -> None:
        first = _materials("b2-source-a", effect_ordinal=2)["source"]
        second = _materials("b2-source-b", effect_ordinal=4)["source"]
        self.assertIs(type(first), OllamaV2SourceBundleDescriptorD2)
        self.assertIs(type(second), OllamaV2SourceBundleDescriptorD2)
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                one = store.register_source(first)
                duplicate = store.register_source(first)
                two = store.register_source(second)
                self.assertTrue(one.committed_now)
                self.assertFalse(duplicate.committed_now)
                self.assertTrue(two.committed_now)
                self.assertEqual(duplicate.event, one.event)
                self.assertEqual(store.load_source(first.descriptor_id), first)
                self.assertEqual(store.load_source(second.descriptor_id), second)
                self.assertIsNone(store.load_source("source-missing"))
                head = store.head()
                self.assertEqual(head.event_sequence, 2)
                self.assertEqual(head.fence_generation, 0)
                self.assertEqual(head.record_sequence, 0)
                self.assertEqual(head.record_head_hash, "0" * 64)

    def test_source_event_identity_is_position_independent_and_unique_collisions_fail(self) -> None:
        prefix = _materials("b2-prefix", effect_ordinal=2)["source"]
        target = _materials("b2-stable-target", effect_ordinal=4)["source"]
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            first_root = self._root(parent, "first")
            second_root = self._root(parent, "second")
            with OllamaV2CustodyLedgerReferenceStore(first_root, mode="create") as first:
                direct = first.register_source(target).event
            with OllamaV2CustodyLedgerReferenceStore(second_root, mode="create") as second:
                second.register_source(prefix)
                shifted = second.register_source(target).event
                collision = _materials("b2-collision", effect_ordinal=2)["source"]
                real_event_id = ledger_module._reference_event_id

                def collide_only_new(identity: dict[str, object]) -> str:
                    if identity["artifact_id"] == collision.descriptor_id:
                        return shifted.event_id
                    return real_event_id(identity)

                with mock.patch.object(
                    ledger_module,
                    "_reference_event_id",
                    side_effect=collide_only_new,
                ):
                    with self.assertRaisesRegex(
                        ledger_module.CustodyLedgerReferenceDuplicateMismatchError,
                        "reference_duplicate_mismatch",
                    ):
                        second.register_source(collision)
            self.assertEqual(direct.event_id, shifted.event_id)
            self.assertNotEqual(direct.sequence, shifted.sequence)
            self.assertNotEqual(direct.event_hash, shifted.event_hash)

    def test_each_event_unique_domain_collision_fails_without_state_change(self) -> None:
        existing_source = _materials("b2-unique-existing", effect_ordinal=2)["source"]
        target_source = _materials("b2-unique-target", effect_ordinal=4)["source"]
        for collision in (
            "event_id",
            "event_hash",
            "artifact_id",
            "artifact_hash",
            "subject_id_subject_stage",
        ):
            with self.subTest(collision=collision), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                    existing = store.register_source(existing_source).event
                    before = store.snapshot()
                    candidate = CustodyLedgerReferenceEventDocument.create(
                        sequence=2,
                        event_type="source.registered",
                        artifact=target_source,
                        binding=None,
                        previous_event_hash=existing.event_hash,
                    )
                    if collision == "subject_id_subject_stage":
                        candidate = _unsafe_rehashed_event_clone(
                            candidate,
                            subject_id=existing.subject_id,
                            subject_stage=existing.subject_stage,
                        )
                    else:
                        candidate = _unsafe_rehashed_event_clone(
                            candidate,
                            **{collision: getattr(existing, collision)},
                        )
                    unique_values = {
                        "event_id": lambda item: item.event_id,
                        "event_hash": lambda item: item.event_hash,
                        "artifact_id": lambda item: item.artifact_id,
                        "artifact_hash": lambda item: item.artifact_hash,
                        "subject_id_subject_stage": lambda item: (
                            item.subject_id,
                            item.subject_stage,
                        ),
                    }
                    for domain, value in unique_values.items():
                        if domain == collision:
                            self.assertEqual(value(candidate), value(existing))
                        else:
                            self.assertNotEqual(value(candidate), value(existing))
                    if collision != "event_hash":
                        self.assertEqual(
                            candidate.event_hash,
                            candidate._computed_event_hash(),
                        )
                    with mock.patch.object(
                        CustodyLedgerReferenceEventDocument,
                        "create",
                        return_value=candidate,
                    ):
                        with self.assertRaisesRegex(
                            CustodyLedgerReferenceDuplicateMismatchError,
                            "^reference_duplicate_mismatch$",
                        ):
                            store.register_source(target_source)
                    self.assertEqual(store.snapshot(), before)
                    self.assertIsNone(store.load_source(target_source.descriptor_id))

        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            binding = _materials("b2-unique-binding", effect_ordinal=0)["binding"]
            target = _materials("b2-unique-binding-source", effect_ordinal=2)["source"]
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                reservation_event = store.reserve(binding).event
                before = store.snapshot()
                candidate = CustodyLedgerReferenceEventDocument.create(
                    sequence=2,
                    event_type="source.registered",
                    artifact=target,
                    binding=None,
                    previous_event_hash=reservation_event.event_hash,
                )
                candidate = _unsafe_rehashed_event_clone(
                    candidate,
                    binding_hash=reservation_event.binding_hash,
                )
                self.assertEqual(candidate.binding_hash, reservation_event.binding_hash)
                self.assertNotEqual(candidate.event_id, reservation_event.event_id)
                self.assertNotEqual(candidate.event_hash, reservation_event.event_hash)
                self.assertEqual(candidate.event_hash, candidate._computed_event_hash())
                with mock.patch.object(
                    CustodyLedgerReferenceEventDocument,
                    "create",
                    return_value=candidate,
                ):
                    with self.assertRaisesRegex(
                        CustodyLedgerReferenceDuplicateMismatchError,
                        "^reference_duplicate_mismatch$",
                    ):
                        store.register_source(target)
                self.assertEqual(store.snapshot(), before)
                self.assertIsNone(store.load_source(target.descriptor_id))

    def test_reservation_requires_registered_source_and_allocates_next_record_slot(self) -> None:
        material = _materials("b2-reserve", effect_ordinal=2)
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceConflictError,
                    "reference_source_not_registered",
                ):
                    store.reserve(material["binding"])
                store.register_source(material["source"])
                held = store.reserve(material["binding"])
                duplicate = store.reserve(material["binding"])
                self.assertTrue(held.committed_now)
                self.assertFalse(duplicate.committed_now)
                self.assertEqual(duplicate.event, held.event)
                reservation = held.snapshot.active_reservation
                self.assertIs(type(reservation), OllamaV2NativeReservationD2)
                self.assertEqual(reservation.fence_generation, 1)
                self.assertEqual(reservation.previous_fence_sequence, 0)
                self.assertEqual(reservation.fence_sequence, 1)
                self.assertEqual(reservation.previous_fence_hash, "0" * 64)
                head = held.snapshot.head
                self.assertEqual(head.event_sequence, 2)
                self.assertEqual(head.fence_generation, 1)
                self.assertEqual(head.record_sequence, 0)
                self.assertEqual(head.record_head_hash, "0" * 64)
                self.assertEqual(head.active_fence_hash, reservation.fence_hash)
                self.assertEqual(store.load_binding(material["binding"].binding_id), material["binding"])
                self.assertEqual(store.load_reservation(reservation.reservation_id), reservation)

    def test_reopen_identical_reservation_is_the_same_non_owner_transition(self) -> None:
        binding = _materials("b2-reopen-duplicate", effect_ordinal=0)["binding"]
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                original = store.reserve(binding)
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as reopened:
                duplicate = reopened.reserve(binding)
                self.assertFalse(duplicate.committed_now)
                self.assertEqual(duplicate.event, original.event)
                self.assertEqual(duplicate.snapshot, original.snapshot)
                self.assertEqual(
                    duplicate.snapshot.active_reservation,
                    original.snapshot.active_reservation,
                )
                self.assertEqual(duplicate.snapshot.head, original.snapshot.head)
                self.assertEqual(reopened.head().event_sequence, 1)
                self.assertEqual(reopened.head().fence_generation, 1)

    def test_reservation_identity_is_stable_across_prior_journal_positions(self) -> None:
        binding = _materials("b2-position-stable", effect_ordinal=0)["binding"]
        prefix = _materials("b2-position-prefix", effect_ordinal=2)["source"]
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            direct_root = self._root(parent, "direct")
            shifted_root = self._root(parent, "shifted")
            with OllamaV2CustodyLedgerReferenceStore(direct_root, mode="create") as direct:
                first = direct.reserve(binding)
            with OllamaV2CustodyLedgerReferenceStore(shifted_root, mode="create") as shifted:
                shifted.register_source(prefix)
                second = shifted.reserve(binding)
            self.assertEqual(
                first.snapshot.active_reservation,
                second.snapshot.active_reservation,
            )
            self.assertEqual(first.event.event_id, second.event.event_id)
            self.assertEqual(first.event.artifact_hash, second.event.artifact_hash)
            self.assertEqual(first.event.binding_hash, second.event.binding_hash)
            self.assertEqual((first.event.sequence, second.event.sequence), (1, 2))
            self.assertNotEqual(first.event.previous_event_hash, second.event.previous_event_hash)
            self.assertNotEqual(first.event.event_hash, second.event.event_hash)

    def test_non_source_effect_reserves_without_registration_and_competitor_conflicts(self) -> None:
        first = _materials("b2-no-source-a", effect_ordinal=0)["binding"]
        second = _materials("b2-no-source-b", effect_ordinal=0)["binding"]
        self.assertIsNone(first.source_bundle_descriptor)
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                winner = store.reserve(first)
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceConflictError,
                    "reference_active_reservation_conflict",
                ):
                    store.reserve(second)
                self.assertEqual(winner.snapshot.active_binding, first)
                self.assertEqual(store.snapshot(), winner.snapshot)

    def test_source_can_register_while_reserved_without_changing_fence(self) -> None:
        binding = _materials("b2-active", effect_ordinal=0)["binding"]
        source = _materials("b2-late-source", effect_ordinal=2)["source"]
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                reserved = store.reserve(binding).snapshot
                registered = store.register_source(source).snapshot
                self.assertEqual(registered.head.event_sequence, 2)
                self.assertEqual(registered.head.fence_generation, reserved.head.fence_generation)
                self.assertEqual(registered.head.record_sequence, reserved.head.record_sequence)
                self.assertEqual(registered.active_reservation, reserved.active_reservation)

    def test_reopen_replays_exact_graph_and_rejects_future_or_rewritten_rows(self) -> None:
        material = _materials("b2-replay", effect_ordinal=2)
        for mutation in (
            "UPDATE ollama_v2_custody_events SET event_type = 'c2.referenced' WHERE sequence = 1",
            "UPDATE ollama_v2_custody_events SET artifact_json = X'7B7D' WHERE sequence = 1",
            "UPDATE ollama_v2_custody_events SET previous_event_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE sequence = 2",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                    store.register_source(material["source"])
                    store.reserve(material["binding"])
                if mutation.startswith("UPDATE"):
                    connection = sqlite3.connect(root / CUSTODY_LEDGER_NAME)
                    try:
                        connection.execute(mutation)
                        connection.commit()
                    finally:
                        connection.close()
                with self.assertRaises(CustodyLedgerReferenceCorruptionError):
                    OllamaV2CustodyLedgerReferenceStore(root, mode="open")

        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                store.register_source(material["source"])
                expected = store.reserve(material["binding"]).snapshot
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as reopened:
                self.assertEqual(reopened.snapshot(), expected)

    def test_replay_rejects_changed_canonical_source_and_binding_bytes_under_same_identity(self) -> None:
        source_material = _materials("b2-source-bytes", effect_ordinal=2)
        foreign_source = _materials("b2-source-bytes-foreign", effect_ordinal=2)[
            "source"
        ]
        binding_material = _materials("b2-binding-bytes", effect_ordinal=0)
        foreign_binding = _materials("b2-binding-bytes-foreign", effect_ordinal=0)[
            "binding"
        ]
        cases = (
            (
                "source",
                source_material,
                "artifact_json",
                foreign_source.to_bytes(),
                1,
            ),
            (
                "binding",
                binding_material,
                "binding_json",
                foreign_binding.to_bytes(),
                1,
            ),
        )
        for name, material, column, replacement, sequence in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                    if name == "source":
                        store.register_source(material["source"])
                    else:
                        store.reserve(material["binding"])
                connection = sqlite3.connect(root / CUSTODY_LEDGER_NAME)
                try:
                    connection.execute(
                        f"UPDATE ollama_v2_custody_events SET {column} = ? WHERE sequence = ?",
                        (replacement, sequence),
                    )
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceCorruptionError,
                    "^reference_event_semantic_replay_invalid$",
                ):
                    OllamaV2CustodyLedgerReferenceStore(root, mode="open")

    def test_same_root_concurrency_serializes_sources_and_reservations(self) -> None:
        source_a = _materials("b2-concurrent-source-a", effect_ordinal=2)["source"]
        source_b = _materials("b2-concurrent-source-b", effect_ordinal=4)["source"]
        binding_a = _materials("b2-concurrent-binding-a", effect_ordinal=0)["binding"]
        binding_b = _materials("b2-concurrent-binding-b", effect_ordinal=0)["binding"]
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create"):
                pass

            def register(source: OllamaV2SourceBundleDescriptorD2) -> bool:
                with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                    return store.register_source(source).committed_now

            with ThreadPoolExecutor(max_workers=3) as pool:
                source_results = list(pool.map(register, (source_a, source_a, source_b)))
            self.assertEqual(sorted(source_results), [False, True, True])

            def reserve(binding: OllamaV2NativeExecutionBindingD2) -> str:
                try:
                    with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                        result = store.reserve(binding)
                        return f"ok:{result.committed_now}"
                except CustodyLedgerReferenceConflictError as exc:
                    return exc.reason_code

            with ThreadPoolExecutor(max_workers=2) as pool:
                reservation_results = list(pool.map(reserve, (binding_a, binding_b)))
            self.assertIn("ok:True", reservation_results)
            self.assertIn("reference_active_reservation_conflict", reservation_results)
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                self.assertEqual(store.head().event_sequence, 3)
                self.assertEqual(store.head().fence_generation, 1)

    def test_distinct_controller_database_identities_share_one_ledger_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            controller_a = OllamaV2ControllerStore(parent / "controller-a.sqlite3")
            controller_b = OllamaV2ControllerStore(parent / "controller-b.sqlite3")
            try:
                bindings = []
                consumed_states = []
                requests = []
                consumptions = []
                for suffix, controller in (
                    ("a", controller_a),
                    ("b", controller_b),
                ):
                    plan = _controller_plan(f"op-b2-controller-{suffix}")
                    created = controller.create_operation(
                        OperationSnapshot.create(plan.operation_id, plan),
                        plan,
                        idempotency_key=f"create-b2-controller-{suffix}",
                    ).snapshot
                    effect = plan.effects[0]
                    request = _controller_request(created, effect.effect_id)
                    pending = controller.record_authorization_pending(
                        created,
                        request,
                    ).snapshot
                    claimed = controller.record_authorization_claimed(
                        pending,
                        request,
                    ).snapshot
                    consumption = AuthorizationConsumption.create(
                        request,
                        authority_id=f"director-b2-{suffix}",
                        decision_id=f"decision-b2-{suffix}",
                    )
                    consumed = controller.record_authorization_consumed(
                        claimed,
                        request,
                        consumption,
                    ).snapshot
                    native = _materials(f"b2-controller-native-{suffix}", effect_ordinal=0)
                    binding = OllamaV2NativeExecutionBindingD2.create(
                        plan=plan,
                        effect=effect,
                        authorization_request=request,
                        c1_consumption=consumption,
                        controller_generation=request.expected_generation,
                        controller_sequence=request.expected_sequence,
                        controller_head_hash=request.expected_head_hash,
                        before_snapshot=plan.initial_snapshot,
                        resource_scope=native["scope"],
                        policy=native["policy"],
                        native_bundle_manifest=native["manifest"],
                        source_bundle_descriptor=None,
                        installation_attestation=native["installation"],
                    )
                    self.assertEqual(
                        controller.load_operation(plan.operation_id),
                        consumed,
                    )
                    self.assertEqual(
                        controller.load_authorization_request(request.content_hash),
                        request,
                    )
                    self.assertEqual(
                        controller.load_authorization_consumption(
                            request.authorization_id
                        ),
                        consumption,
                    )
                    bindings.append(binding)
                    consumed_states.append(consumed)
                    requests.append(request)
                    consumptions.append(consumption)
                self.assertNotEqual(bindings[0].operation_id, bindings[1].operation_id)
                self.assertNotEqual(requests[0].content_hash, requests[1].content_hash)
                self.assertNotEqual(
                    consumptions[0].content_hash,
                    consumptions[1].content_hash,
                )
                self.assertEqual(
                    [state.state for state in consumed_states],
                    ["apply_authorization_consumed", "apply_authorization_consumed"],
                )

                root = self._root(parent)
                with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                    winner = store.reserve(bindings[0])
                with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                    with self.assertRaisesRegex(
                        CustodyLedgerReferenceConflictError,
                        "^reference_active_reservation_conflict$",
                    ):
                        store.reserve(bindings[1])
                    self.assertEqual(store.snapshot().active_binding, bindings[0])
                    self.assertEqual(store.snapshot(), winner.snapshot)
            finally:
                controller_b.close()
                controller_a.close()

    def test_independent_processes_converge_on_one_identical_reservation_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = self._root(parent)
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create"):
                pass
            gate = parent / "go"
            code = """
import sys, time
from pathlib import Path
from tests.test_ollama_v2_native_execution_contracts_d21 import _materials
from worldforge.provider_evidence.ollama_v2_custody_ledger_store import OllamaV2CustodyLedgerReferenceStore
root, gate = Path(sys.argv[1]), Path(sys.argv[2])
store = OllamaV2CustodyLedgerReferenceStore(root, mode='open')
while not gate.exists():
    time.sleep(0.005)
binding = _materials('b2-process-reservation', effect_ordinal=0)['binding']
with store:
    print(store.reserve(binding).committed_now, flush=True)
"""
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(Path(__file__).parents[1] / "src") + os.pathsep + str(Path(__file__).parents[1])
            processes = [
                subprocess.Popen(
                    [sys.executable, "-c", code, str(root), str(gate)],
                    cwd=Path(__file__).parents[1],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for _ in range(2)
            ]
            gate.write_text("go", encoding="ascii")
            results = [process.communicate(timeout=10) for process in processes]
            self.assertEqual([process.returncode for process in processes], [0, 0])
            self.assertCountEqual([stdout.strip() for stdout, _ in results], ["True", "False"])
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as reopened:
                self.assertEqual(reopened.head().event_sequence, 1)
                self.assertEqual(reopened.head().fence_generation, 1)

    def test_commit_loss_reconciles_target_membership_absence_and_invalid_state(self) -> None:
        source = _materials("b2-commit-target", effect_ordinal=2)["source"]
        later = _materials("b2-commit-later", effect_ordinal=4)["source"]
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                original = store._commit

                def commit_then_later_then_raise() -> None:
                    original()
                    with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as other:
                        other.register_source(later)
                    raise RuntimeError("lost reply")

                with mock.patch.object(store, "_commit", side_effect=commit_then_later_then_raise):
                    reconciled = store.register_source(source)
                self.assertFalse(reconciled.committed_now)
                self.assertEqual(reconciled.snapshot.head.event_sequence, 2)

        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                with mock.patch.object(store, "_commit", side_effect=RuntimeError("before commit")):
                    with self.assertRaises(CustodyLedgerReferenceCommitNotAppliedError):
                        store.register_source(source)
                self.assertEqual(store.head().event_sequence, 0)

        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                store.reserve(_materials("b2-poison-lease", effect_ordinal=0)["binding"])
                original = store._commit

                def commit_corrupt_then_raise() -> None:
                    original()
                    connection = sqlite3.connect(root / CUSTODY_LEDGER_NAME)
                    try:
                        connection.execute(
                            "UPDATE ollama_v2_custody_events SET artifact_hash = ? WHERE sequence = 2",
                            (hashlib.sha256(b"foreign").hexdigest(),),
                        )
                        connection.commit()
                    finally:
                        connection.close()
                    raise RuntimeError("indeterminate")

                with mock.patch.object(store, "_commit", side_effect=commit_corrupt_then_raise):
                    with self.assertRaises(CustodyLedgerReferenceRecoveryRequiredError):
                        store.register_source(source)
                connection = sqlite3.connect(root / CUSTODY_LEDGER_NAME)
                try:
                    row = connection.execute(
                        "SELECT active_state, active_reservation_id, poisoned FROM ollama_v2_custody_head"
                    ).fetchone()
                finally:
                    connection.close()
                self.assertEqual(row[0], "reserved")
                self.assertIsNotNone(row[1])
                self.assertEqual(row[2], 1)

    def test_commit_reconciliation_rejects_replaced_database_identity(self) -> None:
        source = _materials("b2-replaced-database", effect_ordinal=2)["source"]
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = self._root(parent, "target")
            replacement_root = self._root(parent, "replacement")
            with OllamaV2CustodyLedgerReferenceStore(
                replacement_root,
                mode="create",
            ):
                pass
            replacement = replacement_root / CUSTODY_LEDGER_NAME
            store = OllamaV2CustodyLedgerReferenceStore(root, mode="create")
            try:
                original = store._commit

                def commit_replace_then_raise() -> None:
                    original()
                    database = root / CUSTODY_LEDGER_NAME
                    database.rename(root / f"{CUSTODY_LEDGER_NAME}.retained")
                    shutil.copyfile(replacement, database)
                    database.chmod(0o600)
                    raise RuntimeError("database replaced")

                with mock.patch.object(store, "_commit", side_effect=commit_replace_then_raise):
                    with self.assertRaises(CustodyLedgerReferenceRecoveryRequiredError):
                        store.register_source(source)
            finally:
                try:
                    store.close()
                except CustodyLedgerReferenceInvalidStateError:
                    pass

    def test_commit_reconciliation_rejects_root_and_lock_identity_replacement(self) -> None:
        source = _materials("b2-replaced-boundary", effect_ordinal=2)["source"]
        for replacement_kind in ("root", "lock"):
            with self.subTest(
                replacement_kind=replacement_kind
            ), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                root = self._root(parent)
                retained_root = parent / "reference.retained"
                retained_lock = root / f"{CUSTODY_LOCK_NAME}.retained"
                store = OllamaV2CustodyLedgerReferenceStore(root, mode="create")
                original = store._commit

                def commit_replace_then_raise() -> None:
                    original()
                    if replacement_kind == "root":
                        root.rename(retained_root)
                        root.mkdir(mode=0o700)
                    else:
                        lock = root / CUSTODY_LOCK_NAME
                        lock.rename(retained_lock)
                        lock.write_bytes(b"\0")
                        lock.chmod(0o600)
                    raise RuntimeError(f"{replacement_kind} replaced")

                try:
                    with mock.patch.object(
                        store,
                        "_commit",
                        side_effect=commit_replace_then_raise,
                    ):
                        with self.assertRaisesRegex(
                            CustodyLedgerReferenceRecoveryRequiredError,
                            "^reference_commit_recovery_required$",
                        ):
                            store.register_source(source)
                finally:
                    if replacement_kind == "root" and retained_root.exists():
                        if root.exists():
                            root.rmdir()
                        retained_root.rename(root)
                    elif replacement_kind == "lock" and retained_lock.exists():
                        lock = root / CUSTODY_LOCK_NAME
                        if lock.exists():
                            lock.unlink()
                        retained_lock.rename(lock)
                    store.close()

    def test_abrupt_process_exit_retains_logical_reservation_on_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            code = """
import os, sys
from pathlib import Path
from tests.test_ollama_v2_native_execution_contracts_d21 import _materials
from worldforge.provider_evidence.ollama_v2_custody_ledger_store import OllamaV2CustodyLedgerReferenceStore
root = Path(sys.argv[1])
binding = _materials('b2-abrupt', effect_ordinal=0)['binding']
store = OllamaV2CustodyLedgerReferenceStore(root, mode='create')
store.reserve(binding)
os._exit(0)
"""
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(Path(__file__).parents[1] / "src") + os.pathsep + str(Path(__file__).parents[1])
            completed = subprocess.run(
                [sys.executable, "-c", code, str(root)],
                cwd=Path(__file__).parents[1],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as reopened:
                snapshot = reopened.snapshot()
                self.assertEqual(snapshot.head.active_state, "reserved")
                self.assertEqual(snapshot.head.fence_generation, 1)
                self.assertEqual(snapshot.head.record_sequence, 0)


if __name__ == "__main__":
    unittest.main()
