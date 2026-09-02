from __future__ import annotations

import dataclasses
import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from worldforge.provider_evidence.ollama_v2_controller_contracts import (
    CONTROLLER_GID,
    CONTROLLER_UID,
    MODEL_FINAL_ROOT,
    RELEASE_FINAL_ROOT,
    AuthorizationConsumption,
    AuthorizationRejection,
    AuthorizationRequest,
    BoundedTreeManifest,
    ManifestEntry,
    OperationSnapshot,
    build_controller_plan,
    build_rollback_plan,
    canonical_controller_bytes,
    host_projection_hash,
    make_empty_host_snapshot,
    project_effect,
)
from worldforge.provider_evidence.ollama_v2_controller_store import (
    ControllerStoreCommitNotApplied,
    ControllerStoreConflictError,
    ControllerStoreCorruptionError,
    ControllerStoreDuplicateMismatch,
    ControllerStoreRecoveryRequired,
    OllamaV2ControllerStore,
)


def _entry(path: str, payload: bytes) -> ManifestEntry:
    return ManifestEntry(
        relative_path=path,
        entry_kind="file",
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        mode=0o444,
        uid=CONTROLLER_UID,
        gid=CONTROLLER_GID,
        link_count=1,
        writable=False,
    )


def _plan(operation_id: str):
    baseline = make_empty_host_snapshot("snap-store-baseline", observed_generation=0)
    release = BoundedTreeManifest(
        purpose="release_final",
        root_path=RELEASE_FINAL_ROOT,
        root_mode=0o555,
        uid=CONTROLLER_UID,
        gid=CONTROLLER_GID,
        sealed=True,
        entries=(_entry("ollama", b"release"),),
    )
    model = BoundedTreeManifest(
        purpose="model_final",
        root_path=MODEL_FINAL_ROOT,
        root_mode=0o555,
        uid=CONTROLLER_UID,
        gid=CONTROLLER_GID,
        sealed=True,
        entries=(_entry("model.gguf", b"model"),),
    )
    return build_controller_plan(
        baseline,
        release,
        model,
        operation_id=operation_id,
    )


def _request(operation: OperationSnapshot, effect_id: str, *, phase: str = "apply"):
    return AuthorizationRequest.create(
        operation_id=operation.operation_id,
        plan_hash=operation.plan_hash,
        effect_id=effect_id,
        phase=phase,
        attempt=operation.next_attempt,
        expected_generation=operation.generation,
        expected_sequence=operation.sequence,
        expected_head_hash=operation.event_head_hash,
        ownership_token=operation.ownership_token,
    )


def _rejection(
    request: AuthorizationRequest,
    *,
    effect_hash: str,
    reason: str,
    settlement_event_id: int,
) -> AuthorizationRejection:
    return AuthorizationRejection.create(
        request,
        authority_id="studio-director-ollama-v2",
        mandate_id=f"mandate-{request.operation_id}-{request.phase}",
        decision_id=f"decision-{request.operation_id}-{request.phase}",
        slot_ordinal=0,
        effect_hash=effect_hash,
        reason=reason,
        settlement_event_id=settlement_event_id,
        settlement_event_hash=f"{settlement_event_id:x}" * 64,
    )


def _record_first_postcondition(
    store: OllamaV2ControllerStore,
    operation_id: str,
):
    plan = _plan(operation_id)
    operation = store.create_operation(
        OperationSnapshot.create(operation_id, plan),
        plan,
        idempotency_key=f"create-{operation_id}",
    ).snapshot
    effect = plan.effects[0]
    request = _request(operation, effect.effect_id)
    pending = store.record_authorization_pending(operation, request).snapshot
    claimed = store.record_authorization_claimed(pending, request).snapshot
    consumption = AuthorizationConsumption.create(
        request,
        authority_id="director-authority",
        decision_id=f"decision-{operation_id}",
    )
    consumed = store.record_authorization_consumed(
        claimed,
        request,
        consumption,
    ).snapshot
    dispatching = store.record_dispatching(
        consumed,
        request,
        consumption,
        plan.initial_snapshot,
    ).snapshot
    applied = project_effect(
        plan.initial_snapshot,
        plan,
        effect,
        operation.operation_id,
    )
    observed = store.record_effect_observation(
        dispatching,
        request,
        applied,
        outcome="postcondition",
    ).snapshot
    return plan, request, consumption, dispatching, observed, applied


def _record_first_rollback_terminal(
    store: OllamaV2ControllerStore,
    operation_id: str,
):
    plan, _request_value, _consumption, _dispatching, applied_operation, applied = (
        _record_first_postcondition(store, operation_id)
    )
    rollback = build_rollback_plan(
        applied_operation.operation_id,
        plan,
        applied_operation.applied_effect_ids,
    )
    rollback_pending = store.record_rollback_plan(
        applied_operation,
        rollback,
    ).snapshot
    effect = rollback.effects[0]
    request = _request(rollback_pending, effect.effect_id, phase="rollback")
    pending = store.record_authorization_pending(rollback_pending, request).snapshot
    claimed = store.record_authorization_claimed(pending, request).snapshot
    consumption = AuthorizationConsumption.create(
        request,
        authority_id="director-authority",
        decision_id=f"decision-{operation_id}-rollback",
    )
    consumed = store.record_authorization_consumed(
        claimed,
        request,
        consumption,
    ).snapshot
    dispatching = store.record_dispatching(
        consumed,
        request,
        consumption,
        applied,
    ).snapshot
    cleaned = project_effect(applied, plan, effect, operation_id)
    terminal = store.record_effect_observation(
        dispatching,
        request,
        cleaned,
        outcome="postcondition",
    ).snapshot
    return plan, terminal, cleaned


class DurableControllerStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="wf-ollama-v2-store-")
        self.database = Path(self.temp_dir.name) / "controller.sqlite3"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_exact_schema_create_reopen_and_duplicate_create_suppression(self) -> None:
        plan = _plan("op-store-create")
        initial = OperationSnapshot.create("op-store-create", plan)
        with OllamaV2ControllerStore(self.database) as store:
            created_result = store.create_operation(
                initial,
                plan,
                idempotency_key="create-key-0001",
            )
            duplicate_result = store.create_operation(
                initial,
                plan,
                idempotency_key="create-key-0001",
            )
            created = created_result.snapshot
            duplicate = duplicate_result.snapshot

            self.assertEqual(created, duplicate)
            self.assertTrue(created_result.committed_now)
            self.assertFalse(duplicate_result.committed_now)
            self.assertEqual(1, created.generation)
            self.assertEqual(1, created.sequence)
            self.assertNotEqual("0" * 64, created.event_head_hash)
            self.assertEqual(plan, store.load_plan(initial.operation_id))
            self.assertEqual(created, store.load_operation(initial.operation_id))
            census = store.schema_census()
            self.assertEqual(
                {
                    "controller_metadata",
                    "controller_operations",
                    "controller_events",
                    "controller_authorizations",
                    "controller_effect_attempts",
                    "controller_host_scope_leases",
                    "idx_controller_events_event_id",
                    "idx_controller_authorizations_effect_attempt",
                    "idx_controller_attempts_effect_attempt",
                },
                {name for _, name, _ in census},
            )

            with self.assertRaises(ControllerStoreDuplicateMismatch):
                store.create_operation(initial, plan, idempotency_key="different-key")

        with OllamaV2ControllerStore(self.database) as reopened:
            self.assertEqual(created, reopened.load_operation(initial.operation_id))
            events = reopened.event_documents(initial.operation_id)
            self.assertEqual(1, len(events))
            self.assertEqual("operation.created", events[0]["event_kind"])
            self.assertEqual(created.event_head_hash, events[0]["event_hash"])

    def test_fixed_host_scope_lease_rejects_a_distinct_active_operation(self) -> None:
        plan = _plan("op-lease-a")
        plan_b = _plan("op-lease-b")
        with OllamaV2ControllerStore(self.database) as store:
            operation_a = store.create_operation(
                OperationSnapshot.create("op-lease-a", plan),
                plan,
                idempotency_key="lease-a",
            ).snapshot
            self.assertEqual("apply_pending", operation_a.state)

            with self.assertRaisesRegex(
                ControllerStoreConflictError,
                "host_scope_lease_conflict",
            ):
                store.create_operation(
                    OperationSnapshot.create("op-lease-b", plan_b),
                    plan_b,
                    idempotency_key="lease-b",
                )

    def test_concurrent_distinct_operations_cannot_both_claim_fixed_host_scope(self) -> None:
        with OllamaV2ControllerStore(self.database):
            pass
        start = threading.Barrier(2)
        lock = threading.Lock()
        successes = []
        conflicts = []

        def worker(operation_id: str) -> None:
            try:
                plan = _plan(operation_id)
                initial = OperationSnapshot.create(operation_id, plan)
                with OllamaV2ControllerStore(self.database) as store:
                    start.wait(timeout=2)
                    result = store.create_operation(
                        initial,
                        plan,
                        idempotency_key=f"create-{operation_id}",
                    )
                    with lock:
                        successes.append(result.snapshot)
            except ControllerStoreConflictError as exc:
                with lock:
                    conflicts.append(exc)

        threads = [
            threading.Thread(target=worker, args=("op-lease-concurrent-a",)),
            threading.Thread(target=worker, args=("op-lease-concurrent-b",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(1, len(successes))
        self.assertEqual(1, len(conflicts))
        self.assertIn("host_scope_lease_conflict", str(conflicts[0]))

    def test_cas_hash_chain_and_exact_duplicate_authorization_transition(self) -> None:
        plan = _plan("op-store-cas")
        with OllamaV2ControllerStore(self.database) as store:
            operation = store.create_operation(
                OperationSnapshot.create("op-store-cas", plan),
                plan,
                idempotency_key="create-key-cas",
            ).snapshot
            request = _request(operation, plan.effects[0].effect_id)
            pending_result = store.record_authorization_pending(operation, request)
            duplicate_result = store.record_authorization_pending(operation, request)
            pending = pending_result.snapshot
            duplicate = duplicate_result.snapshot

            self.assertTrue(pending_result.committed_now)
            self.assertFalse(duplicate_result.committed_now)
            self.assertEqual(pending, duplicate)
            self.assertEqual("apply_authorization_pending", pending.state)
            self.assertEqual(operation.sequence + 1, pending.sequence)
            self.assertEqual(
                operation.event_head_hash,
                store.event_documents(operation.operation_id)[1]["previous_hash"],
            )

            stale = dataclasses.replace(
                operation,
                state="recovery_required",
                recovery_reason="stale-state",
            )
            with self.assertRaises(ControllerStoreConflictError):
                store.record_authorization_pending(stale, request)

            mismatched = dataclasses.replace(request, effect_id="effect-foreign")
            with self.assertRaises(ControllerStoreDuplicateMismatch):
                store.record_authorization_pending(operation, mismatched)

    def test_authorization_consumption_dispatch_and_observation_are_each_durable(self) -> None:
        plan = _plan("op-store-attempt")
        effect = plan.effects[0]
        with OllamaV2ControllerStore(self.database) as store:
            operation = store.create_operation(
                OperationSnapshot.create("op-store-attempt", plan),
                plan,
                idempotency_key="create-key-attempt",
            ).snapshot
            request = _request(operation, effect.effect_id)
            pending_result = store.record_authorization_pending(operation, request)
            pending = pending_result.snapshot
            claimed_result = store.record_authorization_claimed(pending, request)
            claimed_duplicate = store.record_authorization_claimed(pending, request)
            claimed = claimed_result.snapshot
            consumption = AuthorizationConsumption.create(
                request,
                authority_id="director-authority",
                decision_id="decision-attempt",
            )
            consumed_result = store.record_authorization_consumed(
                claimed,
                request,
                consumption,
            )
            consumed_duplicate = store.record_authorization_consumed(
                claimed,
                request,
                consumption,
            )
            consumed = consumed_result.snapshot
            dispatching_result = store.record_dispatching(
                consumed,
                request,
                consumption,
                plan.initial_snapshot,
            )
            dispatching_duplicate = store.record_dispatching(
                consumed,
                request,
                consumption,
                plan.initial_snapshot,
            )
            dispatching = dispatching_result.snapshot
            applied_snapshot = project_effect(
                plan.initial_snapshot,
                plan,
                effect,
                operation.operation_id,
            )
            observed_result = store.record_effect_observation(
                dispatching,
                request,
                applied_snapshot,
                outcome="postcondition",
            )
            observed_duplicate = store.record_effect_observation(
                dispatching,
                request,
                applied_snapshot,
                outcome="postcondition",
            )
            observed = observed_result.snapshot

            self.assertTrue(pending_result.committed_now)
            self.assertTrue(claimed_result.committed_now)
            self.assertFalse(claimed_duplicate.committed_now)
            self.assertTrue(consumed_result.committed_now)
            self.assertFalse(consumed_duplicate.committed_now)
            self.assertTrue(dispatching_result.committed_now)
            self.assertFalse(dispatching_duplicate.committed_now)
            self.assertTrue(observed_result.committed_now)
            self.assertFalse(observed_duplicate.committed_now)

            self.assertEqual("apply_pending", observed.state)
            self.assertEqual(1, observed.apply_cursor)
            self.assertEqual((effect.effect_id,), observed.applied_effect_ids)
            self.assertEqual(2, observed.next_attempt)
            self.assertEqual(applied_snapshot.content_hash, observed.last_host_snapshot_hash)
            self.assertIsNone(observed.current_authorization_hash)
            self.assertEqual(6, observed.sequence)
            self.assertEqual(
                consumption,
                store.load_authorization_consumption(request.authorization_id),
            )
            attempt = store.effect_attempt_document(dispatching.current_attempt_id)
            self.assertEqual("postcondition", attempt["outcome"])
            self.assertEqual(applied_snapshot.to_document(), attempt["after_snapshot"])

    def test_apply_authorization_rejection_is_terminal_durable_and_schema_v1(self) -> None:
        plan = _plan("op-store-apply-rejected")
        effect = plan.effects[0]
        with OllamaV2ControllerStore(self.database) as store:
            operation = store.create_operation(
                OperationSnapshot.create(plan.operation_id, plan),
                plan,
                idempotency_key="create-store-apply-rejected",
            ).snapshot
            request = _request(operation, effect.effect_id)
            pending = store.record_authorization_pending(operation, request).snapshot
            claimed = store.record_authorization_claimed(pending, request).snapshot
            rejection = _rejection(
                request,
                effect_hash=effect.content_hash,
                reason="denied",
                settlement_event_id=1,
            )

            rejected_result = store.record_authorization_rejected(
                claimed,
                request,
                rejection,
            )
            duplicate_result = store.record_authorization_rejected(
                claimed,
                request,
                rejection,
            )
            rejected = rejected_result.snapshot

            self.assertTrue(rejected_result.committed_now)
            self.assertFalse(duplicate_result.committed_now)
            self.assertEqual(rejected, duplicate_result.snapshot)
            self.assertEqual("recovery_required", rejected.state)
            self.assertEqual("authorization_denied", rejected.recovery_reason)
            self.assertIsNone(rejected.current_effect_id)
            self.assertIsNone(rejected.current_authorization_hash)
            self.assertEqual(operation.next_attempt, rejected.next_attempt)
            self.assertEqual(
                0,
                store._connection.execute(
                    "SELECT COUNT(*) FROM controller_effect_attempts WHERE operation_id=?",
                    (operation.operation_id,),
                ).fetchone()[0],
            )
            self.assertIsNone(store.load_authorization_consumption(request.authorization_id))
            events = store.event_documents(operation.operation_id)
            self.assertEqual(
                (
                    "operation.created",
                    "authorization.pending",
                    "authorization.claimed",
                    "authorization.rejected",
                ),
                tuple(event["event_kind"] for event in events),
            )
            self.assertEqual(rejection.content_hash, events[-1]["bindings"]["rejection_hash"])
            row = store._connection.execute(
                "SELECT state, consumption_json FROM controller_authorizations "
                "WHERE authorization_id=?",
                (request.authorization_id,),
            ).fetchone()
            self.assertEqual("consumed", row["state"])
            self.assertEqual(
                rejection,
                AuthorizationRejection.from_document(json.loads(row["consumption_json"])),
            )
            self.assertEqual(1, store._connection.execute("PRAGMA user_version").fetchone()[0])

        with OllamaV2ControllerStore(self.database) as reopened:
            self.assertEqual(rejected, reopened.load_operation(operation.operation_id))
            self.assertEqual(
                "authorization.rejected",
                reopened.event_documents(operation.operation_id)[-1]["event_kind"],
            )

    def test_rollback_authorization_rejection_preserves_exact_replay(self) -> None:
        with OllamaV2ControllerStore(self.database) as store:
            plan, _request_value, _consumption, _dispatching, applied, _snapshot = (
                _record_first_postcondition(store, "op-store-rollback-rejected")
            )
            rollback = build_rollback_plan(
                applied.operation_id,
                plan,
                applied.applied_effect_ids,
            )
            rollback_pending = store.record_rollback_plan(applied, rollback).snapshot
            effect = rollback.effects[0]
            request = _request(rollback_pending, effect.effect_id, phase="rollback")
            pending = store.record_authorization_pending(rollback_pending, request).snapshot
            claimed = store.record_authorization_claimed(pending, request).snapshot
            rejection = _rejection(
                request,
                effect_hash=effect.content_hash,
                reason="revoked",
                settlement_event_id=2,
            )

            rejected = store.record_authorization_rejected(
                claimed,
                request,
                rejection,
            ).snapshot

            self.assertEqual("recovery_required", rejected.state)
            self.assertEqual("authorization_revoked", rejected.recovery_reason)
            self.assertEqual(0, rejected.rollback_cursor)
            self.assertEqual(1, rejected.apply_cursor)
            self.assertEqual(rollback.content_hash, rejected.rollback_plan_hash)

        with OllamaV2ControllerStore(self.database) as reopened:
            self.assertEqual(rejected, reopened.load_operation(applied.operation_id))
            events = reopened.event_documents(applied.operation_id)
            self.assertEqual("authorization.rejected", events[-1]["event_kind"])
            self.assertEqual("rollback", events[-1]["bindings"]["phase"])
            self.assertEqual(rejection.effect_hash, events[-1]["bindings"]["effect_hash"])

    def test_live_claimed_recovery_is_forbidden_but_legacy_history_reopens(self) -> None:
        plan = _plan("op-store-claimed-recovery")
        with OllamaV2ControllerStore(self.database) as store:
            operation = store.create_operation(
                OperationSnapshot.create(plan.operation_id, plan),
                plan,
                idempotency_key="create-store-claimed-recovery",
            ).snapshot
            request = _request(operation, plan.effects[0].effect_id)
            pending = store.record_authorization_pending(operation, request).snapshot
            claimed = store.record_authorization_claimed(pending, request).snapshot

            with self.assertRaisesRegex(
                ControllerStoreConflictError,
                "recovery_source_state_invalid",
            ):
                store.record_recovery(
                    claimed,
                    reason="authorization_outcome_indeterminate",
                    observed_snapshot=None,
                )
            self.assertEqual(claimed, store.load_operation(operation.operation_id))

            reason = "authorization_outcome_indeterminate"
            identity = hashlib.sha256(
                canonical_controller_bytes(
                    {
                        "reason": reason,
                        "expected_head_hash": claimed.event_head_hash,
                        "snapshot_hash": None,
                    }
                )
            ).hexdigest()

            def legacy_mutation(snapshot: OperationSnapshot) -> OperationSnapshot:
                return dataclasses.replace(
                    snapshot,
                    state="recovery_required",
                    recovery_reason=reason,
                    current_effect_id=None,
                    current_authorization_hash=None,
                    current_attempt_id=None,
                )

            legacy = store._append_transition(
                claimed,
                event_kind="operation.recovery_required",
                identity=identity,
                bindings={
                    "reason": reason,
                    "observed_snapshot_hash": None,
                    "observed_projection_hash": None,
                },
                mutation=legacy_mutation,
            ).snapshot
            self.assertEqual("recovery_required", legacy.state)

        with OllamaV2ControllerStore(self.database) as reopened:
            self.assertEqual(legacy, reopened.load_operation(operation.operation_id))
            self.assertEqual(
                (
                    "operation.created",
                    "authorization.pending",
                    "authorization.claimed",
                    "operation.recovery_required",
                ),
                tuple(
                    event["event_kind"]
                    for event in reopened.event_documents(operation.operation_id)
                ),
            )

    def test_precondition_retry_uses_new_attempt_and_foreign_observation_requires_recovery(
        self,
    ) -> None:
        plan = _plan("op-store-outcomes")
        effect = plan.effects[0]
        with OllamaV2ControllerStore(self.database) as store:
            operation = store.create_operation(
                OperationSnapshot.create("op-store-outcomes", plan),
                plan,
                idempotency_key="create-key-outcomes",
            ).snapshot
            request = _request(operation, effect.effect_id)
            pending = store.record_authorization_pending(operation, request).snapshot
            claimed = store.record_authorization_claimed(pending, request).snapshot
            consumption = AuthorizationConsumption.create(
                request,
                authority_id="director-authority",
                decision_id="decision-no-effect",
            )
            consumed = store.record_authorization_consumed(
                claimed,
                request,
                consumption,
            ).snapshot
            dispatching = store.record_dispatching(
                consumed,
                request,
                consumption,
                plan.initial_snapshot,
            ).snapshot
            no_effect = store.record_effect_observation(
                dispatching,
                request,
                plan.initial_snapshot,
                outcome="precondition",
            ).snapshot
            retry = _request(no_effect, effect.effect_id)

            self.assertNotEqual(request.authorization_id, retry.authorization_id)
            self.assertEqual(2, retry.attempt)
            self.assertEqual(0, no_effect.apply_cursor)
            self.assertEqual("apply_pending", no_effect.state)

            pending = store.record_authorization_pending(no_effect, retry).snapshot
            claimed = store.record_authorization_claimed(pending, retry).snapshot
            consumption = AuthorizationConsumption.create(
                retry,
                authority_id="director-authority",
                decision_id="decision-foreign",
            )
            consumed = store.record_authorization_consumed(
                claimed,
                retry,
                consumption,
            ).snapshot
            dispatching = store.record_dispatching(
                consumed,
                retry,
                consumption,
                plan.initial_snapshot,
            ).snapshot
            foreign_root = dataclasses.replace(
                project_effect(
                    plan.initial_snapshot,
                    plan,
                    effect,
                    operation.operation_id,
                ).managed_root,
                root_mode=0o700,
            )
            foreign = dataclasses.replace(
                plan.initial_snapshot,
                snapshot_id="snap-store-foreign",
                managed_root=foreign_root,
            )
            recovery = store.record_effect_observation(
                dispatching,
                retry,
                foreign,
                outcome="foreign",
            ).snapshot
            self.assertEqual("recovery_required", recovery.state)
            self.assertEqual("host_state_foreign", recovery.recovery_reason)
            self.assertEqual(0, recovery.apply_cursor)

    def test_commit_exception_accepts_exact_post_and_rejects_exact_pre_without_guessing(
        self,
    ) -> None:
        plan = _plan("op-store-commit")
        initial = OperationSnapshot.create("op-store-commit", plan)
        store = OllamaV2ControllerStore(self.database)
        original_commit = OllamaV2ControllerStore._commit
        calls = 0

        def committed_then_raise(instance: OllamaV2ControllerStore) -> None:
            nonlocal calls
            calls += 1
            original_commit(instance)
            if calls == 1:
                raise sqlite3.OperationalError("lost commit reply")

        with mock.patch.object(OllamaV2ControllerStore, "_commit", committed_then_raise):
            created_result = store.create_operation(
                initial,
                plan,
                idempotency_key="commit-post",
            )
            created = created_result.snapshot
        self.assertFalse(created_result.committed_now)
        self.assertEqual(1, created.sequence)
        self.assertEqual(created, store.load_operation(initial.operation_id))

        operation = created
        request = _request(operation, plan.effects[0].effect_id)

        def raise_before_commit(instance: OllamaV2ControllerStore) -> None:
            raise sqlite3.OperationalError("commit not attempted")

        with mock.patch.object(OllamaV2ControllerStore, "_commit", raise_before_commit):
            with self.assertRaises(ControllerStoreCommitNotApplied):
                store.record_authorization_pending(operation, request)
        self.assertEqual(operation, store.load_operation(operation.operation_id))
        store.close()

    def test_record_recovery_reconciles_exact_pre_and_post_commit_states(self) -> None:
        plan = _plan("op-store-recovery-boundaries")
        store = OllamaV2ControllerStore(self.database)
        created = store.create_operation(
            OperationSnapshot.create("op-store-recovery-boundaries", plan),
            plan,
            idempotency_key="recovery-boundaries-create",
        ).snapshot
        before_events = store.event_documents(created.operation_id)
        before_lease = tuple(
            store._connection.execute(
                "SELECT * FROM controller_host_scope_leases WHERE operation_id = ?",
                (created.operation_id,),
            ).fetchone()
        )

        def raise_before_commit(_instance: OllamaV2ControllerStore) -> None:
            raise sqlite3.OperationalError("recovery commit not attempted")

        with mock.patch.object(OllamaV2ControllerStore, "_commit", raise_before_commit):
            with self.assertRaises(ControllerStoreCommitNotApplied):
                store.record_recovery(
                    created,
                    reason="host_state_foreign",
                    observed_snapshot=plan.initial_snapshot,
                )
        self.assertEqual(created, store.load_operation(created.operation_id))
        self.assertEqual(before_events, store.event_documents(created.operation_id))
        self.assertEqual(
            before_lease,
            tuple(
                store._connection.execute(
                    "SELECT * FROM controller_host_scope_leases WHERE operation_id = ?",
                    (created.operation_id,),
                ).fetchone()
            ),
        )

        original_commit = OllamaV2ControllerStore._commit
        commit_calls = 0

        def commit_then_lose_reply(instance: OllamaV2ControllerStore) -> None:
            nonlocal commit_calls
            commit_calls += 1
            original_commit(instance)
            raise sqlite3.OperationalError("lost recovery commit reply")

        with mock.patch.object(
            OllamaV2ControllerStore,
            "_commit",
            commit_then_lose_reply,
        ):
            recovered_result = store.record_recovery(
                created,
                reason="host_state_foreign",
                observed_snapshot=plan.initial_snapshot,
            )
        recovered = recovered_result.snapshot
        duplicate = store.record_recovery(
            created,
            reason="host_state_foreign",
            observed_snapshot=plan.initial_snapshot,
        )

        self.assertEqual(1, commit_calls)
        self.assertFalse(recovered_result.committed_now)
        self.assertFalse(duplicate.committed_now)
        self.assertEqual(recovered, duplicate.snapshot)
        self.assertEqual(created.generation + 1, recovered.generation)
        self.assertEqual(created.sequence + 1, recovered.sequence)
        self.assertEqual(2, len(store.event_documents(created.operation_id)))
        store.close()

        with OllamaV2ControllerStore(self.database) as reopened:
            self.assertEqual(recovered, reopened.load_operation(recovered.operation_id))
            self.assertEqual(2, len(reopened.event_documents(recovered.operation_id)))

    def test_rolled_back_clean_rejects_every_reversible_store_entrypoint(self) -> None:
        with OllamaV2ControllerStore(self.database) as store:
            plan, terminal, cleaned = _record_first_rollback_terminal(
                store,
                "op-store-terminal-immutable",
            )
            before_events = store.event_documents(terminal.operation_id)
            self.assertIsNone(
                store._connection.execute(
                    "SELECT operation_id FROM controller_host_scope_leases "
                    "WHERE operation_id = ?",
                    (terminal.operation_id,),
                ).fetchone()
            )

            with self.assertRaisesRegex(
                ControllerStoreConflictError,
                "recovery_source_state_invalid",
            ):
                store.record_recovery(
                    terminal,
                    reason="host_state_foreign",
                    observed_snapshot=cleaned,
                )
            with self.assertRaisesRegex(
                ControllerStoreConflictError,
                "rollback_plan_state_mismatch",
            ):
                store.record_rollback_plan(
                    terminal,
                    build_rollback_plan(
                        terminal.operation_id,
                        plan,
                        terminal.applied_effect_ids,
                    ),
                )
            with self.assertRaisesRegex(
                ControllerStoreConflictError,
                "authorization_state_mismatch",
            ):
                store.record_authorization_pending(
                    terminal,
                    _request(terminal, plan.effects[terminal.apply_cursor].effect_id),
                )

            self.assertEqual(terminal, store.load_operation(terminal.operation_id))
            self.assertEqual(before_events, store.event_documents(terminal.operation_id))
            self.assertIsNone(
                store._connection.execute(
                    "SELECT operation_id FROM controller_host_scope_leases "
                    "WHERE operation_id = ?",
                    (terminal.operation_id,),
                ).fetchone()
            )
            next_plan = _plan("op-store-terminal-next-owner")
            next_operation = store.create_operation(
                OperationSnapshot.create("op-store-terminal-next-owner", next_plan),
                next_plan,
                idempotency_key="terminal-next-owner-create",
            ).snapshot
            self.assertEqual("apply_pending", next_operation.state)

    def test_reopen_rejects_terminal_source_recovery_even_with_repaired_lease(self) -> None:
        with OllamaV2ControllerStore(self.database) as store:
            plan, terminal, cleaned = _record_first_rollback_terminal(
                store,
                "op-store-terminal-recovery-tamper",
            )
            reason = "host_state_foreign"
            identity = hashlib.sha256(
                canonical_controller_bytes(
                    {
                        "reason": reason,
                        "expected_head_hash": terminal.event_head_hash,
                        "snapshot_hash": cleaned.content_hash,
                    }
                )
            ).hexdigest()

            def mutation(snapshot: OperationSnapshot) -> OperationSnapshot:
                return dataclasses.replace(
                    snapshot,
                    state="recovery_required",
                    recovery_reason=reason,
                    last_host_snapshot_hash=cleaned.content_hash,
                )

            def restore_lease(
                connection: sqlite3.Connection,
                _after: OperationSnapshot,
            ) -> None:
                connection.execute(
                    "INSERT INTO controller_host_scope_leases("
                    "scope_id, operation_id, ownership_token, acquired_sequence, state"
                    ") VALUES ('ollama_v2_fixed_host_scope', ?, ?, 1, 'active')",
                    (terminal.operation_id, terminal.ownership_token),
                )

            store._append_transition(
                terminal,
                event_kind="operation.recovery_required",
                identity=identity,
                bindings={
                    "reason": reason,
                    "observed_snapshot_hash": cleaned.content_hash,
                    "observed_projection_hash": host_projection_hash(cleaned),
                },
                mutation=mutation,
                auxiliary=restore_lease,
            )

        with self.assertRaisesRegex(
            ControllerStoreCorruptionError,
            "recovery_event_source_state_invalid",
        ):
            OllamaV2ControllerStore(self.database)

    def test_reopen_rejects_orphan_and_altered_recovery_events(self) -> None:
        orphan_database = Path(self.temp_dir.name) / "orphan-recovery.sqlite3"
        orphan_plan = _plan("op-store-orphan-recovery")
        with OllamaV2ControllerStore(orphan_database) as store:
            created = store.create_operation(
                OperationSnapshot.create("op-store-orphan-recovery", orphan_plan),
                orphan_plan,
                idempotency_key="orphan-recovery-create",
            ).snapshot
            store.record_recovery(
                created,
                reason="host_state_foreign",
                observed_snapshot=orphan_plan.initial_snapshot,
            )
        connection = sqlite3.connect(orphan_database)
        connection.execute(
            "UPDATE controller_operations SET snapshot_json = ?, generation = ?, "
            "sequence = ?, head_hash = ?, state = ? WHERE operation_id = ?",
            (
                canonical_controller_bytes(created.to_document()),
                created.generation,
                created.sequence,
                created.event_head_hash,
                created.state,
                created.operation_id,
            ),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(ControllerStoreCorruptionError):
            OllamaV2ControllerStore(orphan_database)

        altered_database = Path(self.temp_dir.name) / "altered-recovery.sqlite3"
        altered_plan = _plan("op-store-altered-recovery")
        with OllamaV2ControllerStore(altered_database) as store:
            created = store.create_operation(
                OperationSnapshot.create("op-store-altered-recovery", altered_plan),
                altered_plan,
                idempotency_key="altered-recovery-create",
            ).snapshot
            store.record_recovery(
                created,
                reason="host_state_foreign",
                observed_snapshot=altered_plan.initial_snapshot,
            )
        connection = sqlite3.connect(altered_database)
        event_bytes = connection.execute(
            "SELECT event_json FROM controller_events WHERE operation_id = ? AND sequence = 2",
            (created.operation_id,),
        ).fetchone()[0]
        event = json.loads(event_bytes.decode("utf-8"))
        event["bindings"]["reason"] = "host_state_changed"
        connection.execute(
            "UPDATE controller_events SET event_json = ? "
            "WHERE operation_id = ? AND sequence = 2",
            (canonical_controller_bytes(event), created.operation_id),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(ControllerStoreCorruptionError):
            OllamaV2ControllerStore(altered_database)

    def test_commit_exception_with_neither_exact_state_poisons_operation(self) -> None:
        plan = _plan("op-store-poison")
        store = OllamaV2ControllerStore(self.database)
        created = store.create_operation(
            OperationSnapshot.create("op-store-poison", plan),
            plan,
            idempotency_key="poison-create",
        ).snapshot
        request = _request(created, plan.effects[0].effect_id)

        def commit_mutate_then_raise(instance: OllamaV2ControllerStore) -> None:
            instance._connection.execute("COMMIT")
            instance._connection.execute("BEGIN IMMEDIATE")
            instance._connection.execute(
                "UPDATE controller_operations SET generation = generation + 100 "
                "WHERE operation_id = ?",
                (created.operation_id,),
            )
            instance._connection.execute("COMMIT")
            raise sqlite3.OperationalError("foreign post-commit mutation")

        with mock.patch.object(OllamaV2ControllerStore, "_commit", commit_mutate_then_raise):
            with self.assertRaises(ControllerStoreRecoveryRequired):
                store.record_authorization_pending(created, request)
        with self.assertRaises(ControllerStoreRecoveryRequired):
            store.load_operation(created.operation_id)
        store.close()

    def test_commit_exception_rejects_pre_snapshot_with_foreign_related_row(self) -> None:
        plan = _plan("op-store-related-poison")
        store = OllamaV2ControllerStore(self.database)
        created = store.create_operation(
            OperationSnapshot.create("op-store-related-poison", plan),
            plan,
            idempotency_key="related-poison-create",
        ).snapshot
        request = _request(created, plan.effects[0].effect_id)

        def rollback_insert_related_then_raise(instance: OllamaV2ControllerStore) -> None:
            instance._connection.execute("ROLLBACK")
            instance._connection.execute("BEGIN IMMEDIATE")
            instance._connection.execute(
                "INSERT INTO controller_authorizations("
                "authorization_id, operation_id, phase, effect_id, attempt, request_json, "
                "consumption_json, state) VALUES (?, ?, ?, ?, ?, ?, NULL, 'pending')",
                (
                    request.authorization_id,
                    request.operation_id,
                    request.phase,
                    request.effect_id,
                    request.attempt,
                    canonical_controller_bytes(request.to_document()),
                ),
            )
            instance._connection.execute("COMMIT")
            raise sqlite3.OperationalError("foreign related-row commit")

        with mock.patch.object(
            OllamaV2ControllerStore,
            "_commit",
            rollback_insert_related_then_raise,
        ):
            with self.assertRaises(ControllerStoreRecoveryRequired):
                store.record_authorization_pending(created, request)
        with self.assertRaises(ControllerStoreRecoveryRequired):
            store.load_operation(created.operation_id)
        store.close()

    def test_every_durable_boundary_reconciles_a_lost_exact_post_commit_reply(self) -> None:
        plan = _plan("op-store-all-boundaries")
        store = OllamaV2ControllerStore(self.database)
        original_commit = OllamaV2ControllerStore._commit

        def commit_then_lose_reply(instance: OllamaV2ControllerStore) -> None:
            original_commit(instance)
            raise sqlite3.OperationalError("lost exact post-commit reply")

        initial = OperationSnapshot.create("op-store-all-boundaries", plan)
        with mock.patch.object(OllamaV2ControllerStore, "_commit", commit_then_lose_reply):
            create_result = store.create_operation(
                initial,
                plan,
                idempotency_key="all-boundaries-create",
            )
            operation = create_result.snapshot
        request = _request(operation, plan.effects[0].effect_id)
        with mock.patch.object(OllamaV2ControllerStore, "_commit", commit_then_lose_reply):
            pending_result = store.record_authorization_pending(operation, request)
            pending = pending_result.snapshot
        with mock.patch.object(OllamaV2ControllerStore, "_commit", commit_then_lose_reply):
            claimed_result = store.record_authorization_claimed(pending, request)
            claimed = claimed_result.snapshot
        consumption = AuthorizationConsumption.create(
            request,
            authority_id="director-authority",
            decision_id="decision-all-boundaries",
        )
        with mock.patch.object(OllamaV2ControllerStore, "_commit", commit_then_lose_reply):
            consumed_result = store.record_authorization_consumed(
                claimed,
                request,
                consumption,
            )
            consumed = consumed_result.snapshot
        with mock.patch.object(OllamaV2ControllerStore, "_commit", commit_then_lose_reply):
            dispatching_result = store.record_dispatching(
                consumed,
                request,
                consumption,
                plan.initial_snapshot,
            )
            dispatching = dispatching_result.snapshot
        applied = project_effect(
            plan.initial_snapshot,
            plan,
            plan.effects[0],
            operation.operation_id,
        )
        with mock.patch.object(OllamaV2ControllerStore, "_commit", commit_then_lose_reply):
            observed_result = store.record_effect_observation(
                dispatching,
                request,
                applied,
                outcome="postcondition",
            )
            observed = observed_result.snapshot
        rollback = build_rollback_plan(
            observed.operation_id,
            plan,
            observed.applied_effect_ids,
        )
        with mock.patch.object(OllamaV2ControllerStore, "_commit", commit_then_lose_reply):
            rollback_result = store.record_rollback_plan(observed, rollback)
        rollback_duplicate = store.record_rollback_plan(observed, rollback)
        rollback_pending = rollback_result.snapshot

        for boundary, result in {
            "create": create_result,
            "authorization.pending": pending_result,
            "authorization.claimed": claimed_result,
            "authorization.consumed": consumed_result,
            "effect.dispatching": dispatching_result,
            "effect.observed": observed_result,
            "rollback.prepared": rollback_result,
        }.items():
            with self.subTest(boundary=boundary):
                self.assertFalse(result.committed_now)
        self.assertFalse(rollback_duplicate.committed_now)
        self.assertEqual(rollback_pending, rollback_duplicate.snapshot)
        self.assertEqual("rollback_pending", rollback_pending.state)
        self.assertEqual(7, rollback_pending.sequence)
        self.assertEqual(7, len(store.event_documents(operation.operation_id)))
        store.close()

        with OllamaV2ControllerStore(self.database) as reopened:
            self.assertEqual(
                rollback_pending,
                reopened.load_operation(operation.operation_id),
            )
            self.assertEqual(7, len(reopened.event_documents(operation.operation_id)))

    def test_reopen_rejects_missing_inflight_authorization_binding(self) -> None:
        plan = _plan("op-store-missing-auth")
        with OllamaV2ControllerStore(self.database) as store:
            operation = store.create_operation(
                OperationSnapshot.create("op-store-missing-auth", plan),
                plan,
                idempotency_key="missing-auth-create",
            ).snapshot
            request = _request(operation, plan.effects[0].effect_id)
            pending = store.record_authorization_pending(operation, request).snapshot
            self.assertEqual("apply_authorization_pending", pending.state)

        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "DELETE FROM controller_authorizations WHERE authorization_id = ?",
            (request.authorization_id,),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(ControllerStoreCorruptionError):
            OllamaV2ControllerStore(self.database)

    def test_reopen_rejects_orphan_pending_authorization_without_event(self) -> None:
        plan = _plan("op-store-orphan-auth")
        with OllamaV2ControllerStore(self.database) as store:
            operation = store.create_operation(
                OperationSnapshot.create("op-store-orphan-auth", plan),
                plan,
                idempotency_key="orphan-auth-create",
            ).snapshot
            request = _request(operation, plan.effects[0].effect_id)

        connection = sqlite3.connect(self.database)
        connection.execute(
            "INSERT INTO controller_authorizations("
            "authorization_id, operation_id, phase, effect_id, attempt, request_json, "
            "consumption_json, state) VALUES (?, ?, ?, ?, ?, ?, NULL, 'pending')",
            (
                request.authorization_id,
                request.operation_id,
                request.phase,
                request.effect_id,
                request.attempt,
                canonical_controller_bytes(request.to_document()),
            ),
        )
        connection.commit()
        connection.close()

        with self.assertRaises(ControllerStoreCorruptionError):
            OllamaV2ControllerStore(self.database)

    def test_reopen_rejects_altered_consumed_decision_provenance(self) -> None:
        plan = _plan("op-store-consumption-provenance")
        with OllamaV2ControllerStore(self.database) as store:
            operation = store.create_operation(
                OperationSnapshot.create("op-store-consumption-provenance", plan),
                plan,
                idempotency_key="consumption-provenance-create",
            ).snapshot
            request = _request(operation, plan.effects[0].effect_id)
            pending = store.record_authorization_pending(operation, request).snapshot
            claimed = store.record_authorization_claimed(pending, request).snapshot
            original = AuthorizationConsumption.create(
                request,
                authority_id="director-authority",
                decision_id="decision-original",
            )
            consumed = store.record_authorization_consumed(
                claimed,
                request,
                original,
            ).snapshot
            self.assertEqual("apply_authorization_consumed", consumed.state)

        altered = AuthorizationConsumption.create(
            request,
            authority_id="director-authority",
            decision_id="decision-altered",
        )
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE controller_authorizations SET consumption_json = ? "
            "WHERE authorization_id = ?",
            (
                canonical_controller_bytes(altered.to_document()),
                request.authorization_id,
            ),
        )
        connection.commit()
        connection.close()

        with self.assertRaises(ControllerStoreCorruptionError):
            OllamaV2ControllerStore(self.database)

    def test_reopen_rejects_postcondition_attempt_rewritten_to_pre_snapshot(self) -> None:
        with OllamaV2ControllerStore(self.database) as store:
            _plan_value, _request_value, _consumption, dispatching, _observed, _applied = (
                _record_first_postcondition(store, "op-store-attempt-rewrite")
            )
            attempt_id = dispatching.current_attempt_id

        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE controller_effect_attempts "
            "SET after_snapshot_json = before_snapshot_json WHERE attempt_id = ?",
            (attempt_id,),
        )
        connection.commit()
        connection.close()

        with self.assertRaises(ControllerStoreCorruptionError):
            OllamaV2ControllerStore(self.database)

    def test_reopen_rejects_missing_completed_authorization_and_attempt_rows(self) -> None:
        with OllamaV2ControllerStore(self.database) as store:
            _plan_value, request, _consumption, dispatching, _observed, _applied = (
                _record_first_postcondition(store, "op-store-missing-completed-rows")
            )

        connection = sqlite3.connect(self.database)
        connection.execute(
            "DELETE FROM controller_effect_attempts WHERE attempt_id = ?",
            (dispatching.current_attempt_id,),
        )
        connection.execute(
            "DELETE FROM controller_authorizations WHERE authorization_id = ?",
            (request.authorization_id,),
        )
        connection.commit()
        connection.close()

        with self.assertRaises(ControllerStoreCorruptionError):
            OllamaV2ControllerStore(self.database)

    def test_reopen_rejects_extra_attempt_row_without_transition_event(self) -> None:
        with OllamaV2ControllerStore(self.database) as store:
            plan, request, _consumption, _dispatching, observed, _applied = (
                _record_first_postcondition(store, "op-store-extra-attempt")
            )

        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "INSERT INTO controller_effect_attempts("
            "attempt_id, operation_id, phase, effect_id, attempt, authorization_id, "
            "request_hash, before_snapshot_json, after_snapshot_json, outcome, "
            "dispatch_sequence, observation_sequence) "
            "VALUES (?, ?, 'apply', ?, 2, ?, ?, ?, NULL, 'dispatching', ?, NULL)",
            (
                "attempt-extra-without-event",
                observed.operation_id,
                plan.effects[0].effect_id,
                request.authorization_id,
                request.content_hash,
                canonical_controller_bytes(plan.initial_snapshot.to_document()),
                observed.sequence + 1,
            ),
        )
        connection.commit()
        connection.close()

        with self.assertRaises(ControllerStoreCorruptionError):
            OllamaV2ControllerStore(self.database)

    def test_event_payloads_bind_exact_authorization_and_attempt_documents(self) -> None:
        with OllamaV2ControllerStore(self.database) as store:
            plan, request, consumption, dispatching, observed, applied = (
                _record_first_postcondition(store, "op-store-event-bindings")
            )
            events = store.event_documents(observed.operation_id)

        self.assertEqual(plan.content_hash, events[0]["bindings"]["plan_hash"])
        self.assertEqual(request.content_hash, events[1]["bindings"]["request_hash"])
        self.assertEqual(
            consumption.content_hash,
            events[3]["bindings"]["consumption_hash"],
        )
        self.assertEqual(
            dispatching.current_attempt_id,
            events[4]["bindings"]["attempt_id"],
        )
        self.assertEqual(
            applied.content_hash,
            events[5]["bindings"]["after_snapshot_hash"],
        )

    def test_reopen_semantically_replays_complete_apply_and_rollback_history(self) -> None:
        with OllamaV2ControllerStore(self.database) as store:
            plan, _request_value, _consumption, _dispatching, applied_operation, applied = (
                _record_first_postcondition(store, "op-store-replay-rollback")
            )
            rollback = build_rollback_plan(
                applied_operation.operation_id,
                plan,
                applied_operation.applied_effect_ids,
            )
            rollback_pending = store.record_rollback_plan(
                applied_operation,
                rollback,
            ).snapshot
            effect = rollback.effects[0]
            request = _request(
                rollback_pending,
                effect.effect_id,
                phase="rollback",
            )
            pending = store.record_authorization_pending(
                rollback_pending,
                request,
            ).snapshot
            claimed = store.record_authorization_claimed(pending, request).snapshot
            consumption = AuthorizationConsumption.create(
                request,
                authority_id="director-authority",
                decision_id="decision-replay-rollback",
            )
            consumed = store.record_authorization_consumed(
                claimed,
                request,
                consumption,
            ).snapshot
            dispatching = store.record_dispatching(
                consumed,
                request,
                consumption,
                applied,
            ).snapshot
            cleaned = project_effect(
                applied,
                plan,
                effect,
                applied_operation.operation_id,
            )
            terminal = store.record_effect_observation(
                dispatching,
                request,
                cleaned,
                outcome="postcondition",
            ).snapshot
            self.assertEqual("rolled_back_clean", terminal.state)

        with OllamaV2ControllerStore(self.database) as reopened:
            self.assertEqual(terminal, reopened.load_operation(terminal.operation_id))
            self.assertEqual(12, len(reopened.event_documents(terminal.operation_id)))

    def test_reopen_rejects_attempt_after_projection_with_foreign_ownership(self) -> None:
        with OllamaV2ControllerStore(self.database) as store:
            _plan_value, _request_value, _consumption, dispatching, _observed, applied = (
                _record_first_postcondition(store, "op-store-foreign-attempt-owner")
            )
            attempt_id = dispatching.current_attempt_id

        foreign_root = dataclasses.replace(
            applied.managed_root,
            ownership_token="owner-foreign-rewrite-0001",
        )
        foreign = dataclasses.replace(
            applied,
            snapshot_id="snap-store-foreign-attempt-owner",
            managed_root=foreign_root,
        )
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE controller_effect_attempts SET after_snapshot_json = ? "
            "WHERE attempt_id = ?",
            (
                canonical_controller_bytes(foreign.to_document()),
                attempt_id,
            ),
        )
        connection.commit()
        connection.close()

        with self.assertRaises(ControllerStoreCorruptionError):
            OllamaV2ControllerStore(self.database)

    def test_reopen_rejects_event_corruption_and_noncanonical_stored_documents(self) -> None:
        plan = _plan("op-store-corruption")
        with OllamaV2ControllerStore(self.database) as store:
            created = store.create_operation(
                OperationSnapshot.create("op-store-corruption", plan),
                plan,
                idempotency_key="corruption-create",
            ).snapshot
            self.assertEqual(1, created.sequence)

        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE controller_events SET event_hash = ? WHERE operation_id = ? AND sequence = 1",
            ("f" * 64, created.operation_id),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(ControllerStoreCorruptionError):
            OllamaV2ControllerStore(self.database)

    def test_store_has_no_claim_against_coherent_same_principal_database_rollback(self) -> None:
        source = (
            Path(__file__).resolve().parents[1]
            / "src/worldforge/provider_evidence/ollama_v2_controller_store.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "does not protect against coherent rollback by the same OS principal",
            " ".join(source.split()),
        )
        self.assertNotIn("StudioStore", source)
        self.assertNotIn("EventLog", source)


if __name__ == "__main__":
    unittest.main()
