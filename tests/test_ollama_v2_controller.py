from __future__ import annotations

import ast
import dataclasses
import hashlib
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from worldforge.provider_evidence.ollama_v2_controller import (
    ControllerAuthorizationError,
    OllamaV2Authorization,
    OllamaV2Controller,
    OllamaV2HostEffects,
    OllamaV2HostInspector,
    ReconciliationResult,
)
from worldforge.provider_evidence.ollama_v2_controller_contracts import (
    CONTROLLER_GID,
    CONTROLLER_POLICY_CONTENT_HASH,
    CONTROLLER_UID,
    MODEL_FINAL_ROOT,
    RELEASE_FINAL_ROOT,
    SERVICE_UNIT_BYTES,
    SOCKET_UNIT_BYTES,
    AuthorizationConsumption,
    AuthorizationRequest,
    BoundedTreeManifest,
    ControllerPlan,
    HostEffect,
    HostSnapshot,
    InterpreterBinding,
    ManifestEntry,
    PrincipalObservation,
    canonical_interpreter_binding,
    make_empty_host_snapshot,
    project_effect,
)
from worldforge.provider_evidence.ollama_v2_controller_store import (
    ControllerStoreConflictError,
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


def _manifests() -> tuple[BoundedTreeManifest, BoundedTreeManifest]:
    return (
        BoundedTreeManifest(
            purpose="release_final",
            root_path=RELEASE_FINAL_ROOT,
            root_mode=0o555,
            uid=CONTROLLER_UID,
            gid=CONTROLLER_GID,
            sealed=True,
            entries=(_entry("ollama", b"release"),),
        ),
        BoundedTreeManifest(
            purpose="model_final",
            root_path=MODEL_FINAL_ROOT,
            root_mode=0o555,
            uid=CONTROLLER_UID,
            gid=CONTROLLER_GID,
            sealed=True,
            entries=(_entry("model.gguf", b"model"),),
        ),
    )


class _Inspector:
    def __init__(self) -> None:
        self.snapshot = make_empty_host_snapshot("snap-controller-baseline", observed_generation=0)
        self.inspect_calls: list[tuple[str, InterpreterBinding]] = []
        self.observe_calls: list[tuple[str, str]] = []
        self.raise_observe = False

    def inspect(self, policy_hash: str, binding: InterpreterBinding) -> HostSnapshot:
        self.inspect_calls.append((policy_hash, binding))
        return HostSnapshot.from_document(self.snapshot.to_document())

    def observe(self, operation_id: str, plan_hash: str) -> HostSnapshot:
        self.observe_calls.append((operation_id, plan_hash))
        if self.raise_observe:
            raise RuntimeError("host observer unavailable")
        return HostSnapshot.from_document(self.snapshot.to_document())


class _Authorization:
    def __init__(self) -> None:
        self.consumed: dict[str, AuthorizationConsumption] = {}
        self.consume_calls: list[AuthorizationRequest] = []
        self.resolve_calls: list[AuthorizationRequest] = []
        self.reject = False

    def consume(self, request: AuthorizationRequest) -> AuthorizationConsumption:
        self.consume_calls.append(request)
        if self.reject:
            raise RuntimeError("not authorized")
        if request.authorization_id in self.consumed:
            raise RuntimeError("one-use authorization already consumed")
        consumption = AuthorizationConsumption.create(
            request,
            authority_id="director-authority",
            decision_id=f"decision-{request.attempt:04d}",
        )
        self.consumed[request.authorization_id] = consumption
        return consumption

    def resolve(self, request: AuthorizationRequest) -> AuthorizationConsumption | None:
        self.resolve_calls.append(request)
        return self.consumed.get(request.authorization_id)


class _Effects:
    def __init__(self, inspector: _Inspector) -> None:
        self.inspector = inspector
        self.plan: ControllerPlan | None = None
        self.calls: list[tuple[str, str]] = []
        self.raise_before: set[str] = set()
        self.raise_after: set[str] = set()
        self.socket_bytes: bytes | None = None
        self.service_bytes: bytes | None = None

    def _apply(self, effect: HostEffect) -> None:
        if self.plan is None:
            raise AssertionError("test plan was not bound")
        self.calls.append((effect.kind, effect.effect_id))
        if effect.kind in self.raise_before:
            raise RuntimeError("effect rejected before change")
        self.inspector.snapshot = project_effect(
            self.inspector.snapshot,
            self.plan,
            effect,
            self.plan.operation_id,
        )
        if effect.kind in self.raise_after:
            raise RuntimeError("effect reply lost after change")

    def create_managed_root(self, effect: HostEffect) -> None:
        self._apply(effect)

    def create_principal_exact(self, effect: HostEffect) -> None:
        self._apply(effect)

    def stage_release(self, effect: HostEffect, manifest: BoundedTreeManifest) -> None:
        self.assert_manifest(manifest, "release_final")
        self._apply(effect)

    def publish_release(self, effect: HostEffect, manifest: BoundedTreeManifest) -> None:
        self.assert_manifest(manifest, "release_final")
        self._apply(effect)

    def stage_model(self, effect: HostEffect, manifest: BoundedTreeManifest) -> None:
        self.assert_manifest(manifest, "model_final")
        self._apply(effect)

    def publish_model(self, effect: HostEffect, manifest: BoundedTreeManifest) -> None:
        self.assert_manifest(manifest, "model_final")
        self._apply(effect)

    def install_socket_unit(self, effect: HostEffect, unit_bytes: bytes) -> None:
        self.socket_bytes = bytes(unit_bytes)
        self._apply(effect)

    def install_service_unit(self, effect: HostEffect, unit_bytes: bytes) -> None:
        self.service_bytes = bytes(unit_bytes)
        self._apply(effect)

    def reload_manager(self, effect: HostEffect) -> None:
        self._apply(effect)

    def remove_service_unit_exact(self, effect: HostEffect, unit_bytes: bytes) -> None:
        self.service_bytes = bytes(unit_bytes)
        self._apply(effect)

    def remove_socket_unit_exact(self, effect: HostEffect, unit_bytes: bytes) -> None:
        self.socket_bytes = bytes(unit_bytes)
        self._apply(effect)

    def unpublish_model_exact(self, effect: HostEffect, manifest: BoundedTreeManifest) -> None:
        self.assert_manifest(manifest, "model_final")
        self._apply(effect)

    def unstage_model_exact(self, effect: HostEffect, manifest: BoundedTreeManifest) -> None:
        self.assert_manifest(manifest, "model_final")
        self._apply(effect)

    def unpublish_release_exact(self, effect: HostEffect, manifest: BoundedTreeManifest) -> None:
        self.assert_manifest(manifest, "release_final")
        self._apply(effect)

    def unstage_release_exact(self, effect: HostEffect, manifest: BoundedTreeManifest) -> None:
        self.assert_manifest(manifest, "release_final")
        self._apply(effect)

    def remove_principal_exact(self, effect: HostEffect) -> None:
        self._apply(effect)

    def remove_managed_root_exact(self, effect: HostEffect) -> None:
        self._apply(effect)

    def assert_manifest(self, manifest: BoundedTreeManifest, purpose: str) -> None:
        if manifest.purpose != purpose:
            raise AssertionError(f"unexpected manifest purpose: {manifest.purpose}")


class ControllerStateMachineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="wf-ollama-v2-controller-")
        self.store = OllamaV2ControllerStore(Path(self.temp_dir.name) / "controller.sqlite3")
        self.inspector = _Inspector()
        self.authorization = _Authorization()
        self.effects = _Effects(self.inspector)
        self.controller = OllamaV2Controller(
            self.store,
            self.inspector,
            self.authorization,
            self.effects,
        )
        release, model = _manifests()
        inspected = self.controller.inspect()
        self.plan = self.controller.build_plan(
            inspected,
            release,
            model,
            operation_id="op-controller",
        )
        self.effects.plan = self.plan
        self.operation = self.controller.create_operation(
            self.plan,
            operation_id="op-controller",
            idempotency_key="controller-create",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp_dir.cleanup()

    def test_full_apply_consumes_one_authorization_per_effect_and_never_overclaims(self) -> None:
        operation = self.operation
        while operation.state != "prepared_unverified":
            operation = self.controller.advance_apply(operation)

        self.assertEqual(9, operation.apply_cursor)
        self.assertEqual(9, len(operation.applied_effect_ids))
        self.assertEqual(9, len(self.authorization.consume_calls))
        self.assertEqual(
            9,
            len({call.authorization_id for call in self.authorization.consume_calls}),
        )
        self.assertEqual(
            tuple(effect.kind for effect in self.plan.effects),
            tuple(kind for kind, _ in self.effects.calls),
        )
        self.assertEqual(SOCKET_UNIT_BYTES, self.effects.socket_bytes)
        self.assertEqual(SERVICE_UNIT_BYTES, self.effects.service_bytes)
        self.assertEqual("prepared_unverified", operation.state)
        self.assertNotIn(operation.state, {"available", "observed", "pass", "production_ready"})
        self.assertFalse(self.plan.production_eligible)

    def test_effect_exception_always_observes_and_classifies_lost_reply_or_no_effect(self) -> None:
        self.effects.raise_after.add("managed_root.create")
        applied = self.controller.advance_apply(self.operation)

        self.assertEqual(1, applied.apply_cursor)
        self.assertEqual("apply_pending", applied.state)
        self.assertGreaterEqual(len(self.inspector.observe_calls), 2)
        first_request = self.authorization.consume_calls[0]

        self.effects.raise_after.clear()
        self.effects.raise_before.add("principal.create_exact")
        not_applied = self.controller.advance_apply(applied)
        self.assertEqual(1, not_applied.apply_cursor)
        self.assertEqual("apply_pending", not_applied.state)
        self.assertEqual(3, not_applied.next_attempt)

        self.effects.raise_before.clear()
        retried = self.controller.advance_apply(not_applied)
        self.assertEqual(2, retried.apply_cursor)
        self.assertNotEqual(
            first_request.authorization_id,
            self.authorization.consume_calls[-1].authorization_id,
        )
        self.assertEqual(3, len(self.authorization.consume_calls))

    def test_dispatching_resume_observes_only_and_never_reinvokes_possible_effect(self) -> None:
        effect = self.plan.effects[0]
        request = AuthorizationRequest.create(
            operation_id=self.operation.operation_id,
            plan_hash=self.operation.plan_hash,
            effect_id=effect.effect_id,
            phase="apply",
            attempt=self.operation.next_attempt,
            expected_generation=self.operation.generation,
            expected_sequence=self.operation.sequence,
            expected_head_hash=self.operation.event_head_hash,
            ownership_token=self.operation.ownership_token,
        )
        pending = self.store.record_authorization_pending(self.operation, request).snapshot
        claimed = self.store.record_authorization_claimed(pending, request).snapshot
        consumption = self.authorization.consume(request)
        consumed = self.store.record_authorization_consumed(
            claimed,
            request,
            consumption,
        ).snapshot
        dispatching = self.store.record_dispatching(
            consumed,
            request,
            consumption,
            self.inspector.snapshot,
        ).snapshot
        self.inspector.snapshot = project_effect(
            self.inspector.snapshot,
            self.plan,
            effect,
            self.operation.operation_id,
        )
        calls_before = tuple(self.effects.calls)

        resumed = self.controller.advance_apply(dispatching)

        self.assertEqual(1, resumed.apply_cursor)
        self.assertEqual(calls_before, tuple(self.effects.calls))
        self.assertEqual(1, len(self.authorization.consume_calls))
        self.assertEqual("apply_pending", resumed.state)

    def test_pending_authorization_resume_resolves_existing_consumption_without_reconsuming(
        self,
    ) -> None:
        effect = self.plan.effects[0]
        request = AuthorizationRequest.create(
            operation_id=self.operation.operation_id,
            plan_hash=self.operation.plan_hash,
            effect_id=effect.effect_id,
            phase="apply",
            attempt=self.operation.next_attempt,
            expected_generation=self.operation.generation,
            expected_sequence=self.operation.sequence,
            expected_head_hash=self.operation.event_head_hash,
            ownership_token=self.operation.ownership_token,
        )
        pending = self.store.record_authorization_pending(self.operation, request).snapshot
        self.authorization.consume(request)
        consumed_count = len(self.authorization.consume_calls)

        resumed = self.controller.advance_apply(pending)

        self.assertEqual(1, resumed.apply_cursor)
        self.assertEqual(consumed_count, len(self.authorization.consume_calls))
        self.assertGreaterEqual(len(self.authorization.resolve_calls), 1)

    def test_pre_call_foreign_drift_never_dispatches_and_enters_recovery(self) -> None:
        foreign = dataclasses.replace(
            project_effect(
                self.inspector.snapshot,
                self.plan,
                self.plan.effects[0],
                self.operation.operation_id,
            ).managed_root,
            root_mode=0o700,
        )
        self.inspector.snapshot = dataclasses.replace(
            self.inspector.snapshot,
            snapshot_id="snap-controller-foreign-before",
            managed_root=foreign,
        )

        recovered = self.controller.advance_apply(self.operation)

        self.assertEqual("recovery_required", recovered.state)
        self.assertEqual("host_state_foreign", recovered.recovery_reason)
        self.assertEqual([], self.effects.calls)

    def test_apply_rejects_drift_in_an_already_applied_resource_before_authorization(
        self,
    ) -> None:
        operation = self.controller.advance_apply(self.operation)
        self.assertEqual(1, operation.apply_cursor)
        self.inspector.snapshot = dataclasses.replace(
            self.inspector.snapshot,
            snapshot_id="snap-controller-prior-root-removed",
            managed_root=None,
        )
        authorization_count = len(self.authorization.consume_calls)
        effect_count = len(self.effects.calls)

        recovered = self.controller.advance_apply(operation)

        self.assertEqual("recovery_required", recovered.state)
        self.assertEqual("host_state_foreign", recovered.recovery_reason)
        self.assertEqual(authorization_count, len(self.authorization.consume_calls))
        self.assertEqual(effect_count, len(self.effects.calls))
        before = self.controller.status(operation.operation_id)
        result = self.controller.reconcile(before)
        self.assertEqual("foreign", result.classification)
        self.assertEqual(before, self.controller.status(operation.operation_id))

    def test_post_call_observation_failure_is_durable_recovery_not_a_retry(self) -> None:
        class _RaiseOnSecondObserve(_Inspector):
            def observe(self, operation_id: str, plan_hash: str) -> HostSnapshot:
                result = super().observe(operation_id, plan_hash)
                if len(self.observe_calls) == 3:
                    raise RuntimeError("post-call observation unavailable")
                return result

        inspector = _RaiseOnSecondObserve()
        effects = _Effects(inspector)
        with OllamaV2ControllerStore(
            Path(self.temp_dir.name) / "observe-failure.sqlite3"
        ) as store:
            controller = OllamaV2Controller(
                store,
                inspector,
                self.authorization,
                effects,
            )
            release, model = _manifests()
            plan = controller.build_plan(
                controller.inspect(),
                release,
                model,
                operation_id="op-controller-observe-failure",
            )
            effects.plan = plan
            operation = controller.create_operation(
                plan,
                operation_id="op-controller-observe-failure",
                idempotency_key="observe-failure-create",
            )

            recovered = controller.advance_apply(operation)

        self.assertEqual("recovery_required", recovered.state)
        self.assertEqual("host_observation_unavailable", recovered.recovery_reason)
        self.assertEqual(1, len(effects.calls))

    def test_reconcile_is_read_only_and_reports_exact_current_classification(self) -> None:
        before = self.controller.status(self.operation.operation_id)
        result = self.controller.reconcile(before)
        after = self.controller.status(self.operation.operation_id)

        self.assertIsInstance(result, ReconciliationResult)
        self.assertEqual("precondition", result.classification)
        self.assertEqual(self.plan.effects[0].effect_id, result.effect_id)
        self.assertEqual(before, after)
        self.assertEqual(before.content_hash, result.operation_hash)

    def test_explicit_rollback_uses_only_proven_applied_effects_and_finishes_clean(
        self,
    ) -> None:
        operation = self.controller.advance_apply(self.operation)
        operation = self.controller.advance_apply(operation)
        self.assertEqual(2, len(operation.applied_effect_ids))

        rollback_pending = self.controller.prepare_rollback(operation)
        rollback = self.store.load_rollback_plan(operation.operation_id)
        self.assertIsNotNone(rollback)
        self.assertEqual(
            ("principal.remove_exact", "managed_root.remove_exact"),
            tuple(effect.kind for effect in rollback.effects),  # type: ignore[union-attr]
        )
        while rollback_pending.state != "rolled_back_clean":
            rollback_pending = self.controller.advance_rollback(rollback_pending)

        self.assertEqual("rolled_back_clean", rollback_pending.state)
        self.assertFalse(self.inspector.snapshot.principal.present)
        self.assertIsNone(self.inspector.snapshot.managed_root)
        self.assertEqual(4, len(self.authorization.consume_calls))

    def test_clean_multistep_rollback_does_not_invent_active_recovery(self) -> None:
        operation = self.controller.advance_apply(self.operation)
        operation = self.controller.advance_apply(operation)
        rollback = self.controller.prepare_rollback(operation)

        first_compensation = self.controller.advance_rollback(rollback)

        self.assertEqual("rollback_pending", first_compensation.state)
        self.assertIsNone(first_compensation.recovery_reason)

    def test_exact_clean_rollback_releases_scope_for_a_new_operation(self) -> None:
        operation = self.controller.advance_apply(self.operation)
        rollback = self.controller.prepare_rollback(operation)
        rollback = self.controller.advance_rollback(rollback)

        self.assertEqual("rolled_back_clean", rollback.state)
        self.assertIsNone(self.inspector.snapshot.managed_root)
        release, model = _manifests()
        next_plan = self.controller.build_plan(
            self.controller.inspect(),
            release,
            model,
            operation_id="op-controller-next-owner",
        )
        operation_b = self.controller.create_operation(
            next_plan,
            operation_id="op-controller-next-owner",
            idempotency_key="controller-next-owner",
        )
        self.assertNotEqual(operation.ownership_token, operation_b.ownership_token)

        stale = self.controller.advance_rollback(rollback)
        self.assertEqual(rollback, stale)
        self.assertIsNone(self.inspector.snapshot.managed_root)

    def test_full_rollback_clears_manager_owner_before_clean_lease_release(self) -> None:
        database = Path(self.temp_dir.name) / "full-rollback-clean.sqlite3"
        inspector = _Inspector()
        authorization = _Authorization()
        effects = _Effects(inspector)
        release, model = _manifests()
        with OllamaV2ControllerStore(database) as store:
            controller = OllamaV2Controller(
                store,
                inspector,
                authorization,
                effects,
            )
            plan_a = controller.build_plan(
                controller.inspect(),
                release,
                model,
                operation_id="op-full-rollback-owner-a",
            )
            effects.plan = plan_a
            operation_a = controller.create_operation(
                plan_a,
                operation_id="op-full-rollback-owner-a",
                idempotency_key="full-rollback-owner-a",
            )
            while operation_a.state != "prepared_unverified":
                operation_a = controller.advance_apply(operation_a)
            self.assertEqual(
                operation_a.ownership_token,
                inspector.snapshot.manager_reload_ownership_token,
            )

            terminal_a = controller.prepare_rollback(operation_a)
            while terminal_a.state not in {"rolled_back_clean", "recovery_required"}:
                terminal_a = controller.advance_rollback(terminal_a)

            self.assertEqual("rolled_back_clean", terminal_a.state)
            self.assertIsNone(inspector.snapshot.manager_reload_ownership_token)
            self.assertGreater(inspector.snapshot.manager_reload_generation, 0)

        with OllamaV2ControllerStore(database) as reopened:
            controller = OllamaV2Controller(
                reopened,
                inspector,
                authorization,
                effects,
            )
            self.assertEqual(terminal_a, controller.status(terminal_a.operation_id))
            plan_b = controller.build_plan(
                controller.inspect(),
                release,
                model,
                operation_id="op-full-rollback-owner-b",
            )
            operation_b = controller.create_operation(
                plan_b,
                operation_id="op-full-rollback-owner-b",
                idempotency_key="full-rollback-owner-b",
            )
            self.assertEqual("apply_pending", operation_b.state)
            self.assertNotEqual(operation_a.ownership_token, operation_b.ownership_token)

    def test_zero_effect_recovery_clears_only_after_exact_clean_rollback_proof(self) -> None:
        database = Path(self.temp_dir.name) / "zero-recovery-clean.sqlite3"
        inspector = _Inspector()
        authorization = _Authorization()
        effects = _Effects(inspector)
        release, model = _manifests()
        with OllamaV2ControllerStore(database) as store:
            controller = OllamaV2Controller(
                store,
                inspector,
                authorization,
                effects,
            )
            plan_a = controller.build_plan(
                controller.inspect(),
                release,
                model,
                operation_id="op-zero-recovery-owner-a",
            )
            effects.plan = plan_a
            operation_a = controller.create_operation(
                plan_a,
                operation_id="op-zero-recovery-owner-a",
                idempotency_key="zero-recovery-owner-a",
            )
            inspector.snapshot = project_effect(
                plan_a.initial_snapshot,
                plan_a,
                plan_a.effects[0],
                operation_a.operation_id,
            )
            recovery = controller.advance_apply(operation_a)
            self.assertEqual("recovery_required", recovery.state)
            self.assertEqual("host_state_foreign", recovery.recovery_reason)

            inspector.snapshot = dataclasses.replace(
                plan_a.initial_snapshot,
                snapshot_id="snap-zero-recovery-restored",
                observed_generation=1,
            )
            terminal_a = controller.prepare_rollback(recovery)
            self.assertEqual("rolled_back_clean", terminal_a.state)
            self.assertIsNone(terminal_a.recovery_reason)

        with OllamaV2ControllerStore(database) as reopened:
            events = reopened.event_documents(terminal_a.operation_id)
            self.assertIn(
                "operation.recovery_required",
                {event["event_kind"] for event in events},
            )
            controller = OllamaV2Controller(
                reopened,
                inspector,
                authorization,
                effects,
            )
            plan_b = controller.build_plan(
                controller.inspect(),
                release,
                model,
                operation_id="op-zero-recovery-owner-b",
            )
            operation_b = controller.create_operation(
                plan_b,
                operation_id="op-zero-recovery-owner-b",
                idempotency_key="zero-recovery-owner-b",
            )
            self.assertEqual("apply_pending", operation_b.state)

    def test_nonzero_recovery_clears_after_exact_compensation_and_reopens(self) -> None:
        database = Path(self.temp_dir.name) / "nonzero-recovery-clean.sqlite3"
        inspector = _Inspector()
        authorization = _Authorization()
        effects = _Effects(inspector)
        release, model = _manifests()
        with OllamaV2ControllerStore(database) as store:
            controller = OllamaV2Controller(
                store,
                inspector,
                authorization,
                effects,
            )
            plan_a = controller.build_plan(
                controller.inspect(),
                release,
                model,
                operation_id="op-nonzero-recovery-owner-a",
            )
            effects.plan = plan_a
            operation_a = controller.create_operation(
                plan_a,
                operation_id="op-nonzero-recovery-owner-a",
                idempotency_key="nonzero-recovery-owner-a",
            )
            applied = controller.advance_apply(operation_a)
            exact_applied_snapshot = inspector.snapshot
            inspector.snapshot = dataclasses.replace(
                exact_applied_snapshot,
                snapshot_id="snap-nonzero-recovery-drift",
                managed_root=dataclasses.replace(
                    exact_applied_snapshot.managed_root,
                    root_mode=0o700,
                ),
            )
            recovery = controller.advance_apply(applied)
            self.assertEqual("recovery_required", recovery.state)

            inspector.snapshot = exact_applied_snapshot
            terminal_a = controller.prepare_rollback(recovery)
            while terminal_a.state not in {"rolled_back_clean", "recovery_required"}:
                terminal_a = controller.advance_rollback(terminal_a)
            self.assertEqual("rolled_back_clean", terminal_a.state)
            self.assertIsNone(terminal_a.recovery_reason)
            self.assertIsNone(inspector.snapshot.managed_root)

        with OllamaV2ControllerStore(database) as reopened:
            events = reopened.event_documents(terminal_a.operation_id)
            self.assertIn(
                "operation.recovery_required",
                {event["event_kind"] for event in events},
            )
            controller = OllamaV2Controller(
                reopened,
                inspector,
                authorization,
                effects,
            )
            plan_b = controller.build_plan(
                controller.inspect(),
                release,
                model,
                operation_id="op-nonzero-recovery-owner-b",
            )
            operation_b = controller.create_operation(
                plan_b,
                operation_id="op-nonzero-recovery-owner-b",
                idempotency_key="nonzero-recovery-owner-b",
            )
            self.assertEqual("apply_pending", operation_b.state)

    def test_zero_effect_rollback_requires_exact_observation_before_lease_release(self) -> None:
        rollback = self.controller.prepare_rollback(self.operation)

        self.assertEqual("rolled_back_clean", rollback.state)
        release, model = _manifests()
        next_plan = self.controller.build_plan(
            self.controller.inspect(),
            release,
            model,
            operation_id="op-zero-effect-next-owner",
        )
        created = self.controller.create_operation(
            next_plan,
            operation_id="op-zero-effect-next-owner",
            idempotency_key="zero-effect-next-owner",
        )
        self.assertEqual("apply_pending", created.state)

    def test_zero_effect_rollback_preserves_lease_when_initial_projection_drifted(self) -> None:
        self.inspector.snapshot = dataclasses.replace(
            self.inspector.snapshot,
            snapshot_id="snap-zero-effect-foreign-principal",
            principal=PrincipalObservation(
                present=True,
                account="worldforge-ollama-evidence",
                uid=CONTROLLER_UID + 100,
                gid=CONTROLLER_GID + 100,
                primary_group="worldforge-ollama-evidence",
                dedicated_non_login=True,
                supplementary_groups=(),
                owned_by_operation=False,
                uid_owner_account="worldforge-ollama-evidence",
                gid_owner_group="worldforge-ollama-evidence",
            ),
        )

        recovery = self.controller.prepare_rollback(self.operation)

        self.assertEqual("recovery_required", recovery.state)
        self.assertEqual("host_state_foreign", recovery.recovery_reason)
        self.assertIsNone(recovery.rollback_plan_hash)

    def test_rollback_preserves_preexisting_foreign_drift_and_cannot_claim_exact_cleanup(
        self,
    ) -> None:
        operation = self.controller.advance_apply(self.operation)
        self.inspector.snapshot = dataclasses.replace(
            self.inspector.snapshot,
            snapshot_id="snap-controller-foreign-principal",
            principal=PrincipalObservation(
                present=True,
                account="worldforge-ollama-evidence",
                uid=CONTROLLER_UID + 1,
                gid=CONTROLLER_GID + 1,
                primary_group="worldforge-ollama-evidence",
                dedicated_non_login=True,
                supplementary_groups=(),
                owned_by_operation=False,
                uid_owner_account="worldforge-ollama-evidence",
                gid_owner_group="worldforge-ollama-evidence",
            ),
        )
        recovery = self.controller.advance_apply(operation)
        self.assertEqual("host_state_foreign", recovery.recovery_reason)

        rollback_pending = self.controller.prepare_rollback(recovery)
        self.assertEqual("host_state_foreign", rollback_pending.recovery_reason)
        terminal = self.controller.advance_rollback(rollback_pending)

        self.assertEqual("recovery_required", terminal.state)
        self.assertEqual("host_state_foreign", terminal.recovery_reason)
        self.assertIsNotNone(self.inspector.snapshot.managed_root)
        self.assertTrue(self.inspector.snapshot.principal.present)

        effect_calls = tuple(self.effects.calls)
        authorization_calls = tuple(self.authorization.consume_calls)
        result = self.controller.reconcile(terminal)

        self.assertEqual("foreign", result.classification)
        self.assertIsNotNone(result.effect_id)
        self.assertEqual("rollback", result.phase)
        self.assertEqual(terminal.content_hash, result.operation_hash)
        self.assertEqual(terminal, self.controller.status(terminal.operation_id))
        self.assertEqual(effect_calls, tuple(self.effects.calls))
        self.assertEqual(authorization_calls, tuple(self.authorization.consume_calls))

    def test_rollback_rejects_a_previously_cleaned_resource_that_reappears(self) -> None:
        operation = self.controller.advance_apply(self.operation)
        operation = self.controller.advance_apply(operation)
        owned_principal = self.inspector.snapshot.principal
        rollback_pending = self.controller.prepare_rollback(operation)
        rollback_pending = self.controller.advance_rollback(rollback_pending)
        self.assertFalse(self.inspector.snapshot.principal.present)
        self.inspector.snapshot = dataclasses.replace(
            self.inspector.snapshot,
            snapshot_id="snap-controller-cleaned-principal-reappeared",
            principal=owned_principal,
        )
        authorization_count = len(self.authorization.consume_calls)
        effect_count = len(self.effects.calls)

        recovered = self.controller.advance_rollback(rollback_pending)

        self.assertEqual("recovery_required", recovered.state)
        self.assertEqual("host_state_foreign", recovered.recovery_reason)
        self.assertEqual(authorization_count, len(self.authorization.consume_calls))
        self.assertEqual(effect_count, len(self.effects.calls))
        self.assertIsNotNone(self.inspector.snapshot.managed_root)

    def test_authorization_denial_leaves_durable_pending_without_host_call(self) -> None:
        self.authorization.reject = True
        with self.assertRaises(ControllerAuthorizationError):
            self.controller.advance_apply(self.operation)

        pending = self.controller.status(self.operation.operation_id)
        self.assertEqual("apply_authorization_claimed", pending.state)
        self.assertEqual([], self.effects.calls)
        consume_count = len(self.authorization.consume_calls)
        self.authorization.reject = False

        recovered = self.controller.advance_apply(pending)

        self.assertEqual("recovery_required", recovered.state)
        self.assertEqual(
            "authorization_outcome_indeterminate",
            recovered.recovery_reason,
        )
        self.assertEqual(consume_count, len(self.authorization.consume_calls))

    def test_synchronized_controllers_dispatch_same_operation_exactly_once(self) -> None:
        pending_barrier = threading.Barrier(2)
        resolve_barrier = threading.Barrier(2)
        effect_barrier = threading.Barrier(2)
        result_lock = threading.Lock()

        class BarrierStore(OllamaV2ControllerStore):
            def record_authorization_pending(self, expected, request):
                pending_barrier.wait(timeout=2)
                return super().record_authorization_pending(expected, request)

        class ConcurrentAuthorization(_Authorization):
            def __init__(self) -> None:
                super().__init__()
                self.lock = threading.Lock()

            def resolve(self, request: AuthorizationRequest):
                with self.lock:
                    self.resolve_calls.append(request)
                    existing = self.consumed.get(request.authorization_id)
                if existing is not None:
                    return existing
                try:
                    resolve_barrier.wait(timeout=0.3)
                except threading.BrokenBarrierError:
                    pass
                return None

            def consume(self, request: AuthorizationRequest):
                with self.lock:
                    self.consume_calls.append(request)
                    consumption = self.consumed.get(request.authorization_id)
                    if consumption is None:
                        consumption = AuthorizationConsumption.create(
                            request,
                            authority_id="director-authority",
                            decision_id="decision-concurrent",
                        )
                        self.consumed[request.authorization_id] = consumption
                    return consumption

        class ConcurrentEffects(_Effects):
            def __init__(self, inspector: _Inspector) -> None:
                super().__init__(inspector)
                self.lock = threading.Lock()

            def _apply(self, effect: HostEffect) -> None:
                if self.plan is None:
                    raise AssertionError("test plan was not bound")
                with self.lock:
                    self.calls.append((effect.kind, effect.effect_id))
                try:
                    effect_barrier.wait(timeout=0.3)
                except threading.BrokenBarrierError:
                    pass
                with self.lock:
                    if self.inspector.snapshot.managed_root is None:
                        self.inspector.snapshot = project_effect(
                            self.inspector.snapshot,
                            self.plan,
                            effect,
                            "op-controller",
                        )

        inspector = _Inspector()
        authorization = ConcurrentAuthorization()
        effects = ConcurrentEffects(inspector)
        effects.plan = self.plan
        results = []
        errors = []

        def worker() -> None:
            try:
                with BarrierStore(
                    Path(self.temp_dir.name) / "controller.sqlite3"
                ) as thread_store:
                    controller = OllamaV2Controller(
                        thread_store,
                        inspector,
                        authorization,
                        effects,
                    )
                    result = controller.advance_apply(self.operation)
                    with result_lock:
                        results.append(result)
            except BaseException as exc:
                with result_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual([], errors)
        self.assertEqual(2, len(results))
        self.assertEqual(1, len(authorization.consume_calls))
        self.assertEqual(1, len(effects.calls))
        durable = self.controller.status(self.operation.operation_id)
        self.assertEqual(1, durable.apply_cursor)
        self.assertEqual("apply_pending", durable.state)

    def test_exception_reconciled_dispatch_loser_never_owns_host_call(self) -> None:
        effect = self.plan.effects[0]
        request = AuthorizationRequest.create(
            operation_id=self.operation.operation_id,
            plan_hash=self.operation.plan_hash,
            effect_id=effect.effect_id,
            phase="apply",
            attempt=self.operation.next_attempt,
            expected_generation=self.operation.generation,
            expected_sequence=self.operation.sequence,
            expected_head_hash=self.operation.event_head_hash,
            ownership_token=self.operation.ownership_token,
        )
        pending = self.store.record_authorization_pending(
            self.operation,
            request,
        ).snapshot
        claimed = self.store.record_authorization_claimed(pending, request).snapshot
        consumption = self.authorization.consume(request)
        consumed = self.store.record_authorization_consumed(
            claimed,
            request,
            consumption,
        ).snapshot

        a_released_lock = threading.Event()
        a_injected = threading.Event()
        b_committed = threading.Event()
        effect_started = threading.Event()
        second_effect_started = threading.Event()
        a_finished = threading.Event()
        race_resolved = threading.Event()
        allow_effect = threading.Event()
        result_lock = threading.Lock()
        transition_results = {}
        controller_results = {}
        errors = []

        class AStore(OllamaV2ControllerStore):
            def record_dispatching(self, *args, **kwargs):
                result = super().record_dispatching(*args, **kwargs)
                with result_lock:
                    transition_results["a"] = result
                return result

        class BStore(OllamaV2ControllerStore):
            def record_dispatching(self, *args, **kwargs):
                result = super().record_dispatching(*args, **kwargs)
                with result_lock:
                    transition_results["b"] = result
                b_committed.set()
                return result

        class BlockingEffects(_Effects):
            def __init__(self, inspector: _Inspector) -> None:
                super().__init__(inspector)
                self.lock = threading.Lock()

            def _apply(self, candidate: HostEffect) -> None:
                if self.plan is None:
                    raise AssertionError("test plan was not bound")
                with self.lock:
                    self.calls.append((candidate.kind, candidate.effect_id))
                    call_count = len(self.calls)
                if call_count == 1:
                    effect_started.set()
                else:
                    second_effect_started.set()
                    race_resolved.set()
                if not allow_effect.wait(timeout=5):
                    raise AssertionError("effect release barrier timed out")
                with self.lock:
                    if self.inspector.snapshot.managed_root is None:
                        self.inspector.snapshot = project_effect(
                            self.inspector.snapshot,
                            self.plan,
                            candidate,
                            self.plan.operation_id,
                        )

        effects = BlockingEffects(self.inspector)
        effects.plan = self.plan
        database = Path(self.temp_dir.name) / "controller.sqlite3"
        original_commit = OllamaV2ControllerStore._commit

        def racing_commit(instance: OllamaV2ControllerStore) -> None:
            if threading.current_thread() is thread_a and not a_injected.is_set():
                a_injected.set()
                instance._connection.execute("ROLLBACK")
                a_released_lock.set()
                if not b_committed.wait(timeout=5):
                    raise AssertionError("winning commit barrier timed out")
                raise sqlite3.OperationalError("pre-commit ownership race")
            original_commit(instance)

        def worker_a() -> None:
            try:
                with AStore(database) as store_a:
                    controller_a = OllamaV2Controller(
                        store_a,
                        self.inspector,
                        self.authorization,
                        effects,
                    )
                    controller_results["a"] = controller_a.advance_apply(consumed)
            except BaseException as exc:
                with result_lock:
                    errors.append(exc)
            finally:
                a_finished.set()
                race_resolved.set()

        def worker_b() -> None:
            try:
                if not a_released_lock.wait(timeout=5):
                    raise AssertionError("losing rollback barrier timed out")
                with BStore(database) as store_b:
                    controller_b = OllamaV2Controller(
                        store_b,
                        self.inspector,
                        self.authorization,
                        effects,
                    )
                    controller_results["b"] = controller_b.advance_apply(consumed)
            except BaseException as exc:
                with result_lock:
                    errors.append(exc)

        thread_a = threading.Thread(target=worker_a)
        thread_b = threading.Thread(target=worker_b)
        with mock.patch.object(
            OllamaV2ControllerStore,
            "_commit",
            racing_commit,
        ):
            thread_a.start()
            thread_b.start()
            effect_did_start = effect_started.wait(timeout=5)
            race_did_resolve = race_resolved.wait(timeout=5)
            allow_effect.set()
            thread_a.join(timeout=5)
            thread_b.join(timeout=5)

        self.assertFalse(thread_a.is_alive())
        self.assertFalse(thread_b.is_alive())
        self.assertEqual([], errors)
        self.assertTrue(effect_did_start)
        self.assertTrue(race_did_resolve)
        self.assertTrue(transition_results["b"].committed_now)
        self.assertFalse(transition_results["a"].committed_now)
        self.assertEqual(
            transition_results["b"].snapshot,
            transition_results["a"].snapshot,
        )
        self.assertTrue(a_finished.is_set())
        self.assertFalse(second_effect_started.is_set())
        self.assertEqual(1, len(self.authorization.consume_calls))
        self.assertEqual(1, len(effects.calls))
        durable = self.controller.status(self.operation.operation_id)
        self.assertEqual(1, durable.apply_cursor)
        self.assertEqual("apply_pending", durable.state)
        self.assertEqual(2, len(controller_results))

    def test_lost_post_commit_replies_are_nonowning_and_every_phase_resumes(self) -> None:
        original_commit = OllamaV2ControllerStore._commit
        cases = (
            ("authorization.pending", "pending"),
            ("authorization.claimed", "claimed"),
            ("authorization.consumed", "consumed"),
            ("effect.dispatching", "dispatching"),
            ("effect.observed", "observed"),
            ("operation.recovery_required", "recovery"),
            ("rollback.prepared", "rollback"),
        )

        for target_event, label in cases:
            with self.subTest(boundary=target_event), tempfile.TemporaryDirectory(
                prefix=f"wf-ollama-v2-lost-{label}-"
            ) as temporary_directory:

                class LostReplyStore(OllamaV2ControllerStore):
                    def __init__(self, path: Path) -> None:
                        self.target_event = target_event
                        self.injected = False
                        super().__init__(path)

                    def _commit(self) -> None:
                        original_commit(self)
                        latest = self._connection.execute(
                            "SELECT event_kind FROM controller_events "
                            "ORDER BY sequence DESC LIMIT 1"
                        ).fetchone()
                        if (
                            not self.injected
                            and latest is not None
                            and latest["event_kind"] == self.target_event
                        ):
                            self.injected = True
                            raise sqlite3.OperationalError(
                                f"lost {self.target_event} commit reply"
                            )

                inspector = _Inspector()
                authorization = _Authorization()
                effects = _Effects(inspector)
                with LostReplyStore(
                    Path(temporary_directory) / "controller.sqlite3"
                ) as store:
                    controller = OllamaV2Controller(
                        store,
                        inspector,
                        authorization,
                        effects,
                    )
                    release, model = _manifests()
                    plan = controller.build_plan(
                        controller.inspect(),
                        release,
                        model,
                        operation_id=f"op-lost-{label}",
                    )
                    effects.plan = plan
                    operation = controller.create_operation(
                        plan,
                        operation_id=plan.operation_id,
                        idempotency_key=f"lost-{label}-create",
                    )

                    if target_event == "operation.recovery_required":
                        foreign_root = dataclasses.replace(
                            project_effect(
                                inspector.snapshot,
                                plan,
                                plan.effects[0],
                                operation.operation_id,
                            ).managed_root,
                            root_mode=0o700,
                        )
                        inspector.snapshot = dataclasses.replace(
                            inspector.snapshot,
                            snapshot_id=f"snap-lost-{label}-foreign",
                            managed_root=foreign_root,
                        )
                        nonowner = controller.advance_apply(operation)
                    elif target_event == "rollback.prepared":
                        applied = controller.advance_apply(operation)
                        nonowner = controller.prepare_rollback(applied)
                    else:
                        nonowner = controller.advance_apply(operation)

                    self.assertTrue(store.injected)
                    self.assertEqual(nonowner, controller.status(operation.operation_id))

                    if target_event == "authorization.pending":
                        self.assertEqual("apply_authorization_pending", nonowner.state)
                        self.assertEqual(0, len(authorization.consume_calls))
                        self.assertEqual(0, len(effects.calls))
                        resumed = controller.advance_apply(nonowner)
                        self.assertEqual(1, resumed.apply_cursor)
                        self.assertEqual(1, len(authorization.consume_calls))
                        self.assertEqual(1, len(effects.calls))
                    elif target_event == "authorization.claimed":
                        self.assertEqual("apply_authorization_claimed", nonowner.state)
                        self.assertEqual(0, len(authorization.consume_calls))
                        self.assertEqual(0, len(effects.calls))
                        recovery = controller.advance_apply(nonowner)
                        self.assertEqual("recovery_required", recovery.state)
                        self.assertEqual(
                            "authorization_outcome_indeterminate",
                            recovery.recovery_reason,
                        )
                        self.assertEqual(0, len(authorization.consume_calls))
                        self.assertEqual(0, len(effects.calls))
                        clean = controller.prepare_rollback(recovery)
                        self.assertEqual("rolled_back_clean", clean.state)
                    elif target_event == "authorization.consumed":
                        self.assertEqual("apply_authorization_consumed", nonowner.state)
                        self.assertEqual(1, len(authorization.consume_calls))
                        self.assertEqual(0, len(effects.calls))
                        resumed = controller.advance_apply(nonowner)
                        self.assertEqual(1, resumed.apply_cursor)
                        self.assertEqual(1, len(authorization.consume_calls))
                        self.assertEqual(1, len(effects.calls))
                    elif target_event == "effect.dispatching":
                        self.assertEqual("apply_dispatching", nonowner.state)
                        self.assertEqual(1, len(authorization.consume_calls))
                        self.assertEqual(0, len(effects.calls))
                        observed_precondition = controller.advance_apply(nonowner)
                        self.assertEqual("apply_pending", observed_precondition.state)
                        self.assertEqual(0, observed_precondition.apply_cursor)
                        self.assertEqual(0, len(effects.calls))
                        resumed = controller.advance_apply(observed_precondition)
                        self.assertEqual(1, resumed.apply_cursor)
                        self.assertEqual(2, len(authorization.consume_calls))
                        self.assertEqual(1, len(effects.calls))
                    elif target_event == "effect.observed":
                        self.assertEqual("apply_pending", nonowner.state)
                        self.assertEqual(1, nonowner.apply_cursor)
                        self.assertEqual(1, len(authorization.consume_calls))
                        self.assertEqual(1, len(effects.calls))
                        resumed = controller.advance_apply(nonowner)
                        self.assertEqual(2, resumed.apply_cursor)
                        self.assertEqual(2, len(authorization.consume_calls))
                        self.assertEqual(2, len(effects.calls))
                    elif target_event == "operation.recovery_required":
                        self.assertEqual("recovery_required", nonowner.state)
                        self.assertEqual(0, len(authorization.consume_calls))
                        self.assertEqual(0, len(effects.calls))
                        self.assertEqual(
                            "foreign",
                            controller.reconcile(nonowner).classification,
                        )
                        inspector.snapshot = HostSnapshot.from_document(
                            plan.initial_snapshot.to_document()
                        )
                        clean = controller.prepare_rollback(nonowner)
                        self.assertEqual("rolled_back_clean", clean.state)
                    else:
                        self.assertEqual("rollback_pending", nonowner.state)
                        self.assertEqual(1, nonowner.apply_cursor)
                        self.assertEqual(1, len(authorization.consume_calls))
                        self.assertEqual(1, len(effects.calls))
                        clean = controller.advance_rollback(nonowner)
                        self.assertEqual("rolled_back_clean", clean.state)
                        self.assertEqual(2, len(authorization.consume_calls))
                        self.assertEqual(2, len(effects.calls))

    def test_distinct_operation_cannot_claim_scope_while_first_operation_applies(self) -> None:
        release, model = _manifests()
        plan_b = self.controller.build_plan(
            self.plan.initial_snapshot,
            release,
            model,
            operation_id="op-controller-distinct-b",
        )
        start = threading.Barrier(2)
        lock = threading.Lock()
        applied = []
        conflicts = []
        errors = []

        def apply_a() -> None:
            try:
                with OllamaV2ControllerStore(
                    Path(self.temp_dir.name) / "controller.sqlite3"
                ) as store:
                    controller = OllamaV2Controller(
                        store,
                        self.inspector,
                        self.authorization,
                        self.effects,
                    )
                    start.wait(timeout=2)
                    result = controller.advance_apply(self.operation)
                    with lock:
                        applied.append(result)
            except BaseException as exc:
                with lock:
                    errors.append(exc)

        def create_b() -> None:
            try:
                with OllamaV2ControllerStore(
                    Path(self.temp_dir.name) / "controller.sqlite3"
                ) as store:
                    controller = OllamaV2Controller(
                        store,
                        self.inspector,
                        self.authorization,
                        self.effects,
                    )
                    start.wait(timeout=2)
                    controller.create_operation(
                        plan_b,
                        operation_id="op-controller-distinct-b",
                        idempotency_key="controller-distinct-b",
                    )
            except ControllerStoreConflictError as exc:
                with lock:
                    conflicts.append(exc)
            except BaseException as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=apply_a), threading.Thread(target=create_b)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual([], errors)
        self.assertEqual(1, len(applied))
        self.assertEqual(1, applied[0].apply_cursor)
        self.assertEqual(1, len(conflicts))
        self.assertEqual(
            self.operation.ownership_token,
            self.inspector.snapshot.managed_root.ownership_token,
        )

    def test_distinct_operation_never_deletes_or_credits_first_owner_during_rollback(
        self,
    ) -> None:
        database = Path(self.temp_dir.name) / "rollback-lease.sqlite3"
        entered_remove = threading.Event()
        allow_remove = threading.Event()

        class BlockingEffects(_Effects):
            block_remove = False

            def _apply(self, effect: HostEffect) -> None:
                if self.block_remove and effect.kind == "managed_root.remove_exact":
                    entered_remove.set()
                    if not allow_remove.wait(timeout=5):
                        raise AssertionError("rollback release barrier timed out")
                super()._apply(effect)

        inspector = _Inspector()
        authorization = _Authorization()
        effects = BlockingEffects(inspector)
        with OllamaV2ControllerStore(database) as store_a:
            controller_a = OllamaV2Controller(
                store_a,
                inspector,
                authorization,
                effects,
            )
            release, model = _manifests()
            plan_a = controller_a.build_plan(
                controller_a.inspect(),
                release,
                model,
                operation_id="op-rollback-owner-a",
            )
            effects.plan = plan_a
            operation_a = controller_a.create_operation(
                plan_a,
                operation_id="op-rollback-owner-a",
                idempotency_key="rollback-owner-a",
            )
            operation_a = controller_a.advance_apply(operation_a)
            rollback_a = controller_a.prepare_rollback(operation_a)
            effects.block_remove = True
            results = []
            errors = []

            def rollback_worker() -> None:
                try:
                    with OllamaV2ControllerStore(database) as thread_store:
                        controller = OllamaV2Controller(
                            thread_store,
                            inspector,
                            authorization,
                            effects,
                        )
                        results.append(controller.advance_rollback(rollback_a))
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=rollback_worker)
            thread.start()
            entered = entered_remove.wait(timeout=3)
            if not entered:
                allow_remove.set()
                thread.join(timeout=2)
                self.fail("rollback did not reach host effect")
            plan_b = controller_a.build_plan(
                plan_a.initial_snapshot,
                release,
                model,
                operation_id="op-rollback-owner-b",
            )
            with self.assertRaisesRegex(
                ControllerStoreConflictError,
                "host_scope_lease_conflict",
            ):
                controller_a.create_operation(
                    plan_b,
                    operation_id="op-rollback-owner-b",
                    idempotency_key="rollback-owner-b",
                )
            allow_remove.set()
            thread.join(timeout=5)

            self.assertFalse(thread.is_alive())
            self.assertEqual([], errors)
            self.assertEqual("rolled_back_clean", results[0].state)
            operation_b = controller_a.create_operation(
                plan_b,
                operation_id="op-rollback-owner-b",
                idempotency_key="rollback-owner-b",
            )
            effects.plan = plan_b
            operation_b = controller_a.advance_apply(operation_b)
            self.assertEqual(
                operation_b.ownership_token,
                inspector.snapshot.managed_root.ownership_token,
            )

            stale = controller_a.advance_rollback(results[0])
            self.assertEqual(results[0], stale)
            self.assertEqual(
                operation_b.ownership_token,
                inspector.snapshot.managed_root.ownership_token,
            )

    def test_synchronized_pending_resume_claims_authorization_consumption_once(self) -> None:
        effect = self.plan.effects[0]
        request = AuthorizationRequest.create(
            operation_id=self.operation.operation_id,
            plan_hash=self.operation.plan_hash,
            effect_id=effect.effect_id,
            phase="apply",
            attempt=self.operation.next_attempt,
            expected_generation=self.operation.generation,
            expected_sequence=self.operation.sequence,
            expected_head_hash=self.operation.event_head_hash,
            ownership_token=self.operation.ownership_token,
        )
        pending = self.store.record_authorization_pending(
            self.operation,
            request,
        ).snapshot
        start_barrier = threading.Barrier(2)
        resolve_barrier = threading.Barrier(2)
        result_lock = threading.Lock()

        class ConcurrentAuthorization(_Authorization):
            def __init__(self) -> None:
                super().__init__()
                self.lock = threading.Lock()

            def resolve(self, candidate: AuthorizationRequest):
                with self.lock:
                    self.resolve_calls.append(candidate)
                    existing = self.consumed.get(candidate.authorization_id)
                if existing is not None:
                    return existing
                try:
                    resolve_barrier.wait(timeout=0.3)
                except threading.BrokenBarrierError:
                    pass
                return None

            def consume(self, candidate: AuthorizationRequest):
                with self.lock:
                    self.consume_calls.append(candidate)
                    consumption = self.consumed.get(candidate.authorization_id)
                    if consumption is None:
                        consumption = AuthorizationConsumption.create(
                            candidate,
                            authority_id="director-authority",
                            decision_id="decision-pending-concurrent",
                        )
                        self.consumed[candidate.authorization_id] = consumption
                    return consumption

        inspector = _Inspector()
        authorization = ConcurrentAuthorization()
        effects = _Effects(inspector)
        effects.plan = self.plan
        results = []
        errors = []

        def worker() -> None:
            try:
                with OllamaV2ControllerStore(
                    Path(self.temp_dir.name) / "controller.sqlite3"
                ) as thread_store:
                    controller = OllamaV2Controller(
                        thread_store,
                        inspector,
                        authorization,
                        effects,
                    )
                    start_barrier.wait(timeout=2)
                    result = controller.advance_apply(pending)
                    with result_lock:
                        results.append(result)
            except BaseException as exc:
                with result_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual([], errors)
        self.assertEqual(2, len(results))
        self.assertEqual(1, len(authorization.consume_calls))
        self.assertEqual(1, len(effects.calls))
        durable = self.controller.status(self.operation.operation_id)
        self.assertEqual(1, durable.apply_cursor)

    def test_construction_captures_all_call_targets_against_late_replacement(self) -> None:
        original_inspect = self.inspector.inspect
        original_observe = self.inspector.observe
        original_consume = self.authorization.consume
        original_resolve = self.authorization.resolve
        original_effect = self.effects.create_managed_root

        def trap(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("late replacement was invoked")

        self.inspector.inspect = trap  # type: ignore[method-assign,assignment]
        self.inspector.observe = trap  # type: ignore[method-assign,assignment]
        self.authorization.consume = trap  # type: ignore[method-assign,assignment]
        self.authorization.resolve = trap  # type: ignore[method-assign,assignment]
        self.effects.create_managed_root = trap  # type: ignore[method-assign,assignment]

        self.controller.inspect()
        advanced = self.controller.advance_apply(self.operation)

        self.assertEqual(1, advanced.apply_cursor)
        self.assertGreaterEqual(len(self.inspector.inspect_calls), 2)
        self.assertIsNotNone(original_inspect)
        self.assertIsNotNone(original_observe)
        self.assertIsNotNone(original_consume)
        self.assertIsNotNone(original_resolve)
        self.assertIsNotNone(original_effect)

    def test_construction_captures_dispatch_against_controller_class_replacement(self) -> None:
        original_dispatch = OllamaV2Controller._dispatch

        def replacement(
            _controller: OllamaV2Controller,
            _plan: ControllerPlan,
            _effect: HostEffect,
        ):
            raise AssertionError("late controller class replacement redirected dispatch")

        OllamaV2Controller._dispatch = replacement  # type: ignore[method-assign]
        try:
            advanced = self.controller.advance_apply(self.operation)
        finally:
            OllamaV2Controller._dispatch = original_dispatch  # type: ignore[method-assign]

        self.assertEqual(1, advanced.apply_cursor)
        self.assertEqual("managed_root.create", self.effects.calls[0][0])


class ControllerSurfaceTests(unittest.TestCase):
    def test_protocol_surfaces_are_closed_and_controller_has_no_generic_execution(self) -> None:
        inspector_methods = {
            name
            for name, value in OllamaV2HostInspector.__dict__.items()
            if callable(value) and not name.startswith("_")
        }
        authorization_methods = {
            name
            for name, value in OllamaV2Authorization.__dict__.items()
            if callable(value) and not name.startswith("_")
        }
        effect_methods = {
            name
            for name, value in OllamaV2HostEffects.__dict__.items()
            if callable(value) and not name.startswith("_")
        }
        self.assertEqual({"inspect", "observe"}, inspector_methods)
        self.assertEqual({"consume", "resolve"}, authorization_methods)
        self.assertEqual(
            {
                "create_managed_root",
                "create_principal_exact",
                "stage_release",
                "publish_release",
                "stage_model",
                "publish_model",
                "install_socket_unit",
                "install_service_unit",
                "reload_manager",
                "remove_service_unit_exact",
                "remove_socket_unit_exact",
                "unpublish_model_exact",
                "unstage_model_exact",
                "unpublish_release_exact",
                "unstage_release_exact",
                "remove_principal_exact",
                "remove_managed_root_exact",
            },
            effect_methods,
        )

        root = Path(__file__).resolve().parents[1]
        source = (root / "src/worldforge/provider_evidence/ollama_v2_controller.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertNotIn("subprocess", imports)
        self.assertNotIn("socket", imports)
        self.assertNotIn("os", imports)
        for forbidden in (
            "ProviderAdapter",
            "StudioStore",
            "EventLog",
            "agent_harness",
            "subprocess",
            "Popen",
            "shell=True",
            "generic_rpc",
            "def run(",
            "def execute(",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_no_native_interpreter_is_exposed_as_available(self) -> None:
        binding = canonical_interpreter_binding()
        self.assertEqual("absent", binding.native_implementation_state)
        self.assertEqual(CONTROLLER_POLICY_CONTENT_HASH, binding.policy_content_hash)
        self.assertFalse(hasattr(OllamaV2Controller, "start_service"))
        self.assertFalse(hasattr(OllamaV2Controller, "launch_provider"))
        self.assertFalse(hasattr(OllamaV2Controller, "run_inference"))


if __name__ == "__main__":
    unittest.main()
