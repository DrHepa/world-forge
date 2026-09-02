from __future__ import annotations

import copy
import dataclasses
import hashlib
import unittest
from pathlib import Path

from worldforge.provider_evidence.ollama_v2_controller_contracts import (
    CONTROLLER_GID,
    CONTROLLER_POLICY_CONTENT_HASH,
    CONTROLLER_POLICY_SERIALIZED_SHA256,
    CONTROLLER_UID,
    MANAGED_ROOT,
    MODEL_FINAL_ROOT,
    RELEASE_FINAL_ROOT,
    SERVICE_UNIT_BYTES,
    SOCKET_UNIT_BYTES,
    AuthorizationConsumption,
    AuthorizationRequest,
    BoundedTreeManifest,
    ControllerContractError,
    ControllerPlan,
    HostSnapshot,
    InterpreterBinding,
    ManifestEntry,
    OperationSnapshot,
    PrincipalObservation,
    RollbackPlan,
    UnitObservation,
    build_controller_plan,
    build_rollback_plan,
    canonical_controller_bytes,
    canonical_interpreter_binding,
    classify_effect_snapshot,
    is_reusable_clean_projection,
    make_empty_host_snapshot,
    project_effect,
)


def _file(path: str, payload: bytes) -> ManifestEntry:
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


def _manifest(purpose: str) -> BoundedTreeManifest:
    root = RELEASE_FINAL_ROOT if purpose == "release_final" else MODEL_FINAL_ROOT
    return BoundedTreeManifest(
        purpose=purpose,
        root_path=root,
        root_mode=0o555,
        uid=CONTROLLER_UID,
        gid=CONTROLLER_GID,
        sealed=True,
        entries=(
            ManifestEntry(
                relative_path="bin",
                entry_kind="directory",
                size_bytes=0,
                sha256=hashlib.sha256(b"").hexdigest(),
                mode=0o555,
                uid=CONTROLLER_UID,
                gid=CONTROLLER_GID,
                link_count=1,
                writable=False,
            ),
            _file("bin/ollama", b"exact-ollama-release"),
        ),
    )


class ExactControllerContractTests(unittest.TestCase):
    def test_interpreter_binding_and_policy_vector_are_canonical_and_detached(self) -> None:
        binding = canonical_interpreter_binding()
        document = binding.to_document()
        round_tripped = InterpreterBinding.from_document(document)

        self.assertEqual(CONTROLLER_POLICY_CONTENT_HASH, binding.policy_content_hash)
        self.assertEqual(
            CONTROLLER_POLICY_SERIALIZED_SHA256,
            binding.policy_serialized_sha256,
        )
        self.assertEqual(
            hashlib.sha256(SOCKET_UNIT_BYTES).hexdigest(),
            binding.socket_unit_sha256,
        )
        self.assertEqual(
            hashlib.sha256(SERVICE_UNIT_BYTES).hexdigest(),
            binding.service_unit_sha256,
        )
        self.assertEqual(binding, round_tripped)
        self.assertIsNot(document, round_tripped.to_document())
        self.assertRegex(binding.content_hash, r"\A[0-9a-f]{64}\Z")

        document["uid"] = True
        with self.assertRaisesRegex(ControllerContractError, "interpreter_binding_invalid"):
            InterpreterBinding.from_document(document)

    def test_contract_tests_contain_no_vacuous_content_hash_assertion(self) -> None:
        source = Path(__file__).read_text(encoding="utf-8")
        vacuous_assertion = "starts" + 'with(\"\")'
        self.assertNotIn(vacuous_assertion, source)

    def test_frozen_slots_contracts_emit_exact_documents_and_reject_extra_fields(self) -> None:
        binding = canonical_interpreter_binding()
        self.assertTrue(dataclasses.is_dataclass(binding))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            binding.uid = 1  # type: ignore[misc]
        self.assertFalse(hasattr(binding, "__dict__"))

        document = binding.to_document()
        document["unexpected"] = "field"
        with self.assertRaisesRegex(ControllerContractError, "interpreter_binding_invalid"):
            InterpreterBinding.from_document(document)

        missing = binding.to_document()
        del missing["effect_methods"]
        with self.assertRaisesRegex(ControllerContractError, "interpreter_binding_invalid"):
            InterpreterBinding.from_document(missing)

    def test_bounded_manifest_rejects_path_collisions_links_writable_final_and_bounds(self) -> None:
        valid = _manifest("release_final")
        self.assertEqual(valid, BoundedTreeManifest.from_document(valid.to_document()))
        self.assertEqual(2, valid.entry_count)
        self.assertGreater(valid.total_size_bytes, 0)

        hostile_entries = (
            _file("../escape", b"x"),
            _file("bin\x00/escape", b"x"),
            dataclasses.replace(_file("bin/tool", b"x"), link_count=2),
            dataclasses.replace(_file("bin/tool", b"x"), mode=0o644, writable=True),
        )
        for entry in hostile_entries:
            with self.subTest(entry=entry), self.assertRaises(ControllerContractError):
                BoundedTreeManifest(
                    purpose="release_final",
                    root_path=RELEASE_FINAL_ROOT,
                    root_mode=0o555,
                    uid=CONTROLLER_UID,
                    gid=CONTROLLER_GID,
                    sealed=True,
                    entries=(entry,),
                )

        with self.assertRaisesRegex(ControllerContractError, "tree_manifest_collision"):
            BoundedTreeManifest(
                purpose="release_final",
                root_path=RELEASE_FINAL_ROOT,
                root_mode=0o555,
                uid=CONTROLLER_UID,
                gid=CONTROLLER_GID,
                sealed=True,
                entries=(_file("Readme", b"a"), _file("README", b"b")),
            )

    def test_principal_unit_and_host_observations_reject_ambient_and_binding_drift(self) -> None:
        snapshot = make_empty_host_snapshot("snap-contract-baseline", observed_generation=7)
        self.assertEqual(snapshot, HostSnapshot.from_document(snapshot.to_document()))
        self.assertEqual(CONTROLLER_POLICY_CONTENT_HASH, snapshot.policy_content_hash)
        self.assertEqual(MANAGED_ROOT, snapshot.managed_root_path)

        uid_only_collision = PrincipalObservation(
            present=False,
            account="worldforge-ollama-evidence",
            uid=None,
            gid=None,
            primary_group="worldforge-ollama-evidence",
            dedicated_non_login=False,
            supplementary_groups=(),
            owned_by_operation=False,
            uid_owner_account="foreign-uid-owner",
            gid_owner_group=None,
        )
        gid_only_collision = PrincipalObservation(
            present=False,
            account="worldforge-ollama-evidence",
            uid=None,
            gid=None,
            primary_group="worldforge-ollama-evidence",
            dedicated_non_login=False,
            supplementary_groups=(),
            owned_by_operation=False,
            uid_owner_account=None,
            gid_owner_group="foreign-gid-owner",
        )
        release = _manifest("release_final")
        model = _manifest("model_final")
        with self.assertRaisesRegex(ControllerContractError, "plan_precondition_not_empty"):
            build_controller_plan(
                dataclasses.replace(snapshot, principal=uid_only_collision),
                release,
                model,
                operation_id="op-uid-only-collision",
            )
        with self.assertRaisesRegex(ControllerContractError, "plan_precondition_not_empty"):
            build_controller_plan(
                dataclasses.replace(snapshot, principal=gid_only_collision),
                release,
                model,
                operation_id="op-gid-only-collision",
            )

        with self.assertRaisesRegex(ControllerContractError, "principal_observation_invalid"):
            PrincipalObservation(
                present=True,
                account="ollama",
                uid=CONTROLLER_UID,
                gid=CONTROLLER_GID,
                primary_group="ollama",
                dedicated_non_login=True,
                supplementary_groups=(),
                owned_by_operation=False,
                uid_owner_account="ollama",
                gid_owner_group="ollama",
            )
        with self.assertRaisesRegex(ControllerContractError, "unit_observation_invalid"):
            UnitObservation(
                unit_name="ollama.service",
                present=True,
                content_sha256="0" * 64,
                owned_by_operation=False,
                enabled=False,
                active=False,
            )

        drift = snapshot.to_document()
        drift["policy_content_hash"] = "0" * 64
        drift["content_hash"] = HostSnapshot.compute_document_hash(drift)
        with self.assertRaisesRegex(ControllerContractError, "host_snapshot_policy_drift"):
            HostSnapshot.from_document(drift)

        drift = snapshot.to_document()
        drift["interpreter_binding_hash"] = "0" * 64
        drift["content_hash"] = HostSnapshot.compute_document_hash(drift)
        with self.assertRaisesRegex(ControllerContractError, "host_snapshot_interpreter_drift"):
            HostSnapshot.from_document(drift)

    def test_numeric_principal_collisions_are_observable_but_never_adopted(self) -> None:
        baseline = make_empty_host_snapshot("snap-numeric-collision", observed_generation=0)
        collision = PrincipalObservation(
            present=False,
            account="worldforge-ollama-evidence",
            uid=None,
            gid=None,
            primary_group="worldforge-ollama-evidence",
            dedicated_non_login=False,
            supplementary_groups=(),
            owned_by_operation=False,
            uid_owner_account="foreign-account",
            gid_owner_group="foreign-group",
        )
        collided = dataclasses.replace(baseline, principal=collision)
        with self.assertRaisesRegex(ControllerContractError, "plan_precondition_not_empty"):
            build_controller_plan(
                collided,
                _manifest("release_final"),
                dataclasses.replace(
                    _manifest("model_final"),
                    entries=(_file("model.gguf", b"model"),),
                ),
                operation_id="op-numeric-collision",
            )
        with self.assertRaisesRegex(
            ControllerContractError,
            "principal_observation_ambient_resource",
        ):
            PrincipalObservation(
                present=False,
                account="worldforge-ollama-evidence",
                uid=None,
                gid=None,
                primary_group="worldforge-ollama-evidence",
                dedicated_non_login=False,
                supplementary_groups=(),
                owned_by_operation=False,
                uid_owner_account="ollama",
                gid_owner_group="foreign-group",
            )

    def test_deterministic_plan_binds_exact_order_destinations_and_payloads(self) -> None:
        baseline = make_empty_host_snapshot("snap-plan-baseline", observed_generation=3)
        release = _manifest("release_final")
        model = dataclasses.replace(
            _manifest("model_final"),
            entries=(_file("model.gguf", b"exact-model"),),
        )

        first = build_controller_plan(
            baseline,
            release,
            model,
            operation_id="op-contract-plan",
        )
        second = build_controller_plan(
            HostSnapshot.from_document(baseline.to_document()),
            BoundedTreeManifest.from_document(release.to_document()),
            BoundedTreeManifest.from_document(model.to_document()),
            operation_id="op-contract-plan",
        )

        self.assertEqual(first, second)
        self.assertEqual(9, len(first.effects))
        self.assertEqual(
            (
                "managed_root.create",
                "principal.create_exact",
                "release.stage",
                "release.publish",
                "model.stage",
                "model.publish",
                "socket.install",
                "service.install",
                "manager.reload",
            ),
            tuple(effect.kind for effect in first.effects),
        )
        self.assertEqual(tuple(range(9)), tuple(effect.ordinal for effect in first.effects))
        self.assertEqual(CONTROLLER_UID, first.uid)
        self.assertEqual(CONTROLLER_GID, first.gid)
        self.assertEqual("prepared_unverified", first.terminal_apply_state)
        self.assertFalse(first.production_eligible)
        self.assertEqual(first, ControllerPlan.from_document(first.to_document()))

        populated = project_effect(baseline, first, first.effects[0], "op-contract-plan")
        with self.assertRaisesRegex(ControllerContractError, "plan_precondition_not_empty"):
            build_controller_plan(
                populated,
                release,
                model,
                operation_id="op-contract-populated",
            )

    def test_operation_token_binds_effects_and_every_owned_host_resource(self) -> None:
        baseline = make_empty_host_snapshot("snap-owner-baseline", observed_generation=0)
        plan = build_controller_plan(
            baseline,
            _manifest("release_final"),
            dataclasses.replace(
                _manifest("model_final"),
                entries=(_file("model.gguf", b"model"),),
            ),
            operation_id="op-owner-binding",
        )
        operation = OperationSnapshot.create("op-owner-binding", plan)

        self.assertRegex(operation.ownership_token, r"\Aowner-[0-9a-f]{32}\Z")
        self.assertTrue(
            all(effect.ownership_token == operation.ownership_token for effect in plan.effects)
        )
        projected = baseline
        for effect in plan.effects:
            projected = project_effect(projected, plan, effect, operation.operation_id)
        self.assertEqual(operation.ownership_token, projected.managed_root.ownership_token)
        self.assertEqual(operation.ownership_token, projected.principal.ownership_token)
        self.assertEqual(operation.ownership_token, projected.release_final.ownership_token)
        self.assertEqual(operation.ownership_token, projected.model_final.ownership_token)
        self.assertEqual(operation.ownership_token, projected.socket_unit.ownership_token)
        self.assertEqual(operation.ownership_token, projected.service_unit.ownership_token)
        self.assertEqual(
            operation.ownership_token,
            projected.manager_reload_ownership_token,
        )

    def test_full_rollback_clears_manager_ownership_and_preserves_generation(self) -> None:
        baseline = make_empty_host_snapshot(
            "snap-manager-clean-baseline",
            observed_generation=7,
        )
        plan = build_controller_plan(
            baseline,
            _manifest("release_final"),
            dataclasses.replace(
                _manifest("model_final"),
                entries=(_file("model.gguf", b"model"),),
            ),
            operation_id="op-manager-clean-projection",
        )
        projected = baseline
        for effect in plan.effects:
            projected = project_effect(projected, plan, effect, plan.operation_id)
        self.assertEqual(plan.ownership_token, projected.manager_reload_ownership_token)
        after_apply_generation = projected.manager_reload_generation

        rollback = build_rollback_plan(
            plan.operation_id,
            plan,
            tuple(effect.effect_id for effect in plan.effects),
        )
        for effect in rollback.effects:
            projected = project_effect(projected, plan, effect, plan.operation_id)

        self.assertIsNone(projected.manager_reload_ownership_token)
        self.assertEqual(after_apply_generation + 1, projected.manager_reload_generation)
        self.assertTrue(is_reusable_clean_projection(projected, baseline))

    def test_effect_projection_triangulates_pre_post_and_foreign_classification(self) -> None:
        baseline = make_empty_host_snapshot("snap-effect-baseline", observed_generation=0)
        plan = build_controller_plan(
            baseline,
            _manifest("release_final"),
            dataclasses.replace(
                _manifest("model_final"),
                entries=(_file("model.gguf", b"model"),),
            ),
            operation_id="op-effect",
        )
        effect = plan.effects[0]

        self.assertEqual("precondition", classify_effect_snapshot(baseline, effect))
        applied = project_effect(baseline, plan, effect, "op-effect")
        self.assertEqual("postcondition", classify_effect_snapshot(applied, effect))
        foreign_manifest = dataclasses.replace(
            applied.managed_root,
            root_mode=0o700,
        )
        foreign = dataclasses.replace(
            applied,
            snapshot_id="snap-effect-foreign",
            managed_root=foreign_manifest,
        )
        self.assertEqual("foreign", classify_effect_snapshot(foreign, effect))

    def test_authorization_contracts_bind_exact_single_use_request_and_consumption(self) -> None:
        request = AuthorizationRequest.create(
            operation_id="op-authorization",
            plan_hash="1" * 64,
            effect_id="effect-authorization",
            phase="apply",
            attempt=1,
            expected_generation=2,
            expected_sequence=2,
            expected_head_hash="2" * 64,
            ownership_token="owner-" + "1" * 32,
        )
        consumption = AuthorizationConsumption.create(
            request,
            authority_id="director-authority",
            decision_id="decision-0001",
        )

        self.assertEqual(request, AuthorizationRequest.from_document(request.to_document()))
        self.assertEqual(
            consumption,
            AuthorizationConsumption.from_document(consumption.to_document()),
        )
        self.assertTrue(consumption.matches(request))
        self.assertTrue(consumption.single_use)
        self.assertEqual("authorized", consumption.decision)

        other = dataclasses.replace(request, attempt=2)
        self.assertFalse(consumption.matches(other))
        hostile = consumption.to_document()
        hostile["single_use"] = 1
        hostile["content_hash"] = AuthorizationConsumption.compute_document_hash(hostile)
        with self.assertRaisesRegex(ControllerContractError, "authorization_consumption_invalid"):
            AuthorizationConsumption.from_document(hostile)

    def test_operation_and_rollback_contracts_preserve_only_proven_effect_lineage(self) -> None:
        baseline = make_empty_host_snapshot("snap-operation-baseline", observed_generation=0)
        plan = build_controller_plan(
            baseline,
            _manifest("release_final"),
            dataclasses.replace(
                _manifest("model_final"),
                entries=(_file("model.gguf", b"model"),),
            ),
            operation_id="op-contract-state",
        )
        operation = OperationSnapshot.create("op-contract-state", plan)
        self.assertEqual("apply_pending", operation.state)
        self.assertEqual(operation, OperationSnapshot.from_document(operation.to_document()))
        forged_operation = operation.to_document()
        forged_operation["state"] = "apply_dispatching"
        forged_operation["content_hash"] = OperationSnapshot.compute_document_hash(
            forged_operation
        )
        with self.assertRaisesRegex(ControllerContractError, "operation_snapshot_invalid"):
            OperationSnapshot.from_document(forged_operation)

        applied_ids = tuple(effect.effect_id for effect in plan.effects[:4])
        rollback = build_rollback_plan(operation.operation_id, plan, applied_ids)
        self.assertEqual(4, len(rollback.source_applied_effect_ids))
        self.assertEqual(
            (
                "release.unpublish_exact",
                "release.unstage_exact",
                "principal.remove_exact",
                "managed_root.remove_exact",
            ),
            tuple(effect.kind for effect in rollback.effects),
        )
        self.assertEqual(rollback, RollbackPlan.from_document(rollback.to_document()))

        forged = rollback.to_document()
        forged["rollback_id"] = "rollback-" + "0" * 32
        forged["content_hash"] = RollbackPlan.compute_document_hash(forged)
        with self.assertRaisesRegex(ControllerContractError, "rollback_plan_invalid"):
            RollbackPlan.from_document(forged)

        with self.assertRaisesRegex(ControllerContractError, "rollback_lineage_invalid"):
            build_rollback_plan(
                operation.operation_id,
                plan,
                (*applied_ids, "effect-not-from-plan"),
            )

    def test_all_documents_are_canonical_json_and_bool_is_never_an_integer(self) -> None:
        baseline = make_empty_host_snapshot("snap-json-baseline", observed_generation=0)
        encoded = canonical_controller_bytes(baseline.to_document())
        self.assertEqual(encoded, canonical_controller_bytes(copy.deepcopy(baseline.to_document())))
        self.assertNotIn(b" ", encoded)

        hostile = baseline.to_document()
        hostile["observed_generation"] = True
        hostile["content_hash"] = HostSnapshot.compute_document_hash(hostile)
        with self.assertRaisesRegex(ControllerContractError, "host_snapshot_invalid"):
            HostSnapshot.from_document(hostile)


if __name__ == "__main__":
    unittest.main()
