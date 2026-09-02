from __future__ import annotations

import copy
import dataclasses
import hashlib
import unittest

from worldforge.provider_evidence.ollama_v2_controller_contracts import (
    AuthorizationConsumption,
    AuthorizationRejection,
    AuthorizationRequest,
    CONTROLLER_GID,
    CONTROLLER_UID,
    MAX_DOCUMENT_BYTES,
    MAX_ENTRY_BYTES,
    MAX_TREE_BYTES,
    MAX_TREE_ENTRIES,
    MODEL_FINAL_ROOT,
    RELEASE_FINAL_ROOT,
    BoundedTreeManifest,
    ManifestEntry,
    OperationSnapshot,
    build_controller_plan,
    build_rollback_plan,
    make_empty_host_snapshot,
)
from worldforge.studio.ollama_v2_authorization_contracts import (
    StudioOllamaV2AuthorizationContractError,
    StudioOllamaV2AuthorizationDecision,
    StudioOllamaV2AuthorizationEventEvidence,
    StudioOllamaV2AuthorizationImpact,
    StudioOllamaV2AuthorizationReview,
    StudioOllamaV2AuthorizationSnapshot,
    build_ollama_v2_authorization_review,
    exact_authorization_outcome,
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


def _plan():
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
    snapshot = make_empty_host_snapshot("snap-studio-auth", observed_generation=0)
    return build_controller_plan(snapshot, release, model, operation_id="op-studio-auth")


class StudioOllamaV2AuthorizationContractTests(unittest.TestCase):
    def test_apply_review_is_frozen_canonical_detached_and_fully_derived(self) -> None:
        plan = _plan()
        operation = OperationSnapshot.create(plan.operation_id, plan)
        review = build_ollama_v2_authorization_review(operation, plan, phase="apply")

        self.assertTrue(dataclasses.is_dataclass(review))
        self.assertFalse(hasattr(review, "__dict__"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            review.phase = "rollback"  # type: ignore[misc]
        self.assertEqual("apply", review.phase)
        self.assertEqual(operation.to_document(), review.starting_snapshot_document)
        self.assertEqual(plan.to_document(), review.plan_document)
        self.assertIsNone(review.rollback_plan_document)
        self.assertEqual(tuple(effect.effect_id for effect in plan.effects), review.effect_ids)
        self.assertEqual(
            tuple(effect.content_hash for effect in plan.effects), review.effect_hashes
        )
        self.assertEqual("not_applicable", review.impact.pricing_applicability)
        self.assertEqual("prohibited", review.impact.network_egress)
        self.assertEqual(review.impact.resource_ids, review.impact.data_destinations)
        self.assertEqual(review.impact.effect_kinds, review.impact.permissions)
        self.assertEqual(1, review.impact.controller_contract_version)
        self.assertEqual(MAX_DOCUMENT_BYTES, review.impact.maximum_document_bytes)
        self.assertEqual(MAX_TREE_ENTRIES, review.impact.maximum_tree_entries)
        self.assertEqual(MAX_ENTRY_BYTES, review.impact.maximum_entry_bytes)
        self.assertEqual(MAX_TREE_BYTES, review.impact.maximum_tree_bytes)
        self.assertEqual(32, review.impact.maximum_effect_count)
        self.assertIn("sealed_model_manifest", review.impact.data_sources)
        self.assertFalse(review.impact.production_eligible)
        self.assertFalse(review.impact.native_evidence)

        document = review.to_document()
        rebuilt = StudioOllamaV2AuthorizationReview.from_document(copy.deepcopy(document))
        self.assertEqual(review, rebuilt)
        document["phase"] = "rollback"
        self.assertEqual("apply", rebuilt.phase)

    def test_review_rejects_empty_scope_wrong_types_and_document_drift(self) -> None:
        plan = _plan()
        operation = OperationSnapshot.create(plan.operation_id, plan)
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            build_ollama_v2_authorization_review(True, plan, phase="apply")
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            build_ollama_v2_authorization_review(operation, copy.copy(plan), phase="rollback")

        review = build_ollama_v2_authorization_review(operation, plan, phase="apply")
        hostile = review.to_document()
        hostile["unexpected"] = "field"
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            StudioOllamaV2AuthorizationReview.from_document(hostile)

        applied_effect_ids = tuple(effect.effect_id for effect in plan.effects)
        exhausted_apply = dataclasses.replace(
            operation,
            apply_cursor=len(plan.effects),
            applied_effect_ids=applied_effect_ids,
        )
        self.assertEqual(
            exhausted_apply,
            OperationSnapshot.from_document(exhausted_apply.to_document()),
        )
        with self.assertRaisesRegex(
            StudioOllamaV2AuthorizationContractError,
            "ollama_v2_authorization_scope_empty",
        ):
            build_ollama_v2_authorization_review(
                exhausted_apply,
                plan,
                phase="apply",
            )

        rollback = build_rollback_plan(plan.operation_id, plan, ())
        exhausted_rollback = dataclasses.replace(
            operation,
            state="rollback_pending",
            rollback_plan_hash=rollback.content_hash,
        )
        self.assertEqual(
            exhausted_rollback,
            OperationSnapshot.from_document(exhausted_rollback.to_document()),
        )
        with self.assertRaisesRegex(
            StudioOllamaV2AuthorizationContractError,
            "ollama_v2_authorization_scope_empty",
        ):
            build_ollama_v2_authorization_review(
                exhausted_rollback,
                plan,
                phase="rollback",
                rollback_plan=rollback,
            )
        hostile = review.to_document()
        hostile["effect_ids"] = list(reversed(hostile["effect_ids"]))
        hostile["content_hash"] = StudioOllamaV2AuthorizationReview.compute_document_hash(hostile)
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            StudioOllamaV2AuthorizationReview.from_document(hostile)

    def test_decision_and_snapshot_are_closed_and_reject_bool_as_integer(self) -> None:
        plan = _plan()
        operation = OperationSnapshot.create(plan.operation_id, plan)
        review = build_ollama_v2_authorization_review(operation, plan, phase="apply")
        approved = StudioOllamaV2AuthorizationDecision.create(
            review, outcome="approved", expires_at_ms=10_000
        )
        self.assertEqual(
            approved,
            StudioOllamaV2AuthorizationDecision.from_document(approved.to_document()),
        )
        snapshot = StudioOllamaV2AuthorizationSnapshot(
            review=review,
            decision=approved,
            generation=1,
            durable_state="approved",
            consumed_slots=0,
            total_slots=len(review.effect_ids),
            status="consumable",
            next_effect_id=review.effect_ids[0],
        )
        self.assertEqual("consumable", snapshot.to_document()["status"])
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            StudioOllamaV2AuthorizationDecision.create(
                review, outcome="approved", expires_at_ms=True
            )
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            StudioOllamaV2AuthorizationDecision.create(
                review, outcome="denied", expires_at_ms=10_000
            )

    def test_direct_contract_construction_rejects_subclasses_and_malformed_evidence(
        self,
    ) -> None:
        class StringSubclass(str):
            pass

        plan = _plan()
        operation = OperationSnapshot.create(plan.operation_id, plan)
        review = build_ollama_v2_authorization_review(operation, plan, phase="apply")
        first_kind = review.impact.effect_kinds[0]
        first_resource = review.impact.resource_ids[0]
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            dataclasses.replace(
                review.impact,
                effect_count=True,
                effect_kinds=(first_kind,),
                resource_ids=(first_resource,),
                data_destinations=(first_resource,),
                permissions=(first_kind,),
            )
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            dataclasses.replace(review.impact, phase=StringSubclass("apply"))
        hostile_review = review.to_document()
        hostile_review["format"] = StringSubclass(hostile_review["format"])
        hostile_review["content_hash"] = StudioOllamaV2AuthorizationReview.compute_document_hash(
            hostile_review
        )
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            StudioOllamaV2AuthorizationReview.from_document(hostile_review)
        hostile_review = review.to_document()
        hostile_review["phase"] = []
        hostile_review["content_hash"] = StudioOllamaV2AuthorizationReview.compute_document_hash(
            hostile_review
        )
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            StudioOllamaV2AuthorizationReview.from_document(hostile_review)

        approved = StudioOllamaV2AuthorizationDecision.create(
            review, outcome="approved", expires_at_ms=10_000
        )
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            StudioOllamaV2AuthorizationDecision.create(
                review,
                outcome=StringSubclass("approved"),
                expires_at_ms=10_000,
            )
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            dataclasses.replace(approved, reviewer_id=StringSubclass("director_local"))

        snapshot = StudioOllamaV2AuthorizationSnapshot(
            review=review,
            decision=approved,
            generation=1,
            durable_state="approved",
            consumed_slots=0,
            total_slots=len(review.effect_ids),
            status="consumable",
            next_effect_id=review.effect_ids[0],
        )
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            dataclasses.replace(snapshot, status=StringSubclass("consumable"))
        with self.assertRaises(StudioOllamaV2AuthorizationContractError):
            StudioOllamaV2AuthorizationEventEvidence(
                event_id=1,
                mandate_id=review.mandate_id,
                generation=0,
                event_type="prepared",
                slot_ordinal=0,
                content_hash="0" * 64,
                previous_hash="0" * 64,
                mac=b"0" * 32,
                created_at="not-a-timestamp",
            )

        self.assertIsInstance(review.impact, StudioOllamaV2AuthorizationImpact)

    def test_terminal_expired_snapshot_and_rejected_event_are_exact(self) -> None:
        plan = _plan()
        operation = OperationSnapshot.create(plan.operation_id, plan)
        review = build_ollama_v2_authorization_review(operation, plan, phase="apply")
        approved = StudioOllamaV2AuthorizationDecision.create(
            review,
            outcome="approved",
            expires_at_ms=10_000,
        )
        expired = StudioOllamaV2AuthorizationSnapshot(
            review=review,
            decision=approved,
            generation=2,
            durable_state="expired",
            consumed_slots=0,
            total_slots=len(review.effect_ids),
            status="expired",
            next_effect_id=None,
        )
        self.assertEqual("expired", expired.to_document()["durable_state"])
        rejected = StudioOllamaV2AuthorizationEventEvidence(
            event_id=4,
            mandate_id=review.mandate_id,
            generation=2,
            event_type="rejected",
            slot_ordinal=0,
            content_hash="1" * 64,
            previous_hash="2" * 64,
            mac=b"m" * 32,
            created_at="2026-09-02T12:00:00.000000Z",
        )
        self.assertEqual("rejected", rejected.event_type)
        for changes in (
            {"generation": True},
            {"slot_ordinal": None},
            {"event_type": str.__new__(type("S", (str,), {}), "rejected")},
        ):
            with self.subTest(changes=changes), self.assertRaises(
                StudioOllamaV2AuthorizationContractError
            ):
                dataclasses.replace(rejected, **changes)

        self.assertTrue(hasattr(AuthorizationRejection, "create"))

    def test_terminal_outcome_normalizer_preserves_exact_base_type_and_hash(self) -> None:
        plan = _plan()
        operation = OperationSnapshot.create(plan.operation_id, plan)
        review = build_ollama_v2_authorization_review(operation, plan, phase="apply")
        decision = StudioOllamaV2AuthorizationDecision.create(
            review,
            outcome="approved",
            expires_at_ms=10_000,
        )
        request = AuthorizationRequest.create(
            operation_id=operation.operation_id,
            plan_hash=operation.plan_hash,
            effect_id=plan.effects[0].effect_id,
            phase="apply",
            attempt=operation.next_attempt,
            expected_generation=operation.generation,
            expected_sequence=operation.sequence,
            expected_head_hash=operation.event_head_hash,
            ownership_token=operation.ownership_token,
        )
        consumption = AuthorizationConsumption.create(
            request,
            authority_id="studio_director_ollama_v2",
            decision_id=decision.decision_id,
        )
        rejection = AuthorizationRejection.create(
            request,
            authority_id="studio_director_ollama_v2",
            mandate_id=review.mandate_id,
            decision_id=decision.decision_id,
            slot_ordinal=0,
            effect_hash=plan.effects[0].content_hash,
            reason="revoked",
            settlement_event_id=4,
            settlement_event_hash="3" * 64,
        )
        for outcome in (consumption, rejection):
            with self.subTest(outcome=type(outcome).__name__):
                exact = exact_authorization_outcome(outcome)
                self.assertIs(type(outcome), type(exact))
                self.assertEqual(outcome, exact)
                self.assertEqual(outcome.content_hash, exact.content_hash)

        class ConsumptionSubclass(AuthorizationConsumption):
            pass

        for hostile in (True, object.__new__(ConsumptionSubclass)):
            with self.subTest(hostile=type(hostile).__name__), self.assertRaises(
                StudioOllamaV2AuthorizationContractError
            ):
                exact_authorization_outcome(hostile)


if __name__ == "__main__":
    unittest.main()
