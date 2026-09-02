from __future__ import annotations

import ast
import dataclasses
import hashlib
import typing
import unittest
from pathlib import Path

from worldforge.provider_evidence import ollama_v2_native_execution_contracts as d21
from worldforge.provider_evidence.ollama_v2_controller_contracts import (
    APPLY_EFFECT_KINDS,
    CONTROLLER_GID,
    CONTROLLER_UID,
    MODEL_FINAL_ROOT,
    RELEASE_FINAL_ROOT,
    ROLLBACK_EFFECT_KINDS,
    AuthorizationConsumption,
    AuthorizationRequest,
    BoundedTreeManifest,
    ManifestEntry,
    build_controller_plan,
    build_rollback_plan,
    make_empty_host_snapshot,
    project_effect,
)
from worldforge.provider_evidence.ollama_v2_native_execution_contracts import (
    AVAILABILITY,
    CATALOG_ADMITTED,
    CUSTODY_LEDGER_NAME,
    CUSTODY_LOCK_NAME,
    CUSTODY_SCOPE,
    CUSTODY_TARGET_ROOT,
    DEPLOYMENT_BINDING,
    HOST_EXECUTION_ENABLED,
    NATIVE_IMPLEMENTATION_STATE,
    PRODUCTION_ELIGIBLE,
    PROVIDER_EXECUTION_ENABLED,
    ROOT_GLOBAL_ENFORCED,
    SOURCE_CUSTODY_VERIFIED,
    OllamaV2C2AuthorizationReferenceD2,
    OllamaV2CustodyLedgerRecordD2,
    OllamaV2NativeReservationD2,
    OllamaV2DispatchEnvelopeD2,
    OllamaV2NativeInstallationAttestationD2,
    OllamaV2NativeBundleEntryV1,
    OllamaV2NativeBundleManifestV1,
    OllamaV2ManagerReloadWitnessD2,
    OllamaV2MutationAckD2,
    OllamaV2NativeExecutionBindingD2,
    OllamaV2NativeExecutionContractError,
    OllamaV2NativeExecutionPolicyD2,
    OllamaV2NativeResourceScopeD2,
    OllamaV2SourceBundleDescriptorD2,
    canonical_ollama_v2_native_execution_bytes,
    canonical_ollama_v2_native_execution_policy_d2,
    canonical_ollama_v2_native_resource_scope_d2,
    parse_ollama_v2_native_execution_contract,
)


ZERO_HASH = "0" * 64


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


def _manifest(purpose: str, suffix: str) -> BoundedTreeManifest:
    root = RELEASE_FINAL_ROOT if purpose == "release_final" else MODEL_FINAL_ROOT
    if purpose == "release_final":
        entries = (
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
            _file("bin/ollama", f"synthetic-release-{suffix}".encode()),
        )
    else:
        entries = (_file("model.gguf", f"synthetic-model-{suffix}".encode()),)
    return BoundedTreeManifest(
        purpose=purpose,
        root_path=root,
        root_mode=0o555,
        uid=CONTROLLER_UID,
        gid=CONTROLLER_GID,
        sealed=True,
        entries=entries,
    )


def _materials(
    suffix: str,
    *,
    effect_ordinal: int = 0,
    phase: str = "apply",
    controller_sequence: int = 7,
    previous_fence_sequence: int = 8,
    current_controller_sequence: int | None = None,
) -> dict[str, object]:
    baseline = make_empty_host_snapshot(
        f"snap-d21-{suffix}",
        observed_generation=2,
    )
    controller_plan = build_controller_plan(
        baseline,
        _manifest("release_final", suffix),
        _manifest("model_final", suffix),
        operation_id=f"op-d21-{suffix}",
    )
    if phase == "apply":
        plan = controller_plan
        before = baseline
    elif phase == "rollback":
        before = baseline
        for applied in controller_plan.effects:
            before = project_effect(
                before,
                controller_plan,
                applied,
                controller_plan.operation_id,
            )
        plan = build_rollback_plan(
            controller_plan.operation_id,
            controller_plan,
            tuple(effect.effect_id for effect in controller_plan.effects),
        )
    else:
        raise AssertionError(f"unsupported test phase: {phase}")
    effect = plan.effects[effect_ordinal]
    for prior in plan.effects[:effect_ordinal]:
        before = project_effect(
            before,
            controller_plan,
            prior,
            controller_plan.operation_id,
        )
    controller_head_hash = (
        ZERO_HASH
        if controller_sequence == 0
        else hashlib.sha256(f"controller-head-{suffix}".encode()).hexdigest()
    )
    request = AuthorizationRequest.create(
        operation_id=plan.operation_id,
        plan_hash=plan.content_hash,
        effect_id=effect.effect_id,
        phase=effect.phase,
        attempt=1,
        expected_generation=3,
        expected_sequence=controller_sequence,
        expected_head_hash=controller_head_hash,
        ownership_token=plan.ownership_token,
    )
    c1_consumption = AuthorizationConsumption.create(
        request,
        authority_id=f"studio-c1-{suffix}",
        decision_id=f"decision-c1-{suffix}",
    )
    scope = canonical_ollama_v2_native_resource_scope_d2()
    policy = canonical_ollama_v2_native_execution_policy_d2()
    manifest = OllamaV2NativeBundleManifestV1.create(
        (
            OllamaV2NativeBundleEntryV1(
                logical_path="broker/main.py",
                artifact_role="broker-entrypoint",
                size_bytes=17 + len(suffix),
                sha256=hashlib.sha256(f"broker-source-{suffix}".encode()).hexdigest(),
                executable=False,
            ),
            OllamaV2NativeBundleEntryV1(
                logical_path="policy/native-contract.json",
                artifact_role="policy-document",
                size_bytes=23 + len(suffix),
                sha256=hashlib.sha256(f"policy-source-{suffix}".encode()).hexdigest(),
                executable=False,
            ),
        )
    )
    installation = OllamaV2NativeInstallationAttestationD2.create(
        scope,
        policy,
        manifest,
        installation_receipt_hash=hashlib.sha256(
            f"supplied-installation-receipt-{suffix}".encode()
        ).hexdigest(),
        installed_runtime_bundle_hash=hashlib.sha256(
            f"supplied-installed-bundle-{suffix}".encode()
        ).hexdigest(),
    )
    projected_source_manifest = (
        {
            "release.stage": controller_plan.release_manifest,
            "model.stage": controller_plan.model_manifest,
        }.get(effect.kind)
        if phase == "apply"
        else None
    )
    source = (
        None
        if projected_source_manifest is None
        else OllamaV2SourceBundleDescriptorD2.create(
            projected_source_manifest,
            source_label=f"source-{suffix}",
            source_revision=f"revision-{suffix}",
            future_receipt_identity_hash=hashlib.sha256(
                f"future-custody-receipt-{suffix}".encode()
            ).hexdigest(),
        )
    )
    binding_arguments = {
        "plan": plan,
        "effect": effect,
        "authorization_request": request,
        "c1_consumption": c1_consumption,
        "controller_generation": request.expected_generation,
        "controller_sequence": request.expected_sequence,
        "controller_head_hash": request.expected_head_hash,
        "before_snapshot": before,
        "resource_scope": scope,
        "policy": policy,
        "native_bundle_manifest": manifest,
        "source_bundle_descriptor": source,
        "installation_attestation": installation,
    }
    binding = OllamaV2NativeExecutionBindingD2.create(**binding_arguments)
    reservation = OllamaV2NativeReservationD2.create(
        binding,
        fence_generation=4,
        previous_fence_sequence=previous_fence_sequence,
        previous_fence_hash=(
            ZERO_HASH
            if previous_fence_sequence == 0
            else hashlib.sha256(f"previous-fence-{suffix}".encode()).hexdigest()
        ),
    )
    c2 = OllamaV2C2AuthorizationReferenceD2.create(
        binding,
        reservation,
        review_id=f"review-c2-{suffix}",
        review_hash=hashlib.sha256(f"review-c2-{suffix}".encode()).hexdigest(),
        decision_id=f"decision-c2-{suffix}",
        decision_hash=hashlib.sha256(f"decision-c2-{suffix}".encode()).hexdigest(),
        consumption_id=f"consume-c2-{suffix}",
        consumption_hash=hashlib.sha256(f"consume-c2-{suffix}".encode()).hexdigest(),
    )
    if current_controller_sequence is None:
        current_controller_sequence = controller_sequence + 1
    current_controller_head_hash = (
        ZERO_HASH
        if current_controller_sequence == 0
        else hashlib.sha256(f"current-controller-head-{suffix}".encode()).hexdigest()
    )
    dispatch = OllamaV2DispatchEnvelopeD2.create(
        binding,
        reservation,
        c2,
        current_controller_generation=3,
        current_controller_sequence=current_controller_sequence,
        current_controller_head_hash=current_controller_head_hash,
    )
    ack = OllamaV2MutationAckD2.create(
        dispatch,
        correlation_hash=hashlib.sha256(f"correlation-{suffix}".encode()).hexdigest(),
        acknowledged_at_ms=1_800_000_000_000 + len(suffix),
    )
    return {
        "baseline": baseline,
        "before": before,
        "controller_plan": controller_plan,
        "plan": plan,
        "effect": effect,
        "request": request,
        "c1": c1_consumption,
        "scope": scope,
        "policy": policy,
        "manifest": manifest,
        "source": source,
        "installation": installation,
        "binding_arguments": binding_arguments,
        "binding": binding,
        "reservation": reservation,
        "c2": c2,
        "dispatch": dispatch,
        "ack": ack,
    }


def _rederive_document_id(
    document: dict[str, object],
    *,
    identifier_field: str,
    prefix: str,
    contract_type: type,
) -> dict[str, object]:
    seed = {
        key: value
        for key, value in document.items()
        if key not in {"format", "format_version", "content_hash", identifier_field}
    }
    document[identifier_field] = prefix + hashlib.sha256(
        canonical_ollama_v2_native_execution_bytes(seed)
    ).hexdigest()[:32]
    document["content_hash"] = contract_type.compute_document_hash(document)
    return document


class D21NativeExecutionContractTests(unittest.TestCase):
    def test_fixed_policy_scope_and_status_are_exact_and_non_native(self) -> None:
        scope = canonical_ollama_v2_native_resource_scope_d2()
        policy = canonical_ollama_v2_native_execution_policy_d2()

        self.assertEqual(CUSTODY_SCOPE, scope.scope_id)
        self.assertEqual(CUSTODY_TARGET_ROOT, scope.custody_target_root)
        self.assertEqual(CUSTODY_LEDGER_NAME, scope.ledger_name)
        self.assertEqual(CUSTODY_LOCK_NAME, scope.lock_name)
        self.assertEqual(scope.content_hash, policy.resource_scope_hash)
        self.assertEqual("unbound", DEPLOYMENT_BINDING)
        self.assertFalse(ROOT_GLOBAL_ENFORCED)
        self.assertFalse(SOURCE_CUSTODY_VERIFIED)
        self.assertFalse(HOST_EXECUTION_ENABLED)
        self.assertEqual("absent", NATIVE_IMPLEMENTATION_STATE)
        self.assertEqual("unavailable", AVAILABILITY)
        self.assertFalse(PRODUCTION_ELIGIBLE)
        self.assertFalse(CATALOG_ADMITTED)
        self.assertFalse(PROVIDER_EXECUTION_ENABLED)
        self.assertEqual(DEPLOYMENT_BINDING, policy.deployment_binding)
        self.assertFalse(policy.root_global_enforced)
        self.assertFalse(policy.source_custody_verified)
        self.assertFalse(policy.host_execution_enabled)
        self.assertFalse(policy.production_eligible)
        self.assertFalse(policy.catalog_admitted)
        self.assertFalse(policy.provider_execution_enabled)
        installation = _materials("status")["installation"]
        self.assertEqual("supplied_unverified", installation.attestation_state)

        for contract in (scope, policy):
            with self.subTest(contract=type(contract).__name__):
                self.assertTrue(dataclasses.is_dataclass(contract))
                self.assertFalse(hasattr(contract, "__dict__"))
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    setattr(contract, dataclasses.fields(contract)[0].name, "changed")

    def test_canonical_round_trip_is_exact_for_independent_values(self) -> None:
        first = _materials("alpha", effect_ordinal=2)
        second = _materials("bravo", effect_ordinal=2)
        observed = first["baseline"]
        record = OllamaV2CustodyLedgerRecordD2.create(
            first["binding"],
            first["reservation"],
            first["dispatch"],
            first["ack"],
            observed_snapshot=observed,
            reload_witness=None,
        )
        contracts = (
            first["scope"],
            first["policy"],
            first["manifest"],
            first["source"],
            first["installation"],
            first["binding"],
            first["reservation"],
            first["c2"],
            first["dispatch"],
            first["ack"],
            record,
        )
        for contract in contracts:
            with self.subTest(contract=type(contract).__name__):
                encoded = contract.to_bytes()
                self.assertEqual(
                    encoded,
                    canonical_ollama_v2_native_execution_bytes(contract.to_document()),
                )
                self.assertEqual(contract, parse_ollama_v2_native_execution_contract(encoded))
                self.assertRegex(contract.content_hash, r"\A[0-9a-f]{64}\Z")
                self.assertIsNot(contract.to_document(), contract.to_document())
                self.assertTrue(dataclasses.is_dataclass(contract))
                self.assertFalse(hasattr(contract, "__dict__"))

        self.assertNotEqual(first["binding"].content_hash, second["binding"].content_hash)
        self.assertNotEqual(first["dispatch"].content_hash, second["dispatch"].content_hash)

    def test_canonical_vector_hashes_are_literal_compatibility_pins(self) -> None:
        material = _materials("vector")
        vectors = {
            "OllamaV2NativeResourceScopeD2": (
                canonical_ollama_v2_native_resource_scope_d2(),
                "6f685f8fff66686efd9bd454ee5bae29e91801df9e295b0741661d91c75a492d",
                "6b68b8bc05b263b2bef4870a1d8947848a1313f704779a9a1c41cb120dcf2b91",
            ),
            "OllamaV2NativeExecutionPolicyD2": (
                canonical_ollama_v2_native_execution_policy_d2(),
                "b8f090b8bda2083dda685870579ecd2f4dea1024724b318a461bfbd65a813af8",
                "8250ecbca795a69be1c4c4444a25c98089687fd1fbb18f852624a26c077c6741",
            ),
            "OllamaV2NativeExecutionBindingD2": (
                material["binding"],
                "dc6e0c8514d6c224f3c492d2df6847ec41b75402e530a6b345537f22a848c29e",
                "994046168b740ce2b5aa877947871e9deb799d48e2baec10be2fbf32297f0e94",
            ),
            "OllamaV2DispatchEnvelopeD2": (
                material["dispatch"],
                "a8c96e4d886b3496036761061d450dc82526b1c60181bcb67f6786da2968ab52",
                "63103229501bc1f385ade18fa850f97a0677f04154d6b55ae57564925c6a8662",
            ),
            "OllamaV2MutationAckD2": (
                material["ack"],
                "f88c45c4d3b3756ef98e905c183db1c2396769a8fe1f78761147437acc2d63b0",
                "be6f322caa35a6ebb9513ae5ef3c97b3ba8d724c39403db21165eec99210bf9e",
            ),
        }
        for name, (contract, content_hash, serialized_hash) in vectors.items():
            with self.subTest(contract=name):
                self.assertEqual(content_hash, contract.content_hash)
                self.assertEqual(serialized_hash, hashlib.sha256(contract.to_bytes()).hexdigest())

    def test_contract_graph_is_acyclic_and_c2_is_required_for_final_dispatch(self) -> None:
        material = _materials("graph")
        binding_fields = {
            field.name for field in dataclasses.fields(OllamaV2NativeExecutionBindingD2)
        }
        c2_fields = {field.name for field in dataclasses.fields(OllamaV2C2AuthorizationReferenceD2)}
        dispatch_fields = {field.name for field in dataclasses.fields(OllamaV2DispatchEnvelopeD2)}

        self.assertFalse(any("c2" in name for name in binding_fields))
        self.assertFalse(any("dispatch" in name for name in binding_fields))
        self.assertFalse(any("reservation" in name for name in binding_fields))
        self.assertIn("execution_binding_hash", c2_fields)
        self.assertIn("reservation_hash", c2_fields)
        self.assertEqual(
            {"execution_binding", "reservation", "c2_authorization"},
            {
                name
                for name in dispatch_fields
                if name in {"execution_binding", "reservation", "c2_authorization"}
            },
        )
        self.assertTrue(
            {
                "plan_hash",
                "native_bundle_manifest_hash",
                "binding_controller_generation",
                "source_manifest_hash",
                "c1_consumption_hash",
                "fence_generation",
                "c2_consumption_hash",
            }.isdisjoint(dispatch_fields)
        )
        self.assertEqual(
            material["binding"].c1_consumption_hash,
            material["dispatch"].c1_consumption_hash,
        )
        self.assertEqual(
            material["c2"].consumption_hash,
            material["dispatch"].c2_consumption_hash,
        )

        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "dispatch_c2_authorization_missing",
        ):
            OllamaV2DispatchEnvelopeD2.create(
                material["binding"],
                material["reservation"],
                None,
                current_controller_generation=3,
                current_controller_sequence=8,
                current_controller_head_hash="a" * 64,
            )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2DispatchEnvelopeD2.create(
                material["binding"],
                material["reservation"],
                material["c1"],  # type: ignore[arg-type]
                current_controller_generation=3,
                current_controller_sequence=8,
                current_controller_head_hash="a" * 64,
            )

    def test_every_authority_edge_rejects_transplants_and_mismatches(self) -> None:
        first = _materials("transplant-a", effect_ordinal=2)
        second = _materials("transplant-b", effect_ordinal=2)
        base_arguments = dict(first["binding_arguments"])
        hostile_arguments = (
            {"plan": second["plan"]},
            {"effect": second["effect"]},
            {"authorization_request": second["request"]},
            {"c1_consumption": second["c1"]},
            {"source_bundle_descriptor": second["source"]},
            {"installation_attestation": second["installation"]},
            {"controller_head_hash": "f" * 64},
        )
        for change in hostile_arguments:
            with self.subTest(change=tuple(change)), self.assertRaises(
                OllamaV2NativeExecutionContractError
            ):
                OllamaV2NativeExecutionBindingD2.create(**(base_arguments | change))

        binding_document = first["binding"].to_document()
        binding_document["policy_hash"] = "f" * 64
        binding_document["content_hash"] = OllamaV2NativeExecutionBindingD2.compute_document_hash(
            binding_document
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeExecutionBindingD2.from_document(binding_document)

        for reservation, c2 in (
            (second["reservation"], first["c2"]),
            (first["reservation"], second["c2"]),
        ):
            with self.subTest(
                reservation=reservation.reservation_id,
                c2=c2.reference_id,
            ), self.assertRaises(OllamaV2NativeExecutionContractError):
                OllamaV2DispatchEnvelopeD2.create(
                    first["binding"],
                    reservation,
                    c2,
                    current_controller_generation=3,
                    current_controller_sequence=8,
                    current_controller_head_hash="e" * 64,
                )

        for nested_fields in (
            ("execution_binding",),
            ("execution_binding", "reservation"),
            ("reservation", "c2_authorization"),
        ):
            document = first["dispatch"].to_document()
            foreign_document = second["dispatch"].to_document()
            for field_name in nested_fields:
                document[field_name] = foreign_document[field_name]
            _rederive_document_id(
                document,
                identifier_field="dispatch_id",
                prefix="dispatch-",
                contract_type=OllamaV2DispatchEnvelopeD2,
            )
            with self.subTest(nested_fields=nested_fields), self.assertRaisesRegex(
                OllamaV2NativeExecutionContractError,
                "dispatch_envelope_d2_invalid",
            ):
                OllamaV2DispatchEnvelopeD2.from_document(document)

        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2DispatchEnvelopeD2.create(
                first["binding"],
                first["reservation"],
                first["c2"],
                current_controller_generation=2,
                current_controller_sequence=99,
                current_controller_head_hash="e" * 64,
            )

    def test_source_descriptor_is_not_custody_proof_and_receipts_do_not_conflate(self) -> None:
        material = _materials("source", effect_ordinal=2)
        manifest = material["plan"].release_manifest
        source = material["source"]
        other_receipt = OllamaV2SourceBundleDescriptorD2.create(
            manifest,
            source_label=source.source_label,
            source_revision=source.source_revision,
            future_receipt_identity_hash="d" * 64,
        )

        self.assertEqual("non_authoritative", source.descriptor_authority)
        self.assertFalse(source.source_custody_verified)
        self.assertNotEqual(source.descriptor_id, other_receipt.descriptor_id)
        self.assertNotEqual(source.content_hash, other_receipt.content_hash)
        self.assertEqual(
            source.projected_manifest_hash,
            other_receipt.projected_manifest_hash,
        )
        self.assertEqual(source.logical_contents_hash, other_receipt.logical_contents_hash)
        self.assertNotIn("source_path", source.to_document())
        self.assertNotIn("absolute_path", source.to_document())

    def test_ack_is_correlation_only_and_snapshot_is_separate(self) -> None:
        material = _materials("ack")
        ack = material["ack"]
        ack_fields = {field.name for field in dataclasses.fields(OllamaV2MutationAckD2)}
        forbidden = {"success", "applied", "outcome", "result", "host_snapshot_hash"}

        self.assertTrue(forbidden.isdisjoint(ack_fields))
        self.assertEqual("correlation_only", ack.acknowledgement_kind)
        self.assertFalse(ack.native_evidence_verified)
        with self.assertRaises(TypeError):
            OllamaV2CustodyLedgerRecordD2.create(  # type: ignore[call-arg]
                material["binding"],
                material["reservation"],
                material["dispatch"],
                ack,
                reload_witness=None,
            )

        record = OllamaV2CustodyLedgerRecordD2.create(
            material["binding"],
            material["reservation"],
            material["dispatch"],
            ack,
            observed_snapshot=material["baseline"],
            reload_witness=None,
        )
        self.assertEqual(material["baseline"].content_hash, record.observed_snapshot_hash)
        self.assertFalse(record.native_outcome_verified)

    def test_reload_generation_and_timestamp_never_claim_pid1_verification(self) -> None:
        material = _materials("reload", effect_ordinal=8)
        after = project_effect(
            material["before"],
            material["plan"],
            material["effect"],
            material["plan"].operation_id,
        )
        witness = OllamaV2ManagerReloadWitnessD2.create(
            material["binding"],
            material["dispatch"],
            material["ack"],
            before_snapshot=material["before"],
            observed_snapshot=after,
            observed_at_ms=1_800_000_001_234,
            manager_observation_hash="b" * 64,
        )

        self.assertEqual("non_native_unverified", witness.witness_kind)
        self.assertFalse(witness.pid1_manager_verified)
        self.assertFalse(witness.native_evidence_verified)
        self.assertEqual(
            witness,
            parse_ollama_v2_native_execution_contract(witness.to_bytes()),
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            dataclasses.replace(witness, pid1_manager_verified=True)
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            dataclasses.replace(witness, native_evidence_verified=True)

        record = OllamaV2CustodyLedgerRecordD2.create(
            material["binding"],
            material["reservation"],
            material["dispatch"],
            material["ack"],
            observed_snapshot=after,
            reload_witness=witness,
        )
        self.assertEqual(witness.content_hash, record.reload_witness_hash)
        self.assertFalse(record.native_outcome_verified)
        self.assertEqual(
            record,
            parse_ollama_v2_native_execution_contract(record.to_bytes()),
        )

    def test_hostile_values_noncanonical_json_and_derived_drift_fail_closed(self) -> None:
        scope = canonical_ollama_v2_native_resource_scope_d2()
        policy = canonical_ollama_v2_native_execution_policy_d2()
        material = _materials("hostile")

        class IntegerSubclass(int):
            pass

        class StringSubclass(str):
            pass

        class TupleSubclass(tuple):
            pass

        class MappingSubclass(dict):
            pass

        for hostile in (True, 1.0, 9_007_199_254_740_992, IntegerSubclass(3)):
            with self.subTest(hostile=hostile), self.assertRaises(
                OllamaV2NativeExecutionContractError
            ):
                dataclasses.replace(scope, controller_uid=hostile)
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            dataclasses.replace(scope, effect_kinds=TupleSubclass(scope.effect_kinds))

        tuple_fields: dict[tuple[type, str], tuple[object, ...]] = {}
        for contract_type in vars(d21).values():
            if (
                type(contract_type) is not type
                or contract_type.__module__ != d21.__name__
                or not dataclasses.is_dataclass(contract_type)
            ):
                continue
            hints = typing.get_type_hints(contract_type)
            for field in dataclasses.fields(contract_type):
                annotation = hints[field.name]
                if typing.get_origin(annotation) is tuple:
                    tuple_fields[(contract_type, field.name)] = typing.get_args(annotation)
        self.assertEqual(
            {
                (OllamaV2NativeResourceScopeD2, "effect_kinds"): (str, Ellipsis),
                (OllamaV2NativeBundleManifestV1, "entries"): (
                    OllamaV2NativeBundleEntryV1,
                    Ellipsis,
                ),
            },
            tuple_fields,
        )
        self.assertEqual(
            {(OllamaV2NativeResourceScopeD2, "effect_kinds")},
            {
                key
                for key, member_types in tuple_fields.items()
                if member_types == (str, Ellipsis)
            },
        )

        scope_values = {
            field.name: getattr(scope, field.name) for field in dataclasses.fields(scope)
        }
        hostile_scope_values = dict(scope_values)
        hostile_scope_values["effect_kinds"] = tuple(
            StringSubclass(value) for value in scope.effect_kinds
        )
        self.assertIs(type(hostile_scope_values["effect_kinds"]), tuple)
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "resource_scope_d2_invalid",
        ):
            OllamaV2NativeResourceScopeD2(**hostile_scope_values)

        exact_scope = OllamaV2NativeResourceScopeD2(**scope_values)
        self.assertEqual(scope, exact_scope)
        self.assertEqual(
            exact_scope,
            OllamaV2NativeResourceScopeD2.from_document(exact_scope.to_document()),
        )
        self.assertEqual(
            exact_scope,
            parse_ollama_v2_native_execution_contract(exact_scope.to_bytes()),
        )
        hostile_scope_document = scope.to_document()
        hostile_scope_document["effect_kinds"] = [
            StringSubclass(value) for value in scope.effect_kinds
        ]
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "native_execution_document_invalid",
        ):
            OllamaV2NativeResourceScopeD2.from_document(hostile_scope_document)

        tuple_manifest = material["manifest"]
        manifest_values = {
            field.name: getattr(tuple_manifest, field.name)
            for field in dataclasses.fields(tuple_manifest)
        }
        exact_manifest = OllamaV2NativeBundleManifestV1(**manifest_values)
        self.assertEqual(tuple_manifest, exact_manifest)
        self.assertEqual(
            exact_manifest,
            OllamaV2NativeBundleManifestV1.from_document(
                exact_manifest.to_document()
            ),
        )
        self.assertEqual(
            exact_manifest,
            parse_ollama_v2_native_execution_contract(exact_manifest.to_bytes()),
        )

        class EntrySubclass(OllamaV2NativeBundleEntryV1):
            pass

        first_entry = tuple_manifest.entries[0]
        hostile_entry = EntrySubclass(
            logical_path=first_entry.logical_path,
            artifact_role=first_entry.artifact_role,
            size_bytes=first_entry.size_bytes,
            sha256=first_entry.sha256,
            executable=first_entry.executable,
        )
        hostile_manifest_values = dict(manifest_values)
        hostile_manifest_values["entries"] = (
            hostile_entry,
            *tuple_manifest.entries[1:],
        )
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "native_bundle_manifest_v1_invalid",
        ):
            OllamaV2NativeBundleManifestV1(**hostile_manifest_values)

        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeBundleManifestV1.create((object(),))  # type: ignore[arg-type]
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeResourceScopeD2.from_document(MappingSubclass(scope.to_document()))
        for field_name, hostile in (
            ("controller_generation", IntegerSubclass(3)),
            ("controller_sequence", IntegerSubclass(7)),
            (
                "controller_head_hash",
                StringSubclass(material["request"].expected_head_hash),
            ),
        ):
            arguments = dict(material["binding_arguments"])
            arguments[field_name] = hostile
            with self.subTest(binding_create_field=field_name), self.assertRaisesRegex(
                OllamaV2NativeExecutionContractError,
                "native_execution_binding_d2_invalid",
            ):
                OllamaV2NativeExecutionBindingD2.create(**arguments)
        for hostile_json_value in (1.5, "e\u0301", "\ud800"):
            with self.subTest(value=repr(hostile_json_value)), self.assertRaises(
                OllamaV2NativeExecutionContractError
            ):
                canonical_ollama_v2_native_execution_bytes({"value": hostile_json_value})

        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "native_execution_document_invalid",
        ):
            canonical_ollama_v2_native_execution_bytes(
                {"payload": "x" * (4 * 1024 * 1024)}
            )
        too_deep: object = "leaf"
        for _ in range(41):
            too_deep = {"nested": too_deep}
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "native_execution_document_invalid",
        ):
            canonical_ollama_v2_native_execution_bytes(too_deep)

        with self.assertRaises(OllamaV2NativeExecutionContractError):
            parse_ollama_v2_native_execution_contract(
                b'{"format":"duplicate","format":"duplicate"}'
            )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            parse_ollama_v2_native_execution_contract(b" " + policy.to_bytes())

        unknown = scope.to_document()
        unknown["unknown"] = "field"
        unknown["content_hash"] = OllamaV2NativeResourceScopeD2.compute_document_hash(unknown)
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeResourceScopeD2.from_document(unknown)
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeExecutionPolicyD2.from_document(scope.to_document())
        wrong_version = policy.to_document()
        wrong_version["format_version"] = 2
        wrong_version["content_hash"] = OllamaV2NativeExecutionPolicyD2.compute_document_hash(
            wrong_version
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeExecutionPolicyD2.from_document(wrong_version)

        reservation_document = material["reservation"].to_document()
        reservation_document["fence_hash"] = "c" * 64
        reservation_document["content_hash"] = OllamaV2NativeReservationD2.compute_document_hash(
            reservation_document
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeReservationD2.from_document(reservation_document)

        nonmonotonic = material["reservation"].to_document()
        nonmonotonic["fence_sequence"] = nonmonotonic["previous_fence_sequence"]
        nonmonotonic["content_hash"] = OllamaV2NativeReservationD2.compute_document_hash(
            nonmonotonic
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeReservationD2.from_document(nonmonotonic)

        c2_document = material["c2"].to_document()
        c2_document["consumption_reservation_hash"] = "a" * 64
        c2_document["content_hash"] = OllamaV2C2AuthorizationReferenceD2.compute_document_hash(
            c2_document
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2C2AuthorizationReferenceD2.from_document(c2_document)

        manifest_document = material["manifest"].to_document()
        manifest_document["entry_count"] += 1
        manifest_document["content_hash"] = (
            OllamaV2NativeBundleManifestV1.compute_document_hash(manifest_document)
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeBundleManifestV1.from_document(manifest_document)

    def test_module_has_no_execution_surface_or_public_reexport(self) -> None:
        root = Path(__file__).resolve().parents[1]
        module_path = (
            root
            / "src"
            / "worldforge"
            / "provider_evidence"
            / "ollama_v2_native_execution_contracts.py"
        )
        source = module_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots: set[str] = set()
        called_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    called_names.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    called_names.add(node.func.attr)

        self.assertLessEqual(
            imported_roots,
            {
                "__future__",
                "dataclasses",
                "hashlib",
                "json",
                "re",
                "unicodedata",
                "ollama_v2_controller_contracts",
            },
        )
        self.assertTrue(
            {
                "os",
                "subprocess",
                "socket",
                "systemd",
                "pwd",
                "grp",
                "worldforge",
            }.isdisjoint(imported_roots)
        )
        self.assertTrue(
            {
                "open",
                "exec",
                "eval",
                "system",
                "popen",
                "Popen",
                "run",
                "connect",
                "request",
            }.isdisjoint(called_names)
        )
        self.assertNotIn("harness", source.casefold())
        self.assertNotIn("catalog_admit(", source)
        durable_fields = {
            field.name
            for contract_type in (
                OllamaV2NativeExecutionBindingD2,
                OllamaV2NativeReservationD2,
                OllamaV2C2AuthorizationReferenceD2,
                OllamaV2DispatchEnvelopeD2,
                OllamaV2MutationAckD2,
                OllamaV2ManagerReloadWitnessD2,
                OllamaV2CustodyLedgerRecordD2,
            )
            for field in dataclasses.fields(contract_type)
        }
        self.assertTrue(
            {
                "absolute_source_path",
                "source_path",
                "fd",
                "inode",
                "device",
                "mount",
                "pid",
                "process_identity",
                "argv",
                "environment",
                "shell",
                "rpc_method",
            }.isdisjoint(durable_fields)
        )
        package_init = (
            root / "src" / "worldforge" / "provider_evidence" / "__init__.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("ollama_v2_native_execution_contracts", package_init)


class D21JudgeRemediationTests(unittest.TestCase):
    def test_effect_source_lineage_rejects_a_coherent_foreign_bundle_transplant(self) -> None:
        descriptor_type = getattr(d21, "OllamaV2SourceBundleDescriptorD2")
        binding_type = getattr(d21, "OllamaV2NativeExecutionBindingD2")
        for effect_ordinal, manifest_name in ((2, "release_manifest"), (4, "model_manifest")):
            first = _materials(
                f"judge-source-a-{effect_ordinal}",
                effect_ordinal=effect_ordinal,
            )
            second = _materials(
                f"judge-source-b-{effect_ordinal}",
                effect_ordinal=effect_ordinal,
            )
            foreign_descriptor = descriptor_type.create(
                getattr(second["plan"], manifest_name),
                source_label=f"source-judge-foreign-{effect_ordinal}",
                source_revision=f"revision-judge-foreign-{effect_ordinal}",
                future_receipt_identity_hash="a" * 64,
            )
            arguments = dict(first["binding_arguments"])
            arguments["native_bundle_manifest"] = second["manifest"]
            arguments["source_bundle_descriptor"] = foreign_descriptor
            arguments["installation_attestation"] = second["installation"]

            with self.subTest(effect=first["effect"].kind), self.assertRaises(
                OllamaV2NativeExecutionContractError
            ):
                binding_type.create(**arguments)

            common_runtime_arguments = dict(first["binding_arguments"])
            common_runtime_arguments["native_bundle_manifest"] = second["manifest"]
            common_runtime_arguments["installation_attestation"] = second["installation"]
            rebound_runtime = binding_type.create(**common_runtime_arguments)
            self.assertEqual(
                second["manifest"].content_hash,
                rebound_runtime.native_bundle_manifest_hash,
            )
            self.assertEqual(
                first["source"].projected_manifest_hash,
                rebound_runtime.source_manifest_hash,
            )

    def test_source_presence_matrix_covers_apply_and_rollback_effects(self) -> None:
        arbitrary_source = _materials(
            "source-matrix-foreign",
            effect_ordinal=2,
        )["source"]
        observed_apply_kinds: list[str] = []
        for ordinal in range(9):
            material = _materials(f"source-matrix-apply-{ordinal}", effect_ordinal=ordinal)
            binding = material["binding"]
            dispatch = material["dispatch"]
            descriptor = material["source"]
            observed_apply_kinds.append(binding.effect_kind)
            with self.subTest(phase="apply", kind=binding.effect_kind):
                if binding.effect_kind == "release.stage":
                    expected_manifest = material["controller_plan"].release_manifest
                elif binding.effect_kind == "model.stage":
                    expected_manifest = material["controller_plan"].model_manifest
                else:
                    expected_manifest = None
                if expected_manifest is None:
                    self.assertIsNone(descriptor)
                    self.assertIsNone(binding.source_kind)
                    self.assertIsNone(binding.source_bundle_descriptor_id)
                    self.assertIsNone(binding.source_bundle_descriptor_hash)
                    self.assertIsNone(binding.source_manifest_hash)
                    self.assertIsNone(binding.source_logical_contents_hash)
                    self.assertIsNone(binding.source_receipt_identity_hash)
                    self.assertIsNone(dispatch.source_kind)
                    self.assertIsNone(dispatch.source_bundle_descriptor_id)
                    self.assertIsNone(dispatch.source_bundle_descriptor_hash)
                    self.assertIsNone(dispatch.source_manifest_hash)
                    self.assertIsNone(dispatch.source_logical_contents_hash)
                    self.assertIsNone(dispatch.source_receipt_identity_hash)
                    hostile_arguments = dict(material["binding_arguments"])
                    hostile_arguments["source_bundle_descriptor"] = arbitrary_source
                    with self.assertRaises(OllamaV2NativeExecutionContractError):
                        OllamaV2NativeExecutionBindingD2.create(**hostile_arguments)
                else:
                    self.assertEqual(expected_manifest, descriptor.projected_manifest)
                    self.assertEqual(expected_manifest.content_hash, binding.source_manifest_hash)
                    self.assertEqual(descriptor.content_hash, binding.source_bundle_descriptor_hash)
                    self.assertEqual(binding.source_kind, dispatch.source_kind)
                    self.assertEqual(
                        binding.source_bundle_descriptor_hash,
                        dispatch.source_bundle_descriptor_hash,
                    )
                    self.assertEqual(
                        binding.source_manifest_hash,
                        dispatch.source_manifest_hash,
                    )
                    self.assertEqual(
                        binding.source_logical_contents_hash,
                        dispatch.source_logical_contents_hash,
                    )
                    missing_arguments = dict(material["binding_arguments"])
                    missing_arguments["source_bundle_descriptor"] = None
                    with self.assertRaises(OllamaV2NativeExecutionContractError):
                        OllamaV2NativeExecutionBindingD2.create(**missing_arguments)

        self.assertEqual(tuple(APPLY_EFFECT_KINDS), tuple(observed_apply_kinds))

        rollback_probe = _materials("source-matrix-rollback", phase="rollback")
        rollback_count = len(rollback_probe["plan"].effects)
        observed_rollback_kinds: list[str] = []
        for ordinal in range(rollback_count):
            material = _materials(
                f"source-matrix-rollback-{ordinal}",
                phase="rollback",
                effect_ordinal=ordinal,
            )
            binding = material["binding"]
            dispatch = material["dispatch"]
            observed_rollback_kinds.append(binding.effect_kind)
            with self.subTest(phase="rollback", kind=binding.effect_kind):
                self.assertIsNone(material["source"])
                self.assertIsNone(binding.source_kind)
                self.assertIsNone(binding.source_bundle_descriptor_hash)
                self.assertIsNone(dispatch.source_kind)
                self.assertIsNone(dispatch.source_bundle_descriptor_hash)
                hostile_arguments = dict(material["binding_arguments"])
                hostile_arguments["source_bundle_descriptor"] = arbitrary_source
                with self.assertRaises(OllamaV2NativeExecutionContractError):
                    OllamaV2NativeExecutionBindingD2.create(**hostile_arguments)

        self.assertEqual(tuple(ROLLBACK_EFFECT_KINDS), tuple(observed_rollback_kinds))

        installation_fields = {
            field.name
            for field in dataclasses.fields(OllamaV2NativeInstallationAttestationD2)
        }
        self.assertTrue(
            {
                "source_descriptor_id",
                "source_descriptor_hash",
                "source_bundle_descriptor_id",
                "source_bundle_descriptor_hash",
                "source_receipt_identity_hash",
                "source_logical_contents_hash",
                "source_manifest_hash",
                "source_kind",
            }.isdisjoint(installation_fields)
        )

    def test_flattened_binding_phase_kind_parity_fails_closed(self) -> None:
        non_source = _materials("phase-parity")
        binding_document = non_source["binding"].to_document()
        binding_document["plan_kind"] = "rollback"
        binding_document["effect_phase"] = "rollback"
        _rederive_document_id(
            binding_document,
            identifier_field="binding_id",
            prefix="binding-",
            contract_type=OllamaV2NativeExecutionBindingD2,
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeExecutionBindingD2.from_document(binding_document)

    def test_flattened_dispatch_source_kind_parity_fails_closed(self) -> None:
        release = _materials("dispatch-source-kind", effect_ordinal=2)
        model = _materials("dispatch-source-kind-model", effect_ordinal=4)

        def reseal_dispatch(document: dict[str, object]) -> None:
            _rederive_document_id(
                document["execution_binding"],
                identifier_field="binding_id",
                prefix="binding-",
                contract_type=OllamaV2NativeExecutionBindingD2,
            )
            _rederive_document_id(
                document,
                identifier_field="dispatch_id",
                prefix="dispatch-",
                contract_type=OllamaV2DispatchEnvelopeD2,
            )

        dispatch_document = release["dispatch"].to_document()
        dispatch_document["execution_binding"]["source_bundle_descriptor"] = model[
            "source"
        ].to_document()
        reseal_dispatch(dispatch_document)
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "dispatch_envelope_d2_invalid",
        ):
            OllamaV2DispatchEnvelopeD2.from_document(dispatch_document)

        missing_source_document = release["dispatch"].to_document()
        missing_source_document["execution_binding"]["source_bundle_descriptor"] = None
        reseal_dispatch(missing_source_document)
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "dispatch_envelope_d2_invalid",
        ):
            OllamaV2DispatchEnvelopeD2.from_document(missing_source_document)

        ordinary = _materials("dispatch-effect-kind")
        effect_document = ordinary["dispatch"].to_document()
        effect_document["effect_kind"] = "foreign.mutation"
        _rederive_document_id(
            effect_document,
            identifier_field="dispatch_id",
            prefix="dispatch-",
            contract_type=OllamaV2DispatchEnvelopeD2,
        )
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "dispatch_envelope_d2_invalid",
        ):
            OllamaV2DispatchEnvelopeD2.from_document(effect_document)

        extraneous_source_document = ordinary["dispatch"].to_document()
        extraneous_source_document["execution_binding"][
            "source_bundle_descriptor"
        ] = release["source"].to_document()
        reseal_dispatch(extraneous_source_document)
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "dispatch_envelope_d2_invalid",
        ):
            OllamaV2DispatchEnvelopeD2.from_document(extraneous_source_document)

    def test_zero_authority_hashes_and_non_genesis_zero_heads_fail_closed(self) -> None:
        material = _materials("judge-zero")
        binding_document = material["binding"].to_document()
        binding_document["effect"]["content_hash"] = ZERO_HASH
        _rederive_document_id(
            binding_document,
            identifier_field="binding_id",
            prefix="binding-",
            contract_type=OllamaV2NativeExecutionBindingD2,
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeExecutionBindingD2.from_document(binding_document)

        non_genesis = material["reservation"].to_document()
        non_genesis["previous_fence_hash"] = ZERO_HASH
        _rederive_document_id(
            non_genesis,
            identifier_field="reservation_id",
            prefix="reservation-",
            contract_type=OllamaV2NativeReservationD2,
        )
        identity = {
            key: value
            for key, value in non_genesis.items()
            if key
            not in {
                "format",
                "format_version",
                "content_hash",
                "reservation_id",
                "fence_hash",
            }
        }
        non_genesis["fence_hash"] = hashlib.sha256(
            canonical_ollama_v2_native_execution_bytes(
                {"reservation_id": non_genesis["reservation_id"], **identity}
            )
        ).hexdigest()
        non_genesis["content_hash"] = OllamaV2NativeReservationD2.compute_document_hash(
            non_genesis
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeReservationD2.from_document(non_genesis)

    def test_zero_hash_rejection_covers_every_authority_document(self) -> None:
        source_material = _materials("zero-source", effect_ordinal=2)
        ordinary = _materials("zero-ordinary")
        ordinary_record = OllamaV2CustodyLedgerRecordD2.create(
            ordinary["binding"],
            ordinary["reservation"],
            ordinary["dispatch"],
            ordinary["ack"],
            observed_snapshot=ordinary["baseline"],
            reload_witness=None,
        )
        manager = _materials("zero-manager", effect_ordinal=8)
        manager_after = project_effect(
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
            observed_snapshot=manager_after,
            observed_at_ms=1_800_000_200_000,
            manager_observation_hash="b" * 64,
        )

        policy_document = ordinary["policy"].to_document()
        policy_document["resource_scope_hash"] = ZERO_HASH
        policy_document["content_hash"] = (
            OllamaV2NativeExecutionPolicyD2.compute_document_hash(policy_document)
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeExecutionPolicyD2.from_document(policy_document)

        manifest_document = ordinary["manifest"].to_document()
        manifest_document["entries"][0]["sha256"] = ZERO_HASH
        manifest_document["content_hash"] = (
            OllamaV2NativeBundleManifestV1.compute_document_hash(manifest_document)
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeBundleManifestV1.from_document(manifest_document)

        projected_manifest = source_material["source"].projected_manifest
        zero_entry = dataclasses.replace(
            projected_manifest.entries[-1],
            sha256=ZERO_HASH,
        )
        zero_projected_manifest = dataclasses.replace(
            projected_manifest,
            entries=(*projected_manifest.entries[:-1], zero_entry),
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2SourceBundleDescriptorD2.create(
                zero_projected_manifest,
                source_label="source-zero-projected-entry",
                source_revision="revision-zero-projected-entry",
                future_receipt_identity_hash="a" * 64,
            )

        flat_cases = (
            (
                source_material["source"],
                "projected_manifest_hash",
                "descriptor_id",
                "source-",
                OllamaV2SourceBundleDescriptorD2,
            ),
            (
                ordinary["installation"],
                "installation_receipt_hash",
                "attestation_id",
                "install-",
                OllamaV2NativeInstallationAttestationD2,
            ),
            (
                ordinary["reservation"],
                "execution_binding_hash",
                "reservation_id",
                "reservation-",
                OllamaV2NativeReservationD2,
            ),
            (
                ordinary["c2"],
                "consumption_hash",
                "reference_id",
                "c2ref-",
                OllamaV2C2AuthorizationReferenceD2,
            ),
            (
                ordinary["ack"],
                "dispatch_hash",
                "ack_id",
                "ack-",
                OllamaV2MutationAckD2,
            ),
        )
        for contract, hash_field, id_field, prefix, contract_type in flat_cases:
            with self.subTest(contract=contract_type.__name__, field=hash_field):
                document = contract.to_document()
                document[hash_field] = ZERO_HASH
                _rederive_document_id(
                    document,
                    identifier_field=id_field,
                    prefix=prefix,
                    contract_type=contract_type,
                )
                with self.assertRaises(OllamaV2NativeExecutionContractError):
                    contract_type.from_document(document)

        for nested_name in ("plan", "effect", "c1_consumption"):
            with self.subTest(
                contract="OllamaV2NativeExecutionBindingD2",
                field=f"{nested_name}.content_hash",
            ):
                document = ordinary["binding"].to_document()
                document[nested_name]["content_hash"] = ZERO_HASH
                _rederive_document_id(
                    document,
                    identifier_field="binding_id",
                    prefix="binding-",
                    contract_type=OllamaV2NativeExecutionBindingD2,
                )
                with self.assertRaisesRegex(
                    OllamaV2NativeExecutionContractError,
                    "native_execution_binding_d2_invalid",
                ):
                    OllamaV2NativeExecutionBindingD2.from_document(document)

        dispatch_document = ordinary["dispatch"].to_document()
        dispatch_document["c2_authorization"]["consumption_hash"] = ZERO_HASH
        _rederive_document_id(
            dispatch_document["c2_authorization"],
            identifier_field="reference_id",
            prefix="c2ref-",
            contract_type=OllamaV2C2AuthorizationReferenceD2,
        )
        _rederive_document_id(
            dispatch_document,
            identifier_field="dispatch_id",
            prefix="dispatch-",
            contract_type=OllamaV2DispatchEnvelopeD2,
        )
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "dispatch_envelope_d2_invalid",
        ):
            OllamaV2DispatchEnvelopeD2.from_document(dispatch_document)

        for contract, nested_name, id_field, prefix, contract_type, reason in (
            (
                witness,
                "observed_snapshot",
                "witness_id",
                "reload-",
                OllamaV2ManagerReloadWitnessD2,
                "manager_reload_witness_d2_invalid",
            ),
            (
                ordinary_record,
                "observed_snapshot",
                "record_id",
                "record-",
                OllamaV2CustodyLedgerRecordD2,
                "custody_ledger_record_d2_invalid",
            ),
        ):
            document = contract.to_document()
            document[nested_name]["content_hash"] = ZERO_HASH
            _rederive_document_id(
                document,
                identifier_field=id_field,
                prefix=prefix,
                contract_type=contract_type,
            )
            with self.subTest(contract=contract_type.__name__), self.assertRaisesRegex(
                OllamaV2NativeExecutionContractError,
                reason,
            ):
                contract_type.from_document(document)

        content_hash_zero = ordinary["ack"].to_document()
        content_hash_zero["content_hash"] = ZERO_HASH
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2MutationAckD2.from_document(content_hash_zero)

    def test_genesis_zero_heads_are_exactly_sequence_coupled(self) -> None:
        genesis = _materials(
            "genesis",
            controller_sequence=0,
            previous_fence_sequence=0,
            current_controller_sequence=0,
        )
        record = OllamaV2CustodyLedgerRecordD2.create(
            genesis["binding"],
            genesis["reservation"],
            genesis["dispatch"],
            genesis["ack"],
            observed_snapshot=genesis["baseline"],
            reload_witness=None,
        )
        self.assertEqual(ZERO_HASH, genesis["binding"].controller_anchor_head_hash)
        self.assertEqual(ZERO_HASH, genesis["reservation"].previous_fence_hash)
        self.assertEqual(1, genesis["reservation"].fence_sequence)
        self.assertEqual(ZERO_HASH, genesis["dispatch"].current_controller_head_hash)
        self.assertEqual(ZERO_HASH, record.previous_record_hash)
        self.assertEqual(1, record.record_sequence)

        non_genesis_binding = _materials("non-genesis-binding")["binding"].to_document()
        non_genesis_binding["authorization_request"]["expected_head_hash"] = ZERO_HASH
        non_genesis_binding["authorization_request"]["content_hash"] = (
            AuthorizationRequest.compute_document_hash(
                non_genesis_binding["authorization_request"]
            )
        )
        _rederive_document_id(
            non_genesis_binding,
            identifier_field="binding_id",
            prefix="binding-",
            contract_type=OllamaV2NativeExecutionBindingD2,
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeExecutionBindingD2.from_document(non_genesis_binding)

        genesis_binding = genesis["binding"].to_document()
        genesis_binding["authorization_request"]["expected_head_hash"] = "a" * 64
        genesis_binding["authorization_request"]["content_hash"] = (
            AuthorizationRequest.compute_document_hash(
                genesis_binding["authorization_request"]
            )
        )
        _rederive_document_id(
            genesis_binding,
            identifier_field="binding_id",
            prefix="binding-",
            contract_type=OllamaV2NativeExecutionBindingD2,
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeExecutionBindingD2.from_document(genesis_binding)

        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeReservationD2.create(
                genesis["binding"],
                fence_generation=1,
                previous_fence_sequence=0,
                previous_fence_hash="a" * 64,
            )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2NativeReservationD2.create(
                genesis["binding"],
                fence_generation=1,
                previous_fence_sequence=1,
                previous_fence_hash=ZERO_HASH,
            )

        hostile_record = record.to_document()
        hostile_record["record_sequence"] = 2
        _rederive_document_id(
            hostile_record,
            identifier_field="record_id",
            prefix="record-",
            contract_type=OllamaV2CustodyLedgerRecordD2,
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2CustodyLedgerRecordD2.from_document(hostile_record)

        nonzero_genesis_record = record.to_document()
        nonzero_genesis_record["previous_record_hash"] = "a" * 64
        _rederive_document_id(
            nonzero_genesis_record,
            identifier_field="record_id",
            prefix="record-",
            contract_type=OllamaV2CustodyLedgerRecordD2,
        )
        with self.assertRaises(OllamaV2NativeExecutionContractError):
            OllamaV2CustodyLedgerRecordD2.from_document(nonzero_genesis_record)

    def test_resealed_ack_substitution_is_rejected_by_every_consumer(self) -> None:
        first = _materials("judge-ack-a")
        second = _materials("judge-ack-b")
        forbidden_projection_values = {
            "reservation_id": second["reservation"].reservation_id,
            "fence_hash": second["reservation"].fence_hash,
            "operation_id": second["dispatch"].operation_id,
            "effect_id": second["dispatch"].effect_id,
            "effect_hash": second["dispatch"].effect_hash,
            "dispatch_reservation_id": second["reservation"].reservation_id,
            "dispatch_fence_hash": second["reservation"].fence_hash,
            "dispatch_operation_id": second["dispatch"].operation_id,
            "dispatch_effect_id": second["dispatch"].effect_id,
            "dispatch_effect_hash": second["dispatch"].effect_hash,
        }
        for field_name, replacement in forbidden_projection_values.items():
            document = first["ack"].to_document()
            document[field_name] = replacement
            _rederive_document_id(
                document,
                identifier_field="ack_id",
                prefix="ack-",
                contract_type=OllamaV2MutationAckD2,
            )
            with self.subTest(field=field_name), self.assertRaisesRegex(
                OllamaV2NativeExecutionContractError,
                "mutation_ack_d2_invalid",
            ):
                OllamaV2MutationAckD2.from_document(document)

        hostile_ack_document = first["ack"].to_document()
        hostile_ack_document["dispatch_hash"] = second["dispatch"].content_hash
        _rederive_document_id(
            hostile_ack_document,
            identifier_field="ack_id",
            prefix="ack-",
            contract_type=OllamaV2MutationAckD2,
        )
        hostile_ack = OllamaV2MutationAckD2.from_document(hostile_ack_document)
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "custody_ledger_record_d2_invalid",
        ):
            OllamaV2CustodyLedgerRecordD2.create(
                first["binding"],
                first["reservation"],
                first["dispatch"],
                hostile_ack,
                observed_snapshot=first["baseline"],
                reload_witness=None,
            )

        valid_record = OllamaV2CustodyLedgerRecordD2.create(
            first["binding"],
            first["reservation"],
            first["dispatch"],
            first["ack"],
            observed_snapshot=first["baseline"],
            reload_witness=None,
        )
        record_document = valid_record.to_document()
        record_document["ack"] = hostile_ack.to_document()
        _rederive_document_id(
            record_document,
            identifier_field="record_id",
            prefix="record-",
            contract_type=OllamaV2CustodyLedgerRecordD2,
        )
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "custody_ledger_record_d2_invalid",
        ):
            OllamaV2CustodyLedgerRecordD2.from_document(record_document)

        manager = _materials("judge-ack-manager-a", effect_ordinal=8)
        other_manager = _materials("judge-ack-manager-b", effect_ordinal=8)
        manager_after = project_effect(
            manager["before"],
            manager["controller_plan"],
            manager["effect"],
            manager["controller_plan"].operation_id,
        )
        hostile_manager_ack_document = manager["ack"].to_document()
        hostile_manager_ack_document["dispatch_hash"] = other_manager[
            "dispatch"
        ].content_hash
        _rederive_document_id(
            hostile_manager_ack_document,
            identifier_field="ack_id",
            prefix="ack-",
            contract_type=OllamaV2MutationAckD2,
        )
        hostile_manager_ack = OllamaV2MutationAckD2.from_document(
            hostile_manager_ack_document
        )
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "manager_reload_witness_d2_invalid",
        ):
            OllamaV2ManagerReloadWitnessD2.create(
                manager["binding"],
                manager["dispatch"],
                hostile_manager_ack,
                before_snapshot=manager["before"],
                observed_snapshot=manager_after,
                observed_at_ms=1_800_000_100_000,
                manager_observation_hash="b" * 64,
            )

        valid_ack = first["ack"]
        self.assertEqual(
            {
                "format",
                "format_version",
                "ack_id",
                "dispatch_hash",
                "correlation_hash",
                "acknowledged_at_ms",
                "acknowledgement_kind",
                "native_evidence_verified",
                "content_hash",
            },
            set(valid_ack.to_document()),
        )
        self.assertEqual(first["dispatch"].content_hash, valid_ack.dispatch_hash)

    def test_hostile_redundant_edges_fail_during_exact_parsing(self) -> None:
        first = _materials("parse-edges-a")
        second = _materials("parse-edges-b")
        record = OllamaV2CustodyLedgerRecordD2.create(
            first["binding"],
            first["reservation"],
            first["dispatch"],
            first["ack"],
            observed_snapshot=first["baseline"],
            reload_witness=None,
        )
        manager = _materials("parse-edges-manager-a", effect_ordinal=8)
        other_manager = _materials("parse-edges-manager-b", effect_ordinal=8)
        manager_after = project_effect(
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
            observed_snapshot=manager_after,
            observed_at_ms=1_800_000_300_000,
            manager_observation_hash="c" * 64,
        )
        release = _materials("parse-full-hash-release", effect_ordinal=2)
        foreign_release = _materials("parse-full-hash-foreign", effect_ordinal=2)
        dispatch_attacks = {
            "plan_hash": foreign_release["binding"].plan_hash,
            "native_bundle_manifest_hash": foreign_release[
                "binding"
            ].native_bundle_manifest_hash,
            "binding_controller_generation": 2,
            "source_manifest_hash": foreign_release["binding"].source_manifest_hash,
            "c1_consumption_hash": foreign_release["binding"].c1_consumption_hash,
            "fence_generation": 5,
        }
        self.assertTrue(
            set(dispatch_attacks).isdisjoint(release["dispatch"].to_document())
        )
        for field_name, replacement in dispatch_attacks.items():
            document = release["dispatch"].to_document()
            document[field_name] = replacement
            _rederive_document_id(
                document,
                identifier_field="dispatch_id",
                prefix="dispatch-",
                contract_type=OllamaV2DispatchEnvelopeD2,
            )
            with self.subTest(field=field_name), self.assertRaisesRegex(
                OllamaV2NativeExecutionContractError,
                "dispatch_envelope_d2_invalid",
            ):
                forged_dispatch = OllamaV2DispatchEnvelopeD2.from_document(document)
                forged_ack = OllamaV2MutationAckD2.create(
                    forged_dispatch,
                    correlation_hash="d" * 64,
                    acknowledged_at_ms=1_800_000_300_001,
                )
                OllamaV2CustodyLedgerRecordD2.create(
                    release["binding"],
                    release["reservation"],
                    forged_dispatch,
                    forged_ack,
                    observed_snapshot=release["baseline"],
                    reload_witness=None,
                )

        coherent_dispatch = release["dispatch"].to_document()
        coherent_dispatch.update(dispatch_attacks)
        _rederive_document_id(
            coherent_dispatch,
            identifier_field="dispatch_id",
            prefix="dispatch-",
            contract_type=OllamaV2DispatchEnvelopeD2,
        )
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "dispatch_envelope_d2_invalid",
        ):
            OllamaV2DispatchEnvelopeD2.from_document(coherent_dispatch)

        witness_document = witness.to_document()
        witness_document.update(
            {
                "operation_id": other_manager["dispatch"].operation_id,
                "ack_operation_id": other_manager["dispatch"].operation_id,
            }
        )
        _rederive_document_id(
            witness_document,
            identifier_field="witness_id",
            prefix="reload-",
            contract_type=OllamaV2ManagerReloadWitnessD2,
        )
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "manager_reload_witness_d2_invalid",
        ):
            forged_witness = OllamaV2ManagerReloadWitnessD2.from_document(
                witness_document
            )
            OllamaV2CustodyLedgerRecordD2.create(
                manager["binding"],
                manager["reservation"],
                manager["dispatch"],
                manager["ack"],
                observed_snapshot=manager_after,
                reload_witness=forged_witness,
            )

        cases = (
            (
                first["dispatch"],
                "c2_execution_binding_hash",
                second["binding"].content_hash,
                "dispatch_id",
                "dispatch-",
                OllamaV2DispatchEnvelopeD2,
            ),
            (
                first["dispatch"],
                "c2_reservation_hash",
                second["reservation"].content_hash,
                "dispatch_id",
                "dispatch-",
                OllamaV2DispatchEnvelopeD2,
            ),
            (
                first["ack"],
                "dispatch_reservation_id",
                second["reservation"].reservation_id,
                "ack_id",
                "ack-",
                OllamaV2MutationAckD2,
            ),
            (
                first["ack"],
                "dispatch_fence_hash",
                second["reservation"].fence_hash,
                "ack_id",
                "ack-",
                OllamaV2MutationAckD2,
            ),
            (
                witness,
                "ack_dispatch_hash",
                other_manager["dispatch"].content_hash,
                "witness_id",
                "reload-",
                OllamaV2ManagerReloadWitnessD2,
            ),
            (
                witness,
                "ack_reservation_id",
                other_manager["reservation"].reservation_id,
                "witness_id",
                "reload-",
                OllamaV2ManagerReloadWitnessD2,
            ),
            (
                witness,
                "ack_fence_hash",
                other_manager["reservation"].fence_hash,
                "witness_id",
                "reload-",
                OllamaV2ManagerReloadWitnessD2,
            ),
            (
                record,
                "ack_dispatch_hash",
                second["dispatch"].content_hash,
                "record_id",
                "record-",
                OllamaV2CustodyLedgerRecordD2,
            ),
            (
                record,
                "ack_reservation_id",
                second["reservation"].reservation_id,
                "record_id",
                "record-",
                OllamaV2CustodyLedgerRecordD2,
            ),
            (
                record,
                "ack_fence_hash",
                second["reservation"].fence_hash,
                "record_id",
                "record-",
                OllamaV2CustodyLedgerRecordD2,
            ),
        )
        for contract, field_name, replacement, id_field, prefix, contract_type in cases:
            with self.subTest(contract=contract_type.__name__, field=field_name):
                document = contract.to_document()
                document[field_name] = replacement
                _rederive_document_id(
                    document,
                    identifier_field=id_field,
                    prefix=prefix,
                    contract_type=contract_type,
                )
                with self.assertRaises(OllamaV2NativeExecutionContractError):
                    parse_ollama_v2_native_execution_contract(
                        canonical_ollama_v2_native_execution_bytes(document)
                    )

    def test_hostile_nested_source_manifest_uses_the_d21_error_domain(self) -> None:
        material = _materials("nested-source-error", effect_ordinal=2)
        document = material["source"].to_document()
        document["projected_manifest"]["unknown"] = "field"
        document["content_hash"] = (
            OllamaV2SourceBundleDescriptorD2.compute_document_hash(document)
        )
        with self.assertRaisesRegex(
            OllamaV2NativeExecutionContractError,
            "source_bundle_descriptor_d2_invalid",
        ):
            OllamaV2SourceBundleDescriptorD2.from_document(document)

    def test_planned_prefixed_api_and_exact_exports_are_present(self) -> None:
        expected_classes = {
            "OllamaV2C2AuthorizationReferenceD2",
            "OllamaV2CustodyLedgerRecordD2",
            "OllamaV2DispatchEnvelopeD2",
            "OllamaV2ManagerReloadWitnessD2",
            "OllamaV2MutationAckD2",
            "OllamaV2NativeBundleEntryV1",
            "OllamaV2NativeBundleManifestV1",
            "OllamaV2NativeExecutionBindingD2",
            "OllamaV2NativeExecutionContractError",
            "OllamaV2NativeExecutionPolicyD2",
            "OllamaV2NativeInstallationAttestationD2",
            "OllamaV2NativeReservationD2",
            "OllamaV2NativeResourceScopeD2",
            "OllamaV2SourceBundleDescriptorD2",
        }
        expected_exports = expected_classes | {
            "FORMAT_VERSION",
            "CUSTODY_TARGET_ROOT",
            "CUSTODY_LEDGER_NAME",
            "CUSTODY_LOCK_NAME",
            "CUSTODY_SCOPE",
            "DEPLOYMENT_BINDING",
            "ROOT_GLOBAL_ENFORCED",
            "SOURCE_CUSTODY_VERIFIED",
            "HOST_EXECUTION_ENABLED",
            "NATIVE_IMPLEMENTATION_STATE",
            "AVAILABILITY",
            "PRODUCTION_ELIGIBLE",
            "CATALOG_ADMITTED",
            "PROVIDER_EXECUTION_ENABLED",
            "canonical_ollama_v2_native_execution_bytes",
            "canonical_ollama_v2_native_resource_scope_d2",
            "canonical_ollama_v2_native_execution_policy_d2",
            "parse_ollama_v2_native_execution_contract",
        }
        exported = set(getattr(d21, "__all__"))
        self.assertEqual(expected_exports, exported)
        self.assertEqual(
            expected_classes,
            {name for name in exported if isinstance(getattr(d21, name), type)},
        )
        self.assertFalse(
            {
                "NativeExecutionBindingD2",
                "DispatchEnvelopeD2",
                "OllamaV2SealedSourceBundleD2",
            }
            & set(vars(d21))
        )

    def test_dependency_graph_is_topologically_acyclic(self) -> None:
        contract_nodes = {
            "binding": OllamaV2NativeExecutionBindingD2,
            "reservation": OllamaV2NativeReservationD2,
            "c2": OllamaV2C2AuthorizationReferenceD2,
            "dispatch": OllamaV2DispatchEnvelopeD2,
            "ack": OllamaV2MutationAckD2,
            "witness": OllamaV2ManagerReloadWitnessD2,
            "ledger": OllamaV2CustodyLedgerRecordD2,
        }
        dependency_nodes = {
            AuthorizationRequest: "c1",
            AuthorizationConsumption: "c1",
            **{contract_type: node for node, contract_type in contract_nodes.items()},
        }
        graph = {node: set() for node in {"c1", *contract_nodes}}
        for consumer, contract_type in contract_nodes.items():
            hints = typing.get_type_hints(contract_type.create)
            for parameter, annotation in hints.items():
                if parameter == "return":
                    continue
                members = typing.get_args(annotation) or (annotation,)
                for member in members:
                    dependency = dependency_nodes.get(member)
                    if dependency is not None and dependency != consumer:
                        graph[dependency].add(consumer)

        self.assertEqual(
            {
                "c1": {"binding"},
                "binding": {"reservation", "c2", "dispatch", "witness", "ledger"},
                "reservation": {"c2", "dispatch", "ledger"},
                "c2": {"dispatch"},
                "dispatch": {"ack", "witness", "ledger"},
                "ack": {"witness", "ledger"},
                "witness": {"ledger"},
                "ledger": set(),
            },
            graph,
        )
        incoming = {node: 0 for node in graph}
        for successors in graph.values():
            for successor in successors:
                incoming[successor] += 1
        ready = sorted(node for node, count in incoming.items() if count == 0)
        visited: list[str] = []
        while ready:
            node = ready.pop(0)
            visited.append(node)
            for successor in graph[node]:
                incoming[successor] -= 1
                if incoming[successor] == 0:
                    ready.append(successor)
                    ready.sort()
        self.assertEqual(
            ["c1", "binding", "reservation", "c2", "dispatch", "ack", "witness", "ledger"],
            visited,
        )

if __name__ == "__main__":
    unittest.main()
