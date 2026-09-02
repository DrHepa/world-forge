from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import worldforge.studio.authenticated_human_decisions as human_authority_module
import worldforge.studio.ollama_v2_authorizations as authorization_module
from worldforge.agent_harness.approvals import ApprovalError
from worldforge.provider_evidence.ollama_v2_controller import (
    ControllerAuthorizationError,
    ControllerConstructionError,
    ControllerStateError,
    OllamaV2Controller,
)
from worldforge.provider_evidence.ollama_v2_controller_contracts import (
    CONTROLLER_GID,
    CONTROLLER_UID,
    MODEL_FINAL_ROOT,
    RELEASE_FINAL_ROOT,
    AuthorizationConsumption,
    AuthorizationRejection,
    AuthorizationRequest,
    BoundedTreeManifest,
    ControllerPlan,
    HostEffect,
    HostSnapshot,
    InterpreterBinding,
    ManifestEntry,
    OperationSnapshot,
    build_controller_plan,
    make_empty_host_snapshot,
    project_effect,
)
from worldforge.provider_evidence.ollama_v2_controller_store import OllamaV2ControllerStore
from worldforge.studio.director_control import StudioDirectorControl
from worldforge.studio.errors import StudioError
from worldforge.studio.ollama_v2_authorization_contracts import (
    StudioOllamaV2AuthorizationDecision,
    StudioOllamaV2AuthorizationImpact,
    StudioOllamaV2AuthorizationReview,
)
from worldforge.studio.ollama_v2_authorizations import StudioOllamaV2AuthorizationDomain
from worldforge.studio.storage import StudioStore

PASSPHRASE = "correct horse battery staple"


def _set_document_path(
    document: dict[str, object],
    path: tuple[str, ...],
    value: object,
) -> None:
    owner = document
    for name in path[:-1]:
        nested = owner[name]
        if type(nested) is not dict:
            raise AssertionError(f"non-document owner for {path!r}")
        owner = nested
    owner[path[-1]] = value


def _document_path(document: dict[str, object], path: tuple[str, ...]) -> object:
    value: object = document
    for name in path:
        if type(value) is not dict:
            raise AssertionError(f"non-document owner for {path!r}")
        value = value[name]
    return value


def _generic_document_hash(document: dict[str, object]) -> str:
    payload = {name: value for name, value in document.items() if name != "content_hash"}
    return hashlib.sha256(authorization_module._canonical(payload)).hexdigest()


def _event_integer_paths(document: dict[str, object]) -> tuple[tuple[str, ...], ...]:
    paths: list[tuple[str, ...]] = []
    containers = (
        (),
        ("review",),
        ("review", "impact"),
        ("decision",),
        ("request",),
        ("consumption",),
    )
    for prefix in containers:
        current: object = document
        for name in prefix:
            if type(current) is not dict:
                break
            current = current.get(name)
        if type(current) is not dict:
            continue
        for name, value in current.items():
            if type(value) is int:
                paths.append((*prefix, name))
    return tuple(paths)


def _reseal_hostile_event_documents(
    document: dict[str, object],
    path: tuple[str, ...],
) -> None:
    review = document.get("review")
    decision = document.get("decision")
    request = document.get("request")
    consumption = document.get("consumption")
    if type(review) is dict and path[:1] == ("review",):
        impact = review.get("impact")
        if type(impact) is dict and path[:2] == ("review", "impact"):
            impact["content_hash"] = StudioOllamaV2AuthorizationImpact.compute_document_hash(impact)
        review["content_hash"] = StudioOllamaV2AuthorizationReview.compute_document_hash(review)
    decision_keys = {
        "mandate_id",
        "review_hash",
        "reviewer_id",
        "outcome",
        "expires_at_ms",
    }
    if (
        type(decision) is dict
        and decision_keys <= set(decision)
        and path[:1] in {("review",), ("decision",)}
    ):
        if type(review) is dict:
            decision["review_hash"] = review["content_hash"]
        seed = {
            name: decision[name]
            for name in (
                "mandate_id",
                "review_hash",
                "reviewer_id",
                "outcome",
                "expires_at_ms",
            )
        }
        decision["decision_id"] = (
            "decision-" + hashlib.sha256(authorization_module._canonical(seed)).hexdigest()[:32]
        )
        decision["content_hash"] = StudioOllamaV2AuthorizationDecision.compute_document_hash(
            decision
        )
    request_keys = {
        "operation_id",
        "plan_hash",
        "effect_id",
        "phase",
        "attempt",
        "expected_generation",
        "expected_sequence",
        "expected_head_hash",
        "ownership_token",
        "policy_content_hash",
        "interpreter_binding_hash",
    }
    if type(request) is dict and request_keys <= set(request) and path[:1] == ("request",):
        seed = {
            name: request[name]
            for name in (
                "operation_id",
                "plan_hash",
                "effect_id",
                "phase",
                "attempt",
                "expected_generation",
                "expected_sequence",
                "expected_head_hash",
                "ownership_token",
                "policy_content_hash",
                "interpreter_binding_hash",
            )
        }
        request["authorization_id"] = (
            "auth-" + hashlib.sha256(authorization_module._canonical(seed)).hexdigest()[:32]
        )
        request["content_hash"] = _generic_document_hash(request)
    consumption_keys = {
        "authorization_id",
        "request_hash",
        "authority_id",
        "decision_id",
        "decision",
        "single_use",
    }
    if (
        type(consumption) is dict
        and consumption_keys <= set(consumption)
        and path[:1]
        in {
            ("review",),
            ("decision",),
            ("request",),
            ("consumption",),
        }
    ):
        if type(decision) is dict and "decision_id" in decision:
            consumption["decision_id"] = decision["decision_id"]
        if type(request) is dict and {
            "authorization_id",
            "content_hash",
        } <= set(request):
            consumption["authorization_id"] = request["authorization_id"]
            consumption["request_hash"] = request["content_hash"]
        seed = {
            name: consumption[name]
            for name in (
                "authorization_id",
                "request_hash",
                "authority_id",
                "decision_id",
                "decision",
                "single_use",
            )
        }
        consumption["consumption_id"] = (
            "consume-" + hashlib.sha256(authorization_module._canonical(seed)).hexdigest()[:32]
        )
        consumption["content_hash"] = _generic_document_hash(consumption)


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
        self.snapshot = make_empty_host_snapshot("snap-studio-domain", observed_generation=0)

    def inspect(self, _policy_hash: str, _binding: InterpreterBinding) -> HostSnapshot:
        return HostSnapshot.from_document(self.snapshot.to_document())

    def observe(self, _operation_id: str, _plan_hash: str) -> HostSnapshot:
        return HostSnapshot.from_document(self.snapshot.to_document())


class _BootstrapAuthorization:
    def __init__(self) -> None:
        self._consumptions: dict[str, AuthorizationConsumption] = {}

    def consume(self, request):
        consumption = AuthorizationConsumption.create(
            request, authority_id="bootstrap-only", decision_id="bootstrap-only"
        )
        self._consumptions[request.authorization_id] = consumption
        return consumption

    def resolve(self, request):
        return self._consumptions.get(request.authorization_id)


class _Effects:
    def __init__(self, inspector: _Inspector) -> None:
        self.inspector = inspector
        self.plan = None
        self.calls: list[str] = []
        self.no_effect_once = False

    def _apply(self, effect: HostEffect) -> None:
        self.calls.append(effect.effect_id)
        if self.no_effect_once:
            self.no_effect_once = False
            return
        self.inspector.snapshot = project_effect(
            self.inspector.snapshot, self.plan, effect, self.plan.operation_id
        )

    def create_managed_root(self, effect):
        self._apply(effect)

    def create_principal_exact(self, effect):
        self._apply(effect)

    def stage_release(self, effect, _manifest):
        self._apply(effect)

    def publish_release(self, effect, _manifest):
        self._apply(effect)

    def stage_model(self, effect, _manifest):
        self._apply(effect)

    def publish_model(self, effect, _manifest):
        self._apply(effect)

    def install_socket_unit(self, effect, _unit):
        self._apply(effect)

    def install_service_unit(self, effect, _unit):
        self._apply(effect)

    def reload_manager(self, effect):
        self._apply(effect)

    def remove_service_unit_exact(self, effect, _unit):
        self._apply(effect)

    def remove_socket_unit_exact(self, effect, _unit):
        self._apply(effect)

    def unpublish_model_exact(self, effect, _manifest):
        self._apply(effect)

    def unstage_model_exact(self, effect, _manifest):
        self._apply(effect)

    def unpublish_release_exact(self, effect, _manifest):
        self._apply(effect)

    def unstage_release_exact(self, effect, _manifest):
        self._apply(effect)

    def remove_principal_exact(self, effect):
        self._apply(effect)

    def remove_managed_root_exact(self, effect):
        self._apply(effect)


def _persist_controller_operation(
    store: OllamaV2ControllerStore,
    plan: ControllerPlan,
    *,
    idempotency_key: str,
) -> OperationSnapshot:
    initial = OperationSnapshot.create(plan.operation_id, plan)
    return store.create_operation(
        initial,
        plan,
        idempotency_key=idempotency_key,
    ).snapshot


def _request_for_effect(
    operation: OperationSnapshot,
    effect: HostEffect,
    *,
    phase: str = "apply",
) -> AuthorizationRequest:
    return AuthorizationRequest.create(
        operation_id=operation.operation_id,
        plan_hash=operation.plan_hash,
        effect_id=effect.effect_id,
        phase=phase,
        attempt=operation.next_attempt,
        expected_generation=operation.generation,
        expected_sequence=operation.sequence,
        expected_head_hash=operation.event_head_hash,
        ownership_token=operation.ownership_token,
    )


def _claim_controller_authorization(
    store: OllamaV2ControllerStore,
    operation: OperationSnapshot,
    request: AuthorizationRequest,
) -> OperationSnapshot:
    pending = store.record_authorization_pending(operation, request).snapshot
    return store.record_authorization_claimed(pending, request).snapshot


def _attach_studio_authorization_port(
    store: OllamaV2ControllerStore,
    port: object,
    plan: ControllerPlan,
) -> OllamaV2Controller:
    inspector = _Inspector()
    effects = _Effects(inspector)
    effects.plan = plan
    return OllamaV2Controller(store, inspector, port, effects)


class _NthCommitFaultConnection:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        fail_at: int,
        effect: bool,
        after_effect=None,
    ) -> None:
        self._connection = connection
        self._fail_at = fail_at
        self._effect = effect
        self._count = 0
        self._after_effect = after_effect

    def __getattr__(self, name: str):
        return getattr(self._connection, name)

    def commit(self) -> None:
        self._count += 1
        if self._count == self._fail_at:
            if self._effect:
                self._connection.commit()
                if self._after_effect is not None:
                    self._after_effect(self._connection)
            raise sqlite3.OperationalError("injected authorization commit failure")
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()


class _BlockingImmediateConnection:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self.block = False
        self.entered = threading.Event()
        self.release = threading.Event()

    def __getattr__(self, name: str):
        return getattr(self._connection, name)

    def execute(self, sql: str, parameters=()):
        if self.block and sql == "BEGIN IMMEDIATE":
            self.entered.set()
            if not self.release.wait(timeout=5):
                raise RuntimeError("blocking transaction timed out")
        return self._connection.execute(sql, parameters)

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()


class StudioOllamaV2AuthorizationDomainTests(unittest.TestCase):
    def test_credential_created_at_drift_blocks_consumption_before_any_c_mutation(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            plan = build_controller_plan(
                make_empty_host_snapshot(
                    "snap-credential-created-at-drift",
                    observed_generation=0,
                ),
                *_manifests(),
                operation_id="op-credential-created-at-drift",
            )
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-credential-created-at-drift",
            )
            review = control.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(
                review,
                expected_generation=0,
            )
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            inspector = _Inspector()
            effects = _Effects(inspector)
            effects.plan = plan
            OllamaV2Controller(controller_store, inspector, port, effects)
            request = _request_for_effect(operation, plan.effects[0])
            claimed = _claim_controller_authorization(
                controller_store,
                operation,
                request,
            )
            event_count = studio.connection.execute(
                "SELECT count(*) FROM studio_ollama_v2_authorization_events"
            ).fetchone()[0]
            original_created_at = studio.connection.execute(
                "SELECT created_at FROM studio_authenticated_human_credentials"
            ).fetchone()[0]
            drifted_created_at = "2000-01-01T00:00:00.000000Z"
            self.assertNotEqual(original_created_at, drifted_created_at)
            studio.connection.execute(
                "UPDATE studio_authenticated_human_credentials SET created_at=?",
                (drifted_created_at,),
            )
            studio.connection.commit()

            domain = control._ollama_v2_authorizations
            self.assertIsNotNone(domain)
            with self.assertRaises(ApprovalError):
                domain._credential = object()
            with (
                mock.patch.object(
                    authorization_module,
                    "_credential_evidence",
                    return_value=control._authority._credential,
                ),
                mock.patch.object(
                    authorization_module,
                    "_same_credential",
                    return_value=True,
                ),
                mock.patch.object(
                    authorization_module,
                    "_CredentialEvidence",
                    object,
                ),
                mock.patch.object(
                    StudioOllamaV2AuthorizationDomain,
                    "_audit",
                    return_value=(0, "0" * 64),
                ),
            ):
                with self.assertRaisesRegex(StudioError, "authorization audit failed"):
                    port.consume(request)
            self.assertEqual(
                event_count,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                ).fetchone()[0],
            )
            self.assertEqual(
                0,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0],
            )
            self.assertEqual(
                claimed,
                controller_store.load_operation(operation.operation_id),
            )
            self.assertEqual([], effects.calls)
            self.assertFalse(studio.connection.in_transaction)
            self.assertFalse(controller_store._connection.in_transaction)

    def test_complete_credential_evidence_is_exact_and_clean_row_remains_usable(self) -> None:
        cases = (
            ("clean", None, None),
            ("credential_id", "credential_id", "director_other"),
            ("kdf_name", "kdf_name", "other"),
            ("kdf_n", "kdf_n", 0),
            ("kdf_r", "kdf_r", 0),
            ("kdf_p", "kdf_p", 0),
            ("kdf_dklen", "kdf_dklen", 0),
            ("kdf_maxmem", "kdf_maxmem", 0),
            ("salt", "salt", b"s" * 32),
            ("verifier", "verifier", b"v" * 32),
            ("created_at_noncanonical", "created_at", "2000-01-01T00:00:00Z"),
            ("created_at_type", "created_at", sqlite3.Binary(b"not-a-timestamp")),
        )
        for suffix, field, replacement in cases:
            with (
                self.subTest(suffix=suffix),
                tempfile.TemporaryDirectory() as directory,
                StudioStore(Path(directory) / "studio") as studio,
                OllamaV2ControllerStore(
                    Path(directory) / "controller.sqlite3"
                ) as controller_store,
            ):
                control = StudioDirectorControl(studio)
                control.enroll(passphrase=PASSPHRASE)
                plan = build_controller_plan(
                    make_empty_host_snapshot(
                        f"snap-credential-{suffix}",
                        observed_generation=0,
                    ),
                    *_manifests(),
                    operation_id=f"op-credential-{suffix}",
                )
                operation = _persist_controller_operation(
                    controller_store,
                    plan,
                    idempotency_key=f"create-credential-{suffix}",
                )
                review = control.build_ollama_v2_authorization_review(
                    operation,
                    plan,
                    phase="apply",
                )
                prepared = control.prepare_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                )
                approved = control.approve_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                    expected_review_hash=prepared["review"]["content_hash"],
                    expires_at_ms=9_007_199_254_740_991,
                )
                port = control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
                inspector = _Inspector()
                effects = _Effects(inspector)
                effects.plan = plan
                OllamaV2Controller(controller_store, inspector, port, effects)
                request = _request_for_effect(operation, plan.effects[0])
                claimed = _claim_controller_authorization(
                    controller_store,
                    operation,
                    request,
                )
                event_count = studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                ).fetchone()[0]

                if field is None:
                    self.assertTrue(port.consume(request).matches(request))
                    expected_event_count = event_count + 1
                    expected_consumptions = 1
                else:
                    studio.connection.execute("PRAGMA foreign_keys=OFF")
                    studio.connection.execute("PRAGMA ignore_check_constraints=ON")
                    studio.connection.execute(
                        f"UPDATE studio_authenticated_human_credentials SET {field}=?",
                        (replacement,),
                    )
                    studio.connection.commit()
                    studio.connection.execute("PRAGMA ignore_check_constraints=OFF")
                    studio.connection.execute("PRAGMA foreign_keys=ON")
                    with self.assertRaisesRegex(
                        StudioError,
                        "authorization audit failed",
                    ):
                        port.consume(request)
                    expected_event_count = event_count
                    expected_consumptions = 0

                self.assertEqual(
                    expected_event_count,
                    studio.connection.execute(
                        "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    expected_consumptions,
                    studio.connection.execute(
                        "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    claimed,
                    controller_store.load_operation(operation.operation_id),
                )
                self.assertEqual([], effects.calls)
                self.assertFalse(studio.connection.in_transaction)
                self.assertFalse(controller_store._connection.in_transaction)

    def test_consumed_event_cannot_be_reclassified_as_revoked_generation(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
            OllamaV2ControllerStore(Path(directory) / "controller.sqlite3") as controller_store,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-event-transition", observed_generation=0),
                *_manifests(),
                operation_id="op-event-transition",
            )
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-event-transition",
            )
            review = control.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(
                review,
                expected_generation=0,
            )
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            inspector = _Inspector()
            effects = _Effects(inspector)
            effects.plan = plan
            OllamaV2Controller(controller_store, inspector, port, effects)
            request = _request_for_effect(operation, plan.effects[0])
            claimed = _claim_controller_authorization(controller_store, operation, request)
            port.consume(request)

            domain = control._ollama_v2_authorizations
            self.assertIsNotNone(domain)
            event = dict(
                studio.connection.execute(
                    "SELECT * FROM studio_ollama_v2_authorization_events "
                    "ORDER BY event_id DESC LIMIT 1"
                ).fetchone()
            )
            hostile = json.loads(event["content_json"])
            self.assertEqual("consumed", hostile["event_type"])
            self.assertEqual(1, hostile["generation"])
            self.assertEqual("approved", hostile["state"])
            hostile["generation"] = 2
            hostile["state"] = "revoked"
            content_bytes = authorization_module._canonical(hostile)
            content_json = content_bytes.decode("utf-8")
            content_hash = hashlib.sha256(content_bytes).hexdigest()
            event_mac = authorization_module._event_mac(domain._event_key, hostile)
            studio.connection.execute(
                "UPDATE studio_ollama_v2_authorization_events SET generation=?, "
                "content_json=?, content_hash=?, mac=? WHERE event_id=?",
                (2, content_json, content_hash, event_mac, event["event_id"]),
            )
            studio.connection.execute(
                "UPDATE studio_ollama_v2_authorization_decisions SET state='revoked', "
                "generation=2, last_event_hash=? WHERE mandate_id=?",
                (content_hash, review["mandate_id"]),
            )
            studio.connection.execute(
                "UPDATE studio_ollama_v2_authorization_consumptions SET event_hash=? "
                "WHERE mandate_id=?",
                (content_hash, review["mandate_id"]),
            )
            studio.connection.commit()
            event_count = studio.connection.execute(
                "SELECT count(*) FROM studio_ollama_v2_authorization_events"
            ).fetchone()[0]
            consumption_count = studio.connection.execute(
                "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
            ).fetchone()[0]

            with self.assertRaisesRegex(StudioError, "authorization audit failed"):
                control.inspect_ollama_v2_authorization(review)
            self.assertEqual(
                event_count,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                ).fetchone()[0],
            )
            self.assertEqual(
                consumption_count,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0],
            )
            self.assertEqual([], effects.calls)
            self.assertFalse(studio.connection.in_transaction)
            self.assertFalse(controller_store._connection.in_transaction)

    def test_every_event_kind_rejects_legal_but_wrong_generation_state_pair(self) -> None:
        cases = (
            ("prepared", 1, "approved"),
            ("approved", 2, "revoked"),
            ("denied", 2, "revoked"),
            ("revoked", 1, "approved"),
        )
        for stage, hostile_generation, hostile_state in cases:
            with (
                self.subTest(stage=stage),
                tempfile.TemporaryDirectory() as directory,
                StudioStore(Path(directory) / "studio") as studio,
            ):
                control = StudioDirectorControl(studio)
                control.enroll(passphrase=PASSPHRASE)
                plan = build_controller_plan(
                    make_empty_host_snapshot(
                        f"snap-event-pair-{stage}",
                        observed_generation=0,
                    ),
                    *_manifests(),
                    operation_id=f"op-event-pair-{stage}",
                )
                operation = OperationSnapshot.create(plan.operation_id, plan)
                review = control.build_ollama_v2_authorization_review(
                    operation,
                    plan,
                    phase="apply",
                )
                prepared = control.prepare_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                )
                decision = None
                if stage == "denied":
                    decision = control.deny_ollama_v2_authorization(
                        review,
                        expected_generation=0,
                        expected_review_hash=prepared["review"]["content_hash"],
                    )
                elif stage != "prepared":
                    decision = control.approve_ollama_v2_authorization(
                        review,
                        expected_generation=0,
                        expected_review_hash=prepared["review"]["content_hash"],
                        expires_at_ms=9_007_199_254_740_991,
                    )
                if stage == "revoked":
                    control.revoke_ollama_v2_authorization(
                        review,
                        expected_generation=1,
                        expected_decision_hash=decision["decision"]["content_hash"],
                        expected_consumed_slots=0,
                    )

                domain = control._ollama_v2_authorizations
                self.assertIsNotNone(domain)
                event = dict(
                    studio.connection.execute(
                        "SELECT * FROM studio_ollama_v2_authorization_events "
                        "ORDER BY event_id DESC LIMIT 1"
                    ).fetchone()
                )
                hostile = json.loads(event["content_json"])
                self.assertNotEqual(
                    (hostile_generation, hostile_state),
                    (hostile["generation"], hostile["state"]),
                )
                hostile["generation"] = hostile_generation
                hostile["state"] = hostile_state
                content_bytes = authorization_module._canonical(hostile)
                content_json = content_bytes.decode("utf-8")
                content_hash = hashlib.sha256(content_bytes).hexdigest()
                event_mac = authorization_module._event_mac(domain._event_key, hostile)
                studio.connection.execute("PRAGMA ignore_check_constraints=ON")
                studio.connection.execute(
                    "UPDATE studio_ollama_v2_authorization_events SET generation=?, "
                    "content_json=?, content_hash=?, mac=? WHERE event_id=?",
                    (
                        hostile_generation,
                        content_json,
                        content_hash,
                        event_mac,
                        event["event_id"],
                    ),
                )
                studio.connection.execute(
                    "UPDATE studio_ollama_v2_authorization_decisions SET state=?, "
                    "generation=?, last_event_hash=? WHERE mandate_id=?",
                    (
                        hostile_state,
                        hostile_generation,
                        content_hash,
                        review["mandate_id"],
                    ),
                )
                studio.connection.commit()
                studio.connection.execute("PRAGMA ignore_check_constraints=OFF")

                with self.assertRaisesRegex(StudioError, "authorization audit failed"):
                    control.inspect_ollama_v2_authorization(review)
                self.assertFalse(studio.connection.in_transaction)

    def test_authenticated_event_replay_rejects_exact_json_scalar_types(self) -> None:
        stages = ("prepared", "approved", "denied", "consumed", "revoked")
        expected_event_types = {
            "prepared": "prepared",
            "approved": "decided",
            "denied": "decided",
            "consumed": "consumed",
            "revoked": "revoked",
        }
        for stage in stages:
            with (
                self.subTest(stage=stage),
                tempfile.TemporaryDirectory() as directory,
                StudioStore(Path(directory) / "studio") as studio,
            ):
                control = StudioDirectorControl(studio)
                control.enroll(passphrase=PASSPHRASE)
                plan = build_controller_plan(
                    make_empty_host_snapshot(
                        f"snap-event-scalars-{stage}",
                        observed_generation=0,
                    ),
                    *_manifests(),
                    operation_id=f"op-event-scalars-{stage}",
                )
                controller_store = None
                if stage == "consumed":
                    controller_store = OllamaV2ControllerStore(
                        Path(directory) / "controller.sqlite3"
                    )
                    operation = _persist_controller_operation(
                        controller_store,
                        plan,
                        idempotency_key="create-event-scalars-consumed",
                    )
                else:
                    operation = OperationSnapshot.create(plan.operation_id, plan)
                review = control.build_ollama_v2_authorization_review(
                    operation,
                    plan,
                    phase="apply",
                )
                prepared = control.prepare_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                )
                decision = None
                if stage == "denied":
                    decision = control.deny_ollama_v2_authorization(
                        review,
                        expected_generation=0,
                        expected_review_hash=prepared["review"]["content_hash"],
                    )
                elif stage != "prepared":
                    decision = control.approve_ollama_v2_authorization(
                        review,
                        expected_generation=0,
                        expected_review_hash=prepared["review"]["content_hash"],
                        expires_at_ms=9_007_199_254_740_991,
                    )
                if stage == "consumed":
                    port = control.bind_ollama_v2_authorization(
                        review,
                        controller_store=controller_store,
                        operation_id=operation.operation_id,
                        expected_generation=1,
                        expected_decision_hash=decision["decision"]["content_hash"],
                    )
                    _attach_studio_authorization_port(controller_store, port, plan)
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
                    _claim_controller_authorization(
                        controller_store,
                        operation,
                        request,
                    )
                    port.consume(request)
                    controller_store.close()
                elif stage == "revoked":
                    control.revoke_ollama_v2_authorization(
                        review,
                        expected_generation=1,
                        expected_decision_hash=decision["decision"]["content_hash"],
                        expected_consumed_slots=0,
                    )

                control.inspect_ollama_v2_authorization(review)
                event = dict(
                    studio.connection.execute(
                        "SELECT * FROM studio_ollama_v2_authorization_events "
                        "ORDER BY event_id DESC LIMIT 1"
                    ).fetchone()
                )
                projection = dict(
                    studio.connection.execute(
                        "SELECT * FROM studio_ollama_v2_authorization_decisions WHERE mandate_id=?",
                        (review["mandate_id"],),
                    ).fetchone()
                )
                consumption_row = studio.connection.execute(
                    "SELECT * FROM studio_ollama_v2_authorization_consumptions WHERE mandate_id=?",
                    (review["mandate_id"],),
                ).fetchone()
                consumption = None if consumption_row is None else dict(consumption_row)
                outcome_row = studio.connection.execute(
                    "SELECT * FROM studio_ollama_v2_authorization_outcomes WHERE mandate_id=?",
                    (review["mandate_id"],),
                ).fetchone()
                outcome = None if outcome_row is None else dict(outcome_row)
                original_document = json.loads(event["content_json"])
                self.assertEqual(expected_event_types[stage], original_document["event_type"])

                def restore(
                    event=event,
                    projection=projection,
                    review=review,
                    consumption=consumption,
                    outcome=outcome,
                    studio=studio,
                ) -> None:
                    studio.connection.execute("PRAGMA defer_foreign_keys = ON")
                    studio.connection.execute(
                        "UPDATE studio_ollama_v2_authorization_events SET "
                        "generation=?, event_type=?, slot_ordinal=?, content_json=?, "
                        "content_hash=?, previous_hash=?, mac=?, created_at=? "
                        "WHERE event_id=?",
                        (
                            event["generation"],
                            event["event_type"],
                            event["slot_ordinal"],
                            event["content_json"],
                            event["content_hash"],
                            event["previous_hash"],
                            event["mac"],
                            event["created_at"],
                            event["event_id"],
                        ),
                    )
                    studio.connection.execute(
                        "UPDATE studio_ollama_v2_authorization_decisions SET "
                        "review_hash=?, review_json=?, decision_hash=?, decision_json=?, "
                        "last_event_hash=? WHERE mandate_id=?",
                        (
                            projection["review_hash"],
                            projection["review_json"],
                            projection["decision_hash"],
                            projection["decision_json"],
                            projection["last_event_hash"],
                            review["mandate_id"],
                        ),
                    )
                    if consumption is not None:
                        studio.connection.execute(
                            "UPDATE studio_ollama_v2_authorization_consumptions SET "
                            "consumption_id=?, authorization_id=?, request_hash=?, "
                            "request_json=?, consumption_hash=?, consumption_json=?, "
                            "event_hash=? WHERE mandate_id=?",
                            (
                                consumption["consumption_id"],
                                consumption["authorization_id"],
                                consumption["request_hash"],
                                consumption["request_json"],
                                consumption["consumption_hash"],
                                consumption["consumption_json"],
                                consumption["event_hash"],
                                review["mandate_id"],
                            ),
                        )
                    if outcome is not None:
                        studio.connection.execute(
                            "UPDATE studio_ollama_v2_authorization_outcomes SET "
                            "outcome_id=?, authorization_id=?, request_hash=?, request_json=?, "
                            "outcome_hash=?, outcome_json=?, event_hash=?, consumption_id=? "
                            "WHERE mandate_id=?",
                            (
                                outcome["outcome_id"],
                                outcome["authorization_id"],
                                outcome["request_hash"],
                                outcome["request_json"],
                                outcome["outcome_hash"],
                                outcome["outcome_json"],
                                outcome["event_hash"],
                                outcome["consumption_id"],
                                review["mandate_id"],
                            ),
                        )
                    studio.connection.commit()

                cases: list[tuple[tuple[str, ...], object, str]] = []
                for path in _event_integer_paths(original_document):
                    original = _document_path(original_document, path)
                    self.assertIs(type(original), int)
                    cases.extend(
                        (
                            (path, bool(original), "bool"),
                            (path, float(original), "integral_float"),
                        )
                    )
                cases.extend(
                    (
                        (("created_at",), False, "bool_for_timestamp"),
                        (("created_at",), [], "list_for_timestamp"),
                        (("created_at",), {}, "dict_for_timestamp"),
                        (("event_type",), False, "bool_for_literal"),
                        (("event_type",), [], "list_for_literal"),
                        (("event_type",), {}, "dict_for_literal"),
                        (("review",), False, "bool_for_document"),
                        (("review",), "review", "string_for_document"),
                        (("review",), [], "list_for_document"),
                    )
                )
                for payload_name in ("decision", "request", "consumption"):
                    cases.extend(
                        (
                            ((payload_name,), False, "bool_for_optional_document"),
                            ((payload_name,), payload_name, "string_for_optional_document"),
                            ((payload_name,), [], "list_for_optional_document"),
                            ((payload_name,), {}, "dict_for_optional_document"),
                        )
                    )
                if original_document["slot_ordinal"] is None:
                    cases.extend(
                        (
                            (("slot_ordinal",), False, "bool_for_null_ordinal"),
                            (("slot_ordinal",), "0", "string_for_null_ordinal"),
                            (("slot_ordinal",), [], "list_for_null_ordinal"),
                            (("slot_ordinal",), {}, "dict_for_null_ordinal"),
                        )
                    )
                else:
                    cases.extend(
                        (
                            (("slot_ordinal",), "0", "string_for_ordinal"),
                            (("slot_ordinal",), [], "list_for_ordinal"),
                            (("slot_ordinal",), {}, "dict_for_ordinal"),
                        )
                    )
                if type(original_document.get("consumption")) is dict:
                    cases.extend(
                        (
                            (("consumption", "single_use"), 1, "int_for_bool"),
                            (("consumption", "single_use"), "true", "string_for_bool"),
                            (("consumption", "single_use"), [], "list_for_bool"),
                            (("consumption", "single_use"), {}, "dict_for_bool"),
                        )
                    )
                self.assertGreaterEqual(len(cases), 25)

                domain = control._ollama_v2_authorizations
                self.assertIsNotNone(domain)
                for path, replacement, variant in cases:
                    with self.subTest(stage=stage, path=path, variant=variant):
                        restore()
                        hostile = copy.deepcopy(original_document)
                        original = _document_path(hostile, path)
                        if type(original) is type(replacement):
                            self.assertNotEqual(original, replacement)
                        else:
                            self.assertIsNot(type(original), type(replacement))
                        _set_document_path(hostile, path, replacement)
                        _reseal_hostile_event_documents(hostile, path)
                        content_bytes = authorization_module._canonical(hostile)
                        content_json = content_bytes.decode("utf-8")
                        content_hash = hashlib.sha256(content_bytes).hexdigest()
                        event_mac = authorization_module._event_mac(
                            domain._event_key,
                            hostile,
                        )
                        self.assertNotEqual(event["content_hash"], content_hash)
                        studio.connection.execute("PRAGMA defer_foreign_keys = ON")
                        studio.connection.execute(
                            "UPDATE studio_ollama_v2_authorization_events SET "
                            "content_json=?, content_hash=?, mac=? WHERE event_id=?",
                            (content_json, content_hash, event_mac, event["event_id"]),
                        )
                        hostile_review = hostile.get("review")
                        hostile_decision = hostile.get("decision")
                        review_hash = projection["review_hash"]
                        review_json = projection["review_json"]
                        decision_hash = projection["decision_hash"]
                        decision_json = projection["decision_json"]
                        if (
                            type(hostile_review) is dict
                            and type(hostile_review.get("content_hash")) is str
                        ):
                            review_hash = hostile_review["content_hash"]
                            review_json = authorization_module._canonical(hostile_review).decode(
                                "utf-8"
                            )
                        if (
                            type(hostile_decision) is dict
                            and type(hostile_decision.get("content_hash")) is str
                        ):
                            decision_hash = hostile_decision["content_hash"]
                            decision_json = authorization_module._canonical(
                                hostile_decision
                            ).decode("utf-8")
                        studio.connection.execute(
                            "UPDATE studio_ollama_v2_authorization_decisions SET "
                            "review_hash=?, review_json=?, decision_hash=?, decision_json=?, "
                            "last_event_hash=? WHERE mandate_id=?",
                            (
                                review_hash,
                                review_json,
                                decision_hash,
                                decision_json,
                                content_hash,
                                review["mandate_id"],
                            ),
                        )
                        if consumption is not None:
                            hostile_request = hostile.get("request")
                            hostile_consumption = hostile.get("consumption")
                            request_json = consumption["request_json"]
                            request_hash = consumption["request_hash"]
                            authorization_id = consumption["authorization_id"]
                            consumption_id = consumption["consumption_id"]
                            consumption_hash = consumption["consumption_hash"]
                            consumption_json = consumption["consumption_json"]
                            if type(hostile_request) is dict and {
                                "content_hash",
                                "authorization_id",
                            } <= set(hostile_request):
                                request_json = authorization_module._canonical(
                                    hostile_request
                                ).decode("utf-8")
                                request_hash = hostile_request["content_hash"]
                                authorization_id = hostile_request["authorization_id"]
                            if type(hostile_consumption) is dict and {
                                "consumption_id",
                                "content_hash",
                            } <= set(hostile_consumption):
                                consumption_id = hostile_consumption["consumption_id"]
                                consumption_hash = hostile_consumption["content_hash"]
                                consumption_json = authorization_module._canonical(
                                    hostile_consumption
                                ).decode("utf-8")
                            studio.connection.execute(
                                "UPDATE studio_ollama_v2_authorization_consumptions SET "
                                "consumption_id=?, authorization_id=?, request_hash=?, "
                                "request_json=?, consumption_hash=?, consumption_json=?, "
                                "event_hash=? WHERE mandate_id=?",
                                (
                                    consumption_id,
                                    authorization_id,
                                    request_hash,
                                    request_json,
                                    consumption_hash,
                                    consumption_json,
                                    content_hash,
                                    review["mandate_id"],
                                ),
                            )
                            studio.connection.execute(
                                "UPDATE studio_ollama_v2_authorization_outcomes SET "
                                "outcome_id=?, authorization_id=?, request_hash=?, "
                                "request_json=?, outcome_hash=?, outcome_json=?, "
                                "event_hash=?, consumption_id=? WHERE mandate_id=?",
                                (
                                    consumption_id,
                                    authorization_id,
                                    request_hash,
                                    request_json,
                                    consumption_hash,
                                    consumption_json,
                                    content_hash,
                                    consumption_id,
                                    review["mandate_id"],
                                ),
                            )
                        studio.connection.commit()
                        stored = studio.connection.execute(
                            "SELECT content_hash, mac FROM "
                            "studio_ollama_v2_authorization_events WHERE event_id=?",
                            (event["event_id"],),
                        ).fetchone()
                        self.assertEqual(content_hash, stored["content_hash"])
                        self.assertEqual(event_mac, stored["mac"])
                        self.assertEqual(
                            content_hash,
                            studio.connection.execute(
                                "SELECT last_event_hash FROM "
                                "studio_ollama_v2_authorization_decisions WHERE mandate_id=?",
                                (review["mandate_id"],),
                            ).fetchone()[0],
                        )
                        with self.assertRaisesRegex(
                            StudioError,
                            "authorization audit failed",
                        ):
                            control.inspect_ollama_v2_authorization(review)
                restore()

    def test_prepare_commit_third_state_poisons_domain_and_live_director_authority(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            initial = StudioDirectorControl(studio)
            initial.enroll(passphrase=PASSPHRASE)
            initial.lock()
            raw = studio._authenticated_human_decision_connection_instance
            self.assertIsNotNone(raw)

            def create_third_state(connection) -> None:
                connection.execute(
                    "UPDATE studio_ollama_v2_authorization_decisions "
                    "SET updated_at='2026-01-01T00:00:00.000000Z'"
                )
                connection.commit()

            studio._authenticated_human_decision_connection_instance = _NthCommitFaultConnection(
                raw, fail_at=3, effect=True, after_effect=create_third_state
            )
            control = StudioDirectorControl(studio)
            control.unlock(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-commit-third", observed_generation=0),
                *_manifests(),
                operation_id="op-commit-third",
            )
            operation = OperationSnapshot.create(plan.operation_id, plan)
            review = control.build_ollama_v2_authorization_review(operation, plan, phase="apply")
            with (
                mock.patch.object(
                    StudioOllamaV2AuthorizationDomain,
                    "_poison",
                    side_effect=AssertionError("late poison replacement"),
                ),
                self.assertRaisesRegex(StudioError, "outcome is indeterminate"),
            ):
                control.prepare_ollama_v2_authorization(review, expected_generation=0)
            self.assertTrue(control._authority._poisoned)
            with self.assertRaisesRegex(StudioError, "unavailable"):
                control.inspect_ollama_v2_authorization(review)

    def test_prepare_commit_exception_distinguishes_exact_pre_and_post_without_ownership(
        self,
    ) -> None:
        for effect in (False, True):
            with self.subTest(effect=effect), tempfile.TemporaryDirectory() as directory:
                with StudioStore(Path(directory) / "studio") as studio:
                    initial = StudioDirectorControl(studio)
                    initial.enroll(passphrase=PASSPHRASE)
                    initial.lock()
                    raw = studio._authenticated_human_decision_connection_instance
                    self.assertIsNotNone(raw)
                    proxy = _NthCommitFaultConnection(raw, fail_at=3, effect=effect)
                    studio._authenticated_human_decision_connection_instance = proxy
                    control = StudioDirectorControl(studio)
                    control.unlock(passphrase=PASSPHRASE)
                    plan = build_controller_plan(
                        make_empty_host_snapshot(
                            f"snap-commit-{'post' if effect else 'pre'}",
                            observed_generation=0,
                        ),
                        *_manifests(),
                        operation_id=f"op-commit-{'post' if effect else 'pre'}",
                    )
                    operation = OperationSnapshot.create(plan.operation_id, plan)
                    review = control.build_ollama_v2_authorization_review(
                        operation, plan, phase="apply"
                    )
                    expected_error = StudioError if effect else sqlite3.OperationalError
                    with self.assertRaises(expected_error):
                        control.prepare_ollama_v2_authorization(review, expected_generation=0)
                    count = studio.connection.execute(
                        "SELECT count(*) FROM studio_ollama_v2_authorization_decisions"
                    ).fetchone()[0]
                    self.assertEqual(1 if effect else 0, count)
                    if effect:
                        self.assertEqual(
                            "prepared",
                            control.inspect_ollama_v2_authorization(review)["status"],
                        )

    def test_decide_revoke_and_consume_commit_pre_post_are_nonowning(self) -> None:
        for transition, fail_at in (("decide", 4), ("revoke", 5), ("consume", 6)):
            for effect in (False, True):
                with (
                    self.subTest(transition=transition, effect=effect),
                    tempfile.TemporaryDirectory() as directory,
                    StudioStore(Path(directory) / "studio") as studio,
                ):
                    initial = StudioDirectorControl(studio)
                    initial.enroll(passphrase=PASSPHRASE)
                    initial.lock()
                    raw = studio._authenticated_human_decision_connection_instance
                    self.assertIsNotNone(raw)
                    studio._authenticated_human_decision_connection_instance = (
                        _NthCommitFaultConnection(raw, fail_at=fail_at, effect=effect)
                    )
                    control = StudioDirectorControl(studio)
                    control.unlock(passphrase=PASSPHRASE)
                    plan = build_controller_plan(
                        make_empty_host_snapshot(
                            f"snap-{transition}-commit-{'post' if effect else 'pre'}",
                            observed_generation=0,
                        ),
                        *_manifests(),
                        operation_id=(f"op-{transition}-commit-{'post' if effect else 'pre'}"),
                    )
                    controller_store = None
                    if transition == "consume":
                        controller_store = OllamaV2ControllerStore(
                            Path(directory) / "controller.sqlite3"
                        )
                        operation = _persist_controller_operation(
                            controller_store,
                            plan,
                            idempotency_key=(
                                f"create-{transition}-commit-{'post' if effect else 'pre'}"
                            ),
                        )
                    else:
                        operation = OperationSnapshot.create(plan.operation_id, plan)
                    review = control.build_ollama_v2_authorization_review(
                        operation, plan, phase="apply"
                    )
                    prepared = control.prepare_ollama_v2_authorization(
                        review, expected_generation=0
                    )
                    approved = None
                    if transition != "decide":
                        approved = control.approve_ollama_v2_authorization(
                            review,
                            expected_generation=0,
                            expected_review_hash=prepared["review"]["content_hash"],
                            expires_at_ms=9_007_199_254_740_991,
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
                    port = None
                    if transition == "consume":
                        port = control.bind_ollama_v2_authorization(
                            review,
                            controller_store=controller_store,
                            operation_id=operation.operation_id,
                            expected_generation=1,
                            expected_decision_hash=approved["decision"]["content_hash"],
                        )
                        _attach_studio_authorization_port(controller_store, port, plan)
                        _claim_controller_authorization(
                            controller_store,
                            operation,
                            request,
                        )
                    def transition_call():
                        if transition == "decide":
                            return control.approve_ollama_v2_authorization(
                                review,
                                expected_generation=0,
                                expected_review_hash=prepared["review"]["content_hash"],
                                expires_at_ms=9_007_199_254_740_991,
                            )
                        elif transition == "revoke":
                            return control.revoke_ollama_v2_authorization(
                                review,
                                expected_generation=1,
                                expected_decision_hash=approved["decision"]["content_hash"],
                                expected_consumed_slots=0,
                            )
                        else:
                            return port.consume(request)

                    if transition == "consume" and effect:
                        self.assertIsInstance(
                            transition_call(),
                            AuthorizationConsumption,
                        )
                    else:
                        expected_error = StudioError if effect else sqlite3.OperationalError
                        with self.assertRaises(expected_error):
                            transition_call()
                    snapshot = control.inspect_ollama_v2_authorization(review)
                    if transition == "decide":
                        self.assertEqual("consumable" if effect else "prepared", snapshot["status"])
                    elif transition == "revoke":
                        self.assertEqual("revoked" if effect else "consumable", snapshot["status"])
                    elif effect:
                        self.assertEqual(
                            "apply_authorization_claimed",
                            controller_store.load_operation(operation.operation_id).state,
                        )
                        self.assertTrue(port.resolve(request).matches(request))
                    else:
                        self.assertIsNone(port.resolve(request))
                    if controller_store is not None:
                        controller_store.close()

    def test_decide_revoke_and_consume_commit_third_state_poison_authority(self) -> None:
        for transition, fail_at in (("decide", 4), ("revoke", 5), ("consume", 6)):
            with (
                self.subTest(transition=transition),
                tempfile.TemporaryDirectory() as directory,
                StudioStore(Path(directory) / "studio") as studio,
            ):
                initial = StudioDirectorControl(studio)
                initial.enroll(passphrase=PASSPHRASE)
                initial.lock()
                raw = studio._authenticated_human_decision_connection_instance
                self.assertIsNotNone(raw)

                def create_third_state(connection) -> None:
                    connection.execute(
                        "UPDATE studio_ollama_v2_authorization_decisions "
                        "SET updated_at='2026-01-01T00:00:00.000000Z'"
                    )
                    connection.commit()

                studio._authenticated_human_decision_connection_instance = (
                    _NthCommitFaultConnection(
                        raw,
                        fail_at=fail_at,
                        effect=True,
                        after_effect=create_third_state,
                    )
                )
                control = StudioDirectorControl(studio)
                control.unlock(passphrase=PASSPHRASE)
                plan = build_controller_plan(
                    make_empty_host_snapshot(
                        f"snap-{transition}-commit-third", observed_generation=0
                    ),
                    *_manifests(),
                    operation_id=f"op-{transition}-commit-third",
                )
                controller_store = None
                if transition == "consume":
                    controller_store = OllamaV2ControllerStore(
                        Path(directory) / "controller.sqlite3"
                    )
                    operation = _persist_controller_operation(
                        controller_store,
                        plan,
                        idempotency_key="create-consume-commit-third",
                    )
                else:
                    operation = OperationSnapshot.create(plan.operation_id, plan)
                review = control.build_ollama_v2_authorization_review(
                    operation, plan, phase="apply"
                )
                prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
                approved = None
                if transition != "decide":
                    approved = control.approve_ollama_v2_authorization(
                        review,
                        expected_generation=0,
                        expected_review_hash=prepared["review"]["content_hash"],
                        expires_at_ms=9_007_199_254_740_991,
                    )
                with self.assertRaisesRegex(StudioError, "outcome is indeterminate"):
                    if transition == "decide":
                        control.approve_ollama_v2_authorization(
                            review,
                            expected_generation=0,
                            expected_review_hash=prepared["review"]["content_hash"],
                            expires_at_ms=9_007_199_254_740_991,
                        )
                    elif transition == "revoke":
                        control.revoke_ollama_v2_authorization(
                            review,
                            expected_generation=1,
                            expected_decision_hash=approved["decision"]["content_hash"],
                            expected_consumed_slots=0,
                        )
                    else:
                        port = control.bind_ollama_v2_authorization(
                            review,
                            controller_store=controller_store,
                            operation_id=operation.operation_id,
                            expected_generation=1,
                            expected_decision_hash=approved["decision"]["content_hash"],
                        )
                        _attach_studio_authorization_port(controller_store, port, plan)
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
                        _claim_controller_authorization(
                            controller_store,
                            operation,
                            request,
                        )
                        port.consume(request)
                if controller_store is not None:
                    controller_store.close()
                self.assertTrue(control._authority._poisoned)
                with self.assertRaisesRegex(StudioError, "unavailable"):
                    control.inspect_ollama_v2_authorization(review)

    def test_no_effect_retry_requires_fresh_mandate_at_new_snapshot(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            inspector = _Inspector()
            effects = _Effects(inspector)
            bootstrap = OllamaV2Controller(
                controller_store, inspector, _BootstrapAuthorization(), effects
            )
            plan = build_controller_plan(
                inspector.snapshot,
                *_manifests(),
                operation_id="op-no-effect",
            )
            effects.plan = plan
            operation = bootstrap.create_operation(
                plan,
                operation_id=plan.operation_id,
                idempotency_key="create-no-effect",
            )
            review = control.build_ollama_v2_authorization_review(operation, plan, phase="apply")
            prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            controller = OllamaV2Controller(controller_store, inspector, port, effects)
            effects.no_effect_once = True
            retriable = controller.advance_apply(operation)
            self.assertEqual("apply_pending", retriable.state)
            self.assertEqual(0, retriable.apply_cursor)
            self.assertEqual(operation.next_attempt + 1, retriable.next_attempt)
            self.assertEqual(1, control.inspect_ollama_v2_authorization(review)["consumed_slots"])
            with self.assertRaises(ControllerAuthorizationError):
                controller.advance_apply(retriable)

            fresh_review = control.build_ollama_v2_authorization_review(
                retriable, plan, phase="apply"
            )
            self.assertNotEqual(review["mandate_id"], fresh_review["mandate_id"])

    def test_expired_pending_mandate_rebinds_only_to_settle_rejection(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-expired", observed_generation=0),
                *_manifests(),
                operation_id="op-expired",
            )
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-expired",
            )
            review = control.build_ollama_v2_authorization_review(operation, plan, phase="apply")
            prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=time.time_ns() // 1_000_000 + 500,
            )
            time.sleep(0.55)
            self.assertEqual("expired", control.inspect_ollama_v2_authorization(review)["status"])
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            inspector = _Inspector()
            effects = _Effects(inspector)
            effects.plan = plan
            controller = OllamaV2Controller(
                controller_store,
                inspector,
                port,
                effects,
            )
            rejected = controller.advance_apply(operation)
            self.assertEqual("recovery_required", rejected.state)
            self.assertEqual("authorization_expired", rejected.recovery_reason)
            self.assertEqual([], effects.calls)

    def test_exhaustion_remains_terminal_after_approval_expiry(self) -> None:
        clock = [1_000]
        with (
            mock.patch.object(
                human_authority_module,
                "_director_clock_ms",
                side_effect=lambda: clock[0],
            ),
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            inspector = _Inspector()
            effects = _Effects(inspector)
            bootstrap = OllamaV2Controller(
                controller_store,
                inspector,
                _BootstrapAuthorization(),
                effects,
            )
            plan = build_controller_plan(
                inspector.snapshot,
                *_manifests(),
                operation_id="op-exhausted-expired",
            )
            effects.plan = plan
            operation = bootstrap.create_operation(
                plan,
                operation_id=plan.operation_id,
                idempotency_key="create-exhausted-expired",
            )
            for _effect in plan.effects[:8]:
                operation = bootstrap.advance_apply(operation)
            self.assertEqual(8, operation.apply_cursor)
            review = control.build_ollama_v2_authorization_review(operation, plan, phase="apply")
            prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=2_000,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            controller = OllamaV2Controller(controller_store, inspector, port, effects)
            terminal = controller.advance_apply(operation)
            self.assertEqual("prepared_unverified", terminal.state)
            clock[0] = 3_000
            self.assertEqual(
                "exhausted",
                control.inspect_ollama_v2_authorization(review)["status"],
            )

    def test_live_controller_claim_rejects_wrong_request_fields(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-head-lineage", observed_generation=0),
                *_manifests(),
                operation_id="op-head-lineage",
            )
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-head-lineage",
            )
            review = control.build_ollama_v2_authorization_review(operation, plan, phase="apply")
            prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            _attach_studio_authorization_port(controller_store, port, plan)
            first = AuthorizationRequest.create(
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
            _claim_controller_authorization(controller_store, operation, first)
            hostile_fields = (
                {"expected_head_hash": "a" * 64},
                {"expected_generation": operation.generation + 1},
                {"expected_sequence": operation.sequence + 1},
                {"effect_id": plan.effects[1].effect_id},
            )
            for changed in hostile_fields:
                with self.subTest(changed=changed):
                    request_fields = {
                        "operation_id": first.operation_id,
                        "plan_hash": first.plan_hash,
                        "effect_id": first.effect_id,
                        "phase": first.phase,
                        "attempt": first.attempt,
                        "expected_generation": first.expected_generation,
                        "expected_sequence": first.expected_sequence,
                        "expected_head_hash": first.expected_head_hash,
                        "ownership_token": first.ownership_token,
                    }
                    request_fields.update(changed)
                    wrong = AuthorizationRequest.create(**request_fields)
                    with self.assertRaisesRegex(StudioError, "controller claim"):
                        port.consume(wrong)
                    with self.assertRaisesRegex(StudioError, "controller claim"):
                        port.resolve(wrong)
                    self.assertEqual(
                        0,
                        studio.connection.execute(
                            "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                        ).fetchone()[0],
                    )
            consumed = port.consume(first)
            self.assertEqual(consumed, port.resolve(first))

    def test_next_slot_requires_the_exact_durable_controller_claim(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            inspector = _Inspector()
            effects = _Effects(inspector)
            bootstrap = OllamaV2Controller(
                controller_store,
                inspector,
                _BootstrapAuthorization(),
                effects,
            )
            plan = build_controller_plan(
                inspector.snapshot,
                *_manifests(),
                operation_id="op-exact-controller-claim",
            )
            effects.plan = plan
            operation = bootstrap.create_operation(
                plan,
                operation_id=plan.operation_id,
                idempotency_key="create-exact-controller-claim",
            )
            review = control.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(
                review,
                expected_generation=0,
            )
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            controller = OllamaV2Controller(controller_store, inspector, port, effects)

            successor = controller.advance_apply(operation)
            self.assertEqual("apply_pending", successor.state)
            self.assertEqual(1, successor.apply_cursor)
            self.assertEqual(1, len(effects.calls))
            self.assertEqual(
                1,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions "
                    "WHERE mandate_id=?",
                    (review["mandate_id"],),
                ).fetchone()[0],
            )
            event_count = studio.connection.execute(
                "SELECT count(*) FROM studio_ollama_v2_authorization_events"
            ).fetchone()[0]

            forged = AuthorizationRequest.create(
                operation_id=successor.operation_id,
                plan_hash=successor.plan_hash,
                effect_id=plan.effects[1].effect_id,
                phase="apply",
                attempt=successor.next_attempt,
                expected_generation=successor.generation,
                expected_sequence=successor.sequence,
                expected_head_hash="f" * 64,
                ownership_token=successor.ownership_token,
            )
            with self.assertRaisesRegex(StudioError, "controller claim"):
                port.consume(forged)
            self.assertEqual(
                1,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0],
            )
            self.assertEqual(
                event_count,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                ).fetchone()[0],
            )

            concurrent_outcome: list[object] = []

            def preconsume_without_claim() -> None:
                try:
                    concurrent_outcome.append(port.consume(forged))
                except Exception as exc:
                    concurrent_outcome.append(exc)

            caller = threading.Thread(target=preconsume_without_claim)
            caller.start()
            caller.join(timeout=5)
            self.assertFalse(caller.is_alive())
            self.assertEqual(1, len(concurrent_outcome))
            self.assertIsInstance(concurrent_outcome[0], StudioError)
            self.assertEqual(
                1,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0],
            )
            self.assertEqual(
                event_count,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                ).fetchone()[0],
            )

            legitimate = controller.advance_apply(successor)
            self.assertEqual("apply_pending", legitimate.state)
            self.assertEqual(2, legitimate.apply_cursor)
            self.assertEqual(2, len(effects.calls))
            self.assertEqual(
                2,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0],
            )

    def test_controller_store_and_port_identity_are_exact(self) -> None:
        class StoreSubclass(OllamaV2ControllerStore):
            pass

        class EqualStore(OllamaV2ControllerStore):
            def __eq__(self, _other: object) -> bool:
                return True

        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-store-identity", observed_generation=0),
                *_manifests(),
                operation_id="op-store-identity",
            )
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-store-identity",
            )
            review = control.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(
                review,
                expected_generation=0,
            )
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            bind_arguments = {
                "expected_generation": 1,
                "expected_decision_hash": approved["decision"]["content_hash"],
            }
            copied_before_binding = copy.copy(controller_store)
            with self.assertRaisesRegex(StudioError, "identity is ambiguous"):
                control.bind_ollama_v2_authorization(
                    review,
                    controller_store=copied_before_binding,
                    operation_id=operation.operation_id,
                    **bind_arguments,
                )
            del copied_before_binding
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                **bind_arguments,
            )

            with self.assertRaises(AttributeError):
                controller_store.load_operation = lambda _operation_id: operation

            copied_store = copy.copy(controller_store)
            with self.assertRaisesRegex(StudioError, "identity is ambiguous"):
                control.bind_ollama_v2_authorization(
                    review,
                    controller_store=copied_store,
                    operation_id=operation.operation_id,
                    **bind_arguments,
                )
            del copied_store
            for hostile_store in (object.__new__(StoreSubclass), object.__new__(EqualStore)):
                with self.subTest(store_type=type(hostile_store).__name__):
                    with self.assertRaisesRegex(StudioError, "binding is invalid"):
                        control.bind_ollama_v2_authorization(
                            review,
                            controller_store=hostile_store,
                            operation_id=operation.operation_id,
                            **bind_arguments,
                        )
            with self.assertRaisesRegex(StudioError, "binding is invalid"):
                control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id="op-wrong-store-identity",
                    **bind_arguments,
                )

            request = _request_for_effect(operation, plan.effects[0])
            _claim_controller_authorization(controller_store, operation, request)
            with self.assertRaisesRegex(ApprovalError, "approval_authority_invalid"):
                copy.copy(port)
            with self.assertRaisesRegex(
                ControllerConstructionError,
                "controller_authorization_attachment_invalid",
            ):
                _attach_studio_authorization_port(controller_store, port, plan)
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                **bind_arguments,
            )
            _attach_studio_authorization_port(controller_store, port, plan)
            self.assertEqual(
                0,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0],
            )
            consumption = port.consume(request)
            self.assertEqual(consumption, port.resolve(request))

    def test_controller_store_custody_failures_make_zero_studio_mutation(self) -> None:
        cases = ("closed", "corrupt", "poisoned", "path_replaced", "class_replaced")
        for case in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as directory,
                StudioStore(Path(directory) / "studio") as studio,
            ):
                control = StudioDirectorControl(studio)
                control.enroll(passphrase=PASSPHRASE)
                plan = build_controller_plan(
                    make_empty_host_snapshot(
                        f"snap-store-custody-{case}",
                        observed_generation=0,
                    ),
                    *_manifests(),
                    operation_id=f"op-store-custody-{case}",
                )
                controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
                operation = _persist_controller_operation(
                    controller_store,
                    plan,
                    idempotency_key=f"create-store-custody-{case}",
                )
                review = control.build_ollama_v2_authorization_review(
                    operation,
                    plan,
                    phase="apply",
                )
                prepared = control.prepare_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                )
                approved = control.approve_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                    expected_review_hash=prepared["review"]["content_hash"],
                    expires_at_ms=9_007_199_254_740_991,
                )
                port = control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
                _attach_studio_authorization_port(controller_store, port, plan)
                request = _request_for_effect(operation, plan.effects[0])
                _claim_controller_authorization(controller_store, operation, request)
                event_count = studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                ).fetchone()[0]
                original_path = controller_store._path

                if case == "closed":
                    controller_store.close()
                elif case == "corrupt":
                    controller_store._connection.execute(
                        "UPDATE controller_operations SET head_hash=? WHERE operation_id=?",
                        ("0" * 64, operation.operation_id),
                    )
                    controller_store._connection.commit()
                elif case == "poisoned":
                    controller_store._poisoned_operations.add(operation.operation_id)
                elif case == "path_replaced":
                    controller_store._path = Path(str(original_path))

                if case == "class_replaced":
                    with mock.patch.object(
                        OllamaV2ControllerStore,
                        "load_operation",
                        side_effect=AssertionError("late controller-store replacement"),
                    ):
                        with self.assertRaisesRegex(StudioError, "unavailable"):
                            port.consume(request)
                else:
                    with self.assertRaisesRegex(StudioError, "unavailable"):
                        port.consume(request)
                with self.assertRaisesRegex(StudioError, "unavailable"):
                    port.consume(request)
                self.assertEqual(
                    0,
                    studio.connection.execute(
                        "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    event_count,
                    studio.connection.execute(
                        "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                    ).fetchone()[0],
                )
                if case == "path_replaced":
                    controller_store._path = original_path
                controller_store.close()

    def test_dispatching_rebind_observes_precondition_without_redispatch_and_burns_mandate(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-consumed-lineage", observed_generation=0),
                *_manifests(),
                operation_id="op-consumed-lineage",
            )
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-consumed-lineage",
            )
            review = control.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(
                review,
                expected_generation=0,
            )
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            _attach_studio_authorization_port(controller_store, port, plan)
            request = _request_for_effect(operation, plan.effects[0])
            claimed = _claim_controller_authorization(
                controller_store,
                operation,
                request,
            )
            consumption = port.consume(request)
            consumed = controller_store.record_authorization_consumed(
                claimed,
                request,
                consumption,
            ).snapshot
            self.assertEqual(consumption, port.resolve(request))
            self.assertEqual(consumption, port.consume(request))
            dispatching = controller_store.record_dispatching(
                consumed,
                request,
                consumption,
                plan.initial_snapshot,
            ).snapshot
            self.assertEqual("apply_dispatching", dispatching.state)
            rebound = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            inspector = _Inspector()
            effects = _Effects(inspector)
            effects.plan = plan
            restarted = OllamaV2Controller(
                controller_store,
                inspector,
                rebound,
                effects,
            )
            retriable = restarted.advance_apply(dispatching)
            self.assertEqual("apply_pending", retriable.state)
            self.assertEqual(0, retriable.apply_cursor)
            self.assertEqual([], effects.calls)
            with self.assertRaisesRegex(StudioError, "operation does not match mandate"):
                control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
            fresh_review = control.build_ollama_v2_authorization_review(
                retriable,
                plan,
                phase="apply",
            )
            self.assertNotEqual(review["mandate_id"], fresh_review["mandate_id"])
            fresh_prepared = control.prepare_ollama_v2_authorization(
                fresh_review,
                expected_generation=0,
            )
            fresh_approved = control.approve_ollama_v2_authorization(
                fresh_review,
                expected_generation=0,
                expected_review_hash=fresh_prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            fresh_port = control.bind_ollama_v2_authorization(
                fresh_review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=fresh_approved["decision"]["content_hash"],
            )
            fresh_controller = OllamaV2Controller(
                controller_store,
                inspector,
                fresh_port,
                effects,
            )
            retried = fresh_controller.advance_apply(retriable)
            self.assertEqual("apply_pending", retried.state)
            self.assertEqual(1, retried.apply_cursor)
            self.assertEqual([plan.effects[0].effect_id], effects.calls)
            with self.assertRaisesRegex(StudioError, "controller claim"):
                port.consume(request)
            with self.assertRaisesRegex(StudioError, "controller claim"):
                port.resolve(request)
            self.assertEqual(
                1,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions "
                    "WHERE mandate_id=?",
                    (review["mandate_id"],),
                ).fetchone()[0],
            )
            self.assertEqual(
                1,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions "
                    "WHERE mandate_id=?",
                    (fresh_review["mandate_id"],),
                ).fetchone()[0],
            )

    def test_exact_consumption_rebinds_after_claimed_or_consumed_restart(self) -> None:
        for controller_consumed in (False, True):
            with (
                self.subTest(controller_consumed=controller_consumed),
                tempfile.TemporaryDirectory() as directory,
            ):
                suffix = "consumed" if controller_consumed else "claimed"
                studio_path = Path(directory) / "studio"
                controller_path = Path(directory) / "controller.sqlite3"
                studio = StudioStore(studio_path)
                control = StudioDirectorControl(studio)
                control.enroll(passphrase=PASSPHRASE)
                controller_store = OllamaV2ControllerStore(controller_path)
                plan = build_controller_plan(
                    make_empty_host_snapshot(
                        f"snap-rebind-{suffix}",
                        observed_generation=0,
                    ),
                    *_manifests(),
                    operation_id=f"op-rebind-{suffix}",
                )
                operation = _persist_controller_operation(
                    controller_store,
                    plan,
                    idempotency_key=f"create-rebind-{suffix}",
                )
                review = control.build_ollama_v2_authorization_review(
                    operation,
                    plan,
                    phase="apply",
                )
                prepared = control.prepare_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                )
                approved = control.approve_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                    expected_review_hash=prepared["review"]["content_hash"],
                    expires_at_ms=9_007_199_254_740_991,
                )
                port = control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
                _attach_studio_authorization_port(controller_store, port, plan)
                request = _request_for_effect(operation, plan.effects[0])
                claimed = _claim_controller_authorization(
                    controller_store,
                    operation,
                    request,
                )
                consumption = port.consume(request)
                restart_snapshot = claimed
                if controller_consumed:
                    restart_snapshot = controller_store.record_authorization_consumed(
                        claimed,
                        request,
                        consumption,
                    ).snapshot

                self.assertEqual(consumption, port.resolve(request))
                self.assertEqual(
                    1,
                    control.inspect_ollama_v2_authorization(review)["consumed_slots"],
                )
                control.close()
                controller_store.close()
                studio.close()

                with (
                    StudioStore(studio_path) as reopened_studio,
                    OllamaV2ControllerStore(controller_path) as reopened_controller_store,
                ):
                    reopened = StudioDirectorControl(reopened_studio)
                    reopened.unlock(passphrase=PASSPHRASE)
                    self.assertEqual(
                        restart_snapshot,
                        reopened_controller_store.load_operation(operation.operation_id),
                    )
                    rebound = reopened.bind_ollama_v2_authorization(
                        review,
                        controller_store=reopened_controller_store,
                        operation_id=operation.operation_id,
                        expected_generation=1,
                        expected_decision_hash=approved["decision"]["content_hash"],
                    )
                    inspector = _Inspector()
                    inspector.snapshot = HostSnapshot.from_document(
                        plan.initial_snapshot.to_document()
                    )
                    effects = _Effects(inspector)
                    effects.plan = plan
                    restarted = OllamaV2Controller(
                        reopened_controller_store,
                        inspector,
                        rebound,
                        effects,
                    )

                    self.assertEqual(consumption, rebound.resolve(request))
                    self.assertEqual([], effects.calls)
                    self.assertEqual(consumption, rebound.consume(request))
                    self.assertEqual(
                        1,
                        reopened.inspect_ollama_v2_authorization(review)["consumed_slots"],
                    )
                    advanced = restarted.advance_apply(restart_snapshot)
                    self.assertEqual("apply_pending", advanced.state)
                    self.assertEqual([plan.effects[0].effect_id], effects.calls)
                    self.assertEqual(
                        consumption,
                        reopened_controller_store.load_authorization_consumption(
                            request.authorization_id
                        ),
                    )
                    self.assertEqual(
                        1,
                        reopened.inspect_ollama_v2_authorization(review)["consumed_slots"],
                    )
                    with self.assertRaises(ControllerStateError):
                        restarted.advance_apply(restart_snapshot)
                    self.assertEqual([plan.effects[0].effect_id], effects.calls)
                    successor_port = reopened.bind_ollama_v2_authorization(
                        review,
                        controller_store=reopened_controller_store,
                        operation_id=operation.operation_id,
                        expected_generation=1,
                        expected_decision_hash=approved["decision"]["content_hash"],
                    )
                    successor_controller = OllamaV2Controller(
                        reopened_controller_store,
                        inspector,
                        successor_port,
                        effects,
                    )
                    successor = successor_controller.advance_apply(advanced)
                    self.assertEqual("apply_pending", successor.state)
                    self.assertEqual(2, successor.apply_cursor)
                    self.assertEqual(
                        [plan.effects[0].effect_id, plan.effects[1].effect_id],
                        effects.calls,
                    )
                    with self.assertRaisesRegex(StudioError, "controller claim"):
                        rebound.resolve(request)

    def test_reopen_rebinds_only_the_exact_unconsumed_controller_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            studio_path = Path(directory) / "studio"
            controller_path = Path(directory) / "controller.sqlite3"
            studio = StudioStore(studio_path)
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            controller_store = OllamaV2ControllerStore(controller_path)
            plan = build_controller_plan(
                make_empty_host_snapshot(
                    "snap-rebind-unconsumed",
                    observed_generation=0,
                ),
                *_manifests(),
                operation_id="op-rebind-unconsumed",
            )
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-rebind-unconsumed",
            )
            review = control.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(
                review,
                expected_generation=0,
            )
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            inspector = _Inspector()
            effects = _Effects(inspector)
            effects.plan = plan
            OllamaV2Controller(controller_store, inspector, port, effects)
            request = _request_for_effect(operation, plan.effects[0])
            claimed = _claim_controller_authorization(
                controller_store,
                operation,
                request,
            )
            self.assertEqual("apply_authorization_claimed", claimed.state)
            self.assertEqual([], effects.calls)
            control.close()
            controller_store.close()
            studio.close()

            with (
                StudioStore(studio_path) as reopened_studio,
                OllamaV2ControllerStore(controller_path) as reopened_controller_store,
            ):
                reopened = StudioDirectorControl(reopened_studio)
                reopened.unlock(passphrase=PASSPHRASE)
                rebound = reopened.bind_ollama_v2_authorization(
                    review,
                    controller_store=reopened_controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
                _attach_studio_authorization_port(reopened_controller_store, rebound, plan)
                self.assertIsNone(rebound.resolve(request))
                consumption = rebound.consume(request)
                self.assertIsInstance(consumption, AuthorizationConsumption)
                self.assertEqual(consumption, rebound.consume(request))
                self.assertEqual(
                    1,
                    reopened_studio.connection.execute(
                        "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                    ).fetchone()[0],
                )
                self.assertEqual([], effects.calls)

    def test_commit_then_lost_consume_reply_rebinds_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            studio_path = Path(directory) / "studio"
            controller_path = Path(directory) / "controller.sqlite3"
            studio = StudioStore(studio_path)
            initial = StudioDirectorControl(studio)
            initial.enroll(passphrase=PASSPHRASE)
            initial.lock()
            raw = studio._authenticated_human_decision_connection_instance
            self.assertIsNotNone(raw)
            studio._authenticated_human_decision_connection_instance = (
                _NthCommitFaultConnection(raw, fail_at=6, effect=True)
            )
            control = StudioDirectorControl(studio)
            control.unlock(passphrase=PASSPHRASE)
            controller_store = OllamaV2ControllerStore(controller_path)
            plan = build_controller_plan(
                make_empty_host_snapshot(
                    "snap-rebind-lost-reply",
                    observed_generation=0,
                ),
                *_manifests(),
                operation_id="op-rebind-lost-reply",
            )
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-rebind-lost-reply",
            )
            review = control.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(
                review,
                expected_generation=0,
            )
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            inspector = _Inspector()
            effects = _Effects(inspector)
            effects.plan = plan
            OllamaV2Controller(controller_store, inspector, port, effects)
            request = _request_for_effect(operation, plan.effects[0])
            claimed = _claim_controller_authorization(
                controller_store,
                operation,
                request,
            )
            durable_consumption = port.consume(request)
            self.assertEqual(durable_consumption, port.resolve(request))
            self.assertIsNotNone(durable_consumption)
            self.assertTrue(durable_consumption.matches(request))
            self.assertEqual([], effects.calls)
            self.assertEqual(
                1,
                control.inspect_ollama_v2_authorization(review)["consumed_slots"],
            )
            control.close()
            controller_store.close()
            studio.close()

            with (
                StudioStore(studio_path) as reopened_studio,
                OllamaV2ControllerStore(controller_path) as reopened_controller_store,
            ):
                reopened = StudioDirectorControl(reopened_studio)
                reopened.unlock(passphrase=PASSPHRASE)
                rebound = reopened.bind_ollama_v2_authorization(
                    review,
                    controller_store=reopened_controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
                restarted_inspector = _Inspector()
                restarted_inspector.snapshot = HostSnapshot.from_document(
                    plan.initial_snapshot.to_document()
                )
                restarted_effects = _Effects(restarted_inspector)
                restarted_effects.plan = plan
                restarted = OllamaV2Controller(
                    reopened_controller_store,
                    restarted_inspector,
                    rebound,
                    restarted_effects,
                )
                self.assertEqual(durable_consumption, rebound.resolve(request))
                advanced = restarted.advance_apply(claimed)
                self.assertEqual("apply_pending", advanced.state)
                self.assertEqual([plan.effects[0].effect_id], restarted_effects.calls)
                self.assertEqual(
                    1,
                    reopened.inspect_ollama_v2_authorization(review)["consumed_slots"],
                )

    def test_rejection_commit_pre_and_post_converge_exactly(self) -> None:
        for reason in ("revoked", "expired"):
            for committed in (False, True):
                clock = [1_000]
                commit_stage = "post" if committed else "pre"
                with (
                    self.subTest(reason=reason, committed=committed),
                    mock.patch.object(
                        human_authority_module,
                        "_director_clock_ms",
                        side_effect=lambda: clock[0],
                    ),
                    tempfile.TemporaryDirectory() as directory,
                    StudioStore(Path(directory) / "studio") as studio,
                    OllamaV2ControllerStore(
                        Path(directory) / "controller.sqlite3"
                    ) as controller_store,
                ):
                    initial = StudioDirectorControl(studio)
                    initial.enroll(passphrase=PASSPHRASE)
                    initial.lock()
                    raw = studio._authenticated_human_decision_connection_instance
                    self.assertIsNotNone(raw)
                    proxy = _NthCommitFaultConnection(
                        raw,
                        fail_at=9_007_199_254_740_991,
                        effect=committed,
                    )
                    studio._authenticated_human_decision_connection_instance = proxy
                    control = StudioDirectorControl(studio)
                    control.unlock(passphrase=PASSPHRASE)
                    plan = build_controller_plan(
                        make_empty_host_snapshot(
                            f"snap-rejection-commit-{reason}-{commit_stage}",
                            observed_generation=0,
                        ),
                        *_manifests(),
                        operation_id=f"op-rejection-commit-{reason}-{commit_stage}",
                    )
                    operation = _persist_controller_operation(
                        controller_store,
                        plan,
                        idempotency_key=f"create-rejection-commit-{reason}-{commit_stage}",
                    )
                    review = control.build_ollama_v2_authorization_review(
                        operation,
                        plan,
                        phase="apply",
                    )
                    prepared = control.prepare_ollama_v2_authorization(
                        review,
                        expected_generation=0,
                    )
                    approved = control.approve_ollama_v2_authorization(
                        review,
                        expected_generation=0,
                        expected_review_hash=prepared["review"]["content_hash"],
                        expires_at_ms=(
                            2_000 if reason == "expired" else 9_007_199_254_740_991
                        ),
                    )
                    port = control.bind_ollama_v2_authorization(
                        review,
                        controller_store=controller_store,
                        operation_id=operation.operation_id,
                        expected_generation=1,
                        expected_decision_hash=approved["decision"]["content_hash"],
                    )
                    _attach_studio_authorization_port(controller_store, port, plan)
                    request = _request_for_effect(operation, plan.effects[0])
                    _claim_controller_authorization(controller_store, operation, request)
                    if reason == "revoked":
                        control.revoke_ollama_v2_authorization(
                            review,
                            expected_generation=1,
                            expected_decision_hash=approved["decision"]["content_hash"],
                            expected_consumed_slots=0,
                        )
                    else:
                        clock[0] = 3_000
                    proxy._fail_at = proxy._count + 1
                    if committed:
                        rejection = port.consume(request)
                        self.assertIsInstance(rejection, AuthorizationRejection)
                        self.assertEqual(reason, rejection.reason)
                        self.assertEqual(rejection, port.resolve(request))
                        expected_outcomes = 1
                    else:
                        with self.assertRaises(sqlite3.OperationalError):
                            port.consume(request)
                        self.assertIsNone(port.resolve(request))
                        expected_outcomes = 0
                    self.assertEqual(
                        expected_outcomes,
                        studio.connection.execute(
                            "SELECT count(*) FROM studio_ollama_v2_authorization_outcomes"
                        ).fetchone()[0],
                    )
                    snapshot = control.inspect_ollama_v2_authorization(review)
                    self.assertEqual(reason, snapshot["status"])
                    self.assertEqual(0, snapshot["consumed_slots"])

    def test_revoked_or_expired_partial_consumption_rebinds_resolve_only(self) -> None:
        for terminal_status, controller_consumed in (
            ("revoked", False),
            ("revoked", True),
            ("expired", False),
            ("expired", True),
        ):
            clock = [1_000]
            with (
                self.subTest(
                    terminal_status=terminal_status,
                    controller_consumed=controller_consumed,
                ),
                mock.patch.object(
                    human_authority_module,
                    "_director_clock_ms",
                    side_effect=lambda: clock[0],
                ),
                tempfile.TemporaryDirectory() as directory,
            ):
                studio_path = Path(directory) / "studio"
                controller_path = Path(directory) / "controller.sqlite3"
                studio = StudioStore(studio_path)
                control = StudioDirectorControl(studio)
                control.enroll(passphrase=PASSPHRASE)
                controller_store = OllamaV2ControllerStore(controller_path)
                plan = build_controller_plan(
                    make_empty_host_snapshot(
                        f"snap-rebind-{terminal_status}",
                        observed_generation=0,
                    ),
                    *_manifests(),
                    operation_id=f"op-rebind-{terminal_status}",
                )
                operation = _persist_controller_operation(
                    controller_store,
                    plan,
                    idempotency_key=f"create-rebind-{terminal_status}",
                )
                review = control.build_ollama_v2_authorization_review(
                    operation,
                    plan,
                    phase="apply",
                )
                prepared = control.prepare_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                )
                approved = control.approve_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                    expected_review_hash=prepared["review"]["content_hash"],
                    expires_at_ms=2_000,
                )
                port = control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
                inspector = _Inspector()
                inspector.snapshot = HostSnapshot.from_document(
                    plan.initial_snapshot.to_document()
                )
                effects = _Effects(inspector)
                effects.plan = plan
                OllamaV2Controller(controller_store, inspector, port, effects)
                request = _request_for_effect(operation, plan.effects[0])
                claimed = _claim_controller_authorization(
                    controller_store,
                    operation,
                    request,
                )
                consumption = port.consume(request)
                restart_snapshot = claimed
                if controller_consumed:
                    restart_snapshot = controller_store.record_authorization_consumed(
                        claimed,
                        request,
                        consumption,
                    ).snapshot
                if terminal_status == "revoked":
                    control.revoke_ollama_v2_authorization(
                        review,
                        expected_generation=1,
                        expected_decision_hash=approved["decision"]["content_hash"],
                        expected_consumed_slots=1,
                    )
                else:
                    clock[0] = 3_000
                self.assertEqual(
                    terminal_status,
                    control.inspect_ollama_v2_authorization(review)["status"],
                )
                self.assertEqual(consumption, port.resolve(request))
                self.assertEqual([], effects.calls)
                control.close()
                controller_store.close()
                studio.close()

                with (
                    StudioStore(studio_path) as reopened_studio,
                    OllamaV2ControllerStore(controller_path) as reopened_controller_store,
                ):
                    reopened = StudioDirectorControl(reopened_studio)
                    reopened.unlock(passphrase=PASSPHRASE)
                    rebound = reopened.bind_ollama_v2_authorization(
                        review,
                        controller_store=reopened_controller_store,
                        operation_id=operation.operation_id,
                        expected_generation=(2 if terminal_status == "revoked" else 1),
                        expected_decision_hash=approved["decision"]["content_hash"],
                    )
                    restarted = OllamaV2Controller(
                        reopened_controller_store,
                        inspector,
                        rebound,
                        effects,
                    )
                    self.assertEqual(consumption, rebound.resolve(request))
                    self.assertEqual(consumption, rebound.consume(request))
                    advanced = restarted.advance_apply(restart_snapshot)
                    self.assertEqual("apply_pending", advanced.state)
                    self.assertEqual([plan.effects[0].effect_id], effects.calls)
                    rejected = restarted.advance_apply(advanced)
                    self.assertEqual("recovery_required", rejected.state)
                    self.assertEqual(
                        f"authorization_{terminal_status}",
                        rejected.recovery_reason,
                    )
                    self.assertEqual([plan.effects[0].effect_id], effects.calls)
                    snapshot = reopened.inspect_ollama_v2_authorization(review)
                    self.assertEqual(terminal_status, snapshot["status"])
                    self.assertEqual(1, snapshot["consumed_slots"])

    def test_zero_consumption_terminal_reopen_denies_or_settles_without_host_effect(
        self,
    ) -> None:
        for terminal_status in ("denied", "revoked", "expired"):
            clock = [1_000]
            with (
                self.subTest(terminal_status=terminal_status),
                mock.patch.object(
                    human_authority_module,
                    "_director_clock_ms",
                    side_effect=lambda: clock[0],
                ),
                tempfile.TemporaryDirectory() as directory,
            ):
                studio_path = Path(directory) / "studio"
                controller_path = Path(directory) / "controller.sqlite3"
                studio = StudioStore(studio_path)
                control = StudioDirectorControl(studio)
                control.enroll(passphrase=PASSPHRASE)
                controller_store = OllamaV2ControllerStore(controller_path)
                plan = build_controller_plan(
                    make_empty_host_snapshot(
                        f"snap-zero-{terminal_status}",
                        observed_generation=0,
                    ),
                    *_manifests(),
                    operation_id=f"op-zero-{terminal_status}",
                )
                operation = _persist_controller_operation(
                    controller_store,
                    plan,
                    idempotency_key=f"create-zero-{terminal_status}",
                )
                review = control.build_ollama_v2_authorization_review(
                    operation,
                    plan,
                    phase="apply",
                )
                prepared = control.prepare_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                )
                if terminal_status == "denied":
                    terminal = control.deny_ollama_v2_authorization(
                        review,
                        expected_generation=0,
                        expected_review_hash=prepared["review"]["content_hash"],
                    )
                    expected_generation = 1
                else:
                    approved = control.approve_ollama_v2_authorization(
                        review,
                        expected_generation=0,
                        expected_review_hash=prepared["review"]["content_hash"],
                        expires_at_ms=2_000,
                    )
                    terminal = approved
                    expected_generation = 1
                    if terminal_status == "revoked":
                        terminal = control.revoke_ollama_v2_authorization(
                            review,
                            expected_generation=1,
                            expected_decision_hash=approved["decision"]["content_hash"],
                            expected_consumed_slots=0,
                        )
                        expected_generation = 2
                    else:
                        clock[0] = 3_000
                self.assertEqual(
                    terminal_status,
                    control.inspect_ollama_v2_authorization(review)["status"],
                )
                control.close()
                controller_store.close()
                studio.close()

                with (
                    StudioStore(studio_path) as reopened_studio,
                    OllamaV2ControllerStore(controller_path) as reopened_controller_store,
                ):
                    reopened = StudioDirectorControl(reopened_studio)
                    reopened.unlock(passphrase=PASSPHRASE)
                    if terminal_status == "denied":
                        with self.assertRaisesRegex(StudioError, "not approved"):
                            reopened.bind_ollama_v2_authorization(
                                review,
                                controller_store=reopened_controller_store,
                                operation_id=operation.operation_id,
                                expected_generation=expected_generation,
                                expected_decision_hash=terminal["decision"]["content_hash"],
                            )
                    else:
                        port = reopened.bind_ollama_v2_authorization(
                            review,
                            controller_store=reopened_controller_store,
                            operation_id=operation.operation_id,
                            expected_generation=expected_generation,
                            expected_decision_hash=terminal["decision"]["content_hash"],
                        )
                        inspector = _Inspector()
                        effects = _Effects(inspector)
                        effects.plan = plan
                        controller = OllamaV2Controller(
                            reopened_controller_store,
                            inspector,
                            port,
                            effects,
                        )
                        rejected = controller.advance_apply(operation)
                        self.assertEqual("recovery_required", rejected.state)
                        self.assertEqual(
                            f"authorization_{terminal_status}",
                            rejected.recovery_reason,
                        )
                        self.assertEqual([], effects.calls)
                    self.assertEqual(
                        0,
                        reopened_studio.connection.execute(
                            "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                        ).fetchone()[0],
                    )
                    self.assertEqual(
                        0 if terminal_status == "denied" else 1,
                        reopened_studio.connection.execute(
                            "SELECT count(*) FROM studio_ollama_v2_authorization_outcomes"
                        ).fetchone()[0],
                    )

    def test_live_resolve_rejects_foreign_controller_consumption(self) -> None:
        for altered_field in ("authority_id", "decision_id", "authority_and_decision"):
            with (
                self.subTest(altered_field=altered_field),
                tempfile.TemporaryDirectory() as directory,
                StudioStore(Path(directory) / "studio") as studio,
                OllamaV2ControllerStore(
                    Path(directory) / "controller.sqlite3"
                ) as controller_store,
            ):
                control = StudioDirectorControl(studio)
                control.enroll(passphrase=PASSPHRASE)
                plan = build_controller_plan(
                    make_empty_host_snapshot(
                        f"snap-live-foreign-consumption-{altered_field}",
                        observed_generation=0,
                    ),
                    *_manifests(),
                    operation_id=f"op-live-foreign-consumption-{altered_field}",
                )
                operation = _persist_controller_operation(
                    controller_store,
                    plan,
                    idempotency_key=f"create-live-foreign-consumption-{altered_field}",
                )
                review = control.build_ollama_v2_authorization_review(
                    operation,
                    plan,
                    phase="apply",
                )
                prepared = control.prepare_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                )
                approved = control.approve_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                    expected_review_hash=prepared["review"]["content_hash"],
                    expires_at_ms=9_007_199_254_740_991,
                )
                port = control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
                inspector = _Inspector()
                effects = _Effects(inspector)
                effects.plan = plan
                OllamaV2Controller(controller_store, inspector, port, effects)
                request = _request_for_effect(operation, plan.effects[0])
                claimed = _claim_controller_authorization(
                    controller_store,
                    operation,
                    request,
                )
                studio_consumption = port.consume(request)
                controller_consumption = AuthorizationConsumption.create(
                    request,
                    authority_id=(
                        "foreign-live-authority"
                        if altered_field in {"authority_id", "authority_and_decision"}
                        else studio_consumption.authority_id
                    ),
                    decision_id=(
                        "foreign-live-decision"
                        if altered_field in {"decision_id", "authority_and_decision"}
                        else studio_consumption.decision_id
                    ),
                )
                controller_store.record_authorization_consumed(
                    claimed,
                    request,
                    controller_consumption,
                )
                self.assertNotEqual(studio_consumption, controller_consumption)
                event_count = studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                ).fetchone()[0]
                consumption_count = studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0]

                with self.assertRaisesRegex(StudioError, "controller outcome"):
                    port.resolve(request)
                self.assertEqual([], effects.calls)
                self.assertEqual(
                    event_count,
                    studio.connection.execute(
                        "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    consumption_count,
                    studio.connection.execute(
                        "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                    ).fetchone()[0],
                )
                self.assertFalse(studio.connection.in_transaction)
                self.assertFalse(controller_store._connection.in_transaction)

    def _assert_controller_advance_requires_exact_live_consumption(
        self,
        *,
        phase: str,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            for altered_field in ("exact", "authority_id", "decision_id"):
                with (
                    self.subTest(phase=phase, altered_field=altered_field),
                    OllamaV2ControllerStore(
                        Path(directory) / f"controller-{phase}-{altered_field}.sqlite3"
                    ) as controller_store,
                ):
                    inspector = _Inspector()
                    effects = _Effects(inspector)
                    plan = build_controller_plan(
                        inspector.snapshot,
                        *_manifests(),
                        operation_id=f"op-live-{phase}-{altered_field}",
                    )
                    effects.plan = plan
                    operation = _persist_controller_operation(
                        controller_store,
                        plan,
                        idempotency_key=f"create-live-{phase}-{altered_field}",
                    )
                    if phase == "rollback":
                        bootstrap = OllamaV2Controller(
                            controller_store,
                            inspector,
                            _BootstrapAuthorization(),
                            effects,
                        )
                        operation = bootstrap.advance_apply(operation)
                        self.assertEqual(1, operation.apply_cursor)
                        operation = bootstrap.prepare_rollback(operation)
                        rollback = controller_store.load_rollback_plan(
                            operation.operation_id
                        )
                        self.assertIsNotNone(rollback)
                        effect = rollback.effects[0]
                    else:
                        rollback = None
                        effect = plan.effects[0]

                    review = control.build_ollama_v2_authorization_review(
                        operation,
                        plan,
                        phase=phase,
                        rollback_plan=rollback,
                    )
                    prepared = control.prepare_ollama_v2_authorization(
                        review,
                        expected_generation=0,
                    )
                    approved = control.approve_ollama_v2_authorization(
                        review,
                        expected_generation=0,
                        expected_review_hash=prepared["review"]["content_hash"],
                        expires_at_ms=9_007_199_254_740_991,
                    )
                    port = control.bind_ollama_v2_authorization(
                        review,
                        controller_store=controller_store,
                        operation_id=operation.operation_id,
                        expected_generation=1,
                        expected_decision_hash=approved["decision"]["content_hash"],
                    )
                    controller = OllamaV2Controller(
                        controller_store,
                        inspector,
                        port,
                        effects,
                    )
                    request = _request_for_effect(operation, effect, phase=phase)
                    claimed = _claim_controller_authorization(
                        controller_store,
                        operation,
                        request,
                    )
                    studio_consumption = port.consume(request)
                    controller_consumption = (
                        AuthorizationConsumption.from_document(
                            studio_consumption.to_document()
                        )
                        if altered_field == "exact"
                        else AuthorizationConsumption.create(
                            request,
                            authority_id=(
                                "foreign-production-authority"
                                if altered_field == "authority_id"
                                else studio_consumption.authority_id
                            ),
                            decision_id=(
                                "foreign-production-decision"
                                if altered_field == "decision_id"
                                else studio_consumption.decision_id
                            ),
                        )
                    )
                    consumed = controller_store.record_authorization_consumed(
                        claimed,
                        request,
                        controller_consumption,
                    ).snapshot
                    if altered_field == "exact":
                        self.assertEqual(studio_consumption, controller_consumption)
                        self.assertIsNot(studio_consumption, controller_consumption)
                    else:
                        self.assertNotEqual(studio_consumption, controller_consumption)
                    controller_event_count = controller_store._connection.execute(
                        "SELECT count(*) FROM controller_events WHERE operation_id=?",
                        (operation.operation_id,),
                    ).fetchone()[0]
                    controller_attempt_count = controller_store._connection.execute(
                        "SELECT count(*) FROM controller_effect_attempts WHERE operation_id=?",
                        (operation.operation_id,),
                    ).fetchone()[0]
                    studio_event_count = studio.connection.execute(
                        "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                    ).fetchone()[0]
                    studio_consumption_count = studio.connection.execute(
                        "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                    ).fetchone()[0]
                    effect_calls = tuple(effects.calls)

                    advance = (
                        controller.advance_apply
                        if phase == "apply"
                        else controller.advance_rollback
                    )
                    if altered_field == "exact":
                        advanced = advance(consumed)
                        self.assertEqual(
                            "apply_pending" if phase == "apply" else "rolled_back_clean",
                            advanced.state,
                        )
                        self.assertEqual(
                            controller_event_count + 2,
                            controller_store._connection.execute(
                                "SELECT count(*) FROM controller_events "
                                "WHERE operation_id=?",
                                (operation.operation_id,),
                            ).fetchone()[0],
                        )
                        self.assertEqual(
                            controller_attempt_count + 1,
                            controller_store._connection.execute(
                                "SELECT count(*) FROM controller_effect_attempts "
                                "WHERE operation_id=?",
                                (operation.operation_id,),
                            ).fetchone()[0],
                        )
                        self.assertEqual(
                            (*effect_calls, effect.effect_id),
                            tuple(effects.calls),
                        )
                    else:
                        with self.assertRaisesRegex(
                            ControllerAuthorizationError,
                            "authorization_resolution_failed",
                        ):
                            advance(consumed)

                    if altered_field != "exact":
                        self.assertEqual(
                            consumed,
                            controller_store.load_operation(operation.operation_id),
                        )
                        self.assertEqual(
                            controller_event_count,
                            controller_store._connection.execute(
                                "SELECT count(*) FROM controller_events "
                                "WHERE operation_id=?",
                                (operation.operation_id,),
                            ).fetchone()[0],
                        )
                        self.assertEqual(
                            controller_attempt_count,
                            controller_store._connection.execute(
                                "SELECT count(*) FROM controller_effect_attempts "
                                "WHERE operation_id=?",
                                (operation.operation_id,),
                            ).fetchone()[0],
                        )
                        self.assertEqual(effect_calls, tuple(effects.calls))
                    self.assertEqual(
                        studio_event_count,
                        studio.connection.execute(
                            "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                        ).fetchone()[0],
                    )
                    self.assertEqual(
                        studio_consumption_count,
                        studio.connection.execute(
                            "SELECT count(*) FROM "
                            "studio_ollama_v2_authorization_consumptions"
                        ).fetchone()[0],
                    )
                    self.assertFalse(studio.connection.in_transaction)
                    self.assertFalse(controller_store._connection.in_transaction)

    def test_controller_apply_requires_exact_live_consumption_before_dispatch(
        self,
    ) -> None:
        self._assert_controller_advance_requires_exact_live_consumption(phase="apply")

    def test_controller_rollback_requires_exact_live_consumption_before_dispatch(
        self,
    ) -> None:
        self._assert_controller_advance_requires_exact_live_consumption(phase="rollback")

    def test_rebind_rejects_foreign_controller_consumption(self) -> None:
        for altered_field in ("authority_id", "decision_id"):
            with (
                self.subTest(altered_field=altered_field),
                tempfile.TemporaryDirectory() as directory,
            ):
                studio_path = Path(directory) / "studio"
                controller_path = Path(directory) / "controller.sqlite3"
                studio = StudioStore(studio_path)
                control = StudioDirectorControl(studio)
                control.enroll(passphrase=PASSPHRASE)
                controller_store = OllamaV2ControllerStore(controller_path)
                plan = build_controller_plan(
                    make_empty_host_snapshot(
                        f"snap-foreign-consumption-{altered_field}",
                        observed_generation=0,
                    ),
                    *_manifests(),
                    operation_id=f"op-foreign-consumption-{altered_field}",
                )
                operation = _persist_controller_operation(
                    controller_store,
                    plan,
                    idempotency_key=f"create-foreign-consumption-{altered_field}",
                )
                review = control.build_ollama_v2_authorization_review(
                    operation,
                    plan,
                    phase="apply",
                )
                prepared = control.prepare_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                )
                approved = control.approve_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                    expected_review_hash=prepared["review"]["content_hash"],
                    expires_at_ms=9_007_199_254_740_991,
                )
                port = control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
                inspector = _Inspector()
                effects = _Effects(inspector)
                effects.plan = plan
                OllamaV2Controller(controller_store, inspector, port, effects)
                request = _request_for_effect(operation, plan.effects[0])
                claimed = _claim_controller_authorization(
                    controller_store,
                    operation,
                    request,
                )
                studio_consumption = port.consume(request)
                controller_consumption = AuthorizationConsumption.create(
                    request,
                    authority_id=(
                        "foreign-controller-authority"
                        if altered_field == "authority_id"
                        else studio_consumption.authority_id
                    ),
                    decision_id=(
                        "foreign-controller-decision"
                        if altered_field == "decision_id"
                        else studio_consumption.decision_id
                    ),
                )
                consumed = controller_store.record_authorization_consumed(
                    claimed,
                    request,
                    controller_consumption,
                ).snapshot
                self.assertEqual("apply_authorization_consumed", consumed.state)
                self.assertNotEqual(studio_consumption, controller_consumption)
                event_count = studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                ).fetchone()[0]
                control.close()
                controller_store.close()
                studio.close()

                with (
                    StudioStore(studio_path) as reopened_studio,
                    OllamaV2ControllerStore(controller_path) as reopened_controller_store,
                ):
                    reopened = StudioDirectorControl(reopened_studio)
                    reopened.unlock(passphrase=PASSPHRASE)
                    with self.assertRaisesRegex(StudioError, "continuation"):
                        reopened.bind_ollama_v2_authorization(
                            review,
                            controller_store=reopened_controller_store,
                            operation_id=operation.operation_id,
                            expected_generation=1,
                            expected_decision_hash=approved["decision"]["content_hash"],
                        )
                    self.assertEqual([], effects.calls)
                    self.assertEqual(
                        1,
                        reopened.inspect_ollama_v2_authorization(review)["consumed_slots"],
                    )
                    self.assertEqual(
                        event_count,
                        reopened_studio.connection.execute(
                            "SELECT count(*) FROM studio_ollama_v2_authorization_events"
                        ).fetchone()[0],
                    )

    def test_port_reuse_with_another_controller_store_is_rejected(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            first_plan = build_controller_plan(
                make_empty_host_snapshot("snap-port-store-one", observed_generation=0),
                *_manifests(),
                operation_id="op-port-store-one",
            )
            first_store = OllamaV2ControllerStore(Path(directory) / "first.sqlite3")
            self.addCleanup(first_store.close)
            first_operation = _persist_controller_operation(
                first_store,
                first_plan,
                idempotency_key="create-port-store-one",
            )
            review = control.build_ollama_v2_authorization_review(
                first_operation,
                first_plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(
                review,
                expected_generation=0,
            )
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=first_store,
                operation_id=first_operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )

            second_store = OllamaV2ControllerStore(Path(directory) / "second.sqlite3")
            self.addCleanup(second_store.close)
            inspector = _Inspector()
            effects = _Effects(inspector)
            second_plan = build_controller_plan(
                inspector.snapshot,
                *_manifests(),
                operation_id="op-port-store-two",
            )
            effects.plan = second_plan
            bootstrap = OllamaV2Controller(
                second_store,
                inspector,
                _BootstrapAuthorization(),
                effects,
            )
            second_operation = bootstrap.create_operation(
                second_plan,
                operation_id=second_plan.operation_id,
                idempotency_key="create-port-store-two",
            )
            with self.assertRaisesRegex(
                ControllerConstructionError,
                "controller_authorization_store_mismatch",
            ):
                OllamaV2Controller(second_store, inspector, port, effects)
            self.assertEqual([], effects.calls)
            self.assertEqual(
                0,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0],
            )

    def test_controller_attachment_requires_the_exact_bound_store_object(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            controller_path = Path(directory) / "controller.sqlite3"
            first_store = OllamaV2ControllerStore(controller_path)
            self.addCleanup(first_store.close)
            inspector = _Inspector()
            effects = _Effects(inspector)
            bootstrap = OllamaV2Controller(
                first_store,
                inspector,
                _BootstrapAuthorization(),
                effects,
            )
            plan = build_controller_plan(
                inspector.snapshot,
                *_manifests(),
                operation_id="op-exact-controller-attachment",
            )
            effects.plan = plan
            operation = bootstrap.create_operation(
                plan,
                operation_id=plan.operation_id,
                idempotency_key="create-exact-controller-attachment",
            )
            review = control.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(
                review,
                expected_generation=0,
            )
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=first_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            second_store = OllamaV2ControllerStore(controller_path)
            self.addCleanup(second_store.close)

            with self.assertRaisesRegex(
                ControllerConstructionError,
                "controller_authorization_store_mismatch",
            ):
                OllamaV2Controller(second_store, inspector, port, effects)

            self.assertEqual([], effects.calls)
            self.assertEqual(
                0,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0],
            )

    def test_direct_port_calls_require_exact_controller_attachment(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-direct-attachment", observed_generation=0),
                *_manifests(),
                operation_id="op-direct-attachment",
            )
            controller_store = OllamaV2ControllerStore(
                Path(directory) / "controller.sqlite3"
            )
            self.addCleanup(controller_store.close)
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-direct-attachment",
            )
            review = control.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(
                review,
                expected_generation=0,
            )
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            request = _request_for_effect(operation, plan.effects[0])
            _claim_controller_authorization(controller_store, operation, request)

            with self.assertRaisesRegex(StudioError, "not attached"):
                port.consume(request)
            with self.assertRaisesRegex(StudioError, "not attached"):
                port.resolve(request)
            self.assertEqual(
                0,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0],
            )

            inspector = _Inspector()
            effects = _Effects(inspector)
            effects.plan = plan
            with self.assertRaisesRegex(
                ControllerConstructionError,
                "controller_authorization_attachment_invalid",
            ):
                OllamaV2Controller(controller_store, inspector, port, effects)
            rebound = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            OllamaV2Controller(controller_store, inspector, rebound, effects)
            self.assertTrue(rebound.consume(request).matches(request))

    def test_controller_read_rejection_preserves_caller_owned_transaction(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-caller-transaction", observed_generation=0),
                *_manifests(),
                operation_id="op-caller-transaction",
            )
            controller_store = OllamaV2ControllerStore(
                Path(directory) / "controller.sqlite3"
            )
            self.addCleanup(controller_store.close)
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-caller-transaction",
            )
            review = control.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(
                review,
                expected_generation=0,
            )
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            inspector = _Inspector()
            effects = _Effects(inspector)
            effects.plan = plan
            OllamaV2Controller(controller_store, inspector, port, effects)
            request = _request_for_effect(operation, plan.effects[0])
            _claim_controller_authorization(controller_store, operation, request)
            connection = controller_store._connection
            connection.execute("CREATE TEMP TABLE caller_sentinel (value TEXT NOT NULL)")
            connection.execute("BEGIN")
            connection.execute("INSERT INTO caller_sentinel VALUES ('uncommitted')")

            with self.assertRaisesRegex(StudioError, "unavailable"):
                port.consume(request)
            self.assertTrue(connection.in_transaction)
            self.assertEqual(
                ["uncommitted"],
                [row[0] for row in connection.execute("SELECT value FROM caller_sentinel")],
            )
            connection.rollback()
            self.assertTrue(port.consume(request).matches(request))

    def test_concurrent_consume_and_revoke_have_one_exact_cas_winner(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-consume-revoke", observed_generation=0),
                *_manifests(),
                operation_id="op-consume-revoke",
            )
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-consume-revoke",
            )
            review = control.build_ollama_v2_authorization_review(operation, plan, phase="apply")
            prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            _attach_studio_authorization_port(controller_store, port, plan)
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
            _claim_controller_authorization(controller_store, operation, request)
            barrier = threading.Barrier(2)
            outcomes: list[tuple[str, object]] = []
            outcomes_lock = threading.Lock()

            def run_revoke() -> None:
                barrier.wait()
                try:
                    result: object = control.revoke_ollama_v2_authorization(
                        review,
                        expected_generation=1,
                        expected_decision_hash=approved["decision"]["content_hash"],
                        expected_consumed_slots=0,
                    )
                except Exception as exc:
                    result = exc
                with outcomes_lock:
                    outcomes.append(("revoke", result))

            revoke_thread = threading.Thread(target=run_revoke)
            revoke_thread.start()
            barrier.wait()
            try:
                consume_result: object = port.consume(request)
            except Exception as exc:
                consume_result = exc
            with outcomes_lock:
                outcomes.append(("consume", consume_result))
            revoke_thread.join(timeout=5)
            self.assertFalse(revoke_thread.is_alive())

            successes = [
                (name, value) for name, value in outcomes if not isinstance(value, Exception)
            ]
            failures = [(name, value) for name, value in outcomes if isinstance(value, Exception)]
            consumption_count = studio.connection.execute(
                "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
            ).fetchone()[0]
            snapshot = control.inspect_ollama_v2_authorization(review)
            if len(successes) == 2:
                self.assertEqual([], failures)
                self.assertEqual({"consume", "revoke"}, {name for name, _ in successes})
                consume_outcome = next(value for name, value in successes if name == "consume")
                self.assertIsInstance(consume_outcome, AuthorizationRejection)
                self.assertEqual("revoked", consume_outcome.reason)
                self.assertEqual(0, consumption_count)
                self.assertEqual("revoked", snapshot["status"])
            else:
                self.assertEqual(1, len(successes))
                self.assertEqual(1, len(failures))
                self.assertIsInstance(failures[0][1], StudioError)
                self.assertEqual("consume", successes[0][0])
                self.assertEqual(1, consumption_count)
                self.assertEqual("consumable", snapshot["status"])

    def test_lock_waits_for_inflight_consume_on_the_exact_authority_lock(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            initial = StudioDirectorControl(studio)
            initial.enroll(passphrase=PASSPHRASE)
            initial.lock()
            raw = studio._authenticated_human_decision_connection_instance
            self.assertIsNotNone(raw)
            proxy = _BlockingImmediateConnection(raw)
            studio._authenticated_human_decision_connection_instance = proxy
            control = StudioDirectorControl(studio)
            control.unlock(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-lock-consume", observed_generation=0),
                *_manifests(),
                operation_id="op-lock-consume",
            )
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-lock-consume",
            )
            review = control.build_ollama_v2_authorization_review(operation, plan, phase="apply")
            prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            _attach_studio_authorization_port(controller_store, port, plan)
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
            _claim_controller_authorization(controller_store, operation, request)
            proxy.block = True
            lock_result: list[object] = []
            lock_waiting: list[bool] = []
            lock_attempted = threading.Event()

            def lock() -> None:
                if not proxy.entered.wait(timeout=5):
                    lock_result.append(RuntimeError("consume did not enter transaction"))
                    return
                lock_attempted.set()
                try:
                    lock_result.append(control.lock())
                except Exception as exc:
                    lock_result.append(exc)

            lock_thread = threading.Thread(target=lock)
            lock_thread.start()

            def release() -> None:
                if not lock_attempted.wait(timeout=5):
                    return
                time.sleep(0.1)
                lock_waiting.append(lock_thread.is_alive())
                proxy.release.set()

            release_thread = threading.Thread(target=release)
            release_thread.start()
            consume_result = port.consume(request)
            lock_thread.join(timeout=5)
            release_thread.join(timeout=5)
            self.assertFalse(lock_thread.is_alive())
            self.assertFalse(release_thread.is_alive())
            self.assertEqual([True], lock_waiting)
            self.assertIsInstance(consume_result, AuthorizationConsumption)
            self.assertEqual("locked", lock_result[0]["state"])
            with self.assertRaisesRegex(StudioError, "unavailable"):
                port.resolve(request)

    def test_independent_connections_allow_only_one_exact_slot_consumption(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as primary,
            OllamaV2ControllerStore(
                Path(directory) / "controller.sqlite3"
            ) as controller_store,
        ):
            data_dir = Path(directory) / "studio"
            controller_path = Path(directory) / "controller.sqlite3"
            first = StudioDirectorControl(primary)
            first.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-multi-consume", observed_generation=0),
                *_manifests(),
                operation_id="op-multi-consume",
            )
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-multi-consume",
            )
            review = first.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = first.prepare_ollama_v2_authorization(review, expected_generation=0)
            approved = first.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            primary_port = first.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            _attach_studio_authorization_port(controller_store, primary_port, plan)
            request = _request_for_effect(operation, plan.effects[0])
            ready = threading.Event()
            barrier = threading.Barrier(2)
            outcomes: list[object] = []
            outcomes_lock = threading.Lock()

            def consume_secondary() -> None:
                try:
                    with (
                        StudioStore(data_dir, mode="secondary") as secondary,
                        OllamaV2ControllerStore(controller_path) as secondary_controller,
                    ):
                        second = StudioDirectorControl(secondary)
                        second.unlock(passphrase=PASSPHRASE)
                        secondary_port = second.bind_ollama_v2_authorization(
                            review,
                            controller_store=secondary_controller,
                            operation_id=operation.operation_id,
                            expected_generation=1,
                            expected_decision_hash=approved["decision"]["content_hash"],
                        )
                        _attach_studio_authorization_port(
                            secondary_controller,
                            secondary_port,
                            plan,
                        )
                        ready.set()
                        barrier.wait(timeout=5)
                        outcome: object = secondary_port.consume(request)
                except Exception as exc:
                    outcome = exc
                    ready.set()
                with outcomes_lock:
                    outcomes.append(outcome)

            thread = threading.Thread(target=consume_secondary)
            thread.start()
            self.assertTrue(ready.wait(timeout=5))
            with outcomes_lock:
                setup_outcomes = list(outcomes)
            if setup_outcomes:
                thread.join(timeout=5)
                self.fail(f"secondary setup failed: {setup_outcomes[0]!r}")
            _claim_controller_authorization(controller_store, operation, request)
            barrier.wait(timeout=5)
            try:
                primary_outcome: object = primary_port.consume(request)
            except Exception as exc:
                primary_outcome = exc
            with outcomes_lock:
                outcomes.append(primary_outcome)
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

            successes = [
                value for value in outcomes if isinstance(value, AuthorizationConsumption)
            ]
            failures = [value for value in outcomes if isinstance(value, Exception)]
            self.assertEqual(2, len(successes))
            self.assertEqual([], failures)
            self.assertEqual(successes[0], successes[1])
            self.assertEqual(successes[0], primary_port.resolve(request))
            self.assertEqual(
                1,
                primary.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0],
            )

    def test_independent_connections_converge_consume_with_revoke_or_expiry(self) -> None:
        for terminal in ("revoke", "expiry"):
            terminal_clock_active = threading.Event()

            def clock_ms() -> int:
                if (
                    terminal == "expiry"
                    and terminal_clock_active.is_set()
                    and threading.current_thread().name == "terminal-racer"
                ):
                    return 3_000
                return 1_000

            with (
                self.subTest(terminal=terminal),
                mock.patch.object(
                    human_authority_module,
                    "_director_clock_ms",
                    side_effect=clock_ms,
                ),
                tempfile.TemporaryDirectory() as directory,
            ):
                data_dir = Path(directory) / "studio"
                controller_path = Path(directory) / "controller.sqlite3"
                primary = StudioStore(data_dir)
                control = StudioDirectorControl(primary)
                control.enroll(passphrase=PASSPHRASE)
                controller_store = OllamaV2ControllerStore(controller_path)
                plan = build_controller_plan(
                    make_empty_host_snapshot(
                        f"snap-independent-{terminal}",
                        observed_generation=0,
                    ),
                    *_manifests(),
                    operation_id=f"op-independent-{terminal}",
                )
                operation = _persist_controller_operation(
                    controller_store,
                    plan,
                    idempotency_key=f"create-independent-{terminal}",
                )
                review = control.build_ollama_v2_authorization_review(
                    operation,
                    plan,
                    phase="apply",
                )
                prepared = control.prepare_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                )
                approved = control.approve_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                    expected_review_hash=prepared["review"]["content_hash"],
                    expires_at_ms=(2_000 if terminal == "expiry" else 9_007_199_254_740_991),
                )
                primary_port = control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
                _attach_studio_authorization_port(controller_store, primary_port, plan)
                request = _request_for_effect(operation, plan.effects[0])
                ready = threading.Event()
                barrier = threading.Barrier(2)
                results: list[tuple[str, object]] = []
                results_lock = threading.Lock()

                def race_terminal() -> None:
                    try:
                        with StudioStore(data_dir, mode="secondary") as secondary:
                            secondary_control = StudioDirectorControl(secondary)
                            secondary_control.unlock(passphrase=PASSPHRASE)
                            if terminal == "expiry":
                                with OllamaV2ControllerStore(
                                    controller_path
                                ) as secondary_controller:
                                    secondary_port = secondary_control.bind_ollama_v2_authorization(
                                        review,
                                        controller_store=secondary_controller,
                                        operation_id=operation.operation_id,
                                        expected_generation=1,
                                        expected_decision_hash=approved["decision"]["content_hash"],
                                    )
                                    _attach_studio_authorization_port(
                                        secondary_controller,
                                        secondary_port,
                                        plan,
                                    )
                                    ready.set()
                                    barrier.wait(timeout=5)
                                    value: object = secondary_port.consume(request)
                            else:
                                ready.set()
                                barrier.wait(timeout=5)
                                value = secondary_control.revoke_ollama_v2_authorization(
                                    review,
                                    expected_generation=1,
                                    expected_decision_hash=approved["decision"]["content_hash"],
                                    expected_consumed_slots=0,
                                )
                    except Exception as exc:
                        value = exc
                        ready.set()
                    with results_lock:
                        results.append(("terminal", value))

                thread = threading.Thread(target=race_terminal, name="terminal-racer")
                thread.start()
                self.assertTrue(ready.wait(timeout=5))
                with results_lock:
                    setup_results = list(results)
                if setup_results:
                    thread.join(timeout=5)
                    self.fail(f"secondary setup failed: {setup_results[0][1]!r}")
                _claim_controller_authorization(controller_store, operation, request)
                terminal_clock_active.set()
                barrier.wait(timeout=5)
                try:
                    primary_value: object = primary_port.consume(request)
                except Exception as exc:
                    primary_value = exc
                with results_lock:
                    results.append(("consume", primary_value))
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

                outcome = primary_port.resolve(request)
                self.assertIsNotNone(outcome)
                self.assertEqual(1, primary.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_outcomes"
                ).fetchone()[0])
                if terminal == "expiry":
                    self.assertEqual(2, len(results))
                    self.assertTrue(all(not isinstance(value, Exception) for _, value in results))
                    self.assertEqual(outcome, results[0][1])
                    self.assertEqual(outcome, results[1][1])
                else:
                    self.assertEqual(outcome, primary_value)
                    self.assertIsInstance(
                        outcome,
                        (AuthorizationConsumption, AuthorizationRejection),
                    )
                snapshot = control.inspect_ollama_v2_authorization(review)
                if isinstance(outcome, AuthorizationConsumption):
                    self.assertEqual(1, snapshot["consumed_slots"])
                else:
                    self.assertEqual(0, snapshot["consumed_slots"])
                    self.assertEqual(
                        "revoked" if terminal == "revoke" else "expired",
                        outcome.reason,
                    )
                control.close()
                controller_store.close()
                primary.close()

    def test_rollback_requires_a_separate_exact_mandate(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            inspector = _Inspector()
            effects = _Effects(inspector)
            bootstrap = OllamaV2Controller(
                controller_store, inspector, _BootstrapAuthorization(), effects
            )
            plan = build_controller_plan(
                inspector.snapshot,
                *_manifests(),
                operation_id="op-studio-rollback",
            )
            effects.plan = plan
            operation = bootstrap.create_operation(
                plan,
                operation_id=plan.operation_id,
                idempotency_key="create-studio-rollback",
            )
            apply_review = control.build_ollama_v2_authorization_review(
                operation, plan, phase="apply"
            )
            apply_prepared = control.prepare_ollama_v2_authorization(
                apply_review, expected_generation=0
            )
            apply_approved = control.approve_ollama_v2_authorization(
                apply_review,
                expected_generation=0,
                expected_review_hash=apply_prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            apply_port = control.bind_ollama_v2_authorization(
                apply_review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=apply_approved["decision"]["content_hash"],
            )
            apply_controller = OllamaV2Controller(controller_store, inspector, apply_port, effects)
            while operation.state != "prepared_unverified":
                operation = apply_controller.advance_apply(operation)

            operation = apply_controller.prepare_rollback(operation)
            rollback = controller_store.load_rollback_plan(plan.operation_id)
            self.assertIsNotNone(rollback)
            rollback_review = control.build_ollama_v2_authorization_review(
                operation, plan, phase="rollback", rollback_plan=rollback
            )
            self.assertNotEqual(apply_review["mandate_id"], rollback_review["mandate_id"])
            rollback_prepared = control.prepare_ollama_v2_authorization(
                rollback_review, expected_generation=0
            )
            rollback_approved = control.approve_ollama_v2_authorization(
                rollback_review,
                expected_generation=0,
                expected_review_hash=rollback_prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            rollback_port = control.bind_ollama_v2_authorization(
                rollback_review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=rollback_approved["decision"]["content_hash"],
            )
            rollback_controller = OllamaV2Controller(
                controller_store, inspector, rollback_port, effects
            )
            while operation.state != "rolled_back_clean":
                operation = rollback_controller.advance_rollback(operation)

            self.assertEqual("rolled_back_clean", operation.state)
            self.assertEqual(
                len(plan.effects) + len(rollback.effects),
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0],
            )

    def test_rollback_claim_settles_revoked_or_expired_rejection(self) -> None:
        for reason in ("revoked", "expired"):
            clock = [1_000]
            with (
                self.subTest(reason=reason),
                mock.patch.object(
                    human_authority_module,
                    "_director_clock_ms",
                    side_effect=lambda: clock[0],
                ),
                tempfile.TemporaryDirectory() as directory,
                StudioStore(Path(directory) / "studio") as studio,
                OllamaV2ControllerStore(
                    Path(directory) / "controller.sqlite3"
                ) as controller_store,
            ):
                control = StudioDirectorControl(studio)
                control.enroll(passphrase=PASSPHRASE)
                inspector = _Inspector()
                effects = _Effects(inspector)
                bootstrap = OllamaV2Controller(
                    controller_store,
                    inspector,
                    _BootstrapAuthorization(),
                    effects,
                )
                plan = build_controller_plan(
                    inspector.snapshot,
                    *_manifests(),
                    operation_id=f"op-rollback-{reason}",
                )
                effects.plan = plan
                operation = bootstrap.create_operation(
                    plan,
                    operation_id=plan.operation_id,
                    idempotency_key=f"create-rollback-{reason}",
                )
                apply_review = control.build_ollama_v2_authorization_review(
                    operation,
                    plan,
                    phase="apply",
                )
                apply_prepared = control.prepare_ollama_v2_authorization(
                    apply_review,
                    expected_generation=0,
                )
                apply_approved = control.approve_ollama_v2_authorization(
                    apply_review,
                    expected_generation=0,
                    expected_review_hash=apply_prepared["review"]["content_hash"],
                    expires_at_ms=9_007_199_254_740_991,
                )
                apply_port = control.bind_ollama_v2_authorization(
                    apply_review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=apply_approved["decision"]["content_hash"],
                )
                apply_controller = OllamaV2Controller(
                    controller_store,
                    inspector,
                    apply_port,
                    effects,
                )
                while operation.state != "prepared_unverified":
                    operation = apply_controller.advance_apply(operation)
                operation = apply_controller.prepare_rollback(operation)
                rollback = controller_store.load_rollback_plan(plan.operation_id)
                self.assertIsNotNone(rollback)
                review = control.build_ollama_v2_authorization_review(
                    operation,
                    plan,
                    phase="rollback",
                    rollback_plan=rollback,
                )
                prepared = control.prepare_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                )
                approved = control.approve_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                    expected_review_hash=prepared["review"]["content_hash"],
                    expires_at_ms=(
                        2_000 if reason == "expired" else 9_007_199_254_740_991
                    ),
                )
                port = control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
                _attach_studio_authorization_port(controller_store, port, plan)
                request = _request_for_effect(
                    operation,
                    rollback.effects[0],
                    phase="rollback",
                )
                _claim_controller_authorization(controller_store, operation, request)
                if reason == "revoked":
                    control.revoke_ollama_v2_authorization(
                        review,
                        expected_generation=1,
                        expected_decision_hash=approved["decision"]["content_hash"],
                        expected_consumed_slots=0,
                    )
                else:
                    clock[0] = 3_000
                rejection = port.consume(request)
                self.assertIsInstance(rejection, AuthorizationRejection)
                self.assertEqual(reason, rejection.reason)
                self.assertEqual(rejection, port.resolve(request))
                snapshot = control.inspect_ollama_v2_authorization(review)
                self.assertEqual(reason, snapshot["status"])
                self.assertEqual(0, snapshot["consumed_slots"])

    def test_order_duplicate_revoke_lock_and_late_replacement_fail_closed(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-boundaries", observed_generation=0),
                *_manifests(),
                operation_id="op-boundaries",
            )
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-boundaries",
            )
            review = control.build_ollama_v2_authorization_review(operation, plan, phase="apply")
            prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            _attach_studio_authorization_port(controller_store, port, plan)
            wrong_order = AuthorizationRequest.create(
                operation_id=operation.operation_id,
                plan_hash=operation.plan_hash,
                effect_id=plan.effects[1].effect_id,
                phase="apply",
                attempt=operation.next_attempt,
                expected_generation=operation.generation,
                expected_sequence=operation.sequence,
                expected_head_hash=operation.event_head_hash,
                ownership_token=operation.ownership_token,
            )
            exact = AuthorizationRequest.create(
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
            _claim_controller_authorization(controller_store, operation, exact)
            with self.assertRaisesRegex(StudioError, "controller claim"):
                port.consume(wrong_order)
            with self.assertRaisesRegex(StudioError, "controller claim"):
                port.resolve(wrong_order)
            self.assertEqual(
                0,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0],
            )

            with (
                mock.patch.object(
                    StudioOllamaV2AuthorizationDomain,
                    "_consume",
                    side_effect=AssertionError("late class replacement"),
                ),
                mock.patch.object(
                    StudioOllamaV2AuthorizationDomain,
                    "_write",
                    side_effect=AssertionError("late write replacement"),
                ),
                mock.patch.object(
                    StudioOllamaV2AuthorizationDomain,
                    "_require_usable",
                    side_effect=AssertionError("late custody replacement"),
                ),
                mock.patch.object(
                    authorization_module,
                    "_event_mac",
                    side_effect=AssertionError("late global replacement"),
                ),
                mock.patch.object(
                    authorization_module,
                    "_EVENT_MAC_DOMAIN",
                    b"late-replaced-event-mac-domain",
                ),
                mock.patch.object(
                    authorization_module,
                    "_AUTHORITY_ID",
                    "late-replaced-authority",
                ),
                mock.patch.object(
                    authorization_module,
                    "_CREDENTIAL_ID",
                    "late-replaced-credential",
                ),
                mock.patch.object(
                    authorization_module,
                    "_EVENT_FORMAT",
                    "late-replaced-event-format",
                ),
                mock.patch.object(
                    authorization_module,
                    "_OLLAMA_AUTH_CONSUMPTIONS_TABLE",
                    "late_replaced_consumptions",
                ),
            ):
                consumed = port.consume(exact)
            self.assertTrue(consumed.matches(exact))
            self.assertEqual(consumed, port.resolve(exact))
            self.assertEqual(consumed, port.consume(exact))

            revoked = control.revoke_ollama_v2_authorization(
                review,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
                expected_consumed_slots=1,
            )
            self.assertEqual("revoked", revoked["status"])
            next_request = AuthorizationRequest.create(
                operation_id=operation.operation_id,
                plan_hash=operation.plan_hash,
                effect_id=plan.effects[1].effect_id,
                phase="apply",
                attempt=operation.next_attempt + 1,
                expected_generation=operation.generation + 5,
                expected_sequence=operation.sequence + 5,
                expected_head_hash="f" * 64,
                ownership_token=operation.ownership_token,
            )
            with self.assertRaisesRegex(StudioError, "controller claim"):
                port.consume(next_request)
            self.assertEqual(consumed, port.resolve(exact))
            control.lock()
            with self.assertRaisesRegex(StudioError, "unavailable"):
                port.resolve(exact)
            control.unlock(passphrase=PASSPHRASE)
            with self.assertRaisesRegex(StudioError, "unavailable"):
                port.resolve(exact)

    def test_one_approved_apply_mandate_yields_nine_durable_controller_consumptions(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            inspector = _Inspector()
            effects = _Effects(inspector)
            bootstrap = OllamaV2Controller(
                controller_store, inspector, _BootstrapAuthorization(), effects
            )
            release, model = _manifests()
            plan = build_controller_plan(
                inspector.snapshot, release, model, operation_id="op-studio-domain"
            )
            effects.plan = plan
            operation = bootstrap.create_operation(
                plan, operation_id=plan.operation_id, idempotency_key="create-studio-domain"
            )

            review = control.build_ollama_v2_authorization_review(operation, plan, phase="apply")
            prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            self.assertEqual(
                {"consume", "resolve"},
                {
                    name
                    for name in dir(port)
                    if not name.startswith("_") and callable(getattr(port, name))
                },
            )

            controller = OllamaV2Controller(controller_store, inspector, port, effects)
            while operation.state != "prepared_unverified":
                operation = controller.advance_apply(operation)

            self.assertEqual("prepared_unverified", operation.state)
            self.assertEqual(9, len(effects.calls))
            self.assertEqual(
                9,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0],
            )
            snapshot = control.inspect_ollama_v2_authorization(review)
            self.assertEqual("exhausted", snapshot["status"])
            with self.assertRaisesRegex(StudioError, "operation does not match mandate"):
                control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
            studio.connection.execute(
                "UPDATE studio_ollama_v2_authorization_consumptions "
                "SET effect_hash=? WHERE slot_ordinal=0",
                ("0" * 64,),
            )
            studio.connection.commit()
            with self.assertRaisesRegex(StudioError, "authorization audit failed"):
                control.inspect_ollama_v2_authorization(review)

    def test_revoked_or_expired_authorization_pending_rebind_settles_rejection(
        self,
    ) -> None:
        for terminal_status in ("revoked", "expired"):
            clock = [1_000]
            with (
                self.subTest(terminal_status=terminal_status),
                mock.patch.object(
                    human_authority_module,
                    "_director_clock_ms",
                    side_effect=lambda: clock[0],
                ),
                tempfile.TemporaryDirectory() as directory,
                StudioStore(Path(directory) / "studio") as studio,
                OllamaV2ControllerStore(
                    Path(directory) / "controller.sqlite3"
                ) as controller_store,
            ):
                control = StudioDirectorControl(studio)
                control.enroll(passphrase=PASSPHRASE)
                plan = build_controller_plan(
                    make_empty_host_snapshot(
                        f"snap-pending-{terminal_status}",
                        observed_generation=0,
                    ),
                    *_manifests(),
                    operation_id=f"op-pending-{terminal_status}",
                )
                operation = _persist_controller_operation(
                    controller_store,
                    plan,
                    idempotency_key=f"create-pending-{terminal_status}",
                )
                review = control.build_ollama_v2_authorization_review(
                    operation,
                    plan,
                    phase="apply",
                )
                prepared = control.prepare_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                )
                approved = control.approve_ollama_v2_authorization(
                    review,
                    expected_generation=0,
                    expected_review_hash=prepared["review"]["content_hash"],
                    expires_at_ms=2_000,
                )
                request = _request_for_effect(operation, plan.effects[0])
                authorization_pending = controller_store.record_authorization_pending(
                    operation,
                    request,
                ).snapshot
                expected_generation = 1
                if terminal_status == "revoked":
                    control.revoke_ollama_v2_authorization(
                        review,
                        expected_generation=1,
                        expected_decision_hash=approved["decision"]["content_hash"],
                        expected_consumed_slots=0,
                    )
                    expected_generation = 2
                else:
                    clock[0] = 3_000
                port = control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=expected_generation,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
                inspector = _Inspector()
                effects = _Effects(inspector)
                effects.plan = plan
                controller = OllamaV2Controller(
                    controller_store,
                    inspector,
                    port,
                    effects,
                )
                rejected = controller.advance_apply(authorization_pending)
                self.assertEqual("recovery_required", rejected.state)
                self.assertEqual(
                    f"authorization_{terminal_status}",
                    rejected.recovery_reason,
                )
                self.assertEqual([], effects.calls)
                self.assertEqual(
                    0,
                    control.inspect_ollama_v2_authorization(review)["consumed_slots"],
                )

    def test_unrelated_controller_recovery_cannot_rebind_finite_mandate(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
            OllamaV2ControllerStore(
                Path(directory) / "controller.sqlite3"
            ) as controller_store,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-unrelated-recovery", observed_generation=0),
                *_manifests(),
                operation_id="op-unrelated-recovery",
            )
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-unrelated-recovery",
            )
            review = control.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(
                review,
                expected_generation=0,
            )
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            recovery = controller_store.record_recovery(
                operation,
                reason="host_observation_unavailable",
                observed_snapshot=None,
            ).snapshot
            self.assertEqual("recovery_required", recovery.state)
            with self.assertRaisesRegex(StudioError, "operation does not match mandate"):
                control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
            self.assertEqual(
                0,
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_outcomes"
                ).fetchone()[0],
            )

    def test_semantic_replay_rejects_authenticated_consumption_authority_transplant(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-transplant", observed_generation=0),
                *_manifests(),
                operation_id="op-transplant",
            )
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-transplant",
            )
            review = control.build_ollama_v2_authorization_review(operation, plan, phase="apply")
            prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            _attach_studio_authorization_port(controller_store, port, plan)
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
            _claim_controller_authorization(controller_store, operation, request)
            original = port.consume(request)
            transplanted = AuthorizationConsumption.create(
                request,
                authority_id="test-transplanted-authority",
                decision_id=original.decision_id,
            )
            row = studio.connection.execute(
                "SELECT event_id, content_json FROM studio_ollama_v2_authorization_events "
                "WHERE mandate_id=? AND slot_ordinal=0",
                (review["mandate_id"],),
            ).fetchone()
            document = json.loads(row["content_json"])
            document["consumption"] = transplanted.to_document()
            content_bytes = authorization_module._canonical(document)
            content_json = content_bytes.decode("utf-8")
            content_hash = hashlib.sha256(content_bytes).hexdigest()
            domain = control._ollama_v2_authorizations
            self.assertIsNotNone(domain)
            studio.connection.execute("PRAGMA defer_foreign_keys = ON")
            studio.connection.execute(
                "UPDATE studio_ollama_v2_authorization_events "
                "SET content_json=?, content_hash=?, mac=? WHERE event_id=?",
                (
                    content_json,
                    content_hash,
                    authorization_module._event_mac(domain._event_key, document),
                    row["event_id"],
                ),
            )
            studio.connection.execute(
                "UPDATE studio_ollama_v2_authorization_consumptions "
                "SET consumption_id=?, consumption_hash=?, consumption_json=?, event_hash=? "
                "WHERE mandate_id=? AND slot_ordinal=0",
                (
                    transplanted.consumption_id,
                    transplanted.content_hash,
                    authorization_module._canonical(transplanted.to_document()).decode("utf-8"),
                    content_hash,
                    review["mandate_id"],
                ),
            )
            studio.connection.execute(
                "UPDATE studio_ollama_v2_authorization_decisions SET last_event_hash=? "
                "WHERE mandate_id=?",
                (content_hash, review["mandate_id"]),
            )
            studio.connection.execute(
                "UPDATE studio_ollama_v2_authorization_outcomes SET "
                "outcome_id=?, outcome_hash=?, outcome_json=?, event_hash=?, consumption_id=? "
                "WHERE mandate_id=? AND slot_ordinal=0",
                (
                    transplanted.consumption_id,
                    transplanted.content_hash,
                    authorization_module._canonical(transplanted.to_document()).decode("utf-8"),
                    content_hash,
                    transplanted.consumption_id,
                    review["mandate_id"],
                ),
            )
            studio.connection.commit()
            with self.assertRaisesRegex(StudioError, "authorization audit failed"):
                control.inspect_ollama_v2_authorization(review)

    def test_denied_mandate_cannot_bind_and_makes_no_host_call(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-denied-domain", observed_generation=0),
                *_manifests(),
                operation_id="op-denied-domain",
            )
            controller_store = OllamaV2ControllerStore(Path(directory) / "controller.sqlite3")
            self.addCleanup(controller_store.close)
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-denied-domain",
            )
            review = control.build_ollama_v2_authorization_review(operation, plan, phase="apply")
            prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
            denied = control.deny_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
            )
            self.assertEqual("denied", denied["status"])
            with self.assertRaisesRegex(StudioError, "not approved"):
                control.bind_ollama_v2_authorization(
                    review,
                    controller_store=controller_store,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=denied["decision"]["content_hash"],
                )

    def test_revoked_claim_settles_one_idempotent_rejection_outcome(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            StudioStore(Path(directory) / "studio") as studio,
            OllamaV2ControllerStore(Path(directory) / "controller.sqlite3") as controller_store,
        ):
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-revoked-outcome", observed_generation=0),
                *_manifests(),
                operation_id="op-revoked-outcome",
            )
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-revoked-outcome",
            )
            review = control.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=9_007_199_254_740_991,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            _attach_studio_authorization_port(controller_store, port, plan)
            request = _request_for_effect(operation, plan.effects[0])
            claimed = _claim_controller_authorization(
                controller_store,
                operation,
                request,
            )
            revoked = control.revoke_ollama_v2_authorization(
                review,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
                expected_consumed_slots=0,
            )
            self.assertEqual("revoked", revoked["durable_state"])

            first = port.consume(request)
            second = port.consume(request)
            self.assertIsInstance(first, AuthorizationRejection)
            self.assertEqual("revoked", first.reason)
            self.assertEqual(first, second)
            rejected = controller_store.record_authorization_rejected(
                claimed,
                request,
                first,
            ).snapshot
            self.assertEqual("recovery_required", rejected.state)
            self.assertEqual(first, port.resolve(request))
            self.assertEqual(first, port.consume(request))
            self.assertEqual(0, control.inspect_ollama_v2_authorization(review)["consumed_slots"])
            self.assertEqual(
                (1, 0, 1),
                (
                    studio.connection.execute(
                        "SELECT count(*) FROM studio_ollama_v2_authorization_outcomes"
                    ).fetchone()[0],
                    studio.connection.execute(
                        "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                    ).fetchone()[0],
                    studio.connection.execute(
                        "SELECT count(*) FROM studio_ollama_v2_authorization_events "
                        "WHERE event_type='rejected' AND slot_ordinal IS NOT NULL"
                    ).fetchone()[0],
                ),
            )

    def test_expired_claim_is_durably_terminalized_and_unconsumed_claim_rebinds(self) -> None:
        clock = [1_000]
        with (
            mock.patch.object(
                human_authority_module,
                "_director_clock_ms",
                side_effect=lambda: clock[0],
            ),
            tempfile.TemporaryDirectory() as directory,
        ):
            studio_path = Path(directory) / "studio"
            controller_path = Path(directory) / "controller.sqlite3"
            studio = StudioStore(studio_path)
            controller_store = OllamaV2ControllerStore(controller_path)
            control = StudioDirectorControl(studio)
            control.enroll(passphrase=PASSPHRASE)
            plan = build_controller_plan(
                make_empty_host_snapshot("snap-expired-outcome", observed_generation=0),
                *_manifests(),
                operation_id="op-expired-outcome",
            )
            operation = _persist_controller_operation(
                controller_store,
                plan,
                idempotency_key="create-expired-outcome",
            )
            review = control.build_ollama_v2_authorization_review(
                operation,
                plan,
                phase="apply",
            )
            prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
            approved = control.approve_ollama_v2_authorization(
                review,
                expected_generation=0,
                expected_review_hash=prepared["review"]["content_hash"],
                expires_at_ms=2_000,
            )
            port = control.bind_ollama_v2_authorization(
                review,
                controller_store=controller_store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
            )
            _attach_studio_authorization_port(controller_store, port, plan)
            request = _request_for_effect(operation, plan.effects[0])
            _claim_controller_authorization(controller_store, operation, request)
            control.close()
            controller_store.close()
            studio.close()

            with (
                StudioStore(studio_path) as reopened_studio,
                OllamaV2ControllerStore(controller_path) as reopened_controller,
            ):
                reopened = StudioDirectorControl(reopened_studio)
                reopened.unlock(passphrase=PASSPHRASE)
                rebound = reopened.bind_ollama_v2_authorization(
                    review,
                    controller_store=reopened_controller,
                    operation_id=operation.operation_id,
                    expected_generation=1,
                    expected_decision_hash=approved["decision"]["content_hash"],
                )
                _attach_studio_authorization_port(reopened_controller, rebound, plan)
                self.assertIsNone(rebound.resolve(request))
                clock[0] = 3_000
                outcome = rebound.consume(request)
                self.assertIsInstance(outcome, AuthorizationRejection)
                self.assertEqual("expired", outcome.reason)
                snapshot = reopened.inspect_ollama_v2_authorization(review)
                self.assertEqual(("expired", "expired", 2), (
                    snapshot["durable_state"], snapshot["status"], snapshot["generation"]
                ))
                self.assertEqual(outcome, rebound.resolve(request))


if __name__ == "__main__":
    unittest.main()
