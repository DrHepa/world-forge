"""Deterministic non-native Ollama v2 controller over closed host ports.

There is deliberately no POSIX, systemd, process-spawning, socket, provider, or
inference adapter in this module.  Successful application terminates only in
``prepared_unverified`` and cannot establish native or production evidence.
"""

from __future__ import annotations

import gc
import hashlib
import threading
import weakref
from dataclasses import dataclass
from typing import Callable, Protocol

from .ollama_v2_controller_contracts import (
    CONTROLLER_POLICY_CONTENT_HASH,
    SERVICE_UNIT_BYTES,
    SOCKET_UNIT_BYTES,
    AuthorizationConsumption,
    AuthorizationOutcome,
    AuthorizationRejection,
    AuthorizationRequest,
    BoundedTreeManifest,
    ControllerContractError,
    ControllerPlan,
    HostEffect,
    HostSnapshot,
    InterpreterBinding,
    OperationSnapshot,
    RollbackPlan,
    build_controller_plan,
    build_rollback_plan,
    canonical_controller_bytes,
    canonical_interpreter_binding,
    classify_effect_snapshot,
    host_projection_hash,
    is_reusable_clean_projection,
)
from .ollama_v2_controller_store import (
    ControllerStoreTransition,
    OllamaV2ControllerStore,
)


class ControllerError(RuntimeError):
    """Base class for closed controller failures."""


class ControllerConstructionError(ControllerError):
    """A required closed call target is missing or unsafe."""


class ControllerStateError(ControllerError):
    """The caller supplied a stale or inapplicable operation state."""


class ControllerAuthorizationError(ControllerError):
    """The exact one-use authorization could not be proven consumed."""


class ControllerHostObservationError(ControllerError):
    """The host inspector did not return one exact bound snapshot."""


class OllamaV2HostInspector(Protocol):
    def inspect(
        self,
        policy_hash: str,
        binding: InterpreterBinding,
    ) -> HostSnapshot: ...

    def observe(self, operation_id: str, plan_hash: str) -> HostSnapshot: ...


class OllamaV2Authorization(Protocol):
    def consume(self, request: AuthorizationRequest) -> AuthorizationOutcome: ...

    def resolve(
        self,
        request: AuthorizationRequest,
    ) -> AuthorizationOutcome | None: ...


class OllamaV2HostEffects(Protocol):
    def create_managed_root(self, effect: HostEffect) -> None: ...

    def create_principal_exact(self, effect: HostEffect) -> None: ...

    def stage_release(
        self,
        effect: HostEffect,
        manifest: BoundedTreeManifest,
    ) -> None: ...

    def publish_release(
        self,
        effect: HostEffect,
        manifest: BoundedTreeManifest,
    ) -> None: ...

    def stage_model(
        self,
        effect: HostEffect,
        manifest: BoundedTreeManifest,
    ) -> None: ...

    def publish_model(
        self,
        effect: HostEffect,
        manifest: BoundedTreeManifest,
    ) -> None: ...

    def install_socket_unit(self, effect: HostEffect, unit_bytes: bytes) -> None: ...

    def install_service_unit(self, effect: HostEffect, unit_bytes: bytes) -> None: ...

    def reload_manager(self, effect: HostEffect) -> None: ...

    def remove_service_unit_exact(self, effect: HostEffect, unit_bytes: bytes) -> None: ...

    def remove_socket_unit_exact(self, effect: HostEffect, unit_bytes: bytes) -> None: ...

    def unpublish_model_exact(
        self,
        effect: HostEffect,
        manifest: BoundedTreeManifest,
    ) -> None: ...

    def unstage_model_exact(
        self,
        effect: HostEffect,
        manifest: BoundedTreeManifest,
    ) -> None: ...

    def unpublish_release_exact(
        self,
        effect: HostEffect,
        manifest: BoundedTreeManifest,
    ) -> None: ...

    def unstage_release_exact(
        self,
        effect: HostEffect,
        manifest: BoundedTreeManifest,
    ) -> None: ...

    def remove_principal_exact(self, effect: HostEffect) -> None: ...

    def remove_managed_root_exact(self, effect: HostEffect) -> None: ...


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    operation_hash: str
    effect_id: str | None
    phase: str | None
    classification: str
    host_snapshot_hash: str | None

    def __post_init__(self) -> None:
        if (
            type(self.operation_hash) is not str
            or len(self.operation_hash) != 64
            or self.classification
            not in {
                "precondition",
                "postcondition",
                "foreign",
                "recovery_required",
                "terminal",
                "observation_unavailable",
            }
        ):
            raise ControllerStateError("reconciliation_result_invalid")
        if self.effect_id is None:
            if self.phase is not None or self.classification not in {
                "recovery_required",
                "terminal",
            }:
                raise ControllerStateError("reconciliation_result_invalid")
        elif self.phase not in {"apply", "rollback"}:
            raise ControllerStateError("reconciliation_result_invalid")
        if self.host_snapshot_hash is not None and len(self.host_snapshot_hash) != 64:
            raise ControllerStateError("reconciliation_result_invalid")

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(canonical_controller_bytes(self.to_document())).hexdigest()

    def to_document(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.ollama_v2_reconciliation_result",
            "format_version": 1,
            "operation_hash": self.operation_hash,
            "effect_id": self.effect_id,
            "phase": self.phase,
            "classification": self.classification,
            "host_snapshot_hash": self.host_snapshot_hash,
        }


def _capture_call(target: object, name: str):
    candidate = getattr(target, name, None)
    if not callable(candidate):
        raise ControllerConstructionError(f"missing_closed_call:{name}")
    return candidate


def _reject_generic_execution_surface(target: object) -> None:
    for name in dir(target):
        normalized = name.casefold()
        if (
            not name.startswith("_")
            and callable(getattr(target, name, None))
            and (
                normalized in {"run", "execute", "command", "rpc"}
                or "rpc" in normalized
            )
        ):
            raise ControllerConstructionError("generic_execution_surface_forbidden")


def _exact_authorization_outcome(
    value: object,
    request: AuthorizationRequest,
    *,
    _consumption_type=AuthorizationConsumption,
    _rejection_type=AuthorizationRejection,
    _consumption_from_document=AuthorizationConsumption.from_document,
    _rejection_from_document=AuthorizationRejection.from_document,
) -> AuthorizationOutcome:
    try:
        if type(value) is _consumption_type:
            outcome = _consumption_from_document(value.to_document())
        elif type(value) is _rejection_type:
            outcome = _rejection_from_document(value.to_document())
        else:
            raise TypeError("inexact authorization outcome")
    except (ControllerContractError, AttributeError, TypeError) as exc:
        raise ControllerAuthorizationError("authorization_settlement_invalid") from exc
    if not outcome.matches(request):
        raise ControllerAuthorizationError("authorization_request_mismatch")
    return outcome


_STUDIO_AUTHORIZATION_ATTACHMENT_MARKER = object()
_STUDIO_AUTHORIZATION_ATTACHMENT_LOCK = threading.RLock()
_STUDIO_AUTHORIZATION_ATTACHMENTS: dict[int, _StudioAuthorizationAttachment] = {}


class _StudioAuthorizationAttachment:
    __slots__ = (
        "port_ref",
        "store",
        "connection",
        "path",
        "poisoned_operations",
        "attach",
        "state",
    )

    def __init__(
        self,
        *,
        port_ref: weakref.ReferenceType[object],
        store: OllamaV2ControllerStore,
        connection: object,
        path: object,
        poisoned_operations: object,
        attach: Callable[[object, object], None],
    ) -> None:
        self.port_ref = port_ref
        self.store = store
        self.connection = connection
        self.path = path
        self.poisoned_operations = poisoned_operations
        self.attach = attach
        self.state = "registered"

    def __copy__(self) -> object:
        raise ControllerConstructionError("controller_authorization_attachment_invalid")

    def __deepcopy__(self, _memo: object) -> object:
        raise ControllerConstructionError("controller_authorization_attachment_invalid")

    def __reduce__(self) -> object:
        raise ControllerConstructionError("controller_authorization_attachment_invalid")

    def retire(self) -> None:
        self.state = "retired"

    def complete(self, port: object, store: object) -> None:
        if (
            self.state != "consumed"
            or self.port_ref() is not port
            or self.store is not store
        ):
            self.retire()
            raise ControllerConstructionError("controller_authorization_attachment_invalid")
        try:
            self.attach(port, store)
        except BaseException as exc:
            self.retire()
            raise ControllerConstructionError(
                "controller_authorization_attachment_invalid"
            ) from exc
        self.state = "attached"


def _register_studio_authorization_port(
    port: object,
    store: object,
    attach: object,
    *,
    _store_type=OllamaV2ControllerStore,
    _marker=_STUDIO_AUTHORIZATION_ATTACHMENT_MARKER,
    _marker_name="_controller_attachment_marker",
    _attachments=_STUDIO_AUTHORIZATION_ATTACHMENTS,
    _lock=_STUDIO_AUTHORIZATION_ATTACHMENT_LOCK,
    _get_referrers=gc.get_referrers,
    _weakref=weakref.ref,
) -> None:
    if type(store) is not _store_type or not callable(attach):
        raise ControllerConstructionError("controller_authorization_attachment_invalid")
    try:
        connection = store._connection
        path = store._path
        poisoned_operations = store._poisoned_operations
        if type(store._closed) is not bool or store._closed:
            raise ValueError("closed controller store")
        owners = tuple(
            candidate
            for candidate in _get_referrers(connection)
            if type(candidate) is _store_type and candidate._connection is connection
        )
        if len(owners) != 1 or owners[0] is not store:
            raise ValueError("ambiguous controller store")
        key = id(port)

        def release(reference: weakref.ReferenceType[object]) -> None:
            with _lock:
                current = _attachments.get(key)
                if current is not None and current.port_ref is reference:
                    _attachments.pop(key, None)

        reference = _weakref(port, release)
        object.__setattr__(port, _marker_name, _marker)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ControllerConstructionError(
            "controller_authorization_attachment_invalid"
        ) from exc
    registration = _StudioAuthorizationAttachment(
        port_ref=reference,
        store=store,
        connection=connection,
        path=path,
        poisoned_operations=poisoned_operations,
        attach=attach,
    )
    with _lock:
        if key in _attachments:
            registration.retire()
            raise ControllerConstructionError(
                "controller_authorization_attachment_invalid"
            )
        _attachments[key] = registration


def _consume_studio_authorization_port_registration(
    port: object,
    store: object,
    *,
    _store_type=OllamaV2ControllerStore,
    _marker=_STUDIO_AUTHORIZATION_ATTACHMENT_MARKER,
    _marker_name="_controller_attachment_marker",
    _attachments=_STUDIO_AUTHORIZATION_ATTACHMENTS,
    _lock=_STUDIO_AUTHORIZATION_ATTACHMENT_LOCK,
) -> _StudioAuthorizationAttachment | None:
    marker = getattr(port, _marker_name, None)
    key = id(port)
    with _lock:
        registration = _attachments.pop(key, None)
    if marker is not _marker:
        if registration is not None:
            registration.retire()
            raise ControllerConstructionError(
                "controller_authorization_attachment_invalid"
            )
        return None
    if (
        registration is None
        or registration.port_ref() is not port
        or registration.state != "registered"
    ):
        if registration is not None:
            registration.retire()
        raise ControllerConstructionError("controller_authorization_attachment_invalid")
    if (
        type(store) is not _store_type
        or store is not registration.store
        or store._connection is not registration.connection
        or store._path is not registration.path
        or store._poisoned_operations is not registration.poisoned_operations
        or type(store._closed) is not bool
        or store._closed
    ):
        registration.retire()
        raise ControllerConstructionError("controller_authorization_store_mismatch")
    registration.state = "consumed"
    return registration


def _bind_studio_authorization_attachment(consumer):
    def decorate(initializer):
        def attached_init(
            self,
            store: OllamaV2ControllerStore,
            inspector: OllamaV2HostInspector,
            authorization: OllamaV2Authorization,
            effects: OllamaV2HostEffects,
        ) -> None:
            registration = consumer(authorization, store)
            try:
                initializer(self, store, inspector, authorization, effects)
                if registration is not None:
                    registration.complete(authorization, store)
            except BaseException:
                if registration is not None and registration.state == "consumed":
                    registration.retire()
                raise

        attached_init.__name__ = initializer.__name__
        attached_init.__qualname__ = initializer.__qualname__
        attached_init.__doc__ = initializer.__doc__
        attached_init.__annotations__ = initializer.__annotations__
        return attached_init

    return decorate


class OllamaV2Controller:
    """Closed state machine that advances one authorized host effect at a time."""

    __slots__ = (
        "_store_create_operation",
        "_store_load_operation",
        "_store_load_plan",
        "_store_load_rollback_plan",
        "_store_record_authorization_pending",
        "_store_record_authorization_claimed",
        "_store_record_authorization_consumed",
        "_store_record_authorization_rejected",
        "_store_load_authorization_request",
        "_store_load_authorization_consumption",
        "_store_record_dispatching",
        "_store_record_effect_observation",
        "_store_record_recovery",
        "_store_record_rollback_plan",
        "_inspect_call",
        "_observe_call",
        "_consume_call",
        "_resolve_call",
        "_exact_authorization_outcome_call",
        "_create_managed_root_call",
        "_create_principal_call",
        "_stage_release_call",
        "_publish_release_call",
        "_stage_model_call",
        "_publish_model_call",
        "_install_socket_call",
        "_install_service_call",
        "_reload_manager_call",
        "_remove_service_call",
        "_remove_socket_call",
        "_unpublish_model_call",
        "_unstage_model_call",
        "_unpublish_release_call",
        "_unstage_release_call",
        "_remove_principal_call",
        "_remove_managed_root_call",
        "_dispatch_call",
    )

    @_bind_studio_authorization_attachment(
        _consume_studio_authorization_port_registration
    )
    def __init__(
        self,
        store: OllamaV2ControllerStore,
        inspector: OllamaV2HostInspector,
        authorization: OllamaV2Authorization,
        effects: OllamaV2HostEffects,
    ) -> None:
        if not isinstance(store, OllamaV2ControllerStore):
            raise ControllerConstructionError("controller_store_invalid")
        for target in (inspector, authorization, effects):
            _reject_generic_execution_surface(target)

        self._store_create_operation = _capture_call(store, "create_operation")
        self._store_load_operation = _capture_call(store, "load_operation")
        self._store_load_plan = _capture_call(store, "load_plan")
        self._store_load_rollback_plan = _capture_call(store, "load_rollback_plan")
        self._store_record_authorization_pending = _capture_call(
            store, "record_authorization_pending"
        )
        self._store_record_authorization_claimed = _capture_call(
            store, "record_authorization_claimed"
        )
        self._store_record_authorization_consumed = _capture_call(
            store, "record_authorization_consumed"
        )
        self._store_record_authorization_rejected = _capture_call(
            store, "record_authorization_rejected"
        )
        self._store_load_authorization_request = _capture_call(
            store, "load_authorization_request"
        )
        self._store_load_authorization_consumption = _capture_call(
            store, "load_authorization_consumption"
        )
        self._store_record_dispatching = _capture_call(store, "record_dispatching")
        self._store_record_effect_observation = _capture_call(
            store, "record_effect_observation"
        )
        self._store_record_recovery = _capture_call(store, "record_recovery")
        self._store_record_rollback_plan = _capture_call(store, "record_rollback_plan")

        self._inspect_call = _capture_call(inspector, "inspect")
        self._observe_call = _capture_call(inspector, "observe")
        self._consume_call = _capture_call(authorization, "consume")
        self._resolve_call = _capture_call(authorization, "resolve")
        self._exact_authorization_outcome_call = _exact_authorization_outcome
        self._create_managed_root_call = _capture_call(effects, "create_managed_root")
        self._create_principal_call = _capture_call(effects, "create_principal_exact")
        self._stage_release_call = _capture_call(effects, "stage_release")
        self._publish_release_call = _capture_call(effects, "publish_release")
        self._stage_model_call = _capture_call(effects, "stage_model")
        self._publish_model_call = _capture_call(effects, "publish_model")
        self._install_socket_call = _capture_call(effects, "install_socket_unit")
        self._install_service_call = _capture_call(effects, "install_service_unit")
        self._reload_manager_call = _capture_call(effects, "reload_manager")
        self._remove_service_call = _capture_call(effects, "remove_service_unit_exact")
        self._remove_socket_call = _capture_call(effects, "remove_socket_unit_exact")
        self._unpublish_model_call = _capture_call(effects, "unpublish_model_exact")
        self._unstage_model_call = _capture_call(effects, "unstage_model_exact")
        self._unpublish_release_call = _capture_call(effects, "unpublish_release_exact")
        self._unstage_release_call = _capture_call(effects, "unstage_release_exact")
        self._remove_principal_call = _capture_call(effects, "remove_principal_exact")
        self._remove_managed_root_call = _capture_call(effects, "remove_managed_root_exact")
        self._dispatch_call = self._dispatch

    @staticmethod
    def _exact_snapshot(value: object) -> HostSnapshot:
        if type(value) is not HostSnapshot:
            raise ControllerHostObservationError("host_snapshot_type_invalid")
        try:
            return HostSnapshot.from_document(value.to_document())
        except (ControllerContractError, AttributeError, TypeError) as exc:
            raise ControllerHostObservationError("host_snapshot_invalid") from exc

    def inspect(self) -> HostSnapshot:
        binding = canonical_interpreter_binding()
        try:
            value = self._inspect_call(CONTROLLER_POLICY_CONTENT_HASH, binding)
        except BaseException as exc:
            raise ControllerHostObservationError("host_inspection_unavailable") from exc
        return self._exact_snapshot(value)

    @staticmethod
    def build_plan(
        snapshot: HostSnapshot,
        release_manifest: BoundedTreeManifest,
        model_manifest: BoundedTreeManifest,
        *,
        operation_id: str,
    ) -> ControllerPlan:
        return build_controller_plan(
            snapshot,
            release_manifest,
            model_manifest,
            operation_id=operation_id,
        )

    def create_operation(
        self,
        plan: ControllerPlan,
        *,
        operation_id: str,
        idempotency_key: str,
    ) -> OperationSnapshot:
        initial = OperationSnapshot.create(operation_id, plan)
        transition = self._store_create_operation(
            initial,
            plan,
            idempotency_key=idempotency_key,
        )
        return self._exact_transition(transition).snapshot

    def status(self, operation_id: str) -> OperationSnapshot:
        return self._store_load_operation(operation_id)

    @staticmethod
    def _exact_transition(value: object) -> ControllerStoreTransition:
        if type(value) is not ControllerStoreTransition:
            raise ControllerStateError("store_transition_result_invalid")
        return value

    def _exact_expected(self, expected: OperationSnapshot) -> OperationSnapshot:
        try:
            expected = OperationSnapshot.from_document(expected.to_document())
        except (ControllerContractError, AttributeError, TypeError) as exc:
            raise ControllerStateError("operation_snapshot_invalid") from exc
        current = self._store_load_operation(expected.operation_id)
        if current != expected:
            raise ControllerStateError("operation_snapshot_stale")
        return current

    def _observe(self, operation: OperationSnapshot) -> HostSnapshot:
        try:
            value = self._observe_call(operation.operation_id, operation.plan_hash)
        except BaseException as exc:
            raise ControllerHostObservationError("host_observation_unavailable") from exc
        return self._exact_snapshot(value)

    def _settle_authorization(
        self,
        request: AuthorizationRequest,
    ) -> AuthorizationOutcome:
        try:
            resolved = self._resolve_call(request)
        except BaseException as exc:
            raise ControllerAuthorizationError("authorization_settlement_unavailable") from exc
        if resolved is not None:
            return self._exact_authorization_outcome_call(resolved, request)

        returned: object = None
        consume_failed = False
        try:
            returned = self._consume_call(request)
        except BaseException:
            consume_failed = True

        try:
            resolved = self._resolve_call(request)
        except BaseException as exc:
            raise ControllerAuthorizationError("authorization_settlement_unavailable") from exc
        if resolved is None:
            raise ControllerAuthorizationError("authorization_settlement_pending")
        exact_resolved = self._exact_authorization_outcome_call(resolved, request)
        if not consume_failed and returned is not None:
            exact_returned = self._exact_authorization_outcome_call(returned, request)
            if exact_returned != exact_resolved:
                raise ControllerAuthorizationError("authorization_settlement_mismatch")
        return exact_resolved

    def _resolve_durable_consumption(
        self,
        request: AuthorizationRequest,
        durable: AuthorizationConsumption,
    ) -> AuthorizationConsumption:
        try:
            resolved = self._resolve_call(request)
        except BaseException as exc:
            raise ControllerAuthorizationError("authorization_resolution_failed") from exc
        if type(resolved) is not AuthorizationConsumption:
            raise ControllerAuthorizationError("authorization_resolution_invalid")
        try:
            exact = self._exact_authorization_outcome_call(resolved, request)
        except ControllerAuthorizationError as exc:
            raise ControllerAuthorizationError("authorization_resolution_invalid") from exc
        if exact != durable:
            raise ControllerAuthorizationError("authorization_resolution_mismatch")
        return exact

    def _current_effect(
        self,
        operation: OperationSnapshot,
        *,
        phase: str,
    ) -> tuple[ControllerPlan, RollbackPlan | None, HostEffect]:
        plan = self._store_load_plan(operation.operation_id)
        if phase == "apply":
            if operation.apply_cursor >= len(plan.effects):
                raise ControllerStateError("apply_effect_cursor_invalid")
            return plan, None, plan.effects[operation.apply_cursor]
        rollback = self._store_load_rollback_plan(operation.operation_id)
        if rollback is None or operation.rollback_cursor >= len(rollback.effects):
            raise ControllerStateError("rollback_effect_cursor_invalid")
        return plan, rollback, rollback.effects[operation.rollback_cursor]

    def _dispatch(self, plan: ControllerPlan, effect: HostEffect) -> None:
        kind = effect.kind
        if kind == "managed_root.create":
            self._create_managed_root_call(effect)
        elif kind == "principal.create_exact":
            self._create_principal_call(effect)
        elif kind == "release.stage":
            self._stage_release_call(effect, plan.release_manifest)
        elif kind == "release.publish":
            self._publish_release_call(effect, plan.release_manifest)
        elif kind == "model.stage":
            self._stage_model_call(effect, plan.model_manifest)
        elif kind == "model.publish":
            self._publish_model_call(effect, plan.model_manifest)
        elif kind == "socket.install":
            self._install_socket_call(effect, bytes(SOCKET_UNIT_BYTES))
        elif kind == "service.install":
            self._install_service_call(effect, bytes(SERVICE_UNIT_BYTES))
        elif kind == "service.remove_exact":
            self._remove_service_call(effect, bytes(SERVICE_UNIT_BYTES))
        elif kind == "socket.remove_exact":
            self._remove_socket_call(effect, bytes(SOCKET_UNIT_BYTES))
        elif kind == "model.unpublish_exact":
            self._unpublish_model_call(effect, plan.model_manifest)
        elif kind == "model.unstage_exact":
            self._unstage_model_call(effect, plan.model_manifest)
        elif kind == "release.unpublish_exact":
            self._unpublish_release_call(effect, plan.release_manifest)
        elif kind == "release.unstage_exact":
            self._unstage_release_call(effect, plan.release_manifest)
        elif kind == "principal.remove_exact":
            self._remove_principal_call(effect)
        elif kind == "managed_root.remove_exact":
            self._remove_managed_root_call(effect)
        elif kind == "manager.reload":
            self._reload_manager_call(effect)
        else:
            raise ControllerStateError("closed_effect_kind_invalid")

    def _record_unavailable_observation(
        self,
        dispatching: OperationSnapshot,
        request: AuthorizationRequest,
    ) -> OperationSnapshot:
        transition = self._store_record_effect_observation(
            dispatching,
            request,
            None,
            outcome="observation_unavailable",
        )
        return self._exact_transition(transition).snapshot

    def _observe_dispatching(
        self,
        operation: OperationSnapshot,
        request: AuthorizationRequest,
        effect: HostEffect,
    ) -> OperationSnapshot:
        try:
            observed = self._observe(operation)
        except ControllerHostObservationError:
            return self._record_unavailable_observation(operation, request)
        classification = classify_effect_snapshot(observed, effect)
        transition = self._store_record_effect_observation(
            operation,
            request,
            observed,
            outcome=classification,
        )
        return self._exact_transition(transition).snapshot

    def _advance(self, expected: OperationSnapshot, *, phase: str) -> OperationSnapshot:
        operation = self._exact_expected(expected)
        terminal_state = "prepared_unverified" if phase == "apply" else "rolled_back_clean"
        if operation.state == terminal_state:
            return operation
        allowed = {
            f"{phase}_pending",
            f"{phase}_authorization_pending",
            f"{phase}_authorization_claimed",
            f"{phase}_authorization_consumed",
            f"{phase}_dispatching",
        }
        if operation.state not in allowed:
            raise ControllerStateError(f"{phase}_state_invalid")
        plan, _rollback, effect = self._current_effect(operation, phase=phase)

        if operation.state == f"{phase}_pending":
            request = AuthorizationRequest.create(
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
            transition = self._exact_transition(
                self._store_record_authorization_pending(operation, request)
            )
            operation = transition.snapshot
            if not transition.committed_now:
                return operation
        else:
            if operation.current_authorization_hash is None:
                raise ControllerStateError("authorization_binding_missing")
            request = self._store_load_authorization_request(
                operation.current_authorization_hash
            )

        if operation.state == f"{phase}_authorization_pending":
            transition = self._exact_transition(
                self._store_record_authorization_claimed(operation, request)
            )
            operation = transition.snapshot
            if not transition.committed_now:
                return operation

        settled_consumption: AuthorizationConsumption | None = None
        if operation.state == f"{phase}_authorization_claimed":
            outcome = self._settle_authorization(request)
            if type(outcome) is AuthorizationRejection:
                transition = self._exact_transition(
                    self._store_record_authorization_rejected(
                        operation,
                        request,
                        outcome,
                    )
                )
                return transition.snapshot
            if type(outcome) is not AuthorizationConsumption:
                raise ControllerAuthorizationError("authorization_settlement_invalid")
            transition = self._exact_transition(
                self._store_record_authorization_consumed(
                    operation,
                    request,
                    outcome,
                )
            )
            operation = transition.snapshot
            settled_consumption = outcome
            if not transition.committed_now:
                return operation
        elif operation.state not in {
            f"{phase}_authorization_consumed",
            f"{phase}_dispatching",
        }:
            raise ControllerStateError("authorization_state_invalid")

        if operation.state in {
            f"{phase}_authorization_consumed",
            f"{phase}_dispatching",
        }:
            consumption = self._store_load_authorization_consumption(
                request.authorization_id
            )
            if (
                type(consumption) is not AuthorizationConsumption
                or not consumption.matches(request)
            ):
                raise ControllerAuthorizationError("durable_consumption_missing")
            if operation.state == f"{phase}_authorization_consumed":
                if settled_consumption is None:
                    consumption = self._resolve_durable_consumption(request, consumption)
                elif consumption != settled_consumption:
                    raise ControllerAuthorizationError(
                        "authorization_settlement_mismatch"
                    )
        else:
            raise ControllerStateError("authorization_state_invalid")

        if operation.state == f"{phase}_dispatching":
            return self._observe_dispatching(operation, request, effect)

        try:
            before = self._observe(operation)
        except ControllerHostObservationError:
            transition = self._store_record_recovery(
                operation,
                reason="host_observation_unavailable",
                observed_snapshot=None,
            )
            return self._exact_transition(transition).snapshot
        if classify_effect_snapshot(before, effect) != "precondition":
            transition = self._store_record_recovery(
                operation,
                reason="host_state_foreign",
                observed_snapshot=before,
            )
            return self._exact_transition(transition).snapshot
        transition = self._exact_transition(
            self._store_record_dispatching(
                operation,
                request,
                consumption,
                before,
            )
        )
        dispatching = transition.snapshot
        if not transition.committed_now:
            return dispatching
        try:
            self._dispatch_call(plan, effect)
        except BaseException:
            pass
        return self._observe_dispatching(dispatching, request, effect)

    def advance_apply(self, expected: OperationSnapshot) -> OperationSnapshot:
        return self._advance(expected, phase="apply")

    def prepare_rollback(self, expected: OperationSnapshot) -> OperationSnapshot:
        operation = self._exact_expected(expected)
        if operation.state not in {
            "apply_pending",
            "prepared_unverified",
            "recovery_required",
        }:
            raise ControllerStateError("rollback_preparation_state_invalid")
        plan = self._store_load_plan(operation.operation_id)
        rollback = build_rollback_plan(
            operation.operation_id,
            plan,
            operation.applied_effect_ids,
        )
        clean_snapshot = None
        if not rollback.effects:
            try:
                clean_snapshot = self._observe(operation)
            except ControllerHostObservationError:
                transition = self._store_record_recovery(
                    operation,
                    reason="host_observation_unavailable",
                    observed_snapshot=None,
                )
                return self._exact_transition(transition).snapshot
            if not is_reusable_clean_projection(clean_snapshot, plan.initial_snapshot):
                transition = self._store_record_recovery(
                    operation,
                    reason="host_state_foreign",
                    observed_snapshot=clean_snapshot,
                )
                return self._exact_transition(transition).snapshot
        transition = self._store_record_rollback_plan(
            operation,
            rollback,
            clean_snapshot=clean_snapshot,
        )
        return self._exact_transition(transition).snapshot

    def advance_rollback(self, expected: OperationSnapshot) -> OperationSnapshot:
        return self._advance(expected, phase="rollback")

    def reconcile(self, expected: OperationSnapshot) -> ReconciliationResult:
        operation = self._exact_expected(expected)
        if operation.state in {"prepared_unverified", "rolled_back_clean"}:
            return ReconciliationResult(
                operation_hash=operation.content_hash,
                effect_id=None,
                phase=None,
                classification="terminal",
                host_snapshot_hash=operation.last_host_snapshot_hash,
            )
        if operation.state.startswith("apply_"):
            phase = "apply"
        elif operation.state.startswith("rollback_"):
            phase = "rollback"
        elif operation.state == "recovery_required":
            phase = "rollback" if operation.rollback_plan_hash is not None else "apply"
            plan = self._store_load_plan(operation.operation_id)
            if phase == "rollback":
                rollback = self._store_load_rollback_plan(operation.operation_id)
                effect_count = 0 if rollback is None else len(rollback.effects)
                exhausted = operation.rollback_cursor >= effect_count
            else:
                exhausted = operation.apply_cursor >= len(plan.effects)
            if exhausted:
                return ReconciliationResult(
                    operation_hash=operation.content_hash,
                    effect_id=None,
                    phase=None,
                    classification="recovery_required",
                    host_snapshot_hash=operation.last_host_snapshot_hash,
                )
        else:
            raise ControllerStateError("reconciliation_state_invalid")
        _plan, _rollback, effect = self._current_effect(operation, phase=phase)
        try:
            snapshot = self._observe(operation)
        except ControllerHostObservationError:
            return ReconciliationResult(
                operation_hash=operation.content_hash,
                effect_id=effect.effect_id,
                phase=phase,
                classification="observation_unavailable",
                host_snapshot_hash=None,
            )
        return ReconciliationResult(
            operation_hash=operation.content_hash,
            effect_id=effect.effect_id,
            phase=phase,
            classification=classify_effect_snapshot(snapshot, effect),
            host_snapshot_hash=snapshot.content_hash,
        )


__all__ = (
    "ControllerAuthorizationError",
    "ControllerConstructionError",
    "ControllerError",
    "ControllerHostObservationError",
    "ControllerStateError",
    "OllamaV2Authorization",
    "OllamaV2Controller",
    "OllamaV2HostEffects",
    "OllamaV2HostInspector",
    "ReconciliationResult",
)
