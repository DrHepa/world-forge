"""Durable Director plan mandates for the private Ollama-v2 controller."""

from __future__ import annotations

import gc
import hashlib
import hmac
import json
import sqlite3
import threading
from dataclasses import replace

from worldforge.agent_harness.approvals import ApprovalError
from worldforge.provider_evidence.ollama_v2_controller import (
    _register_studio_authorization_port,
)
from worldforge.provider_evidence.ollama_v2_controller_contracts import (
    AuthorizationConsumption,
    AuthorizationOutcome,
    AuthorizationRejection,
    AuthorizationRequest,
    ControllerPlan,
    OperationSnapshot,
    RollbackPlan,
)
from worldforge.provider_evidence.ollama_v2_controller_store import (
    OllamaV2ControllerStore,
)
from worldforge.studio.authenticated_human_decisions import (
    StudioAuthenticatedHumanDecisionAuthority,
    _CredentialEvidence,
    _canonical_utc_timestamp,
    _consume_studio_ollama_v2_authorization_capsule,
    _credential_evidence,
    _same_credential,
)
from worldforge.studio.errors import StudioError
from worldforge.studio.ollama_v2_authorization_contracts import (
    StudioOllamaV2AuthorizationContractError,
    StudioOllamaV2AuthorizationDecision,
    StudioOllamaV2AuthorizationReview,
    StudioOllamaV2AuthorizationSnapshot,
    build_ollama_v2_authorization_review,
    exact_authorization_outcome,
    exact_authorization_request,
)
from worldforge.studio.storage import (
    _OLLAMA_AUTH_CONSUMPTIONS_TABLE,
    _OLLAMA_AUTH_DECISIONS_TABLE,
    _OLLAMA_AUTH_EVENTS_TABLE,
    _OLLAMA_AUTH_OUTCOMES_TABLE,
    _verify_authenticated_human_decision_v6,
    _verify_ollama_v2_authorization_v8,
    utc_now,
)

_ZERO_HASH = "0" * 64
_CREDENTIAL_ID = "director_local"
_AUTHORITY_ID = "studio-director-ollama-v2"
_EVENT_FORMAT = "world-forge.private.studio_ollama_v2_authorization_event"
_EVENT_MAC_DOMAIN = b"world-forge.studio.director.ollama-v2-authorization.event-mac.v1\x00"
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_CONTROLLER_STORE_CUSTODY: dict[int, OllamaV2ControllerStore] = {}
_CONTROLLER_STORE_CUSTODY_LOCK = threading.RLock()


class _ControllerStoreReadBusyError(RuntimeError):
    pass


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise StudioError("invalid_request", "Ollama v2 authorization data is invalid") from exc


def _decode(value: object) -> dict[str, object]:
    if type(value) is not str:
        raise ValueError("authorization JSON")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = item
        return result

    parsed = json.loads(
        value,
        object_pairs_hook=pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
    )
    if type(parsed) is not dict or _canonical(parsed).decode("utf-8") != value:
        raise ValueError("noncanonical authorization JSON")
    return parsed


def _decode_controller_blob(value: object) -> dict[str, object]:
    if type(value) is not bytes:
        raise ValueError("controller authorization JSON")
    try:
        text = value.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("controller authorization JSON") from exc
    document = _decode(text)
    if _canonical(document) != value:
        raise ValueError("controller authorization JSON")
    return document


def _event_mac(
    key: bytes,
    document: dict[str, object],
    _canonical=_canonical,
    _domain=_EVENT_MAC_DOMAIN,
    _hmac_new=hmac.new,
    _sha256=hashlib.sha256,
) -> bytes:
    return _hmac_new(key, _domain + _canonical(document), _sha256).digest()


def _event_document(
    *,
    event_type: str,
    review: StudioOllamaV2AuthorizationReview,
    decision: StudioOllamaV2AuthorizationDecision | None,
    state: str,
    generation: int,
    consumed_count: int,
    slot_ordinal: int | None,
    request: AuthorizationRequest | None,
    consumption: AuthorizationConsumption | None,
    previous_hash: str,
    created_at: str,
    _authority_id=_AUTHORITY_ID,
    _credential_id=_CREDENTIAL_ID,
    _event_format=_EVENT_FORMAT,
) -> dict[str, object]:
    return {
        "format": _event_format,
        "format_version": 1,
        "credential_id": _credential_id,
        "authority_id": _authority_id,
        "event_type": event_type,
        "mandate_id": review.mandate_id,
        "generation": generation,
        "state": state,
        "consumed_count": consumed_count,
        "slot_ordinal": slot_ordinal,
        "review": review.to_document(),
        "decision": None if decision is None else decision.to_document(),
        "request": None if request is None else request.to_document(),
        "consumption": None if consumption is None else consumption.to_document(),
        "previous_hash": previous_hash,
        "created_at": created_at,
    }


def _review(
    value: object,
    _review_type=StudioOllamaV2AuthorizationReview,
    _review_from_document=StudioOllamaV2AuthorizationReview.from_document,
) -> StudioOllamaV2AuthorizationReview:
    if type(value) is _review_type:
        value = value.to_document()
    return _review_from_document(value)


def _authorization_outcome_document(
    value: object,
    *,
    _consumption_from_document=AuthorizationConsumption.from_document,
    _rejection_from_document=AuthorizationRejection.from_document,
) -> AuthorizationOutcome:
    if type(value) is not dict:
        raise StudioError("invalid_state", "Ollama v2 authorization outcome is invalid")
    if value.get("format") == "world-forge.private.ollama_v2_authorization_consumption":
        return _consumption_from_document(value)
    if value.get("format") == "world-forge.private.ollama_v2_authorization_rejection":
        return _rejection_from_document(value)
    raise StudioError("invalid_state", "Ollama v2 authorization outcome is invalid")


def _controller_method_census(
    store_type: type,
) -> tuple[tuple[str, object], ...]:
    return tuple(
        (name, value) for name, value in sorted(store_type.__dict__.items()) if callable(value)
    )


def _controller_claim_binding(
    store: object,
    operation_id: object,
    review: StudioOllamaV2AuthorizationReview,
    *,
    _store_type=OllamaV2ControllerStore,
    _method_census=_controller_method_census,
    _custody=_CONTROLLER_STORE_CUSTODY,
    _custody_lock=_CONTROLLER_STORE_CUSTODY_LOCK,
    _get_referrers=gc.get_referrers,
    _operation_from_document=OperationSnapshot.from_document,
    _plan_from_document=ControllerPlan.from_document,
    _rollback_from_document=RollbackPlan.from_document,
    _request_type=AuthorizationRequest,
    _consumption_type=AuthorizationConsumption,
    _rejection_type=AuthorizationRejection,
    _consumption_from_document=AuthorizationConsumption.from_document,
    _rejection_from_document=AuthorizationRejection.from_document,
    _decode_document=_decode_controller_blob,
    _snapshot_type=OperationSnapshot,
    _plan_type=ControllerPlan,
    _rollback_type=RollbackPlan,
    _programming_error=sqlite3.ProgrammingError,
    _read_busy_type=_ControllerStoreReadBusyError,
    _register_port=_register_studio_authorization_port,
):
    if (
        type(store) is not _store_type
        or type(operation_id) is not str
        or operation_id != review.operation_id
    ):
        raise StudioError(
            "invalid_request",
            "Ollama v2 controller store binding is invalid",
        )
    try:
        connection = store._connection
        path = store._path
        poisoned_operations = store._poisoned_operations
        if type(store._closed) is not bool or store._closed:
            raise ValueError("controller store closed")
        method_census = _method_census(_store_type)
        verify_schema = _store_type._verify_schema.__get__(store, _store_type)
        verify_all_rows = _store_type._verify_all_rows.__get__(store, _store_type)
        load_operation = _store_type.load_operation.__get__(store, _store_type)
        load_plan = _store_type.load_plan.__get__(store, _store_type)
        load_rollback_plan = _store_type.load_rollback_plan.__get__(store, _store_type)
        load_authorization_request = _store_type.load_authorization_request.__get__(
            store,
            _store_type,
        )
        row_factory = connection.row_factory
    except (AttributeError, TypeError, ValueError) as exc:
        raise StudioError(
            "invalid_state",
            "Ollama v2 controller store is unavailable",
        ) from exc
    owners = tuple(
        candidate
        for candidate in _get_referrers(connection)
        if type(candidate) is _store_type and candidate._connection is connection
    )
    if len(owners) != 1 or owners[0] is not store:
        raise StudioError(
            "invalid_request",
            "Ollama v2 controller store identity is ambiguous",
        )
    with _custody_lock:
        existing = _custody.get(id(connection))
        if existing is None:
            _custody[id(connection)] = store
        elif existing is not store:
            raise StudioError(
                "invalid_request",
                "Ollama v2 controller store identity is ambiguous",
            )

    expected_starting = _operation_from_document(review.starting_snapshot_document)
    expected_plan = _plan_from_document(review.plan_document)
    expected_rollback = (
        None
        if review.rollback_plan_document is None
        else _rollback_from_document(review.rollback_plan_document)
    )
    state: dict[str, object] = {
        "poisoned": False,
        "port": None,
        "attached": False,
    }

    def require_custody() -> None:
        if state["poisoned"]:
            raise StudioError(
                "invalid_state",
                "Ollama v2 controller store binding is unavailable",
            )
        current_census = _method_census(_store_type)
        if (
            type(store) is not _store_type
            or store._connection is not connection
            or store._path is not path
            or store._poisoned_operations is not poisoned_operations
            or type(store._closed) is not bool
            or store._closed
            or connection.row_factory is not row_factory
            or operation_id in poisoned_operations
            or len(current_census) != len(method_census)
            or any(
                current_name != expected_name or current_value is not expected_value
                for (current_name, current_value), (expected_name, expected_value) in zip(
                    current_census,
                    method_census,
                    strict=True,
                )
            )
        ):
            raise ValueError("controller store custody changed")

    def read_controller(
        request_binding: AuthorizationRequest | str | None = None,
        _canonical_document=_canonical,
    ):
        began_transaction = False
        try:
            require_custody()
            if connection.in_transaction:
                raise _read_busy_type("controller store transaction already active")
            try:
                connection.execute("BEGIN")
            except BaseException:
                try:
                    began_transaction = bool(connection.in_transaction)
                except BaseException:
                    began_transaction = False
                raise
            began_transaction = True
            verify_schema()
            verify_all_rows()
            snapshot = load_operation(operation_id)
            plan = load_plan(operation_id)
            rollback = load_rollback_plan(operation_id)
            event_rows = connection.execute(
                "SELECT sequence, event_json, snapshot_json FROM controller_events "
                "WHERE operation_id=? ORDER BY sequence",
                (operation_id,),
            ).fetchall()
            authorization_rows = connection.execute(
                "SELECT authorization_id, phase, effect_id, attempt, request_json, "
                "consumption_json, state FROM controller_authorizations "
                "WHERE operation_id=? ORDER BY attempt, authorization_id",
                (operation_id,),
            ).fetchall()
            attempt_rows = connection.execute(
                "SELECT attempt_id, phase, effect_id, attempt, authorization_id, "
                "request_hash, before_snapshot_json, after_snapshot_json, outcome, "
                "dispatch_sequence, observation_sequence "
                "FROM controller_effect_attempts WHERE operation_id=? "
                "ORDER BY attempt, attempt_id",
                (operation_id,),
            ).fetchall()
            authorization_row = None
            if request_binding is None:
                stored_request = None
            elif type(request_binding) is _request_type:
                authorization_row = connection.execute(
                    "SELECT request_json, consumption_json FROM controller_authorizations "
                    "WHERE authorization_id=?",
                    (request_binding.authorization_id,),
                ).fetchone()
                stored_request = (
                    None
                    if authorization_row is None
                    else _request_type.from_document(
                        _decode_document(authorization_row["request_json"])
                    )
                )
            else:
                stored_request = load_authorization_request(request_binding)
            stored_outcome = None
            if stored_request is not None:
                outcome_row = authorization_row
                if outcome_row is None:
                    outcome_row = connection.execute(
                        "SELECT consumption_json FROM controller_authorizations "
                        "WHERE authorization_id=? AND request_json=?",
                        (
                            stored_request.authorization_id,
                            _canonical_document(stored_request.to_document()),
                        ),
                    ).fetchone()
                if outcome_row is None:
                    raise ValueError("controller authorization row missing")
                if outcome_row["consumption_json"] is not None:
                    outcome_document = _decode_document(outcome_row["consumption_json"])
                    if outcome_document.get("format") == (
                        "world-forge.private.ollama_v2_authorization_consumption"
                    ):
                        stored_outcome = _consumption_from_document(outcome_document)
                    elif outcome_document.get("format") == (
                        "world-forge.private.ollama_v2_authorization_rejection"
                    ):
                        stored_outcome = _rejection_from_document(outcome_document)
                    else:
                        raise ValueError("controller authorization outcome invalid")
            if type(snapshot) is not _snapshot_type or type(plan) is not _plan_type:
                raise ValueError("controller store returned inexact contracts")
            if rollback is not None and type(rollback) is not _rollback_type:
                raise ValueError("controller store returned inexact rollback")
            if stored_outcome is not None and type(stored_outcome) not in {
                _consumption_type,
                _rejection_type,
            }:
                raise ValueError("controller store returned inexact outcome")
            events = tuple(
                (
                    int(row["sequence"]),
                    _decode_document(row["event_json"]),
                    _operation_from_document(_decode_document(row["snapshot_json"])),
                )
                for row in event_rows
            )
            authorizations = []
            for row in authorization_rows:
                request = _request_type.from_document(
                    _decode_document(row["request_json"])
                )
                outcome = None
                if row["consumption_json"] is not None:
                    outcome_document = _decode_document(row["consumption_json"])
                    if outcome_document.get("format") == (
                        "world-forge.private.ollama_v2_authorization_consumption"
                    ):
                        outcome = _consumption_from_document(outcome_document)
                    elif outcome_document.get("format") == (
                        "world-forge.private.ollama_v2_authorization_rejection"
                    ):
                        outcome = _rejection_from_document(outcome_document)
                    else:
                        raise ValueError("controller authorization outcome invalid")
                authorizations.append(
                    (
                        request,
                        outcome,
                        row["state"],
                        row["request_json"],
                        row["consumption_json"],
                    )
                )
            proof = (
                tuple(
                    (
                        int(row["sequence"]),
                        row["event_json"],
                        row["snapshot_json"],
                    )
                    for row in event_rows
                ),
                tuple(
                    (
                        row["authorization_id"],
                        row["phase"],
                        row["effect_id"],
                        int(row["attempt"]),
                        row["request_json"],
                        row["consumption_json"],
                        row["state"],
                    )
                    for row in authorization_rows
                ),
                tuple(tuple(row) for row in attempt_rows),
            )
            connection.rollback()
            began_transaction = False
            return (
                snapshot,
                plan,
                rollback,
                stored_request,
                stored_outcome,
                events,
                tuple(authorizations),
                tuple(tuple(row) for row in attempt_rows),
                proof,
            )
        except BaseException as exc:
            if not isinstance(exc, (_programming_error, _read_busy_type)):
                state["poisoned"] = True
            if began_transaction:
                try:
                    connection.rollback()
                except BaseException:
                    pass
            if isinstance(exc, StudioError):
                raise
            raise StudioError(
                "invalid_state",
                "Ollama v2 controller store binding is unavailable",
            ) from exc

    (
        snapshot,
        plan,
        rollback,
        _stored_request,
        _stored_outcome,
        events,
        authorizations,
        attempts,
        initial_proof,
    ) = read_controller()

    def continuation_error() -> None:
        raise StudioError(
            "invalid_state",
            "Ollama v2 controller operation does not match mandate",
        )

    if (
        snapshot.operation_id != operation_id
        or snapshot.plan_hash != review.plan_hash
        or snapshot.ownership_token != review.ownership_token
        or plan != expected_plan
        or (review.phase == "apply" and rollback is not None)
        or (review.phase == "rollback" and rollback != expected_rollback)
    ):
        continuation_error()

    starting_events = tuple(
        event_snapshot
        for sequence, _event, event_snapshot in events
        if sequence == expected_starting.sequence
    )
    if len(starting_events) != 1 or starting_events[0] != expected_starting:
        continuation_error()
    after_start = tuple(
        (sequence, event, event_snapshot)
        for sequence, event, event_snapshot in events
        if sequence > expected_starting.sequence
    )
    state_offsets = {
        f"{review.phase}_pending": 0,
        f"{review.phase}_authorization_pending": 1,
        f"{review.phase}_authorization_claimed": 2,
        f"{review.phase}_authorization_consumed": 3,
        f"{review.phase}_dispatching": 4,
    }
    state_offset = state_offsets.get(snapshot.state)
    cursor = snapshot.apply_cursor if review.phase == "apply" else snapshot.rollback_cursor
    slot_ordinal = cursor - review.starting_cursor
    if (
        type(state_offset) is not int
        or not 0 <= slot_ordinal < len(review.effect_ids)
        or snapshot.generation - expected_starting.generation
        != slot_ordinal * 5 + state_offset
        or snapshot.sequence - expected_starting.sequence
        != slot_ordinal * 5 + state_offset
        or len(after_start) != slot_ordinal * 5 + state_offset
        or tuple(sequence for sequence, _event, _snapshot in after_start)
        != tuple(range(expected_starting.sequence + 1, snapshot.sequence + 1))
        or (
            (after_start and after_start[-1][2] != snapshot)
            or (not after_start and snapshot != expected_starting)
        )
        or (
            review.phase == "apply"
            and snapshot.rollback_cursor != expected_starting.rollback_cursor
        )
        or (
            review.phase == "rollback"
            and snapshot.apply_cursor != expected_starting.apply_cursor
        )
    ):
        continuation_error()

    authorization_by_id = {
        request.authorization_id: (request, outcome, state, request_json, outcome_json)
        for request, outcome, state, request_json, outcome_json in authorizations
    }
    used_authorization_ids: set[str] = set()
    used_attempt_ids: set[str] = set()
    controller_consumptions: list[
        tuple[int, AuthorizationRequest, AuthorizationConsumption, str]
    ] = []

    def validate_slot(
        ordinal: int,
        group: tuple[tuple[int, dict[str, object], OperationSnapshot], ...],
        pre_snapshot: OperationSnapshot,
        offset: int,
    ) -> tuple[AuthorizationRequest | None, AuthorizationConsumption | None]:
        expected_kinds = (
            "authorization.pending",
            "authorization.claimed",
            "authorization.consumed",
            "effect.dispatching",
            "effect.observed",
        )
        if (
            len(group) != offset
            or tuple(event[1].get("event_kind") for event in group)
            != expected_kinds[:offset]
        ):
            continuation_error()
        if offset == 0:
            return None, None
        pending_bindings = group[0][1].get("bindings")
        if type(pending_bindings) is not dict:
            continuation_error()
        authorization_id = pending_bindings.get("authorization_id")
        bound = authorization_by_id.get(authorization_id)
        if bound is None:
            continuation_error()
        request, outcome, authorization_state, _request_json, _outcome_json = bound
        used_authorization_ids.add(request.authorization_id)
        if (
            request.operation_id != operation_id
            or request.plan_hash != review.plan_hash
            or request.phase != review.phase
            or request.effect_id != review.effect_ids[ordinal]
            or request.attempt != review.starting_attempt + ordinal
            or request.expected_generation != pre_snapshot.generation
            or request.expected_sequence != pre_snapshot.sequence
            or request.expected_head_hash != pre_snapshot.event_head_hash
            or request.ownership_token != review.ownership_token
            or request.policy_content_hash != review.policy_content_hash
            or request.interpreter_binding_hash != review.interpreter_binding_hash
            or pending_bindings.get("request_hash") != request.content_hash
            or pending_bindings.get("effect_id") != request.effect_id
            or pending_bindings.get("phase") != request.phase
            or pending_bindings.get("attempt") != request.attempt
            or pending_bindings.get("ownership_token") != request.ownership_token
        ):
            continuation_error()
        for _sequence, event, _event_snapshot in group[: min(offset, 3)]:
            bindings = event.get("bindings")
            if (
                type(bindings) is not dict
                or bindings.get("authorization_id") != request.authorization_id
                or bindings.get("request_hash") != request.content_hash
                or bindings.get("effect_id") != request.effect_id
                or bindings.get("phase") != request.phase
                or bindings.get("attempt") != request.attempt
                or bindings.get("ownership_token") != request.ownership_token
            ):
                continuation_error()
        expected_authorization_state = (
            "pending" if offset == 1 else "claimed" if offset == 2 else "consumed"
        )
        if authorization_state != expected_authorization_state:
            continuation_error()
        consumption = None
        if offset < 3:
            if outcome is not None:
                continuation_error()
        else:
            if type(outcome) is not _consumption_type or not outcome.matches(request):
                continuation_error()
            consumption = outcome
            consumed_bindings = group[2][1].get("bindings")
            if (
                type(consumed_bindings) is not dict
                or consumed_bindings.get("consumption_id") != outcome.consumption_id
                or consumed_bindings.get("consumption_hash") != outcome.content_hash
                or consumed_bindings.get("authority_id") != outcome.authority_id
                or consumed_bindings.get("decision_id") != outcome.decision_id
            ):
                continuation_error()
            controller_consumptions.append(
                (ordinal, request, outcome, review.effect_hashes[ordinal])
            )
        if offset >= 4:
            dispatch_bindings = group[3][1].get("bindings")
            matching_attempts = tuple(
                attempt
                for attempt in attempts
                if attempt[4] == request.authorization_id
                and attempt[5] == request.content_hash
            )
            expected_attempt_outcome = "dispatching" if offset == 4 else "postcondition"
            if (
                type(dispatch_bindings) is not dict
                or dispatch_bindings.get("authorization_id") != request.authorization_id
                or dispatch_bindings.get("request_hash") != request.content_hash
                or dispatch_bindings.get("consumption_hash") != consumption.content_hash
                or dispatch_bindings.get("effect_id") != request.effect_id
                or dispatch_bindings.get("effect_hash") != review.effect_hashes[ordinal]
                or dispatch_bindings.get("phase") != request.phase
                or dispatch_bindings.get("attempt") != request.attempt
                or dispatch_bindings.get("ownership_token") != request.ownership_token
                or len(matching_attempts) != 1
                or matching_attempts[0][1] != request.phase
                or matching_attempts[0][2] != request.effect_id
                or matching_attempts[0][3] != request.attempt
                or matching_attempts[0][8] != expected_attempt_outcome
                or matching_attempts[0][9] != group[3][0]
                or (
                    offset == 4
                    and (
                        matching_attempts[0][7] is not None
                        or matching_attempts[0][10] is not None
                    )
                )
                or (
                    offset == 5
                    and (
                        matching_attempts[0][7] is None
                        or matching_attempts[0][10] != group[4][0]
                    )
                )
            ):
                continuation_error()
            attempt_id = matching_attempts[0][0]
            used_attempt_ids.add(attempt_id)
            if dispatch_bindings.get("attempt_id") != attempt_id:
                continuation_error()
        expected_states = (
            f"{review.phase}_authorization_pending",
            f"{review.phase}_authorization_claimed",
            f"{review.phase}_authorization_consumed",
            f"{review.phase}_dispatching",
        )
        for index, expected_state in enumerate(expected_states[: min(offset, 4)]):
            if group[index][2].state != expected_state:
                continuation_error()
        if offset == 5:
            observed_bindings = group[4][1].get("bindings")
            after_snapshot = group[4][2]
            expected_cursor = review.starting_cursor + ordinal + 1
            if (
                type(observed_bindings) is not dict
                or observed_bindings.get("authorization_id") != request.authorization_id
                or observed_bindings.get("request_hash") != request.content_hash
                or observed_bindings.get("consumption_hash") != consumption.content_hash
                or observed_bindings.get("effect_id") != request.effect_id
                or observed_bindings.get("effect_hash") != review.effect_hashes[ordinal]
                or observed_bindings.get("phase") != request.phase
                or observed_bindings.get("attempt") != request.attempt
                or observed_bindings.get("ownership_token") != request.ownership_token
                or observed_bindings.get("outcome") != "postcondition"
                or observed_bindings.get("attempt_id") != attempt_id
                or after_snapshot.state != f"{review.phase}_pending"
                or (
                    review.phase == "apply"
                    and after_snapshot.apply_cursor != expected_cursor
                )
                or (
                    review.phase == "rollback"
                    and after_snapshot.rollback_cursor != expected_cursor
                )
                or after_snapshot.next_attempt != review.starting_attempt + ordinal + 1
            ):
                continuation_error()
        return request, consumption

    for ordinal in range(slot_ordinal):
        first = ordinal * 5
        group = after_start[first : first + 5]
        pre_snapshot = expected_starting if ordinal == 0 else after_start[first - 1][2]
        validate_slot(ordinal, group, pre_snapshot, 5)

    current_first = slot_ordinal * 5
    current_group = after_start[current_first:]
    current_pre_snapshot = (
        expected_starting
        if slot_ordinal == 0
        else after_start[current_first - 1][2]
    )
    rehydration_request, rehydration_outcome = validate_slot(
        slot_ordinal,
        current_group,
        current_pre_snapshot,
        state_offset,
    )
    relevant_authorization_ids = {
        request.authorization_id
        for request, _outcome, _state, _request_json, _outcome_json in authorizations
        if request.phase == review.phase and request.attempt >= review.starting_attempt
    }
    relevant_attempt_ids = {
        attempt[0]
        for attempt in attempts
        if attempt[1] == review.phase and attempt[3] >= review.starting_attempt
    }
    if (
        relevant_authorization_ids != used_authorization_ids
        or relevant_attempt_ids != used_attempt_ids
        or (state_offset == 0 and snapshot.current_effect_id is not None)
        or (
            state_offset > 0
            and (
                rehydration_request is None
                or snapshot.current_effect_id != rehydration_request.effect_id
                or snapshot.current_authorization_hash
                != rehydration_request.content_hash
            )
        )
    ):
        continuation_error()
    continuation = {
        "controller_consumptions": tuple(controller_consumptions),
        "current_request": rehydration_request,
        "current_state": snapshot.state,
        "slot_ordinal": slot_ordinal,
    }

    def claim(
        port: object,
        request: AuthorizationRequest,
        *,
        resolve: bool,
    ) -> AuthorizationOutcome | None:
        if port is not state["port"] or type(request) is not _request_type:
            raise StudioError(
                "invalid_request",
                "Ollama v2 controller claim binding is invalid",
            )
        if state["attached"] is not True:
            raise StudioError(
                "invalid_state",
                "Ollama v2 authorization port is not attached",
            )
        (
            snapshot,
            plan,
            rollback,
            stored,
            stored_outcome,
            _events,
            _authorizations,
            _attempts,
            _proof,
        ) = read_controller(request)
        allowed_states = {
            f"{request.phase}_authorization_claimed",
            f"{request.phase}_authorization_consumed",
            "recovery_required",
        }
        claimed = snapshot.state == f"{request.phase}_authorization_claimed"
        consumed = snapshot.state == f"{request.phase}_authorization_consumed"
        rejected = snapshot.state == "recovery_required"
        if (
            snapshot.operation_id != operation_id
            or snapshot.plan_hash != review.plan_hash
            or snapshot.ownership_token != review.ownership_token
            or snapshot.state not in allowed_states
            or plan != expected_plan
            or (review.phase == "rollback" and rollback != expected_rollback)
            or (claimed and stored_outcome is not None)
            or (consumed and type(stored_outcome) is not _consumption_type)
            or (rejected and type(stored_outcome) is not _rejection_type)
            or (
                not rejected
                and (
                    snapshot.current_effect_id != request.effect_id
                    or snapshot.current_authorization_hash != request.content_hash
                )
            )
            or (
                rejected
                and snapshot.recovery_reason
                != f"authorization_{stored_outcome.reason}"
            )
        ):
            raise StudioError(
                "invalid_request",
                "Ollama v2 authorization request does not match controller claim",
            )
        if type(stored) is not _request_type or stored != request:
            raise StudioError(
                "invalid_request",
                "Ollama v2 authorization request does not match controller claim",
            )
        return stored_outcome

    def controller_attached(port: object, attached_store: object) -> None:
        if (
            port is not state["port"]
            or attached_store is not store
            or state["attached"] is not False
        ):
            raise StudioError(
                "invalid_state",
                "Ollama v2 authorization port attachment is invalid",
            )
        (
            attached_snapshot,
            attached_plan,
            attached_rollback,
            attached_request,
            attached_outcome,
            _attached_events,
            _attached_authorizations,
            _attached_attempts,
            attached_proof,
        ) = read_controller(
            None
            if rehydration_request is None
            else rehydration_request.content_hash
        )
        if (
            attached_snapshot != snapshot
            or attached_plan != plan
            or attached_rollback != rollback
            or attached_request != rehydration_request
            or attached_outcome != rehydration_outcome
            or attached_proof != initial_proof
        ):
            raise StudioError(
                "invalid_state",
                "Ollama v2 authorization port attachment is invalid",
            )
        state["attached"] = True

    def attach(port: object) -> None:
        if state["port"] is not None:
            raise StudioError(
                "invalid_state",
                "Ollama v2 controller claim binding was already attached",
            )
        state["port"] = port
        _register_port(port, store, controller_attached)

    return claim, attach, rehydration_request, rehydration_outcome, continuation


class StudioOllamaV2AuthorizationDomain:
    """One exact unlocked Director authority's durable mandate domain."""

    __slots__ = (
        "_authority",
        "_store",
        "_event_key",
        "_credential",
        "_connection",
        "_lock",
        "_epoch",
        "_epoch_check",
        "_clock_ms",
        "_require_authority_usable",
        "_poison_authority",
        "_poisoned",
        "_require_usable_call",
        "_poison_call",
        "_audit_call",
        "_read_call",
        "_write_call",
        "_row_call",
        "_append_event_call",
        "_state_digest_call",
        "_snapshot_from_row_call",
        "_validate_request_call",
        "_consume_bound_call",
        "_resolve_bound_call",
        "_review_call",
        "_build_review_call",
    )

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise ApprovalError("approval_authority_invalid")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise ApprovalError("approval_authority_invalid")

    def _require_usable(self) -> None:
        if self._poisoned or not self._epoch_check(self._authority, self._epoch):
            raise StudioError("invalid_state", "Ollama v2 authorization authority is unavailable")
        self._require_authority_usable()

    def _poison(self, _object_setattr=object.__setattr__) -> None:
        _object_setattr(self, "_poisoned", True)
        self._poison_authority()

    def build_review(
        self,
        starting_snapshot: object,
        plan: object,
        *,
        phase: object,
        rollback_plan: object = None,
    ) -> StudioOllamaV2AuthorizationReview:
        self._require_usable_call()
        return self._build_review_call(
            starting_snapshot, plan, phase=phase, rollback_plan=rollback_plan
        )

    def _audit(
        self,
        _verify_authenticated_human_decision_v6=_verify_authenticated_human_decision_v6,
        _verify_ollama_v2_authorization_v8=_verify_ollama_v2_authorization_v8,
        _canonical=_canonical,
        _decode=_decode,
        _event_mac=_event_mac,
        _review_from_document=StudioOllamaV2AuthorizationReview.from_document,
        _decision_from_document=StudioOllamaV2AuthorizationDecision.from_document,
        _request_from_document=AuthorizationRequest.from_document,
        _consumption_from_document=AuthorizationConsumption.from_document,
        _consumption_type=AuthorizationConsumption,
        _rejection_create=AuthorizationRejection.create,
        _rejection_from_document=AuthorizationRejection.from_document,
        _compare_digest=hmac.compare_digest,
        _credential_evidence_call=_credential_evidence,
        _credential_type=_CredentialEvidence,
        _sha256=hashlib.sha256,
        _same_credential_call=_same_credential,
        _canonical_timestamp=_canonical_utc_timestamp,
        _authority_id=_AUTHORITY_ID,
        _consumptions_table=_OLLAMA_AUTH_CONSUMPTIONS_TABLE,
        _credential_id=_CREDENTIAL_ID,
        _decisions_table=_OLLAMA_AUTH_DECISIONS_TABLE,
        _event_format=_EVENT_FORMAT,
        _events_table=_OLLAMA_AUTH_EVENTS_TABLE,
        _outcomes_table=_OLLAMA_AUTH_OUTCOMES_TABLE,
        _bytes_type=bytes,
        _dict_type=dict,
        _int_type=int,
        _len=len,
        _max_safe_integer=_MAX_SAFE_INTEGER,
        _str_type=str,
        _type=type,
        _zero_hash=_ZERO_HASH,
    ) -> tuple[int, str]:
        self._require_usable_call()
        if not self._connection.in_transaction:
            raise StudioError("invalid_state", "Ollama v2 authorization audit failed")
        try:
            _verify_authenticated_human_decision_v6(self._connection)
            _verify_ollama_v2_authorization_v8(self._connection)
            credential_rows = self._connection.execute(
                "SELECT credential_id, kdf_name, kdf_n, kdf_r, kdf_p, kdf_dklen, "
                "kdf_maxmem, salt, verifier, created_at FROM "
                "studio_authenticated_human_credentials"
            ).fetchall()
            observed_credential = (
                None
                if _len(credential_rows) != 1
                else _credential_evidence_call(credential_rows[0])
            )
            if (
                _type(self._credential) is not _credential_type
                or _type(observed_credential) is not _credential_type
                or not _same_credential_call(self._credential, observed_credential)
            ):
                raise ValueError("credential drift")
            projections: dict[str, dict[str, object]] = {}
            consumptions: dict[tuple[str, int], dict[str, object]] = {}
            outcomes: dict[tuple[str, int], dict[str, object]] = {}
            previous = _zero_hash
            expected_event_id = 1
            events = self._connection.execute(
                f"SELECT * FROM {_events_table} ORDER BY event_id"
            ).fetchall()
            for row in events:
                row_event_id = row["event_id"]
                row_generation = row["generation"]
                row_slot_ordinal = row["slot_ordinal"]
                if (
                    _type(row_event_id) is not _int_type
                    or not 1 <= row_event_id <= _max_safe_integer
                    or _type(row["credential_id"]) is not _str_type
                    or _type(row["mandate_id"]) is not _str_type
                    or _type(row_generation) is not _int_type
                    or not 0 <= row_generation <= 2
                    or _type(row["event_type"]) is not _str_type
                    or row["event_type"]
                    not in {"prepared", "decided", "revoked", "consumed", "rejected"}
                    or (
                        row_slot_ordinal is not None
                        and (
                            _type(row_slot_ordinal) is not _int_type
                            or not 0 <= row_slot_ordinal <= 31
                        )
                    )
                    or _type(row["content_json"]) is not _str_type
                    or _type(row["content_hash"]) is not _str_type
                    or _type(row["previous_hash"]) is not _str_type
                    or _type(row["mac"]) is not _bytes_type
                    or _len(row["mac"]) != 32
                    or _type(row["created_at"]) is not _str_type
                ):
                    raise ValueError("event row types")
                if row_event_id != expected_event_id or row["previous_hash"] != previous:
                    raise ValueError("event continuity")
                expected_event_id += 1
                document = _decode(row["content_json"])
                document_generation = document.get("generation")
                document_consumed_count = document.get("consumed_count")
                document_slot_ordinal = document.get("slot_ordinal")
                if (
                    _type(document.get("format")) is not _str_type
                    or _type(document.get("format_version")) is not _int_type
                    or document["format_version"] != 1
                    or _type(document.get("credential_id")) is not _str_type
                    or _type(document.get("authority_id")) is not _str_type
                    or _type(document.get("event_type")) is not _str_type
                    or _type(document.get("mandate_id")) is not _str_type
                    or _type(document_generation) is not _int_type
                    or not 0 <= document_generation <= 2
                    or _type(document.get("state")) is not _str_type
                    or _type(document_consumed_count) is not _int_type
                    or not 0 <= document_consumed_count <= 32
                    or (
                        document_slot_ordinal is not None
                        and (
                            _type(document_slot_ordinal) is not _int_type
                            or not 0 <= document_slot_ordinal <= 31
                        )
                    )
                    or _type(document.get("review")) is not _dict_type
                    or (
                        document.get("decision") is not None
                        and _type(document.get("decision")) is not _dict_type
                    )
                    or (
                        document.get("request") is not None
                        and _type(document.get("request")) is not _dict_type
                    )
                    or (
                        document.get("consumption") is not None
                        and _type(document.get("consumption")) is not _dict_type
                    )
                    or _type(document.get("previous_hash")) is not _str_type
                    or _type(document.get("created_at")) is not _str_type
                ):
                    raise ValueError("event document types")
                created_at = _canonical_timestamp(document["created_at"])
                if _canonical_timestamp(row["created_at"]) != created_at:
                    raise ValueError("event timestamp")
                content_hash = _sha256(_canonical(document)).hexdigest()
                if (
                    frozenset(document)
                    != frozenset(
                        {
                            "format",
                            "format_version",
                            "credential_id",
                            "authority_id",
                            "event_type",
                            "mandate_id",
                            "generation",
                            "state",
                            "consumed_count",
                            "slot_ordinal",
                            "review",
                            "decision",
                            "request",
                            "consumption",
                            "previous_hash",
                            "created_at",
                        }
                    )
                    or document.get("format") != _event_format
                    or content_hash != row["content_hash"]
                    or document.get("previous_hash") != previous
                    or created_at != row["created_at"]
                    or document.get("credential_id") != _credential_id
                    or document.get("authority_id") != _authority_id
                    or document.get("event_type") != row["event_type"]
                    or document.get("mandate_id") != row["mandate_id"]
                    or document_generation != row_generation
                    or document_slot_ordinal != row_slot_ordinal
                    or not _compare_digest(_event_mac(self._event_key, document), row["mac"])
                ):
                    raise ValueError("event integrity")
                review = _review_from_document(document["review"])
                decision_value = document["decision"]
                decision = (
                    None if decision_value is None else _decision_from_document(decision_value)
                )
                if review.mandate_id != row["mandate_id"] or (
                    decision is not None
                    and (
                        decision.mandate_id != review.mandate_id
                        or decision.review_hash != review.content_hash
                    )
                ):
                    raise ValueError("event identity")
                current = projections.get(review.mandate_id)
                event_type = row["event_type"]
                consumed_count = document_consumed_count
                state = document.get("state")
                slot_ordinal = row_slot_ordinal
                if event_type not in {"consumed", "rejected"} and (
                    slot_ordinal is not None
                    or document["request"] is not None
                    or document["consumption"] is not None
                ):
                    raise ValueError("event payload")
                if event_type == "prepared":
                    if (
                        current is not None
                        or decision is not None
                        or state != "prepared"
                        or consumed_count != 0
                        or row_generation != 0
                    ):
                        raise ValueError("prepared transition")
                elif event_type == "decided":
                    if (
                        current is None
                        or current["generation"] != 0
                        or current["review_hash"] != review.content_hash
                        or decision is None
                        or decision.review_hash != review.content_hash
                        or state != decision.outcome
                        or consumed_count != 0
                        or row_generation != 1
                    ):
                        raise ValueError("decision transition")
                elif event_type == "revoked":
                    if (
                        current is None
                        or current["generation"] != 1
                        or current["state"] != "approved"
                        or current["review_hash"] != review.content_hash
                        or decision is None
                        or current["decision_hash"] != decision.content_hash
                        or state != "revoked"
                        or consumed_count != current["consumed_count"]
                        or row_generation != 2
                    ):
                        raise ValueError("revoke transition")
                elif event_type == "consumed":
                    request = _request_from_document(document["request"])
                    consumption = _consumption_from_document(document["consumption"])
                    ordinal = slot_ordinal
                    if (
                        current is None
                        or current["generation"] != 1
                        or current["state"] != "approved"
                        or current["review_hash"] != review.content_hash
                        or decision is None
                        or current["decision_hash"] != decision.content_hash
                        or state != "approved"
                        or row_generation != 1
                        or type(ordinal) is not int
                        or ordinal != current["consumed_count"]
                        or consumed_count != ordinal + 1
                        or ordinal >= _len(review.effect_ids)
                        or request.effect_id != review.effect_ids[ordinal]
                        or consumption.authority_id != _authority_id
                        or consumption.decision_id != decision.decision_id
                        or not consumption.matches(request)
                    ):
                        raise ValueError("consume transition")
                    self._validate_request_call(
                        review,
                        request,
                        {"consumed_count": ordinal},
                    )
                    consumptions[(review.mandate_id, ordinal)] = {
                        "request_json": _canonical(request.to_document()).decode("utf-8"),
                        "consumption_json": _canonical(consumption.to_document()).decode("utf-8"),
                        "event_hash": content_hash,
                        "effect_id": review.effect_ids[ordinal],
                        "effect_hash": review.effect_hashes[ordinal],
                        "consumed_at": row["created_at"],
                    }
                    outcomes[(review.mandate_id, ordinal)] = {
                        "outcome_kind": "consumed",
                        "request": request,
                        "outcome": consumption,
                        "event_id": row_event_id,
                        "event_hash": content_hash,
                        "effect_id": review.effect_ids[ordinal],
                        "effect_hash": review.effect_hashes[ordinal],
                        "consumption_id": consumption.consumption_id,
                        "settled_at": row["created_at"],
                    }
                elif event_type == "rejected":
                    request = _request_from_document(document["request"])
                    ordinal = slot_ordinal
                    reason = state
                    if (
                        current is None
                        or decision is None
                        or decision.outcome != "approved"
                        or current["review_hash"] != review.content_hash
                        or current["decision_hash"] != decision.content_hash
                        or row_generation != 2
                        or type(ordinal) is not int
                        or ordinal != current["consumed_count"]
                        or consumed_count != ordinal
                        or ordinal >= _len(review.effect_ids)
                        or document["consumption"] is not None
                        or request.effect_id != review.effect_ids[ordinal]
                        or reason not in {"revoked", "expired"}
                        or (
                            reason == "revoked"
                            and (
                                current["state"] != "revoked"
                                or current["generation"] != 2
                            )
                        )
                        or (
                            reason == "expired"
                            and (
                                current["state"] != "approved"
                                or current["generation"] != 1
                            )
                        )
                    ):
                        raise ValueError("reject transition")
                    self._validate_request_call(
                        review,
                        request,
                        {"consumed_count": ordinal},
                    )
                    rejection = _rejection_create(
                        request,
                        authority_id=_authority_id,
                        mandate_id=review.mandate_id,
                        decision_id=decision.decision_id,
                        slot_ordinal=ordinal,
                        effect_hash=review.effect_hashes[ordinal],
                        reason=reason,
                        settlement_event_id=row_event_id,
                        settlement_event_hash=content_hash,
                    )
                    outcomes[(review.mandate_id, ordinal)] = {
                        "outcome_kind": "rejected",
                        "request": request,
                        "outcome": rejection,
                        "event_id": row_event_id,
                        "event_hash": content_hash,
                        "effect_id": review.effect_ids[ordinal],
                        "effect_hash": review.effect_hashes[ordinal],
                        "consumption_id": None,
                        "settled_at": row["created_at"],
                    }
                else:
                    raise ValueError("event type")
                projections[review.mandate_id] = {
                    "credential_id": _credential_id,
                    "operation_id": review.operation_id,
                    "phase": review.phase,
                    "plan_hash": review.plan_hash,
                    "rollback_plan_hash": review.rollback_plan_hash,
                    "starting_snapshot_hash": review.starting_snapshot_hash,
                    "review_hash": review.content_hash,
                    "review_json": _canonical(review.to_document()).decode("utf-8"),
                    "decision_hash": None if decision is None else decision.content_hash,
                    "decision_json": (
                        None
                        if decision is None
                        else _canonical(decision.to_document()).decode("utf-8")
                    ),
                    "state": state,
                    "generation": row_generation,
                    "slot_count": _len(review.effect_ids),
                    "consumed_count": consumed_count,
                    "last_event_hash": content_hash,
                    "updated_at": row["created_at"],
                }
                previous = content_hash
            rows = self._connection.execute(f"SELECT * FROM {_decisions_table}").fetchall()
            if _len(rows) != _len(projections):
                raise ValueError("projection count")
            for row in rows:
                if (
                    _type(row["mandate_id"]) is not _str_type
                    or _type(row["credential_id"]) is not _str_type
                    or _type(row["operation_id"]) is not _str_type
                    or _type(row["phase"]) is not _str_type
                    or _type(row["plan_hash"]) is not _str_type
                    or (
                        row["rollback_plan_hash"] is not None
                        and _type(row["rollback_plan_hash"]) is not _str_type
                    )
                    or _type(row["starting_snapshot_hash"]) is not _str_type
                    or _type(row["review_hash"]) is not _str_type
                    or _type(row["review_json"]) is not _str_type
                    or (
                        row["decision_hash"] is not None
                        and _type(row["decision_hash"]) is not _str_type
                    )
                    or (
                        row["decision_json"] is not None
                        and _type(row["decision_json"]) is not _str_type
                    )
                    or _type(row["state"]) is not _str_type
                    or _type(row["generation"]) is not _int_type
                    or not 0 <= row["generation"] <= 2
                    or _type(row["slot_count"]) is not _int_type
                    or not 1 <= row["slot_count"] <= 32
                    or _type(row["consumed_count"]) is not _int_type
                    or not 0 <= row["consumed_count"] <= row["slot_count"]
                    or _type(row["last_event_hash"]) is not _str_type
                    or _type(row["updated_at"]) is not _str_type
                ):
                    raise ValueError("projection row types")
                expected = projections.pop(row["mandate_id"])
                for key, value in expected.items():
                    if row[key] != value:
                        raise ValueError("projection mismatch")
            if projections:
                raise ValueError("projection missing")
            stored = self._connection.execute(f"SELECT * FROM {_consumptions_table}").fetchall()
            if _len(stored) != _len(consumptions):
                raise ValueError("consumption count")
            for row in stored:
                if (
                    _type(row["consumption_id"]) is not _str_type
                    or _type(row["mandate_id"]) is not _str_type
                    or _type(row["slot_ordinal"]) is not _int_type
                    or not 0 <= row["slot_ordinal"] <= 31
                    or _type(row["effect_id"]) is not _str_type
                    or _type(row["effect_hash"]) is not _str_type
                    or _type(row["authorization_id"]) is not _str_type
                    or _type(row["request_hash"]) is not _str_type
                    or _type(row["request_json"]) is not _str_type
                    or _type(row["consumption_hash"]) is not _str_type
                    or _type(row["consumption_json"]) is not _str_type
                    or _type(row["event_hash"]) is not _str_type
                    or _type(row["consumed_at"]) is not _str_type
                ):
                    raise ValueError("consumption row types")
                expected = consumptions.pop((row["mandate_id"], row["slot_ordinal"]))
                if (
                    row["request_json"] != expected["request_json"]
                    or row["consumption_json"] != expected["consumption_json"]
                    or row["event_hash"] != expected["event_hash"]
                    or row["effect_id"] != expected["effect_id"]
                    or row["effect_hash"] != expected["effect_hash"]
                    or row["consumed_at"] != expected["consumed_at"]
                ):
                    raise ValueError("consumption mismatch")
                request = _request_from_document(_decode(row["request_json"]))
                consumption = _consumption_from_document(_decode(row["consumption_json"]))
                if (
                    row["consumption_id"] != consumption.consumption_id
                    or row["effect_id"] != request.effect_id
                    or row["authorization_id"] != request.authorization_id
                    or row["request_hash"] != request.content_hash
                    or row["consumption_hash"] != consumption.content_hash
                ):
                    raise ValueError("consumption fields")
            if consumptions:
                raise ValueError("consumption missing")
            stored_outcomes = self._connection.execute(
                f"SELECT * FROM {_outcomes_table}"
            ).fetchall()
            if _len(stored_outcomes) != _len(outcomes):
                raise ValueError("outcome count")
            for row in stored_outcomes:
                if (
                    _type(row["outcome_id"]) is not _str_type
                    or _type(row["mandate_id"]) is not _str_type
                    or _type(row["outcome_kind"]) is not _str_type
                    or row["outcome_kind"] not in {"consumed", "rejected"}
                    or _type(row["slot_ordinal"]) is not _int_type
                    or not 0 <= row["slot_ordinal"] <= 31
                    or _type(row["effect_id"]) is not _str_type
                    or _type(row["effect_hash"]) is not _str_type
                    or _type(row["authorization_id"]) is not _str_type
                    or _type(row["request_hash"]) is not _str_type
                    or _type(row["request_json"]) is not _str_type
                    or _type(row["outcome_hash"]) is not _str_type
                    or _type(row["outcome_json"]) is not _str_type
                    or _type(row["event_id"]) is not _int_type
                    or not 1 <= row["event_id"] <= _max_safe_integer
                    or _type(row["event_hash"]) is not _str_type
                    or (
                        row["consumption_id"] is not None
                        and _type(row["consumption_id"]) is not _str_type
                    )
                    or _type(row["settled_at"]) is not _str_type
                ):
                    raise ValueError("outcome row types")
                expected = outcomes.pop((row["mandate_id"], row["slot_ordinal"]))
                request = _request_from_document(_decode(row["request_json"]))
                if row["outcome_kind"] == "consumed":
                    outcome = _consumption_from_document(_decode(row["outcome_json"]))
                else:
                    outcome = _rejection_from_document(_decode(row["outcome_json"]))
                if (
                    row["outcome_kind"] != expected["outcome_kind"]
                    or row["effect_id"] != expected["effect_id"]
                    or row["effect_hash"] != expected["effect_hash"]
                    or row["request_json"]
                    != _canonical(expected["request"].to_document()).decode("utf-8")
                    or request != expected["request"]
                    or row["outcome_json"]
                    != _canonical(expected["outcome"].to_document()).decode("utf-8")
                    or outcome != expected["outcome"]
                    or row["outcome_id"]
                    != (
                        outcome.consumption_id
                        if type(outcome) is _consumption_type
                        else outcome.rejection_id
                    )
                    or row["authorization_id"] != request.authorization_id
                    or row["request_hash"] != request.content_hash
                    or row["outcome_hash"] != outcome.content_hash
                    or row["event_id"] != expected["event_id"]
                    or row["event_hash"] != expected["event_hash"]
                    or row["consumption_id"] != expected["consumption_id"]
                    or row["settled_at"] != expected["settled_at"]
                    or not outcome.matches(request)
                ):
                    raise ValueError("outcome mismatch")
            if outcomes:
                raise ValueError("outcome missing")
            return expected_event_id - 1, previous
        except StudioError:
            raise
        except Exception as exc:
            raise StudioError("invalid_state", "Ollama v2 authorization audit failed") from exc

    def _read(self, operation):
        with self._lock:
            self._require_usable_call()
            try:
                self._connection.execute("BEGIN")
                self._audit_call()
                result = operation()
                self._connection.commit()
                return result
            except BaseException:
                try:
                    if self._connection.in_transaction:
                        self._connection.rollback()
                except BaseException:
                    self._poison_call()
                raise

    def _state_digest(
        self,
        _canonical=_canonical,
        _sha256=hashlib.sha256,
        _tables=(
            _OLLAMA_AUTH_DECISIONS_TABLE,
            _OLLAMA_AUTH_CONSUMPTIONS_TABLE,
            _OLLAMA_AUTH_EVENTS_TABLE,
            _OLLAMA_AUTH_OUTCOMES_TABLE,
        ),
    ) -> str:
        values: list[object] = []
        for table in _tables:
            rows = self._connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            values.append(
                [
                    [
                        {"bytes_sha256": _sha256(value).hexdigest(), "size": len(value)}
                        if type(value) is bytes
                        else value
                        for value in row
                    ]
                    for row in rows
                ]
            )
        return _sha256(_canonical(values)).hexdigest()

    def _write(self, operation, *, reconcile=None):
        with self._lock:
            self._require_usable_call()
            phase = "begin"
            pre_digest: str | None = None
            post_digest: str | None = None
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._audit_call()
                pre_digest = self._state_digest_call()
                result = operation()
                self._audit_call()
                post_digest = self._state_digest_call()
                phase = "commit"
                self._connection.commit()
                return result
            except BaseException as error:
                try:
                    if self._connection.in_transaction:
                        self._connection.rollback()
                except BaseException:
                    self._poison_call()
                    raise
                if phase != "commit" or pre_digest is None or post_digest is None:
                    raise
                try:
                    self._connection.execute("BEGIN")
                    self._audit_call()
                    observed = self._state_digest_call()
                except BaseException:
                    self._poison_call()
                    raise StudioError(
                        "invalid_state",
                        "Ollama v2 authorization outcome is indeterminate",
                    ) from error
                if observed == pre_digest:
                    self._connection.commit()
                    raise
                if observed == post_digest:
                    if reconcile is not None:
                        try:
                            result = reconcile()
                            self._connection.commit()
                            return result
                        except BaseException:
                            if self._connection.in_transaction:
                                self._connection.rollback()
                            self._poison_call()
                            raise StudioError(
                                "invalid_state",
                                "Ollama v2 authorization outcome is indeterminate",
                            ) from error
                    self._connection.commit()
                    raise StudioError(
                        "internal_error",
                        "Ollama v2 authorization commit result was lost",
                    ) from error
                self._connection.commit()
                self._poison_call()
                raise StudioError(
                    "invalid_state",
                    "Ollama v2 authorization outcome is indeterminate",
                ) from error

    def _row(self, mandate_id: str, _decisions_table=_OLLAMA_AUTH_DECISIONS_TABLE):
        return self._connection.execute(
            f"SELECT * FROM {_decisions_table} WHERE mandate_id = ?",
            (mandate_id,),
        ).fetchone()

    def _append_event(
        self,
        *,
        review: StudioOllamaV2AuthorizationReview,
        decision: StudioOllamaV2AuthorizationDecision | None,
        state: str,
        generation: int,
        consumed_count: int,
        event_type: str,
        slot_ordinal: int | None = None,
        request: AuthorizationRequest | None = None,
        consumption: AuthorizationConsumption | None = None,
        _utc_now=utc_now,
        _event_document=_event_document,
        _canonical=_canonical,
        _event_mac=_event_mac,
        _sha256=hashlib.sha256,
        _credential_id=_CREDENTIAL_ID,
        _events_table=_OLLAMA_AUTH_EVENTS_TABLE,
        _zero_hash=_ZERO_HASH,
    ) -> tuple[int, str, str]:
        head = self._connection.execute(
            f"SELECT content_hash FROM {_events_table} ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        previous = _zero_hash if head is None else head[0]
        created_at = _utc_now()
        document = _event_document(
            event_type=event_type,
            review=review,
            decision=decision,
            state=state,
            generation=generation,
            consumed_count=consumed_count,
            slot_ordinal=slot_ordinal,
            request=request,
            consumption=consumption,
            previous_hash=previous,
            created_at=created_at,
        )
        content_json = _canonical(document).decode("utf-8")
        content_hash = _sha256(content_json.encode("utf-8")).hexdigest()
        cursor = self._connection.execute(
            f"INSERT INTO {_events_table} "
            "(credential_id, mandate_id, generation, event_type, slot_ordinal, content_json, "
            "content_hash, previous_hash, mac, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _credential_id,
                review.mandate_id,
                generation,
                event_type,
                slot_ordinal,
                content_json,
                content_hash,
                previous,
                _event_mac(self._event_key, document),
                created_at,
            ),
        )
        event_id = cursor.lastrowid
        if type(event_id) is not int or event_id < 1:
            raise StudioError("invalid_state", "Ollama v2 authorization event is invalid")
        return event_id, content_hash, created_at

    def prepare(
        self,
        value: object,
        *,
        expected_generation: object,
        _canonical=_canonical,
        _credential_id=_CREDENTIAL_ID,
        _decisions_table=_OLLAMA_AUTH_DECISIONS_TABLE,
    ) -> StudioOllamaV2AuthorizationSnapshot:
        review = self._review_call(value)
        if type(expected_generation) is not int or expected_generation != 0:
            raise StudioError("conflict", "Ollama v2 authorization state changed")

        def operation():
            if self._row_call(review.mandate_id) is not None:
                raise StudioError("conflict", "Ollama v2 authorization state changed")
            _event_id, event_hash, updated_at = self._append_event_call(
                review=review,
                decision=None,
                state="prepared",
                generation=0,
                consumed_count=0,
                event_type="prepared",
            )
            self._connection.execute(
                f"INSERT INTO {_decisions_table} "
                "(mandate_id, credential_id, operation_id, phase, plan_hash, rollback_plan_hash, "
                "starting_snapshot_hash, review_hash, review_json, decision_hash, decision_json, "
                "state, generation, slot_count, consumed_count, last_event_hash, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 'prepared', 0, ?, 0, ?, ?)",
                (
                    review.mandate_id,
                    _credential_id,
                    review.operation_id,
                    review.phase,
                    review.plan_hash,
                    review.rollback_plan_hash,
                    review.starting_snapshot_hash,
                    review.content_hash,
                    _canonical(review.to_document()).decode("utf-8"),
                    len(review.effect_ids),
                    event_hash,
                    updated_at,
                ),
            )
            return self._snapshot_from_row_call(
                self._row_call(review.mandate_id),
                review,
                now_ms=self._clock_ms(),
            )

        return self._write_call(operation)

    def decide(
        self,
        value: object,
        *,
        outcome: object,
        expected_generation: object,
        expected_review_hash: object,
        expires_at_ms: object,
        _decision_create=StudioOllamaV2AuthorizationDecision.create,
        _contract_error=StudioOllamaV2AuthorizationContractError,
        _canonical=_canonical,
        _decisions_table=_OLLAMA_AUTH_DECISIONS_TABLE,
    ) -> StudioOllamaV2AuthorizationSnapshot:
        review = self._review_call(value)
        if (
            type(expected_generation) is not int
            or expected_generation != 0
            or expected_review_hash != review.content_hash
        ):
            raise StudioError("conflict", "Ollama v2 authorization state changed")
        now = self._clock_ms()
        if outcome == "approved" and (
            type(expires_at_ms) is not int
            or expires_at_ms <= now
            or expires_at_ms > 9_007_199_254_740_991
        ):
            raise StudioError("invalid_request", "Ollama v2 authorization expiry is invalid")
        if outcome == "denied" and expires_at_ms is not None:
            raise StudioError("invalid_request", "Ollama v2 authorization expiry is invalid")
        try:
            decision = _decision_create(review, outcome=outcome, expires_at_ms=expires_at_ms)
        except _contract_error as exc:
            raise StudioError(
                "invalid_request",
                "Ollama v2 authorization decision is invalid",
            ) from exc

        def operation():
            row = self._row_call(review.mandate_id)
            if (
                row is None
                or row["state"] != "prepared"
                or row["generation"] != 0
                or row["review_hash"] != review.content_hash
            ):
                raise StudioError("conflict", "Ollama v2 authorization state changed")
            _event_id, event_hash, updated_at = self._append_event_call(
                review=review,
                decision=decision,
                state=decision.outcome,
                generation=1,
                consumed_count=0,
                event_type="decided",
            )
            cursor = self._connection.execute(
                f"UPDATE {_decisions_table} SET decision_hash=?, decision_json=?, "
                "state=?, generation=1, last_event_hash=?, updated_at=? "
                "WHERE mandate_id=? AND state='prepared' AND generation=0 AND review_hash=?",
                (
                    decision.content_hash,
                    _canonical(decision.to_document()).decode("utf-8"),
                    decision.outcome,
                    event_hash,
                    updated_at,
                    review.mandate_id,
                    review.content_hash,
                ),
            )
            if cursor.rowcount != 1:
                raise StudioError("conflict", "Ollama v2 authorization state changed")
            return self._snapshot_from_row_call(
                self._row_call(review.mandate_id), review, now_ms=now
            )

        return self._write_call(operation)

    def revoke(
        self,
        value: object,
        *,
        expected_generation: object,
        expected_decision_hash: object,
        expected_consumed_slots: object,
        _decision_from_document=StudioOllamaV2AuthorizationDecision.from_document,
        _decode=_decode,
        _decisions_table=_OLLAMA_AUTH_DECISIONS_TABLE,
    ) -> StudioOllamaV2AuthorizationSnapshot:
        review = self._review_call(value)
        if (
            type(expected_generation) is not int
            or expected_generation != 1
            or type(expected_consumed_slots) is not int
            or not 0 <= expected_consumed_slots <= len(review.effect_ids)
        ):
            raise StudioError("conflict", "Ollama v2 authorization state changed")

        def operation():
            row = self._row_call(review.mandate_id)
            if (
                row is None
                or row["state"] != "approved"
                or row["generation"] != 1
                or row["decision_hash"] != expected_decision_hash
                or row["consumed_count"] != expected_consumed_slots
            ):
                raise StudioError("conflict", "Ollama v2 authorization state changed")
            decision = _decision_from_document(_decode(row["decision_json"]))
            _event_id, event_hash, updated_at = self._append_event_call(
                review=review,
                decision=decision,
                state="revoked",
                generation=2,
                consumed_count=row["consumed_count"],
                event_type="revoked",
            )
            cursor = self._connection.execute(
                f"UPDATE {_decisions_table} SET state='revoked', generation=2, "
                "last_event_hash=?, updated_at=? WHERE mandate_id=? AND state='approved' "
                "AND generation=1 AND decision_hash=? AND consumed_count=?",
                (
                    event_hash,
                    updated_at,
                    review.mandate_id,
                    expected_decision_hash,
                    expected_consumed_slots,
                ),
            )
            if cursor.rowcount != 1:
                raise StudioError("conflict", "Ollama v2 authorization state changed")
            return self._snapshot_from_row_call(
                self._row_call(review.mandate_id),
                review,
                now_ms=self._clock_ms(),
            )

        return self._write_call(operation)

    def _snapshot_from_row(
        self,
        row,
        review,
        *,
        now_ms: int,
        _canonical=_canonical,
        _decode=_decode,
        _decision_from_document=StudioOllamaV2AuthorizationDecision.from_document,
        _snapshot_type=StudioOllamaV2AuthorizationSnapshot,
    ):
        if (
            row is None
            or row["review_hash"] != review.content_hash
            or row["review_json"] != _canonical(review.to_document()).decode("utf-8")
        ):
            raise StudioError("conflict", "Ollama v2 authorization state changed")
        decision = (
            None
            if row["decision_json"] is None
            else _decision_from_document(_decode(row["decision_json"]))
        )
        consumed = row["consumed_count"]
        if row["state"] == "prepared":
            status = "prepared"
        elif row["state"] == "denied":
            status = "denied"
        elif row["state"] == "revoked":
            status = "revoked"
        elif row["state"] == "expired":
            status = "expired"
        elif decision is None or decision.expires_at_ms is None:
            raise StudioError("invalid_state", "Ollama v2 authorization audit failed")
        elif consumed == row["slot_count"]:
            status = "exhausted"
        elif now_ms >= decision.expires_at_ms:
            status = "expired"
        else:
            status = "consumable"
        return _snapshot_type(
            review=review,
            decision=decision,
            generation=row["generation"],
            durable_state=row["state"],
            consumed_slots=consumed,
            total_slots=row["slot_count"],
            status=status,
            next_effect_id=(review.effect_ids[consumed] if status == "consumable" else None),
        )

    def snapshot(self, value: object) -> StudioOllamaV2AuthorizationSnapshot:
        review = self._review_call(value)
        return self._read_call(
            lambda: self._snapshot_from_row_call(
                self._row_call(review.mandate_id), review, now_ms=self._clock_ms()
            )
        )

    def bind(
        self,
        value: object,
        *,
        controller_store: object,
        operation_id: object,
        expected_generation: object,
        expected_decision_hash: object,
        _claim_binding=_controller_claim_binding,
        _request_type=AuthorizationRequest,
        _consumption_from_document=AuthorizationConsumption.from_document,
        _rejection_from_document=AuthorizationRejection.from_document,
        _outcome_from_value=exact_authorization_outcome,
        _decode=_decode,
        _canonical=_canonical,
        _authority_id=_AUTHORITY_ID,
        _outcomes_table=_OLLAMA_AUTH_OUTCOMES_TABLE,
    ) -> StudioOllamaV2AuthorizationPort:
        review = self._review_call(value)
        (
            claim,
            attach,
            rehydration_request,
            rehydration_outcome,
            continuation,
        ) = _claim_binding(
            controller_store,
            operation_id,
            review,
        )

        def operation():
            snapshot = self._snapshot_from_row_call(
                self._row_call(review.mandate_id), review, now_ms=self._clock_ms()
            )
            controller_consumptions = continuation["controller_consumptions"]
            current_request = continuation["current_request"]
            current_state = continuation["current_state"]
            current_slot = continuation["slot_ordinal"]
            outcome_rows = self._connection.execute(
                f"SELECT * FROM {_outcomes_table} WHERE mandate_id=? "
                "ORDER BY slot_ordinal",
                (review.mandate_id,),
            ).fetchall()
            rows_by_slot = {row["slot_ordinal"]: row for row in outcome_rows}
            if len(rows_by_slot) != len(outcome_rows):
                raise StudioError(
                    "invalid_state",
                    "Ollama v2 authorization continuation is invalid",
                )
            controller_slots = {record[0] for record in controller_consumptions}
            if controller_slots != set(range(len(controller_consumptions))):
                raise StudioError(
                    "invalid_state",
                    "Ollama v2 authorization continuation is invalid",
                )

            def exact_studio_outcome(row, request, effect_hash):
                if row["outcome_kind"] == "consumed":
                    outcome = _consumption_from_document(_decode(row["outcome_json"]))
                elif row["outcome_kind"] == "rejected":
                    outcome = _rejection_from_document(_decode(row["outcome_json"]))
                else:
                    raise StudioError(
                        "invalid_state",
                        "Ollama v2 authorization continuation is invalid",
                    )
                if (
                    row["effect_id"] != request.effect_id
                    or row["effect_hash"] != effect_hash
                    or row["authorization_id"] != request.authorization_id
                    or row["request_hash"] != request.content_hash
                    or row["request_json"]
                    != _canonical(request.to_document()).decode("utf-8")
                    or row["outcome_hash"] != outcome.content_hash
                    or row["outcome_json"]
                    != _canonical(outcome.to_document()).decode("utf-8")
                    or snapshot.decision is None
                    or outcome.decision_id != snapshot.decision.decision_id
                    or outcome.authority_id != _authority_id
                    or not outcome.matches(request)
                ):
                    raise StudioError(
                        "invalid_state",
                        "Ollama v2 authorization continuation is invalid",
                    )
                return outcome

            for ordinal, request, controller_outcome, effect_hash in controller_consumptions:
                row = rows_by_slot.get(ordinal)
                if row is None:
                    raise StudioError(
                        "invalid_state",
                        "Ollama v2 authorization continuation is invalid",
                    )
                studio_outcome = exact_studio_outcome(row, request, effect_hash)
                if studio_outcome != controller_outcome:
                    raise StudioError(
                        "invalid_state",
                        "Ollama v2 authorization continuation is invalid",
                    )

            current_studio_outcome = None
            if current_state == f"{review.phase}_authorization_claimed":
                row = rows_by_slot.get(current_slot)
                if row is not None:
                    if type(current_request) is not _request_type:
                        raise StudioError(
                            "invalid_state",
                            "Ollama v2 authorization continuation is invalid",
                        )
                    current_studio_outcome = exact_studio_outcome(
                        row,
                        current_request,
                        review.effect_hashes[current_slot],
                    )
            allowed_outcome_slots = set(controller_slots)
            if current_studio_outcome is not None:
                allowed_outcome_slots.add(current_slot)
            if set(rows_by_slot) != allowed_outcome_slots:
                raise StudioError(
                    "invalid_state",
                    "Ollama v2 authorization continuation is invalid",
                )
            continuation_state_allowed = snapshot.status in {"consumable", "exhausted"}
            if snapshot.status in {"revoked", "expired"}:
                continuation_state_allowed = current_state in {
                    f"{review.phase}_pending",
                    f"{review.phase}_authorization_pending",
                    f"{review.phase}_authorization_claimed",
                    f"{review.phase}_authorization_consumed",
                    f"{review.phase}_dispatching",
                }
            if (
                type(expected_generation) is not int
                or snapshot.generation != expected_generation
                or snapshot.decision is None
                or snapshot.decision.content_hash != expected_decision_hash
                or not continuation_state_allowed
            ):
                raise StudioError(
                    "invalid_state",
                    "Ollama v2 authorization mandate is not approved",
                )
            if rehydration_request is not None:
                if type(rehydration_request) is not _request_type:
                    raise StudioError(
                        "invalid_state",
                        "Ollama v2 authorization rehydration is invalid",
                    )
                outcome_row = self._connection.execute(
                    f"SELECT * FROM {_outcomes_table} "
                    "WHERE mandate_id=? AND authorization_id=?",
                    (review.mandate_id, rehydration_request.authorization_id),
                ).fetchone()
                if outcome_row is None:
                    if rehydration_outcome is not None or snapshot.status in {
                        "prepared",
                        "denied",
                        "exhausted",
                    }:
                        raise StudioError(
                            "invalid_state",
                            "Ollama v2 authorization rehydration is invalid",
                        )
                    self._validate_request_call(
                        review,
                        rehydration_request,
                        self._row_call(review.mandate_id),
                    )
                else:
                    outcome = _outcome_from_value(
                        _consumption_from_document(
                            _decode(outcome_row["outcome_json"])
                        )
                        if outcome_row["outcome_kind"] == "consumed"
                        else _rejection_from_document(
                            _decode(outcome_row["outcome_json"])
                        )
                    )
                    if (
                        outcome_row["request_hash"] != rehydration_request.content_hash
                        or outcome_row["request_json"]
                        != _canonical(rehydration_request.to_document()).decode("utf-8")
                        or outcome_row["effect_id"] != rehydration_request.effect_id
                        or outcome_row["effect_hash"]
                        != review.effect_hashes[outcome_row["slot_ordinal"]]
                        or snapshot.decision is None
                        or outcome.decision_id != snapshot.decision.decision_id
                        or outcome.authority_id != _authority_id
                        or not outcome.matches(rehydration_request)
                        or (
                            rehydration_outcome is not None
                            and rehydration_outcome != outcome
                        )
                    ):
                        raise StudioError(
                            "invalid_state",
                            "Ollama v2 authorization rehydration is invalid",
                        )
            port = object.__new__(StudioOllamaV2AuthorizationPort)
            object.__setattr__(port, "_domain", self)
            object.__setattr__(port, "_review", review)
            object.__setattr__(port, "_decision_id", snapshot.decision.decision_id)
            object.__setattr__(port, "_consume_call", self._consume_bound_call)
            object.__setattr__(port, "_resolve_call", self._resolve_bound_call)
            object.__setattr__(port, "_controller_claim_call", claim)
            attach(port)
            return port

        return self._read_call(operation)

    def _validate_request(
        self,
        review,
        request,
        row,
        _exact_request=exact_authorization_request,
        _plan_from_document=ControllerPlan.from_document,
        _rollback_from_document=RollbackPlan.from_document,
        _snapshot_from_document=OperationSnapshot.from_document,
        _consumptions_table=_OLLAMA_AUTH_CONSUMPTIONS_TABLE,
        _decode=_decode,
        _request_from_document=AuthorizationRequest.from_document,
        _zero_hash=_ZERO_HASH,
    ):
        exact = _exact_request(request)
        ordinal = row["consumed_count"]
        if ordinal >= len(review.effect_ids):
            raise StudioError("invalid_state", "Ollama v2 authorization mandate is exhausted")
        plan = _plan_from_document(review.plan_document)
        effect = (
            plan.effects[review.starting_cursor + ordinal]
            if review.phase == "apply"
            else _rollback_from_document(review.rollback_plan_document).effects[
                review.starting_cursor + ordinal
            ]
        )
        starting = _snapshot_from_document(review.starting_snapshot_document)
        previous_request = None
        if ordinal > 0:
            previous_row = self._connection.execute(
                f"SELECT request_json FROM {_consumptions_table} "
                "WHERE mandate_id=? AND slot_ordinal=?",
                (review.mandate_id, ordinal - 1),
            ).fetchone()
            if previous_row is None:
                raise StudioError(
                    "invalid_state",
                    "Ollama v2 authorization consumption lineage is missing",
                )
            previous_request = _request_from_document(_decode(previous_row["request_json"]))
        if (
            exact.operation_id != review.operation_id
            or exact.plan_hash != review.plan_hash
            or exact.phase != review.phase
            or exact.ownership_token != review.ownership_token
            or exact.policy_content_hash != review.policy_content_hash
            or exact.interpreter_binding_hash != review.interpreter_binding_hash
            or exact.effect_id != review.effect_ids[ordinal]
            or effect.content_hash != review.effect_hashes[ordinal]
            or exact.attempt != review.starting_attempt + ordinal
            or exact.expected_generation != starting.generation + ordinal * 5
            or exact.expected_sequence != starting.sequence + ordinal * 5
            or (ordinal == 0 and exact.expected_head_hash != starting.event_head_hash)
            or (ordinal > 0 and exact.expected_head_hash == _zero_hash)
            or (
                previous_request is not None
                and exact.expected_head_hash == previous_request.expected_head_hash
            )
        ):
            raise StudioError(
                "invalid_request",
                "Ollama v2 authorization request does not match mandate",
            )
        return exact, effect, ordinal

    def _consume(
        self,
        review,
        decision_id,
        controller_claim,
        port,
        value,
        _exact_request=exact_authorization_request,
        _consumption_create=AuthorizationConsumption.create,
        _rejection_create=AuthorizationRejection.create,
        _outcome_from_document=_authorization_outcome_document,
        _consumption_type=AuthorizationConsumption,
        _canonical=_canonical,
        _decode=_decode,
        _replace=replace,
        _authority_id=_AUTHORITY_ID,
        _consumptions_table=_OLLAMA_AUTH_CONSUMPTIONS_TABLE,
        _decisions_table=_OLLAMA_AUTH_DECISIONS_TABLE,
        _outcomes_table=_OLLAMA_AUTH_OUTCOMES_TABLE,
    ):
        request = _exact_request(value)
        self._require_usable_call()
        controller_outcome = controller_claim(port, request, resolve=False)

        def load_existing():
            outcome_row = self._connection.execute(
                f"SELECT * FROM {_outcomes_table} WHERE mandate_id=? AND authorization_id=?",
                (review.mandate_id, request.authorization_id),
            ).fetchone()
            if outcome_row is None:
                if controller_outcome is not None:
                    raise StudioError(
                        "invalid_state",
                        "Ollama v2 controller outcome does not match Studio outcome",
                    )
                return None
            if (
                outcome_row["request_hash"] != request.content_hash
                or outcome_row["request_json"]
                != _canonical(request.to_document()).decode("utf-8")
            ):
                raise StudioError(
                    "conflict",
                    "Ollama v2 authorization request identity was reused",
                )
            outcome = _outcome_from_document(_decode(outcome_row["outcome_json"]))
            if (
                outcome.decision_id != decision_id
                or outcome.authority_id != _authority_id
                or not outcome.matches(request)
                or (
                    controller_outcome is not None
                    and controller_outcome != outcome
                )
            ):
                raise StudioError(
                    "invalid_state",
                    "Ollama v2 controller outcome does not match Studio outcome",
                )
            return _replace(outcome)

        def operation():
            existing = load_existing()
            if existing is not None:
                return existing
            row = self._row_call(review.mandate_id)
            now_ms = self._clock_ms()
            snapshot = self._snapshot_from_row_call(row, review, now_ms=now_ms)
            if (
                snapshot.decision is None
                or snapshot.decision.decision_id != decision_id
            ):
                raise StudioError(
                    "invalid_state",
                    "Ollama v2 authorization mandate is not consumable",
                )
            exact, effect, ordinal = self._validate_request_call(review, request, row)
            request_json = _canonical(exact.to_document()).decode("utf-8")
            rejection_reason = None
            if row["state"] == "revoked":
                rejection_reason = "revoked"
            elif row["state"] == "approved" and snapshot.status == "expired":
                rejection_reason = "expired"
            elif row["state"] != "approved" or snapshot.status != "consumable":
                raise StudioError(
                    "invalid_state",
                    "Ollama v2 authorization mandate is not consumable",
                )

            if rejection_reason is None:
                outcome = _consumption_create(
                    exact,
                    authority_id=_authority_id,
                    decision_id=decision_id,
                )
                event_id, event_hash, settled_at = self._append_event_call(
                    review=review,
                    decision=snapshot.decision,
                    state="approved",
                    generation=1,
                    consumed_count=ordinal + 1,
                    event_type="consumed",
                    slot_ordinal=ordinal,
                    request=exact,
                    consumption=outcome,
                )
                outcome_json = _canonical(outcome.to_document()).decode("utf-8")
                self._connection.execute(
                    f"INSERT INTO {_consumptions_table} "
                    "(consumption_id, mandate_id, slot_ordinal, effect_id, effect_hash, "
                    "authorization_id, request_hash, request_json, consumption_hash, "
                    "consumption_json, event_hash, consumed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        outcome.consumption_id,
                        review.mandate_id,
                        ordinal,
                        exact.effect_id,
                        effect.content_hash,
                        exact.authorization_id,
                        exact.content_hash,
                        request_json,
                        outcome.content_hash,
                        outcome_json,
                        event_hash,
                        settled_at,
                    ),
                )
                cursor = self._connection.execute(
                    f"UPDATE {_decisions_table} SET consumed_count=?, "
                    "last_event_hash=?, updated_at=? WHERE mandate_id=? AND state='approved' "
                    "AND generation=1 AND consumed_count=? AND decision_hash=?",
                    (
                        ordinal + 1,
                        event_hash,
                        settled_at,
                        review.mandate_id,
                        ordinal,
                        snapshot.decision.content_hash,
                    ),
                )
                outcome_kind = "consumed"
                consumption_id = outcome.consumption_id
            else:
                event_id, event_hash, settled_at = self._append_event_call(
                    review=review,
                    decision=snapshot.decision,
                    state=rejection_reason,
                    generation=2,
                    consumed_count=ordinal,
                    event_type="rejected",
                    slot_ordinal=ordinal,
                    request=exact,
                    consumption=None,
                )
                outcome = _rejection_create(
                    exact,
                    authority_id=_authority_id,
                    mandate_id=review.mandate_id,
                    decision_id=decision_id,
                    slot_ordinal=ordinal,
                    effect_hash=effect.content_hash,
                    reason=rejection_reason,
                    settlement_event_id=event_id,
                    settlement_event_hash=event_hash,
                )
                outcome_json = _canonical(outcome.to_document()).decode("utf-8")
                if rejection_reason == "expired":
                    cursor = self._connection.execute(
                        f"UPDATE {_decisions_table} SET state='expired', generation=2, "
                        "last_event_hash=?, updated_at=? WHERE mandate_id=? "
                        "AND state='approved' AND generation=1 AND consumed_count=? "
                        "AND decision_hash=?",
                        (
                            event_hash,
                            settled_at,
                            review.mandate_id,
                            ordinal,
                            snapshot.decision.content_hash,
                        ),
                    )
                else:
                    cursor = self._connection.execute(
                        f"UPDATE {_decisions_table} SET last_event_hash=?, updated_at=? "
                        "WHERE mandate_id=? AND state='revoked' AND generation=2 "
                        "AND consumed_count=? AND decision_hash=?",
                        (
                            event_hash,
                            settled_at,
                            review.mandate_id,
                            ordinal,
                            snapshot.decision.content_hash,
                        ),
                    )
                outcome_kind = "rejected"
                consumption_id = None
            if cursor.rowcount != 1:
                raise StudioError("conflict", "Ollama v2 authorization state changed")
            outcome_id = (
                outcome.consumption_id
                if type(outcome) is _consumption_type
                else outcome.rejection_id
            )
            self._connection.execute(
                f"INSERT INTO {_outcomes_table} "
                "(outcome_id, mandate_id, outcome_kind, slot_ordinal, effect_id, "
                "effect_hash, authorization_id, request_hash, request_json, outcome_hash, "
                "outcome_json, event_id, event_hash, consumption_id, settled_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    outcome_id,
                    review.mandate_id,
                    outcome_kind,
                    ordinal,
                    exact.effect_id,
                    effect.content_hash,
                    exact.authorization_id,
                    exact.content_hash,
                    request_json,
                    outcome.content_hash,
                    outcome_json,
                    event_id,
                    event_hash,
                    consumption_id,
                    settled_at,
                ),
            )
            return _replace(outcome)

        return self._write_call(operation, reconcile=load_existing)

    def _resolve(
        self,
        review,
        decision_id,
        controller_claim,
        port,
        value,
        _exact_request=exact_authorization_request,
        _outcome_from_document=_authorization_outcome_document,
        _decode=_decode,
        _canonical=_canonical,
        _replace=replace,
        _authority_id=_AUTHORITY_ID,
        _outcomes_table=_OLLAMA_AUTH_OUTCOMES_TABLE,
    ):
        request = _exact_request(value)
        self._require_usable_call()
        controller_outcome = controller_claim(port, request, resolve=True)

        def operation():
            row = self._connection.execute(
                f"SELECT * FROM {_outcomes_table} WHERE mandate_id=? AND authorization_id=?",
                (review.mandate_id, request.authorization_id),
            ).fetchone()
            if row is None:
                if controller_outcome is not None:
                    raise StudioError(
                        "invalid_state",
                        "Ollama v2 controller outcome does not match Studio outcome",
                    )
                return None
            if row["request_hash"] != request.content_hash or row["request_json"] != _canonical(
                request.to_document()
            ).decode("utf-8"):
                raise StudioError("conflict", "Ollama v2 authorization request identity was reused")
            outcome = _outcome_from_document(_decode(row["outcome_json"]))
            if (
                outcome.decision_id != decision_id
                or outcome.authority_id != _authority_id
                or not outcome.matches(request)
                or (
                    controller_outcome is not None
                    and controller_outcome != outcome
                )
            ):
                raise StudioError(
                    "invalid_state",
                    "Ollama v2 controller outcome does not match Studio outcome",
                )
            return _replace(outcome)

        return self._read_call(operation)


class StudioOllamaV2AuthorizationPort:
    """One exact decision-bound implementation of the controller's closed port."""

    __slots__ = (
        "__weakref__",
        "_domain",
        "_review",
        "_decision_id",
        "_consume_call",
        "_resolve_call",
        "_controller_claim_call",
        "_controller_attachment_marker",
    )

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise ApprovalError("approval_authority_invalid")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise ApprovalError("approval_authority_invalid")

    def consume(self, request: AuthorizationRequest) -> AuthorizationOutcome:
        return self._consume_call(
            self._review,
            self._decision_id,
            self._controller_claim_call,
            self,
            request,
        )

    def resolve(self, request: AuthorizationRequest) -> AuthorizationOutcome | None:
        return self._resolve_call(
            self._review,
            self._decision_id,
            self._controller_claim_call,
            self,
            request,
        )


def _construct_studio_ollama_v2_authorization_domain(
    authority: object,
    capsule: object,
    _consume_capsule=_consume_studio_ollama_v2_authorization_capsule,
    _domain_type=StudioOllamaV2AuthorizationDomain,
    _object_new=object.__new__,
) -> StudioOllamaV2AuthorizationDomain:
    if type(authority) is not StudioAuthenticatedHumanDecisionAuthority:
        raise ApprovalError("approval_authority_invalid")
    values = dict(_consume_capsule(authority, capsule))
    domain = _object_new(_domain_type)
    captured_methods = {
        "_require_usable_call": _domain_type._require_usable,
        "_poison_call": _domain_type._poison,
        "_audit_call": _domain_type._audit,
        "_read_call": _domain_type._read,
        "_write_call": _domain_type._write,
        "_row_call": _domain_type._row,
        "_append_event_call": _domain_type._append_event,
        "_state_digest_call": _domain_type._state_digest,
        "_snapshot_from_row_call": _domain_type._snapshot_from_row,
        "_validate_request_call": _domain_type._validate_request,
        "_consume_bound_call": _domain_type._consume,
        "_resolve_bound_call": _domain_type._resolve,
        "_review_call": _review,
        "_build_review_call": build_ollama_v2_authorization_review,
    }
    for name in _domain_type.__slots__:
        if name == "_poisoned":
            object.__setattr__(domain, name, False)
        elif name in {"_review_call", "_build_review_call"}:
            object.__setattr__(domain, name, captured_methods[name])
        elif name in captured_methods:
            object.__setattr__(
                domain,
                name,
                captured_methods[name].__get__(domain, _domain_type),
            )
        else:
            object.__setattr__(domain, name, values[name])
    with domain._lock:
        domain._connection.execute("BEGIN")
        try:
            domain._audit_call()
            domain._connection.commit()
        except BaseException:
            if domain._connection.in_transaction:
                domain._connection.rollback()
            raise
    return domain


__all__ = (
    "StudioOllamaV2AuthorizationDomain",
    "StudioOllamaV2AuthorizationPort",
)
