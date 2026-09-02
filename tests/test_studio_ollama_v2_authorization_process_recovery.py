from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import worldforge.studio.authenticated_human_decisions as human_authority_module
from worldforge.provider_evidence.ollama_v2_controller import OllamaV2Controller
from worldforge.provider_evidence.ollama_v2_controller_contracts import (
    CONTROLLER_GID,
    CONTROLLER_UID,
    MODEL_FINAL_ROOT,
    RELEASE_FINAL_ROOT,
    AuthorizationConsumption,
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
from worldforge.provider_evidence.ollama_v2_controller_store import (
    OllamaV2ControllerStore,
)
from worldforge.studio.director_control import StudioDirectorControl
from worldforge.studio.errors import StudioError
from worldforge.studio.storage import StudioStore


PASSPHRASE = "correct horse battery staple"
REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class _Case:
    name: str
    phase: str
    outcome: str
    reason: str | None
    fault: str
    exit_code: int


_CASES = {
    case.name: case
    for case in (
        _Case(
            "consumed_after_controller_claim_apply",
            "apply",
            "consumed",
            None,
            "controller_claim",
            81,
        ),
        _Case(
            "revoked_after_controller_claim_rollback",
            "rollback",
            "rejected",
            "revoked",
            "controller_claim",
            82,
        ),
        _Case(
            "consumed_before_studio_commit_rollback",
            "rollback",
            "consumed",
            None,
            "studio_pre",
            83,
        ),
        _Case(
            "expired_before_studio_commit_apply",
            "apply",
            "rejected",
            "expired",
            "studio_pre",
            84,
        ),
        _Case(
            "consumed_after_studio_commit_apply",
            "apply",
            "consumed",
            None,
            "studio_post",
            85,
        ),
        _Case(
            "expired_after_studio_commit_rollback",
            "rollback",
            "rejected",
            "expired",
            "studio_post",
            86,
        ),
        _Case(
            "consumed_after_controller_ack_rollback",
            "rollback",
            "consumed",
            None,
            "controller_ack",
            87,
        ),
        _Case(
            "revoked_after_controller_ack_apply",
            "apply",
            "rejected",
            "revoked",
            "controller_ack",
            88,
        ),
    )
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _emit(value: object) -> None:
    payload = _canonical(value) + b"\n"
    written = os.write(sys.stdout.fileno(), payload)
    if written != len(payload):
        raise RuntimeError("short child JSON write")


def _write_fsynced(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb", buffering=0) as stream:
        written = stream.write(payload)
        if written != len(payload):
            raise RuntimeError("short fixture write")
        os.fsync(stream.fileno())


def _write_json(path: Path, value: object) -> None:
    _write_fsynced(path, _canonical(value) + b"\n")


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise RuntimeError("fixture document is not an object")
    return value


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
            entries=(_entry("ollama", b"process-recovery-release"),),
        ),
        BoundedTreeManifest(
            purpose="model_final",
            root_path=MODEL_FINAL_ROOT,
            root_mode=0o555,
            uid=CONTROLLER_UID,
            gid=CONTROLLER_GID,
            sealed=True,
            entries=(_entry("model.gguf", b"process-recovery-model"),),
        ),
    )


def _read_effects(path: Path) -> tuple[HostEffect, ...]:
    if not path.exists():
        return ()
    effects = []
    for line in path.read_bytes().splitlines():
        if line:
            effects.append(HostEffect.from_document(json.loads(line)))
    return tuple(effects)


class _FileInspector:
    def __init__(self, plan: ControllerPlan, effects_path: Path) -> None:
        self._plan = plan
        self._effects_path = effects_path

    def _snapshot(self) -> HostSnapshot:
        snapshot = HostSnapshot.from_document(self._plan.initial_snapshot.to_document())
        for effect in _read_effects(self._effects_path):
            snapshot = project_effect(
                snapshot,
                self._plan,
                effect,
                self._plan.operation_id,
            )
        return snapshot

    def inspect(self, _policy_hash: str, _binding: InterpreterBinding) -> HostSnapshot:
        return self._snapshot()

    def observe(self, _operation_id: str, _plan_hash: str) -> HostSnapshot:
        return self._snapshot()


class _FileEffects:
    def __init__(self, effects_path: Path) -> None:
        self._effects_path = effects_path

    def _apply(self, effect: HostEffect) -> None:
        payload = _canonical(effect.to_document()) + b"\n"
        with self._effects_path.open("ab", buffering=0) as stream:
            written = stream.write(payload)
            if written != len(payload):
                raise RuntimeError("short effect marker write")
            os.fsync(stream.fileno())

    def create_managed_root(self, effect: HostEffect) -> None:
        self._apply(effect)

    def create_principal_exact(self, effect: HostEffect) -> None:
        self._apply(effect)

    def stage_release(self, effect: HostEffect, _manifest: BoundedTreeManifest) -> None:
        self._apply(effect)

    def publish_release(self, effect: HostEffect, _manifest: BoundedTreeManifest) -> None:
        self._apply(effect)

    def stage_model(self, effect: HostEffect, _manifest: BoundedTreeManifest) -> None:
        self._apply(effect)

    def publish_model(self, effect: HostEffect, _manifest: BoundedTreeManifest) -> None:
        self._apply(effect)

    def install_socket_unit(self, effect: HostEffect, _unit: bytes) -> None:
        self._apply(effect)

    def install_service_unit(self, effect: HostEffect, _unit: bytes) -> None:
        self._apply(effect)

    def reload_manager(self, effect: HostEffect) -> None:
        self._apply(effect)

    def remove_service_unit_exact(self, effect: HostEffect, _unit: bytes) -> None:
        self._apply(effect)

    def remove_socket_unit_exact(self, effect: HostEffect, _unit: bytes) -> None:
        self._apply(effect)

    def unpublish_model_exact(
        self,
        effect: HostEffect,
        _manifest: BoundedTreeManifest,
    ) -> None:
        self._apply(effect)

    def unstage_model_exact(
        self,
        effect: HostEffect,
        _manifest: BoundedTreeManifest,
    ) -> None:
        self._apply(effect)

    def unpublish_release_exact(
        self,
        effect: HostEffect,
        _manifest: BoundedTreeManifest,
    ) -> None:
        self._apply(effect)

    def unstage_release_exact(
        self,
        effect: HostEffect,
        _manifest: BoundedTreeManifest,
    ) -> None:
        self._apply(effect)

    def remove_principal_exact(self, effect: HostEffect) -> None:
        self._apply(effect)

    def remove_managed_root_exact(self, effect: HostEffect) -> None:
        self._apply(effect)


class _ExitAfterFileEffects(_FileEffects):
    def __init__(
        self,
        effects_path: Path,
        store: OllamaV2ControllerStore,
        operation_id: str,
        phase: str,
    ) -> None:
        super().__init__(effects_path)
        self._store = store
        self._operation_id = operation_id
        self._phase = phase

    def _apply(self, effect: HostEffect) -> None:
        super()._apply(effect)
        operation = self._store.load_operation(self._operation_id)
        _emit(
            {
                "bound_from_state": f"{self._phase}_authorization_consumed",
                "effect_id": effect.effect_id,
                "effect_marker_count": _target_effect_count(
                    self._effects_path,
                    effect.effect_id,
                ),
                "state": operation.state,
            }
        )
        os._exit(93)


class _BootstrapAuthorization:
    def __init__(self) -> None:
        self._consumptions: dict[str, AuthorizationConsumption] = {}

    def consume(self, request):
        consumption = AuthorizationConsumption.create(
            request,
            authority_id="process-recovery-bootstrap",
            decision_id="process-recovery-bootstrap",
        )
        self._consumptions[request.authorization_id] = consumption
        return consumption

    def resolve(self, request):
        return self._consumptions.get(request.authorization_id)


class _StudioCommitCrashProxy:
    def __init__(self, connection: sqlite3.Connection, context: dict[str, object]) -> None:
        self._connection = connection
        self._context = context

    def __getattr__(self, name: str):
        return getattr(self._connection, name)

    def commit(self) -> None:
        context = self._context
        if context["armed"] and context["case"].fault == "studio_pre":
            if _studio_outcomes_visible(self._connection, context) == 1:
                _crash_now(context, self._connection)
        self._connection.commit()
        if context["armed"] and context["case"].fault == "studio_post":
            if _studio_outcomes_visible(self._connection, context) == 1:
                _crash_now(context, self._connection)

    def rollback(self) -> None:
        self._connection.rollback()


def _clock_path(root: Path) -> Path:
    return root / "clock-ms.txt"


def _clock_ms(root: Path) -> int:
    return int(_clock_path(root).read_text(encoding="ascii"))


def _studio_outcomes_visible(
    connection: sqlite3.Connection,
    context: dict[str, object],
) -> int:
    row = connection.execute(
        "SELECT count(*) FROM studio_ollama_v2_authorization_outcomes "
        "WHERE mandate_id=? AND effect_id=?",
        (context["mandate_id"], context["target_effect_id"]),
    ).fetchone()
    return int(row[0])


def _target_event_kinds(
    store: OllamaV2ControllerStore,
    *,
    operation_id: str,
    phase: str,
    target_effect_id: str,
) -> list[str]:
    kinds = []
    for event in store.event_documents(operation_id):
        bindings = event.get("bindings")
        if (
            type(bindings) is dict
            and bindings.get("phase") == phase
            and bindings.get("effect_id") == target_effect_id
        ):
            kinds.append(str(event["event_kind"]))
    return kinds


def _target_effect_count(path: Path, target_effect_id: str) -> int:
    return sum(effect.effect_id == target_effect_id for effect in _read_effects(path))


def _crash_now(
    context: dict[str, object],
    studio_connection: sqlite3.Connection,
) -> None:
    case = context["case"]
    store = context["controller_store"]
    operation = store.load_operation(context["operation_id"])
    event_kinds = _target_event_kinds(
        store,
        operation_id=context["operation_id"],
        phase=case.phase,
        target_effect_id=context["target_effect_id"],
    )
    payload = {
        "case": case.name,
        "controller_state": operation.state,
        "cutpoint": case.fault,
        "dispatch_events_before_crash": event_kinds.count("effect.dispatching"),
        "exit_code": case.exit_code,
        "phase": case.phase,
        "studio_outcomes_visible": _studio_outcomes_visible(
            studio_connection,
            context,
        ),
        "studio_transaction_active": bool(studio_connection.in_transaction),
        "target_effect_count_before_crash": _target_effect_count(
            context["effects_path"],
            context["target_effect_id"],
        ),
        "target_event_kinds": event_kinds,
    }
    _emit(payload)
    os._exit(case.exit_code)


def _controller_commit_wrapper(context: dict[str, object]):
    original = OllamaV2ControllerStore._commit

    def wrapped(store: OllamaV2ControllerStore) -> None:
        original(store)
        if not context["armed"] or store is not context.get("controller_store"):
            return
        case = context["case"]
        if case.fault not in {"controller_claim", "controller_ack"}:
            return
        operation = store.load_operation(context["operation_id"])
        if case.fault == "controller_claim":
            expected_state = f"{case.phase}_authorization_claimed"
        elif case.outcome == "consumed":
            expected_state = f"{case.phase}_authorization_consumed"
        else:
            expected_state = "recovery_required"
        if operation.state == expected_state:
            _crash_now(context, context["studio_connection"])

    return wrapped


def _build_operation(
    case: _Case,
    store: OllamaV2ControllerStore,
    plan: ControllerPlan,
    inspector: _FileInspector,
    effects: _FileEffects,
) -> OperationSnapshot:
    controller = OllamaV2Controller(
        store,
        inspector,
        _BootstrapAuthorization(),
        effects,
    )
    operation = controller.create_operation(
        plan,
        operation_id=plan.operation_id,
        idempotency_key=f"create-{case.name}",
    )
    if case.phase == "rollback":
        operation = controller.advance_apply(operation)
        if operation.state != "apply_pending" or operation.apply_cursor != 1:
            raise RuntimeError("rollback fixture did not apply exactly one setup effect")
        operation = controller.prepare_rollback(operation)
        if operation.state != "rollback_pending":
            raise RuntimeError("rollback fixture was not prepared")
    return operation


def _run_crash_child(case: _Case, root: Path) -> None:
    effects_path = root / "effects.jsonl"
    _write_fsynced(_clock_path(root), b"1000\n")
    context: dict[str, object] = {
        "armed": False,
        "case": case,
        "effects_path": effects_path,
    }
    controller_patch = mock.patch.object(
        OllamaV2ControllerStore,
        "_commit",
        new=_controller_commit_wrapper(context),
    )
    patch_controller = case.fault in {"controller_claim", "controller_ack"}
    if patch_controller:
        controller_patch.start()
    try:
        human_authority_module._director_clock_ms = lambda: _clock_ms(root)
        studio = StudioStore(root / "studio")
        initial_control = StudioDirectorControl(studio)
        initial_control.enroll(passphrase=PASSPHRASE)
        initial_control.lock()
        raw_connection = studio._authenticated_human_decision_connection_instance
        if raw_connection is None:
            raise RuntimeError("Studio authority connection is unavailable")
        proxy = _StudioCommitCrashProxy(raw_connection, context)
        studio._authenticated_human_decision_connection_instance = proxy
        control = StudioDirectorControl(studio)
        control.unlock(passphrase=PASSPHRASE)
        store = OllamaV2ControllerStore(root / "controller.sqlite3")
        context["controller_store"] = store
        context["studio_connection"] = raw_connection

        release, model = _manifests()
        plan = build_controller_plan(
            make_empty_host_snapshot(f"snapshot-{case.name}", observed_generation=0),
            release,
            model,
            operation_id=f"operation-{case.name}",
        )
        inspector = _FileInspector(plan, effects_path)
        effects = _FileEffects(effects_path)
        operation = _build_operation(case, store, plan, inspector, effects)
        rollback = store.load_rollback_plan(operation.operation_id)
        target_effect = (
            plan.effects[operation.apply_cursor]
            if case.phase == "apply"
            else rollback.effects[operation.rollback_cursor]
        )
        review = control.build_ollama_v2_authorization_review(
            operation,
            plan,
            rollback_plan=rollback,
            phase=case.phase,
        )
        prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
        approved = control.approve_ollama_v2_authorization(
            review,
            expected_generation=0,
            expected_review_hash=prepared["review"]["content_hash"],
            expires_at_ms=2000 if case.reason == "expired" else 9_007_199_254_740_991,
        )
        context.update(
            {
                "mandate_id": review["mandate_id"],
                "operation_id": operation.operation_id,
                "target_effect_id": target_effect.effect_id,
            }
        )
        _write_json(
            root / "metadata.json",
            {
                "approved": approved,
                "case": case.name,
                "operation_id": operation.operation_id,
                "plan": plan.to_document(),
                "review": review,
                "target_effect_hash": target_effect.content_hash,
                "target_effect_id": target_effect.effect_id,
            },
        )
        port = control.bind_ollama_v2_authorization(
            review,
            controller_store=store,
            operation_id=operation.operation_id,
            expected_generation=1,
            expected_decision_hash=approved["decision"]["content_hash"],
        )
        controller = OllamaV2Controller(store, inspector, port, effects)
        if case.reason == "revoked":
            control.revoke_ollama_v2_authorization(
                review,
                expected_generation=1,
                expected_decision_hash=approved["decision"]["content_hash"],
                expected_consumed_slots=0,
            )
        elif case.reason == "expired":
            _write_fsynced(_clock_path(root), b"3000\n")
        context["armed"] = True
        if case.phase == "apply":
            controller.advance_apply(operation)
        else:
            controller.advance_rollback(operation)
        raise RuntimeError("crash cutpoint was not reached")
    finally:
        if patch_controller:
            controller_patch.stop()


def _normalize_row_value(value: object) -> object:
    if type(value) is bytes:
        return {"bytes_hex": value.hex()}
    if value is None or type(value) in {str, int, float}:
        return value
    raise RuntimeError(f"unsupported SQLite fixture value: {type(value)!r}")


def _logical_rows(
    connection: sqlite3.Connection,
    table_names: tuple[str, ...],
) -> dict[str, list[list[object]]]:
    rows_by_table: dict[str, list[list[object]]] = {}
    for table in table_names:
        rows = [
            [_normalize_row_value(value) for value in row]
            for row in connection.execute(f"SELECT * FROM {table}").fetchall()
        ]
        rows.sort(key=_canonical)
        rows_by_table[table] = rows
    return rows_by_table


def _probe_independent_lock(path: Path) -> bool:
    connection = sqlite3.connect(path, isolation_level=None, timeout=2.0)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.rollback()
        return True
    finally:
        connection.close()


def _audit_summary(
    case: _Case,
    root: Path,
    metadata: dict[str, object],
    studio: StudioStore,
    control: StudioDirectorControl,
    store: OllamaV2ControllerStore,
) -> dict[str, object]:
    operation_id = metadata["operation_id"]
    target_effect_id = metadata["target_effect_id"]
    review = metadata["review"]
    snapshot = control.inspect_ollama_v2_authorization(review)
    operation = store.load_operation(operation_id)
    target_events = _target_event_kinds(
        store,
        operation_id=operation_id,
        phase=case.phase,
        target_effect_id=target_effect_id,
    )
    controller_row = store._connection.execute(
        "SELECT authorization_id, request_json, consumption_json, state "
        "FROM controller_authorizations WHERE operation_id=? AND phase=? AND effect_id=?",
        (operation_id, case.phase, target_effect_id),
    ).fetchone()
    if controller_row is None:
        raise RuntimeError("target controller authorization is missing")
    outcome_rows = studio.connection.execute(
        "SELECT outcome_kind, outcome_json, outcome_hash, consumption_id, "
        "authorization_id, request_hash FROM "
        "studio_ollama_v2_authorization_outcomes WHERE mandate_id=? AND effect_id=?",
        (review["mandate_id"], target_effect_id),
    ).fetchall()
    consumption_rows = studio.connection.execute(
        "SELECT consumption_id, authorization_id, request_hash, consumption_hash, "
        "consumption_json FROM studio_ollama_v2_authorization_consumptions "
        "WHERE mandate_id=? AND effect_id=?",
        (review["mandate_id"], target_effect_id),
    ).fetchall()
    studio_outcome = json.loads(outcome_rows[0]["outcome_json"]) if len(outcome_rows) == 1 else None
    controller_outcome = (
        json.loads(controller_row["consumption_json"])
        if controller_row["consumption_json"] is not None
        else None
    )
    decision_row = studio.connection.execute(
        "SELECT state, generation, consumed_count FROM "
        "studio_ollama_v2_authorization_decisions WHERE mandate_id=?",
        (review["mandate_id"],),
    ).fetchone()
    effect_documents = [effect.to_document() for effect in _read_effects(root / "effects.jsonl")]
    consumption_projection_equal = False
    if len(outcome_rows) == 1:
        outcome_row = outcome_rows[0]
        if outcome_row["outcome_kind"] == "consumed" and len(consumption_rows) == 1:
            consumption_row = consumption_rows[0]
            consumption_projection_equal = (
                outcome_row["consumption_id"] == consumption_row["consumption_id"]
                and outcome_row["authorization_id"] == consumption_row["authorization_id"]
                and outcome_row["request_hash"] == consumption_row["request_hash"]
                and outcome_row["outcome_hash"] == consumption_row["consumption_hash"]
                and outcome_row["outcome_json"] == consumption_row["consumption_json"]
            )
        elif outcome_row["outcome_kind"] == "rejected":
            consumption_projection_equal = (
                outcome_row["consumption_id"] is None and not consumption_rows
            )
    controller_tables = tuple(
        row[0]
        for row in store._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name LIKE 'controller_%' ORDER BY name"
        ).fetchall()
    )
    studio_tables = (
        "studio_ollama_v2_authorization_decisions",
        "studio_ollama_v2_authorization_consumptions",
        "studio_ollama_v2_authorization_events",
        "studio_ollama_v2_authorization_outcomes",
    )
    stable_state = {
        "controller_events": list(store.event_documents(operation_id)),
        "controller_rows": _logical_rows(store._connection, controller_tables),
        "effects": effect_documents,
        "operation": operation.to_document(),
        "studio_rows": _logical_rows(studio.connection, studio_tables),
    }
    studio_lock_released = _probe_independent_lock(studio.database_path)
    controller_lock_released = _probe_independent_lock(root / "controller.sqlite3")
    return {
        "case": case.name,
        "controller_authorization_state": controller_row["state"],
        "controller_event_kinds": target_events,
        "controller_lock_released": controller_lock_released,
        "controller_state": operation.state,
        "consumption_projection_equal": consumption_projection_equal,
        "decision_consumed_count": int(decision_row["consumed_count"]),
        "decision_generation": int(decision_row["generation"]),
        "decision_state": decision_row["state"],
        "dispatch_attempt_count": int(
            store._connection.execute(
                "SELECT count(*) FROM controller_effect_attempts "
                "WHERE operation_id=? AND phase=? AND effect_id=?",
                (operation_id, case.phase, target_effect_id),
            ).fetchone()[0]
        ),
        "lease_count": int(
            store._connection.execute(
                "SELECT count(*) FROM controller_host_scope_leases WHERE operation_id=?",
                (operation_id,),
            ).fetchone()[0]
        ),
        "outcome_documents_equal": controller_outcome == studio_outcome,
        "outcome_kind": outcome_rows[0]["outcome_kind"] if len(outcome_rows) == 1 else None,
        "state_fingerprint": hashlib.sha256(_canonical(stable_state)).hexdigest(),
        "studio_consumption_count": int(
            studio.connection.execute(
                "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions "
                "WHERE mandate_id=? AND effect_id=?",
                (review["mandate_id"], target_effect_id),
            ).fetchone()[0]
        ),
        "studio_lock_released": studio_lock_released,
        "studio_outcome": studio_outcome,
        "studio_outcome_count": len(outcome_rows),
        "studio_rejected_event_count": int(
            studio.connection.execute(
                "SELECT count(*) FROM studio_ollama_v2_authorization_events "
                "WHERE mandate_id=? AND event_type='rejected' AND slot_ordinal IS NOT NULL",
                (review["mandate_id"],),
            ).fetchone()[0]
        ),
        "studio_status": snapshot["status"],
        "target_effect_count": _target_effect_count(
            root / "effects.jsonl",
            target_effect_id,
        ),
    }


def _run_recovery_or_audit_child(case: _Case, root: Path, role: str) -> None:
    metadata = _read_json(root / "metadata.json")
    human_authority_module._director_clock_ms = lambda: _clock_ms(root)
    with (
        StudioStore(root / "studio") as studio,
        OllamaV2ControllerStore(root / "controller.sqlite3") as store,
    ):
        control = StudioDirectorControl(studio)
        control.unlock(passphrase=PASSPHRASE)
        operation = store.load_operation(metadata["operation_id"])
        resume_action = "audit_only"
        if role == "recovery" and operation.state != "recovery_required":
            decision_generation = int(
                studio.connection.execute(
                    "SELECT generation FROM studio_ollama_v2_authorization_decisions "
                    "WHERE mandate_id=?",
                    (metadata["review"]["mandate_id"],),
                ).fetchone()[0]
            )
            port = control.bind_ollama_v2_authorization(
                metadata["review"],
                controller_store=store,
                operation_id=metadata["operation_id"],
                expected_generation=decision_generation,
                expected_decision_hash=metadata["approved"]["decision"]["content_hash"],
            )
            plan = ControllerPlan.from_document(metadata["plan"])
            controller = OllamaV2Controller(
                store,
                _FileInspector(plan, root / "effects.jsonl"),
                port,
                _FileEffects(root / "effects.jsonl"),
            )
            if case.phase == "apply":
                controller.advance_apply(operation)
                resume_action = "advance_apply_once"
            else:
                controller.advance_rollback(operation)
                resume_action = "advance_rollback_once"
        elif role == "recovery":
            store.load_operation(metadata["operation_id"])
            resume_action = "terminal_recovery_audit_once"
        summary = _audit_summary(case, root, metadata, studio, control, store)
        summary["role"] = role
        summary["resume_action"] = resume_action
        control.close()
    _emit(summary)


def _run_denied_child(root: Path) -> None:
    effects_path = root / "effects.jsonl"
    _write_fsynced(_clock_path(root), b"1000\n")
    human_authority_module._director_clock_ms = lambda: _clock_ms(root)
    with (
        StudioStore(root / "studio") as studio,
        OllamaV2ControllerStore(root / "controller.sqlite3") as store,
    ):
        control = StudioDirectorControl(studio)
        control.enroll(passphrase=PASSPHRASE)
        release, model = _manifests()
        plan = build_controller_plan(
            make_empty_host_snapshot("snapshot-denied-process", observed_generation=0),
            release,
            model,
            operation_id="operation-denied-process",
        )
        controller = OllamaV2Controller(
            store,
            _FileInspector(plan, effects_path),
            _BootstrapAuthorization(),
            _FileEffects(effects_path),
        )
        operation = controller.create_operation(
            plan,
            operation_id=plan.operation_id,
            idempotency_key="create-denied-process",
        )
        review = control.build_ollama_v2_authorization_review(operation, plan, phase="apply")
        prepared = control.prepare_ollama_v2_authorization(review, expected_generation=0)
        denied = control.deny_ollama_v2_authorization(
            review,
            expected_generation=0,
            expected_review_hash=prepared["review"]["content_hash"],
        )
        rejection = None
        try:
            control.bind_ollama_v2_authorization(
                review,
                controller_store=store,
                operation_id=operation.operation_id,
                expected_generation=1,
                expected_decision_hash=denied["decision"]["content_hash"],
            )
        except StudioError as exc:
            rejection = exc.code
        payload = {
            "authorization_rows": int(
                store._connection.execute(
                    "SELECT count(*) FROM controller_authorizations"
                ).fetchone()[0]
            ),
            "bind_error": rejection,
            "controller_events": [
                event["event_kind"] for event in store.event_documents(operation.operation_id)
            ],
            "controller_state": store.load_operation(operation.operation_id).state,
            "effect_count": len(_read_effects(effects_path)),
            "studio_consumptions": int(
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_consumptions"
                ).fetchone()[0]
            ),
            "studio_outcomes": int(
                studio.connection.execute(
                    "SELECT count(*) FROM studio_ollama_v2_authorization_outcomes"
                ).fetchone()[0]
            ),
        }
        control.close()
    _emit(payload)


def _run_ladder_setup_child(phase: str, root: Path) -> None:
    if phase not in {"apply", "rollback"}:
        raise RuntimeError("invalid ladder phase")
    effects_path = root / "effects.jsonl"
    _write_fsynced(_clock_path(root), b"1000\n")
    human_authority_module._director_clock_ms = lambda: _clock_ms(root)
    with (
        StudioStore(root / "studio") as studio,
        OllamaV2ControllerStore(root / "controller.sqlite3") as store,
    ):
        control = StudioDirectorControl(studio)
        control.enroll(passphrase=PASSPHRASE)
        release, model = _manifests()
        plan = build_controller_plan(
            make_empty_host_snapshot(f"snapshot-ladder-{phase}", observed_generation=0),
            release,
            model,
            operation_id=f"operation-ladder-{phase}",
        )
        inspector = _FileInspector(plan, effects_path)
        effects = _FileEffects(effects_path)
        bootstrap = OllamaV2Controller(
            store,
            inspector,
            _BootstrapAuthorization(),
            effects,
        )
        operation = bootstrap.create_operation(
            plan,
            operation_id=plan.operation_id,
            idempotency_key=f"create-ladder-{phase}",
        )
        rollback = None
        if phase == "rollback":
            while operation.state != "prepared_unverified":
                operation = bootstrap.advance_apply(operation)
            operation = bootstrap.prepare_rollback(operation)
            rollback = store.load_rollback_plan(operation.operation_id)
            if rollback is None:
                raise RuntimeError("ladder rollback plan is missing")
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
        phase_effects = plan.effects if phase == "apply" else rollback.effects
        _write_json(
            root / "ladder-metadata.json",
            {
                "approved": approved,
                "effect_ids": [effect.effect_id for effect in phase_effects],
                "operation_id": operation.operation_id,
                "phase": phase,
                "plan": plan.to_document(),
                "review": review,
                "rollback": None if rollback is None else rollback.to_document(),
            },
        )
        payload = {
            "effect_count": len(phase_effects),
            "operation_id": operation.operation_id,
            "phase": phase,
            "state": operation.state,
        }
        control.close()
    _emit(payload)


def _ladder_bound_controller(
    root: Path,
    studio: StudioStore,
    store: OllamaV2ControllerStore,
) -> tuple[
    dict[str, object],
    StudioDirectorControl,
    OperationSnapshot,
    OllamaV2Controller,
]:
    metadata = _read_json(root / "ladder-metadata.json")
    human_authority_module._director_clock_ms = lambda: _clock_ms(root)
    control = StudioDirectorControl(studio)
    control.unlock(passphrase=PASSPHRASE)
    operation = store.load_operation(metadata["operation_id"])
    decision_row = studio.connection.execute(
        "SELECT generation FROM studio_ollama_v2_authorization_decisions "
        "WHERE mandate_id=?",
        (metadata["review"]["mandate_id"],),
    ).fetchone()
    port = control.bind_ollama_v2_authorization(
        metadata["review"],
        controller_store=store,
        operation_id=metadata["operation_id"],
        expected_generation=int(decision_row["generation"]),
        expected_decision_hash=metadata["approved"]["decision"]["content_hash"],
    )
    plan = ControllerPlan.from_document(metadata["plan"])
    controller = OllamaV2Controller(
        store,
        _FileInspector(plan, root / "effects.jsonl"),
        port,
        _FileEffects(root / "effects.jsonl"),
    )
    return metadata, control, operation, controller


def _run_ladder_transition_child(phase: str, root: Path) -> None:
    with (
        StudioStore(root / "studio") as studio,
        OllamaV2ControllerStore(root / "controller.sqlite3") as store,
    ):
        original_commit = OllamaV2ControllerStore._commit

        def committed_then_lost_reply(candidate: OllamaV2ControllerStore) -> None:
            original_commit(candidate)
            if candidate is store:
                raise RuntimeError("ladder transition committed")

        with mock.patch.object(
            OllamaV2ControllerStore,
            "_commit",
            new=committed_then_lost_reply,
        ):
            metadata, control, operation, controller = _ladder_bound_controller(
                root,
                studio,
                store,
            )
            if metadata["phase"] != phase:
                raise RuntimeError("ladder phase mismatch")
            before_state = operation.state
            if phase == "apply":
                after = controller.advance_apply(operation)
            else:
                after = controller.advance_rollback(operation)
        payload = {
            "bound_from_state": before_state,
            "generation_delta": after.generation - operation.generation,
            "phase": phase,
            "sequence_delta": after.sequence - operation.sequence,
            "state": after.state,
        }
        control.close()
    _emit(payload)


def _run_ladder_dispatch_child(phase: str, root: Path) -> None:
    with (
        StudioStore(root / "studio") as studio,
        OllamaV2ControllerStore(root / "controller.sqlite3") as store,
    ):
        metadata = _read_json(root / "ladder-metadata.json")
        human_authority_module._director_clock_ms = lambda: _clock_ms(root)
        control = StudioDirectorControl(studio)
        control.unlock(passphrase=PASSPHRASE)
        operation = store.load_operation(metadata["operation_id"])
        if operation.state != f"{phase}_authorization_consumed":
            raise RuntimeError("ladder dispatch source state mismatch")
        decision_row = studio.connection.execute(
            "SELECT generation FROM studio_ollama_v2_authorization_decisions "
            "WHERE mandate_id=?",
            (metadata["review"]["mandate_id"],),
        ).fetchone()
        port = control.bind_ollama_v2_authorization(
            metadata["review"],
            controller_store=store,
            operation_id=metadata["operation_id"],
            expected_generation=int(decision_row["generation"]),
            expected_decision_hash=metadata["approved"]["decision"]["content_hash"],
        )
        plan = ControllerPlan.from_document(metadata["plan"])
        controller = OllamaV2Controller(
            store,
            _FileInspector(plan, root / "effects.jsonl"),
            port,
            _ExitAfterFileEffects(
                root / "effects.jsonl",
                store,
                operation.operation_id,
                phase,
            ),
        )
        if phase == "apply":
            controller.advance_apply(operation)
        else:
            controller.advance_rollback(operation)
        raise RuntimeError("ladder dispatch cutpoint was not reached")


def _run_ladder_audit_child(phase: str, root: Path) -> None:
    metadata = _read_json(root / "ladder-metadata.json")
    human_authority_module._director_clock_ms = lambda: _clock_ms(root)
    with (
        StudioStore(root / "studio") as studio,
        OllamaV2ControllerStore(root / "controller.sqlite3") as store,
    ):
        control = StudioDirectorControl(studio)
        control.unlock(passphrase=PASSPHRASE)
        operation = store.load_operation(metadata["operation_id"])
        snapshot = control.inspect_ollama_v2_authorization(metadata["review"])
        events_by_effect: dict[str, list[str]] = {
            str(effect_id): [] for effect_id in metadata["effect_ids"]
        }
        for event in store.event_documents(metadata["operation_id"]):
            bindings = event["bindings"]
            if (
                bindings.get("phase") == phase
                and bindings.get("effect_id") in events_by_effect
            ):
                events_by_effect[str(bindings["effect_id"])].append(
                    str(event["event_kind"])
                )
        controller_rows = store._connection.execute(
            "SELECT effect_id, request_json, consumption_json FROM "
            "controller_authorizations WHERE operation_id=? AND phase=? "
            "ORDER BY attempt",
            (metadata["operation_id"], phase),
        ).fetchall()
        studio_rows = studio.connection.execute(
            "SELECT effect_id, request_json, outcome_json FROM "
            "studio_ollama_v2_authorization_outcomes WHERE mandate_id=? "
            "ORDER BY slot_ordinal",
            (metadata["review"]["mandate_id"],),
        ).fetchall()
        markers = [
            effect.effect_id
            for effect in _read_effects(root / "effects.jsonl")
            if effect.phase == phase
        ]
        payload = {
            "attempt_count": int(
                store._connection.execute(
                    "SELECT count(*) FROM controller_effect_attempts "
                    "WHERE operation_id=? AND phase=? AND outcome='postcondition'",
                    (metadata["operation_id"], phase),
                ).fetchone()[0]
            ),
            "controller_lock_released": _probe_independent_lock(
                root / "controller.sqlite3"
            ),
            "controller_state": operation.state,
            "decision_consumed_count": snapshot["consumed_slots"],
            "effect_ids": metadata["effect_ids"],
            "event_groups": events_by_effect,
            "lease_count": int(
                store._connection.execute(
                    "SELECT count(*) FROM controller_host_scope_leases "
                    "WHERE operation_id=?",
                    (metadata["operation_id"],),
                ).fetchone()[0]
            ),
            "marker_ids": markers,
            "outcome_parity": len(controller_rows) == len(studio_rows)
            and all(
                controller["effect_id"] == studio_row["effect_id"]
                and controller["request_json"].decode("utf-8")
                == studio_row["request_json"]
                and controller["consumption_json"].decode("utf-8")
                == studio_row["outcome_json"]
                for controller, studio_row in zip(
                    controller_rows,
                    studio_rows,
                    strict=True,
                )
            ),
            "phase": phase,
            "studio_lock_released": _probe_independent_lock(studio.database_path),
            "studio_outcome_count": len(studio_rows),
            "studio_status": snapshot["status"],
        }
        control.close()
    _emit(payload)


def _child_command(role: str, case: str, root: Path) -> list[str]:
    return [
        sys.executable,
        "-B",
        str(Path(__file__).resolve()),
        "--child-role",
        role,
        "--case",
        case,
        "--root",
        str(root),
    ]


def _run_child(role: str, case: str, root: Path) -> tuple[subprocess.CompletedProcess[str], float]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    started = time.monotonic()
    result = subprocess.run(
        _child_command(role, case, root),
        cwd=REPO_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        close_fds=True,
        timeout=30,
        check=False,
    )
    return result, time.monotonic() - started


def _parsed_child_json(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    lines = [line for line in result.stdout.splitlines() if line]
    if len(lines) != 1:
        raise AssertionError(
            f"expected one child JSON line, got stdout={result.stdout!r}, stderr={result.stderr!r}"
        )
    value = json.loads(lines[0])
    if type(value) is not dict:
        raise AssertionError("child JSON is not an object")
    return value


class StudioOllamaV2AuthorizationProcessRecoveryTests(unittest.TestCase):
    maxDiff = None

    def _assert_case(self, case_name: str) -> None:
        case = _CASES[case_name]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crash, crash_seconds = _run_child("crash", case.name, root)
            self.assertEqual(
                case.exit_code,
                crash.returncode,
                msg=f"crash stderr={crash.stderr!r} stdout={crash.stdout!r}",
            )
            crash_json = _parsed_child_json(crash)
            self.assertEqual(case.name, crash_json["case"])
            self.assertEqual(case.fault, crash_json["cutpoint"])
            self.assertEqual(0, crash_json["dispatch_events_before_crash"])
            self.assertEqual(0, crash_json["target_effect_count_before_crash"])
            expected_crash_events = ["authorization.pending", "authorization.claimed"]
            if case.fault == "controller_ack":
                expected_crash_events.append(
                    "authorization.consumed"
                    if case.outcome == "consumed"
                    else "authorization.rejected"
                )
            self.assertEqual(expected_crash_events, crash_json["target_event_kinds"])
            self.assertEqual(
                0 if case.fault == "controller_claim" else 1,
                crash_json["studio_outcomes_visible"],
            )
            self.assertEqual(
                case.fault == "studio_pre",
                crash_json["studio_transaction_active"],
            )

            recovery, recovery_seconds = _run_child("recovery", case.name, root)
            self.assertEqual(
                0,
                recovery.returncode,
                msg=f"recovery stderr={recovery.stderr!r} stdout={recovery.stdout!r}",
            )
            recovered = _parsed_child_json(recovery)
            audit, audit_seconds = _run_child("audit", case.name, root)
            self.assertEqual(
                0,
                audit.returncode,
                msg=f"audit stderr={audit.stderr!r} stdout={audit.stdout!r}",
            )
            audited = _parsed_child_json(audit)

            expected_events = [
                "authorization.pending",
                "authorization.claimed",
                (
                    "authorization.consumed"
                    if case.outcome == "consumed"
                    else "authorization.rejected"
                ),
            ]
            if case.outcome == "consumed":
                expected_events.extend(["effect.dispatching", "effect.observed"])
            self.assertEqual(expected_events, recovered["controller_event_kinds"])
            self.assertEqual(expected_events, audited["controller_event_kinds"])
            self.assertEqual(1, recovered["studio_outcome_count"])
            self.assertEqual(1, audited["studio_outcome_count"])
            self.assertTrue(recovered["outcome_documents_equal"])
            self.assertTrue(audited["outcome_documents_equal"])
            self.assertTrue(recovered["consumption_projection_equal"])
            self.assertTrue(audited["consumption_projection_equal"])
            self.assertTrue(recovered["studio_lock_released"])
            self.assertTrue(recovered["controller_lock_released"])
            self.assertTrue(audited["studio_lock_released"])
            self.assertTrue(audited["controller_lock_released"])
            self.assertEqual(recovered["state_fingerprint"], audited["state_fingerprint"])
            self.assertEqual(
                recovered["studio_outcome"],
                audited["studio_outcome"],
            )

            if case.outcome == "consumed":
                self.assertEqual("consumed", recovered["outcome_kind"])
                self.assertEqual(1, recovered["decision_consumed_count"])
                self.assertEqual(1, recovered["studio_consumption_count"])
                self.assertEqual(0, recovered["studio_rejected_event_count"])
                self.assertEqual(1, recovered["dispatch_attempt_count"])
                self.assertEqual(1, recovered["target_effect_count"])
                self.assertEqual(
                    "apply_pending" if case.phase == "apply" else "rolled_back_clean",
                    recovered["controller_state"],
                )
                self.assertEqual(1 if case.phase == "apply" else 0, recovered["lease_count"])
            else:
                self.assertEqual("rejected", recovered["outcome_kind"])
                self.assertEqual(0, recovered["decision_consumed_count"])
                self.assertEqual(0, recovered["studio_consumption_count"])
                self.assertEqual(1, recovered["studio_rejected_event_count"])
                self.assertEqual(0, recovered["dispatch_attempt_count"])
                self.assertEqual(0, recovered["target_effect_count"])
                self.assertEqual("recovery_required", recovered["controller_state"])
                self.assertEqual(1, recovered["lease_count"])
                self.assertEqual(case.reason, recovered["studio_outcome"]["reason"])
            for child_seconds in (crash_seconds, recovery_seconds, audit_seconds):
                self.assertGreater(child_seconds, 0)
                self.assertLess(child_seconds, 30)

    def test_consumed_after_controller_claim_apply(self) -> None:
        self._assert_case("consumed_after_controller_claim_apply")

    def test_revoked_after_controller_claim_rollback(self) -> None:
        self._assert_case("revoked_after_controller_claim_rollback")

    def test_consumed_before_studio_commit_rollback(self) -> None:
        self._assert_case("consumed_before_studio_commit_rollback")

    def test_expired_before_studio_commit_apply(self) -> None:
        self._assert_case("expired_before_studio_commit_apply")

    def test_consumed_after_studio_commit_apply(self) -> None:
        self._assert_case("consumed_after_studio_commit_apply")

    def test_expired_after_studio_commit_rollback(self) -> None:
        self._assert_case("expired_after_studio_commit_rollback")

    def test_consumed_after_controller_ack_rollback(self) -> None:
        self._assert_case("consumed_after_controller_ack_rollback")

    def test_revoked_after_controller_ack_apply(self) -> None:
        self._assert_case("revoked_after_controller_ack_apply")

    def test_denied_is_a_separate_no_claim_no_outcome_no_effect_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result, _seconds = _run_child("denied", "denied", Path(directory))
            self.assertEqual(
                0,
                result.returncode,
                msg=f"denied stderr={result.stderr!r} stdout={result.stdout!r}",
            )
            payload = _parsed_child_json(result)
            self.assertEqual("invalid_state", payload["bind_error"])
            self.assertEqual("apply_pending", payload["controller_state"])
            self.assertEqual(["operation.created"], payload["controller_events"])
            self.assertEqual(0, payload["authorization_rows"])
            self.assertEqual(0, payload["studio_outcomes"])
            self.assertEqual(0, payload["studio_consumptions"])
            self.assertEqual(0, payload["effect_count"])

    def _assert_full_fresh_process_ladder(self, phase: str) -> None:
        expected_cycle = [
            "authorization.pending",
            "authorization.claimed",
            "authorization.consumed",
            "effect.dispatching",
            "effect.observed",
        ]
        expected_states = [
            f"{phase}_authorization_pending",
            f"{phase}_authorization_claimed",
            f"{phase}_authorization_consumed",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            setup, setup_seconds = _run_child("ladder-setup", phase, root)
            self.assertEqual(
                0,
                setup.returncode,
                msg=f"setup stderr={setup.stderr!r} stdout={setup.stdout!r}",
            )
            setup_payload = _parsed_child_json(setup)
            self.assertEqual(f"{phase}_pending", setup_payload["state"])
            effect_count = int(setup_payload["effect_count"])
            self.assertEqual(9, effect_count)
            child_seconds = [setup_seconds]

            for ordinal in range(effect_count):
                expected_source = f"{phase}_pending"
                for expected_state in expected_states:
                    transition, seconds = _run_child("ladder-transition", phase, root)
                    child_seconds.append(seconds)
                    self.assertEqual(
                        0,
                        transition.returncode,
                        msg=(
                            f"slot={ordinal} source={expected_source} "
                            f"stderr={transition.stderr!r} stdout={transition.stdout!r}"
                        ),
                    )
                    payload = _parsed_child_json(transition)
                    self.assertEqual(expected_source, payload["bound_from_state"])
                    self.assertEqual(expected_state, payload["state"])
                    self.assertEqual(1, payload["generation_delta"])
                    self.assertEqual(1, payload["sequence_delta"])
                    expected_source = expected_state

                dispatch, seconds = _run_child("ladder-dispatch", phase, root)
                child_seconds.append(seconds)
                self.assertEqual(
                    93,
                    dispatch.returncode,
                    msg=f"slot={ordinal} stderr={dispatch.stderr!r} stdout={dispatch.stdout!r}",
                )
                dispatched = _parsed_child_json(dispatch)
                self.assertEqual(
                    f"{phase}_authorization_consumed",
                    dispatched["bound_from_state"],
                )
                self.assertEqual(f"{phase}_dispatching", dispatched["state"])
                self.assertEqual(1, dispatched["effect_marker_count"])

                observed, seconds = _run_child("ladder-transition", phase, root)
                child_seconds.append(seconds)
                self.assertEqual(
                    0,
                    observed.returncode,
                    msg=f"slot={ordinal} stderr={observed.stderr!r} stdout={observed.stdout!r}",
                )
                observed_payload = _parsed_child_json(observed)
                self.assertEqual(
                    f"{phase}_dispatching",
                    observed_payload["bound_from_state"],
                )
                terminal = (
                    "prepared_unverified"
                    if phase == "apply"
                    else "rolled_back_clean"
                )
                self.assertEqual(
                    terminal if ordinal == effect_count - 1 else f"{phase}_pending",
                    observed_payload["state"],
                )
                self.assertEqual(1, observed_payload["generation_delta"])
                self.assertEqual(1, observed_payload["sequence_delta"])

            audit, audit_seconds = _run_child("ladder-audit", phase, root)
            child_seconds.append(audit_seconds)
            self.assertEqual(
                0,
                audit.returncode,
                msg=f"audit stderr={audit.stderr!r} stdout={audit.stdout!r}",
            )
            payload = _parsed_child_json(audit)
            self.assertEqual(
                "prepared_unverified" if phase == "apply" else "rolled_back_clean",
                payload["controller_state"],
            )
            self.assertEqual(effect_count, payload["decision_consumed_count"])
            self.assertEqual(effect_count, payload["studio_outcome_count"])
            self.assertEqual(effect_count, payload["attempt_count"])
            self.assertEqual(payload["effect_ids"], payload["marker_ids"])
            self.assertTrue(payload["outcome_parity"])
            self.assertEqual("exhausted", payload["studio_status"])
            self.assertEqual(1 if phase == "apply" else 0, payload["lease_count"])
            self.assertTrue(payload["studio_lock_released"])
            self.assertTrue(payload["controller_lock_released"])
            self.assertEqual(
                {effect_id: expected_cycle for effect_id in payload["effect_ids"]},
                payload["event_groups"],
            )
            for seconds in child_seconds:
                self.assertGreater(seconds, 0)
                self.assertLess(seconds, 30)

    def test_full_fresh_process_apply_ladder_rebinds_every_nonterminal_state(self) -> None:
        self._assert_full_fresh_process_ladder("apply")

    def test_full_fresh_process_rollback_ladder_rebinds_every_nonterminal_state(self) -> None:
        self._assert_full_fresh_process_ladder("rollback")


def _main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--child-role")
    parser.add_argument("--case")
    parser.add_argument("--root")
    arguments, remaining = parser.parse_known_args()
    if arguments.child_role:
        if remaining or arguments.root is None or arguments.case is None:
            raise SystemExit(2)
        root = Path(arguments.root)
        root.mkdir(parents=True, exist_ok=True)
        if arguments.child_role == "denied":
            _run_denied_child(root)
            return
        if arguments.child_role == "ladder-setup":
            _run_ladder_setup_child(arguments.case, root)
            return
        if arguments.child_role == "ladder-transition":
            _run_ladder_transition_child(arguments.case, root)
            return
        if arguments.child_role == "ladder-dispatch":
            _run_ladder_dispatch_child(arguments.case, root)
            return
        if arguments.child_role == "ladder-audit":
            _run_ladder_audit_child(arguments.case, root)
            return
        case = _CASES[arguments.case]
        if arguments.child_role == "crash":
            _run_crash_child(case, root)
        elif arguments.child_role in {"recovery", "audit"}:
            _run_recovery_or_audit_child(case, root, arguments.child_role)
        else:
            raise SystemExit(2)
        return
    unittest.main(argv=[sys.argv[0], *remaining])


if __name__ == "__main__":
    _main()
