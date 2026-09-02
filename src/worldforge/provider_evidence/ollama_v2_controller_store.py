"""Private durable SQLite store for the non-native Ollama v2 controller.

The store detects malformed schema, non-canonical rows, broken foreign keys,
CAS drift, and hash-chain corruption.  It does not protect against coherent
rollback by the same OS principal; an external monotonic authority would be
required for that stronger claim.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from .ollama_v2_controller_contracts import (
    AuthorizationConsumption,
    AuthorizationRequest,
    ControllerContractError,
    ControllerPlan,
    HostSnapshot,
    OperationSnapshot,
    RollbackPlan,
    build_rollback_plan,
    canonical_controller_bytes,
    classify_effect_snapshot,
    host_projection_hash,
    is_reusable_clean_projection,
)

SCHEMA_VERSION = 1
APPLICATION_ID = 0x57464F32
HOST_SCOPE_ID = "ollama_v2_fixed_host_scope"
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9_.:-]{2,127}$")


class ControllerStoreError(RuntimeError):
    """Base class for private controller-store failures."""


class ControllerStoreCorruptionError(ControllerStoreError):
    """The stored schema, document, or event history is not exact."""


class ControllerStoreConflictError(ControllerStoreError):
    """The supplied generation/sequence/head/state CAS is stale."""


class ControllerStoreDuplicateMismatch(ControllerStoreError):
    """A unique identity was reused with different canonical content."""


class ControllerStoreCommitNotApplied(ControllerStoreError):
    """A commit exception reconciled to the exact pre-transaction state."""


class ControllerStoreRecoveryRequired(ControllerStoreError):
    """A commit exception reconciled to neither exact adjacent state."""


@dataclass(frozen=True, slots=True)
class ControllerStoreTransition:
    """Snapshot plus exclusive ownership of one newly committed transition."""

    snapshot: OperationSnapshot
    committed_now: bool

    def __post_init__(self) -> None:
        if type(self.snapshot) is not OperationSnapshot or type(self.committed_now) is not bool:
            raise ControllerStoreError("transition_result_invalid")


_DDL_BY_NAME = {
    "controller_metadata": """CREATE TABLE controller_metadata (
    key TEXT PRIMARY KEY CHECK (key IN ('schema_version', 'schema_fingerprint')),
    value TEXT NOT NULL
) WITHOUT ROWID""",
    "controller_operations": """CREATE TABLE controller_operations (
    operation_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    plan_json BLOB NOT NULL,
    snapshot_json BLOB NOT NULL,
    rollback_json BLOB,
    generation INTEGER NOT NULL CHECK (generation >= 1),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    head_hash TEXT NOT NULL CHECK (length(head_hash) = 64),
    state TEXT NOT NULL CHECK (state IN (
        'apply_pending',
        'apply_authorization_pending',
        'apply_authorization_claimed',
        'apply_authorization_consumed',
        'apply_dispatching',
        'prepared_unverified',
        'rollback_pending',
        'rollback_authorization_pending',
        'rollback_authorization_claimed',
        'rollback_authorization_consumed',
        'rollback_dispatching',
        'rolled_back_clean',
        'recovery_required'
    )),
    poisoned INTEGER NOT NULL DEFAULT 0 CHECK (poisoned IN (0, 1))
) WITHOUT ROWID""",
    "controller_host_scope_leases": """CREATE TABLE controller_host_scope_leases (
    scope_id TEXT PRIMARY KEY CHECK (scope_id = 'ollama_v2_fixed_host_scope'),
    operation_id TEXT NOT NULL UNIQUE,
    ownership_token TEXT NOT NULL UNIQUE,
    acquired_sequence INTEGER NOT NULL CHECK (acquired_sequence = 1),
    state TEXT NOT NULL CHECK (state = 'active'),
    FOREIGN KEY (operation_id) REFERENCES controller_operations(operation_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) WITHOUT ROWID""",
    "controller_events": """CREATE TABLE controller_events (
    operation_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    event_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    previous_hash TEXT NOT NULL CHECK (length(previous_hash) = 64),
    event_hash TEXT NOT NULL CHECK (length(event_hash) = 64),
    transition_hash TEXT NOT NULL CHECK (length(transition_hash) = 64),
    event_json BLOB NOT NULL,
    snapshot_json BLOB NOT NULL,
    PRIMARY KEY (operation_id, sequence),
    FOREIGN KEY (operation_id) REFERENCES controller_operations(operation_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) WITHOUT ROWID""",
    "controller_authorizations": """CREATE TABLE controller_authorizations (
    authorization_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('apply', 'rollback')),
    effect_id TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt >= 1),
    request_json BLOB NOT NULL,
    consumption_json BLOB,
    state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'consumed')),
    FOREIGN KEY (operation_id) REFERENCES controller_operations(operation_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) WITHOUT ROWID""",
    "controller_effect_attempts": """CREATE TABLE controller_effect_attempts (
    attempt_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('apply', 'rollback')),
    effect_id TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt >= 1),
    authorization_id TEXT NOT NULL,
    request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
    before_snapshot_json BLOB NOT NULL,
    after_snapshot_json BLOB,
    outcome TEXT NOT NULL CHECK (outcome IN (
        'dispatching', 'precondition', 'postcondition', 'foreign',
        'observation_unavailable'
    )),
    dispatch_sequence INTEGER NOT NULL CHECK (dispatch_sequence >= 1),
    observation_sequence INTEGER CHECK (observation_sequence >= 1),
    FOREIGN KEY (operation_id) REFERENCES controller_operations(operation_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (authorization_id) REFERENCES controller_authorizations(authorization_id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) WITHOUT ROWID""",
    "idx_controller_events_event_id": """CREATE UNIQUE INDEX idx_controller_events_event_id
ON controller_events(event_id)""",
    "idx_controller_authorizations_effect_attempt": (
        "CREATE UNIQUE INDEX idx_controller_authorizations_effect_attempt\n"
        "ON controller_authorizations(operation_id, phase, effect_id, attempt)"
    ),
    "idx_controller_attempts_effect_attempt": (
        "CREATE UNIQUE INDEX idx_controller_attempts_effect_attempt\n"
        "ON controller_effect_attempts(operation_id, phase, effect_id, attempt)"
    ),
}


def _schema_fingerprint() -> str:
    payload = [
        {"name": name, "sql": sql}
        for name, sql in sorted(_DDL_BY_NAME.items())
    ]
    return hashlib.sha256(canonical_controller_bytes(payload)).hexdigest()


SCHEMA_FINGERPRINT = _schema_fingerprint()


def _json_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _decode_canonical_json(value: object) -> object:
    if type(value) is not bytes:
        raise ControllerStoreCorruptionError("stored_document_not_bytes")
    try:
        decoded = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=_json_no_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite")),
        )
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise ControllerStoreCorruptionError("stored_document_invalid_json") from exc
    try:
        if canonical_controller_bytes(decoded) != value:
            raise ControllerStoreCorruptionError("stored_document_not_canonical")
    except ControllerContractError as exc:
        raise ControllerStoreCorruptionError("stored_document_not_canonical") from exc
    return decoded


def _encode_document(document: object) -> bytes:
    return canonical_controller_bytes(document)


def _database_value_document(value: object) -> object:
    if type(value) is bytes:
        return {"type": "blob", "hex": value.hex()}
    if value is None or type(value) in {str, int}:
        return value
    raise ControllerStoreCorruptionError("database_value_type_invalid")


def _operation_state_bytes(
    connection: sqlite3.Connection,
    operation_id: str,
) -> bytes:
    queries = (
        (
            "controller_operations",
            "SELECT * FROM controller_operations WHERE operation_id = ? ORDER BY operation_id",
        ),
        (
            "controller_events",
            "SELECT * FROM controller_events WHERE operation_id = ? ORDER BY sequence",
        ),
        (
            "controller_authorizations",
            "SELECT * FROM controller_authorizations WHERE operation_id = ? "
            "ORDER BY authorization_id",
        ),
        (
            "controller_effect_attempts",
            "SELECT * FROM controller_effect_attempts WHERE operation_id = ? "
            "ORDER BY attempt_id",
        ),
        (
            "controller_host_scope_leases",
            "SELECT * FROM controller_host_scope_leases WHERE operation_id = ? "
            "ORDER BY scope_id",
        ),
    )
    tables: list[dict[str, object]] = []
    for table_name, query in queries:
        cursor = connection.execute(query, (operation_id,))
        columns = [str(description[0]) for description in cursor.description]
        rows = [
            [_database_value_document(value) for value in tuple(row)]
            for row in cursor.fetchall()
        ]
        tables.append({"table": table_name, "columns": columns, "rows": rows})
    return canonical_controller_bytes(
        {"operation_id": operation_id, "tables": tables}
    )


def _validate_identifier(value: object, reason: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise ControllerStoreError(reason)
    return value


def _snapshot_projection_hash(snapshot: OperationSnapshot) -> str:
    document = snapshot.to_document()
    document.pop("content_hash")
    document.pop("event_head_hash")
    return hashlib.sha256(canonical_controller_bytes(document)).hexdigest()


_EVENT_BINDING_KEYS = {
    "operation.created": {
        "plan_hash",
        "ownership_token",
        "idempotency_key_hash",
        "host_scope_id",
        "initial_host_snapshot_hash",
        "initial_host_projection_hash",
    },
    "authorization.pending": {
        "authorization_id",
        "request_hash",
        "effect_id",
        "phase",
        "attempt",
        "ownership_token",
    },
    "authorization.claimed": {
        "authorization_id",
        "request_hash",
        "effect_id",
        "phase",
        "attempt",
        "ownership_token",
    },
    "authorization.consumed": {
        "authorization_id",
        "request_hash",
        "effect_id",
        "phase",
        "attempt",
        "ownership_token",
        "consumption_id",
        "consumption_hash",
        "authority_id",
        "decision_id",
    },
    "effect.dispatching": {
        "attempt_id",
        "attempt_document_hash",
        "authorization_id",
        "request_hash",
        "consumption_hash",
        "effect_id",
        "effect_hash",
        "phase",
        "attempt",
        "ownership_token",
        "before_snapshot_hash",
        "before_projection_hash",
    },
    "effect.observed": {
        "attempt_id",
        "attempt_document_hash",
        "authorization_id",
        "request_hash",
        "consumption_hash",
        "effect_id",
        "effect_hash",
        "phase",
        "attempt",
        "ownership_token",
        "outcome",
        "before_snapshot_hash",
        "before_projection_hash",
        "after_snapshot_hash",
        "after_projection_hash",
    },
    "operation.recovery_required": {
        "reason",
        "observed_snapshot_hash",
        "observed_projection_hash",
    },
    "rollback.prepared": {
        "rollback_plan_hash",
        "ownership_token",
        "clean_snapshot",
        "clean_snapshot_hash",
        "clean_projection_hash",
    },
}


def _document_binding_hash(value: object) -> str:
    return hashlib.sha256(canonical_controller_bytes(value)).hexdigest()


def _request_bindings(request: AuthorizationRequest) -> dict[str, object]:
    return {
        "authorization_id": request.authorization_id,
        "request_hash": request.content_hash,
        "effect_id": request.effect_id,
        "phase": request.phase,
        "attempt": request.attempt,
        "ownership_token": request.ownership_token,
    }


def _consumption_bindings(
    request: AuthorizationRequest,
    consumption: AuthorizationConsumption,
) -> dict[str, object]:
    return {
        **_request_bindings(request),
        "consumption_id": consumption.consumption_id,
        "consumption_hash": consumption.content_hash,
        "authority_id": consumption.authority_id,
        "decision_id": consumption.decision_id,
    }


def _attempt_document_hash(
    *,
    attempt_id: str,
    operation_id: str,
    phase: str,
    effect_id: str,
    attempt: int,
    authorization_id: str,
    request_hash: str,
    before_snapshot_hash: str,
    after_snapshot_hash: str | None,
    outcome: str,
    dispatch_sequence: int,
    observation_sequence: int | None,
) -> str:
    return _document_binding_hash(
        {
            "format": "world-forge.private.ollama_v2_controller_effect_attempt",
            "format_version": 1,
            "attempt_id": attempt_id,
            "operation_id": operation_id,
            "phase": phase,
            "effect_id": effect_id,
            "attempt": attempt,
            "authorization_id": authorization_id,
            "request_hash": request_hash,
            "before_snapshot_hash": before_snapshot_hash,
            "after_snapshot_hash": after_snapshot_hash,
            "outcome": outcome,
            "dispatch_sequence": dispatch_sequence,
            "observation_sequence": observation_sequence,
        }
    )


def _validate_event_bindings(event_kind: object, value: object) -> dict[str, object]:
    if type(event_kind) is not str or event_kind not in _EVENT_BINDING_KEYS:
        raise ControllerStoreCorruptionError("event_kind_invalid")
    if type(value) is not dict or set(value) != _EVENT_BINDING_KEYS[event_kind]:
        raise ControllerStoreCorruptionError("event_bindings_invalid")
    bindings = dict(value)
    id_keys = {
        "ownership_token",
        "authorization_id",
        "effect_id",
        "phase",
        "consumption_id",
        "authority_id",
        "decision_id",
        "attempt_id",
        "reason",
        "host_scope_id",
        "outcome",
    }
    hash_keys = {key for key in bindings if key.endswith("_hash")}
    nullable_hashes = {
        "after_snapshot_hash",
        "after_projection_hash",
        "observed_snapshot_hash",
        "observed_projection_hash",
        "clean_snapshot_hash",
        "clean_projection_hash",
    }
    for key in id_keys & set(bindings):
        item = bindings[key]
        if type(item) is not str or _ID_RE.fullmatch(item) is None:
            raise ControllerStoreCorruptionError("event_bindings_invalid")
    for key in hash_keys:
        item = bindings[key]
        if item is None and key in nullable_hashes:
            continue
        if type(item) is not str or _HASH_RE.fullmatch(item) is None:
            raise ControllerStoreCorruptionError("event_bindings_invalid")
    if "attempt" in bindings and (
        type(bindings["attempt"]) is not int or bindings["attempt"] < 1
    ):
        raise ControllerStoreCorruptionError("event_bindings_invalid")
    if bindings.get("phase") not in {None, "apply", "rollback"}:
        raise ControllerStoreCorruptionError("event_bindings_invalid")
    if bindings.get("outcome") not in {
        None,
        "precondition",
        "postcondition",
        "foreign",
        "observation_unavailable",
    }:
        raise ControllerStoreCorruptionError("event_bindings_invalid")
    for first, second in (
        ("after_snapshot_hash", "after_projection_hash"),
        ("observed_snapshot_hash", "observed_projection_hash"),
        ("clean_snapshot_hash", "clean_projection_hash"),
    ):
        if first in bindings and ((bindings[first] is None) != (bindings[second] is None)):
            raise ControllerStoreCorruptionError("event_bindings_invalid")
    if "clean_snapshot" in bindings:
        clean_snapshot = bindings["clean_snapshot"]
        if (clean_snapshot is None) != (bindings["clean_snapshot_hash"] is None):
            raise ControllerStoreCorruptionError("event_bindings_invalid")
        if clean_snapshot is not None:
            try:
                HostSnapshot.from_document(clean_snapshot)
            except (ControllerContractError, TypeError) as exc:
                raise ControllerStoreCorruptionError("event_bindings_invalid") from exc
    return bindings


def _event_document(
    *,
    event_id: str,
    operation_id: str,
    sequence: int,
    event_kind: str,
    previous_hash: str,
    transition_hash: str,
    bindings: dict[str, object],
) -> dict[str, object]:
    bindings = _validate_event_bindings(event_kind, bindings)
    payload: dict[str, object] = {
        "format": "world-forge.private.ollama_v2_controller_event",
        "format_version": 1,
        "event_id": event_id,
        "operation_id": operation_id,
        "sequence": sequence,
        "event_kind": event_kind,
        "previous_hash": previous_hash,
        "transition_hash": transition_hash,
        "bindings": bindings,
    }
    event_hash = hashlib.sha256(
        bytes.fromhex(previous_hash) + canonical_controller_bytes(payload)
    ).hexdigest()
    payload["event_hash"] = event_hash
    return payload


def _verify_event_document(document: object) -> dict[str, object]:
    if type(document) is not dict or set(document) != {
        "format",
        "format_version",
        "event_id",
        "operation_id",
        "sequence",
        "event_kind",
        "previous_hash",
        "transition_hash",
        "bindings",
        "event_hash",
    }:
        raise ControllerStoreCorruptionError("event_document_invalid")
    if (
        document["format"] != "world-forge.private.ollama_v2_controller_event"
        or type(document["format_version"]) is not int
        or document["format_version"] != 1
        or type(document["sequence"]) is not int
        or document["sequence"] < 1
    ):
        raise ControllerStoreCorruptionError("event_document_invalid")
    for key in ("event_id", "operation_id"):
        if type(document[key]) is not str or _ID_RE.fullmatch(document[key]) is None:
            raise ControllerStoreCorruptionError("event_document_invalid")
    for key in ("previous_hash", "transition_hash", "event_hash"):
        if type(document[key]) is not str or _HASH_RE.fullmatch(document[key]) is None:
            raise ControllerStoreCorruptionError("event_document_invalid")
    _validate_event_bindings(document["event_kind"], document["bindings"])
    candidate = dict(document)
    declared = candidate.pop("event_hash")
    expected = hashlib.sha256(
        bytes.fromhex(str(candidate["previous_hash"]))
        + canonical_controller_bytes(candidate)
    ).hexdigest()
    if declared != expected:
        raise ControllerStoreCorruptionError("event_hash_invalid")
    return dict(document)


class OllamaV2ControllerStore:
    """One private exact-schema CAS and hash-chain SQLite store."""

    __slots__ = ("_path", "_connection", "_closed", "_poisoned_operations")

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(os.fspath(path))
        self._closed = False
        self._poisoned_operations: set[str] = set()
        self._connection = sqlite3.connect(
            self._path,
            isolation_level=None,
            timeout=30.0,
        )
        self._connection.row_factory = sqlite3.Row
        self._configure_connection(self._connection)
        try:
            self._initialize_or_verify()
        except BaseException:
            self._connection.close()
            self._closed = True
            raise

    @staticmethod
    def _configure_connection(connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = 30000")

    def __enter__(self) -> OllamaV2ControllerStore:
        self._ensure_open()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._connection.close()
            self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise ControllerStoreError("store_closed")

    def _initialize_or_verify(self) -> None:
        objects = self._connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
        if not objects:
            self._connection.execute("BEGIN EXCLUSIVE")
            try:
                for sql in _DDL_BY_NAME.values():
                    self._connection.execute(sql)
                self._connection.execute(
                    "INSERT INTO controller_metadata(key, value) VALUES (?, ?), (?, ?)",
                    (
                        "schema_version",
                        str(SCHEMA_VERSION),
                        "schema_fingerprint",
                        SCHEMA_FINGERPRINT,
                    ),
                )
                self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                self._connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                self._connection.execute("COMMIT")
            except BaseException:
                self._safe_rollback()
                raise
        self._verify_schema()
        self._verify_all_rows()

    def _verify_schema(self) -> None:
        rows = self._connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
        actual = {str(row["name"]): str(row["sql"]) for row in rows}
        if actual != _DDL_BY_NAME:
            raise ControllerStoreCorruptionError("schema_census_invalid")
        metadata = dict(
            self._connection.execute(
                "SELECT key, value FROM controller_metadata ORDER BY key"
            ).fetchall()
        )
        if metadata != {
            "schema_fingerprint": SCHEMA_FINGERPRINT,
            "schema_version": str(SCHEMA_VERSION),
        }:
            raise ControllerStoreCorruptionError("schema_metadata_invalid")
        if self._connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            raise ControllerStoreCorruptionError("schema_user_version_invalid")
        if self._connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
            raise ControllerStoreCorruptionError("schema_application_id_invalid")
        if self._connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise ControllerStoreCorruptionError("schema_foreign_keys_disabled")
        if self._connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ControllerStoreCorruptionError("sqlite_integrity_invalid")
        if self._connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ControllerStoreCorruptionError("sqlite_foreign_key_invalid")

    def schema_census(self) -> tuple[tuple[str, str, str], ...]:
        self._ensure_open()
        rows = self._connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
        return tuple(
            (
                str(row["type"]),
                str(row["name"]),
                hashlib.sha256(str(row["sql"]).encode("utf-8")).hexdigest(),
            )
            for row in rows
        )

    def _verify_all_rows(self) -> None:
        operation_ids = [
            str(row[0])
            for row in self._connection.execute(
                "SELECT operation_id FROM controller_operations ORDER BY operation_id"
            ).fetchall()
        ]
        for operation_id in operation_ids:
            self._verify_operation(operation_id)
        lease_rows = self._connection.execute(
            "SELECT * FROM controller_host_scope_leases ORDER BY scope_id"
        ).fetchall()
        if len(lease_rows) > 1:
            raise ControllerStoreCorruptionError("host_scope_lease_census_invalid")
        for row in self._connection.execute(
            "SELECT * FROM controller_authorizations ORDER BY authorization_id"
        ).fetchall():
            self._verify_authorization_row(row)
        for row in self._connection.execute(
            "SELECT * FROM controller_effect_attempts ORDER BY attempt_id"
        ).fetchall():
            self._verify_attempt_row(row)

    def _decode_plan(self, value: object) -> ControllerPlan:
        try:
            return ControllerPlan.from_document(_decode_canonical_json(value))
        except (ControllerContractError, TypeError) as exc:
            raise ControllerStoreCorruptionError("stored_plan_invalid") from exc

    def _decode_snapshot(self, value: object) -> OperationSnapshot:
        try:
            return OperationSnapshot.from_document(_decode_canonical_json(value))
        except (ControllerContractError, TypeError) as exc:
            raise ControllerStoreCorruptionError("stored_operation_invalid") from exc

    def _decode_host_snapshot(self, value: object) -> HostSnapshot:
        try:
            return HostSnapshot.from_document(_decode_canonical_json(value))
        except (ControllerContractError, TypeError) as exc:
            raise ControllerStoreCorruptionError("stored_host_snapshot_invalid") from exc

    def _decode_rollback(self, value: object) -> RollbackPlan:
        try:
            return RollbackPlan.from_document(_decode_canonical_json(value))
        except (ControllerContractError, TypeError) as exc:
            raise ControllerStoreCorruptionError("stored_rollback_invalid") from exc

    def _verify_operation(self, operation_id: str) -> None:
        row = self._connection.execute(
            "SELECT * FROM controller_operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise ControllerStoreCorruptionError("operation_missing")
        if row["poisoned"] == 1:
            self._poisoned_operations.add(operation_id)
            raise ControllerStoreRecoveryRequired("operation_poisoned")
        plan = self._decode_plan(row["plan_json"])
        snapshot = self._decode_snapshot(row["snapshot_json"])
        if (
            snapshot.operation_id != operation_id
            or snapshot.plan_hash != plan.content_hash
            or snapshot.ownership_token != plan.ownership_token
            or snapshot.generation != row["generation"]
            or snapshot.sequence != row["sequence"]
            or snapshot.event_head_hash != row["head_hash"]
            or snapshot.state != row["state"]
            or snapshot.generation != snapshot.sequence
        ):
            raise ControllerStoreCorruptionError("operation_columns_invalid")
        lease = self._connection.execute(
            "SELECT * FROM controller_host_scope_leases WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if snapshot.state == "rolled_back_clean":
            if lease is not None:
                raise ControllerStoreCorruptionError("host_scope_lease_release_invalid")
        elif (
            lease is None
            or lease["scope_id"] != HOST_SCOPE_ID
            or lease["ownership_token"] != snapshot.ownership_token
            or lease["acquired_sequence"] != 1
            or lease["state"] != "active"
        ):
            raise ControllerStoreCorruptionError("host_scope_lease_binding_invalid")
        expected_applied = tuple(
            effect.effect_id for effect in plan.effects[: snapshot.apply_cursor]
        )
        if (
            snapshot.apply_cursor > len(plan.effects)
            or snapshot.applied_effect_ids != expected_applied
            or (
                snapshot.state == "prepared_unverified"
                and snapshot.apply_cursor != len(plan.effects)
            )
        ):
            raise ControllerStoreCorruptionError("operation_apply_lineage_invalid")
        rollback: RollbackPlan | None = None
        if row["rollback_json"] is not None:
            rollback = self._decode_rollback(row["rollback_json"])
            if (
                rollback.operation_id != operation_id
                or rollback.ownership_token != plan.ownership_token
                or rollback.plan_hash != plan.content_hash
                or snapshot.rollback_plan_hash != rollback.content_hash
                or rollback.source_applied_effect_ids != snapshot.applied_effect_ids
                or snapshot.rollback_cursor > len(rollback.effects)
                or (
                    snapshot.state == "rolled_back_clean"
                    and snapshot.rollback_cursor != len(rollback.effects)
                )
            ):
                raise ControllerStoreCorruptionError("rollback_binding_invalid")
        elif snapshot.rollback_plan_hash is not None:
            raise ControllerStoreCorruptionError("rollback_binding_invalid")
        authorization_states = {
            "apply_authorization_pending": "pending",
            "rollback_authorization_pending": "pending",
            "apply_authorization_claimed": "claimed",
            "rollback_authorization_claimed": "claimed",
            "apply_authorization_consumed": "consumed",
            "rollback_authorization_consumed": "consumed",
            "apply_dispatching": "consumed",
            "rollback_dispatching": "consumed",
        }
        if snapshot.state in authorization_states:
            if (
                snapshot.current_authorization_hash is None
                or snapshot.current_effect_id is None
            ):
                raise ControllerStoreCorruptionError("authorization_binding_invalid")
            authorization_rows = self._connection.execute(
                "SELECT * FROM controller_authorizations WHERE operation_id = ?",
                (operation_id,),
            ).fetchall()
            matching_rows: list[sqlite3.Row] = []
            for authorization_row in authorization_rows:
                try:
                    request = AuthorizationRequest.from_document(
                        _decode_canonical_json(authorization_row["request_json"])
                    )
                except ControllerContractError as exc:
                    raise ControllerStoreCorruptionError(
                        "authorization_request_invalid"
                    ) from exc
                if request.content_hash == snapshot.current_authorization_hash:
                    matching_rows.append(authorization_row)
            if (
                len(matching_rows) != 1
                or matching_rows[0]["effect_id"] != snapshot.current_effect_id
                or matching_rows[0]["state"] != authorization_states[snapshot.state]
            ):
                raise ControllerStoreCorruptionError("authorization_binding_invalid")
        elif (
            snapshot.current_authorization_hash is not None
            or snapshot.current_effect_id is not None
        ):
            raise ControllerStoreCorruptionError("authorization_binding_invalid")
        if snapshot.state in {"apply_dispatching", "rollback_dispatching"}:
            if snapshot.current_attempt_id is None:
                raise ControllerStoreCorruptionError("effect_attempt_binding_invalid")
            attempt_row = self._connection.execute(
                "SELECT * FROM controller_effect_attempts WHERE attempt_id = ?",
                (snapshot.current_attempt_id,),
            ).fetchone()
            if (
                attempt_row is None
                or attempt_row["operation_id"] != operation_id
                or attempt_row["effect_id"] != snapshot.current_effect_id
                or attempt_row["outcome"] != "dispatching"
            ):
                raise ControllerStoreCorruptionError("effect_attempt_binding_invalid")
        elif snapshot.current_attempt_id is not None:
            raise ControllerStoreCorruptionError("effect_attempt_binding_invalid")
        rows = self._connection.execute(
            "SELECT * FROM controller_events WHERE operation_id = ? ORDER BY sequence",
            (operation_id,),
        ).fetchall()
        if len(rows) != snapshot.sequence:
            raise ControllerStoreCorruptionError("event_sequence_invalid")
        previous_hash = "0" * 64
        last_snapshot: OperationSnapshot | None = None
        history: list[tuple[dict[str, object], OperationSnapshot]] = []
        for expected_sequence, event_row in enumerate(rows, 1):
            event = _verify_event_document(_decode_canonical_json(event_row["event_json"]))
            event_snapshot = self._decode_snapshot(event_row["snapshot_json"])
            if (
                event_row["sequence"] != expected_sequence
                or event["sequence"] != expected_sequence
                or event_row["operation_id"] != operation_id
                or event["operation_id"] != operation_id
                or event_row["event_id"] != event["event_id"]
                or event_row["event_kind"] != event["event_kind"]
                or event_row["previous_hash"] != previous_hash
                or event["previous_hash"] != previous_hash
                or event_row["event_hash"] != event["event_hash"]
                or event_row["transition_hash"] != event["transition_hash"]
                or event_snapshot.sequence != expected_sequence
                or event_snapshot.generation != expected_sequence
                or event_snapshot.event_head_hash != event["event_hash"]
                or _snapshot_projection_hash(event_snapshot) != event["transition_hash"]
            ):
                raise ControllerStoreCorruptionError("event_chain_invalid")
            previous_hash = str(event["event_hash"])
            last_snapshot = event_snapshot
            history.append((event, event_snapshot))
        if last_snapshot != snapshot or previous_hash != snapshot.event_head_hash:
            raise ControllerStoreCorruptionError("event_head_invalid")
        try:
            self._verify_semantic_replay(
                operation_id=operation_id,
                idempotency_key=str(row["idempotency_key"]),
                plan=plan,
                rollback=rollback,
                history=history,
            )
        except ControllerContractError as exc:
            raise ControllerStoreCorruptionError("event_semantic_replay_invalid") from exc

    def _verify_authorization_row(self, row: sqlite3.Row) -> None:
        try:
            request = AuthorizationRequest.from_document(
                _decode_canonical_json(row["request_json"])
            )
        except ControllerContractError as exc:
            raise ControllerStoreCorruptionError("authorization_request_invalid") from exc
        if (
            request.authorization_id != row["authorization_id"]
            or request.operation_id != row["operation_id"]
            or request.phase != row["phase"]
            or request.effect_id != row["effect_id"]
            or request.attempt != row["attempt"]
        ):
            raise ControllerStoreCorruptionError("authorization_columns_invalid")
        if row["state"] in {"pending", "claimed"}:
            if row["consumption_json"] is not None:
                raise ControllerStoreCorruptionError("authorization_state_invalid")
        elif row["state"] == "consumed":
            if row["consumption_json"] is None:
                raise ControllerStoreCorruptionError("authorization_state_invalid")
            try:
                consumption = AuthorizationConsumption.from_document(
                    _decode_canonical_json(row["consumption_json"])
                )
            except ControllerContractError as exc:
                raise ControllerStoreCorruptionError("authorization_consumption_invalid") from exc
            if not consumption.matches(request):
                raise ControllerStoreCorruptionError("authorization_consumption_mismatch")
        else:
            raise ControllerStoreCorruptionError("authorization_state_invalid")

    def _verify_attempt_row(self, row: sqlite3.Row) -> None:
        before = self._decode_host_snapshot(row["before_snapshot_json"])
        after = (
            None
            if row["after_snapshot_json"] is None
            else self._decode_host_snapshot(row["after_snapshot_json"])
        )
        if (
            type(row["attempt_id"]) is not str
            or _ID_RE.fullmatch(row["attempt_id"]) is None
            or type(row["request_hash"]) is not str
            or _HASH_RE.fullmatch(row["request_hash"]) is None
            or before is None
        ):
            raise ControllerStoreCorruptionError("effect_attempt_invalid")
        if row["outcome"] == "dispatching":
            if after is not None or row["observation_sequence"] is not None:
                raise ControllerStoreCorruptionError("effect_attempt_state_invalid")
        elif row["outcome"] == "observation_unavailable":
            if after is not None or row["observation_sequence"] is None:
                raise ControllerStoreCorruptionError("effect_attempt_state_invalid")
        elif after is None or row["observation_sequence"] is None:
            raise ControllerStoreCorruptionError("effect_attempt_state_invalid")

    @staticmethod
    def _replay_effect(
        plan: ControllerPlan,
        rollback: RollbackPlan | None,
        snapshot: OperationSnapshot,
        phase: str,
    ):
        if phase == "apply":
            if snapshot.apply_cursor >= len(plan.effects):
                raise ControllerStoreCorruptionError("event_effect_cursor_invalid")
            return plan.effects[snapshot.apply_cursor]
        if (
            phase != "rollback"
            or rollback is None
            or snapshot.rollback_cursor >= len(rollback.effects)
        ):
            raise ControllerStoreCorruptionError("event_effect_cursor_invalid")
        return rollback.effects[snapshot.rollback_cursor]

    def _verify_semantic_replay(
        self,
        *,
        operation_id: str,
        idempotency_key: str,
        plan: ControllerPlan,
        rollback: RollbackPlan | None,
        history: list[tuple[dict[str, object], OperationSnapshot]],
    ) -> None:
        authorization_rows = self._connection.execute(
            "SELECT * FROM controller_authorizations WHERE operation_id = ? "
            "ORDER BY authorization_id",
            (operation_id,),
        ).fetchall()
        requests: dict[str, AuthorizationRequest] = {}
        consumptions: dict[str, AuthorizationConsumption | None] = {}
        authorization_states: dict[str, str] = {}
        for authorization_row in authorization_rows:
            self._verify_authorization_row(authorization_row)
            request = AuthorizationRequest.from_document(
                _decode_canonical_json(authorization_row["request_json"])
            )
            authorization_id = request.authorization_id
            if authorization_id in requests:
                raise ControllerStoreCorruptionError("authorization_bijection_invalid")
            requests[authorization_id] = request
            authorization_states[authorization_id] = str(authorization_row["state"])
            if authorization_row["consumption_json"] is None:
                consumptions[authorization_id] = None
            else:
                consumptions[authorization_id] = AuthorizationConsumption.from_document(
                    _decode_canonical_json(authorization_row["consumption_json"])
                )

        attempt_rows = self._connection.execute(
            "SELECT * FROM controller_effect_attempts WHERE operation_id = ? "
            "ORDER BY attempt_id",
            (operation_id,),
        ).fetchall()
        attempts: dict[str, tuple[sqlite3.Row, HostSnapshot, HostSnapshot | None]] = {}
        for attempt_row in attempt_rows:
            self._verify_attempt_row(attempt_row)
            attempt_id = str(attempt_row["attempt_id"])
            if attempt_id in attempts:
                raise ControllerStoreCorruptionError("effect_attempt_bijection_invalid")
            before_snapshot = self._decode_host_snapshot(
                attempt_row["before_snapshot_json"]
            )
            after_snapshot = (
                None
                if attempt_row["after_snapshot_json"] is None
                else self._decode_host_snapshot(attempt_row["after_snapshot_json"])
            )
            attempts[attempt_id] = (attempt_row, before_snapshot, after_snapshot)

        pending_events: Counter[str] = Counter()
        claimed_events: Counter[str] = Counter()
        consumed_events: Counter[str] = Counter()
        dispatch_events: Counter[str] = Counter()
        observed_events: Counter[str] = Counter()
        rollback_events = 0
        previous: OperationSnapshot | None = None

        for index, (event, actual) in enumerate(history):
            event_kind = str(event["event_kind"])
            bindings = _validate_event_bindings(event_kind, event["bindings"])
            event_hash = str(event["event_hash"])
            if index == 0:
                if event_kind != "operation.created":
                    raise ControllerStoreCorruptionError("operation_create_event_missing")
                expected_bindings = {
                    "plan_hash": plan.content_hash,
                    "ownership_token": plan.ownership_token,
                    "idempotency_key_hash": _document_binding_hash(idempotency_key),
                    "host_scope_id": HOST_SCOPE_ID,
                    "initial_host_snapshot_hash": plan.initial_snapshot.content_hash,
                    "initial_host_projection_hash": host_projection_hash(
                        plan.initial_snapshot
                    ),
                }
                expected = replace(
                    OperationSnapshot.create(operation_id, plan),
                    generation=1,
                    sequence=1,
                    event_head_hash=event_hash,
                )
                expected_event_id = self._event_id(
                    operation_id,
                    "operation.created",
                    idempotency_key,
                )
                if (
                    bindings != expected_bindings
                    or event["event_id"] != expected_event_id
                    or actual != expected
                ):
                    raise ControllerStoreCorruptionError("operation_create_event_invalid")
                previous = actual
                continue

            if previous is None or event_kind == "operation.created":
                raise ControllerStoreCorruptionError("event_replay_invalid")
            candidate = replace(
                previous,
                generation=previous.generation + 1,
                sequence=previous.sequence + 1,
            )
            expected_event_id: str

            if event_kind in {
                "authorization.pending",
                "authorization.claimed",
                "authorization.consumed",
            }:
                authorization_id = str(bindings["authorization_id"])
                request = requests.get(authorization_id)
                if request is None:
                    raise ControllerStoreCorruptionError(
                        "authorization_event_row_missing"
                    )
                if event_kind == "authorization.pending":
                    pending_events[authorization_id] += 1
                    expected_bindings = _request_bindings(request)
                    if (
                        request.operation_id != operation_id
                        or request.plan_hash != plan.content_hash
                        or request.ownership_token != plan.ownership_token
                        or request.expected_generation != previous.generation
                        or request.expected_sequence != previous.sequence
                        or request.expected_head_hash != previous.event_head_hash
                        or request.attempt != previous.next_attempt
                    ):
                        raise ControllerStoreCorruptionError(
                            "authorization_event_request_invalid"
                        )
                    effect = self._replay_effect(
                        plan,
                        rollback,
                        previous,
                        request.phase,
                    )
                    if (
                        previous.state != f"{request.phase}_pending"
                        or request.effect_id != effect.effect_id
                        or effect.ownership_token != plan.ownership_token
                    ):
                        raise ControllerStoreCorruptionError(
                            "authorization_event_effect_invalid"
                        )
                    expected = replace(
                        candidate,
                        state=f"{request.phase}_authorization_pending",
                        current_effect_id=request.effect_id,
                        current_authorization_hash=request.content_hash,
                        current_attempt_id=None,
                        recovery_reason=(
                            None
                            if request.phase == "apply"
                            else candidate.recovery_reason
                        ),
                    )
                    expected_event_id = self._event_id(
                        operation_id,
                        event_kind,
                        request.content_hash,
                    )
                elif event_kind == "authorization.claimed":
                    claimed_events[authorization_id] += 1
                    expected_bindings = _request_bindings(request)
                    if (
                        previous.state
                        != f"{request.phase}_authorization_pending"
                        or previous.current_effect_id != request.effect_id
                        or previous.current_authorization_hash != request.content_hash
                    ):
                        raise ControllerStoreCorruptionError(
                            "authorization_claim_event_invalid"
                        )
                    expected = replace(
                        candidate,
                        state=f"{request.phase}_authorization_claimed",
                    )
                    expected_event_id = self._event_id(
                        operation_id,
                        event_kind,
                        request.content_hash,
                    )
                else:
                    consumed_events[authorization_id] += 1
                    consumption = consumptions.get(authorization_id)
                    if consumption is None or not consumption.matches(request):
                        raise ControllerStoreCorruptionError(
                            "authorization_consumption_event_invalid"
                        )
                    expected_bindings = _consumption_bindings(request, consumption)
                    if (
                        previous.state
                        != f"{request.phase}_authorization_claimed"
                        or previous.current_effect_id != request.effect_id
                        or previous.current_authorization_hash != request.content_hash
                    ):
                        raise ControllerStoreCorruptionError(
                            "authorization_consumption_event_invalid"
                        )
                    expected = replace(
                        candidate,
                        state=f"{request.phase}_authorization_consumed",
                    )
                    expected_event_id = self._event_id(
                        operation_id,
                        event_kind,
                        consumption.content_hash,
                    )
                if bindings != expected_bindings:
                    raise ControllerStoreCorruptionError(
                        "authorization_event_bindings_invalid"
                    )

            elif event_kind == "effect.dispatching":
                attempt_id = str(bindings["attempt_id"])
                attempt_entry = attempts.get(attempt_id)
                if attempt_entry is None:
                    raise ControllerStoreCorruptionError("effect_attempt_event_row_missing")
                dispatch_events[attempt_id] += 1
                attempt_row, before_snapshot, _after_snapshot = attempt_entry
                authorization_id = str(attempt_row["authorization_id"])
                request = requests.get(authorization_id)
                consumption = consumptions.get(authorization_id)
                if request is None or consumption is None:
                    raise ControllerStoreCorruptionError(
                        "effect_attempt_authorization_invalid"
                    )
                effect = self._replay_effect(
                    plan,
                    rollback,
                    previous,
                    request.phase,
                )
                expected_attempt_id = "attempt-" + hashlib.sha256(
                    canonical_controller_bytes(
                        {
                            "request_hash": request.content_hash,
                            "consumption_hash": consumption.content_hash,
                            "before_snapshot_hash": before_snapshot.content_hash,
                        }
                    )
                ).hexdigest()[:32]
                if (
                    previous.state
                    != f"{request.phase}_authorization_consumed"
                    or previous.current_effect_id != effect.effect_id
                    or previous.current_authorization_hash != request.content_hash
                    or attempt_id != expected_attempt_id
                    or attempt_row["operation_id"] != operation_id
                    or attempt_row["phase"] != request.phase
                    or attempt_row["effect_id"] != effect.effect_id
                    or attempt_row["attempt"] != request.attempt
                    or attempt_row["request_hash"] != request.content_hash
                    or attempt_row["dispatch_sequence"] != actual.sequence
                    or classify_effect_snapshot(before_snapshot, effect) != "precondition"
                    or effect.ownership_token != plan.ownership_token
                ):
                    raise ControllerStoreCorruptionError(
                        "effect_dispatch_event_invalid"
                    )
                dispatch_attempt_hash = _attempt_document_hash(
                    attempt_id=attempt_id,
                    operation_id=operation_id,
                    phase=request.phase,
                    effect_id=effect.effect_id,
                    attempt=request.attempt,
                    authorization_id=request.authorization_id,
                    request_hash=request.content_hash,
                    before_snapshot_hash=before_snapshot.content_hash,
                    after_snapshot_hash=None,
                    outcome="dispatching",
                    dispatch_sequence=actual.sequence,
                    observation_sequence=None,
                )
                expected_bindings = {
                    "attempt_id": attempt_id,
                    "attempt_document_hash": dispatch_attempt_hash,
                    "authorization_id": request.authorization_id,
                    "request_hash": request.content_hash,
                    "consumption_hash": consumption.content_hash,
                    "effect_id": effect.effect_id,
                    "effect_hash": effect.content_hash,
                    "phase": request.phase,
                    "attempt": request.attempt,
                    "ownership_token": effect.ownership_token,
                    "before_snapshot_hash": before_snapshot.content_hash,
                    "before_projection_hash": host_projection_hash(before_snapshot),
                }
                if bindings != expected_bindings:
                    raise ControllerStoreCorruptionError(
                        "effect_dispatch_bindings_invalid"
                    )
                expected = replace(
                    candidate,
                    state=f"{request.phase}_dispatching",
                    current_attempt_id=attempt_id,
                    last_host_snapshot_hash=before_snapshot.content_hash,
                )
                expected_event_id = self._event_id(
                    operation_id,
                    event_kind,
                    attempt_id,
                )

            elif event_kind == "effect.observed":
                attempt_id = str(bindings["attempt_id"])
                attempt_entry = attempts.get(attempt_id)
                if attempt_entry is None:
                    raise ControllerStoreCorruptionError("effect_attempt_event_row_missing")
                observed_events[attempt_id] += 1
                attempt_row, before_snapshot, after_snapshot = attempt_entry
                authorization_id = str(attempt_row["authorization_id"])
                request = requests.get(authorization_id)
                consumption = consumptions.get(authorization_id)
                if request is None or consumption is None:
                    raise ControllerStoreCorruptionError(
                        "effect_attempt_authorization_invalid"
                    )
                effect = self._replay_effect(
                    plan,
                    rollback,
                    previous,
                    request.phase,
                )
                outcome = str(attempt_row["outcome"])
                if (
                    previous.state != f"{request.phase}_dispatching"
                    or previous.current_attempt_id != attempt_id
                    or previous.current_effect_id != effect.effect_id
                    or previous.current_authorization_hash != request.content_hash
                    or attempt_row["observation_sequence"] != actual.sequence
                    or bindings["outcome"] != outcome
                ):
                    raise ControllerStoreCorruptionError(
                        "effect_observation_event_invalid"
                    )
                if outcome == "observation_unavailable":
                    if after_snapshot is not None:
                        raise ControllerStoreCorruptionError(
                            "effect_observation_event_invalid"
                        )
                elif (
                    after_snapshot is None
                    or classify_effect_snapshot(after_snapshot, effect) != outcome
                ):
                    raise ControllerStoreCorruptionError(
                        "effect_observation_classification_invalid"
                    )
                after_snapshot_hash = (
                    None if after_snapshot is None else after_snapshot.content_hash
                )
                observation_attempt_hash = _attempt_document_hash(
                    attempt_id=attempt_id,
                    operation_id=operation_id,
                    phase=request.phase,
                    effect_id=effect.effect_id,
                    attempt=request.attempt,
                    authorization_id=request.authorization_id,
                    request_hash=request.content_hash,
                    before_snapshot_hash=before_snapshot.content_hash,
                    after_snapshot_hash=after_snapshot_hash,
                    outcome=outcome,
                    dispatch_sequence=int(attempt_row["dispatch_sequence"]),
                    observation_sequence=actual.sequence,
                )
                expected_bindings = {
                    "attempt_id": attempt_id,
                    "attempt_document_hash": observation_attempt_hash,
                    "authorization_id": request.authorization_id,
                    "request_hash": request.content_hash,
                    "consumption_hash": consumption.content_hash,
                    "effect_id": effect.effect_id,
                    "effect_hash": effect.content_hash,
                    "phase": request.phase,
                    "attempt": request.attempt,
                    "ownership_token": effect.ownership_token,
                    "outcome": outcome,
                    "before_snapshot_hash": before_snapshot.content_hash,
                    "before_projection_hash": host_projection_hash(before_snapshot),
                    "after_snapshot_hash": after_snapshot_hash,
                    "after_projection_hash": (
                        None
                        if after_snapshot is None
                        else host_projection_hash(after_snapshot)
                    ),
                }
                if bindings != expected_bindings:
                    raise ControllerStoreCorruptionError(
                        "effect_observation_bindings_invalid"
                    )
                common = {
                    "next_attempt": candidate.next_attempt + 1,
                    "current_effect_id": None,
                    "current_authorization_hash": None,
                    "current_attempt_id": None,
                    "last_host_snapshot_hash": (
                        candidate.last_host_snapshot_hash
                        if after_snapshot is None
                        else after_snapshot.content_hash
                    ),
                }
                if outcome in {"foreign", "observation_unavailable"}:
                    expected = replace(
                        candidate,
                        state="recovery_required",
                        recovery_reason=(
                            "host_state_foreign"
                            if outcome == "foreign"
                            else "host_observation_unavailable"
                        ),
                        **common,
                    )
                elif request.phase == "apply":
                    if outcome == "postcondition":
                        cursor = candidate.apply_cursor + 1
                        expected = replace(
                            candidate,
                            state=(
                                "prepared_unverified"
                                if cursor == len(plan.effects)
                                else "apply_pending"
                            ),
                            apply_cursor=cursor,
                            applied_effect_ids=(
                                *candidate.applied_effect_ids,
                                effect.effect_id,
                            ),
                            recovery_reason=None,
                            **common,
                        )
                    else:
                        expected = replace(
                            candidate,
                            state="apply_pending",
                            recovery_reason=None,
                            **common,
                        )
                else:
                    if rollback is None:
                        raise ControllerStoreCorruptionError("rollback_missing")
                    if outcome == "postcondition":
                        cursor = candidate.rollback_cursor + 1
                        cleanup_complete = cursor == len(rollback.effects)
                        clean_proven = (
                            cleanup_complete
                            and after_snapshot is not None
                            and is_reusable_clean_projection(
                                after_snapshot,
                                plan.initial_snapshot,
                            )
                        )
                        if clean_proven:
                            recovery_reason = None
                        elif cleanup_complete:
                            recovery_reason = (
                                candidate.recovery_reason
                                or "host_state_not_reusable"
                            )
                        else:
                            recovery_reason = candidate.recovery_reason
                        expected = replace(
                            candidate,
                            state=(
                                "rolled_back_clean"
                                if clean_proven
                                else "recovery_required"
                                if cleanup_complete
                                else "rollback_pending"
                            ),
                            rollback_cursor=cursor,
                            recovery_reason=recovery_reason,
                            **common,
                        )
                    else:
                        expected = replace(
                            candidate,
                            state="rollback_pending",
                            recovery_reason=candidate.recovery_reason,
                            **common,
                        )
                expected_event_id = self._event_id(
                    operation_id,
                    event_kind,
                    f"{attempt_id}:{outcome}",
                )

            elif event_kind == "operation.recovery_required":
                if previous.state == "rolled_back_clean":
                    raise ControllerStoreCorruptionError(
                        "recovery_event_source_state_invalid"
                    )
                observed_hash = bindings["observed_snapshot_hash"]
                reason = str(bindings["reason"])
                expected = replace(
                    candidate,
                    state="recovery_required",
                    recovery_reason=reason,
                    last_host_snapshot_hash=(
                        candidate.last_host_snapshot_hash
                        if observed_hash is None
                        else str(observed_hash)
                    ),
                    current_effect_id=None,
                    current_authorization_hash=None,
                    current_attempt_id=None,
                )
                recovery_identity = hashlib.sha256(
                    canonical_controller_bytes(
                        {
                            "reason": reason,
                            "expected_head_hash": previous.event_head_hash,
                            "snapshot_hash": observed_hash,
                        }
                    )
                ).hexdigest()
                expected_event_id = self._event_id(
                    operation_id,
                    event_kind,
                    recovery_identity,
                )

            elif event_kind == "rollback.prepared":
                rollback_events += 1
                if (
                    rollback is None
                    or previous.state
                    not in {"apply_pending", "prepared_unverified", "recovery_required"}
                    or rollback
                    != build_rollback_plan(
                        operation_id,
                        plan,
                        previous.applied_effect_ids,
                    )
                ):
                    raise ControllerStoreCorruptionError("rollback_event_invalid")
                expected_bindings = {
                    "rollback_plan_hash": rollback.content_hash,
                    "ownership_token": rollback.ownership_token,
                    "clean_snapshot": bindings["clean_snapshot"],
                    "clean_snapshot_hash": bindings["clean_snapshot_hash"],
                    "clean_projection_hash": bindings["clean_projection_hash"],
                }
                if rollback.effects:
                    if (
                        bindings["clean_snapshot"] is not None
                        or bindings["clean_snapshot_hash"] is not None
                        or bindings["clean_projection_hash"] is not None
                    ):
                        raise ControllerStoreCorruptionError("rollback_event_invalid")
                    clean_snapshot = None
                else:
                    try:
                        clean_snapshot = HostSnapshot.from_document(
                            bindings["clean_snapshot"]
                        )
                    except (ControllerContractError, TypeError) as exc:
                        raise ControllerStoreCorruptionError(
                            "rollback_event_invalid"
                        ) from exc
                    if (
                        bindings["clean_snapshot_hash"]
                        != clean_snapshot.content_hash
                        or bindings["clean_projection_hash"]
                        != host_projection_hash(clean_snapshot)
                        or not is_reusable_clean_projection(
                            clean_snapshot,
                            plan.initial_snapshot,
                        )
                    ):
                        raise ControllerStoreCorruptionError("rollback_event_invalid")
                if bindings != expected_bindings:
                    raise ControllerStoreCorruptionError("rollback_event_invalid")
                terminal = not rollback.effects
                expected = replace(
                    candidate,
                    state=(
                        "rolled_back_clean"
                        if terminal
                        else "rollback_pending"
                    ),
                    rollback_cursor=0,
                    rollback_plan_hash=rollback.content_hash,
                    current_effect_id=None,
                    current_authorization_hash=None,
                    current_attempt_id=None,
                    recovery_reason=(None if terminal else candidate.recovery_reason),
                    last_host_snapshot_hash=(
                        candidate.last_host_snapshot_hash
                        if clean_snapshot is None
                        else clean_snapshot.content_hash
                    ),
                )
                expected_event_id = self._event_id(
                    operation_id,
                    event_kind,
                    rollback.content_hash,
                )
            else:
                raise ControllerStoreCorruptionError("event_kind_invalid")

            expected = replace(expected, event_head_hash=event_hash)
            if event["event_id"] != expected_event_id or expected != actual:
                raise ControllerStoreCorruptionError("event_semantic_transition_invalid")
            previous = actual

        if set(requests) != set(pending_events):
            raise ControllerStoreCorruptionError("authorization_bijection_invalid")
        for authorization_id, state in authorization_states.items():
            if pending_events[authorization_id] != 1:
                raise ControllerStoreCorruptionError("authorization_bijection_invalid")
            expected_claimed = 1 if state in {"claimed", "consumed"} else 0
            expected_consumed = 1 if state == "consumed" else 0
            if (
                claimed_events[authorization_id] != expected_claimed
                or consumed_events[authorization_id] != expected_consumed
            ):
                raise ControllerStoreCorruptionError("authorization_bijection_invalid")
        if set(attempts) != set(dispatch_events):
            raise ControllerStoreCorruptionError("effect_attempt_bijection_invalid")
        for attempt_id, (attempt_row, _before, _after) in attempts.items():
            if dispatch_events[attempt_id] != 1:
                raise ControllerStoreCorruptionError("effect_attempt_bijection_invalid")
            expected_observed = 0 if attempt_row["outcome"] == "dispatching" else 1
            if observed_events[attempt_id] != expected_observed:
                raise ControllerStoreCorruptionError("effect_attempt_bijection_invalid")
        if rollback_events != (0 if rollback is None else 1):
            raise ControllerStoreCorruptionError("rollback_event_bijection_invalid")

    def _safe_rollback(self) -> None:
        try:
            self._connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _commit(self) -> None:
        self._connection.execute("COMMIT")

    def _probe_operation_state(self, operation_id: str) -> bytes:
        probe = sqlite3.connect(self._path, isolation_level=None, timeout=30.0)
        try:
            return _operation_state_bytes(probe, operation_id)
        finally:
            probe.close()

    def _poison_operation(self, operation_id: str) -> None:
        self._poisoned_operations.add(operation_id)
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                "UPDATE controller_operations SET poisoned = 1 WHERE operation_id = ?",
                (operation_id,),
            )
            self._connection.execute("COMMIT")
        except sqlite3.Error:
            self._safe_rollback()

    def _finish_commit(
        self,
        operation_id: str,
        *,
        pre_state: bytes,
        post_state: bytes,
    ) -> bool:
        try:
            self._commit()
            return True
        except BaseException as exc:
            self._safe_rollback()
            observed = self._probe_operation_state(operation_id)
            if observed == post_state:
                try:
                    self._verify_all_rows()
                except ControllerStoreError:
                    self._poison_operation(operation_id)
                    raise ControllerStoreRecoveryRequired(
                        "commit_post_state_related_rows_invalid"
                    ) from exc
                else:
                    return False
            if observed == pre_state:
                raise ControllerStoreCommitNotApplied("commit_reconciled_pre_state") from exc
            self._poison_operation(operation_id)
            raise ControllerStoreRecoveryRequired("commit_state_indeterminate") from exc

    @staticmethod
    def _event_id(operation_id: str, event_kind: str, identity: str) -> str:
        return "event-" + hashlib.sha256(
            canonical_controller_bytes(
                {
                    "operation_id": operation_id,
                    "event_kind": event_kind,
                    "identity": identity,
                }
            )
        ).hexdigest()[:32]

    def create_operation(
        self,
        initial: OperationSnapshot,
        plan: ControllerPlan,
        *,
        idempotency_key: str,
    ) -> ControllerStoreTransition:
        self._ensure_open()
        _validate_identifier(idempotency_key, "idempotency_key_invalid")
        try:
            initial = OperationSnapshot.from_document(initial.to_document())
            plan = ControllerPlan.from_document(plan.to_document())
        except ControllerContractError as exc:
            raise ControllerStoreError("operation_input_invalid") from exc
        if initial != OperationSnapshot.create(initial.operation_id, plan):
            raise ControllerStoreError("operation_initial_state_invalid")
        operation_id = initial.operation_id
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            pre_state = _operation_state_bytes(self._connection, operation_id)
            existing = self._connection.execute(
                "SELECT idempotency_key, plan_json, snapshot_json FROM controller_operations "
                "WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if existing is not None:
                self._connection.execute("ROLLBACK")
                if (
                    existing["idempotency_key"] != idempotency_key
                    or existing["plan_json"] != _encode_document(plan.to_document())
                ):
                    raise ControllerStoreDuplicateMismatch("operation_identity_reused")
                return ControllerStoreTransition(
                    snapshot=self._decode_snapshot(existing["snapshot_json"]),
                    committed_now=False,
                )
            lease = self._connection.execute(
                "SELECT operation_id, ownership_token FROM controller_host_scope_leases "
                "WHERE scope_id = ?",
                (HOST_SCOPE_ID,),
            ).fetchone()
            if lease is not None:
                self._connection.execute("ROLLBACK")
                raise ControllerStoreConflictError("host_scope_lease_conflict")
            candidate = replace(
                initial,
                generation=1,
                sequence=1,
                event_head_hash="f" * 64,
            )
            transition_hash = _snapshot_projection_hash(candidate)
            event_id = self._event_id(operation_id, "operation.created", idempotency_key)
            event = _event_document(
                event_id=event_id,
                operation_id=operation_id,
                sequence=1,
                event_kind="operation.created",
                previous_hash=initial.event_head_hash,
                transition_hash=transition_hash,
                bindings={
                    "plan_hash": plan.content_hash,
                    "ownership_token": plan.ownership_token,
                    "idempotency_key_hash": _document_binding_hash(idempotency_key),
                    "host_scope_id": HOST_SCOPE_ID,
                    "initial_host_snapshot_hash": plan.initial_snapshot.content_hash,
                    "initial_host_projection_hash": host_projection_hash(
                        plan.initial_snapshot
                    ),
                },
            )
            after = replace(candidate, event_head_hash=str(event["event_hash"]))
            plan_bytes = _encode_document(plan.to_document())
            after_bytes = _encode_document(after.to_document())
            self._connection.execute(
                "INSERT INTO controller_operations("
                "operation_id, idempotency_key, plan_json, snapshot_json, rollback_json, "
                "generation, sequence, head_hash, state, poisoned"
                ") VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, 0)",
                (
                    operation_id,
                    idempotency_key,
                    plan_bytes,
                    after_bytes,
                    after.generation,
                    after.sequence,
                    after.event_head_hash,
                    after.state,
                ),
            )
            self._connection.execute(
                "INSERT INTO controller_host_scope_leases("
                "scope_id, operation_id, ownership_token, acquired_sequence, state"
                ") VALUES (?, ?, ?, 1, 'active')",
                (HOST_SCOPE_ID, operation_id, plan.ownership_token),
            )
            self._connection.execute(
                "INSERT INTO controller_events("
                "operation_id, sequence, event_id, event_kind, previous_hash, event_hash, "
                "transition_hash, event_json, snapshot_json"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    operation_id,
                    1,
                    event_id,
                    "operation.created",
                    initial.event_head_hash,
                    event["event_hash"],
                    transition_hash,
                    _encode_document(event),
                    after_bytes,
                ),
            )
            post_state = _operation_state_bytes(self._connection, operation_id)
            committed_now = self._finish_commit(
                operation_id,
                pre_state=pre_state,
                post_state=post_state,
            )
        except (ControllerStoreError, ControllerContractError):
            self._safe_rollback()
            raise
        except sqlite3.IntegrityError as exc:
            self._safe_rollback()
            raise ControllerStoreDuplicateMismatch("operation_unique_conflict") from exc
        except BaseException:
            self._safe_rollback()
            raise
        self._verify_operation(operation_id)
        return ControllerStoreTransition(snapshot=after, committed_now=committed_now)

    def _raw_operation_row(self, operation_id: str) -> sqlite3.Row:
        if operation_id in self._poisoned_operations:
            raise ControllerStoreRecoveryRequired("operation_poisoned")
        row = self._connection.execute(
            "SELECT * FROM controller_operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise ControllerStoreError("operation_not_found")
        if row["poisoned"] == 1:
            self._poisoned_operations.add(operation_id)
            raise ControllerStoreRecoveryRequired("operation_poisoned")
        return row

    def load_operation(self, operation_id: str) -> OperationSnapshot:
        self._ensure_open()
        _validate_identifier(operation_id, "operation_id_invalid")
        row = self._raw_operation_row(operation_id)
        snapshot = self._decode_snapshot(row["snapshot_json"])
        if (
            snapshot.generation != row["generation"]
            or snapshot.sequence != row["sequence"]
            or snapshot.event_head_hash != row["head_hash"]
            or snapshot.state != row["state"]
        ):
            raise ControllerStoreCorruptionError("operation_columns_invalid")
        return snapshot

    def load_plan(self, operation_id: str) -> ControllerPlan:
        self._ensure_open()
        return self._decode_plan(self._raw_operation_row(operation_id)["plan_json"])

    def load_rollback_plan(self, operation_id: str) -> RollbackPlan | None:
        self._ensure_open()
        value = self._raw_operation_row(operation_id)["rollback_json"]
        return None if value is None else self._decode_rollback(value)

    def event_documents(self, operation_id: str) -> tuple[dict[str, object], ...]:
        self._ensure_open()
        self._raw_operation_row(operation_id)
        rows = self._connection.execute(
            "SELECT event_json FROM controller_events WHERE operation_id = ? ORDER BY sequence",
            (operation_id,),
        ).fetchall()
        return tuple(
            _verify_event_document(_decode_canonical_json(row[0])) for row in rows
        )

    def _validate_expected(self, row: sqlite3.Row, expected: OperationSnapshot) -> bytes:
        current_bytes = row["snapshot_json"]
        current = self._decode_snapshot(current_bytes)
        if (
            current != expected
            or row["generation"] != expected.generation
            or row["sequence"] != expected.sequence
            or row["head_hash"] != expected.event_head_hash
            or row["state"] != expected.state
        ):
            raise ControllerStoreConflictError("operation_cas_conflict")
        return current_bytes

    def _append_transition(
        self,
        expected: OperationSnapshot,
        *,
        event_kind: str,
        identity: str,
        bindings: dict[str, object],
        mutation: Callable[[OperationSnapshot], OperationSnapshot],
        auxiliary: Callable[[sqlite3.Connection, OperationSnapshot], None] | None = None,
        rollback_plan: RollbackPlan | None | object = ...,
    ) -> ControllerStoreTransition:
        operation_id = expected.operation_id
        event_id = self._event_id(operation_id, event_kind, identity)
        candidate = mutation(
            replace(
                expected,
                generation=expected.generation + 1,
                sequence=expected.sequence + 1,
            )
        )
        transition_hash = _snapshot_projection_hash(candidate)
        event = _event_document(
            event_id=event_id,
            operation_id=operation_id,
            sequence=candidate.sequence,
            event_kind=event_kind,
            previous_hash=expected.event_head_hash,
            transition_hash=transition_hash,
            bindings=bindings,
        )
        after = replace(candidate, event_head_hash=str(event["event_hash"]))
        after_bytes = _encode_document(after.to_document())
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            pre_state = _operation_state_bytes(self._connection, operation_id)
            duplicate = self._connection.execute(
                "SELECT event_kind, transition_hash, event_json, snapshot_json "
                "FROM controller_events "
                "WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if duplicate is not None:
                self._connection.execute("ROLLBACK")
                if (
                    duplicate["event_kind"] != event_kind
                    or duplicate["transition_hash"] != transition_hash
                    or duplicate["event_json"] != _encode_document(event)
                ):
                    raise ControllerStoreDuplicateMismatch("event_identity_reused")
                return ControllerStoreTransition(
                    snapshot=self._decode_snapshot(duplicate["snapshot_json"]),
                    committed_now=False,
                )
            row = self._raw_operation_row(operation_id)
            self._validate_expected(row, expected)
            if auxiliary is not None:
                auxiliary(self._connection, after)
            if rollback_plan is ...:
                rollback_bytes = row["rollback_json"]
            elif rollback_plan is None:
                rollback_bytes = None
            else:
                rollback_bytes = _encode_document(rollback_plan.to_document())
            cursor = self._connection.execute(
                "UPDATE controller_operations SET snapshot_json = ?, rollback_json = ?, "
                "generation = ?, sequence = ?, head_hash = ?, state = ? "
                "WHERE operation_id = ? AND generation = ? AND sequence = ? "
                "AND head_hash = ? AND state = ? AND poisoned = 0",
                (
                    after_bytes,
                    rollback_bytes,
                    after.generation,
                    after.sequence,
                    after.event_head_hash,
                    after.state,
                    operation_id,
                    expected.generation,
                    expected.sequence,
                    expected.event_head_hash,
                    expected.state,
                ),
            )
            if cursor.rowcount != 1:
                raise ControllerStoreConflictError("operation_cas_conflict")
            self._connection.execute(
                "INSERT INTO controller_events("
                "operation_id, sequence, event_id, event_kind, previous_hash, event_hash, "
                "transition_hash, event_json, snapshot_json"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    operation_id,
                    after.sequence,
                    event_id,
                    event_kind,
                    expected.event_head_hash,
                    after.event_head_hash,
                    transition_hash,
                    _encode_document(event),
                    after_bytes,
                ),
            )
            post_state = _operation_state_bytes(self._connection, operation_id)
            committed_now = self._finish_commit(
                operation_id,
                pre_state=pre_state,
                post_state=post_state,
            )
        except (ControllerStoreError, ControllerContractError):
            self._safe_rollback()
            raise
        except sqlite3.IntegrityError as exc:
            self._safe_rollback()
            raise ControllerStoreDuplicateMismatch("transition_unique_conflict") from exc
        except BaseException:
            self._safe_rollback()
            raise
        return ControllerStoreTransition(snapshot=after, committed_now=committed_now)

    def _normalize_request(self, request: AuthorizationRequest) -> AuthorizationRequest:
        try:
            return AuthorizationRequest.from_document(request.to_document())
        except ControllerContractError as exc:
            row = self._connection.execute(
                "SELECT request_json FROM controller_authorizations WHERE authorization_id = ?",
                (request.authorization_id,),
            ).fetchone()
            if row is not None:
                raise ControllerStoreDuplicateMismatch("authorization_identity_reused") from exc
            raise ControllerStoreError("authorization_request_invalid") from exc

    def _effect_for_request(
        self,
        expected: OperationSnapshot,
        request: AuthorizationRequest,
    ):
        if (
            request.operation_id != expected.operation_id
            or request.plan_hash != expected.plan_hash
            or request.ownership_token != expected.ownership_token
            or request.expected_generation != expected.generation
            or request.expected_sequence != expected.sequence
            or request.expected_head_hash != expected.event_head_hash
            or request.attempt != expected.next_attempt
        ):
            raise ControllerStoreConflictError("authorization_cas_mismatch")
        plan = self.load_plan(expected.operation_id)
        if request.ownership_token != plan.ownership_token:
            raise ControllerStoreConflictError("authorization_ownership_mismatch")
        if request.phase == "apply":
            if expected.state != "apply_pending" or expected.apply_cursor >= len(plan.effects):
                raise ControllerStoreConflictError("authorization_state_mismatch")
            effect = plan.effects[expected.apply_cursor]
        else:
            rollback = self.load_rollback_plan(expected.operation_id)
            if (
                expected.state != "rollback_pending"
                or rollback is None
                or expected.rollback_cursor >= len(rollback.effects)
            ):
                raise ControllerStoreConflictError("authorization_state_mismatch")
            effect = rollback.effects[expected.rollback_cursor]
        if request.effect_id != effect.effect_id:
            raise ControllerStoreConflictError("authorization_effect_mismatch")
        return effect

    def record_authorization_pending(
        self,
        expected: OperationSnapshot,
        request: AuthorizationRequest,
    ) -> ControllerStoreTransition:
        self._ensure_open()
        existing = self._connection.execute(
            "SELECT request_json FROM controller_authorizations WHERE authorization_id = ?",
            (request.authorization_id,),
        ).fetchone()
        request_bytes = _encode_document(request.to_document())
        if existing is not None and existing["request_json"] != request_bytes:
            raise ControllerStoreDuplicateMismatch("authorization_identity_reused")
        request = self._normalize_request(request)
        self._effect_for_request(expected, request)
        next_state = f"{request.phase}_authorization_pending"

        def mutation(snapshot: OperationSnapshot) -> OperationSnapshot:
            return replace(
                snapshot,
                state=next_state,
                current_effect_id=request.effect_id,
                current_authorization_hash=request.content_hash,
                current_attempt_id=None,
                recovery_reason=(
                    None if request.phase == "apply" else snapshot.recovery_reason
                ),
            )

        def auxiliary(connection: sqlite3.Connection, _after: OperationSnapshot) -> None:
            connection.execute(
                "INSERT INTO controller_authorizations("
                "authorization_id, operation_id, phase, effect_id, attempt, request_json, "
                "consumption_json, state"
                ") VALUES (?, ?, ?, ?, ?, ?, NULL, 'pending')",
                (
                    request.authorization_id,
                    request.operation_id,
                    request.phase,
                    request.effect_id,
                    request.attempt,
                    request_bytes,
                ),
            )

        return self._append_transition(
            expected,
            event_kind="authorization.pending",
            identity=request.content_hash,
            bindings=_request_bindings(request),
            mutation=mutation,
            auxiliary=auxiliary,
        )

    def record_authorization_claimed(
        self,
        expected: OperationSnapshot,
        request: AuthorizationRequest,
    ) -> ControllerStoreTransition:
        self._ensure_open()
        request = self._normalize_request(request)
        if (
            expected.state != f"{request.phase}_authorization_pending"
            or expected.current_effect_id != request.effect_id
            or expected.current_authorization_hash != request.content_hash
        ):
            raise ControllerStoreConflictError("authorization_claim_mismatch")

        def mutation(snapshot: OperationSnapshot) -> OperationSnapshot:
            return replace(snapshot, state=f"{request.phase}_authorization_claimed")

        def auxiliary(connection: sqlite3.Connection, _after: OperationSnapshot) -> None:
            cursor = connection.execute(
                "UPDATE controller_authorizations SET state = 'claimed' "
                "WHERE authorization_id = ? AND state = 'pending' AND request_json = ?",
                (
                    request.authorization_id,
                    _encode_document(request.to_document()),
                ),
            )
            if cursor.rowcount != 1:
                raise ControllerStoreConflictError("authorization_claim_conflict")

        return self._append_transition(
            expected,
            event_kind="authorization.claimed",
            identity=request.content_hash,
            bindings=_request_bindings(request),
            mutation=mutation,
            auxiliary=auxiliary,
        )

    def _authorization_row(
        self,
        request: AuthorizationRequest,
        *,
        required_state: str,
    ) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM controller_authorizations WHERE authorization_id = ?",
            (request.authorization_id,),
        ).fetchone()
        if row is None:
            raise ControllerStoreCorruptionError("authorization_missing")
        if row["request_json"] != _encode_document(request.to_document()):
            raise ControllerStoreDuplicateMismatch("authorization_identity_reused")
        if row["state"] != required_state:
            raise ControllerStoreConflictError("authorization_state_mismatch")
        return row

    def record_authorization_consumed(
        self,
        expected: OperationSnapshot,
        request: AuthorizationRequest,
        consumption: AuthorizationConsumption,
    ) -> ControllerStoreTransition:
        self._ensure_open()
        request = self._normalize_request(request)
        try:
            consumption = AuthorizationConsumption.from_document(consumption.to_document())
        except ControllerContractError as exc:
            raise ControllerStoreError("authorization_consumption_invalid") from exc
        if (
            expected.state != f"{request.phase}_authorization_claimed"
            or expected.current_effect_id != request.effect_id
            or expected.current_authorization_hash != request.content_hash
            or not consumption.matches(request)
        ):
            raise ControllerStoreConflictError("authorization_consumption_mismatch")
        consumption_bytes = _encode_document(consumption.to_document())

        def mutation(snapshot: OperationSnapshot) -> OperationSnapshot:
            return replace(snapshot, state=f"{request.phase}_authorization_consumed")

        def auxiliary(connection: sqlite3.Connection, _after: OperationSnapshot) -> None:
            cursor = connection.execute(
                "UPDATE controller_authorizations SET consumption_json = ?, state = 'consumed' "
                "WHERE authorization_id = ? AND state = 'claimed' AND request_json = ?",
                (
                    consumption_bytes,
                    request.authorization_id,
                    _encode_document(request.to_document()),
                ),
            )
            if cursor.rowcount != 1:
                raise ControllerStoreConflictError("authorization_consumption_conflict")

        return self._append_transition(
            expected,
            event_kind="authorization.consumed",
            identity=consumption.content_hash,
            bindings=_consumption_bindings(request, consumption),
            mutation=mutation,
            auxiliary=auxiliary,
        )

    def load_authorization_consumption(
        self,
        authorization_id: str,
    ) -> AuthorizationConsumption | None:
        self._ensure_open()
        row = self._connection.execute(
            "SELECT consumption_json FROM controller_authorizations WHERE authorization_id = ?",
            (authorization_id,),
        ).fetchone()
        if row is None:
            raise ControllerStoreError("authorization_not_found")
        if row[0] is None:
            return None
        try:
            return AuthorizationConsumption.from_document(_decode_canonical_json(row[0]))
        except ControllerContractError as exc:
            raise ControllerStoreCorruptionError("authorization_consumption_invalid") from exc

    def load_authorization_request(self, request_hash: str) -> AuthorizationRequest:
        """Load the one canonical request bound to an in-flight operation state."""

        self._ensure_open()
        if type(request_hash) is not str or _HASH_RE.fullmatch(request_hash) is None:
            raise ControllerStoreError("authorization_request_hash_invalid")
        rows = self._connection.execute(
            "SELECT request_json FROM controller_authorizations ORDER BY authorization_id"
        ).fetchall()
        matches: list[AuthorizationRequest] = []
        for row in rows:
            try:
                request = AuthorizationRequest.from_document(
                    _decode_canonical_json(row["request_json"])
                )
            except ControllerContractError as exc:
                raise ControllerStoreCorruptionError("authorization_request_invalid") from exc
            if request.content_hash == request_hash:
                matches.append(request)
        if len(matches) != 1:
            raise ControllerStoreCorruptionError("authorization_request_binding_invalid")
        return matches[0]

    def record_dispatching(
        self,
        expected: OperationSnapshot,
        request: AuthorizationRequest,
        consumption: AuthorizationConsumption,
        before_snapshot: HostSnapshot,
    ) -> ControllerStoreTransition:
        self._ensure_open()
        request = self._normalize_request(request)
        try:
            before_snapshot = HostSnapshot.from_document(before_snapshot.to_document())
            consumption = AuthorizationConsumption.from_document(consumption.to_document())
        except ControllerContractError as exc:
            raise ControllerStoreError("dispatch_input_invalid") from exc
        if (
            expected.state != f"{request.phase}_authorization_consumed"
            or expected.current_effect_id != request.effect_id
            or expected.current_authorization_hash != request.content_hash
            or not consumption.matches(request)
        ):
            raise ControllerStoreConflictError("dispatch_state_mismatch")
        row = self._authorization_row(request, required_state="consumed")
        if row["consumption_json"] != _encode_document(consumption.to_document()):
            raise ControllerStoreDuplicateMismatch("consumption_identity_reused")
        plan = self.load_plan(expected.operation_id)
        if request.phase == "apply":
            effect = plan.effects[expected.apply_cursor]
        else:
            rollback = self.load_rollback_plan(expected.operation_id)
            if rollback is None:
                raise ControllerStoreCorruptionError("rollback_missing")
            effect = rollback.effects[expected.rollback_cursor]
        if classify_effect_snapshot(before_snapshot, effect) != "precondition":
            raise ControllerStoreConflictError("dispatch_precondition_not_exact")
        attempt_id = "attempt-" + hashlib.sha256(
            canonical_controller_bytes(
                {
                    "request_hash": request.content_hash,
                    "consumption_hash": consumption.content_hash,
                    "before_snapshot_hash": before_snapshot.content_hash,
                }
            )
        ).hexdigest()[:32]
        before_bytes = _encode_document(before_snapshot.to_document())
        dispatch_sequence = expected.sequence + 1
        attempt_document_hash = _attempt_document_hash(
            attempt_id=attempt_id,
            operation_id=request.operation_id,
            phase=request.phase,
            effect_id=request.effect_id,
            attempt=request.attempt,
            authorization_id=request.authorization_id,
            request_hash=request.content_hash,
            before_snapshot_hash=before_snapshot.content_hash,
            after_snapshot_hash=None,
            outcome="dispatching",
            dispatch_sequence=dispatch_sequence,
            observation_sequence=None,
        )

        def mutation(snapshot: OperationSnapshot) -> OperationSnapshot:
            return replace(
                snapshot,
                state=f"{request.phase}_dispatching",
                current_attempt_id=attempt_id,
                last_host_snapshot_hash=before_snapshot.content_hash,
            )

        def auxiliary(connection: sqlite3.Connection, after: OperationSnapshot) -> None:
            connection.execute(
                "INSERT INTO controller_effect_attempts("
                "attempt_id, operation_id, phase, effect_id, attempt, authorization_id, "
                "request_hash, before_snapshot_json, after_snapshot_json, outcome, "
                "dispatch_sequence, observation_sequence"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 'dispatching', ?, NULL)",
                (
                    attempt_id,
                    request.operation_id,
                    request.phase,
                    request.effect_id,
                    request.attempt,
                    request.authorization_id,
                    request.content_hash,
                    before_bytes,
                    after.sequence,
                ),
            )

        return self._append_transition(
            expected,
            event_kind="effect.dispatching",
            identity=attempt_id,
            bindings={
                "attempt_id": attempt_id,
                "attempt_document_hash": attempt_document_hash,
                "authorization_id": request.authorization_id,
                "request_hash": request.content_hash,
                "consumption_hash": consumption.content_hash,
                "effect_id": effect.effect_id,
                "effect_hash": effect.content_hash,
                "phase": request.phase,
                "attempt": request.attempt,
                "ownership_token": effect.ownership_token,
                "before_snapshot_hash": before_snapshot.content_hash,
                "before_projection_hash": host_projection_hash(before_snapshot),
            },
            mutation=mutation,
            auxiliary=auxiliary,
        )

    def record_effect_observation(
        self,
        expected: OperationSnapshot,
        request: AuthorizationRequest,
        observed_snapshot: HostSnapshot | None,
        *,
        outcome: str,
    ) -> ControllerStoreTransition:
        self._ensure_open()
        request = self._normalize_request(request)
        if (
            expected.state != f"{request.phase}_dispatching"
            or expected.current_attempt_id is None
            or expected.current_effect_id != request.effect_id
            or expected.current_authorization_hash != request.content_hash
        ):
            raise ControllerStoreConflictError("observation_state_mismatch")
        if outcome not in {
            "precondition",
            "postcondition",
            "foreign",
            "observation_unavailable",
        }:
            raise ControllerStoreError("observation_outcome_invalid")
        if observed_snapshot is None:
            if outcome != "observation_unavailable":
                raise ControllerStoreError("observation_snapshot_missing")
        else:
            try:
                observed_snapshot = HostSnapshot.from_document(observed_snapshot.to_document())
            except ControllerContractError as exc:
                raise ControllerStoreError("observation_snapshot_invalid") from exc
        plan = self.load_plan(expected.operation_id)
        if request.phase == "apply":
            effect = plan.effects[expected.apply_cursor]
        else:
            rollback = self.load_rollback_plan(expected.operation_id)
            if rollback is None:
                raise ControllerStoreCorruptionError("rollback_missing")
            effect = rollback.effects[expected.rollback_cursor]
        if (
            observed_snapshot is not None
            and classify_effect_snapshot(observed_snapshot, effect) != outcome
        ):
            raise ControllerStoreError("observation_classification_mismatch")
        after_bytes = (
            None
            if observed_snapshot is None
            else _encode_document(observed_snapshot.to_document())
        )
        attempt_id = expected.current_attempt_id
        attempt_row = self._connection.execute(
            "SELECT * FROM controller_effect_attempts WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        exact_attempt_identity = (
            attempt_row is not None
            and attempt_row["operation_id"] == expected.operation_id
            and attempt_row["phase"] == request.phase
            and attempt_row["effect_id"] == request.effect_id
            and attempt_row["attempt"] == request.attempt
            and attempt_row["authorization_id"] == request.authorization_id
            and attempt_row["request_hash"] == request.content_hash
        )
        dispatching_row = (
            exact_attempt_identity
            and attempt_row["outcome"] == "dispatching"
            and attempt_row["after_snapshot_json"] is None
            and attempt_row["observation_sequence"] is None
        )
        exact_observed_duplicate = (
            exact_attempt_identity
            and attempt_row["outcome"] == outcome
            and attempt_row["after_snapshot_json"] == after_bytes
            and attempt_row["observation_sequence"] == expected.sequence + 1
        )
        if not dispatching_row and not exact_observed_duplicate:
            raise ControllerStoreCorruptionError("effect_attempt_binding_invalid")
        before_snapshot = self._decode_host_snapshot(attempt_row["before_snapshot_json"])
        authorization_row = self._authorization_row(request, required_state="consumed")
        try:
            consumption = AuthorizationConsumption.from_document(
                _decode_canonical_json(authorization_row["consumption_json"])
            )
        except (ControllerContractError, ControllerStoreCorruptionError) as exc:
            raise ControllerStoreCorruptionError(
                "authorization_consumption_invalid"
            ) from exc
        observation_sequence = expected.sequence + 1
        after_snapshot_hash = (
            None if observed_snapshot is None else observed_snapshot.content_hash
        )
        attempt_document_hash = _attempt_document_hash(
            attempt_id=attempt_id,
            operation_id=request.operation_id,
            phase=request.phase,
            effect_id=request.effect_id,
            attempt=request.attempt,
            authorization_id=request.authorization_id,
            request_hash=request.content_hash,
            before_snapshot_hash=before_snapshot.content_hash,
            after_snapshot_hash=after_snapshot_hash,
            outcome=outcome,
            dispatch_sequence=int(attempt_row["dispatch_sequence"]),
            observation_sequence=observation_sequence,
        )

        def mutation(snapshot: OperationSnapshot) -> OperationSnapshot:
            common = {
                "next_attempt": snapshot.next_attempt + 1,
                "current_effect_id": None,
                "current_authorization_hash": None,
                "current_attempt_id": None,
                "last_host_snapshot_hash": (
                    snapshot.last_host_snapshot_hash
                    if observed_snapshot is None
                    else observed_snapshot.content_hash
                ),
            }
            if outcome in {"foreign", "observation_unavailable"}:
                return replace(
                    snapshot,
                    state="recovery_required",
                    recovery_reason=(
                        "host_state_foreign"
                        if outcome == "foreign"
                        else "host_observation_unavailable"
                    ),
                    **common,
                )
            if request.phase == "apply":
                if outcome == "postcondition":
                    cursor = snapshot.apply_cursor + 1
                    return replace(
                        snapshot,
                        state=(
                            "prepared_unverified"
                            if cursor == len(plan.effects)
                            else "apply_pending"
                        ),
                        apply_cursor=cursor,
                        applied_effect_ids=(*snapshot.applied_effect_ids, effect.effect_id),
                        recovery_reason=None,
                        **common,
                    )
                return replace(
                    snapshot,
                    state="apply_pending",
                    recovery_reason=None,
                    **common,
                )
            rollback = self.load_rollback_plan(snapshot.operation_id)
            if rollback is None:
                raise ControllerStoreCorruptionError("rollback_missing")
            if outcome == "postcondition":
                cursor = snapshot.rollback_cursor + 1
                cleanup_complete = cursor == len(rollback.effects)
                clean_proven = (
                    cleanup_complete
                    and observed_snapshot is not None
                    and is_reusable_clean_projection(
                        observed_snapshot,
                        plan.initial_snapshot,
                    )
                )
                if clean_proven:
                    recovery_reason = None
                elif cleanup_complete:
                    recovery_reason = (
                        snapshot.recovery_reason or "host_state_not_reusable"
                    )
                else:
                    recovery_reason = snapshot.recovery_reason
                return replace(
                    snapshot,
                    state=(
                        "rolled_back_clean"
                        if clean_proven
                        else "recovery_required"
                        if cleanup_complete
                        else "rollback_pending"
                    ),
                    rollback_cursor=cursor,
                    recovery_reason=recovery_reason,
                    **common,
                )
            return replace(
                snapshot,
                state="rollback_pending",
                recovery_reason=snapshot.recovery_reason,
                **common,
            )

        def auxiliary(connection: sqlite3.Connection, after: OperationSnapshot) -> None:
            cursor = connection.execute(
                "UPDATE controller_effect_attempts SET after_snapshot_json = ?, outcome = ?, "
                "observation_sequence = ? WHERE attempt_id = ? AND outcome = 'dispatching' "
                "AND request_hash = ?",
                (after_bytes, outcome, after.sequence, attempt_id, request.content_hash),
            )
            if cursor.rowcount != 1:
                raise ControllerStoreConflictError("effect_attempt_observation_conflict")
            if after.state == "rolled_back_clean":
                if observed_snapshot is None or not is_reusable_clean_projection(
                    observed_snapshot,
                    plan.initial_snapshot,
                ):
                    raise ControllerStoreCorruptionError(
                        "host_scope_lease_release_projection_invalid"
                    )
                lease_cursor = connection.execute(
                    "DELETE FROM controller_host_scope_leases "
                    "WHERE scope_id = ? AND operation_id = ? AND ownership_token = ? ",
                    (
                        HOST_SCOPE_ID,
                        after.operation_id,
                        after.ownership_token,
                    ),
                )
                if lease_cursor.rowcount != 1:
                    raise ControllerStoreConflictError("host_scope_lease_release_conflict")

        return self._append_transition(
            expected,
            event_kind="effect.observed",
            identity=f"{attempt_id}:{outcome}",
            bindings={
                "attempt_id": attempt_id,
                "attempt_document_hash": attempt_document_hash,
                "authorization_id": request.authorization_id,
                "request_hash": request.content_hash,
                "consumption_hash": consumption.content_hash,
                "effect_id": effect.effect_id,
                "effect_hash": effect.content_hash,
                "phase": request.phase,
                "attempt": request.attempt,
                "ownership_token": effect.ownership_token,
                "outcome": outcome,
                "before_snapshot_hash": before_snapshot.content_hash,
                "before_projection_hash": host_projection_hash(before_snapshot),
                "after_snapshot_hash": after_snapshot_hash,
                "after_projection_hash": (
                    None
                    if observed_snapshot is None
                    else host_projection_hash(observed_snapshot)
                ),
            },
            mutation=mutation,
            auxiliary=auxiliary,
        )

    def record_recovery(
        self,
        expected: OperationSnapshot,
        *,
        reason: str,
        observed_snapshot: HostSnapshot | None,
    ) -> ControllerStoreTransition:
        self._ensure_open()
        if expected.state == "rolled_back_clean":
            raise ControllerStoreConflictError("recovery_source_state_invalid")
        _validate_identifier(reason, "recovery_reason_invalid")
        if observed_snapshot is not None:
            try:
                observed_snapshot = HostSnapshot.from_document(observed_snapshot.to_document())
            except ControllerContractError as exc:
                raise ControllerStoreError("recovery_snapshot_invalid") from exc
        identity = hashlib.sha256(
            canonical_controller_bytes(
                {
                    "reason": reason,
                    "expected_head_hash": expected.event_head_hash,
                    "snapshot_hash": (
                        None if observed_snapshot is None else observed_snapshot.content_hash
                    ),
                }
            )
        ).hexdigest()

        def mutation(snapshot: OperationSnapshot) -> OperationSnapshot:
            return replace(
                snapshot,
                state="recovery_required",
                recovery_reason=reason,
                last_host_snapshot_hash=(
                    snapshot.last_host_snapshot_hash
                    if observed_snapshot is None
                    else observed_snapshot.content_hash
                ),
                current_effect_id=None,
                current_authorization_hash=None,
                current_attempt_id=None,
            )

        return self._append_transition(
            expected,
            event_kind="operation.recovery_required",
            identity=identity,
            bindings={
                "reason": reason,
                "observed_snapshot_hash": (
                    None if observed_snapshot is None else observed_snapshot.content_hash
                ),
                "observed_projection_hash": (
                    None
                    if observed_snapshot is None
                    else host_projection_hash(observed_snapshot)
                ),
            },
            mutation=mutation,
        )

    def record_rollback_plan(
        self,
        expected: OperationSnapshot,
        rollback: RollbackPlan,
        *,
        clean_snapshot: HostSnapshot | None = None,
    ) -> ControllerStoreTransition:
        try:
            rollback = RollbackPlan.from_document(rollback.to_document())
        except ControllerContractError as exc:
            raise ControllerStoreError("rollback_plan_invalid") from exc
        plan = self.load_plan(expected.operation_id)
        exact = build_rollback_plan(
            expected.operation_id,
            plan,
            expected.applied_effect_ids,
        )
        if rollback != exact or expected.state not in {
            "apply_pending",
            "prepared_unverified",
            "recovery_required",
        }:
            raise ControllerStoreConflictError("rollback_plan_state_mismatch")
        if rollback.effects:
            if clean_snapshot is not None:
                raise ControllerStoreConflictError("rollback_clean_snapshot_unexpected")
        else:
            if clean_snapshot is None:
                raise ControllerStoreConflictError("rollback_clean_snapshot_missing")
            try:
                clean_snapshot = HostSnapshot.from_document(clean_snapshot.to_document())
            except ControllerContractError as exc:
                raise ControllerStoreError("rollback_clean_snapshot_invalid") from exc
            if not is_reusable_clean_projection(clean_snapshot, plan.initial_snapshot):
                raise ControllerStoreConflictError("rollback_clean_projection_mismatch")

        def mutation(snapshot: OperationSnapshot) -> OperationSnapshot:
            terminal = not rollback.effects
            return replace(
                snapshot,
                state=(
                    "rolled_back_clean"
                    if terminal
                    else "rollback_pending"
                ),
                rollback_cursor=0,
                rollback_plan_hash=rollback.content_hash,
                current_effect_id=None,
                current_authorization_hash=None,
                current_attempt_id=None,
                recovery_reason=(None if terminal else snapshot.recovery_reason),
                last_host_snapshot_hash=(
                    snapshot.last_host_snapshot_hash
                    if clean_snapshot is None
                    else clean_snapshot.content_hash
                ),
            )

        def auxiliary(connection: sqlite3.Connection, after: OperationSnapshot) -> None:
            if after.state == "rolled_back_clean":
                if clean_snapshot is None or not is_reusable_clean_projection(
                    clean_snapshot,
                    plan.initial_snapshot,
                ):
                    raise ControllerStoreCorruptionError(
                        "host_scope_lease_release_projection_invalid"
                    )
                cursor = connection.execute(
                    "DELETE FROM controller_host_scope_leases "
                    "WHERE scope_id = ? AND operation_id = ? AND ownership_token = ?",
                    (HOST_SCOPE_ID, after.operation_id, after.ownership_token),
                )
                if cursor.rowcount != 1:
                    raise ControllerStoreConflictError("host_scope_lease_release_conflict")

        return self._append_transition(
            expected,
            event_kind="rollback.prepared",
            identity=rollback.content_hash,
            bindings={
                "rollback_plan_hash": rollback.content_hash,
                "ownership_token": rollback.ownership_token,
                "clean_snapshot": (
                    None if clean_snapshot is None else clean_snapshot.to_document()
                ),
                "clean_snapshot_hash": (
                    None if clean_snapshot is None else clean_snapshot.content_hash
                ),
                "clean_projection_hash": (
                    None
                    if clean_snapshot is None
                    else host_projection_hash(clean_snapshot)
                ),
            },
            mutation=mutation,
            auxiliary=auxiliary,
            rollback_plan=rollback,
        )

    def effect_attempt_document(self, attempt_id: str | None) -> dict[str, object]:
        self._ensure_open()
        if attempt_id is None:
            raise ControllerStoreError("attempt_id_invalid")
        row = self._connection.execute(
            "SELECT * FROM controller_effect_attempts WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if row is None:
            raise ControllerStoreError("effect_attempt_not_found")
        self._verify_attempt_row(row)
        return {
            "attempt_id": row["attempt_id"],
            "operation_id": row["operation_id"],
            "phase": row["phase"],
            "effect_id": row["effect_id"],
            "attempt": row["attempt"],
            "authorization_id": row["authorization_id"],
            "request_hash": row["request_hash"],
            "before_snapshot": self._decode_host_snapshot(
                row["before_snapshot_json"]
            ).to_document(),
            "after_snapshot": (
                None
                if row["after_snapshot_json"] is None
                else self._decode_host_snapshot(row["after_snapshot_json"]).to_document()
            ),
            "outcome": row["outcome"],
            "dispatch_sequence": row["dispatch_sequence"],
            "observation_sequence": row["observation_sequence"],
        }


__all__ = (
    "APPLICATION_ID",
    "ControllerStoreCommitNotApplied",
    "ControllerStoreConflictError",
    "ControllerStoreCorruptionError",
    "ControllerStoreDuplicateMismatch",
    "ControllerStoreError",
    "ControllerStoreRecoveryRequired",
    "ControllerStoreTransition",
    "OllamaV2ControllerStore",
    "SCHEMA_FINGERPRINT",
    "SCHEMA_VERSION",
)
