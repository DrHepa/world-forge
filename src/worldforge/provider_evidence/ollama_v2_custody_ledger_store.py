"""Injected local reference store for the Ollama v2 custody ledger.

This module is deliberately not a native custody implementation.  It provides
only an identity-bound, event-only SQLite foundation for deterministic tests
and future local reference semantics.  Its status can never be used as proof
of root-global custody, native execution, or production eligibility.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from worldforge.file_stat import (
    descriptor_file_stat,
    file_identity,
    is_link_or_reparse,
    path_file_stat,
)

from .ollama_v2_native_execution_contracts import (
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
    OllamaV2NativeExecutionBindingD2,
    OllamaV2NativeExecutionContractError,
    OllamaV2NativeReservationD2,
    OllamaV2SourceBundleDescriptorD2,
    canonical_ollama_v2_native_execution_bytes,
    parse_ollama_v2_native_execution_contract,
)

SCHEMA_VERSION = 1
APPLICATION_ID = 0x57464332
REFERENCE_STORE_KIND = "injected_local_reference"
BUSY_TIMEOUT_MS = 5_000
_ZERO_HASH = "0" * 64
_LOCK_IDENTITY = b"\0"
_DESCRIPTOR_DIRECTORY = Path("/proc/self/fd")
_MODES = frozenset({"create", "open", "create_or_open"})
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9_.:-]{2,127}$")
_ACTIVE_STATES = frozenset(
    {
        "idle",
        "reserved",
        "c2_referenced",
        "dispatch_committed",
        "acknowledged",
        "witnessed",
        "observed",
        "tombstoned",
    }
)
_EVENT_FORMAT = "world-forge.private.ollama_v2_custody_reference_event"
_EVENT_ID_DOMAIN = b"world-forge.private.ollama_v2_custody_reference_event_id.v1\0"
_EVENT_HASH_DOMAIN = b"world-forge.private.ollama_v2_custody_reference_event_hash.v1\0"
_SOURCE_FORMAT = "world-forge.private.ollama_v2_source_bundle_descriptor_d2"
_RESERVATION_FORMAT = "world-forge.private.ollama_v2_native_reservation_d2"
_MAX_EVENT_BYTES = 4 * 1024 * 1024


class CustodyLedgerReferenceStoreError(RuntimeError):
    """Base class for local reference-store failures."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class CustodyLedgerReferenceInvalidStateError(CustodyLedgerReferenceStoreError):
    """The caller, process, or injected filesystem state is not acceptable."""


class CustodyLedgerReferenceCorruptionError(CustodyLedgerReferenceStoreError):
    """The persisted store is not the one exact b1 schema and genesis state."""


class CustodyLedgerReferenceUnsupportedError(CustodyLedgerReferenceStoreError):
    """Required current-user POSIX custody primitives are unavailable."""


class CustodyLedgerReferenceClosedError(CustodyLedgerReferenceStoreError):
    """A public operation was attempted after the store was closed."""


class CustodyLedgerReferenceConflictError(CustodyLedgerReferenceStoreError):
    """The supplied transition conflicts with the exact durable state."""


class CustodyLedgerReferenceDuplicateMismatchError(CustodyLedgerReferenceStoreError):
    """A unique identity was reused by a different canonical transition."""


class CustodyLedgerReferenceCommitNotAppliedError(CustodyLedgerReferenceStoreError):
    """A commit exception reconciled to a valid state without the target event."""


class CustodyLedgerReferenceRecoveryRequiredError(CustodyLedgerReferenceStoreError):
    """A commit exception could not be reconciled to one valid event history."""


def _raise_sqlite_failure(exc: sqlite3.Error, corruption_reason: str) -> None:
    error_code = getattr(exc, "sqlite_errorcode", None)
    if type(error_code) is int:
        primary_code = error_code & 0xFF
        if primary_code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_store_busy"
            ) from exc
        if primary_code == sqlite3.SQLITE_IOERR:
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_database_identity_unstable"
            ) from exc
    raise CustodyLedgerReferenceCorruptionError(corruption_reason) from exc


@dataclass(frozen=True, slots=True)
class CustodyLedgerReferenceStatus:
    """Exact non-native status of the injected local reference store."""

    store_kind: str
    deployment_binding: str
    root_global_enforced: bool
    source_custody_verified: bool
    host_execution_enabled: bool
    native_implementation_state: str
    availability: str
    production_eligible: bool
    catalog_admitted: bool
    provider_execution_enabled: bool
    rollback_resistant: bool

    def __post_init__(self) -> None:
        expected = (
            REFERENCE_STORE_KIND,
            DEPLOYMENT_BINDING,
            ROOT_GLOBAL_ENFORCED,
            SOURCE_CUSTODY_VERIFIED,
            HOST_EXECUTION_ENABLED,
            NATIVE_IMPLEMENTATION_STATE,
            AVAILABILITY,
            PRODUCTION_ELIGIBLE,
            CATALOG_ADMITTED,
            PROVIDER_EXECUTION_ENABLED,
            False,
        )
        actual = tuple(getattr(self, name) for name in self.__dataclass_fields__)
        if any(
            type(value) is not type(expected_value) or value != expected_value
            for value, expected_value in zip(actual, expected, strict=True)
        ):
            raise CustodyLedgerReferenceInvalidStateError("reference_status_invalid")


@dataclass(frozen=True, slots=True)
class CustodyLedgerReferenceHead:
    """Transition-neutral singleton projection stored by the b1 foundation."""

    scope: str
    fence_generation: int
    record_sequence: int
    record_head_hash: str
    active_reservation_id: str | None
    active_fence_hash: str | None
    active_state: str
    event_sequence: int
    event_head_hash: str
    poisoned: bool

    def __post_init__(self) -> None:
        integer_values = (
            self.fence_generation,
            self.record_sequence,
            self.event_sequence,
        )
        active = self.active_state != "idle"
        valid = (
            type(self.scope) is str
            and self.scope == CUSTODY_SCOPE
            and all(type(value) is int and value >= 0 for value in integer_values)
            and type(self.record_head_hash) is str
            and _HASH_RE.fullmatch(self.record_head_hash) is not None
            and type(self.event_head_hash) is str
            and _HASH_RE.fullmatch(self.event_head_hash) is not None
            and type(self.active_state) is str
            and self.active_state in _ACTIVE_STATES
            and type(self.poisoned) is bool
            and (self.record_sequence == 0) == (self.record_head_hash == _ZERO_HASH)
            and (self.event_sequence == 0) == (self.event_head_hash == _ZERO_HASH)
            and self.record_sequence <= self.event_sequence
            and active == (self.active_reservation_id is not None)
            and active == (self.active_fence_hash is not None)
            and (not active or self.fence_generation >= 1)
        )
        if active:
            valid = valid and (
                type(self.active_reservation_id) is str
                and _ID_RE.fullmatch(self.active_reservation_id) is not None
                and type(self.active_fence_hash) is str
                and _HASH_RE.fullmatch(self.active_fence_hash) is not None
            )
        if self.event_sequence == 0:
            valid = valid and (
                self.fence_generation == 0
                and self.record_sequence == 0
                and not active
                and self.poisoned is False
            )
        if not valid:
            raise CustodyLedgerReferenceInvalidStateError("reference_head_invalid")


@dataclass(frozen=True, slots=True)
class CustodyLedgerReferenceSchemaObject:
    """One exact persisted SQLite schema object."""

    object_type: str
    name: str
    table_name: str
    sql_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.object_type) is not str
            or self.object_type not in {"index", "table"}
            or type(self.name) is not str
            or _ID_RE.fullmatch(self.name) is None
            or type(self.table_name) is not str
            or _ID_RE.fullmatch(self.table_name) is None
            or type(self.sql_sha256) is not str
            or _HASH_RE.fullmatch(self.sql_sha256) is None
        ):
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_schema_object_invalid"
            )


def _event_identity_payload(
    *,
    event_type: str,
    subject_id: str,
    subject_stage: str,
    artifact_id: str,
    artifact_type: str,
    artifact_hash: str,
    binding_hash: str | None,
) -> dict[str, object]:
    return {
        "event_type": event_type,
        "subject_id": subject_id,
        "subject_stage": subject_stage,
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "artifact_hash": artifact_hash,
        "binding_hash": binding_hash,
    }


def _reference_event_id(identity: dict[str, object]) -> str:
    digest = hashlib.sha256(
        _EVENT_ID_DOMAIN + canonical_ollama_v2_native_execution_bytes(identity)
    ).hexdigest()
    return "event-" + digest[:32]


@dataclass(frozen=True, slots=True)
class CustodyLedgerReferenceEventDocument:
    """One exact store-owned event in the local reference hash chain."""

    sequence: int
    event_id: str
    event_type: str
    subject_id: str
    subject_stage: str
    artifact_id: str
    artifact_type: str
    artifact_hash: str
    artifact: OllamaV2SourceBundleDescriptorD2 | OllamaV2NativeReservationD2
    binding_hash: str | None
    binding: OllamaV2NativeExecutionBindingD2 | None
    previous_event_hash: str
    event_hash: str

    def __post_init__(self) -> None:
        scalar_ids = (self.event_id, self.subject_id, self.artifact_id)
        valid = (
            type(self.sequence) is int
            and self.sequence >= 1
            and all(type(value) is str and _ID_RE.fullmatch(value) for value in scalar_ids)
            and type(self.event_type) is str
            and self.event_type in {"source.registered", "reservation.held"}
            and type(self.subject_stage) is str
            and type(self.artifact_type) is str
            and type(self.artifact_hash) is str
            and _HASH_RE.fullmatch(self.artifact_hash) is not None
            and type(self.previous_event_hash) is str
            and _HASH_RE.fullmatch(self.previous_event_hash) is not None
            and type(self.event_hash) is str
            and _HASH_RE.fullmatch(self.event_hash) is not None
        )
        if not valid:
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_event_document_invalid"
            )
        if self.event_type == "source.registered":
            exact = (
                type(self.artifact) is OllamaV2SourceBundleDescriptorD2
                and self.subject_id == self.artifact.descriptor_id
                and self.subject_stage == "source.registered"
                and self.artifact_id == self.artifact.descriptor_id
                and self.artifact_type == _SOURCE_FORMAT
                and self.binding_hash is None
                and self.binding is None
            )
        else:
            exact = (
                type(self.artifact) is OllamaV2NativeReservationD2
                and type(self.binding) is OllamaV2NativeExecutionBindingD2
                and type(self.binding_hash) is str
                and _HASH_RE.fullmatch(self.binding_hash) is not None
                and self.subject_id == self.binding.binding_id
                and self.subject_stage == "reservation.held"
                and self.artifact_id == self.artifact.reservation_id
                and self.artifact_type == _RESERVATION_FORMAT
                and self.binding_hash == self.binding.content_hash
                and self.artifact.execution_binding_hash == self.binding.content_hash
            )
        identity = _event_identity_payload(
            event_type=self.event_type,
            subject_id=self.subject_id,
            subject_stage=self.subject_stage,
            artifact_id=self.artifact_id,
            artifact_type=self.artifact_type,
            artifact_hash=self.artifact_hash,
            binding_hash=self.binding_hash,
        )
        if (
            not exact
            or self.artifact_hash != self.artifact.content_hash
            or self.event_id != _reference_event_id(identity)
            or self.event_hash != self._computed_event_hash()
        ):
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_event_document_invalid"
            )

    def _payload(self) -> dict[str, object]:
        return {
            "format": _EVENT_FORMAT,
            "format_version": 1,
            "scope": CUSTODY_SCOPE,
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "subject_id": self.subject_id,
            "subject_stage": self.subject_stage,
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "artifact_hash": self.artifact_hash,
            "artifact": self.artifact.to_document(),
            "binding_hash": self.binding_hash,
            "binding": None if self.binding is None else self.binding.to_document(),
            "previous_event_hash": self.previous_event_hash,
        }

    def _computed_event_hash(self) -> str:
        return hashlib.sha256(
            _EVENT_HASH_DOMAIN
            + bytes.fromhex(self.previous_event_hash)
            + canonical_ollama_v2_native_execution_bytes(self._payload())
        ).hexdigest()

    def to_document(self) -> dict[str, object]:
        return {**self._payload(), "event_hash": self.event_hash}

    def to_bytes(self) -> bytes:
        return canonical_ollama_v2_native_execution_bytes(self.to_document())

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        event_type: str,
        artifact: OllamaV2SourceBundleDescriptorD2 | OllamaV2NativeReservationD2,
        binding: OllamaV2NativeExecutionBindingD2 | None,
        previous_event_hash: str,
    ) -> CustodyLedgerReferenceEventDocument:
        if event_type == "source.registered" and type(artifact) is OllamaV2SourceBundleDescriptorD2:
            subject_id = artifact.descriptor_id
            subject_stage = event_type
            artifact_id = artifact.descriptor_id
            artifact_type = _SOURCE_FORMAT
            binding_hash = None
        elif (
            event_type == "reservation.held"
            and type(artifact) is OllamaV2NativeReservationD2
            and type(binding) is OllamaV2NativeExecutionBindingD2
        ):
            subject_id = binding.binding_id
            subject_stage = event_type
            artifact_id = artifact.reservation_id
            artifact_type = _RESERVATION_FORMAT
            binding_hash = binding.content_hash
        else:
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_event_document_invalid"
            )
        identity = _event_identity_payload(
            event_type=event_type,
            subject_id=subject_id,
            subject_stage=subject_stage,
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            artifact_hash=artifact.content_hash,
            binding_hash=binding_hash,
        )
        event_id = _reference_event_id(identity)
        provisional = object.__new__(cls)
        values = {
            "sequence": sequence,
            "event_id": event_id,
            "event_type": event_type,
            "subject_id": subject_id,
            "subject_stage": subject_stage,
            "artifact_id": artifact_id,
            "artifact_type": artifact_type,
            "artifact_hash": artifact.content_hash,
            "artifact": artifact,
            "binding_hash": binding_hash,
            "binding": binding,
            "previous_event_hash": previous_event_hash,
        }
        for name, value in values.items():
            object.__setattr__(provisional, name, value)
        event_hash = provisional._computed_event_hash()
        return cls(event_hash=event_hash, **values)


def _reject_reference_json_number(_: str) -> object:
    raise CustodyLedgerReferenceInvalidStateError("reference_event_json_noncanonical")


def _reference_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_event_json_duplicate_key"
            )
        result[key] = value
    return result


def parse_custody_ledger_reference_event(
    value: object,
) -> CustodyLedgerReferenceEventDocument:
    """Parse one exact canonical store event document."""

    if type(value) is not bytes or not value or len(value) > _MAX_EVENT_BYTES:
        raise CustodyLedgerReferenceInvalidStateError("reference_event_json_invalid")
    try:
        document = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=_reference_object_pairs,
            parse_float=_reject_reference_json_number,
            parse_constant=_reject_reference_json_number,
        )
    except CustodyLedgerReferenceStoreError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise CustodyLedgerReferenceInvalidStateError(
            "reference_event_json_invalid"
        ) from exc
    if (
        type(document) is not dict
        or canonical_ollama_v2_native_execution_bytes(document) != value
        or set(document)
        != {
            "format",
            "format_version",
            "scope",
            "sequence",
            "event_id",
            "event_type",
            "subject_id",
            "subject_stage",
            "artifact_id",
            "artifact_type",
            "artifact_hash",
            "artifact",
            "binding_hash",
            "binding",
            "previous_event_hash",
            "event_hash",
        }
        or document["format"] != _EVENT_FORMAT
        or type(document["format_version"]) is not int
        or document["format_version"] != 1
        or document["scope"] != CUSTODY_SCOPE
    ):
        raise CustodyLedgerReferenceInvalidStateError(
            "reference_event_document_invalid"
        )
    try:
        artifact = parse_ollama_v2_native_execution_contract(
            canonical_ollama_v2_native_execution_bytes(document["artifact"])
        )
        binding_document = document["binding"]
        binding = (
            None
            if binding_document is None
            else parse_ollama_v2_native_execution_contract(
                canonical_ollama_v2_native_execution_bytes(binding_document)
            )
        )
        return CustodyLedgerReferenceEventDocument(
            sequence=document["sequence"],
            event_id=document["event_id"],
            event_type=document["event_type"],
            subject_id=document["subject_id"],
            subject_stage=document["subject_stage"],
            artifact_id=document["artifact_id"],
            artifact_type=document["artifact_type"],
            artifact_hash=document["artifact_hash"],
            artifact=artifact,
            binding_hash=document["binding_hash"],
            binding=binding,
            previous_event_hash=document["previous_event_hash"],
            event_hash=document["event_hash"],
        )
    except (OllamaV2NativeExecutionContractError, TypeError) as exc:
        raise CustodyLedgerReferenceInvalidStateError(
            "reference_event_document_invalid"
        ) from exc


@dataclass(frozen=True, slots=True)
class CustodyLedgerReferenceSnapshot:
    """Exact replayed active projection of the b2 reference store."""

    head: CustodyLedgerReferenceHead
    active_binding: OllamaV2NativeExecutionBindingD2 | None
    active_reservation: OllamaV2NativeReservationD2 | None

    def __post_init__(self) -> None:
        if type(self.head) is not CustodyLedgerReferenceHead:
            raise CustodyLedgerReferenceInvalidStateError("reference_snapshot_invalid")
        if self.head.active_state == "idle":
            valid = self.active_binding is None and self.active_reservation is None
        elif self.head.active_state == "reserved":
            valid = (
                type(self.active_binding) is OllamaV2NativeExecutionBindingD2
                and type(self.active_reservation) is OllamaV2NativeReservationD2
                and self.active_reservation.execution_binding_hash
                == self.active_binding.content_hash
                and self.head.active_reservation_id
                == self.active_reservation.reservation_id
                and self.head.active_fence_hash == self.active_reservation.fence_hash
                and self.head.fence_generation
                == self.active_reservation.fence_generation
                and self.head.record_sequence
                == self.active_reservation.previous_fence_sequence
                and self.head.record_head_hash
                == self.active_reservation.previous_fence_hash
            )
        else:
            valid = False
        if not valid:
            raise CustodyLedgerReferenceInvalidStateError("reference_snapshot_invalid")


@dataclass(frozen=True, slots=True)
class CustodyLedgerReferenceTransition:
    """A replayed snapshot and ownership result for one target event."""

    snapshot: CustodyLedgerReferenceSnapshot
    event: CustodyLedgerReferenceEventDocument
    committed_now: bool

    def __post_init__(self) -> None:
        if (
            type(self.snapshot) is not CustodyLedgerReferenceSnapshot
            or type(self.event) is not CustodyLedgerReferenceEventDocument
            or type(self.committed_now) is not bool
        ):
            raise CustodyLedgerReferenceInvalidStateError("reference_transition_invalid")


@dataclass(slots=True)
class _ReferenceReplay:
    snapshot: CustodyLedgerReferenceSnapshot
    sources: dict[str, tuple[OllamaV2SourceBundleDescriptorD2, CustodyLedgerReferenceEventDocument]]
    events: dict[str, CustodyLedgerReferenceEventDocument]
    active_event: CustodyLedgerReferenceEventDocument | None


_STATUS = CustodyLedgerReferenceStatus(
    store_kind=REFERENCE_STORE_KIND,
    deployment_binding=DEPLOYMENT_BINDING,
    root_global_enforced=ROOT_GLOBAL_ENFORCED,
    source_custody_verified=SOURCE_CUSTODY_VERIFIED,
    host_execution_enabled=HOST_EXECUTION_ENABLED,
    native_implementation_state=NATIVE_IMPLEMENTATION_STATE,
    availability=AVAILABILITY,
    production_eligible=PRODUCTION_ELIGIBLE,
    catalog_admitted=CATALOG_ADMITTED,
    provider_execution_enabled=PROVIDER_EXECUTION_ENABLED,
    rollback_resistant=False,
)


_DDL_BY_NAME = {
    "ollama_v2_custody_metadata": """CREATE TABLE ollama_v2_custody_metadata (
    key TEXT PRIMARY KEY CHECK (key IN ('schema_version', 'schema_fingerprint', 'store_kind')),
    value TEXT NOT NULL
) WITHOUT ROWID""",
    "ollama_v2_custody_head": """CREATE TABLE ollama_v2_custody_head (
    scope TEXT PRIMARY KEY CHECK (scope = 'ollama_v2_root_global_custody'),
    fence_generation INTEGER NOT NULL CHECK (fence_generation >= 0),
    record_sequence INTEGER NOT NULL CHECK (record_sequence >= 0),
    record_head_hash TEXT NOT NULL CHECK (
        typeof(record_head_hash) = 'text'
        AND length(record_head_hash) = 64
        AND record_head_hash NOT GLOB '*[^0-9a-f]*'
    ),
    active_reservation_id TEXT,
    active_fence_hash TEXT CHECK (active_fence_hash IS NULL OR (
        typeof(active_fence_hash) = 'text'
        AND length(active_fence_hash) = 64
        AND active_fence_hash NOT GLOB '*[^0-9a-f]*'
    )),
    active_state TEXT NOT NULL CHECK (active_state IN (
        'idle',
        'reserved',
        'c2_referenced',
        'dispatch_committed',
        'acknowledged',
        'witnessed',
        'observed',
        'tombstoned'
    )),
    event_sequence INTEGER NOT NULL CHECK (event_sequence >= 0),
    event_head_hash TEXT NOT NULL CHECK (
        typeof(event_head_hash) = 'text'
        AND length(event_head_hash) = 64
        AND event_head_hash NOT GLOB '*[^0-9a-f]*'
    ),
    poisoned INTEGER NOT NULL CHECK (poisoned IN (0, 1)),
    CHECK ((record_sequence = 0) = (
        record_head_hash =
        '0000000000000000000000000000000000000000000000000000000000000000'
    )),
    CHECK ((event_sequence = 0) = (
        event_head_hash =
        '0000000000000000000000000000000000000000000000000000000000000000'
    )),
    CHECK ((active_state = 'idle') = (active_reservation_id IS NULL)),
    CHECK ((active_state = 'idle') = (active_fence_hash IS NULL)),
    CHECK (active_state = 'idle' OR fence_generation >= 1),
    CHECK (record_sequence <= event_sequence),
    CHECK (event_sequence != 0 OR (
        fence_generation = 0
        AND record_sequence = 0
        AND active_state = 'idle'
        AND poisoned = 0
    ))
) WITHOUT ROWID""",
    "ollama_v2_custody_events": """CREATE TABLE ollama_v2_custody_events (
    sequence INTEGER PRIMARY KEY CHECK (sequence >= 1),
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'source.registered',
        'reservation.held',
        'c2.referenced',
        'dispatch.committed',
        'mutation.acknowledged',
        'manager.witnessed',
        'effect.observed',
        'reservation.tombstoned',
        'reservation.released'
    )),
    subject_id TEXT NOT NULL,
    subject_stage TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    artifact_hash TEXT NOT NULL CHECK (
        typeof(artifact_hash) = 'text'
        AND length(artifact_hash) = 64
        AND artifact_hash NOT GLOB '*[^0-9a-f]*'
    ),
    artifact_json BLOB NOT NULL CHECK (typeof(artifact_json) = 'blob'),
    binding_hash TEXT CHECK (binding_hash IS NULL OR (
        typeof(binding_hash) = 'text'
        AND length(binding_hash) = 64
        AND binding_hash NOT GLOB '*[^0-9a-f]*'
    )),
    binding_json BLOB CHECK (
        binding_json IS NULL OR typeof(binding_json) = 'blob'
    ),
    previous_event_hash TEXT NOT NULL CHECK (
        typeof(previous_event_hash) = 'text'
        AND length(previous_event_hash) = 64
        AND previous_event_hash NOT GLOB '*[^0-9a-f]*'
    ),
    event_hash TEXT NOT NULL CHECK (
        typeof(event_hash) = 'text'
        AND length(event_hash) = 64
        AND event_hash NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK ((binding_hash IS NULL) = (binding_json IS NULL)),
    CHECK ((event_type = 'reservation.held') = (binding_hash IS NOT NULL))
)""",
    "idx_ollama_v2_custody_events_event_id": (
        "CREATE UNIQUE INDEX idx_ollama_v2_custody_events_event_id\n"
        "ON ollama_v2_custody_events(event_id)"
    ),
    "idx_ollama_v2_custody_events_event_hash": (
        "CREATE UNIQUE INDEX idx_ollama_v2_custody_events_event_hash\n"
        "ON ollama_v2_custody_events(event_hash)"
    ),
    "idx_ollama_v2_custody_events_artifact_id": (
        "CREATE UNIQUE INDEX idx_ollama_v2_custody_events_artifact_id\n"
        "ON ollama_v2_custody_events(artifact_id)"
    ),
    "idx_ollama_v2_custody_events_artifact_hash": (
        "CREATE UNIQUE INDEX idx_ollama_v2_custody_events_artifact_hash\n"
        "ON ollama_v2_custody_events(artifact_hash)"
    ),
    "idx_ollama_v2_custody_events_subject_stage": (
        "CREATE UNIQUE INDEX idx_ollama_v2_custody_events_subject_stage\n"
        "ON ollama_v2_custody_events(subject_id, subject_stage)"
    ),
    "idx_ollama_v2_custody_events_binding_hash": (
        "CREATE UNIQUE INDEX idx_ollama_v2_custody_events_binding_hash\n"
        "ON ollama_v2_custody_events(binding_hash)\n"
        "WHERE binding_hash IS NOT NULL"
    ),
}


def _schema_fingerprint() -> str:
    payload = [
        {"name": name, "sql": sql}
        for name, sql in sorted(_DDL_BY_NAME.items())
    ]
    return hashlib.sha256(
        canonical_ollama_v2_native_execution_bytes(payload)
    ).hexdigest()


SCHEMA_FINGERPRINT = "417618a56f07446749ab8ef792b577934e55fbb7c5870316c7abf465af69e7b2"
if _schema_fingerprint() != SCHEMA_FINGERPRINT:
    raise RuntimeError("custody reference schema fingerprint is stale")


_TABLE_XINFO = {
    "ollama_v2_custody_metadata": (
        (0, "key", "TEXT", 1, None, 1, 0),
        (1, "value", "TEXT", 1, None, 0, 0),
    ),
    "ollama_v2_custody_head": (
        (0, "scope", "TEXT", 1, None, 1, 0),
        (1, "fence_generation", "INTEGER", 1, None, 0, 0),
        (2, "record_sequence", "INTEGER", 1, None, 0, 0),
        (3, "record_head_hash", "TEXT", 1, None, 0, 0),
        (4, "active_reservation_id", "TEXT", 0, None, 0, 0),
        (5, "active_fence_hash", "TEXT", 0, None, 0, 0),
        (6, "active_state", "TEXT", 1, None, 0, 0),
        (7, "event_sequence", "INTEGER", 1, None, 0, 0),
        (8, "event_head_hash", "TEXT", 1, None, 0, 0),
        (9, "poisoned", "INTEGER", 1, None, 0, 0),
    ),
    "ollama_v2_custody_events": (
        (0, "sequence", "INTEGER", 0, None, 1, 0),
        (1, "event_id", "TEXT", 1, None, 0, 0),
        (2, "event_type", "TEXT", 1, None, 0, 0),
        (3, "subject_id", "TEXT", 1, None, 0, 0),
        (4, "subject_stage", "TEXT", 1, None, 0, 0),
        (5, "artifact_id", "TEXT", 1, None, 0, 0),
        (6, "artifact_type", "TEXT", 1, None, 0, 0),
        (7, "artifact_hash", "TEXT", 1, None, 0, 0),
        (8, "artifact_json", "BLOB", 1, None, 0, 0),
        (9, "binding_hash", "TEXT", 0, None, 0, 0),
        (10, "binding_json", "BLOB", 0, None, 0, 0),
        (11, "previous_event_hash", "TEXT", 1, None, 0, 0),
        (12, "event_hash", "TEXT", 1, None, 0, 0),
    ),
}

_INDEX_COLUMNS = {
    "sqlite_autoindex_ollama_v2_custody_metadata_1": ("key",),
    "sqlite_autoindex_ollama_v2_custody_head_1": ("scope",),
    "idx_ollama_v2_custody_events_event_id": ("event_id",),
    "idx_ollama_v2_custody_events_event_hash": ("event_hash",),
    "idx_ollama_v2_custody_events_artifact_id": ("artifact_id",),
    "idx_ollama_v2_custody_events_artifact_hash": ("artifact_hash",),
    "idx_ollama_v2_custody_events_subject_stage": ("subject_id", "subject_stage"),
    "idx_ollama_v2_custody_events_binding_hash": ("binding_hash",),
}

_INDEX_CENSUS = {
    "ollama_v2_custody_metadata": {
        "sqlite_autoindex_ollama_v2_custody_metadata_1": (1, "pk", 0),
    },
    "ollama_v2_custody_head": {
        "sqlite_autoindex_ollama_v2_custody_head_1": (1, "pk", 0),
    },
    "ollama_v2_custody_events": {
        name: (1, "c", 1 if "binding_hash" in name else 0)
        for name in _INDEX_COLUMNS
        if name.startswith("idx_")
    },
}


class OllamaV2CustodyLedgerReferenceStore:
    """Identity-bound b1 foundation for one injected local reference ledger."""

    def __init__(
        self,
        root: str | Path,
        *,
        mode: str = "create_or_open",
    ) -> None:
        self._owner_pid = os.getpid()
        self._closed = False
        self._root_descriptor: int | None = None
        self._lock_descriptor: int | None = None
        self._database_descriptor: int | None = None
        self._connection: sqlite3.Connection | None = None

        if type(mode) is not str or mode not in _MODES:
            raise CustodyLedgerReferenceInvalidStateError("reference_store_mode_invalid")
        self._mode = mode
        self._root = self._validated_root_path(root)
        self._lock_path = self._root / CUSTODY_LOCK_NAME
        self._database_path = self._root / CUSTODY_LEDGER_NAME

        try:
            self._require_supported_platform()
            self._open_root_descriptor()
            lock_exists = self._path_exists(self._lock_path)
            database_exists = self._path_exists(self._database_path)
            if mode == "create" and database_exists:
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_store_already_exists"
                )
            if mode == "open" and (not lock_exists or not database_exists):
                raise CustodyLedgerReferenceInvalidStateError("reference_store_missing")
            if mode == "create_or_open" and database_exists and not lock_exists:
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_store_partial"
                )
            lock_created = self._open_lock(create=mode != "open")
            database_exists = self._path_exists(self._database_path)
            if mode == "create" and database_exists:
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_store_already_exists"
                )
            if mode == "open" and not database_exists:
                raise CustodyLedgerReferenceInvalidStateError("reference_store_missing")
            if mode != "open" and not database_exists and not lock_created:
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_store_partial"
                )
            if mode == "create_or_open" and database_exists == lock_created:
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_store_partial"
                )
            create_database = not database_exists
            self._open_database(create=create_database)
            self._assert_sidecars_absent()
            self._connect()
            self._assert_boundary()
            self._configure_connection(new_database=create_database)
            self._initialize_or_verify(allow_initialize=create_database)
            if lock_created:
                lock_descriptor = self._lock_descriptor
                assert lock_descriptor is not None
                self._acquire_file_lock(lock_descriptor, exclusive=False)
            self._assert_boundary()
        except BaseException:
            self._close_resources(unlock=os.getpid() == self._owner_pid)
            self._closed = True
            raise

    def __enter__(self) -> OllamaV2CustodyLedgerReferenceStore:
        self._assert_boundary()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass

    def native_status(self) -> CustodyLedgerReferenceStatus:
        self._assert_boundary()
        status = _STATUS
        self._assert_boundary()
        return status

    def schema_census(self) -> tuple[CustodyLedgerReferenceSchemaObject, ...]:
        self._assert_boundary()
        self._verify_store()
        census = self._schema_census_unchecked()
        self._assert_boundary()
        return census

    def head(self) -> CustodyLedgerReferenceHead:
        self._assert_boundary()
        head = self._verify_store().snapshot.head
        self._assert_boundary()
        return head

    def snapshot(self) -> CustodyLedgerReferenceSnapshot:
        self._assert_boundary()
        snapshot = self._verify_store().snapshot
        self._assert_boundary()
        return snapshot

    def load_event(self, event_id: str) -> CustodyLedgerReferenceEventDocument | None:
        self._assert_boundary()
        self._assert_identifier(event_id)
        event = self._verify_store().events.get(event_id)
        self._assert_boundary()
        return event

    def load_source(
        self,
        descriptor_id: str,
    ) -> OllamaV2SourceBundleDescriptorD2 | None:
        self._assert_boundary()
        self._assert_identifier(descriptor_id)
        source = self._verify_store().sources.get(descriptor_id)
        self._assert_boundary()
        return None if source is None else source[0]

    def load_binding(
        self,
        binding_id: str,
    ) -> OllamaV2NativeExecutionBindingD2 | None:
        self._assert_boundary()
        self._assert_identifier(binding_id)
        binding = self._verify_store().snapshot.active_binding
        self._assert_boundary()
        return binding if binding is not None and binding.binding_id == binding_id else None

    def load_reservation(
        self,
        reservation_id: str,
    ) -> OllamaV2NativeReservationD2 | None:
        self._assert_boundary()
        self._assert_identifier(reservation_id)
        reservation = self._verify_store().snapshot.active_reservation
        self._assert_boundary()
        return (
            reservation
            if reservation is not None and reservation.reservation_id == reservation_id
            else None
        )

    def register_source(
        self,
        source: OllamaV2SourceBundleDescriptorD2,
    ) -> CustodyLedgerReferenceTransition:
        self._assert_boundary()
        if type(source) is not OllamaV2SourceBundleDescriptorD2:
            raise CustodyLedgerReferenceInvalidStateError("reference_source_invalid")
        self._begin_immediate()
        try:
            state = self._verify_store()
            self._require_mutable(state.snapshot)
            existing = state.sources.get(source.descriptor_id)
            if existing is not None:
                if existing[0].to_bytes() != source.to_bytes():
                    raise CustodyLedgerReferenceDuplicateMismatchError(
                        "reference_duplicate_mismatch"
                    )
                self._rollback()
                return CustodyLedgerReferenceTransition(
                    snapshot=state.snapshot,
                    event=existing[1],
                    committed_now=False,
                )
            event = CustodyLedgerReferenceEventDocument.create(
                sequence=state.snapshot.head.event_sequence + 1,
                event_type="source.registered",
                artifact=source,
                binding=None,
                previous_event_hash=state.snapshot.head.event_head_hash,
            )
            self._assert_no_unique_collision(event)
            self._insert_event(event)
            self._update_head_for_event(event, reservation=None)
            after = self._verify_store().snapshot
            return self._finish_event_commit(event, after)
        except CustodyLedgerReferenceStoreError:
            self._rollback()
            raise
        except sqlite3.Error as exc:
            self._rollback()
            _raise_sqlite_failure(exc, "reference_source_registration_failed")

    def reserve(
        self,
        binding: OllamaV2NativeExecutionBindingD2,
    ) -> CustodyLedgerReferenceTransition:
        self._assert_boundary()
        if type(binding) is not OllamaV2NativeExecutionBindingD2:
            raise CustodyLedgerReferenceInvalidStateError("reference_binding_invalid")
        self._begin_immediate()
        try:
            state = self._verify_store()
            self._require_mutable(state.snapshot)
            active = state.snapshot.active_binding
            if active is not None:
                if active.to_bytes() != binding.to_bytes():
                    raise CustodyLedgerReferenceConflictError(
                        "reference_active_reservation_conflict"
                    )
                assert state.active_event is not None
                self._rollback()
                return CustodyLedgerReferenceTransition(
                    snapshot=state.snapshot,
                    event=state.active_event,
                    committed_now=False,
                )
            self._verify_registered_source(binding, state)
            head = state.snapshot.head
            reservation = OllamaV2NativeReservationD2.create(
                binding,
                fence_generation=head.fence_generation + 1,
                previous_fence_sequence=head.record_sequence,
                previous_fence_hash=head.record_head_hash,
            )
            event = CustodyLedgerReferenceEventDocument.create(
                sequence=head.event_sequence + 1,
                event_type="reservation.held",
                artifact=reservation,
                binding=binding,
                previous_event_hash=head.event_head_hash,
            )
            self._assert_no_unique_collision(event)
            self._insert_event(event)
            self._update_head_for_event(event, reservation=reservation)
            after = self._verify_store().snapshot
            return self._finish_event_commit(event, after)
        except CustodyLedgerReferenceStoreError:
            self._rollback()
            raise
        except (OllamaV2NativeExecutionContractError, sqlite3.Error) as exc:
            self._rollback()
            if isinstance(exc, sqlite3.Error):
                _raise_sqlite_failure(exc, "reference_reservation_failed")
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_reservation_invalid"
            ) from exc

    @staticmethod
    def _assert_identifier(value: object) -> None:
        if type(value) is not str or _ID_RE.fullmatch(value) is None:
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_identifier_invalid"
            )

    @staticmethod
    def _require_mutable(snapshot: CustodyLedgerReferenceSnapshot) -> None:
        if snapshot.head.poisoned:
            raise CustodyLedgerReferenceRecoveryRequiredError(
                "reference_store_poisoned"
            )

    @staticmethod
    def _verify_registered_source(
        binding: OllamaV2NativeExecutionBindingD2,
        state: _ReferenceReplay,
    ) -> None:
        source = binding.source_bundle_descriptor
        if source is None:
            if binding.effect_kind in {"release.stage", "model.stage"}:
                raise CustodyLedgerReferenceConflictError(
                    "reference_source_registration_mismatch"
                )
            return
        if binding.effect_kind not in {"release.stage", "model.stage"}:
            raise CustodyLedgerReferenceConflictError(
                "reference_source_registration_mismatch"
            )
        registered = state.sources.get(source.descriptor_id)
        if registered is None:
            raise CustodyLedgerReferenceConflictError(
                "reference_source_not_registered"
            )
        if registered[0].to_bytes() != source.to_bytes():
            raise CustodyLedgerReferenceConflictError(
                "reference_source_registration_mismatch"
            )

    def _begin_immediate(self) -> None:
        self._assert_boundary()
        connection = self._connection
        assert connection is not None
        try:
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            _raise_sqlite_failure(exc, "reference_transaction_begin_failed")

    def _commit(self) -> None:
        connection = self._connection
        assert connection is not None
        connection.execute("COMMIT")

    def _assert_no_unique_collision(
        self,
        event: CustodyLedgerReferenceEventDocument,
    ) -> None:
        connection = self._connection
        assert connection is not None
        row = connection.execute(
            """SELECT event_id FROM ollama_v2_custody_events
            WHERE event_id = ? OR event_hash = ? OR artifact_id = ?
               OR artifact_hash = ? OR (subject_id = ? AND subject_stage = ?)
               OR (? IS NOT NULL AND binding_hash = ?)
            LIMIT 1""",
            (
                event.event_id,
                event.event_hash,
                event.artifact_id,
                event.artifact_hash,
                event.subject_id,
                event.subject_stage,
                event.binding_hash,
                event.binding_hash,
            ),
        ).fetchone()
        if row is not None:
            raise CustodyLedgerReferenceDuplicateMismatchError(
                "reference_duplicate_mismatch"
            )

    def _insert_event(self, event: CustodyLedgerReferenceEventDocument) -> None:
        connection = self._connection
        assert connection is not None
        connection.execute(
            """INSERT INTO ollama_v2_custody_events(
                sequence, event_id, event_type, subject_id, subject_stage,
                artifact_id, artifact_type, artifact_hash, artifact_json,
                binding_hash, binding_json, previous_event_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.sequence,
                event.event_id,
                event.event_type,
                event.subject_id,
                event.subject_stage,
                event.artifact_id,
                event.artifact_type,
                event.artifact_hash,
                event.artifact.to_bytes(),
                event.binding_hash,
                None if event.binding is None else event.binding.to_bytes(),
                event.previous_event_hash,
                event.event_hash,
            ),
        )

    def _update_head_for_event(
        self,
        event: CustodyLedgerReferenceEventDocument,
        *,
        reservation: OllamaV2NativeReservationD2 | None,
    ) -> None:
        connection = self._connection
        assert connection is not None
        if reservation is None:
            cursor = connection.execute(
                """UPDATE ollama_v2_custody_head
                SET event_sequence = ?, event_head_hash = ?
                WHERE scope = ? AND event_sequence = ?
                  AND event_head_hash = ? AND poisoned = 0""",
                (
                    event.sequence,
                    event.event_hash,
                    CUSTODY_SCOPE,
                    event.sequence - 1,
                    event.previous_event_hash,
                ),
            )
        else:
            cursor = connection.execute(
                """UPDATE ollama_v2_custody_head
                SET fence_generation = ?, active_reservation_id = ?,
                    active_fence_hash = ?, active_state = 'reserved',
                    event_sequence = ?, event_head_hash = ?
                WHERE scope = ? AND fence_generation = ?
                  AND record_sequence = ? AND record_head_hash = ?
                  AND active_state = 'idle' AND active_reservation_id IS NULL
                  AND active_fence_hash IS NULL AND event_sequence = ?
                  AND event_head_hash = ? AND poisoned = 0""",
                (
                    reservation.fence_generation,
                    reservation.reservation_id,
                    reservation.fence_hash,
                    event.sequence,
                    event.event_hash,
                    CUSTODY_SCOPE,
                    reservation.fence_generation - 1,
                    reservation.previous_fence_sequence,
                    reservation.previous_fence_hash,
                    event.sequence - 1,
                    event.previous_event_hash,
                ),
            )
        if cursor.rowcount != 1:
            raise CustodyLedgerReferenceConflictError("reference_head_conflict")

    def _finish_event_commit(
        self,
        event: CustodyLedgerReferenceEventDocument,
        snapshot: CustodyLedgerReferenceSnapshot,
    ) -> CustodyLedgerReferenceTransition:
        try:
            self._commit()
            self._assert_boundary()
            return CustodyLedgerReferenceTransition(
                snapshot=snapshot,
                event=event,
                committed_now=True,
            )
        except BaseException as exc:
            self._rollback()
            try:
                with OllamaV2CustodyLedgerReferenceStore(
                    self._root,
                    mode="open",
                ) as probe:
                    if (
                        probe._root_identity != self._root_identity
                        or probe._lock_identity != self._lock_identity
                        or probe._database_identity != self._database_identity
                    ):
                        raise CustodyLedgerReferenceRecoveryRequiredError(
                            "reference_commit_recovery_required"
                        ) from exc
                    replay = probe._verify_store()
                    observed = replay.events.get(event.event_id)
                    if observed is None:
                        raise CustodyLedgerReferenceCommitNotAppliedError(
                            "reference_commit_not_applied"
                        ) from exc
                    if observed != event:
                        raise CustodyLedgerReferenceRecoveryRequiredError(
                            "reference_commit_recovery_required"
                        ) from exc
                    return CustodyLedgerReferenceTransition(
                        snapshot=replay.snapshot,
                        event=observed,
                        committed_now=False,
                    )
            except CustodyLedgerReferenceCommitNotAppliedError:
                raise
            except BaseException as reconcile_error:
                self._poison_best_effort()
                if isinstance(
                    reconcile_error,
                    CustodyLedgerReferenceRecoveryRequiredError,
                ):
                    raise
                raise CustodyLedgerReferenceRecoveryRequiredError(
                    "reference_commit_recovery_required"
                ) from exc

    def _poison_best_effort(self) -> None:
        try:
            descriptor = self._database_descriptor
            if descriptor is None:
                return
            descriptor_path = _DESCRIPTOR_DIRECTORY / str(descriptor)
            if file_identity(os.stat(descriptor_path)) != self._database_identity:
                return
            connection = sqlite3.connect(
                f"{descriptor_path.as_uri()}?mode=rw",
                isolation_level=None,
                timeout=BUSY_TIMEOUT_MS / 1_000,
                uri=True,
            )
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "UPDATE ollama_v2_custody_head SET poisoned = 1 WHERE scope = ?",
                    (CUSTODY_SCOPE,),
                )
                connection.execute("COMMIT")
            finally:
                connection.close()
        except BaseException:
            pass

    def close(self) -> None:
        if os.getpid() != self._owner_pid:
            self._close_resources(unlock=False)
            self._closed = True
            return
        if self._closed:
            return
        boundary_error: BaseException | None = None
        try:
            self._assert_boundary()
        except BaseException as exc:
            boundary_error = exc
        self._close_resources(unlock=True)
        self._closed = True
        if boundary_error is not None:
            raise boundary_error

    @staticmethod
    def _validated_root_path(root: str | Path) -> Path:
        if not isinstance(root, (str, Path)):
            raise CustodyLedgerReferenceInvalidStateError("reference_root_invalid")
        raw = os.fspath(root)
        if type(raw) is not str or not raw or "\0" in raw:
            raise CustodyLedgerReferenceInvalidStateError("reference_root_invalid")
        supplied = Path(raw)
        if not supplied.is_absolute():
            raise CustodyLedgerReferenceInvalidStateError("reference_root_not_absolute")
        if ".." in supplied.parts:
            raise CustodyLedgerReferenceInvalidStateError("reference_root_ambiguous")
        normalized = Path(os.path.normpath(raw))
        comparison = Path("/" + str(normalized).lstrip("/"))
        if comparison == Path(CUSTODY_TARGET_ROOT):
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_root_canonical_target_forbidden"
            )
        if raw.startswith("//"):
            raise CustodyLedgerReferenceInvalidStateError("reference_root_ambiguous")
        return normalized

    @staticmethod
    def _require_supported_platform() -> None:
        if (
            os.name != "posix"
            or not hasattr(os, "getuid")
            or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY")
        ):
            raise CustodyLedgerReferenceUnsupportedError(
                "reference_store_platform_unsupported"
            )
        try:
            import fcntl
        except (ImportError, AttributeError) as exc:
            raise CustodyLedgerReferenceUnsupportedError(
                "reference_store_lock_unsupported"
            ) from exc
        if any(
            not hasattr(fcntl, name)
            for name in ("flock", "LOCK_EX", "LOCK_SH", "LOCK_NB", "LOCK_UN")
        ):
            raise CustodyLedgerReferenceUnsupportedError(
                "reference_store_lock_unsupported"
            )
        try:
            descriptor_directory = os.stat(_DESCRIPTOR_DIRECTORY)
        except OSError as exc:
            raise CustodyLedgerReferenceUnsupportedError(
                "reference_store_descriptor_reopen_unsupported"
            ) from exc
        if not stat.S_ISDIR(descriptor_directory.st_mode):
            raise CustodyLedgerReferenceUnsupportedError(
                "reference_store_descriptor_reopen_unsupported"
            )

    def _verify_root(self) -> tuple[int, int]:
        current = Path(self._root.anchor)
        try:
            for component in self._root.parts[1:]:
                current /= component
                info = path_file_stat(current)
                if is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
                    raise CustodyLedgerReferenceInvalidStateError(
                        "reference_root_symlink_forbidden"
                    )
        except FileNotFoundError:
            raise CustodyLedgerReferenceInvalidStateError("reference_root_missing") from None
        except CustodyLedgerReferenceStoreError:
            raise
        except (OSError, ValueError) as exc:
            raise CustodyLedgerReferenceInvalidStateError("reference_path_unsafe") from exc
        try:
            final = path_file_stat(self._root)
        except FileNotFoundError:
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_root_missing"
            ) from None
        except (OSError, ValueError) as exc:
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_path_unsafe"
            ) from exc
        if (
            not stat.S_ISDIR(final.st_mode)
            or final.st_uid != os.getuid()
            or stat.S_IMODE(final.st_mode) != 0o700
        ):
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_root_permissions_invalid"
            )
        return file_identity(final)

    def _open_root_descriptor(self) -> None:
        expected = self._verify_root()
        flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(self._root, flags)
        except OSError as exc:
            raise CustodyLedgerReferenceInvalidStateError("reference_path_unsafe") from exc
        try:
            info = descriptor_file_stat(descriptor)
            if (
                is_link_or_reparse(info)
                or not stat.S_ISDIR(info.st_mode)
                or file_identity(info) != expected
            ):
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_root_replaced"
                )
        except BaseException:
            os.close(descriptor)
            raise
        self._root_descriptor = descriptor
        self._root_identity = expected

    @staticmethod
    def _path_exists(path: Path) -> bool:
        try:
            path_file_stat(path)
        except FileNotFoundError:
            return False
        except (OSError, ValueError) as exc:
            raise CustodyLedgerReferenceInvalidStateError("reference_path_unsafe") from exc
        return True

    @staticmethod
    def _open_flags() -> int:
        return (
            os.O_RDWR
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOINHERIT", 0)
            | getattr(os, "O_BINARY", 0)
        )

    def _open_lock(self, *, create: bool) -> bool:
        descriptor: int | None = None
        created = False
        if create:
            try:
                descriptor = os.open(
                    self._lock_path,
                    self._open_flags() | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                created = True
            except FileExistsError:
                pass
            except OSError as exc:
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_lock_open_failed"
                ) from exc
        if descriptor is None:
            try:
                descriptor = os.open(self._lock_path, self._open_flags())
            except FileNotFoundError:
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_lock_missing"
                ) from None
            except OSError as exc:
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_lock_open_failed"
                ) from exc
        try:
            if created:
                self._acquire_file_lock(descriptor, exclusive=True)
                os.fchmod(descriptor, 0o600)
                if os.write(descriptor, _LOCK_IDENTITY) != 1:
                    raise OSError("short lock identity write")
                os.fsync(descriptor)
                self._lock_identity = self._verify_file_descriptor(
                    descriptor,
                    self._lock_path,
                    marker=_LOCK_IDENTITY,
                    invalid_reason="reference_lock_invalid",
                )
            else:
                self._lock_identity = self._wait_for_initialized_lock(descriptor)
        except BaseException:
            self._release_file_lock(descriptor)
            os.close(descriptor)
            raise
        self._lock_descriptor = descriptor
        return created

    def _wait_for_initialized_lock(self, descriptor: int) -> tuple[int, int]:
        deadline = time.monotonic() + BUSY_TIMEOUT_MS / 1_000
        while True:
            self._acquire_file_lock(descriptor, exclusive=False)
            try:
                return self._verify_file_descriptor(
                    descriptor,
                    self._lock_path,
                    marker=_LOCK_IDENTITY,
                    invalid_reason="reference_lock_invalid",
                )
            except CustodyLedgerReferenceInvalidStateError:
                try:
                    transient = (
                        descriptor_file_stat(descriptor).st_size == 0
                        and not self._path_exists(self._database_path)
                    )
                except CustodyLedgerReferenceStoreError:
                    transient = False
                if not transient or time.monotonic() >= deadline:
                    raise
                self._release_file_lock(descriptor)
                time.sleep(0.01)

    @staticmethod
    def _acquire_file_lock(descriptor: int, *, exclusive: bool) -> None:
        try:
            import fcntl

            requested = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            deadline = time.monotonic() + BUSY_TIMEOUT_MS / 1_000
            while True:
                try:
                    fcntl.flock(descriptor, requested | fcntl.LOCK_NB)
                    return
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise CustodyLedgerReferenceInvalidStateError(
                            "reference_store_lock_busy"
                        ) from None
                    time.sleep(0.01)
        except CustodyLedgerReferenceStoreError:
            raise
        except (ImportError, AttributeError, OSError) as exc:
            raise CustodyLedgerReferenceUnsupportedError(
                "reference_store_lock_unsupported"
            ) from exc

    @staticmethod
    def _release_file_lock(descriptor: int) -> None:
        try:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except (ImportError, AttributeError, OSError):
            pass

    def _open_database(self, *, create: bool) -> None:
        descriptor: int | None = None
        if create:
            try:
                descriptor = os.open(
                    self._database_path,
                    self._open_flags() | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_store_partial"
                ) from None
            except OSError as exc:
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_database_open_failed"
                ) from exc
        if descriptor is None:
            try:
                descriptor = os.open(self._database_path, self._open_flags())
            except FileNotFoundError:
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_store_missing"
                ) from None
            except OSError as exc:
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_database_open_failed"
                ) from exc
        try:
            if create:
                os.fchmod(descriptor, 0o600)
            self._database_identity = self._verify_file_descriptor(
                descriptor,
                self._database_path,
                marker=None,
                invalid_reason="reference_database_invalid",
            )
        except BaseException:
            os.close(descriptor)
            raise
        self._database_descriptor = descriptor

    def _connect(self) -> None:
        descriptor = self._database_descriptor
        assert descriptor is not None
        descriptor_path = _DESCRIPTOR_DIRECTORY / str(descriptor)
        try:
            descriptor_identity = file_identity(os.stat(descriptor_path))
        except OSError as exc:
            raise CustodyLedgerReferenceUnsupportedError(
                "reference_store_descriptor_reopen_unsupported"
            ) from exc
        if descriptor_identity != self._database_identity:
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_database_descriptor_replaced"
            )
        try:
            connection = sqlite3.connect(
                f"{descriptor_path.as_uri()}?mode=rw",
                timeout=BUSY_TIMEOUT_MS / 1_000,
                isolation_level=None,
                uri=True,
            )
            connection.row_factory = sqlite3.Row
        except sqlite3.Error as exc:
            _raise_sqlite_failure(exc, "reference_database_connect_failed")
        self._connection = connection

    def _configure_connection(self, *, new_database: bool) -> None:
        connection = self._connection
        assert connection is not None
        try:
            journal_mode = str(
                connection.execute("PRAGMA journal_mode").fetchone()[0]
            ).casefold()
            if new_database:
                journal_mode = str(
                    connection.execute("PRAGMA journal_mode = DELETE").fetchone()[0]
                ).casefold()
            elif journal_mode != "delete":
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_database_journal_mode_invalid"
                )
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA ignore_check_constraints = OFF")
            connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA synchronous = FULL")
        except CustodyLedgerReferenceStoreError:
            raise
        except sqlite3.Error as exc:
            _raise_sqlite_failure(exc, "reference_database_configuration_failed")
        if journal_mode != "delete":
            raise CustodyLedgerReferenceCorruptionError(
                "reference_database_journal_mode_invalid"
            )

    def _initialize_or_verify(self, *, allow_initialize: bool) -> None:
        connection = self._connection
        assert connection is not None
        try:
            connection.execute("BEGIN EXCLUSIVE")
            objects = connection.execute(
                "SELECT name FROM sqlite_schema LIMIT 1"
            ).fetchone()
            if objects is None:
                if not allow_initialize:
                    raise CustodyLedgerReferenceCorruptionError(
                        "reference_schema_missing"
                    )
                for sql in _DDL_BY_NAME.values():
                    connection.execute(sql)
                connection.executemany(
                    "INSERT INTO ollama_v2_custody_metadata(key, value) VALUES (?, ?)",
                    (
                        ("schema_version", str(SCHEMA_VERSION)),
                        ("schema_fingerprint", SCHEMA_FINGERPRINT),
                        ("store_kind", REFERENCE_STORE_KIND),
                    ),
                )
                connection.execute(
                    """INSERT INTO ollama_v2_custody_head(
                        scope, fence_generation, record_sequence, record_head_hash,
                        active_reservation_id, active_fence_hash, active_state,
                        event_sequence, event_head_hash, poisoned
                    ) VALUES (?, 0, 0, ?, NULL, NULL, 'idle', 0, ?, 0)""",
                    (CUSTODY_SCOPE, _ZERO_HASH, _ZERO_HASH),
                )
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            connection.execute("COMMIT")
        except CustodyLedgerReferenceStoreError:
            self._rollback()
            raise
        except sqlite3.Error as exc:
            self._rollback()
            _raise_sqlite_failure(exc, "reference_schema_initialization_failed")
        self._verify_store()

    def _rollback(self) -> None:
        connection = self._connection
        if connection is None:
            return
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _assert_boundary(self) -> None:
        if os.getpid() != self._owner_pid:
            self._close_resources(unlock=False)
            self._closed = True
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_store_process_mismatch"
            )
        if self._closed:
            raise CustodyLedgerReferenceClosedError("reference_store_closed")
        root_descriptor = self._root_descriptor
        lock_descriptor = self._lock_descriptor
        database_descriptor = self._database_descriptor
        if root_descriptor is None or lock_descriptor is None or database_descriptor is None:
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_store_identity_lost"
            )
        if self._verify_root() != self._root_identity:
            raise CustodyLedgerReferenceInvalidStateError("reference_root_replaced")
        try:
            root_info = descriptor_file_stat(root_descriptor)
        except OSError as exc:
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_root_replaced"
            ) from exc
        if (
            is_link_or_reparse(root_info)
            or not stat.S_ISDIR(root_info.st_mode)
            or file_identity(root_info) != self._root_identity
        ):
            raise CustodyLedgerReferenceInvalidStateError("reference_root_replaced")
        if (
            self._verify_file_descriptor(
                lock_descriptor,
                self._lock_path,
                marker=_LOCK_IDENTITY,
                invalid_reason="reference_lock_replaced",
            )
            != self._lock_identity
        ):
            raise CustodyLedgerReferenceInvalidStateError("reference_lock_replaced")
        if (
            self._verify_file_descriptor(
                database_descriptor,
                self._database_path,
                marker=None,
                invalid_reason="reference_database_replaced",
            )
            != self._database_identity
        ):
            raise CustodyLedgerReferenceInvalidStateError(
                "reference_database_replaced"
            )
        self._assert_sidecars_absent(allow_delete_journal=True)

    def _assert_sidecars_absent(self, *, allow_delete_journal: bool = False) -> None:
        for suffix in ("-wal", "-shm", "-journal"):
            if suffix == "-journal" and allow_delete_journal:
                continue
            if self._path_exists(Path(f"{self._database_path}{suffix}")):
                raise CustodyLedgerReferenceInvalidStateError(
                    "reference_database_sidecar_unexpected"
                )

    @staticmethod
    def _read_marker(descriptor: int) -> bytes:
        try:
            return os.pread(descriptor, 2, 0)
        except AttributeError:
            position = os.lseek(descriptor, 0, os.SEEK_CUR)
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                return os.read(descriptor, 2)
            finally:
                os.lseek(descriptor, position, os.SEEK_SET)

    @classmethod
    def _verify_file_descriptor(
        cls,
        descriptor: int,
        path: Path,
        *,
        marker: bytes | None,
        invalid_reason: str,
    ) -> tuple[int, int]:
        try:
            info = descriptor_file_stat(descriptor)
            named = path_file_stat(path)
        except (FileNotFoundError, OSError, ValueError) as exc:
            raise CustodyLedgerReferenceInvalidStateError(invalid_reason) from exc
        identity = file_identity(info)
        if (
            is_link_or_reparse(info)
            or is_link_or_reparse(named)
            or not stat.S_ISREG(info.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or info.st_uid != os.getuid()
            or named.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or stat.S_IMODE(named.st_mode) != 0o600
            or info.st_nlink != 1
            or named.st_nlink != 1
            or identity != file_identity(named)
            or (
                marker is not None
                and (info.st_size != 1 or cls._read_marker(descriptor) != marker)
            )
        ):
            raise CustodyLedgerReferenceInvalidStateError(invalid_reason)
        return identity

    def _verify_store(self) -> _ReferenceReplay:
        connection = self._connection
        assert connection is not None
        owns_transaction = not connection.in_transaction
        if owns_transaction:
            try:
                connection.execute("BEGIN")
            except sqlite3.Error as exc:
                _raise_sqlite_failure(exc, "reference_read_transaction_failed")
        try:
            replay = self._verify_store_in_transaction()
            if owns_transaction:
                connection.execute("COMMIT")
            return replay
        except BaseException:
            if owns_transaction:
                self._rollback()
            raise

    def _verify_store_in_transaction(self) -> _ReferenceReplay:
        connection = self._connection
        assert connection is not None
        try:
            pragmas = {
                "application_id": connection.execute("PRAGMA application_id").fetchone()[0],
                "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
                "foreign_keys": connection.execute("PRAGMA foreign_keys").fetchone()[0],
                "trusted_schema": connection.execute("PRAGMA trusted_schema").fetchone()[0],
                "ignore_check_constraints": connection.execute(
                    "PRAGMA ignore_check_constraints"
                ).fetchone()[0],
                "busy_timeout": connection.execute("PRAGMA busy_timeout").fetchone()[0],
                "synchronous": connection.execute("PRAGMA synchronous").fetchone()[0],
                "journal_mode": str(
                    connection.execute("PRAGMA journal_mode").fetchone()[0]
                ).casefold(),
            }
            expected_pragmas = {
                "application_id": APPLICATION_ID,
                "user_version": SCHEMA_VERSION,
                "foreign_keys": 1,
                "trusted_schema": 0,
                "ignore_check_constraints": 0,
                "busy_timeout": BUSY_TIMEOUT_MS,
                "synchronous": 2,
                "journal_mode": "delete",
            }
            if pragmas != expected_pragmas:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_schema_pragmas_invalid"
                )
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_sqlite_integrity_invalid"
                )
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_sqlite_foreign_key_invalid"
                )
            self._verify_schema_objects()
            self._verify_table_census()
            metadata_rows = connection.execute(
                "SELECT key, value, typeof(key), typeof(value) "
                "FROM ollama_v2_custody_metadata ORDER BY key"
            ).fetchall()
            metadata = [(row[0], row[1], row[2], row[3]) for row in metadata_rows]
            if metadata != [
                ("schema_fingerprint", SCHEMA_FINGERPRINT, "text", "text"),
                ("schema_version", str(SCHEMA_VERSION), "text", "text"),
                ("store_kind", REFERENCE_STORE_KIND, "text", "text"),
            ]:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_schema_metadata_invalid"
                )
            head_rows = connection.execute(
                "SELECT *, typeof(scope), typeof(fence_generation), "
                "typeof(record_sequence), typeof(record_head_hash), "
                "typeof(active_reservation_id), typeof(active_fence_hash), "
                "typeof(active_state), typeof(event_sequence), "
                "typeof(event_head_hash), typeof(poisoned) "
                "FROM ollama_v2_custody_head"
            ).fetchall()
            if len(head_rows) != 1:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_head_census_invalid"
                )
            row = head_rows[0]
            values = tuple(row[index] for index in range(10))
            storage = tuple(row[index] for index in range(10, 20))
            expected_storage = (
                "text",
                "integer",
                "integer",
                "text",
                "null" if values[4] is None else "text",
                "null" if values[5] is None else "text",
                "text",
                "integer",
                "text",
                "integer",
            )
            if storage != expected_storage or values[9] not in {0, 1}:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_head_storage_invalid"
                )
            try:
                persisted_head = CustodyLedgerReferenceHead(
                    scope=values[0],
                    fence_generation=values[1],
                    record_sequence=values[2],
                    record_head_hash=values[3],
                    active_reservation_id=values[4],
                    active_fence_hash=values[5],
                    active_state=values[6],
                    event_sequence=values[7],
                    event_head_hash=values[8],
                    poisoned=bool(values[9]),
                )
            except CustodyLedgerReferenceInvalidStateError as exc:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_head_invalid"
                ) from exc
            replay = self._replay_event_rows(persisted_head)
        except CustodyLedgerReferenceStoreError:
            raise
        except sqlite3.Error as exc:
            _raise_sqlite_failure(exc, "reference_storage_corrupt")
        return replay

    def _replay_event_rows(
        self,
        persisted_head: CustodyLedgerReferenceHead,
    ) -> _ReferenceReplay:
        connection = self._connection
        assert connection is not None
        rows = connection.execute(
            """SELECT *,
                typeof(sequence), typeof(event_id), typeof(event_type),
                typeof(subject_id), typeof(subject_stage), typeof(artifact_id),
                typeof(artifact_type), typeof(artifact_hash), typeof(artifact_json),
                typeof(binding_hash), typeof(binding_json),
                typeof(previous_event_hash), typeof(event_hash)
            FROM ollama_v2_custody_events ORDER BY sequence"""
        ).fetchall()
        expected_sequence = 0
        expected_event_hash = _ZERO_HASH
        fence_generation = 0
        record_sequence = 0
        record_head_hash = _ZERO_HASH
        active_binding: OllamaV2NativeExecutionBindingD2 | None = None
        active_reservation: OllamaV2NativeReservationD2 | None = None
        active_event: CustodyLedgerReferenceEventDocument | None = None
        sources: dict[
            str,
            tuple[
                OllamaV2SourceBundleDescriptorD2,
                CustodyLedgerReferenceEventDocument,
            ],
        ] = {}
        events: dict[str, CustodyLedgerReferenceEventDocument] = {}
        for row in rows:
            values = tuple(row[index] for index in range(13))
            storage = tuple(row[index] for index in range(13, 26))
            expected_storage = (
                "integer",
                "text",
                "text",
                "text",
                "text",
                "text",
                "text",
                "text",
                "blob",
                "null" if values[9] is None else "text",
                "null" if values[10] is None else "blob",
                "text",
                "text",
            )
            if storage != expected_storage or type(values[0]) is not int:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_event_row_bijection_invalid"
                )
            expected_sequence += 1
            if values[0] != expected_sequence or values[11] != expected_event_hash:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_event_chain_invalid"
                )
            try:
                artifact = parse_ollama_v2_native_execution_contract(bytes(values[8]))
                binding = (
                    None
                    if values[10] is None
                    else parse_ollama_v2_native_execution_contract(bytes(values[10]))
                )
                event = CustodyLedgerReferenceEventDocument(
                    sequence=values[0],
                    event_id=values[1],
                    event_type=values[2],
                    subject_id=values[3],
                    subject_stage=values[4],
                    artifact_id=values[5],
                    artifact_type=values[6],
                    artifact_hash=values[7],
                    artifact=artifact,
                    binding_hash=values[9],
                    binding=binding,
                    previous_event_hash=values[11],
                    event_hash=values[12],
                )
            except (
                CustodyLedgerReferenceStoreError,
                OllamaV2NativeExecutionContractError,
                TypeError,
            ) as exc:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_event_semantic_replay_invalid"
                ) from exc
            if (
                event.artifact.to_bytes() != bytes(values[8])
                or (
                    event.binding is None
                    and values[10] is not None
                    or event.binding is not None
                    and event.binding.to_bytes() != bytes(values[10])
                )
                or event.event_id in events
            ):
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_event_row_bijection_invalid"
                )
            if event.event_type == "source.registered":
                source = event.artifact
                assert type(source) is OllamaV2SourceBundleDescriptorD2
                if source.descriptor_id in sources:
                    raise CustodyLedgerReferenceCorruptionError(
                        "reference_source_registry_invalid"
                    )
                sources[source.descriptor_id] = (source, event)
            elif event.event_type == "reservation.held":
                reservation = event.artifact
                binding_value = event.binding
                assert type(reservation) is OllamaV2NativeReservationD2
                assert type(binding_value) is OllamaV2NativeExecutionBindingD2
                if active_reservation is not None:
                    raise CustodyLedgerReferenceCorruptionError(
                        "reference_active_reservation_invalid"
                    )
                source = binding_value.source_bundle_descriptor
                if source is None:
                    source_valid = binding_value.effect_kind not in {
                        "release.stage",
                        "model.stage",
                    }
                else:
                    registered = sources.get(source.descriptor_id)
                    source_valid = (
                        binding_value.effect_kind in {"release.stage", "model.stage"}
                        and registered is not None
                        and registered[0].to_bytes() == source.to_bytes()
                    )
                if (
                    not source_valid
                    or reservation.fence_generation != fence_generation + 1
                    or reservation.previous_fence_sequence != record_sequence
                    or reservation.fence_sequence != record_sequence + 1
                    or reservation.previous_fence_hash != record_head_hash
                ):
                    raise CustodyLedgerReferenceCorruptionError(
                        "reference_reservation_graph_invalid"
                    )
                fence_generation = reservation.fence_generation
                active_binding = binding_value
                active_reservation = reservation
                active_event = event
            else:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_event_type_unsupported"
                )
            events[event.event_id] = event
            expected_event_hash = event.event_hash
        active = active_reservation is not None
        replayed_head = CustodyLedgerReferenceHead(
            scope=CUSTODY_SCOPE,
            fence_generation=fence_generation,
            record_sequence=record_sequence,
            record_head_hash=record_head_hash,
            active_reservation_id=(
                None if active_reservation is None else active_reservation.reservation_id
            ),
            active_fence_hash=(
                None if active_reservation is None else active_reservation.fence_hash
            ),
            active_state="reserved" if active else "idle",
            event_sequence=expected_sequence,
            event_head_hash=expected_event_hash,
            poisoned=persisted_head.poisoned,
        )
        if replayed_head != persisted_head:
            raise CustodyLedgerReferenceCorruptionError(
                "reference_head_replay_mismatch"
            )
        snapshot = CustodyLedgerReferenceSnapshot(
            head=replayed_head,
            active_binding=active_binding,
            active_reservation=active_reservation,
        )
        return _ReferenceReplay(
            snapshot=snapshot,
            sources=sources,
            events=events,
            active_event=active_event,
        )

    def _verify_schema_objects(self) -> None:
        connection = self._connection
        assert connection is not None
        rows = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name"
        ).fetchall()
        actual = {
            str(row[1]): (str(row[0]), str(row[2]), row[3])
            for row in rows
        }
        expected = {
            name: (
                "index" if name.startswith("idx_") else "table",
                "ollama_v2_custody_events" if name.startswith("idx_") else name,
                sql,
            )
            for name, sql in _DDL_BY_NAME.items()
        }
        if actual != expected:
            raise CustodyLedgerReferenceCorruptionError(
                "reference_schema_census_invalid"
            )

    def _verify_table_census(self) -> None:
        connection = self._connection
        assert connection is not None
        for table_name, expected in _TABLE_XINFO.items():
            actual = tuple(
                tuple(row)
                for row in connection.execute(
                    f'PRAGMA table_xinfo("{table_name}")'
                ).fetchall()
            )
            if actual != expected:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_schema_table_census_invalid"
                )
            if connection.execute(
                f'PRAGMA foreign_key_list("{table_name}")'
            ).fetchone() is not None:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_schema_foreign_keys_invalid"
                )
        for table_name, expected_indexes in _INDEX_CENSUS.items():
            actual_indexes = {
                str(row[1]): (int(row[2]), str(row[3]), int(row[4]))
                for row in connection.execute(
                    f'PRAGMA index_list("{table_name}")'
                ).fetchall()
            }
            if actual_indexes != expected_indexes:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_schema_index_census_invalid"
                )
        for name, expected_columns in _INDEX_COLUMNS.items():
            columns = tuple(
                str(row[2])
                for row in connection.execute(f'PRAGMA index_info("{name}")').fetchall()
            )
            if columns != expected_columns:
                raise CustodyLedgerReferenceCorruptionError(
                    "reference_schema_index_census_invalid"
                )

    def _schema_census_unchecked(
        self,
    ) -> tuple[CustodyLedgerReferenceSchemaObject, ...]:
        connection = self._connection
        assert connection is not None
        rows = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name"
        ).fetchall()
        return tuple(
            CustodyLedgerReferenceSchemaObject(
                object_type=str(row[0]),
                name=str(row[1]),
                table_name=str(row[2]),
                sql_sha256=hashlib.sha256(str(row[3]).encode("utf-8")).hexdigest(),
            )
            for row in rows
        )

    def _close_resources(self, *, unlock: bool) -> None:
        connection = self._connection
        if connection is not None:
            try:
                connection.close()
            except BaseException:
                if unlock:
                    raise
            else:
                self._connection = None
            if not unlock:
                self._connection = None
        database_descriptor = self._database_descriptor
        self._database_descriptor = None
        if database_descriptor is not None:
            try:
                os.close(database_descriptor)
            except OSError:
                pass
        lock_descriptor = self._lock_descriptor
        self._lock_descriptor = None
        if lock_descriptor is not None:
            if unlock:
                self._release_file_lock(lock_descriptor)
            try:
                os.close(lock_descriptor)
            except OSError:
                pass
        root_descriptor = self._root_descriptor
        self._root_descriptor = None
        if root_descriptor is not None:
            try:
                os.close(root_descriptor)
            except OSError:
                pass


__all__ = (
    "APPLICATION_ID",
    "BUSY_TIMEOUT_MS",
    "REFERENCE_STORE_KIND",
    "SCHEMA_FINGERPRINT",
    "SCHEMA_VERSION",
    "CustodyLedgerReferenceClosedError",
    "CustodyLedgerReferenceCommitNotAppliedError",
    "CustodyLedgerReferenceConflictError",
    "CustodyLedgerReferenceCorruptionError",
    "CustodyLedgerReferenceDuplicateMismatchError",
    "CustodyLedgerReferenceEventDocument",
    "CustodyLedgerReferenceHead",
    "CustodyLedgerReferenceInvalidStateError",
    "CustodyLedgerReferenceRecoveryRequiredError",
    "CustodyLedgerReferenceSchemaObject",
    "CustodyLedgerReferenceSnapshot",
    "CustodyLedgerReferenceStatus",
    "CustodyLedgerReferenceStoreError",
    "CustodyLedgerReferenceTransition",
    "CustodyLedgerReferenceUnsupportedError",
    "OllamaV2CustodyLedgerReferenceStore",
    "parse_custody_ledger_reference_event",
)
