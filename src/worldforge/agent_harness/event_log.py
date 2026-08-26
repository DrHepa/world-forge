"""Private durable audit log for provider-free Agent Harness executions.

This store records only closed public Harness documents plus code-owned hashes and
control metadata.  It never persists provider payloads, tool arguments, private
inputs or private outputs.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from worldforge.agent_harness_contracts import (
    AGENT_CAPABILITY_GRANT_FORMAT,
    AGENT_EVENT_FORMAT,
    AGENT_EXECUTION_RECEIPT_FORMAT,
    AGENT_MEMORY_PROJECTION_FORMAT,
    AGENT_WORKER_ACTIVATION_FORMAT,
    MAX_AGENT_HARNESS_DOCUMENT_BYTES,
    MAX_SAFE_INTEGER,
    validate_agent_harness_document,
    validate_agent_harness_documents,
)
from worldforge.file_stat import (
    descriptor_file_stat,
    file_identity,
    is_link_or_reparse,
    path_file_stat,
)

if TYPE_CHECKING:
    from .kernel import AgentExecutionKernel
    from .ports import ExecutionRequest, ExecutionResult

AGENT_EVENT_LOG_SCHEMA_VERSION = 2
AGENT_EVENT_LOG_DATABASE_NAME = "agent-events.sqlite3"
AGENT_EVENT_LOG_LOCK_NAME = "agent-events.lock"
MAX_AGENT_EVENT_LOG_EVENTS = 5
MAX_AGENT_EVENT_LOG_EXECUTION_BYTES = 8 * 1024 * 1024
MAX_AGENT_EVENT_LOG_PAGE_SIZE = 100
MAX_AGENT_EVENT_LOG_RECOVERY_SNAPSHOT_BYTES = 64 * 1024 * 1024

_RECOVERY_READ_CHUNK_BYTES = 64 * 1024
_SQLITE_WAL_VERSION = 3_007_000
_SQLITE_WAL_MAGIC_LITTLE_CHECKSUM = 0x377F0682
_SQLITE_WAL_MAGIC_BIG_CHECKSUM = 0x377F0683

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_STATES = frozenset({"open", "terminal", "recovery_required"})
_STATE_FORMAT = "world-forge.private.agent_event_log_state"
_STATE_FORMAT_VERSION = 1
_LOCAL_LOCK_FILE_SYSTEMS = frozenset(
    {
        "apfs",
        "btrfs",
        "ext2",
        "ext3",
        "ext4",
        "f2fs",
        "jfs",
        "overlay",
        "tmpfs",
        "ufs",
        "xfs",
        "zfs",
    }
)
_SCHEMA_TABLE_SQL_V1 = {
    "schema_meta": """CREATE TABLE schema_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                )""",
    "executions": """CREATE TABLE executions (
                    execution_id TEXT PRIMARY KEY NOT NULL,
                    log_id TEXT NOT NULL UNIQUE,
                    request_fingerprint TEXT,
                    activation_hash TEXT NOT NULL,
                    grant_hash TEXT NOT NULL,
                    activation_json BLOB NOT NULL,
                    grant_json BLOB NOT NULL,
                    state TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    next_sequence INTEGER NOT NULL,
                    head_hash TEXT,
                    receipt_id TEXT,
                    receipt_hash TEXT,
                    state_hash TEXT NOT NULL
                )""",
    "events": """CREATE TABLE events (
                    execution_id TEXT NOT NULL REFERENCES executions(execution_id),
                    sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    event_hash TEXT NOT NULL UNIQUE,
                    event_json BLOB NOT NULL,
                    PRIMARY KEY (execution_id, sequence)
                )""",
    "receipts": """CREATE TABLE receipts (
                    execution_id TEXT PRIMARY KEY NOT NULL REFERENCES executions(execution_id),
                    receipt_id TEXT NOT NULL UNIQUE,
                    receipt_hash TEXT NOT NULL UNIQUE,
                    receipt_json BLOB NOT NULL
                )""",
}
_SCHEMA_TABLE_SQL = {
    **_SCHEMA_TABLE_SQL_V1,
    "memory_projections": """CREATE TABLE memory_projections (
                    execution_id TEXT PRIMARY KEY NOT NULL REFERENCES executions(execution_id),
                    projection_id TEXT NOT NULL UNIQUE,
                    projection_hash TEXT NOT NULL UNIQUE,
                    request_fingerprint TEXT NOT NULL,
                    projection_json BLOB NOT NULL
                )""",
}
_EXPECTED_SCHEMA_MANIFESTS = {
    1: tuple(sorted(("table", name, name, sql) for name, sql in _SCHEMA_TABLE_SQL_V1.items())),
    2: tuple(sorted(("table", name, name, sql) for name, sql in _SCHEMA_TABLE_SQL.items())),
}
_EXPECTED_INTERNAL_SCHEMA_OBJECTS = {
    1: tuple(
        sorted(
            (
                ("index", "sqlite_autoindex_schema_meta_1", "schema_meta"),
                ("index", "sqlite_autoindex_executions_1", "executions"),
                ("index", "sqlite_autoindex_executions_2", "executions"),
                ("index", "sqlite_autoindex_events_1", "events"),
                ("index", "sqlite_autoindex_events_2", "events"),
                ("index", "sqlite_autoindex_events_3", "events"),
                ("index", "sqlite_autoindex_receipts_1", "receipts"),
                ("index", "sqlite_autoindex_receipts_2", "receipts"),
                ("index", "sqlite_autoindex_receipts_3", "receipts"),
            )
        )
    ),
}
_EXPECTED_INTERNAL_SCHEMA_OBJECTS[2] = tuple(
    sorted(
        (
            *_EXPECTED_INTERNAL_SCHEMA_OBJECTS[1],
            ("index", "sqlite_autoindex_memory_projections_1", "memory_projections"),
            ("index", "sqlite_autoindex_memory_projections_2", "memory_projections"),
            ("index", "sqlite_autoindex_memory_projections_3", "memory_projections"),
        )
    )
)
_SCHEMA_COLUMNS = {
    "schema_meta": ("key", "value"),
    "executions": (
        "execution_id",
        "log_id",
        "request_fingerprint",
        "activation_hash",
        "grant_hash",
        "activation_json",
        "grant_json",
        "state",
        "generation",
        "next_sequence",
        "head_hash",
        "receipt_id",
        "receipt_hash",
        "state_hash",
    ),
    "events": ("execution_id", "sequence", "event_id", "event_hash", "event_json"),
    "receipts": ("execution_id", "receipt_id", "receipt_hash", "receipt_json"),
    "memory_projections": (
        "execution_id",
        "projection_id",
        "projection_hash",
        "request_fingerprint",
        "projection_json",
    ),
}
_SCHEMA_COLUMN_SHAPES = {
    "schema_meta": (("key", "TEXT", 1, 1), ("value", "TEXT", 1, 0)),
    "executions": (
        ("execution_id", "TEXT", 1, 1),
        ("log_id", "TEXT", 1, 0),
        ("request_fingerprint", "TEXT", 0, 0),
        ("activation_hash", "TEXT", 1, 0),
        ("grant_hash", "TEXT", 1, 0),
        ("activation_json", "BLOB", 1, 0),
        ("grant_json", "BLOB", 1, 0),
        ("state", "TEXT", 1, 0),
        ("generation", "INTEGER", 1, 0),
        ("next_sequence", "INTEGER", 1, 0),
        ("head_hash", "TEXT", 0, 0),
        ("receipt_id", "TEXT", 0, 0),
        ("receipt_hash", "TEXT", 0, 0),
        ("state_hash", "TEXT", 1, 0),
    ),
    "events": (
        ("execution_id", "TEXT", 1, 1),
        ("sequence", "INTEGER", 1, 2),
        ("event_id", "TEXT", 1, 0),
        ("event_hash", "TEXT", 1, 0),
        ("event_json", "BLOB", 1, 0),
    ),
    "receipts": (
        ("execution_id", "TEXT", 1, 1),
        ("receipt_id", "TEXT", 1, 0),
        ("receipt_hash", "TEXT", 1, 0),
        ("receipt_json", "BLOB", 1, 0),
    ),
    "memory_projections": (
        ("execution_id", "TEXT", 1, 1),
        ("projection_id", "TEXT", 1, 0),
        ("projection_hash", "TEXT", 1, 0),
        ("request_fingerprint", "TEXT", 1, 0),
        ("projection_json", "BLOB", 1, 0),
    ),
}


class _WindowsOverlapped(ctypes.Structure):
    _fields_ = [
        ("internal", ctypes.c_size_t),
        ("internal_high", ctypes.c_size_t),
        ("offset", ctypes.c_uint32),
        ("offset_high", ctypes.c_uint32),
        ("event", ctypes.c_void_p),
    ]


def _windows_lock_flags(exclusive: bool) -> int:
    return 0x00000001 | (0x00000002 if exclusive else 0)


def _windows_drive_type_supported(drive_type: int) -> bool:
    return type(drive_type) is int and drive_type == 3


def _decode_mount_path(value: str) -> str:
    for encoded, decoded in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        value = value.replace(encoded, decoded)
    return value


def _lock_filesystem_type_supported(filesystem: object) -> bool:
    return type(filesystem) is str and filesystem in _LOCAL_LOCK_FILE_SYSTEMS


def _lock_filesystem_supported(root: Path) -> bool:
    if os.name == "nt":
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            get_drive_type = kernel32.GetDriveTypeW
            get_drive_type.argtypes = [ctypes.c_wchar_p]
            get_drive_type.restype = ctypes.c_uint32
            return _windows_drive_type_supported(int(get_drive_type(root.anchor)))
        except (AttributeError, OSError, TypeError, ValueError):
            return False
    if os.name != "posix" or not Path("/proc/self/mountinfo").is_file():
        return False
    try:
        lines = Path("/proc/self/mountinfo").read_text("utf-8").splitlines()
    except (OSError, UnicodeError):
        return False
    selected: tuple[int, str] | None = None
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
            mount_point = Path(_decode_mount_path(fields[4]))
            filesystem = fields[separator + 1]
        except (IndexError, ValueError):
            return False
        if root == mount_point or root.is_relative_to(mount_point):
            candidate = (len(mount_point.parts), filesystem)
            if selected is None or candidate[0] > selected[0]:
                selected = candidate
    return selected is not None and _lock_filesystem_type_supported(selected[1])


def _windows_lock_handle(
    handle: int,
    *,
    exclusive: bool,
    kernel32: object | None = None,
    last_error: Callable[[], int] | None = None,
) -> None:
    if kernel32 is None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if last_error is None:
        last_error = ctypes.get_last_error
    lock_file = kernel32.LockFileEx
    lock_file.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(_WindowsOverlapped),
    ]
    lock_file.restype = ctypes.c_int
    overlapped = _WindowsOverlapped()
    if lock_file(
        ctypes.c_void_p(handle),
        _windows_lock_flags(exclusive),
        0,
        1,
        0,
        ctypes.byref(overlapped),
    ):
        return
    error = int(last_error())
    if error in {32, 33}:
        raise AgentEventLogConflict("event_log_recovery_active")
    raise OSError(error, "LockFileEx failed")


def _acquire_os_lock(descriptor: int, *, exclusive: bool) -> None:
    if os.name == "posix":
        try:
            import fcntl

            mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            fcntl.flock(descriptor, mode | fcntl.LOCK_NB)
            return
        except BlockingIOError as exc:
            raise AgentEventLogConflict("event_log_recovery_active") from exc
        except (ImportError, OSError) as exc:
            raise AgentEventLogError("event_log_lock_unsupported") from exc
    if os.name == "nt":
        try:
            import msvcrt

            handle = msvcrt.get_osfhandle(descriptor)
            _windows_lock_handle(handle, exclusive=exclusive)
            return
        except AgentEventLogError:
            raise
        except (AttributeError, ImportError, OSError, ValueError) as exc:
            raise AgentEventLogError("event_log_lock_unsupported") from exc
    raise AgentEventLogError("event_log_lock_unsupported")


def _release_os_lock(descriptor: int) -> None:
    if os.name == "posix":
        try:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except (ImportError, OSError):
            pass
    elif os.name == "nt":
        try:
            import msvcrt

            handle = msvcrt.get_osfhandle(descriptor)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            unlock_file = kernel32.UnlockFileEx
            unlock_file.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.POINTER(_WindowsOverlapped),
            ]
            unlock_file.restype = ctypes.c_int
            overlapped = _WindowsOverlapped()
            unlock_file(ctypes.c_void_p(handle), 0, 1, 0, ctypes.byref(overlapped))
        except (AttributeError, ImportError, OSError, ValueError):
            pass


_SCHEMA_UNIQUE_INDEXES = {
    "schema_meta": (("pk", ("key",)),),
    "executions": (("pk", ("execution_id",)), ("u", ("log_id",))),
    "events": (
        ("pk", ("execution_id", "sequence")),
        ("u", ("event_hash",)),
        ("u", ("event_id",)),
    ),
    "receipts": (
        ("pk", ("execution_id",)),
        ("u", ("receipt_hash",)),
        ("u", ("receipt_id",)),
    ),
    "memory_projections": (
        ("pk", ("execution_id",)),
        ("u", ("projection_hash",)),
        ("u", ("projection_id",)),
    ),
}


class AgentEventLogError(ValueError):
    """Base error for a private durable Agent Harness event log."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class AgentEventLogConflict(AgentEventLogError):
    """A deterministic ID, lifecycle or compare-and-swap conflict."""


class AgentEventLogIndeterminate(AgentEventLogError):
    """The store cannot prove whether a durable boundary committed."""


class AgentEventLogCorrupt(AgentEventLogError):
    """Persisted bytes or their relational projection are incoherent."""


@dataclass(frozen=True, slots=True)
class _RetainedRecoveryFile:
    path: Path
    descriptor: int
    identity: tuple[int, int]
    size: int
    digest: str


@dataclass(frozen=True, slots=True)
class _WalFrame:
    page_number: int
    database_size: int
    page: bytes


@dataclass(frozen=True, slots=True)
class ReplayedExecution:
    execution_id: str
    log_id: str
    request_fingerprint: str | None
    state: str
    generation: int
    next_sequence: int
    head_hash: str | None
    state_hash: str
    activation_bytes: bytes
    grant_bytes: bytes
    event_bytes: tuple[bytes, ...]
    receipt_bytes: bytes | None
    projection_bytes: bytes | None


@dataclass(frozen=True, slots=True)
class OpenExecution:
    execution_id: str
    log_id: str
    request_fingerprint: str | None
    generation: int
    next_sequence: int
    head_hash: str | None


@dataclass(frozen=True, slots=True)
class CoordinatedExecution:
    disposition: str
    records: ReplayedExecution
    result: ExecutionResult | None


def _wal_checksum(
    payload: bytes,
    *,
    byteorder: str,
    first: int = 0,
    second: int = 0,
) -> tuple[int, int]:
    if len(payload) % 8 != 0:
        raise AgentEventLogCorrupt("event_log_storage_corrupt")
    for offset in range(0, len(payload), 8):
        left = int.from_bytes(payload[offset : offset + 4], byteorder)
        right = int.from_bytes(payload[offset + 4 : offset + 8], byteorder)
        first = (first + left + second) & 0xFFFFFFFF
        second = (second + right + first) & 0xFFFFFFFF
    return first, second


def _sqlite_main_page_size(payload: bytes) -> int:
    if len(payload) > MAX_AGENT_EVENT_LOG_RECOVERY_SNAPSHOT_BYTES:
        raise AgentEventLogError("event_log_recovery_snapshot_too_large")
    if len(payload) < 100 or payload[:16] != b"SQLite format 3\x00":
        raise AgentEventLogCorrupt("event_log_storage_corrupt")
    encoded_page_size = int.from_bytes(payload[16:18], "big")
    page_size = 65_536 if encoded_page_size == 1 else encoded_page_size
    if (
        page_size < 512
        or page_size > 65_536
        or page_size & (page_size - 1) != 0
        or len(payload) < page_size
        or len(payload) % page_size != 0
    ):
        raise AgentEventLogCorrupt("event_log_storage_corrupt")
    return page_size


def _validate_wal_bytes(
    payload: bytes,
    *,
    expected_page_size: int,
) -> tuple[_WalFrame, ...]:
    if not payload:
        return ()
    if len(payload) > MAX_AGENT_EVENT_LOG_RECOVERY_SNAPSHOT_BYTES:
        raise AgentEventLogError("event_log_recovery_snapshot_too_large")
    if len(payload) < 32:
        raise AgentEventLogCorrupt("event_log_storage_corrupt")
    magic = int.from_bytes(payload[0:4], "big")
    if magic == _SQLITE_WAL_MAGIC_LITTLE_CHECKSUM:
        checksum_byteorder = "little"
    elif magic == _SQLITE_WAL_MAGIC_BIG_CHECKSUM:
        checksum_byteorder = "big"
    else:
        raise AgentEventLogCorrupt("event_log_storage_corrupt")
    if int.from_bytes(payload[4:8], "big") != _SQLITE_WAL_VERSION:
        raise AgentEventLogCorrupt("event_log_storage_corrupt")
    page_size = int.from_bytes(payload[8:12], "big")
    if (
        page_size < 512
        or page_size > 65_536
        or page_size & (page_size - 1) != 0
        or page_size != expected_page_size
    ):
        raise AgentEventLogCorrupt("event_log_storage_corrupt")
    frame_size = 24 + page_size
    if (len(payload) - 32) % frame_size != 0:
        raise AgentEventLogCorrupt("event_log_storage_corrupt")
    checksum = _wal_checksum(payload[:24], byteorder=checksum_byteorder)
    stored_header_checksum = (
        int.from_bytes(payload[24:28], "big"),
        int.from_bytes(payload[28:32], "big"),
    )
    if checksum != stored_header_checksum:
        raise AgentEventLogCorrupt("event_log_storage_corrupt")
    salt = payload[16:24]
    maximum_pages = MAX_AGENT_EVENT_LOG_RECOVERY_SNAPSHOT_BYTES // page_size
    frames: list[_WalFrame] = []
    for offset in range(32, len(payload), frame_size):
        frame_header = payload[offset : offset + 24]
        page_number = int.from_bytes(frame_header[:4], "big")
        database_size = int.from_bytes(frame_header[4:8], "big")
        if (
            page_number == 0
            or page_number > maximum_pages
            or database_size > maximum_pages
            or frame_header[8:16] != salt
        ):
            raise AgentEventLogCorrupt("event_log_storage_corrupt")
        page = payload[offset + 24 : offset + frame_size]
        checksum = _wal_checksum(
            frame_header[:8] + page,
            byteorder=checksum_byteorder,
            first=checksum[0],
            second=checksum[1],
        )
        stored_frame_checksum = (
            int.from_bytes(frame_header[16:20], "big"),
            int.from_bytes(frame_header[20:24], "big"),
        )
        if checksum != stored_frame_checksum:
            raise AgentEventLogCorrupt("event_log_storage_corrupt")
        frames.append(_WalFrame(page_number, database_size, page))
    return tuple(frames)


def _materialize_offline_recovery_image(main: bytes, wal: bytes) -> bytes:
    if len(main) + len(wal) > MAX_AGENT_EVENT_LOG_RECOVERY_SNAPSHOT_BYTES:
        raise AgentEventLogError("event_log_recovery_snapshot_too_large")
    page_size = _sqlite_main_page_size(main)
    frames = _validate_wal_bytes(wal, expected_page_size=page_size)
    last_commit = -1
    committed_pages = 0
    for index, frame in enumerate(frames):
        if frame.database_size != 0:
            last_commit = index
            committed_pages = frame.database_size
    if last_commit < 0:
        return main
    target_size = committed_pages * page_size
    if target_size > MAX_AGENT_EVENT_LOG_RECOVERY_SNAPSHOT_BYTES:
        raise AgentEventLogError("event_log_recovery_snapshot_too_large")
    image = bytearray(target_size)
    image[: min(len(main), target_size)] = main[:target_size]
    for frame in frames[: last_commit + 1]:
        if frame.page_number > committed_pages:
            continue
        offset = (frame.page_number - 1) * page_size
        image[offset : offset + page_size] = frame.page
    materialized = bytes(image)
    if _sqlite_main_page_size(materialized) != page_size:
        raise AgentEventLogCorrupt("event_log_storage_corrupt")
    return materialized


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_float(_value: str) -> object:
    raise ValueError("stored canonical JSON cannot contain a float literal")


def _reject_constant(_value: str) -> object:
    raise ValueError("stored canonical JSON cannot contain a non-finite number")


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise AgentEventLogCorrupt("event_log_document_invalid") from exc


def _validated_document_bytes(value: object, *, expected_format: str) -> tuple[dict, bytes]:
    try:
        document = validate_agent_harness_document(value, expected_format=expected_format)
        encoded = _canonical_json(document)
    except AgentEventLogError:
        raise
    except Exception as exc:
        raise AgentEventLogCorrupt("event_log_document_invalid") from exc
    if len(encoded) > MAX_AGENT_HARNESS_DOCUMENT_BYTES:
        raise AgentEventLogCorrupt("event_log_document_too_large")
    return document, encoded


def _decode_document(payload: object, *, expected_format: str) -> tuple[dict, bytes]:
    if type(payload) is not bytes:
        raise AgentEventLogCorrupt("event_log_storage_corrupt")
    if len(payload) > MAX_AGENT_HARNESS_DOCUMENT_BYTES:
        raise AgentEventLogCorrupt("event_log_document_too_large")
    try:
        decoded = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise AgentEventLogCorrupt("event_log_storage_corrupt") from exc
    document, canonical = _validated_document_bytes(decoded, expected_format=expected_format)
    if canonical != payload:
        raise AgentEventLogCorrupt("event_log_storage_noncanonical")
    return document, canonical


def _plain_id(value: object, *, reason: str = "event_log_request_invalid") -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise AgentEventLogError(reason)
    return value


def _plain_hash(value: object, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if type(value) is not str or _SHA_RE.fullmatch(value) is None:
        raise AgentEventLogError("event_log_request_invalid")
    return value


def _plain_nonnegative(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise AgentEventLogError("event_log_request_invalid")
    return value


def _memory_projection_event_id(request_fingerprint: object) -> str:
    fingerprint = _plain_hash(request_fingerprint)
    assert fingerprint is not None
    encoded = base64.b32encode(bytes.fromhex(fingerprint)).decode("ascii")
    return "me_" + encoded.casefold().rstrip("=")


def _state_payload(
    *,
    execution_id: str,
    log_id: str,
    request_fingerprint: str | None,
    activation_hash: str,
    grant_hash: str,
    state: str,
    generation: int,
    next_sequence: int,
    head_hash: str | None,
    receipt_id: str | None,
    receipt_hash: str | None,
) -> dict[str, object]:
    return {
        "format": _STATE_FORMAT,
        "format_version": _STATE_FORMAT_VERSION,
        "execution_id": execution_id,
        "log_id": log_id,
        "request_fingerprint": request_fingerprint,
        "activation_hash": activation_hash,
        "grant_hash": grant_hash,
        "state": state,
        "generation": generation,
        "next_sequence": next_sequence,
        "head_hash": head_hash,
        "receipt_id": receipt_id,
        "receipt_hash": receipt_hash,
    }


def _state_hash(**values: object) -> str:
    return hashlib.sha256(_canonical_json(_state_payload(**values))).hexdigest()


def _lifecycle_fold(
    events: list[dict[str, object]], receipt: dict[str, object] | None
) -> tuple[bool, bool]:
    if len(events) > MAX_AGENT_EVENT_LOG_EVENTS:
        raise AgentEventLogCorrupt("event_log_event_bound_exceeded")
    expected_prefix = ("worker.activated", "grant.issued", "execution.started")
    prefix_length = 0
    cancel_seen = False
    terminal_seen = False
    projection_seen = False
    for index, event in enumerate(events):
        event_type = event["event_type"]
        if projection_seen:
            raise AgentEventLogCorrupt("event_log_lifecycle_invalid")
        if event_type == "memory.projected":
            if (
                not terminal_seen
                or receipt is None
                or receipt["outcome"] != "succeeded"
                or index != len(events) - 1
            ):
                raise AgentEventLogCorrupt("event_log_lifecycle_invalid")
            projection_seen = True
        elif terminal_seen:
            raise AgentEventLogCorrupt("event_log_lifecycle_invalid")
        elif event_type in expected_prefix:
            if cancel_seen or prefix_length >= len(expected_prefix):
                raise AgentEventLogCorrupt("event_log_lifecycle_invalid")
            if event_type != expected_prefix[prefix_length]:
                raise AgentEventLogCorrupt("event_log_lifecycle_invalid")
            prefix_length += 1
        elif event_type == "execution.cancel_requested":
            if cancel_seen:
                raise AgentEventLogCorrupt("event_log_lifecycle_invalid")
            cancel_seen = True
        elif event_type == "execution.receipt_recorded":
            if receipt is None:
                raise AgentEventLogCorrupt("event_log_lifecycle_invalid")
            terminal_seen = True
        else:
            raise AgentEventLogCorrupt("event_log_lifecycle_invalid")

    if receipt is not None:
        if not terminal_seen:
            raise AgentEventLogCorrupt("event_log_lifecycle_invalid")
        outcome = receipt["outcome"]
        if outcome == "cancelled" and not cancel_seen:
            raise AgentEventLogCorrupt("event_log_lifecycle_invalid")
        if outcome != "cancelled" and cancel_seen:
            raise AgentEventLogCorrupt("event_log_lifecycle_invalid")
        if outcome == "succeeded" and prefix_length != len(expected_prefix):
            raise AgentEventLogCorrupt("event_log_lifecycle_invalid")
        if outcome == "failed" and prefix_length not in {0, len(expected_prefix)}:
            raise AgentEventLogCorrupt("event_log_lifecycle_invalid")
    elif terminal_seen:
        raise AgentEventLogCorrupt("event_log_lifecycle_invalid")
    return cancel_seen, terminal_seen


def _projection_has_exact_source_lineage(
    projection: dict[str, object],
    source_events: list[dict[str, object]],
) -> bool:
    ordered_events = sorted(
        source_events,
        key=lambda event: str(event["event_id"]).encode("utf-8"),
    )
    expected_refs = [
        {
            "format": AGENT_EVENT_FORMAT,
            "format_version": 1,
            "id": event["event_id"],
            "content_hash": event["content_hash"],
        }
        for event in ordered_events
    ]
    expected_ids = [str(item["id"]) for item in expected_refs]
    return projection["source_events"] == expected_refs and all(
        entry["source_event_ids"] == expected_ids for entry in projection["entries"]
    )


class AgentEventLog:
    """Host-supplied SQLite journal implementing the private journal port."""

    def __init__(
        self,
        root: str | Path,
        *,
        fault_hook: Callable[[str], None] | None = None,
        _recovery_mode: bool = False,
    ) -> None:
        self._owner_pid = os.getpid()
        self._fault_hook = fault_hook
        self._recovery_mode = _recovery_mode
        self._closed = False
        self._lock_descriptor: int | None = None
        self.connection: sqlite3.Connection | None = None
        self._recovery_retained_files: dict[str, _RetainedRecoveryFile | None] = {}
        self._recovery_attested_image_digest: bytes | None = None
        self._recovery_memory_image_digest: bytes | None = None
        self._recovery_memory_active = False
        self._recovery_original_active = False
        self._owned_executions: set[str] = set()
        self._indeterminate_executions: set[str] = set()
        self.root = Path(os.path.abspath(Path(root)))
        if "\x00" in str(self.root):
            raise AgentEventLogError("event_log_path_unsafe")
        self._ensure_safe_root(create=not _recovery_mode)
        self._root_identity = self._directory_identity(self.root)
        if not _lock_filesystem_supported(self.root):
            raise AgentEventLogError("event_log_lock_unsupported")
        self.database_path = self.root / AGENT_EVENT_LOG_DATABASE_NAME
        before = self._safe_file_identity(self.database_path, required=False)
        if _recovery_mode and before is None:
            raise AgentEventLogError("event_log_recovery_store_missing")
        self._validate_sidecars()
        self.lock_path = self.root / AGENT_EVENT_LOG_LOCK_NAME
        self._lock_descriptor = self._open_retained_lock(
            create=before is None and not _recovery_mode
        )
        try:
            _acquire_os_lock(self._lock_descriptor, exclusive=_recovery_mode)
            self._assert_lock_boundary()
            if _recovery_mode:
                assert before is not None
                self.connection = self._open_offline_recovery_snapshot(before)
            else:
                self.connection = sqlite3.connect(self.database_path, timeout=5.0)
        except sqlite3.Error as exc:
            self._discard_recovery_snapshot()
            self._close_lock()
            raise AgentEventLogError("event_log_open_failed") from exc
        except BaseException:
            self._discard_recovery_snapshot()
            self._close_lock()
            raise
        assert self.connection is not None
        self.connection.row_factory = sqlite3.Row
        after = self._safe_file_identity(self.database_path, required=True)
        if before is not None and before != after:
            self.connection.close()
            self._discard_recovery_snapshot()
            self._close_lock()
            raise AgentEventLogError("event_log_path_substituted")
        assert after is not None
        self._database_identity = after
        try:
            if _recovery_mode:
                self._verify_existing_store_readonly()
            else:
                self._configure()
            self._migrate_or_verify(
                new_database=before is None,
                verify_state=_recovery_mode,
            )
            self._sidecar_identities = self._current_sidecar_identities()
            self._assert_boundary()
        except BaseException:
            self.connection.close()
            self._discard_recovery_snapshot()
            self._close_lock()
            raise

    @classmethod
    def recovery(
        cls,
        root: str | Path,
        *,
        fault_hook: Callable[[str], None] | None = None,
    ) -> AgentEventLog:
        """Open an exclusive offline-recovery session for an existing store."""

        return cls(root, fault_hook=fault_hook, _recovery_mode=True)

    def __enter__(self) -> AgentEventLog:
        self._assert_owner_process()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @property
    def schema_version(self) -> int:
        self._assert_owner_process()
        with self._transaction():
            return self._verify_version_locked(allow_legacy=self._recovery_mode)

    def close(self) -> None:
        if os.getpid() != self._owner_pid:
            self._close_inherited_reference()
            return
        if self._closed:
            return
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        self._discard_recovery_snapshot()
        self._owned_executions.clear()
        self._indeterminate_executions.clear()
        self._close_lock()
        self._closed = True

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            # Failed owner-process SQLite close must retain the recovery fence.
            pass

    def _assert_owner_process(self) -> None:
        if os.getpid() != self._owner_pid:
            raise AgentEventLogError("event_log_process_mismatch")

    def _close_inherited_reference(self) -> None:
        if self._closed:
            return
        connection = getattr(self, "connection", None)
        if connection is not None:
            try:
                connection.close()
            except BaseException:
                pass
        self.connection = None
        retained_sets = (getattr(self, "_recovery_retained_files", {}),)
        self._recovery_retained_files = {}
        for retained in retained_sets:
            self._close_retained_files(retained)
        self._owned_executions.clear()
        self._indeterminate_executions.clear()
        self._close_lock(unlock=False)
        self._closed = True

    def _fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)

    def _require_ordinary_session(self) -> None:
        if self._recovery_mode:
            raise AgentEventLogConflict("event_log_recovery_read_only")

    def _require_recovery_session(self) -> None:
        if not self._recovery_mode:
            raise AgentEventLogConflict("event_log_recovery_session_required")

    @staticmethod
    def _directory_identity(path: Path) -> tuple[int, int]:
        try:
            info = path_file_stat(path)
        except (OSError, ValueError) as exc:
            raise AgentEventLogError("event_log_path_unsafe") from exc
        if is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise AgentEventLogError("event_log_path_unsafe")
        return file_identity(info)

    def _ensure_safe_root(self, *, create: bool) -> None:
        if create:
            try:
                self.root.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise AgentEventLogError("event_log_path_unsafe") from exc
        current = Path(self.root.anchor)
        for component in self.root.parts[1:]:
            current /= component
            self._directory_identity(current)

    def _open_retained_lock(self, *, create: bool) -> int:
        flags = (
            os.O_RDWR
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOINHERIT", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor: int | None = None
        created = False
        if create:
            try:
                descriptor = os.open(
                    self.lock_path,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                created = True
            except FileExistsError:
                pass
            except OSError as exc:
                raise AgentEventLogError("event_log_path_unsafe") from exc
        if descriptor is None:
            try:
                descriptor = os.open(self.lock_path, flags)
            except FileNotFoundError:
                raise AgentEventLogError("event_log_path_substituted") from None
            except OSError as exc:
                raise AgentEventLogError("event_log_path_unsafe") from exc
        try:
            if created:
                if os.write(descriptor, b"\0") != 1:
                    raise OSError("short lock identity write")
                os.fsync(descriptor)
            info = descriptor_file_stat(descriptor)
            if (
                is_link_or_reparse(info)
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size != 1
            ):
                raise AgentEventLogError("event_log_path_unsafe")
            identity = file_identity(info)
            if self._safe_file_identity(self.lock_path, required=True) != identity:
                raise AgentEventLogError("event_log_path_substituted")
            if self._read_lock_identity(descriptor) != b"\0":
                raise AgentEventLogError("event_log_path_unsafe")
            self._lock_identity = identity
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _read_lock_identity(descriptor: int) -> bytes:
        try:
            return os.pread(descriptor, 2, 0)
        except AttributeError:
            position = os.lseek(descriptor, 0, os.SEEK_CUR)
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                return os.read(descriptor, 2)
            finally:
                os.lseek(descriptor, position, os.SEEK_SET)

    def _assert_lock_boundary(self) -> None:
        try:
            info = descriptor_file_stat(self._lock_descriptor)
            named_identity = self._safe_file_identity(self.lock_path, required=True)
            payload = self._read_lock_identity(self._lock_descriptor)
        except (OSError, ValueError) as exc:
            raise AgentEventLogError("event_log_path_substituted") from exc
        if (
            is_link_or_reparse(info)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size != 1
            or file_identity(info) != self._lock_identity
            or named_identity != self._lock_identity
            or payload != b"\0"
        ):
            raise AgentEventLogError("event_log_path_substituted")

    def _close_lock(self, *, unlock: bool = True) -> None:
        descriptor = getattr(self, "_lock_descriptor", None)
        if descriptor is None:
            return
        self._lock_descriptor = None
        if unlock:
            _release_os_lock(descriptor)
        try:
            os.close(descriptor)
        except OSError:
            pass

    @staticmethod
    def _safe_file_identity(path: Path, *, required: bool) -> tuple[int, int] | None:
        try:
            info = path_file_stat(path)
        except FileNotFoundError:
            if required:
                raise AgentEventLogError("event_log_path_substituted") from None
            return None
        except (OSError, ValueError) as exc:
            raise AgentEventLogError("event_log_path_unsafe") from exc
        if is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AgentEventLogError("event_log_path_unsafe")
        return file_identity(info)

    @staticmethod
    def _retained_digest(descriptor: int, *, expected_size: int) -> str:
        if not 0 <= expected_size <= MAX_AGENT_EVENT_LOG_RECOVERY_SNAPSHOT_BYTES:
            raise AgentEventLogError("event_log_recovery_snapshot_too_large")
        digest = hashlib.sha256()
        total = 0
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            while True:
                chunk = os.read(descriptor, _RECOVERY_READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > expected_size:
                    raise AgentEventLogError("event_log_path_substituted")
                digest.update(chunk)
        except AgentEventLogError:
            raise
        except OSError as exc:
            raise AgentEventLogError("event_log_recovery_snapshot_failed") from exc
        if total != expected_size:
            raise AgentEventLogError("event_log_path_substituted")
        return digest.hexdigest()

    def _retain_recovery_file(
        self,
        path: Path,
        *,
        required: bool,
        expected_identity: tuple[int, int] | None = None,
        maximum_size: int = MAX_AGENT_EVENT_LOG_RECOVERY_SNAPSHOT_BYTES,
    ) -> _RetainedRecoveryFile | None:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOINHERIT", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            if required:
                raise AgentEventLogError("event_log_path_substituted") from None
            return None
        except OSError as exc:
            raise AgentEventLogError("event_log_path_unsafe") from exc
        try:
            info = descriptor_file_stat(descriptor)
            identity = file_identity(info)
            if (
                is_link_or_reparse(info)
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size < 0
                or info.st_size > maximum_size
                or self._safe_file_identity(path, required=True) != identity
                or (expected_identity is not None and identity != expected_identity)
            ):
                raise AgentEventLogError("event_log_path_substituted")
            digest = self._retained_digest(descriptor, expected_size=info.st_size)
            after = descriptor_file_stat(descriptor)
            if file_identity(after) != identity or after.st_size != info.st_size:
                raise AgentEventLogError("event_log_path_substituted")
            return _RetainedRecoveryFile(path, descriptor, identity, info.st_size, digest)
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

    def _verify_retained_recovery_files(
        self,
        retained: dict[str, _RetainedRecoveryFile | None],
    ) -> None:
        self._verify_retained_files(retained, database_path=self.database_path)

    def _verify_retained_files(
        self,
        retained: dict[str, _RetainedRecoveryFile | None],
        *,
        database_path: Path,
    ) -> None:
        for suffix, item in retained.items():
            path = Path(f"{database_path}{suffix}")
            if item is None:
                if self._safe_file_identity(path, required=False) is not None:
                    raise AgentEventLogError("event_log_path_substituted")
                continue
            try:
                info = descriptor_file_stat(item.descriptor)
            except (OSError, ValueError) as exc:
                raise AgentEventLogError("event_log_path_substituted") from exc
            if (
                is_link_or_reparse(info)
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or file_identity(info) != item.identity
                or info.st_size != item.size
                or self._safe_file_identity(path, required=True) != item.identity
                or self._retained_digest(item.descriptor, expected_size=item.size) != item.digest
            ):
                raise AgentEventLogError("event_log_path_substituted")

    @staticmethod
    def _close_retained_files(
        retained: dict[str, _RetainedRecoveryFile | None],
    ) -> None:
        for item in retained.values():
            if item is not None:
                try:
                    os.close(item.descriptor)
                except OSError:
                    pass

    def _retained_payload(self, retained: _RetainedRecoveryFile) -> bytes:
        payload = bytearray()
        try:
            before = descriptor_file_stat(retained.descriptor)
            os.lseek(retained.descriptor, 0, os.SEEK_SET)
            while len(payload) < retained.size:
                chunk = os.read(
                    retained.descriptor,
                    min(_RECOVERY_READ_CHUNK_BYTES, retained.size - len(payload)),
                )
                if not chunk:
                    break
                payload.extend(chunk)
            after = descriptor_file_stat(retained.descriptor)
        except (OSError, ValueError) as exc:
            raise AgentEventLogError("event_log_recovery_snapshot_failed") from exc
        if (
            len(payload) != retained.size
            or is_link_or_reparse(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or file_identity(before) != retained.identity
            or before.st_size != retained.size
            or is_link_or_reparse(after)
            or not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or file_identity(after) != retained.identity
            or after.st_size != retained.size
            or hashlib.sha256(payload).hexdigest() != retained.digest
        ):
            raise AgentEventLogError("event_log_path_substituted")
        return bytes(payload)

    def _offline_recovery_image_from_retained(
        self,
        retained: dict[str, _RetainedRecoveryFile | None],
    ) -> bytes:
        retained_main = retained.get("")
        if retained_main is None:
            raise AgentEventLogCorrupt("event_log_storage_corrupt")
        main = self._retained_payload(retained_main)
        retained_wal = retained.get("-wal")
        wal = b"" if retained_wal is None else self._retained_payload(retained_wal)
        return _materialize_offline_recovery_image(main, wal)

    def _verify_offline_recovery_image(
        self,
        retained: dict[str, _RetainedRecoveryFile | None],
    ) -> None:
        expected_digest = self._recovery_attested_image_digest
        if expected_digest is None:
            raise AgentEventLogError("event_log_path_substituted")
        logical_image = self._offline_recovery_image_from_retained(retained)
        if hashlib.sha256(logical_image).digest() != expected_digest:
            raise AgentEventLogError("event_log_path_substituted")

    def _open_offline_recovery_snapshot(
        self,
        expected_database_identity: tuple[int, int],
    ) -> sqlite3.Connection:
        retained: dict[str, _RetainedRecoveryFile | None] = {}
        connection: sqlite3.Connection | None = None
        succeeded = False
        try:
            remaining = MAX_AGENT_EVENT_LOG_RECOVERY_SNAPSHOT_BYTES
            retained[""] = self._retain_recovery_file(
                self.database_path,
                required=True,
                expected_identity=expected_database_identity,
                maximum_size=remaining,
            )
            retained_main = retained[""]
            assert retained_main is not None
            remaining -= retained_main.size
            for suffix in ("-wal", "-journal", "-shm"):
                retained[suffix] = self._retain_recovery_file(
                    Path(f"{self.database_path}{suffix}"),
                    required=False,
                    maximum_size=remaining,
                )
                item = retained[suffix]
                if item is not None:
                    remaining -= item.size
            if retained["-journal"] is not None:
                raise AgentEventLogError("event_log_recovery_rollback_journal_unsupported")
            self._verify_retained_recovery_files(retained)
            logical_image = self._offline_recovery_image_from_retained(retained)
            logical_digest = hashlib.sha256(logical_image).digest()
            memory_payload = self._memory_transport_image(logical_image)
            memory_digest = hashlib.sha256(memory_payload).digest()
            connection = sqlite3.connect(":memory:", timeout=5.0)
            connection.deserialize(memory_payload)
            connection.row_factory = sqlite3.Row
            self._configure_recovery_memory_connection(connection)
            if self._database_image_digest(connection) != memory_digest:
                raise AgentEventLogError("event_log_path_substituted")
            self._verify_retained_recovery_files(retained)
            if (
                hashlib.sha256(self._offline_recovery_image_from_retained(retained)).digest()
                != logical_digest
            ):
                raise AgentEventLogError("event_log_path_substituted")
            self._recovery_retained_files = retained
            self._recovery_attested_image_digest = logical_digest
            self._recovery_memory_image_digest = memory_digest
            self._recovery_memory_active = True
            succeeded = True
            return connection
        except AgentEventLogError:
            raise
        except (MemoryError, sqlite3.Error) as exc:
            raise AgentEventLogCorrupt("event_log_storage_corrupt") from exc
        finally:
            if not succeeded:
                if connection is not None:
                    try:
                        connection.close()
                    except BaseException:
                        pass
                self._close_retained_files(retained)

    def _discard_recovery_snapshot(self) -> None:
        retained = self._recovery_retained_files
        self._recovery_retained_files = {}
        self._close_retained_files(retained)
        self._recovery_attested_image_digest = None
        self._recovery_memory_image_digest = None
        self._recovery_memory_active = False

    @staticmethod
    def _memory_transport_image(payload: bytes) -> bytes:
        """Adapt only SQLite's journaling header bytes for in-memory deserialize.

        The offline image remains authoritative and keeps its exact WAL-mode
        header.  An in-memory database has no pathname from which SQLite could
        open a WAL, so deserialize requires the read/write versions to identify
        a self-contained rollback-format image.  No page content is otherwise
        normalized.
        """

        if (
            type(payload) is not bytes
            or len(payload) < 100
            or payload[:16] != b"SQLite format 3\x00"
            or payload[18] not in (1, 2)
            or payload[19] not in (1, 2)
        ):
            raise AgentEventLogCorrupt("event_log_storage_corrupt")
        transported = bytearray(payload)
        transported[18] = 1
        transported[19] = 1
        return bytes(transported)

    def _activate_recovery_mutation(self) -> None:
        self._require_recovery_session()
        if self._recovery_original_active:
            return
        self._assert_boundary()
        self._fault("before_recovery_original_open")
        self._assert_boundary()
        retained_main = self._recovery_retained_files.get("")
        attested_digest = self._recovery_attested_image_digest
        if retained_main is None or attested_digest is None:
            raise AgentEventLogError("event_log_path_substituted")
        snapshot = self.connection
        assert snapshot is not None
        original: sqlite3.Connection | None = None
        try:
            original = sqlite3.connect(
                f"{self.database_path.as_uri()}?mode=rw",
                timeout=5.0,
                uri=True,
            )
            original.row_factory = sqlite3.Row
            if (
                self._safe_file_identity(self.database_path, required=True)
                != retained_main.identity
            ):
                raise AgentEventLogError("event_log_path_substituted")
            self.connection = original
            if self._database_image_digest(original) != attested_digest:
                raise AgentEventLogError("event_log_path_substituted")
            self._verify_existing_store_readonly()
            self._configure()
            self._migrate_or_verify(new_database=False, verify_state=True)
            if self._database_image_digest(original) != attested_digest:
                raise AgentEventLogError("event_log_path_substituted")
            database_identity = self._safe_file_identity(self.database_path, required=True)
            sidecar_identities = self._current_sidecar_identities()
            if self._database_image_digest(original) != attested_digest:
                raise AgentEventLogError("event_log_path_substituted")
        except BaseException:
            self.connection = snapshot
            if original is not None:
                try:
                    original.close()
                except BaseException:
                    pass
            raise
        try:
            snapshot.close()
        except BaseException:
            self.connection = snapshot
            try:
                original.close()
            except BaseException:
                pass
            raise
        assert database_identity is not None
        self.connection = original
        self._database_identity = database_identity
        self._sidecar_identities = sidecar_identities
        self._recovery_original_active = True
        self._discard_recovery_snapshot()
        self._assert_boundary()

    @staticmethod
    def _database_image_bytes(connection: sqlite3.Connection) -> bytes:
        try:
            payload = connection.serialize()
        except (MemoryError, sqlite3.Error) as exc:
            raise AgentEventLogCorrupt("event_log_storage_corrupt") from exc
        if (
            type(payload) is not bytes
            or not payload
            or len(payload) > MAX_AGENT_EVENT_LOG_RECOVERY_SNAPSHOT_BYTES
        ):
            raise AgentEventLogCorrupt("event_log_storage_corrupt")
        return payload

    @staticmethod
    def _database_image_digest(connection: sqlite3.Connection) -> bytes:
        return hashlib.sha256(AgentEventLog._database_image_bytes(connection)).digest()

    def _current_sidecar_identities(self) -> dict[str, tuple[int, int] | None]:
        return {
            suffix: self._safe_file_identity(Path(f"{self.database_path}{suffix}"), required=False)
            for suffix in ("-wal", "-shm", "-journal")
        }

    def _validate_sidecars(self) -> None:
        self._current_sidecar_identities()

    def _assert_boundary(self) -> None:
        self._assert_owner_process()
        if self._directory_identity(self.root) != self._root_identity:
            raise AgentEventLogError("event_log_path_substituted")
        self._assert_lock_boundary()
        if self._recovery_mode and not self._recovery_original_active:
            self._verify_retained_recovery_files(self._recovery_retained_files)
            self._verify_offline_recovery_image(self._recovery_retained_files)
            expected_digest = self._recovery_memory_image_digest
            if (
                not self._recovery_memory_active
                or expected_digest is None
                or self.connection is None
                or self._database_image_digest(self.connection) != expected_digest
            ):
                raise AgentEventLogError("event_log_path_substituted")
            return
        if self._safe_file_identity(self.database_path, required=True) != self._database_identity:
            raise AgentEventLogError("event_log_path_substituted")
        if self._current_sidecar_identities() != self._sidecar_identities:
            raise AgentEventLogError("event_log_path_substituted")

    def _configure(self) -> None:
        self._configure_wal_connection(self.connection)

    @staticmethod
    def _configure_wal_connection(connection: sqlite3.Connection) -> None:
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            connection.execute("PRAGMA synchronous = FULL")
        except sqlite3.Error as exc:
            raise AgentEventLogError("event_log_configuration_failed") from exc
        if str(mode).casefold() != "wal":
            raise AgentEventLogError("event_log_configuration_failed")

    @staticmethod
    def _configure_recovery_memory_connection(connection: sqlite3.Connection) -> None:
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA synchronous = FULL")
            mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
            connection.execute("PRAGMA query_only = ON")
        except sqlite3.Error as exc:
            raise AgentEventLogError("event_log_configuration_failed") from exc
        if str(mode).casefold() != "memory":
            raise AgentEventLogError("event_log_configuration_failed")

    def _migrate_or_verify(self, *, new_database: bool, verify_state: bool) -> None:
        if self._recovery_mode:
            self._verify_version_locked(allow_legacy=True)
            self._verify_physical_integrity_locked()
            self._verify_foreign_keys_locked()
            if verify_state:
                self._verify_all_executions_locked(
                    schema_version=self._read_schema_version_locked()
                )
            return
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            if new_database:
                for statement in _SCHEMA_TABLE_SQL.values():
                    self.connection.execute(statement)
                self.connection.executemany(
                    "INSERT INTO schema_meta(key, value) VALUES (?, ?)",
                    (
                        ("schema_version", str(AGENT_EVENT_LOG_SCHEMA_VERSION)),
                        ("lock_device", str(self._lock_identity[0])),
                        ("lock_inode", str(self._lock_identity[1])),
                    ),
                )
            else:
                version = self._read_schema_version_locked()
                if version == 1:
                    self._verify_schema_locked(schema_version=1)
                    self._verify_lock_binding_locked()
                    self._verify_foreign_keys_locked()
                    self._verify_all_executions_locked(schema_version=1)
                    self.connection.execute(_SCHEMA_TABLE_SQL["memory_projections"])
                    changed = self.connection.execute(
                        "UPDATE schema_meta SET value = '2' WHERE key = 'schema_version' "
                        "AND value = '1'"
                    ).rowcount
                    if changed != 1:
                        raise AgentEventLogCorrupt("event_log_version_unsupported")
                    self._fault("before_schema_v2_migration_commit")
                elif version != AGENT_EVENT_LOG_SCHEMA_VERSION:
                    raise AgentEventLogCorrupt("event_log_version_unsupported")
            self._verify_version_locked()
            self._verify_physical_integrity_locked()
            self._verify_foreign_keys_locked()
            if verify_state:
                self._verify_all_executions_locked(schema_version=AGENT_EVENT_LOG_SCHEMA_VERSION)
            self.connection.commit()
        except Exception:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise

    def _read_schema_version_locked(self) -> int:
        try:
            row = self.connection.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.Error as exc:
            raise AgentEventLogCorrupt("event_log_schema_corrupt") from exc
        if row is None or type(row["value"]) is not str or row["value"] not in {"1", "2"}:
            raise AgentEventLogCorrupt("event_log_version_unsupported")
        return int(row["value"])

    def _verify_version_locked(self, *, allow_legacy: bool = False) -> int:
        version = self._read_schema_version_locked()
        if version != AGENT_EVENT_LOG_SCHEMA_VERSION and not (allow_legacy and version == 1):
            raise AgentEventLogCorrupt("event_log_version_unsupported")
        self._verify_schema_locked(schema_version=version)
        self._verify_lock_binding_locked()
        return version

    def _verify_lock_binding_locked(self) -> None:
        try:
            rows = self.connection.execute(
                """
                SELECT key, value FROM schema_meta
                WHERE key IN ('lock_device', 'lock_inode') ORDER BY key
                """
            ).fetchall()
        except sqlite3.Error as exc:
            raise AgentEventLogCorrupt("event_log_schema_corrupt") from exc
        expected = [
            ("lock_device", str(self._lock_identity[0])),
            ("lock_inode", str(self._lock_identity[1])),
        ]
        if [(row["key"], row["value"]) for row in rows] != expected:
            raise AgentEventLogError("event_log_path_substituted")

    def _verify_foreign_keys_locked(self) -> None:
        try:
            violations = self.connection.execute("PRAGMA foreign_key_check").fetchmany(1)
        except sqlite3.Error as exc:
            raise AgentEventLogCorrupt("event_log_storage_corrupt") from exc
        if violations:
            raise AgentEventLogCorrupt("event_log_storage_corrupt")

    def _verify_physical_integrity_locked(self) -> None:
        try:
            results = self.connection.execute("PRAGMA integrity_check(1)").fetchmany(2)
        except sqlite3.Error as exc:
            raise AgentEventLogCorrupt("event_log_storage_corrupt") from exc
        if (
            len(results) != 1
            or len(results[0]) != 1
            or type(results[0][0]) is not str
            or results[0][0] != "ok"
        ):
            raise AgentEventLogCorrupt("event_log_storage_corrupt")

    def _verify_existing_store_readonly(self) -> None:
        version = self._verify_version_locked(allow_legacy=True)
        self._verify_physical_integrity_locked()
        self._verify_foreign_keys_locked()
        self._verify_all_executions_locked(schema_version=version)

    def _verify_all_executions_locked(self, *, schema_version: int) -> None:
        try:
            rows = self.connection.execute(
                "SELECT * FROM executions ORDER BY execution_id"
            ).fetchall()
        except sqlite3.Error as exc:
            raise AgentEventLogCorrupt("event_log_storage_corrupt") from exc
        for row in rows:
            self._replay_locked(row, schema_version=schema_version)

    def _verify_schema_locked(self, *, schema_version: int) -> None:
        try:
            objects = self.connection.execute(
                """
                SELECT type, name, tbl_name, rootpage, sql FROM sqlite_schema
                ORDER BY type, name, tbl_name
                """
            ).fetchall()
            manifest_rows: list[tuple[str, str, str, str]] = []
            internal_rows: list[tuple[str, str, str]] = []
            rootpages: set[int] = set()
            for row in objects:
                object_type = row["type"]
                name = row["name"]
                table_name = row["tbl_name"]
                rootpage = row["rootpage"]
                sql = row["sql"]
                if (
                    any(type(value) is not str for value in (object_type, name, table_name))
                    or type(rootpage) is not int
                    or rootpage <= 0
                    or rootpage in rootpages
                    or (sql is not None and type(sql) is not str)
                ):
                    raise AgentEventLogCorrupt("event_log_schema_corrupt")
                rootpages.add(rootpage)
                if sql is None:
                    internal_rows.append((object_type, name, table_name))
                else:
                    manifest_rows.append((object_type, name, table_name, sql))
            manifest = tuple(manifest_rows)
            if manifest != _EXPECTED_SCHEMA_MANIFESTS[schema_version]:
                raise AgentEventLogCorrupt("event_log_schema_corrupt")
            if tuple(internal_rows) != _EXPECTED_INTERNAL_SCHEMA_OBJECTS[schema_version]:
                raise AgentEventLogCorrupt("event_log_schema_corrupt")
            expected_tables = _SCHEMA_TABLE_SQL_V1 if schema_version == 1 else _SCHEMA_TABLE_SQL
            for table in expected_tables:
                expected = _SCHEMA_COLUMNS[table]
                table_info = self.connection.execute(f"PRAGMA table_info({table})").fetchall()
                columns = tuple(row["name"] for row in table_info)
                if columns != expected:
                    raise AgentEventLogCorrupt("event_log_schema_corrupt")
                shapes = tuple(
                    (row["name"], row["type"], row["notnull"], row["pk"]) for row in table_info
                )
                if shapes != _SCHEMA_COLUMN_SHAPES[table]:
                    raise AgentEventLogCorrupt("event_log_schema_corrupt")
                indexes: list[tuple[str, tuple[str, ...]]] = []
                for index in self.connection.execute(f"PRAGMA index_list({table})"):
                    if index["unique"] != 1 or index["partial"] != 0:
                        raise AgentEventLogCorrupt("event_log_schema_corrupt")
                    index_columns = tuple(
                        item["name"]
                        for item in self.connection.execute(
                            "SELECT name FROM pragma_index_info(?) ORDER BY seqno",
                            (index["name"],),
                        )
                    )
                    indexes.append((str(index["origin"]), index_columns))
                if sorted(indexes) != sorted(_SCHEMA_UNIQUE_INDEXES[table]):
                    raise AgentEventLogCorrupt("event_log_schema_corrupt")
            expected_foreign_keys = {
                "schema_meta": (),
                "executions": (),
                "events": (
                    ("executions", "execution_id", "execution_id", "NO ACTION", "NO ACTION"),
                ),
                "receipts": (
                    ("executions", "execution_id", "execution_id", "NO ACTION", "NO ACTION"),
                ),
                "memory_projections": (
                    ("executions", "execution_id", "execution_id", "NO ACTION", "NO ACTION"),
                ),
            }
            for table in expected_tables:
                expected = expected_foreign_keys[table]
                foreign_keys = tuple(
                    (
                        row["table"],
                        row["from"],
                        row["to"],
                        row["on_update"],
                        row["on_delete"],
                    )
                    for row in self.connection.execute(f"PRAGMA foreign_key_list({table})")
                )
                if foreign_keys != expected:
                    raise AgentEventLogCorrupt("event_log_schema_corrupt")
            meta = self.connection.execute("SELECT key FROM schema_meta ORDER BY key").fetchall()
            if [row["key"] for row in meta] != [
                "lock_device",
                "lock_inode",
                "schema_version",
            ]:
                raise AgentEventLogCorrupt("event_log_schema_corrupt")
        except AgentEventLogError:
            raise
        except sqlite3.Error as exc:
            raise AgentEventLogCorrupt("event_log_schema_corrupt") from exc

    def _assert_configuration(self) -> None:
        try:
            foreign_keys = self.connection.execute("PRAGMA foreign_keys").fetchone()[0]
            synchronous = self.connection.execute("PRAGMA synchronous").fetchone()[0]
            journal_mode = self.connection.execute("PRAGMA journal_mode").fetchone()[0]
            query_only = self.connection.execute("PRAGMA query_only").fetchone()[0]
        except sqlite3.Error as exc:
            raise AgentEventLogError("event_log_configuration_failed") from exc
        expected_query_only = 1 if self._recovery_mode and not self._recovery_original_active else 0
        expected_journal_mode = "memory" if self._recovery_memory_active else "wal"
        if (
            foreign_keys != 1
            or synchronous != 2
            or str(journal_mode).casefold() != expected_journal_mode
            or query_only != expected_query_only
        ):
            raise AgentEventLogError("event_log_configuration_failed")

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self._assert_owner_process()
        self._assert_boundary()
        primary: BaseException | None = None
        self._assert_configuration()
        try:
            transaction = (
                "BEGIN"
                if self._recovery_mode and not self._recovery_original_active
                else "BEGIN IMMEDIATE"
            )
            self.connection.execute(transaction)
            self._verify_version_locked(allow_legacy=self._recovery_mode)
            yield
            self.connection.commit()
        except BaseException as exc:
            primary = exc
            if self.connection.in_transaction:
                try:
                    self.connection.rollback()
                except BaseException as rollback_error:
                    exc.add_note(f"AgentEventLog rollback failed: {rollback_error}")
            raise
        finally:
            if primary is None:
                self._assert_boundary()
            else:
                try:
                    self._assert_boundary()
                except BaseException as boundary_error:
                    primary.add_note(f"AgentEventLog boundary recheck failed: {boundary_error}")

    @staticmethod
    def _row_state_values(row: sqlite3.Row) -> dict[str, object]:
        return {
            "execution_id": row["execution_id"],
            "log_id": row["log_id"],
            "request_fingerprint": row["request_fingerprint"],
            "activation_hash": row["activation_hash"],
            "grant_hash": row["grant_hash"],
            "state": row["state"],
            "generation": row["generation"],
            "next_sequence": row["next_sequence"],
            "head_hash": row["head_hash"],
            "receipt_id": row["receipt_id"],
            "receipt_hash": row["receipt_hash"],
        }

    def _execution_row_locked(self, execution_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM executions WHERE execution_id = ?", (execution_id,)
        ).fetchone()
        if row is None:
            raise AgentEventLogConflict("event_log_execution_missing")
        return row

    @staticmethod
    def _verify_state_hash(row: sqlite3.Row) -> None:
        ids_valid = all(
            type(row[name]) is str and _ID_RE.fullmatch(row[name]) is not None
            for name in ("execution_id", "log_id")
        )
        hashes_valid = all(
            type(row[name]) is str and _SHA_RE.fullmatch(row[name]) is not None
            for name in (
                "activation_hash",
                "grant_hash",
                "state_hash",
            )
        )
        fingerprint_valid = row["request_fingerprint"] is None or (
            type(row["request_fingerprint"]) is str
            and _SHA_RE.fullmatch(row["request_fingerprint"]) is not None
        )
        counters_valid = all(
            type(row[name]) is int and 0 <= row[name] <= MAX_SAFE_INTEGER
            for name in ("generation", "next_sequence")
        )
        optional_hashes_valid = all(
            row[name] is None
            or (type(row[name]) is str and _SHA_RE.fullmatch(row[name]) is not None)
            for name in ("head_hash", "receipt_hash")
        )
        receipt_id_valid = row["receipt_id"] is None or (
            type(row["receipt_id"]) is str and _ID_RE.fullmatch(row["receipt_id"]) is not None
        )
        if (
            not ids_valid
            or not hashes_valid
            or not fingerprint_valid
            or not counters_valid
            or not optional_hashes_valid
            or not receipt_id_valid
            or row["state"] not in _STATES
            or row["next_sequence"] > MAX_AGENT_EVENT_LOG_EVENTS
            or row["state_hash"] != _state_hash(**AgentEventLog._row_state_values(row))
        ):
            raise AgentEventLogCorrupt("event_log_state_corrupt")

    def begin_execution(
        self,
        execution_id: str,
        log_id: str,
        activation: dict[str, object],
        grant: dict[str, object],
        *,
        request_fingerprint: str | None,
    ) -> bool:
        self._assert_owner_process()
        self._require_ordinary_session()
        execution_id = _plain_id(execution_id)
        log_id = _plain_id(log_id)
        request_fingerprint = _plain_hash(request_fingerprint, allow_none=True)
        try:
            aggregate = validate_agent_harness_documents(activation, grant)
        except Exception as exc:
            raise AgentEventLogError("event_log_request_invalid") from exc
        if aggregate.activation["execution_id"] != execution_id:
            raise AgentEventLogError("event_log_request_invalid")
        _, activation_bytes = _validated_document_bytes(
            aggregate.activation, expected_format=AGENT_WORKER_ACTIVATION_FORMAT
        )
        _, grant_bytes = _validated_document_bytes(
            aggregate.grant, expected_format=AGENT_CAPABILITY_GRANT_FORMAT
        )
        if len(activation_bytes) + len(grant_bytes) > MAX_AGENT_EVENT_LOG_EXECUTION_BYTES:
            raise AgentEventLogError("event_log_execution_too_large")
        activation_hash = str(aggregate.activation["content_hash"])
        grant_hash = str(aggregate.grant["content_hash"])
        if execution_id in self._indeterminate_executions:
            raise AgentEventLogConflict("event_log_execution_conflict")
        try:
            with self._transaction():
                existing = self.connection.execute(
                    "SELECT * FROM executions WHERE execution_id = ?", (execution_id,)
                ).fetchone()
                if existing is not None:
                    self._verify_state_hash(existing)
                    exact = (
                        existing["log_id"] == log_id
                        and existing["request_fingerprint"] == request_fingerprint
                        and existing["activation_hash"] == activation_hash
                        and existing["grant_hash"] == grant_hash
                        and existing["activation_json"] == activation_bytes
                        and existing["grant_json"] == grant_bytes
                    )
                    if (
                        request_fingerprint is not None
                        and exact
                        and existing["state"] == "terminal"
                    ):
                        self._replay_locked(existing)
                        return False
                    raise AgentEventLogConflict("event_log_execution_conflict")
                values = {
                    "execution_id": execution_id,
                    "log_id": log_id,
                    "request_fingerprint": request_fingerprint,
                    "activation_hash": activation_hash,
                    "grant_hash": grant_hash,
                    "state": "open",
                    "generation": 0,
                    "next_sequence": 0,
                    "head_hash": None,
                    "receipt_id": None,
                    "receipt_hash": None,
                }
                try:
                    self.connection.execute(
                        """
                        INSERT INTO executions(
                            execution_id, log_id, request_fingerprint,
                            activation_hash, grant_hash, activation_json, grant_json,
                            state, generation, next_sequence, head_hash,
                            receipt_id, receipt_hash, state_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            execution_id,
                            log_id,
                            request_fingerprint,
                            activation_hash,
                            grant_hash,
                            sqlite3.Binary(activation_bytes),
                            sqlite3.Binary(grant_bytes),
                            "open",
                            0,
                            0,
                            None,
                            None,
                            None,
                            _state_hash(**values),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise AgentEventLogConflict("event_log_execution_conflict") from exc
                self._fault("before_begin_commit")
            self._fault("after_begin_commit")
            self._owned_executions.add(execution_id)
            return True
        except AgentEventLogError:
            raise
        except Exception as exc:
            return self._reconcile_begin(
                execution_id=execution_id,
                log_id=log_id,
                request_fingerprint=request_fingerprint,
                activation_bytes=activation_bytes,
                grant_bytes=grant_bytes,
                cause=exc,
            )

    def _reconcile_begin(
        self,
        *,
        execution_id: str,
        log_id: str,
        request_fingerprint: str | None,
        activation_bytes: bytes,
        grant_bytes: bytes,
        cause: Exception,
    ) -> bool:
        try:
            replay = self.replay_records(execution_id)
        except Exception:
            self._indeterminate_executions.add(execution_id)
            raise AgentEventLogIndeterminate("event_log_begin_indeterminate") from cause
        if request_fingerprint is None or (
            replay.log_id != log_id
            or replay.request_fingerprint != request_fingerprint
            or replay.activation_bytes != activation_bytes
            or replay.grant_bytes != grant_bytes
        ):
            self._indeterminate_executions.add(execution_id)
            raise AgentEventLogIndeterminate("event_log_begin_indeterminate") from cause
        if replay.state == "terminal":
            return False
        if replay.state == "open" and replay.generation == replay.next_sequence == 0:
            self._owned_executions.add(execution_id)
            return True
        self._indeterminate_executions.add(execution_id)
        raise AgentEventLogIndeterminate("event_log_begin_indeterminate") from cause

    def _event_documents_locked(
        self, execution_id: str
    ) -> tuple[list[dict[str, object]], list[bytes]]:
        rows = self.connection.execute(
            """
            SELECT sequence, event_id, event_hash, event_json
            FROM events WHERE execution_id = ? ORDER BY sequence
            """,
            (execution_id,),
        ).fetchall()
        documents: list[dict[str, object]] = []
        encoded: list[bytes] = []
        for index, row in enumerate(rows):
            if row["sequence"] != index:
                raise AgentEventLogCorrupt("event_log_sequence_corrupt")
            document, payload = _decode_document(
                row["event_json"], expected_format=AGENT_EVENT_FORMAT
            )
            if (
                row["event_id"] != document["event_id"]
                or row["event_hash"] != document["content_hash"]
            ):
                raise AgentEventLogCorrupt("event_log_projection_corrupt")
            documents.append(document)
            encoded.append(payload)
        return documents, encoded

    def _current_total_bytes_locked(self, row: sqlite3.Row) -> int:
        event_total = self.connection.execute(
            "SELECT COALESCE(SUM(length(event_json)), 0) FROM events WHERE execution_id = ?",
            (row["execution_id"],),
        ).fetchone()[0]
        receipt_total = self.connection.execute(
            "SELECT COALESCE(SUM(length(receipt_json)), 0) FROM receipts WHERE execution_id = ?",
            (row["execution_id"],),
        ).fetchone()[0]
        projection_total = self.connection.execute(
            "SELECT COALESCE(SUM(length(projection_json)), 0) FROM memory_projections "
            "WHERE execution_id = ?",
            (row["execution_id"],),
        ).fetchone()[0]
        return (
            len(row["activation_json"])
            + len(row["grant_json"])
            + event_total
            + receipt_total
            + projection_total
        )

    def append_event(
        self,
        execution_id: str,
        event: dict[str, object],
        *,
        expected_sequence: int,
        expected_previous_hash: str | None,
        expected_generation: int,
    ) -> None:
        self._assert_owner_process()
        self._require_ordinary_session()
        execution_id = _plain_id(execution_id)
        expected_sequence = _plain_nonnegative(expected_sequence)
        expected_generation = _plain_nonnegative(expected_generation)
        expected_previous_hash = _plain_hash(expected_previous_hash, allow_none=True)
        document, event_bytes = _validated_document_bytes(event, expected_format=AGENT_EVENT_FORMAT)
        if document["event_type"] in {
            "execution.receipt_recorded",
            "memory.projected",
        }:
            raise AgentEventLogConflict("event_log_lifecycle_conflict")
        if (
            execution_id not in self._owned_executions
            or execution_id in self._indeterminate_executions
        ):
            raise AgentEventLogConflict("event_log_writer_not_owned")
        try:
            with self._transaction():
                self._append_event_locked(
                    execution_id=execution_id,
                    document=document,
                    event_bytes=event_bytes,
                    expected_sequence=expected_sequence,
                    expected_previous_hash=expected_previous_hash,
                    expected_generation=expected_generation,
                )
                self._fault("before_append_commit")
            self._fault("after_append_commit")
        except AgentEventLogError:
            raise
        except Exception as exc:
            self._reconcile_append(
                execution_id=execution_id,
                event_bytes=event_bytes,
                event_hash=str(document["content_hash"]),
                expected_sequence=expected_sequence,
                expected_previous_hash=expected_previous_hash,
                expected_generation=expected_generation,
                cause=exc,
            )

    def _append_event_locked(
        self,
        *,
        execution_id: str,
        document: dict[str, object],
        event_bytes: bytes,
        expected_sequence: int,
        expected_previous_hash: str | None,
        expected_generation: int,
    ) -> None:
        row = self._execution_row_locked(execution_id)
        self._verify_state_hash(row)
        if (
            row["state"] != "open"
            or row["next_sequence"] != expected_sequence
            or row["head_hash"] != expected_previous_hash
            or row["generation"] != expected_generation
            or document["execution_id"] != execution_id
            or document["log_id"] != row["log_id"]
            or document["sequence"] != expected_sequence
            or document["previous_event_hash"] != expected_previous_hash
        ):
            raise AgentEventLogConflict("event_log_append_conflict")
        events, _ = self._event_documents_locked(execution_id)
        try:
            _lifecycle_fold(events, None)
        except AgentEventLogError as exc:
            raise AgentEventLogCorrupt("event_log_lifecycle_invalid") from exc
        events.append(document)
        activation, _ = _decode_document(
            row["activation_json"], expected_format=AGENT_WORKER_ACTIVATION_FORMAT
        )
        grant, _ = _decode_document(
            row["grant_json"], expected_format=AGENT_CAPABILITY_GRANT_FORMAT
        )
        try:
            validate_agent_harness_documents(activation, grant, events)
            _lifecycle_fold(events, None)
        except AgentEventLogError as exc:
            raise AgentEventLogConflict("event_log_lifecycle_conflict") from exc
        except Exception as exc:
            raise AgentEventLogConflict("event_log_lifecycle_conflict") from exc
        if len(events) > MAX_AGENT_EVENT_LOG_EVENTS - 1:
            raise AgentEventLogConflict("event_log_event_bound_exceeded")
        if (
            self._current_total_bytes_locked(row) + len(event_bytes)
            > MAX_AGENT_EVENT_LOG_EXECUTION_BYTES
        ):
            raise AgentEventLogConflict("event_log_execution_too_large")
        new_generation = expected_generation + 1
        new_sequence = expected_sequence + 1
        new_head = str(document["content_hash"])
        values = self._row_state_values(row)
        values.update(
            generation=new_generation,
            next_sequence=new_sequence,
            head_hash=new_head,
        )
        try:
            self.connection.execute(
                """
                INSERT INTO events(execution_id, sequence, event_id, event_hash, event_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    execution_id,
                    expected_sequence,
                    document["event_id"],
                    document["content_hash"],
                    sqlite3.Binary(event_bytes),
                ),
            )
            changed = self.connection.execute(
                """
                UPDATE executions
                SET generation = ?, next_sequence = ?, head_hash = ?, state_hash = ?
                WHERE execution_id = ? AND state = 'open' AND generation = ?
                  AND next_sequence = ? AND head_hash IS ?
                """,
                (
                    new_generation,
                    new_sequence,
                    new_head,
                    _state_hash(**values),
                    execution_id,
                    expected_generation,
                    expected_sequence,
                    expected_previous_hash,
                ),
            ).rowcount
        except sqlite3.IntegrityError as exc:
            raise AgentEventLogConflict("event_log_append_conflict") from exc
        if changed != 1:
            raise AgentEventLogConflict("event_log_append_conflict")

    def _reconcile_append(
        self,
        *,
        execution_id: str,
        event_bytes: bytes,
        event_hash: str,
        expected_sequence: int,
        expected_previous_hash: str | None,
        expected_generation: int,
        cause: Exception,
    ) -> None:
        try:
            replay = self.replay_records(execution_id)
            committed = (
                replay.state == "open"
                and replay.generation == expected_generation + 1
                and replay.next_sequence == expected_sequence + 1
                and len(replay.event_bytes) == expected_sequence + 1
                and replay.event_bytes[expected_sequence] == event_bytes
                and replay.head_hash == event_hash
                and (expected_sequence > 0 or expected_previous_hash is None)
            )
        except Exception:
            committed = False
        if not committed:
            self._owned_executions.discard(execution_id)
            self._indeterminate_executions.add(execution_id)
            raise AgentEventLogIndeterminate("event_log_append_indeterminate") from cause

    def finalize(
        self,
        execution_id: str,
        receipt: dict[str, object],
        event: dict[str, object],
        *,
        expected_sequence: int,
        expected_previous_hash: str | None,
        expected_generation: int,
    ) -> None:
        self._assert_owner_process()
        self._require_ordinary_session()
        execution_id = _plain_id(execution_id)
        expected_sequence = _plain_nonnegative(expected_sequence)
        expected_generation = _plain_nonnegative(expected_generation)
        expected_previous_hash = _plain_hash(expected_previous_hash, allow_none=True)
        _, receipt_bytes = _validated_document_bytes(
            receipt, expected_format=AGENT_EXECUTION_RECEIPT_FORMAT
        )
        _, event_bytes = _validated_document_bytes(event, expected_format=AGENT_EVENT_FORMAT)
        try:
            committed_now = self._finalize_once(
                execution_id,
                receipt,
                event,
                expected_sequence=expected_sequence,
                expected_previous_hash=expected_previous_hash,
                expected_generation=expected_generation,
            )
            if committed_now:
                self._fault("after_finalize_commit")
            self._owned_executions.discard(execution_id)
        except AgentEventLogError:
            raise
        except Exception as exc:
            self._reconcile_finalize(
                execution_id=execution_id,
                receipt_bytes=receipt_bytes,
                event_bytes=event_bytes,
                expected_sequence=expected_sequence,
                expected_previous_hash=expected_previous_hash,
                expected_generation=expected_generation,
                cause=exc,
            )

    def _reconcile_finalize(
        self,
        *,
        execution_id: str,
        receipt_bytes: bytes,
        event_bytes: bytes,
        expected_sequence: int,
        expected_previous_hash: str | None,
        expected_generation: int,
        cause: Exception,
    ) -> None:
        try:
            replay = self.replay_records(execution_id)
            committed = (
                replay.state == "terminal"
                and replay.receipt_bytes == receipt_bytes
                and len(replay.event_bytes) == expected_sequence + 1
                and replay.event_bytes[expected_sequence] == event_bytes
                and replay.generation == expected_generation + 1
                and (expected_sequence > 0 or expected_previous_hash is None)
            )
        except Exception:
            committed = False
        if not committed:
            self._owned_executions.discard(execution_id)
            self._indeterminate_executions.add(execution_id)
            raise AgentEventLogIndeterminate("event_log_finalize_indeterminate") from cause
        self._owned_executions.discard(execution_id)

    def _finalize_once(
        self,
        execution_id: str,
        receipt: dict[str, object],
        event: dict[str, object],
        *,
        expected_sequence: int,
        expected_previous_hash: str | None,
        expected_generation: int,
    ) -> bool:
        execution_id = _plain_id(execution_id)
        expected_sequence = _plain_nonnegative(expected_sequence)
        expected_generation = _plain_nonnegative(expected_generation)
        expected_previous_hash = _plain_hash(expected_previous_hash, allow_none=True)
        receipt_document, receipt_bytes = _validated_document_bytes(
            receipt, expected_format=AGENT_EXECUTION_RECEIPT_FORMAT
        )
        event_document, event_bytes = _validated_document_bytes(
            event, expected_format=AGENT_EVENT_FORMAT
        )
        if event_document["event_type"] != "execution.receipt_recorded":
            raise AgentEventLogConflict("event_log_lifecycle_conflict")
        with self._transaction():
            row = self._execution_row_locked(execution_id)
            self._verify_state_hash(row)
            if row["state"] == "terminal":
                existing = self._replay_locked(row)
                exact_terminal = (
                    row["next_sequence"] == expected_sequence + 1
                    and row["generation"] == expected_generation + 1
                    and len(existing.event_bytes) == expected_sequence + 1
                    and existing.projection_bytes is None
                )
                exact_projected_extension = (
                    row["next_sequence"] == expected_sequence + 2
                    and row["generation"] == expected_generation + 2
                    and len(existing.event_bytes) == expected_sequence + 2
                    and existing.projection_bytes is not None
                )
                if (
                    (exact_terminal or exact_projected_extension)
                    and event_document["previous_event_hash"] == expected_previous_hash
                    and existing.receipt_bytes == receipt_bytes
                    and existing.event_bytes[expected_sequence] == event_bytes
                ):
                    return False
                raise AgentEventLogConflict("event_log_finalize_conflict")
            if (
                row["state"] != "open"
                or row["next_sequence"] != expected_sequence
                or row["head_hash"] != expected_previous_hash
                or row["generation"] != expected_generation
                or event_document["execution_id"] != execution_id
                or event_document["log_id"] != row["log_id"]
                or event_document["sequence"] != expected_sequence
                or event_document["previous_event_hash"] != expected_previous_hash
                or receipt_document["execution_id"] != execution_id
            ):
                raise AgentEventLogConflict("event_log_finalize_conflict")
            if (
                execution_id not in self._owned_executions
                or execution_id in self._indeterminate_executions
            ):
                raise AgentEventLogConflict("event_log_writer_not_owned")
            events, _ = self._event_documents_locked(execution_id)
            try:
                _lifecycle_fold(events, None)
            except AgentEventLogError as exc:
                raise AgentEventLogCorrupt("event_log_lifecycle_invalid") from exc
            events.append(event_document)
            activation, _ = _decode_document(
                row["activation_json"], expected_format=AGENT_WORKER_ACTIVATION_FORMAT
            )
            grant, _ = _decode_document(
                row["grant_json"], expected_format=AGENT_CAPABILITY_GRANT_FORMAT
            )
            try:
                validate_agent_harness_documents(activation, grant, events, receipt_document)
                _lifecycle_fold(events, receipt_document)
            except AgentEventLogError as exc:
                raise AgentEventLogConflict("event_log_lifecycle_conflict") from exc
            except Exception as exc:
                raise AgentEventLogConflict("event_log_lifecycle_conflict") from exc
            if len(events) > MAX_AGENT_EVENT_LOG_EVENTS:
                raise AgentEventLogConflict("event_log_event_bound_exceeded")
            if (
                self._current_total_bytes_locked(row) + len(event_bytes) + len(receipt_bytes)
                > MAX_AGENT_EVENT_LOG_EXECUTION_BYTES
            ):
                raise AgentEventLogConflict("event_log_execution_too_large")
            new_generation = expected_generation + 1
            new_sequence = expected_sequence + 1
            new_head = str(event_document["content_hash"])
            receipt_id = str(receipt_document["receipt_id"])
            receipt_hash = str(receipt_document["content_hash"])
            values = self._row_state_values(row)
            values.update(
                state="terminal",
                generation=new_generation,
                next_sequence=new_sequence,
                head_hash=new_head,
                receipt_id=receipt_id,
                receipt_hash=receipt_hash,
            )
            try:
                self.connection.execute(
                    """
                    INSERT INTO receipts(execution_id, receipt_id, receipt_hash, receipt_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        execution_id,
                        receipt_id,
                        receipt_hash,
                        sqlite3.Binary(receipt_bytes),
                    ),
                )
                self._fault("after_finalize_receipt_insert")
                self.connection.execute(
                    """
                    INSERT INTO events(execution_id, sequence, event_id, event_hash, event_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        execution_id,
                        expected_sequence,
                        event_document["event_id"],
                        new_head,
                        sqlite3.Binary(event_bytes),
                    ),
                )
                self._fault("after_finalize_event_insert")
                self._fault("before_finalize_state_update")
                changed = self.connection.execute(
                    """
                    UPDATE executions
                    SET state = 'terminal', generation = ?, next_sequence = ?, head_hash = ?,
                        receipt_id = ?, receipt_hash = ?, state_hash = ?
                    WHERE execution_id = ? AND state = 'open' AND generation = ?
                      AND next_sequence = ? AND head_hash IS ?
                    """,
                    (
                        new_generation,
                        new_sequence,
                        new_head,
                        receipt_id,
                        receipt_hash,
                        _state_hash(**values),
                        execution_id,
                        expected_generation,
                        expected_sequence,
                        expected_previous_hash,
                    ),
                ).rowcount
            except sqlite3.IntegrityError as exc:
                raise AgentEventLogConflict("event_log_finalize_conflict") from exc
            if changed != 1:
                raise AgentEventLogConflict("event_log_finalize_conflict")
            self._fault("before_finalize_commit")
        return True

    def replay_records(self, execution_id: str) -> ReplayedExecution:
        self._assert_owner_process()
        execution_id = _plain_id(execution_id)
        with self._transaction():
            row = self._execution_row_locked(execution_id)
            return self._replay_locked(row)

    def record_memory_projection(
        self,
        execution_id: str,
        projection: dict[str, object],
        event: dict[str, object],
        *,
        request_fingerprint: str,
        expected_sequence: int,
        expected_previous_hash: str,
        expected_generation: int,
    ) -> dict[str, object]:
        """Atomically append one approved projection after a succeeded receipt."""

        self._assert_owner_process()
        self._require_ordinary_session()
        execution_id = _plain_id(execution_id)
        request_fingerprint = _plain_hash(request_fingerprint)  # type: ignore[assignment]
        expected_sequence = _plain_nonnegative(expected_sequence)
        expected_generation = _plain_nonnegative(expected_generation)
        expected_previous_hash = _plain_hash(expected_previous_hash)  # type: ignore[assignment]
        projection_document, projection_bytes = _validated_document_bytes(
            projection,
            expected_format=AGENT_MEMORY_PROJECTION_FORMAT,
        )
        event_document, event_bytes = _validated_document_bytes(
            event,
            expected_format=AGENT_EVENT_FORMAT,
        )
        if (
            event_document["event_type"] != "memory.projected"
            or projection_document["execution_id"] != execution_id
            or event_document["event_id"] != _memory_projection_event_id(request_fingerprint)
        ):
            raise AgentEventLogConflict("event_log_lifecycle_conflict")
        if execution_id in self._indeterminate_executions:
            raise AgentEventLogConflict("event_log_projection_conflict")
        attempted_mutation = [False]
        try:
            result, committed_now = self._record_memory_projection_once(
                execution_id=execution_id,
                projection_document=projection_document,
                projection_bytes=projection_bytes,
                event_document=event_document,
                event_bytes=event_bytes,
                request_fingerprint=request_fingerprint,
                expected_sequence=expected_sequence,
                expected_previous_hash=expected_previous_hash,
                expected_generation=expected_generation,
                attempted_mutation=attempted_mutation,
            )
            if committed_now:
                self._fault("after_projection_commit")
            return result
        except Exception as exc:
            if not attempted_mutation[0]:
                raise
            return self._reconcile_memory_projection(
                execution_id=execution_id,
                projection_bytes=projection_bytes,
                event_bytes=event_bytes,
                request_fingerprint=request_fingerprint,
                expected_sequence=expected_sequence,
                expected_previous_hash=expected_previous_hash,
                expected_generation=expected_generation,
                cause=exc,
            )

    def _record_memory_projection_once(
        self,
        *,
        execution_id: str,
        projection_document: dict[str, object],
        projection_bytes: bytes,
        event_document: dict[str, object],
        event_bytes: bytes,
        request_fingerprint: str,
        expected_sequence: int,
        expected_previous_hash: str,
        expected_generation: int,
        attempted_mutation: list[bool],
    ) -> tuple[dict[str, object], bool]:
        with self._transaction():
            row = self._execution_row_locked(execution_id)
            self._verify_state_hash(row)
            existing_projection = self.connection.execute(
                "SELECT * FROM memory_projections WHERE execution_id = ?",
                (execution_id,),
            ).fetchone()
            if existing_projection is not None:
                replay = self._replay_locked(row)
                if (
                    replay.state == "terminal"
                    and replay.projection_bytes == projection_bytes
                    and existing_projection["request_fingerprint"] == request_fingerprint
                    and replay.next_sequence == expected_sequence + 1
                    and replay.generation == expected_generation + 1
                    and len(replay.event_bytes) == expected_sequence + 1
                    and replay.event_bytes[expected_sequence] == event_bytes
                    and event_document["previous_event_hash"] == expected_previous_hash
                ):
                    return projection_document, False
                raise AgentEventLogConflict("event_log_projection_conflict")
            if (
                row["state"] != "terminal"
                or row["next_sequence"] != expected_sequence
                or row["head_hash"] != expected_previous_hash
                or row["generation"] != expected_generation
                or event_document["execution_id"] != execution_id
                or event_document["log_id"] != row["log_id"]
                or event_document["sequence"] != expected_sequence
                or event_document["previous_event_hash"] != expected_previous_hash
                or event_document["subject"]
                != {
                    "format": AGENT_MEMORY_PROJECTION_FORMAT,
                    "format_version": 1,
                    "id": projection_document["projection_id"],
                    "content_hash": projection_document["content_hash"],
                }
            ):
                raise AgentEventLogConflict("event_log_projection_conflict")
            replay = self._replay_locked(row)
            if replay.receipt_bytes is None:
                raise AgentEventLogCorrupt("event_log_projection_corrupt")
            receipt_document, _ = _decode_document(
                replay.receipt_bytes,
                expected_format=AGENT_EXECUTION_RECEIPT_FORMAT,
            )
            if receipt_document["outcome"] != "succeeded":
                raise AgentEventLogConflict("event_log_lifecycle_conflict")
            activation, _ = _decode_document(
                row["activation_json"],
                expected_format=AGENT_WORKER_ACTIVATION_FORMAT,
            )
            grant, _ = _decode_document(
                row["grant_json"],
                expected_format=AGENT_CAPABILITY_GRANT_FORMAT,
            )
            events, _ = self._event_documents_locked(execution_id)
            if not _projection_has_exact_source_lineage(projection_document, events):
                raise AgentEventLogConflict("event_log_lifecycle_conflict")
            events.append(event_document)
            try:
                validate_agent_harness_documents(
                    activation,
                    grant,
                    events,
                    receipt_document,
                    projection_document,
                )
                _lifecycle_fold(events, receipt_document)
            except AgentEventLogError as exc:
                raise AgentEventLogConflict("event_log_lifecycle_conflict") from exc
            except Exception as exc:
                raise AgentEventLogConflict("event_log_lifecycle_conflict") from exc
            if len(events) > MAX_AGENT_EVENT_LOG_EVENTS:
                raise AgentEventLogConflict("event_log_event_bound_exceeded")
            if (
                self._current_total_bytes_locked(row) + len(event_bytes) + len(projection_bytes)
                > MAX_AGENT_EVENT_LOG_EXECUTION_BYTES
            ):
                raise AgentEventLogConflict("event_log_execution_too_large")
            new_generation = expected_generation + 1
            new_sequence = expected_sequence + 1
            new_head = str(event_document["content_hash"])
            values = self._row_state_values(row)
            values.update(
                generation=new_generation,
                next_sequence=new_sequence,
                head_hash=new_head,
            )
            attempted_mutation[0] = True
            try:
                self._fault("before_projection_table_insert")
                self.connection.execute(
                    """
                    INSERT INTO memory_projections(
                        execution_id, projection_id, projection_hash,
                        request_fingerprint, projection_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        execution_id,
                        projection_document["projection_id"],
                        projection_document["content_hash"],
                        request_fingerprint,
                        sqlite3.Binary(projection_bytes),
                    ),
                )
                self._fault("after_projection_table_insert")
                self._fault("before_projection_event_insert")
                self.connection.execute(
                    """
                    INSERT INTO events(execution_id, sequence, event_id, event_hash, event_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        execution_id,
                        expected_sequence,
                        event_document["event_id"],
                        new_head,
                        sqlite3.Binary(event_bytes),
                    ),
                )
                self._fault("after_projection_event_insert")
                self._fault("before_projection_state_update")
                changed = self.connection.execute(
                    """
                    UPDATE executions
                    SET generation = ?, next_sequence = ?, head_hash = ?, state_hash = ?
                    WHERE execution_id = ? AND state = 'terminal' AND generation = ?
                      AND next_sequence = ? AND head_hash = ?
                    """,
                    (
                        new_generation,
                        new_sequence,
                        new_head,
                        _state_hash(**values),
                        execution_id,
                        expected_generation,
                        expected_sequence,
                        expected_previous_hash,
                    ),
                ).rowcount
                self._fault("after_projection_state_update")
            except sqlite3.IntegrityError as exc:
                raise AgentEventLogConflict("event_log_projection_conflict") from exc
            if changed != 1:
                raise AgentEventLogConflict("event_log_projection_conflict")
            self._fault("before_projection_commit")
        return projection_document, True

    def _reconcile_memory_projection(
        self,
        *,
        execution_id: str,
        projection_bytes: bytes,
        event_bytes: bytes,
        request_fingerprint: str,
        expected_sequence: int,
        expected_previous_hash: str,
        expected_generation: int,
        cause: Exception,
    ) -> dict[str, object]:
        try:
            replay = self.replay_records(execution_id)
            stored = self.connection.execute(
                "SELECT request_fingerprint FROM memory_projections WHERE execution_id = ?",
                (execution_id,),
            ).fetchone()
            committed = (
                replay.state == "terminal"
                and replay.projection_bytes == projection_bytes
                and stored is not None
                and stored["request_fingerprint"] == request_fingerprint
                and replay.next_sequence == expected_sequence + 1
                and replay.generation == expected_generation + 1
                and len(replay.event_bytes) == expected_sequence + 1
                and replay.event_bytes[expected_sequence] == event_bytes
                and expected_previous_hash is not None
            )
            if committed:
                document, _ = _decode_document(
                    projection_bytes,
                    expected_format=AGENT_MEMORY_PROJECTION_FORMAT,
                )
                return document
        except Exception:
            pass
        self._indeterminate_executions.add(execution_id)
        raise AgentEventLogIndeterminate("event_log_projection_indeterminate") from cause

    def list_open(
        self,
        *,
        limit: int,
        after_execution_id: str | None = None,
    ) -> tuple[OpenExecution, ...]:
        self._assert_owner_process()
        if type(limit) is not int or not 1 <= limit <= MAX_AGENT_EVENT_LOG_PAGE_SIZE:
            raise AgentEventLogError("event_log_request_invalid")
        if after_execution_id is not None:
            after_execution_id = _plain_id(after_execution_id)
        with self._transaction():
            if after_execution_id is None:
                rows = self.connection.execute(
                    """
                    SELECT * FROM executions
                    WHERE state = 'open'
                    ORDER BY execution_id
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            else:
                rows = self.connection.execute(
                    """
                    SELECT * FROM executions
                    WHERE state = 'open' AND execution_id > ?
                    ORDER BY execution_id
                    LIMIT ?
                    """,
                    (after_execution_id, limit),
                ).fetchall()
            result: list[OpenExecution] = []
            for row in rows:
                self._verify_state_hash(row)
                if row["generation"] != row["next_sequence"]:
                    raise AgentEventLogCorrupt("event_log_projection_corrupt")
                result.append(
                    OpenExecution(
                        execution_id=str(row["execution_id"]),
                        log_id=str(row["log_id"]),
                        request_fingerprint=(
                            None
                            if row["request_fingerprint"] is None
                            else str(row["request_fingerprint"])
                        ),
                        generation=int(row["generation"]),
                        next_sequence=int(row["next_sequence"]),
                        head_hash=(None if row["head_hash"] is None else str(row["head_hash"])),
                    )
                )
            return tuple(result)

    def mark_recovery_required(
        self,
        execution_id: str,
        *,
        expected_sequence: int,
        expected_previous_hash: str | None,
        expected_generation: int,
    ) -> ReplayedExecution:
        self._assert_owner_process()
        self._require_recovery_session()
        execution_id = _plain_id(execution_id)
        expected_sequence = _plain_nonnegative(expected_sequence)
        expected_generation = _plain_nonnegative(expected_generation)
        expected_previous_hash = _plain_hash(expected_previous_hash, allow_none=True)
        self._activate_recovery_mutation()
        with self._transaction():
            row = self._execution_row_locked(execution_id)
            self._verify_state_hash(row)
            if (
                row["state"] != "open"
                or row["next_sequence"] != expected_sequence
                or row["head_hash"] != expected_previous_hash
                or row["generation"] != expected_generation
            ):
                raise AgentEventLogConflict("event_log_recovery_conflict")
            # A crash prefix is auditable but must never be resumed or completed.
            events, _ = self._event_documents_locked(execution_id)
            _lifecycle_fold(events, None)
            new_generation = expected_generation + 1
            values = self._row_state_values(row)
            values.update(state="recovery_required", generation=new_generation)
            changed = self.connection.execute(
                """
                UPDATE executions
                SET state = 'recovery_required', generation = ?, state_hash = ?
                WHERE execution_id = ? AND state = 'open' AND generation = ?
                  AND next_sequence = ? AND head_hash IS ?
                """,
                (
                    new_generation,
                    _state_hash(**values),
                    execution_id,
                    expected_generation,
                    expected_sequence,
                    expected_previous_hash,
                ),
            ).rowcount
            if changed != 1:
                raise AgentEventLogConflict("event_log_recovery_conflict")
            updated = self._execution_row_locked(execution_id)
            self._owned_executions.discard(execution_id)
            self._indeterminate_executions.discard(execution_id)
            return self._replay_locked(updated)

    def _replay_locked(
        self,
        row: sqlite3.Row,
        *,
        schema_version: int | None = None,
    ) -> ReplayedExecution:
        if schema_version is None:
            schema_version = self._read_schema_version_locked()
        self._verify_state_hash(row)
        activation, activation_bytes = _decode_document(
            row["activation_json"], expected_format=AGENT_WORKER_ACTIVATION_FORMAT
        )
        grant, grant_bytes = _decode_document(
            row["grant_json"], expected_format=AGENT_CAPABILITY_GRANT_FORMAT
        )
        events, event_bytes = self._event_documents_locked(row["execution_id"])
        receipt_row = self.connection.execute(
            "SELECT * FROM receipts WHERE execution_id = ?", (row["execution_id"],)
        ).fetchone()
        receipt: dict[str, object] | None = None
        receipt_bytes: bytes | None = None
        if receipt_row is not None:
            receipt, receipt_bytes = _decode_document(
                receipt_row["receipt_json"], expected_format=AGENT_EXECUTION_RECEIPT_FORMAT
            )
            if (
                receipt_row["execution_id"] != row["execution_id"]
                or receipt_row["receipt_id"] != receipt["receipt_id"]
                or receipt_row["receipt_hash"] != receipt["content_hash"]
            ):
                raise AgentEventLogCorrupt("event_log_projection_corrupt")
        projection: dict[str, object] | None = None
        projection_bytes: bytes | None = None
        projection_row = None
        if schema_version >= 2:
            projection_row = self.connection.execute(
                "SELECT * FROM memory_projections WHERE execution_id = ?",
                (row["execution_id"],),
            ).fetchone()
        if projection_row is not None:
            projection, projection_bytes = _decode_document(
                projection_row["projection_json"],
                expected_format=AGENT_MEMORY_PROJECTION_FORMAT,
            )
            if (
                projection_row["execution_id"] != row["execution_id"]
                or projection_row["projection_id"] != projection["projection_id"]
                or projection_row["projection_hash"] != projection["content_hash"]
                or type(projection_row["request_fingerprint"]) is not str
                or _SHA_RE.fullmatch(projection_row["request_fingerprint"]) is None
            ):
                raise AgentEventLogCorrupt("event_log_projection_corrupt")
        try:
            validate_agent_harness_documents(
                activation,
                grant,
                events,
                receipt,
                projection,
            )
            _lifecycle_fold(events, receipt)
        except AgentEventLogError:
            raise
        except Exception as exc:
            raise AgentEventLogCorrupt("event_log_lifecycle_invalid") from exc
        if (
            activation["execution_id"] != row["execution_id"]
            or grant["execution_id"] != row["execution_id"]
            or activation["content_hash"] != row["activation_hash"]
            or grant["content_hash"] != row["grant_hash"]
            or len(events) != row["next_sequence"]
            or row["generation"] < row["next_sequence"]
            or (None if not events else events[-1]["content_hash"]) != row["head_hash"]
            or any(event["log_id"] != row["log_id"] for event in events)
            or any(event["execution_id"] != row["execution_id"] for event in events)
        ):
            raise AgentEventLogCorrupt("event_log_projection_corrupt")
        if row["state"] == "terminal":
            if (
                receipt is None
                or receipt["receipt_id"] != row["receipt_id"]
                or receipt["content_hash"] != row["receipt_hash"]
                or not events
                or row["generation"] != row["next_sequence"]
            ):
                raise AgentEventLogCorrupt("event_log_projection_corrupt")
            if projection is None:
                if events[-1]["event_type"] != "execution.receipt_recorded":
                    raise AgentEventLogCorrupt("event_log_projection_corrupt")
            elif (
                receipt["outcome"] != "succeeded"
                or len(events) < 2
                or events[-2]["event_type"] != "execution.receipt_recorded"
                or events[-1]["event_type"] != "memory.projected"
                or not _projection_has_exact_source_lineage(projection, events[:-1])
                or events[-1]["event_id"]
                != _memory_projection_event_id(projection_row["request_fingerprint"])
                or projection["execution_id"] != row["execution_id"]
                or events[-1]["subject"]
                != {
                    "format": AGENT_MEMORY_PROJECTION_FORMAT,
                    "format_version": 1,
                    "id": projection["projection_id"],
                    "content_hash": projection["content_hash"],
                }
            ):
                raise AgentEventLogCorrupt("event_log_projection_corrupt")
        elif (
            receipt is not None
            or projection is not None
            or row["receipt_id"] is not None
            or row["receipt_hash"] is not None
            or (
                events
                and events[-1]["event_type"] in {"execution.receipt_recorded", "memory.projected"}
            )
        ):
            raise AgentEventLogCorrupt("event_log_projection_corrupt")
        if row["state"] == "open" and row["generation"] != row["next_sequence"]:
            raise AgentEventLogCorrupt("event_log_projection_corrupt")
        if row["state"] == "recovery_required" and row["generation"] != row["next_sequence"] + 1:
            raise AgentEventLogCorrupt("event_log_projection_corrupt")
        total = len(activation_bytes) + len(grant_bytes) + sum(map(len, event_bytes))
        if receipt_bytes is not None:
            total += len(receipt_bytes)
        if projection_bytes is not None:
            total += len(projection_bytes)
        if total > MAX_AGENT_EVENT_LOG_EXECUTION_BYTES:
            raise AgentEventLogCorrupt("event_log_execution_too_large")
        return ReplayedExecution(
            execution_id=str(row["execution_id"]),
            log_id=str(row["log_id"]),
            request_fingerprint=(
                None if row["request_fingerprint"] is None else str(row["request_fingerprint"])
            ),
            state=str(row["state"]),
            generation=int(row["generation"]),
            next_sequence=int(row["next_sequence"]),
            head_hash=None if row["head_hash"] is None else str(row["head_hash"]),
            state_hash=str(row["state_hash"]),
            activation_bytes=bytes(activation_bytes),
            grant_bytes=bytes(grant_bytes),
            event_bytes=tuple(bytes(item) for item in event_bytes),
            receipt_bytes=None if receipt_bytes is None else bytes(receipt_bytes),
            projection_bytes=(None if projection_bytes is None else bytes(projection_bytes)),
        )


class AgentExecutionCoordinator:
    """Execute once or return immutable terminal evidence for an exact duplicate."""

    def __init__(
        self,
        *,
        kernel: AgentExecutionKernel,
        event_log: AgentEventLog,
    ) -> None:
        if kernel.journal is not event_log:
            raise AgentEventLogError("event_log_coordinator_mismatch")
        self.kernel = kernel
        self.event_log = event_log

    def execute(self, request: ExecutionRequest) -> CoordinatedExecution:
        if self.kernel.journal is not self.event_log:
            raise AgentEventLogError("event_log_coordinator_mismatch")
        # The private coordinator may use the kernel's exact validation helper;
        # this is not a public authoring or wire contract.
        from .kernel import KernelError, _prepared_execution_request

        prepared, activation, _ = _prepared_execution_request(request)
        execution_id = str(activation["execution_id"])
        try:
            result = self.kernel.execute(prepared)
        except KernelError as exc:
            if exc.reason_code != "execution_already_recorded":
                raise
            records = self.event_log.replay_records(execution_id)
            if records.state != "terminal":
                raise AgentEventLogCorrupt("event_log_projection_corrupt") from None
            return CoordinatedExecution("existing_terminal", records, None)
        records = self.event_log.replay_records(execution_id)
        if records.state != "terminal":
            raise AgentEventLogCorrupt("event_log_projection_corrupt")
        return CoordinatedExecution("executed", records, result)


__all__ = (
    "AGENT_EVENT_LOG_SCHEMA_VERSION",
    "AgentEventLog",
    "AgentEventLogConflict",
    "AgentEventLogCorrupt",
    "AgentEventLogError",
    "AgentEventLogIndeterminate",
    "AgentExecutionCoordinator",
    "CoordinatedExecution",
    "OpenExecution",
    "ReplayedExecution",
)
