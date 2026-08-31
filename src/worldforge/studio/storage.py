from __future__ import annotations

import json
import math
import os
import sqlite3
import stat
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from isoworld.content.file_stat import FileStat, path_file_stat
from worldforge.directory_publish import retained_recovery_evidence
from worldforge.studio.contracts import (
    EXTERNAL_JOB_VERSION,
    creation_job_record_hash,
    validate_studio_creation_job,
    validate_studio_creation_output_grant_v6,
    validate_studio_external_grant,
    validate_studio_job,
)
from worldforge.studio.creation_process import (
    CreationProcessError,
    terminate_registered_creation_process,
)
from worldforge.studio.errors import StudioContractError, StudioError

SCHEMA_VERSION = 6
DATABASE_NAME = "studio.sqlite3"
_CREATION_ARTIFACT_SCOPE_MIGRATION_DATA_STEP_COUNT = 11
_CREATION_ARTIFACT_SCOPE_MIGRATION_STEP_COUNT = 12
_CREATION_ARTIFACT_SCOPE_MIGRATION_TABLES = frozenset(
    {
        "creation_artifacts_workspace_scoped",
        "creation_artifact_dependencies_workspace_scoped",
    }
)

_AUTHORITY_SCHEMA_ERROR = "Authenticated decision database schema is invalid"
_AUTHORITY_CREDENTIALS_TABLE = "studio_authenticated_human_credentials"
_AUTHORITY_DECISIONS_TABLE = "studio_authenticated_human_decisions"
_AUTHORITY_EVENTS_TABLE = "studio_authenticated_human_decision_events"
_AUTHORITY_APPROVAL_INDEX = "studio_authenticated_human_decision_events_approval_idx"
_AUTHORITY_CREDENTIALS_DDL = f"""CREATE TABLE IF NOT EXISTS {_AUTHORITY_CREDENTIALS_TABLE} (
    credential_id TEXT PRIMARY KEY NOT NULL
        CHECK (credential_id = 'director_local'),
    kdf_name TEXT NOT NULL CHECK (kdf_name = 'scrypt'),
    kdf_n INTEGER NOT NULL CHECK (kdf_n = 32768),
    kdf_r INTEGER NOT NULL CHECK (kdf_r = 8),
    kdf_p INTEGER NOT NULL CHECK (kdf_p = 1),
    kdf_dklen INTEGER NOT NULL CHECK (kdf_dklen = 32),
    kdf_maxmem INTEGER NOT NULL CHECK (kdf_maxmem = 67108864),
    salt BLOB NOT NULL CHECK (length(salt) = 32),
    verifier BLOB NOT NULL CHECK (length(verifier) = 32),
    created_at TEXT NOT NULL
)"""
_AUTHORITY_DECISIONS_DDL = f"""CREATE TABLE IF NOT EXISTS {_AUTHORITY_DECISIONS_TABLE} (
    approval_id TEXT PRIMARY KEY NOT NULL,
    review_hash TEXT NOT NULL,
    review_json TEXT NOT NULL,
    decision_hash TEXT,
    decision_json TEXT,
    state TEXT NOT NULL CHECK (state IN ('prepared', 'approved', 'denied', 'revoked')),
    generation INTEGER NOT NULL CHECK (generation IN (0, 1, 2)),
    last_event_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (generation = 0 AND state = 'prepared'
            AND decision_hash IS NULL AND decision_json IS NULL)
        OR (generation = 1 AND state IN ('approved', 'denied')
            AND decision_hash IS NOT NULL AND decision_json IS NOT NULL)
        OR (generation = 2 AND state = 'revoked'
            AND decision_hash IS NOT NULL AND decision_json IS NOT NULL)
    )
)"""
_AUTHORITY_EVENTS_DDL = f"""CREATE TABLE IF NOT EXISTS {_AUTHORITY_EVENTS_TABLE} (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id TEXT NOT NULL
        REFERENCES {_AUTHORITY_CREDENTIALS_TABLE}(credential_id),
    approval_id TEXT NOT NULL
        REFERENCES {_AUTHORITY_DECISIONS_TABLE}(approval_id)
        DEFERRABLE INITIALLY DEFERRED,
    generation INTEGER NOT NULL CHECK (generation IN (0, 1, 2)),
    event_type TEXT NOT NULL CHECK (event_type IN ('prepared', 'decided', 'revoked')),
    content_json TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE,
    previous_hash TEXT NOT NULL,
    mac BLOB NOT NULL CHECK (length(mac) = 32),
    created_at TEXT NOT NULL
)"""
_AUTHORITY_APPROVAL_INDEX_DDL = f"""CREATE INDEX IF NOT EXISTS
    {_AUTHORITY_APPROVAL_INDEX}
    ON {_AUTHORITY_EVENTS_TABLE}(approval_id, event_id)"""
_AUTHORITY_V6_DDL = (
    _AUTHORITY_CREDENTIALS_DDL,
    _AUTHORITY_DECISIONS_DDL,
    _AUTHORITY_EVENTS_DDL,
    _AUTHORITY_APPROVAL_INDEX_DDL,
)
_AUTHORITY_TABLE_XINFO = {
    _AUTHORITY_CREDENTIALS_TABLE: (
        (0, "credential_id", "TEXT", 1, None, 1, 0),
        (1, "kdf_name", "TEXT", 1, None, 0, 0),
        (2, "kdf_n", "INTEGER", 1, None, 0, 0),
        (3, "kdf_r", "INTEGER", 1, None, 0, 0),
        (4, "kdf_p", "INTEGER", 1, None, 0, 0),
        (5, "kdf_dklen", "INTEGER", 1, None, 0, 0),
        (6, "kdf_maxmem", "INTEGER", 1, None, 0, 0),
        (7, "salt", "BLOB", 1, None, 0, 0),
        (8, "verifier", "BLOB", 1, None, 0, 0),
        (9, "created_at", "TEXT", 1, None, 0, 0),
    ),
    _AUTHORITY_DECISIONS_TABLE: (
        (0, "approval_id", "TEXT", 1, None, 1, 0),
        (1, "review_hash", "TEXT", 1, None, 0, 0),
        (2, "review_json", "TEXT", 1, None, 0, 0),
        (3, "decision_hash", "TEXT", 0, None, 0, 0),
        (4, "decision_json", "TEXT", 0, None, 0, 0),
        (5, "state", "TEXT", 1, None, 0, 0),
        (6, "generation", "INTEGER", 1, None, 0, 0),
        (7, "last_event_hash", "TEXT", 1, None, 0, 0),
        (8, "updated_at", "TEXT", 1, None, 0, 0),
    ),
    _AUTHORITY_EVENTS_TABLE: (
        (0, "event_id", "INTEGER", 0, None, 1, 0),
        (1, "credential_id", "TEXT", 1, None, 0, 0),
        (2, "approval_id", "TEXT", 1, None, 0, 0),
        (3, "generation", "INTEGER", 1, None, 0, 0),
        (4, "event_type", "TEXT", 1, None, 0, 0),
        (5, "content_json", "TEXT", 1, None, 0, 0),
        (6, "content_hash", "TEXT", 1, None, 0, 0),
        (7, "previous_hash", "TEXT", 1, None, 0, 0),
        (8, "mac", "BLOB", 1, None, 0, 0),
        (9, "created_at", "TEXT", 1, None, 0, 0),
    ),
}
_AUTHORITY_INDEX_LIST = {
    _AUTHORITY_CREDENTIALS_TABLE: {
        (f"sqlite_autoindex_{_AUTHORITY_CREDENTIALS_TABLE}_1", 1, "pk", 0),
    },
    _AUTHORITY_DECISIONS_TABLE: {
        (f"sqlite_autoindex_{_AUTHORITY_DECISIONS_TABLE}_1", 1, "pk", 0),
    },
    _AUTHORITY_EVENTS_TABLE: {
        (_AUTHORITY_APPROVAL_INDEX, 0, "c", 0),
        (f"sqlite_autoindex_{_AUTHORITY_EVENTS_TABLE}_1", 1, "u", 0),
    },
}
_AUTHORITY_INDEX_INFO = {
    f"sqlite_autoindex_{_AUTHORITY_CREDENTIALS_TABLE}_1": (
        (0, 0, "credential_id"),
    ),
    f"sqlite_autoindex_{_AUTHORITY_DECISIONS_TABLE}_1": (
        (0, 0, "approval_id"),
    ),
    _AUTHORITY_APPROVAL_INDEX: ((0, 2, "approval_id"), (1, 0, "event_id")),
    f"sqlite_autoindex_{_AUTHORITY_EVENTS_TABLE}_1": ((0, 6, "content_hash"),),
}
_AUTHORITY_FOREIGN_KEYS = {
    _AUTHORITY_CREDENTIALS_TABLE: set(),
    _AUTHORITY_DECISIONS_TABLE: set(),
    _AUTHORITY_EVENTS_TABLE: {
        (
            _AUTHORITY_DECISIONS_TABLE,
            "approval_id",
            "approval_id",
            "NO ACTION",
            "NO ACTION",
            "NONE",
        ),
        (
            _AUTHORITY_CREDENTIALS_TABLE,
            "credential_id",
            "credential_id",
            "NO ACTION",
            "NO ACTION",
            "NONE",
        ),
    },
}


def _normalize_schema_sql(value: str) -> str:
    return " ".join(value.split())


def _stored_schema_sql(value: str) -> str:
    return _normalize_schema_sql(value).replace(" IF NOT EXISTS", "", 1)


def _verify_authenticated_human_decision_v6(connection: sqlite3.Connection) -> None:
    """Verify the exact private authority schema and live constraint PRAGMAs."""
    try:
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
        ignored_checks = connection.execute(
            "PRAGMA ignore_check_constraints"
        ).fetchone()
        if (
            foreign_keys is None
            or foreign_keys[0] != 1
            or ignored_checks is None
            or ignored_checks[0] != 0
        ):
            raise ValueError("authority pragmas")

        expected_objects: dict[tuple[str, str, str], str | None] = {
            (
                "table",
                _AUTHORITY_CREDENTIALS_TABLE,
                _AUTHORITY_CREDENTIALS_TABLE,
            ): _stored_schema_sql(_AUTHORITY_CREDENTIALS_DDL),
            (
                "table",
                _AUTHORITY_DECISIONS_TABLE,
                _AUTHORITY_DECISIONS_TABLE,
            ): _stored_schema_sql(_AUTHORITY_DECISIONS_DDL),
            (
                "table",
                _AUTHORITY_EVENTS_TABLE,
                _AUTHORITY_EVENTS_TABLE,
            ): _stored_schema_sql(_AUTHORITY_EVENTS_DDL),
            (
                "index",
                _AUTHORITY_APPROVAL_INDEX,
                _AUTHORITY_EVENTS_TABLE,
            ): _stored_schema_sql(_AUTHORITY_APPROVAL_INDEX_DDL),
            (
                "index",
                f"sqlite_autoindex_{_AUTHORITY_CREDENTIALS_TABLE}_1",
                _AUTHORITY_CREDENTIALS_TABLE,
            ): None,
            (
                "index",
                f"sqlite_autoindex_{_AUTHORITY_DECISIONS_TABLE}_1",
                _AUTHORITY_DECISIONS_TABLE,
            ): None,
            (
                "index",
                f"sqlite_autoindex_{_AUTHORITY_EVENTS_TABLE}_1",
                _AUTHORITY_EVENTS_TABLE,
            ): None,
        }
        rows = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema"
        ).fetchall()
        authority_prefix = "studio_authenticated_human_"
        authority_tables = {
            _AUTHORITY_CREDENTIALS_TABLE.casefold(),
            _AUTHORITY_DECISIONS_TABLE.casefold(),
            _AUTHORITY_EVENTS_TABLE.casefold(),
        }
        observed_objects: dict[tuple[str, str, str], str | None] = {}
        for row in rows:
            name = row[1]
            table = row[2]
            if type(name) is not str or type(table) is not str:
                raise ValueError("authority object identity")
            if not (
                name.casefold().startswith(authority_prefix)
                or table.casefold() in authority_tables
            ):
                continue
            sql = row[3]
            if sql is not None and type(sql) is not str:
                raise ValueError("authority schema SQL")
            observed_objects[(row[0], name, table)] = (
                None if sql is None else _normalize_schema_sql(sql)
            )
        if observed_objects != expected_objects:
            raise ValueError("authority object census")

        for table, expected_xinfo in _AUTHORITY_TABLE_XINFO.items():
            xinfo = tuple(
                tuple(row)
                for row in connection.execute(f'PRAGMA table_xinfo("{table}")')
            )
            if xinfo != expected_xinfo:
                raise ValueError("authority columns")

            indexes = {
                (row[1], row[2], row[3], row[4])
                for row in connection.execute(f'PRAGMA index_list("{table}")')
            }
            if indexes != _AUTHORITY_INDEX_LIST[table]:
                raise ValueError("authority indexes")

            foreign_key_rows = connection.execute(
                f'PRAGMA foreign_key_list("{table}")'
            )
            foreign_key_shapes = {
                (row[2], row[3], row[4], row[5], row[6], row[7])
                for row in foreign_key_rows
            }
            if foreign_key_shapes != _AUTHORITY_FOREIGN_KEYS[table]:
                raise ValueError("authority foreign keys")

        for index, expected_info in _AUTHORITY_INDEX_INFO.items():
            info = tuple(
                tuple(row)
                for row in connection.execute(f'PRAGMA index_info("{index}")')
            )
            if info != expected_info:
                raise ValueError("authority index columns")
    except (IndexError, KeyError, sqlite3.Error, TypeError, ValueError) as exc:
        raise StudioError("invalid_state", _AUTHORITY_SCHEMA_ERROR) from exc


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def encode_json(value: object) -> str:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )


def decode_object(value: str, *, context: str) -> dict[str, Any]:
    try:
        decoded = json.loads(
            value,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise StudioError("internal_error", f"Stored {context} is invalid") from exc
    if not isinstance(decoded, dict):
        raise StudioError("internal_error", f"Stored {context} is not an object")
    return decoded


def _absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(Path(path)))


def _is_link_or_reparse(info: FileStat) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def _ensure_safe_directory(path: Path, *, create: bool = True) -> None:
    if create:
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StudioError(
                "internal_error", f"Could not create Studio data directory: {exc}"
            ) from exc
    elif not path.exists():
        raise StudioError("invalid_state", f"Studio directory does not exist: {path}")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = path_file_stat(current)
        except OSError as exc:
            raise StudioError(
                "internal_error", f"Could not inspect Studio data directory: {exc}"
            ) from exc
        if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise StudioError(
                "invalid_request", f"Studio data path is not a safe directory: {current}"
            )


def _safe_database_file(path: Path) -> tuple[int, int] | None:
    try:
        info = path_file_stat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StudioError("internal_error", f"Could not inspect Studio database: {exc}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise StudioError("invalid_request", "Studio database must be a standalone regular file")
    return info.st_dev, info.st_ino


class StudioStore:
    """Durable Studio registry. Repository contents never enter this database."""

    def __init__(
        self,
        data_dir: str | Path,
        *,
        mode: Literal["primary", "secondary"] = "primary",
    ) -> None:
        if mode not in {"primary", "secondary"}:
            raise ValueError("Studio store mode must be 'primary' or 'secondary'")
        self.mode = mode
        self._creator_thread_id = threading.get_ident()
        self._authenticated_human_decision_lock = threading.RLock()
        self._authenticated_human_decision_connection_instance: (
            sqlite3.Connection | None
        ) = None
        self._authenticated_human_decision_connection_unavailable = False
        self._closed = False
        self.data_dir = _absolute(data_dir)
        create = mode == "primary"
        _ensure_safe_directory(self.data_dir, create=create)
        self.blobs_dir = self.data_dir / "blobs/sha256"
        self.journals_dir = self.data_dir / "journals"
        self.creation_changeset_journals_dir = self.journals_dir / "creation-changesets"
        self.creation_job_journals_dir = self.journals_dir / "creation-jobs"
        self.creation_jobs_dir = self.data_dir / "creation-jobs"
        _ensure_safe_directory(self.blobs_dir, create=create)
        _ensure_safe_directory(self.journals_dir, create=create)
        _ensure_safe_directory(self.creation_changeset_journals_dir, create=create)
        _ensure_safe_directory(self.creation_job_journals_dir, create=create)
        _ensure_safe_directory(self.creation_jobs_dir, create=create)
        self.database_path = self.data_dir / DATABASE_NAME
        before = _safe_database_file(self.database_path)
        if mode == "secondary" and before is None:
            raise StudioError(
                "invalid_state", "Secondary Studio store requires an existing database"
            )
        try:
            target: str | Path = self.database_path
            uri = False
            if mode == "secondary":
                target = f"{self.database_path.as_uri()}?mode=rw"
                uri = True
            self.connection = sqlite3.connect(target, timeout=5.0, uri=uri)
        except sqlite3.Error as exc:
            raise StudioError("internal_error", f"Could not open Studio database: {exc}") from exc
        self.connection.row_factory = sqlite3.Row
        after = _safe_database_file(self.database_path)
        if after is None or (before is not None and before != after):
            self.connection.close()
            raise StudioError("conflict", "Studio database identity changed while opening")
        try:
            self._configure(require_existing_wal=mode == "secondary")
            if mode == "primary":
                self._migrate()
                self._reap_registered_creation_workers()
                self._orphan_running_jobs()
            else:
                self._verify_schema()
        except Exception:
            self.connection.close()
            raise

    def __enter__(self) -> StudioStore:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        if threading.get_ident() != self._creator_thread_id:
            raise StudioError(
                "invalid_state", "Studio store close requires its creator thread"
            )
        with self._authenticated_human_decision_lock:
            if self._closed:
                return
            self._closed = True
            authority_connection = self._authenticated_human_decision_connection_instance
            self._authenticated_human_decision_connection_instance = None
            try:
                if authority_connection is not None:
                    authority_connection.close()
            finally:
                self.connection.close()

    def _authenticated_human_decision_connection(self) -> sqlite3.Connection:
        """Return the Store-owned connection isolated for the private authority."""
        with self._authenticated_human_decision_lock:
            if self._closed:
                raise StudioError("invalid_state", "Studio store is closed")
            if self._authenticated_human_decision_connection_unavailable:
                raise StudioError(
                    "invalid_state", "Authenticated decision authority is unavailable"
                )
            existing = self._authenticated_human_decision_connection_instance
            if existing is not None:
                return existing
            before = _safe_database_file(self.database_path)
            if before is None:
                raise StudioError(
                    "invalid_state", "Authenticated decision database is unavailable"
                )
            connection: sqlite3.Connection | None = None
            try:
                connection = sqlite3.connect(
                    f"{self.database_path.as_uri()}?mode=rw",
                    timeout=5.0,
                    uri=True,
                    check_same_thread=False,
                )
                connection.row_factory = sqlite3.Row
                after = _safe_database_file(self.database_path)
                if after != before:
                    raise StudioError(
                        "conflict",
                        "Studio database identity changed while opening authority connection",
                    )
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("PRAGMA busy_timeout = 5000")
                journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
                connection.execute("PRAGMA synchronous = FULL")
                if str(journal_mode).casefold() != "wal":
                    raise StudioError(
                        "invalid_state",
                        "Authenticated decision database requires WAL mode",
                    )
                row = connection.execute(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                ).fetchone()
                if row is None or int(row["value"]) != SCHEMA_VERSION:
                    raise StudioError(
                        "invalid_state",
                        f"Authenticated decision database requires schema version {SCHEMA_VERSION}",
                    )
                _verify_authenticated_human_decision_v6(connection)
            except StudioError:
                if connection is not None:
                    connection.close()
                raise
            except (sqlite3.Error, ValueError) as exc:
                if connection is not None:
                    connection.close()
                raise StudioError(
                    "invalid_state", "Authenticated decision database is unavailable"
                ) from exc
            self._authenticated_human_decision_connection_instance = connection
            return connection

    def _require_active_authenticated_human_decision_connection(
        self, connection: sqlite3.Connection
    ) -> None:
        """Reject a closed Store or an authority connection detached by close()."""
        if self._closed:
            raise StudioError("invalid_state", "Studio store is closed")
        if self._authenticated_human_decision_connection_unavailable:
            raise StudioError(
                "invalid_state", "Authenticated decision authority is unavailable"
            )
        if self._authenticated_human_decision_connection_instance is not connection:
            raise StudioError(
                "invalid_state", "Authenticated decision authority is unavailable"
            )

    def _invalidate_authenticated_human_decision_connection(
        self, connection: sqlite3.Connection
    ) -> None:
        """Permanently disable this Store's uncertain private connection."""
        with self._authenticated_human_decision_lock:
            cached = self._authenticated_human_decision_connection_instance
            self._authenticated_human_decision_connection_instance = None
            self._authenticated_human_decision_connection_unavailable = True
            targets = (connection,) if cached is connection else (connection, cached)
            for target in targets:
                if target is None:
                    continue
                try:
                    target.close()
                except BaseException:
                    pass

    def blob_path(self, digest: str) -> Path:
        return self.blobs_dir / digest[:2] / digest

    def _configure(self, *, require_existing_wal: bool) -> None:
        try:
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA busy_timeout = 5000")
            pragma = "PRAGMA journal_mode" if require_existing_wal else "PRAGMA journal_mode = WAL"
            mode = self.connection.execute(pragma).fetchone()[0]
            self.connection.execute("PRAGMA synchronous = FULL")
        except sqlite3.Error as exc:
            raise StudioError(
                "internal_error", f"Could not configure Studio database: {exc}"
            ) from exc
        if str(mode).casefold() != "wal":
            message = (
                "Secondary Studio database is not already in WAL mode"
                if require_existing_wal
                else "Studio database could not enable WAL mode"
            )
            raise StudioError("internal_error", message)

    def _verify_schema(self) -> None:
        try:
            row = self.connection.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            version = None if row is None else int(row["value"])
        except (sqlite3.Error, ValueError) as exc:
            raise StudioError(
                "invalid_state", "Secondary Studio database schema is unavailable"
            ) from exc
        if version != SCHEMA_VERSION:
            raise StudioError(
                "invalid_state",
                f"Secondary Studio database requires schema version {SCHEMA_VERSION}",
            )
        required_operation_columns = {
            "changeset_id",
            "path",
            "operation",
            "base_blob_sha256",
            "base_size",
            "proposed_blob_sha256",
            "proposed_size",
        }
        try:
            operation_columns = {
                column["name"]
                for column in self.connection.execute(
                    "PRAGMA table_info(creation_changeset_operations)"
                )
            }
        except sqlite3.Error as exc:
            raise StudioError(
                "invalid_state",
                "Secondary Studio database operation projection is unavailable",
            ) from exc
        if not required_operation_columns <= operation_columns:
            raise StudioError(
                "invalid_state",
                "Secondary Studio database is missing required columns in operation projection",
            )
        required_v4_columns = {
            "creation_jobs": {
                "sequence",
                "job_id",
                "workspace_id",
                "operation",
                "state",
                "progress",
                "generation",
                "cancel_requested",
                "record_json",
            },
            "creation_artifacts": {
                "artifact_id",
                "workspace_id",
                "lifecycle",
                "subject_format",
                "subject_version",
                "subject_id",
                "content_hash",
                "roles_json",
                "document_blob_sha256",
                "document_size",
                "blob_dev",
                "blob_ino",
                "producer_job_id",
                "producer_operation",
                "producer_output_position",
                "root_generation",
                "source_revision",
                "workflow_status_hash",
                "input_artifact_snapshot_hash",
                "generation",
                "created_at",
                "record_json",
            },
            "creation_job_attempts": {
                "job_id",
                "phase",
                "journal_name",
                "journal_dev",
                "journal_ino",
                "stage_locator",
                "stage_dev",
                "stage_ino",
                "request_locator",
                "request_sha256",
                "worker_pid",
                "worker_identity_json",
                "binary_output_dev",
                "binary_output_ino",
                "generation",
                "created_at",
                "updated_at",
            },
            "creation_job_inputs": {
                "job_id",
                "position",
                "artifact_id",
                "subject_format",
                "subject_version",
                "subject_id",
                "content_hash",
            },
            "creation_job_payloads": {
                "job_id",
                "document_blob_sha256",
                "document_size",
                "blob_dev",
                "blob_ino",
                "subject_format",
                "subject_version",
                "subject_id",
                "content_hash",
            },
            "creation_job_outputs": {
                "job_id",
                "position",
                "artifact_id",
                "subject_format",
                "subject_version",
                "subject_id",
                "content_hash",
            },
            "creation_output_grants": {
                "grant_id",
                "workspace_id",
                "kind",
                "state",
                "record_json",
                "absolute_path",
                "parent_dev",
                "parent_ino",
                "normalized_leaf",
                "reserved_job_id",
                "generation",
                "expected_manifest_hash",
                "expected_tree_hash",
                "expected_archive_sha256",
                "expected_size_bytes",
                "published_dev",
                "published_ino",
                "recovery_json",
            },
            "creation_artifact_dependencies": {
                "workspace_id",
                "artifact_id",
                "position",
                "dependency_artifact_id",
                "subject_format",
                "subject_version",
                "subject_id",
                "content_hash",
            },
        }
        try:
            for table, required in required_v4_columns.items():
                columns = {
                    column["name"]
                    for column in self.connection.execute(f"PRAGMA table_info({table})")
                }
                if not required <= columns:
                    raise StudioError(
                        "invalid_state",
                        f"Secondary Studio database is missing required columns in {table}",
                    )
        except sqlite3.Error as exc:
            raise StudioError(
                "invalid_state",
                "Secondary Studio database creation-job projection is unavailable",
            ) from exc
        self._verify_creation_v4_relational_shape()
        _verify_authenticated_human_decision_v6(self.connection)

    def _migrate(self) -> None:
        try:
            with self.connection:
                self.connection.execute(
                    "CREATE TABLE IF NOT EXISTS schema_meta ("
                    "key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)"
                )
                row = self.connection.execute(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                ).fetchone()
                version = 0 if row is None else int(row["value"])
                if version > SCHEMA_VERSION:
                    raise StudioError(
                        "invalid_state",
                        f"Studio database uses newer schema version {version}",
                    )
                if version < 1:
                    self._create_v1_schema()
                    self.connection.execute(
                        "INSERT OR REPLACE INTO schema_meta (key, value) "
                        "VALUES ('schema_version', ?)",
                        ("1",),
                    )
                    version = 1
                if version < 2:
                    self._create_v2_schema()
                    self.connection.execute(
                        "INSERT OR REPLACE INTO schema_meta (key, value) "
                        "VALUES ('schema_version', '2')"
                    )
                    version = 2
                if version < 3:
                    self._create_v3_schema()
                    self.connection.execute(
                        "INSERT OR REPLACE INTO schema_meta (key, value) "
                        "VALUES ('schema_version', '3')"
                    )
                    version = 3
                if version < 4:
                    self._create_v4_schema(advance_schema_version=True)
                    version = 4
                if version < 5:
                    self._create_v5_schema(advance_schema_version=True)
                    version = 5
                if version < 6:
                    self._create_v6_schema(advance_schema_version=True)
                    version = 6
                if version >= 3:
                    # Protocol v3 is still additive and unpublished. Re-running
                    # its idempotent DDL lets existing development databases
                    # acquire newly introduced private recovery tables without
                    # reinterpreting any persisted public record.
                    self._create_v3_schema()
                if version >= 4:
                    # Protocol v4 follows the same additive development rule.
                    self._create_v4_schema()
                if version >= 5:
                    self._create_v5_schema()
                if version == 6:
                    _verify_authenticated_human_decision_v6(self.connection)
        except StudioError:
            raise
        except (sqlite3.Error, ValueError) as exc:
            raise StudioError(
                "internal_error", f"Could not migrate Studio database: {exc}"
            ) from exc

    def _create_v1_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS workspaces (
                workspace_id TEXT PRIMARY KEY NOT NULL,
                record_json TEXT NOT NULL,
                forge_dev TEXT NOT NULL,
                forge_ino TEXT NOT NULL,
                world_dev TEXT NOT NULL,
                world_ino TEXT NOT NULL,
                game_dev TEXT,
                game_ino TEXT,
                bundle_dev TEXT,
                bundle_ino TEXT
            );
            CREATE TABLE IF NOT EXISTS changesets (
                changeset_id TEXT PRIMARY KEY NOT NULL,
                workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
                status TEXT NOT NULL,
                record_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS changesets_workspace_idx
                ON changesets(workspace_id, changeset_id);
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY NOT NULL,
                workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
                state TEXT NOT NULL,
                record_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS jobs_workspace_idx ON jobs(workspace_id, job_id);
            CREATE TABLE IF NOT EXISTS events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT REFERENCES workspaces(workspace_id),
                topic TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_workspace_idx ON events(workspace_id, event_id);
            """
        )

    def _create_v2_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS external_grants (
                grant_id TEXT PRIMARY KEY NOT NULL,
                workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
                operation TEXT NOT NULL,
                role TEXT NOT NULL,
                artifact_kind TEXT NOT NULL,
                state TEXT NOT NULL,
                record_json TEXT NOT NULL,
                absolute_path TEXT NOT NULL,
                source_dev TEXT,
                source_ino TEXT,
                parent_dev TEXT,
                parent_ino TEXT,
                normalized_leaf TEXT,
                reserved_job_id TEXT REFERENCES jobs(job_id)
                    DEFERRABLE INITIALLY DEFERRED,
                generation INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS external_grants_workspace_idx
                ON external_grants(workspace_id, grant_id);
            CREATE INDEX IF NOT EXISTS external_grants_reservation_idx
                ON external_grants(reserved_job_id, state);
            """
        )

    def _create_v3_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS creation_root_grants (
                grant_id TEXT PRIMARY KEY NOT NULL,
                role TEXT NOT NULL,
                state TEXT NOT NULL,
                record_json TEXT NOT NULL,
                absolute_path TEXT NOT NULL,
                root_dev TEXT,
                root_ino TEXT,
                parent_dev TEXT,
                parent_ino TEXT,
                normalized_leaf TEXT,
                reserved_workspace_id TEXT,
                generation INTEGER NOT NULL DEFAULT 0,
                creation_spec_json TEXT
            );
            CREATE INDEX IF NOT EXISTS creation_root_grants_state_idx
                ON creation_root_grants(state, grant_id);
            CREATE INDEX IF NOT EXISTS creation_root_grants_reservation_idx
                ON creation_root_grants(reserved_workspace_id, state);
            CREATE TABLE IF NOT EXISTS creation_workspace_attempts (
                workspace_id TEXT PRIMARY KEY NOT NULL,
                grant_id TEXT NOT NULL UNIQUE REFERENCES creation_root_grants(grant_id),
                phase TEXT NOT NULL,
                journal_name TEXT NOT NULL UNIQUE,
                journal_dev TEXT,
                journal_ino TEXT,
                root_dev TEXT,
                root_ino TEXT,
                generation INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS creation_workspace_attempts_phase_idx
                ON creation_workspace_attempts(phase, workspace_id);
            CREATE TABLE IF NOT EXISTS creation_workspaces (
                workspace_id TEXT PRIMARY KEY NOT NULL,
                record_json TEXT NOT NULL,
                absolute_root TEXT NOT NULL,
                root_dev TEXT NOT NULL,
                root_ino TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS creation_changesets (
                changeset_id TEXT PRIMARY KEY NOT NULL,
                workspace_id TEXT NOT NULL REFERENCES creation_workspaces(workspace_id),
                status TEXT NOT NULL,
                record_json TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS creation_changesets_workspace_idx
                ON creation_changesets(workspace_id, changeset_id);
            CREATE INDEX IF NOT EXISTS creation_changesets_status_idx
                ON creation_changesets(status, changeset_id);
            CREATE TABLE IF NOT EXISTS creation_changeset_operations (
                changeset_id TEXT NOT NULL REFERENCES creation_changesets(changeset_id)
                    ON DELETE CASCADE,
                path TEXT NOT NULL,
                operation TEXT NOT NULL,
                base_blob_sha256 TEXT,
                base_size INTEGER,
                proposed_blob_sha256 TEXT,
                proposed_size INTEGER,
                PRIMARY KEY (changeset_id, path)
            );
            CREATE TABLE IF NOT EXISTS creation_changeset_attempts (
                changeset_id TEXT PRIMARY KEY NOT NULL
                    REFERENCES creation_changesets(changeset_id) ON DELETE CASCADE,
                phase TEXT NOT NULL,
                journal_name TEXT NOT NULL UNIQUE,
                journal_dev TEXT,
                journal_ino TEXT,
                root_dev TEXT NOT NULL,
                root_ino TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS creation_changeset_attempts_phase_idx
                ON creation_changeset_attempts(phase, changeset_id);
            CREATE TABLE IF NOT EXISTS creation_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT REFERENCES creation_workspaces(workspace_id),
                topic TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS creation_events_workspace_idx
                ON creation_events(workspace_id, event_id);
            """
        )
        self._ensure_creation_changeset_operation_sizes()

    def _create_v4_schema(self, *, advance_schema_version: bool = False) -> None:
        self._reject_creation_artifact_migration_debris()
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS creation_jobs (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL UNIQUE,
                workspace_id TEXT NOT NULL REFERENCES creation_workspaces(workspace_id),
                operation TEXT NOT NULL,
                state TEXT NOT NULL,
                progress TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                record_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS creation_jobs_workspace_idx
                ON creation_jobs(workspace_id, sequence);
            CREATE INDEX IF NOT EXISTS creation_jobs_queue_idx
                ON creation_jobs(state, sequence);

            CREATE TABLE IF NOT EXISTS creation_job_inputs (
                job_id TEXT NOT NULL REFERENCES creation_jobs(job_id) ON DELETE CASCADE,
                position INTEGER NOT NULL,
                artifact_id TEXT NOT NULL,
                subject_format TEXT NOT NULL,
                subject_version INTEGER NOT NULL,
                subject_id TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                PRIMARY KEY (job_id, position),
                UNIQUE (job_id, artifact_id)
            );
            CREATE INDEX IF NOT EXISTS creation_job_inputs_artifact_idx
                ON creation_job_inputs(artifact_id, job_id);

            CREATE TABLE IF NOT EXISTS creation_job_payloads (
                job_id TEXT PRIMARY KEY NOT NULL
                    REFERENCES creation_jobs(job_id) ON DELETE CASCADE,
                document_blob_sha256 TEXT NOT NULL,
                document_size INTEGER NOT NULL,
                blob_dev TEXT NOT NULL,
                blob_ino TEXT NOT NULL,
                subject_format TEXT NOT NULL,
                subject_version INTEGER NOT NULL,
                subject_id TEXT NOT NULL,
                content_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS creation_job_outputs (
                job_id TEXT NOT NULL REFERENCES creation_jobs(job_id) ON DELETE CASCADE,
                position INTEGER NOT NULL,
                artifact_id TEXT NOT NULL,
                subject_format TEXT NOT NULL,
                subject_version INTEGER NOT NULL,
                subject_id TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                PRIMARY KEY (job_id, position),
                UNIQUE (job_id, artifact_id)
            );
            CREATE INDEX IF NOT EXISTS creation_job_outputs_artifact_idx
                ON creation_job_outputs(artifact_id, job_id);

            CREATE TABLE IF NOT EXISTS creation_job_attempts (
                job_id TEXT PRIMARY KEY NOT NULL
                    REFERENCES creation_jobs(job_id) ON DELETE CASCADE,
                phase TEXT NOT NULL,
                journal_name TEXT NOT NULL UNIQUE,
                journal_dev TEXT,
                journal_ino TEXT,
                stage_locator TEXT NOT NULL UNIQUE,
                stage_dev TEXT,
                stage_ino TEXT,
                request_locator TEXT NOT NULL UNIQUE,
                request_sha256 TEXT NOT NULL,
                worker_pid INTEGER,
                worker_identity_json TEXT,
                binary_output_dev TEXT,
                binary_output_ino TEXT,
                generation INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS creation_job_attempts_phase_idx
                ON creation_job_attempts(phase, job_id);

            CREATE TABLE IF NOT EXISTS creation_output_grants (
                grant_id TEXT PRIMARY KEY NOT NULL,
                workspace_id TEXT NOT NULL REFERENCES creation_workspaces(workspace_id),
                kind TEXT NOT NULL,
                state TEXT NOT NULL,
                record_json TEXT NOT NULL,
                absolute_path TEXT NOT NULL,
                parent_dev TEXT NOT NULL,
                parent_ino TEXT NOT NULL,
                normalized_leaf TEXT NOT NULL,
                reserved_job_id TEXT UNIQUE REFERENCES creation_jobs(job_id)
                    DEFERRABLE INITIALLY DEFERRED,
                generation INTEGER NOT NULL DEFAULT 0,
                expected_manifest_hash TEXT,
                expected_tree_hash TEXT,
                published_dev TEXT,
                published_ino TEXT,
                recovery_json TEXT
            );
            CREATE INDEX IF NOT EXISTS creation_output_grants_workspace_idx
                ON creation_output_grants(workspace_id, state, grant_id);
            CREATE INDEX IF NOT EXISTS creation_output_grants_reservation_idx
                ON creation_output_grants(reserved_job_id, state);

            CREATE TABLE IF NOT EXISTS creation_artifacts (
                artifact_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL REFERENCES creation_workspaces(workspace_id),
                lifecycle TEXT NOT NULL,
                subject_format TEXT NOT NULL,
                subject_version INTEGER NOT NULL,
                subject_id TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                roles_json TEXT NOT NULL,
                record_json TEXT NOT NULL,
                document_blob_sha256 TEXT NOT NULL,
                document_size INTEGER NOT NULL,
                blob_dev TEXT NOT NULL,
                blob_ino TEXT NOT NULL,
                producer_job_id TEXT NOT NULL REFERENCES creation_jobs(job_id),
                producer_operation TEXT NOT NULL,
                producer_output_position INTEGER NOT NULL,
                root_generation INTEGER NOT NULL,
                source_revision TEXT NOT NULL,
                workflow_status_hash TEXT,
                input_artifact_snapshot_hash TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                PRIMARY KEY (workspace_id, artifact_id),
                UNIQUE (
                    workspace_id,
                    subject_format,
                    subject_version,
                    subject_id,
                    content_hash
                ),
                UNIQUE (producer_job_id, producer_output_position)
            );
            CREATE INDEX IF NOT EXISTS creation_artifacts_workspace_idx
                ON creation_artifacts(workspace_id, lifecycle, artifact_id);
            CREATE INDEX IF NOT EXISTS creation_artifacts_subject_idx
                ON creation_artifacts(subject_format, subject_version, subject_id, content_hash);

            CREATE TABLE IF NOT EXISTS creation_artifact_dependencies (
                workspace_id TEXT NOT NULL,
                artifact_id TEXT NOT NULL,
                position INTEGER NOT NULL,
                dependency_artifact_id TEXT NOT NULL,
                subject_format TEXT NOT NULL,
                subject_version INTEGER NOT NULL,
                subject_id TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                PRIMARY KEY (workspace_id, artifact_id, position),
                UNIQUE (workspace_id, artifact_id, dependency_artifact_id),
                FOREIGN KEY (workspace_id, artifact_id)
                    REFERENCES creation_artifacts(workspace_id, artifact_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS creation_artifact_dependencies_input_idx
                ON creation_artifact_dependencies(
                    workspace_id, dependency_artifact_id, artifact_id
                );
            """
        )
        self._ensure_creation_job_columns()
        self._ensure_creation_artifact_workspace_scope(
            advance_schema_version=advance_schema_version
        )
        self._verify_creation_v4_relational_shape()

    def _create_v5_schema(self, *, advance_schema_version: bool = False) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("PRAGMA table_info(creation_output_grants)")
        }
        if "expected_archive_sha256" not in columns:
            self.connection.execute(
                "ALTER TABLE creation_output_grants ADD COLUMN expected_archive_sha256 TEXT"
            )
        if "expected_size_bytes" not in columns:
            self.connection.execute(
                "ALTER TABLE creation_output_grants ADD COLUMN expected_size_bytes INTEGER"
            )
        attempt_columns = {
            row["name"]
            for row in self.connection.execute("PRAGMA table_info(creation_job_attempts)")
        }
        if "binary_output_dev" not in attempt_columns:
            self.connection.execute(
                "ALTER TABLE creation_job_attempts ADD COLUMN binary_output_dev TEXT"
            )
        if "binary_output_ino" not in attempt_columns:
            self.connection.execute(
                "ALTER TABLE creation_job_attempts ADD COLUMN binary_output_ino TEXT"
            )
        if advance_schema_version:
            self.connection.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '5')"
            )
        self._verify_creation_v4_relational_shape()

    def _create_v6_schema(self, *, advance_schema_version: bool = False) -> None:
        """Create the private, additive Studio Director authority projections."""
        savepoint = "studio_v6_schema"
        self.connection.execute(f"SAVEPOINT {savepoint}")
        try:
            for statement in _AUTHORITY_V6_DDL:
                self.connection.execute(statement)
            _verify_authenticated_human_decision_v6(self.connection)
            if advance_schema_version:
                self.connection.execute(
                    "INSERT OR REPLACE INTO schema_meta (key, value) "
                    "VALUES ('schema_version', '6')"
                )
            self.connection.execute(f"RELEASE {savepoint}")
        except Exception:
            self.connection.execute(f"ROLLBACK TO {savepoint}")
            self.connection.execute(f"RELEASE {savepoint}")
            raise

    def _ensure_creation_job_columns(self) -> None:
        columns = {
            row["name"] for row in self.connection.execute("PRAGMA table_info(creation_jobs)")
        }
        if "cancel_requested" not in columns:
            self.connection.execute(
                "ALTER TABLE creation_jobs ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0"
            )

    def _ensure_creation_artifact_workspace_scope(
        self,
        *,
        advance_schema_version: bool,
    ) -> None:
        artifact_columns = self.connection.execute(
            "PRAGMA table_info(creation_artifacts)"
        ).fetchall()
        primary_key = {
            row["name"]: int(row["pk"]) for row in artifact_columns if int(row["pk"]) > 0
        }
        dependency_columns = {
            row["name"]
            for row in self.connection.execute("PRAGMA table_info(creation_artifact_dependencies)")
        }
        if primary_key == {"workspace_id": 1, "artifact_id": 2} and (
            "workspace_id" in dependency_columns
        ):
            if advance_schema_version:
                savepoint = "studio_creation_v4_version"
                self.connection.execute(f"SAVEPOINT {savepoint}")
                try:
                    self._execute_creation_artifact_scope_migration_statement(
                        "INSERT OR REPLACE INTO schema_meta (key, value) "
                        "VALUES ('schema_version', '4')"
                    )
                except BaseException as original_error:
                    try:
                        self.connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                        self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
                    except BaseException as rollback_error:
                        raise rollback_error from original_error
                    raise
                else:
                    self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            return
        if primary_key != {"artifact_id": 1} or "workspace_id" in dependency_columns:
            raise StudioError(
                "invalid_state", "Studio creation artifact registry key shape is unsupported"
            )
        statements = (
            """CREATE TABLE creation_artifacts_workspace_scoped (
                artifact_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL REFERENCES creation_workspaces(workspace_id),
                lifecycle TEXT NOT NULL,
                subject_format TEXT NOT NULL,
                subject_version INTEGER NOT NULL,
                subject_id TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                roles_json TEXT NOT NULL,
                record_json TEXT NOT NULL,
                document_blob_sha256 TEXT NOT NULL,
                document_size INTEGER NOT NULL,
                blob_dev TEXT NOT NULL,
                blob_ino TEXT NOT NULL,
                producer_job_id TEXT NOT NULL REFERENCES creation_jobs(job_id),
                producer_operation TEXT NOT NULL,
                producer_output_position INTEGER NOT NULL,
                root_generation INTEGER NOT NULL,
                source_revision TEXT NOT NULL,
                workflow_status_hash TEXT,
                input_artifact_snapshot_hash TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                PRIMARY KEY (workspace_id, artifact_id),
                UNIQUE (
                    workspace_id,
                    subject_format,
                    subject_version,
                    subject_id,
                    content_hash
                ),
                UNIQUE (producer_job_id, producer_output_position)
            )""",
            """INSERT INTO creation_artifacts_workspace_scoped
                (artifact_id, workspace_id, lifecycle, subject_format, subject_version,
                 subject_id, content_hash, roles_json, record_json, document_blob_sha256,
                 document_size, blob_dev, blob_ino, producer_job_id, producer_operation,
                 producer_output_position, root_generation, source_revision,
                 workflow_status_hash, input_artifact_snapshot_hash, generation, created_at)
                SELECT artifact_id, workspace_id, lifecycle, subject_format, subject_version,
                       subject_id, content_hash, roles_json, record_json,
                       document_blob_sha256, document_size, blob_dev, blob_ino,
                       producer_job_id, producer_operation, producer_output_position,
                       root_generation, source_revision, workflow_status_hash,
                       input_artifact_snapshot_hash, generation, created_at
                FROM creation_artifacts""",
            """CREATE TABLE creation_artifact_dependencies_workspace_scoped (
                workspace_id TEXT NOT NULL,
                artifact_id TEXT NOT NULL,
                position INTEGER NOT NULL,
                dependency_artifact_id TEXT NOT NULL,
                subject_format TEXT NOT NULL,
                subject_version INTEGER NOT NULL,
                subject_id TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                PRIMARY KEY (workspace_id, artifact_id, position),
                UNIQUE (workspace_id, artifact_id, dependency_artifact_id),
                FOREIGN KEY (workspace_id, artifact_id)
                    REFERENCES creation_artifacts_workspace_scoped(
                        workspace_id, artifact_id
                    ) ON DELETE CASCADE
            )""",
            """INSERT INTO creation_artifact_dependencies_workspace_scoped
                (workspace_id, artifact_id, position, dependency_artifact_id,
                 subject_format, subject_version, subject_id, content_hash)
                SELECT artifacts.workspace_id, dependencies.artifact_id,
                       dependencies.position, dependencies.dependency_artifact_id,
                       dependencies.subject_format, dependencies.subject_version,
                       dependencies.subject_id, dependencies.content_hash
                FROM creation_artifact_dependencies AS dependencies
                JOIN creation_artifacts AS artifacts
                  ON artifacts.artifact_id = dependencies.artifact_id""",
            "DROP TABLE creation_artifact_dependencies",
            "DROP TABLE creation_artifacts",
            "ALTER TABLE creation_artifacts_workspace_scoped RENAME TO creation_artifacts",
            """ALTER TABLE creation_artifact_dependencies_workspace_scoped
                RENAME TO creation_artifact_dependencies""",
            """CREATE INDEX creation_artifacts_workspace_idx
                ON creation_artifacts(workspace_id, lifecycle, artifact_id)""",
            """CREATE INDEX creation_artifacts_subject_idx
                ON creation_artifacts(
                    subject_format, subject_version, subject_id, content_hash
                )""",
            """CREATE INDEX creation_artifact_dependencies_input_idx
                ON creation_artifact_dependencies(
                    workspace_id, dependency_artifact_id, artifact_id
                )""",
        )
        if advance_schema_version:
            statements = (
                *statements,
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '4')",
            )
        expected_steps = _CREATION_ARTIFACT_SCOPE_MIGRATION_DATA_STEP_COUNT + int(
            advance_schema_version
        )
        if len(statements) != expected_steps:
            raise StudioError("internal_error", "Creation artifact migration plan is invalid")
        savepoint = "studio_creation_artifact_workspace_scope"
        self.connection.execute(f"SAVEPOINT {savepoint}")
        try:
            for index, statement in enumerate(statements, 1):
                self._execute_creation_artifact_scope_migration_statement(statement)
                if index == 4:
                    old_artifacts = self.connection.execute(
                        "SELECT COUNT(*) FROM creation_artifacts"
                    ).fetchone()[0]
                    new_artifacts = self.connection.execute(
                        "SELECT COUNT(*) FROM creation_artifacts_workspace_scoped"
                    ).fetchone()[0]
                    old_dependencies = self.connection.execute(
                        "SELECT COUNT(*) FROM creation_artifact_dependencies"
                    ).fetchone()[0]
                    new_dependencies = self.connection.execute(
                        "SELECT COUNT(*) FROM creation_artifact_dependencies_workspace_scoped"
                    ).fetchone()[0]
                    if (old_artifacts, old_dependencies) != (
                        new_artifacts,
                        new_dependencies,
                    ):
                        raise StudioError(
                            "invalid_state",
                            "Studio creation artifact migration did not preserve every row",
                        )
            self._verify_creation_v4_relational_shape()
        except BaseException as original_error:
            try:
                self.connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            except BaseException as rollback_error:
                raise rollback_error from original_error
            raise
        else:
            self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")

    def _execute_creation_artifact_scope_migration_statement(
        self,
        statement: str,
    ) -> sqlite3.Cursor:
        return self.connection.execute(statement)

    def _reject_creation_artifact_migration_debris(self) -> None:
        rows = self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (?, ?) ORDER BY name",
            tuple(sorted(_CREATION_ARTIFACT_SCOPE_MIGRATION_TABLES)),
        ).fetchall()
        if rows:
            raise StudioError(
                "invalid_state",
                "Studio creation artifact migration debris requires explicit recovery",
            )

    def _verify_creation_v4_relational_shape(self) -> None:
        expected_primary_keys = {
            "creation_jobs": {"sequence": 1},
            "creation_job_inputs": {"job_id": 1, "position": 2},
            "creation_job_payloads": {"job_id": 1},
            "creation_job_outputs": {"job_id": 1, "position": 2},
            "creation_job_attempts": {"job_id": 1},
            "creation_output_grants": {"grant_id": 1},
            "creation_artifacts": {"workspace_id": 1, "artifact_id": 2},
            "creation_artifact_dependencies": {
                "workspace_id": 1,
                "artifact_id": 2,
                "position": 3,
            },
        }

        def index_columns(index_name: str) -> tuple[str, ...]:
            return tuple(
                row["name"]
                for row in self.connection.execute(
                    "SELECT name FROM pragma_index_info(?) ORDER BY seqno",
                    (index_name,),
                )
            )

        def index_shapes(
            table: str,
        ) -> tuple[
            dict[str, tuple[tuple[str, ...], bool, bool]],
            list[tuple[tuple[str, ...], bool, str, bool]],
        ]:
            named: dict[str, tuple[tuple[str, ...], bool, bool]] = {}
            constraints: list[tuple[tuple[str, ...], bool, str, bool]] = []
            for row in self.connection.execute(f"PRAGMA index_list({table})"):
                columns = index_columns(row["name"])
                unique = bool(row["unique"])
                partial = bool(row["partial"])
                origin = str(row["origin"])
                if origin == "c":
                    named[str(row["name"])] = (columns, unique, partial)
                else:
                    constraints.append((columns, unique, origin, partial))
            constraints.sort()
            return named, constraints

        expected_named_indexes = {
            "creation_jobs": {
                "creation_jobs_workspace_idx": (
                    ("workspace_id", "sequence"),
                    False,
                    False,
                ),
                "creation_jobs_queue_idx": (("state", "sequence"), False, False),
            },
            "creation_job_inputs": {
                "creation_job_inputs_artifact_idx": (
                    ("artifact_id", "job_id"),
                    False,
                    False,
                )
            },
            "creation_job_payloads": {},
            "creation_job_outputs": {
                "creation_job_outputs_artifact_idx": (
                    ("artifact_id", "job_id"),
                    False,
                    False,
                )
            },
            "creation_job_attempts": {
                "creation_job_attempts_phase_idx": (
                    ("phase", "job_id"),
                    False,
                    False,
                )
            },
            "creation_output_grants": {
                "creation_output_grants_workspace_idx": (
                    ("workspace_id", "state", "grant_id"),
                    False,
                    False,
                ),
                "creation_output_grants_reservation_idx": (
                    ("reserved_job_id", "state"),
                    False,
                    False,
                ),
            },
            "creation_artifacts": {
                "creation_artifacts_workspace_idx": (
                    ("workspace_id", "lifecycle", "artifact_id"),
                    False,
                    False,
                ),
                "creation_artifacts_subject_idx": (
                    ("subject_format", "subject_version", "subject_id", "content_hash"),
                    False,
                    False,
                ),
            },
            "creation_artifact_dependencies": {
                "creation_artifact_dependencies_input_idx": (
                    ("workspace_id", "dependency_artifact_id", "artifact_id"),
                    False,
                    False,
                )
            },
        }
        expected_constraints = {
            "creation_jobs": [(("job_id",), True, "u", False)],
            "creation_job_inputs": [
                (("job_id", "position"), True, "pk", False),
                (("job_id", "artifact_id"), True, "u", False),
            ],
            "creation_job_payloads": [(("job_id",), True, "pk", False)],
            "creation_job_outputs": [
                (("job_id", "position"), True, "pk", False),
                (("job_id", "artifact_id"), True, "u", False),
            ],
            "creation_job_attempts": [
                (("job_id",), True, "pk", False),
                (("journal_name",), True, "u", False),
                (("stage_locator",), True, "u", False),
                (("request_locator",), True, "u", False),
            ],
            "creation_output_grants": [
                (("grant_id",), True, "pk", False),
                (("reserved_job_id",), True, "u", False),
            ],
            "creation_artifacts": [
                (("workspace_id", "artifact_id"), True, "pk", False),
                (
                    (
                        "workspace_id",
                        "subject_format",
                        "subject_version",
                        "subject_id",
                        "content_hash",
                    ),
                    True,
                    "u",
                    False,
                ),
                (("producer_job_id", "producer_output_position"), True, "u", False),
            ],
            "creation_artifact_dependencies": [
                (("workspace_id", "artifact_id", "position"), True, "pk", False),
                (
                    ("workspace_id", "artifact_id", "dependency_artifact_id"),
                    True,
                    "u",
                    False,
                ),
            ],
        }

        def foreign_key_shapes(table: str) -> list[tuple[object, ...]]:
            grouped: dict[int, list[sqlite3.Row]] = {}
            for row in self.connection.execute(f"PRAGMA foreign_key_list({table})"):
                grouped.setdefault(int(row["id"]), []).append(row)
            shapes: list[tuple[object, ...]] = []
            for rows in grouped.values():
                ordered = sorted(rows, key=lambda item: int(item["seq"]))
                shapes.append(
                    (
                        ordered[0]["table"],
                        tuple(item["from"] for item in ordered),
                        tuple(item["to"] for item in ordered),
                        ordered[0]["on_update"],
                        ordered[0]["on_delete"],
                        ordered[0]["match"],
                    )
                )
            shapes.sort()
            return shapes

        creation_job_fk = [
            (
                "creation_jobs",
                ("job_id",),
                ("job_id",),
                "NO ACTION",
                "CASCADE",
                "NONE",
            )
        ]
        expected_foreign_keys = {
            "creation_jobs": [
                (
                    "creation_workspaces",
                    ("workspace_id",),
                    ("workspace_id",),
                    "NO ACTION",
                    "NO ACTION",
                    "NONE",
                )
            ],
            "creation_job_inputs": creation_job_fk,
            "creation_job_payloads": creation_job_fk,
            "creation_job_outputs": creation_job_fk,
            "creation_job_attempts": creation_job_fk,
            "creation_output_grants": sorted(
                [
                    (
                        "creation_workspaces",
                        ("workspace_id",),
                        ("workspace_id",),
                        "NO ACTION",
                        "NO ACTION",
                        "NONE",
                    ),
                    (
                        "creation_jobs",
                        ("reserved_job_id",),
                        ("job_id",),
                        "NO ACTION",
                        "NO ACTION",
                        "NONE",
                    ),
                ]
            ),
            "creation_artifacts": sorted(
                [
                    (
                        "creation_workspaces",
                        ("workspace_id",),
                        ("workspace_id",),
                        "NO ACTION",
                        "NO ACTION",
                        "NONE",
                    ),
                    (
                        "creation_jobs",
                        ("producer_job_id",),
                        ("job_id",),
                        "NO ACTION",
                        "NO ACTION",
                        "NONE",
                    ),
                ]
            ),
            "creation_artifact_dependencies": [
                (
                    "creation_artifacts",
                    ("workspace_id", "artifact_id"),
                    ("workspace_id", "artifact_id"),
                    "NO ACTION",
                    "CASCADE",
                    "NONE",
                )
            ],
        }
        for table, expected_primary_key in expected_primary_keys.items():
            primary_key = {
                row["name"]: int(row["pk"])
                for row in self.connection.execute(f"PRAGMA table_info({table})")
                if int(row["pk"]) > 0
            }
            named_indexes, constraints = index_shapes(table)
            if (
                primary_key != expected_primary_key
                or named_indexes != expected_named_indexes[table]
                or constraints != sorted(expected_constraints[table])
                or foreign_key_shapes(table) != sorted(expected_foreign_keys[table])
            ):
                raise StudioError("invalid_state", "Studio v4 creation relational shape is invalid")

    def _ensure_creation_changeset_operation_sizes(self) -> None:
        columns = {
            row["name"]
            for row in self.connection.execute("PRAGMA table_info(creation_changeset_operations)")
        }
        added = False
        if "base_size" not in columns:
            self.connection.execute(
                "ALTER TABLE creation_changeset_operations ADD COLUMN base_size INTEGER"
            )
            added = True
        if "proposed_size" not in columns:
            self.connection.execute(
                "ALTER TABLE creation_changeset_operations ADD COLUMN proposed_size INTEGER"
            )
            added = True
        needs_backfill = (
            added
            or self.connection.execute(
                "SELECT 1 FROM creation_changeset_operations "
                "WHERE (base_blob_sha256 IS NOT NULL AND base_size IS NULL) "
                "OR (proposed_blob_sha256 IS NOT NULL AND proposed_size IS NULL) LIMIT 1"
            ).fetchone()
        )
        if not needs_backfill:
            return
        rows = self.connection.execute(
            "SELECT changeset_id, record_json FROM creation_changesets ORDER BY changeset_id"
        ).fetchall()
        for row in rows:
            record = decode_object(row["record_json"], context="creation changeset")
            operations = record.get("operations")
            if not isinstance(operations, list):
                raise StudioError(
                    "invalid_state",
                    "Creation changeset operation sizes cannot be backfilled",
                )
            for operation in operations:
                if not isinstance(operation, dict) or not isinstance(operation.get("path"), str):
                    raise StudioError(
                        "invalid_state",
                        "Creation changeset operation sizes cannot be backfilled",
                    )
                cursor = self.connection.execute(
                    "UPDATE creation_changeset_operations SET base_size = ?, proposed_size = ? "
                    "WHERE changeset_id = ? AND path = ?",
                    (
                        operation.get("expected_base_size"),
                        operation.get("proposed_size"),
                        row["changeset_id"],
                        operation["path"],
                    ),
                )
                if cursor.rowcount != 1:
                    raise StudioError(
                        "invalid_state",
                        "Creation changeset operation sizes cannot be backfilled",
                    )

    def record_creation_event(
        self,
        *,
        workspace_id: str | None,
        topic: str,
        entity_type: str,
        entity_id: str,
        payload: dict[str, Any] | None = None,
        created_at: str | None = None,
    ) -> int:
        timestamp = created_at or utc_now()
        cursor = self.connection.execute(
            "INSERT INTO creation_events "
            "(workspace_id, topic, entity_type, entity_id, payload_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (workspace_id, topic, entity_type, entity_id, encode_json(payload or {}), timestamp),
        )
        return int(cursor.lastrowid)

    def record_event(
        self,
        *,
        workspace_id: str | None,
        topic: str,
        entity_type: str,
        entity_id: str,
        payload: dict[str, Any] | None = None,
        created_at: str | None = None,
    ) -> int:
        timestamp = created_at or utc_now()
        cursor = self.connection.execute(
            "INSERT INTO events "
            "(workspace_id, topic, entity_type, entity_id, payload_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (workspace_id, topic, entity_type, entity_id, encode_json(payload or {}), timestamp),
        )
        return int(cursor.lastrowid)

    def list_events(
        self,
        *,
        workspace_id: str | None = None,
        after_id: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if workspace_id is None:
            rows = self.connection.execute(
                "SELECT * FROM events WHERE event_id > ? ORDER BY event_id LIMIT ?",
                (after_id, limit),
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM events WHERE workspace_id = ? AND event_id > ? "
                "ORDER BY event_id LIMIT ?",
                (workspace_id, after_id, limit),
            ).fetchall()
        return [
            {
                "event_id": int(row["event_id"]),
                "workspace_id": row["workspace_id"],
                "topic": row["topic"],
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "payload": decode_object(row["payload_json"], context="event payload"),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def list_creation_events(
        self,
        *,
        workspace_id: str,
        after_id: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM creation_events WHERE workspace_id = ? AND event_id > ? "
            "ORDER BY event_id LIMIT ?",
            (workspace_id, after_id, limit),
        ).fetchall()
        return [
            {
                "event_id": int(row["event_id"]),
                "workspace_id": row["workspace_id"],
                "topic": row["topic"],
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "payload": decode_object(row["payload_json"], context="creation event payload"),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def _orphan_running_jobs(self) -> None:
        legacy_rows = self.connection.execute(
            "SELECT job_id, workspace_id, record_json FROM jobs WHERE state = 'running'"
        ).fetchall()
        creation_rows = self.connection.execute(
            "SELECT job_id, workspace_id, record_json FROM creation_jobs "
            "WHERE state = 'running' ORDER BY sequence"
        ).fetchall()
        if not legacy_rows and not creation_rows:
            return
        timestamp = utc_now()
        try:
            with self.connection:
                for row in legacy_rows:
                    record = decode_object(row["record_json"], context="job")
                    record["state"] = "orphaned"
                    if record.get("format_version") == 3:
                        record["result"] = None
                        record["error"] = {
                            "code": "recovery_required",
                            "message": (
                                "External job requires explicit retained-evidence recovery"
                            ),
                        }
                    record["updated_at"] = timestamp
                    try:
                        validate_studio_job(record)
                    except StudioContractError as exc:
                        raise StudioError(
                            "internal_error", "Stored running job is invalid"
                        ) from exc
                    self.connection.execute(
                        "UPDATE jobs SET state = 'orphaned', record_json = ? WHERE job_id = ?",
                        (encode_json(record), row["job_id"]),
                    )
                    if record["format_version"] == EXTERNAL_JOB_VERSION:
                        target_grant_id = record["input"]["target_grant_id"]
                        grant_row = self.connection.execute(
                            "SELECT record_json FROM external_grants WHERE grant_id = ? "
                            "AND reserved_job_id = ?",
                            (target_grant_id, row["job_id"]),
                        ).fetchone()
                        if grant_row is None:
                            raise StudioError(
                                "internal_error",
                                "External job target reservation is unavailable",
                            )
                        grant = decode_object(
                            grant_row["record_json"],
                            context="external grant",
                        )
                        grant["state"] = "recovery_required"
                        grant["updated_at"] = timestamp
                        try:
                            validate_studio_external_grant(grant)
                        except StudioContractError as exc:
                            raise StudioError(
                                "internal_error",
                                "Stored external grant is invalid",
                            ) from exc
                        self.connection.execute(
                            "UPDATE external_grants SET state = 'recovery_required', "
                            "record_json = ? WHERE grant_id = ?",
                            (encode_json(grant), target_grant_id),
                        )
                    self.record_event(
                        workspace_id=row["workspace_id"],
                        topic="job.orphaned",
                        entity_type="job",
                        entity_id=row["job_id"],
                        payload={"previous_state": "running", "reason": "service_restart"},
                        created_at=timestamp,
                    )
                for row in creation_rows:
                    record = decode_object(row["record_json"], context="creation job")
                    attempt = self.connection.execute(
                        "SELECT stage_locator, stage_dev, stage_ino, journal_name, "
                        "journal_dev, journal_ino FROM creation_job_attempts WHERE job_id = ?",
                        (row["job_id"],),
                    ).fetchone()
                    recovery_evidence: dict[str, object] = {}
                    if attempt is not None:
                        stage_identity = (
                            None
                            if attempt["stage_dev"] is None or attempt["stage_ino"] is None
                            else (int(attempt["stage_dev"]), int(attempt["stage_ino"]))
                        )
                        journal_identity = (
                            None
                            if attempt["journal_dev"] is None or attempt["journal_ino"] is None
                            else (int(attempt["journal_dev"]), int(attempt["journal_ino"]))
                        )
                        recovery_evidence = retained_recovery_evidence(
                            stage_path=self.creation_jobs_dir / attempt["stage_locator"],
                            stage_identity=stage_identity,
                            journal_path=(self.creation_job_journals_dir / attempt["journal_name"]),
                            journal_identity=journal_identity,
                        )
                    record["state"] = "orphaned"
                    record["progress"] = "orphaned"
                    record["generation"] += 1
                    record["result"] = None
                    record["error"] = {
                        "code": "recovery_required",
                        "message": (
                            "Studio restarted while creation evidence remained under recovery"
                        ),
                        "retryable": True,
                    }
                    if recovery_evidence:
                        record["error"]["recovery_evidence"] = recovery_evidence
                    record["finished_at"] = timestamp
                    record["updated_at"] = timestamp
                    record["record_hash"] = creation_job_record_hash(record)
                    try:
                        validate_studio_creation_job(record)
                    except StudioContractError as exc:
                        raise StudioError(
                            "internal_error", "Stored running creation job is invalid"
                        ) from exc
                    cursor = self.connection.execute(
                        "UPDATE creation_jobs SET state = 'orphaned', progress = 'orphaned', "
                        "generation = ?, record_json = ? WHERE job_id = ? AND state = 'running'",
                        (record["generation"], encode_json(record), row["job_id"]),
                    )
                    if cursor.rowcount != 1:
                        raise StudioError(
                            "conflict", "Running creation job changed during restart recovery"
                        )
                    if record["format_version"] in {3, 5, 6, 7, 8, 9}:
                        grant_row = self.connection.execute(
                            "SELECT grant_id, record_json, recovery_json FROM "
                            "creation_output_grants WHERE reserved_job_id = ?",
                            (row["job_id"],),
                        ).fetchone()
                        if grant_row is None:
                            raise StudioError(
                                "internal_error",
                                "Creation output grant reservation is unavailable",
                            )
                        if grant_row["recovery_json"] is not None:
                            grant = decode_object(
                                grant_row["record_json"],
                                context="creation output grant",
                            )
                            if grant["state"] == "reserved":
                                grant["state"] = "recovery_required"
                                grant["generation"] += 1
                                grant["updated_at"] = timestamp
                                try:
                                    validate_studio_creation_output_grant_v6(grant)
                                except StudioContractError as exc:
                                    raise StudioError(
                                        "internal_error",
                                        "Stored creation output grant is invalid",
                                    ) from exc
                                self.connection.execute(
                                    "UPDATE creation_output_grants SET state = "
                                    "'recovery_required', generation = ?, record_json = ? "
                                    "WHERE grant_id = ? AND state = 'reserved'",
                                    (
                                        grant["generation"],
                                        encode_json(grant),
                                        grant_row["grant_id"],
                                    ),
                                )
                    self.record_creation_event(
                        workspace_id=row["workspace_id"],
                        topic="creation_job.orphaned",
                        entity_type="creation_job",
                        entity_id=row["job_id"],
                        payload={
                            "previous_state": "running",
                            "reason": "service_restart",
                            "generation": record["generation"],
                        },
                        created_at=timestamp,
                    )
        except sqlite3.Error as exc:
            raise StudioError(
                "internal_error", f"Could not recover running Studio jobs: {exc}"
            ) from exc

    def _reap_registered_creation_workers(self) -> None:
        try:
            rows = self.connection.execute(
                "SELECT job_id, worker_pid, worker_identity_json "
                "FROM creation_job_attempts WHERE worker_pid IS NOT NULL "
                "OR worker_identity_json IS NOT NULL ORDER BY job_id"
            ).fetchall()
            for row in rows:
                if row["worker_pid"] is None or row["worker_identity_json"] is None:
                    raise StudioError(
                        "invalid_state", "Stored creation worker identity is incomplete"
                    )
                identity = decode_object(
                    row["worker_identity_json"],
                    context="creation worker process identity",
                )
                terminate_registered_creation_process(int(row["worker_pid"]), identity)
            if rows:
                with self.connection:
                    for row in rows:
                        cursor = self.connection.execute(
                            "UPDATE creation_job_attempts SET worker_pid = NULL, "
                            "worker_identity_json = NULL WHERE job_id = ? "
                            "AND worker_pid = ? AND worker_identity_json = ?",
                            (
                                row["job_id"],
                                row["worker_pid"],
                                row["worker_identity_json"],
                            ),
                        )
                        if cursor.rowcount != 1:
                            raise StudioError(
                                "conflict", "Stored creation worker identity changed during reap"
                            )
        except StudioError:
            raise
        except (CreationProcessError, sqlite3.Error, TypeError, ValueError) as exc:
            raise StudioError(
                "invalid_state", "Stored creation worker could not be reaped safely"
            ) from exc
