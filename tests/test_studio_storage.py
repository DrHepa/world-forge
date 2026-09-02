from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from worldforge.studio import storage as storage_module
from worldforge.studio.director_control import StudioDirectorControl
from worldforge.studio.errors import StudioError
from worldforge.studio.jobs import JobManager
from worldforge.studio.storage import (
    SCHEMA_VERSION,
    StudioStore,
    _verify_ollama_v2_authorization_v8,
    encode_json,
)

_PRIVATE_EVENTS = "studio_authenticated_human_decision_events"
_PRIVATE_APPROVAL_INDEX = "studio_authenticated_human_decision_events_approval_idx"
_PRIVATE_APPROVAL_INDEX_SQL = (
    f"CREATE INDEX {_PRIVATE_APPROVAL_INDEX} "
    f"ON {_PRIVATE_EVENTS}(approval_id, event_id)"
)


class _SchemaCrash(BaseException):
    pass


class _AuthorizationPragmaMutationConnection:
    def __init__(
        self,
        connection: sqlite3.Connection,
        target: str,
        replacement: tuple[tuple[object, ...], ...],
    ) -> None:
        self._connection = connection
        self._target = target
        self._replacement = replacement

    def execute(self, sql: str, *args: object):
        if sql == self._target:
            return self._replacement
        return self._connection.execute(sql, *args)


def _replace_private_table_sql(
    data_dir: Path,
    table: str,
    old: str,
    new: str,
) -> None:
    with sqlite3.connect(data_dir / "studio.sqlite3") as connection:
        sql = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()[0]
        if old not in sql:
            raise AssertionError(f"private schema mutation source missing: {old}")
        connection.execute(f"DROP TABLE {table}")
        connection.execute(sql.replace(old, new, 1))
        if table == _PRIVATE_EVENTS:
            connection.execute(_PRIVATE_APPROVAL_INDEX_SQL)


def _replace_private_approval_index(data_dir: Path, sql: str | None) -> None:
    with sqlite3.connect(data_dir / "studio.sqlite3") as connection:
        connection.execute(f"DROP INDEX {_PRIVATE_APPROVAL_INDEX}")
        if sql is not None:
            connection.execute(sql)


def _add_private_prefixed_object(data_dir: Path, sql: str) -> None:
    with sqlite3.connect(data_dir / "studio.sqlite3") as connection:
        connection.execute(sql)


def _schema_open_result(data_dir: Path, mode: str) -> tuple[str, str]:
    opened: StudioStore | None = None
    try:
        opened = StudioStore(data_dir, mode=mode)  # type: ignore[arg-type]
    except StudioError as exc:
        return (exc.code, exc.message)
    finally:
        if opened is not None:
            opened.close()
    return ("accepted", "")


def _create_genuine_v5_store(data_dir: Path) -> None:
    with (
        mock.patch.object(
            StudioStore, "_create_v6_schema", autospec=True, return_value=None
        ),
        mock.patch.object(
            StudioStore, "_create_v7_schema", autospec=True, return_value=None
        ),
        mock.patch.object(
            StudioStore, "_create_v8_schema", autospec=True, return_value=None
        ),
        mock.patch(
            "worldforge.studio.storage._verify_authenticated_human_decision_v6",
            return_value=None,
        ),
        mock.patch(
            "worldforge.studio.storage._verify_ollama_v2_authorization_v7",
            return_value=None,
        ),
        mock.patch(
            "worldforge.studio.storage._verify_ollama_v2_authorization_v8",
            return_value=None,
        ),
    ):
        with StudioStore(data_dir) as store:
            version = store.connection.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()[0]
            tables = {
                row[0]
                for row in store.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
    if version != "5" or tables & {
        "studio_authenticated_human_credentials",
        "studio_authenticated_human_decisions",
        "studio_authenticated_human_decision_events",
    }:
        raise AssertionError("fixture is not an exact pre-v6 StudioStore")


def _create_genuine_v6_store(data_dir: Path) -> None:
    with StudioStore(data_dir):
        pass
    with sqlite3.connect(data_dir / "studio.sqlite3") as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("DROP TABLE studio_ollama_v2_authorization_outcomes")
        connection.execute("DROP TABLE studio_ollama_v2_authorization_consumptions")
        connection.execute("DROP TABLE studio_ollama_v2_authorization_events")
        connection.execute("DROP TABLE studio_ollama_v2_authorization_decisions")
        connection.execute(
            "UPDATE schema_meta SET value='6' WHERE key='schema_version'"
        )


def _create_genuine_v7_store(data_dir: Path) -> None:
    with (
        mock.patch.object(
            StudioStore, "_create_v8_schema", autospec=True, return_value=None
        ),
        mock.patch(
            "worldforge.studio.storage._verify_ollama_v2_authorization_v8",
            return_value=None,
        ),
    ):
        with StudioStore(data_dir):
            pass
    with sqlite3.connect(data_dir / "studio.sqlite3") as connection:
        version = connection.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()[0]
        outcome = connection.execute(
            "SELECT name FROM sqlite_schema "
            "WHERE name='studio_ollama_v2_authorization_outcomes'"
        ).fetchone()
    if version != "7" or outcome is not None:
        raise AssertionError("fixture is not an exact schema-v7 StudioStore")


def _create_data_bearing_v7_store(data_dir: Path) -> dict[str, tuple[object, ...]]:
    with StudioStore(data_dir) as store:
        control = StudioDirectorControl(store)
        control.enroll(passphrase="correct horse battery staple")
        control.close()
    values: dict[str, tuple[object, ...]] = {
        "decision": (
            "mandate-migrated",
            "director_local",
            "operation-migrated",
            "apply",
            "p" * 64,
            None,
            "s" * 64,
            "r" * 64,
            '{"legacy":"review"}',
            "d" * 64,
            '{"legacy":"decision"}',
            "approved",
            1,
            1,
            1,
            "e" * 64,
            "2026-09-02T12:00:00.000000Z",
        ),
        "event": (
            1,
            "director_local",
            "mandate-migrated",
            1,
            "consumed",
            0,
            '{"legacy":"event"}',
            "e" * 64,
            "0" * 64,
            b"m" * 32,
            "2026-09-02T12:00:00.000000Z",
        ),
        "consumption": (
            "consumption-migrated",
            "mandate-migrated",
            0,
            "effect-migrated",
            "f" * 64,
            "authorization-migrated",
            "q" * 64,
            '{"legacy":"request"}',
            "c" * 64,
            '{"legacy":"consumption"}',
            "e" * 64,
            "2026-09-02T12:00:00.000000Z",
        ),
    }
    with sqlite3.connect(data_dir / "studio.sqlite3") as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        for table in (
            "studio_ollama_v2_authorization_outcomes",
            "studio_ollama_v2_authorization_consumptions",
            "studio_ollama_v2_authorization_events",
            "studio_ollama_v2_authorization_decisions",
        ):
            connection.execute(f"DROP TABLE {table}")
        for statement in storage_module._OLLAMA_AUTH_V7_DDL:  # noqa: SLF001
            connection.execute(statement)
        connection.execute(
            "INSERT INTO studio_ollama_v2_authorization_decisions VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            values["decision"],
        )
        connection.execute(
            "INSERT INTO studio_ollama_v2_authorization_events VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            values["event"],
        )
        connection.execute(
            "INSERT INTO studio_ollama_v2_authorization_consumptions VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            values["consumption"],
        )
        connection.execute("UPDATE schema_meta SET value='7' WHERE key='schema_version'")
    return values


def _authorization_schema_fingerprint(connection: sqlite3.Connection):
    return connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema "
        "WHERE name LIKE 'studio_ollama_v2_authorization_%' "
        "OR tbl_name LIKE 'studio_ollama_v2_authorization_%' "
        "ORDER BY type, name, tbl_name"
    ).fetchall()


class StudioStorageTests(unittest.TestCase):
    def test_v8_verifier_rejects_exact_xinfo_and_autoindex_shape_drift(self) -> None:
        cases = (
            (
                'PRAGMA table_xinfo("studio_ollama_v2_authorization_decisions")',
                (
                    (0, "mandate_id", "BLOB", 1, None, 1, 0),
                    (1, "credential_id", "TEXT", 1, None, 0, 0),
                    (2, "operation_id", "TEXT", 1, None, 0, 0),
                    (3, "phase", "TEXT", 1, None, 0, 0),
                    (4, "plan_hash", "TEXT", 1, None, 0, 0),
                    (5, "rollback_plan_hash", "TEXT", 0, None, 0, 0),
                    (6, "starting_snapshot_hash", "TEXT", 1, None, 0, 0),
                    (7, "review_hash", "TEXT", 1, None, 0, 0),
                    (8, "review_json", "TEXT", 1, None, 0, 0),
                    (9, "decision_hash", "TEXT", 0, None, 0, 0),
                    (10, "decision_json", "TEXT", 0, None, 0, 0),
                    (11, "state", "TEXT", 1, None, 0, 0),
                    (12, "generation", "INTEGER", 1, None, 0, 0),
                    (13, "slot_count", "INTEGER", 1, None, 0, 0),
                    (14, "consumed_count", "INTEGER", 1, None, 0, 0),
                    (15, "last_event_hash", "TEXT", 1, None, 0, 0),
                    (16, "updated_at", "TEXT", 1, None, 0, 0),
                ),
            ),
            (
                'PRAGMA index_info("sqlite_autoindex_'
                'studio_ollama_v2_authorization_consumptions_2")',
                ((0, 3, "effect_id"),),
            ),
        )
        with tempfile.TemporaryDirectory() as directory, StudioStore(
            Path(directory) / "studio"
        ) as store:
            for target, replacement in cases:
                with self.subTest(target=target), self.assertRaisesRegex(
                    StudioError,
                    "Ollama v2 authorization database schema is invalid",
                ):
                    _verify_ollama_v2_authorization_v8(
                        _AuthorizationPragmaMutationConnection(
                            store.connection,
                            target,
                            replacement,
                        )
                    )

    def test_schema_v8_adds_exact_ollama_authorization_objects(self) -> None:
        with tempfile.TemporaryDirectory() as directory, StudioStore(
            Path(directory) / "studio"
        ) as store:
            self.assertEqual(8, SCHEMA_VERSION)
            self.assertEqual(
                "8",
                store.connection.execute(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                ).fetchone()[0],
            )
            objects = {
                (row[0], row[1], row[2])
                for row in store.connection.execute(
                    "SELECT type, name, tbl_name FROM sqlite_schema "
                    "WHERE name LIKE 'studio_ollama_v2_authorization_%'"
                )
            }
            self.assertEqual(
                {
                    (
                        "table",
                        "studio_ollama_v2_authorization_decisions",
                        "studio_ollama_v2_authorization_decisions",
                    ),
                    (
                        "table",
                        "studio_ollama_v2_authorization_consumptions",
                        "studio_ollama_v2_authorization_consumptions",
                    ),
                    (
                        "table",
                        "studio_ollama_v2_authorization_events",
                        "studio_ollama_v2_authorization_events",
                    ),
                    (
                        "index",
                        "studio_ollama_v2_authorization_events_mandate_idx",
                        "studio_ollama_v2_authorization_events",
                    ),
                    (
                        "table",
                        "studio_ollama_v2_authorization_outcomes",
                        "studio_ollama_v2_authorization_outcomes",
                    ),
                },
                objects,
            )
            _verify_ollama_v2_authorization_v8(store.connection)

    def test_primary_migrates_exact_v7_to_v8_and_secondary_refuses_v7(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            _create_genuine_v7_store(data_dir)
            with self.assertRaisesRegex(StudioError, "requires schema version 8"):
                StudioStore(data_dir, mode="secondary")
            with StudioStore(data_dir) as migrated:
                self.assertEqual(
                    "8",
                    migrated.connection.execute(
                        "SELECT value FROM schema_meta WHERE key='schema_version'"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    1,
                    migrated.connection.execute(
                        "SELECT count(*) FROM sqlite_schema "
                        "WHERE type='table' AND "
                        "name='studio_ollama_v2_authorization_outcomes'"
                    ).fetchone()[0],
                )
            with StudioStore(data_dir, mode="secondary"):
                pass

    def test_v7_to_v8_preserves_rows_backfills_bijection_and_matches_fresh_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "migrated"
            fresh_dir = Path(directory) / "fresh"
            values = _create_data_bearing_v7_store(data_dir)
            with self.assertRaisesRegex(StudioError, "requires schema version 8"):
                StudioStore(data_dir, mode="secondary")
            with StudioStore(data_dir) as migrated, StudioStore(fresh_dir) as fresh:
                self.assertEqual(
                    values["decision"],
                    tuple(
                        migrated.connection.execute(
                            "SELECT * FROM studio_ollama_v2_authorization_decisions"
                        ).fetchone()
                    ),
                )
                self.assertEqual(
                    values["event"],
                    tuple(
                        migrated.connection.execute(
                            "SELECT * FROM studio_ollama_v2_authorization_events"
                        ).fetchone()
                    ),
                )
                self.assertEqual(
                    values["consumption"],
                    tuple(
                        migrated.connection.execute(
                            "SELECT * FROM studio_ollama_v2_authorization_consumptions"
                        ).fetchone()
                    ),
                )
                outcome = migrated.connection.execute(
                    "SELECT * FROM studio_ollama_v2_authorization_outcomes"
                ).fetchone()
                self.assertEqual(
                    (
                        "consumption-migrated",
                        "mandate-migrated",
                        "consumed",
                        0,
                        "effect-migrated",
                        "f" * 64,
                        "authorization-migrated",
                        "q" * 64,
                        '{"legacy":"request"}',
                        "c" * 64,
                        '{"legacy":"consumption"}',
                        1,
                        "e" * 64,
                        "consumption-migrated",
                        "2026-09-02T12:00:00.000000Z",
                    ),
                    tuple(outcome),
                )
                self.assertEqual(
                    _authorization_schema_fingerprint(fresh.connection),
                    _authorization_schema_fingerprint(migrated.connection),
                )
                _verify_ollama_v2_authorization_v8(migrated.connection)

    def test_v7_to_v8_exception_and_baseexception_restore_exact_data_bearing_v7(self) -> None:
        for failure in (
            sqlite3.OperationalError("simulated v8 verification failure"),
            _SchemaCrash("simulated v8 interruption"),
        ):
            with (
                self.subTest(failure=type(failure).__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                data_dir = Path(directory) / "studio"
                values = _create_data_bearing_v7_store(data_dir)
                with sqlite3.connect(data_dir / "studio.sqlite3") as before_connection:
                    before = _authorization_schema_fingerprint(before_connection)
                with mock.patch(
                    "worldforge.studio.storage._verify_ollama_v2_authorization_v8",
                    side_effect=failure,
                ):
                    expected = StudioError if isinstance(failure, Exception) else _SchemaCrash
                    with self.assertRaises(expected):
                        StudioStore(data_dir)
                with sqlite3.connect(data_dir / "studio.sqlite3") as connection:
                    self.assertEqual(
                        "7",
                        connection.execute(
                            "SELECT value FROM schema_meta WHERE key='schema_version'"
                        ).fetchone()[0],
                    )
                    self.assertEqual(before, _authorization_schema_fingerprint(connection))
                    self.assertEqual(
                        values["decision"],
                        tuple(
                            connection.execute(
                                "SELECT * FROM studio_ollama_v2_authorization_decisions"
                            ).fetchone()
                        ),
                    )
                    self.assertEqual(
                        values["event"],
                        tuple(
                            connection.execute(
                                "SELECT * FROM studio_ollama_v2_authorization_events"
                            ).fetchone()
                        ),
                    )
                    self.assertEqual(
                        values["consumption"],
                        tuple(
                            connection.execute(
                                "SELECT * FROM studio_ollama_v2_authorization_consumptions"
                            ).fetchone()
                        ),
                    )

    def test_primary_migrates_exact_v6_to_v8_and_secondary_never_migrates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            _create_genuine_v6_store(data_dir)
            with self.assertRaisesRegex(StudioError, "requires schema version 8"):
                StudioStore(data_dir, mode="secondary")
            with StudioStore(data_dir) as migrated:
                self.assertEqual(
                    "8",
                    migrated.connection.execute(
                        "SELECT value FROM schema_meta WHERE key='schema_version'"
                    ).fetchone()[0],
                )
            with StudioStore(data_dir, mode="secondary"):
                pass

    def test_v6_to_v7_failure_at_every_ddl_boundary_restores_exact_v6(self) -> None:
        boundaries = (
            (sqlite3.SQLITE_CREATE_TABLE, "studio_ollama_v2_authorization_decisions"),
            (sqlite3.SQLITE_CREATE_TABLE, "studio_ollama_v2_authorization_consumptions"),
            (sqlite3.SQLITE_CREATE_TABLE, "studio_ollama_v2_authorization_events"),
            (sqlite3.SQLITE_CREATE_INDEX, "studio_ollama_v2_authorization_events_mandate_idx"),
            (sqlite3.SQLITE_INSERT, "schema_meta"),
        )
        original = StudioStore._create_v7_schema
        for action, object_name in boundaries:
            with self.subTest(object_name=object_name), tempfile.TemporaryDirectory() as directory:
                data_dir = Path(directory) / "studio"
                _create_genuine_v6_store(data_dir)

                def fail(store, *, advance_schema_version=False, _action=action, _name=object_name):
                    def authorizer(observed, first, _second, _database, _trigger):
                        return (
                            sqlite3.SQLITE_DENY
                            if observed == _action and first == _name
                            else sqlite3.SQLITE_OK
                        )
                    store.connection.set_authorizer(authorizer)
                    try:
                        original(store, advance_schema_version=advance_schema_version)
                    finally:
                        store.connection.set_authorizer(None)

                with mock.patch.object(
                    StudioStore, "_create_v7_schema", autospec=True, side_effect=fail
                ):
                    with self.assertRaises(StudioError):
                        StudioStore(data_dir)
                with sqlite3.connect(data_dir / "studio.sqlite3") as connection:
                    self.assertEqual(
                        "6",
                        connection.execute(
                            "SELECT value FROM schema_meta WHERE key='schema_version'"
                        ).fetchone()[0],
                    )
                    self.assertEqual(
                        [],
                        connection.execute(
                            "SELECT name FROM sqlite_schema "
                            "WHERE name LIKE 'studio_ollama_v2_authorization_%'"
                        ).fetchall(),
                    )

    def test_v6_to_v7_baseexception_after_ddl_restores_exact_v6(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            _create_genuine_v6_store(data_dir)
            with mock.patch(
                "worldforge.studio.storage._verify_ollama_v2_authorization_v7",
                side_effect=_SchemaCrash("simulated interruption"),
            ):
                with self.assertRaises(_SchemaCrash):
                    StudioStore(data_dir)
            with sqlite3.connect(data_dir / "studio.sqlite3") as connection:
                self.assertEqual(
                    "6",
                    connection.execute(
                        "SELECT value FROM schema_meta WHERE key='schema_version'"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    [],
                    connection.execute(
                        "SELECT name FROM sqlite_schema "
                        "WHERE name LIKE 'studio_ollama_v2_authorization_%'"
                    ).fetchall(),
                )

    def test_primary_and_secondary_reject_casefold_v7_debris(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            with StudioStore(data_dir):
                pass
            with sqlite3.connect(data_dir / "studio.sqlite3") as connection:
                connection.execute(
                    "CREATE TABLE Studio_Ollama_V2_Authorization_Debris(value TEXT)"
                )
            for mode in ("primary", "secondary"):
                with self.subTest(mode=mode), self.assertRaisesRegex(
                    StudioError, "Ollama v2 authorization database schema is invalid"
                ):
                    StudioStore(data_dir, mode=mode)

    def test_creates_hardened_schema_and_rejects_future_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            with StudioStore(data_dir) as store:
                tables = {
                    row[0]
                    for row in store.connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                self.assertTrue(
                    {"schema_meta", "workspaces", "changesets", "jobs", "events"} <= tables
                )
                self.assertEqual(1, store.connection.execute("PRAGMA foreign_keys").fetchone()[0])
                self.assertEqual(2, store.connection.execute("PRAGMA synchronous").fetchone()[0])
                self.assertEqual(
                    "wal", store.connection.execute("PRAGMA journal_mode").fetchone()[0]
                )

            connection = sqlite3.connect(data_dir / "studio.sqlite3")
            connection.execute("UPDATE schema_meta SET value = '999' WHERE key = 'schema_version'")
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(StudioError, "newer schema"):
                StudioStore(data_dir)

    def test_primary_and_secondary_reject_exact_private_v6_schema_drift_matrix(
        self,
    ) -> None:
        credentials = "studio_authenticated_human_credentials"
        decisions = "studio_authenticated_human_decisions"
        events = _PRIVATE_EVENTS
        table_cases = (
            (
                "credentials_pk",
                credentials,
                "credential_id TEXT PRIMARY KEY NOT NULL",
                "credential_id TEXT NOT NULL",
            ),
            (
                "credential_id_check",
                credentials,
                "CHECK (credential_id = 'director_local')",
                "CHECK (credential_id <> '')",
            ),
            (
                "kdf_name_check",
                credentials,
                "CHECK (kdf_name = 'scrypt')",
                "CHECK (kdf_name <> '')",
            ),
            (
                "kdf_n_check",
                credentials,
                "CHECK (kdf_n = 32768)",
                "CHECK (kdf_n > 0)",
            ),
            (
                "kdf_r_check",
                credentials,
                "CHECK (kdf_r = 8)",
                "CHECK (kdf_r > 0)",
            ),
            (
                "kdf_p_check",
                credentials,
                "CHECK (kdf_p = 1)",
                "CHECK (kdf_p > 0)",
            ),
            (
                "kdf_dklen_check",
                credentials,
                "CHECK (kdf_dklen = 32)",
                "CHECK (kdf_dklen > 0)",
            ),
            (
                "kdf_maxmem_check",
                credentials,
                "CHECK (kdf_maxmem = 67108864)",
                "CHECK (kdf_maxmem > 0)",
            ),
            (
                "salt_length_check",
                credentials,
                "CHECK (length(salt) = 32)",
                "CHECK (length(salt) > 0)",
            ),
            (
                "verifier_length_check",
                credentials,
                "CHECK (length(verifier) = 32)",
                "CHECK (length(verifier) > 0)",
            ),
            (
                "decisions_pk",
                decisions,
                "approval_id TEXT PRIMARY KEY NOT NULL",
                "approval_id TEXT NOT NULL",
            ),
            (
                "decision_state_check",
                decisions,
                "CHECK (state IN ('prepared', 'approved', 'denied', 'revoked'))",
                "CHECK (state <> '')",
            ),
            (
                "decision_generation_check",
                decisions,
                "CHECK (generation IN (0, 1, 2))",
                "CHECK (generation >= 0)",
            ),
            (
                "decision_projection_check",
                decisions,
                "generation = 2 AND state = 'revoked'",
                "generation = 2 AND state = 'denied'",
            ),
            (
                "events_pk_autoincrement",
                events,
                "event_id INTEGER PRIMARY KEY AUTOINCREMENT",
                "event_id INTEGER",
            ),
            (
                "event_content_hash_unique",
                events,
                "content_hash TEXT NOT NULL UNIQUE",
                "content_hash TEXT NOT NULL",
            ),
            (
                "event_generation_check",
                events,
                "CHECK (generation IN (0, 1, 2))",
                "CHECK (generation >= 0)",
            ),
            (
                "event_type_check",
                events,
                "CHECK (event_type IN ('prepared', 'decided', 'revoked'))",
                "CHECK (event_type <> '')",
            ),
            (
                "event_mac_check",
                events,
                "CHECK (length(mac) = 32)",
                "CHECK (length(mac) > 0)",
            ),
            (
                "credential_fk_target",
                events,
                "REFERENCES studio_authenticated_human_credentials(credential_id)",
                "REFERENCES studio_authenticated_human_decisions(approval_id)",
            ),
            (
                "credential_fk_action",
                events,
                "REFERENCES studio_authenticated_human_credentials(credential_id)",
                "REFERENCES studio_authenticated_human_credentials(credential_id) "
                "ON DELETE CASCADE",
            ),
            (
                "credential_fk_deferred",
                events,
                "REFERENCES studio_authenticated_human_credentials(credential_id)",
                "REFERENCES studio_authenticated_human_credentials(credential_id) "
                "DEFERRABLE INITIALLY DEFERRED",
            ),
            (
                "approval_fk_target",
                events,
                "REFERENCES studio_authenticated_human_decisions(approval_id)",
                "REFERENCES studio_authenticated_human_credentials(credential_id)",
            ),
            (
                "approval_fk_action",
                events,
                "REFERENCES studio_authenticated_human_decisions(approval_id)",
                "REFERENCES studio_authenticated_human_decisions(approval_id) "
                "ON UPDATE CASCADE",
            ),
            (
                "approval_fk_not_deferred",
                events,
                "DEFERRABLE INITIALLY DEFERRED",
                "NOT DEFERRABLE INITIALLY IMMEDIATE",
            ),
            (
                "approval_fk_initially_immediate",
                events,
                "INITIALLY DEFERRED",
                "INITIALLY IMMEDIATE",
            ),
            (
                "column_order",
                credentials,
                "kdf_n INTEGER NOT NULL CHECK (kdf_n = 32768),\n"
                "    kdf_r INTEGER NOT NULL CHECK (kdf_r = 8),",
                "kdf_r INTEGER NOT NULL CHECK (kdf_r = 8),\n"
                "    kdf_n INTEGER NOT NULL CHECK (kdf_n = 32768),",
            ),
            (
                "column_name",
                credentials,
                "created_at TEXT NOT NULL",
                "created_on TEXT NOT NULL",
            ),
            (
                "column_type",
                credentials,
                "salt BLOB NOT NULL",
                "salt TEXT NOT NULL",
            ),
            (
                "column_notnull",
                credentials,
                "created_at TEXT NOT NULL",
                "created_at TEXT",
            ),
            (
                "column_default",
                credentials,
                "created_at TEXT NOT NULL",
                "created_at TEXT NOT NULL DEFAULT ''",
            ),
            (
                "column_hidden",
                credentials,
                "created_at TEXT NOT NULL",
                "hidden_probe TEXT GENERATED ALWAYS AS ('x') VIRTUAL,\n"
                "                created_at TEXT NOT NULL",
            ),
            (
                "column_extra",
                credentials,
                "created_at TEXT NOT NULL",
                "extra_probe TEXT,\n                created_at TEXT NOT NULL",
            ),
        )
        index_cases = (
            ("approval_index_missing", None),
            (
                "approval_index_reversed",
                f"CREATE INDEX {_PRIVATE_APPROVAL_INDEX} "
                f"ON {events}(event_id, approval_id)",
            ),
            (
                "approval_index_extra_column",
                f"CREATE INDEX {_PRIVATE_APPROVAL_INDEX} "
                f"ON {events}(approval_id, event_id, created_at)",
            ),
            (
                "approval_index_unique",
                f"CREATE UNIQUE INDEX {_PRIVATE_APPROVAL_INDEX} "
                f"ON {events}(approval_id, event_id)",
            ),
            (
                "approval_index_partial",
                f"CREATE INDEX {_PRIVATE_APPROVAL_INDEX} "
                f"ON {events}(approval_id, event_id) WHERE generation = 0",
            ),
        )
        extra_object_cases = (
            (
                "extra_table",
                "CREATE TABLE studio_authenticated_human_extra_table (value TEXT)",
            ),
            (
                "extra_index",
                "CREATE INDEX studio_authenticated_human_extra_index "
                "ON studio_authenticated_human_credentials(created_at)",
            ),
            (
                "extra_view",
                "CREATE VIEW studio_authenticated_human_extra_view AS "
                "SELECT credential_id FROM studio_authenticated_human_credentials",
            ),
            (
                "extra_trigger",
                "CREATE TRIGGER studio_authenticated_human_extra_trigger "
                "AFTER INSERT ON studio_authenticated_human_credentials "
                "BEGIN SELECT 1; END",
            ),
        )
        observed: list[tuple[str, str, tuple[str, str]]] = []
        for name, table, old, new in table_cases:
            for mode in ("primary", "secondary"):
                with tempfile.TemporaryDirectory() as directory:
                    data_dir = Path(directory) / "studio"
                    with StudioStore(data_dir):
                        pass
                    _replace_private_table_sql(data_dir, table, old, new)
                    observed.append((name, mode, _schema_open_result(data_dir, mode)))
        for name, sql in index_cases:
            for mode in ("primary", "secondary"):
                with tempfile.TemporaryDirectory() as directory:
                    data_dir = Path(directory) / "studio"
                    with StudioStore(data_dir):
                        pass
                    _replace_private_approval_index(data_dir, sql)
                    observed.append((name, mode, _schema_open_result(data_dir, mode)))
        for name, sql in extra_object_cases:
            for mode in ("primary", "secondary"):
                with tempfile.TemporaryDirectory() as directory:
                    data_dir = Path(directory) / "studio"
                    with StudioStore(data_dir):
                        pass
                    _add_private_prefixed_object(data_dir, sql)
                    observed.append((name, mode, _schema_open_result(data_dir, mode)))

        expected = ("invalid_state", "Authenticated decision database schema is invalid")
        self.assertEqual(
            2 * (len(table_cases) + len(index_cases) + len(extra_object_cases)),
            len(observed),
        )
        self.assertTrue(
            all(result == expected for _name, _mode, result in observed),
            observed,
        )

    def test_primary_and_secondary_reject_mixed_case_authority_prefix_objects(
        self,
    ) -> None:
        objects = (
            (
                "table",
                "CREATE TABLE Studio_Authenticated_Human_extra_table (value TEXT)",
            ),
            (
                "index",
                "CREATE INDEX Studio_Authenticated_Human_extra_index "
                "ON schema_meta(value)",
            ),
            (
                "view",
                "CREATE VIEW Studio_Authenticated_Human_extra_view AS "
                "SELECT value FROM schema_meta",
            ),
            (
                "trigger",
                "CREATE TRIGGER Studio_Authenticated_Human_extra_trigger "
                "AFTER UPDATE ON schema_meta BEGIN SELECT 1; END",
            ),
        )
        observed: list[tuple[str, str, tuple[str, str]]] = []
        for object_type, sql in objects:
            for mode in ("primary", "secondary"):
                with tempfile.TemporaryDirectory() as directory:
                    data_dir = Path(directory) / "studio"
                    with StudioStore(data_dir):
                        pass
                    _add_private_prefixed_object(data_dir, sql)
                    observed.append(
                        (object_type, mode, _schema_open_result(data_dir, mode))
                    )

        expected = ("invalid_state", "Authenticated decision database schema is invalid")
        self.assertEqual(2 * len(objects), len(observed))
        self.assertTrue(
            all(result == expected for _object_type, _mode, result in observed),
            observed,
        )

    def test_private_connection_open_rejects_late_private_schema_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            store = StudioStore(data_dir)
            try:
                _add_private_prefixed_object(
                    data_dir,
                    "CREATE VIEW studio_authenticated_human_extra_view AS "
                    "SELECT credential_id FROM studio_authenticated_human_credentials",
                )
                with self.assertRaisesRegex(StudioError, "schema is invalid"):
                    store._authenticated_human_decision_connection()
            finally:
                store.close()

    def test_ordinary_store_connection_retains_default_thread_affinity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with StudioStore(Path(directory) / "studio") as store:
                store.connection.execute("BEGIN IMMEDIATE")
                store.connection.execute(
                    "UPDATE schema_meta SET value = 'foreign-thread-sentinel' "
                    "WHERE key = 'schema_version'"
                )
                outcome: list[object] = []

                def commit_from_foreign_thread() -> None:
                    try:
                        store.connection.commit()
                    except Exception as exc:
                        outcome.append(exc)
                    else:
                        outcome.append("committed")

                thread = threading.Thread(target=commit_from_foreign_thread)
                thread.start()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(1, len(outcome))
                self.assertIsInstance(outcome[0], sqlite3.ProgrammingError)
                store.connection.rollback()
                self.assertEqual(
                    "8",
                    store.connection.execute(
                        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                    ).fetchone()[0],
                )

    def test_private_connection_open_is_fenced_by_terminal_idempotent_close(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StudioStore(Path(directory) / "studio")
            real_connect = sqlite3.connect
            owner_thread_id = threading.get_ident()
            connect_entered = threading.Event()
            allow_connect = threading.Event()
            owner_close_waiting = threading.Event()
            acquired: list[object] = []

            class ObservedRLock:
                def __init__(self) -> None:
                    self._lock = threading.RLock()

                def __enter__(self) -> ObservedRLock:
                    if threading.get_ident() == owner_thread_id:
                        owner_close_waiting.set()
                    self._lock.acquire()
                    return self

                def __exit__(self, *_args: object) -> None:
                    self._lock.release()

            store._authenticated_human_decision_lock = ObservedRLock()

            def paused_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
                connection = real_connect(*args, **kwargs)
                if kwargs.get("check_same_thread") is False:
                    connect_entered.set()
                    if not allow_connect.wait(timeout=2):
                        connection.close()
                        raise RuntimeError("private connection barrier timed out")
                return connection

            def acquire() -> None:
                try:
                    acquired.append(store._authenticated_human_decision_connection())
                except Exception as exc:
                    acquired.append(exc)

            def release_for_owner_close() -> None:
                if owner_close_waiting.wait(timeout=2):
                    allow_connect.set()

            opener: threading.Thread | None = None
            releaser: threading.Thread | None = None
            try:
                with mock.patch(
                    "worldforge.studio.storage.sqlite3.connect",
                    side_effect=paused_connect,
                ) as connect:
                    opener = threading.Thread(target=acquire)
                    opener.start()
                    self.assertTrue(connect_entered.wait(timeout=2))
                    releaser = threading.Thread(target=release_for_owner_close)
                    releaser.start()
                    store.close()
                    opener.join(timeout=2)
                    releaser.join(timeout=2)
                    self.assertFalse(opener.is_alive())
                    self.assertFalse(releaser.is_alive())
                    self.assertTrue(owner_close_waiting.is_set())
                    self.assertEqual(1, len(acquired))
                    self.assertIsInstance(acquired[0], sqlite3.Connection)
                    with self.assertRaises(sqlite3.ProgrammingError):
                        acquired[0].execute("SELECT 1")  # type: ignore[union-attr]
                    connect_count = connect.call_count
                    with self.assertRaisesRegex(StudioError, "closed"):
                        store._authenticated_human_decision_connection()
                    self.assertEqual(connect_count, connect.call_count)
                    self.assertIsNone(
                        store._authenticated_human_decision_connection_instance
                    )
            finally:
                allow_connect.set()
                if opener is not None:
                    opener.join(timeout=2)
                if releaser is not None:
                    releaser.join(timeout=2)
                store.close()

    def test_foreign_thread_close_rejects_before_terminal_state_or_connection_close(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StudioStore(Path(directory) / "studio")
            private_connection = store._authenticated_human_decision_connection()
            outcome: list[object] = []

            def close_from_foreign_thread() -> None:
                try:
                    store.close()
                except Exception as exc:
                    outcome.append(exc)
                else:
                    outcome.append("closed")

            thread = threading.Thread(target=close_from_foreign_thread)
            thread.start()
            thread.join(timeout=2)
            try:
                self.assertFalse(thread.is_alive())
                self.assertEqual(1, len(outcome))
                self.assertIsInstance(outcome[0], StudioError)
                self.assertRegex(str(outcome[0]), "creator thread")
                self.assertFalse(store._closed)
                self.assertIs(
                    private_connection,
                    store._authenticated_human_decision_connection_instance,
                )
                self.assertEqual(1, store.connection.execute("SELECT 1").fetchone()[0])
                self.assertEqual(1, private_connection.execute("SELECT 1").fetchone()[0])

                store.close()
                store.close()
                self.assertTrue(store._closed)
                self.assertIsNone(
                    store._authenticated_human_decision_connection_instance
                )
                with self.assertRaises(sqlite3.ProgrammingError):
                    store.connection.execute("SELECT 1")
                with self.assertRaises(sqlite3.ProgrammingError):
                    private_connection.execute("SELECT 1")
            finally:
                store.connection.close()

    def test_startup_orphans_running_jobs_and_records_an_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            with StudioStore(data_dir) as store:
                timestamp = "2026-07-22T12:00:00Z"
                workspace = {
                    "format": "rpg-world-forge.forge_workspace",
                    "format_version": 1,
                    "workspace_id": "workspace_01",
                    "forge_root": "/forge",
                    "world_root": "/world",
                    "game_root": None,
                    "bundle_root": None,
                    "created_at": timestamp,
                }
                store.connection.execute(
                    "INSERT INTO workspaces "
                    "(workspace_id, record_json, forge_dev, forge_ino, world_dev, world_ino, "
                    "game_dev, game_ino, bundle_dev, bundle_ino) "
                    "VALUES (?, ?, 1, 1, 2, 2, NULL, NULL, NULL, NULL)",
                    ("workspace_01", encode_json(workspace)),
                )
                job = {
                    "format": "rpg-world-forge.studio_job",
                    "format_version": 1,
                    "job_id": "job_01",
                    "workspace_id": "workspace_01",
                    "operation": "forge.validate",
                    "state": "running",
                    "input": {"profile": "release", "legacy_flags": ["offline"]},
                    "result": {"partial": True},
                    "error": {"legacy": "interrupted"},
                    "created_at": timestamp,
                    "updated_at": timestamp,
                }
                store.connection.execute(
                    "INSERT INTO jobs "
                    "(job_id, workspace_id, state, record_json) VALUES (?, ?, ?, ?)",
                    ("job_01", "workspace_01", "running", encode_json(job)),
                )
                queued = {
                    **job,
                    "job_id": "job_02",
                    "state": "queued",
                    "result": None,
                    "error": None,
                }
                store.connection.execute(
                    "INSERT INTO jobs "
                    "(job_id, workspace_id, state, record_json) VALUES (?, ?, ?, ?)",
                    ("job_02", "workspace_01", "queued", encode_json(queued)),
                )
                managed_name_legacy = {
                    **queued,
                    "job_id": "job_03",
                    "operation": "runtime.headless",
                    "input": {"legacy_command": "headless --old-contract"},
                }
                store.connection.execute(
                    "INSERT INTO jobs "
                    "(job_id, workspace_id, state, record_json) VALUES (?, ?, ?, ?)",
                    ("job_03", "workspace_01", "queued", encode_json(managed_name_legacy)),
                )
                store.connection.commit()

            with StudioStore(data_dir) as reopened:
                row = reopened.connection.execute(
                    "SELECT state, record_json FROM jobs WHERE job_id = 'job_01'"
                ).fetchone()
                self.assertEqual("orphaned", row["state"])
                queued_row = reopened.connection.execute(
                    "SELECT state FROM jobs WHERE job_id = 'job_02'"
                ).fetchone()
                self.assertEqual("queued", queued_row["state"])
                events = reopened.list_events(workspace_id="workspace_01")
                self.assertEqual("job.orphaned", events[0]["topic"])
                jobs = JobManager(reopened)
                self.assertEqual("forge.validate", jobs.get("job_01")["operation"])
                self.assertEqual(
                    {"legacy_command": "headless --old-contract"},
                    jobs.get("job_03")["input"],
                )
                self.assertEqual({"job_01", "job_02", "job_03"}, {j["job_id"] for j in jobs.list()})
                self.assertEqual("canceled", jobs.cancel("job_01")["state"])
                self.assertEqual("canceled", jobs.cancel("job_03")["state"])

    def test_secondary_store_never_migrates_or_orphans_primary_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            with StudioStore(data_dir) as store:
                timestamp = "2026-07-22T12:00:00Z"
                workspace = {
                    "format": "rpg-world-forge.forge_workspace",
                    "format_version": 1,
                    "workspace_id": "workspace_01",
                    "forge_root": "/forge",
                    "world_root": "/world",
                    "game_root": None,
                    "bundle_root": None,
                    "created_at": timestamp,
                }
                store.connection.execute(
                    "INSERT INTO workspaces "
                    "(workspace_id, record_json, forge_dev, forge_ino, world_dev, world_ino, "
                    "game_dev, game_ino, bundle_dev, bundle_ino) "
                    "VALUES (?, ?, 1, 1, 2, 2, NULL, NULL, NULL, NULL)",
                    ("workspace_01", encode_json(workspace)),
                )
                job = {
                    "format": "rpg-world-forge.studio_job",
                    "format_version": 1,
                    "job_id": "job_01",
                    "workspace_id": "workspace_01",
                    "operation": "forge.validate",
                    "state": "running",
                    "input": {"profile": "release"},
                    "result": None,
                    "error": None,
                    "created_at": timestamp,
                    "updated_at": timestamp,
                }
                store.connection.execute(
                    "INSERT INTO jobs "
                    "(job_id, workspace_id, state, record_json) VALUES (?, ?, ?, ?)",
                    ("job_01", "workspace_01", "running", encode_json(job)),
                )
                store.connection.commit()

            with StudioStore(data_dir, mode="secondary") as secondary:
                row = secondary.connection.execute(
                    "SELECT state FROM jobs WHERE job_id = 'job_01'"
                ).fetchone()
                self.assertEqual("running", row["state"])
                self.assertEqual([], secondary.list_events(workspace_id="workspace_01"))

            missing = Path(directory) / "missing"
            with self.assertRaisesRegex(StudioError, "does not exist"):
                StudioStore(missing, mode="secondary")

    def test_primary_migrates_v5_through_v8_but_secondary_refuses_to_migrate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "studio"
            _create_genuine_v5_store(data_dir)

            with self.assertRaisesRegex(StudioError, "requires schema version 8"):
                StudioStore(data_dir, mode="secondary")

            with StudioStore(data_dir) as migrated:
                self.assertEqual(
                    "8",
                    migrated.connection.execute(
                        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                    ).fetchone()[0],
                )
                tables = {
                    row[0]
                    for row in migrated.connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                self.assertTrue(
                    {
                        "studio_authenticated_human_credentials",
                        "studio_authenticated_human_decisions",
                        "studio_authenticated_human_decision_events",
                        "studio_ollama_v2_authorization_decisions",
                        "studio_ollama_v2_authorization_consumptions",
                        "studio_ollama_v2_authorization_events",
                        "studio_ollama_v2_authorization_outcomes",
                    }
                    <= tables
                )

    def test_v5_to_v6_failure_at_every_ddl_boundary_rolls_back_all_objects(self) -> None:
        boundaries = (
            (
                "credential_table",
                sqlite3.SQLITE_CREATE_TABLE,
                "studio_authenticated_human_credentials",
            ),
            (
                "projection_table",
                sqlite3.SQLITE_CREATE_TABLE,
                "studio_authenticated_human_decisions",
            ),
            (
                "event_table",
                sqlite3.SQLITE_CREATE_TABLE,
                "studio_authenticated_human_decision_events",
            ),
            (
                "approval_index",
                sqlite3.SQLITE_CREATE_INDEX,
                "studio_authenticated_human_decision_events_approval_idx",
            ),
            ("schema_version", sqlite3.SQLITE_INSERT, "schema_meta"),
        )
        original_create_v6 = StudioStore._create_v6_schema
        for name, denied_action, denied_object in boundaries:
            with self.subTest(boundary=name), tempfile.TemporaryDirectory() as directory:
                data_dir = Path(directory) / "studio"
                _create_genuine_v5_store(data_dir)

                def fail_at_boundary(
                    store: StudioStore,
                    *,
                    advance_schema_version: bool = False,
                    _denied_action: int = denied_action,
                    _denied_object: str = denied_object,
                ) -> None:
                    def authorizer(
                        action: int,
                        first_argument: str | None,
                        _second_argument: str | None,
                        _database: str | None,
                        _trigger: str | None,
                    ) -> int:
                        if action == _denied_action and first_argument == _denied_object:
                            return sqlite3.SQLITE_DENY
                        return sqlite3.SQLITE_OK

                    store.connection.set_authorizer(authorizer)
                    try:
                        original_create_v6(
                            store, advance_schema_version=advance_schema_version
                        )
                    finally:
                        store.connection.set_authorizer(None)

                with mock.patch.object(
                    StudioStore,
                    "_create_v6_schema",
                    autospec=True,
                    side_effect=fail_at_boundary,
                ):
                    with self.assertRaisesRegex(
                        StudioError, "Could not migrate Studio database"
                    ):
                        StudioStore(data_dir)

                with sqlite3.connect(data_dir / "studio.sqlite3") as connection:
                    version = connection.execute(
                        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                    ).fetchone()[0]
                    private_objects = {
                        row[0]
                        for row in connection.execute(
                            "SELECT name FROM sqlite_master WHERE name IN "
                            "('studio_authenticated_human_credentials', "
                            "'studio_authenticated_human_decisions', "
                            "'studio_authenticated_human_decision_events', "
                            "'studio_authenticated_human_decision_events_approval_idx')"
                        )
                    }
                self.assertEqual("5", version)
                self.assertEqual(set(), private_objects)


if __name__ == "__main__":
    unittest.main()
