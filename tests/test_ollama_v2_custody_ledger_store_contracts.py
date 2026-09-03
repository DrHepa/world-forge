from __future__ import annotations

import inspect
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path
from threading import Barrier
from unittest import mock

import worldforge.provider_evidence.ollama_v2_custody_ledger_store as ledger_module
from worldforge.provider_evidence.ollama_v2_custody_ledger_store import (
    APPLICATION_ID,
    BUSY_TIMEOUT_MS,
    REFERENCE_STORE_KIND,
    SCHEMA_FINGERPRINT,
    SCHEMA_VERSION,
    CustodyLedgerReferenceClosedError,
    CustodyLedgerReferenceCorruptionError,
    CustodyLedgerReferenceHead,
    CustodyLedgerReferenceInvalidStateError,
    CustodyLedgerReferenceSchemaObject,
    CustodyLedgerReferenceStatus,
    CustodyLedgerReferenceUnsupportedError,
    OllamaV2CustodyLedgerReferenceStore,
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
)


class CustodyLedgerReferenceStoreSurfaceTests(unittest.TestCase):
    def _root(self, parent: Path, name: str = "reference") -> Path:
        root = parent / name
        root.mkdir(mode=0o700)
        return root

    def test_public_surface_and_status_remain_explicitly_unbound(self) -> None:
        self.assertEqual(SCHEMA_VERSION, 1)
        self.assertEqual(APPLICATION_ID, 0x57464332)
        self.assertEqual(REFERENCE_STORE_KIND, "injected_local_reference")
        self.assertEqual(
            tuple(inspect.signature(OllamaV2CustodyLedgerReferenceStore).parameters),
            ("root", "mode"),
        )
        expected_methods = {
            "attach_c2_reference",
            "close",
            "commit_dispatch_intent",
            "head",
            "load_binding",
            "load_c2_reference",
            "load_dispatch_intent",
            "load_event",
            "load_manager_reload_witness",
            "load_mutation_ack",
            "load_record",
            "load_release",
            "load_reservation",
            "load_source",
            "load_tombstone",
            "native_status",
            "record_effect_observation",
            "record_manager_reload_witness",
            "record_mutation_ack",
            "register_source",
            "release_tombstoned_record",
            "reserve",
            "schema_census",
            "snapshot",
            "tombstone_observed_record",
        }
        actual_methods = {
            name
            for name, member in inspect.getmembers(
                OllamaV2CustodyLedgerReferenceStore, inspect.isfunction
            )
            if not name.startswith("_")
        }
        self.assertEqual(actual_methods, expected_methods)

        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                for descriptor in (
                    store._root_descriptor,
                    store._lock_descriptor,
                    store._database_descriptor,
                ):
                    assert descriptor is not None
                    self.assertFalse(os.get_inheritable(descriptor))
                status = store.native_status()
                self.assertIs(type(status), CustodyLedgerReferenceStatus)
                self.assertEqual(status.store_kind, "injected_local_reference")
                self.assertEqual(status.deployment_binding, DEPLOYMENT_BINDING)
                self.assertEqual(status.root_global_enforced, ROOT_GLOBAL_ENFORCED)
                self.assertEqual(status.source_custody_verified, SOURCE_CUSTODY_VERIFIED)
                self.assertEqual(status.host_execution_enabled, HOST_EXECUTION_ENABLED)
                self.assertEqual(
                    status.native_implementation_state,
                    NATIVE_IMPLEMENTATION_STATE,
                )
                self.assertEqual(status.availability, AVAILABILITY)
                self.assertEqual(status.production_eligible, PRODUCTION_ELIGIBLE)
                self.assertEqual(status.catalog_admitted, CATALOG_ADMITTED)
                self.assertEqual(
                    status.provider_execution_enabled,
                    PROVIDER_EXECUTION_ENABLED,
                )
                self.assertFalse(status.rollback_resistant)
                self.assertTrue(hasattr(store, "register_source"))
                self.assertTrue(hasattr(store, "reserve"))
                self.assertFalse(hasattr(store, "dispatch"))
                self.assertFalse(hasattr(store, "redispatch"))
                self.assertFalse(
                    any(
                        name in vars(store)
                        for name in ("root", "lock_path", "database_path", "connection")
                    )
                )

                head = store.head()
                self.assertIs(type(head), CustodyLedgerReferenceHead)
                self.assertEqual(head.scope, CUSTODY_SCOPE)
                self.assertEqual(head.fence_generation, 0)
                self.assertEqual(head.record_sequence, 0)
                self.assertEqual(head.record_head_hash, "0" * 64)
                self.assertIsNone(head.active_reservation_id)
                self.assertIsNone(head.active_fence_hash)
                self.assertEqual(head.active_state, "idle")
                self.assertEqual(head.event_sequence, 0)
                self.assertEqual(head.event_head_hash, "0" * 64)
                self.assertFalse(head.poisoned)

                with self.assertRaises(FrozenInstanceError):
                    status.availability = "available"  # type: ignore[misc]
                with self.assertRaises(FrozenInstanceError):
                    head.poisoned = True  # type: ignore[misc]

            self.assertEqual((root / CUSTODY_LOCK_NAME).stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / CUSTODY_LEDGER_NAME).stat().st_mode & 0o777, 0o600)

    def test_explicit_exports_and_no_package_reexport_or_lifecycle_callables(self) -> None:
        self.assertEqual(
            ledger_module.__all__,
            (
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
                "CustodyLedgerReferenceRelease",
                "CustodyLedgerReferenceSchemaObject",
                "CustodyLedgerReferenceSnapshot",
                "CustodyLedgerReferenceStatus",
                "CustodyLedgerReferenceStoreError",
                "CustodyLedgerReferenceTombstone",
                "CustodyLedgerReferenceTransition",
                "CustodyLedgerReferenceUnsupportedError",
                "OllamaV2CustodyLedgerReferenceStore",
                "parse_custody_ledger_reference_event",
            ),
        )
        import worldforge.provider_evidence as provider_evidence

        self.assertFalse(
            hasattr(provider_evidence, "OllamaV2CustodyLedgerReferenceStore")
        )
        forbidden = {
            "ack",
            "dispatch",
            "execute",
            "redispatch",
            "release",
            "retry",
            "tombstone",
        }
        public = {
            name
            for name in dir(OllamaV2CustodyLedgerReferenceStore)
            if not name.startswith("_")
        }
        self.assertTrue(public.isdisjoint(forbidden))

    def test_error_classes_are_distinct_and_canonical_root_is_rejected(self) -> None:
        self.assertFalse(
            issubclass(
                CustodyLedgerReferenceCorruptionError,
                CustodyLedgerReferenceInvalidStateError,
            )
        )
        self.assertFalse(
            issubclass(
                CustodyLedgerReferenceUnsupportedError,
                CustodyLedgerReferenceClosedError,
            )
        )
        with self.assertRaisesRegex(
            CustodyLedgerReferenceInvalidStateError,
            "reference_root_canonical_target_forbidden",
        ):
            OllamaV2CustodyLedgerReferenceStore(
                CUSTODY_TARGET_ROOT,
                mode="create_or_open",
            )
        with self.assertRaisesRegex(
            CustodyLedgerReferenceInvalidStateError,
            "reference_root_canonical_target_forbidden",
        ):
            OllamaV2CustodyLedgerReferenceStore(
                f"/{CUSTODY_TARGET_ROOT}",
                mode="create_or_open",
            )

    def test_explicit_absolute_existing_root_and_closed_boundary(self) -> None:
        with self.assertRaisesRegex(
            CustodyLedgerReferenceInvalidStateError,
            "reference_root_not_absolute",
        ):
            OllamaV2CustodyLedgerReferenceStore(Path("relative"), mode="create")

        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with self.assertRaisesRegex(
                CustodyLedgerReferenceInvalidStateError,
                "reference_root_missing",
            ):
                OllamaV2CustodyLedgerReferenceStore(missing, mode="create")

            root = self._root(Path(temporary))
            store = OllamaV2CustodyLedgerReferenceStore(root, mode="create")
            store.close()
            store.close()
            for call in (
                store.native_status,
                store.schema_census,
                store.head,
                store.snapshot,
            ):
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceClosedError,
                    "reference_store_closed",
                ):
                    call()

    def test_status_contract_rejects_equal_subclass_scalars(self) -> None:
        class Text(str):
            pass

        with self.assertRaisesRegex(
            CustodyLedgerReferenceInvalidStateError,
            "reference_status_invalid",
        ):
            CustodyLedgerReferenceStatus(
                store_kind=Text(REFERENCE_STORE_KIND),
                deployment_binding=DEPLOYMENT_BINDING,
                root_global_enforced=False,
                source_custody_verified=False,
                host_execution_enabled=False,
                native_implementation_state=NATIVE_IMPLEMENTATION_STATE,
                availability=AVAILABILITY,
                production_eligible=False,
                catalog_admitted=False,
                provider_execution_enabled=False,
                rollback_resistant=False,
            )

    def test_head_and_schema_objects_reject_non_exact_scalar_shapes(self) -> None:
        with self.assertRaisesRegex(
            CustodyLedgerReferenceInvalidStateError,
            "reference_head_invalid",
        ):
            CustodyLedgerReferenceHead(
                scope=CUSTODY_SCOPE,
                fence_generation=0,
                record_sequence=0,
                record_head_hash="0" * 64,
                active_reservation_id=None,
                active_fence_hash=None,
                active_state="idle",
                event_sequence=0,
                event_head_hash="0" * 64,
                poisoned=0,  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(
            CustodyLedgerReferenceInvalidStateError,
            "reference_schema_object_invalid",
        ):
            CustodyLedgerReferenceSchemaObject(
                object_type="table",
                name="example",
                table_name="example",
                sql_sha256="not-a-hash",
            )


class CustodyLedgerReferenceStoreFilesystemTests(unittest.TestCase):
    def _root(self, parent: Path, name: str = "reference") -> Path:
        root = parent / name
        root.mkdir(mode=0o700)
        return root

    @staticmethod
    def _close_ignoring_boundary(store: OllamaV2CustodyLedgerReferenceStore) -> None:
        try:
            store.close()
        except CustodyLedgerReferenceInvalidStateError:
            pass

    def test_modes_have_exact_create_open_and_create_or_open_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = self._root(parent, "one")
            with self.assertRaisesRegex(
                CustodyLedgerReferenceInvalidStateError,
                "reference_store_missing",
            ):
                OllamaV2CustodyLedgerReferenceStore(root, mode="open")
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create"):
                pass
            with self.assertRaisesRegex(
                CustodyLedgerReferenceInvalidStateError,
                "reference_store_already_exists",
            ):
                OllamaV2CustodyLedgerReferenceStore(root, mode="create")
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as reopened:
                self.assertEqual(reopened.head().event_sequence, 0)
            with OllamaV2CustodyLedgerReferenceStore(
                root, mode="create_or_open"
            ) as reopened:
                self.assertEqual(reopened.head().fence_generation, 0)

            root_two = self._root(parent, "two")
            with OllamaV2CustodyLedgerReferenceStore(
                root_two, mode="create_or_open"
            ):
                pass
            for invalid_mode in ("", "CREATE", "repair", None, 1):
                with self.subTest(mode=invalid_mode), self.assertRaisesRegex(
                    CustodyLedgerReferenceInvalidStateError,
                    "reference_store_mode_invalid",
                ):
                    OllamaV2CustodyLedgerReferenceStore(  # type: ignore[arg-type]
                        root_two,
                        mode=invalid_mode,
                    )
            with self.assertRaises(TypeError):
                OllamaV2CustodyLedgerReferenceStore(
                    root_two,
                    mode="open",
                    database_name="selected.sqlite3",  # type: ignore[call-arg]
                )

    def test_create_or_open_does_not_repair_partial_or_empty_storage(self) -> None:
        for case in ("both_empty", "orphan_lock", "orphan_database"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                lock = root / CUSTODY_LOCK_NAME
                database = root / CUSTODY_LEDGER_NAME
                if case in {"both_empty", "orphan_lock"}:
                    lock.write_bytes(b"\0")
                    lock.chmod(0o600)
                if case in {"both_empty", "orphan_database"}:
                    database.write_bytes(b"")
                    database.chmod(0o600)
                expected = (
                    CustodyLedgerReferenceCorruptionError
                    if case == "both_empty"
                    else CustodyLedgerReferenceInvalidStateError
                )
                with mock.patch.object(ledger_module, "BUSY_TIMEOUT_MS", 20):
                    with self.assertRaises(expected):
                        OllamaV2CustodyLedgerReferenceStore(
                            root,
                            mode="create_or_open",
                        )
                if database.exists():
                    self.assertEqual(database.read_bytes(), b"")

    def test_root_must_be_real_private_current_user_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            permissive = self._root(parent, "permissive")
            permissive.chmod(0o750)
            with self.assertRaisesRegex(
                CustodyLedgerReferenceInvalidStateError,
                "reference_root_permissions_invalid",
            ):
                OllamaV2CustodyLedgerReferenceStore(permissive, mode="create")

            target = self._root(parent, "target")
            link = parent / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(
                CustodyLedgerReferenceInvalidStateError,
                "reference_root_symlink_forbidden",
            ):
                OllamaV2CustodyLedgerReferenceStore(link, mode="create")

            nested_target = self._root(parent, "nested-target")
            link_parent = parent / "link-parent"
            link_parent.symlink_to(nested_target, target_is_directory=True)
            child = nested_target / "child"
            child.mkdir(mode=0o700)
            with self.assertRaisesRegex(
                CustodyLedgerReferenceInvalidStateError,
                "reference_root_symlink_forbidden",
            ):
                OllamaV2CustodyLedgerReferenceStore(link_parent / "child", mode="create")

            owned = self._root(parent, "owned")
            with mock.patch.object(ledger_module.os, "getuid", return_value=os.getuid() + 1):
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceInvalidStateError,
                    "reference_root_permissions_invalid",
                ):
                    OllamaV2CustodyLedgerReferenceStore(owned, mode="create")

    def test_environment_cannot_redirect_fixed_leaf_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with mock.patch.dict(
                os.environ,
                {
                    "WORLD_FORGE_CUSTODY_ROOT": str(Path(temporary) / "elsewhere"),
                    "WORLD_FORGE_CUSTODY_DATABASE": "other.sqlite3",
                    "WORLD_FORGE_CUSTODY_LOCK": "other.lock",
                },
            ):
                with OllamaV2CustodyLedgerReferenceStore(root, mode="create"):
                    pass
            self.assertTrue((root / CUSTODY_LEDGER_NAME).is_file())
            self.assertTrue((root / CUSTODY_LOCK_NAME).is_file())
            self.assertFalse((root / "other.sqlite3").exists())
            self.assertFalse((root / "other.lock").exists())

    def test_lock_and_database_reject_permissions_links_and_symlinks(self) -> None:
        cases = ("lock_mode", "database_mode", "lock_link", "database_link")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                with OllamaV2CustodyLedgerReferenceStore(root, mode="create"):
                    pass
                lock = root / CUSTODY_LOCK_NAME
                database = root / CUSTODY_LEDGER_NAME
                selected = lock if case.startswith("lock") else database
                if case.endswith("mode"):
                    selected.chmod(0o640)
                else:
                    os.link(selected, root / f"{selected.name}.hardlink")
                with self.assertRaises(CustodyLedgerReferenceInvalidStateError):
                    OllamaV2CustodyLedgerReferenceStore(root, mode="open")

        for leaf in (CUSTODY_LOCK_NAME, CUSTODY_LEDGER_NAME):
            with self.subTest(symlink=leaf), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                with OllamaV2CustodyLedgerReferenceStore(root, mode="create"):
                    pass
                path = root / leaf
                original = root / f"{leaf}.original"
                path.rename(original)
                path.symlink_to(original.name)
                with self.assertRaises(CustodyLedgerReferenceInvalidStateError):
                    OllamaV2CustodyLedgerReferenceStore(root, mode="open")

    def test_retained_root_lock_and_database_identity_are_boundary_checked(self) -> None:
        for selected in ("root", "lock", "database"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                root = self._root(parent)
                store = OllamaV2CustodyLedgerReferenceStore(root, mode="create")
                if selected == "root":
                    moved = parent / "moved"
                    root.rename(moved)
                    root.mkdir(mode=0o700)
                else:
                    leaf = CUSTODY_LOCK_NAME if selected == "lock" else CUSTODY_LEDGER_NAME
                    path = root / leaf
                    path.rename(root / f"{leaf}.moved")
                    replacement = root / leaf
                    replacement.write_bytes(b"\0" if selected == "lock" else b"")
                    replacement.chmod(0o600)
                with self.assertRaises(CustodyLedgerReferenceInvalidStateError):
                    store.native_status()
                self._close_ignoring_boundary(store)

    def test_database_substitution_before_sqlite_configuration_is_not_mutated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            database = root / CUSTODY_LEDGER_NAME
            retained = root / f"{CUSTODY_LEDGER_NAME}.retained"
            real_connect = sqlite3.connect

            def substitute_then_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
                database.rename(retained)
                database.write_bytes(b"")
                database.chmod(0o600)
                return real_connect(*args, **kwargs)

            with mock.patch.object(
                ledger_module.sqlite3,
                "connect",
                side_effect=substitute_then_connect,
            ):
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceInvalidStateError,
                    "reference_database_replaced",
                ):
                    OllamaV2CustodyLedgerReferenceStore(root, mode="create")
            self.assertEqual(database.read_bytes(), b"")

    def test_sqlite_connection_is_bound_to_the_retained_database_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            database = root / CUSTODY_LEDGER_NAME
            retained = root / f"{CUSTODY_LEDGER_NAME}.retained"
            decoy = root / f"{CUSTODY_LEDGER_NAME}.decoy"
            real_connect = sqlite3.connect

            def aba_then_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
                database.rename(retained)
                database.write_bytes(b"")
                database.chmod(0o600)
                connection = real_connect(*args, **kwargs)
                database.rename(decoy)
                retained.rename(database)
                return connection

            with mock.patch.object(
                ledger_module.sqlite3,
                "connect",
                side_effect=aba_then_connect,
            ):
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceInvalidStateError,
                    "reference_database_identity_unstable",
                ):
                    OllamaV2CustodyLedgerReferenceStore(root, mode="create")

            self.assertEqual(database.read_bytes(), b"")
            self.assertEqual(decoy.read_bytes(), b"")

    def test_two_same_root_opens_share_lifetime_lock_and_roots_remain_independent(self) -> None:
        import fcntl

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            first_root = self._root(parent, "first")
            second_root = self._root(parent, "second")
            first = OllamaV2CustodyLedgerReferenceStore(first_root, mode="create")
            same = OllamaV2CustodyLedgerReferenceStore(first_root, mode="open")
            independent = OllamaV2CustodyLedgerReferenceStore(
                second_root, mode="create"
            )
            try:
                self.assertEqual(first.head(), same.head())
                for store in (first, same, independent):
                    status = store.native_status()
                    self.assertFalse(status.root_global_enforced)
                    self.assertFalse(status.rollback_resistant)
                    self.assertFalse(status.production_eligible)
                first.close()
                contender = os.open(first_root / CUSTODY_LOCK_NAME, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(contender)
                self.assertEqual(same.head().event_sequence, 0)
            finally:
                independent.close()
                same.close()
                first.close()

    def test_two_create_or_open_callers_initialize_once_and_two_creators_conflict(self) -> None:
        def concurrent_open(root: Path, mode: str) -> str:
            try:
                with OllamaV2CustodyLedgerReferenceStore(root, mode=mode) as store:
                    return f"ok:{store.head().event_sequence}"
            except CustodyLedgerReferenceInvalidStateError as exc:
                return exc.reason_code

        def raced_pair(root: Path, mode: str) -> list[str]:
            barrier = Barrier(2)
            lock_path = root / CUSTODY_LOCK_NAME
            real_open = os.open

            def synchronized_open(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode_bits: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                if Path(path) == lock_path and flags & os.O_CREAT:
                    barrier.wait(timeout=5)
                if dir_fd is None:
                    return real_open(path, flags, mode_bits)
                return real_open(path, flags, mode_bits, dir_fd=dir_fd)

            with mock.patch.object(
                ledger_module.os,
                "open",
                side_effect=synchronized_open,
            ):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    return list(
                        pool.map(
                            lambda _: concurrent_open(root, mode),
                            range(2),
                        )
                    )

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = self._root(parent, "openers")
            results = raced_pair(root, "create_or_open")
            self.assertEqual(results, ["ok:0", "ok:0"])
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as store:
                self.assertEqual(store.head().event_head_hash, "0" * 64)

            create_root = self._root(parent, "creators")
            results = raced_pair(create_root, "create")
            self.assertCountEqual(
                results,
                ["ok:0", "reference_store_already_exists"],
            )

    def test_external_sqlite_writer_contention_is_invalid_state_not_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create"):
                pass
            blocker = sqlite3.connect(root / CUSTODY_LEDGER_NAME, isolation_level=None)
            try:
                blocker.execute("BEGIN EXCLUSIVE")
                with mock.patch.object(ledger_module, "BUSY_TIMEOUT_MS", 20):
                    with self.assertRaisesRegex(
                        CustodyLedgerReferenceInvalidStateError,
                        "reference_store_busy",
                    ):
                        OllamaV2CustodyLedgerReferenceStore(root, mode="open")
            finally:
                blocker.execute("ROLLBACK")
                blocker.close()


class CustodyLedgerReferenceStoreSchemaTests(unittest.TestCase):
    def _root(self, parent: Path, name: str = "reference") -> Path:
        root = parent / name
        root.mkdir(mode=0o700)
        return root

    @staticmethod
    def _create(root: Path) -> Path:
        with OllamaV2CustodyLedgerReferenceStore(root, mode="create"):
            pass
        return root / CUSTODY_LEDGER_NAME

    @staticmethod
    def _mutate(database: Path, sql: str, parameters: tuple[object, ...] = ()) -> None:
        connection = sqlite3.connect(database)
        try:
            connection.execute(sql, parameters)
            connection.commit()
        finally:
            connection.close()

    def test_schema_fingerprint_census_and_pragmas_are_literal(self) -> None:
        self.assertEqual(
            SCHEMA_FINGERPRINT,
            "417618a56f07446749ab8ef792b577934e55fbb7c5870316c7abf465af69e7b2",
        )
        expected = (
            (
                "index",
                "idx_ollama_v2_custody_events_artifact_hash",
                "5fcc5380debb4317cb514cb158bd5fff3847292186b84d0d6b28812848aaf81f",
            ),
            (
                "index",
                "idx_ollama_v2_custody_events_artifact_id",
                "9bc05fabd53cadb9f9d7606cfe6691240298c7b21fb2d8b20392da64015c5ac0",
            ),
            (
                "index",
                "idx_ollama_v2_custody_events_binding_hash",
                "8b991c3a3a55d685f2e556ee6723b4d824f6f243f9395b2a69c0b335b01b5a28",
            ),
            (
                "index",
                "idx_ollama_v2_custody_events_event_hash",
                "373fc49516319853a32365d22aab354e434ff3ac4cae103d0c8fbf8db610c905",
            ),
            (
                "index",
                "idx_ollama_v2_custody_events_event_id",
                "603f406521af2da77e05cda4d975cd361bd69c8f6e26131b84875ea9868dd8b4",
            ),
            (
                "index",
                "idx_ollama_v2_custody_events_subject_stage",
                "32c6b6f41515e70e0922a8075908f41db9cbafa9a9c7d8c961cdf7497175721e",
            ),
            (
                "table",
                "ollama_v2_custody_events",
                "59570a32caaae73383497ba95e13a99613fa82cb2143c7d64ec801cd3182fa85",
            ),
            (
                "table",
                "ollama_v2_custody_head",
                "049096325175495ca3555e5ea072e9f532837b82160d476ba092880e3293a3a9",
            ),
            (
                "table",
                "ollama_v2_custody_metadata",
                "cd28e6be3f2e1cebe32a5d94652e8b25dc14124d8471a4b0df7e3714db104b7c",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                census = store.schema_census()
                self.assertTrue(
                    all(type(item) is CustodyLedgerReferenceSchemaObject for item in census)
                )
                self.assertEqual(
                    tuple((item.object_type, item.name, item.sql_sha256) for item in census),
                    expected,
                )
                connection = store._connection
                assert connection is not None
                self.assertEqual(
                    connection.execute("PRAGMA application_id").fetchone()[0],
                    APPLICATION_ID,
                )
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0],
                    SCHEMA_VERSION,
                )
                self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "delete")
                self.assertEqual(connection.execute("PRAGMA synchronous").fetchone()[0], 2)
                self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
                self.assertEqual(connection.execute("PRAGMA trusted_schema").fetchone()[0], 0)
                self.assertEqual(
                    connection.execute(
                        "PRAGMA ignore_check_constraints"
                    ).fetchone()[0],
                    0,
                )
                self.assertEqual(
                    connection.execute("PRAGMA busy_timeout").fetchone()[0],
                    BUSY_TIMEOUT_MS,
                )
            self.assertFalse(Path(f"{root / CUSTODY_LEDGER_NAME}-wal").exists())
            self.assertFalse(Path(f"{root / CUSTODY_LEDGER_NAME}-shm").exists())
            self.assertFalse(Path(f"{root / CUSTODY_LEDGER_NAME}-journal").exists())

    def test_reopen_preserves_exact_genesis_without_migration_or_backfill(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            database = self._create(root)
            before = database.read_bytes()
            with OllamaV2CustodyLedgerReferenceStore(root, mode="open") as reopened:
                self.assertEqual(reopened.head().record_sequence, 0)
                self.assertEqual(len(reopened.schema_census()), 9)
            self.assertEqual(database.read_bytes(), before)

    def test_head_schema_enforces_zero_event_exact_genesis_coupling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            database = self._create(root)
            connection = sqlite3.connect(database)
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """UPDATE ollama_v2_custody_head
                        SET fence_generation = 1,
                            active_reservation_id = 'reservation-foreign',
                            active_fence_hash = ?,
                            active_state = 'reserved'""",
                        ("1" * 64,),
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """UPDATE ollama_v2_custody_head
                        SET event_sequence = 1,
                            event_head_hash = ?,
                            active_reservation_id = 'reservation-foreign',
                            active_fence_hash = ?,
                            active_state = 'reserved'""",
                        ("2" * 64, "1" * 64),
                    )
            finally:
                connection.close()

    def test_event_schema_requires_lowercase_hashes_and_blob_storage(self) -> None:
        statement = """INSERT INTO ollama_v2_custody_events(
            sequence, event_id, event_type, subject_id, subject_stage,
            artifact_id, artifact_type, artifact_hash, artifact_json,
            binding_hash, binding_json, previous_event_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
        base = (
            1,
            "event-invalid",
            "source.registered",
            "source-invalid",
            "registered",
            "artifact-invalid",
            "source_descriptor",
            "1" * 64,
            b"{}",
            None,
            None,
            "0" * 64,
            "2" * 64,
        )
        variants = (
            (*base[:8], "{}", *base[9:]),
            (*base[:7], "Z" * 64, *base[8:]),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            database = self._create(root)
            connection = sqlite3.connect(database)
            try:
                for values in variants:
                    with self.subTest(values=values[7:9]), self.assertRaises(
                        sqlite3.IntegrityError
                    ):
                        connection.execute(statement, values)
                    connection.execute("DELETE FROM ollama_v2_custody_events")
            finally:
                connection.close()

    def test_foreign_ids_versions_metadata_head_and_event_fail_closed(self) -> None:
        mutations = {
            "application": "PRAGMA application_id = 7",
            "version": "PRAGMA user_version = 7",
            "metadata": (
                "UPDATE ollama_v2_custody_metadata SET value = 'foreign' "
                "WHERE key = 'store_kind'"
            ),
            "head": """UPDATE ollama_v2_custody_head
                SET event_sequence = 1,
                    event_head_hash =
                    '1111111111111111111111111111111111111111111111111111111111111111'""",
            "event": """INSERT INTO ollama_v2_custody_events(
                sequence, event_id, event_type, subject_id, subject_stage,
                artifact_id, artifact_type, artifact_hash, artifact_json,
                binding_hash, binding_json, previous_event_hash, event_hash
            ) VALUES (
                1, 'event-foreign', 'source.registered', 'source-foreign', 'registered',
                'artifact-foreign', 'source_descriptor', ?, ?, NULL, NULL, ?, ?
            )""",
        }
        for name, sql in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                database = self._create(root)
                if name == "event":
                    digest = "1" * 64
                    self._mutate(database, sql, (digest, b"{}", "0" * 64, "2" * 64))
                else:
                    self._mutate(database, sql)
                before = database.read_bytes()
                with self.assertRaises(CustodyLedgerReferenceCorruptionError):
                    OllamaV2CustodyLedgerReferenceStore(root, mode="open")
                self.assertEqual(database.read_bytes(), before)

    def test_missing_extra_reformatted_and_wrong_storage_schema_fail_closed(self) -> None:
        mutations = {
            "missing": "DROP INDEX idx_ollama_v2_custody_events_event_hash",
            "extra_table": "CREATE TABLE foreign_table(value TEXT)",
            "extra_view": "CREATE VIEW foreign_view AS SELECT 1 AS value",
            "extra_trigger": """CREATE TRIGGER foreign_trigger
                AFTER INSERT ON ollama_v2_custody_events
                BEGIN SELECT 1; END""",
            "sqlite_sequence": """CREATE TABLE transient_sequence(
                value INTEGER PRIMARY KEY AUTOINCREMENT
            ); DROP TABLE transient_sequence""",
            "reformatted": """DROP INDEX idx_ollama_v2_custody_events_event_id;
                CREATE UNIQUE INDEX idx_ollama_v2_custody_events_event_id
                ON ollama_v2_custody_events(event_id)""",
            "storage": (
                "UPDATE ollama_v2_custody_metadata SET value = X'31' "
                "WHERE key = 'schema_version'"
            ),
            "metadata_missing": (
                "DELETE FROM ollama_v2_custody_metadata "
                "WHERE key = 'store_kind'"
            ),
            "metadata_extra": """PRAGMA ignore_check_constraints = ON;
                INSERT INTO ollama_v2_custody_metadata(key, value)
                VALUES ('foreign', 'foreign')""",
        }
        for name, script in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                database = self._create(root)
                connection = sqlite3.connect(database)
                try:
                    connection.executescript(script)
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaises(CustodyLedgerReferenceCorruptionError):
                    OllamaV2CustodyLedgerReferenceStore(root, mode="open")

    def test_non_sqlite_payload_is_corruption_not_missing_or_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            lock = root / CUSTODY_LOCK_NAME
            lock.write_bytes(b"\0")
            lock.chmod(0o600)
            database = root / CUSTODY_LEDGER_NAME
            database.write_bytes(b"not sqlite")
            database.chmod(0o600)
            with self.assertRaises(CustodyLedgerReferenceCorruptionError):
                OllamaV2CustodyLedgerReferenceStore(root, mode="open")

    def test_existing_wal_mode_is_rejected_without_journal_mode_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            database = self._create(root)
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(
                    connection.execute("PRAGMA journal_mode = WAL").fetchone()[0],
                    "wal",
                )
            finally:
                connection.close()
            before = database.read_bytes()
            with self.assertRaisesRegex(
                CustodyLedgerReferenceCorruptionError,
                "reference_database_journal_mode_invalid",
            ):
                OllamaV2CustodyLedgerReferenceStore(root, mode="open")
            self.assertEqual(database.read_bytes(), before)

    def test_preexisting_sqlite_sidecars_are_rejected_before_connection(self) -> None:
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temporary:
                root = self._root(Path(temporary))
                database = self._create(root)
                sidecar = Path(f"{database}{suffix}")
                sidecar.write_bytes(b"foreign-sidecar")
                sidecar.chmod(0o600)
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceInvalidStateError,
                    "reference_database_sidecar_unexpected",
                ):
                    OllamaV2CustodyLedgerReferenceStore(root, mode="open")
                self.assertEqual(sidecar.read_bytes(), b"foreign-sidecar")


class CustodyLedgerReferenceStoreProcessTests(unittest.TestCase):
    def _root(self, parent: Path) -> Path:
        root = parent / "reference"
        root.mkdir(mode=0o700)
        return root

    def test_context_closes_and_constructor_fails_canonically_without_posix_locking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with OllamaV2CustodyLedgerReferenceStore(root, mode="create") as store:
                self.assertEqual(store.head().active_state, "idle")
            with self.assertRaises(CustodyLedgerReferenceClosedError):
                store.head()

        original_import = __import__

        def without_fcntl(name: str, *args: object, **kwargs: object) -> object:
            if name == "fcntl":
                raise ImportError("blocked for test")
            return original_import(name, *args, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            with mock.patch("builtins.__import__", side_effect=without_fcntl):
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceUnsupportedError,
                    "reference_store_lock_unsupported",
                ):
                    OllamaV2CustodyLedgerReferenceStore(root, mode="create")
            self.assertFalse((root / CUSTODY_LOCK_NAME).exists())
            self.assertFalse((root / CUSTODY_LEDGER_NAME).exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            missing = root / "missing-descriptor-directory"
            with mock.patch.object(
                ledger_module,
                "_DESCRIPTOR_DIRECTORY",
                missing,
                create=True,
            ):
                with self.assertRaisesRegex(
                    CustodyLedgerReferenceUnsupportedError,
                    "reference_store_descriptor_reopen_unsupported",
                ):
                    OllamaV2CustodyLedgerReferenceStore(root, mode="create")
            self.assertFalse((root / CUSTODY_LOCK_NAME).exists())
            self.assertFalse((root / CUSTODY_LEDGER_NAME).exists())

    def test_close_orders_sqlite_before_lifetime_lock_release(self) -> None:
        class TrackedConnection:
            def __init__(
                self,
                connection: sqlite3.Connection,
                events: list[str],
            ) -> None:
                self._connection = connection
                self._events = events

            def close(self) -> None:
                self._events.append("sqlite")
                self._connection.close()

        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            store = OllamaV2CustodyLedgerReferenceStore(root, mode="create")
            events: list[str] = []
            connection = store._connection
            assert connection is not None
            store._connection = TrackedConnection(connection, events)  # type: ignore[assignment]
            with mock.patch.object(
                OllamaV2CustodyLedgerReferenceStore,
                "_release_file_lock",
                side_effect=lambda _descriptor: events.append("lock"),
            ):
                store.close()
            self.assertEqual(events, ["sqlite", "lock"])

    def test_failed_sqlite_close_retains_lifetime_lock_fence(self) -> None:
        class FailingConnection:
            def close(self) -> None:
                raise RuntimeError("injected close failure")

        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            store = OllamaV2CustodyLedgerReferenceStore(root, mode="create")
            connection = store._connection
            assert connection is not None
            store._connection = FailingConnection()  # type: ignore[assignment]
            releases: list[int] = []
            try:
                with mock.patch.object(
                    OllamaV2CustodyLedgerReferenceStore,
                    "_release_file_lock",
                    side_effect=releases.append,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "injected close failure",
                    ):
                        store.close()
                self.assertEqual(releases, [])
                self.assertIsNotNone(store._lock_descriptor)
            finally:
                store._connection = connection
                store._closed = False
                store.close()

    def test_module_import_does_not_require_posix_locking_module(self) -> None:
        code = """
import builtins
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name == 'fcntl':
        raise AssertionError('fcntl imported eagerly')
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
import worldforge.provider_evidence.ollama_v2_custody_ledger_store
"""
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-c", code],
            cwd=Path(__file__).parents[1],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork semantics")
    def test_inherited_child_invalidates_copy_without_releasing_parent_lock(self) -> None:
        import fcntl

        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(Path(temporary))
            store = OllamaV2CustodyLedgerReferenceStore(root, mode="create")
            read_descriptor, write_descriptor = os.pipe()
            process_id = os.fork()
            if process_id == 0:
                os.close(read_descriptor)
                result = "unexpected"
                exit_code = 0
                try:
                    store.head()
                except CustodyLedgerReferenceInvalidStateError as exc:
                    result = exc.reason_code
                except BaseException as exc:
                    result = type(exc).__name__
                    exit_code = 1
                finally:
                    store.close()
                    os.write(write_descriptor, result.encode("ascii"))
                    os.close(write_descriptor)
                    os._exit(exit_code)
            os.close(write_descriptor)
            child_result = os.read(read_descriptor, 256).decode("ascii")
            os.close(read_descriptor)
            waited, status = os.waitpid(process_id, 0)
            self.assertEqual(waited, process_id)
            self.assertEqual(status, 0)
            self.assertEqual(child_result, "reference_store_process_mismatch")
            self.assertEqual(store.head().event_sequence, 0)

            contender = os.open(root / CUSTODY_LOCK_NAME, os.O_RDWR | os.O_NOFOLLOW)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(contender)
            store.close()


if __name__ == "__main__":
    unittest.main()
