from __future__ import annotations

import copy
import ctypes
import errno
import fcntl
import hashlib
import hmac
import json
import multiprocessing
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.agent_harness_fakes import FakeCancellation, FakeClock
from tests.test_agent_execution_kernel import _request
from tests.test_agent_provider_governance import _execution_selection
from tests.test_agent_runtime_dispatch import _documents_for_runtime
from worldforge.agent_harness import AgentEventLog, AgentExecutionCoordinator, CapabilityBroker
from worldforge.agent_harness import local_service as local_service_module
from worldforge.agent_harness import loopback_gateway as loopback_gateway_module
from worldforge.agent_harness import process_supervisor as process_supervisor_module
from worldforge.agent_harness import supervisor as supervisor_module
from worldforge.agent_harness.kernel import AgentExecutionKernel, KernelError
from worldforge.agent_harness.local_service import (
    LocalServicePolicyError,
    _acquire_local_service_lease,
    _close_local_service_lease,
    _parse_local_service_ready_frame,
    _validate_local_service_attestation,
    _validate_local_service_lease,
    code_owned_local_service_launch_policy,
    local_service_command,
)
from worldforge.agent_harness.ports import ProviderBoundaryControl, ProviderTurnRequest
from worldforge.agent_harness.process_supervisor import (
    ProviderBoundaryFailure,
    ProviderBoundaryIndeterminate,
    ProviderBoundaryStopped,
    ProviderBoundaryUnsupported,
)
from worldforge.agent_harness.provider_governance import (
    InMemoryProviderGovernanceAuthority,
    ProviderGovernanceDecision,
)
from worldforge.agent_harness.supervisor import OneShotProviderSupervisor
from worldforge.agent_harness.worker_registry import (
    _CodeOwnedRuntimeKey,
    code_owned_local_service_provider_catalog,
    local_service_runtime_spec,
)

_HOSTILE_PROCESS_INIT_MARKER_FD = -1


def _local_service_selection(request, broker: CapabilityBroker):
    catalog = code_owned_local_service_provider_catalog()
    spec = local_service_runtime_spec()
    return _execution_selection(
        request,
        broker,
        catalog=catalog,
        spec=spec,
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _signed_ready_frame(*, lease, key: bytes, nonce: str, service_pid: int) -> bytes:
    service_ppid, service_start_time = local_service_module._process_identity(service_pid)
    cwd = os.stat(f"/proc/{service_pid}/cwd")
    document = {
        "bootstrap_hash": lease.policy.bootstrap_hash,
        "cwd_device": cwd.st_dev,
        "cwd_inode": cwd.st_ino,
        "fd_census_hash": local_service_module._FD_CENSUS_HASH,
        "format": local_service_module._READY_FORMAT,
        "format_version": local_service_module._FORMAT_VERSION,
        "launch_policy_hash": lease.policy.content_hash,
        "launch_recipe_hash": lease.recipe.content_hash,
        "listener_fd": lease.listener.fileno(),
        "listener_host": lease.host,
        "listener_inode": lease.listener_inode,
        "listener_port": lease.port,
        "network_filter_hash": lease.policy.network_filter_hash,
        "nonce": nonce,
        "root_device": lease.root_device,
        "root_inode": lease.root_inode,
        "runtime_hash": lease.policy.runtime_hash,
        "self_test_hash": local_service_module._SELF_TEST_HASH,
        "signal_mask": local_service_module._proc_signal_mask(service_pid),
        "service_pid": service_pid,
        "service_ppid": service_ppid,
        "service_revision": lease.policy.service_revision,
        "service_start_time": service_start_time,
    }
    document["mac"] = hmac.new(key, _canonical(document), hashlib.sha256).hexdigest()
    return _canonical(document)


def _popen_new_mutation_probe(connection) -> None:
    popen = local_service_module._CANONICAL_POPEN
    popen.__new__ = staticmethod(lambda _class, *_args, **_kwargs: object())
    try:
        code_owned_local_service_launch_policy()
    except LocalServicePolicyError:
        connection.send_bytes(b"rejected")
    else:
        connection.send_bytes(b"accepted")
    finally:
        connection.close()


def _audit_fork_exec_mutation_probe(connection) -> None:
    policy = code_owned_local_service_launch_policy()
    recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
    lease = _acquire_local_service_lease(policy, recipe=recipe)
    launch = local_service_module._broker_launch_from_lease(
        lease,
        key=b"q" * 32,
        nonce="e" * 64,
    )
    hostile_called = False
    spawned = None

    def hostile_fork_exec(*_args, **_kwargs):
        nonlocal hostile_called
        hostile_called = True
        raise OSError("hostile fork_exec executed")

    def audit(event, _args):
        if event == "subprocess.Popen":
            local_service_module.subprocess._fork_exec = hostile_fork_exec

    sys.addaudithook(audit)
    try:
        with tempfile.TemporaryDirectory() as scratch:
            try:
                spawned = local_service_module._spawn_code_owned_local_service(
                    launch,
                    scratch=scratch,
                )
            except LocalServicePolicyError:
                rejected = True
            else:
                rejected = False
        connection.send((rejected, hostile_called))
    finally:
        if spawned is not None:
            spawned.process.kill()
            spawned.process.wait(timeout=0.5)
            os.close(spawned.control_write_fd)
            os.close(spawned.ready_read_fd)
        _close_local_service_lease(lease)
        connection.close()


def _transitive_fsencode_mutation_probe(connection) -> None:
    policy = code_owned_local_service_launch_policy()
    recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
    lease = _acquire_local_service_lease(policy, recipe=recipe)
    launch = local_service_module._broker_launch_from_lease(
        lease,
        key=b"r" * 32,
        nonce="f" * 64,
    )
    hostile_called = False
    spawned = None

    def hostile_fsencode(_value):
        nonlocal hostile_called
        hostile_called = True
        raise OSError("hostile fsencode executed")

    local_service_module.subprocess.os.fsencode = hostile_fsencode
    try:
        with tempfile.TemporaryDirectory() as scratch:
            try:
                spawned = local_service_module._spawn_code_owned_local_service(
                    launch,
                    scratch=scratch,
                )
            except LocalServicePolicyError:
                accepted_or_rejected = "rejected"
            else:
                accepted_or_rejected = "accepted"
        connection.send((accepted_or_rejected, hostile_called))
    finally:
        if spawned is not None:
            spawned.process.kill()
            spawned.process.wait(timeout=0.5)
            os.close(spawned.control_write_fd)
            os.close(spawned.ready_read_fd)
        _close_local_service_lease(lease)
        connection.close()


def _audit_preexec_frame_probe(connection) -> None:
    policy = code_owned_local_service_launch_policy()
    recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
    lease = _acquire_local_service_lease(policy, recipe=recipe)
    launch = local_service_module._broker_launch_from_lease(
        lease,
        key=b"t" * 32,
        nonce="2" * 64,
    )
    exposed = False

    def no_op_signal_mask(*_args, **_kwargs):
        return frozenset()

    def audit(event, _args):
        nonlocal exposed
        if event != "subprocess.Popen":
            return
        frame = sys._getframe()
        while frame is not None:
            for name in ("preexec_fn", "parent_death_preexec"):
                candidate = frame.f_locals.get(name)
                if candidate is not None:
                    exposed = True
                    for cell in candidate.__closure__ or ():
                        if getattr(cell.cell_contents, "__name__", None) == "pthread_sigmask":
                            cell.cell_contents = no_op_signal_mask
            frame = frame.f_back

    sys.addaudithook(audit)
    spawned = None
    try:
        with tempfile.TemporaryDirectory() as scratch:
            try:
                spawned = local_service_module._spawn_code_owned_local_service(
                    launch,
                    scratch=scratch,
                )
            except LocalServicePolicyError:
                pass
        connection.send(exposed)
    finally:
        if spawned is not None:
            spawned.process.kill()
            spawned.process.wait(timeout=0.5)
            os.close(spawned.control_write_fd)
            os.close(spawned.ready_read_fd)
        _close_local_service_lease(lease)
        connection.close()


def _audit_signal_restorer_probe(connection) -> None:
    policy = code_owned_local_service_launch_policy()
    recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
    lease = _acquire_local_service_lease(policy, recipe=recipe)
    launch = local_service_module._broker_launch_from_lease(
        lease,
        key=b"u" * 32,
        nonce="3" * 64,
    )
    mask_authority = signal.pthread_sigmask
    original_mask = frozenset(mask_authority(signal.SIG_BLOCK, frozenset()))
    restorer = local_service_module._CANONICAL_SIGNAL_RESTORER
    original_code = restorer.__code__
    exposed = False

    def no_op_restorer(*_args, **_kwargs):
        return None

    def audit(event, _args):
        nonlocal exposed
        if event != "subprocess.Popen":
            return
        frame = sys._getframe()
        while frame is not None:
            if frame.f_locals.get("signal_restorer") is restorer:
                exposed = True
                restorer.__code__ = no_op_restorer.__code__
            frame = frame.f_back

    sys.addaudithook(audit)
    spawned = None
    try:
        with tempfile.TemporaryDirectory() as scratch:
            try:
                spawned = local_service_module._spawn_code_owned_local_service(
                    launch,
                    scratch=scratch,
                )
            except LocalServicePolicyError:
                pass
        current_mask = frozenset(mask_authority(signal.SIG_BLOCK, frozenset()))
        connection.send((exposed, current_mask == original_mask))
    finally:
        restorer.__code__ = original_code
        mask_authority(signal.SIG_SETMASK, original_mask)
        if spawned is not None:
            spawned.process.kill()
            spawned.process.wait(timeout=0.5)
            os.close(spawned.control_write_fd)
            os.close(spawned.ready_read_fd)
        _close_local_service_lease(lease)
        connection.close()


def _audit_process_constructor_probe(connection) -> None:
    policy = code_owned_local_service_launch_policy()
    recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
    lease = _acquire_local_service_lease(policy, recipe=recipe)
    launch = local_service_module._broker_launch_from_lease(
        lease,
        key=b"v" * 32,
        nonce="4" * 64,
    )
    constructor = local_service_module._CANONICAL_PROCESS_TYPE.__init__
    original_code = constructor.__code__
    marker_read, marker_write = os.pipe()
    local_service_module._HOSTILE_PROCESS_INIT_MARKER_FD = marker_write

    def hostile_constructor(self, *_args, **_kwargs):
        os.write(_HOSTILE_PROCESS_INIT_MARKER_FD, b"1")
        self.pid = 1

    def audit(event, _args):
        if event == "subprocess.Popen":
            constructor.__code__ = hostile_constructor.__code__

    sys.addaudithook(audit)
    try:
        with tempfile.TemporaryDirectory() as scratch:
            try:
                local_service_module._spawn_code_owned_local_service(
                    launch,
                    scratch=scratch,
                )
            except LocalServicePolicyError:
                rejected = True
            else:
                rejected = False
        os.close(marker_write)
        marker_write = -1
        connection.send((rejected, os.read(marker_read, 1) == b"1"))
    finally:
        constructor.__code__ = original_code
        del local_service_module._HOSTILE_PROCESS_INIT_MARKER_FD
        for descriptor in (marker_read, marker_write):
            if descriptor >= 0:
                os.close(descriptor)
        _close_local_service_lease(lease)
        connection.close()


class LocalServiceClosedAuthorityTests(unittest.TestCase):
    def test_launch_recipe_is_exact_registered_authority(self) -> None:
        policy = code_owned_local_service_launch_policy()
        recipe = local_service_module._code_owned_local_service_launch_recipe(policy)

        self.assertIs(policy, recipe.policy)
        self.assertEqual(
            local_service_module.LOCAL_SERVICE_BOOTSTRAP_SOURCE,
            recipe.bootstrap_source,
        )
        self.assertEqual(local_service_command(), recipe.argv)
        self.assertEqual(
            local_service_module._local_service_environment(),
            dict(recipe.environment),
        )
        self.assertEqual(
            policy.parent_death_policy_hash,
            recipe.parent_death_policy_hash,
        )
        for field in (
            "custody_installer_code_hash",
            "custody_factory_code_hash",
            "custody_dependency_hash",
            "single_thread_checker_hash",
            "popen_launch_contract_hash",
            "popen_init_hash",
            "popen_new_hash",
            "popen_dependency_hash",
            "native_prctl_hash",
            "signal_mask_policy_hash",
        ):
            self.assertRegex(getattr(policy, field), r"^[0-9a-f]{64}$")
            self.assertEqual(getattr(policy, field), getattr(recipe, field))
        self.assertIs(
            recipe,
            local_service_module._validate_local_service_launch_recipe(
                recipe,
                policy=policy,
            ),
        )

        class DerivedRecipe(type(recipe)):
            pass

        derived_recipe = DerivedRecipe(
            **{field: getattr(recipe, field) for field in recipe.__dataclass_fields__}
        )
        for candidate in (
            copy.copy(recipe),
            object.__new__(type(recipe)),
            derived_recipe,
        ):
            if type(candidate) is type(recipe) and not hasattr(candidate, "policy"):
                for field in recipe.__dataclass_fields__:
                    object.__setattr__(candidate, field, getattr(recipe, field))
            with self.subTest(candidate=type(candidate).__name__):
                with self.assertRaises(LocalServicePolicyError):
                    local_service_module._validate_local_service_launch_recipe(
                        candidate,
                        policy=policy,
                    )

        for field, hostile in (
            ("bootstrap_source", "raise SystemExit(73)"),
            ("environment", (("PYTHONUTF8", "0"),)),
            ("parent_death_policy_hash", "0" * 64),
            ("executable", "/tmp/worldforge-hostile-python"),
            ("executable_inode", recipe.executable_inode + 1),
        ):
            original = getattr(recipe, field)
            object.__setattr__(recipe, field, hostile)
            try:
                with self.subTest(field=field), self.assertRaises(LocalServicePolicyError):
                    local_service_module._validate_local_service_launch_recipe(
                        recipe,
                        policy=policy,
                    )
            finally:
                object.__setattr__(recipe, field, original)

    def test_policy_and_lease_retain_immutable_issued_owner_identity(self) -> None:
        original_bind_port = local_service_module._CANONICAL_POLICY.bind_port
        object.__setattr__(local_service_module._CANONICAL_POLICY, "bind_port", 7)
        try:
            policy = code_owned_local_service_launch_policy()
        finally:
            object.__setattr__(
                local_service_module._CANONICAL_POLICY,
                "bind_port",
                original_bind_port,
            )
        self.assertEqual(0, policy.bind_port)

        recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
        lease = _acquire_local_service_lease(policy, recipe=recipe)
        issued_policy = lease.policy
        try:
            for hostile_policy in (
                code_owned_local_service_launch_policy(),
                copy.copy(policy),
                object.__new__(type(policy)),
            ):
                if not hasattr(hostile_policy, "bind_host"):
                    for field in policy.__dataclass_fields__:
                        object.__setattr__(hostile_policy, field, getattr(policy, field))
                object.__setattr__(lease, "policy", hostile_policy)
                try:
                    with (
                        self.subTest(hostile_policy=type(hostile_policy).__name__),
                        self.assertRaises(LocalServicePolicyError),
                    ):
                        _validate_local_service_lease(lease)
                finally:
                    object.__setattr__(lease, "policy", issued_policy)
        finally:
            self.assertTrue(_close_local_service_lease(lease))

    def test_policy_catalog_and_command_are_fixed_and_origin_free(self) -> None:
        policy = code_owned_local_service_launch_policy()
        catalog = code_owned_local_service_provider_catalog()
        spec = local_service_runtime_spec()

        self.assertEqual(2, len(catalog.specs))
        self.assertEqual(
            (
                "worldforge_conformance_provider",
                "worldforge_deterministic_probe_provider",
            ),
            tuple(item.runtime_id for item in catalog.specs),
        )
        self.assertEqual("loopback", spec.network_scope)
        self.assertIsNone(spec.endpoint_origin)
        self.assertEqual(policy.content_hash, spec.endpoint_policy_hash)
        self.assertEqual(spec, catalog.specs[1])
        self.assertEqual("127.0.0.1", policy.bind_host)
        self.assertEqual(0, policy.bind_port)
        self.assertEqual(1, policy.service_revision)
        self.assertRegex(policy.bootstrap_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(policy.runtime_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(policy.argv_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(policy.environment_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(policy.parent_death_policy_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(policy.popen_launch_contract_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(policy.network_filter_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(policy.content_hash, r"^[0-9a-f]{64}$")
        self.assertEqual(policy, code_owned_local_service_launch_policy())
        self.assertEqual(
            (
                os.path.abspath(sys.executable),
                "-I",
                "-B",
                "-S",
                "-u",
                "-X",
                "utf8",
                "-c",
                local_service_module.LOCAL_SERVICE_BOOTSTRAP_SOURCE,
            ),
            local_service_command(),
        )
        self.assertEqual(
            {
                "LC_CTYPE": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONIOENCODING": "utf-8",
                "PYTHONUTF8": "1",
            },
            local_service_module._local_service_environment(),
        )
        self.assertIn(
            "dict(os.environ) != EXPECTED_ENVIRONMENT",
            local_service_module.LOCAL_SERVICE_BOOTSTRAP_SOURCE,
        )
        self.assertLess(
            local_service_module.LOCAL_SERVICE_BOOTSTRAP_SOURCE.index("parent_death_proof"),
            local_service_module.LOCAL_SERVICE_BOOTSTRAP_SOURCE.index("raw_config = read_exact"),
        )
        expected_denials = {
            "aarch64": {198, 199, 200, 201, 203, 211, 212, 434, 438},
            "x86_64": {41, 42, 46, 47, 49, 50, 53, 434, 438},
        }
        for program in local_service_module._SERVICE_ARCHITECTURE_PROGRAMS:
            self.assertLessEqual(
                expected_denials[program.machine],
                set(program.denied_syscalls),
            )
        serialized = _canonical(policy.as_document())
        self.assertNotIn(b"Ollama", serialized)
        self.assertNotIn(b"ollama", serialized)
        self.assertNotIn(b"vendor", serialized)
        with self.assertRaises(FrozenInstanceError):
            policy.bind_port = 9  # type: ignore[misc]

    def test_policy_lease_and_attestation_reject_copies_forgery_and_replay(self) -> None:
        policy = code_owned_local_service_launch_policy()
        with self.assertRaises(LocalServicePolicyError):
            local_service_module._validate_local_service_launch_policy(copy.copy(policy))
        forged_policy = object.__new__(type(policy))
        for field in policy.__dataclass_fields__:
            object.__setattr__(forged_policy, field, getattr(policy, field))
        with self.assertRaises(LocalServicePolicyError):
            local_service_module._validate_local_service_launch_policy(forged_policy)

        class DerivedPolicy(type(policy)):
            pass

        derived_policy = DerivedPolicy(
            **{field: getattr(policy, field) for field in policy.__dataclass_fields__}
        )
        with self.assertRaises(LocalServicePolicyError):
            local_service_module._validate_local_service_launch_policy(derived_policy)

        recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
        lease = _acquire_local_service_lease(policy, recipe=recipe)
        leased_address = (lease.host, lease.port)
        key = b"k" * 32
        nonce = "1" * 64
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as competitor:
                with self.assertRaises(OSError):
                    competitor.bind(leased_address)
            with self.assertRaises(LocalServicePolicyError):
                _validate_local_service_lease(copy.copy(lease))

            class DerivedLease(type(lease)):
                pass

            derived_lease = DerivedLease(
                **{field: getattr(lease, field) for field in lease.__dataclass_fields__}
            )
            with self.assertRaises(LocalServicePolicyError):
                _validate_local_service_lease(derived_lease)
            frame = _signed_ready_frame(
                lease=lease,
                key=key,
                nonce=nonce,
                service_pid=os.getpid(),
            )
            attestation = _parse_local_service_ready_frame(
                frame,
                lease=lease,
                key=key,
                expected_nonce=nonce,
                expected_cwd_device=os.stat(f"/proc/{os.getpid()}/cwd").st_dev,
                expected_cwd_inode=os.stat(f"/proc/{os.getpid()}/cwd").st_ino,
            )
            self.assertEqual(os.getpid(), attestation.service_pid)
            self.assertEqual(lease.port, attestation.listener_port)
            _validate_local_service_attestation(attestation, lease=lease)
            with self.assertRaises(LocalServicePolicyError):
                _validate_local_service_attestation(copy.copy(attestation), lease=lease)

            class DerivedAttestation(type(attestation)):
                pass

            derived_attestation = DerivedAttestation(
                **{field: getattr(attestation, field) for field in attestation.__dataclass_fields__}
            )
            with self.assertRaises(LocalServicePolicyError):
                _validate_local_service_attestation(derived_attestation, lease=lease)
            forged_attestation = object.__new__(type(attestation))
            for field in attestation.__dataclass_fields__:
                object.__setattr__(
                    forged_attestation,
                    field,
                    getattr(attestation, field),
                )
            with self.assertRaises(LocalServicePolicyError):
                _validate_local_service_attestation(forged_attestation, lease=lease)
            with self.assertRaises(LocalServicePolicyError):
                _parse_local_service_ready_frame(
                    frame,
                    lease=lease,
                    key=key,
                    expected_nonce=nonce,
                    expected_cwd_device=os.stat(f"/proc/{os.getpid()}/cwd").st_dev,
                    expected_cwd_inode=os.stat(f"/proc/{os.getpid()}/cwd").st_ino,
                )

            hostile_values = {
                "bootstrap_hash": "0" * 64,
                "cwd_device": attestation.cwd_device + 1,
                "cwd_inode": attestation.cwd_inode + 1,
                "fd_census_hash": "1" * 64,
                "launch_policy_hash": "2" * 64,
                "launch_recipe_hash": "8" * 64,
                "listener_fd": attestation.listener_fd + 1,
                "listener_host": "127.0.0.2",
                "listener_inode": attestation.listener_inode + 1,
                "listener_port": attestation.listener_port + 1,
                "network_filter_hash": "3" * 64,
                "nonce": "4" * 64,
                "root_device": attestation.root_device + 1,
                "root_inode": attestation.root_inode + 1,
                "runtime_hash": "5" * 64,
                "self_test_hash": "6" * 64,
                "service_pid": attestation.service_pid + 100_000,
                "service_ppid": attestation.service_ppid + 1,
                "service_revision": attestation.service_revision + 1,
                "service_start_time": attestation.service_start_time + 1,
                "signal_mask": "0000000000000001",
                "mac": "7" * 64,
            }
            self.assertEqual(
                set(attestation.__dataclass_fields__),
                set(hostile_values),
            )
            for field in attestation.__dataclass_fields__:
                original = getattr(attestation, field)
                object.__setattr__(attestation, field, hostile_values[field])
                try:
                    with (
                        self.subTest(post_parse_field=field),
                        self.assertRaises(LocalServicePolicyError),
                    ):
                        _validate_local_service_attestation(attestation, lease=lease)
                finally:
                    object.__setattr__(attestation, field, original)
        finally:
            self.assertTrue(_close_local_service_lease(lease))
        with self.assertRaises(LocalServicePolicyError):
            _validate_local_service_lease(lease)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as successor:
            successor.bind(leased_address)

        for index, field in enumerate(
            (
                "nonce",
                "launch_policy_hash",
                "launch_recipe_hash",
                "bootstrap_hash",
                "cwd_device",
                "cwd_inode",
                "runtime_hash",
                "network_filter_hash",
                "fd_census_hash",
                "self_test_hash",
                "listener_fd",
                "listener_host",
                "listener_port",
                "listener_inode",
                "root_device",
                "root_inode",
                "service_pid",
                "service_ppid",
                "service_start_time",
                "service_revision",
            ),
            start=2,
        ):
            hostile_recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
            hostile_lease = _acquire_local_service_lease(
                policy,
                recipe=hostile_recipe,
            )
            hostile_key = bytes([index]) * 32
            hostile_nonce = f"{index:064x}"
            try:
                candidate = json.loads(
                    _signed_ready_frame(
                        lease=hostile_lease,
                        key=hostile_key,
                        nonce=hostile_nonce,
                        service_pid=os.getpid(),
                    )
                )
                hostile_values = {
                    "nonce": "f" * 64,
                    "launch_policy_hash": "e" * 64,
                    "launch_recipe_hash": "8" * 64,
                    "bootstrap_hash": "d" * 64,
                    "cwd_device": candidate["cwd_device"] + 1,
                    "cwd_inode": candidate["cwd_inode"] + 1,
                    "runtime_hash": "c" * 64,
                    "network_filter_hash": "b" * 64,
                    "fd_census_hash": "a" * 64,
                    "self_test_hash": "9" * 64,
                    "listener_fd": hostile_lease.listener.fileno() + 1,
                    "listener_host": "127.0.0.2",
                    "listener_port": hostile_lease.port + 1,
                    "listener_inode": hostile_lease.listener_inode + 1,
                    "root_device": hostile_lease.root_device + 1,
                    "root_inode": hostile_lease.root_inode + 1,
                    "service_pid": os.getpid() + 100_000,
                    "service_ppid": candidate["service_ppid"] + 1,
                    "service_start_time": candidate["service_start_time"] + 1,
                    "service_revision": 2,
                }
                candidate[field] = hostile_values[field]
                unsigned = {name: value for name, value in candidate.items() if name != "mac"}
                candidate["mac"] = hmac.new(
                    hostile_key,
                    _canonical(unsigned),
                    hashlib.sha256,
                ).hexdigest()
                with (
                    self.subTest(field=field),
                    self.assertRaises(LocalServicePolicyError),
                ):
                    _parse_local_service_ready_frame(
                        _canonical(candidate),
                        lease=hostile_lease,
                        key=hostile_key,
                        expected_nonce=hostile_nonce,
                        expected_cwd_device=os.stat(f"/proc/{os.getpid()}/cwd").st_dev,
                        expected_cwd_inode=os.stat(f"/proc/{os.getpid()}/cwd").st_ino,
                    )
            finally:
                self.assertTrue(_close_local_service_lease(hostile_lease))

    def test_constructor_accepts_no_origin_port_command_or_factory_authority(self) -> None:
        activation, grant = _documents_for_runtime(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        broker = CapabilityBroker()
        request = _request(activation, grant, max_duration_ms=2_000)
        selection = _local_service_selection(request, broker)

        for name, value in (
            ("origin", "http://127.0.0.1:1"),
            ("port", 1),
            ("command", ("hostile",)),
            ("factory", lambda: None),
        ):
            with self.subTest(name=name), self.assertRaises(TypeError):
                OneShotProviderSupervisor.for_local_service(
                    selection,
                    turn_timeout_ms=2_000,
                    **{name: value},
                )

        genuine = OneShotProviderSupervisor.for_local_service(
            selection,
            turn_timeout_ms=2_000,
        )
        with self.assertRaises(KernelError):
            AgentExecutionKernel(
                provider=copy.copy(genuine),
                broker=object(),  # type: ignore[arg-type]
                journal=object(),  # type: ignore[arg-type]
                clock=object(),  # type: ignore[arg-type]
                cancellation=object(),  # type: ignore[arg-type]
                provider_catalog=code_owned_local_service_provider_catalog(),
            )
        self.assertEqual(0, genuine.spawn_count)
        self.assertEqual(0, genuine._process_supervisor.local_service_bind_count)
        self.assertEqual(0, genuine._process_supervisor.local_service_spawn_count)

    def test_subclassed_factory_and_owner_swapped_capability_are_rejected(self) -> None:
        activation, grant = _documents_for_runtime(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        broker = CapabilityBroker()
        request = _request(activation, grant, max_duration_ms=2_000)
        selection = _local_service_selection(request, broker)

        class HostileSupervisor(OneShotProviderSupervisor):
            pass

        with self.assertRaises(ValueError):
            HostileSupervisor.for_local_service(selection, turn_timeout_ms=2_000)

        provider = OneShotProviderSupervisor.for_local_service(
            selection,
            turn_timeout_ms=2_000,
        )
        capability = provider._authority.local_service_capability
        self.assertIsNotNone(capability)
        object.__setattr__(capability, "_owner", object())
        with self.assertRaises(ValueError):
            OneShotProviderSupervisor._require_gateway_authority(
                provider,
                code_owned_local_service_provider_catalog(),
            )
        self.assertEqual(0, provider._process_supervisor.local_service_bind_count)
        self.assertEqual(0, provider._process_supervisor.local_service_spawn_count)

        canonical = code_owned_local_service_launch_policy()
        forged = object.__new__(type(canonical))
        for field in canonical.__dataclass_fields__:
            object.__setattr__(forged, field, getattr(canonical, field))
        replacements = (
            ("canonical_other", canonical),
            ("copy", copy.copy(canonical)),
            ("object_new", forged),
        )
        for replacement_kind, replacement in replacements:
            for mutation in ("authority", "capability", "coordinated"):
                provider = OneShotProviderSupervisor.for_local_service(
                    selection,
                    turn_timeout_ms=2_000,
                )
                authority = provider._authority
                capability = authority.local_service_capability
                self.assertIsNotNone(capability)
                issued_policy = authority.local_service_policy
                self.assertIs(issued_policy, capability._policy)
                if mutation in {"authority", "coordinated"}:
                    object.__setattr__(authority, "local_service_policy", replacement)
                if mutation in {"capability", "coordinated"}:
                    object.__setattr__(capability, "_policy", replacement)
                with (
                    self.subTest(
                        replacement_kind=replacement_kind,
                        mutation=mutation,
                    ),
                    self.assertRaises(ValueError),
                ):
                    OneShotProviderSupervisor._require_gateway_authority(
                        provider,
                        code_owned_local_service_provider_catalog(),
                    )
                self.assertEqual(0, provider._process_supervisor.local_service_bind_count)
                self.assertEqual(0, provider._process_supervisor.local_service_spawn_count)


class LocalServiceLifecycleTests(unittest.TestCase):
    def _provider(
        self,
        *,
        turn_timeout_ms: int = 2_000,
    ) -> tuple[OneShotProviderSupervisor, ProviderTurnRequest]:
        activation, grant = _documents_for_runtime(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        broker = CapabilityBroker()
        request = _request(activation, grant, max_duration_ms=2_000)
        provider = OneShotProviderSupervisor.for_local_service(
            _local_service_selection(request, broker),
            turn_timeout_ms=turn_timeout_ms,
        )
        turn = ProviderTurnRequest(
            execution_id="exec_local_service_one",
            turn_index=0,
            private_input={"private": "RAW_LOCAL_SERVICE_PRIVATE_SENTINEL"},
            transcript=(),
            tool_summaries=(),
            exposed_tools=(),
        )
        return provider, turn

    def test_clean_unsupported_hosts_import_before_native_preflight(self) -> None:
        source = r"""
import ctypes
import json
import multiprocessing
import os
import signal
import shutil
import subprocess
import sys

sys.platform = sys.argv[1]
for module, names in (
    (subprocess, ("_fork_exec",)),
    (os, (
        "pidfd_open", "waitid", "P_PIDFD", "WEXITED", "WNOHANG",
        "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED",
    )),
    (signal, (
        "pidfd_send_signal", "pthread_sigmask", "SIG_BLOCK",
        "SIG_SETMASK", "SIGKILL", "SIGSTOP",
    )),
):
    for name in names:
        if hasattr(module, name):
            delattr(module, name)

def forbidden_cdll(*_args, **_kwargs):
    raise AssertionError("native libc resolution occurred during portable import")

ctypes.CDLL = forbidden_cdll

from worldforge.agent_harness import (
    AgentExecutionKernel,
    CapabilityBroker,
    ExecutionLimits,
    ExecutionRequest,
    OneShotProviderSupervisor,
    ProviderRuntimeSpec,
)
from worldforge.agent_harness.process_supervisor import (
    LinuxProcessSupervisor,
    ProviderBoundaryUnsupported,
)
from worldforge.agent_harness import local_service as local_service_module
from worldforge.agent_harness import supervisor as supervisor_module

public_contracts = (
    AgentExecutionKernel,
    CapabilityBroker,
    ExecutionLimits,
    ExecutionRequest,
    OneShotProviderSupervisor,
    ProviderRuntimeSpec,
)
actions = []

def forbidden_action(*_args, **_kwargs):
    actions.append("provider_action")
    raise AssertionError("provider action occurred before unsupported rejection")

for name in (
    "code_owned_local_service_launch_policy",
    "_code_owned_local_service_launch_recipe",
    "code_owned_local_service_provider_catalog",
    "runtime_entry_for_local_service_selection",
):
    setattr(supervisor_module, name, forbidden_action)

rejections = []
for operation in (
    lambda: OneShotProviderSupervisor.for_local_service(object()),
    lambda: LinuxProcessSupervisor(),
):
    try:
        operation()
    except ProviderBoundaryUnsupported as exc:
        rejections.append(exc.args)
    else:
        raise AssertionError("unsupported Linux supervisor construction succeeded")

print(json.dumps({
    "actions": actions,
    "authority_loaded": local_service_module._LINUX_AUTHORITY is not None,
    "contracts": [value.__name__ for value in public_contracts],
    "rejections": rejections,
}, sort_keys=True))
"""
        expected_contracts = [
            "AgentExecutionKernel",
            "CapabilityBroker",
            "ExecutionLimits",
            "ExecutionRequest",
            "OneShotProviderSupervisor",
            "ProviderRuntimeSpec",
        ]
        for platform in ("win32", "darwin"):
            completed = subprocess.run(
                [sys.executable, "-c", source, platform],
                check=False,
                capture_output=True,
                text=True,
                timeout=5.0,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            with self.subTest(platform=platform):
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual(
                    {
                        "actions": [],
                        "authority_loaded": False,
                        "contracts": expected_contracts,
                        "rejections": [
                            ["worker_containment_unavailable"],
                            ["worker_containment_unavailable"],
                        ],
                    },
                    json.loads(completed.stdout),
                )

    def test_clean_linux_cpython_311_rejects_before_service_authority(self) -> None:
        source = r"""
import json
import sys
import types

from worldforge.agent_harness import OneShotProviderSupervisor
from worldforge.agent_harness.process_supervisor import ProviderBoundaryUnsupported
from worldforge.agent_harness import supervisor as supervisor_module

actions = []

def audit_effect(event, _args):
    if event in {
        "socket.__new__",
        "socket.bind",
        "socket.connect",
        "subprocess.Popen",
    }:
        actions.append(event)

sys.addaudithook(audit_effect)

def forbidden_action(name):
    def reject(*_args, **_kwargs):
        actions.append(name)
        raise AssertionError(f"{name} occurred before runtime rejection")
    return reject

for name in (
    "code_owned_local_service_launch_policy",
    "_code_owned_local_service_launch_recipe",
    "code_owned_local_service_provider_catalog",
    "runtime_entry_for_local_service_selection",
):
    setattr(supervisor_module, name, forbidden_action(name))
supervisor_module.OneShotProviderSupervisor._initialize = forbidden_action(
    "provider_initialization"
)

sys.platform = "linux"
sys.implementation.name = sys.argv[1]
sys.version_info = types.SimpleNamespace(major=int(sys.argv[2]), minor=int(sys.argv[3]))

try:
    OneShotProviderSupervisor.for_local_service(object())
except Exception as exc:
    result = {
        "actions": actions,
        "exception": type(exc).__name__,
        "reason": getattr(exc, "reason_code", None),
        "args": exc.args,
    }
else:
    result = {
        "actions": actions,
        "exception": None,
        "reason": None,
        "args": (),
    }

print(json.dumps(result, sort_keys=True))
"""
        for implementation, major, minor in (
            ("cpython", 3, 11),
            ("pypy", 3, 12),
            ("cpython", 4, 0),
        ):
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    source,
                    implementation,
                    str(major),
                    str(minor),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5.0,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            with self.subTest(
                implementation=implementation,
                major=major,
                minor=minor,
            ):
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual(
                    {
                        "actions": [],
                        "args": ["worker_containment_unavailable"],
                        "exception": ProviderBoundaryUnsupported.__name__,
                        "reason": "worker_containment_unavailable",
                    },
                    json.loads(completed.stdout),
                )

    def test_clean_linux_import_lazily_seals_stable_authority_hashes(self) -> None:
        source = r"""
import json
from worldforge.agent_harness import local_service

before = local_service._LINUX_AUTHORITY is None
policy = local_service.code_owned_local_service_launch_policy()
recipe = local_service._code_owned_local_service_launch_recipe(policy)
print(json.dumps({
    "authority_loaded": local_service._LINUX_AUTHORITY is not None,
    "before": before,
    "policy": policy.content_hash,
    "recipe": recipe.content_hash,
}, sort_keys=True))
"""
        documents = []
        for _index in range(2):
            completed = subprocess.run(
                [sys.executable, "-c", source],
                check=False,
                capture_output=True,
                text=True,
                timeout=5.0,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            documents.append(json.loads(completed.stdout))
        self.assertEqual(documents[0], documents[1])
        self.assertEqual(True, documents[0]["before"])
        self.assertEqual(True, documents[0]["authority_loaded"])
        self.assertRegex(documents[0]["policy"], r"^[0-9a-f]{64}$")
        self.assertRegex(documents[0]["recipe"], r"^[0-9a-f]{64}$")

    def test_unsupported_platform_and_preflight_stop_have_zero_service_effect(self) -> None:
        activation, grant = _documents_for_runtime(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        broker = CapabilityBroker()
        request = _request(activation, grant, max_duration_ms=2_000)
        selection = _local_service_selection(request, broker)
        with (
            mock.patch.object(supervisor_module.sys, "platform", "win32"),
            mock.patch.object(
                supervisor_module,
                "code_owned_local_service_launch_policy",
                side_effect=AssertionError("provider action occurred"),
            ) as policy_factory,
            self.assertRaises(ProviderBoundaryUnsupported),
        ):
            OneShotProviderSupervisor.for_local_service(selection, turn_timeout_ms=2_000)
        policy_factory.assert_not_called()

        provider, turn = self._provider()
        cleanup_calls: list[dict[str, object]] = []
        real_cleanup = process_supervisor_module._attempt_linux_domain_cleanup
        with self.assertRaises(ProviderBoundaryStopped):
            provider.turn(
                turn,
                boundary=ProviderBoundaryControl(lambda: "execution_cancelled"),
            )
        self.assertEqual(0, provider.spawn_count)
        self.assertEqual(0, provider._process_supervisor.local_service_bind_count)
        self.assertEqual(0, provider._process_supervisor.local_service_spawn_count)

        provider, turn = self._provider()

        def stop_after_worker_identity() -> str | None:
            return "execution_cancelled" if provider.active_worker_pid is not None else None

        def record_cleanup(**kwargs):
            cleanup_calls.append(dict(kwargs))
            return real_cleanup(**kwargs)

        with (
            mock.patch.object(
                process_supervisor_module,
                "_attempt_linux_domain_cleanup",
                side_effect=record_cleanup,
            ),
            mock.patch.object(
                process_supervisor_module,
                "_prove_listener_inode_absent",
                return_value=True,
            ) as absence_proof,
            self.assertRaises(ProviderBoundaryStopped),
        ):
            provider.turn(turn, boundary=ProviderBoundaryControl(stop_after_worker_identity))
        self.assertTrue(cleanup_calls)
        self.assertTrue(
            all(type(call.get("listener_inode")) is int for call in cleanup_calls),
            cleanup_calls,
        )
        absence_proof.assert_called()
        self.assertEqual(1, provider.spawn_count)
        self.assertEqual(1, provider._process_supervisor.local_service_bind_count)
        self.assertEqual(0, provider._process_supervisor.local_service_spawn_count)
        self.assertIsNone(provider.active_broker_pid)
        self.assertIsNone(provider.active_worker_pid)
        self.assertIsNone(provider._process_supervisor.active_local_service_pid)
        self.assertIsNone(provider._process_supervisor.active_local_service_port)

    def test_startup_timeout_and_unexpected_inherited_descriptors_fail_cleanly(self) -> None:
        provider, turn = self._provider(turn_timeout_ms=1)
        with self.assertRaises(ProviderBoundaryFailure):
            provider.turn(turn, boundary=ProviderBoundaryControl(lambda: None))
        self.assertEqual(1, provider._process_supervisor.local_service_bind_count)
        self.assertEqual(0, provider._process_supervisor.local_service_spawn_count)
        self.assertIsNone(provider.active_broker_pid)
        self.assertIsNone(provider.active_worker_pid)
        self.assertIsNone(provider._process_supervisor.active_local_service_pid)
        self.assertIsNone(provider._process_supervisor.active_local_service_port)

        real_popen = local_service_module.subprocess.Popen

        for descriptor_kind in ("pipe", "file", "socket"):
            launched_processes = []

            def popen_with_extra_descriptor(
                *args,
                kind=descriptor_kind,
                processes=launched_processes,
                **kwargs,
            ):
                opened: list[object] = []
                if kind == "pipe":
                    source, peer = os.pipe()
                    opened.extend((source, peer))
                elif kind == "file":
                    source = os.open("/dev/null", os.O_RDONLY)
                    opened.append(source)
                else:
                    owned_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    source = owned_socket.fileno()
                    opened.append(owned_socket)
                high = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, 128)
                try:
                    kwargs["pass_fds"] = (*kwargs["pass_fds"], high)
                    process = real_popen(*args, **kwargs)
                    processes.append(process)
                    return process
                finally:
                    os.close(high)
                    for item in opened:
                        if isinstance(item, int):
                            os.close(item)
                        else:
                            item.close()

            with (
                self.subTest(descriptor_kind=descriptor_kind),
                tempfile.TemporaryDirectory() as scratch,
            ):
                policy = code_owned_local_service_launch_policy()
                recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
                lease = _acquire_local_service_lease(policy, recipe=recipe)
                try:
                    launch = local_service_module._broker_launch_from_lease(
                        lease,
                        key=b"d" * 32,
                        nonce="d" * 64,
                    )
                    with self.assertRaises(LocalServicePolicyError):
                        local_service_module._spawn_code_owned_local_service(
                            launch,
                            scratch=scratch,
                            _test_popen=popen_with_extra_descriptor,
                        )
                    self.assertEqual(1, len(launched_processes))
                    self.assertIsNotNone(launched_processes[0].poll())
                    self.assertNotEqual(0, launched_processes[0].returncode)
                finally:
                    self.assertTrue(_close_local_service_lease(lease))

    def test_readiness_secret_is_absent_until_post_spawn_proof(self) -> None:
        policy = code_owned_local_service_launch_policy()
        recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
        lease = _acquire_local_service_lease(policy, recipe=recipe)
        observed: list[str] = []

        def inspect_gate_then_fail(*_args, **kwargs):
            config_read = kwargs["pass_fds"][1]
            os.set_blocking(config_read, False)
            try:
                observed.append("data" if os.read(config_read, 1) else "eof")
            except BlockingIOError:
                observed.append("blocked")
            raise OSError("intentional pre-spawn seam")

        try:
            launch = local_service_module._broker_launch_from_lease(
                lease,
                key=b"g" * 32,
                nonce="8" * 64,
            )
            with (
                tempfile.TemporaryDirectory() as scratch,
                self.assertRaises(LocalServicePolicyError),
            ):
                local_service_module._spawn_code_owned_local_service(
                    launch,
                    scratch=scratch,
                    _test_popen=inspect_gate_then_fail,
                )
            self.assertEqual(["blocked"], observed)
        finally:
            self.assertTrue(_close_local_service_lease(lease))

    def test_spawn_race_uses_recipe_not_mutable_launch_globals(self) -> None:
        policy = code_owned_local_service_launch_policy()
        recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
        lease = _acquire_local_service_lease(policy, recipe=recipe)
        observed = []

        def inspect_captured_recipe(command, **kwargs):
            observed.append(
                (
                    tuple(command),
                    dict(kwargs["env"]),
                    kwargs.get("preexec_fn"),
                    dict(kwargs),
                )
            )
            raise OSError("intentional pre-popen race seam")

        try:
            launch = local_service_module._broker_launch_from_lease(
                lease,
                key=b"i" * 32,
                nonce="a" * 64,
            )
            with (
                tempfile.TemporaryDirectory() as scratch,
                mock.patch.object(
                    local_service_module,
                    "LOCAL_SERVICE_BOOTSTRAP_SOURCE",
                    "raise SystemExit(73)",
                ),
                mock.patch.object(local_service_module.sys, "executable", "/tmp/hostile"),
                mock.patch.object(
                    local_service_module,
                    "_SERVICE_ENVIRONMENT",
                    (("PYTHONUTF8", "0"),),
                ),
                mock.patch.object(
                    local_service_module,
                    "_local_service_environment",
                    side_effect=AssertionError("mutable environment accessor was used"),
                ) as environment_accessor,
                self.assertRaises(LocalServicePolicyError),
            ):
                local_service_module._spawn_code_owned_local_service(
                    launch,
                    scratch=scratch,
                    _test_popen=inspect_captured_recipe,
                )
            environment_accessor.assert_not_called()
            self.assertEqual(recipe.argv, observed[0][0])
            self.assertEqual(dict(recipe.environment), observed[0][1])
            self.assertEqual(
                {
                    "LC_CTYPE": "C.UTF-8",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONIOENCODING": "utf-8",
                    "PYTHONUTF8": "1",
                },
                observed[0][1],
            )
            self.assertTrue(callable(observed[0][2]))
            self.assertEqual(
                {
                    "close_fds",
                    "cwd",
                    "env",
                    "pass_fds",
                    "preexec_fn",
                    "shell",
                    "stderr",
                    "stdin",
                    "stdout",
                },
                set(observed[0][3]),
            )
        finally:
            self.assertTrue(_close_local_service_lease(lease))

    def test_captured_custody_default_mutation_rejects_before_service_action(self) -> None:
        targets = (
            local_service_module._install_local_service_parent_death_policy,
            local_service_module._fixed_parent_death_preexec,
            local_service_module._require_single_threaded_broker,
            local_service_module._launch_local_service_popen,
            local_service_module._block_local_service_launch_signals,
            local_service_module._restore_local_service_launch_signals,
        )
        for target in targets:
            provider, turn = self._provider()
            defaults = target.__defaults__
            kwdefaults = target.__kwdefaults__
            target.__defaults__ = (*(() if defaults is None else defaults), object())
            target.__kwdefaults__ = {"hostile": object()}
            try:
                with (
                    self.subTest(target=target.__name__),
                    self.assertRaises(ProviderBoundaryFailure),
                ):
                    provider.turn(turn, boundary=ProviderBoundaryControl(lambda: None))
            finally:
                target.__defaults__ = defaults
                target.__kwdefaults__ = kwdefaults
            self.assertEqual(0, provider._process_supervisor.local_service_bind_count)
            self.assertEqual(0, provider._process_supervisor.local_service_spawn_count)

    def test_custody_code_substitution_rejects_before_service_action(self) -> None:
        def substituted(*_args, **_kwargs):
            return None

        targets = (
            local_service_module._install_local_service_parent_death_policy,
            local_service_module._fixed_parent_death_preexec,
            local_service_module._require_single_threaded_broker,
            local_service_module._launch_local_service_popen,
            local_service_module._block_local_service_launch_signals,
            local_service_module._restore_local_service_launch_signals,
        )
        for target in targets:
            provider, turn = self._provider()
            code = target.__code__
            target.__code__ = substituted.__code__
            try:
                with (
                    self.subTest(target=target.__name__),
                    self.assertRaises(ProviderBoundaryFailure),
                ):
                    provider.turn(turn, boundary=ProviderBoundaryControl(lambda: None))
            finally:
                target.__code__ = code
            self.assertEqual(0, provider._process_supervisor.local_service_bind_count)
            self.assertEqual(0, provider._process_supervisor.local_service_spawn_count)

        provider, turn = self._provider()
        with (
            mock.patch.object(local_service_module.subprocess, "Popen", object()),
            self.assertRaises(ProviderBoundaryFailure),
        ):
            provider.turn(turn, boundary=ProviderBoundaryControl(lambda: None))
        self.assertEqual(0, provider._process_supervisor.local_service_bind_count)
        self.assertEqual(0, provider._process_supervisor.local_service_spawn_count)

    def test_same_popen_class_method_mutation_rejects_before_service_action(self) -> None:
        popen = local_service_module._CANONICAL_POPEN

        def substituted_init(self, *_args, **_kwargs):
            self.pid = 1

        for attribute in ("__code__", "__defaults__", "__kwdefaults__"):
            provider, turn = self._provider()
            original = getattr(popen.__init__, attribute)
            hostile = (
                substituted_init.__code__
                if attribute == "__code__"
                else ((object(),) if attribute == "__defaults__" else {"hostile": object()})
            )
            setattr(popen.__init__, attribute, hostile)
            try:
                with (
                    self.subTest(attribute=attribute),
                    self.assertRaises(ProviderBoundaryFailure),
                ):
                    provider.turn(turn, boundary=ProviderBoundaryControl(lambda: None))
            finally:
                setattr(popen.__init__, attribute, original)
            self.assertEqual(0, provider._process_supervisor.local_service_bind_count)
            self.assertEqual(0, provider._process_supervisor.local_service_spawn_count)

        context = multiprocessing.get_context("spawn")
        result_read, result_write = context.Pipe(duplex=False)
        process = context.Process(
            target=_popen_new_mutation_probe,
            args=(result_write,),
        )
        try:
            process.start()
            result_write.close()
            self.assertTrue(result_read.poll(2.0))
            self.assertEqual(b"rejected", result_read.recv_bytes())
            process.join(timeout=2.0)
            self.assertFalse(process.is_alive())
            self.assertEqual(0, process.exitcode)
        finally:
            if process.is_alive():
                process.kill()
                process.join(timeout=0.5)
            result_read.close()
            result_write.close()

        class HostileMeta(type):
            def __call__(cls, *_args, **_kwargs):
                raise AssertionError("hostile metaclass executed")

        class HostilePopen(metaclass=HostileMeta):
            pass

        provider, turn = self._provider()
        with (
            mock.patch.object(local_service_module.subprocess, "Popen", HostilePopen),
            self.assertRaises(ProviderBoundaryFailure),
        ):
            provider.turn(turn, boundary=ProviderBoundaryControl(lambda: None))
        self.assertEqual(0, provider._process_supervisor.local_service_bind_count)
        self.assertEqual(0, provider._process_supervisor.local_service_spawn_count)

    def test_signal_handler_cannot_mutate_popen_between_validation_and_exec(self) -> None:
        policy = code_owned_local_service_launch_policy()
        recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
        lease = _acquire_local_service_lease(policy, recipe=recipe)
        launch = local_service_module._broker_launch_from_lease(
            lease,
            key=b"m" * 32,
            nonce="c" * 64,
        )
        popen_init = local_service_module._CANONICAL_POPEN.__init__
        original_code = popen_init.__code__
        previous_handler = signal.getsignal(signal.SIGUSR1)
        observed_during_launch: list[bool] = []

        def substituted_init(self, *_args, **_kwargs):
            self.pid = 1

        def mutate_popen(_signum, _frame):
            popen_init.__code__ = substituted_init.__code__

        def signal_during_launch(*_args, **_kwargs):
            os.kill(os.getpid(), signal.SIGUSR1)
            observed_during_launch.append(popen_init.__code__ is substituted_init.__code__)
            raise OSError("intentional signal-window seam")

        signal.signal(signal.SIGUSR1, mutate_popen)
        try:
            with (
                tempfile.TemporaryDirectory() as scratch,
                self.assertRaises(LocalServicePolicyError),
            ):
                local_service_module._spawn_code_owned_local_service(
                    launch,
                    scratch=scratch,
                    _test_popen=signal_during_launch,
                )
            self.assertEqual([False], observed_during_launch)
            self.assertIs(popen_init.__code__, substituted_init.__code__)
        finally:
            popen_init.__code__ = original_code
            signal.signal(signal.SIGUSR1, previous_handler)
            self.assertTrue(_close_local_service_lease(lease))

    def test_redirected_child_cwd_fails_before_config_release(self) -> None:
        policy = code_owned_local_service_launch_policy()
        recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
        lease = _acquire_local_service_lease(policy, recipe=recipe)
        launch = local_service_module._broker_launch_from_lease(
            lease,
            key=b"n" * 32,
            nonce="d" * 64,
        )
        real_popen = local_service_module.subprocess.Popen
        spawned = None

        with tempfile.TemporaryDirectory() as scratch, tempfile.TemporaryDirectory() as wrong:

            def redirect_cwd(*args, **kwargs):
                kwargs["cwd"] = wrong
                return real_popen(*args, **kwargs)

            try:
                with self.assertRaises(LocalServicePolicyError):
                    spawned = local_service_module._spawn_code_owned_local_service(
                        launch,
                        scratch=scratch,
                        _test_popen=redirect_cwd,
                    )
            finally:
                if spawned is not None:
                    spawned.process.kill()
                    spawned.process.wait(timeout=0.5)
                    os.close(spawned.control_write_fd)
                    os.close(spawned.ready_read_fd)
                self.assertTrue(_close_local_service_lease(lease))

    def test_mutable_ctypes_lookup_and_native_prctl_dependencies_are_rejected(self) -> None:
        provider, turn = self._provider()

        def hostile_cdll(*_args, **_kwargs):
            raise AssertionError("mutable ctypes lookup executed")

        with (
            mock.patch.object(local_service_module.ctypes, "CDLL", hostile_cdll),
            self.assertRaises(ProviderBoundaryFailure),
        ):
            provider.turn(turn, boundary=ProviderBoundaryControl(lambda: None))
        self.assertEqual(0, provider._process_supervisor.local_service_bind_count)
        self.assertEqual(0, provider._process_supervisor.local_service_spawn_count)

        self.assertIsNotNone(local_service_module._CANONICAL_PRCTL)
        self.assertIsInstance(local_service_module._CANONICAL_PRCTL_ADDRESS, int)
        original_restype = local_service_module._CANONICAL_PRCTL.restype
        local_service_module._CANONICAL_PRCTL.restype = ctypes.c_long
        try:
            with self.assertRaises(LocalServicePolicyError):
                local_service_module._validate_custody_authority()
        finally:
            local_service_module._CANONICAL_PRCTL.restype = original_restype

    def test_audit_hook_cannot_replace_low_level_exec_authority(self) -> None:
        context = multiprocessing.get_context("spawn")
        result_read, result_write = context.Pipe(duplex=False)
        process = context.Process(
            target=_audit_fork_exec_mutation_probe,
            args=(result_write,),
        )
        try:
            process.start()
            result_write.close()
            self.assertTrue(result_read.poll(2.0))
            self.assertEqual((True, False), result_read.recv())
            process.join(timeout=2.0)
            self.assertFalse(process.is_alive())
            self.assertEqual(0, process.exitcode)
        finally:
            if process.is_alive():
                process.kill()
                process.join(timeout=0.5)
            result_read.close()
            result_write.close()

    def test_transitive_fsencode_mutation_is_outside_launch_authority(self) -> None:
        context = multiprocessing.get_context("spawn")
        result_read, result_write = context.Pipe(duplex=False)
        process = context.Process(
            target=_transitive_fsencode_mutation_probe,
            args=(result_write,),
        )
        try:
            process.start()
            result_write.close()
            self.assertTrue(result_read.poll(2.0))
            self.assertEqual(("accepted", False), result_read.recv())
            process.join(timeout=2.0)
            self.assertFalse(process.is_alive())
            self.assertEqual(0, process.exitcode)
        finally:
            if process.is_alive():
                process.kill()
                process.join(timeout=0.5)
            result_read.close()
            result_write.close()

    def test_audit_hook_cannot_observe_preexec_or_mutable_restorer_authority(self) -> None:
        context = multiprocessing.get_context("spawn")
        for target, expected in (
            (_audit_preexec_frame_probe, False),
            (_audit_signal_restorer_probe, (False, True)),
        ):
            result_read, result_write = context.Pipe(duplex=False)
            process = context.Process(target=target, args=(result_write,))
            try:
                process.start()
                result_write.close()
                self.assertTrue(result_read.poll(2.0))
                self.assertEqual(expected, result_read.recv())
                process.join(timeout=2.0)
                self.assertFalse(process.is_alive())
                self.assertEqual(0, process.exitcode)
            finally:
                if process.is_alive():
                    process.kill()
                    process.join(timeout=0.5)
                result_read.close()
                result_write.close()

    def test_audit_hook_constructor_mutation_is_rejected_before_execution(self) -> None:
        context = multiprocessing.get_context("spawn")
        result_read, result_write = context.Pipe(duplex=False)
        process = context.Process(
            target=_audit_process_constructor_probe,
            args=(result_write,),
        )
        try:
            process.start()
            result_write.close()
            self.assertTrue(result_read.poll(2.0))
            self.assertEqual((True, False), result_read.recv())
            process.join(timeout=2.0)
            self.assertFalse(process.is_alive())
            self.assertEqual(0, process.exitcode)
        finally:
            if process.is_alive():
                process.kill()
                process.join(timeout=0.5)
            result_read.close()
            result_write.close()

    def test_process_handle_retries_eintr_and_never_signals_a_reused_pid(self) -> None:
        closed: list[int] = []
        sent: list[tuple[int, int]] = []
        poll_results = iter(
            (
                InterruptedError(),
                None,
                InterruptedError(),
                SimpleNamespace(si_pid=321, si_code=os.CLD_EXITED, si_status=7),
            )
        )

        def waitid(_idtype, _pidfd, _options):
            result = next(poll_results)
            if isinstance(result, BaseException):
                raise result
            return result

        process = local_service_module._LocalServiceProcess(
            pid=321,
            pidfd=9,
            stdout=None,
            stderr=None,
        )
        self.assertIsNone(process.poll(_waitid=waitid, _close=closed.append))
        self.assertEqual(7, process.wait(timeout=0.1, _waitid=waitid, _close=closed.append))
        self.assertEqual([9], closed)
        process.close(_close=closed.append)
        process.close(_close=closed.append)
        self.assertEqual([9], closed)

        externally_reaped = local_service_module._LocalServiceProcess(
            pid=654,
            pidfd=10,
            stdout=None,
            stderr=None,
        )

        def reaped_waitid(_idtype, _pidfd, _options):
            raise ChildProcessError()

        with self.assertRaises(LocalServicePolicyError):
            externally_reaped.kill(
                _waitid=reaped_waitid,
                _pidfd_send_signal=lambda pidfd, signum, *_args: sent.append((pidfd, signum)),
                _close=closed.append,
            )
        self.assertEqual([], sent)
        self.assertEqual([9, 10], closed)

    def test_process_handle_kill_retries_eintr_and_destructor_closes_once(self) -> None:
        closed: list[int] = []
        calls = iter((InterruptedError(), None))
        sends = iter((InterruptedError(), None))

        def waitid(_idtype, _pidfd, _options):
            result = next(calls)
            if isinstance(result, BaseException):
                raise result
            return result

        def send(_pidfd, _signal, _siginfo, _flags):
            result = next(sends)
            if isinstance(result, BaseException):
                raise result

        process = local_service_module._LocalServiceProcess(
            pid=987,
            pidfd=11,
            stdout=None,
            stderr=None,
        )
        process.kill(
            _waitid=waitid,
            _pidfd_send_signal=send,
            _close=closed.append,
        )
        self.assertEqual([], closed)
        process.__del__(_close=closed.append, _waitid=lambda *_args: None)
        process.__del__(_close=closed.append, _waitid=lambda *_args: None)
        self.assertEqual([11], closed)

    def test_signal_is_blocked_before_single_thread_proof(self) -> None:
        policy = code_owned_local_service_launch_policy()
        recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
        lease = _acquire_local_service_lease(policy, recipe=recipe)
        launch = local_service_module._broker_launch_from_lease(
            lease,
            key=b"s" * 32,
            nonce="1" * 64,
        )
        previous_handler = signal.getsignal(signal.SIGUSR1)
        handler_ran: list[bool] = []
        observed_before_proof: list[bool] = []

        def handler(_signum, _frame):
            thread = threading.Thread(target=lambda: handler_ran.append(True))
            thread.start()
            thread.join(timeout=0.5)

        def before_single_thread() -> None:
            os.kill(os.getpid(), signal.SIGUSR1)
            observed_before_proof.append(bool(handler_ran))

        def fail_launch(*_args, **_kwargs):
            raise OSError("intentional post-proof seam")

        signal.signal(signal.SIGUSR1, handler)
        try:
            with (
                tempfile.TemporaryDirectory() as scratch,
                self.assertRaises(LocalServicePolicyError),
            ):
                local_service_module._spawn_code_owned_local_service(
                    launch,
                    scratch=scratch,
                    _test_before_single_thread=before_single_thread,
                    _test_popen=fail_launch,
                )
            self.assertEqual([False], observed_before_proof)
            self.assertEqual([True], handler_ran)
        finally:
            signal.signal(signal.SIGUSR1, previous_handler)
            self.assertTrue(_close_local_service_lease(lease))

    def test_dependency_fingerprint_is_typed_canonical_and_transitive(self) -> None:
        fingerprint = local_service_module._dependency_fingerprint
        self.assertNotEqual(fingerprint((1, 2)), fingerprint([1, 2]))
        self.assertNotEqual(fingerprint((1, 2)), fingerprint(frozenset((1, 2))))
        self.assertEqual(
            {"type": "bytes", "value_base64": "AP8="},
            fingerprint(b"\x00\xff"),
        )

        dependency_value = 1

        def dependency(value=dependency_value):
            return value

        def authority():
            return dependency()

        original_defaults = dependency.__defaults__
        before = fingerprint(authority)
        dependency.__defaults__ = (2,)
        try:
            self.assertNotEqual(before, fingerprint(authority))
        finally:
            dependency.__defaults__ = original_defaults

        def closure_factory(value):
            def closure():
                return value

            return closure

        closure = closure_factory(b"closed")
        self.assertIn("value_base64", json.dumps(fingerprint(closure), sort_keys=True))

    def test_parent_death_installer_uses_exact_prctl_and_fails_closed(self) -> None:
        class FakePrctl:
            def __init__(self, result: int) -> None:
                self.result = result
                self.calls: list[tuple[int, ...]] = []
                self.argtypes = None
                self.restype = None

            def __call__(self, *args):
                self.calls.append(args)
                return self.result

        successful = FakePrctl(0)
        local_service_module._install_local_service_parent_death_policy(
            77,
            successful,
            lambda: errno.EPERM,
            lambda: 77,
            lambda _code: self.fail("matching PPID exited"),
            signal.SIGKILL,
        )
        self.assertEqual([(1, signal.SIGKILL, 0, 0, 0)], successful.calls)

        failed = FakePrctl(-1)
        with self.assertRaises(OSError) as raised:
            local_service_module._install_local_service_parent_death_policy(
                77,
                failed,
                lambda: errno.EPERM,
                lambda: 77,
                lambda _code: None,
                signal.SIGKILL,
            )
        self.assertEqual(errno.EPERM, raised.exception.errno)

        exits: list[int] = []
        no_op = FakePrctl(0)
        local_service_module._install_local_service_parent_death_policy(
            77,
            no_op,
            lambda: errno.EPERM,
            lambda: 1,
            exits.append,
            signal.SIGKILL,
        )
        self.assertEqual([70], exits)

    def test_preconfig_parent_death_proof_rejects_noop_prctl_state(self) -> None:
        class RunningProcess:
            @staticmethod
            def poll():
                return None

        for custody_signal, accepted in ((signal.SIGKILL, True), (0, False)):
            proof = _canonical(
                {
                    "blocked_signal_mask": "0000000000000000",
                    "format": local_service_module._PARENT_DEATH_PROOF_FORMAT,
                    "format_version": 1,
                    "parent_death_signal": custody_signal,
                    "service_pid": 321,
                    "service_ppid": 123,
                    "service_start_time": 456,
                }
            )
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, len(proof).to_bytes(4, "big") + proof)
                os.set_blocking(read_fd, False)
                if accepted:
                    self.assertEqual(
                        proof,
                        local_service_module._read_parent_death_proof(
                            RunningProcess(),
                            ready_read_fd=read_fd,
                            expected_pid=321,
                            expected_ppid=123,
                            expected_start_time=456,
                        ),
                    )
                else:
                    with self.assertRaises(LocalServicePolicyError):
                        local_service_module._read_parent_death_proof(
                            RunningProcess(),
                            ready_read_fd=read_fd,
                            expected_pid=321,
                            expected_ppid=123,
                            expected_start_time=456,
                        )
            finally:
                os.close(read_fd)
                os.close(write_fd)

    def test_preconfig_parent_death_proof_rejects_blocked_signal_mask_mismatch(self) -> None:
        class RunningProcess:
            @staticmethod
            def poll():
                return None

        for actual_mask, accepted in (("0000000000000000", True), ("fffffffe7ffbfeff", False)):
            proof = _canonical(
                {
                    "blocked_signal_mask": actual_mask,
                    "format": local_service_module._PARENT_DEATH_PROOF_FORMAT,
                    "format_version": 1,
                    "parent_death_signal": signal.SIGKILL,
                    "service_pid": 321,
                    "service_ppid": 123,
                    "service_start_time": 456,
                }
            )
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, len(proof).to_bytes(4, "big") + proof)
                os.set_blocking(read_fd, False)
                if accepted:
                    self.assertEqual(
                        proof,
                        local_service_module._read_parent_death_proof(
                            RunningProcess(),
                            ready_read_fd=read_fd,
                            expected_pid=321,
                            expected_ppid=123,
                            expected_start_time=456,
                            expected_signal_mask="0000000000000000",
                        ),
                    )
                else:
                    with self.assertRaises(LocalServicePolicyError):
                        local_service_module._read_parent_death_proof(
                            RunningProcess(),
                            ready_read_fd=read_fd,
                            expected_pid=321,
                            expected_ppid=123,
                            expected_start_time=456,
                            expected_signal_mask="0000000000000000",
                        )
            finally:
                os.close(read_fd)
                os.close(write_fd)

    def test_privilege_changing_executable_is_rejected(self) -> None:
        executable = os.path.realpath(sys.executable)
        metadata = os.stat(executable, follow_symlinks=False)
        values = list(metadata)
        values[0] |= stat.S_ISUID | stat.S_ISGID
        privileged = os.stat_result(values)
        with (
            mock.patch.object(local_service_module.os, "stat", return_value=privileged),
            self.assertRaises(LocalServicePolicyError),
        ):
            local_service_module._executable_snapshot(executable)

        with (
            mock.patch.object(local_service_module.os, "getxattr", return_value=b"capability"),
            self.assertRaises(LocalServicePolicyError),
        ):
            local_service_module._executable_snapshot(executable)

    def test_parent_death_preexec_requires_a_single_threaded_broker(self) -> None:
        current = mock.Mock()
        current.name = str(os.getpid())
        sibling = mock.Mock()
        sibling.name = str(os.getpid() + 1)
        scanner = mock.MagicMock()
        scanner.__enter__.return_value = [current, sibling]
        scanner.__exit__.return_value = False

        with self.assertRaises(LocalServicePolicyError):
            local_service_module._require_single_threaded_broker(
                os.getpid(),
                _scandir=lambda _path: scanner,
            )

        current_only = mock.MagicMock()
        current_only.__enter__.return_value = [current]
        current_only.__exit__.return_value = False
        for callback_name in ("_gettrace", "_getprofile"):
            dependencies = {
                "_getpid": os.getpid,
                "_scandir": lambda _path: current_only,
                "_gettrace": lambda: None,
                "_getprofile": lambda: None,
            }
            dependencies[callback_name] = lambda: object()
            with self.subTest(callback=callback_name), self.assertRaises(LocalServicePolicyError):
                local_service_module._require_single_threaded_broker(
                    os.getpid(),
                    **dependencies,
                )

    def test_listener_inode_observation_never_tracks_or_signals_unrelated_holder(self) -> None:
        listener_inode = 12345
        candidate_pid = 45678
        entry = mock.Mock(path=f"/proc/{candidate_pid}/fd/9")
        scanner = mock.MagicMock()
        scanner.__enter__.return_value = [entry]
        scanner.__exit__.return_value = False
        metadata = mock.Mock(st_uid=os.geteuid())

        with (
            mock.patch.object(
                process_supervisor_module,
                "_process_table",
                return_value={candidate_pid: (1, 222, "S")},
            ),
            mock.patch.object(process_supervisor_module.os, "stat", return_value=metadata),
            mock.patch.object(process_supervisor_module.os, "scandir", return_value=scanner),
            mock.patch.object(
                process_supervisor_module.os,
                "readlink",
                return_value=f"socket:[{listener_inode}]",
            ),
            mock.patch.object(
                process_supervisor_module,
                "_proc_identity",
                return_value=(1, 222, "S"),
            ),
            mock.patch.object(
                process_supervisor_module,
                "_retain_linux_identity",
                side_effect=AssertionError("listener observation granted signal authority"),
            ) as retain,
            mock.patch.object(
                process_supervisor_module,
                "_signal_identity",
                side_effect=AssertionError("listener observation signalled an unrelated holder"),
            ) as send_signal,
        ):
            self.assertFalse(process_supervisor_module._prove_listener_inode_absent(listener_inode))
        retain.assert_not_called()
        send_signal.assert_not_called()

    def test_inaccessible_plausible_listener_holder_prevents_absence_proof(self) -> None:
        candidate_pid = 45679
        metadata = mock.Mock(st_uid=os.geteuid())
        with (
            mock.patch.object(
                process_supervisor_module,
                "_process_table",
                return_value={candidate_pid: (1, 223, "S")},
            ),
            mock.patch.object(process_supervisor_module.os, "stat", return_value=metadata),
            mock.patch.object(
                process_supervisor_module.os,
                "scandir",
                side_effect=PermissionError("denied"),
            ),
        ):
            self.assertFalse(process_supervisor_module._prove_listener_inode_absent(12346))

    def test_pid_reuse_during_listener_scan_prevents_absence_proof(self) -> None:
        candidate_pid = 45680
        entry = mock.Mock(path=f"/proc/{candidate_pid}/fd/9")
        scanner = mock.MagicMock()
        scanner.__enter__.return_value = [entry]
        scanner.__exit__.return_value = False
        metadata = mock.Mock(st_uid=os.geteuid())
        with (
            mock.patch.object(
                process_supervisor_module,
                "_process_table",
                return_value={candidate_pid: (1, 224, "S")},
            ),
            mock.patch.object(process_supervisor_module.os, "stat", return_value=metadata),
            mock.patch.object(process_supervisor_module.os, "scandir", return_value=scanner),
            mock.patch.object(process_supervisor_module.os, "readlink", return_value="pipe:[1]"),
            mock.patch.object(
                process_supervisor_module,
                "_proc_identity",
                return_value=(1, 225, "S"),
            ),
        ):
            self.assertFalse(process_supervisor_module._prove_listener_inode_absent(12347))

    def test_older_listener_holder_is_never_excluded_from_absence_proof(self) -> None:
        listener_inode = 12348
        candidate_pid = 45681
        entry = mock.Mock(path=f"/proc/{candidate_pid}/fd/9")
        scanner = mock.MagicMock()
        scanner.__enter__.return_value = [entry]
        scanner.__exit__.return_value = False
        metadata = mock.Mock(st_uid=os.geteuid())
        with (
            mock.patch.object(
                process_supervisor_module,
                "_process_table",
                return_value={candidate_pid: (1, 100, "S")},
            ),
            mock.patch.object(process_supervisor_module.os, "stat", return_value=metadata),
            mock.patch.object(process_supervisor_module.os, "scandir", return_value=scanner),
            mock.patch.object(
                process_supervisor_module.os,
                "readlink",
                return_value=f"socket:[{listener_inode}]",
            ),
            mock.patch.object(
                process_supervisor_module,
                "_proc_identity",
                return_value=(1, 100, "S"),
            ),
        ):
            self.assertFalse(process_supervisor_module._prove_listener_inode_absent(listener_inode))

    def test_older_inaccessible_holder_is_never_excluded_from_absence_proof(self) -> None:
        candidate_pid = 45682
        metadata = mock.Mock(st_uid=os.geteuid())
        with (
            mock.patch.object(
                process_supervisor_module,
                "_process_table",
                return_value={candidate_pid: (1, 100, "S")},
            ),
            mock.patch.object(process_supervisor_module.os, "stat", return_value=metadata),
            mock.patch.object(
                process_supervisor_module.os,
                "scandir",
                side_effect=PermissionError("denied"),
            ),
        ):
            self.assertFalse(process_supervisor_module._prove_listener_inode_absent(12349))

    def test_launch_recipe_drift_has_zero_bind_spawn_or_service_action(self) -> None:
        for field, hostile in (
            ("bootstrap_source", "raise SystemExit(73)"),
            ("environment", (("PYTHONUTF8", "0"),)),
            ("parent_death_policy_hash", "0" * 64),
            ("executable", "/tmp/worldforge-hostile-python"),
            ("executable_inode", 1),
        ):
            provider, turn = self._provider()
            recipe = provider._authority.local_service_recipe
            self.assertIsNotNone(recipe)
            original = getattr(recipe, field)
            object.__setattr__(recipe, field, hostile)
            try:
                with (
                    self.subTest(field=field),
                    self.assertRaises(ProviderBoundaryFailure),
                ):
                    provider.turn(
                        turn,
                        boundary=ProviderBoundaryControl(lambda: None),
                    )
            finally:
                object.__setattr__(recipe, field, original)
            self.assertEqual(0, provider.spawn_count)
            self.assertEqual(0, provider._process_supervisor.local_service_bind_count)
            self.assertEqual(0, provider._process_supervisor.local_service_spawn_count)
            self.assertIsNone(provider.active_broker_pid)
            self.assertIsNone(provider.active_worker_pid)
            self.assertIsNone(provider._process_supervisor.active_local_service_pid)

    def test_substituted_child_cannot_read_secret_before_proc_proof(self) -> None:
        policy = code_owned_local_service_launch_policy()
        recipe = local_service_module._code_owned_local_service_launch_recipe(policy)
        lease = _acquire_local_service_lease(policy, recipe=recipe)
        real_popen = local_service_module.subprocess.Popen
        real_attest = local_service_module._attest_spawned_local_service_process
        observation_read, observation_write = os.pipe()
        launched = []

        def substitute_child(_command, **kwargs):
            config_read = kwargs["pass_fds"][1]
            source = (
                "import os,time\n"
                f"os.set_blocking({config_read},False)\n"
                "try:\n"
                f" data=os.read({config_read},1)\n"
                " state=b'data' if data else b'eof'\n"
                "except BlockingIOError:\n"
                " state=b'blocked'\n"
                f"os.write({observation_write},state)\n"
                "time.sleep(1)\n"
            )
            kwargs["pass_fds"] = (*kwargs["pass_fds"], observation_write)
            process = real_popen(
                (
                    recipe.executable,
                    "-I",
                    "-B",
                    "-S",
                    "-u",
                    "-X",
                    "utf8",
                    "-c",
                    source,
                ),
                **kwargs,
            )
            launched.append(process)
            return process

        def attest_after_probe(*args, **kwargs):
            os.set_blocking(observation_read, False)
            deadline = local_service_module.time.monotonic() + 0.25
            while local_service_module.time.monotonic() < deadline:
                try:
                    observed = os.read(observation_read, 16)
                except BlockingIOError:
                    local_service_module.time.sleep(0.001)
                    continue
                self.assertEqual(b"blocked", observed)
                break
            else:
                self.fail("substituted child did not reach the pre-proof gate")
            return real_attest(*args, **kwargs)

        try:
            launch = local_service_module._broker_launch_from_lease(
                lease,
                key=b"h" * 32,
                nonce="9" * 64,
            )
            with (
                tempfile.TemporaryDirectory() as scratch,
                mock.patch.object(
                    local_service_module,
                    "_attest_spawned_local_service_process",
                    attest_after_probe,
                ),
                self.assertRaises(LocalServicePolicyError),
            ):
                local_service_module._spawn_code_owned_local_service(
                    launch,
                    scratch=scratch,
                    _test_popen=substitute_child,
                )
            self.assertEqual(1, len(launched))
            self.assertIsNotNone(launched[0].poll())
        finally:
            os.close(observation_read)
            os.close(observation_write)
            self.assertTrue(_close_local_service_lease(lease))

    def test_preconnected_attacker_can_only_force_closed_failure(self) -> None:
        provider, turn = self._provider()
        real_acquire = process_supervisor_module._acquire_local_service_lease
        attacker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        def acquire_with_attacker(*args, **kwargs):
            lease = real_acquire(*args, **kwargs)
            attacker.connect((lease.host, lease.port))
            attacker.sendall(b"GET /forged-ready HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            return lease

        try:
            with (
                mock.patch.object(
                    process_supervisor_module,
                    "_acquire_local_service_lease",
                    acquire_with_attacker,
                ),
                self.assertRaises((ProviderBoundaryFailure, ProviderBoundaryIndeterminate)),
            ):
                provider.turn(turn, boundary=ProviderBoundaryControl(lambda: None))
            attacker.settimeout(1)
            try:
                received = attacker.recv(1)
            except ConnectionResetError:
                received = b""
            self.assertEqual(b"", received)
        finally:
            attacker.close()
        self.assertIsNone(provider.active_broker_pid)
        self.assertIsNone(provider.active_worker_pid)
        self.assertIsNone(provider._process_supervisor.active_local_service_pid)
        self.assertIsNone(provider._process_supervisor.active_local_service_port)

    def test_crash_after_first_request_byte_is_indeterminate_and_clean(self) -> None:
        provider, turn = self._provider()
        real_execute = process_supervisor_module.execute_loopback_exchange
        real_socket = loopback_gateway_module.socket.socket
        crashed = False

        class CrashServiceAfterFirstSend(real_socket):
            def send(self, data, *args, **kwargs):
                nonlocal crashed
                sent = super().send(data, *args, **kwargs)
                if sent > 0 and not crashed:
                    service_pid = provider._process_supervisor.active_local_service_pid
                    if service_pid is None:
                        raise AssertionError("service attestation was not retained before send")
                    os.kill(service_pid, signal.SIGKILL)
                    crashed = True
                return sent

        def execute_with_crash(*args, **kwargs):
            with mock.patch.object(
                loopback_gateway_module.socket,
                "socket",
                CrashServiceAfterFirstSend,
            ):
                return real_execute(*args, **kwargs)

        with (
            mock.patch.object(
                process_supervisor_module,
                "execute_loopback_exchange",
                execute_with_crash,
            ),
            self.assertRaises(ProviderBoundaryIndeterminate),
        ):
            provider.turn(turn, boundary=ProviderBoundaryControl(lambda: None))
        self.assertTrue(crashed)
        self.assertEqual(1, provider._process_supervisor.local_service_spawn_count)
        self.assertIsNone(provider.active_broker_pid)
        self.assertIsNone(provider.active_worker_pid)
        self.assertIsNone(provider._process_supervisor.active_local_service_pid)
        self.assertIsNone(provider._process_supervisor.active_local_service_port)

    def test_broker_death_after_owned_service_handoff_leaves_no_service_or_listener(self) -> None:
        provider, turn = self._provider()
        real_acquire = process_supervisor_module._acquire_local_service_lease

        with tempfile.TemporaryDirectory() as temporary:
            port_path = Path(temporary, "port")
            outcome: list[BaseException | None] = []

            def acquire_and_record(*args, **kwargs):
                lease = real_acquire(*args, **kwargs)
                port_path.write_text(str(lease.port), encoding="ascii")
                return lease

            def run_turn():
                try:
                    provider.turn(turn, boundary=ProviderBoundaryControl(lambda: None))
                except BaseException as exc:
                    outcome.append(exc)
                else:
                    outcome.append(None)

            with mock.patch.object(
                process_supervisor_module,
                "_acquire_local_service_lease",
                acquire_and_record,
            ):
                runner = threading.Thread(target=run_turn)
                runner.start()
                deadline = process_supervisor_module.time.monotonic() + 2.0
                while (
                    provider._process_supervisor.active_local_service_pid is None
                    and process_supervisor_module.time.monotonic() < deadline
                ):
                    process_supervisor_module.time.sleep(0.001)
                service_pid = provider._process_supervisor.active_local_service_pid
                broker_pid = provider.active_broker_pid
                self.assertIsNotNone(service_pid)
                self.assertIsNotNone(broker_pid)
                os.kill(broker_pid, signal.SIGKILL)
                runner.join(timeout=3.0)
                self.assertFalse(runner.is_alive())
            self.assertEqual(1, len(outcome))
            self.assertIsInstance(outcome[0], ProviderBoundaryIndeterminate)
            self.assertIsNone(process_supervisor_module._proc_identity(service_pid))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as successor:
                successor.bind(("127.0.0.1", int(port_path.read_text(encoding="ascii"))))
        self.assertIsNone(provider._process_supervisor.active_local_service_pid)
        self.assertIsNone(provider._process_supervisor.active_local_service_port)

    def _assert_broker_death_before_service_handoff(
        self,
        *,
        phase: str,
    ) -> None:
        provider, turn = self._provider()
        real_acquire = process_supervisor_module._acquire_local_service_lease
        real_execute = provider._process_supervisor._execute_with_scratch
        context = multiprocessing.get_context("spawn")
        spawned_read, spawned_write = context.Pipe(duplex=False)
        self.addCleanup(spawned_read.close)
        self.addCleanup(spawned_write.close)
        release_read, release_write = context.Pipe(duplex=False)
        self.addCleanup(release_read.close)
        self.addCleanup(release_write.close)
        synchronization = process_supervisor_module._BrokerTestSynchronization(
            spawned=spawned_write,
            release=release_read,
            phase=phase,
        )

        with tempfile.TemporaryDirectory() as temporary:
            lease_path = Path(temporary, "lease")
            outcome: list[BaseException | None] = []

            def acquire_and_record(*args, **kwargs):
                lease = real_acquire(*args, **kwargs)
                lease_path.write_text(f"{lease.port}:{lease.listener_inode}", encoding="ascii")
                return lease

            def run_turn():
                try:
                    provider.turn(turn, boundary=ProviderBoundaryControl(lambda: None))
                except BaseException as exc:
                    outcome.append(exc)
                else:
                    outcome.append(None)

            def execute_with_barrier(*args, **kwargs):
                return real_execute(
                    *args,
                    **kwargs,
                    broker_test_synchronization=synchronization,
                )

            service_pid: int | None = None
            service_start: int | None = None
            with (
                mock.patch.object(
                    process_supervisor_module,
                    "_acquire_local_service_lease",
                    acquire_and_record,
                ),
                mock.patch.object(
                    provider._process_supervisor,
                    "_execute_with_scratch",
                    execute_with_barrier,
                ),
            ):
                runner = threading.Thread(target=run_turn)
                runner.start()
                deadline = process_supervisor_module.time.monotonic() + 2.0
                while (
                    not lease_path.exists() or provider.active_broker_pid is None
                ) and process_supervisor_module.time.monotonic() < deadline:
                    process_supervisor_module.time.sleep(0.001)
                self.assertTrue(lease_path.exists())
                port_text, inode_text = lease_path.read_text(encoding="ascii").split(":")
                listener_inode = int(inode_text)
                broker_pid = provider.active_broker_pid
                self.assertIsNotNone(broker_pid)
                self.assertTrue(spawned_read.poll(2.0))
                service_pid = int(spawned_read.recv_bytes().decode("ascii"))
                children = (
                    Path(f"/proc/{broker_pid}/task/{broker_pid}/children")
                    .read_text(encoding="ascii")
                    .split()
                )
                self.assertIn(str(service_pid), children)
                holder_deadline = process_supervisor_module.time.monotonic() + 0.25
                holds_listener = False
                while process_supervisor_module.time.monotonic() < holder_deadline:
                    try:
                        holds_listener = any(
                            os.readlink(descriptor) == f"socket:[{listener_inode}]"
                            for descriptor in Path(f"/proc/{service_pid}/fd").iterdir()
                        )
                        if holds_listener:
                            break
                    except OSError:
                        pass
                    process_supervisor_module.time.sleep(0.001)
                self.assertTrue(holds_listener)
                service_identity = process_supervisor_module._proc_identity(service_pid)
                self.assertIsNotNone(service_identity)
                service_start = service_identity[1]
                self.assertIsNone(provider._process_supervisor.active_local_service_pid)
                before_stop = process_supervisor_module._proc_identity(service_pid)
                self.assertIsNotNone(before_stop)
                self.assertEqual(service_start, before_stop[1])
                os.kill(service_pid, signal.SIGSTOP)
                stop_deadline = process_supervisor_module.time.monotonic() + 0.25
                stopped = process_supervisor_module._proc_identity(service_pid)
                while (
                    stopped is not None
                    and stopped[2] not in {"T", "t"}
                    and process_supervisor_module.time.monotonic() < stop_deadline
                ):
                    process_supervisor_module.time.sleep(0.001)
                    stopped = process_supervisor_module._proc_identity(service_pid)
                self.assertIsNotNone(stopped)
                self.assertIn(stopped[2], {"T", "t"})
                os.kill(broker_pid, signal.SIGKILL)
                release_write.send_bytes(b"1")
                runner.join(timeout=0.25)
                returned_without_cleanup = not runner.is_alive()
                if not returned_without_cleanup:
                    current = process_supervisor_module._proc_identity(service_pid)
                    if current is not None and current[1] == service_start:
                        os.kill(service_pid, signal.SIGKILL)
                    runner.join(timeout=3.0)
                self.assertFalse(runner.is_alive())
            try:
                self.assertEqual(1, len(outcome))
                self.assertIsInstance(outcome[0], ProviderBoundaryIndeterminate)
                self.assertTrue(returned_without_cleanup)
                self.assertIsNone(process_supervisor_module._proc_identity(service_pid))
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as successor:
                    successor.bind(("127.0.0.1", int(port_text)))
            finally:
                spawned_read.close()
                spawned_write.close()
                release_read.close()
                release_write.close()
                if service_pid is not None:
                    current = process_supervisor_module._proc_identity(service_pid)
                    if current is not None and current[1] == service_start:
                        os.kill(service_pid, signal.SIGKILL)

    def test_broker_death_during_popen_leaves_no_listener_holder(self) -> None:
        self._assert_broker_death_before_service_handoff(phase="post_popen")

    def test_broker_death_after_preconfig_proof_leaves_no_listener_holder(self) -> None:
        self._assert_broker_death_before_service_handoff(phase="post_proof")

    def test_listener_close_uncertainty_is_indeterminate_after_real_cleanup(self) -> None:
        provider, turn = self._provider()
        real_close = process_supervisor_module._close_local_service_lease

        def close_but_report_uncertain(value):
            self.assertTrue(real_close(value))
            return False

        with (
            mock.patch.object(
                process_supervisor_module,
                "_close_local_service_lease",
                close_but_report_uncertain,
            ),
            self.assertRaises(ProviderBoundaryIndeterminate),
        ):
            provider.turn(turn, boundary=ProviderBoundaryControl(lambda: None))
        self.assertEqual(1, provider._process_supervisor.local_service_spawn_count)
        self.assertIsNone(provider.active_broker_pid)
        self.assertIsNone(provider.active_worker_pid)
        self.assertIsNone(provider._process_supervisor.active_local_service_pid)
        self.assertIsNone(provider._process_supervisor.active_local_service_port)

    def test_native_service_is_attested_socket_restricted_and_domain_empty_on_return(self) -> None:
        provider, turn = self._provider()
        result = provider.turn(turn, boundary=ProviderBoundaryControl(lambda: None))

        self.assertEqual(
            [
                {
                    "format": "world-forge.synthetic.local_service_health",
                    "ready": True,
                    "revision": 1,
                },
                {
                    "accepted": True,
                    "format": "world-forge.synthetic.local_service_operation",
                    "revision": 1,
                },
            ],
            result.private_output["gateway_response"],
        )
        self.assertNotIn(
            "RAW_LOCAL_SERVICE_PRIVATE_SENTINEL",
            json.dumps(result.private_output, sort_keys=True),
        )
        self.assertEqual(1, provider.spawn_count)
        self.assertEqual(1, provider._process_supervisor.local_service_bind_count)
        self.assertEqual(1, provider._process_supervisor.local_service_spawn_count)
        self.assertIsNone(provider.active_broker_pid)
        self.assertIsNone(provider.active_worker_pid)
        self.assertIsNone(provider._process_supervisor.active_local_service_pid)
        self.assertIsNone(provider._process_supervisor.active_local_service_port)

    def test_kernel_terminal_duplicate_has_zero_additional_bind_spawn_or_connect(self) -> None:
        activation, grant = _documents_for_runtime(_CodeOwnedRuntimeKey.DETERMINISTIC_PROBE)
        broker = CapabilityBroker()
        request = _request(activation, grant, max_duration_ms=2_000)
        catalog = code_owned_local_service_provider_catalog()
        selection = _local_service_selection(request, broker)
        request = replace(
            request,
            provider_approval_id="provider_approval_local_service_01",
            provider_selection=selection,
        )
        authority = InMemoryProviderGovernanceAuthority()
        provider = OneShotProviderSupervisor.for_local_service(
            selection,
            turn_timeout_ms=2_000,
        )

        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as journal:
            kernel = AgentExecutionKernel(
                provider=provider,
                broker=broker,
                journal=journal,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
                provider_catalog=catalog,
                provider_governance_authority=authority,
            )
            review = kernel.prepare_provider_governance_review(request)
            authority.decide(
                ProviderGovernanceDecision.create(
                    review=review,
                    reviewer_id="provider_reviewer_local_service_01",
                    outcome="approved",
                    expires_at_ms=5_000,
                ),
                expected_generation=0,
                expected_review_hash=review.content_hash,
            )
            coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=journal)
            first = coordinator.execute(request)
            before = (
                provider.spawn_count,
                provider._process_supervisor.local_service_bind_count,
                provider._process_supervisor.local_service_spawn_count,
            )
            with (
                mock.patch.object(
                    loopback_gateway_module.socket,
                    "socket",
                    side_effect=AssertionError("duplicate connect effect occurred"),
                ) as socket_constructor,
                mock.patch.object(
                    process_supervisor_module,
                    "_close_local_service_lease",
                    side_effect=AssertionError("duplicate cleanup effect occurred"),
                ) as lease_cleanup,
            ):
                duplicate = coordinator.execute(request)
            socket_constructor.assert_not_called()
            lease_cleanup.assert_not_called()
            after = (
                provider.spawn_count,
                provider._process_supervisor.local_service_bind_count,
                provider._process_supervisor.local_service_spawn_count,
            )
            durable = b"".join(
                path.read_bytes() for path in Path(temporary).rglob("*") if path.is_file()
            )

        self.assertEqual("succeeded", first.result.outcome)
        self.assertEqual("existing_terminal", duplicate.disposition)
        self.assertEqual((1, 1, 1), before)
        self.assertEqual(before, after)
        for private in (
            b"RAW_LOCAL_SERVICE_PRIVATE_SENTINEL",
            b"127.0.0.1",
            b"world-forge.synthetic.local_service_health",
        ):
            self.assertNotIn(private, durable)


class LocalServiceCompatibilityPinsTests(unittest.TestCase):
    def test_public_eventlog_worker_and_protocol_sources_remain_byte_identical(self) -> None:
        root = Path(__file__).resolve().parents[1]
        expected = {
            "src/worldforge/agent_harness/kernel.py": (
                "621514a6853adff3dac4ead8ba396e532ad2c565bf1d25234a87a85508b42b6f"
            ),
            "src/worldforge/agent_harness/ports.py": (
                "c36fae5d9493ef667614d5a6ac740df5c2fe27a97ec27cd9f210d159fe1d65c6"
            ),
            "src/worldforge/agent_harness/event_log.py": (
                "025e340983229a176382d0e9bf886796a8924ca38bdc87414c848d7034d30d37"
            ),
            "src/worldforge/agent_harness/worker.py": (
                "6b818249f8cca6bcca397f96f5dc37e1e6c13e07f3cb3d7962714556a9396a63"
            ),
            "src/worldforge/agent_harness/worker_protocol.py": (
                "0f2e93e27103eaf359f424ce2cb62dfd31d3a283717af75838031cde77c04470"
            ),
            "src/worldforge/agent_harness/loopback_protocol.py": (
                "e884f1586c4c202b32d167b34214ba84ab7c8d645bfcc6bca35df924301e2d25"
            ),
            "schemas/agent-capability-grant.schema.json": (
                "102d55a9934ef97e9d155557f4999c3b8d74654f9eeb566a54d3a6cf2e6b86cf"
            ),
            "schemas/agent-event.schema.json": (
                "82c9a51b913758cbec69cf81c6646a7b52043e16b45a96f60816f74bd63bed27"
            ),
            "schemas/agent-execution-receipt.schema.json": (
                "3ed9fe19b189e47552c2e68aab827e00d148ed209958654754fcbb3e90a54f4a"
            ),
            "schemas/agent-memory-projection.schema.json": (
                "dc3ec9f77f0d85a03033a33acd7e6738467ec668cfb893263b618cb57bc283b4"
            ),
            "schemas/agent-worker-activation.schema.json": (
                "40888648df32abb8c682dfd8e683bf5a4743a9d366905ed8b2ed89d047930d5b"
            ),
        }
        self.assertEqual(
            expected,
            {
                relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
                for relative in expected
            },
        )


if __name__ == "__main__":
    unittest.main()
