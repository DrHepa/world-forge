from __future__ import annotations

import errno
import hashlib
import json
import socket
import subprocess
import sys
import unittest
from contextlib import contextmanager
from dataclasses import replace
from unittest import mock

from worldforge.agent_harness import process_supervisor as process_supervisor_module
from worldforge.agent_harness import provider_egress as provider_egress_module
from worldforge.agent_harness.process_supervisor import (
    ProviderBoundaryFailure,
    ProviderBoundaryUnsupported,
)
from worldforge.agent_harness.provider_egress import provider_egress_enforcement_profile
from worldforge.agent_harness.worker_registry import (
    _CodeOwnedRuntimeKey,
    code_owned_provider_catalog,
    runtime_entry,
)


def _filtered_python(source: str, *, pass_fds: tuple[int, ...] = ()) -> subprocess.CompletedProcess:
    return subprocess.run(
        (sys.executable, "-I", "-B", "-S", "-u", "-X", "utf8", "-c", source),
        capture_output=True,
        close_fds=True,
        pass_fds=pass_fds,
        preexec_fn=provider_egress_module._install_provider_egress_enforcement,
        timeout=3,
        check=False,
    )


def _simulate_filter(machine: str, syscall_number: int, *, argument0: int = 0) -> int:
    program = next(
        item for item in provider_egress_module._ARCHITECTURE_PROGRAMS if item.machine == machine
    )
    accumulator = 0
    program_counter = 0
    instructions = provider_egress_module._instructions(program)
    values = {
        provider_egress_module._SECCOMP_DATA_ARCH_OFFSET: program.audit_arch,
        provider_egress_module._SECCOMP_DATA_NR_OFFSET: syscall_number,
        provider_egress_module._SECCOMP_DATA_ARG0_OFFSET: argument0,
    }
    while program_counter < len(instructions):
        code, jump_true, jump_false, value = instructions[program_counter]
        if code == provider_egress_module._BPF_LD_W_ABS:
            accumulator = values[value]
            program_counter += 1
        elif code == provider_egress_module._BPF_JMP_JEQ_K:
            program_counter += 1 + (jump_true if accumulator == value else jump_false)
        elif code == provider_egress_module._BPF_JMP_JSET_K:
            program_counter += 1 + (jump_true if accumulator & value else jump_false)
        elif code == provider_egress_module._BPF_RET_K:
            return value
        else:
            raise AssertionError(f"unknown BPF instruction {code}")
    raise AssertionError("filter program did not return")


@contextmanager
def _connected_socket_pair(family: int):
    if family == socket.AF_UNIX:
        first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            yield first, second
        finally:
            first.close()
            second.close()
        return

    listener = socket.socket(family, socket.SOCK_STREAM)
    client = socket.socket(family, socket.SOCK_STREAM)
    accepted = None
    try:
        if family == socket.AF_INET:
            listener.bind(("127.0.0.1", 0))
        elif family == socket.AF_INET6:
            listener.bind(("::1", 0))
        else:
            raise AssertionError("unsupported test family")
        listener.listen(1)
        client.connect(listener.getsockname())
        accepted, _address = listener.accept()
        yield client, accepted
    finally:
        listener.close()
        client.close()
        if accepted is not None:
            accepted.close()


class ProviderEgressProfileTests(unittest.TestCase):
    def test_x86_64_x32_syscall_aliases_fail_closed_before_native_matching(self) -> None:
        x32_bit = 0x40000000
        denied = provider_egress_module._SECCOMP_RET_ERRNO | errno.EPERM
        for native_number in (0, 39, 41, 435):
            with self.subTest(native_number=native_number):
                self.assertEqual(
                    denied,
                    _simulate_filter("x86_64", native_number | x32_bit),
                )
        self.assertEqual(
            provider_egress_module._SECCOMP_RET_ALLOW,
            _simulate_filter("x86_64", 39),
        )

    def test_filter_denies_descriptor_acquisition_and_async_network_routes(self) -> None:
        denied = provider_egress_module._SECCOMP_RET_ERRNO | errno.EPERM
        routes = {
            "aarch64": (97, 212, 243, 268, 280, 425, 434, 438),
            "x86_64": (47, 272, 299, 308, 321, 425, 434, 438),
        }
        for machine, syscall_numbers in routes.items():
            for syscall_number in syscall_numbers:
                with self.subTest(machine=machine, syscall=syscall_number):
                    self.assertEqual(
                        denied,
                        _simulate_filter(machine, syscall_number),
                    )

    def test_profile_pins_exact_linux_architectures_filter_launcher_and_hash(self) -> None:
        profile = provider_egress_enforcement_profile()
        document = profile.as_document()

        self.assertEqual("deny_all_direct_network", profile.mode)
        self.assertEqual(("linux",), profile.supported_platforms)
        self.assertEqual(
            ("linux/aarch64/audit-c00000b7", "linux/x86_64/audit-c000003e"),
            profile.architecture_identities,
        )
        self.assertEqual(
            "a17cdbc24b77961aaeec0545803d6b1d37da1ccd955569eea955b89bba2b7296",
            profile.filter_hash,
        )
        self.assertEqual(
            "225a7d144ded2f529f7b073359c3d977106d7b0e359d217a31536907f8913cc9",
            profile.launcher_hash,
        )
        expected = hashlib.sha256(
            json.dumps(
                {name: value for name, value in document.items() if name != "content_hash"},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(expected, profile.content_hash)
        self.assertEqual(
            "8fb13baab64fc9ec770178998f3455e2f93ab276ae918ab4550a28827cb05c50",
            profile.content_hash,
        )
        self.assertEqual(profile.content_hash, document["content_hash"])

    def test_profile_rejects_hostile_exact_types_and_returns_detached_identity(self) -> None:
        profile = provider_egress_enforcement_profile()

        class HostileTuple(tuple):
            pass

        for field, value in (
            ("mode", type("HostileStr", (str,), {})(profile.mode)),
            ("supported_platforms", HostileTuple(profile.supported_platforms)),
            ("architecture_identities", HostileTuple(profile.architecture_identities)),
            ("filter_hash", type("HostileHash", (str,), {})(profile.filter_hash)),
            ("launcher_hash", type("HostileHash", (str,), {})(profile.launcher_hash)),
            ("content_hash", type("HostileHash", (str,), {})(profile.content_hash)),
        ):
            with self.subTest(field=field):
                hostile = replace(profile, **{field: value})
                with self.assertRaisesRegex(RuntimeError, "provider_egress_profile_invalid"):
                    provider_egress_module._validate_provider_egress_profile(hostile)

        leaked = provider_egress_enforcement_profile()
        object.__setattr__(leaked, "mode", "caller_supplied")
        self.assertEqual("deny_all_direct_network", provider_egress_enforcement_profile().mode)

    def test_every_code_owned_runtime_spec_binds_the_exact_egress_profile_hash(self) -> None:
        profile = provider_egress_enforcement_profile()
        catalog = code_owned_provider_catalog()

        self.assertEqual(2, len(catalog.specs))
        for spec in catalog.specs:
            with self.subTest(runtime=spec.runtime_id):
                self.assertEqual("none", spec.network_scope)
                self.assertEqual(profile.content_hash, spec.egress_enforcement_hash)

        for key in _CodeOwnedRuntimeKey:
            with self.subTest(key=key):
                entry = runtime_entry(key)
                self.assertEqual(profile, entry.egress_enforcement)
                self.assertEqual(profile.content_hash, entry.spec.egress_enforcement_hash)

    def test_profile_or_spec_tampering_fails_before_launch_authority(self) -> None:
        entry = runtime_entry(_CodeOwnedRuntimeKey.CONFORMANCE)
        hostile_profile = replace(entry.egress_enforcement, mode="caller_supplied")
        hostile_entry = replace(entry, egress_enforcement=hostile_profile)
        with self.assertRaises(ProviderBoundaryFailure):
            process_supervisor_module._capture_runtime_launch(hostile_entry)

        hostile_spec = replace(entry.spec, egress_enforcement_hash="0" * 64)
        hostile_entry = replace(entry, spec=hostile_spec)
        with self.assertRaises(ProviderBoundaryFailure):
            process_supervisor_module._capture_runtime_launch(hostile_entry)


@unittest.skipUnless(sys.platform == "linux", "seccomp enforcement is Linux-only")
class LinuxProviderEgressEnforcementTests(unittest.TestCase):
    def test_real_child_reports_no_new_privs_and_seccomp_filter_before_action(self) -> None:
        source = r"""
from pathlib import Path

fields = {}
for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
    if line.startswith(("NoNewPrivs:", "Seccomp:")):
        name, value = line.split(":", 1)
        fields[name] = int(value.strip())
print(fields["NoNewPrivs"], fields["Seccomp"])
"""
        completed = _filtered_python(source)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("1 2", completed.stdout.decode("ascii").strip())

    def test_real_child_denies_ipv4_ipv6_and_unix_socket_creation(self) -> None:
        source = r"""
import errno
import json
import socket

result = {}
for name, family in (("ipv4", socket.AF_INET), ("ipv6", socket.AF_INET6), ("unix", socket.AF_UNIX)):
    try:
        socket.socket(family, socket.SOCK_STREAM)
    except OSError as exc:
        result[name] = exc.errno
    else:
        result[name] = 0
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
"""
        completed = _filtered_python(source)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(
            {"ipv4": errno.EPERM, "ipv6": errno.EPERM, "unix": errno.EPERM},
            json.loads(completed.stdout),
        )

    def test_launcher_rejects_valid_connected_ipv4_ipv6_and_unix_descriptors(self) -> None:
        worker_source = "import os; os.write(INHERITED_FD, b'request-derived-action')"
        for name, family in (
            ("ipv4", socket.AF_INET),
            ("ipv6", socket.AF_INET6),
            ("unix", socket.AF_UNIX),
        ):
            with self.subTest(family=name), _connected_socket_pair(family) as (worker, peer):
                attempted = worker_source.replace("INHERITED_FD", str(worker.fileno()))
                launcher = provider_egress_module._provider_worker_launcher_source(attempted)
                completed = subprocess.run(
                    (sys.executable, "-I", "-B", "-S", "-u", "-X", "utf8", "-c", launcher),
                    capture_output=True,
                    close_fds=True,
                    pass_fds=(worker.fileno(),),
                    timeout=3,
                    check=False,
                )
                self.assertEqual(70, completed.returncode)
                self.assertEqual(b"", completed.stdout)
                self.assertEqual(b"", completed.stderr)
                peer.setblocking(False)
                with self.assertRaises(BlockingIOError):
                    peer.recv(1)

    def test_filter_is_inherited_across_fork_and_exec_without_breaking_pipe_ipc(self) -> None:
        source = r"""
import os
import sys

pid = os.fork()
if pid == 0:
    child_source = (
        "import errno,socket\n"
        "try: socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
        "except OSError as exc: print(exc.errno)\n"
        "else: print(0)"
    )
    os.execv(
        sys.executable,
        (sys.executable, "-I", "-B", "-S", "-u", "-X", "utf8", "-c",
         child_source),
    )
_, status = os.waitpid(pid, 0)
if status != 0:
    raise SystemExit(71)
"""
        completed = _filtered_python(source)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(str(errno.EPERM), completed.stdout.decode("ascii").strip())

    def test_filter_denies_network_namespace_escape_syscalls(self) -> None:
        source = r"""
import ctypes
import errno
import json
import platform

numbers = {
    "aarch64": (97, 268),
    "x86_64": (272, 308),
}[platform.machine()]
libc = ctypes.CDLL(None, use_errno=True)
result = []
for number, arguments in ((numbers[0], (0x40000000,)), (numbers[1], (-1, 0x40000000))):
    ctypes.set_errno(0)
    returned = libc.syscall(number, *arguments)
    result.append((returned, ctypes.get_errno()))
print(json.dumps(result, separators=(",", ":")))
"""
        completed = _filtered_python(source)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual([[-1, errno.EPERM], [-1, errno.EPERM]], json.loads(completed.stdout))

    def test_real_child_denies_pidfd_descriptor_acquisition_syscalls(self) -> None:
        source = r"""
import ctypes
import json
import os

libc = ctypes.CDLL(None, use_errno=True)
result = []
for number, arguments in ((434, (os.getpid(), 0)), (438, (-1, 0, 0))):
    ctypes.set_errno(0)
    returned = libc.syscall(number, *arguments)
    result.append((returned, ctypes.get_errno()))
print(json.dumps(result, separators=(",", ":")))
"""
        completed = _filtered_python(source)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual([[-1, errno.EPERM], [-1, errno.EPERM]], json.loads(completed.stdout))

    def test_preflight_and_setup_fail_closed_without_raw_error_text(self) -> None:
        with mock.patch.object(provider_egress_module.platform, "machine", return_value="riscv64"):
            with self.assertRaisesRegex(
                provider_egress_module.ProviderEgressEnforcementUnavailable,
                "worker_containment_unavailable",
            ):
                provider_egress_module._preflight_provider_egress_enforcement()

        for failed_call in (1, 2):
            calls = 0

            def fail_prctl(*_args, target=failed_call):
                nonlocal calls
                calls += 1
                return -1 if calls == target else 0

            with self.subTest(failed_call=failed_call):
                with mock.patch.object(
                    provider_egress_module,
                    "_call_prctl",
                    side_effect=fail_prctl,
                ):
                    with self.assertRaisesRegex(
                        provider_egress_module.ProviderEgressEnforcementUnavailable,
                        "worker_containment_unavailable",
                    ) as caught:
                        provider_egress_module._install_provider_egress_enforcement()
                self.assertNotIn("prctl", str(caught.exception))
                self.assertNotIn("seccomp", str(caught.exception))

    def test_descriptor_census_errors_fail_closed_before_prctl(self) -> None:
        for operation in ("scandir", "fstat"):
            with (
                self.subTest(operation=operation),
                mock.patch.object(provider_egress_module.os, operation) as failed,
            ):
                failed.side_effect = OSError("raw census error must not escape")
                with mock.patch.object(
                    provider_egress_module,
                    "_call_prctl",
                    return_value=0,
                ) as prctl:
                    with self.assertRaisesRegex(
                        provider_egress_module.ProviderEgressEnforcementUnavailable,
                        "worker_containment_unavailable",
                    ) as caught:
                        provider_egress_module._install_provider_egress_enforcement()
                prctl.assert_not_called()
                self.assertNotIn("census", str(caught.exception))

    def test_runtime_launch_uses_exact_clean_fd_launcher_before_worker_source(self) -> None:
        entry = runtime_entry(_CodeOwnedRuntimeKey.CONFORMANCE)
        launch = process_supervisor_module._capture_runtime_launch(entry)
        observed: dict[str, object] = {}

        class FailedSetup:
            def __init__(self, command, **kwargs):
                observed["command"] = command
                observed.update(kwargs)
                raise subprocess.SubprocessError("raw spawn failure")

        with (
            mock.patch.object(process_supervisor_module.subprocess, "Popen", FailedSetup),
            self.assertRaises(ProviderBoundaryFailure) as caught,
        ):
            process_supervisor_module._spawn_code_owned_worker(launch, "/tmp")
        self.assertEqual("provider_failed", str(caught.exception))
        self.assertNotIn("spawn", str(caught.exception))
        self.assertNotIn("preexec_fn", observed)
        self.assertTrue(observed["close_fds"])
        self.assertEqual((), observed["pass_fds"])
        launcher = observed["command"][8]
        self.assertEqual(
            provider_egress_module._provider_worker_launcher_source(
                entry.artifact.bootstrap_source
            ),
            launcher,
        )
        self.assertNotEqual(entry.artifact.bootstrap_source, launcher)
        main_offset = launcher.index("def main():")
        census_offset = launcher.index("assert_no_socket_descriptors()", main_offset)
        filter_offset = launcher.index("install_filter()", main_offset)
        exec_offset = launcher.index("os.execve(", main_offset)
        self.assertLess(census_offset, filter_offset)
        self.assertLess(filter_offset, exec_offset)

    def test_forged_launch_command_environment_or_profile_causes_zero_spawn(self) -> None:
        entry = runtime_entry(_CodeOwnedRuntimeKey.CONFORMANCE)
        launch = process_supervisor_module._capture_runtime_launch(entry)
        cases = (
            ("command", replace(launch, command=("/bin/sh",))),
            ("environment", replace(launch, environment=(("PATH", "/tmp"),))),
            (
                "profile",
                replace(
                    launch,
                    egress_enforcement=replace(
                        launch.egress_enforcement,
                        launcher_hash="0" * 64,
                    ),
                ),
            ),
        )
        for label, hostile in cases:
            with self.subTest(case=label):
                with mock.patch.object(process_supervisor_module.subprocess, "Popen") as spawn:
                    with self.assertRaises(ProviderBoundaryFailure):
                        process_supervisor_module._spawn_code_owned_worker(hostile, "/tmp")
                spawn.assert_not_called()

    def test_unsupported_os_or_arch_rejects_launch_preflight_before_spawn(self) -> None:
        entry = runtime_entry(_CodeOwnedRuntimeKey.CONFORMANCE)
        with mock.patch.object(provider_egress_module.sys, "platform", "win32"):
            with self.assertRaises(ProviderBoundaryUnsupported):
                process_supervisor_module._capture_runtime_launch(entry)
        with mock.patch.object(provider_egress_module.platform, "machine", return_value="riscv64"):
            with self.assertRaises(ProviderBoundaryUnsupported):
                process_supervisor_module._capture_runtime_launch(entry)


if __name__ == "__main__":
    unittest.main()
