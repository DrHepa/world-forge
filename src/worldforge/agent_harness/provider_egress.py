"""Private code-owned deny-all direct-network enforcement for provider workers."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import stat
import sys
from dataclasses import dataclass, replace

_PROFILE_ERROR = "provider_egress_profile_invalid"
_UNAVAILABLE = "worker_containment_unavailable"
_PROFILE_FORMAT = "world-forge.private.provider_egress_enforcement_profile"
_FILTER_FORMAT = "world-forge.private.seccomp_bpf"
_FORMAT_VERSION = 1
_MODE = "deny_all_direct_network"
_SUPPORTED_PLATFORMS = ("linux",)

_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_EPERM = 1

_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_JMP_JSET_K = 0x45
_BPF_RET_K = 0x06
_SECCOMP_DATA_NR_OFFSET = 0
_SECCOMP_DATA_ARCH_OFFSET = 4
_SECCOMP_DATA_ARG0_OFFSET = 16
_CLONE_NAMESPACE_MASK = 0x7E020080
_X32_SYSCALL_BIT = 0x40000000

_FILTER_PROGRAMS_TOKEN = "__WORLD_FORGE_FILTER_PROGRAMS__"
_WORKER_SOURCE_TOKEN = "__WORLD_FORGE_WORKER_SOURCE__"
_PROVIDER_WORKER_LAUNCHER_TEMPLATE = r"""
import ctypes
import os
import stat
import sys

FILTER_PROGRAMS = __WORLD_FORGE_FILTER_PROGRAMS__
WORKER_SOURCE = __WORLD_FORGE_WORKER_SOURCE__

class SockFilter(ctypes.Structure):
    _fields_ = (
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    )

class SockFprog(ctypes.Structure):
    _fields_ = (
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(SockFilter)),
    )

def assert_no_socket_descriptors():
    with os.scandir("/proc/self/fd") as entries:
        for entry in entries:
            if not entry.name.isascii() or not entry.name.isdigit():
                raise RuntimeError()
            if stat.S_ISSOCK(os.fstat(int(entry.name)).st_mode):
                raise RuntimeError()

def install_filter():
    if sys.platform != "linux":
        raise RuntimeError()
    machine = os.uname().machine
    if machine not in FILTER_PROGRAMS:
        raise RuntimeError()
    instructions = FILTER_PROGRAMS[machine]
    filters = (SockFilter * len(instructions))(
        *(SockFilter(*instruction) for instruction in instructions)
    )
    program = SockFprog(
        len=len(instructions),
        filter=ctypes.cast(filters, ctypes.POINTER(SockFilter)),
    )
    prctl = ctypes.CDLL(None, use_errno=True).prctl
    prctl.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    prctl.restype = ctypes.c_int
    if prctl(38, 1, 0, 0, 0) != 0:
        raise RuntimeError()
    if prctl(22, 2, ctypes.addressof(program), 0, 0) != 0:
        raise RuntimeError()

def main():
    if len(sys.argv) != 1 or not os.path.isabs(sys.executable):
        raise RuntimeError()
    assert_no_socket_descriptors()
    install_filter()
    os.execve(
        sys.executable,
        (sys.executable, "-I", "-B", "-S", "-u", "-X", "utf8", "-c", WORKER_SOURCE),
        dict(os.environ),
    )

try:
    main()
except BaseException:
    os._exit(70)
"""


@dataclass(frozen=True, slots=True)
class _ArchitectureProgram:
    machine: str
    audit_arch: int
    clone_syscall: int
    denied_syscalls: tuple[int, ...]

    @property
    def identity(self) -> str:
        return f"linux/{self.machine}/audit-{self.audit_arch:08x}"


# Reviewed syscall identities for Linux's native aarch64 and x86_64 ABIs.  The
# lists deny socket creation and socket-specific use, io_uring creation (which
# otherwise exposes socket/connect operations), and namespace-changing entry
# points.  Ordinary clone/fork remains available, but clone namespace flags do
# not.
_ARCHITECTURE_PROGRAMS = (
    _ArchitectureProgram(
        machine="aarch64",
        audit_arch=0xC00000B7,
        clone_syscall=220,
        denied_syscalls=(
            97,  # unshare
            198,  # socket
            199,  # socketpair
            200,  # bind
            201,  # listen
            202,  # accept
            203,  # connect
            204,  # getsockname
            205,  # getpeername
            206,  # sendto
            207,  # recvfrom
            208,  # setsockopt
            209,  # getsockopt
            210,  # shutdown
            211,  # sendmsg
            212,  # recvmsg
            242,  # accept4
            243,  # recvmmsg
            268,  # setns
            269,  # sendmmsg
            280,  # bpf
            425,  # io_uring_setup
            434,  # pidfd_open
            435,  # clone3
            438,  # pidfd_getfd
        ),
    ),
    _ArchitectureProgram(
        machine="x86_64",
        audit_arch=0xC000003E,
        clone_syscall=56,
        denied_syscalls=(
            41,  # socket
            42,  # connect
            43,  # accept
            44,  # sendto
            45,  # recvfrom
            46,  # sendmsg
            47,  # recvmsg
            48,  # shutdown
            49,  # bind
            50,  # listen
            51,  # getsockname
            52,  # getpeername
            53,  # socketpair
            54,  # setsockopt
            55,  # getsockopt
            272,  # unshare
            288,  # accept4
            299,  # recvmmsg
            307,  # sendmmsg
            308,  # setns
            321,  # bpf
            425,  # io_uring_setup
            434,  # pidfd_open
            435,  # clone3
            438,  # pidfd_getfd
        ),
    ),
)


class ProviderEgressEnforcementUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__(_UNAVAILABLE)


class _SockFilter(ctypes.Structure):
    _fields_ = (
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    )


class _SockFprog(ctypes.Structure):
    _fields_ = (
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    )


def _instructions(program: _ArchitectureProgram) -> tuple[tuple[int, int, int, int], ...]:
    instructions: list[tuple[int, int, int, int]] = [
        (_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARCH_OFFSET),
        (_BPF_JMP_JEQ_K, 1, 0, program.audit_arch),
        (_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        (_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_NR_OFFSET),
    ]
    if program.machine == "x86_64":
        instructions.extend(
            (
                (_BPF_JMP_JSET_K, 0, 1, _X32_SYSCALL_BIT),
                (_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | _EPERM),
            )
        )
    for syscall_number in program.denied_syscalls:
        instructions.extend(
            (
                (_BPF_JMP_JEQ_K, 0, 1, syscall_number),
                (_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | _EPERM),
            )
        )
    instructions.extend(
        (
            (_BPF_JMP_JEQ_K, 0, 3, program.clone_syscall),
            (_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARG0_OFFSET),
            (_BPF_JMP_JSET_K, 0, 1, _CLONE_NAMESPACE_MASK),
            (_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | _EPERM),
            (_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW),
        )
    )
    return tuple(instructions)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _filter_document() -> dict[str, object]:
    return {
        "format": _FILTER_FORMAT,
        "format_version": _FORMAT_VERSION,
        "architectures": [
            {
                "audit_arch": program.audit_arch,
                "instructions": [list(item) for item in _instructions(program)],
                "machine": program.machine,
            }
            for program in _ARCHITECTURE_PROGRAMS
        ],
    }


def _launcher_hash() -> str:
    return hashlib.sha256(_PROVIDER_WORKER_LAUNCHER_TEMPLATE.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ProviderEgressEnforcementProfile:
    mode: str
    supported_platforms: tuple[str, ...]
    architecture_identities: tuple[str, ...]
    filter_hash: str
    launcher_hash: str
    content_hash: str

    def as_document(self) -> dict[str, object]:
        return {
            "format": _PROFILE_FORMAT,
            "format_version": _FORMAT_VERSION,
            "mode": self.mode,
            "supported_platforms": list(self.supported_platforms),
            "architecture_identities": list(self.architecture_identities),
            "filter_hash": self.filter_hash,
            "launcher_hash": self.launcher_hash,
            "content_hash": self.content_hash,
        }


def _build_profile() -> ProviderEgressEnforcementProfile:
    values: dict[str, object] = {
        "format": _PROFILE_FORMAT,
        "format_version": _FORMAT_VERSION,
        "mode": _MODE,
        "supported_platforms": list(_SUPPORTED_PLATFORMS),
        "architecture_identities": [program.identity for program in _ARCHITECTURE_PROGRAMS],
        "filter_hash": _hash(_filter_document()),
        "launcher_hash": _launcher_hash(),
    }
    return ProviderEgressEnforcementProfile(
        mode=_MODE,
        supported_platforms=_SUPPORTED_PLATFORMS,
        architecture_identities=tuple(values["architecture_identities"]),
        filter_hash=str(values["filter_hash"]),
        launcher_hash=str(values["launcher_hash"]),
        content_hash=_hash(values),
    )


_CANONICAL_PROFILE = _build_profile()


def _validate_provider_egress_profile(value: object) -> ProviderEgressEnforcementProfile:
    if (
        type(value) is not ProviderEgressEnforcementProfile
        or type(value.mode) is not str
        or type(value.supported_platforms) is not tuple
        or any(type(item) is not str for item in tuple.__iter__(value.supported_platforms))
        or type(value.architecture_identities) is not tuple
        or any(type(item) is not str for item in tuple.__iter__(value.architecture_identities))
        or type(value.filter_hash) is not str
        or type(value.launcher_hash) is not str
        or type(value.content_hash) is not str
        or value != _CANONICAL_PROFILE
        or value.as_document() != _CANONICAL_PROFILE.as_document()
    ):
        raise RuntimeError(_PROFILE_ERROR)
    return replace(value)


def provider_egress_enforcement_profile() -> ProviderEgressEnforcementProfile:
    """Return a detached exact profile for the code-owned worker launcher."""

    return _validate_provider_egress_profile(_CANONICAL_PROFILE)


def _provider_worker_launcher_source(worker_source: object) -> str:
    if (
        type(worker_source) is not str
        or not worker_source
        or _PROVIDER_WORKER_LAUNCHER_TEMPLATE.count(_FILTER_PROGRAMS_TOKEN) != 1
        or _PROVIDER_WORKER_LAUNCHER_TEMPLATE.count(_WORKER_SOURCE_TOKEN) != 1
    ):
        raise RuntimeError(_PROFILE_ERROR)
    programs = {program.machine: _instructions(program) for program in _ARCHITECTURE_PROGRAMS}
    return _PROVIDER_WORKER_LAUNCHER_TEMPLATE.replace(
        _FILTER_PROGRAMS_TOKEN,
        repr(programs),
    ).replace(
        _WORKER_SOURCE_TOKEN,
        repr(worker_source),
    )


def _current_program() -> _ArchitectureProgram:
    if sys.platform != "linux":
        raise ProviderEgressEnforcementUnavailable()
    machine = platform.machine()
    matches = tuple(program for program in _ARCHITECTURE_PROGRAMS if program.machine == machine)
    if len(matches) != 1:
        raise ProviderEgressEnforcementUnavailable()
    return matches[0]


def _preflight_provider_egress_enforcement(
    profile: object | None = None,
) -> ProviderEgressEnforcementProfile:
    checked = (
        provider_egress_enforcement_profile()
        if profile is None
        else (_validate_provider_egress_profile(profile))
    )
    _current_program()
    try:
        function = ctypes.CDLL(None, use_errno=True).prctl
    except (AttributeError, OSError):
        raise ProviderEgressEnforcementUnavailable() from None
    if function is None:
        raise ProviderEgressEnforcementUnavailable()
    return checked


def _call_prctl(option: int, argument2: int, argument3: int, argument4: int, argument5: int) -> int:
    function = ctypes.CDLL(None, use_errno=True).prctl
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    function.restype = ctypes.c_int
    return int(function(option, argument2, argument3, argument4, argument5))


def _assert_no_socket_descriptors() -> None:
    try:
        entries = os.scandir("/proc/self/fd")
        with entries:
            for entry in entries:
                if (
                    type(entry.name) is not str
                    or not entry.name.isascii()
                    or not entry.name.isdigit()
                ):
                    raise ProviderEgressEnforcementUnavailable()
                descriptor = int(entry.name)
                if stat.S_ISSOCK(os.fstat(descriptor).st_mode):
                    raise ProviderEgressEnforcementUnavailable()
    except ProviderEgressEnforcementUnavailable:
        raise
    except BaseException:
        raise ProviderEgressEnforcementUnavailable() from None


def _install_provider_egress_enforcement() -> None:
    """Install the inherited exact deny filter in the child immediately before exec."""

    _preflight_provider_egress_enforcement()
    _assert_no_socket_descriptors()
    program = _current_program()
    raw_instructions = _instructions(program)
    filters = (_SockFilter * len(raw_instructions))(
        *(_SockFilter(*instruction) for instruction in raw_instructions)
    )
    filter_program = _SockFprog(
        len=len(raw_instructions),
        filter=ctypes.cast(filters, ctypes.POINTER(_SockFilter)),
    )
    try:
        if _call_prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise ProviderEgressEnforcementUnavailable()
        if (
            _call_prctl(
                _PR_SET_SECCOMP,
                _SECCOMP_MODE_FILTER,
                ctypes.addressof(filter_program),
                0,
                0,
            )
            != 0
        ):
            raise ProviderEgressEnforcementUnavailable()
    except ProviderEgressEnforcementUnavailable:
        raise
    except BaseException:
        raise ProviderEgressEnforcementUnavailable() from None


__all__ = (
    "ProviderEgressEnforcementProfile",
    "provider_egress_enforcement_profile",
)
