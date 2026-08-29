"""Private code-owned synthetic loopback service and one-use lease authority."""

from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import hmac
import json
import os
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import BuiltinFunctionType, CodeType, FunctionType, ModuleType
from weakref import ReferenceType, ref

_POLICY_ERROR = "local_service_policy_invalid"
_POLICY_FORMAT = "world-forge.private.local_service_launch_policy"
_READY_FORMAT = "world-forge.private.local_service_ready"
_FORMAT_VERSION = 1
_SERVICE_REVISION = 1
_BIND_HOST = "127.0.0.1"
_BIND_PORT = 0
_LISTEN_BACKLOG = 2
_READY_FRAME_LIMIT = 8 * 1024
_PARENT_DEATH_PROOF_LIMIT = 1024
_PARENT_DEATH_PROOF_FORMAT = "world-forge.private.local_service_parent_death_proof"
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNAL_MASK_RE = re.compile(r"^[0-9a-f]{16}$")
_LINUX_SIGKILL = 9
_LINUX_SIGSTOP = 19
_LINUX_PIDFD_ID = 3
_LINUX_WNOHANG = 1
_LINUX_WEXITED = 4
_LINUX_CLD_EXITED = 1
_LINUX_CLD_KILLED = 2
_LINUX_CLD_DUMPED = 3
_LINUX_NATIVE_UNBOUND = object()

_SERVICE_ENVIRONMENT = (
    ("LC_CTYPE", "C.UTF-8"),
    ("PYTHONDONTWRITEBYTECODE", "1"),
    ("PYTHONIOENCODING", "utf-8"),
    ("PYTHONUTF8", "1"),
)

_PARENT_DEATH_POLICY_DOCUMENT = {
    "failure_exit_code": 70,
    "implementation": "prctl(PR_SET_PDEATHSIG,SIGKILL);exact_getppid_check",
    "parent_identity": "exact_broker_pid_captured_before_popen",
    "prctl_option": 1,
    "signal": _LINUX_SIGKILL,
    "single_threaded_parent_required": True,
    "version": 1,
}

_POPEN_LAUNCH_CONTRACT_DOCUMENT = {
    "authority": "captured_cpython_3_12_subprocess__fork_exec",
    "audit": "emit_subprocess.Popen_then_revalidate_low_level_authority",
    "close_fds": True,
    "cwd": "fresh_owned_service_scratch",
    "environment": "exact_validated_recipe_environment",
    "pass_fds": ["listener", "config_read", "ready_write"],
    "pid_authority": "pidfd_open_then_waitid_P_PIDFD_and_pidfd_send_signal",
    "preexec_fn": "exact_validated_parent_death_factory",
    "shell": False,
    "stderr": "pipe",
    "stdin": "devnull",
    "stdout": "pipe",
    "version": 2,
}

_SIGNAL_MASK_POLICY_DOCUMENT = {
    "audit_order": "audit_before_preexec_construction_then_exact_revalidation",
    "broker": "block_all_catchable_signals_before_single_thread_fence",
    "child": "restore_exact_prior_mask_after_parent_death_custody",
    "child_proof": "exact_proc_status_SigBlk_before_config_release_and_in_ready_hmac",
    "restore": "exact_prior_mask_in_broker_finally_after_exec_handshake",
    "uncatchable_excluded": [_LINUX_SIGKILL, _LINUX_SIGSTOP],
    "version": 1,
}

_CANONICAL_CTYPES_CDLL = ctypes.CDLL
_CANONICAL_CTYPES_CAST = ctypes.cast
_CANONICAL_CTYPES_C_INT = ctypes.c_int
_CANONICAL_CTYPES_C_ULONG = ctypes.c_ulong
_CANONICAL_CTYPES_C_VOID_P = ctypes.c_void_p
_CANONICAL_GET_ERRNO = ctypes.get_errno
_CANONICAL_FORK_EXEC = _LINUX_NATIVE_UNBOUND
_CANONICAL_SYS_AUDIT = sys.audit
_CANONICAL_SYS_GETTRACE = sys.gettrace
_CANONICAL_SYS_GETPROFILE = sys.getprofile
_CANONICAL_OS_PIPE = os.pipe
_CANONICAL_OS_DUP = os.dup
_CANONICAL_OS_OPEN = os.open
_CANONICAL_OS_CLOSE = os.close
_CANONICAL_OS_READ = os.read
_CANONICAL_OS_FDOPEN = os.fdopen
_CANONICAL_OS_PIDFD_OPEN = _LINUX_NATIVE_UNBOUND
_CANONICAL_OS_WAITID = _LINUX_NATIVE_UNBOUND
_CANONICAL_OS_WAITPID = os.waitpid
_CANONICAL_PIDFD_SEND_SIGNAL = _LINUX_NATIVE_UNBOUND
_CANONICAL_PTHREAD_SIGMASK = _LINUX_NATIVE_UNBOUND
_CANONICAL_TIME_MONOTONIC = time.monotonic
_CANONICAL_TIME_SLEEP = time.sleep
_CANONICAL_FS_ENCODING = sys.getfilesystemencoding()
_CANONICAL_DEVNULL_PATH = os.devnull
_CANONICAL_LIBC = _LINUX_NATIVE_UNBOUND
_CANONICAL_PRCTL = _LINUX_NATIVE_UNBOUND
_CANONICAL_PRCTL_ADDRESS: int | None = None
_CANONICAL_PIDFD_ID = _LINUX_NATIVE_UNBOUND
_CANONICAL_WEXITED = _LINUX_NATIVE_UNBOUND
_CANONICAL_WNOHANG = _LINUX_NATIVE_UNBOUND
_CANONICAL_CLD_EXITED = _LINUX_NATIVE_UNBOUND
_CANONICAL_CLD_KILLED = _LINUX_NATIVE_UNBOUND
_CANONICAL_CLD_DUMPED = _LINUX_NATIVE_UNBOUND
_CANONICAL_SIG_BLOCK = _LINUX_NATIVE_UNBOUND
_CANONICAL_SIG_SETMASK = _LINUX_NATIVE_UNBOUND
_CANONICAL_SIGKILL = _LINUX_NATIVE_UNBOUND
_CATCHABLE_SIGNALS = _LINUX_NATIVE_UNBOUND
_LINUX_AUTHORITY_LOCK = threading.Lock()

_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_JMP_JSET_K = 0x45
_BPF_RET_K = 0x06
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_X32_SYSCALL_BIT = 0x40000000
_CLONE_NAMESPACE_MASK = 0x7E020080


@dataclass(frozen=True, slots=True)
class _ServiceArchitectureProgram:
    machine: str
    audit_arch: int
    clone_syscall: int
    socket_syscall: int
    denied_syscalls: tuple[int, ...]


_SERVICE_ARCHITECTURE_PROGRAMS = (
    _ServiceArchitectureProgram(
        "aarch64",
        0xC00000B7,
        220,
        198,
        (
            97,  # unshare
            198,  # socket
            199,  # socketpair
            200,  # bind
            201,  # listen
            203,  # connect
            211,  # sendmsg / SCM_RIGHTS
            212,  # recvmsg / SCM_RIGHTS
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
    _ServiceArchitectureProgram(
        "x86_64",
        0xC000003E,
        56,
        41,
        (
            41,  # socket
            42,  # connect
            46,  # sendmsg / SCM_RIGHTS
            47,  # recvmsg / SCM_RIGHTS
            49,  # bind
            50,  # listen
            53,  # socketpair
            272,  # unshare
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


def _service_filter_instructions(
    program: _ServiceArchitectureProgram,
) -> tuple[tuple[int, int, int, int], ...]:
    instructions: list[tuple[int, int, int, int]] = [
        (_BPF_LD_W_ABS, 0, 0, 4),
        (_BPF_JMP_JEQ_K, 1, 0, program.audit_arch),
        (_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        (_BPF_LD_W_ABS, 0, 0, 0),
    ]
    if program.machine == "x86_64":
        instructions.extend(
            (
                (_BPF_JMP_JSET_K, 0, 1, _X32_SYSCALL_BIT),
                (_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | 1),
            )
        )
    for syscall_number in program.denied_syscalls:
        instructions.extend(
            (
                (_BPF_JMP_JEQ_K, 0, 1, syscall_number),
                (_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | 1),
            )
        )
    instructions.extend(
        (
            (_BPF_JMP_JEQ_K, 0, 3, program.clone_syscall),
            (_BPF_LD_W_ABS, 0, 0, 16),
            (_BPF_JMP_JSET_K, 0, 1, _CLONE_NAMESPACE_MASK),
            (_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | 1),
            (_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW),
        )
    )
    return tuple(instructions)


_FILTER_PROGRAMS = {
    program.machine: {
        "instructions": _service_filter_instructions(program),
        "socket_syscall": program.socket_syscall,
    }
    for program in _SERVICE_ARCHITECTURE_PROGRAMS
}

_FILTER_PROGRAMS_TOKEN = "__WORLD_FORGE_LOCAL_SERVICE_FILTER_PROGRAMS__"
_SERVICE_ENVIRONMENT_TOKEN = "__WORLD_FORGE_LOCAL_SERVICE_ENVIRONMENT__"
_LOCAL_SERVICE_BOOTSTRAP_TEMPLATE = r"""
import base64
import ctypes
import errno
import fcntl
import hashlib
import hmac
import json
import os
import socket
import stat
import sys

FILTER_PROGRAMS = __WORLD_FORGE_LOCAL_SERVICE_FILTER_PROGRAMS__
EXPECTED_ENVIRONMENT = __WORLD_FORGE_LOCAL_SERVICE_ENVIRONMENT__
READY_FORMAT = "world-forge.private.local_service_ready"
READY_VERSION = 1
SERVICE_REVISION = 1
PATH = "/worldforge/v1/ordered-loopback-probe"
PARENT_DEATH_PROOF_FORMAT = "world-forge.private.local_service_parent_death_proof"

class SockFilter(ctypes.Structure):
    _fields_ = (
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    )

class SockFprog(ctypes.Structure):
    _fields_ = (("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter)))

def canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")

def read_exact(fd, size):
    value = bytearray()
    while len(value) < size:
        chunk = os.read(fd, size - len(value))
        if not chunk:
            raise RuntimeError()
        value.extend(chunk)
    return bytes(value)

def write_all(fd, value):
    pending = memoryview(value)
    while pending:
        written = os.write(fd, pending)
        if written <= 0:
            raise RuntimeError()
        pending = pending[written:]

def proc_identity(pid):
    raw = open("/proc/%d/stat" % pid, "rb").read()
    tail = raw.rsplit(b")", 1)
    if len(tail) != 2:
        raise RuntimeError()
    fields = tail[1].split()
    if len(fields) < 20 or fields[0] in (b"Z", b"X", b"x"):
        raise RuntimeError()
    return int(fields[1]), int(fields[19])

def blocked_signal_mask():
    lines = open("/proc/self/status", "rb").read().splitlines()
    values = [line.split(b":", 1)[1].strip() for line in lines if line.startswith(b"SigBlk:")]
    if len(values) != 1 or len(values[0]) != 16:
        raise RuntimeError()
    text = values[0].decode("ascii")
    if any(character not in "0123456789abcdef" for character in text):
        raise RuntimeError()
    return text

def write_parent_death_proof(ready_fd):
    signal_value = ctypes.c_int(0)
    prctl = ctypes.CDLL(None, use_errno=True).prctl
    prctl.argtypes = (
        ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
    )
    prctl.restype = ctypes.c_int
    if prctl(2, ctypes.byref(signal_value), 0, 0, 0) != 0:
        raise RuntimeError()
    ppid, start_time = proc_identity(os.getpid())
    proof = canonical({
        "blocked_signal_mask": blocked_signal_mask(),
        "format": PARENT_DEATH_PROOF_FORMAT,
        "format_version": 1,
        "parent_death_signal": signal_value.value,
        "service_pid": os.getpid(),
        "service_ppid": ppid,
        "service_start_time": start_time,
    })
    if len(proof) > 1024:
        raise RuntimeError()
    write_all(ready_fd, len(proof).to_bytes(4, "big") + proof)

def descriptor_census():
    values = []
    scanner_fd = None
    with os.scandir("/proc/self/fd") as entries:
        for entry in entries:
            if not entry.name.isascii() or not entry.name.isdigit():
                raise RuntimeError()
            fd = int(entry.name)
            mode = os.fstat(fd).st_mode
            target = os.readlink("/proc/self/fd/%d" % fd)
            if stat.S_ISDIR(mode) and target.endswith("/fd"):
                if scanner_fd is not None:
                    raise RuntimeError()
                scanner_fd = fd
                continue
            values.append((fd, mode, target, fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE))
    if scanner_fd is None or len(values) != 6 or {item[0] for item in values} < {0, 1, 2}:
        raise RuntimeError()
    standard = {item[0]: item for item in values if item[0] in {0, 1, 2}}
    if (
        not stat.S_ISCHR(standard[0][1])
        or standard[0][2] != "/dev/null"
        or standard[0][3] != os.O_RDWR
        or not all(
            stat.S_ISFIFO(standard[fd][1]) and standard[fd][3] == os.O_WRONLY
            for fd in (1, 2)
        )
    ):
        raise RuntimeError()
    extras = [item for item in values if item[0] > 2]
    sockets = [item for item in extras if stat.S_ISSOCK(item[1])]
    readers = [item for item in extras if stat.S_ISFIFO(item[1]) and item[3] == os.O_RDONLY]
    writers = [item for item in extras if stat.S_ISFIFO(item[1]) and item[3] == os.O_WRONLY]
    if len(sockets) != 1 or len(readers) != 1 or len(writers) != 1:
        raise RuntimeError()
    roles = ["stdin_null", "stdout_pipe", "stderr_pipe", "listener", "control_read", "ready_write"]
    return sockets[0][0], readers[0][0], writers[0][0], hashlib.sha256(canonical(roles)).hexdigest()

def install_filter():
    if sys.platform != "linux" or os.uname().machine not in FILTER_PROGRAMS:
        raise RuntimeError()
    raw = FILTER_PROGRAMS[os.uname().machine]["instructions"]
    filters = (SockFilter * len(raw))(*(SockFilter(*item) for item in raw))
    program = SockFprog(len=len(raw), filter=ctypes.cast(filters, ctypes.POINTER(SockFilter)))
    prctl = ctypes.CDLL(None, use_errno=True).prctl
    prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    prctl.restype = ctypes.c_int
    if prctl(38, 1, 0, 0, 0) != 0 or prctl(22, 2, ctypes.addressof(program), 0, 0) != 0:
        raise RuntimeError()

def denied_self_tests(listener):
    libc = ctypes.CDLL(None, use_errno=True)
    socket_nr = FILTER_PROGRAMS[os.uname().machine]["socket_syscall"]
    ctypes.set_errno(0)
    if (
        libc.syscall(socket_nr, socket.AF_INET, socket.SOCK_STREAM, 0) != -1
        or ctypes.get_errno() != errno.EPERM
    ):
        raise RuntimeError()
    ctypes.set_errno(0)
    if libc.syscall(434, os.getpid(), 0) != -1 or ctypes.get_errno() != errno.EPERM:
        raise RuntimeError()
    try:
        listener.recvmsg(1)
    except OSError as exc:
        if exc.errno != errno.EPERM:
            raise
    else:
        raise RuntimeError()
    proof = {"outbound_socket": "denied", "pidfd_open": "denied", "recvmsg": "denied"}
    return hashlib.sha256(canonical(proof)).hexdigest()

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise RuntimeError()
        result[key] = value
    return result

def read_request(connection, method, host_header):
    raw = bytearray()
    while b"\r\n\r\n" not in raw:
        chunk = connection.recv(4096)
        if not chunk or len(raw) + len(chunk) > 8192:
            raise RuntimeError()
        raw.extend(chunk)
    headers, initial = bytes(raw).split(b"\r\n\r\n", 1)
    expected_start = (method + " " + PATH + " HTTP/1.1").encode("ascii")
    lines = headers.split(b"\r\n")
    if not lines or lines[0] != expected_start:
        raise RuntimeError()
    if method == "GET":
        expected = [
            ("Host: " + host_header).encode("ascii"),
            b"Accept: application/json",
            b"Connection: close",
        ]
        length = 0
    else:
        if len(lines) != 6 or not lines[4].startswith(b"Content-Length: "):
            raise RuntimeError()
        length_text = lines[4].split(b": ", 1)[1]
        if not length_text.isdigit() or length_text.startswith(b"0") and length_text != b"0":
            raise RuntimeError()
        length = int(length_text)
        expected = [
            ("Host: " + host_header).encode("ascii"),
            b"Content-Type: application/json",
            b"Accept: application/json",
            b"Content-Length: " + length_text,
            b"Connection: close",
        ]
    if lines[1:] != expected or length > 8192 or len(initial) > length:
        raise RuntimeError()
    body = bytearray(initial)
    while len(body) < length:
        chunk = connection.recv(length - len(body))
        if not chunk:
            raise RuntimeError()
        body.extend(chunk)
    if method == "POST":
        parsed = json.loads(
            bytes(body),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(RuntimeError()),
        )
        if canonical(parsed) != bytes(body):
            raise RuntimeError()

def send_response(connection, value):
    body = canonical(value)
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + ("Content-Length: %d\r\n" % len(body)).encode("ascii")
        + b"Connection: close\r\n\r\n"
        + body
    )
    connection.sendall(response)

def main():
    if (
        len(sys.argv) != 1
        or not os.path.isabs(sys.executable)
        or dict(os.environ) != EXPECTED_ENVIRONMENT
    ):
        raise RuntimeError()
    listener_fd, control_fd, ready_fd, fd_census_hash = descriptor_census()
    write_parent_death_proof(ready_fd)
    size = int.from_bytes(read_exact(control_fd, 4), "big")
    if size <= 0 or size > 4096:
        raise RuntimeError()
    raw_config = read_exact(control_fd, size)
    config = json.loads(raw_config, object_pairs_hook=pairs)
    if canonical(config) != raw_config or set(config) != {
        "bootstrap_hash", "cwd_device", "cwd_inode", "key_base64",
        "launch_policy_hash", "launch_recipe_hash",
        "listener_host", "listener_inode", "listener_port", "network_filter_hash",
        "nonce", "root_device", "root_inode", "runtime_hash", "service_revision",
        "signal_mask",
    }:
        raise RuntimeError()
    key = base64.b64decode(config["key_base64"], validate=True)
    if (
        len(key) != 32
        or config["listener_host"] != "127.0.0.1"
        or config["service_revision"] != SERVICE_REVISION
        or config["signal_mask"] != blocked_signal_mask()
    ):
        raise RuntimeError()
    listener = socket.socket(fileno=listener_fd)
    address = listener.getsockname()
    listener_inode = os.fstat(listener_fd).st_ino
    cwd = os.stat(".")
    root = os.stat("/")
    if (
        listener.family != socket.AF_INET
        or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
        or address != (config["listener_host"], config["listener_port"])
        or listener_inode != config["listener_inode"]
        or cwd.st_dev != config["cwd_device"]
        or cwd.st_ino != config["cwd_inode"]
        or root.st_dev != config["root_device"]
        or root.st_ino != config["root_inode"]
    ):
        raise RuntimeError()
    ppid, start_time = proc_identity(os.getpid())
    install_filter()
    self_test_hash = denied_self_tests(listener)
    document = {
        "bootstrap_hash": config["bootstrap_hash"],
        "cwd_device": cwd.st_dev,
        "cwd_inode": cwd.st_ino,
        "fd_census_hash": fd_census_hash,
        "format": READY_FORMAT,
        "format_version": READY_VERSION,
        "launch_policy_hash": config["launch_policy_hash"],
        "launch_recipe_hash": config["launch_recipe_hash"],
        "listener_fd": listener_fd,
        "listener_host": config["listener_host"],
        "listener_inode": listener_inode,
        "listener_port": config["listener_port"],
        "network_filter_hash": config["network_filter_hash"],
        "nonce": config["nonce"],
        "root_device": root.st_dev,
        "root_inode": root.st_ino,
        "runtime_hash": config["runtime_hash"],
        "self_test_hash": self_test_hash,
        "signal_mask": config["signal_mask"],
        "service_pid": os.getpid(),
        "service_ppid": ppid,
        "service_revision": SERVICE_REVISION,
        "service_start_time": start_time,
    }
    document["mac"] = hmac.new(key, canonical(document), hashlib.sha256).hexdigest()
    ready = canonical(document)
    write_all(ready_fd, len(ready).to_bytes(4, "big") + ready)
    os.close(ready_fd)
    host_header = "%s:%d" % address
    responses = (
        {"format": "world-forge.synthetic.local_service_health", "ready": True, "revision": 1},
        {
            "accepted": True,
            "format": "world-forge.synthetic.local_service_operation",
            "revision": 1,
        },
    )
    for method, response in zip(("GET", "POST"), responses):
        connection, peer = listener.accept()
        try:
            if peer[0] != "127.0.0.1":
                raise RuntimeError()
            read_request(connection, method, host_header)
            send_response(connection, response)
        finally:
            connection.close()
    while os.read(control_fd, 1):
        pass

try:
    main()
except BaseException:
    os._exit(70)
"""

LOCAL_SERVICE_BOOTSTRAP_SOURCE = _LOCAL_SERVICE_BOOTSTRAP_TEMPLATE.replace(
    _FILTER_PROGRAMS_TOKEN,
    repr(_FILTER_PROGRAMS),
).replace(_SERVICE_ENVIRONMENT_TOKEN, repr(dict(_SERVICE_ENVIRONMENT)))


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except Exception:
        raise LocalServicePolicyError() from None


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


_FD_CENSUS_HASH = _hash(
    ["stdin_null", "stdout_pipe", "stderr_pipe", "listener", "control_read", "ready_write"]
)
_SELF_TEST_HASH = _hash({"outbound_socket": "denied", "pidfd_open": "denied", "recvmsg": "denied"})
_NETWORK_FILTER_HASH = _hash(
    {
        "format": "world-forge.private.local_service_seccomp_bpf",
        "format_version": 1,
        "programs": _FILTER_PROGRAMS,
    }
)
_BOOTSTRAP_HASH = hashlib.sha256(LOCAL_SERVICE_BOOTSTRAP_SOURCE.encode("utf-8")).hexdigest()
_RUNTIME_HASH = _hash(
    {
        "format": "world-forge.private.synthetic_local_service_runtime",
        "format_version": 1,
        "health_response": {
            "format": "world-forge.synthetic.local_service_health",
            "ready": True,
            "revision": 1,
        },
        "operation_response": {
            "accepted": True,
            "format": "world-forge.synthetic.local_service_operation",
            "revision": 1,
        },
        "ordered_methods": ["GET", "POST"],
        "path": "/worldforge/v1/ordered-loopback-probe",
    }
)
_ARGV_HASH = _hash(
    {
        "executable": "current_absolute_python_executable",
        "arguments": ["-I", "-B", "-S", "-u", "-X", "utf8", "-c"],
        "bootstrap_hash": _BOOTSTRAP_HASH,
    }
)
_ENVIRONMENT_HASH = _hash(dict(_SERVICE_ENVIRONMENT))
_PARENT_DEATH_POLICY_HASH = _hash(_PARENT_DEATH_POLICY_DOCUMENT)


def _install_local_service_parent_death_policy(
    expected_parent_pid: int,
    _prctl: object = _LINUX_NATIVE_UNBOUND,
    _get_errno: object = _CANONICAL_GET_ERRNO,
    _getppid: object = os.getppid,
    _exit: object = os._exit,
    _sigkill: object = _LINUX_NATIVE_UNBOUND,
) -> None:
    """Install kernel custody in the forked child before its service exec."""

    if _prctl is _LINUX_NATIVE_UNBOUND or _sigkill is _LINUX_NATIVE_UNBOUND:
        authority = _load_linux_authority()
        if _prctl is _LINUX_NATIVE_UNBOUND:
            _prctl = authority.prctl
        if _sigkill is _LINUX_NATIVE_UNBOUND:
            _sigkill = authority.sigkill

    if _prctl(1, _sigkill, 0, 0, 0) != 0:  # type: ignore[operator]
        raise OSError(_get_errno(), "prctl(PR_SET_PDEATHSIG)")  # type: ignore[operator]
    if _getppid() != expected_parent_pid:  # type: ignore[operator]
        _exit(70)  # type: ignore[operator]


def _fixed_parent_death_preexec(
    expected_parent_pid: int,
    prior_signal_mask: frozenset[int | signal.Signals],
    _prctl: object = _LINUX_NATIVE_UNBOUND,
    _get_errno: object = _CANONICAL_GET_ERRNO,
    _getppid: object = os.getppid,
    _exit: object = os._exit,
    _sigkill: object = _LINUX_NATIVE_UNBOUND,
    _pthread_sigmask: object = _LINUX_NATIVE_UNBOUND,
    _sig_setmask: object = _LINUX_NATIVE_UNBOUND,
):
    if (
        _prctl is _LINUX_NATIVE_UNBOUND
        or _sigkill is _LINUX_NATIVE_UNBOUND
        or _pthread_sigmask is _LINUX_NATIVE_UNBOUND
        or _sig_setmask is _LINUX_NATIVE_UNBOUND
    ):
        authority = _load_linux_authority()
        if _prctl is _LINUX_NATIVE_UNBOUND:
            _prctl = authority.prctl
        if _sigkill is _LINUX_NATIVE_UNBOUND:
            _sigkill = authority.sigkill
        if _pthread_sigmask is _LINUX_NATIVE_UNBOUND:
            _pthread_sigmask = authority.pthread_sigmask
        if _sig_setmask is _LINUX_NATIVE_UNBOUND:
            _sig_setmask = authority.sig_setmask
    if (
        type(expected_parent_pid) is not int
        or expected_parent_pid <= 0
        or type(prior_signal_mask) is not frozenset
        or any(type(item) not in {int, signal.Signals} for item in prior_signal_mask)
    ):
        raise LocalServicePolicyError()

    def install() -> None:
        if _prctl(1, _sigkill, 0, 0, 0) != 0:  # type: ignore[operator]
            raise OSError(_get_errno(), "prctl(PR_SET_PDEATHSIG)")  # type: ignore[operator]
        if _getppid() != expected_parent_pid:  # type: ignore[operator]
            _exit(70)  # type: ignore[operator]
        _pthread_sigmask(_sig_setmask, prior_signal_mask)  # type: ignore[operator]

    return install


def _require_single_threaded_broker(
    expected_pid: int,
    _getpid: object = os.getpid,
    _scandir: object = os.scandir,
    _gettrace: object = sys.gettrace,
    _getprofile: object = sys.getprofile,
) -> None:
    try:
        if (
            expected_pid != _getpid()  # type: ignore[operator]
            or _gettrace() is not None  # type: ignore[operator]
            or _getprofile() is not None  # type: ignore[operator]
        ):
            raise LocalServicePolicyError()
        with _scandir("/proc/self/task") as entries:  # type: ignore[operator]
            tasks = {
                int(entry.name)
                for entry in entries
                if entry.name.isascii() and entry.name.isdigit()
            }
        if tasks != {expected_pid}:
            raise LocalServicePolicyError()
    except LocalServicePolicyError:
        raise
    except BaseException:
        raise LocalServicePolicyError() from None


def _linux_signal_mask_hex(value: frozenset[int | signal.Signals]) -> str:
    if type(value) is not frozenset:
        raise LocalServicePolicyError()
    mask = 0
    for item in value:
        signum = int(item)
        if type(item) not in {int, signal.Signals} or not 1 <= signum <= 64:
            raise LocalServicePolicyError()
        mask |= 1 << (signum - 1)
    return f"{mask:016x}"


def _block_local_service_launch_signals(
    _pthread_sigmask: object = _LINUX_NATIVE_UNBOUND,
    _sig_block: object = _LINUX_NATIVE_UNBOUND,
    _catchable: object = _LINUX_NATIVE_UNBOUND,
) -> frozenset[int | signal.Signals]:
    try:
        if (
            _pthread_sigmask is _LINUX_NATIVE_UNBOUND
            or _sig_block is _LINUX_NATIVE_UNBOUND
            or _catchable is _LINUX_NATIVE_UNBOUND
        ):
            authority = _load_linux_authority()
            if _pthread_sigmask is _LINUX_NATIVE_UNBOUND:
                _pthread_sigmask = authority.pthread_sigmask
            if _sig_block is _LINUX_NATIVE_UNBOUND:
                _sig_block = authority.sig_block
            if _catchable is _LINUX_NATIVE_UNBOUND:
                _catchable = authority.catchable_signals
        previous = _pthread_sigmask(_sig_block, _catchable)  # type: ignore[operator]
        result = frozenset(previous)
        if any(type(item) not in {int, signal.Signals} for item in result):
            raise LocalServicePolicyError()
        return result
    except LocalServicePolicyError:
        raise
    except BaseException:
        raise LocalServicePolicyError() from None


def _restore_local_service_launch_signals(
    prior_signal_mask: frozenset[int | signal.Signals],
    _pthread_sigmask: object = _LINUX_NATIVE_UNBOUND,
    _sig_setmask: object = _LINUX_NATIVE_UNBOUND,
) -> None:
    try:
        if _pthread_sigmask is _LINUX_NATIVE_UNBOUND or _sig_setmask is _LINUX_NATIVE_UNBOUND:
            authority = _load_linux_authority()
            if _pthread_sigmask is _LINUX_NATIVE_UNBOUND:
                _pthread_sigmask = authority.pthread_sigmask
            if _sig_setmask is _LINUX_NATIVE_UNBOUND:
                _sig_setmask = authority.sig_setmask
        if type(prior_signal_mask) is not frozenset or any(
            type(item) not in {int, signal.Signals} for item in prior_signal_mask
        ):
            raise LocalServicePolicyError()
        _pthread_sigmask(_sig_setmask, prior_signal_mask)  # type: ignore[operator]
    except LocalServicePolicyError:
        raise
    except BaseException:
        raise LocalServicePolicyError() from None


class LocalServicePolicyError(ValueError):
    def __init__(self) -> None:
        super().__init__(_POLICY_ERROR)


class _LocalServiceProcess:
    __slots__ = ("pid", "pidfd", "stdout", "stderr", "returncode", "stdin")

    def __init__(
        self,
        pid: int,
        pidfd: int,
        stdout: object,
        stderr: object,
    ) -> None:
        self.pid = pid
        self.pidfd = pidfd
        self.stdout = stdout
        self.stderr = stderr
        self.returncode: int | None = None
        self.stdin = None

    def poll(
        self,
        _waitid: object = _LINUX_NATIVE_UNBOUND,
        _close: object = _CANONICAL_OS_CLOSE,
        _pidfd_id: int = _LINUX_PIDFD_ID,
        _options: int = _LINUX_WEXITED | _LINUX_WNOHANG,
        _cld_exited: int = _LINUX_CLD_EXITED,
        _cld_killed: int = _LINUX_CLD_KILLED,
        _cld_dumped: int = _LINUX_CLD_DUMPED,
        _policy_error: type[Exception] = LocalServicePolicyError,
    ) -> int | None:
        if self.returncode is not None:
            return self.returncode
        if self.pidfd < 0:
            raise _policy_error()
        while True:
            try:
                result = _waitid(_pidfd_id, self.pidfd, _options)  # type: ignore[operator]
                break
            except InterruptedError:
                continue
            except ChildProcessError:
                descriptor = self.pidfd
                self.pidfd = -1
                try:
                    _close(descriptor)  # type: ignore[operator]
                except BaseException:
                    pass
                raise _policy_error() from None
        if result is None:
            return None
        if result.si_pid != self.pid:
            descriptor = self.pidfd
            self.pidfd = -1
            try:
                _close(descriptor)  # type: ignore[operator]
            except BaseException:
                pass
            raise _policy_error()
        if result.si_code == _cld_exited:
            self.returncode = result.si_status
        elif result.si_code in {_cld_killed, _cld_dumped}:
            self.returncode = -result.si_status
        else:
            descriptor = self.pidfd
            self.pidfd = -1
            try:
                _close(descriptor)  # type: ignore[operator]
            except BaseException:
                pass
            raise _policy_error()
        descriptor = self.pidfd
        self.pidfd = -1
        try:
            _close(descriptor)  # type: ignore[operator]
        except BaseException:
            pass
        return self.returncode

    def wait(
        self,
        timeout: float | None = None,
        _waitid: object = _LINUX_NATIVE_UNBOUND,
        _close: object = _CANONICAL_OS_CLOSE,
        _monotonic: object = _CANONICAL_TIME_MONOTONIC,
        _sleep: object = _CANONICAL_TIME_SLEEP,
        _pidfd_id: int = _LINUX_PIDFD_ID,
        _wexited: int = _LINUX_WEXITED,
        _wnohang: int = _LINUX_WNOHANG,
        _cld_exited: int = _LINUX_CLD_EXITED,
        _cld_killed: int = _LINUX_CLD_KILLED,
        _cld_dumped: int = _LINUX_CLD_DUMPED,
        _policy_error: type[Exception] = LocalServicePolicyError,
    ) -> int:
        if self.returncode is not None:
            return self.returncode
        if self.pidfd < 0:
            raise _policy_error()
        deadline = None if timeout is None else _monotonic() + max(0.0, timeout)  # type: ignore[operator]
        while True:
            try:
                result = _waitid(  # type: ignore[operator]
                    _pidfd_id,
                    self.pidfd,
                    _wexited if deadline is None else _wexited | _wnohang,
                )
            except InterruptedError:
                continue
            except ChildProcessError:
                descriptor = self.pidfd
                self.pidfd = -1
                try:
                    _close(descriptor)  # type: ignore[operator]
                except BaseException:
                    pass
                raise _policy_error() from None
            if result is not None:
                if result.si_pid != self.pid:
                    descriptor = self.pidfd
                    self.pidfd = -1
                    try:
                        _close(descriptor)  # type: ignore[operator]
                    except BaseException:
                        pass
                    raise _policy_error()
                if result.si_code == _cld_exited:
                    self.returncode = result.si_status
                elif result.si_code in {_cld_killed, _cld_dumped}:
                    self.returncode = -result.si_status
                else:
                    descriptor = self.pidfd
                    self.pidfd = -1
                    try:
                        _close(descriptor)  # type: ignore[operator]
                    except BaseException:
                        pass
                    raise _policy_error()
                descriptor = self.pidfd
                self.pidfd = -1
                try:
                    _close(descriptor)  # type: ignore[operator]
                except BaseException:
                    pass
                return self.returncode
            if deadline is not None and _monotonic() >= deadline:  # type: ignore[operator]
                raise TimeoutError()
            _sleep(0.001)  # type: ignore[operator]

    def kill(
        self,
        _waitid: object = _LINUX_NATIVE_UNBOUND,
        _pidfd_send_signal: object = _LINUX_NATIVE_UNBOUND,
        _close: object = _CANONICAL_OS_CLOSE,
        _pidfd_id: int = _LINUX_PIDFD_ID,
        _options: int = _LINUX_WEXITED | _LINUX_WNOHANG,
        _sigkill: int = _LINUX_SIGKILL,
        _cld_exited: int = _LINUX_CLD_EXITED,
        _cld_killed: int = _LINUX_CLD_KILLED,
        _cld_dumped: int = _LINUX_CLD_DUMPED,
        _policy_error: type[Exception] = LocalServicePolicyError,
    ) -> None:
        if self.returncode is not None:
            return
        if self.pidfd < 0:
            raise _policy_error()
        while True:
            try:
                result = _waitid(_pidfd_id, self.pidfd, _options)  # type: ignore[operator]
                break
            except InterruptedError:
                continue
            except ChildProcessError:
                descriptor = self.pidfd
                self.pidfd = -1
                try:
                    _close(descriptor)  # type: ignore[operator]
                except BaseException:
                    pass
                raise _policy_error() from None
        if result is not None:
            if result.si_pid != self.pid:
                descriptor = self.pidfd
                self.pidfd = -1
                try:
                    _close(descriptor)  # type: ignore[operator]
                except BaseException:
                    pass
                raise _policy_error()
            if result.si_code == _cld_exited:
                self.returncode = result.si_status
            elif result.si_code in {_cld_killed, _cld_dumped}:
                self.returncode = -result.si_status
            else:
                descriptor = self.pidfd
                self.pidfd = -1
                try:
                    _close(descriptor)  # type: ignore[operator]
                except BaseException:
                    pass
                raise _policy_error()
            descriptor = self.pidfd
            self.pidfd = -1
            try:
                _close(descriptor)  # type: ignore[operator]
            except BaseException:
                pass
            return
        while True:
            try:
                _pidfd_send_signal(self.pidfd, _sigkill, None, 0)  # type: ignore[operator]
                return
            except InterruptedError:
                continue
            except ProcessLookupError:
                descriptor = self.pidfd
                self.pidfd = -1
                try:
                    _close(descriptor)  # type: ignore[operator]
                except BaseException:
                    pass
                raise _policy_error() from None

    def close(
        self,
        _close: object = _CANONICAL_OS_CLOSE,
    ) -> None:
        descriptor = self.pidfd
        self.pidfd = -1
        if descriptor >= 0:
            try:
                _close(descriptor)  # type: ignore[operator]
            except BaseException:
                pass
        for stream_name in ("stdout", "stderr"):
            try:
                stream = getattr(self, stream_name)
                if stream is not None:
                    stream.close()
            except BaseException:
                pass

    def __del__(
        self,
        _close: object = _CANONICAL_OS_CLOSE,
        _waitid: object = _LINUX_NATIVE_UNBOUND,
        _pidfd_id: int = _LINUX_PIDFD_ID,
        _options: int = _LINUX_WEXITED | _LINUX_WNOHANG,
    ) -> None:
        try:
            descriptor = self.pidfd
        except BaseException:
            return
        self.pidfd = -1
        if descriptor >= 0:
            while True:
                try:
                    _waitid(_pidfd_id, descriptor, _options)  # type: ignore[operator]
                    break
                except InterruptedError:
                    continue
                except BaseException:
                    break
            try:
                _close(descriptor)  # type: ignore[operator]
            except BaseException:
                pass
        for stream_name in ("stdout", "stderr"):
            try:
                stream = getattr(self, stream_name)
                if stream is not None:
                    stream.close()
            except BaseException:
                pass


def _launch_local_service_popen(
    fork_exec: object,
    audit: object,
    process_type: type[_LocalServiceProcess],
    process_class_items: tuple[tuple[str, object], ...],
    process_function_snapshots: tuple[tuple[str, object, object, object, object], ...],
    policy_error: type[Exception],
    custody_factory: object,
    custody_factory_snapshot: tuple[object, object, object, object],
    custody_dependencies: tuple[object, ...],
    native_prctl: object,
    native_int: object,
    native_ulong: object,
    signal_mask_authority: object,
    expected_parent_pid: int,
    prior_signal_mask: frozenset[int | signal.Signals],
    abort_write_fd: int,
    command: tuple[str, ...],
    *,
    service_scratch: str,
    environment: dict[str, str],
    pass_fds: tuple[int, int, int],
    _subprocess_module: object = subprocess,
    _os_module: object = os,
    _signal_module: object = signal,
    _getpid: object = os.getpid,
    _scandir: object = os.scandir,
    _gettrace: object = sys.gettrace,
    _getprofile: object = sys.getprofile,
    _pipe: object = _CANONICAL_OS_PIPE,
    _dup: object = _CANONICAL_OS_DUP,
    _open: object = _CANONICAL_OS_OPEN,
    _close: object = _CANONICAL_OS_CLOSE,
    _read: object = _CANONICAL_OS_READ,
    _fdopen: object = _CANONICAL_OS_FDOPEN,
    _pidfd_open: object = _LINUX_NATIVE_UNBOUND,
    _waitid: object = _LINUX_NATIVE_UNBOUND,
    _waitpid: object = _CANONICAL_OS_WAITPID,
    _pidfd_send_signal: object = _LINUX_NATIVE_UNBOUND,
    _fs_encoding: str = _CANONICAL_FS_ENCODING,
    _devnull_path: str = _CANONICAL_DEVNULL_PATH,
    _type: object = type,
    _int: object = int,
    _len: object = len,
    _zip: object = zip,
    _bytearray: object = bytearray,
    _tuple: object = tuple,
    _sorted: object = sorted,
    _any: object = any,
    _sigkill: object = _LINUX_NATIVE_UNBOUND,
    _pidfd_id: object = _LINUX_NATIVE_UNBOUND,
    _wexited: object = _LINUX_NATIVE_UNBOUND,
) -> _LocalServiceProcess:
    if any(
        value is _LINUX_NATIVE_UNBOUND
        for value in (
            _pidfd_open,
            _waitid,
            _pidfd_send_signal,
            _sigkill,
            _pidfd_id,
            _wexited,
        )
    ):
        authority = _load_linux_authority()
        if _pidfd_open is _LINUX_NATIVE_UNBOUND:
            _pidfd_open = authority.pidfd_open
        if _waitid is _LINUX_NATIVE_UNBOUND:
            _waitid = authority.waitid
        if _pidfd_send_signal is _LINUX_NATIVE_UNBOUND:
            _pidfd_send_signal = authority.pidfd_send_signal
        if _sigkill is _LINUX_NATIVE_UNBOUND:
            _sigkill = authority.sigkill
        if _pidfd_id is _LINUX_NATIVE_UNBOUND:
            _pidfd_id = authority.pidfd_id
        if _wexited is _LINUX_NATIVE_UNBOUND:
            _wexited = authority.wexited
    descriptors: set[int] = set()
    pid: int | None = None
    pidfd = -1
    try:
        devnull = _open(_devnull_path, os.O_RDWR)  # type: ignore[operator]
        descriptors.add(devnull)
        stdout_read, stdout_write = _pipe()  # type: ignore[operator]
        descriptors.update((stdout_read, stdout_write))
        stderr_read, stderr_write = _pipe()  # type: ignore[operator]
        descriptors.update((stderr_read, stderr_write))
        errpipe_read, errpipe_write = _pipe()  # type: ignore[operator]
        descriptors.update((errpipe_read, errpipe_write))
        while errpipe_write < 3:
            replacement = _dup(errpipe_write)  # type: ignore[operator]
            descriptors.add(replacement)
            _close(errpipe_write)  # type: ignore[operator]
            descriptors.remove(errpipe_write)
            errpipe_write = replacement

        encoded_command = tuple(item.encode(_fs_encoding, "surrogateescape") for item in command)
        encoded_environment = tuple(
            key.encode(_fs_encoding, "surrogateescape")
            + b"="
            + value.encode(_fs_encoding, "surrogateescape")
            for key, value in environment.items()
        )
        encoded_cwd = service_scratch.encode(_fs_encoding, "surrogateescape")
        keep_fds = tuple(sorted((*pass_fds, errpipe_write)))
        audit(  # type: ignore[operator]
            "subprocess.Popen",
            command[0],
            command,
            service_scratch,
            dict(environment),
        )

        if (
            _type(expected_parent_pid) is not _int  # type: ignore[operator]
            or expected_parent_pid <= 0
            or _getpid() != expected_parent_pid  # type: ignore[operator]
            or _gettrace() is not None  # type: ignore[operator]
            or _getprofile() is not None  # type: ignore[operator]
            or _subprocess_module._fork_exec is not fork_exec  # type: ignore[union-attr]
            or _os_module.pidfd_open is not _pidfd_open  # type: ignore[union-attr]
            or _os_module.waitid is not _waitid  # type: ignore[union-attr]
            or _os_module.waitpid is not _waitpid  # type: ignore[union-attr]
            or _os_module.close is not _close  # type: ignore[union-attr]
            or _signal_module.pthread_sigmask is not signal_mask_authority  # type: ignore[union-attr]
            or _signal_module.pidfd_send_signal is not _pidfd_send_signal  # type: ignore[union-attr]
        ):
            raise policy_error()
        with _scandir("/proc/self/task") as entries:  # type: ignore[operator]
            tasks = {
                _int(entry.name)  # type: ignore[operator]
                for entry in entries
                if entry.name.isascii() and entry.name.isdigit()
            }
        if tasks != {expected_parent_pid}:
            raise policy_error()
        if (
            _tuple(native_prctl.argtypes)  # type: ignore[operator,union-attr]
            != (
                native_int,
                native_ulong,
                native_ulong,
                native_ulong,
                native_ulong,
            )
            or native_prctl.restype is not native_int  # type: ignore[union-attr]
        ):
            raise policy_error()
        factory, factory_code, factory_defaults, factory_kwdefaults = custody_factory_snapshot
        if _type(custody_dependencies) is not _tuple or _len(custody_dependencies) != 7:  # type: ignore[operator]
            raise policy_error()
        (
            custody_prctl,
            custody_get_errno,
            custody_getppid,
            custody_exit,
            custody_sigkill,
            custody_pthread_sigmask,
            custody_sig_setmask,
        ) = custody_dependencies
        if (
            custody_factory is not factory
            or custody_factory.__code__ is not factory_code  # type: ignore[union-attr]
            or custody_factory.__defaults__ != factory_defaults  # type: ignore[union-attr]
            or custody_factory.__kwdefaults__ != factory_kwdefaults  # type: ignore[union-attr]
            or custody_prctl is not native_prctl
            or custody_get_errno is not _CANONICAL_GET_ERRNO
            or custody_getppid is not _os_module.getppid  # type: ignore[union-attr]
            or custody_exit is not _os_module._exit  # type: ignore[union-attr]
            or custody_sigkill != _sigkill
            or custody_pthread_sigmask is not signal_mask_authority
            or custody_sig_setmask != _signal_module.SIG_SETMASK  # type: ignore[union-attr]
        ):
            raise policy_error()
        current_class_items = _tuple(  # type: ignore[operator]
            _sorted(process_type.__dict__.items())  # type: ignore[operator]
        )
        if _len(current_class_items) != _len(process_class_items):  # type: ignore[operator]
            raise policy_error()
        if _any(  # type: ignore[operator]
            name != expected_name or current is not expected
            for (name, current), (expected_name, expected) in _zip(  # type: ignore[operator]
                current_class_items,
                process_class_items,
                strict=True,
            )
        ):
            raise policy_error()
        for name, function, code, defaults, kwdefaults in process_function_snapshots:
            current = process_type.__dict__.get(name)
            if (
                current is not function
                or current.__code__ is not code
                or current.__defaults__ != defaults
                or current.__kwdefaults__ != kwdefaults
            ):
                raise policy_error()

        preexec_fn = custody_factory(  # type: ignore[operator]
            expected_parent_pid,
            prior_signal_mask,
            custody_prctl,
            custody_get_errno,
            custody_getppid,
            custody_exit,
            custody_sigkill,
            custody_pthread_sigmask,
            custody_sig_setmask,
        )
        pid = fork_exec(  # type: ignore[operator]
            encoded_command,
            (encoded_command[0],),
            True,
            keep_fds,
            encoded_cwd,
            encoded_environment,
            devnull,
            -1,
            stdout_read,
            stdout_write,
            stderr_read,
            stderr_write,
            errpipe_read,
            errpipe_write,
            True,
            False,
            -1,
            None,
            None,
            None,
            -1,
            preexec_fn,
            False,
        )
        if _type(pid) is not _int or pid <= 0:  # type: ignore[operator]
            raise policy_error()
        while True:
            try:
                pidfd = _pidfd_open(pid, 0)  # type: ignore[operator]
                break
            except InterruptedError:
                continue
        if _type(pidfd) is not _int or pidfd < 0:  # type: ignore[operator]
            raise policy_error()

        for descriptor in (devnull, stdout_write, stderr_write, errpipe_write):
            _close(descriptor)  # type: ignore[operator]
            descriptors.remove(descriptor)
        error_data = _bytearray()  # type: ignore[operator]
        while True:
            try:
                chunk = _read(errpipe_read, 50_000)  # type: ignore[operator]
            except InterruptedError:
                continue
            error_data.extend(chunk)
            if not chunk or _len(error_data) > 50_000:  # type: ignore[operator]
                break
        _close(errpipe_read)  # type: ignore[operator]
        descriptors.remove(errpipe_read)
        if error_data:
            while True:
                try:
                    result = _waitid(_pidfd_id, pidfd, _wexited)  # type: ignore[operator]
                    break
                except InterruptedError:
                    continue
            if result is None or result.si_pid != pid:
                raise policy_error()
            _close(pidfd)  # type: ignore[operator]
            pidfd = -1
            pid = None
            raise policy_error()

        stdout = _fdopen(stdout_read, "rb", buffering=0)  # type: ignore[operator]
        descriptors.remove(stdout_read)
        stderr = _fdopen(stderr_read, "rb", buffering=0)  # type: ignore[operator]
        descriptors.remove(stderr_read)
        current_class_items = _tuple(  # type: ignore[operator]
            _sorted(process_type.__dict__.items())  # type: ignore[operator]
        )
        if _len(current_class_items) != _len(process_class_items) or _any(  # type: ignore[operator]
            name != expected_name or current is not expected
            for (name, current), (expected_name, expected) in _zip(  # type: ignore[operator]
                current_class_items,
                process_class_items,
                strict=True,
            )
        ):
            raise policy_error()
        for name, function, code, defaults, kwdefaults in process_function_snapshots:
            current = process_type.__dict__.get(name)
            if (
                current is not function
                or current.__code__ is not code
                or current.__defaults__ != defaults
                or current.__kwdefaults__ != kwdefaults
            ):
                raise policy_error()

        return process_type(pid, pidfd, stdout, stderr)
    except BaseException:
        if abort_write_fd >= 0:
            try:
                _close(abort_write_fd)  # type: ignore[operator]
            except BaseException:
                pass
            abort_write_fd = -1
        if pidfd >= 0:
            while True:
                try:
                    _pidfd_send_signal(pidfd, _sigkill, None, 0)  # type: ignore[operator]
                    break
                except InterruptedError:
                    continue
                except ProcessLookupError:
                    break
                except BaseException:
                    break
            while True:
                try:
                    _waitid(_pidfd_id, pidfd, _wexited)  # type: ignore[operator]
                    break
                except InterruptedError:
                    continue
                except BaseException:
                    break
            try:
                _close(pidfd)  # type: ignore[operator]
            except BaseException:
                pass
        elif pid is not None:
            while True:
                try:
                    waited_pid, _status = _waitpid(pid, 0)  # type: ignore[operator]
                    if waited_pid != pid:
                        raise policy_error()
                    break
                except InterruptedError:
                    continue
        for descriptor in _tuple(descriptors):  # type: ignore[operator]
            try:
                _close(descriptor)  # type: ignore[operator]
            except BaseException:
                pass
        raise


def _code_hash(value: object) -> str:
    try:

        def normalize_constant(constant: object) -> object:
            if isinstance(constant, CodeType):
                return normalize_code(constant)
            if constant is None or type(constant) in {bool, int, float, str}:
                return constant
            if type(constant) is bytes:
                return {"bytes_base64": base64.b64encode(constant).decode("ascii")}
            if type(constant) is tuple:
                return [normalize_constant(item) for item in constant]
            raise LocalServicePolicyError()

        def normalize_code(code: CodeType) -> dict[str, object]:
            return {
                "argcount": code.co_argcount,
                "cellvars": list(code.co_cellvars),
                "code_base64": base64.b64encode(code.co_code).decode("ascii"),
                "consts": [normalize_constant(item) for item in code.co_consts],
                "exceptiontable_base64": base64.b64encode(code.co_exceptiontable).decode("ascii"),
                "flags": code.co_flags,
                "freevars": list(code.co_freevars),
                "kwonlyargcount": code.co_kwonlyargcount,
                "names": list(code.co_names),
                "nlocals": code.co_nlocals,
                "posonlyargcount": code.co_posonlyargcount,
                "stacksize": code.co_stacksize,
                "varnames": list(code.co_varnames),
            }

        return _hash(normalize_code(value.__code__))  # type: ignore[union-attr]
    except BaseException:
        raise LocalServicePolicyError() from None


_CANONICAL_CUSTODY_INSTALLER = _install_local_service_parent_death_policy
_CANONICAL_CUSTODY_FACTORY = _fixed_parent_death_preexec
_CANONICAL_SINGLE_THREAD_CHECKER = _require_single_threaded_broker
_CANONICAL_POPEN_LAUNCHER = _launch_local_service_popen
_CANONICAL_PROCESS_TYPE = _LocalServiceProcess
_CANONICAL_POLICY_ERROR = LocalServicePolicyError
_CANONICAL_PROCESS_CLASS_ITEMS = tuple(sorted(_CANONICAL_PROCESS_TYPE.__dict__.items()))
_CANONICAL_PROCESS_FUNCTION_SNAPSHOTS: tuple[tuple[str, object, object, object, object], ...] = ()
_CANONICAL_POPEN = subprocess.Popen
_CANONICAL_INSTALLER_DEFAULTS: tuple[object, ...] = ()
_CANONICAL_FACTORY_DEFAULTS: tuple[object, ...] = ()
_CANONICAL_FACTORY_SNAPSHOT: tuple[object, object, object, object] = (
    _LINUX_NATIVE_UNBOUND,
    _LINUX_NATIVE_UNBOUND,
    _LINUX_NATIVE_UNBOUND,
    _LINUX_NATIVE_UNBOUND,
)
_CANONICAL_CHECKER_DEFAULTS = tuple(_CANONICAL_SINGLE_THREAD_CHECKER.__defaults__ or ())
_CANONICAL_LAUNCHER_DEFAULTS: tuple[object, ...] = ()
_CANONICAL_INSTALLER_KWDEFAULTS: tuple[tuple[str, object], ...] = ()
_CANONICAL_FACTORY_KWDEFAULTS: tuple[tuple[str, object], ...] = ()
_CANONICAL_CHECKER_KWDEFAULTS = tuple(
    sorted((_CANONICAL_SINGLE_THREAD_CHECKER.__kwdefaults__ or {}).items())
)
_CANONICAL_LAUNCHER_KWDEFAULTS: tuple[tuple[str, object], ...] = ()
_CUSTODY_INSTALLER_CODE_HASH = _code_hash(_CANONICAL_CUSTODY_INSTALLER)
_CUSTODY_FACTORY_CODE_HASH = _code_hash(_CANONICAL_CUSTODY_FACTORY)
_SINGLE_THREAD_CHECKER_HASH = _code_hash(_CANONICAL_SINGLE_THREAD_CHECKER)
_POPEN_LAUNCHER_CODE_HASH = _code_hash(_CANONICAL_POPEN_LAUNCHER)


def _dependency_fingerprint(value: object) -> object:
    def fingerprint(item: object, active: dict[int, int]) -> object:
        item_type = type(item)
        if item is _LINUX_NATIVE_UNBOUND:
            return {"type": "linux_native_dependency_slot"}
        if item is None:
            return {"type": "none"}
        if item_type is bool:
            return {"type": "bool", "value": item}
        if item_type is int:
            return {"type": "int", "value": item}
        if item_type is float:
            return {"type": "float", "value": repr(item)}
        if item_type is str:
            return {"type": "str", "value": item}
        if item_type is bytes:
            return {
                "type": "bytes",
                "value_base64": base64.b64encode(item).decode("ascii"),
            }
        if isinstance(item, int):
            return {
                "type": f"{item_type.__module__}.{item_type.__qualname__}",
                "value": int(item),
            }
        identity = id(item)
        if identity in active:
            return {"type": "cycle", "target": active[identity]}
        active[identity] = len(active)
        try:
            if item_type in {tuple, list}:
                return {
                    "type": item_type.__name__,
                    "items": [fingerprint(value, active) for value in item],  # type: ignore[union-attr]
                }
            if item_type is frozenset:
                values = [fingerprint(value, active) for value in item]  # type: ignore[union-attr]
                return {"type": "frozenset", "items": sorted(values, key=_canonical)}
            if item_type is dict:
                values = [
                    [fingerprint(key, active), fingerprint(value, active)]
                    for key, value in item.items()  # type: ignore[union-attr]
                ]
                return {"type": "dict", "items": sorted(values, key=_canonical)}
            if item_type is classmethod:
                return {"type": "classmethod", "function": fingerprint(item.__func__, active)}
            if item_type is property:
                return {
                    "type": "property",
                    "accessors": [
                        {"type": "none"} if value is None else fingerprint(value, active)
                        for value in (item.fget, item.fset, item.fdel)
                    ],
                }
            if item_type is ModuleType:
                return {"type": "module", "name": item.__name__}
            if item_type is FunctionType:
                closure: list[object] = []
                for cell in item.__closure__ or ():
                    try:
                        closure.append(fingerprint(cell.cell_contents, active))
                    except ValueError:
                        closure.append({"type": "empty_cell"})
                globals_document = [
                    [name, fingerprint(item.__globals__[name], active)]
                    for name in sorted(set(item.__code__.co_names))
                    if name in item.__globals__
                ]
                builtins_namespace = item.__builtins__
                if type(builtins_namespace) is not dict:
                    builtins_namespace = vars(builtins_namespace)
                builtins_document = [
                    [name, fingerprint(builtins_namespace[name], active)]
                    for name in sorted(set(item.__code__.co_names))
                    if name not in item.__globals__ and name in builtins_namespace
                ]
                return {
                    "type": "function",
                    "module": item.__module__,
                    "qualname": item.__qualname__,
                    "code_hash": _code_hash(item),
                    "defaults": fingerprint(tuple(item.__defaults__ or ()), active),
                    "kwdefaults": fingerprint(dict(item.__kwdefaults__ or {}), active),
                    "closure": closure,
                    "globals": globals_document,
                    "builtins": builtins_document,
                }
            if isinstance(item, ctypes._CFuncPtr):
                return {
                    "type": f"{item_type.__module__}.{item_type.__qualname__}",
                    "name": getattr(item, "__name__", None),
                }
            module = getattr(item, "__module__", None)
            qualname = getattr(item, "__qualname__", None)
            if type(module) is str and type(qualname) is str:
                return {
                    "type": f"{item_type.__module__}.{item_type.__qualname__}",
                    "module": module,
                    "qualname": qualname,
                }
            name = getattr(item, "__name__", None)
            if type(name) is str:
                return {
                    "type": f"{item_type.__module__}.{item_type.__qualname__}",
                    "name": name,
                }
            raise ValueError("unsupported custody dependency")
        finally:
            del active[identity]

    return fingerprint(value, {})


def _capture_python_function_state(value: object) -> tuple[object, ...]:
    code = value.__code__  # type: ignore[union-attr]
    defaults = tuple(value.__defaults__ or ())  # type: ignore[union-attr]
    kwdefaults = tuple(sorted((value.__kwdefaults__ or {}).items()))  # type: ignore[union-attr]
    closure = tuple(
        cell.cell_contents
        for cell in (value.__closure__ or ())  # type: ignore[union-attr]
    )
    globals_snapshot = tuple(
        (name, value.__globals__[name])  # type: ignore[union-attr]
        for name in sorted(set(code.co_names))
        if name in value.__globals__  # type: ignore[operator,union-attr]
    )
    return (
        value,
        _code_hash(value),
        defaults,
        kwdefaults,
        closure,
        globals_snapshot,
        _hash(_dependency_fingerprint(value)),
    )


def _python_function_state_matches(value: object, state: tuple[object, ...]) -> bool:
    if len(state) != 7 or value is not state[0] or _code_hash(value) != state[1]:
        return False
    if not _defaults_match_exactly(value, state[2], state[3]):  # type: ignore[arg-type]
        return False
    try:
        closure = tuple(
            cell.cell_contents
            for cell in (value.__closure__ or ())  # type: ignore[union-attr]
        )
        expected_closure = state[4]
        if type(expected_closure) is not tuple or len(closure) != len(expected_closure):
            return False
        if any(
            not _dependency_matches(actual, expected)
            for actual, expected in zip(closure, expected_closure, strict=True)
        ):
            return False
        expected_globals = state[5]
        if type(expected_globals) is not tuple:
            return False
        current_globals = tuple(
            (name, value.__globals__[name])  # type: ignore[union-attr]
            for name, _dependency in expected_globals
            if name in value.__globals__  # type: ignore[operator,union-attr]
        )
        if len(current_globals) != len(expected_globals):
            return False
        return (
            all(
                name == expected_name and _dependency_matches(actual, expected)
                for (name, actual), (expected_name, expected) in zip(
                    current_globals,
                    expected_globals,
                    strict=True,
                )
            )
            and _hash(_dependency_fingerprint(value)) == state[6]
        )
    except BaseException:
        return False


def _popen_python_functions(value: type[object]) -> tuple[object, ...]:
    functions: list[object] = []
    for attribute in value.__dict__.values():
        candidates = (
            (attribute.__func__,)
            if type(attribute) is classmethod
            else (
                tuple(
                    item
                    for item in (attribute.fget, attribute.fset, attribute.fdel)
                    if item is not None
                )
                if type(attribute) is property
                else (attribute,)
            )
        )
        functions.extend(item for item in candidates if type(item) is FunctionType)
    return tuple(functions)


_PRELOAD_POPEN_CLASS_ITEMS = tuple(sorted(_CANONICAL_POPEN.__dict__.items()))
_PRELOAD_POPEN_FUNCTION_SNAPSHOTS = tuple(
    (
        function,
        function.__code__,
        function.__defaults__,
        function.__kwdefaults__,
    )
    for function in _popen_python_functions(_CANONICAL_POPEN)
)
_PRELOAD_POPEN_NEW = _CANONICAL_POPEN.__new__
_PRELOAD_POPEN_INIT = _CANONICAL_POPEN.__init__
_PRELOAD_POPEN_METACLASS = type(_CANONICAL_POPEN)
_PRELOAD_POPEN_METACLASS_CALL = _PRELOAD_POPEN_METACLASS.__call__


_CANONICAL_POPEN_NEW = _LINUX_NATIVE_UNBOUND
_CANONICAL_POPEN_NEW_SELF = _LINUX_NATIVE_UNBOUND
_CANONICAL_POPEN_INIT = _LINUX_NATIVE_UNBOUND
_CANONICAL_POPEN_METACLASS = _LINUX_NATIVE_UNBOUND
_CANONICAL_POPEN_METACLASS_CALL = _LINUX_NATIVE_UNBOUND
_CANONICAL_POPEN_CLASS_ITEMS: tuple[tuple[str, object], ...] = ()
_CANONICAL_POPEN_FUNCTION_STATES: tuple[tuple[object, ...], ...] = ()
_CANONICAL_POPEN_INIT_STATE: tuple[object, ...] = ()
_POPEN_INIT_HASH = ""
_POPEN_NEW_HASH = ""
_POPEN_DEPENDENCY_HASH = ""
_NATIVE_PRCTL_HASH = ""
_PROCESS_HANDLE_HASH = ""

_CANONICAL_SIGNAL_BLOCKER = _block_local_service_launch_signals
_CANONICAL_SIGNAL_RESTORER = _restore_local_service_launch_signals
_CANONICAL_BLOCKER_DEFAULTS: tuple[object, ...] = ()
_CANONICAL_RESTORER_DEFAULTS: tuple[object, ...] = ()
_CANONICAL_BLOCKER_KWDEFAULTS: tuple[tuple[str, object], ...] = ()
_CANONICAL_RESTORER_KWDEFAULTS: tuple[tuple[str, object], ...] = ()
_SIGNAL_BLOCKER_CODE_HASH = _code_hash(_CANONICAL_SIGNAL_BLOCKER)
_SIGNAL_RESTORER_CODE_HASH = _code_hash(_CANONICAL_SIGNAL_RESTORER)
_SIGNAL_MASK_POLICY_HASH = ""
_CUSTODY_DEPENDENCY_HASH = ""
_POPEN_LAUNCH_CONTRACT_HASH = ""

_LINUX_DEFAULT_BINDING_FUNCTIONS = (
    _CANONICAL_CUSTODY_INSTALLER,
    _CANONICAL_CUSTODY_FACTORY,
    _CANONICAL_POPEN_LAUNCHER,
    _CANONICAL_SIGNAL_BLOCKER,
    _CANONICAL_SIGNAL_RESTORER,
    _CANONICAL_PROCESS_TYPE.poll,
    _CANONICAL_PROCESS_TYPE.wait,
    _CANONICAL_PROCESS_TYPE.kill,
    _CANONICAL_PROCESS_TYPE.__del__,
)
_PRELOAD_LINUX_DEFAULT_SNAPSHOTS = tuple(
    (
        function,
        function.__code__,
        function.__defaults__,
        function.__kwdefaults__,
    )
    for function in _LINUX_DEFAULT_BINDING_FUNCTIONS
)


def _bind_linux_function_defaults(
    function: object,
    replacements: dict[str, object],
) -> None:
    code = function.__code__  # type: ignore[union-attr]
    positional_names = code.co_varnames[: code.co_argcount]
    defaults = list(function.__defaults__ or ())  # type: ignore[union-attr]
    offset = len(positional_names) - len(defaults)
    for index, value in enumerate(defaults):
        if value is _LINUX_NATIVE_UNBOUND:
            defaults[index] = replacements[positional_names[offset + index]]
    keywords = dict(function.__kwdefaults__ or {})  # type: ignore[union-attr]
    for name, value in tuple(keywords.items()):
        if value is _LINUX_NATIVE_UNBOUND:
            keywords[name] = replacements[name]
    function.__defaults__ = tuple(defaults)  # type: ignore[union-attr]
    function.__kwdefaults__ = keywords or None  # type: ignore[union-attr]


def _dependency_matches(actual: object, canonical: object) -> bool:
    if type(canonical) in {int, str, bytes, tuple}:
        return type(actual) is type(canonical) and actual == canonical
    return actual is canonical


def _defaults_match_exactly(
    value: object,
    expected: tuple[object, ...],
    expected_keywords: tuple[tuple[str, object], ...],
) -> bool:
    defaults = tuple(value.__defaults__ or ())  # type: ignore[union-attr]
    if defaults != expected or len(defaults) != len(expected):
        return False
    for actual, canonical in zip(defaults, expected, strict=True):
        if not _dependency_matches(actual, canonical):
            return False
    keywords = tuple(sorted((value.__kwdefaults__ or {}).items()))  # type: ignore[union-attr]
    if tuple(key for key, _value in keywords) != tuple(key for key, _value in expected_keywords):
        return False
    return all(
        _dependency_matches(actual, canonical)
        for (_key, actual), (_expected_key, canonical) in zip(
            keywords,
            expected_keywords,
            strict=True,
        )
    )


def _validate_custody_authority() -> None:
    authority = _load_linux_authority()
    try:
        popen_items = tuple(sorted(_CANONICAL_POPEN.__dict__.items()))
        popen_class_matches = len(popen_items) == len(_CANONICAL_POPEN_CLASS_ITEMS) and all(
            name == expected_name and _dependency_matches(actual, expected)
            for (name, actual), (expected_name, expected) in zip(
                popen_items,
                _CANONICAL_POPEN_CLASS_ITEMS,
                strict=True,
            )
        )
        popen_functions_match = all(
            _python_function_state_matches(state[0], state)
            for state in _CANONICAL_POPEN_FUNCTION_STATES
        )
        prctl_address = _CANONICAL_CTYPES_CAST(
            _CANONICAL_PRCTL,
            _CANONICAL_CTYPES_C_VOID_P,
        ).value
        process_handle_hash = _hash(
            {
                "class_items": [
                    [name, _dependency_fingerprint(value)]
                    for name, value in _CANONICAL_PROCESS_CLASS_ITEMS
                ],
                "functions": [
                    _hash(_dependency_fingerprint(snapshot[1]))
                    for snapshot in _CANONICAL_PROCESS_FUNCTION_SNAPSHOTS
                ],
                "type": _dependency_fingerprint(_CANONICAL_PROCESS_TYPE),
            }
        )
        current_process_items = tuple(sorted(_CANONICAL_PROCESS_TYPE.__dict__.items()))
        process_class_matches = len(current_process_items) == len(
            _CANONICAL_PROCESS_CLASS_ITEMS
        ) and all(
            name == expected_name and actual is expected
            for (name, actual), (expected_name, expected) in zip(
                current_process_items,
                _CANONICAL_PROCESS_CLASS_ITEMS,
                strict=True,
            )
        )
        process_functions_match = all(
            _CANONICAL_PROCESS_TYPE.__dict__[name] is function
            and function.__code__ is code
            and function.__defaults__ == defaults
            and function.__kwdefaults__ == kwdefaults
            for name, function, code, defaults, kwdefaults in (
                _CANONICAL_PROCESS_FUNCTION_SNAPSHOTS
            )
        )
    except BaseException:
        raise LocalServicePolicyError() from None
    if (
        _LINUX_AUTHORITY is not authority
        or _CANONICAL_FORK_EXEC is not authority.fork_exec
        or _CANONICAL_OS_PIDFD_OPEN is not authority.pidfd_open
        or _CANONICAL_OS_WAITID is not authority.waitid
        or _CANONICAL_PIDFD_SEND_SIGNAL is not authority.pidfd_send_signal
        or _CANONICAL_PTHREAD_SIGMASK is not authority.pthread_sigmask
        or _CANONICAL_LIBC is not authority.libc
        or _CANONICAL_PRCTL is not authority.prctl
        or _CANONICAL_PRCTL_ADDRESS != authority.prctl_address
        or _CANONICAL_PIDFD_ID != authority.pidfd_id
        or _CANONICAL_WEXITED != authority.wexited
        or _CANONICAL_WNOHANG != authority.wnohang
        or _CANONICAL_CLD_EXITED != authority.cld_exited
        or _CANONICAL_CLD_KILLED != authority.cld_killed
        or _CANONICAL_CLD_DUMPED != authority.cld_dumped
        or _CANONICAL_SIG_BLOCK != authority.sig_block
        or _CANONICAL_SIG_SETMASK != authority.sig_setmask
        or _CANONICAL_SIGKILL != authority.sigkill
        or _CATCHABLE_SIGNALS != authority.catchable_signals
        or _POPEN_INIT_HASH != authority.popen_init_hash
        or _POPEN_NEW_HASH != authority.popen_new_hash
        or _POPEN_DEPENDENCY_HASH != authority.popen_dependency_hash
        or _NATIVE_PRCTL_HASH != authority.native_prctl_hash
        or _PROCESS_HANDLE_HASH != authority.process_handle_hash
        or _SIGNAL_MASK_POLICY_HASH != authority.signal_mask_policy_hash
        or _CUSTODY_DEPENDENCY_HASH != authority.custody_dependency_hash
        or _POPEN_LAUNCH_CONTRACT_HASH != authority.popen_launch_contract_hash
        or _CANONICAL_POLICY is not authority.policy
        or _CANONICAL_POLICY_FIELDS != authority.policy_fields
        or _CANONICAL_POLICY_SNAPSHOT != authority.policy_snapshot
        or _install_local_service_parent_death_policy is not _CANONICAL_CUSTODY_INSTALLER
        or _fixed_parent_death_preexec is not _CANONICAL_CUSTODY_FACTORY
        or _require_single_threaded_broker is not _CANONICAL_SINGLE_THREAD_CHECKER
        or _launch_local_service_popen is not _CANONICAL_POPEN_LAUNCHER
        or _block_local_service_launch_signals is not _CANONICAL_SIGNAL_BLOCKER
        or _restore_local_service_launch_signals is not _CANONICAL_SIGNAL_RESTORER
        or LocalServicePolicyError is not _CANONICAL_POLICY_ERROR
        or _LocalServiceProcess is not _CANONICAL_PROCESS_TYPE
        or not process_class_matches
        or not process_functions_match
        or process_handle_hash != _PROCESS_HANDLE_HASH
        or subprocess._fork_exec is not _CANONICAL_FORK_EXEC
        or sys.audit is not _CANONICAL_SYS_AUDIT
        or sys.gettrace is not _CANONICAL_SYS_GETTRACE
        or sys.getprofile is not _CANONICAL_SYS_GETPROFILE
        or os.pipe is not _CANONICAL_OS_PIPE
        or os.dup is not _CANONICAL_OS_DUP
        or os.open is not _CANONICAL_OS_OPEN
        or os.close is not _CANONICAL_OS_CLOSE
        or os.read is not _CANONICAL_OS_READ
        or os.fdopen is not _CANONICAL_OS_FDOPEN
        or os.pidfd_open is not _CANONICAL_OS_PIDFD_OPEN
        or os.waitid is not _CANONICAL_OS_WAITID
        or os.P_PIDFD != _CANONICAL_PIDFD_ID
        or os.WEXITED != _CANONICAL_WEXITED
        or os.WNOHANG != _CANONICAL_WNOHANG
        or os.CLD_EXITED != _CANONICAL_CLD_EXITED
        or os.CLD_KILLED != _CANONICAL_CLD_KILLED
        or os.CLD_DUMPED != _CANONICAL_CLD_DUMPED
        or os.waitpid is not _CANONICAL_OS_WAITPID
        or signal.pidfd_send_signal is not _CANONICAL_PIDFD_SEND_SIGNAL
        or signal.pthread_sigmask is not _CANONICAL_PTHREAD_SIGMASK
        or signal.SIG_BLOCK != _CANONICAL_SIG_BLOCK
        or signal.SIG_SETMASK != _CANONICAL_SIG_SETMASK
        or signal.SIGKILL != _CANONICAL_SIGKILL
        or time.monotonic is not _CANONICAL_TIME_MONOTONIC
        or time.sleep is not _CANONICAL_TIME_SLEEP
        or subprocess.Popen is not _CANONICAL_POPEN
        or type(_CANONICAL_POPEN) is not _CANONICAL_POPEN_METACLASS
        or type(_CANONICAL_POPEN.__new__) is not type(_CANONICAL_POPEN_NEW)
        or getattr(_CANONICAL_POPEN.__new__, "__self__", None) is not _CANONICAL_POPEN_NEW_SELF
        or _hash(_dependency_fingerprint(_CANONICAL_POPEN.__new__)) != _POPEN_NEW_HASH
        or _CANONICAL_POPEN.__init__ is not _CANONICAL_POPEN_INIT
        or _CANONICAL_POPEN_METACLASS.__call__ is not _CANONICAL_POPEN_METACLASS_CALL
        or not popen_class_matches
        or not popen_functions_match
        or not _python_function_state_matches(
            _CANONICAL_POPEN_INIT,
            _CANONICAL_POPEN_INIT_STATE,
        )
        or ctypes.CDLL is not _CANONICAL_CTYPES_CDLL
        or ctypes.cast is not _CANONICAL_CTYPES_CAST
        or ctypes.c_int is not _CANONICAL_CTYPES_C_INT
        or ctypes.c_ulong is not _CANONICAL_CTYPES_C_ULONG
        or ctypes.c_void_p is not _CANONICAL_CTYPES_C_VOID_P
        or ctypes.get_errno is not _CANONICAL_GET_ERRNO
        or _CANONICAL_LIBC.prctl is not _CANONICAL_PRCTL
        or prctl_address != _CANONICAL_PRCTL_ADDRESS
        or tuple(_CANONICAL_PRCTL.argtypes)
        != (
            _CANONICAL_CTYPES_C_INT,
            _CANONICAL_CTYPES_C_ULONG,
            _CANONICAL_CTYPES_C_ULONG,
            _CANONICAL_CTYPES_C_ULONG,
            _CANONICAL_CTYPES_C_ULONG,
        )
        or _CANONICAL_PRCTL.restype is not _CANONICAL_CTYPES_C_INT
        or _code_hash(_CANONICAL_CUSTODY_INSTALLER) != _CUSTODY_INSTALLER_CODE_HASH
        or _code_hash(_CANONICAL_CUSTODY_FACTORY) != _CUSTODY_FACTORY_CODE_HASH
        or _code_hash(_CANONICAL_SINGLE_THREAD_CHECKER) != _SINGLE_THREAD_CHECKER_HASH
        or _code_hash(_CANONICAL_POPEN_LAUNCHER) != _POPEN_LAUNCHER_CODE_HASH
        or _code_hash(_CANONICAL_SIGNAL_BLOCKER) != _SIGNAL_BLOCKER_CODE_HASH
        or _code_hash(_CANONICAL_SIGNAL_RESTORER) != _SIGNAL_RESTORER_CODE_HASH
        or not _defaults_match_exactly(
            _CANONICAL_CUSTODY_INSTALLER,
            _CANONICAL_INSTALLER_DEFAULTS,
            _CANONICAL_INSTALLER_KWDEFAULTS,
        )
        or not _defaults_match_exactly(
            _CANONICAL_CUSTODY_FACTORY,
            _CANONICAL_FACTORY_DEFAULTS,
            _CANONICAL_FACTORY_KWDEFAULTS,
        )
        or not _defaults_match_exactly(
            _CANONICAL_SINGLE_THREAD_CHECKER,
            _CANONICAL_CHECKER_DEFAULTS,
            _CANONICAL_CHECKER_KWDEFAULTS,
        )
        or not _defaults_match_exactly(
            _CANONICAL_POPEN_LAUNCHER,
            _CANONICAL_LAUNCHER_DEFAULTS,
            _CANONICAL_LAUNCHER_KWDEFAULTS,
        )
        or not _defaults_match_exactly(
            _CANONICAL_SIGNAL_BLOCKER,
            _CANONICAL_BLOCKER_DEFAULTS,
            _CANONICAL_BLOCKER_KWDEFAULTS,
        )
        or not _defaults_match_exactly(
            _CANONICAL_SIGNAL_RESTORER,
            _CANONICAL_RESTORER_DEFAULTS,
            _CANONICAL_RESTORER_KWDEFAULTS,
        )
    ):
        raise LocalServicePolicyError()


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LocalServiceLaunchPolicy:
    bind_host: str
    bind_port: int
    listen_backlog: int
    service_revision: int
    bootstrap_hash: str
    runtime_hash: str
    argv_hash: str
    environment_hash: str
    parent_death_policy_hash: str
    custody_installer_code_hash: str
    custody_factory_code_hash: str
    custody_dependency_hash: str
    single_thread_checker_hash: str
    popen_launch_contract_hash: str
    popen_init_hash: str
    popen_new_hash: str
    popen_dependency_hash: str
    native_prctl_hash: str
    signal_mask_policy_hash: str
    network_filter_hash: str
    content_hash: str

    def as_document(self) -> dict[str, object]:
        return {
            "format": _POLICY_FORMAT,
            "format_version": _FORMAT_VERSION,
            "bind_host": self.bind_host,
            "bind_port": self.bind_port,
            "listen_backlog": self.listen_backlog,
            "service_revision": self.service_revision,
            "bootstrap_hash": self.bootstrap_hash,
            "runtime_hash": self.runtime_hash,
            "argv_hash": self.argv_hash,
            "environment_hash": self.environment_hash,
            "parent_death_policy_hash": self.parent_death_policy_hash,
            "custody_installer_code_hash": self.custody_installer_code_hash,
            "custody_factory_code_hash": self.custody_factory_code_hash,
            "custody_dependency_hash": self.custody_dependency_hash,
            "single_thread_checker_hash": self.single_thread_checker_hash,
            "popen_launch_contract_hash": self.popen_launch_contract_hash,
            "popen_init_hash": self.popen_init_hash,
            "popen_new_hash": self.popen_new_hash,
            "popen_dependency_hash": self.popen_dependency_hash,
            "native_prctl_hash": self.native_prctl_hash,
            "signal_mask_policy_hash": self.signal_mask_policy_hash,
            "network_filter_hash": self.network_filter_hash,
            "content_hash": self.content_hash,
        }


@dataclass(frozen=True, slots=True)
class _LinuxLocalServiceAuthority:
    fork_exec: object
    pidfd_open: object
    waitid: object
    pidfd_send_signal: object
    pthread_sigmask: object
    libc: object
    prctl: object
    prctl_address: int
    pidfd_id: int
    wexited: int
    wnohang: int
    cld_exited: int
    cld_killed: int
    cld_dumped: int
    sig_block: int
    sig_setmask: int
    sigkill: int
    catchable_signals: frozenset[int | signal.Signals]
    popen_new: object
    popen_new_self: object
    popen_init: object
    popen_metaclass: object
    popen_metaclass_call: object
    popen_class_items: tuple[tuple[str, object], ...]
    popen_function_states: tuple[tuple[object, ...], ...]
    popen_init_state: tuple[object, ...]
    popen_init_hash: str
    popen_new_hash: str
    popen_dependency_hash: str
    native_prctl_hash: str
    process_handle_hash: str
    signal_mask_policy_hash: str
    custody_dependency_hash: str
    popen_launch_contract_hash: str
    policy: LocalServiceLaunchPolicy
    policy_fields: tuple[tuple[str, object], ...]
    policy_snapshot: bytes


_LINUX_AUTHORITY: _LinuxLocalServiceAuthority | None = None


def _build_policy(hashes: dict[str, str]) -> LocalServiceLaunchPolicy:
    values: dict[str, object] = {
        "format": _POLICY_FORMAT,
        "format_version": _FORMAT_VERSION,
        "bind_host": _BIND_HOST,
        "bind_port": _BIND_PORT,
        "listen_backlog": _LISTEN_BACKLOG,
        "service_revision": _SERVICE_REVISION,
        "bootstrap_hash": _BOOTSTRAP_HASH,
        "runtime_hash": _RUNTIME_HASH,
        "argv_hash": _ARGV_HASH,
        "environment_hash": _ENVIRONMENT_HASH,
        "parent_death_policy_hash": _PARENT_DEATH_POLICY_HASH,
        "custody_installer_code_hash": hashes["custody_installer_code_hash"],
        "custody_factory_code_hash": hashes["custody_factory_code_hash"],
        "custody_dependency_hash": hashes["custody_dependency_hash"],
        "single_thread_checker_hash": hashes["single_thread_checker_hash"],
        "popen_launch_contract_hash": hashes["popen_launch_contract_hash"],
        "popen_init_hash": hashes["popen_init_hash"],
        "popen_new_hash": hashes["popen_new_hash"],
        "popen_dependency_hash": hashes["popen_dependency_hash"],
        "native_prctl_hash": hashes["native_prctl_hash"],
        "signal_mask_policy_hash": hashes["signal_mask_policy_hash"],
        "network_filter_hash": _NETWORK_FILTER_HASH,
    }
    return LocalServiceLaunchPolicy(
        bind_host=_BIND_HOST,
        bind_port=_BIND_PORT,
        listen_backlog=_LISTEN_BACKLOG,
        service_revision=_SERVICE_REVISION,
        bootstrap_hash=_BOOTSTRAP_HASH,
        runtime_hash=_RUNTIME_HASH,
        argv_hash=_ARGV_HASH,
        environment_hash=_ENVIRONMENT_HASH,
        parent_death_policy_hash=_PARENT_DEATH_POLICY_HASH,
        custody_installer_code_hash=hashes["custody_installer_code_hash"],
        custody_factory_code_hash=hashes["custody_factory_code_hash"],
        custody_dependency_hash=hashes["custody_dependency_hash"],
        single_thread_checker_hash=hashes["single_thread_checker_hash"],
        popen_launch_contract_hash=hashes["popen_launch_contract_hash"],
        popen_init_hash=hashes["popen_init_hash"],
        popen_new_hash=hashes["popen_new_hash"],
        popen_dependency_hash=hashes["popen_dependency_hash"],
        native_prctl_hash=hashes["native_prctl_hash"],
        signal_mask_policy_hash=hashes["signal_mask_policy_hash"],
        network_filter_hash=_NETWORK_FILTER_HASH,
        content_hash=_hash(values),
    )


_CANONICAL_POLICY: LocalServiceLaunchPolicy | object = _LINUX_NATIVE_UNBOUND
_CANONICAL_POLICY_FIELDS: tuple[tuple[str, object], ...] = ()
_CANONICAL_POLICY_SNAPSHOT = b""


def _load_linux_authority() -> _LinuxLocalServiceAuthority:
    global _CANONICAL_CLD_DUMPED
    global _CANONICAL_CLD_EXITED
    global _CANONICAL_CLD_KILLED
    global _CANONICAL_FORK_EXEC
    global _CANONICAL_FACTORY_DEFAULTS
    global _CANONICAL_FACTORY_KWDEFAULTS
    global _CANONICAL_FACTORY_SNAPSHOT
    global _CANONICAL_INSTALLER_DEFAULTS
    global _CANONICAL_INSTALLER_KWDEFAULTS
    global _CANONICAL_LAUNCHER_DEFAULTS
    global _CANONICAL_LAUNCHER_KWDEFAULTS
    global _CANONICAL_LIBC
    global _CANONICAL_OS_PIDFD_OPEN
    global _CANONICAL_OS_WAITID
    global _CANONICAL_PIDFD_ID
    global _CANONICAL_PIDFD_SEND_SIGNAL
    global _CANONICAL_POLICY
    global _CANONICAL_POLICY_FIELDS
    global _CANONICAL_POLICY_SNAPSHOT
    global _CANONICAL_PROCESS_CLASS_ITEMS
    global _CANONICAL_PROCESS_FUNCTION_SNAPSHOTS
    global _CANONICAL_POPEN_CLASS_ITEMS
    global _CANONICAL_POPEN_FUNCTION_STATES
    global _CANONICAL_POPEN_INIT
    global _CANONICAL_POPEN_INIT_STATE
    global _CANONICAL_POPEN_METACLASS
    global _CANONICAL_POPEN_METACLASS_CALL
    global _CANONICAL_POPEN_NEW
    global _CANONICAL_POPEN_NEW_SELF
    global _CANONICAL_PRCTL
    global _CANONICAL_PRCTL_ADDRESS
    global _CANONICAL_PTHREAD_SIGMASK
    global _CANONICAL_SIG_BLOCK
    global _CANONICAL_SIG_SETMASK
    global _CANONICAL_SIGKILL
    global _CANONICAL_BLOCKER_DEFAULTS
    global _CANONICAL_BLOCKER_KWDEFAULTS
    global _CANONICAL_RESTORER_DEFAULTS
    global _CANONICAL_RESTORER_KWDEFAULTS
    global _CANONICAL_WEXITED
    global _CANONICAL_WNOHANG
    global _CATCHABLE_SIGNALS
    global _CUSTODY_DEPENDENCY_HASH
    global _LINUX_AUTHORITY
    global _NATIVE_PRCTL_HASH
    global _POPEN_DEPENDENCY_HASH
    global _POPEN_INIT_HASH
    global _POPEN_LAUNCH_CONTRACT_HASH
    global _POPEN_NEW_HASH
    global _PROCESS_HANDLE_HASH
    global _SIGNAL_MASK_POLICY_HASH

    if type(sys.platform) is not str or sys.platform != "linux":
        raise LocalServicePolicyError()
    authority = _LINUX_AUTHORITY
    if authority is not None:
        return authority
    with _LINUX_AUTHORITY_LOCK:
        authority = _LINUX_AUTHORITY
        if authority is not None:
            return authority
        defaults_bound = False
        try:
            if (
                sys.implementation.name != "cpython"
                or sys.version_info.major != 3
                or sys.version_info.minor != 12
                or ctypes.CDLL is not _CANONICAL_CTYPES_CDLL
                or ctypes.cast is not _CANONICAL_CTYPES_CAST
                or ctypes.c_int is not _CANONICAL_CTYPES_C_INT
                or ctypes.c_ulong is not _CANONICAL_CTYPES_C_ULONG
                or ctypes.c_void_p is not _CANONICAL_CTYPES_C_VOID_P
                or ctypes.get_errno is not _CANONICAL_GET_ERRNO
                or type(_CANONICAL_CTYPES_CDLL) is not type
                or _CANONICAL_CTYPES_CDLL.__module__ != "ctypes"
                or _CANONICAL_CTYPES_CDLL.__qualname__ != "CDLL"
            ):
                raise LocalServicePolicyError()
            fork_exec = subprocess._fork_exec
            pidfd_open = os.pidfd_open
            waitid = os.waitid
            pidfd_send_signal = signal.pidfd_send_signal
            pthread_sigmask = signal.pthread_sigmask
            pidfd_id = os.P_PIDFD
            wexited = os.WEXITED
            wnohang = os.WNOHANG
            cld_exited = os.CLD_EXITED
            cld_killed = os.CLD_KILLED
            cld_dumped = os.CLD_DUMPED
            sig_block = signal.SIG_BLOCK
            sig_setmask = signal.SIG_SETMASK
            sigkill = signal.SIGKILL
            sigstop = signal.SIGSTOP
            catchable_signals = frozenset(signal.valid_signals()) - {sigkill, sigstop}
            if (
                type(fork_exec) is not BuiltinFunctionType
                or fork_exec.__module__ != "_posixsubprocess"
                or fork_exec.__name__ != "fork_exec"
                or type(pidfd_open) is not BuiltinFunctionType
                or pidfd_open.__module__ != "posix"
                or pidfd_open.__name__ != "pidfd_open"
                or type(waitid) is not BuiltinFunctionType
                or waitid.__module__ != "posix"
                or waitid.__name__ != "waitid"
                or type(pidfd_send_signal) is not BuiltinFunctionType
                or pidfd_send_signal.__module__ != "_signal"
                or pidfd_send_signal.__name__ != "pidfd_send_signal"
                or type(pthread_sigmask) is not FunctionType
                or pthread_sigmask.__module__ != "signal"
                or pthread_sigmask.__qualname__ != "pthread_sigmask"
                or type(pidfd_id) is not int
                or type(wexited) is not int
                or type(wnohang) is not int
                or type(cld_exited) is not int
                or type(cld_killed) is not int
                or type(cld_dumped) is not int
                or int(sig_block) != 0
                or int(sig_setmask) != 2
                or int(sigkill) != _LINUX_SIGKILL
                or int(sigstop) != _LINUX_SIGSTOP
                or not catchable_signals
            ):
                raise LocalServicePolicyError()
            libc = _CANONICAL_CTYPES_CDLL(None, use_errno=True)
            prctl = libc.prctl
            if not isinstance(prctl, ctypes._CFuncPtr) or prctl.__name__ != "prctl":
                raise LocalServicePolicyError()
            prctl.argtypes = (
                _CANONICAL_CTYPES_C_INT,
                _CANONICAL_CTYPES_C_ULONG,
                _CANONICAL_CTYPES_C_ULONG,
                _CANONICAL_CTYPES_C_ULONG,
                _CANONICAL_CTYPES_C_ULONG,
            )
            prctl.restype = _CANONICAL_CTYPES_C_INT
            prctl_address = _CANONICAL_CTYPES_CAST(
                prctl,
                _CANONICAL_CTYPES_C_VOID_P,
            ).value
            if type(prctl_address) is not int or prctl_address <= 0:
                raise LocalServicePolicyError()

            if any(
                function is not expected_function
                or function.__code__ is not expected_code
                or function.__defaults__ is not expected_defaults
                or function.__kwdefaults__ is not expected_kwdefaults
                for function, (
                    expected_function,
                    expected_code,
                    expected_defaults,
                    expected_kwdefaults,
                ) in zip(
                    _LINUX_DEFAULT_BINDING_FUNCTIONS,
                    _PRELOAD_LINUX_DEFAULT_SNAPSHOTS,
                    strict=True,
                )
            ):
                raise LocalServicePolicyError()
            replacements = {
                "_prctl": prctl,
                "_sigkill": int(sigkill),
                "_pthread_sigmask": pthread_sigmask,
                "_sig_setmask": int(sig_setmask),
                "_sig_block": int(sig_block),
                "_catchable": catchable_signals,
                "_waitid": waitid,
                "_pidfd_send_signal": pidfd_send_signal,
                "_pidfd_open": pidfd_open,
                "_pidfd_id": pidfd_id,
                "_wexited": wexited,
            }
            defaults_bound = True
            for function in _LINUX_DEFAULT_BINDING_FUNCTIONS:
                _bind_linux_function_defaults(function, replacements)
            installer_defaults = tuple(_CANONICAL_CUSTODY_INSTALLER.__defaults__ or ())
            installer_kwdefaults = tuple(
                sorted((_CANONICAL_CUSTODY_INSTALLER.__kwdefaults__ or {}).items())
            )
            factory_defaults = tuple(_CANONICAL_CUSTODY_FACTORY.__defaults__ or ())
            factory_kwdefaults = tuple(
                sorted((_CANONICAL_CUSTODY_FACTORY.__kwdefaults__ or {}).items())
            )
            factory_snapshot = (
                _CANONICAL_CUSTODY_FACTORY,
                _CANONICAL_CUSTODY_FACTORY.__code__,
                _CANONICAL_CUSTODY_FACTORY.__defaults__,
                _CANONICAL_CUSTODY_FACTORY.__kwdefaults__,
            )
            launcher_defaults = tuple(_CANONICAL_POPEN_LAUNCHER.__defaults__ or ())
            launcher_kwdefaults = tuple(
                sorted((_CANONICAL_POPEN_LAUNCHER.__kwdefaults__ or {}).items())
            )
            blocker_defaults = tuple(_CANONICAL_SIGNAL_BLOCKER.__defaults__ or ())
            blocker_kwdefaults = tuple(
                sorted((_CANONICAL_SIGNAL_BLOCKER.__kwdefaults__ or {}).items())
            )
            restorer_defaults = tuple(_CANONICAL_SIGNAL_RESTORER.__defaults__ or ())
            restorer_kwdefaults = tuple(
                sorted((_CANONICAL_SIGNAL_RESTORER.__kwdefaults__ or {}).items())
            )
            process_class_items = tuple(sorted(_CANONICAL_PROCESS_TYPE.__dict__.items()))
            process_function_snapshots = tuple(
                (
                    name,
                    function,
                    function.__code__,
                    function.__defaults__,
                    function.__kwdefaults__,
                )
                for name, function in process_class_items
                if type(function) is FunctionType
            )

            popen_items = tuple(sorted(_CANONICAL_POPEN.__dict__.items()))
            popen_functions = _popen_python_functions(_CANONICAL_POPEN)
            if (
                len(popen_items) != len(_PRELOAD_POPEN_CLASS_ITEMS)
                or any(
                    name != expected_name or value is not expected
                    for (name, value), (expected_name, expected) in zip(
                        popen_items,
                        _PRELOAD_POPEN_CLASS_ITEMS,
                        strict=True,
                    )
                )
                or len(popen_functions) != len(_PRELOAD_POPEN_FUNCTION_SNAPSHOTS)
                or any(
                    function is not expected_function
                    or function.__code__ is not expected_code
                    or function.__defaults__ is not expected_defaults
                    or function.__kwdefaults__ is not expected_kwdefaults
                    for function, (
                        expected_function,
                        expected_code,
                        expected_defaults,
                        expected_kwdefaults,
                    ) in zip(
                        popen_functions,
                        _PRELOAD_POPEN_FUNCTION_SNAPSHOTS,
                        strict=True,
                    )
                )
                or _CANONICAL_POPEN.__init__ is not _PRELOAD_POPEN_INIT
                or type(_CANONICAL_POPEN) is not _PRELOAD_POPEN_METACLASS
                or type(_CANONICAL_POPEN).__call__ is not _PRELOAD_POPEN_METACLASS_CALL
            ):
                raise LocalServicePolicyError()
            popen_new = _CANONICAL_POPEN.__new__
            if type(popen_new) is not type(_PRELOAD_POPEN_NEW) or getattr(
                popen_new, "__self__", None
            ) is not getattr(_PRELOAD_POPEN_NEW, "__self__", None):
                raise LocalServicePolicyError()
            popen_init = _CANONICAL_POPEN.__init__
            popen_metaclass = type(_CANONICAL_POPEN)
            popen_metaclass_call = popen_metaclass.__call__
            popen_function_states = tuple(
                _capture_python_function_state(value) for value in popen_functions
            )
            popen_init_state = _capture_python_function_state(popen_init)
            popen_init_hash = popen_init_state[6]
            popen_new_hash = _hash(_dependency_fingerprint(popen_new))
            popen_dependency_hash = _hash(
                {
                    "class_items": [
                        [name, _dependency_fingerprint(value)] for name, value in popen_items
                    ],
                    "functions": [state[6] for state in popen_function_states],
                    "metaclass": _dependency_fingerprint(popen_metaclass),
                    "metaclass_call": _dependency_fingerprint(popen_metaclass_call),
                    "new": _dependency_fingerprint(popen_new),
                }
            )
            native_prctl_hash = _hash(
                {
                    "argtypes": _dependency_fingerprint(tuple(prctl.argtypes)),
                    "cast": _dependency_fingerprint(_CANONICAL_CTYPES_CAST),
                    "cdll": _dependency_fingerprint(_CANONICAL_CTYPES_CDLL),
                    "get_errno": _dependency_fingerprint(_CANONICAL_GET_ERRNO),
                    "library": "CDLL(None,use_errno=True)",
                    "restype": _dependency_fingerprint(prctl.restype),
                    "symbol": "prctl",
                }
            )
            process_handle_hash = _hash(
                {
                    "class_items": [
                        [name, _dependency_fingerprint(value)]
                        for name, value in process_class_items
                    ],
                    "functions": [
                        _hash(_dependency_fingerprint(snapshot[1]))
                        for snapshot in process_function_snapshots
                    ],
                    "type": _dependency_fingerprint(_CANONICAL_PROCESS_TYPE),
                }
            )
            signal_mask_policy_hash = _hash(
                {
                    "blocker_code_hash": _SIGNAL_BLOCKER_CODE_HASH,
                    "blocker_defaults": _dependency_fingerprint(blocker_defaults),
                    "document": _SIGNAL_MASK_POLICY_DOCUMENT,
                    "pthread_sigmask": _dependency_fingerprint(pthread_sigmask),
                    "restorer_code_hash": _SIGNAL_RESTORER_CODE_HASH,
                    "restorer_defaults": _dependency_fingerprint(restorer_defaults),
                }
            )
            custody_dependency_hash = _hash(
                {
                    "checker_defaults": _dependency_fingerprint(_CANONICAL_CHECKER_DEFAULTS),
                    "checker_kwdefaults": _dependency_fingerprint(_CANONICAL_CHECKER_KWDEFAULTS),
                    "factory_defaults": _dependency_fingerprint(factory_defaults),
                    "factory_kwdefaults": _dependency_fingerprint(factory_kwdefaults),
                    "fork_exec": _dependency_fingerprint(fork_exec),
                    "installer_defaults": _dependency_fingerprint(installer_defaults),
                    "installer_kwdefaults": _dependency_fingerprint(installer_kwdefaults),
                    "launcher_defaults": _dependency_fingerprint(launcher_defaults),
                    "launcher_kwdefaults": _dependency_fingerprint(launcher_kwdefaults),
                    "python_abi": {
                        "implementation": sys.implementation.name,
                        "major": sys.version_info.major,
                        "minor": sys.version_info.minor,
                    },
                    "sys_audit": _dependency_fingerprint(_CANONICAL_SYS_AUDIT),
                    "sys_getprofile": _dependency_fingerprint(_CANONICAL_SYS_GETPROFILE),
                    "sys_gettrace": _dependency_fingerprint(_CANONICAL_SYS_GETTRACE),
                    "native_prctl_hash": native_prctl_hash,
                    "pidfd_open": _dependency_fingerprint(pidfd_open),
                    "pidfd_send_signal": _dependency_fingerprint(pidfd_send_signal),
                    "popen_dependency_hash": popen_dependency_hash,
                    "process_handle_hash": process_handle_hash,
                    "signal_mask_policy_hash": signal_mask_policy_hash,
                    "waitid": _dependency_fingerprint(waitid),
                }
            )
            popen_launch_contract_hash = _hash(
                {
                    "contract": _POPEN_LAUNCH_CONTRACT_DOCUMENT,
                    "dependency_hash": custody_dependency_hash,
                    "launcher_code_hash": _POPEN_LAUNCHER_CODE_HASH,
                    "process_handle_hash": process_handle_hash,
                    "popen_dependency_hash": popen_dependency_hash,
                    "popen_init_hash": popen_init_hash,
                    "popen_new_hash": popen_new_hash,
                    "signal_mask_policy_hash": signal_mask_policy_hash,
                }
            )
            hashes = {
                "custody_installer_code_hash": _CUSTODY_INSTALLER_CODE_HASH,
                "custody_factory_code_hash": _CUSTODY_FACTORY_CODE_HASH,
                "custody_dependency_hash": custody_dependency_hash,
                "single_thread_checker_hash": _SINGLE_THREAD_CHECKER_HASH,
                "popen_launch_contract_hash": popen_launch_contract_hash,
                "popen_init_hash": popen_init_hash,
                "popen_new_hash": popen_new_hash,
                "popen_dependency_hash": popen_dependency_hash,
                "native_prctl_hash": native_prctl_hash,
                "signal_mask_policy_hash": signal_mask_policy_hash,
            }
            policy = _build_policy(hashes)
            policy_fields = tuple(
                (field, getattr(policy, field)) for field in policy.__dataclass_fields__
            )
            policy_snapshot = _canonical(policy.as_document())
            authority = _LinuxLocalServiceAuthority(
                fork_exec=fork_exec,
                pidfd_open=pidfd_open,
                waitid=waitid,
                pidfd_send_signal=pidfd_send_signal,
                pthread_sigmask=pthread_sigmask,
                libc=libc,
                prctl=prctl,
                prctl_address=prctl_address,
                pidfd_id=pidfd_id,
                wexited=wexited,
                wnohang=wnohang,
                cld_exited=cld_exited,
                cld_killed=cld_killed,
                cld_dumped=cld_dumped,
                sig_block=int(sig_block),
                sig_setmask=int(sig_setmask),
                sigkill=int(sigkill),
                catchable_signals=catchable_signals,
                popen_new=popen_new,
                popen_new_self=getattr(popen_new, "__self__", None),
                popen_init=popen_init,
                popen_metaclass=popen_metaclass,
                popen_metaclass_call=popen_metaclass_call,
                popen_class_items=popen_items,
                popen_function_states=popen_function_states,
                popen_init_state=popen_init_state,
                popen_init_hash=popen_init_hash,
                popen_new_hash=popen_new_hash,
                popen_dependency_hash=popen_dependency_hash,
                native_prctl_hash=native_prctl_hash,
                process_handle_hash=process_handle_hash,
                signal_mask_policy_hash=signal_mask_policy_hash,
                custody_dependency_hash=custody_dependency_hash,
                popen_launch_contract_hash=popen_launch_contract_hash,
                policy=policy,
                policy_fields=policy_fields,
                policy_snapshot=policy_snapshot,
            )
        except BaseException as exc:
            if defaults_bound:
                for (
                    function,
                    _expected_code,
                    expected_defaults,
                    expected_kwdefaults,
                ) in _PRELOAD_LINUX_DEFAULT_SNAPSHOTS:
                    function.__defaults__ = expected_defaults
                    function.__kwdefaults__ = expected_kwdefaults
            if isinstance(exc, LocalServicePolicyError):
                raise
            raise LocalServicePolicyError() from None

        _CANONICAL_FORK_EXEC = authority.fork_exec
        _CANONICAL_OS_PIDFD_OPEN = authority.pidfd_open
        _CANONICAL_OS_WAITID = authority.waitid
        _CANONICAL_PIDFD_SEND_SIGNAL = authority.pidfd_send_signal
        _CANONICAL_PTHREAD_SIGMASK = authority.pthread_sigmask
        _CANONICAL_LIBC = authority.libc
        _CANONICAL_PRCTL = authority.prctl
        _CANONICAL_PRCTL_ADDRESS = authority.prctl_address
        _CANONICAL_PIDFD_ID = authority.pidfd_id
        _CANONICAL_WEXITED = authority.wexited
        _CANONICAL_WNOHANG = authority.wnohang
        _CANONICAL_CLD_EXITED = authority.cld_exited
        _CANONICAL_CLD_KILLED = authority.cld_killed
        _CANONICAL_CLD_DUMPED = authority.cld_dumped
        _CANONICAL_SIG_BLOCK = authority.sig_block
        _CANONICAL_SIG_SETMASK = authority.sig_setmask
        _CANONICAL_SIGKILL = authority.sigkill
        _CATCHABLE_SIGNALS = authority.catchable_signals
        _CANONICAL_INSTALLER_DEFAULTS = installer_defaults
        _CANONICAL_INSTALLER_KWDEFAULTS = installer_kwdefaults
        _CANONICAL_FACTORY_DEFAULTS = factory_defaults
        _CANONICAL_FACTORY_KWDEFAULTS = factory_kwdefaults
        _CANONICAL_FACTORY_SNAPSHOT = factory_snapshot
        _CANONICAL_LAUNCHER_DEFAULTS = launcher_defaults
        _CANONICAL_LAUNCHER_KWDEFAULTS = launcher_kwdefaults
        _CANONICAL_BLOCKER_DEFAULTS = blocker_defaults
        _CANONICAL_BLOCKER_KWDEFAULTS = blocker_kwdefaults
        _CANONICAL_RESTORER_DEFAULTS = restorer_defaults
        _CANONICAL_RESTORER_KWDEFAULTS = restorer_kwdefaults
        _CANONICAL_PROCESS_CLASS_ITEMS = process_class_items
        _CANONICAL_PROCESS_FUNCTION_SNAPSHOTS = process_function_snapshots
        _CANONICAL_POPEN_NEW = authority.popen_new
        _CANONICAL_POPEN_NEW_SELF = authority.popen_new_self
        _CANONICAL_POPEN_INIT = authority.popen_init
        _CANONICAL_POPEN_METACLASS = authority.popen_metaclass
        _CANONICAL_POPEN_METACLASS_CALL = authority.popen_metaclass_call
        _CANONICAL_POPEN_CLASS_ITEMS = authority.popen_class_items
        _CANONICAL_POPEN_FUNCTION_STATES = authority.popen_function_states
        _CANONICAL_POPEN_INIT_STATE = authority.popen_init_state
        _POPEN_INIT_HASH = authority.popen_init_hash
        _POPEN_NEW_HASH = authority.popen_new_hash
        _POPEN_DEPENDENCY_HASH = authority.popen_dependency_hash
        _NATIVE_PRCTL_HASH = authority.native_prctl_hash
        _PROCESS_HANDLE_HASH = authority.process_handle_hash
        _SIGNAL_MASK_POLICY_HASH = authority.signal_mask_policy_hash
        _CUSTODY_DEPENDENCY_HASH = authority.custody_dependency_hash
        _POPEN_LAUNCH_CONTRACT_HASH = authority.popen_launch_contract_hash
        _CANONICAL_POLICY = authority.policy
        _CANONICAL_POLICY_FIELDS = authority.policy_fields
        _CANONICAL_POLICY_SNAPSHOT = authority.policy_snapshot
        _LINUX_AUTHORITY = authority
        return authority


_POLICY_IDENTITIES: dict[
    int,
    tuple[ReferenceType[object], bytes, str],
] = {}


def _register_policy(value: LocalServiceLaunchPolicy) -> None:
    identity = id(value)

    def retire(reference: ReferenceType[object]) -> None:
        registered = _POLICY_IDENTITIES.get(identity)
        if registered is not None and registered[0] is reference:
            del _POLICY_IDENTITIES[identity]

    snapshot = _canonical(value.as_document())
    _POLICY_IDENTITIES[identity] = (ref(value, retire), snapshot, value.content_hash)


def _new_local_service_launch_policy(
    _fields: object = _LINUX_NATIVE_UNBOUND,
) -> LocalServiceLaunchPolicy:
    authority = _load_linux_authority()
    _validate_custody_authority()
    if _fields is _LINUX_NATIVE_UNBOUND:
        _fields = authority.policy_fields
    if type(_fields) is not tuple:
        raise LocalServicePolicyError()
    value = LocalServiceLaunchPolicy(**dict(_fields))
    _register_policy(value)
    return value


def code_owned_local_service_launch_policy() -> LocalServiceLaunchPolicy:
    return _new_local_service_launch_policy()


def _validate_local_service_launch_policy(
    value: object,
    _snapshot: object = _LINUX_NATIVE_UNBOUND,
) -> LocalServiceLaunchPolicy:
    authority = _load_linux_authority()
    _validate_custody_authority()
    if _snapshot is _LINUX_NATIVE_UNBOUND:
        _snapshot = authority.policy_snapshot
    if type(_snapshot) is not bytes:
        raise LocalServicePolicyError()
    registered = _POLICY_IDENTITIES.get(id(value))
    if (
        type(value) is not LocalServiceLaunchPolicy
        or _canonical(value.as_document()) != _snapshot
        or registered is None
        or registered[0]() is not value
        or registered[1] != _snapshot
        or registered[2] != value.content_hash
    ):
        raise LocalServicePolicyError()
    return value


def _fixed_local_service_environment(
    _environment: tuple[tuple[str, str], ...] = _SERVICE_ENVIRONMENT,
) -> dict[str, str]:
    return dict(_environment)


def _local_service_environment() -> dict[str, str]:
    return _fixed_local_service_environment()


_CANONICAL_EXECUTABLE = os.path.abspath(sys.executable)
_CANONICAL_BOOTSTRAP_SOURCE = LOCAL_SERVICE_BOOTSTRAP_SOURCE
_ARGV_ROLES = (
    "executable",
    "isolated",
    "no_bytecode",
    "no_site",
    "unbuffered",
    "implementation_option",
    "utf8_mode",
    "command",
    "bootstrap",
)


def _fixed_local_service_command(
    _executable: str = _CANONICAL_EXECUTABLE,
    _bootstrap: str = _CANONICAL_BOOTSTRAP_SOURCE,
) -> tuple[str, ...]:
    executable = _executable
    if not os.path.isabs(executable):
        raise LocalServicePolicyError()
    return (
        executable,
        "-I",
        "-B",
        "-S",
        "-u",
        "-X",
        "utf8",
        "-c",
        _bootstrap,
    )


def local_service_command() -> tuple[str, ...]:
    return _fixed_local_service_command()


def _hash_file(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb", buffering=0) as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    return digest.hexdigest()
                digest.update(chunk)
    except BaseException:
        raise LocalServicePolicyError() from None


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _LocalServiceLaunchRecipe:
    policy: LocalServiceLaunchPolicy
    executable: str
    executable_realpath: str
    executable_device: int
    executable_inode: int
    executable_mode: int
    executable_size: int
    executable_mtime_ns: int
    executable_hash: str
    executable_capabilities_hash: str
    bootstrap_source: str
    bootstrap_hash: str
    argv_roles: tuple[str, ...]
    argv: tuple[str, ...]
    argv_content_hash: str
    environment: tuple[tuple[str, str], ...]
    environment_canonical: bytes
    environment_hash: str
    parent_death_policy_hash: str
    custody_installer_code_hash: str
    custody_factory_code_hash: str
    custody_dependency_hash: str
    single_thread_checker_hash: str
    popen_launch_contract_hash: str
    popen_init_hash: str
    popen_new_hash: str
    popen_dependency_hash: str
    native_prctl_hash: str
    signal_mask_policy_hash: str
    runtime_hash: str
    network_filter_hash: str
    fd_census_hash: str
    self_test_hash: str
    content_hash: str


def _recipe_document(value: _LocalServiceLaunchRecipe) -> dict[str, object]:
    return {
        "format": "world-forge.private.local_service_launch_recipe",
        "format_version": _FORMAT_VERSION,
        "policy_hash": value.policy.content_hash,
        "executable": value.executable,
        "executable_realpath": value.executable_realpath,
        "executable_device": value.executable_device,
        "executable_inode": value.executable_inode,
        "executable_mode": value.executable_mode,
        "executable_size": value.executable_size,
        "executable_mtime_ns": value.executable_mtime_ns,
        "executable_hash": value.executable_hash,
        "executable_capabilities_hash": value.executable_capabilities_hash,
        "bootstrap_source": value.bootstrap_source,
        "bootstrap_hash": value.bootstrap_hash,
        "argv_roles": list(value.argv_roles),
        "argv": list(value.argv),
        "argv_content_hash": value.argv_content_hash,
        "environment": [list(item) for item in value.environment],
        "environment_canonical_base64": base64.b64encode(value.environment_canonical).decode(
            "ascii"
        ),
        "environment_hash": value.environment_hash,
        "parent_death_policy_hash": value.parent_death_policy_hash,
        "custody_installer_code_hash": value.custody_installer_code_hash,
        "custody_factory_code_hash": value.custody_factory_code_hash,
        "custody_dependency_hash": value.custody_dependency_hash,
        "single_thread_checker_hash": value.single_thread_checker_hash,
        "popen_launch_contract_hash": value.popen_launch_contract_hash,
        "popen_init_hash": value.popen_init_hash,
        "popen_new_hash": value.popen_new_hash,
        "popen_dependency_hash": value.popen_dependency_hash,
        "native_prctl_hash": value.native_prctl_hash,
        "signal_mask_policy_hash": value.signal_mask_policy_hash,
        "runtime_hash": value.runtime_hash,
        "network_filter_hash": value.network_filter_hash,
        "fd_census_hash": value.fd_census_hash,
        "self_test_hash": value.self_test_hash,
    }


_RECIPE_IDENTITIES: dict[
    int,
    tuple[ReferenceType[object], ReferenceType[object], bytes, str],
] = {}


def _register_recipe(value: _LocalServiceLaunchRecipe) -> None:
    identity = id(value)

    def retire(reference: ReferenceType[object]) -> None:
        registered = _RECIPE_IDENTITIES.get(identity)
        if registered is not None and registered[0] is reference:
            del _RECIPE_IDENTITIES[identity]

    snapshot = _canonical(_recipe_document(value))
    _RECIPE_IDENTITIES[identity] = (
        ref(value, retire),
        ref(value.policy),
        snapshot,
        value.content_hash,
    )


def _executable_snapshot(path: str) -> tuple[str, os.stat_result, str, str]:
    try:
        if type(path) is not str or not os.path.isabs(path):
            raise ValueError
        realpath = os.path.realpath(path)
        if not os.path.isabs(realpath):
            raise ValueError
        metadata = os.stat(realpath, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise ValueError
        try:
            capabilities = os.getxattr(
                realpath,
                "security.capability",
                follow_symlinks=False,
            )
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                raise
            capabilities = b""
        if capabilities:
            raise ValueError
        content_hash = _hash_file(realpath)
    except LocalServicePolicyError:
        raise
    except BaseException:
        raise LocalServicePolicyError() from None
    return realpath, metadata, content_hash, hashlib.sha256(capabilities).hexdigest()


def _issue_local_service_launch_recipe(
    policy: object,
    _executable: str = _CANONICAL_EXECUTABLE,
    _bootstrap: str = _CANONICAL_BOOTSTRAP_SOURCE,
    _environment: tuple[tuple[str, str], ...] = _SERVICE_ENVIRONMENT,
    _argv_roles: tuple[str, ...] = _ARGV_ROLES,
) -> _LocalServiceLaunchRecipe:
    checked = _validate_local_service_launch_policy(policy)
    realpath, metadata, executable_hash, executable_capabilities_hash = _executable_snapshot(
        _executable
    )
    argv = _fixed_local_service_command(_executable, _bootstrap)
    environment = tuple(_environment)
    environment_canonical = _canonical(dict(environment))
    values: dict[str, object] = {
        "policy_hash": checked.content_hash,
        "executable": _executable,
        "executable_realpath": realpath,
        "executable_device": metadata.st_dev,
        "executable_inode": metadata.st_ino,
        "executable_mode": metadata.st_mode,
        "executable_size": metadata.st_size,
        "executable_mtime_ns": metadata.st_mtime_ns,
        "executable_hash": executable_hash,
        "executable_capabilities_hash": executable_capabilities_hash,
        "bootstrap_source": _bootstrap,
        "bootstrap_hash": hashlib.sha256(_bootstrap.encode("utf-8")).hexdigest(),
        "argv_roles": _argv_roles,
        "argv": argv,
        "argv_content_hash": _hash(list(argv)),
        "environment": environment,
        "environment_canonical": environment_canonical,
        "environment_hash": hashlib.sha256(environment_canonical).hexdigest(),
        "parent_death_policy_hash": checked.parent_death_policy_hash,
        "custody_installer_code_hash": checked.custody_installer_code_hash,
        "custody_factory_code_hash": checked.custody_factory_code_hash,
        "custody_dependency_hash": checked.custody_dependency_hash,
        "single_thread_checker_hash": checked.single_thread_checker_hash,
        "popen_launch_contract_hash": checked.popen_launch_contract_hash,
        "popen_init_hash": checked.popen_init_hash,
        "popen_new_hash": checked.popen_new_hash,
        "popen_dependency_hash": checked.popen_dependency_hash,
        "native_prctl_hash": checked.native_prctl_hash,
        "signal_mask_policy_hash": checked.signal_mask_policy_hash,
        "runtime_hash": checked.runtime_hash,
        "network_filter_hash": checked.network_filter_hash,
        "fd_census_hash": _FD_CENSUS_HASH,
        "self_test_hash": _SELF_TEST_HASH,
    }
    content_values = dict(values)
    content_values["environment_canonical_base64"] = base64.b64encode(environment_canonical).decode(
        "ascii"
    )
    del content_values["environment_canonical"]
    recipe = _LocalServiceLaunchRecipe(
        checked,
        _executable,
        realpath,
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        executable_hash,
        executable_capabilities_hash,
        _bootstrap,
        values["bootstrap_hash"],  # type: ignore[arg-type]
        _argv_roles,
        argv,
        values["argv_content_hash"],  # type: ignore[arg-type]
        environment,
        environment_canonical,
        values["environment_hash"],  # type: ignore[arg-type]
        checked.parent_death_policy_hash,
        checked.custody_installer_code_hash,
        checked.custody_factory_code_hash,
        checked.custody_dependency_hash,
        checked.single_thread_checker_hash,
        checked.popen_launch_contract_hash,
        checked.popen_init_hash,
        checked.popen_new_hash,
        checked.popen_dependency_hash,
        checked.native_prctl_hash,
        checked.signal_mask_policy_hash,
        checked.runtime_hash,
        checked.network_filter_hash,
        _FD_CENSUS_HASH,
        _SELF_TEST_HASH,
        _hash(content_values),
    )
    _register_recipe(recipe)
    return _validate_local_service_launch_recipe(recipe, policy=checked)


def _code_owned_local_service_launch_recipe(
    policy: object,
) -> _LocalServiceLaunchRecipe:
    return _issue_local_service_launch_recipe(policy)


def _validate_recipe_snapshot(
    value: object,
    *,
    policy: object,
    require_live_executable: bool,
    _argv_roles: tuple[str, ...] = _ARGV_ROLES,
    _environment: tuple[tuple[str, str], ...] = _SERVICE_ENVIRONMENT,
    _fd_census_hash: str = _FD_CENSUS_HASH,
    _self_test_hash: str = _SELF_TEST_HASH,
    _parent_death_policy_hash: str = _PARENT_DEATH_POLICY_HASH,
) -> _LocalServiceLaunchRecipe:
    if type(value) is not _LocalServiceLaunchRecipe or type(policy) is not LocalServiceLaunchPolicy:
        raise LocalServicePolicyError()
    try:
        environment_canonical = _canonical(dict(value.environment))
        (
            realpath,
            metadata,
            executable_hash,
            executable_capabilities_hash,
        ) = _executable_snapshot(value.executable)
        expected_values = {
            "policy_hash": policy.content_hash,
            "executable": value.executable,
            "executable_realpath": value.executable_realpath,
            "executable_device": value.executable_device,
            "executable_inode": value.executable_inode,
            "executable_mode": value.executable_mode,
            "executable_size": value.executable_size,
            "executable_mtime_ns": value.executable_mtime_ns,
            "executable_hash": value.executable_hash,
            "executable_capabilities_hash": value.executable_capabilities_hash,
            "bootstrap_source": value.bootstrap_source,
            "bootstrap_hash": value.bootstrap_hash,
            "argv_roles": value.argv_roles,
            "argv": value.argv,
            "argv_content_hash": value.argv_content_hash,
            "environment": value.environment,
            "environment_canonical": value.environment_canonical,
            "environment_hash": value.environment_hash,
            "parent_death_policy_hash": value.parent_death_policy_hash,
            "custody_installer_code_hash": value.custody_installer_code_hash,
            "custody_factory_code_hash": value.custody_factory_code_hash,
            "custody_dependency_hash": value.custody_dependency_hash,
            "single_thread_checker_hash": value.single_thread_checker_hash,
            "popen_launch_contract_hash": value.popen_launch_contract_hash,
            "popen_init_hash": value.popen_init_hash,
            "popen_new_hash": value.popen_new_hash,
            "popen_dependency_hash": value.popen_dependency_hash,
            "native_prctl_hash": value.native_prctl_hash,
            "signal_mask_policy_hash": value.signal_mask_policy_hash,
            "runtime_hash": value.runtime_hash,
            "network_filter_hash": value.network_filter_hash,
            "fd_census_hash": value.fd_census_hash,
            "self_test_hash": value.self_test_hash,
        }
        content_values = dict(expected_values)
        content_values["environment_canonical_base64"] = base64.b64encode(
            value.environment_canonical
        ).decode("ascii")
        del content_values["environment_canonical"]
        if (
            value.policy is not policy
            or value.bootstrap_hash != policy.bootstrap_hash
            or hashlib.sha256(value.bootstrap_source.encode("utf-8")).hexdigest()
            != value.bootstrap_hash
            or value.argv_roles != _argv_roles
            or value.argv
            != (
                value.executable,
                "-I",
                "-B",
                "-S",
                "-u",
                "-X",
                "utf8",
                "-c",
                value.bootstrap_source,
            )
            or value.argv_content_hash != _hash(list(value.argv))
            or value.environment != _environment
            or value.environment_canonical != environment_canonical
            or value.environment_hash != hashlib.sha256(environment_canonical).hexdigest()
            or value.environment_hash != policy.environment_hash
            or value.parent_death_policy_hash != _parent_death_policy_hash
            or value.parent_death_policy_hash != policy.parent_death_policy_hash
            or value.custody_installer_code_hash != _CUSTODY_INSTALLER_CODE_HASH
            or value.custody_installer_code_hash != policy.custody_installer_code_hash
            or value.custody_factory_code_hash != _CUSTODY_FACTORY_CODE_HASH
            or value.custody_factory_code_hash != policy.custody_factory_code_hash
            or value.custody_dependency_hash != _CUSTODY_DEPENDENCY_HASH
            or value.custody_dependency_hash != policy.custody_dependency_hash
            or value.single_thread_checker_hash != _SINGLE_THREAD_CHECKER_HASH
            or value.single_thread_checker_hash != policy.single_thread_checker_hash
            or value.popen_launch_contract_hash != _POPEN_LAUNCH_CONTRACT_HASH
            or value.popen_launch_contract_hash != policy.popen_launch_contract_hash
            or value.popen_init_hash != _POPEN_INIT_HASH
            or value.popen_init_hash != policy.popen_init_hash
            or value.popen_new_hash != _POPEN_NEW_HASH
            or value.popen_new_hash != policy.popen_new_hash
            or value.popen_dependency_hash != _POPEN_DEPENDENCY_HASH
            or value.popen_dependency_hash != policy.popen_dependency_hash
            or value.native_prctl_hash != _NATIVE_PRCTL_HASH
            or value.native_prctl_hash != policy.native_prctl_hash
            or value.signal_mask_policy_hash != _SIGNAL_MASK_POLICY_HASH
            or value.signal_mask_policy_hash != policy.signal_mask_policy_hash
            or value.runtime_hash != policy.runtime_hash
            or value.network_filter_hash != policy.network_filter_hash
            or value.fd_census_hash != _fd_census_hash
            or value.self_test_hash != _self_test_hash
            or value.content_hash != _hash(content_values)
            or require_live_executable
            and (
                realpath != value.executable_realpath
                or metadata.st_dev != value.executable_device
                or metadata.st_ino != value.executable_inode
                or metadata.st_mode != value.executable_mode
                or metadata.st_size != value.executable_size
                or metadata.st_mtime_ns != value.executable_mtime_ns
                or executable_hash != value.executable_hash
                or executable_capabilities_hash != value.executable_capabilities_hash
            )
        ):
            raise LocalServicePolicyError()
    except LocalServicePolicyError:
        raise
    except BaseException:
        raise LocalServicePolicyError() from None
    return value


def _validate_local_service_launch_recipe(
    value: object,
    *,
    policy: object,
) -> _LocalServiceLaunchRecipe:
    checked_policy = _validate_local_service_launch_policy(policy)
    checked = _validate_recipe_snapshot(
        value,
        policy=checked_policy,
        require_live_executable=True,
    )
    registered = _RECIPE_IDENTITIES.get(id(checked))
    if (
        registered is None
        or registered[0]() is not checked
        or registered[1]() is not checked_policy
        or registered[2] != _canonical(_recipe_document(checked))
        or registered[3] != checked.content_hash
    ):
        raise LocalServicePolicyError()
    return checked


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _LocalServiceLease:
    policy: LocalServiceLaunchPolicy
    recipe: _LocalServiceLaunchRecipe
    listener: socket.socket
    host: str
    port: int
    listener_inode: int
    root_device: int
    root_inode: int


_LEASE_IDENTITIES: dict[
    int,
    tuple[
        ReferenceType[object],
        ReferenceType[object],
        ReferenceType[object],
        int,
        int,
        str,
        bytes,
    ],
] = {}


def _register_lease(value: _LocalServiceLease) -> None:
    identity = id(value)

    def retire(reference: ReferenceType[object]) -> None:
        registered = _LEASE_IDENTITIES.get(identity)
        if registered is not None and registered[0] is reference:
            del _LEASE_IDENTITIES[identity]

    snapshot = _canonical(
        {
            "policy_hash": value.policy.content_hash,
            "recipe_hash": value.recipe.content_hash,
            "listener_identity": id(value.listener),
            "listener_fd": value.listener.fileno(),
            "host": value.host,
            "port": value.port,
            "listener_inode": value.listener_inode,
            "root_device": value.root_device,
            "root_inode": value.root_inode,
        }
    )
    _LEASE_IDENTITIES[identity] = (
        ref(value, retire),
        ref(value.policy),
        ref(value.recipe),
        id(value.listener),
        value.listener.fileno(),
        "open",
        snapshot,
    )


def _acquire_local_service_lease(
    policy: object,
    *,
    recipe: object,
) -> _LocalServiceLease:
    checked = _validate_local_service_launch_policy(policy)
    checked_recipe = _validate_local_service_launch_recipe(recipe, policy=checked)
    listener: socket.socket | None = None
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.set_inheritable(False)
        listener.bind((_BIND_HOST, _BIND_PORT))
        listener.listen(_LISTEN_BACKLOG)
        address = listener.getsockname()
        descriptor = listener.fileno()
        inode = os.fstat(descriptor).st_ino
        root = os.stat("/")
        if (
            type(address) is not tuple
            or address[0] != _BIND_HOST
            or type(address[1]) is not int
            or not 1 <= address[1] <= 65535
            or listener.family != socket.AF_INET
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            or descriptor < 0
            or inode <= 0
        ):
            raise LocalServicePolicyError()
        lease = _LocalServiceLease(
            checked,
            checked_recipe,
            listener,
            _BIND_HOST,
            address[1],
            inode,
            root.st_dev,
            root.st_ino,
        )
        _register_lease(lease)
        return lease
    except LocalServicePolicyError:
        if listener is not None:
            listener.close()
        raise
    except BaseException:
        if listener is not None:
            try:
                listener.close()
            except BaseException:
                pass
        raise LocalServicePolicyError() from None


def _validate_local_service_lease(value: object) -> _LocalServiceLease:
    registered = _LEASE_IDENTITIES.get(id(value))
    try:
        if (
            type(value) is not _LocalServiceLease
            or registered is None
            or registered[0]() is not value
            or registered[1]() is not value.policy
            or registered[2]() is not value.recipe
            or registered[3] != id(value.listener)
            or registered[4] != value.listener.fileno()
            or registered[5] != "open"
            or registered[6]
            != _canonical(
                {
                    "policy_hash": value.policy.content_hash,
                    "recipe_hash": value.recipe.content_hash,
                    "listener_identity": id(value.listener),
                    "listener_fd": value.listener.fileno(),
                    "host": value.host,
                    "port": value.port,
                    "listener_inode": value.listener_inode,
                    "root_device": value.root_device,
                    "root_inode": value.root_inode,
                }
            )
            or value.listener.fileno() < 0
            or value.listener.family != socket.AF_INET
            or value.listener.getsockname() != (value.host, value.port)
            or value.host != _BIND_HOST
            or not 1 <= value.port <= 65535
            or os.fstat(value.listener.fileno()).st_ino != value.listener_inode
            or os.stat("/").st_dev != value.root_device
            or os.stat("/").st_ino != value.root_inode
        ):
            raise LocalServicePolicyError()
        _validate_local_service_launch_policy(value.policy)
        _validate_local_service_launch_recipe(value.recipe, policy=value.policy)
    except LocalServicePolicyError:
        raise
    except BaseException:
        raise LocalServicePolicyError() from None
    return value


def _close_local_service_lease(value: object) -> bool:
    try:
        lease = _validate_local_service_lease(value)
    except LocalServicePolicyError:
        return False
    registered = _LEASE_IDENTITIES.get(id(lease))
    if registered is None:
        return False
    _LEASE_IDENTITIES[id(lease)] = (*registered[:5], "closing", registered[6])
    try:
        lease.listener.close()
    except BaseException:
        _LEASE_IDENTITIES[id(lease)] = (*registered[:5], "uncertain", registered[6])
        return False
    _LEASE_IDENTITIES[id(lease)] = (
        registered[0],
        registered[1],
        registered[2],
        registered[3],
        -1,
        "closed",
        registered[6],
    )
    return lease.listener.fileno() == -1


def _process_identity(pid: int) -> tuple[int, int]:
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
        tail = raw.rsplit(b")", 1)
        fields = tail[1].split()
        if len(tail) != 2 or len(fields) < 20 or fields[0] in {b"Z", b"X", b"x"}:
            raise ValueError
        return int(fields[1]), int(fields[19])
    except BaseException:
        raise LocalServicePolicyError() from None


def _proc_signal_mask(pid: int) -> str:
    try:
        values = [
            line.split(":", 1)[1].strip()
            for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines()
            if line.startswith("SigBlk:")
        ]
        if len(values) != 1 or _SIGNAL_MASK_RE.fullmatch(values[0]) is None:
            raise LocalServicePolicyError()
        return values[0]
    except LocalServicePolicyError:
        raise
    except BaseException:
        raise LocalServicePolicyError() from None


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _LocalServiceReadyAttestation:
    bootstrap_hash: str
    cwd_device: int
    cwd_inode: int
    fd_census_hash: str
    launch_policy_hash: str
    launch_recipe_hash: str
    listener_fd: int
    listener_host: str
    listener_inode: int
    listener_port: int
    network_filter_hash: str
    nonce: str
    root_device: int
    root_inode: int
    runtime_hash: str
    self_test_hash: str
    signal_mask: str
    service_pid: int
    service_ppid: int
    service_revision: int
    service_start_time: int
    mac: str


_ATTESTATION_IDENTITIES: dict[
    int,
    tuple[
        ReferenceType[object],
        ReferenceType[object],
        ReferenceType[object],
        ReferenceType[object],
        bytes,
        str,
    ],
] = {}
_ATTESTED_LEASE_IDENTITIES: dict[int, ReferenceType[object]] = {}


def _ready_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise LocalServicePolicyError()
        result[key] = value
    return result


def _attestation_snapshot(value: _LocalServiceReadyAttestation) -> bytes:
    return _canonical({field: getattr(value, field) for field in value.__dataclass_fields__})


def _register_attestation(
    value: _LocalServiceReadyAttestation,
    *,
    lease: _LocalServiceLease,
) -> None:
    identity = id(value)

    def retire(reference: ReferenceType[object]) -> None:
        registered = _ATTESTATION_IDENTITIES.get(identity)
        if registered is not None and registered[0] is reference:
            del _ATTESTATION_IDENTITIES[identity]

    snapshot = _attestation_snapshot(value)
    _ATTESTATION_IDENTITIES[identity] = (
        ref(value, retire),
        ref(lease),
        ref(lease.recipe),
        ref(lease.policy),
        snapshot,
        hashlib.sha256(snapshot).hexdigest(),
    )


def _consume_ready_lease(value: _LocalServiceLease) -> None:
    identity = id(value)
    registered = _ATTESTED_LEASE_IDENTITIES.get(identity)
    if registered is not None and registered() is not None:
        raise LocalServicePolicyError()

    def retire(reference: ReferenceType[object]) -> None:
        current = _ATTESTED_LEASE_IDENTITIES.get(identity)
        if current is reference:
            del _ATTESTED_LEASE_IDENTITIES[identity]

    _ATTESTED_LEASE_IDENTITIES[identity] = ref(value, retire)


def _parse_local_service_ready_frame(
    frame: object,
    *,
    lease: object,
    key: object,
    expected_nonce: object,
    expected_cwd_device: object,
    expected_cwd_inode: object,
    expected_signal_mask: object = None,
) -> _LocalServiceReadyAttestation:
    checked = _validate_local_service_lease(lease)
    if (
        type(frame) is not bytes
        or not 1 <= len(frame) <= _READY_FRAME_LIMIT
        or type(key) is not bytes
        or len(key) != 32
        or type(expected_nonce) is not str
        or _HEX_RE.fullmatch(expected_nonce) is None
        or type(expected_cwd_device) is not int
        or expected_cwd_device <= 0
        or type(expected_cwd_inode) is not int
        or expected_cwd_inode <= 0
        or expected_signal_mask is not None
        and (
            type(expected_signal_mask) is not str
            or _SIGNAL_MASK_RE.fullmatch(expected_signal_mask) is None
        )
    ):
        raise LocalServicePolicyError()
    try:
        document = json.loads(frame, object_pairs_hook=_ready_pairs)
    except LocalServicePolicyError:
        raise
    except Exception:
        raise LocalServicePolicyError() from None
    fields = {
        "bootstrap_hash",
        "cwd_device",
        "cwd_inode",
        "fd_census_hash",
        "format",
        "format_version",
        "launch_policy_hash",
        "launch_recipe_hash",
        "listener_fd",
        "listener_host",
        "listener_inode",
        "listener_port",
        "mac",
        "network_filter_hash",
        "nonce",
        "root_device",
        "root_inode",
        "runtime_hash",
        "self_test_hash",
        "signal_mask",
        "service_pid",
        "service_ppid",
        "service_revision",
        "service_start_time",
    }
    if type(document) is not dict or set(document) != fields or _canonical(document) != frame:
        raise LocalServicePolicyError()
    mac = document["mac"]
    unsigned = {name: value for name, value in document.items() if name != "mac"}
    if (
        type(mac) is not str
        or _HEX_RE.fullmatch(mac) is None
        or not hmac.compare_digest(
            mac,
            hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest(),
        )
        or document["format"] != _READY_FORMAT
        or type(document["format_version"]) is not int
        or document["format_version"] != _FORMAT_VERSION
        or document["nonce"] != expected_nonce
        or document["launch_policy_hash"] != checked.policy.content_hash
        or document["launch_recipe_hash"] != checked.recipe.content_hash
        or document["bootstrap_hash"] != checked.policy.bootstrap_hash
        or document["cwd_device"] != expected_cwd_device
        or document["cwd_inode"] != expected_cwd_inode
        or document["runtime_hash"] != checked.policy.runtime_hash
        or document["network_filter_hash"] != checked.policy.network_filter_hash
        or document["fd_census_hash"] != checked.recipe.fd_census_hash
        or document["self_test_hash"] != checked.recipe.self_test_hash
        or expected_signal_mask is not None
        and document["signal_mask"] != expected_signal_mask
        or type(document["signal_mask"]) is not str
        or _SIGNAL_MASK_RE.fullmatch(document["signal_mask"]) is None
        or document["service_revision"] != checked.policy.service_revision
        or document["listener_host"] != checked.host
        or document["listener_port"] != checked.port
        or document["listener_inode"] != checked.listener_inode
        or document["root_device"] != checked.root_device
        or document["root_inode"] != checked.root_inode
    ):
        raise LocalServicePolicyError()
    integer_fields = (
        "listener_fd",
        "listener_inode",
        "listener_port",
        "cwd_device",
        "cwd_inode",
        "root_device",
        "root_inode",
        "service_pid",
        "service_ppid",
        "service_revision",
        "service_start_time",
    )
    if any(type(document[name]) is not int or document[name] <= 0 for name in integer_fields):
        raise LocalServicePolicyError()
    _consume_ready_lease(checked)
    value = _LocalServiceReadyAttestation(
        **{field: document[field] for field in _LocalServiceReadyAttestation.__dataclass_fields__}
    )
    _register_attestation(value, lease=checked)
    return _validate_local_service_attestation(value, lease=checked)


def _validate_local_service_attestation(
    value: object,
    *,
    lease: object,
) -> _LocalServiceReadyAttestation:
    checked = _validate_local_service_lease(lease)
    registered = _ATTESTATION_IDENTITIES.get(id(value))
    try:
        if type(value) is not _LocalServiceReadyAttestation or registered is None:
            raise LocalServicePolicyError()
        snapshot = _attestation_snapshot(value)
        if (
            registered[0]() is not value
            or registered[1]() is not checked
            or registered[2]() is not checked.recipe
            or registered[3]() is not checked.policy
            or registered[4] != snapshot
            or registered[5] != hashlib.sha256(snapshot).hexdigest()
        ):
            raise LocalServicePolicyError()
        ppid, start_time = _process_identity(value.service_pid)
        if (
            value.launch_policy_hash != checked.policy.content_hash
            or value.launch_recipe_hash != checked.recipe.content_hash
            or value.bootstrap_hash != checked.recipe.bootstrap_hash
            or value.runtime_hash != checked.recipe.runtime_hash
            or value.network_filter_hash != checked.recipe.network_filter_hash
            or value.fd_census_hash != checked.recipe.fd_census_hash
            or value.self_test_hash != checked.recipe.self_test_hash
            or _SIGNAL_MASK_RE.fullmatch(value.signal_mask) is None
            or _proc_signal_mask(value.service_pid) != value.signal_mask
            or value.service_revision != checked.policy.service_revision
            or value.listener_inode != checked.listener_inode
            or value.listener_host != checked.host
            or value.listener_port != checked.port
            or value.root_device != checked.root_device
            or value.root_inode != checked.root_inode
            or ppid != value.service_ppid
            or start_time != value.service_start_time
            or os.readlink(f"/proc/{value.service_pid}/fd/{value.listener_fd}")
            != f"socket:[{value.listener_inode}]"
            or os.stat(f"/proc/{value.service_pid}/root").st_dev != value.root_device
            or os.stat(f"/proc/{value.service_pid}/root").st_ino != value.root_inode
            or os.stat(f"/proc/{value.service_pid}/cwd").st_dev != value.cwd_device
            or os.stat(f"/proc/{value.service_pid}/cwd").st_ino != value.cwd_inode
        ):
            raise LocalServicePolicyError()
    except LocalServicePolicyError:
        raise
    except BaseException:
        raise LocalServicePolicyError() from None
    return value


@dataclass(frozen=True, slots=True)
class _LocalServiceBrokerLaunch:
    listener: socket.socket
    recipe: _LocalServiceLaunchRecipe
    key: bytes
    nonce: str
    policy_hash: str
    bootstrap_hash: str
    runtime_hash: str
    network_filter_hash: str
    host: str
    port: int
    listener_inode: int
    root_device: int
    root_inode: int


def _broker_launch_from_lease(
    lease: object,
    *,
    key: object,
    nonce: object,
) -> _LocalServiceBrokerLaunch:
    checked = _validate_local_service_lease(lease)
    if (
        type(key) is not bytes
        or len(key) != 32
        or type(nonce) is not str
        or _HEX_RE.fullmatch(nonce) is None
    ):
        raise LocalServicePolicyError()
    return _LocalServiceBrokerLaunch(
        checked.listener,
        checked.recipe,
        key,
        nonce,
        checked.policy.content_hash,
        checked.policy.bootstrap_hash,
        checked.policy.runtime_hash,
        checked.policy.network_filter_hash,
        checked.host,
        checked.port,
        checked.listener_inode,
        checked.root_device,
        checked.root_inode,
    )


def _validate_broker_launch(
    value: object,
    _policy_fields: object = _LINUX_NATIVE_UNBOUND,
    _policy_snapshot: object = _LINUX_NATIVE_UNBOUND,
) -> _LocalServiceBrokerLaunch:
    authority = _load_linux_authority()
    if _policy_fields is _LINUX_NATIVE_UNBOUND:
        _policy_fields = authority.policy_fields
    if _policy_snapshot is _LINUX_NATIVE_UNBOUND:
        _policy_snapshot = authority.policy_snapshot
    if type(_policy_fields) is not tuple or type(_policy_snapshot) is not bytes:
        raise LocalServicePolicyError()
    policy = LocalServiceLaunchPolicy(**dict(_policy_fields))
    try:
        if (
            type(value) is not _LocalServiceBrokerLaunch
            or type(value.listener) is not socket.socket
            or type(value.recipe) is not _LocalServiceLaunchRecipe
            or type(value.key) is not bytes
            or len(value.key) != 32
            or type(value.nonce) is not str
            or _HEX_RE.fullmatch(value.nonce) is None
            or value.policy_hash != policy.content_hash
            or value.bootstrap_hash != policy.bootstrap_hash
            or value.runtime_hash != policy.runtime_hash
            or value.network_filter_hash != policy.network_filter_hash
            or value.host != _BIND_HOST
            or not 1 <= value.port <= 65535
            or value.listener.family != socket.AF_INET
            or value.listener.getsockname() != (value.host, value.port)
            or value.listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            or os.fstat(value.listener.fileno()).st_ino != value.listener_inode
            or os.stat("/").st_dev != value.root_device
            or os.stat("/").st_ino != value.root_inode
        ):
            raise LocalServicePolicyError()
        _validate_recipe_snapshot(
            value.recipe,
            policy=value.recipe.policy,
            require_live_executable=True,
        )
        if (
            _canonical(value.recipe.policy.as_document()) != _policy_snapshot
            or value.recipe.policy.content_hash != value.policy_hash
            or value.recipe.bootstrap_hash != value.bootstrap_hash
            or value.recipe.runtime_hash != value.runtime_hash
            or value.recipe.network_filter_hash != value.network_filter_hash
        ):
            raise LocalServicePolicyError()
    except LocalServicePolicyError:
        raise
    except BaseException:
        raise LocalServicePolicyError() from None
    return value


@dataclass(slots=True)
class _SpawnedLocalService:
    process: _LocalServiceProcess | subprocess.Popen[bytes]
    control_write_fd: int
    ready_read_fd: int
    config_frame: bytes
    service_pid: int
    service_ppid: int
    service_start_time: int
    signal_mask: str


def _write_all(fd: int, value: bytes) -> None:
    pending = memoryview(value)
    while pending:
        written = os.write(fd, pending)
        if written <= 0:
            raise LocalServicePolicyError()
        pending = pending[written:]


def _proc_fd_access_mode(pid: int, descriptor: int) -> int:
    try:
        for line in (
            Path(f"/proc/{pid}/fdinfo/{descriptor}").read_text(encoding="ascii").splitlines()
        ):
            if line.startswith("flags:\t"):
                return int(line.split("\t", 1)[1], 8) & os.O_ACCMODE
    except BaseException:
        pass
    raise LocalServicePolicyError()


def _proof_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise LocalServicePolicyError()
        result[key] = value
    return result


def _read_parent_death_proof(
    process: _LocalServiceProcess | subprocess.Popen[bytes],
    *,
    ready_read_fd: int,
    expected_pid: int,
    expected_ppid: int,
    expected_start_time: int,
    expected_signal_mask: str = "0000000000000000",
) -> bytes:
    frame = bytearray()
    deadline = time.monotonic() + 0.25
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise LocalServicePolicyError()
        try:
            chunk = os.read(
                ready_read_fd,
                max(1, _PARENT_DEATH_PROOF_LIMIT + 5 - len(frame)),
            )
        except BlockingIOError:
            chunk = None
        except InterruptedError:
            continue
        if chunk == b"":
            raise LocalServicePolicyError()
        if chunk:
            frame.extend(chunk)
        if len(frame) >= 4:
            size = int.from_bytes(frame[:4], "big")
            if not 1 <= size <= _PARENT_DEATH_PROOF_LIMIT:
                raise LocalServicePolicyError()
            if len(frame) > size + 4:
                raise LocalServicePolicyError()
            if len(frame) == size + 4:
                raw = bytes(frame[4:])
                try:
                    proof = json.loads(raw, object_pairs_hook=_proof_pairs)
                except Exception:
                    raise LocalServicePolicyError() from None
                if (
                    type(proof) is not dict
                    or _canonical(proof) != raw
                    or set(proof)
                    != {
                        "blocked_signal_mask",
                        "format",
                        "format_version",
                        "parent_death_signal",
                        "service_pid",
                        "service_ppid",
                        "service_start_time",
                    }
                    or proof["format"] != _PARENT_DEATH_PROOF_FORMAT
                    or proof["format_version"] != 1
                    or proof["blocked_signal_mask"] != expected_signal_mask
                    or _SIGNAL_MASK_RE.fullmatch(proof["blocked_signal_mask"]) is None
                    or proof["parent_death_signal"] != signal.SIGKILL
                    or proof["service_pid"] != expected_pid
                    or proof["service_ppid"] != expected_ppid
                    or proof["service_start_time"] != expected_start_time
                    or any(
                        type(proof[name]) is not int or proof[name] <= 0
                        for name in (
                            "parent_death_signal",
                            "service_pid",
                            "service_ppid",
                            "service_start_time",
                        )
                    )
                ):
                    raise LocalServicePolicyError()
                return raw
        time.sleep(0.001)
    raise LocalServicePolicyError()


def _attest_spawned_local_service_process(
    process: _LocalServiceProcess | subprocess.Popen[bytes],
    *,
    launch: _LocalServiceBrokerLaunch,
    command: tuple[str, ...],
    config_read_fd: int,
    config_write_fd: int,
    ready_read_fd: int,
    ready_write_fd: int,
    expected_cwd_device: int,
    expected_cwd_inode: int,
) -> tuple[int, int, int]:
    try:
        pid = process.pid
        if type(pid) is not int or pid <= 0:
            raise LocalServicePolicyError()
        assert process.stdout is not None
        assert process.stderr is not None
        expected_descriptors = {
            0,
            1,
            2,
            launch.listener.fileno(),
            config_read_fd,
            ready_write_fd,
        }
        expected_cmdline = (
            b"\0".join(item.encode(_CANONICAL_FS_ENCODING, "surrogateescape") for item in command)
            + b"\0"
        )
        expected_targets = {
            1: f"pipe:[{os.fstat(process.stdout.fileno()).st_ino}]",
            2: f"pipe:[{os.fstat(process.stderr.fileno()).st_ino}]",
            launch.listener.fileno(): f"socket:[{launch.listener_inode}]",
            config_read_fd: f"pipe:[{os.fstat(config_write_fd).st_ino}]",
            ready_write_fd: f"pipe:[{os.fstat(ready_read_fd).st_ino}]",
        }
        expected_modes = {
            0: os.O_RDWR,
            1: os.O_WRONLY,
            2: os.O_WRONLY,
            launch.listener.fileno(): os.O_RDWR,
            config_read_fd: os.O_RDONLY,
            ready_write_fd: os.O_WRONLY,
        }
        deadline = time.monotonic() + 0.25
        while True:
            if process.poll() is not None:
                raise LocalServicePolicyError()
            try:
                service_ppid, service_start_time = _process_identity(pid)
                with os.scandir(f"/proc/{pid}/fd") as entries:
                    descriptors = {
                        int(entry.name)
                        for entry in entries
                        if entry.name.isascii() and entry.name.isdigit()
                    }
                if descriptors != expected_descriptors:
                    raise LocalServicePolicyError()
                if os.readlink(f"/proc/{pid}/fd/0") != "/dev/null":
                    raise LocalServicePolicyError()
                for descriptor, target in expected_targets.items():
                    if os.readlink(f"/proc/{pid}/fd/{descriptor}") != target:
                        raise LocalServicePolicyError()
                for descriptor, mode in expected_modes.items():
                    if _proc_fd_access_mode(pid, descriptor) != mode:
                        raise LocalServicePolicyError()
                executable = os.stat(f"/proc/{pid}/exe")
                root = os.stat(f"/proc/{pid}/root")
                cwd = os.stat(f"/proc/{pid}/cwd")
                if (
                    service_ppid != os.getpid()
                    or Path(f"/proc/{pid}/cmdline").read_bytes() != expected_cmdline
                    or executable.st_dev != launch.recipe.executable_device
                    or executable.st_ino != launch.recipe.executable_inode
                    or executable.st_mode != launch.recipe.executable_mode
                    or executable.st_size != launch.recipe.executable_size
                    or _hash_file(f"/proc/{pid}/exe") != launch.recipe.executable_hash
                    or root.st_dev != launch.root_device
                    or root.st_ino != launch.root_inode
                    or cwd.st_dev != expected_cwd_device
                    or cwd.st_ino != expected_cwd_inode
                ):
                    raise LocalServicePolicyError()
                return pid, service_ppid, service_start_time
            except (LocalServicePolicyError, FileNotFoundError, ProcessLookupError):
                if time.monotonic() >= deadline:
                    raise LocalServicePolicyError() from None
                if process.poll() is not None:
                    raise LocalServicePolicyError() from None
                time.sleep(0.001)
    except LocalServicePolicyError:
        raise
    except BaseException:
        raise LocalServicePolicyError() from None


def _spawn_code_owned_local_service(
    value: object,
    *,
    scratch: object,
    _test_popen: object | None = None,
    _test_after_popen: object | None = None,
    _test_before_single_thread: object | None = None,
) -> _SpawnedLocalService:
    authority = _load_linux_authority()
    _validate_custody_authority()
    launch = _validate_broker_launch(value)
    if type(scratch) is not str or not os.path.isabs(scratch) or not Path(scratch).is_dir():
        raise LocalServicePolicyError()
    service_scratch = os.path.join(scratch, "local-service")
    config_read = config_write = ready_read = ready_write = -1
    process: _LocalServiceProcess | subprocess.Popen[bytes] | None = None
    try:
        os.mkdir(service_scratch, 0o700)
        service_scratch_metadata = os.stat(service_scratch, follow_symlinks=False)
        if not stat.S_ISDIR(service_scratch_metadata.st_mode):
            raise LocalServicePolicyError()
        config_read, config_write = os.pipe()
        ready_read, ready_write = os.pipe()
        config = {
            "bootstrap_hash": launch.bootstrap_hash,
            "cwd_device": service_scratch_metadata.st_dev,
            "cwd_inode": service_scratch_metadata.st_ino,
            "key_base64": base64.b64encode(launch.key).decode("ascii"),
            "launch_policy_hash": launch.policy_hash,
            "launch_recipe_hash": launch.recipe.content_hash,
            "listener_host": launch.host,
            "listener_inode": launch.listener_inode,
            "listener_port": launch.port,
            "network_filter_hash": launch.network_filter_hash,
            "nonce": launch.nonce,
            "root_device": launch.root_device,
            "root_inode": launch.root_inode,
            "runtime_hash": launch.runtime_hash,
            "service_revision": _SERVICE_REVISION,
        }
        launch = _validate_broker_launch(launch)
        command = tuple(launch.recipe.argv)
        environment = dict(launch.recipe.environment)
        listener_fd = launch.listener.fileno()
        config_read_fd = config_read
        ready_write_fd = ready_write
        custody_factory = _CANONICAL_CUSTODY_FACTORY
        custody_dependencies = (
            authority.prctl,
            _CANONICAL_GET_ERRNO,
            os.getppid,
            os._exit,
            authority.sigkill,
            authority.pthread_sigmask,
            authority.sig_setmask,
        )
        single_thread_check = _CANONICAL_SINGLE_THREAD_CHECKER
        signal_mask_authority = authority.pthread_sigmask
        popen_launcher = _CANONICAL_POPEN_LAUNCHER
        fork_exec = authority.fork_exec
        audit = _CANONICAL_SYS_AUDIT
        process_type = _CANONICAL_PROCESS_TYPE
        process_class_items = _CANONICAL_PROCESS_CLASS_ITEMS
        process_function_snapshots = _CANONICAL_PROCESS_FUNCTION_SNAPSHOTS
        policy_error = _CANONICAL_POLICY_ERROR
        prior_signal_mask = frozenset(
            signal_mask_authority(authority.sig_block, authority.catchable_signals)
        )
        expected_signal_mask = _linux_signal_mask_hex(prior_signal_mask)
        config["signal_mask"] = expected_signal_mask
        raw = _canonical(config)
        try:
            if _test_before_single_thread is not None:
                _test_before_single_thread()  # type: ignore[operator]
            broker_pid = _CANONICAL_CHECKER_DEFAULTS[0]()  # type: ignore[operator]
            single_thread_check(broker_pid)
            _validate_custody_authority()
            if _test_popen is None:
                config_write_fd = config_write
                config_write = -1
                process = popen_launcher(
                    fork_exec,
                    audit,
                    process_type,
                    process_class_items,
                    process_function_snapshots,
                    policy_error,
                    custody_factory,
                    _CANONICAL_FACTORY_SNAPSHOT,
                    custody_dependencies,
                    _CANONICAL_PRCTL,
                    _CANONICAL_CTYPES_C_INT,
                    _CANONICAL_CTYPES_C_ULONG,
                    signal_mask_authority,
                    broker_pid,
                    prior_signal_mask,
                    config_write_fd,
                    command,
                    service_scratch=service_scratch,
                    environment=environment,
                    pass_fds=(listener_fd, config_read_fd, ready_write_fd),
                    _pidfd_open=authority.pidfd_open,
                    _waitid=authority.waitid,
                    _pidfd_send_signal=authority.pidfd_send_signal,
                    _sigkill=authority.sigkill,
                    _pidfd_id=authority.pidfd_id,
                    _wexited=authority.wexited,
                )
                config_write = config_write_fd
            else:
                parent_death_preexec = custody_factory(broker_pid, prior_signal_mask)
                process = _test_popen(  # type: ignore[operator]
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=service_scratch,
                    env=environment,
                    shell=False,
                    close_fds=True,
                    pass_fds=(listener_fd, config_read_fd, ready_write_fd),
                    preexec_fn=parent_death_preexec,
                )
        finally:
            signal_mask_authority(authority.sig_setmask, prior_signal_mask)
        if _test_after_popen is not None:
            _test_after_popen(process.pid)  # type: ignore[operator]
        os.close(config_read)
        config_read = -1
        os.close(ready_write)
        ready_write = -1
        service_pid, service_ppid, service_start_time = _attest_spawned_local_service_process(
            process,
            launch=launch,
            command=command,
            config_read_fd=config_read_fd,
            config_write_fd=config_write,
            ready_read_fd=ready_read,
            ready_write_fd=ready_write_fd,
            expected_cwd_device=service_scratch_metadata.st_dev,
            expected_cwd_inode=service_scratch_metadata.st_ino,
        )
        os.set_blocking(ready_read, False)
        _read_parent_death_proof(
            process,
            ready_read_fd=ready_read,
            expected_pid=service_pid,
            expected_ppid=service_ppid,
            expected_start_time=service_start_time,
            expected_signal_mask=expected_signal_mask,
        )
        assert process.stdout is not None
        assert process.stderr is not None
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        return _SpawnedLocalService(
            process,
            config_write,
            ready_read,
            struct.pack(">I", len(raw)) + raw,
            service_pid,
            service_ppid,
            service_start_time,
            expected_signal_mask,
        )
    except BaseException:
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except BaseException:
                pass
            try:
                process.wait(timeout=0.5)
            except BaseException:
                pass
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException:
                        pass
            if type(process) is _LocalServiceProcess:
                process.close()
        for descriptor in (config_read, config_write, ready_read, ready_write):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except BaseException:
                    pass
        raise LocalServicePolicyError() from None


def _release_code_owned_local_service(value: object) -> None:
    if type(value) is not _SpawnedLocalService:
        raise LocalServicePolicyError()
    try:
        _write_all(value.control_write_fd, value.config_frame)
    except BaseException:
        raise LocalServicePolicyError() from None


__all__ = (
    "LocalServicePolicyError",
    "code_owned_local_service_launch_policy",
    "local_service_command",
)
