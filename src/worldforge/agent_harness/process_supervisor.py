"""OS-owned containment for one exact code-owned provider turn."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import multiprocessing
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .loopback_gateway import (
    LoopbackGatewayError,
    LoopbackGatewayIndeterminate,
    LoopbackGatewayPolicy,
    LoopbackGatewayStopped,
    execute_loopback_exchange,
)
from .loopback_protocol import (
    MAX_LOOPBACK_REQUEST_FRAME_BYTES,
    MAX_LOOPBACK_RESPONSE_FRAME_BYTES,
    LoopbackProtocolError,
    LoopbackProtocolSession,
    parse_loopback_context_frame,
    parse_loopback_response_frame,
)
from .ports import ProviderBoundaryControl
from .provider_egress import (
    ProviderEgressEnforcementProfile,
    ProviderEgressEnforcementUnavailable,
    _preflight_provider_egress_enforcement,
    _provider_worker_launcher_source,
    _validate_provider_egress_profile,
)
from .worker_protocol import (
    MAX_WORKER_RESPONSE_BYTES,
    MAX_WORKER_STDERR_BYTES,
    WorkerProtocolError,
    _strip_gateway_result_proof,
)
from .worker_registry import (
    _CodeOwnedRuntimeEntry,
    _CodeOwnedRuntimeKey,
    _validate_entry,
    runtime_entry,
)

_CONTROL_FORMAT = "world-forge.private.worker_broker_control"
_CONTROL_VERSION = 1
_CONTROL_LIMIT = 48 * 1024 * 1024
_CONTROL_POLL_SECONDS = 0.01
_BROKER_EXIT_SECONDS = 2.0
_DOMAIN_FIXED_POINT_LIMIT = 128
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_SEQUENCE_BY_KIND = {
    "cancel": 1,
    "domain_empty": 1,
    "ready": 0,
    "release": 0,
    "start": 0,
    "gateway_request": 1,
    "gateway_response": 2,
}
_ALLOWED_STOP_REASONS = frozenset(
    {
        "cancellation_check_failed",
        "execution_cancelled",
        "execution_deadline_exceeded",
        "duration_budget_exceeded",
        "provider_not_authorized",
        "tool_not_authorized",
    }
)


class ProviderBoundaryFailure(RuntimeError):
    def __init__(self) -> None:
        self.reason_code = "provider_failed"
        super().__init__(self.reason_code)


class ProviderBoundaryStopped(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        if reason_code not in _ALLOWED_STOP_REASONS:
            raise ValueError("invalid provider boundary stop")
        self.reason_code = reason_code
        super().__init__(reason_code)


class ProviderBoundaryIndeterminate(RuntimeError):
    def __init__(self) -> None:
        self.reason_code = "provider_boundary_indeterminate"
        super().__init__(self.reason_code)


class ProviderBoundaryUnsupported(RuntimeError):
    def __init__(self) -> None:
        self.reason_code = "worker_containment_unavailable"
        super().__init__(self.reason_code)


@dataclass(slots=True)
class _ProcessIdentity:
    pid: int
    start_time: int
    pidfd: int | None = None
    pidfd_close_attempted: bool = False
    pidfd_close_quarantined: bool = False


@dataclass(frozen=True, slots=True)
class _BrokerReport:
    status: str
    response: bytes | None


@dataclass(frozen=True, slots=True)
class _LoopbackTurnAuthority:
    policy: LoopbackGatewayPolicy
    worker_nonce: str
    original_request_hash: str
    context_frame: bytes

    @property
    def correlation(self) -> dict[str, object]:
        return {
            "nonce": self.worker_nonce,
            "original_request_hash": self.original_request_hash,
            "gateway_policy_hash": self.policy.content_hash,
        }


class _DuplicateControlKey(ValueError):
    pass


def _control_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateControlKey(key)
        result[key] = value
    return result


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _control_document(
    *,
    kind: str,
    sequence: int,
    nonce: str,
    payload: dict[str, object],
    key: bytes,
) -> dict[str, object]:
    if (
        type(kind) is not str
        or kind not in _CONTROL_SEQUENCE_BY_KIND
        or type(sequence) is not int
        or sequence != _CONTROL_SEQUENCE_BY_KIND[kind]
        or type(nonce) is not str
        or _HEX_RE.fullmatch(nonce) is None
        or type(payload) is not dict
        or type(key) is not bytes
        or len(key) != 32
    ):
        raise ProviderBoundaryIndeterminate()
    _validate_control_payload(kind, payload)
    document: dict[str, object] = {
        "format": _CONTROL_FORMAT,
        "format_version": _CONTROL_VERSION,
        "kind": kind,
        "nonce": nonce,
        "payload": payload,
        "sequence": sequence,
    }
    document["mac"] = hmac.new(key, _canonical(document), hashlib.sha256).hexdigest()
    return document


def _validate_control_payload(kind: str, payload: dict[str, object]) -> None:
    if kind in {"cancel", "start"}:
        valid = not payload
    elif kind == "release":
        valid = set(payload) == {"release"} and type(payload["release"]) is bool
    elif kind in {"gateway_request", "gateway_response"}:
        encoded = payload.get("frame_base64")
        runtime = payload.get("runtime")
        maximum = (
            MAX_LOOPBACK_REQUEST_FRAME_BYTES + 4
            if kind == "gateway_request"
            else MAX_LOOPBACK_RESPONSE_FRAME_BYTES + 4
        )
        valid = (
            set(payload)
            == {
                "frame_base64",
                "frame_hash",
                "gateway_policy_hash",
                "original_request_hash",
                "runtime",
                "worker_nonce",
            }
            and type(encoded) is str
            and type(payload.get("frame_hash")) is str
            and _HEX_RE.fullmatch(payload["frame_hash"]) is not None
            and type(payload.get("gateway_policy_hash")) is str
            and _HEX_RE.fullmatch(payload["gateway_policy_hash"]) is not None
            and type(payload.get("original_request_hash")) is str
            and _HEX_RE.fullmatch(payload["original_request_hash"]) is not None
            and type(payload.get("worker_nonce")) is str
            and _HEX_RE.fullmatch(payload["worker_nonce"]) is not None
            and type(runtime) is dict
            and set(runtime) == {"id", "revision", "content_hash"}
            and type(runtime.get("id")) is str
            and type(runtime.get("revision")) is int
            and type(runtime.get("content_hash")) is str
            and _HEX_RE.fullmatch(runtime["content_hash"]) is not None
        )
        if valid:
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except Exception:
                valid = False
            else:
                valid = (
                    len(decoded) <= maximum
                    and hashlib.sha256(decoded).hexdigest() == payload["frame_hash"]
                )
    elif kind == "ready":
        valid = (
            set(payload) == {"worker_pid", "worker_start_time"}
            and type(payload["worker_pid"]) is int
            and payload["worker_pid"] > 0
            and type(payload["worker_start_time"]) is int
            and payload["worker_start_time"] > 0
        )
    elif kind == "domain_empty":
        status = payload.get("status")
        if type(status) is not str or status not in {
            "cancelled",
            "containment_lost",
            "provider_failed",
            "response",
        }:
            valid = False
        elif status == "response":
            encoded = payload.get("response_base64")
            valid = set(payload) == {"response_base64", "status"} and type(encoded) is str
            if valid:
                try:
                    decoded = base64.b64decode(encoded, validate=True)
                except Exception:
                    valid = False
                else:
                    valid = len(decoded) <= MAX_WORKER_RESPONSE_BYTES + 4
        else:
            valid = set(payload) == {"status"}
    else:
        valid = False
    if not valid:
        raise ProviderBoundaryIndeterminate()


def _encode_control(**values: object) -> bytes:
    document = _control_document(**values)  # type: ignore[arg-type]
    payload = _canonical(document)
    if len(payload) > _CONTROL_LIMIT:
        raise ProviderBoundaryIndeterminate()
    return struct.pack(">I", len(payload)) + payload


def _decode_control(
    frame: bytes,
    *,
    key: bytes,
    nonce: str,
    kind: str,
    sequence: int,
) -> dict[str, object]:
    try:
        document = json.loads(
            frame.decode("utf-8"),
            object_pairs_hook=_control_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        if type(document) is not dict or _canonical(document) != frame:
            raise ValueError
        if set(document) != {
            "format",
            "format_version",
            "kind",
            "mac",
            "nonce",
            "payload",
            "sequence",
        }:
            raise ValueError
        supplied = document["mac"]
        if type(supplied) is not str or _HEX_RE.fullmatch(supplied) is None:
            raise ValueError
        if (
            type(document["format"]) is not str
            or document["format"] != _CONTROL_FORMAT
            or type(document["format_version"]) is not int
            or document["format_version"] != _CONTROL_VERSION
            or type(document["kind"]) is not str
            or document["kind"] != kind
            or type(document["nonce"]) is not str
            or _HEX_RE.fullmatch(document["nonce"]) is None
            or document["nonce"] != nonce
            or type(document["sequence"]) is not int
            or document["sequence"] != sequence
            or type(document["payload"]) is not dict
        ):
            raise ValueError
        expected = _control_document(
            kind=document["kind"],
            sequence=document["sequence"],
            nonce=document["nonce"],
            payload=document["payload"],
            key=key,
        )["mac"]
        if not hmac.compare_digest(supplied, expected):
            raise ValueError
        return document["payload"]
    except Exception:
        raise ProviderBoundaryIndeterminate() from None


class _ControlReader:
    def __init__(self, stream: socket.socket) -> None:
        self.stream = stream
        self.buffer = bytearray()
        self.closed = False

    def poll(self) -> bytes | None:
        while True:
            try:
                chunk = self.stream.recv(64 * 1024)
            except BlockingIOError:
                break
            except InterruptedError:
                continue
            except OSError:
                raise ProviderBoundaryIndeterminate() from None
            if not chunk:
                self.closed = True
                break
            self.buffer.extend(chunk)
            if len(self.buffer) > _CONTROL_LIMIT + 4:
                raise ProviderBoundaryIndeterminate()
        if len(self.buffer) < 4:
            return None
        size = struct.unpack(">I", self.buffer[:4])[0]
        if size > _CONTROL_LIMIT:
            raise ProviderBoundaryIndeterminate()
        if len(self.buffer) < size + 4:
            return None
        frame = bytes(self.buffer[4 : 4 + size])
        del self.buffer[: size + 4]
        return frame

    def require_clean_eof(self, *, timeout_seconds: float) -> None:
        deadline = time.monotonic() + timeout_seconds
        while True:
            if self.poll() is not None:
                raise ProviderBoundaryIndeterminate()
            if self.closed:
                if self.buffer:
                    raise ProviderBoundaryIndeterminate()
                return
            if time.monotonic() >= deadline:
                raise ProviderBoundaryIndeterminate()
            time.sleep(0.001)


def _send_all(stream: socket.socket, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        try:
            sent = stream.send(view)
        except InterruptedError:
            continue
        except OSError:
            raise ProviderBoundaryIndeterminate() from None
        if sent <= 0:
            raise ProviderBoundaryIndeterminate()
        view = view[sent:]


def _recv_exact(stream: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        try:
            chunk = stream.recv(remaining)
        except InterruptedError:
            continue
        except OSError:
            raise ProviderBoundaryIndeterminate() from None
        if not chunk:
            raise ProviderBoundaryIndeterminate()
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_control_frame(stream: socket.socket) -> bytes:
    size = struct.unpack(">I", _recv_exact(stream, 4))[0]
    if size > _CONTROL_LIMIT:
        raise ProviderBoundaryIndeterminate()
    return _recv_exact(stream, size)


def _gateway_control_payload(
    frame: bytes,
    *,
    runtime: dict[str, object],
    authority: _LoopbackTurnAuthority,
) -> dict[str, object]:
    return {
        "frame_base64": base64.b64encode(frame).decode("ascii"),
        "frame_hash": hashlib.sha256(frame).hexdigest(),
        "gateway_policy_hash": authority.policy.content_hash,
        "original_request_hash": authority.original_request_hash,
        "runtime": dict(runtime),
        "worker_nonce": authority.worker_nonce,
    }


def _validate_gateway_control_payload(
    payload: object,
    *,
    runtime: dict[str, object],
    authority: _LoopbackTurnAuthority,
    kind: str,
) -> bytes:
    if type(payload) is not dict:
        raise ProviderBoundaryIndeterminate()
    _validate_control_payload(kind, payload)
    if (
        payload["runtime"] != runtime
        or payload["gateway_policy_hash"] != authority.policy.content_hash
        or payload["original_request_hash"] != authority.original_request_hash
        or payload["worker_nonce"] != authority.worker_nonce
    ):
        raise ProviderBoundaryIndeterminate()
    try:
        frame = base64.b64decode(payload["frame_base64"], validate=True)
    except Exception:
        raise ProviderBoundaryIndeterminate() from None
    if hashlib.sha256(frame).hexdigest() != payload["frame_hash"]:
        raise ProviderBoundaryIndeterminate()
    return frame


def _validate_loopback_turn_authority(
    value: object,
    *,
    worker_key: bytes,
    runtime_launch: _CodeOwnedRuntimeLaunch,
) -> _LoopbackTurnAuthority:
    if type(value) is not _LoopbackTurnAuthority:
        raise ProviderBoundaryFailure()
    try:
        policy = LoopbackGatewayPolicy.create(value.policy.endpoint_origin)
        if policy != value.policy or policy.canonical_document != value.policy.canonical_document:
            raise ValueError
        if (
            runtime_launch.authority.key is not _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE
            or runtime_launch.authority.spec.network_scope != "loopback"
            or runtime_launch.authority.spec.endpoint_origin != policy.endpoint_origin
            or runtime_launch.authority.spec.endpoint_policy_hash != policy.content_hash
            or type(value.worker_nonce) is not str
            or _HEX_RE.fullmatch(value.worker_nonce) is None
            or type(value.original_request_hash) is not str
            or _HEX_RE.fullmatch(value.original_request_hash) is None
            or type(value.context_frame) is not bytes
        ):
            raise ValueError
        parse_loopback_context_frame(
            value.context_frame,
            key=worker_key,
            nonce=value.worker_nonce,
            runtime=runtime_launch.authority.runtime_binding,
            original_request_hash=value.original_request_hash,
            gateway_policy_hash=policy.content_hash,
        )
    except Exception:
        raise ProviderBoundaryFailure() from None
    return _LoopbackTurnAuthority(
        policy,
        value.worker_nonce,
        value.original_request_hash,
        bytes(value.context_frame),
    )


def _minimal_environment(
    runtime_key: _CodeOwnedRuntimeKey = _CodeOwnedRuntimeKey.CONFORMANCE,
    *,
    runtime_authority: _CodeOwnedRuntimeEntry | None = None,
) -> dict[str, str]:
    authority = _resolve_runtime_authority(runtime_key, runtime_authority)
    try:
        return dict(tuple.__iter__(authority.environment_profile))
    except Exception:
        raise ProviderBoundaryFailure() from None


def fixed_worker_command(
    runtime_key: _CodeOwnedRuntimeKey = _CodeOwnedRuntimeKey.CONFORMANCE,
    *,
    runtime_authority: _CodeOwnedRuntimeEntry | None = None,
) -> tuple[str, ...]:
    authority = _resolve_runtime_authority(runtime_key, runtime_authority)
    executable = os.path.abspath(sys.executable)
    if not os.path.isabs(executable) or not os.path.isfile(executable):
        raise ProviderBoundaryUnsupported()
    try:
        bootstrap = _provider_worker_launcher_source(authority.artifact.bootstrap_source)
    except Exception:
        raise ProviderBoundaryFailure() from None
    return (executable, "-I", "-B", "-S", "-u", "-X", "utf8", "-c", bootstrap)


def _resolve_runtime_authority(
    runtime_key: object,
    runtime_authority: _CodeOwnedRuntimeEntry | None,
) -> _CodeOwnedRuntimeEntry:
    if type(runtime_key) is not _CodeOwnedRuntimeKey:
        raise ProviderBoundaryFailure()
    if runtime_authority is not None:
        if (
            type(runtime_authority) is not _CodeOwnedRuntimeEntry
            or runtime_authority.key is not runtime_key
        ):
            raise ProviderBoundaryFailure()
        return runtime_authority
    try:
        return runtime_entry(runtime_key)
    except RuntimeError:
        raise ProviderBoundaryFailure() from None


@dataclass(frozen=True, slots=True)
class _CodeOwnedRuntimeLaunch:
    authority: _CodeOwnedRuntimeEntry
    command: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    egress_enforcement: ProviderEgressEnforcementProfile


def _capture_runtime_launch(
    authority: _CodeOwnedRuntimeEntry,
) -> _CodeOwnedRuntimeLaunch:
    if type(authority) is not _CodeOwnedRuntimeEntry:
        raise ProviderBoundaryFailure()
    try:
        authority = _validate_entry(authority)
        egress_enforcement = _validate_provider_egress_profile(authority.egress_enforcement)
        if authority.spec.egress_enforcement_hash != egress_enforcement.content_hash:
            raise RuntimeError
        command = fixed_worker_command(authority.key, runtime_authority=authority)
        environment = tuple(authority.environment_profile)
    except ProviderEgressEnforcementUnavailable:
        raise ProviderBoundaryUnsupported() from None
    except Exception:
        raise ProviderBoundaryFailure() from None
    if (
        type(command) is not tuple
        or len(command) != 9
        or any(type(part) is not str for part in command)
        or type(environment) is not tuple
        or any(
            type(item) is not tuple or len(item) != 2 or any(type(part) is not str for part in item)
            for item in environment
        )
    ):
        raise ProviderBoundaryFailure()
    try:
        _preflight_provider_egress_enforcement(egress_enforcement)
    except ProviderEgressEnforcementUnavailable:
        raise ProviderBoundaryUnsupported() from None
    return _validate_runtime_launch(
        _CodeOwnedRuntimeLaunch(authority, command, environment, egress_enforcement)
    )


def _validate_runtime_launch(value: object) -> _CodeOwnedRuntimeLaunch:
    try:
        if type(value) is not _CodeOwnedRuntimeLaunch:
            raise RuntimeError
        authority = _validate_entry(value.authority)
        egress_enforcement = _validate_provider_egress_profile(value.egress_enforcement)
        launcher_source = _provider_worker_launcher_source(authority.artifact.bootstrap_source)
        expected_command = (
            os.path.abspath(sys.executable),
            "-I",
            "-B",
            "-S",
            "-u",
            "-X",
            "utf8",
            "-c",
            launcher_source,
        )
        expected_environment = tuple(authority.environment_profile)
        if (
            type(value.command) is not tuple
            or any(type(part) is not str for part in tuple.__iter__(value.command))
            or value.command != expected_command
            or type(value.environment) is not tuple
            or any(
                type(item) is not tuple
                or len(item) != 2
                or any(type(part) is not str for part in tuple.__iter__(item))
                for item in tuple.__iter__(value.environment)
            )
            or value.environment != expected_environment
            or egress_enforcement != authority.egress_enforcement
            or authority.spec.egress_enforcement_hash != egress_enforcement.content_hash
        ):
            raise RuntimeError
    except Exception:
        raise ProviderBoundaryFailure() from None
    return _CodeOwnedRuntimeLaunch(
        authority=authority,
        command=expected_command,
        environment=expected_environment,
        egress_enforcement=egress_enforcement,
    )


def _spawn_code_owned_worker(
    runtime_launch: _CodeOwnedRuntimeLaunch,
    scratch: str,
) -> subprocess.Popen[bytes]:
    try:
        runtime_launch = _validate_runtime_launch(runtime_launch)
        return subprocess.Popen(
            runtime_launch.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=scratch,
            env=dict(runtime_launch.environment),
            shell=False,
            close_fds=True,
            pass_fds=(),
        )
    except Exception:
        raise ProviderBoundaryFailure() from None


def _proc_identity(pid: int) -> tuple[int, int, str] | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (FileNotFoundError, ProcessLookupError):
        return None
    except (OSError, UnicodeError, ValueError):
        raise ProviderBoundaryIndeterminate() from None
    end = raw.rfind(")")
    if end < 0:
        raise ProviderBoundaryIndeterminate()
    fields = raw[end + 2 :].split()
    if len(fields) < 20:
        raise ProviderBoundaryIndeterminate()
    try:
        state = fields[0]
        if len(state) != 1:
            raise ValueError
        return int(fields[1]), int(fields[19]), state
    except ValueError:
        raise ProviderBoundaryIndeterminate() from None


def _process_table() -> dict[int, tuple[int, int, str]]:
    result: dict[int, tuple[int, int, str]] = {}
    try:
        entries = os.scandir("/proc")
    except OSError:
        raise ProviderBoundaryIndeterminate() from None
    with entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            identity = _proc_identity(pid)
            if identity is not None:
                result[pid] = identity
    return result


def _entry_is_live(entry: tuple[int, int, str]) -> bool:
    return entry[2] not in {"X", "Z", "x"}


def _descendants(root_pid: int, table: dict[int, tuple[int, int, str]]) -> set[int]:
    lineage: set[int] = set()
    changed = True
    while changed:
        changed = False
        for pid, (parent, _start, _state) in table.items():
            if pid == root_pid or pid in lineage:
                continue
            if parent == root_pid or parent in lineage:
                lineage.add(pid)
                changed = True
    return {pid for pid in lineage if _entry_is_live(table[pid])}


def _close_linux_identity(identity: _ProcessIdentity) -> bool:
    descriptor = identity.pidfd
    if descriptor is None:
        return not identity.pidfd_close_quarantined
    if identity.pidfd_close_attempted:
        return False
    identity.pidfd_close_attempted = True
    try:
        os.close(descriptor)
    except BaseException:
        # Linux releases the descriptor number before reporting a close error;
        # never retry because that could close an unrelated reused descriptor.
        identity.pidfd = None
        identity.pidfd_close_quarantined = True
        return False
    identity.pidfd = None
    return True


def _retain_linux_identity(pid: int, start_time: int | None) -> _ProcessIdentity | None:
    if (
        type(pid) is not int
        or pid <= 0
        or (start_time is not None and (type(start_time) is not int or start_time <= 0))
        or not callable(getattr(os, "pidfd_open", None))
        or not callable(getattr(signal, "pidfd_send_signal", None))
    ):
        raise ProviderBoundaryIndeterminate()
    try:
        descriptor = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        current = _proc_identity(pid)
        if start_time is not None and current is not None and current[1] != start_time:
            raise ProviderBoundaryIndeterminate() from None
        return None
    except OSError:
        raise ProviderBoundaryIndeterminate() from None
    identity = _ProcessIdentity(pid, start_time or 1, descriptor)
    try:
        current = _proc_identity(pid)
        if current is None or not _entry_is_live(current):
            if not _close_linux_identity(identity):
                raise ProviderBoundaryIndeterminate()
            return None
        if start_time is not None and current[1] != start_time:
            raise ProviderBoundaryIndeterminate()
        identity.start_time = current[1]
        return identity
    except BaseException:
        if identity.pidfd is not None:
            _close_linux_identity(identity)
        raise


def _signal_identity(identity: _ProcessIdentity, signum: int) -> bool:
    retained = identity
    owned = False
    original: BaseException | None = None
    if identity.pidfd is None:
        retained = _retain_linux_identity(identity.pid, identity.start_time)
        if retained is None:
            return False
        owned = True
    try:
        current = _proc_identity(identity.pid)
        if current is None:
            return False
        if current[1] != identity.start_time:
            raise ProviderBoundaryIndeterminate()
        if not _entry_is_live(current):
            return False
        try:
            assert retained.pidfd is not None
            signal.pidfd_send_signal(retained.pidfd, signum, None, 0)
        except ProcessLookupError:
            after = _proc_identity(identity.pid)
            if after is not None and after[1] != identity.start_time:
                raise ProviderBoundaryIndeterminate() from None
            return False
        except OSError:
            raise ProviderBoundaryIndeterminate() from None
        after = _proc_identity(identity.pid)
        if after is not None and after[1] != identity.start_time:
            raise ProviderBoundaryIndeterminate()
        return True
    except BaseException as exc:
        original = exc
        raise
    finally:
        if owned and not _close_linux_identity(retained):
            if original is None or isinstance(original, Exception):
                raise ProviderBoundaryIndeterminate() from None
            try:
                original.add_note("provider pidfd cleanup was indeterminate")
            except BaseException:
                pass


def _reap_children() -> None:
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        except InterruptedError:
            continue
        if pid == 0:
            return


def _observe_linux_identities_stopped(identities: tuple[_ProcessIdentity, ...]) -> bool:
    """Confirm SIGSTOP delivery instead of treating signal submission as a fence."""

    for _round in range(_DOMAIN_FIXED_POINT_LIMIT):
        table = _process_table()
        all_stopped = True
        for identity in identities:
            current = table.get(identity.pid)
            if current is None or not _entry_is_live(current):
                continue
            if current[1] != identity.start_time:
                return False
            if current[2] not in {"T", "t"}:
                all_stopped = False
        if all_stopped:
            return True
        time.sleep(0.002)
    return False


def _attempt_linux_domain_cleanup(
    *,
    broker: multiprocessing.Process,
    broker_identity: _ProcessIdentity,
    tracked: dict[int, int],
) -> bool:
    """Make emergency cleanup total so it cannot replace a latched outcome."""

    try:
        return _cleanup_linux_broker_domain(
            broker=broker,
            broker_identity=broker_identity,
            tracked=tracked,
        )
    except BaseException:
        return False


def _prove_linux_domain_empty(
    *,
    broker_pid: int,
    tracked: dict[int, int],
) -> bool:
    stable_empty = 0
    for _round in range(_DOMAIN_FIXED_POINT_LIMIT):
        _reap_children()
        table = _process_table()
        domain = _descendants(broker_pid, table)
        for pid, start in tuple(tracked.items()):
            current = table.get(pid)
            if current is None or not _entry_is_live(current):
                continue
            if current[1] != start:
                return False
            domain.add(pid)
            domain.update(_descendants(pid, table))
        for pid in domain:
            start = table[pid][1]
            previous = tracked.setdefault(pid, start)
            if previous != start:
                return False
        for pid, start in tuple(tracked.items()):
            current = table.get(pid)
            if current is not None and current[1] != start:
                return False
        if not domain:
            stable_empty += 1
            if stable_empty >= 2:
                return True
            time.sleep(0.002)
            continue
        stable_empty = 0
        identities = [_ProcessIdentity(pid, tracked[pid]) for pid in sorted(domain, reverse=True)]
        try:
            if not all(_signal_identity(identity, signal.SIGSTOP) for identity in identities):
                continue
            if not _observe_linux_identities_stopped(tuple(identities)):
                return False
            frozen_table = _process_table()
            frozen_domain = _descendants(broker_pid, frozen_table)
            for pid in frozen_domain:
                start = frozen_table[pid][1]
                previous = tracked.setdefault(pid, start)
                if previous != start:
                    return False
            if frozen_domain != domain:
                continue
            if any(frozen_table[pid][2] not in {"T", "t"} for pid in frozen_domain):
                continue
            for identity in identities:
                _signal_identity(identity, signal.SIGKILL)
        except ProviderBoundaryIndeterminate:
            return False
        time.sleep(0.002)
    return False


def _known_linux_domain(
    *,
    broker_identity: _ProcessIdentity,
    tracked: dict[int, int],
    table: dict[int, tuple[int, int, str]],
) -> tuple[set[int], bool, bool]:
    """Find only descendants still attributable to the broker or known worker roots."""

    exact = True
    broker_current = table.get(broker_identity.pid)
    broker_alive = broker_current is not None and _entry_is_live(broker_current)
    if broker_alive and broker_current[1] != broker_identity.start_time:
        broker_alive = False
        exact = False
    domain = _descendants(broker_identity.pid, table) if broker_alive else set()
    for pid, start_time in tuple(tracked.items()):
        current = table.get(pid)
        if current is None:
            continue
        if current[1] != start_time:
            exact = False
            continue
        if not _entry_is_live(current):
            continue
        domain.add(pid)
        domain.update(_descendants(pid, table))
    for pid in domain:
        start_time = table[pid][1]
        previous = tracked.setdefault(pid, start_time)
        if previous != start_time:
            exact = False
    return domain, exact, broker_alive


def _cleanup_linux_broker_domain(
    *,
    broker: multiprocessing.Process,
    broker_identity: _ProcessIdentity,
    tracked: dict[int, int],
) -> bool:
    """Freeze and kill a broker tree, proving empty only when the live root was fenced."""

    proof_possible = True
    try:
        broker_frozen = _signal_identity(broker_identity, signal.SIGSTOP)
    except ProviderBoundaryIndeterminate:
        broker_frozen = False
        proof_possible = False
    if not broker_frozen:
        proof_possible = False
    elif not _observe_linux_identities_stopped((broker_identity,)):
        proof_possible = False

    stable_domain: set[int] | None = None
    stable_rounds = 0
    for _round in range(_DOMAIN_FIXED_POINT_LIMIT):
        try:
            table = _process_table()
            domain, exact, broker_alive = _known_linux_domain(
                broker_identity=broker_identity,
                tracked=tracked,
                table=table,
            )
        except ProviderBoundaryIndeterminate:
            proof_possible = False
            break
        proof_possible = proof_possible and exact and broker_alive
        identities = [_ProcessIdentity(pid, tracked[pid]) for pid in sorted(domain)]
        try:
            for identity in identities:
                _signal_identity(identity, signal.SIGSTOP)
        except ProviderBoundaryIndeterminate:
            proof_possible = False
            break
        try:
            descendants_stopped = _observe_linux_identities_stopped(tuple(identities))
        except ProviderBoundaryIndeterminate:
            descendants_stopped = False
        if not descendants_stopped:
            proof_possible = False
            break
        try:
            frozen_table = _process_table()
            frozen_domain, exact, broker_alive = _known_linux_domain(
                broker_identity=broker_identity,
                tracked=tracked,
                table=frozen_table,
            )
        except ProviderBoundaryIndeterminate:
            proof_possible = False
            break
        proof_possible = proof_possible and exact and broker_alive
        broker_entry = frozen_table.get(broker_identity.pid)
        broker_stopped = (
            broker_entry is not None
            and broker_entry[1] == broker_identity.start_time
            and broker_entry[2] in {"T", "t"}
        )
        descendants_stopped = all(frozen_table[pid][2] in {"T", "t"} for pid in frozen_domain)
        proof_possible = proof_possible and broker_stopped and descendants_stopped
        if frozen_domain == domain and stable_domain == frozen_domain:
            stable_rounds += 1
        else:
            stable_domain = frozen_domain
            stable_rounds = 1
        if stable_rounds >= 2:
            break
        time.sleep(0.002)
    else:
        proof_possible = False

    if stable_rounds < 2:
        proof_possible = False
    identities = [
        _ProcessIdentity(pid, tracked[pid]) for pid in sorted(stable_domain or set(), reverse=True)
    ]
    for identity in identities:
        try:
            _signal_identity(identity, signal.SIGKILL)
        except ProviderBoundaryIndeterminate:
            proof_possible = False
    try:
        if not _signal_identity(broker_identity, signal.SIGKILL):
            proof_possible = False
    except ProviderBoundaryIndeterminate:
        proof_possible = False
    try:
        broker.join(_BROKER_EXIT_SECONDS)
    except BaseException:
        proof_possible = False
    try:
        if broker.is_alive():
            proof_possible = False
            try:
                _signal_identity(broker_identity, signal.SIGKILL)
            except ProviderBoundaryIndeterminate:
                pass
            broker.join(0.5)
    except BaseException:
        proof_possible = False

    absent_rounds = 0
    deadline = time.monotonic() + _BROKER_EXIT_SECONDS
    while time.monotonic() < deadline:
        try:
            table = _process_table()
        except ProviderBoundaryIndeterminate:
            proof_possible = False
            time.sleep(0.005)
            continue
        known = [
            broker_identity,
            *(_ProcessIdentity(pid, start) for pid, start in tracked.items()),
        ]
        all_absent = True
        for identity in known:
            current = table.get(identity.pid)
            if current is None:
                continue
            if current[1] != identity.start_time:
                proof_possible = False
                continue
            if not _entry_is_live(current):
                continue
            all_absent = False
            for descendant in _descendants(identity.pid, table):
                start_time = table[descendant][1]
                previous = tracked.setdefault(descendant, start_time)
                if previous != start_time:
                    proof_possible = False
            try:
                _signal_identity(identity, signal.SIGKILL)
            except ProviderBoundaryIndeterminate:
                proof_possible = False
        if all_absent:
            absent_rounds += 1
            if absent_rounds >= 2:
                return proof_possible
        else:
            absent_rounds = 0
        time.sleep(0.005)
    return False


def _set_linux_subreaper() -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), "prctl")
    except (AttributeError, OSError):
        raise ProviderBoundaryIndeterminate() from None


def _read_pipe_nonblocking(stream: object, maximum: int, buffer: bytearray) -> bool:
    descriptor = stream.fileno()  # type: ignore[attr-defined]
    while True:
        try:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(buffer)))
        except BlockingIOError:
            return False
        except InterruptedError:
            continue
        if not chunk:
            return True
        buffer.extend(chunk)
        if len(buffer) > maximum:
            return False


def _linux_broker_main(
    control_fd: int,
    *,
    runtime_launch: _CodeOwnedRuntimeLaunch,
    broker_key: bytes,
    broker_nonce: str,
    worker_key: bytes,
    request_frame: bytes,
    scratch: str,
    loopback_turn: _LoopbackTurnAuthority | None = None,
) -> int:
    if type(runtime_launch) is not _CodeOwnedRuntimeLaunch:
        raise ProviderBoundaryIndeterminate()
    control = socket.socket(fileno=control_fd)
    control.setblocking(False)
    reader = _ControlReader(control)
    broker_pid = os.getpid()
    process: subprocess.Popen[bytes] | None = None
    worker_identity: _ProcessIdentity | None = None
    tracked: dict[int, int] = {}
    status = "containment_lost"
    response: bytes | None = None
    try:
        _set_linux_subreaper()
        if not os.path.isabs(scratch) or not os.path.isdir(scratch):
            raise ProviderBoundaryIndeterminate()
        process = _spawn_code_owned_worker(runtime_launch, scratch)
        worker_identity = _retain_linux_identity(process.pid, None)
        if worker_identity is None:
            raise ProviderBoundaryIndeterminate()
        tracked[process.pid] = worker_identity.start_time
        _send_all(
            control,
            _encode_control(
                kind="ready",
                sequence=0,
                nonce=broker_nonce,
                payload={
                    "worker_pid": process.pid,
                    "worker_start_time": worker_identity.start_time,
                },
                key=broker_key,
            ),
        )

        gate_decided = False
        run_worker = False
        while not gate_decided:
            frame = reader.poll()
            if frame is not None:
                try:
                    payload = _decode_control(
                        frame,
                        key=broker_key,
                        nonce=broker_nonce,
                        kind="release",
                        sequence=0,
                    )
                except ProviderBoundaryIndeterminate:
                    status = "containment_lost"
                    break
                if set(payload) != {"release"} or type(payload["release"]) is not bool:
                    status = "containment_lost"
                    break
                run_worker = payload["release"]
                gate_decided = True
                status = "running" if run_worker else "cancelled"
                break
            if reader.closed:
                status = "cancelled"
                break
            time.sleep(_CONTROL_POLL_SECONDS)

        stdout = bytearray()
        stderr = bytearray()
        if run_worker:
            assert process.stdin is not None
            assert process.stdout is not None
            assert process.stderr is not None
            for stream in (process.stdin, process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
            if loopback_turn is not None:
                loopback_turn = _validate_loopback_turn_authority(
                    loopback_turn,
                    worker_key=worker_key,
                    runtime_launch=runtime_launch,
                )
            pending = memoryview(
                worker_key
                + request_frame
                + (b"" if loopback_turn is None else loopback_turn.context_frame)
            )
            cancelled = False
            protocol_failure = False
            gateway_requested = False
            gateway_response_received = False
            gateway_exchange_hash: str | None = None
            while True:
                frame = reader.poll()
                if frame is not None:
                    try:
                        if gateway_requested and not gateway_response_received:
                            assert loopback_turn is not None
                            payload = _decode_control(
                                frame,
                                key=broker_key,
                                nonce=broker_nonce,
                                kind="gateway_response",
                                sequence=2,
                            )
                            response_frame = _validate_gateway_control_payload(
                                payload,
                                runtime=runtime_launch.authority.runtime_binding,
                                authority=loopback_turn,
                                kind="gateway_response",
                            )
                            parsed_gateway_response = parse_loopback_response_frame(
                                response_frame,
                                key=worker_key,
                                nonce=loopback_turn.worker_nonce,
                                runtime=runtime_launch.authority.runtime_binding,
                                original_request_hash=loopback_turn.original_request_hash,
                                gateway_policy_hash=loopback_turn.policy.content_hash,
                            )
                            if (
                                parsed_gateway_response.response_challenge is None
                                or parsed_gateway_response.exchange_hash is None
                            ):
                                raise ProviderBoundaryIndeterminate()
                            gateway_exchange_hash = parsed_gateway_response.exchange_hash
                            pending = memoryview(response_frame)
                            gateway_response_received = True
                        else:
                            _decode_control(
                                frame,
                                key=broker_key,
                                nonce=broker_nonce,
                                kind="cancel",
                                sequence=1,
                            )
                            cancelled = True
                    except ProviderBoundaryIndeterminate:
                        status = "containment_lost"
                        break
                    if cancelled:
                        break
                if reader.closed:
                    cancelled = True
                    break
                if pending:
                    try:
                        written = os.write(process.stdin.fileno(), pending[: 64 * 1024])
                    except BlockingIOError:
                        written = 0
                    except (BrokenPipeError, OSError):
                        pending = pending[0:0]
                    if written:
                        pending = pending[written:]
                    if not pending and (loopback_turn is None or gateway_response_received):
                        process.stdin.close()
                _read_pipe_nonblocking(process.stdout, MAX_WORKER_RESPONSE_BYTES + 4, stdout)
                _read_pipe_nonblocking(process.stderr, MAX_WORKER_STDERR_BYTES, stderr)
                if (
                    len(stdout) > MAX_WORKER_RESPONSE_BYTES + 4
                    or len(stderr) > MAX_WORKER_STDERR_BYTES
                ):
                    protocol_failure = True
                    break
                if (
                    len(stdout) >= 4
                    and int.from_bytes(stdout[:4], "big") > MAX_WORKER_RESPONSE_BYTES
                ):
                    protocol_failure = True
                    break
                if stderr:
                    protocol_failure = True
                    break
                if loopback_turn is not None and not gateway_requested and len(stdout) >= 4:
                    size = int.from_bytes(stdout[:4], "big")
                    if size > MAX_LOOPBACK_REQUEST_FRAME_BYTES:
                        protocol_failure = True
                        break
                    if len(stdout) >= size + 4:
                        gateway_frame = bytes(stdout[: size + 4])
                        del stdout[: size + 4]
                        try:
                            gateway_session = LoopbackProtocolSession(
                                key=worker_key,
                                nonce=loopback_turn.worker_nonce,
                                runtime=runtime_launch.authority.runtime_binding,
                                original_request_hash=loopback_turn.original_request_hash,
                                gateway_policy_hash=loopback_turn.policy.content_hash,
                            )
                            gateway_session.accept_request(gateway_frame)
                            _send_all(
                                control,
                                _encode_control(
                                    kind="gateway_request",
                                    sequence=1,
                                    nonce=broker_nonce,
                                    payload=_gateway_control_payload(
                                        gateway_frame,
                                        runtime=runtime_launch.authority.runtime_binding,
                                        authority=loopback_turn,
                                    ),
                                    key=broker_key,
                                ),
                            )
                        except (LoopbackProtocolError, ProviderBoundaryIndeterminate):
                            protocol_failure = True
                            break
                        gateway_requested = True
                if process.poll() is not None:
                    # A worker may exit after emitting bytes that predate the
                    # parent response.  Wait for that response so only its
                    # fresh exchange proof can authorize the final envelope.
                    if (
                        loopback_turn is not None
                        and gateway_requested
                        and not gateway_response_received
                    ):
                        time.sleep(0.001)
                        continue
                    break
                time.sleep(0.001)

            if cancelled:
                status = "cancelled"
            elif status == "containment_lost":
                pass
            elif protocol_failure:
                status = "provider_failed"
            elif process.poll() is None:
                status = "provider_failed"
            elif loopback_turn is not None and not gateway_response_received:
                status = "provider_failed"
            else:
                status = "response" if process.returncode == 0 else "provider_failed"

        if process is not None and process.poll() is None:
            try:
                if worker_identity is None:
                    raise ProviderBoundaryIndeterminate()
                _signal_identity(worker_identity, signal.SIGKILL)
            except ProviderBoundaryIndeterminate:
                pass
            try:
                process.wait(timeout=0.5)
            except (subprocess.TimeoutExpired, OSError):
                pass
        elif process is not None:
            try:
                process.wait(timeout=0)
            except (subprocess.TimeoutExpired, OSError):
                pass

        if not _prove_linux_domain_empty(broker_pid=broker_pid, tracked=tracked):
            status = "containment_lost"
        elif process is not None and status == "response":
            assert process.stdout is not None
            assert process.stderr is not None
            _read_pipe_nonblocking(process.stdout, MAX_WORKER_RESPONSE_BYTES + 4, stdout)
            _read_pipe_nonblocking(process.stderr, MAX_WORKER_STDERR_BYTES, stderr)
            if stderr or len(stdout) > MAX_WORKER_RESPONSE_BYTES + 4:
                status = "provider_failed"
            else:
                response = bytes(stdout)
                if loopback_turn is not None:
                    if gateway_exchange_hash is None:
                        status = "provider_failed"
                        response = None
                    else:
                        try:
                            response = _strip_gateway_result_proof(
                                response,
                                key=worker_key,
                                nonce=loopback_turn.worker_nonce,
                                request_hash=loopback_turn.original_request_hash,
                                expected_exchange_hash=gateway_exchange_hash,
                                runtime_key=runtime_launch.authority.key,
                                runtime_authority=runtime_launch.authority,
                            )
                        except WorkerProtocolError:
                            status = "provider_failed"
                            response = None

        payload: dict[str, object] = {"status": status}
        if response is not None:
            payload["response_base64"] = base64.b64encode(response).decode("ascii")
        control.setblocking(True)
        _send_all(
            control,
            _encode_control(
                kind="domain_empty",
                sequence=1,
                nonce=broker_nonce,
                payload=payload,
                key=broker_key,
            ),
        )
        return 0
    except BaseException:
        if process is not None and process.poll() is None:
            try:
                if worker_identity is not None:
                    _signal_identity(worker_identity, signal.SIGKILL)
            except BaseException:
                pass
        empty = False
        try:
            empty = _prove_linux_domain_empty(broker_pid=broker_pid, tracked=tracked)
        except BaseException:
            pass
        try:
            control.setblocking(True)
            _send_all(
                control,
                _encode_control(
                    kind="domain_empty",
                    sequence=1,
                    nonce=broker_nonce,
                    payload={"status": "provider_failed" if empty else "containment_lost"},
                    key=broker_key,
                ),
            )
        except BaseException:
            pass
        return 1
    finally:
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException:
                        pass
        if worker_identity is not None:
            _close_linux_identity(worker_identity)
        try:
            control.close()
        except BaseException:
            pass
        _remove_scratch(scratch)


def _linux_broker_process_entry(
    control: socket.socket,
    runtime_launch: _CodeOwnedRuntimeLaunch,
    broker_key: bytes,
    broker_nonce: str,
    worker_key: bytes,
    request_frame: bytes,
    scratch: str,
    loopback_turn: _LoopbackTurnAuthority | None = None,
) -> None:
    descriptor = control.detach()
    gate = socket.socket(fileno=descriptor)
    try:
        gate.setblocking(True)
        _decode_control(
            _recv_control_frame(gate),
            key=broker_key,
            nonce=broker_nonce,
            kind="start",
            sequence=0,
        )
        if type(runtime_launch) is not _CodeOwnedRuntimeLaunch:
            raise ProviderBoundaryIndeterminate()
        code = _linux_broker_main(
            gate.detach(),
            runtime_launch=runtime_launch,
            broker_key=broker_key,
            broker_nonce=broker_nonce,
            worker_key=worker_key,
            request_frame=request_frame,
            scratch=scratch,
            loopback_turn=loopback_turn,
        )
    except BaseException:
        try:
            gate.close()
        except BaseException:
            pass
        code = 1
    _remove_scratch(scratch)
    raise SystemExit(code)


def _remove_scratch(path: str) -> bool:
    for _attempt in range(2):
        try:
            shutil.rmtree(path)
        except FileNotFoundError:
            return True
        except BaseException:
            pass
        try:
            if not Path(path).exists():
                return True
        except BaseException:
            pass
        try:
            time.sleep(0.002)
        except BaseException:
            pass
    return False


class LinuxProcessSupervisor:
    """A per-turn subreaper broker whose private domain contains only one worker tree."""

    def __init__(self, *, runtime_launch: _CodeOwnedRuntimeLaunch | None = None) -> None:
        if not sys.platform.startswith("linux") or not Path("/proc/self/stat").is_file():
            raise ProviderBoundaryUnsupported()
        if not callable(getattr(os, "pidfd_open", None)) or not callable(
            getattr(signal, "pidfd_send_signal", None)
        ):
            raise ProviderBoundaryUnsupported()
        if runtime_launch is None:
            runtime_launch = _capture_runtime_launch(
                runtime_entry(_CodeOwnedRuntimeKey.CONFORMANCE)
            )
        elif type(runtime_launch) is not _CodeOwnedRuntimeLaunch:
            raise ProviderBoundaryFailure()
        self._runtime_launch = runtime_launch
        self.spawn_count = 0
        self.active_broker_pid: int | None = None
        self.active_worker_pid: int | None = None
        self._lock = threading.Lock()
        self._turn_lock = threading.Lock()

    def _set_active(self, pid: int | None) -> None:
        with self._lock:
            self.active_broker_pid = pid

    def _set_worker(self, pid: int | None) -> None:
        with self._lock:
            self.active_worker_pid = pid

    @staticmethod
    def _close_socket(stream: socket.socket) -> None:
        try:
            stream.close()
        except BaseException:
            pass

    @staticmethod
    def _stop_unidentified_broker(broker: multiprocessing.Process) -> bool:
        """Stop and wait before a trustworthy PID/start-time identity exists."""

        descriptor: int | None = None
        close_ok = True
        try:
            pid = broker.pid
            if type(pid) is not int or pid <= 0:
                return False
            descriptor = os.pidfd_open(pid, 0)
            signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
        except BaseException:
            return False
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except BaseException:
                    close_ok = False
        if not close_ok:
            return False
        try:
            broker.join(0.5)
        except BaseException:
            pass
        try:
            alive = broker.is_alive()
        except BaseException:
            return False
        if alive:
            return False
        try:
            broker.close()
        except BaseException:
            return False
        return True

    def execute(
        self,
        request_frame: bytes,
        *,
        worker_key: bytes,
        boundary: ProviderBoundaryControl,
        turn_timeout_ms: int,
        runtime_key: _CodeOwnedRuntimeKey = _CodeOwnedRuntimeKey.CONFORMANCE,
        runtime_launch: _CodeOwnedRuntimeLaunch | None = None,
        gateway_policy: LoopbackGatewayPolicy | None = None,
        worker_nonce: str | None = None,
        original_request_hash: str | None = None,
        gateway_context_frame: bytes | None = None,
    ) -> _BrokerReport:
        if type(runtime_key) is not _CodeOwnedRuntimeKey:
            raise ProviderBoundaryFailure()
        if runtime_launch is None:
            runtime_launch = self._runtime_launch
        if (
            type(runtime_launch) is not _CodeOwnedRuntimeLaunch
            or runtime_launch.authority.key is not runtime_key
        ):
            raise ProviderBoundaryFailure()
        supplied_gateway = (
            gateway_policy,
            worker_nonce,
            original_request_hash,
            gateway_context_frame,
        )
        if all(value is None for value in supplied_gateway):
            loopback_turn = None
        elif any(value is None for value in supplied_gateway):
            raise ProviderBoundaryFailure()
        else:
            loopback_turn = _validate_loopback_turn_authority(
                _LoopbackTurnAuthority(
                    gateway_policy,  # type: ignore[arg-type]
                    worker_nonce,  # type: ignore[arg-type]
                    original_request_hash,  # type: ignore[arg-type]
                    gateway_context_frame,  # type: ignore[arg-type]
                ),
                worker_key=worker_key,
                runtime_launch=runtime_launch,
            )
        if not self._turn_lock.acquire(blocking=False):
            raise ProviderBoundaryFailure()
        started = 0.0
        scratch: str | None = None
        original: BaseException | None = None
        try:
            started = time.monotonic()
            scratch = tempfile.mkdtemp(prefix="worldforge-worker-")
            os.chmod(scratch, 0o700)
            return self._execute_with_scratch(
                request_frame,
                worker_key=worker_key,
                boundary=boundary,
                turn_timeout_ms=turn_timeout_ms,
                runtime_launch=runtime_launch,
                scratch=scratch,
                started=started,
                loopback_turn=loopback_turn,
            )
        except BaseException as exc:
            original = exc
            if isinstance(exc, Exception):
                if isinstance(
                    exc,
                    (
                        ProviderBoundaryFailure,
                        ProviderBoundaryIndeterminate,
                        ProviderBoundaryStopped,
                    ),
                ):
                    raise
                raise ProviderBoundaryFailure() from None
            raise
        finally:
            try:
                if scratch is not None and not _remove_scratch(scratch):
                    if original is None or isinstance(original, Exception):
                        raise ProviderBoundaryIndeterminate() from None
                    try:
                        original.add_note("provider scratch cleanup was indeterminate")
                    except BaseException:
                        pass
            finally:
                self._turn_lock.release()

    def _execute_with_scratch(
        self,
        request_frame: bytes,
        *,
        worker_key: bytes,
        boundary: ProviderBoundaryControl,
        turn_timeout_ms: int,
        runtime_launch: _CodeOwnedRuntimeLaunch,
        scratch: str,
        started: float,
        loopback_turn: _LoopbackTurnAuthority | None = None,
    ) -> _BrokerReport:
        initial = boundary.poll_stop_reason()
        if initial is not None:
            raise ProviderBoundaryStopped(initial)
        if (time.monotonic() - started) * 1000 > turn_timeout_ms:
            raise ProviderBoundaryFailure()
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        broker: multiprocessing.Process | None = None
        broker_identity: _ProcessIdentity | None = None
        setup_complete = False
        child_closed = False
        setup_domain_proven = False
        try:
            broker_key = os.urandom(32)
            broker_nonce = os.urandom(32).hex()
            # ``spawn`` avoids unsafe post-fork Python in a multi-threaded Studio
            # host and creates no persistent fork-server/RPC process.
            context = multiprocessing.get_context("spawn")
            broker_args = (
                child,
                runtime_launch,
                broker_key,
                broker_nonce,
                worker_key,
                request_frame,
                scratch,
            )
            if loopback_turn is not None:
                broker_args = (*broker_args, loopback_turn)
            broker = context.Process(
                target=_linux_broker_process_entry,
                args=broker_args,
                daemon=False,
            )
            broker.start()
            pid = broker.pid
            if pid is None:
                raise ProviderBoundaryIndeterminate()
            broker_identity = _retain_linux_identity(pid, None)
            if broker_identity is None:
                raise ProviderBoundaryIndeterminate()
            self.spawn_count += 1
            self._set_active(pid)
            child.close()
            child_closed = True
            _send_all(
                parent,
                _encode_control(
                    kind="start",
                    sequence=0,
                    nonce=broker_nonce,
                    payload={},
                    key=broker_key,
                ),
            )
            setup_complete = True
        except ProviderBoundaryIndeterminate:
            if broker is not None and broker_identity is not None:
                setup_domain_proven = _attempt_linux_domain_cleanup(
                    broker=broker,
                    broker_identity=broker_identity,
                    tracked={},
                )
            elif broker is not None:
                setup_domain_proven = self._stop_unidentified_broker(broker)
            if broker is not None and not setup_domain_proven:
                raise ProviderBoundaryIndeterminate() from None
            raise
        except Exception:
            if broker is not None and broker_identity is not None:
                setup_domain_proven = _attempt_linux_domain_cleanup(
                    broker=broker,
                    broker_identity=broker_identity,
                    tracked={},
                )
            elif broker is not None:
                setup_domain_proven = self._stop_unidentified_broker(broker)
            if broker is not None and not setup_domain_proven:
                raise ProviderBoundaryIndeterminate() from None
            raise ProviderBoundaryFailure() from None
        except BaseException as exc:
            if broker is not None and broker_identity is not None:
                setup_domain_proven = _attempt_linux_domain_cleanup(
                    broker=broker,
                    broker_identity=broker_identity,
                    tracked={},
                )
            elif broker is not None:
                setup_domain_proven = self._stop_unidentified_broker(broker)
            if broker is not None and not setup_domain_proven:
                try:
                    exc.add_note("provider setup cleanup was indeterminate")
                except BaseException:
                    pass
            raise
        finally:
            if not setup_complete:
                self._close_socket(parent)
            if not child_closed:
                self._close_socket(child)
            if not setup_complete:
                if broker is not None and broker_identity is not None:
                    try:
                        broker.close()
                    except BaseException:
                        pass
                    if not _close_linux_identity(broker_identity):
                        active = sys.exception()
                        if active is None or isinstance(active, Exception):
                            raise ProviderBoundaryIndeterminate() from None
                        try:
                            active.add_note("provider pidfd cleanup was indeterminate")
                        except BaseException:
                            pass
                self._set_active(None)
                self._set_worker(None)
        assert broker is not None
        assert broker_identity is not None
        parent.setblocking(False)
        reader = _ControlReader(parent)
        ready_identity: _ProcessIdentity | None = None
        released = False
        cancel_sent = False
        stop_reason: str | None = None
        pending_control_error: BaseException | None = None
        timed_out = False
        control_latched = False
        tracked: dict[int, int] = {}
        report: _BrokerReport | None = None
        gateway_exchanged = False
        gateway_response_accepted = False
        domain_report_proven = False
        cleanup_attempted = False
        cleanup_domain_proven = False

        def poll_control_once() -> None:
            nonlocal control_latched
            nonlocal pending_control_error
            nonlocal stop_reason
            nonlocal timed_out

            if control_latched:
                return
            try:
                reason = boundary.poll_stop_reason()
            except BaseException as exc:
                pending_control_error = exc
                stop_reason = "execution_cancelled"
                control_latched = True
                return
            if reason is not None:
                stop_reason = reason
                control_latched = True
                return
            if (time.monotonic() - started) * 1000 > turn_timeout_ms:
                timed_out = True
                control_latched = True

        def raise_latched_control_outcome(*, domain_empty: bool) -> None:
            if not control_latched:
                raise ProviderBoundaryIndeterminate()
            if not domain_empty:
                if pending_control_error is not None and not isinstance(
                    pending_control_error, Exception
                ):
                    try:
                        pending_control_error.add_note("provider cleanup was indeterminate")
                    except BaseException:
                        pass
                    raise pending_control_error
                raise ProviderBoundaryIndeterminate()
            if gateway_response_accepted:
                if pending_control_error is not None and not isinstance(
                    pending_control_error, Exception
                ):
                    try:
                        pending_control_error.add_note(
                            "provider outcome is indeterminate after loopback response"
                        )
                    except BaseException:
                        pass
                    raise pending_control_error
                raise ProviderBoundaryIndeterminate()
            if pending_control_error is not None:
                if isinstance(pending_control_error, Exception):
                    raise ProviderBoundaryFailure() from None
                raise pending_control_error
            if stop_reason is not None:
                raise ProviderBoundaryStopped(stop_reason)
            if timed_out:
                raise ProviderBoundaryFailure()
            raise ProviderBoundaryIndeterminate()

        try:
            while report is None:
                poll_control_once()
                if not released and (
                    stop_reason is not None or timed_out or pending_control_error is not None
                ):
                    cleanup_attempted = True
                    cleanup_domain_proven = _attempt_linux_domain_cleanup(
                        broker=broker,
                        broker_identity=broker_identity,
                        tracked=tracked,
                    )
                    domain_report_proven = cleanup_domain_proven
                    raise_latched_control_outcome(domain_empty=cleanup_domain_proven)
                frame = reader.poll()
                if frame is not None:
                    if not released:
                        payload = _decode_control(
                            frame,
                            key=broker_key,
                            nonce=broker_nonce,
                            kind="ready",
                            sequence=0,
                        )
                        if set(payload) != {"worker_pid", "worker_start_time"} or any(
                            type(payload[name]) is not int
                            for name in ("worker_pid", "worker_start_time")
                        ):
                            raise ProviderBoundaryIndeterminate()
                        ready_identity = _retain_linux_identity(
                            payload["worker_pid"], payload["worker_start_time"]
                        )
                        if ready_identity is None:
                            raise ProviderBoundaryIndeterminate()
                        tracked[ready_identity.pid] = ready_identity.start_time
                        self._set_worker(ready_identity.pid)
                        poll_control_once()
                        if (
                            stop_reason is not None
                            or timed_out
                            or pending_control_error is not None
                        ):
                            cleanup_attempted = True
                            cleanup_domain_proven = _attempt_linux_domain_cleanup(
                                broker=broker,
                                broker_identity=broker_identity,
                                tracked=tracked,
                            )
                            domain_report_proven = cleanup_domain_proven
                            raise_latched_control_outcome(domain_empty=cleanup_domain_proven)
                        _send_all(
                            parent,
                            _encode_control(
                                kind="release",
                                sequence=0,
                                nonce=broker_nonce,
                                payload={"release": True},
                                key=broker_key,
                            ),
                        )
                        released = True
                    else:
                        if loopback_turn is not None and not gateway_exchanged:
                            try:
                                gateway_payload = _decode_control(
                                    frame,
                                    key=broker_key,
                                    nonce=broker_nonce,
                                    kind="gateway_request",
                                    sequence=1,
                                )
                            except ProviderBoundaryIndeterminate:
                                payload = _decode_control(
                                    frame,
                                    key=broker_key,
                                    nonce=broker_nonce,
                                    kind="domain_empty",
                                    sequence=1,
                                )
                            else:
                                gateway_frame = _validate_gateway_control_payload(
                                    gateway_payload,
                                    runtime=runtime_launch.authority.runtime_binding,
                                    authority=loopback_turn,
                                    kind="gateway_request",
                                )
                                session = LoopbackProtocolSession(
                                    key=worker_key,
                                    nonce=loopback_turn.worker_nonce,
                                    runtime=runtime_launch.authority.runtime_binding,
                                    original_request_hash=loopback_turn.original_request_hash,
                                    gateway_policy_hash=loopback_turn.policy.content_hash,
                                )
                                request = session.accept_request(gateway_frame)
                                try:
                                    response_body = execute_loopback_exchange(
                                        loopback_turn.policy,
                                        request.body,
                                        boundary=boundary.poll_stop_reason,
                                        started=started,
                                        private_deadline=(started + turn_timeout_ms / 1000.0),
                                    )
                                    gateway_response_accepted = True
                                except LoopbackGatewayStopped as exc:
                                    raise ProviderBoundaryStopped(exc.reason_code) from None
                                except LoopbackGatewayError:
                                    raise ProviderBoundaryFailure() from None
                                except LoopbackGatewayIndeterminate:
                                    raise ProviderBoundaryIndeterminate() from None
                                poll_control_once()
                                if control_latched:
                                    raise ProviderBoundaryIndeterminate()
                                response_frame = session.build_response(
                                    response_body,
                                    response_challenge=os.urandom(32).hex(),
                                )
                                _send_all(
                                    parent,
                                    _encode_control(
                                        kind="gateway_response",
                                        sequence=2,
                                        nonce=broker_nonce,
                                        payload=_gateway_control_payload(
                                            response_frame,
                                            runtime=runtime_launch.authority.runtime_binding,
                                            authority=loopback_turn,
                                        ),
                                        key=broker_key,
                                    ),
                                )
                                gateway_exchanged = True
                                continue
                        else:
                            payload = _decode_control(
                                frame,
                                key=broker_key,
                                nonce=broker_nonce,
                                kind="domain_empty",
                                sequence=1,
                            )
                        status = payload.get("status")
                        if status not in {
                            "response",
                            "provider_failed",
                            "cancelled",
                            "containment_lost",
                        }:
                            raise ProviderBoundaryIndeterminate()
                        encoded = payload.get("response_base64")
                        if status == "response":
                            if type(encoded) is not str:
                                raise ProviderBoundaryIndeterminate()
                            try:
                                response = base64.b64decode(encoded, validate=True)
                            except Exception:
                                raise ProviderBoundaryIndeterminate() from None
                            if len(response) > MAX_WORKER_RESPONSE_BYTES + 4:
                                raise ProviderBoundaryIndeterminate()
                        elif encoded is not None:
                            raise ProviderBoundaryIndeterminate()
                        else:
                            response = None
                        report = _BrokerReport(status, response)
                        break
                if reader.closed:
                    raise ProviderBoundaryIndeterminate()
                if released and (stop_reason is not None or timed_out) and not cancel_sent:
                    _send_all(
                        parent,
                        _encode_control(
                            kind="cancel",
                            sequence=1,
                            nonce=broker_nonce,
                            payload={},
                            key=broker_key,
                        ),
                    )
                    cancel_sent = True
                if not broker.is_alive() and report is None:
                    raise ProviderBoundaryIndeterminate()
                time.sleep(_CONTROL_POLL_SECONDS)

            assert report is not None
            broker.join(_BROKER_EXIT_SECONDS)
            if broker.is_alive():
                _signal_identity(broker_identity, signal.SIGKILL)
                broker.join(0.5)
                if broker.is_alive():
                    raise ProviderBoundaryIndeterminate()
            reader.require_clean_eof(timeout_seconds=_BROKER_EXIT_SECONDS)
            if report.status == "containment_lost":
                raise ProviderBoundaryIndeterminate()
            if loopback_turn is not None and not gateway_exchanged and report.status == "response":
                raise ProviderBoundaryIndeterminate()
            domain_report_proven = True
            poll_control_once()
            if control_latched:
                raise_latched_control_outcome(domain_empty=True)
            if report.status != "response":
                if gateway_response_accepted:
                    raise ProviderBoundaryIndeterminate()
                raise ProviderBoundaryFailure()
            return report
        except BaseException as exc:
            if control_latched:
                if not domain_report_proven and not cleanup_attempted:
                    cleanup_attempted = True
                    cleanup_domain_proven = _attempt_linux_domain_cleanup(
                        broker=broker,
                        broker_identity=broker_identity,
                        tracked=tracked,
                    )
                    domain_report_proven = cleanup_domain_proven
                raise_latched_control_outcome(
                    domain_empty=domain_report_proven or cleanup_domain_proven
                )
            if isinstance(exc, ProviderBoundaryIndeterminate):
                if not cleanup_attempted and not domain_report_proven:
                    cleanup_attempted = True
                    _attempt_linux_domain_cleanup(
                        broker=broker,
                        broker_identity=broker_identity,
                        tracked=tracked,
                    )
                raise
            if isinstance(exc, (ProviderBoundaryFailure, ProviderBoundaryStopped)):
                if not domain_report_proven:
                    if not cleanup_attempted:
                        cleanup_attempted = True
                        cleanup_domain_proven = _attempt_linux_domain_cleanup(
                            broker=broker,
                            broker_identity=broker_identity,
                            tracked=tracked,
                        )
                    if not cleanup_domain_proven:
                        raise ProviderBoundaryIndeterminate() from None
                raise
            if isinstance(exc, Exception):
                if not domain_report_proven and not cleanup_attempted:
                    cleanup_attempted = True
                    cleanup_domain_proven = _attempt_linux_domain_cleanup(
                        broker=broker,
                        broker_identity=broker_identity,
                        tracked=tracked,
                    )
                if not (domain_report_proven or cleanup_domain_proven):
                    raise ProviderBoundaryIndeterminate() from None
                if gateway_response_accepted:
                    raise ProviderBoundaryIndeterminate() from None
                raise ProviderBoundaryFailure() from None
            if domain_report_proven or cleanup_attempted:
                raise
            cleanup_attempted = True
            cleanup_domain_proven = _attempt_linux_domain_cleanup(
                broker=broker,
                broker_identity=broker_identity,
                tracked=tracked,
            )
            if not cleanup_domain_proven:
                try:
                    exc.add_note("provider cleanup was indeterminate")
                except BaseException:
                    pass
            raise
        finally:
            self._close_socket(parent)
            try:
                broker.close()
            except BaseException:
                pass
            identities_closed = True
            if ready_identity is not None:
                identities_closed = _close_linux_identity(ready_identity)
            if not _close_linux_identity(broker_identity):
                identities_closed = False
            self._set_active(None)
            self._set_worker(None)
            if not identities_closed:
                active = sys.exception()
                if active is None or isinstance(active, Exception):
                    raise ProviderBoundaryIndeterminate() from None
                try:
                    active.add_note("provider pidfd cleanup was indeterminate")
                except BaseException:
                    pass


__all__ = (
    "LinuxProcessSupervisor",
    "ProviderBoundaryFailure",
    "ProviderBoundaryIndeterminate",
    "ProviderBoundaryStopped",
    "ProviderBoundaryUnsupported",
    "fixed_worker_command",
)
