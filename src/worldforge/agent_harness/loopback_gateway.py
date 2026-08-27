"""Exact-origin, parent-owned, fixed ordered HTTP loopback plan."""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import select
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .loopback_protocol import (
    MAX_LOOPBACK_REQUEST_BODY_BYTES,
    MAX_LOOPBACK_RESPONSE_BODY_BYTES,
    LoopbackProtocolError,
    LoopbackStepResult,
    canonical_loopback_json,
)

MAX_LOOPBACK_RESPONSE_HEADER_BYTES = 8 * 1024
MAX_LOOPBACK_RESPONSE_HEADERS_TOTAL_BYTES = 16 * 1024
_PATH = "/worldforge/v1/ordered-loopback-probe"
_TOTAL_DEADLINE_MS = 2_000
_ORIGIN_RE = re.compile(r"^http://(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$")
_POLICY_FORMAT = "world-forge.private.parent_loopback_gateway_policy"
_POLICY_VERSION = 2
_PLAN_FORMAT = "world-forge.private.ordered_loopback_operation_plan"
_PLAN_VERSION = 1
_NO_TELEMETRY_FORMAT = "world-forge.private.code_owned_no_telemetry_branch"
_NO_TELEMETRY_VERSION = 1
_POLL_SECONDS = 0.01
_MAX_SAFE_INTEGER = (1 << 53) - 1
_NO_RESPONSE = object()


class LoopbackGatewayError(ValueError):
    def __init__(self) -> None:
        super().__init__("loopback_gateway_failed")


class LoopbackGatewayStopped(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class LoopbackGatewayIndeterminate(RuntimeError):
    def __init__(self) -> None:
        super().__init__("loopback_gateway_indeterminate")


def _canonical(value: object) -> bytes:
    try:
        return canonical_loopback_json(value)
    except LoopbackProtocolError:
        raise LoopbackGatewayError() from None


@dataclass(frozen=True, slots=True)
class LoopbackStepPolicy:
    index: int
    method: str
    path: str
    body_present: bool
    request_body_limit: int
    response_header_limit: int
    response_body_limit: int
    content_hash: str

    @property
    def canonical_values(self) -> dict[str, object]:
        return {
            "body_present": self.body_present,
            "index": self.index,
            "method": self.method,
            "path": self.path,
            "request_body_limit": self.request_body_limit,
            "response_body_limit": self.response_body_limit,
            "response_header_limit": self.response_header_limit,
        }


def _fixed_steps() -> tuple[LoopbackStepPolicy, LoopbackStepPolicy]:
    values = (
        {
            "body_present": False,
            "index": 0,
            "method": "GET",
            "path": _PATH,
            "request_body_limit": 0,
            "response_body_limit": MAX_LOOPBACK_RESPONSE_BODY_BYTES,
            "response_header_limit": MAX_LOOPBACK_RESPONSE_HEADER_BYTES,
        },
        {
            "body_present": True,
            "index": 1,
            "method": "POST",
            "path": _PATH,
            "request_body_limit": MAX_LOOPBACK_REQUEST_BODY_BYTES,
            "response_body_limit": MAX_LOOPBACK_RESPONSE_BODY_BYTES,
            "response_header_limit": MAX_LOOPBACK_RESPONSE_HEADER_BYTES,
        },
    )
    return tuple(
        LoopbackStepPolicy(**value, content_hash=hashlib.sha256(_canonical(value)).hexdigest())
        for value in values
    )  # type: ignore[return-value]


def _ordered_plan_values(steps: tuple[LoopbackStepPolicy, LoopbackStepPolicy]) -> dict[str, object]:
    """Return the one closed, code-owned semantic authority document."""

    return {
        "aggregate_bounds": {
            "request_body_bytes": MAX_LOOPBACK_REQUEST_BODY_BYTES,
            "response_body_bytes": MAX_LOOPBACK_RESPONSE_BODY_BYTES,
            "response_header_bytes": MAX_LOOPBACK_RESPONSE_HEADERS_TOTAL_BYTES,
        },
        "deadline_policy": {
            "anchor_event": (
                "process_supervisor_execute_after_authority_validation_and_turn_lock_"
                "before_scratch_or_process_setup"
            ),
            "clock": "monotonic",
            "private_deadline_rule": "minimum",
            "scope": "plan_global_absolute",
            "total_deadline_ms": _TOTAL_DEADLINE_MS,
            "reset_between_steps": False,
        },
        "effect_policy": {
            "latch_point": "immediately_before_first_send_syscall",
            "post_latch_failure": "indeterminate",
            "reset": False,
            "scope": "plan_global",
        },
        "format": _PLAN_FORMAT,
        "format_version": _PLAN_VERSION,
        "json_policy": {
            "canonical_form": "utf8_sorted_compact_json",
            "canonicalize_after_decode": True,
            "duplicate_keys": "reject_any_depth",
            "encoding": "utf-8",
            "maximum_depth": 64,
            "nonfinite_numbers": "reject",
            "ordinary_json_input": True,
            "unsafe_integer_absolute_max": _MAX_SAFE_INTEGER,
        },
        "ordered_steps": [step.canonical_values for step in steps],
        "operation_policy": {
            "caller_selected_fields": [],
            "origin": "approved_numeric_loopback",
            "query": "absent",
            "worker_selected_fields": [],
        },
        "plan_count": len(steps),
        "request_policy": {
            "bodyless_headers": [
                {"name": "Host", "value_source": "approved_origin_authority"},
                {"name": "Accept", "value": "application/json"},
                {"name": "Connection", "value": "close"},
            ],
            "body_headers": [
                {"name": "Host", "value_source": "approved_origin_authority"},
                {"name": "Content-Type", "value": "application/json"},
                {"name": "Accept", "value": "application/json"},
                {"name": "Content-Length", "value_source": "canonical_body_length"},
                {"name": "Connection", "value": "close"},
            ],
            "http_version": "HTTP/1.1",
            "host_generation": "approved_numeric_origin_host_and_port",
        },
        "response_policy": {
            "clean_eof_required": True,
            "connection_header": "absent_or_close",
            "content_length_count": 1,
            "content_type": "application/json",
            "header_terminator_rule": "first_crlf_crlf",
            "forbidden": [
                "bare_lf_in_header_section",
                "content_encoding",
                "interim_1xx",
                "obs_fold",
                "redirect_3xx",
                "surplus_body",
                "trailers",
                "transfer_encoding",
                "truncated_body",
                "upgrade",
            ],
            "http_version": "HTTP/1.1",
            "status": 200,
        },
        "socket_lifecycle": {
            "bind": False,
            "close_before_next_step": True,
            "close_before_relay": True,
            "connection": "close",
            "dns": False,
            "fresh_socket_per_step": True,
            "listen": False,
            "nonblocking": True,
            "owner": "main_parent",
            "pooling": False,
            "proxy": False,
            "reconnect": False,
            "redirects": False,
            "retry_count": 0,
            "sequential": True,
            "caller_selected_socket_options": False,
        },
    }


@dataclass(frozen=True, slots=True)
class LoopbackGatewayPolicy:
    endpoint_origin: str
    family: int
    host: str
    port: int
    path: str
    total_deadline_ms: int
    request_body_limit: int
    response_header_limit: int
    response_body_limit: int
    aggregate_response_header_limit: int
    plan_count: int
    plan_hash: str
    ordered_steps: tuple[LoopbackStepPolicy, LoopbackStepPolicy]
    content_hash: str
    canonical_document: bytes = field(repr=False, compare=False)

    @classmethod
    def create(cls, endpoint_origin: object) -> LoopbackGatewayPolicy:
        if type(endpoint_origin) is not str:
            raise LoopbackGatewayError()
        match = _ORIGIN_RE.fullmatch(endpoint_origin)
        if match is None:
            raise LoopbackGatewayError()
        port = int(match.group(2))
        if not 1 <= port <= 65535:
            raise LoopbackGatewayError()
        literal = match.group(1)
        if literal == "127.0.0.1":
            family = socket.AF_INET
            host = literal
        elif literal == "[::1]":
            family = socket.AF_INET6
            host = "::1"
        else:
            raise LoopbackGatewayError()
        steps = _fixed_steps()
        step_documents = [step.canonical_values for step in steps]
        plan_values = _ordered_plan_values(steps)
        plan_hash = hashlib.sha256(_canonical(plan_values)).hexdigest()
        values = {
            "aggregate_request_body_limit": MAX_LOOPBACK_REQUEST_BODY_BYTES,
            "aggregate_response_body_limit": MAX_LOOPBACK_RESPONSE_BODY_BYTES,
            "aggregate_response_header_limit": MAX_LOOPBACK_RESPONSE_HEADERS_TOTAL_BYTES,
            "endpoint_origin": endpoint_origin,
            "family": int(family),
            "format": _POLICY_FORMAT,
            "format_version": _POLICY_VERSION,
            "host": host,
            "ordered_steps": step_documents,
            "ordered_plan": plan_values,
            "plan_count": len(steps),
            "plan_format": _PLAN_FORMAT,
            "plan_hash": plan_hash,
            "plan_version": _PLAN_VERSION,
            "port": port,
            "total_deadline_ms": _TOTAL_DEADLINE_MS,
        }
        document = _canonical(values)
        return cls(
            endpoint_origin=endpoint_origin,
            family=family,
            host=host,
            port=port,
            path=_PATH,
            total_deadline_ms=_TOTAL_DEADLINE_MS,
            request_body_limit=MAX_LOOPBACK_REQUEST_BODY_BYTES,
            response_header_limit=MAX_LOOPBACK_RESPONSE_HEADER_BYTES,
            response_body_limit=MAX_LOOPBACK_RESPONSE_BODY_BYTES,
            aggregate_response_header_limit=MAX_LOOPBACK_RESPONSE_HEADERS_TOTAL_BYTES,
            plan_count=len(steps),
            plan_hash=plan_hash,
            ordered_steps=steps,
            content_hash=hashlib.sha256(document).hexdigest(),
            canonical_document=document,
        )


def code_owned_no_telemetry_branch_hash() -> str:
    """Hash a truthful code-owned no-telemetry branch, not vendor behavior."""

    return hashlib.sha256(
        _canonical(
            {
                "emits_telemetry": False,
                "format": _NO_TELEMETRY_FORMAT,
                "format_version": _NO_TELEMETRY_VERSION,
                "scope": "deterministic_ordered_loopback_probe_only",
                "vendor_attestation": False,
            }
        )
    ).hexdigest()


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise LoopbackGatewayError()
        result[key] = value
    return result


def _parse_int(value: str) -> int:
    parsed = int(value)
    if abs(parsed) > _MAX_SAFE_INTEGER:
        raise ValueError
    return parsed


def _parse_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError
    return parsed


def _parse_http_response(response: object) -> tuple[object, int, int, bytes]:
    if type(response) is not bytes:
        raise LoopbackGatewayError()
    marker = b"\r\n\r\n"
    marker_index = response.find(marker)
    if marker_index < 0:
        raise LoopbackGatewayError()
    raw_headers = response[:marker_index]
    body = response[marker_index + len(marker) :]
    if b"\n" in raw_headers.replace(b"\r\n", b""):
        raise LoopbackGatewayError()
    header_length = len(raw_headers) + len(marker)
    if header_length > MAX_LOOPBACK_RESPONSE_HEADER_BYTES:
        raise LoopbackGatewayError()
    lines = raw_headers.split(b"\r\n")
    if not lines or re.fullmatch(rb"HTTP/1\.1 200(?: [\x20-\x7e]*)?", lines[0]) is None:
        raise LoopbackGatewayError()
    headers: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
            raise LoopbackGatewayError()
        name, value = line.split(b":", 1)
        if re.fullmatch(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name) is None or any(
            byte < 32 or byte == 127 for byte in value
        ):
            raise LoopbackGatewayError()
        headers.append((name.lower(), value.strip()))
    content_lengths = [value for name, value in headers if name == b"content-length"]
    content_types = [value for name, value in headers if name == b"content-type"]
    if (
        len(content_lengths) != 1
        or re.fullmatch(rb"0|[1-9][0-9]*", content_lengths[0]) is None
        or len(content_types) != 1
        or content_types[0].lower() != b"application/json"
        or any(name == b"transfer-encoding" for name, _value in headers)
        or any(name == b"content-encoding" for name, _value in headers)
        or any(name == b"upgrade" for name, _value in headers)
        or any(name == b"connection" and value.lower() != b"close" for name, value in headers)
    ):
        raise LoopbackGatewayError()
    expected_length = int(content_lengths[0])
    if expected_length > MAX_LOOPBACK_RESPONSE_BODY_BYTES or len(body) != expected_length:
        raise LoopbackGatewayError()
    try:
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            parse_int=_parse_int,
            parse_float=_parse_float,
        )
        canonical = _canonical(value)
        if len(canonical) > MAX_LOOPBACK_RESPONSE_BODY_BYTES:
            raise ValueError
        return value, header_length, len(body), canonical
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        raise LoopbackGatewayError() from None


def parse_loopback_http_response(response: object) -> object:
    return _parse_http_response(response)[0]


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _poll_boundary(boundary: Callable[[], str | None], *, effect_possible: bool) -> None:
    try:
        reason = boundary()
    except BaseException as exc:
        if not isinstance(exc, Exception):
            if effect_possible:
                try:
                    exc.add_note("loopback plan outcome is indeterminate after a send attempt")
                except BaseException:
                    pass
            raise
        if effect_possible:
            raise LoopbackGatewayIndeterminate() from None
        raise
    if reason is not None:
        if effect_possible:
            raise LoopbackGatewayIndeterminate()
        raise LoopbackGatewayStopped(reason)


def _wait_socket(
    stream: socket.socket,
    *,
    write: bool,
    deadline: float,
    boundary: Callable[[], str | None],
    effect_possible: bool,
) -> None:
    while True:
        _poll_boundary(boundary, effect_possible=effect_possible)
        remaining = _remaining(deadline)
        if remaining <= 0:
            if effect_possible:
                raise LoopbackGatewayIndeterminate()
            raise LoopbackGatewayError()
        try:
            readable, writable, exceptional = select.select(
                [] if write else [stream],
                [stream] if write else [],
                [stream],
                min(_POLL_SECONDS, remaining),
            )
        except InterruptedError:
            continue
        except Exception:
            if effect_possible:
                raise LoopbackGatewayIndeterminate() from None
            raise LoopbackGatewayError() from None
        if exceptional:
            if effect_possible:
                raise LoopbackGatewayIndeterminate()
            raise LoopbackGatewayError()
        if (write and writable) or (not write and readable):
            return


def _host_header(policy: LoopbackGatewayPolicy) -> str:
    return (
        f"[{policy.host}]:{policy.port}"
        if policy.family == socket.AF_INET6
        else f"{policy.host}:{policy.port}"
    )


def _http_request(
    policy: LoopbackGatewayPolicy,
    step: LoopbackStepPolicy,
    semantic_body: bytes,
) -> tuple[bytes, bytes]:
    if step.body_present:
        body = semantic_body
        headers = (
            f"POST {step.path} HTTP/1.1\r\n"
            f"Host: {_host_header(policy)}\r\n"
            "Content-Type: application/json\r\n"
            "Accept: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
    else:
        body = b""
        headers = (
            f"GET {step.path} HTTP/1.1\r\n"
            f"Host: {_host_header(policy)}\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
    return headers + body, body


def _connected_stream(
    policy: LoopbackGatewayPolicy,
    stream: socket.socket,
    *,
    deadline: float,
    boundary: Callable[[], str | None],
    effect_possible: bool,
) -> socket.socket:
    stream.setblocking(False)
    address: tuple[object, ...] = (
        (policy.host, policy.port)
        if policy.family == socket.AF_INET
        else (policy.host, policy.port, 0, 0)
    )
    code = stream.connect_ex(address)
    if code not in {0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR}:
        raise LoopbackGatewayError()
    if code != 0:
        _wait_socket(
            stream,
            write=True,
            deadline=deadline,
            boundary=boundary,
            effect_possible=effect_possible,
        )
        if stream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0:
            raise LoopbackGatewayError()
    try:
        peer = stream.getpeername()
    except OSError:
        raise LoopbackGatewayError() from None
    if (
        stream.family != policy.family
        or type(peer) is not tuple
        or len(peer) < 2
        or peer[0] != policy.host
        or peer[1] != policy.port
    ):
        raise LoopbackGatewayError()
    return stream


def _normalize_failure(exc: BaseException, *, effect_possible: bool) -> BaseException:
    if not isinstance(exc, Exception):
        if effect_possible:
            try:
                exc.add_note("loopback plan outcome is indeterminate after a send attempt")
            except BaseException:
                pass
        return exc
    if isinstance(exc, LoopbackGatewayIndeterminate):
        return exc
    if isinstance(exc, LoopbackGatewayStopped) and not effect_possible:
        return exc
    if isinstance(exc, LoopbackGatewayError) and not effect_possible:
        return exc
    return LoopbackGatewayIndeterminate() if effect_possible else LoopbackGatewayError()


def execute_loopback_exchange(
    policy: object,
    body: object,
    *,
    boundary: Callable[[], str | None],
    started: float,
    private_deadline: float | None = None,
) -> tuple[LoopbackStepResult, LoopbackStepResult]:
    """Run the single code-owned GET-then-POST plan on fresh parent sockets."""

    if type(policy) is not LoopbackGatewayPolicy or not callable(boundary):
        raise LoopbackGatewayError()
    if type(started) is not float or not math.isfinite(started):
        raise LoopbackGatewayError()
    if private_deadline is not None and (
        type(private_deadline) is not float or not math.isfinite(private_deadline)
    ):
        raise LoopbackGatewayError()
    canonical_policy = LoopbackGatewayPolicy.create(policy.endpoint_origin)
    if (
        policy != canonical_policy
        or policy.canonical_document != canonical_policy.canonical_document
    ):
        raise LoopbackGatewayError()
    semantic_body = _canonical(body)
    if len(semantic_body) > policy.request_body_limit:
        raise LoopbackGatewayError()
    deadline = started + policy.total_deadline_ms / 1000.0
    if private_deadline is not None:
        deadline = min(deadline, private_deadline)
    _poll_boundary(boundary, effect_possible=False)
    try:
        if _remaining(deadline) <= 0:
            raise LoopbackGatewayError()
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        if isinstance(exc, LoopbackGatewayError):
            raise
        raise LoopbackGatewayError() from None

    effect_possible = False
    total_headers = 0
    total_response_bodies = 0
    results: list[LoopbackStepResult] = []
    for step in policy.ordered_steps:
        stream: socket.socket | None = None
        primary: BaseException | None = None
        response_value: object = _NO_RESPONSE
        response_canonical = b""
        request_body = b""
        header_length = 0
        wire_body_length = 0
        try:
            _poll_boundary(boundary, effect_possible=effect_possible)
            stream = socket.socket(policy.family, socket.SOCK_STREAM)
            stream = _connected_stream(
                policy,
                stream,
                deadline=deadline,
                boundary=boundary,
                effect_possible=effect_possible,
            )
            request, request_body = _http_request(policy, step, semantic_body)
            pending = memoryview(request)
            while pending:
                _poll_boundary(boundary, effect_possible=effect_possible)
                _wait_socket(
                    stream,
                    write=True,
                    deadline=deadline,
                    boundary=boundary,
                    effect_possible=effect_possible,
                )
                effect_possible = True
                try:
                    sent = stream.send(pending)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    raise LoopbackGatewayIndeterminate() from None
                if sent <= 0:
                    raise LoopbackGatewayIndeterminate()
                pending = pending[sent:]
            response = bytearray()
            maximum = step.response_header_limit + step.response_body_limit
            while True:
                _poll_boundary(boundary, effect_possible=True)
                _wait_socket(
                    stream,
                    write=False,
                    deadline=deadline,
                    boundary=boundary,
                    effect_possible=True,
                )
                try:
                    chunk = stream.recv(min(64 * 1024, maximum + 1 - len(response)))
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    raise LoopbackGatewayIndeterminate() from None
                if not chunk:
                    break
                response.extend(chunk)
                marker_index = response.find(b"\r\n\r\n")
                if (
                    len(response) > maximum
                    or marker_index < 0
                    and len(response) > step.response_header_limit
                    or marker_index >= 0
                    and marker_index + 4 > step.response_header_limit
                ):
                    raise LoopbackGatewayIndeterminate()
            try:
                response_value, header_length, wire_body_length, response_canonical = (
                    _parse_http_response(bytes(response))
                )
            except LoopbackGatewayError:
                raise LoopbackGatewayIndeterminate() from None
            total_headers += header_length
            total_response_bodies += wire_body_length
            if (
                total_headers > policy.aggregate_response_header_limit
                or total_response_bodies > policy.response_body_limit
            ):
                raise LoopbackGatewayIndeterminate()
            _poll_boundary(boundary, effect_possible=True)
        except BaseException as exc:
            primary = exc

        close_failure: BaseException | None = None
        if stream is not None:
            try:
                stream.close()
            except BaseException as exc:
                close_failure = exc
        if close_failure is not None:
            fatal = (
                primary
                if primary is not None and not isinstance(primary, Exception)
                else close_failure
                if not isinstance(close_failure, Exception)
                else None
            )
            if fatal is not None:
                try:
                    fatal.add_note("loopback socket cleanup outcome is indeterminate")
                except BaseException:
                    pass
                raise fatal from None
            raise LoopbackGatewayIndeterminate() from None
        if primary is not None:
            raise _normalize_failure(primary, effect_possible=effect_possible) from None
        try:
            challenge = os.urandom(32).hex()
        except BaseException as exc:
            raise _normalize_failure(exc, effect_possible=effect_possible) from None
        if response_value is _NO_RESPONSE or len(challenge) != 64:
            raise LoopbackGatewayIndeterminate()
        results.append(
            LoopbackStepResult(
                index=step.index,
                step_policy_hash=step.content_hash,
                request_body_present=step.body_present,
                request_body_hash=hashlib.sha256(request_body).hexdigest(),
                request_body_length=len(request_body),
                response_body=response_value,
                response_body_hash=hashlib.sha256(response_canonical).hexdigest(),
                response_body_length=len(response_canonical),
                response_challenge=challenge,
            )
        )
    try:
        if _remaining(deadline) <= 0:
            raise LoopbackGatewayIndeterminate()
    except BaseException as exc:
        raise _normalize_failure(exc, effect_possible=effect_possible) from None
    _poll_boundary(boundary, effect_possible=True)
    if len(results) != policy.plan_count:
        raise LoopbackGatewayIndeterminate()
    return (results[0], results[1])


__all__ = (
    "LoopbackGatewayError",
    "LoopbackGatewayIndeterminate",
    "LoopbackGatewayPolicy",
    "LoopbackGatewayStopped",
    "LoopbackStepPolicy",
    "LoopbackStepResult",
    "MAX_LOOPBACK_RESPONSE_HEADER_BYTES",
    "MAX_LOOPBACK_RESPONSE_HEADERS_TOTAL_BYTES",
    "code_owned_no_telemetry_branch_hash",
    "execute_loopback_exchange",
    "parse_loopback_http_response",
)
