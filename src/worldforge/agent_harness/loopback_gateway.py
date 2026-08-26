"""Exact-origin, parent-owned, one-shot HTTP loopback gateway."""

from __future__ import annotations

import errno
import hashlib
import json
import math
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
    canonical_loopback_json,
)

MAX_LOOPBACK_RESPONSE_HEADER_BYTES = 8 * 1024
_PATH = "/worldforge/v1/loopback-probe"
_TOTAL_DEADLINE_MS = 2_000
_ORIGIN_RE = re.compile(r"^http://(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$")
_POLICY_FORMAT = "world-forge.private.parent_loopback_gateway_policy"
_POLICY_VERSION = 1
_NO_TELEMETRY_FORMAT = "world-forge.private.code_owned_no_telemetry_branch"
_NO_TELEMETRY_VERSION = 1
_POLL_SECONDS = 0.01
_NO_EXCHANGE_RESULT = object()


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
        values = {
            "endpoint_origin": endpoint_origin,
            "family": int(family),
            "format": _POLICY_FORMAT,
            "format_version": _POLICY_VERSION,
            "host": host,
            "method": "POST",
            "path": _PATH,
            "port": port,
            "request_body_limit": MAX_LOOPBACK_REQUEST_BODY_BYTES,
            "response_body_limit": MAX_LOOPBACK_RESPONSE_BODY_BYTES,
            "response_header_limit": MAX_LOOPBACK_RESPONSE_HEADER_BYTES,
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
                "scope": "deterministic_loopback_probe_only",
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


def parse_loopback_http_response(response: object) -> object:
    if type(response) is not bytes:
        raise LoopbackGatewayError()
    if b"\n" in response.replace(b"\r\n", b""):
        raise LoopbackGatewayError()
    marker = b"\r\n\r\n"
    if response.count(marker) != 1:
        raise LoopbackGatewayError()
    raw_headers, body = response.split(marker, 1)
    if len(raw_headers) + len(marker) > MAX_LOOPBACK_RESPONSE_HEADER_BYTES:
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
        )
        if _canonical(value) != body:
            raise ValueError
        return value
    except Exception:
        raise LoopbackGatewayError() from None


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _poll_boundary(boundary: Callable[[], str | None], *, after_write: bool) -> None:
    try:
        reason = boundary()
    except BaseException as exc:
        if not isinstance(exc, Exception):
            if after_write:
                try:
                    exc.add_note("loopback exchange outcome is indeterminate after request bytes")
                except BaseException:
                    pass
            raise
        if after_write:
            raise LoopbackGatewayIndeterminate() from None
        raise
    if reason is not None:
        if after_write:
            raise LoopbackGatewayIndeterminate()
        raise LoopbackGatewayStopped(reason)


def _wait_socket(
    stream: socket.socket,
    *,
    write: bool,
    deadline: float,
    boundary: Callable[[], str | None],
    after_write: bool,
) -> None:
    while True:
        _poll_boundary(boundary, after_write=after_write)
        remaining = _remaining(deadline)
        if remaining <= 0:
            if after_write:
                raise LoopbackGatewayIndeterminate()
            raise LoopbackGatewayError()
        timeout = min(_POLL_SECONDS, remaining)
        try:
            readable, writable, exceptional = select.select(
                [] if write else [stream], [stream] if write else [], [stream], timeout
            )
        except InterruptedError:
            continue
        except Exception:
            if after_write:
                raise LoopbackGatewayIndeterminate() from None
            raise LoopbackGatewayError() from None
        if exceptional:
            if after_write:
                raise LoopbackGatewayIndeterminate()
            raise LoopbackGatewayError()
        if (write and writable) or (not write and readable):
            return


def _http_request(policy: LoopbackGatewayPolicy, body: object) -> bytes:
    encoded = _canonical(body)
    if len(encoded) > policy.request_body_limit:
        raise LoopbackGatewayError()
    host = (
        f"[{policy.host}]:{policy.port}"
        if policy.family == socket.AF_INET6
        else (f"{policy.host}:{policy.port}")
    )
    headers = (
        f"POST {policy.path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/json\r\n"
        "Accept: application/json\r\n"
        f"Content-Length: {len(encoded)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    return headers + encoded


def execute_loopback_exchange(
    policy: object,
    body: object,
    *,
    boundary: Callable[[], str | None],
    started: float,
    private_deadline: float | None = None,
) -> object:
    """Perform one nonblocking numeric-loopback exchange in the calling parent."""

    if type(policy) is not LoopbackGatewayPolicy or not callable(boundary):
        raise LoopbackGatewayError()
    if type(started) is not float or not math.isfinite(started):
        raise LoopbackGatewayError()
    if private_deadline is not None and (
        type(private_deadline) is not float or not math.isfinite(private_deadline)
    ):
        raise LoopbackGatewayError()
    # Recreate from the exact authority to reject ordinary forged dataclass values.
    canonical = LoopbackGatewayPolicy.create(policy.endpoint_origin)
    if policy != canonical or policy.canonical_document != canonical.canonical_document:
        raise LoopbackGatewayError()
    request = _http_request(policy, body)
    policy_deadline = started + policy.total_deadline_ms / 1000.0
    deadline = (
        policy_deadline if private_deadline is None else min(policy_deadline, private_deadline)
    )
    _poll_boundary(boundary, after_write=False)
    try:
        expired = _remaining(deadline) <= 0
    except BaseException as exc:
        if isinstance(exc, Exception):
            raise LoopbackGatewayError() from None
        raise
    if expired:
        raise LoopbackGatewayError()
    stream: socket.socket | None = None
    after_write = False
    result: object = _NO_EXCHANGE_RESULT
    primary: BaseException | None = None
    try:
        stream = socket.socket(policy.family, socket.SOCK_STREAM)
        stream.setblocking(False)
        address: tuple[object, ...]
        if policy.family == socket.AF_INET:
            address = (policy.host, policy.port)
        else:
            address = (policy.host, policy.port, 0, 0)
        code = stream.connect_ex(address)
        if code not in {0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR}:
            raise LoopbackGatewayError()
        if code != 0:
            _wait_socket(
                stream,
                write=True,
                deadline=deadline,
                boundary=boundary,
                after_write=False,
            )
            error = stream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if error != 0:
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
        pending = memoryview(request)
        while pending:
            _poll_boundary(boundary, after_write=after_write)
            _wait_socket(
                stream,
                write=True,
                deadline=deadline,
                boundary=boundary,
                after_write=after_write,
            )
            try:
                sent = stream.send(pending)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                if after_write:
                    raise LoopbackGatewayIndeterminate() from None
                raise LoopbackGatewayError() from None
            if sent <= 0:
                if after_write:
                    raise LoopbackGatewayIndeterminate()
                raise LoopbackGatewayError()
            after_write = True
            pending = pending[sent:]
        response = bytearray()
        maximum = policy.response_header_limit + policy.response_body_limit
        while True:
            _poll_boundary(boundary, after_write=True)
            _wait_socket(
                stream,
                write=False,
                deadline=deadline,
                boundary=boundary,
                after_write=True,
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
                and len(response) > policy.response_header_limit
                or marker_index >= 0
                and marker_index + 4 > policy.response_header_limit
            ):
                raise LoopbackGatewayIndeterminate()
        try:
            result = parse_loopback_http_response(bytes(response))
        except LoopbackGatewayError:
            raise LoopbackGatewayIndeterminate() from None
        _poll_boundary(boundary, after_write=True)
    except BaseException as exc:
        primary = exc

    close_uncertain = False
    if stream is not None:
        try:
            stream.close()
        except BaseException:
            close_uncertain = True
    if close_uncertain:
        if primary is not None and not isinstance(primary, Exception):
            try:
                primary.add_note("loopback socket cleanup outcome is indeterminate")
            except BaseException:
                pass
            raise primary from None
        raise LoopbackGatewayIndeterminate() from None
    if primary is not None:
        if isinstance(
            primary,
            (LoopbackGatewayError, LoopbackGatewayStopped, LoopbackGatewayIndeterminate),
        ):
            raise primary from None
        if isinstance(primary, Exception):
            if after_write:
                raise LoopbackGatewayIndeterminate() from None
            raise LoopbackGatewayError() from None
        raise primary from None
    try:
        expired = _remaining(deadline) <= 0
    except BaseException as exc:
        if isinstance(exc, Exception):
            raise LoopbackGatewayIndeterminate() from None
        try:
            exc.add_note("loopback exchange outcome is indeterminate after request bytes")
        except BaseException:
            pass
        raise
    if expired:
        raise LoopbackGatewayIndeterminate()
    _poll_boundary(boundary, after_write=True)
    if result is _NO_EXCHANGE_RESULT:
        raise LoopbackGatewayIndeterminate()
    return result


__all__ = (
    "LoopbackGatewayError",
    "LoopbackGatewayIndeterminate",
    "LoopbackGatewayPolicy",
    "LoopbackGatewayStopped",
    "MAX_LOOPBACK_RESPONSE_HEADER_BYTES",
    "code_owned_no_telemetry_branch_hash",
    "execute_loopback_exchange",
    "parse_loopback_http_response",
)
