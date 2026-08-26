"""Authenticated one-shot side-band framing for the parent loopback gateway."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass

MAX_LOOPBACK_REQUEST_BODY_BYTES = 8 * 1024
MAX_LOOPBACK_RESPONSE_BODY_BYTES = 64 * 1024
MAX_LOOPBACK_REQUEST_FRAME_BYTES = 16 * 1024
MAX_LOOPBACK_RESPONSE_FRAME_BYTES = 80 * 1024
_REQUEST_FORMAT = "world-forge.private.loopback_gateway_request"
_RESPONSE_FORMAT = "world-forge.private.loopback_gateway_response"
_CONTEXT_FORMAT = "world-forge.private.loopback_gateway_context"
_FORMAT_VERSION = 1
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_RUNTIME_FIELDS = frozenset({"id", "revision", "content_hash"})
_MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_DEPTH = 64


class LoopbackProtocolError(ValueError):
    def __init__(self) -> None:
        super().__init__("loopback_protocol_invalid")


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ParsedLoopbackFrame:
    body: object
    body_hash: str
    body_length: int
    response_challenge: str | None = None
    exchange_hash: str | None = None


def _snapshot(value: object, *, depth: int = 1, active: set[int] | None = None) -> object:
    if depth > _MAX_DEPTH:
        raise LoopbackProtocolError()
    if active is None:
        active = set()
    if type(value) is dict:
        identity = id(value)
        if identity in active:
            raise LoopbackProtocolError()
        active.add(identity)
        try:
            result: dict[str, object] = {}
            for key, item in dict.items(value):
                if type(key) is not str:
                    raise LoopbackProtocolError()
                result[key] = _snapshot(item, depth=depth + 1, active=active)
            return result
        finally:
            active.remove(identity)
    if type(value) is list:
        identity = id(value)
        if identity in active:
            raise LoopbackProtocolError()
        active.add(identity)
        try:
            return [_snapshot(item, depth=depth + 1, active=active) for item in value]
        finally:
            active.remove(identity)
    if value is None or type(value) in {bool, str}:
        return value
    if type(value) is int and abs(value) <= _MAX_SAFE_INTEGER:
        return value
    if type(value) is float and value == value and value not in {float("inf"), -float("inf")}:
        return value
    raise LoopbackProtocolError()


def canonical_loopback_json(value: object) -> bytes:
    try:
        return json.dumps(
            _snapshot(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except LoopbackProtocolError:
        raise
    except Exception:
        raise LoopbackProtocolError() from None


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _decode(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        if type(value) is not dict or canonical_loopback_json(value) != payload:
            raise ValueError
        return value
    except Exception:
        raise LoopbackProtocolError() from None


def _require_hash(value: object) -> str:
    if type(value) is not str or _HEX_RE.fullmatch(value) is None:
        raise LoopbackProtocolError()
    return value


def _require_key(value: object) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise LoopbackProtocolError()
    return value


def _require_runtime(value: object) -> dict[str, object]:
    if (
        type(value) is not dict
        or frozenset(value) != _RUNTIME_FIELDS
        or type(value["id"]) is not str
        or not value["id"]
        or type(value["revision"]) is not int
        or value["revision"] < 1
    ):
        raise LoopbackProtocolError()
    _require_hash(value["content_hash"])
    return dict(value)


def _frame(payload: bytes, *, maximum: int) -> bytes:
    if len(payload) > maximum:
        raise LoopbackProtocolError()
    return len(payload).to_bytes(4, "big") + payload


def _extract(frame: object, *, maximum: int) -> bytes:
    if type(frame) is not bytes or len(frame) < 4:
        raise LoopbackProtocolError()
    size = int.from_bytes(frame[:4], "big")
    if size > maximum or len(frame) != size + 4:
        raise LoopbackProtocolError()
    return frame[4:]


def _body_fields(body: object, *, maximum: int) -> tuple[object, bytes, str]:
    closed = _snapshot(body)
    encoded = canonical_loopback_json(closed)
    if len(encoded) > maximum:
        raise LoopbackProtocolError()
    return closed, encoded, hashlib.sha256(encoded).hexdigest()


def _document(
    *,
    format_name: str,
    body: object,
    body_maximum: int,
    key: bytes,
    nonce: str,
    runtime: object,
    original_request_hash: str,
    gateway_policy_hash: str,
    response_challenge: str | None = None,
) -> dict[str, object]:
    checked_key = _require_key(key)
    checked_runtime = _require_runtime(runtime)
    closed_body, body_bytes, body_hash = _body_fields(body, maximum=body_maximum)
    document: dict[str, object] = {
        "body": closed_body,
        "body_hash": body_hash,
        "body_length": len(body_bytes),
        "format": format_name,
        "format_version": _FORMAT_VERSION,
        "gateway_policy_hash": _require_hash(gateway_policy_hash),
        "nonce": _require_hash(nonce),
        "original_request_hash": _require_hash(original_request_hash),
        "runtime": checked_runtime,
        "sequence": 0,
    }
    if format_name == _RESPONSE_FORMAT:
        document["response_challenge"] = _require_hash(response_challenge)
        document["exchange_hash"] = hashlib.sha256(canonical_loopback_json(document)).hexdigest()
    elif response_challenge is not None:
        raise LoopbackProtocolError()
    document["mac"] = hmac.new(
        checked_key,
        canonical_loopback_json(document),
        hashlib.sha256,
    ).hexdigest()
    return document


def _context_document(
    *,
    key: bytes,
    nonce: str,
    runtime: object,
    original_request_hash: str,
    gateway_policy_hash: str,
) -> dict[str, object]:
    checked_key = _require_key(key)
    document: dict[str, object] = {
        "format": _CONTEXT_FORMAT,
        "format_version": _FORMAT_VERSION,
        "gateway_policy_hash": _require_hash(gateway_policy_hash),
        "nonce": _require_hash(nonce),
        "original_request_hash": _require_hash(original_request_hash),
        "runtime": _require_runtime(runtime),
        "sequence": 0,
    }
    document["mac"] = hmac.new(
        checked_key,
        canonical_loopback_json(document),
        hashlib.sha256,
    ).hexdigest()
    return document


def build_loopback_context_frame(**correlation: object) -> bytes:
    return _frame(
        canonical_loopback_json(_context_document(**correlation)),  # type: ignore[arg-type]
        maximum=MAX_LOOPBACK_REQUEST_FRAME_BYTES,
    )


def parse_loopback_context_frame(frame: object, **correlation: object) -> None:
    checked_key = _require_key(correlation.get("key"))
    document = _decode(_extract(frame, maximum=MAX_LOOPBACK_REQUEST_FRAME_BYTES))
    if set(document) != {
        "format",
        "format_version",
        "gateway_policy_hash",
        "mac",
        "nonce",
        "original_request_hash",
        "runtime",
        "sequence",
    }:
        raise LoopbackProtocolError()
    supplied = _require_hash(document["mac"])
    unsigned = {name: value for name, value in document.items() if name != "mac"}
    expected = hmac.new(
        checked_key,
        canonical_loopback_json(unsigned),
        hashlib.sha256,
    ).hexdigest()
    if (
        not hmac.compare_digest(supplied, expected)
        or document["format"] != _CONTEXT_FORMAT
        or type(document["format_version"]) is not int
        or document["format_version"] != _FORMAT_VERSION
        or type(document["sequence"]) is not int
        or document["sequence"] != 0
        or document["nonce"] != _require_hash(correlation.get("nonce"))
        or document["runtime"] != _require_runtime(correlation.get("runtime"))
        or document["original_request_hash"]
        != _require_hash(correlation.get("original_request_hash"))
        or document["gateway_policy_hash"] != _require_hash(correlation.get("gateway_policy_hash"))
    ):
        raise LoopbackProtocolError()


def _parse(
    frame: object,
    *,
    format_name: str,
    frame_maximum: int,
    body_maximum: int,
    key: bytes,
    nonce: str,
    runtime: object,
    original_request_hash: str,
    gateway_policy_hash: str,
) -> ParsedLoopbackFrame:
    checked_key = _require_key(key)
    payload = _extract(frame, maximum=frame_maximum)
    document = _decode(payload)
    expected_fields = {
        "body",
        "body_hash",
        "body_length",
        "format",
        "format_version",
        "gateway_policy_hash",
        "mac",
        "nonce",
        "original_request_hash",
        "runtime",
        "sequence",
    }
    if format_name == _RESPONSE_FORMAT:
        expected_fields.update({"exchange_hash", "response_challenge"})
    if set(document) != expected_fields:
        raise LoopbackProtocolError()
    supplied_mac = _require_hash(document["mac"])
    unsigned = {name: value for name, value in document.items() if name != "mac"}
    expected_mac = hmac.new(
        checked_key,
        canonical_loopback_json(unsigned),
        hashlib.sha256,
    ).hexdigest()
    expected_runtime = _require_runtime(runtime)
    body, body_bytes, body_hash = _body_fields(document["body"], maximum=body_maximum)
    response_challenge = None
    exchange_hash = None
    if format_name == _RESPONSE_FORMAT:
        response_challenge = _require_hash(document["response_challenge"])
        exchange_hash = _require_hash(document["exchange_hash"])
        exchange_document = {
            name: value for name, value in document.items() if name not in {"exchange_hash", "mac"}
        }
        if not hmac.compare_digest(
            exchange_hash,
            hashlib.sha256(canonical_loopback_json(exchange_document)).hexdigest(),
        ):
            raise LoopbackProtocolError()
    if (
        not hmac.compare_digest(supplied_mac, expected_mac)
        or type(document["format"]) is not str
        or document["format"] != format_name
        or type(document["format_version"]) is not int
        or document["format_version"] != _FORMAT_VERSION
        or type(document["sequence"]) is not int
        or document["sequence"] != 0
        or document["nonce"] != _require_hash(nonce)
        or document["runtime"] != expected_runtime
        or document["original_request_hash"] != _require_hash(original_request_hash)
        or document["gateway_policy_hash"] != _require_hash(gateway_policy_hash)
        or type(document["body_length"]) is not int
        or document["body_length"] != len(body_bytes)
        or document["body_hash"] != body_hash
    ):
        raise LoopbackProtocolError()
    return ParsedLoopbackFrame(
        body,
        body_hash,
        len(body_bytes),
        response_challenge,
        exchange_hash,
    )


def build_loopback_request_frame(body: object, **correlation: object) -> bytes:
    document = _document(
        format_name=_REQUEST_FORMAT,
        body=body,
        body_maximum=MAX_LOOPBACK_REQUEST_BODY_BYTES,
        **correlation,  # type: ignore[arg-type]
    )
    return _frame(canonical_loopback_json(document), maximum=MAX_LOOPBACK_REQUEST_FRAME_BYTES)


def parse_loopback_request_frame(frame: object, **correlation: object) -> ParsedLoopbackFrame:
    return _parse(
        frame,
        format_name=_REQUEST_FORMAT,
        frame_maximum=MAX_LOOPBACK_REQUEST_FRAME_BYTES,
        body_maximum=MAX_LOOPBACK_REQUEST_BODY_BYTES,
        **correlation,  # type: ignore[arg-type]
    )


def build_loopback_response_frame(
    body: object,
    *,
    response_challenge: object,
    **correlation: object,
) -> bytes:
    document = _document(
        format_name=_RESPONSE_FORMAT,
        body=body,
        body_maximum=MAX_LOOPBACK_RESPONSE_BODY_BYTES,
        response_challenge=response_challenge,  # type: ignore[arg-type]
        **correlation,  # type: ignore[arg-type]
    )
    return _frame(canonical_loopback_json(document), maximum=MAX_LOOPBACK_RESPONSE_FRAME_BYTES)


def parse_loopback_response_frame(frame: object, **correlation: object) -> ParsedLoopbackFrame:
    return _parse(
        frame,
        format_name=_RESPONSE_FORMAT,
        frame_maximum=MAX_LOOPBACK_RESPONSE_FRAME_BYTES,
        body_maximum=MAX_LOOPBACK_RESPONSE_BODY_BYTES,
        **correlation,  # type: ignore[arg-type]
    )


class LoopbackProtocolSession:
    """One-request/one-response replay fence for a single worker spawn."""

    __slots__ = ("_correlation", "_request_accepted", "_response_built")

    def __init__(self, **correlation: object) -> None:
        # Validate and snapshot correlation before any state transition.
        _require_key(correlation.get("key"))
        _require_hash(correlation.get("nonce"))
        _require_runtime(correlation.get("runtime"))
        _require_hash(correlation.get("original_request_hash"))
        _require_hash(correlation.get("gateway_policy_hash"))
        self._correlation = {
            "key": bytes(correlation["key"]),  # type: ignore[arg-type]
            "nonce": str(correlation["nonce"]),
            "runtime": dict(correlation["runtime"]),  # type: ignore[arg-type]
            "original_request_hash": str(correlation["original_request_hash"]),
            "gateway_policy_hash": str(correlation["gateway_policy_hash"]),
        }
        self._request_accepted = False
        self._response_built = False

    def accept_request(self, frame: object) -> ParsedLoopbackFrame:
        if self._request_accepted:
            raise LoopbackProtocolError()
        parsed = parse_loopback_request_frame(frame, **self._correlation)
        self._request_accepted = True
        return parsed

    def build_response(self, body: object, *, response_challenge: object) -> bytes:
        if not self._request_accepted or self._response_built:
            raise LoopbackProtocolError()
        frame = build_loopback_response_frame(
            body,
            response_challenge=response_challenge,
            **self._correlation,
        )
        self._response_built = True
        return frame


__all__ = (
    "LoopbackProtocolError",
    "LoopbackProtocolSession",
    "MAX_LOOPBACK_REQUEST_BODY_BYTES",
    "MAX_LOOPBACK_REQUEST_FRAME_BYTES",
    "MAX_LOOPBACK_RESPONSE_BODY_BYTES",
    "MAX_LOOPBACK_RESPONSE_FRAME_BYTES",
    "build_loopback_context_frame",
    "build_loopback_request_frame",
    "build_loopback_response_frame",
    "canonical_loopback_json",
    "parse_loopback_context_frame",
    "parse_loopback_request_frame",
    "parse_loopback_response_frame",
)
