"""Authenticated side-band v2 framing for one fixed ordered loopback plan."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from dataclasses import dataclass

MAX_LOOPBACK_REQUEST_BODY_BYTES = 8 * 1024
MAX_LOOPBACK_RESPONSE_BODY_BYTES = 64 * 1024
MAX_LOOPBACK_REQUEST_FRAME_BYTES = 16 * 1024
MAX_LOOPBACK_RESPONSE_FRAME_BYTES = 80 * 1024
_REQUEST_FORMAT = "world-forge.private.loopback_gateway_request"
_RESPONSE_FORMAT = "world-forge.private.loopback_gateway_response"
_CONTEXT_FORMAT = "world-forge.private.loopback_gateway_context"
_CHAIN_SEED_FORMAT = "world-forge.private.loopback_gateway_chain_seed"
_CHAIN_LINK_FORMAT = "world-forge.private.loopback_gateway_chain_link"
_TERMINAL_FORMAT = "world-forge.private.loopback_gateway_terminal_chain"
_FORMAT_VERSION = 2
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
class LoopbackStepResult:
    index: int
    step_policy_hash: str
    request_body_present: bool
    request_body_hash: str
    request_body_length: int
    response_body: object
    response_body_hash: str
    response_body_length: int
    response_challenge: str


@dataclass(frozen=True, slots=True)
class ParsedLoopbackFrame:
    body: object
    body_hash: str
    body_length: int
    response_challenge: str | None = None
    exchange_hash: str | None = None
    steps: tuple[dict[str, object], ...] = ()
    completed_count: int | None = None
    terminal_chain_hash: str | None = None


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
    if type(value) is float and math.isfinite(value):
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


def _decode(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            parse_int=_parse_int,
            parse_float=_parse_float,
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


def _require_count(value: object) -> int:
    if type(value) is not int or value != 2:
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


def _require_step_hashes(value: object) -> tuple[str, str]:
    if type(value) is not tuple or len(value) != 2:
        raise LoopbackProtocolError()
    return (_require_hash(value[0]), _require_hash(value[1]))


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


def _correlation_values(
    *,
    nonce: object,
    runtime: object,
    original_request_hash: object,
    gateway_policy_hash: object,
    gateway_plan_hash: object,
    gateway_plan_count: object,
) -> dict[str, object]:
    return {
        "gateway_plan_count": _require_count(gateway_plan_count),
        "gateway_plan_hash": _require_hash(gateway_plan_hash),
        "gateway_policy_hash": _require_hash(gateway_policy_hash),
        "nonce": _require_hash(nonce),
        "original_request_hash": _require_hash(original_request_hash),
        "runtime": _require_runtime(runtime),
    }


def _request_document(
    body: object,
    *,
    key: bytes,
    **correlation: object,
) -> dict[str, object]:
    checked_key = _require_key(key)
    closed_body, body_bytes, body_hash = _body_fields(body, maximum=MAX_LOOPBACK_REQUEST_BODY_BYTES)
    document: dict[str, object] = {
        "body": closed_body,
        "body_hash": body_hash,
        "body_length": len(body_bytes),
        "format": _REQUEST_FORMAT,
        "format_version": _FORMAT_VERSION,
        **_correlation_values(**correlation),
        "sequence": 0,
    }
    document["mac"] = hmac.new(
        checked_key, canonical_loopback_json(document), hashlib.sha256
    ).hexdigest()
    return document


def _context_document(*, key: bytes, **correlation: object) -> dict[str, object]:
    checked_key = _require_key(key)
    document: dict[str, object] = {
        "format": _CONTEXT_FORMAT,
        "format_version": _FORMAT_VERSION,
        **_correlation_values(**correlation),
        "sequence": 0,
    }
    document["mac"] = hmac.new(
        checked_key, canonical_loopback_json(document), hashlib.sha256
    ).hexdigest()
    return document


def build_loopback_context_frame(**correlation: object) -> bytes:
    correlation.pop("gateway_step_policy_hashes", None)
    return _frame(
        canonical_loopback_json(_context_document(**correlation)),  # type: ignore[arg-type]
        maximum=MAX_LOOPBACK_REQUEST_FRAME_BYTES,
    )


def _validate_signed_document(
    document: dict[str, object],
    *,
    key: bytes,
    expected_fields: set[str],
    format_name: str,
    correlation: dict[str, object],
) -> None:
    if set(document) != expected_fields:
        raise LoopbackProtocolError()
    supplied = _require_hash(document["mac"])
    unsigned = {name: value for name, value in document.items() if name != "mac"}
    expected = hmac.new(key, canonical_loopback_json(unsigned), hashlib.sha256).hexdigest()
    expected_correlation = _correlation_values(**correlation)
    if (
        not hmac.compare_digest(supplied, expected)
        or document["format"] != format_name
        or type(document["format_version"]) is not int
        or document["format_version"] != _FORMAT_VERSION
        or type(document["sequence"]) is not int
        or document["sequence"] != 0
        or any(document[name] != value for name, value in expected_correlation.items())
    ):
        raise LoopbackProtocolError()


_CORRELATION_FIELDS = {
    "gateway_plan_count",
    "gateway_plan_hash",
    "gateway_policy_hash",
    "nonce",
    "original_request_hash",
    "runtime",
}


def parse_loopback_context_frame(frame: object, **correlation: object) -> None:
    checked_key = _require_key(correlation.pop("key", None))
    correlation.pop("gateway_step_policy_hashes", None)
    document = _decode(_extract(frame, maximum=MAX_LOOPBACK_REQUEST_FRAME_BYTES))
    _validate_signed_document(
        document,
        key=checked_key,
        expected_fields={"format", "format_version", "mac", "sequence"} | _CORRELATION_FIELDS,
        format_name=_CONTEXT_FORMAT,
        correlation=correlation,
    )


def build_loopback_request_frame(body: object, **correlation: object) -> bytes:
    correlation.pop("gateway_step_policy_hashes", None)
    document = _request_document(body, **correlation)  # type: ignore[arg-type]
    return _frame(canonical_loopback_json(document), maximum=MAX_LOOPBACK_REQUEST_FRAME_BYTES)


def parse_loopback_request_frame(frame: object, **correlation: object) -> ParsedLoopbackFrame:
    checked_key = _require_key(correlation.pop("key", None))
    correlation.pop("gateway_step_policy_hashes", None)
    document = _decode(_extract(frame, maximum=MAX_LOOPBACK_REQUEST_FRAME_BYTES))
    _validate_signed_document(
        document,
        key=checked_key,
        expected_fields={
            "body",
            "body_hash",
            "body_length",
            "format",
            "format_version",
            "mac",
            "sequence",
        }
        | _CORRELATION_FIELDS,
        format_name=_REQUEST_FORMAT,
        correlation=correlation,
    )
    body, body_bytes, body_hash = _body_fields(
        document["body"], maximum=MAX_LOOPBACK_REQUEST_BODY_BYTES
    )
    if (
        type(document["body_length"]) is not int
        or document["body_length"] != len(body_bytes)
        or document["body_hash"] != body_hash
    ):
        raise LoopbackProtocolError()
    return ParsedLoopbackFrame(body, body_hash, len(body_bytes))


def _chain_seed(key: bytes, correlation: dict[str, object]) -> str:
    document = {
        "format": _CHAIN_SEED_FORMAT,
        "format_version": _FORMAT_VERSION,
        **_correlation_values(**correlation),
    }
    return hmac.new(key, canonical_loopback_json(document), hashlib.sha256).hexdigest()


def _build_step_record(
    result: LoopbackStepResult,
    *,
    index: int,
    expected_policy_hash: str,
    prior_chain_hash: str,
    key: bytes,
    correlation: dict[str, object],
) -> tuple[dict[str, object], str]:
    if type(result) is not LoopbackStepResult:
        raise LoopbackProtocolError()
    response_body, response_bytes, response_hash = _body_fields(
        result.response_body, maximum=MAX_LOOPBACK_RESPONSE_BODY_BYTES
    )
    if (
        type(result.index) is not int
        or result.index != index
        or result.step_policy_hash != expected_policy_hash
        or type(result.request_body_present) is not bool
        or result.request_body_present is not (index == 1)
        or result.request_body_hash != _require_hash(result.request_body_hash)
        or type(result.request_body_length) is not int
        or result.request_body_length < 0
        or (
            index == 0
            and (
                result.request_body_length != 0
                or result.request_body_hash != hashlib.sha256(b"").hexdigest()
            )
        )
        or (index == 1 and not 1 <= result.request_body_length <= MAX_LOOPBACK_REQUEST_BODY_BYTES)
        or result.response_body_hash != response_hash
        or type(result.response_body_length) is not int
        or result.response_body_length != len(response_bytes)
    ):
        raise LoopbackProtocolError()
    base: dict[str, object] = {
        "index": index,
        "prior_chain_hash": _require_hash(prior_chain_hash),
        "request_body_hash": result.request_body_hash,
        "request_body_length": result.request_body_length,
        "request_body_present": result.request_body_present,
        "response_body": response_body,
        "response_body_hash": response_hash,
        "response_body_length": len(response_bytes),
        "response_challenge": _require_hash(result.response_challenge),
        "step_policy_hash": expected_policy_hash,
    }
    transcript_hash = hashlib.sha256(canonical_loopback_json(base)).hexdigest()
    with_transcript = {**base, "step_transcript_hash": transcript_hash}
    step_mac = hmac.new(key, canonical_loopback_json(with_transcript), hashlib.sha256).hexdigest()
    link = {
        "format": _CHAIN_LINK_FORMAT,
        "format_version": _FORMAT_VERSION,
        "gateway_plan_count": correlation["gateway_plan_count"],
        "gateway_plan_hash": correlation["gateway_plan_hash"],
        "index": index,
        "prior_chain_hash": prior_chain_hash,
        "step_mac": step_mac,
        "step_transcript_hash": transcript_hash,
    }
    cumulative = hmac.new(key, canonical_loopback_json(link), hashlib.sha256).hexdigest()
    return (
        {**with_transcript, "step_mac": step_mac, "cumulative_chain_hash": cumulative},
        cumulative,
    )


def _terminal_hash(key: bytes, correlation: dict[str, object], cumulative: str) -> str:
    terminal = {
        "completed_count": correlation["gateway_plan_count"],
        "cumulative_chain_hash": cumulative,
        "format": _TERMINAL_FORMAT,
        "format_version": _FORMAT_VERSION,
        "gateway_plan_count": correlation["gateway_plan_count"],
        "gateway_plan_hash": correlation["gateway_plan_hash"],
    }
    return hmac.new(key, canonical_loopback_json(terminal), hashlib.sha256).hexdigest()


def build_loopback_response_frame(results: object, **correlation: object) -> bytes:
    checked_key = _require_key(correlation.pop("key", None))
    step_hashes = _require_step_hashes(correlation.pop("gateway_step_policy_hashes", None))
    checked_correlation = _correlation_values(**correlation)
    if type(results) is not tuple or len(results) != checked_correlation["gateway_plan_count"]:
        raise LoopbackProtocolError()
    prior = _chain_seed(checked_key, checked_correlation)
    records: list[dict[str, object]] = []
    response_total = 0
    challenges: set[str] = set()
    for index, result in enumerate(results):
        record, prior = _build_step_record(
            result,
            index=index,
            expected_policy_hash=step_hashes[index],
            prior_chain_hash=prior,
            key=checked_key,
            correlation=checked_correlation,
        )
        response_total += record["response_body_length"]  # type: ignore[operator]
        if response_total > MAX_LOOPBACK_RESPONSE_BODY_BYTES:
            raise LoopbackProtocolError()
        if result.response_challenge in challenges:
            raise LoopbackProtocolError()
        challenges.add(result.response_challenge)
        records.append(record)
    terminal_hash = _terminal_hash(checked_key, checked_correlation, prior)
    document: dict[str, object] = {
        "completed_count": len(records),
        "format": _RESPONSE_FORMAT,
        "format_version": _FORMAT_VERSION,
        **checked_correlation,
        "sequence": 0,
        "steps": records,
        "terminal_chain_hash": terminal_hash,
    }
    document["mac"] = hmac.new(
        checked_key, canonical_loopback_json(document), hashlib.sha256
    ).hexdigest()
    return _frame(canonical_loopback_json(document), maximum=MAX_LOOPBACK_RESPONSE_FRAME_BYTES)


def parse_loopback_response_frame(frame: object, **correlation: object) -> ParsedLoopbackFrame:
    checked_key = _require_key(correlation.pop("key", None))
    step_hashes = _require_step_hashes(correlation.pop("gateway_step_policy_hashes", None))
    document = _decode(_extract(frame, maximum=MAX_LOOPBACK_RESPONSE_FRAME_BYTES))
    _validate_signed_document(
        document,
        key=checked_key,
        expected_fields={
            "completed_count",
            "format",
            "format_version",
            "mac",
            "sequence",
            "steps",
            "terminal_chain_hash",
        }
        | _CORRELATION_FIELDS,
        format_name=_RESPONSE_FORMAT,
        correlation=correlation,
    )
    if (
        type(document["completed_count"]) is not int
        or document["completed_count"] != 2
        or type(document["steps"]) is not list
        or len(document["steps"]) != 2
    ):
        raise LoopbackProtocolError()
    checked_correlation = _correlation_values(**correlation)
    prior = _chain_seed(checked_key, checked_correlation)
    checked_records: list[dict[str, object]] = []
    bodies: list[object] = []
    response_total = 0
    challenges: set[str] = set()
    for index, supplied in enumerate(document["steps"]):
        if type(supplied) is not dict or set(supplied) != {
            "cumulative_chain_hash",
            "index",
            "prior_chain_hash",
            "request_body_hash",
            "request_body_length",
            "request_body_present",
            "response_body",
            "response_body_hash",
            "response_body_length",
            "response_challenge",
            "step_mac",
            "step_policy_hash",
            "step_transcript_hash",
        }:
            raise LoopbackProtocolError()
        reconstructed = LoopbackStepResult(
            index=supplied["index"],  # type: ignore[arg-type]
            step_policy_hash=supplied["step_policy_hash"],  # type: ignore[arg-type]
            request_body_present=supplied["request_body_present"],  # type: ignore[arg-type]
            request_body_hash=supplied["request_body_hash"],  # type: ignore[arg-type]
            request_body_length=supplied["request_body_length"],  # type: ignore[arg-type]
            response_body=supplied["response_body"],
            response_body_hash=supplied["response_body_hash"],  # type: ignore[arg-type]
            response_body_length=supplied["response_body_length"],  # type: ignore[arg-type]
            response_challenge=supplied["response_challenge"],  # type: ignore[arg-type]
        )
        expected, cumulative = _build_step_record(
            reconstructed,
            index=index,
            expected_policy_hash=step_hashes[index],
            prior_chain_hash=prior,
            key=checked_key,
            correlation=checked_correlation,
        )
        if supplied != expected:
            raise LoopbackProtocolError()
        prior = cumulative
        response_total += reconstructed.response_body_length
        if response_total > MAX_LOOPBACK_RESPONSE_BODY_BYTES:
            raise LoopbackProtocolError()
        if reconstructed.response_challenge in challenges:
            raise LoopbackProtocolError()
        challenges.add(reconstructed.response_challenge)
        checked_records.append(dict(supplied))
        bodies.append(_snapshot(reconstructed.response_body))
    terminal_hash = _terminal_hash(checked_key, checked_correlation, prior)
    if not hmac.compare_digest(_require_hash(document["terminal_chain_hash"]), terminal_hash):
        raise LoopbackProtocolError()
    body_bytes = canonical_loopback_json(bodies)
    return ParsedLoopbackFrame(
        bodies,
        hashlib.sha256(body_bytes).hexdigest(),
        len(body_bytes),
        exchange_hash=terminal_hash,
        steps=tuple(checked_records),
        completed_count=2,
        terminal_chain_hash=terminal_hash,
    )


class LoopbackProtocolSession:
    """One-plan-request/one-combined-response replay fence per worker spawn."""

    __slots__ = ("_correlation", "_request_accepted", "_response_built")

    def __init__(self, **correlation: object) -> None:
        _require_key(correlation.get("key"))
        _require_hash(correlation.get("nonce"))
        _require_runtime(correlation.get("runtime"))
        _require_hash(correlation.get("original_request_hash"))
        _require_hash(correlation.get("gateway_policy_hash"))
        _require_hash(correlation.get("gateway_plan_hash"))
        _require_count(correlation.get("gateway_plan_count"))
        _require_step_hashes(correlation.get("gateway_step_policy_hashes"))
        self._correlation = {
            "key": bytes(correlation["key"]),  # type: ignore[arg-type]
            "nonce": str(correlation["nonce"]),
            "runtime": dict(correlation["runtime"]),  # type: ignore[arg-type]
            "original_request_hash": str(correlation["original_request_hash"]),
            "gateway_policy_hash": str(correlation["gateway_policy_hash"]),
            "gateway_plan_hash": str(correlation["gateway_plan_hash"]),
            "gateway_plan_count": int(correlation["gateway_plan_count"]),
            "gateway_step_policy_hashes": tuple(correlation["gateway_step_policy_hashes"]),
        }
        self._request_accepted = False
        self._response_built = False

    def accept_request(self, frame: object) -> ParsedLoopbackFrame:
        if self._request_accepted:
            raise LoopbackProtocolError()
        parsed = parse_loopback_request_frame(frame, **self._correlation)
        self._request_accepted = True
        return parsed

    def build_response(self, results: object) -> bytes:
        if not self._request_accepted or self._response_built:
            raise LoopbackProtocolError()
        frame = build_loopback_response_frame(results, **self._correlation)
        self._response_built = True
        return frame


__all__ = (
    "LoopbackProtocolError",
    "LoopbackProtocolSession",
    "LoopbackStepResult",
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
