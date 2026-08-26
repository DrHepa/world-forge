"""Authenticated canonical framing for the private one-shot worker boundary."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass

from .ports import (
    ArtifactProposal,
    MemoryProposal,
    ProviderTurnRequest,
    ProviderTurnResult,
    ProviderUsage,
    ToolCall,
)
from .worker_registry import (
    CONFORMANCE_RUNTIME_HASH,
    CONFORMANCE_RUNTIME_ID,
    CONFORMANCE_RUNTIME_REVISION,
    fixed_runtime_identity,
)

MAX_WORKER_REQUEST_BYTES = 256 * 1024
MAX_WORKER_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_WORKER_STDERR_BYTES = 64 * 1024
MAX_WORKER_JSON_DEPTH = 64
MAX_WORKER_HISTORY_ITEMS = 256
MAX_SAFE_INTEGER = (1 << 53) - 1
_REQUEST_FORMAT = "world-forge.private.provider_turn_request"
_RESULT_FORMAT = "world-forge.private.provider_turn_result"
_PROTOCOL_VERSION = 1
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_TOOL_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}(?:\.[a-z][a-z0-9_]{1,63})+$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")


class WorkerProtocolError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ParsedWorkerRequest:
    nonce: str
    runtime: dict[str, object]
    request_hash: str
    request: ProviderTurnRequest


def _snapshot(value: object, *, depth: int = 1, active: set[int] | None = None) -> object:
    if depth > MAX_WORKER_JSON_DEPTH:
        raise WorkerProtocolError("worker_protocol_depth_exceeded")
    if active is None:
        active = set()
    if type(value) is dict:
        identity = id(value)
        if identity in active:
            raise WorkerProtocolError("worker_protocol_invalid")
        active.add(identity)
        try:
            result: dict[str, object] = {}
            for key, item in dict.items(value):
                if type(key) is not str:
                    raise WorkerProtocolError("worker_protocol_invalid")
                result[key] = _snapshot(item, depth=depth + 1, active=active)
            return result
        finally:
            active.remove(identity)
    if type(value) is list:
        identity = id(value)
        if identity in active:
            raise WorkerProtocolError("worker_protocol_invalid")
        active.add(identity)
        try:
            return [
                _snapshot(item, depth=depth + 1, active=active) for item in list.__iter__(value)
            ]
        finally:
            active.remove(identity)
    if value is None or type(value) in {bool, str}:
        return value
    if type(value) is int and 0 <= abs(value) <= MAX_SAFE_INTEGER:
        return value
    if type(value) is float and value == value and value not in {float("inf"), -float("inf")}:
        return value
    raise WorkerProtocolError("worker_protocol_invalid")


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            _snapshot(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except WorkerProtocolError:
        raise
    except Exception:
        raise WorkerProtocolError("worker_protocol_invalid") from None


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _decode_canonical(payload: bytes) -> dict[str, object]:
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except _DuplicateKey:
        raise WorkerProtocolError("worker_protocol_duplicate_key") from None
    except Exception:
        raise WorkerProtocolError("worker_protocol_invalid") from None
    if type(document) is not dict:
        raise WorkerProtocolError("worker_protocol_invalid")
    if _canonical(document) != payload:
        raise WorkerProtocolError("worker_protocol_noncanonical")
    return document


def _extract_frame(frame: bytes, *, maximum: int) -> bytes:
    if type(frame) is not bytes or len(frame) < 4:
        raise WorkerProtocolError("worker_protocol_truncated")
    size = int.from_bytes(frame[:4], "big")
    if size > maximum:
        raise WorkerProtocolError("worker_protocol_oversized")
    if len(frame) < size + 4:
        raise WorkerProtocolError("worker_protocol_truncated")
    if len(frame) != size + 4:
        raise WorkerProtocolError("worker_protocol_trailing_bytes")
    return frame[4:]


def _frame(payload: bytes, *, maximum: int) -> bytes:
    if len(payload) > maximum:
        raise WorkerProtocolError("worker_protocol_oversized")
    return len(payload).to_bytes(4, "big") + payload


def _require_key(key: bytes) -> bytes:
    if type(key) is not bytes or len(key) != 32:
        raise WorkerProtocolError("worker_protocol_authentication_failed")
    return key


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _mac(document: dict[str, object], key: bytes) -> str:
    body = {name: value for name, value in document.items() if name != "mac"}
    return hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()


def _validate_runtime(value: object) -> dict[str, object]:
    if (
        type(value) is not dict
        or set(value) != {"id", "revision", "content_hash"}
        or type(value["id"]) is not str
        or value["id"] != CONFORMANCE_RUNTIME_ID
        or type(value["revision"]) is not int
        or value["revision"] != CONFORMANCE_RUNTIME_REVISION
        or type(value["content_hash"]) is not str
        or value["content_hash"] != CONFORMANCE_RUNTIME_HASH
    ):
        raise WorkerProtocolError("worker_protocol_runtime_mismatch")
    return fixed_runtime_identity()


def _validate_nonce(value: object) -> str:
    if type(value) is not str or _HEX_64_RE.fullmatch(value) is None:
        raise WorkerProtocolError("worker_protocol_correlation_failed")
    return value


def _validate_sha256(value: object, *, reason_code: str) -> str:
    if type(value) is not str or _HEX_64_RE.fullmatch(value) is None:
        raise WorkerProtocolError(reason_code)
    return value


def _request_payload(request: ProviderTurnRequest) -> dict[str, object]:
    if type(request) is not ProviderTurnRequest:
        raise WorkerProtocolError("worker_protocol_request_invalid")
    if (
        type(request.execution_id) is not str
        or _ID_RE.fullmatch(request.execution_id) is None
        or type(request.turn_index) is not int
        or not 0 <= request.turn_index <= 64
        or type(request.history) is not tuple
        or len(request.history) > MAX_WORKER_HISTORY_ITEMS
    ):
        raise WorkerProtocolError("worker_protocol_request_invalid")
    return {
        "execution_id": request.execution_id,
        "turn_index": request.turn_index,
        "private_input": _snapshot(request.private_input),
        "history": [_snapshot(item) for item in tuple.__iter__(request.history)],
    }


def build_request_frame(
    request: ProviderTurnRequest,
    *,
    key: bytes,
    nonce: str,
) -> bytes:
    key = _require_key(key)
    nonce = _validate_nonce(nonce)
    payload = _request_payload(request)
    document: dict[str, object] = {
        "format": _REQUEST_FORMAT,
        "format_version": _PROTOCOL_VERSION,
        "nonce": nonce,
        "request": payload,
        "request_hash": _digest(payload),
        "runtime": fixed_runtime_identity(),
    }
    document["mac"] = _mac(document, key)
    return _frame(_canonical(document), maximum=MAX_WORKER_REQUEST_BYTES)


def parse_request_frame(frame: bytes, *, key: bytes) -> ParsedWorkerRequest:
    key = _require_key(key)
    document = _decode_canonical(_extract_frame(frame, maximum=MAX_WORKER_REQUEST_BYTES))
    if set(document) != {
        "format",
        "format_version",
        "mac",
        "nonce",
        "request",
        "request_hash",
        "runtime",
    }:
        raise WorkerProtocolError("worker_protocol_request_invalid")
    if (
        document["format"] != _REQUEST_FORMAT
        or type(document["format_version"]) is not int
        or document["format_version"] != _PROTOCOL_VERSION
    ):
        raise WorkerProtocolError("worker_protocol_request_invalid")
    if type(document["mac"]) is not str or not hmac.compare_digest(
        document["mac"], _mac(document, key)
    ):
        raise WorkerProtocolError("worker_protocol_authentication_failed")
    nonce = _validate_nonce(document["nonce"])
    runtime = _validate_runtime(document["runtime"])
    payload = document["request"]
    if type(payload) is not dict or set(payload) != {
        "execution_id",
        "turn_index",
        "private_input",
        "history",
    }:
        raise WorkerProtocolError("worker_protocol_request_invalid")
    request_hash = _validate_sha256(
        document["request_hash"], reason_code="worker_protocol_hash_mismatch"
    )
    if not hmac.compare_digest(request_hash, _digest(payload)):
        raise WorkerProtocolError("worker_protocol_hash_mismatch")
    history = payload["history"]
    if type(history) is not list:
        raise WorkerProtocolError("worker_protocol_request_invalid")
    request = ProviderTurnRequest(
        execution_id=payload["execution_id"],
        turn_index=payload["turn_index"],
        private_input=payload["private_input"],
        history=tuple(history),
    )
    _request_payload(request)
    return ParsedWorkerRequest(nonce, runtime, request_hash, request)


def _usage_payload(usage: ProviderUsage) -> dict[str, object]:
    if type(usage) is not ProviderUsage:
        raise WorkerProtocolError("worker_protocol_result_invalid")
    return {
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "cached_input_tokens": usage.cached_input_tokens,
        "cost_minor_units": usage.cost_minor_units,
        "currency": usage.currency,
    }


def _exact_nonnegative(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise WorkerProtocolError("worker_protocol_result_invalid")
    return value


def _parse_usage(payload: object) -> ProviderUsage:
    if type(payload) is not dict or set(payload) != {
        "input_tokens",
        "output_tokens",
        "cached_input_tokens",
        "cost_minor_units",
        "currency",
    }:
        raise WorkerProtocolError("worker_protocol_result_invalid")
    input_tokens = _exact_nonnegative(payload["input_tokens"])
    output_tokens = _exact_nonnegative(payload["output_tokens"])
    cached_input_tokens = _exact_nonnegative(payload["cached_input_tokens"])
    if cached_input_tokens > input_tokens:
        raise WorkerProtocolError("worker_protocol_result_invalid")
    cost = payload["cost_minor_units"]
    currency = payload["currency"]
    if (cost is None) != (currency is None):
        raise WorkerProtocolError("worker_protocol_result_invalid")
    if cost is not None:
        cost = _exact_nonnegative(cost)
        if type(currency) is not str or _CURRENCY_RE.fullmatch(currency) is None:
            raise WorkerProtocolError("worker_protocol_result_invalid")
    return ProviderUsage(input_tokens, output_tokens, cached_input_tokens, cost, currency)


def _parse_result_payload(payload: object) -> ProviderTurnResult:
    if type(payload) is not dict or set(payload) != {
        "private_output",
        "usage",
        "tool_calls",
        "artifact_proposals",
        "memory_proposals",
        "completed",
    }:
        raise WorkerProtocolError("worker_protocol_result_invalid")
    if type(payload["completed"]) is not bool:
        raise WorkerProtocolError("worker_protocol_result_invalid")
    tool_values = payload["tool_calls"]
    artifact_values = payload["artifact_proposals"]
    memory_values = payload["memory_proposals"]
    if not all(type(value) is list for value in (tool_values, artifact_values, memory_values)):
        raise WorkerProtocolError("worker_protocol_result_invalid")
    if len(tool_values) > 128 or len(artifact_values) > 64 or len(memory_values) > 64:
        raise WorkerProtocolError("worker_protocol_result_invalid")
    tool_calls: list[ToolCall] = []
    for item in tool_values:
        if type(item) is not dict or set(item) != {"tool_id", "private_arguments"}:
            raise WorkerProtocolError("worker_protocol_result_invalid")
        tool_id = item["tool_id"]
        if type(tool_id) is not str or _TOOL_RE.fullmatch(tool_id) is None:
            raise WorkerProtocolError("worker_protocol_result_invalid")
        tool_calls.append(ToolCall(tool_id, item["private_arguments"]))
    artifact_proposals: list[ArtifactProposal] = []
    for item in artifact_values:
        if type(item) is not dict or set(item) != {"private_payload"}:
            raise WorkerProtocolError("worker_protocol_result_invalid")
        artifact_proposals.append(ArtifactProposal(item["private_payload"]))
    memory_proposals: list[MemoryProposal] = []
    for item in memory_values:
        if type(item) is not dict or set(item) != {"private_payload"}:
            raise WorkerProtocolError("worker_protocol_result_invalid")
        memory_proposals.append(MemoryProposal(item["private_payload"]))
    return ProviderTurnResult(
        private_output=payload["private_output"],
        usage=_parse_usage(payload["usage"]),
        tool_calls=tuple(tool_calls),
        artifact_proposals=tuple(artifact_proposals),
        memory_proposals=tuple(memory_proposals),
        completed=payload["completed"],
    )


def _result_payload(result: ProviderTurnResult) -> dict[str, object]:
    if type(result) is not ProviderTurnResult:
        raise WorkerProtocolError("worker_protocol_result_invalid")
    if (
        type(result.tool_calls) is not tuple
        or type(result.artifact_proposals) is not tuple
        or type(result.memory_proposals) is not tuple
        or type(result.completed) is not bool
    ):
        raise WorkerProtocolError("worker_protocol_result_invalid")
    payload = {
        "private_output": _snapshot(result.private_output),
        "usage": _usage_payload(result.usage),
        "tool_calls": [
            {"tool_id": call.tool_id, "private_arguments": _snapshot(call.private_arguments)}
            for call in result.tool_calls
            if type(call) is ToolCall
        ],
        "artifact_proposals": [
            {"private_payload": _snapshot(proposal.private_payload)}
            for proposal in result.artifact_proposals
            if type(proposal) is ArtifactProposal
        ],
        "memory_proposals": [
            {"private_payload": _snapshot(proposal.private_payload)}
            for proposal in result.memory_proposals
            if type(proposal) is MemoryProposal
        ],
        "completed": result.completed,
    }
    _parse_result_payload(payload)
    return payload


def build_result_frame(
    result: ProviderTurnResult,
    *,
    key: bytes,
    nonce: str,
    request_hash: str,
) -> bytes:
    key = _require_key(key)
    nonce = _validate_nonce(nonce)
    if type(request_hash) is not str or _HEX_64_RE.fullmatch(request_hash) is None:
        raise WorkerProtocolError("worker_protocol_correlation_failed")
    payload = _result_payload(result)
    # Filtering a malformed nested collection must not accidentally accept it.
    if (
        len(payload["tool_calls"]) != len(result.tool_calls)
        or len(payload["artifact_proposals"]) != len(result.artifact_proposals)
        or len(payload["memory_proposals"]) != len(result.memory_proposals)
    ):
        raise WorkerProtocolError("worker_protocol_result_invalid")
    document: dict[str, object] = {
        "format": _RESULT_FORMAT,
        "format_version": _PROTOCOL_VERSION,
        "nonce": nonce,
        "request_hash": request_hash,
        "result": payload,
        "result_hash": _digest(payload),
        "runtime": fixed_runtime_identity(),
    }
    document["mac"] = _mac(document, key)
    return _frame(_canonical(document), maximum=MAX_WORKER_RESPONSE_BYTES)


def parse_result_frame(
    frame: bytes,
    *,
    key: bytes,
    nonce: str,
    request_hash: str,
) -> ProviderTurnResult:
    key = _require_key(key)
    expected_nonce = _validate_nonce(nonce)
    expected_request_hash = _validate_sha256(
        request_hash, reason_code="worker_protocol_correlation_failed"
    )
    document = _decode_canonical(_extract_frame(frame, maximum=MAX_WORKER_RESPONSE_BYTES))
    if set(document) != {
        "format",
        "format_version",
        "mac",
        "nonce",
        "request_hash",
        "result",
        "result_hash",
        "runtime",
    }:
        raise WorkerProtocolError("worker_protocol_result_invalid")
    if (
        document["format"] != _RESULT_FORMAT
        or type(document["format_version"]) is not int
        or document["format_version"] != _PROTOCOL_VERSION
    ):
        raise WorkerProtocolError("worker_protocol_result_invalid")
    if type(document["mac"]) is not str or not hmac.compare_digest(
        document["mac"], _mac(document, key)
    ):
        raise WorkerProtocolError("worker_protocol_authentication_failed")
    response_request_hash = _validate_sha256(
        document["request_hash"], reason_code="worker_protocol_correlation_failed"
    )
    if document["nonce"] != expected_nonce or response_request_hash != expected_request_hash:
        raise WorkerProtocolError("worker_protocol_correlation_failed")
    _validate_runtime(document["runtime"])
    payload = document["result"]
    result_hash = document["result_hash"]
    if (
        type(result_hash) is not str
        or _HEX_64_RE.fullmatch(result_hash) is None
        or not hmac.compare_digest(result_hash, _digest(payload))
    ):
        raise WorkerProtocolError("worker_protocol_hash_mismatch")
    try:
        return _parse_result_payload(payload)
    except WorkerProtocolError:
        raise
    except Exception:
        raise WorkerProtocolError("worker_protocol_result_invalid") from None


__all__ = (
    "MAX_WORKER_REQUEST_BYTES",
    "MAX_WORKER_RESPONSE_BYTES",
    "MAX_WORKER_STDERR_BYTES",
    "ParsedWorkerRequest",
    "WorkerProtocolError",
    "build_request_frame",
    "build_result_frame",
    "parse_request_frame",
    "parse_result_frame",
)
