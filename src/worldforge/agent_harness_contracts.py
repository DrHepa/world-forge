"""Closed, pre-execution Agent Harness public contract validation."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

AGENT_HARNESS_VERSION = 1
AGENT_WORKER_ACTIVATION_FORMAT = "world-forge.agent_worker_activation"
AGENT_CAPABILITY_GRANT_FORMAT = "world-forge.agent_capability_grant"
MAX_AGENT_HARNESS_DOCUMENT_BYTES = 1024 * 1024
MAX_AGENT_HARNESS_JSON_DEPTH = 64
MAX_AGENT_HARNESS_TOOL_ID_LENGTH = 1024
MAX_SAFE_INTEGER = 9_007_199_254_740_991

_CAPABILITIES = frozenset(
    {
        "project.read",
        "artifact.read",
        "artifact.propose",
        "tool.invoke",
        "memory.read",
        "memory.propose",
    }
)
_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TOOL_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}(?:\.[a-z][a-z0-9_]{1,63})+$")
_ACTIVATION_FIELDS = frozenset(
    {
        "format",
        "format_version",
        "activation_id",
        "execution_id",
        "role",
        "work_order",
        "runtime",
        "prompt",
        "input",
        "context_mode",
        "requested_capability_ids",
        "requested_tool_ids",
        "content_hash",
    }
)
_GRANT_FIELDS = frozenset(
    {
        "format",
        "format_version",
        "grant_id",
        "execution_id",
        "activation",
        "role",
        "work_order",
        "runtime",
        "policy",
        "role_capability_ids",
        "role_tool_ids",
        "effective_capability_ids",
        "effective_tool_ids",
        "content_hash",
    }
)
_BINDING_FIELDS = frozenset({"id", "revision", "content_hash"})
_WORK_ORDER_FIELDS = frozenset({"id", "revision", "content_hash", "capability_ids", "tool_ids"})
_IDENTITY_FIELDS = frozenset({"id", "content_hash"})
_POLICY_FIELDS = frozenset({"capability_ids", "tool_ids"})


class AgentHarnessContractError(ValueError):
    """Raised when a closed Agent Harness document is invalid."""

    def __init__(self, detail: str, *, reason_code: str = "agent_harness_invalid") -> None:
        if reason_code != "agent_harness_invalid":
            raise ValueError("unknown Agent Harness contract reason code")
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class AgentHarnessDocuments:
    activation: dict[str, Any]
    grant: dict[str, Any]


def _error(detail: str) -> None:
    raise AgentHarnessContractError(detail)


def _normalize_json_numbers(value: object, *, context: str) -> object:
    active: set[int] = set()

    def normalize(current: object, depth: int) -> object:
        if isinstance(current, (dict, list)):
            if depth > MAX_AGENT_HARNESS_JSON_DEPTH:
                _error(f"{context} JSON depth exceeds {MAX_AGENT_HARNESS_JSON_DEPTH}")
            identity = id(current)
            if identity in active:
                _error(f"{context} JSON container cycle is unsupported")
            active.add(identity)
            try:
                if isinstance(current, dict):
                    result: dict[str, object] = {}
                    for key, item in current.items():
                        if not isinstance(key, str):
                            _error(f"{context} JSON object keys must be strings")
                        result[key] = normalize(item, depth + 1)
                    return result
                return [normalize(item, depth + 1) for item in current]
            finally:
                active.remove(identity)
        if current is None or isinstance(current, bool):
            return current
        if isinstance(current, int):
            if not -MAX_SAFE_INTEGER <= current <= MAX_SAFE_INTEGER:
                _error(f"{context} JSON integer is outside the JavaScript-safe range")
            return current
        if isinstance(current, float):
            if (
                not math.isfinite(current)
                or not current.is_integer()
                or not -MAX_SAFE_INTEGER <= current <= MAX_SAFE_INTEGER
            ):
                _error(f"{context} JSON number must be a finite JavaScript-safe integer")
            return int(current)
        if isinstance(current, str):
            try:
                current.encode("utf-8")
            except UnicodeError as exc:
                raise AgentHarnessContractError(f"{context} strings must be valid UTF-8") from exc
            return current
        _error(f"{context} contains unsupported JSON value {type(current).__name__}")

    return normalize(value, 1)


def _structure(value: object, *, context: str) -> None:
    active: set[int] = set()
    stack: list[tuple[bool, object, int]] = [(True, value, 1)]
    while stack:
        entering, current, depth = stack.pop()
        if not entering:
            active.remove(id(current))
            continue
        if isinstance(current, (dict, list)):
            if depth > MAX_AGENT_HARNESS_JSON_DEPTH:
                _error(f"{context} JSON depth exceeds {MAX_AGENT_HARNESS_JSON_DEPTH}")
            if id(current) in active:
                _error(f"{context} JSON container cycle is unsupported")
            active.add(id(current))
            stack.append((False, current, depth))
            if isinstance(current, dict):
                children = []
                for key, item in current.items():
                    if not isinstance(key, str):
                        _error(f"{context} JSON object keys must be strings")
                    children.extend((key, item))
            else:
                children = list(current)
            stack.extend((True, item, depth + 1) for item in reversed(children))
        elif current is None or isinstance(current, bool):
            continue
        elif isinstance(current, int):
            if not -MAX_SAFE_INTEGER <= current <= MAX_SAFE_INTEGER:
                _error(f"{context} JSON integer is outside the JavaScript-safe range")
        elif isinstance(current, float):
            _error(f"{context} decimal or exponent JSON numbers are unsupported")
        elif isinstance(current, str):
            try:
                current.encode("utf-8")
            except UnicodeError as exc:
                raise AgentHarnessContractError(f"{context} strings must be valid UTF-8") from exc
        else:
            _error(f"{context} contains unsupported JSON value {type(current).__name__}")


def canonical_agent_harness_hash(value: Mapping[str, object]) -> str:
    payload = dict(value)
    payload.pop("content_hash", None)
    payload = _normalize_json_numbers(payload, context="Agent Harness canonical JSON")
    _structure(payload, context="Agent Harness canonical JSON")
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise AgentHarnessContractError(
            f"could not encode canonical Agent Harness JSON: {exc}"
        ) from exc
    if len(encoded) > MAX_AGENT_HARNESS_DOCUMENT_BYTES:
        _error(f"Agent Harness document exceeds {MAX_AGENT_HARNESS_DOCUMENT_BYTES}-byte limit")
    return hashlib.sha256(encoded).hexdigest()


def _object(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _error(f"{context} must be an object")
    return value


def _exact(value: Mapping[str, object], fields: frozenset[str], context: str) -> None:
    unknown, missing = set(value) - fields, fields - set(value)
    if unknown:
        _error(f"{context} contains unknown fields: {', '.join(sorted(unknown))}")
    if missing:
        _error(f"{context} is missing fields: {', '.join(sorted(missing))}")


def _id(value: object, context: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        _error(f"{context} must be a portable lowercase ID")
    return value


def _hash(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _error(f"{context} must be a lowercase SHA-256")
    return value


def _revision(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_SAFE_INTEGER:
        _error(f"{context} must be a positive JavaScript-safe integer")
    return value


def _sorted_unique(
    values: object, context: str, *, allowed: frozenset[str] | None = None
) -> list[str]:
    if (
        not isinstance(values, list)
        or len(values) > 64
        or any(not isinstance(item, str) for item in values)
    ):
        _error(f"{context} must be a bounded string array")
    if values != sorted(set(values), key=lambda item: item.encode("utf-8")):
        _error(f"{context} must be sorted unique")
    if allowed is not None and any(item not in allowed for item in values):
        _error(f"{context} contains unsupported capability")
    if allowed is None and any(
        _TOOL_RE.fullmatch(item) is None or len(item) > MAX_AGENT_HARNESS_TOOL_ID_LENGTH
        for item in values
    ):
        _error(f"{context} contains an invalid tool ID")
    return values


def _binding(value: object, context: str) -> dict[str, Any]:
    result = _object(value, context)
    _exact(result, _BINDING_FIELDS, context)
    _id(result.get("id"), f"{context}.id")
    _revision(result.get("revision"), f"{context}.revision")
    _hash(result.get("content_hash"), f"{context}.content_hash")
    return result


def _work_order(value: object, context: str) -> dict[str, Any]:
    result = _object(value, context)
    _exact(result, _WORK_ORDER_FIELDS, context)
    _id(result.get("id"), f"{context}.id")
    _revision(result.get("revision"), f"{context}.revision")
    _hash(result.get("content_hash"), f"{context}.content_hash")
    _sorted_unique(result.get("capability_ids"), f"{context}.capability_ids", allowed=_CAPABILITIES)
    _sorted_unique(result.get("tool_ids"), f"{context}.tool_ids")
    return result


def _identity(value: object, context: str) -> dict[str, Any]:
    result = _object(value, context)
    _exact(result, _IDENTITY_FIELDS, context)
    _id(result.get("id"), f"{context}.id")
    _hash(result.get("content_hash"), f"{context}.content_hash")
    return result


def _verify_common(value: dict[str, Any], expected_format: str) -> None:
    if (
        value.get("format") != expected_format
        or isinstance(value.get("format_version"), bool)
        or value.get("format_version") != AGENT_HARNESS_VERSION
    ):
        _error("Agent Harness format or format_version is unsupported")
    if canonical_agent_harness_hash(value) != value.get("content_hash"):
        _error("Agent Harness content hash does not match canonical contents")


def _validate_activation(value: dict[str, Any]) -> None:
    _exact(value, _ACTIVATION_FIELDS, "agent worker activation")
    _verify_common(value, AGENT_WORKER_ACTIVATION_FORMAT)
    _id(value.get("activation_id"), "activation_id")
    _id(value.get("execution_id"), "execution_id")
    _binding(value.get("role"), "role")
    work_order = _work_order(value.get("work_order"), "work_order")
    _binding(value.get("runtime"), "runtime")
    _identity(value.get("prompt"), "prompt")
    _identity(value.get("input"), "input")
    if value.get("context_mode") != "fresh":
        _error("context_mode must be fresh")
    capabilities = _sorted_unique(
        value.get("requested_capability_ids"), "requested capability IDs", allowed=_CAPABILITIES
    )
    tools = _sorted_unique(value.get("requested_tool_ids"), "requested tools")
    if capabilities != work_order["capability_ids"]:
        _error("requested capabilities must exactly match work order")
    if tools != work_order["tool_ids"]:
        _error("requested tools must exactly match work order")


def _validate_grant(value: dict[str, Any]) -> None:
    _exact(value, _GRANT_FIELDS, "agent capability grant")
    _verify_common(value, AGENT_CAPABILITY_GRANT_FORMAT)
    _id(value.get("grant_id"), "grant_id")
    _id(value.get("execution_id"), "execution_id")
    _identity(value.get("activation"), "activation")
    _binding(value.get("role"), "role")
    work_order = _work_order(value.get("work_order"), "work_order")
    _binding(value.get("runtime"), "runtime")
    policy = _object(value.get("policy"), "policy")
    _exact(policy, _POLICY_FIELDS, "policy")
    policy_capabilities = _sorted_unique(
        policy.get("capability_ids"), "policy capability IDs", allowed=_CAPABILITIES
    )
    policy_tools = _sorted_unique(policy.get("tool_ids"), "policy tools")
    role_capabilities = _sorted_unique(
        value.get("role_capability_ids"), "role capability IDs", allowed=_CAPABILITIES
    )
    role_tools = _sorted_unique(value.get("role_tool_ids"), "role tools")
    effective_capabilities = _sorted_unique(
        value.get("effective_capability_ids"), "effective capability IDs", allowed=_CAPABILITIES
    )
    effective_tools = _sorted_unique(value.get("effective_tool_ids"), "effective tools")
    expected_capabilities = sorted(
        set(policy_capabilities) & set(role_capabilities) & set(work_order["capability_ids"]),
        key=lambda item: item.encode("utf-8"),
    )
    expected_tools = sorted(
        set(policy_tools) & set(role_tools) & set(work_order["tool_ids"]),
        key=lambda item: item.encode("utf-8"),
    )
    if effective_capabilities != expected_capabilities or effective_tools != expected_tools:
        _error(
            "effective capabilities and tools must equal the sorted unique three-way intersection"
        )


def validate_agent_harness_document(
    value: object, *, expected_format: str | None = None
) -> dict[str, Any]:
    normalized = _normalize_json_numbers(value, context="Agent Harness document")
    _structure(normalized, context="Agent Harness document")
    document = _object(normalized, "Agent Harness document")
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_AGENT_HARNESS_DOCUMENT_BYTES:
        _error(f"Agent Harness document exceeds {MAX_AGENT_HARNESS_DOCUMENT_BYTES}-byte limit")
    format_name = document.get("format")
    if expected_format is not None and format_name != expected_format:
        _error(f"Agent Harness document format must be {expected_format}")
    if format_name == AGENT_WORKER_ACTIVATION_FORMAT:
        _validate_activation(document)
    elif format_name == AGENT_CAPABILITY_GRANT_FORMAT:
        _validate_grant(document)
    else:
        _error("Agent Harness format or format_version is unsupported")
    return copy.deepcopy(document)


def validate_agent_harness_documents(activation: object, grant: object) -> AgentHarnessDocuments:
    active = validate_agent_harness_document(
        activation, expected_format=AGENT_WORKER_ACTIVATION_FORMAT
    )
    capability_grant = validate_agent_harness_document(
        grant, expected_format=AGENT_CAPABILITY_GRANT_FORMAT
    )
    if active["execution_id"] != capability_grant["execution_id"]:
        _error("activation and grant execution binding must match")
    if capability_grant["activation"] != {
        "id": active["activation_id"],
        "content_hash": active["content_hash"],
    }:
        _error("activation binding must match activation identity and hash")
    for name in ("role", "work_order", "runtime"):
        if active[name] != capability_grant[name]:
            _error(f"activation and grant {name} binding must match")
    return AgentHarnessDocuments(activation=active, grant=capability_grant)
