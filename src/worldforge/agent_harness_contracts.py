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
    events: tuple[dict[str, Any], ...] = ()
    receipt: dict[str, Any] | None = None
    projection: dict[str, Any] | None = None


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


# Additive Slice 1B.2 event/receipt and Slice 1B.3 projection vocabulary.
AGENT_EVENT_FORMAT = "world-forge.agent_event"
AGENT_EXECUTION_RECEIPT_FORMAT = "world-forge.agent_execution_receipt"
AGENT_MEMORY_PROJECTION_FORMAT = "world-forge.agent_memory_projection"
_EVENT_TYPES = frozenset(
    {
        "worker.activated",
        "grant.issued",
        "execution.started",
        "execution.cancel_requested",
        "execution.receipt_recorded",
        "memory.projected",
    }
)
_EVENT_FIELDS = frozenset(
    {
        "format",
        "format_version",
        "event_id",
        "log_id",
        "execution_id",
        "sequence",
        "previous_event_hash",
        "event_type",
        "subject",
        "content_hash",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "format",
        "format_version",
        "receipt_id",
        "execution_id",
        "activation",
        "grant",
        "runtime_binding",
        "prompt_identities",
        "tool_invocations",
        "result_artifacts",
        "usage",
        "outcome",
        "failure_codes",
        "replay_support",
        "content_hash",
    }
)
_SUBJECT_FIELDS = frozenset({"format", "format_version", "id", "content_hash"})
_USAGE_FIELDS = frozenset(
    {
        "input_tokens",
        "output_tokens",
        "cached_input_tokens",
        "duration_ms",
        "cost_minor_units",
        "currency",
    }
)
_INVOCATION_FIELDS = frozenset(
    {
        "invocation_id",
        "sequence",
        "tool_id",
        "request_hash",
        "outcome",
        "result_artifacts",
        "failure_codes",
    }
)
_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_PROJECTION_FIELDS = frozenset(
    {
        "format",
        "format_version",
        "projection_id",
        "execution_id",
        "receipt",
        "source_events",
        "review",
        "entries",
        "content_hash",
    }
)
_PROJECTION_REVIEW_FIELDS = frozenset(
    {
        "review_id",
        "reviewer_id",
        "policy_id",
        "policy_version",
        "policy_hash",
        "receipt_content_hash",
        "decision",
    }
)
_PROJECTION_ENTRY_FIELDS = frozenset(
    {"entry_id", "kind", "subject_id", "value_hash", "source_event_ids"}
)
_PROJECTION_ENTRY_KINDS = frozenset({"decision", "constraint", "discovery", "preference"})
_PROJECTION_FORBIDDEN_FIELDS = frozenset(
    {
        "memory_text",
        "prompt",
        "transcript",
        "rationale",
        "path",
        "url",
        "endpoint",
        "command",
        "env",
        "stderr",
        "secret",
        "credentials",
        "token",
        "provider_payload",
        "executable",
        "executable_content",
    }
)


def _nonnegative(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SAFE_INTEGER:
        _error(f"{context} must be a nonnegative JavaScript-safe integer")
    return value


def _subject(value: object, context: str) -> dict[str, Any]:
    result = _object(value, context)
    _exact(result, _SUBJECT_FIELDS, context)
    if (
        not isinstance(result.get("format"), str)
        or isinstance(result.get("format_version"), bool)
        or result.get("format_version") != 1
    ):
        _error(f"{context} has unsupported format or format_version")
    _id(result.get("id"), f"{context}.id")
    _hash(result.get("content_hash"), f"{context}.content_hash")
    return result


def _reason_codes(value: object, context: str, *, required: bool) -> list[str]:
    if not isinstance(value, list) or len(value) > 64 or (required and not value):
        _error(f"{context} must be a bounded reason token array")
    if any(not isinstance(item, str) or _REASON_RE.fullmatch(item) is None for item in value):
        _error(f"{context} must contain reason tokens")
    if value != sorted(set(value), key=lambda item: item.encode("utf-8")):
        _error(f"{context} must be sorted unique")
    return value


def _identity_array(value: object, context: str, *, maximum: int = 64) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > maximum:
        _error(f"{context} must be a bounded identity array")
    result = [_identity(item, f"{context}/{index}") for index, item in enumerate(value)]
    if [item["id"] for item in result] != sorted(
        (item["id"] for item in result), key=lambda item: item.encode("utf-8")
    ) or len({item["id"] for item in result}) != len(result):
        _error(f"{context} must be sorted unique")
    return result


def _portable_id_array(
    value: object, context: str, *, minimum: int = 1, maximum: int = 64
) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        _error(f"{context} must be a bounded non-empty ID array")
    result = [_id(item, f"{context}/{index}") for index, item in enumerate(value)]
    if result != sorted(set(result), key=lambda item: item.encode("utf-8")):
        _error(f"{context} must be sorted unique")
    return result


def _document_ref(value: object, context: str, *, expected_format: str) -> dict[str, Any]:
    result = _subject(value, context)
    if result["format"] != expected_format:
        _error(f"{context} format must be {expected_format}")
    return result


def _document_ref_array(
    value: object, context: str, *, expected_format: str
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        _error(f"{context} must be a bounded non-empty document-ref array")
    result = [
        _document_ref(item, f"{context}/{index}", expected_format=expected_format)
        for index, item in enumerate(value)
    ]
    ids = [item["id"] for item in result]
    if ids != sorted(set(ids), key=lambda item: item.encode("utf-8")):
        _error(f"{context} must be sorted unique by id")
    return result


def _reject_projection_forbidden_fields(value: object) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            forbidden = set(current) & _PROJECTION_FORBIDDEN_FIELDS
            if forbidden:
                _error(
                    "agent memory projection contains forbidden fields: "
                    + ", ".join(sorted(forbidden))
                )
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def _validate_event(value: dict[str, Any]) -> None:
    _exact(value, _EVENT_FIELDS, "agent event")
    _verify_common(value, AGENT_EVENT_FORMAT)
    _id(value.get("event_id"), "event_id")
    _id(value.get("log_id"), "log_id")
    _id(value.get("execution_id"), "execution_id")
    sequence = _nonnegative(value.get("sequence"), "sequence")
    previous = value.get("previous_event_hash")
    if (sequence == 0 and previous is not None) or (sequence > 0 and not isinstance(previous, str)):
        _error("previous_event_hash must be null only at sequence 0")
    if previous is not None:
        _hash(previous, "previous_event_hash")
    event_type = value.get("event_type")
    if event_type not in _EVENT_TYPES:
        _error("event_type is unsupported")
    subject = _subject(value.get("subject"), "subject")
    expected = {
        "worker.activated": AGENT_WORKER_ACTIVATION_FORMAT,
        "grant.issued": AGENT_CAPABILITY_GRANT_FORMAT,
        "execution.started": AGENT_WORKER_ACTIVATION_FORMAT,
        "execution.cancel_requested": AGENT_WORKER_ACTIVATION_FORMAT,
        "execution.receipt_recorded": AGENT_EXECUTION_RECEIPT_FORMAT,
        "memory.projected": AGENT_MEMORY_PROJECTION_FORMAT,
    }
    if subject["format"] != expected[event_type]:
        _error("event subject format is incompatible")


def _validate_receipt(value: dict[str, Any]) -> None:
    _exact(value, _RECEIPT_FIELDS, "agent execution receipt")
    _verify_common(value, AGENT_EXECUTION_RECEIPT_FORMAT)
    _id(value.get("receipt_id"), "receipt_id")
    _id(value.get("execution_id"), "execution_id")
    _identity(value.get("activation"), "activation")
    _identity(value.get("grant"), "grant")
    _binding(value.get("runtime_binding"), "runtime_binding")
    _identity_array(value.get("prompt_identities"), "prompt_identities")
    _identity_array(value.get("result_artifacts"), "result_artifacts")
    outcome = value.get("outcome")
    if outcome not in {"succeeded", "failed", "cancelled"}:
        _error("outcome is unsupported")
    _reason_codes(value.get("failure_codes"), "failure_codes", required=outcome != "succeeded")
    if outcome == "succeeded" and value["failure_codes"]:
        _error("succeeded receipt must not contain failure codes")
    usage = _object(value.get("usage"), "usage")
    _exact(usage, _USAGE_FIELDS, "usage")
    for name in ("input_tokens", "output_tokens", "cached_input_tokens", "duration_ms"):
        _nonnegative(usage.get(name), f"usage.{name}")
    if usage["cached_input_tokens"] > usage["input_tokens"]:
        _error("cached_input_tokens must not exceed input_tokens")
    if (usage["cost_minor_units"] is None) != (usage["currency"] is None):
        _error("cost_minor_units and currency must be jointly null or present")
    if usage["cost_minor_units"] is not None:
        _nonnegative(usage["cost_minor_units"], "usage.cost_minor_units")
    if usage["currency"] is not None and (
        not isinstance(usage["currency"], str)
        or re.fullmatch(r"[A-Z]{3}", usage["currency"]) is None
    ):
        _error("currency must be ISO-4217 uppercase")
    if value.get("replay_support") != "not_claimed":
        _error("replay_support must be not_claimed")
    invocations = value.get("tool_invocations")
    if not isinstance(invocations, list) or len(invocations) > 128:
        _error("tool_invocations must be bounded")
    invocation_ids: set[str] = set()
    for index, invocation in enumerate(invocations):
        item = _object(invocation, f"tool_invocations/{index}")
        _exact(item, _INVOCATION_FIELDS, f"tool_invocations/{index}")
        invocation_id = _id(item.get("invocation_id"), "invocation_id")
        if invocation_id in invocation_ids:
            _error("tool invocation IDs must be unique")
        invocation_ids.add(invocation_id)
        if _nonnegative(item.get("sequence"), "invocation sequence") != index:
            _error("tool_invocations must be contiguous by sequence")
        _sorted_unique([item.get("tool_id")], "tool invocation tool IDs")
        _hash(item.get("request_hash"), "request_hash")
        _identity_array(item.get("result_artifacts"), "invocation result artifacts")
        if item.get("outcome") not in {"succeeded", "failed", "cancelled"}:
            _error("invocation outcome is unsupported")
        _reason_codes(
            item.get("failure_codes"),
            "invocation failure codes",
            required=item["outcome"] != "succeeded",
        )
        if item["outcome"] == "succeeded" and item["failure_codes"]:
            _error("successful invocation must not contain failure codes")


def _validate_projection(value: dict[str, Any]) -> None:
    _reject_projection_forbidden_fields(value)
    _exact(value, _PROJECTION_FIELDS, "agent memory projection")
    _verify_common(value, AGENT_MEMORY_PROJECTION_FORMAT)
    _id(value.get("projection_id"), "projection_id")
    _id(value.get("execution_id"), "execution_id")
    receipt_ref = _document_ref(
        value.get("receipt"),
        "receipt",
        expected_format=AGENT_EXECUTION_RECEIPT_FORMAT,
    )
    source_events = _document_ref_array(
        value.get("source_events"),
        "source_events",
        expected_format=AGENT_EVENT_FORMAT,
    )
    review = _object(value.get("review"), "review")
    _exact(review, _PROJECTION_REVIEW_FIELDS, "review")
    for name in ("review_id", "reviewer_id", "policy_id"):
        _id(review.get(name), f"review.{name}")
    _revision(review.get("policy_version"), "review.policy_version")
    _hash(review.get("policy_hash"), "review.policy_hash")
    _hash(review.get("receipt_content_hash"), "review.receipt_content_hash")
    if review["receipt_content_hash"] != receipt_ref["content_hash"]:
        _error("review receipt_content_hash must match the projected receipt ref")
    if review.get("decision") != "approved":
        _error("review.decision must be approved")
    entries = value.get("entries")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 64:
        _error("entries must be a bounded non-empty memory-entry array")
    entry_ids: list[str] = []
    source_ids = {item["id"] for item in source_events}
    for index, entry in enumerate(entries):
        item = _object(entry, f"entries/{index}")
        _exact(item, _PROJECTION_ENTRY_FIELDS, f"entries/{index}")
        entry_ids.append(_id(item.get("entry_id"), f"entries/{index}.entry_id"))
        if item.get("kind") not in _PROJECTION_ENTRY_KINDS:
            _error(f"entries/{index}.kind is unsupported")
        _id(item.get("subject_id"), f"entries/{index}.subject_id")
        _hash(item.get("value_hash"), f"entries/{index}.value_hash")
        entry_sources = _portable_id_array(
            item.get("source_event_ids"), f"entries/{index}.source_event_ids"
        )
        if not set(entry_sources) <= source_ids:
            _error("entry source_event_ids must be a subset of projection source events")
    if entry_ids != sorted(set(entry_ids), key=lambda item: item.encode("utf-8")):
        _error("entries must be sorted unique by entry_id")


# Override public dispatch and aggregate additively.
_old_validate_agent_harness_document = validate_agent_harness_document


def validate_agent_harness_document(
    value: object, *, expected_format: str | None = None
) -> dict[str, Any]:
    normalized = _normalize_json_numbers(value, context="Agent Harness document")
    document = _object(normalized, "Agent Harness document")
    if document.get("format") in {
        AGENT_EVENT_FORMAT,
        AGENT_EXECUTION_RECEIPT_FORMAT,
        AGENT_MEMORY_PROJECTION_FORMAT,
    }:
        _structure(document, context="Agent Harness document")
        encoded = json.dumps(
            document, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False
        ).encode("utf-8")
        if len(encoded) > MAX_AGENT_HARNESS_DOCUMENT_BYTES:
            _error(f"Agent Harness document exceeds {MAX_AGENT_HARNESS_DOCUMENT_BYTES}-byte limit")
        if expected_format is not None and document.get("format") != expected_format:
            _error(f"Agent Harness document format must be {expected_format}")
        validators = {
            AGENT_EVENT_FORMAT: _validate_event,
            AGENT_EXECUTION_RECEIPT_FORMAT: _validate_receipt,
            AGENT_MEMORY_PROJECTION_FORMAT: _validate_projection,
        }
        validators[document["format"]](document)
        return copy.deepcopy(document)
    return _old_validate_agent_harness_document(document, expected_format=expected_format)


_old_validate_agent_harness_documents = validate_agent_harness_documents


def validate_agent_harness_documents(
    activation: object,
    grant: object,
    events: object = (),
    receipt: object | None = None,
    projection: object | None = None,
) -> AgentHarnessDocuments:
    aggregate = _old_validate_agent_harness_documents(activation, grant)
    event_values = tuple(
        validate_agent_harness_document(item, expected_format=AGENT_EVENT_FORMAT) for item in events
    )
    if event_values:
        if event_values[0]["sequence"] != 0:
            _error("event log must start at sequence 0")
        log_id, execution_id = event_values[0]["log_id"], event_values[0]["execution_id"]
        ids: set[str] = set()
        previous: str | None = None
        activation_ref = {
            "format": AGENT_WORKER_ACTIVATION_FORMAT,
            "format_version": AGENT_HARNESS_VERSION,
            "id": aggregate.activation["activation_id"],
            "content_hash": aggregate.activation["content_hash"],
        }
        grant_ref = {
            "format": AGENT_CAPABILITY_GRANT_FORMAT,
            "format_version": AGENT_HARNESS_VERSION,
            "id": aggregate.grant["grant_id"],
            "content_hash": aggregate.grant["content_hash"],
        }
        for index, event in enumerate(event_values):
            if (
                event["event_id"] in ids
                or event["log_id"] != log_id
                or event["execution_id"] != execution_id
                or event["execution_id"] != aggregate.activation["execution_id"]
                or event["sequence"] != index
                or event["previous_event_hash"] != previous
            ):
                _error("event chain lineage is invalid")
            expected_subject = (
                activation_ref
                if event["event_type"]
                in {"worker.activated", "execution.started", "execution.cancel_requested"}
                else grant_ref
                if event["event_type"] == "grant.issued"
                else None
            )
            if expected_subject is not None and event["subject"] != expected_subject:
                _error("event subject lineage does not match its supplied binding")
            ids.add(event["event_id"])
            previous = event["content_hash"]
    receipt_value = (
        None
        if receipt is None
        else validate_agent_harness_document(
            receipt, expected_format=AGENT_EXECUTION_RECEIPT_FORMAT
        )
    )
    if (
        any(event["event_type"] == "execution.receipt_recorded" for event in event_values)
        and receipt_value is None
    ):
        _error("receipt-recorded event requires a supplied receipt")
    if receipt_value is not None:
        if (
            receipt_value["execution_id"] != aggregate.activation["execution_id"]
            or receipt_value["activation"]
            != {
                "id": aggregate.activation["activation_id"],
                "content_hash": aggregate.activation["content_hash"],
            }
            or receipt_value["grant"]
            != {"id": aggregate.grant["grant_id"], "content_hash": aggregate.grant["content_hash"]}
            or receipt_value["runtime_binding"] != aggregate.activation["runtime"]
            or receipt_value["prompt_identities"] != [aggregate.activation["prompt"]]
        ):
            _error("receipt lineage does not match activation and grant")
        for event in event_values:
            if event["event_type"] == "execution.receipt_recorded" and event["subject"] != {
                "format": AGENT_EXECUTION_RECEIPT_FORMAT,
                "format_version": 1,
                "id": receipt_value["receipt_id"],
                "content_hash": receipt_value["content_hash"],
            }:
                _error("receipt event subject does not match supplied receipt")
        for item in receipt_value["tool_invocations"]:
            if item["tool_id"] not in aggregate.grant["effective_tool_ids"]:
                _error("receipt invokes an ungranted tool")
    projection_value = (
        None
        if projection is None
        else validate_agent_harness_document(
            projection, expected_format=AGENT_MEMORY_PROJECTION_FORMAT
        )
    )
    if projection_value is not None and receipt_value is None:
        _error("memory projection requires a supplied receipt")
    if projection_value is not None:
        expected_receipt_ref = {
            "format": AGENT_EXECUTION_RECEIPT_FORMAT,
            "format_version": AGENT_HARNESS_VERSION,
            "id": receipt_value["receipt_id"],
            "content_hash": receipt_value["content_hash"],
        }
        if (
            projection_value["execution_id"] != aggregate.activation["execution_id"]
            or projection_value["receipt"] != expected_receipt_ref
            or projection_value["review"]["receipt_content_hash"] != receipt_value["content_hash"]
        ):
            _error("memory projection lineage does not match execution and receipt")
        event_refs = {
            event["event_id"]: {
                "format": AGENT_EVENT_FORMAT,
                "format_version": AGENT_HARNESS_VERSION,
                "id": event["event_id"],
                "content_hash": event["content_hash"],
            }
            for event in event_values
        }
        for source_ref in projection_value["source_events"]:
            if event_refs.get(source_ref["id"]) != source_ref:
                _error("memory projection source event does not resolve exactly")
    memory_events = [event for event in event_values if event["event_type"] == "memory.projected"]
    if memory_events and projection_value is None:
        _error("memory-projected event requires a supplied projection")
    if projection_value is not None:
        expected_projection_ref = {
            "format": AGENT_MEMORY_PROJECTION_FORMAT,
            "format_version": AGENT_HARNESS_VERSION,
            "id": projection_value["projection_id"],
            "content_hash": projection_value["content_hash"],
        }
        for event in memory_events:
            if event["subject"] != expected_projection_ref:
                _error("memory projection event subject does not match supplied projection")
    return AgentHarnessDocuments(
        activation=aggregate.activation,
        grant=aggregate.grant,
        events=event_values,
        receipt=receipt_value,
        projection=projection_value,
    )
