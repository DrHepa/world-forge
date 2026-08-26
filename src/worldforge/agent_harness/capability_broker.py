"""Default-deny capability routing for one in-process execution."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace

from worldforge.agent_harness_contracts import MAX_SAFE_INTEGER

from .ports import (
    ArtifactProposal,
    ArtifactProposalPort,
    MemoryProposal,
    MemoryProposalPort,
    ProviderToolDefinition,
    ProviderToolSummary,
    ToolAdapter,
    ToolCall,
    ToolResult,
)

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_TOOL_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}(?:\.[a-z][a-z0-9_]{1,63})+$")
_CAPABILITIES = frozenset(
    {
        "artifact.propose",
        "artifact.read",
        "memory.propose",
        "memory.read",
        "project.read",
        "tool.invoke",
    }
)
_MAX_TOOL_SUMMARY_BYTES = 1024
_MAX_TOOL_SCHEMA_BYTES = 16 * 1024
_MAX_TOOL_SCHEMA_DEPTH = 32


class BrokerError(ValueError):
    def __init__(self, reason_code: str, *, invoked: bool = False) -> None:
        self.reason_code = reason_code
        self.invoked = invoked
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class ClosedIdentity:
    id: str
    content_hash: str

    def as_document(self) -> dict[str, str]:
        return {"id": self.id, "content_hash": self.content_hash}


@dataclass(frozen=True, slots=True)
class _ToolBinding:
    invoke: Callable[[ToolCall], object] = field(repr=False, compare=False)
    descriptor: ToolDescriptorSnapshot


@dataclass(frozen=True, slots=True)
class ToolDescriptorSnapshot:
    tool_id: str
    required_capability_id: str
    summary: str
    descriptor_hash: str
    _input_schema_bytes: bytes = field(repr=False)

    def summary_document(self) -> dict[str, str]:
        return {
            "tool_id": self.tool_id,
            "summary": self.summary,
            "descriptor_hash": self.descriptor_hash,
        }

    def definition_document(self) -> dict[str, object]:
        return {
            "tool_id": self.tool_id,
            "required_capability_id": self.required_capability_id,
            "summary": self.summary,
            "input_schema": json.loads(self._input_schema_bytes),
            "descriptor_hash": self.descriptor_hash,
        }

    def provider_summary(self) -> ProviderToolSummary:
        return ProviderToolSummary(self.tool_id, self.summary, self.descriptor_hash)

    def provider_definition(self) -> ProviderToolDefinition:
        return ProviderToolDefinition(
            self.tool_id,
            self.required_capability_id,
            self.summary,
            json.loads(self._input_schema_bytes),
            self.descriptor_hash,
        )


@dataclass(frozen=True, slots=True)
class ToolCatalogSnapshot:
    descriptors: tuple[ToolDescriptorSnapshot, ...]
    catalog_hash: str

    @property
    def candidates(self) -> tuple[tuple[str, str], ...]:
        return tuple((item.tool_id, item.descriptor_hash) for item in self.descriptors)

    def approved(self, tool_ids: tuple[str, ...]) -> ToolCatalogSnapshot:
        allowed = frozenset(tool_ids)
        descriptors = tuple(replace(item) for item in self.descriptors if item.tool_id in allowed)
        return ToolCatalogSnapshot(descriptors, self.catalog_hash)


def _schema_snapshot(value: object) -> bytes:
    active: set[int] = set()

    def snapshot(current: object, depth: int) -> object:
        if depth > _MAX_TOOL_SCHEMA_DEPTH:
            raise ValueError("invalid tool adapter")
        if type(current) is dict:
            identity = id(current)
            if identity in active:
                raise ValueError("invalid tool adapter")
            active.add(identity)
            try:
                result: dict[str, object] = {}
                for key, item in dict.items(current):
                    if type(key) is not str:
                        raise ValueError("invalid tool adapter")
                    result[key] = snapshot(item, depth + 1)
                return result
            finally:
                active.remove(identity)
        if type(current) is list:
            identity = id(current)
            if identity in active:
                raise ValueError("invalid tool adapter")
            active.add(identity)
            try:
                return [snapshot(item, depth + 1) for item in list.__iter__(current)]
            finally:
                active.remove(identity)
        if current is None or type(current) in {bool, str}:
            return current
        if type(current) is int and -MAX_SAFE_INTEGER <= current <= MAX_SAFE_INTEGER:
            return current
        if type(current) is float and math.isfinite(current):
            return current
        raise ValueError("invalid tool adapter")

    if type(value) is not dict:
        raise ValueError("invalid tool adapter")
    try:
        encoded = json.dumps(
            snapshot(value, 1),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except ValueError:
        raise
    except Exception:
        raise ValueError("invalid tool adapter") from None
    if len(encoded) > _MAX_TOOL_SCHEMA_BYTES:
        raise ValueError("invalid tool adapter")
    return encoded


def _descriptor_snapshot(
    adapter: object,
) -> tuple[ToolDescriptorSnapshot, Callable[[ToolCall], object]]:
    try:
        tool_id = adapter.tool_id
        required_capability_id = adapter.required_capability_id
        invoke = adapter.invoke
    except Exception:
        raise ValueError("invalid tool adapter") from None
    try:
        summary = adapter.summary
    except Exception:
        raise ValueError("invalid tool adapter") from None
    try:
        input_schema = adapter.input_schema
    except Exception:
        raise ValueError("invalid tool adapter") from None
    if (
        type(tool_id) is not str
        or len(tool_id) > 1024
        or _TOOL_RE.fullmatch(tool_id) is None
        or type(required_capability_id) is not str
        or required_capability_id not in _CAPABILITIES
        or type(summary) is not str
        or not summary
        or any(ord(character) < 32 or ord(character) == 127 for character in summary)
        or not callable(invoke)
    ):
        raise ValueError("invalid tool adapter")
    try:
        summary_bytes = summary.encode("utf-8")
    except Exception:
        raise ValueError("invalid tool adapter") from None
    if len(summary_bytes) > _MAX_TOOL_SUMMARY_BYTES:
        raise ValueError("invalid tool adapter")
    schema_bytes = _schema_snapshot(input_schema)
    descriptor_body = {
        "tool_id": tool_id,
        "required_capability_id": required_capability_id,
        "summary": summary,
        "input_schema": json.loads(schema_bytes),
    }
    descriptor_hash = hashlib.sha256(
        json.dumps(
            descriptor_body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return (
        ToolDescriptorSnapshot(
            tool_id,
            required_capability_id,
            summary,
            descriptor_hash,
            schema_bytes,
        ),
        invoke,
    )


def _closed_identity(value: object, reason_code: str) -> ClosedIdentity:
    if not isinstance(value, Mapping) or set(value) != {"id", "content_hash"}:
        raise BrokerError(reason_code)
    identifier, content_hash = value.get("id"), value.get("content_hash")
    if (
        type(identifier) is not str
        or _ID_RE.fullmatch(identifier) is None
        or type(content_hash) is not str
        or _HASH_RE.fullmatch(content_hash) is None
    ):
        raise BrokerError(reason_code)
    return ClosedIdentity(identifier, content_hash)


class CapabilityBroker:
    """Routes only exact, effectively granted authorities; everything else is denied."""

    def __init__(
        self,
        *,
        tools: Iterable[ToolAdapter] = (),
        artifact_port: ArtifactProposalPort | None = None,
        memory_port: MemoryProposalPort | None = None,
    ) -> None:
        registry: dict[str, _ToolBinding] = {}
        for adapter in tools:
            try:
                descriptor, invoke = _descriptor_snapshot(adapter)
            except Exception:
                raise ValueError("invalid tool adapter") from None
            if descriptor.tool_id in registry:
                raise ValueError("duplicate tool adapter")
            registry[descriptor.tool_id] = _ToolBinding(invoke, descriptor)
        self._tools = registry
        self._artifact_port = artifact_port
        self._memory_port = memory_port
        self._execution_id: str | None = None
        self._activation_lease: object | None = None
        self._routing = False

    def eligible_tool_catalog(
        self,
        *,
        effective_capabilities: frozenset[str],
        effective_tools: frozenset[str],
    ) -> ToolCatalogSnapshot:
        descriptors = tuple(
            replace(binding.descriptor)
            for tool_id, binding in sorted(self._tools.items())
            if tool_id in effective_tools
            and "tool.invoke" in effective_capabilities
            and binding.descriptor.required_capability_id in effective_capabilities
        )
        body = [descriptor.definition_document() for descriptor in descriptors]
        catalog_hash = hashlib.sha256(
            json.dumps(
                body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        return ToolCatalogSnapshot(descriptors, catalog_hash)

    def activate(self, execution_id: str) -> object:
        if type(execution_id) is not str or _ID_RE.fullmatch(execution_id) is None:
            raise BrokerError("execution_invalid")
        if self._execution_id is not None:
            raise BrokerError("execution_reentrant")
        lease = object()
        self._execution_id = execution_id
        self._activation_lease = lease
        return lease

    def release(self, execution_id: str, lease: object) -> None:
        if self._execution_id == execution_id and self._activation_lease is lease:
            self._execution_id = None
            self._activation_lease = None
            self._routing = False

    def _enter(self, execution_id: str) -> None:
        if self._execution_id != execution_id or self._routing:
            raise BrokerError("execution_reentrant")
        self._routing = True

    def _leave(self) -> None:
        self._routing = False

    def _authorized_tool(
        self,
        call: ToolCall,
        *,
        effective_capabilities: frozenset[str],
        effective_tools: frozenset[str],
    ) -> _ToolBinding:
        binding = self._tools.get(call.tool_id)
        if (
            binding is None
            or call.tool_id not in effective_tools
            or "tool.invoke" not in effective_capabilities
            or binding.descriptor.required_capability_id not in effective_capabilities
        ):
            raise BrokerError("tool_not_authorized")
        return binding

    def preflight(
        self,
        execution_id: str,
        *,
        tool_calls: tuple[ToolCall, ...],
        artifact_count: int,
        memory_count: int,
        effective_capabilities: frozenset[str],
        effective_tools: frozenset[str],
        exposed_tools: frozenset[str] | None = None,
    ) -> None:
        """Authorize a complete provider turn without invoking any external port."""

        if self._execution_id != execution_id or self._routing:
            raise BrokerError("execution_reentrant")
        for call in tool_calls:
            if exposed_tools is not None and call.tool_id not in exposed_tools:
                raise BrokerError("tool_not_authorized")
            self._authorized_tool(
                call,
                effective_capabilities=effective_capabilities,
                effective_tools=effective_tools,
            )
        if artifact_count and (
            "artifact.propose" not in effective_capabilities or self._artifact_port is None
        ):
            code = (
                "artifact_capability_denied"
                if "artifact.propose" not in effective_capabilities
                else "artifact_port_unavailable"
            )
            raise BrokerError(code)
        if memory_count and (
            "memory.propose" not in effective_capabilities or self._memory_port is None
        ):
            code = (
                "memory_capability_denied"
                if "memory.propose" not in effective_capabilities
                else "memory_port_unavailable"
            )
            raise BrokerError(code)

    def preflight_exposure_requests(
        self,
        *,
        requested_tool_ids: tuple[str, ...],
        effective_capabilities: frozenset[str],
        effective_tools: frozenset[str],
    ) -> None:
        for tool_id in requested_tool_ids:
            binding = self._tools.get(tool_id)
            if (
                binding is None
                or tool_id not in effective_tools
                or "tool.invoke" not in effective_capabilities
                or binding.descriptor.required_capability_id not in effective_capabilities
            ):
                raise BrokerError("tool_not_authorized")

    def invoke_tool(
        self,
        execution_id: str,
        call: ToolCall,
        *,
        effective_capabilities: frozenset[str],
        effective_tools: frozenset[str],
    ) -> ToolResult:
        binding = self._authorized_tool(
            call,
            effective_capabilities=effective_capabilities,
            effective_tools=effective_tools,
        )
        try:
            private_call = copy.deepcopy(call)
        except Exception:
            raise BrokerError("tool_request_invalid") from None
        self._enter(execution_id)
        try:
            try:
                result = binding.invoke(private_call)
            except Exception:
                raise BrokerError("tool_failed", invoked=True) from None
        finally:
            self._leave()
        if type(result) is not ToolResult:
            raise BrokerError("tool_result_invalid", invoked=True)
        try:
            return copy.deepcopy(result)
        except Exception:
            raise BrokerError("tool_result_invalid", invoked=True) from None

    def propose_artifact(
        self,
        execution_id: str,
        proposal: ArtifactProposal,
        *,
        effective_capabilities: frozenset[str],
    ) -> ClosedIdentity:
        if "artifact.propose" not in effective_capabilities:
            raise BrokerError("artifact_capability_denied")
        if self._artifact_port is None:
            raise BrokerError("artifact_port_unavailable")
        try:
            private_proposal = copy.deepcopy(proposal)
        except Exception:
            raise BrokerError("artifact_proposal_invalid") from None
        self._enter(execution_id)
        try:
            try:
                identity = self._artifact_port.propose(private_proposal)
            except Exception:
                raise BrokerError("artifact_proposal_failed", invoked=True) from None
        finally:
            self._leave()
        try:
            return _closed_identity(identity, "artifact_result_invalid")
        except Exception:
            raise BrokerError("artifact_result_invalid", invoked=True) from None

    def propose_memory(
        self,
        execution_id: str,
        proposal: MemoryProposal,
        *,
        effective_capabilities: frozenset[str],
    ) -> ClosedIdentity:
        if "memory.propose" not in effective_capabilities:
            raise BrokerError("memory_capability_denied")
        if self._memory_port is None:
            raise BrokerError("memory_port_unavailable")
        try:
            private_proposal = copy.deepcopy(proposal)
        except Exception:
            raise BrokerError("memory_proposal_invalid") from None
        self._enter(execution_id)
        try:
            try:
                identity = self._memory_port.propose(private_proposal)
            except Exception:
                raise BrokerError("memory_proposal_failed", invoked=True) from None
        finally:
            self._leave()
        try:
            return _closed_identity(identity, "memory_result_invalid")
        except Exception:
            raise BrokerError("memory_result_invalid", invoked=True) from None
