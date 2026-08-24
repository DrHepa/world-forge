"""Default-deny capability routing for one in-process execution."""

from __future__ import annotations

import copy
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .ports import (
    ArtifactProposal,
    ArtifactProposalPort,
    MemoryProposal,
    MemoryProposalPort,
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
    adapter: ToolAdapter
    tool_id: str
    required_capability_id: str


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
                tool_id = adapter.tool_id
                required_capability_id = adapter.required_capability_id
            except Exception:
                raise ValueError("invalid tool adapter") from None
            if (
                type(tool_id) is not str
                or len(tool_id) > 1024
                or _TOOL_RE.fullmatch(tool_id) is None
                or type(required_capability_id) is not str
                or required_capability_id not in _CAPABILITIES
            ):
                raise ValueError("invalid tool adapter")
            if tool_id in registry:
                raise ValueError("duplicate tool adapter")
            registry[tool_id] = _ToolBinding(adapter, tool_id, required_capability_id)
        self._tools = registry
        self._artifact_port = artifact_port
        self._memory_port = memory_port
        self._execution_id: str | None = None
        self._activation_lease: object | None = None
        self._routing = False

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
            or binding.required_capability_id not in effective_capabilities
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
    ) -> None:
        """Authorize a complete provider turn without invoking any external port."""

        if self._execution_id != execution_id or self._routing:
            raise BrokerError("execution_reentrant")
        for call in tool_calls:
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
                result = binding.adapter.invoke(private_call)
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
