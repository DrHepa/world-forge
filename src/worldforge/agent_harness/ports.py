"""Private, provider-neutral ports for bounded Agent Harness execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class ExecutionLimits:
    max_turns: int
    max_tool_calls: int
    max_total_tokens: int
    max_cost_minor_units: int | None
    currency: str | None
    max_duration_ms: int
    deadline_ms: int | None = None


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    activation: dict[str, Any]
    grant: dict[str, Any]
    log_id: str
    receipt_id: str
    event_id_prefix: str
    invocation_id_prefix: str
    limits: ExecutionLimits
    private_input: object = None


@dataclass(frozen=True, slots=True)
class ProviderUsage:
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    cost_minor_units: int | None
    currency: str | None


@dataclass(frozen=True, slots=True)
class ToolCall:
    tool_id: str
    private_arguments: object = None


@dataclass(frozen=True, slots=True)
class ToolResult:
    private_output: object = None


@dataclass(frozen=True, slots=True)
class ArtifactProposal:
    private_payload: object


@dataclass(frozen=True, slots=True)
class MemoryProposal:
    private_payload: object


@dataclass(frozen=True, slots=True)
class ProviderTurnRequest:
    execution_id: str
    turn_index: int
    private_input: object
    history: tuple[object, ...] = ()


@dataclass(frozen=True, slots=True)
class ProviderTurnResult:
    private_output: object
    usage: ProviderUsage
    tool_calls: tuple[ToolCall, ...] = ()
    artifact_proposals: tuple[ArtifactProposal, ...] = ()
    memory_proposals: tuple[MemoryProposal, ...] = ()
    completed: bool = False


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    outcome: str
    events: tuple[dict[str, Any], ...]
    receipt: dict[str, Any]
    private_output: object = field(default=None, repr=False)


class ProviderAdapter(Protocol):
    def turn(self, request: ProviderTurnRequest) -> ProviderTurnResult: ...


class ToolAdapter(Protocol):
    tool_id: str
    required_capability_id: str

    def invoke(self, call: ToolCall) -> ToolResult: ...


class ArtifactProposalPort(Protocol):
    def propose(self, proposal: ArtifactProposal) -> dict[str, str]: ...


class MemoryProposalPort(Protocol):
    def propose(self, proposal: MemoryProposal) -> dict[str, str]: ...


class ExecutionJournal(Protocol):
    def begin_execution(
        self,
        execution_id: str,
        log_id: str,
        activation: dict[str, object],
        grant: dict[str, object],
        *,
        request_fingerprint: str | None,
    ) -> bool: ...

    def append_event(
        self,
        execution_id: str,
        event: dict[str, object],
        *,
        expected_sequence: int,
        expected_previous_hash: str | None,
        expected_generation: int,
    ) -> None: ...

    def finalize(
        self,
        execution_id: str,
        receipt: dict[str, object],
        event: dict[str, object],
        *,
        expected_sequence: int,
        expected_previous_hash: str | None,
        expected_generation: int,
    ) -> None: ...


class Clock(Protocol):
    def now_ms(self) -> int: ...


class CancellationToken(Protocol):
    def is_cancelled(self) -> bool: ...
