from __future__ import annotations

import copy
from collections.abc import Callable, Sequence

from worldforge.agent_harness.ports import (
    ArtifactProposal,
    ExecutionJournal,
    MemoryProposal,
    ProviderBoundaryControl,
    ProviderTurnRequest,
    ToolCall,
    ToolResult,
)
from worldforge.agent_harness.worker_registry import fixed_runtime_identity

_DEFAULT_RUNTIME_BINDING = object()


class FakeClock:
    def __init__(self, now_ms: int = 1_000) -> None:
        self.value = now_ms

    def now_ms(self) -> int:
        return self.value

    def advance(self, milliseconds: int) -> None:
        self.value += milliseconds


class FakeCancellation:
    def __init__(self, *, cancel_on_check: int | None = None) -> None:
        self.cancel_on_check = cancel_on_check
        self.checks = 0
        self.cancelled = False

    def is_cancelled(self) -> bool:
        self.checks += 1
        return self.cancelled or (
            self.cancel_on_check is not None and self.checks >= self.cancel_on_check
        )


class FakeProvider:
    def __init__(
        self,
        script: Sequence[object],
        *,
        runtime_binding: object = _DEFAULT_RUNTIME_BINDING,
    ) -> None:
        self.script = list(script)
        self.requests: list[ProviderTurnRequest] = []
        self._runtime_binding = (
            fixed_runtime_identity()
            if runtime_binding is _DEFAULT_RUNTIME_BINDING
            else runtime_binding
        )
        self.runtime_binding_reads = 0

    @property
    def runtime_binding(self) -> object:
        self.runtime_binding_reads += 1
        return self._runtime_binding

    def turn(
        self,
        request: ProviderTurnRequest,
        *,
        boundary: ProviderBoundaryControl,
    ) -> object:
        del boundary
        self.requests.append(request)
        if not self.script:
            raise RuntimeError("private provider exhaustion")
        action = self.script.pop(0)
        if isinstance(action, BaseException):
            raise action
        if callable(action):
            action = action(request)
        return action


class FakeTool:
    def __init__(
        self,
        tool_id: str,
        required_capability_id: str,
        result: ToolResult | BaseException | Callable[[ToolCall], ToolResult],
        *,
        summary: object | None = None,
        input_schema: object | None = None,
    ) -> None:
        self.tool_id = tool_id
        self.required_capability_id = required_capability_id
        self.summary = tool_id if summary is None else summary
        self.input_schema = {"type": "object"} if input_schema is None else input_schema
        self.result = result
        self.calls: list[ToolCall] = []

    def invoke(self, call: ToolCall) -> ToolResult:
        self.calls.append(call)
        if isinstance(self.result, BaseException):
            raise self.result
        if callable(self.result):
            return self.result(call)
        return self.result


class FakeArtifactPort:
    def __init__(self, identities: Sequence[dict[str, str] | BaseException]) -> None:
        self.identities = list(identities)
        self.proposals: list[ArtifactProposal] = []

    def propose(self, proposal: ArtifactProposal) -> dict[str, str]:
        self.proposals.append(proposal)
        value = self.identities.pop(0)
        if isinstance(value, BaseException):
            raise value
        return copy.deepcopy(value)


class FakeMemoryPort:
    def __init__(self, identities: Sequence[dict[str, str] | BaseException]) -> None:
        self.identities = list(identities)
        self.proposals: list[MemoryProposal] = []

    def propose(self, proposal: MemoryProposal) -> dict[str, str]:
        self.proposals.append(proposal)
        value = self.identities.pop(0)
        if isinstance(value, BaseException):
            raise value
        return copy.deepcopy(value)


class FakeJournal(ExecutionJournal):
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []
        self.receipt: dict[str, object] | None = None
        self.usage_accounting: dict[str, object] | None = None
        self.fail_next = False
        self.operations: list[str] = []
        self.begin_calls: list[
            tuple[str, str, dict[str, object], dict[str, object], str | None]
        ] = []
        self.begin_result: bool | BaseException = True

    def begin_execution(
        self,
        execution_id: str,
        log_id: str,
        activation: dict[str, object],
        grant: dict[str, object],
        *,
        request_fingerprint: str | None,
    ) -> bool:
        self.operations.append("begin")
        self.begin_calls.append(
            (
                execution_id,
                log_id,
                copy.deepcopy(activation),
                copy.deepcopy(grant),
                request_fingerprint,
            )
        )
        if isinstance(self.begin_result, BaseException):
            raise self.begin_result
        return self.begin_result

    def append_event(
        self,
        execution_id: str,
        event: dict[str, object],
        *,
        expected_sequence: int,
        expected_previous_hash: str | None,
        expected_generation: int,
    ) -> None:
        self.operations.append("append")
        if self.fail_next:
            self.fail_next = False
            raise ValueError("private tampered journal head")
        if expected_sequence != len(self.events) or expected_generation != len(self.events):
            raise ValueError("private sequence mismatch")
        actual = None if not self.events else self.events[-1]["content_hash"]
        if expected_previous_hash != actual:
            raise ValueError("private head mismatch")
        if event["execution_id"] != execution_id:
            raise ValueError("private execution mismatch")
        self.events.append(copy.deepcopy(event))

    def finalize(
        self,
        execution_id: str,
        receipt: dict[str, object],
        event: dict[str, object],
        usage_accounting: dict[str, object],
        *,
        expected_sequence: int,
        expected_previous_hash: str | None,
        expected_generation: int,
    ) -> None:
        self.operations.append("finalize")
        if (
            self.receipt is not None
            or self.usage_accounting is not None
            or expected_sequence != len(self.events)
            or expected_generation != len(self.events)
        ):
            raise ValueError("private finalization conflict")
        actual = None if not self.events else self.events[-1]["content_hash"]
        if expected_previous_hash != actual or event["execution_id"] != execution_id:
            raise ValueError("private finalization head mismatch")
        self.receipt = copy.deepcopy(receipt)
        self.usage_accounting = copy.deepcopy(usage_accounting)
        self.events.append(copy.deepcopy(event))
