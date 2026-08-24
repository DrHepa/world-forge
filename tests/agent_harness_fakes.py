from __future__ import annotations

import copy
from collections.abc import Callable, Sequence

from worldforge.agent_harness.ports import (
    ArtifactProposal,
    ExecutionJournal,
    MemoryProposal,
    ProviderTurnRequest,
    ToolCall,
    ToolResult,
)


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
    def __init__(self, script: Sequence[object]) -> None:
        self.script = list(script)
        self.requests: list[ProviderTurnRequest] = []

    def turn(self, request: ProviderTurnRequest) -> object:
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
    ) -> None:
        self.tool_id = tool_id
        self.required_capability_id = required_capability_id
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
        self.fail_next = False

    def append_event(
        self,
        execution_id: str,
        event: dict[str, object],
        *,
        expected_sequence: int,
        expected_previous_hash: str | None,
    ) -> None:
        if self.fail_next:
            self.fail_next = False
            raise ValueError("private tampered journal head")
        if expected_sequence != len(self.events):
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
        *,
        expected_sequence: int,
        expected_previous_hash: str | None,
    ) -> None:
        if self.receipt is not None or expected_sequence != len(self.events):
            raise ValueError("private finalization conflict")
        actual = None if not self.events else self.events[-1]["content_hash"]
        if expected_previous_hash != actual or event["execution_id"] != execution_id:
            raise ValueError("private finalization head mismatch")
        self.receipt = copy.deepcopy(receipt)
        self.events.append(copy.deepcopy(event))
