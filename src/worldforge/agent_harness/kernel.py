"""Synchronous provider-free Agent Execution Kernel foundation."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, replace

from worldforge.agent_harness_contracts import (
    AGENT_CAPABILITY_GRANT_FORMAT,
    AGENT_EVENT_FORMAT,
    AGENT_EXECUTION_RECEIPT_FORMAT,
    AGENT_WORKER_ACTIVATION_FORMAT,
    MAX_AGENT_HARNESS_DOCUMENT_BYTES,
    MAX_AGENT_HARNESS_JSON_DEPTH,
    MAX_SAFE_INTEGER,
    AgentHarnessContractError,
    validate_agent_harness_document,
    validate_agent_harness_documents,
)

from .capability_broker import BrokerError, CapabilityBroker
from .ports import (
    ArtifactProposal,
    CancellationToken,
    Clock,
    ExecutionJournal,
    ExecutionLimits,
    ExecutionRequest,
    ExecutionResult,
    MemoryProposal,
    ProviderAdapter,
    ProviderBoundaryControl,
    ProviderTurnRequest,
    ProviderTurnResult,
    ProviderUsage,
    ToolCall,
)
from .process_supervisor import ProviderBoundaryIndeterminate, ProviderBoundaryStopped
from .records import build_event, build_receipt

_PORTABLE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TOOL_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}(?:\.[a-z][a-z0-9_]{1,63})+$")
_RUNTIME_BINDING_FIELDS = frozenset({"id", "revision", "content_hash"})
_MAX_PRIVATE_FIELD_BYTES = 64 * 1024
_MAX_ARTIFACT_PROPOSALS = 64
_MAX_MEMORY_PROPOSALS = 64
_INVALID_PRIVATE_INPUT = object()


class KernelError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class _ProviderRuntimeBinding:
    identifier: str
    revision: int
    content_hash: str

    def as_document(self) -> dict[str, object]:
        return {
            "id": self.identifier,
            "revision": self.revision,
            "content_hash": self.content_hash,
        }

    def matches(self, value: object) -> bool:
        return type(value) is dict and value == self.as_document()


@dataclass(frozen=True, slots=True)
class _ProviderAuthority:
    adapter: ProviderAdapter
    runtime_binding: _ProviderRuntimeBinding
    turn: Callable[..., object]


def _snapshot_provider_runtime_binding(provider: object) -> _ProviderRuntimeBinding:
    try:
        value = provider.runtime_binding
    except Exception:
        raise KernelError("provider_runtime_binding_invalid") from None
    if type(value) is not dict:
        raise KernelError("provider_runtime_binding_invalid")
    try:
        items = tuple(dict.items(value))
    except Exception:
        raise KernelError("provider_runtime_binding_invalid") from None
    if (
        len(items) != len(_RUNTIME_BINDING_FIELDS)
        or any(type(key) is not str for key, _item in items)
        or frozenset(key for key, _item in items) != _RUNTIME_BINDING_FIELDS
    ):
        raise KernelError("provider_runtime_binding_invalid")
    values = {key: item for key, item in items}
    identifier = values["id"]
    revision = values["revision"]
    content_hash = values["content_hash"]
    if (
        type(identifier) is not str
        or _PORTABLE_ID_RE.fullmatch(identifier) is None
        or type(revision) is not int
        or not 1 <= revision <= MAX_SAFE_INTEGER
        or type(content_hash) is not str
        or _SHA256_RE.fullmatch(content_hash) is None
    ):
        raise KernelError("provider_runtime_binding_invalid")
    return _ProviderRuntimeBinding(identifier, revision, content_hash)


def _snapshot_provider_authority(provider: object) -> _ProviderAuthority:
    runtime_binding = _snapshot_provider_runtime_binding(provider)
    try:
        turn = provider.turn
    except Exception:
        raise KernelError("provider_runtime_binding_invalid") from None
    if not callable(turn):
        raise KernelError("provider_runtime_binding_invalid")
    return _ProviderAuthority(provider, runtime_binding, turn)


def _bounded_integer(value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        raise KernelError("execution_limits_invalid")
    return value


def _validate_limits(limits: object) -> ExecutionLimits:
    if type(limits) is not ExecutionLimits:
        raise KernelError("execution_limits_invalid")
    try:
        max_turns = limits.max_turns
        max_tool_calls = limits.max_tool_calls
        max_total_tokens = limits.max_total_tokens
        max_cost_minor_units = limits.max_cost_minor_units
        currency = limits.currency
        max_duration_ms = limits.max_duration_ms
        deadline_ms = limits.deadline_ms
    except Exception:
        raise KernelError("execution_limits_invalid") from None
    _bounded_integer(max_turns, minimum=1)
    _bounded_integer(max_tool_calls)
    _bounded_integer(max_total_tokens)
    _bounded_integer(max_duration_ms)
    if max_turns > 64 or max_tool_calls > 128:
        raise KernelError("execution_limits_invalid")
    if deadline_ms is not None:
        _bounded_integer(deadline_ms)
    if max_cost_minor_units is not None:
        _bounded_integer(max_cost_minor_units)
    if (max_cost_minor_units is None) != (currency is None):
        raise KernelError("execution_limits_invalid")
    if currency is not None and (
        type(currency) is not str or re.fullmatch(r"[A-Z]{3}", currency) is None
    ):
        raise KernelError("execution_limits_invalid")
    return ExecutionLimits(
        max_turns=max_turns,
        max_tool_calls=max_tool_calls,
        max_total_tokens=max_total_tokens,
        max_cost_minor_units=max_cost_minor_units,
        currency=currency,
        max_duration_ms=max_duration_ms,
        deadline_ms=deadline_ms,
    )


def _exact_json_snapshot(value: object, *, reason_code: str) -> tuple[object, bytes]:
    active: set[int] = set()

    def snapshot(current: object, depth: int) -> object:
        if type(current) is dict:
            if depth > MAX_AGENT_HARNESS_JSON_DEPTH:
                raise KernelError(reason_code)
            identity = id(current)
            if identity in active:
                raise KernelError(reason_code)
            active.add(identity)
            try:
                result: dict[str, object] = {}
                for key, item in dict.items(current):
                    if type(key) is not str:
                        raise KernelError(reason_code)
                    result[key] = snapshot(item, depth + 1)
                return result
            finally:
                active.remove(identity)
        if type(current) is list:
            if depth > MAX_AGENT_HARNESS_JSON_DEPTH:
                raise KernelError(reason_code)
            identity = id(current)
            if identity in active:
                raise KernelError(reason_code)
            active.add(identity)
            try:
                return [snapshot(item, depth + 1) for item in list.__iter__(current)]
            finally:
                active.remove(identity)
        if current is None or type(current) in {bool, int, float, str}:
            return current
        raise KernelError(reason_code)

    try:
        closed = snapshot(value, 1)
        encoded = json.dumps(
            closed,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except KernelError:
        raise
    except Exception:
        raise KernelError(reason_code) from None
    if len(encoded) > MAX_AGENT_HARNESS_DOCUMENT_BYTES:
        raise KernelError(reason_code)
    return closed, encoded


def _journal_record_bytes(value: object, *, expected_format: str) -> bytes:
    closed, encoded = _exact_json_snapshot(value, reason_code="journal_corrupt")
    try:
        validate_agent_harness_document(closed, expected_format=expected_format)
    except KernelError:
        raise
    except Exception:
        raise KernelError("journal_corrupt") from None
    return encoded


def _prepared_execution_request(
    request: object,
) -> tuple[ExecutionRequest, dict[str, object], dict[str, object]]:
    if type(request) is not ExecutionRequest:
        raise KernelError("execution_request_invalid")
    try:
        activation_value = request.activation
        grant_value = request.grant
        log_id = request.log_id
        receipt_id = request.receipt_id
        event_id_prefix = request.event_id_prefix
        invocation_id_prefix = request.invocation_id_prefix
        limits_value = request.limits
        private_input = request.private_input
    except Exception:
        raise KernelError("execution_request_invalid") from None

    limits = _validate_limits(limits_value)
    for identifier in (log_id, receipt_id, event_id_prefix, invocation_id_prefix):
        if type(identifier) is not str or _PORTABLE_ID_RE.fullmatch(identifier) is None:
            raise KernelError("execution_request_invalid")
    if len(event_id_prefix) > 60 or len(invocation_id_prefix) > 60:
        raise KernelError("execution_request_invalid")

    activation, _ = _exact_json_snapshot(activation_value, reason_code="execution_request_invalid")
    grant, _ = _exact_json_snapshot(grant_value, reason_code="execution_request_invalid")
    try:
        aggregate = validate_agent_harness_documents(activation, grant)
    except KernelError:
        raise
    except Exception:
        raise KernelError("execution_request_invalid") from None
    prepared = ExecutionRequest(
        activation=aggregate.activation,
        grant=aggregate.grant,
        log_id=log_id,
        receipt_id=receipt_id,
        event_id_prefix=event_id_prefix,
        invocation_id_prefix=invocation_id_prefix,
        limits=limits,
        private_input=private_input,
    )
    return prepared, aggregate.activation, aggregate.grant


def _private_bytes(value: object) -> bytes:
    _, encoded = _private_snapshot(value)
    return encoded


def _private_snapshot(value: object) -> tuple[object, bytes]:
    closed, encoded = _exact_json_snapshot(value, reason_code="private_field_invalid")
    if len(encoded) > _MAX_PRIVATE_FIELD_BYTES:
        raise KernelError("private_field_invalid")
    return closed, encoded


def _execution_request_fingerprint(
    request: ExecutionRequest,
    activation: dict[str, object],
    grant: dict[str, object],
    private_input_bytes: bytes,
) -> str:
    limits = request.limits
    controls = {
        "format": "world-forge.private.agent_execution_request_fingerprint",
        "format_version": 1,
        "execution_id": activation["execution_id"],
        "activation_hash": activation["content_hash"],
        "grant_hash": grant["content_hash"],
        "log_id": request.log_id,
        "receipt_id": request.receipt_id,
        "event_id_prefix": request.event_id_prefix,
        "invocation_id_prefix": request.invocation_id_prefix,
        "limits": {
            "max_turns": limits.max_turns,
            "max_tool_calls": limits.max_tool_calls,
            "max_total_tokens": limits.max_total_tokens,
            "max_cost_minor_units": limits.max_cost_minor_units,
            "currency": limits.currency,
            "max_duration_ms": limits.max_duration_ms,
            "deadline_ms": limits.deadline_ms,
        },
        "private_input_hash": hashlib.sha256(private_input_bytes).hexdigest(),
    }
    return hashlib.sha256(
        json.dumps(
            controls,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _sealed_private_value(value: object) -> object:
    """Return a plain JSON-owned snapshot with no aliases to untrusted objects."""

    closed, _ = _private_snapshot(value)
    return closed


def _request_hash(call: ToolCall) -> str:
    if (
        type(call) is not ToolCall
        or type(call.tool_id) is not str
        or len(call.tool_id) > 1024
        or _TOOL_ID_RE.fullmatch(call.tool_id) is None
    ):
        raise KernelError("tool_call_invalid")
    try:
        private_arguments = _private_bytes(call.private_arguments)
        copy.deepcopy(call)
    except (KernelError, Exception):
        raise KernelError("tool_call_invalid") from None
    return hashlib.sha256(call.tool_id.encode("utf-8") + b"\0" + private_arguments).hexdigest()


@dataclass(frozen=True, slots=True)
class _PreparedProviderTurn:
    private_output: object
    tool_calls: tuple[ToolCall, ...]
    request_hashes: tuple[str, ...]
    artifact_proposals: tuple[ArtifactProposal, ...]
    memory_proposals: tuple[MemoryProposal, ...]
    completed: bool


@dataclass(slots=True)
class BudgetLedger:
    limits: ExecutionLimits
    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0
    cost_minor_units: int | None = None
    currency: str | None = None
    turns: int = 0
    tool_calls: int = 0
    artifact_proposals: int = 0
    memory_proposals: int = 0

    def __post_init__(self) -> None:
        if self.limits.max_cost_minor_units is not None:
            self.cost_minor_units = 0
            self.currency = self.limits.currency

    def add_usage(self, usage: ProviderUsage) -> None:
        if type(usage) is not ProviderUsage:
            raise KernelError("provider_usage_invalid")
        values = (usage.input_tokens, usage.output_tokens, usage.cached_input_tokens)
        if any(type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER for value in values):
            raise KernelError("provider_usage_invalid")
        if usage.cached_input_tokens > usage.input_tokens:
            raise KernelError("provider_usage_invalid")
        if (usage.cost_minor_units is None) != (usage.currency is None):
            raise KernelError("provider_usage_invalid")
        if self.limits.max_cost_minor_units is None and usage.cost_minor_units is not None:
            raise KernelError("provider_usage_invalid")
        if self.limits.max_cost_minor_units is not None and usage.cost_minor_units is None:
            raise KernelError("provider_usage_invalid")
        if usage.cost_minor_units is not None and (
            type(usage.cost_minor_units) is not int
            or not 0 <= usage.cost_minor_units <= MAX_SAFE_INTEGER
        ):
            raise KernelError("provider_usage_invalid")
        if usage.currency is not None and type(usage.currency) is not str:
            raise KernelError("provider_usage_invalid")
        if usage.currency is not None and usage.currency != self.limits.currency:
            raise KernelError("provider_currency_mismatch")
        additions = (
            (self.input_tokens, usage.input_tokens),
            (self.output_tokens, usage.output_tokens),
            (self.cached_input_tokens, usage.cached_input_tokens),
        )
        if any(current > MAX_SAFE_INTEGER - added for current, added in additions):
            raise KernelError("provider_usage_invalid")
        if (
            self.input_tokens + self.output_tokens
            > MAX_SAFE_INTEGER - usage.input_tokens - usage.output_tokens
        ):
            raise KernelError("provider_usage_invalid")
        new_input = self.input_tokens + usage.input_tokens
        new_output = self.output_tokens + usage.output_tokens
        new_cached = self.cached_input_tokens + usage.cached_input_tokens
        if usage.cost_minor_units is None:
            if self.turns > 0 and self.cost_minor_units is not None:
                raise KernelError("provider_usage_invalid")
            new_cost = None
            new_currency = None
        else:
            if self.cost_minor_units is None:
                raise KernelError("provider_usage_invalid")
            if self.cost_minor_units > MAX_SAFE_INTEGER - usage.cost_minor_units:
                raise KernelError("provider_usage_invalid")
            new_cost = self.cost_minor_units + usage.cost_minor_units
            new_currency = usage.currency

        # Valid reported usage is incurred evidence even when it crosses a budget.
        self.input_tokens = new_input
        self.output_tokens = new_output
        self.cached_input_tokens = new_cached
        self.cost_minor_units = new_cost
        self.currency = new_currency
        self.turns += 1
        if new_input + new_output > self.limits.max_total_tokens:
            raise KernelError("token_budget_exceeded")
        if (
            self.limits.max_cost_minor_units is not None
            and new_cost is not None
            and new_cost > self.limits.max_cost_minor_units
        ):
            raise KernelError("cost_budget_exceeded")


class AgentExecutionKernel:
    def __setattr__(self, name: str, value: object) -> None:
        if name == "_provider_authority":
            try:
                object.__getattribute__(self, name)
            except AttributeError:
                pass
            else:
                raise AttributeError("provider authority is immutable")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if name == "_provider_authority":
            raise AttributeError("provider authority is immutable")
        object.__delattr__(self, name)

    def __init__(
        self,
        *,
        provider: ProviderAdapter,
        broker: CapabilityBroker,
        journal: ExecutionJournal,
        clock: Clock,
        cancellation: CancellationToken,
    ) -> None:
        self._provider_authority = _snapshot_provider_authority(provider)
        self.broker = broker
        self.journal = journal
        self.clock = clock
        self.cancellation = cancellation
        self._active_execution_id: str | None = None

    @property
    def provider(self) -> ProviderAdapter:
        return self._provider_authority.adapter

    @property
    def _provider(self) -> ProviderAdapter:
        return self._provider_authority.adapter

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        if type(request) is not ExecutionRequest:
            raise KernelError("execution_request_invalid")
        if self._active_execution_id is not None:
            raise KernelError("execution_reentrant")
        request, activation, grant = _prepared_execution_request(request)
        provider_authority = self._provider_authority
        provider_runtime_matches = provider_authority.runtime_binding.matches(activation["runtime"])
        execution_id = activation["execution_id"]
        self._active_execution_id = execution_id
        lease: object | None = None
        try:
            start_ms = self._safe_now()
            initial_reason = self._cancellation_reason(request.limits, start_ms)
            try:
                private_input, private_input_bytes = _private_snapshot(request.private_input)
            except KernelError:
                private_input = _INVALID_PRIVATE_INPUT
                request_fingerprint = None
            else:
                request_fingerprint = _execution_request_fingerprint(
                    request,
                    activation,
                    grant,
                    private_input_bytes,
                )
            request = replace(request, private_input=private_input)
            journal_activation = copy.deepcopy(activation)
            journal_grant = copy.deepcopy(grant)
            expected_journal_activation = _journal_record_bytes(
                journal_activation, expected_format=AGENT_WORKER_ACTIVATION_FORMAT
            )
            expected_journal_grant = _journal_record_bytes(
                journal_grant, expected_format=AGENT_CAPABILITY_GRANT_FORMAT
            )
            try:
                begun = self.journal.begin_execution(
                    execution_id,
                    request.log_id,
                    journal_activation,
                    journal_grant,
                    request_fingerprint=request_fingerprint,
                )
            except Exception:
                actual_activation = _journal_record_bytes(
                    journal_activation, expected_format=AGENT_WORKER_ACTIVATION_FORMAT
                )
                actual_grant = _journal_record_bytes(
                    journal_grant, expected_format=AGENT_CAPABILITY_GRANT_FORMAT
                )
                if (
                    actual_activation != expected_journal_activation
                    or actual_grant != expected_journal_grant
                ):
                    raise KernelError("journal_corrupt") from None
                raise KernelError("journal_begin_ambiguous") from None
            actual_activation = _journal_record_bytes(
                journal_activation, expected_format=AGENT_WORKER_ACTIVATION_FORMAT
            )
            actual_grant = _journal_record_bytes(
                journal_grant, expected_format=AGENT_CAPABILITY_GRANT_FORMAT
            )
            if (
                actual_activation != expected_journal_activation
                or actual_grant != expected_journal_grant
            ):
                raise KernelError("journal_corrupt")
            if type(begun) is not bool:
                raise KernelError("journal_begin_ambiguous")
            if not begun:
                raise KernelError("execution_already_recorded")
            after_begin_reason = self._cancellation_reason(request.limits, start_ms)
            if initial_reason is None:
                initial_reason = after_begin_reason
            if initial_reason is None and provider_runtime_matches:
                try:
                    lease = self.broker.activate(execution_id)
                except BrokerError:
                    raise KernelError("execution_reentrant") from None
                except Exception:
                    raise KernelError("broker_activation_failed") from None
            return self._execute_validated(
                request,
                activation,
                grant,
                start_ms=start_ms,
                initial_reason=initial_reason,
                provider_runtime_matches=provider_runtime_matches,
                provider_turn=provider_authority.turn,
            )
        finally:
            try:
                if lease is not None:
                    self.broker.release(execution_id, lease)
            finally:
                self._active_execution_id = None

    def _execute_validated(
        self,
        request: ExecutionRequest,
        activation: dict[str, object],
        grant: dict[str, object],
        *,
        start_ms: int,
        initial_reason: str | None,
        provider_runtime_matches: bool,
        provider_turn: Callable[..., object],
    ) -> ExecutionResult:
        ledger = BudgetLedger(request.limits)
        events: list[dict[str, object]] = []
        invocations: list[dict[str, object]] = []
        artifacts: list[dict[str, str]] = []
        history: list[object] = []
        private_output: object = None
        effective_capabilities = frozenset(grant["effective_capability_ids"])
        effective_tools = frozenset(grant["effective_tool_ids"])
        outcome = "failed"
        failure_codes: list[str] = []

        if initial_reason is not None:
            outcome, failure_codes = "cancelled", [initial_reason]
        elif not provider_runtime_matches:
            outcome, failure_codes = "failed", ["provider_failed"]
        else:
            try:
                private_input = _sealed_private_value(request.private_input)
            except (KernelError, Exception):
                outcome, failure_codes = "failed", ["private_field_invalid"]
            else:
                for event_type, subject_format, subject_id, subject_hash in (
                    (
                        "worker.activated",
                        AGENT_WORKER_ACTIVATION_FORMAT,
                        str(activation["activation_id"]),
                        str(activation["content_hash"]),
                    ),
                    (
                        "grant.issued",
                        AGENT_CAPABILITY_GRANT_FORMAT,
                        str(grant["grant_id"]),
                        str(grant["content_hash"]),
                    ),
                    (
                        "execution.started",
                        AGENT_WORKER_ACTIVATION_FORMAT,
                        str(activation["activation_id"]),
                        str(activation["content_hash"]),
                    ),
                ):
                    reason = self._append_event(
                        request,
                        activation,
                        grant,
                        events,
                        event_type,
                        subject_format,
                        subject_id,
                        subject_hash,
                        start_ms=start_ms,
                    )
                    if reason is not None:
                        outcome, failure_codes = "cancelled", [reason]
                        break
                else:
                    outcome, failure_codes, private_output = self._run_turns(
                        request,
                        activation,
                        grant,
                        ledger,
                        invocations,
                        artifacts,
                        history,
                        effective_capabilities,
                        effective_tools,
                        private_input,
                        start_ms,
                        provider_turn,
                    )

        return self._finalize_result(
            request=request,
            activation=activation,
            grant=grant,
            ledger=ledger,
            events=events,
            invocations=invocations,
            artifacts=artifacts,
            outcome=outcome,
            failure_codes=failure_codes,
            private_output=private_output,
            start_ms=start_ms,
        )

    def _run_turns(
        self,
        request: ExecutionRequest,
        activation: dict[str, object],
        grant: dict[str, object],
        ledger: BudgetLedger,
        invocations: list[dict[str, object]],
        artifacts: list[dict[str, str]],
        history: list[object],
        effective_capabilities: frozenset[str],
        effective_tools: frozenset[str],
        private_input: object,
        start_ms: int,
        provider_turn: Callable[..., object],
    ) -> tuple[str, list[str], object]:
        execution_id = str(activation["execution_id"])
        private_output: object = None
        while ledger.turns < request.limits.max_turns:
            reason = self._cancellation_reason(request.limits, start_ms)
            if reason is not None:
                return "cancelled", [reason], None
            try:
                safe_history = _sealed_private_value(history)
                turn_request = ProviderTurnRequest(
                    execution_id=execution_id,
                    turn_index=ledger.turns,
                    private_input=copy.deepcopy(private_input),
                    history=tuple(safe_history),
                )
            except (KernelError, Exception):
                return "failed", ["private_field_invalid"], None
            reason = self._cancellation_reason(request.limits, start_ms)
            if reason is not None:
                return "cancelled", [reason], None
            try:
                turn = provider_turn(
                    turn_request,
                    boundary=ProviderBoundaryControl(
                        lambda: self._cancellation_reason(request.limits, start_ms)
                    ),
                )
            except ProviderBoundaryIndeterminate:
                # Containment uncertainty is not a provider failure.  The
                # durable prefix must remain open for exclusive recovery.
                raise
            except ProviderBoundaryStopped as exc:
                return "cancelled", [exc.reason_code], None
            except Exception:
                reason = self._cancellation_reason(request.limits, start_ms)
                if reason is not None:
                    return "cancelled", [reason], None
                return "failed", ["provider_failed"], None

            if type(turn) is not ProviderTurnResult:
                reason = self._cancellation_reason(request.limits, start_ms)
                if reason is not None:
                    return "cancelled", [reason], None
                return "failed", ["provider_result_invalid"], None
            try:
                usage = turn.usage
            except Exception:
                self._cancellation_reason(request.limits, start_ms)
                return "failed", ["provider_result_invalid"], None
            try:
                ledger.add_usage(usage)
            except KernelError as exc:
                self._cancellation_reason(request.limits, start_ms)
                return "failed", [exc.reason_code], None
            except Exception:
                self._cancellation_reason(request.limits, start_ms)
                return "failed", ["provider_usage_invalid"], None

            # Valid incurred usage is sealed before cancellation can win at this boundary.
            reason = self._cancellation_reason(request.limits, start_ms)
            if reason is not None:
                return "cancelled", [reason], None
            try:
                prepared = self._preflight_provider_result(
                    turn,
                    remaining_tool_calls=request.limits.max_tool_calls - ledger.tool_calls,
                    remaining_artifact_proposals=(
                        _MAX_ARTIFACT_PROPOSALS - ledger.artifact_proposals
                    ),
                    remaining_memory_proposals=(_MAX_MEMORY_PROPOSALS - ledger.memory_proposals),
                )
            except KernelError as exc:
                reason = self._cancellation_reason(request.limits, start_ms)
                if reason is not None:
                    return "cancelled", [reason], None
                return "failed", [exc.reason_code], None

            # Preflight can traverse private provider values, so check its boundary again.
            reason = self._cancellation_reason(request.limits, start_ms)
            if reason is not None:
                return "cancelled", [reason], None
            try:
                self.broker.preflight(
                    execution_id,
                    tool_calls=prepared.tool_calls,
                    artifact_count=len(prepared.artifact_proposals),
                    memory_count=len(prepared.memory_proposals),
                    effective_capabilities=effective_capabilities,
                    effective_tools=effective_tools,
                )
            except BrokerError as exc:
                reason = self._cancellation_reason(request.limits, start_ms)
                if reason is not None:
                    return "cancelled", [reason], None
                return "failed", [exc.reason_code], None
            except Exception:
                reason = self._cancellation_reason(request.limits, start_ms)
                if reason is not None:
                    return "cancelled", [reason], None
                return "failed", ["broker_preflight_failed"], None

            for call, request_hash in zip(
                prepared.tool_calls, prepared.request_hashes, strict=True
            ):
                reason = self._cancellation_reason(request.limits, start_ms)
                if reason is not None:
                    return "cancelled", [reason], None
                invocation = {
                    "invocation_id": f"{request.invocation_id_prefix}_{len(invocations):03d}",
                    "sequence": len(invocations),
                    "tool_id": call.tool_id,
                    "request_hash": request_hash,
                    "outcome": "failed",
                    "result_artifacts": [],
                    "failure_codes": ["tool_failed"],
                }
                ledger.tool_calls += 1
                try:
                    tool_result = self.broker.invoke_tool(
                        execution_id,
                        call,
                        effective_capabilities=effective_capabilities,
                        effective_tools=effective_tools,
                    )
                except BrokerError as exc:
                    reason = (
                        self._cancellation_reason(request.limits, start_ms) if exc.invoked else None
                    )
                    if reason is not None:
                        invocation["outcome"] = "cancelled"
                        invocation["failure_codes"] = [reason]
                        invocations.append(invocation)
                        return "cancelled", [reason], None
                    if exc.invoked:
                        invocation["failure_codes"] = [exc.reason_code]
                        invocations.append(invocation)
                    else:
                        ledger.tool_calls -= 1
                    return "failed", [exc.reason_code], None
                except Exception:
                    reason = self._cancellation_reason(request.limits, start_ms)
                    if reason is not None:
                        invocation["outcome"] = "cancelled"
                        invocation["failure_codes"] = [reason]
                        invocations.append(invocation)
                        return "cancelled", [reason], None
                    invocation["failure_codes"] = ["tool_failed"]
                    invocations.append(invocation)
                    return "failed", ["tool_failed"], None
                reason = self._cancellation_reason(request.limits, start_ms)
                if reason is not None:
                    invocation["outcome"] = "cancelled"
                    invocation["failure_codes"] = [reason]
                    invocations.append(invocation)
                    return "cancelled", [reason], None
                try:
                    safe_tool_output = _sealed_private_value(tool_result.private_output)
                except Exception:
                    reason = self._cancellation_reason(request.limits, start_ms)
                    if reason is not None:
                        invocation["outcome"] = "cancelled"
                        invocation["failure_codes"] = [reason]
                        invocations.append(invocation)
                        return "cancelled", [reason], None
                    invocation["failure_codes"] = ["tool_result_invalid"]
                    invocations.append(invocation)
                    return "failed", ["tool_result_invalid"], None
                invocation["outcome"] = "succeeded"
                invocation["failure_codes"] = []
                invocations.append(invocation)
                history.append(safe_tool_output)

            for proposal in prepared.artifact_proposals:
                reason = self._cancellation_reason(request.limits, start_ms)
                if reason is not None:
                    return "cancelled", [reason], None
                ledger.artifact_proposals += 1
                try:
                    identity = self.broker.propose_artifact(
                        execution_id,
                        proposal,
                        effective_capabilities=effective_capabilities,
                    )
                except BrokerError as exc:
                    reason = (
                        self._cancellation_reason(request.limits, start_ms) if exc.invoked else None
                    )
                    if reason is not None:
                        return "cancelled", [reason], None
                    return "failed", [exc.reason_code], None
                except Exception:
                    reason = self._cancellation_reason(request.limits, start_ms)
                    if reason is not None:
                        return "cancelled", [reason], None
                    return "failed", ["artifact_proposal_failed"], None
                artifacts.append(identity.as_document())
                reason = self._cancellation_reason(request.limits, start_ms)
                if reason is not None:
                    return "cancelled", [reason], None

            for proposal in prepared.memory_proposals:
                reason = self._cancellation_reason(request.limits, start_ms)
                if reason is not None:
                    return "cancelled", [reason], None
                ledger.memory_proposals += 1
                try:
                    self.broker.propose_memory(
                        execution_id,
                        proposal,
                        effective_capabilities=effective_capabilities,
                    )
                except BrokerError as exc:
                    reason = (
                        self._cancellation_reason(request.limits, start_ms) if exc.invoked else None
                    )
                    if reason is not None:
                        return "cancelled", [reason], None
                    return "failed", [exc.reason_code], None
                except Exception:
                    reason = self._cancellation_reason(request.limits, start_ms)
                    if reason is not None:
                        return "cancelled", [reason], None
                    return "failed", ["memory_proposal_failed"], None
                reason = self._cancellation_reason(request.limits, start_ms)
                if reason is not None:
                    return "cancelled", [reason], None

            private_output = copy.deepcopy(prepared.private_output)
            history.append(copy.deepcopy(prepared.private_output))
            if prepared.completed:
                return "succeeded", [], private_output
        return "failed", ["turn_budget_exceeded"], None

    @staticmethod
    def _preflight_provider_result(
        turn: object,
        *,
        remaining_tool_calls: int,
        remaining_artifact_proposals: int,
        remaining_memory_proposals: int,
    ) -> _PreparedProviderTurn:
        try:
            if type(turn) is not ProviderTurnResult or type(turn.completed) is not bool:
                raise KernelError("provider_result_invalid")
            if (
                type(turn.tool_calls) is not tuple
                or type(turn.artifact_proposals) is not tuple
                or type(turn.memory_proposals) is not tuple
            ):
                raise KernelError("provider_result_invalid")
            if len(turn.tool_calls) > min(128, remaining_tool_calls):
                raise KernelError("tool_budget_exceeded")
            if len(turn.artifact_proposals) > min(
                _MAX_ARTIFACT_PROPOSALS, remaining_artifact_proposals
            ) or len(turn.memory_proposals) > min(
                _MAX_MEMORY_PROPOSALS, remaining_memory_proposals
            ):
                raise KernelError("provider_result_invalid")
            if any(type(call) is not ToolCall for call in turn.tool_calls):
                raise KernelError("provider_result_invalid")
            if any(
                type(proposal) is not ArtifactProposal for proposal in turn.artifact_proposals
            ) or any(type(proposal) is not MemoryProposal for proposal in turn.memory_proposals):
                raise KernelError("provider_result_invalid")
            try:
                private_output = _sealed_private_value(turn.private_output)
            except (KernelError, Exception):
                raise KernelError("provider_result_invalid") from None
            try:
                tool_calls = tuple(
                    ToolCall(call.tool_id, _sealed_private_value(call.private_arguments))
                    for call in turn.tool_calls
                )
                artifact_proposals = tuple(
                    ArtifactProposal(_sealed_private_value(proposal.private_payload))
                    for proposal in turn.artifact_proposals
                )
                memory_proposals = tuple(
                    MemoryProposal(_sealed_private_value(proposal.private_payload))
                    for proposal in turn.memory_proposals
                )
            except KernelError:
                raise KernelError("provider_result_invalid") from None
            request_hashes = tuple(_request_hash(call) for call in tool_calls)
            if len(request_hashes) != len(set(request_hashes)):
                raise KernelError("duplicate_tool_call")
            return _PreparedProviderTurn(
                private_output=private_output,
                tool_calls=tool_calls,
                request_hashes=request_hashes,
                artifact_proposals=artifact_proposals,
                memory_proposals=memory_proposals,
                completed=turn.completed,
            )
        except KernelError:
            raise
        except Exception:
            raise KernelError("provider_result_invalid") from None

    def _append_event(
        self,
        request: ExecutionRequest,
        activation: dict[str, object],
        grant: dict[str, object],
        events: list[dict[str, object]],
        event_type: str,
        subject_format: str,
        subject_id: str,
        subject_hash: str,
        *,
        start_ms: int,
        allow_cancelled: bool = False,
    ) -> str | None:
        before = self._cancellation_reason(request.limits, start_ms)
        if before is not None and not allow_cancelled:
            return before
        sequence = len(events)
        previous = None if not events else str(events[-1]["content_hash"])
        event = build_event(
            event_id=f"{request.event_id_prefix}_{sequence:03d}",
            log_id=request.log_id,
            execution_id=str(activation["execution_id"]),
            sequence=sequence,
            previous_event_hash=previous,
            event_type=event_type,
            subject_format=subject_format,
            subject_id=subject_id,
            subject_hash=subject_hash,
        )
        journal_event = copy.deepcopy(event)
        expected_journal_event = _journal_record_bytes(
            journal_event, expected_format=AGENT_EVENT_FORMAT
        )
        try:
            self.journal.append_event(
                str(activation["execution_id"]),
                journal_event,
                expected_sequence=sequence,
                expected_previous_hash=previous,
                expected_generation=sequence,
            )
        except Exception:
            actual_journal_event = _journal_record_bytes(
                journal_event, expected_format=AGENT_EVENT_FORMAT
            )
            if actual_journal_event != expected_journal_event:
                raise KernelError("journal_corrupt") from None
            raise KernelError("journal_append_ambiguous") from None
        actual_journal_event = _journal_record_bytes(
            journal_event, expected_format=AGENT_EVENT_FORMAT
        )
        if actual_journal_event != expected_journal_event:
            raise KernelError("journal_corrupt") from None
        after = self._cancellation_reason(request.limits, start_ms)
        events.append(event)
        try:
            validate_agent_harness_documents(activation, grant, events)
        except AgentHarnessContractError:
            raise KernelError("journal_corrupt") from None
        return after if after is not None else before

    def _finalize_result(
        self,
        *,
        request: ExecutionRequest,
        activation: dict[str, object],
        grant: dict[str, object],
        ledger: BudgetLedger,
        events: list[dict[str, object]],
        invocations: list[dict[str, object]],
        artifacts: list[dict[str, str]],
        outcome: str,
        failure_codes: list[str],
        private_output: object,
        start_ms: int,
    ) -> ExecutionResult:
        cancel_event_recorded = any(
            event["event_type"] == "execution.cancel_requested" for event in events
        )
        try:
            artifacts = self._sorted_unique_identities(artifacts)
        except KernelError as exc:
            outcome, failure_codes, private_output, artifacts = (
                "failed",
                [exc.reason_code],
                None,
                [],
            )

        while True:
            if outcome == "cancelled" and not cancel_event_recorded:
                self._append_event(
                    request,
                    activation,
                    grant,
                    events,
                    "execution.cancel_requested",
                    AGENT_WORKER_ACTIVATION_FORMAT,
                    str(activation["activation_id"]),
                    str(activation["content_hash"]),
                    start_ms=start_ms,
                    allow_cancelled=True,
                )
                cancel_event_recorded = True
            duration = self._duration(start_ms)
            if outcome == "succeeded" and duration > request.limits.max_duration_ms:
                outcome, failure_codes, private_output = (
                    "failed",
                    ["duration_budget_exceeded"],
                    None,
                )
            if outcome == "succeeded":
                failure_codes = []
            usage = {
                "input_tokens": ledger.input_tokens,
                "output_tokens": ledger.output_tokens,
                "cached_input_tokens": ledger.cached_input_tokens,
                "duration_ms": duration,
                "cost_minor_units": ledger.cost_minor_units,
                "currency": ledger.currency,
            }
            receipt = build_receipt(
                receipt_id=request.receipt_id,
                activation=activation,
                grant=grant,
                tool_invocations=invocations,
                result_artifacts=artifacts,
                usage=usage,
                outcome=outcome,
                failure_codes=failure_codes,
            )
            sequence = len(events)
            previous = None if not events else str(events[-1]["content_hash"])
            receipt_event = build_event(
                event_id=f"{request.event_id_prefix}_{sequence:03d}",
                log_id=request.log_id,
                execution_id=str(activation["execution_id"]),
                sequence=sequence,
                previous_event_hash=previous,
                event_type="execution.receipt_recorded",
                subject_format=AGENT_EXECUTION_RECEIPT_FORMAT,
                subject_id=str(receipt["receipt_id"]),
                subject_hash=str(receipt["content_hash"]),
            )
            try:
                validate_agent_harness_documents(
                    activation, grant, [*events, receipt_event], receipt
                )
            except AgentHarnessContractError:
                raise KernelError("kernel_record_invalid") from None
            journal_receipt = copy.deepcopy(receipt)
            journal_event = copy.deepcopy(receipt_event)
            expected_journal_receipt = _journal_record_bytes(
                journal_receipt, expected_format=AGENT_EXECUTION_RECEIPT_FORMAT
            )
            expected_journal_event = _journal_record_bytes(
                journal_event, expected_format=AGENT_EVENT_FORMAT
            )

            # This is the last cooperative check before the single atomic side effect.
            final_reason = self._cancellation_reason(request.limits, start_ms)
            if outcome == "succeeded" and final_reason is not None:
                outcome, failure_codes, private_output = "cancelled", [final_reason], None
                continue
            break

        try:
            self.journal.finalize(
                str(activation["execution_id"]),
                journal_receipt,
                journal_event,
                expected_sequence=sequence,
                expected_previous_hash=previous,
                expected_generation=sequence,
            )
        except Exception:
            actual_journal_receipt = _journal_record_bytes(
                journal_receipt, expected_format=AGENT_EXECUTION_RECEIPT_FORMAT
            )
            actual_journal_event = _journal_record_bytes(
                journal_event, expected_format=AGENT_EVENT_FORMAT
            )
            if (
                actual_journal_receipt != expected_journal_receipt
                or actual_journal_event != expected_journal_event
            ):
                raise KernelError("journal_corrupt") from None
            raise KernelError("journal_finalization_ambiguous") from None

        actual_journal_receipt = _journal_record_bytes(
            journal_receipt, expected_format=AGENT_EXECUTION_RECEIPT_FORMAT
        )
        actual_journal_event = _journal_record_bytes(
            journal_event, expected_format=AGENT_EVENT_FORMAT
        )
        if (
            actual_journal_receipt != expected_journal_receipt
            or actual_journal_event != expected_journal_event
        ):
            raise KernelError("journal_corrupt") from None
        post_reason = self._cancellation_reason(request.limits, start_ms)
        if outcome == "succeeded" and post_reason is not None:
            raise KernelError("journal_finalization_ambiguous")
        events.append(receipt_event)
        try:
            validate_agent_harness_documents(activation, grant, events, receipt)
        except AgentHarnessContractError:
            raise KernelError("kernel_record_invalid") from None
        return ExecutionResult(
            outcome,
            tuple(copy.deepcopy(events)),
            copy.deepcopy(receipt),
            copy.deepcopy(private_output) if outcome == "succeeded" else None,
        )

    def _safe_now(self) -> int:
        try:
            value = self.clock.now_ms()
        except Exception:
            raise KernelError("clock_invalid") from None
        if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
            raise KernelError("clock_invalid")
        return value

    def _duration(self, start_ms: int) -> int:
        now = self._safe_now()
        if now < start_ms:
            raise KernelError("clock_invalid")
        return now - start_ms

    def _cancellation_reason(self, limits: ExecutionLimits, start_ms: int) -> str | None:
        try:
            if self.cancellation.is_cancelled():
                return "execution_cancelled"
        except Exception:
            return "cancellation_check_failed"
        now = self._safe_now()
        if limits.deadline_ms is not None and now >= limits.deadline_ms:
            return "execution_deadline_exceeded"
        if now - start_ms > limits.max_duration_ms:
            return "duration_budget_exceeded"
        return None

    @staticmethod
    def _sorted_unique_identities(values: list[dict[str, str]]) -> list[dict[str, str]]:
        by_id: dict[str, dict[str, str]] = {}
        for value in values:
            if value["id"] in by_id:
                raise KernelError("artifact_result_invalid")
            by_id[value["id"]] = value
        return [by_id[key] for key in sorted(by_id)]
