"""ProviderAdapter backed by one fresh code-owned runtime process per turn."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, replace

from .ports import ProviderBoundaryControl, ProviderTurnRequest, ProviderTurnResult
from .process_supervisor import (
    LinuxProcessSupervisor,
    ProviderBoundaryFailure,
    ProviderBoundaryUnsupported,
    _capture_runtime_launch,
    _CodeOwnedRuntimeLaunch,
)
from .worker_protocol import (
    WorkerProtocolError,
    build_request_frame,
    parse_request_frame,
    parse_result_frame,
)
from .worker_registry import (
    _CodeOwnedRuntimeEntry,
    _CodeOwnedRuntimeKey,
    runtime_entry,
    runtime_entry_for_selection,
)

_MAX_PRIVATE_TURN_TIMEOUT_MS = 60_000


@dataclass(frozen=True, slots=True)
class _ProviderSupervisorAuthority:
    runtime: _CodeOwnedRuntimeEntry
    process_supervisor: LinuxProcessSupervisor
    runtime_launch: _CodeOwnedRuntimeLaunch
    turn_timeout_ms: int
    dispatch: Callable[..., ProviderTurnResult]


class OneShotProviderSupervisor:
    """Run one exact code-owned offline runtime in a fresh containment domain."""

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("provider authority is immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("provider authority is immutable")

    def __init__(self, *, turn_timeout_ms: int = 30_000) -> None:
        self._initialize(
            runtime=runtime_entry(_CodeOwnedRuntimeKey.CONFORMANCE),
            turn_timeout_ms=turn_timeout_ms,
        )

    @classmethod
    def for_selection(
        cls,
        selection: object,
        *,
        turn_timeout_ms: int = 30_000,
    ) -> OneShotProviderSupervisor:
        """Resolve one exact governed selection through the closed runtime table."""

        entry = runtime_entry_for_selection(selection)
        instance = cls.__new__(cls)
        instance._initialize(runtime=entry, turn_timeout_ms=turn_timeout_ms)
        return instance

    def _initialize(
        self,
        *,
        runtime: _CodeOwnedRuntimeEntry,
        turn_timeout_ms: int,
    ) -> None:
        if (
            type(turn_timeout_ms) is not int
            or not 1 <= turn_timeout_ms <= _MAX_PRIVATE_TURN_TIMEOUT_MS
        ):
            raise ValueError("provider_turn_timeout_invalid")
        if type(runtime) is not _CodeOwnedRuntimeEntry:
            raise ValueError("provider_runtime_unavailable")
        if sys.platform.startswith("linux"):
            runtime_launch = _capture_runtime_launch(runtime)
            process_supervisor = LinuxProcessSupervisor(runtime_launch=runtime_launch)
        else:
            raise ProviderBoundaryUnsupported()
        dispatch = _bind_runtime_dispatch(
            runtime=runtime,
            runtime_launch=runtime_launch,
            turn_timeout_ms=turn_timeout_ms,
            process_execute=process_supervisor.execute,
            request_builder=build_request_frame,
            request_parser=parse_request_frame,
            result_parser=parse_result_frame,
        )
        object.__setattr__(
            self,
            "_authority",
            _ProviderSupervisorAuthority(
                runtime=runtime,
                process_supervisor=process_supervisor,
                runtime_launch=runtime_launch,
                turn_timeout_ms=turn_timeout_ms,
                dispatch=dispatch,
            ),
        )

    @property
    def _runtime_key(self) -> _CodeOwnedRuntimeKey:
        return self._authority.runtime.key

    @property
    def _process_supervisor(self) -> LinuxProcessSupervisor:
        return self._authority.process_supervisor

    @property
    def _turn_timeout_ms(self) -> int:
        return self._authority.turn_timeout_ms

    @property
    def spawn_count(self) -> int:
        return self._process_supervisor.spawn_count

    @property
    def runtime_binding(self) -> dict[str, object]:
        """Return the selected bootstrap-derived identity without caller aliases."""

        return self._authority.runtime.runtime_binding

    @property
    def runtime_spec(self):
        """Return the selected exact catalog descriptor without caller aliases."""

        return replace(self._authority.runtime.spec)

    @property
    def active_broker_pid(self) -> int | None:
        return self._process_supervisor.active_broker_pid

    @property
    def active_worker_pid(self) -> int | None:
        return self._process_supervisor.active_worker_pid

    @property
    def turn(self) -> Callable[..., ProviderTurnResult]:
        return self._authority.dispatch


def _bind_runtime_dispatch(
    *,
    runtime: _CodeOwnedRuntimeEntry,
    runtime_launch: _CodeOwnedRuntimeLaunch,
    turn_timeout_ms: int,
    process_execute: Callable[..., object],
    request_builder: Callable[..., bytes],
    request_parser: Callable[..., object],
    result_parser: Callable[..., ProviderTurnResult],
) -> Callable[..., ProviderTurnResult]:
    def dispatch(
        request: ProviderTurnRequest,
        *,
        boundary: ProviderBoundaryControl,
    ) -> ProviderTurnResult:
        if type(boundary) is not ProviderBoundaryControl:
            raise ProviderBoundaryFailure()
        key = os.urandom(32)
        nonce = os.urandom(32).hex()
        try:
            frame = request_builder(
                request,
                key=key,
                nonce=nonce,
                runtime_key=runtime.key,
                runtime_authority=runtime,
            )
            request_hash = request_parser(
                frame,
                key=key,
                runtime_key=runtime.key,
                runtime_authority=runtime,
            ).request_hash
        except WorkerProtocolError:
            raise ProviderBoundaryFailure() from None
        report = process_execute(
            frame,
            worker_key=key,
            boundary=boundary,
            turn_timeout_ms=turn_timeout_ms,
            runtime_key=runtime.key,
            runtime_launch=runtime_launch,
        )
        if report.response is None:
            raise ProviderBoundaryFailure()
        try:
            return result_parser(
                report.response,
                key=key,
                nonce=nonce,
                request_hash=request_hash,
                runtime_key=runtime.key,
                runtime_authority=runtime,
            )
        except WorkerProtocolError:
            raise ProviderBoundaryFailure() from None

    return dispatch


__all__ = ("OneShotProviderSupervisor",)
