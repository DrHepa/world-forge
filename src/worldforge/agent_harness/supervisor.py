"""ProviderAdapter backed by one fresh fixed-runtime process per turn."""

from __future__ import annotations

import os
import sys

from .ports import ProviderBoundaryControl, ProviderTurnRequest, ProviderTurnResult
from .process_supervisor import (
    LinuxProcessSupervisor,
    ProviderBoundaryFailure,
    ProviderBoundaryUnsupported,
)
from .worker_protocol import (
    WorkerProtocolError,
    build_request_frame,
    parse_result_frame,
)

_MAX_PRIVATE_TURN_TIMEOUT_MS = 60_000


class OneShotProviderSupervisor:
    """Run only the code-owned conformance runtime in a fresh containment domain."""

    def __init__(self, *, turn_timeout_ms: int = 30_000) -> None:
        if (
            type(turn_timeout_ms) is not int
            or not 1 <= turn_timeout_ms <= _MAX_PRIVATE_TURN_TIMEOUT_MS
        ):
            raise ValueError("provider_turn_timeout_invalid")
        if sys.platform.startswith("linux"):
            process_supervisor = LinuxProcessSupervisor()
        else:
            raise ProviderBoundaryUnsupported()
        self._process_supervisor = process_supervisor
        self._turn_timeout_ms = turn_timeout_ms

    @property
    def spawn_count(self) -> int:
        return self._process_supervisor.spawn_count

    @property
    def active_broker_pid(self) -> int | None:
        return self._process_supervisor.active_broker_pid

    @property
    def active_worker_pid(self) -> int | None:
        return self._process_supervisor.active_worker_pid

    def turn(
        self,
        request: ProviderTurnRequest,
        *,
        boundary: ProviderBoundaryControl,
    ) -> ProviderTurnResult:
        if type(boundary) is not ProviderBoundaryControl:
            raise ProviderBoundaryFailure()
        key = os.urandom(32)
        nonce = os.urandom(32).hex()
        try:
            frame = build_request_frame(request, key=key, nonce=nonce)
            request_hash = parse_request_frame_for_hash(frame, key=key)
        except WorkerProtocolError:
            raise ProviderBoundaryFailure() from None
        report = self._process_supervisor.execute(
            frame,
            worker_key=key,
            boundary=boundary,
            turn_timeout_ms=self._turn_timeout_ms,
        )
        if report.response is None:
            raise ProviderBoundaryFailure()
        try:
            return parse_result_frame(
                report.response,
                key=key,
                nonce=nonce,
                request_hash=request_hash,
            )
        except WorkerProtocolError:
            raise ProviderBoundaryFailure() from None


def parse_request_frame_for_hash(frame: bytes, *, key: bytes) -> str:
    """Keep the authenticated request hash code-owned and out of child output."""

    from .worker_protocol import parse_request_frame

    return parse_request_frame(frame, key=key).request_hash


__all__ = ("OneShotProviderSupervisor",)
