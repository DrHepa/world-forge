"""ProviderAdapter backed by one fresh code-owned runtime process per turn."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, replace

from .loopback_gateway import LoopbackGatewayPolicy
from .loopback_protocol import build_loopback_context_frame
from .ports import ProviderBoundaryControl, ProviderTurnRequest, ProviderTurnResult
from .process_supervisor import (
    LinuxProcessSupervisor,
    ProviderBoundaryFailure,
    ProviderBoundaryUnsupported,
    _capture_runtime_launch,
    _CodeOwnedRuntimeLaunch,
    _validate_runtime_launch,
)
from .provider_catalog import ProviderExecutionSelection, ProviderRuntimeCatalog
from .worker_protocol import (
    WorkerProtocolError,
    build_request_frame,
    parse_request_frame,
    parse_result_frame,
)
from .worker_registry import (
    _CodeOwnedRuntimeEntry,
    _CodeOwnedRuntimeKey,
    code_owned_provider_catalog,
    runtime_entry,
    runtime_entry_for_selection,
)

_MAX_PRIVATE_TURN_TIMEOUT_MS = 60_000
_GATEWAY_AUTHORITY_PROOF = object()


class _GatewayAuthorityCapability:
    __slots__ = (
        "_catalog_hash",
        "_dispatch",
        "_owner",
        "_policy_hash",
        "_process_supervisor",
        "_proof",
        "_runtime_launch",
        "_selection_hash",
        "_state",
    )

    def __init__(
        self,
        *,
        owner: OneShotProviderSupervisor,
        catalog: ProviderRuntimeCatalog,
        selection: ProviderExecutionSelection,
        policy: LoopbackGatewayPolicy,
        process_supervisor: LinuxProcessSupervisor,
        runtime_launch: _CodeOwnedRuntimeLaunch,
        dispatch: Callable[..., ProviderTurnResult],
        proof: object,
    ) -> None:
        if proof is not _GATEWAY_AUTHORITY_PROOF:
            raise ValueError("provider_runtime_unavailable")
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_catalog_hash", catalog.catalog_hash)
        object.__setattr__(self, "_selection_hash", selection.content_hash)
        object.__setattr__(self, "_policy_hash", policy.content_hash)
        object.__setattr__(self, "_process_supervisor", process_supervisor)
        object.__setattr__(self, "_runtime_launch", runtime_launch)
        object.__setattr__(self, "_dispatch", dispatch)
        object.__setattr__(self, "_state", "open")
        object.__setattr__(self, "_proof", proof)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("gateway authority is immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("gateway authority is immutable")


@dataclass(frozen=True, slots=True)
class _ProviderSupervisorAuthority:
    runtime: _CodeOwnedRuntimeEntry
    process_supervisor: LinuxProcessSupervisor
    runtime_launch: _CodeOwnedRuntimeLaunch
    turn_timeout_ms: int
    dispatch: Callable[..., ProviderTurnResult]
    gateway_policy: LoopbackGatewayPolicy | None
    provider_catalog: ProviderRuntimeCatalog | None
    provider_selection: ProviderExecutionSelection | None
    gateway_capability: _GatewayAuthorityCapability | None


class OneShotProviderSupervisor:
    """Run one exact code-owned runtime in a fresh containment domain."""

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("provider authority is immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("provider authority is immutable")

    def __init__(self, *, turn_timeout_ms: int = 30_000) -> None:
        self._initialize(
            runtime=runtime_entry(_CodeOwnedRuntimeKey.CONFORMANCE),
            turn_timeout_ms=turn_timeout_ms,
            gateway_policy=None,
            provider_catalog=None,
            provider_selection=None,
        )

    @classmethod
    def for_selection(
        cls,
        selection: object,
        *,
        turn_timeout_ms: int = 30_000,
        gateway_policy: LoopbackGatewayPolicy | None = None,
    ) -> OneShotProviderSupervisor:
        """Resolve one exact governed selection through the closed runtime table."""

        if gateway_policy is None:
            entry = runtime_entry_for_selection(selection)
            frozen_catalog = None
        else:
            if type(gateway_policy) is not LoopbackGatewayPolicy:
                raise ValueError("provider_runtime_unavailable")
            checked_policy = LoopbackGatewayPolicy.create(gateway_policy.endpoint_origin)
            if (
                checked_policy != gateway_policy
                or checked_policy.canonical_document != gateway_policy.canonical_document
            ):
                raise ValueError("provider_runtime_unavailable")
            frozen_catalog = code_owned_provider_catalog(gateway_policy=checked_policy)
            entry = runtime_entry_for_selection(selection, gateway_policy=checked_policy)
            gateway_policy = checked_policy
        if type(selection) is not ProviderExecutionSelection:
            raise ValueError("provider_runtime_unavailable")
        instance = cls.__new__(cls)
        instance._initialize(
            runtime=entry,
            turn_timeout_ms=turn_timeout_ms,
            gateway_policy=gateway_policy,
            provider_catalog=frozen_catalog,
            provider_selection=replace(selection),
        )
        return instance

    def _initialize(
        self,
        *,
        runtime: _CodeOwnedRuntimeEntry,
        turn_timeout_ms: int,
        gateway_policy: LoopbackGatewayPolicy | None,
        provider_catalog: ProviderRuntimeCatalog | None,
        provider_selection: ProviderExecutionSelection | None,
    ) -> None:
        if (
            type(turn_timeout_ms) is not int
            or not 1 <= turn_timeout_ms <= _MAX_PRIVATE_TURN_TIMEOUT_MS
        ):
            raise ValueError("provider_turn_timeout_invalid")
        if type(runtime) is not _CodeOwnedRuntimeEntry:
            raise ValueError("provider_runtime_unavailable")
        if gateway_policy is not None:
            if (
                runtime.key is not _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE
                or provider_catalog is None
                or provider_selection is None
                or turn_timeout_ms > gateway_policy.total_deadline_ms
                or provider_catalog.resolve(provider_selection).spec != runtime.spec
            ):
                raise ValueError("provider_runtime_unavailable")
        elif (
            provider_catalog is not None
            or provider_selection is not None
            and (
                runtime.key is _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE
                and runtime.spec.network_scope == "loopback"
            )
        ):
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
            gateway_policy=gateway_policy,
        )
        frozen_catalog = None if provider_catalog is None else provider_catalog.snapshot()
        frozen_selection = None if provider_selection is None else replace(provider_selection)
        gateway_capability = None
        if gateway_policy is not None:
            if frozen_catalog is None or frozen_selection is None:
                raise ValueError("provider_runtime_unavailable")
            gateway_capability = _GatewayAuthorityCapability(
                owner=self,
                catalog=frozen_catalog,
                selection=frozen_selection,
                policy=gateway_policy,
                process_supervisor=process_supervisor,
                runtime_launch=runtime_launch,
                dispatch=dispatch,
                proof=_GATEWAY_AUTHORITY_PROOF,
            )
        authority = _ProviderSupervisorAuthority(
            runtime=runtime,
            process_supervisor=process_supervisor,
            runtime_launch=runtime_launch,
            turn_timeout_ms=turn_timeout_ms,
            dispatch=dispatch,
            gateway_policy=gateway_policy,
            provider_catalog=frozen_catalog,
            provider_selection=frozen_selection,
            gateway_capability=gateway_capability,
        )
        object.__setattr__(self, "_authority", authority)
        gateway_validator = None
        if gateway_capability is not None:
            issued_owner = self
            issued_authority = authority
            issued_capability = gateway_capability
            issued_proof = _GATEWAY_AUTHORITY_PROOF

            def validate_gateway_issuance(
                candidate_owner: object,
                candidate_authority: object,
                candidate_capability: object,
            ) -> bool:
                return (
                    issued_proof is _GATEWAY_AUTHORITY_PROOF
                    and candidate_owner is issued_owner
                    and candidate_authority is issued_authority
                    and candidate_capability is issued_capability
                )

            gateway_validator = validate_gateway_issuance
        object.__setattr__(self, "_gateway_authority_validator", gateway_validator)

    @classmethod
    def _require_gateway_authority(
        cls,
        provider: object,
        catalog: object,
    ) -> ProviderExecutionSelection:
        """Validate the exact captured parent gateway authority as one unit."""

        try:
            if cls is not OneShotProviderSupervisor or type(provider) is not cls:
                raise ValueError
            if type(catalog) is not ProviderRuntimeCatalog:
                raise ValueError
            frozen_catalog = catalog.snapshot()
            authority = object.__getattribute__(provider, "_authority")
            if type(authority) is not _ProviderSupervisorAuthority:
                raise ValueError
            capability = authority.gateway_capability
            validator = object.__getattribute__(provider, "_gateway_authority_validator")
            policy = authority.gateway_policy
            selection = authority.provider_selection
            captured_catalog = authority.provider_catalog
            if (
                type(capability) is not _GatewayAuthorityCapability
                or not callable(validator)
                or validator(provider, authority, capability) is not True
                or capability._proof is not _GATEWAY_AUTHORITY_PROOF
                or capability._owner is not provider
                or capability._state != "open"
                or type(policy) is not LoopbackGatewayPolicy
                or type(selection) is not ProviderExecutionSelection
                or type(captured_catalog) is not ProviderRuntimeCatalog
                or type(authority.runtime) is not _CodeOwnedRuntimeEntry
                or authority.runtime.key is not _CodeOwnedRuntimeKey.DETERMINISTIC_PROBE
                or authority.runtime.spec.network_scope != "loopback"
                or type(authority.runtime_launch) is not _CodeOwnedRuntimeLaunch
                or type(authority.process_supervisor) is not LinuxProcessSupervisor
                or capability._catalog_hash != frozen_catalog.catalog_hash
                or capability._selection_hash != selection.content_hash
                or capability._policy_hash != policy.content_hash
                or capability._process_supervisor is not authority.process_supervisor
                or capability._runtime_launch is not authority.runtime_launch
                or capability._dispatch is not authority.dispatch
                or authority.process_supervisor._runtime_launch is not authority.runtime_launch
            ):
                raise ValueError
            checked_policy = LoopbackGatewayPolicy.create(policy.endpoint_origin)
            if checked_policy != policy or checked_policy.content_hash != capability._policy_hash:
                raise ValueError
            expected_catalog = code_owned_provider_catalog(gateway_policy=checked_policy)
            if (
                captured_catalog.snapshot() != expected_catalog
                or frozen_catalog != expected_catalog
                or captured_catalog != frozen_catalog
            ):
                raise ValueError
            resolved = frozen_catalog.resolve(selection)
            expected_runtime = runtime_entry_for_selection(
                selection,
                gateway_policy=checked_policy,
            )
            checked_launch = _validate_runtime_launch(authority.runtime_launch)
            if (
                resolved.spec != authority.runtime.spec
                or expected_runtime != authority.runtime
                or checked_launch != authority.runtime_launch
                or not 1 <= authority.turn_timeout_ms <= checked_policy.total_deadline_ms
            ):
                raise ValueError
            return replace(selection)
        except BaseException as exc:
            if not isinstance(exc, Exception):
                raise
            raise ValueError("provider_gateway_authority_invalid") from None

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
    def gateway_policy(self) -> LoopbackGatewayPolicy | None:
        return self._authority.gateway_policy

    @property
    def provider_catalog(self) -> ProviderRuntimeCatalog | None:
        value = self._authority.provider_catalog
        return None if value is None else value.snapshot()

    @property
    def provider_selection(self) -> ProviderExecutionSelection | None:
        value = self._authority.provider_selection
        return None if value is None else replace(value)

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
    gateway_policy: LoopbackGatewayPolicy | None,
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
        process_values = {
            "worker_key": key,
            "boundary": boundary,
            "turn_timeout_ms": turn_timeout_ms,
            "runtime_key": runtime.key,
            "runtime_launch": runtime_launch,
        }
        if gateway_policy is not None:
            try:
                context_frame = build_loopback_context_frame(
                    key=key,
                    nonce=nonce,
                    runtime=runtime.runtime_binding,
                    original_request_hash=request_hash,
                    gateway_policy_hash=gateway_policy.content_hash,
                )
            except Exception:
                raise ProviderBoundaryFailure() from None
            process_values.update(
                {
                    "gateway_policy": gateway_policy,
                    "worker_nonce": nonce,
                    "original_request_hash": request_hash,
                    "gateway_context_frame": context_frame,
                }
            )
        report = process_execute(frame, **process_values)
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
