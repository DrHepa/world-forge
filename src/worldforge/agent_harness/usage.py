"""Private truthful provider-usage evidence and sanitized accounting records."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from weakref import ReferenceType, ref

from worldforge.agent_harness_contracts import MAX_SAFE_INTEGER

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_STATES = frozenset({"observed", "derived", "unavailable"})
_TOKEN_SOURCES = frozenset({"provider_result", "code_owned_runtime", "none"})
_COST_SOURCES = frozenset({"provider_result", "parent_pricing_policy", "none"})
_UNAVAILABLE_REASONS = frozenset(
    {
        "provider_omitted",
        "code_owned_policy_absent",
        "parent_pricing_unavailable",
        "legacy_receipt_only",
    }
)
_ACCOUNTING_FORMAT = "world-forge.private.provider_usage_accounting"
_ACCOUNTING_VERSION = 1
_LINEAGE_FORMAT = "world-forge.private.provider_accounting_lineage"
_LINEAGE_VERSION = 1
_CODE_OWNED_USAGE_POLICIES = {
    "worldforge_conformance_provider": {
        "format": "world-forge.private.code_owned_usage_policy",
        "format_version": 1,
        "policy_id": "conformance_synthetic_turn_unit",
        "policy_version": 1,
        "input_tokens": "one unit for each authenticated accepted request",
        "output_tokens": "one unit for each authenticated emitted result",
        "cached_input_tokens": "unavailable because this runtime has no cache observation",
    },
    "worldforge_deterministic_probe_provider": {
        "format": "world-forge.private.code_owned_usage_policy",
        "format_version": 1,
        "policy_id": "deterministic_probe_synthetic_turn_unit",
        "policy_version": 1,
        "input_tokens": "one unit for each authenticated accepted request",
        "output_tokens": "one unit for each authenticated emitted result",
        "cached_input_tokens": "unavailable because this runtime has no cache observation",
    },
}


class UsageEvidenceError(ValueError):
    def __init__(self, reason_code: str = "provider_usage_invalid") -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _hash(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except Exception:
        raise UsageEvidenceError() from None
    return hashlib.sha256(encoded).hexdigest()


def canonical_usage_hash(document: object) -> str:
    if type(document) is not dict:
        raise UsageEvidenceError()
    try:
        body = {key: value for key, value in dict.items(document) if key != "content_hash"}
    except Exception:
        raise UsageEvidenceError() from None
    return _hash(body)


def code_owned_usage_policy_hash(runtime_id: object) -> str:
    if type(runtime_id) is not str or runtime_id not in _CODE_OWNED_USAGE_POLICIES:
        raise UsageEvidenceError("provider_usage_policy_invalid")
    return _hash(_CODE_OWNED_USAGE_POLICIES[runtime_id])


def _exact_hash(value: object, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise UsageEvidenceError()
    return value


def _exact_nonnegative(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise UsageEvidenceError()
    return value


def _exact_state(value: object) -> str:
    if type(value) is not str or value not in _STATES:
        raise UsageEvidenceError()
    return value


def _unavailable_reason(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str or value not in _UNAVAILABLE_REASONS:
        raise UsageEvidenceError()
    return value


@dataclass(frozen=True, slots=True)
class TokenEvidence:
    state: str
    source_kind: str
    value: int | None
    policy_hash: str | None
    unavailable_reason: str | None

    @classmethod
    def create(
        cls,
        *,
        state: object,
        source_kind: object,
        value: object = None,
        policy_hash: object = None,
        unavailable_reason: object = None,
    ) -> TokenEvidence:
        checked_state = _exact_state(state)
        if type(source_kind) is not str or source_kind not in _TOKEN_SOURCES:
            raise UsageEvidenceError()
        reason = _unavailable_reason(unavailable_reason)
        policy = _exact_hash(policy_hash, optional=True)
        if checked_state == "observed":
            if source_kind != "provider_result" or policy is not None or reason is not None:
                raise UsageEvidenceError()
            checked_value = _exact_nonnegative(value)
        elif checked_state == "derived":
            if source_kind != "code_owned_runtime" or policy is None or reason is not None:
                raise UsageEvidenceError()
            checked_value = _exact_nonnegative(value)
        else:
            if source_kind != "none" or value is not None or policy is not None or reason is None:
                raise UsageEvidenceError()
            checked_value = None
        return cls(checked_state, source_kind, checked_value, policy, reason)

    def as_document(self) -> dict[str, object]:
        return {
            "state": self.state,
            "source_kind": self.source_kind,
            "value": self.value,
            "policy_hash": self.policy_hash,
            "unavailable_reason": self.unavailable_reason,
        }


def validate_token_evidence(value: object) -> TokenEvidence:
    if type(value) is not TokenEvidence:
        raise UsageEvidenceError()
    return TokenEvidence.create(
        state=value.state,
        source_kind=value.source_kind,
        value=value.value,
        policy_hash=value.policy_hash,
        unavailable_reason=value.unavailable_reason,
    )


@dataclass(frozen=True, slots=True)
class CostEvidence:
    state: str
    source_kind: str
    value: int | None
    currency: str | None
    policy_hash: str | None
    unavailable_reason: str | None

    @classmethod
    def create(
        cls,
        *,
        state: object,
        source_kind: object,
        value: object = None,
        currency: object = None,
        policy_hash: object = None,
        unavailable_reason: object = None,
    ) -> CostEvidence:
        checked_state = _exact_state(state)
        if type(source_kind) is not str or source_kind not in _COST_SOURCES:
            raise UsageEvidenceError()
        reason = _unavailable_reason(unavailable_reason)
        policy = _exact_hash(policy_hash, optional=True)
        if checked_state in {"observed", "derived"}:
            expected_source = (
                "provider_result" if checked_state == "observed" else "parent_pricing_policy"
            )
            if (
                source_kind != expected_source
                or (checked_state == "observed" and policy is not None)
                or (checked_state == "derived" and policy is None)
                or reason is not None
                or type(currency) is not str
                or _CURRENCY_RE.fullmatch(currency) is None
            ):
                raise UsageEvidenceError()
            checked_value = _exact_nonnegative(value)
            checked_currency = currency
        else:
            if (
                source_kind != "none"
                or value is not None
                or currency is not None
                or policy is not None
                or reason is None
            ):
                raise UsageEvidenceError()
            checked_value = None
            checked_currency = None
        return cls(
            checked_state,
            source_kind,
            checked_value,
            checked_currency,
            policy,
            reason,
        )

    def as_document(self) -> dict[str, object]:
        return {
            "state": self.state,
            "source_kind": self.source_kind,
            "value": self.value,
            "currency": self.currency,
            "policy_hash": self.policy_hash,
            "unavailable_reason": self.unavailable_reason,
        }


def validate_cost_evidence(value: object) -> CostEvidence:
    if type(value) is not CostEvidence:
        raise UsageEvidenceError()
    return CostEvidence.create(
        state=value.state,
        source_kind=value.source_kind,
        value=value.value,
        currency=value.currency,
        policy_hash=value.policy_hash,
        unavailable_reason=value.unavailable_reason,
    )


_LIVE_PROVIDER_LINEAGE_IDENTITIES: dict[
    int,
    tuple[ReferenceType[object], str],
] = {}


def _retire_registered_identity(
    registry: dict[int, tuple[object, ...]],
    identity: int,
    registered_ref: ReferenceType[object],
) -> None:
    """Retire only the exact weak registration that produced the callback."""

    registered = registry.get(identity)
    if registered is not None and registered[0] is registered_ref:
        del registry[identity]


def _register_live_lineage_authority(value: ProviderAccountingLineage) -> None:
    identity = id(value)

    def retire(registered_ref: ReferenceType[object]) -> None:
        _retire_registered_identity(  # type: ignore[arg-type]
            _LIVE_PROVIDER_LINEAGE_IDENTITIES,
            identity,
            registered_ref,
        )

    _LIVE_PROVIDER_LINEAGE_IDENTITIES[identity] = (
        ref(value, retire),
        value.content_hash,
    )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ProviderAccountingLineage:
    execution_id: str
    request_fingerprint: str
    runtime_id: str
    runtime_revision: int
    runtime_content_hash: str
    runtime_spec_hash: str
    selection_hash: str
    usage_policy_hash: str
    pricing_policy_hash: str | None
    pricing_currency: str | None
    content_hash: str

    @classmethod
    def from_resolved(
        cls,
        *,
        execution_id: object,
        request_fingerprint: object,
        resolved: object,
    ) -> ProviderAccountingLineage:
        try:
            from .pricing import validate_code_owned_pricing_binding
            from .provider_catalog import _validate_authoritative_resolved

            checked = _validate_authoritative_resolved(resolved)
            pricing_policy = validate_code_owned_pricing_binding(
                runtime_id=checked.spec.runtime_id,
                runtime_revision=checked.spec.runtime_revision,
                runtime_content_hash=checked.spec.runtime_content_hash,
                usage_policy_hash=checked.spec.usage_policy_hash,
                pricing_policy_hash=checked.spec.pricing_policy_hash,
                pricing_currency=checked.spec.pricing_currency,
            )
            if checked.spec.pricing_policy_hash is not None and pricing_policy is None:
                raise UsageEvidenceError("provider_usage_policy_invalid")
        except Exception:
            raise UsageEvidenceError("provider_usage_policy_invalid") from None
        lineage = cls._create_validated(
            execution_id=execution_id,
            request_fingerprint=request_fingerprint,
            runtime_id=checked.spec.runtime_id,
            runtime_revision=checked.spec.runtime_revision,
            runtime_content_hash=checked.spec.runtime_content_hash,
            runtime_spec_hash=checked.spec.content_hash,
            selection_hash=checked.selection.content_hash,
            usage_policy_hash=checked.spec.usage_policy_hash,
            pricing_policy_hash=checked.spec.pricing_policy_hash,
            pricing_currency=checked.spec.pricing_currency,
        )
        _register_live_lineage_authority(lineage)
        return lineage

    @classmethod
    def create(
        cls,
        *,
        execution_id: object,
        request_fingerprint: object,
        runtime_id: object,
        runtime_revision: object,
        runtime_content_hash: object,
        runtime_spec_hash: object,
        selection_hash: object,
        usage_policy_hash: object,
        pricing_policy_hash: object,
        pricing_currency: object,
    ) -> ProviderAccountingLineage:
        """Reject hash-only live construction; use ``from_resolved`` authority."""

        raise UsageEvidenceError("provider_usage_policy_invalid")

    @classmethod
    def _create_validated(
        cls,
        *,
        execution_id: object,
        request_fingerprint: object,
        runtime_id: object,
        runtime_revision: object,
        runtime_content_hash: object,
        runtime_spec_hash: object,
        selection_hash: object,
        usage_policy_hash: object,
        pricing_policy_hash: object,
        pricing_currency: object,
    ) -> ProviderAccountingLineage:
        if type(execution_id) is not str or _ID_RE.fullmatch(execution_id) is None:
            raise UsageEvidenceError("provider_usage_policy_invalid")
        if type(runtime_id) is not str or _ID_RE.fullmatch(runtime_id) is None:
            raise UsageEvidenceError("provider_usage_policy_invalid")
        if type(runtime_revision) is not int or not 1 <= runtime_revision <= MAX_SAFE_INTEGER:
            raise UsageEvidenceError("provider_usage_policy_invalid")
        checked_pricing = _exact_hash(pricing_policy_hash, optional=True)
        if pricing_currency is None:
            checked_currency = None
        elif type(pricing_currency) is str and _CURRENCY_RE.fullmatch(pricing_currency):
            checked_currency = pricing_currency
        else:
            raise UsageEvidenceError("provider_usage_policy_invalid")
        if (checked_pricing is None) != (checked_currency is None):
            raise UsageEvidenceError("provider_usage_policy_invalid")
        values: dict[str, object] = {
            "execution_id": execution_id,
            "request_fingerprint": _exact_hash(request_fingerprint),
            "runtime_id": runtime_id,
            "runtime_revision": runtime_revision,
            "runtime_content_hash": _exact_hash(runtime_content_hash),
            "runtime_spec_hash": _exact_hash(runtime_spec_hash),
            "selection_hash": _exact_hash(selection_hash),
            "usage_policy_hash": _exact_hash(usage_policy_hash),
            "pricing_policy_hash": checked_pricing,
            "pricing_currency": checked_currency,
        }
        try:
            from .pricing import validate_code_owned_pricing_binding

            validate_code_owned_pricing_binding(
                runtime_id=values["runtime_id"],
                runtime_revision=values["runtime_revision"],
                runtime_content_hash=values["runtime_content_hash"],
                usage_policy_hash=values["usage_policy_hash"],
                pricing_policy_hash=values["pricing_policy_hash"],
                pricing_currency=values["pricing_currency"],
            )
        except Exception:
            raise UsageEvidenceError("provider_usage_policy_invalid") from None
        document = cls._document(values)
        return cls(  # type: ignore[arg-type]
            **values,
            content_hash=_hash(document),
        )

    @staticmethod
    def _document(values: dict[str, object]) -> dict[str, object]:
        return {
            "format": _LINEAGE_FORMAT,
            "format_version": _LINEAGE_VERSION,
            **values,
        }

    def as_document(self) -> dict[str, object]:
        values = {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name != "content_hash"
        }
        return {**self._document(values), "content_hash": self.content_hash}


def validate_provider_accounting_lineage(value: object) -> ProviderAccountingLineage:
    """Validate an exact live lineage issued by authoritative catalog resolution."""

    if type(value) is not ProviderAccountingLineage or not _has_live_lineage_authority(value):
        raise UsageEvidenceError("provider_usage_policy_invalid")
    recreated = _reconstruct_provider_accounting_lineage(value.as_document())
    if value != recreated:
        raise UsageEvidenceError("provider_usage_policy_invalid")
    return value


def _has_live_lineage_authority(value: ProviderAccountingLineage) -> bool:
    if type(value) is not ProviderAccountingLineage:
        return False
    registered = _LIVE_PROVIDER_LINEAGE_IDENTITIES.get(id(value))
    return (
        registered is not None and registered[0]() is value and registered[1] == value.content_hash
    )


def _reconstruct_provider_accounting_lineage(
    supplied: object,
) -> ProviderAccountingLineage:
    if type(supplied) is not dict:
        raise UsageEvidenceError("provider_usage_policy_invalid")
    if (
        set(supplied)
        != {
            "format",
            "format_version",
            "execution_id",
            "request_fingerprint",
            "runtime_id",
            "runtime_revision",
            "runtime_content_hash",
            "runtime_spec_hash",
            "selection_hash",
            "usage_policy_hash",
            "pricing_policy_hash",
            "pricing_currency",
            "content_hash",
        }
        or supplied.get("format") != _LINEAGE_FORMAT
        or supplied.get("format_version") != 1
    ):
        raise UsageEvidenceError("provider_usage_policy_invalid")
    recreated = ProviderAccountingLineage._create_validated(
        **{
            name: supplied[name]
            for name in ProviderAccountingLineage.__dataclass_fields__
            if name != "content_hash"
        },
    )
    if supplied["content_hash"] != recreated.content_hash:
        raise UsageEvidenceError("provider_usage_policy_invalid")
    return recreated


def _validate_durable_provider_accounting_lineage(
    value: object,
) -> ProviderAccountingLineage:
    if type(value) is ProviderAccountingLineage:
        supplied = value.as_document()
    elif type(value) is dict:
        supplied = value
    else:
        raise UsageEvidenceError("provider_usage_policy_invalid")
    return _reconstruct_provider_accounting_lineage(supplied)


@dataclass(slots=True)
class UsageAccounting:
    execution_id: str
    runtime_spec_hash: str
    selection_hash: str
    usage_policy_hash: str
    pricing_policy_hash: str | None
    _turns: list[dict[str, object]] = field(default_factory=list)
    _input_tokens: int = 0
    _output_tokens: int = 0
    _cached_input_tokens: int = 0
    _cost_minor_units: int | None = None
    _currency: str | None = None
    _pricing_policy: object | None = field(default=None, repr=False)
    _provider_lineage: ProviderAccountingLineage | None = field(default=None, repr=False)
    _pricing_available: bool = field(default=True, repr=False)
    _cached_input_evidence_complete: bool = field(default=True, repr=False)

    @classmethod
    def create(
        cls,
        *,
        execution_id: object,
        runtime_spec_hash: object,
        selection_hash: object,
        usage_policy_hash: object,
        pricing_policy_hash: object,
    ) -> UsageAccounting:
        if type(execution_id) is not str or _ID_RE.fullmatch(execution_id) is None:
            raise UsageEvidenceError()
        checked_usage_policy_hash = _exact_hash(usage_policy_hash)
        checked_pricing_policy_hash = _exact_hash(pricing_policy_hash, optional=True)
        if checked_pricing_policy_hash is not None:
            raise UsageEvidenceError("provider_usage_policy_invalid")
        return cls(
            execution_id,
            _exact_hash(runtime_spec_hash),  # type: ignore[arg-type]
            _exact_hash(selection_hash),  # type: ignore[arg-type]
            checked_usage_policy_hash,  # type: ignore[arg-type]
            None,
            _pricing_available=False,
        )

    @classmethod
    def create_from_resolved(
        cls,
        *,
        execution_id: object,
        request_fingerprint: object,
        resolved: object,
    ) -> UsageAccounting:
        lineage = ProviderAccountingLineage.from_resolved(
            execution_id=execution_id,
            request_fingerprint=request_fingerprint,
            resolved=resolved,
        )
        return cls._from_lineage(lineage)

    @classmethod
    def _from_lineage(cls, lineage: object) -> UsageAccounting:
        checked = validate_provider_accounting_lineage(lineage)
        return cls._from_validated_lineage(checked)

    @classmethod
    def _from_durable_lineage(cls, lineage: object) -> UsageAccounting:
        checked = _validate_durable_provider_accounting_lineage(lineage)
        return cls._from_validated_lineage(checked)

    @classmethod
    def _from_validated_lineage(
        cls,
        checked: ProviderAccountingLineage,
    ) -> UsageAccounting:
        pricing_policy = None
        if checked.pricing_policy_hash is not None:
            try:
                from .pricing import (
                    resolve_code_owned_pricing_policy,
                    validate_code_owned_pricing_binding,
                )

                checked_policy = validate_code_owned_pricing_binding(
                    runtime_id=checked.runtime_id,
                    runtime_revision=checked.runtime_revision,
                    runtime_content_hash=checked.runtime_content_hash,
                    usage_policy_hash=checked.usage_policy_hash,
                    pricing_policy_hash=checked.pricing_policy_hash,
                    pricing_currency=checked.pricing_currency,
                )
                if checked_policy is None:
                    raise UsageEvidenceError("provider_usage_policy_invalid")
                pricing_policy = resolve_code_owned_pricing_policy(
                    checked.pricing_policy_hash,
                    checked.usage_policy_hash,
                )
            except Exception:
                raise UsageEvidenceError("provider_usage_policy_invalid") from None
        return cls(
            checked.execution_id,
            checked.runtime_spec_hash,
            checked.selection_hash,
            checked.usage_policy_hash,
            checked.pricing_policy_hash,
            _pricing_policy=pricing_policy,
            _provider_lineage=checked,
            _pricing_available=pricing_policy is not None,
        )

    @property
    def provider_lineage(self) -> ProviderAccountingLineage | None:
        if self._provider_lineage is None:
            return None
        if _has_live_lineage_authority(self._provider_lineage):
            return validate_provider_accounting_lineage(self._provider_lineage)
        return _validate_durable_provider_accounting_lineage(self._provider_lineage)

    @staticmethod
    def _sum(current: int, addition: int) -> int:
        if current > MAX_SAFE_INTEGER - addition:
            raise UsageEvidenceError()
        return current + addition

    def _prepare_tokens(
        self,
        *,
        input_tokens: object,
        output_tokens: object,
        cached_input_tokens: object,
    ) -> tuple[
        TokenEvidence,
        TokenEvidence,
        TokenEvidence,
        int,
        int,
        int,
        bool,
        str | None,
    ]:
        input_evidence = validate_token_evidence(input_tokens)
        output_evidence = validate_token_evidence(output_tokens)
        cached_evidence = validate_token_evidence(cached_input_tokens)
        for evidence in (input_evidence, output_evidence, cached_evidence):
            if evidence.state == "derived" and evidence.policy_hash != self.usage_policy_hash:
                raise UsageEvidenceError()
        if input_evidence.state == "unavailable" and cached_evidence.state != "unavailable":
            raise UsageEvidenceError()
        recognized_input = input_evidence.value
        recognized_output = output_evidence.value
        recognized_cached = 0 if cached_evidence.value is None else cached_evidence.value
        if (
            recognized_input is not None
            and cached_evidence.value is not None
            and recognized_cached > recognized_input
        ):
            raise UsageEvidenceError()
        new_input = self._input_tokens
        new_output = self._output_tokens
        new_cached = self._cached_input_tokens
        if recognized_input is not None:
            new_input = self._sum(new_input, recognized_input)
        if recognized_output is not None:
            new_output = self._sum(new_output, recognized_output)
        if self._sum(new_input, new_output) > MAX_SAFE_INTEGER:
            raise UsageEvidenceError()
        new_cached = self._sum(new_cached, recognized_cached)
        cached_complete = self._cached_input_evidence_complete and cached_evidence.value is not None
        unavailable_reason = (
            "provider_usage_unavailable"
            if input_evidence.state == "unavailable" or output_evidence.state == "unavailable"
            else None
        )
        return (
            input_evidence,
            output_evidence,
            cached_evidence,
            new_input,
            new_output,
            new_cached,
            cached_complete,
            unavailable_reason,
        )

    def _parent_cost(
        self,
        *,
        new_input: int,
        new_output: int,
        new_cached: int,
        cached_complete: bool,
        usage_unavailable: bool,
        recorded_validation: bool,
    ) -> tuple[CostEvidence, int | None, str | None, bool]:
        if self._pricing_policy is None or self.pricing_policy_hash is None:
            raise UsageEvidenceError("provider_usage_policy_invalid")
        pricing_available = self._pricing_available and not usage_unavailable
        total_cost: int | None = None
        if pricing_available:
            try:
                from .pricing import (
                    _verify_recorded_execution_cost,
                    calculate_execution_cost,
                    resolve_code_owned_pricing_policy,
                )

                canonical_policy = resolve_code_owned_pricing_policy(
                    self.pricing_policy_hash,
                    self.usage_policy_hash,
                )
                if self._pricing_policy != canonical_policy:
                    raise UsageEvidenceError("provider_usage_policy_invalid")
                calculator = (
                    _verify_recorded_execution_cost
                    if recorded_validation
                    else calculate_execution_cost
                )
                total_cost = calculator(
                    canonical_policy,
                    input_tokens=new_input,
                    output_tokens=new_output,
                    cached_input_tokens=new_cached if cached_complete else None,
                )
            except Exception:
                raise UsageEvidenceError("provider_usage_invalid") from None
            pricing_available = total_cost is not None
        if not pricing_available or total_cost is None:
            return (
                CostEvidence.create(
                    state="unavailable",
                    source_kind="none",
                    unavailable_reason="parent_pricing_unavailable",
                ),
                None,
                None,
                False,
            )
        previous_cost = 0 if self._cost_minor_units is None else self._cost_minor_units
        if total_cost < previous_cost:
            raise UsageEvidenceError("provider_usage_invalid")
        turn_cost = total_cost - previous_cost
        currency = canonical_policy.currency
        return (
            CostEvidence.create(
                state="derived",
                source_kind="parent_pricing_policy",
                value=turn_cost,
                currency=currency,
                policy_hash=self.pricing_policy_hash,
            ),
            total_cost,
            currency,
            True,
        )

    def _commit_turn(
        self,
        *,
        input_evidence: TokenEvidence,
        output_evidence: TokenEvidence,
        cached_evidence: TokenEvidence,
        cost_evidence: CostEvidence,
        new_input: int,
        new_output: int,
        new_cached: int,
        new_cost: int | None,
        new_currency: str | None,
        cached_complete: bool,
        pricing_available: bool,
    ) -> None:
        self._turns.append(
            {
                "turn_index": len(self._turns),
                "input_tokens": input_evidence.as_document(),
                "output_tokens": output_evidence.as_document(),
                "cached_input_tokens": cached_evidence.as_document(),
                "cost": cost_evidence.as_document(),
            }
        )
        self._input_tokens = new_input
        self._output_tokens = new_output
        self._cached_input_tokens = new_cached
        self._cost_minor_units = new_cost
        self._currency = new_currency
        self._cached_input_evidence_complete = cached_complete
        self._pricing_available = pricing_available

    def add_provider_turn(
        self,
        *,
        input_tokens: object,
        output_tokens: object,
        cached_input_tokens: object,
        worker_cost: object,
    ) -> tuple[str | None, bool]:
        prepared = self._prepare_tokens(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_input_tokens=cached_input_tokens,
        )
        (
            input_evidence,
            output_evidence,
            cached_evidence,
            new_input,
            new_output,
            new_cached,
            cached_complete,
            unavailable_reason,
        ) = prepared
        try:
            supplied_cost = validate_cost_evidence(worker_cost)
        except UsageEvidenceError:
            supplied_cost = None
        worker_cost_invalid = supplied_cost is None or supplied_cost.state != "unavailable"
        if self._pricing_policy is None:
            pricing_available = False
            new_cost = None
            new_currency = None
            cost_evidence = (
                supplied_cost
                if supplied_cost is not None and supplied_cost.state == "unavailable"
                else CostEvidence.create(
                    state="unavailable",
                    source_kind="none",
                    unavailable_reason="parent_pricing_unavailable",
                )
            )
        else:
            cost_evidence, new_cost, new_currency, pricing_available = self._parent_cost(
                new_input=new_input,
                new_output=new_output,
                new_cached=new_cached,
                cached_complete=cached_complete,
                usage_unavailable=unavailable_reason is not None,
                recorded_validation=False,
            )
        self._commit_turn(
            input_evidence=input_evidence,
            output_evidence=output_evidence,
            cached_evidence=cached_evidence,
            cost_evidence=cost_evidence,
            new_input=new_input,
            new_output=new_output,
            new_cached=new_cached,
            new_cost=new_cost,
            new_currency=new_currency,
            cached_complete=cached_complete,
            pricing_available=pricing_available,
        )
        return unavailable_reason, worker_cost_invalid

    def add_turn(
        self,
        *,
        input_tokens: object,
        output_tokens: object,
        cached_input_tokens: object,
        cost: object,
    ) -> str | None:
        prepared = self._prepare_tokens(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_input_tokens=cached_input_tokens,
        )
        (
            input_evidence,
            output_evidence,
            cached_evidence,
            new_input,
            new_output,
            new_cached,
            cached_complete,
            unavailable_reason,
        ) = prepared
        cost_evidence = validate_cost_evidence(cost)
        if self._pricing_policy is None:
            if cost_evidence.state != "unavailable":
                raise UsageEvidenceError()
            new_cost = None
            new_currency = None
            pricing_available = False
        else:
            expected, new_cost, new_currency, pricing_available = self._parent_cost(
                new_input=new_input,
                new_output=new_output,
                new_cached=new_cached,
                cached_complete=cached_complete,
                usage_unavailable=unavailable_reason is not None,
                recorded_validation=True,
            )
            if cost_evidence != expected:
                raise UsageEvidenceError()
        self._commit_turn(
            input_evidence=input_evidence,
            output_evidence=output_evidence,
            cached_evidence=cached_evidence,
            cost_evidence=cost_evidence,
            new_input=new_input,
            new_output=new_output,
            new_cached=new_cached,
            new_cost=new_cost,
            new_currency=new_currency,
            cached_complete=cached_complete,
            pricing_available=pricing_available,
        )
        return unavailable_reason

    @property
    def turn_count(self) -> int:
        return len(self._turns)

    @property
    def recognized_totals(self) -> dict[str, object]:
        return {
            "input_tokens": self._input_tokens,
            "output_tokens": self._output_tokens,
            "cached_input_tokens": self._cached_input_tokens,
            "cost_minor_units": self._cost_minor_units,
            "currency": self._currency,
        }

    def seal(self, *, receipt_hash: object) -> dict[str, object]:
        document: dict[str, object] = {
            "format": _ACCOUNTING_FORMAT,
            "format_version": _ACCOUNTING_VERSION,
            "record_mode": "live_evidence",
            "execution_id": self.execution_id,
            "receipt_hash": _exact_hash(receipt_hash),
            "runtime_spec_hash": self.runtime_spec_hash,
            "selection_hash": self.selection_hash,
            "usage_policy_hash": self.usage_policy_hash,
            "pricing_policy_hash": self.pricing_policy_hash,
            "turn_count": len(self._turns),
            "turns": [dict(item) for item in self._turns],
            "recognized_totals": self.recognized_totals,
        }
        document["content_hash"] = canonical_usage_hash(document)
        return document


def build_legacy_usage_accounting(receipt: object) -> dict[str, object]:
    if type(receipt) is not dict or type(receipt.get("usage")) is not dict:
        raise UsageEvidenceError()
    execution_id = receipt.get("execution_id")
    receipt_hash = receipt.get("content_hash")
    if type(execution_id) is not str or _ID_RE.fullmatch(execution_id) is None:
        raise UsageEvidenceError()
    _exact_hash(receipt_hash)
    usage = receipt["usage"]
    if set(usage) != {
        "input_tokens",
        "output_tokens",
        "cached_input_tokens",
        "duration_ms",
        "cost_minor_units",
        "currency",
    }:
        raise UsageEvidenceError()
    totals = {
        "input_tokens": _exact_nonnegative(usage["input_tokens"]),
        "output_tokens": _exact_nonnegative(usage["output_tokens"]),
        "cached_input_tokens": _exact_nonnegative(usage["cached_input_tokens"]),
        "cost_minor_units": (
            None
            if usage["cost_minor_units"] is None
            else _exact_nonnegative(usage["cost_minor_units"])
        ),
        "currency": usage["currency"],
    }
    if (totals["cost_minor_units"] is None) != (totals["currency"] is None):
        raise UsageEvidenceError()
    if totals["currency"] is not None and (
        type(totals["currency"]) is not str or _CURRENCY_RE.fullmatch(totals["currency"]) is None
    ):
        raise UsageEvidenceError()
    document: dict[str, object] = {
        "format": _ACCOUNTING_FORMAT,
        "format_version": _ACCOUNTING_VERSION,
        "record_mode": "legacy_receipt_totals",
        "execution_id": execution_id,
        "receipt_hash": receipt_hash,
        "runtime_spec_hash": None,
        "selection_hash": None,
        "usage_policy_hash": None,
        "pricing_policy_hash": None,
        "turn_count": 0,
        "turns": [],
        "recognized_totals": totals,
    }
    document["content_hash"] = canonical_usage_hash(document)
    return document


def build_no_provider_usage_accounting(receipt: object) -> dict[str, object]:
    document = build_legacy_usage_accounting(receipt)
    document["record_mode"] = "no_provider_attempt"
    document["content_hash"] = canonical_usage_hash(document)
    return document


def _validate_recognized_totals(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != {
        "input_tokens",
        "output_tokens",
        "cached_input_tokens",
        "cost_minor_units",
        "currency",
    }:
        raise UsageEvidenceError()
    input_tokens = _exact_nonnegative(value["input_tokens"])
    output_tokens = _exact_nonnegative(value["output_tokens"])
    cached_input_tokens = _exact_nonnegative(value["cached_input_tokens"])
    if cached_input_tokens > input_tokens:
        raise UsageEvidenceError()
    cost = value["cost_minor_units"]
    currency = value["currency"]
    if (cost is None) != (currency is None):
        raise UsageEvidenceError()
    checked_cost = None if cost is None else _exact_nonnegative(cost)
    if currency is not None and (
        type(currency) is not str or _CURRENCY_RE.fullmatch(currency) is None
    ):
        raise UsageEvidenceError()
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cached_input_tokens": cached_input_tokens,
        "cost_minor_units": checked_cost,
        "currency": currency,
    }


def validate_usage_accounting(
    document: object,
    *,
    trusted_lineage: object = None,
) -> dict[str, object]:
    if type(document) is not dict:
        raise UsageEvidenceError()
    try:
        closed = json.loads(
            json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
        )
    except Exception:
        raise UsageEvidenceError() from None
    if type(closed) is not dict or set(closed) != {
        "format",
        "format_version",
        "record_mode",
        "execution_id",
        "receipt_hash",
        "runtime_spec_hash",
        "selection_hash",
        "usage_policy_hash",
        "pricing_policy_hash",
        "turn_count",
        "turns",
        "recognized_totals",
        "content_hash",
    }:
        raise UsageEvidenceError()
    if (
        closed["format"] != _ACCOUNTING_FORMAT
        or type(closed["format_version"]) is not int
        or closed["format_version"] != _ACCOUNTING_VERSION
        or closed["record_mode"]
        not in {"live_evidence", "legacy_receipt_totals", "no_provider_attempt"}
        or type(closed["execution_id"]) is not str
        or _ID_RE.fullmatch(closed["execution_id"]) is None
        or type(closed["turn_count"]) is not int
        or type(closed["turns"]) is not list
        or closed["turn_count"] != len(closed["turns"])
    ):
        raise UsageEvidenceError()
    for name in ("receipt_hash", "content_hash"):
        _exact_hash(closed[name])
    if closed["content_hash"] != canonical_usage_hash(closed):
        raise UsageEvidenceError()
    checked_totals = _validate_recognized_totals(closed["recognized_totals"])
    if checked_totals != closed["recognized_totals"]:
        raise UsageEvidenceError()
    if closed["record_mode"] in {"legacy_receipt_totals", "no_provider_attempt"}:
        if (
            closed["turns"]
            or closed["turn_count"] != 0
            or any(
                closed[name] is not None
                for name in (
                    "runtime_spec_hash",
                    "selection_hash",
                    "usage_policy_hash",
                    "pricing_policy_hash",
                )
            )
        ):
            raise UsageEvidenceError()
    else:
        for name in ("runtime_spec_hash", "selection_hash", "usage_policy_hash"):
            _exact_hash(closed[name])
        _exact_hash(closed["pricing_policy_hash"], optional=True)
        if trusted_lineage is None:
            if closed["pricing_policy_hash"] is not None:
                raise UsageEvidenceError("provider_usage_policy_invalid")
            rebuilt = UsageAccounting.create(
                execution_id=closed["execution_id"],
                runtime_spec_hash=closed["runtime_spec_hash"],
                selection_hash=closed["selection_hash"],
                usage_policy_hash=closed["usage_policy_hash"],
                pricing_policy_hash=None,
            )
        else:
            checked_lineage = _validate_durable_provider_accounting_lineage(trusted_lineage)
            if (
                closed["execution_id"] != checked_lineage.execution_id
                or closed["runtime_spec_hash"] != checked_lineage.runtime_spec_hash
                or closed["selection_hash"] != checked_lineage.selection_hash
                or closed["usage_policy_hash"] != checked_lineage.usage_policy_hash
                or closed["pricing_policy_hash"] != checked_lineage.pricing_policy_hash
            ):
                raise UsageEvidenceError("provider_usage_policy_invalid")
            rebuilt = UsageAccounting._from_validated_lineage(checked_lineage)
        for index, turn in enumerate(closed["turns"]):
            if (
                type(turn) is not dict
                or set(turn)
                != {"turn_index", "input_tokens", "output_tokens", "cached_input_tokens", "cost"}
                or type(turn["turn_index"]) is not int
                or turn["turn_index"] != index
            ):
                raise UsageEvidenceError()

            def token(payload: object) -> TokenEvidence:
                if type(payload) is not dict:
                    raise UsageEvidenceError()
                return TokenEvidence.create(**payload)

            if type(turn["cost"]) is not dict:
                raise UsageEvidenceError()
            rebuilt.add_turn(
                input_tokens=token(turn["input_tokens"]),
                output_tokens=token(turn["output_tokens"]),
                cached_input_tokens=token(turn["cached_input_tokens"]),
                cost=CostEvidence.create(**turn["cost"]),
            )
        if rebuilt.recognized_totals != checked_totals:
            raise UsageEvidenceError()
    return closed


__all__ = (
    "CostEvidence",
    "ProviderAccountingLineage",
    "TokenEvidence",
    "UsageAccounting",
    "UsageEvidenceError",
    "build_legacy_usage_accounting",
    "build_no_provider_usage_accounting",
    "canonical_usage_hash",
    "code_owned_usage_policy_hash",
    "validate_cost_evidence",
    "validate_provider_accounting_lineage",
    "validate_token_evidence",
    "validate_usage_accounting",
)
