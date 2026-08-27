"""Private code-owned exact pricing for one neutral synthetic runtime."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace

from worldforge.agent_harness_contracts import MAX_SAFE_INTEGER

_POLICY_FORMAT = "world-forge.private.exact_pricing_policy"
_POLICY_FORMAT_VERSION = 1
_CONFORMANCE_RUNTIME_ID = "worldforge_conformance_provider"
_PROBE_RUNTIME_ID = "worldforge_deterministic_probe_provider"
_POLICY_ID = "deterministic_probe_synthetic_xts"
_ROUNDING_MODE = "ceiling_at_execution_total_v1"
_CURRENCY = "XTS"
_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CODE_OWNED_POLICY: ExactPricingPolicy | None
_CODE_OWNED_CONFORMANCE_BINDING: _UnpricedRuntimeBinding | None


class PricingAuthorityError(ValueError):
    def __init__(self, reason_code: str = "provider_pricing_policy_invalid") -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except Exception:
        raise PricingAuthorityError() from None


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def canonical_pricing_hash(document: object) -> str:
    if type(document) is not dict:
        raise PricingAuthorityError()
    try:
        body = {key: value for key, value in dict.items(document) if key != "content_hash"}
    except Exception:
        raise PricingAuthorityError() from None
    return _hash(body)


def _exact_id(value: object) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise PricingAuthorityError()
    return value


def _exact_hash(value: object) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise PricingAuthorityError()
    return value


def _exact_integer(value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        raise PricingAuthorityError()
    return value


@dataclass(frozen=True, slots=True)
class ExactPricingPolicy:
    runtime_id: str
    runtime_revision: int
    runtime_content_hash: str
    usage_policy_hash: str
    policy_id: str
    policy_version: int
    currency: str
    denominator: int
    uncached_input_numerator: int
    cached_input_numerator: int
    output_numerator: int
    rounding_mode: str
    content_hash: str

    @classmethod
    def create(
        cls,
        *,
        runtime_id: object,
        runtime_revision: object,
        runtime_content_hash: object,
        usage_policy_hash: object,
        policy_id: object,
        policy_version: object,
        currency: object,
        denominator: object,
        uncached_input_numerator: object,
        cached_input_numerator: object,
        output_numerator: object,
        rounding_mode: object,
    ) -> ExactPricingPolicy:
        if type(currency) is not str or currency != _CURRENCY:
            raise PricingAuthorityError()
        if type(rounding_mode) is not str or rounding_mode != _ROUNDING_MODE:
            raise PricingAuthorityError()
        values: dict[str, object] = {
            "runtime_id": _exact_id(runtime_id),
            "runtime_revision": _exact_integer(runtime_revision, minimum=1),
            "runtime_content_hash": _exact_hash(runtime_content_hash),
            "usage_policy_hash": _exact_hash(usage_policy_hash),
            "policy_id": _exact_id(policy_id),
            "policy_version": _exact_integer(policy_version, minimum=1),
            "currency": currency,
            "denominator": _exact_integer(denominator, minimum=1),
            "uncached_input_numerator": _exact_integer(uncached_input_numerator),
            "cached_input_numerator": _exact_integer(cached_input_numerator),
            "output_numerator": _exact_integer(output_numerator),
            "rounding_mode": rounding_mode,
        }
        document = cls._document(values)
        return cls(**values, content_hash=_hash(document))  # type: ignore[arg-type]

    @staticmethod
    def _document(values: dict[str, object]) -> dict[str, object]:
        return {
            "format": _POLICY_FORMAT,
            "format_version": _POLICY_FORMAT_VERSION,
            **values,
        }

    def as_document(self) -> dict[str, object]:
        values = {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
            if field != "content_hash"
        }
        return {**self._document(values), "content_hash": self.content_hash}


@dataclass(frozen=True, slots=True)
class _UnpricedRuntimeBinding:
    runtime_id: str
    runtime_revision: int
    runtime_content_hash: str
    usage_policy_hash: str

    @classmethod
    def create(
        cls,
        *,
        runtime_id: object,
        runtime_revision: object,
        runtime_content_hash: object,
        usage_policy_hash: object,
    ) -> _UnpricedRuntimeBinding:
        if type(runtime_id) is not str or runtime_id != _CONFORMANCE_RUNTIME_ID:
            raise PricingAuthorityError()
        return cls(
            runtime_id,
            _exact_integer(runtime_revision, minimum=1),
            _exact_hash(runtime_content_hash),
            _exact_hash(usage_policy_hash),
        )


def _validate_policy(value: object) -> ExactPricingPolicy:
    if type(value) is not ExactPricingPolicy:
        raise PricingAuthorityError()
    recreated = ExactPricingPolicy.create(
        **{
            field: getattr(value, field)
            for field in value.__dataclass_fields__
            if field != "content_hash"
        }
    )
    if type(value.content_hash) is not str or value.content_hash != recreated.content_hash:
        raise PricingAuthorityError()
    return recreated


def _build_code_owned_pricing_policy(
    *,
    runtime_id: object,
    runtime_revision: object,
    runtime_content_hash: object,
    usage_policy_hash: object,
) -> ExactPricingPolicy:
    if type(runtime_id) is not str or runtime_id != _PROBE_RUNTIME_ID:
        raise PricingAuthorityError()
    return ExactPricingPolicy.create(
        runtime_id=runtime_id,
        runtime_revision=runtime_revision,
        runtime_content_hash=runtime_content_hash,
        usage_policy_hash=usage_policy_hash,
        policy_id=_POLICY_ID,
        policy_version=1,
        currency=_CURRENCY,
        denominator=4,
        uncached_input_numerator=2,
        cached_input_numerator=2,
        output_numerator=3,
        rounding_mode=_ROUNDING_MODE,
    )


_CODE_OWNED_POLICY = None
_CODE_OWNED_CONFORMANCE_BINDING = None


def _build_code_owned_unpriced_runtime_binding(
    *,
    runtime_id: object,
    runtime_revision: object,
    runtime_content_hash: object,
    usage_policy_hash: object,
) -> _UnpricedRuntimeBinding:
    return _UnpricedRuntimeBinding.create(
        runtime_id=runtime_id,
        runtime_revision=runtime_revision,
        runtime_content_hash=runtime_content_hash,
        usage_policy_hash=usage_policy_hash,
    )


def _install_code_owned_unpriced_runtime_binding(binding: object) -> None:
    """Bind the construction-time unpriced conformance identity exactly once."""

    global _CODE_OWNED_CONFORMANCE_BINDING
    if type(binding) is not _UnpricedRuntimeBinding:
        raise PricingAuthorityError()
    checked = _UnpricedRuntimeBinding.create(
        runtime_id=binding.runtime_id,
        runtime_revision=binding.runtime_revision,
        runtime_content_hash=binding.runtime_content_hash,
        usage_policy_hash=binding.usage_policy_hash,
    )
    if _CODE_OWNED_CONFORMANCE_BINDING is None:
        _CODE_OWNED_CONFORMANCE_BINDING = replace(checked)
        return
    if _CODE_OWNED_CONFORMANCE_BINDING != checked:
        raise PricingAuthorityError()


def _install_code_owned_pricing_policy(policy: object) -> None:
    """Bind the construction-time registry policy exactly once."""

    global _CODE_OWNED_POLICY
    checked = _validate_policy(policy)
    if checked.runtime_id != _PROBE_RUNTIME_ID:
        raise PricingAuthorityError()
    if _CODE_OWNED_POLICY is None:
        _CODE_OWNED_POLICY = replace(checked)
        return
    if _CODE_OWNED_POLICY != checked:
        raise PricingAuthorityError()


def code_owned_pricing_policy() -> ExactPricingPolicy:
    """Return the sole construction-time policy without runtime registry lookup."""

    if _CODE_OWNED_POLICY is None:
        # Importing the registry performs its single construction-time install.
        from . import worker_registry as _worker_registry  # noqa: F401

    if _CODE_OWNED_POLICY is None:
        raise PricingAuthorityError()
    return replace(_validate_policy(_CODE_OWNED_POLICY))


def _code_owned_unpriced_runtime_binding() -> _UnpricedRuntimeBinding:
    if _CODE_OWNED_CONFORMANCE_BINDING is None:
        from . import worker_registry as _worker_registry  # noqa: F401

    if _CODE_OWNED_CONFORMANCE_BINDING is None:
        raise PricingAuthorityError()
    binding = _CODE_OWNED_CONFORMANCE_BINDING
    return replace(
        _UnpricedRuntimeBinding.create(
            runtime_id=binding.runtime_id,
            runtime_revision=binding.runtime_revision,
            runtime_content_hash=binding.runtime_content_hash,
            usage_policy_hash=binding.usage_policy_hash,
        )
    )


def resolve_code_owned_pricing_policy(
    pricing_policy_hash: object,
    usage_policy_hash: object,
) -> ExactPricingPolicy:
    supplied_pricing_hash = _exact_hash(pricing_policy_hash)
    supplied_usage_hash = _exact_hash(usage_policy_hash)
    policy = code_owned_pricing_policy()
    if (
        supplied_pricing_hash != policy.content_hash
        or supplied_usage_hash != policy.usage_policy_hash
    ):
        raise PricingAuthorityError()
    return replace(policy)


def validate_code_owned_pricing_binding(
    *,
    runtime_id: object,
    runtime_revision: object,
    runtime_content_hash: object,
    usage_policy_hash: object,
    pricing_policy_hash: object,
    pricing_currency: object,
) -> ExactPricingPolicy | None:
    """Require the exact pricing shape of each code-owned runtime."""

    policy = code_owned_pricing_policy()
    conformance = _code_owned_unpriced_runtime_binding()
    if runtime_id == conformance.runtime_id:
        if (
            type(runtime_id) is not str
            or type(runtime_revision) is not int
            or runtime_revision != conformance.runtime_revision
            or type(runtime_content_hash) is not str
            or runtime_content_hash != conformance.runtime_content_hash
            or type(usage_policy_hash) is not str
            or usage_policy_hash != conformance.usage_policy_hash
            or pricing_policy_hash is not None
            or pricing_currency is not None
        ):
            raise PricingAuthorityError()
        return None
    if runtime_id == policy.runtime_id:
        if (
            type(runtime_id) is not str
            or type(runtime_revision) is not int
            or runtime_revision != policy.runtime_revision
            or type(runtime_content_hash) is not str
            or runtime_content_hash != policy.runtime_content_hash
            or type(usage_policy_hash) is not str
            or usage_policy_hash != policy.usage_policy_hash
            or type(pricing_policy_hash) is not str
            or pricing_policy_hash != policy.content_hash
            or type(pricing_currency) is not str
            or pricing_currency != policy.currency
        ):
            raise PricingAuthorityError()
        return replace(policy)
    if pricing_policy_hash is not None or pricing_currency is not None:
        raise PricingAuthorityError()
    return None


def _checked_product(left: int, right: int) -> int:
    if left != 0 and right > MAX_SAFE_INTEGER // left:
        raise PricingAuthorityError("provider_pricing_overflow")
    return left * right


def _checked_sum(left: int, right: int) -> int:
    if left > MAX_SAFE_INTEGER - right:
        raise PricingAuthorityError("provider_pricing_overflow")
    return left + right


def _calculate_execution_cost(
    policy: object,
    *,
    input_tokens: object,
    output_tokens: object,
    cached_input_tokens: object,
) -> int | None:
    checked = _validate_policy(policy)
    input_value = _exact_integer(input_tokens)
    output_value = _exact_integer(output_tokens)
    if cached_input_tokens is None:
        if checked.cached_input_numerator != checked.uncached_input_numerator:
            return None
        input_numerator = _checked_product(
            input_value,
            checked.uncached_input_numerator,
        )
    else:
        cached_value = _exact_integer(cached_input_tokens)
        if cached_value > input_value:
            raise PricingAuthorityError()
        uncached_value = input_value - cached_value
        input_numerator = _checked_sum(
            _checked_product(uncached_value, checked.uncached_input_numerator),
            _checked_product(cached_value, checked.cached_input_numerator),
        )
    numerator = _checked_sum(
        input_numerator,
        _checked_product(output_value, checked.output_numerator),
    )
    quotient, remainder = divmod(numerator, checked.denominator)
    if remainder:
        quotient = _checked_sum(quotient, 1)
    return quotient


def calculate_execution_cost(
    policy: object,
    *,
    input_tokens: object,
    output_tokens: object,
    cached_input_tokens: object,
) -> int | None:
    """Derive one live cumulative cost after a durable execution begin."""

    return _calculate_execution_cost(
        policy,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_input_tokens=cached_input_tokens,
    )


def _verify_recorded_execution_cost(
    policy: object,
    *,
    input_tokens: object,
    output_tokens: object,
    cached_input_tokens: object,
) -> int | None:
    """Verify stored arithmetic without entering the live pricing transition."""

    return _calculate_execution_cost(
        policy,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_input_tokens=cached_input_tokens,
    )


__all__ = (
    "ExactPricingPolicy",
    "PricingAuthorityError",
    "calculate_execution_cost",
    "canonical_pricing_hash",
    "code_owned_pricing_policy",
    "resolve_code_owned_pricing_policy",
    "validate_code_owned_pricing_binding",
)
