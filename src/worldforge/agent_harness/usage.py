"""Private truthful provider-usage evidence and sanitized accounting records."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

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
        return cls(
            execution_id,
            _exact_hash(runtime_spec_hash),  # type: ignore[arg-type]
            _exact_hash(selection_hash),  # type: ignore[arg-type]
            _exact_hash(usage_policy_hash),  # type: ignore[arg-type]
            _exact_hash(pricing_policy_hash, optional=True),
        )

    @staticmethod
    def _sum(current: int, addition: int) -> int:
        if current > MAX_SAFE_INTEGER - addition:
            raise UsageEvidenceError()
        return current + addition

    def add_turn(
        self,
        *,
        input_tokens: object,
        output_tokens: object,
        cached_input_tokens: object,
        cost: object,
    ) -> str | None:
        input_evidence = validate_token_evidence(input_tokens)
        output_evidence = validate_token_evidence(output_tokens)
        cached_evidence = validate_token_evidence(cached_input_tokens)
        cost_evidence = validate_cost_evidence(cost)
        # Provider-reported money is retained only as rejected evidence. It cannot
        # become an incurred ledger value until parent-owned pricing exists.
        if cost_evidence.state == "observed":
            raise UsageEvidenceError()
        for evidence in (input_evidence, output_evidence, cached_evidence):
            if evidence.state == "derived" and evidence.policy_hash != self.usage_policy_hash:
                raise UsageEvidenceError()
        if input_evidence.state == "unavailable" and cached_evidence.state != "unavailable":
            raise UsageEvidenceError()
        if cost_evidence.state == "derived" and (
            self.pricing_policy_hash is None
            or cost_evidence.policy_hash != self.pricing_policy_hash
        ):
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
        if cost_evidence.value is None:
            new_cost = None
            new_currency = None
        else:
            if self._cost_minor_units is None and self._turns:
                raise UsageEvidenceError()
            base = 0 if self._cost_minor_units is None else self._cost_minor_units
            new_cost = self._sum(base, cost_evidence.value)
            new_currency = cost_evidence.currency
            if self._currency is not None and self._currency != new_currency:
                raise UsageEvidenceError("provider_currency_mismatch")
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
        if input_evidence.state == "unavailable" or output_evidence.state == "unavailable":
            return "provider_usage_unavailable"
        return None

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


def validate_usage_accounting(document: object) -> dict[str, object]:
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
        rebuilt = UsageAccounting.create(
            execution_id=closed["execution_id"],
            runtime_spec_hash=closed["runtime_spec_hash"],
            selection_hash=closed["selection_hash"],
            usage_policy_hash=closed["usage_policy_hash"],
            pricing_policy_hash=closed["pricing_policy_hash"],
        )
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
    "TokenEvidence",
    "UsageAccounting",
    "UsageEvidenceError",
    "build_legacy_usage_accounting",
    "build_no_provider_usage_accounting",
    "canonical_usage_hash",
    "code_owned_usage_policy_hash",
    "validate_cost_evidence",
    "validate_token_evidence",
    "validate_usage_accounting",
)
