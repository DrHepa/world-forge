"""Private four-facet provider execution approval authority."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, replace

from worldforge.agent_harness_contracts import MAX_SAFE_INTEGER

from .provider_catalog import (
    ProviderCatalogError,
    ResolvedProviderExecution,
    _validate_resolved,
)

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REVIEW_FORMAT = "world-forge.private.provider_governance_review"
_DECISION_FORMAT = "world-forge.private.provider_governance_decision"
_FORMAT_VERSION = 1


class ProviderGovernanceError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _canonical(value: object, reason_code: str) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except Exception:
        raise ProviderGovernanceError(reason_code) from None


def _hash(value: object, reason_code: str) -> str:
    return hashlib.sha256(_canonical(value, reason_code)).hexdigest()


def _exact_id(value: object, reason_code: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise ProviderGovernanceError(reason_code)
    return value


def _exact_hash(value: object, reason_code: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ProviderGovernanceError(reason_code)
    return value


def _exact_integer(value: object, reason_code: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        raise ProviderGovernanceError(reason_code)
    return value


def _resolved(value: object, reason_code: str) -> ResolvedProviderExecution:
    try:
        return _validate_resolved(value)
    except ProviderCatalogError:
        raise ProviderGovernanceError(reason_code) from None


@dataclass(frozen=True, slots=True)
class ProviderGovernanceReview:
    approval_id: str
    execution_id: str
    activation_hash: str
    grant_hash: str
    work_order_hash: str
    private_input_hash: str
    selection_hash: str
    selection_facet_hash: str
    destination_facet_hash: str
    data_facet_hash: str
    pricing_facet_hash: str
    generation: int
    content_hash: str

    @classmethod
    def create(
        cls,
        *,
        approval_id: object,
        execution_id: object,
        activation_hash: object,
        grant_hash: object,
        work_order_hash: object,
        private_input_hash: object,
        resolved: object,
    ) -> ProviderGovernanceReview:
        reason = "provider_governance_review_invalid"
        resolved = _resolved(resolved, reason)
        spec = resolved.spec
        selection = resolved.selection
        checked_private_input_hash = _exact_hash(private_input_hash, reason)
        if checked_private_input_hash != selection.base_payload_hash:
            raise ProviderGovernanceError(reason)
        selection_hash = selection.content_hash
        destination_hash = _hash(
            {
                "deployment_class": spec.deployment_class,
                "network_scope": spec.network_scope,
                "endpoint_origin": spec.endpoint_origin,
                "endpoint_policy_hash": spec.endpoint_policy_hash,
                "egress_enforcement_hash": spec.egress_enforcement_hash,
                "telemetry_attestation_hash": spec.telemetry_attestation_hash,
                "redirects_disabled": spec.redirects_disabled,
            },
            reason,
        )
        data_hash = _hash(
            {
                "disclosure_plan_hash": selection.disclosure_plan_hash,
                "disclosed_data_classes": list(selection.disclosed_data_classes),
                "base_payload_hash": selection.base_payload_hash,
            },
            reason,
        )
        pricing_hash = _hash(
            {
                "usage_policy_hash": selection.usage_policy_hash,
                "pricing_policy_hash": selection.pricing_policy_hash,
                "currency": selection.currency,
                "max_total_tokens": selection.max_total_tokens,
                "max_cost_minor_units": selection.max_cost_minor_units,
            },
            reason,
        )
        values: dict[str, object] = {
            "approval_id": _exact_id(approval_id, reason),
            "execution_id": _exact_id(execution_id, reason),
            "activation_hash": _exact_hash(activation_hash, reason),
            "grant_hash": _exact_hash(grant_hash, reason),
            "work_order_hash": _exact_hash(work_order_hash, reason),
            "private_input_hash": checked_private_input_hash,
            "selection_hash": selection_hash,
            "selection_facet_hash": selection_hash,
            "destination_facet_hash": destination_hash,
            "data_facet_hash": data_hash,
            "pricing_facet_hash": pricing_hash,
            "generation": 0,
        }
        document = {"format": _REVIEW_FORMAT, "format_version": _FORMAT_VERSION, **values}
        return cls(**values, content_hash=_hash(document, reason))  # type: ignore[arg-type]

    def as_document(self) -> dict[str, object]:
        return {
            "format": _REVIEW_FORMAT,
            "format_version": _FORMAT_VERSION,
            **{field: getattr(self, field) for field in self.__dataclass_fields__},
        }


def _validate_review(value: object) -> ProviderGovernanceReview:
    reason = "provider_governance_review_invalid"
    if type(value) is not ProviderGovernanceReview:
        raise ProviderGovernanceError(reason)
    for name in (
        "activation_hash",
        "grant_hash",
        "work_order_hash",
        "private_input_hash",
        "selection_hash",
        "selection_facet_hash",
        "destination_facet_hash",
        "data_facet_hash",
        "pricing_facet_hash",
        "content_hash",
    ):
        _exact_hash(getattr(value, name), reason)
    _exact_id(value.approval_id, reason)
    _exact_id(value.execution_id, reason)
    if (
        type(value.generation) is not int
        or value.generation != 0
        or value.selection_hash != value.selection_facet_hash
    ):
        raise ProviderGovernanceError(reason)
    document = {key: item for key, item in value.as_document().items() if key != "content_hash"}
    if value.content_hash != _hash(document, reason):
        raise ProviderGovernanceError(reason)
    return replace(value)


@dataclass(frozen=True, slots=True)
class ProviderGovernanceDecision:
    approval_id: str
    execution_id: str
    activation_hash: str
    grant_hash: str
    work_order_hash: str
    private_input_hash: str
    review_hash: str
    selection_hash: str
    selection_facet_hash: str
    destination_facet_hash: str
    data_facet_hash: str
    pricing_facet_hash: str
    generation: int
    reviewer_id: str
    outcome: str
    expires_at_ms: int | None
    content_hash: str

    @classmethod
    def create(
        cls,
        *,
        review: object,
        reviewer_id: object,
        outcome: object,
        expires_at_ms: object,
    ) -> ProviderGovernanceDecision:
        reason = "provider_governance_decision_invalid"
        review = _validate_review(review)
        if type(outcome) is not str or outcome not in {"approved", "denied"}:
            raise ProviderGovernanceError(reason)
        if expires_at_ms is None:
            expiry = None
        else:
            expiry = _exact_integer(expires_at_ms, reason)
        if outcome == "approved" and expiry is None or outcome == "denied" and expiry is not None:
            raise ProviderGovernanceError(reason)
        values: dict[str, object] = {
            "approval_id": review.approval_id,
            "execution_id": review.execution_id,
            "activation_hash": review.activation_hash,
            "grant_hash": review.grant_hash,
            "work_order_hash": review.work_order_hash,
            "private_input_hash": review.private_input_hash,
            "review_hash": review.content_hash,
            "selection_hash": review.selection_hash,
            "selection_facet_hash": review.selection_facet_hash,
            "destination_facet_hash": review.destination_facet_hash,
            "data_facet_hash": review.data_facet_hash,
            "pricing_facet_hash": review.pricing_facet_hash,
            "generation": 1,
            "reviewer_id": _exact_id(reviewer_id, reason),
            "outcome": outcome,
            "expires_at_ms": expiry,
        }
        document = {"format": _DECISION_FORMAT, "format_version": _FORMAT_VERSION, **values}
        return cls(**values, content_hash=_hash(document, reason))  # type: ignore[arg-type]

    def as_document(self) -> dict[str, object]:
        return {
            "format": _DECISION_FORMAT,
            "format_version": _FORMAT_VERSION,
            **{field: getattr(self, field) for field in self.__dataclass_fields__},
        }


def _validate_decision(value: object) -> ProviderGovernanceDecision:
    reason = "provider_governance_decision_invalid"
    if type(value) is not ProviderGovernanceDecision:
        raise ProviderGovernanceError(reason)
    _exact_id(value.approval_id, reason)
    _exact_id(value.execution_id, reason)
    _exact_id(value.reviewer_id, reason)
    for name in (
        "activation_hash",
        "grant_hash",
        "work_order_hash",
        "private_input_hash",
        "review_hash",
        "selection_hash",
        "selection_facet_hash",
        "destination_facet_hash",
        "data_facet_hash",
        "pricing_facet_hash",
        "content_hash",
    ):
        _exact_hash(getattr(value, name), reason)
    if (
        type(value.generation) is not int
        or value.generation != 1
        or type(value.outcome) is not str
        or value.outcome not in {"approved", "denied"}
        or value.outcome == "approved"
        and value.expires_at_ms is None
        or value.outcome == "denied"
        and value.expires_at_ms is not None
    ):
        raise ProviderGovernanceError(reason)
    if value.expires_at_ms is not None:
        _exact_integer(value.expires_at_ms, reason)
    document = {key: item for key, item in value.as_document().items() if key != "content_hash"}
    if value.content_hash != _hash(document, reason):
        raise ProviderGovernanceError(reason)
    return replace(value)


@dataclass(frozen=True, slots=True)
class ProviderGovernanceCheck:
    review_hash: str
    decision_hash: str
    selection_hash: str
    destination_facet_hash: str
    data_facet_hash: str
    pricing_facet_hash: str


@dataclass(frozen=True, slots=True)
class ProviderGovernanceSnapshot:
    prepared_review: ProviderGovernanceReview | None
    current_decision: ProviderGovernanceDecision | None
    generation: int
    review_hash: str
    decision_hash: str | None
    state: str


@dataclass(slots=True)
class _Record:
    review: ProviderGovernanceReview
    decision: ProviderGovernanceDecision | None = None
    revoked: bool = False

    @property
    def generation(self) -> int:
        return 2 if self.revoked else 1 if self.decision is not None else 0


class InMemoryProviderGovernanceAuthority:
    """Instance-scoped CAS store; reviewer labels are not authenticated."""

    def __init__(self) -> None:
        self._records: dict[str, _Record] = {}
        self._lock = threading.RLock()

    def prepare(
        self,
        review: object,
        *,
        expected_generation: object,
    ) -> ProviderGovernanceReview:
        review = _validate_review(review)
        if type(expected_generation) is not int or expected_generation != 0:
            raise ProviderGovernanceError("provider_approval_stale")
        with self._lock:
            record = self._records.get(review.approval_id)
            if record is None:
                self._records[review.approval_id] = _Record(replace(review))
                return replace(review)
            if record.review == review:
                return replace(record.review)
            raise ProviderGovernanceError("provider_approval_stale")

    def decide(
        self,
        decision: object,
        *,
        expected_generation: object,
        expected_review_hash: object,
    ) -> ProviderGovernanceDecision:
        decision = _validate_decision(decision)
        if (
            type(expected_generation) is not int
            or expected_generation != 0
            or _exact_hash(expected_review_hash, "provider_approval_stale") != decision.review_hash
        ):
            raise ProviderGovernanceError("provider_approval_stale")
        with self._lock:
            record = self._records.get(decision.approval_id)
            if record is None:
                raise ProviderGovernanceError("provider_approval_required")
            if record.decision == decision and not record.revoked:
                return replace(record.decision)
            review = record.review
            if (
                record.generation != 0
                or review.content_hash != decision.review_hash
                or review.execution_id != decision.execution_id
                or review.activation_hash != decision.activation_hash
                or review.grant_hash != decision.grant_hash
                or review.work_order_hash != decision.work_order_hash
                or review.private_input_hash != decision.private_input_hash
                or review.selection_hash != decision.selection_hash
                or review.selection_facet_hash != decision.selection_facet_hash
                or review.destination_facet_hash != decision.destination_facet_hash
                or review.data_facet_hash != decision.data_facet_hash
                or review.pricing_facet_hash != decision.pricing_facet_hash
            ):
                raise ProviderGovernanceError("provider_approval_stale")
            record.decision = replace(decision)
            return replace(record.decision)

    def revoke(
        self,
        approval_id: object,
        *,
        expected_generation: object,
        expected_decision_hash: object,
    ) -> None:
        approval_id = _exact_id(approval_id, "provider_approval_stale")
        decision_hash = _exact_hash(expected_decision_hash, "provider_approval_stale")
        if type(expected_generation) is not int or expected_generation != 1:
            raise ProviderGovernanceError("provider_approval_stale")
        with self._lock:
            record = self._records.get(approval_id)
            if record is None or record.decision is None:
                raise ProviderGovernanceError("provider_approval_required")
            if record.decision.content_hash != decision_hash:
                raise ProviderGovernanceError("provider_approval_stale")
            if record.revoked:
                return
            if record.generation != 1:
                raise ProviderGovernanceError("provider_approval_stale")
            record.revoked = True

    def snapshot(self, review: object) -> ProviderGovernanceSnapshot:
        review = _validate_review(review)
        with self._lock:
            record = self._records.get(review.approval_id)
            if record is None:
                return ProviderGovernanceSnapshot(
                    None,
                    None,
                    0,
                    review.content_hash,
                    None,
                    "missing",
                )
            if record.review != review:
                return ProviderGovernanceSnapshot(
                    None,
                    None,
                    0,
                    review.content_hash,
                    None,
                    "stale",
                )
            decision = None if record.decision is None else replace(record.decision)
            state = (
                "revoked"
                if record.revoked
                else "prepared"
                if decision is None
                else decision.outcome
            )
            return ProviderGovernanceSnapshot(
                replace(record.review),
                decision,
                record.generation,
                record.review.content_hash,
                None if decision is None else decision.content_hash,
                state,
            )

    def check_snapshot(
        self,
        review: object,
        expected: object,
        *,
        now_ms: object,
    ) -> ProviderGovernanceCheck:
        review = _validate_review(review)
        expected = _validate_snapshot(expected)
        now = _exact_integer(now_ms, "provider_approval_check_failed")
        if expected.review_hash != review.content_hash:
            raise ProviderGovernanceError("provider_approval_stale")
        if expected.state in {"missing", "prepared"}:
            raise ProviderGovernanceError("provider_approval_required")
        if expected.state == "stale":
            raise ProviderGovernanceError("provider_approval_stale")
        with self._lock:
            record = self._records.get(review.approval_id)
            if record is None or record.review != review:
                raise ProviderGovernanceError("provider_approval_stale")
            if record.revoked:
                raise ProviderGovernanceError("provider_approval_revoked")
            decision = record.decision
            if (
                decision is None
                or record.generation != expected.generation
                or expected.prepared_review != record.review
                or expected.current_decision != decision
                or expected.decision_hash != decision.content_hash
            ):
                raise ProviderGovernanceError("provider_approval_stale")
            if expected.state == "denied":
                raise ProviderGovernanceError("provider_approval_denied")
            if expected.state != "approved" or decision.outcome != "approved":
                raise ProviderGovernanceError("provider_approval_invalid")
            if decision.expires_at_ms is None:
                raise ProviderGovernanceError("provider_approval_invalid")
            if now >= decision.expires_at_ms:
                raise ProviderGovernanceError("provider_approval_expired")
            return ProviderGovernanceCheck(
                review.content_hash,
                decision.content_hash,
                decision.selection_hash,
                decision.destination_facet_hash,
                decision.data_facet_hash,
                decision.pricing_facet_hash,
            )

    def check(self, review: object, *, now_ms: object) -> ProviderGovernanceCheck:
        return self.check_snapshot(review, self.snapshot(review), now_ms=now_ms)


def _validate_snapshot(value: object) -> ProviderGovernanceSnapshot:
    reason = "provider_approval_check_failed"
    if type(value) is not ProviderGovernanceSnapshot:
        raise ProviderGovernanceError(reason)
    review_hash = _exact_hash(value.review_hash, reason)
    generation = _exact_integer(value.generation, reason)
    if type(value.state) is not str or value.state not in {
        "missing",
        "stale",
        "prepared",
        "approved",
        "denied",
        "revoked",
    }:
        raise ProviderGovernanceError(reason)
    if value.state in {"missing", "stale"}:
        if (
            value.prepared_review is not None
            or value.current_decision is not None
            or value.decision_hash is not None
            or generation != 0
        ):
            raise ProviderGovernanceError(reason)
        return replace(value, review_hash=review_hash)
    review = _validate_review(value.prepared_review)
    if review.content_hash != review_hash:
        raise ProviderGovernanceError(reason)
    if value.state == "prepared":
        if value.current_decision is not None or value.decision_hash is not None or generation != 0:
            raise ProviderGovernanceError(reason)
        return replace(value, prepared_review=review)
    decision = _validate_decision(value.current_decision)
    decision_hash = _exact_hash(value.decision_hash, reason)
    if (
        decision.review_hash != review_hash
        or decision.content_hash != decision_hash
        or decision.approval_id != review.approval_id
        or decision.execution_id != review.execution_id
        or decision.activation_hash != review.activation_hash
        or decision.grant_hash != review.grant_hash
        or decision.work_order_hash != review.work_order_hash
        or decision.private_input_hash != review.private_input_hash
        or decision.selection_hash != review.selection_hash
        or decision.selection_facet_hash != review.selection_facet_hash
        or decision.destination_facet_hash != review.destination_facet_hash
        or decision.data_facet_hash != review.data_facet_hash
        or decision.pricing_facet_hash != review.pricing_facet_hash
    ):
        raise ProviderGovernanceError(reason)
    if value.state == "revoked":
        if generation != 2:
            raise ProviderGovernanceError(reason)
    elif generation != 1 or value.state != decision.outcome:
        raise ProviderGovernanceError(reason)
    return replace(
        value,
        prepared_review=review,
        current_decision=decision,
        review_hash=review_hash,
        decision_hash=decision_hash,
    )


__all__ = (
    "InMemoryProviderGovernanceAuthority",
    "ProviderGovernanceCheck",
    "ProviderGovernanceDecision",
    "ProviderGovernanceError",
    "ProviderGovernanceReview",
    "ProviderGovernanceSnapshot",
)
