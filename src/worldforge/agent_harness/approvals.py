"""Private execution-approval values and code-owned authority custody.

The in-memory authority retains an asserted reviewer label. The authenticated
durable Studio authority implements the same narrow execution port and may be
composed explicitly into a same-process kernel under ADR-0049. Automatic Studio
execution hydration and separate-process authority isolation remain absent.
Authority identity and live trust operations are held only by synchronized
closure-owned weak custody.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from types import FunctionType, MethodType
from weakref import ReferenceType, ref

from worldforge.agent_harness_contracts import MAX_SAFE_INTEGER

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_TOOL_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}(?:\.[a-z][a-z0-9_]{1,63})+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_REVIEW_FORMAT = "world-forge.private.execution_approval_review"
_DECISION_FORMAT = "world-forge.private.execution_approval_decision"
_FORMAT_VERSION = 1
_MAX_TOOL_CANDIDATES = 128
_MAX_TOOL_ID_CHARACTERS = 1024
_RLOCK_TYPE = type(threading.RLock())


class ApprovalError(ValueError):
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
        raise ApprovalError(reason_code) from None


def _hash(document: dict[str, object], reason_code: str) -> str:
    return hashlib.sha256(_canonical(document, reason_code)).hexdigest()


def _exact_id(value: object, reason_code: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise ApprovalError(reason_code)
    return value


def _exact_hash(value: object, reason_code: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ApprovalError(reason_code)
    return value


def _exact_integer(value: object, reason_code: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        raise ApprovalError(reason_code)
    return value


def _exact_optional_integer(value: object, reason_code: str) -> int | None:
    if value is None:
        return None
    return _exact_integer(value, reason_code)


def _tool_candidates(
    value: object,
    reason_code: str,
) -> tuple[tuple[str, str], ...]:
    if type(value) is not tuple or len(value) > _MAX_TOOL_CANDIDATES:
        raise ApprovalError(reason_code)
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in tuple.__iter__(value):
        if type(item) is not tuple or len(item) != 2:
            raise ApprovalError(reason_code)
        tool_id, descriptor_hash = item
        if (
            type(tool_id) is not str
            or len(tool_id) > _MAX_TOOL_ID_CHARACTERS
            or _TOOL_RE.fullmatch(tool_id) is None
            or tool_id in seen
        ):
            raise ApprovalError(reason_code)
        seen.add(tool_id)
        result.append((tool_id, _exact_hash(descriptor_hash, reason_code)))
    return tuple(result)


def _tool_ids(value: object, reason_code: str) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > _MAX_TOOL_CANDIDATES:
        raise ApprovalError(reason_code)
    result: list[str] = []
    seen: set[str] = set()
    for tool_id in tuple.__iter__(value):
        if (
            type(tool_id) is not str
            or len(tool_id) > _MAX_TOOL_ID_CHARACTERS
            or _TOOL_RE.fullmatch(tool_id) is None
            or tool_id in seen
        ):
            raise ApprovalError(reason_code)
        seen.add(tool_id)
        result.append(tool_id)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class ExecutionApprovalReview:
    approval_id: str
    execution_id: str
    activation_hash: str
    grant_hash: str
    private_input_hash: str
    runtime_id: str
    runtime_revision: int
    runtime_content_hash: str
    max_turns: int
    max_tool_calls: int
    max_total_tokens: int
    max_cost_minor_units: int | None
    currency: str | None
    max_duration_ms: int
    deadline_ms: int | None
    tool_candidates: tuple[tuple[str, str], ...]
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
        private_input_hash: object,
        runtime_id: object,
        runtime_revision: object,
        runtime_content_hash: object,
        max_turns: object,
        max_tool_calls: object,
        max_total_tokens: object,
        max_cost_minor_units: object,
        currency: object,
        max_duration_ms: object,
        deadline_ms: object,
        tool_candidates: object,
    ) -> ExecutionApprovalReview:
        reason = "approval_review_invalid"
        values = {
            "approval_id": _exact_id(approval_id, reason),
            "execution_id": _exact_id(execution_id, reason),
            "activation_hash": _exact_hash(activation_hash, reason),
            "grant_hash": _exact_hash(grant_hash, reason),
            "private_input_hash": _exact_hash(private_input_hash, reason),
            "runtime_id": _exact_id(runtime_id, reason),
            "runtime_revision": _exact_integer(runtime_revision, reason, minimum=1),
            "runtime_content_hash": _exact_hash(runtime_content_hash, reason),
            "max_turns": _exact_integer(max_turns, reason, minimum=1),
            "max_tool_calls": _exact_integer(max_tool_calls, reason),
            "max_total_tokens": _exact_integer(max_total_tokens, reason),
            "max_cost_minor_units": _exact_optional_integer(max_cost_minor_units, reason),
            "currency": currency,
            "max_duration_ms": _exact_integer(max_duration_ms, reason),
            "deadline_ms": _exact_optional_integer(deadline_ms, reason),
            "tool_candidates": _tool_candidates(tool_candidates, reason),
            "generation": 0,
        }
        if (values["max_cost_minor_units"] is None) != (currency is None):
            raise ApprovalError(reason)
        if values["max_turns"] > 64 or values["max_tool_calls"] > 128:
            raise ApprovalError(reason)
        if currency is not None and (
            type(currency) is not str or _CURRENCY_RE.fullmatch(currency) is None
        ):
            raise ApprovalError(reason)
        document = cls._document_from_values(values)
        return cls(**values, content_hash=_hash(document, reason))  # type: ignore[arg-type]

    @staticmethod
    def _document_from_values(values: dict[str, object]) -> dict[str, object]:
        return {
            "format": _REVIEW_FORMAT,
            "format_version": _FORMAT_VERSION,
            **values,
            "tool_candidates": [
                {"tool_id": tool_id, "descriptor_hash": descriptor_hash}
                for tool_id, descriptor_hash in values["tool_candidates"]  # type: ignore[union-attr]
            ],
        }

    def as_document(self) -> dict[str, object]:
        values = {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
            if field != "content_hash"
        }
        return {**self._document_from_values(values), "content_hash": self.content_hash}


def _validate_review(value: object) -> ExecutionApprovalReview:
    reason = "approval_review_invalid"
    if type(value) is not ExecutionApprovalReview:
        raise ApprovalError(reason)
    _exact_hash(value.content_hash, reason)
    recreated = ExecutionApprovalReview.create(
        approval_id=value.approval_id,
        execution_id=value.execution_id,
        activation_hash=value.activation_hash,
        grant_hash=value.grant_hash,
        private_input_hash=value.private_input_hash,
        runtime_id=value.runtime_id,
        runtime_revision=value.runtime_revision,
        runtime_content_hash=value.runtime_content_hash,
        max_turns=value.max_turns,
        max_tool_calls=value.max_tool_calls,
        max_total_tokens=value.max_total_tokens,
        max_cost_minor_units=value.max_cost_minor_units,
        currency=value.currency,
        max_duration_ms=value.max_duration_ms,
        deadline_ms=value.deadline_ms,
        tool_candidates=value.tool_candidates,
    )
    if type(value.generation) is not int or value.generation != 0 or value != recreated:
        raise ApprovalError(reason)
    return recreated


@dataclass(frozen=True, slots=True)
class ExecutionApprovalDecision:
    approval_id: str
    execution_id: str
    review_hash: str
    generation: int
    reviewer_id: str
    outcome: str
    approved_tool_ids: tuple[str, ...]
    expires_at_ms: int | None
    content_hash: str

    @classmethod
    def create(
        cls,
        *,
        review: object,
        reviewer_id: object,
        outcome: object,
        approved_tool_ids: object,
        expires_at_ms: object,
    ) -> ExecutionApprovalDecision:
        reason = "approval_decision_invalid"
        review = _validate_review(review)
        reviewer_id = _exact_id(reviewer_id, reason)
        if type(outcome) is not str or outcome not in {"approved", "denied"}:
            raise ApprovalError(reason)
        approved = _tool_ids(approved_tool_ids, reason)
        expiry = _exact_optional_integer(expires_at_ms, reason)
        candidate_order = tuple(tool_id for tool_id, _descriptor_hash in review.tool_candidates)
        if (
            outcome == "denied"
            and (approved or expiry is not None)
            or outcome == "approved"
            and (
                expiry is None
                or any(tool_id not in candidate_order for tool_id in approved)
                or approved != tuple(tool_id for tool_id in candidate_order if tool_id in approved)
            )
        ):
            raise ApprovalError(reason)
        values: dict[str, object] = {
            "approval_id": review.approval_id,
            "execution_id": review.execution_id,
            "review_hash": review.content_hash,
            "generation": 1,
            "reviewer_id": reviewer_id,
            "outcome": outcome,
            "approved_tool_ids": approved,
            "expires_at_ms": expiry,
        }
        document = {
            "format": _DECISION_FORMAT,
            "format_version": _FORMAT_VERSION,
            **values,
            "approved_tool_ids": list(approved),
        }
        return cls(**values, content_hash=_hash(document, reason))  # type: ignore[arg-type]

    def as_document(self) -> dict[str, object]:
        return {
            "format": _DECISION_FORMAT,
            "format_version": _FORMAT_VERSION,
            "approval_id": self.approval_id,
            "execution_id": self.execution_id,
            "review_hash": self.review_hash,
            "generation": self.generation,
            "reviewer_id": self.reviewer_id,
            "outcome": self.outcome,
            "approved_tool_ids": list(self.approved_tool_ids),
            "expires_at_ms": self.expires_at_ms,
            "content_hash": self.content_hash,
        }


def _validate_decision(value: object) -> ExecutionApprovalDecision:
    reason = "approval_decision_invalid"
    if type(value) is not ExecutionApprovalDecision:
        raise ApprovalError(reason)
    _exact_id(value.approval_id, reason)
    _exact_id(value.execution_id, reason)
    _exact_hash(value.review_hash, reason)
    _exact_integer(value.generation, reason, minimum=1)
    _exact_id(value.reviewer_id, reason)
    approved = _tool_ids(value.approved_tool_ids, reason)
    expiry = _exact_optional_integer(value.expires_at_ms, reason)
    _exact_hash(value.content_hash, reason)
    if (
        value.generation != 1
        or type(value.outcome) is not str
        or value.outcome not in {"approved", "denied"}
    ):
        raise ApprovalError(reason)
    if value.outcome == "denied" and (approved or expiry is not None):
        raise ApprovalError(reason)
    if value.outcome == "approved" and expiry is None:
        raise ApprovalError(reason)
    document = {key: item for key, item in value.as_document().items() if key != "content_hash"}
    if value.content_hash != _hash(document, reason):
        raise ApprovalError(reason)
    return replace(value, approved_tool_ids=approved)


@dataclass(frozen=True, slots=True)
class ApprovalCheck:
    review_hash: str
    decision_hash: str
    approved_tool_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ApprovalAuthoritySnapshot:
    """Detached authority state captured atomically for one execution attempt."""

    prepared_review: ExecutionApprovalReview | None
    current_decision: ExecutionApprovalDecision | None
    generation: int
    review_hash: str
    decision_hash: str | None
    state: str


class ExecutionApprovalAuthority(ABC):
    """Narrow host-owned approval port consumed by the execution kernel."""

    @abstractmethod
    def prepare(
        self,
        review: object,
        *,
        expected_generation: object,
    ) -> ExecutionApprovalReview: ...

    @abstractmethod
    def snapshot(self, review: object) -> ApprovalAuthoritySnapshot: ...

    @abstractmethod
    def check_snapshot(
        self,
        review: object,
        expected: object,
        *,
        now_ms: object,
    ) -> ApprovalCheck: ...


@dataclass(frozen=True, slots=True)
class _ExecutionApprovalAuthorityBinding:
    owner: ExecutionApprovalAuthority
    prepare: object
    snapshot: object
    check_snapshot: object
    _validate_owner: FunctionType
    _validate_captured: FunctionType

    def validate(self) -> None:
        self._validate_owner(self.owner)


@dataclass(slots=True)
class _ApprovalRecord:
    review: ExecutionApprovalReview
    decision: ExecutionApprovalDecision | None = None
    revoked: bool = False

    @property
    def generation(self) -> int:
        return 2 if self.revoked else 1 if self.decision is not None else 0


class InMemoryHumanApprovalAuthority(ExecutionApprovalAuthority):
    """Instance-scoped CAS store; it authenticates no reviewer identities."""

    def __init__(self) -> None:
        self._records: dict[str, _ApprovalRecord] = {}
        self._lock = threading.RLock()
        _register_in_memory_execution_approval_authority(self)

    def prepare(
        self,
        review: object,
        *,
        expected_generation: object,
    ) -> ExecutionApprovalReview:
        review = _validate_review(review)
        if type(expected_generation) is not int or expected_generation != 0:
            raise ApprovalError("approval_stale")
        with self._lock:
            record = self._records.get(review.approval_id)
            if record is None:
                record = _ApprovalRecord(replace(review))
                self._records[review.approval_id] = record
                return replace(record.review)
            if record.review == review:
                return replace(record.review)
            raise ApprovalError("approval_stale")

    def decide(
        self,
        decision: object,
        *,
        expected_generation: object,
        expected_review_hash: object,
    ) -> ExecutionApprovalDecision:
        decision = _validate_decision(decision)
        if (
            type(expected_generation) is not int
            or expected_generation != 0
            or _exact_hash(expected_review_hash, "approval_stale") != decision.review_hash
        ):
            raise ApprovalError("approval_stale")
        with self._lock:
            record = self._records.get(decision.approval_id)
            if record is None:
                raise ApprovalError("approval_required")
            if record.decision == decision and not record.revoked:
                return replace(record.decision)
            if (
                record.generation != 0
                or record.review.content_hash != decision.review_hash
                or record.review.execution_id != decision.execution_id
            ):
                raise ApprovalError("approval_stale")
            candidates = tuple(tool_id for tool_id, _hash_value in record.review.tool_candidates)
            if any(tool_id not in candidates for tool_id in decision.approved_tool_ids):
                raise ApprovalError("approval_invalid")
            if decision.approved_tool_ids != tuple(
                tool_id for tool_id in candidates if tool_id in decision.approved_tool_ids
            ):
                raise ApprovalError("approval_invalid")
            record.decision = replace(decision)
            return replace(record.decision)

    def revoke(
        self,
        approval_id: object,
        *,
        expected_generation: object,
        expected_decision_hash: object,
    ) -> None:
        approval_id = _exact_id(approval_id, "approval_stale")
        decision_hash = _exact_hash(expected_decision_hash, "approval_stale")
        if type(expected_generation) is not int or expected_generation != 1:
            raise ApprovalError("approval_stale")
        with self._lock:
            record = self._records.get(approval_id)
            if record is None or record.decision is None:
                raise ApprovalError("approval_required")
            if record.decision.content_hash != decision_hash:
                raise ApprovalError("approval_stale")
            if record.revoked:
                return
            if record.generation != 1:
                raise ApprovalError("approval_stale")
            record.revoked = True

    def fingerprint_hashes(
        self,
        review: object,
    ) -> tuple[str, str | None]:
        snapshot = self.snapshot(review)
        return snapshot.review_hash, snapshot.decision_hash

    def snapshot(self, review: object) -> ApprovalAuthoritySnapshot:
        """Capture review, decision, generation, hashes, and state under one lock."""

        review = _validate_review(review)
        with self._lock:
            record = self._records.get(review.approval_id)
            if record is None:
                return ApprovalAuthoritySnapshot(
                    prepared_review=None,
                    current_decision=None,
                    generation=0,
                    review_hash=review.content_hash,
                    decision_hash=None,
                    state="missing",
                )
            if record.review != review:
                return ApprovalAuthoritySnapshot(
                    prepared_review=None,
                    current_decision=None,
                    generation=0,
                    review_hash=review.content_hash,
                    decision_hash=None,
                    state="stale",
                )
            decision = None if record.decision is None else replace(record.decision)
            state = (
                "revoked"
                if record.revoked
                else "prepared"
                if decision is None
                else decision.outcome
            )
            return ApprovalAuthoritySnapshot(
                prepared_review=replace(record.review),
                current_decision=decision,
                generation=record.generation,
                review_hash=record.review.content_hash,
                decision_hash=None if decision is None else decision.content_hash,
                state=state,
            )

    def check_snapshot(
        self,
        review: object,
        expected: object,
        *,
        now_ms: object,
    ) -> ApprovalCheck:
        """Authorize only the immutable authority snapshot chosen before journal begin."""

        review = _validate_review(review)
        expected = _validate_authority_snapshot(expected)
        now = _exact_integer(now_ms, "approval_check_failed")
        if expected.review_hash != review.content_hash:
            raise ApprovalError("approval_stale")
        if expected.state == "missing" or expected.state == "prepared":
            # A decision arriving after the snapshot is deliberately not adopted.
            raise ApprovalError("approval_required")
        if expected.state == "stale":
            raise ApprovalError("approval_stale")
        with self._lock:
            record = self._records.get(review.approval_id)
            if record is None or record.review != review:
                raise ApprovalError("approval_stale")
            if record.revoked:
                raise ApprovalError("approval_revoked")
            decision = record.decision
            if (
                decision is None
                or record.generation != expected.generation
                or expected.prepared_review != record.review
                or expected.current_decision != decision
                or expected.decision_hash != decision.content_hash
            ):
                raise ApprovalError("approval_stale")
            if expected.state == "denied":
                raise ApprovalError("approval_denied")
            if expected.state != "approved" or decision.outcome != "approved":
                raise ApprovalError("approval_invalid")
            if decision.expires_at_ms is None:
                raise ApprovalError("approval_invalid")
            if now >= decision.expires_at_ms:
                raise ApprovalError("approval_expired")
            return ApprovalCheck(
                review_hash=review.content_hash,
                decision_hash=decision.content_hash,
                approved_tool_ids=decision.approved_tool_ids,
            )

    def check(self, review: object, *, now_ms: object) -> ApprovalCheck:
        snapshot = self.snapshot(review)
        return self.check_snapshot(review, snapshot, now_ms=now_ms)


def _validate_authority_snapshot(value: object) -> ApprovalAuthoritySnapshot:
    reason = "approval_check_failed"
    if type(value) is not ApprovalAuthoritySnapshot:
        raise ApprovalError(reason)
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
        raise ApprovalError(reason)
    if value.state in {"missing", "stale"}:
        if (
            value.prepared_review is not None
            or value.current_decision is not None
            or value.decision_hash is not None
            or generation != 0
        ):
            raise ApprovalError(reason)
        return replace(value, review_hash=review_hash)
    review = _validate_review(value.prepared_review)
    if review.content_hash != review_hash:
        raise ApprovalError(reason)
    if value.state == "prepared":
        if value.current_decision is not None or value.decision_hash is not None or generation != 0:
            raise ApprovalError(reason)
        return replace(value, prepared_review=review, review_hash=review_hash)
    decision = _validate_decision(value.current_decision)
    decision_hash = _exact_hash(value.decision_hash, reason)
    if (
        decision.review_hash != review_hash
        or decision.content_hash != decision_hash
        or decision.approval_id != review.approval_id
        or decision.execution_id != review.execution_id
    ):
        raise ApprovalError(reason)
    candidates = tuple(tool_id for tool_id, _descriptor_hash in review.tool_candidates)
    if decision.approved_tool_ids != tuple(
        tool_id for tool_id in candidates if tool_id in decision.approved_tool_ids
    ):
        raise ApprovalError(reason)
    if value.state == "revoked":
        if generation != 2:
            raise ApprovalError(reason)
    elif generation != 1 or value.state != decision.outcome:
        raise ApprovalError(reason)
    return replace(
        value,
        prepared_review=review,
        current_decision=decision,
        review_hash=review_hash,
        decision_hash=decision_hash,
    )


def _validate_approval_check(value: object) -> ApprovalCheck:
    reason = "approval_check_failed"
    if type(value) is not ApprovalCheck:
        raise ApprovalError(reason)
    return replace(
        value,
        review_hash=_exact_hash(value.review_hash, reason),
        decision_hash=_exact_hash(value.decision_hash, reason),
        approved_tool_ids=_tool_ids(value.approved_tool_ids, reason),
    )


def _validate_authority_snapshot_for_review(
    value: object,
    review: object,
) -> ApprovalAuthoritySnapshot:
    review = _validate_review(review)
    snapshot = _validate_authority_snapshot(value)
    if snapshot.review_hash != review.content_hash or (
        snapshot.prepared_review is not None and snapshot.prepared_review != review
    ):
        raise ApprovalError("approval_check_failed")
    return snapshot


def _validate_prepared_review_for_review(
    value: object,
    review: object,
) -> ExecutionApprovalReview:
    review = _validate_review(review)
    prepared = _validate_review(value)
    if prepared != review:
        raise ApprovalError("approval_check_failed")
    return prepared


def _validate_approval_check_for_snapshot(
    value: object,
    review: object,
    snapshot: object,
    *,
    now_ms: object,
) -> ApprovalCheck:
    review = _validate_review(review)
    snapshot = _validate_authority_snapshot_for_review(snapshot, review)
    check = _validate_approval_check(value)
    now = _exact_integer(now_ms, "approval_check_failed")
    decision = snapshot.current_decision
    if (
        snapshot.state != "approved"
        or decision is None
        or decision.outcome != "approved"
        or decision.expires_at_ms is None
        or now >= decision.expires_at_ms
        or check.review_hash != review.content_hash
        or check.decision_hash != snapshot.decision_hash
        or check.approved_tool_ids != decision.approved_tool_ids
    ):
        raise ApprovalError("approval_check_failed")
    return check


def _authority_functions(
    authority_type: type[object],
    _approval_error=ApprovalError,
    _function_type=FunctionType,
    _list_type=list,
    _tuple_type=tuple,
    _type=type,
    _vars=vars,
) -> tuple[tuple[str, FunctionType, object], ...]:
    result: list[tuple[str, FunctionType, object]] = _list_type()
    authority_values = _vars(authority_type)
    port_names = ("prepare", "snapshot", "check_snapshot")
    for name in port_names:
        value = authority_values.get(name)
        if _type(value) is not _function_type:
            raise _approval_error("approval_authority_invalid")
        result.append((name, value, value.__code__))
    for name, value in authority_values.items():
        if name not in port_names and _type(value) is _function_type:
            result.append((name, value, value.__code__))
    return _tuple_type(result)


_IN_MEMORY_AUTHORITY_FUNCTIONS = _authority_functions(InMemoryHumanApprovalAuthority)
_IN_MEMORY_AUTHORITY_CONSTRUCTOR_CODE = InMemoryHumanApprovalAuthority.__init__.__code__


def _build_execution_approval_authority_capsule(
    _all=all,
    _any=any,
    _approval_error=ApprovalError,
    _authority_base=ExecutionApprovalAuthority,
    _authority_functions_impl=_authority_functions,
    _binding_type=_ExecutionApprovalAuthorityBinding,
    _dict_type=dict,
    _exception_type=Exception,
    _frame_getter=sys._getframe,
    _function_type=FunctionType,
    _id=id,
    _in_memory_type=InMemoryHumanApprovalAuthority,
    _method_type=MethodType,
    _modules=sys.modules,
    _object_getattribute=object.__getattribute__,
    _ref=ref,
    _rlock_factory=threading.RLock,
    _rlock_type=_RLOCK_TYPE,
    _type=type,
    _vars=vars,
):
    authority_functions = _authority_functions_impl
    authority_metaclass = _type(_authority_base)
    in_memory_type = _in_memory_type
    in_memory_functions = authority_functions(in_memory_type)
    in_memory_constructor_code = in_memory_type.__init__.__code__
    binding_validate_function = _binding_type.validate
    registry: dict[
        int,
        tuple[
            ReferenceType[object],
            type[object],
            tuple[tuple[str, FunctionType, object], ...],
            tuple[tuple[str, object], ...],
        ],
    ] = {}
    lock = _rlock_factory()
    studio_trust: tuple[
        type[object],
        tuple[tuple[str, FunctionType, object], ...],
        FunctionType,
    ] | None = None

    def register(
        value: object,
        authority_type: type[object],
        functions: tuple[tuple[str, FunctionType, object], ...],
        sealed_values: tuple[tuple[str, object], ...],
    ) -> None:
        identity = _id(value)

        def retire(registered_ref: ReferenceType[object]) -> None:
            with lock:
                registered = registry.get(identity)
                if registered is not None and registered[0] is registered_ref:
                    del registry[identity]

        with lock:
            registry[identity] = (
                _ref(value, retire),
                authority_type,
                functions,
                sealed_values,
            )

    def register_in_memory(value: object) -> None:
        try:
            caller_code = _frame_getter(1).f_code
        except _exception_type:
            raise _approval_error("approval_authority_invalid") from None
        if (
            _type(value) is not in_memory_type
            or caller_code is not in_memory_constructor_code
            or _type(value._records) is not _dict_type
            or _type(value._lock) is not _rlock_type
            or authority_functions(_type(value)) != in_memory_functions
        ):
            raise _approval_error("approval_authority_invalid")
        register(
            value,
            in_memory_type,
            in_memory_functions,
            (("_records", value._records), ("_lock", value._lock)),
        )

    def configure_studio(
        authority_type: object,
        provenance_consumer: object,
    ) -> None:
        nonlocal studio_trust
        try:
            caller = _frame_getter(1)
            caller_globals = caller.f_globals
            module = _modules["worldforge.studio.authenticated_human_decisions"]
        except _exception_type:
            raise _approval_error("approval_authority_invalid") from None
        if (
            studio_trust is not None
            or _type(authority_type) is not authority_metaclass
            or authority_type.__module__
            != "worldforge.studio.authenticated_human_decisions"
            or authority_type.__name__
            != "StudioAuthenticatedHumanDecisionAuthority"
            or caller_globals is not _vars(module)
            or caller_globals.get("StudioAuthenticatedHumanDecisionAuthority")
            is not authority_type
            or _type(provenance_consumer) is not _function_type
        ):
            raise _approval_error("approval_authority_invalid")
        studio_trust = (
            authority_type,
            authority_functions(authority_type),
            provenance_consumer,
        )

    def register_studio(value: object, provenance: object) -> None:
        trust = studio_trust
        if trust is None:
            raise _approval_error("approval_authority_invalid")
        studio_type, studio_functions, provenance_consumer = trust
        sealed_values = provenance_consumer(
            value,
            provenance,
        )
        if (
            _type(value) is not studio_type
            or authority_functions(_type(value)) != studio_functions
        ):
            raise _approval_error("approval_authority_invalid")
        try:
            if not _all(
                _object_getattribute(value, name) is expected
                for name, expected in sealed_values
            ):
                raise _approval_error("approval_authority_invalid")
        except _approval_error:
            raise
        except _exception_type:
            raise _approval_error("approval_authority_invalid") from None
        register(
            value,
            studio_type,
            studio_functions,
            sealed_values,
        )

    def validate(value: object) -> tuple[tuple[str, FunctionType, object], ...]:
        with lock:
            registered = registry.get(_id(value))
            if registered is None or registered[0]() is not value:
                raise _approval_error("approval_authority_invalid")
            try:
                valid = (
                    _type(value) is registered[1]
                    and authority_functions(_type(value)) == registered[2]
                    and _all(
                        _object_getattribute(value, name) is expected
                        for name, expected in registered[3]
                    )
                )
            except _exception_type:
                valid = False
            if not valid:
                raise _approval_error("approval_authority_invalid")
            functions = registered[2]
        instance_values = _object_getattribute(value, "__dict__")
        if _any(name in instance_values for name, _function, _code in functions):
            raise _approval_error("approval_authority_invalid")
        return functions

    def contains(value: object) -> bool:
        with lock:
            registered = registry.get(_id(value))
            return registered is not None and registered[0]() is value

    def bind(value: object) -> _ExecutionApprovalAuthorityBinding:
        functions = validate(value)
        bound: list[MethodType] = []
        for name, function, code in functions:
            try:
                method = _object_getattribute(value, name)
            except _exception_type:
                raise _approval_error("approval_authority_invalid") from None
            if (
                _type(method) is not _method_type
                or method.__self__ is not value
                or method.__func__ is not function
                or method.__func__.__code__ is not code
            ):
                raise _approval_error("approval_authority_invalid")
            if name in ("prepare", "snapshot", "check_snapshot"):
                bound.append(method)
        binding = None
        binding_identity = None

        def validate_captured() -> None:
            if (
                binding is None
                or binding_identity is None
                or _id(binding) != binding_identity
            ):
                raise _approval_error("approval_authority_invalid")
            validate(value)

        binding = _binding_type(
            value,
            *bound,
            validate,
            validate_captured,
        )
        binding_identity = _id(binding)
        try:
            binding_validate = _object_getattribute(binding, "validate")
        except _exception_type:
            raise _approval_error("approval_authority_invalid") from None
        if (
            _type(binding_validate) is not _method_type
            or binding_validate.__self__ is not binding
            or binding_validate.__func__ is not binding_validate_function
            or binding_validate.__func__.__code__ is not binding_validate_function.__code__
        ):
            raise _approval_error("approval_authority_invalid")
        return binding

    return (
        register_in_memory,
        configure_studio,
        register_studio,
        validate,
        contains,
        bind,
    )


(
    _register_in_memory_execution_approval_authority,
    _configure_studio_execution_approval_authority,
    _register_studio_execution_approval_authority,
    _validate_registered_execution_approval_authority,
    _execution_approval_authority_registered,
    _validate_execution_approval_authority,
) = _build_execution_approval_authority_capsule()


__all__ = (
    "ApprovalAuthoritySnapshot",
    "ApprovalError",
    "ExecutionApprovalDecision",
    "ExecutionApprovalAuthority",
    "ExecutionApprovalReview",
    "InMemoryHumanApprovalAuthority",
)
