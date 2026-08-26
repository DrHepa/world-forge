"""Separate in-memory review authority for hash-only memory projection.

This authority is intentionally unrelated to execution/tool approval.  Reviewer
identities are asserted audit labels; authentication remains Studio-owned.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import TypeVar

from worldforge.agent_harness_contracts import MAX_SAFE_INTEGER

from .memory_projection import (
    MemoryProjectionError,
    _validated_snapshot,
)

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_REVIEW_FORMAT = "world-forge.private.memory_projection_review"
_DECISION_FORMAT = "world-forge.private.memory_projection_decision"
_FORMAT_VERSION = 1
MEMORY_PROJECTION_POLICY_ID = "lossless_hash_projection"
MEMORY_PROJECTION_POLICY_VERSION = 1
_T = TypeVar("_T")
_POLICY_DOCUMENT = {
    "format": "world-forge.private.memory_projection_policy",
    "format_version": 1,
    "policy_id": MEMORY_PROJECTION_POLICY_ID,
    "policy_version": MEMORY_PROJECTION_POLICY_VERSION,
    "content_handling": "hash_only",
    "compaction": "lossless_exact_deduplication",
    "conflict_rule": "one_value_hash_per_kind_and_subject",
    "ordering": "utf8_identifier_bytes",
    "semantic_summarization": False,
}


class MemoryApprovalError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _try_canonical(value: object) -> bytes | None:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return None


def _canonical(value: object, reason: str) -> bytes:
    encoded = _try_canonical(value)
    if encoded is None:
        raise MemoryApprovalError(reason)
    return encoded


def _hash(value: object, reason: str) -> str:
    return hashlib.sha256(_canonical(value, reason)).hexdigest()


MEMORY_PROJECTION_POLICY_HASH = _hash(
    _POLICY_DOCUMENT,
    "memory_approval_policy_invalid",
)


def _exact_id(value: object, reason: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise MemoryApprovalError(reason)
    return value


def _exact_hash(value: object, reason: str) -> str:
    if type(value) is not str or _SHA_RE.fullmatch(value) is None:
        raise MemoryApprovalError(reason)
    return value


def _exact_integer(value: object, reason: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        raise MemoryApprovalError(reason)
    return value


def _exact_optional_integer(value: object, reason: str) -> int | None:
    if value is None:
        return None
    return _exact_integer(value, reason)


def _source_event_chain(value: object, reason: str) -> tuple[tuple[str, str], ...]:
    if type(value) is not tuple or not 1 <= len(value) <= 64:
        raise MemoryApprovalError(reason)
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in tuple.__iter__(value):
        if type(item) is not tuple or len(item) != 2:
            raise MemoryApprovalError(reason)
        event_id = _exact_id(item[0], reason)
        event_hash = _exact_hash(item[1], reason)
        if event_id in seen:
            raise MemoryApprovalError(reason)
        seen.add(event_id)
        result.append((event_id, event_hash))
    return tuple(result)


def _candidate_proposals(value: object, reason: str) -> tuple[tuple[str, str], ...]:
    if type(value) is not tuple or not 1 <= len(value) <= 64:
        raise MemoryApprovalError(reason)
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in tuple.__iter__(value):
        if type(item) is not tuple or len(item) != 2:
            raise MemoryApprovalError(reason)
        proposal_id = _exact_id(item[0], reason)
        proposal_hash = _exact_hash(item[1], reason)
        if proposal_id in seen:
            raise MemoryApprovalError(reason)
        seen.add(proposal_id)
        result.append((proposal_id, proposal_hash))
    expected = tuple(sorted(result, key=lambda item: item[0].encode("utf-8")))
    if tuple(result) != expected:
        raise MemoryApprovalError(reason)
    return tuple(result)


def _proposal_ids(value: object, reason: str) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > 64:
        raise MemoryApprovalError(reason)
    result: list[str] = []
    for item in tuple.__iter__(value):
        proposal_id = _exact_id(item, reason)
        if proposal_id in result:
            raise MemoryApprovalError(reason)
        result.append(proposal_id)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class MemoryProjectionReview:
    review_id: str
    execution_id: str
    receipt_id: str
    receipt_content_hash: str
    source_event_chain: tuple[tuple[str, str], ...]
    pre_projection_event_head_hash: str
    candidate_proposals: tuple[tuple[str, str], ...]
    candidate_snapshot_hash: str
    policy_id: str
    policy_version: int
    policy_hash: str
    generation: int
    content_hash: str

    @classmethod
    def create(
        cls,
        *,
        review_id: object,
        execution_id: object,
        receipt_id: object,
        receipt_content_hash: object,
        source_event_chain: object,
        candidate_snapshot: object,
    ) -> MemoryProjectionReview:
        reason = "memory_approval_review_invalid"
        try:
            snapshot = _validated_snapshot(candidate_snapshot, require_nonempty=True)
        except MemoryProjectionError:
            raise MemoryApprovalError(reason) from None
        execution = _exact_id(execution_id, reason)
        if snapshot.execution_id != execution:
            raise MemoryApprovalError(reason)
        chain = _source_event_chain(source_event_chain, reason)
        candidates = tuple((item.proposal_id, item.content_hash) for item in snapshot.proposals)
        values: dict[str, object] = {
            "review_id": _exact_id(review_id, reason),
            "execution_id": execution,
            "receipt_id": _exact_id(receipt_id, reason),
            "receipt_content_hash": _exact_hash(receipt_content_hash, reason),
            "source_event_chain": chain,
            "pre_projection_event_head_hash": chain[-1][1],
            "candidate_proposals": candidates,
            "candidate_snapshot_hash": snapshot.content_hash,
            "policy_id": MEMORY_PROJECTION_POLICY_ID,
            "policy_version": MEMORY_PROJECTION_POLICY_VERSION,
            "policy_hash": MEMORY_PROJECTION_POLICY_HASH,
            "generation": 0,
        }
        return cls(
            **values,
            content_hash=_hash(cls._document_from_values(values), reason),
        )  # type: ignore[arg-type]

    @staticmethod
    def _document_from_values(values: dict[str, object]) -> dict[str, object]:
        return {
            "format": _REVIEW_FORMAT,
            "format_version": _FORMAT_VERSION,
            **values,
            "source_event_chain": [
                {"event_id": event_id, "content_hash": content_hash}
                for event_id, content_hash in values["source_event_chain"]  # type: ignore[union-attr]
            ],
            "candidate_proposals": [
                {"proposal_id": proposal_id, "content_hash": content_hash}
                for proposal_id, content_hash in values["candidate_proposals"]  # type: ignore[union-attr]
            ],
        }

    def as_document(self) -> dict[str, object]:
        values = {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
            if field != "content_hash"
        }
        return {**self._document_from_values(values), "content_hash": self.content_hash}


def _validate_review(value: object) -> MemoryProjectionReview:
    reason = "memory_approval_review_invalid"
    if type(value) is not MemoryProjectionReview:
        raise MemoryApprovalError(reason)
    chain = _source_event_chain(value.source_event_chain, reason)
    candidates = _candidate_proposals(value.candidate_proposals, reason)
    if (
        _exact_id(value.review_id, reason) != value.review_id
        or _exact_id(value.execution_id, reason) != value.execution_id
        or _exact_id(value.receipt_id, reason) != value.receipt_id
        or _exact_hash(value.receipt_content_hash, reason) != value.receipt_content_hash
        or _exact_hash(value.pre_projection_event_head_hash, reason) != chain[-1][1]
        or _exact_hash(value.candidate_snapshot_hash, reason) != value.candidate_snapshot_hash
        or type(value.policy_id) is not str
        or value.policy_id != MEMORY_PROJECTION_POLICY_ID
        or type(value.policy_version) is not int
        or value.policy_version != MEMORY_PROJECTION_POLICY_VERSION
        or type(value.policy_hash) is not str
        or value.policy_hash != MEMORY_PROJECTION_POLICY_HASH
        or type(value.generation) is not int
        or value.generation != 0
    ):
        raise MemoryApprovalError(reason)
    values: dict[str, object] = {
        "review_id": value.review_id,
        "execution_id": value.execution_id,
        "receipt_id": value.receipt_id,
        "receipt_content_hash": value.receipt_content_hash,
        "source_event_chain": chain,
        "pre_projection_event_head_hash": value.pre_projection_event_head_hash,
        "candidate_proposals": candidates,
        "candidate_snapshot_hash": value.candidate_snapshot_hash,
        "policy_id": value.policy_id,
        "policy_version": value.policy_version,
        "policy_hash": value.policy_hash,
        "generation": value.generation,
    }
    if _exact_hash(value.content_hash, reason) != _hash(
        MemoryProjectionReview._document_from_values(values), reason
    ):
        raise MemoryApprovalError(reason)
    return replace(value, source_event_chain=chain, candidate_proposals=candidates)


@dataclass(frozen=True, slots=True)
class MemoryProjectionDecision:
    review_id: str
    execution_id: str
    review_hash: str
    generation: int
    reviewer_id: str
    outcome: str
    approved_proposal_ids: tuple[str, ...]
    expires_at_ms: int | None
    content_hash: str

    @classmethod
    def create(
        cls,
        *,
        review: object,
        reviewer_id: object,
        outcome: object,
        approved_proposal_ids: object,
        expires_at_ms: object,
    ) -> MemoryProjectionDecision:
        reason = "memory_approval_decision_invalid"
        review = _validate_review(review)
        reviewer = _exact_id(reviewer_id, reason)
        if type(outcome) is not str or outcome not in {"approved", "denied"}:
            raise MemoryApprovalError(reason)
        approved = _proposal_ids(approved_proposal_ids, reason)
        expiry = _exact_optional_integer(expires_at_ms, reason)
        candidates = tuple(item[0] for item in review.candidate_proposals)
        if outcome == "denied":
            if approved or expiry is not None:
                raise MemoryApprovalError(reason)
        elif (
            not approved
            or expiry is None
            or any(item not in candidates for item in approved)
            or approved != tuple(item for item in candidates if item in approved)
        ):
            raise MemoryApprovalError(reason)
        values: dict[str, object] = {
            "review_id": review.review_id,
            "execution_id": review.execution_id,
            "review_hash": review.content_hash,
            "generation": 1,
            "reviewer_id": reviewer,
            "outcome": outcome,
            "approved_proposal_ids": approved,
            "expires_at_ms": expiry,
        }
        document = {
            "format": _DECISION_FORMAT,
            "format_version": _FORMAT_VERSION,
            **values,
            "approved_proposal_ids": list(approved),
        }
        return cls(**values, content_hash=_hash(document, reason))  # type: ignore[arg-type]

    def as_document(self) -> dict[str, object]:
        return {
            "format": _DECISION_FORMAT,
            "format_version": _FORMAT_VERSION,
            "review_id": self.review_id,
            "execution_id": self.execution_id,
            "review_hash": self.review_hash,
            "generation": self.generation,
            "reviewer_id": self.reviewer_id,
            "outcome": self.outcome,
            "approved_proposal_ids": list(self.approved_proposal_ids),
            "expires_at_ms": self.expires_at_ms,
            "content_hash": self.content_hash,
        }


def _validate_decision(value: object) -> MemoryProjectionDecision:
    reason = "memory_approval_decision_invalid"
    if type(value) is not MemoryProjectionDecision:
        raise MemoryApprovalError(reason)
    approved = _proposal_ids(value.approved_proposal_ids, reason)
    expiry = _exact_optional_integer(value.expires_at_ms, reason)
    if (
        _exact_id(value.review_id, reason) != value.review_id
        or _exact_id(value.execution_id, reason) != value.execution_id
        or _exact_hash(value.review_hash, reason) != value.review_hash
        or type(value.generation) is not int
        or value.generation != 1
        or _exact_id(value.reviewer_id, reason) != value.reviewer_id
        or type(value.outcome) is not str
        or value.outcome not in {"approved", "denied"}
        or (value.outcome == "denied" and (approved or expiry is not None))
        or (value.outcome == "approved" and (not approved or expiry is None))
    ):
        raise MemoryApprovalError(reason)
    document = {key: item for key, item in value.as_document().items() if key != "content_hash"}
    if _exact_hash(value.content_hash, reason) != _hash(document, reason):
        raise MemoryApprovalError(reason)
    return replace(value, approved_proposal_ids=approved, expires_at_ms=expiry)


@dataclass(frozen=True, slots=True)
class MemoryApprovalCheck:
    review_hash: str
    decision_hash: str
    approved_proposal_ids: tuple[str, ...]
    reviewer_id: str


@dataclass(frozen=True, slots=True)
class MemoryApprovalAuthoritySnapshot:
    prepared_review: MemoryProjectionReview | None
    current_decision: MemoryProjectionDecision | None
    generation: int
    review_hash: str
    decision_hash: str | None
    state: str


@dataclass(slots=True)
class _ApprovalRecord:
    review: MemoryProjectionReview
    decision: MemoryProjectionDecision | None = None
    revoked: bool = False

    @property
    def generation(self) -> int:
        return 2 if self.revoked else 1 if self.decision is not None else 0


class InMemoryMemoryApprovalAuthority:
    """Instance-scoped CAS authority that cannot authorize tools."""

    def __init__(self) -> None:
        self._records: dict[str, _ApprovalRecord] = {}
        self._lock = threading.RLock()

    def prepare(
        self,
        review: object,
        *,
        expected_generation: object,
    ) -> MemoryProjectionReview:
        review = _validate_review(review)
        if type(expected_generation) is not int or expected_generation != 0:
            raise MemoryApprovalError("memory_approval_stale")
        with self._lock:
            record = self._records.get(review.review_id)
            if record is None:
                self._records[review.review_id] = _ApprovalRecord(replace(review))
                return replace(review)
            if record.review == review:
                return replace(record.review)
            raise MemoryApprovalError("memory_approval_stale")

    def decide(
        self,
        decision: object,
        *,
        expected_generation: object,
        expected_review_hash: object,
    ) -> MemoryProjectionDecision:
        decision = _validate_decision(decision)
        if (
            type(expected_generation) is not int
            or expected_generation != 0
            or _exact_hash(expected_review_hash, "memory_approval_stale") != decision.review_hash
        ):
            raise MemoryApprovalError("memory_approval_stale")
        with self._lock:
            record = self._records.get(decision.review_id)
            if record is None:
                raise MemoryApprovalError("memory_approval_required")
            if record.decision == decision and not record.revoked:
                return replace(record.decision)
            if (
                record.generation != 0
                or record.review.content_hash != decision.review_hash
                or record.review.execution_id != decision.execution_id
            ):
                raise MemoryApprovalError("memory_approval_stale")
            candidates = tuple(item[0] for item in record.review.candidate_proposals)
            if any(
                item not in candidates for item in decision.approved_proposal_ids
            ) or decision.approved_proposal_ids != tuple(
                item for item in candidates if item in decision.approved_proposal_ids
            ):
                raise MemoryApprovalError("memory_approval_invalid")
            record.decision = replace(decision)
            return replace(record.decision)

    def snapshot(self, review: object) -> MemoryApprovalAuthoritySnapshot:
        review = _validate_review(review)
        with self._lock:
            record = self._records.get(review.review_id)
            if record is None:
                return MemoryApprovalAuthoritySnapshot(
                    prepared_review=None,
                    current_decision=None,
                    generation=0,
                    review_hash=review.content_hash,
                    decision_hash=None,
                    state="missing",
                )
            if record.review != review:
                return MemoryApprovalAuthoritySnapshot(
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
            return MemoryApprovalAuthoritySnapshot(
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
    ) -> MemoryApprovalCheck:
        review = _validate_review(review)
        expected = _validate_authority_snapshot(expected)
        now = _exact_integer(now_ms, "memory_approval_check_failed")
        if expected.review_hash != review.content_hash:
            raise MemoryApprovalError("memory_approval_stale")
        if expected.state in {"missing", "prepared"}:
            raise MemoryApprovalError("memory_approval_required")
        if expected.state == "stale":
            raise MemoryApprovalError("memory_approval_stale")
        with self._lock:
            record = self._records.get(review.review_id)
            if record is None or record.review != review:
                raise MemoryApprovalError("memory_approval_stale")
            if record.revoked:
                raise MemoryApprovalError("memory_approval_revoked")
            decision = record.decision
            if (
                decision is None
                or record.generation != expected.generation
                or expected.prepared_review != record.review
                or expected.current_decision != decision
                or expected.decision_hash != decision.content_hash
            ):
                raise MemoryApprovalError("memory_approval_stale")
            if expected.state == "denied":
                raise MemoryApprovalError("memory_approval_denied")
            if expected.state != "approved" or decision.outcome != "approved":
                raise MemoryApprovalError("memory_approval_invalid")
            if decision.expires_at_ms is None:
                raise MemoryApprovalError("memory_approval_invalid")
            if now >= decision.expires_at_ms:
                raise MemoryApprovalError("memory_approval_expired")
            return MemoryApprovalCheck(
                review_hash=review.content_hash,
                decision_hash=decision.content_hash,
                approved_proposal_ids=decision.approved_proposal_ids,
                reviewer_id=decision.reviewer_id,
            )

    def check(self, review: object, *, now_ms: object) -> MemoryApprovalCheck:
        return self.check_snapshot(review, self.snapshot(review), now_ms=now_ms)

    def revoke(
        self,
        review_id: object,
        *,
        expected_generation: object,
        expected_decision_hash: object,
    ) -> None:
        review = _exact_id(review_id, "memory_approval_stale")
        decision_hash = _exact_hash(expected_decision_hash, "memory_approval_stale")
        if type(expected_generation) is not int or expected_generation != 1:
            raise MemoryApprovalError("memory_approval_stale")
        with self._lock:
            record = self._records.get(review)
            if record is None or record.decision is None:
                raise MemoryApprovalError("memory_approval_required")
            if record.decision.content_hash != decision_hash:
                raise MemoryApprovalError("memory_approval_stale")
            if record.revoked:
                return
            if record.generation != 1:
                raise MemoryApprovalError("memory_approval_stale")
            record.revoked = True

    def _perform_if_approved(
        self,
        review: object,
        expected: object,
        *,
        now_ms: object,
        action: Callable[[MemoryApprovalCheck], _T],
    ) -> _T:
        if not callable(action):
            raise MemoryApprovalError("memory_approval_check_failed")
        with self._lock:
            check = self.check_snapshot(review, expected, now_ms=now_ms)
            return action(check)


def _validate_authority_snapshot(value: object) -> MemoryApprovalAuthoritySnapshot:
    reason = "memory_approval_check_failed"
    if type(value) is not MemoryApprovalAuthoritySnapshot:
        raise MemoryApprovalError(reason)
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
        raise MemoryApprovalError(reason)
    if value.state in {"missing", "stale"}:
        if (
            value.prepared_review is not None
            or value.current_decision is not None
            or value.decision_hash is not None
            or generation != 0
        ):
            raise MemoryApprovalError(reason)
        return replace(value, review_hash=review_hash)
    review = _validate_review(value.prepared_review)
    if review.content_hash != review_hash:
        raise MemoryApprovalError(reason)
    if value.state == "prepared":
        if value.current_decision is not None or value.decision_hash is not None or generation != 0:
            raise MemoryApprovalError(reason)
        return replace(value, prepared_review=review, review_hash=review_hash)
    decision = _validate_decision(value.current_decision)
    decision_hash = _exact_hash(value.decision_hash, reason)
    if (
        decision.review_hash != review_hash
        or decision.content_hash != decision_hash
        or decision.review_id != review.review_id
        or decision.execution_id != review.execution_id
    ):
        raise MemoryApprovalError(reason)
    if value.state == "revoked":
        if generation != 2:
            raise MemoryApprovalError(reason)
    elif generation != 1 or value.state != decision.outcome:
        raise MemoryApprovalError(reason)
    return replace(
        value,
        prepared_review=review,
        current_decision=decision,
        review_hash=review_hash,
        decision_hash=decision_hash,
    )


__all__ = (
    "InMemoryMemoryApprovalAuthority",
    "MEMORY_PROJECTION_POLICY_HASH",
    "MEMORY_PROJECTION_POLICY_ID",
    "MEMORY_PROJECTION_POLICY_VERSION",
    "MemoryApprovalAuthoritySnapshot",
    "MemoryApprovalCheck",
    "MemoryApprovalError",
    "MemoryProjectionDecision",
    "MemoryProjectionReview",
)
