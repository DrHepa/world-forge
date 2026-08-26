"""Private, provider-free approved memory projection primitives.

Raw candidate values exist only inside the process-local proposal source.  Every
other boundary in this module carries closed identities and hashes only.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import TypeVar

from worldforge.agent_harness_contracts import (
    AGENT_EVENT_FORMAT,
    AGENT_EXECUTION_RECEIPT_FORMAT,
    AGENT_HARNESS_VERSION,
    AGENT_MEMORY_PROJECTION_FORMAT,
    MAX_SAFE_INTEGER,
    canonical_agent_harness_hash,
    validate_agent_harness_document,
)

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_KINDS = frozenset({"decision", "constraint", "discovery", "preference"})
_SOURCE_FORMAT = "world-forge.private.memory_proposal"
_SNAPSHOT_FORMAT = "world-forge.private.memory_proposal_snapshot"
_FORMAT_VERSION = 1
_MAX_PROPOSALS = 64
_MAX_VALUE_BYTES = 64 * 1024
_MAX_EXECUTION_VALUE_BYTES = 256 * 1024
_MAX_JSON_DEPTH = 32
_T = TypeVar("_T")


class MemoryProjectionError(ValueError):
    """Closed private failure whose message never contains candidate content."""

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
        raise MemoryProjectionError(reason)
    return encoded


def _hash(value: object, reason: str) -> str:
    return hashlib.sha256(_canonical(value, reason)).hexdigest()


def _exact_id(value: object, reason: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise MemoryProjectionError(reason)
    return value


def _exact_hash(value: object, reason: str) -> str:
    if type(value) is not str or _SHA_RE.fullmatch(value) is None:
        raise MemoryProjectionError(reason)
    return value


def _normalize_json(
    value: object,
    *,
    depth: int = 0,
    active: set[int] | None = None,
) -> object:
    reason = "memory_proposal_invalid"
    if depth > _MAX_JSON_DEPTH:
        raise MemoryProjectionError(reason)
    if value is None or type(value) in {str, bool}:
        return value
    if type(value) is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise MemoryProjectionError(reason)
        return value
    if type(value) not in {dict, list}:
        raise MemoryProjectionError(reason)
    if active is None:
        active = set()
    identity = id(value)
    if identity in active:
        raise MemoryProjectionError(reason)
    active.add(identity)
    try:
        if type(value) is list:
            return [
                _normalize_json(item, depth=depth + 1, active=active)
                for item in list.__iter__(value)
            ]
        normalized: dict[str, object] = {}
        for key, item in dict.items(value):
            if type(key) is not str or key in normalized:
                raise MemoryProjectionError(reason)
            normalized[key] = _normalize_json(item, depth=depth + 1, active=active)
        return normalized
    finally:
        active.remove(identity)


@dataclass(frozen=True, slots=True)
class MemoryProposalIdentity:
    proposal_id: str
    execution_id: str
    kind: str
    subject_id: str
    value_hash: str
    content_hash: str

    def as_document(self) -> dict[str, object]:
        return {
            "format": _SOURCE_FORMAT,
            "format_version": _FORMAT_VERSION,
            "proposal_id": self.proposal_id,
            "execution_id": self.execution_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "value_hash": self.value_hash,
            "content_hash": self.content_hash,
        }


def _build_identity(
    *,
    execution_id: str,
    kind: str,
    subject_id: str,
    value_hash: str,
) -> MemoryProposalIdentity:
    material = {
        "format": _SOURCE_FORMAT,
        "format_version": _FORMAT_VERSION,
        "execution_id": execution_id,
        "kind": kind,
        "subject_id": subject_id,
        "value_hash": value_hash,
    }
    material_hash = _hash(material, "memory_proposal_invalid")
    proposal_id = "proposal_" + material_hash[:55]
    document = {**material, "proposal_id": proposal_id}
    return MemoryProposalIdentity(
        proposal_id=proposal_id,
        execution_id=execution_id,
        kind=kind,
        subject_id=subject_id,
        value_hash=value_hash,
        content_hash=_hash(document, "memory_proposal_invalid"),
    )


def _validated_identity(value: object) -> MemoryProposalIdentity:
    reason = "memory_proposal_invalid"
    if type(value) is not MemoryProposalIdentity:
        raise MemoryProjectionError(reason)
    proposal_id = _exact_id(value.proposal_id, reason)
    execution_id = _exact_id(value.execution_id, reason)
    if type(value.kind) is not str or value.kind not in _KINDS:
        raise MemoryProjectionError(reason)
    subject_id = _exact_id(value.subject_id, reason)
    value_hash = _exact_hash(value.value_hash, reason)
    content_hash = _exact_hash(value.content_hash, reason)
    expected = _build_identity(
        execution_id=execution_id,
        kind=value.kind,
        subject_id=subject_id,
        value_hash=value_hash,
    )
    if (
        proposal_id != expected.proposal_id
        or content_hash != expected.content_hash
        or value != expected
    ):
        raise MemoryProjectionError(reason)
    return replace(expected)


@dataclass(frozen=True, slots=True)
class MemoryProposalSnapshot:
    execution_id: str
    proposals: tuple[MemoryProposalIdentity, ...]
    content_hash: str


def _build_snapshot(
    execution_id: str,
    proposals: tuple[MemoryProposalIdentity, ...],
) -> MemoryProposalSnapshot:
    document = {
        "format": _SNAPSHOT_FORMAT,
        "format_version": _FORMAT_VERSION,
        "execution_id": execution_id,
        "proposals": [item.as_document() for item in proposals],
    }
    return MemoryProposalSnapshot(
        execution_id=execution_id,
        proposals=proposals,
        content_hash=_hash(document, "memory_proposal_snapshot_invalid"),
    )


def _validated_snapshot(value: object, *, require_nonempty: bool) -> MemoryProposalSnapshot:
    reason = "memory_proposal_snapshot_invalid"
    if type(value) is not MemoryProposalSnapshot:
        raise MemoryProjectionError(reason)
    execution_id = _exact_id(value.execution_id, reason)
    if type(value.proposals) is not tuple or len(value.proposals) > _MAX_PROPOSALS:
        raise MemoryProjectionError(reason)
    if require_nonempty and not value.proposals:
        raise MemoryProjectionError(reason)
    proposals = tuple(_validated_identity(item) for item in tuple.__iter__(value.proposals))
    proposal_ids = tuple(item.proposal_id for item in proposals)
    if any(item.execution_id != execution_id for item in proposals) or proposal_ids != tuple(
        sorted(set(proposal_ids), key=lambda item: item.encode("utf-8"))
    ):
        raise MemoryProjectionError(reason)
    recreated = _build_snapshot(execution_id, proposals)
    if type(value.content_hash) is not str or value != recreated:
        raise MemoryProjectionError(reason)
    return recreated


@dataclass(slots=True)
class _ProposalRecord:
    identity: MemoryProposalIdentity
    private_value: object
    encoded_bytes: int


class InMemoryMemoryProposalSource:
    """Process-local proposal source with copy-in/copy-out raw values."""

    def __init__(self) -> None:
        self._records: dict[str, dict[str, _ProposalRecord]] = {}
        self._lock = threading.RLock()

    def propose(
        self,
        *,
        execution_id: object,
        kind: object,
        subject_id: object,
        value: object,
    ) -> MemoryProposalIdentity:
        reason = "memory_proposal_invalid"
        execution = _exact_id(execution_id, reason)
        if type(kind) is not str or kind not in _KINDS:
            raise MemoryProjectionError(reason)
        subject = _exact_id(subject_id, reason)
        normalized = _normalize_json(value)
        encoded = _canonical(normalized, reason)
        if len(encoded) > _MAX_VALUE_BYTES:
            raise MemoryProjectionError("memory_proposal_bound_exceeded")
        value_hash = hashlib.sha256(encoded).hexdigest()
        identity = _build_identity(
            execution_id=execution,
            kind=kind,
            subject_id=subject,
            value_hash=value_hash,
        )
        with self._lock:
            records = self._records.setdefault(execution, {})
            existing = records.get(identity.proposal_id)
            if existing is not None:
                if existing.identity != identity or existing.private_value != normalized:
                    raise MemoryProjectionError("memory_proposal_conflict")
                return replace(existing.identity)
            if len(records) >= _MAX_PROPOSALS:
                raise MemoryProjectionError("memory_proposal_bound_exceeded")
            if sum(item.encoded_bytes for item in records.values()) + len(encoded) > (
                _MAX_EXECUTION_VALUE_BYTES
            ):
                raise MemoryProjectionError("memory_proposal_bound_exceeded")
            records[identity.proposal_id] = _ProposalRecord(
                identity=replace(identity),
                private_value=copy.deepcopy(normalized),
                encoded_bytes=len(encoded),
            )
            return replace(identity)

    def snapshot(self, execution_id: object) -> MemoryProposalSnapshot:
        execution = _exact_id(execution_id, "memory_proposal_snapshot_invalid")
        with self._lock:
            records = self._records.get(execution, {})
            proposals = tuple(
                _validated_identity(records[proposal_id].identity)
                for proposal_id in sorted(records, key=lambda item: item.encode("utf-8"))
            )
            return _validated_snapshot(
                _build_snapshot(execution, proposals),
                require_nonempty=False,
            )

    def private_value(self, execution_id: object, proposal_id: object) -> object:
        execution = _exact_id(execution_id, "memory_proposal_missing")
        proposal = _exact_id(proposal_id, "memory_proposal_missing")
        with self._lock:
            record = self._records.get(execution, {}).get(proposal)
            if record is None:
                raise MemoryProjectionError("memory_proposal_missing")
            _validated_identity(record.identity)
            return copy.deepcopy(record.private_value)

    def _perform_if_snapshot(
        self,
        execution_id: object,
        expected_snapshot_hash: object,
        action: Callable[[], _T],
    ) -> _T:
        execution = _exact_id(execution_id, "memory_projection_stale")
        expected = _exact_hash(expected_snapshot_hash, "memory_projection_stale")
        if not callable(action):
            raise MemoryProjectionError("memory_projection_invalid")
        with self._lock:
            if self.snapshot(execution).content_hash != expected:
                raise MemoryProjectionError("memory_projection_stale")
            return action()


class LosslessMemoryProjectionCompiler:
    """Compile approved candidate identities without semantic summarization."""

    def compile(
        self,
        *,
        source: object,
        review: object,
        decision: object,
        receipt: object,
        source_events: object,
    ) -> dict[str, object]:
        from .memory_approvals import _validate_decision, _validate_review

        reason = "memory_projection_invalid"
        if type(source) is not InMemoryMemoryProposalSource:
            raise MemoryProjectionError(reason)
        try:
            review = _validate_review(review)
            decision = _validate_decision(decision)
            receipt_document = validate_agent_harness_document(
                receipt,
                expected_format=AGENT_EXECUTION_RECEIPT_FORMAT,
            )
        except Exception:
            raise MemoryProjectionError(reason) from None

        if type(source_events) is not tuple or not 1 <= len(source_events) <= 64:
            raise MemoryProjectionError(reason)
        try:
            events = tuple(
                validate_agent_harness_document(item, expected_format=AGENT_EVENT_FORMAT)
                for item in tuple.__iter__(source_events)
            )
        except Exception:
            raise MemoryProjectionError(reason) from None
        event_chain = tuple(
            (str(event["event_id"]), str(event["content_hash"])) for event in events
        )
        previous: str | None = None
        event_ids: set[str] = set()
        for sequence, event in enumerate(events):
            if (
                event["sequence"] != sequence
                or event["execution_id"] != review.execution_id
                or event["event_id"] in event_ids
                or event["previous_event_hash"] != previous
            ):
                raise MemoryProjectionError(reason)
            event_ids.add(str(event["event_id"]))
            previous = str(event["content_hash"])
        if (
            review.source_event_chain != event_chain
            or review.pre_projection_event_head_hash != previous
            or receipt_document["execution_id"] != review.execution_id
            or receipt_document["receipt_id"] != review.receipt_id
            or receipt_document["content_hash"] != review.receipt_content_hash
            or receipt_document["outcome"] != "succeeded"
            or events[-1]["event_type"] != "execution.receipt_recorded"
            or events[-1]["subject"]
            != {
                "format": AGENT_EXECUTION_RECEIPT_FORMAT,
                "format_version": AGENT_HARNESS_VERSION,
                "id": receipt_document["receipt_id"],
                "content_hash": receipt_document["content_hash"],
            }
            or decision.review_id != review.review_id
            or decision.execution_id != review.execution_id
            or decision.review_hash != review.content_hash
            or decision.outcome != "approved"
        ):
            raise MemoryProjectionError(reason)
        snapshot = source.snapshot(review.execution_id)
        if (
            snapshot.content_hash != review.candidate_snapshot_hash
            or tuple((item.proposal_id, item.content_hash) for item in snapshot.proposals)
            != review.candidate_proposals
        ):
            raise MemoryProjectionError("memory_projection_stale")
        approved_ids = set(decision.approved_proposal_ids)
        approved = tuple(item for item in snapshot.proposals if item.proposal_id in approved_ids)
        if tuple(item.proposal_id for item in approved) != decision.approved_proposal_ids:
            raise MemoryProjectionError(reason)

        exact_entries: dict[tuple[str, str, str], MemoryProposalIdentity] = {}
        subject_values: dict[tuple[str, str], str] = {}
        for proposal in approved:
            raw_value = source.private_value(review.execution_id, proposal.proposal_id)
            normalized = _normalize_json(raw_value)
            raw_hash = hashlib.sha256(
                _canonical(normalized, "memory_projection_invalid")
            ).hexdigest()
            if raw_hash != proposal.value_hash:
                raise MemoryProjectionError("memory_projection_stale")
            subject_key = (proposal.kind, proposal.subject_id)
            existing_hash = subject_values.get(subject_key)
            if existing_hash is not None and existing_hash != proposal.value_hash:
                raise MemoryProjectionError("memory_projection_value_conflict")
            subject_values[subject_key] = proposal.value_hash
            exact_entries.setdefault(
                (proposal.kind, proposal.subject_id, proposal.value_hash),
                proposal,
            )

        sorted_source_events = sorted(
            events,
            key=lambda event: str(event["event_id"]).encode("utf-8"),
        )
        source_refs = [
            {
                "format": AGENT_EVENT_FORMAT,
                "format_version": AGENT_HARNESS_VERSION,
                "id": event["event_id"],
                "content_hash": event["content_hash"],
            }
            for event in sorted_source_events
        ]
        source_ids = [str(item["id"]) for item in source_refs]
        entries: list[dict[str, object]] = []
        for key in sorted(
            exact_entries,
            key=lambda item: tuple(part.encode("utf-8") for part in item),
        ):
            proposal = exact_entries[key]
            entry_material = {
                "format": "world-forge.private.memory_projection_entry_identity",
                "format_version": 1,
                "execution_id": review.execution_id,
                "kind": proposal.kind,
                "subject_id": proposal.subject_id,
                "value_hash": proposal.value_hash,
                "source_event_ids": source_ids,
            }
            entry_hash = _hash(entry_material, reason)
            entries.append(
                {
                    "entry_id": "entry_" + entry_hash[:58],
                    "kind": proposal.kind,
                    "subject_id": proposal.subject_id,
                    "value_hash": proposal.value_hash,
                    "source_event_ids": source_ids,
                }
            )
        entries.sort(key=lambda item: str(item["entry_id"]).encode("utf-8"))
        projection_material = {
            "format": "world-forge.private.memory_projection_identity",
            "format_version": 1,
            "execution_id": review.execution_id,
            "receipt_hash": review.receipt_content_hash,
            "source_event_chain": [
                {"event_id": event_id, "content_hash": content_hash}
                for event_id, content_hash in review.source_event_chain
            ],
            "review_hash": review.content_hash,
            "decision_hash": decision.content_hash,
            "policy_hash": review.policy_hash,
            "entries": entries,
        }
        projection_identity_hash = _hash(projection_material, reason)
        projection = {
            "format": AGENT_MEMORY_PROJECTION_FORMAT,
            "format_version": AGENT_HARNESS_VERSION,
            "projection_id": "projection_" + projection_identity_hash[:53],
            "execution_id": review.execution_id,
            "receipt": {
                "format": AGENT_EXECUTION_RECEIPT_FORMAT,
                "format_version": AGENT_HARNESS_VERSION,
                "id": review.receipt_id,
                "content_hash": review.receipt_content_hash,
            },
            "source_events": source_refs,
            "review": {
                "review_id": review.review_id,
                "reviewer_id": decision.reviewer_id,
                "policy_id": review.policy_id,
                "policy_version": review.policy_version,
                "policy_hash": review.policy_hash,
                "receipt_content_hash": review.receipt_content_hash,
                "decision": "approved",
            },
            "entries": entries,
            "content_hash": "",
        }
        projection["content_hash"] = canonical_agent_harness_hash(projection)
        try:
            return validate_agent_harness_document(
                projection,
                expected_format=AGENT_MEMORY_PROJECTION_FORMAT,
            )
        except Exception:
            raise MemoryProjectionError(reason) from None


class MemoryProjectionCoordinator:
    """Coordinate terminal evidence, separate approval, compilation, and recording."""

    def __init__(
        self,
        *,
        source: object,
        approval_authority: object,
        event_log: object,
        compiler: object | None = None,
    ) -> None:
        from .event_log import AgentEventLog
        from .memory_approvals import InMemoryMemoryApprovalAuthority

        if (
            type(source) is not InMemoryMemoryProposalSource
            or type(approval_authority) is not InMemoryMemoryApprovalAuthority
            or type(event_log) is not AgentEventLog
            or (compiler is not None and type(compiler) is not LosslessMemoryProjectionCompiler)
        ):
            raise MemoryProjectionError("memory_projection_coordinator_invalid")
        self.source = source
        self.approval_authority = approval_authority
        self.event_log = event_log
        self.compiler = LosslessMemoryProjectionCompiler() if compiler is None else compiler

    @staticmethod
    def _terminal_documents(
        replay: object,
    ) -> tuple[dict[str, object], tuple[dict[str, object], ...], bool]:
        try:
            if replay.state != "terminal" or replay.receipt_bytes is None:
                raise MemoryProjectionError("memory_projection_terminal_required")
            receipt = validate_agent_harness_document(
                json.loads(replay.receipt_bytes.decode("utf-8")),
                expected_format=AGENT_EXECUTION_RECEIPT_FORMAT,
            )
            events = tuple(
                validate_agent_harness_document(
                    json.loads(payload.decode("utf-8")),
                    expected_format=AGENT_EVENT_FORMAT,
                )
                for payload in replay.event_bytes
            )
        except MemoryProjectionError:
            raise
        except Exception:
            raise MemoryProjectionError("memory_projection_terminal_invalid") from None
        projected = bool(events and events[-1]["event_type"] == "memory.projected")
        source_events = events[:-1] if projected else events
        if (
            receipt["outcome"] != "succeeded"
            or not source_events
            or source_events[-1]["event_type"] != "execution.receipt_recorded"
            or (projected and replay.projection_bytes is None)
            or (not projected and replay.projection_bytes is not None)
        ):
            raise MemoryProjectionError("memory_projection_terminal_required")
        return receipt, source_events, projected

    def prepare_review(
        self,
        execution_id: object,
        *,
        review_id: object,
    ) -> object:
        from .memory_approvals import MemoryProjectionReview

        execution = _exact_id(execution_id, "memory_projection_invalid")
        review_identifier = _exact_id(review_id, "memory_projection_invalid")
        replay = self.event_log.replay_records(execution)
        receipt, source_events, _projected = self._terminal_documents(replay)
        snapshot = self.source.snapshot(execution)
        if not snapshot.proposals:
            raise MemoryProjectionError("memory_projection_candidates_required")
        review = MemoryProjectionReview.create(
            review_id=review_identifier,
            execution_id=execution,
            receipt_id=receipt["receipt_id"],
            receipt_content_hash=receipt["content_hash"],
            source_event_chain=tuple(
                (event["event_id"], event["content_hash"]) for event in source_events
            ),
            candidate_snapshot=snapshot,
        )
        return self.approval_authority.prepare(review, expected_generation=0)

    def project(
        self,
        review: object,
        *,
        expected_approval: object,
        now_ms: object,
    ) -> dict[str, object]:
        from .event_log import _memory_projection_event_id
        from .memory_approvals import (
            MemoryApprovalCheck,
            _validate_authority_snapshot,
            _validate_review,
        )
        from .records import build_event

        review = _validate_review(review)
        expected_approval = _validate_authority_snapshot(expected_approval)
        if type(now_ms) is not int or not 0 <= now_ms <= MAX_SAFE_INTEGER:
            raise MemoryProjectionError("memory_projection_invalid")
        replay = self.event_log.replay_records(review.execution_id)
        receipt, source_events, projected = self._terminal_documents(replay)

        def approved_action(check: object) -> dict[str, object]:
            decision = expected_approval.current_decision
            if decision is None:
                raise MemoryProjectionError("memory_projection_approval_invalid")

            def snapshot_action() -> dict[str, object]:
                projection = self.compiler.compile(
                    source=self.source,
                    review=review,
                    decision=decision,
                    receipt=receipt,
                    source_events=source_events,
                )
                fingerprint_document = {
                    "format": "world-forge.private.memory_projection_request",
                    "format_version": 1,
                    "execution_id": review.execution_id,
                    "execution_request_fingerprint": replay.request_fingerprint,
                    "receipt_id": review.receipt_id,
                    "receipt_hash": review.receipt_content_hash,
                    "source_event_chain": [
                        {"event_id": event_id, "content_hash": content_hash}
                        for event_id, content_hash in review.source_event_chain
                    ],
                    "pre_projection_event_head_hash": (review.pre_projection_event_head_hash),
                    "pre_projection_sequence": len(source_events),
                    "pre_projection_generation": len(source_events),
                    "candidate_snapshot_hash": review.candidate_snapshot_hash,
                    "review_hash": check.review_hash,
                    "decision_hash": check.decision_hash,
                    "policy_hash": review.policy_hash,
                    "projection_hash": projection["content_hash"],
                }
                request_fingerprint = _hash(
                    fingerprint_document,
                    "memory_projection_invalid",
                )
                event = build_event(
                    event_id=_memory_projection_event_id(request_fingerprint),
                    log_id=replay.log_id,
                    execution_id=review.execution_id,
                    sequence=len(source_events),
                    previous_event_hash=review.pre_projection_event_head_hash,
                    event_type="memory.projected",
                    subject_format=AGENT_MEMORY_PROJECTION_FORMAT,
                    subject_id=projection["projection_id"],
                    subject_hash=projection["content_hash"],
                )
                return self.event_log.record_memory_projection(
                    review.execution_id,
                    projection,
                    event,
                    request_fingerprint=request_fingerprint,
                    expected_sequence=len(source_events),
                    expected_previous_hash=review.pre_projection_event_head_hash,
                    expected_generation=len(source_events),
                )

            return self.source._perform_if_snapshot(
                review.execution_id,
                review.candidate_snapshot_hash,
                snapshot_action,
            )

        if projected:
            if (
                expected_approval.state != "approved"
                or expected_approval.current_decision is None
                or expected_approval.decision_hash is None
            ):
                raise MemoryProjectionError("memory_projection_approval_invalid")
            return approved_action(
                MemoryApprovalCheck(
                    review_hash=expected_approval.review_hash,
                    decision_hash=expected_approval.decision_hash,
                    approved_proposal_ids=(
                        expected_approval.current_decision.approved_proposal_ids
                    ),
                    reviewer_id=expected_approval.current_decision.reviewer_id,
                )
            )
        return self.approval_authority._perform_if_approved(
            review,
            expected_approval,
            now_ms=now_ms,
            action=approved_action,
        )


__all__ = (
    "InMemoryMemoryProposalSource",
    "LosslessMemoryProjectionCompiler",
    "MemoryProjectionCoordinator",
    "MemoryProjectionError",
    "MemoryProposalIdentity",
    "MemoryProposalSnapshot",
)
