"""Service-owned ceremony boundary for the fixed local Studio Director.

The durable authority remains the only cryptographic and storage authority.
This wrapper owns only the live unlocked reference and exact protocol-facing
review transitions.  Dropping that reference is a lock operation, not a claim
that Python objects or process memory have been securely zeroized.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, TypeVar

from worldforge.agent_harness.approvals import (
    ApprovalAuthoritySnapshot,
    ApprovalError,
    ExecutionApprovalDecision,
    ExecutionApprovalReview,
)
from worldforge.studio.authenticated_human_decisions import (
    StudioAuthenticatedHumanDecisionAuthority,
    _credential_evidence,
    _review_from_document,
)
from worldforge.studio.errors import StudioError, conflict, invalid_request, invalid_state
from worldforge.studio.storage import (
    StudioStore,
    _verify_authenticated_human_decision_v6,
)

_CREDENTIAL_ID = "director_local"
_T = TypeVar("_T")


def _snapshot_document(snapshot: ApprovalAuthoritySnapshot) -> dict[str, object]:
    return {
        "prepared_review": (
            None
            if snapshot.prepared_review is None
            else snapshot.prepared_review.as_document()
        ),
        "current_decision": (
            None
            if snapshot.current_decision is None
            else snapshot.current_decision.as_document()
        ),
        "generation": snapshot.generation,
        "review_hash": snapshot.review_hash,
        "decision_hash": snapshot.decision_hash,
        "state": snapshot.state,
    }


def _translate_review_error(operation: Callable[[], _T]) -> _T:
    try:
        return operation()
    except StudioError:
        raise
    except ApprovalError as exc:
        if exc.reason_code == "approval_stale":
            raise conflict("Director review state changed") from exc
        if exc.reason_code == "approval_required":
            raise invalid_state("Director review is not prepared") from exc
        if exc.reason_code in {
            "approval_revoked",
            "approval_denied",
            "approval_expired",
        }:
            raise invalid_state("Director review is not actionable") from exc
        raise invalid_request("Director review data is invalid") from exc
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise invalid_request("Director review data is invalid") from exc
    except Exception as exc:
        raise StudioError("internal_error", "Director review operation failed") from exc


class StudioDirectorControl:
    """Serialize one process-local lock state over the durable Director authority."""

    def __init__(self, store: StudioStore) -> None:
        self._store = store
        self._authority: StudioAuthenticatedHumanDecisionAuthority | None = None
        self._closed = False
        self._lock = threading.RLock()

    def _require_open(self) -> None:
        if self._closed:
            raise invalid_state("Director control is closed")

    def _credential_enrolled(self) -> bool:
        connection = self._store._authenticated_human_decision_connection()
        with self._store._authenticated_human_decision_lock:
            self._store._require_active_authenticated_human_decision_connection(
                connection
            )
            try:
                _verify_authenticated_human_decision_v6(connection)
                rows = connection.execute(
                    "SELECT credential_id, kdf_name, kdf_n, kdf_r, kdf_p, "
                    "kdf_dklen, kdf_maxmem, salt, verifier, created_at FROM "
                    "studio_authenticated_human_credentials"
                ).fetchall()
                if not rows:
                    return False
                if len(rows) != 1:
                    raise ValueError("credential count")
                _credential_evidence(rows[0])
                return True
            except StudioError:
                raise
            except (KeyError, TypeError, ValueError) as exc:
                raise invalid_state("Director credential state is unavailable") from exc
            except Exception as exc:
                raise StudioError(
                    "internal_error", "Director credential status failed"
                ) from exc

    def status(self) -> dict[str, str]:
        with self._lock:
            self._require_open()
            enrolled = self._credential_enrolled()
            if self._authority is not None and not enrolled:
                self._authority = None
                raise invalid_state("Director credential state is unavailable")
            state = (
                "unlocked"
                if self._authority is not None
                else "locked"
                if enrolled
                else "not_enrolled"
            )
            return {"credential_id": _CREDENTIAL_ID, "state": state}

    def enroll(self, *, passphrase: object) -> dict[str, str]:
        with self._lock:
            self._require_open()
            if self._authority is not None:
                raise invalid_state("Director credential is already unlocked")
            self._authority = StudioAuthenticatedHumanDecisionAuthority.enroll(
                self._store,
                passphrase=passphrase,
            )
            return {"credential_id": _CREDENTIAL_ID, "state": "unlocked"}

    def unlock(self, *, passphrase: object) -> dict[str, str]:
        with self._lock:
            self._require_open()
            if self._authority is not None:
                raise invalid_state("Director credential is already unlocked")
            self._authority = StudioAuthenticatedHumanDecisionAuthority.unlock(
                self._store,
                passphrase=passphrase,
            )
            return {"credential_id": _CREDENTIAL_ID, "state": "unlocked"}

    def lock(self) -> dict[str, str]:
        with self._lock:
            self._require_open()
            was_unlocked = self._authority is not None
            self._authority = None
            if was_unlocked:
                return {"credential_id": _CREDENTIAL_ID, "state": "locked"}
            return self.status()

    def close(self) -> None:
        with self._lock:
            self._authority = None
            self._closed = True

    def _require_authority(self) -> StudioAuthenticatedHumanDecisionAuthority:
        self._require_open()
        if self._authority is None:
            raise invalid_state("Director credential is locked")
        return self._authority

    @staticmethod
    def _review(value: object) -> ExecutionApprovalReview:
        return _review_from_document(value)

    def inspect(self, review: object) -> dict[str, object]:
        with self._lock:
            authority = self._require_authority()
            return _translate_review_error(
                lambda: _snapshot_document(authority.snapshot(self._review(review)))
            )

    def prepare(
        self, review: object, *, expected_generation: object
    ) -> dict[str, object]:
        with self._lock:
            authority = self._require_authority()

            def operation() -> dict[str, object]:
                parsed = self._review(review)
                authority.prepare(parsed, expected_generation=expected_generation)
                return _snapshot_document(authority.snapshot(parsed))

            return _translate_review_error(operation)

    def approve(
        self,
        review: object,
        *,
        expected_generation: object,
        expected_review_hash: object,
        approved_tool_ids: object,
        expires_at_ms: object,
    ) -> dict[str, object]:
        with self._lock:
            authority = self._require_authority()

            def operation() -> dict[str, object]:
                parsed = self._review(review)
                if type(approved_tool_ids) is not list:
                    raise ValueError("approved tool IDs")
                decision = ExecutionApprovalDecision.create(
                    review=parsed,
                    reviewer_id=_CREDENTIAL_ID,
                    outcome="approved",
                    approved_tool_ids=tuple(approved_tool_ids),
                    expires_at_ms=expires_at_ms,
                )
                authority.decide(
                    decision,
                    expected_generation=expected_generation,
                    expected_review_hash=expected_review_hash,
                )
                return _snapshot_document(authority.snapshot(parsed))

            return _translate_review_error(operation)

    def deny(
        self,
        review: object,
        *,
        expected_generation: object,
        expected_review_hash: object,
    ) -> dict[str, object]:
        with self._lock:
            authority = self._require_authority()

            def operation() -> dict[str, object]:
                parsed = self._review(review)
                decision = ExecutionApprovalDecision.create(
                    review=parsed,
                    reviewer_id=_CREDENTIAL_ID,
                    outcome="denied",
                    approved_tool_ids=(),
                    expires_at_ms=None,
                )
                authority.decide(
                    decision,
                    expected_generation=expected_generation,
                    expected_review_hash=expected_review_hash,
                )
                return _snapshot_document(authority.snapshot(parsed))

            return _translate_review_error(operation)

    def revoke(
        self,
        review: object,
        *,
        expected_generation: object,
        expected_decision_hash: object,
    ) -> dict[str, object]:
        with self._lock:
            authority = self._require_authority()

            def operation() -> dict[str, object]:
                parsed = self._review(review)
                authority.revoke(
                    parsed.approval_id,
                    expected_generation=expected_generation,
                    expected_decision_hash=expected_decision_hash,
                )
                return _snapshot_document(authority.snapshot(parsed))

            return _translate_review_error(operation)


__all__ = ("StudioDirectorControl",)
