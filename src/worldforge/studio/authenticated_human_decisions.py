"""Private durable possession authentication for Studio Director decisions.

This module authenticates possession of one locally enrolled passphrase and
stores only a salted verifier plus authenticated decision evidence. ADR-0049
permits explicit same-process composition into Agent Harness; automatic Studio
execution hydration and separate-process isolation remain absent. Direct
authority construction is closed; successful audited enroll/unlock completion
owns the one-time private registration provenance and closure-captured
construction dispatch.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import sys
import threading
import time
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from worldforge.agent_harness.approvals import (
    ApprovalAuthoritySnapshot,
    ApprovalCheck,
    ApprovalError,
    ExecutionApprovalAuthority,
    ExecutionApprovalDecision,
    ExecutionApprovalReview,
    _authority_functions,
    _configure_studio_execution_approval_authority,
    _exact_hash,
    _exact_id,
    _exact_integer,
    _register_studio_execution_approval_authority,
    _validate_authority_snapshot,
    _validate_decision,
    _validate_review,
)
from worldforge.studio.errors import StudioError
from worldforge.studio.storage import (
    _AUTHORITY_SCHEMA_ERROR,
    StudioStore,
    _verify_authenticated_human_decision_v6,
    decode_object,
    encode_json,
    utc_now,
)

_CREDENTIAL_ID = "director_local"
_KDF = (32768, 8, 1, 32, 67108864)
_ZERO_HASH = "0" * 64
_EVENT_FORMAT = "world-forge.private.studio_authenticated_human_decision_event"
_EVENT_VERSION = 1
_AUTHORITY_KIND = "agent_tool_approval"
_CREDENTIAL_FORMAT = "world-forge.private.studio_authenticated_human_credential"
_CREDENTIAL_VERSION = 1
_CANONICAL_UTC_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z"
)
_EVENT_DOCUMENT_KEYS = frozenset(
    {
        "format",
        "format_version",
        "credential_id",
        "authority_kind",
        "event_type",
        "approval_id",
        "generation",
        "previous_hash",
        "review",
        "decision",
        "state",
        "updated_at",
    }
)
_VERIFIER_DOMAIN = b"world-forge.studio.director.verifier.v1\x00"
_EVENT_KEY_DOMAIN = b"world-forge.studio.director.event-key.v1\x00"
_EVENT_MAC_DOMAIN = b"world-forge.studio.director.event-mac.v1\x00"


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise StudioError("invalid_request", "authenticated decision data is invalid") from exc


def _passphrase_bytes(value: object) -> bytes:
    if type(value) is not str:
        raise StudioError("invalid_request", "passphrase invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise StudioError("invalid_request", "passphrase invalid") from exc
    if not 16 <= len(encoded) <= 1024:
        raise StudioError("invalid_request", "passphrase invalid")
    return encoded


def _derive_master(passphrase: bytes, salt: bytes) -> bytes:
    n, r, p, dklen, maxmem = _KDF
    return hashlib.scrypt(passphrase, salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=maxmem)


def _subkey(master: bytes, domain: bytes) -> bytes:
    return hmac.new(master, domain, hashlib.sha256).digest()


def _canonical_utc_timestamp(value: object) -> str:
    if type(value) is not str or _CANONICAL_UTC_TIMESTAMP_RE.fullmatch(value) is None:
        raise ValueError("canonical UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise ValueError("canonical UTC timestamp") from exc
    canonical = (
        f"{parsed.year:04d}-{parsed.month:02d}-{parsed.day:02d}T"
        f"{parsed.hour:02d}:{parsed.minute:02d}:{parsed.second:02d}."
        f"{parsed.microsecond:06d}Z"
    )
    if canonical != value:
        raise ValueError("canonical UTC timestamp")
    return value


def _validate_director_decision(value: object) -> ExecutionApprovalDecision:
    decision = _validate_decision(value)
    if decision.reviewer_id != _CREDENTIAL_ID:
        raise ApprovalError("approval_decision_invalid")
    return decision


def _event_mac(key: bytes, document: dict[str, object]) -> bytes:
    return hmac.new(key, _EVENT_MAC_DOMAIN + _canonical(document), hashlib.sha256).digest()


def _event_document(
    *,
    event_type: str,
    review: ExecutionApprovalReview,
    decision: ExecutionApprovalDecision | None,
    state: str,
    generation: int,
    previous_hash: str,
    updated_at: str,
) -> dict[str, object]:
    return {
        "format": _EVENT_FORMAT,
        "format_version": _EVENT_VERSION,
        "credential_id": _CREDENTIAL_ID,
        "authority_kind": _AUTHORITY_KIND,
        "event_type": event_type,
        "approval_id": review.approval_id,
        "generation": generation,
        "previous_hash": previous_hash,
        "review": review.as_document(),
        "decision": None if decision is None else decision.as_document(),
        "state": state,
        "updated_at": updated_at,
    }


@dataclass(frozen=True, slots=True)
class _PendingEvent:
    content_json: str
    content_hash: str
    mac: bytes
    created_at: str


@dataclass(frozen=True, slots=True)
class _CredentialEvidence:
    credential_id: str
    kdf_name: str
    kdf_n: int
    kdf_r: int
    kdf_p: int
    kdf_dklen: int
    kdf_maxmem: int
    salt: bytes
    verifier: bytes
    created_at: str


@dataclass(frozen=True, slots=True)
class _AuditHead:
    event_id: int
    content_hash: str


@dataclass(frozen=True, slots=True)
class _WriteCommitReconciliation:
    observed: _AuditHead | None
    usable: bool


@dataclass(slots=True)
class _LatchedFailure:
    source: BaseException
    outcome: BaseException


_EMPTY_AUDIT_HEAD = _AuditHead(0, _ZERO_HASH)


def _credential_envelope(evidence: _CredentialEvidence) -> dict[str, object]:
    return {
        "format": _CREDENTIAL_FORMAT,
        "format_version": _CREDENTIAL_VERSION,
        "credential_id": evidence.credential_id,
        "kdf_name": evidence.kdf_name,
        "kdf_n": evidence.kdf_n,
        "kdf_r": evidence.kdf_r,
        "kdf_p": evidence.kdf_p,
        "kdf_dklen": evidence.kdf_dklen,
        "kdf_maxmem": evidence.kdf_maxmem,
        "salt_hex": evidence.salt.hex(),
        "created_at": evidence.created_at,
    }


def _verifier(master: bytes, evidence: _CredentialEvidence) -> bytes:
    message = _VERIFIER_DOMAIN + _canonical(_credential_envelope(evidence))
    return hmac.new(_subkey(master, _VERIFIER_DOMAIN), message, hashlib.sha256).digest()


def _credential_evidence(row: Any) -> _CredentialEvidence:
    evidence = _CredentialEvidence(
        credential_id=row["credential_id"],
        kdf_name=row["kdf_name"],
        kdf_n=row["kdf_n"],
        kdf_r=row["kdf_r"],
        kdf_p=row["kdf_p"],
        kdf_dklen=row["kdf_dklen"],
        kdf_maxmem=row["kdf_maxmem"],
        salt=row["salt"],
        verifier=row["verifier"],
        created_at=row["created_at"],
    )
    if (
        evidence.credential_id != _CREDENTIAL_ID
        or evidence.kdf_name != "scrypt"
        or (
            evidence.kdf_n,
            evidence.kdf_r,
            evidence.kdf_p,
            evidence.kdf_dklen,
            evidence.kdf_maxmem,
        )
        != _KDF
        or type(evidence.salt) is not bytes
        or len(evidence.salt) != 32
        or type(evidence.verifier) is not bytes
        or len(evidence.verifier) != 32
    ):
        raise ValueError("credential evidence")
    _canonical_utc_timestamp(evidence.created_at)
    return evidence


def _same_credential(
    expected: _CredentialEvidence, observed: _CredentialEvidence
) -> bool:
    return (
        observed.credential_id == expected.credential_id
        and observed.kdf_name == expected.kdf_name
        and observed.kdf_n == expected.kdf_n
        and observed.kdf_r == expected.kdf_r
        and observed.kdf_p == expected.kdf_p
        and observed.kdf_dklen == expected.kdf_dklen
        and observed.kdf_maxmem == expected.kdf_maxmem
        and hmac.compare_digest(observed.salt, expected.salt)
        and hmac.compare_digest(observed.verifier, expected.verifier)
        and observed.created_at == expected.created_at
    )


def _rollback_or_invalidate_store_connection(
    store: StudioStore, connection: sqlite3.Connection
) -> bool:
    try:
        if connection.in_transaction:
            connection.rollback()
        if connection.in_transaction:
            raise RuntimeError("credential transaction remains active")
    except BaseException:
        store._invalidate_authenticated_human_decision_connection(connection)
        return False
    return True


def _note_indeterminate_cleanup(error: BaseException) -> None:
    try:
        error.add_note("authenticated decision transaction cleanup was indeterminate")
    except BaseException:
        pass


def _raise_latched_failure(failure: _LatchedFailure) -> None:
    if failure.outcome is failure.source:
        raise failure.source
    raise failure.outcome from failure.source


def _immediate_interrupted_primary(
    escaped: BaseException,
) -> BaseException | None:
    try:
        primary = escaped.__context__
        if primary is None or primary is escaped:
            return None
        primary_context = primary.__context__
        primary_cause = primary.__cause__
        if (
            primary_context is primary
            or primary_context is escaped
            or primary_cause is primary
            or primary_cause is escaped
        ):
            return None
    except BaseException:
        return None
    return primary


class StudioAuthenticatedHumanDecisionAuthority(ExecutionApprovalAuthority):
    """One locked/unlocked, transactionally durable Director authority."""

    def __init__(
        self,
        store: StudioStore,
        event_key: bytes,
        credential: _CredentialEvidence,
        provenance: object = None,
    ) -> None:
        raise ApprovalError("approval_authority_invalid")

    @classmethod
    def enroll(
        cls,
        store: StudioStore,
        provisional_authority,
        complete_registration,
        *,
        passphrase: object,
    ) -> StudioAuthenticatedHumanDecisionAuthority:
        if store.mode != "primary":
            raise StudioError(
                "invalid_state", "credential enrollment requires primary Studio store"
            )
        encoded = _passphrase_bytes(passphrase)
        salt = os.urandom(32)
        master = _derive_master(encoded, salt)
        created_at = _canonical_utc_timestamp(utc_now())
        credential = _CredentialEvidence(
            credential_id=_CREDENTIAL_ID,
            kdf_name="scrypt",
            kdf_n=_KDF[0],
            kdf_r=_KDF[1],
            kdf_p=_KDF[2],
            kdf_dklen=_KDF[3],
            kdf_maxmem=_KDF[4],
            salt=salt,
            verifier=b"",
            created_at=created_at,
        )
        verifier = _verifier(master, credential)
        credential = replace(credential, verifier=verifier)
        event_key = _subkey(master, _EVENT_KEY_DOMAIN)
        connection = store._authenticated_human_decision_connection()
        lock = store._authenticated_human_decision_lock
        with lock:
            store._require_active_authenticated_human_decision_connection(connection)
            failure: _LatchedFailure | None = None
            phase = "begin"
            try:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    phase = "body"
                    _verify_authenticated_human_decision_v6(connection)
                    existing = connection.execute(
                        "SELECT credential_id FROM studio_authenticated_human_credentials"
                    ).fetchone()
                    if existing is not None:
                        raise StudioError("invalid_state", "credential already enrolled")
                    connection.execute(
                        "INSERT INTO studio_authenticated_human_credentials "
                        "(credential_id, kdf_name, kdf_n, kdf_r, kdf_p, kdf_dklen, "
                        "kdf_maxmem, salt, verifier, created_at) VALUES "
                        "(?, 'scrypt', ?, ?, ?, ?, ?, ?, ?, ?)",
                        (_CREDENTIAL_ID, *_KDF, salt, verifier, created_at),
                    )
                    authority = provisional_authority(
                        cls,
                        store,
                        event_key,
                        credential,
                    )
                    head = authority._audit_in_transaction()
                    phase = "commit"
                    connection.commit()
                    authority._advance_anchor(head)
                    complete_registration(
                        authority,
                        store,
                        event_key,
                        credential,
                    )
                    return authority
                except BaseException as exc:
                    failure = (
                        _LatchedFailure(exc, exc)
                        if not isinstance(exc, Exception)
                        or (isinstance(exc, StudioError) and phase != "commit")
                        else _LatchedFailure(
                            exc,
                            StudioError(
                                "internal_error", "credential enrollment failed"
                            ),
                        )
                    )
                    if phase == "commit":
                        store._invalidate_authenticated_human_decision_connection(
                            connection
                        )
                    elif not _rollback_or_invalidate_store_connection(
                        store, connection
                    ):
                        if isinstance(exc, Exception):
                            failure.outcome = StudioError(
                                "internal_error", "credential enrollment failed"
                            )
                        else:
                            _note_indeterminate_cleanup(exc)
                    _raise_latched_failure(failure)
            except BaseException as escaped:
                if failure is not None and (
                    escaped is failure.source or escaped is failure.outcome
                ):
                    raise
                secondary = failure is not None
                if failure is None:
                    primary = _immediate_interrupted_primary(escaped)
                    secondary = primary is not None
                    if primary is None:
                        primary = escaped
                    failure = (
                        _LatchedFailure(primary, primary)
                        if not isinstance(primary, Exception)
                        or (isinstance(primary, StudioError) and phase != "commit")
                        else _LatchedFailure(
                            primary,
                            StudioError(
                                "internal_error", "credential enrollment failed"
                            ),
                        )
                    )
                    if secondary:
                        _note_indeterminate_cleanup(failure.source)
                else:
                    _note_indeterminate_cleanup(failure.source)
                cleanup_safe = _rollback_or_invalidate_store_connection(
                    store, connection
                )
                if secondary or not cleanup_safe or phase == "commit":
                    store._invalidate_authenticated_human_decision_connection(
                        connection
                    )
                _raise_latched_failure(failure)

    @classmethod
    def unlock(
        cls,
        store: StudioStore,
        provisional_authority,
        complete_registration,
        *,
        passphrase: object,
    ) -> StudioAuthenticatedHumanDecisionAuthority:
        encoded = _passphrase_bytes(passphrase)
        connection = store._authenticated_human_decision_connection()
        lock = store._authenticated_human_decision_lock
        with lock:
            store._require_active_authenticated_human_decision_connection(connection)
            failure: _LatchedFailure | None = None
            phase = "begin"
            try:
                try:
                    connection.execute("BEGIN")
                    phase = "body"
                    _verify_authenticated_human_decision_v6(connection)
                    row = connection.execute(
                        "SELECT credential_id, kdf_name, kdf_n, kdf_r, kdf_p, kdf_dklen, "
                        "kdf_maxmem, salt, verifier, created_at FROM "
                        "studio_authenticated_human_credentials"
                    ).fetchone()
                    if row is None:
                        raise StudioError("invalid_state", "credential not enrolled")
                    credential = _credential_evidence(row)
                    master = _derive_master(encoded, credential.salt)
                    if not hmac.compare_digest(
                        _verifier(master, credential), credential.verifier
                    ):
                        raise StudioError("invalid_state", "authentication failed")
                    event_key = _subkey(master, _EVENT_KEY_DOMAIN)
                    authority = provisional_authority(
                        cls,
                        store,
                        event_key,
                        credential,
                    )
                    head = authority._audit_in_transaction()
                    phase = "commit"
                    connection.commit()
                    authority._advance_anchor(head)
                    complete_registration(
                        authority,
                        store,
                        event_key,
                        credential,
                    )
                    return authority
                except BaseException as exc:
                    if not isinstance(exc, Exception):
                        failure = _LatchedFailure(exc, exc)
                    elif phase == "commit":
                        failure = _LatchedFailure(
                            exc,
                            StudioError(
                                "invalid_state",
                                "authenticated decision audit failed",
                            ),
                        )
                    elif isinstance(
                        exc, (KeyError, TypeError, ValueError, MemoryError)
                    ):
                        failure = _LatchedFailure(
                            exc, StudioError("invalid_state", "authentication failed")
                        )
                    elif isinstance(exc, StudioError):
                        failure = _LatchedFailure(exc, exc)
                    else:
                        failure = _LatchedFailure(
                            exc,
                            StudioError(
                                "invalid_state",
                                "authenticated decision audit failed",
                            ),
                        )
                    if phase == "commit":
                        store._invalidate_authenticated_human_decision_connection(
                            connection
                        )
                    elif not _rollback_or_invalidate_store_connection(
                        store, connection
                    ):
                        if isinstance(exc, Exception):
                            failure.outcome = StudioError(
                                "invalid_state", "authentication failed"
                            )
                        else:
                            _note_indeterminate_cleanup(exc)
                    _raise_latched_failure(failure)
            except BaseException as escaped:
                if failure is not None and (
                    escaped is failure.source or escaped is failure.outcome
                ):
                    raise
                secondary = failure is not None
                if failure is None:
                    primary = _immediate_interrupted_primary(escaped)
                    secondary = primary is not None
                    if primary is None:
                        primary = escaped
                    if not isinstance(primary, Exception):
                        failure = _LatchedFailure(primary, primary)
                    elif phase == "commit":
                        failure = _LatchedFailure(
                            primary,
                            StudioError(
                                "invalid_state",
                                "authenticated decision audit failed",
                            ),
                        )
                    elif isinstance(
                        primary, (KeyError, TypeError, ValueError, MemoryError)
                    ):
                        failure = _LatchedFailure(
                            primary,
                            StudioError("invalid_state", "authentication failed"),
                        )
                    elif isinstance(primary, StudioError):
                        failure = _LatchedFailure(primary, primary)
                    else:
                        failure = _LatchedFailure(
                            primary,
                            StudioError(
                                "invalid_state",
                                "authenticated decision audit failed",
                            ),
                        )
                    if secondary:
                        _note_indeterminate_cleanup(failure.source)
                else:
                    _note_indeterminate_cleanup(failure.source)
                cleanup_safe = _rollback_or_invalidate_store_connection(
                    store, connection
                )
                if secondary or not cleanup_safe or phase == "commit":
                    store._invalidate_authenticated_human_decision_connection(
                        connection
                    )
                _raise_latched_failure(failure)

    def _audit_in_transaction(
        self, observed_head: list[_AuditHead] | None = None
    ) -> _AuditHead:
        """Audit one exact DB snapshot without owning its transaction boundary."""
        try:
            if not self._connection.in_transaction:
                raise ValueError("audit transaction")
            _verify_authenticated_human_decision_v6(self._connection)
            credentials = self._connection.execute(
                "SELECT credential_id, kdf_name, kdf_n, kdf_r, kdf_p, kdf_dklen, "
                "kdf_maxmem, salt, verifier, created_at FROM "
                "studio_authenticated_human_credentials"
            ).fetchall()
            if len(credentials) != 1 or not _same_credential(
                self._credential, _credential_evidence(credentials[0])
            ):
                raise ValueError("credential drift")
            rows = self._connection.execute(
                "SELECT event_id, credential_id, approval_id, generation, event_type, "
                "content_json, content_hash, previous_hash, mac, created_at FROM "
                "studio_authenticated_human_decision_events "
                "ORDER BY event_id"
            ).fetchall()
            projections: dict[str, dict[str, object]] = {}
            previous = _ZERO_HASH
            expected_event_id = 1
            anchor_seen = self._anchor.event_id == 0
            for row in rows:
                if row["credential_id"] != _CREDENTIAL_ID:
                    raise ValueError("event credential")
                if row["event_id"] != expected_event_id or row["previous_hash"] != previous:
                    raise ValueError("event continuity")
                expected_event_id += 1
                document = decode_object(
                    row["content_json"], context="authenticated decision event"
                )
                if encode_json(document) != row["content_json"]:
                    raise ValueError("noncanonical event")
                if frozenset(document) != _EVENT_DOCUMENT_KEYS:
                    raise ValueError("event document keys")
                updated_at = _canonical_utc_timestamp(document["updated_at"])
                created_at = _canonical_utc_timestamp(row["created_at"])
                content_hash = hashlib.sha256(_canonical(document)).hexdigest()
                if content_hash != row["content_hash"] or not hmac.compare_digest(
                    _event_mac(self._event_key, document), row["mac"]
                ):
                    raise ValueError("event integrity")
                if row["event_id"] == self._anchor.event_id:
                    if not hmac.compare_digest(
                        row["content_hash"], self._anchor.content_hash
                    ):
                        raise ValueError("event anchor")
                    anchor_seen = True
                review = _review_from_document(document.get("review"))
                decision = _decision_from_document(document.get("decision"), review)
                if (
                    document.get("format") != _EVENT_FORMAT
                    or type(document.get("format_version")) is not int
                    or document["format_version"] != _EVENT_VERSION
                    or document.get("credential_id") != _CREDENTIAL_ID
                    or document.get("authority_kind") != _AUTHORITY_KIND
                    or document.get("approval_id") != review.approval_id
                    or row["approval_id"] != review.approval_id
                    or type(document.get("generation")) is not int
                    or document["generation"] != row["generation"]
                    or document.get("previous_hash") != previous
                    or document.get("event_type") != row["event_type"]
                    or type(document.get("state")) is not str
                    or updated_at != created_at
                ):
                    raise ValueError("event fields")
                state = document["state"]
                current = projections.get(review.approval_id)
                if row["event_type"] == "prepared":
                    if (
                        current is not None
                        or decision is not None
                        or state != "prepared"
                        or row["generation"] != 0
                    ):
                        raise ValueError("prepared transition")
                elif row["event_type"] == "decided":
                    if (
                        current is None
                        or current["generation"] != 0
                        or current["review_hash"] != review.content_hash
                        or current["review_json"] != encode_json(review.as_document())
                        or current["decision_hash"] is not None
                        or current["decision_json"] is not None
                        or current["state"] != "prepared"
                        or decision is None
                        or state not in {"approved", "denied"}
                        or decision.outcome != state
                        or row["generation"] != 1
                    ):
                        raise ValueError("decision transition")
                elif row["event_type"] == "revoked":
                    if (
                        current is None
                        or current["generation"] != 1
                        or current["review_hash"] != review.content_hash
                        or current["review_json"] != encode_json(review.as_document())
                        or decision is None
                        or current["decision_hash"] != decision.content_hash
                        or current["decision_json"] != encode_json(decision.as_document())
                        or current["state"] != decision.outcome
                        or state != "revoked"
                        or row["generation"] != 2
                    ):
                        raise ValueError("revoke transition")
                else:
                    raise ValueError("event type")
                projections[review.approval_id] = _projection(
                    review,
                    decision,
                    state,
                    row["generation"],
                    row["content_hash"],
                    updated_at,
                )
                previous = row["content_hash"]
            head = _AuditHead(expected_event_id - 1, previous)
            if not anchor_seen or head.event_id < self._anchor.event_id:
                raise ValueError("event anchor")
            stored = self._connection.execute(
                "SELECT approval_id, review_hash, review_json, decision_hash, "
                "decision_json, state, generation, last_event_hash, updated_at FROM "
                "studio_authenticated_human_decisions"
            ).fetchall()
            if len(stored) != len(projections):
                raise ValueError("projection count")
            for row in stored:
                expected = projections.pop(row["approval_id"])
                for name, value in expected.items():
                    if row[name] != value:
                        raise ValueError("projection mismatch")
            if projections:
                raise ValueError("projection missing")
            if observed_head is not None:
                self._poisoned = True
                observed_head.append(head)
                self._poisoned = False
            return head
        except StudioError as exc:
            if exc.code == "invalid_state" and exc.message == _AUTHORITY_SCHEMA_ERROR:
                raise
            raise StudioError(
                "invalid_state", "authenticated decision audit failed"
            ) from exc
        except Exception as exc:
            raise StudioError("invalid_state", "authenticated decision audit failed") from exc

    def _advance_anchor(self, head: _AuditHead) -> None:
        if head.event_id < self._anchor.event_id or (
            head.event_id == self._anchor.event_id
            and not hmac.compare_digest(head.content_hash, self._anchor.content_hash)
        ):
            raise StudioError("invalid_state", "authenticated decision audit failed")
        self._anchor = head

    def _publish_anchor_after_commit(self, head: _AuditHead) -> None:
        try:
            self._advance_anchor(head)
        except BaseException:
            self._poison()
            raise

    def _retain_anchor_during_failure(
        self, head: _AuditHead, error: BaseException
    ) -> bool:
        try:
            self._advance_anchor(head)
        except BaseException:
            self._poison()
            _note_indeterminate_cleanup(error)
            return False
        return True

    def _require_usable(self) -> None:
        if self._poisoned:
            raise StudioError(
                "invalid_state", "Authenticated decision authority is unavailable"
            )
        self._store._require_active_authenticated_human_decision_connection(
            self._connection
        )

    def _poison(self) -> None:
        self._poisoned = True

    def _rollback_or_poison(self) -> bool:
        try:
            if self._connection.in_transaction:
                self._connection.rollback()
            if self._connection.in_transaction:
                raise RuntimeError("authenticated decision transaction remains active")
        except BaseException:
            self._poison()
            try:
                if self._connection.in_transaction:
                    self._connection.rollback()
            except BaseException:
                pass
            return False
        return True

    def _reconcile_failed_write_commit(
        self, entry: _AuditHead, final: _AuditHead, error: BaseException
    ) -> _WriteCommitReconciliation:
        observed: _AuditHead | None = None
        commit_started = False
        try:
            try:
                if not self._retain_anchor_during_failure(entry, error):
                    self._rollback_or_poison()
                    return _WriteCommitReconciliation(None, False)
                if not self._rollback_or_poison():
                    _note_indeterminate_cleanup(error)
                    return _WriteCommitReconciliation(None, False)
                self._require_usable()
                self._connection.execute("BEGIN")
                observed = self._audit_in_transaction()
                if observed not in {entry, final}:
                    raise ValueError("ambiguous commit head")
                commit_started = True
                self._connection.commit()
                if not self._retain_anchor_during_failure(observed, error):
                    self._rollback_or_poison()
                    return _WriteCommitReconciliation(None, False)
            except BaseException:
                try:
                    transaction_active = self._connection.in_transaction
                except BaseException:
                    self._poison()
                    _note_indeterminate_cleanup(error)
                    return _WriteCommitReconciliation(None, False)
                if transaction_active or not commit_started or observed is None:
                    self._rollback_or_poison()
                    self._poison()
                    _note_indeterminate_cleanup(error)
                    return _WriteCommitReconciliation(None, False)
                if not self._retain_anchor_during_failure(observed, error):
                    self._rollback_or_poison()
                    return _WriteCommitReconciliation(None, False)
            return _WriteCommitReconciliation(observed, True)
        except BaseException:
            self._rollback_or_poison()
            self._poison()
            _note_indeterminate_cleanup(error)
            return _WriteCommitReconciliation(None, False)

    def _build_event(
        self,
        *,
        event_type: str,
        review: ExecutionApprovalReview,
        decision: ExecutionApprovalDecision | None,
        state: str,
        generation: int,
        previous_hash: str,
    ) -> _PendingEvent:
        created_at = utc_now()
        document = _event_document(
            event_type=event_type,
            review=review,
            decision=decision,
            state=state,
            generation=generation,
            previous_hash=previous_hash,
            updated_at=created_at,
        )
        content_json = encode_json(document)
        content_hash = hashlib.sha256(content_json.encode("utf-8")).hexdigest()
        return _PendingEvent(
            content_json=content_json,
            content_hash=content_hash,
            mac=_event_mac(self._event_key, document),
            created_at=created_at,
        )

    def _append(
        self,
        *,
        event_type: str,
        review: ExecutionApprovalReview,
        generation: int,
        previous_hash: str,
        event: _PendingEvent,
    ) -> None:
        self._connection.execute(
            "INSERT INTO studio_authenticated_human_decision_events "
            "(credential_id, approval_id, generation, event_type, content_json, "
            "content_hash, previous_hash, mac, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _CREDENTIAL_ID,
                review.approval_id,
                generation,
                event_type,
                event.content_json,
                event.content_hash,
                previous_hash,
                event.mac,
                event.created_at,
            ),
        )

    @contextmanager
    def _read_transaction(self) -> Iterator[_AuditHead]:
        with self._lock:
            self._require_usable()
            head: _AuditHead | None = None
            observed_heads: list[_AuditHead] = []
            failure: _LatchedFailure | None = None
            phase = "begin"
            try:
                try:
                    self._connection.execute("BEGIN")
                    phase = "body"
                    head = self._audit_in_transaction(observed_heads)
                    yield head
                    phase = "commit"
                    self._connection.commit()
                    self._publish_anchor_after_commit(head)
                    phase = "done"
                    _ = phase
                except sqlite3.Error as exc:
                    failure = _LatchedFailure(
                        exc,
                        StudioError(
                            "internal_error",
                            "authenticated decision transaction failed",
                        ),
                    )
                    if head is None and observed_heads:
                        head = observed_heads[-1]
                    if head is not None:
                        self._retain_anchor_during_failure(head, exc)
                    self._rollback_or_poison()
                    _raise_latched_failure(failure)
                except Exception as exc:
                    failure = _LatchedFailure(exc, exc)
                    if head is None and observed_heads:
                        head = observed_heads[-1]
                    if head is not None:
                        self._retain_anchor_during_failure(head, exc)
                    if not self._rollback_or_poison():
                        failure.outcome = StudioError(
                            "internal_error",
                            "authenticated decision transaction failed",
                        )
                    _raise_latched_failure(failure)
                except BaseException as exc:
                    failure = _LatchedFailure(exc, exc)
                    if head is None and observed_heads:
                        head = observed_heads[-1]
                    if head is not None:
                        self._retain_anchor_during_failure(head, exc)
                    if not self._rollback_or_poison():
                        _note_indeterminate_cleanup(exc)
                    _raise_latched_failure(failure)
            except BaseException as escaped:
                if failure is not None and (
                    escaped is failure.source or escaped is failure.outcome
                ):
                    raise
                if failure is None:
                    primary = _immediate_interrupted_primary(escaped)
                    recovered = primary is not None
                    if primary is None:
                        primary = escaped
                    failure = (
                        _LatchedFailure(
                            primary,
                            StudioError(
                                "internal_error",
                                "authenticated decision transaction failed",
                            ),
                        )
                        if isinstance(primary, sqlite3.Error)
                        else _LatchedFailure(primary, primary)
                    )
                    if recovered:
                        _note_indeterminate_cleanup(failure.source)
                else:
                    _note_indeterminate_cleanup(failure.source)
                self._poison()
                if head is not None:
                    try:
                        self._retain_anchor_during_failure(head, failure.source)
                    except BaseException:
                        pass
                try:
                    if not self._rollback_or_poison():
                        _note_indeterminate_cleanup(failure.source)
                except BaseException:
                    _note_indeterminate_cleanup(failure.source)
                _raise_latched_failure(failure)

    @contextmanager
    def _write_transaction(self) -> Iterator[_AuditHead]:
        with self._lock:
            self._require_usable()
            entry: _AuditHead | None = None
            observed_entries: list[_AuditHead] = []
            final: _AuditHead | None = None
            failure: _LatchedFailure | None = None
            phase = "begin"
            try:
                try:
                    self._connection.execute("BEGIN IMMEDIATE")
                    phase = "body"
                    entry = self._audit_in_transaction(observed_entries)
                    yield entry
                    final = self._audit_in_transaction()
                    phase = "commit"
                    self._connection.commit()
                    self._publish_anchor_after_commit(final)
                    phase = "done"
                except sqlite3.Error as exc:
                    failure = _LatchedFailure(
                        exc,
                        StudioError(
                            "internal_error",
                            "authenticated decision transaction failed",
                        ),
                    )
                    if entry is None and observed_entries:
                        entry = observed_entries[-1]
                    if phase == "commit" and entry is not None and final is not None:
                        self._reconcile_failed_write_commit(entry, final, exc)
                    else:
                        if entry is not None:
                            self._retain_anchor_during_failure(entry, exc)
                        self._rollback_or_poison()
                    _raise_latched_failure(failure)
                except Exception as exc:
                    failure = _LatchedFailure(exc, exc)
                    if entry is None and observed_entries:
                        entry = observed_entries[-1]
                    if phase == "commit" and entry is not None and final is not None:
                        self._reconcile_failed_write_commit(entry, final, exc)
                    else:
                        if entry is not None:
                            self._retain_anchor_during_failure(entry, exc)
                        if not self._rollback_or_poison():
                            failure.outcome = StudioError(
                                "internal_error",
                                "authenticated decision transaction failed",
                            )
                    _raise_latched_failure(failure)
                except BaseException as exc:
                    failure = _LatchedFailure(exc, exc)
                    if entry is None and observed_entries:
                        entry = observed_entries[-1]
                    if phase == "commit" and entry is not None and final is not None:
                        self._reconcile_failed_write_commit(entry, final, exc)
                    else:
                        if entry is not None:
                            self._retain_anchor_during_failure(entry, exc)
                        if not self._rollback_or_poison():
                            _note_indeterminate_cleanup(exc)
                    _raise_latched_failure(failure)
            except BaseException as escaped:
                if failure is not None and (
                    escaped is failure.source or escaped is failure.outcome
                ):
                    raise
                if failure is None:
                    primary = _immediate_interrupted_primary(escaped)
                    recovered = primary is not None
                    if primary is None:
                        primary = escaped
                    failure = (
                        _LatchedFailure(
                            primary,
                            StudioError(
                                "internal_error",
                                "authenticated decision transaction failed",
                            ),
                        )
                        if isinstance(primary, sqlite3.Error)
                        else _LatchedFailure(primary, primary)
                    )
                    if recovered:
                        _note_indeterminate_cleanup(failure.source)
                else:
                    _note_indeterminate_cleanup(failure.source)
                self._poison()
                if entry is not None:
                    try:
                        self._retain_anchor_during_failure(entry, failure.source)
                    except BaseException:
                        pass
                try:
                    if not self._rollback_or_poison():
                        _note_indeterminate_cleanup(failure.source)
                except BaseException:
                    _note_indeterminate_cleanup(failure.source)
                _raise_latched_failure(failure)

    def prepare(self, review: object, *, expected_generation: object) -> ExecutionApprovalReview:
        review = _validate_review(review)
        if _exact_integer(expected_generation, "approval_stale") != 0:
            raise ApprovalError("approval_stale")
        with self._write_transaction() as head:
            row = self._row(review.approval_id)
            if row is not None:
                stored = _review_from_json(row["review_json"])
                if row["review_hash"] == review.content_hash and stored == review:
                    return replace(stored)
                raise ApprovalError("approval_stale")
            previous_hash = head.content_hash
            event = self._build_event(
                event_type="prepared",
                review=review,
                decision=None,
                state="prepared",
                generation=0,
                previous_hash=previous_hash,
            )
            if not self._insert_projection(
                review,
                decision=None,
                state="prepared",
                generation=0,
                event=event,
            ):
                raise ApprovalError("approval_stale")
            self._append(
                event_type="prepared",
                review=review,
                generation=0,
                previous_hash=previous_hash,
                event=event,
            )
        return replace(review)

    def decide(
        self, decision: object, *, expected_generation: object, expected_review_hash: object
    ) -> ExecutionApprovalDecision:
        decision = _validate_director_decision(decision)
        if (
            _exact_integer(expected_generation, "approval_stale") != 0
            or _exact_hash(expected_review_hash, "approval_stale")
            != decision.review_hash
        ):
            raise ApprovalError("approval_stale")
        with self._write_transaction() as head:
            row = self._row(decision.approval_id)
            if row is None:
                raise ApprovalError("approval_required")
            review = _review_from_json(row["review_json"])
            stored = _decision_from_json(row["decision_json"], review)
            if row["decision_hash"] == decision.content_hash and row["generation"] == 1:
                assert stored is not None
                return replace(stored)
            if (
                row["generation"] != 0
                or review.content_hash != decision.review_hash
                or review.execution_id != decision.execution_id
            ):
                raise ApprovalError("approval_stale")
            candidates = tuple(tool_id for tool_id, _descriptor_hash in review.tool_candidates)
            if any(tool_id not in candidates for tool_id in decision.approved_tool_ids) or (
                decision.approved_tool_ids
                != tuple(
                    tool_id for tool_id in candidates if tool_id in decision.approved_tool_ids
                )
            ):
                raise ApprovalError("approval_invalid")
            previous_hash = head.content_hash
            event = self._build_event(
                event_type="decided",
                review=review,
                decision=decision,
                state=decision.outcome,
                generation=1,
                previous_hash=previous_hash,
            )
            if not self._update_projection(
                review,
                decision=decision,
                state=decision.outcome,
                generation=1,
                event=event,
                expected_generation=0,
                expected_decision_hash=None,
            ):
                raise ApprovalError("approval_stale")
            self._append(
                event_type="decided",
                review=review,
                generation=1,
                previous_hash=previous_hash,
                event=event,
            )
        return replace(decision)

    def revoke(
        self, approval_id: object, *, expected_generation: object, expected_decision_hash: object
    ) -> None:
        approval_id = _exact_id(approval_id, "approval_stale")
        decision_hash = _exact_hash(expected_decision_hash, "approval_stale")
        if _exact_integer(expected_generation, "approval_stale") != 1:
            raise ApprovalError("approval_stale")
        with self._write_transaction() as head:
            row = self._row(approval_id)
            if row is None or row["decision_json"] is None:
                raise ApprovalError("approval_required")
            review = _review_from_json(row["review_json"])
            decision = _decision_from_json(row["decision_json"], review)
            if decision.content_hash != decision_hash:
                raise ApprovalError("approval_stale")
            if row["generation"] == 2:
                return
            if row["generation"] != 1:
                raise ApprovalError("approval_stale")
            previous_hash = head.content_hash
            event = self._build_event(
                event_type="revoked",
                review=review,
                decision=decision,
                state="revoked",
                generation=2,
                previous_hash=previous_hash,
            )
            if not self._update_projection(
                review,
                decision=decision,
                state="revoked",
                generation=2,
                event=event,
                expected_generation=1,
                expected_decision_hash=decision_hash,
            ):
                raise ApprovalError("approval_stale")
            self._append(
                event_type="revoked",
                review=review,
                generation=2,
                previous_hash=previous_hash,
                event=event,
            )

    def fingerprint_hashes(self, review: object) -> tuple[str, str | None]:
        snapshot = self.snapshot(review)
        return snapshot.review_hash, snapshot.decision_hash

    def snapshot(self, review: object) -> ApprovalAuthoritySnapshot:
        review = _validate_review(review)
        with self._read_transaction():
            return self._snapshot_in_transaction(review)

    def _snapshot_in_transaction(
        self, review: ExecutionApprovalReview
    ) -> ApprovalAuthoritySnapshot:
        row = self._row(review.approval_id)
        if row is None:
            return ApprovalAuthoritySnapshot(
                None, None, 0, review.content_hash, None, "missing"
            )
        stored_review = _review_from_json(row["review_json"])
        if stored_review != review:
            return ApprovalAuthoritySnapshot(
                None, None, 0, review.content_hash, None, "stale"
            )
        decision = _decision_from_json(row["decision_json"], stored_review)
        return ApprovalAuthoritySnapshot(
            replace(stored_review),
            None if decision is None else replace(decision),
            row["generation"],
            stored_review.content_hash,
            None if decision is None else decision.content_hash,
            row["state"],
        )

    def check_snapshot(
        self,
        review: object,
        expected: object,
        *,
        now_ms: object,
    ) -> ApprovalCheck:
        review = _validate_review(review)
        expected = _validate_authority_snapshot(expected)
        now = _exact_integer(now_ms, "approval_check_failed")
        if expected.review_hash != review.content_hash:
            raise ApprovalError("approval_stale")
        with self._read_transaction():
            current = self._snapshot_in_transaction(review)
            if expected.state in {"missing", "prepared"}:
                raise ApprovalError("approval_required")
            if expected.state == "stale":
                raise ApprovalError("approval_stale")
            if current.state in {"missing", "stale"}:
                raise ApprovalError("approval_stale")
            if current.state == "revoked":
                raise ApprovalError("approval_revoked")
            decision = current.current_decision
            if (
                decision is None
                or current.prepared_review != review
                or current.generation != expected.generation
                or expected.prepared_review != current.prepared_review
                or expected.current_decision != decision
                or expected.decision_hash != decision.content_hash
            ):
                raise ApprovalError("approval_stale")
            if expected.state == "denied":
                raise ApprovalError("approval_denied")
            if (
                expected.state != "approved"
                or current.state != "approved"
                or decision.outcome != "approved"
            ):
                raise ApprovalError("approval_invalid")
            if decision.expires_at_ms is None:
                raise ApprovalError("approval_invalid")
            if now >= decision.expires_at_ms:
                raise ApprovalError("approval_expired")
        return ApprovalCheck(
            review.content_hash,
            decision.content_hash,
            decision.approved_tool_ids,
        )

    def check(self, review: object, *, now_ms: object) -> ApprovalCheck:
        now = _exact_integer(now_ms, "approval_check_failed")
        snapshot = self.snapshot(review)
        return self.check_snapshot(review, snapshot, now_ms=now)

    def _row(self, approval_id: str) -> Any:
        return self._connection.execute(
            "SELECT approval_id, review_hash, review_json, decision_hash, decision_json, state, "
            "generation, last_event_hash, updated_at FROM studio_authenticated_human_decisions "
            "WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()

    def _insert_projection(
        self,
        review: ExecutionApprovalReview,
        *,
        decision: ExecutionApprovalDecision | None,
        state: str,
        generation: int,
        event: _PendingEvent,
    ) -> bool:
        values = _projection(
            review,
            decision,
            state,
            generation,
            event.content_hash,
            event.created_at,
        )
        cursor = self._connection.execute(
            "INSERT INTO studio_authenticated_human_decisions "
            "(approval_id, review_hash, review_json, decision_hash, decision_json, state, "
            "generation, last_event_hash, updated_at) VALUES (:approval_id, :review_hash, "
            ":review_json, :decision_hash, :decision_json, :state, :generation, "
            ":last_event_hash, :updated_at) ON CONFLICT(approval_id) DO NOTHING",
            values,
        )
        return cursor.rowcount == 1

    def _update_projection(
        self,
        review: ExecutionApprovalReview,
        *,
        decision: ExecutionApprovalDecision,
        state: str,
        generation: int,
        event: _PendingEvent,
        expected_generation: int,
        expected_decision_hash: str | None,
    ) -> bool:
        values = {
            **_projection(
                review,
                decision,
                state,
                generation,
                event.content_hash,
                event.created_at,
            ),
            "expected_generation": expected_generation,
            "expected_decision_hash": expected_decision_hash,
        }
        cursor = self._connection.execute(
            "UPDATE studio_authenticated_human_decisions SET "
            "decision_hash=:decision_hash, decision_json=:decision_json, state=:state, "
            "generation=:generation, last_event_hash=:last_event_hash, updated_at=:updated_at "
            "WHERE approval_id=:approval_id AND review_hash=:review_hash "
            "AND generation=:expected_generation "
            "AND decision_hash IS :expected_decision_hash",
            values,
        )
        return cursor.rowcount == 1


def _projection(
    review: ExecutionApprovalReview,
    decision: ExecutionApprovalDecision | None,
    state: str,
    generation: int,
    event_hash: str,
    updated_at: str,
) -> dict[str, object]:
    return {
        "approval_id": review.approval_id,
        "review_hash": review.content_hash,
        "review_json": encode_json(review.as_document()),
        "decision_hash": None if decision is None else decision.content_hash,
        "decision_json": None if decision is None else encode_json(decision.as_document()),
        "state": state,
        "generation": generation,
        "last_event_hash": event_hash,
        "updated_at": updated_at,
    }


def _review_from_document(value: object) -> ExecutionApprovalReview:
    if type(value) is not dict:
        raise ValueError("review document")
    fields = {
        key: item
        for key, item in value.items()
        if key not in {"format", "format_version", "content_hash", "generation"}
    }
    fields["tool_candidates"] = tuple(
        (item["tool_id"], item["descriptor_hash"])
        for item in fields.get("tool_candidates", [])
    )
    recreated = ExecutionApprovalReview.create(**fields)
    if value != recreated.as_document():
        raise ValueError("review exactness")
    return recreated


def _review_from_json(value: object) -> ExecutionApprovalReview:
    if type(value) is not str:
        raise ValueError("review JSON")
    return _review_from_document(decode_object(value, context="authenticated decision review"))


def _decision_from_document(
    value: object, review: ExecutionApprovalReview
) -> ExecutionApprovalDecision | None:
    if value is None:
        return None
    if type(value) is not dict:
        raise ValueError("decision document")
    fields = {
        key: item
        for key, item in value.items()
        if key
        not in {
            "format",
            "format_version",
            "content_hash",
            "approval_id",
            "execution_id",
            "review_hash",
            "generation",
        }
    }
    fields["review"] = review
    fields["approved_tool_ids"] = tuple(fields.get("approved_tool_ids", []))
    recreated = ExecutionApprovalDecision.create(**fields)
    if value != recreated.as_document():
        raise ValueError("decision exactness")
    return _validate_director_decision(recreated)


def _decision_from_json(
    value: object, review: ExecutionApprovalReview
) -> ExecutionApprovalDecision | None:
    if value is None:
        return None
    if type(value) is not str:
        raise ValueError("decision JSON")
    return _decision_from_document(decode_object(value, context="authenticated decision"), review)


def _director_clock_ms(_time_ns=time.time_ns) -> int:
    return _time_ns() // 1_000_000


def _build_ollama_v2_authorization_construction_capsule(
    _authority_type=StudioAuthenticatedHumanDecisionAuthority,
    _credential_type=_CredentialEvidence,
    _id=id,
    _object_factory=object,
    _rlock_factory=threading.RLock,
    _store_type=StudioStore,
    _type=type,
    _weakref_ref=weakref.ref,
):
    """Bind one-use construction to an exact successfully registered authority."""
    registry: dict[int, tuple[object, ...]] = {}
    pending: dict[int, tuple[object, ...]] = {}
    lock = _rlock_factory()

    def register(authority: StudioAuthenticatedHumanDecisionAuthority) -> None:
        if _type(authority) is not _authority_type:
            raise ApprovalError("approval_authority_invalid")
        epoch = _object_factory()
        record = (
            _weakref_ref(authority),
            authority._store,
            authority._event_key,
            authority._credential,
            authority._connection,
            authority._lock,
            epoch,
        )
        with lock:
            stale_authorities = [
                key for key, existing in registry.items() if existing[1] is authority._store
            ]
            for key in stale_authorities:
                registry.pop(key, None)
            stale_tokens = [
                key for key, issued in pending.items() if issued[2] is authority._store
            ]
            for key in stale_tokens:
                pending.pop(key, None)
            registry[_id(authority)] = record

    def invalidate(authority: object) -> None:
        if _type(authority) is not _authority_type:
            raise ApprovalError("approval_authority_invalid")
        with lock:
            record = registry.get(_id(authority))
        if record is None or record[0]() is not authority:
            with lock:
                stale = [key for key, value in pending.items() if value[1] is authority]
                for key in stale:
                    pending.pop(key, None)
            return
        authority_lock = record[5]
        with authority_lock:
            with lock:
                if registry.get(_id(authority)) is record:
                    registry.pop(_id(authority), None)
                stale = [key for key, value in pending.items() if value[1] is authority]
                for key in stale:
                    pending.pop(key, None)

    def active(authority: object, epoch: object) -> bool:
        with lock:
            record = registry.get(_id(authority))
        if record is None:
            return False
        reference = record[0]
        return reference() is authority and record[6] is epoch

    def issue(authority: object) -> object:
        if _type(authority) is not _authority_type:
            raise ApprovalError("approval_authority_invalid")
        with lock:
            record = registry.get(_id(authority))
            if record is None or record[0]() is not authority:
                raise ApprovalError("approval_authority_invalid")
            token = _object_factory()
            pending[_id(token)] = (token, authority, *record[1:])
        return token

    def consume(authority: object, token: object) -> tuple[tuple[str, object], ...]:
        with lock:
            issued = pending.pop(_id(token), None)
            current = registry.get(_id(authority))
        valid = (
            issued is not None
            and current is not None
            and issued[0] is token
            and issued[1] is authority
            and current[0]() is authority
            and all(issued[index + 2] is current[index + 1] for index in range(6))
        )
        if not valid:
            raise ApprovalError("approval_authority_invalid")
        assert issued is not None
        return (
            ("_authority", authority),
            ("_store", issued[2]),
            ("_event_key", issued[3]),
            ("_credential", issued[4]),
            ("_connection", issued[5]),
            ("_lock", issued[6]),
            ("_epoch", issued[7]),
            ("_epoch_check", active),
            ("_clock_ms", _director_clock_ms),
            ("_require_authority_usable", authority._require_usable),
            ("_poison_authority", authority._poison),
        )

    return register, invalidate, issue, consume


(
    _register_studio_ollama_v2_authorization_authority,
    _invalidate_studio_ollama_v2_authorization_authority,
    _issue_studio_ollama_v2_authorization_capsule,
    _consume_studio_ollama_v2_authorization_capsule,
) = _build_ollama_v2_authorization_construction_capsule()


def _build_studio_authority_construction_capsule(
    register_studio,
    _register_ollama=_register_studio_ollama_v2_authorization_authority,
    _approval_error=ApprovalError,
    _authority_type=StudioAuthenticatedHumanDecisionAuthority,
    _base_exception=BaseException,
    _bytes_type=bytes,
    _credential_type=_CredentialEvidence,
    _empty_head=_EMPTY_AUDIT_HEAD,
    _exception_type=Exception,
    _frame_getter=sys._getframe,
    _frozenset_type=frozenset,
    _id=id,
    _len=len,
    _object_factory=object,
    _object_new=object.__new__,
    _rlock_factory=threading.RLock,
    _store_type=StudioStore,
    _type=type,
):
    pending: dict[
        int,
        tuple[
            object,
            object,
            StudioStore,
            bytes,
            _CredentialEvidence,
            sqlite3.Connection,
            object,
        ],
    ] = {}
    lock = _rlock_factory()
    allowed_codes = _frozenset_type(
        {
            _authority_type.enroll.__func__.__code__,
            _authority_type.unlock.__func__.__code__,
        }
    )

    def allowed_path(code: object) -> bool:
        return code in allowed_codes

    def provisional(
        authority_type: object,
        store: StudioStore,
        event_key: bytes,
        credential: _CredentialEvidence,
    ) -> StudioAuthenticatedHumanDecisionAuthority:
        try:
            caller_code = _frame_getter(1).f_code
        except _exception_type:
            raise _approval_error("approval_authority_invalid") from None
        if (
            not allowed_path(caller_code)
            or authority_type is not _authority_type
            or _type(store) is not _store_type
            or _type(event_key) is not _bytes_type
            or _len(event_key) != 32
            or _type(credential) is not _credential_type
        ):
            raise _approval_error("approval_authority_invalid")
        authority = _object_new(_authority_type)
        authority._store = store
        authority._event_key = event_key
        authority._credential = credential
        authority._anchor = _empty_head
        authority._poisoned = False
        authority._connection = store._authenticated_human_decision_connection()
        authority._lock = store._authenticated_human_decision_lock
        return authority

    def consume(
        authority: object,
        token: object,
    ) -> tuple[tuple[str, object], ...]:
        token_id = _id(token)
        with lock:
            issued = pending.pop(token_id, None)
        try:
            valid = (
                issued is not None
                and issued[0] is token
                and issued[1] is authority
                and issued[2] is authority._store
                and issued[3] is authority._event_key
                and issued[4] is authority._credential
                and issued[5] is authority._connection
                and issued[6] is authority._lock
            )
        except _exception_type:
            valid = False
        if not valid:
            raise _approval_error("approval_authority_invalid")
        assert issued is not None
        return (
            ("_store", issued[2]),
            ("_event_key", issued[3]),
            ("_credential", issued[4]),
            ("_connection", issued[5]),
            ("_lock", issued[6]),
        )

    def complete(
        authority: StudioAuthenticatedHumanDecisionAuthority,
        store: StudioStore,
        event_key: bytes,
        credential: _CredentialEvidence,
    ) -> None:
        try:
            caller_code = _frame_getter(1).f_code
        except _exception_type:
            raise _approval_error("approval_authority_invalid") from None
        if not allowed_path(caller_code):
            raise _approval_error("approval_authority_invalid")
        connection = store._authenticated_human_decision_connection()
        store_lock = store._authenticated_human_decision_lock
        if (
            authority._store is not store
            or authority._event_key is not event_key
            or authority._credential is not credential
            or authority._connection is not connection
            or authority._lock is not store_lock
        ):
            raise _approval_error("approval_authority_invalid")
        token = _object_factory()
        token_id = _id(token)
        with lock:
            pending[token_id] = (
                token,
                authority,
                store,
                event_key,
                credential,
                connection,
                store_lock,
            )
        try:
            register_studio(authority, token)
            _register_ollama(authority)
        except _base_exception:
            with lock:
                pending.pop(token_id, None)
            raise

    return provisional, complete, consume


(
    _new_provisional_studio_authority,
    _complete_studio_authority_registration,
    _consume_studio_authority_registration_provenance,
) = _build_studio_authority_construction_capsule(
    _register_studio_execution_approval_authority
)


class _BoundStudioConstructionEntrypoint:
    __slots__ = ("_owner", "__func__", "_provisional", "_complete")

    def __init__(
        self,
        owner,
        implementation,
        provisional,
        complete,
        _object_setattr=object.__setattr__,
    ) -> None:
        _object_setattr(self, "_owner", owner)
        _object_setattr(self, "__func__", implementation)
        _object_setattr(self, "_provisional", provisional)
        _object_setattr(self, "_complete", complete)

    def __setattr__(self, _name, _value, _approval_error=ApprovalError) -> None:
        raise _approval_error("approval_authority_invalid")

    def __call__(self, store: StudioStore, *, passphrase: object):
        return self.__func__(
            self._owner,
            store,
            self._provisional,
            self._complete,
            passphrase=passphrase,
        )


class _StudioConstructionEntrypoint:
    __slots__ = ("_implementation", "_provisional", "_complete", "_bound_factory")

    def __init__(
        self,
        implementation,
        provisional,
        complete,
        _bound_factory=_BoundStudioConstructionEntrypoint,
        _object_setattr=object.__setattr__,
    ) -> None:
        _object_setattr(self, "_implementation", implementation)
        _object_setattr(self, "_provisional", provisional)
        _object_setattr(self, "_complete", complete)
        _object_setattr(self, "_bound_factory", _bound_factory)

    def __setattr__(self, _name, _value, _approval_error=ApprovalError) -> None:
        raise _approval_error("approval_authority_invalid")

    def __get__(self, _instance, owner):
        return self._bound_factory(
            owner,
            self._implementation,
            self._provisional,
            self._complete,
        )


StudioAuthenticatedHumanDecisionAuthority.enroll = _StudioConstructionEntrypoint(
    StudioAuthenticatedHumanDecisionAuthority.enroll.__func__,
    _new_provisional_studio_authority,
    _complete_studio_authority_registration,
)
StudioAuthenticatedHumanDecisionAuthority.unlock = _StudioConstructionEntrypoint(
    StudioAuthenticatedHumanDecisionAuthority.unlock.__func__,
    _new_provisional_studio_authority,
    _complete_studio_authority_registration,
)


_STUDIO_AUTHORITY_FUNCTIONS = _authority_functions(
    StudioAuthenticatedHumanDecisionAuthority
)
_configure_studio_execution_approval_authority(
    StudioAuthenticatedHumanDecisionAuthority,
    _consume_studio_authority_registration_provenance,
)


__all__ = ("StudioAuthenticatedHumanDecisionAuthority",)
