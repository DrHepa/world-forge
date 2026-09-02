"""Closed private contracts for Director-governed Ollama-v2 plan mandates."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime

from worldforge.provider_evidence.ollama_v2_controller_contracts import (
    CONTROLLER_POLICY_CONTENT_HASH,
    CONTROLLER_POLICY_SERIALIZED_SHA256,
    MAX_DOCUMENT_BYTES,
    MAX_ENTRY_BYTES,
    MAX_TREE_BYTES,
    MAX_TREE_ENTRIES,
    AuthorizationConsumption,
    AuthorizationOutcome,
    AuthorizationRejection,
    AuthorizationRequest,
    ControllerContractError,
    ControllerPlan,
    HostEffect,
    OperationSnapshot,
    RollbackPlan,
    canonical_controller_bytes,
    canonical_interpreter_binding,
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
_HASH = re.compile(r"[0-9a-f]{64}")
_FORMAT_VERSION = 1
_DIRECTOR_ID = "director_local"
_CANONICAL_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")


class StudioOllamaV2AuthorizationContractError(ValueError):
    """An exact private authorization contract was rejected."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _fail(reason: str) -> None:
    raise StudioOllamaV2AuthorizationContractError(reason)


def _id(value: object, reason: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        _fail(reason)
    return value


def _hash(value: object, reason: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _fail(reason)
    return value


def _int(value: object, reason: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        _fail(reason)
    return value


def _timestamp(value: object, reason: str) -> str:
    if type(value) is not str or _CANONICAL_TIMESTAMP.fullmatch(value) is None:
        _fail(reason)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        _fail(reason)
    canonical = (
        f"{parsed.year:04d}-{parsed.month:02d}-{parsed.day:02d}T"
        f"{parsed.hour:02d}:{parsed.minute:02d}:{parsed.second:02d}."
        f"{parsed.microsecond:06d}Z"
    )
    if canonical != value:
        _fail(reason)
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        _fail("authorization_document_invalid")


def _decode(value: str) -> object:
    def reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                _fail("authorization_document_invalid")
            result[key] = item
        return result

    try:
        return json.loads(
            value,
            object_pairs_hook=reject_pairs,
            parse_constant=lambda _value: _fail("authorization_document_invalid"),
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        _fail("authorization_document_invalid")


def _json_text(value: object) -> str:
    return _canonical(value).decode("utf-8")


def _document_hash(value: object) -> str:
    if type(value) is not dict:
        _fail("authorization_document_invalid")
    payload = {key: item for key, item in value.items() if key != "content_hash"}
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _seal(value: dict[str, object]) -> dict[str, object]:
    return {**value, "content_hash": _document_hash(value)}


def _expect(
    value: object,
    *,
    keys: frozenset[str],
    format_name: str,
    reason: str,
) -> dict[str, object]:
    if (
        type(value) is not dict
        or any(type(key) is not str for key in value)
        or frozenset(value) != keys
    ):
        _fail(reason)
    checked = value
    _hash(checked.get("content_hash"), reason)
    if (
        type(checked.get("format")) is not str
        or checked.get("format") != format_name
        or type(checked.get("format_version")) is not int
        or checked["format_version"] != _FORMAT_VERSION
        or checked.get("content_hash") != _document_hash(checked)
    ):
        _fail(reason)
    return checked


class _Canonical:
    __slots__ = ()

    @staticmethod
    def compute_document_hash(document: object) -> str:
        return _document_hash(document)


@dataclass(frozen=True, slots=True)
class StudioOllamaV2AuthorizationImpact(_Canonical):
    phase: str
    controller_contract_version: int
    authorization_contract_version: int
    policy_content_hash: str
    policy_serialized_sha256: str
    interpreter_binding_hash: str
    maximum_document_bytes: int
    maximum_tree_entries: int
    maximum_entry_bytes: int
    maximum_tree_bytes: int
    maximum_effect_count: int
    release_manifest_hash: str
    model_manifest_hash: str
    release_entry_count: int
    model_entry_count: int
    release_size_bytes: int
    model_size_bytes: int
    effect_count: int
    effect_kinds: tuple[str, ...]
    resource_ids: tuple[str, ...]
    data_sources: tuple[str, ...]
    data_destinations: tuple[str, ...]
    permissions: tuple[str, ...]
    network_egress: str
    pricing_applicability: str
    availability: str
    production_eligible: bool
    catalog_admission: bool
    provider_execution: bool
    native_evidence: bool
    public_receipt: bool
    user_data: bool

    def __post_init__(self) -> None:
        reason = "ollama_v2_authorization_impact_invalid"
        _int(self.effect_count, reason, minimum=1, maximum=32)
        _hash(self.policy_content_hash, reason)
        _hash(self.policy_serialized_sha256, reason)
        _hash(self.interpreter_binding_hash, reason)
        _hash(self.release_manifest_hash, reason)
        _hash(self.model_manifest_hash, reason)
        for value in (
            self.maximum_document_bytes,
            self.maximum_tree_entries,
            self.maximum_entry_bytes,
            self.maximum_tree_bytes,
            self.maximum_effect_count,
        ):
            _int(value, reason, minimum=1)
        if (
            type(self.phase) is not str
            or self.phase not in {"apply", "rollback"}
            or type(self.controller_contract_version) is not int
            or self.controller_contract_version != 1
            or type(self.authorization_contract_version) is not int
            or self.authorization_contract_version != 1
            or self.policy_content_hash != CONTROLLER_POLICY_CONTENT_HASH
            or self.policy_serialized_sha256 != CONTROLLER_POLICY_SERIALIZED_SHA256
            or self.interpreter_binding_hash != canonical_interpreter_binding().content_hash
            or self.maximum_document_bytes != MAX_DOCUMENT_BYTES
            or self.maximum_tree_entries != MAX_TREE_ENTRIES
            or self.maximum_entry_bytes != MAX_ENTRY_BYTES
            or self.maximum_tree_bytes != MAX_TREE_BYTES
            or self.maximum_effect_count != 32
            or type(self.effect_kinds) is not tuple
            or type(self.resource_ids) is not tuple
            or type(self.data_sources) is not tuple
            or type(self.data_destinations) is not tuple
            or type(self.permissions) is not tuple
            or len(self.effect_kinds) != len(self.resource_ids)
            or self.data_destinations != self.resource_ids
            or self.permissions != self.effect_kinds
            or self.effect_count != len(self.effect_kinds)
            or any(type(item) is not str or not item for item in self.effect_kinds)
            or any(type(item) is not str or not item for item in self.resource_ids)
            or any(type(item) is not str or not item for item in self.data_sources)
            or type(self.network_egress) is not str
            or self.network_egress != "prohibited"
            or type(self.pricing_applicability) is not str
            or self.pricing_applicability != "not_applicable"
            or type(self.availability) is not str
            or self.availability != "unavailable"
            or self.production_eligible is not False
            or self.catalog_admission is not False
            or self.provider_execution is not False
            or self.native_evidence is not False
            or self.public_receipt is not False
            or self.user_data is not False
        ):
            _fail(reason)
        for value in (
            self.release_entry_count,
            self.model_entry_count,
            self.release_size_bytes,
            self.model_size_bytes,
        ):
            _int(value, reason)

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.studio_ollama_v2_authorization_impact",
            "format_version": _FORMAT_VERSION,
            "phase": self.phase,
            "controller_contract_version": self.controller_contract_version,
            "authorization_contract_version": self.authorization_contract_version,
            "policy_content_hash": self.policy_content_hash,
            "policy_serialized_sha256": self.policy_serialized_sha256,
            "interpreter_binding_hash": self.interpreter_binding_hash,
            "maximum_document_bytes": self.maximum_document_bytes,
            "maximum_tree_entries": self.maximum_tree_entries,
            "maximum_entry_bytes": self.maximum_entry_bytes,
            "maximum_tree_bytes": self.maximum_tree_bytes,
            "maximum_effect_count": self.maximum_effect_count,
            "release_manifest_hash": self.release_manifest_hash,
            "model_manifest_hash": self.model_manifest_hash,
            "release_entry_count": self.release_entry_count,
            "model_entry_count": self.model_entry_count,
            "release_size_bytes": self.release_size_bytes,
            "model_size_bytes": self.model_size_bytes,
            "effect_count": self.effect_count,
            "effect_kinds": list(self.effect_kinds),
            "resource_ids": list(self.resource_ids),
            "data_sources": list(self.data_sources),
            "data_destinations": list(self.data_destinations),
            "permissions": list(self.permissions),
            "network_egress": self.network_egress,
            "pricing_applicability": self.pricing_applicability,
            "availability": self.availability,
            "production_eligible": self.production_eligible,
            "catalog_admission": self.catalog_admission,
            "provider_execution": self.provider_execution,
            "native_evidence": self.native_evidence,
            "public_receipt": self.public_receipt,
            "user_data": self.user_data,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def from_document(cls, value: object) -> StudioOllamaV2AuthorizationImpact:
        reason = "ollama_v2_authorization_impact_invalid"
        keys = frozenset(
            {
                "format",
                "format_version",
                "phase",
                "controller_contract_version",
                "authorization_contract_version",
                "policy_content_hash",
                "policy_serialized_sha256",
                "interpreter_binding_hash",
                "maximum_document_bytes",
                "maximum_tree_entries",
                "maximum_entry_bytes",
                "maximum_tree_bytes",
                "maximum_effect_count",
                "release_manifest_hash",
                "model_manifest_hash",
                "release_entry_count",
                "model_entry_count",
                "release_size_bytes",
                "model_size_bytes",
                "effect_count",
                "effect_kinds",
                "resource_ids",
                "data_sources",
                "data_destinations",
                "permissions",
                "network_egress",
                "pricing_applicability",
                "availability",
                "production_eligible",
                "catalog_admission",
                "provider_execution",
                "native_evidence",
                "public_receipt",
                "user_data",
                "content_hash",
            }
        )
        checked = _expect(
            value,
            keys=keys,
            format_name="world-forge.private.studio_ollama_v2_authorization_impact",
            reason=reason,
        )
        if any(
            type(checked[name]) is not list
            for name in (
                "effect_kinds",
                "resource_ids",
                "data_sources",
                "data_destinations",
                "permissions",
            )
        ):
            _fail(reason)
        kwargs = {
            key: checked[key]
            for key in keys
            - {
                "format",
                "format_version",
                "content_hash",
                "effect_kinds",
                "resource_ids",
                "data_sources",
                "data_destinations",
                "permissions",
            }
        }
        for name in (
            "effect_kinds",
            "resource_ids",
            "data_sources",
            "data_destinations",
            "permissions",
        ):
            kwargs[name] = tuple(checked[name])
        try:
            return cls(**kwargs)  # type: ignore[arg-type]
        except TypeError:
            _fail(reason)


@dataclass(frozen=True, slots=True)
class StudioOllamaV2AuthorizationReview(_Canonical):
    mandate_id: str
    operation_id: str
    phase: str
    plan_hash: str
    rollback_plan_hash: str | None
    starting_snapshot_hash: str
    starting_cursor: int
    starting_attempt: int
    ownership_token: str
    policy_content_hash: str
    interpreter_binding_hash: str
    effect_ids: tuple[str, ...]
    effect_hashes: tuple[str, ...]
    impact: StudioOllamaV2AuthorizationImpact
    _plan_json: str
    _rollback_plan_json: str | None
    _starting_snapshot_json: str

    def __post_init__(self) -> None:
        reason = "ollama_v2_authorization_review_invalid"
        _id(self.mandate_id, reason)
        _id(self.operation_id, reason)
        _hash(self.plan_hash, reason)
        if self.rollback_plan_hash is not None:
            _hash(self.rollback_plan_hash, reason)
        _hash(self.starting_snapshot_hash, reason)
        _int(self.starting_cursor, reason, maximum=31)
        _int(self.starting_attempt, reason, minimum=1)
        _id(self.ownership_token, reason)
        _hash(self.policy_content_hash, reason)
        _hash(self.interpreter_binding_hash, reason)
        if (
            type(self.phase) is not str
            or self.phase not in {"apply", "rollback"}
            or self.policy_content_hash != CONTROLLER_POLICY_CONTENT_HASH
            or self.interpreter_binding_hash != canonical_interpreter_binding().content_hash
            or type(self.effect_ids) is not tuple
            or type(self.effect_hashes) is not tuple
            or not 1 <= len(self.effect_ids) <= 32
            or len(self.effect_ids) != len(self.effect_hashes)
            or len(set(self.effect_ids)) != len(self.effect_ids)
            or type(self.impact) is not StudioOllamaV2AuthorizationImpact
            or self.impact.phase != self.phase
            or type(self._plan_json) is not str
            or (self._rollback_plan_json is not None and type(self._rollback_plan_json) is not str)
            or type(self._starting_snapshot_json) is not str
        ):
            _fail(reason)
        for item in self.effect_ids:
            _id(item, reason)
        for item in self.effect_hashes:
            _hash(item, reason)

    @property
    def plan_document(self) -> dict[str, object]:
        value = _decode(self._plan_json)
        if type(value) is not dict:
            _fail("ollama_v2_authorization_review_invalid")
        return value

    @property
    def rollback_plan_document(self) -> dict[str, object] | None:
        if self._rollback_plan_json is None:
            return None
        value = _decode(self._rollback_plan_json)
        if type(value) is not dict:
            _fail("ollama_v2_authorization_review_invalid")
        return value

    @property
    def starting_snapshot_document(self) -> dict[str, object]:
        value = _decode(self._starting_snapshot_json)
        if type(value) is not dict:
            _fail("ollama_v2_authorization_review_invalid")
        return value

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.studio_ollama_v2_authorization_review",
            "format_version": _FORMAT_VERSION,
            "mandate_id": self.mandate_id,
            "operation_id": self.operation_id,
            "phase": self.phase,
            "plan_hash": self.plan_hash,
            "rollback_plan_hash": self.rollback_plan_hash,
            "starting_snapshot_hash": self.starting_snapshot_hash,
            "starting_cursor": self.starting_cursor,
            "starting_attempt": self.starting_attempt,
            "ownership_token": self.ownership_token,
            "policy_content_hash": self.policy_content_hash,
            "interpreter_binding_hash": self.interpreter_binding_hash,
            "effect_ids": list(self.effect_ids),
            "effect_hashes": list(self.effect_hashes),
            "impact": self.impact.to_document(),
            "plan": self.plan_document,
            "rollback_plan": self.rollback_plan_document,
            "starting_snapshot": self.starting_snapshot_document,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def from_document(cls, value: object) -> StudioOllamaV2AuthorizationReview:
        reason = "ollama_v2_authorization_review_invalid"
        keys = frozenset(
            {
                "format",
                "format_version",
                "mandate_id",
                "operation_id",
                "phase",
                "plan_hash",
                "rollback_plan_hash",
                "starting_snapshot_hash",
                "starting_cursor",
                "starting_attempt",
                "ownership_token",
                "policy_content_hash",
                "interpreter_binding_hash",
                "effect_ids",
                "effect_hashes",
                "impact",
                "plan",
                "rollback_plan",
                "starting_snapshot",
                "content_hash",
            }
        )
        checked = _expect(
            value,
            keys=keys,
            format_name="world-forge.private.studio_ollama_v2_authorization_review",
            reason=reason,
        )
        if type(checked["effect_ids"]) is not list or type(checked["effect_hashes"]) is not list:
            _fail(reason)
        try:
            operation = OperationSnapshot.from_document(checked["starting_snapshot"])
            plan = ControllerPlan.from_document(checked["plan"])
            rollback = (
                None
                if checked["rollback_plan"] is None
                else RollbackPlan.from_document(checked["rollback_plan"])
            )
        except ControllerContractError:
            _fail(reason)
        rebuilt = build_ollama_v2_authorization_review(
            operation,
            plan,
            phase=checked["phase"],  # type: ignore[arg-type]
            rollback_plan=rollback,
        )
        if rebuilt.to_document() != checked:
            _fail(reason)
        return rebuilt


def _derive_impact(
    plan: ControllerPlan,
    effects: tuple[HostEffect, ...],
    phase: str,
) -> StudioOllamaV2AuthorizationImpact:
    return StudioOllamaV2AuthorizationImpact(
        phase=phase,
        controller_contract_version=1,
        authorization_contract_version=1,
        policy_content_hash=plan.policy_content_hash,
        policy_serialized_sha256=plan.policy_serialized_sha256,
        interpreter_binding_hash=plan.interpreter_binding.content_hash,
        maximum_document_bytes=MAX_DOCUMENT_BYTES,
        maximum_tree_entries=MAX_TREE_ENTRIES,
        maximum_entry_bytes=MAX_ENTRY_BYTES,
        maximum_tree_bytes=MAX_TREE_BYTES,
        maximum_effect_count=32,
        release_manifest_hash=plan.release_manifest.content_hash,
        model_manifest_hash=plan.model_manifest.content_hash,
        release_entry_count=plan.release_manifest.entry_count,
        model_entry_count=plan.model_manifest.entry_count,
        release_size_bytes=plan.release_manifest.total_size_bytes,
        model_size_bytes=plan.model_manifest.total_size_bytes,
        effect_count=len(effects),
        effect_kinds=tuple(effect.kind for effect in effects),
        resource_ids=tuple(effect.resource_id for effect in effects),
        data_sources=(
            "controller_plan",
            "operation_snapshot",
            "sealed_release_manifest",
            "sealed_model_manifest",
            *(("rollback_plan",) if phase == "rollback" else ()),
        ),
        data_destinations=tuple(effect.resource_id for effect in effects),
        permissions=tuple(effect.kind for effect in effects),
        network_egress="prohibited",
        pricing_applicability="not_applicable",
        availability="unavailable",
        production_eligible=False,
        catalog_admission=False,
        provider_execution=False,
        native_evidence=False,
        public_receipt=False,
        user_data=False,
    )


def build_ollama_v2_authorization_review(
    starting_snapshot: object,
    plan: object,
    *,
    phase: object,
    rollback_plan: object = None,
) -> StudioOllamaV2AuthorizationReview:
    reason = "ollama_v2_authorization_review_invalid"
    if type(starting_snapshot) is not OperationSnapshot or type(plan) is not ControllerPlan:
        _fail(reason)
    if type(phase) is not str or phase not in {"apply", "rollback"}:
        _fail(reason)
    try:
        exact_snapshot = OperationSnapshot.from_document(starting_snapshot.to_document())
        exact_plan = ControllerPlan.from_document(plan.to_document())
    except ControllerContractError:
        _fail(reason)
    if (
        exact_snapshot.operation_id != exact_plan.operation_id
        or exact_snapshot.plan_hash != exact_plan.content_hash
        or exact_snapshot.ownership_token != exact_plan.ownership_token
        or exact_snapshot.applied_effect_ids
        != tuple(effect.effect_id for effect in exact_plan.effects[: exact_snapshot.apply_cursor])
    ):
        _fail(reason)
    exact_rollback: RollbackPlan | None = None
    if phase == "apply":
        if rollback_plan is not None or exact_snapshot.state != "apply_pending":
            _fail(reason)
        cursor = exact_snapshot.apply_cursor
        effects = exact_plan.effects[cursor:]
    else:
        if type(rollback_plan) is not RollbackPlan or exact_snapshot.state != "rollback_pending":
            _fail(reason)
        try:
            exact_rollback = RollbackPlan.from_document(rollback_plan.to_document())
        except ControllerContractError:
            _fail(reason)
        if (
            exact_rollback.operation_id != exact_plan.operation_id
            or exact_rollback.plan_hash != exact_plan.content_hash
            or exact_rollback.ownership_token != exact_plan.ownership_token
            or exact_rollback.source_applied_effect_ids != exact_snapshot.applied_effect_ids
            or exact_snapshot.rollback_plan_hash != exact_rollback.content_hash
        ):
            _fail(reason)
        cursor = exact_snapshot.rollback_cursor
        effects = exact_rollback.effects[cursor:]
    if not effects:
        _fail("ollama_v2_authorization_scope_empty")
    seed = {
        "operation_id": exact_snapshot.operation_id,
        "phase": phase,
        "plan_hash": exact_plan.content_hash,
        "rollback_plan_hash": None if exact_rollback is None else exact_rollback.content_hash,
        "starting_snapshot_hash": exact_snapshot.content_hash,
        "starting_cursor": cursor,
        "starting_attempt": exact_snapshot.next_attempt,
        "effect_hashes": [effect.content_hash for effect in effects],
    }
    mandate_id = "mandate-" + hashlib.sha256(canonical_controller_bytes(seed)).hexdigest()[:32]
    return StudioOllamaV2AuthorizationReview(
        mandate_id=mandate_id,
        operation_id=exact_snapshot.operation_id,
        phase=phase,
        plan_hash=exact_plan.content_hash,
        rollback_plan_hash=None if exact_rollback is None else exact_rollback.content_hash,
        starting_snapshot_hash=exact_snapshot.content_hash,
        starting_cursor=cursor,
        starting_attempt=exact_snapshot.next_attempt,
        ownership_token=exact_plan.ownership_token,
        policy_content_hash=exact_plan.policy_content_hash,
        interpreter_binding_hash=exact_plan.interpreter_binding.content_hash,
        effect_ids=tuple(effect.effect_id for effect in effects),
        effect_hashes=tuple(effect.content_hash for effect in effects),
        impact=_derive_impact(exact_plan, effects, phase),
        _plan_json=_json_text(exact_plan.to_document()),
        _rollback_plan_json=(
            None if exact_rollback is None else _json_text(exact_rollback.to_document())
        ),
        _starting_snapshot_json=_json_text(exact_snapshot.to_document()),
    )


@dataclass(frozen=True, slots=True)
class StudioOllamaV2AuthorizationDecision(_Canonical):
    decision_id: str
    mandate_id: str
    review_hash: str
    reviewer_id: str
    outcome: str
    expires_at_ms: int | None

    def __post_init__(self) -> None:
        reason = "ollama_v2_authorization_decision_invalid"
        _id(self.decision_id, reason)
        _id(self.mandate_id, reason)
        _hash(self.review_hash, reason)
        if (
            type(self.reviewer_id) is not str
            or self.reviewer_id != _DIRECTOR_ID
            or type(self.outcome) is not str
            or self.outcome not in {"approved", "denied"}
            or (self.outcome == "approved" and self.expires_at_ms is None)
            or (self.outcome == "denied" and self.expires_at_ms is not None)
        ):
            _fail(reason)
        if self.expires_at_ms is not None:
            _int(
                self.expires_at_ms,
                reason,
                minimum=1,
                maximum=9_007_199_254_740_991,
            )

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.studio_ollama_v2_authorization_decision",
            "format_version": _FORMAT_VERSION,
            "decision_id": self.decision_id,
            "mandate_id": self.mandate_id,
            "review_hash": self.review_hash,
            "reviewer_id": self.reviewer_id,
            "outcome": self.outcome,
            "expires_at_ms": self.expires_at_ms,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def create(
        cls,
        review: StudioOllamaV2AuthorizationReview,
        *,
        outcome: object,
        expires_at_ms: object,
    ) -> StudioOllamaV2AuthorizationDecision:
        if type(review) is not StudioOllamaV2AuthorizationReview:
            _fail("ollama_v2_authorization_decision_invalid")
        seed = {
            "mandate_id": review.mandate_id,
            "review_hash": review.content_hash,
            "reviewer_id": _DIRECTOR_ID,
            "outcome": outcome,
            "expires_at_ms": expires_at_ms,
        }
        decision_id = "decision-" + hashlib.sha256(_canonical(seed)).hexdigest()[:32]
        return cls(decision_id=decision_id, **seed)  # type: ignore[arg-type]

    @classmethod
    def from_document(cls, value: object) -> StudioOllamaV2AuthorizationDecision:
        reason = "ollama_v2_authorization_decision_invalid"
        keys = frozenset(
            {
                "format",
                "format_version",
                "decision_id",
                "mandate_id",
                "review_hash",
                "reviewer_id",
                "outcome",
                "expires_at_ms",
                "content_hash",
            }
        )
        checked = _expect(
            value,
            keys=keys,
            format_name="world-forge.private.studio_ollama_v2_authorization_decision",
            reason=reason,
        )
        try:
            result = cls(
                **{key: checked[key] for key in keys - {"format", "format_version", "content_hash"}}
            )  # type: ignore[arg-type]
        except TypeError:
            _fail(reason)
        seed = {
            "mandate_id": result.mandate_id,
            "review_hash": result.review_hash,
            "reviewer_id": result.reviewer_id,
            "outcome": result.outcome,
            "expires_at_ms": result.expires_at_ms,
        }
        expected_id = "decision-" + hashlib.sha256(_canonical(seed)).hexdigest()[:32]
        if result.decision_id != expected_id:
            _fail(reason)
        return result


@dataclass(frozen=True, slots=True)
class StudioOllamaV2AuthorizationSnapshot:
    review: StudioOllamaV2AuthorizationReview
    decision: StudioOllamaV2AuthorizationDecision | None
    generation: int
    durable_state: str
    consumed_slots: int
    total_slots: int
    status: str
    next_effect_id: str | None

    def __post_init__(self) -> None:
        reason = "ollama_v2_authorization_snapshot_invalid"
        _int(self.generation, reason, maximum=2)
        _int(self.total_slots, reason, minimum=1, maximum=32)
        _int(self.consumed_slots, reason, maximum=self.total_slots)
        if (
            type(self.review) is not StudioOllamaV2AuthorizationReview
            or (
                self.decision is not None
                and type(self.decision) is not StudioOllamaV2AuthorizationDecision
            )
            or type(self.durable_state) is not str
            or self.durable_state
            not in {"prepared", "approved", "denied", "revoked", "expired"}
            or type(self.status) is not str
            or self.status
            not in {"prepared", "denied", "revoked", "expired", "exhausted", "consumable"}
            or self.total_slots != len(self.review.effect_ids)
        ):
            _fail(reason)
        if self.next_effect_id is not None:
            _id(self.next_effect_id, reason)
        expected_generation = {
            "prepared": 0,
            "approved": 1,
            "denied": 1,
            "revoked": 2,
            "expired": 2,
        }[self.durable_state]
        if (
            self.generation != expected_generation
            or (self.durable_state == "prepared" and self.decision is not None)
            or (self.durable_state != "prepared" and self.decision is None)
            or (
                self.decision is not None
                and (
                    self.decision.mandate_id != self.review.mandate_id
                    or self.decision.review_hash != self.review.content_hash
                    or (
                        self.durable_state in {"approved", "revoked", "expired"}
                        and self.decision.outcome != "approved"
                    )
                    or (self.durable_state == "denied" and self.decision.outcome != "denied")
                )
            )
            or (
                self.durable_state == "prepared"
                and (self.status != "prepared" or self.consumed_slots != 0)
            )
            or (
                self.durable_state == "denied"
                and (self.status != "denied" or self.consumed_slots != 0)
            )
            or (self.durable_state == "revoked" and self.status != "revoked")
            or (self.durable_state == "expired" and self.status != "expired")
            or (
                self.durable_state == "approved"
                and self.status not in {"expired", "exhausted", "consumable"}
            )
            or (self.status == "exhausted" and self.consumed_slots != self.total_slots)
            or (
                self.status in {"consumable", "expired"} and self.consumed_slots >= self.total_slots
            )
        ):
            _fail(reason)
        expected_next = (
            self.review.effect_ids[self.consumed_slots] if self.status == "consumable" else None
        )
        if self.next_effect_id != expected_next:
            _fail(reason)

    def to_document(self) -> dict[str, object]:
        return {
            "review": self.review.to_document(),
            "decision": None if self.decision is None else self.decision.to_document(),
            "generation": self.generation,
            "durable_state": self.durable_state,
            "consumed_slots": self.consumed_slots,
            "total_slots": self.total_slots,
            "status": self.status,
            "next_effect_id": self.next_effect_id,
        }


@dataclass(frozen=True, slots=True)
class StudioOllamaV2AuthorizationEventEvidence:
    event_id: int
    mandate_id: str
    generation: int
    event_type: str
    slot_ordinal: int | None
    content_hash: str
    previous_hash: str
    mac: bytes
    created_at: str

    def __post_init__(self) -> None:
        reason = "ollama_v2_authorization_event_invalid"
        _int(self.event_id, reason, minimum=1)
        _id(self.mandate_id, reason)
        _int(self.generation, reason, maximum=2)
        if type(self.event_type) is not str or self.event_type not in {
            "prepared",
            "decided",
            "revoked",
            "consumed",
            "rejected",
        }:
            _fail(reason)
        if self.slot_ordinal is not None:
            _int(self.slot_ordinal, reason, maximum=31)
        _hash(self.content_hash, reason)
        _hash(self.previous_hash, reason)
        expected_generation = {
            "prepared": 0,
            "decided": 1,
            "consumed": 1,
            "revoked": 2,
            "rejected": 2,
        }[self.event_type]
        if (
            self.generation != expected_generation
            or (self.event_type in {"consumed", "rejected"})
            != (self.slot_ordinal is not None)
            or type(self.mac) is not bytes
            or len(self.mac) != 32
        ):
            _fail(reason)
        _timestamp(self.created_at, reason)


def exact_authorization_request(value: object) -> AuthorizationRequest:
    if type(value) is not AuthorizationRequest:
        _fail("ollama_v2_authorization_request_invalid")
    try:
        return AuthorizationRequest.from_document(value.to_document())
    except ControllerContractError:
        _fail("ollama_v2_authorization_request_invalid")


def exact_authorization_consumption(value: object) -> AuthorizationConsumption:
    if type(value) is not AuthorizationConsumption:
        _fail("ollama_v2_authorization_consumption_invalid")
    try:
        return AuthorizationConsumption.from_document(value.to_document())
    except ControllerContractError:
        _fail("ollama_v2_authorization_consumption_invalid")


def exact_authorization_outcome(value: object) -> AuthorizationOutcome:
    if type(value) is AuthorizationConsumption:
        return exact_authorization_consumption(value)
    if type(value) is AuthorizationRejection:
        try:
            return AuthorizationRejection.from_document(value.to_document())
        except ControllerContractError:
            _fail("ollama_v2_authorization_outcome_invalid")
    _fail("ollama_v2_authorization_outcome_invalid")


__all__ = (
    "StudioOllamaV2AuthorizationContractError",
    "StudioOllamaV2AuthorizationDecision",
    "StudioOllamaV2AuthorizationEventEvidence",
    "StudioOllamaV2AuthorizationImpact",
    "StudioOllamaV2AuthorizationReview",
    "StudioOllamaV2AuthorizationSnapshot",
    "build_ollama_v2_authorization_review",
    "exact_authorization_outcome",
)
