"""Private, pure-Python contracts for a future Ollama v2 native boundary.

Nothing in this module performs installation, custody, dispatch, mutation,
manager reload, provider execution, or host observation.  Every native-facing
claim is deliberately fixed to unavailable and unverified for the D2.1a
contract-only slice.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, fields

from .ollama_v2_controller_contracts import (
    APPLY_EFFECT_KINDS,
    CONTROLLER_ACCOUNT,
    CONTROLLER_GID,
    CONTROLLER_GROUP,
    CONTROLLER_POLICY_CONTENT_HASH,
    CONTROLLER_POLICY_SERIALIZED_SHA256,
    CONTROLLER_UID,
    INTERPRETER_PATH,
    MANAGED_ROOT,
    MODEL_FINAL_ROOT,
    MODEL_STAGE_ROOT,
    RELEASE_FINAL_ROOT,
    RELEASE_STAGE_ROOT,
    ROLLBACK_EFFECT_KINDS,
    SERVICE_UNIT_NAME,
    SOCKET_UNIT_NAME,
    UNIT_DIRECTORY,
    AuthorizationConsumption,
    AuthorizationRequest,
    BoundedTreeManifest,
    ControllerContractError,
    ControllerPlan,
    HostEffect,
    HostSnapshot,
    RollbackPlan,
    canonical_interpreter_binding,
    classify_effect_snapshot,
)

FORMAT_VERSION = 1
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 40
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_LOGICAL_ENTRIES = 4096
MAX_LOGICAL_ENTRY_BYTES = 64 * 1024 * 1024 * 1024
MAX_LOGICAL_BUNDLE_BYTES = 256 * 1024 * 1024 * 1024

CUSTODY_TARGET_ROOT = "/var/lib/worldforge/ollama-evidence-v2-custody"
CUSTODY_LEDGER_NAME = "custody-ledger.sqlite3"
CUSTODY_LOCK_NAME = "custody-ledger.lock"
CUSTODY_SCOPE = "ollama_v2_root_global_custody"

DEPLOYMENT_BINDING = "unbound"
ROOT_GLOBAL_ENFORCED = False
SOURCE_CUSTODY_VERIFIED = False
HOST_EXECUTION_ENABLED = False
NATIVE_IMPLEMENTATION_STATE = "absent"
AVAILABILITY = "unavailable"
PRODUCTION_ELIGIBLE = False
CATALOG_ADMITTED = False
PROVIDER_EXECUTION_ENABLED = False

__all__ = (
    "FORMAT_VERSION",
    "CUSTODY_TARGET_ROOT",
    "CUSTODY_LEDGER_NAME",
    "CUSTODY_LOCK_NAME",
    "CUSTODY_SCOPE",
    "DEPLOYMENT_BINDING",
    "ROOT_GLOBAL_ENFORCED",
    "SOURCE_CUSTODY_VERIFIED",
    "HOST_EXECUTION_ENABLED",
    "NATIVE_IMPLEMENTATION_STATE",
    "AVAILABILITY",
    "PRODUCTION_ELIGIBLE",
    "CATALOG_ADMITTED",
    "PROVIDER_EXECUTION_ENABLED",
    "OllamaV2NativeExecutionContractError",
    "OllamaV2NativeResourceScopeD2",
    "OllamaV2NativeExecutionPolicyD2",
    "OllamaV2NativeBundleEntryV1",
    "OllamaV2NativeBundleManifestV1",
    "OllamaV2SourceBundleDescriptorD2",
    "OllamaV2NativeInstallationAttestationD2",
    "OllamaV2NativeExecutionBindingD2",
    "OllamaV2NativeReservationD2",
    "OllamaV2C2AuthorizationReferenceD2",
    "OllamaV2DispatchEnvelopeD2",
    "OllamaV2MutationAckD2",
    "OllamaV2ManagerReloadWitnessD2",
    "OllamaV2CustodyLedgerRecordD2",
    "canonical_ollama_v2_native_execution_bytes",
    "canonical_ollama_v2_native_resource_scope_d2",
    "canonical_ollama_v2_native_execution_policy_d2",
    "parse_ollama_v2_native_execution_contract",
)

_ZERO_HASH = "0" * 64
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9_.:-]{2,127}$")
_EFFECT_KINDS = tuple(dict.fromkeys((*APPLY_EFFECT_KINDS, *ROLLBACK_EFFECT_KINDS)))


class OllamaV2NativeExecutionContractError(ValueError):
    """Raised when one D2.1a contract fails closed validation."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _fail(reason_code: str) -> None:
    raise OllamaV2NativeExecutionContractError(reason_code)


def _require_text(value: object, reason: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        _fail(reason)
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail(reason)
    if unicodedata.normalize("NFC", value) != value:
        _fail(reason)
    return value


def _require_id(value: object, reason: str) -> str:
    text = _require_text(value, reason)
    if _ID_RE.fullmatch(text) is None:
        _fail(reason)
    return text


def _require_hash(value: object, reason: str, *, allow_zero: bool = False) -> str:
    text = _require_text(value, reason)
    if _HASH_RE.fullmatch(text) is None or (not allow_zero and text == _ZERO_HASH):
        _fail(reason)
    return text


def _require_int(
    value: object,
    reason: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_SAFE_INTEGER,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(reason)
    return value


def _require_bool(value: object, reason: str) -> bool:
    if type(value) is not bool:
        _fail(reason)
    return value


def _copy_json(
    value: object,
    *,
    depth: int = 1,
    active: set[int] | None = None,
) -> object:
    reason = "native_execution_document_invalid"
    if active is None:
        active = set()
    if depth > MAX_JSON_DEPTH:
        _fail(reason)
    if type(value) is dict:
        identity = id(value)
        if identity in active:
            _fail(reason)
        active.add(identity)
        try:
            result: dict[str, object] = {}
            for key, item in dict.items(value):
                checked_key = _require_text(key, reason, allow_empty=True)
                result[checked_key] = _copy_json(
                    item,
                    depth=depth + 1,
                    active=active,
                )
            return result
        finally:
            active.remove(identity)
    if type(value) is list:
        identity = id(value)
        if identity in active:
            _fail(reason)
        active.add(identity)
        try:
            return [
                _copy_json(item, depth=depth + 1, active=active)
                for item in list.__iter__(value)
            ]
        finally:
            active.remove(identity)
    if value is None or type(value) is bool:
        return value
    if type(value) is str:
        return _require_text(value, reason, allow_empty=True)
    if type(value) is int and -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        return value
    _fail(reason)


def canonical_ollama_v2_native_execution_bytes(value: object) -> bytes:
    """Return exact canonical JSON bytes for one safe JSON value."""

    checked = _copy_json(value)
    try:
        encoded = json.dumps(
            checked,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("native_execution_document_invalid")
    if len(encoded) > MAX_DOCUMENT_BYTES:
        _fail("native_execution_document_invalid")
    return encoded


def _document_hash(document: object) -> str:
    checked = _copy_json(document)
    if type(checked) is not dict:
        _fail("native_execution_document_invalid")
    checked.pop("content_hash", None)
    return hashlib.sha256(canonical_ollama_v2_native_execution_bytes(checked)).hexdigest()


def _seal(payload: dict[str, object]) -> dict[str, object]:
    result = dict(payload)
    result["content_hash"] = _document_hash(result)
    return result


def _expect_document(
    value: object,
    *,
    keys: set[str],
    format_name: str,
    reason: str,
) -> dict[str, object]:
    checked = _copy_json(value)
    if (
        type(checked) is not dict
        or set(checked) != keys
        or checked.get("format") != format_name
        or checked.get("format_version") != FORMAT_VERSION
        or type(checked.get("format_version")) is not int
        or type(checked.get("content_hash")) is not str
        or _HASH_RE.fullmatch(str(checked.get("content_hash"))) is None
        or checked.get("content_hash") == _ZERO_HASH
        or _document_hash(checked) != checked["content_hash"]
    ):
        _fail(reason)
    return checked


def _derive_id(prefix: str, payload: dict[str, object]) -> str:
    payload_hash = hashlib.sha256(
        canonical_ollama_v2_native_execution_bytes(payload)
    ).hexdigest()
    return prefix + payload_hash[:32]


class _CanonicalContract:
    __slots__ = ()
    _FORMAT = ""
    _REASON = "native_execution_contract_invalid"
    _TUPLE_FIELDS: frozenset[str] = frozenset()

    def _payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "format": self._FORMAT,
            "format_version": FORMAT_VERSION,
        }
        for field in fields(self):
            value = getattr(self, field.name)
            payload[field.name] = list(value) if field.name in self._TUPLE_FIELDS else value
        return payload

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    def to_bytes(self) -> bytes:
        return canonical_ollama_v2_native_execution_bytes(self.to_document())

    @staticmethod
    def compute_document_hash(document: object) -> str:
        return _document_hash(document)

    @classmethod
    def from_document(cls, value: object):
        field_names = {field.name for field in fields(cls)}
        checked = _expect_document(
            value,
            keys={"format", "format_version", "content_hash", *field_names},
            format_name=cls._FORMAT,
            reason=cls._REASON,
        )
        kwargs = {name: checked[name] for name in field_names}
        for name in cls._TUPLE_FIELDS:
            if type(kwargs[name]) is not list:
                _fail(cls._REASON)
            kwargs[name] = tuple(kwargs[name])
        try:
            result = cls(**kwargs)
        except (TypeError, KeyError):
            _fail(cls._REASON)
        if checked["content_hash"] != result.content_hash:
            _fail(cls._REASON)
        return result


@dataclass(frozen=True, slots=True)
class OllamaV2NativeResourceScopeD2(_CanonicalContract):
    scope_id: str
    custody_target_root: str
    ledger_name: str
    lock_name: str
    controller_managed_root: str
    release_stage_root: str
    release_final_root: str
    model_stage_root: str
    model_final_root: str
    unit_directory: str
    socket_unit_name: str
    service_unit_name: str
    interpreter_path: str
    controller_account: str
    controller_group: str
    controller_uid: int
    controller_gid: int
    effect_kinds: tuple[str, ...]

    _FORMAT = "world-forge.private.ollama_v2_resource_scope_d2"
    _REASON = "resource_scope_d2_invalid"
    _TUPLE_FIELDS = frozenset({"effect_kinds"})

    def __post_init__(self) -> None:
        reason = self._REASON
        expected = {
            "scope_id": CUSTODY_SCOPE,
            "custody_target_root": CUSTODY_TARGET_ROOT,
            "ledger_name": CUSTODY_LEDGER_NAME,
            "lock_name": CUSTODY_LOCK_NAME,
            "controller_managed_root": MANAGED_ROOT,
            "release_stage_root": RELEASE_STAGE_ROOT,
            "release_final_root": RELEASE_FINAL_ROOT,
            "model_stage_root": MODEL_STAGE_ROOT,
            "model_final_root": MODEL_FINAL_ROOT,
            "unit_directory": UNIT_DIRECTORY,
            "socket_unit_name": SOCKET_UNIT_NAME,
            "service_unit_name": SERVICE_UNIT_NAME,
            "interpreter_path": INTERPRETER_PATH,
            "controller_account": CONTROLLER_ACCOUNT,
            "controller_group": CONTROLLER_GROUP,
            "controller_uid": CONTROLLER_UID,
            "controller_gid": CONTROLLER_GID,
            "effect_kinds": _EFFECT_KINDS,
        }
        if type(self.effect_kinds) is not tuple or any(
            type(effect_kind) is not str for effect_kind in self.effect_kinds
        ):
            _fail(reason)
        for name, expected_value in expected.items():
            value = getattr(self, name)
            if type(expected_value) is int:
                _require_int(value, reason)
            elif type(expected_value) is str:
                _require_text(value, reason)
            if value != expected_value:
                _fail(reason)


def canonical_ollama_v2_native_resource_scope_d2() -> OllamaV2NativeResourceScopeD2:
    return OllamaV2NativeResourceScopeD2(
        scope_id=CUSTODY_SCOPE,
        custody_target_root=CUSTODY_TARGET_ROOT,
        ledger_name=CUSTODY_LEDGER_NAME,
        lock_name=CUSTODY_LOCK_NAME,
        controller_managed_root=MANAGED_ROOT,
        release_stage_root=RELEASE_STAGE_ROOT,
        release_final_root=RELEASE_FINAL_ROOT,
        model_stage_root=MODEL_STAGE_ROOT,
        model_final_root=MODEL_FINAL_ROOT,
        unit_directory=UNIT_DIRECTORY,
        socket_unit_name=SOCKET_UNIT_NAME,
        service_unit_name=SERVICE_UNIT_NAME,
        interpreter_path=INTERPRETER_PATH,
        controller_account=CONTROLLER_ACCOUNT,
        controller_group=CONTROLLER_GROUP,
        controller_uid=CONTROLLER_UID,
        controller_gid=CONTROLLER_GID,
        effect_kinds=_EFFECT_KINDS,
    )


@dataclass(frozen=True, slots=True)
class OllamaV2NativeExecutionPolicyD2(_CanonicalContract):
    policy_id: str
    custody_scope: str
    resource_scope_hash: str
    controller_policy_content_hash: str
    controller_policy_serialized_sha256: str
    interpreter_binding_hash: str
    deployment_binding: str
    root_global_enforced: bool
    source_custody_verified: bool
    host_execution_enabled: bool
    native_implementation_state: str
    availability: str
    production_eligible: bool
    catalog_admitted: bool
    provider_execution_enabled: bool

    _FORMAT = "world-forge.private.ollama_v2_native_execution_policy_d2"
    _REASON = "native_execution_policy_d2_invalid"

    def __post_init__(self) -> None:
        reason = self._REASON
        expected = {
            "policy_id": "ollama_v2_native_execution_policy_d2",
            "custody_scope": CUSTODY_SCOPE,
            "resource_scope_hash": canonical_ollama_v2_native_resource_scope_d2().content_hash,
            "controller_policy_content_hash": CONTROLLER_POLICY_CONTENT_HASH,
            "controller_policy_serialized_sha256": CONTROLLER_POLICY_SERIALIZED_SHA256,
            "interpreter_binding_hash": canonical_interpreter_binding().content_hash,
            "deployment_binding": DEPLOYMENT_BINDING,
            "root_global_enforced": ROOT_GLOBAL_ENFORCED,
            "source_custody_verified": SOURCE_CUSTODY_VERIFIED,
            "host_execution_enabled": HOST_EXECUTION_ENABLED,
            "native_implementation_state": NATIVE_IMPLEMENTATION_STATE,
            "availability": AVAILABILITY,
            "production_eligible": PRODUCTION_ELIGIBLE,
            "catalog_admitted": CATALOG_ADMITTED,
            "provider_execution_enabled": PROVIDER_EXECUTION_ENABLED,
        }
        for name, expected_value in expected.items():
            value = getattr(self, name)
            if type(expected_value) is bool:
                _require_bool(value, reason)
            elif type(expected_value) is str:
                _require_text(value, reason)
            if value != expected_value:
                _fail(reason)


def canonical_ollama_v2_native_execution_policy_d2() -> OllamaV2NativeExecutionPolicyD2:
    scope = canonical_ollama_v2_native_resource_scope_d2()
    return OllamaV2NativeExecutionPolicyD2(
        policy_id="ollama_v2_native_execution_policy_d2",
        custody_scope=CUSTODY_SCOPE,
        resource_scope_hash=scope.content_hash,
        controller_policy_content_hash=CONTROLLER_POLICY_CONTENT_HASH,
        controller_policy_serialized_sha256=CONTROLLER_POLICY_SERIALIZED_SHA256,
        interpreter_binding_hash=canonical_interpreter_binding().content_hash,
        deployment_binding=DEPLOYMENT_BINDING,
        root_global_enforced=ROOT_GLOBAL_ENFORCED,
        source_custody_verified=SOURCE_CUSTODY_VERIFIED,
        host_execution_enabled=HOST_EXECUTION_ENABLED,
        native_implementation_state=NATIVE_IMPLEMENTATION_STATE,
        availability=AVAILABILITY,
        production_eligible=PRODUCTION_ELIGIBLE,
        catalog_admitted=CATALOG_ADMITTED,
        provider_execution_enabled=PROVIDER_EXECUTION_ENABLED,
    )


def _validate_logical_path(path: object, reason: str) -> str:
    text = _require_text(path, reason)
    if (
        "\x00" in text
        or "\\" in text
        or text.startswith("/")
        or text.endswith("/")
        or "//" in text
        or len(text.encode("utf-8")) > 4096
    ):
        _fail(reason)
    segments = text.split("/")
    if any(
        segment in {"", ".", ".."} or len(segment.encode("utf-8")) > 255
        for segment in segments
    ):
        _fail(reason)
    return text


@dataclass(frozen=True, slots=True)
class OllamaV2NativeBundleEntryV1:
    logical_path: str
    artifact_role: str
    size_bytes: int
    sha256: str
    executable: bool

    def __post_init__(self) -> None:
        reason = "native_bundle_entry_v1_invalid"
        _validate_logical_path(self.logical_path, reason)
        _require_id(self.artifact_role, reason)
        _require_int(self.size_bytes, reason, maximum=MAX_LOGICAL_ENTRY_BYTES)
        _require_hash(self.sha256, reason)
        _require_bool(self.executable, reason)

    def to_document(self) -> dict[str, object]:
        return {
            "logical_path": self.logical_path,
            "artifact_role": self.artifact_role,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "executable": self.executable,
        }

    @classmethod
    def from_document(cls, value: object) -> OllamaV2NativeBundleEntryV1:
        reason = "native_bundle_entry_v1_invalid"
        checked = _copy_json(value)
        keys = {"logical_path", "artifact_role", "size_bytes", "sha256", "executable"}
        if type(checked) is not dict or set(checked) != keys:
            _fail(reason)
        try:
            return cls(**checked)
        except TypeError:
            _fail(reason)


def _logical_manifest_identity_payload(
    bundle_kind: str,
    entries: tuple[OllamaV2NativeBundleEntryV1, ...],
    logical_identity_only: bool,
    physical_custody_verified: bool,
) -> dict[str, object]:
    return {
        "bundle_kind": bundle_kind,
        "entries": [entry.to_document() for entry in entries],
        "logical_identity_only": logical_identity_only,
        "physical_custody_verified": physical_custody_verified,
    }


@dataclass(frozen=True, slots=True)
class OllamaV2NativeBundleManifestV1(_CanonicalContract):
    manifest_id: str
    bundle_kind: str
    entries: tuple[OllamaV2NativeBundleEntryV1, ...]
    entry_count: int
    total_size_bytes: int
    logical_identity_only: bool
    physical_custody_verified: bool

    _FORMAT = "world-forge.private.ollama_v2_native_bundle_manifest_v1"
    _REASON = "native_bundle_manifest_v1_invalid"

    def __post_init__(self) -> None:
        reason = self._REASON
        _require_id(self.manifest_id, reason)
        if self.bundle_kind != "ollama_v2_native_execution_bundle":
            _fail(reason)
        if type(self.entries) is not tuple or not 1 <= len(self.entries) <= MAX_LOGICAL_ENTRIES:
            _fail(reason)
        if any(type(entry) is not OllamaV2NativeBundleEntryV1 for entry in self.entries):
            _fail(reason)
        ordering = [entry.logical_path.encode("utf-8") for entry in self.entries]
        if ordering != sorted(ordering):
            _fail("native_bundle_manifest_order_invalid")
        folded = [entry.logical_path.casefold() for entry in self.entries]
        if len(folded) != len(set(folded)):
            _fail("native_bundle_manifest_collision")
        calculated_size = sum(entry.size_bytes for entry in self.entries)
        if calculated_size > MAX_LOGICAL_BUNDLE_BYTES:
            _fail(reason)
        _require_int(self.entry_count, reason, maximum=MAX_LOGICAL_ENTRIES)
        _require_int(self.total_size_bytes, reason, maximum=MAX_LOGICAL_BUNDLE_BYTES)
        if self.entry_count != len(self.entries) or self.total_size_bytes != calculated_size:
            _fail(reason)
        if self.logical_identity_only is not True or self.physical_custody_verified is not False:
            _fail(reason)
        _require_bool(self.logical_identity_only, reason)
        _require_bool(self.physical_custody_verified, reason)
        identity = _logical_manifest_identity_payload(
            self.bundle_kind,
            self.entries,
            self.logical_identity_only,
            self.physical_custody_verified,
        )
        if self.manifest_id != _derive_id("manifest-", identity):
            _fail(reason)

    def _payload(self) -> dict[str, object]:
        return {
            "format": self._FORMAT,
            "format_version": FORMAT_VERSION,
            "manifest_id": self.manifest_id,
            "bundle_kind": self.bundle_kind,
            "entries": [entry.to_document() for entry in self.entries],
            "entry_count": self.entry_count,
            "total_size_bytes": self.total_size_bytes,
            "logical_identity_only": self.logical_identity_only,
            "physical_custody_verified": self.physical_custody_verified,
        }

    @classmethod
    def create(
        cls,
        entries: tuple[OllamaV2NativeBundleEntryV1, ...],
    ) -> OllamaV2NativeBundleManifestV1:
        if type(entries) is not tuple or any(
            type(entry) is not OllamaV2NativeBundleEntryV1 for entry in entries
        ):
            _fail(cls._REASON)
        bundle_kind = "ollama_v2_native_execution_bundle"
        logical_identity_only = True
        physical_custody_verified = False
        identity = _logical_manifest_identity_payload(
            bundle_kind,
            entries,
            logical_identity_only,
            physical_custody_verified,
        )
        return cls(
            manifest_id=_derive_id("manifest-", identity),
            bundle_kind=bundle_kind,
            entries=entries,
            entry_count=len(entries),
            total_size_bytes=sum(entry.size_bytes for entry in entries),
            logical_identity_only=logical_identity_only,
            physical_custody_verified=physical_custody_verified,
        )

    @classmethod
    def from_document(cls, value: object) -> OllamaV2NativeBundleManifestV1:
        reason = cls._REASON
        checked = _expect_document(
            value,
            keys={
                "format",
                "format_version",
                "manifest_id",
                "bundle_kind",
                "entries",
                "entry_count",
                "total_size_bytes",
                "logical_identity_only",
                "physical_custody_verified",
                "content_hash",
            },
            format_name=cls._FORMAT,
            reason=reason,
        )
        if type(checked["entries"]) is not list:
            _fail(reason)
        try:
            result = cls(
                manifest_id=checked["manifest_id"],
                bundle_kind=checked["bundle_kind"],
                entries=tuple(
                    OllamaV2NativeBundleEntryV1.from_document(entry)
                    for entry in checked["entries"]
                ),
                entry_count=checked["entry_count"],
                total_size_bytes=checked["total_size_bytes"],
                logical_identity_only=checked["logical_identity_only"],
                physical_custody_verified=checked["physical_custody_verified"],
            )
        except TypeError:
            _fail(reason)
        if checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


@dataclass(frozen=True, slots=True)
class OllamaV2SourceBundleDescriptorD2(_CanonicalContract):
    descriptor_id: str
    source_kind: str
    projected_manifest: BoundedTreeManifest
    projected_manifest_hash: str
    logical_contents_hash: str
    source_label: str
    source_revision: str
    future_receipt_identity_hash: str
    descriptor_authority: str
    source_custody_verified: bool

    _FORMAT = "world-forge.private.ollama_v2_source_bundle_descriptor_d2"
    _REASON = "source_bundle_descriptor_d2_invalid"

    def __post_init__(self) -> None:
        reason = self._REASON
        for value in (
            self.descriptor_id,
            self.source_label,
            self.source_revision,
        ):
            _require_id(value, reason)
        if type(self.projected_manifest) is not BoundedTreeManifest:
            _fail(reason)
        expected_kind = {
            "release_final": "release",
            "model_final": "model",
        }.get(self.projected_manifest.purpose)
        if (
            expected_kind is None
            or self.source_kind != expected_kind
            or self.projected_manifest.ownership_token is not None
        ):
            _fail(reason)
        for entry in self.projected_manifest.entries:
            _require_hash(entry.sha256, reason)
        _require_text(self.source_kind, reason)
        _require_hash(self.projected_manifest_hash, reason)
        _require_hash(self.logical_contents_hash, reason)
        _require_hash(self.future_receipt_identity_hash, reason)
        if (
            self.projected_manifest_hash != self.projected_manifest.content_hash
            or self.logical_contents_hash
            != _source_manifest_logical_contents_hash(self.projected_manifest)
            or self.descriptor_authority != "non_authoritative"
            or self.source_custody_verified is not False
        ):
            _fail(reason)
        _require_text(self.descriptor_authority, reason)
        _require_bool(self.source_custody_verified, reason)
        seed = {
            "source_kind": self.source_kind,
            "projected_manifest": self.projected_manifest.to_document(),
            "projected_manifest_hash": self.projected_manifest_hash,
            "logical_contents_hash": self.logical_contents_hash,
            "source_label": self.source_label,
            "source_revision": self.source_revision,
            "future_receipt_identity_hash": self.future_receipt_identity_hash,
            "descriptor_authority": self.descriptor_authority,
            "source_custody_verified": self.source_custody_verified,
        }
        if self.descriptor_id != _derive_id("source-", seed):
            _fail(reason)

    def _payload(self) -> dict[str, object]:
        return {
            "format": self._FORMAT,
            "format_version": FORMAT_VERSION,
            "descriptor_id": self.descriptor_id,
            "source_kind": self.source_kind,
            "projected_manifest": self.projected_manifest.to_document(),
            "projected_manifest_hash": self.projected_manifest_hash,
            "logical_contents_hash": self.logical_contents_hash,
            "source_label": self.source_label,
            "source_revision": self.source_revision,
            "future_receipt_identity_hash": self.future_receipt_identity_hash,
            "descriptor_authority": self.descriptor_authority,
            "source_custody_verified": self.source_custody_verified,
        }

    @classmethod
    def create(
        cls,
        projected_manifest: BoundedTreeManifest,
        *,
        source_label: str,
        source_revision: str,
        future_receipt_identity_hash: str,
    ) -> OllamaV2SourceBundleDescriptorD2:
        if type(projected_manifest) is not BoundedTreeManifest:
            _fail(cls._REASON)
        source_kind = {
            "release_final": "release",
            "model_final": "model",
        }.get(projected_manifest.purpose)
        if source_kind is None:
            _fail(cls._REASON)
        values = {
            "source_kind": source_kind,
            "projected_manifest": projected_manifest,
            "projected_manifest_hash": projected_manifest.content_hash,
            "logical_contents_hash": _source_manifest_logical_contents_hash(
                projected_manifest
            ),
            "source_label": source_label,
            "source_revision": source_revision,
            "future_receipt_identity_hash": future_receipt_identity_hash,
            "descriptor_authority": "non_authoritative",
            "source_custody_verified": False,
        }
        identity = {
            **values,
            "projected_manifest": projected_manifest.to_document(),
        }
        return cls(descriptor_id=_derive_id("source-", identity), **values)

    @classmethod
    def from_document(cls, value: object) -> OllamaV2SourceBundleDescriptorD2:
        reason = cls._REASON
        checked = _expect_document(
            value,
            keys={
                "format",
                "format_version",
                "descriptor_id",
                "source_kind",
                "projected_manifest",
                "projected_manifest_hash",
                "logical_contents_hash",
                "source_label",
                "source_revision",
                "future_receipt_identity_hash",
                "descriptor_authority",
                "source_custody_verified",
                "content_hash",
            },
            format_name=cls._FORMAT,
            reason=reason,
        )
        try:
            result = cls(
                descriptor_id=checked["descriptor_id"],
                source_kind=checked["source_kind"],
                projected_manifest=BoundedTreeManifest.from_document(
                    checked["projected_manifest"]
                ),
                projected_manifest_hash=checked["projected_manifest_hash"],
                logical_contents_hash=checked["logical_contents_hash"],
                source_label=checked["source_label"],
                source_revision=checked["source_revision"],
                future_receipt_identity_hash=checked["future_receipt_identity_hash"],
                descriptor_authority=checked["descriptor_authority"],
                source_custody_verified=checked["source_custody_verified"],
            )
        except (ControllerContractError, TypeError):
            _fail(reason)
        if checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


def _source_manifest_logical_contents_hash(manifest: BoundedTreeManifest) -> str:
    if type(manifest) is not BoundedTreeManifest:
        _fail("source_bundle_descriptor_d2_invalid")
    projection = {
        "purpose": manifest.purpose,
        "root_mode": manifest.root_mode,
        "uid": manifest.uid,
        "gid": manifest.gid,
        "sealed": manifest.sealed,
        "entries": [entry.to_document() for entry in manifest.entries],
        "entry_count": manifest.entry_count,
        "total_size_bytes": manifest.total_size_bytes,
    }
    return hashlib.sha256(
        canonical_ollama_v2_native_execution_bytes(projection)
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class OllamaV2NativeInstallationAttestationD2(_CanonicalContract):
    attestation_id: str
    resource_scope_hash: str
    policy_hash: str
    native_bundle_manifest_id: str
    native_bundle_manifest_hash: str
    installation_receipt_hash: str
    installed_runtime_bundle_hash: str
    attestation_state: str
    deployment_binding: str
    root_global_enforced: bool
    source_custody_verified: bool
    host_execution_enabled: bool
    native_implementation_state: str
    availability: str
    production_eligible: bool
    catalog_admitted: bool
    provider_execution_enabled: bool

    _FORMAT = "world-forge.private.ollama_v2_native_installation_attestation_d2"
    _REASON = "native_installation_attestation_d2_invalid"

    def __post_init__(self) -> None:
        reason = self._REASON
        for value in (
            self.attestation_id,
            self.native_bundle_manifest_id,
        ):
            _require_id(value, reason)
        for value in (
            self.resource_scope_hash,
            self.policy_hash,
            self.native_bundle_manifest_hash,
            self.installation_receipt_hash,
            self.installed_runtime_bundle_hash,
        ):
            _require_hash(value, reason)
        expected = {
            "resource_scope_hash": canonical_ollama_v2_native_resource_scope_d2().content_hash,
            "policy_hash": canonical_ollama_v2_native_execution_policy_d2().content_hash,
            "attestation_state": "supplied_unverified",
            "deployment_binding": DEPLOYMENT_BINDING,
            "root_global_enforced": ROOT_GLOBAL_ENFORCED,
            "source_custody_verified": SOURCE_CUSTODY_VERIFIED,
            "host_execution_enabled": HOST_EXECUTION_ENABLED,
            "native_implementation_state": NATIVE_IMPLEMENTATION_STATE,
            "availability": AVAILABILITY,
            "production_eligible": PRODUCTION_ELIGIBLE,
            "catalog_admitted": CATALOG_ADMITTED,
            "provider_execution_enabled": PROVIDER_EXECUTION_ENABLED,
        }
        for name, expected_value in expected.items():
            value = getattr(self, name)
            if type(expected_value) is bool:
                _require_bool(value, reason)
            elif type(expected_value) is str:
                _require_text(value, reason)
            if value != expected_value:
                _fail(reason)
        seed = {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name != "attestation_id"
        }
        if self.attestation_id != _derive_id("install-", seed):
            _fail(reason)

    @classmethod
    def create(
        cls,
        resource_scope: OllamaV2NativeResourceScopeD2,
        policy: OllamaV2NativeExecutionPolicyD2,
        native_bundle_manifest: OllamaV2NativeBundleManifestV1,
        *,
        installation_receipt_hash: str,
        installed_runtime_bundle_hash: str,
    ) -> OllamaV2NativeInstallationAttestationD2:
        if (
            type(resource_scope) is not OllamaV2NativeResourceScopeD2
            or resource_scope != canonical_ollama_v2_native_resource_scope_d2()
            or type(policy) is not OllamaV2NativeExecutionPolicyD2
            or policy != canonical_ollama_v2_native_execution_policy_d2()
            or type(native_bundle_manifest) is not OllamaV2NativeBundleManifestV1
        ):
            _fail(cls._REASON)
        values = {
            "resource_scope_hash": resource_scope.content_hash,
            "policy_hash": policy.content_hash,
            "native_bundle_manifest_id": native_bundle_manifest.manifest_id,
            "native_bundle_manifest_hash": native_bundle_manifest.content_hash,
            "installation_receipt_hash": installation_receipt_hash,
            "installed_runtime_bundle_hash": installed_runtime_bundle_hash,
            "attestation_state": "supplied_unverified",
            "deployment_binding": DEPLOYMENT_BINDING,
            "root_global_enforced": ROOT_GLOBAL_ENFORCED,
            "source_custody_verified": SOURCE_CUSTODY_VERIFIED,
            "host_execution_enabled": HOST_EXECUTION_ENABLED,
            "native_implementation_state": NATIVE_IMPLEMENTATION_STATE,
            "availability": AVAILABILITY,
            "production_eligible": PRODUCTION_ELIGIBLE,
            "catalog_admitted": CATALOG_ADMITTED,
            "provider_execution_enabled": PROVIDER_EXECUTION_ENABLED,
        }
        return cls(attestation_id=_derive_id("install-", values), **values)


def _plan_parts(plan: object, reason: str) -> tuple[str, str, str, str, tuple[HostEffect, ...]]:
    if type(plan) is ControllerPlan:
        return "apply", plan.plan_id, plan.content_hash, plan.operation_id, plan.effects
    if type(plan) is RollbackPlan:
        return "rollback", plan.rollback_id, plan.content_hash, plan.operation_id, plan.effects
    _fail(reason)


def _parse_plan_document(
    value: object,
    reason: str,
) -> ControllerPlan | RollbackPlan:
    checked = _copy_json(value)
    if type(checked) is not dict:
        _fail(reason)
    parser = {
        "world-forge.private.ollama_v2_controller_plan": ControllerPlan,
        "world-forge.private.ollama_v2_rollback_plan": RollbackPlan,
    }.get(checked.get("format"))
    if parser is None:
        _fail(reason)
    try:
        return parser.from_document(checked)
    except ControllerContractError:
        _fail(reason)


def _binding_serialized_values(values: dict[str, object]) -> dict[str, object]:
    source = values["source_bundle_descriptor"]
    return {
        "plan": values["plan"].to_document(),  # type: ignore[union-attr]
        "effect": values["effect"].to_document(),  # type: ignore[union-attr]
        "authorization_request": values[
            "authorization_request"
        ].to_document(),  # type: ignore[union-attr]
        "c1_consumption": values["c1_consumption"].to_document(),  # type: ignore[union-attr]
        "before_snapshot": values["before_snapshot"].to_document(),  # type: ignore[union-attr]
        "resource_scope": values["resource_scope"].to_document(),  # type: ignore[union-attr]
        "policy": values["policy"].to_document(),  # type: ignore[union-attr]
        "native_bundle_manifest": values[
            "native_bundle_manifest"
        ].to_document(),  # type: ignore[union-attr]
        "source_bundle_descriptor": (
            None if source is None else source.to_document()  # type: ignore[union-attr]
        ),
        "installation_attestation": values[
            "installation_attestation"
        ].to_document(),  # type: ignore[union-attr]
        "authorization_state": values["authorization_state"],
        "deployment_binding": values["deployment_binding"],
        "root_global_enforced": values["root_global_enforced"],
        "source_custody_verified": values["source_custody_verified"],
        "host_execution_enabled": values["host_execution_enabled"],
        "availability": values["availability"],
        "production_eligible": values["production_eligible"],
    }


@dataclass(frozen=True, slots=True)
class OllamaV2NativeExecutionBindingD2(_CanonicalContract):
    binding_id: str
    plan: ControllerPlan | RollbackPlan
    effect: HostEffect
    authorization_request: AuthorizationRequest
    c1_consumption: AuthorizationConsumption
    before_snapshot: HostSnapshot
    resource_scope: OllamaV2NativeResourceScopeD2
    policy: OllamaV2NativeExecutionPolicyD2
    native_bundle_manifest: OllamaV2NativeBundleManifestV1
    source_bundle_descriptor: OllamaV2SourceBundleDescriptorD2 | None
    installation_attestation: OllamaV2NativeInstallationAttestationD2
    authorization_state: str
    deployment_binding: str
    root_global_enforced: bool
    source_custody_verified: bool
    host_execution_enabled: bool
    availability: str
    production_eligible: bool

    _FORMAT = "world-forge.private.ollama_v2_native_execution_binding_d2"
    _REASON = "native_execution_binding_d2_invalid"

    def __post_init__(self) -> None:
        reason = self._REASON
        _require_id(self.binding_id, reason)
        plan_kind, _, plan_hash, operation_id, effects = _plan_parts(self.plan, reason)
        if (
            type(self.effect) is not HostEffect
            or self.effect not in effects
            or self.effect.phase != plan_kind
            or type(self.authorization_request) is not AuthorizationRequest
            or type(self.c1_consumption) is not AuthorizationConsumption
            or type(self.before_snapshot) is not HostSnapshot
            or type(self.resource_scope) is not OllamaV2NativeResourceScopeD2
            or self.resource_scope != canonical_ollama_v2_native_resource_scope_d2()
            or type(self.policy) is not OllamaV2NativeExecutionPolicyD2
            or self.policy != canonical_ollama_v2_native_execution_policy_d2()
            or type(self.native_bundle_manifest) is not OllamaV2NativeBundleManifestV1
            or type(self.installation_attestation)
            is not OllamaV2NativeInstallationAttestationD2
        ):
            _fail(reason)
        request = self.authorization_request
        if (
            request.operation_id != operation_id
            or request.plan_hash != plan_hash
            or request.effect_id != self.effect.effect_id
            or request.phase != self.effect.phase
            or request.ownership_token != self.plan.ownership_token
            or not self.c1_consumption.matches(request)
            or classify_effect_snapshot(self.before_snapshot, self.effect) != "precondition"
        ):
            _fail(reason)
        _require_hash(
            request.expected_head_hash,
            reason,
            allow_zero=request.expected_sequence == 0,
        )
        if (request.expected_sequence == 0) != (request.expected_head_hash == _ZERO_HASH):
            _fail(reason)
        expected_source_manifest: BoundedTreeManifest | None = None
        if self.effect.kind == "release.stage" and type(self.plan) is ControllerPlan:
            expected_source_manifest = self.plan.release_manifest
        elif self.effect.kind == "model.stage" and type(self.plan) is ControllerPlan:
            expected_source_manifest = self.plan.model_manifest
        if expected_source_manifest is None:
            if self.source_bundle_descriptor is not None:
                _fail(reason)
        elif (
            type(self.source_bundle_descriptor) is not OllamaV2SourceBundleDescriptorD2
            or self.source_bundle_descriptor.projected_manifest != expected_source_manifest
            or self.source_bundle_descriptor.projected_manifest_hash
            != expected_source_manifest.content_hash
            or self.source_bundle_descriptor.logical_contents_hash
            != _source_manifest_logical_contents_hash(expected_source_manifest)
        ):
            _fail(reason)
        installation = self.installation_attestation
        if (
            installation.resource_scope_hash != self.resource_scope.content_hash
            or installation.policy_hash != self.policy.content_hash
            or installation.native_bundle_manifest_id
            != self.native_bundle_manifest.manifest_id
            or installation.native_bundle_manifest_hash
            != self.native_bundle_manifest.content_hash
        ):
            _fail(reason)
        for nested_hash in (
            self.plan.content_hash,
            self.effect.content_hash,
            request.content_hash,
            self.c1_consumption.content_hash,
            self.before_snapshot.content_hash,
            self.resource_scope.content_hash,
            self.policy.content_hash,
            self.native_bundle_manifest.content_hash,
            installation.content_hash,
        ):
            _require_hash(nested_hash, reason)
        if self.source_bundle_descriptor is not None:
            _require_hash(self.source_bundle_descriptor.content_hash, reason)
        expected = {
            "authorization_state": "c1_consumed_c2_required",
            "deployment_binding": DEPLOYMENT_BINDING,
            "root_global_enforced": ROOT_GLOBAL_ENFORCED,
            "source_custody_verified": SOURCE_CUSTODY_VERIFIED,
            "host_execution_enabled": HOST_EXECUTION_ENABLED,
            "availability": AVAILABILITY,
            "production_eligible": PRODUCTION_ELIGIBLE,
        }
        for name, expected_value in expected.items():
            value = getattr(self, name)
            if type(expected_value) is bool:
                _require_bool(value, reason)
            elif type(expected_value) is str:
                _require_text(value, reason)
            if value != expected_value:
                _fail(reason)
        values = {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name != "binding_id"
        }
        seed = _binding_serialized_values(values)
        if self.binding_id != _derive_id("binding-", seed):
            _fail(reason)

    def _payload(self) -> dict[str, object]:
        values = {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name != "binding_id"
        }
        return {
            "format": self._FORMAT,
            "format_version": FORMAT_VERSION,
            "binding_id": self.binding_id,
            **_binding_serialized_values(values),
        }

    @property
    def operation_id(self) -> str:
        return self.plan.operation_id

    @property
    def plan_kind(self) -> str:
        return "apply" if type(self.plan) is ControllerPlan else "rollback"

    @property
    def plan_id(self) -> str:
        return self.plan.plan_id if type(self.plan) is ControllerPlan else self.plan.rollback_id

    @property
    def plan_hash(self) -> str:
        return self.plan.content_hash

    @property
    def ownership_token(self) -> str:
        return self.plan.ownership_token

    @property
    def effect_id(self) -> str:
        return self.effect.effect_id

    @property
    def effect_hash(self) -> str:
        return self.effect.content_hash

    @property
    def effect_kind(self) -> str:
        return self.effect.kind

    @property
    def effect_phase(self) -> str:
        return self.effect.phase

    @property
    def controller_anchor_generation(self) -> int:
        return self.authorization_request.expected_generation

    @property
    def controller_anchor_sequence(self) -> int:
        return self.authorization_request.expected_sequence

    @property
    def controller_anchor_head_hash(self) -> str:
        return self.authorization_request.expected_head_hash

    @property
    def c1_authorization_id(self) -> str:
        return self.authorization_request.authorization_id

    @property
    def c1_request_hash(self) -> str:
        return self.authorization_request.content_hash

    @property
    def c1_consumption_id(self) -> str:
        return self.c1_consumption.consumption_id

    @property
    def c1_consumption_hash(self) -> str:
        return self.c1_consumption.content_hash

    @property
    def c1_authority_id(self) -> str:
        return self.c1_consumption.authority_id

    @property
    def c1_decision_id(self) -> str:
        return self.c1_consumption.decision_id

    @property
    def resource_scope_hash(self) -> str:
        return self.resource_scope.content_hash

    @property
    def policy_hash(self) -> str:
        return self.policy.content_hash

    @property
    def interpreter_binding_hash(self) -> str:
        return self.policy.interpreter_binding_hash

    @property
    def native_bundle_manifest_id(self) -> str:
        return self.native_bundle_manifest.manifest_id

    @property
    def native_bundle_manifest_hash(self) -> str:
        return self.native_bundle_manifest.content_hash

    @property
    def source_kind(self) -> str | None:
        source = self.source_bundle_descriptor
        return None if source is None else source.source_kind

    @property
    def source_bundle_descriptor_id(self) -> str | None:
        source = self.source_bundle_descriptor
        return None if source is None else source.descriptor_id

    @property
    def source_bundle_descriptor_hash(self) -> str | None:
        source = self.source_bundle_descriptor
        return None if source is None else source.content_hash

    @property
    def source_manifest_hash(self) -> str | None:
        source = self.source_bundle_descriptor
        return None if source is None else source.projected_manifest_hash

    @property
    def source_logical_contents_hash(self) -> str | None:
        source = self.source_bundle_descriptor
        return None if source is None else source.logical_contents_hash

    @property
    def source_receipt_identity_hash(self) -> str | None:
        source = self.source_bundle_descriptor
        return None if source is None else source.future_receipt_identity_hash

    @property
    def installation_attestation_id(self) -> str:
        return self.installation_attestation.attestation_id

    @property
    def installation_attestation_hash(self) -> str:
        return self.installation_attestation.content_hash

    @property
    def before_snapshot_id(self) -> str:
        return self.before_snapshot.snapshot_id

    @property
    def before_snapshot_hash(self) -> str:
        return self.before_snapshot.content_hash

    @classmethod
    def create(
        cls,
        *,
        plan: ControllerPlan | RollbackPlan,
        effect: HostEffect,
        authorization_request: AuthorizationRequest,
        c1_consumption: AuthorizationConsumption,
        controller_generation: int,
        controller_sequence: int,
        controller_head_hash: str,
        before_snapshot: HostSnapshot,
        resource_scope: OllamaV2NativeResourceScopeD2,
        policy: OllamaV2NativeExecutionPolicyD2,
        native_bundle_manifest: OllamaV2NativeBundleManifestV1,
        source_bundle_descriptor: OllamaV2SourceBundleDescriptorD2 | None,
        installation_attestation: OllamaV2NativeInstallationAttestationD2,
    ) -> OllamaV2NativeExecutionBindingD2:
        reason = cls._REASON
        plan_kind, _, _, _, effects = _plan_parts(plan, reason)
        _require_int(controller_generation, reason)
        _require_int(controller_sequence, reason)
        _require_hash(
            controller_head_hash,
            reason,
            allow_zero=controller_sequence == 0,
        )
        if (controller_sequence == 0) != (controller_head_hash == _ZERO_HASH):
            _fail(reason)
        if (
            type(effect) is not HostEffect
            or effect not in effects
            or effect.phase != plan_kind
            or type(authorization_request) is not AuthorizationRequest
            or type(c1_consumption) is not AuthorizationConsumption
            or type(before_snapshot) is not HostSnapshot
            or type(resource_scope) is not OllamaV2NativeResourceScopeD2
            or resource_scope != canonical_ollama_v2_native_resource_scope_d2()
            or type(policy) is not OllamaV2NativeExecutionPolicyD2
            or policy != canonical_ollama_v2_native_execution_policy_d2()
            or type(native_bundle_manifest) is not OllamaV2NativeBundleManifestV1
            or type(installation_attestation) is not OllamaV2NativeInstallationAttestationD2
        ):
            _fail(reason)
        if (
            authorization_request.expected_generation != controller_generation
            or authorization_request.expected_sequence != controller_sequence
            or authorization_request.expected_head_hash != controller_head_hash
        ):
            _fail(reason)
        values = {
            "plan": plan,
            "effect": effect,
            "authorization_request": authorization_request,
            "c1_consumption": c1_consumption,
            "before_snapshot": before_snapshot,
            "resource_scope": resource_scope,
            "policy": policy,
            "native_bundle_manifest": native_bundle_manifest,
            "source_bundle_descriptor": source_bundle_descriptor,
            "installation_attestation": installation_attestation,
            "authorization_state": "c1_consumed_c2_required",
            "deployment_binding": DEPLOYMENT_BINDING,
            "root_global_enforced": ROOT_GLOBAL_ENFORCED,
            "source_custody_verified": SOURCE_CUSTODY_VERIFIED,
            "host_execution_enabled": HOST_EXECUTION_ENABLED,
            "availability": AVAILABILITY,
            "production_eligible": PRODUCTION_ELIGIBLE,
        }
        return cls(
            binding_id=_derive_id("binding-", _binding_serialized_values(values)),
            **values,
        )

    @classmethod
    def from_document(cls, value: object) -> OllamaV2NativeExecutionBindingD2:
        reason = cls._REASON
        field_names = {field.name for field in fields(cls)}
        checked = _expect_document(
            value,
            keys={"format", "format_version", "content_hash", *field_names},
            format_name=cls._FORMAT,
            reason=reason,
        )
        try:
            source_document = checked["source_bundle_descriptor"]
            result = cls(
                binding_id=checked["binding_id"],
                plan=_parse_plan_document(checked["plan"], reason),
                effect=HostEffect.from_document(checked["effect"]),
                authorization_request=AuthorizationRequest.from_document(
                    checked["authorization_request"]
                ),
                c1_consumption=AuthorizationConsumption.from_document(
                    checked["c1_consumption"]
                ),
                before_snapshot=HostSnapshot.from_document(checked["before_snapshot"]),
                resource_scope=OllamaV2NativeResourceScopeD2.from_document(
                    checked["resource_scope"]
                ),
                policy=OllamaV2NativeExecutionPolicyD2.from_document(checked["policy"]),
                native_bundle_manifest=OllamaV2NativeBundleManifestV1.from_document(
                    checked["native_bundle_manifest"]
                ),
                source_bundle_descriptor=(
                    None
                    if source_document is None
                    else OllamaV2SourceBundleDescriptorD2.from_document(source_document)
                ),
                installation_attestation=(
                    OllamaV2NativeInstallationAttestationD2.from_document(
                        checked["installation_attestation"]
                    )
                ),
                authorization_state=checked["authorization_state"],
                deployment_binding=checked["deployment_binding"],
                root_global_enforced=checked["root_global_enforced"],
                source_custody_verified=checked["source_custody_verified"],
                host_execution_enabled=checked["host_execution_enabled"],
                availability=checked["availability"],
                production_eligible=checked["production_eligible"],
            )
        except ControllerContractError:
            _fail(reason)
        if checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


def _reservation_identity(values: dict[str, object]) -> str:
    return _derive_id("reservation-", values)


def _fence_identity(reservation_id: str, values: dict[str, object]) -> str:
    return hashlib.sha256(
        canonical_ollama_v2_native_execution_bytes(
            {"reservation_id": reservation_id, **values}
        )
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class OllamaV2NativeReservationD2(_CanonicalContract):
    reservation_id: str
    custody_scope: str
    execution_binding_hash: str
    fence_generation: int
    previous_fence_sequence: int
    fence_sequence: int
    previous_fence_hash: str
    fence_hash: str
    reservation_state: str
    root_global_enforced: bool
    host_execution_enabled: bool

    _FORMAT = "world-forge.private.ollama_v2_native_reservation_d2"
    _REASON = "native_reservation_d2_invalid"

    def __post_init__(self) -> None:
        reason = self._REASON
        _require_id(self.reservation_id, reason)
        for value in (self.execution_binding_hash, self.fence_hash):
            _require_hash(value, reason)
        if self.custody_scope != CUSTODY_SCOPE:
            _fail(reason)
        _require_text(self.custody_scope, reason)
        _require_int(self.fence_generation, reason, minimum=1)
        _require_int(
            self.previous_fence_sequence,
            reason,
            maximum=MAX_SAFE_INTEGER - 1,
        )
        _require_int(self.fence_sequence, reason, minimum=1)
        _require_hash(self.previous_fence_hash, reason, allow_zero=True)
        if self.fence_sequence != self.previous_fence_sequence + 1:
            _fail(reason)
        if (self.previous_fence_sequence == 0) != (self.previous_fence_hash == _ZERO_HASH):
            _fail(reason)
        if (
            self.reservation_state != "held_unverified"
            or self.root_global_enforced is not False
            or self.host_execution_enabled is not False
        ):
            _fail(reason)
        _require_bool(self.root_global_enforced, reason)
        _require_bool(self.host_execution_enabled, reason)
        identity = {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name not in {"reservation_id", "fence_hash"}
        }
        expected_id = _reservation_identity(identity)
        if self.reservation_id != expected_id:
            _fail(reason)
        if self.fence_hash != _fence_identity(expected_id, identity):
            _fail(reason)

    @classmethod
    def create(
        cls,
        execution_binding: OllamaV2NativeExecutionBindingD2,
        *,
        fence_generation: int,
        previous_fence_sequence: int,
        previous_fence_hash: str,
    ) -> OllamaV2NativeReservationD2:
        if type(execution_binding) is not OllamaV2NativeExecutionBindingD2:
            _fail(cls._REASON)
        _require_int(
            previous_fence_sequence,
            cls._REASON,
            maximum=MAX_SAFE_INTEGER - 1,
        )
        identity = {
            "custody_scope": CUSTODY_SCOPE,
            "execution_binding_hash": execution_binding.content_hash,
            "fence_generation": fence_generation,
            "previous_fence_sequence": previous_fence_sequence,
            "fence_sequence": previous_fence_sequence + 1,
            "previous_fence_hash": previous_fence_hash,
            "reservation_state": "held_unverified",
            "root_global_enforced": ROOT_GLOBAL_ENFORCED,
            "host_execution_enabled": HOST_EXECUTION_ENABLED,
        }
        reservation_id = _reservation_identity(identity)
        return cls(
            reservation_id=reservation_id,
            fence_hash=_fence_identity(reservation_id, identity),
            **identity,
        )


@dataclass(frozen=True, slots=True)
class OllamaV2C2AuthorizationReferenceD2(_CanonicalContract):
    reference_id: str
    execution_binding_hash: str
    reservation_hash: str
    review_id: str
    review_hash: str
    decision_id: str
    decision_hash: str
    consumption_id: str
    consumption_hash: str
    terminal_decision: str
    single_use: bool
    reference_state: str

    _FORMAT = "world-forge.private.ollama_v2_c2_authorization_reference_d2"
    _REASON = "c2_authorization_reference_d2_invalid"

    def __post_init__(self) -> None:
        reason = self._REASON
        for value in (
            self.reference_id,
            self.review_id,
            self.decision_id,
            self.consumption_id,
        ):
            _require_id(value, reason)
        for value in (
            self.execution_binding_hash,
            self.reservation_hash,
            self.review_hash,
            self.decision_hash,
            self.consumption_hash,
        ):
            _require_hash(value, reason, allow_zero=False)
        if (
            self.terminal_decision != "authorized"
            or self.single_use is not True
            or self.reference_state != "studio_store_required"
        ):
            _fail(reason)
        _require_bool(self.single_use, reason)
        seed = {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name != "reference_id"
        }
        if self.reference_id != _derive_id("c2ref-", seed):
            _fail(reason)

    @classmethod
    def create(
        cls,
        execution_binding: OllamaV2NativeExecutionBindingD2,
        reservation: OllamaV2NativeReservationD2,
        *,
        review_id: str,
        review_hash: str,
        decision_id: str,
        decision_hash: str,
        consumption_id: str,
        consumption_hash: str,
    ) -> OllamaV2C2AuthorizationReferenceD2:
        if (
            type(execution_binding) is not OllamaV2NativeExecutionBindingD2
            or type(reservation) is not OllamaV2NativeReservationD2
            or reservation.execution_binding_hash != execution_binding.content_hash
        ):
            _fail(cls._REASON)
        values = {
            "execution_binding_hash": execution_binding.content_hash,
            "reservation_hash": reservation.content_hash,
            "review_id": review_id,
            "review_hash": review_hash,
            "decision_id": decision_id,
            "decision_hash": decision_hash,
            "consumption_id": consumption_id,
            "consumption_hash": consumption_hash,
            "terminal_decision": "authorized",
            "single_use": True,
            "reference_state": "studio_store_required",
        }
        return cls(reference_id=_derive_id("c2ref-", values), **values)


def _dispatch_serialized_values(values: dict[str, object]) -> dict[str, object]:
    return {
        "execution_binding": values["execution_binding"].to_document(),  # type: ignore[union-attr]
        "reservation": values["reservation"].to_document(),  # type: ignore[union-attr]
        "c2_authorization": values["c2_authorization"].to_document(),  # type: ignore[union-attr]
        "current_controller_generation": values["current_controller_generation"],
        "current_controller_sequence": values["current_controller_sequence"],
        "current_controller_head_hash": values["current_controller_head_hash"],
        "authorization_state": values["authorization_state"],
        "deployment_binding": values["deployment_binding"],
        "root_global_enforced": values["root_global_enforced"],
        "source_custody_verified": values["source_custody_verified"],
        "host_execution_enabled": values["host_execution_enabled"],
        "availability": values["availability"],
        "production_eligible": values["production_eligible"],
    }


@dataclass(frozen=True, slots=True)
class OllamaV2DispatchEnvelopeD2(_CanonicalContract):
    dispatch_id: str
    execution_binding: OllamaV2NativeExecutionBindingD2
    reservation: OllamaV2NativeReservationD2
    c2_authorization: OllamaV2C2AuthorizationReferenceD2
    current_controller_generation: int
    current_controller_sequence: int
    current_controller_head_hash: str
    authorization_state: str
    deployment_binding: str
    root_global_enforced: bool
    source_custody_verified: bool
    host_execution_enabled: bool
    availability: str
    production_eligible: bool

    _FORMAT = "world-forge.private.ollama_v2_dispatch_envelope_d2"
    _REASON = "dispatch_envelope_d2_invalid"

    def __post_init__(self) -> None:
        reason = self._REASON
        _require_id(self.dispatch_id, reason)
        if (
            type(self.execution_binding) is not OllamaV2NativeExecutionBindingD2
            or type(self.reservation) is not OllamaV2NativeReservationD2
            or type(self.c2_authorization)
            is not OllamaV2C2AuthorizationReferenceD2
            or self.reservation.execution_binding_hash
            != self.execution_binding.content_hash
            or self.c2_authorization.execution_binding_hash
            != self.execution_binding.content_hash
            or self.c2_authorization.reservation_hash != self.reservation.content_hash
        ):
            _fail(reason)
        for nested_hash in (
            self.execution_binding.content_hash,
            self.reservation.content_hash,
            self.c2_authorization.content_hash,
        ):
            _require_hash(nested_hash, reason)
        _require_int(self.current_controller_generation, reason)
        _require_int(self.current_controller_sequence, reason)
        _require_hash(
            self.current_controller_head_hash,
            reason,
            allow_zero=self.current_controller_sequence == 0,
        )
        if (self.current_controller_sequence == 0) != (
            self.current_controller_head_hash == _ZERO_HASH
        ):
            _fail(reason)
        if (
            self.current_controller_generation
            < self.execution_binding.controller_anchor_generation
            or (
                self.current_controller_generation
                == self.execution_binding.controller_anchor_generation
                and self.current_controller_sequence
                < self.execution_binding.controller_anchor_sequence
            )
        ):
            _fail("dispatch_controller_anchor_regressed")
        expected = {
            "authorization_state": "c1_and_c2_terminal_consumed",
            "deployment_binding": DEPLOYMENT_BINDING,
            "root_global_enforced": ROOT_GLOBAL_ENFORCED,
            "source_custody_verified": SOURCE_CUSTODY_VERIFIED,
            "host_execution_enabled": HOST_EXECUTION_ENABLED,
            "availability": AVAILABILITY,
            "production_eligible": PRODUCTION_ELIGIBLE,
        }
        for name, expected_value in expected.items():
            value = getattr(self, name)
            if type(expected_value) is bool:
                _require_bool(value, reason)
            else:
                _require_text(value, reason)
            if value != expected_value:
                _fail(reason)
        values = {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name != "dispatch_id"
        }
        if self.dispatch_id != _derive_id(
            "dispatch-", _dispatch_serialized_values(values)
        ):
            _fail(reason)

    def _payload(self) -> dict[str, object]:
        values = {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name != "dispatch_id"
        }
        return {
            "format": self._FORMAT,
            "format_version": FORMAT_VERSION,
            "dispatch_id": self.dispatch_id,
            **_dispatch_serialized_values(values),
        }

    @property
    def execution_binding_id(self) -> str:
        return self.execution_binding.binding_id

    @property
    def execution_binding_hash(self) -> str:
        return self.execution_binding.content_hash

    @property
    def reservation_id(self) -> str:
        return self.reservation.reservation_id

    @property
    def reservation_hash(self) -> str:
        return self.reservation.content_hash

    @property
    def fence_generation(self) -> int:
        return self.reservation.fence_generation

    @property
    def fence_sequence(self) -> int:
        return self.reservation.fence_sequence

    @property
    def fence_hash(self) -> str:
        return self.reservation.fence_hash

    @property
    def operation_id(self) -> str:
        return self.execution_binding.operation_id

    @property
    def plan_id(self) -> str:
        return self.execution_binding.plan_id

    @property
    def plan_hash(self) -> str:
        return self.execution_binding.plan_hash

    @property
    def effect_id(self) -> str:
        return self.execution_binding.effect_id

    @property
    def effect_hash(self) -> str:
        return self.execution_binding.effect_hash

    @property
    def effect_kind(self) -> str:
        return self.execution_binding.effect_kind

    @property
    def binding_controller_generation(self) -> int:
        return self.execution_binding.controller_anchor_generation

    @property
    def binding_controller_sequence(self) -> int:
        return self.execution_binding.controller_anchor_sequence

    @property
    def binding_controller_head_hash(self) -> str:
        return self.execution_binding.controller_anchor_head_hash

    @property
    def c1_consumption_id(self) -> str:
        return self.execution_binding.c1_consumption_id

    @property
    def c1_consumption_hash(self) -> str:
        return self.execution_binding.c1_consumption_hash

    @property
    def c2_reference_id(self) -> str:
        return self.c2_authorization.reference_id

    @property
    def c2_reference_hash(self) -> str:
        return self.c2_authorization.content_hash

    @property
    def c2_execution_binding_hash(self) -> str:
        return self.c2_authorization.execution_binding_hash

    @property
    def c2_reservation_hash(self) -> str:
        return self.c2_authorization.reservation_hash

    @property
    def c2_review_id(self) -> str:
        return self.c2_authorization.review_id

    @property
    def c2_review_hash(self) -> str:
        return self.c2_authorization.review_hash

    @property
    def c2_decision_id(self) -> str:
        return self.c2_authorization.decision_id

    @property
    def c2_decision_hash(self) -> str:
        return self.c2_authorization.decision_hash

    @property
    def c2_consumption_id(self) -> str:
        return self.c2_authorization.consumption_id

    @property
    def c2_consumption_hash(self) -> str:
        return self.c2_authorization.consumption_hash

    @property
    def resource_scope_hash(self) -> str:
        return self.execution_binding.resource_scope_hash

    @property
    def policy_hash(self) -> str:
        return self.execution_binding.policy_hash

    @property
    def native_bundle_manifest_hash(self) -> str:
        return self.execution_binding.native_bundle_manifest_hash

    @property
    def source_kind(self) -> str | None:
        return self.execution_binding.source_kind

    @property
    def source_bundle_descriptor_id(self) -> str | None:
        return self.execution_binding.source_bundle_descriptor_id

    @property
    def source_bundle_descriptor_hash(self) -> str | None:
        return self.execution_binding.source_bundle_descriptor_hash

    @property
    def source_manifest_hash(self) -> str | None:
        return self.execution_binding.source_manifest_hash

    @property
    def source_logical_contents_hash(self) -> str | None:
        return self.execution_binding.source_logical_contents_hash

    @property
    def source_receipt_identity_hash(self) -> str | None:
        return self.execution_binding.source_receipt_identity_hash

    @property
    def installation_attestation_hash(self) -> str:
        return self.execution_binding.installation_attestation_hash

    @property
    def before_snapshot_hash(self) -> str:
        return self.execution_binding.before_snapshot_hash

    @classmethod
    def create(
        cls,
        execution_binding: OllamaV2NativeExecutionBindingD2,
        reservation: OllamaV2NativeReservationD2,
        c2_authorization: OllamaV2C2AuthorizationReferenceD2 | None,
        *,
        current_controller_generation: int,
        current_controller_sequence: int,
        current_controller_head_hash: str,
    ) -> OllamaV2DispatchEnvelopeD2:
        if c2_authorization is None:
            _fail("dispatch_c2_authorization_missing")
        if (
            type(execution_binding) is not OllamaV2NativeExecutionBindingD2
            or type(reservation) is not OllamaV2NativeReservationD2
            or type(c2_authorization) is not OllamaV2C2AuthorizationReferenceD2
            or reservation.execution_binding_hash != execution_binding.content_hash
            or c2_authorization.execution_binding_hash
            != execution_binding.content_hash
            or c2_authorization.reservation_hash != reservation.content_hash
        ):
            _fail(cls._REASON)
        values = {
            "execution_binding": execution_binding,
            "reservation": reservation,
            "c2_authorization": c2_authorization,
            "current_controller_generation": current_controller_generation,
            "current_controller_sequence": current_controller_sequence,
            "current_controller_head_hash": current_controller_head_hash,
            "authorization_state": "c1_and_c2_terminal_consumed",
            "deployment_binding": DEPLOYMENT_BINDING,
            "root_global_enforced": ROOT_GLOBAL_ENFORCED,
            "source_custody_verified": SOURCE_CUSTODY_VERIFIED,
            "host_execution_enabled": HOST_EXECUTION_ENABLED,
            "availability": AVAILABILITY,
            "production_eligible": PRODUCTION_ELIGIBLE,
        }
        return cls(
            dispatch_id=_derive_id("dispatch-", _dispatch_serialized_values(values)),
            **values,
        )

    @classmethod
    def from_document(cls, value: object) -> OllamaV2DispatchEnvelopeD2:
        reason = cls._REASON
        field_names = {field.name for field in fields(cls)}
        checked = _expect_document(
            value,
            keys={"format", "format_version", "content_hash", *field_names},
            format_name=cls._FORMAT,
            reason=reason,
        )
        try:
            result = cls(
                dispatch_id=checked["dispatch_id"],
                execution_binding=OllamaV2NativeExecutionBindingD2.from_document(
                    checked["execution_binding"]
                ),
                reservation=OllamaV2NativeReservationD2.from_document(
                    checked["reservation"]
                ),
                c2_authorization=OllamaV2C2AuthorizationReferenceD2.from_document(
                    checked["c2_authorization"]
                ),
                current_controller_generation=checked[
                    "current_controller_generation"
                ],
                current_controller_sequence=checked["current_controller_sequence"],
                current_controller_head_hash=checked["current_controller_head_hash"],
                authorization_state=checked["authorization_state"],
                deployment_binding=checked["deployment_binding"],
                root_global_enforced=checked["root_global_enforced"],
                source_custody_verified=checked["source_custody_verified"],
                host_execution_enabled=checked["host_execution_enabled"],
                availability=checked["availability"],
                production_eligible=checked["production_eligible"],
            )
        except OllamaV2NativeExecutionContractError:
            _fail(reason)
        if checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


@dataclass(frozen=True, slots=True)
class OllamaV2MutationAckD2(_CanonicalContract):
    ack_id: str
    dispatch_hash: str
    correlation_hash: str
    acknowledged_at_ms: int
    acknowledgement_kind: str
    native_evidence_verified: bool

    _FORMAT = "world-forge.private.ollama_v2_mutation_ack_d2"
    _REASON = "mutation_ack_d2_invalid"

    def __post_init__(self) -> None:
        reason = self._REASON
        _require_id(self.ack_id, reason)
        for value in (self.dispatch_hash, self.correlation_hash):
            _require_hash(value, reason)
        _require_int(self.acknowledged_at_ms, reason)
        if (
            self.acknowledgement_kind != "correlation_only"
            or self.native_evidence_verified is not False
        ):
            _fail(reason)
        _require_bool(self.native_evidence_verified, reason)
        seed = {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name != "ack_id"
        }
        if self.ack_id != _derive_id("ack-", seed):
            _fail(reason)

    @classmethod
    def create(
        cls,
        dispatch: OllamaV2DispatchEnvelopeD2,
        *,
        correlation_hash: str,
        acknowledged_at_ms: int,
    ) -> OllamaV2MutationAckD2:
        if type(dispatch) is not OllamaV2DispatchEnvelopeD2:
            _fail(cls._REASON)
        values = {
            "dispatch_hash": dispatch.content_hash,
            "correlation_hash": correlation_hash,
            "acknowledged_at_ms": acknowledged_at_ms,
            "acknowledgement_kind": "correlation_only",
            "native_evidence_verified": False,
        }
        return cls(ack_id=_derive_id("ack-", values), **values)


def _witness_serialized_values(values: dict[str, object]) -> dict[str, object]:
    return {
        "dispatch": values["dispatch"].to_document(),  # type: ignore[union-attr]
        "ack": values["ack"].to_document(),  # type: ignore[union-attr]
        "observed_snapshot": values[
            "observed_snapshot"
        ].to_document(),  # type: ignore[union-attr]
        "observed_at_ms": values["observed_at_ms"],
        "manager_observation_hash": values["manager_observation_hash"],
        "witness_kind": values["witness_kind"],
        "pid1_manager_verified": values["pid1_manager_verified"],
        "native_evidence_verified": values["native_evidence_verified"],
    }


@dataclass(frozen=True, slots=True)
class OllamaV2ManagerReloadWitnessD2(_CanonicalContract):
    witness_id: str
    dispatch: OllamaV2DispatchEnvelopeD2
    ack: OllamaV2MutationAckD2
    observed_snapshot: HostSnapshot
    observed_at_ms: int
    manager_observation_hash: str
    witness_kind: str
    pid1_manager_verified: bool
    native_evidence_verified: bool

    _FORMAT = "world-forge.private.ollama_v2_manager_reload_witness_d2"
    _REASON = "manager_reload_witness_d2_invalid"

    def __post_init__(self) -> None:
        reason = self._REASON
        _require_id(self.witness_id, reason)
        if (
            type(self.dispatch) is not OllamaV2DispatchEnvelopeD2
            or self.dispatch.effect_kind != "manager.reload"
            or type(self.ack) is not OllamaV2MutationAckD2
            or self.ack.dispatch_hash != self.dispatch.content_hash
            or type(self.observed_snapshot) is not HostSnapshot
        ):
            _fail(reason)
        for nested_hash in (
            self.dispatch.content_hash,
            self.ack.content_hash,
            self.observed_snapshot.content_hash,
            self.manager_observation_hash,
        ):
            _require_hash(nested_hash, reason)
        _require_int(self.observed_at_ms, reason)
        if (
            self.observed_snapshot.manager_reload_generation
            < self.dispatch.execution_binding.before_snapshot.manager_reload_generation
            or self.witness_kind != "non_native_unverified"
            or self.pid1_manager_verified is not False
            or self.native_evidence_verified is not False
        ):
            _fail(reason)
        _require_bool(self.pid1_manager_verified, reason)
        _require_bool(self.native_evidence_verified, reason)
        values = {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name != "witness_id"
        }
        if self.witness_id != _derive_id(
            "reload-", _witness_serialized_values(values)
        ):
            _fail(reason)

    def _payload(self) -> dict[str, object]:
        values = {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name != "witness_id"
        }
        return {
            "format": self._FORMAT,
            "format_version": FORMAT_VERSION,
            "witness_id": self.witness_id,
            **_witness_serialized_values(values),
        }

    @property
    def execution_binding_hash(self) -> str:
        return self.dispatch.execution_binding_hash

    @property
    def dispatch_id(self) -> str:
        return self.dispatch.dispatch_id

    @property
    def dispatch_hash(self) -> str:
        return self.dispatch.content_hash

    @property
    def reservation_id(self) -> str:
        return self.dispatch.reservation_id

    @property
    def fence_hash(self) -> str:
        return self.dispatch.fence_hash

    @property
    def operation_id(self) -> str:
        return self.dispatch.operation_id

    @property
    def effect_id(self) -> str:
        return self.dispatch.effect_id

    @property
    def effect_hash(self) -> str:
        return self.dispatch.effect_hash

    @property
    def ack_id(self) -> str:
        return self.ack.ack_id

    @property
    def ack_hash(self) -> str:
        return self.ack.content_hash

    @property
    def ack_dispatch_hash(self) -> str:
        return self.ack.dispatch_hash

    @property
    def before_snapshot_hash(self) -> str:
        return self.dispatch.before_snapshot_hash

    @property
    def observed_snapshot_hash(self) -> str:
        return self.observed_snapshot.content_hash

    @property
    def manager_reload_generation_before(self) -> int:
        return self.dispatch.execution_binding.before_snapshot.manager_reload_generation

    @property
    def manager_reload_generation_observed(self) -> int:
        return self.observed_snapshot.manager_reload_generation

    @classmethod
    def create(
        cls,
        execution_binding: OllamaV2NativeExecutionBindingD2,
        dispatch: OllamaV2DispatchEnvelopeD2,
        ack: OllamaV2MutationAckD2,
        *,
        before_snapshot: HostSnapshot,
        observed_snapshot: HostSnapshot,
        observed_at_ms: int,
        manager_observation_hash: str,
    ) -> OllamaV2ManagerReloadWitnessD2:
        if (
            type(execution_binding) is not OllamaV2NativeExecutionBindingD2
            or execution_binding.effect_kind != "manager.reload"
            or type(dispatch) is not OllamaV2DispatchEnvelopeD2
            or dispatch.execution_binding != execution_binding
            or type(ack) is not OllamaV2MutationAckD2
            or ack.dispatch_hash != dispatch.content_hash
            or type(before_snapshot) is not HostSnapshot
            or before_snapshot != execution_binding.before_snapshot
            or type(observed_snapshot) is not HostSnapshot
        ):
            _fail(cls._REASON)
        values = {
            "dispatch": dispatch,
            "ack": ack,
            "observed_snapshot": observed_snapshot,
            "observed_at_ms": observed_at_ms,
            "manager_observation_hash": manager_observation_hash,
            "witness_kind": "non_native_unverified",
            "pid1_manager_verified": False,
            "native_evidence_verified": False,
        }
        return cls(
            witness_id=_derive_id("reload-", _witness_serialized_values(values)),
            **values,
        )

    @classmethod
    def from_document(cls, value: object) -> OllamaV2ManagerReloadWitnessD2:
        reason = cls._REASON
        field_names = {field.name for field in fields(cls)}
        checked = _expect_document(
            value,
            keys={"format", "format_version", "content_hash", *field_names},
            format_name=cls._FORMAT,
            reason=reason,
        )
        try:
            result = cls(
                witness_id=checked["witness_id"],
                dispatch=OllamaV2DispatchEnvelopeD2.from_document(
                    checked["dispatch"]
                ),
                ack=OllamaV2MutationAckD2.from_document(checked["ack"]),
                observed_snapshot=HostSnapshot.from_document(
                    checked["observed_snapshot"]
                ),
                observed_at_ms=checked["observed_at_ms"],
                manager_observation_hash=checked["manager_observation_hash"],
                witness_kind=checked["witness_kind"],
                pid1_manager_verified=checked["pid1_manager_verified"],
                native_evidence_verified=checked["native_evidence_verified"],
            )
        except (OllamaV2NativeExecutionContractError, ControllerContractError):
            _fail(reason)
        if checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


def _ledger_serialized_values(values: dict[str, object]) -> dict[str, object]:
    return {
        "custody_scope": values["custody_scope"],
        "record_generation": values["record_generation"],
        "record_sequence": values["record_sequence"],
        "previous_record_hash": values["previous_record_hash"],
        "dispatch": values["dispatch"].to_document(),  # type: ignore[union-attr]
        "ack": values["ack"].to_document(),  # type: ignore[union-attr]
        "observed_snapshot": values[
            "observed_snapshot"
        ].to_document(),  # type: ignore[union-attr]
        "reload_witness_hash": values["reload_witness_hash"],
        "custody_state": values["custody_state"],
        "root_global_enforced": values["root_global_enforced"],
        "host_execution_enabled": values["host_execution_enabled"],
        "native_outcome_verified": values["native_outcome_verified"],
        "production_eligible": values["production_eligible"],
    }


@dataclass(frozen=True, slots=True)
class OllamaV2CustodyLedgerRecordD2(_CanonicalContract):
    record_id: str
    custody_scope: str
    record_generation: int
    record_sequence: int
    previous_record_hash: str
    dispatch: OllamaV2DispatchEnvelopeD2
    ack: OllamaV2MutationAckD2
    observed_snapshot: HostSnapshot
    reload_witness_hash: str | None
    custody_state: str
    root_global_enforced: bool
    host_execution_enabled: bool
    native_outcome_verified: bool
    production_eligible: bool

    _FORMAT = "world-forge.private.ollama_v2_custody_ledger_record_d2"
    _REASON = "custody_ledger_record_d2_invalid"

    def __post_init__(self) -> None:
        reason = self._REASON
        _require_id(self.record_id, reason)
        _require_text(self.custody_scope, reason)
        if (
            self.custody_scope != CUSTODY_SCOPE
            or type(self.dispatch) is not OllamaV2DispatchEnvelopeD2
            or type(self.ack) is not OllamaV2MutationAckD2
            or self.ack.dispatch_hash != self.dispatch.content_hash
            or type(self.observed_snapshot) is not HostSnapshot
        ):
            _fail(reason)
        for nested_hash in (
            self.dispatch.content_hash,
            self.ack.content_hash,
            self.observed_snapshot.content_hash,
        ):
            _require_hash(nested_hash, reason)
        _require_int(self.record_generation, reason, minimum=1)
        _require_int(self.record_sequence, reason, minimum=1)
        _require_hash(self.previous_record_hash, reason, allow_zero=True)
        reservation = self.dispatch.reservation
        if (
            self.record_generation != reservation.fence_generation
            or self.record_sequence != reservation.fence_sequence
            or self.previous_record_hash != reservation.previous_fence_hash
            or (self.record_sequence == 1)
            != (self.previous_record_hash == _ZERO_HASH)
        ):
            _fail(reason)
        if self.effect_kind == "manager.reload":
            _require_hash(self.reload_witness_hash, reason, allow_zero=False)
        elif self.reload_witness_hash is not None:
            _fail(reason)
        if (
            self.custody_state != "observed_unverified"
            or self.root_global_enforced is not False
            or self.host_execution_enabled is not False
            or self.native_outcome_verified is not False
            or self.production_eligible is not False
        ):
            _fail(reason)
        for value in (
            self.root_global_enforced,
            self.host_execution_enabled,
            self.native_outcome_verified,
            self.production_eligible,
        ):
            _require_bool(value, reason)
        values = {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name != "record_id"
        }
        if self.record_id != _derive_id(
            "record-", _ledger_serialized_values(values)
        ):
            _fail(reason)

    def _payload(self) -> dict[str, object]:
        values = {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name != "record_id"
        }
        return {
            "format": self._FORMAT,
            "format_version": FORMAT_VERSION,
            "record_id": self.record_id,
            **_ledger_serialized_values(values),
        }

    @property
    def execution_binding_id(self) -> str:
        return self.dispatch.execution_binding_id

    @property
    def execution_binding_hash(self) -> str:
        return self.dispatch.execution_binding_hash

    @property
    def reservation_id(self) -> str:
        return self.dispatch.reservation_id

    @property
    def reservation_hash(self) -> str:
        return self.dispatch.reservation_hash

    @property
    def fence_hash(self) -> str:
        return self.dispatch.fence_hash

    @property
    def dispatch_id(self) -> str:
        return self.dispatch.dispatch_id

    @property
    def dispatch_hash(self) -> str:
        return self.dispatch.content_hash

    @property
    def ack_id(self) -> str:
        return self.ack.ack_id

    @property
    def ack_hash(self) -> str:
        return self.ack.content_hash

    @property
    def ack_dispatch_hash(self) -> str:
        return self.ack.dispatch_hash

    @property
    def operation_id(self) -> str:
        return self.dispatch.operation_id

    @property
    def plan_hash(self) -> str:
        return self.dispatch.plan_hash

    @property
    def effect_id(self) -> str:
        return self.dispatch.effect_id

    @property
    def effect_hash(self) -> str:
        return self.dispatch.effect_hash

    @property
    def effect_kind(self) -> str:
        return self.dispatch.effect_kind

    @property
    def c1_consumption_hash(self) -> str:
        return self.dispatch.c1_consumption_hash

    @property
    def c2_consumption_hash(self) -> str:
        return self.dispatch.c2_consumption_hash

    @property
    def before_snapshot_hash(self) -> str:
        return self.dispatch.before_snapshot_hash

    @property
    def observed_snapshot_hash(self) -> str:
        return self.observed_snapshot.content_hash

    @classmethod
    def create(
        cls,
        execution_binding: OllamaV2NativeExecutionBindingD2,
        reservation: OllamaV2NativeReservationD2,
        dispatch: OllamaV2DispatchEnvelopeD2,
        ack: OllamaV2MutationAckD2,
        *,
        observed_snapshot: HostSnapshot,
        reload_witness: OllamaV2ManagerReloadWitnessD2 | None,
    ) -> OllamaV2CustodyLedgerRecordD2:
        if (
            type(execution_binding) is not OllamaV2NativeExecutionBindingD2
            or type(reservation) is not OllamaV2NativeReservationD2
            or type(dispatch) is not OllamaV2DispatchEnvelopeD2
            or dispatch.execution_binding != execution_binding
            or dispatch.reservation != reservation
            or type(ack) is not OllamaV2MutationAckD2
            or ack.dispatch_hash != dispatch.content_hash
            or type(observed_snapshot) is not HostSnapshot
        ):
            _fail(cls._REASON)
        if execution_binding.effect_kind == "manager.reload":
            if (
                type(reload_witness) is not OllamaV2ManagerReloadWitnessD2
                or reload_witness.dispatch != dispatch
                or reload_witness.ack != ack
                or reload_witness.observed_snapshot != observed_snapshot
            ):
                _fail(cls._REASON)
            reload_witness_hash: str | None = reload_witness.content_hash
        else:
            if reload_witness is not None:
                _fail(cls._REASON)
            reload_witness_hash = None
        values = {
            "custody_scope": CUSTODY_SCOPE,
            "record_generation": reservation.fence_generation,
            "record_sequence": reservation.fence_sequence,
            "previous_record_hash": reservation.previous_fence_hash,
            "dispatch": dispatch,
            "ack": ack,
            "observed_snapshot": observed_snapshot,
            "reload_witness_hash": reload_witness_hash,
            "custody_state": "observed_unverified",
            "root_global_enforced": ROOT_GLOBAL_ENFORCED,
            "host_execution_enabled": HOST_EXECUTION_ENABLED,
            "native_outcome_verified": False,
            "production_eligible": PRODUCTION_ELIGIBLE,
        }
        return cls(
            record_id=_derive_id("record-", _ledger_serialized_values(values)),
            **values,
        )

    @classmethod
    def from_document(cls, value: object) -> OllamaV2CustodyLedgerRecordD2:
        reason = cls._REASON
        field_names = {field.name for field in fields(cls)}
        checked = _expect_document(
            value,
            keys={"format", "format_version", "content_hash", *field_names},
            format_name=cls._FORMAT,
            reason=reason,
        )
        try:
            result = cls(
                record_id=checked["record_id"],
                custody_scope=checked["custody_scope"],
                record_generation=checked["record_generation"],
                record_sequence=checked["record_sequence"],
                previous_record_hash=checked["previous_record_hash"],
                dispatch=OllamaV2DispatchEnvelopeD2.from_document(
                    checked["dispatch"]
                ),
                ack=OllamaV2MutationAckD2.from_document(checked["ack"]),
                observed_snapshot=HostSnapshot.from_document(
                    checked["observed_snapshot"]
                ),
                reload_witness_hash=checked["reload_witness_hash"],
                custody_state=checked["custody_state"],
                root_global_enforced=checked["root_global_enforced"],
                host_execution_enabled=checked["host_execution_enabled"],
                native_outcome_verified=checked["native_outcome_verified"],
                production_eligible=checked["production_eligible"],
            )
        except (OllamaV2NativeExecutionContractError, ControllerContractError):
            _fail(reason)
        if checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


def _reject_json_number(_: str) -> object:
    _fail("native_execution_json_noncanonical")


def _reject_json_constant(_: str) -> object:
    _fail("native_execution_json_noncanonical")


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("native_execution_json_duplicate_key")
        result[key] = value
    return result


def _decode_canonical_document(value: object) -> dict[str, object]:
    if type(value) is not bytes or not value or len(value) > MAX_DOCUMENT_BYTES:
        _fail("native_execution_json_invalid")
    try:
        text = value.decode("utf-8")
        document = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_constant,
        )
    except OllamaV2NativeExecutionContractError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError):
        _fail("native_execution_json_invalid")
    checked = _copy_json(document)
    if type(checked) is not dict or canonical_ollama_v2_native_execution_bytes(checked) != value:
        _fail("native_execution_json_noncanonical")
    return checked


def parse_ollama_v2_native_execution_contract(value: object) -> _CanonicalContract:
    """Parse one exact canonical D2.1a document without format coercion."""

    document = _decode_canonical_document(value)
    format_name = document.get("format")
    parsers = {
        OllamaV2NativeResourceScopeD2._FORMAT: OllamaV2NativeResourceScopeD2,
        OllamaV2NativeExecutionPolicyD2._FORMAT: OllamaV2NativeExecutionPolicyD2,
        OllamaV2NativeBundleManifestV1._FORMAT: OllamaV2NativeBundleManifestV1,
        OllamaV2SourceBundleDescriptorD2._FORMAT: OllamaV2SourceBundleDescriptorD2,
        OllamaV2NativeInstallationAttestationD2._FORMAT: OllamaV2NativeInstallationAttestationD2,
        OllamaV2NativeExecutionBindingD2._FORMAT: OllamaV2NativeExecutionBindingD2,
        OllamaV2NativeReservationD2._FORMAT: OllamaV2NativeReservationD2,
        OllamaV2C2AuthorizationReferenceD2._FORMAT: OllamaV2C2AuthorizationReferenceD2,
        OllamaV2DispatchEnvelopeD2._FORMAT: OllamaV2DispatchEnvelopeD2,
        OllamaV2MutationAckD2._FORMAT: OllamaV2MutationAckD2,
        OllamaV2ManagerReloadWitnessD2._FORMAT: OllamaV2ManagerReloadWitnessD2,
        OllamaV2CustodyLedgerRecordD2._FORMAT: OllamaV2CustodyLedgerRecordD2,
    }
    parser = parsers.get(format_name)
    if parser is None:
        _fail("native_execution_format_unknown")
    return parser.from_document(document)
