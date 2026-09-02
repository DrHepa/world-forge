"""Closed private contracts for the non-native Ollama v2 controller core.

The module is deterministic and performs no filesystem, account, service,
socket, network, model, or provider operation.  Its host projections describe
the states a separately implemented interpreter would have to prove.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, replace

from .ollama_v2 import (
    canonical_corrected_evidence_foundation_policy_document,
    canonical_ollama_evidence_bytes,
)

FORMAT_VERSION = 1
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 40
MAX_TREE_ENTRIES = 4096
MAX_ENTRY_BYTES = 64 * 1024 * 1024 * 1024
MAX_TREE_BYTES = 256 * 1024 * 1024 * 1024
MAX_SAFE_INTEGER = 9_007_199_254_740_991

CONTROLLER_UID = 9731
CONTROLLER_GID = 9731
CONTROLLER_ACCOUNT = "worldforge-ollama-evidence"
CONTROLLER_GROUP = "worldforge-ollama-evidence"
MANAGED_ROOT = "/var/lib/worldforge/ollama-evidence-v2"
RELEASE_STAGE_ROOT = f"{MANAGED_ROOT}/staging/release"
RELEASE_FINAL_ROOT = f"{MANAGED_ROOT}/releases/ollama"
MODEL_STAGE_ROOT = f"{MANAGED_ROOT}/staging/model"
MODEL_FINAL_ROOT = f"{MANAGED_ROOT}/models/qwen3.6-27b"
UNIT_DIRECTORY = "/etc/systemd/system"
SOCKET_UNIT_NAME = "worldforge-ollama-evidence.socket"
SERVICE_UNIT_NAME = "worldforge-ollama-evidence.service"
INTERPRETER_PATH = "/usr/libexec/worldforge-ollama-evidence-v2-broker"

SOCKET_UNIT_BYTES = (
    b"[Unit]\n"
    b"Description=World Forge observed Ollama evidence socket (non-production)\n"
    b"\n"
    b"[Socket]\n"
    b"ListenStream=127.0.0.1:11435\n"
    b"FileDescriptorName=ollama-http\n"
    b"SocketUser=worldforge-ollama-evidence\n"
    b"SocketGroup=worldforge-ollama-evidence\n"
    b"SocketMode=0600\n"
    b"Accept=no\n"
    b"\n"
    b"[Install]\n"
    b"WantedBy=sockets.target\n"
)

SERVICE_UNIT_BYTES = (
    b"[Unit]\n"
    b"Description=World Forge observed Ollama evidence service (non-production)\n"
    b"Requires=worldforge-ollama-evidence.socket\n"
    b"After=worldforge-ollama-evidence.socket\n"
    b"\n"
    b"[Service]\n"
    b"Type=simple\n"
    b"User=worldforge-ollama-evidence\n"
    b"Group=worldforge-ollama-evidence\n"
    b"SupplementaryGroups=\n"
    b"ExecStart=/usr/libexec/worldforge-ollama-evidence-v2-broker\n"
    b"StandardInput=fd:ollama-http\n"
    b"Environment=OLLAMA_NO_CLOUD=1\n"
    b"UnsetEnvironment=ALL_PROXY FTP_PROXY HTTPS_PROXY HTTP_PROXY NO_PROXY "
    b"all_proxy ftp_proxy https_proxy http_proxy no_proxy\n"
    b"NoNewPrivileges=yes\n"
    b"PrivateDevices=yes\n"
    b"DevicePolicy=closed\n"
    b"RestrictAddressFamilies=AF_UNIX AF_INET\n"
    b"ProtectSystem=strict\n"
    b"ProtectHome=yes\n"
    b"ReadWritePaths=/var/lib/worldforge/ollama-evidence-v2\n"
)

INTERPRETER_CONTRACT_BYTES = (
    b"world-forge.private.ollama-v2-controller-interpreter\n"
    b"revision=1\n"
    b"authority=closed-effect-methods-only\n"
    b"native-implementation=absent\n"
)

_FOUNDATION_POLICY = canonical_corrected_evidence_foundation_policy_document()
CONTROLLER_POLICY_CONTENT_HASH = str(_FOUNDATION_POLICY["content_hash"])
CONTROLLER_POLICY_SERIALIZED_SHA256 = hashlib.sha256(
    canonical_ollama_evidence_bytes(_FOUNDATION_POLICY)
).hexdigest()

APPLY_EFFECT_KINDS = (
    "managed_root.create",
    "principal.create_exact",
    "release.stage",
    "release.publish",
    "model.stage",
    "model.publish",
    "socket.install",
    "service.install",
    "manager.reload",
)
ROLLBACK_EFFECT_KINDS = (
    "service.remove_exact",
    "socket.remove_exact",
    "model.unpublish_exact",
    "model.unstage_exact",
    "release.unpublish_exact",
    "release.unstage_exact",
    "principal.remove_exact",
    "managed_root.remove_exact",
    "manager.reload",
)
EFFECT_KINDS = tuple(dict.fromkeys((*APPLY_EFFECT_KINDS, *ROLLBACK_EFFECT_KINDS)))
INTERPRETER_EFFECT_METHODS = (
    "create_managed_root",
    "create_principal_exact",
    "stage_release",
    "publish_release",
    "stage_model",
    "publish_model",
    "install_socket_unit",
    "install_service_unit",
    "reload_manager",
    "remove_service_unit_exact",
    "remove_socket_unit_exact",
    "unpublish_model_exact",
    "unstage_model_exact",
    "unpublish_release_exact",
    "unstage_release_exact",
    "remove_principal_exact",
    "remove_managed_root_exact",
)

_ZERO_HASH = "0" * 64
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9_.:-]{2,127}$")


class ControllerContractError(ValueError):
    """Raised when one closed controller document fails validation."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _fail(reason_code: str) -> None:
    raise ControllerContractError(reason_code)


def _copy_json(value: object, *, depth: int = 1, active: set[int] | None = None) -> object:
    if active is None:
        active = set()
    if depth > MAX_JSON_DEPTH:
        _fail("controller_document_invalid")
    if type(value) is dict:
        identity = id(value)
        if identity in active:
            _fail("controller_document_invalid")
        active.add(identity)
        try:
            result: dict[str, object] = {}
            for key, item in dict.items(value):
                if type(key) is not str:
                    _fail("controller_document_invalid")
                result[key] = _copy_json(item, depth=depth + 1, active=active)
            return result
        finally:
            active.remove(identity)
    if type(value) is list:
        identity = id(value)
        if identity in active:
            _fail("controller_document_invalid")
        active.add(identity)
        try:
            return [
                _copy_json(item, depth=depth + 1, active=active)
                for item in list.__iter__(value)
            ]
        finally:
            active.remove(identity)
    if value is None or type(value) is bool or type(value) is str:
        return value
    if type(value) is int and -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        return value
    _fail("controller_document_invalid")


def canonical_controller_bytes(value: object) -> bytes:
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
        _fail("controller_document_invalid")
    if len(encoded) > MAX_DOCUMENT_BYTES:
        _fail("controller_document_invalid")
    return encoded


def _document_hash(document: object) -> str:
    checked = _copy_json(document)
    if type(checked) is not dict:
        _fail("controller_document_invalid")
    checked.pop("content_hash", None)
    return hashlib.sha256(canonical_controller_bytes(checked)).hexdigest()


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
        or type(checked.get("content_hash")) is not str
        or _HASH_RE.fullmatch(str(checked.get("content_hash"))) is None
        or _document_hash(checked) != checked["content_hash"]
    ):
        _fail(reason)
    return checked


def _require_hash(value: object, reason: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        _fail(reason)
    return value


def _require_id(value: object, reason: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        _fail(reason)
    return value


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


class _CanonicalContract:
    __slots__ = ()

    @staticmethod
    def compute_document_hash(document: object) -> str:
        return _document_hash(document)


@dataclass(frozen=True, slots=True)
class ManifestEntry(_CanonicalContract):
    relative_path: str
    entry_kind: str
    size_bytes: int
    sha256: str
    mode: int
    uid: int
    gid: int
    link_count: int
    writable: bool

    def __post_init__(self) -> None:
        reason = "tree_entry_invalid"
        if type(self.relative_path) is not str or not self.relative_path:
            _fail(reason)
        if self.entry_kind not in {"file", "directory"}:
            _fail(reason)
        _require_int(self.size_bytes, reason, maximum=MAX_ENTRY_BYTES)
        _require_hash(self.sha256, reason)
        _require_int(self.mode, reason, maximum=0o777)
        _require_int(self.uid, reason)
        _require_int(self.gid, reason)
        _require_int(self.link_count, reason, minimum=1, maximum=MAX_SAFE_INTEGER)
        if type(self.writable) is not bool:
            _fail(reason)
        if self.entry_kind == "directory" and (
            self.size_bytes != 0 or self.sha256 != _EMPTY_SHA256
        ):
            _fail(reason)
        if self.writable != bool(self.mode & 0o222):
            _fail(reason)

    def to_document(self) -> dict[str, object]:
        return {
            "relative_path": self.relative_path,
            "entry_kind": self.entry_kind,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "link_count": self.link_count,
            "writable": self.writable,
        }

    @classmethod
    def from_document(cls, value: object) -> ManifestEntry:
        checked = _copy_json(value)
        keys = {
            "relative_path",
            "entry_kind",
            "size_bytes",
            "sha256",
            "mode",
            "uid",
            "gid",
            "link_count",
            "writable",
        }
        if type(checked) is not dict or set(checked) != keys:
            _fail("tree_entry_invalid")
        try:
            return cls(**checked)  # type: ignore[arg-type]
        except TypeError:
            _fail("tree_entry_invalid")


_MANIFEST_ROOTS = {
    "managed_root": MANAGED_ROOT,
    "release_stage": RELEASE_STAGE_ROOT,
    "release_final": RELEASE_FINAL_ROOT,
    "model_stage": MODEL_STAGE_ROOT,
    "model_final": MODEL_FINAL_ROOT,
}


def _validate_relative_path(path: str) -> tuple[str, ...]:
    if (
        "\x00" in path
        or "\\" in path
        or path.startswith("/")
        or path.endswith("/")
        or "//" in path
        or unicodedata.normalize("NFC", path) != path
    ):
        _fail("tree_manifest_path_invalid")
    segments = tuple(path.split("/"))
    if not segments or any(segment in {"", ".", ".."} for segment in segments):
        _fail("tree_manifest_path_invalid")
    if any(len(segment.encode("utf-8")) > 255 for segment in segments):
        _fail("tree_manifest_path_invalid")
    return segments


@dataclass(frozen=True, slots=True)
class BoundedTreeManifest(_CanonicalContract):
    purpose: str
    root_path: str
    root_mode: int
    uid: int
    gid: int
    sealed: bool
    entries: tuple[ManifestEntry, ...]
    ownership_token: str | None = None

    def __post_init__(self) -> None:
        reason = "tree_manifest_invalid"
        if type(self.purpose) is not str or self.purpose not in _MANIFEST_ROOTS:
            _fail(reason)
        if type(self.root_path) is not str or self.root_path != _MANIFEST_ROOTS[self.purpose]:
            _fail(reason)
        _require_int(self.root_mode, reason, maximum=0o777)
        _require_int(self.uid, reason)
        _require_int(self.gid, reason)
        if type(self.sealed) is not bool or type(self.entries) is not tuple:
            _fail(reason)
        if self.ownership_token is not None:
            _require_id(self.ownership_token, reason)
        entries = tuple(tuple.__iter__(self.entries))
        if len(entries) > MAX_TREE_ENTRIES or any(
            type(entry) is not ManifestEntry for entry in entries
        ):
            _fail("tree_manifest_bounds_exceeded")
        if sum(entry.size_bytes for entry in entries) > MAX_TREE_BYTES:
            _fail("tree_manifest_bounds_exceeded")
        if self.purpose == "managed_root":
            if self.sealed or entries or self.ownership_token is None:
                _fail(reason)
        else:
            if (
                not self.sealed
                or self.root_mode & 0o222
                or self.uid != CONTROLLER_UID
                or self.gid != CONTROLLER_GID
            ):
                _fail(reason)
        seen: set[str] = set()
        paths: dict[str, ManifestEntry] = {}
        ordering: list[bytes] = []
        for entry in entries:
            segments = _validate_relative_path(entry.relative_path)
            folded = "/".join(segment.casefold() for segment in segments)
            if folded in seen:
                _fail("tree_manifest_collision")
            seen.add(folded)
            paths[entry.relative_path] = entry
            ordering.append(entry.relative_path.encode("utf-8"))
            if entry.link_count != 1:
                _fail("tree_manifest_hardlink_forbidden")
            if self.purpose.endswith("_final") and entry.writable:
                _fail("tree_manifest_writable_final_forbidden")
            if entry.uid != CONTROLLER_UID or entry.gid != CONTROLLER_GID:
                _fail(reason)
        if ordering != sorted(ordering):
            _fail("tree_manifest_order_invalid")
        for path, entry in paths.items():
            segments = path.split("/")
            for index in range(1, len(segments)):
                parent = "/".join(segments[:index])
                parent_entry = paths.get(parent)
                if parent_entry is None or parent_entry.entry_kind != "directory":
                    _fail("tree_manifest_overlap_invalid")
            if entry.entry_kind == "file" and any(
                other.startswith(path + "/") for other in paths if other != path
            ):
                _fail("tree_manifest_overlap_invalid")

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    @property
    def total_size_bytes(self) -> int:
        return sum(entry.size_bytes for entry in self.entries)

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.ollama_v2_tree_manifest",
            "format_version": FORMAT_VERSION,
            "purpose": self.purpose,
            "root_path": self.root_path,
            "root_mode": self.root_mode,
            "uid": self.uid,
            "gid": self.gid,
            "sealed": self.sealed,
            "entries": [entry.to_document() for entry in self.entries],
            "ownership_token": self.ownership_token,
            "entry_count": self.entry_count,
            "total_size_bytes": self.total_size_bytes,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def from_document(cls, value: object) -> BoundedTreeManifest:
        reason = "tree_manifest_invalid"
        checked = _expect_document(
            value,
            keys={
                "format",
                "format_version",
                "purpose",
                "root_path",
                "root_mode",
                "uid",
                "gid",
                "sealed",
                "entries",
                "ownership_token",
                "entry_count",
                "total_size_bytes",
                "content_hash",
            },
            format_name="world-forge.private.ollama_v2_tree_manifest",
            reason=reason,
        )
        if type(checked["entries"]) is not list:
            _fail(reason)
        manifest = cls(
            purpose=checked["purpose"],  # type: ignore[arg-type]
            root_path=checked["root_path"],  # type: ignore[arg-type]
            root_mode=checked["root_mode"],  # type: ignore[arg-type]
            uid=checked["uid"],  # type: ignore[arg-type]
            gid=checked["gid"],  # type: ignore[arg-type]
            sealed=checked["sealed"],  # type: ignore[arg-type]
            entries=tuple(ManifestEntry.from_document(item) for item in checked["entries"]),
            ownership_token=checked["ownership_token"],  # type: ignore[arg-type]
        )
        if (
            checked["entry_count"] != manifest.entry_count
            or checked["total_size_bytes"] != manifest.total_size_bytes
            or checked["content_hash"] != manifest.content_hash
        ):
            _fail(reason)
        return manifest

    def relocated(self, purpose: str) -> BoundedTreeManifest:
        if purpose not in _MANIFEST_ROOTS:
            _fail("tree_manifest_invalid")
        return replace(self, purpose=purpose, root_path=_MANIFEST_ROOTS[purpose])

    def owned(self, purpose: str, ownership_token: str) -> BoundedTreeManifest:
        _require_id(ownership_token, "tree_manifest_invalid")
        if purpose not in _MANIFEST_ROOTS:
            _fail("tree_manifest_invalid")
        return replace(
            self,
            purpose=purpose,
            root_path=_MANIFEST_ROOTS[purpose],
            ownership_token=ownership_token,
        )


@dataclass(frozen=True, slots=True)
class InterpreterBinding(_CanonicalContract):
    interpreter_id: str
    revision: int
    abi: str
    interpreter_path: str
    interpreter_contract_sha256: str
    effect_methods: tuple[str, ...]
    uid: int
    gid: int
    managed_root: str
    unit_directory: str
    socket_unit_sha256: str
    service_unit_sha256: str
    policy_content_hash: str
    policy_serialized_sha256: str
    native_implementation_state: str

    def __post_init__(self) -> None:
        expected = {
            "interpreter_id": "worldforge_ollama_v2_closed_host_effects",
            "revision": 1,
            "abi": "closed-methods-v1",
            "interpreter_path": INTERPRETER_PATH,
            "interpreter_contract_sha256": hashlib.sha256(INTERPRETER_CONTRACT_BYTES).hexdigest(),
            "effect_methods": INTERPRETER_EFFECT_METHODS,
            "uid": CONTROLLER_UID,
            "gid": CONTROLLER_GID,
            "managed_root": MANAGED_ROOT,
            "unit_directory": UNIT_DIRECTORY,
            "socket_unit_sha256": hashlib.sha256(SOCKET_UNIT_BYTES).hexdigest(),
            "service_unit_sha256": hashlib.sha256(SERVICE_UNIT_BYTES).hexdigest(),
            "policy_content_hash": CONTROLLER_POLICY_CONTENT_HASH,
            "policy_serialized_sha256": CONTROLLER_POLICY_SERIALIZED_SHA256,
            "native_implementation_state": "absent",
        }
        for field_name, expected_value in expected.items():
            if getattr(self, field_name) != expected_value:
                _fail("interpreter_binding_invalid")
        if type(self.revision) is not int or type(self.uid) is not int or type(self.gid) is not int:
            _fail("interpreter_binding_invalid")
        if type(self.effect_methods) is not tuple:
            _fail("interpreter_binding_invalid")

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.ollama_v2_interpreter_binding",
            "format_version": FORMAT_VERSION,
            "interpreter_id": self.interpreter_id,
            "revision": self.revision,
            "abi": self.abi,
            "interpreter_path": self.interpreter_path,
            "interpreter_contract_sha256": self.interpreter_contract_sha256,
            "effect_methods": list(self.effect_methods),
            "uid": self.uid,
            "gid": self.gid,
            "managed_root": self.managed_root,
            "unit_directory": self.unit_directory,
            "socket_unit_sha256": self.socket_unit_sha256,
            "service_unit_sha256": self.service_unit_sha256,
            "policy_content_hash": self.policy_content_hash,
            "policy_serialized_sha256": self.policy_serialized_sha256,
            "native_implementation_state": self.native_implementation_state,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def from_document(cls, value: object) -> InterpreterBinding:
        reason = "interpreter_binding_invalid"
        keys = {
            "format",
            "format_version",
            "interpreter_id",
            "revision",
            "abi",
            "interpreter_path",
            "interpreter_contract_sha256",
            "effect_methods",
            "uid",
            "gid",
            "managed_root",
            "unit_directory",
            "socket_unit_sha256",
            "service_unit_sha256",
            "policy_content_hash",
            "policy_serialized_sha256",
            "native_implementation_state",
            "content_hash",
        }
        checked = _expect_document(
            value,
            keys=keys,
            format_name="world-forge.private.ollama_v2_interpreter_binding",
            reason=reason,
        )
        if type(checked["effect_methods"]) is not list:
            _fail(reason)
        try:
            binding = cls(
                interpreter_id=checked["interpreter_id"],  # type: ignore[arg-type]
                revision=checked["revision"],  # type: ignore[arg-type]
                abi=checked["abi"],  # type: ignore[arg-type]
                interpreter_path=checked["interpreter_path"],  # type: ignore[arg-type]
                interpreter_contract_sha256=checked[
                    "interpreter_contract_sha256"
                ],  # type: ignore[arg-type]
                effect_methods=tuple(checked["effect_methods"]),  # type: ignore[arg-type]
                uid=checked["uid"],  # type: ignore[arg-type]
                gid=checked["gid"],  # type: ignore[arg-type]
                managed_root=checked["managed_root"],  # type: ignore[arg-type]
                unit_directory=checked["unit_directory"],  # type: ignore[arg-type]
                socket_unit_sha256=checked["socket_unit_sha256"],  # type: ignore[arg-type]
                service_unit_sha256=checked["service_unit_sha256"],  # type: ignore[arg-type]
                policy_content_hash=checked["policy_content_hash"],  # type: ignore[arg-type]
                policy_serialized_sha256=checked[
                    "policy_serialized_sha256"
                ],  # type: ignore[arg-type]
                native_implementation_state=checked[
                    "native_implementation_state"
                ],  # type: ignore[arg-type]
            )
        except TypeError:
            _fail(reason)
        if checked["content_hash"] != binding.content_hash:
            _fail(reason)
        return binding


def canonical_interpreter_binding() -> InterpreterBinding:
    return InterpreterBinding(
        interpreter_id="worldforge_ollama_v2_closed_host_effects",
        revision=1,
        abi="closed-methods-v1",
        interpreter_path=INTERPRETER_PATH,
        interpreter_contract_sha256=hashlib.sha256(INTERPRETER_CONTRACT_BYTES).hexdigest(),
        effect_methods=INTERPRETER_EFFECT_METHODS,
        uid=CONTROLLER_UID,
        gid=CONTROLLER_GID,
        managed_root=MANAGED_ROOT,
        unit_directory=UNIT_DIRECTORY,
        socket_unit_sha256=hashlib.sha256(SOCKET_UNIT_BYTES).hexdigest(),
        service_unit_sha256=hashlib.sha256(SERVICE_UNIT_BYTES).hexdigest(),
        policy_content_hash=CONTROLLER_POLICY_CONTENT_HASH,
        policy_serialized_sha256=CONTROLLER_POLICY_SERIALIZED_SHA256,
        native_implementation_state="absent",
    )


@dataclass(frozen=True, slots=True)
class PrincipalObservation(_CanonicalContract):
    present: bool
    account: str
    uid: int | None
    gid: int | None
    primary_group: str
    dedicated_non_login: bool
    supplementary_groups: tuple[str, ...]
    owned_by_operation: bool
    uid_owner_account: str | None
    gid_owner_group: str | None
    ownership_token: str | None = None

    def __post_init__(self) -> None:
        reason = "principal_observation_invalid"
        if (
            type(self.present) is not bool
            or self.account != CONTROLLER_ACCOUNT
            or self.primary_group != CONTROLLER_GROUP
            or type(self.dedicated_non_login) is not bool
            or type(self.supplementary_groups) is not tuple
            or type(self.owned_by_operation) is not bool
        ):
            _fail(reason)
        groups = tuple(tuple.__iter__(self.supplementary_groups))
        if any(type(group) is not str or not group for group in groups):
            _fail(reason)
        folded = {group.casefold() for group in groups}
        if len(folded) != len(groups) or folded & {"ollama", "render", "video"}:
            _fail("principal_observation_ambient_resource")
        owners = (self.uid_owner_account, self.gid_owner_group)
        if any(owner is not None and type(owner) is not str for owner in owners):
            _fail(reason)
        if self.ownership_token is not None:
            _require_id(self.ownership_token, reason)
        if self.owned_by_operation != (self.ownership_token is not None):
            _fail(reason)
        owner_names = {
            owner.casefold() for owner in owners if type(owner) is str
        }
        if owner_names & {"ollama", "render", "video"}:
            _fail("principal_observation_ambient_resource")
        if not self.present:
            if (
                self.uid is not None
                or self.gid is not None
                or self.dedicated_non_login
                or groups
                or self.owned_by_operation
            ):
                _fail(reason)
            if self.uid_owner_account == self.account or self.gid_owner_group == self.primary_group:
                _fail(reason)
        else:
            _require_int(self.uid, reason)  # type: ignore[arg-type]
            _require_int(self.gid, reason)  # type: ignore[arg-type]
            if (
                self.uid_owner_account != self.account
                or self.gid_owner_group != self.primary_group
            ):
                _fail(reason)

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.ollama_v2_principal_observation",
            "format_version": FORMAT_VERSION,
            "present": self.present,
            "account": self.account,
            "uid": self.uid,
            "gid": self.gid,
            "primary_group": self.primary_group,
            "dedicated_non_login": self.dedicated_non_login,
            "supplementary_groups": list(self.supplementary_groups),
            "owned_by_operation": self.owned_by_operation,
            "uid_owner_account": self.uid_owner_account,
            "gid_owner_group": self.gid_owner_group,
            "ownership_token": self.ownership_token,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def from_document(cls, value: object) -> PrincipalObservation:
        reason = "principal_observation_invalid"
        checked = _expect_document(
            value,
            keys={
                "format",
                "format_version",
                "present",
                "account",
                "uid",
                "gid",
                "primary_group",
                "dedicated_non_login",
                "supplementary_groups",
                "owned_by_operation",
                "uid_owner_account",
                "gid_owner_group",
                "ownership_token",
                "content_hash",
            },
            format_name="world-forge.private.ollama_v2_principal_observation",
            reason=reason,
        )
        if type(checked["supplementary_groups"]) is not list:
            _fail(reason)
        try:
            result = cls(
                present=checked["present"],  # type: ignore[arg-type]
                account=checked["account"],  # type: ignore[arg-type]
                uid=checked["uid"],  # type: ignore[arg-type]
                gid=checked["gid"],  # type: ignore[arg-type]
                primary_group=checked["primary_group"],  # type: ignore[arg-type]
                dedicated_non_login=checked["dedicated_non_login"],  # type: ignore[arg-type]
                supplementary_groups=tuple(
                    checked["supplementary_groups"]
                ),  # type: ignore[arg-type]
                owned_by_operation=checked["owned_by_operation"],  # type: ignore[arg-type]
                uid_owner_account=checked["uid_owner_account"],  # type: ignore[arg-type]
                gid_owner_group=checked["gid_owner_group"],  # type: ignore[arg-type]
                ownership_token=checked["ownership_token"],  # type: ignore[arg-type]
            )
        except TypeError:
            _fail(reason)
        if checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


def _absent_principal() -> PrincipalObservation:
    return PrincipalObservation(
        present=False,
        account=CONTROLLER_ACCOUNT,
        uid=None,
        gid=None,
        primary_group=CONTROLLER_GROUP,
        dedicated_non_login=False,
        supplementary_groups=(),
        owned_by_operation=False,
        uid_owner_account=None,
        gid_owner_group=None,
    )


@dataclass(frozen=True, slots=True)
class UnitObservation(_CanonicalContract):
    unit_name: str
    present: bool
    content_sha256: str | None
    owned_by_operation: bool
    enabled: bool
    active: bool
    ownership_token: str | None = None

    def __post_init__(self) -> None:
        reason = "unit_observation_invalid"
        if (
            self.unit_name not in {SOCKET_UNIT_NAME, SERVICE_UNIT_NAME}
            or type(self.present) is not bool
            or type(self.owned_by_operation) is not bool
            or type(self.enabled) is not bool
            or type(self.active) is not bool
        ):
            _fail(reason)
        if self.present:
            _require_hash(self.content_sha256, reason)
        elif (
            self.content_sha256 is not None
            or self.owned_by_operation
            or self.enabled
            or self.active
        ):
            _fail(reason)
        if self.ownership_token is not None:
            _require_id(self.ownership_token, reason)
        if self.owned_by_operation != (self.ownership_token is not None):
            _fail(reason)

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.ollama_v2_unit_observation",
            "format_version": FORMAT_VERSION,
            "unit_name": self.unit_name,
            "present": self.present,
            "content_sha256": self.content_sha256,
            "owned_by_operation": self.owned_by_operation,
            "enabled": self.enabled,
            "active": self.active,
            "ownership_token": self.ownership_token,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def from_document(cls, value: object) -> UnitObservation:
        reason = "unit_observation_invalid"
        checked = _expect_document(
            value,
            keys={
                "format",
                "format_version",
                "unit_name",
                "present",
                "content_sha256",
                "owned_by_operation",
                "enabled",
                "active",
                "ownership_token",
                "content_hash",
            },
            format_name="world-forge.private.ollama_v2_unit_observation",
            reason=reason,
        )
        try:
            result = cls(
                unit_name=checked["unit_name"],  # type: ignore[arg-type]
                present=checked["present"],  # type: ignore[arg-type]
                content_sha256=checked["content_sha256"],  # type: ignore[arg-type]
                owned_by_operation=checked["owned_by_operation"],  # type: ignore[arg-type]
                enabled=checked["enabled"],  # type: ignore[arg-type]
                active=checked["active"],  # type: ignore[arg-type]
                ownership_token=checked["ownership_token"],  # type: ignore[arg-type]
            )
        except TypeError:
            _fail(reason)
        if checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


def _absent_unit(name: str) -> UnitObservation:
    return UnitObservation(
        unit_name=name,
        present=False,
        content_sha256=None,
        owned_by_operation=False,
        enabled=False,
        active=False,
    )


@dataclass(frozen=True, slots=True)
class HostSnapshot(_CanonicalContract):
    snapshot_id: str
    observed_generation: int
    policy_content_hash: str
    policy_serialized_sha256: str
    interpreter_binding_hash: str
    managed_root_path: str
    managed_root: BoundedTreeManifest | None
    principal: PrincipalObservation
    release_stage: BoundedTreeManifest | None
    release_final: BoundedTreeManifest | None
    model_stage: BoundedTreeManifest | None
    model_final: BoundedTreeManifest | None
    socket_unit: UnitObservation
    service_unit: UnitObservation
    manager_reload_generation: int
    manager_reload_ownership_token: str | None = None

    def __post_init__(self) -> None:
        reason = "host_snapshot_invalid"
        _require_id(self.snapshot_id, reason)
        _require_int(self.observed_generation, reason)
        _require_hash(self.policy_content_hash, reason)
        _require_hash(self.policy_serialized_sha256, reason)
        _require_hash(self.interpreter_binding_hash, reason)
        if self.policy_content_hash != CONTROLLER_POLICY_CONTENT_HASH or (
            self.policy_serialized_sha256 != CONTROLLER_POLICY_SERIALIZED_SHA256
        ):
            _fail("host_snapshot_policy_drift")
        if self.interpreter_binding_hash != canonical_interpreter_binding().content_hash:
            _fail("host_snapshot_interpreter_drift")
        if self.managed_root_path != MANAGED_ROOT:
            _fail("host_snapshot_ambient_resource")
        expected_purposes = (
            (self.managed_root, "managed_root"),
            (self.release_stage, "release_stage"),
            (self.release_final, "release_final"),
            (self.model_stage, "model_stage"),
            (self.model_final, "model_final"),
        )
        for manifest, purpose in expected_purposes:
            if manifest is not None and (
                type(manifest) is not BoundedTreeManifest
                or manifest.purpose != purpose
                or manifest.ownership_token is None
            ):
                _fail(reason)
        if type(self.principal) is not PrincipalObservation:
            _fail(reason)
        if (
            type(self.socket_unit) is not UnitObservation
            or self.socket_unit.unit_name != SOCKET_UNIT_NAME
            or type(self.service_unit) is not UnitObservation
            or self.service_unit.unit_name != SERVICE_UNIT_NAME
        ):
            _fail(reason)
        _require_int(self.manager_reload_generation, reason)
        if self.manager_reload_ownership_token is not None:
            _require_id(self.manager_reload_ownership_token, reason)
        if self.manager_reload_generation == 0 and self.manager_reload_ownership_token is not None:
            _fail(reason)

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.ollama_v2_host_snapshot",
            "format_version": FORMAT_VERSION,
            "snapshot_id": self.snapshot_id,
            "observed_generation": self.observed_generation,
            "policy_content_hash": self.policy_content_hash,
            "policy_serialized_sha256": self.policy_serialized_sha256,
            "interpreter_binding_hash": self.interpreter_binding_hash,
            "managed_root_path": self.managed_root_path,
            "managed_root": None if self.managed_root is None else self.managed_root.to_document(),
            "principal": self.principal.to_document(),
            "release_stage": (
                None if self.release_stage is None else self.release_stage.to_document()
            ),
            "release_final": (
                None if self.release_final is None else self.release_final.to_document()
            ),
            "model_stage": None if self.model_stage is None else self.model_stage.to_document(),
            "model_final": None if self.model_final is None else self.model_final.to_document(),
            "socket_unit": self.socket_unit.to_document(),
            "service_unit": self.service_unit.to_document(),
            "manager_reload_generation": self.manager_reload_generation,
            "manager_reload_ownership_token": self.manager_reload_ownership_token,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def from_document(cls, value: object) -> HostSnapshot:
        reason = "host_snapshot_invalid"
        checked = _expect_document(
            value,
            keys={
                "format",
                "format_version",
                "snapshot_id",
                "observed_generation",
                "policy_content_hash",
                "policy_serialized_sha256",
                "interpreter_binding_hash",
                "managed_root_path",
                "managed_root",
                "principal",
                "release_stage",
                "release_final",
                "model_stage",
                "model_final",
                "socket_unit",
                "service_unit",
                "manager_reload_generation",
                "manager_reload_ownership_token",
                "content_hash",
            },
            format_name="world-forge.private.ollama_v2_host_snapshot",
            reason=reason,
        )

        def manifest_or_none(item: object) -> BoundedTreeManifest | None:
            return None if item is None else BoundedTreeManifest.from_document(item)

        try:
            result = cls(
                snapshot_id=checked["snapshot_id"],  # type: ignore[arg-type]
                observed_generation=checked["observed_generation"],  # type: ignore[arg-type]
                policy_content_hash=checked["policy_content_hash"],  # type: ignore[arg-type]
                policy_serialized_sha256=checked[
                    "policy_serialized_sha256"
                ],  # type: ignore[arg-type]
                interpreter_binding_hash=checked[
                    "interpreter_binding_hash"
                ],  # type: ignore[arg-type]
                managed_root_path=checked["managed_root_path"],  # type: ignore[arg-type]
                managed_root=manifest_or_none(checked["managed_root"]),
                principal=PrincipalObservation.from_document(checked["principal"]),
                release_stage=manifest_or_none(checked["release_stage"]),
                release_final=manifest_or_none(checked["release_final"]),
                model_stage=manifest_or_none(checked["model_stage"]),
                model_final=manifest_or_none(checked["model_final"]),
                socket_unit=UnitObservation.from_document(checked["socket_unit"]),
                service_unit=UnitObservation.from_document(checked["service_unit"]),
                manager_reload_generation=checked[
                    "manager_reload_generation"
                ],  # type: ignore[arg-type]
                manager_reload_ownership_token=checked[
                    "manager_reload_ownership_token"
                ],  # type: ignore[arg-type]
            )
        except TypeError:
            _fail(reason)
        if checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


def make_empty_host_snapshot(snapshot_id: str, *, observed_generation: int) -> HostSnapshot:
    binding = canonical_interpreter_binding()
    return HostSnapshot(
        snapshot_id=snapshot_id,
        observed_generation=observed_generation,
        policy_content_hash=CONTROLLER_POLICY_CONTENT_HASH,
        policy_serialized_sha256=CONTROLLER_POLICY_SERIALIZED_SHA256,
        interpreter_binding_hash=binding.content_hash,
        managed_root_path=MANAGED_ROOT,
        managed_root=None,
        principal=_absent_principal(),
        release_stage=None,
        release_final=None,
        model_stage=None,
        model_final=None,
        socket_unit=_absent_unit(SOCKET_UNIT_NAME),
        service_unit=_absent_unit(SERVICE_UNIT_NAME),
        manager_reload_generation=0,
        manager_reload_ownership_token=None,
    )


_EFFECT_TARGETS = {
    "managed_root.create": "managed_root",
    "managed_root.remove_exact": "managed_root",
    "principal.create_exact": "principal",
    "principal.remove_exact": "principal",
    "release.stage": "release_stage",
    "release.unstage_exact": "release_stage",
    "release.publish": "release_publish",
    "release.unpublish_exact": "release_publish",
    "model.stage": "model_stage",
    "model.unstage_exact": "model_stage",
    "model.publish": "model_publish",
    "model.unpublish_exact": "model_publish",
    "socket.install": "socket_unit",
    "socket.remove_exact": "socket_unit",
    "service.install": "service_unit",
    "service.remove_exact": "service_unit",
    "manager.reload": "manager",
}


@dataclass(frozen=True, slots=True)
class HostEffect(_CanonicalContract):
    effect_id: str
    ordinal: int
    phase: str
    kind: str
    resource_id: str
    ownership_token: str
    payload_hash: str
    precondition_hash: str
    postcondition_hash: str

    def __post_init__(self) -> None:
        reason = "host_effect_invalid"
        _require_id(self.effect_id, reason)
        _require_int(self.ordinal, reason, maximum=31)
        if self.phase not in {"apply", "rollback"}:
            _fail(reason)
        if self.kind not in EFFECT_KINDS or self.resource_id != _EFFECT_TARGETS[self.kind]:
            _fail(reason)
        if self.phase == "apply" and self.kind not in APPLY_EFFECT_KINDS:
            _fail(reason)
        if self.phase == "rollback" and self.kind not in ROLLBACK_EFFECT_KINDS:
            _fail(reason)
        _require_id(self.ownership_token, reason)
        _require_hash(self.payload_hash, reason)
        _require_hash(self.precondition_hash, reason)
        _require_hash(self.postcondition_hash, reason)
        if self.precondition_hash == self.postcondition_hash:
            _fail(reason)

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.ollama_v2_host_effect",
            "format_version": FORMAT_VERSION,
            "effect_id": self.effect_id,
            "ordinal": self.ordinal,
            "phase": self.phase,
            "kind": self.kind,
            "resource_id": self.resource_id,
            "ownership_token": self.ownership_token,
            "payload_hash": self.payload_hash,
            "precondition_hash": self.precondition_hash,
            "postcondition_hash": self.postcondition_hash,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def from_document(cls, value: object) -> HostEffect:
        reason = "host_effect_invalid"
        checked = _expect_document(
            value,
            keys={
                "format",
                "format_version",
                "effect_id",
                "ordinal",
                "phase",
                "kind",
                "resource_id",
                "ownership_token",
                "payload_hash",
                "precondition_hash",
                "postcondition_hash",
                "content_hash",
            },
            format_name="world-forge.private.ollama_v2_host_effect",
            reason=reason,
        )
        try:
            result = cls(
                effect_id=checked["effect_id"],  # type: ignore[arg-type]
                ordinal=checked["ordinal"],  # type: ignore[arg-type]
                phase=checked["phase"],  # type: ignore[arg-type]
                kind=checked["kind"],  # type: ignore[arg-type]
                resource_id=checked["resource_id"],  # type: ignore[arg-type]
                ownership_token=checked["ownership_token"],  # type: ignore[arg-type]
                payload_hash=checked["payload_hash"],  # type: ignore[arg-type]
                precondition_hash=checked["precondition_hash"],  # type: ignore[arg-type]
                postcondition_hash=checked["postcondition_hash"],  # type: ignore[arg-type]
            )
        except TypeError:
            _fail(reason)
        if checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


def host_projection_hash(snapshot: HostSnapshot) -> str:
    if type(snapshot) is not HostSnapshot:
        _fail("host_snapshot_invalid")
    document = snapshot.to_document()
    document.pop("content_hash")
    document.pop("snapshot_id")
    document.pop("observed_generation")
    return hashlib.sha256(
        canonical_controller_bytes(document)
    ).hexdigest()


def is_reusable_clean_projection(
    snapshot: HostSnapshot,
    initial_snapshot: HostSnapshot,
) -> bool:
    if type(snapshot) is not HostSnapshot or type(initial_snapshot) is not HostSnapshot:
        _fail("host_snapshot_invalid")
    if (
        initial_snapshot.manager_reload_ownership_token is not None
        or snapshot.manager_reload_ownership_token is not None
        or snapshot.manager_reload_generation
        < initial_snapshot.manager_reload_generation
    ):
        return False
    current = snapshot.to_document()
    initial = initial_snapshot.to_document()
    for document in (current, initial):
        document.pop("content_hash")
        document.pop("snapshot_id")
        document.pop("observed_generation")
        document["manager_reload_generation"] = 0
    return canonical_controller_bytes(current) == canonical_controller_bytes(initial)


def classify_effect_snapshot(snapshot: HostSnapshot, effect: HostEffect) -> str:
    current = host_projection_hash(snapshot)
    if current == effect.precondition_hash:
        return "precondition"
    if current == effect.postcondition_hash:
        return "postcondition"
    return "foreign"


def _managed_root_manifest(ownership_token: str) -> BoundedTreeManifest:
    return BoundedTreeManifest(
        purpose="managed_root",
        root_path=MANAGED_ROOT,
        root_mode=0o755,
        uid=CONTROLLER_UID,
        gid=CONTROLLER_GID,
        sealed=False,
        entries=(),
        ownership_token=ownership_token,
    )


def _expected_principal(ownership_token: str) -> PrincipalObservation:
    return PrincipalObservation(
        present=True,
        account=CONTROLLER_ACCOUNT,
        uid=CONTROLLER_UID,
        gid=CONTROLLER_GID,
        primary_group=CONTROLLER_GROUP,
        dedicated_non_login=True,
        supplementary_groups=(),
        owned_by_operation=True,
        uid_owner_account=CONTROLLER_ACCOUNT,
        gid_owner_group=CONTROLLER_GROUP,
        ownership_token=ownership_token,
    )


def _project_kind(
    snapshot: HostSnapshot,
    *,
    kind: str,
    release_manifest: BoundedTreeManifest,
    model_manifest: BoundedTreeManifest,
    snapshot_id: str,
    ownership_token: str,
    phase: str,
) -> HostSnapshot:
    changes: dict[str, object] = {
        "snapshot_id": snapshot_id,
        "observed_generation": snapshot.observed_generation + 1,
    }
    if kind == "managed_root.create":
        changes["managed_root"] = _managed_root_manifest(ownership_token)
    elif kind == "managed_root.remove_exact":
        changes["managed_root"] = None
    elif kind == "principal.create_exact":
        changes["principal"] = _expected_principal(ownership_token)
    elif kind == "principal.remove_exact":
        changes["principal"] = _absent_principal()
    elif kind == "release.stage":
        changes["release_stage"] = release_manifest.owned(
            "release_stage",
            ownership_token,
        )
    elif kind == "release.publish":
        changes["release_stage"] = None
        changes["release_final"] = release_manifest.owned(
            "release_final",
            ownership_token,
        )
    elif kind == "release.unpublish_exact":
        changes["release_stage"] = release_manifest.owned(
            "release_stage",
            ownership_token,
        )
        changes["release_final"] = None
    elif kind == "release.unstage_exact":
        changes["release_stage"] = None
    elif kind == "model.stage":
        changes["model_stage"] = model_manifest.owned("model_stage", ownership_token)
    elif kind == "model.publish":
        changes["model_stage"] = None
        changes["model_final"] = model_manifest.owned("model_final", ownership_token)
    elif kind == "model.unpublish_exact":
        changes["model_stage"] = model_manifest.owned("model_stage", ownership_token)
        changes["model_final"] = None
    elif kind == "model.unstage_exact":
        changes["model_stage"] = None
    elif kind == "socket.install":
        changes["socket_unit"] = UnitObservation(
            unit_name=SOCKET_UNIT_NAME,
            present=True,
            content_sha256=hashlib.sha256(SOCKET_UNIT_BYTES).hexdigest(),
            owned_by_operation=True,
            enabled=False,
            active=False,
            ownership_token=ownership_token,
        )
    elif kind == "socket.remove_exact":
        changes["socket_unit"] = _absent_unit(SOCKET_UNIT_NAME)
    elif kind == "service.install":
        changes["service_unit"] = UnitObservation(
            unit_name=SERVICE_UNIT_NAME,
            present=True,
            content_sha256=hashlib.sha256(SERVICE_UNIT_BYTES).hexdigest(),
            owned_by_operation=True,
            enabled=False,
            active=False,
            ownership_token=ownership_token,
        )
    elif kind == "service.remove_exact":
        changes["service_unit"] = _absent_unit(SERVICE_UNIT_NAME)
    elif kind == "manager.reload":
        changes["manager_reload_generation"] = snapshot.manager_reload_generation + 1
        changes["manager_reload_ownership_token"] = (
            ownership_token if phase == "apply" else None
        )
    else:
        _fail("host_effect_invalid")
    return replace(snapshot, **changes)


def _effect_payload_hash(
    kind: str,
    release_manifest: BoundedTreeManifest,
    model_manifest: BoundedTreeManifest,
) -> str:
    if kind.startswith("release."):
        payload: object = release_manifest.to_document()
    elif kind.startswith("model."):
        payload = model_manifest.to_document()
    elif kind.startswith("socket."):
        payload = {
            "unit_name": SOCKET_UNIT_NAME,
            "unit_directory": UNIT_DIRECTORY,
            "sha256": hashlib.sha256(SOCKET_UNIT_BYTES).hexdigest(),
        }
    elif kind.startswith("service."):
        payload = {
            "unit_name": SERVICE_UNIT_NAME,
            "unit_directory": UNIT_DIRECTORY,
            "sha256": hashlib.sha256(SERVICE_UNIT_BYTES).hexdigest(),
        }
    elif kind.startswith("principal."):
        payload = {
            "account": CONTROLLER_ACCOUNT,
            "group": CONTROLLER_GROUP,
            "uid": CONTROLLER_UID,
            "gid": CONTROLLER_GID,
        }
    elif kind.startswith("managed_root."):
        payload = {"path": MANAGED_ROOT, "uid": CONTROLLER_UID, "gid": CONTROLLER_GID}
    else:
        payload = {
            "socket_unit_sha256": hashlib.sha256(SOCKET_UNIT_BYTES).hexdigest(),
            "service_unit_sha256": hashlib.sha256(SERVICE_UNIT_BYTES).hexdigest(),
        }
    return hashlib.sha256(canonical_controller_bytes(payload)).hexdigest()


def _make_effect(
    snapshot: HostSnapshot,
    *,
    ordinal: int,
    phase: str,
    kind: str,
    release_manifest: BoundedTreeManifest,
    model_manifest: BoundedTreeManifest,
    identity_seed: str,
    ownership_token: str,
) -> tuple[HostEffect, HostSnapshot]:
    payload_hash = _effect_payload_hash(kind, release_manifest, model_manifest)
    precondition_hash = host_projection_hash(snapshot)
    projected = _project_kind(
        snapshot,
        kind=kind,
        release_manifest=release_manifest,
        model_manifest=model_manifest,
        snapshot_id=f"snap-projection-{phase}-{ordinal}",
        ownership_token=ownership_token,
        phase=phase,
    )
    postcondition_hash = host_projection_hash(projected)
    effect_id = "effect-" + hashlib.sha256(
        canonical_controller_bytes(
            {
                "identity_seed": identity_seed,
                "ordinal": ordinal,
                "phase": phase,
                "kind": kind,
                "ownership_token": ownership_token,
                "payload_hash": payload_hash,
                "precondition_hash": precondition_hash,
                "postcondition_hash": postcondition_hash,
            }
        )
    ).hexdigest()[:32]
    return (
        HostEffect(
            effect_id=effect_id,
            ordinal=ordinal,
            phase=phase,
            kind=kind,
            resource_id=_EFFECT_TARGETS[kind],
            ownership_token=ownership_token,
            payload_hash=payload_hash,
            precondition_hash=precondition_hash,
            postcondition_hash=postcondition_hash,
        ),
        projected,
    )


def _operation_ownership_token(
    operation_id: str,
    initial_snapshot: HostSnapshot,
    release_manifest: BoundedTreeManifest,
    model_manifest: BoundedTreeManifest,
) -> str:
    _require_id(operation_id, "controller_plan_invalid")
    seed = {
        "operation_id": operation_id,
        "host_scope": "ollama_v2_fixed_host_scope",
        "managed_root": MANAGED_ROOT,
        "initial_snapshot_hash": initial_snapshot.content_hash,
        "release_manifest_hash": release_manifest.content_hash,
        "model_manifest_hash": model_manifest.content_hash,
        "policy_content_hash": CONTROLLER_POLICY_CONTENT_HASH,
        "interpreter_binding_hash": canonical_interpreter_binding().content_hash,
    }
    return "owner-" + hashlib.sha256(canonical_controller_bytes(seed)).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class ControllerPlan(_CanonicalContract):
    plan_id: str
    operation_id: str
    ownership_token: str
    policy_content_hash: str
    policy_serialized_sha256: str
    interpreter_binding: InterpreterBinding
    uid: int
    gid: int
    initial_snapshot: HostSnapshot
    release_manifest: BoundedTreeManifest
    model_manifest: BoundedTreeManifest
    effects: tuple[HostEffect, ...]
    terminal_apply_state: str
    availability: str
    production_eligible: bool

    def __post_init__(self) -> None:
        reason = "controller_plan_invalid"
        _require_id(self.plan_id, reason)
        _require_id(self.operation_id, reason)
        _require_id(self.ownership_token, reason)
        if (
            self.policy_content_hash != CONTROLLER_POLICY_CONTENT_HASH
            or self.policy_serialized_sha256 != CONTROLLER_POLICY_SERIALIZED_SHA256
            or self.interpreter_binding != canonical_interpreter_binding()
            or type(self.uid) is not int
            or type(self.gid) is not int
            or self.uid != CONTROLLER_UID
            or self.gid != CONTROLLER_GID
            or type(self.initial_snapshot) is not HostSnapshot
            or self.release_manifest.purpose != "release_final"
            or self.model_manifest.purpose != "model_final"
            or type(self.effects) is not tuple
            or not 1 <= len(self.effects) <= 32
            or self.terminal_apply_state != "prepared_unverified"
            or self.availability != "unavailable"
            or self.production_eligible is not False
        ):
            _fail(reason)
        if self.ownership_token != _operation_ownership_token(
            self.operation_id,
            self.initial_snapshot,
            self.release_manifest,
            self.model_manifest,
        ):
            _fail(reason)
        if tuple(effect.kind for effect in self.effects) != APPLY_EFFECT_KINDS:
            _fail(reason)
        if any(effect.ownership_token != self.ownership_token for effect in self.effects):
            _fail(reason)
        if tuple(effect.ordinal for effect in self.effects) != tuple(range(len(self.effects))):
            _fail(reason)
        seed = _plan_identity_payload(
            self.operation_id,
            self.ownership_token,
            self.initial_snapshot,
            self.release_manifest,
            self.model_manifest,
            self.effects,
        )
        expected_id = "plan-" + hashlib.sha256(canonical_controller_bytes(seed)).hexdigest()[:32]
        if self.plan_id != expected_id:
            _fail(reason)

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.ollama_v2_controller_plan",
            "format_version": FORMAT_VERSION,
            "plan_id": self.plan_id,
            "operation_id": self.operation_id,
            "ownership_token": self.ownership_token,
            "policy_content_hash": self.policy_content_hash,
            "policy_serialized_sha256": self.policy_serialized_sha256,
            "interpreter_binding": self.interpreter_binding.to_document(),
            "uid": self.uid,
            "gid": self.gid,
            "initial_snapshot": self.initial_snapshot.to_document(),
            "release_manifest": self.release_manifest.to_document(),
            "model_manifest": self.model_manifest.to_document(),
            "effects": [effect.to_document() for effect in self.effects],
            "terminal_apply_state": self.terminal_apply_state,
            "availability": self.availability,
            "production_eligible": self.production_eligible,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def from_document(cls, value: object) -> ControllerPlan:
        reason = "controller_plan_invalid"
        checked = _expect_document(
            value,
            keys={
                "format",
                "format_version",
                "plan_id",
                "operation_id",
                "ownership_token",
                "policy_content_hash",
                "policy_serialized_sha256",
                "interpreter_binding",
                "uid",
                "gid",
                "initial_snapshot",
                "release_manifest",
                "model_manifest",
                "effects",
                "terminal_apply_state",
                "availability",
                "production_eligible",
                "content_hash",
            },
            format_name="world-forge.private.ollama_v2_controller_plan",
            reason=reason,
        )
        if type(checked["effects"]) is not list:
            _fail(reason)
        try:
            result = cls(
                plan_id=checked["plan_id"],  # type: ignore[arg-type]
                operation_id=checked["operation_id"],  # type: ignore[arg-type]
                ownership_token=checked["ownership_token"],  # type: ignore[arg-type]
                policy_content_hash=checked["policy_content_hash"],  # type: ignore[arg-type]
                policy_serialized_sha256=checked[
                    "policy_serialized_sha256"
                ],  # type: ignore[arg-type]
                interpreter_binding=InterpreterBinding.from_document(
                    checked["interpreter_binding"]
                ),
                uid=checked["uid"],  # type: ignore[arg-type]
                gid=checked["gid"],  # type: ignore[arg-type]
                initial_snapshot=HostSnapshot.from_document(checked["initial_snapshot"]),
                release_manifest=BoundedTreeManifest.from_document(checked["release_manifest"]),
                model_manifest=BoundedTreeManifest.from_document(checked["model_manifest"]),
                effects=tuple(HostEffect.from_document(item) for item in checked["effects"]),
                terminal_apply_state=checked["terminal_apply_state"],  # type: ignore[arg-type]
                availability=checked["availability"],  # type: ignore[arg-type]
                production_eligible=checked["production_eligible"],  # type: ignore[arg-type]
            )
        except TypeError:
            _fail(reason)
        rebuilt = build_controller_plan(
            result.initial_snapshot,
            result.release_manifest,
            result.model_manifest,
            operation_id=result.operation_id,
        )
        if result != rebuilt or checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


def _plan_identity_payload(
    operation_id: str,
    ownership_token: str,
    initial_snapshot: HostSnapshot,
    release_manifest: BoundedTreeManifest,
    model_manifest: BoundedTreeManifest,
    effects: tuple[HostEffect, ...],
) -> dict[str, object]:
    return {
        "operation_id": operation_id,
        "ownership_token": ownership_token,
        "policy_content_hash": CONTROLLER_POLICY_CONTENT_HASH,
        "policy_serialized_sha256": CONTROLLER_POLICY_SERIALIZED_SHA256,
        "interpreter_binding_hash": canonical_interpreter_binding().content_hash,
        "initial_snapshot_hash": initial_snapshot.content_hash,
        "release_manifest_hash": release_manifest.content_hash,
        "model_manifest_hash": model_manifest.content_hash,
        "effect_hashes": [effect.content_hash for effect in effects],
    }


def _require_empty_plan_precondition(snapshot: HostSnapshot) -> None:
    if (
        snapshot.managed_root is not None
        or snapshot.principal.present
        or snapshot.principal.uid_owner_account is not None
        or snapshot.principal.gid_owner_group is not None
        or snapshot.release_stage is not None
        or snapshot.release_final is not None
        or snapshot.model_stage is not None
        or snapshot.model_final is not None
        or snapshot.socket_unit.present
        or snapshot.service_unit.present
        or snapshot.manager_reload_ownership_token is not None
    ):
        _fail("plan_precondition_not_empty")


def build_controller_plan(
    initial_snapshot: HostSnapshot,
    release_manifest: BoundedTreeManifest,
    model_manifest: BoundedTreeManifest,
    *,
    operation_id: str,
) -> ControllerPlan:
    _require_id(operation_id, "controller_plan_invalid")
    if type(initial_snapshot) is not HostSnapshot:
        _fail("controller_plan_invalid")
    if (
        type(release_manifest) is not BoundedTreeManifest
        or release_manifest.purpose != "release_final"
        or release_manifest.ownership_token is not None
    ):
        _fail("controller_plan_invalid")
    if (
        type(model_manifest) is not BoundedTreeManifest
        or model_manifest.purpose != "model_final"
        or model_manifest.ownership_token is not None
    ):
        _fail("controller_plan_invalid")
    _require_empty_plan_precondition(initial_snapshot)
    ownership_token = _operation_ownership_token(
        operation_id,
        initial_snapshot,
        release_manifest,
        model_manifest,
    )
    identity_seed = hashlib.sha256(
        canonical_controller_bytes(
            {
                "initial": initial_snapshot.content_hash,
                "release": release_manifest.content_hash,
                "model": model_manifest.content_hash,
                "policy": CONTROLLER_POLICY_CONTENT_HASH,
                "interpreter": canonical_interpreter_binding().content_hash,
                "operation_id": operation_id,
                "ownership_token": ownership_token,
            }
        )
    ).hexdigest()
    effects: list[HostEffect] = []
    projected = initial_snapshot
    for ordinal, kind in enumerate(APPLY_EFFECT_KINDS):
        effect, projected = _make_effect(
            projected,
            ordinal=ordinal,
            phase="apply",
            kind=kind,
            release_manifest=release_manifest,
            model_manifest=model_manifest,
            identity_seed=identity_seed,
            ownership_token=ownership_token,
        )
        effects.append(effect)
    effect_tuple = tuple(effects)
    plan_id = "plan-" + hashlib.sha256(
        canonical_controller_bytes(
            _plan_identity_payload(
                operation_id,
                ownership_token,
                initial_snapshot,
                release_manifest,
                model_manifest,
                effect_tuple,
            )
        )
    ).hexdigest()[:32]
    return ControllerPlan(
        plan_id=plan_id,
        operation_id=operation_id,
        ownership_token=ownership_token,
        policy_content_hash=CONTROLLER_POLICY_CONTENT_HASH,
        policy_serialized_sha256=CONTROLLER_POLICY_SERIALIZED_SHA256,
        interpreter_binding=canonical_interpreter_binding(),
        uid=CONTROLLER_UID,
        gid=CONTROLLER_GID,
        initial_snapshot=initial_snapshot,
        release_manifest=release_manifest,
        model_manifest=model_manifest,
        effects=effect_tuple,
        terminal_apply_state="prepared_unverified",
        availability="unavailable",
        production_eligible=False,
    )


def project_effect(
    snapshot: HostSnapshot,
    plan: ControllerPlan,
    effect: HostEffect,
    operation_id: str,
) -> HostSnapshot:
    _require_id(operation_id, "operation_id_invalid")
    if operation_id != plan.operation_id or effect.ownership_token != plan.ownership_token:
        _fail("host_effect_ownership_invalid")
    if effect not in plan.effects and effect.phase != "rollback":
        _fail("host_effect_not_in_plan")
    if classify_effect_snapshot(snapshot, effect) != "precondition":
        _fail("host_effect_precondition_failed")
    snapshot_id = "snap-" + hashlib.sha256(
        canonical_controller_bytes(
            {
                "operation_id": operation_id,
                "effect_id": effect.effect_id,
                "before": snapshot.content_hash,
            }
        )
    ).hexdigest()[:32]
    projected = _project_kind(
        snapshot,
        kind=effect.kind,
        release_manifest=plan.release_manifest,
        model_manifest=plan.model_manifest,
        snapshot_id=snapshot_id,
        ownership_token=plan.ownership_token,
        phase=effect.phase,
    )
    if classify_effect_snapshot(projected, effect) != "postcondition":
        _fail("host_effect_projection_invalid")
    return projected


@dataclass(frozen=True, slots=True)
class AuthorizationRequest(_CanonicalContract):
    authorization_id: str
    operation_id: str
    plan_hash: str
    effect_id: str
    phase: str
    attempt: int
    expected_generation: int
    expected_sequence: int
    expected_head_hash: str
    ownership_token: str
    policy_content_hash: str
    interpreter_binding_hash: str

    def __post_init__(self) -> None:
        reason = "authorization_request_invalid"
        _require_id(self.authorization_id, reason)
        _require_id(self.operation_id, reason)
        _require_hash(self.plan_hash, reason)
        _require_id(self.effect_id, reason)
        if self.phase not in {"apply", "rollback"}:
            _fail(reason)
        _require_int(self.attempt, reason, minimum=1)
        _require_int(self.expected_generation, reason)
        _require_int(self.expected_sequence, reason)
        _require_hash(self.expected_head_hash, reason)
        _require_id(self.ownership_token, reason)
        if (
            self.policy_content_hash != CONTROLLER_POLICY_CONTENT_HASH
            or self.interpreter_binding_hash != canonical_interpreter_binding().content_hash
        ):
            _fail(reason)

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.ollama_v2_authorization_request",
            "format_version": FORMAT_VERSION,
            "authorization_id": self.authorization_id,
            "operation_id": self.operation_id,
            "plan_hash": self.plan_hash,
            "effect_id": self.effect_id,
            "phase": self.phase,
            "attempt": self.attempt,
            "expected_generation": self.expected_generation,
            "expected_sequence": self.expected_sequence,
            "expected_head_hash": self.expected_head_hash,
            "ownership_token": self.ownership_token,
            "policy_content_hash": self.policy_content_hash,
            "interpreter_binding_hash": self.interpreter_binding_hash,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        plan_hash: str,
        effect_id: str,
        phase: str,
        attempt: int,
        expected_generation: int,
        expected_sequence: int,
        expected_head_hash: str,
        ownership_token: str,
    ) -> AuthorizationRequest:
        seed = {
            "operation_id": operation_id,
            "plan_hash": plan_hash,
            "effect_id": effect_id,
            "phase": phase,
            "attempt": attempt,
            "expected_generation": expected_generation,
            "expected_sequence": expected_sequence,
            "expected_head_hash": expected_head_hash,
            "ownership_token": ownership_token,
            "policy_content_hash": CONTROLLER_POLICY_CONTENT_HASH,
            "interpreter_binding_hash": canonical_interpreter_binding().content_hash,
        }
        authorization_id = "auth-" + hashlib.sha256(
            canonical_controller_bytes(seed)
        ).hexdigest()[:32]
        return cls(authorization_id=authorization_id, **seed)  # type: ignore[arg-type]

    @classmethod
    def from_document(cls, value: object) -> AuthorizationRequest:
        reason = "authorization_request_invalid"
        keys = {
            "format",
            "format_version",
            "authorization_id",
            "operation_id",
            "plan_hash",
            "effect_id",
            "phase",
            "attempt",
            "expected_generation",
            "expected_sequence",
            "expected_head_hash",
            "ownership_token",
            "policy_content_hash",
            "interpreter_binding_hash",
            "content_hash",
        }
        checked = _expect_document(
            value,
            keys=keys,
            format_name="world-forge.private.ollama_v2_authorization_request",
            reason=reason,
        )
        kwargs = {key: checked[key] for key in keys - {"format", "format_version", "content_hash"}}
        try:
            result = cls(**kwargs)  # type: ignore[arg-type]
        except TypeError:
            _fail(reason)
        rebuilt = cls.create(
            operation_id=result.operation_id,
            plan_hash=result.plan_hash,
            effect_id=result.effect_id,
            phase=result.phase,
            attempt=result.attempt,
            expected_generation=result.expected_generation,
            expected_sequence=result.expected_sequence,
            expected_head_hash=result.expected_head_hash,
            ownership_token=result.ownership_token,
        )
        if result != rebuilt or checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


@dataclass(frozen=True, slots=True)
class AuthorizationConsumption(_CanonicalContract):
    consumption_id: str
    authorization_id: str
    request_hash: str
    authority_id: str
    decision_id: str
    decision: str
    single_use: bool

    def __post_init__(self) -> None:
        reason = "authorization_consumption_invalid"
        _require_id(self.consumption_id, reason)
        _require_id(self.authorization_id, reason)
        _require_hash(self.request_hash, reason)
        _require_id(self.authority_id, reason)
        _require_id(self.decision_id, reason)
        if self.decision != "authorized" or self.single_use is not True:
            _fail(reason)

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.ollama_v2_authorization_consumption",
            "format_version": FORMAT_VERSION,
            "consumption_id": self.consumption_id,
            "authorization_id": self.authorization_id,
            "request_hash": self.request_hash,
            "authority_id": self.authority_id,
            "decision_id": self.decision_id,
            "decision": self.decision,
            "single_use": self.single_use,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def create(
        cls,
        request: AuthorizationRequest,
        *,
        authority_id: str,
        decision_id: str,
    ) -> AuthorizationConsumption:
        seed = {
            "authorization_id": request.authorization_id,
            "request_hash": request.content_hash,
            "authority_id": authority_id,
            "decision_id": decision_id,
            "decision": "authorized",
            "single_use": True,
        }
        consumption_id = "consume-" + hashlib.sha256(
            canonical_controller_bytes(seed)
        ).hexdigest()[:32]
        return cls(consumption_id=consumption_id, **seed)  # type: ignore[arg-type]

    def matches(self, request: AuthorizationRequest) -> bool:
        return (
            self.authorization_id == request.authorization_id
            and self.request_hash == request.content_hash
            and self.decision == "authorized"
            and self.single_use
        )

    @classmethod
    def from_document(cls, value: object) -> AuthorizationConsumption:
        reason = "authorization_consumption_invalid"
        keys = {
            "format",
            "format_version",
            "consumption_id",
            "authorization_id",
            "request_hash",
            "authority_id",
            "decision_id",
            "decision",
            "single_use",
            "content_hash",
        }
        checked = _expect_document(
            value,
            keys=keys,
            format_name="world-forge.private.ollama_v2_authorization_consumption",
            reason=reason,
        )
        kwargs = {key: checked[key] for key in keys - {"format", "format_version", "content_hash"}}
        try:
            result = cls(**kwargs)  # type: ignore[arg-type]
        except TypeError:
            _fail(reason)
        seed = {
            "authorization_id": result.authorization_id,
            "request_hash": result.request_hash,
            "authority_id": result.authority_id,
            "decision_id": result.decision_id,
            "decision": result.decision,
            "single_use": result.single_use,
        }
        expected_id = "consume-" + hashlib.sha256(
            canonical_controller_bytes(seed)
        ).hexdigest()[:32]
        if result.consumption_id != expected_id or checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


OPERATION_STATES = (
    "apply_pending",
    "apply_authorization_pending",
    "apply_authorization_claimed",
    "apply_authorization_consumed",
    "apply_dispatching",
    "prepared_unverified",
    "rollback_pending",
    "rollback_authorization_pending",
    "rollback_authorization_claimed",
    "rollback_authorization_consumed",
    "rollback_dispatching",
    "rolled_back_clean",
    "recovery_required",
)


@dataclass(frozen=True, slots=True)
class OperationSnapshot(_CanonicalContract):
    operation_id: str
    plan_hash: str
    ownership_token: str
    generation: int
    sequence: int
    event_head_hash: str
    state: str
    apply_cursor: int
    rollback_cursor: int
    next_attempt: int
    applied_effect_ids: tuple[str, ...]
    rollback_plan_hash: str | None
    current_effect_id: str | None
    current_authorization_hash: str | None
    current_attempt_id: str | None
    last_host_snapshot_hash: str | None
    recovery_reason: str | None

    def __post_init__(self) -> None:
        reason = "operation_snapshot_invalid"
        _require_id(self.operation_id, reason)
        _require_hash(self.plan_hash, reason)
        _require_id(self.ownership_token, reason)
        _require_int(self.generation, reason)
        _require_int(self.sequence, reason)
        _require_hash(self.event_head_hash, reason)
        if self.state not in OPERATION_STATES:
            _fail(reason)
        _require_int(self.apply_cursor, reason, maximum=32)
        _require_int(self.rollback_cursor, reason, maximum=32)
        _require_int(self.next_attempt, reason, minimum=1)
        if type(self.applied_effect_ids) is not tuple:
            _fail(reason)
        for effect_id in self.applied_effect_ids:
            _require_id(effect_id, reason)
        if len(set(self.applied_effect_ids)) != len(self.applied_effect_ids):
            _fail(reason)
        for value, validator in (
            (self.rollback_plan_hash, _require_hash),
            (self.current_effect_id, _require_id),
            (self.current_authorization_hash, _require_hash),
            (self.current_attempt_id, _require_id),
            (self.last_host_snapshot_hash, _require_hash),
            (self.recovery_reason, _require_id),
        ):
            if value is not None:
                validator(value, reason)
        authorization_states = {
            "apply_authorization_pending",
            "apply_authorization_claimed",
            "apply_authorization_consumed",
            "apply_dispatching",
            "rollback_authorization_pending",
            "rollback_authorization_claimed",
            "rollback_authorization_consumed",
            "rollback_dispatching",
        }
        dispatch_states = {"apply_dispatching", "rollback_dispatching"}
        rollback_states = {
            "rollback_pending",
            "rollback_authorization_pending",
            "rollback_authorization_claimed",
            "rollback_authorization_consumed",
            "rollback_dispatching",
            "rolled_back_clean",
        }
        if (
            self.generation != self.sequence
            or (self.sequence == 0 and self.event_head_hash != _ZERO_HASH)
            or (self.sequence > 0 and self.event_head_hash == _ZERO_HASH)
            or self.apply_cursor != len(self.applied_effect_ids)
        ):
            _fail(reason)
        if self.state in authorization_states:
            if self.current_effect_id is None or self.current_authorization_hash is None:
                _fail(reason)
        elif self.current_effect_id is not None or self.current_authorization_hash is not None:
            _fail(reason)
        if self.state in dispatch_states:
            if self.current_attempt_id is None:
                _fail(reason)
        elif self.current_attempt_id is not None:
            _fail(reason)
        if self.state in rollback_states:
            if self.rollback_plan_hash is None:
                _fail(reason)
        elif self.state != "recovery_required" and self.rollback_plan_hash is not None:
            _fail(reason)
        if self.state == "recovery_required":
            if self.recovery_reason is None:
                _fail(reason)
        elif self.state == "rolled_back_clean":
            if self.recovery_reason is not None:
                _fail(reason)
        elif self.state not in rollback_states and self.recovery_reason is not None:
            _fail(reason)

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.ollama_v2_operation_snapshot",
            "format_version": FORMAT_VERSION,
            "operation_id": self.operation_id,
            "plan_hash": self.plan_hash,
            "ownership_token": self.ownership_token,
            "generation": self.generation,
            "sequence": self.sequence,
            "event_head_hash": self.event_head_hash,
            "state": self.state,
            "apply_cursor": self.apply_cursor,
            "rollback_cursor": self.rollback_cursor,
            "next_attempt": self.next_attempt,
            "applied_effect_ids": list(self.applied_effect_ids),
            "rollback_plan_hash": self.rollback_plan_hash,
            "current_effect_id": self.current_effect_id,
            "current_authorization_hash": self.current_authorization_hash,
            "current_attempt_id": self.current_attempt_id,
            "last_host_snapshot_hash": self.last_host_snapshot_hash,
            "recovery_reason": self.recovery_reason,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def create(cls, operation_id: str, plan: ControllerPlan) -> OperationSnapshot:
        if operation_id != plan.operation_id:
            _fail("operation_snapshot_invalid")
        return cls(
            operation_id=operation_id,
            plan_hash=plan.content_hash,
            ownership_token=plan.ownership_token,
            generation=0,
            sequence=0,
            event_head_hash=_ZERO_HASH,
            state="apply_pending",
            apply_cursor=0,
            rollback_cursor=0,
            next_attempt=1,
            applied_effect_ids=(),
            rollback_plan_hash=None,
            current_effect_id=None,
            current_authorization_hash=None,
            current_attempt_id=None,
            last_host_snapshot_hash=plan.initial_snapshot.content_hash,
            recovery_reason=None,
        )

    @classmethod
    def from_document(cls, value: object) -> OperationSnapshot:
        reason = "operation_snapshot_invalid"
        keys = {
            "format",
            "format_version",
            "operation_id",
            "plan_hash",
            "ownership_token",
            "generation",
            "sequence",
            "event_head_hash",
            "state",
            "apply_cursor",
            "rollback_cursor",
            "next_attempt",
            "applied_effect_ids",
            "rollback_plan_hash",
            "current_effect_id",
            "current_authorization_hash",
            "current_attempt_id",
            "last_host_snapshot_hash",
            "recovery_reason",
            "content_hash",
        }
        checked = _expect_document(
            value,
            keys=keys,
            format_name="world-forge.private.ollama_v2_operation_snapshot",
            reason=reason,
        )
        if type(checked["applied_effect_ids"]) is not list:
            _fail(reason)
        kwargs = {key: checked[key] for key in keys - {"format", "format_version", "content_hash"}}
        kwargs["applied_effect_ids"] = tuple(checked["applied_effect_ids"])
        try:
            result = cls(**kwargs)  # type: ignore[arg-type]
        except TypeError:
            _fail(reason)
        if checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


@dataclass(frozen=True, slots=True)
class RollbackPlan(_CanonicalContract):
    rollback_id: str
    operation_id: str
    ownership_token: str
    plan_hash: str
    source_applied_effect_ids: tuple[str, ...]
    effects: tuple[HostEffect, ...]
    terminal_state: str
    availability: str
    production_eligible: bool

    def __post_init__(self) -> None:
        reason = "rollback_plan_invalid"
        _require_id(self.rollback_id, reason)
        _require_id(self.operation_id, reason)
        _require_id(self.ownership_token, reason)
        _require_hash(self.plan_hash, reason)
        if (
            type(self.source_applied_effect_ids) is not tuple
            or type(self.effects) is not tuple
            or len(self.effects) > 32
            or self.terminal_state != "rolled_back_clean"
            or self.availability != "unavailable"
            or self.production_eligible is not False
        ):
            _fail(reason)
        for effect_id in self.source_applied_effect_ids:
            _require_id(effect_id, reason)
        if (
            len(set(self.source_applied_effect_ids)) != len(self.source_applied_effect_ids)
            or any(effect.phase != "rollback" for effect in self.effects)
            or tuple(effect.ordinal for effect in self.effects)
            != tuple(range(len(self.effects)))
        ):
            _fail(reason)
        seed = {
            "operation_id": self.operation_id,
            "ownership_token": self.ownership_token,
            "plan_hash": self.plan_hash,
            "source_applied_effect_ids": list(self.source_applied_effect_ids),
            "effect_hashes": [effect.content_hash for effect in self.effects],
        }
        expected_id = "rollback-" + hashlib.sha256(
            canonical_controller_bytes(seed)
        ).hexdigest()[:32]
        if self.rollback_id != expected_id:
            _fail(reason)

    @property
    def content_hash(self) -> str:
        return _document_hash(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "format": "world-forge.private.ollama_v2_rollback_plan",
            "format_version": FORMAT_VERSION,
            "rollback_id": self.rollback_id,
            "operation_id": self.operation_id,
            "ownership_token": self.ownership_token,
            "plan_hash": self.plan_hash,
            "source_applied_effect_ids": list(self.source_applied_effect_ids),
            "effects": [effect.to_document() for effect in self.effects],
            "terminal_state": self.terminal_state,
            "availability": self.availability,
            "production_eligible": self.production_eligible,
        }

    def to_document(self) -> dict[str, object]:
        return _seal(self._payload())

    @classmethod
    def from_document(cls, value: object) -> RollbackPlan:
        reason = "rollback_plan_invalid"
        checked = _expect_document(
            value,
            keys={
                "format",
                "format_version",
                "rollback_id",
                "operation_id",
                "ownership_token",
                "plan_hash",
                "source_applied_effect_ids",
                "effects",
                "terminal_state",
                "availability",
                "production_eligible",
                "content_hash",
            },
            format_name="world-forge.private.ollama_v2_rollback_plan",
            reason=reason,
        )
        if (
            type(checked["source_applied_effect_ids"]) is not list
            or type(checked["effects"]) is not list
        ):
            _fail(reason)
        try:
            result = cls(
                rollback_id=checked["rollback_id"],  # type: ignore[arg-type]
                operation_id=checked["operation_id"],  # type: ignore[arg-type]
                ownership_token=checked["ownership_token"],  # type: ignore[arg-type]
                plan_hash=checked["plan_hash"],  # type: ignore[arg-type]
                source_applied_effect_ids=tuple(
                    checked["source_applied_effect_ids"]
                ),  # type: ignore[arg-type]
                effects=tuple(HostEffect.from_document(item) for item in checked["effects"]),
                terminal_state=checked["terminal_state"],  # type: ignore[arg-type]
                availability=checked["availability"],  # type: ignore[arg-type]
                production_eligible=checked["production_eligible"],  # type: ignore[arg-type]
            )
        except TypeError:
            _fail(reason)
        if checked["content_hash"] != result.content_hash:
            _fail(reason)
        return result


_COMPENSATION = {
    "service.install": "service.remove_exact",
    "socket.install": "socket.remove_exact",
    "model.publish": "model.unpublish_exact",
    "model.stage": "model.unstage_exact",
    "release.publish": "release.unpublish_exact",
    "release.stage": "release.unstage_exact",
    "principal.create_exact": "principal.remove_exact",
    "managed_root.create": "managed_root.remove_exact",
}


def build_rollback_plan(
    operation_id: str,
    plan: ControllerPlan,
    applied_effect_ids: tuple[str, ...],
) -> RollbackPlan:
    _require_id(operation_id, "rollback_plan_invalid")
    if type(applied_effect_ids) is not tuple:
        _fail("rollback_lineage_invalid")
    if operation_id != plan.operation_id:
        _fail("rollback_lineage_invalid")
    expected_prefix = tuple(effect.effect_id for effect in plan.effects[: len(applied_effect_ids)])
    if applied_effect_ids != expected_prefix:
        _fail("rollback_lineage_invalid")
    projected = plan.initial_snapshot
    for effect in plan.effects[: len(applied_effect_ids)]:
        projected = project_effect(projected, plan, effect, operation_id)
    kinds = [
        _COMPENSATION[effect.kind]
        for effect in reversed(plan.effects[: len(applied_effect_ids)])
        if effect.kind in _COMPENSATION
    ]
    unit_or_reload_applied = any(
        effect.kind in {"socket.install", "service.install", "manager.reload"}
        for effect in plan.effects[: len(applied_effect_ids)]
    )
    if unit_or_reload_applied:
        kinds.append("manager.reload")
    identity_seed = hashlib.sha256(
        canonical_controller_bytes(
            {
                "operation_id": operation_id,
                "plan_hash": plan.content_hash,
                "applied_effect_ids": list(applied_effect_ids),
            }
        )
    ).hexdigest()
    effects: list[HostEffect] = []
    for ordinal, kind in enumerate(kinds):
        effect, projected = _make_effect(
            projected,
            ordinal=ordinal,
            phase="rollback",
            kind=kind,
            release_manifest=plan.release_manifest,
            model_manifest=plan.model_manifest,
            identity_seed=identity_seed,
            ownership_token=plan.ownership_token,
        )
        effects.append(effect)
    seed = {
        "operation_id": operation_id,
        "ownership_token": plan.ownership_token,
        "plan_hash": plan.content_hash,
        "source_applied_effect_ids": list(applied_effect_ids),
        "effect_hashes": [effect.content_hash for effect in effects],
    }
    rollback_id = "rollback-" + hashlib.sha256(canonical_controller_bytes(seed)).hexdigest()[:32]
    return RollbackPlan(
        rollback_id=rollback_id,
        operation_id=operation_id,
        ownership_token=plan.ownership_token,
        plan_hash=plan.content_hash,
        source_applied_effect_ids=applied_effect_ids,
        effects=tuple(effects),
        terminal_state="rolled_back_clean",
        availability="unavailable",
        production_eligible=False,
    )


__all__ = (
    "APPLY_EFFECT_KINDS",
    "AuthorizationConsumption",
    "AuthorizationRequest",
    "BoundedTreeManifest",
    "CONTROLLER_ACCOUNT",
    "CONTROLLER_GID",
    "CONTROLLER_GROUP",
    "CONTROLLER_POLICY_CONTENT_HASH",
    "CONTROLLER_POLICY_SERIALIZED_SHA256",
    "CONTROLLER_UID",
    "ControllerContractError",
    "ControllerPlan",
    "EFFECT_KINDS",
    "HostEffect",
    "HostSnapshot",
    "INTERPRETER_CONTRACT_BYTES",
    "INTERPRETER_EFFECT_METHODS",
    "INTERPRETER_PATH",
    "InterpreterBinding",
    "MANAGED_ROOT",
    "MODEL_FINAL_ROOT",
    "MODEL_STAGE_ROOT",
    "ManifestEntry",
    "OPERATION_STATES",
    "OperationSnapshot",
    "RELEASE_FINAL_ROOT",
    "RELEASE_STAGE_ROOT",
    "ROLLBACK_EFFECT_KINDS",
    "RollbackPlan",
    "SERVICE_UNIT_BYTES",
    "SERVICE_UNIT_NAME",
    "SOCKET_UNIT_BYTES",
    "SOCKET_UNIT_NAME",
    "PrincipalObservation",
    "UNIT_DIRECTORY",
    "UnitObservation",
    "build_controller_plan",
    "build_rollback_plan",
    "canonical_controller_bytes",
    "canonical_interpreter_binding",
    "classify_effect_snapshot",
    "make_empty_host_snapshot",
    "host_projection_hash",
    "is_reusable_clean_projection",
    "project_effect",
)
