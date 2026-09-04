"""Canonical static-build contracts for the ADR-0050 D2.2a codec probes.

This module is platform-neutral and performs no filesystem access, compilation,
installation, socket work, host observation, or effect execution.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, fields

FORMAT_VERSION = 1
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_ENTRIES = 4096

_ZERO_HASH = "0" * 64
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_BUILD_ID_RE = re.compile(r"^[0-9a-f]{40}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9_.:-]{2,127}$")
_SOURCE_ROLES = frozenset(
    {
        "shared_codec_header",
        "shared_codec_source",
        "codec_initiator_source",
        "codec_responder_source",
        "build_driver_source",
        "contract_source",
        "protocol_lock",
        "toolchain_lock",
        "license",
        "notice",
    }
)
CANONICAL_SOURCE_INVENTORY_D22A = (
    ("LICENSE", "license"),
    ("THIRD_PARTY_NOTICES.md", "notice"),
    ("native/ollama_v2_control/codec_initiator.c", "codec_initiator_source"),
    ("native/ollama_v2_control/codec_responder.c", "codec_responder_source"),
    ("native/ollama_v2_control/protocol-lock.json", "protocol_lock"),
    ("native/ollama_v2_control/toolchain-lock.json", "toolchain_lock"),
    ("native/ollama_v2_control/wf_ov2_protocol.c", "shared_codec_source"),
    ("native/ollama_v2_control/wf_ov2_protocol.h", "shared_codec_header"),
    ("scripts/build_ollama_v2_native.py", "build_driver_source"),
    (
        "src/worldforge/provider_evidence/ollama_v2_native_build_contracts.py",
        "contract_source",
    ),
)
_ELF_FILENAMES = {
    "codec_initiator_probe": "worldforge-ollama-v2-codec-initiator-d22a",
    "codec_responder_probe": "worldforge-ollama-v2-codec-responder-d22a",
}

__all__ = (
    "FORMAT_VERSION",
    "MAX_DOCUMENT_BYTES",
    "CANONICAL_SOURCE_INVENTORY_D22A",
    "OllamaV2NativeBuildContractError",
    "OllamaV2NativeSourceEntryV1",
    "OllamaV2NativeSourceManifestD22A",
    "OllamaV2NativeBuildProfileD22A",
    "OllamaV2NativeToolchainEntryV1",
    "OllamaV2NativeToolchainManifestD22A",
    "OllamaV2NativeElfEntryV1",
    "OllamaV2NativeStaticBundleManifestD22A",
    "OllamaV2NativeTwoRootReceiptD22A",
    "canonical_ollama_v2_native_build_bytes",
    "canonical_ollama_v2_native_build_profile_d22a",
    "parse_ollama_v2_native_build_contract",
    "validate_ollama_v2_native_build_lineage_d22a",
)


class OllamaV2NativeBuildContractError(ValueError):
    """Raised when a D2.2a static-build contract fails closed validation."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _fail(reason: str) -> None:
    raise OllamaV2NativeBuildContractError(reason)


def _text(value: object, reason: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        _fail(reason)
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail(reason)
    if unicodedata.normalize("NFC", value) != value:
        _fail(reason)
    return value


def _identifier(value: object, reason: str) -> str:
    result = _text(value, reason)
    if _ID_RE.fullmatch(result) is None:
        _fail(reason)
    return result


def _digest(value: object, reason: str) -> str:
    result = _text(value, reason)
    if _HASH_RE.fullmatch(result) is None or result == _ZERO_HASH:
        _fail(reason)
    return result


def _integer(value: object, reason: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        _fail(reason)
    return value


def _boolean(value: object, reason: str) -> bool:
    if type(value) is not bool:
        _fail(reason)
    return value


def _logical_path(value: object, reason: str) -> str:
    result = _text(value, reason)
    if (
        result.startswith("/")
        or "\\" in result
        or "\x00" in result
        or any(part in {"", ".", ".."} for part in result.split("/"))
    ):
        _fail(reason)
    return result


def _absolute_path(value: object, reason: str) -> str:
    result = _text(value, reason)
    if (
        not result.startswith("/")
        or "\\" in result
        or "\x00" in result
        or any(part in {"", ".", ".."} for part in result[1:].split("/"))
    ):
        _fail(reason)
    return result


def _copy_json(value: object, *, depth: int = 1) -> object:
    if depth > 40:
        _fail("native_build_document_invalid")
    if type(value) is dict:
        return {
            _text(key, "native_build_document_invalid", allow_empty=True): _copy_json(
                item, depth=depth + 1
            )
            for key, item in dict.items(value)
        }
    if type(value) is list:
        return [_copy_json(item, depth=depth + 1) for item in list.__iter__(value)]
    if value is None or type(value) is bool:
        return value
    if type(value) is str:
        return _text(value, "native_build_document_invalid", allow_empty=True)
    if type(value) is int and -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        return value
    _fail("native_build_document_invalid")


def canonical_ollama_v2_native_build_bytes(value: object) -> bytes:
    checked = _copy_json(value)
    try:
        result = json.dumps(
            checked,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("native_build_document_invalid")
    if len(result) > MAX_DOCUMENT_BYTES:
        _fail("native_build_document_invalid")
    return result


def _content_hash(document: object) -> str:
    checked = _copy_json(document)
    if type(checked) is not dict:
        _fail("native_build_document_invalid")
    checked.pop("content_hash", None)
    return hashlib.sha256(canonical_ollama_v2_native_build_bytes(checked)).hexdigest()


class _Canonical:
    __slots__ = ()
    _FORMAT = ""
    _REASON = "native_build_contract_invalid"
    _TUPLES: frozenset[str] = frozenset()

    def _payload(self) -> dict[str, object]:
        result: dict[str, object] = {"format": self._FORMAT, "format_version": FORMAT_VERSION}
        for field in fields(self):
            value = getattr(self, field.name)
            if field.name in self._TUPLES:
                value = [
                    item.to_document() if isinstance(item, _Canonical) else item for item in value
                ]
            result[field.name] = value
        return result

    @property
    def content_hash(self) -> str:
        return _content_hash(self._payload())

    def to_document(self) -> dict[str, object]:
        result = self._payload()
        result["content_hash"] = _content_hash(result)
        return result

    def to_bytes(self) -> bytes:
        return canonical_ollama_v2_native_build_bytes(self.to_document())


@dataclass(frozen=True, slots=True)
class OllamaV2NativeSourceEntryV1(_Canonical):
    logical_path: str
    artifact_role: str
    size_bytes: int
    sha256: str

    _FORMAT = "world-forge.private.ollama_v2_native_source_entry_v1"

    def __post_init__(self) -> None:
        _logical_path(self.logical_path, "native_build_source_entry_invalid")
        if type(self.artifact_role) is not str or self.artifact_role not in _SOURCE_ROLES:
            _fail("native_build_source_entry_invalid")
        _integer(self.size_bytes, "native_build_source_entry_invalid", minimum=1)
        _digest(self.sha256, "native_build_source_entry_invalid")


@dataclass(frozen=True, slots=True)
class OllamaV2NativeSourceManifestD22A(_Canonical):
    source_scope: str
    entries: tuple[OllamaV2NativeSourceEntryV1, ...]

    _FORMAT = "world-forge.private.ollama_v2_native_source_manifest_d22a"
    _TUPLES = frozenset({"entries"})

    def __post_init__(self) -> None:
        if self.source_scope != "ollama_v2_codec_probe_source_d22a":
            _fail("native_build_source_manifest_invalid")
        if type(self.entries) is not tuple or not 1 <= len(self.entries) <= MAX_ENTRIES:
            _fail("native_build_source_manifest_invalid")
        if any(type(entry) is not OllamaV2NativeSourceEntryV1 for entry in self.entries):
            _fail("native_build_source_manifest_invalid")
        paths = [entry.logical_path for entry in self.entries]
        if paths != sorted(paths, key=lambda item: item.encode("utf-8")):
            _fail("native_build_source_manifest_invalid")
        if len(paths) != len(set(paths)) or len(paths) != len({path.casefold() for path in paths}):
            _fail("native_build_source_manifest_invalid")


_CANONICAL_BUILD_PROFILE_FIELDS_D22A = (
    ("profile_id", "ollama_v2_codec_probe_linux_aarch64_d22a_v1"),
    ("target_os", "linux"),
    ("target_architecture", "aarch64"),
    ("executable_format", "elf64-little-aarch64-pie"),
    ("language_standard", "c17"),
    ("linkage", "dynamic-libc-loader-only"),
    ("compiler_driver", "/usr/bin/aarch64-linux-gnu-gcc-13"),
    ("compiler_version", "13.3.0"),
    ("binutils_version", "2.42"),
    ("glibc_version", "2.39"),
    ("dynamic_interpreter", "/lib/ld-linux-aarch64.so.1"),
    ("artifact_roles", ("codec_initiator_probe", "codec_responder_probe")),
    (
        "compile_flags",
        (
            "-std=c17",
            "-pedantic-errors",
            "-O2",
            "-fPIE",
            "-fno-common",
            "-fno-builtin",
            "-fvisibility=hidden",
            "-fstack-protector-strong",
            "-D_FORTIFY_SOURCE=3",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wconversion",
            "-Wsign-conversion",
            "-Wformat=2",
            "-Wshadow",
            "-Wstrict-prototypes",
            "-Wmissing-prototypes",
            "-Wundef",
            "-Wdate-time",
            "-Wstack-protector",
            "-ffunction-sections",
            "-fdata-sections",
        ),
    ),
    (
        "root_mapped_flags",
        (
            "-ffile-prefix-map={SOURCE_ROOT}=/usr/src/world-forge",
            "-fmacro-prefix-map={SOURCE_ROOT}=/usr/src/world-forge",
            "-fdebug-prefix-map={SOURCE_ROOT}=/usr/src/world-forge",
        ),
    ),
    (
        "link_flags",
        (
            "-v",
            "-pie",
            "-Wl,-z,relro,-z,now,-z,noexecstack",
            "-Wl,--as-needed,--build-id=sha1,--fatal-warnings,--gc-sections,--strip-all",
            "-Wl,--trace",
        ),
    ),
    (
        "environment",
        ("LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "SOURCE_DATE_EPOCH=0", "TZ=UTC"),
    ),
    ("byte_identity", "sha256-whole-elf"),
    ("gnu_build_id_semantics", "correlation-only"),
    (
        "compiler_link_diagnostic_sha256",
        "0d599bda5372f0455f4f2566cf7c31d6f28a2b260e8a9d1473dc91115ce608bc",
    ),
    (
        "source_inventory_sha256",
        "7f4a7ac2ed2c5a5c892abddf0fedb87689cacd29fdd1cd735fed75ac92682100",
    ),
    (
        "toolchain_inventory_sha256",
        "acdb15daa9f8e16853a78fcda554629af82405df19ecf4273b7ef07c87df0331",
    ),
    ("driver_descriptor_bound", True),
    ("subtool_paths_pre_post_verified", True),
    ("same_principal_or_root_coherent_substitution_resistant", False),
)


@dataclass(frozen=True, slots=True)
class OllamaV2NativeBuildProfileD22A(_Canonical):
    profile_id: str
    target_os: str
    target_architecture: str
    executable_format: str
    language_standard: str
    linkage: str
    compiler_driver: str
    compiler_version: str
    binutils_version: str
    glibc_version: str
    dynamic_interpreter: str
    artifact_roles: tuple[str, ...]
    compile_flags: tuple[str, ...]
    root_mapped_flags: tuple[str, ...]
    link_flags: tuple[str, ...]
    environment: tuple[str, ...]
    byte_identity: str
    gnu_build_id_semantics: str
    compiler_link_diagnostic_sha256: str
    source_inventory_sha256: str
    toolchain_inventory_sha256: str
    driver_descriptor_bound: bool
    subtool_paths_pre_post_verified: bool
    same_principal_or_root_coherent_substitution_resistant: bool

    _FORMAT = "world-forge.private.ollama_v2_native_build_profile_d22a"
    _TUPLES = frozenset(
        {"artifact_roles", "compile_flags", "root_mapped_flags", "link_flags", "environment"}
    )

    def __post_init__(self) -> None:
        for value in (
            self.profile_id,
            self.target_os,
            self.target_architecture,
            self.executable_format,
            self.language_standard,
            self.linkage,
            self.compiler_driver,
            self.compiler_version,
            self.binutils_version,
            self.glibc_version,
            self.dynamic_interpreter,
            self.byte_identity,
            self.gnu_build_id_semantics,
        ):
            _text(value, "native_build_profile_invalid")
        _digest(self.source_inventory_sha256, "native_build_profile_invalid")
        _digest(self.toolchain_inventory_sha256, "native_build_profile_invalid")
        _digest(self.compiler_link_diagnostic_sha256, "native_build_profile_invalid")
        for value in (
            self.driver_descriptor_bound,
            self.subtool_paths_pre_post_verified,
            self.same_principal_or_root_coherent_substitution_resistant,
        ):
            _boolean(value, "native_build_profile_invalid")
        for values in (
            self.artifact_roles,
            self.compile_flags,
            self.root_mapped_flags,
            self.link_flags,
            self.environment,
        ):
            if (
                type(values) is not tuple
                or not values
                or any(type(item) is not str for item in values)
            ):
                _fail("native_build_profile_invalid")
        observed = tuple((field.name, getattr(self, field.name)) for field in fields(self))
        if observed != _CANONICAL_BUILD_PROFILE_FIELDS_D22A:
            _fail("native_build_profile_invalid")


def canonical_ollama_v2_native_build_profile_d22a() -> OllamaV2NativeBuildProfileD22A:
    return OllamaV2NativeBuildProfileD22A(**dict(_CANONICAL_BUILD_PROFILE_FIELDS_D22A))


@dataclass(frozen=True, slots=True)
class OllamaV2NativeToolchainEntryV1(_Canonical):
    logical_role: str
    resolved_path: str
    size_bytes: int
    sha256: str

    _FORMAT = "world-forge.private.ollama_v2_native_toolchain_entry_v1"

    def __post_init__(self) -> None:
        _identifier(self.logical_role, "native_build_toolchain_entry_invalid")
        _absolute_path(self.resolved_path, "native_build_toolchain_entry_invalid")
        _integer(self.size_bytes, "native_build_toolchain_entry_invalid", minimum=1)
        _digest(self.sha256, "native_build_toolchain_entry_invalid")


@dataclass(frozen=True, slots=True)
class OllamaV2NativeToolchainManifestD22A(_Canonical):
    build_profile_hash: str
    compiler_specs_sha256: str
    entries: tuple[OllamaV2NativeToolchainEntryV1, ...]

    _FORMAT = "world-forge.private.ollama_v2_native_toolchain_manifest_d22a"
    _TUPLES = frozenset({"entries"})

    def __post_init__(self) -> None:
        _digest(self.build_profile_hash, "native_build_toolchain_manifest_invalid")
        _digest(self.compiler_specs_sha256, "native_build_toolchain_manifest_invalid")
        if type(self.entries) is not tuple or not 1 <= len(self.entries) <= MAX_ENTRIES:
            _fail("native_build_toolchain_manifest_invalid")
        if any(type(entry) is not OllamaV2NativeToolchainEntryV1 for entry in self.entries):
            _fail("native_build_toolchain_manifest_invalid")
        keys = [(entry.logical_role, entry.resolved_path) for entry in self.entries]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            _fail("native_build_toolchain_manifest_invalid")


@dataclass(frozen=True, slots=True)
class OllamaV2NativeElfEntryV1(_Canonical):
    artifact_role: str
    filename: str
    size_bytes: int
    sha256: str
    gnu_build_id: str

    _FORMAT = "world-forge.private.ollama_v2_native_elf_entry_v1"

    def __post_init__(self) -> None:
        if (
            type(self.artifact_role) is not str
            or self.artifact_role not in _ELF_FILENAMES
            or self.filename != _ELF_FILENAMES[self.artifact_role]
        ):
            _fail("native_build_elf_entry_invalid")
        _integer(self.size_bytes, "native_build_elf_entry_invalid", minimum=1)
        _digest(self.sha256, "native_build_elf_entry_invalid")
        if type(self.gnu_build_id) is not str or _BUILD_ID_RE.fullmatch(self.gnu_build_id) is None:
            _fail("native_build_elf_entry_invalid")


@dataclass(frozen=True, slots=True)
class OllamaV2NativeStaticBundleManifestD22A(_Canonical):
    source_manifest_hash: str
    build_profile_hash: str
    toolchain_manifest_hash: str
    entries: tuple[OllamaV2NativeElfEntryV1, ...]
    codec_implementation_state: str
    effect_interpreter_state: str
    installed: bool
    root_custody_verified: bool
    source_custody_verified: bool
    host_execution_enabled: bool
    native_evidence_verified: bool
    provider_execution_enabled: bool
    catalog_admitted: bool
    production_eligible: bool
    availability: str

    _FORMAT = "world-forge.private.ollama_v2_native_static_bundle_manifest_d22a"
    _TUPLES = frozenset({"entries"})

    def __post_init__(self) -> None:
        reason = "native_build_bundle_manifest_invalid"
        for digest in (
            self.source_manifest_hash,
            self.build_profile_hash,
            self.toolchain_manifest_hash,
        ):
            _digest(digest, reason)
        if type(self.entries) is not tuple or tuple(
            entry.artifact_role for entry in self.entries
        ) != (
            "codec_initiator_probe",
            "codec_responder_probe",
        ):
            _fail(reason)
        if any(type(entry) is not OllamaV2NativeElfEntryV1 for entry in self.entries):
            _fail(reason)
        if self.codec_implementation_state != "built" or self.effect_interpreter_state != "absent":
            _fail(reason)
        if self.availability != "unavailable":
            _fail(reason)
        for value in (
            self.installed,
            self.root_custody_verified,
            self.source_custody_verified,
            self.host_execution_enabled,
            self.native_evidence_verified,
            self.provider_execution_enabled,
            self.catalog_admitted,
            self.production_eligible,
        ):
            if _boolean(value, reason):
                _fail(reason)


@dataclass(frozen=True, slots=True)
class OllamaV2NativeTwoRootReceiptD22A(_Canonical):
    protocol_lock_hash: str
    source_manifest_hash: str
    build_profile_hash: str
    toolchain_manifest_hash: str
    static_bundle_manifest_hash: str
    root_labels: tuple[str, ...]
    root_a_entries: tuple[OllamaV2NativeElfEntryV1, ...]
    root_b_entries: tuple[OllamaV2NativeElfEntryV1, ...]
    comparison: str
    claim_scope: str

    _FORMAT = "world-forge.private.ollama_v2_native_two_root_receipt_d22a"
    _TUPLES = frozenset({"root_labels", "root_a_entries", "root_b_entries"})

    def __post_init__(self) -> None:
        reason = "native_build_two_root_receipt_invalid"
        for digest in (
            self.protocol_lock_hash,
            self.source_manifest_hash,
            self.build_profile_hash,
            self.toolchain_manifest_hash,
            self.static_bundle_manifest_hash,
        ):
            _digest(digest, reason)
        if self.root_labels != ("root-a", "different-root-b"):
            _fail(reason)
        expected_roles = ("codec_initiator_probe", "codec_responder_probe")
        for entries in (self.root_a_entries, self.root_b_entries):
            if (
                type(entries) is not tuple
                or any(type(entry) is not OllamaV2NativeElfEntryV1 for entry in entries)
                or tuple(entry.artifact_role for entry in entries) != expected_roles
            ):
                _fail(reason)
        if self.root_a_entries != self.root_b_entries:
            _fail(reason)
        if self.comparison != "byte-identical" or self.claim_scope != "static-codec-build-only":
            _fail(reason)


def validate_ollama_v2_native_build_lineage_d22a(
    bundle: object,
    source: object,
    profile: object,
    toolchain: object,
) -> None:
    if (
        type(bundle) is not OllamaV2NativeStaticBundleManifestD22A
        or type(source) is not OllamaV2NativeSourceManifestD22A
        or type(profile) is not OllamaV2NativeBuildProfileD22A
        or type(toolchain) is not OllamaV2NativeToolchainManifestD22A
        or profile != canonical_ollama_v2_native_build_profile_d22a()
        or toolchain.build_profile_hash != profile.content_hash
        or bundle.source_manifest_hash != source.content_hash
        or bundle.build_profile_hash != profile.content_hash
        or bundle.toolchain_manifest_hash != toolchain.content_hash
    ):
        _fail("native_build_lineage_invalid")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("native_build_json_duplicate_key")
        result[key] = value
    return result


def _reject_number(_: str) -> object:
    _fail("native_build_json_noncanonical")


def _decode(value: object) -> dict[str, object]:
    if type(value) is not bytes or not value or len(value) > MAX_DOCUMENT_BYTES:
        _fail("native_build_json_invalid")
    try:
        document = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except OllamaV2NativeBuildContractError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError):
        _fail("native_build_json_invalid")
    checked = _copy_json(document)
    if type(checked) is not dict or canonical_ollama_v2_native_build_bytes(checked) != value:
        _fail("native_build_json_noncanonical")
    return checked


def _entry_from_document(cls, value: object):
    if type(value) is not dict:
        _fail("native_build_contract_invalid")
    expected = {"format", "format_version", "content_hash", *(field.name for field in fields(cls))}
    if (
        set(value) != expected
        or value.get("format") != cls._FORMAT
        or value.get("format_version") != 1
    ):
        _fail("native_build_contract_invalid")
    kwargs = {field.name: value[field.name] for field in fields(cls)}
    result = cls(**kwargs)
    if value["content_hash"] != result.content_hash:
        _fail("native_build_contract_invalid")
    return result


def _contract_from_document(cls, document: dict[str, object]):
    expected = {"format", "format_version", "content_hash", *(field.name for field in fields(cls))}
    if (
        set(document) != expected
        or document.get("format") != cls._FORMAT
        or document.get("format_version") != 1
    ):
        _fail("native_build_contract_invalid")
    kwargs = {field.name: document[field.name] for field in fields(cls)}
    tuple_types = {
        OllamaV2NativeSourceManifestD22A: (("entries", OllamaV2NativeSourceEntryV1),),
        OllamaV2NativeToolchainManifestD22A: (("entries", OllamaV2NativeToolchainEntryV1),),
        OllamaV2NativeStaticBundleManifestD22A: (("entries", OllamaV2NativeElfEntryV1),),
        OllamaV2NativeTwoRootReceiptD22A: (
            ("root_a_entries", OllamaV2NativeElfEntryV1),
            ("root_b_entries", OllamaV2NativeElfEntryV1),
        ),
    }
    if cls is OllamaV2NativeBuildProfileD22A:
        for name in cls._TUPLES:
            if type(kwargs[name]) is not list:
                _fail("native_build_contract_invalid")
            kwargs[name] = tuple(kwargs[name])
    elif cls in tuple_types:
        for name, entry_cls in tuple_types[cls]:
            if type(kwargs[name]) is not list:
                _fail("native_build_contract_invalid")
            kwargs[name] = tuple(_entry_from_document(entry_cls, item) for item in kwargs[name])
        if cls is OllamaV2NativeTwoRootReceiptD22A:
            if type(kwargs["root_labels"]) is not list:
                _fail("native_build_contract_invalid")
            kwargs["root_labels"] = tuple(kwargs["root_labels"])
    result = cls(**kwargs)
    if document["content_hash"] != result.content_hash:
        _fail("native_build_contract_invalid")
    return result


def parse_ollama_v2_native_build_contract(value: object) -> _Canonical:
    document = _decode(value)
    parsers = {
        OllamaV2NativeSourceManifestD22A._FORMAT: OllamaV2NativeSourceManifestD22A,
        OllamaV2NativeBuildProfileD22A._FORMAT: OllamaV2NativeBuildProfileD22A,
        OllamaV2NativeToolchainManifestD22A._FORMAT: OllamaV2NativeToolchainManifestD22A,
        OllamaV2NativeStaticBundleManifestD22A._FORMAT: OllamaV2NativeStaticBundleManifestD22A,
        OllamaV2NativeTwoRootReceiptD22A._FORMAT: OllamaV2NativeTwoRootReceiptD22A,
    }
    cls = parsers.get(document.get("format"))
    if cls is None:
        _fail("native_build_format_unknown")
    return _contract_from_document(cls, document)
