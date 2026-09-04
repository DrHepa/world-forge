#!/usr/bin/env python3
"""Build and attest the Linux/aarch64 ADR-0050 D2.2a codec probes."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import platform
import re
import shlex
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import types
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


class NativeBuildError(RuntimeError):
    pass


class _SourceOnlyModuleSpec:
    __slots__ = ("has_location", "origin")

    def __init__(self, origin: str) -> None:
        self.origin = origin
        self.has_location = True


_CONTRACT_LOGICAL_PATH = PurePosixPath(
    "src/worldforge/provider_evidence/ollama_v2_native_build_contracts.py"
)
_SOURCE_ONLY_MODULE_SEQUENCE = 0


def _load_contract_source_only(source_root: Path) -> types.ModuleType:
    global _SOURCE_ONLY_MODULE_SEQUENCE
    root = Path(os.path.abspath(source_root))
    origin = root.joinpath(*_CONTRACT_LOGICAL_PATH.parts)
    descriptor = -1
    try:
        if Path(os.path.realpath(origin)) != origin:
            raise NativeBuildError("contract source-only origin is not canonical")
        before = origin.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise NativeBuildError("contract source-only origin is not a regular file")

        def identity_of(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
            return (
                int(info.st_mode),
                int(info.st_uid),
                int(info.st_gid),
                int(info.st_dev),
                int(info.st_ino),
                int(info.st_size),
                int(info.st_mtime_ns),
                int(info.st_ctime_ns),
            )

        identity = identity_of(before)
        descriptor = os.open(
            origin,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if identity_of(opened) != identity:
            raise NativeBuildError("contract source-only origin identity changed")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 64 * 1024):
            chunks.append(chunk)
        payload = b"".join(chunks)
        if (
            identity_of(os.fstat(descriptor)) != identity
            or len(payload) != before.st_size
            or identity_of(origin.lstat()) != identity
        ):
            raise NativeBuildError("contract source-only origin identity changed")
    except OSError as exc:
        raise NativeBuildError("contract source-only origin is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    module_name = (
        "_worldforge_ollama_v2_native_build_contracts_source_only_d22a_"
        f"{_SOURCE_ONLY_MODULE_SEQUENCE}"
    )
    _SOURCE_ONLY_MODULE_SEQUENCE += 1
    module = types.ModuleType(module_name)
    module.__file__ = str(origin)
    module.__cached__ = None
    module.__loader__ = None
    module.__package__ = ""
    module.__spec__ = _SourceOnlyModuleSpec(str(origin))
    module.__source_only_identity__ = identity
    module.__source_only_payload__ = payload
    sys.modules[module_name] = module
    try:
        code = compile(payload, str(origin), "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__)
        if (
            module.__source_only_identity__ != identity
            or module.__source_only_payload__ != payload
            or module.__cached__ is not None
        ):
            raise NativeBuildError("contract source-only module metadata changed")
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module


_build_contracts_module = _load_contract_source_only(ROOT)
CANONICAL_SOURCE_INVENTORY_D22A = _build_contracts_module.CANONICAL_SOURCE_INVENTORY_D22A
OllamaV2NativeBuildContractError = _build_contracts_module.OllamaV2NativeBuildContractError
OllamaV2NativeElfEntryV1 = _build_contracts_module.OllamaV2NativeElfEntryV1
OllamaV2NativeSourceEntryV1 = _build_contracts_module.OllamaV2NativeSourceEntryV1
OllamaV2NativeSourceManifestD22A = _build_contracts_module.OllamaV2NativeSourceManifestD22A
OllamaV2NativeStaticBundleManifestD22A = (
    _build_contracts_module.OllamaV2NativeStaticBundleManifestD22A
)
OllamaV2NativeToolchainEntryV1 = _build_contracts_module.OllamaV2NativeToolchainEntryV1
OllamaV2NativeToolchainManifestD22A = _build_contracts_module.OllamaV2NativeToolchainManifestD22A
OllamaV2NativeTwoRootReceiptD22A = _build_contracts_module.OllamaV2NativeTwoRootReceiptD22A
canonical_ollama_v2_native_build_bytes = (
    _build_contracts_module.canonical_ollama_v2_native_build_bytes
)
canonical_ollama_v2_native_build_profile_d22a = (
    _build_contracts_module.canonical_ollama_v2_native_build_profile_d22a
)
parse_ollama_v2_native_build_contract = (
    _build_contracts_module.parse_ollama_v2_native_build_contract
)
validate_ollama_v2_native_build_lineage_d22a = (
    _build_contracts_module.validate_ollama_v2_native_build_lineage_d22a
)

NATIVE_ROOT = PurePosixPath("native/ollama_v2_control")
PROTOCOL_LOCK = NATIVE_ROOT / "protocol-lock.json"
SOURCE_LOCK = NATIVE_ROOT / "source-lock.json"
TOOLCHAIN_LOCK = NATIVE_ROOT / "toolchain-lock.json"
SOURCE_FILES = (
    NATIVE_ROOT / "wf_ov2_protocol.c",
    NATIVE_ROOT / "wf_ov2_protocol.h",
    NATIVE_ROOT / "codec_initiator.c",
    NATIVE_ROOT / "codec_responder.c",
)
OUTPUT_NAME = "world-forge-ollama-v2-codec-d22a-linux-aarch64.tar.gz"
ROLE_FILENAMES = {
    "codec_initiator_probe": "worldforge-ollama-v2-codec-initiator-d22a",
    "codec_responder_probe": "worldforge-ollama-v2-codec-responder-d22a",
}
EXPECTED_SECTIONS = (
    "",
    ".interp",
    ".note.gnu.build-id",
    ".note.ABI-tag",
    ".gnu.hash",
    ".dynsym",
    ".dynstr",
    ".gnu.version",
    ".gnu.version_r",
    ".rela.dyn",
    ".rela.plt",
    ".init",
    ".plt",
    ".text",
    ".fini",
    ".rodata",
    ".eh_frame_hdr",
    ".eh_frame",
    ".init_array",
    ".fini_array",
    ".dynamic",
    ".got",
    ".data",
    ".bss",
    ".comment",
    ".shstrtab",
)
EXPECTED_NEEDED = ("libc.so.6", "ld-linux-aarch64.so.1")
_COMMON_DYNAMIC_SYMBOLS = (
    "_ITM_deregisterTMCloneTable",
    "_ITM_registerTMCloneTable",
    "__cxa_finalize",
    "__errno_location",
    "__gmon_start__",
    "__libc_start_main",
    "__stack_chk_fail",
    "__stack_chk_guard",
    "abort",
    "clock_gettime",
    "close",
    "getsockopt",
    "ppoll",
    "recvmsg",
    "sendmsg",
    "setsockopt",
    "shutdown",
    "timerfd_create",
    "timerfd_settime",
)
EXPECTED_DYNAMIC_SYMBOLS = {
    "codec_initiator_probe": tuple(sorted((*_COMMON_DYNAMIC_SYMBOLS, "getrandom"))),
    "codec_responder_probe": tuple(sorted(_COMMON_DYNAMIC_SYMBOLS)),
}
EXPECTED_VERSION_REQUIREMENTS = {
    "codec_initiator_probe": (
        ("ld-linux-aarch64.so.1", ("GLIBC_2.17",)),
        ("libc.so.6", ("GLIBC_2.25", "GLIBC_2.34", "GLIBC_2.17")),
    ),
    "codec_responder_probe": (
        ("ld-linux-aarch64.so.1", ("GLIBC_2.17",)),
        ("libc.so.6", ("GLIBC_2.34", "GLIBC_2.17")),
    ),
}
_SYMBOL_VERSION = {
    "_ITM_deregisterTMCloneTable": ("", ""),
    "_ITM_registerTMCloneTable": ("", ""),
    "__cxa_finalize": ("libc.so.6", "GLIBC_2.17"),
    "__errno_location": ("libc.so.6", "GLIBC_2.17"),
    "__gmon_start__": ("", ""),
    "__libc_start_main": ("libc.so.6", "GLIBC_2.34"),
    "__stack_chk_fail": ("libc.so.6", "GLIBC_2.17"),
    "__stack_chk_guard": ("ld-linux-aarch64.so.1", "GLIBC_2.17"),
    "abort": ("libc.so.6", "GLIBC_2.17"),
    "clock_gettime": ("libc.so.6", "GLIBC_2.17"),
    "close": ("libc.so.6", "GLIBC_2.17"),
    "getrandom": ("libc.so.6", "GLIBC_2.25"),
    "getsockopt": ("libc.so.6", "GLIBC_2.17"),
    "ppoll": ("libc.so.6", "GLIBC_2.17"),
    "recvmsg": ("libc.so.6", "GLIBC_2.17"),
    "sendmsg": ("libc.so.6", "GLIBC_2.17"),
    "setsockopt": ("libc.so.6", "GLIBC_2.17"),
    "shutdown": ("libc.so.6", "GLIBC_2.17"),
    "timerfd_create": ("libc.so.6", "GLIBC_2.17"),
    "timerfd_settime": ("libc.so.6", "GLIBC_2.17"),
}
EXPECTED_SYMBOL_VERSIONS = {
    role: tuple((name, *_SYMBOL_VERSION[name]) for name in symbols)
    for role, symbols in EXPECTED_DYNAMIC_SYMBOLS.items()
}
DOMAIN = b"worldforge-ollama-v2-d22a-build-receipt-v1\0"
SOURCE_INVENTORY_DOMAIN = b"worldforge-ollama-v2-d22a-source-inventory-v1\0"
TOOLCHAIN_INVENTORY_DOMAIN = b"worldforge-ollama-v2-d22a-toolchain-inventory-v1\0"
TOOLCHAIN_INVENTORY_ENTRIES = 126
TOOL_EXECUTABLE_ROLES = (
    "compiler_driver",
    "compiler_frontend",
    "compiler_lto_wrapper",
    "assembler",
    "compiler_collector",
    "linker",
)
TOOL_SHARED_OBJECT_INPUTS = (("linker_plugin", "liblto_plugin.so"),)
TOOL_RUNTIME_PROVIDERS = (
    (
        "dynamic_loader",
        "ld-linux-aarch64.so.1",
        "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
    ),
    ("libc_runtime", "libc.so.6", "/usr/lib/aarch64-linux-gnu/libc.so.6"),
    (
        "tool_runtime_libbfd",
        "libbfd-2.42-system.so",
        "/usr/lib/aarch64-linux-gnu/libbfd-2.42-system.so",
    ),
    (
        "tool_runtime_libctf",
        "libctf.so.0",
        "/usr/lib/aarch64-linux-gnu/libctf.so.0.0.0",
    ),
    (
        "tool_runtime_libgmp",
        "libgmp.so.10",
        "/usr/lib/aarch64-linux-gnu/libgmp.so.10.5.0",
    ),
    (
        "tool_runtime_libisl",
        "libisl.so.23",
        "/usr/lib/aarch64-linux-gnu/libisl.so.23.3.0",
    ),
    (
        "tool_runtime_libjansson",
        "libjansson.so.4",
        "/usr/lib/aarch64-linux-gnu/libjansson.so.4.14.0",
    ),
    ("tool_runtime_libm", "libm.so.6", "/usr/lib/aarch64-linux-gnu/libm.so.6"),
    (
        "tool_runtime_libmpc",
        "libmpc.so.3",
        "/usr/lib/aarch64-linux-gnu/libmpc.so.3.3.1",
    ),
    (
        "tool_runtime_libmpfr",
        "libmpfr.so.6",
        "/usr/lib/aarch64-linux-gnu/libmpfr.so.6.2.1",
    ),
    (
        "tool_runtime_libopcodes",
        "libopcodes-2.42-system.so",
        "/usr/lib/aarch64-linux-gnu/libopcodes-2.42-system.so",
    ),
    (
        "tool_runtime_libsframe",
        "libsframe.so.1",
        "/usr/lib/aarch64-linux-gnu/libsframe.so.1.0.0",
    ),
    (
        "tool_runtime_libz",
        "libz.so.1",
        "/usr/lib/aarch64-linux-gnu/libz.so.1.3",
    ),
    (
        "tool_runtime_libzstd",
        "libzstd.so.1",
        "/usr/lib/aarch64-linux-gnu/libzstd.so.1.5.5",
    ),
)
LOADER_CACHE_ROLE = "loader_cache"
LOADER_CACHE_PATH = "/etc/ld.so.cache"
LOADER_PRELOAD_PATH = Path("/etc/ld.so.preload")
FORBIDDEN_LOADER_ENVIRONMENT = frozenset({"LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD"})
LINKER_SEARCH_DIRECTORIES = (
    Path("/usr/lib/gcc/aarch64-linux-gnu/13"),
    Path("/usr/lib/aarch64-linux-gnu"),
)
LINKER_SCRIPT_CLOSURE = (
    (
        "libc_linker_script",
        "/usr/lib/aarch64-linux-gnu/libc.so",
        (
            ("libc_runtime", "/usr/lib/aarch64-linux-gnu/libc.so.6", False),
            ("libc_nonshared_archive", "/usr/lib/aarch64-linux-gnu/libc_nonshared.a", False),
            ("dynamic_loader", "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", True),
        ),
    ),
    (
        "libgcc_linker_script",
        "/usr/lib/gcc/aarch64-linux-gnu/13/libgcc_s.so",
        (
            ("libgcc_shared", "/usr/lib/aarch64-linux-gnu/libgcc_s.so.1", False),
            ("libgcc_archive", "/usr/lib/gcc/aarch64-linux-gnu/13/libgcc.a", False),
        ),
    ),
)
LINK_DIAGNOSTIC_GENERATED_ROLES = (
    "generated_protocol_object",
    "generated_main_object",
)
LINK_RESOLUTION_OPTION_RE = re.compile(r"-plugin-opt=-fresolution=/tmp/cc[A-Za-z0-9]{6}\.res")


@dataclass(frozen=True, slots=True)
class ElfInspection:
    machine: int
    elf_type: int
    interpreter: str
    needed: tuple[str, ...]
    build_id: str
    sections: tuple[str, ...]
    dynamic_symbols: tuple[str, ...]
    version_requirements: tuple[tuple[str, tuple[str, ...]], ...]
    symbol_versions: tuple[tuple[str, str, str], ...]
    pie: bool
    bind_now: bool
    relro: bool
    nx_stack: bool
    writable_executable_load: bool
    rpath_present: bool
    runpath_present: bool
    textrel_present: bool


@dataclass(frozen=True, slots=True)
class ElfRuntimeRequirements:
    machine: int
    elf_type: int
    interpreter: str
    soname: str
    needed: tuple[str, ...]
    path_override_present: bool
    audit_or_filter_present: bool


@dataclass(frozen=True, slots=True)
class _RetainedSourceEntry:
    contract: OllamaV2NativeSourceEntryV1
    path: Path
    descriptor: int
    identity: tuple[int, int, int, int, int, int, int, int]
    payload: bytes


@dataclass(frozen=True, slots=True)
class _ActiveImplementationIdentity:
    artifact_role: str
    logical_path: str
    module_name: str
    module: object
    module_spec: object | None
    origin: Path
    identity: tuple[int, int, int, int, int, int, int, int]
    payload: bytes
    sha256: str


@dataclass(slots=True)
class _RetainedSource:
    manifest: OllamaV2NativeSourceManifestD22A
    entries: tuple[_RetainedSourceEntry, ...]

    def payload_for(self, relative: PurePosixPath | str) -> bytes:
        name = str(relative)
        matches = [entry.payload for entry in self.entries if entry.contract.logical_path == name]
        if len(matches) != 1:
            raise NativeBuildError(f"retained source census is invalid: {name}")
        return matches[0]

    def close(self) -> None:
        for entry in self.entries:
            try:
                os.close(entry.descriptor)
            except OSError:
                pass


@dataclass(frozen=True, slots=True)
class _RetainedToolchainEntry:
    contract: OllamaV2NativeToolchainEntryV1
    path: Path
    descriptor: int
    identity: tuple[int, int, int, int, int, int, int, int]


@dataclass(slots=True)
class _RetainedToolchain:
    manifest: OllamaV2NativeToolchainManifestD22A
    entries: tuple[_RetainedToolchainEntry, ...]

    def close(self) -> None:
        for entry in self.entries:
            try:
                os.close(entry.descriptor)
            except OSError:
                pass


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_regular(root: Path, relative: PurePosixPath) -> bytes:
    path = root.joinpath(*relative.parts)
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise NativeBuildError(f"locked input is not a regular file: {relative}")
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise NativeBuildError(f"could not open locked input {relative}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != identity:
            raise NativeBuildError(f"locked input identity changed: {relative}")
        chunks: list[bytes] = []
        while data := os.read(descriptor, 64 * 1024):
            chunks.append(data)
        after = os.fstat(descriptor)
        named = path.lstat()
        for current in (after, named):
            if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != identity:
                raise NativeBuildError(f"locked input identity changed: {relative}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _canonical_document(value: dict[str, object]) -> bytes:
    payload = dict(value)
    payload.pop("content_hash", None)
    value = dict(payload)
    value["content_hash"] = _sha256(canonical_ollama_v2_native_build_bytes(payload))
    return canonical_ollama_v2_native_build_bytes(value)


def _parse_protocol_lock(raw: bytes) -> dict[str, object]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise NativeBuildError("protocol lock is invalid JSON") from exc
    expected = {
        "format": "world-forge.private.ollama_v2_probe_protocol_lock_d22a",
        "format_version": 1,
        "magic_hex": "5746353044323241",
        "byte_order": "big-endian",
        "header_size": 120,
        "header_fields": [
            ["magic", 0, 8],
            ["major", 8, 2],
            ["header_len", 10, 2],
            ["type", 12, 2],
            ["flags", 14, 2],
            ["sequence", 16, 8],
            ["body_len", 24, 4],
            ["fd_count", 28, 2],
            ["reserved", 30, 2],
            ["nonce", 32, 16],
            ["deadline_ns", 48, 8],
            ["prior_packet_sha256", 56, 32],
            ["body_sha256", 88, 32],
        ],
        "max_body_size": 48,
        "max_record_size": 168,
        "negotiate_type": 1,
        "negotiate_body_size": 24,
        "negotiate_fields": [
            ["minimum_major", 0, 2, 1],
            ["maximum_major", 2, 2, 1],
            ["maximum_body", 4, 4, 48],
            ["maximum_record", 8, 4, 168],
            ["feature_flags", 12, 2, 0],
            ["reserved", 14, 2, 0],
            ["negotiate_type", 16, 2, 1],
            ["unavailable_type", 18, 2, 2],
            ["message_count", 20, 2, 2],
            ["fd_count", 22, 2, 0],
        ],
        "unavailable_type": 2,
        "unavailable_body_size": 48,
        "unavailable_fields": [
            ["selected_major", 0, 2, 1],
            ["terminal_class", 2, 2, 1],
            ["reason", 4, 4, 1],
            ["request_sequence", 8, 8, 0],
            ["request_packet_sha256", 16, 32, "request_packet_sha256"],
        ],
        "packet_hash_domain": "worldforge-ollama-v2-d22a-packet-v1\0",
        "packet_hash_rule": "sha256(domain_nul || completed_header || body)",
        "sequence_rule": "request=0 prior=zero; response=1 prior=request_packet_sha256",
        "nonce_rule": "request nonzero 16 bytes; response exact request nonce",
        "deadline_rule": "CLOCK_BOOTTIME absolute; now < deadline <= now + 5000000000",
        "fd_count": 0,
        "socket_requirements": [
            "connected AF_UNIX SOCK_SEQPACKET on stdin",
            "SO_PASSCRED enabled and read back",
            "exactly one SCM_CREDENTIALS per record",
            "MSG_CMSG_CLOEXEC",
            "no SCM_RIGHTS",
            "zero-length SOCK_SEQPACKET records are not EOF",
        ],
        "exit_statuses": [
            ["success", 0],
            ["argument", 64],
            ["protocol", 65],
            ["sequence_or_state", 66],
            ["socket_or_ancillary", 67],
            ["io_or_truncated", 68],
            ["nonce_or_deadline", 69],
            ["hash", 70],
        ],
        "effect_execution": "rejected",
    }
    if type(document) is not dict or set(document) != {*expected, "content_hash"}:
        raise NativeBuildError("protocol lock shape is invalid")
    if any(
        document[key] != value or type(document[key]) is not type(value)
        for key, value in expected.items()
    ):
        raise NativeBuildError("protocol lock value is invalid")
    if raw != _canonical_document(document):
        raise NativeBuildError("protocol lock is not canonical or correctly hashed")
    return document


def _load_protocol_lock(source_root: Path) -> tuple[dict[str, object], bytes]:
    raw = _read_regular(source_root, PROTOCOL_LOCK)
    return _parse_protocol_lock(raw), raw


def _parse_contract(raw: bytes, relative: PurePosixPath, expected_type: type):
    try:
        value = parse_ollama_v2_native_build_contract(raw)
    except OllamaV2NativeBuildContractError as exc:
        raise NativeBuildError(f"invalid locked manifest {relative}: {exc}") from exc
    if type(value) is not expected_type:
        raise NativeBuildError(f"wrong locked manifest type: {relative}")
    return value


def _load_contract(source_root: Path, relative: PurePosixPath, expected_type: type):
    raw = _read_regular(source_root, relative)
    return _parse_contract(raw, relative, expected_type), raw


def _inventory_sha256(domain: bytes, entries: tuple[tuple[str, str], ...]) -> str:
    payload = [[left, right] for left, right in entries]
    return _sha256(domain + canonical_ollama_v2_native_build_bytes(payload))


def _retain_source_entry(
    source_root: Path,
    entry: OllamaV2NativeSourceEntryV1,
) -> _RetainedSourceEntry:
    path = source_root.joinpath(*PurePosixPath(entry.logical_path).parts)
    descriptor = -1
    try:
        before = _path_lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise NativeBuildError(f"source entry is not a regular file: {entry.logical_path}")
        identity = _file_identity(before)
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        if _file_identity(os.fstat(descriptor)) != identity:
            raise NativeBuildError(f"source path identity changed: {entry.logical_path}")
        payload = _read_descriptor_bytes(descriptor)
        if len(payload) != entry.size_bytes or _sha256(payload) != entry.sha256:
            raise NativeBuildError(f"source lock mismatch: {entry.logical_path}")
        if _file_identity(_path_lstat(path)) != identity:
            raise NativeBuildError(f"source path identity changed: {entry.logical_path}")
        return _RetainedSourceEntry(entry, path, descriptor, identity, payload)
    except OSError as exc:
        raise NativeBuildError(f"source entry is unavailable: {entry.logical_path}") from exc
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _verify_source_lock(
    source_root: Path,
    manifest: OllamaV2NativeSourceManifestD22A,
) -> _RetainedSource:
    profile = canonical_ollama_v2_native_build_profile_d22a()
    inventory = tuple((entry.logical_path, entry.artifact_role) for entry in manifest.entries)
    if (
        inventory != CANONICAL_SOURCE_INVENTORY_D22A
        or _inventory_sha256(SOURCE_INVENTORY_DOMAIN, inventory) != profile.source_inventory_sha256
    ):
        raise NativeBuildError("source manifest census does not match the canonical inventory")
    retained_entries: list[_RetainedSourceEntry] = []
    try:
        for entry in manifest.entries:
            retained_entries.append(_retain_source_entry(source_root, entry))
        return _RetainedSource(manifest, tuple(retained_entries))
    except Exception:
        for retained in retained_entries:
            os.close(retained.descriptor)
        raise


def _reverify_source_lock(source: _RetainedSource) -> None:
    for retained in source.entries:
        path = retained.path
        name = retained.contract.logical_path
        descriptor = -1
        try:
            named_before = _path_lstat(path)
            if stat.S_ISLNK(named_before.st_mode) or not stat.S_ISREG(named_before.st_mode):
                raise NativeBuildError(f"source path identity changed: {name}")
            if _file_identity(named_before) != retained.identity:
                raise NativeBuildError(f"source path identity changed: {name}")
            if _file_identity(os.fstat(retained.descriptor)) != retained.identity:
                raise NativeBuildError(f"retained source identity changed: {name}")
            if _read_descriptor_bytes(retained.descriptor) != retained.payload:
                raise NativeBuildError(f"retained source byte identity changed: {name}")
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            )
            if _file_identity(os.fstat(descriptor)) != retained.identity:
                raise NativeBuildError(f"source path identity changed: {name}")
            if _read_descriptor_bytes(descriptor) != retained.payload:
                raise NativeBuildError(f"source byte identity changed: {name}")
            if _file_identity(_path_lstat(path)) != retained.identity:
                raise NativeBuildError(f"source path identity changed: {name}")
        except OSError as exc:
            raise NativeBuildError(f"source entry is unavailable: {name}") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def _single_toolchain_path(
    manifest: OllamaV2NativeToolchainManifestD22A,
    logical_role: str,
) -> str:
    matches = [
        entry.resolved_path for entry in manifest.entries if entry.logical_role == logical_role
    ]
    if len(matches) != 1:
        raise NativeBuildError(f"toolchain role census is invalid: {logical_role}")
    return matches[0]


def _path_lstat(path: Path) -> os.stat_result:
    return path.lstat()


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        int(info.st_mode),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def _assert_secure_toolchain_path(path: Path) -> None:
    if not path.is_absolute() or Path(os.path.abspath(path)) != path:
        raise NativeBuildError(f"toolchain path is not canonical: {path}")
    try:
        if Path(os.path.realpath(path)) != path:
            raise NativeBuildError(f"toolchain path is a symlink or is not canonical: {path}")
        chain = (path, *path.parents)
        for index, current in enumerate(chain):
            info = _path_lstat(current)
            if stat.S_ISLNK(info.st_mode):
                raise NativeBuildError(f"toolchain path contains a symlink: {current}")
            expected_type = stat.S_ISREG if index == 0 else stat.S_ISDIR
            if not expected_type(info.st_mode):
                raise NativeBuildError(f"toolchain path has the wrong file type: {current}")
            if info.st_uid != 0:
                raise NativeBuildError(f"toolchain path is not root-owned: {current}")
            if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise NativeBuildError(f"toolchain path is group/world-writable: {current}")
    except OSError as exc:
        raise NativeBuildError(f"toolchain entry is unavailable: {path}") from exc


def _assert_no_loader_overrides(env: dict[str, str] | None = None) -> None:
    active = FORBIDDEN_LOADER_ENVIRONMENT.intersection(os.environ)
    supplied = FORBIDDEN_LOADER_ENVIRONMENT.intersection(env or {})
    if active or supplied:
        names = ",".join(sorted(active | supplied))
        raise NativeBuildError(f"dynamic loader override is prohibited: {names}")
    try:
        _path_lstat(LOADER_PRELOAD_PATH)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise NativeBuildError("could not verify absence of /etc/ld.so.preload") from exc
    raise NativeBuildError("system dynamic loader override /etc/ld.so.preload is prohibited")


def _read_descriptor_bytes(descriptor: int) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while payload := os.read(descriptor, 64 * 1024):
            chunks.append(payload)
        return b"".join(chunks)
    except OSError as exc:
        raise NativeBuildError("could not read a retained input descriptor") from exc
    finally:
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
        except OSError:
            pass


def _active_module_origin(
    module: object,
    logical_path: str,
    *,
    allow_missing_spec: bool,
) -> Path:
    raw_file = getattr(module, "__file__", None)
    if type(raw_file) is not str or not raw_file:
        raise NativeBuildError("active implementation module origin is invalid")
    origin = Path(os.path.abspath(raw_file))
    spec = getattr(module, "__spec__", None)
    if spec is None:
        if not allow_missing_spec:
            raise NativeBuildError("active implementation module origin is invalid")
    else:
        raw_spec_origin = getattr(spec, "origin", None)
        if (
            type(raw_spec_origin) is not str
            or Path(os.path.abspath(raw_spec_origin)) != origin
            or getattr(spec, "has_location", None) is not True
        ):
            raise NativeBuildError("active implementation module origin is invalid")
    logical_parts = PurePosixPath(logical_path).parts
    if (
        not origin.is_absolute()
        or len(origin.parts) <= len(logical_parts)
        or origin.parts[-len(logical_parts) :] != logical_parts
        or Path(os.path.realpath(origin)) != origin
    ):
        raise NativeBuildError("active implementation module origin is invalid")
    return origin


def _capture_active_implementation_identity(
    artifact_role: str,
    logical_path: str,
    module: object,
    *,
    active_root: Path | None,
    allow_missing_spec: bool,
) -> tuple[Path, _ActiveImplementationIdentity]:
    origin = _active_module_origin(
        module,
        logical_path,
        allow_missing_spec=allow_missing_spec,
    )
    logical_parts = PurePosixPath(logical_path).parts
    discovered_root = origin.parents[len(logical_parts) - 1]
    if active_root is not None and (
        discovered_root != active_root or origin != active_root.joinpath(*logical_parts)
    ):
        raise NativeBuildError("active implementation module origin is incoherent")
    descriptor = -1
    try:
        before = _path_lstat(origin)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise NativeBuildError("active implementation module origin is not a regular file")
        identity = _file_identity(before)
        descriptor = os.open(
            origin,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        if _file_identity(os.fstat(descriptor)) != identity:
            raise NativeBuildError("active implementation origin identity changed")
        payload = _read_descriptor_bytes(descriptor)
        if _file_identity(os.fstat(descriptor)) != identity:
            raise NativeBuildError("active implementation origin identity changed")
        if _file_identity(_path_lstat(origin)) != identity:
            raise NativeBuildError("active implementation origin identity changed")
        source_only_payload = getattr(module, "__source_only_payload__", None)
        source_only_identity = getattr(module, "__source_only_identity__", None)
        if (source_only_payload is None) != (source_only_identity is None) or (
            source_only_payload is not None
            and (source_only_payload != payload or source_only_identity != identity)
        ):
            raise NativeBuildError("active source-only implementation identity changed")
        return discovered_root, _ActiveImplementationIdentity(
            artifact_role=artifact_role,
            logical_path=logical_path,
            module_name=str(getattr(module, "__name__", "")),
            module=module,
            module_spec=getattr(module, "__spec__", None),
            origin=origin,
            identity=identity,
            payload=payload,
            sha256=_sha256(payload),
        )
    except OSError as exc:
        raise NativeBuildError("active implementation module origin is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _capture_active_implementation_identities() -> tuple[
    Path, tuple[_ActiveImplementationIdentity, ...]
]:
    driver_module = sys.modules.get(__name__)
    if driver_module is None:
        raise NativeBuildError("active build driver module is unavailable")
    active_root, driver = _capture_active_implementation_identity(
        "build_driver_source",
        "scripts/build_ollama_v2_native.py",
        driver_module,
        active_root=None,
        allow_missing_spec=True,
    )
    _contract_root, contract = _capture_active_implementation_identity(
        "contract_source",
        "src/worldforge/provider_evidence/ollama_v2_native_build_contracts.py",
        _build_contracts_module,
        active_root=active_root,
        allow_missing_spec=False,
    )
    return active_root, (driver, contract)


_ACTIVE_IMPLEMENTATION_ROOT, _ACTIVE_IMPLEMENTATION_IDENTITIES = (
    _capture_active_implementation_identities()
)


def _verify_active_implementation_source(source: _RetainedSource) -> None:
    for active in _ACTIVE_IMPLEMENTATION_IDENTITIES:
        matches = [
            retained
            for retained in source.entries
            if retained.contract.artifact_role == active.artifact_role
            and retained.contract.logical_path == active.logical_path
        ]
        if len(matches) != 1:
            raise NativeBuildError(f"active implementation source mismatch: {active.artifact_role}")
        retained = matches[0]
        if (
            retained.payload != active.payload
            or retained.contract.size_bytes != len(active.payload)
            or retained.contract.sha256 != active.sha256
        ):
            raise NativeBuildError(f"active implementation source mismatch: {active.artifact_role}")


def _reverify_active_implementation_identities() -> None:
    for active in _ACTIVE_IMPLEMENTATION_IDENTITIES:
        if (
            not active.module_name
            or sys.modules.get(active.module_name) is not active.module
            or getattr(active.module, "__spec__", None) is not active.module_spec
            or (
                active.artifact_role == "contract_source"
                and (
                    getattr(active.module, "__cached__", object()) is not None
                    or getattr(active.module, "__source_only_payload__", None) != active.payload
                    or getattr(active.module, "__source_only_identity__", None) != active.identity
                )
            )
        ):
            raise NativeBuildError("active implementation module origin changed")
        current_origin = _active_module_origin(
            active.module,
            active.logical_path,
            allow_missing_spec=active.module_spec is None,
        )
        if current_origin != active.origin:
            raise NativeBuildError("active implementation module origin changed")
        descriptor = -1
        try:
            before = _path_lstat(active.origin)
            if (
                stat.S_ISLNK(before.st_mode)
                or not stat.S_ISREG(before.st_mode)
                or _file_identity(before) != active.identity
            ):
                raise NativeBuildError("active implementation origin identity changed")
            descriptor = os.open(
                active.origin,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            )
            if _file_identity(os.fstat(descriptor)) != active.identity:
                raise NativeBuildError("active implementation origin identity changed")
            if _read_descriptor_bytes(descriptor) != active.payload:
                raise NativeBuildError("active implementation origin byte identity changed")
            if _file_identity(os.fstat(descriptor)) != active.identity:
                raise NativeBuildError("active implementation origin identity changed")
            if _file_identity(_path_lstat(active.origin)) != active.identity:
                raise NativeBuildError("active implementation origin identity changed")
        except OSError as exc:
            raise NativeBuildError("active implementation module origin is unavailable") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def _retain_toolchain_entry(
    entry: OllamaV2NativeToolchainEntryV1,
) -> _RetainedToolchainEntry:
    path = Path(entry.resolved_path)
    _assert_secure_toolchain_path(path)
    descriptor = -1
    try:
        before = _path_lstat(path)
        identity = _file_identity(before)
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        if _file_identity(os.fstat(descriptor)) != identity:
            raise NativeBuildError(f"toolchain path identity changed: {path}")
        payload = _read_descriptor_bytes(descriptor)
        if len(payload) != entry.size_bytes or _sha256(payload) != entry.sha256:
            raise NativeBuildError(f"toolchain lock mismatch: {path}")
        if _file_identity(_path_lstat(path)) != identity:
            raise NativeBuildError(f"toolchain path identity changed: {path}")
        return _RetainedToolchainEntry(entry, path, descriptor, identity)
    except OSError as exc:
        raise NativeBuildError(f"toolchain entry is unavailable: {path}") from exc
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _single_retained_toolchain_entry(
    toolchain: _RetainedToolchain,
    logical_role: str,
) -> _RetainedToolchainEntry:
    matches = [entry for entry in toolchain.entries if entry.contract.logical_role == logical_role]
    if len(matches) != 1:
        raise NativeBuildError(f"toolchain role census is invalid: {logical_role}")
    return matches[0]


def _verify_toolchain_inventory(manifest: OllamaV2NativeToolchainManifestD22A) -> None:
    profile = canonical_ollama_v2_native_build_profile_d22a()
    inventory = tuple((entry.logical_role, entry.resolved_path) for entry in manifest.entries)
    if (
        len(inventory) != TOOLCHAIN_INVENTORY_ENTRIES
        or _inventory_sha256(TOOLCHAIN_INVENTORY_DOMAIN, inventory)
        != profile.toolchain_inventory_sha256
    ):
        raise NativeBuildError("toolchain inventory does not match the canonical census")


def _reverify_toolchain_lock(toolchain: _RetainedToolchain) -> None:
    _assert_no_loader_overrides()
    for retained in toolchain.entries:
        path = retained.path
        _assert_secure_toolchain_path(path)
        if _file_identity(_path_lstat(path)) != retained.identity:
            raise NativeBuildError(f"toolchain path identity changed: {path}")
        if _file_identity(os.fstat(retained.descriptor)) != retained.identity:
            raise NativeBuildError(f"retained toolchain identity changed: {path}")
        retained_payload = _read_descriptor_bytes(retained.descriptor)
        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            )
            if _file_identity(os.fstat(descriptor)) != retained.identity:
                raise NativeBuildError(f"toolchain path identity changed: {path}")
            named_payload = _read_descriptor_bytes(descriptor)
        except OSError as exc:
            raise NativeBuildError(f"toolchain entry is unavailable: {path}") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if (
            retained_payload != named_payload
            or len(named_payload) != retained.contract.size_bytes
            or _sha256(named_payload) != retained.contract.sha256
        ):
            raise NativeBuildError(f"toolchain byte identity changed: {path}")
        if _file_identity(_path_lstat(path)) != retained.identity:
            raise NativeBuildError(f"toolchain path identity changed: {path}")
    _verify_declared_tool_runtime_closure(toolchain)
    _verify_declared_linker_script_closure(toolchain)


def _verify_toolchain_lock(
    manifest: OllamaV2NativeToolchainManifestD22A, env: dict[str, str]
) -> _RetainedToolchain:
    _assert_no_loader_overrides(env)
    profile = canonical_ollama_v2_native_build_profile_d22a()
    if manifest.build_profile_hash != profile.content_hash:
        raise NativeBuildError("toolchain lock names the wrong build profile")
    _verify_toolchain_inventory(manifest)
    if _single_toolchain_path(manifest, "compiler_driver") != profile.compiler_driver:
        raise NativeBuildError("build profile does not invoke the locked compiler driver")
    retained_entries: list[_RetainedToolchainEntry] = []
    try:
        for entry in manifest.entries:
            retained_entries.append(_retain_toolchain_entry(entry))
        retained = _RetainedToolchain(manifest, tuple(retained_entries))
        _verify_declared_tool_runtime_closure(retained)
        _verify_declared_linker_script_closure(retained)
        specs = _run_driver(retained, ["-dumpspecs"], cwd=ROOT, env=env)
        if _sha256(specs.stdout.encode("utf-8")) != manifest.compiler_specs_sha256:
            raise NativeBuildError("compiler reported specs do not match the toolchain lock")
        _reverify_toolchain_lock(retained)
        return retained
    except Exception:
        for entry in retained_entries:
            os.close(entry.descriptor)
        raise


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    executable: str | None = None,
    pass_fds: tuple[int, ...] = (),
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        executable=executable,
        pass_fds=pass_fds,
    )
    if result.returncode != 0:
        detail = "\n".join(part for part in (result.stdout, result.stderr) if part)
        raise NativeBuildError(f"command failed: {' '.join(command)}\n{detail}")
    return result


def _run_retained_tool(
    retained: _RetainedToolchainEntry,
    arguments: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return _run(
        [str(retained.path), *arguments],
        cwd=cwd,
        env=env,
        executable=f"/proc/self/fd/{retained.descriptor}",
        pass_fds=(retained.descriptor,),
    )


def _run_driver(
    toolchain: _RetainedToolchain,
    arguments: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    driver = _single_retained_toolchain_entry(toolchain, "compiler_driver")
    return _run_retained_tool(driver, arguments, cwd=cwd, env=env)


def _machine_preflight() -> None:
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise NativeBuildError("D2.2a native build requires Linux/aarch64")


def _versions(env: dict[str, str], toolchain: _RetainedToolchain) -> None:
    profile = canonical_ollama_v2_native_build_profile_d22a()
    gcc = _run_driver(toolchain, ["-dumpfullversion", "-dumpversion"], cwd=ROOT, env=env)
    ld = _run_retained_tool(
        _single_retained_toolchain_entry(toolchain, "linker"),
        ["--version"],
        cwd=ROOT,
        env=env,
    )
    libc = os.confstr("CS_GNU_LIBC_VERSION")
    if gcc.stdout.strip() != profile.compiler_version:
        raise NativeBuildError("compiler version does not match build profile")
    if not ld.stdout.splitlines() or not ld.stdout.splitlines()[0].endswith(
        profile.binutils_version
    ):
        raise NativeBuildError("binutils version does not match build profile")
    if libc != f"glibc {profile.glibc_version}":
        raise NativeBuildError("glibc version does not match build profile")


def _cstring(data: bytes, offset: int, maximum: int) -> str:
    if offset < 0 or offset >= maximum or maximum > len(data):
        raise NativeBuildError("ELF string offset is invalid")
    end = data.find(b"\0", offset, maximum)
    if end < 0:
        raise NativeBuildError("ELF string is unterminated")
    try:
        return data[offset:end].decode("ascii")
    except UnicodeError as exc:
        raise NativeBuildError("ELF string is not ASCII") from exc


def _inspect_elf_runtime_requirements(data: bytes) -> ElfRuntimeRequirements:
    if type(data) is not bytes or len(data) < 64:
        raise NativeBuildError("tool runtime ELF is truncated")
    ident = data[:16]
    if ident[:7] != b"\x7fELF\x02\x01\x01" or ident[7] not in (0, 3):
        raise NativeBuildError("tool runtime ELF identity is invalid")
    try:
        (
            elf_type,
            machine,
            version,
            _entry,
            phoff,
            _shoff,
            _flags,
            ehsize,
            phentsize,
            phnum,
            _shentsize,
            _shnum,
            _shstrndx,
        ) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    except struct.error as exc:
        raise NativeBuildError("tool runtime ELF header is truncated") from exc
    if (
        version != 1
        or ehsize != 64
        or phentsize != 56
        or phnum == 0
        or phnum > 1024
        or phoff > len(data)
        or phnum > (len(data) - phoff) // phentsize
    ):
        raise NativeBuildError("tool runtime ELF program table is invalid")
    programs = [
        struct.unpack_from("<IIQQQQQQ", data, phoff + index * phentsize) for index in range(phnum)
    ]
    for program in programs:
        offset, file_size, memory_size = program[2], program[5], program[6]
        if offset > len(data) or file_size > len(data) - offset or memory_size < file_size:
            raise NativeBuildError("tool runtime ELF segment exceeds its file")

    interpreters = [program for program in programs if program[0] == 3]
    if len(interpreters) > 1:
        raise NativeBuildError("tool runtime ELF has multiple interpreters")
    interpreter = ""
    if interpreters:
        program = interpreters[0]
        raw = data[program[2] : program[2] + program[5]]
        if not raw or not raw.endswith(b"\0") or raw.count(b"\0") != 1:
            raise NativeBuildError("tool runtime ELF interpreter is malformed")
        try:
            interpreter = raw[:-1].decode("ascii")
        except UnicodeError as exc:
            raise NativeBuildError("tool runtime ELF interpreter is not ASCII") from exc

    dynamics = [program for program in programs if program[0] == 2]
    if len(dynamics) != 1 or dynamics[0][5] < 16 or dynamics[0][5] % 16:
        raise NativeBuildError("tool runtime ELF dynamic table is invalid")
    dynamic_program = dynamics[0]
    dynamic: list[tuple[int, int]] = []
    terminated = False
    for offset in range(
        dynamic_program[2],
        dynamic_program[2] + dynamic_program[5],
        16,
    ):
        tag, value = struct.unpack_from("<qQ", data, offset)
        if terminated:
            if tag != 0 or value != 0:
                raise NativeBuildError("tool runtime ELF dynamic residue is noncanonical")
        elif tag == 0:
            if value != 0:
                raise NativeBuildError("tool runtime ELF terminator is noncanonical")
            terminated = True
        else:
            dynamic.append((tag, value))
    if not terminated:
        raise NativeBuildError("tool runtime ELF dynamic table is unterminated")

    def virtual_to_offset(address: int, size: int) -> int:
        if size < 1:
            raise NativeBuildError("tool runtime ELF string table is empty")
        matches = []
        for program in programs:
            if (
                program[0] == 1
                and program[3] <= address
                and address - program[3] <= program[5]
                and size <= program[5] - (address - program[3])
            ):
                matches.append(program[2] + address - program[3])
        if len(matches) != 1:
            raise NativeBuildError("tool runtime ELF virtual address is ambiguous or unmapped")
        return matches[0]

    values: dict[int, list[int]] = {}
    for tag, value in dynamic:
        values.setdefault(tag, []).append(value)
    if len(values.get(5, ())) != 1 or len(values.get(10, ())) != 1:
        raise NativeBuildError("tool runtime ELF dynamic strings are absent")
    string_size = values[10][0]
    string_offset = virtual_to_offset(values[5][0], string_size)
    dynamic_strings = data[string_offset : string_offset + string_size]
    needed = tuple(
        _cstring(dynamic_strings, offset, len(dynamic_strings)) for offset in values.get(1, ())
    )
    if len(needed) != len(set(needed)):
        raise NativeBuildError("tool runtime ELF dependency census is invalid")
    sonames = values.get(14, ())
    if len(sonames) > 1:
        raise NativeBuildError("tool runtime ELF SONAME census is invalid")
    soname = _cstring(dynamic_strings, sonames[0], len(dynamic_strings)) if sonames else ""
    return ElfRuntimeRequirements(
        machine=machine,
        elf_type=elf_type,
        interpreter=interpreter,
        soname=soname,
        needed=needed,
        path_override_present=15 in values or 29 in values,
        audit_or_filter_present=any(
            tag in values for tag in (0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF)
        ),
    )


def _parse_loader_cache(data: bytes) -> tuple[tuple[int, str, str, int, int], ...]:
    header_size = 48
    entry_size = 24
    if type(data) is not bytes or len(data) < header_size:
        raise NativeBuildError("loader cache is truncated")
    try:
        magic, count, string_size, flags, extension_offset, zero_a, zero_b, zero_c = (
            struct.unpack_from("<20sIIIIIII", data, 0)
        )
    except struct.error as exc:
        raise NativeBuildError("loader cache header is truncated") from exc
    if (
        magic != b"glibc-ld.so.cache1.1"
        or count == 0
        or count > 65536
        or string_size == 0
        or flags != 2
        or any((zero_a, zero_b, zero_c))
    ):
        raise NativeBuildError("loader cache header is unsupported")
    if count > (len(data) - header_size) // entry_size:
        raise NativeBuildError("loader cache entry table exceeds its file")
    entries_end = header_size + count * entry_size
    if string_size > len(data) - entries_end:
        raise NativeBuildError("loader cache string table exceeds its file")
    strings_end = entries_end + string_size
    if (
        extension_offset < strings_end
        or extension_offset > len(data)
        or any(data[strings_end:extension_offset])
    ):
        raise NativeBuildError("loader cache extension offset is invalid")

    def cache_string(offset: int) -> str:
        if offset < entries_end or offset >= strings_end:
            raise NativeBuildError("loader cache string offset is invalid")
        return _cstring(data, offset, strings_end)

    result: list[tuple[int, str, str, int, int]] = []
    for index in range(count):
        entry_flags, key, value, os_version, hwcap = struct.unpack_from(
            "<iIIIQ",
            data,
            header_size + index * entry_size,
        )
        result.append(
            (
                entry_flags,
                cache_string(key),
                cache_string(value),
                os_version,
                hwcap,
            )
        )
    return tuple(result)


def _resolve_loader_cache_dependency(
    entries: tuple[tuple[int, str, str, int, int], ...],
    soname: str,
) -> str:
    targets: set[str] = set()
    matches = [entry for entry in entries if entry[1] == soname]
    if not matches:
        raise NativeBuildError(f"loader cache does not resolve runtime dependency: {soname}")
    for flags, _key, value, os_version, hwcap in matches:
        if flags != 0x0A03 or os_version != 0 or hwcap != 0:
            raise NativeBuildError(f"loader cache has unsupported resolution: {soname}")
        if not value.startswith("/lib/aarch64-linux-gnu/") and value != (
            "/lib/ld-linux-aarch64.so.1"
        ):
            raise NativeBuildError(f"loader cache escaped the fixed search policy: {soname}")
        resolved = Path(os.path.realpath(value))
        _assert_secure_toolchain_path(resolved)
        targets.add(str(resolved))
    if len(targets) != 1:
        raise NativeBuildError(f"loader cache resolution is ambiguous: {soname}")
    return targets.pop()


def _parse_gnu_linker_script(data: bytes) -> tuple[tuple[str, bool], ...]:
    if type(data) is not bytes or not data or len(data) > 4096:
        raise NativeBuildError("GNU linker script is invalid")
    try:
        text = data.decode("ascii")
    except UnicodeError as exc:
        raise NativeBuildError("GNU linker script is not ASCII") from exc

    uncommented: list[str] = []
    cursor = 0
    while cursor < len(text):
        if text.startswith("/*", cursor):
            end = text.find("*/", cursor + 2)
            if end < 0 or text.find("/*", cursor + 2, end) >= 0:
                raise NativeBuildError("GNU linker script comment is invalid")
            uncommented.append(" ")
            cursor = end + 2
            continue
        if text.startswith("*/", cursor):
            raise NativeBuildError("GNU linker script comment is invalid")
        uncommented.append(text[cursor])
        cursor += 1
    text = "".join(uncommented)

    tokens: list[str] = []
    cursor = 0
    while cursor < len(text):
        if text[cursor].isspace():
            cursor += 1
            continue
        if text[cursor] in "()":
            tokens.append(text[cursor])
            cursor += 1
            continue
        end = cursor
        while end < len(text) and not text[end].isspace() and text[end] not in "()":
            end += 1
        token = text[cursor:end]
        if re.fullmatch(r"[A-Za-z0-9_+./=-]+", token) is None:
            raise NativeBuildError("GNU linker script token is unsupported")
        tokens.append(token)
        cursor = end

    position = 0
    references: list[tuple[str, bool]] = []
    input_directives = 0
    output_format_seen = False

    def take(expected: str | None = None) -> str:
        nonlocal position
        if position >= len(tokens):
            raise NativeBuildError("GNU linker script is truncated")
        token = tokens[position]
        position += 1
        if expected is not None and token != expected:
            raise NativeBuildError("GNU linker script grammar is unsupported")
        return token

    def validate_reference(token: str) -> None:
        if token.startswith("-l"):
            if re.fullmatch(r"-l[A-Za-z0-9_+.-]+", token) is None:
                raise NativeBuildError("GNU linker script library name is invalid")
            return
        if token.startswith("/"):
            if any(part in {"", ".", ".."} for part in token[1:].split("/")):
                raise NativeBuildError("GNU linker script path is invalid")
            return
        if "/" in token or re.fullmatch(r"[A-Za-z0-9_+.-]+", token) is None:
            raise NativeBuildError("GNU linker script relative input is invalid")

    def parse_inputs(*, as_needed: bool) -> None:
        start = len(references)
        while position < len(tokens) and tokens[position] != ")":
            token = take()
            if token == "AS_NEEDED":
                if as_needed:
                    raise NativeBuildError("GNU linker script AS_NEEDED nesting is invalid")
                take("(")
                parse_inputs(as_needed=True)
                take(")")
                continue
            if token in {"GROUP", "INPUT", "OUTPUT_FORMAT"} or token == "(":
                raise NativeBuildError("GNU linker script nesting is unsupported")
            validate_reference(token)
            references.append((token, as_needed))
        if len(references) == start:
            raise NativeBuildError("GNU linker script input group is empty")

    while position < len(tokens):
        directive = take()
        if directive == "OUTPUT_FORMAT":
            if output_format_seen:
                raise NativeBuildError("GNU linker script output format is duplicated")
            output_format_seen = True
            take("(")
            if take() != "elf64-littleaarch64":
                raise NativeBuildError("GNU linker script output format is unsupported")
            take(")")
            continue
        if directive not in {"GROUP", "INPUT"}:
            raise NativeBuildError("GNU linker script directive is unsupported")
        input_directives += 1
        if input_directives != 1:
            raise NativeBuildError("GNU linker script input directive is duplicated")
        take("(")
        parse_inputs(as_needed=False)
        take(")")
    if input_directives != 1:
        raise NativeBuildError("GNU linker script input directive is absent")
    return tuple(references)


def _resolve_linker_script_reference(reference: str) -> str:
    if reference.startswith("/"):
        resolved = Path(os.path.realpath(reference))
        _assert_secure_toolchain_path(resolved)
        return str(resolved)

    names = (reference,)
    if reference.startswith("-l"):
        stem = reference[2:]
        names = (f"lib{stem}.so", f"lib{stem}.a")
    candidates: set[str] = set()
    for directory in LINKER_SEARCH_DIRECTORIES:
        for name in names:
            candidate = directory / name
            try:
                resolved = Path(os.path.realpath(candidate))
                info = _path_lstat(resolved)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise NativeBuildError(
                    f"GNU linker script input is unavailable: {reference}"
                ) from exc
            if not stat.S_ISREG(info.st_mode):
                raise NativeBuildError(f"GNU linker script input is not regular: {reference}")
            _assert_secure_toolchain_path(resolved)
            candidates.add(str(resolved))
    if len(candidates) != 1:
        raise NativeBuildError(f"GNU linker script resolution is ambiguous: {reference}")
    return candidates.pop()


def _verify_declared_linker_script_closure(
    toolchain: _RetainedToolchain,
) -> tuple[tuple[str, str], ...]:
    edges: list[tuple[str, str]] = []
    for script_role, script_path, expected in LINKER_SCRIPT_CLOSURE:
        script = _single_retained_toolchain_entry(toolchain, script_role)
        if str(script.path) != script_path:
            raise NativeBuildError(f"GNU linker script role has the wrong path: {script_role}")
        references = _parse_gnu_linker_script(_read_descriptor_bytes(script.descriptor))
        resolved = tuple(
            (_resolve_linker_script_reference(reference), as_needed)
            for reference, as_needed in references
        )
        expected_resolution = tuple((path, as_needed) for _role, path, as_needed in expected)
        if resolved != expected_resolution:
            raise NativeBuildError(f"GNU linker script closure is not exact: {script_role}")
        for role, path, _as_needed in expected:
            retained = _single_retained_toolchain_entry(toolchain, role)
            if str(retained.path) != path:
                raise NativeBuildError(f"GNU linker script input role is invalid: {role}")
            edges.append((script_path, path))
    return tuple(edges)


def _verify_successful_link_diagnostics(
    completed: subprocess.CompletedProcess[str],
    toolchain: _RetainedToolchain,
    generated_inputs: tuple[Path, ...],
    output_path: Path,
) -> tuple[str, ...]:
    if (
        completed.returncode != 0
        or type(completed.stdout) is not str
        or type(completed.stderr) is not str
        or len(completed.stdout.encode("utf-8")) > 256 * 1024
        or len(completed.stderr.encode("utf-8")) > 256 * 1024
    ):
        raise NativeBuildError("successful link input diagnostic is invalid")

    if (
        len(generated_inputs) != len(LINK_DIAGNOSTIC_GENERATED_ROLES)
        or len(set(generated_inputs)) != len(generated_inputs)
        or not output_path.is_absolute()
        or not completed.stdout.endswith("\n")
        or not completed.stderr.endswith("\n")
        or "\r" in completed.stdout
        or "\r" in completed.stderr
        or "\0" in completed.stdout
        or "\0" in completed.stderr
    ):
        raise NativeBuildError("successful link input diagnostic is invalid")

    path_roles: dict[str, str] = {}
    for retained in toolchain.entries:
        path = str(retained.path)
        if path in path_roles:
            raise NativeBuildError("successful link input role census is ambiguous")
        path_roles[path] = retained.contract.logical_role
    generated_roles = {
        str(path): role
        for path, role in zip(
            generated_inputs,
            LINK_DIAGNOSTIC_GENERATED_ROLES,
            strict=True,
        )
    }
    if len(generated_roles) != len(generated_inputs) or any(
        path in path_roles for path in generated_roles
    ):
        raise NativeBuildError("successful link input generated census is invalid")

    observed_generated: set[str] = set()
    observed_system: set[str] = set()
    normalized_stdout_lines: list[str] = []
    trace_lines = completed.stdout[:-1].split("\n")
    if not trace_lines or len(trace_lines) > 256:
        raise NativeBuildError("successful link input trace census is invalid")
    for raw_line in trace_lines:
        if raw_line != raw_line.strip() or not raw_line.startswith("/") or "\0" in raw_line:
            raise NativeBuildError("successful link input trace line is invalid")
        generated_role = generated_roles.get(raw_line)
        if generated_role is not None:
            observed_generated.add(raw_line)
            normalized_stdout_lines.append(f"{{{generated_role.upper()}}}")
        else:
            resolved = os.path.realpath(raw_line)
            role = path_roles.get(resolved)
            if role is None:
                raise NativeBuildError("successful link input is not declared")
            observed_system.add(resolved)
            normalized_stdout_lines.append(raw_line)
    if observed_generated != set(generated_roles):
        raise NativeBuildError("successful link input generated census is not exact")

    substitutions = (
        (str(output_path), "{OUTPUT}"),
        (str(generated_inputs[0]), "{GENERATED_PROTOCOL_OBJECT}"),
        (str(generated_inputs[1]), "{GENERATED_MAIN_OBJECT}"),
    )
    normalized_stderr = completed.stderr
    for source, replacement in substitutions:
        if not source or replacement in normalized_stderr or source not in normalized_stderr:
            raise NativeBuildError("successful link input diagnostic is invalid")
        normalized_stderr = normalized_stderr.replace(source, replacement)
    normalized_stderr, resolution_count = LINK_RESOLUTION_OPTION_RE.subn(
        "-plugin-opt={RESOLUTION}", normalized_stderr
    )
    if resolution_count != 1:
        raise NativeBuildError("successful link input diagnostic is invalid")
    normalized_stderr_lines = normalized_stderr[:-1].split("\n")
    if (
        not normalized_stderr_lines
        or len(normalized_stderr_lines) > 256
        or any(not line for line in normalized_stderr_lines)
    ):
        raise NativeBuildError("successful link input diagnostic is invalid")
    canonical_diagnostic = json.dumps(
        {
            "stderr": normalized_stderr_lines,
            "stdout": normalized_stdout_lines,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    profile = canonical_ollama_v2_native_build_profile_d22a()
    if _sha256(canonical_diagnostic) != profile.compiler_link_diagnostic_sha256:
        raise NativeBuildError("successful link input diagnostic is not canonical")

    stderr_lines = completed.stderr[:-1].split("\n")
    wrapper_values = tuple(
        line.removeprefix("COLLECT_LTO_WRAPPER=")
        for line in stderr_lines
        if line.startswith("COLLECT_LTO_WRAPPER=")
    )
    if len(wrapper_values) != 1:
        raise NativeBuildError("successful link input LTO wrapper diagnostic is not exact")

    collector = _single_retained_toolchain_entry(toolchain, "compiler_collector")
    plugin = _single_retained_toolchain_entry(toolchain, "linker_plugin")
    wrapper = _single_retained_toolchain_entry(toolchain, "compiler_lto_wrapper")
    collector_invocations: list[list[str]] = []
    try:
        for line in stderr_lines:
            arguments = shlex.split(line)
            if arguments and os.path.realpath(arguments[0]) == str(collector.path):
                collector_invocations.append(arguments)
    except ValueError as exc:
        raise NativeBuildError("successful link input driver diagnostic is malformed") from exc
    if len(collector_invocations) != 1:
        raise NativeBuildError("successful link input collect2 census is not exact")
    arguments = collector_invocations[0]
    plugin_positions = [index for index, value in enumerate(arguments) if value == "-plugin"]
    if len(plugin_positions) != 1 or plugin_positions[0] + 1 >= len(arguments):
        raise NativeBuildError("successful link input plugin diagnostic is not exact")
    plugin_path = os.path.realpath(arguments[plugin_positions[0] + 1])
    wrapper_options = tuple(
        value.removeprefix("-plugin-opt=")
        for value in arguments
        if value.startswith("-plugin-opt=/")
    )
    wrapper_path = os.path.realpath(wrapper_values[0])
    if (
        plugin_path != str(plugin.path)
        or wrapper_path != str(wrapper.path)
        or wrapper_options != (str(wrapper.path),)
    ):
        raise NativeBuildError("successful link input plugin closure is not exact")
    return tuple(
        sorted(
            (*observed_system, plugin_path, wrapper_path),
            key=lambda value: value.encode("utf-8"),
        )
    )


def _verify_declared_tool_runtime_closure(
    toolchain: _RetainedToolchain,
) -> tuple[tuple[str, str, str], ...]:
    profile = canonical_ollama_v2_native_build_profile_d22a()
    cache_entry = _single_retained_toolchain_entry(toolchain, LOADER_CACHE_ROLE)
    if str(cache_entry.path) != LOADER_CACHE_PATH:
        raise NativeBuildError("loader cache path does not match the fixed runtime policy")
    cache = _parse_loader_cache(_read_descriptor_bytes(cache_entry.descriptor))

    providers: dict[str, _RetainedToolchainEntry] = {}
    requirements: dict[str, ElfRuntimeRequirements] = {}
    for role, soname, expected_path in TOOL_RUNTIME_PROVIDERS:
        entry = _single_retained_toolchain_entry(toolchain, role)
        if str(entry.path) != expected_path:
            raise NativeBuildError(f"runtime dependency role has the wrong path: {role}")
        inspected = _inspect_elf_runtime_requirements(_read_descriptor_bytes(entry.descriptor))
        if (
            inspected.machine != 183
            or inspected.elf_type != 3
            or inspected.soname != soname
            or inspected.path_override_present
            or inspected.audit_or_filter_present
            or (inspected.interpreter and inspected.interpreter != profile.dynamic_interpreter)
        ):
            raise NativeBuildError(f"runtime dependency ELF is outside the fixed policy: {role}")
        if _resolve_loader_cache_dependency(cache, soname) != expected_path:
            raise NativeBuildError(
                f"loader cache resolved an unexpected runtime dependency: {soname}"
            )
        if soname in providers:
            raise NativeBuildError(f"runtime dependency provider is ambiguous: {soname}")
        providers[soname] = entry
        requirements[expected_path] = inspected

    queue: list[_RetainedToolchainEntry] = []
    shared_object_inputs = dict(TOOL_SHARED_OBJECT_INPUTS)
    for role in (*TOOL_EXECUTABLE_ROLES, *shared_object_inputs):
        entry = _single_retained_toolchain_entry(toolchain, role)
        inspected = _inspect_elf_runtime_requirements(_read_descriptor_bytes(entry.descriptor))
        expected_soname = shared_object_inputs.get(role)
        if expected_soname is None:
            valid_identity = (
                inspected.elf_type in (2, 3)
                and inspected.interpreter == profile.dynamic_interpreter
                and not inspected.soname
            )
        else:
            valid_identity = (
                inspected.elf_type == 3
                and not inspected.interpreter
                and inspected.soname == expected_soname
            )
        if (
            inspected.machine != 183
            or not valid_identity
            or inspected.path_override_present
            or inspected.audit_or_filter_present
        ):
            raise NativeBuildError(
                f"compiler tool/input ELF is outside the fixed runtime policy: {role}"
            )
        requirements[str(entry.path)] = inspected
        queue.append(entry)

    visited: set[str] = set()
    used_providers: set[str] = set()
    edges: list[tuple[str, str, str]] = []
    while queue:
        consumer = queue.pop(0)
        consumer_path = str(consumer.path)
        if consumer_path in visited:
            continue
        visited.add(consumer_path)
        inspected = requirements[consumer_path]
        dependency_names = list(inspected.needed)
        if inspected.interpreter:
            interpreter_name = PurePosixPath(inspected.interpreter).name
            if interpreter_name not in dependency_names:
                dependency_names.append(interpreter_name)
        for soname in dependency_names:
            provider = providers.get(soname)
            if provider is None:
                raise NativeBuildError(f"runtime dependency is not declared: {soname}")
            provider_path = str(provider.path)
            if _resolve_loader_cache_dependency(cache, soname) != provider_path:
                raise NativeBuildError(f"runtime dependency resolution drifted: {soname}")
            edges.append((consumer_path, soname, provider_path))
            used_providers.add(provider_path)
            if provider_path not in visited:
                queue.append(provider)
    expected_providers = {path for _role, _soname, path in TOOL_RUNTIME_PROVIDERS}
    if used_providers != expected_providers:
        raise NativeBuildError("declared runtime dependency provider census is not exact")
    return tuple(sorted(edges, key=lambda edge: tuple(value.encode("utf-8") for value in edge)))


def inspect_elf(data: bytes) -> ElfInspection:
    if type(data) is not bytes or len(data) < 64:
        raise NativeBuildError("ELF is truncated")
    ident = data[:16]
    if ident[:4] != b"\x7fELF" or ident[4:7] != b"\x02\x01\x01" or ident[7] not in (0, 3):
        raise NativeBuildError("ELF identity is not ELF64 little-endian")
    try:
        (
            elf_type,
            machine,
            version,
            _entry,
            phoff,
            shoff,
            _flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        ) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    except struct.error as exc:
        raise NativeBuildError("ELF header is truncated") from exc
    if version != 1 or ehsize != 64 or phentsize != 56 or shentsize != 64:
        raise NativeBuildError("ELF header layout is invalid")
    if phnum == 0 or shnum == 0 or shstrndx >= shnum:
        raise NativeBuildError("ELF tables are absent")
    if phoff + phnum * phentsize > len(data) or shoff + shnum * shentsize > len(data):
        raise NativeBuildError("ELF table exceeds file")
    programs = [struct.unpack_from("<IIQQQQQQ", data, phoff + index * 56) for index in range(phnum)]
    sections_raw = [
        struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * 64) for index in range(shnum)
    ]
    shstr = sections_raw[shstrndx]
    if shstr[4] + shstr[5] > len(data):
        raise NativeBuildError("ELF section strings exceed file")
    section_blob = data[shstr[4] : shstr[4] + shstr[5]]
    section_names = tuple(
        _cstring(section_blob, entry[0], len(section_blob)) for entry in sections_raw
    )

    interpreter = ""
    relro = False
    nx_stack = False
    writable_executable = False
    dynamic_offset = None
    dynamic_size = None
    for p_type, p_flags, p_offset, _vaddr, _paddr, p_filesz, _memsz, _align in programs:
        if p_offset + p_filesz > len(data):
            raise NativeBuildError("ELF segment exceeds file")
        if p_type == 3:
            raw = data[p_offset : p_offset + p_filesz]
            if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
                raise NativeBuildError("ELF interpreter is malformed")
            interpreter = raw[:-1].decode("ascii")
        elif p_type == 2:
            dynamic_offset, dynamic_size = p_offset, p_filesz
        elif p_type == 1 and (p_flags & 3) == 3:
            writable_executable = True
        elif p_type == 0x6474E552:
            relro = True
        elif p_type == 0x6474E551:
            nx_stack = (p_flags & 1) == 0
    if dynamic_offset is None or dynamic_size is None or dynamic_size % 16 != 0:
        raise NativeBuildError("ELF dynamic table is invalid")

    dynamic: list[tuple[int, int]] = []
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
        tag, value = struct.unpack_from("<qQ", data, offset)
        dynamic.append((tag, value))
        if tag == 0:
            break

    def virtual_to_offset(address: int, size: int = 1) -> int:
        for p_type, _pf, p_offset, p_vaddr, _pa, p_filesz, _pm, _al in programs:
            if p_type == 1 and p_vaddr <= address and address + size <= p_vaddr + p_filesz:
                return p_offset + address - p_vaddr
        raise NativeBuildError("ELF virtual address is unmapped")

    values: dict[int, list[int]] = {}
    for tag, value in dynamic:
        values.setdefault(tag, []).append(value)
    if 5 not in values or 10 not in values or len(values[5]) != 1 or len(values[10]) != 1:
        raise NativeBuildError("ELF dynamic strings are absent")
    string_size = values[10][0]
    string_offset = virtual_to_offset(values[5][0], string_size)
    dynamic_strings = data[string_offset : string_offset + string_size]
    needed = tuple(
        _cstring(dynamic_strings, offset, len(dynamic_strings)) for offset in values.get(1, [])
    )
    flags = values.get(30, [0])[-1]
    flags_1 = values.get(0x6FFFFFFB, [0])[-1]

    build_ids: list[str] = []
    for p_type, p_flags, p_offset, _pv, _pa, p_filesz, p_memsz, p_align in programs:
        if p_type != 4:
            continue
        if (
            p_flags != 4
            or p_align != 4
            or p_offset % 4 != 0
            or p_filesz == 0
            or p_filesz != p_memsz
        ):
            raise NativeBuildError("ELF PT_NOTE segment layout is invalid")
        cursor = p_offset
        end = p_offset + p_filesz
        while cursor < end:
            if end - cursor < 12:
                raise NativeBuildError("ELF PT_NOTE has noncanonical trailing bytes")
            namesz, descsz, note_type = struct.unpack_from("<III", data, cursor)
            cursor += 12
            if namesz == 0 or descsz == 0 or namesz > end - cursor:
                raise NativeBuildError("ELF PT_NOTE field exceeds its segment")
            name_end = cursor + namesz
            aligned_name_end = name_end + (-namesz & 3)
            if aligned_name_end > end:
                raise NativeBuildError("ELF PT_NOTE name alignment exceeds its segment")
            name = data[cursor:name_end]
            if name[-1:] != b"\0" or any(data[name_end:aligned_name_end]):
                raise NativeBuildError("ELF PT_NOTE name or padding is noncanonical")
            cursor = aligned_name_end
            if descsz > end - cursor:
                raise NativeBuildError("ELF PT_NOTE description exceeds its segment")
            description_end = cursor + descsz
            aligned_description_end = description_end + (-descsz & 3)
            if aligned_description_end > end:
                raise NativeBuildError("ELF PT_NOTE description alignment exceeds its segment")
            description = data[cursor:description_end]
            if any(data[description_end:aligned_description_end]):
                raise NativeBuildError("ELF PT_NOTE description padding is noncanonical")
            cursor = aligned_description_end
            if name.rstrip(b"\0") == b"GNU" and note_type == 3:
                build_ids.append(description.hex())
    if len(build_ids) != 1:
        raise NativeBuildError("ELF PT_NOTE GNU build-id census is invalid")
    build_id = build_ids[0]

    symbols: list[str] = []
    undefined_symbols: list[tuple[str, int]] = []
    symbol_versions: tuple[tuple[str, str, str], ...] = ()
    version_requirements: list[tuple[str, tuple[str, ...]]] = []
    if ".dynsym" in section_names and ".dynstr" in section_names:
        sym = sections_raw[section_names.index(".dynsym")]
        strings = sections_raw[section_names.index(".dynstr")]
        if strings[4] + strings[5] > len(data):
            raise NativeBuildError("ELF dynamic strings are malformed")
        string_data = data[strings[4] : strings[4] + strings[5]]
        if sym[9] != 24 or sym[5] % 24 != 0 or sym[4] + sym[5] > len(data):
            raise NativeBuildError("ELF dynamic symbols are malformed")
        for symbol_index, offset in enumerate(range(sym[4], sym[4] + sym[5], 24)):
            name_offset, _info, _other, shndx, _value, _size = struct.unpack_from(
                "<IBBHQQ", data, offset
            )
            if shndx == 0 and name_offset:
                name = _cstring(string_data, name_offset, len(string_data)).split("@", 1)[0]
                symbols.append(name)
                undefined_symbols.append((name, symbol_index))

        if ".gnu.version" not in section_names or ".gnu.version_r" not in section_names:
            raise NativeBuildError("ELF symbol versions are absent")
        versym = sections_raw[section_names.index(".gnu.version")]
        verneed = sections_raw[section_names.index(".gnu.version_r")]
        symbol_count = sym[5] // 24
        if (
            versym[5] != symbol_count * 2
            or versym[9] != 2
            or versym[4] + versym[5] > len(data)
            or verneed[4] + verneed[5] > len(data)
            or verneed[7] == 0
        ):
            raise NativeBuildError("ELF symbol version tables are malformed")
        version_indices = struct.unpack_from(
            f"<{symbol_count}H",
            data,
            versym[4],
        )
        version_names: dict[int, tuple[str, str]] = {}
        cursor = verneed[4]
        version_end = verneed[4] + verneed[5]
        for requirement_index in range(verneed[7]):
            if version_end - cursor < 16:
                raise NativeBuildError("ELF version requirement header is truncated")
            version, count, filename_offset, auxiliary_offset, next_offset = struct.unpack_from(
                "<HHIII", data, cursor
            )
            if version != 1 or count == 0 or auxiliary_offset < 16:
                raise NativeBuildError("ELF version requirement header is invalid")
            filename = _cstring(string_data, filename_offset, len(string_data))
            auxiliary_cursor = cursor + auxiliary_offset
            names: list[str] = []
            auxiliary_end = auxiliary_cursor
            for auxiliary_index in range(count):
                if auxiliary_cursor < cursor or version_end - auxiliary_cursor < 16:
                    raise NativeBuildError("ELF version auxiliary entry is truncated")
                _hash, flags_value, other, name_offset, auxiliary_next = struct.unpack_from(
                    "<IHHII", data, auxiliary_cursor
                )
                if flags_value != 0 or other <= 1 or other in version_names:
                    raise NativeBuildError("ELF version auxiliary entry is invalid")
                name = _cstring(string_data, name_offset, len(string_data))
                names.append(name)
                version_names[other] = (filename, name)
                auxiliary_end = auxiliary_cursor + 16
                if auxiliary_index + 1 == count:
                    if auxiliary_next != 0:
                        raise NativeBuildError("ELF version auxiliary chain is noncanonical")
                elif auxiliary_next < 16 or auxiliary_cursor + auxiliary_next > version_end:
                    raise NativeBuildError("ELF version auxiliary chain is invalid")
                else:
                    auxiliary_cursor += auxiliary_next
            version_requirements.append((filename, tuple(names)))
            if requirement_index + 1 == verneed[7]:
                if next_offset != 0 or auxiliary_end != version_end:
                    raise NativeBuildError("ELF version requirement residue is noncanonical")
            elif next_offset < 16 or cursor + next_offset != auxiliary_end:
                raise NativeBuildError("ELF version requirement chain is invalid")
            else:
                cursor += next_offset
        if any(
            index & 0x8000 or ((index & 0x7FFF) > 1 and (index & 0x7FFF) not in version_names)
            for index in version_indices
        ):
            raise NativeBuildError("ELF symbol version index is unresolved")
        symbol_versions = tuple(
            sorted(
                (
                    name,
                    *(version_names.get(version_indices[index] & 0x7FFF, ("", ""))),
                )
                for name, index in undefined_symbols
            )
        )

    return ElfInspection(
        machine=machine,
        elf_type=elf_type,
        interpreter=interpreter,
        needed=needed,
        build_id=build_id,
        sections=section_names,
        dynamic_symbols=tuple(sorted(set(symbols))),
        version_requirements=tuple(version_requirements),
        symbol_versions=symbol_versions,
        pie=bool(flags_1 & 0x08000000),
        bind_now=bool((flags & 0x8) or (flags_1 & 0x1)),
        relro=relro,
        nx_stack=nx_stack,
        writable_executable_load=writable_executable,
        rpath_present=15 in values,
        runpath_present=29 in values,
        textrel_present=22 in values or bool(flags & 0x4),
    )


def _verify_elf(data: bytes, role: str) -> ElfInspection:
    result = inspect_elf(data)
    if result.machine != 183 or result.elf_type != 3:
        raise NativeBuildError("ELF target is not AArch64 ET_DYN")
    if result.interpreter != "/lib/ld-linux-aarch64.so.1":
        raise NativeBuildError("ELF interpreter is not locked")
    if result.needed != EXPECTED_NEEDED:
        raise NativeBuildError("ELF dependency set does not match the stack-protected profile")
    if len(result.build_id) != 40:
        raise NativeBuildError("ELF GNU SHA-1 build-id is absent")
    if not all((result.pie, result.bind_now, result.relro, result.nx_stack)):
        raise NativeBuildError("ELF hardening is incomplete")
    if any(
        (
            result.writable_executable_load,
            result.rpath_present,
            result.runpath_present,
            result.textrel_present,
        )
    ):
        raise NativeBuildError("ELF contains a prohibited load or dynamic feature")
    forbidden = {
        "accept",
        "bind",
        "clone",
        "connect",
        "dlopen",
        "execve",
        "fork",
        "ioctl",
        "kill",
        "mount",
        "open",
        "openat",
        "popen",
        "rename",
        "setgid",
        "setuid",
        "socket",
        "system",
        "unlink",
        "vfork",
    }
    if forbidden.intersection(result.dynamic_symbols):
        raise NativeBuildError("ELF imports a prohibited effect symbol")
    if result.sections != EXPECTED_SECTIONS:
        raise NativeBuildError("ELF section census does not match the build profile")
    if result.dynamic_symbols != EXPECTED_DYNAMIC_SYMBOLS.get(role):
        raise NativeBuildError("ELF dynamic symbol census does not match the artifact role")
    if result.version_requirements != EXPECTED_VERSION_REQUIREMENTS.get(role):
        raise NativeBuildError("ELF version census does not match the artifact role")
    if result.symbol_versions != EXPECTED_SYMBOL_VERSIONS.get(role):
        raise NativeBuildError("ELF symbol-version census does not match the artifact role")
    return result


def _environment() -> dict[str, str]:
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "SOURCE_DATE_EPOCH": "0",
        "TZ": "UTC",
    }


def _build_one(
    retained_source: _RetainedSource,
    build_root: Path,
    toolchain: _RetainedToolchain,
) -> dict[str, tuple[bytes, ElfInspection]]:
    profile = canonical_ollama_v2_native_build_profile_d22a()
    source = build_root / "source"
    objects = build_root / "objects"
    output = build_root / "bin"
    source.mkdir(parents=True)
    objects.mkdir()
    output.mkdir()
    for relative in SOURCE_FILES:
        target = source.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(retained_source.payload_for(relative))
        target.chmod(0o644)
    env = _environment()
    prefix = str(source)
    mapped = tuple(flag.replace("{SOURCE_ROOT}", prefix) for flag in profile.root_mapped_flags)
    protocol_object = objects / "wf_ov2_protocol.o"
    compile_inputs = (
        (source / NATIVE_ROOT / "wf_ov2_protocol.c", protocol_object),
        (source / NATIVE_ROOT / "codec_initiator.c", objects / "codec_initiator.o"),
        (source / NATIVE_ROOT / "codec_responder.c", objects / "codec_responder.o"),
    )
    for input_path, object_path in compile_inputs:
        _run_driver(
            toolchain,
            [
                *profile.compile_flags,
                *mapped,
                f"-frandom-seed={object_path.stem}",
                "-c",
                str(input_path),
                "-o",
                str(object_path),
            ],
            cwd=source,
            env=env,
        )
    result: dict[str, tuple[bytes, ElfInspection]] = {}
    for role, main_object in (
        ("codec_initiator_probe", objects / "codec_initiator.o"),
        ("codec_responder_probe", objects / "codec_responder.o"),
    ):
        executable = output / ROLE_FILENAMES[role]
        completed_link = _run_driver(
            toolchain,
            [
                *profile.link_flags,
                str(protocol_object),
                str(main_object),
                "-o",
                str(executable),
            ],
            cwd=source,
            env=env,
        )
        _verify_successful_link_diagnostics(
            completed_link,
            toolchain,
            (protocol_object, main_object),
            executable,
        )
        executable.chmod(0o755)
        payload = executable.read_bytes()
        result[role] = (payload, _verify_elf(payload, role))
    return result


def _tar_bytes(files: dict[str, tuple[bytes, int]]) -> bytes:
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            directories: set[str] = set()
            for name in files:
                parts = PurePosixPath(name).parts
                for length in range(1, len(parts)):
                    directories.add("/".join(parts[:length]) + "/")
            for name in sorted((*directories, *files)):
                info = tarfile.TarInfo(name)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                if name.endswith("/"):
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    archive.addfile(info)
                else:
                    payload, mode = files[name]
                    info.size = len(payload)
                    info.mode = mode
                    archive.addfile(info, io.BytesIO(payload))
    return raw.getvalue()


def _is_direct_source_entry(
    *,
    module_name: object,
    module_spec: object,
    cached_path: object,
    loader_name: object,
    loader_path: object,
    module_file: object,
    argv0: object,
) -> bool:
    if (
        module_name != "__main__"
        or module_spec is not None
        or cached_path is not None
        or loader_name != "SourceFileLoader"
        or type(loader_path) is not str
        or type(module_file) is not str
        or type(argv0) is not str
    ):
        return False
    paths = tuple(Path(value) for value in (loader_path, module_file, argv0))
    return all(path.is_absolute() for path in paths) and paths[0] == paths[1] == paths[2]


def _require_direct_source_entry() -> None:
    loader = globals().get("__loader__")
    if not _is_direct_source_entry(
        module_name=__name__,
        module_spec=globals().get("__spec__"),
        cached_path=globals().get("__cached__"),
        loader_name=type(loader).__name__,
        loader_path=getattr(loader, "path", None),
        module_file=globals().get("__file__"),
        argv0=sys.argv[0] if sys.argv else None,
    ):
        raise NativeBuildError("authoritative publication requires direct source-file execution")


def _prepare_native_archive(source_root: Path) -> bytes:
    source_root = source_root.resolve()
    _machine_preflight()
    old_umask = os.umask(0o022)
    retained_source: _RetainedSource | None = None
    retained_toolchain: _RetainedToolchain | None = None
    try:
        source_manifest, source_bytes = _load_contract(
            source_root, SOURCE_LOCK, OllamaV2NativeSourceManifestD22A
        )
        retained_source = _verify_source_lock(source_root, source_manifest)
        _verify_active_implementation_source(retained_source)
        _reverify_active_implementation_identities()
        protocol_bytes = retained_source.payload_for(PROTOCOL_LOCK)
        protocol = _parse_protocol_lock(protocol_bytes)
        toolchain_bytes = retained_source.payload_for(TOOLCHAIN_LOCK)
        toolchain = _parse_contract(
            toolchain_bytes,
            TOOLCHAIN_LOCK,
            OllamaV2NativeToolchainManifestD22A,
        )
        env = _environment()
        retained_toolchain = _verify_toolchain_lock(toolchain, env)
        _reverify_source_lock(retained_source)
        _versions(env, retained_toolchain)
        _reverify_source_lock(retained_source)
        _reverify_toolchain_lock(retained_toolchain)
        with tempfile.TemporaryDirectory(prefix="wf-d22a-native-") as temporary:
            scratch = Path(temporary)
            first = _build_one(retained_source, scratch / "root-a", retained_toolchain)
            _reverify_source_lock(retained_source)
            _reverify_toolchain_lock(retained_toolchain)
            second = _build_one(
                retained_source,
                scratch / "different-root-b",
                retained_toolchain,
            )
            _reverify_source_lock(retained_source)
            _reverify_toolchain_lock(retained_toolchain)
        if set(first) != set(second):
            raise NativeBuildError("two-root artifact roles differ")
        entries: list[OllamaV2NativeElfEntryV1] = []
        for role in sorted(first):
            left, left_elf = first[role]
            right, right_elf = second[role]
            if left != right or left_elf.build_id != right_elf.build_id:
                raise NativeBuildError(f"non-reproducible native artifact: {role}")
            entries.append(
                OllamaV2NativeElfEntryV1(
                    artifact_role=role,
                    filename=ROLE_FILENAMES[role],
                    size_bytes=len(left),
                    sha256=_sha256(left),
                    gnu_build_id=left_elf.build_id,
                )
            )
        profile = canonical_ollama_v2_native_build_profile_d22a()
        bundle = OllamaV2NativeStaticBundleManifestD22A(
            source_manifest_hash=source_manifest.content_hash,
            build_profile_hash=profile.content_hash,
            toolchain_manifest_hash=toolchain.content_hash,
            entries=tuple(entries),
            codec_implementation_state="built",
            effect_interpreter_state="absent",
            installed=False,
            root_custody_verified=False,
            source_custody_verified=False,
            host_execution_enabled=False,
            native_evidence_verified=False,
            provider_execution_enabled=False,
            catalog_admitted=False,
            production_eligible=False,
            availability="unavailable",
        )
        validate_ollama_v2_native_build_lineage_d22a(bundle, source_manifest, profile, toolchain)
        receipt = OllamaV2NativeTwoRootReceiptD22A(
            protocol_lock_hash=protocol["content_hash"],
            source_manifest_hash=source_manifest.content_hash,
            build_profile_hash=profile.content_hash,
            toolchain_manifest_hash=toolchain.content_hash,
            static_bundle_manifest_hash=bundle.content_hash,
            root_labels=("root-a", "different-root-b"),
            root_a_entries=tuple(entries),
            root_b_entries=tuple(entries),
            comparison="byte-identical",
            claim_scope="static-codec-build-only",
        )
        files: dict[str, tuple[bytes, int]] = {
            "manifests/protocol-lock.json": (protocol_bytes, 0o644),
            "manifests/source-lock.json": (source_bytes, 0o644),
            "manifests/build-profile.json": (profile.to_bytes(), 0o644),
            "manifests/toolchain-lock.json": (toolchain_bytes, 0o644),
            "manifests/static-bundle-manifest.json": (bundle.to_bytes(), 0o644),
            "manifests/two-root-build-receipt.json": (receipt.to_bytes(), 0o644),
            "legal/LICENSE": (retained_source.payload_for("LICENSE"), 0o644),
            "legal/THIRD_PARTY_NOTICES.md": (
                retained_source.payload_for("THIRD_PARTY_NOTICES.md"),
                0o644,
            ),
        }
        for role, (payload, _inspection) in first.items():
            files[f"bin/{ROLE_FILENAMES[role]}"] = (payload, 0o755)
        archive = _tar_bytes(files)
        _reverify_toolchain_lock(retained_toolchain)
        _reverify_source_lock(retained_source)
        _reverify_active_implementation_identities()
        return archive
    finally:
        if retained_toolchain is not None:
            retained_toolchain.close()
        if retained_source is not None:
            retained_source.close()
        os.umask(old_umask)


def build_native_bundle(source_root: Path, output_dir: Path) -> list[Path]:
    _require_direct_source_entry()
    output_dir = Path(os.path.abspath(output_dir))
    target = output_dir / OUTPUT_NAME
    if target.exists() or target.is_symlink():
        raise NativeBuildError(f"refusing to replace existing artifact: {target}")
    archive = _prepare_native_archive(source_root)
    _reverify_active_implementation_identities()
    output_dir.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(archive)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return [target]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        artifacts = build_native_bundle(args.source_root, args.output_dir)
    except NativeBuildError as exc:
        print(f"error: {exc}", file=__import__("sys").stderr)
        return 1
    for artifact in artifacts:
        print(f"artifact={artifact} sha256={_sha256(artifact.read_bytes())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
