from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import py_compile
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import scripts.build_ollama_v2_native as native_builder

ROOT = Path(__file__).resolve().parents[1]
MAGIC = b"WF50D22A"
DOMAIN = b"worldforge-ollama-v2-d22a-packet-v1\0"
HEADER_SIZE = 120
MAX_RECORD = 168
ZERO_HASH = bytes(32)
GOLDEN_REQUEST_HEX = (
    "5746353044323241000100780001000000000000000000000000001800000000"
    "00112233445566778899aabbccddeeff01020304050607080000000000000000"
    "0000000000000000000000000000000000000000000000000e44affb9f354673"
    "9a1d18ad74e1399d134f734299bbbc70bf09583ec1af78ea0001000100000030"
    "000000a8000000000001000200020000"
)
GOLDEN_REQUEST_PACKET_SHA256 = "cb40efbb9062b4b4668436a5c812f461dee9e33c139490b13d1d67d82915c595"
GOLDEN_RESPONSE_HEX = (
    "5746353044323241000100780002000000000000000000010000003000000000"
    "00112233445566778899aabbccddeeff0102030405060708cb40efbb9062b4b4"
    "668436a5c812f461dee9e33c139490b13d1d67d82915c595ed9583defe4d42a6"
    "2270805cb0cfc618d6b0921e3fa1046c3881b2f0478b7bf60001000100000001"
    "0000000000000000cb40efbb9062b4b4668436a5c812f461dee9e33c139490b1"
    "3d1d67d82915c595"
)
GOLDEN_RESPONSE_PACKET_SHA256 = "ef84a9a2340e67e843d31a9937f37082ba80e9f24303ecb7301faae2a3b9bab7"


def _sha(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _packet_hash(packet: bytes) -> bytes:
    return _sha(DOMAIN + packet)


def _canonical_rehash(document: dict[str, object]) -> bytes:
    payload = dict(document)
    payload.pop("content_hash", None)
    result = dict(payload)
    result["content_hash"] = hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return json.dumps(
        result,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode()


def _copy_locked_source_tree(target: Path) -> dict[str, object]:
    source_document = json.loads((ROOT / "native/ollama_v2_control/source-lock.json").read_bytes())
    for entry in source_document["entries"]:
        relative = entry["logical_path"]
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    source_lock = target / "native/ollama_v2_control/source-lock.json"
    source_lock.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "native/ollama_v2_control/source-lock.json", source_lock)
    return source_document


def _rewrite_declared_source_bytes(
    source: Path,
    source_document: dict[str, object],
    replacements: dict[str, bytes],
) -> None:
    entries = {entry["artifact_role"]: entry for entry in source_document["entries"]}
    for role, payload in replacements.items():
        entry = entries[role]
        (source / entry["logical_path"]).write_bytes(payload)
        entry["size_bytes"] = len(payload)
        entry["sha256"] = hashlib.sha256(payload).hexdigest()
        entry.update(json.loads(_canonical_rehash(entry)))
    (source / "native/ollama_v2_control/source-lock.json").write_bytes(
        _canonical_rehash(source_document)
    )


def _rewrite_toolchain_and_source(
    source: Path,
    source_document: dict[str, object],
    toolchain_document: dict[str, object],
) -> None:
    toolchain_path = source / "native/ollama_v2_control/toolchain-lock.json"
    toolchain_bytes = _canonical_rehash(toolchain_document)
    toolchain_path.write_bytes(toolchain_bytes)
    for entry in source_document["entries"]:
        if entry["logical_path"] == "native/ollama_v2_control/toolchain-lock.json":
            entry["size_bytes"] = len(toolchain_bytes)
            entry["sha256"] = hashlib.sha256(toolchain_bytes).hexdigest()
            entry.update(json.loads(_canonical_rehash(entry)))
            break
    else:
        raise AssertionError("toolchain lock is absent from the source manifest fixture")
    (source / "native/ollama_v2_control/source-lock.json").write_bytes(
        _canonical_rehash(source_document)
    )


def _write_marker_pyc(
    source_path: Path,
    marker: str,
    invalidation_mode: py_compile.PycInvalidationMode,
) -> Path:
    canonical = source_path.read_bytes()
    original = source_path.stat()
    attack = (
        f"print({marker!r})\nexec(compile(open(__file__, 'rb').read(), __file__, 'exec'))\n"
    ).encode()
    if len(attack) >= len(canonical):
        raise AssertionError("marker pyc fixture exceeds the canonical source length")
    attack += b"#" + b" " * (len(canonical) - len(attack) - 2) + b"\n"
    source_path.write_bytes(attack)
    os.utime(source_path, ns=(original.st_atime_ns, original.st_mtime_ns))
    cache_path = Path(importlib.util.cache_from_source(str(source_path)))
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    py_compile.compile(
        str(source_path),
        cfile=str(cache_path),
        doraise=True,
        invalidation_mode=invalidation_mode,
    )
    source_path.write_bytes(canonical)
    os.utime(source_path, ns=(original.st_atime_ns, original.st_mtime_ns))
    return cache_path


def _run_native_builder_cli(source: Path, output: Path, *, module: bool = False):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(source / "src")
    command = [str(Path(sys.executable))]
    if module:
        command.extend(("-m", "scripts.build_ollama_v2_native"))
    else:
        command.append(str(source / "scripts/build_ollama_v2_native.py"))
    command.extend(("--source-root", str(source), "--output-dir", str(output)))
    return subprocess.run(
        command,
        cwd=source,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _build_non_authoritative_test_bundle(source: Path, output: Path) -> list[Path]:
    target = output / native_builder.OUTPUT_NAME
    if target.exists() or target.is_symlink():
        raise native_builder.NativeBuildError(f"refusing to replace test artifact: {target}")
    archive = native_builder._prepare_native_archive(source)
    output.mkdir(parents=True, exist_ok=True)
    target.write_bytes(archive)
    return [target]


def _independently_observed_link_inputs(
    completed_links: list[tuple[subprocess.CompletedProcess[str], Path]],
) -> frozenset[str]:
    observed: set[str] = set()
    collect2_invocations = 0
    for completed, build_root in completed_links:
        if completed.returncode != 0:
            raise AssertionError("captured linker diagnostic was not successful")
        for line in completed.stdout.splitlines():
            candidate = line.strip()
            if not candidate.startswith("/"):
                continue
            resolved = Path(os.path.realpath(candidate))
            if resolved.is_relative_to(build_root):
                if resolved.suffix != ".o":
                    raise AssertionError(f"unexpected generated linker input: {resolved}")
                continue
            observed.add(str(resolved))

        wrapper_lines = [
            line.removeprefix("COLLECT_LTO_WRAPPER=")
            for line in completed.stderr.splitlines()
            if line.startswith("COLLECT_LTO_WRAPPER=")
        ]
        if len(wrapper_lines) != 1:
            continue
        observed.add(os.path.realpath(wrapper_lines[0]))
        for line in completed.stderr.splitlines():
            arguments = shlex.split(line)
            if not arguments or not arguments[0].endswith("/collect2"):
                continue
            collect2_invocations += 1
            plugin_positions = [
                index for index, argument in enumerate(arguments) if argument == "-plugin"
            ]
            if len(plugin_positions) != 1 or plugin_positions[0] + 1 >= len(arguments):
                raise AssertionError("captured collect2 plugin diagnostic is malformed")
            observed.add(os.path.realpath(arguments[plugin_positions[0] + 1]))
    if collect2_invocations != len(completed_links):
        raise AssertionError("captured collect2 invocation census is incomplete")
    return frozenset(observed)


def _request(*, deadline_ns: int | None = None, nonce: bytes = b"0123456789abcdef") -> bytes:
    if deadline_ns is None:
        deadline_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 2_000_000_000
    body = struct.pack(">HHIIHHHHHH", 1, 1, 48, 168, 0, 0, 1, 2, 2, 0)
    header = struct.pack(
        ">8sHHHHQIHH16sQ32s32s",
        MAGIC,
        1,
        120,
        1,
        0,
        0,
        len(body),
        0,
        0,
        nonce,
        deadline_ns,
        ZERO_HASH,
        _sha(body),
    )
    return header + body


def _response(request: bytes) -> bytes:
    request_hash = _packet_hash(request)
    nonce = request[32:48]
    deadline_ns = struct.unpack_from(">Q", request, 48)[0]
    body = struct.pack(">HHIQ32s", 1, 1, 1, 0, request_hash)
    header = struct.pack(
        ">8sHHHHQIHH16sQ32s32s",
        MAGIC,
        1,
        120,
        2,
        0,
        1,
        len(body),
        0,
        0,
        nonce,
        deadline_ns,
        request_hash,
        _sha(body),
    )
    return header + body


def _locked_body_values(
    record: bytes,
    fields: list[list[object]],
) -> dict[str, int | bytes]:
    result: dict[str, int | bytes] = {}
    for name, offset, size, expected in fields:
        if type(name) is not str or type(offset) is not int or type(size) is not int:
            raise AssertionError("protocol-lock body field is malformed")
        value = record[HEADER_SIZE + offset : HEADER_SIZE + offset + size]
        if len(value) != size:
            raise AssertionError(f"protocol-lock body field is truncated: {name}")
        result[name] = value if type(expected) is str else int.from_bytes(value, "big")
    return result


def _locked_expected_values(
    fields: list[list[object]],
    *,
    request_hash: bytes,
) -> dict[str, int | bytes]:
    return {
        name: request_hash if expected == "request_packet_sha256" else expected
        for name, _offset, _size, expected in fields
    }


def _run_pair(initiator: Path, responder: Path, *, initiator_first: bool) -> tuple[int, int]:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        for endpoint in (left, right):
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        order = ((initiator, left), (responder, right))
        if not initiator_first:
            order = tuple(reversed(order))
        processes: dict[str, subprocess.Popen[bytes]] = {}
        for executable, endpoint in order:
            process = subprocess.Popen(
                [str(executable)],
                stdin=endpoint.fileno(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            processes[executable.name] = process
            time.sleep(0.02)
        left.close()
        right.close()
        return (
            processes[initiator.name].wait(timeout=5),
            processes[responder.name].wait(timeout=5),
        )
    finally:
        left.close()
        right.close()


_TDD_EVIDENCE_COLUMNS = (
    "Task",
    "Test file",
    "Layer",
    "Safety net",
    "RED",
    "GREEN",
    "Triangulate",
    "Refactor",
)
_TDD_EVIDENCE_TASKS = (
    "Final7: actual link-input and LTO-plugin closure",
    "Final8: locked `unavailable_type` and fail-closed complete diagnostic transcript",
    "Final9: preserve lexical trace identity",
)


def _parse_tdd_cycle_evidence(evidence: str) -> dict[str, dict[str, str]]:
    heading = "## TDD Cycle Evidence"
    header = "| " + " | ".join(_TDD_EVIDENCE_COLUMNS) + " |"
    if evidence.count(heading) != 1 or evidence.count(header) != 1:
        raise AssertionError("TDD evidence heading/header is not exact")
    section = evidence.split(heading, 1)[1].split("\n## ", 1)[0]
    lines = section.splitlines()
    header_index = lines.index(header)
    separator = lines[header_index + 1]
    if separator != "|" + "---|" * len(_TDD_EVIDENCE_COLUMNS):
        raise AssertionError("TDD evidence separator is not exact")
    row_lines: list[str] = []
    for line in lines[header_index + 2 :]:
        if not line.startswith("|"):
            break
        row_lines.append(line)
    if len(row_lines) != len(_TDD_EVIDENCE_TASKS):
        raise AssertionError("TDD evidence row count is not exact")
    rows: dict[str, dict[str, str]] = {}
    ordered_tasks: list[str] = []
    for line in row_lines:
        cells = tuple(cell.strip() for cell in line[1:-1].split("|"))
        if len(cells) != len(_TDD_EVIDENCE_COLUMNS) or any(not cell for cell in cells):
            raise AssertionError("TDD evidence row fields are not exact and nonempty")
        row = dict(zip(_TDD_EVIDENCE_COLUMNS, cells, strict=True))
        task = row["Task"]
        if task in rows:
            raise AssertionError("TDD evidence task keys are not unique")
        ordered_tasks.append(task)
        rows[task] = row
    if tuple(ordered_tasks) != _TDD_EVIDENCE_TASKS:
        raise AssertionError("TDD evidence task keys/order are not exact")
    return rows


class D22ANativeBuildTests(unittest.TestCase):
    def test_entry_mode_contract_accepts_only_direct_source_file_execution(self) -> None:
        script = str(ROOT / "scripts/build_ollama_v2_native.py")
        direct = {
            "module_name": "__main__",
            "module_spec": None,
            "cached_path": None,
            "loader_name": "SourceFileLoader",
            "loader_path": script,
            "module_file": script,
            "argv0": script,
        }
        self.assertTrue(native_builder._is_direct_source_entry(**direct))
        for field, value in (
            ("module_name", "scripts.build_ollama_v2_native"),
            ("module_spec", object()),
            ("cached_path", script + "c"),
            ("loader_name", "SourcelessFileLoader"),
            ("loader_path", script + ".other"),
            ("module_file", script + ".other"),
            ("argv0", script + ".other"),
        ):
            changed = dict(direct)
            changed[field] = value
            with self.subTest(field=field):
                self.assertFalse(native_builder._is_direct_source_entry(**changed))

        with (
            tempfile.TemporaryDirectory(prefix="wf-d22a-imported-entry-") as temporary,
            patch.object(
                native_builder,
                "_machine_preflight",
                side_effect=AssertionError("imported publication reached native preflight"),
            ) as preflight,
            self.assertRaisesRegex(native_builder.NativeBuildError, "direct source-file"),
        ):
            native_builder.build_native_bundle(ROOT, Path(temporary) / "output")
        preflight.assert_not_called()

        with tempfile.TemporaryDirectory(prefix="wf-d22a-module-entry-") as temporary:
            source = Path(temporary) / "source"
            _copy_locked_source_tree(source)
            completed = _run_native_builder_cli(
                source,
                Path(temporary) / "module-output",
                module=True,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn("direct source-file", completed.stderr)
            self.assertFalse(
                (Path(temporary) / "module-output" / native_builder.OUTPUT_NAME).exists()
            )

    def test_source_only_contract_loader_ignores_all_pyc_invalidation_modes(self) -> None:
        modes = (
            py_compile.PycInvalidationMode.TIMESTAMP,
            py_compile.PycInvalidationMode.CHECKED_HASH,
            py_compile.PycInvalidationMode.UNCHECKED_HASH,
        )
        for mode in modes:
            with (
                self.subTest(mode=mode.name),
                tempfile.TemporaryDirectory(prefix="wf-d22a-source-only-loader-") as temporary,
            ):
                source = Path(temporary) / "source"
                _copy_locked_source_tree(source)
                contract = (
                    source / "src/worldforge/provider_evidence/ollama_v2_native_build_contracts.py"
                )
                marker = f"MALICIOUS-CONTRACT-PYC-{mode.name}"
                cache = _write_marker_pyc(contract, marker, mode)
                captured = io.StringIO()
                with contextlib.redirect_stdout(captured):
                    loaded = native_builder._load_contract_source_only(source)

                self.assertTrue(cache.is_file())
                self.assertNotIn(marker, captured.getvalue())
                self.assertIsNone(loaded.__cached__)
                self.assertEqual(
                    native_builder.canonical_ollama_v2_native_build_profile_d22a().to_bytes(),
                    loaded.canonical_ollama_v2_native_build_profile_d22a().to_bytes(),
                )

    def test_direct_source_cli_ignores_driver_and_contract_caches(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wf-d22a-direct-source-pyc-") as temporary:
            root = Path(temporary)
            clean_source = root / "clean-source"
            attacked_source = root / "attacked-source"
            _copy_locked_source_tree(clean_source)
            _copy_locked_source_tree(attacked_source)
            contract_marker = "MALICIOUS-CONTRACT-PYC-TIMESTAMP"
            driver_marker = "MALICIOUS-DRIVER-PYC-TIMESTAMP"
            _write_marker_pyc(
                attacked_source
                / "src/worldforge/provider_evidence/ollama_v2_native_build_contracts.py",
                contract_marker,
                py_compile.PycInvalidationMode.TIMESTAMP,
            )
            _write_marker_pyc(
                attacked_source / "scripts/build_ollama_v2_native.py",
                driver_marker,
                py_compile.PycInvalidationMode.TIMESTAMP,
            )

            clean = _run_native_builder_cli(clean_source, root / "clean-output")
            attacked = _run_native_builder_cli(attacked_source, root / "attacked-output")
            clean_archive = root / "clean-output" / native_builder.OUTPUT_NAME
            attacked_archive = root / "attacked-output" / native_builder.OUTPUT_NAME

            self.assertEqual(0, clean.returncode, clean.stderr or clean.stdout)
            self.assertEqual(0, attacked.returncode, attacked.stderr or attacked.stdout)
            self.assertNotIn(contract_marker, attacked.stdout)
            self.assertNotIn(driver_marker, attacked.stdout)
            self.assertTrue(clean_archive.is_file())
            self.assertTrue(attacked_archive.is_file())
            self.assertEqual(clean_archive.read_bytes(), attacked_archive.read_bytes())

    def test_active_driver_and_contract_bytes_bind_source_before_tool_query(self) -> None:
        invalid_driver = b"this is deliberately not valid Python !!!\n"
        invalid_contract = b"this is not valid Python either !!!\n"
        cases = {
            "changed-driver": {"build_driver_source": invalid_driver},
            "changed-contract": {"contract_source": invalid_contract},
            "changed-both": {
                "build_driver_source": invalid_driver,
                "contract_source": invalid_contract,
            },
        }
        for label, replacements in cases.items():
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory(prefix="wf-d22a-active-lineage-red-") as temporary,
            ):
                source = Path(temporary) / "source"
                source_document = _copy_locked_source_tree(source)
                _rewrite_declared_source_bytes(source, source_document, replacements)
                output = Path(temporary) / "output"
                with (
                    patch.object(
                        native_builder.subprocess,
                        "run",
                        side_effect=AssertionError("driver queried for foreign active source"),
                    ) as runner,
                    self.assertRaisesRegex(
                        native_builder.NativeBuildError,
                        "active implementation source mismatch",
                    ),
                ):
                    _build_non_authoritative_test_bundle(source, output)
                runner.assert_not_called()
                self.assertFalse((output / native_builder.OUTPUT_NAME).exists())

    def test_identical_copied_root_and_fresh_script_use_their_declared_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wf-d22a-active-copy-") as temporary:
            root = Path(temporary)
            source = root / "source"
            _copy_locked_source_tree(source)

            imported_archive = _build_non_authoritative_test_bundle(
                source, root / "already-imported-output"
            )[0]
            env = os.environ.copy()
            env["PYTHONPATH"] = str(source / "src")
            completed = subprocess.run(
                [
                    str(Path(sys.executable)),
                    str(source / "scripts/build_ollama_v2_native.py"),
                    "--source-root",
                    str(source),
                    "--output-dir",
                    str(root / "fresh-script-output"),
                ],
                cwd=source,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            fresh_archive = root / "fresh-script-output" / native_builder.OUTPUT_NAME

            self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)
            self.assertTrue(fresh_archive.is_file())
            self.assertIn(str(fresh_archive), completed.stdout)
            self.assertEqual(imported_archive.read_bytes(), fresh_archive.read_bytes())

    def test_active_origins_are_rechecked_and_late_failure_blocks_publication(self) -> None:
        identities = native_builder._ACTIVE_IMPLEMENTATION_IDENTITIES
        self.assertEqual(
            ("build_driver_source", "contract_source"),
            tuple(identity.artifact_role for identity in identities),
        )
        original_lstat = native_builder._path_lstat
        target = identities[0]

        def changed_origin(path: Path):
            info = original_lstat(path)
            if path == target.origin:
                return types.SimpleNamespace(
                    st_mode=info.st_mode,
                    st_uid=info.st_uid,
                    st_gid=info.st_gid,
                    st_dev=info.st_dev,
                    st_ino=info.st_ino + 1,
                    st_size=info.st_size,
                    st_mtime_ns=info.st_mtime_ns,
                    st_ctime_ns=info.st_ctime_ns,
                )
            return info

        with (
            patch.object(native_builder, "_path_lstat", side_effect=changed_origin),
            self.assertRaisesRegex(
                native_builder.NativeBuildError, "active implementation origin identity"
            ),
        ):
            native_builder._reverify_active_implementation_identities()

        with (
            patch.object(
                target.module,
                "__file__",
                str(target.origin.with_name("substituted-build-driver.py")),
            ),
            self.assertRaisesRegex(
                native_builder.NativeBuildError, "active implementation module origin"
            ),
        ):
            native_builder._reverify_active_implementation_identities()

        self.assertIsNotNone(target.module.__spec__)
        with (
            patch.object(target.module, "__spec__", None),
            self.assertRaisesRegex(
                native_builder.NativeBuildError, "active implementation module origin"
            ),
        ):
            native_builder._reverify_active_implementation_identities()

        original_reverify = native_builder._reverify_active_implementation_identities
        checks = 0

        def fail_late() -> None:
            nonlocal checks
            checks += 1
            if checks == 2:
                raise native_builder.NativeBuildError(
                    "active implementation origin identity changed before publication"
                )
            original_reverify()

        with tempfile.TemporaryDirectory(prefix="wf-d22a-active-late-") as temporary:
            output = Path(temporary) / "output"
            with (
                patch.object(
                    native_builder,
                    "_reverify_active_implementation_identities",
                    side_effect=fail_late,
                ),
                self.assertRaisesRegex(native_builder.NativeBuildError, "before publication"),
            ):
                _build_non_authoritative_test_bundle(ROOT, output)
            self.assertEqual(2, checks)
            self.assertFalse((output / native_builder.OUTPUT_NAME).exists())

    def test_literal_golden_records_freeze_every_byte_and_packet_hash(self) -> None:
        request = _request(
            deadline_ns=0x0102030405060708,
            nonce=bytes.fromhex("00112233445566778899aabbccddeeff"),
        )
        self.assertEqual(bytes.fromhex(GOLDEN_REQUEST_HEX), request)
        self.assertEqual(GOLDEN_REQUEST_PACKET_SHA256, _packet_hash(request).hex())
        response = _response(request)
        self.assertEqual(bytes.fromhex(GOLDEN_RESPONSE_HEX), response)
        self.assertEqual(GOLDEN_RESPONSE_PACKET_SHA256, _packet_hash(response).hex())

    def test_protocol_lock_body_fields_bind_encoders_decoders_and_goldens(self) -> None:
        protocol = json.loads((ROOT / "native/ollama_v2_control/protocol-lock.json").read_bytes())
        request = _request(
            deadline_ns=0x0102030405060708,
            nonce=bytes.fromhex("00112233445566778899aabbccddeeff"),
        )
        self.assertEqual(bytes.fromhex(GOLDEN_REQUEST_HEX), request)
        self.assertEqual(
            _locked_expected_values(protocol["negotiate_fields"], request_hash=b""),
            _locked_body_values(request, protocol["negotiate_fields"]),
        )
        self.assertEqual(protocol["negotiate_type"], int.from_bytes(request[12:14], "big"))

        request_hash = _packet_hash(request)
        response = _response(request)
        self.assertEqual(bytes.fromhex(GOLDEN_RESPONSE_HEX), response)
        self.assertEqual(
            _locked_expected_values(protocol["unavailable_fields"], request_hash=request_hash),
            _locked_body_values(response, protocol["unavailable_fields"]),
        )
        self.assertEqual(protocol["unavailable_type"], int.from_bytes(response[12:14], "big"))

    def test_protocol_sources_freeze_probe_only_abi_and_exclude_effect_surface(self) -> None:
        header = (ROOT / "native/ollama_v2_control/wf_ov2_protocol.h").read_text()
        sources = "\n".join(
            (ROOT / relative).read_text()
            for relative in (
                "native/ollama_v2_control/wf_ov2_protocol.c",
                "native/ollama_v2_control/codec_initiator.c",
                "native/ollama_v2_control/codec_responder.c",
            )
        )

        for literal in (
            "#define WF_OV2_HEADER_SIZE 120u",
            "#define WF_OV2_OFFSET_MAGIC 0u",
            "#define WF_OV2_OFFSET_MAJOR 8u",
            "#define WF_OV2_OFFSET_HEADER_SIZE 10u",
            "#define WF_OV2_OFFSET_TYPE 12u",
            "#define WF_OV2_OFFSET_FLAGS 14u",
            "#define WF_OV2_OFFSET_SEQUENCE 16u",
            "#define WF_OV2_OFFSET_BODY_SIZE 24u",
            "#define WF_OV2_OFFSET_FD_COUNT 28u",
            "#define WF_OV2_OFFSET_RESERVED 30u",
            "#define WF_OV2_OFFSET_NONCE 32u",
            "#define WF_OV2_OFFSET_DEADLINE_NS 48u",
            "#define WF_OV2_OFFSET_PRIOR_PACKET_SHA256 56u",
            "#define WF_OV2_OFFSET_BODY_SHA256 88u",
            "#define WF_OV2_NEGOTIATE_BODY_SIZE 24u",
            "#define WF_OV2_UNAVAILABLE_BODY_SIZE 48u",
            "#define WF_OV2_MAX_RECORD_SIZE 168u",
            "WF_OV2_MSG_NEGOTIATE = 1",
            "WF_OV2_MSG_UNAVAILABLE_TERMINAL = 2",
            "WF_OV2_TERMINAL_CLASS_UNAVAILABLE = 1",
            "WF_OV2_REASON_EFFECT_EXECUTION_UNAVAILABLE = 1",
        ):
            self.assertIn(literal, header)
        protocol = json.loads((ROOT / "native/ollama_v2_control/protocol-lock.json").read_bytes())
        self.assertEqual("big-endian", protocol["byte_order"])
        self.assertEqual(DOMAIN.decode("utf-8"), protocol["packet_hash_domain"])
        self.assertIn(
            "zero-length SOCK_SEQPACKET records are not EOF",
            protocol["socket_requirements"],
        )
        self.assertEqual(
            [
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
            protocol["header_fields"],
        )
        self.assertEqual(
            [
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
            protocol["negotiate_fields"],
        )
        self.assertEqual(
            [
                ["selected_major", 0, 2, 1],
                ["terminal_class", 2, 2, 1],
                ["reason", 4, 4, 1],
                ["request_sequence", 8, 8, 0],
                ["request_packet_sha256", 16, 32, "request_packet_sha256"],
            ],
            protocol["unavailable_fields"],
        )
        for forbidden in (
            "execve",
            "fork(",
            "clone(",
            "system(",
            "popen(",
            "connect(",
            "bind(",
            "listen(",
            "accept(",
            "unlink(",
            "rename(",
            "mount(",
            "provider",
            "argv",
            "ollama_v2_native_execution",
        ):
            self.assertNotIn(forbidden, sources)
        self.assertNotIn("WF_OV2_MSG_ACK", header)

    def test_builder_produces_reproducible_hardened_bundle_and_real_exchange(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wf-d22a-build-test-") as temporary:
            output = Path(temporary) / "output"
            first = _run_native_builder_cli(ROOT, output)
            artifacts = [output / native_builder.OUTPUT_NAME]

            self.assertEqual(0, first.returncode, first.stderr or first.stdout)
            self.assertEqual(1, len(artifacts))
            archive = artifacts[0]
            self.assertTrue(archive.is_file())
            with tarfile.open(archive, "r:gz") as bundle:
                names = bundle.getnames()
                self.assertEqual(sorted(names), names)
                bundle.extractall(Path(temporary) / "extracted", filter="data")
            root = Path(temporary) / "extracted"
            initiator = root / "bin/worldforge-ollama-v2-codec-initiator-d22a"
            responder = root / "bin/worldforge-ollama-v2-codec-responder-d22a"
            manifest = json.loads((root / "manifests/static-bundle-manifest.json").read_bytes())

            self.assertEqual("built", manifest["codec_implementation_state"])
            self.assertEqual("absent", manifest["effect_interpreter_state"])
            self.assertEqual("unavailable", manifest["availability"])
            for field in (
                "installed",
                "root_custody_verified",
                "source_custody_verified",
                "host_execution_enabled",
                "native_evidence_verified",
                "provider_execution_enabled",
                "catalog_admitted",
                "production_eligible",
            ):
                self.assertFalse(manifest[field], field)
            self.assertEqual((0, 0), _run_pair(initiator, responder, initiator_first=True))
            self.assertEqual((0, 0), _run_pair(initiator, responder, initiator_first=False))
            for executable in (initiator, responder):
                inspection = native_builder.inspect_elf(executable.read_bytes())
                self.assertEqual(183, inspection.machine)
                self.assertEqual(native_builder.EXPECTED_NEEDED, inspection.needed)
                self.assertTrue(inspection.pie)
                self.assertTrue(inspection.bind_now)
                self.assertTrue(inspection.relro)
                self.assertTrue(inspection.nx_stack)
                self.assertEqual(native_builder.EXPECTED_SECTIONS, inspection.sections)
                role = (
                    "codec_initiator_probe" if executable == initiator else "codec_responder_probe"
                )
                self.assertEqual(
                    native_builder.EXPECTED_VERSION_REQUIREMENTS[role],
                    inspection.version_requirements,
                )
                self.assertEqual(
                    native_builder.EXPECTED_SYMBOL_VERSIONS[role],
                    inspection.symbol_versions,
                )
                self.assertEqual(
                    native_builder.EXPECTED_DYNAMIC_SYMBOLS[role],
                    inspection.dynamic_symbols,
                )
                self.assertIn("__stack_chk_fail", inspection.dynamic_symbols)
                self.assertIn("__stack_chk_guard", inspection.dynamic_symbols)

            no_replace = _run_native_builder_cli(ROOT, output)
            self.assertNotEqual(0, no_replace.returncode)
            self.assertIn("refusing to replace existing artifact", no_replace.stderr)

            second_output = Path(temporary) / "second-output"
            second = _run_native_builder_cli(ROOT, second_output)
            self.assertEqual(0, second.returncode, second.stderr or second.stdout)
            second_archive = second_output / native_builder.OUTPUT_NAME
            self.assertEqual(archive.read_bytes(), second_archive.read_bytes())

    def test_responder_emits_exact_terminal_and_rejects_mutated_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wf-d22a-wire-test-") as temporary:
            protocol = json.loads(
                (ROOT / "native/ollama_v2_control/protocol-lock.json").read_bytes()
            )
            output = Path(temporary) / "output"
            archive = _build_non_authoritative_test_bundle(ROOT, output)[0]
            with tarfile.open(archive, "r:gz") as bundle:
                bundle.extractall(Path(temporary) / "extracted", filter="data")
            responder = Path(temporary) / "extracted/bin/worldforge-ollama-v2-codec-responder-d22a"

            valid = _request()
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                right.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                process = subprocess.Popen(
                    [str(responder)],
                    stdin=right.fileno(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                )
                right.close()
                left.send(valid)
                left.shutdown(socket.SHUT_WR)
                response = left.recv(MAX_RECORD + 1)
                self.assertEqual(168, len(response))
                self.assertEqual(2, struct.unpack_from(">H", response, 12)[0])
                self.assertEqual(1, struct.unpack_from(">Q", response, 16)[0])
                self.assertEqual(_packet_hash(valid), response[56:88])
                self.assertEqual(_packet_hash(valid), response[136:168])
                self.assertEqual(
                    _locked_expected_values(
                        protocol["unavailable_fields"],
                        request_hash=_packet_hash(valid),
                    ),
                    _locked_body_values(response, protocol["unavailable_fields"]),
                )
                self.assertEqual(b"", left.recv(1))
                self.assertEqual(0, process.wait(timeout=5))
            finally:
                left.close()
                right.close()

            mutations = {
                "magic": (slice(0, 1), b"X"),
                "major": (slice(9, 10), b"\x02"),
                "header-size": (slice(11, 12), b"\x77"),
                "type": (slice(13, 14), b"\x03"),
                "flags": (slice(15, 16), b"\x01"),
                "sequence": (slice(23, 24), b"\x01"),
                "body-length": (slice(27, 28), b"\x17"),
                "fd-count": (slice(29, 30), b"\x01"),
                "reserved": (slice(31, 32), b"\x01"),
                "nonce": (slice(32, 48), bytes(16)),
                "prior": (slice(56, 57), b"\x01"),
                "body-hash": (slice(88, 89), b"\x01"),
                "body": (slice(120, 121), b"\x01"),
            }
            for label, (where, replacement) in mutations.items():
                record = bytearray(valid)
                record[where] = replacement
                with self.subTest(label=label):
                    self.assertNotEqual(0, self._run_responder(responder, bytes(record)))

            deadline_mutations = {
                "deadline-expired": time.clock_gettime_ns(time.CLOCK_BOOTTIME) - 1,
                "deadline-too-far": time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 6_000_000_000,
            }
            for label, deadline_ns in deadline_mutations.items():
                record = bytearray(valid)
                record[48:56] = struct.pack(">Q", deadline_ns)
                with self.subTest(label=label):
                    self.assertNotEqual(0, self._run_responder(responder, bytes(record)))

            for field_name, body_offset, _size, _expected in protocol["negotiate_fields"]:
                record = bytearray(valid)
                record[HEADER_SIZE + body_offset] ^= 0x01
                record[88:120] = _sha(record[120:])
                with self.subTest(body_field=field_name):
                    self.assertNotEqual(0, self._run_responder(responder, bytes(record)))

    def test_initiator_emits_independently_decoded_big_endian_request(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wf-d22a-initiator-test-") as temporary:
            protocol = json.loads(
                (ROOT / "native/ollama_v2_control/protocol-lock.json").read_bytes()
            )
            archive = _build_non_authoritative_test_bundle(ROOT, Path(temporary) / "output")[0]
            with tarfile.open(archive, "r:gz") as bundle:
                bundle.extractall(Path(temporary) / "extracted", filter="data")
            initiator = Path(temporary) / (
                "extracted/bin/worldforge-ollama-v2-codec-initiator-d22a"
            )
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                right.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                process = subprocess.Popen(
                    [str(initiator)],
                    stdin=right.fileno(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                )
                right.close()
                request, ancillary, flags, _address = left.recvmsg(MAX_RECORD + 1, 256)
                self.assertEqual(144, len(request))
                self.assertEqual(0, flags)
                self.assertEqual(1, len(ancillary))
                self.assertEqual((socket.SOL_SOCKET, socket.SCM_CREDENTIALS), ancillary[0][:2])
                self.assertEqual(
                    (MAGIC, 1, 120, 1, 0, 0, 24, 0, 0),
                    struct.unpack_from(">8sHHHHQIHH", request, 0),
                )
                self.assertNotEqual(bytes(16), request[32:48])
                self.assertEqual(ZERO_HASH, request[56:88])
                self.assertEqual(_sha(request[120:]), request[88:120])
                self.assertEqual(
                    _locked_expected_values(protocol["negotiate_fields"], request_hash=b""),
                    _locked_body_values(request, protocol["negotiate_fields"]),
                )
                self.assertEqual(b"", left.recv(1))
                left.send(_response(request))
                left.shutdown(socket.SHUT_WR)
                self.assertEqual(0, process.wait(timeout=5))
            finally:
                left.close()
                right.close()

            mutations = {
                "magic": (slice(0, 1), b"X", False),
                "endian-major": (slice(8, 10), b"\x01\x00", False),
                "header-size": (slice(10, 12), b"\x00\x77", False),
                "type": (slice(12, 14), b"\x00\x03", False),
                "flags": (slice(14, 16), b"\x00\x01", False),
                "sequence": (slice(16, 24), bytes(8), False),
                "body-length": (slice(24, 28), b"\x00\x00\x00\x2f", False),
                "fd-count": (slice(28, 30), b"\x00\x01", False),
                "reserved": (slice(30, 32), b"\x00\x01", False),
                "nonce": (slice(32, 48), bytes(16), False),
                "deadline": (slice(48, 56), bytes(8), False),
                "prior": (slice(56, 88), bytes(32), False),
                "body-hash": (slice(88, 120), bytes(32), False),
            }
            for field_name, body_offset, size, _expected in protocol["unavailable_fields"]:
                mutations[f"body-{field_name}"] = (
                    slice(HEADER_SIZE + body_offset, HEADER_SIZE + body_offset + size),
                    b"\xff" * size,
                    True,
                )
            for label, (where, replacement, rehash_body) in mutations.items():
                with self.subTest(response_mutation=label):
                    self.assertNotEqual(
                        0,
                        self._run_initiator_with_mutated_response(
                            initiator,
                            where,
                            replacement,
                            rehash_body=rehash_body,
                        ),
                    )

    def test_socket_rights_truncation_eof_and_extra_packet_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wf-d22a-boundary-test-") as temporary:
            output = Path(temporary) / "output"
            archive = _build_non_authoritative_test_bundle(ROOT, output)[0]
            with tarfile.open(archive, "r:gz") as bundle:
                bundle.extractall(Path(temporary) / "extracted", filter="data")
            responder = Path(temporary) / (
                "extracted/bin/worldforge-ollama-v2-codec-responder-d22a"
            )

            stream_left, stream_right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                process = subprocess.Popen(
                    [str(responder)],
                    stdin=stream_right.fileno(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                )
                self.assertEqual(67, process.wait(timeout=5))
            finally:
                stream_left.close()
                stream_right.close()

            self.assertEqual(68, self._run_responder(responder, bytes(MAX_RECORD + 1)))

            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            read_descriptor, write_descriptor = os.pipe()
            try:
                left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                right.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                process = subprocess.Popen(
                    [str(responder)],
                    stdin=right.fileno(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                )
                right.close()
                left.sendmsg(
                    [_request()],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", write_descriptor))],
                )
                os.close(write_descriptor)
                write_descriptor = -1
                left.shutdown(socket.SHUT_WR)
                self.assertEqual(67, process.wait(timeout=5))
                self.assertEqual(b"", os.read(read_descriptor, 1))
            finally:
                left.close()
                right.close()
                os.close(read_descriptor)
                if write_descriptor >= 0:
                    os.close(write_descriptor)

            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                right.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                process = subprocess.Popen(
                    [str(responder)],
                    stdin=right.fileno(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                )
                right.close()
                left.send(_request())
                left.send(b"extra")
                left.shutdown(socket.SHUT_WR)
                self.assertEqual(68, process.wait(timeout=5))
            finally:
                left.close()
                right.close()

            deadline = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 100_000_000
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                right.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                process = subprocess.Popen(
                    [str(responder)],
                    stdin=right.fileno(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                )
                right.close()
                left.send(_request(deadline_ns=deadline))
                self.assertEqual(69, process.wait(timeout=5))
            finally:
                left.close()
                right.close()

    def test_zero_length_seqpacket_is_never_accepted_as_eof_in_either_direction(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wf-d22a-zero-record-red-") as temporary:
            archive = _build_non_authoritative_test_bundle(ROOT, Path(temporary) / "output")[0]
            with tarfile.open(archive, "r:gz") as bundle:
                bundle.extractall(Path(temporary) / "extracted", filter="data")
            initiator = Path(temporary) / (
                "extracted/bin/worldforge-ollama-v2-codec-initiator-d22a"
            )
            responder = Path(temporary) / (
                "extracted/bin/worldforge-ollama-v2-codec-responder-d22a"
            )

            for shutdown_after in (False, True):
                with self.subTest(direction="request", shutdown_after=shutdown_after):
                    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    try:
                        for endpoint in (left, right):
                            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                        process = subprocess.Popen(
                            [str(responder)],
                            stdin=right.fileno(),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            close_fds=True,
                        )
                        right.close()
                        left.send(_request())
                        self.assertEqual(0, left.send(b""))
                        if shutdown_after:
                            left.shutdown(socket.SHUT_WR)
                        self.assertEqual(66, process.wait(timeout=5))
                    finally:
                        left.close()
                        right.close()

                with self.subTest(direction="response", shutdown_after=shutdown_after):
                    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    try:
                        for endpoint in (left, right):
                            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                        process = subprocess.Popen(
                            [str(initiator)],
                            stdin=right.fileno(),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            close_fds=True,
                        )
                        right.close()
                        request = left.recv(MAX_RECORD + 1)
                        self.assertEqual(144, len(request))
                        self.assertEqual(b"", left.recv(1))
                        left.send(_response(request))
                        self.assertEqual(0, left.send(b""))
                        if shutdown_after:
                            left.shutdown(socket.SHUT_WR)
                        self.assertEqual(66, process.wait(timeout=5))
                    finally:
                        left.close()
                        right.close()

            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            read_descriptor, write_descriptor = os.pipe()
            try:
                for endpoint in (left, right):
                    endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                process = subprocess.Popen(
                    [str(responder)],
                    stdin=right.fileno(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                )
                right.close()
                left.send(_request())
                self.assertEqual(
                    0,
                    left.sendmsg(
                        [b""],
                        [
                            (
                                socket.SOL_SOCKET,
                                socket.SCM_RIGHTS,
                                struct.pack("i", write_descriptor),
                            )
                        ],
                    ),
                )
                os.close(write_descriptor)
                write_descriptor = -1
                left.shutdown(socket.SHUT_WR)
                self.assertEqual(67, process.wait(timeout=5))
                self.assertEqual(b"", os.read(read_descriptor, 1))
            finally:
                left.close()
                right.close()
                os.close(read_descriptor)
                if write_descriptor >= 0:
                    os.close(write_descriptor)

    def test_source_lock_tamper_and_negative_elf_fixtures_fail_before_claim(self) -> None:
        source_lock = json.loads((ROOT / "native/ollama_v2_control/source-lock.json").read_bytes())
        locked_paths = [entry["logical_path"] for entry in source_lock["entries"]]
        self.assertNotIn("native/ollama_v2_control/source-lock.json", locked_paths)
        self.assertFalse(any(path.endswith(".o") or path.endswith(".elf") for path in locked_paths))

        with tempfile.TemporaryDirectory(prefix="wf-d22a-tamper-test-") as temporary:
            source = Path(temporary) / "source"
            for relative in (*locked_paths, "native/ollama_v2_control/source-lock.json"):
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            target = source / "native/ollama_v2_control/codec_responder.c"
            target.write_bytes(target.read_bytes() + b"\n")
            with patch.object(native_builder.subprocess, "run") as runner:
                with self.assertRaisesRegex(
                    native_builder.NativeBuildError, "source lock mismatch"
                ):
                    _build_non_authoritative_test_bundle(source, Path(temporary) / "output")
                runner.assert_not_called()

        with self.assertRaisesRegex(native_builder.NativeBuildError, "ELF is truncated"):
            native_builder.inspect_elf(b"not-elf")
        with tempfile.TemporaryDirectory(prefix="wf-d22a-elf-negative-") as temporary:
            archive = _build_non_authoritative_test_bundle(ROOT, Path(temporary) / "output")[0]
            with tarfile.open(archive, "r:gz") as bundle:
                member = bundle.extractfile("bin/worldforge-ollama-v2-codec-initiator-d22a")
                self.assertIsNotNone(member)
                valid_bytes = member.read()
                valid = bytearray(valid_bytes)
            valid[18:20] = struct.pack("<H", 62)
            with self.assertRaisesRegex(native_builder.NativeBuildError, "AArch64"):
                native_builder._verify_elf(bytes(valid), "codec_initiator_probe")

            for symbol, replacement in (
                (b"__stack_chk_fail", b"__stack_chx_fail"),
                (b"__stack_chk_guard", b"__stack_chx_guard"),
            ):
                changed = valid_bytes.replace(symbol, replacement, 1)
                self.assertNotEqual(valid_bytes, changed)
                with self.subTest(missing_canary_symbol=symbol.decode()):
                    with self.assertRaisesRegex(
                        native_builder.NativeBuildError, "dynamic symbol census"
                    ):
                        native_builder._verify_elf(changed, "codec_initiator_probe")

            changed_version = valid_bytes.replace(b"GLIBC_2.25", b"GLIBC_2.24", 1)
            self.assertNotEqual(valid_bytes, changed_version)
            with self.assertRaisesRegex(native_builder.NativeBuildError, "version census"):
                native_builder._verify_elf(changed_version, "codec_initiator_probe")

            shoff = struct.unpack_from("<Q", valid_bytes, 40)[0]
            shnum = struct.unpack_from("<H", valid_bytes, 60)[0]
            shstrndx = struct.unpack_from("<H", valid_bytes, 62)[0]
            sections = [
                struct.unpack_from("<IIQQQQIIQQ", valid_bytes, shoff + index * 64)
                for index in range(shnum)
            ]
            shstr = sections[shstrndx]
            shstr_data = valid_bytes[shstr[4] : shstr[4] + shstr[5]]
            section_names = [
                native_builder._cstring(shstr_data, section[0], len(shstr_data))
                for section in sections
            ]
            dynsym = sections[section_names.index(".dynsym")]
            dynstr = sections[section_names.index(".dynstr")]
            dynstr_data = valid_bytes[dynstr[4] : dynstr[4] + dynstr[5]]
            getrandom_index = next(
                index
                for index, offset in enumerate(range(dynsym[4], dynsym[4] + dynsym[5], 24))
                if native_builder._cstring(
                    dynstr_data,
                    struct.unpack_from("<I", valid_bytes, offset)[0],
                    len(dynstr_data),
                )
                == "getrandom"
            )
            versym = sections[section_names.index(".gnu.version")]
            changed_assignment = bytearray(valid_bytes)
            struct.pack_into("<H", changed_assignment, versym[4] + getrandom_index * 2, 2)
            with self.assertRaisesRegex(native_builder.NativeBuildError, "symbol-version census"):
                native_builder._verify_elf(bytes(changed_assignment), "codec_initiator_probe")

            changed_section = valid_bytes.replace(b".comment\0", b".comnent\0", 1)
            self.assertNotEqual(valid_bytes, changed_section)
            with self.assertRaisesRegex(native_builder.NativeBuildError, "section census"):
                native_builder._verify_elf(changed_section, "codec_initiator_probe")

    def test_source_manifest_requires_the_exact_fixed_census_before_driver_query(self) -> None:
        expected_census = (
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
        for mutation in (
            "remove-compiled-input",
            "relabel-compiled-input",
            "extra-input",
            "casefold-alias",
            "reorder",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory(prefix="wf-d22a-source-census-red-") as temporary,
            ):
                source = Path(temporary) / "source"
                document = _copy_locked_source_tree(source)
                entries = document["entries"]
                if mutation == "remove-compiled-input":
                    document["entries"] = [
                        entry
                        for entry in entries
                        if entry["logical_path"] != "native/ollama_v2_control/codec_initiator.c"
                    ]
                elif mutation == "relabel-compiled-input":
                    changed_entry = next(
                        entry
                        for entry in entries
                        if entry["logical_path"] == "native/ollama_v2_control/codec_responder.c"
                    )
                    changed_entry["artifact_role"] = "shared_codec_source"
                    changed_entry.update(json.loads(_canonical_rehash(changed_entry)))
                elif mutation in {"extra-input", "casefold-alias"}:
                    original_entry = next(
                        entry
                        for entry in entries
                        if entry["logical_path"] == "native/ollama_v2_control/codec_initiator.c"
                    )
                    changed_entry = dict(original_entry)
                    changed_entry["logical_path"] = (
                        "native/ollama_v2_control/extra.c"
                        if mutation == "extra-input"
                        else "native/ollama_v2_control/Codec_initiator.c"
                    )
                    changed_entry["artifact_role"] = "shared_codec_source"
                    changed_entry.update(json.loads(_canonical_rehash(changed_entry)))
                    document["entries"] = sorted(
                        [*entries, changed_entry], key=lambda entry: entry["logical_path"]
                    )
                    extra = source / changed_entry["logical_path"]
                    extra.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source / "native/ollama_v2_control/codec_initiator.c", extra)
                else:
                    document["entries"] = list(reversed(entries))
                (source / "native/ollama_v2_control/source-lock.json").write_bytes(
                    _canonical_rehash(document)
                )
                with (
                    patch.object(
                        native_builder.subprocess,
                        "run",
                        side_effect=AssertionError("driver queried for incomplete source census"),
                    ) as runner,
                    self.assertRaises(native_builder.NativeBuildError),
                ):
                    _build_non_authoritative_test_bundle(source, Path(temporary) / "output")
                runner.assert_not_called()
        self.assertEqual(expected_census, native_builder.CANONICAL_SOURCE_INVENTORY_D22A)

    def test_gnu_linker_scripts_are_parsed_and_resolved_to_exact_locked_inputs(self) -> None:
        libc_script = Path("/usr/lib/aarch64-linux-gnu/libc.so").read_bytes()
        libgcc_script = Path("/usr/lib/gcc/aarch64-linux-gnu/13/libgcc_s.so").read_bytes()
        self.assertEqual(
            (
                ("/lib/aarch64-linux-gnu/libc.so.6", False),
                ("/usr/lib/aarch64-linux-gnu/libc_nonshared.a", False),
                ("/lib/ld-linux-aarch64.so.1", True),
            ),
            native_builder._parse_gnu_linker_script(libc_script),
        )
        self.assertEqual(
            (("libgcc_s.so.1", False), ("-lgcc", False)),
            native_builder._parse_gnu_linker_script(libgcc_script),
        )
        self.assertEqual(
            (("/fixed/libone.so", False), ("-ltwo", True)),
            native_builder._parse_gnu_linker_script(
                b"INPUT ( /fixed/libone.so AS_NEEDED ( -ltwo ) )"
            ),
        )
        for payload in (
            b'SEARCH_DIR("/tmp") GROUP ( -lgcc )',
            b"GROUP ( -lgcc",
            b"GROUP ( GROUP ( -lgcc ) )",
            b"GROUP ( ) trailing",
            b"/* unterminated GROUP ( -lgcc )",
            b"GROUP ( -l:unsafe )",
        ):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(native_builder.NativeBuildError, "linker script"):
                    native_builder._parse_gnu_linker_script(payload)

        manifest, _raw = native_builder._load_contract(
            ROOT,
            native_builder.TOOLCHAIN_LOCK,
            native_builder.OllamaV2NativeToolchainManifestD22A,
        )
        retained = native_builder._verify_toolchain_lock(
            manifest,
            native_builder._environment(),
        )
        try:
            self.assertEqual(
                (
                    (
                        "/usr/lib/aarch64-linux-gnu/libc.so",
                        "/usr/lib/aarch64-linux-gnu/libc.so.6",
                    ),
                    (
                        "/usr/lib/aarch64-linux-gnu/libc.so",
                        "/usr/lib/aarch64-linux-gnu/libc_nonshared.a",
                    ),
                    (
                        "/usr/lib/aarch64-linux-gnu/libc.so",
                        "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
                    ),
                    (
                        "/usr/lib/gcc/aarch64-linux-gnu/13/libgcc_s.so",
                        "/usr/lib/aarch64-linux-gnu/libgcc_s.so.1",
                    ),
                    (
                        "/usr/lib/gcc/aarch64-linux-gnu/13/libgcc_s.so",
                        "/usr/lib/gcc/aarch64-linux-gnu/13/libgcc.a",
                    ),
                ),
                native_builder._verify_declared_linker_script_closure(retained),
            )
        finally:
            retained.close()

    def test_authoritative_link_diagnostics_bind_observed_inputs_to_lock(self) -> None:
        completed_links: list[tuple[subprocess.CompletedProcess[str], Path]] = []
        original_run_driver = native_builder._run_driver

        def capture_successful_link(
            toolchain,
            arguments: list[str],
            *,
            cwd: Path,
            env: dict[str, str],
        ) -> subprocess.CompletedProcess[str]:
            completed = original_run_driver(toolchain, arguments, cwd=cwd, env=env)
            if "-o" in arguments and "-c" not in arguments:
                completed_links.append((completed, cwd.parent))
            return completed

        with (
            tempfile.TemporaryDirectory(prefix="wf-d22a-real-link-diagnostic-") as temporary,
            patch.object(native_builder, "_run_driver", side_effect=capture_successful_link),
        ):
            root = Path(temporary)
            _build_non_authoritative_test_bundle(ROOT, root / "output")
            observed = _independently_observed_link_inputs(completed_links)

        document = json.loads((ROOT / "native/ollama_v2_control/toolchain-lock.json").read_bytes())
        declared = {entry["resolved_path"]: entry["logical_role"] for entry in document["entries"]}
        self.assertEqual(4, len(completed_links))
        self.assertTrue(observed)
        self.assertEqual(set(), observed - declared.keys())
        self.assertEqual(
            (
                "/usr/lib/gcc/aarch64-linux-gnu/13/../../../aarch64-linux-gnu/Scrt1.o",
                "/usr/lib/gcc/aarch64-linux-gnu/13/../../../aarch64-linux-gnu/crti.o",
                "/usr/lib/gcc/aarch64-linux-gnu/13/../../../aarch64-linux-gnu/libgcc_s.so.1",
                "/usr/lib/gcc/aarch64-linux-gnu/13/../../../aarch64-linux-gnu/libc.so",
                "/usr/lib/gcc/aarch64-linux-gnu/13/../../../aarch64-linux-gnu/libgcc_s.so.1",
                "/usr/lib/gcc/aarch64-linux-gnu/13/../../../aarch64-linux-gnu/crtn.o",
            ),
            tuple(
                line for line in completed_links[0][0].stdout.splitlines() if "/../../../" in line
            ),
        )
        observed_roles = {declared[path] for path in observed}
        self.assertIn("linker_plugin", observed_roles)
        self.assertIn("compiler_lto_wrapper", observed_roles)

    def test_successful_link_diagnostics_are_closed_canonical_and_complete(self) -> None:
        def mutate_stderr(stderr: str, mutation: str) -> str:
            lines = stderr.splitlines()
            if mutation == "malformed":
                index = next(
                    index
                    for index, line in enumerate(lines)
                    if line.startswith("COLLECT_GCC_OPTIONS=")
                )
                lines[index] += " MALFORMED"
            elif mutation == "localized":
                lines[0] = "DIAGNOSTICO LOCALIZADO MALFORMADO"
            elif mutation == "extra":
                lines.append("DIAGNOSTICO LOCALIZADO MALFORMADO")
            elif mutation == "reordered":
                lines[0], lines[1] = lines[1], lines[0]
            elif mutation == "duplicate":
                lines.insert(1, lines[0])
            elif mutation == "suppressed":
                del lines[0]
            else:
                raise AssertionError(f"unknown diagnostic mutation: {mutation}")
            return "\n".join(lines) + "\n"

        def mutate_stdout(stdout: str, mutation: str, alias_root: Path) -> str:
            lines = stdout.splitlines()
            if mutation == "stdout-malformed":
                lines[0] = "relative-or-localized-input"
            elif mutation == "stdout-extra":
                lines.append(lines[0])
            elif mutation == "stdout-reordered":
                lines[0], lines[1] = lines[1], lines[0]
            elif mutation == "stdout-duplicate":
                lines.insert(1, lines[0])
            elif mutation == "stdout-suppressed":
                del lines[0]
            elif mutation == "stdout-symlink-alias":
                alias = alias_root / "trace-input-alias"
                if not alias.is_symlink():
                    alias.symlink_to(Path(lines[0]).resolve(strict=True))
                lines[0] = str(alias)
            elif mutation == "stdout-dot-alias":
                lines[0] = "/./" + lines[0].removeprefix("/")
            elif mutation == "stdout-dotdot-alias":
                original = Path(lines[0])
                lines[0] = f"{original.parent}/../{original.parent.name}/{original.name}"
            elif mutation == "stdout-duplicate-slash":
                separator = lines[0].find("/", 1)
                if separator < 0:
                    raise AssertionError("system trace path has no internal separator")
                lines[0] = lines[0][:separator] + "/" + lines[0][separator:]
            else:
                raise AssertionError(f"unknown stdout diagnostic mutation: {mutation}")
            return "\n".join(lines) + "\n"

        for mutation in (
            "malformed",
            "localized",
            "extra",
            "reordered",
            "duplicate",
            "suppressed",
            "stdout-malformed",
            "stdout-extra",
            "stdout-reordered",
            "stdout-duplicate",
            "stdout-suppressed",
            "stdout-symlink-alias",
            "stdout-dot-alias",
            "stdout-dotdot-alias",
            "stdout-duplicate-slash",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory(prefix="wf-d22a-link-diagnostic-red-") as temporary,
            ):
                original_run_driver = native_builder._run_driver
                changed_links = 0

                def tamper_successful_link(
                    toolchain,
                    arguments: list[str],
                    *,
                    cwd: Path,
                    env: dict[str, str],
                    _mutation: str = mutation,
                    _run=original_run_driver,
                ) -> subprocess.CompletedProcess[str]:
                    nonlocal changed_links
                    completed = _run(toolchain, arguments, cwd=cwd, env=env)
                    if "-o" not in arguments or "-c" in arguments:
                        return completed
                    changed_links += 1
                    return subprocess.CompletedProcess(
                        completed.args,
                        completed.returncode,
                        (
                            mutate_stdout(completed.stdout, _mutation, Path(temporary))
                            if _mutation.startswith("stdout-")
                            else completed.stdout
                        ),
                        (
                            completed.stderr
                            if _mutation.startswith("stdout-")
                            else mutate_stderr(completed.stderr, _mutation)
                        ),
                    )

                output = Path(temporary) / "output"
                with (
                    patch.object(native_builder, "_run_driver", side_effect=tamper_successful_link),
                    self.assertRaisesRegex(
                        native_builder.NativeBuildError,
                        "successful link input",
                    ),
                ):
                    _build_non_authoritative_test_bundle(ROOT, output)
                self.assertGreaterEqual(changed_links, 1)
                self.assertFalse((output / native_builder.OUTPUT_NAME).exists())
        self.assertRegex(
            native_builder.canonical_ollama_v2_native_build_profile_d22a().compiler_link_diagnostic_sha256,
            r"^[0-9a-f]{64}$",
        )

    def test_undeclared_actual_link_input_blocks_bundle_publication(self) -> None:
        original_run_driver = native_builder._run_driver
        extra_input = "/usr/lib/aarch64-linux-gnu/libdl.so.2"
        locked_paths = {
            entry["resolved_path"]
            for entry in json.loads(
                (ROOT / "native/ollama_v2_control/toolchain-lock.json").read_bytes()
            )["entries"]
        }
        self.assertNotIn(extra_input, locked_paths)
        injected = False

        def inject_actual_regular_link_input(
            toolchain,
            arguments: list[str],
            *,
            cwd: Path,
            env: dict[str, str],
        ) -> subprocess.CompletedProcess[str]:
            nonlocal injected
            changed = list(arguments)
            if not injected and "-o" in changed and "-c" not in changed:
                changed.insert(changed.index("-o"), extra_input)
                injected = True
            return original_run_driver(toolchain, changed, cwd=cwd, env=env)

        with (
            tempfile.TemporaryDirectory(prefix="wf-d22a-undeclared-link-input-") as temporary,
            patch.object(
                native_builder, "_run_driver", side_effect=inject_actual_regular_link_input
            ),
            self.assertRaisesRegex(native_builder.NativeBuildError, "successful link input"),
        ):
            output = Path(temporary) / "output"
            _build_non_authoritative_test_bundle(ROOT, output)
        self.assertTrue(injected)
        self.assertFalse((output / native_builder.OUTPUT_NAME).exists())

    def test_toolchain_manifest_requires_all_126_fixed_entries_before_driver_query(self) -> None:
        original = json.loads((ROOT / "native/ollama_v2_control/toolchain-lock.json").read_bytes())
        self.assertEqual(126, len(original["entries"]))
        mutations = {
            "compiler-and-linker-only": lambda entry: (
                entry["logical_role"] in {"compiler_driver", "linker"}
            ),
            "omit-system-headers": lambda entry: entry["logical_role"] != "system_header",
            "omit-crt": lambda entry: not entry["logical_role"].startswith("crt_"),
            "omit-libc": lambda entry: (
                entry["logical_role"]
                not in {
                    "libc_linker_script",
                    "libc_runtime",
                    "libc_nonshared_archive",
                }
            ),
            "omit-libgcc-linker-script": lambda entry: (
                entry["logical_role"] != "libgcc_linker_script"
            ),
            "omit-libc-nonshared": lambda entry: entry["logical_role"] != "libc_nonshared_archive",
            "omit-lto-wrapper": lambda entry: entry["logical_role"] != "compiler_lto_wrapper",
            "omit-linker-plugin": lambda entry: entry["logical_role"] != "linker_plugin",
            "omit-loader": lambda entry: entry["logical_role"] != "dynamic_loader",
        }
        for label, keep in mutations.items():
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory(prefix="wf-d22a-toolchain-census-red-") as temporary,
            ):
                source = Path(temporary) / "source"
                source_document = _copy_locked_source_tree(source)
                changed = dict(original)
                changed["entries"] = [entry for entry in original["entries"] if keep(entry)]
                _rewrite_toolchain_and_source(source, source_document, changed)
                with (
                    patch.object(
                        native_builder.subprocess,
                        "run",
                        side_effect=AssertionError(
                            "driver queried for incomplete toolchain census"
                        ),
                    ) as runner,
                    self.assertRaisesRegex(native_builder.NativeBuildError, "toolchain inventory"),
                ):
                    _build_non_authoritative_test_bundle(source, Path(temporary) / "output")
                runner.assert_not_called()

        for role in (
            "compiler_lto_wrapper",
            "libc_nonshared_archive",
            "libgcc_linker_script",
            "linker_plugin",
        ):
            with (
                self.subTest(drift=role),
                patch.object(
                    native_builder.subprocess,
                    "run",
                    side_effect=AssertionError("driver queried before linker-input drift"),
                ) as runner,
            ):
                manifest, _raw = native_builder._load_contract(
                    ROOT,
                    native_builder.TOOLCHAIN_LOCK,
                    native_builder.OllamaV2NativeToolchainManifestD22A,
                )
                target = next(entry for entry in manifest.entries if entry.logical_role == role)
                changed_target = replace(
                    target, sha256=("0" if target.sha256[0] != "0" else "1") + target.sha256[1:]
                )
                changed = replace(
                    manifest,
                    entries=tuple(
                        changed_target if entry is target else entry for entry in manifest.entries
                    ),
                )
                with self.assertRaisesRegex(native_builder.NativeBuildError, "toolchain lock"):
                    native_builder._verify_toolchain_lock(
                        changed,
                        native_builder._environment(),
                    )
                runner.assert_not_called()

        for label in ("relabel", "extra", "case-alias", "reorder"):
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory(
                    prefix="wf-d22a-toolchain-census-triangulate-"
                ) as temporary,
            ):
                source = Path(temporary) / "source"
                source_document = _copy_locked_source_tree(source)
                changed = json.loads(json.dumps(original))
                if label == "relabel":
                    entry = next(
                        item
                        for item in changed["entries"]
                        if item["logical_role"] == "linker_plugin"
                    )
                    entry["logical_role"] = "system_header"
                    entry.update(json.loads(_canonical_rehash(entry)))
                    changed["entries"].sort(
                        key=lambda item: (item["logical_role"], item["resolved_path"])
                    )
                elif label == "extra":
                    entry = dict(
                        next(
                            item
                            for item in changed["entries"]
                            if item["logical_role"] == "assembler"
                        )
                    )
                    entry["logical_role"] = "system_header"
                    entry.update(json.loads(_canonical_rehash(entry)))
                    changed["entries"].append(entry)
                    changed["entries"].sort(
                        key=lambda item: (item["logical_role"], item["resolved_path"])
                    )
                elif label == "case-alias":
                    entry = next(
                        item for item in changed["entries"] if item["logical_role"] == "assembler"
                    )
                    entry["resolved_path"] = "/usr/bin/AARCH64-linux-gnu-as"
                    entry.update(json.loads(_canonical_rehash(entry)))
                    changed["entries"].sort(
                        key=lambda item: (item["logical_role"], item["resolved_path"])
                    )
                else:
                    changed["entries"] = list(reversed(changed["entries"]))
                _rewrite_toolchain_and_source(source, source_document, changed)
                with (
                    patch.object(
                        native_builder.subprocess,
                        "run",
                        side_effect=AssertionError("driver queried for noncanonical census"),
                    ) as runner,
                    self.assertRaises(native_builder.NativeBuildError),
                ):
                    _build_non_authoritative_test_bundle(source, Path(temporary) / "output")
                runner.assert_not_called()

    def test_retained_driver_and_late_path_drift_block_publication(self) -> None:
        profile = native_builder.canonical_ollama_v2_native_build_profile_d22a()
        output_name = native_builder.OUTPUT_NAME
        original_run = subprocess.run
        original_build_one = native_builder._build_one
        original_lstat = native_builder._path_lstat
        late = False
        driver_invocations = 0

        def run_checked(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            nonlocal driver_invocations
            if command[0] == profile.compiler_driver:
                executable = kwargs.get("executable")
                self.assertIsInstance(executable, str)
                self.assertTrue(str(executable).startswith("/proc/self/fd/"))
                descriptor = int(str(executable).rsplit("/", 1)[1])
                self.assertIn(descriptor, kwargs.get("pass_fds", ()))
                os.fstat(descriptor)
                driver_invocations += 1
            return original_run(command, **kwargs)

        def build_then_drift(*args: object, **kwargs: object):
            nonlocal late
            result = original_build_one(*args, **kwargs)
            late = True
            return result

        def late_lstat(path: Path):
            info = original_lstat(path)
            if late and str(path) == profile.compiler_driver:
                return types.SimpleNamespace(
                    st_mode=info.st_mode,
                    st_uid=info.st_uid,
                    st_gid=info.st_gid,
                    st_dev=info.st_dev,
                    st_ino=info.st_ino + 1,
                    st_size=info.st_size,
                    st_mtime_ns=info.st_mtime_ns,
                    st_ctime_ns=info.st_ctime_ns,
                )
            return info

        with tempfile.TemporaryDirectory(prefix="wf-d22a-late-tool-drift-") as temporary:
            output = Path(temporary) / "output"
            with (
                patch.object(native_builder, "_path_lstat", side_effect=late_lstat),
                patch.object(native_builder, "_build_one", side_effect=build_then_drift),
                patch.object(native_builder.subprocess, "run", side_effect=run_checked),
                self.assertRaisesRegex(native_builder.NativeBuildError, "toolchain.*identity"),
            ):
                _build_non_authoritative_test_bundle(ROOT, output)
            self.assertGreaterEqual(driver_invocations, 5)
            self.assertFalse((output / output_name).exists())

        with tempfile.TemporaryDirectory(prefix="wf-d22a-insecure-tool-path-") as temporary:
            path = Path(temporary) / "tool"
            path.write_bytes(b"tool")
            path.chmod(0o666)
            with self.assertRaisesRegex(
                native_builder.NativeBuildError, "root-owned|group/world-writable"
            ):
                native_builder._assert_secure_toolchain_path(path)
            alias = Path(temporary) / "alias"
            alias.symlink_to(path)
            with self.assertRaisesRegex(native_builder.NativeBuildError, "symlink|canonical"):
                native_builder._assert_secure_toolchain_path(alias)

    def test_all_source_bytes_are_retained_and_late_drift_blocks_publication(self) -> None:
        relative = Path("native/ollama_v2_control/wf_ov2_protocol.c")
        with tempfile.TemporaryDirectory(prefix="wf-d22a-late-source-drift-") as temporary:
            source = Path(temporary) / "source"
            _copy_locked_source_tree(source)
            original = (source / relative).read_bytes()
            changed = original.replace(
                b"'W', 'F', '5', '0', 'D', '2', '2', 'A'",
                b"'W', 'F', '5', '0', 'D', '2', '2', 'B'",
                1,
            )
            self.assertNotEqual(original, changed)
            output = Path(temporary) / "output"
            materialized: list[bytes] = []
            original_build_one = native_builder._build_one
            mutated = False

            def mutate_before_materialization(*args: object, **kwargs: object):
                nonlocal mutated
                if not mutated:
                    (source / relative).write_bytes(changed)
                    mutated = True
                result = original_build_one(*args, **kwargs)
                build_root = args[1]
                self.assertIsInstance(build_root, Path)
                materialized.append((build_root / "source" / relative).read_bytes())
                return result

            with (
                patch.object(
                    native_builder,
                    "_build_one",
                    side_effect=mutate_before_materialization,
                ),
                self.assertRaisesRegex(native_builder.NativeBuildError, "source.*(identity|byte)"),
            ):
                _build_non_authoritative_test_bundle(source, output)
            self.assertEqual([original], materialized)
            self.assertFalse((output / native_builder.OUTPUT_NAME).exists())

    def test_retained_source_detects_deleted_replaced_and_restored_paths(self) -> None:
        relative = Path("native/ollama_v2_control/wf_ov2_protocol.c")
        for mutation in ("deleted", "replaced", "replaced-then-restored"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory(prefix="wf-d22a-source-identity-") as temporary,
            ):
                source = Path(temporary) / "source"
                _copy_locked_source_tree(source)
                manifest, _raw = native_builder._load_contract(
                    source,
                    native_builder.SOURCE_LOCK,
                    native_builder.OllamaV2NativeSourceManifestD22A,
                )
                retained = native_builder._verify_source_lock(source, manifest)
                path = source / relative
                original = path.read_bytes()
                try:
                    if mutation == "deleted":
                        path.unlink()
                    elif mutation == "replaced":
                        replacement = path.with_name("replacement.c")
                        replacement.write_bytes(original)
                        os.replace(replacement, path)
                    else:
                        saved = path.with_name("saved.c")
                        path.rename(saved)
                        path.write_bytes(original)
                        os.replace(saved, path)
                    with self.assertRaisesRegex(
                        native_builder.NativeBuildError,
                        "source.*(unavailable|identity|byte)",
                    ):
                        native_builder._reverify_source_lock(retained)
                finally:
                    retained.close()

    def test_tool_runtime_library_closure_is_exact_and_recursive(self) -> None:
        manifest, _raw = native_builder._load_contract(
            ROOT,
            native_builder.TOOLCHAIN_LOCK,
            native_builder.OllamaV2NativeToolchainManifestD22A,
        )
        expected_runtime_roles = {
            "dynamic_loader": "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
            "libc_runtime": "/usr/lib/aarch64-linux-gnu/libc.so.6",
            "loader_cache": "/etc/ld.so.cache",
            "tool_runtime_libbfd": "/usr/lib/aarch64-linux-gnu/libbfd-2.42-system.so",
            "tool_runtime_libctf": "/usr/lib/aarch64-linux-gnu/libctf.so.0.0.0",
            "tool_runtime_libgmp": "/usr/lib/aarch64-linux-gnu/libgmp.so.10.5.0",
            "tool_runtime_libisl": "/usr/lib/aarch64-linux-gnu/libisl.so.23.3.0",
            "tool_runtime_libjansson": "/usr/lib/aarch64-linux-gnu/libjansson.so.4.14.0",
            "tool_runtime_libm": "/usr/lib/aarch64-linux-gnu/libm.so.6",
            "tool_runtime_libmpc": "/usr/lib/aarch64-linux-gnu/libmpc.so.3.3.1",
            "tool_runtime_libmpfr": "/usr/lib/aarch64-linux-gnu/libmpfr.so.6.2.1",
            "tool_runtime_libopcodes": "/usr/lib/aarch64-linux-gnu/libopcodes-2.42-system.so",
            "tool_runtime_libsframe": "/usr/lib/aarch64-linux-gnu/libsframe.so.1.0.0",
            "tool_runtime_libz": "/usr/lib/aarch64-linux-gnu/libz.so.1.3",
            "tool_runtime_libzstd": "/usr/lib/aarch64-linux-gnu/libzstd.so.1.5.5",
        }
        by_role = {entry.logical_role: entry.resolved_path for entry in manifest.entries}
        self.assertEqual(
            expected_runtime_roles, {role: by_role[role] for role in expected_runtime_roles}
        )

        retained_entries = tuple(
            native_builder._retain_toolchain_entry(entry) for entry in manifest.entries
        )
        retained = native_builder._RetainedToolchain(manifest, retained_entries)
        try:
            edges = native_builder._verify_declared_tool_runtime_closure(retained)
        finally:
            retained.close()
        providers = {provider for _consumer, _soname, provider in edges}
        self.assertEqual(
            {path for role, path in expected_runtime_roles.items() if role != "loader_cache"},
            providers,
        )
        self.assertIn(
            (
                "/usr/lib/aarch64-linux-gnu/libbfd-2.42-system.so",
                "libsframe.so.1",
                "/usr/lib/aarch64-linux-gnu/libsframe.so.1.0.0",
            ),
            edges,
        )

    def test_each_tool_runtime_dependency_omission_fails_before_driver_query(self) -> None:
        original = json.loads((ROOT / "native/ollama_v2_control/toolchain-lock.json").read_bytes())
        omitted_roles = (
            "tool_runtime_libisl",
            "tool_runtime_libmpc",
            "tool_runtime_libmpfr",
            "tool_runtime_libgmp",
            "tool_runtime_libz",
            "tool_runtime_libzstd",
            "tool_runtime_libopcodes",
            "tool_runtime_libbfd",
            "tool_runtime_libctf",
            "tool_runtime_libjansson",
            "tool_runtime_libm",
            "tool_runtime_libsframe",
            "loader_cache",
        )
        self.assertTrue(
            set(omitted_roles).issubset({item["logical_role"] for item in original["entries"]})
        )
        for role in omitted_roles:
            with (
                self.subTest(role=role),
                tempfile.TemporaryDirectory(prefix="wf-d22a-runtime-omission-") as temporary,
            ):
                source = Path(temporary) / "source"
                source_document = _copy_locked_source_tree(source)
                changed = dict(original)
                changed["entries"] = [
                    entry for entry in original["entries"] if entry["logical_role"] != role
                ]
                _rewrite_toolchain_and_source(source, source_document, changed)
                with (
                    patch.object(
                        native_builder.subprocess,
                        "run",
                        side_effect=AssertionError(
                            "driver queried before runtime-closure rejection"
                        ),
                    ) as runner,
                    self.assertRaisesRegex(
                        native_builder.NativeBuildError,
                        "toolchain inventory|runtime dependency|loader cache",
                    ),
                ):
                    _build_non_authoritative_test_bundle(source, Path(temporary) / "output")
                runner.assert_not_called()

    def test_loader_override_environment_is_rejected_before_driver_query(self) -> None:
        for variable in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"):
            with (
                self.subTest(variable=variable),
                tempfile.TemporaryDirectory(prefix="wf-d22a-loader-override-") as temporary,
                patch.dict(os.environ, {variable: "/tmp/forbidden.so"}, clear=False),
                patch.object(
                    native_builder.subprocess,
                    "run",
                    side_effect=AssertionError("driver queried with a loader override"),
                ) as runner,
                self.assertRaisesRegex(native_builder.NativeBuildError, "loader override"),
            ):
                _build_non_authoritative_test_bundle(ROOT, Path(temporary) / "output")
            runner.assert_not_called()

    def test_toolchain_bytes_are_rejected_before_any_driver_query(self) -> None:
        manifest, _raw = native_builder._load_contract(
            ROOT,
            native_builder.TOOLCHAIN_LOCK,
            native_builder.OllamaV2NativeToolchainManifestD22A,
        )
        self.assertEqual(
            ["/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"],
            [
                item.resolved_path
                for item in manifest.entries
                if item.logical_role == "dynamic_loader"
            ],
        )
        self.assertEqual(
            [native_builder.canonical_ollama_v2_native_build_profile_d22a().compiler_driver],
            [
                item.resolved_path
                for item in manifest.entries
                if item.logical_role == "compiler_driver"
            ],
        )
        for role in ("compiler_driver", "system_header", "loader_cache", "tool_runtime_libisl"):
            entry = next(item for item in manifest.entries if item.logical_role == role)
            replacement = ("0" if entry.sha256[0] != "0" else "1") + entry.sha256[1:]
            tampered_entry = replace(entry, sha256=replacement)
            tampered_manifest = replace(
                manifest,
                entries=tuple(
                    tampered_entry if item is entry else item for item in manifest.entries
                ),
            )

            with self.subTest(role=role):
                with (
                    patch.object(
                        native_builder.subprocess,
                        "run",
                        side_effect=AssertionError("driver ran before byte verification"),
                    ) as runner,
                    self.assertRaisesRegex(
                        native_builder.NativeBuildError, "toolchain lock mismatch"
                    ),
                ):
                    native_builder._verify_toolchain_lock(
                        tampered_manifest,
                        native_builder._environment(),
                    )
                runner.assert_not_called()

        synthetic_specs = b"locked synthetic specs\n"
        ordered_manifest = native_builder.OllamaV2NativeToolchainManifestD22A(
            build_profile_hash=manifest.build_profile_hash,
            compiler_specs_sha256=_sha(synthetic_specs).hex(),
            entries=manifest.entries,
        )
        locked_paths = {item.resolved_path for item in manifest.entries}
        observed_paths: set[str] = set()
        original_retain = native_builder._retain_toolchain_entry

        def observed_retain(entry):
            retained = original_retain(entry)
            observed_paths.add(entry.resolved_path)
            return retained

        def reported_specs(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            self.assertEqual(locked_paths, observed_paths)
            return subprocess.CompletedProcess(args[0], 0, synthetic_specs.decode(), "")

        with (
            patch.object(native_builder, "_retain_toolchain_entry", side_effect=observed_retain),
            patch.object(native_builder.subprocess, "run", side_effect=reported_specs) as runner,
        ):
            retained = native_builder._verify_toolchain_lock(
                ordered_manifest,
                native_builder._environment(),
            )
        retained.close()
        self.assertEqual(1, runner.call_count)
        self.assertEqual(
            [
                native_builder.canonical_ollama_v2_native_build_profile_d22a().compiler_driver,
                "-dumpspecs",
            ],
            runner.call_args.args[0],
        )
        executable = runner.call_args.kwargs["executable"]
        self.assertTrue(executable.startswith("/proc/self/fd/"))
        self.assertEqual((int(executable.rsplit("/", 1)[1]),), runner.call_args.kwargs["pass_fds"])

    def test_elf_note_parser_bounds_every_field_to_the_note_segment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wf-d22a-note-red-") as temporary:
            archive = _build_non_authoritative_test_bundle(ROOT, Path(temporary) / "output")[0]
            with tarfile.open(archive, "r:gz") as bundle:
                member = bundle.extractfile("bin/worldforge-ollama-v2-codec-initiator-d22a")
                self.assertIsNotNone(member)
                valid = member.read()

        phoff = struct.unpack_from("<Q", valid, 32)[0]
        phnum = struct.unpack_from("<H", valid, 56)[0]
        note_header = next(
            phoff + index * 56
            for index in range(phnum)
            if struct.unpack_from("<I", valid, phoff + index * 56)[0] == 4
        )
        note_offset = struct.unpack_from("<Q", valid, note_header + 8)[0]
        self.assertEqual(68, struct.unpack_from("<Q", valid, note_header + 32)[0])
        second_note = note_offset + 36

        cases: dict[str, bytearray] = {}
        shrunk = bytearray(valid)
        struct.pack_into("<Q", shrunk, note_header + 32, 67)
        cases["description-crosses-segment"] = shrunk
        truncated_header = bytearray(valid)
        struct.pack_into("<Q", truncated_header, note_header + 32, 40)
        cases["header-crosses-segment"] = truncated_header
        for label, field_offset, value in (
            ("name-size-overflow", second_note, 0xFFFFFFFF),
            ("description-size-overflow", second_note + 4, 0xFFFFFFFF),
            ("description-alignment-overflow", second_note + 4, 17),
            ("zero-name", second_note, 0),
            ("zero-description", second_note + 4, 0),
        ):
            changed = bytearray(valid)
            struct.pack_into("<I", changed, field_offset, value)
            cases[label] = changed
        aligned_name = bytearray(valid)
        struct.pack_into("<Q", aligned_name, note_header + 32, 67)
        struct.pack_into("<I", aligned_name, second_note, 18)
        cases["aligned-name-crosses-segment"] = aligned_name
        aligned_description = bytearray(valid)
        struct.pack_into("<Q", aligned_description, note_header + 32, 67)
        struct.pack_into("<I", aligned_description, second_note + 4, 14)
        cases["aligned-description-crosses-segment"] = aligned_description
        bad_alignment = bytearray(valid)
        struct.pack_into("<Q", bad_alignment, note_header + 48, 8)
        cases["segment-alignment"] = bad_alignment
        trailing_nonzero = bytearray(valid)
        struct.pack_into("<Q", trailing_nonzero, note_header + 32, 69)
        cases["nonzero-trailing-byte"] = trailing_nonzero
        trailing_zero = bytearray(valid)
        struct.pack_into("<Q", trailing_zero, note_header + 32, 72)
        trailing_zero[note_offset + 68 : note_offset + 72] = bytes(4)
        cases["zero-trailing-word"] = trailing_zero

        for label, changed in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(native_builder.NativeBuildError, "PT_NOTE"):
                    native_builder.inspect_elf(bytes(changed))

    def _assert_tdd_cycle_evidence(self, evidence: str) -> None:
        rows = _parse_tdd_cycle_evidence(evidence)
        self.assertIn("Writer-reported historical RED", evidence)
        self.assertRegex(evidence, r"not a\s+freshly reproducible failing state")
        self.assertRegex(
            evidence,
            r"exact shell\s+command or elapsed time is marked unretained rather than reconstructed",
        )
        self.assertIn("Current independently reproducible GREEN", evidence)
        self.assertRegex(evidence, r"Git history does not prove\s+this chronology")

        exact_fields = {
            _TDD_EVIDENCE_TASKS[0]: {
                "Test file": "`tests/test_ollama_v2_native_build_d22a.py`",
                "Layer": "Local build integration",
            },
            _TDD_EVIDENCE_TASKS[1]: {
                "Test file": (
                    "`tests/test_ollama_v2_native_build_d22a.py`; "
                    "`tests/test_ollama_v2_native_build_contracts_d22a.py`"
                ),
                "Layer": "Unit plus local build/transport integration",
            },
            _TDD_EVIDENCE_TASKS[2]: {
                "Test file": "`tests/test_ollama_v2_native_build_d22a.py`",
                "Layer": "Local build integration",
            },
        }
        markers = {
            _TDD_EVIDENCE_TASKS[0]: {
                "Safety net": (
                    "prior focused candidate green",
                    "exact count and timing were not retained",
                ),
                "RED": (
                    "**Writer-reported historical RED.**",
                    "Current test IDs corresponding to the three writer-reported "
                    "historical RED assertions are",
                    "test_authoritative_link_diagnostics_bind_observed_inputs_to_lock",
                    "test_undeclared_actual_link_input_blocks_bundle_publication",
                    "test_toolchain_manifest_requires_all_126_fixed_entries_before_driver_query",
                    "original full command, elapsed time, and exact test selection were "
                    "not retained",
                    "historical execution was not independently reconstructed",
                    "three selected tests failed",
                    "absent captured diagnostics",
                    "undeclared successful link input",
                    "stale 124-entry census",
                    "documentation assertions also failed",
                ),
                "GREEN": (
                    "Historical final7 focused GREEN: 34/34",
                    "elapsed time unretained",
                    "**Current independently reproducible GREEN:**",
                    "python3 -m unittest tests.test_ollama_v2_native_build_contracts_d22a "
                    "tests.test_ollama_v2_native_build_d22a",
                    "36/36 in 21.363s",
                    "`OK`",
                ),
                "Triangulate": (
                    "GCC `-v`",
                    "GNU ld `--trace`",
                    "opened `liblto_plugin.so`",
                    "unexecuted `lto-wrapper`",
                    "omission, relabel, drift, and undeclared-input cases",
                ),
                "Refactor": (
                    "two self-consistent expected sets",
                    "124 to 126 entries",
                ),
            },
            _TDD_EVIDENCE_TASKS[1]: {
                "Safety net": ("34/34", "17.006s", "before production/native changes"),
                "RED": (
                    "**Writer-reported historical RED.**",
                    "test_protocol_lock_body_fields_bind_encoders_decoders_and_goldens",
                    "test_successful_link_diagnostics_are_closed_canonical_and_complete",
                    "exact launcher prefix was not retained",
                    "2 tests in 5.926s",
                    "`FAILED (failures=7, errors=1)`",
                    "encoder emitted `1`",
                    "lock required `2`",
                    "six mutated stderr transcripts still published",
                    "diagnostic profile pin was absent",
                ),
                "GREEN": (
                    "two-test GREEN: 2/2 in 2.353s",
                    "focused GREEN: 36/36 in 19.595s",
                    "**Current independently reproducible GREEN:**",
                    "36/36 in 21.363s",
                    "`OK`",
                ),
                "Triangulate": (
                    "every body field",
                    "malformed, localized, extra, reordered, duplicated, and suppressed",
                    "real initiator/responder transport remained green",
                ),
                "Refactor": (
                    "protocol lock authoritative",
                    "terminal type `2`",
                    "removed duplicated input-role expectations",
                    "complete normalized ordered transcript",
                ),
            },
            _TDD_EVIDENCE_TASKS[2]: {
                "Safety net": (
                    "test_successful_link_diagnostics_are_closed_canonical_and_complete",
                    "1/1 in 5.215s",
                    "`OK`",
                ),
                "RED": (
                    "**Writer-reported historical RED.**",
                    "same targeted command",
                    "1 test in 8.553s",
                    "`FAILED (failures=4)`",
                    "symlink, `/./`, alternate `/../`, and duplicate-slash aliases",
                    "all published",
                ),
                "GREEN": (
                    "same targeted command",
                    "1/1 in 5.882s",
                    "**Current independently reproducible GREEN:**",
                    "36/36 in 21.363s",
                    "`OK`",
                ),
                "Triangulate": (
                    "test pair passed 2/2 in 6.522s",
                    "15 mutation cases",
                    "six legitimate ordered `../../../` trace lines",
                ),
                "Refactor": (
                    "Raw ordered system/toolchain spellings",
                    "only exact generated paths are substituted",
                    "resolved-path role/byte mapping remains a separate parity check",
                ),
            },
        }
        for task in _TDD_EVIDENCE_TASKS:
            row = rows[task]
            for field, expected in exact_fields[task].items():
                self.assertEqual(expected, row[field])
            for field, required in markers[task].items():
                for marker in required:
                    self.assertIn(marker, row[field])

    def test_docs_and_notices_state_the_exact_non_authoritative_boundary(self) -> None:
        evidence = (ROOT / "docs/evidence/ollama-v2-native-static-codec-d22a.md").read_text()
        adr = (
            ROOT / "docs/decisions/0050-studio-director-governed-ollama-evidence-v2.md"
        ).read_text()
        architecture = (ROOT / "docs/ARCHITECTURE.md").read_text()
        readme = (ROOT / "README.md").read_text()
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text()

        for document in (evidence, adr, architecture, readme):
            self.assertIn("codec_implementation_state: built", document)
            self.assertIn("effect_interpreter_state: absent", document)
            self.assertIn("availability: unavailable", document)
            self.assertIn("production_eligible: false", document)
            self.assertRegex(document, r"system/toolchain trace\s+path spellings")
            self.assertIn("`../../../`", document)
            self.assertRegex(document, r"(?i)symlink and lexical aliases")
        self.assertIn("GNU C Library 2.39", notices)
        self.assertIn("Linux UAPI headers", notices)
        self.assertIn("not bundled", notices)
        self.assertIn("SO_PEERCRED", evidence)
        self.assertIn("not authentication", evidence)
        self.assertIn("does not prove replay protection", evidence)
        self.assertIn(
            "Locked executable and input bytes are verified before the first driver query.",
            evidence,
        )
        self.assertIn(
            "Driver-reported built-in specs are verified after that query and before compilation.",
            evidence,
        )
        self.assertIn("`-fstack-protector-strong`", evidence)
        self.assertIn("`__stack_chk_fail` and `__stack_chk_guard`", evidence)
        self.assertIn("driver_descriptor_bound: true", evidence)
        self.assertIn("subtool_paths_pre_post_verified: true", evidence)
        self.assertIn("same_principal_or_root_coherent_substitution_resistant: false", evidence)
        self.assertIn("does not resist malicious root", evidence)
        self.assertIn("All ten canonical source entries remain open", evidence)
        self.assertIn("materialized exclusively from retained bytes", evidence)
        self.assertIn("source_custody_verified: false", evidence)
        self.assertIn("active build-driver and build-contract source bytes", evidence)
        self.assertIn("python_interpreter_custody_verified: false", evidence)
        self.assertIn("python_stdlib_custody_verified: false", evidence)
        self.assertIn("hostile_in_memory_code_resistance_verified: false", evidence)
        self.assertIn("direct source-file execution", evidence)
        self.assertIn("source-only loader", evidence)
        self.assertIn("does not consult cached bytecode", evidence)
        self.assertIn("126-entry toolchain", evidence)
        self.assertIn("/usr/lib/gcc/aarch64-linux-gnu/13/libgcc_s.so", evidence)
        self.assertIn("/usr/lib/aarch64-linux-gnu/libc_nonshared.a", evidence)
        self.assertIn("/usr/libexec/gcc/aarch64-linux-gnu/13/liblto_plugin.so", evidence)
        self.assertIn("/usr/libexec/gcc/aarch64-linux-gnu/13/lto-wrapper", evidence)
        self.assertIn("captured GCC `-v` and GNU ld `--trace` diagnostics", evidence)
        self.assertIn("opened `liblto_plugin.so`", evidence)
        self.assertIn("did not open or execute `lto-wrapper`", evidence)
        self.assertIn("The D2.2a native builder", adr)
        self.assertNotIn("sdist builder", adr.lower())
        self.assertIn("libgcc_s.so", notices)
        self.assertIn("libc_nonshared.a", notices)
        self.assertIn("liblto_plugin.so", notices)
        self.assertIn("lto-wrapper", notices)
        self.assertIn("captured successful link-input closure", evidence)
        self.assertIn("`unavailable_type` at body offset 18 is `2`", evidence)
        self.assertIn("`compiler_link_diagnostic_sha256`", evidence)
        self.assertIn("every ordered stdout and stderr line", evidence)
        self.assertIn(
            "extra, reordered, duplicated, suppressed, malformed, or localized diagnostics",
            evidence,
        )
        self.assertIn("does not claim a syscall-complete OS-input closure", evidence)
        self.assertIn("not the kernel, locale database, or malicious-root inputs", evidence)
        self.assertIn(
            "Root canonically regenerated `contracts/legacy-identity-allowlist.json`",
            evidence,
        )
        self.assertIn(
            "immediately following identity check-only passed: `entries=306 occurrences=1072`",
            evidence,
        )
        self.assertIn(
            "That result preceded this evidence-only reconciliation",
            evidence,
        )
        self.assertRegex(
            evidence,
            r"Root and a fresh reviewer\s+independently ran",
        )
        self.assertIn(
            "test_release_builder_uses_git_archive_and_publishes_reproducible_artifacts",
            evidence,
        )
        self.assertIn("the isolated D2.2a packaging venv under `/tmp`", evidence)
        self.assertIn("`build==1.5.0`", evidence)
        self.assertIn("`setuptools==83.0.0`", evidence)
        self.assertIn("`wheel==0.47.0`", evidence)
        self.assertIn("each passed 1/1 in approximately 32 seconds", evidence)
        self.assertIn("real sdist and wheel", evidence)
        self.assertIn("source-free wheel install", evidence)
        self.assertIn("`pip check`", evidence)
        self.assertIn("isolated import", evidence)
        self.assertIn("`audit-contracts`", evidence)
        self.assertRegex(
            evidence,
            r"Root's subsequent full\s+`M5ReleaseBuilderTests` run passed 21/21 in "
            r"38\.626s",
        )
        self.assertRegex(
            evidence,
            r"test cleanup removed the\s+temporary release artifacts",
        )
        self.assertRegex(
            evidence,
            r"no sdist or wheel SHA-256 is retained or claimed here",
        )
        self.assertNotIn("All 20 dependency-safe M5 release-builder selectors passed", evidence)
        self.assertNotIn("remaining pre-existing integration selector is blocked", evidence)
        self.assertNotIn("expected stale `MANIFEST.in` hash", evidence)
        self.assertNotIn("allowlist was not rewritten", evidence)
        self.assertIn("## TDD Cycle Evidence", evidence)
        self.assertIn(
            "| Task | Test file | Layer | Safety net | RED | GREEN | Triangulate | Refactor |",
            evidence,
        )
        self.assertIn("Writer-reported historical RED", evidence)
        self.assertIn("Current independently reproducible GREEN", evidence)
        self.assertRegex(evidence, r"Git history does not prove\s+this chronology")
        self._assert_tdd_cycle_evidence(evidence)
        self._assert_tdd_cycle_evidence_mutations(evidence)

    def _assert_tdd_cycle_evidence_mutations(self, evidence: str) -> None:
        self._assert_tdd_cycle_evidence(evidence)
        row_lines = {
            task: next(line for line in evidence.splitlines() if line.startswith(f"| {task} |"))
            for task in _TDD_EVIDENCE_TASKS
        }

        for task, row in row_lines.items():
            with self.subTest(mutation="missing-row", task=task):
                changed = evidence.replace(row + "\n", "", 1)
                with self.assertRaises(AssertionError):
                    self._assert_tdd_cycle_evidence(changed)

            cells = [cell.strip() for cell in row[1:-1].split("|")]
            self.assertEqual(len(_TDD_EVIDENCE_COLUMNS), len(cells))
            for index, field in enumerate(_TDD_EVIDENCE_COLUMNS):
                with self.subTest(mutation="nonempty-field-drift", task=task, field=field):
                    changed_cells = list(cells)
                    changed_cells[index] = "mutated-but-nonempty"
                    changed_row = "| " + " | ".join(changed_cells) + " |"
                    changed = evidence.replace(row, changed_row, 1)
                    with self.assertRaises(AssertionError):
                        self._assert_tdd_cycle_evidence(changed)

        first_row = row_lines[_TDD_EVIDENCE_TASKS[0]]
        second_row = row_lines[_TDD_EVIDENCE_TASKS[1]]
        structural_mutations = {
            "duplicate-key": evidence.replace(first_row, first_row + "\n" + first_row, 1),
            "reordered-keys": evidence.replace(
                first_row + "\n" + second_row,
                second_row + "\n" + first_row,
                1,
            ),
            "extra-row": evidence.replace(
                first_row,
                first_row
                + "\n| FinalX: unreviewed | `tests/unknown.py` | Unit | set | red | green"
                + " | tri | refactor |",
                1,
            ),
            "header-field": evidence.replace("| Safety net |", "| Baseline |", 1),
            "separator": evidence.replace("|---|---|---|---|---|---|---|---|", "|---|---|", 1),
            "invented-command-caveat": evidence.replace(
                "marked unretained rather than reconstructed",
                "silently reconstructed",
                1,
            ),
            "git-chronology-caveat": evidence.replace(
                "Git history does not prove\nthis chronology",
                "Git history proves\nthis chronology",
                1,
            ),
        }
        for mutation, changed in structural_mutations.items():
            with self.subTest(mutation=mutation):
                self.assertNotEqual(evidence, changed)
                with self.assertRaises(AssertionError):
                    self._assert_tdd_cycle_evidence(changed)

        final7_red_markers = (
            "Current test IDs corresponding to the three writer-reported historical RED "
            "assertions are",
            "test_authoritative_link_diagnostics_bind_observed_inputs_to_lock",
            "test_undeclared_actual_link_input_blocks_bundle_publication",
            "test_toolchain_manifest_requires_all_126_fixed_entries_before_driver_query",
            "original full command, elapsed time, and exact test selection were not retained",
            "historical execution was not independently reconstructed",
        )
        for marker in final7_red_markers:
            self.assertEqual(1, evidence.count(marker))
            for mutation, replacement in (
                ("final7-red-identity-deletion", ""),
                ("final7-red-identity-drift", "mutated-final7-red-identity"),
            ):
                with self.subTest(mutation=mutation, marker=marker):
                    changed = evidence.replace(marker, replacement, 1)
                    with self.assertRaises(AssertionError):
                        self._assert_tdd_cycle_evidence(changed)

    def _run_responder(self, responder: Path, record: bytes) -> int:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            right.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            process = subprocess.Popen(
                [str(responder)],
                stdin=right.fileno(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            right.close()
            left.send(record)
            left.shutdown(socket.SHUT_WR)
            return process.wait(timeout=6)
        finally:
            left.close()
            right.close()

    def _run_initiator_with_mutated_response(
        self,
        initiator: Path,
        where: slice,
        replacement: bytes,
        *,
        rehash_body: bool,
    ) -> int:
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            right.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            process = subprocess.Popen(
                [str(initiator)],
                stdin=right.fileno(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            right.close()
            request = left.recv(MAX_RECORD + 1)
            self.assertEqual(144, len(request))
            self.assertEqual(b"", left.recv(1))
            response = bytearray(_response(request))
            response[where] = replacement
            if rehash_body:
                response[88:120] = _sha(response[120:])
            left.send(response)
            left.shutdown(socket.SHUT_WR)
            return process.wait(timeout=5)
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
