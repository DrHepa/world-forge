from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from worldforge.provider_evidence.ollama_v2_native_build_contracts import (
    FORMAT_VERSION,
    MAX_DOCUMENT_BYTES,
    OllamaV2NativeBuildContractError,
    OllamaV2NativeElfEntryV1,
    OllamaV2NativeSourceEntryV1,
    OllamaV2NativeSourceManifestD22A,
    OllamaV2NativeStaticBundleManifestD22A,
    OllamaV2NativeToolchainEntryV1,
    OllamaV2NativeToolchainManifestD22A,
    OllamaV2NativeTwoRootReceiptD22A,
    canonical_ollama_v2_native_build_bytes,
    canonical_ollama_v2_native_build_profile_d22a,
    parse_ollama_v2_native_build_contract,
    validate_ollama_v2_native_build_lineage_d22a,
)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


PROFILE_GOLDEN_BYTES = (
    b'{"artifact_roles":["codec_initiator_probe","codec_responder_probe"],'
    b'"binutils_version":"2.42","byte_identity":"sha256-whole-elf",'
    b'"compile_flags":["-std=c17","-pedantic-errors","-O2","-fPIE",'
    b'"-fno-common","-fno-builtin","-fvisibility=hidden","-fstack-protector-strong",'
    b'"-D_FORTIFY_SOURCE=3","-Wall","-Wextra","-Werror","-Wconversion",'
    b'"-Wsign-conversion","-Wformat=2","-Wshadow","-Wstrict-prototypes",'
    b'"-Wmissing-prototypes","-Wundef","-Wdate-time","-Wstack-protector",'
    b'"-ffunction-sections",'
    b'"-fdata-sections"],"compiler_driver":"/usr/bin/aarch64-linux-gnu-gcc-13",'
    b'"compiler_link_diagnostic_sha256":'
    b'"0d599bda5372f0455f4f2566cf7c31d6f28a2b260e8a9d1473dc91115ce608bc",'
    b'"compiler_version":"13.3.0","content_hash":'
    b'"103524a1551e569383591a1f629484da2135e53c246194b6e9a3fa02b4cb9fdc",'
    b'"driver_descriptor_bound":true,'
    b'"dynamic_interpreter":"/lib/ld-linux-aarch64.so.1","environment":["LANG=C",'
    b'"LC_ALL=C","PATH=/usr/bin:/bin","SOURCE_DATE_EPOCH=0","TZ=UTC"],'
    b'"executable_format":"elf64-little-aarch64-pie","format":'
    b'"world-forge.private.ollama_v2_native_build_profile_d22a","format_version":1,'
    b'"glibc_version":"2.39","gnu_build_id_semantics":"correlation-only",'
    b'"language_standard":"c17","link_flags":["-v","-pie",'
    b'"-Wl,-z,relro,-z,now,-z,noexecstack",'
    b'"-Wl,--as-needed,--build-id=sha1,--fatal-warnings,--gc-sections,--strip-all",'
    b'"-Wl,--trace"],'
    b'"linkage":"dynamic-libc-loader-only","profile_id":'
    b'"ollama_v2_codec_probe_linux_aarch64_d22a_v1","root_mapped_flags":'
    b'["-ffile-prefix-map={SOURCE_ROOT}=/usr/src/world-forge",'
    b'"-fmacro-prefix-map={SOURCE_ROOT}=/usr/src/world-forge",'
    b'"-fdebug-prefix-map={SOURCE_ROOT}=/usr/src/world-forge"],'
    b'"same_principal_or_root_coherent_substitution_resistant":false,'
    b'"source_inventory_sha256":'
    b'"7f4a7ac2ed2c5a5c892abddf0fedb87689cacd29fdd1cd735fed75ac92682100",'
    b'"subtool_paths_pre_post_verified":true,'
    b'"target_architecture":"aarch64","target_os":"linux",'
    b'"toolchain_inventory_sha256":'
    b'"acdb15daa9f8e16853a78fcda554629af82405df19ecf4273b7ef07c87df0331"}'
)
PROFILE_GOLDEN_SHA256 = "d946c52fd07ef173a7b1ca1ad79f36f423a3f6d68ab9bc859a4cd9d7e2d28584"
ROOT = Path(__file__).resolve().parents[1]


class D22ANativeBuildContractTests(unittest.TestCase):
    def test_profile_parser_rejects_fixed_field_mutations_in_a_fresh_process(
        self,
    ) -> None:
        script = r"""
import hashlib
import json
import sys

from worldforge.provider_evidence.ollama_v2_native_build_contracts import (
    OllamaV2NativeBuildContractError,
    canonical_ollama_v2_native_build_bytes,
    parse_ollama_v2_native_build_contract,
)

original = bytes.fromhex(sys.argv[1])
mutations = (
    ("target_os", "windows"),
    ("target_architecture", "x86_64"),
    ("compiler_version", "13.3.1"),
    ("compiler_link_diagnostic_sha256", "1" * 64),
    ("linkage", "static"),
    ("driver_descriptor_bound", False),
)
rejected = 0
for field, value in mutations:
    document = json.loads(original)
    document[field] = value
    document.pop("content_hash")
    document["content_hash"] = hashlib.sha256(
        canonical_ollama_v2_native_build_bytes(document)
    ).hexdigest()
    candidate = canonical_ollama_v2_native_build_bytes(document)
    try:
        parse_ollama_v2_native_build_contract(candidate)
    except OllamaV2NativeBuildContractError as exc:
        if exc.reason_code != "native_build_profile_invalid":
            raise
        rejected += 1
    else:
        raise SystemExit(f"accepted noncanonical profile field: {field}")

parsed = parse_ollama_v2_native_build_contract(original)
if parsed.to_bytes() != original:
    raise SystemExit("valid profile vector changed")
print(f"rejected={rejected};valid_sha256={hashlib.sha256(parsed.to_bytes()).hexdigest()}")
"""
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        completed = subprocess.run(
            [sys.executable, "-c", script, PROFILE_GOLDEN_BYTES.hex()],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)
        self.assertEqual(
            f"rejected=6;valid_sha256={PROFILE_GOLDEN_SHA256}\n",
            completed.stdout,
        )

    def test_profile_parser_is_repeated_and_concurrent_order_independent(self) -> None:
        def rehashed_mutation(field: str, value: object) -> bytes:
            document = json.loads(PROFILE_GOLDEN_BYTES)
            document[field] = value
            document.pop("content_hash")
            document["content_hash"] = _sha(canonical_ollama_v2_native_build_bytes(document))
            return canonical_ollama_v2_native_build_bytes(document)

        invalid = (
            rehashed_mutation("target_os", "windows"),
            rehashed_mutation("artifact_roles", ["codec_initiator_probe"]),
            rehashed_mutation("environment", ["LANG=C"]),
            rehashed_mutation("compiler_link_diagnostic_sha256", "1" * 64),
            rehashed_mutation("source_inventory_sha256", "1" * 64),
            rehashed_mutation("same_principal_or_root_coherent_substitution_resistant", True),
        )

        def outcome(value: bytes) -> tuple[str, str]:
            try:
                parsed = parse_ollama_v2_native_build_contract(value)
            except OllamaV2NativeBuildContractError as exc:
                return ("rejected", exc.reason_code)
            return ("accepted", _sha(parsed.to_bytes()))

        sequence = tuple(
            item
            for _ in range(8)
            for item in (*invalid, PROFILE_GOLDEN_BYTES, PROFILE_GOLDEN_BYTES)
        )
        with ThreadPoolExecutor(max_workers=8) as executor:
            observed = tuple(executor.map(outcome, sequence))

        expected_cycle = (
            *(("rejected", "native_build_profile_invalid"),) * len(invalid),
            ("accepted", PROFILE_GOLDEN_SHA256),
            ("accepted", PROFILE_GOLDEN_SHA256),
        )
        self.assertEqual(expected_cycle * 8, observed)
        self.assertNotIn("_expected", canonical_ollama_v2_native_build_profile_d22a.__dict__)
        self.assertEqual(
            PROFILE_GOLDEN_BYTES,
            canonical_ollama_v2_native_build_profile_d22a().to_bytes(),
        )

    def test_profile_is_literal_platform_and_authority_boundary(self) -> None:
        profile = canonical_ollama_v2_native_build_profile_d22a()

        self.assertEqual(1, FORMAT_VERSION)
        self.assertEqual(1024 * 1024, MAX_DOCUMENT_BYTES)
        self.assertEqual("ollama_v2_codec_probe_linux_aarch64_d22a_v1", profile.profile_id)
        self.assertEqual("linux", profile.target_os)
        self.assertEqual("aarch64", profile.target_architecture)
        self.assertEqual("elf64-little-aarch64-pie", profile.executable_format)
        self.assertEqual("c17", profile.language_standard)
        self.assertEqual("dynamic-libc-loader-only", profile.linkage)
        self.assertEqual(
            ("codec_initiator_probe", "codec_responder_probe"),
            profile.artifact_roles,
        )
        self.assertEqual("sha256-whole-elf", profile.byte_identity)
        self.assertEqual("correlation-only", profile.gnu_build_id_semantics)
        self.assertEqual(
            "0d599bda5372f0455f4f2566cf7c31d6f28a2b260e8a9d1473dc91115ce608bc",
            profile.compiler_link_diagnostic_sha256,
        )
        self.assertEqual(
            "7f4a7ac2ed2c5a5c892abddf0fedb87689cacd29fdd1cd735fed75ac92682100",
            profile.source_inventory_sha256,
        )
        self.assertEqual(
            "acdb15daa9f8e16853a78fcda554629af82405df19ecf4273b7ef07c87df0331",
            profile.toolchain_inventory_sha256,
        )
        self.assertTrue(profile.driver_descriptor_bound)
        self.assertTrue(profile.subtool_paths_pre_post_verified)
        self.assertFalse(profile.same_principal_or_root_coherent_substitution_resistant)
        self.assertIn("-fstack-protector-strong", profile.compile_flags)
        self.assertIn("-Wstack-protector", profile.compile_flags)
        self.assertNotIn("-fno-stack-protector", profile.compile_flags)
        self.assertIn("-v", profile.link_flags)
        self.assertIn("-Wl,--trace", profile.link_flags)
        self.assertEqual(
            (
                "-ffile-prefix-map={SOURCE_ROOT}=/usr/src/world-forge",
                "-fmacro-prefix-map={SOURCE_ROOT}=/usr/src/world-forge",
                "-fdebug-prefix-map={SOURCE_ROOT}=/usr/src/world-forge",
            ),
            profile.root_mapped_flags,
        )

        document = profile.to_document()
        self.assertNotIn("commit_oid", document)
        self.assertNotIn("archive_hash", document)
        self.assertNotIn("root_path", document)
        self.assertNotIn("available", document)
        self.assertEqual(profile, parse_ollama_v2_native_build_contract(profile.to_bytes()))
        self.assertEqual(PROFILE_GOLDEN_BYTES, profile.to_bytes())
        self.assertEqual(PROFILE_GOLDEN_SHA256, _sha(profile.to_bytes()))

    def test_source_toolchain_bundle_graph_is_acyclic_and_exact(self) -> None:
        profile = canonical_ollama_v2_native_build_profile_d22a()
        source = OllamaV2NativeSourceManifestD22A(
            source_scope="ollama_v2_codec_probe_source_d22a",
            entries=(
                OllamaV2NativeSourceEntryV1(
                    logical_path="LICENSE",
                    artifact_role="license",
                    size_bytes=3,
                    sha256=_sha(b"MIT"),
                ),
                OllamaV2NativeSourceEntryV1(
                    logical_path="native/ollama_v2_control/wf_ov2_protocol.c",
                    artifact_role="shared_codec_source",
                    size_bytes=4,
                    sha256=_sha(b"code"),
                ),
            ),
        )
        toolchain = OllamaV2NativeToolchainManifestD22A(
            build_profile_hash=profile.content_hash,
            compiler_specs_sha256=_sha(b"gcc specs"),
            entries=(
                OllamaV2NativeToolchainEntryV1(
                    logical_role="compiler_driver",
                    resolved_path="/usr/bin/aarch64-linux-gnu-gcc-13",
                    size_bytes=5,
                    sha256=_sha(b"gcc13"),
                ),
            ),
        )
        bundle = OllamaV2NativeStaticBundleManifestD22A(
            source_manifest_hash=source.content_hash,
            build_profile_hash=profile.content_hash,
            toolchain_manifest_hash=toolchain.content_hash,
            entries=(
                OllamaV2NativeElfEntryV1(
                    artifact_role="codec_initiator_probe",
                    filename="worldforge-ollama-v2-codec-initiator-d22a",
                    size_bytes=7,
                    sha256=_sha(b"elf-one"),
                    gnu_build_id="1" * 40,
                ),
                OllamaV2NativeElfEntryV1(
                    artifact_role="codec_responder_probe",
                    filename="worldforge-ollama-v2-codec-responder-d22a",
                    size_bytes=7,
                    sha256=_sha(b"elf-two"),
                    gnu_build_id="2" * 40,
                ),
            ),
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

        validate_ollama_v2_native_build_lineage_d22a(bundle, source, profile, toolchain)
        receipt = OllamaV2NativeTwoRootReceiptD22A(
            protocol_lock_hash=_sha(b"protocol-lock"),
            source_manifest_hash=source.content_hash,
            build_profile_hash=profile.content_hash,
            toolchain_manifest_hash=toolchain.content_hash,
            static_bundle_manifest_hash=bundle.content_hash,
            root_labels=("root-a", "different-root-b"),
            root_a_entries=bundle.entries,
            root_b_entries=bundle.entries,
            comparison="byte-identical",
            claim_scope="static-codec-build-only",
        )
        self.assertEqual(
            [source, profile, toolchain, bundle, receipt],
            [
                parse_ollama_v2_native_build_contract(item.to_bytes())
                for item in (source, profile, toolchain, bundle, receipt)
            ],
        )
        self.assertNotIn("bundle_manifest_hash", source.to_document())
        self.assertNotIn("bundle_manifest_hash", profile.to_document())
        self.assertNotIn("bundle_manifest_hash", toolchain.to_document())

    def test_hostile_values_and_noncanonical_json_fail_closed(self) -> None:
        profile = canonical_ollama_v2_native_build_profile_d22a()
        canonical = profile.to_bytes()
        document = profile.to_document()

        hostile = [
            b"",
            canonical + b"\n",
            canonical.replace(b'"format":', b'"format" :', 1),
            canonical.replace(b'"format":', b'"format":"duplicate","format":', 1),
            json.dumps(document, indent=2).encode(),
            b'{"value":1.0}',
            b'{"value":NaN}',
            b"[]",
            "not-bytes",
        ]
        for value in hostile:
            with self.subTest(value=repr(value)[:80]):
                with self.assertRaises(OllamaV2NativeBuildContractError):
                    parse_ollama_v2_native_build_contract(value)

        changed = dict(document)
        changed["linkage"] = "static"
        changed_bytes = canonical_ollama_v2_native_build_bytes(changed)
        with self.assertRaises(OllamaV2NativeBuildContractError):
            parse_ollama_v2_native_build_contract(changed_bytes)

    def test_entries_reject_unsafe_paths_roles_order_and_subclasses(self) -> None:
        digest = _sha(b"x")
        bad_paths = ("", "/absolute", "../escape", "a/../b", "a\\b", "a//b")
        for path in bad_paths:
            with self.subTest(path=path):
                with self.assertRaises(OllamaV2NativeBuildContractError):
                    OllamaV2NativeSourceEntryV1(path, "license", 1, digest)

        valid = OllamaV2NativeSourceEntryV1("LICENSE", "license", 1, digest)
        self.assertEqual(
            "protocol_lock",
            OllamaV2NativeSourceEntryV1(
                "native/ollama_v2_control/protocol-lock.json",
                "protocol_lock",
                1,
                digest,
            ).artifact_role,
        )
        self.assertEqual(
            "toolchain_lock",
            OllamaV2NativeSourceEntryV1(
                "native/ollama_v2_control/toolchain-lock.json",
                "toolchain_lock",
                1,
                digest,
            ).artifact_role,
        )
        with self.assertRaises(OllamaV2NativeBuildContractError):
            OllamaV2NativeSourceManifestD22A("ollama_v2_codec_probe_source_d22a", (valid, valid))

        class Text(str):
            pass

        with self.assertRaises(OllamaV2NativeBuildContractError):
            OllamaV2NativeSourceEntryV1(Text("LICENSE"), "license", 1, digest)


if __name__ == "__main__":
    unittest.main()
